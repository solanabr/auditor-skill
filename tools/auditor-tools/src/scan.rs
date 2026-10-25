//! Static-analysis scanner for Solana/Anchor Rust codebases.
//!
//! Each `*.rs` file is lexed with `proc-macro2` (whose lexer and drop do not
//! recurse, and whose `span-locations` feature yields real line numbers), checked
//! for nesting and chains deeper than [`MAX_DEPTH`] and [`MAX_CHAIN`] allow, then
//! parsed with `syn` and walked with a [`syn::visit::Visit`] implementation to
//! enumerate the risky surface an auditor would otherwise have to find by hand. A
//! snippet is rendered from the file's tokens, a token at a time, up to
//! `SNIPPET_MAX` characters.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use proc_macro2::{Delimiter, LineColumn, Spacing, Span, TokenStream, TokenTree};
use quote::ToTokens;
use serde::Serialize;
use syn::punctuated::{Pair, Punctuated};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, Type};

use crate::confine::{self, is_run_dir_name, os_message, MAX_FILE};

const SNIPPET_MAX: usize = 80;

/// Group nesting (`(`, `[` and `{`) past which a file is not parsed.
pub const MAX_DEPTH: usize = 256;

/// The longest chain of tokens a file may hold before it is not parsed: the
/// tokens since the last `;`, the last `,` outside an unclosed `<`, an inner
/// attribute, or the start of an item or statement after a block, counted on
/// through every group they are nested in. syn's tree nests at most one level a
/// token along such a chain.
pub const MAX_CHAIN: usize = 20_000;

/// Directory nesting below the scanned directory past which the walk does not go:
/// it holds a descriptor open for each level.
pub const MAX_WALK: usize = 128;

/// The stacks the scan runs on, the first the system grants: syn's parser, the
/// visit and the drop of a tree recurse on it, one level for each level the tree
/// nests. The first holds the deepest tree `MAX_DEPTH` and `MAX_CHAIN` let through
/// several times over (20,000 nested `break`, the deepest shape measured, need
/// more than 64 MiB and less than 128); the second, for a system that grants no
/// more, holds any tree real code nests.
const STACKS: [usize; 2] = [512 << 20, 64 << 20];

/// Top-level scan report — serialized to a single JSON object.
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub root: String,
    pub files_scanned: usize,
    pub instructions: Vec<Instruction>,
    pub accounts_structs: Vec<AccountsStruct>,
    pub pdas: Vec<Pda>,
    pub arithmetic_sites: Vec<ArithmeticSite>,
    pub panic_sites: Vec<PanicSite>,
    pub unsafe_blocks: Vec<UnsafeBlock>,
    pub cpi_sites: Vec<CpiSite>,
    pub remaining_accounts_sites: Vec<RemainingAccountsSite>,
    pub functions: Vec<FunctionDef>,
    /// Every symbolic link the walk did not follow, every directory it did not
    /// enter, and every `*.rs` file it did not parse, with the reason.
    pub skipped: Vec<Skipped>,
}

#[derive(Debug, Serialize)]
pub struct Skipped {
    pub file: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct Arg {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Serialize)]
pub struct Instruction {
    pub name: String,
    pub file: String,
    pub line: usize,
    pub args: Vec<Arg>,
}

#[derive(Debug, Serialize)]
pub struct AccountsStruct {
    pub name: String,
    pub file: String,
    pub line: usize,
    pub fields: Vec<AccountField>,
}

#[derive(Debug, Serialize)]
pub struct AccountField {
    pub name: String,
    pub ty: String,
    /// True when the field type is Anchor's `UncheckedAccount` (manual validation required).
    pub unchecked: bool,
    pub constraints: AccountConstraints,
}

#[derive(Debug, Serialize)]
pub struct AccountConstraints {
    pub init: bool,
    pub init_if_needed: bool,
    #[serde(rename = "mut")]
    pub is_mut: bool,
    pub signer: bool,
    pub has_one: Vec<String>,
    pub seeds: Vec<String>,
    pub bump: bool,
    pub close: Option<String>,
    pub owner: Option<String>,
    pub token: bool,
    pub associated_token: bool,
    pub realloc: bool,
    pub raw: String,
}

#[derive(Debug, Serialize)]
pub struct Pda {
    #[serde(rename = "struct")]
    pub struct_name: String,
    pub field: String,
    pub seeds: Vec<String>,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Serialize)]
pub struct ArithmeticSite {
    pub file: String,
    pub line: usize,
    pub op: String,
    pub snippet: String,
}

#[derive(Debug, Serialize)]
pub struct PanicSite {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub snippet: String,
}

#[derive(Debug, Serialize)]
pub struct UnsafeBlock {
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Serialize)]
pub struct CpiSite {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub snippet: String,
}

#[derive(Debug, Serialize)]
pub struct RemainingAccountsSite {
    pub file: String,
    pub line: usize,
    pub snippet: String,
}

#[derive(Debug, Serialize)]
pub struct FunctionDef {
    pub name: String,
    pub file: String,
    pub line: usize,
    #[serde(rename = "pub")]
    pub is_pub: bool,
}

impl ScanReport {
    fn new(root: String, files_scanned: usize) -> Self {
        Self {
            root,
            files_scanned,
            instructions: Vec::new(),
            accounts_structs: Vec::new(),
            pdas: Vec::new(),
            arithmetic_sites: Vec::new(),
            panic_sites: Vec::new(),
            unsafe_blocks: Vec::new(),
            cpi_sites: Vec::new(),
            remaining_accounts_sites: Vec::new(),
            functions: Vec::new(),
            skipped: Vec::new(),
        }
    }
}

/// Scan every `*.rs` file under the directory `root`, a path relative to the
/// working directory, returning one merged report.
///
/// The walk opens each directory from its parent's descriptor without following a
/// link, so a name swapped for a link while it runs is not entered, and reads only
/// regular files with one name of at most 4 MiB, each opened the same way. Every
/// link it meets, every directory nested more than `MAX_WALK` levels down, and
/// every `*.rs` file it does not parse (not regular, too large, unreadable, not
/// UTF-8, nested or chained too deeply, or not Rust that `syn` parses) is listed
/// in `skipped`. Directories named `target`, `.git` and `node_modules` below
/// `root` are pruned, and so are the run directories and `.audit-memory/` when
/// `root` is the working directory. Entries are visited in byte order of their
/// names, and the spans of each file are released once it is visited, so the
/// total source read has no limit. The scan runs on a thread of its own, on the
/// first of `STACKS` the system grants.
pub fn scan_path(root: &Path) -> io::Result<ScanReport> {
    let mut refused = None;
    for stack in STACKS {
        let root = root.to_path_buf();
        match std::thread::Builder::new()
            .name("audit-scan".into())
            .stack_size(stack)
            .spawn(move || walk(&root))
        {
            Ok(scan) => {
                return match scan.join() {
                    Ok(report) => Ok(report),
                    Err(panic) => std::panic::resume_unwind(panic),
                }
            }
            Err(e) => refused = Some(e),
        }
    }
    Err(refused.unwrap_or_else(|| io::Error::other("no stack to scan on")))
}

fn walk(root: &Path) -> ScanReport {
    let mut scan = Scan {
        report: ScanReport::new(root.display().to_string(), 0),
        top: root == Path::new("."),
    };
    match open_root(root) {
        Ok(dir) => scan.dir(&dir, root, 0),
        Err(e) => scan.skip(root, format!("cannot be read: {}", os_message(&e))),
    }
    scan.report
}

/// The directory to scan, each name on its way opened from the one before
/// without following a link.
fn open_root(root: &Path) -> io::Result<OwnedFd> {
    let mut dir = confine::open_dir(libc::AT_FDCWD, b".")?;
    if root != Path::new(".") {
        for part in root.as_os_str().as_bytes().split(|&c| c == b'/') {
            dir = confine::open_dir(dir.as_raw_fd(), part)?;
        }
    }
    Ok(dir)
}

/// A scan under way: the report so far, and whether the root is the working
/// directory.
struct Scan {
    report: ScanReport,
    top: bool,
}

impl Scan {
    fn skip(&mut self, path: &Path, reason: impl Into<String>) {
        self.report.skipped.push(Skipped {
            file: path.display().to_string(),
            reason: reason.into(),
        });
    }

    /// The entries of the directory `dir`, named `path`, `depth` levels below the
    /// root.
    fn dir(&mut self, dir: &OwnedFd, path: &Path, depth: usize) {
        let names = match confine::names(dir) {
            Ok(names) => names,
            Err(e) => return self.skip(path, format!("cannot be read: {}", os_message(&e))),
        };
        for name in names {
            let child = path.join(OsStr::from_bytes(&name));
            let kind = match confine::kind_at(dir.as_raw_fd(), &name) {
                Ok(kind) => kind,
                Err(e) => {
                    self.skip(&child, format!("cannot be read: {}", os_message(&e)));
                    continue;
                }
            };
            match kind {
                libc::S_IFLNK => self.skip(&child, "a symbolic link, not followed"),
                libc::S_IFDIR => self.subdir(dir, &name, &child, depth + 1),
                _ if !name.ends_with(b".rs") => {}
                libc::S_IFREG => self.file(dir, &name, &child),
                _ => self.skip(&child, "not a regular file"),
            }
        }
    }

    /// A directory in `dir`: build output, git's own directory, installed
    /// packages and, when the root is the working directory, its run directories
    /// and `.audit-memory/` (an audit's own output) are not entered.
    fn subdir(&mut self, dir: &OwnedFd, name: &[u8], path: &Path, depth: usize) {
        if matches!(name, b"target" | b".git" | b"node_modules")
            || (self.top && depth == 1 && (name == b".audit-memory" || is_run_dir_name(name)))
        {
            return;
        }
        if depth > MAX_WALK {
            return self.skip(path, "nested too deeply to walk");
        }
        match confine::open_dir(dir.as_raw_fd(), name) {
            Ok(sub) => self.dir(&sub, path, depth),
            Err(e) => match confine::kind_at(dir.as_raw_fd(), name) {
                Ok(libc::S_IFLNK) => self.skip(path, "a symbolic link, not followed"),
                _ => self.skip(path, format!("cannot be read: {}", os_message(&e))),
            },
        }
    }

    fn file(&mut self, dir: &OwnedFd, name: &[u8], path: &Path) {
        let label = path.display().to_string();
        match read_source(dir.as_raw_fd(), name).and_then(|source| parse(&source)) {
            Ok((ast, tokens)) => {
                self.report.files_scanned += 1;
                let mut visitor = FileVisitor::new(&label, &tokens);
                visitor.visit_file(&ast);
                visitor.drain_into(&mut self.report);
            }
            Err(reason) => self.report.skipped.push(Skipped {
                file: label,
                reason,
            }),
        }
        // No span of this file is left: free proc-macro2's map of the source parsed on
        // this thread, whose 32-bit offsets would wrap past 4 GiB of source.
        proc_macro2::extra::invalidate_current_thread_spans();
    }
}

/// A `*.rs` file's text: a regular file with one name (a second name could be a
/// file outside the tree) of at most 4 MiB, opened from its directory without
/// following a link or blocking on a FIFO, and UTF-8.
fn read_source(dir: RawFd, name: &[u8]) -> Result<String, String> {
    let unreadable = |e: io::Error| format!("cannot be read: {}", os_message(&e));
    let file = confine::open_file(dir, name).map_err(unreadable)?;
    let md = file.metadata().map_err(unreadable)?;
    if !md.file_type().is_file() {
        return Err("not a regular file".to_string());
    }
    if md.nlink() != 1 {
        return Err("has more than one name (a hard link)".to_string());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if md.len() > MAX_FILE || bytes.len() as u64 > MAX_FILE {
        return Err("larger than 4 MiB".to_string());
    }
    String::from_utf8(bytes).map_err(|_| "not UTF-8".to_string())
}

/// A source's syntax tree and its tokens, laid out for snippets, as
/// `syn::parse_file` reads it (a byte order mark and a `#!` line left out), or why
/// it is not parsed. syn's parser, the visit and the drop of the tree recurse once
/// for each level the tree nests, so a file whose tokens could nest it deeper than
/// the scan's stack holds (`Tokens::lay_out`) is not handed to syn.
fn parse(source: &str) -> Result<(syn::File, Tokens), String> {
    let (shebang, content) = split_shebang(source);
    let stream: TokenStream = content
        .parse()
        .map_err(|_| "does not parse as Rust".to_string())?;
    let tokens = Tokens::lay_out(stream.clone())
        .ok_or_else(|| "nested or chained too deeply to parse".to_string())?;
    let mut file: syn::File =
        syn::parse2(stream).map_err(|_| "does not parse as Rust".to_string())?;
    file.shebang = shebang;
    Ok((file, tokens))
}

/// The `#!` line `syn::parse_file` leaves out of a file (one not followed by `[`,
/// which starts an inner attribute), and the text after it and a byte order mark;
/// the newline that ends the line stays, so line numbers hold.
fn split_shebang(source: &str) -> (Option<String>, &str) {
    let content = source.strip_prefix('\u{feff}').unwrap_or(source);
    if let Some(rest) = content.strip_prefix("#!") {
        if !skip_space(rest).starts_with('[') {
            return match content.find('\n') {
                Some(i) => (Some(content[..i].to_string()), &content[i..]),
                None => (Some(content.to_string()), ""),
            };
        }
    }
    (None, content)
}

/// `s` past its leading whitespace and its comments that are not doc comments, as
/// syn's `whitespace::skip` reads it.
fn skip_space(mut s: &str) -> &str {
    'skip: while !s.is_empty() {
        let byte = s.as_bytes()[0];
        if byte == b'/' {
            if s.starts_with("//")
                && (!s.starts_with("///") || s.starts_with("////"))
                && !s.starts_with("//!")
            {
                match s.find('\n') {
                    Some(i) => {
                        s = &s[i + 1..];
                        continue;
                    }
                    None => return "",
                }
            } else if s.starts_with("/**/") {
                s = &s[4..];
                continue;
            } else if s.starts_with("/*")
                && (!s.starts_with("/**") || s.starts_with("/***"))
                && !s.starts_with("/*!")
            {
                let bytes = s.as_bytes();
                let (mut depth, mut i) = (0usize, 0usize);
                while i + 1 < bytes.len() {
                    if bytes[i] == b'/' && bytes[i + 1] == b'*' {
                        depth += 1;
                        i += 1;
                    } else if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            s = &s[i + 2..];
                            continue 'skip;
                        }
                        i += 1;
                    }
                    i += 1;
                }
                return s;
            }
        }
        match byte {
            b' ' | 0x09..=0x0D => {
                s = &s[1..];
                continue;
            }
            b if b <= 0x7F => {}
            _ => {
                if let Some(c) = s.chars().next() {
                    if c.is_whitespace() || c == '\u{200e}' || c == '\u{200f}' {
                        s = &s[c.len_utf8()..];
                        continue;
                    }
                }
            }
        }
        return s;
    }
    s
}

/// Scan a single in-memory source string (used by tests and the demo path), on
/// the calling thread's stack.
///
/// Returns `None` if the source is not parsed.
pub fn scan_source(file_label: &str, source: &str) -> Option<ScanReport> {
    let (ast, tokens) = parse(source).ok()?;
    let mut report = ScanReport::new(file_label.to_string(), 1);
    let mut visitor = FileVisitor::new(file_label, &tokens);
    visitor.visit_file(&ast);
    visitor.drain_into(&mut report);
    Some(report)
}

fn truncate_snippet(s: &str) -> String {
    // Collapse internal whitespace so multi-line exprs read on one line.
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > SNIPPET_MAX {
        let mut out: String = collapsed.chars().take(SNIPPET_MAX).collect();
        out.push_str("...");
        out
    } else {
        collapsed
    }
}

fn tokens_string<T: ToTokens>(node: &T) -> String {
    node.to_token_stream().to_string()
}

/// One file's tokens in source order, a group laid out as its opening, its
/// tokens and its closing, each where it starts: what snippets are rendered from.
struct Tokens {
    atoms: Vec<Atom>,
    /// The text of every token, one after another.
    text: String,
}

#[derive(Clone, Copy)]
struct Atom {
    line: u32,
    column: u32,
    piece: Piece,
}

#[derive(Clone, Copy)]
enum Piece {
    Open(Delimiter),
    Close(Delimiter),
    /// A token: its text in `Tokens::text`, and whether it is punctuation joined
    /// to the token after it.
    Token {
        at: u32,
        len: u32,
        joint: bool,
    },
}

impl Atom {
    fn at(&self) -> (u32, u32) {
        (self.line, self.column)
    }
}

fn place(at: LineColumn) -> (u32, u32) {
    (
        u32::try_from(at.line).unwrap_or(u32::MAX),
        u32::try_from(at.column).unwrap_or(u32::MAX),
    )
}

/// What a group level of `Tokens::lay_out` counts.
struct Level {
    rest: proc_macro2::token_stream::IntoIter,
    /// Where the group closes, and with what (none for the file itself).
    close: Option<(LineColumn, Delimiter)>,
    /// The chain of the levels around it when the group opened.
    base: usize,
    /// The chain at this level since its last end.
    run: usize,
    /// `<` at this level that no `>` has closed since the chain's last end.
    angle: usize,
    /// The last token, when it is punctuation joined to this one.
    joint: Option<char>,
    /// Whether the last token was a brace group.
    after_brace: bool,
    /// How much of an inner attribute's `#!` the last tokens were: 1 for `#`, 2
    /// for `#` then `!`.
    attr: u8,
    /// Whether the group is an inner attribute's `[…]`, which ends the chain of
    /// the level around it.
    ends_chain: bool,
}

impl Level {
    fn new(
        rest: proc_macro2::token_stream::IntoIter,
        close: Option<(LineColumn, Delimiter)>,
        base: usize,
    ) -> Level {
        Level {
            rest,
            close,
            base,
            run: 0,
            angle: 0,
            joint: None,
            after_brace: false,
            attr: 0,
            ends_chain: false,
        }
    }
}

/// After a block, a token that can only start another item or statement: a name
/// other than `else` and `as`, a literal, or the `#` of an attribute.
fn starts_anew(tt: &TokenTree) -> bool {
    match tt {
        TokenTree::Ident(i) => i != "else" && i != "as",
        TokenTree::Literal(_) => true,
        TokenTree::Punct(p) => p.as_char() == '#',
        TokenTree::Group(_) => false,
    }
}

impl Tokens {
    /// The stream laid out flat, or `None` when a group nests deeper than
    /// `MAX_DEPTH` or a chain runs past `MAX_CHAIN` tokens. A chain ends at `;`,
    /// at `,` with no `<` open since its start (inside `<…>`, a `,` separates
    /// generic arguments that nest on), after an inner attribute (`#![…]`, found
    /// only before items and statements), and, after a block, at a token that can
    /// only start another item or statement (`starts_anew`); `->` closes no `<`,
    /// `=>` closes every one, and `<=` opens none. Each token of a group counts
    /// toward the chain of every group around it, from where that group opened.
    fn lay_out(stream: TokenStream) -> Option<Tokens> {
        let mut tokens = Tokens {
            atoms: Vec::new(),
            text: String::new(),
        };
        let mut around: Vec<Level> = Vec::new();
        let mut level = Level::new(stream.into_iter(), None, 0);
        loop {
            let Some(tt) = level.rest.next() else {
                let (close, ends_chain) = (level.close, level.ends_chain);
                let Some(parent) = around.pop() else {
                    return Some(tokens);
                };
                if let Some((at, delim)) = close {
                    tokens.push(at, Piece::Close(delim));
                }
                level = parent;
                level.after_brace = matches!(close, Some((_, Delimiter::Brace)));
                if ends_chain {
                    level.run = 0;
                    level.angle = 0;
                }
                continue;
            };
            if std::mem::take(&mut level.after_brace) && starts_anew(&tt) {
                level.run = 0;
                level.angle = 0;
            }
            let joint = level.joint.take();
            let attr = std::mem::take(&mut level.attr);
            if let TokenTree::Punct(p) = &tt {
                let c = p.as_char();
                tokens.push_token(&tt);
                if p.spacing() == Spacing::Joint {
                    level.joint = Some(c);
                }
                level.attr = match (c, attr) {
                    ('#', _) => 1,
                    ('!', 1) => 2,
                    _ => 0,
                };
                match c {
                    ';' => {
                        level.run = 0;
                        level.angle = 0;
                        continue;
                    }
                    ',' if level.angle == 0 => {
                        level.run = 0;
                        continue;
                    }
                    '<' => level.angle += 1,
                    '=' if joint == Some('<') => level.angle = level.angle.saturating_sub(1),
                    '>' => match joint {
                        Some('-') => {}
                        Some('=') => level.angle = 0,
                        _ => level.angle = level.angle.saturating_sub(1),
                    },
                    _ => {}
                }
            }
            level.run += 1;
            if level.base + level.run > MAX_CHAIN {
                return None;
            }
            match tt {
                TokenTree::Group(g) => {
                    if around.len() >= MAX_DEPTH {
                        return None;
                    }
                    tokens.push(g.span_open().start(), Piece::Open(g.delimiter()));
                    let mut inner = Level::new(
                        g.stream().into_iter(),
                        Some((g.span_close().start(), g.delimiter())),
                        level.base + level.run,
                    );
                    inner.ends_chain = attr == 2 && g.delimiter() == Delimiter::Bracket;
                    around.push(std::mem::replace(&mut level, inner));
                }
                TokenTree::Punct(_) => {}
                other => tokens.push_token(&other),
            }
        }
    }

    fn push(&mut self, at: LineColumn, piece: Piece) {
        let (line, column) = place(at);
        self.atoms.push(Atom {
            line,
            column,
            piece,
        });
    }

    fn push_token(&mut self, tt: &TokenTree) {
        use std::fmt::Write;
        let start = self.text.len();
        let _ = write!(self.text, "{tt}");
        let joint = matches!(tt, TokenTree::Punct(p) if p.spacing() == Spacing::Joint);
        let at = u32::try_from(start).unwrap_or(u32::MAX);
        let len = u32::try_from(self.text.len() - start).unwrap_or(0);
        self.push(tt.span().start(), Piece::Token { at, len, joint });
    }

    /// The first token that starts at `at`.
    fn first_at(&self, at: LineColumn) -> Option<usize> {
        let key = place(at);
        let i = self.atoms.partition_point(|a| a.at() < key);
        (i < self.atoms.len() && self.atoms[i].at() == key).then_some(i)
    }

    /// The last token that starts before `end`: the last of a span that ends
    /// there, whether it covers one token or several (a negative literal).
    fn last_before(&self, end: LineColumn) -> Option<usize> {
        let key = place(end);
        self.atoms.partition_point(|a| a.at() < key).checked_sub(1)
    }

    /// The tokens from `first` to `last` as proc-macro2 prints a token stream (a
    /// space between two tokens unless the first is joined punctuation, `{ … }`
    /// around the tokens of a brace group), as `truncate_snippet` collapses and cuts
    /// them, printing no more than it keeps. `None` when the tokens are not whole
    /// groups, so not an expression's.
    fn render(&self, first: usize, last: usize) -> Option<String> {
        let mut out = Snippet::default();
        // For each open group: whether a token is printed in it, and whether the
        // last is joined punctuation.
        let mut open = vec![(false, false)];
        for atom in self.atoms.get(first..=last)? {
            match atom.piece {
                Piece::Open(delimiter) => {
                    let top = open.last_mut()?;
                    if top.0 && !top.1 {
                        out.push(" ");
                    }
                    *top = (true, false);
                    out.push(match delimiter {
                        Delimiter::Parenthesis => "(",
                        Delimiter::Bracket => "[",
                        Delimiter::Brace => "{ ",
                        Delimiter::None => "",
                    });
                    open.push((false, false));
                }
                Piece::Close(delimiter) => {
                    if open.len() < 2 {
                        return None;
                    }
                    let (printed, _) = open.pop()?;
                    if delimiter == Delimiter::Brace && printed {
                        out.push(" ");
                    }
                    out.push(match delimiter {
                        Delimiter::Parenthesis => ")",
                        Delimiter::Bracket => "]",
                        Delimiter::Brace => "}",
                        Delimiter::None => "",
                    });
                }
                Piece::Token { at, len, joint } => {
                    let top = open.last_mut()?;
                    if top.0 && !top.1 {
                        out.push(" ");
                    }
                    *top = (true, joint);
                    let start = at as usize;
                    out.push(self.text.get(start..start + len as usize)?);
                }
            }
            if out.full() {
                return Some(out.finish());
            }
        }
        (open.len() == 1).then(|| out.finish())
    }
}

/// Text collapsed as `truncate_snippet` collapses it (each run of whitespace one
/// space, none at either end), held only up to one character past `SNIPPET_MAX`.
#[derive(Default)]
struct Snippet {
    text: String,
    chars: usize,
    space: bool,
}

impl Snippet {
    fn push(&mut self, s: &str) {
        for c in s.chars() {
            if self.full() {
                return;
            }
            if c.is_whitespace() {
                self.space = self.chars > 0;
                continue;
            }
            if std::mem::take(&mut self.space) {
                self.put(' ');
                if self.full() {
                    return;
                }
            }
            self.put(c);
        }
    }

    fn put(&mut self, c: char) {
        self.text.push(c);
        self.chars += 1;
    }

    /// More than `SNIPPET_MAX` characters are in, so the rest is cut.
    fn full(&self) -> bool {
        self.chars > SNIPPET_MAX
    }

    fn finish(mut self) -> String {
        if self.full() {
            let cut = self
                .text
                .char_indices()
                .nth(SNIPPET_MAX)
                .map_or(self.text.len(), |(i, _)| i);
            self.text.truncate(cut);
            self.text.push_str("...");
        }
        self.text
    }
}

/// One step toward an expression's first or last token: the token, or the
/// expression on that side whose token it is.
enum Step<'a> {
    At(Span),
    Expr(&'a Expr),
}

fn expr_attrs(e: &Expr) -> &[syn::Attribute] {
    match e {
        Expr::Array(x) => &x.attrs,
        Expr::Assign(x) => &x.attrs,
        Expr::Async(x) => &x.attrs,
        Expr::Await(x) => &x.attrs,
        Expr::Binary(x) => &x.attrs,
        Expr::Block(x) => &x.attrs,
        Expr::Break(x) => &x.attrs,
        Expr::Call(x) => &x.attrs,
        Expr::Cast(x) => &x.attrs,
        Expr::Closure(x) => &x.attrs,
        Expr::Const(x) => &x.attrs,
        Expr::Continue(x) => &x.attrs,
        Expr::Field(x) => &x.attrs,
        Expr::ForLoop(x) => &x.attrs,
        Expr::Group(x) => &x.attrs,
        Expr::If(x) => &x.attrs,
        Expr::Index(x) => &x.attrs,
        Expr::Infer(x) => &x.attrs,
        Expr::Let(x) => &x.attrs,
        Expr::Lit(x) => &x.attrs,
        Expr::Loop(x) => &x.attrs,
        Expr::Macro(x) => &x.attrs,
        Expr::Match(x) => &x.attrs,
        Expr::MethodCall(x) => &x.attrs,
        Expr::Paren(x) => &x.attrs,
        Expr::Path(x) => &x.attrs,
        Expr::Range(x) => &x.attrs,
        Expr::RawAddr(x) => &x.attrs,
        Expr::Reference(x) => &x.attrs,
        Expr::Repeat(x) => &x.attrs,
        Expr::Return(x) => &x.attrs,
        Expr::Struct(x) => &x.attrs,
        Expr::Try(x) => &x.attrs,
        Expr::TryBlock(x) => &x.attrs,
        Expr::Tuple(x) => &x.attrs,
        Expr::Unary(x) => &x.attrs,
        Expr::Unsafe(x) => &x.attrs,
        Expr::While(x) => &x.attrs,
        Expr::Yield(x) => &x.attrs,
        _ => &[],
    }
}

/// The first outer attribute: syn prints those before the node, and its inner
/// ones (`#![…]`) inside its braces.
fn attrs_first(attrs: &[syn::Attribute]) -> Option<Span> {
    attrs
        .iter()
        .find(|a| matches!(a.style, syn::AttrStyle::Outer))
        .map(|a| a.pound_token.span())
}

fn label_first(label: &Option<syn::Label>, keyword: Span) -> Span {
    label.as_ref().map_or(keyword, |l| l.name.apostrophe)
}

fn path_first(path: &syn::Path) -> Span {
    match (&path.leading_colon, path.segments.first()) {
        (Some(colons), _) => colons.spans[0],
        (None, Some(segment)) => segment.ident.span(),
        (None, None) => path.span(),
    }
}

fn qpath_first(qself: &Option<syn::QSelf>, path: &syn::Path) -> Span {
    qself
        .as_ref()
        .map_or_else(|| path_first(path), |q| q.lt_token.span())
}

fn closure_first(x: &syn::ExprClosure) -> Span {
    if let Some(l) = &x.lifetimes {
        return l.for_token.span();
    }
    if let Some(t) = &x.constness {
        return t.span();
    }
    if let Some(t) = &x.movability {
        return t.span();
    }
    if let Some(t) = &x.asyncness {
        return t.span();
    }
    if let Some(t) = &x.capture {
        return t.span();
    }
    x.or1_token.span()
}

/// The first token of a stream, a group by its opening.
fn stream_first(tokens: TokenStream) -> Span {
    match tokens.into_iter().next() {
        Some(TokenTree::Group(g)) => g.span_open(),
        Some(t) => t.span(),
        None => Span::call_site(),
    }
}

/// The last token of a stream, a group by its closing.
fn stream_last(tokens: TokenStream) -> Span {
    match tokens.into_iter().last() {
        Some(TokenTree::Group(g)) => g.span_close(),
        Some(t) => t.span(),
        None => Span::call_site(),
    }
}

/// The step from an expression toward its first token, as syn prints it: outer
/// attributes first, then down the left operand of the expressions that start
/// with one.
fn first_step(e: &Expr) -> Step<'_> {
    if let Some(at) = attrs_first(expr_attrs(e)) {
        return Step::At(at);
    }
    match e {
        Expr::Array(x) => Step::At(x.bracket_token.span.open()),
        Expr::Assign(x) => Step::Expr(&x.left),
        Expr::Async(x) => Step::At(x.async_token.span()),
        Expr::Await(x) => Step::Expr(&x.base),
        Expr::Binary(x) => Step::Expr(&x.left),
        Expr::Block(x) => Step::At(label_first(&x.label, x.block.brace_token.span.open())),
        Expr::Break(x) => Step::At(x.break_token.span()),
        Expr::Call(x) => Step::Expr(&x.func),
        Expr::Cast(x) => Step::Expr(&x.expr),
        Expr::Closure(x) => Step::At(closure_first(x)),
        Expr::Const(x) => Step::At(x.const_token.span()),
        Expr::Continue(x) => Step::At(x.continue_token.span()),
        Expr::Field(x) => Step::Expr(&x.base),
        Expr::ForLoop(x) => Step::At(label_first(&x.label, x.for_token.span())),
        Expr::Group(x) => Step::Expr(&x.expr),
        Expr::If(x) => Step::At(x.if_token.span()),
        Expr::Index(x) => Step::Expr(&x.expr),
        Expr::Infer(x) => Step::At(x.underscore_token.span()),
        Expr::Let(x) => Step::At(x.let_token.span()),
        Expr::Lit(x) => Step::At(x.lit.span()),
        Expr::Loop(x) => Step::At(label_first(&x.label, x.loop_token.span())),
        Expr::Macro(x) => Step::At(path_first(&x.mac.path)),
        Expr::Match(x) => Step::At(x.match_token.span()),
        Expr::MethodCall(x) => Step::Expr(&x.receiver),
        Expr::Paren(x) => Step::At(x.paren_token.span.open()),
        Expr::Path(x) => Step::At(qpath_first(&x.qself, &x.path)),
        Expr::Range(x) => match &x.start {
            Some(start) => Step::Expr(start),
            None => Step::At(x.limits.span()),
        },
        Expr::RawAddr(x) => Step::At(x.and_token.span()),
        Expr::Reference(x) => Step::At(x.and_token.span()),
        Expr::Repeat(x) => Step::At(x.bracket_token.span.open()),
        Expr::Return(x) => Step::At(x.return_token.span()),
        Expr::Struct(x) => Step::At(qpath_first(&x.qself, &x.path)),
        Expr::Try(x) => Step::Expr(&x.expr),
        Expr::TryBlock(x) => Step::At(x.try_token.span()),
        Expr::Tuple(x) => Step::At(x.paren_token.span.open()),
        Expr::Unary(x) => Step::At(x.op.span()),
        Expr::Unsafe(x) => Step::At(x.unsafe_token.span()),
        Expr::Verbatim(tokens) => Step::At(stream_first(tokens.clone())),
        Expr::While(x) => Step::At(label_first(&x.label, x.while_token.span())),
        Expr::Yield(x) => Step::At(x.yield_token.span()),
        other => Step::At(stream_first(other.to_token_stream())),
    }
}

/// The step from an expression toward its last token, as syn prints it: down the
/// right operand of the expressions that end with one.
fn last_step(e: &Expr) -> Step<'_> {
    match e {
        Expr::Array(x) => Step::At(x.bracket_token.span.close()),
        Expr::Assign(x) => Step::Expr(&x.right),
        Expr::Async(x) => Step::At(x.block.brace_token.span.close()),
        Expr::Await(x) => Step::At(x.await_token.span()),
        Expr::Binary(x) => Step::Expr(&x.right),
        Expr::Block(x) => Step::At(x.block.brace_token.span.close()),
        Expr::Break(x) => match (&x.expr, &x.label) {
            (Some(value), _) => Step::Expr(value),
            (None, Some(label)) => Step::At(label.ident.span()),
            (None, None) => Step::At(x.break_token.span()),
        },
        Expr::Call(x) => Step::At(x.paren_token.span.close()),
        Expr::Cast(x) => Step::At(type_last(&x.ty)),
        Expr::Closure(x) => Step::Expr(&x.body),
        Expr::Const(x) => Step::At(x.block.brace_token.span.close()),
        Expr::Continue(x) => Step::At(
            x.label
                .as_ref()
                .map_or_else(|| x.continue_token.span(), |l| l.ident.span()),
        ),
        Expr::Field(x) => Step::At(match &x.member {
            syn::Member::Named(name) => name.span(),
            syn::Member::Unnamed(index) => index.span,
        }),
        Expr::ForLoop(x) => Step::At(x.body.brace_token.span.close()),
        Expr::Group(x) => Step::Expr(&x.expr),
        Expr::If(x) => match &x.else_branch {
            Some((_, branch)) => Step::Expr(branch),
            None => Step::At(x.then_branch.brace_token.span.close()),
        },
        Expr::Index(x) => Step::At(x.bracket_token.span.close()),
        Expr::Infer(x) => Step::At(x.underscore_token.span()),
        Expr::Let(x) => Step::Expr(&x.expr),
        Expr::Lit(x) => Step::At(x.lit.span()),
        Expr::Loop(x) => Step::At(x.body.brace_token.span.close()),
        Expr::Macro(x) => Step::At(delimiter_close(&x.mac.delimiter)),
        Expr::Match(x) => Step::At(x.brace_token.span.close()),
        Expr::MethodCall(x) => Step::At(x.paren_token.span.close()),
        Expr::Paren(x) => Step::At(x.paren_token.span.close()),
        Expr::Path(x) => match path_tail(&x.path) {
            Tail::At(at) => Step::At(at),
            Tail::Ty(ty) => Step::At(type_last(ty)),
        },
        Expr::Range(x) => match (&x.end, &x.limits) {
            (Some(end), _) => Step::Expr(end),
            (None, syn::RangeLimits::HalfOpen(dots)) => Step::At(dots.spans[1]),
            (None, syn::RangeLimits::Closed(dots)) => Step::At(dots.spans[2]),
        },
        Expr::RawAddr(x) => Step::Expr(&x.expr),
        Expr::Reference(x) => Step::Expr(&x.expr),
        Expr::Repeat(x) => Step::At(x.bracket_token.span.close()),
        Expr::Return(x) => match &x.expr {
            Some(value) => Step::Expr(value),
            None => Step::At(x.return_token.span()),
        },
        Expr::Struct(x) => Step::At(x.brace_token.span.close()),
        Expr::Try(x) => Step::At(x.question_token.span()),
        Expr::TryBlock(x) => Step::At(x.block.brace_token.span.close()),
        Expr::Tuple(x) => Step::At(x.paren_token.span.close()),
        Expr::Unary(x) => Step::Expr(&x.expr),
        Expr::Unsafe(x) => Step::At(x.block.brace_token.span.close()),
        Expr::Verbatim(tokens) => Step::At(stream_last(tokens.clone())),
        Expr::While(x) => Step::At(x.body.brace_token.span.close()),
        Expr::Yield(x) => match &x.expr {
            Some(value) => Step::Expr(value),
            None => Step::At(x.yield_token.span()),
        },
        other => Step::At(stream_last(other.to_token_stream())),
    }
}

fn delimiter_close(delimiter: &syn::MacroDelimiter) -> Span {
    match delimiter {
        syn::MacroDelimiter::Paren(p) => p.span.close(),
        syn::MacroDelimiter::Brace(b) => b.span.close(),
        syn::MacroDelimiter::Bracket(b) => b.span.close(),
    }
}

/// Where a path or bound ends: at a token, or with a type, whose last token is
/// its own.
enum Tail<'a> {
    At(Span),
    Ty(&'a Type),
}

fn path_tail(path: &syn::Path) -> Tail<'_> {
    let Some(segment) = path.segments.last() else {
        return Tail::At(stream_last(path.to_token_stream()));
    };
    match &segment.arguments {
        syn::PathArguments::None => Tail::At(segment.ident.span()),
        syn::PathArguments::AngleBracketed(args) => Tail::At(args.gt_token.span()),
        syn::PathArguments::Parenthesized(args) => match &args.output {
            syn::ReturnType::Default => Tail::At(args.paren_token.span.close()),
            syn::ReturnType::Type(_, ty) => Tail::Ty(ty),
        },
    }
}

fn bounds_tail<'a>(
    bounds: &'a Punctuated<syn::TypeParamBound, syn::Token![+]>,
    whole: Span,
) -> Tail<'a> {
    match bounds.pairs().next_back() {
        None => Tail::At(whole),
        Some(Pair::Punctuated(_, plus)) => Tail::At(plus.span()),
        Some(Pair::End(bound)) => match bound {
            syn::TypeParamBound::Trait(t) => match &t.paren_token {
                Some(paren) => Tail::At(paren.span.close()),
                None => path_tail(&t.path),
            },
            syn::TypeParamBound::Lifetime(l) => Tail::At(l.ident.span()),
            syn::TypeParamBound::PreciseCapture(c) => Tail::At(c.gt_token.span()),
            syn::TypeParamBound::Verbatim(tokens) => Tail::At(stream_last(tokens.clone())),
            other => Tail::At(stream_last(other.to_token_stream())),
        },
    }
}

/// The last token of a type, found down its last parts.
fn type_last(mut ty: &Type) -> Span {
    loop {
        let tail = match ty {
            Type::Array(x) => Tail::At(x.bracket_token.span.close()),
            Type::BareFn(x) => match &x.output {
                syn::ReturnType::Type(_, ret) => Tail::Ty(ret),
                syn::ReturnType::Default => Tail::At(x.paren_token.span.close()),
            },
            Type::Group(x) => Tail::Ty(&x.elem),
            Type::ImplTrait(x) => bounds_tail(&x.bounds, x.impl_token.span()),
            Type::Infer(x) => Tail::At(x.underscore_token.span()),
            Type::Macro(x) => Tail::At(delimiter_close(&x.mac.delimiter)),
            Type::Never(x) => Tail::At(x.bang_token.span()),
            Type::Paren(x) => Tail::At(x.paren_token.span.close()),
            Type::Path(x) => path_tail(&x.path),
            Type::Ptr(x) => Tail::Ty(&x.elem),
            Type::Reference(x) => Tail::Ty(&x.elem),
            Type::Slice(x) => Tail::At(x.bracket_token.span.close()),
            Type::TraitObject(x) => bounds_tail(
                &x.bounds,
                x.dyn_token
                    .as_ref()
                    .map_or_else(Span::call_site, |t| t.span()),
            ),
            Type::Tuple(x) => Tail::At(x.paren_token.span.close()),
            Type::Verbatim(tokens) => Tail::At(stream_last(tokens.clone())),
            other => Tail::At(stream_last(other.to_token_stream())),
        };
        match tail {
            Tail::At(at) => return at,
            Tail::Ty(next) => ty = next,
        }
    }
}

/// Per-file AST visitor. Accumulates findings, then `drain_into` merges them.
struct FileVisitor<'t> {
    file: String,
    tokens: &'t Tokens,
    /// The first and the last token of each expression looked up, by its address:
    /// a chain's are found once for all its links.
    firsts: HashMap<usize, Span>,
    lasts: HashMap<usize, Span>,
    /// Depth of `#[program]` module nesting we are currently inside.
    program_depth: usize,
    instructions: Vec<Instruction>,
    accounts_structs: Vec<AccountsStruct>,
    pdas: Vec<Pda>,
    arithmetic_sites: Vec<ArithmeticSite>,
    panic_sites: Vec<PanicSite>,
    unsafe_blocks: Vec<UnsafeBlock>,
    cpi_sites: Vec<CpiSite>,
    remaining_accounts_sites: Vec<RemainingAccountsSite>,
    functions: Vec<FunctionDef>,
}

impl<'t> FileVisitor<'t> {
    fn new(file: &str, tokens: &'t Tokens) -> Self {
        Self {
            file: file.to_string(),
            tokens,
            firsts: HashMap::new(),
            lasts: HashMap::new(),
            program_depth: 0,
            instructions: Vec::new(),
            accounts_structs: Vec::new(),
            pdas: Vec::new(),
            arithmetic_sites: Vec::new(),
            panic_sites: Vec::new(),
            unsafe_blocks: Vec::new(),
            cpi_sites: Vec::new(),
            remaining_accounts_sites: Vec::new(),
            functions: Vec::new(),
        }
    }

    fn drain_into(self, report: &mut ScanReport) {
        report.instructions.extend(self.instructions);
        report.accounts_structs.extend(self.accounts_structs);
        report.pdas.extend(self.pdas);
        report.arithmetic_sites.extend(self.arithmetic_sites);
        report.panic_sites.extend(self.panic_sites);
        report.unsafe_blocks.extend(self.unsafe_blocks);
        report.cpi_sites.extend(self.cpi_sites);
        report
            .remaining_accounts_sites
            .extend(self.remaining_accounts_sites);
        report.functions.extend(self.functions);
    }

    /// The first token of `e`, found down its left operands; every expression on
    /// the way is remembered with it.
    fn first(&mut self, e: &Expr) -> Span {
        Self::end_of(&mut self.firsts, e, first_step)
    }

    /// The last token of `e`, found down its right operands, the same way.
    fn last(&mut self, e: &Expr) -> Span {
        Self::end_of(&mut self.lasts, e, last_step)
    }

    fn end_of(known: &mut HashMap<usize, Span>, e: &Expr, step: fn(&Expr) -> Step<'_>) -> Span {
        let mut on_the_way = Vec::new();
        let mut e = e;
        let at = loop {
            let key = e as *const Expr as usize;
            if let Some(&at) = known.get(&key) {
                break at;
            }
            on_the_way.push(key);
            match step(e) {
                Step::At(at) => break at,
                Step::Expr(next) => e = next,
            }
        };
        for key in on_the_way {
            known.insert(key, at);
        }
        at
    }

    /// The snippet of `node`, whose tokens run from `first` to `last`, rendered
    /// from the file's tokens; from the node itself when they are not found there.
    fn snippet<T: ToTokens>(&self, node: &T, first: Span, last: Span) -> String {
        self.tokens
            .first_at(first.start())
            .zip(self.tokens.last_before(last.end()))
            .filter(|(a, b)| a <= b)
            .and_then(|(a, b)| self.tokens.render(a, b))
            .unwrap_or_else(|| truncate_snippet(&tokens_string(node)))
    }

    fn record_instruction(&mut self, func: &syn::ItemFn) {
        let name = func.sig.ident.to_string();
        let line = func.sig.ident.span().start().line;
        let args = collect_instruction_args(&func.sig);
        self.instructions.push(Instruction {
            name,
            file: self.file.clone(),
            line,
            args,
        });
    }

    fn record_accounts_struct(&mut self, item: &syn::ItemStruct) {
        let struct_name = item.ident.to_string();
        let line = item.ident.span().start().line;
        let mut fields = Vec::new();

        if let syn::Fields::Named(named) = &item.fields {
            for field in &named.named {
                let field_name = match &field.ident {
                    Some(id) => id.to_string(),
                    None => continue,
                };
                let ty = tokens_string(&field.ty);
                let (constraints, seeds) = parse_account_attr(&field.attrs);

                if !seeds.is_empty() {
                    self.pdas.push(Pda {
                        struct_name: struct_name.clone(),
                        field: field_name.clone(),
                        seeds: seeds.clone(),
                        file: self.file.clone(),
                        line: field.ident.span().start().line,
                    });
                }

                fields.push(AccountField {
                    name: field_name,
                    ty: ty.clone(),
                    unchecked: is_unchecked_account_ty(&ty),
                    constraints,
                });
            }
        }

        self.accounts_structs.push(AccountsStruct {
            name: struct_name,
            file: self.file.clone(),
            line,
            fields,
        });
    }
}

impl<'ast> Visit<'ast> for FileVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let is_program = has_attr_path(&node.attrs, "program");
        if is_program {
            self.program_depth += 1;
            // Instructions are the fns directly in the program module.
            if let Some((_brace, items)) = &node.content {
                for item in items {
                    if let syn::Item::Fn(func) = item {
                        self.record_instruction(func);
                    }
                }
            }
        }
        syn::visit::visit_item_mod(self, node);
        if is_program {
            self.program_depth -= 1;
        }
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if derive_contains(&node.attrs, "Accounts") {
            self.record_accounts_struct(node);
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.functions.push(FunctionDef {
            name: node.sig.ident.to_string(),
            file: self.file.clone(),
            line: node.sig.ident.span().start().line,
            is_pub: matches!(node.vis, syn::Visibility::Public(_)),
        });
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.functions.push(FunctionDef {
            name: node.sig.ident.to_string(),
            file: self.file.clone(),
            line: node.sig.ident.span().start().line,
            is_pub: matches!(node.vis, syn::Visibility::Public(_)),
        });
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        // syn 2 models both plain arithmetic (`a + b`) and compound assignment
        // (`a += b`) as `ExprBinary`, distinguished by the `BinOp` variant.
        let op = match node.op {
            syn::BinOp::Add(_) => Some("+"),
            syn::BinOp::Sub(_) => Some("-"),
            syn::BinOp::Mul(_) => Some("*"),
            syn::BinOp::Div(_) => Some("/"),
            syn::BinOp::AddAssign(_) => Some("+="),
            syn::BinOp::SubAssign(_) => Some("-="),
            syn::BinOp::MulAssign(_) => Some("*="),
            syn::BinOp::DivAssign(_) => Some("/="),
            _ => None,
        };
        if let Some(op) = op {
            let first = attrs_first(&node.attrs).unwrap_or_else(|| self.first(&node.left));
            let last = self.last(&node.right);
            let snippet = self.snippet(node, first, last);
            self.arithmetic_sites.push(ArithmeticSite {
                file: self.file.clone(),
                line: first.start().line,
                op: op.to_string(),
                snippet,
            });
        }
        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if method == "unwrap" || method == "expect" {
            let first = attrs_first(&node.attrs).unwrap_or_else(|| self.first(&node.receiver));
            let snippet = self.snippet(node, first, node.paren_token.span.close());
            self.panic_sites.push(PanicSite {
                file: self.file.clone(),
                line: node.method.span().start().line,
                kind: method,
                snippet,
            });
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast syn::ExprIndex) {
        let first = attrs_first(&node.attrs).unwrap_or_else(|| self.first(&node.expr));
        let snippet = self.snippet(node, first, node.bracket_token.span.close());
        self.panic_sites.push(PanicSite {
            file: self.file.clone(),
            line: first.start().line,
            kind: "index".to_string(),
            snippet,
        });
        syn::visit::visit_expr_index(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(seg) = node.path.segments.last() {
            let name = seg.ident.to_string();
            if matches!(name.as_str(), "panic" | "unreachable" | "unwrap") {
                let first = path_first(&node.path);
                let snippet = self.snippet(node, first, delimiter_close(&node.delimiter));
                self.panic_sites.push(PanicSite {
                    file: self.file.clone(),
                    line: first.start().line,
                    kind: "panic".to_string(),
                    snippet,
                });
            }
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.unsafe_blocks.push(UnsafeBlock {
            file: self.file.clone(),
            line: node.unsafe_token.span().start().line,
        });
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        if let syn::Member::Named(ident) = &node.member {
            if ident == "remaining_accounts" {
                let first = attrs_first(&node.attrs).unwrap_or_else(|| self.first(&node.base));
                let snippet = self.snippet(node, first, ident.span());
                self.remaining_accounts_sites.push(RemainingAccountsSite {
                    file: self.file.clone(),
                    line: ident.span().start().line,
                    snippet,
                });
            }
        }
        syn::visit::visit_expr_field(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path_expr) = node.func.as_ref() {
            if let Some(seg) = path_expr.path.segments.last() {
                let name = seg.ident.to_string();
                let kind = match name.as_str() {
                    "invoke" => Some("invoke"),
                    "invoke_signed" => Some("invoke_signed"),
                    _ => None,
                };
                if let Some(kind) = kind {
                    let first = attrs_first(&node.attrs).unwrap_or_else(|| self.first(&node.func));
                    let snippet = self.snippet(node, first, node.paren_token.span.close());
                    self.cpi_sites.push(CpiSite {
                        file: self.file.clone(),
                        line: seg.ident.span().start().line,
                        kind: kind.to_string(),
                        snippet,
                    });
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        // Detect `.invoke()` / `.invoke_signed()` method-style CPIs and any
        // reference to `CpiContext`.
        if let Some(seg) = node.segments.last() {
            let name = seg.ident.to_string();
            if name == "CpiContext" {
                self.cpi_sites.push(CpiSite {
                    file: self.file.clone(),
                    line: seg.ident.span().start().line,
                    kind: "CpiContext".to_string(),
                    snippet: "CpiContext".to_string(),
                });
            }
        }
        syn::visit::visit_path(self, node);
    }
}

/// Collect the instruction-data arguments of an Anchor handler.
///
/// Skips `self` receivers and the leading Anchor `Context<..>` parameter so the
/// reported args are exactly the caller-supplied instruction data (`amount`,
/// `params`, ...), which is what an auditor reasons about.
fn collect_instruction_args(sig: &syn::Signature) -> Vec<Arg> {
    let mut args = Vec::new();
    for input in &sig.inputs {
        if let syn::FnArg::Typed(pat_type) = input {
            let ty = tokens_string(&pat_type.ty);
            if is_context_ty(&pat_type.ty) {
                continue;
            }
            let name = match pat_type.pat.as_ref() {
                syn::Pat::Ident(id) => id.ident.to_string(),
                other => tokens_string(other),
            };
            args.push(Arg { name, ty });
        }
    }
    args
}

/// True when an Accounts field type is Anchor's `UncheckedAccount` (any path qualification).
fn is_unchecked_account_ty(ty_str: &str) -> bool {
    ty_str.contains("UncheckedAccount")
}

/// True if the type is Anchor's `Context<..>` (possibly path-qualified).
fn is_context_ty(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        if let Some(seg) = type_path.path.segments.last() {
            return seg.ident == "Context";
        }
    }
    false
}

/// True if any attribute's path matches `ident` (single-segment).
fn has_attr_path(attrs: &[syn::Attribute], ident: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(ident))
}

/// True if any `#[derive(...)]` attribute lists a trait named `trait_name`.
fn derive_contains(attrs: &[syn::Attribute], trait_name: &str) -> bool {
    for attr in attrs {
        if !attr.path().is_ident("derive") {
            continue;
        }
        let mut found = false;
        // parse_nested_meta walks each path inside the derive list.
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident(trait_name) {
                found = true;
            }
            Ok(())
        });
        if found {
            return true;
        }
    }
    false
}

/// Parse the `#[account(...)]` attribute of an Accounts field, returning the
/// structured constraints plus the extracted `seeds` list (also surfaced
/// separately for the top-level `pdas` array).
fn parse_account_attr(attrs: &[syn::Attribute]) -> (AccountConstraints, Vec<String>) {
    let mut constraints = AccountConstraints {
        init: false,
        init_if_needed: false,
        is_mut: false,
        signer: false,
        has_one: Vec::new(),
        seeds: Vec::new(),
        bump: false,
        close: None,
        owner: None,
        token: false,
        associated_token: false,
        realloc: false,
        raw: String::new(),
    };

    let account_attr = attrs.iter().find(|a| a.path().is_ident("account"));
    let attr = match account_attr {
        Some(a) => a,
        None => return (constraints, Vec::new()),
    };

    constraints.raw = tokens_string(attr);

    // The inner tokens of `account(...)` are a comma-separated meta list. We
    // tokenize once and scan structurally: `parse_nested_meta` handles the
    // scalar flags and `key = value` pairs; `seeds = [ ... ]` needs the raw
    // token walk because its value is a bracketed array.
    let inner_tokens = match attr.meta.require_list() {
        Ok(list) => list.tokens.clone(),
        Err(_) => proc_macro2::TokenStream::new(),
    };
    let metas = split_top_level_metas(inner_tokens);
    for meta in &metas {
        apply_meta(meta, &mut constraints);
    }

    let seeds = constraints.seeds.clone();
    (constraints, seeds)
}

/// A single top-level constraint fragment, e.g. `init`, `mut`, `has_one = x`,
/// or `seeds = [ a, b ]`, preserved as its own token stream.
struct MetaFragment {
    key: String,
    /// Tokens after the `=`, if any.
    value: Option<proc_macro2::TokenStream>,
}

/// Split the inner tokens of `account(...)` on top-level commas, capturing the
/// leading identifier and any `= <value>` tail for each fragment. Commas inside
/// `[]`, `()`, or `{}` are ignored so `seeds = [a, b]` stays intact.
fn split_top_level_metas(tokens: proc_macro2::TokenStream) -> Vec<MetaFragment> {
    use proc_macro2::TokenTree;

    let mut fragments = Vec::new();
    let mut key = String::new();
    let mut value: Option<proc_macro2::TokenStream> = None;
    let mut seen_eq = false;
    let mut value_acc = proc_macro2::TokenStream::new();

    let flush = |key: &mut String,
                 value: &mut Option<proc_macro2::TokenStream>,
                 seen_eq: &mut bool,
                 value_acc: &mut proc_macro2::TokenStream,
                 fragments: &mut Vec<MetaFragment>| {
        if key.is_empty() && value_acc.is_empty() && !*seen_eq {
            return;
        }
        let val = if *seen_eq {
            Some(std::mem::take(value_acc))
        } else {
            value.take()
        };
        fragments.push(MetaFragment {
            key: std::mem::take(key),
            value: val,
        });
        *seen_eq = false;
        *value_acc = proc_macro2::TokenStream::new();
    };

    for tt in tokens {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' => {
                flush(
                    &mut key,
                    &mut value,
                    &mut seen_eq,
                    &mut value_acc,
                    &mut fragments,
                );
            }
            TokenTree::Punct(p) if p.as_char() == '=' && !seen_eq => {
                seen_eq = true;
            }
            other => {
                if seen_eq {
                    value_acc.extend(std::iter::once(other.clone()));
                } else if key.is_empty() {
                    // First token of the fragment: expect the constraint name.
                    if let TokenTree::Ident(id) = other {
                        key = id.to_string();
                    } else {
                        // Path-like keys such as `token::mint`. Accumulate.
                        key = other.to_string();
                    }
                } else {
                    // Path continuation, e.g. the `::mint` in `token::mint`.
                    key.push_str(&other.to_string());
                }
            }
        }
    }
    flush(
        &mut key,
        &mut value,
        &mut seen_eq,
        &mut value_acc,
        &mut fragments,
    );

    fragments
}

fn apply_meta(meta: &MetaFragment, c: &mut AccountConstraints) {
    let key = meta.key.as_str();
    match key {
        "init" => c.init = true,
        "init_if_needed" => c.init_if_needed = true,
        "mut" => c.is_mut = true,
        "signer" => c.signer = true,
        "bump" => c.bump = true,
        "realloc" => c.realloc = true,
        "has_one" => {
            if let Some(v) = &meta.value {
                // has_one = x  (may carry `@ Error`; keep just the identifier).
                let s = v.to_string();
                let ident = s.split_whitespace().next().unwrap_or("").to_string();
                if !ident.is_empty() {
                    c.has_one.push(ident);
                }
            }
        }
        "close" => {
            if let Some(v) = &meta.value {
                c.close = Some(
                    v.to_string()
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
        }
        "owner" => {
            if let Some(v) = &meta.value {
                c.owner = Some(
                    v.to_string()
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
        }
        "seeds" => {
            if let Some(v) = &meta.value {
                c.seeds = parse_seed_array(v.clone());
            }
        }
        _ => {
            if key.starts_with("token::") || key == "token" {
                c.token = true;
            }
            if key.starts_with("associated_token::") || key == "associated_token" {
                c.associated_token = true;
            }
            if key.starts_with("realloc::") {
                c.realloc = true;
            }
        }
    }
}

/// Parse the `[ ... ]` value of a `seeds = [...]` constraint into one string
/// per top-level element.
fn parse_seed_array(tokens: proc_macro2::TokenStream) -> Vec<String> {
    use proc_macro2::TokenTree;

    // The value should be a single bracket Group; unwrap it if so.
    let inner = {
        let mut iter = tokens.clone().into_iter();
        match (iter.next(), iter.next()) {
            (Some(TokenTree::Group(g)), None)
                if g.delimiter() == proc_macro2::Delimiter::Bracket =>
            {
                g.stream()
            }
            _ => tokens,
        }
    };

    let mut elems = Vec::new();
    let mut current = proc_macro2::TokenStream::new();
    for tt in inner {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' => {
                let s = current.to_string();
                let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
                if !s.is_empty() {
                    elems.push(s);
                }
                current = proc_macro2::TokenStream::new();
            }
            other => current.extend(std::iter::once(other.clone())),
        }
    }
    let s = current.to_string();
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if !s.is_empty() {
        elems.push(s);
    }
    elems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn laid_out(source: &str) -> bool {
        Tokens::lay_out(source.parse().expect("the source lexes")).is_some()
    }

    #[test]
    fn groups_nest_up_to_the_limit() {
        let nest = |n: usize| format!("const X: u8 = {}1{};", "(".repeat(n), ")".repeat(n));
        assert!(laid_out(&nest(MAX_DEPTH)));
        assert!(!laid_out(&nest(MAX_DEPTH + 1)));
    }

    #[test]
    fn a_chain_runs_up_to_the_limit() {
        // `const X : bool =` and `true` are 6 tokens of the chain; `;` ends it.
        let chain = |n: usize| format!("const X: bool = {}true;", "!".repeat(n));
        assert!(laid_out(&chain(MAX_CHAIN - 6)));
        assert!(!laid_out(&chain(MAX_CHAIN - 5)));
        // A chain counts on through the groups it is nested in.
        let inner = "!".repeat(MAX_CHAIN / 2);
        assert!(!laid_out(&format!("const X: bool = {inner}({inner}true);")));
        assert!(!laid_out(&format!(
            "const X: bool = {inner}{{ {inner}true }};"
        )));
    }

    #[test]
    fn chains_end_only_where_the_tree_cannot_nest_on() {
        let half = "!".repeat(MAX_CHAIN * 3 / 4);
        let two = |sep: &str| format!("fn f() {{ let x = {half}true{sep} let y = {half}true; }}");
        assert!(laid_out(&two(";")), "a statement ends at ;");
        let ones = vec!["1"; MAX_CHAIN * 2].join(", ");
        assert!(
            laid_out(&format!("const X: [u8; 2] = [{ones}];")),
            "elements end at ,"
        );
        let args = vec!["B"; MAX_CHAIN].join(", ");
        assert!(
            !laid_out(&format!("type T = A<{args}>;")),
            "inside <…>, a , ends nothing"
        );
        let arrows = "fn() -> B, ".repeat(MAX_CHAIN / 5);
        assert!(
            !laid_out(&format!("type T = A<{arrows}u8>;")),
            "-> closes no <"
        );
        let items = "fn a() {} ".repeat(MAX_CHAIN / 2);
        assert!(laid_out(&items), "an item after a block starts anew");
        let docs = "#![doc = \"x\"]\n".repeat(MAX_CHAIN);
        assert!(laid_out(&docs), "an inner attribute ends a chain");
        let blocks = " + {1}".repeat(MAX_CHAIN);
        assert!(
            !laid_out(&format!("const X: u8 = {{1}}{blocks};")),
            "an operator after a block goes on"
        );
        let calls = "(1)".repeat(MAX_CHAIN);
        assert!(
            !laid_out(&format!("const X: u8 = {{f}}{calls};")),
            "a call after a block goes on"
        );
        let elses = " else if a {}".repeat(MAX_CHAIN / 4);
        assert!(
            !laid_out(&format!("fn f() {{ if a {{}}{elses} }}")),
            "else after a block goes on"
        );
        let outer = "#[doc = \"x\"] 1 + ".repeat(MAX_CHAIN / 3);
        assert!(
            !laid_out(&format!("const X: u8 = {outer}1;")),
            "an outer attribute ends nothing"
        );
    }

    #[test]
    fn a_file_nested_too_deeply_is_not_parsed() {
        let deep = format!("fn f() {{ let x = {}true; }}", "!".repeat(MAX_CHAIN));
        assert_eq!(
            parse(&deep).err().as_deref(),
            Some("nested or chained too deeply to parse")
        );
        assert!(scan_source("deep.rs", &deep).is_none());
        assert_eq!(
            parse("fn f( {").err().as_deref(),
            Some("does not parse as Rust")
        );
    }

    #[test]
    fn a_byte_order_mark_and_a_shebang_are_left_out_as_syn_leaves_them() {
        let (ast, _) =
            parse("\u{feff}#!/usr/bin/env run-cargo-script\nfn main() {}\n").expect("parses");
        assert_eq!(
            ast.shebang.as_deref(),
            Some("#!/usr/bin/env run-cargo-script")
        );
        let (ast, _) = parse("#![allow(dead_code)]\nfn main() {}\n").expect("parses");
        assert_eq!(ast.shebang, None);
        let report = scan_source("s.rs", "#!/bin/x\nfn f() { let y = a + b; }\n").expect("parses");
        assert_eq!(report.arithmetic_sites[0].line, 2);
    }

    /// Checks every expression outside an attribute: its first and last tokens, as
    /// found down its operands, are where syn's span of it starts and ends.
    struct Ends<'t> {
        visitor: FileVisitor<'t>,
        checked: usize,
    }

    impl<'ast> Visit<'ast> for Ends<'_> {
        fn visit_attribute(&mut self, _: &'ast syn::Attribute) {}

        fn visit_expr(&mut self, e: &'ast Expr) {
            let whole = e.span();
            let (first, last) = (self.visitor.first(e), self.visitor.last(e));
            assert_eq!(
                (first.start(), last.end()),
                (whole.start(), whole.end()),
                "{}",
                tokens_string(e)
            );
            self.checked += 1;
            syn::visit::visit_expr(self, e);
        }
    }

    const SHAPES: &str = r#"
        fn shapes() {
            let a = x.checked_add(y).unwrap().pow(2) as u64 + b[i][j] * -c;
            let b = 'outer: loop { break 'outer 1; };
            let c = move |p: u8| -> u8 { p + 1 };
            let d = async move { f().await? };
            let e = <T as Trait>::f::<u8>(1) + S::<u8> { a: 1, ..d };
            let f = if a { 1 } else if b { 2 } else { 3 };
            let g = match x { #![allow(x)] 1..=-1 => 0, _ => 1 };
            let h = &mut *p as *const dyn Fn(u8) -> u8 as usize;
            let i = (1, 2).0 + t.0.1 + [0u8; 4][..2].len() + (a..).len() + (..=b).len();
            let j = #[cfg(x)] unsafe { g() } + const { 1 } + 'b: { 2 };
            let k = x as fn() -> u8 as Box<dyn Fn() -> u8 + Send>;
            let l = return;
            let m = || continue;
            let n = vec![1, 2] + m!{} + n![];
            let o = || yield 1;
            let p = a = b;
            let q = while x {} == for _ in y {};
            let r = x as Box<dyn A<B> + 'a>;
            let s = &raw const x;
        }
    "#;

    #[test]
    fn an_expressions_ends_are_where_syns_span_of_it_ends() {
        let mut checked = 0;
        for source in [
            SHAPES,
            include_str!("scan.rs"),
            include_str!("mem.rs"),
            include_str!("confine.rs"),
            include_str!("bin/audit-mem.rs"),
            include_str!("bin/audit-scan.rs"),
        ] {
            let (ast, tokens) = parse(source).expect("parses");
            let mut ends = Ends {
                visitor: FileVisitor::new("x.rs", &tokens),
                checked: 0,
            };
            ends.visit_file(&ast);
            checked += ends.checked;
            proc_macro2::extra::invalidate_current_thread_spans();
        }
        assert!(checked > 5_000, "{checked} expressions");
    }

    #[test]
    fn a_snippet_is_the_expressions_tokens_collapsed_and_cut() {
        let source = "fn f() {\n    let v = ctx.accounts\n        .vault.amount.checked_add(x).unwrap();\n    \
                      let w = a + b;\n    let s = msg(\"a   b\").expect(\"e\");\n    let t = g(|| {}).unwrap();\n    \
                      let long = aaaaaaaaaa + bbbbbbbbbb + cccccccccc + dddddddddd + eeeeeeeeee + ffffffffff + gggggggggg;\n}\n";
        let report = scan_source("f.rs", source).expect("parses");
        let panics: Vec<&str> = report
            .panic_sites
            .iter()
            .map(|p| p.snippet.as_str())
            .collect();
        assert_eq!(
            panics,
            [
                "ctx . accounts . vault . amount . checked_add (x) . unwrap ()",
                "msg (\"a b\") . expect (\"e\")",
                "g (|| { }) . unwrap ()",
            ]
        );
        let sums: Vec<&str> = report
            .arithmetic_sites
            .iter()
            .map(|a| a.snippet.as_str())
            .collect();
        assert_eq!(sums[0], "a + b");
        assert_eq!(
            sums[1],
            "aaaaaaaaaa + bbbbbbbbbb + cccccccccc + dddddddddd + eeeeeeeeee + ffffffffff + gg..."
        );
        assert_eq!(report.panic_sites[0].line, 3);
        assert_eq!(report.arithmetic_sites[0].line, 4);
    }
}
