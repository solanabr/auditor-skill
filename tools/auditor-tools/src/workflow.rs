//! A workflow-aware pass over `.github/workflows/*.yml`, with a hand-written
//! strict-subset YAML parser.
//!
//! The parser is not a general YAML library. It reads the block and flow subset
//! GitHub Actions workflows are written in: block mappings and sequences, flow
//! `[…]` and `{…}` on one line or several, plain and quoted scalars, wrapped over
//! lines or not, with every escape YAML 1.2 defines, and `|`/`>` block scalars
//! with their indicators. It fails closed on the rest. A construct outside that
//! subset (an alias, a tag, a merge key, an explicit `?` key) is listed in that
//! workflow's `unknown` with the lines it covers, which are not read; an anchor is
//! listed too, though its node is read. A line it cannot place (YAML that does not
//! parse, a tab in indentation, a character YAML parsers read differently) ends
//! the read, and `unknown` says the file is not read from that line to the end. A
//! workflow is read whole only when its `unknown` is empty. The parser never
//! expands an alias. A file with a second YAML document, or more structure than
//! the caps allow, is listed in `skipped`.
//!
//! Each file is parsed in a child of audit-scan (`parse_stdin`), as a `*.rs` file
//! is, so a parse that does not finish costs only that file, and no file is parsed
//! once the scan's time is spent. The caps bound what is built: [`MAX_WF_DEPTH`]
//! on nesting, [`MAX_WF_NODES`] on nodes a file, `confine::MAX_FILE` on bytes a
//! file, `confine::MAX_ANSWER` on the facts of a file, [`MAX_WF_FILES`] on files a
//! directory, and what the `*.rs` walk left of `scan::MAX_REPORT` on the facts of
//! them all, each counted as audit-scan prints it ([`printed_size`]).

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::confine::{self, os_message};
use crate::scan::Skipped;

/// Block and flow nesting past which the parser stops and lists the node in
/// `unknown`: deeper than any real workflow, so a file that reaches it is hostile
/// or generated.
pub const MAX_WF_DEPTH: usize = 32;

/// The most nodes (mappings' entries, sequences' items, scalars) one file may
/// hold before it is listed in `skipped` as holding more structure than the
/// parser lists.
pub const MAX_WF_NODES: usize = 50_000;

/// The most `*.yml`/`*.yaml` files one directory's pass parses; past them each
/// further file is in `skipped` as not parsed.
pub const MAX_WF_FILES: usize = 256;

/// The longest a scalar or a key is kept: its whitespace collapsed to single
/// spaces and cut after this many characters with `...`, as a report snippet is.
const MAX_WF_SCALAR: usize = 200;

/// The word audit-scan starts itself with, as its only argument, to parse
/// workflow files in a child (`parse_stdin`). Anywhere else the grammar refuses
/// it, as an option it does not know.
pub const PARSE_WORKFLOWS: &str = "--internal-parse-workflows";

const FULL: &str = "not parsed: the report is full";
const SPENT: &str = "not parsed: the scan's time is spent";
const UNFINISHED: &str = "the parser could not finish";
const TOO_MANY_FACTS: &str = "not listed: its facts take more than 32 MiB";
const _: () = assert!(
    confine::MAX_ANSWER == 32 << 20,
    "TOO_MANY_FACTS names MAX_ANSWER"
);

/// One parsed workflow file: the facts the pass reads, and what in it the parser
/// did not read.
#[derive(Debug, Serialize, Deserialize)]
pub struct Workflow {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The event names under `on:` (`push`, `pull_request_target`, …).
    pub triggers: Vec<String>,
    /// `permissions:` as `scope: level`, or a single token (`write-all`); empty
    /// when the key is absent.
    pub permissions: Vec<String>,
    pub jobs: Vec<Job>,
    /// Every construct in this file outside the parser's subset, and every line
    /// it did not read, with its line: empty only when the whole file was read.
    pub unknown: Vec<Unknown>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub line: usize,
    #[serde(rename = "if", skip_serializing_if = "Option::is_none")]
    pub cond: Option<String>,
    pub permissions: Vec<String>,
    /// A reusable workflow called at the job level (`uses:` on the job).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses: Option<String>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Step {
    pub line: usize,
    #[serde(rename = "if", skip_serializing_if = "Option::is_none")]
    pub cond: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    pub with: Vec<Pair>,
    pub env: Vec<Pair>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pair {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Unknown {
    pub line: usize,
    pub what: String,
}

/// The child's answer for one file: its workflow, or why it is skipped.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Answer {
    Workflow(Workflow),
    Skipped(String),
}

/// Parse every `*.yml` and `*.yaml` file directly in the directory `dir` (a path
/// relative to the working directory), each in a child of this binary started by
/// the path it runs from (`confine::Parser`) and given `confine::PARSE_TIME`, as
/// `scan_workflows_with` does with `cap` bytes left of a report printed `pretty` or
/// compact, until `until`.
pub fn scan_workflows(
    dir: &Path,
    cap: usize,
    pretty: bool,
    until: Option<Instant>,
) -> io::Result<(Vec<Workflow>, Vec<Skipped>)> {
    let mut parser = confine::Parser::with(&confine::own_exe()?, &[OsStr::new(PARSE_WORKFLOWS)]);
    Ok(scan_workflows_with(dir, cap, pretty, until, &mut |bytes| {
        parser.parse(bytes, confine::PARSE_TIME)
    }))
}

/// Parse every `*.yml` and `*.yaml` file directly in the directory `dir`, in byte
/// order of their names, each file's bytes handed to `parse`, which gives the
/// answer `parse_stdin` gives for them, or `None` when the parser could not
/// finish. Returns the workflows parsed and the files skipped. GitHub reads
/// workflows only from the directory itself, so the pass does not recurse; it
/// follows no symbolic link, and reads only regular files with one name of at
/// most 4 MiB, each opened from the directory's descriptor without following a
/// link. A `*.y*ml` entry that is a link or not a regular file, one that is not
/// UTF-8, one with a second YAML document or more structure than the caps allow,
/// one the parser could not finish, and every file past `MAX_WF_FILES`, is listed
/// in `skipped` with the reason. The workflows take about `cap` bytes at most of a
/// report printed `pretty` or compact (`printed_size`): the file whose facts would
/// take them past it, and each file after it, is in `skipped` as not parsed. No
/// file is handed to `parse` at or past `until` (never, with `None`): each is in
/// `skipped` as not parsed, while a file handed to it before then keeps the time
/// `parse` gives it.
pub fn scan_workflows_with(
    dir: &Path,
    cap: usize,
    pretty: bool,
    until: Option<Instant>,
    parse: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> (Vec<Workflow>, Vec<Skipped>) {
    let mut workflows = Vec::new();
    let mut skipped = Vec::new();
    let unreadable = |e: &io::Error| Skipped {
        file: dir.display().to_string(),
        reason: format!("cannot be read: {}", os_message(e)),
    };
    let fd = match crate::scan::open_root(dir) {
        Ok(fd) => fd,
        Err(e) => {
            skipped.push(unreadable(&e));
            return (workflows, skipped);
        }
    };
    let names = match confine::names(&fd) {
        Ok(names) => names,
        Err(e) => {
            skipped.push(unreadable(&e));
            return (workflows, skipped);
        }
    };
    let mut parsed = 0usize;
    let mut size = 0usize;
    let mut full = false;
    for name in names {
        if !(name.ends_with(b".yml") || name.ends_with(b".yaml")) {
            continue;
        }
        let label = dir.join(OsStr::from_bytes(&name)).display().to_string();
        let mut skip = |reason: String| {
            skipped.push(Skipped {
                file: label.clone(),
                reason,
            })
        };
        match confine::kind_at(fd.as_raw_fd(), &name) {
            Ok(libc::S_IFREG) => {}
            Ok(libc::S_IFLNK) => {
                skip("a symbolic link, not followed".to_string());
                continue;
            }
            Ok(_) => {
                skip("not a regular file".to_string());
                continue;
            }
            Err(e) => {
                skip(format!("cannot be read: {}", os_message(&e)));
                continue;
            }
        }
        if parsed >= MAX_WF_FILES {
            skip("not parsed: too many workflow files".to_string());
            continue;
        }
        parsed += 1;
        if full {
            skip(FULL.to_string());
            continue;
        }
        if until.is_some_and(|until| Instant::now() >= until) {
            skip(SPENT.to_string());
            continue;
        }
        let answer = crate::scan::read_bytes(fd.as_raw_fd(), &name).and_then(|bytes| {
            parse(&bytes)
                .and_then(|out| serde_json::from_slice::<Answer>(&out).ok())
                .ok_or_else(|| UNFINISHED.to_string())
        });
        match answer {
            Ok(Answer::Workflow(mut wf)) => {
                wf.file = label.clone();
                // A workflow sits two levels into the report, a comma after it.
                let cost = printed_size(&wf, pretty, 2).saturating_add(1);
                if size.saturating_add(cost) > cap {
                    full = true;
                    skip(FULL.to_string());
                    continue;
                }
                size += cost;
                workflows.push(wf);
            }
            Ok(Answer::Skipped(reason)) | Err(reason) => skip(reason),
        }
    }
    (workflows, skipped)
}

/// The bytes `value` takes as audit-scan prints it, `depth` levels into its
/// report: its JSON as `serde_json` writes it, compact or `pretty` (where each
/// line takes two spaces more for each level), with each character
/// `confine::json_text` escapes counted as its escape. Counted, not kept.
pub fn printed_size<T: Serialize + ?Sized>(value: &T, pretty: bool, depth: usize) -> usize {
    struct Count {
        bytes: usize,
        indent: usize,
    }
    impl Write for Count {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // serde_json writes a whole number of characters at a time; should a
            // write not hold one, the count fails, past any cap.
            let text = std::str::from_utf8(buf).map_err(io::Error::other)?;
            let lines = text.bytes().filter(|&b| b == b'\n').count();
            self.bytes = self
                .bytes
                .saturating_add(printed_len(text))
                .saturating_add(lines.saturating_mul(self.indent));
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count {
        bytes: 0,
        indent: if pretty { depth.saturating_mul(2) } else { 0 },
    };
    let written = if pretty {
        serde_json::to_writer_pretty(&mut count, value)
    } else {
        serde_json::to_writer(&mut count, value)
    };
    match written {
        Ok(()) => count.bytes,
        Err(_) => usize::MAX,
    }
}

/// The bytes the JSON text `json` takes once `confine::json_text` has escaped it:
/// six for each UTF-16 unit of a character it writes as a `\u` escape.
fn printed_len(json: &str) -> usize {
    json.chars()
        .filter(|&c| c >= '\u{7f}' && confine::unsafe_char(c))
        .fold(json.len(), |len, c| {
            len.saturating_add(6 * c.len_utf16() - c.len_utf8())
        })
}

/// audit-scan started as its own child to parse workflow files
/// (`PARSE_WORKFLOWS`): each file's bytes, at most `MAX_FILE`, come on stdin as a
/// frame (their length in 8 bytes, little-endian, then the bytes), and the answer
/// for that one file goes to stdout the same way: its workflow, with the file
/// named `""` for the parent to name, or why it is skipped. It reads and writes
/// nothing else, and ends at the end of its stdin. Each file may use twice
/// `confine::PARSE_TIME` of CPU (`parse_frames`).
pub fn parse_stdin() -> io::Result<()> {
    parse_frames(
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
        confine::PARSE_TIME * 2,
    )
}

/// `parse_stdin`, from `input` to `output`, each file given `cpu`: before each
/// frame is read, this process's CPU limit is set to the CPU it has used so far and
/// `cpu` more (`confine::limit_cpu`), so a child whose parent is gone, with no one
/// left to kill it, dies once one file has used that.
pub fn parse_frames(input: &mut dyn Read, output: &mut dyn Write, cpu: Duration) -> io::Result<()> {
    loop {
        confine::limit_cpu(cpu)?;
        let mut head = [0u8; 8];
        if input.read(&mut head[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut head[1..])?;
        let len = u64::from_le_bytes(head);
        if len > confine::MAX_FILE {
            return Err(io::Error::other("a file larger than 4 MiB"));
        }
        let mut bytes = vec![0u8; len as usize];
        input.read_exact(&mut bytes)?;
        let json = answer(&bytes, confine::MAX_ANSWER)?;
        output.write_all(&(json.len() as u64).to_le_bytes())?;
        output.write_all(&json)?;
        output.flush()?;
    }
}

/// The answer for one file's bytes, as JSON that takes at most `cap` bytes once
/// audit-scan prints it (`printed_len`): a workflow whose facts take more is
/// skipped instead.
fn answer(bytes: &[u8], cap: usize) -> io::Result<Vec<u8>> {
    let answer = match std::str::from_utf8(bytes) {
        Err(_) => Answer::Skipped("not UTF-8".to_string()),
        Ok(text) => match parse_workflow("", text) {
            Ok(wf) => Answer::Workflow(wf),
            Err(reason) => Answer::Skipped(reason),
        },
    };
    let json = serde_json::to_string(&answer).map_err(io::Error::other)?;
    if printed_len(&json) <= cap {
        return Ok(json.into_bytes());
    }
    serde_json::to_vec(&Answer::Skipped(TOO_MANY_FACTS.to_string())).map_err(io::Error::other)
}

/// Parse one workflow source into its facts, the file named `label`. `Err(reason)`
/// means the file is skipped whole: it is not a single YAML mapping, it holds a
/// second document, or it holds more structure than the caps allow.
pub fn parse_workflow(label: &str, source: &str) -> Result<Workflow, String> {
    let normal = normalize(source);
    let (text, cut) = cut_at_odd_char(&normal);
    let src = Src::new(text);
    let mut p = P {
        src: &src,
        end: src.count(),
        pos: 0,
        nodes: 0,
        truncated: false,
        stopped: false,
        unknown: Vec::new(),
    };
    if let Some((no, what)) = cut {
        p.mark(no, &format!("{what}: not read from line {no} to the end"));
    }
    let inline = p.document()?;
    let root = match inline {
        Some(li) => p.inline_root(li),
        None => p.block(0, 0),
    };
    p.finish();
    if p.truncated {
        return Err(format!(
            "holds more structure than the parser lists (over {MAX_WF_NODES} nodes)"
        ));
    }
    match root.kind {
        NodeKind::Map(entries) => Ok(build(label, entries, p.unknown)),
        NodeKind::Unknown => Ok(build(label, Vec::new(), p.unknown)),
        NodeKind::Null if !p.unknown.is_empty() => Ok(build(label, Vec::new(), p.unknown)),
        _ => Err("not a YAML mapping".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Characters and lines
// ---------------------------------------------------------------------------

/// The source with one leading byte order mark dropped and every line break
/// (`\r\n`, `\r`, `\n`, as YAML reads them) written as `\n`.
fn normalize(source: &str) -> String {
    let s = source.strip_prefix('\u{feff}').unwrap_or(source);
    if s.contains('\r') {
        s.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        s.to_string()
    }
}

/// The text up to the line holding the first character YAML parsers refuse or
/// read differently (a control character, a NEL, LS or PS, which YAML 1.1 parsers
/// read as a line break, a byte order mark past the start), and that line's number
/// and what it holds; the whole text when there is none.
fn cut_at_odd_char(text: &str) -> (&str, Option<(usize, &'static str)>) {
    for (at, c) in text.char_indices() {
        let what = match c {
            '\t' | '\n' | ' '..='~' => continue,
            '\u{85}' | '\u{2028}' | '\u{2029}' => {
                "a NEL, LS or PS character, which YAML 1.1 parsers read as a line break"
            }
            '\u{feff}' => "a byte order mark past the start of the file",
            '\0'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{fffe}' | '\u{ffff}' => {
                "a control character YAML does not allow"
            }
            _ => continue,
        };
        let start = text[..at].rfind('\n').map_or(0, |i| i + 1);
        let no = text[..start].matches('\n').count() + 1;
        return (&text[..start], Some((no, what)));
    }
    (text, None)
}

/// The source's lines: where each starts, and one past the end of the last.
struct Src<'s> {
    text: &'s str,
    starts: Vec<usize>,
}

/// One line: its index, its indentation (leading spaces) and the text past it.
#[derive(Clone, Copy)]
struct Line<'s> {
    index: usize,
    indent: usize,
    rest: &'s str,
}

impl<'s> Src<'s> {
    fn new(text: &'s str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            text.bytes()
                .enumerate()
                .filter(|&(_, b)| b == b'\n')
                .map(|(i, _)| i + 1),
        );
        starts.push(text.len() + 1);
        Src { text, starts }
    }

    fn count(&self) -> usize {
        self.starts.len() - 1
    }

    fn end_of(&self, index: usize) -> usize {
        self.starts[index + 1] - 1
    }

    fn line(&self, index: usize) -> Line<'s> {
        let raw = &self.text[self.starts[index]..self.end_of(index)];
        let rest = raw.trim_start_matches(' ');
        Line {
            index,
            indent: raw.len() - rest.len(),
            rest,
        }
    }

    /// The index of the line holding byte `at`.
    fn line_of(&self, at: usize) -> usize {
        match self.starts.binary_search(&at) {
            Ok(i) => i,
            Err(i) => i - 1,
        }
    }

    /// Where `s`, a slice of the text, starts in it.
    fn offset(&self, s: &str) -> usize {
        s.as_ptr() as usize - self.text.as_ptr() as usize
    }

    /// The column `s`, a slice of the text, starts at in its line.
    fn column(&self, s: &str) -> usize {
        let at = self.offset(s);
        at - self.starts[self.line_of(at)]
    }
}

impl Line<'_> {
    fn no(&self) -> usize {
        self.index + 1
    }

    fn blank(&self) -> bool {
        self.rest.bytes().all(|b| b == b' ' || b == b'\t')
    }

    fn comment(&self) -> bool {
        self.rest.trim_start_matches([' ', '\t']).starts_with('#')
    }

    fn skippable(&self) -> bool {
        self.blank() || self.comment()
    }

    /// A tab right after the leading spaces of a line with content.
    fn tabbed(&self) -> bool {
        self.rest.starts_with('\t')
    }
}

/// A line that opens a block sequence entry: `-` alone, or `-` then a space or a
/// tab.
fn is_seq_line(t: &str) -> bool {
    let b = t.as_bytes();
    b.first() == Some(&b'-') && (b.len() == 1 || matches!(b[1], b' ' | b'\t'))
}

/// `line N`, or `lines N-M` for what runs from line `no` to line `last`.
fn lines(no: usize, last: usize) -> String {
    if last == no {
        format!("line {no}")
    } else {
        format!("lines {no}-{last}")
    }
}

/// A scalar as the report keeps it, built a piece at a time: its whitespace
/// collapsed to single spaces, cut after `MAX_WF_SCALAR` characters with `...`.
/// Only what is kept is stored.
struct Clip {
    out: String,
    chars: usize,
    space: bool,
    cut: bool,
}

impl Clip {
    fn new() -> Self {
        Clip {
            out: String::new(),
            chars: 0,
            space: false,
            cut: false,
        }
    }

    fn push(&mut self, c: char) {
        if self.cut {
            return;
        }
        if c.is_whitespace() {
            self.space = self.chars > 0;
            return;
        }
        if self.space && self.chars < MAX_WF_SCALAR {
            self.out.push(' ');
            self.chars += 1;
        }
        self.space = false;
        if self.chars == MAX_WF_SCALAR {
            self.cut = true;
            return;
        }
        self.out.push(c);
        self.chars += 1;
    }

    fn push_str(&mut self, s: &str) {
        for c in s.chars() {
            if self.cut {
                return;
            }
            self.push(c);
        }
    }

    fn done(mut self) -> String {
        if self.cut {
            self.out.push_str("...");
        }
        self.out
    }
}

fn clipped(s: &str) -> String {
    let mut c = Clip::new();
    c.push_str(s);
    c.done()
}

// ---------------------------------------------------------------------------
// Scalars on their own
// ---------------------------------------------------------------------------

const BAD_ESCAPE: &str = "an escape YAML does not define";

/// Why a quoted scalar is not read: it does not close, or an escape at this byte
/// is not one YAML defines.
enum QuotedError {
    Unclosed,
    Escape(usize),
}

/// The quoted scalar `s` opens with (its first byte is `"` or `'`), read up to its
/// closing quote, on its line or later ones: its value, with every escape YAML 1.2
/// defines decoded and its line breaks folded, and how many bytes of `s` it spans.
fn quoted(s: &str) -> Result<(String, usize), QuotedError> {
    let b = s.as_bytes();
    let double = b[0] == b'"';
    let mut clip = Clip::new();
    let mut i = 1;
    loop {
        let Some(c) = s[i..].chars().next() else {
            return Err(QuotedError::Unclosed);
        };
        match c {
            '\'' if !double => {
                if b.get(i + 1) == Some(&b'\'') {
                    clip.push('\'');
                    i += 2;
                    continue;
                }
                return Ok((clip.done(), i + 1));
            }
            '"' if double => return Ok((clip.done(), i + 1)),
            '\\' if double => {
                let at = i;
                let Some(e) = s[i + 1..].chars().next() else {
                    return Err(QuotedError::Unclosed);
                };
                i += 1 + e.len_utf8();
                let decoded = match e {
                    '0' => '\0',
                    'a' => '\u{7}',
                    'b' => '\u{8}',
                    't' | '\t' => '\t',
                    'n' => '\n',
                    'v' => '\u{b}',
                    'f' => '\u{c}',
                    'r' => '\r',
                    'e' => '\u{1b}',
                    ' ' => ' ',
                    '"' => '"',
                    '/' => '/',
                    '\\' => '\\',
                    'N' => '\u{85}',
                    '_' => '\u{a0}',
                    'L' => '\u{2028}',
                    'P' => '\u{2029}',
                    'x' | 'u' | 'U' => {
                        let n = match e {
                            'x' => 2,
                            'u' => 4,
                            _ => 8,
                        };
                        let code = s
                            .get(i..i + n)
                            .filter(|h| h.bytes().all(|d| d.is_ascii_hexdigit()))
                            .and_then(|h| u32::from_str_radix(h, 16).ok())
                            .and_then(char::from_u32)
                            .ok_or(QuotedError::Escape(at))?;
                        i += n;
                        code
                    }
                    '\n' => {
                        // An escaped line break: the break, and the next line's
                        // leading whitespace, are dropped.
                        while matches!(b.get(i), Some(b' ' | b'\t')) {
                            i += 1;
                        }
                        continue;
                    }
                    _ => return Err(QuotedError::Escape(at)),
                };
                clip.push(decoded);
            }
            _ => {
                clip.push(c);
                i += c.len_utf8();
            }
        }
    }
}

/// A plain scalar's text on one line, up to a comment (a `#` after a space or a
/// tab) with its trailing whitespace dropped, and whether a comment ended it.
fn plain_line(t: &str) -> (&str, bool) {
    let b = t.as_bytes();
    for i in 1..b.len() {
        if b[i] == b'#' && matches!(b[i - 1], b' ' | b'\t') {
            return (t[..i].trim_end_matches([' ', '\t']), true);
        }
    }
    (t.trim_end_matches([' ', '\t']), false)
}

/// Whether a plain scalar's text holds `: ` (or a `:` that ends it), which YAML
/// reads as a mapping's value indicator, not as text.
fn holds_indicator(t: &str) -> bool {
    let b = t.as_bytes();
    (0..b.len()).any(|i| b[i] == b':' && (i + 1 == b.len() || matches!(b[i + 1], b' ' | b'\t')))
}

/// A plain key on a line: the text up to the first `:` that ends the line or is
/// followed by a space or a tab, before any comment, and the text after that `:`.
fn plain_key(t: &str) -> Option<(&str, &str)> {
    let b = t.as_bytes();
    for i in 0..b.len() {
        match b[i] {
            b':' if i + 1 == b.len() || matches!(b[i + 1], b' ' | b'\t') => {
                let key = t[..i].trim_end_matches([' ', '\t']);
                return (!key.is_empty()).then(|| (key, &t[i + 1..]));
            }
            b'#' if i > 0 && matches!(b[i - 1], b' ' | b'\t') => return None,
            _ => {}
        }
    }
    None
}

/// An anchor's, an alias's or a tag's text: up to whitespace or a flow indicator.
fn prop_word(s: &str) -> &str {
    let end = s
        .find([' ', '\t', '\n', ',', '[', ']', '{', '}'])
        .unwrap_or(s.len());
    &s[..end]
}

fn flow_indicator(b: u8) -> bool {
    matches!(b, b',' | b'[' | b']' | b'{' | b'}')
}

// ---------------------------------------------------------------------------
// The generic node tree
// ---------------------------------------------------------------------------

struct Node {
    line: usize,
    kind: NodeKind,
}

enum NodeKind {
    Scalar(String),
    Map(Vec<Entry>),
    Seq(Vec<Node>),
    Null,
    /// A node the parser did not read; `unknown` says why.
    Unknown,
}

impl Node {
    fn null(line: usize) -> Node {
        Node {
            line,
            kind: NodeKind::Null,
        }
    }

    fn unknown(line: usize) -> Node {
        Node {
            line,
            kind: NodeKind::Unknown,
        }
    }

    fn scalar(line: usize, s: String) -> Node {
        Node {
            line,
            kind: NodeKind::Scalar(s),
        }
    }
}

struct Entry {
    key: String,
    line: usize,
    value: Node,
}

/// What a line opens with, where a mapping's key belongs.
enum Key<'s> {
    /// A key, the text after its `:`, and the anchors written before it.
    Pair(String, &'s str, Vec<&'s str>),
    /// A key the parser does not read (a merge key, an alias, a tagged key).
    Unread(String),
    /// An explicit key, `?`.
    Explicit,
    /// A key YAML refuses.
    Bad(&'static str),
    /// No key: the line is not a mapping entry.
    None,
}

/// What a node's text starts with, past its properties.
enum Props<'s> {
    /// The node's text past any anchors (listed) and the whitespace after them.
    Node(&'s str),
    /// A tag: the node is not read.
    Tag(String),
    /// An alias, and the text after it.
    Alias(String, &'s str),
}

type FlowError = (usize, &'static str);

const UNCLOSED_FLOW: &str = "a flow collection that does not close";

/// A parse under way: the lines, the first line not to read, the next line to
/// read, the nodes counted, and what was not read. Once `stopped`, nothing more is
/// read.
struct P<'s> {
    src: &'s Src<'s>,
    end: usize,
    pos: usize,
    nodes: usize,
    truncated: bool,
    stopped: bool,
    unknown: Vec<Unknown>,
}

impl<'s> P<'s> {
    fn peek(&self) -> Option<Line<'s>> {
        (self.pos < self.end).then(|| self.src.line(self.pos))
    }

    fn skip_blank(&mut self) {
        while self.pos < self.end && self.src.line(self.pos).skippable() {
            self.pos += 1;
        }
    }

    /// Count a node; past the cap the parse is truncated and stops.
    fn count(&mut self) -> bool {
        self.nodes += 1;
        if self.nodes > MAX_WF_NODES {
            self.truncated = true;
            self.stopped = true;
            self.pos = self.end;
            return false;
        }
        true
    }

    fn mark(&mut self, line: usize, what: &str) {
        if self.unknown.len() < MAX_WF_NODES {
            self.unknown.push(Unknown {
                line,
                what: what.to_string(),
            });
        }
    }

    /// The read ends at line `no`: nothing from it to the end of the file is read.
    fn fail(&mut self, no: usize, what: &str) -> Node {
        if !self.stopped {
            self.mark(no, &format!("{what}: not read from line {no} to the end"));
            self.stopped = true;
        }
        self.pos = self.end;
        Node::unknown(no)
    }

    /// `fail` for a node that starts at line `no` and goes wrong at byte `at`.
    fn fail_at(&mut self, no: usize, at: usize, what: &str) -> Node {
        let line = self.src.line_of(at) + 1;
        if line == no {
            self.fail(no, what)
        } else {
            self.fail(no, &format!("{what} (line {line})"))
        }
    }

    /// The lines from the next one that belong to a node at line `no` the parser
    /// does not read — blank and comment lines, lines indented `min` or more, and,
    /// with `seq`, sequence entries at that indentation — passed over, and listed
    /// with `what`.
    fn unread(&mut self, no: usize, min: usize, seq: Option<usize>, what: &str) -> Node {
        let mut last = no;
        while let Some(l) = self.peek() {
            if !l.skippable() {
                if !(l.indent >= min || (seq == Some(l.indent) && is_seq_line(l.rest))) {
                    break;
                }
                last = l.no();
            }
            self.pos += 1;
        }
        self.mark(no, &format!("{what}: {} not read", lines(no, last)));
        Node::unknown(no)
    }

    /// Directives and document markers: a `%` directive before the document is
    /// listed; one leading `---` opens it, and the root may start on that line
    /// (its index is returned); a `...` ends it. A second document is refused.
    fn document(&mut self) -> Result<Option<usize>, String> {
        let marker = |l: &Line, m: &str| {
            l.indent == 0
                && l.rest.starts_with(m)
                && matches!(l.rest.as_bytes().get(3), None | Some(b' ' | b'\t'))
        };
        let mut started = false;
        let mut content = false;
        let mut inline = None;
        let mut i = 0;
        while i < self.end {
            let l = self.src.line(i);
            i += 1;
            if l.skippable() {
                continue;
            }
            if marker(&l, "...") {
                let after = l.rest[3..].trim_start_matches([' ', '\t']);
                if !(after.is_empty() || after.starts_with('#'))
                    || (i..self.end).any(|j| !self.src.line(j).skippable())
                {
                    return Err("holds more than one YAML document".to_string());
                }
                self.end = l.index;
                break;
            }
            if marker(&l, "---") {
                if started || content {
                    return Err("holds more than one YAML document".to_string());
                }
                started = true;
                self.pos = i;
                let after = l.rest[3..].trim_start_matches([' ', '\t']);
                if !after.is_empty() && !after.starts_with('#') {
                    inline = Some(l.index);
                    content = true;
                }
                continue;
            }
            if !started && !content && l.indent == 0 && l.rest.starts_with('%') {
                self.mark(l.no(), "a YAML directive");
                self.pos = i;
                continue;
            }
            content = true;
        }
        Ok(inline)
    }

    /// Nothing may be left once the root is read.
    fn finish(&mut self) {
        if self.stopped {
            return;
        }
        self.skip_blank();
        if let Some(l) = self.peek() {
            self.fail(l.no(), "a line the parser could not place");
        }
    }

    /// A node's anchors (each listed), and a tag or an alias, at the start of `t`.
    fn props(&mut self, mut t: &'s str, no: usize) -> Props<'s> {
        loop {
            match t.as_bytes().first() {
                Some(b'&') => {
                    let name = prop_word(&t[1..]);
                    self.anchor(no, name);
                    t = t[1 + name.len()..].trim_start_matches([' ', '\t']);
                }
                Some(b'!') => return Props::Tag(clipped(prop_word(t))),
                Some(b'*') => {
                    let name = prop_word(&t[1..]);
                    return Props::Alias(clipped(name), &t[1 + name.len()..]);
                }
                _ => return Props::Node(t),
            }
        }
    }

    fn anchor(&mut self, no: usize, name: &str) {
        self.mark(
            no,
            &format!(
                "an anchor (&{}): its node is read; an alias to it is not expanded",
                clipped(name)
            ),
        );
    }

    /// An alias node, `*name`, at line `no`, followed by `after` on its line.
    fn alias(&mut self, no: usize, name: &str, after: &str) -> Node {
        let rest = after.trim_start_matches([' ', '\t']);
        if !(rest.is_empty() || rest.starts_with('#')) {
            return self.fail(no, "content after an alias");
        }
        self.mark(no, &format!("an alias (*{name}), not expanded"));
        Node::unknown(no)
    }

    /// What `t`, at a mapping key's place, opens with.
    fn key_of(&self, t: &'s str) -> Key<'s> {
        let mut t = t;
        let mut anchors = Vec::new();
        let mut tag = None;
        loop {
            match t.as_bytes().first() {
                Some(b'&') => {
                    let name = prop_word(&t[1..]);
                    anchors.push(name);
                    t = t[1 + name.len()..].trim_start_matches([' ', '\t']);
                }
                Some(b'!') if tag.is_none() => {
                    let word = prop_word(t);
                    tag = Some(clipped(word));
                    t = t[word.len()..].trim_start_matches([' ', '\t']);
                }
                _ => break,
            }
        }
        let b = t.as_bytes();
        let key = match b.first() {
            None => return Key::None,
            Some(b'?') if b.len() == 1 || matches!(b[1], b' ' | b'\t') => return Key::Explicit,
            Some(b'"' | b'\'') => match quoted(t) {
                Err(QuotedError::Unclosed) => return Key::None,
                Err(QuotedError::Escape(_)) => return Key::Bad(BAD_ESCAPE),
                Ok((key, len)) => {
                    let after = t[len..].trim_start_matches([' ', '\t']);
                    match after.strip_prefix(':') {
                        Some(rest) if rest.is_empty() || rest.starts_with([' ', '\t']) => {
                            (key, rest)
                        }
                        _ => return Key::None,
                    }
                }
            },
            Some(b'*') => {
                let name = prop_word(&t[1..]);
                let after = t[1 + name.len()..].trim_start_matches([' ', '\t']);
                return match after.strip_prefix(':') {
                    Some(rest) if rest.is_empty() || rest.starts_with([' ', '\t']) => {
                        Key::Unread(format!("an alias (*{}) as a key", clipped(name)))
                    }
                    _ => Key::None,
                };
            }
            Some(b'[' | b'{' | b'|' | b'>' | b'%' | b'@' | b'`' | b',' | b']' | b'}' | b'#') => {
                return Key::None
            }
            Some(b'-') if is_seq_line(t) => return Key::None,
            _ => match plain_key(t) {
                Some(("<<", _)) if tag.is_none() => {
                    return Key::Unread("a merge key (<<)".to_string())
                }
                Some((key, rest)) => (clipped(key), rest),
                None => return Key::None,
            },
        };
        match tag {
            Some(tag) => Key::Unread(format!("a tag ({tag}) on a key")),
            None => Key::Pair(key.0, key.1, anchors),
        }
    }

    /// The root on the `---` line at index `li`.
    fn inline_root(&mut self, li: usize) -> Node {
        let no = li + 1;
        let t = self.src.line(li).rest[3..].trim_start_matches([' ', '\t']);
        self.pos = no;
        let t = match self.props(t, no) {
            Props::Node(t) => t,
            Props::Tag(tag) => return self.unread(no, 0, None, &format!("a tag ({tag})")),
            Props::Alias(name, after) => return self.alias(no, &name, after),
        };
        if t.is_empty() || t.starts_with('#') {
            return self.block(0, 1);
        }
        if is_seq_line(t) || !matches!(self.key_of(t), Key::None) {
            return self.fail(no, "a block collection on the `---` line");
        }
        self.inline_value(t, no, 0, 0)
    }

    /// A node on its own lines, indented `min` or more: a block sequence, a block
    /// mapping, or a scalar or flow collection, whichever its first line opens.
    fn block(&mut self, min: usize, depth: usize) -> Node {
        self.skip_blank();
        let Some(l) = self.peek() else {
            return Node::null(0);
        };
        let no = l.no();
        if l.indent < min {
            return Node::null(no);
        }
        if depth > MAX_WF_DEPTH {
            return self.unread(no, min, None, "nested too deeply");
        }
        if l.tabbed() {
            return self.fail(no, "a tab in indentation");
        }
        let t = match self.props(l.rest, no) {
            Props::Node(t) => t,
            Props::Tag(tag) => return self.unread(no, min, None, &format!("a tag ({tag})")),
            Props::Alias(name, after) => {
                self.pos = l.index + 1;
                return self.alias(no, &name, after);
            }
        };
        if t.is_empty() || t.starts_with('#') {
            // Properties alone on their line: the node is on the lines below.
            self.pos = l.index + 1;
            return self.block(min, depth + 1);
        }
        if is_seq_line(t) {
            if t.len() != l.rest.len() {
                return self.fail(no, "properties before a sequence entry");
            }
            return self.seq(l.indent, depth, None);
        }
        if !matches!(self.key_of(t), Key::None) {
            return self.map(l.indent, depth, Some((l.index, t)));
        }
        self.pos = l.index + 1;
        self.inline_value(t, no, min, depth)
    }

    /// A block mapping whose keys sit at column `indent`, its first entry `first`
    /// when that opens on a line read already (a sequence entry's `- key: value`).
    fn map(&mut self, indent: usize, depth: usize, first: Option<(usize, &'s str)>) -> Node {
        let line = first.map_or_else(|| self.peek().map_or(0, |l| l.no()), |(li, _)| li + 1);
        let mut entries = Vec::new();
        if let Some((li, t)) = first {
            self.entry(li, indent, t, depth, &mut entries);
        }
        loop {
            self.skip_blank();
            let Some(l) = self.peek() else { break };
            if l.indent < indent {
                break;
            }
            if l.indent > indent {
                self.fail(l.no(), "a line indented deeper than the entries before it");
                break;
            }
            if l.tabbed() {
                self.fail(l.no(), "a tab in indentation");
                break;
            }
            if is_seq_line(l.rest) {
                self.fail(l.no(), "a sequence entry inside a mapping");
                break;
            }
            self.entry(l.index, indent, l.rest, depth, &mut entries);
        }
        Node {
            line,
            kind: NodeKind::Map(entries),
        }
    }

    /// One mapping entry, `t` on the line at index `li`, its key at column
    /// `indent`.
    fn entry(
        &mut self,
        li: usize,
        indent: usize,
        t: &'s str,
        depth: usize,
        entries: &mut Vec<Entry>,
    ) {
        let no = li + 1;
        self.pos = no;
        if !self.count() {
            return;
        }
        match self.key_of(t) {
            Key::Pair(key, rest, anchors) => {
                for name in anchors {
                    self.anchor(no, name);
                }
                let value = self.entry_value(rest, no, indent, depth + 1);
                entries.push(Entry {
                    key,
                    line: no,
                    value,
                });
            }
            Key::Unread(what) => {
                self.unread(no, indent + 1, Some(indent), &what);
            }
            Key::Explicit => self.explicit(no, indent),
            Key::Bad(what) => {
                self.fail(no, what);
            }
            Key::None => {
                self.fail(no, "a line that is not a `key: value` entry");
            }
        }
    }

    /// An explicit `?` entry at line `no`, its `?` at column `indent`: its key's
    /// lines, then a `:` line at that column and its value's lines, are listed and
    /// not read.
    fn explicit(&mut self, no: usize, indent: usize) {
        let mut last = no;
        let mut value = false;
        while let Some(l) = self.peek() {
            if !l.skippable() {
                let colon = l.rest == ":" || l.rest.starts_with(": ") || l.rest.starts_with(":\t");
                let deeper =
                    l.indent > indent || (l.indent == indent && value && is_seq_line(l.rest));
                if !deeper && !(l.indent == indent && !value && colon) {
                    break;
                }
                value |= !deeper;
                last = l.no();
            }
            self.pos += 1;
        }
        self.mark(
            no,
            &format!("an explicit key (?): {} not read", lines(no, last)),
        );
    }

    /// A mapping entry's value: the text `rest` after its key's `:` on line `no`,
    /// or, when that is empty, the node on the lines below (a sequence at the key's
    /// column `key_indent` or deeper, anything else deeper).
    fn entry_value(&mut self, rest: &'s str, no: usize, key_indent: usize, depth: usize) -> Node {
        let min = key_indent + 1;
        if depth > MAX_WF_DEPTH {
            return self.unread(no, min, Some(key_indent), "nested too deeply");
        }
        let t = match self.props(rest.trim_start_matches([' ', '\t']), no) {
            Props::Node(t) => t,
            Props::Tag(tag) => {
                return self.unread(no, min, Some(key_indent), &format!("a tag ({tag})"))
            }
            Props::Alias(name, after) => return self.alias(no, &name, after),
        };
        if !(t.is_empty() || t.starts_with('#')) {
            return self.inline_value(t, no, min, depth);
        }
        self.skip_blank();
        match self.peek() {
            Some(l) if l.indent == key_indent && is_seq_line(l.rest) => {
                self.seq(key_indent, depth, None)
            }
            Some(l) if l.indent > key_indent => self.block(min, depth),
            _ => Node::null(no),
        }
    }

    /// A block sequence whose dashes sit at column `indent`, its first entry
    /// `first` when that opens on a line read already (`- - item`).
    fn seq(&mut self, indent: usize, depth: usize, first: Option<(usize, &'s str)>) -> Node {
        let line = first.map_or_else(|| self.peek().map_or(0, |l| l.no()), |(li, _)| li + 1);
        let mut items = Vec::new();
        let mut next = first;
        loop {
            let (li, t) = match next.take() {
                Some(item) => item,
                None => {
                    self.skip_blank();
                    let Some(l) = self.peek() else { break };
                    if l.indent < indent {
                        break;
                    }
                    if l.indent > indent {
                        self.fail(l.no(), "a line indented deeper than the entries before it");
                        break;
                    }
                    if l.tabbed() {
                        self.fail(l.no(), "a tab in indentation");
                        break;
                    }
                    if !is_seq_line(l.rest) {
                        break;
                    }
                    (l.index, l.rest)
                }
            };
            self.pos = li + 1;
            if !self.count() {
                break;
            }
            let item = self.item(li, indent, &t[1..], depth + 1);
            items.push(item);
        }
        Node {
            line,
            kind: NodeKind::Seq(items),
        }
    }

    /// A sequence entry: `after`, the text after its dash at column `dash` on the
    /// line at index `li`, or the node on the lines below.
    fn item(&mut self, li: usize, dash: usize, after: &'s str, depth: usize) -> Node {
        let no = li + 1;
        let min = dash + 1;
        if depth > MAX_WF_DEPTH {
            return self.unread(no, min, None, "nested too deeply");
        }
        let t = after.trim_start_matches(' ');
        let rest = t.trim_start_matches([' ', '\t']);
        if t.starts_with('\t') && !(rest.is_empty() || rest.starts_with('#')) {
            return self.fail(no, "a tab after a sequence entry's dash");
        }
        let column = if rest.is_empty() {
            0
        } else {
            self.src.column(rest)
        };
        let t = match self.props(rest, no) {
            Props::Node(t) => t,
            Props::Tag(tag) => return self.unread(no, min, None, &format!("a tag ({tag})")),
            Props::Alias(name, after) => return self.alias(no, &name, after),
        };
        if t.is_empty() || t.starts_with('#') {
            let node = self.block(min, depth);
            return match node.kind {
                NodeKind::Null => Node::null(no),
                _ => node,
            };
        }
        if is_seq_line(t) {
            if t.len() != rest.len() {
                return self.fail(no, "properties before a sequence entry");
            }
            return self.seq(column, depth, Some((li, t)));
        }
        if !matches!(self.key_of(t), Key::None) {
            return self.map(column, depth, Some((li, t)));
        }
        self.inline_value(t, no, min, depth)
    }

    /// A value that starts on line `no` with `t` (not empty, no comment, no
    /// properties): a block scalar, a flow collection, a quoted or a plain scalar.
    /// Lines that go on with it are indented `min` or more.
    fn inline_value(&mut self, t: &'s str, no: usize, min: usize, depth: usize) -> Node {
        let b = t.as_bytes();
        match b[0] {
            b'|' | b'>' => self.block_scalar(t, no, min),
            b'[' | b'{' => {
                let mut at = self.src.offset(t);
                match self.flow_node(&mut at, depth) {
                    Ok(node) if self.after_inline(at) => node,
                    Ok(_) => Node::unknown(no),
                    Err((at, what)) => self.fail_at(no, at, what),
                }
            }
            b'"' | b'\'' => {
                let at = self.src.offset(t);
                match quoted(&self.src.text[at..]) {
                    Ok((value, len)) if self.after_inline(at + len) => {
                        self.count();
                        Node::scalar(no, value)
                    }
                    Ok(_) => Node::unknown(no),
                    Err(QuotedError::Unclosed) => {
                        self.fail(no, "a quoted scalar that does not close")
                    }
                    Err(QuotedError::Escape(off)) => self.fail_at(no, at + off, BAD_ESCAPE),
                }
            }
            b'%' | b'@' | b'`' | b',' | b']' | b'}' => {
                self.fail(no, "a value that starts with a character YAML reserves")
            }
            b'-' | b'?' | b':' if b.len() == 1 || matches!(b[1], b' ' | b'\t') => {
                self.fail(no, "a `-`, `?` or `:` indicator where a value belongs")
            }
            _ => self.plain(t, no, min),
        }
    }

    /// The rest of the line holding byte `at`, where a flow collection or a quoted
    /// scalar ended, holds nothing but a comment; the read goes on with the next
    /// line. Otherwise the read ends there.
    fn after_inline(&mut self, at: usize) -> bool {
        let li = self.src.line_of(at);
        let rest = self.src.text[at..self.src.end_of(li)].trim_start_matches([' ', '\t']);
        if rest.is_empty() || rest.starts_with('#') {
            self.pos = li + 1;
            true
        } else {
            self.fail(li + 1, "content after a flow collection or a quoted scalar");
            false
        }
    }

    /// A plain scalar that starts on line `no` with `t`, and goes on over the
    /// lines below indented `min` or more, up to a comment.
    fn plain(&mut self, t: &'s str, no: usize, min: usize) -> Node {
        const COLON: &str = "a plain scalar holding `: `, which YAML reads as a key";
        let (first, mut ended) = plain_line(t);
        if holds_indicator(first) {
            return self.fail(no, COLON);
        }
        let mut clip = Clip::new();
        clip.push_str(first);
        self.pos = no;
        while !ended {
            let Some(l) = self.peek() else { break };
            if l.blank() {
                self.pos += 1;
                continue;
            }
            if l.indent < min || l.comment() {
                break;
            }
            let (piece, comment) = plain_line(l.rest.trim_start_matches([' ', '\t']));
            if holds_indicator(piece) {
                return self.fail(l.no(), COLON);
            }
            clip.push(' ');
            clip.push_str(piece);
            self.pos += 1;
            ended = comment;
        }
        self.count();
        Node::scalar(no, clip.done())
    }

    /// A `|` or `>` block scalar whose header `t` is on line `no`; its body is the
    /// lines below indented `min` or more, at the indentation its header gives or
    /// its first line of text has (a blank line before that one may not have more
    /// spaces). Literal (`|`) and folded (`>`) are kept alike, since the value's
    /// whitespace is collapsed.
    fn block_scalar(&mut self, t: &'s str, no: usize, min: usize) -> Node {
        const LEADING_BLANK: &str =
            "a block scalar's leading blank line indented more than its first line";
        let mut rest = &t[1..];
        let mut given = None;
        let mut chomp = false;
        loop {
            match rest.as_bytes().first() {
                Some(&d @ b'1'..=b'9') if given.is_none() => given = Some(usize::from(d - b'0')),
                Some(b'+' | b'-') if !chomp => chomp = true,
                _ => break,
            }
            rest = &rest[1..];
        }
        let rest = rest.trim_start_matches([' ', '\t']);
        if !(rest.is_empty() || rest.starts_with('#')) {
            return self.fail(no, "a block scalar header YAML does not define");
        }
        self.pos = no;
        let body = match given {
            Some(n) => Some(min + n - 1),
            None => {
                let first = (self.pos..self.end)
                    .map(|i| self.src.line(i))
                    .find(|l| !l.blank());
                let body = first.map(|l| l.indent).filter(|&indent| indent >= min);
                // YAML refuses a leading blank line with more spaces than the first
                // line of text; YAML 1.1 parsers take those spaces for the
                // indentation, and leave the text out of the scalar.
                let over = body.and_then(|body| {
                    (self.pos..self.end)
                        .map(|i| self.src.line(i))
                        .take_while(|l| l.blank())
                        .find(|l| l.indent > body)
                });
                if let Some(l) = over {
                    return self.fail(l.no(), LEADING_BLANK);
                }
                body
            }
        };
        let mut clip = Clip::new();
        while let Some(l) = self.peek() {
            if l.blank() {
                self.pos += 1;
                continue;
            }
            match body {
                Some(body) if l.indent >= body => {
                    clip.push('\n');
                    let raw = &self.src.text[self.src.starts[l.index]..self.src.end_of(l.index)];
                    clip.push_str(raw.get(body..).unwrap_or(""));
                    self.pos += 1;
                }
                _ if l.indent < min || l.comment() => break,
                _ => return self.fail(l.no(), "a block scalar line indented less than its first"),
            }
        }
        self.count();
        Node::scalar(no, clip.done())
    }

    // -----------------------------------------------------------------------
    // Flow collections, on one line or several
    // -----------------------------------------------------------------------

    /// Whitespace, line breaks and comments from byte `at`.
    fn ws(&self, at: &mut usize) {
        let b = self.src.text.as_bytes();
        while let Some(&c) = b.get(*at) {
            match c {
                b' ' | b'\t' | b'\n' => *at += 1,
                b'#' => {
                    while b.get(*at).is_some_and(|&c| c != b'\n') {
                        *at += 1;
                    }
                }
                _ => break,
            }
        }
    }

    /// Whether byte `at` is a `:` that indicates a value: followed by whitespace,
    /// a flow indicator or the end, or right after a quoted scalar or a flow
    /// collection (`json`).
    fn indicates_value(&self, at: usize, json: bool) -> bool {
        let b = self.src.text.as_bytes();
        b.get(at) == Some(&b':')
            && (json
                || b.get(at + 1)
                    .is_none_or(|&c| matches!(c, b' ' | b'\t' | b'\n') || flow_indicator(c)))
    }

    /// An explicit `?` at byte `at`, passed over with the whitespace after it.
    fn explicit_flow(&self, at: &mut usize) -> bool {
        let b = self.src.text.as_bytes();
        let alone = b
            .get(*at + 1)
            .is_none_or(|&c| matches!(c, b' ' | b'\t' | b'\n') || flow_indicator(c));
        if b.get(*at) != Some(&b'?') || !alone {
            return false;
        }
        *at += 1;
        self.ws(at);
        true
    }

    /// Whether the flow mapping key at byte `at`, past any anchors, is the plain
    /// scalar `<<`: a merge key, which YAML 1.1 parsers merge into the mapping. A
    /// quoted `"<<"` is a key like any other.
    fn merge_key(&self, mut at: usize) -> bool {
        let t = self.src.text;
        while t.as_bytes().get(at) == Some(&b'&') {
            at += prop_word(&t[at..]).len();
            self.ws(&mut at);
        }
        t[at..].starts_with("<<")
    }

    /// Whether byte `at` ends a flow entry: `,`, a closing bracket, or the end.
    fn entry_ends(&self, at: usize, close: u8) -> bool {
        self.src
            .text
            .as_bytes()
            .get(at)
            .is_none_or(|&c| c == b',' || c == close)
    }

    /// The flow node at byte `at`, which is passed over it.
    fn flow_node(&mut self, at: &mut usize, depth: usize) -> Result<Node, FlowError> {
        let t = self.src.text;
        let no = self.src.line_of(*at) + 1;
        if self.stopped {
            return Ok(Node::unknown(no));
        }
        let Some(c) = t[*at..].chars().next() else {
            return Err((*at, UNCLOSED_FLOW));
        };
        match c {
            '[' | '{' => {
                if depth > MAX_WF_DEPTH {
                    return Err((*at, "a flow collection nested too deeply"));
                }
                self.flow_collection(at, depth, c == '[')
            }
            '"' | '\'' => match quoted(&t[*at..]) {
                Ok((value, len)) => {
                    *at += len;
                    self.count();
                    Ok(Node::scalar(no, value))
                }
                Err(QuotedError::Unclosed) => Err((*at, "a quoted scalar that does not close")),
                Err(QuotedError::Escape(off)) => Err((*at + off, BAD_ESCAPE)),
            },
            '*' => {
                let name = prop_word(&t[*at + 1..]);
                *at += 1 + name.len();
                self.mark(no, &format!("an alias (*{}), not expanded", clipped(name)));
                Ok(Node::unknown(no))
            }
            '&' | '!' => {
                let mut tagged = false;
                while let Some(&p @ (b'&' | b'!')) = t.as_bytes().get(*at) {
                    let word = prop_word(&t[*at..]);
                    *at += word.len();
                    if p == b'&' {
                        self.anchor(no, &word[1..]);
                    } else {
                        tagged = true;
                        self.mark(
                            no,
                            &format!("a tag ({}): its node is not read", clipped(word)),
                        );
                    }
                    self.ws(at);
                }
                let node = if self.entry_ends(*at, b']') || self.entry_ends(*at, b'}') {
                    Node::null(no)
                } else {
                    self.flow_node(at, depth)?
                };
                Ok(if tagged { Node::unknown(no) } else { node })
            }
            '|' | '>' => Err((*at, "a block scalar inside a flow collection")),
            ',' | ']' | '}' => Err((*at, "an empty entry in a flow collection")),
            '%' | '@' | '`' => Err((*at, "a value that starts with a character YAML reserves")),
            '-' | '?' | ':'
                if t.as_bytes()
                    .get(*at + 1)
                    .is_none_or(|&c| matches!(c, b' ' | b'\t' | b'\n') || flow_indicator(c)) =>
            {
                Err((*at, "a `-`, `?` or `:` indicator where a value belongs"))
            }
            _ => Ok(self.flow_plain(at, no)),
        }
    }

    /// A flow sequence (`seq`) or mapping opening at byte `at`.
    fn flow_collection(
        &mut self,
        at: &mut usize,
        depth: usize,
        seq: bool,
    ) -> Result<Node, FlowError> {
        let start = *at;
        let no = self.src.line_of(start) + 1;
        let close = if seq { b']' } else { b'}' };
        *at += 1;
        self.count();
        let mut items = Vec::new();
        let mut entries = Vec::new();
        loop {
            self.ws(at);
            if self.stopped {
                return Ok(Node::unknown(no));
            }
            match self.src.text.as_bytes().get(*at) {
                None => return Err((start, UNCLOSED_FLOW)),
                Some(&c) if c == close => {
                    *at += 1;
                    break;
                }
                _ => {}
            }
            let line = self.src.line_of(*at) + 1;
            let explicit = self.explicit_flow(at);
            let key_at = *at;
            let first = self.src.text.as_bytes().get(*at).copied();
            let json = matches!(first, Some(b'"' | b'\'' | b'[' | b'{'));
            let key =
                if self.indicates_value(*at, false) || (explicit && self.entry_ends(*at, close)) {
                    Node::null(line)
                } else {
                    self.flow_node(at, depth + 1)?
                };
            self.ws(at);
            let value = if self.indicates_value(*at, json) {
                // An implicit key sits on one line, with its `:`.
                if !explicit && self.src.line_of(*at) + 1 != line {
                    return Err((*at, "a flow mapping key that spans lines"));
                }
                *at += 1;
                self.ws(at);
                Some(if self.entry_ends(*at, close) {
                    Node::null(line)
                } else {
                    self.flow_node(at, depth + 1)?
                })
            } else {
                None
            };
            self.count();
            if seq {
                if explicit || value.is_some() {
                    self.mark(
                        line,
                        "a mapping inside a flow sequence: its entry is not read",
                    );
                    items.push(Node::unknown(line));
                } else {
                    items.push(key);
                }
            } else {
                match key.kind {
                    NodeKind::Scalar(k) if !explicit && k == "<<" && self.merge_key(key_at) => {
                        let last = self.src.line_of(at.saturating_sub(1)) + 1;
                        self.mark(
                            line,
                            &format!("a merge key (<<): {} not read", lines(line, last)),
                        );
                    }
                    NodeKind::Scalar(k) if !explicit => entries.push(Entry {
                        key: k,
                        line,
                        value: value.unwrap_or(Node::null(line)),
                    }),
                    _ => self.mark(
                        line,
                        "a flow mapping key that is not a scalar: its entry is not read",
                    ),
                }
            }
            self.ws(at);
            match self.src.text.as_bytes().get(*at) {
                Some(b',') => *at += 1,
                Some(&c) if c == close => {
                    *at += 1;
                    break;
                }
                None => return Err((start, UNCLOSED_FLOW)),
                Some(_) if seq => {
                    return Err((*at, "a flow sequence entry not followed by , or ]"))
                }
                Some(_) => return Err((*at, "a flow mapping entry not followed by , or }")),
            }
        }
        let kind = if seq {
            NodeKind::Seq(items)
        } else {
            NodeKind::Map(entries)
        };
        Ok(Node { line: no, kind })
    }

    /// A plain scalar inside a flow collection, from byte `at`: up to a flow
    /// indicator, a `:` that indicates a value, or a comment, over line breaks.
    fn flow_plain(&mut self, at: &mut usize, no: usize) -> Node {
        let t = self.src.text;
        let b = t.as_bytes();
        let ends = |i: usize| match b.get(i) {
            None => true,
            Some(&c) if flow_indicator(c) || c == b'#' => true,
            Some(b':') => b
                .get(i + 1)
                .is_none_or(|&c| matches!(c, b' ' | b'\t' | b'\n') || flow_indicator(c)),
            _ => false,
        };
        let mut clip = Clip::new();
        let mut i = *at;
        let mut end = i;
        while let Some(c) = t[i..].chars().next() {
            match c {
                ' ' | '\t' | '\n' => {
                    let mut j = i;
                    while matches!(b.get(j), Some(b' ' | b'\t' | b'\n')) {
                        j += 1;
                    }
                    if ends(j) {
                        break;
                    }
                    clip.push(' ');
                    i = j;
                }
                ',' | '[' | ']' | '{' | '}' => break,
                ':' if ends(i) => break,
                _ => {
                    clip.push(c);
                    i += c.len_utf8();
                    end = i;
                }
            }
        }
        *at = end;
        self.count();
        Node::scalar(no, clip.done())
    }
}

// ---------------------------------------------------------------------------
// The node tree mapped to workflow facts
// ---------------------------------------------------------------------------

/// The facts of the modeled keys an entry list holds. A modeled key written twice
/// is listed in `unknown`, since YAML parsers read a repeated key differently,
/// and the facts of both are kept.
fn repeated(
    key: &str,
    line: usize,
    names: &[&str],
    seen: &mut Vec<String>,
    unknown: &mut Vec<Unknown>,
) {
    if !names.contains(&key) {
        return;
    }
    if seen.iter().any(|s| s == key) {
        unknown.push(Unknown {
            line,
            what: format!("a second `{key}` key, which YAML parsers read differently"),
        });
    } else {
        seen.push(key.to_string());
    }
}

/// A modeled key's value that is not the kind GitHub reads there is listed.
fn not_a(key: &str, line: usize, what: &str, unknown: &mut Vec<Unknown>) {
    unknown.push(Unknown {
        line,
        what: format!("a `{key}` value that is not {what}"),
    });
}

fn build(label: &str, entries: Vec<Entry>, mut unknown: Vec<Unknown>) -> Workflow {
    let mut wf = Workflow {
        file: label.to_string(),
        name: None,
        triggers: Vec::new(),
        permissions: Vec::new(),
        jobs: Vec::new(),
        unknown: Vec::new(),
    };
    let mut seen = Vec::new();
    for Entry { key, line, value } in entries {
        repeated(
            &key,
            line,
            &["name", "on", "permissions", "jobs"],
            &mut seen,
            &mut unknown,
        );
        match key.as_str() {
            "name" => {
                if let Some(s) = text(&key, &value, &mut unknown) {
                    wf.name.get_or_insert(s);
                }
            }
            "on" => events(&value, &mut wf.triggers, &mut unknown),
            "permissions" => perms(&value, &mut wf.permissions, &mut unknown),
            "jobs" => match value.kind {
                NodeKind::Map(jobs) => wf
                    .jobs
                    .extend(jobs.into_iter().map(|j| job(j, &mut unknown))),
                NodeKind::Null | NodeKind::Unknown => {}
                _ => not_a("jobs", value.line, "a mapping", &mut unknown),
            },
            _ => {}
        }
    }
    unknown.sort_by_key(|u| u.line);
    wf.unknown = unknown;
    wf
}

/// A scalar's text; `None` for no value, and for a collection, which is listed.
fn text(key: &str, node: &Node, unknown: &mut Vec<Unknown>) -> Option<String> {
    match &node.kind {
        NodeKind::Scalar(s) => Some(s.clone()),
        NodeKind::Null | NodeKind::Unknown => None,
        NodeKind::Map(_) | NodeKind::Seq(_) => {
            not_a(key, node.line, "a scalar", unknown);
            None
        }
    }
}

fn events(node: &Node, out: &mut Vec<String>, unknown: &mut Vec<Unknown>) {
    match &node.kind {
        NodeKind::Scalar(s) => out.push(s.clone()),
        NodeKind::Seq(items) => {
            for item in items {
                out.extend(text("on", item, unknown));
            }
        }
        NodeKind::Map(entries) => out.extend(entries.iter().map(|e| e.key.clone())),
        NodeKind::Null | NodeKind::Unknown => {}
    }
}

fn perms(node: &Node, out: &mut Vec<String>, unknown: &mut Vec<Unknown>) {
    match &node.kind {
        NodeKind::Scalar(s) => out.push(s.clone()),
        NodeKind::Map(entries) => {
            for e in entries {
                out.push(match text("permissions", &e.value, unknown) {
                    Some(v) => format!("{}: {}", e.key, v),
                    None => e.key.clone(),
                });
            }
        }
        NodeKind::Seq(_) => not_a("permissions", node.line, "a mapping or a scalar", unknown),
        NodeKind::Null | NodeKind::Unknown => {}
    }
}

fn job(entry: Entry, unknown: &mut Vec<Unknown>) -> Job {
    let mut j = Job {
        id: entry.key,
        line: entry.line,
        cond: None,
        permissions: Vec::new(),
        uses: None,
        steps: Vec::new(),
    };
    match entry.value.kind {
        NodeKind::Map(entries) => {
            let mut seen = Vec::new();
            for Entry { key, line, value } in entries {
                repeated(
                    &key,
                    line,
                    &["if", "permissions", "uses", "steps"],
                    &mut seen,
                    unknown,
                );
                match key.as_str() {
                    "if" => j.cond = j.cond.take().or(text(&key, &value, unknown)),
                    "permissions" => perms(&value, &mut j.permissions, unknown),
                    "uses" => j.uses = j.uses.take().or(text(&key, &value, unknown)),
                    "steps" => match value.kind {
                        NodeKind::Seq(items) => j
                            .steps
                            .extend(items.into_iter().map(|item| step(item, unknown))),
                        NodeKind::Null | NodeKind::Unknown => {}
                        _ => not_a("steps", value.line, "a sequence", unknown),
                    },
                    _ => {}
                }
            }
        }
        NodeKind::Null | NodeKind::Unknown => {}
        _ => not_a(&j.id, entry.value.line, "a mapping", unknown),
    }
    j
}

fn step(node: Node, unknown: &mut Vec<Unknown>) -> Step {
    let mut s = Step {
        line: node.line,
        cond: None,
        uses: None,
        run: None,
        with: Vec::new(),
        env: Vec::new(),
    };
    match node.kind {
        NodeKind::Map(entries) => {
            let mut seen = Vec::new();
            for Entry { key, line, value } in entries {
                repeated(
                    &key,
                    line,
                    &["if", "uses", "run", "with", "env"],
                    &mut seen,
                    unknown,
                );
                match key.as_str() {
                    "if" => s.cond = s.cond.take().or(text(&key, &value, unknown)),
                    "uses" => s.uses = s.uses.take().or(text(&key, &value, unknown)),
                    "run" => s.run = s.run.take().or(text(&key, &value, unknown)),
                    "with" => pairs(&key, &value, &mut s.with, unknown),
                    "env" => pairs(&key, &value, &mut s.env, unknown),
                    _ => {}
                }
            }
        }
        NodeKind::Null | NodeKind::Unknown => {}
        _ => not_a("steps", node.line, "a mapping", unknown),
    }
    s
}

fn pairs(key: &str, node: &Node, out: &mut Vec<Pair>, unknown: &mut Vec<Unknown>) {
    match &node.kind {
        NodeKind::Map(entries) => {
            for e in entries {
                out.push(Pair {
                    key: e.key.clone(),
                    value: text(key, &e.value, unknown).unwrap_or_default(),
                });
            }
        }
        NodeKind::Null | NodeKind::Unknown => {}
        _ => not_a(key, node.line, "a mapping", unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wf(src: &str) -> Workflow {
        parse_workflow("w.yml", src).expect("parses")
    }

    fn unknown(w: &Workflow) -> Vec<(usize, &str)> {
        w.unknown
            .iter()
            .map(|u| (u.line, u.what.as_str()))
            .collect()
    }

    fn job_ids(w: &Workflow) -> Vec<&str> {
        w.jobs.iter().map(|j| j.id.as_str()).collect()
    }

    #[test]
    fn reads_triggers_jobs_and_steps() {
        let w = wf("name: f07\n\
                    on:\n  pull_request_target:\n    types: [opened, synchronize]\n\
                    permissions:\n  contents: write\n\
                    jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n\
                    \x20     - uses: actions/checkout@v5\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n\
                    \x20     - run: echo hi\n");
        assert_eq!(w.name.as_deref(), Some("f07"));
        assert_eq!(w.triggers, ["pull_request_target"]);
        assert_eq!(w.permissions, ["contents: write"]);
        assert_eq!(w.jobs.len(), 1);
        assert_eq!(w.jobs[0].id, "build");
        assert_eq!(w.jobs[0].steps.len(), 2);
        assert_eq!(
            w.jobs[0].steps[0].uses.as_deref(),
            Some("actions/checkout@v5")
        );
        assert_eq!(w.jobs[0].steps[0].with[0].key, "ref");
        assert_eq!(
            w.jobs[0].steps[0].with[0].value,
            "${{ github.event.pull_request.head.sha }}"
        );
        assert_eq!(w.jobs[0].steps[1].run.as_deref(), Some("echo hi"));
        assert!(w.unknown.is_empty());
    }

    #[test]
    fn list_and_scalar_and_flow_and_quoted_triggers() {
        assert_eq!(
            wf("on: [issue_comment, issues]\n").triggers,
            ["issue_comment", "issues"]
        );
        assert_eq!(wf("on: issue_comment\n").triggers, ["issue_comment"]);
        assert_eq!(wf("\"on\": issue_comment\n").triggers, ["issue_comment"]);
        assert_eq!(
            wf("on:\n  issue_comment: {types: [created]}\n").triggers,
            ["issue_comment"]
        );
        let seq = wf("on:\n- push\n- pull_request\n");
        assert_eq!(seq.triggers, ["push", "pull_request"]);
    }

    #[test]
    fn folded_and_literal_block_scalars() {
        let folded = wf("jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v5\n        with:\n          ref: >-\n            ${{ github.event.pull_request.head.sha }}\n");
        assert_eq!(
            folded.jobs[0].steps[0].with[0].value,
            "${{ github.event.pull_request.head.sha }}"
        );
        let literal =
            wf("jobs:\n  t:\n    steps:\n      - run: |\n          echo one\n          echo two\n");
        assert_eq!(
            literal.jobs[0].steps[0].run.as_deref(),
            Some("echo one echo two")
        );
    }

    #[test]
    fn env_block_before_run() {
        let w = wf("jobs:\n  b:\n    steps:\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: echo \"$TITLE\"\n");
        let step = &w.jobs[0].steps[0];
        assert_eq!(step.env[0].key, "TITLE");
        assert_eq!(step.env[0].value, "${{ github.event.pull_request.title }}");
        assert_eq!(step.run.as_deref(), Some("echo \"$TITLE\""));
    }

    #[test]
    fn anchors_aliases_tags_are_unknown_not_expanded() {
        let w = wf("on: push\nx: &a value\ny: *a\nz: !!str 1\n");
        assert_eq!(w.triggers, ["push"]);
        assert_eq!(
            unknown(&w),
            [
                (
                    2,
                    "an anchor (&a): its node is read; an alias to it is not expanded"
                ),
                (3, "an alias (*a), not expanded"),
                (4, "a tag (!!str): line 4 not read"),
            ]
        );
    }

    #[test]
    fn a_tab_in_indentation_ends_the_read() {
        let w = wf("on: push\njobs:\n\tbuild:\n    steps: []\n");
        assert_eq!(w.triggers, ["push"]);
        assert_eq!(
            unknown(&w),
            [(3, "a tab in indentation: not read from line 3 to the end")]
        );
    }

    #[test]
    fn a_second_document_is_refused() {
        let e = parse_workflow("w.yml", "on: push\n---\non: pull_request\n").unwrap_err();
        assert_eq!(e, "holds more than one YAML document");
        let e = parse_workflow("w.yml", "on: push\n...\non: pull_request\n").unwrap_err();
        assert_eq!(e, "holds more than one YAML document");
        let e = parse_workflow("w.yml", "on: push\n... on: pull_request\n").unwrap_err();
        assert_eq!(e, "holds more than one YAML document");
        // A document end marker with nothing after it closes the one document.
        assert_eq!(wf("on: push\n...\n# end\n").triggers, ["push"]);
    }

    #[test]
    fn a_non_mapping_is_refused() {
        assert_eq!(
            parse_workflow("w.yml", "- just\n- a\n- list\n").unwrap_err(),
            "not a YAML mapping"
        );
    }

    #[test]
    fn a_leading_document_marker_is_allowed() {
        assert_eq!(wf("---\non: push\n").triggers, ["push"]);
        assert_eq!(wf("--- {on: push}\n").triggers, ["push"]);
        let w = wf("%YAML 1.2\n---\non: push\n");
        assert_eq!(w.triggers, ["push"]);
        assert_eq!(unknown(&w), [(1, "a YAML directive")]);
    }

    #[test]
    fn over_deep_nesting_is_marked_unknown_and_the_rest_is_read() {
        let mut src = String::from("a:\n");
        for i in 0..(MAX_WF_DEPTH + 5) {
            src.push_str(&"  ".repeat(i + 1));
            src.push_str("b:\n");
        }
        src.push_str("on: push\n");
        let w = parse_workflow("w.yml", &src).expect("parses");
        assert_eq!(w.triggers, ["push"]);
        assert_eq!(w.unknown.len(), 1);
        assert!(
            w.unknown[0].what.starts_with("nested too deeply: lines "),
            "{:?}",
            w.unknown
        );
        assert!(
            w.unknown[0].what.ends_with("-38 not read"),
            "{:?}",
            w.unknown
        );
        // A flow collection nested past the cap ends the read.
        let deep = format!("on: push\nx: {}{}\n", "[".repeat(40), "]".repeat(40));
        let w = wf(&deep);
        assert_eq!(w.triggers, ["push"]);
        assert_eq!(
            unknown(&w),
            [(
                2,
                "a flow collection nested too deeply: not read from line 2 to the end"
            )]
        );
    }

    #[test]
    fn too_many_nodes_skips_the_file() {
        let mut src = String::from("jobs:\n  b:\n    steps:\n");
        for _ in 0..(MAX_WF_NODES + 10) {
            src.push_str("      - run: x\n");
        }
        let e = parse_workflow("w.yml", &src).unwrap_err();
        assert!(e.contains("more structure than the parser lists"), "{e}");
    }

    #[test]
    fn a_hash_after_a_space_starts_a_comment_even_between_quotes_of_a_plain_scalar() {
        // `'#` is no comment; ` #` is one, whatever quotes a plain scalar holds.
        let w = wf("jobs:\n  b:\n    steps:\n      - run: echo '# not a comment'\n      - run: echo \"x # y\"\n");
        assert_eq!(
            w.jobs[0].steps[0].run.as_deref(),
            Some("echo '# not a comment'")
        );
        assert_eq!(w.jobs[0].steps[1].run.as_deref(), Some("echo \"x"));
        assert!(w.unknown.is_empty());
    }

    #[test]
    fn job_if_and_permissions() {
        let w = wf("on: issue_comment\njobs:\n  deploy:\n    if: contains(github.event.comment.body, '/deploy')\n    permissions:\n      contents: write\n    steps:\n      - run: echo\n");
        assert_eq!(
            w.jobs[0].cond.as_deref(),
            Some("contains(github.event.comment.body, '/deploy')")
        );
        assert_eq!(w.jobs[0].permissions, ["contents: write"]);
    }

    /// The pull_request_target job the tests below expect to survive.
    const PRT_JOB: &str = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: ./build.sh\n";

    fn assert_prt(w: &Workflow) {
        assert_eq!(w.triggers, ["pull_request_target"], "{w:?}");
        assert_eq!(job_ids(w), ["b"], "{w:?}");
        let steps = &w.jobs[0].steps;
        assert_eq!(steps.len(), 2, "{w:?}");
        assert_eq!(steps[0].uses.as_deref(), Some("actions/checkout@v4"));
        assert_eq!(
            steps[0].with[0].value,
            "${{ github.event.pull_request.head.sha }}"
        );
        assert_eq!(steps[1].run.as_deref(), Some("./build.sh"));
    }

    #[test]
    fn wrapped_plain_and_quoted_scalars_are_read_whole() {
        let w = wf(&format!(
            "name: Build and\n  test\non: pull_request_target\n{PRT_JOB}"
        ));
        assert_prt(&w);
        assert_eq!(w.name.as_deref(), Some("Build and test"));
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);

        let w = wf(&format!(
            "name: \"Build\n  and test\"\non: pull_request_target\n{PRT_JOB}"
        ));
        assert_prt(&w);
        assert_eq!(w.name.as_deref(), Some("Build and test"));
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);

        let w = wf("on: pull_request_target\njobs:\n  deploy:\n    if: github.event.issue.pull_request &&\n      contains(github.event.comment.body, '/deploy')\n    steps:\n      - run: npm ci &&\n          npm test\n      - run: ./build.sh\n  later:\n    if:\n      github.event_name == 'x' &&\n      github.actor == 'y'\n    steps:\n      - run: echo later\n");
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);
        assert_eq!(job_ids(&w), ["deploy", "later"]);
        assert_eq!(
            w.jobs[0].cond.as_deref(),
            Some(
                "github.event.issue.pull_request && contains(github.event.comment.body, '/deploy')"
            )
        );
        assert_eq!(
            w.jobs[0].steps[0].run.as_deref(),
            Some("npm ci && npm test")
        );
        assert_eq!(w.jobs[0].steps[1].run.as_deref(), Some("./build.sh"));
        assert_eq!(
            w.jobs[1].cond.as_deref(),
            Some("github.event_name == 'x' && github.actor == 'y'")
        );
    }

    #[test]
    fn what_cannot_be_placed_ends_the_read_and_says_so() {
        // `? on` is an explicit key: listed with its lines, and the rest is read.
        let w = wf(&format!("name: x\n? on\n: pull_request_target\n{PRT_JOB}"));
        assert_eq!(
            unknown(&w),
            [(2, "an explicit key (?): lines 2-3 not read")]
        );
        assert_eq!(job_ids(&w), ["b"]);
        // A wrapped value holding `: ` does not parse: nothing after it is read.
        let w = wf(&format!(
            "on: pull_request_target\nname: a\n  b: c\n{PRT_JOB}"
        ));
        assert_eq!(w.triggers, ["pull_request_target"]);
        assert!(w.jobs.is_empty());
        assert_eq!(
            unknown(&w),
            [(
                3,
                "a plain scalar holding `: `, which YAML reads as a key: not read from line 3 to the end"
            )]
        );
        // A line indented to no open block.
        let w = wf("jobs:\n    build:\n      steps: []\n  test:\n    steps: []\non: push\n");
        assert_eq!(job_ids(&w), ["build"]);
        assert_eq!(
            unknown(&w),
            [(
                4,
                "a line indented deeper than the entries before it: not read from line 4 to the end"
            )]
        );
        // A root indented past the lines after it.
        let w = wf("  on: push\njobs: {}\n");
        assert_eq!(w.triggers, ["push"]);
        assert_eq!(
            unknown(&w),
            [(
                2,
                "a line the parser could not place: not read from line 2 to the end"
            )]
        );
    }

    #[test]
    fn a_tab_after_a_colon_separates_and_tabbed_blank_or_comment_lines_are_skipped() {
        let w = wf(&format!(
            "name: x\non:\tpull_request_target\n{}",
            PRT_JOB.replacen(
                "    steps:\n",
                "\t\n    \t# checkout the PR\n    steps:\n",
                1
            )
        ));
        assert_prt(&w);
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);
    }

    #[test]
    fn escapes_are_decoded() {
        for key in ["\"o\\u006e\"", "\"\\x6fn\"", "\"o\\U0000006e\"", "'on'"] {
            let w = wf(&format!("{key}: pull_request_target\n{PRT_JOB}"));
            assert_prt(&w);
            assert!(w.unknown.is_empty(), "{key}: {:?}", w.unknown);
        }
        let w = wf(&format!("on: \"pull_request_t\\x61rget\"\n{PRT_JOB}"));
        assert_prt(&w);
        let w = wf("on: push\nname: \"\\0\\a\\b\\t\\\t\\n\\v\\f\\r\\e\\ \\\"\\/\\\\\\N\\_\\L\\P|\\x41\\u00e9\\U0001F600\"\n");
        assert_eq!(
            w.name.as_deref(),
            Some("\0\u{7}\u{8} \u{1b} \"/\\ |A\u{e9}\u{1f600}")
        );
        // An escaped line break joins the lines with nothing between them.
        let w = wf("on: push\nname: \"one \\\n   two\\\n   three\"\n");
        assert_eq!(w.name.as_deref(), Some("one twothree"));
        for bad in ["\"\\q\"", "\"\\ud800\"", "\"\\U00110000\"", "\"\\x4\""] {
            let w = wf(&format!("on: push\nname: {bad}\n{PRT_JOB}"));
            assert_eq!(w.triggers, ["push"]);
            assert!(w.jobs.is_empty(), "{bad}");
            assert_eq!(
                unknown(&w),
                [(
                    2,
                    "an escape YAML does not define: not read from line 2 to the end"
                )],
                "{bad}"
            );
        }
    }

    #[test]
    fn a_byte_order_mark_and_every_line_break_are_read_as_yaml_reads_them() {
        assert_prt(&wf(&format!("\u{feff}on: pull_request_target\n{PRT_JOB}")));
        assert_prt(&wf(
            &format!("on: pull_request_target\n{PRT_JOB}").replace('\n', "\r")
        ));
        assert_prt(&wf(
            &format!("on: pull_request_target\n{PRT_JOB}").replace('\n', "\r\n")
        ));
        // A mark, or a character YAML parsers read differently, past the start.
        for (odd, what) in [
            ("\u{feff}", "a byte order mark past the start of the file"),
            (
                "\u{2028}",
                "a NEL, LS or PS character, which YAML 1.1 parsers read as a line break",
            ),
            (
                "\u{85}",
                "a NEL, LS or PS character, which YAML 1.1 parsers read as a line break",
            ),
            ("\u{7}", "a control character YAML does not allow"),
            ("\u{7f}", "a control character YAML does not allow"),
        ] {
            let w = wf(&format!(
                "on: push\nname: a{odd}on: pull_request_target\n{PRT_JOB}"
            ));
            assert_eq!(w.triggers, ["push"]);
            assert!(w.jobs.is_empty());
            assert_eq!(
                unknown(&w),
                [(
                    2,
                    format!("{what}: not read from line 2 to the end").as_str()
                )]
            );
        }
    }

    #[test]
    fn a_flow_root_and_flow_collections_over_lines_are_read() {
        let w = wf("{\"on\": \"pull_request_target\", \"jobs\": {\"b\": {\"runs-on\": \"ubuntu-latest\", \"steps\": [{\"run\": \"echo ${{ github.event.pull_request.title }}\"}]}}}\n");
        assert_eq!(w.triggers, ["pull_request_target"]);
        assert_eq!(
            w.jobs[0].steps[0].run.as_deref(),
            Some("echo ${{ github.event.pull_request.title }}")
        );
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);
        let w = wf("{\"on\":\"push\",\"jobs\":{}}\n");
        assert_eq!(w.triggers, ["push"]);
        let w = wf(&format!(
            "on: [push,\n  pull_request_target] # both\n{}",
            PRT_JOB.replacen("    steps:\n", "    strategy:\n      matrix:\n        os: [ubuntu-latest,\n             macos-latest]\n    steps:\n", 1)
        ));
        assert_eq!(w.triggers, ["push", "pull_request_target"]);
        assert_eq!(w.jobs[0].steps.len(), 2);
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);
    }

    #[test]
    fn a_mismatched_or_open_flow_collection_ends_the_read() {
        for (src, what) in [
            ("x: {a]\non: push\n", "a flow mapping entry not followed by , or }: not read from line 1 to the end"),
            ("on: push\nbranches: [main}\n", "a flow sequence entry not followed by , or ]: not read from line 2 to the end"),
            ("on: push\nx: [a, b\n", "a flow collection that does not close: not read from line 2 to the end"),
            ("on: push\nx: [a, , b]\n", "an empty entry in a flow collection: not read from line 2 to the end"),
            ("on: push\nx: [a] b\n", "content after a flow collection or a quoted scalar: not read from line 2 to the end"),
            ("on: push\nx: {a\n: b}\n", "a flow mapping key that spans lines (line 3): not read from line 2 to the end"),
            ("on: push\nx: {\"a\n b\": c}\n", "a flow mapping key that spans lines (line 3): not read from line 2 to the end"),
        ] {
            let w = wf(src);
            assert_eq!(unknown(&w), [(if src.starts_with("x") { 1 } else { 2 }, what)], "{src:?}");
        }
        // Valid YAML with quotes that open no scalar, and brackets inside quotes.
        let w = wf("on: push\nx: {a: don't, b: ']'}\njobs:\n  b:\n    steps:\n      - uses: some/action@v1\n        with: {title: don't merge, pattern: ']'}\n");
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);
        assert_eq!(w.jobs[0].steps[0].with[0].value, "don't merge");
        assert_eq!(w.jobs[0].steps[0].with[1].value, "]");
    }

    #[test]
    fn an_escaped_line_break_in_a_flow_item_and_a_short_block_scalar_line_do_not_panic() {
        let w = wf("on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: x\n        with:\n          a: [\"\\\n");
        assert_eq!(w.triggers, ["pull_request_target"]);
        assert_eq!(
            unknown(&w),
            [(
                7,
                "a quoted scalar that does not close: not read from line 7 to the end"
            )]
        );
        // An escaped line break inside a flow item is read; an input GitHub reads
        // as a string given a sequence is listed.
        let w = wf("on: push\njobs:\n  b:\n    steps:\n      - uses: some/action@v1\n        with:\n          args: [\"first \\\n            second\"]\n");
        assert_eq!(w.jobs[0].steps[0].with[0].value, "");
        assert_eq!(unknown(&w), [(7, "a `with` value that is not a scalar")]);
        let w = wf("on: pull_request_target\nx: |\n      a\n   \u{e9}\u{e9}\u{e9}\njobs:\n  b:\n    steps:\n      - run: echo hi\n");
        assert_eq!(
            unknown(&w),
            [(
                4,
                "a block scalar line indented less than its first: not read from line 4 to the end"
            )]
        );
    }

    #[test]
    fn block_scalar_indicators_set_the_indentation() {
        let w = wf("on: push\njobs:\n  b:\n    steps:\n      - run: |2\n              echo a\n            curl https://example.invalid/x | sh\n      - run: |2-\n              echo b\n             \u{e9}\u{e9}\u{e9}\n");
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);
        assert_eq!(
            w.jobs[0].steps[0].run.as_deref(),
            Some("echo a curl https://example.invalid/x | sh")
        );
        assert_eq!(
            w.jobs[0].steps[1].run.as_deref(),
            Some("echo b \u{e9}\u{e9}\u{e9}")
        );
        // A line less indented than the header's indentation does not parse.
        let w = wf("on: push\na: |2\n x\nb: 1\n");
        assert_eq!(
            unknown(&w),
            [(
                3,
                "a block scalar line indented less than its first: not read from line 3 to the end"
            )]
        );
        // A trailing comment less indented than the body ends it.
        let w = wf("run: |\n    echo\n  # c\non: push\n");
        assert_eq!(w.triggers, ["push"]);
        assert!(w.unknown.is_empty());
        assert_eq!(
            unknown(&wf("on: push\nx: |x\n  y\n")),
            [(
                2,
                "a block scalar header YAML does not define: not read from line 2 to the end"
            )]
        );
    }

    #[test]
    fn a_leading_blank_line_with_more_spaces_than_a_block_scalars_text_ends_the_read() {
        // YAML refuses it; YAML 1.1 parsers read the scalar as empty and the text as
        // a comment.
        let w = wf("on: pull_request_target\njobs:\n  b:\n    steps:\n      - run: |\n              \n          # curl https://example.invalid/x | sh\n");
        assert_eq!(
            unknown(&w),
            [(
                6,
                "a block scalar's leading blank line indented more than its first line: not read from line 6 to the end"
            )]
        );
        // A tab past the spaces does not hide them.
        let w = wf("on: push\nx: |\n\n         \t\n    a\n");
        assert_eq!(unknown(&w)[0].0, 4);
        // As many spaces as the first line of text, or fewer, is read; so is any
        // blank line under an indentation indicator, or after the first line.
        let w = wf("on: push\nx: |\n\n  \n    \n    a\n\n          \n    b\ny: |2\n\n        \n    c\njobs:\n  b:\n    steps:\n      - run: d\n");
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);
        assert_eq!(w.jobs[0].steps[0].run.as_deref(), Some("d"));
    }

    #[test]
    fn a_quoted_scalar_followed_by_a_comment_is_unquoted() {
        let w = wf("\"on\": pull_request_target # trigger\njobs:\n  b:\n    steps:\n      - uses: \"actions/checkout@v4\" # v4\n        with:\n          ref: \"${{ github.event.pull_request.head.sha }}\" # PR head\n      - uses: 'example/single@v1'#c\n");
        assert_eq!(w.triggers, ["pull_request_target"]);
        assert_eq!(
            w.jobs[0].steps[0].uses.as_deref(),
            Some("actions/checkout@v4")
        );
        assert_eq!(
            w.jobs[0].steps[0].with[0].value,
            "${{ github.event.pull_request.head.sha }}"
        );
        assert_eq!(
            w.jobs[0].steps[1].uses.as_deref(),
            Some("example/single@v1")
        );
        assert!(w.unknown.is_empty());
    }

    #[test]
    fn an_anchored_block_is_read_and_its_alias_listed() {
        // GitHub's documented anchor shape: both jobs are read.
        let w = wf("on: pull_request_target\njobs:\n  job1:\n    env: &env_vars\n      NODE_ENV: production\n    steps:\n      - run: echo one\n  job2:\n    env: *env_vars\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm install && npm test\n");
        assert_eq!(job_ids(&w), ["job1", "job2"]);
        assert_eq!(w.jobs[1].steps.len(), 2);
        assert_eq!(
            unknown(&w),
            [
                (
                    4,
                    "an anchor (&env_vars): its node is read; an alias to it is not expanded"
                ),
                (9, "an alias (*env_vars), not expanded"),
            ]
        );
        let w = wf("on: pull_request_target\ndefaults_anchor: &defaults\n  runs-on: ubuntu-latest\njobs:\n  b:\n    <<: *defaults\n    steps:\n      - run: x\n");
        assert_eq!(job_ids(&w), ["b"]);
        assert_eq!(w.jobs[0].steps[0].run.as_deref(), Some("x"));
        assert_eq!(
            unknown(&w),
            [
                (
                    2,
                    "an anchor (&defaults): its node is read; an alias to it is not expanded"
                ),
                (6, "a merge key (<<): line 6 not read"),
            ]
        );
        // A tagged block is not read, and what follows it is.
        let w = wf("x: !custom\n  a: 1\n  b: [2,\n    3]\non: push\n");
        assert_eq!(w.triggers, ["push"]);
        assert_eq!(unknown(&w), [(1, "a tag (!custom): lines 1-4 not read")]);
        // A merge key's flow value.
        let w = wf("on: push\njobs:\n  b:\n    <<: {runs-on: ubuntu-latest}\n    steps:\n      - run: echo hi\n");
        assert_eq!(unknown(&w), [(4, "a merge key (<<): line 4 not read")]);
        assert_eq!(w.jobs[0].steps.len(), 1);
    }

    #[test]
    fn a_merge_key_in_a_flow_mapping_is_listed_as_in_a_block_mapping() {
        // The steps a YAML 1.1 parser merges into job b are not read, and listed.
        let w = wf("on: pull_request_target\njobs:\n  b: {<<: {steps: [{uses: actions/checkout@v4, with: {ref: \"${{ github.event.pull_request.head.sha }}\"}}]}}\n");
        assert_eq!(job_ids(&w), ["b"]);
        assert_eq!(unknown(&w), [(3, "a merge key (<<): line 3 not read")]);
        let w = wf("on: {<<: {pull_request_target: null},\n  push: null}\n");
        assert_eq!(w.triggers, ["push"]);
        assert_eq!(unknown(&w), [(1, "a merge key (<<): line 1 not read")]);
        // Over lines, and past an anchor.
        let w = wf("on: push\nx: {<<: {a: 1,\n    b: 2}, c: 3}\ny: {&m <<: [z]}\n");
        assert_eq!(
            unknown(&w),
            [
                (2, "a merge key (<<): lines 2-3 not read"),
                (
                    4,
                    "an anchor (&m): its node is read; an alias to it is not expanded"
                ),
                (4, "a merge key (<<): line 4 not read"),
            ]
        );
        // A quoted "<<", and a plain key that only starts with <<, are keys like
        // any other, as YAML 1.1 parsers read them.
        let w = wf("on: {\"<<\": null, <<x: null}\n");
        assert_eq!(w.triggers, ["<<", "<<x"]);
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);
    }

    #[test]
    fn a_repeated_key_keeps_both_and_is_listed() {
        let w = wf("on: pull_request_target\non: push\n");
        assert_eq!(w.triggers, ["pull_request_target", "push"]);
        assert_eq!(
            unknown(&w),
            [(2, "a second `on` key, which YAML parsers read differently")]
        );
    }

    #[test]
    fn a_compact_and_nested_sequence_and_mapping() {
        let w = wf("on: push\nx:\n- - a\n  - b\n- c\njobs:\n  b:\n    steps:\n    - name: x\n      uses: y\n    -   run: z\n        if: always()\n");
        assert!(w.unknown.is_empty(), "{:?}", w.unknown);
        assert_eq!(w.jobs[0].steps[0].uses.as_deref(), Some("y"));
        assert_eq!(w.jobs[0].steps[1].run.as_deref(), Some("z"));
        assert_eq!(w.jobs[0].steps[1].cond.as_deref(), Some("always()"));
    }

    #[test]
    fn keys_and_values_are_cut() {
        let long = "k".repeat(5000);
        let w = wf(&format!("on:\n  {long}:\n"));
        assert_eq!(w.triggers[0].chars().count(), MAX_WF_SCALAR + 3);
        assert!(w.triggers[0].ends_with("..."));
    }

    #[test]
    fn no_prefix_of_a_workflow_panics_or_loops() {
        let src = format!("%YAML 1.2\n--- &root\nname: \"Build\\x20and\n  test\" # c\non: [push,\n  'pull_request_target']\nx: {{a: don't, b: ']', c: [\"\\u00e9\\\n d\"]}}\ny: !t\n  z: 1\njobs:\n  b:\n    if: a &&\n      b\n    steps:\n      - run: |2-\n            echo \u{e9}\n          echo\n      - ? k\n        : v\n      - *a\n      - - x\n        - y\n{PRT_JOB}");
        for (i, _) in src.char_indices() {
            let _ = parse_workflow("w.yml", &src[..i]);
        }
    }

    #[test]
    fn a_large_answer_is_skipped_rather_than_cut() {
        let src = "on: push\njobs:\n  b:\n    steps:\n      - run: x\n";
        let small: Answer =
            serde_json::from_slice(&answer(src.as_bytes(), 1 << 20).unwrap()).unwrap();
        assert!(matches!(small, Answer::Workflow(_)));
        let tight: Answer = serde_json::from_slice(&answer(src.as_bytes(), 50).unwrap()).unwrap();
        match tight {
            Answer::Skipped(why) => assert_eq!(why, TOO_MANY_FACTS),
            other => panic!("{other:?}"),
        }
        let bad: Answer = serde_json::from_slice(&answer(&[0xff], 1 << 20).unwrap()).unwrap();
        assert!(matches!(bad, Answer::Skipped(why) if why == "not UTF-8"));
    }

    #[test]
    fn an_answer_is_capped_as_audit_scan_prints_it() {
        // 200 DELs in a value: 200 bytes as serde_json writes them, 1,200 printed.
        let src = format!(
            "on: push\njobs:\n  b:\n    steps:\n      - run: x\n        env:\n          K: \"{}\"\n",
            "\\x7f".repeat(200)
        );
        let json = answer(src.as_bytes(), usize::MAX).unwrap();
        let printed = confine::json_text(String::from_utf8(json.clone()).unwrap()).len();
        assert_eq!(printed, json.len() + 1000);
        let fits: Answer =
            serde_json::from_slice(&answer(src.as_bytes(), printed).unwrap()).unwrap();
        assert!(matches!(fits, Answer::Workflow(_)));
        let over: Answer =
            serde_json::from_slice(&answer(src.as_bytes(), printed - 1).unwrap()).unwrap();
        assert!(matches!(over, Answer::Skipped(why) if why == TOO_MANY_FACTS));
    }

    #[test]
    fn printed_size_counts_what_audit_scan_prints() {
        let odd =
            "\u{7f}\u{7f} \u{85}\u{200b}\u{202e}\u{e0001} \"q\" \\ \n \u{e9} \u{2713} \u{1f980}";
        for v in ["plain", odd, ""] {
            let one = serde_json::json!({"key": v, "list": [v, 1, null, []], "map": {"a": [v]}});
            for pretty in [false, true] {
                let printed = |value: &serde_json::Value| {
                    let json = if pretty {
                        serde_json::to_string_pretty(value)
                    } else {
                        serde_json::to_string(value)
                    };
                    confine::json_text(json.unwrap()).len()
                };
                assert_eq!(printed_size(&one, pretty, 0), printed(&one), "{v:?}");
                // Two levels into a report, as a workflow sits in it.
                let around = printed(&serde_json::json!({"workflows": [0]})) - 1;
                assert_eq!(
                    printed_size(&one, pretty, 2) + around,
                    printed(&serde_json::json!({"workflows": [one]})),
                    "{v:?}"
                );
            }
        }
        // A DEL a workflow's value holds takes six bytes printed, one in serde_json.
        let w = wf("on: push\njobs:\n  b:\n    steps:\n      - run: \"\\x7f\\x7f\"\n");
        assert_eq!(
            printed_size(&w, false, 0),
            serde_json::to_string(&w).unwrap().len() + 10
        );
    }
}
