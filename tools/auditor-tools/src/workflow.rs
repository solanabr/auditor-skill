//! A workflow-aware pass over `.github/workflows/*.yml`, with a hand-written
//! strict-subset YAML parser.
//!
//! The parser is not a general YAML library: it reads the block and flow subset
//! GitHub Actions workflows are written in (block mappings and sequences, flow
//! `[…]` and `{…}`, plain and quoted scalars, and `|`/`>` block scalars), and
//! marks anything outside that subset — an anchor (`&`), an alias (`*`), a tag
//! (`!…`), a merge key, an indentation tab, an unterminated flow — as `unknown`
//! rather than guessing it. It never expands an alias, so no input can grow its
//! output beyond the bytes it read. A whole file with a second YAML document, or
//! more structure than the caps allow, is listed in `skipped`; a construct inside
//! a file the parser did model is listed in that workflow's `unknown`, and the
//! auditor reads those by hand.
//!
//! It is bounded by construction — [`MAX_WF_DEPTH`] on nesting, [`MAX_WF_NODES`]
//! on nodes a file, `confine::MAX_FILE` on bytes a file (the walk enforces it),
//! [`MAX_WF_FILES`] on files a directory — so, unlike the recursive-descent Rust
//! parser, it runs in this process and needs no child.

use std::os::fd::AsRawFd;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::confine::{self, os_message};
use crate::scan::Skipped;

/// Block and flow nesting past which the parser stops and marks the node
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

/// The longest a scalar is kept: its whitespace collapsed to single spaces and
/// cut after this many characters with `...`, as a report snippet is.
const MAX_WF_SCALAR: usize = 200;

/// One parsed workflow file: the facts the pass reads, and the constructs in it
/// the parser left unresolved.
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
    /// Every construct in this file outside the parser's subset, with its line.
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

/// Parse every `*.yml` and `*.yaml` file directly in the directory `dir` (a path
/// relative to the working directory), in byte order of their names, returning
/// the workflows parsed and the files skipped. GitHub reads workflows only from
/// the directory itself, so the pass does not recurse; it follows no symbolic
/// link, and reads only regular files with one name of at most 4 MiB, each opened
/// from the directory's descriptor without following a link. A `*.y*ml` entry
/// that is a link or not a regular file, one that is not UTF-8, one with a second
/// YAML document or more structure than the caps allow, and every file past
/// `MAX_WF_FILES`, is listed in `skipped` with the reason.
pub fn scan_workflows(dir: &Path) -> (Vec<Workflow>, Vec<Skipped>) {
    let mut workflows = Vec::new();
    let mut skipped = Vec::new();
    let fd = match crate::scan::open_root(dir) {
        Ok(fd) => fd,
        Err(e) => {
            skipped.push(Skipped {
                file: dir.display().to_string(),
                reason: format!("cannot be read: {}", os_message(&e)),
            });
            return (workflows, skipped);
        }
    };
    let names = match confine::names(&fd) {
        Ok(names) => names,
        Err(e) => {
            skipped.push(Skipped {
                file: dir.display().to_string(),
                reason: format!("cannot be read: {}", os_message(&e)),
            });
            return (workflows, skipped);
        }
    };
    let mut parsed = 0usize;
    for name in names {
        if !(name.ends_with(b".yml") || name.ends_with(b".yaml")) {
            continue;
        }
        let label = dir.join(std::ffi::OsStr::from_bytes(&name));
        let label = label.display().to_string();
        let kind = match confine::kind_at(fd.as_raw_fd(), &name) {
            Ok(kind) => kind,
            Err(e) => {
                skipped.push(Skipped {
                    file: label,
                    reason: format!("cannot be read: {}", os_message(&e)),
                });
                continue;
            }
        };
        match kind {
            libc::S_IFLNK => {
                skipped.push(Skipped {
                    file: label,
                    reason: "a symbolic link, not followed".to_string(),
                });
                continue;
            }
            libc::S_IFREG => {}
            _ => {
                skipped.push(Skipped {
                    file: label,
                    reason: "not a regular file".to_string(),
                });
                continue;
            }
        }
        if parsed >= MAX_WF_FILES {
            skipped.push(Skipped {
                file: label,
                reason: "not parsed: too many workflow files".to_string(),
            });
            continue;
        }
        parsed += 1;
        match crate::scan::read_bytes(fd.as_raw_fd(), &name) {
            Ok(bytes) => match std::str::from_utf8(&bytes) {
                Ok(text) => match parse_workflow(&label, text) {
                    Ok(wf) => workflows.push(wf),
                    Err(reason) => skipped.push(Skipped {
                        file: label,
                        reason,
                    }),
                },
                Err(_) => skipped.push(Skipped {
                    file: label,
                    reason: "not UTF-8".to_string(),
                }),
            },
            Err(reason) => skipped.push(Skipped {
                file: label,
                reason,
            }),
        }
    }
    (workflows, skipped)
}

use std::os::unix::ffi::OsStrExt;

/// Parse one workflow source into its facts, the file named `label`. `Err(reason)`
/// means the file is skipped whole: it is not a single YAML mapping, it holds a
/// second document, or it holds more structure than the caps allow.
pub fn parse_workflow(label: &str, source: &str) -> Result<Workflow, String> {
    let lines = split_lines(source);
    only_one_document(&lines)?;
    let mut p = P {
        lines,
        pos: 0,
        nodes: 0,
        truncated: false,
        unknown: Vec::new(),
    };
    // A single leading `---` opens the one document.
    p.skip_blanks();
    if p.peek().is_some_and(|l| l.content.trim_end() == "---") {
        p.pos += 1;
    }
    let root = p.parse_block(0, 0);
    if p.truncated {
        return Err(format!(
            "holds more structure than the parser lists (over {MAX_WF_NODES} nodes)"
        ));
    }
    let NodeKind::Map(entries) = root.kind else {
        return Err("not a YAML mapping".to_string());
    };
    Ok(build(label, entries, p.unknown))
}

// ---------------------------------------------------------------------------
// Lines
// ---------------------------------------------------------------------------

/// One source line: its number, its indentation (leading spaces), the text past
/// the indentation, the whole line (for a block scalar's body), whether it is
/// blank or a comment, and whether a tab sits in its indentation.
struct Raw<'a> {
    number: usize,
    indent: usize,
    content: &'a str,
    raw: &'a str,
    blank_or_comment: bool,
    tab_indent: bool,
}

/// Split the source into lines (`\n`, a trailing `\r` dropped), each measured.
fn split_lines(source: &str) -> Vec<Raw<'_>> {
    source
        .split('\n')
        .enumerate()
        .map(|(i, line)| {
            let raw = line.strip_suffix('\r').unwrap_or(line);
            let mut indent = 0;
            let mut tab_indent = false;
            for b in raw.bytes() {
                match b {
                    b' ' => indent += 1,
                    b'\t' => {
                        tab_indent = true;
                        break;
                    }
                    _ => break,
                }
            }
            let content = &raw[indent..];
            let blank_or_comment = content.is_empty() || content.starts_with('#');
            Raw {
                number: i + 1,
                indent,
                content,
                raw,
                blank_or_comment,
                tab_indent,
            }
        })
        .collect()
}

/// A second YAML document (a `---` or `...` marker at the left margin after the
/// first content line) is refused: the parser reads one document.
fn only_one_document(lines: &[Raw]) -> Result<(), String> {
    let mut seen_content = false;
    for l in lines {
        if l.blank_or_comment {
            continue;
        }
        let t = l.content.trim_end();
        if l.indent == 0 && (t == "---" || t == "...") {
            if t == "..." || seen_content {
                return Err("holds more than one YAML document".to_string());
            }
            // A single leading `---` opens the first document.
            seen_content = true;
            continue;
        }
        seen_content = true;
    }
    Ok(())
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
    Unknown,
}

struct Entry {
    key: String,
    line: usize,
    value: Node,
}

struct P<'a> {
    lines: Vec<Raw<'a>>,
    pos: usize,
    nodes: usize,
    truncated: bool,
    unknown: Vec<Unknown>,
}

impl<'a> P<'a> {
    fn skip_blanks(&mut self) {
        while self.lines.get(self.pos).is_some_and(|l| l.blank_or_comment) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<&Raw<'a>> {
        self.lines.get(self.pos)
    }

    /// Count a node; once past the cap the parse is truncated and stops building.
    fn node(&mut self) -> bool {
        self.nodes += 1;
        if self.nodes > MAX_WF_NODES {
            self.truncated = true;
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

    fn unknown_at(&mut self, line: usize, what: &str) -> Node {
        self.mark(line, what);
        Node {
            line,
            kind: NodeKind::Unknown,
        }
    }

    /// The block at `min_indent` or deeper: a sequence, a mapping, or a bare
    /// scalar, whichever its first non-blank line begins.
    fn parse_block(&mut self, min_indent: usize, depth: usize) -> Node {
        self.skip_blanks();
        if self.truncated || depth > MAX_WF_DEPTH {
            if depth > MAX_WF_DEPTH {
                let line = self.peek().map_or(0, |l| l.number);
                return self.unknown_at(line, "nested too deeply");
            }
            return Node {
                line: 0,
                kind: NodeKind::Null,
            };
        }
        let Some(l) = self.peek() else {
            return Node {
                line: 0,
                kind: NodeKind::Null,
            };
        };
        if l.indent < min_indent {
            return Node {
                line: l.number,
                kind: NodeKind::Null,
            };
        }
        let indent = l.indent;
        let (number, tab) = (l.number, l.tab_indent);
        if tab {
            self.pos += 1;
            return self.unknown_at(number, "a tab in indentation");
        }
        if is_seq_line(l) {
            return self.parse_seq(indent, depth);
        }
        if split_key(l.content).is_some() {
            return self.parse_map(indent, depth);
        }
        // A bare scalar as the whole block value.
        let value = scalar_value(l.content);
        self.pos += 1;
        self.node();
        Node {
            line: number,
            kind: NodeKind::Scalar(value),
        }
    }

    fn parse_map(&mut self, indent: usize, depth: usize) -> Node {
        let start = self.peek().map_or(0, |l| l.number);
        let mut entries = Vec::new();
        loop {
            self.skip_blanks();
            if self.truncated {
                break;
            }
            let Some(l) = self.peek() else { break };
            if l.indent != indent {
                break;
            }
            if l.tab_indent {
                let n = l.number;
                self.pos += 1;
                self.mark(n, "a tab in indentation");
                continue;
            }
            let Some((key, rest)) = split_key(l.content) else {
                break;
            };
            let (number, rest) = (l.number, rest.to_string());
            self.pos += 1;
            if !self.node() {
                break;
            }
            let value = self.parse_entry_value(&rest, number, indent, depth);
            entries.push(Entry {
                key,
                line: number,
                value,
            });
        }
        Node {
            line: start,
            kind: NodeKind::Map(entries),
        }
    }

    fn parse_seq(&mut self, indent: usize, depth: usize) -> Node {
        let start = self.peek().map_or(0, |l| l.number);
        let mut items = Vec::new();
        loop {
            self.skip_blanks();
            if self.truncated {
                break;
            }
            let Some(l) = self.peek() else { break };
            if l.indent != indent || !is_seq_line(l) {
                break;
            }
            let number = l.number;
            // The text after the `-` and the spaces following it.
            let after = &l.content[1..];
            let trimmed = after.trim_start();
            let dash_prefix = l.content.len() - trimmed.len();
            let item_indent = indent + dash_prefix;
            let rest = trimmed.to_string();
            self.pos += 1;
            if !self.node() {
                break;
            }
            let item = if rest.is_empty() || rest.starts_with('#') {
                // The value sits on the lines below, deeper than the dash.
                self.parse_block(indent + 1, depth + 1)
            } else if let Some((key, krest)) = split_key(&rest) {
                self.parse_map_from(key, krest, number, item_indent, depth + 1)
            } else {
                self.parse_inline(&rest, number, item_indent, depth + 1)
            };
            items.push(item);
        }
        Node {
            line: start,
            kind: NodeKind::Seq(items),
        }
    }

    /// A mapping whose first entry opens on a sequence item's `-` line
    /// (`- key: value`), its remaining entries at column `indent`.
    fn parse_map_from(
        &mut self,
        first_key: String,
        first_rest: &str,
        line: usize,
        indent: usize,
        depth: usize,
    ) -> Node {
        if depth > MAX_WF_DEPTH {
            return self.unknown_at(line, "nested too deeply");
        }
        let mut entries = Vec::new();
        let first_rest = first_rest.to_string();
        if self.node() {
            let value = self.parse_entry_value(&first_rest, line, indent, depth);
            entries.push(Entry {
                key: first_key,
                line,
                value,
            });
        }
        loop {
            self.skip_blanks();
            if self.truncated {
                break;
            }
            let Some(l) = self.peek() else { break };
            if l.indent != indent {
                break;
            }
            if l.tab_indent {
                let n = l.number;
                self.pos += 1;
                self.mark(n, "a tab in indentation");
                continue;
            }
            let Some((key, rest)) = split_key(l.content) else {
                break;
            };
            let (number, rest) = (l.number, rest.to_string());
            self.pos += 1;
            if !self.node() {
                break;
            }
            let value = self.parse_entry_value(&rest, number, indent, depth);
            entries.push(Entry {
                key,
                line: number,
                value,
            });
        }
        Node {
            line,
            kind: NodeKind::Map(entries),
        }
    }

    /// A mapping entry's value: the inline text after `key:`, or, when that is
    /// empty, the block on the lines below (a sequence at `key_indent` or deeper,
    /// a mapping or scalar deeper).
    fn parse_entry_value(
        &mut self,
        rest: &str,
        line: usize,
        key_indent: usize,
        depth: usize,
    ) -> Node {
        let trimmed = rest.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            self.skip_blanks();
            return match self.peek() {
                Some(l) if is_seq_line(l) && l.indent >= key_indent && !l.tab_indent => {
                    self.parse_seq(l.indent, depth + 1)
                }
                Some(l) if l.indent > key_indent => self.parse_block(key_indent + 1, depth + 1),
                _ => Node {
                    line,
                    kind: NodeKind::Null,
                },
            };
        }
        self.parse_inline(trimmed, line, key_indent, depth + 1)
    }

    /// An inline value: a block scalar (`|`/`>`), a flow `[…]` or `{…}`, a plain
    /// or quoted scalar, or a construct outside the subset.
    fn parse_inline(&mut self, text: &str, line: usize, owner_indent: usize, depth: usize) -> Node {
        if depth > MAX_WF_DEPTH {
            return self.unknown_at(line, "nested too deeply");
        }
        let first = text.as_bytes()[0];
        match first {
            b'|' | b'>' => self.parse_block_scalar(text, line, owner_indent),
            b'[' | b'{' => {
                let (node, used) = self.parse_flow(text, line, depth);
                let tail = text[used..].trim_start();
                if !tail.is_empty() && !tail.starts_with('#') {
                    self.mark(line, "content after a flow collection");
                }
                node
            }
            b'&' => self.unknown_at(line, "an anchor (&)"),
            b'*' => self.unknown_at(line, "an alias (*)"),
            b'!' => self.unknown_at(line, "a tag (!)"),
            _ => {
                self.node();
                Node {
                    line,
                    kind: NodeKind::Scalar(scalar_value(text)),
                }
            }
        }
    }

    /// A `|` or `>` block scalar: the body is the lines below, more indented than
    /// the owning key or dash; literal (`|`) keeps their line breaks, folded
    /// (`>`) joins them with spaces. The value is collapsed and cut like any
    /// scalar, so only what is kept is built.
    fn parse_block_scalar(&mut self, header: &str, line: usize, owner_indent: usize) -> Node {
        let folded = header.starts_with('>');
        let mut body: Vec<&str> = Vec::new();
        let mut body_indent: Option<usize> = None;
        while let Some(l) = self.lines.get(self.pos) {
            if !l.raw.trim().is_empty() && l.indent <= owner_indent {
                break;
            }
            let strip = *body_indent.get_or_insert(l.indent);
            let line_text = if l.raw.len() >= strip {
                &l.raw[strip.min(l.raw.len())..]
            } else {
                ""
            };
            body.push(line_text);
            self.pos += 1;
        }
        self.node();
        let joined = body.join(if folded { " " } else { "\n" });
        Node {
            line,
            kind: NodeKind::Scalar(clip(&joined)),
        }
    }

    /// A single-line flow collection. Returns the node and how many bytes of
    /// `text` it spanned (through the closing `]`/`}`). An unterminated or
    /// over-deep flow is `unknown`.
    fn parse_flow(&mut self, text: &str, line: usize, depth: usize) -> (Node, usize) {
        if depth > MAX_WF_DEPTH {
            return (self.unknown_at(line, "nested too deeply"), text.len());
        }
        let bytes = text.as_bytes();
        let open = bytes[0];
        let (close, seq) = if open == b'[' {
            (b']', true)
        } else {
            (b'}', false)
        };
        self.node();
        let mut items: Vec<Node> = Vec::new();
        let mut entries: Vec<Entry> = Vec::new();
        let mut i = 1;
        loop {
            // Skip spaces between items.
            while i < bytes.len() && bytes[i] == b' ' {
                i += 1;
            }
            if i >= bytes.len() {
                return (self.unknown_at(line, "an unterminated flow collection"), i);
            }
            if bytes[i] == close {
                i += 1;
                break;
            }
            // An empty collection `[]` / `{}` closes at once (handled above); a
            // trailing comma before the close is tolerated.
            let (raw_item, next) = scan_flow_item(text, i, close);
            i = next;
            let item = raw_item.trim();
            if !item.is_empty() {
                if seq {
                    let node = self.flow_value(item, line, depth);
                    items.push(node);
                } else if let Some((key, val)) = split_flow_entry(item) {
                    let value = self.flow_value(val.trim(), line, depth);
                    entries.push(Entry { key, line, value });
                } else {
                    self.mark(line, "a flow mapping entry without a key");
                }
            }
            // Step past a separating comma.
            while i < bytes.len() && bytes[i] == b' ' {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b',' {
                i += 1;
            } else if i < bytes.len() && bytes[i] == close {
                i += 1;
                break;
            } else if i >= bytes.len() {
                return (self.unknown_at(line, "an unterminated flow collection"), i);
            }
        }
        let kind = if seq {
            NodeKind::Seq(items)
        } else {
            NodeKind::Map(entries)
        };
        (Node { line, kind }, i)
    }

    /// A value inside a flow collection: a nested flow, or a scalar.
    fn flow_value(&mut self, item: &str, line: usize, depth: usize) -> Node {
        if item.starts_with('[') || item.starts_with('{') {
            let (node, used) = self.parse_flow(item, line, depth + 1);
            let tail = item[used.min(item.len())..].trim();
            if !tail.is_empty() {
                self.mark(line, "content after a flow collection");
            }
            node
        } else if item.starts_with('&') || item.starts_with('*') || item.starts_with('!') {
            self.unknown_at(line, "an anchor, alias or tag")
        } else {
            self.node();
            Node {
                line,
                kind: NodeKind::Scalar(scalar_value(item)),
            }
        }
    }
}

/// A line that opens a sequence item: `-` alone, or `-` then a space.
fn is_seq_line(l: &Raw) -> bool {
    l.content == "-" || l.content.starts_with("- ")
}

/// The bytes of one flow item, from `start` up to the next top-level `,` or the
/// closing `close`, quotes and nested `[]`/`{}` passed over. Returns the item's
/// text and the index of the delimiter.
fn scan_flow_item(text: &str, start: usize, close: u8) -> (&str, usize) {
    let bytes = text.as_bytes();
    let mut i = start;
    let mut depth = 0usize;
    let mut in_s = false;
    let mut in_d = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_s {
            if c == b'\'' {
                in_s = false;
            }
        } else if in_d {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_d = false;
            }
        } else {
            match c {
                b'\'' => in_s = true,
                b'"' => in_d = true,
                b'[' | b'{' => depth += 1,
                b']' | b'}' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                b',' if depth == 0 => break,
                c if c == close && depth == 0 => break,
                _ => {}
            }
        }
        i += 1;
    }
    (&text[start..i], i)
}

/// A flow mapping entry split at its `key:`.
fn split_flow_entry(item: &str) -> Option<(String, &str)> {
    let bytes = item.as_bytes();
    let mut in_s = false;
    let mut in_d = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_s {
            if c == b'\'' {
                in_s = false;
            }
        } else if in_d {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_d = false;
            }
        } else {
            match c {
                b'\'' => in_s = true,
                b'"' => in_d = true,
                b':' if i + 1 == bytes.len() || bytes[i + 1] == b' ' => {
                    let key = scalar_value(item[..i].trim());
                    if key.is_empty() {
                        return None;
                    }
                    return Some((key, &item[i + 1..]));
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// A line's `key:` split into the key (unquoted) and the text after the colon,
/// or `None` when the line is not a mapping entry. The key is a leading quoted
/// string, or the text up to the first `:` that ends the line or is followed by a
/// space, outside quotes.
fn split_key(content: &str) -> Option<(String, &str)> {
    let bytes = content.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == b'"' || bytes[0] == b'\'' {
        let q = bytes[0];
        let mut i = 1;
        while i < bytes.len() {
            if q == b'"' && bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == q {
                if q == b'\'' && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                break;
            }
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        let key_raw = &content[..=i];
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] == b' ' {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b':' {
            return None;
        }
        if j + 1 < bytes.len() && bytes[j + 1] != b' ' {
            return None;
        }
        let key = scalar_value(key_raw);
        let rest = content.get(j + 1..).unwrap_or("");
        return Some((key, rest));
    }
    let mut in_s = false;
    let mut in_d = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_s {
            if c == b'\'' {
                in_s = false;
            }
        } else if in_d {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_d = false;
            }
        } else {
            match c {
                b'\'' => in_s = true,
                b'"' => in_d = true,
                b':' if i + 1 == bytes.len() || bytes[i + 1] == b' ' => {
                    let key = content[..i].trim_end();
                    if key.is_empty() {
                        return None;
                    }
                    return Some((key.to_string(), content.get(i + 1..).unwrap_or("")));
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// A scalar's value: a fully single- or double-quoted string unquoted, else the
/// plain text with a trailing ` #` comment removed; then collapsed and cut.
fn scalar_value(r: &str) -> String {
    let t = r.trim();
    if let Some(inner) = fully_quoted(t) {
        return clip(&inner);
    }
    clip(strip_comment(t))
}

/// The content of `t` when it is one fully quoted scalar (the opening quote's
/// match is its last character), unescaped; `None` otherwise.
fn fully_quoted(t: &str) -> Option<String> {
    let bytes = t.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let q = bytes[0];
    if q != b'"' && q != b'\'' {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        if q == b'"' && bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == q {
            if q == b'\'' && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                i += 2;
                continue;
            }
            break;
        }
        i += 1;
    }
    if i != bytes.len() - 1 {
        return None; // the close is not the last character
    }
    let inner = &t[1..i];
    Some(if q == b'"' {
        unescape_double(inner)
    } else {
        inner.replace("''", "'")
    })
}

/// A double-quoted scalar's common escapes; an unknown escape is kept as written.
fn unescape_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('0') => out.push('\0'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The text before a ` #` comment, the comment outside quotes; `t` is trimmed.
fn strip_comment(t: &str) -> &str {
    let bytes = t.as_bytes();
    let mut in_s = false;
    let mut in_d = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_s {
            if c == b'\'' {
                in_s = false;
            }
        } else if in_d {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_d = false;
            }
        } else {
            match c {
                b'\'' => in_s = true,
                b'"' => in_d = true,
                b'#' if i > 0 && bytes[i - 1] == b' ' => return t[..i].trim_end(),
                _ => {}
            }
        }
        i += 1;
    }
    t
}

/// A scalar for a report: its whitespace collapsed to single spaces, cut after
/// `MAX_WF_SCALAR` characters with `...`.
fn clip(s: &str) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > MAX_WF_SCALAR {
        let mut out: String = collapsed.chars().take(MAX_WF_SCALAR).collect();
        out.push_str("...");
        out
    } else {
        collapsed
    }
}

// ---------------------------------------------------------------------------
// The node tree mapped to workflow facts
// ---------------------------------------------------------------------------

fn build(label: &str, entries: Vec<Entry>, unknown: Vec<Unknown>) -> Workflow {
    let mut wf = Workflow {
        file: label.to_string(),
        name: None,
        triggers: Vec::new(),
        permissions: Vec::new(),
        jobs: Vec::new(),
        unknown,
    };
    for e in entries {
        match e.key.as_str() {
            "name" => wf.name = scalar_of(&e.value),
            "on" => wf.triggers = events(&e.value),
            "permissions" => wf.permissions = perms(&e.value),
            "jobs" => {
                if let NodeKind::Map(jobs) = e.value.kind {
                    for j in jobs {
                        wf.jobs.push(job(j));
                    }
                }
            }
            _ => {}
        }
    }
    wf
}

fn events(node: &Node) -> Vec<String> {
    match &node.kind {
        NodeKind::Scalar(s) => vec![s.clone()],
        NodeKind::Seq(items) => items.iter().filter_map(scalar_of).collect(),
        NodeKind::Map(entries) => entries.iter().map(|e| e.key.clone()).collect(),
        _ => Vec::new(),
    }
}

fn perms(node: &Node) -> Vec<String> {
    match &node.kind {
        NodeKind::Scalar(s) => vec![s.clone()],
        NodeKind::Map(entries) => entries
            .iter()
            .map(|e| match scalar_of(&e.value) {
                Some(v) => format!("{}: {}", e.key, v),
                None => e.key.clone(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn job(entry: Entry) -> Job {
    let mut j = Job {
        id: entry.key,
        line: entry.line,
        cond: None,
        permissions: Vec::new(),
        uses: None,
        steps: Vec::new(),
    };
    if let NodeKind::Map(entries) = entry.value.kind {
        for e in entries {
            match e.key.as_str() {
                "if" => j.cond = scalar_of(&e.value),
                "permissions" => j.permissions = perms(&e.value),
                "uses" => j.uses = scalar_of(&e.value),
                "steps" => {
                    if let NodeKind::Seq(items) = e.value.kind {
                        for item in items {
                            j.steps.push(step(item));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    j
}

fn step(node: Node) -> Step {
    let mut s = Step {
        line: node.line,
        cond: None,
        uses: None,
        run: None,
        with: Vec::new(),
        env: Vec::new(),
    };
    if let NodeKind::Map(entries) = node.kind {
        for e in entries {
            match e.key.as_str() {
                "if" => s.cond = scalar_of(&e.value),
                "uses" => s.uses = scalar_of(&e.value),
                "run" => s.run = scalar_of(&e.value),
                "with" => s.with = pairs(&e.value),
                "env" => s.env = pairs(&e.value),
                _ => {}
            }
        }
    }
    s
}

fn pairs(node: &Node) -> Vec<Pair> {
    match &node.kind {
        NodeKind::Map(entries) => entries
            .iter()
            .map(|e| Pair {
                key: e.key.clone(),
                value: scalar_of(&e.value).unwrap_or_default(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn scalar_of(node: &Node) -> Option<String> {
    match &node.kind {
        NodeKind::Scalar(s) => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wf(src: &str) -> Workflow {
        parse_workflow("w.yml", src).expect("parses")
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
        let kinds: Vec<&str> = w.unknown.iter().map(|u| u.what.as_str()).collect();
        assert!(kinds.contains(&"an anchor (&)"), "{kinds:?}");
        assert!(kinds.contains(&"an alias (*)"), "{kinds:?}");
        assert!(kinds.contains(&"a tag (!)"), "{kinds:?}");
    }

    #[test]
    fn a_tab_in_indentation_is_unknown() {
        let w = wf("on: push\njobs:\n\tbuild:\n    steps: []\n");
        assert!(w.unknown.iter().any(|u| u.what == "a tab in indentation"));
    }

    #[test]
    fn a_second_document_is_refused() {
        let e = parse_workflow("w.yml", "on: push\n---\non: pull_request\n").unwrap_err();
        assert_eq!(e, "holds more than one YAML document");
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
        let w = wf("---\non: push\n");
        assert_eq!(w.triggers, ["push"]);
    }

    #[test]
    fn over_deep_nesting_is_marked_unknown() {
        let mut src = String::from("a:\n");
        for i in 0..(MAX_WF_DEPTH + 5) {
            src.push_str(&"  ".repeat(i + 1));
            src.push_str("b:\n");
        }
        // Parses without panic; the deepest levels are marked unknown.
        let w = parse_workflow("w.yml", &src).expect("parses");
        assert!(w.unknown.iter().any(|u| u.what == "nested too deeply"));
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
    fn comment_inside_quotes_is_not_a_comment() {
        let w = wf("jobs:\n  b:\n    steps:\n      - run: echo '# not a comment'\n");
        assert_eq!(
            w.jobs[0].steps[0].run.as_deref(),
            Some("echo '# not a comment'")
        );
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
}
