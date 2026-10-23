//! The recipes' input contract (scripts/dnr/README.md, "Input contract"): how
//! lines are read, which lines are malformed, the first-signature dedupe, and
//! the "skipped" notes. Each rule mirrors the block that profile.sh, frames.py
//! and deltas.py share.

use std::collections::HashSet;
use std::fs::Metadata;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;

use crate::confine::open_checked;
use crate::json::{parse_line, Value};

/// What one pass skipped: later copies of a transaction, and per input the
/// malformed lines (label, count, first line number).
#[derive(Default)]
pub struct Stats {
    pub dupes: u64,
    pub bad: Vec<(String, u64, u64)>,
}

impl Stats {
    /// The notes, each to follow the word "skipped": the copies first, then the
    /// malformed lines of each input, which are collection gaps.
    pub fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.dupes > 0 {
            notes.push(format!(
                "{} transaction(s) already read under the same signature",
                self.dupes
            ));
        }
        for (label, count, first) in &self.bad {
            notes.push(format!(
                "{count} malformed line(s) in {label}, the first at line {first} (not a getTransaction JSON object the recipes can read)"
            ));
        }
        notes
    }
}

/// A path or other text for a message, as the scripts' `shown()` prints it:
/// Python's `unicode_escape` of the text (bytes that are not UTF-8 as `\udcXX`,
/// as Python decodes a command-line argument), cut at 120 characters.
pub fn shown(raw: &[u8]) -> String {
    let mut s = String::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let (good, bad) = match std::str::from_utf8(rest) {
            Ok(text) => (text, 0),
            Err(e) => {
                let valid = e.valid_up_to();
                let text = std::str::from_utf8(&rest[..valid]).unwrap_or("");
                (text, e.error_len().unwrap_or(rest.len() - valid))
            }
        };
        for c in good.chars() {
            escape_char(&mut s, c as u32);
        }
        let skip = good.len();
        for &b in &rest[skip..skip + bad] {
            escape_char(&mut s, 0xDC00 + u32::from(b));
        }
        rest = &rest[skip + bad..];
    }
    if s.len() > 120 {
        s.truncate(120);
        s.push_str("...");
    }
    s
}

/// Appends Python's `unicode_escape` of one character.
pub fn escape_char(s: &mut String, c: u32) {
    match c {
        0x5C => s.push_str("\\\\"),
        0x09 => s.push_str("\\t"),
        0x0A => s.push_str("\\n"),
        0x0D => s.push_str("\\r"),
        0x20..=0x7E => s.push(char::from(c as u8)),
        0..=0xFF => s.push_str(&format!("\\x{c:02x}")),
        0x100..=0xFFFF => s.push_str(&format!("\\u{c:04x}")),
        _ => s.push_str(&format!("\\U{c:08x}")),
    }
}

/// A character the recipes never accept in a key, program id or version, and
/// never print raw: a C0 control, DEL, a C1 control, the line and paragraph
/// separators, a bidirectional control, or a zero-width character.
pub fn unsafe_char(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{1f}'
        | '\u{7f}'..='\u{9f}'
        | '\u{2028}'
        | '\u{2029}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}'
        | '\u{200e}'
        | '\u{200f}'
        | '\u{61c}'
        | '\u{200b}'..='\u{200d}'
        | '\u{feff}')
}

/// A string with no unsafe character, so it prints as one line, as written.
fn plain(v: &Value) -> bool {
    match v {
        Value::Str(s) => !s.chars().any(unsafe_char),
        _ => false,
    }
}

/// `_of(v, *types)`: absent or null, or exactly the given kind.
fn of(v: Option<&Value>, kind: fn(&Value) -> bool) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(x) => kind(x),
    }
}

fn is_obj(v: &Value) -> bool {
    matches!(v, Value::Obj(_))
}

fn is_arr(v: &Value) -> bool {
    matches!(v, Value::Arr(_))
}

fn is_int(v: &Value) -> bool {
    v.as_int_lit().is_some()
}

fn is_str(v: &Value) -> bool {
    matches!(v, Value::Str(_))
}

/// Items of an optional list; absent, null or empty all give none.
fn items<'v, 'a>(v: Option<&'v Value<'a>>) -> &'v [Value<'a>] {
    v.and_then(Value::as_array).unwrap_or(&[])
}

/// Decimal digits that hold a u64 value (leading zeros allowed).
fn u64_digits(digits: &str) -> bool {
    let value = digits.trim_start_matches('0');
    !digits.is_empty()
        && digits.bytes().all(|c| c.is_ascii_digit())
        && (value.len() < 20 || (value.len() == 20 && value <= "18446744073709551615"))
}

/// `_u64`: an integer a u64 holds, as a lamport balance and the fee are.
fn u64_int(v: &Value) -> bool {
    match v.as_int_lit() {
        Some("-0") => true,
        Some(lit) => u64_digits(lit),
        None => false,
    }
}

/// `_index`: absent or null, or an integer from 0.
fn index(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(x) => x
            .as_int_lit()
            .is_some_and(|lit| lit == "-0" || !lit.starts_with('-')),
    }
}

/// `_amount`: the decimal text of a u64, in at most 20 ASCII digits.
fn amount(v: &Value) -> bool {
    match v {
        Value::Str(s) => s.len() <= 20 && u64_digits(s),
        _ => false,
    }
}

fn instruction(ix: &Value) -> bool {
    ix.is_object()
        && index(ix.get("programIdIndex"))
        && of(ix.get("accounts"), is_arr)
        && match ix.get("programId") {
            None | Some(Value::Null) => true,
            Some(p) => plain(p) && p.as_str() != Some(""),
        }
}

fn token_balance(b: &Value) -> bool {
    if !(b.is_object()
        && index(b.get("accountIndex"))
        && of(b.get("owner"), is_str)
        && of(b.get("mint"), is_str)
        && of(b.get("uiTokenAmount"), is_obj))
    {
        return false;
    }
    match b.get("uiTokenAmount").and_then(|u| u.get("amount")) {
        None | Some(Value::Null) => true,
        Some(a) => amount(a),
    }
}

/// `shaped()`: every field a recipe reads has the type it reads it as, and every
/// key, program id and version profile.sh prints is one line.
pub fn shaped(tx: &Value) -> bool {
    if !tx.is_object() {
        return false;
    }
    let t = tx.get("transaction");
    let meta = tx.get("meta");
    if !(of(t, is_obj) && of(meta, is_obj) && of(tx.get("blockTime"), is_int)) {
        return false;
    }
    if let Some(v @ Value::Str(_)) = tx.get("version") {
        if !plain(v) {
            return false;
        }
    }
    let m = t.and_then(|t| t.get("message"));
    let sigs = t.and_then(|t| t.get("signatures"));
    if !(of(m, is_obj) && of(sigs, is_arr) && items(sigs).iter().all(is_str)) {
        return false;
    }
    let keys = m.and_then(|m| m.get("accountKeys"));
    let header = m.and_then(|m| m.get("header"));
    let ixs = m.and_then(|m| m.get("instructions"));
    if !(of(keys, is_arr)
        && of(header, is_obj)
        && of(ixs, is_arr)
        && index(header.and_then(|h| h.get("numRequiredSignatures")))
        && items(ixs).iter().all(instruction))
    {
        return false;
    }
    let keys = items(keys);
    if !keys.is_empty()
        && !(keys.iter().all(plain)
            || keys
                .iter()
                .all(|k| k.is_object() && k.get("pubkey").is_some_and(plain)))
    {
        return false;
    }
    let groups = meta.and_then(|m| m.get("innerInstructions"));
    let loaded = meta.and_then(|m| m.get("loadedAddresses"));
    let logs = meta.and_then(|m| m.get("logMessages"));
    if !(of(groups, is_arr)
        && of(loaded, is_obj)
        && of(logs, is_arr)
        && of(meta.and_then(|m| m.get("fee")), u64_int)
        && items(logs).iter().all(is_str))
    {
        return false;
    }
    for g in items(groups) {
        let inner = g.get("instructions");
        if !(g.is_object()
            && !matches!(g.get("index"), None | Some(Value::Null))
            && index(g.get("index"))
            && of(inner, is_arr)
            && items(inner).iter().all(instruction))
        {
            return false;
        }
    }
    for name in ["writable", "readonly"] {
        let v = loaded.and_then(|l| l.get(name));
        if !(of(v, is_arr) && items(v).iter().all(is_str)) {
            return false;
        }
    }
    for name in ["preBalances", "postBalances"] {
        let v = meta.and_then(|m| m.get(name));
        if !(of(v, is_arr) && items(v).iter().all(u64_int)) {
            return false;
        }
    }
    let balances = |name| items(meta.and_then(|m| m.get(name))).len();
    if balances("preBalances") != balances("postBalances") {
        return false;
    }
    for name in ["preTokenBalances", "postTokenBalances"] {
        let v = meta.and_then(|m| m.get(name));
        if !(of(v, is_arr) && items(v).iter().all(token_balance)) {
            return false;
        }
    }
    true
}

/// Python's `bytes.strip()`: space, tab, LF, CR, VT and FF at either end.
fn strip(line: &[u8]) -> &[u8] {
    let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C);
    let start = line.iter().position(|c| !ws(c)).unwrap_or(line.len());
    let end = line.iter().rposition(|c| !ws(c)).map_or(start, |i| i + 1);
    &line[start..end]
}

/// Where an input's lines come from: a checked file, opened when its turn
/// comes and refused unless it is still the file checked, or stdin.
pub enum Source {
    Stdin,
    File(PathBuf, Metadata),
}

/// One input to read, with the label its "skipped" note names it by.
pub struct Input {
    pub label: String,
    pub source: Source,
}

/// Calls `each` with every well-formed transaction of the inputs, in order, once
/// per signature: lines split on LF only, stripped, UTF-8, one JSON object of
/// the right shape. Malformed lines and later copies are counted in `stats`.
pub fn for_each_record<F>(inputs: Vec<Input>, stats: &mut Stats, mut each: F) -> io::Result<()>
where
    F: FnMut(&Value) -> io::Result<()>,
{
    let mut seen: HashSet<String> = HashSet::new();
    let mut buf = Vec::with_capacity(1 << 16);
    for input in inputs {
        let mut reader: Box<dyn BufRead> = match &input.source {
            Source::Stdin => Box::new(io::stdin().lock()),
            Source::File(path, md) => {
                Box::new(BufReader::with_capacity(1 << 16, open_checked(path, md)?))
            }
        };
        let mut bad: Option<usize> = None;
        let mut lineno: u64 = 0;
        loop {
            buf.clear();
            if reader.read_until(b'\n', &mut buf)? == 0 {
                break;
            }
            lineno += 1;
            let line = strip(&buf);
            if line.is_empty() {
                continue;
            }
            let tx = std::str::from_utf8(line)
                .ok()
                .and_then(parse_line)
                .filter(shaped);
            let Some(tx) = tx else {
                match bad {
                    Some(i) => stats.bad[i].1 += 1,
                    None => {
                        stats.bad.push((input.label.clone(), 1, lineno));
                        bad = Some(stats.bad.len() - 1);
                    }
                }
                continue;
            };
            let first_sig = tx
                .field("transaction")
                .and_then(|t| t.field("signatures"))
                .and_then(Value::as_array)
                .and_then(|s| s.first())
                .and_then(Value::as_str);
            if let Some(sig) = first_sig {
                if seen.contains(sig) {
                    stats.dupes += 1;
                    continue;
                }
                seen.insert(sig.to_string());
            }
            each(&tx)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shown_escapes_like_python() {
        assert_eq!(
            shown(b"incident_1/corpus/transactions.jsonl"),
            "incident_1/corpus/transactions.jsonl"
        );
        assert_eq!(
            shown("a\\b\tc\nd\u{1b}e\u{7f}é\u{2028}\u{1F600}".as_bytes()),
            "a\\\\b\\tc\\nd\\x1be\\x7f\\xe9\\u2028\\U0001f600"
        );
        assert_eq!(shown(b"x\xffy\xe2\x82z"), "x\\udcffy\\udce2\\udc82z");
        let long = "x".repeat(200);
        assert_eq!(shown(long.as_bytes()), format!("{}...", "x".repeat(120)));
    }

    fn reads(meta: &str, message: &str) -> bool {
        let line = format!(
            r#"{{"meta":{{{meta}}},"transaction":{{"signatures":["S"],"message":{{{message}}}}}}}"#
        );
        parse_line(&line).is_some_and(|tx| shaped(&tx))
    }

    #[test]
    fn balances_and_amounts_are_u64() {
        let keys = r#""accountKeys":["K","L"]"#;
        assert!(reads(
            r#""preBalances":[0,18446744073709551615],"postBalances":[-0,1]"#,
            keys
        ));
        assert!(!reads(
            r#""preBalances":[18446744073709551616],"postBalances":[1]"#,
            keys
        ));
        assert!(!reads(r#""preBalances":[-1],"postBalances":[1]"#, keys));
        assert!(!reads(r#""preBalances":[1,2],"postBalances":[1]"#, keys));
        assert!(!reads(r#""preBalances":[1]"#, keys));
        assert!(!reads(r#""fee":-5"#, keys));
        let amount = |a: &str| {
            reads(
                &format!(r#""postTokenBalances":[{{"uiTokenAmount":{{"amount":{a}}}}}]"#),
                keys,
            )
        };
        assert!(amount(r#""18446744073709551615""#));
        assert!(amount(r#""00000000000000000007""#));
        assert!(!amount(r#""18446744073709551616""#));
        assert!(!amount(r#""000000000000000000007""#));
        assert!(!amount(r#""""#));
    }

    #[test]
    fn indexes_and_program_ids() {
        let ix = |i: &str| reads("", &format!(r#""accountKeys":["K"],"instructions":[{i}]"#));
        assert!(ix(r#"{"programIdIndex":0}"#));
        assert!(ix(r#"{"programIdIndex":-0}"#));
        assert!(!ix(r#"{"programIdIndex":-1}"#));
        assert!(!ix(r#"{"programId":""}"#));
        assert!(reads(
            r#""innerInstructions":[{"index":3,"instructions":[]}]"#,
            ""
        ));
        assert!(!reads(
            r#""innerInstructions":[{"index":-2,"instructions":[]}]"#,
            ""
        ));
        assert!(!reads(
            r#""innerInstructions":[{"index":null,"instructions":[]}]"#,
            ""
        ));
        assert!(!reads("", r#""header":{"numRequiredSignatures":-1}"#));
    }

    #[test]
    fn keys_hold_no_unsafe_character() {
        for c in [
            "\\u0000", "\\u001b", "\\u007f", "\\u0085", "\\u2028", "\\u2029", "\\u202e", "\\u2066",
            "\\u200f", "\\u061c", "\\u200b", "\\ufeff",
        ] {
            assert!(!reads("", &format!(r#""accountKeys":["K{c}"]"#)), "{c}");
        }
        assert!(reads("", r#""accountKeys":["K é　"]"#));
    }

    #[test]
    fn strips_ascii_whitespace_only() {
        assert_eq!(strip(b" \t{}\r\n"), b"{}");
        assert_eq!(strip(b"\x0b\x0c{}\x0c"), b"{}");
        assert_eq!(strip(b"\x1c{}"), b"\x1c{}");
        assert_eq!(strip(b" \r\n"), b"");
    }
}
