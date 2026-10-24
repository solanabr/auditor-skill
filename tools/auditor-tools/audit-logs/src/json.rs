//! A JSON reader that accepts exactly the lines the recipes' Python reader
//! accepts, and the two writers whose bytes the recipes print: Python's
//! `json.dumps(ensure_ascii=False)` and jq's compact `tostring`.
//!
//! Python rules kept here: whitespace is space, tab, LF and CR; `NaN`,
//! `Infinity` and a float that overflows are refused; a control character inside
//! a string is refused; a repeated key keeps its first position and its last
//! value; and a lone surrogate left by a `\u` escape refuses the line, unless a
//! later copy of its key replaced it. The recipes' own bounds are kept too: an
//! integer literal of more than 20 digits, or `-0`, anywhere in the line, refuses
//! it, and so does nesting deeper than 128 levels anywhere in the text (jq gives an
//! object two of its 256 parser slots), counted on the text before it is parsed,
//! so a value a later duplicate key replaces counts too ([`too_deep`]).

use std::borrow::Cow;
use std::collections::HashMap;

use crate::contract::unsafe_char;
use crate::num::{jq_number, py_float_repr, MAX_INT_DIGITS};

/// The deepest nesting a line may have, the top-level object being 1; one more
/// `[` or `{` makes the line malformed.
pub const MAX_DEPTH: usize = 128;

/// The recipes' `_too_deep`: true when the brackets outside strings in a line nest
/// deeper than [`MAX_DEPTH`]. A string, its escapes included, is one token, as is
/// one that never ends, which runs to the end of the line: one pass, whatever the
/// line holds. Unmatched closing brackets count down, as in the recipes.
pub fn too_deep(text: &[u8]) -> bool {
    if text.iter().filter(|&&c| c == b'[' || c == b'{').count() <= MAX_DEPTH {
        return false;
    }
    let mut depth: i64 = 0;
    let mut i = 0;
    while i < text.len() {
        match text[i] {
            b'"' => {
                i += 1;
                while i < text.len() && text[i] != b'"' {
                    i += if text[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'[' | b'{' => {
                depth += 1;
                if depth > MAX_DEPTH as i64 {
                    return true;
                }
                i += 1;
            }
            b']' | b'}' => {
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    false
}

/// Objects with more keys than this look up repeated keys through a map.
const INDEXED_KEYS: usize = 32;

#[derive(Debug)]
pub enum Value<'a> {
    Null,
    Bool(bool),
    Num(Num<'a>),
    Str(Cow<'a, str>),
    Arr(Vec<Value<'a>>),
    Obj(Vec<(Cow<'a, str>, Value<'a>)>),
}

/// A number as written in the line: a Python int when `float` is false, else a
/// Python float.
#[derive(Debug, Clone, Copy)]
pub struct Num<'a> {
    pub lit: &'a str,
    pub float: bool,
}

impl<'a> Value<'a> {
    /// The value under `key`, as Python's `dict.get`: `None` when the key is
    /// absent or this is not an object.
    pub fn get(&self, key: &str) -> Option<&Value<'a>> {
        match self {
            Value::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value under `key`, with JSON null read as absent (`dict.get(k) is None`).
    pub fn field(&self, key: &str) -> Option<&Value<'a>> {
        match self.get(key) {
            Some(Value::Null) | None => None,
            v => v,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value<'a>]> {
        match self {
            Value::Arr(items) => Some(items),
            _ => None,
        }
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Value::Obj(_))
    }

    /// An integer literal (a Python int, not a bool or a float).
    pub fn as_int_lit(&self) -> Option<&'a str> {
        match self {
            Value::Num(n) if !n.float => Some(n.lit),
            _ => None,
        }
    }
}

/// The value one line holds, or `None` when Python's reader would refuse it.
pub fn parse_line(text: &str) -> Option<Value<'_>> {
    let mut p = Parser {
        s: text,
        b: text.as_bytes(),
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let (value, lone) = p.value().ok()?;
    p.skip_ws();
    if p.pos != p.b.len() || lone {
        return None;
    }
    Some(value)
}

struct Parser<'a> {
    s: &'a str,
    b: &'a [u8],
    pos: usize,
    depth: usize,
}

/// A parse error; the line is malformed.
struct Bad;

type Parsed<'a> = Result<(Value<'a>, bool), Bad>;

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.b.get(self.pos) {
            self.pos += 1;
        }
    }

    fn literal(&mut self, word: &str, value: Value<'a>) -> Parsed<'a> {
        if self.b[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok((value, false))
        } else {
            Err(Bad)
        }
    }

    /// One value. The flag is true when a lone surrogate is still in it.
    fn value(&mut self) -> Parsed<'a> {
        match self.b.get(self.pos) {
            Some(b'"') => {
                let (s, lone) = self.string()?;
                Ok((Value::Str(s), lone))
            }
            Some(b'{') => self.nested(Self::object),
            Some(b'[') => self.nested(Self::array),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(Bad),
        }
    }

    fn nested(&mut self, parse: fn(&mut Self) -> Parsed<'a>) -> Parsed<'a> {
        if self.depth == MAX_DEPTH {
            return Err(Bad);
        }
        self.depth += 1;
        let out = parse(self);
        self.depth -= 1;
        out
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while let Some(b'0'..=b'9') = self.b.get(self.pos) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Parsed<'a> {
        let start = self.pos;
        if self.b[self.pos] == b'-' {
            self.pos += 1;
        }
        match self.b.get(self.pos) {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(Bad),
        }
        let int_end = self.pos;
        let mut float = false;
        if self.b.get(self.pos) == Some(&b'.')
            && matches!(self.b.get(self.pos + 1), Some(b'0'..=b'9'))
        {
            self.pos += 1;
            self.digits();
            float = true;
        }
        if let Some(b'e' | b'E') = self.b.get(self.pos) {
            let mark = self.pos;
            self.pos += 1;
            if let Some(b'+' | b'-') = self.b.get(self.pos) {
                self.pos += 1;
            }
            if self.digits() > 0 {
                float = true;
            } else {
                self.pos = mark;
            }
        }
        let lit = &self.s[start..self.pos];
        if float {
            match lit.parse::<f64>() {
                Ok(v) if v.is_finite() => {}
                _ => return Err(Bad),
            }
        } else {
            let digits = int_end - start - usize::from(lit.starts_with('-'));
            if digits > MAX_INT_DIGITS || lit == "-0" {
                return Err(Bad);
            }
        }
        Ok((Value::Num(Num { lit, float }), false))
    }

    fn hex4(&mut self) -> Result<u32, Bad> {
        let quad = self.b.get(self.pos..self.pos + 4).ok_or(Bad)?;
        let mut v = 0u32;
        for &c in quad {
            v = v * 16 + char::from(c).to_digit(16).ok_or(Bad)?;
        }
        self.pos += 4;
        Ok(v)
    }

    /// A string, the cursor on its opening quote. The flag is true when a `\u`
    /// escape left a lone surrogate (kept as U+FFFD; the line is refused anyway).
    fn string(&mut self) -> Result<(Cow<'a, str>, bool), Bad> {
        self.pos += 1;
        let start = self.pos;
        loop {
            match self.b.get(self.pos) {
                None => return Err(Bad),
                Some(b'"') => {
                    let s = &self.s[start..self.pos];
                    self.pos += 1;
                    return Ok((Cow::Borrowed(s), false));
                }
                Some(b'\\') => break,
                Some(&c) if c < 0x20 => return Err(Bad),
                Some(_) => self.pos += 1,
            }
        }
        let mut out = String::from(&self.s[start..self.pos]);
        let mut lone = false;
        loop {
            let run = self.pos;
            loop {
                match self.b.get(self.pos) {
                    None => return Err(Bad),
                    Some(b'"' | b'\\') => break,
                    Some(&c) if c < 0x20 => return Err(Bad),
                    Some(_) => self.pos += 1,
                }
            }
            out.push_str(&self.s[run..self.pos]);
            if self.b[self.pos] == b'"' {
                self.pos += 1;
                return Ok((Cow::Owned(out), lone));
            }
            self.pos += 1;
            let esc = *self.b.get(self.pos).ok_or(Bad)?;
            self.pos += 1;
            match esc {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let hi = self.hex4()?;
                    if (0xD800..0xDC00).contains(&hi) && self.b[self.pos..].starts_with(b"\\u") {
                        let mark = self.pos;
                        self.pos += 2;
                        let lo = self.hex4()?;
                        if (0xDC00..0xE000).contains(&lo) {
                            let c = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                            out.push(char::from_u32(c).ok_or(Bad)?);
                            continue;
                        }
                        self.pos = mark;
                    }
                    match char::from_u32(hi) {
                        Some(c) => out.push(c),
                        None => {
                            out.push('\u{FFFD}');
                            lone = true;
                        }
                    }
                }
                _ => return Err(Bad),
            }
        }
    }

    fn array(&mut self) -> Parsed<'a> {
        self.pos += 1;
        self.skip_ws();
        let mut items = Vec::new();
        let mut lone = false;
        if self.b.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok((Value::Arr(items), false));
        }
        loop {
            let (v, l) = self.value()?;
            items.push(v);
            lone |= l;
            self.skip_ws();
            match self.b.get(self.pos) {
                Some(b']') => {
                    self.pos += 1;
                    return Ok((Value::Arr(items), lone));
                }
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                _ => return Err(Bad),
            }
        }
    }

    fn object(&mut self) -> Parsed<'a> {
        self.pos += 1;
        self.skip_ws();
        let mut entries: Vec<(Cow<'a, str>, Value<'a>)> = Vec::new();
        let mut value_lone: Vec<bool> = Vec::new();
        let mut key_lone = false;
        let mut index: Option<HashMap<String, usize>> = None;
        if self.b.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok((Value::Obj(entries), false));
        }
        loop {
            if self.b.get(self.pos) != Some(&b'"') {
                return Err(Bad);
            }
            let (key, kl) = self.string()?;
            key_lone |= kl;
            self.skip_ws();
            if self.b.get(self.pos) != Some(&b':') {
                return Err(Bad);
            }
            self.pos += 1;
            self.skip_ws();
            let (v, vl) = self.value()?;
            let found = match &index {
                Some(map) => map.get(key.as_ref()).copied(),
                None => entries.iter().position(|(k, _)| *k == key),
            };
            match found {
                Some(i) => {
                    entries[i].1 = v;
                    value_lone[i] = vl;
                }
                None => {
                    if let Some(map) = index.as_mut() {
                        map.insert(key.to_string(), entries.len());
                    }
                    entries.push((key, v));
                    value_lone.push(vl);
                    if index.is_none() && entries.len() > INDEXED_KEYS {
                        index = Some(
                            entries
                                .iter()
                                .enumerate()
                                .map(|(i, (k, _))| (k.to_string(), i))
                                .collect(),
                        );
                    }
                }
            }
            self.skip_ws();
            match self.b.get(self.pos) {
                Some(b'}') => {
                    self.pos += 1;
                    let lone = key_lone || value_lone.iter().any(|&l| l);
                    return Ok((Value::Obj(entries), lone));
                }
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                _ => return Err(Bad),
            }
        }
    }
}

/// Appends `json.dumps(value, ensure_ascii=False)` as Python prints it.
pub fn write_py(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Num(n) => write_py_num(out, n),
        Value::Str(s) => write_py_str(out, s),
        Value::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py(out, item);
            }
            out.push(']');
        }
        Value::Obj(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py_str(out, k);
                out.push_str(": ");
                write_py(out, v);
            }
            out.push('}');
        }
    }
}

fn write_py_num(out: &mut String, n: &Num) {
    if n.float {
        match n.lit.parse::<f64>() {
            Ok(v) => out.push_str(&py_float_repr(v)),
            Err(_) => out.push_str(n.lit),
        }
    } else {
        out.push_str(n.lit);
    }
}

/// Appends `c` as a JSON `\uNNNN` escape, or a surrogate pair of them above U+FFFF.
fn push_json_escape(out: &mut String, c: char) {
    let mut units = [0u16; 2];
    for unit in c.encode_utf16(&mut units).iter() {
        out.push_str(&format!("\\u{unit:04x}"));
    }
}

/// A Python str as frames.py writes it: `json.dumps(ensure_ascii=False)`, which
/// escapes quote, backslash and the C0 controls (`\n`-style where JSON has one,
/// else `\u00XX`), then every other unsafe character as `\uNNNN` (a surrogate
/// pair above U+FFFF).
pub fn write_py_str(out: &mut String, s: &str) {
    out.push('"');
    let mut run = 0;
    for (i, c) in s.char_indices() {
        let esc = match c {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            '\u{8}' => "\\b",
            '\u{c}' => "\\f",
            c if unsafe_char(c) => "",
            _ => continue,
        };
        out.push_str(&s[run..i]);
        if esc.is_empty() {
            push_json_escape(out, c);
        } else {
            out.push_str(esc);
        }
        run = i + c.len_utf8();
    }
    out.push_str(&s[run..]);
    out.push('"');
}

/// Appends a value's compact JSON text as profile.sh prints a version that is not a
/// string: jq's `tostring`, with no unsafe character raw.
pub fn write_jq(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Num(n) => out.push_str(&jq_number(n.lit)),
        Value::Str(s) => write_jq_str(out, s),
        Value::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jq(out, item);
            }
            out.push(']');
        }
        Value::Obj(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jq_str(out, k);
                out.push(':');
                write_jq(out, v);
            }
            out.push('}');
        }
    }
}

/// A string as profile.sh prints it in a version: jq's dump (quote and backslash
/// escaped, the C0 controls and DEL as `\n`-style escapes or `\u00xx`), with every
/// other unsafe character as `\uNNNN` too (a surrogate pair above U+FFFF).
fn write_jq_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if unsafe_char(c) => push_json_escape(out, c),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py(line: &str) -> Option<String> {
        parse_line(line).map(|v| {
            let mut s = String::new();
            write_py(&mut s, &v);
            s
        })
    }

    #[test]
    fn accepts_what_python_accepts() {
        assert_eq!(
            py(r#"{"a": [1, 2.50, -1, 1E2, -0.0, "x"]}"#).unwrap(),
            r#"{"a": [1, 2.5, -1, 100.0, -0.0, "x"]}"#
        );
        assert_eq!(py("{\"a\":\r1}").unwrap(), r#"{"a": 1}"#);
        assert_eq!(
            py(r#"{"a": 1, "b": 2, "a": 3}"#).unwrap(),
            r#"{"a": 3, "b": 2}"#
        );
        assert_eq!(
            py(r#"["\ud83d\ude00", "\\ud800"]"#).unwrap(),
            "[\"\u{1F600}\", \"\\\\ud800\"]"
        );
        assert_eq!(
            py(r#"{"a": "\ud800", "a": "ok"}"#).unwrap(),
            r#"{"a": "ok"}"#
        );
        assert_eq!(
            py(r#"[1e-400, 1e16, 1e-7]"#).unwrap(),
            "[0.0, 1e+16, 1e-07]"
        );
        assert_eq!(py(&format!("[{}]", "1".repeat(20))).unwrap().len(), 22);
        assert_eq!(py(&format!("[-{}]", "9".repeat(20))).unwrap().len(), 23);
        assert_eq!(
            py("\"\u{7f}\u{85}\u{2028}\u{202e}\u{feff}\u{a0}\u{e9}\"").unwrap(),
            "\"\\u007f\\u0085\\u2028\\u202e\\ufeff\u{a0}\u{e9}\""
        );
        assert_eq!(py(r#""\u0001\b\f""#).unwrap(), r#""\u0001\b\f""#);
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(py(&deep).is_some());
    }

    #[test]
    fn refuses_what_python_refuses() {
        for bad in [
            "{\"a\": NaN}",
            "[Infinity]",
            "[-Infinity]",
            "[1e400]",
            "[01]",
            "[1.]",
            "[.5]",
            "[+1]",
            "[1,]",
            "{\"a\":1,}",
            "{a:1}",
            "\"a\u{1}b\"",
            "\"a\tb\"",
            "[\"\\ud800\"]",
            "{\"\\udc00\": 1}",
            "[\"\\ud800\\u0041\"]",
            "[\"\\x\"]",
            "[\"\\u12\"]",
            "[1] [2]",
            "[1]\u{b}",
            "\u{feff}[1]",
            "",
            "tru",
        ] {
            assert!(py(bad).is_none(), "{bad:?}");
        }
        assert!(py(&format!("[{}]", "1".repeat(21))).is_none());
        assert!(py(&format!("[-{}]", "1".repeat(21))).is_none());
        assert!(py("[-0]").is_none());
        assert!(py(r#"{"a": -0, "a": 1}"#).is_none());
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert!(py(&deep).is_none());
    }

    fn objects(n: usize) -> String {
        format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n))
    }

    #[test]
    fn depth_is_counted_on_the_text() {
        assert!(!too_deep(objects(128).as_bytes()));
        assert!(py(&objects(128)).is_some());
        assert!(too_deep(objects(129).as_bytes()));
        let mixed = format!(
            "{}{}{}",
            "{\"a\":".repeat(100),
            "[".repeat(29),
            "]".repeat(29)
        );
        assert!(too_deep(mixed.as_bytes()));
        // A replaced value counts; brackets inside a string, escaped quotes included, do not.
        let replaced = format!("{{\"x\":{},\"x\":1}}", "[".repeat(150) + &"]".repeat(150));
        assert!(too_deep(replaced.as_bytes()));
        let quoted = format!("{{\"x\":\"\\\"{}\"}}", "[".repeat(300));
        assert!(!too_deep(quoted.as_bytes()));
        // Closing brackets first count down.
        let down = format!("{}{}", "]".repeat(200), "[".repeat(200));
        assert!(!too_deep(down.as_bytes()));
        // A string that never ends is one token to the end of the line, read once:
        // the brackets after its opening quote are inside it.
        let open = format!(
            "{{\"note\": \"x{}{}",
            "\\\"".repeat(512 * 1024),
            "[".repeat(200)
        );
        assert!(!too_deep(open.as_bytes()));
        assert!(py(&open).is_none());
        let after = format!("{}\"{}", "[".repeat(129), "\\\"".repeat(512 * 1024));
        assert!(too_deep(after.as_bytes()));
        // A backslash that ends the line ends the string before it.
        assert!(!too_deep(format!("\"{}\\", "[".repeat(200)).as_bytes()));
    }

    #[test]
    fn jq_text() {
        let v = parse_line(r#"{"a":[1.0,"\u007f",1E2,{"b":true}],"c":null}"#).unwrap();
        let mut s = String::new();
        write_jq(&mut s, &v);
        assert_eq!(s, r#"{"a":[1.0,"\u007f",1E+2,{"b":true}],"c":null}"#);
        let v = parse_line(
            r#"{"k\u2028":["\u0001\n\u0085\u00a0\u061c\u200b\u202e\u2069\ufeff\u3000"]}"#,
        )
        .unwrap();
        let mut s = String::new();
        write_jq(&mut s, &v);
        assert_eq!(
            s,
            "{\"k\\u2028\":[\"\\u0001\\n\\u0085\u{a0}\\u061c\\u200b\\u202e\\u2069\\ufeff\u{3000}\"]}"
        );
        let v =
            parse_line(r#"["\u00ad\u2060\ud834\udd73\udb40\udc41\ufff9\ud83d\ude00"]"#).unwrap();
        let mut s = String::new();
        write_jq(&mut s, &v);
        assert_eq!(
            s,
            "[\"\\u00ad\\u2060\\ud834\\udd73\\udb40\\udc41\u{fff9}\u{1f600}\"]"
        );
        let mut s = String::new();
        write_py(&mut s, &v);
        assert_eq!(
            s,
            "[\"\\u00ad\\u2060\\ud834\\udd73\\udb40\\udc41\u{fff9}\u{1f600}\"]"
        );
    }
}
