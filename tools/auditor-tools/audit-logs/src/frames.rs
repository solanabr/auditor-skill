//! `audit-logs frames [--instructions]`: the records `scripts/dnr/frames.py`
//! prints, as `json.dumps(ensure_ascii=False)` writes them. The log array is
//! walked one element at a time, and the runtime's own lines are matched whole,
//! so text inside a `Program log:` payload never opens or closes a frame.

use std::collections::HashMap;

use crate::json::{write_py, write_py_str, Value};

const LOG: &str = "Program log: ";
const DATA: &str = "Program data: ";

fn b58(c: u8) -> bool {
    matches!(c, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}

/// `([B58]{32,44})` at the start of `s`, followed by `sep`: the id and the rest.
fn id_then<'s>(s: &'s str, sep: &str) -> Option<(&'s str, &'s str)> {
    let n = s.bytes().take_while(|&c| b58(c)).count();
    if (32..=44).contains(&n) && s[n..].starts_with(sep) {
        Some((&s[..n], &s[n + sep.len()..]))
    } else {
        None
    }
}

fn ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// `^Program (<id>) invoke \[([0-9]{1,9})\]\Z`
fn invoke(msg: &str) -> Option<(&str, u32)> {
    let (id, rest) = id_then(msg.strip_prefix("Program ")?, " invoke [")?;
    let depth = rest.strip_suffix(']')?;
    if depth.len() <= 9 && ascii_digits(depth) {
        Some((id, depth.parse().ok()?))
    } else {
        None
    }
}

/// `^Program (<id>) (success|failed: .*)\Z`, where `.` is any character but LF.
fn exit(msg: &str) -> Option<&str> {
    let (_, rest) = id_then(msg.strip_prefix("Program ")?, " ")?;
    (rest == "success" || (rest.starts_with("failed: ") && !rest.contains('\n'))).then_some(rest)
}

/// `^Program (<id>) consumed [0-9]+ of [0-9]+ compute units\Z`
fn consumed(msg: &str) -> bool {
    let check = || {
        let (_, rest) = id_then(msg.strip_prefix("Program ")?, " consumed ")?;
        let (used, rest) = rest.split_once(" of ")?;
        let limit = rest.strip_suffix(" compute units")?;
        (ascii_digits(used) && ascii_digits(limit)).then_some(())
    };
    check().is_some()
}

/// `^Program return: (<id>) (.*)\Z`
fn returned(msg: &str) -> Option<(&str, &str)> {
    let (id, rest) = id_then(msg.strip_prefix("Program return: ")?, " ")?;
    (!rest.contains('\n')).then_some((id, rest))
}

fn first_sig<'v>(tx: &'v Value) -> &'v str {
    tx.field("transaction")
        .and_then(|t| t.field("signatures"))
        .and_then(Value::as_array)
        .and_then(|s| s.first())
        .and_then(Value::as_str)
        .unwrap_or("?")
}

fn ok(tx: &Value) -> bool {
    tx.field("meta").and_then(|m| m.field("err")).is_none()
}

fn logs<'v, 'a>(tx: &'v Value<'a>) -> impl Iterator<Item = &'v str> {
    tx.field("meta")
        .and_then(|m| m.field("logMessages"))
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(Value::as_str)
}

fn head(out: &mut String, sig: &str, ok: bool) {
    out.push_str("{\"sig\": ");
    write_py_str(out, sig);
    out.push_str(if ok {
        ", \"ok\": true"
    } else {
        ", \"ok\": false"
    });
}

/// One record per program-emitted log line, attributed to the open frame.
pub fn rows(tx: &Value, out: &mut String) {
    let sig = first_sig(tx);
    let ok = ok(tx);
    let mut stack: Vec<&str> = Vec::new();
    for msg in logs(tx) {
        if let Some((id, _)) = invoke(msg) {
            stack.push(id);
            continue;
        }
        if exit(msg).is_some() {
            stack.pop();
            continue;
        }
        if consumed(msg) {
            continue;
        }
        let mut program = stack.last().copied().unwrap_or("?");
        let (kind, text) = if msg == "Log truncated" {
            ("truncated", "")
        } else if let Some(t) = msg.strip_prefix(LOG) {
            ("log", t)
        } else if let Some(t) = msg.strip_prefix(DATA) {
            ("data", t)
        } else if let Some((id, t)) = returned(msg) {
            program = id;
            ("return", t)
        } else {
            ("unparsed", msg)
        };
        head(out, sig, ok);
        out.push_str(&format!(", \"depth\": {}, \"program\": ", stack.len()));
        write_py_str(out, program);
        out.push_str(", \"kind\": ");
        write_py_str(out, kind);
        out.push_str(", \"text\": ");
        write_py_str(out, text);
        out.push_str("}\n");
    }
}

/// The transaction's account keys in index order; encoding json appends the
/// lookup-table addresses, which jsonParsed already folds in.
fn keys<'v>(tx: &'v Value) -> Vec<&'v str> {
    let listed = tx
        .field("transaction")
        .and_then(|t| t.field("message"))
        .and_then(|m| m.field("accountKeys"))
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    let mut keys: Vec<&str> = listed
        .iter()
        .filter_map(|k| match k {
            Value::Obj(_) => k.get("pubkey").and_then(Value::as_str),
            _ => k.as_str(),
        })
        .collect();
    if let Some(loaded @ Value::Obj(entries)) =
        tx.field("meta").and_then(|m| m.field("loadedAddresses"))
    {
        if !entries.is_empty() && !listed.iter().any(Value::is_object) {
            for name in ["writable", "readonly"] {
                let more = loaded.field(name).and_then(Value::as_array).unwrap_or(&[]);
                keys.extend(more.iter().filter_map(Value::as_str));
            }
        }
    }
    keys
}

/// An index `0 <= i < len` from an integer literal.
fn in_range(lit: &str, len: usize) -> Option<usize> {
    let i: i128 = lit.parse().ok()?;
    (0..len as i128).contains(&i).then_some(i as usize)
}

/// Python's `depth == want` for an int `depth` and a JSON value `want`.
fn equals(depth: u32, want: &Value) -> bool {
    match want {
        Value::Bool(b) => u32::from(*b) == depth,
        Value::Num(n) if n.float => n.lit.parse::<f64>().is_ok_and(|f| f == f64::from(depth)),
        Value::Num(n) => n.lit.parse::<i128>().is_ok_and(|i| i == i128::from(depth)),
        _ => false,
    }
}

struct Ix<'v, 'a> {
    program: &'v str,
    inner: bool,
    stack_height: Option<&'v Value<'a>>,
}

fn ix_record<'v, 'a>(
    out: &mut String,
    ix: &'v Value<'a>,
    keys: &[&'v str],
    head_: (&str, bool),
    seq: usize,
    top: usize,
    inner: Option<usize>,
) -> Ix<'v, 'a> {
    let mut program = ix.field("programId").and_then(Value::as_str);
    if ix.field("programId").is_none() {
        if let Some(i) = ix
            .field("programIdIndex")
            .and_then(Value::as_int_lit)
            .and_then(|l| in_range(l, keys.len()))
        {
            program = Some(keys[i]);
        }
    }
    let program = match program {
        Some(p) if !p.is_empty() => p,
        _ => "?",
    };
    let stack_height = ix.field("stackHeight");
    let data = ix.get("data").and_then(Value::as_str);

    head(out, head_.0, head_.1);
    out.push_str(&format!(
        ", \"kind\": \"ix\", \"seq\": {seq}, \"top\": {top}, \"inner\": "
    ));
    match inner {
        Some(j) => out.push_str(&j.to_string()),
        None => out.push_str("null"),
    }
    out.push_str(", \"stack_height\": ");
    match stack_height {
        Some(v) => write_py(out, v),
        None => out.push_str("null"),
    }
    out.push_str(", \"program\": ");
    write_py_str(out, program);
    out.push_str(", \"data\": ");
    match data {
        Some(d) => {
            write_py_str(out, d);
            out.push_str(", \"data_status\": \"raw\"");
        }
        None => {
            out.push_str("null");
            match ix.get("parsed") {
                Some(parsed) => {
                    out.push_str(", \"data_status\": \"parsed-only\", \"program_name\": ");
                    match ix.field("program") {
                        Some(name) => write_py(out, name),
                        None => out.push_str("null"),
                    }
                    out.push_str(", \"parsed\": ");
                    write_py(out, parsed);
                }
                None => out.push_str(", \"data_status\": \"absent\""),
            }
        }
    }
    out.push_str(", \"accounts\": [");
    let accounts = ix
        .field("accounts")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    for (n, a) in accounts.iter().enumerate() {
        if n > 0 {
            out.push_str(", ");
        }
        match a.as_int_lit().and_then(|l| in_range(l, keys.len())) {
            Some(i) => write_py_str(out, keys[i]),
            None => write_py(out, a),
        }
    }
    out.push_str("]}\n");
    Ix {
        program,
        inner: inner.is_some(),
        stack_height,
    }
}

/// `ix` records from the instruction lists, then `invoke` records from the
/// runtime's invoke / success / failed lines, each joined to the `ix` it ran.
pub fn instruction_rows(tx: &Value, out: &mut String) {
    let sig = first_sig(tx);
    let ok = ok(tx);
    let keys = keys(tx);
    let mut inner_by_top: HashMap<usize, Vec<&Value>> = HashMap::new();
    let groups = tx
        .field("meta")
        .and_then(|m| m.field("innerInstructions"))
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    for group in groups {
        let index = group
            .get("index")
            .and_then(Value::as_int_lit)
            .and_then(|l| l.parse::<i128>().ok());
        if let Some(index) = index.and_then(|i| usize::try_from(i).ok()) {
            let list = group
                .field("instructions")
                .and_then(Value::as_array)
                .unwrap_or(&[]);
            inner_by_top.entry(index).or_default().extend(list.iter());
        }
    }
    let top_level = tx
        .field("transaction")
        .and_then(|t| t.field("message"))
        .and_then(|m| m.field("instructions"))
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    let mut ixs: Vec<Ix> = Vec::new();
    for (i, ix) in top_level.iter().enumerate() {
        let rec = ix_record(out, ix, &keys, (sig, ok), ixs.len(), i, None);
        ixs.push(rec);
        for (j, inner) in inner_by_top
            .get(&i)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .enumerate()
        {
            let rec = ix_record(out, inner, &keys, (sig, ok), ixs.len(), i, Some(j));
            ixs.push(rec);
        }
    }

    struct Invoke<'m> {
        program: &'m str,
        depth: u32,
        outcome: Option<&'m str>,
        ix_seq: Option<usize>,
    }
    let mut invokes: Vec<Invoke> = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    let mut ptr = 0;
    for msg in logs(tx) {
        if let Some((program, depth)) = invoke(msg) {
            let mut matched = None;
            while ptr < ixs.len() {
                let cand = &ixs[ptr];
                ptr += 1;
                let fits = if !cand.inner {
                    depth == 1
                } else {
                    match cand.stack_height {
                        None => depth >= 2,
                        Some(want) => equals(depth, want),
                    }
                };
                if cand.program == program && fits {
                    matched = Some(ptr - 1);
                    break;
                }
            }
            open.push(invokes.len());
            invokes.push(Invoke {
                program,
                depth,
                outcome: None,
                ix_seq: matched,
            });
            continue;
        }
        if let Some(outcome) = exit(msg) {
            if let Some(i) = open.pop() {
                invokes[i].outcome = Some(outcome);
            }
        }
    }
    for (seq, inv) in invokes.iter().enumerate() {
        head(out, sig, ok);
        out.push_str(&format!(
            ", \"kind\": \"invoke\", \"seq\": {seq}, \"program\": "
        ));
        write_py_str(out, inv.program);
        out.push_str(&format!(", \"depth\": {}, \"outcome\": ", inv.depth));
        match inv.outcome {
            Some(o) => write_py_str(out, o),
            None => out.push_str("null"),
        }
        out.push_str(", \"ix_seq\": ");
        match inv.ix_seq {
            Some(s) => out.push_str(&s.to_string()),
            None => out.push_str("null"),
        }
        out.push_str("}\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "Vote111111111111111111111111111111111111111";

    #[test]
    fn runtime_lines_match_whole() {
        assert_eq!(invoke(&format!("Program {ID} invoke [1]")), Some((ID, 1)));
        assert_eq!(invoke(&format!("Program {ID} invoke [007]")), Some((ID, 7)));
        assert_eq!(invoke(&format!("Program {ID} invoke [1]\n")), None);
        assert_eq!(invoke(&format!("Program {ID} invoke [1234567890]")), None);
        assert_eq!(invoke("Program log: x invoke [1]"), None);
        assert_eq!(
            invoke(&format!("Program {ID}x invoke [1]")),
            Some((&*format!("{ID}x"), 1))
        );
        assert_eq!(invoke(&format!("Program {}0 invoke [1]", &ID[..40])), None);
        assert_eq!(exit(&format!("Program {ID} success")), Some("success"));
        assert_eq!(
            exit(&format!("Program {ID} failed: custom program error: 0x1")),
            Some("failed: custom program error: 0x1")
        );
        assert_eq!(exit(&format!("Program {ID} failed: a\nb")), None);
        assert_eq!(
            exit(&format!("Program {ID} failed: a\rb")),
            Some("failed: a\rb")
        );
        assert!(consumed(&format!(
            "Program {ID} consumed 1 of 200000 compute units"
        )));
        assert!(!consumed(&format!(
            "Program {ID} consumed  of 2 compute units"
        )));
        assert_eq!(
            returned(&format!("Program return: {ID} AQID")),
            Some((ID, "AQID"))
        );
        assert_eq!(returned(&format!("Program return: {ID} ")), Some((ID, "")));
    }
}
