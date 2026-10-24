//! `audit-logs profile`: what `scripts/dnr/profile.sh` prints, from one pass.
//! Each section is the result of one of its jq queries piped through
//! `sort | uniq -c` (counts padded to 7 columns, as GNU uniq pads them), the
//! top-20 lists through `sort -rn`, whose ties fall in descending byte order of
//! the line, as `sort` orders them under `LC_ALL=C`.

use std::cmp::Ordering;
use std::collections::HashMap;

use crate::json::{write_jq, Value};
use crate::num::{cmp_int_literals, jq_number};

#[derive(Default)]
pub struct Profile {
    ok: u64,
    failed: u64,
    versions: HashMap<String, u64>,
    block_min: Option<String>,
    block_max: Option<String>,
    block_count: u64,
    payers: HashMap<String, u64>,
    signers: HashMap<String, u64>,
    programs: HashMap<String, u64>,
}

/// jq's `key`: an account key object's `pubkey`, or the key itself.
fn key<'v>(k: &'v Value) -> Option<&'v str> {
    match k {
        Value::Obj(_) => k.get("pubkey").and_then(Value::as_str),
        _ => k.as_str(),
    }
}

/// jq's `//`: null and false count as absent.
fn present<'v, 'a>(v: Option<&'v Value<'a>>) -> Option<&'v Value<'a>> {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => None,
        v => v,
    }
}

/// Orders blockTime literals as `sort -n` does: by value, then by text.
fn block_order(a: &str, b: &str) -> Ordering {
    cmp_int_literals(a, b).then_with(|| a.cmp(b))
}

/// jq's array index: negative counts from the end; out of range is null.
fn index(len: usize, lit: &str) -> Option<usize> {
    let i: i128 = lit.parse().ok()?;
    let i = if i < 0 { i + len as i128 } else { i };
    (0..len as i128).contains(&i).then_some(i as usize)
}

/// jq's `.[0:n]` end: negative counts from the end, clamped to the array.
fn slice_end(len: usize, lit: &str) -> usize {
    let negative = lit.starts_with('-');
    match lit.parse::<i128>() {
        Ok(n) if n < 0 => (n + len as i128).max(0) as usize,
        Ok(n) => n.min(len as i128) as usize,
        Err(_) if negative => 0,
        Err(_) => len,
    }
}

fn bump(map: &mut HashMap<String, u64>, k: &str) {
    match map.get_mut(k) {
        Some(n) => *n += 1,
        None => {
            map.insert(k.to_string(), 1);
        }
    }
}

impl Profile {
    pub fn add(&mut self, tx: &Value) {
        let meta = tx.get("meta");
        match meta.and_then(|m| m.get("err")) {
            None | Some(Value::Null) => self.ok += 1,
            Some(_) => self.failed += 1,
        }

        let version = match present(tx.get("version")) {
            None => "legacy".to_string(),
            Some(Value::Str(s)) => s.to_string(),
            Some(v) => {
                let mut s = String::new();
                write_jq(&mut s, v);
                s
            }
        };
        bump(&mut self.versions, &version);

        if let Some(lit) = tx.get("blockTime").and_then(Value::as_int_lit) {
            let text = jq_number(lit);
            if self
                .block_min
                .as_deref()
                .is_none_or(|m| block_order(&text, m) == Ordering::Less)
            {
                self.block_min = Some(text.clone());
            }
            if self
                .block_max
                .as_deref()
                .is_none_or(|m| block_order(&text, m) != Ordering::Less)
            {
                self.block_max = Some(text);
            }
            self.block_count += 1;
        }

        let m = tx.get("transaction").and_then(|t| t.get("message"));
        let keys = present(m.and_then(|m| m.get("accountKeys")))
            .and_then(Value::as_array)
            .unwrap_or(&[]);
        if let Some(payer) = present(keys.first()).and_then(key) {
            bump(&mut self.payers, payer);
        }

        if keys.first().is_some_and(Value::is_object) {
            for k in keys {
                if let Some(Value::Bool(true)) = present(k.get("signer")) {
                    if let Some(pk) = k.get("pubkey").and_then(Value::as_str) {
                        bump(&mut self.signers, pk);
                    }
                }
            }
        } else {
            let n = match present(
                m.and_then(|m| m.get("header"))
                    .and_then(|h| h.get("numRequiredSignatures")),
            ) {
                Some(v) => v
                    .as_int_lit()
                    .map_or(1.min(keys.len()), |lit| slice_end(keys.len(), lit)),
                None => 1.min(keys.len()),
            };
            for k in &keys[..n] {
                if let Some(pk) = key(k) {
                    bump(&mut self.signers, pk);
                }
            }
        }

        let resolved: Vec<Option<&str>> = keys.iter().map(key).collect();
        let ixs = m
            .and_then(|m| m.get("instructions"))
            .and_then(Value::as_array)
            .unwrap_or(&[]);
        for ix in ixs {
            let program = match present(ix.get("programId")) {
                Some(p) => p.as_str(),
                None => match ix.get("programIdIndex").and_then(Value::as_int_lit) {
                    Some(lit) => index(resolved.len(), lit).and_then(|i| resolved[i]),
                    None => None,
                },
            };
            if let Some(p) = program {
                bump(&mut self.programs, p);
            }
        }
    }

    /// The report, from its header line to the closing "-- skipped" lines.
    pub fn report(&self, header: &str, notes: &[String]) -> String {
        let mut out = String::new();
        out.push_str(header);
        out.push('\n');
        out.push_str("-- transactions / outcome\n");
        if self.failed > 0 {
            out.push_str(&format!("{:>7} failed\n", self.failed));
        }
        if self.ok > 0 {
            out.push_str(&format!("{:>7} ok\n", self.ok));
        }
        out.push_str("-- version\n");
        let mut versions: Vec<_> = self.versions.iter().collect();
        versions.sort_by(|a, b| a.0.cmp(b.0));
        for (v, n) in versions {
            out.push_str(&format!("{n:>7} {v}\n"));
        }
        out.push_str("-- time window (blockTime)\n");
        match (&self.block_min, &self.block_max) {
            (Some(first), Some(last)) => out.push_str(&format!(
                "   first={first}  last={last}  spanning={} entries with a blockTime\n",
                self.block_count
            )),
            _ => out.push_str("   (no blockTime on these entries)\n"),
        }
        out.push_str("-- fee payers (accountKeys[0], top 20)\n");
        top20(&mut out, &self.payers);
        out.push_str("-- signers (top 20)\n");
        top20(&mut out, &self.signers);
        out.push_str(
            "-- top-level programs invoked (instructions[].programId / programIdIndex, top 20)\n",
        );
        top20(&mut out, &self.programs);
        for note in notes {
            out.push_str("-- skipped: ");
            out.push_str(note);
            out.push('\n');
        }
        out
    }
}

fn top20(out: &mut String, counts: &HashMap<String, u64>) {
    let mut rows: Vec<_> = counts.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then_with(|| b.0.cmp(a.0)));
    for (k, n) in rows.into_iter().take(20) {
        out.push_str(&format!("{n:>7} {k}\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jq_indexing() {
        assert_eq!(index(3, "-1"), Some(2));
        assert_eq!(index(3, "3"), None);
        assert_eq!(index(3, "-4"), None);
        assert_eq!(index(3, &"9".repeat(50)), None);
        assert_eq!(slice_end(3, "-1"), 2);
        assert_eq!(slice_end(3, "-9"), 0);
        assert_eq!(slice_end(3, "0"), 0);
        assert_eq!(slice_end(3, &"9".repeat(50)), 3);
        assert_eq!(slice_end(3, &format!("-{}", "9".repeat(50))), 0);
    }
}
