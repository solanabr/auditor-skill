//! `audit-logs deltas lamports|tokens`: the TSV rows `scripts/dnr/deltas.py`
//! prints, every total an exact integer, successful transactions only.

use std::collections::HashMap;

use crate::contract::{escape_char, unsafe_char};
use crate::json::Value;
use crate::num::Int;

/// Escapes what could break a TSV row, or hide in one: backslash, tab, LF and CR
/// as `\\`, `\t`, `\n`, `\r`, and every other unsafe character as Python's
/// `unicode_escape` writes it (`\x1b`, `\u2028`).
fn clean(out: &mut String, s: &str) {
    for c in s.chars() {
        if c == '\\' || unsafe_char(c) {
            escape_char(out, c as u32);
        } else {
            out.push(c);
        }
    }
}

fn ok(tx: &Value) -> bool {
    tx.field("meta").and_then(|m| m.field("err")).is_none()
}

fn sig<'v>(tx: &'v Value) -> &'v str {
    let sigs = tx
        .field("transaction")
        .and_then(|t| t.field("signatures"))
        .and_then(Value::as_array);
    match sigs {
        Some([first, ..]) => first.as_str().unwrap_or("?"),
        _ => "?",
    }
}

fn list<'v, 'a>(v: Option<&'v Value<'a>>) -> &'v [Value<'a>] {
    v.and_then(Value::as_array).unwrap_or(&[])
}

/// The account keys in balance order: encoding json appends the lookup-table
/// addresses when the static keys are fewer than the balances.
fn account_keys<'v>(tx: &'v Value) -> Vec<&'v str> {
    let meta = tx.field("meta");
    let listed = list(
        tx.field("transaction")
            .and_then(|t| t.field("message"))
            .and_then(|m| m.field("accountKeys")),
    );
    let mut keys: Vec<&str> = listed
        .iter()
        .filter_map(|k| match k {
            Value::Obj(_) => k.get("pubkey").and_then(Value::as_str),
            _ => k.as_str(),
        })
        .collect();
    if let Some(loaded @ Value::Obj(entries)) = meta.and_then(|m| m.field("loadedAddresses")) {
        if !entries.is_empty() && keys.len() < list(meta.and_then(|m| m.field("preBalances"))).len()
        {
            for name in ["writable", "readonly"] {
                keys.extend(list(loaded.field(name)).iter().filter_map(Value::as_str));
            }
        }
    }
    keys
}

fn int(v: &Value) -> Int {
    v.as_int_lit()
        .and_then(Int::parse)
        .unwrap_or_else(Int::zero)
}

/// Per (signature, account): the non-zero lamport delta, with the fee added back
/// for the fee payer. A balance whose index has no account key is printed as
/// `#<index>`; returns how many rows name one.
pub fn lamports(tx: &Value, out: &mut String) -> u64 {
    if !ok(tx) {
        return 0;
    }
    let meta = tx.field("meta");
    let pre = list(meta.and_then(|m| m.field("preBalances")));
    let post = list(meta.and_then(|m| m.field("postBalances")));
    let fee = meta
        .and_then(|m| m.field("fee"))
        .map(int)
        .unwrap_or_else(Int::zero);
    let keys = account_keys(tx);
    let sig = sig(tx);
    // pre and post are the same length (the input contract).
    let mut keyless = 0;
    for (i, (p, q)) in pre.iter().zip(post).enumerate() {
        let mut d = int(q).sub(&int(p));
        if i == 0 {
            d = d.add(&fee);
        }
        if !d.is_zero() {
            clean(out, sig);
            out.push('\t');
            match keys.get(i) {
                Some(k) => clean(out, k),
                None => {
                    out.push_str(&format!("#{i}"));
                    keyless += 1;
                }
            }
            out.push_str(&format!("\t{d}\n"));
        }
    }
    keyless
}

/// Per (signature, token account, mint): the non-zero raw-unit delta, with the
/// owner as a label. Without a usable accountIndex the owner is the bucket.
pub fn tokens(tx: &Value, out: &mut String) {
    if !ok(tx) {
        return;
    }
    let meta = tx.field("meta");
    let sig = sig(tx);
    let keys = account_keys(tx);
    let mut order: Vec<(String, String)> = Vec::new();
    let mut acc: HashMap<(String, String), [Int; 2]> = HashMap::new();
    let mut labels: HashMap<(String, String), (String, String)> = HashMap::new();
    for (slot, name) in [(0, "preTokenBalances"), (1, "postTokenBalances")] {
        for b in list(meta.and_then(|m| m.field(name))) {
            let owner = match b.field("owner").and_then(Value::as_str) {
                Some(o) if !o.is_empty() => o,
                _ => "?",
            };
            let mint = match b.field("mint").and_then(Value::as_str) {
                Some(m) if !m.is_empty() => m,
                _ => "?",
            };
            let val = b
                .field("uiTokenAmount")
                .and_then(|u| u.field("amount"))
                .and_then(Value::as_str)
                .and_then(Int::parse)
                .unwrap_or_else(Int::zero);
            let account = b
                .field("accountIndex")
                .and_then(Value::as_int_lit)
                .and_then(|l| l.parse::<i128>().ok())
                .and_then(|i| usize::try_from(i).ok())
                .and_then(|i| keys.get(i).copied());
            let key = (
                account.map_or_else(|| format!("owner:{owner}"), str::to_string),
                mint.to_string(),
            );
            let sums = match acc.get_mut(&key) {
                Some(sums) => sums,
                None => {
                    order.push(key.clone());
                    acc.entry(key.clone()).or_insert([Int::zero(), Int::zero()])
                }
            };
            sums[slot] = sums[slot].add(&val);
            let has_owner = b
                .field("owner")
                .and_then(Value::as_str)
                .is_some_and(|o| !o.is_empty());
            if !labels.contains_key(&key) || has_owner {
                let account = match account {
                    Some(a) if !a.is_empty() => a,
                    _ => "?",
                };
                labels.insert(key, (owner.to_string(), account.to_string()));
            }
        }
    }
    for key in &order {
        let (Some([p, q]), Some((owner, account))) = (acc.get(key), labels.get(key)) else {
            continue;
        };
        let d = q.sub(p);
        if !d.is_zero() {
            clean(out, sig);
            out.push('\t');
            clean(out, owner);
            out.push('\t');
            clean(out, &key.1);
            out.push_str(&format!("\t{d}\t"));
            clean(out, account);
            out.push('\n');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsv_fields_are_escaped() {
        let mut s = String::new();
        clean(
            &mut s,
            "a\\b\tc\nd\re\u{1b}f\u{7f}g\u{85}h\u{2028}i\u{feff}j\u{a0}k\u{e9}l\u{ad}m\u{2060}n\u{e0041}o",
        );
        assert_eq!(
            s,
            "a\\\\b\\tc\\nd\\re\\x1bf\\x7fg\\x85h\\u2028i\\ufeffj\u{a0}k\u{e9}l\\xadm\\u2060n\\U000e0041o"
        );
    }
}
