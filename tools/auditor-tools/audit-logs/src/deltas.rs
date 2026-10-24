//! `audit-logs deltas lamports|tokens [--by ...]`: the TSV rows, or the sums,
//! `scripts/dnr/deltas.py` prints, every total an exact integer, successful
//! transactions only.

use std::collections::HashMap;

use crate::contract::{escape_char, unsafe_char};
use crate::json::Value;
use crate::num::{cmp_int_literals, Int};

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

fn cleaned(s: &str) -> String {
    let mut out = String::new();
    clean(&mut out, s);
    out
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

/// One movement: the signature, the token owner and mint (empty for lamports), the
/// account as a row names it, whether that is an account key rather than
/// `#<index>` or `#?`, and the delta.
pub struct Row {
    sig: String,
    owner: String,
    mint: String,
    account: String,
    keyed: bool,
    delta: Int,
}

/// Per (signature, account): the non-zero lamport delta, with the fee added back
/// for the fee payer. A balance whose index has no account key is printed as
/// `#<index>`; returns how many rows name one.
pub fn lamports(tx: &Value, out: &mut String) -> u64 {
    let mut rows = Vec::new();
    let keyless = lamport_rows(tx, &mut rows);
    for r in &rows {
        clean(out, &r.sig);
        out.push('\t');
        clean(out, &r.account);
        out.push_str(&format!("\t{}\n", r.delta));
    }
    keyless
}

/// The movements `lamports` prints, added to `rows`; returns how many name a
/// balance index that has no account key.
pub fn lamport_rows(tx: &Value, rows: &mut Vec<Row>) -> u64 {
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
            let (account, keyed) = match keys.get(i) {
                Some(k) => (k.to_string(), true),
                None => {
                    keyless += 1;
                    (format!("#{i}"), false)
                }
            };
            rows.push(Row {
                sig: sig.to_string(),
                owner: String::new(),
                mint: String::new(),
                account,
                keyed,
                delta: d,
            });
        }
    }
    keyless
}

/// What a token balance is summed under, with its mint: its account key; an index
/// that has no account key; or, with no accountIndex, the balance itself (its side
/// and place), which nothing pairs with its other side.
#[derive(Clone, PartialEq, Eq, Hash)]
enum Bucket {
    Key(String),
    Index(String),
    Entry(usize, usize),
}

/// Per (signature, token account, mint): the non-zero raw-unit delta, with the
/// owner as a label. A balance whose index has no account key is printed as
/// `#<index>`, and one with no accountIndex as `#?`, a row of its own; neither is
/// ever merged with another account. Returns how many rows name each.
pub fn tokens(tx: &Value, out: &mut String) -> (u64, u64) {
    let mut rows = Vec::new();
    let counts = token_rows(tx, &mut rows);
    for r in &rows {
        clean(out, &r.sig);
        out.push('\t');
        clean(out, &r.owner);
        out.push('\t');
        clean(out, &r.mint);
        out.push_str(&format!("\t{}\t", r.delta));
        clean(out, &r.account);
        out.push('\n');
    }
    counts
}

/// The movements `tokens` prints, added to `rows`; returns how many name each kind
/// of placeholder account.
pub fn token_rows(tx: &Value, rows: &mut Vec<Row>) -> (u64, u64) {
    if !ok(tx) {
        return (0, 0);
    }
    let meta = tx.field("meta");
    let sig = sig(tx);
    let keys = account_keys(tx);
    let mut order: Vec<(Bucket, String)> = Vec::new();
    let mut acc: HashMap<(Bucket, String), [Int; 2]> = HashMap::new();
    let mut labels: HashMap<(Bucket, String), (String, String)> = HashMap::new();
    for (slot, name) in [(0, "preTokenBalances"), (1, "postTokenBalances")] {
        for (n, b) in list(meta.and_then(|m| m.field(name))).iter().enumerate() {
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
            // The input contract makes accountIndex null or an integer from 0.
            let (bucket, account) = match b.field("accountIndex").and_then(Value::as_int_lit) {
                Some(lit) => match lit.parse::<usize>().ok().and_then(|i| keys.get(i)) {
                    Some(k) => (Bucket::Key(k.to_string()), k.to_string()),
                    None => (Bucket::Index(lit.to_string()), format!("#{lit}")),
                },
                None => (Bucket::Entry(slot, n), "#?".to_string()),
            };
            let key = (bucket, mint.to_string());
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
                labels.insert(key, (owner.to_string(), account));
            }
        }
    }
    let (mut keyless, mut indexless) = (0, 0);
    for key in &order {
        let (Some([p, q]), Some((owner, account))) = (acc.get(key), labels.get(key)) else {
            continue;
        };
        let d = q.sub(p);
        if !d.is_zero() {
            match key.0 {
                Bucket::Index(_) => keyless += 1,
                Bucket::Entry(..) => indexless += 1,
                Bucket::Key(_) => {}
            }
            rows.push(Row {
                sig: sig.to_string(),
                owner: owner.clone(),
                mint: key.1.clone(),
                account: account.clone(),
                keyed: matches!(key.0, Bucket::Key(_)),
                delta: d,
            });
        }
    }
    (keyless, indexless)
}

/// What `--by` sums the rows by: `lamports --by account`, `tokens --by owner,mint`,
/// `tokens --by mint`.
#[derive(Clone, Copy, PartialEq)]
pub enum By {
    Account,
    OwnerMint,
    Mint,
}

/// Per mint, over the owners' nets: the sum of the negative ones and how many,
/// then the sum of the positive ones and how many.
struct MintSums {
    loss: Int,
    losers: u64,
    gain: Int,
    gainers: u64,
}

/// The nets `--by` prints, keyed by names as `clean` writes them: (account) for
/// lamports, (owner, mint) for tokens, with the token account as well for a balance
/// the RPC gave no owner (`?`), which is summed per token account.
#[derive(Default)]
pub struct Sums {
    nets: HashMap<(String, String, String), Int>,
    /// Rows no sum holds: a lamport row named `#<index>`, or a token row named
    /// `#<index>` or `#?` that also has no owner, whose account stands for one only
    /// within its own transaction.
    pub left_out: u64,
}

impl Sums {
    pub fn add(&mut self, by: By, rows: &[Row]) {
        for r in rows {
            let key = match by {
                By::Account => r
                    .keyed
                    .then(|| (cleaned(&r.account), String::new(), String::new())),
                _ if r.owner != "?" => Some((cleaned(&r.owner), cleaned(&r.mint), String::new())),
                _ => r
                    .keyed
                    .then(|| ("?".to_string(), cleaned(&r.mint), cleaned(&r.account))),
            };
            match key {
                Some(k) => {
                    let net = self.nets.entry(k).or_insert_with(Int::zero);
                    *net = net.add(&r.delta);
                }
                None => self.left_out += 1,
            }
        }
    }

    /// One TSV row per sum, as deltas.py writes them: the most negative first, then
    /// by name in byte order; a sum of 0 prints no row.
    pub fn write(&self, by: By, out: &mut String) {
        if by == By::Mint {
            let mut mints: HashMap<&str, MintSums> = HashMap::new();
            for ((_, mint, _), net) in &self.nets {
                let m = mints.entry(mint.as_str()).or_insert_with(|| MintSums {
                    loss: Int::zero(),
                    losers: 0,
                    gain: Int::zero(),
                    gainers: 0,
                });
                if net.to_string().starts_with('-') {
                    m.loss = m.loss.add(net);
                    m.losers += 1;
                } else if !net.is_zero() {
                    m.gain = m.gain.add(net);
                    m.gainers += 1;
                }
            }
            let mut list: Vec<(String, &str, &MintSums)> = mints
                .iter()
                .filter(|(_, m)| m.losers > 0 || m.gainers > 0)
                .map(|(mint, m)| (m.loss.to_string(), *mint, m))
                .collect();
            list.sort_by(|a, b| cmp_int_literals(&a.0, &b.0).then_with(|| a.1.cmp(b.1)));
            for (loss, mint, m) in list {
                out.push_str(&format!(
                    "{mint}\t{loss}\t{}\t{}\t{}\n",
                    m.losers, m.gain, m.gainers
                ));
            }
            return;
        }
        let mut list: Vec<(String, &(String, String, String))> = self
            .nets
            .iter()
            .filter(|(_, net)| !net.is_zero())
            .map(|(key, net)| (net.to_string(), key))
            .collect();
        list.sort_by(|a, b| cmp_int_literals(&a.0, &b.0).then_with(|| a.1.cmp(b.1)));
        for (net, (name, mint, account)) in list {
            if by == By::Account {
                out.push_str(&format!("{name}\t{net}\n"));
            } else {
                out.push_str(&format!("{name}\t{mint}\t{net}\t{account}\n"));
            }
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
