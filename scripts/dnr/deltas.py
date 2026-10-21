#!/usr/bin/env python3
"""deltas.py — compute balance movements from a getTransaction JSONL corpus, with
every total done in Python integers.

Input: one getTransaction result object per line (`jsonParsed` or `json`), on
stdin or in files named as args.

Two modes:
  deltas.py lamports [files...]   per (signature, account) non-zero lamport delta;
                                  the fee is added back for the fee payer (index 0),
                                  so the row reflects movement, not the fee.
  deltas.py tokens   [files...]   per (signature, owner, mint) raw-unit token delta.

Output: TSV. Signatures, owners and mints are base58 in real RPC data and deltas
are decimal integers; any tab, newline, carriage return or backslash in a string
field is escaped (`\\t`, `\\n`, `\\r`, `\\\\`), so a crafted corpus cannot forge a
row. Token deltas are net per (owner, mint), summed across every token account the
owner holds of that mint. Aggregate further in Python ints — never in jq or awk,
whose numbers are doubles.

Why Python ints, not jq: a u64 token amount or a lamport balance can exceed 2^53,
and jq numbers are IEEE doubles. Over the adversarial fixture
`token-amount-over-2-53.jsonl`, `jq` reports a delta of 2 for a true 1 and drops
a true 1 entirely. Python's `int` is arbitrary precision, and these amounts arrive
as JSON strings (`uiTokenAmount.amount`) or as JSON integers that Python parses
losslessly, so the arithmetic is exact.

Success-only: a failed transaction commits no instruction state (atomic revert —
`references/false-positives.md` FP-4), so a delta from a failed tx would be a
phantom. Both modes skip `meta.err != null`.

Account indexing note: in `jsonParsed`, `accountKeys` already includes
lookup-table-loaded addresses, so it lines up 1:1 with pre/postBalances. With
`encoding: json`, append `meta.loadedAddresses.writable` then `.readonly` to the
static keys before indexing; this script handles both.

No network. python3 stdlib only.
"""

from __future__ import annotations

import json
import sys
from collections import OrderedDict


def _account_keys(tx: dict) -> list[str]:
    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = []
    for k in msg.get("accountKeys") or []:
        keys.append(k["pubkey"] if isinstance(k, dict) else k)
    # encoding: json keeps loaded (ALT) addresses out of accountKeys; jsonParsed
    # already folds them in. Append only when they are not already present.
    loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
    if loaded and len(keys) < len(((tx.get("meta") or {}).get("preBalances")) or []):
        keys += list(loaded.get("writable") or [])
        keys += list(loaded.get("readonly") or [])
    return keys


def _ok(tx: dict) -> bool:
    return (tx.get("meta") or {}).get("err") is None


def _clean(s) -> str:
    """Escape the bytes that could break a TSV row. Real RPC data carries base58
    here, but a corpus can come from an untrusted export, so a key or mint holding a
    tab or newline must not be able to forge an extra row or column."""
    return (str(s).replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\n", "\\n").replace("\r", "\\r"))


def _lamports(txs, out):
    for tx in txs:
        if not _ok(tx):
            continue
        meta = tx.get("meta") or {}
        pre = meta.get("preBalances") or []
        post = meta.get("postBalances") or []
        fee = int(meta.get("fee") or 0)
        keys = _account_keys(tx)
        sig = ((tx.get("transaction") or {}).get("signatures") or ["?"])[0]
        for i in range(min(len(pre), len(post), len(keys))):
            d = int(post[i]) - int(pre[i]) + (fee if i == 0 else 0)
            if d != 0:
                out.write(f"{_clean(sig)}\t{_clean(keys[i])}\t{d}\n")


def _tokens(txs, out):
    for tx in txs:
        if not _ok(tx):
            continue
        meta = tx.get("meta") or {}
        sig = ((tx.get("transaction") or {}).get("signatures") or ["?"])[0]
        acc: "OrderedDict[tuple[str, str], list[int]]" = OrderedDict()

        def fold(entries, slot):
            for b in entries or []:
                owner = b.get("owner") or "?"
                mint = b.get("mint") or "?"
                amt = (b.get("uiTokenAmount") or {}).get("amount")
                # amount is a decimal STRING of the raw u64/u128; int() is exact.
                val = int(amt) if amt is not None else 0
                # SUM, never assign: one owner can hold several token accounts of
                # the same mint (a vault split across ATAs, a PDA with two
                # accounts). Assigning would keep only the last account's balance —
                # an internal move between them would read as a phantom drain, and a
                # two-account drain would be undercounted. Fixtures:
                # same-owner-move.jsonl (true net 0), same-owner-drain.jsonl (-140).
                acc.setdefault((owner, mint), [0, 0])[slot] += val

        fold(meta.get("preTokenBalances"), 0)
        fold(meta.get("postTokenBalances"), 1)
        for (owner, mint), (p, q) in acc.items():
            d = q - p
            if d != 0:
                out.write(f"{_clean(sig)}\t{_clean(owner)}\t{_clean(mint)}\t{d}\n")


def _iter_tx(argv):
    srcs = argv or ["-"]
    for path in srcs:
        fh = sys.stdin if path == "-" else open(path, encoding="utf-8", errors="replace")
        try:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    yield obj
        finally:
            if fh is not sys.stdin:
                fh.close()


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("lamports", "tokens"):
        print("usage: deltas.py lamports|tokens [files...]", file=sys.stderr)
        return 2
    mode, files = argv[0], argv[1:]
    txs = list(_iter_tx(files))
    if mode == "lamports":
        _lamports(txs, sys.stdout)
    else:
        _tokens(txs, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
