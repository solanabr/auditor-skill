#!/usr/bin/env python3
"""frames.py — attribute each program-emitted log line to the program frame that
emitted it, reading a getTransaction JSONL corpus.

Input: one getTransaction result object per line (the `result` field of an RPC
response, encoding `jsonParsed` or `json`), on stdin or in files named as args.
Output: JSONL, one record per emitted log line:

    {"sig": "...", "ok": true, "depth": 2, "program": "<id|?>",
     "kind": "log|data|return|truncated|unparsed", "text": "..."}

Design rules, each forced by a real failure mode:

  * Walk `logMessages` one element at a time. Never flatten the array into one
    string and grep it: a `\\n` inside a `Program log:` payload would then forge
    frame lines (adversarial fixture `log-newline-injection.jsonl` turns 2 logs
    into 4 apparent frames under `jq -r '.[]' | grep`). JSON arrays keep each log
    a single element no matter what bytes it contains, so the newline never
    splits a record here.
  * Match invoke / success / failure lines ANCHORED at start-of-string with the
    base58 program-id shape. A program can emit `Program log: ... invoke [1]`
    (Anchor's own client carries a regression test for exactly that string); an
    unanchored contains-match would pop the frame stack on it.
  * A `Program log:` / `Program data:` line is PROGRAM-ASSERTED. It attributes an
    utterance to a frame; it is never proof that a state change happened (KV-122).
    Downstream verdict logic must treat `kind in {log,data,return}` as a hint.
  * Output is JSONL with the raw text in a JSON string, so tabs/newlines inside a
    payload are escaped by the encoder and can never break a column.

No network. bash/python3 only. stdlib only.
"""

from __future__ import annotations

import json
import re
import sys

# base58 (Bitcoin alphabet) pubkey, 32..44 chars — the shape of a program id.
_B58 = r"[1-9A-HJ-NP-Za-km-z]{32,44}"
_INVOKE = re.compile(rf"^Program ({_B58}) invoke \[(\d+)\]$")
_EXIT = re.compile(rf"^Program ({_B58}) (success|failed: .*)$")
_LOG = "Program log: "
_DATA = "Program data: "
_RETURN = re.compile(rf"^Program return: ({_B58}) (.*)$")
_CONSUMED = re.compile(rf"^Program ({_B58}) consumed \d+ of \d+ compute units$")


def _rows(tx: dict):
    meta = tx.get("meta") or {}
    txn = tx.get("transaction") or {}
    sigs = txn.get("signatures") or []
    sig = sigs[0] if sigs else "?"
    ok = meta.get("err") is None
    stack: list[str] = []
    for msg in meta.get("logMessages") or []:
        if not isinstance(msg, str):
            continue
        m = _INVOKE.match(msg)
        if m:
            stack.append(m.group(1))
            continue
        if _EXIT.match(msg):
            if stack:
                stack.pop()
            continue
        if _CONSUMED.match(msg):
            continue
        depth = len(stack)
        prog = stack[-1] if stack else "?"
        if msg == "Log truncated":
            yield {"sig": sig, "ok": ok, "depth": depth, "program": prog,
                   "kind": "truncated", "text": ""}
        elif msg.startswith(_LOG):
            yield {"sig": sig, "ok": ok, "depth": depth, "program": prog,
                   "kind": "log", "text": msg[len(_LOG):]}
        elif msg.startswith(_DATA):
            yield {"sig": sig, "ok": ok, "depth": depth, "program": prog,
                   "kind": "data", "text": msg[len(_DATA):]}
        elif (r := _RETURN.match(msg)):
            yield {"sig": sig, "ok": ok, "depth": depth, "program": r.group(1),
                   "kind": "return", "text": r.group(2)}
        else:
            # A runtime diagnostic with no program prefix (e.g. a bare
            # "<pubkey> signer_key().is_none()" before a failure). Keep it,
            # attributed to the open frame, flagged so it is never mistaken for
            # a program-asserted log.
            yield {"sig": sig, "ok": ok, "depth": depth, "program": prog,
                   "kind": "unparsed", "text": msg}


def _iter_lines(argv: list[str]):
    if argv:
        for path in argv:
            with open(path, encoding="utf-8", errors="replace") as fh:
                yield from fh
    else:
        yield from sys.stdin


def main(argv: list[str]) -> int:
    out = sys.stdout
    for line in _iter_lines(argv):
        line = line.strip()
        if not line:
            continue
        try:
            tx = json.loads(line)
        except json.JSONDecodeError:
            print(json.dumps({"kind": "parse_error", "text": line[:200]}), file=out)
            continue
        if not isinstance(tx, dict):
            continue
        for row in _rows(tx):
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
