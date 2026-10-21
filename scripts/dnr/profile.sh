#!/usr/bin/env bash
# profile.sh — baseline a getTransaction JSONL corpus WITHOUT reading it into a
# context window. Prints a handful of small aggregates: the numbers you quote in
# the ledger, each the output of one query over the corpus.
#
#   profile.sh <corpus.jsonl>
#
# What it reports (all from structural fields, never from log text):
#   - transaction count and the finalized/failed split (meta.err)
#   - version histogram (legacy / 0 / 1)
#   - time window (min/max blockTime, when present)
#   - fee-payer inventory: accountKeys[0].pubkey, top 20 by count
#   - signer inventory: every accountKeys[].signer == true, top 20 by count
#   - top-level program inventory: transaction.message.instructions[].programId,
#     top 20 by count  (the ACTUAL invoked programs, read from the instruction
#     list — NOT parsed out of logMessages, where a program-emitted line can
#     forge an "invoke" entry; see frames.py for log attribution)
#
# It deliberately does NOT touch logMessages or balances: those go through
# frames.py and deltas.py, which handle the newline-forgery and >2^53 hazards.
#
# Uses jq per line. jq is fine for counting scalars and grouping base58 strings;
# it is only unsafe for u64 ARITHMETIC (see deltas.py) and for flattening the log
# array (see frames.py). bash >= 3.2, jq, no network.

set -euo pipefail

corpus="${1:-}"
if [[ -z "$corpus" || ! -f "$corpus" ]]; then
  echo "usage: profile.sh <corpus.jsonl>" >&2
  exit 2
fi

echo "== corpus: $corpus"
echo "-- transactions / outcome"
jq -r 'if (.meta.err == null) then "ok" else "failed" end' "$corpus" | sort | uniq -c
echo "-- version"
jq -r '(.version // "legacy") | tostring' "$corpus" | sort | uniq -c
echo "-- time window (blockTime)"
jq -r '.blockTime // empty' "$corpus" | sort -n | awk '
  NR==1 {min=$0} {max=$0} END {
    if (NR) printf "   first=%s  last=%s  spanning=%d entries with a blockTime\n", min, max, NR
    else    print "   (no blockTime on these entries)"
  }'
echo "-- fee payers (accountKeys[0], top 20)"
jq -r '(.transaction.message.accountKeys[0].pubkey // .transaction.message.accountKeys[0]) // empty' "$corpus" \
  | sort | uniq -c | sort -rn | head -20
echo "-- signers (top 20)"
jq -r '.transaction.message.accountKeys[]? | select((.signer // false) == true) | (.pubkey // .)' "$corpus" \
  | sort | uniq -c | sort -rn | head -20
echo "-- top-level programs invoked (instructions[].programId, top 20)"
jq -r '.transaction.message.instructions[]?.programId // empty' "$corpus" \
  | sort | uniq -c | sort -rn | head -20
