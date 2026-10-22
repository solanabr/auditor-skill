#!/usr/bin/env bash
# test-dnr-collect.sh — self-test for the two networked D&R steps, collect.sh and
# snapshot-program.sh, against stand-ins for curl, jq and the solana CLI.
#
# Runnable from the repo root with bash >= 3.2, using only jq / python3 / awk / sed.
# No network. CI (corpus-check.yml) runs every scripts/tests/*.sh. test-dnr.sh
# covers the offline recipes and the gating, redaction and run-directory checks;
# this suite covers what the two scripts collect and keep.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DNR="$HERE/../dnr"
FIX="$DNR/fixtures"
fails=0
ok()   { printf 'ok   %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1" >&2; fails=$((fails+1)); }
eq()   { if [[ "$2" == "$3" ]]; then ok "$1 ($2)"; else bad "$1: expected '$3', got '$2'"; fi; }

for tool in jq python3 awk sed; do
  command -v "$tool" >/dev/null 2>&1 || { echo "test-dnr-collect: missing required tool: $tool" >&2; exit 3; }
done
TT="$(mktemp -d "${TMPDIR:-/tmp}/dnr_collect_test.XXXXXX")" || exit 3
trap 'rm -rf "$TT"' EXIT
# The stand-ins run on the real interpreter by absolute path, so python3 can be
# left off PATH for the scripts under test.
PY="$(python3 -I -c 'import sys; print(sys.executable)')"
A_ADDR="AddrA111111111111111111111111111111111111111"
export RPC_URL="https://rpc.example.test/"

# ---------------------------------------------------------------------------
# Stand-in RPC behind a fake curl. $FAKE_BOOK is a JSON file:
#   {"sigs": {<address>: [<getSignaturesForAddress entries, newest first>]},
#    "tx":   {<signature>: <transaction JSON text, spliced verbatim>}}
# Pages honour "limit" and "before". A transaction not in "tx" is a small one
# made from its signature entry. FAKE_TX_FAIL=<mode>[:<k>] fails every k-th
# getTransaction call (every call when k is left out): transport (curl exit 28),
# rpc429 (JSON-RPC error 429) or null (result null). Every request is appended
# to $FAKE_CURL_LOG.
# ---------------------------------------------------------------------------
mkdir -p "$TT/bin"
printf '#!/bin/sh\nexec "%s" -I "$0.py" "$@"\n' "$PY" > "$TT/bin/curl"
cat > "$TT/bin/curl.py" <<'PY'
import json, os, re, sys
args = sys.argv[1:]
url = ""
if args[args.index("-K") + 1] == "-":
    for line in sys.stdin:
        m = re.match(r'\s*url\s*=\s*"(.*)"\s*$', line)
        url = m.group(1) if m else url
if not url:
    sys.stderr.write("curl: no URL specified\n"); sys.exit(2)
req = json.loads(args[args.index("--data-raw") + 1])
m, p = req["method"], req["params"]
log = os.environ["FAKE_CURL_LOG"]
with open(log, "a") as f:
    f.write(json.dumps({"method": m, "params": p}) + "\n")
book = json.load(open(os.environ["FAKE_BOOK"]))
def reply(member):
    sys.stdout.write('{"jsonrpc":"2.0","id":1,' + member + '}'); sys.exit(0)
if m == "getSignaturesForAddress":
    entries = book["sigs"].get(p[0], [])
    names = [e["signature"] for e in entries]
    start = names.index(p[1]["before"]) + 1 if p[1].get("before") in names else 0
    reply('"result":' + json.dumps(entries[start:start + p[1]["limit"]]))
if m == "getTransaction":
    calls = sum(1 for line in open(log) if '"getTransaction"' in line)
    mode, _, every = os.environ.get("FAKE_TX_FAIL", "").partition(":")
    if mode and calls % int(every or 1) == 0:
        if mode == "transport":
            sys.stderr.write("curl: (28) Operation timed out after 60000 milliseconds with 0 bytes received\n"); sys.exit(28)
        if mode == "rpc429":
            reply('"error":{"code":429,"message":"Too many requests for a specific RPC call"}')
        reply('"result":null')
    raw = book.get("tx", {}).get(p[0])
    if raw is None:
        slot = next(e["slot"] for es in book["sigs"].values() for e in es if e["signature"] == p[0])
        raw = json.dumps({"slot": slot, "meta": {"err": None}, "transaction": {"signatures": [p[0]]}})
    reply('"result":' + raw)
reply('"error":{"code":-32601,"message":"Method not found"}')
PY
chmod +x "$TT/bin/curl"
export FAKE_CURL_LOG="$TT/curl.log" FAKE_BOOK="$TT/book.json"
# book <python expression for the "sigs" map> [<"tx" map>]: write $FAKE_BOOK.
book() {
  "$PY" -I -c 'import json, sys
print(json.dumps({"sigs": eval(sys.argv[1]), "tx": eval(sys.argv[2] or "{}")}))' "$1" "${2:-}" > "$FAKE_BOOK"
}
# collect <out dir> <args...>: run collect.sh against the stand-in, output in <out>.out.
collect() {
  local out="$1"; shift
  ( PATH="$TT/bin:$PATH" bash "$DNR/collect.sh" --out "$out" --confirmed "$@" ) > "$out.out" 2>&1
}
calls() { grep -c "\"$1\"" "$FAKE_CURL_LOG" 2>/dev/null || true; }
sigs_of() { jq -r '.transaction.signatures[0]' "$1" 2>/dev/null | tr '\n' ' '; }

# ---------------------------------------------------------------------------
# 1. Fetch order is the same in every locale: newest slot first and, within a
#    slot, the RPC's own order, so --max-tx keeps the same transactions whatever
#    the caller's collation.
# ---------------------------------------------------------------------------
book '{"'"$A_ADDR"'": [
  {"signature": "SigTop", "slot": 60, "err": None, "blockTime": 1700000600},
  {"signature": "SigBeta", "slot": 50, "err": None, "blockTime": 1700000500},
  {"signature": "sigalpha", "slot": 50, "err": None, "blockTime": 1700000500},
  {"signature": "SigAlpha", "slot": 50, "err": None, "blockTime": 1700000500},
  {"signature": "Sig_x", "slot": 50, "err": None, "blockTime": 1700000500},
  {"signature": "SigLow", "slot": 40, "err": None, "blockTime": 1700000400}]}'
LC_ALL=C collect "$TT/loc-c" --max-tx 3 -- "$A_ADDR"
eq "order: --max-tx 3 keeps the newest slot, then the RPC's order within slot 50 (LC_ALL=C)" \
  "$(sigs_of "$TT/loc-c/transactions.jsonl")|$(cut -f1 "$TT/loc-c/collection-gaps.tsv")" "SigTop SigBeta sigalpha |SigAlpha"
utf8="$(locale -a 2>/dev/null | grep -i -m1 -E '^en_US\.utf-?8$' || true)"
if [[ -n "$utf8" ]]; then
  LC_ALL="$utf8" collect "$TT/loc-u" --max-tx 3 -- "$A_ADDR"
  if cmp -s "$TT/loc-c/transactions.jsonl" "$TT/loc-u/transactions.jsonl" \
     && cmp -s "$TT/loc-c/collection-gaps.tsv" "$TT/loc-u/collection-gaps.tsv"; then
    ok "order: identical corpus and gap rows under C and $utf8"
  else
    bad "order: $utf8 gave '$(sigs_of "$TT/loc-u/transactions.jsonl")', C gave '$(sigs_of "$TT/loc-c/transactions.jsonl")'"
  fi
else
  ok "order: en_US.UTF-8 is not installed here; the second-locale run is skipped"
fi

if [[ "$fails" -ne 0 ]]; then
  echo "test-dnr-collect: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr-collect: all assertions passed"
