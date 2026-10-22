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

# A jq 1.6 stand-in, first on PATH from $TT/jq16: it reads every input number as
# an IEEE-754 double and prints it the way jq 1.6 does (shortest round-trip
# digits; exponent form when the decimal point is more than 15 places past the
# last digit, or before -3), then runs the filter in the real jq.
export REAL_JQ="$(command -v jq)"
mkdir -p "$TT/jq16"
printf '#!/bin/sh\nexec "%s" -I "$0.py" "$@"\n' "$PY" > "$TT/jq16/jq"
cat > "$TT/jq16/jq.py" <<'PY'
import json, os, subprocess, sys
from decimal import Decimal
args = sys.argv[1:]
if args == ["--version"]:
    print("jq-1.6"); sys.exit(0)
opts, rest, i = [], [], 0
while i < len(args):
    if args[i] in ("--arg", "--argjson"):
        opts += args[i:i + 3]; i += 3
    elif args[i].startswith("-") and len(args[i]) > 1:
        opts.append(args[i]); i += 1
    else:
        rest.append(args[i]); i += 1
text = "".join(open(f).read() for f in rest[1:]) if len(rest) > 1 else sys.stdin.read()
def num(x):
    if x != x:
        return "null"
    x = max(min(x, 1.7976931348623157e308), -1.7976931348623157e308)
    if x == 0:
        return "-0" if str(x).startswith("-") else "0"
    sign, digits, exp = Decimal(repr(x)).normalize().as_tuple()
    ds = "".join(map(str, digits)); nd = len(ds); dp = nd + exp
    s = "-" if sign else ""
    if dp <= -4 or dp > nd + 15:
        e = dp - 1
        return s + ds[0] + ("." + ds[1:] if nd > 1 else "") + "e" + ("-" if e < 0 else "+") + "%02d" % abs(e)
    if dp <= 0:
        return s + "0." + "0" * -dp + ds
    if dp >= nd:
        return s + ds + "0" * (dp - nd)
    return s + ds[:dp] + "." + ds[dp:]
def dump(v):
    if isinstance(v, float):
        return num(v)
    if isinstance(v, list):
        return "[" + ",".join(dump(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k) + ":" + dump(x) for k, x in v.items()) + "}"
    return json.dumps(v)
try:
    dec, outs, pos = json.JSONDecoder(parse_int=float, parse_float=float), [], 0
    while True:
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        if pos >= len(text):
            break
        v, pos = dec.raw_decode(text, pos)
        outs.append(dump(v))
    text = "".join(o + "\n" for o in outs)
except ValueError:
    pass  # not JSON: the real jq reports it
sys.exit(subprocess.run([os.environ["REAL_JQ"]] + opts + rest[:1], input=text.encode()).returncode)
PY
chmod +x "$TT/jq16/jq"
# $TT/nopy: the tools the two scripts run, linked one by one, python3 left out.
mkdir -p "$TT/nopy"
for t in bash env dirname basename find git mkdir mktemp rm sed awk tr sort grep cat cut head od cmp cp mv ln ls chmod wc; do
  p="$(command -v "$t" 2>/dev/null)" && [[ "$p" == /* ]] && ln -s "$p" "$TT/nopy/$t"
done
if PATH="$TT/nopy" command -v python3 >/dev/null 2>&1; then
  bad "setup: python3 is still reachable through $TT/nopy"
fi

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

# ---------------------------------------------------------------------------
# 2. Integers above 2^53 reach transactions.jsonl exactly, on any jq. The
#    stand-in RPC splices the fixture's text verbatim, so the big literals reach
#    the collector as written. With a jq that rounds (the 1.6 stand-in), python3
#    -I writes the corpus; with no python3 either, the run stops before any call.
# ---------------------------------------------------------------------------
BIG="$FIX/lamports-over-2-53.jsonl"
eq "jq 1.6 stand-in: reports its version" "$(PATH="$TT/jq16:$PATH" jq --version)" "jq-1.6"
rounded="$(PATH="$TT/jq16:$PATH" jq -c . "$BIG")"
case "$rounded" in
  *'"preBalances":[100000,9007199254740992,12345678901234568]'*) ok "jq 1.6 stand-in: rounds the fixture's balances (control)" ;;
  *) bad "jq 1.6 stand-in: the fixture came back unrounded ($rounded)" ;;
esac
book '{"'"$A_ADDR"'": [{"signature": "SigBigLamports", "slot": 403, "err": None, "blockTime": 1700000700}]}' \
     '{"SigBigLamports": open("'"$BIG"'").read().strip()}'
collect "$TT/big-jq" -- "$A_ADDR"
if cmp -s "$TT/big-jq/transactions.jsonl" "$BIG"; then ok "exact: this jq writes the fixture byte for byte"; else bad "exact: this jq changed the fixture ($(cat "$TT/big-jq/transactions.jsonl"))"; fi
( PATH="$TT/jq16:$TT/bin:$PATH" bash "$DNR/collect.sh" --out "$TT/big-16" --confirmed -- "$A_ADDR" ) > "$TT/big-16.out" 2>&1
eq "exact: with jq 1.6 the run still exits 0" "$?" "0"
if cmp -s "$TT/big-16/transactions.jsonl" "$BIG"; then
  ok "exact: with jq 1.6, python3 -I writes the fixture byte for byte"
else
  bad "exact: the jq 1.6 path changed the fixture ($(cat "$TT/big-16/transactions.jsonl"))"
fi
eq "exact: deltas.py on that corpus sees +1 for BigOne and BigTwo" \
  "$(python3 -I "$DNR/deltas.py" lamports "$TT/big-16/transactions.jsonl" | awk -F'\t' '$2=="BigOne"||$2=="BigTwo"{print $2"="$3}' | tr '\n' ' ')" \
  "BigOne=1 BigTwo=1 "
# The python3 that writes the corpus runs isolated: a json.py planted in the
# working directory and on PYTHONPATH never loads.
mkdir -p "$TT/evil"; printf 'open(%s, "a").write("json\\n")\n' "'$TT/shadow.marker'" > "$TT/evil/json.py"
( cd "$TT/evil" && PATH="$TT/jq16:$TT/bin:$PATH" PYTHONPATH="$TT/evil" bash "$DNR/collect.sh" --out "$TT/big-iso" --confirmed -- "$A_ADDR" ) > "$TT/big-iso.out" 2>&1
if cmp -s "$TT/big-iso/transactions.jsonl" "$BIG" && [[ ! -e "$TT/shadow.marker" ]]; then
  ok "exact: the python3 -I path ignores a json.py in the working directory and on PYTHONPATH"
else
  bad "exact: hostile working directory changed the result or loaded json.py"
fi
before="$(calls getSignaturesForAddress)"
( PATH="$TT/jq16:$TT/bin:$TT/nopy" bash "$DNR/collect.sh" --out "$TT/big-nopy" --confirmed -- "$A_ADDR" ) > "$TT/big-nopy.out" 2>&1
code=$?
if [[ "$code" == 3 && ! -e "$TT/big-nopy" ]] && grep -q 'blocker.*rounds integers above 2^53.*python3' "$TT/big-nopy.out"; then
  ok "exact: jq 1.6 and no python3 -> named blocker (exit 3), nothing written"
else
  bad "exact: jq 1.6 without python3 -> exit $code ($(tr '\n' ' ' < "$TT/big-nopy.out"))"
fi
eq "exact: that blocker comes before any RPC call" "$(calls getSignaturesForAddress)" "$before"

if [[ "$fails" -ne 0 ]]; then
  echo "test-dnr-collect: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr-collect: all assertions passed"
