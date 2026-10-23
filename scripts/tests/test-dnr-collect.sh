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
# Pages honour "limit" and "before"; FAKE_SIG_FIRST_PAGE=<n> cuts the first page
# (the one without "before") to n entries, a short page before the end of the
# history. A transaction not in "tx" is a small one
# made from its signature entry. FAKE_TX_FAIL=<mode>[:<k>] fails every k-th
# getTransaction call (every call when k is left out): transport (curl exit 28),
# rpc429 (JSON-RPC error 429) or null (result null). FAKE_SWAP=<method>|<path>|<target>
# replaces <path> with a symbolic link to <target> during the first call of that
# method. FAKE_HOLD=<method>|<k>|<dir> holds the k-th call of that method: it creates
# <dir>/reached, then waits (20 s at most) for <dir>/release before it replies. Every
# request is appended to $FAKE_CURL_LOG.
# ---------------------------------------------------------------------------
mkdir -p "$TT/bin"
printf '#!/bin/sh\nexec "%s" -I "$0.py" "$@"\n' "$PY" > "$TT/bin/curl"
cat > "$TT/bin/curl.py" <<'PY'
import json, os, re, sys, time
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
swap_on, _, swap = os.environ.get("FAKE_SWAP", "").partition("|")
if swap_on == m and not os.path.islink(swap.partition("|")[0]):
    path, _, target = swap.partition("|")
    os.remove(path)
    os.symlink(target, path)
hold_on, _, hold = os.environ.get("FAKE_HOLD", "").partition("|")
if hold_on == m:
    k, _, hold_dir = hold.partition("|")
    if sum(1 for line in open(log) if '"%s"' % m in line) == int(k):
        open(os.path.join(hold_dir, "reached"), "w").close()
        for _ in range(400):
            if os.path.exists(os.path.join(hold_dir, "release")):
                break
            time.sleep(0.05)
book = json.load(open(os.environ["FAKE_BOOK"]))
def reply(member):
    sys.stdout.write('{"jsonrpc":"2.0","id":1,' + member + '}'); sys.exit(0)
if m == "getSignaturesForAddress":
    entries = book["sigs"].get(p[0], [])
    names = [e["signature"] for e in entries]
    start = names.index(p[1]["before"]) + 1 if p[1].get("before") in names else 0
    limit = p[1]["limit"]
    if "before" not in p[1] and os.environ.get("FAKE_SIG_FIRST_PAGE"):
        limit = min(limit, int(os.environ["FAKE_SIG_FIRST_PAGE"]))
    reply('"result":' + json.dumps(entries[start:start + limit]))
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
calls() { if [[ -f "$FAKE_CURL_LOG" ]]; then grep -c "\"$1\"" "$FAKE_CURL_LOG"; else echo 0; fi; }
sigs_of() { jq -r '.transaction.signatures[0]' "$1" 2>/dev/null | tr '\n' ' '; }

# A jq 1.6 stand-in, first on PATH from $TT/jq16: it reads every input number as
# an IEEE-754 double and prints it the way jq 1.6 does (the shortest digits that
# round-trip, in exponent form for very large or very small magnitudes), then runs
# the filter in the real jq.
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
utf8="$(locale -a 2>/dev/null | grep -i -E '^en_US\.utf-?8$' | sed -n 1p || true)"
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

# ---------------------------------------------------------------------------
# 3. collect.sh never truncates a corpus: an --out that holds any of its three
#    files, even an empty one, is refused before any call, and the file is left
#    as it was.
# ---------------------------------------------------------------------------
before="$(calls getSignaturesForAddress)"
for f in transactions.jsonl signatures.jsonl collection-gaps.tsv; do
  mkdir -p "$TT/keep-$f"; printf '{"kept":1}\n' > "$TT/keep-$f/$f"
  collect "$TT/keep-$f" -- "$A_ADDR"
  code=$?
  if [[ "$code" == 2 && "$(cat "$TT/keep-$f/$f")" == '{"kept":1}' && "$(ls "$TT/keep-$f")" == "$f" ]] \
     && grep -q "already holds a collected corpus ($f)" "$TT/keep-$f.out"; then
    ok "no clobber: an --out holding only $f is refused (exit 2), the file intact"
  else
    bad "no clobber: --out holding $f -> exit $code, now '$(cat "$TT/keep-$f/$f")', dir: $(ls "$TT/keep-$f" | tr '\n' ' ')"
  fi
done
mkdir -p "$TT/keep-empty"; : > "$TT/keep-empty/signatures.jsonl"
collect "$TT/keep-empty" -- "$A_ADDR"
eq "no clobber: an empty signatures.jsonl is refused too (exit 2)" "$?" "2"
eq "no clobber: refused runs made no RPC call" "$(calls getSignaturesForAddress)" "$before"

# ---------------------------------------------------------------------------
# 4. --max-tx counts getTransaction calls, failed ones included, and 10 failed
#    calls in a row stop the run, so a failing endpoint gets no more calls than
#    the estimate the human approved. Each run starts a fresh call log.
# ---------------------------------------------------------------------------
book '{"'"$A_ADDR"'": [{"signature": "S%02d" % k, "slot": 100 - k, "err": None, "blockTime": 1700000000 - k} for k in range(1, 26)]}'
rm -f "$FAKE_CURL_LOG"
FAKE_TX_FAIL=rpc429 collect "$TT/fail-cap" --max-tx 2 -- "$A_ADDR"
code=$?
eq "failing endpoint: --max-tx 2 makes exactly 2 getTransaction calls" "$(calls getTransaction)" "2"
eq "failing endpoint: exit 0; two error rows, then the cap row naming the third signature" \
  "$code|$(cut -f1 "$TT/fail-cap/collection-gaps.tsv" | tr '\n' ' ')|$(cut -f2 "$TT/fail-cap/collection-gaps.tsv" | sed -n 3p)" \
  "0|S01 S02 S03 |not fetched: --max-tx=2 calls reached; this and 22 older signatures in signatures.jsonl were not fetched"
rm -f "$FAKE_CURL_LOG"
FAKE_TX_FAIL=transport collect "$TT/fail-run" -- "$A_ADDR"
code=$?
eq "failing endpoint: 10 failed calls in a row stop the run (default --max-tx)" "$(calls getTransaction)/$code" "10/0"
eq "failing endpoint: the stop is a gap row naming the first signature not fetched" \
  "$(sed -n 11p "$TT/fail-run/collection-gaps.tsv")" \
  "S11$(printf '\t')not fetched: stopped after 10 getTransaction calls in a row failed (last: transport error (curl exit 28)); this and 14 older signatures in signatures.jsonl were not fetched"
if grep -q 'stopped: 10 getTransaction calls in a row failed .*the endpoint is failing (rate limit or outage.*collected 0, collection gaps 11' "$TT/fail-run.out" \
   && grep -q '^collection gaps: 11 ' "$TT/fail-run.out"; then
  ok "failing endpoint: the run says the endpoint is failing, with what it collected and the gap count"
else
  bad "failing endpoint: stop message missing ($(grep -m1 'stopped' "$TT/fail-run.out"))"
fi
rm -f "$FAKE_CURL_LOG"
FAKE_TX_FAIL=null:2 collect "$TT/fail-alt" -- "$A_ADDR"
eq "failing endpoint: failures that alternate with successes never stop the run (25 calls, 13 fetched, 12 gaps)" \
  "$(calls getTransaction)/$(grep -c . "$TT/fail-alt/transactions.jsonl")/$(grep -c . "$TT/fail-alt/collection-gaps.tsv")" "25/13/12"
eq "failing endpoint: the summary gives the transactions fetched out of the calls made" \
  "$(grep '^transactions fetched: ' "$TT/fail-alt.out")" "transactions fetched: 13 of 25 calls -> $TT/fail-alt/transactions.jsonl"
rm -f "$FAKE_CURL_LOG"
FAKE_TX_FAIL=null:2 collect "$TT/fail-alt-cap" --max-tx 5 -- "$A_ADDR"
eq "failing endpoint: --max-tx 5 with every second call failing -> 5 calls, 3 fetched, cap row names S06" \
  "$(calls getTransaction)/$(grep -c . "$TT/fail-alt-cap/transactions.jsonl")/$(tail -1 "$TT/fail-alt-cap/collection-gaps.tsv" | cut -f1)" "5/3/S06"

# ---------------------------------------------------------------------------
# 5. An empty page ends an address's history. A page shorter than 1000 ends it
#    only on the cap's last page, since a node can return one before the end. A
#    page cap that stops on a full page, before --since was crossed, may have left
#    older history out, whatever --since and --until are: a notice with the
#    --before to resume from, and a gap row. These runs pass --max-tx 0 and look
#    only at the paging.
# ---------------------------------------------------------------------------
# hist <n>: <n> signatures P0001.. newest first, block times 1700005000 - k.
hist() { book '{"'"$A_ADDR"'": [{"signature": "P%04d" % k, "slot": 100000 - k, "err": None, "blockTime": 1700005000 - k} for k in range(1, '"$1"' + 1)]}'; }
trunc_row() { grep "^$A_ADDR$(printf '\t')" "$1/collection-gaps.tsv" | cut -f2; }
hist 1500; rm -f "$FAKE_CURL_LOG"
collect "$TT/pg-short" --since 1000 --max-pages 2 --max-tx 0 -- "$A_ADDR"
if [[ "$(calls getSignaturesForAddress)" == 2 && -z "$(trunc_row "$TT/pg-short")" ]] && ! grep -q 'page cap' "$TT/pg-short.out"; then
  ok "paging: a short last page at the cap (1000 + 500, --since never crossed) ends the history: no notice, no gap row"
else
  bad "paging: short last page at the cap -> $(grep -m1 'page cap' "$TT/pg-short.out")"
fi
hist 2000; rm -f "$FAKE_CURL_LOG"
collect "$TT/pg-exact" --max-pages 3 --max-tx 0 -- "$A_ADDR"
if [[ "$(calls getSignaturesForAddress)" == 3 && -z "$(trunc_row "$TT/pg-exact")" ]]; then
  ok "paging: an empty page under the cap ends the history (1000 + 1000 + 0): no gap row"
else
  bad "paging: history ending on a page boundary -> row '$(trunc_row "$TT/pg-exact")'"
fi
hist 1500; rm -f "$FAKE_CURL_LOG"
collect "$TT/pg-tail" --max-tx 0 -- "$A_ADDR"
eq "paging: a short page under the cap costs one more call, and the empty page ends the history (calls, paging notices, gap row)" \
  "$(calls getSignaturesForAddress)|$(grep -c 'older history may exist' "$TT/pg-tail.out")|$(trunc_row "$TT/pg-tail")" "3|0|"
rm -f "$FAKE_CURL_LOG"
FAKE_SIG_FIRST_PAGE=300 collect "$TT/pg-midshort" --max-tx 0 -- "$A_ADDR"
eq "paging: a short page followed by more history keeps paging (300 + 1000 + 200 + 0; calls, signatures, gap row)" \
  "$(calls getSignaturesForAddress)|$(grep -c . "$TT/pg-midshort/signatures.jsonl")|$(trunc_row "$TT/pg-midshort")" "4|1500|"
rm -f "$FAKE_CURL_LOG"
FAKE_SIG_FIRST_PAGE=300 collect "$TT/pg-capshort" --max-pages 1 --max-tx 0 -- "$A_ADDR"
eq "paging: a short page on the cap's last page ends the history quietly (calls, paging notices, gap row)" \
  "$(calls getSignaturesForAddress)|$(grep -c 'older history may exist' "$TT/pg-capshort.out")|$(trunc_row "$TT/pg-capshort")" "1|0|"
hist 2500
collect "$TT/pg-full" --max-pages 2 --max-tx 0 -- "$A_ADDR"
eq "paging: no window, the cap stops on a full page -> a gap row saying older history may exist, with the resume cursor" \
  "$(trunc_row "$TT/pg-full")" \
  "older history may exist: the page cap (--max-pages 2) stopped on a full page at blockTime 1700003000; resume into a new --out with --before P2000, or raise --max-pages"
if grep -q "older history may exist for $A_ADDR: the page cap (--max-pages 2) stopped on a full page at blockTime 1700003000 — resume into a new --out with --before P2000" "$TT/pg-full.out"; then
  ok "paging: no window, the run prints the notice"
else
  bad "paging: no notice without a window"
fi
collect "$TT/pg-until" --until 100 --max-pages 2 --max-tx 0 -- "$A_ADDR"
case "$(trunc_row "$TT/pg-until")" in
  *"blockTime 1700003000, still after --until 100, so nothing inside the window was collected; resume into a new --out with --before P2000"*)
    ok "paging: --until only, the cap stops on a full page above --until -> gap row says nothing inside the window was collected" ;;
  *) bad "paging: --until only, full page above --until -> row '$(trunc_row "$TT/pg-until")'" ;;
esac
collect "$TT/pg-until-in" --until 1700004500 --max-pages 2 --max-tx 0 -- "$A_ADDR"
case "$(trunc_row "$TT/pg-until-in")" in
  "older history may exist: the page cap (--max-pages 2) stopped on a full page at blockTime 1700003000; resume into a new --out with --before P2000, or raise --max-pages")
    ok "paging: --until only, the cap stops on a full page inside the window -> gap row" ;;
  *) bad "paging: --until only, full page inside the window -> row '$(trunc_row "$TT/pg-until-in")'" ;;
esac
hist 1500
collect "$TT/pg-until-short" --until 100 --max-pages 2 --max-tx 0 -- "$A_ADDR"
eq "paging: --until only, a short last page at the cap above --until -> no notice, no gap row" \
  "$(grep -c '^  ! ' "$TT/pg-until-short.out")|$(trunc_row "$TT/pg-until-short")" "0|"
hist 2500
collect "$TT/pg-since" --since 1700003500 --max-pages 2 --max-tx 0 -- "$A_ADDR"
eq "paging: the cap's last full page crossed --since -> no gap row" "$(trunc_row "$TT/pg-since")" ""
collect "$TT/pg-since-cap" --since 1700002000 --max-pages 2 --max-tx 0 -- "$A_ADDR"
case "$(trunc_row "$TT/pg-since-cap")" in
  *"at blockTime 1700003000, still after --since 1700002000; resume into a new --out with --before P2000"*) ok "paging: the cap stops on a full page still after --since -> gap row" ;;
  *) bad "paging: full page still after --since -> row '$(trunc_row "$TT/pg-since-cap")'" ;;
esac

# ---------------------------------------------------------------------------
# A solana CLI stand-in that answers like solana-cli 3.1.10 (Agave) did against a
# loopback RPC serving each kind of account: the same output lines and error text.
#   * a config without websocket_url is ignored (defaults: mainnet-beta, id.json);
#   * `program show` and `program-v4 show` resolve a default signer unless
#     --buffer-authority / --authority is given;
#   * `program show` / `program dump` reject a loader-v4 or non-program account
#     ("is not an SBF program"); `program-v4 show` / `download` reject anything
#     not owned by loader-v4 ("is not owned by loader-v4");
#   * an immutable loader (BPFLoader2, BPFLoader) shows no authority and no slot;
#   * `account` shows the owner, and with --output-file writes the data there instead
#     of a hex dump; an address with no account is "AccountNotFound".
# FAKE_SOL_LOADER is v3 (upgradeable, default), v2, v1, v4, v3data (a data account of
# the upgradeable loader, not executable), none (an account owned by the System
# Program) or missing (no account at all). FAKE_SOL_SHOW_FAIL=1 makes both show
# commands fail as a rate-limited endpoint does. FAKE_SOL_AUTH and FAKE_SOL_STATUS
# replace the authority and the loader-v4 status a show prints. FAKE_SOL_SLOTS
# is a comma list of last-deployed slots: each read of the program (show, dump,
# download) takes the next one and the last one repeats, so a deploy can land
# between two reads. The dumped ELF carries its slot, so each deploy hashes apart.
# FAKE_SOL_SALT=<text> adds that text to the ELF, so the same slot can give other
# bytes. FAKE_SOL_SHOWN_ID=<id>[:<k>] makes a show name <id> as its Program Id once
# k reads (default 0) have been made. FAKE_SOL_LINK=<link>|<target> makes the dump
# call also create <link>, a symbolic link to <target>. Every call is appended to
# $FAKE_SOL_ARGV.
# ---------------------------------------------------------------------------
mkdir -p "$TT/sol"
printf '#!/bin/sh\nexec "%s" -I "$0.py" "$@"\n' "$PY" > "$TT/sol/solana"
cat > "$TT/sol/solana.py" <<'PY'
import json, os, re, sys
a = sys.argv[1:]
with open(os.environ["FAKE_SOL_ARGV"], "a") as log:
    log.write(json.dumps(a) + "\n")
cfg = {}
if "-C" in a:
    i = a.index("-C")
    for line in open(a[i + 1]):
        m = re.match(r'(\w+): "(.*)"$', line.rstrip("\n"))
        if m:
            cfg[m.group(1)] = m.group(2)
    del a[i:i + 2]
if "websocket_url" not in cfg:
    cfg = {"json_rpc_url": "https://api.mainnet-beta.solana.com", "keypair_path": "/home/fake/.config/solana/id.json"}
kp = cfg["keypair_path"]
if a[:3] == ["config", "get", "keypair"]:
    print(f"Key Path: {kp}"); sys.exit(0)
def fail(msg):
    sys.stderr.write(f"Error: {msg}\n"); sys.exit(1)
def opt(name):
    return a[a.index(name) + 1] if name in a else None
OWNERS = {"v3": "BPFLoaderUpgradeab1e11111111111111111111111", "v2": "BPFLoader2111111111111111111111111111111111",
          "v1": "BPFLoader1111111111111111111111111111111111", "v4": "LoaderV411111111111111111111111111111111111",
          "v3data": "BPFLoaderUpgradeab1e11111111111111111111111", "none": "11111111111111111111111111111111"}
loader = os.environ.get("FAKE_SOL_LOADER", "v3")
AUTH = os.environ.get("FAKE_SOL_AUTH", "p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV")
def read_slot():
    if loader in ("v1", "v2"):
        return 0
    slots = os.environ.get("FAKE_SOL_SLOTS", "12345").split(",")
    path = os.environ["FAKE_SOL_READS"]
    n = int(open(path).read()) if os.path.exists(path) else 0
    open(path, "w").write(str(n + 1))
    return int(slots[min(n, len(slots) - 1)])
def elf(slot):
    salt = os.environ.get("FAKE_SOL_SALT", "").encode()
    return b"\x7fELF" + slot.to_bytes(8, "little") + bytes(range(1, 40)) + salt + b"\0" * 300
def length(data):
    return f"{len(data)} ({len(data):#x}) bytes"
def no_signer():
    fail(f'Dynamic program error: No default signer found, run "solana-keygen new -o {kp}" to create a new one')
def shown():
    other, _, start = os.environ.get("FAKE_SOL_SHOWN_ID", "").partition(":")
    path = os.environ["FAKE_SOL_READS"]
    n = int(open(path).read()) if os.path.exists(path) else 0
    return other if other and n >= int(start or 0) else pid
cmd = a[:2]
if cmd == ["program", "show"] or cmd == ["program-v4", "show"]:
    if opt("--buffer-authority" if cmd[0] == "program" else "--authority") is None and not os.path.exists(kp):
        no_signer()
pid = a[2] if cmd[0] == "program" else a[1] if cmd[0] == "account" else opt("--program-id")
if cmd[0] in ("program", "program-v4") and loader == "missing":
    fail(f"Unable to find the account {pid}")
if cmd in (["program", "show"], ["program-v4", "show"]) and os.environ.get("FAKE_SOL_SHOW_FAIL"):
    fail("429 Too Many Requests")
if cmd in (["program", "show"], ["program", "dump"]) and loader == "v3data":
    fail(f"{pid} is not an upgradeable program")
if cmd in (["program", "show"], ["program", "dump"]) and loader in ("v4", "none"):
    fail(f"{pid} is not an SBF program")
if cmd[0] == "program-v4" and loader != "v4":
    fail(f"{pid} is not owned by loader-v4")
if cmd == ["program", "show"] and loader == "v3":
    shown_id = shown()
    slot = read_slot()
    print(f"\nProgram Id: {shown_id}\nOwner: {OWNERS[loader]}\nProgramData Address: YMN9Qj5jPNp7j14VPcML1B6xGgcPWVZUGLFU3Mnyfaf\n"
          f"Authority: {AUTH}\nLast Deployed In Slot: {slot}\nData Length: {length(elf(slot))}\nBalance: 0.00114144 SOL\n")
elif cmd == ["program", "show"]:
    print(f"\nProgram Id: {shown()}\nOwner: {OWNERS[loader]}\nData Length: {length(elf(0))}\n")
elif cmd == ["program-v4", "show"]:
    shown_id = shown()
    slot = read_slot()
    print(f"\nProgram Id: {shown_id}\nOwner: {OWNERS[loader]}\nAuthority: {AUTH}\nLast Deployed In Slot: {slot}\n"
          f"Status: {os.environ.get('FAKE_SOL_STATUS', 'deployed')}\nData Length: {length(elf(slot))}\n")
elif cmd[0] == "account":
    if loader == "missing":
        fail(f"AccountNotFound: pubkey={pid}")
    data = elf(0) if loader not in ("none", "v3data") else b"\x01" * 165
    print(f"\nPublic Key: {pid}\nBalance: 0.00203928 SOL\nOwner: {OWNERS[loader]}\n"
          f"Executable: {str(loader not in ('none', 'v3data')).lower()}\nRent Epoch: 18446744073709551615")
    if opt("--output-file"):
        open(opt("--output-file"), "wb").write(data)
        print(f"\nWrote account data to {opt('--output-file')}")
    else:
        print(f"Length: {length(data)}\n0000:   " + " ".join(f"{b:02x}" for b in data[:16]))
elif cmd in (["program", "dump"], ["program-v4", "download"]):
    path = a[3] if cmd[0] == "program" else [x for x in a[2:] if not x.startswith("--") and x != pid][-1]
    open(path, "wb").write(elf(read_slot()))
    link, _, target = os.environ.get("FAKE_SOL_LINK", "").partition("|")
    if link and not os.path.lexists(link):
        os.symlink(target, link)
    print(f"Wrote program to {path}")
else:
    sys.stderr.write("fake solana: refusing an unexpected subcommand\n"); sys.exit(9)
PY
chmod +x "$TT/sol/solana"
export FAKE_SOL_ARGV="$TT/sol.argv" FAKE_SOL_READS="$TT/sol.reads"
PID="ProgTest11111111111111111111111111111111111"   # base58, 32 bytes
# snap <dir> [var=value ...]: run snapshot-program.sh on a fresh read counter,
# output in <dir>.out; extra variables go to the stand-in.
snap() {
  local dir="$1"; shift
  rm -f "$FAKE_SOL_READS"
  ( export "$@" PATH="$TT/sol:$TT/bin:$PATH"; bash "$DNR/snapshot-program.sh" "$PID" "$dir" ) > "$dir.out" 2>&1
}
cli_calls() { if [[ -f "$FAKE_SOL_ARGV" ]]; then grep -c . "$FAKE_SOL_ARGV"; else echo 0; fi; }
names() { ls "$1" | LC_ALL=C sort | tr '\n' ' '; }   # a directory's entries, in byte order

# ---------------------------------------------------------------------------
# 6. snapshot-program.sh needs python3 (the id check and the hash): with none on
#    PATH it stops with a named blocker (exit 3) before the CLI runs, and writes
#    nothing.
# ---------------------------------------------------------------------------
before="$(cli_calls)"
( PATH="$TT/sol:$TT/nopy" bash "$DNR/snapshot-program.sh" "$PID" "$TT/nopy-inc" ) > "$TT/nopy-inc.out" 2>&1
code=$?
if [[ "$code" == 3 && ! -e "$TT/nopy-inc" ]] && grep -q '^\[blocker\] python3 not on PATH' "$TT/nopy-inc.out"; then
  ok "snapshot: no python3 -> named blocker (exit 3), nothing written"
else
  bad "snapshot: no python3 -> exit $code ($(tr '\n' ' ' < "$TT/nopy-inc.out"))"
fi
eq "snapshot: no CLI call before the python3 check" "$(cli_calls)" "$before"

# ---------------------------------------------------------------------------
# 7. A snapshot is never overwritten. The first one is bin/<id>.so + .show.txt;
#    a later run at the same slot and hash prints "unchanged" and rewrites
#    nothing; a later run at another slot keeps bin/<id>@<slot>.so + .show.txt
#    beside the first and prints both lines; a name already taken is a blocker.
# ---------------------------------------------------------------------------
K="$TT/keep/incident_1"; mkdir -p "$TT/keep"
snap "$K" FAKE_SOL_SLOTS=100
code=$?
line1="$(cat "$K.out")"
if [[ "$code" == 0 && -s "$K/bin/$PID.so" && -s "$K/bin/$PID.show.txt" ]] \
   && [[ "$line1" == "program=$PID "*"last_deployed_slot=100 "*" file=bin/$PID.so" ]]; then
  ok "keep: the first snapshot is bin/<id>.so + bin/<id>.show.txt, one ledger line"
else
  bad "keep: first snapshot -> exit $code ($line1)"
fi
cp "$K/bin/$PID.so" "$TT/first.so"; cp "$K/bin/$PID.show.txt" "$TT/first.show"
touch -t 200001010000 "$K/bin/$PID.so" "$K/bin/$PID.show.txt"; touch -t 200101010000 "$TT/ref2001"
snap "$K" FAKE_SOL_SLOTS=100
code=$?
eq "keep: same slot and hash -> exit 0, 'unchanged', then the first snapshot's line" \
  "$code|$(sed -n 1p "$K.out")|$(sed -n 2p "$K.out")" \
  "0|unchanged: the program on-chain matches bin/$PID.so (same last-deployed slot and zero-trimmed sha256); nothing written|$line1"
eq "keep: an unchanged run rewrites nothing and adds nothing" \
  "$(find "$K/bin" -type f -newer "$TT/ref2001" | wc -l | tr -d ' ')|$(names "$K/bin")" "0|$PID.show.txt $PID.so "
snap "$K" FAKE_SOL_SLOTS=200
code=$?
if [[ "$code" == 0 ]] && cmp -s "$K/bin/$PID.so" "$TT/first.so" && cmp -s "$K/bin/$PID.show.txt" "$TT/first.show" \
   && [[ -s "$K/bin/$PID@200.so" && -s "$K/bin/$PID@200.show.txt" ]] && ! cmp -s "$K/bin/$PID@200.so" "$TT/first.so"; then
  ok "keep: a redeploy (slot 200) is kept as bin/<id>@200.so; bin/<id>.so and its .show.txt are untouched"
else
  bad "keep: redeploy -> exit $code, bin: $(ls "$K/bin" | tr '\n' ' ')"
fi
eq "keep: the redeploy run prints the first snapshot's line, then the new one" \
  "$(sed -n 2p "$K.out")|$(sed -n 3p "$K.out" | grep -o 'last_deployed_slot=200 .* file=bin/.*$' | sed 's/sha256_zero_trimmed=[0-9a-f]* //')" \
  "$line1|last_deployed_slot=200 authority=p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV elf_bytes=51 padding_bytes=300 file=bin/$PID@200.so"
snap "$K" FAKE_SOL_SLOTS=200
eq "keep: a run at slot 200 again matches bin/<id>@200.so" "$?|$(sed -n 1p "$K.out" | cut -d' ' -f1-6)" "0|unchanged: the program on-chain matches bin/$PID@200.so"
printf 'other bytes\n' > "$K/bin/$PID@300.show.txt"
snap "$K" FAKE_SOL_SLOTS=300
code=$?
if [[ "$code" == 3 && "$(cat "$K/bin/$PID@300.show.txt")" == "other bytes" && ! -e "$K/bin/$PID@300.so" ]] \
   && grep -q "blocker.*bin/$PID@300.show.txt exists without bin/$PID@300.so (an earlier snapshot did not finish).*never overwritten" "$K.out"; then
  ok "keep: a taken bin/<id>@<slot>.show.txt is a blocker (exit 3) and stays as it was"
else
  bad "keep: taken @300 name -> exit $code ($(tr '\n' ' ' < "$K.out"))"
fi
rm -f "$K/bin/$PID@300.show.txt"
# A kept snapshot must still be what was written: a regular .so with the ELF magic,
# beside a regular .show.txt. Bytes on-chain that differ from a snapshot kept at the
# same or a later slot are a blocker, never "unchanged" and never a new snapshot.
K3="$TT/keep3/incident_1"; mkdir -p "$TT/keep3"
snap "$K3" FAKE_SOL_SLOTS=100
cp -p "$K3/bin/$PID.so" "$TT/k3.so"
for case in "same slot, other bytes|FAKE_SOL_SLOTS=100|FAKE_SOL_SALT=x" "an older slot than kept, other bytes|FAKE_SOL_SLOTS=90|FAKE_SOL_SALT="; do
  label="${case%%|*}"; rest="${case#*|}"
  snap "$K3" "${rest%%|*}" "${rest#*|}"
  code=$?
  if [[ "$code" == 3 && "$(names "$K3/bin")" == "$PID.show.txt $PID.so " ]] && cmp -s "$K3/bin/$PID.so" "$TT/k3.so" \
     && ! grep -q '^unchanged' "$K3.out" && grep -q "blocker.*bin/$PID.so was kept at last-deployed slot 100, not older than the slot on-chain now" "$K3.out"; then
    ok "kept snapshots: $label -> blocker (exit 3), not 'unchanged', nothing written"
  else
    bad "kept snapshots: $label -> exit $code, bin: $(names "$K3/bin") ($(tr '\n' ' ' < "$K3.out"))"
  fi
done
snap "$K3" FAKE_SOL_SLOTS=100
eq "kept snapshots: control, the same slot and bytes are still 'unchanged'" "$?|$(sed -n 1p "$K3.out" | cut -d' ' -f1)" "0|unchanged:"
for case in "a .so without the ELF magic|so-text" "a .show.txt that is a directory|show-dir" "a .so that is a directory|so-dir"; do
  label="${case%%|*}"; how="${case#*|}"
  K4="$TT/keep4-$how/incident_1"; mkdir -p "$TT/keep4-$how"
  snap "$K4" FAKE_SOL_SLOTS=100
  case "$how" in
    so-text) printf 'not an elf\n' > "$K4/bin/$PID.so.new"; mv "$K4/bin/$PID.so.new" "$K4/bin/$PID.so" ;;
    show-dir) mv "$K4/bin/$PID.show.txt" "$TT/keep4.show.txt"; mkdir "$K4/bin/$PID.show.txt" ;;
    so-dir) mkdir "$K4/bin/$PID@50.so"; cp "$K4/bin/$PID.show.txt" "$K4/bin/$PID@50.show.txt" ;;
  esac
  before_names="$(names "$K4/bin")"
  snap "$K4" FAKE_SOL_SLOTS=200
  code=$?
  if [[ "$code" == 3 && "$(names "$K4/bin")" == "$before_names" ]] && grep -q 'blocker.*is not a regular file with the ELF magic beside a regular' "$K4.out"; then
    ok "kept snapshots: $label -> blocker (exit 3), nothing written"
  else
    bad "kept snapshots: $label -> exit $code, bin: $(names "$K4/bin") ($(tr '\n' ' ' < "$K4.out"))"
  fi
done
# Every kept snapshot is checked before any of them can match, so a match with one
# never hides another that is damaged, or that the chain's bytes disagree with.
for case in "a later snapshot with other bytes than the chain|other" "a later snapshot that is not an ELF|text" \
            "a later snapshot's .show.txt that is a directory|dir" "a later .show.txt without its .so|lone"; do
  label="${case%%|*}"; how="${case#*|}"
  K5="$TT/keep5-$how/incident_1"; mkdir -p "$TT/keep5-$how"
  snap "$K5" FAKE_SOL_SLOTS=100; snap "$K5" FAKE_SOL_SLOTS=200
  case "$how" in
    text) printf 'not an elf\n' > "$K5/bin/$PID@200.so.new"; mv "$K5/bin/$PID@200.so.new" "$K5/bin/$PID@200.so" ;;
    dir) rm -f "$K5/bin/$PID@200.show.txt"; mkdir "$K5/bin/$PID@200.show.txt" ;;
    lone) rm -f "$K5/bin/$PID@200.so" ;;
  esac
  before_names="$(names "$K5/bin")"
  snap "$K5" FAKE_SOL_SLOTS=100
  code=$?
  if [[ "$code" == 3 && "$(names "$K5/bin")" == "$before_names" ]] && ! grep -q '^unchanged' "$K5.out" && grep -q "^\[blocker\] bin/$PID@200" "$K5.out"; then
    ok "kept snapshots: the chain matches bin/<id>.so, but $label -> blocker (exit 3), nothing written"
  else
    bad "kept snapshots: the chain matches bin/<id>.so, but $label -> exit $code ($(tr '\n' ' ' < "$K5.out"))"
  fi
done
# Later snapshots without the first one: the incident-time bytes are gone, and no new
# "first" snapshot takes their place.
K6="$TT/keep6/incident_1"; mkdir -p "$TT/keep6"
snap "$K6" FAKE_SOL_SLOTS=100; snap "$K6" FAKE_SOL_SLOTS=200
rm -f "$K6/bin/$PID.so" "$K6/bin/$PID.show.txt"
snap "$K6" FAKE_SOL_SLOTS=200 FAKE_SOL_SALT=x
code=$?
if [[ "$code" == 3 && "$(names "$K6/bin")" == "$PID@200.show.txt $PID@200.so " ]] \
   && grep -q "^\[blocker\] bin/ holds later snapshots of $PID but not the first one" "$K6.out"; then
  ok "kept snapshots: later snapshots without bin/<id>.so -> blocker (exit 3), no new first snapshot"
else
  bad "kept snapshots: later snapshots without bin/<id>.so -> exit $code, bin: $(names "$K6/bin") ($(tr '\n' ' ' < "$K6.out"))"
fi
# An unchanged program whose authority or loader-v4 status changed: the line gives the
# values read now, and a notice names the change.
K7="$TT/keep7/incident_1"; mkdir -p "$TT/keep7"
snap "$K7" FAKE_SOL_LOADER=v4 FAKE_SOL_SLOTS=100
snap "$K7" FAKE_SOL_LOADER=v4 FAKE_SOL_SLOTS=100 FAKE_SOL_STATUS=finalized FAKE_SOL_AUTH=NewAuth1111111111111111111111111111111111111
code=$?
eq "unchanged: the line gives the authority and status read now, and a notice names the change" \
  "$code|$(sed -n 1p "$K7.out" | cut -d' ' -f1)|$(grep -o 'authority=[^ ]* status=[^ ]*' "$K7.out")|$(grep -c '^  ! the authority or status of .* changed since bin/.*show.txt was kept (authority/status then: p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV/deployed; now: NewAuth1111111111111111111111111111111111111/finalized)' "$K7.out")" \
  "0|unchanged:|authority=NewAuth1111111111111111111111111111111111111 status=finalized|1"
K2="$TT/keep2/incident_1"; mkdir -p "$K2/bin"; printf 'partial\n' > "$K2/bin/$PID.show.txt"
snap "$K2" FAKE_SOL_SLOTS=100
code=$?
if [[ "$code" == 3 && "$(cat "$K2/bin/$PID.show.txt")" == partial && ! -e "$K2/bin/$PID.so" ]]; then
  ok "keep: a bin/<id>.show.txt without its .so is a blocker (exit 3), left as it was"
else
  bad "keep: lone show.txt -> exit $code, bin: $(ls "$K2/bin" | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
# 8. Every loader the CLI knows: upgradeable (program show / dump), immutable
#    (no slot, no authority) and loader-v4 (program-v4 show / download, after
#    `program show` rejects it). An account under none of them is a blocker that
#    shows both CLI errors; an id that is not 32 bytes is refused before the CLI.
# ---------------------------------------------------------------------------
L="$TT/loaders"; mkdir -p "$L"; rm -f "$FAKE_SOL_ARGV"
snap "$L/v4" FAKE_SOL_LOADER=v4 FAKE_SOL_SLOTS=777
code=$?
case "$code|$(cat "$L/v4.out")" in
  "0|program=$PID owner=LoaderV411111111111111111111111111111111111 last_deployed_slot=777 authority=p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV status=deployed sha256_zero_trimmed="*" elf_bytes=51 padding_bytes=300 file=bin/$PID.so")
    ok "loader-v4: snapshotted (exit 0) with its owner, deploy slot, authority and status" ;;
  *) bad "loader-v4: exit $code ($(tr '\n' ' ' < "$L/v4.out"))" ;;
esac
eq "loader-v4: the CLI calls, in order" \
  "$(jq -r 'map(select(. != "-C" and (test("cli.yml$") | not) and (test("dump.so$") | not))) | join(" ")' "$FAKE_SOL_ARGV" | grep -v '^config ' | tr '\n' '|')" \
  "program show $PID --buffer-authority 11111111111111111111111111111111|program-v4 show --program-id $PID --authority 11111111111111111111111111111111|program-v4 download --program-id $PID|program-v4 show --program-id $PID --authority 11111111111111111111111111111111|"
snap "$L/v4" FAKE_SOL_LOADER=v4 FAKE_SOL_SLOTS=900
eq "loader-v4: a redeploy is kept beside the first snapshot" "$?|$(names "$L/v4/bin")" \
  "0|$PID.show.txt $PID.so $PID@900.show.txt $PID@900.so "
for ld in v2 v1; do
  snap "$L/$ld" FAKE_SOL_LOADER="$ld"
  code=$?
  case "$code|$(cat "$L/$ld.out")" in
    "0|program=$PID owner=BPFLoader"*" last_deployed_slot=n/a (immutable loader) authority=none sha256_zero_trimmed="*" file=bin/$PID.so")
      ok "immutable loader ($ld): last_deployed_slot=n/a (immutable loader), no authority" ;;
    *) bad "immutable loader ($ld): exit $code ($(tr '\n' ' ' < "$L/$ld.out"))" ;;
  esac
done
snap "$L/v2" FAKE_SOL_LOADER=v2
eq "immutable loader: a second run is 'unchanged'" "$?|$(sed -n 1p "$L/v2.out" | cut -d' ' -f1)" "0|unchanged:"
snap "$L/none" FAKE_SOL_LOADER=none
code=$?
if [[ "$code" == 3 && ! -e "$L/none/bin" ]] && grep -q 'neither solana program show nor program-v4 show reads' "$L/none.out" \
   && grep -q "Error: $PID is not an SBF program" "$L/none.out" && grep -q "Error: $PID is not owned by loader-v4" "$L/none.out"; then
  ok "no program: a blocker (exit 3) with both CLI errors, nothing written"
else
  bad "no program: exit $code ($(tr '\n' ' ' < "$L/none.out"))"
fi
eq "no program: the blocker names the account's owner, read with one more call" \
  "$(grep 'is not a program' "$L/none.out")|$(grep '"account"' "$FAKE_SOL_ARGV" | grep -c '"--output-file"')" \
  "[blocker] $PID is not a program: its account is owned by 11111111111111111111111111111111. Check the id; nothing written.|1"
# An account a loader owns: executable, when both show commands failed on a program
# (here a rate-limited endpoint), the blocker says to run the snapshot again; a data
# account of the loader, to check the id.
snap "$L/show-fail" FAKE_SOL_SHOW_FAIL=1
code=$?
if [[ "$code" == 3 && ! -e "$L/show-fail/bin" ]] && ! grep -q 'is not a program' "$L/show-fail.out" \
   && grep -q "^\[blocker\] the account of $PID is owned by BPFLoaderUpgradeab1e11111111111111111111111, a loader, yet neither show command read it as a program (see the errors above): .* Run the snapshot again" "$L/show-fail.out"; then
  ok "no show: a program the show commands failed to read -> blocker (exit 3) to run again, never 'not a program'"
else
  bad "no show: exit $code ($(tr '\n' ' ' < "$L/show-fail.out"))"
fi
snap "$L/v3data" FAKE_SOL_LOADER=v3data
code=$?
if [[ "$code" == 3 && ! -e "$L/v3data/bin" ]] \
   && grep -q "^\[blocker\] $PID is not a program: it is a data account of BPFLoaderUpgradeab1e11111111111111111111111, a loader (a program's data account or a buffer). Check the id" "$L/v3data.out"; then
  ok "no program: a data account of the loader -> blocker (exit 3) to check the id"
else
  bad "no program: loader data account -> exit $code ($(tr '\n' ' ' < "$L/v3data.out"))"
fi
snap "$L/missing" FAKE_SOL_LOADER=missing
code=$?
if [[ "$code" == 3 && ! -e "$L/missing/bin" ]] && grep -q "^\[blocker\] $PID is not a program, and its account could not be read either:$" "$L/missing.out" \
   && grep -q "Error: AccountNotFound: pubkey=$PID" "$L/missing.out"; then
  ok "no account: a blocker (exit 3) that says the account could not be read either, with the CLI's error"
else
  bad "no account: exit $code ($(tr '\n' ' ' < "$L/missing.out"))"
fi
# The show output must name the requested id as its Program Id, before the dump and
# when the program is read again after it.
for case in "the first show|0|0" "the show after the dump|2|1"; do
  label="${case%%|*}"; rest="${case#*|}"; from="${rest%%|*}"; dumps="${rest#*|}"
  rm -f "$FAKE_SOL_ARGV"
  snap "$L/other-id-$from" FAKE_SOL_SHOWN_ID="OtherProg1111111111111111111111111111111111:$from"
  code=$?
  if [[ "$code" == 3 && ! -e "$L/other-id-$from/bin" && "$(grep -c '"dump"' "$FAKE_SOL_ARGV")" == "$dumps" ]] \
     && grep -q "^\[blocker\] the solana CLI's show output does not name $PID as its Program Id; nothing written.$" "$L/other-id-$from.out"; then
    ok "program id: another Program Id in $label -> blocker (exit 3), nothing written"
  else
    bad "program id: another Program Id in $label -> exit $code ($(tr '\n' ' ' < "$L/other-id-$from.out"))"
  fi
done
before="$(cli_calls)"
( PATH="$TT/sol:$TT/bin:$PATH" bash "$DNR/snapshot-program.sh" "ProgTest1111111111111111111111111111111111" "$L/short" ) > "$L/short.out" 2>&1
code=$?
if [[ "$code" == 2 && ! -e "$L/short" ]] && grep -q 'does not decode to a 32-byte public key' "$L/short.out"; then
  ok "id check: a base58 id of 31 bytes is refused (exit 2), nothing written"
else
  bad "id check: 31-byte id -> exit $code ($(tr '\n' ' ' < "$L/short.out"))"
fi
eq "id check: no CLI call for that id" "$(cli_calls)" "$before"

# ---------------------------------------------------------------------------
# 9. The slot and the bytes agree. The slot is read again after the dump; a
#    deploy that lands in between means one more dump, and a slot that moves
#    again is a blocker. The stand-in's ELF carries its slot at bytes 4..12, so
#    the kept bytes can be checked against the reported slot.
# ---------------------------------------------------------------------------
elf_slot() { python3 -I -c 'import sys; print(int.from_bytes(open(sys.argv[1], "rb").read()[4:12], "little"))' "$1"; }
R="$TT/race"; mkdir -p "$R"; rm -f "$FAKE_SOL_ARGV"
snap "$R/still" FAKE_SOL_SLOTS=100
eq "slot check: a program that does not move is shown, dumped and shown again (3 program calls, no retry)" \
  "$?|$(grep -c '"program' "$FAKE_SOL_ARGV")|$(grep -c 'dumping again' "$R/still.out")" "0|3|0"
snap "$R/once" FAKE_SOL_SLOTS=100,200
code=$?
if [[ "$code" == 0 ]] && grep -q "the last-deployed slot of $PID moved during the dump (100 -> 200); dumping again" "$R/once.out" \
   && grep -q "^program=$PID .* last_deployed_slot=200 " "$R/once.out" && [[ "$(elf_slot "$R/once/bin/$PID.so")" == 200 ]]; then
  ok "slot check: a deploy during the dump -> one more dump; the kept bytes are slot 200's, and the line says 200"
else
  bad "slot check: one deploy during the dump -> exit $code ($(tr '\n' ' ' < "$R/once.out"))"
fi
snap "$R/twice" FAKE_SOL_SLOTS=100,200,300,400,500
code=$?
if [[ "$code" == 3 && ! -e "$R/twice/bin" ]] && grep -q "blocker.*moved during both dumps (100 -> 300 -> 500)" "$R/twice.out"; then
  ok "slot check: a slot that moves during both dumps is a blocker (exit 3), nothing written"
else
  bad "slot check: deploys during both dumps -> exit $code ($(tr '\n' ' ' < "$R/twice.out"))"
fi
snap "$R/v4" FAKE_SOL_LOADER=v4 FAKE_SOL_SLOTS=700,800
code=$?
if [[ "$code" == 0 ]] && grep -q "moved during the dump (700 -> 800); dumping again" "$R/v4.out" \
   && grep -q "^program=$PID owner=LoaderV4.* last_deployed_slot=800 " "$R/v4.out" && [[ "$(elf_slot "$R/v4/bin/$PID.so")" == 800 ]]; then
  ok "slot check: the loader-v4 path re-reads the slot and dumps again too"
else
  bad "slot check: loader-v4 deploy during the dump -> exit $code ($(tr '\n' ' ' < "$R/v4.out"))"
fi

# ---------------------------------------------------------------------------
# 10. collect.sh makes its private temp directory before it writes anything and
#     removes it on exit; when none can be made it stops with a blocker (exit 3)
#     and --out is not created. An --out it cannot write into is named as such
#     (exit 2). The corpus files are written only through the descriptors opened
#     when they were created, and the fetch list comes from a private copy of the
#     signature list: a corpus file replaced by a symbolic link mid-run never
#     receives a write, or hands over a signature, through that link.
# ---------------------------------------------------------------------------
book '{"'"$A_ADDR"'": [{"signature": "S%02d" % k, "slot": 100 - k, "err": None, "blockTime": 1700000000 - k} for k in range(1, 4)]}'
mkdir -p "$TT/tmpd"
( export TMPDIR="$TT/tmpd"; collect "$TT/w-ok" -- "$A_ADDR" )
eq "temp dir: a run exits 0 and leaves no dnr_collect.* directory behind" "$?|$(ls -A "$TT/tmpd" | tr '\n' ' ')" "0|"
( export TMPDIR="$TT/tmpd" FAKE_TX_FAIL=transport; collect "$TT/w-fail" -- "$A_ADDR" )
eq "temp dir: ... nor does a run whose every fetch fails" "$?|$(ls -A "$TT/tmpd" | tr '\n' ' ')" "0|"
before="$(calls getSignaturesForAddress)"
( export TMPDIR="$TT/no-such-dir"; collect "$TT/w-notmp" -- "$A_ADDR" )
code=$?
if [[ "$code" == 3 && ! -e "$TT/w-notmp" ]] && grep -q '^\[blocker\] cannot create a private temp directory' "$TT/w-notmp.out"; then
  ok "temp dir: none can be made -> named blocker (exit 3), --out not created"
else
  bad "temp dir: no temp dir -> exit $code, --out $( [[ -e "$TT/w-notmp" ]] && echo created || echo absent) ($(tr '\n' ' ' < "$TT/w-notmp.out"))"
fi
eq "temp dir: ... and no RPC call" "$(calls getSignaturesForAddress)" "$before"
mkdir -p "$TT/w-ro"; chmod 0500 "$TT/w-ro"
if [[ -w "$TT/w-ro" ]]; then
  ok "unwritable --out: skipped, this user can write into a 0500 directory"
else
  collect "$TT/w-ro" -- "$A_ADDR"
  code=$?
  if [[ "$code" == 2 ]] && grep -q "cannot create the corpus files in $TT/w-ro" "$TT/w-ro.out" && ! grep -q 'already holds' "$TT/w-ro.out"; then
    ok "unwritable --out: exit 2, named as a directory it cannot create the corpus files in"
  else
    bad "unwritable --out: exit $code ($(tr '\n' ' ' < "$TT/w-ro.out"))"
  fi
fi
chmod 0700 "$TT/w-ro"
printf 'outside\n' > "$TT/outside-tx"; printf 'outside\n' > "$TT/outside-gaps"
printf '{"signature":"SForged","slot":999,"err":null,"blockTime":1700000999}\n' > "$TT/outside-sigs"
cp "$TT/outside-sigs" "$TT/outside-sigs.before"
FAKE_SWAP="getTransaction|$TT/w-swap-tx/transactions.jsonl|$TT/outside-tx" collect "$TT/w-swap-tx" -- "$A_ADDR"
code=$?
if [[ "$code" == 0 && "$(cat "$TT/outside-tx")" == outside && -L "$TT/w-swap-tx/transactions.jsonl" ]]; then
  ok "descriptors: transactions.jsonl replaced by a link mid-run -> no write goes through the link"
else
  bad "descriptors: swapped transactions.jsonl -> exit $code, outside file now '$(tr '\n' ' ' < "$TT/outside-tx")'"
fi
FAKE_TX_FAIL=null FAKE_SWAP="getTransaction|$TT/w-swap-gaps/collection-gaps.tsv|$TT/outside-gaps" collect "$TT/w-swap-gaps" -- "$A_ADDR"
code=$?
if [[ "$code" == 0 && "$(cat "$TT/outside-gaps")" == outside ]] && grep -q '^collection gaps: 3 ' "$TT/w-swap-gaps.out"; then
  ok "descriptors: collection-gaps.tsv replaced by a link mid-run -> its 3 rows never go through the link"
else
  bad "descriptors: swapped collection-gaps.tsv -> exit $code, outside file now '$(tr '\n' ' ' < "$TT/outside-gaps")'"
fi
rm -f "$FAKE_CURL_LOG"
FAKE_SWAP="getSignaturesForAddress|$TT/w-swap-sigs/signatures.jsonl|$TT/outside-sigs" collect "$TT/w-swap-sigs" -- "$A_ADDR"
code=$?
eq "descriptors: signatures.jsonl replaced by a link mid-run -> the 3 signatures the RPC gave are fetched, none from the link" \
  "$code|$(calls getTransaction)|$(grep -c SForged "$FAKE_CURL_LOG")" "0|3|0"
if cmp -s "$TT/outside-sigs" "$TT/outside-sigs.before"; then
  ok "descriptors: ... and no signature line is written through the link"
else
  bad "descriptors: the swapped signatures.jsonl link received lines"
fi

# ---------------------------------------------------------------------------
# 11. snapshot-program.sh checks the run directory again just before its first
#     write: a symbolic link that appears in it while the CLI runs (here during
#     the dump) stops the run with exit 2, and nothing is written inside or outside.
# ---------------------------------------------------------------------------
mkdir -p "$TT/link-out"
for case in "bin|$TT/link-out" "LEDGER.md|$TT/link-out/ledger"; do
  name="${case%%|*}"; target="${case#*|}"
  P="$TT/late-$name/incident_1"; mkdir -p "$P"
  snap "$P" FAKE_SOL_LINK="$P/$name|$target"
  code=$?
  if [[ "$code" == 2 && ! -e "$P/bin/$PID.so" && -z "$(ls -A "$TT/link-out")" ]] && grep -q "refusing $P" "$P.out"; then
    ok "re-check: a $name link that appears during the dump -> exit 2, nothing written inside or outside"
  else
    bad "re-check: $name link made during the dump -> exit $code, outside: $(ls -A "$TT/link-out" | tr '\n' ' ') ($(tr '\n' ' ' < "$P.out"))"
  fi
done

# ---------------------------------------------------------------------------
# 12. A run stopped by INT, TERM or HUP (sent while the stand-in holds one call)
#     records what it had not finished as collection gaps, prints its closing lines
#     and exits 128 + the signal number. During the fetch, one row names the first
#     signature listed but not fetched; during paging, the address being paged is a
#     row too, with the point to resume from once a page has been read, and nothing
#     is fetched.
# ---------------------------------------------------------------------------
# hold_run <out dir> <method>|<k> <signal> <args...>: run collect.sh in the
# background, with SIGINT at its default as in a run from a terminal, and send it
# <signal> while the stand-in holds call k of <method>; returns its exit status.
hold_run() {
  local out="$1" hold="$2" sig="$3" pid n=0
  shift 3
  mkdir -p "$TT/hold"; rm -f "$TT/hold/reached" "$TT/hold/release"
  FAKE_HOLD="$hold|$TT/hold" PATH="$TT/bin:$PATH" "$PY" -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
os.execvp("bash", ["bash"] + sys.argv[1:])' "$DNR/collect.sh" --out "$out" --confirmed "$@" > "$out.out" 2>&1 &
  pid=$!
  while [[ ! -e "$TT/hold/reached" && "$n" -lt 200 ]]; do sleep 0.05; n=$((n + 1)); done
  kill -"$sig" "$pid"
  touch "$TT/hold/release"
  wait "$pid"
}
book '{"'"$A_ADDR"'": [{"signature": "S%02d" % k, "slot": 100 - k, "err": None, "blockTime": 1700000000 - k} for k in range(1, 6)]}'
rm -f "$FAKE_CURL_LOG"
hold_run "$TT/int-fetch" "getTransaction|3" TERM -- "$A_ADDR"
code=$?
row="$(grep 'interrupted' "$TT/int-fetch/collection-gaps.tsv")"
first="${row%%$(printf '\t')*}"
k="${first#S0}"
eq "interrupted fetch: exit 143, and one gap row naming the first signature not fetched, with the rest counted" \
  "$code|$row" "143|$first$(printf '\t')not fetched: the run was interrupted (TERM); this and $((5 - ${k:-0})) older signatures in signatures.jsonl were not fetched"
eq "interrupted fetch: every listed signature is fetched or covered by that row" \
  "$(python3 -I -c 'import json, sys
got = {json.loads(l)["transaction"]["signatures"][0] for l in open(sys.argv[1])}
print(sorted(got | {"S%02d" % k for k in range(int(sys.argv[2] or 9), 6)}) == ["S%02d" % k for k in range(1, 6)])' "$TT/int-fetch/transactions.jsonl" "$k")" "True"
eq "interrupted fetch: the run still closes with its fetch summary and gap count" \
  "$(grep -c '^transactions fetched: [0-9]* of [0-9]* calls -> ' "$TT/int-fetch.out")|$(grep -c '^collection gaps: 1 (see ' "$TT/int-fetch.out")" "1|1"
B_ADDR="AddrB111111111111111111111111111111111111111"
book '{"'"$A_ADDR"'": [{"signature": "SigA%d" % k, "slot": 30 - k, "err": None, "blockTime": 1700000030 - k} for k in range(1, 4)],
       "'"$B_ADDR"'": [{"signature": "SigB%d" % k, "slot": 20 - k, "err": None, "blockTime": 1700000020 - k} for k in range(1, 4)]}'
rm -f "$FAKE_CURL_LOG"
hold_run "$TT/int-page" "getSignaturesForAddress|3" TERM -- "$A_ADDR" "$B_ADDR"
code=$?
eq "interrupted paging: exit 143, and no getTransaction call" "$code|$(calls getTransaction)" "143|0"
if grep -q "^$B_ADDR$(printf '\t')getSignaturesForAddress page 0: the run was interrupted (TERM); older history not collected$" "$TT/int-page/collection-gaps.tsv" \
   && grep -q "^SigA1$(printf '\t')not fetched: the run was interrupted (TERM); this and 2 older signatures in signatures.jsonl were not fetched$" "$TT/int-page/collection-gaps.tsv" \
   && grep -q '^collection gaps: 2 (see ' "$TT/int-page.out"; then
  ok "interrupted paging: a gap row for the address being paged, one for the signatures listed, and the closing lines"
else
  bad "interrupted paging: rows '$(tr '\n' '|' < "$TT/int-page/collection-gaps.tsv")', output '$(tr '\n' '|' < "$TT/int-page.out")'"
fi
# INT during the fetch, as from a terminal: exit 130, the same row naming INT.
rm -f "$FAKE_CURL_LOG"
book '{"'"$A_ADDR"'": [{"signature": "S%02d" % k, "slot": 100 - k, "err": None, "blockTime": 1700000000 - k} for k in range(1, 6)]}'
hold_run "$TT/int-int" "getTransaction|2" INT -- "$A_ADDR"
code=$?
eq "interrupted fetch, INT: exit 130, and the row for the signatures not fetched" \
  "$code|$(cut -f2 "$TT/int-int/collection-gaps.tsv")" "130|not fetched: the run was interrupted (INT); this and 3 older signatures in signatures.jsonl were not fetched"
# HUP while the second page of an address is read: exit 129, and the address row
# names the signature to resume from with --before.
rm -f "$FAKE_CURL_LOG"
hold_run "$TT/int-hup" "getSignaturesForAddress|2" HUP -- "$A_ADDR"
code=$?
eq "interrupted paging, HUP on a later page: exit 129, the address row with its resume point, and the closing lines" \
  "$code|$(sed -n 1p "$TT/int-hup/collection-gaps.tsv")|$(grep -c '^collection gaps: 2 (see ' "$TT/int-hup.out")" \
  "129|$A_ADDR$(printf '\t')getSignaturesForAddress page 1: the run was interrupted (HUP); older history not collected; resume into a new --out with --before S05|1"
book '{"'"$A_ADDR"'": [{"signature": "SigA%d" % k, "slot": 30 - k, "err": None, "blockTime": 1700000030 - k} for k in range(1, 4)],
       "'"$B_ADDR"'": [{"signature": "SigB%d" % k, "slot": 20 - k, "err": None, "blockTime": 1700000020 - k} for k in range(1, 4)]}'
# The same paging run with its stdout through a pipe that is closed when the run is
# stopped: TERM goes to the whole process group, as for `collect.sh … | tee log`, so
# the reader dies too. Every gap row still lands before any output, and the run
# exits 143, whether SIGPIPE was ignored when it started or at its default.
# grouprun <out dir> <method>|<k> ignore|default <args...>: run collect.sh piped into
# cat, in a process group of its own, and send TERM to the group while the stand-in
# holds call k of <method>. collect.sh's exit status is written to <out dir>.status.
grouprun() {
  local out="$1" hold="$2" pipe="$3" n=0 pg
  shift 3
  mkdir -p "$TT/hold"; rm -f "$TT/hold/reached" "$TT/hold/release" "$TT/pg"
  FAKE_HOLD="$hold|$TT/hold" PATH="$TT/bin:$PATH" "$PY" -c 'import os, signal, sys
if sys.argv[2] == "default":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
os.setsid()
open(sys.argv[1], "w").write(str(os.getpid()))
os.execvp("bash", ["bash", "-c", sys.argv[3]] + sys.argv[4:])' "$TT/pg" "$pipe" \
    'trap : TERM; ( trap : TERM; bash "$1" --out "$2" --confirmed "${@:3}" 2> "$2.err"; echo "$?" > "$2.status" ) | cat > "$2.out"' \
    _ "$DNR/collect.sh" "$out" "$@" &
  while [[ ! -e "$TT/hold/reached" && "$n" -lt 200 ]]; do sleep 0.05; n=$((n + 1)); done
  pg="$(cat "$TT/pg")"
  kill -TERM -- "-$pg"
  touch "$TT/hold/release"
  wait
  n=0; while [[ ! -s "$out.status" && "$n" -lt 200 ]]; do sleep 0.05; n=$((n + 1)); done
}
for pipe in ignore default; do
  rm -f "$FAKE_CURL_LOG"
  grouprun "$TT/int-pipe-$pipe" "getSignaturesForAddress|3" "$pipe" -- "$A_ADDR" "$B_ADDR"
  eq "interrupted paging, stdout closed (SIGPIPE $pipe): exit 143, the address row and the row for the signatures listed" \
    "$(cat "$TT/int-pipe-$pipe.status" 2>/dev/null)|$(cut -f1 "$TT/int-pipe-$pipe/collection-gaps.tsv" | tr '\n' ' ')" "143|$B_ADDR SigA1 "
done

# A run whose stdout is a pipe no one reads any more (the reader exited before the
# run began): every message fails, and the collection still completes with a whole
# corpus, whether SIGPIPE was ignored when it started or at its default.
book '{"'"$A_ADDR"'": [{"signature": "S%02d" % k, "slot": 100 - k, "err": None, "blockTime": 1700000000 - k} for k in range(1, 6)]}'
for pipe in ignore default; do
  out="$TT/closed-$pipe"; rm -f "$TT/closed-reader"
  { n=0; while [[ ! -e "$TT/closed-reader" && "$n" -lt 200 ]]; do sleep 0.05; n=$((n + 1)); done; sleep 0.2
    PATH="$TT/bin:$PATH" "$PY" -c 'import os, signal, sys
signal.signal(signal.SIGPIPE, signal.SIG_IGN if sys.argv[1] == "ignore" else signal.SIG_DFL)
os.execvp("bash", ["bash"] + sys.argv[2:])' "$pipe" "$DNR/collect.sh" --out "$out" --confirmed -- "$A_ADDR" 2> "$out.err"
    echo "$?" > "$out.status"; } | { exec 0<&-; touch "$TT/closed-reader"; }
  eq "closed stdout (SIGPIPE $pipe): the run completes, every signature listed and fetched, no gap row" \
    "$(cat "$out.status")|$(grep -c '"queried_address"' "$out/signatures.jsonl")|$(jq -r '.transaction.signatures[0]' "$out/transactions.jsonl" | tr '\n' ' ')|$(grep -c . "$out/collection-gaps.tsv")" \
    "0|5|S01 S02 S03 S04 S05 |0"
done

if [[ "$fails" -ne 0 ]]; then
  echo "test-dnr-collect: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr-collect: all assertions passed"
