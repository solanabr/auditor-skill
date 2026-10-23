#!/usr/bin/env bash
# test-dnr.sh — self-test for the detection & response recipes (scripts/dnr/).
#
# Runnable from the repo root with bash >= 3.2, using only jq / python3 / awk / sed.
# No network. Exits non-zero on the first failed assertion. CI (corpus-check.yml)
# runs every scripts/tests/*.sh.
#
# Each assertion pins a documented property against the committed adversarial
# fixtures, so "validated" claims in the docs point at a real check.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DNR="$HERE/../dnr"
FIX="$DNR/fixtures"
fails=0
ok()   { printf 'ok   %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1" >&2; fails=$((fails+1)); }
eq()   { if [[ "$2" == "$3" ]]; then ok "$1 ($2)"; else bad "$1: expected '$3', got '$2'"; fi; }

for tool in jq python3 awk sed; do
  command -v "$tool" >/dev/null 2>&1 || { echo "test-dnr: missing required tool: $tool" >&2; exit 3; }
done
# collect.sh takes only base58 addresses and signatures (32-44 / 32-88 characters).
A_ADDR="AddrA111111111111111111111111111111111111111"
B_ADDR="AddrB111111111111111111111111111111111111111"
CURSOR="SigStart111111111111111111111111111111111111111111111111111111111111111111111111111"

# ---------------------------------------------------------------------------
# 1. frames.py attributes program logs by frame and never splits on an embedded
#    newline. The newline-injection fixture carries a forged "invoke [1]" inside
#    a Program log: payload.
# ---------------------------------------------------------------------------
logs="$(python3 -I "$DNR/frames.py" "$FIX/log-newline-injection.jsonl")"
n_log="$(printf '%s\n' "$logs" | jq -c 'select(.kind=="log")' | grep -c . || true)"
eq "frames: exactly the 2 real Program-log lines survive" "$n_log" "2"
n_forged="$(printf '%s\n' "$logs" | jq -rc 'select(.program|test("Fake"))' | grep -c . || true)"
eq "frames: zero frames attributed to the forged (injected) program id" "$n_forged" "0"
# All surviving log frames belong to the one real invoker.
n_vote="$(printf '%s\n' "$logs" | jq -rc 'select(.kind=="log" and .program=="Vote111111111111111111111111111111111111111")' | grep -c . || true)"
eq "frames: both real logs attributed to the real invoker frame" "$n_vote" "2"
# Demonstrate the hazard the design avoids: a naive flatten over-counts invokes.
naive="$(jq -r '.meta.logMessages[]' "$FIX/log-newline-injection.jsonl" | grep -cE 'invoke \[1\]$' || true)"
eq "frames: naive flatten would forge an extra invoke (hazard present in fixture)" "$naive" "2"

# ---------------------------------------------------------------------------
# 2. deltas.py tokens is exact above 2^53, where jq doubles are not.
# ---------------------------------------------------------------------------
tok="$(python3 -I "$DNR/deltas.py" tokens "$FIX/token-amount-over-2-53.jsonl")"
d1="$(printf '%s\n' "$tok" | awk -F'\t' '$2 ~ /^OwnerOne/ {print $4}')"
d2="$(printf '%s\n' "$tok" | awk -F'\t' '$2 ~ /^OwnerTwo/ {print $4}')"
eq "deltas tokens: true delta 1 preserved (jq doubles drop it to 0)" "$d1" "1"
eq "deltas tokens: true delta 1 preserved (jq doubles inflate it to 2)" "$d2" "1"
# Confirm the fixture really breaks jq doubles, so the claim is grounded.
jq_bad="$(jq -r '
  (.meta.preTokenBalances | map({(.owner): (.uiTokenAmount.amount|tonumber)}) | add) as $pre
  | .meta.postTokenBalances[] | "\(.owner)=\(((.uiTokenAmount.amount|tonumber)) - ($pre[.owner]))"' \
  "$FIX/token-amount-over-2-53.jsonl" | tr '\n' ' ')"
case "$jq_bad" in
  *"OwnerOne"*"=0"*|*"=0 "*OwnerOne*) ok "deltas tokens: jq-double path is wrong on this fixture ($jq_bad)" ;;
  *) [[ "$jq_bad" == *"=1"*"=1"* ]] && bad "deltas tokens: fixture no longer exercises the jq hazard ($jq_bad)" || ok "deltas tokens: jq-double path differs from exact ($jq_bad)" ;;
esac

# ---------------------------------------------------------------------------
# 3. deltas.py skips failed transactions (atomic revert, FP-4).
# ---------------------------------------------------------------------------
lam="$(python3 -I "$DNR/deltas.py" lamports "$FIX/clean-mixed.jsonl")"
n_failrows="$(printf '%s\n' "$lam" | grep -c 'SigCleanFail' || true)"
eq "deltas lamports: no rows from the failed tx" "$n_failrows" "0"
n_okrows="$(printf '%s\n' "$lam" | grep -c 'SigCleanOkV0' || true)"
eq "deltas lamports: movement rows from the successful tx present" "$n_okrows" "2"

# ---------------------------------------------------------------------------
# 4. profile.sh baselines without touching logMessages.
# ---------------------------------------------------------------------------
prof="$(bash "$DNR/profile.sh" "$FIX/clean-mixed.jsonl")"
v1="$(printf '%s\n' "$prof" | awk '/^-- version/{f=1;next} /^--/{f=0} f && $2=="1"{print $1}')"
eq "profile: v1 transaction counted in the version histogram" "$v1" "1"

# ---------------------------------------------------------------------------
# 5. redact.sh strips keys wherever a provider puts them — query, path, userinfo,
#    subdomain, and curl's own error and verbose lines — and keeps the text around
#    the URL intact (a closing paren or quote is not eaten).
# ---------------------------------------------------------------------------
red() { printf '%s\n' "$1" | bash "$DNR/redact.sh"; }
r1="$(red 'error: failed POST https://rpc.example.com/?api-key=SECRET123456 after 1 try')"
case "$r1" in *SECRET123456*) bad "redact: query api-key leaked ($r1)" ;; *REDACTED*) ok "redact: query-string key removed" ;; *) bad "redact: unexpected ($r1)" ;; esac
r2="$(red 'see (https://solana-mainnet.g.alchemy.com/v2/ALCHEMYKEY123) now')"
eq "redact: path-segment key (/v2/<key>) removed, closing paren kept" "$r2" "see (https://REDACTED.alchemy.com/REDACTED) now"
r3="$(red 'url https://rpc.ankr.com/solana/ANKRKEY456 timed out')"
eq "redact: second-segment key (/solana/<key>) removed" "$r3" "url https://REDACTED.ankr.com/REDACTED timed out"
r4="$(red 'auth https://user:PASSW0RD@host.example.com/rpc failed')"
eq "redact: userinfo key removed" "$r4" "auth https://REDACTED@REDACTED.example.com/REDACTED failed"
r5="$(red 'header api-key=BAREKEY99&x=1 rejected')"
eq "redact: bare api-key=value removed" "$r5" "header api-key=REDACTED&x=1 rejected"
r6="$(red 'plain text, no url')"
eq "redact: text without a URL is unchanged" "$r6" "plain text, no url"
r7="$(red 'HTTPS://user:SECRETPW@Host.Example.com/v2/KEYUP done')"
eq "redact: upper-case scheme, userinfo and path key removed" "$r7" "HTTPS://REDACTED@REDACTED.Example.com/REDACTED done"
r8="$(red 'wss://rpc.example.com/ws?api-key=WSKEY1 closed')"
eq "redact: a websocket URL is redacted like https" "$r8" "wss://REDACTED.example.com/REDACTED closed"
r9="$(red 'Api-Key=UPPERKEY9 and ACCESS_TOKEN=T0K3N&x=1')"
eq "redact: key names in any letter case" "$r9" "Api-Key=REDACTED and ACCESS_TOKEN=REDACTED&x=1"
eq "redact: an invalid UTF-8 byte under a UTF-8 locale does not stop the filter" \
  "$(printf 'bad \377 byte https://rpc.example.com/?api-key=K1 end\n' | LC_ALL=C.UTF-8 bash "$DNR/redact.sh" | LC_ALL=C tr -d '\377')" \
  "bad  byte https://REDACTED.example.com/REDACTED end"
eq "redact: a subdomain token keeps only the last two labels" \
  "$(red 'via https://TOKSUB42.rpc.example.test then https://TOKSUB42.rpc.example.test/v2/K')" \
  "via https://REDACTED.example.test then https://REDACTED.example.test/REDACTED"
eq "redact: an IP address and a two-label host are kept" \
  "$(red 'http://127.0.0.1:8899/v2/K and https://example.test/v2/K')" "http://127.0.0.1:8899/REDACTED and https://example.test/REDACTED"
eq "redact: curl verbose request line loses its path" "$(red '> POST /v2/LEAKME42 HTTP/2')" "> POST /REDACTED HTTP/2"
eq "redact: curl verbose Host header keeps the last two labels" "$(red '> Host: TOKSUB42.rpc.example.test')" "> Host: REDACTED.example.test"
eq "redact: curl HTTP/2 :path header loses its path" "$(red '* [HTTP/2] [1] [:path: /v2/LEAKME42]')" "* [HTTP/2] [1] [:path: /REDACTED]"
eq "redact: curl error naming a bare host keeps the last two labels" \
  "$(red 'curl: (6) Could not resolve host: TOKSUB42.rpc.example.test')" "curl: (6) Could not resolve host: REDACTED.example.test"
eq "redact: dotted names in other text are left alone" "$(red 'curl 8.7.1 calls os.path.join')" "curl 8.7.1 calls os.path.join"
# The documented recipe keeps the filtered command's failure: `set -o pipefail;`
# starts the line. Without it the filter's own 0 is the status (the control).
for sh in bash zsh; do
  command -v "$sh" >/dev/null 2>&1 || continue
  "$sh" -c '(exit 7) 2>&1 | bash "$1"' _ "$DNR/redact.sh" >/dev/null 2>&1
  eq "redact: control, $sh without pipefail loses the failure" "$?" "0"
  "$sh" -c 'set -o pipefail; (exit 7) 2>&1 | bash "$1"' _ "$DNR/redact.sh" >/dev/null 2>&1
  eq "redact: $sh 'set -o pipefail; <cmd> 2>&1 | redact.sh' keeps the failure" "$?" "7"
done
# The documented capture-to-a-file line, run as written (some-cmd stands in for a
# command that prints a key and fails), in a shell with noclobber set: it writes with
# 2>|, so it redacts and keeps the status. The control with a plain 2> fails before
# the command runs.
form="$(awk '/^#     err="\$\(mktemp/ { sub(/^#     /, ""); print }' "$DNR/redact.sh")"
case "$form" in *'some-cmd 2>|"$err"'*) ok "redact: the documented capture line writes with 2>|" ;; *) bad "redact: capture line not found or not 2>| ($form)" ;; esac
for sh in bash zsh; do
  command -v "$sh" >/dev/null 2>&1 || continue
  case "$sh" in bash) nc='set -C' ;; *) nc='setopt noclobber' ;; esac
  for variant in '2>|' '2>'; do
    line="${form//some-cmd 2>|/some_cmd $variant}"
    got="$(CLAUDE_PLUGIN_ROOT="$HERE/../.." "$sh" -c "$nc; some_cmd() { echo 'via https://rpc.example.test/?api-key=NOCLOBKEY42' >&2; return 7; }; $line" 2>&1)"
    code=$?
    if [[ "$variant" == '2>|' ]]; then
      if [[ "$code" == 7 && "$got" == *REDACTED* && "$got" != *NOCLOBKEY42* ]]; then
        ok "redact: $sh with noclobber, the documented capture line redacts and keeps the status (7)"
      else
        bad "redact: $sh with noclobber, capture line -> exit $code ($got)"
      fi
    elif [[ "$code" != 7 ]]; then
      ok "redact: control, $sh with noclobber and a plain 2> fails before the command runs (exit $code)"
    else
      bad "redact: control, $sh with noclobber accepted a plain 2> ($got)"
    fi
  done
done

# ---------------------------------------------------------------------------
# 6. collect.sh is gated: it refuses without --confirmed, and without $RPC_URL,
#    before any network call. The --confirmed case runs with $RPC_URL set and a
#    curl on PATH that records every call, so only the gate can stop it.
# ---------------------------------------------------------------------------
GATE="$(mktemp -d "${TMPDIR:-/tmp}/dnr_gate.XXXXXX")"
printf '#!/bin/sh\necho "$*" >> "%s/calls"\n' "$GATE" > "$GATE/curl"; chmod +x "$GATE/curl"
( PATH="$GATE:$PATH" RPC_URL="https://rpc.example.test/" bash "$DNR/collect.sh" --out "$GATE/out" -- "$A_ADDR" ) >/dev/null 2>&1
code=$?
if [[ "$code" == 2 && ! -e "$GATE/calls" && ! -e "$GATE/out" ]]; then
  ok "collect: refuses without --confirmed, \$RPC_URL set (exit 2, no curl call, nothing written)"
else
  bad "collect: without --confirmed -> exit $code, curl calls: $(grep -c . "$GATE/calls" 2>/dev/null || echo 0)"
fi
rm -rf "$GATE"
if ( unset RPC_URL; bash "$DNR/collect.sh" --out "${TMPDIR:-/tmp}/dnr_ct.$$" --confirmed -- "$A_ADDR" ) >/dev/null 2>&1; then
  bad "collect: ran without \$RPC_URL (must refuse)"
else
  ok "collect: refuses without \$RPC_URL"
fi

# ---------------------------------------------------------------------------
# 7. deltas.py keys token movement by token account and mint, with the owner as a
#    label: an owner's net is the sum of its rows (Python ints), and two accounts
#    never share a bucket, even with no owner. Lamport math stays exact above 2^53.
# ---------------------------------------------------------------------------
owner_sum() {  # owner_sum <owner> < deltas tokens output: that owner's net, in Python ints
  python3 -I -c 'import sys
print(sum(int(r.split("\t")[3]) for r in sys.stdin if r.split("\t")[1] == sys.argv[1]))' "$1"
}
mvrows="$(python3 -I "$DNR/deltas.py" tokens "$FIX/same-owner-move.jsonl")"
eq "deltas tokens: an internal move shows both legs (two token accounts)" \
  "$(printf '%s\n' "$mvrows" | awk -F'\t' '{printf "%s:%s ", $5, $4}')" "TA1:-100 TA2:100 "
eq "deltas tokens: ... and nets to zero for the owner" "$(printf '%s\n' "$mvrows" | owner_sum VaultPDA)" "0"
dr="$(python3 -I "$DNR/deltas.py" tokens "$FIX/same-owner-drain.jsonl")"
eq "deltas tokens: a two-account drain sums to -140 for the owner" "$(printf '%s\n' "$dr" | owner_sum VaultPDA)" "-140"
eq "deltas tokens: attacker receives +140" "$(printf '%s\n' "$dr" | owner_sum Attacker)" "140"
nrows="$(python3 -I -c 'import json
bal = lambda i, a: {"accountIndex": i, "mint": "MintNoOwner", "uiTokenAmount": {"amount": str(a)}}
print(json.dumps({"meta": {"err": None, "preTokenBalances": [bal(1, 100), bal(2, 0)],
    "postTokenBalances": [bal(1, 60), bal(2, 40)]},
    "transaction": {"signatures": ["SigNoOwner"], "message": {"accountKeys": [
        {"pubkey": "Payer"}, {"pubkey": "TokAcctA"}, {"pubkey": "TokAcctB"}]}}}))' \
  | python3 -I "$DNR/deltas.py" tokens)"
eq "deltas tokens: two owner-less accounts that transfer to each other show both legs" \
  "$(printf '%s\n' "$nrows" | awk -F'\t' '{printf "%s %s %s; ", $2, $5, $4}')" "? TokAcctA -40; ? TokAcctB 40; "
# A balance whose index has no account key is keyed, and printed, as #<index>, as in
# lamports; one with no accountIndex is a row of its own, #?. A note counts each kind,
# and a transfer between two such accounts never nets to zero, with an owner or none.
krows="$(python3 -I -c 'import json
def bal(i, a, owner=None):
    b = {"mint": "MintK", "uiTokenAmount": {"amount": str(a)}}
    if i is not None:
        b["accountIndex"] = i
    if owner:
        b["owner"] = owner
    return b
def tx(sig, pre, post):
    print(json.dumps({"meta": {"err": None, "preTokenBalances": pre, "postTokenBalances": post},
        "transaction": {"signatures": [sig], "message": {"accountKeys": [{"pubkey": "Payer"}]}}}))
tx("SigKeyless", [bal(1, 100), bal(2, 0)], [bal(1, 60), bal(2, 40)])
tx("SigKeylessVault", [bal(1, 100, "VaultPDA"), bal(2, 0, "VaultPDA")], [bal(1, 60, "VaultPDA"), bal(2, 40, "VaultPDA")])
tx("SigNoIndex", [bal(None, 100), bal(None, 0)], [bal(None, 60), bal(None, 40)])' \
  | python3 -I "$DNR/deltas.py" tokens 2>&1)"
eq "deltas tokens: balances whose index has no account key are rows #<index>, never merged, owner or none" \
  "$(printf '%s\n' "$krows" | awk -F'\t' '$1 ~ /^SigKeyless/ {printf "%s %s %s %s; ", $1, $2, $5, $4}')" \
  "SigKeyless ? #1 -40; SigKeyless ? #2 40; SigKeylessVault VaultPDA #1 -40; SigKeylessVault VaultPDA #2 40; "
eq "deltas tokens: balances with no accountIndex are rows of their own, #?, pre negative and post positive" \
  "$(printf '%s\n' "$krows" | awk -F'\t' '$1 == "SigNoIndex" {printf "%s %s; ", $5, $4}')" "#? -100; #? 60; #? 40; "
eq "deltas tokens: a note on stderr counts each kind of row" \
  "$(printf '%s\n' "$krows" | grep -c '^deltas.py: 4 row(s) name a balance index that has no account key, as #<index>: ')|$(printf '%s\n' "$krows" | grep -c '^deltas.py: 3 row(s) name a token balance that has no accountIndex, as #?: ')" "1|1"
bl="$(python3 -I "$DNR/deltas.py" lamports "$FIX/lamports-over-2-53.jsonl")"
eq "deltas lamports: +1 above 2^53 is exact (BigOne)" "$(printf '%s\n' "$bl" | awk -F'\t' '$2=="BigOne"{print $3}')" "1"
eq "deltas lamports: +1 above 2^53 is exact (BigTwo)" "$(printf '%s\n' "$bl" | awk -F'\t' '$2=="BigTwo"{print $3}')" "1"

# ---------------------------------------------------------------------------
# 8. frames.py: a tab-separated forged record plus a newline-forged invoke inside
#    Program log payloads yields valid JSONL, attributed to the real invoker only.
# ---------------------------------------------------------------------------
tabrows="$(python3 -I "$DNR/frames.py" "$FIX/log-tab-injection.jsonl")"
eq "frames: tab/newline payloads stay 2 records" "$(printf '%s\n' "$tabrows" | grep -c . || true)" "2"
bad_json="$(printf '%s\n' "$tabrows" | python3 -I -c 'import sys,json
n=0
for l in sys.stdin:
    try: json.loads(l)
    except Exception: n+=1
print(n)')"
eq "frames: every output line is valid JSON" "$bad_json" "0"
eq "frames: nothing attributed to the forged victim program" \
  "$(printf '%s\n' "$tabrows" | jq -rc 'select(.program|test("Vict1m"))' | grep -c . || true)" "0"

# ---------------------------------------------------------------------------
# 9. profile.sh resolves programIdIndex (encoding: json) as well as programId.
# ---------------------------------------------------------------------------
TT="$(mktemp -d "${TMPDIR:-/tmp}/dnr_test.XXXXXX")"
trap 'rm -rf "$TT"' EXIT
printf '%s\n' '{"slot":1,"version":0,"meta":{"err":null},"transaction":{"signatures":["S"],"message":{"accountKeys":["Payer1","ProgIdx111"],"instructions":[{"programIdIndex":1}]}}}' > "$TT/json-enc.jsonl"
pidx="$(bash "$DNR/profile.sh" "$TT/json-enc.jsonl" | awk '/^-- top-level programs/{f=1;next} f && $2=="ProgIdx111"{print $1}')"
eq "profile: programIdIndex resolved through accountKeys" "$pidx" "1"

# ---------------------------------------------------------------------------
# 10. collect.sh end to end against a fake `curl` (no network): runs under the
#     system bash, keeps FAILED transactions, takes a short page on the cap's last
#     page as the end of history, passes --before through, and never prints the key.
# ---------------------------------------------------------------------------
mkdir -p "$TT/bin"
cat > "$TT/bin/curl" <<'PY'
#!/usr/bin/env python3
import json, os, re, sys
args = sys.argv[1:]
with open(os.environ["FAKE_CURL_ARGV"], "a") as log:
    log.write(json.dumps(args) + "\n")
url = ""
if args[args.index("-K") + 1] == "-":
    for line in sys.stdin:
        m = re.match(r'\s*url\s*=\s*"(.*)"\s*$', line)
        url = m.group(1) if m else url
if not url:
    sys.stderr.write("curl: no URL specified\n"); sys.exit(2)
body = args[args.index("--data-raw") + 1]
sys.stderr.write(f"curl: note: talking to {url}\n")
req = json.loads(body)
with open(os.environ["FAKE_CURL_LOG"], "a") as log:
    log.write(json.dumps(req) + "\n")
m, p = req["method"], req["params"]
# FAKE_CURL_TX_FAIL=<sig>=transport|rpc|null fails that one getTransaction;
# FAKE_CURL_PAGE_FAIL=1 fails every getSignaturesForAddress with an RPC error.
fail_sig, _, fail_mode = os.environ.get("FAKE_CURL_TX_FAIL", "").partition("=")
if m == "getTransaction" and p[0] == fail_sig and fail_mode == "transport":
    sys.stderr.write(f"curl: (7) Failed to connect to {url.split('/')[2]} port 443 after 2 ms: Couldn't connect to server\n")
    sys.exit(7)
if m == "getTransaction" and p[0] == fail_sig and fail_mode in ("rpc", "null"):
    out = {"error": {"code": -32009, "message": "Transaction version (1) is not supported"}} if fail_mode == "rpc" else {"result": None}
    print(json.dumps(dict({"jsonrpc": "2.0", "id": 1}, **out))); sys.exit(0)
if m == "getSignaturesForAddress" and os.environ.get("FAKE_CURL_PAGE_FAIL"):
    print(json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "Node is behind"}})); sys.exit(0)
if m == "getSignaturesForAddress" and p[0].startswith("AddrB"):
    res = [
        {"signature": "SigZnewest", "slot": 9, "err": None, "blockTime": 1700000900},
        {"signature": "SigAoldest", "slot": 0, "err": None, "blockTime": 1700000100},
    ]
    print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": res}))
elif m == "getSignaturesForAddress":
    res = [] if "before" in p[1] and p[1]["before"] == "SigFail" else [
        {"signature": "SigOK", "slot": 2, "err": None, "blockTime": 1700000500},
        {"signature": "SigFail", "slot": 1, "err": {"InstructionError": [0, {"Custom": 1}]}, "blockTime": 1700000400},
    ]
    print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": res}))
elif m == "getTransaction":
    sig = p[0]
    err = None if sig == "SigOK" else {"InstructionError": [0, {"Custom": 1}]}
    print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"slot": 1, "meta": {"err": err}, "transaction": {"signatures": [sig]}}}))
else:
    print(json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nope"}}))
PY
chmod +x "$TT/bin/curl"
export FAKE_CURL_LOG="$TT/curl.log" FAKE_CURL_ARGV="$TT/curl.argv"
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/?api-key=LEAKME42" \
    bash "$DNR/collect.sh" --out "$TT/c" --confirmed --since 1 --max-pages 1 --before "$CURSOR" -- "$A_ADDR" ) > "$TT/c.out" 2>&1
code=$?
eq "collect: exits 0 against the fake RPC (system bash)" "$code" "0"
eq "collect: fetched both the successful AND the failed transaction" \
  "$(grep -c . "$TT/c/transactions.jsonl" 2>/dev/null || true)" "2"
eq "collect: a short last page at the page cap is the end of history (no notice, no gap row)" \
  "$(grep -c '^  ! ' "$TT/c.out")/$(grep -c . "$TT/c/collection-gaps.tsv")" "0/0"
if grep -q "\"before\": \"$CURSOR\"" "$FAKE_CURL_LOG"; then ok "collect: --before passed through to the first page"; else bad "collect: --before not passed through"; fi
if grep -q 'LEAKME42' "$TT/c.out" "$TT/c/signatures.jsonl" "$TT/c/transactions.jsonl"; then
  bad "collect: the key leaked into output"
else
  ok "collect: key absent from stdout/stderr and corpus files"
fi
if grep -q 'provider: example.test ' "$TT/c.out"; then ok "collect: provider disclosed as its last two DNS labels"; else bad "collect: provider line wrong"; fi
if grep -q LEAKME42 "$FAKE_CURL_ARGV"; then bad "collect: the key reached curl's argv"; else ok "collect: the key never reaches curl's argv (URL via -K - on stdin)"; fi
eq "collect: every curl call starts with -q (no ~/.curlrc)" "$(grep -vc '^\["-q", "-K", "-",' "$FAKE_CURL_ARGV")" "0"
( PATH="$TT/bin:$PATH" RPC_URL="https://TOKSUB42.rpc.example.test/v2/LEAKME42" \
    bash "$DNR/collect.sh" --out "$TT/c-sub" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/c-sub.out" 2>&1
if grep -q 'provider: example.test ' "$TT/c-sub.out" && ! grep -q 'TOKSUB42\|LEAKME42' "$TT/c-sub.out"; then
  ok "collect: a subdomain token never reaches the output"
else
  bad "collect: subdomain token or key in the output ($(grep -m1 'TOKSUB42\|LEAKME42\|provider' "$TT/c-sub.out"))"
fi
# Collection gaps: every getTransaction that fails (transport error, RPC error,
# null result), a failed signature page, a page cap on a full page and the --max-tx cap
# each become a <subject>TAB<reason> row of collection-gaps.tsv, and the run says how
# many. curl's own exit status reaches the row.
eq "collect: a clean run reports no collection gaps" \
  "$(grep -c '^collection gaps: 0 (see .*collection-gaps.tsv)$' "$TT/c-sub.out")/$(grep -c . "$TT/c-sub/collection-gaps.tsv")" "1/0"
for mode in "transport:transport error (curl exit 7)" "rpc:RPC error -32009" "null:null result"; do
  ( PATH="$TT/bin:$PATH" FAKE_CURL_TX_FAIL="SigOK=${mode%%:*}" RPC_URL="https://TOKSUB42.rpc.example.test/v2/LEAKME42" \
      bash "$DNR/collect.sh" --out "$TT/g-${mode%%:*}" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/g.out" 2>&1
  code=$?
  row="$(cat "$TT/g-${mode%%:*}/collection-gaps.tsv" 2>/dev/null)"
  if [[ "$code" == 0 && "$row" == "SigOK$(printf '\t')getTransaction: ${mode#*:}" ]] \
     && grep -q '^collection gaps: 1 (see .*collection-gaps.tsv)$' "$TT/g.out" \
     && [[ "$(grep -c . "$TT/g-${mode%%:*}/transactions.jsonl")" == 1 ]]; then
    ok "collect: a failed getTransaction (${mode%%:*}) is a gap row with its reason; the rest is still fetched"
  else
    bad "collect: failed getTransaction (${mode%%:*}) -> exit $code, row '$row'"
  fi
done
if grep -q 'TOKSUB42\|LEAKME42' "$TT/g.out"; then bad "collect: curl's error leaked the endpoint"; else ok "collect: curl's own error is redacted (no subdomain token, no key)"; fi
( PATH="$TT/bin:$PATH" FAKE_CURL_PAGE_FAIL=1 RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/g-page" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/g.out" 2>&1
eq "collect: a failed signature page is a gap row" "$(cat "$TT/g-page/collection-gaps.tsv")" \
  "$A_ADDR$(printf '\t')getSignaturesForAddress page 0: RPC error -32005; older history not collected"
calls_before="$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)"
for url in 'a space:https://rpc.example.test/?k=a b' 'a quote:https://rpc.example.test/"x' 'a backslash:https://rpc.example.test/\x'; do
  ( PATH="$TT/bin:$PATH" RPC_URL="${url#*:}" bash "$DNR/collect.sh" --out "$TT/c-bad" --confirmed -- "$A_ADDR" ) > /dev/null 2>&1
  code=$?
  if [[ "$code" == 2 && ! -e "$TT/c-bad" ]]; then ok "collect: refuses an \$RPC_URL holding ${url%%:*} (exit 2)"; else bad "collect: \$RPC_URL holding ${url%%:*} -> exit $code"; fi
done
eq "collect: a refused \$RPC_URL made no RPC call" "$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)" "$calls_before"
# --max-tx keeps the newest signatures across addresses (by slot), not the first
# address's or the alphabetically first ones.
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/c2" --confirmed --max-pages 1 --max-tx 2 -- "$A_ADDR" "$B_ADDR" ) > "$TT/c2.out" 2>&1
got="$(jq -r '.transaction.signatures[0]' "$TT/c2/transactions.jsonl" 2>/dev/null | tr '\n' ' ')"
eq "collect: --max-tx 2 fetches the two newest signatures across both addresses" "$got" "SigZnewest SigOK "
# With only --until set, a short page on the cap's last page still ends the history,
# so there is no notice and no gap row.
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/c3" --confirmed --until 100 --max-pages 1 -- "$A_ADDR" ) > "$TT/c3.out" 2>&1
eq "collect: --until only, a short last page at the cap is the end of history (no notice, no gap row)" \
  "$(grep -c '^  ! ' "$TT/c3.out")/$(grep -c . "$TT/c3/collection-gaps.tsv")" "0/0"
eq "collect: the --max-tx cap is one gap row naming the first signature not fetched" \
  "$(cut -f1 "$TT/c2/collection-gaps.tsv")|$(grep -c 'collection gaps: 1 ' "$TT/c2.out")" "SigFail|1"
# A second pass into an --out that already holds a corpus is refused, so the first
# pass survives.
cp "$TT/c/signatures.jsonl" "$TT/c.sig.before"
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/c" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/c4.out" 2>&1
code=$?
if [[ "$code" == 2 ]] && grep -q 'use a new --out' "$TT/c4.out" && cmp -s "$TT/c/signatures.jsonl" "$TT/c.sig.before"; then
  ok "collect: refuses to reuse an --out that holds a corpus (exit 2, corpus intact)"
else
  bad "collect: reuse of a filled --out -> exit $code"
fi
# Inputs are checked before any write or RPC call: an address that is not base58,
# a --before that is not a signature, a cap that is not a number.
calls_before="$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)"
for args in "-- AddrA" "-- ../../x" "--before not/a/sig -- $A_ADDR" "--max-tx 2x -- $A_ADDR"; do
  # shellcheck disable=SC2086
  ( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
      bash "$DNR/collect.sh" --out "$TT/c5" --confirmed $args ) > /dev/null 2>&1
  code=$?
  if [[ "$code" == 2 && ! -e "$TT/c5" ]]; then ok "collect: refuses '$args' (exit 2, nothing written)"; else bad "collect: '$args' -> exit $code"; fi
done
eq "collect: refused inputs made no RPC call" "$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)" "$calls_before"
# Rule 11d: an incident_<n>/ that the corpus lands in ignores itself; an existing
# .gitignore is left alone.
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/incident_7/corpus" --confirmed --max-pages 1 -- "$A_ADDR" ) > /dev/null 2>&1
eq "collect: incident_<n>/.gitignore holds '*'" "$(cat "$TT/incident_7/.gitignore" 2>/dev/null)" "*"
mkdir -p "$TT/incident_9"; printf 'keep-me\n' > "$TT/incident_9/.gitignore"
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/incident_9/corpus" --confirmed --max-pages 1 -- "$A_ADDR" ) > /dev/null 2>&1
eq "collect: an existing incident_<n>/.gitignore is not overwritten" "$(cat "$TT/incident_9/.gitignore")" "keep-me"

# ---------------------------------------------------------------------------
# 11. snapshot-program.sh against a fake `solana`: writes bin/<id>.so, prints the
#     ledger line (owner, last-deployed slot, zero-trimmed hash, padding), redacts a
#     CLI error, and reads a loader-v4 program through program-v4 show / download.
#     The CLI runs from a throwaway -C config: no URL in argv, a keypair path that
#     does not exist, a 0700 directory removed on exit, and a blocker if the CLI
#     ignores the config. Like solana-cli 3.1, the fake reads a config only when it
#     holds websocket_url, `program show` / `program-v4 show` need a signer unless
#     --buffer-authority / --authority is given, `program show` / `dump` reject a
#     loader-v4 program ("is not an SBF program"), and `program-v4` commands reject
#     anything else ("is not owned by loader-v4").
# ---------------------------------------------------------------------------
printf '#!/bin/sh\nexec python3 -I "$0.py" "$@"\n' > "$TT/bin/solana"
cat > "$TT/bin/solana.py" <<'PY'
import json, os, re, sys
a = sys.argv[1:]
with open(os.environ["FAKE_SOLANA_ARGV"], "a") as log:
    log.write(json.dumps(a) + "\n")
cfg = {}
if "-C" in a:
    i = a.index("-C")
    for line in open(a[i + 1]):
        m = re.match(r'(\w+): "(.*)"$', line.rstrip("\n"))
        if m:
            cfg[m.group(1)] = m.group(2)
    del a[i:i + 2]
if "websocket_url" not in cfg or os.environ.get("FAKE_SOLANA_IGNORE_CONFIG"):
    cfg = {"json_rpc_url": "https://api.mainnet-beta.solana.com", "keypair_path": "/home/fake/.config/solana/id.json"}
url, kp = cfg.get("json_rpc_url", ""), cfg.get("keypair_path", "")
if a[:3] == ["config", "get", "keypair"]:
    print(f"Key Path: {kp} "); sys.exit(0)
try:
    mode = oct(os.stat(os.path.dirname(kp)).st_mode & 0o777)
except OSError:
    mode = "none"
with open(os.environ["FAKE_SOLANA_SEEN"], "a") as log:
    log.write(f"{kp}\t{os.path.exists(kp)}\t{mode}\n")
if os.environ.get("FAKE_SOLANA_FAIL"):
    sys.stderr.write(f"Error: RPC request error: cluster version query failed: {url}\n"); sys.exit(1)
v4 = bool(os.environ.get("FAKE_SOLANA_V4"))
owner = "LoaderV411111111111111111111111111111111111" if v4 else "BPFLoaderUpgradeab1e11111111111111111111111"
if (a[:2] == ["program", "show"] and "--buffer-authority" not in a or a[:2] == ["program-v4", "show"] and "--authority" not in a) \
        and not os.path.exists(kp):
    sys.stderr.write(f'Error: Dynamic program error: No default signer found, run "solana-keygen new -o {kp}" to create a new one\n'); sys.exit(1)
pid = a[2] if a[0] == "program" else a[a.index("--program-id") + 1]
if a[:2] in (["program", "show"], ["program", "dump"]) and v4:
    sys.stderr.write(f"Error: {pid} is not an SBF program\n"); sys.exit(1)
if a[0] == "program-v4" and not v4:
    sys.stderr.write(f"Error: {pid} is not owned by loader-v4\n"); sys.exit(1)
if a[:2] == ["program", "show"]:
    print(f"\nProgram Id: {pid}\nOwner: {owner}\nProgramData Address: PdA111\nAuthority: Auth111\nLast Deployed In Slot: 12345\nData Length: 100 (0x64) bytes\nBalance: 1 SOL\n")
elif a[:2] == ["program-v4", "show"]:
    print(f"\nProgram Id: {pid}\nOwner: {owner}\nAuthority: Auth111\nLast Deployed In Slot: 12345\nStatus: deployed\nData Length: 100 (0x64) bytes\n")
elif a[:2] in (["program", "dump"], ["program-v4", "download"]):
    open(a[-1], "wb").write(b"\x7fELF" + bytes(range(1, 30)) + b"\x00" * 500)
    print(f"Wrote program to {a[-1]}")
else:
    sys.stderr.write("fake solana: refusing unexpected subcommand\n"); sys.exit(9)
PY
chmod +x "$TT/bin/solana"
export FAKE_SOLANA_ARGV="$TT/solana.argv" FAKE_SOLANA_SEEN="$TT/solana.seen"
PID="ProgTest11111111111111111111111111111111111"   # base58, decodes to 32 bytes
snap="$(PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/v2/LEAKME42" bash "$DNR/snapshot-program.sh" "$PID" "$TT/inc" 2>&1)"
code=$?
eq "snapshot: exits 0 with the fake CLI" "$code" "0"
want="$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\x00")).hexdigest())' "$TT/inc/bin/$PID.so" 2>/dev/null)"
case "$snap" in
  *"last_deployed_slot=12345"*"sha256_zero_trimmed=$want"*"padding_bytes=500"*) ok "snapshot: ledger line carries slot, zero-trimmed hash and padding" ;;
  *) bad "snapshot: unexpected ledger line ($snap)" ;;
esac
snapfail="$(PATH="$TT/bin:$PATH" FAKE_SOLANA_FAIL=1 RPC_URL="https://rpc.example.test/v2/LEAKME42" bash "$DNR/snapshot-program.sh" "$PID" "$TT/inc2" 2>&1)"
code=$?
eq "snapshot: CLI failure -> exit 3" "$code" "3"
case "$snapfail" in *LEAKME42*) bad "snapshot: key leaked from the CLI error" ;; *REDACTED*) ok "snapshot: CLI error redacted" ;; *) bad "snapshot: error text not shown ($snapfail)" ;; esac
if grep -q LEAKME42 "$FAKE_SOLANA_ARGV"; then bad "snapshot: the key reached the CLI's argv"; else ok "snapshot: the key never reaches the CLI's argv"; fi
eq "snapshot: every CLI call names a -C config and none passes --url" \
  "$(grep -c . "$FAKE_SOLANA_ARGV")/$(grep -c '"-C"' "$FAKE_SOLANA_ARGV")/$(grep -c '"--url"' "$FAKE_SOLANA_ARGV")" \
  "$(grep -c . "$FAKE_SOLANA_ARGV")/$(grep -c . "$FAKE_SOLANA_ARGV")/0"
eq "snapshot: the CLI is given a keypair path that does not exist, in a 0700 directory" \
  "$(awk -F'\t' '{print $2, $3}' "$FAKE_SOLANA_SEEN" | sort -u)" "False 0o700"
gone=1; while IFS="$(printf '\t')" read -r kp _ _; do [[ -e "$(dirname "$kp")" ]] && gone=0; done < "$FAKE_SOLANA_SEEN"
if [[ "$gone" == 1 ]]; then ok "snapshot: the temp config directory is removed on exit"; else bad "snapshot: a temp config directory was left behind"; fi
calls_before="$(grep -c '"program"' "$FAKE_SOLANA_ARGV")"
PATH="$TT/bin:$PATH" FAKE_SOLANA_IGNORE_CONFIG=1 RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" "$PID" "$TT/inc6" > "$TT/inc6.out" 2>&1
code=$?
if [[ "$code" == 3 && ! -e "$TT/inc6/bin" ]] && grep -q 'did not load the keyless config' "$TT/inc6.out"; then
  ok "snapshot: a CLI that ignores the config stops with a blocker before show or dump (exit 3)"
else
  bad "snapshot: CLI ignoring the config -> exit $code"
fi
eq "snapshot: no program call after the config check failed" "$(grep -c '"program"' "$FAKE_SOLANA_ARGV")" "$calls_before"
PATH="$TT/bin:$PATH" RPC_URL='https://rpc.example.test/"x' bash "$DNR/snapshot-program.sh" "$PID" "$TT/inc7" >/dev/null 2>&1
code=$?
if [[ "$code" == 2 && ! -e "$TT/inc7" ]]; then ok "snapshot: refuses an \$RPC_URL holding a quote (exit 2, nothing written)"; else bad "snapshot: quoted \$RPC_URL -> exit $code"; fi
v4snap="$(PATH="$TT/bin:$PATH" FAKE_SOLANA_V4=1 RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" "$PID" "$TT/inc3" 2>&1)"
code=$?
case "$code|$v4snap" in
  "0|program=$PID owner=LoaderV411111111111111111111111111111111111 last_deployed_slot=12345 authority=Auth111 status=deployed sha256_zero_trimmed="*" file=bin/$PID.so")
    ok "snapshot: a loader-v4 program is read with program-v4 show / download (exit 0)" ;;
  *) bad "snapshot: loader-v4 program -> exit $code ($v4snap)" ;;
esac
# The id is used in file names: anything but a base58 key is refused before any write.
for badid in '../../escape' 'Prog111' 'ProgTest111111111111111111111111111111111/x' 'Prog0OIl1111111111111111111111111111111111'; do
  PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" "$badid" "$TT/inc5" >/dev/null 2>&1
  code=$?
  if [[ "$code" == 2 && ! -e "$TT/inc5" ]]; then ok "snapshot: refuses the id '$badid' (exit 2, nothing written)"; else bad "snapshot: id '$badid' -> exit $code"; fi
done
# Rule 11d: snapshotting into incident_<n>/ makes it ignore itself; a directory with
# another name gets no .gitignore from the script.
PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" "$PID" "$TT/incident_8" >/dev/null 2>&1
eq "snapshot: incident_<n>/.gitignore holds '*'" "$(cat "$TT/incident_8/.gitignore" 2>/dev/null)" "*"
if [[ ! -e "$TT/inc/.gitignore" ]]; then ok "snapshot: no .gitignore written into a directory not named incident_*"; else bad "snapshot: wrote a .gitignore outside an incident_* directory"; fi

# ---------------------------------------------------------------------------
# 12. Bundled python runs isolated (`python3 -I`). A json.py / re.py / hashlib.py
#     that an audited repo ships in the working directory, or puts on PYTHONPATH,
#     must never load — not in frames.py / deltas.py, and not in the hash that
#     snapshot-program.sh computes with `python3 -I -`. The two controls show the
#     planted modules DO load once -I is left out, so the checks are not vacuous.
# ---------------------------------------------------------------------------
EVIL="$TT/evil"; MARK="$TT/shadow.marker"; mkdir -p "$EVIL"
for m in json re hashlib; do
  printf 'open(%s, "a").write("%s\\n")\n' "'$MARK'" "$m" > "$EVIL/$m.py"
done
( cd "$EVIL" && printf 'import json\n' | python3 - >/dev/null 2>&1 )
if grep -q json "$MARK" 2>/dev/null; then ok "isolation control: without -I, a json.py in the working directory replaces the stdlib (python3 -)"; else bad "isolation control: the planted json.py did not load, so the checks below prove nothing"; fi
rm -f "$MARK"
( cd "$EVIL" && PYTHONPATH="$EVIL" python3 "$DNR/deltas.py" tokens "$FIX/same-owner-drain.jsonl" >/dev/null 2>&1 )
if grep -q json "$MARK" 2>/dev/null; then ok "isolation control: without -I, PYTHONPATH loads a planted json.py even for a script file"; else bad "isolation control: PYTHONPATH did not load the planted json.py"; fi
rm -f "$MARK"
iso="$(cd "$EVIL" && PYTHONPATH="$EVIL" python3 -I "$DNR/frames.py" "$FIX/log-newline-injection.jsonl" 2>&1)"
if [[ "$iso" == "$logs" ]]; then ok "isolation: frames.py output unchanged from a hostile cwd + PYTHONPATH"; else bad "isolation: frames.py output changed under a hostile cwd + PYTHONPATH"; fi
iso="$(cd "$EVIL" && PYTHONPATH="$EVIL" python3 -I "$DNR/deltas.py" tokens "$FIX/same-owner-drain.jsonl" 2>&1)"
if [[ "$iso" == "$dr" ]]; then ok "isolation: deltas.py output unchanged from a hostile cwd + PYTHONPATH"; else bad "isolation: deltas.py output changed under a hostile cwd + PYTHONPATH"; fi
iso="$(cd "$EVIL" && PATH="$TT/bin:$PATH" PYTHONPATH="$EVIL" RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" "$PID" "$TT/inc4" 2>&1)"
case "$iso" in
  *"sha256_zero_trimmed=$want "*) ok "isolation: snapshot-program.sh hashes correctly from a hostile cwd + PYTHONPATH" ;;
  *) bad "isolation: snapshot hash wrong or missing ($iso)" ;;
esac
if [[ -e "$MARK" ]]; then bad "isolation: a planted module ran ($(tr '\n' ' ' < "$MARK"))"; else ok "isolation: no planted json.py / re.py / hashlib.py ran"; fi

# ---------------------------------------------------------------------------
# 13. profile.sh on a large corpus: 5,000 transactions with distinct fee payers,
#     signers and programs, so every top-20 list is well past the pipe buffer. It
#     must finish (exit 0) and print the last section, not die of SIGPIPE (141).
# ---------------------------------------------------------------------------
python3 -I -c 'import json, sys
for i in range(5000):
    payer = "Payer%039d" % i
    prog = "Prog%040d" % i
    print(json.dumps({"slot": i, "version": 0, "meta": {"err": None},
        "transaction": {"signatures": ["S%d" % i], "message": {
            "accountKeys": [{"pubkey": payer, "signer": True}, {"pubkey": prog, "signer": False}],
            "instructions": [{"programId": prog}]}}}))' > "$TT/big.jsonl"
bash "$DNR/profile.sh" "$TT/big.jsonl" > "$TT/big.out" 2>&1
eq "profile: a 5,000-payer corpus completes (no SIGPIPE exit)" "$?" "0"
eq "profile: the last section still prints its 20 rows" \
  "$(awk '/^-- top-level programs/{f=1;next} f' "$TT/big.out" | grep -c .)" "20"

# ---------------------------------------------------------------------------
# 14. deltas.py streams its corpus and checks every input before the first row:
#     a missing or unreadable later file exits 1 with no output, and a 20,000-
#     transaction corpus split over two files sums exactly.
# ---------------------------------------------------------------------------
for later in "a missing file:$TT/no-such-corpus.jsonl" "a directory:$TT"; do
  python3 -I "$DNR/deltas.py" tokens "$FIX/same-owner-drain.jsonl" "${later#*:}" > "$TT/d.out" 2> "$TT/d.err"
  code=$?
  if [[ "$code" == 1 && ! -s "$TT/d.out" ]] && grep -q 'cannot read' "$TT/d.err"; then
    ok "deltas: ${later%%:*} as a later input exits 1 before any row"
  else
    bad "deltas: ${later%%:*} as a later input -> exit $code, $(grep -c . "$TT/d.out") row(s)"
  fi
done
python3 -I -c 'import json, sys
amt = 2**60 + 1
for part, rng in ((sys.argv[1], range(0, 10000)), (sys.argv[2], range(10000, 20000))):
    with open(part, "w") as f:
        for i in rng:
            bal = lambda k, o, a: {"accountIndex": k, "owner": o, "mint": "MintBig", "uiTokenAmount": {"amount": str(a)}}
            f.write(json.dumps({"meta": {"err": None,
                "preTokenBalances": [bal(1, "Vault", 2**64 - 1), bal(2, "Attacker", 0)],
                "postTokenBalances": [bal(1, "Vault", 2**64 - 1 - amt), bal(2, "Attacker", amt)]},
                "transaction": {"signatures": ["S%d" % i], "message": {
                    "accountKeys": ["Payer", "VaultTok", "AttackerTok"]}}}) + "\n")' "$TT/big-a.jsonl" "$TT/big-b.jsonl"
python3 -I "$DNR/deltas.py" tokens "$TT/big-a.jsonl" "$TT/big-b.jsonl" > "$TT/big-d.tsv"
eq "deltas: a 20,000-transaction corpus over two files completes" "$?" "0"
eq "deltas: two rows per transaction" "$(grep -c . "$TT/big-d.tsv")" "40000"
eq "deltas: the attacker total is exact (Python ints)" \
  "$(python3 -I -c 'import sys
print(sum(int(l.split("\t")[3]) for l in open(sys.argv[1]) if l.split("\t")[1] == "Attacker"))' "$TT/big-d.tsv")" \
  "$(python3 -I -c 'print(20000 * (2**60 + 1))')"

# ---------------------------------------------------------------------------
# 15. collect.sh and snapshot-program.sh refuse a run directory that holds a
#     symbolic link, is one, or is tracked by git (in any letter case): exit 2,
#     nothing written inside it or outside it, no RPC call. An untracked,
#     link-free incident_<n>/ in the same repository is still accepted.
# ---------------------------------------------------------------------------
X="$TT/outside"; mkdir -p "$X/bin" "$X/corpus" "$X/b3"; printf 'canary\n' > "$X/canary"
mkdir -p "$TT/pl-a/incident_2" "$TT/pl-b"
ln -s "$X/canary" "$TT/pl-a/incident_2/LEDGER.md"
ln -s "$X/gitignore" "$TT/pl-a/incident_2/.gitignore"   # dangling: a write would create it outside
ln -s "$X/bin" "$TT/pl-a/incident_2/bin"
ln -s "$X/corpus" "$TT/pl-a/incident_2/corpus"
ln -s "$X/b3" "$TT/pl-b/incident_3"
REPO="$TT/repo"; mkdir -p "$REPO/incident_4" "$REPO/INCIDENT_6" "$REPO/incident_5"
for f in incident_4/LEDGER.md INCIDENT_6/LEDGER.md incident_5/LEDGER.md; do printf 'prior\n' > "$REPO/$f"; done
if git -C "$REPO" init -q >/dev/null 2>&1 && git -C "$REPO" add incident_4/LEDGER.md INCIDENT_6/LEDGER.md; then
  ok "run dir: test repository tracks incident_4/ and INCIDENT_6/"
else
  bad "run dir: could not set up the test repository"
fi
tree_state() { find "$X" "$TT/pl-a" "$TT/pl-b" "$REPO" -path "$REPO/.git" -prune -o -print | LC_ALL=C sort; cat "$X/canary"; }
state_before="$(tree_state)"
calls_before="$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)"
for case in \
  "a symbolic link inside the run dir:$TT/pl-a/incident_2:$TT/pl-a/incident_2/corpus2" \
  "a run dir that is a symbolic link:$TT/pl-b/incident_3:$TT/pl-b/incident_3/corpus" \
  "the same link with a trailing slash:$TT/pl-b/incident_3/:$TT/pl-b/incident_3/" \
  "a run dir git tracks:$REPO/incident_4:$REPO/incident_4/corpus" \
  "a run dir git tracks in another letter case:$REPO/incident_6:$REPO/incident_6/corpus"; do
  label="${case%%:*}"; rest="${case#*:}"; snapdir="${rest%%:*}"; outdir="${rest#*:}"
  ( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
      bash "$DNR/collect.sh" --out "$outdir" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/rd.out" 2>&1
  c1=$?
  PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" "$PID" "$snapdir" >> "$TT/rd.out" 2>&1
  c2=$?
  if [[ "$c1" == 2 && "$c2" == 2 ]] && [[ "$(grep -c 'refusing' "$TT/rd.out")" == 2 ]]; then
    ok "run dir: $label -> collect and snapshot refuse (exit 2)"
  else
    bad "run dir: $label -> collect exit $c1, snapshot exit $c2 ($(tr '\n' ' ' < "$TT/rd.out"))"
  fi
done
if [[ "$(tree_state)" == "$state_before" ]]; then ok "run dir: refused runs wrote nothing, inside or outside"; else bad "run dir: a refused run changed the tree"; fi
eq "run dir: refused runs made no RPC call" "$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)" "$calls_before"
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$REPO/incident_5/corpus" --confirmed --max-pages 1 -- "$A_ADDR" ) > /dev/null 2>&1
c1=$?
PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" "$PID" "$REPO/incident_5" > /dev/null 2>&1
c2=$?
if [[ "$c1" == 0 && "$c2" == 0 && -s "$REPO/incident_5/corpus/transactions.jsonl" && -s "$REPO/incident_5/bin/$PID.so" ]]; then
  ok "run dir: an untracked, link-free incident_<n>/ in a repository is accepted (control)"
else
  bad "run dir: the untracked control dir -> collect exit $c1, snapshot exit $c2"
fi
# A check that cannot run refuses instead of passing. Git refusing the repository
# (owned by another user, as with a checkout mounted into a container), git missing
# or failing, and a run directory find cannot read (here hiding a link to the
# outside) each mean exit 2, nothing written and no RPC call. The ownership cases run
# with no global or system git config: a machine-wide safe.directory (CI runners set
# one) would otherwise make git trust the repository. A repository named in the
# environment (GIT_DIR, GIT_WORK_TREE) never stands in for the one the run directory
# is in: the tracked directory is still refused.
mkdir -p "$TT/gitfail" "$TT/pl-c/incident_9"
git init -q "$TT/other-repo" >/dev/null 2>&1
printf '#!/bin/sh\nexit 127\n' > "$TT/gitfail/git"; chmod +x "$TT/gitfail/git"
ln -s "$X/bin" "$TT/pl-c/incident_9/bin"; chmod 0300 "$TT/pl-c/incident_9"
state_before="$(tree_state)"
calls_before="$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)"
for case in \
  "git does not trust the repository|GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TEST_ASSUME_DIFFERENT_OWNER=1 PATH=$TT/bin:$PATH|$REPO/incident_4|$REPO/incident_4/corpus" \
  "git does not trust the repository, untracked dir|GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TEST_ASSUME_DIFFERENT_OWNER=1 PATH=$TT/bin:$PATH|$REPO/incident_5|$REPO/incident_5/corpus-2" \
  "git missing or failing|PATH=$TT/gitfail:$TT/bin:$PATH|$REPO/incident_4|$REPO/incident_4/corpus" \
  "a repository named in the environment|GIT_DIR=$TT/other-repo/.git GIT_WORK_TREE=$TT/other-repo PATH=$TT/bin:$PATH|$REPO/incident_4|$REPO/incident_4/corpus" \
  "a run dir find cannot read|PATH=$TT/bin:$PATH|$TT/pl-c/incident_9|$TT/pl-c/incident_9/corpus"; do
  label="${case%%|*}"; rest="${case#*|}"; envs="${rest%%|*}"; rest="${rest#*|}"; snapdir="${rest%%|*}"; outdir="${rest#*|}"
  ( export RPC_URL="https://rpc.example.test/" ${envs%% PATH=*} PATH="${envs##*PATH=}"
    bash "$DNR/collect.sh" --out "$outdir" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/rd.out" 2>&1
  c1=$?
  ( export RPC_URL="https://rpc.example.test/" ${envs%% PATH=*} PATH="${envs##*PATH=}"
    bash "$DNR/snapshot-program.sh" "$PID" "$snapdir" ) >> "$TT/rd.out" 2>&1
  c2=$?
  if [[ "$c1" == 2 && "$c2" == 2 ]] && [[ "$(grep -c 'refusing' "$TT/rd.out")" == 2 ]]; then
    ok "run dir: $label -> collect and snapshot refuse (exit 2)"
  else
    bad "run dir: $label -> collect exit $c1, snapshot exit $c2 ($(tr '\n' ' ' < "$TT/rd.out"))"
  fi
done
chmod 0700 "$TT/pl-c/incident_9"
if [[ "$(tree_state)" == "$state_before" && -z "$(ls -A "$X/bin")" ]]; then
  ok "run dir: unverifiable runs wrote nothing, inside or outside"
else
  bad "run dir: an unverifiable run changed the tree"
fi
eq "run dir: unverifiable runs made no RPC call" "$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)" "$calls_before"

# ---------------------------------------------------------------------------
# 16. A second collection into an incident goes to corpus-2/, next to corpus/, and
#     is accepted; the recipes then read corpus*/ and count a transaction held by
#     both corpora once (first occurrence wins), so damage figures are not doubled.
# ---------------------------------------------------------------------------
mkdir "$TT/incident_21"
for c in corpus corpus-2; do
  ( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
      bash "$DNR/collect.sh" --out "$TT/incident_21/$c" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/incident_21.$c.out" 2>&1
  eq "two corpora: collecting into incident_21/$c succeeds" "$?" "0"
done
python3 -I "$DNR/deltas.py" lamports "$TT"/incident_21/corpus*/transactions.jsonl > /dev/null 2> "$TT/both.err"
if grep -q '^deltas.py: skipped 2 transaction(s) already read under the same signature$' "$TT/both.err"; then
  ok "two corpora: what both collections fetched is read once (2 copies skipped)"
else
  bad "two corpora: no skipped-copy note ($(tr '\n' ' ' < "$TT/both.err"))"
fi
mkdir -p "$TT/incident_22/corpus" "$TT/incident_22/corpus-2"
for c in corpus corpus-2; do cp "$FIX/same-owner-drain.jsonl" "$TT/incident_22/$c/transactions.jsonl"; done
both="$(python3 -I "$DNR/deltas.py" tokens "$TT"/incident_22/corpus*/transactions.jsonl 2>/dev/null)"
eq "two corpora: a drain held by both is counted once (3 rows, VaultPDA -140)" \
  "$(printf '%s\n' "$both" | grep -c .)/$(printf '%s\n' "$both" | owner_sum VaultPDA)" "3/-140"
for mode in tokens lamports; do
  eq "dedupe: deltas $mode over two fixtures given twice equals them once" \
    "$(python3 -I "$DNR/deltas.py" $mode "$FIX/same-owner-drain.jsonl" "$FIX/lamports-over-2-53.jsonl" "$FIX/same-owner-drain.jsonl" "$FIX/lamports-over-2-53.jsonl" 2>/dev/null)" \
    "$(python3 -I "$DNR/deltas.py" $mode "$FIX/same-owner-drain.jsonl" "$FIX/lamports-over-2-53.jsonl")"
done
eq "dedupe: frames over a fixture given twice equals the fixture once" \
  "$(python3 -I "$DNR/frames.py" "$FIX/log-newline-injection.jsonl" "$FIX/log-newline-injection.jsonl" 2>/dev/null)" "$logs"
prof2="$(bash "$DNR/profile.sh" "$FIX/clean-mixed.jsonl" "$FIX/clean-mixed.jsonl")"
eq "dedupe: profile over a corpus given twice counts each transaction once" \
  "$(printf '%s\n' "$prof2" | sed -n '/^-- transactions/,/^-- version/p' | tr -s ' ' | tr '\n' '|')" \
  "$(bash "$DNR/profile.sh" "$FIX/clean-mixed.jsonl" | sed -n '/^-- transactions/,/^-- version/p' | tr -s ' ' | tr '\n' '|')"
if grep -q '^-- skipped: 3 transaction(s) already read under the same signature$' <<< "$prof2"; then
  ok "dedupe: profile reports the copies it skipped"
else
  bad "dedupe: profile did not report skipped copies"
fi

# ---------------------------------------------------------------------------
# 17. profile.sh skips and counts malformed lines instead of stopping: a corpus
#     with invalid JSON and a wrongly shaped object in the middle still profiles
#     its three good transactions, exits 0, and reports the two lines it skipped.
#     A missing python3 is a named blocker.
# ---------------------------------------------------------------------------
{ sed -n 1p "$FIX/clean-mixed.jsonl"; echo 'not json {'; echo '{"transaction": "not an object"}'; sed -n '2,$p' "$FIX/clean-mixed.jsonl"; } > "$TT/malformed.jsonl"
bash "$DNR/profile.sh" "$TT/malformed.jsonl" > "$TT/malformed.out" 2>&1
eq "profile: a corpus with malformed lines still completes" "$?" "0"
eq "profile: the good transactions are all counted" \
  "$(sed -n '/^-- transactions/,/^-- version/p' "$TT/malformed.out" | tr -s ' ' | tr '\n' '|')" \
  "$(bash "$DNR/profile.sh" "$FIX/clean-mixed.jsonl" | sed -n '/^-- transactions/,/^-- version/p' | tr -s ' ' | tr '\n' '|')"
if grep -q '^-- skipped: 2 malformed line(s)' "$TT/malformed.out" && grep -q '^-- top-level programs' "$TT/malformed.out"; then
  ok "profile: the two malformed lines are counted at the end, and every section printed"
else
  bad "profile: malformed lines not reported ($(tail -n 2 "$TT/malformed.out" | tr '\n' ' '))"
fi
# The first pass runs as python3 -I: on a PATH without python3, a named blocker
# (exit 3) and no profile.
mkdir -p "$TT/prof-nopy"
for t in jq sed sort uniq awk tr cut mktemp rm cat; do
  p="$(command -v "$t" 2>/dev/null)" && [[ "$p" == /* ]] && ln -s "$p" "$TT/prof-nopy/$t"
done
if PATH="$TT/prof-nopy" "$(command -v bash)" -c 'command -v python3' >/dev/null 2>&1; then
  bad "profile: setup, python3 is still reachable through $TT/prof-nopy"
fi
PATH="$TT/prof-nopy" "$(command -v bash)" "$DNR/profile.sh" "$FIX/clean-mixed.jsonl" > "$TT/prof-nopy.out" 2> "$TT/prof-nopy.err"
code=$?
if [[ "$code" == 3 && ! -s "$TT/prof-nopy.out" ]] && grep -q '^\[blocker\] python3 is not on PATH' "$TT/prof-nopy.err"; then
  ok "profile: without python3 on PATH, a named blocker (exit 3) and no profile"
else
  bad "profile: no python3 -> exit $code ($(tr '\n' ' ' < "$TT/prof-nopy.err"))"
fi

# ---------------------------------------------------------------------------
# 18. frames.py --instructions: which instruction ran comes from the transaction's
#     runtime-recorded instruction lists, never from a log. The default mode finds
#     nothing for a program that logs nothing or one reached by CPI, and cannot tell
#     an Anchor program's "Instruction: X" from a lying program's; the ix records
#     can: their data is decoded here against the Anchor discriminator.
# ---------------------------------------------------------------------------
ixr() { python3 -I "$DNR/frames.py" --instructions "$FIX/$1.jsonl"; }
# disc8 <ix-record query>: the first 8 bytes (hex) of the selected record's base58 data
disc8() { python3 -I -c 'import json, sys
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
recs = [json.loads(l) for l in sys.stdin]
r = [x for x in recs if x["kind"] == "ix" and x["seq"] == int(sys.argv[1])][0]
n = 0
for c in r["data"]:
    n = n * 58 + B58.index(c)
raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
print(raw[:8].hex())' "$1"; }
anchor_disc() { python3 -I -c 'import hashlib, sys; print(hashlib.sha256(("global:" + sys.argv[1]).encode()).digest()[:8].hex())' "$1"; }
eq "instructions: control, the default mode yields no record for a program that logs nothing or one reached by CPI" \
  "$(python3 -I "$DNR/frames.py" "$FIX/ix-native-no-logs.jsonl" "$FIX/ix-cpi-victim.jsonl" | grep -c . || true)" "0"
eq "instructions: control, a lying program's log line equals the Anchor victim's" \
  "$(python3 -I "$DNR/frames.py" "$FIX/ix-lying-log.jsonl" | jq -r .text)" "$(python3 -I "$DNR/frames.py" "$FIX/ix-anchor-victim.jsonl" | jq -r .text)"
nat="$(ixr ix-native-no-logs)"
eq "instructions: a program that logs nothing still has its ix record, data exactly as given" \
  "$(printf '%s\n' "$nat" | jq -r 'select(.kind=="ix" and .seq==0) | "\(.program) \(.data)"')" \
  "$(jq -r '.transaction.message.instructions[0] | "\(.programId) \(.data)"' "$FIX/ix-native-no-logs.jsonl")"
eq "instructions: ... joined to its runtime invoke line (ix_seq 0, depth 1, success)" \
  "$(printf '%s\n' "$nat" | jq -r 'select(.kind=="invoke" and .seq==0) | "\(.ix_seq) \(.depth) \(.outcome)"')" "0 1 success"
eq "instructions: an RPC-parsed instruction is marked parsed-only, with what the RPC gave" \
  "$(printf '%s\n' "$nat" | jq -r 'select(.kind=="ix" and .seq==1) | "\(.data_status) \(.data) \(.program_name) \(.parsed.type)"')" "parsed-only null system transfer"
cpi="$(ixr ix-cpi-victim)"
eq "instructions: a CPI-reached victim (encoding json) is an inner ix record: program, top 0, inner 0, stack height 2" \
  "$(printf '%s\n' "$cpi" | jq -r 'select(.kind=="ix" and .seq==1) | "\(.program) \(.top) \(.inner) \(.stack_height)"')" "CpiVictim1111111111111111111111111111111111 0 0 2"
eq "instructions: ... whose data carries set_authority's discriminator" "$(printf '%s\n' "$cpi" | disc8 1)" "$(anchor_disc set_authority)"
eq "instructions: ... and whose depth-2 invoke line joins it (ix_seq 1, success)" \
  "$(printf '%s\n' "$cpi" | jq -r 'select(.kind=="invoke" and .depth==2) | "\(.ix_seq) \(.outcome)"')" "1 success"
eq "instructions: the Anchor victim's data carries set_authority's discriminator" "$(ixr ix-anchor-victim | disc8 0)" "$(anchor_disc set_authority)"
eq "instructions: the lying program's data carries deposit's discriminator, whatever its log says" "$(ixr ix-lying-log | disc8 0)" "$(anchor_disc deposit)"
eq "instructions: no ix record carries a log-derived field" \
  "$(for f in ix-native-no-logs ix-cpi-victim ix-anchor-victim ix-lying-log; do ixr "$f"; done | jq -r 'select(.kind=="ix") | keys - ["sig","ok","kind","seq","top","inner","stack_height","program","data","data_status","accounts","program_name","parsed"] | length' | sort -u)" "0"

# ---------------------------------------------------------------------------
# 19. Run-directory paths. collect.sh and snapshot-program.sh take a plain path:
#     a . or .. component is refused, and so is a path whose way passes through a
#     symbolic link inside the working directory (the tree under audit), whether
#     the path is relative or absolute, and even when an outside link leads into
#     that directory. A link above the working directory is the operator's and is
#     followed. When --out is itself an incident_* directory, collect.sh checks the
#     incident_* directory above it too, since it writes a .gitignore there.
#     Refusals exit 2 before any write or RPC / CLI call.
# ---------------------------------------------------------------------------
WD="$TT/wd19"; Y="$TT/elsewhere19"; OP="$TT/opdir19"
mkdir -p "$WD/real" "$WD/incident_30" "$Y" "$OP"
printf 'canary\n' > "$Y/canary"
ln -s "$Y" "$WD/linked"                      # a link inside the working directory
ln -s "$WD" "$TT/to-wd19"                    # an outside link into the working directory
ln -s "$OP" "$TT/op-link19"                  # an outside link to an outside directory
ln -s "$Y/canary" "$WD/incident_30/LEDGER.md"
y_state() { find "$Y" "$WD" | LC_ALL=C sort; cat "$Y/canary"; }
state_before="$(y_state)"
calls_before="$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)"
cli_before="$(grep -c . "$FAKE_SOLANA_ARGV" 2>/dev/null || true)"
for case in \
  "a .. component|real/../incident_31" \
  "a . component|real/./incident_32" \
  "a relative path through a link in the working directory|linked/incident_33" \
  "an absolute path through a link in the working directory|$WD/linked/incident_34" \
  "an outside link into the working directory, then a link in it|$TT/to-wd19/linked/incident_35"; do
  label="${case%%|*}"; d="${case#*|}"
  ( cd "$WD" && PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
      bash "$DNR/collect.sh" --out "$d/corpus" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/p19.out" 2>&1
  c1=$?
  ( cd "$WD" && PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
      bash "$DNR/snapshot-program.sh" "$PID" "$d" ) >> "$TT/p19.out" 2>&1
  c2=$?
  if [[ "$c1" == 2 && "$c2" == 2 ]]; then
    ok "run-dir path: $label -> collect and snapshot refuse (exit 2)"
  else
    bad "run-dir path: $label -> collect exit $c1, snapshot exit $c2 ($(tr '\n' ' ' < "$TT/p19.out"))"
  fi
done
( cd "$WD" && PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out incident_30/incident_36 --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/p19.out" 2>&1
code=$?
if [[ "$code" == 2 ]] && grep -q 'refusing incident_30' "$TT/p19.out"; then
  ok "run-dir path: an incident_* --out inside an incident_* directory that holds a link -> collect refuses (exit 2)"
else
  bad "run-dir path: incident_* in incident_* -> exit $code ($(tr '\n' ' ' < "$TT/p19.out"))"
fi
if [[ "$(y_state)" == "$state_before" ]]; then ok "run-dir path: refused runs wrote nothing, inside or outside"; else bad "run-dir path: a refused run changed the tree"; fi
eq "run-dir path: refused runs made no RPC call" "$(grep -c . "$FAKE_CURL_LOG" 2>/dev/null || true)" "$calls_before"
eq "run-dir path: refused runs made no CLI call" "$(grep -c . "$FAKE_SOLANA_ARGV" 2>/dev/null || true)" "$cli_before"
for case in \
  "a plain relative path|real/incident_37|$WD/real/incident_37" \
  "a leading ./|./real/incident_38|$WD/real/incident_38" \
  "an absolute path through the operator's link above the working directory|$TT/op-link19/incident_39|$OP/incident_39"; do
  label="${case%%|*}"; rest="${case#*|}"; d="${rest%%|*}"; landed="${rest#*|}"
  ( cd "$WD" && PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
      bash "$DNR/collect.sh" --out "$d/corpus" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/p19.out" 2>&1
  c1=$?
  ( cd "$WD" && PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
      bash "$DNR/snapshot-program.sh" "$PID" "$d" ) >> "$TT/p19.out" 2>&1
  c2=$?
  if [[ "$c1" == 0 && "$c2" == 0 && -s "$landed/corpus/transactions.jsonl" && -s "$landed/bin/$PID.so" ]]; then
    ok "run-dir path: $label is accepted (control)"
  else
    bad "run-dir path: $label -> collect exit $c1, snapshot exit $c2 ($(tr '\n' ' ' < "$TT/p19.out"))"
  fi
done

# ---------------------------------------------------------------------------
# 20. One input contract for profile.sh, frames.py and deltas.py (README.md):
#     binary lines split on LF only, ASCII whitespace stripped, strict UTF-8, one
#     JSON object per line with every field the recipes read of the type they read
#     it as, amounts and balances exact integers. A malformed line is skipped and
#     counted, never echoed and never a traceback, and the three recipes agree on
#     it. The contract code is one block, the same in all three files.
# ---------------------------------------------------------------------------
contract() { sed -n '/^# ---- input contract/,/^# ---- end of input contract/p' "$1"; }
if [[ -n "$(contract "$DNR/frames.py")" ]] && [[ "$(contract "$DNR/frames.py")" == "$(contract "$DNR/deltas.py")" ]] \
   && [[ "$(contract "$DNR/frames.py")" == "$(contract "$DNR/profile.sh")" ]]; then
  ok "contract: the input-contract block is the same in profile.sh, frames.py and deltas.py"
else
  bad "contract: the input-contract block differs between the recipes"
fi
# Each case is one crafted line (holding the word CRAFTED, so an echo would show)
# followed by one clean transaction, which must always come through.
python3 -I - "$TT/c20" <<'PY'
import json, os, sys
d = sys.argv[1]
os.makedirs(d)
P = "Prog7xQmP4sN9kR2wBcD3eF5gH6jK8mN1pQ2rS3tUvW"
def tx(sig, logs=None, pre=None, post=None, pre_tb=None, post_tb=None, keys=None, ixs=None, meta_extra=None, mark=True):
    meta = {"err": None, "fee": 5000, "preBalances": pre or [10000, 5], "postBalances": post or [5000, 10],
            "preTokenBalances": pre_tb or [], "postTokenBalances": post_tb or [],
            "logMessages": logs if logs is not None else ["Program %s invoke [1]" % P, "Program log: hello", "Program %s success" % P]}
    meta.update(meta_extra or {})
    t = {"blockTime": 1700000000, "meta": meta, "transaction": {"signatures": [sig], "message": {
        "accountKeys": keys if keys is not None else [{"pubkey": "Payer1111111111111111111111111111111111111", "signer": True},
                                                     {"pubkey": "TokAcct11111111111111111111111111111111111", "signer": False}],
        "instructions": ixs if ixs is not None else [{"programId": P, "accounts": [0, 1], "data": "3Bxs4h24hBtQy9rw"}]}}}
    if mark:
        t["note"] = "CRAFTED"
    return t
def bal(amount):
    return {"accountIndex": 1, "mint": "MintM", "owner": "OwnerA", "uiTokenAmount": {"amount": amount, "decimals": 0}}
def enc(obj):
    return json.dumps(obj, ensure_ascii=False).encode()
def nested(bracket, depth):
    """The value of meta.x such that the deepest bracket of the line is at depth, the
    line's object being 1 and meta 2: objects ({"a": {...}}) or arrays ([[...]])."""
    n = depth - 2
    if bracket == b"{":
        return b'{"a": ' * (n - 1) + b"{}" + b"}" * (n - 1)
    return b"[" * n + b"]" * n
clean = enc(tx("SigClean", pre_tb=[bal("0")], post_tb=[bal("7")], mark=False,
               keys=[{"pubkey": "PayerClean111111111111111111111111111111111", "signer": True},
                     {"pubkey": "TokAcct11111111111111111111111111111111111", "signer": False}]))
bad = {
    "lone-surrogate-in-a-log": enc(tx("SigBad1")).replace(b"Program log: hello", b"Program log: \\ud800 hello"),
    "lone-surrogate-in-an-owner": enc(tx("SigBad2", pre_tb=[bal("0")], post_tb=[bal("1")])).replace(b'"OwnerA"', b'"\\udc80"', 1),
    "meta-is-a-list": b'{"meta":[1,"CRAFTED"],"transaction":{"signatures":["SigBad3"],"message":{"accountKeys":[],"instructions":[]}}}',
    "key-without-pubkey": enc(tx("SigBad4", keys=[{"pubkey": "Payer1111111111111111111111111111111111111"}, {"signer": False}])),
    "keys-strings-and-objects": enc(tx("SigBad5", keys=["Payer1111111111111111111111111111111111111", {"pubkey": "TokAcct11111111111111111111111111111111111"}])),
    "instruction-a-string": enc(tx("SigBad6", ixs=["CRAFTED"])),
    "header-count-a-string": enc(tx("SigBad7", keys=["Payer1111111111111111111111111111111111111"])).replace(b'"instructions"', b'"header": {"numRequiredSignatures": "1"}, "instructions"'),
    "raw-CR-inside-a-string": enc(tx("SigBad8")).replace(b"Program log: hello", b"Program log: hel\rlo"),
    "amount-1_000": enc(tx("SigBad9", pre_tb=[bal("0")], post_tb=[bal("1_000")])),
    "amount-arabic-indic-digit": enc(tx("SigBad10", pre_tb=[bal("0")], post_tb=[bal("٣")])),
    "amount-full-width-digits": enc(tx("SigBad11", pre_tb=[bal("0")], post_tb=[bal("１２")])),
    "amount-a-JSON-float": enc(tx("SigBad12", pre_tb=[bal("0")], post_tb=[bal(1.5)])),
    "amount-1e3": enc(tx("SigBad13", pre_tb=[bal("0")], post_tb=[bal("1e3")])),
    "amount-signed": enc(tx("SigBad14", pre_tb=[bal("0")], post_tb=[bal("+5")])),
    "lamports-a-float": enc(tx("SigBad15", pre=[10000, 1.5], post=[5000, 3.5])),
    "lamports-Infinity": enc(tx("SigBad16", pre=[10000, 1], post=[5000, 2])).replace(b"[5000, 2]", b"[5000, Infinity]"),
    "lamports-NaN": enc(tx("SigBad17", pre=[10000, 1], post=[5000, 2])).replace(b"[5000, 2]", b"[5000, NaN]"),
    "fee-a-string": enc(tx("SigBad18", meta_extra={"fee": "5000"})),
    "float-out-of-range": enc(tx("SigBad19", meta_extra={"computeUnitsConsumed": 1.5})).replace(b"1.5", b"1e400"),
    "invalid-UTF-8": enc(tx("SigBad20")).replace(b"Program log: hello", b"Program log: hel\xfflo"),
    "leading-x1c": b"\x1c" + enc(tx("SigBad21")),
    "a-JSON-array": b'["CRAFTED"]',
    "a-log-that-is-not-a-string": enc(tx("SigBad22", logs=["Program log: hello", 5])),
    "inner-group-without-index": enc(tx("SigBad23", meta_extra={"innerInstructions": [{"instructions": []}]})),
    "nesting-deeper-than-the-parser": b'{"meta":{"x":' + b"[" * 100000 + b"]" * 100000 + b'},"note":"CRAFTED"}',
    "a-truncated-line-holding-a-drain": enc(tx("SigBad24", pre_tb=[bal("9000000")], post_tb=[bal("0")]))[:-2],
    "amount-a-float-above-2^53": enc(tx("SigBad25", pre_tb=[bal("0")], post_tb=[bal("PLACE")])).replace(b'"PLACE"', b"9007199254740993.0"),
    "lamports-a-float-above-2^53": enc(tx("SigBad26", pre=[10000, 1], post=[5000, 2])).replace(b"[5000, 2]", b"[5000, 9007199254740993.0]"),
    "a-pubkey-that-is-an-object": enc(tx("SigBad27", keys=[{"pubkey": {"a": 1, "b": 2}, "signer": True}])),
    "a-key-holding-a-newline": enc(tx("SigBad28", keys=["Payer11111111111\nForged2222222222222222222"])),
    "a-program-id-holding-a-newline": enc(tx("SigBad29", ixs=[{"programId": "Prog\nForged", "accounts": []}])),
    "a-version-holding-a-newline": enc(dict(tx("SigBad30"), version="0\n   999 legacy")),
    "balance-lists-of-different-lengths": enc(tx("SigBad31", pre=[10000, 5, 9000000000], post=[5000, 10])),
    "nesting-300-deep": enc(tx("SigBad32", meta_extra={"x": "PLACE"})).replace(b'"PLACE"', b"[" * 300 + b"]" * 300),
    "a-lamport-balance-above-u64": enc(tx("SigBad33", pre=[10000, 5], post=[5000, 2**64])),
    "a-negative-lamport-balance": enc(tx("SigBad34", pre=[10000, -5], post=[5000, 10])),
    "a-fee-above-u64": enc(tx("SigBad35", meta_extra={"fee": 2**64})),
    "an-amount-above-u64": enc(tx("SigBad36", pre_tb=[bal("0")], post_tb=[bal(str(2**64))])),
    "a-45-digit-amount": enc(tx("SigBad37", pre_tb=[bal("0")], post_tb=[bal("1" * 45)])),
    "lamports-a-4301-digit-delta": enc(tx("SigBad38", pre=[10000, 0], post=[5000, 0])).replace(
        b"[10000, 0]", b"[10000, -" + b"9" * 4300 + b"]").replace(b"[5000, 0]", b"[5000, " + b"9" * 4300 + b"]"),
    "tokens-a-4301-digit-sum": enc(tx("SigBad39", pre_tb=[bal("0")], post_tb=[bal("9" * 4300), bal("9" * 4300)])),
    "a-negative-programIdIndex": enc(tx("SigBad40", keys=["Payer1111111111111111111111111111111111111", "Last111111111111111111111111111111111111111"],
                                        ixs=[{"programIdIndex": -1, "accounts": [0]}])),
    "an-empty-programId": enc(tx("SigBad41", ixs=[{"programId": "", "accounts": [0]}])),
    "a-negative-numRequiredSignatures": enc(tx("SigBad42", keys=["Payer1111111111111111111111111111111111111", "Two1111111111111111111111111111111111111111"])).replace(
        b'"instructions"', b'"header": {"numRequiredSignatures": -1}, "instructions"'),
    "a-negative-accountIndex": enc(tx("SigBad43", pre_tb=[dict(bal("0"), accountIndex=-1)], post_tb=[dict(bal("5"), accountIndex=-1)])),
    "a-negative-inner-index": enc(tx("SigBad44", meta_extra={"innerInstructions": [{"index": -1, "instructions": []}]})),
    "a-key-holding-a-line-separator": enc(tx("SigBad45", keys=["Payer1111111111111111\u2028Forged222222222222222", "Two1111111111111111111111111111111111111111"])),
    "a-program-id-holding-a-next-line": enc(tx("SigBad46", ixs=[{"programId": "Prog\x85Forged", "accounts": []}])),
    "nesting-300-deep-under-a-key-repeated-later": enc(tx("SigBad47", meta_extra={"x": "PLACE"})).replace(
        b'"PLACE"', b"[" * 298 + b"]" * 298 + b', "x": 1'),
    "a-key-holding-a-right-to-left-override": enc(tx("SigBad48", keys=["Payer‮111111111111111111111111111111111111", "Two1111111111111111111111111111111111111111"])),
    "a-key-holding-a-first-strong-isolate": enc(tx("SigBad49", keys=["Payer⁨111111111111111111111111111111111111", "Two1111111111111111111111111111111111111111"])),
    "a-key-holding-an-arabic-letter-mark": enc(tx("SigBad50", keys=["Payer؜111111111111111111111111111111111111", "Two1111111111111111111111111111111111111111"])),
    "a-key-holding-DEL": enc(tx("SigBad51", keys=["Payer\x7f111111111111111111111111111111111111", "Two1111111111111111111111111111111111111111"])),
    "a-program-id-holding-a-zero-width-space": enc(tx("SigBad52", ixs=[{"programId": "Prog​Forged", "accounts": []}])),
    "a-version-holding-a-byte-order-mark": enc(dict(tx("SigBad53"), version="0﻿")),
    "a-21-digit-integer-in-a-field-no-recipe-reads": enc(tx("SigBad54", meta_extra={"computeUnitsConsumed": 10 ** 20})),
    "a-4301-digit-integer-in-a-field-no-recipe-reads": enc(tx("SigBad55", meta_extra={"computeUnitsConsumed": "PLACE"})).replace(
        b'"PLACE"', b"9" * 4301),
    "minus-0-in-a-field-no-recipe-reads": enc(tx("SigBad56", meta_extra={"computeUnitsConsumed": "PLACE"})).replace(b'"PLACE"', b"-0"),
    "a-fee-of-minus-0": enc(tx("SigBad57", meta_extra={"fee": "PLACE"})).replace(b'"PLACE"', b"-0"),
    "objects-nested-129-deep": enc(tx("SigBad58", meta_extra={"x": "PLACE"})).replace(b'"PLACE"', nested(b"{", 129)),
    "objects-nested-200-deep": enc(tx("SigBad59", meta_extra={"x": "PLACE"})).replace(b'"PLACE"', nested(b"{", 200)),
    "arrays-nested-129-deep": enc(tx("SigBad60", meta_extra={"x": "PLACE"})).replace(b'"PLACE"', nested(b"[", 129)),
}
last = ("instruction-a-string", "keys-strings-and-objects", "header-count-a-string", "a-pubkey-that-is-an-object",
        "a-truncated-line-holding-a-drain", "nesting-300-deep", "nesting-300-deep-under-a-key-repeated-later",
        "objects-nested-129-deep", "objects-nested-200-deep", "arrays-nested-129-deep")
good = {
    "raw-CR-between-tokens": enc(tx("SigGood1", mark=False)).replace(b', "transaction"', b',\r"transaction"'),
    "CRLF-line-end": enc(tx("SigGood2", mark=False)) + b"\r",
    "a-surrogate-pair-escape": enc(tx("SigGood3", mark=False)).replace(b"Program log: hello", b"Program log: \\ud83d\\ude00"),
    "an-escaped-backslash-before-u": enc(tx("SigGood4", mark=False)).replace(b"Program log: hello", b"Program log: \\\\ud800"),
    "an-amount-of-u64-max": enc(tx("SigGood5", pre_tb=[bal("0")], post_tb=[bal(str(2**64 - 1))], mark=False)),
    "a-duplicate-key": enc(tx("SigGood6", mark=False)).replace(b'"err": null', b'"err": {"Custom": 1}, "err": null'),
    "fewer-keys-than-balances": enc(tx("SigGood7", pre=[10000, 5, 9000000000], post=[5000, 10, 0], mark=False)),
    "arrays-nested-128-deep": enc(tx("SigGood8", meta_extra={"x": "PLACE"}, mark=False)).replace(b'"PLACE"', nested(b"[", 128)),
    "objects-nested-128-deep": enc(tx("SigGood14", meta_extra={"x": "PLACE"}, mark=False)).replace(b'"PLACE"', nested(b"{", 128)),
    "a-key-holding-a-character-new-in-Unicode-15": enc(tx("SigGood11", mark=False,
        keys=[{"pubkey": "Payer\U0001fae8111111111111111111111111111111111", "signer": True},
              {"pubkey": "TokAcct\U0001fae8 1111111111111111111111111111111111", "signer": False}],
        pre_tb=[dict(bal("0"), owner="Own\U0001fae8er")], post_tb=[dict(bal("4"), owner="Own\U0001fae8er")])),
    "bidi-and-zero-width-characters-in-owner-mint-and-a-log": enc(tx("SigGood12", mark=False,
        logs=["Program %s invoke [1]" % P, "Program log: a‮b\x85c\x7fd​e﻿f", "Program %s success" % P],
        pre_tb=[dict(bal("0"), owner="Own‮er​X﻿", mint="Mi؜nt⁦\x7f")],
        post_tb=[dict(bal("5"), owner="Own‮er​X﻿", mint="Mi؜nt⁦\x7f")])),
    "a-20-digit-integer-and-minus-0.0-in-fields-no-recipe-reads": enc(tx("SigGood13", mark=False,
        meta_extra={"computeUnitsConsumed": 99999999999999999999, "y": "PLACE"})).replace(b'"PLACE"', b"-0.0"),
    "brackets-and-escaped-quotes-inside-strings": enc(tx("SigGood10", mark=False)).replace(
        b"Program log: hello", b"Program log: " + b"[{" * 150 + b'\\\\\\" ' + b"[" * 150),
    "control-characters-in-owner-mint-and-signature": enc(tx("Sig\x0bGood9", pre=[10000, 5], post=[5000, 6], mark=False,
        pre_tb=[dict(bal("0"), owner="Own\x00er\u2028X", mint="Mi\x1e\x85nt")], post_tb=[dict(bal("5"), owner="Own\x00er\u2028X", mint="Mi\x1e\x85nt")])),
}
for kind, cases in (("bad", bad), ("good", good)):
    for name, line in cases.items():
        assert kind == "good" or b"CRAFTED" in line, name
        with open(os.path.join(d, "%s-%s.jsonl" % (kind, name)), "wb") as f:
            f.write(line + b"\n" + clean + b"\n")
# The same crafted lines after the clean one: the result must not depend on where they sit.
for kind, cases, names in (("bad", bad, last), ("good", good, ("arrays-nested-128-deep", "objects-nested-128-deep"))):
    for name in names:
        with open(os.path.join(d, "%s-%s-last.jsonl" % (kind, name)), "wb") as f:
            f.write(clean + b"\n" + cases[name] + b"\n")
PY
# runs20 <corpus>: exit status and malformed count of profile, frames, frames
# --instructions, deltas lamports and deltas tokens, as "s:n s:n s:n s:n s:n", where n
# is the count from the "skipped N malformed" line on stderr (0 when there is none).
runs20() {
  local f="$1" out="" rc n
  for r in profile frames ix lamports tokens; do
    case "$r" in
      profile) bash "$DNR/profile.sh" "$f" > "$TT/r20.out" 2> "$TT/r20.err" ;;
      frames) python3 -I "$DNR/frames.py" "$f" > "$TT/r20.out" 2> "$TT/r20.err" ;;
      ix) python3 -I "$DNR/frames.py" --instructions "$f" > "$TT/r20.out" 2> "$TT/r20.err" ;;
      *) python3 -I "$DNR/deltas.py" "$r" "$f" > "$TT/r20.out" 2> "$TT/r20.err" ;;
    esac
    rc=$?
    n="$(sed -n 's/^[a-z]*\.[a-z]*: skipped \([0-9]*\) malformed line.*/\1/p' "$TT/r20.err")"
    out="$out $rc:${n:-0}"
    cat "$TT/r20.out" "$TT/r20.err" >> "$TT/r20.all"
    case "$r" in
      profile) grep -q 'PayerClean' "$TT/r20.out" || echo "profile lost the clean transaction" >> "$TT/r20.lost" ;;
      frames|ix) grep -q '"sig": "SigClean"' "$TT/r20.out" || echo "$r lost the clean transaction" >> "$TT/r20.lost" ;;
      lamports|tokens) grep -q '^SigClean	' "$TT/r20.out" || echo "$r lost the clean transaction" >> "$TT/r20.lost" ;;
    esac
  done
  echo "${out# }"
}
for f in "$TT"/c20/bad-*.jsonl; do
  name="${f##*/bad-}"; name="${name%.jsonl}"
  : > "$TT/r20.all"; rm -f "$TT/r20.lost"
  eq "contract: $name is one malformed line for every recipe, which carries on" "$(runs20 "$f")" "0:1 0:1 0:1 0:1 0:1"
  if grep -q 'CRAFTED\|Traceback\|^jq: ' "$TT/r20.all" || [[ -e "$TT/r20.lost" ]]; then
    bad "contract: $name was echoed, raised, failed a query, or lost the clean transaction ($(cat "$TT/r20.lost" 2>/dev/null))"
  fi
done
for f in "$TT"/c20/good-*.jsonl; do
  name="${f##*/good-}"; name="${name%.jsonl}"
  : > "$TT/r20.all"; rm -f "$TT/r20.lost"
  eq "contract: $name is read as a transaction by every recipe" "$(runs20 "$f")" "0:0 0:0 0:0 0:0 0:0"
  if grep -q 'Traceback\|^jq: ' "$TT/r20.all" || [[ -e "$TT/r20.lost" ]]; then
    bad "contract: $name raised, failed a query, or lost the clean transaction ($(cat "$TT/r20.lost" 2>/dev/null))"
  fi
done
# A string that never ends, of 80 KiB and of 1 MiB of escaped quotes followed by 200
# brackets, before and after the clean transaction: the depth pre-scan reads it in one
# pass, so each recipe finishes within 10 seconds and counts one malformed line. The
# recipes run under a Python timeout, so no GNU timeout is needed; a run past it is
# stopped with its whole process group. long20.py prints "<case> s:n s:n s:n s:n s:n"
# per file, as runs20 does (T for a run that timed out), and a PROBLEM line for an
# echoed line, a traceback or a lost clean transaction.
cat > "$TT/long20.py" <<'PY'
import os, re, signal, subprocess, sys
dnr, d = sys.argv[1], sys.argv[2]
clean = open(os.path.join(d, "bad-a-JSON-array.jsonl"), "rb").read().split(b"\n")[1]
runs = (("profile", ["bash", dnr + "/profile.sh"], b"PayerClean"),
        ("frames", ["python3", "-I", dnr + "/frames.py"], b'"sig": "SigClean"'),
        ("ix", ["python3", "-I", dnr + "/frames.py", "--instructions"], b'"sig": "SigClean"'),
        ("lamports", ["python3", "-I", dnr + "/deltas.py", "lamports"], b"\nSigClean\t"),
        ("tokens", ["python3", "-I", dnr + "/deltas.py", "tokens"], b"\nSigClean\t"))
for size, k in (("80KiB", 40 * 1024), ("1MiB", 512 * 1024)):
    line = b'{"note": "CRAFTED ' + b'\\"' * k + b"[" * 200
    for pos in ("first", "last"):
        name = "unterminated-string-%s-%s" % (size, pos)
        path = os.path.join(d, name + ".jsonl")
        with open(path, "wb") as f:
            f.write(line + b"\n" + clean + b"\n" if pos == "first" else clean + b"\n" + line + b"\n")
        got = []
        for label, cmd, mark in runs:
            p = subprocess.Popen(cmd + [path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
            try:
                out, err = p.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.communicate()
                got.append("T")
                continue
            n = re.search(rb"skipped (\d+) malformed line", err)
            got.append("%d:%s" % (p.returncode, n.group(1).decode() if n else "0"))
            if b"CRAFTED" in out + err or b"Traceback" in err or mark not in b"\n" + out:
                print("PROBLEM %s %s: echoed the line, raised, or lost the clean transaction" % (name, label))
        print(name + " " + " ".join(got))
PY
long20="$(python3 -I "$TT/long20.py" "$DNR" "$TT/c20")"
for size in 80KiB 1MiB; do
  for pos in first last; do
    eq "contract: a string that never ends ($size, $pos) is one malformed line for every recipe, each within 10 s" \
      "$(printf '%s\n' "$long20" | sed -n "s/^unterminated-string-$size-$pos //p")" "0:1 0:1 0:1 0:1 0:1"
  done
done
case "$long20" in *PROBLEM*) bad "contract: strings that never end: $(printf '%s\n' "$long20" | sed -n 's/^PROBLEM //p' | tr '\n' ';')" ;; esac
eq "contract: a raw CR between JSON tokens is not a line break: deltas keeps that transaction's rows" \
  "$(python3 -I "$DNR/deltas.py" lamports "$TT/c20/good-raw-CR-between-tokens.jsonl" | cut -f1 | sort -u | tr '\n' ' ')" "SigClean SigGood1 "
eq "contract: a balance whose index has no account key is a row named #<index>, with a note" \
  "$(python3 -I "$DNR/deltas.py" lamports "$TT/c20/good-fewer-keys-than-balances.jsonl" 2> "$TT/k20.err" | grep '^SigGood7' | tr '\t\n' ' |')$(grep -c '^deltas.py: 1 row(s) name a balance index that has no account key, as #<index>' "$TT/k20.err")" \
  "SigGood7 TokAcct11111111111111111111111111111111111 5|SigGood7 #2 -9000000000|1"
# unsafe20 <file>: how many characters of the contract's fixed list, tab and newline
# aside, <file> holds.
unsafe20() { python3 -I -c 'import re, sys
print(len(re.findall(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]",
                     open(sys.argv[1], encoding="utf-8").read())))' "$1"; }
python3 -I "$DNR/deltas.py" tokens "$TT/c20/good-control-characters-in-owner-mint-and-signature.jsonl" > "$TT/u20.tokens"
python3 -I "$DNR/deltas.py" tokens "$TT/c20/good-bidi-and-zero-width-characters-in-owner-mint-and-a-log.jsonl" >> "$TT/u20.tokens"
eq "contract: deltas escapes each character of the fixed list, in every column" \
  "$(grep -c '^Sig\\x0bGood9	Own\\x00er\\u2028X	Mi\\x1e\\x85nt	5	TokAcct' "$TT/u20.tokens")|$(grep -c '^SigGood12	Own\\u202eer\\u200bX\\ufeff	Mi\\u061cnt\\u2066\\x7f	5	TokAcct' "$TT/u20.tokens")|$(python3 -I "$DNR/deltas.py" lamports "$TT/c20/good-control-characters-in-owner-mint-and-signature.jsonl" | grep -c '^Sig\\x0bGood9	')|$(unsafe20 "$TT/u20.tokens")" \
  "1|1|1|0"
python3 -I "$DNR/frames.py" "$TT/c20/good-bidi-and-zero-width-characters-in-owner-mint-and-a-log.jsonl" > "$TT/u20.frames"
eq "contract: frames writes those characters as \\u escapes, and the text reads back the same" \
  "$(grep -c -F '"text": "a\u202eb\u0085c\u007fd\u200be\ufefff"' "$TT/u20.frames")|$(unsafe20 "$TT/u20.frames")|$(python3 -I -c 'import json, sys
print(any(json.loads(l).get("text") == "a\u202eb\x85c\x7fd\u200be\ufefff" for l in open(sys.argv[1], encoding="utf-8")))' "$TT/u20.frames")" \
  "1|0|True"
# profile.sh counts and orders keys byte by byte under every locale: fee payers that
# differ only in a character a UTF-8 collation ignores (U+00AD, U+034F, U+2060) stay
# separate lines, in the same order under en_US.UTF-8 as under C.
python3 -I - "$TT/l20.jsonl" <<'PY'
import json, sys
def tx(sig, payer):
    return {"blockTime": 1700000000, "version": 0,
            "meta": {"err": None, "fee": 5000, "preBalances": [1], "postBalances": [1]},
            "transaction": {"signatures": [sig], "message": {"accountKeys": [payer]}}}
payers = ["Payer1", "Pay­er1", "Payer1͏", "Pay⁠er1", "Payer1"]
with open(sys.argv[1], "w", encoding="utf-8") as f:
    for k, payer in enumerate(payers):
        f.write(json.dumps(tx("SigLook%d" % k, payer), ensure_ascii=False) + "\n")
PY
LC_ALL=en_US.UTF-8 bash "$DNR/profile.sh" "$TT/l20.jsonl" > "$TT/l20.en" 2> /dev/null
LC_ALL=C bash "$DNR/profile.sh" "$TT/l20.jsonl" > "$TT/l20.c" 2> /dev/null
eq "contract: profile counts keys byte by byte, the same under every locale" \
  "$(sed -n '/^-- fee payers/,/^-- signers/p' "$TT/l20.en" | grep -c '^ *[12] Pay')|$(cmp -s "$TT/l20.en" "$TT/l20.c" && echo same)" "4|same"
# U+1FAE8 is new in Unicode 15: Python 3.9 (Unicode 13) and 3.11 (Unicode 14) do not
# count it printable, Python 3.12 does; nor does any of them count U+00A0 (a no-break
# space). The fixed list makes no difference between them: both print as themselves.
u15="$(python3 -I -c 'print("\U0001fae8")')"; nbsp="$(python3 -I -c 'print("\u00a0")')"
eq "contract: a character new in Unicode 15 is printed as itself by profile and deltas, under any Python" \
  "$(bash "$DNR/profile.sh" "$TT/c20/good-a-key-holding-a-character-new-in-Unicode-15.jsonl" 2>/dev/null | grep -c "Payer${u15}111")|$(python3 -I "$DNR/deltas.py" lamports "$TT/c20/good-a-key-holding-a-character-new-in-Unicode-15.jsonl" | grep -c "^SigGood11	TokAcct${u15}${nbsp}111")|$(python3 -I "$DNR/deltas.py" tokens "$TT/c20/good-a-key-holding-a-character-new-in-Unicode-15.jsonl" | grep -c "^SigGood11	Own${u15}er	")" \
  "2|1|1"
eq "contract: the u64 maximum stays exact" \
  "$(python3 -I "$DNR/deltas.py" tokens "$TT/c20/good-an-amount-of-u64-max.jsonl" | awk -F'\t' '$1 == "SigGood5" { print $4 }')" "18446744073709551615"
eq "contract: malformed lines are counted per input, named by path and line, not echoed; copies are counted apart" \
  "$(cd "$TT/c20" && python3 -I "$DNR/frames.py" good-a-duplicate-key.jsonl bad-meta-is-a-list.jsonl bad-a-JSON-array.jsonl 2>&1 >/dev/null | tr '\n' '|')" \
  "frames.py: skipped 2 transaction(s) already read under the same signature|frames.py: skipped 1 malformed line(s) in input 2 (bad-meta-is-a-list.jsonl), the first at line 1 (not a getTransaction JSON object the recipes can read)|frames.py: skipped 1 malformed line(s) in input 3 (bad-a-JSON-array.jsonl), the first at line 1 (not a getTransaction JSON object the recipes can read)|"
eq "contract: on stdin, the same note names stdin" \
  "$(python3 -I "$DNR/deltas.py" lamports < "$TT/c20/bad-meta-is-a-list.jsonl" 2>&1 >/dev/null)" \
  "deltas.py: skipped 1 malformed line(s) in stdin, the first at line 1 (not a getTransaction JSON object the recipes can read)"
prof20="$(cd "$TT/c20" && bash "$DNR/profile.sh" bad-meta-is-a-list.jsonl 2> "$TT/p20.err")"
eq "contract: profile.sh closes its report with the note, and prints it on stderr too" \
  "$(printf '%s\n' "$prof20" | grep '^-- skipped:')|$(cat "$TT/p20.err")" \
  "-- skipped: 1 malformed line(s) in input 1 (bad-meta-is-a-list.jsonl), the first at line 1 (not a getTransaction JSON object the recipes can read)|profile.sh: skipped 1 malformed line(s) in input 1 (bad-meta-is-a-list.jsonl), the first at line 1 (not a getTransaction JSON object the recipes can read)"

# ---------------------------------------------------------------------------
# 21. The recipes refuse a corpus path that is a symbolic link, or that passes
#     through a directory link inside the working directory (exit 2, no output),
#     and show a path they cannot use only escaped and capped. A link above the
#     working directory, the operator's own, is followed.
# ---------------------------------------------------------------------------
W21="$TT/wd21"; mkdir -p "$W21/real" "$TT/op21"
cp "$FIX/same-owner-drain.jsonl" "$W21/real/corpus.jsonl"
cp "$FIX/same-owner-drain.jsonl" "$TT/op21/corpus.jsonl"
ln -s "$W21/real/corpus.jsonl" "$W21/file-link.jsonl"
ln -s "$W21/real" "$W21/dir-link"
ln -s "$TT/op21" "$TT/op-link21"
# runs21 <path>: "status:output lines:refusal lines" for profile, frames and deltas,
# each run from $W21.
runs21() {
  local res="" r
  for r in profile frames tokens; do
    case "$r" in
      profile) ( cd "$W21" && bash "$DNR/profile.sh" "$1" ) > "$TT/r21.out" 2> "$TT/r21.err" ;;
      frames) ( cd "$W21" && python3 -I "$DNR/frames.py" "$1" ) > "$TT/r21.out" 2> "$TT/r21.err" ;;
      tokens) ( cd "$W21" && python3 -I "$DNR/deltas.py" tokens "$1" ) > "$TT/r21.out" 2> "$TT/r21.err" ;;
    esac
    res="$res $?:$(grep -c . "$TT/r21.out"):$(grep -c 'is a symbolic link, or is reached through one inside the working directory; refusing it$' "$TT/r21.err")"
  done
  echo "${res# }"
}
for case in "a file that is a link|file-link.jsonl" "a path through a directory link in the working directory|dir-link/corpus.jsonl" \
  "the same path, absolute|$W21/dir-link/corpus.jsonl"; do
  eq "input links: ${case%%|*} -> profile, frames and deltas refuse it (exit 2, no output)" "$(runs21 "${case#*|}")" "2:0:1 2:0:1 2:0:1"
done
got="$(runs21 "$TT/op-link21/corpus.jsonl")"
case "$got" in
  0:[1-9]*:0\ 0:*:0\ 0:[1-9]*:0) ok "input links: a directory link above the working directory is followed ($got)" ;;
  *) bad "input links: the operator's directory link was refused ($got)" ;;
esac
oddp="$TT/no such"$'\n'"line"$'\033'"[31m.jsonl"
longp="$TT/$(python3 -I -c 'print("x" * 400)').jsonl"
for r in frames lamports; do
  for p in "$oddp" "$longp"; do
    case "$r" in
      frames) python3 -I "$DNR/frames.py" "$p" > "$TT/r21.out" 2> "$TT/r21.err" ;;
      lamports) python3 -I "$DNR/deltas.py" lamports "$p" > "$TT/r21.out" 2> "$TT/r21.err" ;;
    esac
    code=$?
    msg="$(cat "$TT/r21.err")"
    if [[ "$code" == 1 && ! -s "$TT/r21.out" && "$(grep -c . "$TT/r21.err")" == 1 && "$msg" == *"cannot read input 1 ("* \
          && "$msg" != *$'\033'* && ${#msg} -lt 260 ]] \
       && { [[ "$p" == "$longp" && "$msg" == *"...)"* ]] || [[ "$p" == "$oddp" && "$msg" == *'such\nline\x1b[31m.jsonl'* ]]; }; then
      ok "input paths: $r shows an unreadable path escaped and capped, on one line (exit 1)"
    else
      bad "input paths: $r unreadable path -> exit $code, message '$msg'"
    fi
  done
done
# A FIFO named as a corpus is not a regular file: each recipe refuses it at once,
# never waiting for a writer (a run still going after 10 s is stopped and fails).
mkfifo "$TT/in21.fifo"
res=""
for r in profile frames lamports; do
  case "$r" in
    profile) ( bash "$DNR/profile.sh" "$TT/in21.fifo" > /dev/null 2> "$TT/f21.err"; echo "$?" > "$TT/f21.code" ) & ;;
    frames) ( python3 -I "$DNR/frames.py" "$TT/in21.fifo" > /dev/null 2> "$TT/f21.err"; echo "$?" > "$TT/f21.code" ) & ;;
    lamports) ( python3 -I "$DNR/deltas.py" lamports "$TT/in21.fifo" > /dev/null 2> "$TT/f21.err"; echo "$?" > "$TT/f21.code" ) & ;;
  esac
  pid=$!; n=0
  while kill -0 "$pid" 2>/dev/null && [[ "$n" -lt 200 ]]; do sleep 0.05; n=$((n + 1)); done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    res="$res $r:waiting"
  else
    wait "$pid"
    res="$res $(cat "$TT/f21.code"):$(grep -c 'usage: profile.sh\|cannot read input 1 (.*): not a regular file$' "$TT/f21.err")"
  fi
done
eq "input paths: a FIFO is refused at once by profile (usage, exit 2), frames and deltas (exit 1)" "${res# }" "2:1 1:1 1:1"
# The README's exit statuses for an input: profile.sh refuses a missing file or a
# directory as a usage error (exit 2); a regular file it cannot read is exit 1, and
# frames.py and deltas.py give exit 1 for all three.
cp "$FIX/clean-mixed.jsonl" "$TT/unread21.jsonl"; chmod 000 "$TT/unread21.jsonl"
if [[ -r "$TT/unread21.jsonl" ]]; then
  ok "input paths: skipped, this user can read a 000 file"
else
  res=""
  for p in "$TT/no-such21.jsonl" "$TT" "$TT/unread21.jsonl"; do
    bash "$DNR/profile.sh" "$p" > /dev/null 2>&1; s1=$?
    python3 -I "$DNR/frames.py" "$p" > /dev/null 2>&1; s2=$?
    python3 -I "$DNR/deltas.py" lamports "$p" > /dev/null 2>&1; s3=$?
    res="$res $s1:$s2:$s3"
  done
  eq "input paths: a missing file, a directory and an unreadable file -> profile 2, 2, 1; frames and deltas 1" "${res# }" "2:1:1 2:1:1 1:1:1"
fi
chmod 0600 "$TT/unread21.jsonl"

# ---------------------------------------------------------------------------
# 22. --out writes a recipe's output to a temporary file beside <file> and gives
#     it that name only once it is whole: <file> then holds what stdout would have,
#     and no temporary file is left. An output never replaces a file: an --out that
#     exists, the input corpus among them, is refused (exit 2) and left as it was,
#     and so is one that is a symbolic link, or reached through one inside the
#     working directory. A run stopped by SIGTERM leaves no <file> and no
#     temporary file.
# ---------------------------------------------------------------------------
W22="$TT/wd22"; mkdir -p "$W22/out" "$TT/elsewhere22"
cat "$FIX/clean-mixed.jsonl" "$FIX/same-owner-drain.jsonl" "$FIX/ix-cpi-victim.jsonl" "$FIX/log-tab-injection.jsonl" > "$W22/corpus.jsonl"
cp "$W22/corpus.jsonl" "$TT/corpus22.before"
printf 'previous\n' > "$W22/out/taken.txt"
for r in profile frames ix lamports tokens; do
  case "$r" in
    profile) set -- bash "$DNR/profile.sh" ;;
    frames) set -- python3 -I "$DNR/frames.py" ;;
    ix) set -- python3 -I "$DNR/frames.py" --instructions ;;
    *) set -- python3 -I "$DNR/deltas.py" "$r" ;;
  esac
  "$@" "$W22/corpus.jsonl" > "$TT/o22.stdout" 2>/dev/null
  "$@" --out "$W22/out/$r.txt" "$W22/corpus.jsonl" > "$TT/o22.out" 2>/dev/null
  code=$?
  if [[ "$code" == 0 && -s "$TT/o22.stdout" && ! -s "$TT/o22.out" ]] && cmp -s "$TT/o22.stdout" "$W22/out/$r.txt"; then
    ok "--out: $r writes what it prints on stdout into the file, and nothing on stdout"
  else
    bad "--out: $r -> exit $code, file and stdout differ"
  fi
  "$@" --out "$W22/corpus.jsonl" "$W22/corpus.jsonl" > /dev/null 2> "$TT/o22.err"
  c1=$?
  "$@" --out "$W22/out/taken.txt" "$W22/corpus.jsonl" > /dev/null 2>> "$TT/o22.err"
  c2=$?
  if [[ "$c1" == 2 && "$c2" == 2 && "$(cat "$W22/out/taken.txt")" == previous \
        && "$(grep -c 'already exists, and an output never replaces a file: name a new one$' "$TT/o22.err")" == 2 ]] \
     && cmp -s "$W22/corpus.jsonl" "$TT/corpus22.before"; then
    ok "--out: $r refuses an --out that exists, its own input corpus too (exit 2, both left as they were)"
  else
    bad "--out: $r with an existing --out -> exit $c1 / $c2 ($(tr '\n' ' ' < "$TT/o22.err"))"
  fi
done
eq "--out: no temporary file is left beside the outputs" "$(ls -A "$W22/out" | tr '\n' ' ')" "frames.txt ix.txt lamports.txt profile.txt taken.txt tokens.txt "
ln -s "$TT/elsewhere22/out.txt" "$W22/out-link.txt"
ln -s "$TT/elsewhere22" "$W22/dir-link"
for case in "a link|out-link.txt" "a path through a directory link in the working directory|dir-link/out.txt"; do
  res=""
  for r in profile frames lamports; do
    case "$r" in
      profile) ( cd "$W22" && bash "$DNR/profile.sh" --out "${case#*|}" corpus.jsonl ) > /dev/null 2> "$TT/o22.err" ;;
      frames) ( cd "$W22" && python3 -I "$DNR/frames.py" --out "${case#*|}" corpus.jsonl ) > /dev/null 2> "$TT/o22.err" ;;
      lamports) ( cd "$W22" && python3 -I "$DNR/deltas.py" lamports --out "${case#*|}" corpus.jsonl ) > /dev/null 2> "$TT/o22.err" ;;
    esac
    res="$res $?:$(grep -c 'is a symbolic link, or is reached through one inside the working directory; refusing it$' "$TT/o22.err")"
  done
  eq "--out: ${case%%|*} -> profile, frames and deltas refuse it (exit 2)" "${res# }" "2:1 2:1 2:1"
done
eq "--out: nothing was written through those links" "$(ls -A "$TT/elsewhere22" | tr '\n' ' ')" ""
# A run stopped by SIGTERM while it reads: stdin holds one transaction, then stays
# open until the test has stopped the run and lets the writer go.
partial22() { local f; for f in "$W22"/out/."$1".*.partial; do [[ -e "$f" ]] && return 0; done; return 1; }
for r in frames deltas; do
  rm -f "$TT/release22"
  case "$r" in
    frames) ( sed -n 1p "$FIX/clean-mixed.jsonl"; n=0; while [[ ! -e "$TT/release22" && "$n" -lt 400 ]]; do sleep 0.05; n=$((n + 1)); done ) \
              | python3 -I "$DNR/frames.py" --out "$W22/out/held-$r.txt" & ;;
    deltas) ( sed -n 1p "$FIX/clean-mixed.jsonl"; n=0; while [[ ! -e "$TT/release22" && "$n" -lt 400 ]]; do sleep 0.05; n=$((n + 1)); done ) \
              | python3 -I "$DNR/deltas.py" lamports --out "$W22/out/held-$r.txt" & ;;
  esac
  pid=$!
  n=0; while ! partial22 "held-$r.txt" && [[ "$n" -lt 200 ]]; do sleep 0.05; n=$((n + 1)); done
  kill -TERM "$pid" 2>/dev/null
  wait "$pid"
  code=$?
  touch "$TT/release22"
  eq "--out: $r stopped by SIGTERM -> exit 143, no file under the --out name, no temporary file left" \
    "$code|$([[ -e "$W22/out/held-$r.txt" ]] && echo written)|$(partial22 "held-$r.txt" && echo left)" "143||"
done

# ---------------------------------------------------------------------------
# 23. The --out directory is opened once, one name at a time from the working
#     directory, and the temporary file is made, linked and removed through it. A run
#     directory moved aside and replaced by a link to a directory outside, mid-run,
#     never receives the output through that link, and no temporary file is left:
#     frames.py and deltas.py finish in the directory they opened; profile.sh, which
#     writes its report to its private temp directory first, opens the --out
#     directory only then, and refuses the link (exit 2). A swap that keeps
#     alternating while each recipe runs many times changes nothing either.
# ---------------------------------------------------------------------------
W23="$TT/wd23"; mkdir -p "$W23" "$TT/outside23"
partial23() { local f; for f in "$1"/.*.partial; do [[ -e "$f" ]] && return 0; done; return 1; }
for r in frames deltas; do
  case "$r" in
    frames) set -- python3 -I "$DNR/frames.py" ;;
    deltas) set -- python3 -I "$DNR/deltas.py" lamports ;;
  esac
  mkdir -p "$W23/incident_$r"; rm -f "$TT/release23"
  ( sed -n 1p "$FIX/clean-mixed.jsonl"; n=0; while [[ ! -e "$TT/release23" && "$n" -lt 400 ]]; do sleep 0.05; n=$((n + 1)); done ) \
    | ( cd "$W23" && exec "$@" --out "incident_$r/out.txt" ) 2> /dev/null &
  pid=$!
  n=0; while ! partial23 "$W23/incident_$r" && [[ "$n" -lt 200 ]]; do sleep 0.05; n=$((n + 1)); done
  mv "$W23/incident_$r" "$W23/moved-$r" && ln -s "$TT/outside23" "$W23/incident_$r"
  touch "$TT/release23"
  wait "$pid"
  code=$?
  eq "--out: $r whose run directory is replaced by a link mid-run -> exit 0, the output in the directory it opened, nothing through the link" \
    "$code|$(ls -A "$W23/moved-$r" | tr '\n' ' ')|$(ls -A "$TT/outside23" | tr '\n' ' ')" "0|out.txt |"
done
mkdir -p "$TT/jq23" "$W23/incident_profile"; rm -f "$TT/release23"
printf '#!/bin/sh\n[ -e "%s/held" ] || { : > "%s/held"; n=0; while [ ! -e "%s" ] && [ "$n" -lt 400 ]; do sleep 0.05; n=$((n + 1)); done; }\nexec "%s" "$@"\n' \
  "$TT/jq23" "$TT/jq23" "$TT/release23" "$(command -v jq)" > "$TT/jq23/jq"
chmod +x "$TT/jq23/jq"
( cd "$W23" && PATH="$TT/jq23:$PATH" exec bash "$DNR/profile.sh" --out incident_profile/out.txt "$FIX/clean-mixed.jsonl" ) > /dev/null 2> "$TT/p23.err" &
pid=$!
n=0; while [[ ! -e "$TT/jq23/held" && "$n" -lt 200 ]]; do sleep 0.05; n=$((n + 1)); done
mv "$W23/incident_profile" "$W23/moved-profile" && ln -s "$TT/outside23" "$W23/incident_profile"
touch "$TT/release23"
wait "$pid"
code=$?
eq "--out: profile whose run directory is replaced by a link while its queries run -> refused (exit 2), nothing written inside or outside" \
  "$code|$(grep -c 'is a symbolic link, or is reached through one inside the working directory; refusing it$' "$TT/p23.err")|$(ls -A "$W23/moved-profile" | tr '\n' ' ')|$(ls -A "$TT/outside23" | tr '\n' ' ')" \
  "2|1||"
# race23.py: each recipe runs 40 times with --out incident_1/o-<recipe>-<k>.txt while
# a thread keeps moving incident_1 aside and putting a link to a directory outside in
# its place, then moving it back. Prints the files outside, the temporary files left,
# and whether any run exited 0.
cat > "$TT/race23.py" <<'PY'
import os, subprocess, sys, threading, time
base, dnr, corpus = sys.argv[1:4]
wt, outside, real = base + "/wt", base + "/outside", base + "/wt/incident_1.real"
os.makedirs(wt + "/incident_1")
os.makedirs(outside)
stop = []
def swap():
    while not stop:
        try:
            os.rename(wt + "/incident_1", real)
            os.symlink(outside, wt + "/incident_1")
            time.sleep(0.0003)
            os.unlink(wt + "/incident_1")
            os.rename(real, wt + "/incident_1")
            time.sleep(0.0015)
        except OSError:
            pass
runs = {"frames": ["python3", "-I", dnr + "/frames.py"], "deltas": ["python3", "-I", dnr + "/deltas.py", "lamports"],
        "profile": ["bash", dnr + "/profile.sh"]}
done = 0
t = threading.Thread(target=swap)
t.start()
try:
    for name, cmd in runs.items():
        for k in range(40):
            p = subprocess.run(cmd + ["--out", "incident_1/o-%s-%d.txt" % (name, k), corpus], cwd=wt,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            done += p.returncode == 0
finally:
    stop.append(1)
    t.join()
    if os.path.islink(wt + "/incident_1"):
        os.unlink(wt + "/incident_1")
    if os.path.isdir(real):
        os.rename(real, wt + "/incident_1")
left = [n for n in os.listdir(wt + "/incident_1") if not n.startswith("o-")]
print("%d|%d|%s" % (len(os.listdir(outside)), len(left), "some" if done else "none"))
PY
race23="$(python3 -I "$TT/race23.py" "$TT/race23" "$DNR" "$FIX/clean-mixed.jsonl")"
eq "--out: 120 runs under a directory swap -> no file outside, no temporary file left, and some runs completed" "$race23" "0|0|some"

if [[ "$fails" -ne 0 ]]; then
  echo "test-dnr: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr: all assertions passed"
