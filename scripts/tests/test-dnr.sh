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

# ---------------------------------------------------------------------------
# 6. collect.sh is gated: it refuses without --confirmed, and without $RPC_URL,
#    before any network call.
# ---------------------------------------------------------------------------
if ( unset RPC_URL; bash "$DNR/collect.sh" --out "${TMPDIR:-/tmp}/dnr_ct.$$" -- "$A_ADDR" ) >/dev/null 2>&1; then
  bad "collect: ran without --confirmed (must refuse)"
else
  ok "collect: refuses without --confirmed"
fi
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
#     system bash, keeps FAILED transactions, reports a history truncated by
#     --max-pages (and nothing else), passes --before through, counts every
#     getTransaction call toward --max-tx, and never prints the key.
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
# FAKE_CURL_TX_FAIL_ALL=1 fails every getTransaction (a rate-limited endpoint).
if m == "getTransaction" and os.environ.get("FAKE_CURL_TX_FAIL_ALL"):
    print(json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": 429, "message": "Too many requests"}})); sys.exit(0)
# FAKE_CURL_TX_FIXTURE=<file>: one signature, whose getTransaction result is that
# file's first line spliced in verbatim, so big integers arrive as literals.
fx = os.environ.get("FAKE_CURL_TX_FIXTURE")
if fx:
    tx = open(fx).readline().strip()
    if m == "getSignaturesForAddress":
        res = [] if "before" in p[1] else [{"signature": json.loads(tx)["transaction"]["signatures"][0], "slot": 403, "err": None, "blockTime": 1700000700}]
        print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": res}))
    else:
        sys.stdout.write('{"jsonrpc":"2.0","id":1,"result":' + tx + '}')
    sys.exit(0)
# FAKE_CURL_HISTORY=<n>: any address has n signatures (slots n..1, newest first),
# served at most `limit` per page and only older than `before`.
hist = int(os.environ.get("FAKE_CURL_HISTORY") or 0)
if m == "getSignaturesForAddress" and hist:
    b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    def hsig(k):
        out = ""
        while True:
            out, k = b58[k % 58] + out, k // 58
            if not k:
                return "Hist" + out.rjust(40, "1")
    slots = {hsig(k): k for k in range(1, hist + 1)}
    top = slots.get(p[1].get("before"), hist + 1) - 1
    res = [{"signature": hsig(k), "slot": k, "err": None, "blockTime": 1700000000 + k}
           for k in range(top, max(top - p[1]["limit"], 0), -1)]
    print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": res})); sys.exit(0)
# FAKE_CURL_SAMESLOT=1: two signatures in one slot, which the C and en_US
# collations would order differently.
if m == "getSignaturesForAddress" and os.environ.get("FAKE_CURL_SAMESLOT"):
    res = [] if "before" in p[1] else [
        {"signature": "SigbSameSlot111111111111111111111111111111", "slot": 5, "err": None, "blockTime": 1700000500},
        {"signature": "SigBSameSlot111111111111111111111111111111", "slot": 5, "err": None, "blockTime": 1700000500},
    ]
    print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": res})); sys.exit(0)
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
# The --confirmed gate alone: a usable $RPC_URL and a reachable (fake) endpoint, yet
# no --confirmed means exit 2 and no call at all.
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/c0" --max-pages 1 -- "$A_ADDR" ) > "$TT/c0.out" 2>&1
code=$?
if [[ "$code" == 2 && ! -e "$TT/c0" && ! -s "$FAKE_CURL_LOG" ]] && grep -q 'pass --confirmed' "$TT/c0.out"; then
  ok "collect: without --confirmed, a usable endpoint gets no call (exit 2)"
else
  bad "collect: ran without --confirmed -> exit $code"
fi
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/?api-key=LEAKME42" \
    bash "$DNR/collect.sh" --out "$TT/c" --confirmed --since 1 --max-pages 1 --before "$CURSOR" -- "$A_ADDR" ) > "$TT/c.out" 2>&1
code=$?
eq "collect: exits 0 against the fake RPC (system bash)" "$code" "0"
eq "collect: fetched both the successful AND the failed transaction" \
  "$(grep -c . "$TT/c/transactions.jsonl" 2>/dev/null || true)" "2"
if ! grep -q 'truncated by --max-pages' "$TT/c.out" && [[ ! -s "$TT/c/collection-gaps.tsv" ]]; then
  ok "collect: a short last page at the page cap is the end of history (no truncation notice, no gap)"
else
  bad "collect: a short last page was reported as truncated"
fi
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
# null result), a failed signature page, an unreached window and the --max-tx cap
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
# Within one slot the RPC's own newest-first order decides what --max-tx keeps, in
# any locale: the sort is stable, on the slot only, under LC_ALL=C.
for loc in C en_US.UTF-8; do
  ( PATH="$TT/bin:$PATH" LC_ALL="$loc" FAKE_CURL_SAMESLOT=1 RPC_URL="https://rpc.example.test/" \
      bash "$DNR/collect.sh" --out "$TT/loc-$loc" --confirmed --max-tx 1 -- "$A_ADDR" ) > /dev/null 2>&1
done
eq "collect: the same-slot signature kept by --max-tx 1 is the RPC's first, under C and en_US.UTF-8" \
  "$(jq -r '.transaction.signatures[0]' "$TT/loc-C/transactions.jsonl")/$(jq -r '.transaction.signatures[0]' "$TT/loc-en_US.UTF-8/transactions.jsonl")" \
  "SigbSameSlot111111111111111111111111111111/SigbSameSlot111111111111111111111111111111"
ctl_c="$(printf '5 SigbX\n5 SigBX\n' | LC_ALL=C sort -k1,1nr 2>/dev/null | sed -n 1p)"
ctl_u="$(printf '5 SigbX\n5 SigBX\n' | LC_ALL=en_US.UTF-8 sort -k1,1nr 2>/dev/null | sed -n 1p)"
if [[ "$ctl_c" != "$ctl_u" ]]; then
  ok "collect: control, a plain sort -k1,1nr breaks same-slot ties by locale ('$ctl_c' vs '$ctl_u')"
else
  ok "collect: control not exercised here (no en_US.UTF-8 collation)"
fi
eq "collect: the --max-tx cap is one gap row naming the first signature not fetched" \
  "$(cut -f1 "$TT/c2/collection-gaps.tsv")|$(grep -c 'collection gaps: 1 ' "$TT/c2.out")" "SigFail|1"
# Paging stops at the end of history (a page shorter than 1000), when --since is
# crossed, or at --max-pages; only the last, after a full page, truncates history,
# and then the notice and a gap row give the cursor that resumes it, whatever the
# window. --max-tx 0 keeps these runs to paging.
hrun() {  # hrun <out> <history size> <collect args...>: page a served history
  local o="$1" h="$2"; shift 2
  ( PATH="$TT/bin:$PATH" FAKE_CURL_HISTORY="$h" RPC_URL="https://rpc.example.test/" \
      bash "$DNR/collect.sh" --out "$TT/$o" --confirmed --max-tx 0 "$@" -- "$A_ADDR" ) > "$TT/$o.out" 2>&1
}
truncated() { grep -c 'truncated by --max-pages' "$TT/$1/collection-gaps.tsv" 2>/dev/null || true; }
hrun h3 3 --since 1600000000 --max-pages 1
eq "collect: 3 signatures, a short page at the cap, --since unreached -> no truncation" "$(truncated h3)/$(grep -c 'truncated' "$TT/h3.out")" "0/0"
hrun h3u 3 --until 100 --max-pages 1
eq "collect: 3 signatures, --until only, short page -> no truncation" "$(truncated h3u)/$(grep -c 'truncated' "$TT/h3u.out")" "0/0"
hrun h1500 1500 --max-pages 2
eq "collect: 1,500 signatures over 2 pages (1,000 + 500) -> no truncation, all collected" \
  "$(truncated h1500)/$(grep -c . "$TT/h1500/signatures.jsonl")" "0/1500"
hrun h2500 2500 --max-pages 2
eq "collect: 2,500 signatures, no window, full page at --max-pages 2 -> truncated, gap row" \
  "$(truncated h2500)/$(grep -c 'truncated by --max-pages=2 after 2000 signatures' "$TT/h2500.out")" "1/1"
cursor="$(sed -n 's/.*resume into a new --out with --before \([1-9A-HJ-NP-Za-km-z]*\).*/\1/p' "$TT/h2500/collection-gaps.tsv")"
eq "collect: the resume cursor is the oldest signature collected" "$cursor" "$(jq -r '.signature' "$TT/h2500/signatures.jsonl" | tail -n 1)"
hrun h2500r 2500 --max-pages 2 --before "$cursor"
eq "collect: resuming with --before collects exactly the rest, with no notice" \
  "$(grep -c . "$TT/h2500r/signatures.jsonl")/$(truncated h2500r)/$(cat "$TT/h2500/signatures.jsonl" "$TT/h2500r/signatures.jsonl" | jq -r .signature | sort -u | grep -c .)" "500/0/2500"
hrun h2500u 2500 --until 1700000100 --max-pages 1
if grep -q 'nothing at or before --until 1700000100 was collected' "$TT/h2500u/collection-gaps.tsv"; then
  ok "collect: --until only, full page at the cap above --until -> truncated, nothing inside the window"
else
  bad "collect: --until-only truncation not reported ($(cat "$TT/h2500u/collection-gaps.tsv"))"
fi
hrun h2500s 2500 --since 1700002000 --max-pages 2
eq "collect: --since crossed inside the cap -> no truncation" "$(truncated h2500s)" "0"
# A second pass into an --out that already holds a corpus is refused, so the first
# pass survives — and so is an --out holding only an earlier transactions.jsonl.
cp "$TT/c/signatures.jsonl" "$TT/c.sig.before"
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/c" --confirmed --max-pages 1 -- "$A_ADDR" ) > "$TT/c4.out" 2>&1
code=$?
if [[ "$code" == 2 ]] && grep -q 'use a new --out' "$TT/c4.out" && cmp -s "$TT/c/signatures.jsonl" "$TT/c.sig.before"; then
  ok "collect: refuses to reuse an --out that holds a corpus (exit 2, corpus intact)"
else
  bad "collect: reuse of a filled --out -> exit $code"
fi
mkdir -p "$TT/c6"; cp "$TT/c/transactions.jsonl" "$TT/c6/transactions.jsonl"
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/c6" --confirmed --max-pages 1 -- "$A_ADDR" ) > /dev/null 2>&1
code=$?
if [[ "$code" == 2 && ! -e "$TT/c6/signatures.jsonl" ]] && cmp -s "$TT/c6/transactions.jsonl" "$TT/c/transactions.jsonl"; then
  ok "collect: an earlier transactions.jsonl alone is never truncated (exit 2, file intact)"
else
  bad "collect: an --out holding transactions.jsonl -> exit $code"
fi
# --max-tx counts every getTransaction call, failed ones included, and 10 failures
# in a row stop the run with a gap row for the rest.
txcalls() { grep -c '"method": "getTransaction"' "$FAKE_CURL_LOG" 2>/dev/null || true; }
before_tx="$(txcalls)"
( PATH="$TT/bin:$PATH" FAKE_CURL_TX_FAIL_ALL=1 FAKE_CURL_HISTORY=30 RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/f2" --confirmed --max-tx 2 -- "$A_ADDR" ) > "$TT/f2.out" 2>&1
eq "collect: an always-failing endpoint with --max-tx 2 gets exactly 2 getTransaction calls" "$(( $(txcalls) - before_tx ))" "2"
before_tx="$(txcalls)"
( PATH="$TT/bin:$PATH" FAKE_CURL_TX_FAIL_ALL=1 FAKE_CURL_HISTORY=30 RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/f10" --confirmed --max-tx 100 -- "$A_ADDR" ) > "$TT/f10.out" 2>&1
code=$?
eq "collect: 10 failed calls in a row stop the run (10 calls, not 30)" "$(( $(txcalls) - before_tx ))" "10"
if [[ "$code" == 0 ]] && grep -q 'endpoint failing (rate limit or outage): 10 getTransaction calls in a row failed, so the run stops — 0 transactions collected, 11 collection gaps' "$TT/f10.out" \
   && grep -q 'in a row failed (rate limit or outage); this and 19 older signatures' "$TT/f10/collection-gaps.tsv"; then
  ok "collect: the stop is reported (collected and gap counts) and the rest is one gap row"
else
  bad "collect: consecutive-failure stop not reported ($(grep 'endpoint\|gaps' "$TT/f10.out" | tr '\n' ' '))"
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
# 11. snapshot-program.sh against a fake `solana`: keeps bin/<id>@<slot>.so, prints
#     the ledger line (owner, last-deployed slot, zero-trimmed hash, padding), and
#     redacts a CLI error. The CLI runs from a throwaway -C config: no URL in argv, a
#     keypair path that does not exist, a 0700 directory removed on exit, and a
#     blocker if the CLI ignores the config. The fake mirrors solana-cli 3.1.10:
#     it reads a config only when it holds websocket_url; `program show` and
#     `program-v4 show` need a signer unless --buffer-authority / --authority is
#     given; `program show` and `program dump` refuse a loader-v4 program ("is not an
#     SBF program"), which `program-v4 show` / `program-v4 download` read; and a
#     BPFLoader2 program's record has no slot or authority. FAKE_SOLANA_SLOTS lists
#     the last-deployed slot each successive record read returns.
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
kind = "v4" if os.environ.get("FAKE_SOLANA_V4") else "v2" if os.environ.get("FAKE_SOLANA_V2") else \
       "wallet" if os.environ.get("FAKE_SOLANA_NOTPROG") else "v3"
owner = {"v4": "LoaderV411111111111111111111111111111111111", "v2": "BPFLoader2111111111111111111111111111111111",
         "wallet": "11111111111111111111111111111111", "v3": "BPFLoaderUpgradeab1e11111111111111111111111"}[kind]
pid = a[a.index("--program-id") + 1] if "--program-id" in a else (a[2] if len(a) > 2 else "?")
slots = (os.environ.get("FAKE_SOLANA_SLOTS") or "12345").split(",")
state = os.environ["FAKE_SOLANA_SEEN"] + ".slot"
def current():
    try:
        return int(open(state).read())
    except (OSError, ValueError):
        return 0
def read_record():  # each record read moves to the next listed slot (the last one repeats)
    n = current() + 1
    open(state, "w").write(str(n))
    return slots[min(n, len(slots)) - 1]
def elf():  # the bytes depend on the slot now deployed
    k = slots[min(max(current(), 1), len(slots)) - 1]
    return b"\x7fELF" + int(k).to_bytes(8, "little") + bytes(range(1, 30)) + b"\x00" * 500
def need_signer(flag):
    if flag not in a and not os.path.exists(kp):
        sys.stderr.write(f'Error: Dynamic program error: No default signer found, run "solana-keygen new -o {kp}"\n'); sys.exit(1)
if a[:1] == ["account"]:
    print(json.dumps({"pubkey": a[1], "account": {"lamports": 1, "data": ["", "base64"], "owner": owner, "executable": kind != "wallet"}}))
elif a[:2] == ["program", "show"]:
    need_signer("--buffer-authority")
    if kind in ("v4", "wallet"):
        sys.stderr.write(f"Error: {pid} is not an SBF program\n"); sys.exit(1)
    if kind == "v2":
        print(f"Program Id: {pid}\nOwner: {owner}\nData Length: 100 (0x64) bytes")
    else:
        print(f"Program Id: {pid}\nOwner: {owner}\nProgramData Address: PdA111\nAuthority: Auth111\nLast Deployed In Slot: {read_record()}\nData Length: 100 (0x64) bytes\nBalance: 1 SOL")
elif a[:2] == ["program", "dump"]:
    if kind in ("v4", "wallet"):
        sys.stderr.write(f"Error: {pid} is not an SBF program\n"); sys.exit(1)
    open(a[3], "wb").write(elf())
    print(f"Wrote program to {a[3]}")
elif a[:2] == ["program-v4", "show"] and kind == "v4":
    need_signer("--authority")
    print(f"Program Id: {pid}\nOwner: {owner}\nAuthority: Auth111\nLast Deployed In Slot: {read_record()}\nStatus: deployed\nData Length: 100 (0x64) bytes")
elif a[:2] == ["program-v4", "download"] and kind == "v4":
    open(a[2], "wb").write(elf())
    print(f"Wrote program to {a[2]}")
else:
    sys.stderr.write("fake solana: refusing unexpected subcommand\n"); sys.exit(9)
PY
chmod +x "$TT/bin/solana"
export FAKE_SOLANA_ARGV="$TT/solana.argv" FAKE_SOLANA_SEEN="$TT/solana.seen"
PID="ProgTest1111111111111111111111111111111111"   # 42 base58 characters
snap="$(PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/v2/LEAKME42" bash "$DNR/snapshot-program.sh" "$PID" "$TT/inc" 2>&1)"
code=$?
eq "snapshot: exits 0 with the fake CLI" "$code" "0"
sha_trim() { python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\x00")).hexdigest())' "$1" 2>/dev/null; }
want="$(sha_trim "$TT/inc/bin/$PID@12345.so")"
case "$snap" in
  *"last_deployed_slot=12345"*"sha256_zero_trimmed=$want"*"padding_bytes=500 file=bin/$PID@12345.so"*) ok "snapshot: ledger line carries slot, zero-trimmed hash, padding and bin/<id>@<slot>.so" ;;
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
snaprun() {  # snaprun <dir> [VAR=value ...]: one snapshot with the fake CLI, output in <dir>.out
  local d="$1"; shift
  rm -f "$FAKE_SOLANA_SEEN.slot"
  env PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" "$@" bash "$DNR/snapshot-program.sh" "$PID" "$d" > "$d.out" 2>&1
}
# A loader-v4 program: `program show` refuses it, so the owner comes from the account
# and the bytes from program-v4 show / download.
snaprun "$TT/inc3" FAKE_SOLANA_V4=1
code=$?
if [[ "$code" == 0 ]] && grep -q "owner=LoaderV411111111111111111111111111111111111 last_deployed_slot=12345 authority=Auth111 status=deployed .* file=bin/$PID@12345.so" "$TT/inc3.out" \
   && [[ "$(head -c 4 "$TT/inc3/bin/$PID@12345.so" | od -An -tx1 | tr -d ' \n')" == 7f454c46 ]]; then
  ok "snapshot: a loader-v4 program is read with program-v4 show and kept from program-v4 download"
else
  bad "snapshot: loader-v4 program -> exit $code ($(tr '\n' ' ' < "$TT/inc3.out"))"
fi
snaprun "$TT/inc3b" FAKE_SOLANA_NOTPROG=1
code=$?
if [[ "$code" == 3 && ! -e "$TT/inc3b/bin" ]] && grep -q 'is not a program the solana CLI can dump (owner 11111111111111111111111111111111)' "$TT/inc3b.out"; then
  ok "snapshot: an id that is not a program names its owner in a blocker (exit 3), nothing written"
else
  bad "snapshot: not-a-program id -> exit $code ($(tr '\n' ' ' < "$TT/inc3b.out"))"
fi
snaprun "$TT/inc3c" FAKE_SOLANA_V2=1
if grep -q "owner=BPFLoader2111111111111111111111111111111111 last_deployed_slot=n/a (immutable loader) authority=none sha256_zero_trimmed=.* file=bin/$PID@immutable.so" "$TT/inc3c.out" \
   && [[ -s "$TT/inc3c/bin/$PID@immutable.so" ]]; then
  ok "snapshot: a BPFLoader2 program has no deploy slot: n/a (immutable loader), bin/<id>@immutable.so"
else
  bad "snapshot: BPFLoader2 program ($(tr '\n' ' ' < "$TT/inc3c.out"))"
fi
# Snapshots are never overwritten. A later run at a new slot (a hotfix) adds a file
# next to the preserved one; a run at the same slot keeps the file it finds when the
# bytes match, and stops with a blocker, writing nothing, when they do not.
snaprun "$TT/keep"
cp "$TT/keep/bin/$PID@12345.so" "$TT/keep.orig.so"
snaprun "$TT/keep" FAKE_SOLANA_SLOTS=12400
if [[ -s "$TT/keep/bin/$PID@12400.so" && -s "$TT/keep/bin/$PID@12400.show.txt" ]] && cmp -s "$TT/keep/bin/$PID@12345.so" "$TT/keep.orig.so" \
   && ! cmp -s "$TT/keep/bin/$PID@12400.so" "$TT/keep.orig.so"; then
  ok "snapshot: two runs at different slots keep both binaries; the first is unchanged"
else
  bad "snapshot: a second slot replaced or lost a binary ($(ls "$TT/keep/bin" | tr '\n' ' '))"
fi
snaprun "$TT/keep"
code=$?
if [[ "$code" == 0 ]] && grep -q "kept bin/$PID@12345.so" "$TT/keep.out" && cmp -s "$TT/keep/bin/$PID@12345.so" "$TT/keep.orig.so"; then
  ok "snapshot: a rerun at the same slot with the same bytes keeps the preserved file"
else
  bad "snapshot: same-slot rerun -> exit $code"
fi
printf 'x' >> "$TT/keep/bin/$PID@12345.so"; cp "$TT/keep/bin/$PID@12345.so" "$TT/keep.changed.so"
snaprun "$TT/keep"
code=$?
if [[ "$code" == 3 ]] && grep -q 'already exists with other bytes' "$TT/keep.out" && cmp -s "$TT/keep/bin/$PID@12345.so" "$TT/keep.changed.so" \
   && [[ "$(ls "$TT/keep/bin" | grep -c .)" == 4 ]]; then
  ok "snapshot: other bytes under the same slot stop with a blocker; the file is kept, nothing is written"
else
  bad "snapshot: same slot, other bytes -> exit $code ($(ls "$TT/keep/bin" | tr '\n' ' '))"
fi
# A redeploy between the record read and the dump: the slot read after the dump
# differs, so it dumps once more; a slot that moves twice is a blocker.
dumps() { grep -c '"dump"\|"download"' "$FAKE_SOLANA_ARGV"; }
d0="$(dumps)"; snaprun "$TT/race1" FAKE_SOLANA_SLOTS=100,200
code=$?
if [[ "$code" == 0 && "$(( $(dumps) - d0 ))" == 2 ]] && grep -q "last_deployed_slot=200 .* file=bin/$PID@200.so" "$TT/race1.out" && [[ ! -e "$TT/race1/bin/$PID@100.so" ]]; then
  ok "snapshot: a slot that moved during the dump is dumped again and kept under the new slot"
else
  bad "snapshot: moved slot -> exit $code ($(tr '\n' ' ' < "$TT/race1.out"))"
fi
snaprun "$TT/race2" FAKE_SOLANA_SLOTS=100,200,300
code=$?
if [[ "$code" == 3 && ! -e "$TT/race2/bin" ]] && grep -q 'was redeployed during the snapshot' "$TT/race2.out"; then
  ok "snapshot: a slot that moves twice stops with a blocker (exit 3), nothing written"
else
  bad "snapshot: slot moving twice -> exit $code ($(tr '\n' ' ' < "$TT/race2.out"))"
fi
# The id is used in file names: anything but a base58 key is refused before any write.
for badid in '../../escape' 'Prog111' 'ProgTest111111111111111111111111111111111/x' 'Prog0OIl1111111111111111111111111111111111'; do
  PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" "$badid" "$TT/inc5" >/dev/null 2>&1
  code=$?
  if [[ "$code" == 2 && ! -e "$TT/inc5" ]]; then ok "snapshot: refuses the id '$badid' (exit 2, nothing written)"; else bad "snapshot: id '$badid' -> exit $code"; fi
done
# python3 hashes the dump: on a PATH without it, a named blocker (exit 3) comes
# before anything is written.
mkdir -p "$TT/nopy"
for t in dirname basename; do ln -s "$(command -v "$t")" "$TT/nopy/$t"; done
PATH="$TT/nopy:$TT/bin" RPC_URL="https://rpc.example.test/" "$(command -v bash)" "$DNR/snapshot-program.sh" "$PID" "$TT/inc-nopy" > "$TT/nopy.out" 2>&1
code=$?
if [[ "$code" == 3 && ! -e "$TT/inc-nopy" ]] && grep -q '^\[blocker\] python3 not on PATH' "$TT/nopy.out"; then
  ok "snapshot: without python3 on PATH, a named blocker (exit 3) and nothing written"
else
  bad "snapshot: no python3 -> exit $code ($(tr '\n' ' ' < "$TT/nopy.out"))"
fi
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
            bal = lambda o, a: {"owner": o, "mint": "MintBig", "uiTokenAmount": {"amount": str(a)}}
            f.write(json.dumps({"meta": {"err": None,
                "preTokenBalances": [bal("Vault", 2**64), bal("Attacker", 0)],
                "postTokenBalances": [bal("Vault", 2**64 - amt), bal("Attacker", amt)]},
                "transaction": {"signatures": ["S%d" % i]}}) + "\n")' "$TT/big-a.jsonl" "$TT/big-b.jsonl"
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
if [[ "$c1" == 0 && "$c2" == 0 && -s "$REPO/incident_5/corpus/transactions.jsonl" && -s "$REPO/incident_5/bin/$PID@12345.so" ]]; then
  ok "run dir: an untracked, link-free incident_<n>/ in a repository is accepted (control)"
else
  bad "run dir: the untracked control dir -> collect exit $c1, snapshot exit $c2"
fi

# ---------------------------------------------------------------------------
# 16. Big integers survive jq < 1.7. A stand-in jq rounds every number it reads on
#     stdin to a double first, as jq 1.6 does (the apt package on Ubuntu 22.04 and
#     Debian 12). Through it, the old `jq -c .result` path rounds the fixture's
#     lamports (the control); collect.sh's corpus line comes out byte-identical to
#     the RPC's literal, and deltas.py stays exact.
# ---------------------------------------------------------------------------
REAL_JQ="$(command -v jq)"; export REAL_JQ
mkdir -p "$TT/jq16"
cat > "$TT/jq16/jq" <<'PY'
#!/usr/bin/env python3
import json, os, subprocess, sys
args, real = sys.argv[1:], os.environ["REAL_JQ"]
if "--version" in args or any(os.path.isfile(a) for a in args):
    os.execv(real, [real] + args)
def dump(v):
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() else repr(v)
    if isinstance(v, list):
        return "[" + ",".join(dump(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k) + ":" + dump(x) for k, x in v.items()) + "}"
    return json.dumps(v)
data, dec, i, out = sys.stdin.read(), json.JSONDecoder(parse_int=float), 0, []
while True:
    while i < len(data) and data[i] in " \t\r\n":
        i += 1
    if i >= len(data):
        break
    v, i = dec.raw_decode(data, i)
    out.append(dump(v))
sys.exit(subprocess.run([real] + args, input="\n".join(out).encode()).returncode)
PY
chmod +x "$TT/jq16/jq"
ctl="$(printf '{"result":%s}' "$(cat "$FIX/lamports-over-2-53.jsonl")" | PATH="$TT/jq16:$PATH" jq -c .result \
  | python3 -I "$DNR/deltas.py" lamports | awk -F'\t' '$2=="BigOne"{print $3}')"
eq "big ints: control, through the jq 1.6 stand-in jq -c .result rounds BigOne's +1 to +2" "$ctl" "2"
( PATH="$TT/jq16:$TT/bin:$PATH" FAKE_CURL_TX_FIXTURE="$FIX/lamports-over-2-53.jsonl" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/big16" --confirmed -- "$A_ADDR" ) > "$TT/big16.out" 2>&1
if cmp -s "$TT/big16/transactions.jsonl" "$FIX/lamports-over-2-53.jsonl"; then
  ok "big ints: with jq 1.6, collect.sh writes the transaction byte-identical to the RPC's literal"
else
  bad "big ints: the corpus line differs from the RPC's literal ($(head -c 200 "$TT/big16/transactions.jsonl" 2>/dev/null))"
fi
eq "big ints: deltas over that corpus stay exact (BigOne, BigTwo)" \
  "$(python3 -I "$DNR/deltas.py" lamports "$TT/big16/transactions.jsonl" | awk -F'\t' '{printf "%s=%s ", $2, $3}')" "BigOne=1 BigTwo=1 "

# ---------------------------------------------------------------------------
# 17. A second collection into an incident goes to corpus-2/ and is not refused;
#     the recipes then read corpus*/ and count a transaction held by both corpora
#     once (first occurrence wins), so damage figures are not doubled.
# ---------------------------------------------------------------------------
mkdir "$TT/incident_21"
for c in corpus corpus-2; do
  [[ "$c" == corpus ]] || mkdir "$TT/incident_21/$c"
  ( PATH="$TT/bin:$PATH" FAKE_CURL_TX_FIXTURE="$FIX/same-owner-drain.jsonl" RPC_URL="https://rpc.example.test/" \
      bash "$DNR/collect.sh" --out "$TT/incident_21/$c" --confirmed -- "$A_ADDR" ) > "$TT/incident_21.$c.out" 2>&1
  eq "two corpora: collecting into incident_21/$c succeeds" "$?" "0"
done
both="$(python3 -I "$DNR/deltas.py" tokens "$TT"/incident_21/corpus*/transactions.jsonl 2> "$TT/both.err")"
eq "two corpora: a drain held by both is counted once (3 rows, VaultPDA -140)" \
  "$(printf '%s\n' "$both" | grep -c .)/$(printf '%s\n' "$both" | owner_sum VaultPDA)" "3/-140"
if grep -q 'skipped 1 transaction(s) already read under the same signature' "$TT/both.err"; then ok "two corpora: deltas.py says how many copies it skipped"; else bad "two corpora: no skipped-copy note"; fi
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
if printf '%s\n' "$prof2" | grep -q '^-- skipped: 3 transaction(s) already read under the same signature$'; then
  ok "dedupe: profile reports the copies it skipped"
else
  bad "dedupe: profile did not report skipped copies"
fi

# ---------------------------------------------------------------------------
# 18. profile.sh skips and counts malformed lines instead of stopping: a corpus
#     with invalid JSON and a wrongly shaped object in the middle still profiles
#     its three good transactions, exits 0, and reports the two lines it skipped.
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

if [[ "$fails" -ne 0 ]]; then
  echo "test-dnr: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr: all assertions passed"
