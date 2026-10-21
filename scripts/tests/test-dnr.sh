#!/usr/bin/env bash
# test-dnr.sh — self-test for the detection & response recipes (scripts/dnr/).
#
# Runnable from the repo root with bash >= 3.2, using only jq / python3 / awk / sed.
# No network. Exits non-zero on the first failed assertion. The integrator wires a
# CI step that runs every scripts/tests/*.sh.
#
# Each assertion pins a property a must-fix demanded, against the committed
# adversarial fixtures, so "validated" claims in the docs point at a real check.

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

# ---------------------------------------------------------------------------
# 1. frames.py attributes program logs by frame and never splits on an embedded
#    newline. The newline-injection fixture carries a forged "invoke [1]" inside
#    a Program log: payload.
# ---------------------------------------------------------------------------
logs="$(python3 "$DNR/frames.py" "$FIX/log-newline-injection.jsonl")"
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
tok="$(python3 "$DNR/deltas.py" tokens "$FIX/token-amount-over-2-53.jsonl")"
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
lam="$(python3 "$DNR/deltas.py" lamports "$FIX/clean-mixed.jsonl")"
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
# 5. redact.sh strips keys wherever a provider puts them, and keeps the text
#    around the URL intact (a closing paren or quote is not eaten).
# ---------------------------------------------------------------------------
red() { printf '%s\n' "$1" | bash "$DNR/redact.sh"; }
r1="$(red 'error: failed POST https://rpc.example.com/?api-key=SECRET123456 after 1 try')"
case "$r1" in *SECRET123456*) bad "redact: query api-key leaked ($r1)" ;; *REDACTED*) ok "redact: query-string key removed" ;; *) bad "redact: unexpected ($r1)" ;; esac
r2="$(red 'see (https://solana-mainnet.g.alchemy.com/v2/ALCHEMYKEY123) now')"
eq "redact: path-segment key (/v2/<key>) removed, closing paren kept" "$r2" "see (https://solana-mainnet.g.alchemy.com/REDACTED) now"
r3="$(red 'url https://rpc.ankr.com/solana/ANKRKEY456 timed out')"
eq "redact: second-segment key (/solana/<key>) removed" "$r3" "url https://rpc.ankr.com/REDACTED timed out"
r4="$(red 'auth https://user:PASSW0RD@host.example.com/rpc failed')"
eq "redact: userinfo key removed" "$r4" "auth https://REDACTED@host.example.com/REDACTED failed"
r5="$(red 'header api-key=BAREKEY99&x=1 rejected')"
eq "redact: bare api-key=value removed" "$r5" "header api-key=REDACTED&x=1 rejected"
r6="$(red 'plain text, no url')"
eq "redact: text without a URL is unchanged" "$r6" "plain text, no url"

# ---------------------------------------------------------------------------
# 6. collect.sh is gated: it refuses without --confirmed, and without $RPC_URL,
#    before any network call.
# ---------------------------------------------------------------------------
if ( unset RPC_URL; bash "$DNR/collect.sh" --out "${TMPDIR:-/tmp}/dnr_ct.$$" -- Addr1 ) >/dev/null 2>&1; then
  bad "collect: ran without --confirmed (must refuse)"
else
  ok "collect: refuses without --confirmed"
fi
if ( unset RPC_URL; bash "$DNR/collect.sh" --out "${TMPDIR:-/tmp}/dnr_ct.$$" --confirmed -- Addr1 ) >/dev/null 2>&1; then
  bad "collect: ran without \$RPC_URL (must refuse)"
else
  ok "collect: refuses without \$RPC_URL"
fi

# ---------------------------------------------------------------------------
# 7. deltas.py sums one owner's token accounts per mint (no overwrite), and keeps
#    lamport math exact above 2^53.
# ---------------------------------------------------------------------------
mv="$(python3 "$DNR/deltas.py" tokens "$FIX/same-owner-move.jsonl" | grep -c . || true)"
eq "deltas tokens: internal move between one owner's accounts nets to zero (no row)" "$mv" "0"
dr="$(python3 "$DNR/deltas.py" tokens "$FIX/same-owner-drain.jsonl")"
eq "deltas tokens: two-account drain is the sum (-140), not the last account" \
  "$(printf '%s\n' "$dr" | awk -F'\t' '$2=="VaultPDA"{print $4}')" "-140"
eq "deltas tokens: attacker receives +140" \
  "$(printf '%s\n' "$dr" | awk -F'\t' '$2=="Attacker"{print $4}')" "140"
bl="$(python3 "$DNR/deltas.py" lamports "$FIX/lamports-over-2-53.jsonl")"
eq "deltas lamports: +1 above 2^53 is exact (BigOne)" "$(printf '%s\n' "$bl" | awk -F'\t' '$2=="BigOne"{print $3}')" "1"
eq "deltas lamports: +1 above 2^53 is exact (BigTwo)" "$(printf '%s\n' "$bl" | awk -F'\t' '$2=="BigTwo"{print $3}')" "1"

# ---------------------------------------------------------------------------
# 8. frames.py: a tab-separated forged record plus a newline-forged invoke inside
#    Program log payloads yields valid JSONL, attributed to the real invoker only.
# ---------------------------------------------------------------------------
tabrows="$(python3 "$DNR/frames.py" "$FIX/log-tab-injection.jsonl")"
eq "frames: tab/newline payloads stay 2 records" "$(printf '%s\n' "$tabrows" | grep -c . || true)" "2"
bad_json="$(printf '%s\n' "$tabrows" | python3 -c 'import sys,json
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
#     system bash, keeps FAILED transactions, reports an unreached window, passes
#     --before through, and never prints the key.
# ---------------------------------------------------------------------------
mkdir -p "$TT/bin"
cat > "$TT/bin/curl" <<'PY'
#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
body = args[args.index("-d") + 1]
url = args[-1]
sys.stderr.write(f"curl: note: talking to {url}\n")
req = json.loads(body)
with open(os.environ["FAKE_CURL_LOG"], "a") as log:
    log.write(json.dumps(req) + "\n")
m, p = req["method"], req["params"]
if m == "getSignaturesForAddress":
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
export FAKE_CURL_LOG="$TT/curl.log"
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/?api-key=LEAKME42" \
    bash "$DNR/collect.sh" --out "$TT/c" --confirmed --since 1 --max-pages 1 --before SigStart -- AddrA ) > "$TT/c.out" 2>&1
code=$?
eq "collect: exits 0 against the fake RPC (system bash)" "$code" "0"
eq "collect: fetched both the successful AND the failed transaction" \
  "$(grep -c . "$TT/c/transactions.jsonl" 2>/dev/null || true)" "2"
if grep -q 'window not reached' "$TT/c.out"; then ok "collect: reports the unreached window when the page cap stops first"; else bad "collect: no 'window not reached' notice"; fi
if grep -q '"before": "SigStart"' "$FAKE_CURL_LOG"; then ok "collect: --before passed through to the first page"; else bad "collect: --before not passed through"; fi
if grep -q 'LEAKME42' "$TT/c.out" "$TT/c/signatures.jsonl" "$TT/c/transactions.jsonl"; then
  bad "collect: the key leaked into output"
else
  ok "collect: key absent from stdout/stderr and corpus files"
fi
if grep -q 'provider: rpc.example.test ' "$TT/c.out"; then ok "collect: provider disclosed as host only"; else bad "collect: provider line wrong"; fi

# ---------------------------------------------------------------------------
# 11. snapshot-program.sh against a fake `solana`: writes bin/<id>.so, prints the
#     ledger line (owner, last-deployed slot, zero-trimmed hash, padding), redacts a
#     CLI error, and stops with a blocker for loader-v4.
# ---------------------------------------------------------------------------
cat > "$TT/bin/solana" <<'PY'
#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
url = a[a.index("--url") + 1] if "--url" in a else ""
if os.environ.get("FAKE_SOLANA_FAIL"):
    sys.stderr.write(f"Error: RPC request error: cluster version query failed: {url}\n"); sys.exit(1)
owner = "LoaderV411111111111111111111111111111111111" if os.environ.get("FAKE_SOLANA_V4") else "BPFLoaderUpgradeab1e11111111111111111111111"
if a[:2] == ["program", "show"]:
    print(f"Program Id: {a[2]}\nOwner: {owner}\nProgramData Address: PdA111\nAuthority: Auth111\nLast Deployed In Slot: 12345\nData Length: 100 (0x64) bytes\nBalance: 1 SOL")
elif a[:2] == ["program", "dump"]:
    open(a[3], "wb").write(b"\x7fELF" + bytes(range(1, 30)) + b"\x00" * 500)
    print(f"Wrote program to {a[3]}")
else:
    sys.stderr.write("fake solana: refusing unexpected subcommand\n"); sys.exit(9)
PY
chmod +x "$TT/bin/solana"
snap="$(PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/v2/LEAKME42" bash "$DNR/snapshot-program.sh" Prog111 "$TT/inc" 2>&1)"
code=$?
eq "snapshot: exits 0 with the fake CLI" "$code" "0"
want="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\x00")).hexdigest())' "$TT/inc/bin/Prog111.so" 2>/dev/null)"
case "$snap" in
  *"last_deployed_slot=12345"*"sha256_zero_trimmed=$want"*"padding_bytes=500"*) ok "snapshot: ledger line carries slot, zero-trimmed hash and padding" ;;
  *) bad "snapshot: unexpected ledger line ($snap)" ;;
esac
snapfail="$(PATH="$TT/bin:$PATH" FAKE_SOLANA_FAIL=1 RPC_URL="https://rpc.example.test/v2/LEAKME42" bash "$DNR/snapshot-program.sh" Prog111 "$TT/inc2" 2>&1)"
code=$?
eq "snapshot: CLI failure -> exit 3" "$code" "3"
case "$snapfail" in *LEAKME42*) bad "snapshot: key leaked from the CLI error" ;; *REDACTED*) ok "snapshot: CLI error redacted" ;; *) bad "snapshot: error text not shown ($snapfail)" ;; esac
PATH="$TT/bin:$PATH" FAKE_SOLANA_V4=1 RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" Prog111 "$TT/inc3" >/dev/null 2>&1
eq "snapshot: loader-v4 program stops with a named blocker (exit 3)" "$?" "3"

if [[ "$fails" -ne 0 ]]; then
  echo "test-dnr: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr: all assertions passed"
