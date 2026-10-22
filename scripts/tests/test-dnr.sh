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
r7="$(red 'HTTPS://user:SECRETPW@Host.Example.com/v2/KEYUP done')"
eq "redact: upper-case scheme, userinfo and path key removed" "$r7" "HTTPS://REDACTED@Host.Example.com/REDACTED done"
r8="$(red 'wss://rpc.example.com/ws?api-key=WSKEY1 closed')"
eq "redact: a websocket URL is redacted like https" "$r8" "wss://rpc.example.com/REDACTED closed"
r9="$(red 'Api-Key=UPPERKEY9 and ACCESS_TOKEN=T0K3N&x=1')"
eq "redact: key names in any letter case" "$r9" "Api-Key=REDACTED and ACCESS_TOKEN=REDACTED&x=1"

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
# 7. deltas.py sums one owner's token accounts per mint (no overwrite), and keeps
#    lamport math exact above 2^53.
# ---------------------------------------------------------------------------
mv="$(python3 -I "$DNR/deltas.py" tokens "$FIX/same-owner-move.jsonl" | grep -c . || true)"
eq "deltas tokens: internal move between one owner's accounts nets to zero (no row)" "$mv" "0"
dr="$(python3 -I "$DNR/deltas.py" tokens "$FIX/same-owner-drain.jsonl")"
eq "deltas tokens: two-account drain is the sum (-140), not the last account" \
  "$(printf '%s\n' "$dr" | awk -F'\t' '$2=="VaultPDA"{print $4}')" "-140"
eq "deltas tokens: attacker receives +140" \
  "$(printf '%s\n' "$dr" | awk -F'\t' '$2=="Attacker"{print $4}')" "140"
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
export FAKE_CURL_LOG="$TT/curl.log"
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/?api-key=LEAKME42" \
    bash "$DNR/collect.sh" --out "$TT/c" --confirmed --since 1 --max-pages 1 --before "$CURSOR" -- "$A_ADDR" ) > "$TT/c.out" 2>&1
code=$?
eq "collect: exits 0 against the fake RPC (system bash)" "$code" "0"
eq "collect: fetched both the successful AND the failed transaction" \
  "$(grep -c . "$TT/c/transactions.jsonl" 2>/dev/null || true)" "2"
if grep -q 'window not reached' "$TT/c.out"; then ok "collect: reports the unreached window when the page cap stops first"; else bad "collect: no 'window not reached' notice"; fi
if grep -q "\"before\": \"$CURSOR\"" "$FAKE_CURL_LOG"; then ok "collect: --before passed through to the first page"; else bad "collect: --before not passed through"; fi
if grep -q 'LEAKME42' "$TT/c.out" "$TT/c/signatures.jsonl" "$TT/c/transactions.jsonl"; then
  bad "collect: the key leaked into output"
else
  ok "collect: key absent from stdout/stderr and corpus files"
fi
if grep -q 'provider: rpc.example.test ' "$TT/c.out"; then ok "collect: provider disclosed as host only"; else bad "collect: provider line wrong"; fi
# --max-tx keeps the newest signatures across addresses (by slot), not the first
# address's or the alphabetically first ones.
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/c2" --confirmed --max-pages 1 --max-tx 2 -- "$A_ADDR" "$B_ADDR" ) > "$TT/c2.out" 2>&1
got="$(jq -r '.transaction.signatures[0]' "$TT/c2/transactions.jsonl" 2>/dev/null | tr '\n' ' ')"
eq "collect: --max-tx 2 fetches the two newest signatures across both addresses" "$got" "SigZnewest SigOK "
# With only --until set, a page cap that stops above it collected nothing inside the window.
( PATH="$TT/bin:$PATH" RPC_URL="https://rpc.example.test/" \
    bash "$DNR/collect.sh" --out "$TT/c3" --confirmed --until 100 --max-pages 1 -- "$A_ADDR" ) > "$TT/c3.out" 2>&1
if grep -q 'stopped paging above --until' "$TT/c3.out"; then ok "collect: warns when paging stops above --until"; else bad "collect: no warning for a window above --until"; fi
if grep -q 'resume into a new --out with --before' "$TT/c3.out"; then ok "collect: the notice says to resume into a new --out"; else bad "collect: resume notice still points at the same --out"; fi
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
#     CLI error, and stops with a blocker for loader-v4.
# ---------------------------------------------------------------------------
printf '#!/bin/sh\nexec python3 -I "$0.py" "$@"\n' > "$TT/bin/solana"
cat > "$TT/bin/solana.py" <<'PY'
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
PID="ProgTest1111111111111111111111111111111111"   # 42 base58 characters
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
PATH="$TT/bin:$PATH" FAKE_SOLANA_V4=1 RPC_URL="https://rpc.example.test/" bash "$DNR/snapshot-program.sh" "$PID" "$TT/inc3" >/dev/null 2>&1
eq "snapshot: loader-v4 program stops with a named blocker (exit 3)" "$?" "3"
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

if [[ "$fails" -ne 0 ]]; then
  echo "test-dnr: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr: all assertions passed"
