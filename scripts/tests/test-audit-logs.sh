#!/usr/bin/env bash
# test-audit-logs.sh — audit-logs (tools/auditor-tools/audit-logs) against the scripts it
# mirrors, scripts/dnr/profile.sh, frames.py and deltas.py, and its confinement.
#
# Builds audit-logs from a copy of its package (it has no dependencies, so cargo needs no
# network), runs it and the scripts on the same corpora from the same working directory,
# and compares, for each of the five recipes (profile, frames, frames --instructions,
# deltas lamports, deltas tokens), the exit status, stdout and the "skipped" notes on
# stderr. The corpora:
#   1. every committed fixture in scripts/dnr/fixtures/, one at a time and all at once;
#   2. the crafted input-contract cases of test-dnr.sh §20, made by the code in that file;
#   3. cases of its own: amounts and balances above 2^53, forged log lines, ties at the
#      top-20 cut, jq's number forms, odd indices and stack heights, floats Python rounds;
#   4. a generated corpus of 6,000 transactions in two files, well past the pipe buffer;
#   5. stdin, --out, and the exit statuses for a missing, unreadable, linked or
#      non-regular input or --out.
# Then confinement: every case in fixtures/audit-logs/hostile-args.txt exits non-zero,
# changes no file, leaves no temporary file and prints no canary text; an installation
# inside the working directory, or under a path a quoted rule cannot match, is refused;
# and a run stopped by SIGTERM leaves its --out file as it was.
#
# The scripts run under LC_ALL=C: audit-logs orders profile.sh's ties by byte value, as
# sort does there. profile.sh's count column, which BSD uniq pads to 4 and GNU uniq to 7,
# is compared as GNU pads it. Without cargo the suite is skipped, loudly; with
# REQUIRE_TOOLCHAIN=1 (CI) that is a failure. AUDIT_LOGS=<path> tests a binary already
# built (CI's release build) instead of building one.
#
# bash >= 3.2, jq, python3, awk, sed, cmp. No network.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DNR="$ROOT/scripts/dnr"
FIX="$DNR/fixtures"
PKG="$ROOT/tools/auditor-tools/audit-logs"
CASES="$HERE/fixtures/audit-logs/hostile-args.txt"
fails=0
ok()  { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1" >&2; fails=$((fails+1)); }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1 ($2)"; else bad "$1: expected '$3', got '$2'"; fi; }
finish() {
  if [[ "$fails" -ne 0 ]]; then echo "test-audit-logs: $fails assertion(s) FAILED" >&2; exit 1; fi
  echo "test-audit-logs: all assertions passed"; exit 0
}

for tool in jq python3 awk sed cmp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "test-audit-logs: missing required tool: $tool" >&2; exit 3; }
done
T="$(mktemp -d "${TMPDIR:-/tmp}/audit_logs_test.XXXXXX")" || exit 1
trap 'rm -rf "$T"' EXIT

# ---------------------------------------------------------------------------
# 0. The binary: AUDIT_LOGS when given, else a release build of a copy of the
#    package, a workspace of its own with the release profile of tools/auditor-tools.
#    The package has no dependencies, no build script, and no code that opens a
#    socket, runs a program or reads the environment.
# ---------------------------------------------------------------------------
if grep -nE 'std::net|TcpStream|UdpSocket|process::Command|Command::new|env::var|set_var|env::vars' "$PKG"/src/*.rs > "$T/apis"; then
  bad "source: audit-logs names a network, process or environment API ($(tr '\n' ' ' < "$T/apis"))"
else
  ok "source: audit-logs names no network, process or environment API"
fi
deps="$(awk '/^\[/ { d = ($0 ~ /dependencies\]$/) } d && /=/' "$PKG/Cargo.toml")"
if [[ -z "$deps" && ! -e "$PKG/build.rs" ]]; then ok "source: audit-logs has no dependency and no build script"; else bad "source: audit-logs has dependencies or a build script ($deps)"; fi

if [[ -n "${AUDIT_LOGS:-}" ]]; then
  case "$AUDIT_LOGS" in /*) BIN="$AUDIT_LOGS" ;; *) BIN="$PWD/$AUDIT_LOGS" ;; esac
  if [[ ! -f "$BIN" || ! -x "$BIN" ]]; then echo "test-audit-logs: AUDIT_LOGS ($AUDIT_LOGS) is not an executable file" >&2; exit 1; fi
  ok "build: testing the binary AUDIT_LOGS names"
elif command -v cargo >/dev/null 2>&1; then
  mkdir "$T/pkg"
  cp -R "$PKG/Cargo.toml" "$PKG/src" "$T/pkg/"
  { printf '\n[workspace]\n\n'; awk '/^\[/ { p = ($0 == "[profile.release]") } p' "$ROOT/tools/auditor-tools/Cargo.toml"; } >> "$T/pkg/Cargo.toml"
  if cargo build --release --offline --manifest-path "$T/pkg/Cargo.toml" --target-dir "$T/target" > "$T/build.log" 2>&1; then
    BIN="$T/target/release/audit-logs"
    # A cargo config that names a build target puts the binary under target/<triple>/.
    for b in "$T"/target/*/release/audit-logs; do [[ -x "$BIN" || ! -x "$b" ]] || BIN="$b"; done
    if grep -q '^warning' "$T/build.log"; then bad "build: cargo build --release printed warnings"; sed -n '1,40p' "$T/build.log" >&2
    else ok "build: cargo build --release, offline, with no warning"; fi
  else
    sed -n '1,60p' "$T/build.log" >&2
    bad "build: cargo build --release failed"
    finish
  fi
elif [[ "${REQUIRE_TOOLCHAIN:-}" == 1 ]]; then
  bad "REQUIRE_TOOLCHAIN=1, but cargo is not on PATH: audit-logs cannot be built, so its parity with scripts/dnr is not checked"
  finish
else
  echo "SKIP test-audit-logs: cargo is not on PATH, so audit-logs is not built and its parity with scripts/dnr is NOT checked"
  exit 0
fi

WT="$T/wt"
mkdir -p "$WT/incident_1/corpus" "$WT/incident_1/out"
printf '*\n' > "$WT/incident_1/.gitignore"

# norm_counts: profile.sh's count column as GNU uniq pads it, 7 columns.
norm_counts() {
  LC_ALL=C awk 'match($0, /^ *[0-9]+ /) { c = substr($0, 1, RLENGTH - 1); sub(/^ +/, "", c)
                 printf "%7s %s\n", c, substr($0, RLENGTH + 1); next } { print }'
}
# notes <stderr file>: its "skipped" notes, without the program name.
notes() { sed -n 's/^[a-z][a-z.-]*: skipped /skipped /p' "$1"; }

# script|binary <recipe> <args...>: one run of a recipe, from $WT.
script() {
  local r="$1"; shift
  case "$r" in
    profile) ( cd "$WT" && LC_ALL=C bash "$DNR/profile.sh" "$@" ) ;;
    frames) ( cd "$WT" && LC_ALL=C python3 -I "$DNR/frames.py" "$@" ) ;;
    ix) ( cd "$WT" && LC_ALL=C python3 -I "$DNR/frames.py" --instructions "$@" ) ;;
    *) ( cd "$WT" && LC_ALL=C python3 -I "$DNR/deltas.py" "$r" "$@" ) ;;
  esac
}
binary() {
  local r="$1"; shift
  case "$r" in
    profile) ( cd "$WT" && "$BIN" profile "$@" ) ;;
    frames) ( cd "$WT" && "$BIN" frames "$@" ) ;;
    ix) ( cd "$WT" && "$BIN" frames --instructions "$@" ) ;;
    *) ( cd "$WT" && "$BIN" deltas "$r" "$@" ) ;;
  esac
}

# agree <recipe> [<stdin file>] -- <args...>: runs the script and audit-logs, and leaves in
# $T/diff why they differ (exit status, stdout, "skipped" notes); empty when they agree.
# The outputs stay in $T/s.* and $T/b.*.
agree() {
  local r="$1" in=/dev/null sc bc; shift
  if [[ "$1" != -- ]]; then in="$1"; shift; fi
  shift
  script "$r" ${1+"$@"} < "$in" > "$T/s.out" 2> "$T/s.err"; sc=$?
  binary "$r" ${1+"$@"} < "$in" > "$T/b.out" 2> "$T/b.err"; bc=$?
  if [[ "$r" == profile ]]; then norm_counts < "$T/s.out" > "$T/s.cmp"; else cp "$T/s.out" "$T/s.cmp"; fi
  notes "$T/s.err" > "$T/s.notes"; notes "$T/b.err" > "$T/b.notes"
  : > "$T/diff"
  [[ "$sc" == "$bc" ]] || echo "exit $sc (script) vs $bc (audit-logs)" >> "$T/diff"
  cmp -s "$T/s.cmp" "$T/b.out" || { echo "stdout:"; diff "$T/s.cmp" "$T/b.out" | sed -n '1,6p'; } >> "$T/diff"
  cmp -s "$T/s.notes" "$T/b.notes" || { echo "notes:"; diff "$T/s.notes" "$T/b.notes" | sed -n '1,4p'; } >> "$T/diff"
}

# same5 <what> <args...>: the five recipes agree on the same arguments.
same5() {
  local what="$1" r differ=""; shift
  for r in profile frames ix lamports tokens; do
    agree "$r" -- "$@"
    if [[ -s "$T/diff" ]]; then differ="$differ $r"; sed "s/^/  $r: /" "$T/diff" >&2; fi
  done
  if [[ -z "$differ" ]]; then ok "$what: the five recipes agree"; else bad "$what: differs in$differ"; fi
}

# ---------------------------------------------------------------------------
# 1. Every committed fixture, one at a time, then all at once (later copies of a
#    signature are skipped and counted the same way).
# ---------------------------------------------------------------------------
cp "$FIX"/*.jsonl "$WT/incident_1/corpus/"
fixtures=()
for f in "$FIX"/*.jsonl; do
  same5 "fixture ${f##*/}" "incident_1/corpus/${f##*/}"
  fixtures+=("incident_1/corpus/${f##*/}")
done
same5 "all fixtures, each named twice" "${fixtures[@]}" "${fixtures[@]}"
( cd "$WT" && "$BIN" frames "${fixtures[@]}" "${fixtures[@]}" ) > /dev/null 2> "$T/twice.err"
if grep -q '^audit-logs: skipped [1-9][0-9]* transaction(s) already read under the same signature$' "$T/twice.err"; then
  ok "all fixtures twice: audit-logs reports the copies it skipped"
else
  bad "all fixtures twice: no skipped-copy note ($(tr '\n' ' ' < "$T/twice.err"))"
fi
agree lamports -- incident_1/corpus/lamports-over-2-53.jsonl
eq "fixture: a +1 lamport delta above 2^53 is exact in audit-logs" "$(awk -F'\t' '$2 == "BigOne" { print $3 }' "$T/b.out")" "1"
agree tokens -- incident_1/corpus/token-amount-over-2-53.jsonl
eq "fixture: token deltas of 1 above 2^53 are exact in audit-logs" "$(awk -F'\t' '{ printf "%s ", $4 }' "$T/b.out")" "1 1 "
agree frames -- incident_1/corpus/log-newline-injection.jsonl
jq -c 'select(.program | test("Fake"))' "$T/b.out" > "$T/forged"
eq "fixture: no frame is attributed to the program a log line forged" "$(grep -c . "$T/forged")" "0"

# ---------------------------------------------------------------------------
# 2. The crafted input-contract cases of test-dnr.sh §20, made by its own code:
#    each malformed line is counted, never echoed, by both, and each well-formed
#    one read the same way.
# ---------------------------------------------------------------------------
sed -n "/^python3 -I - \"\$TT\/c20\" <<'PY'\$/,/^PY\$/p" "$HERE/test-dnr.sh" > "$T/c20.raw"
sed '1d;$d' "$T/c20.raw" > "$T/c20.py"
if [[ "$(grep -c . "$T/c20.py")" -gt 20 ]] && python3 -I "$T/c20.py" "$WT/incident_1/c20" 2> "$T/c20.err"; then
  n=0
  for f in "$WT"/incident_1/c20/*.jsonl; do
    same5 "test-dnr.sh contract case ${f##*/}" "incident_1/c20/${f##*/}"
    n=$((n + 1))
  done
  [[ "$n" -ge 30 ]] && ok "contract cases: $n files from test-dnr.sh §20" || bad "contract cases: only $n files from test-dnr.sh §20"
else
  bad "contract cases: could not run the case generator from test-dnr.sh §20 ($(tr '\n' ' ' < "$T/c20.err" 2>/dev/null))"
fi

# ---------------------------------------------------------------------------
# 3. Cases of its own. jq writes a number as it was given (1.0, 1E+2), so the
#    version and blockTime cases that print one need a jq that keeps number
#    literals (jq 1.7 with decNumber); with another jq they are left out, and said so.
# ---------------------------------------------------------------------------
literal=0
if [[ "$(printf '[100000000000000000001,1.0,1E2]\n' | jq -c . 2>/dev/null)" == '[100000000000000000001,1.0,1E+2]' ]]; then
  literal=1
else
  echo "note: this jq does not keep number literals; the version and blockTime literal cases are left out"
fi
python3 -I - "$WT/incident_1/crafted" "$literal" <<'PY'
import json, os, sys
d, literal = sys.argv[1], sys.argv[2] == "1"
os.makedirs(d)
P = "Prog7xQmP4sN9kR2wBcD3eF5gH6jK8mN1pQ2rS3tUvW"
Q = "Vict1m9xQmP4sN9kR2wBcD3eF5gH6jK8mN1pQ2rS3tU"
TOK = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
def tx(sig, meta=None, keys=None, ixs=None, extra=None):
    t = {"meta": dict({"err": None, "fee": 5000}, **(meta or {})),
         "transaction": {"signatures": [sig], "message": {"accountKeys": keys if keys is not None else ["Payer1"],
                                                          "instructions": ixs if ixs is not None else []}}}
    t.update(extra or {})
    return t
def write(name, lines):
    with open(os.path.join(d, name), "wb") as f:
        for line in lines:
            f.write((line if isinstance(line, bytes) else json.dumps(line, ensure_ascii=False).encode()) + b"\n")
big = [
    tx("SigBig1", {"fee": 5000, "preBalances": [2**64, 2**53 + 1, 10**40], "postBalances": [2**64 - 4999, 2**53, 10**40 + 10**39]},
       ["PayerBig", "AcctBig", "Acct40"]),
    tx("SigBig2", {"fee": 10**30, "preBalances": [10**31, 7], "postBalances": [0, 7]}, ["PayerFee", "Same"]),
    tx("SigBig3", {"preBalances": [int("9" * 4300), -5], "postBalances": [int("9" * 4300) - 1, 5]}, ["Payer4300", "Neg"]),
    tx("SigBig4", {"preTokenBalances": [
        {"accountIndex": 1, "mint": "MintA", "owner": "Vault", "uiTokenAmount": {"amount": str(2**64 + 1)}},
        {"accountIndex": 2, "mint": "MintA", "owner": "", "uiTokenAmount": {"amount": "0000000000000000000007"}},
        {"mint": "MintB", "owner": "NoIndex", "uiTokenAmount": {"amount": "1" * 45}},
        {"accountIndex": 99, "mint": "MintB", "owner": "NoIndex", "uiTokenAmount": {"amount": "2"}}],
       "postTokenBalances": [
        {"accountIndex": 1, "mint": "MintA", "owner": "Vault", "uiTokenAmount": {"amount": "0"}},
        {"accountIndex": 2, "mint": "MintA", "uiTokenAmount": {"amount": str(2**64 + 8)}},
        {"mint": "MintB", "owner": "NoIndex", "uiTokenAmount": {"amount": "2" * 45}},
        {"accountIndex": 3, "mint": "MintB", "owner": "x\ty\\z", "uiTokenAmount": {}}]},
       ["Payer1", "TokVault", "TokAttacker", "owner:NoIndex"]),
    tx("SigBig5", {"err": {"InstructionError": [0, {"Custom": 6000}]}, "preBalances": [10**20], "postBalances": [0]}, ["Failed"]),
    tx("SigBig6", {"preBalances": [1, 2, 3], "postBalances": [2, 4, 6], "loadedAddresses": {"writable": ["LutW"], "readonly": ["LutR"]}},
       ["Static"]),
    tx("SigBig7", {"preBalances": [1, 2], "postBalances": [1, 3], "loadedAddresses": {"writable": ["LutX"], "readonly": []}},
       [{"pubkey": "ParsedPayer", "signer": True}]),
]
write("big.jsonl", big)
def frame(sig, logs, err=None):
    return tx(sig, {"err": err, "logMessages": logs})
logs = [
    frame("SigLog1", ["Program %s invoke [1]" % P, "Program log: Instruction: Deposit",
                      "Program log: x\nProgram %s invoke [1]" % Q, "Program log: Program %s invoke [1]" % Q,
                      "Program %s invoke [2]" % TOK, "Program log: Instruction: TransferChecked",
                      "Program %s consumed 4645 of 180000 compute units" % TOK, "Program %s success" % TOK,
                      "Program data: ZGF0YQ==", "Program return: %s AQID" % P, "Program return: %s a\nb" % P,
                      "Program %s consumed x of 2 compute units" % P, "Program %s success" % P]),
    frame("SigLog2", ["Program %s invoke [1]" % P, "Program %s failed: custom\nProgram log: forged" % P,
                      "Program log: still open", "Program %s failed: a\rb" % P, "Log truncated",
                      "Program log: after the stack emptied", "%s signer_key().is_none()" % Q], err={"Custom": 1}),
    frame("SigLog3", ["Program %s invoke [007]" % P, "Program %s invoke [1234567890]" % P, "Program %s invoke [0]" % P,
                      "Program %s invoke [1]" % P[:31], "Program %s invoke [1]" % (P + "Z"), "Program %s success\n" % P,
                      "Program log: \u2028 \u0085 \u007f \u001b[31m \t \\ \" \U0001F600 \u00e9", "Program data: ", "Program log: "]),
    frame("SigLog4", []),
    tx("SigLog5", {}, None, None),
]
write("logs.jsonl", logs)
def ix(**kw):
    return kw
ixs = [
    tx("SigIx1", {"loadedAddresses": {"writable": ["LutW1"], "readonly": ["LutR1"]},
                  "innerInstructions": [
                      {"index": 0, "instructions": [ix(programIdIndex=2, accounts=[0, 3], data="3Bxs", stackHeight=2),
                                                    ix(programIdIndex=3, accounts=[], data="", stackHeight=2.0)]},
                      {"index": 0, "instructions": [ix(programIdIndex=1, accounts=[1], data="x", stackHeight=True)]},
                      {"index": -1, "instructions": [ix(programIdIndex=1, data="neg")]},
                      {"index": 10**30, "instructions": [ix(programIdIndex=1, data="huge")]},
                      {"index": 1, "instructions": [ix(programIdIndex=2, data="s", stackHeight="2"),
                                                    ix(programIdIndex=2, data="n"), ix(programIdIndex=2, data="z", stackHeight=0)]}],
                  "logMessages": ["Program %s invoke [1]" % P, "Program LutW1111111111111111111111111111111111 invoke [2]",
                                  "Program %s invoke [2]" % Q, "Program %s success" % Q, "Program %s success" % P,
                                  "Program %s invoke [1]" % Q, "Program %s invoke [2]" % Q, "Program %s invoke [3]" % Q,
                                  "Program %s failed: custom program error: 0x1" % Q]},
       ["Payer1", P, Q, "LutW1111111111111111111111111111111111"],
       [ix(programIdIndex=1, accounts=[0, 1, 2, 3, 4, 5, -1, 10**25, 1.5, None, {"k": [1e16, 1e-07]}], data="3Bxs4h24hBtQy9rw"),
        ix(programIdIndex=2, accounts=[], data="")], {"version": 0}),
    tx("SigIx2", {"loadedAddresses": {"writable": ["NotAppended"]}},
       [{"pubkey": "ParsedPayer", "signer": True, "writable": True}, {"pubkey": P, "signer": False}],
       [ix(programId="11111111111111111111111111111111", program="system",
           parsed={"type": "transfer", "info": {"lamports": 2**64 + 1, "ratio": 0.1, "big": 1e22, "tiny": 5e-324,
                                                "neg": -0.0, "whole": 100.0, "tie": 1365507272084322.25, "list": [1, "two", None, True]}},
           accounts=None),
        ix(programIdIndex=-1, parsed=None, program=7),
        ix(programIdIndex=1, parsed={"type": "x"}),
        ix(programId="", data="emptyid"),
        ix(programIdIndex=2, accounts=[1])]),
    b'{"meta":{"err":null,"innerInstructions":[{"index":0,"instructions":[{"programIdIndex":1,"stackHeight":2,"data":"d"}]}],'
    b'"logMessages":["Program ' + P.encode() + b' invoke [1]","Program ' + P.encode() + b' invoke [2]"]},'
    b'"transaction":{"signatures":["SigIx3"],"message":{"accountKeys":["Payer1","' + P.encode() + b'"],'
    b'"instructions":[{"programIdIndex":1,"accounts":[-0,1],"data":"a","parsed":{"a":1,"b":2,"a":3},"stackHeight":-0}]}}}',
]
write("instructions.jsonl", ixs)
ties = []
names = ["aaa", "AAA", "Bbb", "bBB", "\u00e9", "e", "z", "Z", "a b", "a", "ab", "a_", "Ab", "b", "B", "zz", "Zz", "zZ",
         "m", "M", "n", "N", "\u2028", "x\u0085y", ""]
for k, n in enumerate(names):
    for c in range(2):
        ties.append(tx("SigTie%d_%d" % (k, c), {"preBalances": [1], "postBalances": [1]}, [n, "Second" + str(k % 3)],
                       [ix(programId=n or "?x"), ix(programIdIndex=-1), ix(programIdIndex=1)],
                       {"blockTime": 1700000000 + k}))
for k in range(3):
    ties.append(tx("SigTop%d" % k, {}, ["Top", "Top2"], [], {"blockTime": 1700000000}))
for k, h in enumerate([0, -1, 1, 2, 10**30, None, -(10**30)]):
    t = tx("SigHdr%d" % k, {}, ["H1", "H2", "H3"], [])
    t["transaction"]["message"]["header"] = {"numRequiredSignatures": h}
    ties.append(t)
for k, s in enumerate([True, False, 1, "true", None]):
    ties.append(tx("SigSigner%d" % k, {}, [{"pubkey": "ObjSigner%d" % k, "signer": s}, {"pubkey": "ObjOther", "signer": True}], []))
write("ties.jsonl", ties)
nums = [tx("SigNum0", {}, ["P"], [], {"version": "legacy", "blockTime": 1700000000}),
        tx("SigNum1", {}, ["P"], [], {"version": "0", "blockTime": -5}),
        tx("SigNum2", {}, ["P"], [], {"version": True}),
        tx("SigNum3", {}, ["P"], [], {"version": False}),
        tx("SigNum4", {}, ["P"], [], {"version": None}),
        tx("SigNum5", {}, ["P"], [], {"version": [0, "\u007f"]}),
        tx("SigNum6", {}, ["P"], [], {"version": "v\u2028x"})]
if literal:
    nums += [b'{"version":1.0,"blockTime":-0,"meta":null,"transaction":{"signatures":["SigNum7"]}}',
             b'{"version":1E2,"blockTime":0,"transaction":{"signatures":["SigNum8"]}}',
             b'{"version":{"a":[1.50,"\\u007f"],"b":1e-7,"c":-0},"blockTime":100000000000000000000000000001,"transaction":{"signatures":["SigNum9"]}}',
             b'{"version":-0,"blockTime":-100000000000000000000000000001,"transaction":{"signatures":["SigNum10"]}}']
write("numbers.jsonl", nums)
PY
for f in big logs instructions ties numbers; do
  same5 "own case $f.jsonl" "incident_1/crafted/$f.jsonl"
done
same5 "own cases, all files at once" incident_1/crafted/big.jsonl incident_1/crafted/logs.jsonl \
  incident_1/crafted/instructions.jsonl incident_1/crafted/ties.jsonl incident_1/crafted/numbers.jsonl
agree lamports -- incident_1/crafted/big.jsonl
eq "own cases: lamport deltas above 2^53 and of 40 digits are exact" \
  "$(awk -F'\t' '$1 == "SigBig1" { printf "%s=%s ", $2, $3 }' "$T/b.out")" "PayerBig=1 AcctBig=-1 Acct40=1000000000000000000000000000000000000000 "
agree tokens -- incident_1/crafted/big.jsonl
eq "own cases: token deltas above 2^64 are exact, keyed by account and mint (an account named owner:X shares the owner's bucket)" \
  "$(awk -F'\t' '$1 == "SigBig4" { printf "%s:%s:%s ", $5, $3, $4 }' "$T/b.out")" \
  "TokVault:MintA:-18446744073709551617 TokAttacker:MintA:18446744073709551617 owner:NoIndex:MintB:111111111111111111111111111111111111111111109 "
agree profile -- incident_1/crafted/ties.jsonl
eq "own cases: the top-20 cut falls inside a tie of 25, broken by descending byte order" \
  "$(LC_ALL=C awk '/^-- fee payers/ { f = 1; next } /^--/ { f = 0 } f { n++; if (n == 1 || n == 20) printf "%s|", $0 }' "$T/b.out")" \
  "      7 H1|      2 Z|"
if [[ "$literal" == 1 ]]; then
  agree profile -- incident_1/crafted/numbers.jsonl
  if grep -q '^      1 1E+2$' "$T/b.out" && grep -q 'first=-100000000000000000000000000001  last=100000000000000000000000000001' "$T/b.out"; then
    ok "own cases: versions and blockTimes print as jq writes them (1E+2, 30 digits)"
  else
    bad "own cases: the jq number forms are missing from the profile"
  fi
fi

# ---------------------------------------------------------------------------
# 4. A generated corpus: 6,000 transactions in two files, the second opening with
#    150 copies from the first and holding a few malformed lines; both encodings,
#    lookup tables, inner instructions, failures, values above 2^53, and fee payers
#    and programs drawn from small pools, so the top-20 lists tie.
# ---------------------------------------------------------------------------
python3 -I - "$WT/incident_1/corpus" <<'PY'
import json, random, sys
R = random.Random(22)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(n):
    return "".join(R.choice(B58) for _ in range(n))
payers = [b58(44) for _ in range(40)]
progs = [b58(44) for _ in range(30)]
accts = [b58(44) for _ in range(200)]
mints = [b58(44) for _ in range(5)]
def one(i):
    parsed = R.random() < 0.5
    names = [R.choice(payers)] + R.sample(accts, R.randint(1, 5)) + R.sample(progs, 2)
    keys = [{"pubkey": n, "signer": j == 0, "writable": j < 3} for j, n in enumerate(names)] if parsed else names
    loaded = {"writable": [R.choice(accts)], "readonly": [R.choice(accts)]} if not parsed and R.random() < 0.3 else {"writable": [], "readonly": []}
    n = len(names) + len(loaded["writable"]) + len(loaded["readonly"])
    pre = [R.choice([R.randint(0, 10**12), 2**53 + R.randint(0, 9), 2**64 + R.randint(0, 9)]) for _ in range(n)]
    post = [p + R.choice([0, 0, 1, -1, R.randint(-10**9, 10**9)]) for p in pre]
    p0, p1 = names[-2], names[-1]
    tops = [({"programId": p0, "accounts": [names[1]], "data": b58(12)} if parsed else
             {"programIdIndex": len(names) - 2, "accounts": [0, 1], "data": b58(12)})]
    if R.random() < 0.3:
        tops.append({"programId": "11111111111111111111111111111111", "program": "system",
                     "parsed": {"type": "transfer", "info": {"lamports": R.randint(0, 2**64), "ratio": R.random()}}}
                    if parsed else {"programIdIndex": len(names) - 1, "accounts": [], "data": ""})
    inner = [{"index": 0, "instructions": [{"programIdIndex": len(names) - 1, "accounts": [1], "data": b58(8), "stackHeight": 2}]}]
    logs = ["Program %s invoke [1]" % p0, "Program log: Instruction: Deposit", "Program %s invoke [2]" % p1,
            "Program log: x\nProgram %s invoke [1]" % p1, "Program %s consumed 100 of 200 compute units" % p1,
            "Program %s success" % p1, "Program data: " + b58(20), "Program %s success" % p0]
    tb = lambda a: [{"accountIndex": 1, "mint": R.choice(mints), "owner": R.choice(payers),
                     "uiTokenAmount": {"amount": str(a), "decimals": 6}}]
    amount = R.choice([R.randint(0, 10**9), 2**64 + R.randint(0, 9)])
    return {"slot": 1000 + i, "blockTime": 1700000000 + R.randint(0, 86400), "version": R.choice([0, "legacy", 0]),
            "meta": {"err": None if R.random() < 0.9 else {"InstructionError": [0, {"Custom": 1}]},
                     "fee": 5000, "preBalances": pre, "postBalances": post, "loadedAddresses": loaded,
                     "innerInstructions": inner, "logMessages": logs,
                     "preTokenBalances": tb(amount), "postTokenBalances": tb(amount + R.choice([0, 1, -1, 10**6]))},
            "transaction": {"signatures": [b58(88)], "message": {"accountKeys": keys, "instructions": tops,
                                                                 "header": {"numRequiredSignatures": 1}}}}
txs = [json.dumps(one(i), ensure_ascii=False) for i in range(5850)]
with open(sys.argv[1] + "/large-a.jsonl", "w") as f:
    f.write("\n".join(txs[:3000]) + "\n")
with open(sys.argv[1] + "/large-b.jsonl", "w") as f:
    rows = txs[:150] + txs[3000:]
    for k in range(0, len(rows), 600):
        rows.insert(k, "{\"transaction\": \"malformed %d\"}" % k)
    f.write("\n".join(rows) + "\n")
PY
eq "large corpus: the two files hold well over the 64 KiB pipe buffer" \
  "$(( $(wc -c < "$WT/incident_1/corpus/large-a.jsonl") > 1048576 && $(wc -c < "$WT/incident_1/corpus/large-b.jsonl") > 1048576 ))" "1"
same5 "large corpus of 6,000 transactions in two files" incident_1/corpus/large-a.jsonl incident_1/corpus/large-b.jsonl
eq "large corpus: audit-logs read 150 copies once and counted the malformed lines" "$(tr '\n' '|' < "$T/b.notes")" \
  "skipped 150 transaction(s) already read under the same signature|skipped 5 malformed line(s) in input 2 (incident_1/corpus/large-b.jsonl), the first at line 1 (not a getTransaction JSON object the recipes can read)|"

# ---------------------------------------------------------------------------
# 5. stdin, --out, and the exit statuses for inputs and outputs that cannot be used.
# ---------------------------------------------------------------------------
for r in frames ix lamports tokens; do
  agree "$r" "$WT/incident_1/crafted/instructions.jsonl" --
  if [[ -s "$T/diff" ]]; then bad "stdin: $r differs ($(tr '\n' ' ' < "$T/diff"))"; else ok "stdin: $r agrees when it reads stdin"; fi
done
two=(incident_1/crafted/big.jsonl incident_1/crafted/logs.jsonl)
for r in profile frames ix lamports tokens; do
  binary "$r" "${two[@]}" > "$T/b.stdout" 2> /dev/null
  script "$r" --out "incident_1/out/s-$r.txt" "${two[@]}" > "$T/s.out" 2> /dev/null; sc=$?
  binary "$r" --out "incident_1/out/$r.txt" "${two[@]}" > "$T/b.out" 2> /dev/null; bc=$?
  if [[ "$r" == profile ]]; then norm_counts < "$WT/incident_1/out/s-$r.txt" > "$T/s.file"; else cp "$WT/incident_1/out/s-$r.txt" "$T/s.file"; fi
  if [[ "$sc$bc" == 00 && ! -s "$T/s.out" && ! -s "$T/b.out" ]] && cmp -s "$T/b.stdout" "$WT/incident_1/out/$r.txt" \
     && cmp -s "$T/s.file" "$WT/incident_1/out/$r.txt"; then
    ok "--out: audit-logs $r writes into the file what it prints on stdout, as the script does"
  else
    bad "--out: audit-logs $r -> exit $sc (script) / $bc, or the files differ"
  fi
done
eq "--out: no temporary file is left beside the outputs" "$(ls -A "$WT/incident_1/out" | tr '\n' ' ')" \
  "frames.txt ix.txt lamports.txt profile.txt s-frames.txt s-ix.txt s-lamports.txt s-profile.txt s-tokens.txt tokens.txt "
mkdir -p "$WT/incident_1/unread" "$T/elsewhere"
cp "$FIX/clean-mixed.jsonl" "$WT/incident_1/unread/c.jsonl"; chmod 000 "$WT/incident_1/unread/c.jsonl"
cp "$FIX/clean-mixed.jsonl" "$T/elsewhere/c.jsonl"
ln -s ../corpus/clean-mixed.jsonl "$WT/incident_1/link.jsonl"
ln -s "$T/elsewhere" "$WT/incident_1/dirlink"
mkfifo "$WT/incident_1/fifo"
for c in "missing|incident_1/corpus/no-such.jsonl" "a directory|incident_1/corpus" "a link|incident_1/link.jsonl" \
         "a path through a directory link|incident_1/dirlink/c.jsonl" "a FIFO|incident_1/fifo" \
         "a good corpus, then a missing one|incident_1/corpus/clean-mixed.jsonl incident_1/corpus/no-such.jsonl" \
         "unreadable|incident_1/unread/c.jsonl"; do
  if [[ "${c%%|*}" == unreadable && -r "$WT/incident_1/unread/c.jsonl" ]]; then
    echo "note: running as a user who can read a mode-000 file; the unreadable case is skipped"; continue
  fi
  differ=""
  for r in profile frames ix lamports tokens; do
    # The case's paths are separate words.
    agree "$r" -- ${c#*|}
    if [[ -s "$T/diff" || -s "$T/b.out" ]] || ! grep -q '^audit-logs: ' "$T/b.err"; then differ="$differ $r"; fi
  done
  if [[ -z "$differ" ]]; then ok "input that cannot be used, $c: same exit status as each script, nothing on stdout"
  else bad "input that cannot be used, ${c%%|*}: differs in$differ"; fi
done
printf 'previous\n' > "$WT/incident_1/out/kept.txt"
ln -s "$T/elsewhere/out.txt" "$WT/incident_1/out-link.txt"
for c in "a link|incident_1/out-link.txt" "a path through a directory link|incident_1/dirlink/out.txt" \
         "in a missing directory|incident_1/no-such-dir/out.txt" "a directory|incident_1/out"; do
  differ=""
  for r in profile frames lamports; do
    agree "$r" -- --out "${c#*|}" incident_1/corpus/clean-mixed.jsonl
    [[ -s "$T/diff" || -s "$T/b.out" ]] && differ="$differ $r"
  done
  if [[ -z "$differ" ]]; then ok "--out that cannot be used, ${c%%|*}: same exit status as each script"
  else bad "--out that cannot be used, ${c%%|*}: differs in$differ"; fi
done
eq "--out: nothing was written through a link" "$(ls -A "$T/elsewhere" | tr '\n' ' ')" "c.jsonl "
eq "--out: the files beside them are as they were" "$(cat "$WT/incident_1/out/kept.txt")" "previous"

# SIGTERM while audit-logs reads: stdin holds one transaction, then stays open until
# the run has been stopped. The --out file keeps what it held, and no temporary
# file is left.
partial() { local f; for f in "$WT"/incident_1/out/.held.txt.*.partial; do [[ -e "$f" ]] && return 0; done; return 1; }
printf 'previous\n' > "$WT/incident_1/out/held.txt"
( sed -n 1p "$FIX/clean-mixed.jsonl"; sleep 3 ) | ( cd "$WT" && exec "$BIN" frames --out incident_1/out/held.txt ) &
pid=$!
n=0; while ! partial && [[ "$n" -lt 100 ]]; do sleep 0.1; n=$((n + 1)); done
kill -TERM "$pid" 2>/dev/null
wait "$pid"
code=$?
eq "SIGTERM: exit 143, the --out file as it was, no temporary file left" \
  "$code|$(cat "$WT/incident_1/out/held.txt")|$(partial && echo left)" "143|previous|"

# ---------------------------------------------------------------------------
# 6. Confinement. The working directory reached through a link above it is the
#    operator's and is followed. An installation inside the working directory, or
#    under a path holding a quote, $, backtick, backslash or newline, is refused.
# ---------------------------------------------------------------------------
ln -s "$WT" "$T/wt-link"
( cd "$T/wt-link" && "$BIN" frames incident_1/corpus/clean-mixed.jsonl ) > "$T/via-link.out" 2>&1
code=$?
( cd "$WT" && "$BIN" frames incident_1/corpus/clean-mixed.jsonl ) > "$T/direct.out" 2>&1
if [[ "$code" == 0 ]] && cmp -s "$T/via-link.out" "$T/direct.out"; then
  ok "confinement: a working directory reached through a link above it is followed"
else
  bad "confinement: a link above the working directory -> exit $code"
fi
mkdir -p "$WT/tools/auditor-tools/target/release" "$T/dollar\$dir" "$T/quote\"dir"
cp "$BIN" "$WT/tools/auditor-tools/target/release/audit-logs"
cp "$BIN" "$T/dollar\$dir/audit-logs"
cp "$BIN" "$T/quote\"dir/audit-logs"
for c in "inside the working directory|$WT/tools/auditor-tools/target/release/audit-logs" \
         "under a path holding \$|$T/dollar\$dir/audit-logs" "under a path holding a quote|$T/quote\"dir/audit-logs"; do
  ( cd "$WT" && "${c#*|}" frames incident_1/corpus/clean-mixed.jsonl ) > "$T/c1.out" 2> "$T/c1.err"
  code=$?
  if [[ "$code" == 2 && ! -s "$T/c1.out" ]] && grep -q '^audit-logs: refused: ' "$T/c1.err"; then
    ok "confinement: an installation ${c%%|*} is refused (exit 2, no output)"
  else
    bad "confinement: an installation ${c%%|*} -> exit $code ($(tr '\n' ' ' < "$T/c1.err"))"
  fi
done

# The hostile-argument cases, from a working directory laid out for them: a
# canary file outside every run directory and one outside the working directory,
# links to both from inside incident_1/, a linked run directory, run directories
# without a proper .gitignore, a FIFO, a file with a second name, and a link where
# an output would go. Each case runs with stdin from /dev/null and a 10 s limit.
H="$T/hostile"; HW="$H/wt"; HO="$H/outside"
mkdir -p "$HW/incident_1/subdir" "$HW/incident_3" "$HW/incident_4" "$HW/audit_1" "$HO"
printf '*\n' > "$HW/incident_1/.gitignore"; printf '*\n' > "$HW/audit_1/.gitignore"
printf '!x\n' > "$HW/incident_4/.gitignore"; printf '*\n' > "$HO/.gitignore"
CANARY="SEKRET4f1c9e2a"
canary="{\"meta\":{\"err\":null,\"fee\":0,\"preBalances\":[1],\"postBalances\":[2],\"logMessages\":[\"Program log: $CANARY\"]},\"transaction\":{\"signatures\":[\"Sig$CANARY\"],\"message\":{\"accountKeys\":[\"Key$CANARY\"],\"instructions\":[{\"programId\":\"Prog$CANARY\",\"accounts\":[0],\"data\":\"x\"}]}}}"
for f in "$HW/canary.jsonl" "$HO/secret.jsonl" "$HW/incident_3/canary.jsonl" "$HW/incident_4/canary.jsonl" "$HW/audit_1/canary.jsonl"; do
  printf '%s\n' "$canary" > "$f"
done
sed -n 1p "$FIX/clean-mixed.jsonl" > "$HW/incident_1/corpus.jsonl"
ln -s ../canary.jsonl "$HW/incident_1/link.jsonl"
ln -s "$HO" "$HW/incident_1/dlink"
ln -s "$HO" "$HW/incident_2"
mkfifo "$HW/incident_1/fifo"
printf 'protected\n' > "$HW/protected.txt"
ln "$HW/protected.txt" "$HW/incident_1/hard.txt"
ln -s ../protected.txt "$HW/incident_1/out-link.txt"
# snapshot: every path under $H, never following a link: type, size, mtime, link
# target and a hash of each regular file.
snapshot() {
  python3 -I - "$H" <<'PY'
import hashlib, os, stat, sys
root = sys.argv[1]
for top, dirs, files in os.walk(root):
    dirs.sort()
    for name in sorted(dirs + files):
        p = os.path.join(top, name)
        st = os.lstat(p)
        line = [os.path.relpath(p, root), oct(stat.S_IFMT(st.st_mode)), str(st.st_size), str(st.st_mtime_ns)]
        if stat.S_ISLNK(st.st_mode):
            line.append(os.readlink(p))
        elif stat.S_ISREG(st.st_mode):
            with open(p, "rb") as f:
                line.append(hashlib.sha256(f.read()).hexdigest())
        print("\t".join(line))
PY
}
# expand: the case file's cases, one file per case in $T/cases: its name, then each
# argument, NUL-terminated, with the placeholders filled in.
mkdir "$T/cases"
python3 -I - "$CASES" "$T/cases" "$HW" "$HO" <<'PY'
import os, re, sys
cases, out, wt, outside = sys.argv[1:5]
n = 0
with open(cases, encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        def fill(a):
            a = a.replace("@WT@", wt).replace("@OUT@", outside).replace("@NL@", "\n").replace("@ESC@", "\x1b")
            return re.sub(r"@LONG:([0-9]+)@", lambda m: "a" * int(m.group(1)), a)
        with open(os.path.join(out, "%03d" % n), "wb") as g:
            for word in [fields[0]] + [fill(a) for a in fields[1:]]:
                g.write(os.fsencode(word) + b"\0")
        n += 1
PY
snapshot > "$T/h.before"
ncases=0
for cf in "$T"/cases/*; do
  args=(); name=""
  while IFS= read -r -d '' word; do
    if [[ -z "$name" ]]; then name="$word"; else args+=("$word"); fi
  done < "$cf"
  ( cd "$HW" && exec "$BIN" ${args[@]+"${args[@]}"} ) < /dev/null > "$T/h.out" 2> "$T/h.err" &
  pid=$!
  n=0
  while kill -0 "$pid" 2>/dev/null && [[ "$n" -lt 100 ]]; do sleep 0.1; n=$((n + 1)); done
  if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; code=hung; else wait "$pid"; code=$?; fi
  snapshot > "$T/h.after"
  partials="$(find "$H" -name '*.partial' 2>/dev/null)"
  why=""
  [[ "$code" == hung ]] && why="$why still running after 10 s;"
  [[ "$code" == 0 ]] && why="$why exit 0;"
  cmp -s "$T/h.before" "$T/h.after" || why="$why changed files ($(diff "$T/h.before" "$T/h.after" | sed -n '2p'));"
  [[ -z "$partials" ]] || why="$why left $partials;"
  grep -q "$CANARY" "$T/h.out" "$T/h.err" && why="$why printed the canary;"
  if [[ -z "$why" ]]; then ok "hostile arguments: $name (exit $code)"; else bad "hostile arguments: $name:$why"; fi
  cp "$T/h.after" "$T/h.before"
  ncases=$((ncases + 1))
done
if [[ "$ncases" -ge 50 ]]; then ok "hostile arguments: $ncases cases from ${CASES##*/}"; else bad "hostile arguments: only $ncases cases read from ${CASES##*/}"; fi
eq "hostile arguments: the protected file is unchanged" "$(cat "$HW/protected.txt")" "protected"

finish
