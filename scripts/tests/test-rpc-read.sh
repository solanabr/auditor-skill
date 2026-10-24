#!/usr/bin/env bash
# test-rpc-read.sh — self-test for scripts/rpc-read.sh against a stand-in for the solana CLI: the
# argument grammar and refusals, the throwaway config (endpoint from $RPC_URL or a fixed --cluster, a
# keypair path that does not exist), the three reads, account data kept only in R/rpc/ and never
# printed, control characters shown as ?, redacted CLI errors, the disclosure row, and the case file
# fixtures/rpc-read/cases.txt, run under each bash on the machine (/bin/bash and the bash running this
# suite, when they differ), which must print the same. Needs python3; no network.
# Usage (from the repo root): bash scripts/tests/test-rpc-read.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
READ="$ROOT/scripts/rpc-read.sh"
RUNDIR="$ROOT/scripts/rundir.sh"
CASES="$ROOT/scripts/tests/fixtures/rpc-read/cases.txt"
T=$(mktemp -d "${TMPDIR:-/tmp}/rpc-read-test.XXXXXX") || exit 1
T=$(cd -P "$T" && pwd -P) || exit 1
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
PY=$(python3 -I -c 'import sys; print(sys.executable)') || { echo "FAIL - python3 is needed"; exit 1; }
export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
mkdir -p "$HOME" "$T/sol"

pass=0 fail=0 skip=0
ok()   { pass=$((pass + 1)); echo "ok   - $1"; }
ko()   { fail=$((fail + 1)); echo "FAIL - $1"; }
skp()  { skip=$((skip + 1)); echo "skip - $1"; }
check() { # check <name> <command>...: on a failure, also show the last run
  if "${@:2}"; then ok "$1"; else ko "$1"; echo "#   status ${RC:-} stdout [$(cat "$T/out" 2>/dev/null)] stderr [$(cat "$T/err" 2>/dev/null)]"; fi
}
has()   { grep -qF -- "$2" "$1"; }
hasnt() { ! grep -qF -- "$2" "$1"; }

ADDR="AddrA111111111111111111111111111111111111111"   # base58, 32 bytes
PID="ProgTest11111111111111111111111111111111111"     # base58, 32 bytes
SIG="5h6xBEauJ3PK6SWCZ1PGjBvj8vDdWG3KpwATGy1ARAXFSDwt8GFXM7W5Ncn16wmqokgpiKRLuS83KUxyZyv2sUYv"   # 64 bytes
export RPC_URL="https://key9.rpc.example.test/v2/SECRETKEY?api-key=QKEY"

# ---------------------------------------------------------------------------------------------------
# A solana CLI stand-in that answers like solana-cli 3.1.10: a config without websocket_url is ignored
# (defaults: mainnet-beta and id.json); `account` prints a hex dump of the data unless --output-file names a
# file for it; `confirm -v` starts with the endpoint, key included, and the keypair path; `program show`
# rejects a loader-v4 program; errors name the endpoint, key included, as the real CLI's do.
# FAKE_ACCOUNT=missing, FAKE_CONFIRM=missing|url-in-text, FAKE_LOADER=v4|none, FAKE_SHOW=url-in-text and
# FAKE_SHOWN_ID=<id> shape the answers (url-in-text: the endpoint in the text of an answer that succeeds);
# FAKE_IGNORE_CONFIG=1 makes it ignore every config. Every call is appended to $FAKE_ARGV as JSON: the
# arguments and the endpoint and keypair path it used.
# ---------------------------------------------------------------------------------------------------
printf '#!/bin/sh\nexec "%s" -I "$0.py" "$@"\n' "$PY" > "$T/sol/solana"
cat > "$T/sol/solana.py" <<'PY'
import json, os, re, sys
a = sys.argv[1:]
cfg = {}
if "-C" in a:
    i = a.index("-C")
    for line in open(a[i + 1]):
        m = re.match(r'(\w+): "(.*)"$', line.rstrip("\n"))
        if m:
            cfg[m.group(1)] = m.group(2)
    del a[i:i + 2]
if "websocket_url" not in cfg or os.environ.get("FAKE_IGNORE_CONFIG"):
    cfg = {"json_rpc_url": "https://api.mainnet-beta.solana.com", "keypair_path": "/home/fake/.config/solana/id.json"}
url, kp = cfg["json_rpc_url"], cfg["keypair_path"]
with open(os.environ["FAKE_ARGV"], "a") as log:
    log.write(json.dumps({"argv": a, "url": url, "keypair": kp, "keypair_exists": os.path.exists(kp)}) + "\n")
def fail(msg):
    sys.stderr.write(f"Error: {msg} (endpoint {url})\n"); sys.exit(1)
def opt(name):
    return a[a.index(name) + 1] if name in a else None
if a[:3] == ["config", "get", "keypair"]:
    print(f"Key Path: {kp}"); sys.exit(0)
if a[0] == "account":
    if os.environ.get("FAKE_ACCOUNT") == "missing":
        fail(f"AccountNotFound: pubkey={a[1]}")
    data = b"\x01\x02ACCOUNT-DATA-\xff" + bytes(range(32))
    bal = "2039280 lamports" if "--lamports" in a else "0.00203928 SOL"
    print(f"\nPublic Key: {a[1]}\nBalance: {bal}\nOwner: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA\nExecutable: false\nRent Epoch: 18446744073709551615")
    if opt("--output-file"):
        open(opt("--output-file"), "wb").write(data)
        print(f"\nWrote account data to {opt('--output-file')}")
    else:
        print(f"Length: {len(data)} ({len(data):#x}) bytes\n0000:   " + " ".join(f"{b:02x}" for b in data[:16]))
    sys.exit(0)
if a[0] == "confirm":
    if os.environ.get("FAKE_CONFIRM") == "missing":
        fail("Signature not found")
    if "-v" in a:
        print(f"RPC URL: {url}\nDefault Signer Path: {kp}\nCommitment: confirmed")
    sig = a[a.index("-v") + 1] if "-v" in a else a[1]
    print(f"Transaction executed in slot 123:\n  Block Time: 2026-10-23T10:00:00Z\n  Recent Blockhash: 11111111111111111111111111111111\n"
          f"  Signature 0: {sig}\n  Log Messages:\n    Program log: hi\x1b[31m red\x07 bell\ttab\r carriage")
    if os.environ.get("FAKE_CONFIRM") == "url-in-text":
        print(f"  Status: unavailable (error sending request for url ({url}))")
    print("Finalized")
    sys.exit(0)
loader = os.environ.get("FAKE_LOADER", "v3")
pid = a[2] if a[0] == "program" else opt("--program-id")
shown = os.environ.get("FAKE_SHOWN_ID") or pid
if a[:2] == ["program", "show"]:
    if opt("--buffer-authority") is None and not os.path.exists(kp):
        fail(f'Dynamic program error: No default signer found, run "solana-keygen new -o {kp}" to create a new one')
    if loader in ("v4", "none"):
        fail(f"{pid} is not an SBF program")
    print(f"\nProgram Id: {shown}\nOwner: BPFLoaderUpgradeab1e11111111111111111111111\nProgramData Address: YMN9Qj5jPNp7j14VPcML1B6xGgcPWVZUGLFU3Mnyfaf\n"
          f"Authority: p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV\nLast Deployed In Slot: 12345\nData Length: 351 (0x15f) bytes\nBalance: 0.00114144 SOL\n")
    if os.environ.get("FAKE_SHOW") == "url-in-text":
        print(f"Read from {url}")
    sys.exit(0)
if a[:2] == ["program-v4", "show"]:
    if opt("--authority") is None and not os.path.exists(kp):
        fail("Dynamic program error: No default signer found")
    if loader != "v4":
        fail(f"{pid} is not owned by loader-v4")
    print(f"\nProgram Id: {shown}\nOwner: LoaderV411111111111111111111111111111111111\nAuthority: p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV\n"
          "Last Deployed In Slot: 777\nStatus: deployed\nData Length: 351 (0x15f) bytes\n")
    sys.exit(0)
sys.stderr.write("fake solana: refusing an unexpected subcommand\n"); sys.exit(9)
PY
chmod +x "$T/sol/solana"
export FAKE_ARGV="$T/sol.argv"
calls() { if [ -f "$FAKE_ARGV" ]; then grep -c . "$FAKE_ARGV"; else echo 0; fi; }
# reads: the CLI calls that read the chain (every call but `config get keypair`)
reads() { if [ -f "$FAKE_ARGV" ]; then grep -vc '"argv": \["config", "get", "keypair"\]' "$FAKE_ARGV"; else echo 0; fi; }

W="$T/wt"; mkdir -p "$W"
R=$(cd "$W" && "$RUNDIR" new incident) || { ko "rundir.sh new incident failed"; exit 1; }
A=$(cd "$W" && "$RUNDIR" new audit) || { ko "rundir.sh new audit failed"; exit 1; }
# run <args...>: rpc-read.sh, run directly from $W with the stand-in on PATH; output in $T/out, $T/err, $RC.
run() { (cd "$W" && PATH="$T/sol:$PATH" "$READ" "$@") >"$T/out" 2>"$T/err" </dev/null; RC=$?; }
refused() { [ "$RC" = 64 ] && [ "$(cat "$T/err")" = "rpc-read: refused: $1" ] && [ ! -s "$T/out" ]; }
tree() { (cd "$1" && find . -print | LC_ALL=C sort); }

# =================================================================================================
# The entry point and its grammar. Every refusal is one line, exit 64, before the CLI runs.
# =================================================================================================
check "rpc-read.sh starts with #!/bin/bash" test "$(sed -n 1p "$READ")" = '#!/bin/bash'
check "rpc-read.sh is executable" test -x "$READ"
USAGE='usage: rpc-read.sh account <address> | confirm <signature> | program-show <program_id> [--run <R>] [--cluster mainnet-beta|devnet|testnet]'
mkdir "$W/incident_0"; ln -s "$R" "$W/incident_00"
tree "$W" > "$T/tree.before"; rm -f "$FAKE_ARGV"
run
check "no arguments: the usage, exit 64" refused "$USAGE"
run account
check "a read with no id: the usage" refused "$USAGE"
run balance "$ADDR"
check "an unknown read: the usage" refused "$USAGE"
run account "$ADDR" --run "$R" --run "$R"
check "--run given twice is refused" refused "--run is given twice"
run account "$ADDR" --cluster devnet --cluster devnet
check "--cluster given twice is refused" refused "--cluster is given twice"
run account "$ADDR" --run
check "--run with no value is refused" refused "--run needs a value"
run account "$ADDR" --url https://evil.example/
check "an unknown option is refused (no --url: the endpoint is never an argument)" refused "unknown argument: --url"
run account "$ADDR" -u mainnet-beta
check "... nor -u" refused "unknown argument: -u"
run account "$ADDR" --cluster localhost
check "--cluster takes only the three public clusters" refused "--cluster takes mainnet-beta, devnet or testnet, not localhost"
run account "$ADDR" --cluster "https://evil.example/"
check "--cluster never takes a URL" refused "--cluster takes mainnet-beta, devnet or testnet, not https://evil.example/"
for bad in -x ../../etc/passwd "$HOME/.config/solana/id.json" ASK usb://ledger - "$ADDR;id" "0OIl$ADDR" short; do
  run account "$bad"
  check "an address that is not base58 is refused: $bad" sh -c "[ $RC = 64 ] && grep -q 'is not a base58 address' '$T/err'"
done
run confirm "-v"
check "a signature that is not base58 is refused" refused "'-v' is not a base58 signature (32-88 characters of [1-9A-HJ-NP-Za-km-z])"
run account "ProgTest1111111111111111111111111111111111"
check "a base58 address of 31 bytes is refused after the python3 check" refused "'ProgTest1111111111111111111111111111111111' does not decode to 32 bytes"
run confirm "$ADDR"
check "a 32-byte id is not a signature" refused "'$ADDR' does not decode to 64 bytes"
run program-show "$SIG"
check "a signature is not a program id" sh -c "[ $RC = 64 ] && grep -q 'is not a base58 address' '$T/err'"
(cd "$W" && unset RPC_URL && PATH="$T/sol:$PATH" "$READ" account "$ADDR") >"$T/out" 2>"$T/err"; RC=$?
check "no \$RPC_URL and no --cluster is refused" refused "set \$RPC_URL in the environment, or pass --cluster mainnet-beta, devnet or testnet"
for url in 'https://rpc.example.test/"x' 'https://rpc.example.test/ x' 'https://rpc.example.test/\x'; do
  (cd "$W" && RPC_URL=$url PATH="$T/sol:$PATH" "$READ" account "$ADDR") >"$T/out" 2>"$T/err"; RC=$?
  check "an \$RPC_URL that could escape the config is refused: $url" refused "\$RPC_URL holds a quote, a backslash, whitespace or a control character"
done
for run_arg in "$W/$R" "/tmp/$R" "../wt/$R" "$R/rpc" "$R/" "audit_x" "incident_999" "Incident_1" "bootstrap"; do
  run account "$ADDR" --run "$run_arg"
  check "--run $run_arg is refused" test "$RC" = 64
done
run account "$ADDR" --run incident_0
check "--run without its .gitignore of * is refused" refused "--run has no .gitignore holding exactly *: incident_0"
run account "$ADDR" --run incident_00
check "--run that is a symbolic link is refused" refused "--run is a symbolic link: incident_00"
check "no refusal ran the CLI" test "$(calls)" = 0
tree "$W" > "$T/tree.after"
check "no refusal changed anything in the working directory" cmp -s "$T/tree.before" "$T/tree.after"
(cd "$ROOT" && PATH="$T/sol:$PATH" "$READ" account "$ADDR") >"$T/out" 2>"$T/err"; RC=$?
check "the installation inside the working directory is refused (exit 64)" \
  sh -c "[ $RC = 64 ] && grep -q 'the installation lies inside the working directory' '$T/err'"
mkdir -p "$W/tmpin"
(cd "$W" && TMPDIR="$W/tmpin" PATH="$T/sol:$PATH" "$READ" account "$ADDR") >"$T/out" 2>"$T/err"; RC=$?
check "a TMPDIR inside the working directory is a blocker (exit 3), with nothing made there" \
  sh -c "[ $RC = 3 ] && [ -z \"\$(ls -A '$W/tmpin')\" ] && grep -q 'TMPDIR lies inside the working directory' '$T/err'"
rmdir "$W/tmpin"

# =================================================================================================
# account: the summary, the data's length and sha256, never the data itself.
# =================================================================================================
python3 -I -c 'import sys; open(sys.argv[1], "wb").write(b"\x01\x02ACCOUNT-DATA-\xff" + bytes(range(32)))' "$T/want.data"
WANT_SUM=$(python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$T/want.data")
tree "$W" > "$T/tree.before"; rm -f "$FAKE_ARGV"
run account "$ADDR"
check "account: exit 0" test "$RC" = 0
check "account: the summary lines, the balance in lamports" \
  test "$(cat "$T/out")" = "Public Key: $ADDR
Balance: 2039280 lamports
Owner: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
Executable: false
Rent Epoch: 18446744073709551615
Data Length: 48 bytes
Data SHA-256: $WANT_SUM"
check "account: no hex dump and no data on stdout" sh -c "! grep -q '^0000:\|ACCOUNT-DATA' '$T/out'"
check "account: no temp path on stdout" hasnt "$T/out" "Wrote account data"
check "account: one read, with the data sent to a file" \
  sh -c "[ \"\$(grep -c '\"account\"' '$FAKE_ARGV')\" = 1 ] && grep '\"account\"' '$FAKE_ARGV' | grep -q '\"--output-file\"'"
check "account: the CLI read the endpoint from the config, never from its arguments" \
  python3 -I -c 'import json, sys
calls = [json.loads(l) for l in open(sys.argv[1])]
sys.exit(not all(c["url"] == sys.argv[2] for c in calls) or any("SECRETKEY" in w for c in calls for w in c["argv"]))' "$FAKE_ARGV" "$RPC_URL"
check "account: the keypair path the CLI got names no file" \
  python3 -I -c 'import json, sys; sys.exit(any(json.loads(l)["keypair_exists"] for l in open(sys.argv[1])))' "$FAKE_ARGV"
check "account: without --run, stderr names what went where, for the report" \
  test "$(cat "$T/err")" = "rpc-read: no --run, so no disclosures.tsv row: example.test received account address (getAccountInfo): $ADDR (Rule 11b; list it in the report)"
tree "$W" > "$T/tree.after"
check "account: without --run nothing is written in the working directory" cmp -s "$T/tree.before" "$T/tree.after"
run account "$ADDR" --run "$R"
check "account --run: exit 0" test "$RC" = 0
check "account --run: the data is kept in R/rpc/, byte for byte" cmp -s "$T/want.data" "$W/$R/rpc/account-$ADDR.data"
check "account --run: stdout ends with where the data was kept" test "$(sed -n '$p' "$T/out")" = "Kept: $R/rpc/account-$ADDR.data"
check "account --run: what was printed is kept as R/rpc/account-<address>.txt" cmp -s "$T/out" "$W/$R/rpc/account-$ADDR.txt"
check "account --run: the kept files are readable by their owner only" \
  test "$(ls -l "$W/$R/rpc/account-$ADDR.data" | cut -c1-10)$(ls -l "$W/$R/rpc/account-$ADDR.txt" | cut -c1-10)" = '-rw--------rw-------'
check "account --run: no stderr note" test ! -s "$T/err"
D="$W/$R/disclosures.tsv"
check "account --run: disclosures.tsv starts with its header" test "$(sed -n 1p "$D")" = "$(printf 'time\ttool\tservice\tsent\tcount')"
check "account --run: one row: the tool, the domain, what was sent, 1" \
  test "$(sed -n 2p "$D" | cut -f2-)" = "$(printf 'scripts/rpc-read.sh\texample.test\taccount address (getAccountInfo): %s\t1' "$ADDR")"
check "account --run: the row's time is UTC" sh -c "sed -n 2p '$D' | cut -f1 | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\$'"
check "account --run: no part of the URL but its domain reaches disclosures.tsv" sh -c "! grep -q 'SECRETKEY\|QKEY\|key9' '$D'"
run account "$ADDR" --run "$R"
check "account --run again: the next free names, -2" \
  sh -c "[ $RC = 0 ] && [ -s '$W/$R/rpc/account-$ADDR-2.data' ] && [ -s '$W/$R/rpc/account-$ADDR-2.txt' ]"
check "account --run again: a second row under the same header" test "$(grep -c . "$D")" = 3
run account "$ADDR" --run "./$A" --cluster devnet
check "account --run audit_<n> --cluster devnet: exit 0" test "$RC" = 0
check "--cluster devnet: the fixed public endpoint, in the config" \
  sh -c "tail -n 1 '$FAKE_ARGV' | grep -qF '\"url\": \"https://api.devnet.solana.com\"'"
check "--cluster devnet: the row names solana.com" \
  test "$(sed -n 2p "$W/$A/disclosures.tsv" | cut -f3)" = solana.com
for c in mainnet-beta testnet; do
  run account "$ADDR" --cluster "$c"
  check "--cluster $c: its fixed public endpoint" sh -c "tail -n 1 '$FAKE_ARGV' | grep -qF '\"url\": \"https://api.$c.solana.com\"'"
done
FAKE_ACCOUNT=missing run account "$ADDR" --run "$R"
check "account: an account the CLI cannot read exits 1" test "$RC" = 1
check "... with the CLI's error, the endpoint redacted" \
  sh -c "grep -q 'AccountNotFound' '$T/err' && ! grep -q 'SECRETKEY\|QKEY\|key9' '$T/err'"
check "... and nothing kept" test ! -e "$W/$R/rpc/account-$ADDR-3.data"
FAKE_IGNORE_CONFIG=1 run account "$ADDR"
check "a CLI that does not take the config is a blocker (exit 3)" \
  sh -c "[ $RC = 3 ] && grep -q 'did not load the keyless config' '$T/err'"
check "... and makes no read" sh -c "! tail -n 1 '$FAKE_ARGV' | grep -q '\"account\"'"

# =================================================================================================
# confirm and program-show.
# =================================================================================================
run confirm "$SIG" --run "$R"
check "confirm: exit 0" test "$RC" = 0
check "confirm: the transaction's text, ESC, BEL and CR shown as ?, TAB kept" \
  has "$T/out" "    Program log: hi?[31m red? bell$(printf '\t')tab? carriage"
check "confirm: no raw control character reaches stdout" \
  sh -c "! LC_ALL=C grep -q \"\$(printf '[\\001-\\010\\013-\\037\\177]')\" '$T/out'"
check "confirm: kept as R/rpc/confirm-<signature>.txt" cmp -s "$T/out" "$W/$R/rpc/confirm-$SIG.txt"
check "confirm: the CLI's lines naming the endpoint and the keypair path are dropped" \
  sh -c "[ -s '$T/out' ] && ! grep -q '^RPC URL:\|^Default Signer Path:\|no-keypair' '$T/out'"
check "confirm: the rest of its header stays" has "$T/out" "Commitment: confirmed"
check "confirm: no part of the endpoint but its domain reaches stdout or the kept file" \
  sh -c "[ -s '$W/$R/rpc/confirm-$SIG.txt' ] && ! grep -q 'SECRETKEY\|QKEY\|key9' '$T/out' '$W/$R/rpc/confirm-$SIG.txt'"
FAKE_CONFIRM=url-in-text run confirm "$SIG" --run "$R"
check "confirm: an endpoint named in the transaction's text is redacted, on stdout and in the kept file" \
  sh -c "[ $RC = 0 ] && grep -q 'error sending request for url' '$T/out' && [ -s '$W/$R/rpc/confirm-$SIG-2.txt' ] && ! grep -q 'SECRETKEY\|QKEY\|key9' '$T/out' '$W/$R/rpc/confirm-$SIG-2.txt'"
check "confirm: the row names the signature" \
  sh -c "tail -n 1 '$D' | cut -f2- | grep -qxF \"\$(printf 'scripts/rpc-read.sh\texample.test\ttransaction signature (getSignatureStatuses, getTransaction): %s\t1' '$SIG')\""
FAKE_CONFIRM=missing run confirm "$SIG"
check "confirm: a signature the CLI cannot read exits 1, the error redacted" \
  sh -c "[ $RC = 1 ] && grep -q 'Signature not found' '$T/err' && ! grep -q 'SECRETKEY' '$T/err'"
rm -f "$FAKE_ARGV"
run program-show "$PID" --run "$R"
check "program-show: exit 0, the show output" sh -c "[ $RC = 0 ] && grep -qx 'Program Id: $PID' '$T/out' && grep -qx 'Authority: p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV' '$T/out'"
check "program-show: with a fixed buffer authority, so no signer is looked for" \
  sh -c "grep '\"program\", \"show\"' '$FAKE_ARGV' | grep -q '\"--buffer-authority\", \"11111111111111111111111111111111\"'"
check "program-show: kept as R/rpc/program-show-<id>.txt" cmp -s "$T/out" "$W/$R/rpc/program-show-$PID.txt"
FAKE_SHOW=url-in-text run program-show "$PID" --run "$R"
check "program-show: an endpoint named in the show output is redacted, on stdout and in the kept file" \
  sh -c "[ $RC = 0 ] && grep -q '^Read from' '$T/out' && [ -s '$W/$R/rpc/program-show-$PID-2.txt' ] && ! grep -q 'SECRETKEY\|QKEY\|key9' '$T/out' '$W/$R/rpc/program-show-$PID-2.txt'"
FAKE_LOADER=v4 run program-show "$PID"
check "program-show: a loader-v4 program is read with program-v4 show" \
  sh -c "[ $RC = 0 ] && grep -qx 'Owner: LoaderV411111111111111111111111111111111111' '$T/out' && tail -n 1 '$FAKE_ARGV' | grep -q '\"program-v4\", \"show\", \"--program-id\", \"$PID\", \"--authority\"'"
FAKE_LOADER=none run program-show "$PID"
check "program-show: an id neither show reads exits 1 with both errors, redacted" \
  sh -c "[ $RC = 1 ] && grep -q 'is not an SBF program' '$T/err' && grep -q 'is not owned by loader-v4' '$T/err' && ! grep -q 'SECRETKEY' '$T/err'"
FAKE_SHOWN_ID=OtherProg1111111111111111111111111111111111 run program-show "$PID" --run "$R"
check "program-show: output naming another Program Id is a blocker (exit 3)" \
  sh -c "[ $RC = 3 ] && grep -q 'does not name $PID as its Program Id' '$T/err'"
check "... and nothing is kept" test ! -e "$W/$R/rpc/program-show-$PID-3.txt"

# =================================================================================================
# Blockers and the run directory's checks.
# =================================================================================================
mkdir -p "$T/nosol" "$T/nopy"
for t in bash env git find wc cat sed awk tr mktemp rm mkdir date python3; do
  p=$(command -v "$t" 2>/dev/null) && case "$p" in /*) ln -s "$p" "$T/nosol/$t" ;; esac
done
for t in bash env git find wc cat sed awk tr mktemp rm mkdir date; do
  p=$(command -v "$t" 2>/dev/null) && case "$p" in /*) ln -s "$p" "$T/nopy/$t" ;; esac
done
ln -s "$T/sol/solana" "$T/nopy/solana"
(cd "$W" && PATH="$T/nosol" "$READ" account "$ADDR") >"$T/out" 2>"$T/err"; RC=$?
check "no solana CLI: a blocker (exit 3)" sh -c "[ $RC = 3 ] && grep -q '^\[blocker\] solana CLI not on PATH' '$T/err'"
rm -f "$FAKE_ARGV"
(cd "$W" && PATH="$T/nopy" "$READ" account "$ADDR") >"$T/out" 2>"$T/err"; RC=$?
check "no python3: a blocker (exit 3), before any CLI call" sh -c "[ $RC = 3 ] && grep -q '^\[blocker\] python3 not on PATH' '$T/err' && [ ! -e '$FAKE_ARGV' ]"
G=$(cd "$W" && "$RUNDIR" new incident); mkdir "$W/$G/disclosures.tsv"
run account "$ADDR" --run "$G"
check "a disclosures.tsv that cannot take the row is refused (exit 64), before any CLI call" \
  sh -c "[ $RC = 64 ] && grep -q 'disclosures.tsv is not a regular file of its own' '$T/err' && [ ! -e '$FAKE_ARGV' ]"
G2=$(cd "$W" && "$RUNDIR" new incident); ln -s "$T" "$W/$G2/rpc"
run account "$ADDR" --run "$G2"
check "an R/rpc that is a symbolic link is refused (exit 64)" refused "--run holds a symbolic link: $G2"
G3=$(cd "$W" && "$RUNDIR" new incident); printf 'x\n' > "$W/$G3/rpc"
run account "$ADDR" --run "$G3"
check "an R/rpc that is a file is refused (exit 64)" refused "$G3/rpc is not a directory"
check "... nothing was read for either" test ! -e "$FAKE_ARGV"

# =================================================================================================
# The case file, under each bash on the machine.
# =================================================================================================
SHELLS=("$BASH")
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then
  SHELLS+=(/bin/bash)
fi
echo "# shells: ${SHELLS[*]}"
CW="$T/cases-wt"; mkdir -p "$CW"; (cd "$CW" && "$RUNDIR" new incident >/dev/null); ln -s incident_1 "$CW/incident_2"
tree "$CW" > "$T/ctree.before"; rm -f "$FAKE_ARGV"
ncase=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  want_rc=${line%%$'\t'*}
  rest=${line#*$'\t'}
  want_err=${rest%%$'\t'*}
  rest=${rest#*$'\t'}
  IFS=$'\t' read -r -a args <<< "$rest"
  ncase=$((ncase + 1))
  i=0
  for sh in "${SHELLS[@]}"; do
    (cd "$CW" && PATH="$T/sol:$PATH" RPC_URL=https://rpc.example.test/ "$sh" "$READ" "${args[@]}") >"$T/out" 2>"$T/err" </dev/null
    RC=$?
    if [ "$RC" = "$want_rc" ] && [ "$(cat "$T/err")" = "$want_err" ] && [ ! -s "$T/out" ]; then
      [ "$i" -gt 0 ] || ok "case: rpc-read.sh ${args[*]}"
    else
      ko "case ($sh): rpc-read.sh ${args[*]} -> status $RC, stderr: $(cat "$T/err")"
    fi
    i=$((i + 1))
  done
done < "$CASES"
check "the case file has cases ($ncase)" test "$ncase" -gt 30
tree "$CW" > "$T/ctree.after"
check "no case changed anything in the working directory" cmp -s "$T/ctree.before" "$T/ctree.after"
check "no case ran the CLI" test ! -e "$FAKE_ARGV"

echo
echo "rpc-read tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
