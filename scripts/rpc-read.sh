#!/bin/bash
# rpc-read.sh — one read-only Solana RPC read through the solana CLI: an account, a transaction or a
# program's metadata, for the audit and detection & response flows.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rpc-read.sh" account <address> [--run <R>] [--cluster mainnet-beta|devnet|testnet]
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rpc-read.sh" confirm <signature> [--run <R>] [--cluster mainnet-beta|devnet|testnet]
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rpc-read.sh" program-show <program_id> [--run <R>] [--cluster mainnet-beta|devnet|testnet]
#
# Run it directly by its quoted path in the installation, from the working directory, never as a scripts/
# path relative to it. Each option is given at most once. A refusal is one stderr line,
# "rpc-read: refused: <reason>", with exit 64, before anything is read or written.
#
# Endpoint: $RPC_URL from the environment (never typed on the command line), or, with --cluster, one of
# the public endpoints fixed here: mainnet-beta https://api.mainnet-beta.solana.com, devnet
# https://api.devnet.solana.com, testnet https://api.testnet.solana.com. The CLI runs on a throwaway
# config in a private temp directory (mode 0700, outside the working directory, removed on exit):
# json_rpc_url is the endpoint, so the URL never appears in argv, and keypair_path names a file that does
# not exist. `solana config get keypair` must report that path back, or the CLI fell back to its defaults
# (public mainnet-beta and the default keypair) and the read stops with a blocker. An $RPC_URL holding a
# quote, a backslash, whitespace or a control character is refused. The CLI's output and errors pass
# through scripts/dnr/redact.sh, since its text can name the endpoint, key included.
#
# Reads, with read-only RPC methods only (nothing is signed or sent):
#   account <address>      `solana account <address> --lamports --output-file <temp file>`: prints the
#                          address, balance in lamports, owner, executable flag and rent epoch, then the
#                          data's length and sha256. The data itself is never printed; with --run it is
#                          kept as R/rpc/account-<address>.data.
#   confirm <signature>    `solana confirm -v <signature>`: the transaction's status and details, without
#                          the CLI's first lines, which name the endpoint and the keypair path.
#   program-show <id>      `solana program show <id>`, or `program-v4 show` for a loader-v4 program (both
#                          with a fixed authority, so the CLI never looks for a signer); the output must
#                          name <id> as its Program Id.
# An address or program id is base58 that decodes to 32 bytes, a signature to 64. Every control character
# in what is printed shows as ?, except TAB and LF.
#
# --run R names a run directory, audit_<n> or incident_<n> (scripts/lib/confine.sh: directly in the
# working directory, holding no symbolic link, untracked in any letter case, a .gitignore of "*"). The read
# is then recorded in R/disclosures.tsv before the CLI contacts the endpoint (OUTPUT-RULES.md Rule 11b; the
# format is in scripts/lib/confine.sh), and what was printed is kept as R/rpc/<read>-<id>.txt (account-,
# confirm- or program-show-; <read>-<id>-2.txt and so on once a name is taken), each file created anew with
# noclobber. Without --run nothing is written, and stderr names the service and what it received, for the
# report's Rule 11b list.
#
# Exit: 0 done · 1 the CLI ran and the read failed (its error, redacted, on stderr) · 3 blocker (no solana
# CLI or python3, no private temp directory, the CLI did not take the config, a disclosure row or a kept
# file that could not be written, show output naming another program id) · 64 refused.
# Needs bash >= 3.2, the solana CLI, and python3 (the id check and the hash, as python3 -I).

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'rpc-read: refused: the installation cannot be resolved\n' >&2; exit 64; }
. "$here/lib/confine.sh" || { printf 'rpc-read: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
confine_init rpc-read "${here%/*}"
confine_need env git find wc cat sed awk tr mktemp rm mkdir date
WT=$CONFINE_WT
REDACT="$here/dnr/redact.sh"
exec </dev/null

refuse() { confine_refuse "$1"; }
USAGE='usage: rpc-read.sh account <address> | confirm <signature> | program-show <program_id> [--run <R>] [--cluster mainnet-beta|devnet|testnet]'
SYSTEM_ID=11111111111111111111111111111111

[ $# -ge 2 ] || refuse "$USAGE"
what=$1 id=$2
shift 2
case "$what" in
  account|program-show) bytes=32 ;;
  confirm) bytes=64 ;;
  *) refuse "$USAGE" ;;
esac
run="" cluster="" seen=" "
while [ $# -gt 0 ]; do
  case "$1" in
    --run|--cluster)
      case "$seen" in *" $1 "*) refuse "$1 is given twice" ;; esac
      seen="$seen$1 "
      [ $# -ge 2 ] || refuse "$1 needs a value"
      if [ "$1" = --run ]; then run=$2; else cluster=$2; fi
      shift 2 ;;
    *) refuse "unknown argument: $(confine_text "$1")" ;;
  esac
done
# The id reaches the CLI as an argument and names a kept file: base58 only, so it can carry neither an
# option nor a path.
if [ "$bytes" -eq 64 ]; then
  [[ "$id" =~ ^[1-9A-HJ-NP-Za-km-z]{32,88}$ ]] || refuse "'$(confine_text "$id")' is not a base58 signature (32-88 characters of [1-9A-HJ-NP-Za-km-z])"
else
  [[ "$id" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]] || refuse "'$(confine_text "$id")' is not a base58 address (32-44 characters of [1-9A-HJ-NP-Za-km-z])"
fi
case "$cluster" in
  '')
    [ -n "${RPC_URL:-}" ] || refuse "set \$RPC_URL in the environment, or pass --cluster mainnet-beta, devnet or testnet"
    url=$RPC_URL ;;
  mainnet-beta) url=https://api.mainnet-beta.solana.com ;;
  devnet) url=https://api.devnet.solana.com ;;
  testnet) url=https://api.testnet.solana.com ;;
  *) refuse "--cluster takes mainnet-beta, devnet or testnet, not $(confine_text "$cluster")" ;;
esac
# The URL goes into a quoted YAML value: refuse what could end or escape it.
case "$url" in
  *[[:space:][:cntrl:]\"\\]*) refuse "\$RPC_URL holds a quote, a backslash, whitespace or a control character" ;;
esac
if [ -n "$run" ]; then
  confine_rundir "$run" "--run"
  run=$CONFINE_RUN
  confine_path "$run/rpc" "$run/rpc" any
  case "$CONFINE_TYPE" in file) refuse "$run/rpc is not a directory" ;; esac
  confine_disclosures_ok "$run" ||
    refuse "$run/disclosures.tsv is not a regular file of its own with the disclosure header, so the read could not be recorded"
fi

if ! command -v solana >/dev/null 2>&1; then
  echo "[blocker] solana CLI not on PATH; install it to read $id." >&2
  exit 3
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[blocker] python3 not on PATH; it checks the id and hashes the data." >&2
  exit 3
fi
case "$(confine_b58_bytes "$id")" in
  "$bytes") ;;
  [0-9]*) refuse "'$id' does not decode to $bytes bytes" ;;
  *) echo "[blocker] python3 -I did not run, so $id could not be checked." >&2; exit 3 ;;
esac

if confine_scratch rpc_read; then
  tmp=$CONFINE_SCRATCH
elif [ $? -eq 2 ]; then
  echo "[blocker] cannot create a private temp directory: TMPDIR lies inside the working directory; set it to a directory outside the tree." >&2; exit 3
else
  echo "[blocker] cannot create a private temp directory for the CLI config." >&2; exit 3
fi
trap 'rm -rf "$tmp"' EXIT
err="$tmp/stderr" cfg="$tmp/cli.yml" nokey="$tmp/no-keypair.json" cli="$tmp/cli.txt" out="$tmp/out.txt" data="$tmp/account.data"
printf 'json_rpc_url: "%s"\nwebsocket_url: ""\nkeypair_path: "%s"\n' "$url" "$nokey" > "$cfg" ||
  { echo "[blocker] cannot write the CLI config." >&2; exit 3; }
case "$(solana -C "$cfg" config get keypair 2>/dev/null)" in
  *"$nokey"*) ;;
  *) echo "[blocker] the solana CLI did not load the keyless config; read $id another way." >&2
     exit 3 ;;
esac

# Rule 11b: with --run, the row goes into R/disclosures.tsv before the CLI contacts the endpoint.
confine_service "$url"
case "$what" in
  account) kind="account address (getAccountInfo)" ;;
  confirm) kind="transaction signature (getSignatureStatuses, getTransaction)" ;;
  program-show) kind="program id (solana program show)" ;;
esac
if [ -n "$run" ]; then
  confine_disclose "$run" scripts/rpc-read.sh "$CONFINE_SERVICE" "$kind" "$id" ||
    { echo "[blocker] cannot add the read's row to $run/disclosures.tsv, so nothing was read." >&2; exit 3; }
else
  printf 'rpc-read: no --run, so no disclosures.tsv row: %s received %s: %s (Rule 11b; list it in the report)\n' \
    "$CONFINE_SERVICE" "$kind" "$id" >&2
fi

# shown <file>: the file with every control character but TAB and LF as ?.
shown() { tr '\000-\010\013-\037\177' '?' < "$1"; }
field() { awk -F': *' -v k="$1" '$1 == k { print $2; exit }' "$2" 2>/dev/null; }
failed() { # failed <what>: the CLI's error, redacted, and exit 1
  echo "rpc-read: $1:" >&2
  "$REDACT" < "$err" >&2
  exit 1
}

case "$what" in
  account)
    # --output-file sends the data to a file, so the CLI prints no hex dump of it.
    solana -C "$cfg" account "$id" --lamports --output-file "$data" > "$tmp/account.txt" 2> "$err" ||
      failed "the solana CLI could not read the account $id"
    [ -f "$data" ] || : > "$data"
    # From /, as every python3 call here: nothing in the working directory picks the interpreter.
    sum=$(cd / && python3 -I -c 'import hashlib, sys
d = open(sys.argv[1], "rb").read()
print(len(d), hashlib.sha256(d).hexdigest())' "$data" 2>/dev/null)
    [[ "$sum" =~ ^[0-9]+\ [0-9a-f]{64}$ ]] || { echo "[blocker] python3 -I did not hash the account data." >&2; exit 3; }
    { awk '/^(Public Key|Balance|Owner|Executable|Rent Epoch): / { print }' "$tmp/account.txt"
      printf 'Data Length: %s bytes\nData SHA-256: %s\n' "${sum%% *}" "${sum#* }"; } > "$cli" ;;
  confirm)
    # In verbose mode the CLI's text starts with the endpoint, URL and key included, and the keypair path.
    solana -C "$cfg" confirm -v "$id" > "$tmp/confirm.txt" 2> "$err" ||
      failed "the solana CLI could not read the transaction $id"
    sed -e '/^RPC URL: /d' -e '/^Default Signer Path: /d' "$tmp/confirm.txt" > "$cli" ||
      { echo "[blocker] the CLI's output could not be read back." >&2; exit 3; } ;;
  program-show)
    if ! solana -C "$cfg" program show "$id" --buffer-authority "$SYSTEM_ID" > "$cli" 2> "$err"; then
      mv "$err" "$tmp/stderr.show"
      if ! solana -C "$cfg" program-v4 show --program-id "$id" --authority "$SYSTEM_ID" > "$cli" 2> "$err"; then
        echo "rpc-read: neither solana program show nor program-v4 show reads $id as a program:" >&2
        "$REDACT" < "$tmp/stderr.show" >&2
        "$REDACT" < "$err" >&2
        exit 1
      fi
    fi
    if [ "$(field "Program Id" "$cli")" != "$id" ]; then
      echo "[blocker] the solana CLI's show output does not name $id as its Program Id." >&2
      exit 3
    fi ;;
esac
# What the CLI printed passes through redact.sh, as its errors do, before it is shown or kept.
"$REDACT" < "$cli" > "$out" || { echo "[blocker] the CLI's output could not be redacted." >&2; exit 3; }

# keep_stem <stem>: sets STEM to the first free R/rpc/<stem>[-<k>] name, for the .txt and the .data file alike.
keep_stem() {
  local k=1
  STEM=$1
  while [ -e "$WT/$run/rpc/$STEM.txt" ] || [ -L "$WT/$run/rpc/$STEM.txt" ] ||
        [ -e "$WT/$run/rpc/$STEM.data" ] || [ -L "$WT/$run/rpc/$STEM.data" ]; do
    k=$((k + 1))
    [ "$k" -le 999 ] || return 1
    STEM=$1-$k
  done
}
if [ -n "$run" ]; then
  confine_rundir "$run" "--run"
  confine_path "$run/rpc" "$run/rpc" any
  case "$CONFINE_TYPE" in
    file) refuse "$run/rpc is not a directory" ;;
    none) confine_mkdir "$WT/$run/rpc" || { echo "[blocker] cannot create $run/rpc." >&2; exit 3; } ;;
  esac
  keep_stem "$what-$id" || { echo "[blocker] no free name for $what-$id in $run/rpc." >&2; exit 3; }
  if [ "$what" = account ]; then
    confine_new_copy "$data" "$WT/$run/rpc/$STEM.data" || { echo "[blocker] could not write $run/rpc/$STEM.data." >&2; exit 3; }
    printf 'Kept: %s\n' "$run/rpc/$STEM.data" >> "$out"
  fi
  shown "$out" > "$tmp/kept.txt"
  confine_new_copy "$tmp/kept.txt" "$WT/$run/rpc/$STEM.txt" || { echo "[blocker] could not write $run/rpc/$STEM.txt." >&2; exit 3; }
fi
shown "$out"
