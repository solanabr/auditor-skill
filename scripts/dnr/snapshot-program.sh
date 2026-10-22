#!/usr/bin/env bash
# snapshot-program.sh — preserve the deployed program bytes BEFORE anything else.
#
#   bash "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/snapshot-program.sh" <program_id> <incident_dir>
#
# $RPC_URL must already be exported (never typed on the command line). Run it from
# the installation, never as a relative scripts/ path: the audited repo may ship a
# same-named file.
#
# Why first: a hotfix upgrade overwrites the on-chain ELF. If the team ships a fix
# while the hunt is running, the incident binary is gone, and Leg 3 of
# `confirmed_exploited` (a PoC on the real bytes) can no longer be met. So step 1 of
# /auditor:hunt and /auditor:respond runs this for every implicated program, before
# any collection or analysis.
#
# What it does (read-only — no signing, and no keypair the CLI could sign with):
#   1. writes a throwaway CLI config in a private temp dir (mode 0700, removed on
#      exit): `json_rpc_url` is $RPC_URL, so the URL never appears in argv, and
#      `keypair_path` names a file that does not exist. `solana config get keypair`
#      must report that path back, or the CLI fell back to its defaults and the
#      script stops with a blocker.
#   2. reads the program's record: `solana -C <config> program show <id>` (with a
#      fixed `--buffer-authority`, so the CLI never looks for a signer). That command
#      refuses a loader-v4 program ("is not an SBF program"), so when it fails the
#      script reads the account's owner (`solana account <id> --output json`); for
#      LoaderV4 it uses `solana program-v4 show --program-id <id>` (fixed
#      `--authority`) instead, and any other owner is a named blocker.
#   3. dumps the bytes to the temp dir (`program dump`, or `program-v4 download` for
#      loader-v4), then reads the record again: a last-deployed slot that changed in
#      between means a redeploy raced the dump, so it dumps once more, and stops with
#      a blocker if the slot moves again.
#   4. checks the ELF magic, hashes the dump the way solana-verify does (trailing
#      zero padding trimmed, then sha256), and keeps it as
#      <incident_dir>/bin/<id>@<slot>.so with the record as bin/<id>@<slot>.show.txt.
#      A program on an immutable loader (BPFLoader2 / BPFLoader1) has no deploy slot:
#      it is recorded as `n/a (immutable loader)` and kept as bin/<id>@immutable.so.
#      Files are never overwritten: when bin/<id>@<slot>.so already exists, the new
#      dump must have the same bytes (it is then kept as it was), or the script
#      stops with a blocker and writes nothing. A later run after a hotfix therefore
#      adds bin/<id>@<new slot>.so next to the preserved incident binary.
#   5. prints ONE ledger-ready line:
#        program=<id> owner=<loader> last_deployed_slot=<N> authority=<A>
#        [status=<loader-v4 status>] sha256_zero_trimmed=<hex> elf_bytes=<n>
#        padding_bytes=<n> file=bin/<id>@<slot>.so
#
# Compare `last_deployed_slot` to the incident slot: earlier → this dump IS the
# incident binary (binary_provenance: dumped-unchanged); later → a newer upgrade
# replaced it (dumped-after-hotfix; the incident bytes need an archived binary or a
# solana-verify hash-matched build).
#
# RUN DIRECTORY: <incident_dir>, and the nearest incident_* directory above it, must
# not be a symbolic link, hold one, or be tracked by git; such a directory is refused
# with exit 2 before anything is written or the CLI runs.
#
# SECRETS: the CLI reads "$RPC_URL" from the temp config, never from argv; an
# $RPC_URL holding a quote, a backslash, whitespace or a control character is refused.
# The CLI's stderr is captured to a temp file and passed through redact.sh (the CLI
# echoes the full URL, key included, in its errors). Nothing written to
# <incident_dir> contains the URL.
#
# Exit: 0 ok · 2 usage / not a base58 id / no or unusable $RPC_URL / a refused run
# directory · 3 named blocker (no solana CLI, no python3, config not taken, not a
# program, CLI error, redeployed during the snapshot, dump without ELF magic, a
# preserved file with other bytes). bash >= 3.2; python3 parses the account and
# hashes the dump, run as `python3 -I` because the working directory is usually the
# audited repo: without -I, a hashlib.py there would be imported in place of the
# stdlib.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDACT="$HERE/redact.sh"

pid="${1:-}"; dir="${2:-}"
if [ -z "$pid" ] || [ -z "$dir" ]; then
  echo "usage: snapshot-program.sh <program_id> <incident_dir>" >&2
  exit 2
fi
# The id becomes part of file names under <incident_dir>/bin/: accept only a base58
# public key (32-44 characters of the Bitcoin alphabet), so it cannot carry a path.
if ! [[ "$pid" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]]; then
  echo "snapshot-program.sh: '$pid' is not a base58 program id (32-44 characters of [1-9A-HJ-NP-Za-km-z])." >&2
  exit 2
fi
if [ -z "${RPC_URL:-}" ]; then
  echo "snapshot-program.sh: set \$RPC_URL in the environment." >&2
  exit 2
fi
# The URL goes into a quoted YAML value: refuse what could end or escape it.
case "$RPC_URL" in
  *[[:space:][:cntrl:]\"\\]*)
    echo "snapshot-program.sh: \$RPC_URL holds a quote, a backslash, whitespace or a control character; refusing it." >&2
    exit 2 ;;
esac
case "$dir" in */) dir="${dir%"${dir##*[!/]}"}"; [ -n "$dir" ] || dir=/ ;; esac

# refuse_planted <dir>: exit 2 unless <dir> is safe to write into — not a symbolic
# link, holding none, and not tracked by git. The git calls carry the Rule 11c flags,
# because the tree is usually the audited one. Outside a work tree nothing is tracked;
# inside one, a path git cannot classify is refused.
refuse_planted() {
  local listed
  if [ -L "$1" ]; then
    echo "${0##*/}: refusing $1: it is a symbolic link — use a new run directory." >&2; exit 2
  fi
  if [ -d "$1" ] && [ -n "$(find "$1" -type l -print -quit 2>/dev/null)" ]; then
    echo "${0##*/}: refusing $1: it contains a symbolic link — use a new run directory." >&2; exit 2
  fi
  [ -d "$(dirname "$1")" ] || return 0
  [ "$(git --no-pager -c core.fsmonitor=false -c log.showSignature=false -C "$(dirname "$1")" \
        rev-parse --is-inside-work-tree 2>/dev/null)" = true ] || return 0
  if ! listed="$(git --no-pager -c core.fsmonitor=false -c log.showSignature=false -C "$(dirname "$1")" \
        ls-files -- ":(literal,icase)$(basename "$1")" 2>/dev/null)"; then
    echo "${0##*/}: refusing $1: git cannot tell whether it is tracked." >&2; exit 2
  fi
  if [ -n "$listed" ]; then
    echo "${0##*/}: refusing $1: git tracks it, so it is not a run directory to write into." >&2; exit 2
  fi
  return 0
}
# <incident_dir>, and the nearest incident_* directory above it, checked as a whole.
refuse_planted "$dir"
run_dir="$dir"
while :; do
  case "$(basename "$run_dir")" in incident_*) [ "$run_dir" = "$dir" ] || refuse_planted "$run_dir"; break ;; esac
  case "$run_dir" in .|/) break ;; esac
  run_dir="$(dirname "$run_dir")"
done

if ! command -v solana >/dev/null 2>&1; then
  echo "[blocker] solana CLI not on PATH — install it, or dump the program another way and record its zero-trimmed sha256 and last-deployed slot in LEDGER.md by hand." >&2
  exit 3
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[blocker] python3 not on PATH — it reads the account owner and hashes the dump; install it, or dump the program another way and record its zero-trimmed sha256 and last-deployed slot in LEDGER.md by hand." >&2
  exit 3
fi

# mktemp -d creates the directory with mode 0700.
tmp="$(mktemp -d "${TMPDIR:-/tmp}/dnr_snap.XXXXXX")" || {
  echo "[blocker] cannot create a private temp directory for the CLI config." >&2; exit 3; }
trap 'rm -rf "$tmp"' EXIT
err="$tmp/stderr"; cfg="$tmp/cli.yml"; nokey="$tmp/no-keypair.json"
show="$tmp/show.txt"; dump="$tmp/dump.so"
printf 'json_rpc_url: "%s"\nwebsocket_url: ""\nkeypair_path: "%s"\n' "$RPC_URL" "$nokey" > "$cfg"
# A config the CLI cannot parse is silently replaced by its defaults (public
# mainnet-beta and the default keypair), so confirm it took this one.
case "$(solana -C "$cfg" config get keypair 2>/dev/null)" in
  *"$nokey"*) ;;
  *) echo "[blocker] the solana CLI did not load the keyless config; snapshot $pid by hand and record its zero-trimmed sha256 and last-deployed slot in LEDGER.md." >&2
     exit 3 ;;
esac

blocker() {  # blocker <message>: print it and the CLI's redacted stderr, then exit 3
  echo "[blocker] $1" >&2
  "$REDACT" <"$err" >&2
  exit 3
}
# A fixed, valid pubkey (the System Program id) for --buffer-authority / --authority:
# both only select listings, and naming one stops the CLI from resolving a signer.
NOBODY=11111111111111111111111111111111
LOADER_V4=LoaderV411111111111111111111111111111111111
loader=v3; dumpcmd="program dump"
show_program() {  # the program's record -> $show
  : > "$err"
  if [ "$loader" = v4 ]; then
    solana -C "$cfg" program-v4 show --program-id "$pid" --authority "$NOBODY" >"$show" 2>"$err"
  else
    solana -C "$cfg" program show "$pid" --buffer-authority "$NOBODY" >"$show" 2>"$err"
  fi
}
dump_program() {  # the program's bytes -> $dump
  : > "$err"; rm -f "$dump"
  if [ "$loader" = v4 ]; then
    solana -C "$cfg" program-v4 download "$dump" --program-id "$pid" >/dev/null 2>"$err"
  else
    solana -C "$cfg" program dump "$pid" "$dump" >/dev/null 2>"$err"
  fi
}
field() { awk -F': *' -v k="$1" '$1 == k {print $2; exit}' "$show"; }

if ! show_program; then
  # `program show` refuses a loader-v4 account ("is not an SBF program"): read the
  # owner from the account itself before deciding what the id is.
  cp "$err" "$tmp/show.err"
  owner="$(solana -C "$cfg" account "$pid" --output json 2>/dev/null \
    | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["account"]["owner"])' 2>/dev/null)"
  cp "$tmp/show.err" "$err"
  case "$owner" in
    "$LOADER_V4") loader=v4; dumpcmd="program-v4 download"
      show_program || blocker "solana program-v4 show failed for $pid:" ;;
    "") blocker "solana program show failed for $pid, and its account could not be read:" ;;
    *) blocker "$pid is not a program the solana CLI can dump (owner $owner):" ;;
  esac
fi

# Dump, then read the record again: a redeploy between the two reads pairs one
# slot with another slot's bytes, so a moved slot means one more try, then a stop.
slot="$(field "Last Deployed In Slot")"
tries=0
while :; do
  dump_program || blocker "solana $dumpcmd failed for $pid:"
  first="$slot"
  show_program || blocker "re-reading $pid after the dump failed:"
  slot="$(field "Last Deployed In Slot")"
  [ "$slot" = "$first" ] && break
  tries=$((tries + 1))
  if [ "$tries" -ge 2 ]; then
    : > "$err"
    blocker "$pid was redeployed during the snapshot (last-deployed slot moved from $first to $slot, twice in a row); run it again, or record the bytes by hand."
  fi
done
owner="$(field "Owner")"; auth="$(field "Authority")"; status="$(field "Status")"

magic="$(head -c 4 "$dump" | od -An -tx1 | tr -d ' \n')"
if [ "$magic" != "7f454c46" ]; then
  echo "[blocker] dump of $pid is not an ELF (magic=${magic:-empty}); not usable as program bytes." >&2
  exit 3
fi

case "$owner" in
  BPFLoader1111111111111111111111111111111111|BPFLoader2111111111111111111111111111111111)
    slot_out="n/a (immutable loader)"; tag=immutable ;;
  *) slot_out="${slot:-unknown}"; tag="$slot"
     [[ "$tag" =~ ^[0-9]+$ ]] || tag=unknown ;;
esac

mkdir -p "$dir/bin" || exit 2
# Rule 11d: an incident_<n>/ directory ignores itself when it has no .gitignore of
# its own, so the dumped program never shows in git status.
case "$(basename "$dir")" in
  incident_*) [ -e "$dir/.gitignore" ] || printf '*\n' > "$dir/.gitignore" ;;
esac
so="$dir/bin/$pid@$tag.so"
# Never overwrite a preserved binary: the same slot must mean the same bytes.
if [ -e "$so" ]; then
  if ! cmp -s "$so" "$dump"; then
    echo "[blocker] bin/$pid@$tag.so already exists with other bytes than the program has now; it was kept, and nothing was written. Compare the two before trusting either." >&2
    exit 3
  fi
  echo "kept bin/$pid@$tag.so: the program still has the same bytes" >&2
else
  ( set -C; cat "$dump" > "$so" ) 2>/dev/null || {
    echo "[blocker] could not write bin/$pid@$tag.so without overwriting a file." >&2; exit 3; }
fi
[ -e "$dir/bin/$pid@$tag.show.txt" ] || ( set -C; cat "$show" > "$dir/bin/$pid@$tag.show.txt" ) 2>/dev/null

if ! stats="$(python3 -I -c 'import hashlib, sys
raw = open(sys.argv[1], "rb").read()
trimmed = raw.rstrip(b"\0")
print(hashlib.sha256(trimmed).hexdigest(), len(trimmed), len(raw) - len(trimmed))' "$so")" || [ -z "$stats" ]; then
  echo "[blocker] could not hash bin/$pid@$tag.so." >&2
  exit 3
fi
set -- $stats
echo "program=$pid owner=${owner:-unknown} last_deployed_slot=$slot_out authority=${auth:-none}${status:+ status=$status} sha256_zero_trimmed=$1 elf_bytes=$2 padding_bytes=$3 file=bin/$pid@$tag.so"
