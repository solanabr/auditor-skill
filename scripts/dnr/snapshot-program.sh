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
# What it does (read-only — two CLI calls, no signing, no keypair):
#   1. `solana program show <id>` → <incident_dir>/bin/<id>.show.txt
#   2. `solana program dump <id> <incident_dir>/bin/<id>.so`
#   3. checks the ELF magic, hashes the dump the way solana-verify does (trailing
#      zero padding trimmed, then sha256), and prints ONE ledger-ready line:
#        program=<id> owner=<loader> last_deployed_slot=<N> authority=<A>
#        sha256_zero_trimmed=<hex> elf_bytes=<n> padding_bytes=<n> file=bin/<id>.so
#
# Compare `last_deployed_slot` to the incident slot: earlier → this dump IS the
# incident binary (binary_provenance: dumped-unchanged); later → a newer upgrade
# replaced it (dumped-after-hotfix; the incident bytes need an archived binary or a
# solana-verify hash-matched build).
#
# Loader-v4 programs (owner LoaderV411…) are not handled here: the script stops
# with a named blocker rather than guess at a CLI command.
#
# SECRETS: --url takes "$RPC_URL" from the environment; the CLI's stderr is captured
# to a temp file and passed through redact.sh (the CLI echoes the full URL, key
# included, in its errors). Nothing written to <incident_dir> contains the URL.
#
# Exit: 0 ok · 2 usage / not a base58 id / no $RPC_URL · 3 named blocker (no solana
# CLI, CLI error, loader-v4, dump without ELF magic). bash >= 3.2, python3 for the
# hash, run as `python3 -I` because the working directory is usually the audited
# repo: without -I, a hashlib.py there would be imported in place of the stdlib.

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
if ! command -v solana >/dev/null 2>&1; then
  echo "[blocker] solana CLI not on PATH — install it, or dump the program another way and record its zero-trimmed sha256 and last-deployed slot in LEDGER.md by hand." >&2
  exit 3
fi

mkdir -p "$dir/bin"
# Rule 11d: an incident_<n>/ directory ignores itself when it has no .gitignore of
# its own, so the dumped program never shows in git status.
case "$(basename "$dir")" in
  incident_*) [ -e "$dir/.gitignore" ] || printf '*\n' > "$dir/.gitignore" ;;
esac
err="$(mktemp "${TMPDIR:-/tmp}/dnr_snap.XXXXXX")"
trap 'rm -f "$err"' EXIT
show="$dir/bin/$pid.show.txt"
so="$dir/bin/$pid.so"

if ! solana program show "$pid" --url "$RPC_URL" >"$show" 2>"$err"; then
  echo "[blocker] solana program show failed for $pid:" >&2
  "$REDACT" <"$err" >&2
  exit 3
fi
field() { awk -F': *' -v k="$1" '$1 == k {print $2; exit}' "$show"; }
owner="$(field "Owner")"
slot="$(field "Last Deployed In Slot")"
auth="$(field "Authority")"

case "$owner" in
  LoaderV4*)
    echo "[blocker] $pid is a loader-v4 program (owner $owner): snapshot it with loader-v4 tooling and record the zero-trimmed sha256 and the deploy slot (LoaderV4State bytes [0..8]) in LEDGER.md by hand." >&2
    exit 3 ;;
esac

: > "$err"
if ! solana program dump "$pid" "$so" --url "$RPC_URL" >/dev/null 2>"$err"; then
  echo "[blocker] solana program dump failed for $pid:" >&2
  "$REDACT" <"$err" >&2
  exit 3
fi

magic="$(head -c 4 "$so" | od -An -tx1 | tr -d ' \n')"
if [ "$magic" != "7f454c46" ]; then
  echo "[blocker] dump of $pid is not an ELF (magic=${magic:-empty}); not usable as program bytes." >&2
  exit 3
fi

stats="$(python3 -I -c 'import hashlib, sys
raw = open(sys.argv[1], "rb").read()
trimmed = raw.rstrip(b"\0")
print(hashlib.sha256(trimmed).hexdigest(), len(trimmed), len(raw) - len(trimmed))' "$so")"
set -- $stats
echo "program=$pid owner=${owner:-unknown} last_deployed_slot=${slot:-unknown} authority=${auth:-none} sha256_zero_trimmed=$1 elf_bytes=$2 padding_bytes=$3 file=bin/$pid.so"
