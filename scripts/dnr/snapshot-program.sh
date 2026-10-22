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
#   2. `solana -C <config> program show <id>` into the temp dir (with a fixed
#      `--buffer-authority`, so the CLI never looks for a signer)
#   3. `solana -C <config> program dump <id>` into the temp dir
#   4. checks the ELF magic, hashes the dump the way solana-verify does (trailing
#      zero padding trimmed, then sha256), keeps the dump and the show output in
#      <incident_dir>/bin/, and prints ONE ledger-ready line:
#        program=<id> owner=<loader> last_deployed_slot=<N> authority=<A>
#        sha256_zero_trimmed=<hex> elf_bytes=<n> padding_bytes=<n> file=bin/<id>.so
#
# NEVER OVERWRITTEN: the first snapshot is bin/<id>.so + bin/<id>.show.txt, the
# incident-time bytes that Leg 3 and the patch flow run on. A later run (respond
# runs this again after the hunt) compares the program on-chain with every
# snapshot already in bin/:
#   * the same last-deployed slot and zero-trimmed sha256 as one of them: it prints
#     "unchanged" and that snapshot's line, writes nothing, and exits 0;
#   * otherwise it keeps the current bytes as bin/<id>@<slot>.so and
#     bin/<id>@<slot>.show.txt, and prints the first snapshot's line and the new one.
# Files are written with noclobber (`set -C`): a name already taken stops the
# script with a blocker instead of being replaced.
#
# Compare `last_deployed_slot` to the incident slot: earlier → this dump IS the
# incident binary (binary_provenance: dumped-unchanged); later → a newer upgrade
# replaced it (dumped-after-hotfix; the incident bytes need an archived binary or a
# solana-verify hash-matched build).
#
# Loader-v4 programs (owner LoaderV411…) are not handled here: the script stops
# with a named blocker rather than guess at a CLI command.
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
# directory · 3 named blocker (no solana CLI or python3, config not taken, CLI error,
# loader-v4, dump without ELF magic, hash not computed, a snapshot name already
# taken).
# bash >= 3.2, python3 for the hash, checked before the CLI runs, and run as
# `python3 -I` because the working directory is usually the audited repo: without
# -I, a hashlib.py there would be imported in place of the stdlib.

# -C (noclobber): no redirection in this script replaces an existing file.
set -Cuo pipefail

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
  echo "[blocker] python3 not on PATH — it hashes the dump; install it, or snapshot $pid by hand and record its zero-trimmed sha256 and last-deployed slot in LEDGER.md." >&2
  exit 3
fi

# mktemp -d creates the directory with mode 0700.
tmp="$(mktemp -d "${TMPDIR:-/tmp}/dnr_snap.XXXXXX")" || {
  echo "[blocker] cannot create a private temp directory for the CLI config." >&2; exit 3; }
trap 'rm -rf "$tmp"' EXIT
err="$tmp/stderr"; cfg="$tmp/cli.yml"; nokey="$tmp/no-keypair.json"
printf 'json_rpc_url: "%s"\nwebsocket_url: ""\nkeypair_path: "%s"\n' "$RPC_URL" "$nokey" > "$cfg"
# A config the CLI cannot parse is silently replaced by its defaults (public
# mainnet-beta and the default keypair), so confirm it took this one.
case "$(solana -C "$cfg" config get keypair 2>/dev/null)" in
  *"$nokey"*) ;;
  *) echo "[blocker] the solana CLI did not load the keyless config; snapshot $pid by hand and record its zero-trimmed sha256 and last-deployed slot in LEDGER.md." >&2
     exit 3 ;;
esac

show="$tmp/show.txt"; dump="$tmp/dump.so"
# --buffer-authority only matters for --buffers / --programs listings; naming one
# (the System Program id) stops `show` from resolving a default signer.
if ! solana -C "$cfg" program show "$pid" --buffer-authority 11111111111111111111111111111111 >"$show" 2>"$err"; then
  echo "[blocker] solana program show failed for $pid:" >&2
  "$REDACT" <"$err" >&2
  exit 3
fi
field() { awk -F': *' -v k="$1" '$1 == k {print $2; exit}' "$2" 2>/dev/null; }
owner="$(field "Owner" "$show")"
slot="$(field "Last Deployed In Slot" "$show")"

case "$owner" in
  LoaderV4*)
    echo "[blocker] $pid is a loader-v4 program (owner $owner): snapshot it with loader-v4 tooling and record the zero-trimmed sha256 and the deploy slot (LoaderV4State bytes [0..8]) in LEDGER.md by hand." >&2
    exit 3 ;;
esac

rm -f "$err"
if ! solana -C "$cfg" program dump "$pid" "$dump" >/dev/null 2>"$err"; then
  echo "[blocker] solana program dump failed for $pid:" >&2
  "$REDACT" <"$err" >&2
  exit 3
fi

magic="$(head -c 4 "$dump" | od -An -tx1 | tr -d ' \n')"
if [ "$magic" != "7f454c46" ]; then
  echo "[blocker] dump of $pid is not an ELF (magic=${magic:-empty}); not usable as program bytes." >&2
  exit 3
fi

# hash_of <file>: "<sha256 of the bytes without trailing zeros> <their length> <padding length>"
hash_of() {
  python3 -I -c 'import hashlib, sys
raw = open(sys.argv[1], "rb").read()
trimmed = raw.rstrip(b"\0")
print(hashlib.sha256(trimmed).hexdigest(), len(trimmed), len(raw) - len(trimmed))' "$1" 2>/dev/null
}
re='^[0-9a-f]{64} [0-9]+ [0-9]+$'
hashed() {  # hashed <file>: hash_of, or a blocker
  local s
  s="$(hash_of "$1")"
  if ! [[ "$s" =~ $re ]]; then
    echo "[blocker] python3 -I did not hash ${1#"$dir/"}; hash it by hand (trailing zero bytes trimmed, then sha256)." >&2
    exit 3
  fi
  echo "$s"
}
sha="$(hashed "$dump")" || exit 3
sha="${sha%% *}"
# ledger_line <.so> <.show.txt>: the line for one snapshot kept in bin/.
ledger_line() {
  local s o l a
  s="$(hashed "$1")" || exit 3
  o="$(field "Owner" "$2")"; l="$(field "Last Deployed In Slot" "$2")"; a="$(field "Authority" "$2")"
  # shellcheck disable=SC2086
  set -- "${1#"$dir/"}" $s
  echo "program=$pid owner=${o:-unknown} last_deployed_slot=${l:-unknown} authority=${a:-none} sha256_zero_trimmed=$2 elf_bytes=$3 padding_bytes=$4 file=$1"
}
# keep <temp file> <path in bin/>: copy under a name that must still be free. With
# set -C the `: >` fails on a taken name, so a kept snapshot is never replaced.
keep() {
  if ! { : > "$2"; } 2>/dev/null; then
    echo "[blocker] ${2#"$dir/"} already exists; a snapshot is never overwritten, and nothing replaced it." >&2
    exit 3
  fi
  if ! cat "$1" >> "$2"; then
    rm -f "$2"
    echo "[blocker] could not write ${2#"$dir/"}." >&2
    exit 3
  fi
}

mkdir -p "$dir/bin" || exit 2
# Rule 11d: an incident_<n>/ directory ignores itself when it has no .gitignore of
# its own, so the dumped program never shows in git status.
case "$(basename "$dir")" in
  incident_*) [ -e "$dir/.gitignore" ] || printf '*\n' > "$dir/.gitignore" ;;
esac
first="$dir/bin/$pid.so"; first_show="$dir/bin/$pid.show.txt"
if [ ! -e "$first" ] && [ ! -e "$first_show" ]; then
  keep "$dump" "$first"; keep "$show" "$first_show"
  ledger_line "$first" "$first_show"
  exit 0
fi
if [ ! -e "$first" ]; then
  echo "[blocker] bin/$pid.show.txt exists without bin/$pid.so (an earlier snapshot did not finish): move it aside and run again; it is never overwritten." >&2
  exit 3
fi
# A later run: the program on-chain may be a snapshot already kept.
for f in "$first" "$dir/bin/$pid"@*.so; do
  [ -f "$f" ] || continue
  if [ "$(field "Last Deployed In Slot" "${f%.so}.show.txt")" = "$slot" ] \
     && [ "$(hash_of "$f" | cut -d' ' -f1)" = "$sha" ]; then
    echo "unchanged: the program on-chain matches ${f#"$dir/"} (same last-deployed slot and zero-trimmed sha256); nothing written"
    ledger_line "$f" "${f%.so}.show.txt"
    exit 0
  fi
done
case "$slot" in
  ''|*[!0-9]*)
    echo "[blocker] the program on-chain differs from every snapshot in bin/, and its last-deployed slot ('$slot') cannot name a new one; nothing written." >&2
    exit 3 ;;
esac
new="$dir/bin/$pid@$slot.so"; new_show="$dir/bin/$pid@$slot.show.txt"
if [ -e "$new" ] || [ -e "$new_show" ]; then
  echo "[blocker] bin/$pid@$slot.so or bin/$pid@$slot.show.txt already exists, with other bytes than the program on-chain; it is never overwritten, and nothing was written." >&2
  exit 3
fi
keep "$dump" "$new"; keep "$show" "$new_show"
echo "changed since bin/$pid.so: the current bytes are kept as bin/$pid@$slot.so; bin/$pid.so stays the first snapshot"
ledger_line "$first" "$first_show"
ledger_line "$new" "$new_show"
