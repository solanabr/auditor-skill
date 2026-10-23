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
#      `--buffer-authority`, so the CLI never looks for a signer). It rejects a
#      loader-v4 program as "not an SBF program"; that one is read with
#      `program-v4 show --program-id <id>` (a fixed `--authority`, for the same
#      reason). The output must name <id> as its Program Id, or the script stops
#      with a blocker. An account neither command reads stops with a blocker that
#      names the account's owner, from one more read (`solana -C <config> account
#      <id> --output-file <temp file>`, so no hex dump of its data is printed). When
#      a loader owns it, the blocker says which case it is: a data account of the
#      loader (a program's data account or a buffer: check the id), or an
#      executable account the show commands failed to read (a closed program, or a
#      failing endpoint: run the snapshot again).
#   3. `solana -C <config> program dump <id>` (loader-v4: `program-v4 download
#      --program-id <id>`) into the temp dir, then `show` again: the slot and the
#      bytes come from separate reads, so a slot that moved means a deploy landed
#      in between. The dump is then taken once more, and a slot that moves again
#      stops the script with a blocker.
#   4. checks the ELF magic, hashes the dump the way solana-verify does (trailing
#      zero padding trimmed, then sha256), keeps the dump and the show output in
#      <incident_dir>/bin/, and prints ONE ledger-ready line:
#        program=<id> owner=<loader> last_deployed_slot=<N> authority=<A>
#        sha256_zero_trimmed=<hex> elf_bytes=<n> padding_bytes=<n> file=bin/<id>.so
#      A program under an immutable loader (BPFLoader2, or the older BPFLoader) has
#      no deploy slot and no authority: last_deployed_slot=n/a (immutable loader).
#      A loader-v4 program's line also carries its status after the authority:
#      status=deployed, retracted or finalized.
#
# NEVER OVERWRITTEN: the first snapshot is bin/<id>.so + bin/<id>.show.txt, the
# incident-time bytes that Leg 3 and the patch flow run on. A later run (respond
# runs this again after the hunt) checks every snapshot already in bin/, then
# compares the program on-chain with them, in this order:
#   * each kept .so must still be a regular file with the ELF magic, beside a
#     regular .show.txt (a .show.txt alone counts as a snapshot too), and later
#     snapshots need the first one; anything else stops it with a blocker;
#   * other bytes than any snapshot kept at the same or a later last-deployed slot:
#     bin/ and the chain disagree, so it stops with a blocker and writes nothing,
#     even when another snapshot matches;
#   * the same last-deployed slot and zero-trimmed sha256 as one of them: it prints
#     "unchanged" and that snapshot's line, with the authority and status read now
#     (a transfer or a loader-v4 finalize changes neither the slot nor the bytes;
#     a notice on stderr names a change since the snapshot was kept), writes
#     nothing, and exits 0;
#   * otherwise it keeps the current bytes as bin/<id>@<slot>.so and
#     bin/<id>@<slot>.show.txt, and prints the first snapshot's line and the new one.
# Files are written with noclobber (`set -C`), each through the descriptor opened
# when it was created: a name already taken stops the script with a blocker instead
# of being replaced.
#
# Compare `last_deployed_slot` to the incident slot: earlier → this dump IS the
# incident binary (binary_provenance: dumped-unchanged); later → a newer upgrade
# replaced it (dumped-after-hotfix; the incident bytes need an archived binary or a
# solana-verify hash-matched build).
#
# RUN DIRECTORY: <incident_dir> is a plain path, with no . or .. component, and no
# directory on its way may be a symbolic link inside the working directory (a link
# above it, such as /tmp on macOS, is the operator's). <incident_dir>, and the nearest
# incident_* directory above it, must not be a symbolic link, hold one, or be tracked
# by git, and git and find must be able to check it; any other directory is refused
# with exit 2 before anything is written or the CLI runs. The check runs again just
# before the first write, when bin/ must also be a directory of its own, not a link.
#
# SECRETS: the CLI reads "$RPC_URL" from the temp config, never from argv; an
# $RPC_URL holding a quote, a backslash, whitespace or a control character is refused.
# The CLI's stderr is captured to a temp file and passed through redact.sh (the CLI
# echoes the full URL, key included, in its errors). Nothing written to
# <incident_dir> contains the URL.
#
# Exit: 0 ok · 2 usage / not a base58 32-byte public key / no or unusable $RPC_URL /
# a refused run directory · 3 named blocker (no solana CLI or python3, config not
# taken, CLI error, no program under any loader (the blocker names the account's
# owner), show output naming another Program Id, dump without ELF magic, the
# last-deployed slot moving during two dumps, hash not computed, a snapshot name
# already taken, a kept snapshot that is not a regular ELF file beside a regular
# .show.txt, later snapshots without the first one, or a snapshot the chain's bytes
# disagree with at its slot or a later one).
# bash >= 3.2, and python3 for the id check and the hash: checked before the CLI
# runs, and run as `python3 -I` because the working directory is usually the audited
# repo: without -I, a hashlib.py there would be imported in place of the stdlib.

# -C (noclobber): no redirection in this script replaces an existing file.
set -Cuo pipefail
# Bytes, not characters, in every tool this script runs.
export LC_ALL=C
# No cd may search $CDPATH, and no git call may use a repository named in the
# environment instead of the directory it is pointed at.
unset CDPATH GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDACT="$HERE/redact.sh"

pid="${1:-}"; dir="${2:-}"
if [ -z "$pid" ] || [ -z "$dir" ]; then
  echo "usage: snapshot-program.sh <program_id> <incident_dir>" >&2
  exit 2
fi
# The id becomes part of file names under <incident_dir>/bin/: accept only a base58
# public key (32-44 characters of the Bitcoin alphabet), so it cannot carry a path;
# that it decodes to 32 bytes is checked once python3 is known to be there.
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
# The run directory is checked by name and component by component below, so it is a
# plain path: no "." or ".." component (a leading "./" aside).
dir="${dir#./}"
case "/$dir/" in
  */./*|*/../*) echo "snapshot-program.sh: <incident_dir> takes a plain path without . or .. components: $dir" >&2; exit 2 ;;
esac

# The working directory is usually the audited repository: a symbolic link below it
# belongs to that tree.
if ! here="$(pwd -P)"; then
  echo "snapshot-program.sh: cannot resolve the working directory." >&2; exit 2
fi
# linked_on_way <path>: status 0 when a directory on the way to <path> is a symbolic
# link inside the working directory, or one whose place cannot be resolved. A link
# above the working directory (/tmp on macOS, say) is the operator's, and is followed.
linked_on_way() {
  local rest="$1" cur comp phys
  case "$rest" in /*) cur=""; rest="${rest#/}" ;; *) cur="$here" ;; esac
  while :; do
    case "$rest" in */*) comp="${rest%%/*}"; rest="${rest#*/}" ;; *) return 1 ;; esac
    [ -n "$comp" ] || continue
    if [ -L "$cur/$comp" ]; then
      phys="$(cd "${cur:-/}" 2>/dev/null && pwd -P)" || return 0
      case "$phys/" in "${here%/}"/*) return 0 ;; esac
    fi
    cur="$cur/$comp"
  done
}

# refuse_planted <dir>: exit 2 unless <dir> is safe to write into — not a symbolic
# link, holding none, and not tracked by git. The git calls carry the Rule 11c flags,
# because the tree is usually the audited one. Outside a work tree nothing is tracked;
# inside one, a path git cannot classify is refused, and so is a directory find
# cannot read: a check that cannot run never counts as a pass.
refuse_planted() {
  local listed top
  if [ -L "$1" ]; then
    echo "${0##*/}: refusing $1: it is a symbolic link — use a new run directory." >&2; exit 2
  fi
  if [ -d "$1" ] && { listed="$(find "$1" -type l -print -quit 2>/dev/null)"; [ $? -ne 0 ] || [ -n "$listed" ]; }; then
    echo "${0##*/}: refusing $1: it contains a symbolic link, or a directory find cannot read — use a new run directory." >&2; exit 2
  fi
  [ -d "$(dirname "$1")" ] || return 0
  # A .git at or above the directory means git must answer; with none, nothing is tracked.
  if ! top="$(cd "$(dirname "$1")" && pwd -P)"; then
    echo "${0##*/}: refusing $1: its parent directory cannot be resolved." >&2; exit 2
  fi
  while [ ! -e "$top/.git" ]; do [ "$top" = / ] && return 0; top="$(dirname "$top")"; done
  if ! listed="$(GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false -C "$(dirname "$1")" --icase-pathspecs \
        ls-files -- ":(literal,icase)$(basename "$1")" 2>/dev/null)"; then
    echo "${0##*/}: refusing $1: it is inside a git work tree and git cannot tell whether it is tracked (git missing, or it does not trust this repository)." >&2; exit 2
  fi
  if [ -n "$listed" ]; then
    echo "${0##*/}: refusing $1: git tracks it, so it is not a run directory to write into." >&2; exit 2
  fi
  return 0
}
# check_run_dir: every directory on the way to <incident_dir>; then <incident_dir>, and
# the nearest incident_* directory above it, each checked as a whole. It runs before the
# CLI, and again just before the first write.
check_run_dir() {
  local run_dir
  if linked_on_way "$dir"; then
    echo "snapshot-program.sh: refusing $dir: a directory on its way is a symbolic link inside the working directory — use a run directory reached without one." >&2
    exit 2
  fi
  refuse_planted "$dir"
  run_dir="$dir"
  while :; do
    case "$(basename "$run_dir")" in incident_*) [ "$run_dir" = "$dir" ] || refuse_planted "$run_dir"; break ;; esac
    case "$run_dir" in .|/) break ;; esac
    run_dir="$(dirname "$run_dir")"
  done
}
check_run_dir

if ! command -v solana >/dev/null 2>&1; then
  echo "[blocker] solana CLI not on PATH — install it, or dump the program another way and record its zero-trimmed sha256 and last-deployed slot in LEDGER.md by hand." >&2
  exit 3
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[blocker] python3 not on PATH — it checks the id and hashes the dump; install it, or snapshot $pid by hand and record its zero-trimmed sha256 and last-deployed slot in LEDGER.md." >&2
  exit 3
fi
# The CLI takes an id that is not 32 bytes as no id at all: `program-v4 show` then
# lists every loader-v4 program of the authority instead of failing.
case "$(python3 -I -c 'import sys
a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = 0
for c in sys.argv[1]:
    n = n * 58 + a.index(c)
print(len(sys.argv[1]) - len(sys.argv[1].lstrip("1")) + (n.bit_length() + 7) // 8)' "$pid" 2>/dev/null)" in
  32) ;;
  [0-9]*) echo "snapshot-program.sh: '$pid' does not decode to a 32-byte public key." >&2; exit 2 ;;
  *) echo "[blocker] python3 -I did not run; snapshot $pid by hand and record its zero-trimmed sha256 and last-deployed slot in LEDGER.md." >&2; exit 3 ;;
esac

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

show="$tmp/show.txt"; dump="$tmp/dump.so"; v4=0
# show_program <file>: the program's `show` output. --buffer-authority and
# --authority only matter for listings; naming one (the System Program id) stops
# the CLI from resolving a default signer.
show_program() {
  rm -f "$1" "$err"
  if [ "$v4" -eq 1 ]; then
    solana -C "$cfg" program-v4 show --program-id "$pid" --authority 11111111111111111111111111111111 >"$1" 2>"$err"
  else
    solana -C "$cfg" program show "$pid" --buffer-authority 11111111111111111111111111111111 >"$1" 2>"$err"
  fi
}
# dump_program <file>: the program's bytes, as the CLI writes them.
dump_program() {
  rm -f "$1" "$err"
  if [ "$v4" -eq 1 ]; then
    solana -C "$cfg" program-v4 download --program-id "$pid" "$1" >/dev/null 2>"$err"
  else
    solana -C "$cfg" program dump "$pid" "$1" >/dev/null 2>"$err"
  fi
}
field() { awk -F': *' -v k="$1" '$1 == k {print $2; exit}' "$2" 2>/dev/null; }
# slot_of <show output>: the last-deployed slot; an immutable loader has none.
slot_of() {
  case "$(field "Owner" "$1")" in
    BPFLoader2111111111111111111111111111111111|BPFLoader1111111111111111111111111111111111)
      echo "n/a (immutable loader)" ;;
    *) field "Last Deployed In Slot" "$1" ;;
  esac
}

# named_pid <show output>: a blocker unless the output names the requested id as its
# Program Id.
named_pid() {
  if [ "$(field "Program Id" "$1")" != "$pid" ]; then
    echo "[blocker] the solana CLI's show output does not name $pid as its Program Id; nothing written." >&2
    exit 3
  fi
}

# `program show` reads upgradeable and immutable-loader programs and rejects a
# loader-v4 one, which `program-v4 show` reads.
if ! show_program "$show"; then
  mv "$err" "$tmp/stderr.show"
  v4=1
  if ! show_program "$show" || [ "$(field "Owner" "$show")" != LoaderV411111111111111111111111111111111111 ]; then
    echo "[blocker] neither solana program show nor program-v4 show reads $pid as a program:" >&2
    "$REDACT" <"$tmp/stderr.show" >&2
    "$REDACT" <"$err" >&2
    # One more read names the account's owner. The data goes to a file, so the CLI
    # prints no hex dump of it.
    rm -f "$err"
    if solana -C "$cfg" account "$pid" --output-file "$tmp/account.data" >"$tmp/account.txt" 2>"$err" \
       && owner="$(field "Owner" "$tmp/account.txt")" && [[ "$owner" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]]; then
      # An account a loader owns is a program, or one of its data accounts: when it is
      # executable, the show commands failed on a program (closed, or a failing
      # endpoint), and the id is right.
      case "$owner" in
        BPFLoaderUpgradeab1e11111111111111111111111|BPFLoader2111111111111111111111111111111111|BPFLoader1111111111111111111111111111111111|LoaderV411111111111111111111111111111111111)
          if [ "$(field "Executable" "$tmp/account.txt")" = false ]; then
            echo "[blocker] $pid is not a program: it is a data account of $owner, a loader (a program's data account or a buffer). Check the id, and use the program's own address; nothing written." >&2
          else
            echo "[blocker] the account of $pid is owned by $owner, a loader, yet neither show command read it as a program (see the errors above): the program may be closed, or the endpoint failed or limited the requests. Run the snapshot again before treating the id as wrong; nothing written." >&2
          fi ;;
        *)
          echo "[blocker] $pid is not a program: its account is owned by $owner. Check the id; nothing written." >&2 ;;
      esac
    else
      echo "[blocker] $pid is not a program, and its account could not be read either:" >&2
      "$REDACT" <"$err" >&2
    fi
    exit 3
  fi
fi
named_pid "$show"
slot="$(slot_of "$show")"; seen="$slot"; dumps=0
# Read the slot again after each dump; a deploy in between means the bytes may be
# the newer program's, so dump once more, and stop if the slot moves again.
while :; do
  if ! dump_program "$dump"; then
    echo "[blocker] the solana CLI could not dump $pid:" >&2
    "$REDACT" <"$err" >&2
    exit 3
  fi
  dumps=$((dumps + 1))
  if ! show_program "$show"; then
    echo "[blocker] the solana CLI could not read $pid again after the dump:" >&2
    "$REDACT" <"$err" >&2
    exit 3
  fi
  named_pid "$show"
  now="$(slot_of "$show")"
  [ "$now" = "$slot" ] && break
  seen="$seen -> $now"
  if [ "$dumps" -ge 2 ]; then
    echo "[blocker] the last-deployed slot of $pid moved during both dumps ($seen): deploys are still landing. Run the snapshot again once they stop; nothing was written." >&2
    exit 3
  fi
  echo "  ! the last-deployed slot of $pid moved during the dump ($seen); dumping again" >&2
  slot="$now"
done

# elf_magic <file>: its first four bytes in hex (7f454c46 for an ELF).
elf_magic() { head -c 4 "$1" | od -An -tx1 | tr -d ' \n'; }
magic="$(elf_magic "$dump")"
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
  local s o l a st=""
  s="$(hashed "$1")" || exit 3
  o="$(field "Owner" "$2")"; l="$(slot_of "$2")"; a="$(field "Authority" "$2")"
  # A loader-v4 program also has a status (deployed, retracted or finalized).
  if [ "$o" = LoaderV411111111111111111111111111111111111 ]; then
    st="$(field "Status" "$2")"; st=" status=${st:-unknown}"
  fi
  # shellcheck disable=SC2086
  set -- "${1#"$dir/"}" $s
  echo "program=$pid owner=${o:-unknown} last_deployed_slot=${l:-unknown} authority=${a:-none}$st sha256_zero_trimmed=$2 elf_bytes=$3 padding_bytes=$4 file=$1"
}
# keep <temp file> <path in bin/>: copy under a name that must still be free. With
# set -C the descriptor cannot be opened on a taken name, so a kept snapshot is never
# replaced, and the bytes go through the descriptor opened when the file was created.
keep() {
  if ! { exec 6>"$2"; } 2>/dev/null; then
    echo "[blocker] ${2#"$dir/"} already exists; a snapshot is never overwritten, and nothing replaced it." >&2
    exit 3
  fi
  if ! cat "$1" >&6; then
    exec 6>&-
    rm -f "$2"
    echo "[blocker] could not write ${2#"$dir/"}." >&2
    exit 3
  fi
  exec 6>&-
}

# Just before the first write: the run directory again (the CLI reads take time), and a
# bin/ that is a directory of its own, not a symbolic link.
check_run_dir
mkdir -p "$dir/bin" || exit 2
if [ -L "$dir/bin" ] || [ ! -d "$dir/bin" ]; then
  echo "snapshot-program.sh: refusing $dir/bin: it is not a directory of its own — use a new run directory." >&2
  exit 2
fi
# Rule 11d: an incident_<n>/ directory ignores itself when it has no .gitignore of
# its own, so the dumped program never shows in git status.
case "$(basename "$dir")" in
  incident_*) [ -e "$dir/.gitignore" ] || printf '*\n' > "$dir/.gitignore" ;;
esac
first="$dir/bin/$pid.so"; first_show="$dir/bin/$pid.show.txt"
# Every snapshot kept in bin/, the first one and each later one, named by its path
# without .so or .show.txt: a lone .show.txt counts too.
stems=()
for f in "$first" "$first_show" "$dir/bin/$pid"@*.so "$dir/bin/$pid"@*.show.txt; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  f="${f%.so}"; f="${f%.show.txt}"; known=0
  for g in ${stems[@]+"${stems[@]}"}; do [ "$g" = "$f" ] && known=1; done
  [ "$known" = 1 ] || stems+=("$f")
done
if [ "${#stems[@]}" -eq 0 ]; then
  keep "$dump" "$first"; keep "$show" "$first_show"
  ledger_line "$first" "$first_show"
  exit 0
fi
if [ ! -e "$first" ] && [ ! -L "$first" ] && [ ! -e "$first_show" ] && [ ! -L "$first_show" ]; then
  echo "[blocker] bin/ holds later snapshots of $pid but not the first one, bin/$pid.so with its .show.txt: the incident-time bytes are missing. Put them back from where they were copied, or use a new run directory; nothing written." >&2
  exit 3
fi
# A later run: first every kept snapshot must still be as it was written, a regular .so
# with the ELF magic beside a regular .show.txt.
for f in "${stems[@]}"; do
  if [ ! -e "$f.so" ] && [ ! -L "$f.so" ]; then
    echo "[blocker] ${f#"$dir/"}.show.txt exists without ${f#"$dir/"}.so (an earlier snapshot did not finish): move it aside and run again; it is never overwritten." >&2
    exit 3
  fi
  if [ -L "$f.so" ] || [ ! -f "$f.so" ] || [ "$(elf_magic "$f.so")" != "7f454c46" ] || [ -L "$f.show.txt" ] || [ ! -f "$f.show.txt" ]; then
    echo "[blocker] ${f#"$dir/"}.so is not a regular file with the ELF magic beside a regular ${f#"$dir/"}.show.txt: a kept snapshot is no longer as it was written. Compare it with the ledger line it was kept with; nothing written." >&2
    exit 3
  fi
done
# Then any of them kept at the same or a later last-deployed slot than the chain's,
# with other bytes: bin/ and the chain disagree, so nothing matches and nothing is kept.
slots=(); hashes=()
for f in "${stems[@]}"; do
  k="$(slot_of "$f.show.txt")"
  h="$(hashed "$f.so")" || exit 3
  h="${h%% *}"
  slots+=("$k"); hashes+=("$h")
  if [ "$h" != "$sha" ] && [[ "$k" =~ ^[0-9]{1,18}$ && "$slot" =~ ^[0-9]{1,18}$ ]] && [ "$k" -ge "$slot" ]; then
    echo "[blocker] ${f#"$dir/"}.so was kept at last-deployed slot $k, not older than the slot on-chain now ($slot), yet the program on-chain has other bytes: bin/ and the chain disagree. Compare that snapshot with its ledger line before trusting either; nothing written." >&2
    exit 3
  fi
done
# Only then a match: the same slot and bytes. The line gives the authority and status
# read now, which a transfer or a loader-v4 finalize changes without a deploy.
i=0
for f in "${stems[@]}"; do
  if [ "${slots[$i]}" = "$slot" ] && [ "${hashes[$i]}" = "$sha" ]; then
    echo "unchanged: the program on-chain matches ${f#"$dir/"}.so (same last-deployed slot and zero-trimmed sha256); nothing written"
    ledger_line "$f.so" "$show"
    was="$(field "Authority" "$f.show.txt")/$(field "Status" "$f.show.txt")"
    now="$(field "Authority" "$show")/$(field "Status" "$show")"
    if [ "$was" != "$now" ]; then
      echo "  ! the authority or status of $pid changed since ${f#"$dir/"}.show.txt was kept (authority/status then: ${was}; now: ${now}); the line above gives the current ones" >&2
    fi
    exit 0
  fi
  i=$((i + 1))
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
