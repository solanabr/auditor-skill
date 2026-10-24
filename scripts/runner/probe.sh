#!/bin/bash
# probe.sh — what this machine offers the PoC and target runners: the version of each tool they use, and
# whether the credentials the isolation self-check reads are readable here (OUTPUT-RULES.md Rule 11a). It runs
# no target code, reads nothing in the working directory, and writes only a scratch directory of its own,
# removed on exit.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/runner/probe.sh" [--only <name>[,<name>...]]
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under
# audit. A refusal is one stderr line, "probe: refused: <reason>", with exit 64.
#
# One line per name, in this order: "<name>: <the first line its version query prints>", "<name>: absent"
# when the program is not on PATH, or "<name>: unusable (<why>)" when its version query fails.
#   cargo             cargo --version
#   rustup            rustup --version
#   cargo-build-sbf   cargo build-sbf --version
#   cargo-fuzz        cargo fuzz --version
#   trident           trident --version
#   anchor            anchor --version
#   solana            solana --version
#   surfpool          surfpool --version
#   semgrep           semgrep --version
#   pandoc            pandoc --version
#   python3           python3 --version
#   isolation         "none of the credentials the self-check reads is readable", "readable: <path>, ...",
#                     or "not checked (<why>)": the check of scripts/lib/isolation.sh
# Each query runs from the scratch directory, outside the working directory and with no .cargo/config or
# rust-toolchain file at or above it, with standard input closed and RUSTUP_TOOLCHAIN pinned to the caller's
# value or rustup's default. Its environment is the cleaned one of scripts/lib/isolation.sh, with the real
# HOME kept so that each tool finds its own install. cargo runs offline, rustup installs nothing, semgrep
# checks for no new version and keeps its settings in the scratch directory, and every proxy variable names
# a closed local port, so a tool that honours them reaches no network.
#
# Exit: 0 · 64 refused. Needs bash >= 3.2, env, mkdir, mktemp and rm; python3 for the isolation line.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'probe: refused: the installation cannot be resolved\n' >&2; exit 64; }
case "$here" in
  */scripts/runner) root=${here%/scripts/runner} ;;
  *) printf 'probe: refused: probe.sh runs from <auditor-skill root>/scripts/runner\n' >&2; exit 64 ;;
esac
. "$root/scripts/lib/confine.sh" || { printf 'probe: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
. "$root/scripts/lib/isolation.sh" || { printf 'probe: refused: scripts/lib/isolation.sh cannot be read\n' >&2; exit 64; }
confine_init probe "$root"
confine_need env mkdir mktemp rm

NAMES='cargo rustup cargo-build-sbf cargo-fuzz trident anchor solana surfpool semgrep pandoc python3 isolation'
USAGE="usage: probe.sh [--only <name>[,<name>...]], with names from: ${NAMES// /, }"

want=" $NAMES "
case $# in
  0) ;;
  2)
    [ "$1" = --only ] || confine_refuse "$USAGE"
    [ -n "$2" ] || confine_refuse "--only needs a name"
    want=" "
    rest="$2,"
    while [ -n "$rest" ]; do
      n=${rest%%,*}
      rest=${rest#*,}
      case "$n" in
        '') confine_refuse "--only has an empty name: $(confine_text "$2")" ;;
        *[!a-z0-9-]*) confine_refuse "--only takes names from: ${NAMES// /, }, not $(confine_text "$n")" ;;
      esac
      case " $NAMES " in
        *" $n "*) want="$want$n " ;;
        *) confine_refuse "--only takes names from: ${NAMES// /, }, not $(confine_text "$n")" ;;
      esac
    done ;;
  *) confine_refuse "$USAGE" ;;
esac

trap 'case "${ISO_SCRATCH:-}" in */auditor-probe.*) rm -rf -- "$ISO_SCRATCH" ;; esac' EXIT
iso_scratch probe
iso_env "$ISO_SCRATCH" keep-home || confine_refuse "cannot prepare a cleaned environment in $(confine_text "$ISO_SCRATCH")"
OFF=http://127.0.0.1:9
ISO_ENV+=("HTTP_PROXY=$OFF" "HTTPS_PROXY=$OFF" "ALL_PROXY=$OFF" "http_proxy=$OFF" "https_proxy=$OFF" "all_proxy=$OFF"
  NO_PROXY= no_proxy= CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off
  "SEMGREP_SETTINGS_FILE=$ISO_SCRATCH/semgrep-settings.yml")
if [ -z "${RUSTUP_TOOLCHAIN:-}" ] && command -v rustup >/dev/null 2>&1; then
  tc=$(cd "$ISO_SCRATCH" && iso_run rustup default 2>/dev/null </dev/null) || tc=""
  case "$tc" in *"(default)"*) ISO_ENV+=("RUSTUP_TOOLCHAIN=${tc%% *}") ;; esac
fi

first_line() { # first_line <file>: its first line that is not blank; status 1 when there is none
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in *[![:space:]]*) printf '%s' "$line"; return 0 ;; esac
  done < "$1"
  return 1
}

probe() { # probe <name> <program that must be on PATH> <query>...
  local name=$1 rc=0 line
  shift
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s: absent\n' "$name"
    return 0
  fi
  shift
  (cd "$ISO_SCRATCH" && iso_run "$@") </dev/null >"$ISO_SCRATCH/out" 2>"$ISO_SCRATCH/err" || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '%s: unusable (exit %s)\n' "$name" "$rc"
  elif line=$(first_line "$ISO_SCRATCH/out") || line=$(first_line "$ISO_SCRATCH/err"); then
    printf '%s: %s\n' "$name" "$(confine_text "$line")"
  else
    printf '%s: unusable (no version printed)\n' "$name"
  fi
}

for name in $NAMES; do
  case "$want" in *" $name "*) ;; *) continue ;; esac
  case "$name" in
    cargo-build-sbf) probe "$name" cargo-build-sbf cargo build-sbf --version ;;
    cargo-fuzz) probe "$name" cargo-fuzz cargo fuzz --version ;;
    isolation)
      rc=0
      iso_credentials || rc=$?
      case "$rc" in
        0) printf 'isolation: none of the credentials the self-check reads is readable\n' ;;
        1) printf 'isolation: readable: %s\n' "${ISO_READABLE//$'\n'/, }" ;;
        *) printf 'isolation: not checked (%s)\n' "$ISO_WHY" ;;
      esac ;;
    *) probe "$name" "$name" "$name" --version ;;
  esac
done
exit 0
