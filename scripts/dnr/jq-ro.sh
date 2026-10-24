#!/bin/bash
# jq-ro.sh — jq over files inside a run directory, with nothing else to read: no other file, no jq
# module and none of the caller's environment.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/jq-ro.sh" [-c] [-r] [-s] [-e] [-n] [--arg <name> <value>]...
#       [--argjson <name> <json>]... <filter> <file>...
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under
# audit. Its checks hold whatever words follow, and a refusal is one stderr line, "jq-ro: refused:
# <reason>", with exit 2.
#
# Options come first, each its own word: -c, -r, -s, -e and -n, which may repeat, and --arg and --argjson,
# each with a name (letters, digits and _, at most 64 bytes, not starting with a digit) bound once, and a
# value. Any other word that starts with - before the filter is refused: --rawfile, --slurpfile,
# -f/--from-file and -L among them, since they read a file named on the command line (and a parse error
# prints its text). The filter is the next word: at most 4096 bytes, no control character but tab and
# newline, and none of import, include or modulemeta anywhere in it, since those read jq modules from the
# library path. Every word after the filter is an input: a path relative to the working directory, with
# no ., .. or empty component, no symbolic link on the way, naming a regular file with one link inside a
# run directory, audit_<n>/ or incident_<n>/ (scripts/lib/confine.sh). Give at least one; standard input
# is never read.
#
# jq is found on PATH (absolute entries outside the working directory) and runs as
#   env -i HOME=/nonexistent PATH=/usr/bin:/bin <jq> <options> <filter> <inputs> </dev/null
# so $ENV and env hold those two values only, and no ~/.jq is loaded.
#
# Output: what jq prints, on stdout and on stderr, with every control character but tab and newline, NUL
# included, as ?.
# Exit: jq's own status (0; 1 or 4 with -e; 2 a usage or system error; 3 a compile error; 5 a runtime
# error) · 2 refused. Needs bash >= 3.2 and jq; env, git, find, tr, wc and cat.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'jq-ro: refused: the installation cannot be resolved\n' >&2; exit 2; }
. "${here%/*}/lib/confine.sh" || { printf 'jq-ro: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 2; }
# The shared checks refuse with 64; this tool's refusals exit 2, as the D&R recipes' do.
confine_refuse() {
  printf '%s: refused: %s\n' "${CONFINE_TOOL:-confine}" "$1" >&2
  exit 2
}
confine_init jq-ro "${here%/*/*}"
confine_need env jq git find tr wc cat

USAGE='usage: jq-ro.sh [-c] [-r] [-s] [-e] [-n] [--arg <name> <value>]... [--argjson <name> <json>]... <filter> <file>...'
CLEAN_PATH=/usr/bin:/bin
TAB_NL=$'\t\n'

refuse() { confine_refuse "$1"; }

main() {
  local a f n bound=" " checked=" " filter run shown jq_bin env_bin links
  local -a opts=() inputs=()
  while [ $# -gt 0 ]; do
    case "$1" in
      -c|-r|-s|-e|-n) opts+=("$1"); shift ;;
      --arg|--argjson)
        [ $# -ge 3 ] || refuse "$1 takes a name and a value"
        n=$2
        case "$n" in
          ''|[0-9]*|*[!A-Za-z0-9_]*) refuse "$1 takes a name of letters, digits and _, not starting with a digit, not $(confine_text "$n")" ;;
        esac
        [ "${#n}" -le 64 ] || refuse "$1 takes a name of at most 64 bytes"
        case "$bound" in *" $n "*) refuse "\$$n is bound twice" ;; esac
        bound="$bound$n "
        opts+=("$1" "$n" "$3")
        shift 3 ;;
      -[crsen][crsen]*)
        case "${1#-}" in
          *[!crsen]*) refuse "$(confine_text "$1") is not an option jq-ro passes on; it takes -c, -r, -s, -e, -n, --arg and --argjson" ;;
          *) refuse "give -c, -r, -s, -e and -n as separate words, not $1" ;;
        esac ;;
      -*) refuse "$(confine_text "$1") is not an option jq-ro passes on; it takes -c, -r, -s, -e, -n, --arg and --argjson" ;;
      *) break ;;
    esac
  done
  [ $# -gt 0 ] || refuse "$USAGE"
  filter=$1
  shift
  [ -n "$filter" ] || refuse "the filter is empty"
  [ "${#filter}" -le 4096 ] || refuse "the filter is longer than 4096 bytes"
  a=${filter//[$TAB_NL]/}
  case "$a" in *[[:cntrl:]]*) refuse "the filter holds a control character other than tab and newline" ;; esac
  case "$filter" in
    *import*|*include*|*modulemeta*)
      refuse "the filter holds import, include or modulemeta, which read jq modules from outside the run directory" ;;
  esac
  [ $# -gt 0 ] || refuse "name at least one file inside a run directory; jq-ro never reads standard input"
  for f in "$@"; do
    confine_shown "$f"
    shown=$CONFINE_SHOWN
    confine_path "$f" "the input" any
    [ "$CONFINE_TYPE" = file ] || refuse "the input is not an existing regular file: $shown"
    run=${CONFINE_REL%%/*}
    [ "$run" != "$CONFINE_REL" ] && confine_rundir_name "$run" ||
      refuse "the input must lie inside a run directory, audit_<n>/ or incident_<n>/ in the working directory: $shown"
    case "$checked" in
      *" $run "*) ;;
      *) confine_rundir "$run" "the run directory"; checked="$checked$run " ;;
    esac
    links=$(find "$CONFINE_WT/$CONFINE_REL" -links +1 -print 2>/dev/null) ||
      refuse "the input cannot be checked for other hard links: $shown"
    [ -z "$links" ] || refuse "the input has another hard link, which can name a file outside the run directory: $shown"
    inputs+=("$CONFINE_REL")
  done
  # Each input is checked again right before jq opens it.
  for f in "${inputs[@]}"; do
    [ -f "$CONFINE_WT/$f" ] && [ ! -L "$CONFINE_WT/$f" ] || refuse "the input changed while it was checked: $(confine_text "$f")"
  done
  jq_bin=$(type -P jq) && env_bin=$(type -P env) || refuse "jq or env cannot be found on PATH"
  "$env_bin" -i HOME=/nonexistent PATH="$CLEAN_PATH" "$jq_bin" ${opts[@]+"${opts[@]}"} "$filter" "${inputs[@]}" </dev/null
}

# What jq prints, errors included, goes out with every control character but tab and newline, NUL too, as ?.
CTRL='\000-\010\013-\037\177'
{ main "$@" 2>&1 1>&3 3>&- | tr "$CTRL" '?' 1>&2 3>&-; } 3>&1 | tr "$CTRL" '?'
