#!/bin/bash
# rundir.sh — create, check and reuse run directories (OUTPUT-RULES.md Rule 11d).
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" new audit|incident [--strict]   creates <kind>_<max+1>; prints its name
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" check <R>            checks <R> for reuse; prints "ok <R>"
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" sub <R> <rel>        creates one subdirectory; prints its path
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" store                checks the in-tree audit-mem store
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under
# audit. A refusal is one stderr line, "rundir: refused: <reason>", with exit 64.
#
# A run directory <R> is audit_<n> or incident_<n> (n of 1 to 6 digits), directly in the working
# directory: a real directory, holding no symbolic link, tracked by no repository in any letter case,
# whose .gitignore holds exactly "*", named as the disk spells it. check verifies exactly that (scripts/lib/confine.sh confine_rundir:
# in default mode a link that resolves inside it passes, and so does one git cannot tell about); reuse a
# directory only after the human confirms which one.
#
# new takes the highest n over real directories named <kind>_<n>, plus one, passing over a name the
# repository tracks in any letter case. A path the repository tracks under a top-level directory named
# audit_* or incident_* (or a submodule of that name) gets a note on stderr, since the commands'
# Edit(audit_*/**) and Edit(incident_*/**) rules also cover it; so does a repository git cannot tell about
# (Rule 11d). In strict mode (OUTPUT-RULES.md Rule 11f; --strict turns it on) both are refused, as writes
# into run directories could then reach tracked files. A next name that a file, a link or a folder spelled
# in other letters holds is passed over too, with a note naming it as the disk spells it; strict mode
# refuses it. new refuses when no number is left. It creates the directory with plain mkdir, writes .gitignore
# first, with noclobber, then, in strict mode, the marker strict (holding "strict"), which keeps every
# later run in this working directory strict until it is deleted, then the standard subdirectories:
#   audit: worksheets/context, poc, patches, exec, deps, sast;
#   incident: bin, poc, patches, exec, logs.
# stdout is the name alone; the notes go to stderr.
#
# sub creates <R>/<rel> (and <R>/poc for poc/<ID>) when missing, and accepts an existing one. <rel> is
# one of poc/<ID>, patches, harnesses, bootstrap, corpus-<k>, logs or rpc, where <ID> is F-<1-4 digits>
# or INC-<1-6 digits>.<1-4 digits> and <k> is 1 to 4 digits.
#
# store prints .audit-memory/audit.db when the store is usable: a real directory holding no symbolic
# link (in default mode, none that resolves outside it, as for a run directory), tracked in no letter
# case, whose .gitignore holds exactly "*", and whose audit.db, if present, is a regular file. It prints "absent" when .audit-memory does not exist and nothing is tracked there
# (audit-mem init creates it). Otherwise it refuses, and the flow uses <R>/audit-mem.db instead. Whether
# you created the store yourself stays your judgement.
#
# Exit: 0 done · 64 refused. Needs bash >= 3.2 and git; env, find, wc, cat and mkdir.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'rundir: refused: the installation cannot be resolved\n' >&2; exit 64; }
. "$here/lib/confine.sh" || { printf 'rundir: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
confine_init rundir "${here%/*}"
confine_need env git find wc cat mkdir
WT=$CONFINE_WT

refuse() { confine_refuse "$1"; }

# tracked_run_dirs: the repository's entries named audit_* or incident_* at the top level, and the
# paths under such directories, in any letter case; status 2 when git cannot tell. Outside every
# repository (confine_no_repo) nothing is tracked.
tracked_run_dirs() {
  local err
  if err=$(CONFINE_CEILING='' hgit "$WT" rev-parse --is-inside-work-tree 2>&1 >/dev/null); then
    :
  elif confine_no_repo "$?" "$err"; then
    return 0
  else
    return 2
  fi
  CONFINE_CEILING='' hgit "$WT" ls-files --stage -- ':(glob,icase)audit_*' ':(glob,icase)audit_*/**' \
    ':(glob,icase)incident_*' ':(glob,icase)incident_*/**' 2>/dev/null || return 2
}

cmd_new() { # cmd_new audit|incident [--strict]
  local kind listed line path top max=0 d n name doubt=0 taken=" " noted="/" nnoted=0 held nheld=0
  local -a notes=() helds=()
  [ $# -ge 1 ] || refuse "new takes audit or incident, then --strict or nothing"
  kind=$1
  shift
  case "$kind" in audit|incident) ;; *) refuse "new takes audit or incident, not $(confine_text "$kind")" ;; esac
  if [ $# -ge 1 ] && [ "$1" = --strict ]; then confine_strict_on --strict; shift; fi
  [ $# -eq 0 ] || refuse "new takes audit or incident, then --strict or nothing, not $(confine_text "$1")"
  # In this shell, so a file git would wait on is refused for what it is, and tracked_run_dirs finds it checked.
  CONFINE_CEILING='' confine_git_files "$WT"
  if listed=$(tracked_run_dirs); then
    # Split on line ends, not read from a here-document, which bash 3.2 writes to a file in the working
    # directory when it finds no TMPDIR it can write to.
    IFS=$'\n'
    set -f
    for line in $listed; do
      path=${line#*$'\t'}
      case "$line" in 160000\ *) path=$path/ ;; esac
      top=${path#\"}
      top=${top%%/*}
      case "$top" in
        [Aa][Uu][Dd][Ii][Tt]_*) taken="${taken}audit_${top#*_} " ;;
        [Ii][Nn][Cc][Ii][Dd][Ee][Nn][Tt]_*) taken="${taken}incident_${top#*_} " ;;
      esac
      case "$path" in
        */*)
          [ "$CONFINE_STRICT" != 1 ] ||
            refuse "the repository tracks $(confine_text "$path"), so writes into a run directory could reach tracked files; audit a copy"
          case "$noted" in *"/$top/"*) continue ;; esac
          noted="$noted$top/"
          nnoted=$((nnoted + 1))
          [ "$nnoted" -gt 5 ] || notes+=("$(confine_text "$top")/") ;;
      esac
    done
    set +f
    IFS=$' \t\n'
  else
    [ "$CONFINE_STRICT" != 1 ] || refuse "git cannot tell whether the repository tracks a run directory"
    doubt=1
  fi
  for d in "$WT/$kind"_*; do
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    n=${d##*/}
    confine_rundir_name "$n" || continue
    n=${n#*_}
    n=$((10#$n))
    [ "$n" -le "$max" ] || max=$n
  done
  n=$((max + 1))
  # A name the repository tracks is passed over; so, in default mode, is one a file, a link or a folder
  # spelled in other letters holds (strict mode refuses it), named as the disk spells it.
  while :; do
    [ "$n" -le 999999 ] || refuse "no ${kind}_<n> name is left"
    name=${kind}_$n
    case "$taken" in *" $name "*) n=$((n + 1)); continue ;; esac
    if [ -e "$WT/$name" ] || [ -L "$WT/$name" ]; then
      [ "$CONFINE_STRICT" != 1 ] || refuse "$name already exists and is not a run directory"
      confine_spelled "$name"
      held=$CONFINE_SPELLED
      nheld=$((nheld + 1))
      [ "$nheld" -gt 5 ] || helds+=("$(confine_text "$held")")
      n=$((n + 1))
      continue
    fi
    break
  done
  confine_mkdir "$WT/$name" || refuse "cannot create $name"
  confine_new_file "$WT/$name/.gitignore" '*'$'\n' || refuse "cannot write $name/.gitignore"
  if [ "$CONFINE_STRICT" = 1 ]; then
    confine_new_file "$WT/$name/strict" 'strict'$'\n' || refuse "cannot write $name/strict"
  fi
  if [ "$kind" = audit ]; then
    set -- worksheets worksheets/context poc patches exec deps sast
  else
    set -- bin poc patches exec logs
  fi
  for d in "$@"; do
    confine_mkdir "$WT/$name/$d" || refuse "cannot create $name/$d"
  done
  printf '%s\n' "$name"
  for path in ${notes[@]+"${notes[@]}"}; do
    confine_note "the repository tracks $path, under a name the commands' Edit(audit_*/**) and Edit(incident_*/**) rules also cover; this run writes only in $name (Rule 11d)"
  done
  [ "$nnoted" -le 5 ] ||
    confine_note "the repository tracks paths under $((nnoted - 5)) more such names; this run writes only in $name (Rule 11d)"
  for path in ${helds[@]+"${helds[@]}"}; do
    confine_note "$path already exists and is not a run directory; this run writes only in $name (Rule 11d)"
  done
  [ "$nheld" -le 5 ] ||
    confine_note "$((nheld - 5)) more such names are taken; this run writes only in $name (Rule 11d)"
  [ "$doubt" -eq 0 ] ||
    confine_note "git cannot tell whether the repository tracks a run directory; $name is new, and its .gitignore of * keeps git off it (Rule 11d)"
}

cmd_check() { # cmd_check <R>
  [ $# -eq 1 ] || refuse "check takes one run directory"
  confine_rundir "$1" "the run directory"
  printf 'ok %s\n' "$CONFINE_RUN"
}

digits() { # digits <s> <n>: status 0 when <s> is 1 to <n> digits
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ "${#1}" -le "$2" ]
}

cmd_sub() { # cmd_sub <R> <rel>
  local rel ok=0 d
  [ $# -eq 2 ] || refuse "sub takes a run directory and one subdirectory"
  rel=$2
  case "$rel" in
    patches|harnesses|bootstrap|logs|rpc) ok=1 ;;
    corpus-*) digits "${rel#corpus-}" 4 && ok=1 ;;
    poc/F-*) digits "${rel#poc/F-}" 4 && ok=1 ;;
    poc/INC-*.*) d=${rel#poc/INC-}; digits "${d%%.*}" 6 && digits "${d#*.}" 4 && ok=1 ;;
  esac
  [ "$ok" -eq 1 ] ||
    refuse "sub creates poc/<ID>, patches, harnesses, bootstrap, corpus-<k>, logs or rpc, not $(confine_text "$rel")"
  confine_rundir "$1" "the run directory"
  case "$rel" in
    poc/*) sub_dir "$CONFINE_RUN/poc" ;;
  esac
  sub_dir "$CONFINE_RUN/$rel"
  printf '%s\n' "$CONFINE_RUN/$rel"
}

sub_dir() { # sub_dir <path under WT>: an existing real directory, or a new one
  if [ -L "$WT/$1" ]; then refuse "$1 is a symbolic link"; fi
  if [ -e "$WT/$1" ]; then
    [ -d "$WT/$1" ] || refuse "$1 exists and is not a directory"
    return 0
  fi
  confine_mkdir "$WT/$1" || refuse "cannot create $1"
}

cmd_store() {
  local d=.audit-memory listed links
  [ $# -eq 0 ] || refuse "store takes no arguments"
  listed=$(confine_tracked "$d") || refuse "git cannot tell whether $d is tracked"
  [ -z "$listed" ] || refuse "the repository tracks $d (in some letter case); use <R>/audit-mem.db"
  if [ ! -e "$WT/$d" ] && [ ! -L "$WT/$d" ]; then
    printf 'absent\n'
    return 0
  fi
  [ ! -L "$WT/$d" ] || refuse "$d is a symbolic link; use <R>/audit-mem.db"
  [ -d "$WT/$d" ] || refuse "$d is not a directory; use <R>/audit-mem.db"
  links=$(find "$WT/$d" -type l -print 2>/dev/null) || refuse "$d cannot be fully read; use <R>/audit-mem.db"
  if [ -n "$links" ]; then
    [ "$CONFINE_STRICT" != 1 ] && confine_links_inside "$WT/$d" || refuse "$d holds a symbolic link; use <R>/audit-mem.db"
  fi
  confine_ignore_all "$WT/$d/.gitignore" || refuse "$d has no .gitignore holding exactly *; use <R>/audit-mem.db"
  if [ -e "$WT/$d/audit.db" ] && [ ! -f "$WT/$d/audit.db" ]; then
    refuse "$d/audit.db is not a regular file; use <R>/audit-mem.db"
  fi
  printf '%s\n' "$d/audit.db"
}

[ $# -gt 0 ] || refuse "usage: rundir.sh new audit|incident, check <R>, sub <R> <rel>, or store"
verb=$1
shift
case "$verb" in
  new) cmd_new "$@" ;;
  check) cmd_check "$@" ;;
  sub) cmd_sub "$@" ;;
  store) cmd_store "$@" ;;
  *) refuse "usage: rundir.sh new audit|incident, check <R>, sub <R> <rel>, or store" ;;
esac
