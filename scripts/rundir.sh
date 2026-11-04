#!/bin/bash
# rundir.sh — create, check and reuse run directories (OUTPUT-RULES.md Rule 11d).
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" new audit|incident   creates <kind>_<max+1>; prints its name
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" check <R>            checks <R> for reuse; prints "ok <R>"
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" sub <R> <rel>        creates one subdirectory; prints its path
#   "${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" store                checks the in-tree audit-mem store
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under
# audit. A refusal is one stderr line, "rundir: refused: <reason>", with exit 64.
#
# A run directory <R> is audit_<n> or incident_<n> (n of 1 to 6 digits), directly in the working
# directory: a real directory, holding no symbolic link, tracked by no repository in any letter case,
# whose .gitignore holds exactly "*". check verifies exactly that; reuse a directory only after the
# human confirms which one.
#
# new takes the highest n over real directories named <kind>_<n>, plus one. It refuses when the
# repository tracks a path under a top-level directory named audit_* or incident_* (or a submodule of
# that name), in any letter case, since writes into run directories could then reach tracked files,
# and when the next name is already taken. It creates the directory with plain mkdir, writes .gitignore
# first, with noclobber, then the standard subdirectories:
#   audit: worksheets/context, poc, patches, exec, deps, sast;
#   incident: bin, poc, patches, exec, logs.
#
# sub creates <R>/<rel> (and <R>/poc for poc/<ID>) when missing, and accepts an existing one. <rel> is
# one of poc/<ID>, patches, harnesses, bootstrap, corpus-<k>, logs or rpc, where <ID> is F-<1-4 digits>
# or INC-<1-6 digits>.<1-4 digits> and <k> is 1 to 4 digits.
#
# store prints .audit-memory/audit.db when the store is usable: a real directory holding no symbolic
# link, tracked in no letter case, whose .gitignore holds exactly "*", and whose audit.db, if present, is
# a regular file. It prints "absent" when .audit-memory does not exist and nothing is tracked there
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
# paths under such directories, in any letter case; status 2 when git cannot tell.
tracked_run_dirs() {
  local err
  if ! err=$(CONFINE_CEILING='' hgit "$WT" rev-parse --is-inside-work-tree 2>&1 >/dev/null); then
    case "$err" in *'not a git repository'*) return 0 ;; esac
    return 2
  fi
  CONFINE_CEILING='' hgit "$WT" ls-files --stage -- ':(glob,icase)audit_*' ':(glob,icase)audit_*/**' \
    ':(glob,icase)incident_*' ':(glob,icase)incident_*/**' 2>/dev/null || return 2
}

cmd_new() { # cmd_new audit|incident
  local kind listed line path max=0 d n name
  [ $# -eq 1 ] || refuse "new takes one word: audit or incident"
  kind=$1
  case "$kind" in audit|incident) ;; *) refuse "new takes audit or incident, not $(confine_text "$kind")" ;; esac
  listed=$(tracked_run_dirs) || refuse "git cannot tell whether the repository tracks a run directory"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    path=${line#*$'\t'}
    case "$line" in 160000\ *) path=$path/ ;; esac
    case "$path" in
      */*) refuse "the repository tracks $(confine_text "$path"), so writes into a run directory could reach tracked files; audit a copy" ;;
    esac
  done <<EOF
$listed
EOF
  for d in "$WT/$kind"_*; do
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    n=${d##*/}
    confine_rundir_name "$n" || continue
    n=${n#*_}
    n=$((10#$n))
    [ "$n" -le "$max" ] || max=$n
  done
  n=$((max + 1))
  [ "$n" -le 999999 ] || refuse "no ${kind}_<n> name is left"
  name=${kind}_$n
  if [ -e "$WT/$name" ] || [ -L "$WT/$name" ]; then refuse "$name already exists and is not a run directory"; fi
  confine_mkdir "$WT/$name" || refuse "cannot create $name"
  confine_new_file "$WT/$name/.gitignore" '*'$'\n' || refuse "cannot write $name/.gitignore"
  if [ "$kind" = audit ]; then
    set -- worksheets worksheets/context poc patches exec deps sast
  else
    set -- bin poc patches exec logs
  fi
  for d in "$@"; do
    confine_mkdir "$WT/$name/$d" || refuse "cannot create $name/$d"
  done
  printf '%s\n' "$name"
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
  [ -z "$links" ] || refuse "$d holds a symbolic link; use <R>/audit-mem.db"
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
