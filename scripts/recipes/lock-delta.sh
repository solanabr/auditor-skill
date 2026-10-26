#!/bin/bash
# lock-delta.sh — the lockfile hints of checklists/11-supply-chain.md §11.11: each version, source and checksum
# line that changed in the lockfiles between two commits, with the name of its package.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/recipes/lock-delta.sh" [--repo <dir> | --git-dir <R>/src[-<k>].git] npm|bun|cargo <base>..<head>
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under audit.
# Its checks hold whatever words follow, and a refusal is one stderr line, "lock-delta: refused: <reason>", with
# exit 64, before git reads the history.
#
# What it prints, for the lockfiles of that kind anywhere in the tree, below each file's "+++ b/<path>" line
# ("+++ /dev/null" for a file the range deletes):
#   npm    package-lock.json, npm-shrinkwrap.json and yarn.lock (v1 and berry): each changed version, resolved,
#          resolution, integrity or checksum line after the key of its entry (an npm alias: after its "name"
#          line), as "<key> <line>", with "?" for a key that lies outside the hunk;
#   bun    the text bun.lock: each changed entry as "<- or +> <name>@<version>";
#   cargo  Cargo.lock: each changed version, source or checksum line after its package name, as "<name> <line>".
#
# --repo <dir> is "." (the default) or a path relative to the working directory, with no "..", and no symbolic
# link on the way, that is the top level of a repository whose git directory lies inside the working directory
# (scripts/lib/confine.sh, as scripts/git-ro.sh takes it). --git-dir names a copy that scripts/git-ro.sh copy
# made in a run directory <R>, audit_<n> or incident_<n>. <base> and <head> name commits: letters, digits and
# ._/~^+-, starting with a letter or a digit, with no "..", at most 255 bytes each.
#
# git runs through the hardened call of scripts/lib/confine.sh (OUTPUT-RULES.md Rule 11c; scripts/git-ro.sh's
# header lists what it switches off), as
#   git diff --no-textconv --no-ext-diff --ignore-submodules=none --text --no-color -U3 <base>..<head> -- <lockfiles>
# with every hunk kept apart, three lines of context and the a/ and b/ prefixes, whatever the checkout's config
# sets, so neither a committed .gitattributes that marks lockfiles binary or -diff nor the checkout's colour,
# context or prefix settings change a line. It reads committed content only, never the work tree. In a partial
# clone a note goes to stderr first ("lock-delta: partial clone: ..."), nothing is fetched and a missing object
# fails; in a shallow clone a note says the history before the boundary is missing.
#
# Output: every control character other than TAB and LF, NUL included, prints as ?, on stdout and stderr; a CR
# that ends a lockfile line is dropped first for npm. Standard input is never read.
# Exit: 0 done, whether or not a line printed · 64 refused · git's own status when git fails (128: a revision it
# cannot find). Needs bash >= 3.2 and git; env, find, wc, od, tr, awk and sed.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'lock-delta: refused: the installation cannot be resolved\n' >&2; exit 64; }
case "$here" in
  */scripts/recipes) root=${here%/scripts/recipes} ;;
  *) printf 'lock-delta: refused: lock-delta.sh runs from <auditor-skill root>/scripts/recipes\n' >&2; exit 64 ;;
esac
. "$root/scripts/lib/confine.sh" || { printf 'lock-delta: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
confine_init lock-delta "$root"
confine_need env git find wc od tr awk sed
exec </dev/null
WT=$CONFINE_WT
REPO=""

USAGE='usage: lock-delta.sh [--repo <dir> | --git-dir <R>/src.git] npm|bun|cargo <base>..<head>'

# The npm / yarn hint: a key is an entry's "<name>": { line, its "name" line, or a yarn key at the start of a
# line; each changed field line below it prints after the key the hunk last showed, old (-) or new (+).
NPM_AWK='{sub(/\r$/, "")} /^[+][+][+] /{print} /^@@/{o=n="?"}
  /^[-+ ][[:space:]]*"[^"]*": [{]$/ || /^[-+ ][[:space:]]+"name": / || /^[-+ ][^[:space:]#].*:$/ {k=$0; sub(/^[-+ ][[:space:]]*/, "", k)
    sub(/(: [{]|:|,)$/, "", k); if (/^-/) o=k; else if (/^[+]/) n=k; else o=n=k}
  /^-[[:space:]]+"?(version|resolved|resolution|integrity|checksum)"?:?[[:space:]]/{print o, $0}
  /^[+][[:space:]]+"?(version|resolved|resolution|integrity|checksum)"?:?[[:space:]]/{print n, $0}'
# The text bun.lock: the first array element of an entry is name@version.
BUN_SED='/^\+\+\+ /p; s/^([-+])[[:space:]]+"[^"]+": \["([^"]+)".*/\1 \2/p'
# Cargo.lock: the name line of each [[package]] comes before its version, source and checksum lines.
CARGO_AWK='/^[+][+][+] /{print} /^ name = /{o=n=$3} /^-name = /{o=$3} /^[+]name = /{n=$3}
  /^-(version|source|checksum) = /{print o, $0} /^[+](version|source|checksum) = /{print n, $0}'

refuse() { confine_refuse "$1"; }

check_rev() { # check_rev <name>: status 0 for a commit name of the grammar above
  case "$1" in
    ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._/~^+-]*|*..*) return 1 ;;
  esac
  [ "${#1}" -le 255 ]
}

open_copy() { # open_copy <R>/src[-<k>].git: a copy that git-ro.sh copy made, as git-ro.sh opens it
  local v=${1#./} r rest k shown
  shown=$(confine_text "$1")
  r=${v%%/*}
  rest=${v#*/}
  [ "$r" != "$v" ] || refuse "--git-dir takes <R>/src.git or <R>/src-<k>.git: $shown"
  case "$rest" in
    src.git) ;;
    src-*.git)
      k=${rest#src-}
      k=${k%.git}
      case "$k" in ''|*[!0-9]*) refuse "--git-dir takes <R>/src.git or <R>/src-<k>.git: $shown" ;; esac ;;
    *) refuse "--git-dir takes <R>/src.git or <R>/src-<k>.git: $shown" ;;
  esac
  confine_rundir "$r" "--git-dir's run directory"
  [ -d "$WT/$r/$rest" ] && [ -f "$WT/$r/$rest/auditor-copy" ] ||
    refuse "--git-dir names no copy that git-ro.sh copy made: $shown"
  confine_repo "$r/$rest" "--git-dir"
  [ "$CONFINE_BARE" = true ] || refuse "--git-dir is not a bare repository: $shown"
}

note_history() { # the notes for a partial or a shallow clone
  confine_partial_clone "$REPO" >/dev/null
  case $? in
    0) printf '%s\n' 'lock-delta: partial clone: missing objects are not fetched; history and contents may be incomplete (Rule 11c)' >&2 ;;
    2) refuse "git cannot read the repository's config, so a partial clone cannot be ruled out" ;;
  esac
  if [ -e "$CONFINE_COMMON_DIR/shallow" ]; then
    printf '%s\n' 'lock-delta: shallow clone: history before the shallow boundary is missing (Rule 11c)' >&2
  fi
}

delta() { # delta <range> <pathspec>...: the diff the lines are read from
  local range=$1
  shift
  hgit_text "$REPO" -c diff.noprefix=false -c diff.mnemonicPrefix=false -c diff.srcPrefix=a/ -c diff.dstPrefix=b/ \
    diff --no-textconv --no-ext-diff --ignore-submodules=none --text --no-color -U3 --end-of-options "$range" \
    -- "$@" </dev/null
}

main() {
  local a repo=. given=0 gitdir="" what="the working directory" kind range base head
  local -a st=()
  for a in "$@"; do
    case "$a" in *[[:cntrl:]]*) refuse "an argument holds a control character: $(confine_text "$a")" ;; esac
    [ "${#a}" -le 4096 ] || refuse "an argument is longer than 4096 bytes"
  done
  while [ $# -gt 0 ]; do
    case "$1" in
      --repo|--git-dir)
        [ "$given" -eq 0 ] || refuse "give --repo or --git-dir once"
        [ $# -ge 2 ] || refuse "$1 needs a value"
        if [ "$1" = --repo ]; then repo=$2 what=--repo; else gitdir=$2; fi
        given=1
        shift 2 ;;
      *) break ;;
    esac
  done
  [ $# -eq 2 ] || refuse "$USAGE"
  kind=$1 range=$2
  case "$kind" in
    npm|bun|cargo) ;;
    *) refuse "$USAGE" ;;
  esac
  case "$range" in
    *..*) base=${range%%..*} head=${range#*..} ;;
    *) refuse "the range is <base>..<head>, two commits joined by ..: $(confine_text "$range")" ;;
  esac
  check_rev "$base" && check_rev "$head" ||
    refuse "<base> and <head> name commits: letters, digits and ._/~^+-, starting with a letter or a digit, with no .., at most 255 bytes each: $(confine_text "$range")"
  if [ -n "$gitdir" ]; then open_copy "$gitdir"; else confine_repo "$repo" "$what"; fi
  REPO=$CONFINE_REPO
  note_history
  case "$kind" in
    npm) delta "$range" '*package-lock.json' '*npm-shrinkwrap.json' '*yarn.lock' | awk "$NPM_AWK" ;;
    bun) delta "$range" '*bun.lock' | sed -nE "$BUN_SED" ;;
    cargo) delta "$range" '*Cargo.lock' | awk "$CARGO_AWK" ;;
  esac
  st=("${PIPESTATUS[@]}")
  [ "${st[0]}" -eq 0 ] || exit "${st[0]}"
  exit "${st[1]}"
}

# What git and the parsers print, errors included, goes out with every control character but TAB and LF, NUL
# too, as ?.
CTRL='\000-\010\013-\037\177'
{ main "$@" 2>&1 1>&3 3>&- | tr "$CTRL" '?' 1>&2 3>&-; } 3>&1 | tr "$CTRL" '?'
