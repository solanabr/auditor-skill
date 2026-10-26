#!/bin/bash
# web3js-history.sh — the history half of the known-bad release check (FULL-AUDIT.md Step 3.2, KV-077 Step 2):
# the commits, on every branch, that add or remove the hijacked @solana/web3.js 1.95.6 / 1.95.7 or axios
# 1.14.1 / 0.30.4 in a manifest or a lockfile.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/recipes/web3js-history.sh" [--repo <dir> | --git-dir <R>/src[-<k>].git]
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under audit.
# Its checks hold whatever words follow, and a refusal is one stderr line, "web3js-history: refused:
# <reason>", with exit 64, before git reads the history.
#
# Two searches, each over every branch, merge commits (against their first parent) and the root commit, each
# under its own heading line:
#   == single-line form   git log -G over *lock*, *package.json and *npm-shrinkwrap.json: each commit that adds
#                         or removes a line naming one of those releases, as a resolved URL, a pnpm, yarn or bun
#                         key, or an exact pin; printed as "<commit> <subject>";
#   == key-line form      package-lock.json and npm-shrinkwrap.json written without "resolved" fields name a
#                         package only on its entry's key line (or its "name" line, for an alias), with the
#                         version on a line below it: each such version line added, removed, or kept under a key
#                         that changed, printed as "<commit> <a/ or b/ path> <line>".
# Another package at one of those versions is not reported. Nothing under either heading means none was found.
#
# --repo <dir> is "." (the default) or a path relative to the working directory, with no "..", and no symbolic
# link on the way, that is the top level of a repository whose git directory lies inside the working directory
# (scripts/lib/confine.sh, as scripts/git-ro.sh takes it). --git-dir names a copy that scripts/git-ro.sh copy
# made in a run directory <R>, audit_<n> or incident_<n>.
#
# git runs through the hardened call of scripts/lib/confine.sh (OUTPUT-RULES.md Rule 11c; scripts/git-ro.sh's
# header lists what it switches off), as
#   git log --no-textconv --no-ext-diff --all --full-history --root --diff-merges=first-parent --text -G<pattern>
# with --no-patch --oneline --no-decorate for the first search and -p -U3 --no-color --format='commit %h' for
# the second, every hunk kept apart and the a/ and b/ prefixes, whatever the checkout's config sets: a committed
# .gitattributes that marks lockfiles binary or -diff hides nothing (--text), and the checkout's colour, context,
# prefix and decoration settings change no line. In a partial clone a note goes to stderr first
# ("web3js-history: partial clone: ..."), nothing is fetched and a missing object fails (a fatal: line); in a
# shallow clone a note says the history before the boundary is missing. Either way the history is incomplete.
#
# Output: every control character other than TAB and LF, NUL included, prints as ?, on stdout and stderr; a CR
# that ends a lockfile line is dropped first. Standard input is never read.
# Exit: 0 both searches ran, whether or not a line printed · 64 refused · git's own status when git fails (the
# other search still runs). Needs bash >= 3.2 and git; env, find, wc, od, tr and awk.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'web3js-history: refused: the installation cannot be resolved\n' >&2; exit 64; }
case "$here" in
  */scripts/recipes) root=${here%/scripts/recipes} ;;
  *) printf 'web3js-history: refused: web3js-history.sh runs from <auditor-skill root>/scripts/recipes\n' >&2; exit 64 ;;
esac
. "$root/scripts/lib/confine.sh" || { printf 'web3js-history: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
confine_init web3js-history "$root"
confine_need env git find wc od tr awk
exec </dev/null
WT=$CONFINE_WT
REPO=""

USAGE='usage: web3js-history.sh [--repo <dir> | --git-dir <R>/src.git]'

# The known-bad releases in one line: exact pins and resolved versions in package.json, package-lock /
# npm-shrinkwrap, pnpm (lockfile v5 keys too), yarn v1 and berry, and bun. A range such as "^1.95.7" does not
# match on its own.
AX='(^|[^A-Za-z0-9_.-])axios[@/](npm:)?(1\.14\.1|0\.30\.4)([^0-9]|$)|/axios/-/axios-(1\.14\.1|0\.30\.4)\.tgz|"axios"[[:space:]]*:[[:space:]]*"=?(1\.14\.1|0\.30\.4)"'
W3='web3\.js[@/](npm:)?1\.95\.(6|7)([^0-9]|$)|/web3\.js/-/web3\.js-1\.95\.(6|7)\.tgz|"@solana/web3\.js"[[:space:]]*:[[:space:]]*"=?1\.95\.(6|7)"'
# The key-line form: a key, "name" or version line of either package, for -G; the awk then pairs each version
# line with the key the hunk last showed, old (-) and new (+), and prints the ones that name a bad release.
KL='"(([^"]*/)?node_modules/)?axios": [{]|"name": "axios"|"version": "(1\.14\.1|0\.30\.4)"|"([^"]*/)?@solana/web3\.js": [{]|"name": "@solana/web3\.js"|"version": "1\.95\.(6|7)"'
KL_AWK='function bad(k) {return (k ~ /"(([^"]*\/)?node_modules\/)?axios"/ && /"version": "(1\.14\.1|0\.30\.4)"/) ||
                               (k ~ /@solana\/web3\.js"/ && /"version": "1\.95\.(6|7)"/)}
  {sub(/\r$/, "")} /^commit /{c=$2} /^--- /{f=substr($0, 5)} /^[+][+][+] [^\/]/{f=substr($0, 5)} /^@@/{o=n=""}
  /^[-+ ][[:space:]]*"[^"]*": [{]$/ || /^[-+ ][[:space:]]+"name": /{if (/^-/) o=$0; else if (/^[+]/) n=$0; else o=n=$0}
  /^[-+ ][[:space:]]+"version": "/{w=bad(o); v=bad(n); if ((/^-/ && w) || (/^[+]/ && v) || (/^ / && w != v)) print c, f, $0}'

refuse() { confine_refuse "$1"; }

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
    0) printf '%s\n' 'web3js-history: partial clone: missing objects are not fetched; history and contents may be incomplete (Rule 11c)' >&2 ;;
    2) refuse "git cannot read the repository's config, so a partial clone cannot be ruled out" ;;
  esac
  if [ -e "$CONFINE_COMMON_DIR/shallow" ]; then
    printf '%s\n' 'web3js-history: shallow clone: history before the shallow boundary is missing (Rule 11c)' >&2
  fi
}

main() {
  local a repo=. given=0 gitdir="" what="the working directory" rc=0 st1
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
      *) refuse "$USAGE" ;;
    esac
  done
  if [ -n "$gitdir" ]; then open_copy "$gitdir"; else confine_repo "$repo" "$what"; fi
  REPO=$CONFINE_REPO
  note_history
  printf '%s\n' '== single-line form: <commit> <subject> of each commit that adds or removes a known-bad release'
  hgit "$REPO" log --no-textconv --no-ext-diff --ignore-submodules=none --all --full-history --root \
    --diff-merges=first-parent --no-patch --oneline --no-decorate --text -G"$AX|$W3" \
    -- '*lock*' '*package.json' '*npm-shrinkwrap.json' </dev/null
  st1=$?
  printf '%s\n' '== key-line form: <commit> <file> <line> of each version line under a known-bad entry'
  hgit_text "$REPO" -c diff.noprefix=false -c diff.mnemonicPrefix=false -c diff.srcPrefix=a/ -c diff.dstPrefix=b/ \
    log --no-textconv --no-ext-diff --ignore-submodules=none --all --full-history --root \
    --diff-merges=first-parent -p -U3 --no-color --format='commit %h' --text -G"$KL" \
    -- '*package-lock.json' '*npm-shrinkwrap.json' </dev/null | awk "$KL_AWK"
  st=("${PIPESTATUS[@]}")
  for rc in "$st1" "${st[0]}" "${st[1]}"; do
    [ "$rc" -eq 0 ] || exit "$rc"
  done
  exit 0
}

# What git and the parser print, errors included, goes out with every control character but TAB and LF, NUL
# too, as ?.
CTRL='\000-\010\013-\037\177'
{ main "$@" 2>&1 1>&3 3>&- | tr "$CTRL" '?' 1>&2 3>&-; } 3>&1 | tr "$CTRL" '?'
