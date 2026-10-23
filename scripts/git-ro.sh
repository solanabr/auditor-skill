#!/bin/bash
# git-ro.sh — read-only git for checkouts the auditor did not create (OUTPUT-RULES.md Rule 11c).
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/git-ro.sh" [--repo <dir> | --git-dir <R>/src[-<k>].git] <subcommand> [<arg>...]
#   "${CLAUDE_PLUGIN_ROOT}/scripts/git-ro.sh" copy <dir> <R>          bare copy into <R>/src[-<k>].git; prints its path
#   "${CLAUDE_PLUGIN_ROOT}/scripts/git-ro.sh" partial [--repo <dir>]  0 = not partial, 3 = partial (keys printed)
#   "${CLAUDE_PLUGIN_ROOT}/scripts/git-ro.sh" tracked <path>          what git tracks at <path>, any letter case
#
# Run it directly by its quoted absolute path, with no bash in front. Its checks hold whatever words
# follow, and a refusal is one stderr line, "git-ro: refused: <reason>", with exit 64.
#
# <dir> is "." (the default) or a path relative to the working directory, with no "..", and no symbolic
# link on the way. It must be the top level of a repository, or a bare repository, whose git directory
# lies inside the working directory, holds no symbolic link and borrows no objects (alternates).
# --git-dir names a copy that `copy` made in a run directory <R> (audit_<n> or incident_<n>).
#
# No caller word ever precedes the git subcommand. Every argument lands after the subcommand name, so
# git reads it as an option of that subcommand, never as a global git option: in `git-ro.sh log -c x=y`
# the -c is log's own. Only --repo and --git-dir may come before the subcommand, and a git option there
# (-c, -C, --exec-path, --git-dir=, --config-env) is refused.
#
# Subcommands:
#   log, shortlog, rev-list, show, ls-tree, cat-file, rev-parse, merge-base, name-rev, for-each-ref,
#   show-ref, count-objects, cherry, reflog show: allowed, subject to the denylist below.
#   diff: committed revisions only, A..B, A...B, A^!, A B or --cached [A]; paths go after --. The
#     revisions are the last one or two words before -- that are not options. git-ro puts them behind
#     --end-of-options and ends them with --, so no option can take one as its value.
#   diff-tree: as git always runs it, on trees.
#   blame: needs <rev> -- <path>; git-ro puts the revision right after the subcommand. It refuses a
#     repository whose config sets blame.ignoreRevsFile: git reads that file, prints a line it cannot
#     parse, and no command-line value resets the setting. Blame a copy instead.
#   grep: committed content only. With no revision it searches the index, as with --cached.
#   ls-files: no -m/--modified (it runs clean filters), --eol, or --format reading the work tree.
#   cat-file: no --filters or --batch-command; standard input reaches --batch and --batch-check only.
#   describe: no --dirty or --broken.
#   config: reads of the repository's own config file, never of included files: --get, --get-all,
#     --get-regexp, --get-urlmatch or --list, with --show-origin, --show-scope, --name-only, -z, --type
#     and the type flags; `config get` and `config list` on git 2.46 and later.
#   remote: remote, remote -v, remote get-url [--all] [--push] <name>, printing the URLs as the
#     repository's config file writes them (no insteadOf rewriting, no included files).
#   Anything else is refused, range-diff too: the git log it starts runs textconv drivers whatever flags
#   it gets. shortlog never reads standard input, so give it a revision (HEAD).
#
# Denylist, at any position before the first --, abbreviations and --no-no-<x> spellings included:
#   --output*, --ext-diff, --textconv, --show-signature, --exec*, --upload-pack*, --receive-pack*,
#   --remote (--remotes is allowed), --git-dir*, --work-tree*, --namespace*, --super-prefix*,
#   --config-env*, --recurse-submodules*, --submodule*, --no-index, --contents*, --ignore-revs-file*,
#   --exclude-from*, --pathspec-from-file*, --open-files-in-pager*, --remerge-diff and --diff-merges=remerge
#   or r (they run the merge drivers the repository configures); -O (a diff order file, grep's pager),
#   grep -f/--file and --untracked, ls-files -X, blame -S.
# --format and --pretty take a built-in name, a format: or tformat: string, or a string with a %. Other
# names can be pretty.<name> aliases from the repository's config, and %G or %(signature runs the
# signature program, so both are refused.
#
# The hardened call (hgit in scripts/lib/confine.sh) runs every git command with env -i and only HOME,
# PATH (absolute entries outside the working directory), TMPDIR, LC_ALL=C and TZ, plus GIT_NO_LAZY_FETCH,
# GIT_TERMINAL_PROMPT=0, GIT_OPTIONAL_LOCKS=0, GIT_CEILING_DIRECTORIES at the working directory's parent,
# and system and global config dropped. git runs with --no-pager, and -c pins override the repository's
# config. They switch off:
#   - programs config can name: core.fsmonitor, core.pager, core.hooksPath (hooks), diff.external,
#     gpg.program, gpg.ssh.program and gpg.x509.program, log.showSignature and format.pretty, and
#     log.diffMerges (a remerge diff runs merge.<driver>.driver);
#   - fetching: protocol.allow=never stops lazy fetch and every remote helper on every git version;
#   - files outside the tree that config can name and git prints from or parses: core.attributesFile,
#     core.excludesFile, diff.orderFile, mailmap.file;
#   - other repositories: submodule.recurse, diff.submodule;
#   - output shaping: colour, core.quotePath, i18n.logOutputEncoding, core.bigFileThreshold.
# --no-textconv --no-ext-diff go on log, show, diff, diff-tree, blame and reflog show, and --no-textconv
# on grep. Clean and smudge filters cannot be pinned by name, so no allowed form reads the work tree's
# content. Re-check the pins and this list against each new git release: a new config key that runs a
# program or reads a file, or a read command that starts one, reopens what they close. The fixtures in
# scripts/tests/test-git-ro.sh only prove the keys they set.
#
# Output: control characters other than TAB and LF in what git prints, errors included, print as ?, so
# binary content does not round-trip. Standard input is never read except as above. In a partial
# clone, every read prints a note first; nothing is fetched, and a missing object fails.
#
# copy runs `clone --no-local --bare --no-recurse-submodules --template=` of <dir> into <R>/src.git
# (src-2.git, src-3.git, ... once that exists) under the same hardened call, with protocol.file.allow
# for that clone, from a scratch directory outside the working directory. It refuses a partial clone
# (exit 3) and git without the May-2024 clone fixes, CVE-2024-32004 and CVE-2024-32465 (exit 69):
# accepted are 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, 2.46 and later in each line. It
# writes <R>/src.git/auditor-copy; read the copy with --git-dir <R>/src.git.
#
# Exit: git's own status (0, 1, 128, ...) · 3 partial clone (partial, copy) · 64 refused · 69 git too
# old to copy. Needs bash >= 3.2 and git; env, find, tr, wc, cat, sort, mkdir, mktemp and rmdir.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'git-ro: refused: the installation cannot be resolved\n' >&2; exit 64; }
. "$here/lib/confine.sh" || { printf 'git-ro: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
confine_init git-ro "${here%/*}"
confine_need env git find tr wc cat sort mkdir mktemp rmdir
WT=$CONFINE_WT
REPO=""

USAGE='usage: git-ro.sh [--repo <dir> | --git-dir <R>/src.git] <subcommand> [<arg>...], or copy <dir> <R>, partial [--repo <dir>], tracked <path>'
DIFF_USAGE='diff compares committed revisions: give A..B, A...B, A^!, A B or --cached [A], and paths after --'
BLAME_USAGE='blame needs <rev> -- <path>: a revision, then --, then one path'
# Long options refused with any ending, refused as written, and allowed only with a checked value; an
# abbreviation of any of them is refused, except the four exact options that share a denied name's prefix.
DENY_PREFIX='output exec upload-pack receive-pack git-dir work-tree namespace super-prefix config-env recurse-submodules submodule contents ignore-revs-file exclude-from pathspec-from-file open-files-in-pager'
DENY_EXACT='ext-diff textconv show-signature no-index remote remerge-diff'
GUARDED='format pretty diff-merges'
EXACT_OK='exclude text ignore-rev batch'

refuse() { confine_refuse "$1"; }

refuse_option() { refuse "$SUB does not allow $(confine_text "$1")"; }

check_format() { # check_format <value of --format or --pretty>
  case "$1" in
    oneline|short|medium|full|fuller|reference|email|raw|mboxrd|format:*|tformat:*|*%*) ;;
    *) refuse "--format and --pretty take a built-in name, a format: or tformat: string, or a string with %, not $(confine_text "$1")" ;;
  esac
  case "$1" in
    *%G*|*'%(signature'*) refuse "a format with %G or %(signature runs the signature program: $(confine_text "$1")" ;;
  esac
  if [ "$SUB" = ls-files ]; then
    case "$1" in *worktree*) refuse "ls-files does not read the work tree: $(confine_text "$1")" ;; esac
  fi
}

check_merges() { # check_merges <value of --diff-merges>
  case "$1" in
    remerge|r) refuse "a remerge diff runs the merge drivers the repository configures: --diff-merges=$(confine_text "$1")" ;;
  esac
}

check_long() { # check_long <option without its leading -->: sets NEXT when the next word is its value
  local name=${1%%=*} d
  while :; do
    case "$name" in no-no-*) name=${name#no-no-} ;; *) break ;; esac
  done
  for d in $DENY_PREFIX; do
    case "$name" in "$d"*) refuse_option "--$1" ;; esac
  done
  for d in $DENY_EXACT $EXTRA; do
    [ "$name" != "$d" ] || refuse_option "--$1"
  done
  case " $EXACT_OK " in *" $name "*) return 0 ;; esac
  for d in $DENY_PREFIX $DENY_EXACT $EXTRA $GUARDED; do
    case "$d" in "$name"?*) refuse "$SUB does not allow $(confine_text "--$1"): write options out in full" ;; esac
  done
  case "$name" in
    format|pretty)
      case "$1" in
        *=*) check_format "${1#*=}" ;;
        format) NEXT=format ;;
      esac ;;
    diff-merges)
      case "$1" in
        *=*) check_merges "${1#*=}" ;;
        *) NEXT=merges ;;
      esac ;;
  esac
  return 0
}

# check_options <subcommand> <arg>...: the denylist, before the first --. A short option whose first
# letter takes free text (-S<string>, -e<pattern>) is checked by that letter only. The value of
# --format or --diff-merges given as the next word is checked as a value, and as an option too.
check_options() {
  local a short_deny short_free first
  NEXT=""
  SUB=$1
  shift
  case "$SUB" in
    grep) EXTRA='file untracked' ;;
    ls-files) EXTRA='modified eol' ;;
    cat-file) EXTRA='filters batch-command' ;;
    describe) EXTRA='dirty broken' ;;
    *) EXTRA='' ;;
  esac
  case "$SUB" in
    log|show|diff|diff-tree|reflog) short_deny=O short_free=SGIL ;;
    grep) short_deny=Of short_free=e ;;
    ls-files) short_deny=mX short_free=x ;;
    blame) short_deny=S short_free=L ;;
    *) short_deny='' short_free='' ;;
  esac
  for a in "$@"; do
    case "$NEXT" in
      format) NEXT=""; check_format "$a" ;;
      merges) NEXT=""; check_merges "$a" ;;
    esac
    case "$a" in
      --) break ;;
      --?*) check_long "${a#--}" ;;
      -?*)
        [ -n "$short_deny" ] || continue
        first=${a#-}
        first=${first%"${first#?}"}
        case "$short_free" in *"$first"*) continue ;; esac
        case "${a#-}" in *["$short_deny"]*) refuse_option "$a" ;; esac ;;
    esac
  done
}

note_partial() {
  confine_partial_clone "$REPO" >/dev/null
  case $? in
    0) printf '%s\n' 'git-ro: partial clone: missing objects are not fetched; history and contents may be incomplete (Rule 11c)' >&2 ;;
    2) refuse "git cannot read the repository's config, so a partial clone cannot be ruled out" ;;
  esac
}

open_copy() { # open_copy <R>/src[-<k>].git: a copy that copy made
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

copy_git_ok() { # status 0 when git has the May-2024 clone fixes
  local v maj min pat
  v=$(env -i PATH="$PATH" git --version 2>/dev/null) || return 1
  v=${v#git version }
  v=${v%% *}
  maj=${v%%.*}; v=${v#"$maj"}; v=${v#.}
  min=${v%%.*}; v=${v#"$min"}; v=${v#.}
  pat=${v%%.*}
  maj=${maj%%[!0-9]*}; min=${min%%[!0-9]*}; pat=${pat%%[!0-9]*}
  [ -n "$maj" ] && [ -n "$min" ] || return 1
  [ -n "$pat" ] || pat=0
  [ "$maj" -le 2 ] || return 0
  [ "$maj" -eq 2 ] || return 1
  case "$min" in
    39|43) [ "$pat" -ge 4 ] ;;
    40|42) [ "$pat" -ge 2 ] ;;
    41|44|45) [ "$pat" -ge 1 ] ;;
    *) [ "$min" -ge 46 ] ;;
  esac
}

run_copy() { # run_copy <dir> <R>
  local src rel r dest k scratch rc
  [ $# -eq 2 ] || refuse "copy takes a repository and a run directory: copy <dir> <R>"
  confine_repo "$1" "copy's repository"
  src=$CONFINE_REPO
  rel=$CONFINE_REL
  confine_rundir "$2" "copy's run directory"
  r=$CONFINE_RUN
  confine_partial_clone "$src" >/dev/null
  case $? in
    0) printf 'git-ro: %s is a partial clone: a copy would lack the objects it never fetched, and nothing is fetched; make a full copy from a source you trust (Rule 11c)\n' "$(confine_text "$1")" >&2
       exit 3 ;;
    2) refuse "git cannot read the config of $(confine_text "$1"), so a partial clone cannot be ruled out" ;;
  esac
  if ! copy_git_ok; then
    printf 'git-ro: refused: copy needs git with the May-2024 clone fixes: 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, or 2.46 or later\n' >&2
    exit 69
  fi
  dest=src.git
  k=2
  while [ -e "$WT/$r/$dest" ] || [ -L "$WT/$r/$dest" ]; do
    [ "$k" -le 9999 ] || refuse "$r holds too many copies"
    dest=src-$k.git
    k=$((k + 1))
  done
  confine_mkdir "$WT/$r/$dest" || refuse "cannot create $r/$dest"
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/auditor-git-ro.XXXXXX") && confine_phys "$scratch" ||
    { rmdir "$WT/$r/$dest"; refuse "cannot create a scratch directory"; }
  scratch=$CONFINE_PHYS
  case "$scratch/" in
    "${WT%/}/"*) rmdir "$scratch" "$WT/$r/$dest"; refuse "the scratch directory (TMPDIR) lies inside the working directory" ;;
  esac
  CONFINE_CEILING=${scratch%/*} hgit "$scratch" -c protocol.file.allow=always \
    clone --no-local --bare --no-recurse-submodules --template= -- "$src" "$WT/$r/$dest" </dev/null
  rc=$?
  rmdir "$scratch"
  if [ "$rc" -ne 0 ]; then
    rmdir "$WT/$r/$dest" 2>/dev/null
    exit "$rc"
  fi
  confine_new_file "$WT/$r/$dest/auditor-copy" "auditor-copy: made by git-ro.sh copy from $rel"$'\n' ||
    refuse "cannot write $r/$dest/auditor-copy"
  printf '%s\n' "$r/$dest"
  exit 0
}

run_tracked() { # run_tracked <path>
  local out
  [ $# -eq 1 ] || refuse "tracked takes one path"
  confine_path "$1" "tracked's path" any
  out=$(confine_tracked "$CONFINE_REL") || refuse "git cannot tell whether $(confine_text "$1") is tracked"
  [ -z "$out" ] || printf '%s\n' "$out"
  exit 0
}

run_partial() {
  local keys rc
  keys=$(confine_partial_clone "$REPO")
  rc=$?
  case $rc in
    0) printf '%s\n' "$keys"; exit 3 ;;
    1) exit 0 ;;
  esac
  refuse "git cannot read the repository's config, so a partial clone cannot be ruled out"
}

run_config() { # run_config <arg>...: reads of the repository's own config file
  local form=legacy action="" n
  local -a opts=() pos=()
  case "${1-}" in get|list) form=$1; shift ;; esac
  while [ $# -gt 0 ]; do
    case "$form:$1" in
      legacy:--get|legacy:--get-all|legacy:--get-regexp|legacy:--get-urlmatch|legacy:--list|legacy:-l)
        [ -z "$action" ] || refuse "config takes one action"
        action=$1 ;;
      get:--all|get:--regexp|get:--value=*|get:--url=*|get:--default=*|legacy:--default=*)
        opts+=("$1") ;;
      *:--show-origin|*:--show-scope|*:--name-only|*:-z|*:--null|*:--local|*:--no-includes)
        opts+=("$1") ;;
      get:--bool|get:--int|get:--bool-or-int|get:--path|get:--expiry-date|get:--fixed-value|get:--type=*)
        opts+=("$1") ;;
      legacy:--bool|legacy:--int|legacy:--bool-or-int|legacy:--path|legacy:--expiry-date|legacy:--fixed-value|legacy:--type=*)
        opts+=("$1") ;;
      get:--type|get:--default|legacy:--type|legacy:--default)
        [ $# -ge 2 ] || refuse "config $1 needs a value"
        opts+=("$1" "$2")
        shift ;;
      *:-*) refuse "config only reads the repository's own config file: $(confine_text "$1") is not allowed" ;;
      *) pos+=("$1") ;;
    esac
    shift
  done
  n=${#pos[@]}
  case "$form:$action" in
    legacy:--get|legacy:--get-all|legacy:--get-regexp) [ "$n" -ge 1 ] && [ "$n" -le 2 ] ;;
    legacy:--get-urlmatch) [ "$n" -eq 2 ] ;;
    legacy:--list|legacy:-l|list:) [ "$n" -eq 0 ] ;;
    get:) [ "$n" -eq 1 ] ;;
    *) false ;;
  esac || refuse "config only reads: --get, --get-all or --get-regexp <name> [<value-pattern>], --get-urlmatch <name> <URL>, --list, config get <name>, config list"
  if [ "$form" = legacy ]; then
    hgit "$REPO" config --local --no-includes ${opts[@]+"${opts[@]}"} "$action" ${pos[@]+"${pos[@]}"} </dev/null
  else
    hgit "$REPO" config "$form" --local --no-includes ${opts[@]+"${opts[@]}"} ${pos[@]+"${pos[@]}"} </dev/null
  fi
  exit $?
}

# remote_table <mode> <name> <all> <push>: the "remote" output, from config -z records of
# remote.<name>.url and remote.<name>.pushurl on stdin.
remote_table() {
  local mode=$1 want=$2 all=$3 push=$4 rec key val n i names found kind
  local -a rn=() rk=() rv=()
  while IFS= read -r -d '' rec; do
    case "$rec" in
      *$'\n'*) key=${rec%%$'\n'*}; val=${rec#*$'\n'} ;;
      *) key=$rec; val="" ;;
    esac
    val=${val//$'\n'/?}
    case "$key" in
      remote.*.url) n=${key#remote.}; n=${n%.url}; kind=url ;;
      remote.*.pushurl) n=${key#remote.}; n=${n%.pushurl}; kind=pushurl ;;
      *) continue ;;
    esac
    rn+=("$n"); rk+=("$kind"); rv+=("$val")
  done
  names=$(i=0; while [ "$i" -lt "${#rn[@]}" ]; do printf '%s\n' "${rn[$i]}"; i=$((i + 1)); done | sort -u)
  case "$mode" in
    names) [ -z "$names" ] || printf '%s\n' "$names" ;;
    verbose)
      while IFS= read -r n; do
        [ -n "$n" ] || continue
        found=0 i=0
        while [ "$i" -lt "${#rn[@]}" ]; do
          if [ "${rn[$i]}" = "$n" ] && [ "${rk[$i]}" = url ]; then printf '%s\t%s (fetch)\n' "$n" "${rv[$i]}"; break; fi
          i=$((i + 1))
        done
        for kind in pushurl url; do
          i=0
          while [ "$i" -lt "${#rn[@]}" ]; do
            if [ "${rn[$i]}" = "$n" ] && [ "${rk[$i]}" = "$kind" ]; then printf '%s\t%s (push)\n' "$n" "${rv[$i]}"; found=1; fi
            i=$((i + 1))
          done
          [ "$found" -eq 0 ] || break
        done
      done <<EOF
$names
EOF
      ;;
    url)
      case "
$names
" in
        *"
$want
"*) ;;
        *) printf "error: No such remote '%s'\n" "$want" >&2; return 2 ;;
      esac
      kind=url
      if [ "$push" -eq 1 ]; then
        i=0
        while [ "$i" -lt "${#rn[@]}" ]; do
          if [ "${rn[$i]}" = "$want" ] && [ "${rk[$i]}" = pushurl ]; then kind=pushurl; break; fi
          i=$((i + 1))
        done
      fi
      i=0
      while [ "$i" -lt "${#rn[@]}" ]; do
        if [ "${rn[$i]}" = "$want" ] && [ "${rk[$i]}" = "$kind" ]; then
          printf '%s\n' "${rv[$i]}"
          [ "$all" -eq 1 ] || break
        fi
        i=$((i + 1))
      done ;;
  esac
  return 0
}

run_remote() { # run_remote <arg>...: remote, remote -v, remote get-url [--all] [--push] <name>
  local mode name="" all=0 push=0
  local -a st=()
  if [ $# -eq 0 ]; then
    mode=names
  elif [ $# -eq 1 ] && { [ "$1" = -v ] || [ "$1" = --verbose ]; }; then
    mode=verbose
  elif [ "$1" = get-url ]; then
    mode=url
    shift
    while [ $# -gt 0 ]; do
      case "$1" in
        --all) all=1 ;;
        --push) push=1 ;;
        -*) refuse "remote get-url takes --all, --push and one remote name, not $(confine_text "$1")" ;;
        *) [ -z "$name" ] || refuse "remote get-url takes one remote name"; name=$1 ;;
      esac
      shift
    done
    [ -n "$name" ] || refuse "remote get-url needs a remote name"
  else
    refuse "remote only reads: remote, remote -v, or remote get-url [--all] [--push] <name>"
  fi
  hgit "$REPO" config --local --no-includes -z --get-regexp '^remote\..*\.(url|pushurl)$' </dev/null |
    remote_table "$mode" "$name" "$all" "$push"
  st=("${PIPESTATUS[@]}")
  [ "${st[0]}" -le 1 ] || exit "${st[0]}"
  exit "${st[1]}"
}

# run_diff <arg>...: the revisions are the last one or two words before -- that are not options (one
# when it is a range, A..B, A...B or A^!). They move behind --end-of-options and end with --, so git
# reads them as revisions whatever option precedes them, and two revisions never reach the work tree.
run_diff() {
  local a seen=0 cached=0 i last=-1 prev=-1
  local -a pre=() post=() opts=() revs=() rest=()
  for a in "$@"; do
    if [ "$seen" -eq 0 ] && [ "$a" = -- ]; then seen=1; continue; fi
    if [ "$seen" -eq 0 ]; then pre+=("$a"); else post+=("$a"); fi
  done
  check_options diff ${pre[@]+"${pre[@]}"}
  for a in ${pre[@]+"${pre[@]}"}; do
    case "$a" in --cached|--staged) cached=1 ;; *) opts+=("$a") ;; esac
  done
  if [ "$cached" -eq 1 ]; then
    hgit "$REPO" diff --no-textconv --no-ext-diff --cached ${opts[@]+"${opts[@]}"} -- ${post[@]+"${post[@]}"} </dev/null
    exit $?
  fi
  i=0
  while [ "$i" -lt "${#opts[@]}" ]; do
    case "${opts[$i]}" in -*) ;; *) prev=$last; last=$i ;; esac
    i=$((i + 1))
  done
  [ "$last" -ge 0 ] || refuse "$DIFF_USAGE"
  case "${opts[$last]}" in
    *..*|*'^!') revs=("${opts[$last]}"); prev=-1 ;;
    *) [ "$prev" -ge 0 ] || refuse "$DIFF_USAGE"
       revs=("${opts[$prev]}" "${opts[$last]}") ;;
  esac
  i=0
  while [ "$i" -lt "${#opts[@]}" ]; do
    [ "$i" -eq "$last" ] || [ "$i" -eq "$prev" ] || rest+=("${opts[$i]}")
    i=$((i + 1))
  done
  hgit "$REPO" diff --no-textconv --no-ext-diff ${rest[@]+"${rest[@]}"} --end-of-options "${revs[@]}" -- ${post[@]+"${post[@]}"} </dev/null
  exit $?
}

run_blame() { # run_blame [<options>] <rev> -- <path>
  local a i=0 dd=-1 rev path
  local -a args=("$@") opts=()
  for a in "$@"; do
    if [ "$a" = -- ]; then dd=$i; break; fi
    i=$((i + 1))
  done
  [ "$dd" -ge 1 ] && [ $(($# - dd)) -eq 2 ] || refuse "$BLAME_USAGE"
  rev=${args[$((dd - 1))]}
  path=${args[$((dd + 1))]}
  case "$rev" in -*) refuse "$BLAME_USAGE" ;; esac
  [ "$dd" -lt 2 ] || opts=("${args[@]:0:$((dd - 1))}")
  check_options blame ${opts[@]+"${opts[@]}"}
  hgit "$REPO" config --get-all blame.ignorerevsfile >/dev/null 2>&1
  case $? in
    1) ;;
    0) refuse "blame does not run where the repository's config sets blame.ignoreRevsFile; blame a copy (git-ro.sh copy, then --git-dir)" ;;
    *) refuse "git cannot read the repository's config" ;;
  esac
  hgit "$REPO" blame --no-textconv --no-ext-diff "$rev" ${opts[@]+"${opts[@]}"} -- "$path" </dev/null
  exit $?
}

run_grep() { # run_grep <arg>...: the index first; the same words again only when git says they name trees
  local err rc
  check_options grep "$@"
  { err=$(hgit "$REPO" grep --no-textconv --cached "$@" 2>&1 1>&3 3>&- </dev/null); rc=$?; } 3>&1
  if [ "$rc" -eq 128 ]; then
    case "$err" in
      *'both --cached and trees are given'*)
        hgit "$REPO" grep --no-textconv "$@" </dev/null
        exit $? ;;
    esac
  fi
  [ -z "$err" ] || printf '%s\n' "$err" >&2
  exit "$rc"
}

main() {
  local a t repo=. given=0 gitdir="" what="the working directory" sub batch=0
  for a in "$@"; do
    t=${a//$'\t'/}
    case "$t" in *[[:cntrl:]]*) refuse "an argument holds a control character: $(confine_text "$a")" ;; esac
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
  [ $# -gt 0 ] || refuse "$USAGE"
  sub=$1
  shift
  case "$sub" in
    copy) [ "$given" -eq 0 ] || refuse "copy takes no --repo or --git-dir"; run_copy "$@" ;;
    tracked) [ "$given" -eq 0 ] || refuse "tracked takes no --repo or --git-dir"; run_tracked "$@" ;;
    partial)
      if [ $# -gt 0 ]; then
        [ "$given" -eq 0 ] && [ $# -eq 2 ] && [ "$1" = --repo ] || refuse "usage: partial [--repo <dir>]"
        repo=$2 what=--repo
        shift 2
      fi ;;
    log|shortlog|rev-list|show|ls-tree|cat-file|rev-parse|merge-base|name-rev|for-each-ref|show-ref|count-objects|cherry|reflog|diff|diff-tree|blame|grep|ls-files|describe|config|remote) ;;
    -*) refuse "only --repo <dir> or --git-dir <R>/src.git may come before the subcommand, never a git option: $(confine_text "$sub")" ;;
    *) refuse "$(confine_text "$sub") is not a read-only subcommand that git-ro runs" ;;
  esac
  if [ -n "$gitdir" ]; then open_copy "$gitdir"; else confine_repo "$repo" "$what"; fi
  REPO=$CONFINE_REPO
  case "$sub" in
    partial) run_partial ;;
    config) run_config "$@" ;;
    remote) run_remote "$@" ;;
  esac
  note_partial
  case "$sub" in
    diff) run_diff "$@" ;;
    blame) run_blame "$@" ;;
    grep) run_grep "$@" ;;
    reflog)
      [ "${1-}" = show ] || refuse "reflog only reads: reflog show [<options>] [<ref>]"
      shift
      check_options reflog "$@"
      hgit "$REPO" reflog show --no-textconv --no-ext-diff "$@" </dev/null ;;
    log|show|diff-tree)
      check_options "$sub" "$@"
      hgit "$REPO" "$sub" --no-textconv --no-ext-diff "$@" </dev/null ;;
    cat-file)
      check_options cat-file "$@"
      for a in "$@"; do
        [ "$a" != -- ] || break
        case "$a" in --batch|--batch=*|--batch-check|--batch-check=*) batch=1 ;; esac
      done
      if [ "$batch" -eq 1 ]; then hgit "$REPO" cat-file "$@"; else hgit "$REPO" cat-file "$@" </dev/null; fi ;;
    *)
      check_options "$sub" "$@"
      hgit "$REPO" "$sub" "$@" </dev/null ;;
  esac
  exit $?
}

# What git prints, errors included, goes out with control characters other than TAB and LF as ?.
CTRL='\001-\010\013-\037\177'
{ main "$@" 2>&1 1>&3 3>&- | tr "$CTRL" '?' 1>&2 3>&-; } 3>&1 | tr "$CTRL" '?'
