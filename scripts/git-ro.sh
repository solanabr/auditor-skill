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
# lies inside the working directory (scripts/lib/confine.sh confine_repo). Strict mode (OUTPUT-RULES.md
# Rule 11f) also refuses one whose git directory holds a symbolic link, borrows objects (alternates) or
# rewrites commit parents (info/grafts). Default mode reads those, alternates and grafts with a note on
# stderr, and:
#   - "." may lie below the top level of a repository that tracks something there, as in a session
#     started in a package of a monorepo: git-ro reads that repository, and every path in and out is
#     relative to the working directory, as plain git in it takes and prints them;
#   - a git directory outside the working directory is read where git's own layout ties it back (a
#     linked worktree, a submodule, a separate git directory naming it in core.worktree); one that
#     nothing ties back gets a note, and git-ro reads nothing and exits 0.
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
#     revisions are the last one or two words before -- that are not options. git-ro resolves each side
#     to one tree itself (A...B through the merge base, A^! through A's first parent, the empty tree for
#     a commit without one) and gives git just the two tree ids, behind --end-of-options and ended with
#     --: git then compares two trees and reads neither the index nor the work tree. A word that names
#     no single commit or tree (^A, A^@, A^-, two revisions in one) is refused, and so is --merge-base
#     beside two revisions (write A...B; --cached --merge-base [A] runs).
#   diff-tree: as git always runs it, on trees.
#   blame: needs <rev> -- <path>, with only blame's own options before <rev>, written out in full (-L,
#     --date, --ignore-rev, --since, --after, --until and --before may take the next word as their
#     value). git-ro resolves <rev> to a commit (A..B, for --reverse, to two different commits) and passes
#     the ids, so blame starts from a commit and never annotates the work tree. Where the repository's
#     config sets blame.ignoreRevsFile, which no command-line value resets, default mode copies each file
#     it names into git's empty work tree, where git looks for a relative one: a relative path with no
#     empty, . or .. component and no link on the way, to a regular file of one link and at most 1 MiB
#     in the work tree. Anything else, and strict mode, refuse it: blame a copy instead.
#   grep: committed content only. git-ro reads the words as git grep does (options, then a pattern
#     unless -e, --and, --not, ( or ) came first, then revisions, -- and paths) and resolves each
#     revision. With none it searches the index, as with --cached; with some it gives git exactly those
#     revisions, behind --end-of-options and ended with --. Without --, every word after the pattern must
#     be a revision once one is: give paths after --.
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
#   or r (they run the merge drivers the repository configures), --no-cached and --no-staged (they would
#   undo the --cached git-ro adds), -z, --null and cat-file -Z (NUL-separated output; see Output); -O (a
#   diff order file, grep's pager), grep -f/--file and --untracked, ls-files -X and
#   --exclude-per-directory, blame -S.
# --format and --pretty take a built-in name, a format: or tformat: string, or a string with a %. Other
# names can be pretty.<name> aliases from the repository's config, and %G or %(signature runs the
# signature program, so both are refused.
#
# The hardened call (hgit in scripts/lib/confine.sh) runs every git command with env -i and only HOME,
# PATH (absolute entries outside the working directory and the tree it lies in), TMPDIR, LC_ALL=C and TZ,
# plus GIT_NO_LAZY_FETCH, GIT_TERMINAL_PROMPT=0, GIT_OPTIONAL_LOCKS=0, GIT_ALLOW_PROTOCOL (the transport
# allowlist, empty here), GIT_CEILING_DIRECTORIES at the working directory's parent,
# and the system config dropped. The global config is none in strict mode; in default mode it is
# scripts/lib/safe-directory.gitconfig, so a checkout another user owns is read. It refuses before git starts when the repository holds a named
# pipe or device git would open, and kills git, refusing, when a question (rev-parse, config, ls-files)
# has not been answered within 10 s; any other read runs as long as it takes. Every subcommand but
# rev-parse, ls-files, config and remote reads with a private empty directory under TMPDIR as git's work
# tree, beside the repository's git directory (hgit_tree), so git opens no file of the work tree: it
# takes .gitattributes and .gitmodules from the index, and reads no .mailmap there. Such a read is refused
# when TMPDIR lies inside the working directory or cannot hold that directory. git runs with
# --no-pager, and -c pins override the repository's config. They switch off:
#   - programs config can name: core.fsmonitor, core.pager, core.hooksPath (hooks), diff.external,
#     gpg.program, gpg.ssh.program and gpg.x509.program, log.showSignature and format.pretty, and
#     log.diffMerges (a remerge diff runs merge.<driver>.driver);
#   - fetching: the empty transport allowlist above stops lazy fetch and every remote helper on every
#     git version, and the repository's config cannot widen it; protocol.allow=never is only a backstop,
#     since it sets the default that a protocol.<name>.allow in the repository's config overrides;
#   - files outside the tree that config can name and git prints from or parses: core.attributesFile,
#     core.excludesFile, diff.orderFile, mailmap.file;
#   - other repositories: submodule.recurse, diff.submodule;
#   - what a read would hide or replace: grep.patternType and grep.extendedRegexp (how grep and log
#     --grep read a pattern; -E, -F, -G and -P still choose), log.showRoot (the root commit's patch),
#     core.useReplaceRefs (refs/replace), core.commitGraph (its cached parents);
#   - output shaping: colour, core.quotePath, i18n.logOutputEncoding, core.bigFileThreshold.
# --no-textconv --no-ext-diff --ignore-submodules=none go on log, show, diff, diff-tree and reflog show
# (submodule.<name>.ignore, even from .gitmodules, would hide a submodule's new commit), --no-textconv
# --no-ext-diff on blame, and --no-textconv on grep. Clean and smudge filters cannot be pinned by name,
# so no allowed form reads the work tree's content. Re-check the pins and this list against each new git
# release: a new config key that runs a program or reads a file, or that hides or replaces what a read
# shows, reopens what they close. The fixtures in scripts/tests/test-git-ro.sh only prove the keys they set.
# Not pinned, because they shape output but still show every change, or come from content the
# repository carries: diff.renames, diff.renameLimit, diff.context, diff.algorithm and the other diff
# layout keys; a mailmap in the history (a bare copy's HEAD:.mailmap, or the blob mailmap.blob names: it
# renames authors in the default formats; %an and %ae print the commit's own); the index's gitattributes
# binary or -diff and diff.<driver>.binary ("Binary files differ"; add --text or -a); .gitignore and
# info/exclude for ls-files -o --exclude-standard. log -p prints no patch for a merge
# unless asked (--cc, -m, --diff-merges). Reads trust the repository's object store; copy runs every
# object through index-pack, which checks each one's hash.
#
# Output: every control character other than TAB and LF, NUL included, prints as ? in what git prints,
# errors included, so binary content does not round-trip, and a %x00 in a format prints ?. The options
# that only change separators to NUL (-z, --null, cat-file -Z) are refused. Standard input is never read
# except as above. In a partial clone every read prints a note first; nothing is fetched, and a missing
# object fails. In a shallow clone every read notes that older history is missing.
#
# copy runs `clone --no-local --bare --no-recurse-submodules --template=` of <dir> into <R>/src.git
# (src-2.git, src-3.git, ... once that exists) under the same hardened call, with protocol.file.allow
# for that clone and no global config (the clone's upload-pack runs in <dir> without hgit's -c pins, so
# git's ownership check stays on), from a scratch directory outside the working directory. It refuses a
# partial clone (exit 3). A git without the May-2024 clone fixes, CVE-2024-32004 and CVE-2024-32465
# (accepted are 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, 2.46 and later in each line),
# is refused in strict mode (exit 69). In default mode such a git, or a <dir> another user owns, gets the
# same bare copy without clone: pack-objects in <dir>, index-pack in the copy, which checks each object's
# hash, then the branches, tags and HEAD (a note says so for the old git, and every read on it notes the
# git too). It writes <R>/src.git/auditor-copy; read the copy with --git-dir <R>/src.git.
#
# Exit: git's own status (0, 1, 128, ...) · 3 partial clone (partial, copy) · 64 refused · 69 git too
# old to copy (strict mode). Needs bash >= 3.2 and git; env, find, tr, wc, cat, sort, mkdir, mktemp,
# rmdir and rm (and python3 for a run directory that holds a link, in default mode).

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'git-ro: refused: the installation cannot be resolved\n' >&2; exit 64; }
. "$here/lib/confine.sh" || { printf 'git-ro: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
confine_init git-ro "${here%/*}"
confine_need env git find tr wc cat sort mkdir mktemp rmdir rm
WT=$CONFINE_WT
REPO=""

USAGE='usage: git-ro.sh [--repo <dir> | --git-dir <R>/src.git] <subcommand> [<arg>...], or copy <dir> <R>, partial [--repo <dir>], tracked <path>'
FIXES='2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, 2.46 and later'
GIT_VERSION=unknown
DIFF_USAGE='diff compares committed revisions: give A..B, A...B, A^!, A B or --cached [A], and paths after --'
BLAME_USAGE='blame needs <rev> -- <path>: a revision, then --, then one path'
IGNORE_REVS="blame does not run where the repository's config sets blame.ignoreRevsFile; blame a copy (git-ro.sh copy, then --git-dir)"
COPIES=""
# Long options refused with any ending, refused as written, and allowed only with a checked value; an
# abbreviation of any of them is refused, except the four exact options that share a denied name's prefix.
DENY_PREFIX='output exec upload-pack receive-pack git-dir work-tree namespace super-prefix config-env recurse-submodules submodule contents ignore-revs-file exclude-from pathspec-from-file open-files-in-pager'
DENY_EXACT='ext-diff textconv show-signature no-index remote remerge-diff no-cached no-staged null'
GUARDED='format pretty diff-merges'
EXACT_OK='exclude text ignore-rev batch'

refuse() { confine_refuse "$1"; }

refuse_option() { refuse "$SUB does not allow $(confine_text "$1")"; }

# rgit <git arguments>: plain hgit, for a question about the repository read that touches no history
# (rev-parse, ls-files, config, remote, merge-base): in a session below the repository's top level
# (CONFINE_PREFIX), asked in the working directory itself with no ceiling, so git takes and prints paths
# from there, as it does in that directory.
rgit() {
  if [ -n "$CONFINE_PREFIX" ]; then CONFINE_CEILING='' hgit "$WT" "$@"; else hgit "$REPO" "$@"; fi
}

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
    ls-files) EXTRA='modified eol exclude-per-directory' ;;
    cat-file) EXTRA='filters batch-command' ;;
    describe) EXTRA='dirty broken' ;;
    *) EXTRA='' ;;
  esac
  case "$SUB" in
    log|show|diff|diff-tree|reflog) short_deny=Oz short_free=SGIL ;;
    grep) short_deny=Ofz short_free=e ;;
    ls-files) short_deny=mXz short_free=x ;;
    blame) short_deny=Sz short_free=L ;;
    cat-file) short_deny=zZ short_free='' ;;
    *) short_deny=z short_free='' ;;
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
        first=${a#-}
        first=${first%"${first#?}"}
        case "$short_free" in *"$first"*) continue ;; esac
        case "${a#-}" in *["$short_deny"]*) refuse_option "$a" ;; esac ;;
    esac
  done
}

note_history() { # the notes for a partial or a shallow clone
  confine_partial_clone "$REPO" >/dev/null
  case $? in
    0) printf '%s\n' 'git-ro: partial clone: missing objects are not fetched; history and contents may be incomplete (Rule 11c)' >&2 ;;
    2) refuse "git cannot read the repository's config, so a partial clone cannot be ruled out" ;;
  esac
  if [ -e "$CONFINE_COMMON_DIR/shallow" ]; then
    printf '%s\n' 'git-ro: shallow clone: history before the shallow boundary is missing (Rule 11c)' >&2
  fi
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

copy_git_ok() { # status 0 when git has the May-2024 clone fixes; sets GIT_VERSION to what git --version names
  local v maj min pat
  GIT_VERSION=unknown
  v=$(hgit / --version </dev/null 2>/dev/null) || return 1
  v=${v#git version }
  confine_shown "$v"
  GIT_VERSION=$CONFINE_SHOWN
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
  local src rel r dest k scratch rc fixed=1 how=clone
  [ $# -eq 2 ] || refuse "copy takes a repository and a run directory: copy <dir> <R>"
  confine_repo "$1" "copy's repository" 0
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
  copy_git_ok || fixed=0
  if [ "$fixed" -eq 0 ] && [ "$CONFINE_STRICT" = 1 ]; then
    printf 'git-ro: refused: copy needs git with the May-2024 clone fixes: 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, or 2.46 or later\n' >&2
    exit 69
  fi
  # The clone's upload-pack runs in the source with none of hgit's -c pins (git's local transport clears
  # GIT_CONFIG_PARAMETERS for it), so it keeps git's own ownership check: no global config. In default mode
  # a git without the clone fixes, or a source another user owns, gets the copy through plumbing instead.
  if [ "$CONFINE_STRICT" != 1 ] && { [ "$fixed" -eq 0 ] || [ ! -O "$src" ] || [ ! -O "$CONFINE_GIT_DIR" ] || [ ! -O "$CONFINE_COMMON_DIR" ]; }; then
    how=plumbing
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
  if confine_inside "$scratch" "$WT"; then
    rmdir "$scratch" "$WT/$r/$dest"
    refuse "the scratch directory (TMPDIR) lies inside the working directory"
  fi
  if [ "$how" = clone ]; then
    CONFINE_GIT_GLOBAL=/dev/null CONFINE_ALLOW_PROTOCOL=file CONFINE_CEILING=${scratch%/*} hgit "$scratch" -c protocol.file.allow=always \
      clone --no-local --bare --no-recurse-submodules --template= -- "$src" "$WT/$r/$dest" </dev/null
    rc=$?
  else
    copy_plumbing "$src" "$WT/$r/$dest" "$scratch"
    rc=$?
  fi
  rmdir "$scratch"
  if [ "$rc" -ne 0 ]; then
    [ "$how" = clone ] || rm -rf -- "$WT/$r/$dest"
    rmdir "$WT/$r/$dest" 2>/dev/null
    exit "$rc"
  fi
  confine_new_file "$WT/$r/$dest/auditor-copy" "auditor-copy: made by git-ro.sh copy from $rel"$'\n' ||
    refuse "cannot write $r/$dest/auditor-copy"
  [ "$fixed" -eq 1 ] ||
    confine_note "this git ($GIT_VERSION) has none of the May-2024 clone fixes for its release line ($FIXES), so copy made $r/$dest from git's plumbing instead of cloning (pack-objects in the source, index-pack in the copy); strict mode refuses this (Rule 11f)"
  printf '%s\n' "$r/$dest"
  exit 0
}

# copy_plumbing <source top level> <empty destination> <scratch directory>: the bare copy clone --bare
# would make, made without clone, a transport or upload-pack: git init --bare with no template in the
# destination; the objects every branch and tag and HEAD reach, packed by pack-objects in the source and
# indexed by index-pack in the copy, which checks each object's hash; then the branches, the tags, HEAD,
# and the shallow file, when the source has one. Each call is hardened (hgit), none opens a work tree,
# and each runs in the scratch directory, the source or the copy. Status: git's own when a step fails.
copy_plumbing() {
  local src=$1 dest=$2 scratch=$3 fmt line ref head refs="" tips="" rc
  local -a st=()
  fmt=$(hgit "$src" rev-parse --show-object-format </dev/null 2>/dev/null) || fmt=sha1
  case "$fmt" in sha256) ;; *) fmt=sha1 ;; esac
  if [ "$fmt" = sha1 ]; then
    CONFINE_CEILING=${scratch%/*} hgit "$scratch" -c init.defaultBranch=main init -q --bare --template= "$dest" </dev/null >/dev/null || return
  else
    CONFINE_CEILING=${scratch%/*} hgit "$scratch" -c init.defaultBranch=main init -q --bare --template= --object-format="$fmt" "$dest" </dev/null >/dev/null || return
  fi
  refs=$(hgit "$src" for-each-ref --format='%(objectname) %(refname)' refs/heads refs/tags </dev/null) || return
  # Split on line ends, not read from a here-document, which bash 3.2 writes to a file in the working
  # directory when it finds no TMPDIR it can write to. Ref names hold no blank or line end.
  IFS=$'\n'
  set -f
  for line in $refs; do tips=$tips${line%% *}$'\n'; done
  set +f
  IFS=$' \t\n'
  head=$(hgit "$src" rev-parse --verify --quiet HEAD </dev/null) && tips=$tips$head$'\n'
  if [ -n "$tips" ]; then
    printf '%s' "$tips" | hgit "$src" pack-objects --revs --stdout -q | hgit "$dest" index-pack --stdin >/dev/null
    st=("${PIPESTATUS[@]}")
    for rc in "${st[@]}"; do [ "$rc" -eq 0 ] || return "$rc"; done
  fi
  if [ -e "$CONFINE_COMMON_DIR/shallow" ]; then
    confine_new_copy "$CONFINE_COMMON_DIR/shallow" "$dest/shallow" || return 1
  fi
  if [ -n "$refs" ]; then
    ( IFS=$'\n'
      set -f
      for line in $refs; do printf 'create %s %s\n' "${line#* }" "${line%% *}"; done ) | hgit "$dest" update-ref --stdin || return
  fi
  if ref=$(hgit "$src" symbolic-ref -q HEAD </dev/null); then
    hgit "$dest" symbolic-ref HEAD "$ref" </dev/null || return
  elif [ -n "$head" ]; then
    hgit "$dest" update-ref --no-deref HEAD "$head" </dev/null || return
  fi
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
      *:--show-origin|*:--show-scope|*:--name-only|*:--local|*:--no-includes)
        opts+=("$1") ;;
      *:-z|*:--null) refuse "config does not allow $1" ;;
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
    rgit config --local --no-includes ${opts[@]+"${opts[@]}"} "$action" ${pos[@]+"${pos[@]}"} </dev/null
  else
    rgit config "$form" --local --no-includes ${opts[@]+"${opts[@]}"} ${pos[@]+"${pos[@]}"} </dev/null
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
  rgit config --local --no-includes -z --get-regexp '^remote\..*\.(url|pushurl)$' </dev/null |
    remote_table "$mode" "$name" "$all" "$push"
  st=("${PIPESTATUS[@]}")
  [ "${st[0]}" -le 1 ] || exit "${st[0]}"
  exit "${st[1]}"
}

# one_object <word> <type>: sets OID to the full id of the one object <word> names, peeled to <type>
# (commit, tree, or object for any); status 1 when it names none, more than one (A..B, A^@, A^-) or a
# negation (^A, which rev-parse prints as ^<id>). git resolves the word; only its plain answer counts.
one_object() {
  local o
  o=$(rgit rev-parse --verify --quiet --end-of-options "$1" 2>/dev/null </dev/null) && is_oid "$o" &&
    o=$(rgit rev-parse --verify --quiet "$o^{$2}" 2>/dev/null </dev/null) && is_oid "$o" || return 1
  OID=$o
}

is_oid() { # is_oid <s>: status 0 for a full object id, 40 or 64 lowercase hex digits
  case "$1" in ''|*[!0-9a-f]*) return 1 ;; esac
  [ "${#1}" -eq 40 ] || [ "${#1}" -eq 64 ]
}

diff_side() { # diff_side <word> <commit|tree>: one_object, or refuse
  one_object "$1" "$2" ||
    refuse "diff compares committed revisions (A..B, A...B, A^!, A B or --cached [A]), and this names no single $2: $(confine_text "$1")"
}

# run_diff <arg>...: the revisions are the last one or two words before -- that are not options (one
# when it is A..B, A...B or A^!). git-ro resolves the two sides to trees and hands git only their ids,
# behind --end-of-options and ended with --. Given two trees, git diff compares them, whatever else the
# words say: other words can add trees or blobs (git then refuses or shows a combined diff), never take
# one away, so the index and the work tree stay unread. --cached [A] compares the index with A (HEAD by
# default); with --cached git reads no file of the work tree either.
run_diff() {
  local a seen=0 cached=0 i last=-1 prev=-1 w l r ca cb tl tr bases parents
  local -a pre=() post=() opts=() rest=()
  for a in "$@"; do
    if [ "$seen" -eq 0 ] && [ "$a" = -- ]; then seen=1; continue; fi
    if [ "$seen" -eq 0 ]; then pre+=("$a"); else post+=("$a"); fi
  done
  check_options diff ${pre[@]+"${pre[@]}"}
  for a in ${pre[@]+"${pre[@]}"}; do
    case "$a" in --cached|--staged) cached=1 ;; *) opts+=("$a") ;; esac
  done
  if [ "$cached" -eq 1 ]; then
    hgit_tree "$REPO" diff --no-textconv --no-ext-diff --ignore-submodules=none --cached ${opts[@]+"${opts[@]}"} -- ${post[@]+"${post[@]}"} </dev/null
    exit $?
  fi
  for a in ${opts[@]+"${opts[@]}"}; do
    [ "$a" != --merge-base ] || refuse "diff --merge-base A B is written A...B here: git-ro gives git trees, which have no merge base"
  done
  i=0
  while [ "$i" -lt "${#opts[@]}" ]; do
    case "${opts[$i]}" in -*) ;; *) prev=$last; last=$i ;; esac
    i=$((i + 1))
  done
  [ "$last" -ge 0 ] || refuse "$DIFF_USAGE"
  w=${opts[$last]}
  case "$w" in
    *..*)
      prev=-1
      l=${w%%..*}
      r=${w#*..}
      [ -n "$l" ] || l=HEAD
      case "$r" in
        .*) # A...B: from the merge base of A and B (the first, as git diff takes it) to B
          r=${r#.}
          [ -n "$r" ] || r=HEAD
          diff_side "$l" commit; ca=$OID
          diff_side "$r" commit; cb=$OID
          bases=$(rgit merge-base --all "$ca" "$cb" </dev/null)
          case $? in
            0) ;;
            1) printf 'fatal: %s...%s: no merge base\n' "$l" "$r" >&2; exit 128 ;;
            *) exit 128 ;;
          esac
          case "$bases" in
            *$'\n'*) printf 'warning: %s...%s: multiple merge bases, using %s\n' "$l" "$r" "${bases%%$'\n'*}" >&2 ;;
          esac
          diff_side "${bases%%$'\n'*}" tree; tl=$OID
          diff_side "$cb" tree; tr=$OID ;;
        *) # A..B
          [ -n "$r" ] || r=HEAD
          diff_side "$l" tree; tl=$OID
          diff_side "$r" tree; tr=$OID ;;
      esac ;;
    *'^!') # A^!: from A's first parent to A; a commit without one (a root, or cut off by .git/shallow)
      # starts from the empty tree
      prev=-1
      diff_side "${w%'^!'}" commit; ca=$OID
      parents=$(rgit rev-parse "$ca^@" </dev/null) || exit 128
      if [ -n "$parents" ]; then
        diff_side "${parents%%$'\n'*}" tree
      else
        a=$(rgit hash-object -t tree /dev/null </dev/null) && is_oid "$a" || exit 128
        OID=$a
      fi
      tl=$OID
      diff_side "$ca" tree; tr=$OID ;;
    *)
      [ "$prev" -ge 0 ] || refuse "$DIFF_USAGE"
      diff_side "${opts[$prev]}" tree; tl=$OID
      diff_side "$w" tree; tr=$OID ;;
  esac
  i=0
  while [ "$i" -lt "${#opts[@]}" ]; do
    [ "$i" -eq "$last" ] || [ "$i" -eq "$prev" ] || rest+=("${opts[$i]}")
    i=$((i + 1))
  done
  hgit_tree "$REPO" diff --no-textconv --no-ext-diff --ignore-submodules=none ${rest[@]+"${rest[@]}"} --end-of-options "$tl" "$tr" \
    -- ${post[@]+"${post[@]}"} </dev/null
  exit $?
}

blame_short() { # blame_short <word>: status 0 for a cluster of blame's short flags (b c e f l n p s t w, M and C with an optional number)
  local r=${1#-} c
  [ -n "$r" ] || return 1
  while [ -n "$r" ]; do
    c=${r%"${r#?}"}
    r=${r#?}
    case "$c" in
      [bceflnpstw]) ;;
      M|C) while :; do case "$r" in [0-9]*) r=${r#?} ;; *) break ;; esac; done ;;
      *) return 1 ;;
    esac
  done
}

# blame_options <word>...: refuse any word but blame's own options and the value that follows -L, --date,
# --ignore-rev, --since, --after, --until or --before. None of them names or negates a revision, so the
# one commit git-ro resolved stays the commit blame starts from. A revision word (^A, A..B) or a ref
# option (--not --all) could mark that commit uninteresting, and blame with no commit left to start
# from annotates the work tree.
blame_options() {
  local a
  while [ $# -gt 0 ]; do
    a=$1
    case "$a" in
      -L|--date|--ignore-rev|--since|--after|--until|--before)
        [ $# -ge 2 ] || refuse "blame's $a needs a value"
        shift ;;
      -L?*|--date=*|--ignore-rev=*|--since=*|--after=*|--until=*|--before=*|--encoding=*|--abbrev=*) ;;
      --root|--show-stats|--reverse|--first-parent|--porcelain|--line-porcelain|--incremental|--progress|--no-progress|\
      --score-debug|--show-name|--show-number|--show-email|--minimal|--color-lines|--color-by-age|--abbrev) ;;
      -?*) blame_short "$a" || refuse_option "$a" ;;
      *) refuse "$BLAME_USAGE; only options may come before the revision, not $(confine_text "$a")" ;;
    esac
    shift
  done
}

# run_blame [<options>] <rev> -- <path>: <rev>, or A..B, resolved to commits first. With A..B the two
# must differ: one commit as both ends is uninteresting, and blame would fall back to the work tree.
run_blame() {
  local a i=0 dd=-1 rev path l r spec
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
  blame_options ${opts[@]+"${opts[@]}"}
  case "$rev" in
    *...*) refuse "blame takes one revision, or A..B with --reverse, not $(confine_text "$rev")" ;;
    *..*)
      l=${rev%%..*}
      r=${rev#*..}
      [ -n "$l" ] || l=HEAD
      [ -n "$r" ] || r=HEAD
      one_object "$l" commit || refuse "blame needs commits, and this names no single commit: $(confine_text "$l")"
      spec=$OID
      one_object "$r" commit || refuse "blame needs commits, and this names no single commit: $(confine_text "$r")"
      [ "$OID" != "$spec" ] || refuse "blame's A..B needs two different commits: $(confine_text "$rev")"
      spec=$spec..$OID ;;
    *)
      one_object "$rev" commit || refuse "blame needs a commit, and this names no single commit: $(confine_text "$rev")"
      spec=$OID ;;
  esac
  rgit config --get-all blame.ignorerevsfile >/dev/null 2>&1
  case $? in
    1) ;;
    0) ignore_revs_copies ;;
    *) refuse "git cannot read the repository's config" ;;
  esac
  CONFINE_TREE_COPY=$COPIES hgit_tree "$REPO" blame --no-textconv --no-ext-diff "$spec" ${opts[@]+"${opts[@]}"} -- "$path" </dev/null
  exit $?
}

# ignore_revs_copies: for a repository whose config sets blame.ignoreRevsFile, which no command-line value
# resets, sets COPIES (CONFINE_TREE_COPY's lines) so git finds each file it names in its empty work tree,
# where it looks for a relative one. In default mode (Rule 11f) each value must be a relative path, with
# no empty, . or .. component and no link on the way, to a regular file of one link and at most 1 MiB in
# the repository's work tree; anything else, a bare repository, and strict mode keep the refusal.
ignore_revs_copies() {
  local v d rest c size
  local -a vals=()
  COPIES=""
  [ "$CONFINE_STRICT" != 1 ] && [ "$CONFINE_BARE" = false ] || refuse "$IGNORE_REVS"
  while IFS= read -r -d '' v; do vals+=("$v"); done < <(rgit config -z --get-all blame.ignorerevsfile 2>/dev/null </dev/null)
  [ "${#vals[@]}" -gt 0 ] || refuse "$IGNORE_REVS"
  for v in "${vals[@]}"; do
    case "$v" in ''|/*|'~'*|'%(prefix)/'*|-*|*[[:cntrl:]]*) refuse "$IGNORE_REVS" ;; esac
    case "/$v/" in *//*|*/./*|*/../*) refuse "$IGNORE_REVS" ;; esac
    [ "${#v}" -le 1024 ] || refuse "$IGNORE_REVS"
    d=$REPO rest=$v
    while :; do
      c=${rest%%/*}
      d=$d/$c
      [ ! -L "$d" ] || refuse "$IGNORE_REVS"
      case "$rest" in */*) [ -d "$d" ] || refuse "$IGNORE_REVS"; rest=${rest#*/} ;; *) break ;; esac
    done
    confine_one_link "$d" || refuse "$IGNORE_REVS"
    size=$(wc -c < "$d" 2>/dev/null) || refuse "$IGNORE_REVS"
    size=${size//[!0-9]/}
    [ -n "$size" ] && [ "$size" -le 1048576 ] || refuse "$IGNORE_REVS"
    COPIES=$COPIES$v$'\t'$d$'\n'
  done
}

# run_grep <arg>...: the words read the way git grep reads them. Options come first, up to the first word
# that is not one, or --, or --end-of-options; -e, -f, -A, -B, -C and -m (and --max-depth, --threads,
# --context, --after-context, --before-context and --max-count) take the rest of the word or the next
# one. When no -e, --and, --not, ( or ) came, the next word (after one --) is the pattern. What follows
# are revisions up to --, then paths; without --, revisions until the first word that is not one.
# git-ro resolves the revisions itself. With none, git searches the index (--cached) and the remaining
# words go to it as given. With some, git gets the options, the pattern as -e, and exactly those
# revisions behind --end-of-options and ended with --, so it searches them and nothing else; a path
# without -- after them is refused, since only a -- keeps git from reading a revision as a path. Neither
# form reads the work tree, and nothing depends on what git prints.
run_grep() {
  local a c rest n i=0 j dd=-1 havepat=0 pat=""
  local -a args=("$@") optw=() trees=() paths=() tail=()
  check_options grep "$@"
  n=$#
  while [ "$i" -lt "$n" ]; do
    a=${args[$i]}
    case "$a" in
      --) break ;;
      --end-of-options) i=$((i + 1)); break ;;
      '('|')'|--and|--not) havepat=1; optw+=("$a") ;;
      --max-depth|--threads|--context|--after-context|--before-context|--max-count)
        optw+=("$a")
        i=$((i + 1))
        [ "$i" -ge "$n" ] || optw+=("${args[$i]}") ;;
      --?*) optw+=("$a") ;;
      -?*)
        optw+=("$a")
        rest=${a#-}
        while [ -n "$rest" ]; do
          c=${rest%"${rest#?}"}
          rest=${rest#?}
          case "$c" in
            e|f|A|B|C|m)
              case "$c" in e|f) havepat=1 ;; esac
              if [ -z "$rest" ]; then
                i=$((i + 1))
                [ "$i" -ge "$n" ] || optw+=("${args[$i]}")
              fi
              break ;;
            O) break ;;
          esac
        done ;;
      *) break ;;
    esac
    i=$((i + 1))
  done
  if [ "$havepat" -eq 0 ]; then
    if [ "$i" -lt "$n" ] && [ "${args[$i]}" = -- ]; then i=$((i + 1)); fi
    if [ "$i" -lt "$n" ]; then pat=${args[$i]}; havepat=2; i=$((i + 1)); fi
  fi
  j=$i
  while [ "$j" -lt "$n" ]; do
    [ "${args[$j]}" != -- ] || { dd=$j; break; }
    j=$((j + 1))
  done
  j=$i
  while [ "$j" -lt "$n" ]; do
    a=${args[$j]}
    [ "$a" != -- ] || break
    if one_object "$a" object; then
      trees+=("$a")
    elif [ "$dd" -ge 0 ] || [ "${#trees[@]}" -gt 0 ]; then
      if [ "$dd" -lt 0 ]; then refuse "grep searches these revisions, so give paths after --: $(confine_text "$a")"; fi
      trees=()
      break
    else
      break
    fi
    j=$((j + 1))
  done
  [ "$havepat" -ne 2 ] || optw+=(-e "$pat")
  if [ "${#trees[@]}" -eq 0 ]; then
    [ "$i" -ge "$n" ] || tail=("${args[@]:$i}")
    hgit_tree "$REPO" grep --no-textconv --cached ${optw[@]+"${optw[@]}"} --end-of-options ${tail[@]+"${tail[@]}"} </dev/null
    exit $?
  fi
  [ "$dd" -lt 0 ] || [ $((dd + 1)) -ge "$n" ] || paths=("${args[@]:$((dd + 1))}")
  hgit_tree "$REPO" grep --no-textconv ${optw[@]+"${optw[@]}"} --end-of-options "${trees[@]}" -- ${paths[@]+"${paths[@]}"} </dev/null
  exit $?
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
  if [ -n "$gitdir" ]; then open_copy "$gitdir"; else confine_repo "$repo" "$what" 0; fi
  REPO=$CONFINE_REPO
  [ "$CONFINE_STRICT" = 1 ] || copy_git_ok ||
    confine_note "this git ($GIT_VERSION) has none of the May-2024 clone fixes for its release line ($FIXES); git-ro's reads clone nothing, and copy makes its copy from git's plumbing instead of cloning (Rule 11f)"
  case "$sub" in
    partial) run_partial ;;
    config) run_config "$@" ;;
    remote) run_remote "$@" ;;
  esac
  note_history
  case "$sub" in
    diff) run_diff "$@" ;;
    blame) run_blame "$@" ;;
    grep) run_grep "$@" ;;
    reflog)
      [ "${1-}" = show ] || refuse "reflog only reads: reflog show [<options>] [<ref>]"
      shift
      check_options reflog "$@"
      hgit_tree "$REPO" reflog show --no-textconv --no-ext-diff --ignore-submodules=none "$@" </dev/null ;;
    log|show|diff-tree)
      check_options "$sub" "$@"
      hgit_tree "$REPO" "$sub" --no-textconv --no-ext-diff --ignore-submodules=none "$@" </dev/null ;;
    cat-file)
      check_options cat-file "$@"
      for a in "$@"; do
        [ "$a" != -- ] || break
        case "$a" in --batch|--batch=*|--batch-check|--batch-check=*) batch=1 ;; esac
      done
      if [ "$batch" -eq 1 ]; then hgit_tree "$REPO" cat-file "$@"; else hgit_tree "$REPO" cat-file "$@" </dev/null; fi ;;
    rev-parse|ls-files)
      check_options "$sub" "$@"
      rgit "$sub" "$@" </dev/null ;;
    *)
      check_options "$sub" "$@"
      hgit_tree "$REPO" "$sub" "$@" </dev/null ;;
  esac
  exit $?
}

# What git prints, errors included, goes out with every control character but TAB and LF, NUL too, as ?.
CTRL='\000-\010\013-\037\177'
{ main "$@" 2>&1 1>&3 3>&- | tr "$CTRL" '?' 1>&2 3>&-; } 3>&1 | tr "$CTRL" '?'
