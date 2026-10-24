# confine.sh — shared confinement checks for the bundled entry points (scripts/git-ro.sh,
# scripts/rundir.sh). Sourced, never run. Every check fails closed: one that cannot run is a refusal,
# printed as the one stderr line "<tool>: refused: <reason>", with exit 64.
#
# WT is the physical working directory, taken once by confine_init.
#   - A confined path is relative, non-empty, at most 1024 bytes and free of control characters. It
#     does not start with "-" or "~", has no empty, "." or ".." component once one leading "./" is
#     dropped, passes through no symbolic link and resolves inside WT. An existing final object is a
#     regular file or a directory.
#   - A run directory is audit_<n> or incident_<n> (n of 1 to 6 digits): a real directory directly in
#     WT, holding no symbolic link, tracked by no repository in any letter case, whose .gitignore holds
#     exactly "*".
#   - A new file is created with noclobber and written through the descriptor opened at creation; a
#     new directory is created with plain mkdir, never -p.
# confine_init also sets LC_ALL=C and umask 077 and unsets CDPATH, BASH_ENV and ENV. It refuses an
# installation root that holds a quote, "$", a backtick, a backslash or a control character, since the
# quoted call could not match as written, or that lies inside WT (Rule 11e). PATH keeps only absolute
# entries that resolve outside WT.
# hgit is the hardened git call of OUTPUT-RULES.md Rule 11c. scripts/git-ro.sh's header lists what its
# -c pins switch off and when to re-check them; keep the two in step.
# Needs bash >= 3.2 and, on the cleaned PATH, env, git, find, wc and cat.

confine_refuse() { # confine_refuse <reason>: the refusal line, then exit 64
  printf '%s: refused: %s\n' "${CONFINE_TOOL:-confine}" "$1" >&2
  exit 64
}

confine_shown() { # confine_shown <s>: sets CONFINE_SHOWN to <s> for a message: control characters as ?, cut after 200 bytes
  CONFINE_SHOWN=${1//[[:cntrl:]]/?}
  if [ "${#CONFINE_SHOWN}" -gt 200 ]; then CONFINE_SHOWN="${CONFINE_SHOWN:0:200}..."; fi
}

confine_text() { # confine_text <s>: prints <s> as confine_shown sets it
  confine_shown "$1"
  printf '%s' "$CONFINE_SHOWN"
}

# confine_phys <dir>: sets CONFINE_PHYS to <dir> with every symbolic link resolved, then goes back to WT;
# status 1 when <dir> cannot be entered.
confine_phys() {
  local rc=0
  if cd -P -- "$1" 2>/dev/null; then CONFINE_PHYS=$PWD; else rc=1; fi
  cd -- "$CONFINE_WT" 2>/dev/null || confine_refuse "the working directory cannot be entered again"
  return "$rc"
}

confine_init() { # confine_init <tool> <installation root, physical>
  local root=$2 rest e clean=""
  CONFINE_TOOL=$1
  IFS=$' \t\n'
  unset CDPATH BASH_ENV ENV
  LC_ALL=C
  export LC_ALL
  umask 077
  case "$root" in
    ''|*'"'*|*'$'*|*'`'*|*'\'*|*[[:cntrl:]]*)
      confine_refuse "the installation path holds a quote, \$, a backtick, a backslash or a control character, so its quoted call cannot match as written" ;;
  esac
  cd -P . 2>/dev/null || confine_refuse "the working directory cannot be resolved"
  CONFINE_WT=$PWD
  case "$CONFINE_WT" in
    /*) ;;
    *) confine_refuse "the working directory cannot be resolved" ;;
  esac
  case "$CONFINE_WT" in *[[:cntrl:]]*) confine_refuse "the working directory path holds a control character" ;; esac
  case "$root/" in
    "${CONFINE_WT%/}/"*) confine_refuse "the installation lies inside the working directory; install it outside the tree under audit (Rule 11e)" ;;
  esac
  rest="${PATH-}:"
  while [ -n "$rest" ]; do
    e=${rest%%:*}
    rest=${rest#*:}
    case "$e" in /*) ;; *) continue ;; esac
    confine_phys "$e" || continue
    case "$CONFINE_PHYS" in *[[:cntrl:]]*) continue ;; esac
    case "$CONFINE_PHYS/" in "${CONFINE_WT%/}/"*) continue ;; esac
    clean=${clean:+$clean:}$CONFINE_PHYS
  done
  [ -n "$clean" ] || confine_refuse "no PATH entry is left outside the working directory"
  PATH=$clean
  export PATH
  hash -r
  CONFINE_ROOT=$root
  CONFINE_CEILING=${CONFINE_WT%/*}
  [ -n "$CONFINE_CEILING" ] || CONFINE_CEILING=/
}

confine_need() { # confine_need <program>...: refuse unless each is on the cleaned PATH
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || confine_refuse "$c is not on PATH"
  done
}

# ---- git (OUTPUT-RULES.md Rule 11c) --------------------------------------------------------------------
# hgit <dir> <git arguments>: git in <dir> with only the environment below, and the -c pins over the
# repository's own config: what it runs, what it fetches, the files it reads, and how it reads history
# and patterns (grep.patternType, log.showRoot, replace refs, the commit-graph cache).
# GIT_CEILING_DIRECTORIES stops discovery at WT's parent unless the caller sets CONFINE_CEILING for one
# call. GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS makes git refuse abbreviated long options where its option
# parser checks it; git-ro.sh refuses them on its own as well.
hgit() {
  local d=$1
  shift
  env -i ${HOME+"HOME=$HOME"} PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" LC_ALL=C TZ="${TZ:-UTC}" \
    GIT_NO_LAZY_FETCH=1 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 \
    GIT_OPTIONAL_LOCKS=0 GIT_CEILING_DIRECTORIES="$CONFINE_CEILING" GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS=true \
    git --no-pager -C "$d" \
    -c core.fsmonitor=false -c core.pager=cat -c core.hooksPath=/dev/null -c core.untrackedCache=false \
    -c log.showSignature=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false \
    -c protocol.allow=never -c diff.external= -c core.bigFileThreshold=512m \
    -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null -c diff.orderFile=/dev/null \
    -c mailmap.file=/dev/null -c color.ui=never -c color.diff=never -c color.grep=never \
    -c color.decorate=never -c core.quotePath=false -c i18n.logOutputEncoding=UTF-8 -c format.pretty=medium \
    -c log.diffMerges=separate -c submodule.recurse=false -c diff.submodule=short \
    -c grep.patternType=basic -c grep.extendedRegexp=false -c log.showRoot=true \
    -c core.useReplaceRefs=false -c core.commitGraph=false "$@"
}

# confine_repo_top <dir>: status 0 when <dir> (absolute) is the top level of its own repository, or a
# bare repository itself, compared with symbolic links resolved on both sides. A directory inside
# another repository fails, so that repository is never read in its place.
confine_repo_top() {
  local top here
  if [ "$(hgit "$1" rev-parse --is-bare-repository 2>/dev/null)" = true ]; then
    top=$(hgit "$1" rev-parse --absolute-git-dir 2>/dev/null) || return 1
  else
    top=$(hgit "$1" rev-parse --show-toplevel 2>/dev/null) || return 1
  fi
  [ -n "$top" ] && confine_phys "$1" || return 1
  here=$CONFINE_PHYS
  confine_phys "$top" && [ "$CONFINE_PHYS" = "$here" ]
}

# confine_partial_clone <dir>: status 0 for a partial clone (extensions.partialClone, or a
# remote.<name>.promisor key; the keys go to stdout), where reading a missing object would fetch it from
# the promisor remote; 1 for none; 2 when git cannot read the config. Reading config runs nothing.
confine_partial_clone() {
  local keys rc
  keys=$(hgit "$1" config --get-regexp '^(extensions\.partialclone|remote\..*\.promisor)$' 2>/dev/null)
  rc=$?
  if [ "$rc" -eq 0 ] && [ -n "$keys" ]; then
    printf '%s\n' "$keys"
    return 0
  fi
  if [ "$rc" -le 1 ]; then return 1; fi
  return 2
}

# confine_repo <dir> <what>: refuse <dir> (. for WT, or a confined directory) unless it is the top level
# of a repository, or a bare repository, whose git directory and common directory resolve inside WT,
# hold no symbolic link, borrow no objects (objects/info/alternates) and rewrite no commit's parents
# (info/grafts). Sets CONFINE_REPO (its physical path), CONFINE_GIT_DIR, CONFINE_COMMON_DIR and
# CONFINE_BARE (true or false).
confine_repo() {
  local what=$2 shown abs info bare gitdir common top d links
  confine_shown "$1"
  shown=$CONFINE_SHOWN
  confine_path "$1" "$what" dir
  if [ "$CONFINE_REL" = . ]; then abs=$CONFINE_WT; else abs=$CONFINE_WT/$CONFINE_REL; fi
  confine_phys "$abs" || confine_refuse "$what cannot be resolved: $shown"
  abs=$CONFINE_PHYS
  # One call where there is a work tree; a bare repository has no top level, so it takes a second.
  if info=$(hgit "$abs" rev-parse --is-bare-repository --absolute-git-dir --git-common-dir --show-toplevel 2>/dev/null); then
    top=${info##*$'\n'}
    info=${info%$'\n'*}
  else
    info=$(hgit "$abs" rev-parse --is-bare-repository --absolute-git-dir --git-common-dir 2>/dev/null) ||
      confine_refuse "$what is not a git repository that git can read (none there, or another user owns it: audit a copy): $shown"
    top=""
  fi
  bare=${info%%$'\n'*}
  info=${info#*$'\n'}
  gitdir=${info%%$'\n'*}
  common=${info#*$'\n'}
  case "$bare" in
    true) top=$gitdir ;;
    false) ;;
    *) confine_refuse "git cannot describe the repository at $what: $shown" ;;
  esac
  [ -n "$top" ] && confine_phys "$top" && [ "$CONFINE_PHYS" = "$abs" ] ||
    confine_refuse "$what is not the top level of its repository: $shown"
  case "$common" in /*) ;; *) common=$abs/$common ;; esac
  confine_phys "$gitdir" || confine_refuse "$what has a git directory that cannot be resolved: $shown"
  gitdir=$CONFINE_PHYS
  confine_phys "$common" || confine_refuse "$what has a git directory that cannot be resolved: $shown"
  common=$CONFINE_PHYS
  for d in "$gitdir" "$common"; do
    case "$d/" in
      "${CONFINE_WT%/}/"*) ;;
      *) confine_refuse "$what keeps its git directory outside the working directory: $shown" ;;
    esac
    links=$(find "$d" -type l -print 2>/dev/null) || confine_refuse "$what has a git directory that find cannot fully read: $shown"
    [ -z "$links" ] || confine_refuse "$what has a symbolic link in its git directory: $shown"
    [ "$common" != "$gitdir" ] || break
  done
  if [ -e "$common/objects/info/alternates" ]; then
    confine_refuse "$what borrows objects from another repository (objects/info/alternates); audit a full copy: $shown"
  fi
  if [ -e "$common/info/grafts" ]; then
    confine_refuse "$what rewrites commit parents (info/grafts), so git would show another history; review that file: $shown"
  fi
  CONFINE_REPO=$abs
  CONFINE_GIT_DIR=$gitdir
  CONFINE_COMMON_DIR=$common
  CONFINE_BARE=$bare
}

# confine_tracked <path>: print what git tracks at <path> (relative to WT, in any letter case) and
# return 0, or return 2 when git cannot tell. Outside every repository nothing is tracked. Discovery
# may go above WT for this one question, since a repository there decides it; only paths at <path>
# are printed.
confine_tracked() {
  local err
  if ! err=$(CONFINE_CEILING='' hgit "$CONFINE_WT" rev-parse --is-inside-work-tree 2>&1 >/dev/null); then
    case "$err" in *'not a git repository'*) return 0 ;; esac
    return 2
  fi
  CONFINE_CEILING='' hgit "$CONFINE_WT" --icase-pathspecs ls-files -- ":(literal,icase)$1" 2>/dev/null || return 2
}

# ---- paths ---------------------------------------------------------------------------------------------
# confine_path <path> <what> <want>: refuse <path> unless it is a confined path of the kind <want> names:
# dir (an existing directory; "." is WT itself), new (nothing there yet) or any (absent, a regular file
# or a directory). Sets CONFINE_REL (the path without a leading ./) and CONFINE_TYPE (dir, file or none).
confine_path() {
  local p=$1 what=$2 want=$3 shown rest cur comp d
  confine_shown "$p"
  shown=$CONFINE_SHOWN
  if [ "$p" = . ] && [ "$want" = dir ]; then
    CONFINE_REL=. CONFINE_TYPE=dir
    return 0
  fi
  [ -n "$p" ] || confine_refuse "$what is empty"
  [ "${#p}" -le 1024 ] || confine_refuse "$what is longer than 1024 bytes"
  case "$p" in *[[:cntrl:]]*) confine_refuse "$what holds a control character: $shown" ;; esac
  case "$p" in
    /*) confine_refuse "$what must be relative to the working directory: $shown" ;;
    -*|'~'*) confine_refuse "$what may not start with - or ~: $shown" ;;
  esac
  p=${p#./}
  case "/$p/" in *//*|*/./*|*/../*) confine_refuse "$what has an empty, . or .. component: $shown" ;; esac
  rest=$p
  cur=$CONFINE_WT
  CONFINE_TYPE=none
  while :; do
    comp=${rest%%/*}
    cur=$cur/$comp
    [ ! -L "$cur" ] || confine_refuse "$what passes through a symbolic link: $shown"
    [ -e "$cur" ] || break
    case "$rest" in
      */*)
        [ -d "$cur" ] || confine_refuse "$what has a component that is not a directory: $shown"
        rest=${rest#*/} ;;
      *)
        if [ -d "$cur" ]; then CONFINE_TYPE=dir
        elif [ -f "$cur" ]; then CONFINE_TYPE=file
        else confine_refuse "$what is not a regular file or a directory: $shown"
        fi
        break ;;
    esac
  done
  if [ "$CONFINE_TYPE" = dir ]; then d=$cur; else d=${cur%/*}; fi
  confine_phys "$d" || confine_refuse "$what cannot be resolved: $shown"
  case "$CONFINE_PHYS/" in
    "${CONFINE_WT%/}/"*) ;;
    *) confine_refuse "$what resolves outside the working directory: $shown" ;;
  esac
  case "$want" in
    dir) [ "$CONFINE_TYPE" = dir ] || confine_refuse "$what is not an existing directory: $shown" ;;
    new) [ "$CONFINE_TYPE" = none ] || confine_refuse "$what already exists: $shown" ;;
  esac
  CONFINE_REL=$p
}

confine_rundir_name() { # confine_rundir_name <name>: status 0 for audit_<n> or incident_<n>, n of 1 to 6 digits
  local n
  case "$1" in
    audit_*|incident_*) n=${1#*_} ;;
    *) return 1 ;;
  esac
  case "$n" in ''|*[!0-9]*) return 1 ;; esac
  [ "${#n}" -le 6 ]
}

confine_ignore_all() { # confine_ignore_all <file>: status 0 when <file> is a regular file holding exactly "*" (one newline may follow)
  local size text
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  size=$(wc -c < "$1") || return 1
  size=${size//[!0-9]/}
  case "$size" in 1|2) ;; *) return 1 ;; esac
  text=$(cat -- "$1") || return 1
  [ "$text" = '*' ]
}

# confine_rundir <R> <what>: refuse <R> unless it is a run directory (see the top). Sets CONFINE_RUN to
# its name without a leading ./.
confine_rundir() {
  local r=${1#./} what=$2 shown links listed
  confine_shown "$1"
  shown=$CONFINE_SHOWN
  confine_rundir_name "$r" ||
    confine_refuse "$what must be a run directory named audit_<n> or incident_<n> in the working directory: $shown"
  [ ! -L "$CONFINE_WT/$r" ] || confine_refuse "$what is a symbolic link: $shown"
  [ -d "$CONFINE_WT/$r" ] || confine_refuse "$what is not an existing directory: $shown"
  links=$(find "$CONFINE_WT/$r" -type l -print 2>/dev/null) || confine_refuse "$what cannot be fully read: $shown"
  [ -z "$links" ] || confine_refuse "$what holds a symbolic link: $shown"
  listed=$(confine_tracked "$r") || confine_refuse "git cannot tell whether $what is tracked: $shown"
  [ -z "$listed" ] || confine_refuse "$what is tracked by git: $shown"
  confine_ignore_all "$CONFINE_WT/$r/.gitignore" || confine_refuse "$what has no .gitignore holding exactly *: $shown"
  CONFINE_RUN=$r
}

# ---- writes --------------------------------------------------------------------------------------------
# confine_new_file <path> <text>: create <path>, which must not exist (a symbolic link counts), with
# noclobber, and write <text> through the descriptor opened at creation. Status 1 when it cannot.
confine_new_file() {
  if [ -e "$1" ] || [ -L "$1" ]; then return 1; fi
  ( set -C; exec 9>"$1" && printf '%s' "$2" >&9 ) 2>/dev/null
}

confine_mkdir() { # confine_mkdir <path>: create one directory (never -p); status 1 when it cannot, or a link took its place
  mkdir -- "$1" 2>/dev/null && [ -d "$1" ] && [ ! -L "$1" ]
}
