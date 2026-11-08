# confine.sh — shared confinement checks for the bundled entry points (scripts/git-ro.sh,
# scripts/rundir.sh, scripts/rpc-read.sh, scripts/report-to-pdf.sh, the two collectors and
# scripts/dnr/snapshot-program.sh). Sourced, never run. Every check fails closed: one that cannot run is
# a refusal, printed as the one stderr line "<tool>: refused: <reason>", with exit 64, or with the status
# the tool gave confine_init (the collectors and snapshot-program.sh keep their 2).
#
# WT is the physical working directory, taken once by confine_init, with the names the disk gives it
# (getcwd's: on a case-insensitive or firmlinked volume bash keeps the letters as typed).
#   - A confined path is relative, non-empty, at most 1024 bytes and free of control characters. It
#     does not start with "-" or "~", has no empty, "." or ".." component once one leading "./" is
#     dropped, passes through no symbolic link and resolves inside WT. An existing final object is a
#     regular file or a directory.
#   - A run directory is audit_<n> or incident_<n> (n of 1 to 6 digits): a real directory directly in
#     WT, holding no symbolic link (in default mode, none that resolves outside it), tracked by no
#     repository in any letter case, whose .gitignore holds exactly "*".
#   - A new file is created with noclobber and written through the descriptor opened at creation; a
#     new directory is created with plain mkdir, never -p.
# confine_init also sets LC_ALL=C and umask 077 and unsets CDPATH, BASH_ENV and ENV, and the variables a
# caller sets for one hgit call only (CONFINE_ALLOW_PROTOCOL, CONFINE_GIT_TIME, CONFINE_TREE_COPY). It refuses an
# installation root that holds a quote, "$", a backtick, a backslash or a control character, since the
# quoted call could not match as written, or that lies inside WT (Rule 11e). PATH keeps only absolute
# entries that resolve outside WT and outside the tree WT lies in: the outermost of WT and the directories
# above it, below HOME (to / when WT is not under HOME), that holds a .git of any kind, since the tree can
# put a .git of its own anywhere below its top. Whether a path lies inside a directory is decided by
# identity (device and inode) along its ancestors, never by comparing spellings.
# confine_init then reads the mode (OUTPUT-RULES.md Rule 11f; confine_mode): default, where the checks
# that would refuse a repository for what it contains print a note and go on, or strict, which keeps
# those refusals.
# hgit is the hardened git call of OUTPUT-RULES.md Rule 11c. scripts/git-ro.sh's header lists what its
# -c pins switch off and when to re-check them; keep the two in step.
# A tool that contacts an outside service records it in <R>/disclosures.tsv (OUTPUT-RULES.md Rule 11b;
# the format is at confine_disclose).
# Needs bash >= 3.2 and, on the cleaned PATH, env, git, find, wc and cat (grep, when there, saves a git
# call); confine_scratch needs mktemp, hgit_tree mktemp and rmdir (and /bin/sh after a Ctrl-C; rm for a
# file CONFINE_TREE_COPY places), confine_service sed, confine_disclose date, and confine_b58_bytes and
# confine_links_inside python3.

# confine_refuse <reason>: the refusal line, then exit 64 (or the status confine_init was given). A tool
# may set CONFINE_HINT around a check; the line then ends with "; <hint>". confine_init clears one the
# environment passed in.
confine_refuse() {
  printf '%s: refused: %s%s\n' "${CONFINE_TOOL:-confine}" "$1" "${CONFINE_HINT:+; $CONFINE_HINT}" >&2
  exit "${CONFINE_STATUS:-64}"
}

# Under LC_ALL=C the control characters are the C0 controls and DEL, and every other byte prints as it is;
# confine.rs's shown masks more (bytes that are not UTF-8, the characters its unsafe_char lists), so the
# two print the same for ASCII text, and for other UTF-8 text that holds none of those characters.
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

confine_inside() { # confine_inside <absolute path> <directory>: status 0 when the path is the directory or lies below it
  # Compared by identity (device and inode) up the path's ancestors, not by spelling: on a case-insensitive
  # or firmlinked volume one directory has several spellings.
  local p=$1
  while :; do
    [ "$p" -ef "$2" ] && return 0
    case "$p" in /|'') return 1 ;; esac
    p=${p%/*}
    [ -n "$p" ] || p=/
  done
}

confine_init() { # confine_init <tool> <installation root, physical> [<refusal status, default 64>]
  local root=$2 rest e p top="" clean=""
  CONFINE_TOOL=$1
  CONFINE_STATUS=${3:-64}
  CONFINE_HINT=""
  CONFINE_GIT_CHECKED=$'\n'
  CONFINE_GIT_CHECKING=$'\n'
  CONFINE_TREES=''
  IFS=$' \t\n'
  unset CDPATH BASH_ENV ENV CONFINE_GIT_TIME CONFINE_ALLOW_PROTOCOL CONFINE_TREE_COPY
  LC_ALL=C
  export LC_ALL
  umask 077
  case "$root" in
    ''|*'"'*|*'$'*|*'`'*|*'\'*|*[[:cntrl:]]*)
      confine_refuse "the installation path holds a quote, \$, a backtick, a backslash or a control character, so its quoted call cannot match as written" ;;
  esac
  cd -P . 2>/dev/null || confine_refuse "the working directory cannot be resolved"
  # bash keeps the letters of the path as typed; take the names on disk (getcwd's), as git reports them.
  p=$(/bin/pwd -P 2>/dev/null) && [ -n "$p" ] && [ "$p" -ef . ] && cd -- "$p" 2>/dev/null
  CONFINE_WT=$PWD
  case "$CONFINE_WT" in
    /*) ;;
    *) confine_refuse "the working directory cannot be resolved" ;;
  esac
  case "$CONFINE_WT" in *[[:cntrl:]]*) confine_refuse "the working directory path holds a control character" ;; esac
  if confine_inside "$root" "$CONFINE_WT"; then
    confine_refuse "the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)"
  fi
  # The tree WT lies in: the outermost of WT and the directories above it, below HOME, that holds a .git
  # of any kind. Its tree is under audit as well, so PATH entries inside it are dropped too; a .git the
  # tree puts nearer (an empty one, which git walks past) does not shrink it.
  p=$CONFINE_WT
  while :; do
    if [ -e "$p/.git" ] || [ -L "$p/.git" ]; then top=$p; fi
    [ "$p" != / ] || break
    p=${p%/*}
    [ -n "$p" ] || p=/
    if [ -n "${HOME-}" ] && [ "$p" -ef "$HOME" ]; then break; fi
  done
  rest="${PATH-}:"
  while [ -n "$rest" ]; do
    e=${rest%%:*}
    rest=${rest#*:}
    case "$e" in /*) ;; *) continue ;; esac
    confine_phys "$e" || continue
    case "$CONFINE_PHYS" in *[[:cntrl:]]*) continue ;; esac
    confine_inside "$CONFINE_PHYS" "$CONFINE_WT" && continue
    [ -z "$top" ] || ! confine_inside "$CONFINE_PHYS" "$top" || continue
    clean=${clean:+$clean:}$CONFINE_PHYS
  done
  [ -n "$clean" ] || confine_refuse "no PATH entry is left outside the working directory"
  PATH=$clean
  export PATH
  hash -r
  CONFINE_ROOT=$root
  CONFINE_CEILING=${CONFINE_WT%/*}
  [ -n "$CONFINE_CEILING" ] || CONFINE_CEILING=/
  CONFINE_PREFIX=''
  confine_mode
}

confine_need() { # confine_need <program>...: refuse unless each is on the cleaned PATH
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || confine_refuse "$c is not on PATH"
  done
}

# ---- the mode (OUTPUT-RULES.md Rule 11f) ---------------------------------------------------------------
# Strict mode is on when any of these says so, and nothing in a call turns it off again:
#   - AUDITOR_STRICT: 1, true, yes or on, in any letter case, turn it on; 0, false, no, off, empty and
#     unset leave it off; any other value turns it on, with the note "AUDITOR_STRICT is '<v>', read as on";
#   - a --strict argument, for the tools that take one: they call confine_strict_on;
#   - a marker: an entry named strict, of any kind, in a run directory of WT (audit_<n>/strict or
#     incident_<n>/strict, the name as confine_rundir_name takes it and the marker lowercase), unless git
#     tracks anything under that run directory: then it is the repository's, not the auditor's. When git
#     cannot tell, the marker counts.
# confine_mode sets, as confine_init's last step:
#   CONFINE_STRICT      1 in strict mode, else 0;
#   CONFINE_MODE_WHY    the first source found, in the order above: AUDITOR_STRICT=<v>, --strict or
#                       <R>/strict (empty in default mode);
#   CONFINE_MARKERS     every marker that counts, as <R>/strict, separated by spaces (run directory
#                       names hold no blank);
#   CONFINE_MODE_NOTE   the AUDITOR_STRICT note's text when the value was read as on with a note, else
#                       empty (confine_mode prints the note itself, once);
#   CONFINE_GIT_GLOBAL  the GIT_CONFIG_GLOBAL hgit gives git: /dev/null in strict mode; in default mode
#                       scripts/lib/safe-directory.gitconfig of the installation, which trusts a
#                       repository another user owns (git's safe.directory). hgit's -c pins switch off
#                       every key known to name a program, so that check adds nothing to these reads.
# The markers cost one glob of WT when there are none. When there are, git is asked once, with the git
# environment of strict mode (GIT_CONFIG_GLOBAL /dev/null), whatever the mode: in a checkout another user
# owns git then cannot tell, and the marker counts, as it does for the Rust tools.
confine_mode() {
  local v=${AUDITOR_STRICT-} d n cand="" tracked=" " listed line
  CONFINE_STRICT=0 CONFINE_MODE_WHY='' CONFINE_MARKERS='' CONFINE_MODE_NOTE='' CONFINE_GIT_GLOBAL=/dev/null
  case "$v" in
    ''|0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]|[Oo][Ff][Ff]) ;;
    1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn])
      CONFINE_STRICT=1 CONFINE_MODE_WHY="AUDITOR_STRICT=$v" ;;
    *)
      confine_shown "$v"
      CONFINE_STRICT=1 CONFINE_MODE_WHY="AUDITOR_STRICT=$CONFINE_SHOWN"
      CONFINE_MODE_NOTE="AUDITOR_STRICT is '$CONFINE_SHOWN', read as on"
      confine_note "$CONFINE_MODE_NOTE" ;;
  esac
  for d in "$CONFINE_WT"/audit_* "$CONFINE_WT"/incident_*; do
    n=${d##*/}
    confine_rundir_name "$n" || continue
    if [ -e "$d/strict" ] || [ -L "$d/strict" ]; then cand="$cand $n"; fi
  done
  if [ -n "$cand" ]; then
    # One question for them all. git prints each tracked path from WT, the run directory first, in the
    # letter case the repository gave it (and after a quote when it quotes the path).
    if CONFINE_CEILING='' confine_git_check "$CONFINE_WT" && listed=$(confine_tracked $cand 2>/dev/null); then
      # Split on line ends, not read from a here-document: bash 3.2 writes one to a file, in the working
      # directory when it finds no TMPDIR it can write to.
      IFS=$'\n'
      set -f
      for line in $listed; do
        line=${line#\"}
        line=${line%%/*}
        case "$line" in
          [Aa][Uu][Dd][Ii][Tt]_*) tracked="${tracked}audit_${line#*_} " ;;
          [Ii][Nn][Cc][Ii][Dd][Ee][Nn][Tt]_*) tracked="${tracked}incident_${line#*_} " ;;
        esac
      done
      set +f
      IFS=$' \t\n'
    fi
    for n in $cand; do
      case "$tracked" in *" $n "*) continue ;; esac
      CONFINE_MARKERS=${CONFINE_MARKERS:+$CONFINE_MARKERS }$n/strict
      CONFINE_STRICT=1
      [ -n "$CONFINE_MODE_WHY" ] || CONFINE_MODE_WHY=$n/strict
    done
  fi
  [ "$CONFINE_STRICT" = 1 ] || CONFINE_GIT_GLOBAL=$CONFINE_ROOT/scripts/lib/safe-directory.gitconfig
}

# confine_strict_on <why>: strict mode from here on, for a tool given --strict (<why> is that word). It
# names the mode's source in place of a marker, not in place of AUDITOR_STRICT, which comes first.
confine_strict_on() {
  CONFINE_STRICT=1
  CONFINE_GIT_GLOBAL=/dev/null
  case "$CONFINE_MODE_WHY" in AUDITOR_STRICT=*) ;; *) CONFINE_MODE_WHY=$1 ;; esac
}

confine_note() { # confine_note <text>: the line "<tool>: note: <text>" on stderr
  printf '%s: note: %s\n' "${CONFINE_TOOL:-confine}" "$1" >&2
}

# confine_strict_refuse <reason> <note>: for a check that only strict mode keeps as a refusal. In strict
# mode, confine_refuse <reason>; in default mode, confine_note <note> (nothing when it is empty), status 0.
confine_strict_refuse() {
  [ "$CONFINE_STRICT" != 1 ] || confine_refuse "$1"
  [ -z "$2" ] || confine_note "$2"
}

# ---- git (OUTPUT-RULES.md Rule 11c) --------------------------------------------------------------------
# git opens the files of a repository with a blocking open, so a named pipe where it expects a file (a
# FIFO as HEAD, or one its config includes) stops it for good; tar carries such files, and a config can
# include a terminal device. These checks run without git, before git starts. A socket is let through:
# opening one fails at once, and git's own fsmonitor daemon keeps one in .git. hgit's time limit
# (confine_git_limit) is the backstop for a pipe they do not see, such as one behind a directory link.

confine_special() { # confine_special <path>: status 0 for a named pipe or a device, a link followed
  [ -p "$1" ] || [ -b "$1" ] || [ -c "$1" ]
}

confine_git_wait() { # confine_git_wait <where> <value>: CONFINE_GIT_WHY for a file git would wait on, then status 1
  CONFINE_GIT_WHY="a named pipe or device $1, and git would wait on it for good: $(confine_text "$2")"
  return 1
}

confine_git_unread() { # confine_git_unread <file>: CONFINE_GIT_WHY for a gitfile or commondir file these checks cannot read as git does
  CONFINE_GIT_WHY="a .git file or commondir file holds a NUL byte or more than 16 KiB, so where git would look cannot be told: $(confine_text "$1")"
}

# confine_named_dir <file> <prefix>: sets CONFINE_NAMED to the directory a gitfile ("gitdir: <dir>") or a
# commondir file names, as git reads it: the text after <prefix>, without its trailing line ends, relative
# to the file's directory (a commondir of line ends alone names that directory). Status 1 when git takes
# no directory from it (not a regular file it can read, no <prefix>, nothing after a gitfile's); 2 when it
# holds a NUL byte or more than 16 KiB, which these checks do not read as git does.
confine_named_dir() {
  local s
  [ -f "$1" ] && [ -r "$1" ] || return 1
  s=$(wc -c < "$1" 2>/dev/null) || return 1
  s=${s//[!0-9]/}
  [ -n "$s" ] && [ "$s" -le 16384 ] || return 2
  s=""
  if IFS= read -r -d '' s 2>/dev/null < "$1"; then return 2; fi
  while :; do
    case "$s" in *$'\n'|*$'\r') s=${s%?} ;; *) break ;; esac
  done
  case "$s" in "$2"*) s=${s#"$2"} ;; *) return 1 ;; esac
  [ -n "$s" ] || [ -z "$2" ] || return 1
  case "$s" in /*) ;; *) s=${1%/*}/$s ;; esac
  CONFINE_NAMED=$s
}

# confine_git_head <dir>: how git's discovery takes <dir>/HEAD (validate_headref in git's setup.c):
# status 0 for a regular file whose text, to its first NUL within its first 255 bytes, is "ref:", blanks,
# then refs/..., or starts with 40 hex digits; 2 for a symbolic link, which git takes when it points into
# refs/ (where it points is not read here); 1 for anything else, which git does not take for a HEAD. The
# blanks are those git's own isspace() knows: space, tab, CR and LF, never a vertical tab or form feed.
confine_git_head() {
  local h="" b=$' \t\r\n'
  [ ! -L "$1/HEAD" ] || return 2
  [ -f "$1/HEAD" ] && [ -r "$1/HEAD" ] || return 1
  IFS= read -r -d '' -n 255 h 2>/dev/null < "$1/HEAD"
  case "$h" in
    ref:*)
      h=${h#ref:}
      h=${h#"${h%%[!$b]*}"}
      case "$h" in refs/*) return 0 ;; esac
      return 1 ;;
  esac
  [ "${#h}" -ge 40 ] || return 1
  case "${h:0:40}" in *[!0-9a-fA-F]*) return 1 ;; esac
}

# confine_git_includes <config file>...: status 1 (CONFINE_GIT_WHY says why) when an include.path or
# includeIf.<condition>.path value in the files, or in a file they include in turn, names a named pipe or
# device or a file whose name holds a line end, when git cannot list one file's values, when one file
# lists more than 64 includes, or when they include more than 64 files. Each file is read once, nearest
# first, to git's 10 levels: git lists its values with no repository (--git-dir=/dev/null), following
# none. A value written ~user/ or %(prefix)/ names a place outside the tree and is not followed.
confine_git_includes() {
  local f t line out level=0 n=0 dup s values=0
  local -a cur=("$@") next=() seen=("$@")
  while [ "${#cur[@]}" -gt 0 ] && [ "$level" -le 10 ]; do
    next=()
    for f in "${cur[@]}"; do
      [ -f "$f" ] || continue
      grep -i -q -e include -- "$f" 2>/dev/null
      [ "$?" -ne 1 ] || continue
      out=$(hgit / --git-dir=/dev/null config --file "$f" --no-includes -z --get-regexp '^include(if\..+)?\.path$' 2>/dev/null </dev/null |
        while IFS= read -r -d '' t; do
          case "$t" in (*$'\n'*) t=${t#*$'\n'} ;; (*) continue ;; esac
          line=$t
          values=$((values + 1))
          if [ "$values" -gt 64 ]; then printf 'M\n'; break; fi
          case "$t" in
            ('~/'*) t=${HOME-}/${t#'~/'} ;;
            ('~'*|'%(prefix)/'*) continue ;;
            (/*) ;;
            (*) t=${f%/*}/$t ;;
          esac
          case "$t" in (*$'\n'*) printf 'N\n'; break ;; esac
          if confine_special "$t"; then printf 'S%s\n' "$line"; break; fi
          [ ! -f "$t" ] || printf 'F%s\n' "$t"
        done
        printf 'R%s\n' "${PIPESTATUS[0]}")
      while [ -n "$out" ]; do
        case "$out" in
          *$'\n'*) line=${out%%$'\n'*}; out=${out#*$'\n'} ;;
          *) line=$out; out="" ;;
        esac
        case "$line" in
          N) CONFINE_GIT_WHY="the repository's config includes a file whose name holds a line end"; return 1 ;;
          M) CONFINE_GIT_WHY="a config file of the repository lists more than 64 includes, more than these checks follow: $(confine_text "$f")"; return 1 ;;
          S*) confine_git_wait "is included by the repository's config" "${line#S}"; return 1 ;;
          R0|R1) ;;
          R*) CONFINE_GIT_WHY="git cannot list what this config file includes: $(confine_text "$f")"; return 1 ;;
          F*)
            t=${line#F}
            dup=0
            for s in "${seen[@]}"; do
              if [ "$t" -ef "$s" ]; then dup=1; break; fi
            done
            [ "$dup" -eq 0 ] || continue
            n=$((n + 1))
            if [ "$n" -gt 64 ]; then
              CONFINE_GIT_WHY="the repository's config includes more than 64 files, more than these checks follow"
              return 1
            fi
            seen+=("$t")
            next+=("$t") ;;
        esac
      done
    done
    cur=(${next[@]+"${next[@]}"})
    level=$((level + 1))
  done
}

# confine_git_dir_files <git directory> <common directory>: status 1 (CONFINE_GIT_WHY says why) when
# something in either, or a file their config includes, could stop git: a named pipe or device, a
# symbolic link to one, a name holding a line end (git makes none), a directory find cannot read (what
# it holds cannot be told), or a file an include names (confine_git_includes). Each is resolved first,
# since git opens what a link to it names; then find lists the pipes and devices of each, then its
# links, one to a line, and the shell tests where each leads, with no program per link.
confine_git_dir_files() {
  local g c d odd
  # Resolved in a subshell, so the caller's working directory stays as it is (target.sh runs from /).
  g=$(cd -P -- "$1" 2>/dev/null && printf '%s/' "$PWD") ||
    { CONFINE_GIT_WHY="the git directory cannot be resolved: $(confine_text "$1")"; return 1; }
  c=$(cd -P -- "$2" 2>/dev/null && printf '%s/' "$PWD") ||
    { CONFINE_GIT_WHY="the git directory cannot be resolved: $(confine_text "$2")"; return 1; }
  g=${g%/} c=${c%/}
  for d in "$g" "$c"; do
    odd=$(find "$d" \( -type p -o -type b -o -type c \) -print 2>/dev/null) || {
      CONFINE_GIT_WHY="the git directory holds a directory that cannot be read, so a named pipe or device in it cannot be ruled out: $(confine_text "$d")"
      return 1
    }
    [ -z "$odd" ] || { confine_git_wait "is in the git directory" "$d"; return 1; }
    odd=$(find "$d" -name '*'$'\n''*' -print 2>/dev/null)
    [ -z "$odd" ] || { CONFINE_GIT_WHY="a name in the git directory holds a line end: $(confine_text "$d")"; return 1; }
    odd=$(find "$d" -type l -print 2>/dev/null)
    [ -z "$odd" ] || odd=$(IFS=$'\n'; set -f; for f in $odd; do if confine_special "$f"; then printf l; break; fi; done)
    [ -z "$odd" ] || { confine_git_wait "is named by a link in the git directory" "$d"; return 1; }
    [ ! "$c" -ef "$g" ] || break
  done
  confine_git_includes "$c/config" "$g/config.worktree"
}

# confine_git_candidate <dir>: what git's discovery makes of <dir> as a git directory (is_git_directory):
# status 1 (CONFINE_GIT_WHY says why) for a named pipe or device as its HEAD or commondir, or for what
# confine_git_dir_files finds; 0 when git takes it for a repository, once checked; 3 when git passes it
# over, or may (a HEAD that is a link: checked as well, and the walk goes on); 4 when git stops there,
# unable to read its commondir. git opens HEAD first, and commondir only past a HEAD it takes; a
# repository has objects and refs in its common directory.
confine_git_candidate() {
  local g=$1 c head
  if confine_special "$g/HEAD"; then confine_git_wait "is in the git directory" "$g"; return 1; fi
  confine_git_head "$g"
  head=$?
  [ "$head" -ne 1 ] || return 3
  if confine_special "$g/commondir"; then confine_git_wait "is in the git directory" "$g"; return 1; fi
  c=$g
  if [ -e "$g/commondir" ]; then
    confine_named_dir "$g/commondir" ''
    case $? in
      0) c=$CONFINE_NAMED ;;
      1) return 4 ;;
      *) confine_git_unread "$g/commondir"; return 1 ;;
    esac
  fi
  [ -x "$c/objects" ] && [ -x "$c/refs" ] || return 3
  confine_git_dir_files "$g" "$c" || return 1
  [ "$head" -eq 0 ] || return 3
}

# confine_git_walk <absolute dir>: confine_git_check's walk, the way git's discovery goes (setup.c): in
# each directory from <dir> up to CONFINE_CEILING (which, as for git, is not looked at), first .git, then
# the directory itself as a bare repository, up to the first git takes. A .git file names the directory
# to look at instead, and git goes no further whatever it finds there; a .git that is neither a file
# nor a directory is passed over.
confine_git_walk() {
  local p=$1 g
  while :; do
    if [ -f "$p/.git" ]; then
      confine_named_dir "$p/.git" 'gitdir: '
      case $? in
        0) confine_git_candidate "$CONFINE_NAMED"; [ "$?" -ne 1 ] || return 1 ;;
        2) confine_git_unread "$p/.git"; return 1 ;;
      esac
      return 0
    fi
    for g in "$p/.git" "$p"; do
      [ -d "$g" ] || continue
      confine_git_candidate "$g"
      case $? in
        0|4) return 0 ;;
        1) return 1 ;;
      esac
    done
    [ "$p" != / ] || return 0
    p=${p%/*}
    [ -n "$p" ] || p=/
    [ -z "${CONFINE_CEILING-}" ] || [ "$p" != "$CONFINE_CEILING" ] || return 0
  done
}

# confine_git_check <dir>: status 1 (CONFINE_GIT_WHY says why) when git, run in <dir>, would wait on a
# file for good: what it opens on its way (confine_git_walk), in each candidate the HEAD, the commondir
# and, in each that may be a repository, everything confine_git_dir_files checks. A directory that passed
# is not checked again for the same ceiling in the same shell, nor while its own check is under way (the
# git call that check makes reads no repository).
confine_git_check() {
  local p=$1 key busy rc
  case "$p" in /*) ;; *) p=$CONFINE_WT/$p ;; esac
  key=$p$'\t'${CONFINE_CEILING-}$'\n'
  busy=${CONFINE_GIT_CHECKING:-$'\n'}
  case "${CONFINE_GIT_CHECKED-}$busy" in *$'\n'"$key"*) return 0 ;; esac
  CONFINE_GIT_CHECKING=$busy$key
  confine_git_walk "$p"
  rc=$?
  CONFINE_GIT_CHECKING=$busy
  [ "$rc" -ne 0 ] || CONFINE_GIT_CHECKED=${CONFINE_GIT_CHECKED-}$key
  return "$rc"
}

confine_git_files() { # confine_git_files <dir>: refuse where confine_git_check finds a file git would wait on
  confine_git_check "$1" || confine_refuse "$CONFINE_GIT_WHY"
}

# confine_git_limit <git arguments>: sets CONFINE_LIMIT, the seconds hgit gives git (0 for no limit):
# CONFINE_GIT_TIME when the caller set it for the call, else 10 for rev-parse, config and ls-files, the
# questions callers ask before they read, and no limit for the rest, which read a history or make a copy
# and take as long as that takes. A value that is not a whole number counts as 10.
confine_git_limit() {
  local a skip=0
  CONFINE_LIMIT=${CONFINE_GIT_TIME-}
  if [ -z "$CONFINE_LIMIT" ]; then
    CONFINE_LIMIT=0
    for a in "$@"; do
      if [ "$skip" -eq 1 ]; then skip=0; continue; fi
      case "$a" in
        -c|-C) skip=1 ;;
        -*) ;;
        rev-parse|config|ls-files) CONFINE_LIMIT=10; break ;;
        *) break ;;
      esac
    done
  fi
  case "$CONFINE_LIMIT" in *[!0-9]*) CONFINE_LIMIT=10 ;; esac
}

# confine_timed <seconds> <dir> <command>...: the command (hgit's git), run in a child of this shell, which
# it may replace with exec, with this shell's standard input and output; when it has not ended after
# <seconds> (0: no limit) it is killed and the call refused, so a named pipe or device the checks above do
# not see ends in a refusal, not a wait. Built from the shell alone: one side of a pipe starts git in the
# background, sends its process id, waits for it and sends "done"; the other reads the id, then waits up
# to the limit for "done" (read -t), and kills git when it does not come. bash's own note of a job ended
# by a signal is kept off stderr; the status says it. So is the write of "done" once the limit has passed
# and the other side has gone: where SIGPIPE is ignored, as GitHub's runners start their steps, that write
# fails with a message instead of ending this side quietly.
confine_timed() {
  local t=$1 d=$2
  local -a st
  shift 2
  if [ "$t" -eq 0 ]; then ( "$@" ); return; fi
  {
    ( "$@" 0<&7 7<&- 1>&8 8>&- &
      printf '%s\n' "$!"
      wait "$!" 2>/dev/null
      s=$?
      printf 'done\n' 2>/dev/null
      exit "$s" ) 7<&0 |
      ( read -r p
        if read -r -t "$t" x; then exit 0; fi
        kill -KILL "$p" 2>/dev/null
        exit 3 ) 8>&- >/dev/null 2>&1
    st=("${PIPESTATUS[@]}")
  } 8>&1
  [ "${st[1]}" != 3 ] ||
    confine_refuse "git has not answered within $t s in $(confine_text "$d"), so a file it opens there may be a named pipe or device that it would wait on for good"
  return "${st[0]}"
}

# confine_exec_clean <command>...: the command in place of this shell (exec), with an empty environment
# (exec -c). hgit starts env so, in confine_timed's child: a loader variable of the caller's would
# otherwise act on env itself, and on Linux an LD_PRELOAD naming no library puts the loader's line ahead
# of git's own answer on stderr, which confine_no_repo reads.
confine_exec_clean() { exec -c "$@"; }

# hgit <dir> <git arguments>: git in <dir> with only the environment below, and the -c pins over the
# repository's own config: what it runs, what it fetches, the files it reads, and how it reads history
# and patterns (grep.patternType, log.showRoot, replace refs, the commit-graph cache).
# GIT_CEILING_DIRECTORIES stops discovery at WT's parent unless the caller sets CONFINE_CEILING for one
# call. GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS makes git refuse abbreviated long options where its option
# parser checks it; git-ro.sh refuses them on its own as well. GIT_ALLOW_PROTOCOL carries the transport
# allowlist in the environment, which the repository's config cannot widen; it is empty (no transport)
# unless the caller sets CONFINE_ALLOW_PROTOCOL for one call. confine_git_files runs first, so git never
# starts on a repository that holds a file it would wait on, and git gets the time confine_git_limit
# gives it (CONFINE_GIT_TIME sets it for one call). env itself starts with an empty environment
# (confine_exec_clean). The system config is never read, and the global config is CONFINE_GIT_GLOBAL
# (confine_mode): no file in strict mode, the shipped safe-directory file in default mode.
hgit() {
  local d=$1
  shift
  confine_git_files "$d"
  confine_git_limit "$@"
  confine_timed "$CONFINE_LIMIT" "$d" confine_exec_clean env -i ${HOME+"HOME=$HOME"} PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" LC_ALL=C TZ="${TZ:-UTC}" \
    GIT_NO_LAZY_FETCH=1 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="${CONFINE_GIT_GLOBAL:-/dev/null}" GIT_TERMINAL_PROMPT=0 \
    GIT_OPTIONAL_LOCKS=0 GIT_ALLOW_PROTOCOL="${CONFINE_ALLOW_PROTOCOL-}" GIT_CEILING_DIRECTORIES="$CONFINE_CEILING" GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS=true \
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

# hgit_text <dir> <git arguments>: hgit, plus the pins a parser of git's text output needs (the
# threat-model collector's): grep prints no line or column number unless asked, and a diff keeps every
# hunk apart, with three lines of context.
hgit_text() {
  local d=$1
  shift
  hgit "$d" -c grep.lineNumber=false -c grep.column=false -c diff.interHunkContext=0 -c diff.context=3 "$@"
}

# hgit_tree <dir> <git arguments>, hgit_text_tree <dir> <git arguments>: hgit and hgit_text for a read of
# the history or the objects of the repository whose top level <dir> is, made with no file of its work
# tree open. git runs in a private empty directory under TMPDIR, outside WT, given as the work tree
# beside the repository's own git directory, so it takes .gitattributes and .gitmodules from the index
# and reads no .mailmap, whatever the work tree holds there: a named pipe behind a directory link, in a
# directory that cannot be listed, or under a directory named .git waits for good, and
# confine_work_files does not see it. A bare repository has no work tree and is read as hgit reads it.
# <dir> is the top level of a work tree, or a bare repository: one confine_repo or confine_repo_top
# accepted, or that git describes so here (confine_tree_add); anything else is refused. A question about
# the work tree (rev-parse --show-toplevel, ls-files) keeps plain hgit.
# For a repository confine_repo accepted from a directory below its top level (CONFINE_PREFIX), git runs
# in <empty>/<prefix>, so it takes a caller's paths relative to the same directory as in the working
# directory itself, and prints them as git does there. Each line of CONFINE_TREE_COPY, set for one call,
# names a file to place in the empty work tree first, as <path there><TAB><file to copy>; the caller
# checks both. What is made there goes again as the directory does.
hgit_tree() { confine_tree hgit "$@"; }
hgit_text_tree() { confine_tree hgit_text "$@"; }

confine_tree() { # confine_tree <hgit|hgit_text> <dir> <git arguments>: hgit_tree and hgit_text_tree
  local call=$1 d=$2 e rc in
  shift 2
  confine_git_files "$d"
  confine_tree_of "$d" || { confine_tree_add "$d" && confine_tree_of "$d"; } ||
    confine_refuse "git does not describe $(confine_text "$d") as the top level of a work tree or a bare repository"
  if [ "$CONFINE_TREE_BARE" = true ]; then
    "$call" "$d" "$@"
    return
  fi
  # As confine_scratch makes one, without leaving the caller's working directory (collect.sh reads from
  # its own temporary directory).
  e=$(cd -P -- "${TMPDIR:-/tmp}" 2>/dev/null && printf '%s/' "$PWD") ||
    confine_refuse "no empty directory can be made under TMPDIR for git to read in"
  e=${e%/}
  ! confine_inside "$e" "$CONFINE_WT" ||
    confine_refuse "TMPDIR lies inside the working directory, so git has no empty work tree to read in; point it outside the tree under audit"
  e=$(mktemp -d "${e%/}/auditor-git.XXXXXX" 2>/dev/null) && [ -d "$e" ] && [ ! -L "$e" ] ||
    confine_refuse "no empty directory can be made under TMPDIR for git to read in"
  in=$e
  [ -z "$CONFINE_TREE_PREFIX" ] || in=$e/${CONFINE_TREE_PREFIX%/}
  # git runs in a subshell that removes the directory as it ends: when git is done, when a signal ends the
  # subshell, and, when a signal ends only the caller (a timeout's alarm), once git is done. After a
  # Ctrl-C it removes the directory and then ends by SIGINT itself, so the caller stops as it would have.
  # A refusal in there (a question's time limit) ends that subshell alone, and its status is returned.
  ( trap 'confine_tree_clean "$e"' EXIT
    trap 'confine_tree_clean "$e"; trap - INT; exec /bin/sh -c "kill -INT \$\$"' INT
    confine_tree_fill "$e"
    CONFINE_CEILING=${e%/*} "$call" "$in" --git-dir="$CONFINE_TREE_GIT" --work-tree="$e" "$@" )
  rc=$?
  confine_tree_clean "$e"
  return "$rc"
}

# confine_tree_dirs: the directories confine_tree_fill makes in the empty work tree, each parent before
# what it holds, one to a line: those of CONFINE_TREE_PREFIX, then the parents of each file to copy.
confine_tree_dirs() {
  local line rel IFS=$'\n'
  confine_tree_parents "${CONFINE_TREE_PREFIX%/}"
  set -f
  for line in ${CONFINE_TREE_COPY-}; do
    rel=${line%%$'\t'*}
    case "$rel" in */*) confine_tree_parents "${rel%/*}" ;; esac
  done
  set +f
}

confine_tree_parents() { # confine_tree_parents <relative directory>: each directory on its way, the topmost first
  local p="" rest=$1
  while [ -n "$rest" ]; do
    p=${p:+$p/}${rest%%/*}
    case "$rest" in */*) rest=${rest#*/} ;; *) rest="" ;; esac
    printf '%s\n' "$p"
  done
}

# confine_tree_fill <empty work tree>: makes the directories of confine_tree_dirs with plain mkdir, then
# copies each file of CONFINE_TREE_COPY with noclobber; a step that fails is refused.
confine_tree_fill() {
  local line dirs IFS=$'\n'
  [ -n "${CONFINE_TREE_PREFIX}${CONFINE_TREE_COPY-}" ] || return 0
  dirs=$(confine_tree_dirs)
  set -f
  for line in $dirs; do
    [ -d "$1/$line" ] || confine_mkdir "$1/$line" ||
      confine_refuse "no empty work tree can be made under TMPDIR for git to read in"
  done
  for line in ${CONFINE_TREE_COPY-}; do
    confine_new_copy "${line#*$'\t'}" "$1/${line%%$'\t'*}" ||
      confine_refuse "cannot copy $(confine_text "${line%%$'\t'*}") into git's empty work tree"
  done
  set +f
}

# confine_tree_clean <empty work tree>: removes the files confine_tree_fill copied and the directories it
# made, the deepest first, then the directory itself. Nothing else is removed: rmdir takes only an empty
# directory.
confine_tree_clean() {
  local line i IFS=$'\n'
  local -a dirs=()
  if [ -z "${CONFINE_TREE_PREFIX}${CONFINE_TREE_COPY-}" ]; then rmdir -- "$1" 2>/dev/null; return; fi
  set -f
  for line in ${CONFINE_TREE_COPY-}; do
    rm -f -- "$1/${line%%$'\t'*}" 2>/dev/null
  done
  for line in $(confine_tree_dirs); do
    dirs+=("$line")
  done
  set +f
  i=${#dirs[@]}
  while [ "$i" -gt 0 ]; do
    i=$((i - 1))
    rmdir -- "$1/${dirs[$i]}" 2>/dev/null
  done
  rmdir -- "$1" 2>/dev/null
}

# confine_tree_of <dir>: status 0 when CONFINE_TREES holds <dir> (the same directory, by identity), as
# confine_repo, confine_repo_top and confine_tree_add put it there in this shell; sets CONFINE_TREE_BARE
# (true or false), CONFINE_TREE_GIT, its git directory, and CONFINE_TREE_PREFIX, the path of the working
# directory in it when confine_repo accepted it from there (CONFINE_PREFIX), else empty. CONFINE_TREES
# holds one line per directory: <dir><TAB><bare><TAB><git directory><TAB><prefix>.
confine_tree_of() {
  local rest=${CONFINE_TREES-} line
  while [ -n "$rest" ]; do
    line=${rest%%$'\n'*}
    rest=${rest#*$'\n'}
    [ "${line%%$'\t'*}" -ef "$1" ] || continue
    line=${line#*$'\t'}
    CONFINE_TREE_BARE=${line%%$'\t'*}
    line=${line#*$'\t'}
    CONFINE_TREE_GIT=${line%%$'\t'*}
    CONFINE_TREE_PREFIX=${line#*$'\t'}
    return 0
  done
  return 1
}

# confine_tree_add <dir> [<bare>]: adds <dir> to CONFINE_TREES as git describes it, asking git whether
# it is bare unless the caller says (true or false): status 1 unless git takes <dir> for the top level
# of its work tree, or for a bare repository's git directory, compared by identity, or when <dir> or a
# path git gives holds a control character. It changes no working directory.
confine_tree_add() {
  local bare=${2-} gd top
  [ -n "$bare" ] || bare=$(hgit "$1" rev-parse --is-bare-repository 2>/dev/null) || return 1
  gd=$(hgit "$1" rev-parse --absolute-git-dir 2>/dev/null && printf x) || return 1
  gd=${gd%x}
  gd=${gd%$'\n'}
  case "$bare" in
    true) top=$gd ;;
    false)
      top=$(hgit "$1" rev-parse --show-toplevel 2>/dev/null && printf x) || return 1
      top=${top%x}
      top=${top%$'\n'} ;;
    *) return 1 ;;
  esac
  case "$1$gd$top" in *[[:cntrl:]]*) return 1 ;; esac
  [ -n "$gd" ] && [ -n "$top" ] && [ "$top" -ef "$1" ] || return 1
  CONFINE_TREES=${CONFINE_TREES-}$1$'\t'$bare$'\t'$gd$'\t'$'\n'
}

# confine_work_files <work tree>: status 1 (CONFINE_GIT_WHY says why) when a file git reads in the work
# tree of a repository whose history it shows (.gitattributes and .gitignore in any directory, .mailmap,
# .gitmodules) is a named pipe or device, or a symbolic link to one (git before 2.32 follows such a
# link): git opens it with a blocking open, while it reads, and would wait on it for good. Nothing inside
# a .git is looked at here (confine_git_check does that).
confine_work_files() {
  local odd
  odd=$(find "$1" -name .git -prune -o \( -name .gitattributes -o -name .mailmap -o -name .gitignore -o -name .gitmodules \) \
    \( -type p -o -type b -o -type c -o -type l \) -print 2>/dev/null)
  [ -z "$odd" ] || odd=$(IFS=$'\n'; set -f; for f in $odd; do if [ ! -L "$f" ] || confine_special "$f"; then printf '%s' "$f"; break; fi; done)
  [ -z "$odd" ] || confine_git_wait "is where git reads its own files in the work tree" "$odd"
}

# confine_repo_top <dir>: status 0 when <dir> (absolute) is the top level of its own repository, or a
# bare repository itself, compared with symbolic links resolved on both sides and by identity. A
# directory inside another repository fails, so that repository is never read in its place; so does one
# whose repository holds a file git would wait on (confine_git_check), or, in strict mode, whose work tree
# does (confine_work_files: hgit_tree's reads open no file of the work tree, and its questions have a time
# limit). One that passes is added to CONFINE_TREES (confine_tree_add) for hgit_tree.
confine_repo_top() {
  local top here bare
  confine_git_check "$1" || return 1
  bare=$(hgit "$1" rev-parse --is-bare-repository 2>/dev/null)
  if [ "$bare" = true ]; then
    top=$(hgit "$1" rev-parse --absolute-git-dir 2>/dev/null) || return 1
  else
    top=$(hgit "$1" rev-parse --show-toplevel 2>/dev/null) || return 1
  fi
  [ -n "$top" ] && confine_phys "$1" || return 1
  here=$CONFINE_PHYS
  confine_phys "$top" && [ "$CONFINE_PHYS" -ef "$here" ] || return 1
  [ "$bare" = true ] || [ "$CONFINE_STRICT" != 1 ] || confine_work_files "$here" || return 1
  confine_tree_add "$1" "$bare"
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

# confine_repo <dir> <what> [<status>]: refuse <dir> (. for WT, or a confined directory) unless it is the
# top level of a repository, or a bare repository, whose git directory and common directory resolve inside
# WT and hold no named pipe or device (confine_git_files runs first), and, in strict mode, hold no symbolic
# link, borrow no objects (objects/info/alternates), rewrite no commit's parents (info/grafts), and whose
# work tree holds no file git would wait on (confine_work_files). In default mode (Rule 11f):
#   - . may also lie below the top level of a repository that tracks something there, as in a session
#     started in a package of a monorepo (confine_repo_above): that top level is read, CONFINE_PREFIX is
#     the path of WT in it, and its git directory must lie inside it;
#   - a git directory or common directory outside is accepted where git's own layout ties it back to the
#     top level (confine_git_dir_ours). One it does not tie back is refused, or, given <status>, gets a
#     note and ends the tool with <status>, with nothing read;
#   - a symbolic link in a hooks directory is accepted, since git opens no hook there with core.hooksPath
#     pinned to /dev/null; any other link is refused, as git would read through it;
#   - alternates get a note once each object directory they name passes the checks a git directory gets
#     (confine_alternates_ok), and grafts get a note;
#   - the work tree is not searched: hgit_tree's reads open no file of it, and its questions have a time
#     limit.
# Sets CONFINE_REPO (the physical path of the top level), CONFINE_GIT_DIR, CONFINE_COMMON_DIR,
# CONFINE_BARE (true or false) and CONFINE_PREFIX, and adds it to CONFINE_TREES for hgit_tree.
confine_repo() {
  local what=$2 unread=${3-} shown abs ran base info bare gitdir common top d odd n lines links ours="" prefix=""
  confine_shown "$1"
  shown=$CONFINE_SHOWN
  confine_path "$1" "$what" dir
  if [ "$CONFINE_REL" = . ]; then abs=$CONFINE_WT; else abs=$CONFINE_WT/$CONFINE_REL; fi
  confine_phys "$abs" || confine_refuse "$what cannot be resolved: $shown"
  abs=$CONFINE_PHYS
  ran=$abs
  base=$CONFINE_WT
  confine_git_files "$abs"
  # One call where there is a work tree; a bare repository has no top level, so it takes a second. git
  # prints each value on a line of its own, and a path can hold a line end (a core.worktree, a gitfile
  # or a commondir file can name one), which would shift the values: the output must hold exactly one
  # line per value, the x keeping a last empty line, and no other control character.
  if info=$(hgit "$abs" rev-parse --is-bare-repository --absolute-git-dir --git-common-dir --show-toplevel 2>/dev/null && printf x); then
    n=4
  elif info=$(hgit "$abs" rev-parse --is-bare-repository --absolute-git-dir --git-common-dir 2>/dev/null && printf x); then
    n=3
  elif [ "$CONFINE_REL" = . ] && confine_repo_above; then
    n=4
  else
    confine_refuse "$what is not a git repository that git can read (none there, or another user owns it: audit a copy): $shown"
  fi
  info=${info%x}
  lines=${info//[!$'\n']/}
  case "${info//$'\n'/}" in *[[:cntrl:]]*) lines="" ;; esac
  [ "${#lines}" -eq "$n" ] ||
    confine_refuse "git describes the repository at $what with a line end or control character inside a path: $shown"
  info=${info%$'\n'}
  bare=${info%%$'\n'*}
  info=${info#*$'\n'}
  gitdir=${info%%$'\n'*}
  info=${info#*$'\n'}
  common=${info%%$'\n'*}
  top=""
  [ "$n" -eq 3 ] || top=${info#*$'\n'}
  case "$bare" in
    true) top=$gitdir ;;
    false) ;;
    *) confine_refuse "git cannot describe the repository at $what: $shown" ;;
  esac
  [ -n "$top" ] && confine_phys "$top" && [ "$CONFINE_PHYS" -ef "$abs" ] ||
    confine_refuse "$what is not the top level of its repository: $shown"
  case "$common" in /*) ;; *) common=$ran/$common ;; esac
  confine_phys "$gitdir" || confine_refuse "$what has a git directory that cannot be resolved: $shown"
  gitdir=$CONFINE_PHYS
  confine_phys "$common" || confine_refuse "$what has a git directory that cannot be resolved: $shown"
  common=$CONFINE_PHYS
  for d in "$gitdir" "$common"; do
    if ! confine_inside "$d" "$base"; then
      [ "$CONFINE_STRICT" != 1 ] || confine_refuse "$what keeps its git directory outside the working directory: $shown"
      if [ -z "$ours" ]; then
        if confine_git_dir_ours "$abs" "$gitdir" "$common"; then ours=yes; else ours=no; fi
      fi
      if [ "$ours" = no ]; then
        [ -n "$unread" ] || confine_refuse "$what keeps its git directory outside the working directory: $shown"
        confine_note "$what keeps its git directory outside the working directory, and nothing there ties it back to this working tree, so its history is not read; strict mode refuses this (Rule 11f)"
        exit "$unread"
      fi
    fi
    odd=$(find "$d" ! -type f ! -type d ! -type s -print 2>/dev/null) || confine_refuse "$what has a git directory that find cannot fully read: $shown"
    if [ -n "$odd" ]; then
      links=$(find "$d" -type l -print 2>/dev/null)
      if [ -n "$links" ] && { [ "$CONFINE_STRICT" = 1 ] || ! confine_hook_links "$d" "$links"; }; then
        confine_refuse "$what has a symbolic link in its git directory: $shown"
      fi
      [ -z "$(find "$d" \( -type p -o -type b -o -type c \) -print 2>/dev/null)" ] ||
        confine_refuse "$what has a named pipe or device in its git directory, and git would wait on it for good: $shown"
    fi
    [ "$common" != "$gitdir" ] || break
  done
  if [ -e "$common/objects/info/alternates" ]; then
    [ "$CONFINE_STRICT" != 1 ] ||
      confine_refuse "$what borrows objects from another repository (objects/info/alternates); audit a full copy: $shown"
    confine_alternates_ok "$common/objects" || confine_refuse "$what $CONFINE_GIT_WHY: $shown"
    confine_note "$what borrows objects from another repository (objects/info/alternates), so its history is read from there too; strict mode refuses this (Rule 11f)"
  fi
  if [ -e "$common/info/grafts" ]; then
    confine_strict_refuse "$what rewrites commit parents (info/grafts), so git would show another history; review that file: $shown" \
      "$what rewrites commit parents (info/grafts), so git shows the history that file sets; strict mode refuses this (Rule 11f)"
  fi
  [ "$bare" = true ] || [ "$CONFINE_STRICT" != 1 ] || confine_work_files "$abs" || confine_refuse "$CONFINE_GIT_WHY"
  CONFINE_REPO=$abs
  CONFINE_GIT_DIR=$gitdir
  CONFINE_COMMON_DIR=$common
  CONFINE_BARE=$bare
  CONFINE_PREFIX=$prefix
  CONFINE_TREES=${CONFINE_TREES-}$abs$'\t'$bare$'\t'$gitdir$'\t'$prefix$'\n'
}

# confine_repo_above: for confine_repo ., the repository WT lies in below its top level. git, asked with no
# ceiling, must put WT inside a work tree whose top level lies above WT, with WT's path in it as the
# prefix, and must track a path under WT, so a repository at home that tracks nothing here is never taken
# for the target. In strict mode such a repository is refused by name; in default mode it is taken: this
# sets confine_repo's info (as its first call prints it), abs and base (the top level), ran (where git
# answered) and prefix. Status 1 when there is none.
confine_repo_above() {
  local v inside b g c t p up=..
  CONFINE_CEILING='' confine_git_files "$CONFINE_WT"
  v=$(CONFINE_CEILING='' hgit "$CONFINE_WT" rev-parse --is-inside-work-tree --is-bare-repository --absolute-git-dir \
    --git-common-dir --show-toplevel --show-prefix 2>/dev/null && printf x) || return 1
  v=${v%x}
  case "${v//$'\n'/}" in *[[:cntrl:]]*) return 1 ;; esac
  inside=${v%%$'\n'*}; v=${v#*$'\n'}
  b=${v%%$'\n'*}; v=${v#*$'\n'}
  g=${v%%$'\n'*}; v=${v#*$'\n'}
  c=${v%%$'\n'*}; v=${v#*$'\n'}
  t=${v%%$'\n'*}; v=${v#*$'\n'}
  p=${v%%$'\n'*}; v=${v#*$'\n'}
  [ "$inside:$b" = true:false ] && [ -z "$v" ] && [ -n "$g" ] && [ -n "$c" ] && [ -n "$t" ] || return 1
  case "$p" in ?*/) ;; *) return 1 ;; esac
  confine_phys "$t" && [ ! "$CONFINE_PHYS" -ef "$CONFINE_WT" ] && confine_inside "$CONFINE_WT" "$CONFINE_PHYS" &&
    [ "$CONFINE_PHYS/${p%/}" -ef "$CONFINE_WT" ] || return 1
  t=$CONFINE_PHYS
  CONFINE_CEILING='' hgit "$CONFINE_WT" ls-files --error-unmatch -- . >/dev/null 2>&1 || return 1
  if [ "$CONFINE_STRICT" = 1 ]; then
    v=${p%/}
    while :; do case "$v" in */*) v=${v#*/}; up=$up/.. ;; *) break ;; esac; done
    confine_refuse "the working directory lies below the top level of its repository ($up); strict mode reads a repository only from its top level: start Claude Code there (Rule 11f)"
  fi
  info=false$'\n'$g$'\n'$c$'\n'$t$'\n'x
  ran=$CONFINE_WT
  abs=$t
  base=$t
  prefix=$p
}

# confine_git_dir_ours <top> <git directory> <common directory>, all physical: status 0 when git's own
# layout ties a git directory outside <top> back to <top>: a linked worktree's, which is
# <common>/worktrees/<id> and whose gitdir file names <top>/.git; one whose core.worktree names <top>, as a
# separate git directory's may and a submodule's does; or a submodule's that lies inside the top level of
# the repository above <top>, which tracks <top> as a submodule. Status 1 for any other layout.
confine_git_dir_ours() {
  local top=$1 g=$2 c=$3 v sup rel
  if [ ! "$g" -ef "$c" ]; then
    [ -f "$g/gitdir" ] && [ "${g%/*}" -ef "$c/worktrees" ] && confine_named_dir "$g/gitdir" '' &&
      [ "$CONFINE_NAMED" -ef "$top/.git" ]
    return
  fi
  # git takes a relative core.worktree from the git directory.
  v=$(CONFINE_CEILING='' hgit "$top" config --get core.worktree 2>/dev/null) || v=""
  if [ -n "$v" ]; then
    case "$v" in /*) ;; *) v=$g/$v ;; esac
    [ ! "$v" -ef "$top" ] || return 0
  fi
  sup=$(CONFINE_CEILING='' hgit "${top%/*}" rev-parse --show-toplevel 2>/dev/null) && confine_phys "$sup" || return 1
  sup=$CONFINE_PHYS
  [ ! "$sup" -ef "$top" ] && confine_inside "$g" "$sup" || return 1
  case "$top" in "$sup"/*) rel=${top#"$sup"/} ;; *) return 1 ;; esac
  v=$(CONFINE_CEILING='' hgit "$sup" ls-files --stage -- ":(literal)$rel" 2>/dev/null) || return 1
  case "$v" in "160000 "*$'\t'"$rel") return 0 ;; esac
  return 1
}

confine_hook_links() { # confine_hook_links <git directory> <links, one to a line>: status 0 when each is the hooks directory there or lies in it
  local l rc=0 IFS=$'\n'
  set -f
  for l in $2; do
    case "$l" in "$1/hooks"|"$1/hooks/"*) ;; *) rc=1; break ;; esac
  done
  set +f
  return "$rc"
}

# confine_alternates_ok <objects directory> [<depth>]: status 1 (CONFINE_GIT_WHY says why, after the
# repository's name) when its info/alternates cannot be read, writes a path these checks do not read as
# git does (a quoted one), or names an object directory that is a named pipe or device, holds one or a
# symbolic link, or cannot be fully read; the object directories those name are checked in turn, to git's
# depth of 5. One that does not exist is passed over, as git passes over it.
confine_alternates_ok() {
  local o=$1 depth=${2:-0} line a odd
  [ "$depth" -lt 5 ] || return 0
  [ -f "$o/info/alternates" ] && [ -r "$o/info/alternates" ] ||
    { CONFINE_GIT_WHY="has an objects/info/alternates that cannot be read"; return 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) continue ;;
      '"'*) CONFINE_GIT_WHY="borrows objects through a quoted path in objects/info/alternates, which these checks do not read"; return 1 ;;
      /*) a=$line ;;
      *) a=$o/$line ;;
    esac
    if confine_special "$a"; then
      CONFINE_GIT_WHY="borrows objects from a named pipe or device (objects/info/alternates), and git would wait on it for good"
      return 1
    fi
    [ -d "$a" ] || continue
    a=$(cd -P -- "$a" 2>/dev/null && printf '%s/' "$PWD") || continue
    a=${a%/}
    odd=$(find "$a" ! -type f ! -type d ! -type s -print 2>/dev/null) ||
      { CONFINE_GIT_WHY="borrows objects from a directory that find cannot fully read (objects/info/alternates)"; return 1; }
    [ -z "$odd" ] ||
      { CONFINE_GIT_WHY="borrows objects from a directory that holds a symbolic link, named pipe or device (objects/info/alternates)"; return 1; }
    [ ! -e "$a/info/alternates" ] || confine_alternates_ok "$a" $((depth + 1)) || return 1
  done < "$o/info/alternates"
}

# confine_no_repo <status> <output>: status 0 when git, asked about a directory, answered that no
# repository there is one it can use: it exited 128 and its output starts with its own "fatal: not a git
# repository", or with "fatal: gitfile does not point to a valid repository", the words git 2.56 and later
# use where a .git file names none (earlier versions say "not a git repository: <dir>" there). Nothing
# else counts, and no part of the output alone: a refusal of the checks above or of hgit's time limit
# exits 64, and git's own messages can quote a name the repository chose. git 2.54 and later stop at a
# .git that is neither a regular file nor a directory, or that stat cannot read ("not a regular file:
# '<dir>/.git'", "error reading '<dir>/.git'"), where earlier versions walked on: git looks no further,
# but a repository above may still hold the directory in its work tree, so those words do not count.
confine_no_repo() {
  [ "$1" = 128 ] || return 1
  case "$2" in 'fatal: not a git repository'*|'fatal: gitfile does not point to a valid repository'*) return 0 ;; esac
  return 1
}

# confine_tracked <path>...: print what git tracks at each <path> (relative to WT, in any letter case)
# and return 0, or return 2 when git cannot tell. Outside every repository (confine_no_repo) nothing is
# tracked. Discovery may go above WT for this one question, since a repository there decides it; only
# paths at a <path> are printed.
confine_tracked() {
  local err p
  local -a specs=()
  for p in "$@"; do specs+=(":(literal,icase)$p"); done
  [ "${#specs[@]}" -gt 0 ] || return 0
  # Checked here first, so the two calls below find it done.
  CONFINE_CEILING='' confine_git_check "$CONFINE_WT" || return 2
  if err=$(CONFINE_CEILING='' hgit "$CONFINE_WT" rev-parse --is-inside-work-tree 2>&1 >/dev/null); then
    :
  elif confine_no_repo "$?" "$err"; then
    return 0
  else
    return 2
  fi
  CONFINE_CEILING='' hgit "$CONFINE_WT" --icase-pathspecs ls-files -- "${specs[@]}" 2>/dev/null || return 2
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
  local size hex
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  size=$(wc -c < "$1") || return 1
  size=${size//[!0-9]/}
  case "$size" in 1|2) ;; *) return 1 ;; esac
  hex=$(od -An -tx1 < "$1" | tr -d ' \n') || return 1
  [ "$hex" = 2a ] || [ "$hex" = 2a0a ]
}

# confine_rundir <R> <what>: refuse <R> unless it is a run directory (see the top). Sets CONFINE_RUN to
# its name without a leading ./. In default mode (Rule 11f) a symbolic link in it passes when it resolves
# to a path inside it (confine_links_inside), and when git cannot tell whether it is tracked, its
# .gitignore of * is enough. Strict mode refuses both.
confine_rundir() {
  local r=${1#./} what=$2 shown links listed
  confine_shown "$1"
  shown=$CONFINE_SHOWN
  confine_rundir_name "$r" ||
    confine_refuse "$what must be a run directory named audit_<n> or incident_<n> in the working directory: $shown"
  [ ! -L "$CONFINE_WT/$r" ] || confine_refuse "$what is a symbolic link: $shown"
  [ -d "$CONFINE_WT/$r" ] || confine_refuse "$what is not an existing directory: $shown"
  links=$(find "$CONFINE_WT/$r" -type l -print 2>/dev/null) || confine_refuse "$what cannot be fully read: $shown"
  if [ -n "$links" ]; then
    [ "$CONFINE_STRICT" != 1 ] && confine_links_inside "$CONFINE_WT/$r" || confine_refuse "$what holds a symbolic link: $shown"
  fi
  # In this shell, so a file git would wait on is refused for what it is, and confine_tracked finds it checked.
  CONFINE_CEILING='' confine_git_files "$CONFINE_WT"
  if listed=$(confine_tracked "$r"); then
    [ -z "$listed" ] || confine_refuse "$what is tracked by git: $shown"
  else
    [ "$CONFINE_STRICT" != 1 ] || confine_refuse "git cannot tell whether $what is tracked: $shown"
  fi
  confine_ignore_all "$CONFINE_WT/$r/.gitignore" || confine_refuse "$what has no .gitignore holding exactly *: $shown"
  CONFINE_RUN=$r
}

# confine_links_inside <directory>: status 0 when every symbolic link below <directory> resolves, every
# link on its way followed, to a path that exists and lies inside <directory>, judged by identity along
# its ancestors as confine_inside judges; status 1 for a link that resolves outside, to nothing, or in a
# loop, and when python3 -I cannot run (from /, so nothing in the working directory picks it).
confine_links_inside() {
  (cd / && exec python3 -I -c 'import os, sys
top = os.stat(sys.argv[1])
def inside(p):
    while True:
        try:
            s = os.stat(p)
        except OSError:
            return False
        if (s.st_dev, s.st_ino) == (top.st_dev, top.st_ino):
            return True
        q = os.path.dirname(p)
        if q == p:
            return False
        p = q
def stop(e):
    sys.exit(1)
for d, dirs, files in os.walk(sys.argv[1], onerror=stop):
    for n in dirs + files:
        p = os.path.join(d, n)
        if os.path.islink(p):
            r = os.path.realpath(p)
            if not os.path.exists(r) or not inside(r):
                sys.exit(1)' "$1") 2>/dev/null
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

# confine_new_copy <file> <path>: create <path> as confine_new_file does and copy the bytes of <file>
# into it through the descriptor opened at creation. Status 1 when it cannot.
confine_new_copy() {
  if [ -e "$2" ] || [ -L "$2" ]; then return 1; fi
  ( set -C; exec 9>"$2" && cat -- "$1" >&9 ) 2>/dev/null
}

# confine_scratch <prefix>: make a private scratch directory, <TMPDIR>/<prefix>.XXXXXX (mode 0700), and
# set CONFINE_SCRATCH to its physical path. Status 1 when it cannot be made, 2 when TMPDIR resolves
# inside WT (nothing is made there).
confine_scratch() {
  local d
  confine_phys "${TMPDIR:-/tmp}" || return 1
  ! confine_inside "$CONFINE_PHYS" "$CONFINE_WT" || return 2
  d=$(mktemp -d "$CONFINE_PHYS/$1.XXXXXX" 2>/dev/null) || return 1
  confine_phys "$d" || return 1
  CONFINE_SCRATCH=$CONFINE_PHYS
}

# confine_one_link <absolute path>: status 0 when the path is a regular file, not a symbolic link, with one
# link, so a tool may replace it as its own output or add a line to it.
confine_one_link() {
  local listed
  [ ! -L "$1" ] && [ -f "$1" ] || return 1
  listed=$(find "$1" -prune -type f -links 1 -print 2>/dev/null) || return 1
  [ "$listed" = "$1" ]
}

# ---- outside services (OUTPUT-RULES.md Rule 11b) -------------------------------------------------------
# confine_service <url>: sets CONFINE_SERVICE to the domain a request to <url> reaches, as a disclosure
# names it: the host's last two DNS labels (an IP address, or a host of one or two labels, stays whole),
# without scheme, userinfo, path, query or fragment; a port stays. Some providers put an endpoint token
# in a subdomain, so no more of the host is kept.
confine_service() {
  CONFINE_SERVICE=$(printf '%s\n' "$1" | sed -E -e 's|^[A-Za-z][A-Za-z0-9+.-]*://||' -e 's|^[^/?#]*@||' \
    -e 's|[/?#].*$||' -e 's|^.*\.([^.]+\.[A-Za-z][^.:]*)\.?(:[0-9]*)?$|\1\2|')
  CONFINE_SERVICE=${CONFINE_SERVICE//[[:cntrl:]]/?}
}

# <R>/disclosures.tsv holds one row for each run of a bundled tool that sent something to an outside
# service, under one header line; the report's list of outside services is built from it.
#   time<TAB>tool<TAB>service<TAB>sent<TAB>count
#   time     UTC, as YYYY-MM-DDTHH:MM:SSZ, taken just before the first request
#   tool     the script, relative to the installation root, e.g. scripts/dnr/collect.sh
#   service  the domain that received the requests (confine_service)
#   sent     what the requests carried: "<kind>: <value> <value> ..."
#   count    how many values
# A cell holds no control character; each one prints as ?.
CONFINE_DISCLOSURES_HEADER=$'time\ttool\tservice\tsent\tcount'

# confine_disclosures_ok <R>: status 0 when <R>/disclosures.tsv is absent, or a regular file with one link
# whose first line is the header, so a row can be added to it.
confine_disclosures_ok() {
  local f=$CONFINE_WT/$1/disclosures.tsv first
  if [ ! -e "$f" ] && [ ! -L "$f" ]; then return 0; fi
  confine_one_link "$f" || return 1
  IFS= read -r first < "$f" || return 1
  [ "$first" = "$CONFINE_DISCLOSURES_HEADER" ]
}

# confine_disclose <R> <tool> <service> <kind> <value>...: add one row to <R>/disclosures.tsv (R a run
# directory already checked). An absent file is created, header first, with noclobber; a row is added
# only to a file confine_disclosures_ok accepts, re-tested just before. Status 1 when it cannot.
confine_disclose() {
  local r=$1 tool=$2 service=$3 kind=$4 f now row v sent="" n=0
  shift 4
  for v in "$@"; do
    sent=${sent:+$sent }$v
    n=$((n + 1))
  done
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ) || return 1
  sent="$kind: $sent"
  row=${now//[[:cntrl:]]/?}$'\t'${tool//[[:cntrl:]]/?}$'\t'${service//[[:cntrl:]]/?}$'\t'${sent//[[:cntrl:]]/?}$'\t'$n
  f=$CONFINE_WT/$r/disclosures.tsv
  confine_disclosures_ok "$r" || return 1
  if [ ! -e "$f" ] && [ ! -L "$f" ]; then
    confine_new_file "$f" "$CONFINE_DISCLOSURES_HEADER"$'\n'"$row"$'\n' && return 0
    confine_disclosures_ok "$r" || return 1
  fi
  confine_one_link "$f" || return 1
  printf '%s\n' "$row" 2>/dev/null >> "$f"
}

# confine_b58_bytes <s>: print how many bytes the base58 text <s> (its alphabet already checked) decodes
# to, each leading 1 counting as a zero byte; status 1 when python3 -I did not run. python3 runs from /,
# so nothing in the working directory (a .python-version a pyenv shim reads) picks the interpreter.
confine_b58_bytes() {
  (cd / && exec python3 -I -c 'import sys
a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = 0
for c in sys.argv[1]:
    n = n * 58 + a.index(c)
print(len(sys.argv[1]) - len(sys.argv[1].lstrip("1")) + (n.bit_length() + 7) // 8)' "$1") 2>/dev/null
}
