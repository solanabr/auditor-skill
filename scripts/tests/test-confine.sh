#!/usr/bin/env bash
# test-confine.sh — self-test for scripts/lib/confine.sh, the checks the bundled entry points share: the
# working directory and installation checks of confine_init, the cleaned PATH, confined paths (the case
# file fixtures/confine/paths.txt), run-directory names and .gitignore files, noclobber writes, the
# environment and order of the hardened git call, the repository, tracked and partial-clone checks, and
# the named pipes git would wait on. Every case runs under each bash on the machine (/bin/bash and the
# bash running this suite, when they differ) and must print the same under each. Needs git and mkfifo;
# python3 for the socket case; no network.
# Usage (from the repo root): bash scripts/tests/test-confine.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
LIB="$ROOT/scripts/lib/confine.sh"
CASES="$ROOT/scripts/tests/fixtures/confine/paths.txt"
T=$(mktemp -d "${TMPDIR:-/tmp}/confine-test.XXXXXX") || exit 1
T=$(cd -P "$T" && pwd -P) || exit 1
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
REAL_GIT=$(command -v git) || { echo "FAIL - git is not on PATH"; exit 1; }

export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
mkdir -p "$HOME"

pass=0 fail=0 skip=0
ok()   { pass=$((pass + 1)); echo "ok   - $1"; }
ko()   { fail=$((fail + 1)); echo "FAIL - $1"; }
skp()  { skip=$((skip + 1)); echo "skip - $1"; }
check() { # check <name> <command>...: on a failure, also show the last lib run
  if "${@:2}"; then ok "$1"; else ko "$1"; echo "#   status ${RC:-} stdout [$(cat "$T/out" 2>/dev/null)] stderr [$(cat "$T/err" 2>/dev/null)]"; fi
}
has()   { grep -qF -- "$2" "$1"; }

SHELLS=("$BASH")
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then
  SHELLS+=(/bin/bash)
fi
echo "# shells: ${SHELLS[*]}"

# lib <dir> <code> [<root>]: <code> run from <dir> with confine.sh sourced and confine_init done (tool
# "test", installation <root>, by default this checkout), under each shell, with $LIB_PATH as PATH when
# it is set. Output in $T/out, $T/err and $RC; every shell must produce the same three, byte for byte.
# lib_once: under the first shell only, for code that changes what the next run sees.
lib() {
  local dir=$1 code=$2 root=${3-$ROOT} i=1 rc
  (cd "$dir" && PATH=${LIB_PATH:-$PATH} "${SHELLS[0]}" -c '. "$1" && confine_init test "$2" && eval "$3"' lib "$LIB" "$root" "$code") \
    >"$T/out" 2>"$T/err" </dev/null
  RC=$?
  while [ "$i" -lt "${#SHELLS[@]}" ]; do
    (cd "$dir" && PATH=${LIB_PATH:-$PATH} "${SHELLS[$i]}" -c '. "$1" && confine_init test "$2" && eval "$3"' lib "$LIB" "$root" "$code") \
      >"$T/out.$i" 2>"$T/err.$i" </dev/null
    rc=$?
    if [ "$rc" != "$RC" ] || ! cmp -s "$T/out" "$T/out.$i" || ! cmp -s "$T/err" "$T/err.$i"; then
      ko "the same output under ${SHELLS[0]} and ${SHELLS[$i]}: $code"
    fi
    i=$((i + 1))
  done
}
lib_once() { local -a all=("${SHELLS[@]}"); SHELLS=("${all[0]}"); lib "$@"; SHELLS=("${all[@]}"); }
out_is() { [ "$RC" = 0 ] && [ "$(cat "$T/out")" = "$1" ] && [ ! -s "$T/err" ]; }
refused() { [ "$RC" = 64 ] && [ "$(cat "$T/err")" = "test: refused: $1" ] && [ ! -s "$T/out" ]; }

mkrepo() { git init -q "$1" && git -C "$1" symbolic-ref HEAD refs/heads/main; }
put()    { mkdir -p "$(dirname "$1/$2")" && printf '%s\n' "$3" > "$1/$2" && git -C "$1" add -- "$2"; }
commit() { git -C "$1" commit -q "${@:2}"; }

# bounded gives a run 10 s (or BOUND tenths of a second), then reads 142 and opens the named pipe it was
# given for writing, so a git still waiting there (as before the checks below existed) goes on and ends.
# script runs one of the entry points that start git, from a directory, under the first shell.
script() { # script <dir> <script> <arg>...: scripts/<script>, with its output in $T/out and $T/err and its status in RC
  local dir=$1 s=$2
  shift 2
  (cd "$dir" && "${SHELLS[0]}" "$ROOT/scripts/$s" "$@") >"$T/out" 2>"$T/err" </dev/null
  RC=$?
}
refused_by() { [ "$RC" = 64 ] && [ "$(sed -n '$=' "$T/err")" = 1 ] && grep -q "^$1: refused: " "$T/err"; }
lib_bounded() { local f=$1; shift; bounded "$f" lib "$@"; } # lib_bounded <pipe> <lib arguments>...
bounded() { # bounded <pipe> <command>...: the command (lib or script), bounded as above
  local f=$1 pid n=0 limit=${BOUND:-100}
  shift
  rm -f "$T/rc"
  ( "$@"; printf '%s' "$RC" > "$T/rc" ) &
  pid=$!
  while kill -0 "$pid" 2>/dev/null && [ "$n" -lt "$limit" ]; do sleep 0.1; n=$((n + 1)); done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    ( : > "$f" ) &
    pid=$!
    n=0
    while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 20 ]; do sleep 0.1; n=$((n + 1)); done
    kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    RC=142
  else
    wait "$pid"
    RC=$(cat "$T/rc" 2>/dev/null)
  fi
}

# =================================================================================================
# confine_init: the working directory, the installation and the environment.
# =================================================================================================
WT="$T/wt"
mkdir -p "$WT/src/deep" "$WT/bin" "$T/ok" "$T/ok2" "$T/outside"
lib "$WT" 'printf "%s|%s|%s|%s" "$CONFINE_WT" "$CONFINE_ROOT" "$CONFINE_CEILING" "$CONFINE_TOOL"'
check "confine_init takes the physical working directory, the root and WT's parent" out_is "$WT|$ROOT|$T|test"
lib "$WT" 'umask; printf "%s|%s|%s|" "${CDPATH-unset}" "${BASH_ENV-unset}" "${ENV-unset}"; sh -c "printf %s \"\$LC_ALL\""'
check "... sets umask 077 and LC_ALL=C for children, and unsets CDPATH, BASH_ENV and ENV" \
  out_is "$(printf '0077\nunset|unset|unset|C')"
CDPATH="$T" ENV="$T/env.sh" lib "$WT" 'printf "%s|%s" "${CDPATH-unset}" "${ENV-unset}"'
check "... whatever the caller set" out_is 'unset|unset'
ln -s "$WT" "$T/wt-link"
lib "$T/wt-link" 'printf "%s" "$CONFINE_WT"'
check "a working directory reached through a link above it resolves to the physical path" out_is "$WT"
L="$T/wt-link" lib "$WT" 'printf "%s" "$PWD"; confine_phys "$L"; printf "|%s|%s" "$CONFINE_PHYS" "$PWD"'
check "confine_phys resolves links and leaves the working directory as it was" out_is "$WT|$WT|$WT"
lib "$ROOT" 'printf ran'
check "an installation that is the working directory is refused" \
  refused 'the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)'
lib "$WT" 'printf ran' "$WT/inst"
check "an installation inside the working directory is refused" \
  refused 'the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)'
lib / 'printf ran'
check "a working directory of / holds every installation, so it is refused" \
  refused 'the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)'
lib "$WT" 'printf ran' "$T/wt2"
check "an installation beside the working directory is accepted" out_is ran
for c in '"' '$' '`' '\' $'\n' $'\t' $'\177'; do
  lib "$WT" 'printf ran' "$T/inst${c}x"
  check "an installation path holding $(printf '%s' "$c" | od -An -c | tr -d ' \n') is refused" \
    refused 'the installation path holds a quote, $, a backtick, a backslash or a control character, so its quoted call cannot match as written'
done
lib "$WT" 'printf ran' ''
check "an empty installation path is refused" \
  refused 'the installation path holds a quote, $, a backtick, a backslash or a control character, so its quoted call cannot match as written'
NLDIR="$T/a"$'\n'"b"
if mkdir -p "$NLDIR" 2>/dev/null; then
  lib "$NLDIR" 'printf ran'
  check "a working directory whose path holds a control character is refused" \
    refused 'the working directory path holds a control character'
else
  skp "this filesystem refuses a newline in a directory name"
fi

# PATH: only absolute entries that resolve outside the working directory, as physical paths.
ln -s "$WT/bin" "$T/link-into-wt"
ln -s "$T/ok2" "$T/link-out"
LIB_PATH="$WT/bin:bin:.::$T/ok:$T/link-into-wt:/nonexistent/x:$T/link-out:$WT" lib "$WT" 'printf "%s" "$PATH"'
check "PATH keeps absolute entries outside the working directory, resolved" out_is "$T/ok:$T/ok2"
(cd "$WT" && PATH="$WT/bin:bin:." "$BASH" -c '. "$1" && confine_init test "$2"' lib "$LIB" "$ROOT") >"$T/out" 2>"$T/err" </dev/null
RC=$?
check "a PATH with nothing outside the working directory is refused" refused 'no PATH entry is left outside the working directory'
# A working directory inside a repository (a program of a monorepo): that repository's tree is under
# audit too, so its node_modules/.bin is dropped. A .git the tree puts nearer does not shrink that tree:
# an empty one, or a HEAD alone (git walks past both), or a repository of its own. A repository at HOME
# (the auditor's own) is not taken.
mkrepo "$T/mono"
mkdir -p "$T/mono/node_modules/.bin" "$T/mono/programs/v"
LIB_PATH="$T/mono/node_modules/.bin:$T/ok:$T/link-out" lib "$T/mono/programs/v" 'printf "%s" "$PATH"'
check "PATH drops an entry inside the repository the working directory lies in" out_is "$T/ok:$T/ok2"
mkdir "$T/mono/programs/v/.git"
LIB_PATH="$T/mono/node_modules/.bin:$T/ok" lib "$T/mono/programs/v" 'printf "%s" "$PATH"'
check "... also when the working directory holds an empty .git directory" out_is "$T/ok"
rmdir "$T/mono/programs/v/.git"
: > "$T/mono/programs/.git"
LIB_PATH="$T/mono/node_modules/.bin:$T/ok" lib "$T/mono/programs/v" 'printf "%s" "$PATH"'
check "... or an empty .git file lies between it and the repository's top level" out_is "$T/ok"
rm "$T/mono/programs/.git"
mkdir "$T/mono/programs/.git"
printf 'ref: refs/heads/main\n' > "$T/mono/programs/.git/HEAD"
LIB_PATH="$T/mono/node_modules/.bin:$T/ok" lib "$T/mono/programs/v" 'printf "%s" "$PATH"'
check "... or a .git holding a HEAD alone lies there" out_is "$T/ok"
rm -r "$T/mono/programs/.git"
mkrepo "$T/mono/programs/own"
LIB_PATH="$T/mono/node_modules/.bin:$T/ok" lib "$T/mono/programs/own" 'printf "%s" "$PATH"'
check "... or the working directory is a repository of its own inside the outer one" out_is "$T/ok"
mkdir -p "$HOME/bin" "$HOME/work/w"
git init -q "$HOME"
LIB_PATH="$HOME/bin:$T/ok" lib "$HOME/work/w" 'printf "%s" "$PATH"'
check "... but keeps entries under HOME when HOME itself is a repository" out_is "$HOME/bin:$T/ok"
rm -rf "$HOME/.git"
# On a volume that ignores letter case one directory has several spellings: the checks compare
# directories, not spellings.
if [ -d "$T/WT" ] && [ "$T/WT" -ef "$WT" ]; then
  LIB_PATH="$T/WT/bin:$T/ok" lib "$WT" 'printf "%s" "$PATH"'
  check "PATH drops an entry inside the working directory spelled in other letters" out_is "$T/ok"
  lib "$WT" 'printf ran' "$T/WT/inst"
  check "an installation inside the working directory spelled in other letters is refused" \
    refused 'the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)'
  lib "$T/WT" 'printf "%s" "$CONFINE_WT"'
  check "a working directory entered in other letters is taken with the names on disk" out_is "$WT"
else
  skp "this volume tells letter case apart: the spelling cases"
fi
lib "$WT" 'confine_need sh nosuch-tool-for-confine-test; printf ran'
check "confine_need refuses a program that is not on PATH" refused 'nosuch-tool-for-confine-test is not on PATH'
lib "$WT" 'confine_refuse "a reason"; printf ran'
check "confine_refuse prints one line and exits 64" refused 'a reason'
lib "$WT" 'confine_text "$(printf "a\001b\033c\177d\te")"; printf "|"; confine_text "$(printf "%0300d" 0)"'
check "confine_text shows control characters as ? and cuts after 200 bytes" \
  out_is "a?b?c?d?e|$(printf '%0200d' 0)..."

# =================================================================================================
# confine_path: the case file, lengths and control characters among its cases.
# =================================================================================================
printf 'fn a() {}\n' > "$WT/a.rs"
printf 'fn lib() {}\n' > "$WT/src/lib.rs"
printf 'fn x() {}\n' > "$WT/src/deep/x.rs"
ln -s a.rs "$WT/link"
ln -s src "$WT/linkdir"
ln -s nowhere "$WT/dangling"
ln -s "$T/outside" "$WT/out"
ln -s ../a.rs "$WT/src/inner"
if ! mkfifo "$WT/fifo" 2>/dev/null; then skp "mkfifo is not available: the FIFO case fails below"; fi
mkdir "$WT/src/locked" && chmod 000 "$WT/src/locked"
# fill <var> <field>: <var> set to a field of the case file with its placeholders filled in (its header
# lists them), as tools/auditor-tools/tests/confine_agrees.rs fills them.
fill() {
  local rest=$2 out='' name a
  [ "$rest" = @EMPTY@ ] && rest=''
  while [[ $rest == *@*@* ]]; do
    out=$out${rest%%@*}
    rest=${rest#*@}
    name=${rest%%@*}
    rest=${rest#*@}
    case $name in
      SOH) out=$out$'\001' ;;
      TAB) out=$out$'\t' ;;
      NL) out=$out$'\n' ;;
      ESC) out=$out$'\033' ;;
      DEL) out=$out$'\177' ;;
      LONG:*) printf -v a '%*s' "${name#LONG:}" ''; out=$out${a// /a} ;;
      *) out=$out@$name@ ;;
    esac
  done
  printf -v "$1" '%s' "$out$rest"
}
ncase=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  IFS=$'\t' read -r want p status expect <<< "$line"
  case "$want" in
    noroot:*)
      want=${want#noroot:}
      if [ "$(id -u)" -eq 0 ]; then skp "confine_path $want $p: root may search any directory"; continue; fi ;;
  esac
  fill p "$p"
  fill expect "$expect"
  ncase=$((ncase + 1))
  P="$p" W="$want" lib "$WT" 'confine_path "$P" "the path" "$W"; printf "%s %s" "$CONFINE_REL" "$CONFINE_TYPE"'
  if [ "$status" = 0 ]; then check "confine_path $want $p" out_is "$expect"
  else check "confine_path $want $p refused" refused "${expect#test: refused: }"; fi
done < "$CASES"
check "the path case file has cases ($ncase)" test "$ncase" -gt 40
chmod 700 "$WT/src/locked" && rmdir "$WT/src/locked"

# =================================================================================================
# Run directories: names, .gitignore, and the whole check.
# =================================================================================================
for n in audit_1 incident_1 audit_999999 incident_000001 audit_0; do
  N="$n" lib "$WT" 'confine_rundir_name "$N" && printf yes'
  check "run directory name $n" out_is yes
done
for n in audit_ audit_1234567 Audit_1 AUDIT_1 audit_1a audit_-1 audit_+1 'audit_1 ' audit_1/ audit_1/x ./audit_1 incident_ report_1 audit audit_x_1; do
  N="$n" lib "$WT" 'confine_rundir_name "$N" && printf yes || printf no'
  check "not a run directory name: '$n'" out_is no
done
mkdir -p "$WT/gi"
n=0
for content in '*' "$(printf '*\nx')" '**' '* ' '' '!x' ' *'; do
  n=$((n + 1))
  printf '%s' "$content" > "$WT/gi/f$n"
done
printf '*\n' > "$WT/gi/nl"
printf '*\r\n' > "$WT/gi/crlf"
printf '\n*' > "$WT/gi/lead"
printf '*\n\n' > "$WT/gi/two"
printf '*\000' > "$WT/gi/nul"
mkdir -p "$WT/gi/dir"
ln -s nl "$WT/gi/link"
lib "$WT" 'for f in f1 nl f2 f3 f4 f5 f6 f7 crlf lead two nul dir link absent; do confine_ignore_all "$CONFINE_WT/gi/$f" && printf "%s " "$f"; done; :'
check "a .gitignore must hold exactly * (one newline may follow), as a regular file, its bytes compared" out_is 'f1 nl '

mkdir -p "$WT/audit_1/poc" "$WT/audit_2" "$WT/audit_3/x" "$WT/audit_4"
printf '*\n' > "$WT/audit_1/.gitignore"
printf '*\n' > "$WT/audit_3/.gitignore"
ln -s "$T/outside" "$WT/audit_3/x/link"
printf '*\n!x\n' > "$WT/audit_4/.gitignore"
ln -s audit_1 "$WT/audit_5"
lib "$WT" 'confine_rundir audit_1 R; printf "%s" "$CONFINE_RUN"'
check "a run directory passes" out_is audit_1
lib "$WT" 'confine_rundir ./audit_1 R; printf "%s" "$CONFINE_RUN"'
check "... written ./audit_1" out_is audit_1
lib "$WT" 'confine_rundir audit_2 R'
check "a run directory without a .gitignore is refused" refused 'R has no .gitignore holding exactly *: audit_2'
lib "$WT" 'confine_rundir audit_3 R'
check "a run directory holding a symbolic link is refused" refused 'R holds a symbolic link: audit_3'
lib "$WT" 'confine_rundir audit_4 R'
check "a .gitignore that lets a file through is refused" refused 'R has no .gitignore holding exactly *: audit_4'
lib "$WT" 'confine_rundir audit_5 R'
check "a run directory that is a symbolic link is refused" refused 'R is a symbolic link: audit_5'
lib "$WT" 'confine_rundir audit_6 R'
check "a missing run directory is refused" refused 'R is not an existing directory: audit_6'
lib "$WT" 'confine_rundir src R'
check "a directory with another name is refused" \
  refused 'R must be a run directory named audit_<n> or incident_<n> in the working directory: src'
if [ "$(id -u)" -ne 0 ]; then
  mkdir -p "$WT/audit_7/locked"
  printf '*\n' > "$WT/audit_7/.gitignore"
  chmod 000 "$WT/audit_7/locked"
  lib "$WT" 'confine_rundir audit_7 R'
  check "a run directory that find cannot fully read is refused" refused 'R cannot be fully read: audit_7'
  chmod 700 "$WT/audit_7/locked"
else
  skp "running as root: an unreadable directory cannot be made"
fi

# =================================================================================================
# Writes: noclobber files through the descriptor, plain mkdir.
# =================================================================================================
mkdir -p "$WT/w"
TXT=$(printf 'one\ntwo\nx'); TXT="$TXT"$'\n'
TXT=$TXT lib_once "$WT" 'confine_new_file "$CONFINE_WT/w/new" "$TXT" && printf ok'
printf 'one\ntwo\nx\n' > "$T/new.want"
check "confine_new_file creates a file" out_is ok
check "... with exactly the text" cmp -s "$WT/w/new" "$T/new.want"
check "... readable by its owner only" test "$(ls -l "$WT/w/new" | cut -c1-10)" = '-rw-------'
lib "$WT" 'confine_new_file "$CONFINE_WT/w/new" replaced || printf refused'
check "confine_new_file never replaces a file" sh -c "[ \"\$(cat '$T/out')\" = refused ] && cmp -s '$WT/w/new' '$T/new.want'"
ln -s "$T/outside/created-through-link" "$WT/w/dangling"
lib "$WT" 'confine_new_file "$CONFINE_WT/w/dangling" x || printf refused'
check "confine_new_file does not write through a dangling link" \
  sh -c "[ \"\$(cat '$T/out')\" = refused ] && [ ! -e '$T/outside/created-through-link' ]"
printf 'keep\n' > "$T/outside/target"
ln -s "$T/outside/target" "$WT/w/tolink"
lib "$WT" 'confine_new_file "$CONFINE_WT/w/tolink" x || printf refused'
check "... nor through a link to a file" sh -c "[ \"\$(cat '$T/out')\" = refused ] && [ \"\$(cat '$T/outside/target')\" = keep ]"
lib_once "$WT" 'confine_mkdir "$CONFINE_WT/w/d" && printf made; confine_mkdir "$CONFINE_WT/w/d" || printf " again-refused"; confine_mkdir "$CONFINE_WT/w/no/such" || printf " parent-refused"'
check "confine_mkdir makes one directory and never two levels or an existing one" out_is 'made again-refused parent-refused'
check "... readable by its owner only" test "$(ls -ld "$WT/w/d" | cut -c1-10)" = 'drwx------'

# =================================================================================================
# hgit: the environment and the words git receives.
# =================================================================================================
mkdir -p "$T/rec"
cat > "$T/rec/git" <<EOF
#!/bin/sh
{ printf 'ARGV'; for a in "\$@"; do printf '\037%s' "\$a"; done; printf '\n'; env | sed 's/^/ENV /'; } >> "$T/rec.log"
exec "$REAL_GIT" "\$@"
EOF
chmod +x "$T/rec/git"
R="$T/repo"; mkrepo "$R"
put "$R" f.txt 'one'
commit "$R" -m one
: > "$T/rec.log"
GIT_DIR=/nonexistent GIT_CONFIG_PARAMETERS="'core.pager=false'" GIT_EXTERNAL_DIFF=false PAGER=false GIT_PAGER=false \
GIT_EXEC_PATH=/nonexistent GIT_SSH_COMMAND=false GIT_TRACE="$T/trace" PATH="$T/rec:$PATH" \
  lib "$R" 'hgit "$CONFINE_WT" rev-parse --abbrev-ref HEAD'
check "hgit reads the repository it is given, whatever GIT_* the caller set" out_is main
check "... and git writes no trace" test ! -e "$T/trace"
awk '/^ENV / { sub(/^ENV /, ""); sub(/=.*/, ""); print }' "$T/rec.log" | sort -u > "$T/env.names"
check "hgit passes only the hardened environment" \
  test -z "$(grep -vxE 'HOME|PATH|TMPDIR|LC_ALL|TZ|GIT_NO_LAZY_FETCH|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|GIT_ALLOW_PROTOCOL|GIT_CEILING_DIRECTORIES|GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS|PWD|OLDPWD|SHLVL|_' "$T/env.names")"
awk -F '\037' '$1 == "ARGV" { print $2, ($3 == "-C"), $5, $6; exit }' "$T/rec.log" > "$T/argv"
check "hgit runs git --no-pager -C <dir> -c core.fsmonitor=false first" test "$(cat "$T/argv")" = '--no-pager 1 -c core.fsmonitor=false'
for pin in core.pager=cat core.hooksPath=/dev/null protocol.allow=never core.attributesFile=/dev/null \
           log.showSignature=false gpg.program=false submodule.recurse=false diff.submodule=short \
           log.diffMerges=separate grep.patternType=basic grep.extendedRegexp=false log.showRoot=true \
           core.useReplaceRefs=false core.commitGraph=false; do
  check "hgit pins $pin before the subcommand" \
    awk -F '\037' -v pin="$pin" '$1 == "ARGV" { for (i = 2; i <= NF && $i != "rev-parse"; i++) if ($i == pin && $(i - 1) == "-c") found = 1; exit } END { exit !found }' "$T/rec.log"
done
# The time git gets: 10 s for the questions rev-parse, config and ls-files answer, no limit for a read or a
# copy, CONFINE_GIT_TIME for one call (a value that is no whole number counting as 10), never the
# environment's.
lib "$R" 'for w in rev-parse "-c a=b config" "--icase-pathspecs ls-files" log "-c x=y clone" "-C d rev-parse" ""; do confine_git_limit $w; printf "%s " "$CONFINE_LIMIT"; done
  CONFINE_GIT_TIME=3 confine_git_limit log; printf "%s " "$CONFINE_LIMIT"; CONFINE_GIT_TIME=x confine_git_limit log; printf "%s" "$CONFINE_LIMIT"'
check "confine_git_limit: 10 s for rev-parse, config and ls-files, none for the rest, CONFINE_GIT_TIME for one call" \
  out_is '10 10 10 0 0 10 0 3 10'
CONFINE_GIT_TIME=0 lib "$R" 'confine_git_limit rev-parse; printf "%s" "$CONFINE_LIMIT"'
check "... and confine_init drops one the environment passes in" out_is 10
# With a limit, git keeps the caller's standard input and its own status, and a call that ends at once
# returns at once: the watcher holds none of its output.
lib "$R" 'printf "HEAD\n" | CONFINE_GIT_TIME=5 hgit "$CONFINE_WT" cat-file --batch-check="%(objecttype)"; CONFINE_GIT_TIME=5 hgit "$CONFINE_WT" rev-parse --verify --quiet nosuch; printf "%s" "$?"'
check "under a limit git reads the caller's standard input and keeps its status" out_is "$(printf 'commit\n1')"
BOUND=50 bounded /dev/null lib "$R" 'b=$(CONFINE_GIT_TIME=30 hgit "$CONFINE_WT" rev-parse --abbrev-ref HEAD); printf "%s" "$b"'
check "... and a call that ends at once returns at once" out_is main
# The limit and the checks need only the shell and the programs hgit needs: no sleep, sh or grep.
mkdir -p "$T/minpath"
for t in env git find wc cat; do ln -s "$(command -v "$t")" "$T/minpath/$t"; done
LIB_PATH="$T/minpath" lib "$R" 'hgit "$CONFINE_WT" rev-parse --abbrev-ref HEAD'
check "hgit answers a question on a PATH of env, git, find, wc and cat alone" out_is main

# =================================================================================================
# Repositories: the top level, git directories inside WT, partial clones, and what is tracked.
# =================================================================================================
O="$T/outside-repo"; mkrepo "$O"; put "$O" s.txt 'outside'; commit "$O" -m outside
RW="$T/rw"; mkrepo "$RW"; put "$RW" programs/x.rs 'fn x() {}'; commit "$RW" -m x
git clone -q --bare "$RW" "$RW/copy.git"
mkdir -p "$RW/plain" "$RW/gitfile" "$RW/gitlink"
printf 'gitdir: %s/.git\n' "$O" > "$RW/gitfile/.git"
ln -s "$O/.git" "$RW/gitlink/.git"
for d in linked alt wtree grafted; do mkrepo "$RW/$d"; put "$RW/$d" f "$d"; commit "$RW/$d" -m "$d"; done
git -C "$RW/grafted" rev-parse HEAD > "$RW/grafted/.git/info/grafts"
ln -s "$O/.git/HEAD" "$RW/linked/.git/refs/heads/elsewhere"
printf '%s/.git/objects\n' "$O" > "$RW/alt/.git/objects/info/alternates"
git -C "$RW/wtree" config core.worktree "$O"
lib "$RW" 'confine_repo . R; printf "%s|%s|%s|%s" "$CONFINE_REPO" "$CONFINE_GIT_DIR" "$CONFINE_COMMON_DIR" "$CONFINE_BARE"'
check "confine_repo accepts the working directory's repository" out_is "$RW|$RW/.git|$RW/.git|false"
lib "$RW" 'confine_repo copy.git R; printf "%s|%s|%s|%s" "$CONFINE_REPO" "$CONFINE_GIT_DIR" "$CONFINE_COMMON_DIR" "$CONFINE_BARE"'
check "... and a bare repository inside it" out_is "$RW/copy.git|$RW/copy.git|$RW/copy.git|true"
lib "$RW" 'confine_repo programs R'
check "a directory inside the repository is not its top level" refused 'R is not the top level of its repository: programs'
lib "$RW" 'confine_repo plain/../programs R'
check "... nor reached with .." refused 'R has an empty, . or .. component: plain/../programs'
lib "$RW" 'confine_repo gitfile R'
check "a .git file naming a repository outside is refused" refused 'R keeps its git directory outside the working directory: gitfile'
lib "$RW" 'confine_repo gitlink R'
check "a .git link to a repository outside is refused" refused 'R keeps its git directory outside the working directory: gitlink'
lib "$RW" 'confine_repo linked R'
check "a symbolic link inside the git directory is refused" refused 'R has a symbolic link in its git directory: linked'
lib "$RW" 'confine_repo alt R'
check "a repository with alternates is refused" \
  refused 'R borrows objects from another repository (objects/info/alternates); audit a full copy: alt'
lib "$RW" 'confine_repo wtree R'
check "a repository whose work tree is elsewhere is refused" refused 'R is not the top level of its repository: wtree'
lib "$RW" 'confine_repo grafted R'
check "a repository that rewrites commit parents with info/grafts is refused" \
  refused 'R rewrites commit parents (info/grafts), so git would show another history; review that file: grafted'
lib "$RW/plain" 'confine_repo . R'
check "a working directory that is not a repository top level is refused (discovery stops at WT's parent)" \
  refused 'R is not a git repository that git can read (none there, or another user owns it: audit a copy): .'
lib "$RW" 'confine_repo_top "$CONFINE_WT" && printf top; confine_repo_top "$CONFINE_WT/programs" || printf " not-top"; confine_repo_top "$CONFINE_WT/copy.git" && printf " bare-top"'
check "confine_repo_top: a top level, a subdirectory, a bare repository" out_is 'top not-top bare-top'
lib "$RW" 'confine_partial_clone "$CONFINE_WT"; printf "%s" "$?"'
check "confine_partial_clone: not partial (1)" out_is 1
git -C "$RW/linked" config remote.origin.promisor true
git -C "$RW/alt" config extensions.partialClone origin
lib "$RW" 'confine_partial_clone "$CONFINE_WT/linked"; printf "|%s|" "$?"; confine_partial_clone "$CONFINE_WT/alt"; printf "|%s" "$?"'
check "confine_partial_clone: partial (0), printing the key" \
  out_is "$(printf 'remote.origin.promisor true\n|0|extensions.partialclone origin\n|0')"
if [ "$(id -u)" -ne 0 ]; then
  chmod 000 "$RW/wtree/.git/config"
  lib "$RW" 'confine_partial_clone "$CONFINE_WT/wtree"; printf "%s" "$?"'
  check "confine_partial_clone: an unreadable config cannot be ruled out (2)" out_is 2
  chmod 600 "$RW/wtree/.git/config"
else
  skp "running as root: an unreadable config cannot be made"
fi
put "$RW" Audit_9/notes 'tracked'
commit "$RW" -m 'tracked run directory'
lib "$RW" 'confine_tracked audit_9; printf "[%s]" "$?"; confine_tracked audit_8; printf "[%s]" "$?"'
check "confine_tracked lists a path tracked in another letter case, and nothing for an untracked one" \
  out_is "$(printf 'Audit_9/notes\n[0][0]')"
lib "$RW/plain" 'confine_tracked x; printf "[%s]" "$?"'
check "confine_tracked asks the repository above the working directory" out_is '[0]'
put "$RW" plain/audit_2/x 'x'
commit "$RW" -m nested
lib "$RW/plain" 'confine_tracked audit_2; printf "[%s]" "$?"'
check "... and lists what it tracks under the working directory" out_is "$(printf 'audit_2/x\n[0]')"
mkdir -p "$T/norepo/d"
lib "$T/norepo/d" 'confine_tracked x; printf "[%s]" "$?"'
check "outside every repository nothing is tracked" out_is '[0]'
if [ "$(id -u)" -ne 0 ]; then
  chmod 000 "$RW/.git/index"
  lib "$RW" 'confine_tracked audit_9; printf "[%s]" "$?"'
  check "confine_tracked fails closed (2) when git cannot read the index" out_is '[2]'
  chmod 600 "$RW/.git/index"
else
  skp "running as root: an unreadable index cannot be made"
fi

# =================================================================================================
# Repositories git describes in a way that would pass the checks above: a value printed across lines, a
# common directory apart from the git directory, and files git would wait on for good.
# =================================================================================================
# shown <s>: <s> as a refusal line shows it, cut after 200 bytes
shown() { if [ "${#1}" -gt 200 ]; then printf '%s...' "${1:0:200}"; else printf '%s' "$1"; fi; }
# A core.worktree holding a line end: git prints the top level across two lines, and the old split read
# the alternates and grafts of a directory the repository chose instead of its own.
mkrepo "$RW/wtnl"; put "$RW/wtnl" f wtnl; commit "$RW/wtnl" -m wtnl
printf '%s/.git/objects\n' "$O" > "$RW/wtnl/.git/objects/info/alternates"
if mkdir -p "$RW/wtnl/z"$'\n'"$RW/wtnl" "$RW/wtnl/.git"$'\n'"$RW/wtnl/z" 2>/dev/null; then
  printf '[core]\n\tworktree = %s\n' "$RW/wtnl/z\\n$RW/wtnl" >> "$RW/wtnl/.git/config"
  lib "$RW" 'confine_repo wtnl R'
  check "a core.worktree holding a line end is refused, not read past the alternates check" \
    refused 'git describes the repository at R with a line end or control character inside a path: wtnl'
else
  skp "this filesystem refuses a newline in a directory name: the core.worktree line-end case"
fi
# A commondir file naming a repository outside: git takes objects, refs and config from the common
# directory, which must lie inside as the git directory does.
mkrepo "$RW/cdir"; put "$RW/cdir" f cdir; commit "$RW/cdir" -m cdir
printf '%s/.git\n' "$O" > "$RW/cdir/.git/commondir"
lib "$RW" 'confine_repo cdir R'
check "a git directory whose commondir names a repository outside is refused" \
  refused 'R keeps its git directory outside the working directory: cdir'
# A linked worktree of a repository inside: a common directory apart from its git directory, checked too.
mkrepo "$RW/main"; put "$RW/main" f main; commit "$RW/main" -m main
git -C "$RW/main" worktree add -q -b linked "$RW/linkedwt" >/dev/null 2>&1
lib "$RW" 'confine_repo linkedwt R; printf "%s|%s" "$CONFINE_GIT_DIR" "$CONFINE_COMMON_DIR"'
check "a linked worktree of a repository inside is accepted, with its common directory apart" \
  out_is "$RW/main/.git/worktrees/linkedwt|$RW/main/.git"
ln -s "$O/.git/HEAD" "$RW/main/.git/refs/heads/elsewhere"
lib "$RW" 'confine_repo linkedwt R'
check "... and refused once that common directory holds a symbolic link" refused 'R has a symbolic link in its git directory: linkedwt'
rm "$RW/main/.git/refs/heads/elsewhere"
# Named pipes: git opens them with a blocking open and waits for good, so each is refused before git
# starts (each run bounded, as at the top).
if mkfifo "$T/fifo-probe" 2>/dev/null; then
  mkrepo "$RW/fifohead"; put "$RW/fifohead" f x; commit "$RW/fifohead" -m x
  rm "$RW/fifohead/.git/HEAD"; mkfifo "$RW/fifohead/.git/HEAD"
  lib_bounded "$RW/fifohead/.git/HEAD" "$RW" 'confine_repo fifohead R'
  check "a named pipe as .git/HEAD is refused before git starts" \
    refused "a named pipe or device is in the git directory, and git would wait on it for good: $(shown "$RW/fifohead/.git")"
  mkrepo "$RW/fifoinc"; put "$RW/fifoinc" f x; commit "$RW/fifoinc" -m x
  mkfifo "$RW/fifoinc/pipe"
  printf '[include]\n\tpath = ../pipe\n' >> "$RW/fifoinc/.git/config"
  lib_bounded "$RW/fifoinc/pipe" "$RW" 'confine_repo fifoinc R'
  check "... and one the repository's config includes from the work tree" \
    refused "a named pipe or device is included by the repository's config, and git would wait on it for good: ../pipe"
  mkrepo "$RW/fifoinc2"; put "$RW/fifoinc2" f x; commit "$RW/fifoinc2" -m x
  mkdir -p "$RW/fifoinc2/cfg"
  mkfifo "$RW/fifoinc2/cfg/pipe"
  printf '[include]\n\tpath = pipe\n' > "$RW/fifoinc2/cfg/more.cfg"
  printf '[includeIf "gitdir:**"]\n\tpath = ../cfg/more.cfg\n' >> "$RW/fifoinc2/.git/config"
  lib_bounded "$RW/fifoinc2/cfg/pipe" "$RW" 'confine_repo fifoinc2 R'
  check "... and one a file the config includes includes in turn, named relative to that file" \
    refused "a named pipe or device is included by the repository's config, and git would wait on it for good: pipe"
  # Includes that fan out over the same files: each file is read once, nearest first, and a named pipe
  # at the far end is still found. Here every file of a level includes all four of the next one.
  mkrepo "$RW/incfan"; put "$RW/incfan" f x; commit "$RW/incfan" -m x
  mkdir -p "$RW/incfan/i"
  mkfifo "$RW/incfan/i/pipe"
  for l in 1 2 3 4; do
    for i in 1 2 3 4; do
      { printf '[include]\n'
        if [ "$l" -lt 4 ]; then for j in 1 2 3 4; do printf '\tpath = %s.%s\n' "$((l + 1))" "$j"; done
        elif [ "$i" = 4 ]; then printf '\tpath = pipe\n'; fi; } > "$RW/incfan/i/$l.$i"
    done
  done
  { printf '[include]\n'; for j in 1 2 3 4; do printf '\tpath = ../i/1.%s\n' "$j"; done; } >> "$RW/incfan/.git/config"
  lib_bounded "$RW/incfan/i/pipe" "$RW" 'confine_repo incfan R'
  check "... and one at the far end of includes that fan out over the same files" \
    refused "a named pipe or device is included by the repository's config, and git would wait on it for good: pipe"
  mkrepo "$T/above"; put "$T/above" f x; commit "$T/above" -m x
  mkdir -p "$T/above/sub"
  rm "$T/above/.git/HEAD"; mkfifo "$T/above/.git/HEAD"
  lib_bounded "$T/above/.git/HEAD" "$T/above/sub" 'CONFINE_CEILING="" hgit "$CONFINE_WT" rev-parse --is-inside-work-tree'
  check "hgit refuses to start git on a repository above the working directory whose HEAD is a named pipe" \
    refused "a named pipe or device is in the git directory, and git would wait on it for good: $(shown "$T/above/.git")"
  lib_bounded "$T/above/.git/HEAD" "$T/above/sub" 'confine_tracked x; printf "[%s]" "$?"'
  check "... and confine_tracked fails closed (2) there" out_is '[2]'
  # A .git that git walks past on its way up (a HEAD alone; a HEAD it does not take, beside objects and
  # refs) does not end the check either: it goes on, as git does, to the repository above.
  mkdir -p "$T/above/sub/dec/.git" "$T/above/sub/bad/.git/objects" "$T/above/sub/bad/.git/refs" "$T/above/sub/gf/gd"
  printf 'ref: refs/heads/main\n' > "$T/above/sub/dec/.git/HEAD"
  : > "$T/above/sub/bad/.git/HEAD"
  for d in dec bad; do
    lib_bounded "$T/above/.git/HEAD" "$T/above/sub/$d" 'CONFINE_CEILING="" hgit "$CONFINE_WT" rev-parse --is-inside-work-tree'
    check "... and from below a .git that git walks past ($d)" \
      refused "a named pipe or device is in the git directory, and git would wait on it for good: $(shown "$T/above/.git")"
  done
  lib_bounded "$T/above/.git/HEAD" "$T/above/sub/dec" 'confine_tracked x; printf "[%s]" "$?"'
  check "... where confine_tracked fails closed (2) too" out_is '[2]'
  bounded "$T/above/.git/HEAD" script "$T/above/sub/dec" rundir.sh new audit
  check "rundir.sh new audit refuses there at once" refused_by rundir
  bounded "$T/above/.git/HEAD" script "$T/above/sub/dec" preflight.sh
  check "... and so does preflight.sh" refused_by preflight
  # A .git file is where git stops, whatever the directory it names holds: git runs, and fails on its own.
  printf 'ref: refs/heads/main\n' > "$T/above/sub/gf/gd/HEAD"
  printf 'gitdir: gd\n' > "$T/above/sub/gf/.git"
  lib_bounded "$T/above/.git/HEAD" "$T/above/sub/gf" 'CONFINE_CEILING="" hgit "$CONFINE_WT" rev-parse --is-inside-work-tree'
  check "... while below a .git file, where git stops, git runs and fails on its own" test "$RC" = 128
  # The same for a repository inside the working directory, through git-ro.sh --repo.
  mkrepo "$RW/up"; put "$RW/up" sub/f x; commit "$RW/up" -m x
  rm "$RW/up/.git/HEAD"; mkfifo "$RW/up/.git/HEAD"
  mkdir "$RW/up/sub/.git"
  printf 'ref: refs/heads/main\n' > "$RW/up/sub/.git/HEAD"
  bounded "$RW/up/.git/HEAD" script "$RW" git-ro.sh --repo up/sub log --oneline
  check "git-ro.sh --repo refuses a repository below one whose HEAD is a named pipe, past a .git git walks past" \
    sh -c "[ '$RC' = 64 ] && [ \"\$(cat '$T/err')\" = 'git-ro: refused: a named pipe or device is in the git directory, and git would wait on it for good: $(shown "$RW/up/.git")' ]"
  # A named pipe these checks do not see, behind a link to a directory outside the git directory: git
  # waits on it, and the time limit ends that. 2 s set for one call; 10 s by default for rev-parse.
  mkrepo "$T/lr"; put "$T/lr" f x; commit "$T/lr" -m x
  mkdir -p "$T/lr-out"
  mv "$T/lr/.git/refs/heads" "$T/lr-out/heads"
  ln -s "$T/lr-out/heads" "$T/lr/.git/refs/heads"
  rm "$T/lr-out/heads/main"; mkfifo "$T/lr-out/heads/main"
  lib_bounded "$T/lr-out/heads/main" "$T/lr" 'CONFINE_GIT_TIME=2 hgit "$CONFINE_WT" rev-parse --verify HEAD'
  check "git that has not answered within the time it was given is killed, and the call refused" \
    refused "git has not answered within 2 s in $(shown "$T/lr"), so a file it opens there may be a named pipe or device that it would wait on for good"
  BOUND=350 lib_bounded "$T/lr-out/heads/main" "$T/lr" 'hgit "$CONFINE_WT" rev-parse --verify HEAD'
  check "... after 10 s by default for a question such as rev-parse" \
    refused "git has not answered within 10 s in $(shown "$T/lr"), so a file it opens there may be a named pipe or device that it would wait on for good"
  LIB_PATH="$T/minpath" lib_bounded "$T/lr-out/heads/main" "$T/lr" 'CONFINE_GIT_TIME=2 hgit "$CONFINE_WT" rev-parse --verify HEAD'
  check "... also on a PATH of env, git, find, wc and cat alone" \
    refused "git has not answered within 2 s in $(shown "$T/lr"), so a file it opens there may be a named pipe or device that it would wait on for good"
  # The files git reads in the work tree of a repository whose history it shows, which reads take no
  # time limit: .mailmap, and .gitattributes and .gitignore in any directory. A named pipe there, or a
  # link to one, is refused; a link to a regular file passes.
  mkrepo "$RW/wtpipe"; put "$RW/wtpipe" src/f x; put "$RW/wtpipe" src/g y; commit "$RW/wtpipe" -m x
  printf 'z\n' >> "$RW/wtpipe/src/f"; git -C "$RW/wtpipe" commit -q -am y
  wtmsg='a named pipe or device is where git reads its own files in the work tree, and git would wait on it for good'
  mkfifo "$RW/wtpipe/.mailmap"
  lib_bounded "$RW/wtpipe/.mailmap" "$RW" 'confine_repo wtpipe R'
  check "a named pipe as the work tree's .mailmap is refused" refused "$wtmsg: $(shown "$RW/wtpipe/.mailmap")"
  bounded "$RW/wtpipe/.mailmap" script "$RW" git-ro.sh --repo wtpipe log -1
  check "... so git-ro.sh log refuses at once" refused_by git-ro
  bounded "$RW/wtpipe/.mailmap" script "$RW" git-ro.sh --repo wtpipe shortlog HEAD
  check "... and so does git-ro.sh shortlog" refused_by git-ro
  rm "$RW/wtpipe/.mailmap"
  mkfifo "$RW/wtpipe/src/.gitattributes"
  bounded "$RW/wtpipe/src/.gitattributes" script "$RW" git-ro.sh --repo wtpipe diff HEAD~1 HEAD
  check "... and a named pipe as a .gitattributes below: git-ro.sh diff refuses at once" refused_by git-ro
  lib_bounded "$RW/wtpipe/src/.gitattributes" "$RW" 'confine_repo_top "$CONFINE_WT/wtpipe" && printf top || printf not-top'
  check "... and confine_repo_top fails there" out_is not-top
  rm "$RW/wtpipe/src/.gitattributes"
  mkfifo "$RW/wtpipe/pipe"
  ln -s pipe "$RW/wtpipe/.gitignore"
  lib_bounded "$RW/wtpipe/pipe" "$RW" 'confine_repo wtpipe R'
  check "... and a .gitignore that is a link to a named pipe" refused "$wtmsg: $(shown "$RW/wtpipe/.gitignore")"
  rm "$RW/wtpipe/.gitignore" "$RW/wtpipe/pipe"
  ln -s src/g "$RW/wtpipe/.gitignore"
  lib "$RW" 'confine_repo wtpipe R; printf "%s" "$CONFINE_BARE"'
  check "... while a .gitignore that is a link to a regular file passes" out_is false
else
  skp "mkfifo is not available: the named pipe cases"
fi
# A git directory holding 2000 symbolic links: one find lists them and the shell tests each, so rundir.sh
# and confine_repo end within 5 s (a find -exec per link took minutes).
mkrepo "$RW/links"; put "$RW/links" f x; commit "$RW/links" -m x
mkdir "$RW/links/.git/many"
set --
i=0
while [ "$i" -lt 2000 ]; do set -- "$@" "../h$i"; i=$((i + 1)); done
(cd "$RW/links/.git/many" && ln -s "$@" .)
set --
BOUND=50 bounded /dev/null script "$RW/links" rundir.sh new audit
check "rundir.sh new audit in a repository whose git directory holds 2000 links ends within 5 s" sh -c "[ '$RC' = 0 ] && [ \"\$(cat '$T/out')\" = audit_1 ]"
BOUND=50 bounded /dev/null lib "$RW" 'confine_repo links R'
check "... and confine_repo refuses that git directory for its links within 5 s" refused 'R has a symbolic link in its git directory: links'
# git makes no name with a line end, and the links are read one to a line: such a name is refused.
mkrepo "$RW/nlname"; put "$RW/nlname" f x; commit "$RW/nlname" -m x
if : > "$RW/nlname/.git/a"$'\n'"b" 2>/dev/null; then
  lib "$RW" 'confine_repo nlname R'
  check "a git directory holding a name with a line end is refused" \
    refused "a name in the git directory holds a line end: $(shown "$RW/nlname/.git")"
else
  skp "this filesystem refuses a newline in a file name: the line-end name case"
fi
# A config that includes itself six times: each file is read once, so the check ends at once, and git's
# own refusal (it stops at a depth of 10) follows. More than 64 included files, a file git cannot read as
# config, and a file name holding a line end are refused before git starts.
mkrepo "$RW/incself"; put "$RW/incself" f x; commit "$RW/incself" -m x
{ printf '[include]\n'; for i in 1 2 3 4 5 6; do printf '\tpath = config\n'; done; } >> "$RW/incself/.git/config"
bounded /dev/null lib "$RW" 'confine_repo incself R'
check "a config that includes itself six times is read once, then git refuses it at once" \
  refused 'R is not a git repository that git can read (none there, or another user owns it: audit a copy): incself'
# 8 files, each including 9 more: 80 files in all, no file listing more than 9.
mkrepo "$RW/incmany"; put "$RW/incmany" f x; commit "$RW/incmany" -m x
printf '[include]\n' >> "$RW/incmany/.git/config"
for i in 0 1 2 3 4 5 6 7; do
  printf '\tpath = a%s\n' "$i" >> "$RW/incmany/.git/config"
  printf '[include]\n' > "$RW/incmany/.git/a$i"
  for j in 0 1 2 3 4 5 6 7 8; do
    printf '\tpath = b%s%s\n' "$i" "$j" >> "$RW/incmany/.git/a$i"
    printf '[core]\n' > "$RW/incmany/.git/b$i$j"
  done
done
lib "$RW" 'confine_repo incmany R'
check "a config that includes more than 64 files in all is refused" \
  refused "the repository's config includes more than 64 files, more than these checks follow"
mkrepo "$RW/incvals"; put "$RW/incvals" f x; commit "$RW/incvals" -m x
{ printf '[include]\n'; i=0; while [ "$i" -lt 65 ]; do printf '\tpath = one\n'; i=$((i + 1)); done; } >> "$RW/incvals/.git/config"
printf '[core]\n' > "$RW/incvals/.git/one"
lib "$RW" 'confine_repo incvals R'
check "... and one whose config lists more than 64 includes, even of one file" \
  refused "a config file of the repository lists more than 64 includes, more than these checks follow: $(shown "$RW/incvals/.git/config")"
mkrepo "$RW/incbad"; put "$RW/incbad" f x; commit "$RW/incbad" -m x
printf '[include\n' > "$RW/incbad/.git/junk"
printf '[include]\n\tpath = junk\n' >> "$RW/incbad/.git/config"
lib "$RW" 'confine_repo incbad R'
check "... and one that includes a file git cannot read as config" \
  refused "git cannot list what this config file includes: $(shown "$RW/incbad/.git/junk")"
mkrepo "$RW/incnl"; put "$RW/incnl" f x; commit "$RW/incnl" -m x
printf '[include]\n\tpath = "a\\nb"\n' >> "$RW/incnl/.git/config"
lib "$RW" 'confine_repo incnl R'
check "... and one that includes a file whose name holds a line end" \
  refused "the repository's config includes a file whose name holds a line end"
# A socket in the git directory (git's own fsmonitor daemon keeps one there) does not block an open, and
# passes. Making one needs a machine that allows it: on CI one that does not fails, elsewhere a skip.
mkrepo "$RW/sock"; put "$RW/sock" f x; commit "$RW/sock" -m x
if python3 -I -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$RW/sock/.git/s" 2>/dev/null &&
   [ -S "$RW/sock/.git/s" ]; then
  lib "$RW" 'confine_repo sock R; printf "%s" "$CONFINE_BARE"'
  check "a socket in the git directory is let through" out_is false
elif [ "${CI:-}" = true ]; then
  ko "a socket in the git directory: this machine does not let the suite make a Unix socket"
else
  skp "this machine does not let the suite make a Unix socket: the socket case (on CI this fails)"
fi

echo
echo "confine tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
