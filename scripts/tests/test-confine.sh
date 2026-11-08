#!/usr/bin/env bash
# test-confine.sh — self-test for scripts/lib/confine.sh, the checks the bundled entry points share: the
# working directory and installation checks of confine_init, the cleaned PATH, the mode (AUDITOR_STRICT,
# strict markers, the global git config of each mode), confined paths (the case
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
unset AUDITOR_STRICT
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
# The mode (Rule 11f): AUDITOR_STRICT, the strict markers of run directories, confine_strict_on, and
# the global git config hgit gives git in each mode.
# =================================================================================================
SAFE="$ROOT/scripts/lib/safe-directory.gitconfig"
MODE='printf "%s|%s|%s|%s" "$CONFINE_STRICT" "$CONFINE_MODE_WHY" "$CONFINE_MARKERS" "$CONFINE_GIT_GLOBAL"'
mkdir -p "$T/mode/plain"
lib "$T/mode/plain" "$MODE"
check "with AUDITOR_STRICT unset and no marker the mode is default, with the safe-directory file as git's global config" \
  out_is "0|||$SAFE"
for v in '' 0 false FALSE No off OFF; do
  AUDITOR_STRICT=$v lib "$T/mode/plain" "$MODE"
  check "AUDITOR_STRICT='$v' leaves the mode default" out_is "0|||$SAFE"
done
for v in 1 true TRUE Yes on ON; do
  AUDITOR_STRICT=$v lib "$T/mode/plain" "$MODE"
  check "AUDITOR_STRICT=$v turns strict mode on, with no global git config" out_is "1|AUDITOR_STRICT=$v||/dev/null"
done
for v in maybe 2 ' 1' strict; do
  AUDITOR_STRICT=$v lib "$T/mode/plain" "$MODE; printf \"|%s\" \"\$CONFINE_MODE_NOTE\""
  check "AUDITOR_STRICT='$v' is read as on, with one note on stderr and no refusal" \
    test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|1|AUDITOR_STRICT=$v||/dev/null|AUDITOR_STRICT is '$v', read as on|test: note: AUDITOR_STRICT is '$v', read as on"
done
AUDITOR_STRICT=$'a\001b' lib "$T/mode/plain" "$MODE"
check "... and the note shows a control character in the value as ?" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|1|AUDITOR_STRICT=a?b||/dev/null|test: note: AUDITOR_STRICT is 'a?b', read as on"
printf '[safe]\n\tdirectory = *\n' > "$T/safe.want"
check "the safe-directory file holds [safe] and directory = *, and nothing else" cmp -s "$SAFE" "$T/safe.want"
lib "$T/mode/plain" 'confine_strict_on --strict; '"$MODE"
check "confine_strict_on turns strict mode on and names its source" out_is "1|--strict||/dev/null"
AUDITOR_STRICT=yes lib "$T/mode/plain" 'confine_strict_on --strict; '"$MODE"
check "... but AUDITOR_STRICT, which comes first, stays the named source" out_is "1|AUDITOR_STRICT=yes||/dev/null"
lib "$T/mode/plain" 'printf "[%s]" "$CONFINE_PREFIX"'
check "CONFINE_PREFIX starts empty" out_is '[]'
CONFINE_STRICT=1 CONFINE_MODE_WHY=x CONFINE_MARKERS=audit_1/strict CONFINE_GIT_GLOBAL=/etc/passwd CONFINE_PREFIX=p/ \
  lib "$T/mode/plain" "$MODE"'; printf "|%s" "$CONFINE_PREFIX"'
check "... and the environment sets none of the mode's variables" out_is "0|||$SAFE|"
lib "$T/mode/plain" 'confine_note "a b"; printf ran'
check "confine_note prints one note line on stderr" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|ran|test: note: a b"
lib "$T/mode/plain" 'confine_strict_refuse "the reason" "the note"; printf "went on"'
check "confine_strict_refuse notes in default mode and goes on" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|went on|test: note: the note"
lib "$T/mode/plain" 'confine_strict_refuse "the reason" ""; printf "went on"'
check "... silently when the note is empty" out_is 'went on'
AUDITOR_STRICT=1 lib "$T/mode/plain" 'confine_strict_refuse "the reason" "the note"; printf "went on"'
check "... and refuses in strict mode" refused 'the reason'
lib "$T/mode/plain" 'confine_strict_on --strict; confine_strict_refuse "the reason" "the note"; printf "went on"'
check "... also once confine_strict_on has run" refused 'the reason'

# Markers: an entry named strict, of any kind, in a run directory of the working directory.
mk_mode_wt() { rm -rf "$T/mode/w" && mkdir -p "$T/mode/w"; } # a fresh working directory, $T/mode/w
mk_mode_wt; mkdir "$T/mode/w/audit_1"; printf 'strict\n' > "$T/mode/w/audit_1/strict"
lib "$T/mode/w" "$MODE"
check "a strict marker in a run directory turns strict mode on and is named" out_is "1|audit_1/strict|audit_1/strict|/dev/null"
for kind in empty dir link dangling; do
  mk_mode_wt; mkdir "$T/mode/w/incident_2"
  case "$kind" in
    empty) : > "$T/mode/w/incident_2/strict" ;;
    dir) mkdir "$T/mode/w/incident_2/strict" ;;
    link) ln -s "$T/safe.want" "$T/mode/w/incident_2/strict" ;;
    dangling) ln -s nowhere "$T/mode/w/incident_2/strict" ;;
  esac
  lib "$T/mode/w" "$MODE"
  check "... and so does a marker that is $kind" out_is "1|incident_2/strict|incident_2/strict|/dev/null"
done
for d in audit_x audit_ Audit_3 AUDIT_3 audit_1234567 report_1 audit_1a; do
  mk_mode_wt; mkdir "$T/mode/w/$d"; : > "$T/mode/w/$d/strict"
  lib "$T/mode/w" "$MODE"
  check "a strict entry in $d, which is no run directory name, counts for nothing" out_is "0|||$SAFE"
done
mk_mode_wt; mkdir "$T/mode/w/audit_1"; : > "$T/mode/w/audit_1/STRICT"; : > "$T/mode/w/audit_1/strict.txt"
if [ -e "$T/mode/w/audit_1/strict" ]; then
  skp "this volume ignores letter case: a STRICT entry is the strict marker here"
else
  lib "$T/mode/w" "$MODE"
  check "the marker's name is lowercase strict: STRICT and strict.txt count for nothing" out_is "0|||$SAFE"
fi
mk_mode_wt; mkdir -p "$T/mode/w/audit_2" "$T/mode/w/incident_1" "$T/mode/w/audit_3"
: > "$T/mode/w/audit_2/strict"; : > "$T/mode/w/incident_1/strict"
lib "$T/mode/w" "$MODE"
check "every marker is listed, the first named as the source" \
  out_is "1|audit_2/strict|audit_2/strict incident_1/strict|/dev/null"
AUDITOR_STRICT=1 lib "$T/mode/w" "$MODE"
check "... after AUDITOR_STRICT, which comes first" out_is "1|AUDITOR_STRICT=1|audit_2/strict incident_1/strict|/dev/null"
lib "$T/mode/w" 'confine_strict_on --strict; '"$MODE"
check "... and after --strict, which comes before a marker" out_is "1|--strict|audit_2/strict incident_1/strict|/dev/null"
# git: asked only when a marker exists, once for them all, with the global config of strict mode.
mkdir -p "$T/mrec"
cat > "$T/mrec/git" <<EOF
#!/bin/sh
{ printf 'ARGV'; for a in "\$@"; do printf '\037%s' "\$a"; done; printf '\n'; env | sed 's/^/ENV /'; } >> "$T/mrec.log"
exec "$REAL_GIT" "\$@"
EOF
chmod +x "$T/mrec/git"
: > "$T/mrec.log"
LIB_PATH="$T/mrec:$PATH" lib "$T/mode/plain" ':'
check "with no marker the mode costs no git call" test ! -s "$T/mrec.log"
LIB_PATH="$T/mrec:$PATH" lib "$T/mode/w" ':'
check "with markers outside every repository git is asked once, and answers there is none" \
  test "$(awk -F '\037' '$1 == "ARGV" { for (i = 2; i <= NF; i++) if ($i == "rev-parse" || $i == "ls-files") print $i }' "$T/mrec.log" | tr '\n' ' ')" = 'rev-parse '
check "... with no global git config" test "$(sed -n 's/^ENV GIT_CONFIG_GLOBAL=//p' "$T/mrec.log" | sort -u)" = /dev/null
MR="$T/mode/r"; rm -rf "$MR"; mkrepo "$MR"
put "$MR" audit_5/REPORT.md 'tracked'; put "$MR" audit_8/strict 'strict'; commit "$MR" -m 'tracked run directories'
mkdir -p "$MR/audit_6"; : > "$MR/audit_5/strict"; : > "$MR/audit_6/strict"
: > "$T/mrec.log"
LIB_PATH="$T/mrec:$PATH" lib "$MR" "$MODE"
check "in a repository, a marker under a run directory git tracks anything under counts for nothing; one in an untracked run directory counts" \
  out_is "1|audit_6/strict|audit_6/strict|/dev/null"
check "... and git was asked once (one ls-files for all three)" \
  test "$(awk -F '\037' '$1 == "ARGV" { for (i = 2; i <= NF; i++) if ($i == "rev-parse" || $i == "ls-files") print $i }' "$T/mrec.log" | tr '\n' ' ')" = 'rev-parse ls-files '
rm "$MR/audit_6/strict"
lib "$MR" "$MODE"
check "... and with the untracked one gone, the mode is default" out_is "0|||$SAFE"
mkdir -p "$MR/AUDIT_9"
if [ -d "$MR/audit_9" ]; then
  rmdir "$MR/AUDIT_9"
  skp "this volume ignores letter case: a run directory tracked in other letters is one directory here"
else
  put "$MR" AUDIT_9/x 'tracked'; commit "$MR" -m 'other letters'
  mkdir -p "$MR/audit_9"; : > "$MR/audit_9/strict"
  lib "$MR" "$MODE"
  check "... and a marker under a run directory git tracks in other letters counts for nothing" out_is "0|||$SAFE"
  rm -rf "$MR/audit_9"
fi
mkdir -p "$MR/sub/audit_1" "$MR/sub/audit_2"; put "$MR" sub/audit_1/x 'tracked'; commit "$MR" -m sub
: > "$MR/sub/audit_1/strict"; : > "$MR/sub/audit_2/strict"
lib "$MR/sub" "$MODE"
check "... also when the repository lies above the working directory" out_is "1|audit_2/strict|audit_2/strict|/dev/null"
# When git cannot tell, the marker counts: a git that fails with no answer, and a checkout another user
# owns, which git refuses to read without the safe-directory file (git's own test knob stands for the
# other user).
mkdir -p "$T/mode/nogit" "$T/mode/other"
printf '#!/bin/sh\necho "fatal: something else" >&2\nexit 1\n' > "$T/mode/nogit/git"
printf '#!/bin/sh\nGIT_TEST_ASSUME_DIFFERENT_OWNER=1 exec "%s" "$@"\n' "$REAL_GIT" > "$T/mode/other/git"
chmod +x "$T/mode/nogit/git" "$T/mode/other/git"
: > "$MR/audit_5/strict"
LIB_PATH="$T/mode/nogit:$PATH" lib "$MR" "$MODE"
check "a marker counts when git cannot tell whether its run directory is tracked, a committed one too" \
  out_is "1|audit_5/strict|audit_5/strict audit_8/strict|/dev/null"
LIB_PATH="$T/mode/other:$PATH" lib "$MR" "$MODE"
check "... so in a checkout another user owns, markers in tracked run directories count" \
  out_is "1|audit_5/strict|audit_5/strict audit_8/strict|/dev/null"
rm -f "$MR/audit_5/strict"
MO="$T/mode/o"; mkrepo "$MO"; put "$MO" f 'x'; commit "$MO" -m x
LIB_PATH="$T/mode/other:$PATH" lib "$MO" "$MODE"'; printf "|"; hgit "$CONFINE_WT" rev-parse --is-inside-work-tree'
check "in default mode hgit reads a checkout another user owns, through the safe-directory file" out_is "0|||$SAFE|true"
AUDITOR_STRICT=1 LIB_PATH="$T/mode/other:$PATH" lib "$MO" 'hgit "$CONFINE_WT" rev-parse --is-inside-work-tree; printf "|%s" "$?"'
check "... and in strict mode git refuses it, as with no global config" \
  test "$(cat "$T/out")|$(head -n 1 "$T/err")" = "|128|fatal: detected dubious ownership in repository at '$MO'"
LIB_PATH="$T/mode/other:$PATH" lib "$MO" 'confine_strict_on --strict; hgit "$CONFINE_WT" rev-parse --is-inside-work-tree; printf "|%s" "$?"'
check "... and so it does once confine_strict_on has run" \
  test "$(cat "$T/out")|$(head -n 1 "$T/err")" = "|128|fatal: detected dubious ownership in repository at '$MO'"

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
check "a run directory holding a symbolic link out of it is refused" refused 'R holds a symbolic link: audit_3'
AUDITOR_STRICT=1 lib "$WT" 'confine_rundir audit_3 R'
check "... in strict mode too" refused 'R holds a symbolic link: audit_3'
# In default mode a link that resolves inside the run directory, every link on the way followed, passes
# (CONF-15); strict mode refuses any link. One that leads nowhere, in a loop, or out through another
# link inside still counts as out.
mkdir -p "$WT/audit_8/poc/a/b"
printf '*\n' > "$WT/audit_8/.gitignore"
ln -s a "$WT/audit_8/poc/latest"
ln -s ../../.gitignore "$WT/audit_8/poc/a/gi"
ln -s latest/b "$WT/audit_8/poc/chain"
ln -s .. "$WT/audit_8/poc/up"
lib "$WT" 'confine_rundir audit_8 R; printf "%s" "$CONFINE_RUN"'
check "a run directory whose links all resolve inside it passes in default mode" out_is audit_8
AUDITOR_STRICT=1 lib "$WT" 'confine_rundir audit_8 R'
check "... and is refused in strict mode" refused 'R holds a symbolic link: audit_8'
for bad in dangling:nowhere loop:loop out-through:up/.. out-abs:"$T/outside"; do
  ln -s "${bad#*:}" "$WT/audit_8/poc/${bad%%:*}"
  lib "$WT" 'confine_rundir audit_8 R'
  check "... but one holding a link that leads ${bad%%:*} is refused in default mode too" refused 'R holds a symbolic link: audit_8'
  rm "$WT/audit_8/poc/${bad%%:*}"
done
# When git cannot tell whether the run directory is tracked, its .gitignore of * is enough in default
# mode (CONF-16); strict mode refuses. A git that fails with no answer stands for that.
mkdir -p "$T/cantell"
printf '#!/bin/sh\necho "fatal: something else" >&2\nexit 1\n' > "$T/cantell/git"
chmod +x "$T/cantell/git"
LIB_PATH="$T/cantell:$PATH" lib "$WT" 'confine_rundir audit_1 R; printf "%s" "$CONFINE_RUN"'
check "a run directory git cannot tell about passes in default mode on its .gitignore of *" out_is audit_1
LIB_PATH="$T/cantell:$PATH" lib "$WT" 'confine_rundir audit_2 R'
check "... which it still needs" refused 'R has no .gitignore holding exactly *: audit_2'
AUDITOR_STRICT=1 LIB_PATH="$T/cantell:$PATH" lib "$WT" 'confine_rundir audit_1 R'
check "... and strict mode refuses it" refused 'git cannot tell whether R is tracked: audit_1'
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
# The transport allowlist is empty unless the caller sets CONFINE_ALLOW_PROTOCOL for one call: a value the
# environment passes in widens no call.
: > "$T/rec.log"
CONFINE_ALLOW_PROTOCOL=ext PATH="$T/rec:$PATH" \
  lib "$R" 'hgit "$CONFINE_WT" rev-parse --abbrev-ref HEAD; CONFINE_ALLOW_PROTOCOL=file hgit "$CONFINE_WT" rev-parse --abbrev-ref HEAD'
check "hgit gives git an empty GIT_ALLOW_PROTOCOL whatever CONFINE_ALLOW_PROTOCOL the environment holds, and one call its own" \
  test "$RC:$(sed -n 's/^ENV GIT_ALLOW_PROTOCOL=/=/p' "$T/rec.log" | sort -u | tr '\n' ' ')" = '0:= =file '
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
UNREAD='test: note: R keeps its git directory outside the working directory, and nothing there ties it back to this working tree, so its history is not read; strict mode refuses this (Rule 11f)'
for d in gitfile gitlink; do
  D=$d lib "$RW" 'confine_repo "$D" R 0; printf "went on"'
  check "given a status, in default mode a git directory outside that nothing ties back ($d) gets a note, and the tool ends with it" \
    test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0||$UNREAD"
  D=$d AUDITOR_STRICT=1 lib "$RW" 'confine_repo "$D" R 0; printf "went on"'
  check "... and in strict mode is refused ($d)" refused "R keeps its git directory outside the working directory: $d"
done
lib "$RW" 'confine_repo linked R'
check "a symbolic link inside the git directory is refused" refused 'R has a symbolic link in its git directory: linked'
AUDITOR_STRICT=1 lib "$RW" 'confine_repo linked R'
check "... in strict mode too" refused 'R has a symbolic link in its git directory: linked'
AUDITOR_STRICT=1 lib "$RW" 'confine_repo alt R'
check "in strict mode a repository with alternates is refused" \
  refused 'R borrows objects from another repository (objects/info/alternates); audit a full copy: alt'
lib "$RW" 'confine_repo alt R; printf "%s" "$CONFINE_BARE"'
check "... and in default mode read, with one note (CONF-08)" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|false|test: note: R borrows objects from another repository (objects/info/alternates), so its history is read from there too; strict mode refuses this (Rule 11f)"
lib "$RW" 'confine_repo wtree R'
check "a repository whose work tree is elsewhere is refused" refused 'R is not the top level of its repository: wtree'
AUDITOR_STRICT=1 lib "$RW" 'confine_repo grafted R'
check "in strict mode a repository that rewrites commit parents with info/grafts is refused" \
  refused 'R rewrites commit parents (info/grafts), so git would show another history; review that file: grafted'
lib "$RW" 'confine_repo grafted R; printf "%s" "$CONFINE_BARE"'
check "... and in default mode read, with one note (CONF-09)" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|false|test: note: R rewrites commit parents (info/grafts), so git shows the history that file sets; strict mode refuses this (Rule 11f)"
lib "$RW/plain" 'confine_repo . R'
check "a working directory under which its repository tracks nothing is refused (discovery stops at WT's parent)" \
  refused 'R is not a git repository that git can read (none there, or another user owns it: audit a copy): .'
AUDITOR_STRICT=1 lib "$RW/plain" 'confine_repo . R'
check "... in strict mode too" \
  refused 'R is not a git repository that git can read (none there, or another user owns it: audit a copy): .'
lib "$RW" 'confine_repo_top "$CONFINE_WT" && printf top; confine_repo_top "$CONFINE_WT/programs" || printf " not-top"; confine_repo_top "$CONFINE_WT/copy.git" && printf " bare-top"'
check "confine_repo_top: a top level, a subdirectory, a bare repository" out_is 'top not-top bare-top'
# A session started in a subdirectory of a repository that tracks something there (spec §4.2): in default
# mode confine_repo . takes the repository at its top level, with the working directory's path in it as
# the prefix, and hgit_tree reads from <empty>/<prefix>, so paths mean what they mean in the subdirectory.
# Strict mode refuses it by name. An explicit --repo below a top level stays refused (above).
lib "$RW/programs" 'confine_repo . R; printf "%s|%s|%s|%s" "$CONFINE_REPO" "$CONFINE_PREFIX" "$CONFINE_GIT_DIR" "$CONFINE_BARE"'
check "in default mode confine_repo . from a subdirectory takes the repository at its top level, with the prefix" \
  out_is "$RW|programs/|$RW/.git|false"
AUDITOR_STRICT=1 lib "$RW/programs" 'confine_repo . R'
check "... and strict mode refuses it, naming where the top level lies" \
  refused 'the working directory lies below the top level of its repository (..); strict mode reads a repository only from its top level: start Claude Code there (Rule 11f)'
mkdir -p "$T/tmps"
TMPDIR="$T/tmps" lib "$RW/programs" 'confine_repo . R && hgit_tree "$CONFINE_REPO" log --format=%s -- x.rs &&
  hgit_tree "$CONFINE_REPO" ls-tree --name-only HEAD && hgit_text_tree "$CONFINE_REPO" rev-parse --show-prefix'
check "... where hgit_tree and hgit_text_tree read from the subdirectory, as git does there" out_is "$(printf 'x\nx.rs\nprograms/')"
check "... and leave nothing under TMPDIR" test -z "$(ls -A "$T/tmps")"
# A symbolic link in a hooks directory (CONF-07): git opens no hook with core.hooksPath pinned to
# /dev/null, so default mode accepts it; any other link stays refused (above), since git reads through it.
mkrepo "$RW/hooklink"; put "$RW/hooklink" f x; commit "$RW/hooklink" -m x
mkdir -p "$T/hooks-src"; printf '#!/bin/sh\n' > "$T/hooks-src/pre-commit"
ln -s "$T/hooks-src/pre-commit" "$RW/hooklink/.git/hooks/pre-commit"
lib "$RW" 'confine_repo hooklink R; printf "%s" "$CONFINE_BARE"'
check "in default mode a symbolic link in the hooks directory is accepted" out_is false
AUDITOR_STRICT=1 lib "$RW" 'confine_repo hooklink R'
check "... and strict mode refuses it" refused 'R has a symbolic link in its git directory: hooklink'
rm -r "$RW/hooklink/.git/hooks"; ln -s "$T/hooks-src" "$RW/hooklink/.git/hooks"
lib "$RW" 'confine_repo hooklink R; printf "%s" "$CONFINE_BARE"'
check "... as is a hooks directory that is a link itself" out_is false
# Alternates in default mode: each object directory they name, and those its own alternates name, is
# checked as a git directory is; a quoted path, which these checks do not read as git does, is refused.
mkrepo "$RW/alt2"; put "$RW/alt2" f x; commit "$RW/alt2" -m x
git clone -q --bare "$O" "$T/alt-store.git"
git clone -q --bare "$O" "$T/alt-store2.git"
printf '# a comment\n\n%s/objects\n' "$T/alt-store.git" > "$RW/alt2/.git/objects/info/alternates"
lib "$RW" 'confine_repo alt2 R 2>/dev/null; printf "%s" "$CONFINE_BARE"'
check "in default mode alternates naming a plain object directory are read" out_is false
ln -s "$O/.git/HEAD" "$T/alt-store.git/objects/pick"
lib "$RW" 'confine_repo alt2 R'
check "... but not one that holds a symbolic link" \
  refused 'R borrows objects from a directory that holds a symbolic link, named pipe or device (objects/info/alternates): alt2'
rm "$T/alt-store.git/objects/pick"
printf '%s/objects\n' "$T/alt-store2.git" > "$T/alt-store.git/objects/info/alternates"
ln -s "$O/.git/HEAD" "$T/alt-store2.git/objects/pick"
lib "$RW" 'confine_repo alt2 R'
check "... nor one whose own alternates name such a directory" \
  refused 'R borrows objects from a directory that holds a symbolic link, named pipe or device (objects/info/alternates): alt2'
rm "$T/alt-store2.git/objects/pick" "$T/alt-store.git/objects/info/alternates"
printf '"%s/objects"\n' "$T/alt-store.git" > "$RW/alt2/.git/objects/info/alternates"
lib "$RW" 'confine_repo alt2 R'
check "... nor a quoted path" \
  refused 'R borrows objects through a quoted path in objects/info/alternates, which these checks do not read: alt2'
# Git's own layouts with a git directory outside (addendum I). In default mode a linked worktree whose main
# checkout lies elsewhere, a submodule opened from inside, and a separate git directory whose
# core.worktree names the working tree are read; strict mode refuses each. A gitdir file naming another
# tree, a separate git directory with no core.worktree (git init writes none), and a submodule its
# superproject does not track are not tied back.
MO2="$T/main-out"; mkrepo "$MO2"; put "$MO2" f main; commit "$MO2" -m main
git -C "$MO2" worktree add -q -b lw "$RW/lwout" >/dev/null 2>&1
lib "$RW" 'confine_repo lwout R 0; printf "%s|%s" "$CONFINE_GIT_DIR" "$CONFINE_COMMON_DIR"'
check "in default mode a linked worktree whose main checkout lies outside is read" out_is "$MO2/.git/worktrees/lwout|$MO2/.git"
AUDITOR_STRICT=1 lib "$RW" 'confine_repo lwout R 0'
check "... and refused in strict mode" refused 'R keeps its git directory outside the working directory: lwout'
cp "$MO2/.git/worktrees/lwout/gitdir" "$T/gitdir.kept"
printf '%s/.git\n' "$O" > "$MO2/.git/worktrees/lwout/gitdir"
lib "$RW" 'confine_repo lwout R 0; printf "went on"'
check "... but not one whose gitdir file names another tree" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0||$UNREAD"
cp "$T/gitdir.kept" "$MO2/.git/worktrees/lwout/gitdir"
SUP="$T/super"; mkrepo "$SUP"; put "$SUP" top.txt t; commit "$SUP" -m top
mkdir -p "$SUP/.git/modules"
git init -q --separate-git-dir="$SUP/.git/modules/sub" "$SUP/sub"
printf 'gitdir: ../.git/modules/sub\n' > "$SUP/sub/.git"
git -C "$SUP/sub" config core.worktree ../../../sub
git -C "$SUP/sub" symbolic-ref HEAD refs/heads/main; put "$SUP/sub" s.txt s; commit "$SUP/sub" -m sub
git -C "$SUP" update-index --add --cacheinfo "160000,$(git -C "$SUP/sub" rev-parse HEAD),sub"; commit "$SUP" -m 'add sub'
lib "$SUP/sub" 'confine_repo . R 0; printf "%s" "$CONFINE_GIT_DIR"'
check "in default mode a submodule opened from inside, whose core.worktree names it, is read" out_is "$SUP/.git/modules/sub"
AUDITOR_STRICT=1 lib "$SUP/sub" 'confine_repo . R 0'
check "... and refused in strict mode" refused 'R keeps its git directory outside the working directory: .'
git -C "$SUP/sub" config --unset core.worktree
lib "$SUP/sub" 'confine_repo . R 0; printf "%s" "$CONFINE_GIT_DIR"'
check "... and so is one with no core.worktree inside the top level of the superproject, which tracks it" out_is "$SUP/.git/modules/sub"
git -C "$SUP" rm -q --cached sub
lib "$SUP/sub" 'confine_repo . R 0; printf "went on"'
check "... but not once the superproject tracks it no more" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0||$UNREAD"
git init -q --separate-git-dir="$T/sep.git" "$RW/sep"
git -C "$RW/sep" symbolic-ref HEAD refs/heads/main; put "$RW/sep" f x; commit "$RW/sep" -m x
lib "$RW" 'confine_repo sep R 0; printf "went on"'
check "a separate git directory outside with no core.worktree is not tied back" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0||$UNREAD"
git --git-dir="$T/sep.git" config core.worktree "$RW/sep"
lib "$RW" 'confine_repo sep R 0; printf "%s" "$CONFINE_GIT_DIR"'
check "... while one whose core.worktree names the working tree is read" out_is "$T/sep.git"
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
# Outside every repository only on git's own answer (confine_no_repo): exit 128, its "fatal: not a git
# repository" first, or git 2.56's "fatal: gitfile does not point to a valid repository" for a .git file
# that names none. The same words further on, as when another user owns a repository named so, or with
# another status, leave confine_tracked unable to tell (2), and so do the words git 2.54 and later stop
# with at a .git that is neither a regular file nor a directory, or that stat cannot read: git looks no
# further, but a repository above may track the path. Each git here prints its line and exits.
for c in own:128 gitfile:128 quoted:128 status:1 notfile:128 unread:128; do
  n=${c%%:*}
  mkdir -p "$T/fg-$n"
  case "$n" in
    quoted) printf "fatal: detected dubious ownership in repository at '%s/not a git repository'\n" "$T" ;;
    gitfile) printf 'fatal: gitfile does not point to a valid repository: %s/norepo/.git\n' "$T" ;;
    notfile) printf "fatal: not a regular file: '%s/norepo/d/.git'\n" "$T" ;;
    unread) printf "fatal: error reading '%s/norepo/d/.git'\n" "$T" ;;
    *) printf 'fatal: not a git repository (or any of the parent directories): .git\n' ;;
  esac > "$T/fg-$n/msg"
  printf '#!/bin/sh\ncat "%s/fg-%s/msg" >&2\nexit %s\n' "$T" "$n" "${c#*:}" > "$T/fg-$n/git"
  chmod +x "$T/fg-$n/git"
done
LIB_PATH="$T/fg-own:$PATH" lib "$T/norepo/d" 'confine_tracked x; printf "[%s]" "$?"'
check "confine_tracked takes git's own no-repository answer, exit 128, for nothing tracked" out_is '[0]'
LIB_PATH="$T/fg-gitfile:$PATH" lib "$T/norepo/d" 'confine_tracked x; printf "[%s]" "$?"'
check "... and so git 2.56's answer for a .git file that names no repository" out_is '[0]'
LIB_PATH="$T/fg-quoted:$PATH" lib "$T/norepo/d" 'confine_tracked x; printf "[%s]" "$?"'
check "... but those words inside another message of git's for not telling (2)" out_is '[2]'
LIB_PATH="$T/fg-status:$PATH" lib "$T/norepo/d" 'confine_tracked x; printf "[%s]" "$?"'
check "... and git's own words with another exit status for not telling (2)" out_is '[2]'
LIB_PATH="$T/fg-notfile:$PATH" lib "$T/norepo/d" 'confine_tracked x; printf "[%s]" "$?"'
check "... and git 2.54's stop at a .git that is no regular file or directory for not telling (2)" out_is '[2]'
LIB_PATH="$T/fg-unread:$PATH" lib "$T/norepo/d" 'confine_tracked x; printf "[%s]" "$?"'
check "... and its stop at a .git that stat cannot read for not telling (2)" out_is '[2]'
# On Linux an LD_PRELOAD that names no library makes the loader print a line on stderr in each program
# started with it, ahead of anything that program writes. env, which sets git's environment, starts with
# an empty one (exec -c), so git's answer still comes first. The env here prints that line, as glibc's
# loader does, when it starts with such an LD_PRELOAD.
mkdir -p "$T/ldenv"
cat > "$T/ldenv/env" <<EOF
#!/bin/sh
if [ -n "\${LD_PRELOAD-}" ] && [ ! -e "\$LD_PRELOAD" ]; then
  printf "ERROR: ld.so: object '%s' from LD_PRELOAD cannot be preloaded (cannot open shared object file): ignored.\n" "\$LD_PRELOAD" >&2
fi
exec $(command -v env) "\$@"
EOF
chmod +x "$T/ldenv/env"
LD_PRELOAD="$T/no-such.so" LIB_PATH="$T/ldenv:$PATH" lib "$T/norepo/d" 'confine_tracked x; printf "[%s]" "$?"'
check "... and the caller's LD_PRELOAD naming no library, whose loader line would come first, still leaves nothing tracked" \
  test "$RC:$(cat "$T/out")" = '0:[0]'
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
  # A vertical tab or form feed after "ref:" is no blank to git, so it walks past such a HEAD too.
  mkdir -p "$T/above/sub/dec/.git" "$T/above/sub/bad/.git/objects" "$T/above/sub/bad/.git/refs" "$T/above/sub/gf/gd"
  printf 'ref: refs/heads/main\n' > "$T/above/sub/dec/.git/HEAD"
  : > "$T/above/sub/bad/.git/HEAD"
  for d in vt ff; do
    mkdir -p "$T/above/sub/$d/.git/objects" "$T/above/sub/$d/.git/refs"
  done
  printf 'ref:\vrefs/heads/main\n' > "$T/above/sub/vt/.git/HEAD"
  printf 'ref:\frefs/heads/main\n' > "$T/above/sub/ff/.git/HEAD"
  for d in dec bad vt ff; do
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
  # There the write of "done" after the limit fails aloud once the watcher has left the pipe, and which side
  # comes first changes from run to run. So a printf of the test's, which the library's calls find before
  # the builtin, holds that one write until a byte no longer goes into the pipe: the watcher has gone, every
  # run. It leaves a mark, so a change to the write's words fails here instead of passing by chance.
  MARK="$T/done-held" lib_bounded "$T/lr-out/heads/main" "$T/lr" 'trap "" PIPE
    printf() {
      if [ "$#" -eq 1 ] && [ "$1" = "done\n" ]; then
        : > "$MARK"
        while builtin printf " " 2>/dev/null; do sleep 0.05; done
      fi
      builtin printf "$@"
    }
    CONFINE_GIT_TIME=1 hgit "$CONFINE_WT" rev-parse --verify HEAD'
  check "... and with SIGPIPE ignored, as GitHub's runners start their steps, the refusal is the only line on stderr once the watcher has left" \
    refused "git has not answered within 1 s in $(shown "$T/lr"), so a file it opens there may be a named pipe or device that it would wait on for good"
  check "... the write of done waiting for the watcher to leave" test -e "$T/done-held"
  # The files git reads in the work tree of a repository whose history it shows, which reads take no
  # time limit: .mailmap, and .gitattributes and .gitignore in any directory. A named pipe there, or a
  # link to one, is refused; a link to a regular file passes.
  mkrepo "$RW/wtpipe"; put "$RW/wtpipe" src/f x; put "$RW/wtpipe" src/g y; commit "$RW/wtpipe" -m x
  printf 'z\n' >> "$RW/wtpipe/src/f"; git -C "$RW/wtpipe" commit -q -am y
  # Strict mode searches the work tree for them (CONF-11); default mode does not, since hgit_tree's reads
  # open no file of it and its questions have a time limit, and the same fixtures read at once.
  wtmsg='a named pipe or device is where git reads its own files in the work tree, and git would wait on it for good'
  mkfifo "$RW/wtpipe/.mailmap"
  AUDITOR_STRICT=1 lib_bounded "$RW/wtpipe/.mailmap" "$RW" 'confine_repo wtpipe R'
  check "in strict mode a named pipe as the work tree's .mailmap is refused" refused "$wtmsg: $(shown "$RW/wtpipe/.mailmap")"
  AUDITOR_STRICT=1 bounded "$RW/wtpipe/.mailmap" script "$RW" git-ro.sh --repo wtpipe log -1
  check "... so git-ro.sh log refuses at once" refused_by git-ro
  AUDITOR_STRICT=1 bounded "$RW/wtpipe/.mailmap" script "$RW" git-ro.sh --repo wtpipe shortlog HEAD
  check "... and so does git-ro.sh shortlog" refused_by git-ro
  lib_bounded "$RW/wtpipe/.mailmap" "$RW" 'confine_repo wtpipe R; printf "%s" "$CONFINE_BARE"'
  check "in default mode confine_repo takes that repository" out_is false
  bounded "$RW/wtpipe/.mailmap" script "$RW" git-ro.sh --repo wtpipe log -1
  check "... and git-ro.sh log reads it at once" sh -c "[ '$RC' = 0 ] && [ ! -s '$T/err' ] && grep -q '^commit ' '$T/out'"
  bounded "$RW/wtpipe/.mailmap" script "$RW" git-ro.sh --repo wtpipe shortlog HEAD
  check "... and so does git-ro.sh shortlog" sh -c "[ '$RC' = 0 ] && [ ! -s '$T/err' ] && grep -q '^fixture (2):' '$T/out'"
  rm "$RW/wtpipe/.mailmap"
  mkfifo "$RW/wtpipe/src/.gitattributes"
  AUDITOR_STRICT=1 bounded "$RW/wtpipe/src/.gitattributes" script "$RW" git-ro.sh --repo wtpipe diff HEAD~1 HEAD
  check "in strict mode a named pipe as a .gitattributes below: git-ro.sh diff refuses at once" refused_by git-ro
  AUDITOR_STRICT=1 lib_bounded "$RW/wtpipe/src/.gitattributes" "$RW" 'confine_repo_top "$CONFINE_WT/wtpipe" && printf top || printf not-top'
  check "... and confine_repo_top fails there" out_is not-top
  bounded "$RW/wtpipe/src/.gitattributes" script "$RW" git-ro.sh --repo wtpipe diff HEAD~1 HEAD
  check "in default mode git-ro.sh diff reads past it at once" sh -c "[ '$RC' = 0 ] && [ ! -s '$T/err' ] && grep -q '^+z' '$T/out'"
  lib_bounded "$RW/wtpipe/src/.gitattributes" "$RW" 'confine_repo_top "$CONFINE_WT/wtpipe" && printf top || printf not-top'
  check "... and confine_repo_top takes that repository" out_is top
  rm "$RW/wtpipe/src/.gitattributes"
  mkfifo "$RW/wtpipe/pipe"
  ln -s pipe "$RW/wtpipe/.gitignore"
  AUDITOR_STRICT=1 lib_bounded "$RW/wtpipe/pipe" "$RW" 'confine_repo wtpipe R'
  check "in strict mode a .gitignore that is a link to a named pipe is refused" refused "$wtmsg: $(shown "$RW/wtpipe/.gitignore")"
  lib_bounded "$RW/wtpipe/pipe" "$RW" 'confine_repo wtpipe R; printf "%s" "$CONFINE_BARE"'
  check "... and taken in default mode" out_is false
  rm "$RW/wtpipe/.gitignore" "$RW/wtpipe/pipe"
  # A question that opens such a file in default mode meets its time limit: a named pipe as the top-level
  # .gitignore, which ls-files -o reads.
  mkfifo "$RW/wtpipe/.gitignore"
  BOUND=150 bounded "$RW/wtpipe/.gitignore" script "$RW" git-ro.sh --repo wtpipe ls-files -o --exclude-standard
  check "in default mode a question that opens a named pipe in the work tree is cut off by its time limit, refused" \
    sh -c "[ '$RC' = 64 ] && grep -q '^git-ro: refused: git has not answered within 10 s' '$T/err'"
  rm "$RW/wtpipe/.gitignore"
  ln -s src/g "$RW/wtpipe/.gitignore"
  lib "$RW" 'confine_repo wtpipe R; printf "%s" "$CONFINE_BARE"'
  check "... while a .gitignore that is a link to a regular file passes" out_is false
  # A git directory reached through a link is searched where the link leads, so a named pipe there is
  # found before git starts; so is one as the config there. A directory in it that find cannot read
  # is refused, since what it holds cannot be told. The caller's working directory stays as it was.
  for d in gl gc gu; do mkrepo "$RW/$d"; put "$RW/$d" f x; commit "$RW/$d" -m x; done
  for d in gl gc; do mv "$RW/$d/.git" "$RW/$d/.realgit"; ln -s .realgit "$RW/$d/.git"; done
  mkfifo "$RW/gl/.realgit/info/attributes"
  mv "$RW/gc/.realgit/config" "$RW/gc/config.kept"; mkfifo "$RW/gc/.realgit/config"
  lib_bounded "$RW/gl/.realgit/info/attributes" "$RW" 'confine_repo_top "$CONFINE_WT/gl" || printf "%s" "$CONFINE_GIT_WHY"'
  check "a named pipe in a git directory that .git links to is found before git starts" \
    out_is "a named pipe or device is in the git directory, and git would wait on it for good: $(shown "$RW/gl/.realgit")"
  BOUND=50 lib_bounded "$RW/gc/.realgit/config" "$RW/gc" 'CONFINE_CEILING="" hgit "$CONFINE_WT" rev-parse --is-inside-work-tree'
  check "... and a named pipe as the config there is refused at once, not after git's time is up" \
    refused "a named pipe or device is in the git directory, and git would wait on it for good: $(shown "$RW/gc/.realgit")"
  mkdir -p "$RW/audit_1"; printf '*\n' > "$RW/audit_1/.gitignore"
  bounded "$RW/gl/.realgit/info/attributes" script "$RW" threat-model/collect.sh --network --repo gl --out audit_1/bootstrap
  check "... so collect.sh --network refuses that target at once" \
    sh -c "[ '$RC' = 3 ] && [ \"\$(cat '$T/err')\" = 'collect.sh: a named pipe or device is in the git directory, and git would wait on it for good: $(shown "$RW/gl/.realgit")' ]"
  lib "$RW" 'cd / && CONFINE_CEILING="" hgit "$CONFINE_WT/gu" rev-parse --git-dir >/dev/null && pwd'
  check "... and git's checks leave the caller's working directory as it was (target.sh runs from /)" out_is /
  if [ "$(id -u)" -ne 0 ]; then
    mkfifo "$RW/gu/.git/info/attributes"
    chmod 0311 "$RW/gu/.git/info"
    lib_bounded "$RW/gu/.git/info/attributes" "$RW" 'confine_repo_top "$CONFINE_WT/gu" || printf "%s" "$CONFINE_GIT_WHY"'
    check "a git directory holding a directory that find cannot read is refused before git starts" \
      out_is "the git directory holds a directory that cannot be read, so a named pipe or device in it cannot be ruled out: $(shown "$RW/gu/.git")"
    chmod 0755 "$RW/gu/.git/info"
  else
    skp "running as root: a directory find cannot read cannot be made"
  fi
  # git-ro's reads take no file of the work tree (hgit_tree), so a named pipe the work-tree scan does
  # not see changes nothing: behind a link to a directory, in a directory that cannot be listed, under a
  # directory named .git, or at the top of a repository that cannot be listed (.mailmap).
  for d in wl wu wd wm; do
    mkrepo "$RW/$d"; put "$RW/$d" sub/x a; commit "$RW/$d" -m one
    printf 'b\n' >> "$RW/$d/sub/x"; git -C "$RW/$d" commit -qam two
  done
  mkdir -p "$T/wl-out"; mkfifo "$T/wl-out/.gitattributes"; rm -r "$RW/wl/sub"; ln -s "$T/wl-out" "$RW/wl/sub"
  mkdir -p "$RW/wd/deco/.git"; mkfifo "$RW/wd/deco/.git/.gitattributes"; rm -r "$RW/wd/sub"; ln -s deco/.git "$RW/wd/sub"
  set -- wl "$T/wl-out/.gitattributes" wd "$RW/wd/deco/.git/.gitattributes"
  if [ "$(id -u)" -ne 0 ]; then
    mkfifo "$RW/wu/sub/.gitattributes"; chmod 0311 "$RW/wu/sub"
    mkfifo "$RW/wm/.mailmap"; chmod 0311 "$RW/wm"
    set -- "$@" wu "$RW/wu/sub/.gitattributes" wm "$RW/wm/.mailmap"
  else
    skp "running as root: a directory that cannot be listed cannot be made (wu, wm)"
  fi
  while [ $# -gt 0 ]; do
    for a in 'diff HEAD~1 HEAD' 'show HEAD' 'log -p -1' 'log -1' 'shortlog HEAD' 'grep -e b HEAD' 'blame HEAD -- sub/x' \
             'diff --cached' 'grep -e b'; do
      # shellcheck disable=SC2086
      bounded "$2" script "$RW" git-ro.sh --repo "$1" $a
      check "git-ro.sh --repo $1 $a answers at once, past a named pipe in the work tree" \
        sh -c "[ '$RC' = 0 ] && [ ! -s '$T/err' ]"
    done
    has "$T/out" 'sub/x' || ko "git-ro.sh --repo $1 grep -e b found nothing"
    shift 2
  done
  # The other readers of a target's history read with an empty work tree too (hgit_tree, hgit_text_tree):
  # lock-delta.sh past a lockfile's directory that links to one holding a .gitattributes pipe, and
  # web3js-history.sh and collect.sh --offline past wm's .mailmap.
  mkrepo "$RW/wlock"; put "$RW/wlock" sub/Cargo.lock "$(printf '[[package]]\nname = "a"\nversion = "1.0.0"')"
  commit "$RW/wlock" -m one
  printf '[[package]]\nname = "a"\nversion = "1.0.1"\n' > "$RW/wlock/sub/Cargo.lock"; git -C "$RW/wlock" commit -qam two
  mkdir -p "$T/wlock-out"; mkfifo "$T/wlock-out/.gitattributes"; rm -r "$RW/wlock/sub"; ln -s "$T/wlock-out" "$RW/wlock/sub"
  bounded "$T/wlock-out/.gitattributes" script "$RW" recipes/lock-delta.sh --repo wlock cargo HEAD~1..HEAD
  check "lock-delta.sh --repo wlock answers at once, past a named pipe in the work tree, with the changed version" \
    sh -c "[ '$RC' = 0 ] && grep -q '^\"a\" +version = \"1.0.1\"\$' '$T/out'"
  if [ "$(id -u)" -ne 0 ]; then
    bounded "$RW/wm/.mailmap" script "$RW" recipes/web3js-history.sh --repo wm
    check "web3js-history.sh --repo wm answers at once, past a named pipe in the work tree" sh -c "[ '$RC' = 0 ]"
    bounded "$RW/wm/.mailmap" script "$RW" threat-model/collect.sh --offline --repo wm --out audit_1/bootstrap
    check "collect.sh --offline --repo wm answers at once, past a named pipe in the work tree" sh -c "[ '$RC' = 0 ]"
    rm -rf "$RW/audit_1/bootstrap"
  fi
  chmod 0755 "$RW/wu/sub" "$RW/wm" 2>/dev/null
  # hgit_tree itself: an empty directory under TMPDIR as the work tree, the git directory named, gone
  # afterwards; a bare repository read as hgit reads it; no TMPDIR inside the working directory; only a
  # top level or a bare repository.
  mkdir -p "$T/tmpd" "$RW/tmpd"
  : > "$T/rec.log"
  TMPDIR="$T/tmpd" PATH="$T/rec:$PATH" lib "$RW" 'confine_repo wl R && hgit_tree "$CONFINE_REPO" log --format=%s -1'
  check "hgit_tree reads the history of the repository confine_repo accepted" out_is two
  check "... with git started in an empty directory under TMPDIR, given as the work tree beside the git directory" \
    awk -F '\037' -v t="$T/tmpd/auditor-git." -v g="--git-dir=$RW/wl/.git" '$1 == "ARGV" && $3 == "-C" && index($4, t) == 1 {
      for (i = 5; i <= NF; i++) { if ($i == g) gd = 1; if ($i == "--work-tree=" $4) w = 1 } } END { exit !(gd && w) }' "$T/rec.log"
  check "... which is gone afterwards" test -z "$(ls -A "$T/tmpd")"
  # ... also when a signal ends the caller while git reads: only the caller, as a timeout's alarm does (the
  # directory goes once git is done), or its whole process group, as Ctrl-C does (the caller still stops).
  # This git sleeps 2 s before it reads a history; each wait below gives up after 30 s.
  mkdir -p "$T/slow"
  cat > "$T/slow/git" <<EOF
#!/bin/sh
for a in "\$@"; do
  [ "\$a" = log ] || continue
  : > "$T/slow.started"; sleep 2; break
done
exec "$REAL_GIT" "\$@"
EOF
  chmod +x "$T/slow/git"
  slow_read() { # slow_read <signal> caller|group: a read with TMPDIR $T/tmp-<signal>, which <signal> ends once git sleeps
    local pid n=0 d="$T/tmp-$1"
    local -a start=("${SHELLS[0]}")
    # For the group, python3 starts the shell with SIGINT at its default, as in a run from a terminal (a
    # background job inherits it ignored, and so may the suite), in a process group of its own.
    [ "$2" != group ] || start=(python3 -I -c 'import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
os.setpgid(0, 0)
os.execvp(sys.argv[1], sys.argv[1:])' "${SHELLS[0]}")
    mkdir -p "$d"
    rm -f "$T/slow.started"
    (cd "$RW" && TMPDIR="$d" PATH="$T/slow:$PATH" exec "${start[@]}" -c \
      '. "$1" && confine_init test "$2" && confine_repo wl R && hgit_tree "$CONFINE_REPO" log --format=%s -1; printf "went on\n"' \
      lib "$LIB" "$ROOT") >"$T/out" 2>"$T/err" </dev/null &
    pid=$!
    while [ ! -e "$T/slow.started" ] && [ "$n" -lt 300 ]; do sleep 0.1; n=$((n + 1)); done
    SLOW_LEFT=$(ls -A "$d")
    SLOW_KILLED=1
    if [ "$2" != group ]; then
      kill -"$1" "$pid" 2>/dev/null
    elif kill -0 -- "-$pid" 2>/dev/null; then
      kill -"$1" -- "-$pid" 2>/dev/null
    else
      SLOW_KILLED=0
    fi
    wait "$pid" 2>/dev/null
    RC=$?
    n=0
    while [ -n "$(ls -A "$d")" ] && [ "$n" -lt 300 ]; do sleep 0.1; n=$((n + 1)); done
    SLOW_NOW=$(ls -A "$d")
  }
  slow_read ALRM caller
  check "... a caller an alarm ends while git reads leaves no directory under TMPDIR once git is done" \
    test "$SLOW_LEFT:$SLOW_NOW" = "${SLOW_LEFT:-none}:"
  if ! command -v python3 >/dev/null 2>&1; then
    skp "... Ctrl-C: needs python3"
  elif slow_read INT group; [ "$SLOW_KILLED" = 0 ]; then
    skp "... Ctrl-C: the read got no process group of its own here"
  else
    check "... nor does Ctrl-C, which still stops the caller" \
      test "$RC:$SLOW_LEFT:$SLOW_NOW:$(cat "$T/out")" = "130:${SLOW_LEFT:-none}::"
  fi
  TMPDIR="$T/tmpd" lib "$RW" 'confine_repo copy.git R && hgit_tree "$CONFINE_REPO" rev-list --count HEAD && ls -A "$TMPDIR"'
  check "... and a bare repository read as hgit reads it, with no directory made" out_is 1
  TMPDIR="$RW/tmpd" lib "$RW" 'confine_repo wl R && hgit_tree "$CONFINE_REPO" log -1'
  check "... and TMPDIR inside the working directory refused" \
    refused 'TMPDIR lies inside the working directory, so git has no empty work tree to read in; point it outside the tree under audit'
  TMPDIR="$T/tmpd" lib "$RW" 'hgit_tree "$CONFINE_WT/programs" log -1'
  check "... and a directory that is not a top level refused" \
    refused "git does not describe $(shown "$RW/programs") as the top level of a work tree or a bare repository"
  TMPDIR="$T/tmpd" lib "$RW" 'hgit_text_tree "$CONFINE_WT/wl" log --format=%s -1'
  check "... while a top level confine_repo did not see is described by git and read" out_is two
  TMPDIR="$T/tmpd" lib "$RW" 'confine_repo wl R && cd / && hgit_tree "$CONFINE_REPO" log --format=%s -1 && pwd'
  check "... and the caller's working directory stays as it was" out_is "$(printf 'two\n/')"
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
