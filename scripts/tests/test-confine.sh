#!/usr/bin/env bash
# test-confine.sh — self-test for scripts/lib/confine.sh, the checks the bundled entry points share: the
# working directory and installation checks of confine_init, the cleaned PATH, confined paths (the case
# file fixtures/confine/paths.txt), run-directory names and .gitignore files, noclobber writes, the
# environment and order of the hardened git call, and the repository, tracked and partial-clone checks.
# Every case runs under each bash on the machine (/bin/bash and the bash running this suite, when they
# differ) and must print the same under each. Needs git; no network.
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
lib "$WT" 'confine_need sh nosuch-tool-for-confine-test; printf ran'
check "confine_need refuses a program that is not on PATH" refused 'nosuch-tool-for-confine-test is not on PATH'
lib "$WT" 'confine_refuse "a reason"; printf ran'
check "confine_refuse prints one line and exits 64" refused 'a reason'
lib "$WT" 'confine_text "$(printf "a\001b\033c\177d\te")"; printf "|"; confine_text "$(printf "%0300d" 0)"'
check "confine_text shows control characters as ? and cuts after 200 bytes" \
  out_is "a?b?c?d?e|$(printf '%0200d' 0)..."

# =================================================================================================
# confine_path: the case file, then lengths and control characters.
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
ncase=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  IFS=$'\t' read -r want p status expect <<< "$line"
  ncase=$((ncase + 1))
  P="$p" W="$want" lib "$WT" 'confine_path "$P" "the path" "$W"; printf "%s %s" "$CONFINE_REL" "$CONFINE_TYPE"'
  if [ "$status" = 0 ]; then check "confine_path $want $p" out_is "$expect"
  else check "confine_path $want $p refused" refused "${expect#test: refused: }"; fi
done < "$CASES"
check "the path case file has cases ($ncase)" test "$ncase" -gt 40
long=$(awk 'BEGIN { for (i = 0; i < 1025; i++) printf "a" }')
P="$long" lib "$WT" 'confine_path "$P" "the path" any'
check "a path longer than 1024 bytes is refused" refused 'the path is longer than 1024 bytes'
P="${long%a}" lib "$WT" 'confine_path "$P" "the path" any; printf "%s" "$CONFINE_TYPE"'
check "a path of 1024 bytes is accepted" out_is none
P='' lib "$WT" 'confine_path "$P" "the path" any'
check "an empty path is refused" refused 'the path is empty'
for c in $'\001' $'\n' $'\t' $'\033' $'\177'; do
  P="src/a${c}b" lib "$WT" 'confine_path "$P" "the path" any'
  check "a path holding $(printf '%s' "$c" | od -An -c | tr -d ' \n') is refused" refused 'the path holds a control character: src/a?b'
done

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
mkdir -p "$WT/gi/dir"
ln -s nl "$WT/gi/link"
lib "$WT" 'for f in f1 nl f2 f3 f4 f5 f6 f7 crlf lead two dir link absent; do confine_ignore_all "$CONFINE_WT/gi/$f" && printf "%s " "$f"; done; :'
check "a .gitignore must hold exactly * (one newline may follow), as a regular file" out_is 'f1 nl '

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
  test -z "$(grep -vxE 'HOME|PATH|TMPDIR|LC_ALL|TZ|GIT_NO_LAZY_FETCH|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|GIT_CEILING_DIRECTORIES|GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS|PWD|OLDPWD|SHLVL|_' "$T/env.names")"
awk -F '\037' '$1 == "ARGV" { print $2, ($3 == "-C"), $5, $6; exit }' "$T/rec.log" > "$T/argv"
check "hgit runs git --no-pager -C <dir> -c core.fsmonitor=false first" test "$(cat "$T/argv")" = '--no-pager 1 -c core.fsmonitor=false'
for pin in core.pager=cat core.hooksPath=/dev/null protocol.allow=never core.attributesFile=/dev/null \
           log.showSignature=false gpg.program=false submodule.recurse=false diff.submodule=short \
           log.diffMerges=separate grep.patternType=basic grep.extendedRegexp=false log.showRoot=true \
           core.useReplaceRefs=false core.commitGraph=false; do
  check "hgit pins $pin before the subcommand" \
    awk -F '\037' -v pin="$pin" '$1 == "ARGV" { for (i = 2; i <= NF && $i != "rev-parse"; i++) if ($i == pin && $(i - 1) == "-c") found = 1; exit } END { exit !found }' "$T/rec.log"
done

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

echo
echo "confine tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
