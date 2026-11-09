#!/usr/bin/env bash
# test-rundir.sh — self-test for scripts/rundir.sh: the case file fixtures/rundir/cases.txt, new (names,
# numbering, .gitignore first, the standard subdirectories, repositories that track run directories,
# in default and strict mode, the strict marker), check, sub and store, in repositories whose config
# names programs. Every case runs under each bash on
# the machine (/bin/bash and the bash running this suite, when they differ) and must print the same
# under each. Needs git; no network. Usage (from the repo root): bash scripts/tests/test-rundir.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
RUNDIR="$ROOT/scripts/rundir.sh"
CASES="$ROOT/scripts/tests/fixtures/rundir/cases.txt"
T=$(mktemp -d "${TMPDIR:-/tmp}/rundir-test.XXXXXX") || exit 1
T=$(cd -P "$T" && pwd -P) || exit 1
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT

export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
unset AUDITOR_STRICT
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
mkdir -p "$HOME" "$T/bin" "$T/marks" "$T/hooks"
PATH="$T/bin:$PATH"
export PATH

pass=0 fail=0 skip=0
ok()   { pass=$((pass + 1)); echo "ok   - $1"; }
ko()   { fail=$((fail + 1)); echo "FAIL - $1"; }
skp()  { skip=$((skip + 1)); echo "skip - $1"; }
check() { # check <name> <command>...: on a failure, also show the last run
  if "${@:2}"; then ok "$1"; else ko "$1"; echo "#   status ${RC:-} stdout [$(cat "$T/out" 2>/dev/null)] stderr [$(cat "$T/err" 2>/dev/null)]"; fi
}
nomarks() { [ -z "$(ls -A "$T/marks")" ]; }

SHELLS=("$BASH")
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then
  SHELLS+=(/bin/bash)
fi
echo "# shells: ${SHELLS[*]}"

# run <dir> <arg>...: rundir.sh from <dir> under each shell. Output in $T/out, $T/err and $RC; every shell
# must produce the same three, byte for byte. run_once: under the first shell only, for new (each run
# makes the next name).
run() {
  local dir=$1 i=1 rc
  shift
  (cd "$dir" && "${SHELLS[0]}" "$RUNDIR" "$@") >"$T/out" 2>"$T/err" </dev/null
  RC=$?
  while [ "$i" -lt "${#SHELLS[@]}" ]; do
    (cd "$dir" && "${SHELLS[$i]}" "$RUNDIR" "$@") >"$T/out.$i" 2>"$T/err.$i" </dev/null
    rc=$?
    if [ "$rc" != "$RC" ] || ! cmp -s "$T/out" "$T/out.$i" || ! cmp -s "$T/err" "$T/err.$i"; then
      ko "the same output under ${SHELLS[0]} and ${SHELLS[$i]}: rundir.sh $*"
    fi
    i=$((i + 1))
  done
}
run_once() { local -a all=("${SHELLS[@]}"); SHELLS=("${all[0]}"); run "$@"; SHELLS=("${all[@]}"); }
out_is() { [ "$RC" = 0 ] && [ "$(cat "$T/out")" = "$1" ] && [ ! -s "$T/err" ]; }
refused() { [ "$RC" = 64 ] && [ "$(cat "$T/err")" = "rundir: refused: $1" ] && [ ! -s "$T/out" ]; }
tree() { (cd "$1" && find . -print | LC_ALL=C sort); }

# The fixtures' own git calls run with fsmonitor, hooks and the filter off, so only rundir.sh could
# leave a mark.
tgit()   { git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c filter.evil.clean=cat -c filter.evil.smudge=cat "$@"; }
mkrepo() { git init -q "$1" && git -C "$1" symbolic-ref HEAD refs/heads/main; }
put()    { mkdir -p "$(dirname "$1/$2")" && printf '%s\n' "$3" > "$1/$2" && tgit -C "$1" add -- "$2"; }
commit() { tgit -C "$1" commit -q "${@:2}"; }
hostile() { # hostile <repo>: config that names programs, and hooks, none of which may run
  local m
  for m in fsmonitor pager textconv clean smudge; do
    printf '#!/bin/sh\ntouch "%s/marks/%s"\nexit 0\n' "$T" "$m" > "$T/bin/mark-$m"
    chmod +x "$T/bin/mark-$m"
  done
  for m in post-index-change post-checkout reference-transaction; do
    printf '#!/bin/sh\ntouch "%s/marks/hook-%s"\n' "$T" "$m" > "$T/hooks/$m"
    chmod +x "$T/hooks/$m"
  done
  printf '*.rs diff=evil filter=evil\n' > "$1/.gitattributes"
  cat >> "$1/.git/config" <<EOF
[core]
	fsmonitor = $T/bin/mark-fsmonitor
	pager = $T/bin/mark-pager
	hooksPath = $T/hooks
	untrackedCache = true
[diff "evil"]
	textconv = $T/bin/mark-textconv
[filter "evil"]
	clean = $T/bin/mark-clean
	smudge = $T/bin/mark-smudge
[remote "origin"]
	url = ext::sh -c touch% $T/marks/ext
	promisor = false
EOF
}

# =================================================================================================
# The entry point, and new in a directory that is not a repository.
# =================================================================================================
check "rundir.sh starts with #!/bin/bash" test "$(sed -n 1p "$RUNDIR")" = '#!/bin/bash'
check "rundir.sh is executable" test -x "$RUNDIR"
P="$T/plain"; mkdir -p "$P"
(cd "$P" && "$RUNDIR" new audit) >"$T/out" 2>"$T/err"
check "run directly by its path, new audit makes audit_1" test "$(cat "$T/out")" = audit_1
check "... with a .gitignore of exactly *" test "$(cat "$P/audit_1/.gitignore")" = '*'
check "... one line" test "$(wc -c < "$P/audit_1/.gitignore" | tr -d ' ')" = 2
check "... and the standard audit subdirectories" \
  test "$(tree "$P/audit_1" | tr '\n' ' ')" = '. ./.gitignore ./deps ./exec ./patches ./poc ./sast ./worksheets ./worksheets/context '
check "... readable by its owner only" test "$(ls -ld "$P/audit_1" | cut -c1-10)" = 'drwx------'
run_once "$P" new audit
check "new audit again makes audit_2" out_is audit_2
run_once "$P" new incident
check "new incident makes incident_1" out_is incident_1
check "... with the standard incident subdirectories" \
  test "$(tree "$P/incident_1" | tr '\n' ' ')" = '. ./.gitignore ./bin ./exec ./logs ./patches ./poc '
mkdir "$P/audit_7" "$P/audit_009" "$P/audit_1234567" "$P/audit_x"
ln -s audit_7 "$P/audit_50"
printf 'x\n' > "$P/audit_60"
run_once "$P" new audit
check "new takes the highest number over real run directories (audit_009 counts as 9; a link, a file and other names do not count)" out_is audit_10
# The next name held by a file, a link, or a folder spelled in other letters: strict mode refuses; default
# mode passes over it, as over a tracked name, and names it as the disk spells it.
printf 'x\n' > "$P/audit_11"
AUDITOR_STRICT=1 run_once "$P" new audit
check "in strict mode new refuses when the next name is taken" refused 'audit_11 already exists and is not a run directory'
check "... and creates nothing" test ! -d "$P/audit_11" -a ! -e "$P/audit_12"
rm "$P/audit_11"
ln -s "$T/elsewhere" "$P/audit_11"
AUDITOR_STRICT=1 run_once "$P" new audit
check "in strict mode new refuses when the next name is a symbolic link" refused 'audit_11 already exists and is not a run directory'
check "... and nothing is made through it" test ! -e "$T/elsewhere"
run_once "$P" new audit
check "in default mode new passes over that link, with a note" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|audit_12|rundir: note: audit_11 already exists and is not a run directory; this run writes only in audit_12 (Rule 11d)"
check "... and nothing is made through it" test ! -e "$T/elsewhere"
rm "$P/audit_11"
printf 'x\n' > "$P/audit_13"
run_once "$P" new audit
check "... and so it does over a file" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|audit_14|rundir: note: audit_13 already exists and is not a run directory; this run writes only in audit_14 (Rule 11d)"
rm "$P/audit_13"
P2="$T/plain-taken"; mkdir -p "$P2"
for i in 1 2 3 4 5 6 7; do printf 'x\n' > "$P2/audit_$i"; done
run_once "$P2" new audit
check "... five taken names named, then a count" \
  test "$RC|$(cat "$T/out")|$(sed -n '$=' "$T/err")|$(sed -n '$p' "$T/err")" = "0|audit_8|6|rundir: note: 2 more such names are taken; this run writes only in audit_8 (Rule 11d)"
P3="$T/plain-cap"; mkdir -p "$P3/Audit_1"
if [ -d "$P3/audit_1" ]; then
  AUDITOR_STRICT=1 run_once "$P3" new audit
  check "in strict mode new refuses a name a folder spelled in other letters holds" refused 'audit_1 already exists and is not a run directory'
  run_once "$P3" new audit
  check "... which default mode passes over, naming the folder as the disk spells it" \
    test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|audit_2|rundir: note: Audit_1 already exists and is not a run directory; this run writes only in audit_2 (Rule 11d)"
  printf '*\n' > "$P3/Audit_1/.gitignore"
  run "$P3" check audit_1
  check "check refuses a run directory whose name the disk spells in other letters, in either mode" \
    refused "the run directory is spelled Audit_1 on disk, and a run directory's name is lowercase: audit_1"
  AUDITOR_STRICT=1 run "$P3" check audit_1
  check "... (strict mode)" refused "the run directory is spelled Audit_1 on disk, and a run directory's name is lowercase: audit_1"
else
  skp "this volume tells letter case apart: a folder Audit_1 does not hold audit_1"
fi
# Each shell makes a run directory of its own; the output must match but for the number.
i=0
for sh in "${SHELLS[@]}"; do
  (cd "$P" && "$sh" "$RUNDIR" new incident) 2>&1 | sed 's/incident_[0-9]*/incident_<n>/' > "$T/new.$i"
  i=$((i + 1))
done
check "new prints the same under each shell" sh -c "[ \"\$(cat '$T'/new.* | sort -u | wc -l | tr -d ' ')\" = 1 ]"

# =================================================================================================
# The case file, in a repository whose config names programs.
# =================================================================================================
W="$T/wt"; mkrepo "$W"
put "$W" a.rs 'fn a() {}'
put "$W" src/lib.rs 'fn lib() {}'
commit "$W" -m initial
hostile "$W"
(cd "$W" && "$RUNDIR" new audit) >/dev/null 2>&1
tree "$W" > "$T/tree.before"
ncase=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  want_rc=${line%%$'\t'*}
  rest=${line#*$'\t'}
  want_err=${rest%%$'\t'*}
  rest=${rest#*$'\t'}
  IFS=$'\t' read -r -a args <<< "$rest"
  run "$W" "${args[@]}"
  ncase=$((ncase + 1))
  if [ "$RC" = "$want_rc" ] && [ "$(cat "$T/err")" = "$want_err" ] && [ ! -s "$T/out" ]; then ok "case: rundir.sh ${args[*]}"
  else ko "case: rundir.sh ${args[*]} -> status $RC, stderr: $(cat "$T/err")"; fi
done < "$CASES"
check "the case file has cases ($ncase)" test "$ncase" -gt 70
tree "$W" > "$T/tree.after"
check "no case changed anything in the working directory" cmp -s "$T/tree.before" "$T/tree.after"
run "$W"
check "no arguments: usage, exit 64" refused 'usage: rundir.sh new audit|incident, check <R>, sub <R> <rel>, or store'

# =================================================================================================
# check
# =================================================================================================
run "$W" check audit_1
check "check accepts a run directory new made" out_is 'ok audit_1'
run "$W" check ./audit_1
check "... written ./audit_1" out_is 'ok audit_1'
mkdir -p "$W/audit_2/poc" "$W/audit_3" "$W/audit_4" "$W/audit_5" "$W/audit_6"
printf '*\n' > "$W/audit_2/.gitignore"
ln -s "$T" "$W/audit_2/poc/out"
run "$W" check audit_2
check "check refuses a run directory that holds a symbolic link out of it" refused 'the run directory holds a symbolic link: audit_2'
AUDITOR_STRICT=1 run "$W" check audit_2
check "... in strict mode too" refused 'the run directory holds a symbolic link: audit_2'
mkdir -p "$W/audit_9/poc/a"; printf '*\n' > "$W/audit_9/.gitignore"; ln -s a "$W/audit_9/poc/latest"
run "$W" check audit_9
check "check takes a run directory whose link resolves inside it in default mode (CONF-15)" out_is 'ok audit_9'
AUDITOR_STRICT=1 run "$W" check audit_9
check "... and strict mode refuses it" refused 'the run directory holds a symbolic link: audit_9'
rm -r "$W/audit_9"
run "$W" check audit_3
check "check refuses a run directory without a .gitignore" refused 'the run directory has no .gitignore holding exactly *: audit_3'
printf '*\n!REPORT.md\n' > "$W/audit_4/.gitignore"
run "$W" check audit_4
check "check refuses a .gitignore that lets a file through" refused 'the run directory has no .gitignore holding exactly *: audit_4'
mkdir "$W/audit_5/.gitignore"
run "$W" check audit_5
check "check refuses a .gitignore that is not a file" refused 'the run directory has no .gitignore holding exactly *: audit_5'
ln -s audit_1 "$W/audit_8"
run "$W" check audit_8
check "check refuses a run directory that is a symbolic link" refused 'the run directory is a symbolic link: audit_8'
printf '*\n' > "$W/audit_6/.gitignore"
tgit -C "$W" add -f audit_6/.gitignore
run "$W" check audit_6
check "check refuses a run directory git tracks" refused 'the run directory is tracked by git: audit_6'
tgit -C "$W" rm -q --cached audit_6/.gitignore
if [ "$(id -u)" -ne 0 ]; then
  mkdir -p "$W/audit_1/locked"
  chmod 000 "$W/audit_1/locked"
  run "$W" check audit_1
  check "check refuses a run directory find cannot fully read" refused 'the run directory cannot be fully read: audit_1'
  chmod 700 "$W/audit_1/locked"
  rmdir "$W/audit_1/locked"
else
  skp "running as root: an unreadable directory cannot be made"
fi
check "check ran no configured program, hook or helper" nomarks

# =================================================================================================
# sub
# =================================================================================================
for rel in poc/F-12 poc/INC-3.1 poc/INC-123456.1234 patches harnesses bootstrap corpus-2 corpus-1234 logs rpc; do
  run "$W" sub audit_1 "$rel"
  check "sub audit_1 $rel" sh -c "[ '$RC' = 0 ] && [ \"\$(cat '$T/out')\" = 'audit_1/$rel' ] && [ -d '$W/audit_1/$rel' ] && [ ! -L '$W/audit_1/$rel' ]"
done
run "$W" sub audit_1 poc/F-12
check "sub accepts a subdirectory that already exists" out_is audit_1/poc/F-12
(cd "$W" && "$RUNDIR" new incident) >/dev/null 2>&1
rmdir "$W/incident_1/poc"
run_once "$W" sub incident_1 poc/INC-7.2
check "sub makes poc when it is missing" sh -c "[ \"\$(cat '$T/out')\" = incident_1/poc/INC-7.2 ] && [ -d '$W/incident_1/poc/INC-7.2' ]"
printf 'x\n' > "$W/audit_1/rpc2"
mv "$W/audit_1/rpc" "$W/audit_1/rpc.d"
mv "$W/audit_1/rpc2" "$W/audit_1/rpc"
run "$W" sub audit_1 rpc
check "sub refuses a name that is taken by a file" refused 'audit_1/rpc exists and is not a directory'
rm "$W/audit_1/rpc"
mv "$W/audit_1/rpc.d" "$W/audit_1/rpc"
run "$W" sub audit_2 patches
check "sub refuses a run directory that fails check" refused 'the run directory holds a symbolic link: audit_2'
check "... and creates nothing there" test ! -e "$W/audit_2/patches"
check "sub ran no configured program, hook or helper" nomarks

# =================================================================================================
# new in repositories
# =================================================================================================
check "new in a repository whose config names programs ran none of them" nomarks
R1="$T/r1"; mkrepo "$R1"; put "$R1" audit_notes.md 'notes'; commit "$R1" -m notes
run_once "$R1" new audit
check "new accepts a repository that tracks a top-level file named audit_*" out_is audit_1
# A path the repository tracks under a top-level audit_* or incident_* directory (RD-02): strict mode
# refuses; default mode takes the next number whose name the repository tracks in no letter case, and
# notes each such top-level name (the first 5, then a count), with stdout the name alone.
tnote() { # tnote <tracked top-level name> <run directory made>: the note new prints
  printf "rundir: note: the repository tracks %s/, under a name the commands' Edit(/audit_*/**) and Edit(/incident_*/**) rules also cover; this run writes only in %s (Rule 11d)" "$1" "$2"
}
for c in audit_5/REPORT.md:audit_6 AUDIT_6/x:audit_1 Incident_2/y:audit_1 incident_3/deep/z:audit_1 AUDIT_1/x:audit_2; do
  p=${c%%:*} want=${c#*:}
  R="$T/r-$(printf '%s' "$p" | tr '/' '_')"; mkrepo "$R"; put "$R" "$p" 'tracked'; commit "$R" -m tracked
  tree "$R" > "$T/tree.before"
  AUDITOR_STRICT=1 run "$R" new audit
  check "in strict mode new refuses a repository that tracks $p" refused "the repository tracks $p, so writes into a run directory could reach tracked files; audit a copy"
  tree "$R" > "$T/tree.after"
  check "... and creates nothing" cmp -s "$T/tree.before" "$T/tree.after"
  run_once "$R" new audit
  check "in default mode new makes $want there, and notes ${p%%/*}/" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|$want|$(tnote "${p%%/*}" "$want")"
  tree "$R" > "$T/tree.after"
  check "... changing nothing but making $want" \
    test "$(LC_ALL=C comm -23 "$T/tree.before" "$T/tree.after" | wc -l | tr -d ' '):$(LC_ALL=C comm -13 "$T/tree.before" "$T/tree.after" | grep -cv "^\./$want\(/.*\)\{0,1\}\$")" = 0:0
done
R="$T/r-many"; mkrepo "$R"
for d in audit_1 audit_2 Audit_3 incident_4 audit_reports incident_response audit_x; do put "$R" "$d/f" 'tracked'; done
commit "$R" -m many
run_once "$R" new audit
check "in default mode new names the first five tracked names, then a count" \
  test "$RC|$(cat "$T/out")|$(sed -n '$=' "$T/err")|$(sed -n '$p' "$T/err")" = "0|audit_4|6|rundir: note: the repository tracks paths under 2 more such names; this run writes only in audit_4 (Rule 11d)"
O="$T/sm"; mkrepo "$O"; put "$O" f 'x'; commit "$O" -m x
R="$T/r-gitlink"; mkrepo "$R"
tgit -C "$R" update-index --add --cacheinfo "160000,$(git -C "$O" rev-parse HEAD),audit_9"
commit "$R" -m gitlink
AUDITOR_STRICT=1 run "$R" new audit
check "in strict mode new refuses a repository with a submodule named audit_*" \
  refused 'the repository tracks audit_9/, so writes into a run directory could reach tracked files; audit a copy'
run_once "$R" new audit
check "... and default mode makes audit_1 and notes it" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|audit_1|$(tnote audit_9 audit_1)"
R="$T/r-outer"; mkrepo "$R"; put "$R" inner/audit_3/x 'x'; commit "$R" -m nested
AUDITOR_STRICT=1 run "$R/inner" new audit
check "in strict mode new asks the repository above the working directory" \
  refused 'the repository tracks audit_3/x, so writes into a run directory could reach tracked files; audit a copy'
run_once "$R/inner" new audit
check "... and default mode makes audit_4 there" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|audit_4|$(tnote audit_3 audit_4)"
# When git cannot tell whether the repository tracks a run directory (RD-03): default mode goes on with a
# note, strict mode refuses. A git that fails with no answer stands for that.
mkdir -p "$T/cantell"
printf '#!/bin/sh\necho "fatal: something else" >&2\nexit 1\n' > "$T/cantell/git"
chmod +x "$T/cantell/git"
P5="$T/cantell-wt"; mkdir -p "$P5"
PATH="$T/cantell:$PATH" run_once "$P5" new audit
check "in default mode new goes on when git cannot tell, with a note" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|audit_1|rundir: note: git cannot tell whether the repository tracks a run directory; audit_1 is new, and its .gitignore of * keeps git off it (Rule 11d)"
AUDITOR_STRICT=1 PATH="$T/cantell:$PATH" run "$P5" new audit
check "... and strict mode refuses" refused 'git cannot tell whether the repository tracks a run directory'
PATH="$T/cantell:$PATH" run "$P5" check audit_1
check "check takes a run directory git cannot tell about in default mode (CONF-16)" out_is 'ok audit_1'
AUDITOR_STRICT=1 PATH="$T/cantell:$PATH" run "$P5" check audit_1
check "... and strict mode refuses it" refused 'git cannot tell whether the run directory is tracked: audit_1'
# A checkout another user owns (CONF-05; git's own test knob stands for the other user).
mkdir -p "$T/other"
printf '#!/bin/sh\nGIT_TEST_ASSUME_DIFFERENT_OWNER=1 exec "%s" "$@"\n' "$(command -v git)" > "$T/other/git"
chmod +x "$T/other/git"
R="$T/r-other"; mkrepo "$R"; put "$R" a.rs 'x'; commit "$R" -m x
PATH="$T/other:$PATH" run_once "$R" new audit
check "in default mode new works in a checkout another user owns" out_is audit_1
AUDITOR_STRICT=1 PATH="$T/other:$PATH" run "$R" new audit
check "... and strict mode refuses it" refused 'git cannot tell whether the repository tracks a run directory'
# The strict marker: new writes <name>/strict whenever strict mode is on, whatever turned it on, and a
# marker in a run directory of the working directory turns it on for every later call there.
P6="$T/marker"; mkdir -p "$P6"
run_once "$P6" new audit
check "new in default mode writes no marker" sh -c "[ '$RC' = 0 ] && [ ! -e '$P6/audit_1/strict' ]"
run_once "$P6" new audit --strict
check "new audit --strict makes audit_2" out_is audit_2
check "... with the marker strict, holding strict" test "$(cat "$P6/audit_2/strict")" = strict
check "... one line, readable by its owner only" test "$(wc -c < "$P6/audit_2/strict" | tr -d ' '):$(ls -l "$P6/audit_2/strict" | cut -c1-10)" = '7:-rw-------'
check "... right after the .gitignore, beside the standard subdirectories" \
  test "$(tree "$P6/audit_2" | tr '\n' ' ')" = '. ./.gitignore ./deps ./exec ./patches ./poc ./sast ./strict ./worksheets ./worksheets/context '
run_once "$P6" new incident
check "... and every later new there is strict too, from that marker" sh -c "[ \"\$(cat '$T/out')\" = incident_1 ] && [ -f '$P6/incident_1/strict' ]"
P7="$T/marker-env"; mkdir -p "$P7"
AUDITOR_STRICT=yes run_once "$P7" new audit
check "AUDITOR_STRICT=yes makes new write the marker" sh -c "[ \"\$(cat '$T/out')\" = audit_1 ] && [ -f '$P7/audit_1/strict' ]"
R="$T/r-marker"; mkrepo "$R"; put "$R" audit_1/strict 'strict'; commit "$R" -m 'a committed marker'
run_once "$R" new audit
check "a marker the repository tracks turns nothing on: new makes audit_2, with no marker" \
  sh -c "[ \"\$(cat '$T/out')\" = audit_2 ] && [ ! -e '$R/audit_2/strict' ]"
# Only git's own answer says there is no repository: a worktree whose admin directory bears git's words for
# that, with a commondir git still reads past 16 KiB of line ends, is refused for that file.
R="$T/r-main"; mkrepo "$R"; put "$R" f 'x'; commit "$R" -m x
A="$R/.git/worktrees/not a git repository"
if tgit -C "$R" worktree add -q "$T/r-wt" 2>/dev/null && mv "$R/.git/worktrees/r-wt" "$A" &&
  printf 'gitdir: %s\n' "$A" > "$T/r-wt/.git"; then
  { printf '../..\n'; awk 'BEGIN { for (i = 0; i < 17000; i++) printf "\n" }'; } > "$A/commondir"
  s="$A/commondir"
  [ "${#s}" -le 200 ] || s="${s:0:200}..."
  tree "$T/r-wt" > "$T/tree.before"
  run "$T/r-wt" new audit
  check "new refuses a worktree whose commondir holds more than 16 KiB, whatever its admin directory is named" \
    refused "a .git file or commondir file holds a NUL byte or more than 16 KiB, so where git would look cannot be told: $s"
  tree "$T/r-wt" > "$T/tree.after"
  check "... and creates nothing" cmp -s "$T/tree.before" "$T/tree.after"
else
  skp "git worktree add is not available"
fi

# =================================================================================================
# store
# =================================================================================================
S="$T/store"; mkrepo "$S"; put "$S" a.rs 'x'; commit "$S" -m x
hostile "$S"
run "$S" store
check "store: no .audit-memory prints absent" out_is absent
mkdir "$S/.audit-memory"
printf '*\n' > "$S/.audit-memory/.gitignore"
run "$S" store
check "store: a usable store prints its database path" out_is .audit-memory/audit.db
printf 'SQLite format 3\n' > "$S/.audit-memory/audit.db"
run "$S" store
check "... with the database present" out_is .audit-memory/audit.db
ln -s "$T" "$S/.audit-memory/link"
run "$S" store
check "store refuses a store that holds a symbolic link out of it" refused '.audit-memory holds a symbolic link; use <R>/audit-mem.db'
rm "$S/.audit-memory/link"
ln -s audit.db "$S/.audit-memory/latest"
run "$S" store
check "in default mode store takes a store whose link resolves inside it" out_is .audit-memory/audit.db
AUDITOR_STRICT=1 run "$S" store
check "... and strict mode refuses it" refused '.audit-memory holds a symbolic link; use <R>/audit-mem.db'
rm "$S/.audit-memory/latest"
printf '*\n!audit.db\n' > "$S/.audit-memory/.gitignore"
run "$S" store
check "store refuses a store whose .gitignore lets a file through" refused '.audit-memory has no .gitignore holding exactly *; use <R>/audit-mem.db'
printf '*\n' > "$S/.audit-memory/.gitignore"
rm "$S/.audit-memory/audit.db"
mkdir "$S/.audit-memory/audit.db"
run "$S" store
check "store refuses an audit.db that is not a regular file" refused '.audit-memory/audit.db is not a regular file; use <R>/audit-mem.db'
rmdir "$S/.audit-memory/audit.db"
mv "$S/.audit-memory" "$S/store-real"
ln -s store-real "$S/.audit-memory"
run "$S" store
check "store refuses a store that is a symbolic link" refused '.audit-memory is a symbolic link; use <R>/audit-mem.db'
rm "$S/.audit-memory"
printf 'x\n' > "$S/.audit-memory"
run "$S" store
check "store refuses a store that is not a directory" refused '.audit-memory is not a directory; use <R>/audit-mem.db'
rm "$S/.audit-memory"
put "$S" .Audit-Memory/audit.db 'tracked'
commit "$S" -m 'tracked store'
run "$S" store
check "store refuses a store the repository tracks in another letter case" \
  refused 'the repository tracks .audit-memory (in some letter case); use <R>/audit-mem.db'
tgit -C "$S" rm -q -r --cached .Audit-Memory
rm -r "$S/.Audit-Memory"
commit "$S" -m 'untrack'
put "$S" .audit-memory/audit.db 'tracked'
commit "$S" -m 'tracked again'
rm -r "$S/.audit-memory"
run "$S" store
check "store refuses a tracked store that is missing from the working tree" \
  refused 'the repository tracks .audit-memory (in some letter case); use <R>/audit-mem.db'
check "store ran no configured program, hook or helper" nomarks

# =================================================================================================
# The installation is never inside the working directory.
# =================================================================================================
run "$ROOT" check audit_1
check "an installation inside the working directory is refused" \
  refused 'the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)'
mkdir -p "$T/fake/.bin"
for p in git mkdir find env; do
  printf '#!/bin/sh\ntouch "%s/marks/wt-%s"\nexit 0\n' "$T" "$p" > "$T/fake/.bin/$p"
  chmod +x "$T/fake/.bin/$p"
done
(cd "$T/fake" && PATH="$T/fake/.bin:.bin:$PATH" "$RUNDIR" new audit) >"$T/out" 2>"$T/err"
check "programs inside the working directory are never run from PATH" sh -c "[ \"\$(cat '$T/out')\" = audit_1 ] && [ -d '$T/fake/audit_1' ]"
check "... none of them ran" nomarks

echo
echo "rundir tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
