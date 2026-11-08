#!/usr/bin/env bash
# test-git-ro.sh — self-test for scripts/git-ro.sh and the hardened git call in scripts/lib/confine.sh.
# Builds hostile repositories under ${TMPDIR:-/tmp} at test time: config that names programs (pager,
# fsmonitor, external diff, textconv, clean, smudge and process filters, a merge driver, signature
# programs, a pretty alias, aliases, an include, hooks through core.hooksPath and .git/hooks), a
# submodule whose git directory lies outside, and a partial clone whose promisor remote is a custom
# helper or ext::. Runs the case file fixtures/git-ro/cases.txt (its strict-mode rows in both modes), every
# allowed form, the copy and its git version gate in both modes, reads from a subdirectory of a repository,
# blame's ignore-revs copy, another user's checkout and a linked worktree, and checks the argument order
# and environment git receives. Every case runs under each
# bash on the machine (/bin/bash and the bash running this suite, when they differ) and must print the
# same under each.
# Needs git and awk; no network. Usage (from the repo root): bash scripts/tests/test-git-ro.sh
# CONFINE_TRANSCRIPT=<file> saves every case's output, the temp path shown as <T>, to compare runs.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
GITRO="$ROOT/scripts/git-ro.sh"
RUNDIR="$ROOT/scripts/rundir.sh"
CASES="$ROOT/scripts/tests/fixtures/git-ro/cases.txt"
T=$(mktemp -d "${TMPDIR:-/tmp}/git-ro-test.XXXXXX") || exit 1
T=$(cd -P "$T" && pwd -P) || exit 1
trap 'rm -rf "$T"' EXIT
REAL_GIT=$(command -v git) || { echo "FAIL - git is not on PATH"; exit 1; }

# Isolate the fixtures' own git calls from the caller's configuration (signing, hooks, templates).
export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
unset AUDITOR_STRICT
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
export GIT_AUTHOR_DATE='2026-01-02T03:04:05Z' GIT_COMMITTER_DATE='2026-01-02T03:04:05Z'
mkdir -p "$HOME" "$T/bin" "$T/marks" "$T/hooks"
PATH="$T/bin:$PATH"
export PATH

pass=0 fail=0 skip=0
ok()   { pass=$((pass + 1)); echo "ok   - $1"; }
ko()   { fail=$((fail + 1)); echo "FAIL - $1"; }
skp()  { skip=$((skip + 1)); echo "skip - $1"; }
check() { if "${@:2}"; then ok "$1"; else ko "$1"; fi; }
has()   { grep -qF -- "$2" "$1"; }
hasnt() { ! grep -qF -- "$2" "$1"; }
nomarks() { [ -z "$(ls -A "$T/marks")" ]; }
clearmarks() { rm -f "$T/marks"/*; }
# snapshot <dir> <file> [<top-level name to leave out>]: every directory, link and file under <dir>, each
# file with its checksum, so two snapshots differ when any byte of the repository or its work tree did.
snapshot() {
  local -a skip=()
  [ -z "${3-}" ] || skip=(-path "./$3" -prune -o)
  (cd "$1" && {
    find . ${skip[@]+"${skip[@]}"} -type d -print
    find . ${skip[@]+"${skip[@]}"} -type l -print | while IFS= read -r l; do printf '%s -> %s\n' "$l" "$(readlink "$l")"; done
    find . ${skip[@]+"${skip[@]}"} -type f -exec cksum {} +
  }) | LC_ALL=C sort > "$2"
}

SHELLS=("$BASH")
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then
  SHELLS+=(/bin/bash)
fi
echo "# shells: ${SHELLS[*]}"

# run <dir> <arg>...: git-ro.sh from <dir> under each shell, standard input empty. Its stdout, stderr and
# status land in $T/out, $T/err and $RC; every shell must produce the same three, byte for byte.
# run_in <file> <dir> <arg>...: the same, with <file> as standard input. run_once <dir> <arg>...: under
# the first shell only, for a call that changes what the next one sees (copy).
run() { run_in /dev/null "$@"; }
run_once() { local -a all=("${SHELLS[@]}"); SHELLS=("${all[0]}"); run_in /dev/null "$@"; SHELLS=("${all[@]}"); }
run_in() {
  local input=$1 dir=$2 i=1 rc
  shift 2
  (cd "$dir" && "${SHELLS[0]}" "$GITRO" "$@") >"$T/out" 2>"$T/err" <"$input"
  RC=$?
  while [ "$i" -lt "${#SHELLS[@]}" ]; do
    (cd "$dir" && "${SHELLS[$i]}" "$GITRO" "$@") >"$T/out.$i" 2>"$T/err.$i" <"$input"
    rc=$?
    if [ "$rc" != "$RC" ] || ! cmp -s "$T/out" "$T/out.$i" || ! cmp -s "$T/err" "$T/err.$i"; then
      ko "the same output under ${SHELLS[0]} and ${SHELLS[$i]}: git-ro.sh $*"
    fi
    i=$((i + 1))
  done
  if [ -n "${CONFINE_TRANSCRIPT:-}" ]; then
    { printf '$ git-ro.sh %s\nstatus %s\n' "$*" "$RC"; cat "$T/out" "$T/err"; } | sed "s#$T#<T>#g" >> "$T/transcript"
  fi
}
err_is() { [ "$(cat "$T/err")" = "$1" ]; }
out_empty() { [ ! -s "$T/out" ]; }

mkrepo() { git init -q "$1" && git -C "$1" symbolic-ref HEAD refs/heads/main; }
put()    { mkdir -p "$(dirname "$1/$2")" && printf '%s\n' "$3" > "$1/$2" && git -C "$1" add -- "$2"; }
commit() { git -C "$1" commit -q "${@:2}"; }
marker() { # marker <name>: a program that records its own run, in $T/bin/mark-<name>
  printf '#!/bin/sh\ntouch "%s/marks/%s"\n[ -n "$1" ] && [ -f "$1" ] && cat "$1"\nexit 0\n' "$T" "$1" > "$T/bin/mark-$1"
  chmod +x "$T/bin/mark-$1"
}
for m in pager pagerlog incpager fsmonitor external extdiff textconv clean smudge process gpg gpgssh gpgx509 \
         alias-log alias-lg packhook envpager envdiff envssh mergedriver; do
  marker "$m"
done
for h in post-checkout post-index-change reference-transaction post-merge post-rewrite pre-auto-gc pre-commit; do
  printf '#!/bin/sh\ntouch "%s/marks/hook-%s"\n' "$T" "$h" > "$T/hooks/$h"
  chmod +x "$T/hooks/$h"
done
printf '#!/bin/sh\ntouch "%s/marks/remote-helper"\nexit 1\n' "$T" > "$T/bin/git-remote-evil"
chmod +x "$T/bin/git-remote-evil"

# =================================================================================================
# Fixtures. O is a repository outside the working directory. WT, the working directory under audit, is
# the hostile repository: its history is built first, its config and hooks last.
# =================================================================================================
O="$T/outside"; mkrepo "$O"
put "$O" secret.txt 'OUTSIDE-SECRET-CONTENT one'
commit "$O" -m 'outside first'
put "$O" secret.txt 'OUTSIDE-SECRET-CONTENT two'
commit "$O" -m 'OUTSIDE-SECRET-SUBJECT'
O1=$(git -C "$O" rev-parse HEAD~1)
O2=$(git -C "$O" rev-parse HEAD)

WT="$T/wt"; mkrepo "$WT"
put "$WT" .gitattributes '*.rs diff=evil filter=evil'
put "$WT" a.rs 'fn a() {}'
put "$WT" programs/demo/src/lib.rs '#[account(mut, has_one = authority)]'
commit "$WT" -m 'initial import'
# The branch merged ends in a merge whose sides conflicted, so a remerge diff would need the merge driver.
git -C "$WT" checkout -q -b merged
put "$WT" m.txt "$(printf 'a\nb\nc')"
commit "$WT" -m 'merge base'
git -C "$WT" checkout -q -b theirs
put "$WT" m.txt "$(printf 'a\nX\nc')"
commit "$WT" -m 'theirs'
git -C "$WT" checkout -q merged
put "$WT" m.txt "$(printf 'a\nY\nc')"
commit "$WT" -m 'ours'
git -C "$WT" merge -q theirs -m 'merge theirs' >/dev/null 2>&1
put "$WT" m.txt "$(printf 'a\nZ\nc')"
commit "$WT" -m 'merge theirs'
git -C "$WT" checkout -q main
git -C "$WT" checkout -q -b side
put "$WT" b.rs 'fn side() {}'
commit "$WT" -m 'side work'
git -C "$WT" checkout -q main
put "$WT" a.rs 'fn a() { require!(owner == authority); } // Owner check'
awk 'BEGIN { for (i = 0; i < 4000; i++) printf "line %05d of a blob larger than a pipe buffer\n", i }' > "$WT/big.txt"
git -C "$WT" add big.txt
commit "$WT" -m 'Check the owner'
printf '[submodule "sub"]\n\tpath = sub\n\turl = ./sub\n' > "$WT/.gitmodules"
git -C "$WT" add .gitmodules
git -C "$WT" update-index --add --cacheinfo "160000,$O1,sub"
commit "$WT" -m 'add the submodule'
git -C "$WT" update-index --cacheinfo "160000,$O2,sub"
commit "$WT" -m "$(printf 'control \033[31mred\033[0m\r\a bytes')"
C_CTRL=$(git -C "$WT" rev-parse HEAD)
# HEAD again as a signed commit (a gpgsig header written with hash-object; no gpg needed), so that
# log.showSignature has a signature to check with the configured gpg.program.
SIGNED=$(git -C "$WT" cat-file commit HEAD | awk '{ print } /^committer / && !done {
  print "gpgsig -----BEGIN PGP SIGNATURE-----"; print " "; print " iQEzBAABCAAdFiEEZml4dHVyZS1zaWduYXR1cmUtbm90LXJlYWw="
  print " -----END PGP SIGNATURE-----"; done = 1 }' | git -C "$WT" hash-object -t commit -w --stdin)
git -C "$WT" update-ref refs/heads/main "$SIGNED"
mkdir -p "$WT/sub"
printf 'gitdir: %s/.git\n' "$O" > "$WT/sub/.git"
printf 'Mapped Outside <fixture@example.invalid>\n' > "$T/outside-mailmap"
printf 'NOT-A-REVISION\n' > "$T/outside-revs"
printf '[core]\n\tpager = %s/bin/mark-incpager\n[url "https://TOKEN-FROM-INCLUDE@example.invalid/"]\n\tinsteadOf = https://example.invalid/\n' \
  "$T" > "$T/include.cfg"
for h in post-checkout post-index-change reference-transaction; do cp "$T/hooks/$h" "$WT/.git/hooks/$h"; done
printf '* merge=evil\n' > "$WT/.git/info/attributes"
cat >> "$WT/.git/config" <<EOF
[core]
	pager = $T/bin/mark-pager
	fsmonitor = $T/bin/mark-fsmonitor
	hooksPath = $T/hooks
	untrackedCache = true
[pager]
	log = $T/bin/mark-pagerlog
[diff]
	external = $T/bin/mark-external
	submodule = log
[diff "evil"]
	textconv = $T/bin/mark-textconv
	command = $T/bin/mark-extdiff
[filter "evil"]
	clean = $T/bin/mark-clean
	smudge = $T/bin/mark-smudge
	process = $T/bin/mark-process
[gpg]
	program = $T/bin/mark-gpg
[gpg "ssh"]
	program = $T/bin/mark-gpgssh
[gpg "x509"]
	program = $T/bin/mark-gpgx509
[log]
	showSignature = true
	diffMerges = remerge
[merge "evil"]
	name = evil
	driver = $T/bin/mark-mergedriver %A %O %B
[format]
	pretty = sig
[pretty]
	sig = %h %G? %s
[alias]
	log = !$T/bin/mark-alias-log
	lg = !$T/bin/mark-alias-lg
[include]
	path = $T/include.cfg
[submodule]
	recurse = true
[submodule "sub"]
	url = ./sub
	active = true
[mailmap]
	file = $T/outside-mailmap
[blame]
	ignoreRevsFile = $T/outside-revs
[color]
	ui = always
	diff = always
	grep = always
	decorate = always
[uploadpack]
	packObjectsHook = $T/bin/mark-packhook
[remote "origin"]
	url = https://example.invalid/acme/pool.git
	pushurl = https://example.invalid/acme/pool-push.git
[remote "up"]
	url = ext::sh -c touch% $T/marks/ext-up
EOF

# Nested repositories for the case file's --repo refusals.
mkdir -p "$WT/escape" "$WT/escape-link"
printf 'gitdir: %s/.git\n' "$O" > "$WT/escape/.git"
ln -s "$O/.git" "$WT/escape-link/.git"
for d in inner-link alt worktree cdir; do mkrepo "$WT/$d"; put "$WT/$d" f.txt "$d"; commit "$WT/$d" -m "$d"; done
ln -s "$O/.git/refs/heads/main" "$WT/inner-link/.git/refs/heads/outside"
printf '%s/.git/objects\n' "$O" > "$WT/alt/.git/objects/info/alternates"
git -C "$WT/worktree" config core.worktree "$O"
printf '%s/.git\n' "$O" > "$WT/cdir/.git/commondir"
ln -s inner-link "$WT/linkrepo"

# Sanity: the fixture really is hostile for plain git (a git that does not run one of these is skipped).
sane() { # sane <what> marker|text <marker name, "any", or text in the output> <git arguments>...
  local what=$1 kind=$2 want=$3
  shift 3
  clearmarks
  git -C "$WT" "$@" >"$T/sane.out" 2>&1
  case "$kind:$want" in
    text:*) grep -qF -- "$want" "$T/sane.out" ;;
    marker:any) ! nomarks ;;
    *) [ -e "$T/marks/$want" ] ;;
  esac
  if [ $? -eq 0 ]; then ok "sanity: plain git $what"; else skp "sanity: this git does not $what"; fi
}
sane "log -p runs a diff driver or filter" marker any log -p -1 -- a.rs
sane "diff runs an external diff program" marker any diff HEAD~3 HEAD~2 -- a.rs
sane "status runs core.fsmonitor" marker fsmonitor status
sane "log checks the signature with gpg.program" marker gpg log -1
sane "remote -v shows a URL rewritten by an included file" text TOKEN-FROM-INCLUDE remote -v
sane "log -p shows the history of the submodule's outside repository" text OUTSIDE-SECRET-SUBJECT log -p -1 HEAD
sane "log applies the outside mailmap file" text 'Mapped Outside' log --format=%aN -1
sane "grep recurses into the submodule's outside repository" text OUTSIDE-SECRET-CONTENT grep -e OUTSIDE-SECRET-CONTENT HEAD
sane "read-tree runs the post-index-change hook" marker hook-post-index-change read-tree HEAD
sane "blame reads the outside ignore-revs file" text NOT-A-REVISION blame HEAD -- a.rs
sane "show --remerge-diff runs the merge driver" marker mergedriver show --remerge-diff merged
sane "log -p -m runs the merge driver through log.diffMerges" marker mergedriver log -p -m -1 merged
clearmarks

# =================================================================================================
# The entry point itself, and a run directory with a copy for the cases below.
# =================================================================================================
check "git-ro.sh starts with #!/bin/bash" test "$(sed -n 1p "$GITRO")" = '#!/bin/bash'
check "git-ro.sh is executable" test -x "$GITRO"
(cd "$WT" && "$GITRO" rev-parse HEAD) >"$T/direct.out" 2>&1
check "run directly by its path, it reads the repository" test "$(cat "$T/direct.out")" = "$SIGNED"
(cd "$WT" && "$RUNDIR" new audit) >"$T/new.out" 2>&1
check "rundir.sh new audit makes audit_1 for the copy" test "$(cat "$T/new.out")" = audit_1
snapshot "$WT" "$T/snap.copy.before" audit_1
run_once "$WT" copy . audit_1
snapshot "$WT" "$T/snap.copy.after" audit_1
check "copy changes no byte outside its run directory" cmp -s "$T/snap.copy.before" "$T/snap.copy.after"
check "copy prints the copy's path" test "$(cat "$T/out")" = audit_1/src.git
check "copy exits 0" test "$RC" = 0
check "copy writes the auditor-copy marker" \
  test "$(cat "$WT/audit_1/src.git/auditor-copy")" = 'auditor-copy: made by git-ro.sh copy from .'
check "the copy is a bare repository" test "$(git --git-dir="$WT/audit_1/src.git" rev-parse --is-bare-repository)" = true
check "the copy has no hooks directory (no templates)" test ! -e "$WT/audit_1/src.git/hooks"
check "the copy's config keeps none of the repository's settings" hasnt "$WT/audit_1/src.git/config" mark-
check "the copy holds every branch" \
  test "$(git --git-dir="$WT/audit_1/src.git" for-each-ref --format='%(refname)' refs/heads | tr '\n' ' ')" = 'refs/heads/main refs/heads/merged refs/heads/side refs/heads/theirs '
check "copy ran no hook, filter, driver or helper and contacted no remote" nomarks
run "$WT" --git-dir audit_1/src.git log --format=%H -1
check "--git-dir reads the copy" test "$(cat "$T/out")" = "$SIGNED"
run_once "$WT" copy . audit_1
check "a second copy goes to src-2.git" test "$(cat "$T/out")" = audit_1/src-2.git
# Each shell copies the hostile repository into a fresh run directory of its own, in a working
# directory of its own (so the run directories in WT do not depend on how many shells there are).
i=0
for sh in "${SHELLS[@]}"; do
  git clone -q --no-local "$WT/audit_1/src.git" "$T/copyx$i" >/dev/null 2>&1
  cat "$WT/.git/config" >> "$T/copyx$i/.git/config"
  (cd "$T/copyx$i" && "$RUNDIR" new audit >/dev/null && "$sh" "$GITRO" copy . audit_1) 2>&1 | sed "s#$T/copyx$i#<W>#g" > "$T/copy.$i"
  i=$((i + 1))
done
check "copy prints the same under each shell" sh -c "[ -z \"\$(cat '$T'/copy.* | sort -u | sed 1,2d)\" ]"
check "... and ran nothing the copied config names" nomarks

# =================================================================================================
# The case file: hostile argument vectors, each refused with its one line.
# =================================================================================================
# A plain status holds in both modes, so its case runs once, in default mode; one ending in s runs as
# written under AUDITOR_STRICT=1, then in default mode, where it exits 0 with notes on stderr alone.
notes_only() { [ -s "$T/err" ] && ! grep -qv '^git-ro: note: ' "$T/err"; }
ncase=0 nstrict=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  want_rc=${line%%$'\t'*}
  rest=${line#*$'\t'}
  want_err=${rest%%$'\t'*}
  rest=${rest#*$'\t'}
  IFS=$'\t' read -r -a args <<< "$rest"
  ncase=$((ncase + 1))
  case "$want_rc" in
    *s)
      nstrict=$((nstrict + 1))
      AUDITOR_STRICT=1 run "$WT" "${args[@]}"
      if [ "$RC" = "${want_rc%s}" ] && err_is "$want_err" && out_empty; then ok "case, strict mode: git-ro.sh ${args[*]}"
      else ko "case, strict mode: git-ro.sh ${args[*]} -> status $RC, stderr: $(cat "$T/err")"; fi
      run "$WT" "${args[@]}"
      if [ "$RC" = 0 ] && notes_only && nomarks; then ok "case, default mode: git-ro.sh ${args[*]} goes on with a note"
      else ko "case, default mode: git-ro.sh ${args[*]} -> status $RC, stderr: $(cat "$T/err")"; fi ;;
    *)
      run "$WT" "${args[@]}"
      if [ "$RC" = "$want_rc" ] && err_is "$want_err" && out_empty; then ok "case: git-ro.sh ${args[*]}"
      else ko "case: git-ro.sh ${args[*]} -> status $RC, stderr: $(cat "$T/err")"; fi ;;
  esac
done < "$CASES"
check "the case file has cases ($ncase), $nstrict of them strict mode's alone" test "$ncase" -gt 200 -a "$nstrict" -ge 3
UNREAD="git-ro: note: --repo keeps its git directory outside the working directory, and nothing there ties it back to this working tree, so its history is not read; strict mode refuses this (Rule 11f)"
run "$WT" --repo escape log
check "... where a git directory outside that nothing ties back is noted, and its history not read" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0||$UNREAD"
run "$WT" --repo alt log --format=%s
check "... and a repository with alternates is read, after its note" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|alt|git-ro: note: --repo borrows objects from another repository (objects/info/alternates), so its history is read from there too; strict mode refuses this (Rule 11f)"
# copy makes no copy of such a repository, and says so as a refusal in both modes: a copy that cannot be
# made never reads as one made (the case file's copy escape row).
before=$(ls "$WT/audit_1" | tr '\n' ' ')
run_once "$WT" copy escape audit_1
check "... while copy of a repository whose git directory nothing ties back is refused, and copies nothing" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")|$(ls "$WT/audit_1" | tr '\n' ' ')" = "64||git-ro: refused: copy's repository keeps its git directory outside the working directory: escape|$before"
# cdir, whose commondir names a repository outside, is this suite's alone: the case file is shared with
# test-preapproved-entrypoints.sh, whose fixture has no cdir.
AUDITOR_STRICT=1 run "$WT" --repo cdir log
check "in strict mode --repo cdir (a commondir file naming a repository outside) is refused" \
  sh -c "[ '$RC' = 64 ] && [ ! -s '$T/out' ] && [ \"\$(cat '$T/err')\" = 'git-ro: refused: --repo keeps its git directory outside the working directory: cdir' ]"
run "$WT" --repo cdir log
check "... and in default mode noted, its history not read" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0||$UNREAD"
check "no case ran a configured program, hook or helper" nomarks
run "$WT"
check "no arguments: usage, exit 64" \
  err_is 'git-ro: refused: usage: git-ro.sh [--repo <dir> | --git-dir <R>/src.git] <subcommand> [<arg>...], or copy <dir> <R>, partial [--repo <dir>], tracked <path>'

# =================================================================================================
# Every allowed form runs, prints, and starts nothing the repository's config names.
# =================================================================================================
# Each one must also leave every byte of the repository and its work tree as it was.
nallowed=0
snapshot "$WT" "$T/snap.base"
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  want_rc=${line%%$'\t'*}
  IFS=$'\t' read -r -a args <<< "${line#*$'\t'}"
  run "$WT" "${args[@]}"
  nallowed=$((nallowed + 1))
  snapshot "$WT" "$T/snap.now"
  if [ "$RC" = "$want_rc" ] && { [ "$want_rc" != 0 ] || [ -s "$T/out" ]; } && nomarks && cmp -s "$T/snap.base" "$T/snap.now"; then
    ok "allowed: git-ro.sh ${args[*]}"
  else
    ko "allowed: git-ro.sh ${args[*]} -> status $RC, marks: $(ls "$T/marks" | tr '\n' ' ') stderr: $(cat "$T/err"), repository $(cmp -s "$T/snap.base" "$T/snap.now" && echo unchanged || echo CHANGED)"
  fi
  clearmarks
done <<'EOF'
0	log
0	log	--oneline
0	log	-p
0	log	-p	--stat	-1
0	log	-S	require	--oneline
0	log	-G	owner ==	--oneline
0	log	-SOwner	--oneline	--all
0	log	--format=%H%n%s	-2
0	log	--pretty=oneline	-1
0	log	--pretty=format:%h	-1
0	log	--format=tformat:%an	-1
0	log	--oneline	--follow	--	a.rs
0	log	-L	1,1:a.rs	--oneline
0	log	--all	--oneline
0	log	--remotes	--branches	--oneline
0	log	-c	--oneline	-1
0	log	--no-textconv	--no-ext-diff	--no-show-signature	-1
0	log	--exclude=refs/heads/side	--all	--oneline
0	log	--oneline	--end-of-options	HEAD
0	log	-p	-m	-1	merged
0	log	-p	--diff-merges=first-parent	-1	merged
0	log	--diff-merges	separate	-p	-1	merged
0	show	merged
0	shortlog	-sn	HEAD
0	rev-list	--count	HEAD
0	rev-list	--objects	--all
0	show	HEAD
0	show	--stat	HEAD
0	show	HEAD:a.rs
0	show	HEAD~1:programs/demo/src/lib.rs
0	ls-tree	-r	HEAD
0	ls-tree	--format=%(path)	HEAD
0	cat-file	-p	HEAD
0	cat-file	-t	HEAD
0	cat-file	-s	HEAD:big.txt
0	cat-file	blob	HEAD:a.rs
0	rev-parse	HEAD
0	rev-parse	--show-toplevel
0	rev-parse	--abbrev-ref	HEAD
0	merge-base	main	side
0	name-rev	HEAD
0	for-each-ref	--format=%(refname)
0	for-each-ref	--format	%(refname) %(objectname)
0	show-ref
0	count-objects	-v
0	cherry	side	main
0	reflog	show	-1
0	reflog	show	-p	-1
0	diff	HEAD~1..HEAD
0	diff	HEAD~3	HEAD	--stat
0	diff	side...main
0	diff	HEAD~2^!
0	diff	--cached	HEAD~2	--stat
0	diff	-U1	HEAD~3	HEAD	--	a.rs
0	diff	--stat	HEAD~3..HEAD	--	a.rs
0	diff	-S	require	HEAD~3..HEAD
0	diff-tree	-p	HEAD~2
0	diff-tree	-r	--name-only	HEAD~3	HEAD
0	grep	-n	require
0	grep	-n	-e	require	HEAD
0	grep	-n	require	HEAD	--	*.rs
0	grep	-c	fn	HEAD~2
0	grep	--cached	-n	require
0	grep	-n	-e	fn	HEAD	side
1	grep	-e	OUTSIDE-SECRET-CONTENT	HEAD
0	ls-files
0	ls-files	-s
0	ls-files	-o	--exclude-standard
0	ls-files	--exclude=*.md	-o	--directory
0	describe	--always
0	config	--get	remote.origin.url
0	config	--get-regexp	^remote\.
0	config	--list
0	config	--list	--show-origin
0	config	--get	--type=bool	core.bare
0	config	--type	bool	--get	core.bare
1	config	--get-urlmatch	http.sslverify	https://example.invalid/
0	remote
0	remote	-v
0	remote	get-url	origin
0	remote	get-url	--push	origin
0	remote	get-url	--all	up
0	tracked	a.rs
0	tracked	Programs
EOF
check "every allowed form ran ($nallowed)" test "$nallowed" -gt 70
run "$WT" diff --cached
check "diff --cached of a clean index exits 0 and prints nothing" test "$RC:$(wc -c < "$T/out" | tr -d ' ')" = 0:0
run "$WT" partial
check "partial: not a partial clone, exit 0, nothing printed" test "$RC:$(cat "$T/out")" = 0:
run "$WT" tracked audit_1
check "tracked: an untracked run directory prints nothing, exit 0" test "$RC:$(cat "$T/out")" = 0:
run "$WT" tracked Programs
check "tracked matches in any letter case" has "$T/out" programs/demo/src/lib.rs

# What the repository's config would change stays off.
run "$WT" log -1
check "format.pretty from the repository is not used (no alias, no %G)" has "$T/out" "commit $SIGNED"
run "$WT" remote -v
check "remote -v prints the URLs as the config file writes them" \
  test "$(cat "$T/out")" = "$(printf 'origin\thttps://example.invalid/acme/pool.git (fetch)\norigin\thttps://example.invalid/acme/pool-push.git (push)\nup\text::sh -c touch%% %s/marks/ext-up (fetch)\nup\text::sh -c touch%% %s/marks/ext-up (push)' "$T" "$T")"
run "$WT" remote get-url origin
check "remote get-url: no insteadOf rewriting from an included file" test "$(cat "$T/out")" = https://example.invalid/acme/pool.git
run "$WT" remote get-url nosuch
check "remote get-url of an unknown remote: git's message, exit 2" test "$RC:$(cat "$T/err")" = "2:error: No such remote 'nosuch'"
run "$WT" config --list
check "config --list shows the repository's own file only (no included values)" hasnt "$T/out" TOKEN-FROM-INCLUDE
check "config --list shows the include line itself" has "$T/out" "include.path=$T/include.cfg"
check "config --list does not show the pins as the repository's" hasnt "$T/out" core.fsmonitor=false
run "$WT" log --format=%aN -1
check "mailmap.file from the repository is not read" test "$(cat "$T/out")" = fixture
run "$WT" log -p -1 HEAD
check "the submodule's outside repository is not read (diff.submodule)" hasnt "$T/out" OUTSIDE-SECRET-SUBJECT
check "... the gitlink shows as a plain commit id" has "$T/out" "+Subproject commit $O2"
run "$WT" blame HEAD -- a.rs
check "blame refuses a repository whose config names an ignore-revs file" \
  err_is "git-ro: refused: blame does not run where the repository's config sets blame.ignoreRevsFile; blame a copy (git-ro.sh copy, then --git-dir)"
check "... and prints nothing from that file" hasnt "$T/err" NOT-A-REVISION
run "$WT" --git-dir audit_1/src.git blame HEAD -- a.rs
check "blame reads a copy" has "$T/out" 'require!(owner == authority)'
snapshot "$WT" "$T/snap.now"
check "the reads since the allowed forms changed no byte of the repository either" cmp -s "$T/snap.base" "$T/snap.now"
git -C "$WT" config --unset blame.ignoreRevsFile
snapshot "$WT" "$T/snap.base"
for b in 'HEAD -- a.rs' '-L 1,1 HEAD -- a.rs' '-w --reverse HEAD~3..HEAD -- a.rs' '-M -C HEAD -- programs/demo/src/lib.rs'; do
  # shellcheck disable=SC2086
  run "$WT" blame $b
  check "allowed: git-ro.sh blame $b (diff driver, filters and hooks configured)" sh -c "[ '$RC' = 0 ] && [ -s '$T/out' ] && [ -z \"\$(ls -A '$T/marks')\" ]"
done
snapshot "$WT" "$T/snap.now"
check "blame changed no byte of the repository" cmp -s "$T/snap.base" "$T/snap.now"
git -C "$WT" config blame.ignoreRevsFile "$T/outside-revs"
snapshot "$WT" "$T/snap.base"
run "$WT" diff HEAD~3..HEAD
check "no colour reaches the output, whatever color.* the repository sets" hasnt "$T/out" '?['
run "$WT" log --format=%s -1 "$C_CTRL"
check "control characters in a commit subject print as ?" test "$(cat "$T/out")" = 'control ?[31mred?[0m?? bytes'
run "$WT" cat-file -p HEAD:big.txt
check "a blob above the 64 KiB pipe buffer comes through whole" \
  test "$RC:$(wc -c < "$T/out" | tr -d ' ')" = "0:$(git -C "$WT" cat-file -s HEAD:big.txt)"
printf 'HEAD:a.rs\n' > "$T/batch.in"
run_in "$T/batch.in" "$WT" cat-file --batch
check "cat-file --batch reads standard input" has "$T/out" 'fn a() { require!(owner == authority); }'
run_in "$T/batch.in" "$WT" cat-file --batch-check
check "cat-file --batch-check reads standard input" has "$T/out" ' blob '
if [ "$(git version | awk '{ split($3, v, "."); print (v[1] > 2 || (v[1] == 2 && v[2] >= 46)) ? "yes" : "no" }')" = yes ]; then
  run "$WT" config get remote.origin.url
  check "config get reads the repository's own file" test "$RC:$(cat "$T/out")" = 0:https://example.invalid/acme/pool.git
  run "$WT" config list
  check "config list shows no included values" sh -c "[ '$RC' = 0 ] && ! grep -q TOKEN-FROM-INCLUDE '$T/out' && grep -q '^include.path=' '$T/out'"
else
  skp "config get and config list need git 2.46 or later"
fi
printf '%s\n' "$SIGNED control bytes" "$O1 first" > "$T/shortlog.in"
run_in "$T/shortlog.in" "$WT" shortlog -s
check "other subcommands never read standard input (shortlog prints nothing)" test "$RC:$(cat "$T/out")" = 0:
run "$WT" grep -e $'\t' HEAD
check "a TAB in an argument is allowed" test "$RC" != 64
run "$WT" log --format=%H%x00 -1
check "a NUL a format asks for prints as ?" test "$(cat "$T/out")" = "$SIGNED?"
check "no allowed form ran a configured program, hook or helper" nomarks
snapshot "$WT" "$T/snap.now"
check "... and none changed a byte of the repository or its work tree" cmp -s "$T/snap.base" "$T/snap.now"

# =================================================================================================
# The argument order and the environment git receives.
# =================================================================================================
mkdir -p "$T/rec"
cat > "$T/rec/git" <<EOF
#!/bin/sh
{ printf 'ARGV'; for a in "\$@"; do printf '\037%s' "\$a"; done; printf '\n'; env | sed 's/^/ENV /'; } >> "$T/rec.log"
exec "$REAL_GIT" "\$@"
EOF
chmod +x "$T/rec/git"
: > "$T/rec.log"
PATH="$T/rec:$PATH" run "$WT" log -c core.abbrev=40 --format=%h -1
check "log -c x=y: git reads -c as log's option and refuses the revision" test "$RC" = 128
check "... and prints no 40-character id" hasnt "$T/out" "$SIGNED"
argv_order() { # argv_order <subcommand> <caller word>: the word comes after the subcommand, never before
  awk -F '\037' -v sub_="$1" -v word="$2" '
    $1 == "ARGV" { s = 0; w = 0; for (i = 2; i <= NF; i++) { if (!s && $i == sub_) s = i; if ($i == word) { w = i; if (!s) bad = 1 } }
                   if (s && w > s) seen = 1 }
    END { exit (seen && !bad) ? 0 : 1 }' "$T/rec.log"
}
check "the caller's -c lands after the subcommand name" argv_order log core.abbrev=40
check "git's first word is --no-pager" awk -F '\037' '$1 == "ARGV" && $2 != "--no-pager" { bad = 1 } END { exit bad }' "$T/rec.log"
: > "$T/rec.log"
PATH="$T/rec:$PATH" run "$WT" log --oneline -1 -- --exec-path=x
check "a word after -- stays a path" test "$RC" = 0
check "... and lands after the subcommand name" argv_order log --exec-path=x
: > "$T/rec.log"
GIT_DIR="$O/.git" GIT_WORK_TREE="$O" GIT_INDEX_FILE="$T/index" GIT_OBJECT_DIRECTORY="$O/.git/objects" \
GIT_ALTERNATE_OBJECT_DIRECTORIES="$O/.git/objects" GIT_CONFIG_PARAMETERS="'core.pager=$T/bin/mark-envpager'" \
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=diff.external GIT_CONFIG_VALUE_0="$T/bin/mark-envdiff" \
GIT_EXTERNAL_DIFF="$T/bin/mark-envdiff" GIT_PAGER="$T/bin/mark-envpager" PAGER="$T/bin/mark-envpager" \
GIT_SSH_COMMAND="$T/bin/mark-envssh" GIT_TRACE="$T/trace.log" GIT_TRACE2_EVENT="$T/trace2.log" \
GIT_NAMESPACE=x CDPATH="$T" ENV="$T/env.sh" PATH="$T/rec:$PATH" run "$WT" log --format=%s -p -1 HEAD~2
check "with GIT_DIR and friends set, git-ro still reads the working directory's repository" has "$T/out" 'Check the owner'
check "... and runs no program they name" nomarks
check "... and git writes no trace" test ! -e "$T/trace.log" -a ! -e "$T/trace2.log"
awk '/^ENV / { sub(/^ENV /, ""); sub(/=.*/, ""); print }' "$T/rec.log" | sort -u > "$T/env.names"
check "git receives only the hardened environment" \
  test -z "$(grep -vxE 'HOME|PATH|TMPDIR|LC_ALL|TZ|GIT_NO_LAZY_FETCH|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|GIT_ALLOW_PROTOCOL|GIT_CEILING_DIRECTORIES|GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS|PWD|OLDPWD|SHLVL|_' "$T/env.names")"
check "... with GIT_CONFIG_NOSYSTEM=1, and in default mode GIT_CONFIG_GLOBAL the installation's safe-directory file" \
  sh -c "[ \"\$(sed -n 's/^ENV GIT_CONFIG_GLOBAL=//p' '$T/rec.log' | sort -u)\" = '$ROOT/scripts/lib/safe-directory.gitconfig' ] && grep -qx 'ENV GIT_CONFIG_NOSYSTEM=1' '$T/rec.log'"
check "... and GIT_CEILING_DIRECTORIES at the working directory's parent" grep -qx "ENV GIT_CEILING_DIRECTORIES=$T" "$T/rec.log"
: > "$T/rec.log"
AUDITOR_STRICT=1 PATH="$T/rec:$PATH" run "$WT" log --format=%s -p -1 HEAD~2
check "... and in strict mode GIT_CONFIG_GLOBAL=/dev/null" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(sed -n 's/^ENV GIT_CONFIG_GLOBAL=//p' '$T/rec.log' | sort -u)\" = /dev/null ]"
clearmarks
: > "$T/rec.log"
GIT_DIR="$O/.git" GIT_CONFIG_PARAMETERS="'core.hooksPath=$T/hooks'" PATH="$T/rec:$PATH" run_once "$WT" copy . audit_1
check "copy under the recorder makes a copy" test "$RC" = 0
before_clone() { # before_clone <word> <next word>: the clone's git call carries "<word> <next word>" before clone
  awk -F '\037' -v a="$1" -v b="$2" '$1 == "ARGV" { c = 0; for (i = 2; i <= NF; i++) if ($i == "clone") { c = i; break }
    if (c) for (i = 2; i < c; i++) if ($i == a && $(i + 1) == b) found = 1 } END { exit !found }' "$T/rec.log"
}
check "copy's clone runs with -c core.hooksPath=/dev/null" before_clone -c core.hooksPath=/dev/null
check "... with -c protocol.allow=never" before_clone -c protocol.allow=never
check "... and -c protocol.file.allow=always for this clone" before_clone -c protocol.file.allow=always
check "... with --no-local --bare --no-recurse-submodules --template=" \
  awk -F '\037' '$1 == "ARGV" { for (i = 2; i <= NF; i++) if ($i == "clone") { ok = ($(i + 1) == "--no-local" && $(i + 2) == "--bare" && $(i + 3) == "--no-recurse-submodules" && $(i + 4) == "--template=") } } END { exit !ok }' "$T/rec.log"
awk '/^ENV / { sub(/^ENV /, ""); sub(/=.*/, ""); print }' "$T/rec.log" | sort -u > "$T/env.names"
check "... and only the hardened environment" \
  test -z "$(grep -vxE 'HOME|PATH|TMPDIR|LC_ALL|TZ|GIT_NO_LAZY_FETCH|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|GIT_ALLOW_PROTOCOL|GIT_CEILING_DIRECTORIES|GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS|PWD|OLDPWD|SHLVL|_' "$T/env.names")"
check "... with GIT_ALLOW_PROTOCOL=file, so the copy's clone permits only the local-file transport" \
  grep -qx "ENV GIT_ALLOW_PROTOCOL=file" "$T/rec.log"
# The clone's upload-pack runs in the source without hgit's -c pins (git's local transport clears
# GIT_CONFIG_PARAMETERS for it), so the clone keeps git's own ownership check, in default mode too.
check "... and with no global git config, in default mode too" \
  awk -F '\037' '$1 == "ARGV" { c = 0; for (i = 2; i <= NF; i++) if ($i == "clone") c = 1 } $1 == "ARGV" && c { want = 1; next }
    want && /^ENV GIT_CONFIG_GLOBAL=/ { found = ($0 == "ENV GIT_CONFIG_GLOBAL=/dev/null"); want = 0 } END { exit !found }' "$T/rec.log"
check "... and runs no hook" nomarks

# PATH: entries inside the working directory, relative ones and "." are dropped before anything runs.
mkdir -p "$WT/.bin" "$WT/bin"
for d in .bin bin; do
  for p in git env tr find sort; do
    printf '#!/bin/sh\ntouch "%s/marks/wt-%s"\nexit 0\n' "$T" "$p" > "$WT/$d/$p"
    chmod +x "$WT/$d/$p"
  done
done
PATH="$WT/.bin:bin:.:$PATH" run "$WT" rev-parse HEAD
check "programs inside the working directory are never run from PATH" test "$RC:$(cat "$T/out")" = "0:$SIGNED"
check "... none of them ran" nomarks
mv "$WT/.bin" "$T/wt-dotbin"
mv "$WT/bin" "$T/wt-bin"

# =================================================================================================
# Partial clones: a note on every read, nothing fetched, and copy refused.
# =================================================================================================
SRV="$T/promisor"; mkrepo "$SRV"
put "$SRV" f.txt 'first'
commit "$SRV" -m 'first'
put "$SRV" f.txt 'second'
commit "$SRV" -m 'second'
git -C "$SRV" config uploadpack.allowFilter true
PC="$T/partial"
if ! git clone -q --filter=blob:none --no-local "file://$SRV" "$PC" >/dev/null 2>&1; then
  skp "partial clones: this git could not make a blobless clone"
else
  git -C "$PC" config remote.origin.url "evil::$SRV"
  git -C "$PC" config core.hooksPath "$T/hooks"
  for h in post-checkout post-index-change reference-transaction; do cp "$T/hooks/$h" "$PC/.git/hooks/$h"; done
  MISSING=$(git -C "$SRV" rev-parse HEAD~1:f.txt)
  clearmarks
  env -u GIT_NO_LAZY_FETCH git -C "$PC" cat-file -p "$MISSING" >/dev/null 2>&1
  if [ -e "$T/marks/remote-helper" ]; then ok "sanity: plain git fetches a missing object through the promisor's helper"
  else skp "sanity: this git did not fetch the missing object"; fi
  clearmarks
  NOTE='git-ro: partial clone: missing objects are not fetched; history and contents may be incomplete (Rule 11c)'
  run "$PC" partial
  check "partial: exit 3" test "$RC" = 3
  check "... printing the promisor key" has "$T/out" 'remote.origin.promisor true'
  run "$PC" cat-file -p "$MISSING"
  check "a read of a missing object fails" test "$RC" = 128
  check "... after the partial-clone note" test "$(sed -n 1p "$T/err")" = "$NOTE"
  run "$PC" log -p --oneline
  check "log -p in a partial clone prints the note" has "$T/err" "$NOTE"
  run "$PC" grep -e first HEAD~1
  check "grep of an older revision fails rather than fetch" test "$RC" != 0
  check "no read reached the promisor's helper" nomarks
  git -C "$PC" config remote.origin.url "ext::sh -c touch% $T/marks/ext-fetch"
  run "$PC" show HEAD~1:f.txt
  check "an ext:: promisor is not run either" nomarks
  (cd "$PC" && "$RUNDIR" new audit) >/dev/null 2>&1
  run_once "$PC" copy . audit_1
  check "copy of a partial clone: exit 3" test "$RC" = 3
  check "... with its one line" err_is "git-ro: . is a partial clone: a copy would lack the objects it never fetched, and nothing is fetched; make a full copy from a source you trust (Rule 11c)"
  check "... and nothing copied or fetched" sh -c "[ ! -e '$PC/audit_1/src.git' ] && [ -z \"\$(ls -A '$T/marks')\" ]"
fi

# =================================================================================================
# The transport allowlist is carried in the environment, so a checkout whose own config permits a
# non-local transport cannot widen it. On a git that ignores GIT_NO_LAZY_FETCH (git before 2.44.0, here
# a shim) a read of a missing object fetches nothing and runs nothing outside the tree.
# =================================================================================================
mkdir -p "$T/oldgit-nlf"
printf '#!/bin/sh\nunset GIT_NO_LAZY_FETCH\nexec "%s" "$@"\n' "$REAL_GIT" > "$T/oldgit-nlf/git"
chmod +x "$T/oldgit-nlf/git"
APC="$T/allow-partial"
if ! git clone -q --filter=blob:none --no-local "file://$SRV" "$APC" >/dev/null 2>&1; then
  skp "transport allowlist: this git could not make a blobless clone"
else
  git -C "$APC" config remote.origin.url "ext::sh -c touch% $T/marks/ext-reenabled"
  git -C "$APC" config protocol.ext.allow always
  clearmarks
  # Control: on a git that ignores GIT_NO_LAZY_FETCH, plain git reaches the ext:: transport this
  # checkout's config permits. Assert the allowlist stops it only when the control confirms the fixture
  # reaches it, so the assertion is never vacuous.
  ( cd "$APC" && PATH="$T/oldgit-nlf:$PATH" git -c protocol.allow=never show "HEAD~1:f.txt" ) >/dev/null 2>&1
  if [ -e "$T/marks/ext-reenabled" ]; then
    ok "control: this git reaches the ext:: transport once GIT_NO_LAZY_FETCH is ignored"
    clearmarks
    PATH="$T/oldgit-nlf:$PATH" run "$APC" show "HEAD~1:f.txt"
    check "a missing object is not fetched through a config-permitted ext:: transport" test "$RC" != 0
    check "... and nothing outside the tree runs" nomarks
    clearmarks
  else
    clearmarks
    skp "control: this git did not reach the ext:: transport; the transport-allowlist check is skipped"
  fi
fi

# =================================================================================================
# copy: the git version gate (a fake git that only answers --version), and an environment that names
# programs and templates.
# =================================================================================================
mkdir -p "$T/oldgit"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/oldgit/calls"\nfor a in "$@"; do :; done\nif [ "$a" = --version ]; then cat "%s/oldgit/version"; exit 0; fi\nexec "%s" "$@"\n' "$T" "$T" "$REAL_GIT" > "$T/oldgit/git"
chmod +x "$T/oldgit/git"
OLD='git-ro: refused: copy needs git with the May-2024 clone fixes: 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, or 2.46 or later'
FIXES='2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, 2.46 and later'
for v in 2.39.3 2.40.1 2.41.0 2.42.1 2.43.3 2.44.0 2.45.0 2.38.9 1.9.9 'garbage' '2'; do
  printf 'git version %s\n' "$v" > "$T/oldgit/version"
  before=$(ls "$WT/audit_1" | tr '\n' ' ')
  AUDITOR_STRICT=1 PATH="$T/oldgit:$PATH" run "$WT" copy . audit_1
  check "in strict mode copy with git $v: exit 69 and nothing copied" \
    sh -c "[ '$RC' = 69 ] && [ \"\$(cat '$T/err')\" = '$OLD' ] && [ \"\$(ls '$WT/audit_1' | tr '\n' ' ')\" = '$before' ]"
done
# In default mode (addendum H) such a git clones nothing: copy makes the bare copy with git's plumbing,
# with a note, and the copy holds what a clone would: every branch and tag, HEAD, the same objects.
: > "$T/oldgit/calls"
for v in 2.39.3 2.43.0 2.34.1 'garbage'; do
  printf 'git version %s\n' "$v" > "$T/oldgit/version"
  PATH="$T/oldgit:$PATH" run_once "$WT" copy . audit_1
  c=$(cat "$T/out")
  check "in default mode copy with git $v makes a copy, with one note" \
    test "$RC|$(cat "$T/err")" = "0|git-ro: note: this git ($v) has none of the May-2024 clone fixes for its release line ($FIXES), so copy made $c from git's plumbing instead of cloning (pack-objects in the source, index-pack in the copy); strict mode refuses this (Rule 11f)"
  check "... which holds every branch and tag of the repository, and its HEAD" \
    test "$(git --git-dir="$WT/$c" for-each-ref --format='%(objectname) %(refname)' | tr '\n' ' ')|$(git --git-dir="$WT/$c" symbolic-ref HEAD)" = \
      "$(git -C "$WT" for-each-ref --format='%(objectname) %(refname)' refs/heads refs/tags | tr '\n' ' ')|$(git -C "$WT" symbolic-ref HEAD)"
  check "... is whole, its objects checked" sh -c "git --git-dir='$WT/$c' fsck --no-dangling >/dev/null 2>&1"
  check "... and is a copy git-ro reads" sh -c "cd '$WT' && '$GITRO' --git-dir '$c' log --format=%H -1 | grep -qx '$SIGNED'"
done
check "... while git clone never ran" sh -c "grep -q ' pack-objects ' '$T/oldgit/calls' && ! grep -q ' clone ' '$T/oldgit/calls'"
check "... nor did a hook, a filter or a helper" nomarks
printf 'git version 2.34.1\n' > "$T/oldgit/version"
PATH="$T/oldgit:$PATH" run "$WT" rev-parse HEAD
check "a read with such a git gets a note in default mode" \
  test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|$SIGNED|git-ro: note: this git (2.34.1) has none of the May-2024 clone fixes for its release line ($FIXES); git-ro's reads clone nothing, and copy makes its copy from git's plumbing instead of cloning (Rule 11f)"
AUDITOR_STRICT=1 PATH="$T/oldgit:$PATH" run "$WT" rev-parse HEAD
check "... and none in strict mode" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|$SIGNED|"
for v in 2.39.4 2.40.2 2.41.1 2.42.2 2.43.4 2.44.1 2.45.1 2.46.0 3.0.0 '2.39.5 (Apple Git-154)' 2.47.0.windows.1 2.48.0-rc1; do
  printf 'git version %s\n' "$v" > "$T/oldgit/version"
  PATH="$T/oldgit:$PATH" run_once "$WT" copy . audit_1
  check "copy with git $v: accepted" test "$RC" = 0
done
mkdir -p "$T/evil-exec" "$T/evil-tpl/hooks"
for p in git-upload-pack git-remote-ext git-remote-https; do
  printf '#!/bin/sh\ntouch "%s/marks/exec-%s"\nexit 1\n' "$T" "$p" > "$T/evil-exec/$p"
  chmod +x "$T/evil-exec/$p"
done
cp "$T/hooks/post-checkout" "$T/evil-tpl/hooks/post-checkout"
GIT_EXEC_PATH="$T/evil-exec" GIT_TEMPLATE_DIR="$T/evil-tpl" GIT_CONFIG_PARAMETERS="'core.hooksPath=$T/hooks'" \
  run_once "$WT" copy . audit_1
check "copy ignores GIT_EXEC_PATH, GIT_TEMPLATE_DIR and GIT_CONFIG_PARAMETERS" test "$RC" = 0
check "... no program they name ran" nomarks
check "... and the copy has no hooks" test ! -e "$WT/$(cat "$T/out")/hooks"

# A copy that changed after copy made it is refused.
cp -R "$WT/audit_1/src.git" "$WT/audit_1/src-90.git"
git --git-dir="$WT/audit_1/src-90.git" config core.bare false
git --git-dir="$WT/audit_1/src-90.git" config core.worktree "$O"
run "$WT" --git-dir audit_1/src-90.git log -1
check "--git-dir whose config names a work tree is refused" \
  err_is 'git-ro: refused: --git-dir is not the top level of its repository: audit_1/src-90.git'
cp -R "$WT/audit_1/src.git" "$WT/audit_1/src-91.git"
rm "$WT/audit_1/src-91.git/auditor-copy"
run "$WT" --git-dir audit_1/src-91.git log -1
check "--git-dir without the auditor-copy marker is refused" \
  err_is 'git-ro: refused: --git-dir names no copy that git-ro.sh copy made: audit_1/src-91.git'
LR=$(cd "$WT" && "$RUNDIR" new audit)
run_once "$WT" copy . "$LR"
ln -s "$O" "$WT/$LR/poc/outside"
run "$WT" --git-dir "$LR/src.git" log -1
check "--git-dir in a run directory that holds a symbolic link is refused" \
  err_is "git-ro: refused: --git-dir's run directory holds a symbolic link: $LR"
run "$WT" copy . "$LR"
check "copy into a run directory that holds a symbolic link is refused" \
  err_is "git-ro: refused: copy's run directory holds a symbolic link: $LR"
rm "$WT/$LR/poc/outside"

# =================================================================================================
# tracked: case-insensitive, outside a repository, and with the repository above the working directory.
# =================================================================================================
TRK="$T/trk"; mkrepo "$TRK"
put "$TRK" Incident_5/notes.txt 'tracked notes'
put "$TRK" .Audit-Memory/audit.db 'x'
commit "$TRK" -m 'tracked run directory'
run "$TRK" tracked incident_5
check "tracked: a run directory tracked in another letter case is listed" test "$RC:$(cat "$T/out")" = 0:Incident_5/notes.txt
run "$TRK" tracked .audit-memory
check "tracked: the store tracked in another letter case is listed" test "$(cat "$T/out")" = .Audit-Memory/audit.db
mkdir -p "$T/plain"
run "$T/plain" tracked audit_1
check "tracked outside every repository: nothing, exit 0" test "$RC:$(cat "$T/out")" = 0:
mkdir -p "$TRK/inner"
put "$TRK" inner/audit_3/x.txt 'x'
commit "$TRK" -m 'nested'
run "$TRK/inner" tracked audit_3
check "tracked: a repository above the working directory decides" test "$(cat "$T/out")" = audit_3/x.txt
AUDITOR_STRICT=1 run "$TRK/inner" log -1
check "... and in strict mode git-ro never reads that repository's history, saying where its top level lies" \
  err_is 'git-ro: refused: the working directory lies below the top level of its repository (..); strict mode reads a repository only from its top level: start Claude Code there (Rule 11f)'
run "$TRK/inner" log --format=%s -1
check "... while in default mode it reads it from its top level (a session in a subdirectory)" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|nested|"
mkdir -p "$TRK/untracked/deep"
NOTHING='git-ro: refused: the working directory lies below the top level of its repository (../..), which tracks nothing under it, so it is not taken for the tree under audit: start Claude Code at that top level, or in a folder the repository tracks (Rule 11c)'
run "$TRK/untracked/deep" log -1
check "... but not from a directory under which it tracks nothing, in either mode, which it says" err_is "$NOTHING"
AUDITOR_STRICT=1 run "$TRK/untracked/deep" log -1
check "... (strict mode)" err_is "$NOTHING"

# =================================================================================================
# grep never reads the work tree: a tracked directory replaced by a link to files outside stays unread.
# =================================================================================================
G="$T/grep-link"; mkrepo "$G"
put "$G" keys/id.txt 'committed text'
commit "$G" -m keys
mkdir -p "$T/outside-keys"
printf 'OUTSIDE-KEY-MATERIAL\n' > "$T/outside-keys/id.txt"
rm -r "$G/keys"
ln -s "$T/outside-keys" "$G/keys"
if git -C "$G" grep -e OUTSIDE-KEY-MATERIAL >/dev/null 2>&1; then ok "sanity: plain git grep reads a file through the linked directory"
else skp "sanity: this git does not read through the linked directory"; fi
run "$G" grep -e OUTSIDE-KEY-MATERIAL
check "git-ro grep searches the index, not the linked directory" test "$RC:$(cat "$T/out")" = 1:
run "$G" grep -n -e committed
check "... and finds the committed text" test "$(cat "$T/out")" = 'keys/id.txt:1:committed text'

# =================================================================================================
# Revisions git-ro resolves itself. diff, blame and grep start from commits and trees whatever revision
# syntax they get: a root or shallow commit's A^!, A^@ (no parent at all), a negation, a range of one
# commit, ref options that mark the commit uninteresting. git would otherwise compare with or annotate
# the work tree, running its clean filter and reading files through linked directories.
# =================================================================================================
RT="$T/root-filter"; mkrepo "$RT"
printf '* filter=evil\n' > "$RT/.gitattributes"
git -C "$RT" add .gitattributes
put "$RT" a.rs 'fn a() {}'
commit "$RT" -m 'root import'
git -C "$RT" config filter.evil.clean "$T/bin/mark-clean"
touch -t 202001010000 "$RT/a.rs"
clearmarks
git -C "$RT" diff 'HEAD^!' >/dev/null 2>&1
if nomarks; then skp "sanity: this git does not run the clean filter for diff A^! of a root commit"
else ok "sanity: plain git diff A^! of a root commit runs the clean filter on the work tree"; fi
clearmarks
git -C "$RT" blame '^HEAD' -- a.rs >/dev/null 2>&1
if nomarks; then skp "sanity: this git does not run the clean filter for blame ^HEAD"
else ok "sanity: plain git blame ^HEAD annotates the work tree, running the clean filter"; fi
clearmarks
touch -t 202101010000 "$RT/a.rs"
snapshot "$RT" "$T/snap.base"
run "$RT" diff 'HEAD^!'
check "diff A^! of a root commit compares it with the empty tree" \
  sh -c "[ '$RC' = 0 ] && grep -q '^new file mode' '$T/out' && grep -qx '+fn a() {}' '$T/out'"
check "... runs no clean filter" nomarks
snapshot "$RT" "$T/snap.now"
check "... and leaves the index and the work tree as they were" cmp -s "$T/snap.base" "$T/snap.now"
run "$RT" diff 'HEAD^@' 'HEAD^@'
check "diff A^@ (a root commit has no parent) is refused" \
  err_is 'git-ro: refused: diff compares committed revisions (A..B, A...B, A^!, A B or --cached [A]), and this names no single tree: HEAD^@'
run "$RT" diff 'HEAD^@' HEAD:a.rs -- a.rs
check "... and so is a blob against nothing, which git compares with the file in the work tree" \
  err_is 'git-ro: refused: diff compares committed revisions (A..B, A...B, A^!, A B or --cached [A]), and this names no single tree: HEAD^@'
# --merge-base takes commits, and git-ro hands git trees (git 2.50 crashes on them): A...B says the same.
run "$RT" diff --merge-base HEAD HEAD
check "diff --merge-base A B is refused, pointing to A...B" \
  sh -c "[ '$RC' = 64 ] && [ ! -s '$T/out' ] && [ \"\$(cat '$T/err')\" = 'git-ro: refused: diff --merge-base A B is written A...B here: git-ro gives git trees, which have no merge base' ]"
run "$RT" diff --cached --merge-base HEAD
check "... while diff --cached --merge-base A runs" test "$RC" = 0
for b in "^HEAD -- a.rs" "HEAD..HEAD -- a.rs" "--not --all HEAD -- a.rs" "^HEAD HEAD -- a.rs" "HEAD^@ -- a.rs"; do
  # shellcheck disable=SC2086
  run "$RT" blame $b
  check "blame $b is refused before git runs" sh -c "[ '$RC' = 64 ] && [ ! -s '$T/out' ]"
done
check "... none ran the clean filter" nomarks
run "$RT" blame HEAD -- a.rs
check "blame of a commit still runs" sh -c "[ '$RC' = 0 ] && grep -q 'fn a() {}' '$T/out'"
git -C "$RT" config --unset filter.evil.clean
put "$RT" a.rs 'fn a() { second(); }'
commit "$RT" -m second
git -C "$RT" config filter.evil.clean "$T/bin/mark-clean"
git -C "$RT" rev-parse HEAD > "$RT/.git/shallow"
touch -t 202001010000 "$RT/a.rs"
clearmarks
run "$RT" diff 'HEAD^!'
check "diff A^! of a commit the shallow file cuts off compares it with the empty tree" \
  sh -c "[ '$RC' = 0 ] && grep -qx '+fn a() { second(); }' '$T/out' && ! grep -qx -- '-fn a() {}' '$T/out'"
check "... runs no clean filter" nomarks
rm "$RT/.git/shallow"
run "$RT" diff 'HEAD^!'
check "diff A^! of a commit with a parent compares it with that parent" \
  sh -c "grep -qx -- '-fn a() {}' '$T/out' && grep -qx '+fn a() { second(); }' '$T/out'"
run "$RT" blame --reverse HEAD~1..HEAD -- a.rs
check "blame --reverse A..B still runs" test "$RC" = 0
run "$G" blame '^HEAD' -- keys/id.txt
check "blame ^HEAD never reads a file through a linked directory" sh -c "[ '$RC' = 64 ] && ! grep -q OUTSIDE-KEY-MATERIAL '$T/out'"
check "no case of this section ran a configured program" nomarks
# grep decides from its words. A git directory named after git's own message and a corrupt blob made git
# grep --cached fail with that text, which the old fallback took for "trees are given".
GM="$T/grep-message"; MSG='gd both --cached and trees are given'
mkdir -p "$GM"
git init -q --separate-git-dir="$GM/$MSG" "$GM"
git -C "$GM" symbolic-ref HEAD refs/heads/main
put "$GM" a.txt 'hello'
put "$GM" keys/id.txt 'committed text'
commit "$GM" -m keys
oid=$(git -C "$GM" rev-parse HEAD:a.txt)
chmod u+w "$GM/$MSG/objects/${oid:0:2}/${oid:2}"
printf 'garbage' > "$GM/$MSG/objects/${oid:0:2}/${oid:2}"
rm -r "$GM/keys"
ln -s "$T/outside-keys" "$GM/keys"
git -C "$GM" grep --cached -e OUTSIDE-KEY-MATERIAL > "$T/plain.out" 2>&1
if grep -qF 'both --cached and trees are given' "$T/plain.out"; then ok "sanity: git's error on the corrupt blob holds the text, in the git directory's name"
else skp "sanity: this git's error does not name the git directory"; fi
run "$GM" grep -n -e OUTSIDE-KEY-MATERIAL
check "grep of an index with a corrupt blob fails, and never falls back to the work tree" \
  sh -c "[ '$RC' != 0 ] && [ '$RC' != 64 ] && ! grep -q OUTSIDE-KEY-MATERIAL '$T/out'"
# A revision named like an option (refs/heads/-n) stays a revision: git gets it behind --end-of-options.
git -C "$G" update-ref refs/heads/-n HEAD
run "$G" grep committed -n
check "grep searches a revision named -n as a revision" test "$(cat "$T/out")" = '-n:keys/id.txt:committed text'
run "$G" grep OUTSIDE-KEY-MATERIAL -n
check "... and finds nothing of the linked directory there" test "$RC:$(cat "$T/out")" = 1:
git -C "$G" update-ref -d refs/heads/-n
run "$G" grep -n -e committed HEAD keys
check "grep with revisions and then a path without -- is refused" \
  err_is 'git-ro: refused: grep searches these revisions, so give paths after --: keys'
run "$G" grep -n -e committed HEAD -- keys
check "... and with -- searches that path of the revision" test "$(cat "$T/out")" = 'HEAD:keys/id.txt:1:committed text'

# =================================================================================================
# What the repository could set to change what a read shows: how grep and log --grep read a pattern,
# the root commit's patch, replace refs, submodule ignore rules, grafts and a shallow file.
# =================================================================================================
SH="$T/shape"; mkrepo "$SH"
put "$SH" src/a.rs "$(printf 'let owner_ok = true;\nliteral (ok) here\npipe a|b here\ncount x{2} here\nxx double')"
printf 'a\000b\001c\n' > "$SH/bin.dat"
git -C "$SH" add bin.dat
commit "$SH" -m 'root import'
put "$SH" src/b.rs 'fn second() {}'
commit "$SH" -m 'second step'
printf '[submodule "sub"]\n\tpath = sub\n\turl = ./sub\n\tignore = all\n' > "$SH/.gitmodules"
git -C "$SH" add .gitmodules
git -C "$SH" update-index --add --cacheinfo "160000,$O1,sub"
commit "$SH" -m 'add sub'
git -C "$SH" update-index --cacheinfo "160000,$O2,sub"
commit "$SH" -m 'move sub'
# Each case runs through git-ro and through plain git, with the repository's config clean and then under
# each setting that changes how a pattern is read. git-ro must print what it printed with a clean config.
PATTERNS=$(printf '%s\n' 'grep	-n	-e	owner.*ok	HEAD' 'grep	-n	-e	(ok)	HEAD' 'grep	-n	-e	a|b	HEAD' \
  'grep	-n	-e	x{2}	HEAD' 'grep	-n	-e	owner.*ok' 'grep	-n	-E	-e	(ok)	HEAD' 'grep	-n	-F	-e	x{2}	HEAD' \
  'log	--format=%s	--grep	sec.nd' 'log	--format=%s	-E	--grep	second|root')
shape_runs() { # shape_runs <tag>: git-ro's output into $T/shape.<tag>, plain git's into $T/plain.<tag>
  local line
  : > "$T/shape.$1"
  : > "$T/plain.$1"
  while IFS= read -r line; do
    IFS=$'\t' read -r -a args <<< "$line"
    run "$SH" "${args[@]}"
    { printf '$ %s\nstatus %s\n' "${args[*]}" "$RC"; cat "$T/out" "$T/err"; } >> "$T/shape.$1"
    { printf '$ %s\n' "${args[*]}"; git -C "$SH" "${args[@]}" 2>&1; printf 'status %s\n' "$?"; } >> "$T/plain.$1"
  done <<EOF
$PATTERNS
EOF
}
snapshot "$SH" "$T/snap.base"
shape_runs clean
check "the clean grep cases find what they look for" has "$T/shape.clean" 'HEAD:src/a.rs:1:let owner_ok = true;'
check "... where a basic pattern's parentheses match themselves" \
  awk '/^\$ / { on = ($0 == "$ grep -n -e (ok) HEAD") } on && /^HEAD:src\/a.rs:/ { n++; if ($0 !~ /^HEAD:src\/a.rs:2:/) bad = 1 } END { exit !(n == 1 && !bad) }' "$T/shape.clean"
check "... and a caller's -E still reads an extended pattern" \
  awk '/^\$ / { on = ($0 == "$ grep -n -E -e (ok) HEAD") } on && /^HEAD:src\/a.rs:1:/ { found = 1 } END { exit !found }' "$T/shape.clean"
for setting in grep.patternType=fixed grep.patternType=perl grep.patternType=extended grep.extendedRegexp=true; do
  git -C "$SH" config "${setting%%=*}" "${setting#*=}"
  shape_runs "$setting"
  git -C "$SH" config --unset "${setting%%=*}"
  if cmp -s "$T/plain.clean" "$T/plain.$setting"; then skp "sanity: plain git reads patterns the same under $setting"
  else ok "sanity: plain git reads patterns differently under $setting"; fi
  check "git-ro grep and log --grep under $setting print what they print with a clean config" \
    cmp -s "$T/shape.clean" "$T/shape.$setting"
done
snapshot "$SH" "$T/snap.now"
check "... and changed no byte of the repository" cmp -s "$T/snap.base" "$T/snap.now"
git -C "$SH" config log.showRoot false
git -C "$SH" log -p --reverse --format=%s > "$T/plain.out" 2>&1
if grep -qF '+let owner_ok = true;' "$T/plain.out"; then skp "sanity: plain git still shows the root patch under log.showRoot=false"
else ok "sanity: plain git hides the root commit's patch under log.showRoot=false"; fi
run "$SH" log -p --reverse --format=%s
check "log.showRoot=false from the repository does not hide the root commit's patch" has "$T/out" '+let owner_ok = true;'
git -C "$SH" config --unset log.showRoot
C2=$(git -C "$SH" rev-parse HEAD~2)
FAKE=$(git -C "$SH" commit-tree -p "$(git -C "$SH" rev-parse HEAD~3)" -m 'REPLACED STEP' "$(git -C "$SH" rev-parse "$C2^{tree}")")
git -C "$SH" replace "$C2" "$FAKE"
git -C "$SH" log --format=%s > "$T/plain.out" 2>&1
if grep -qx 'REPLACED STEP' "$T/plain.out"; then ok "sanity: plain git shows the replacement commit"
else skp "sanity: this git does not show the replacement commit"; fi
run "$SH" log --format=%s
check "a replace ref does not change what log shows" sh -c "grep -qx 'second step' '$T/out' && ! grep -q 'REPLACED STEP' '$T/out'"
git -C "$SH" replace -d "$C2" >/dev/null
git -C "$SH" log -p -1 > "$T/plain.out" 2>&1
if grep -qF "+Subproject commit $O2" "$T/plain.out"; then skp "sanity: plain git shows the submodule change that .gitmodules ignores"
else ok "sanity: plain git hides a submodule change that .gitmodules ignores"; fi
for c in 'log -p -1' 'show HEAD' 'diff HEAD~1..HEAD' 'diff-tree -p HEAD' 'reflog show -p -1'; do
  # shellcheck disable=SC2086
  run "$SH" $c
  check "git-ro $c shows the submodule's new commit whatever .gitmodules ignores" has "$T/out" "+Subproject commit $O2"
done
run "$SH" cat-file -p HEAD:bin.dat
printf 'a?b?c\n' > "$T/bin.want"
check "NUL and the other control bytes of a blob print as ?" cmp -s "$T/out" "$T/bin.want"
git -C "$SH" rev-parse HEAD > "$SH/.git/info/grafts"
if [ "$(git -C "$SH" -c advice.graftFileDeprecated=false rev-list --count HEAD 2>/dev/null)" = 1 ]; then
  ok "sanity: plain git cuts the history at the grafted commit"
else skp "sanity: this git does not read info/grafts"; fi
AUDITOR_STRICT=1 run "$SH" log --oneline
check "in strict mode a repository with info/grafts is refused" \
  err_is 'git-ro: refused: the working directory rewrites commit parents (info/grafts), so git would show another history; review that file: .'
run "$SH" log --oneline
# git itself adds a hint that info/grafts is deprecated.
check "... and in default mode read with a note first, as the grafts set it" \
  test "$RC|$(wc -l < "$T/out" | tr -d ' ')|$(sed -n 1p "$T/err")" = "0|1|git-ro: note: the working directory rewrites commit parents (info/grafts), so git shows the history that file sets; strict mode refuses this (Rule 11f)"
rm "$SH/.git/info/grafts"
git -C "$SH" rev-parse HEAD~1 > "$SH/.git/shallow"
run "$SH" log --format=%s
check "a shallow clone gets a note" test "$(sed -n 1p "$T/err")" = 'git-ro: shallow clone: history before the shallow boundary is missing (Rule 11c)'
check "... and its history stops at the boundary" test "$(wc -l < "$T/out" | tr -d ' ')" = 2
rm "$SH/.git/shallow"

# =================================================================================================
# A session started in a subdirectory of a repository (spec §4.2): in default mode git-ro reads the
# repository from its top level, and every read prints what plain git prints in that subdirectory; git
# runs in <empty>/<prefix>, made and removed with each read. Strict mode refuses (above, with TRK).
# =================================================================================================
SUB="$T/mono"; mkrepo "$SUB"
put "$SUB" programs/foo/src/lib.rs "$(printf 'fn a() {}\nlet x = 1;')"
put "$SUB" programs/foo/README 'foo'
put "$SUB" other/o.rs 'fn o() {}'
put "$SUB" Cargo.lock "$(printf '[[package]]\nname = "a"\nversion = "1.0.0"')"
commit "$SUB" -m one
put "$SUB" programs/foo/src/lib.rs "$(printf 'fn a() { b(); }\nlet x = 2;')"
put "$SUB" Cargo.lock "$(printf '[[package]]\nname = "a"\nversion = "1.0.1"')"
commit "$SUB" -m two
mkdir -p "$T/subtmp"
nsub=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  IFS=$'\t' read -r -a args <<< "$line"
  nsub=$((nsub + 1))
  TMPDIR="$T/subtmp" run "$SUB/programs/foo" "${args[@]}"
  (cd "$SUB/programs/foo" && git "${args[@]}") > "$T/plain.out" 2>&1
  if [ "$RC" = 0 ] && [ ! -s "$T/err" ] && cmp -s "$T/out" "$T/plain.out" && [ -z "$(ls -A "$T/subtmp")" ]; then
    ok "from programs/foo: git-ro.sh ${args[*]} prints what git prints there"
  else
    ko "from programs/foo: git-ro.sh ${args[*]} -> status $RC, stderr $(cat "$T/err"), $(cmp -s "$T/out" "$T/plain.out" && echo same || echo DIFFERENT), left: $(ls -A "$T/subtmp")"
  fi
done <<'EOF'
log	--format=%s	--	src/lib.rs
log	--oneline
log	-p	-1	--	src
log	-L	1,1:src/lib.rs	--format=%s
show	HEAD:./src/lib.rs
show	HEAD:programs/foo/README
show	--stat	HEAD
cat-file	-p	HEAD:./src/lib.rs
grep	-n	fn
grep	-n	-e	let	HEAD
grep	-n	-e	let	HEAD	--	src
ls-files
ls-tree	HEAD
ls-tree	HEAD	src
ls-tree	-r	--name-only	HEAD
blame	HEAD	--	src/lib.rs
diff	HEAD~1	HEAD	--	src
diff	HEAD~1..HEAD	--stat
diff-tree	-r	HEAD~1	HEAD	--	src
rev-parse	--show-prefix
rev-parse	--show-toplevel
EOF
check "the subdirectory reads ran ($nsub)" test "$nsub" -ge 20
# The repository's diff.relative and grep.fullName would hide the changes outside the subdirectory and
# change the paths grep prints; git-ro pins both off there, and plain git given the same pins agrees.
git -C "$SUB" config diff.relative true; git -C "$SUB" config grep.fullName true
for a in 'diff --stat HEAD~1 HEAD' 'log -p -1' 'show HEAD' 'grep -n -e let HEAD'; do
  # shellcheck disable=SC2086
  TMPDIR="$T/subtmp" run "$SUB/programs/foo" $a
  # shellcheck disable=SC2086
  (cd "$SUB/programs/foo" && git -c diff.relative=false -c grep.fullName=false $a) > "$T/plain.out" 2>&1
  check "from programs/foo, git-ro.sh $a reads past the repository's diff.relative and grep.fullName" \
    sh -c "[ '$RC' = 0 ] && cmp -s '$T/out' '$T/plain.out' && [ -z \"\$(ls -A '$T/subtmp')\" ]"
done
run "$SUB/programs/foo" diff --stat HEAD~1 HEAD
check "... so the diff still shows the lockfile at the top level" grep -q 'Cargo.lock' "$T/out"
run "$SUB/programs/foo" diff --relative --stat HEAD~1 HEAD
check "... while the caller's own --relative still applies" sh -c "[ '$RC' = 0 ] && ! grep -q 'Cargo.lock' '$T/out'"
git -C "$SUB" config --unset diff.relative; git -C "$SUB" config --unset grep.fullName
mkdir -p "$SUB/programs/foo/src/deep"; put "$SUB" programs/foo/src/deep/d.rs 'fn d() {}'; commit "$SUB" -m deep
AUDITOR_STRICT=1 run "$SUB/programs/foo/src/deep" log -1
check "strict mode names the top level two levels up" \
  err_is 'git-ro: refused: the working directory lies below the top level of its repository (../../../..); strict mode reads a repository only from its top level: start Claude Code there (Rule 11f)'
# Below the hostile repository: the reads run nothing its config names there either.
clearmarks
for a in 'log -p -1' 'show HEAD' 'grep -n -e has_one HEAD' 'diff HEAD~3 HEAD' 'ls-files' 'config --list'; do
  # shellcheck disable=SC2086
  run "$WT/programs/demo" $a
  check "from a subdirectory of the hostile repository, git-ro.sh $a runs and starts nothing" \
    sh -c "[ '$RC' != 64 ] && [ -z \"\$(ls -A '$T/marks')\" ]"
done

# =================================================================================================
# blame where the repository's config sets blame.ignoreRevsFile (GIT-06). In default mode git-ro copies
# the file it names into git's empty work tree, where git looks for a relative one, when that is a
# regular file of one link and at most 1 MiB in the work tree; anything else, and strict mode, refuse.
# =================================================================================================
BI="$T/blame-ignore"; mkrepo "$BI"
put "$BI" sub/f.txt "$(printf 'a\nb')"; commit "$BI" -m one
put "$BI" sub/f.txt "$(printf 'A\nb')"; commit "$BI" -m reformat
git -C "$BI" rev-parse HEAD > "$BI/.git-blame-ignore-revs"; git -C "$BI" add .git-blame-ignore-revs; commit "$BI" -m ignore
git -C "$BI" config blame.ignoreRevsFile .git-blame-ignore-revs
mkdir -p "$T/bitmp"
(cd "$BI" && git blame HEAD -- sub/f.txt) > "$T/plain.out" 2>&1
TMPDIR="$T/bitmp" run "$BI" blame HEAD -- sub/f.txt
check "in default mode blame honours an ignore-revs file the work tree holds, as plain git does" \
  sh -c "[ '$RC' = 0 ] && [ ! -s '$T/err' ] && cmp -s '$T/out' '$T/plain.out' && [ -z \"\$(ls -A '$T/bitmp')\" ]"
check "... where the reformatting commit is passed over" sh -c "! grep -q \"^\$(git -C '$BI' rev-parse --short=7 HEAD~1)\" '$T/out'"
TMPDIR="$T/bitmp" run "$BI/sub" blame HEAD -- f.txt
check "... and from a subdirectory too" sh -c "[ '$RC' = 0 ] && [ ! -s '$T/err' ] && cmp -s '$T/out' '$T/plain.out' && [ -z \"\$(ls -A '$T/bitmp')\" ]"
IGN="git-ro: refused: blame does not run where the repository's config sets blame.ignoreRevsFile; blame a copy (git-ro.sh copy, then --git-dir)"
AUDITOR_STRICT=1 run "$BI" blame HEAD -- sub/f.txt
check "... and strict mode refuses" err_is "$IGN"
mv "$BI/.git-blame-ignore-revs" "$T/revs.kept"
run "$BI" blame HEAD -- sub/f.txt
check "default mode refuses when the file is missing" err_is "$IGN"
ln -s "$T/revs.kept" "$BI/.git-blame-ignore-revs"
run "$BI" blame HEAD -- sub/f.txt
check "... or a link" err_is "$IGN"
rm "$BI/.git-blame-ignore-revs"
ln "$T/revs.kept" "$BI/.git-blame-ignore-revs"
run "$BI" blame HEAD -- sub/f.txt
check "... or a file with a second link" err_is "$IGN"
rm "$BI/.git-blame-ignore-revs"
awk 'BEGIN { for (i = 0; i < 30000; i++) print "0123456789012345678901234567890123456789" }' > "$BI/.git-blame-ignore-revs"
run "$BI" blame HEAD -- sub/f.txt
check "... or one over 1 MiB" err_is "$IGN"
mv "$T/revs.kept" "$BI/.git-blame-ignore-revs"
for v in "$BI/.git-blame-ignore-revs" '~/revs' 'sub/../.git-blame-ignore-revs' ''; do
  git -C "$BI" config blame.ignoreRevsFile "$v"
  run "$BI" blame HEAD -- sub/f.txt
  check "... or when the key names '$v'" err_is "$IGN"
done
git -C "$BI" config blame.ignoreRevsFile .git-blame-ignore-revs
check "the blame cases ran nothing a config names" nomarks

# =================================================================================================
# A checkout another user owns (CONF-05; git's own test knob stands for the other user, and the suite's
# git sees no system or global config, as on CI): default mode reads it through the safe-directory file,
# strict mode refuses it. A linked worktree whose main checkout lies outside (spec §4.5, addendum I):
# default mode reads it, strict mode refuses it.
# =================================================================================================
mkdir -p "$T/other"
printf '#!/bin/sh\nGIT_TEST_ASSUME_DIFFERENT_OWNER=1 exec "%s" "$@"\n' "$REAL_GIT" > "$T/other/git"
chmod +x "$T/other/git"
PATH="$T/other:$PATH" run "$SUB" log --format=%s -1
check "in default mode git-ro reads a checkout another user owns" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|deep|"
AUDITOR_STRICT=1 PATH="$T/other:$PATH" run "$SUB" log --format=%s -1
check "... and strict mode refuses it" \
  err_is 'git-ro: refused: the working directory is not a git repository that git can read (none there, or another user owns it: audit a copy): .'
MAINO="$T/main-out"; mkrepo "$MAINO"; put "$MAINO" m.rs 'fn m() {}'; commit "$MAINO" -m main
git -C "$MAINO" worktree add -q -b lw "$T/lwt" >/dev/null 2>&1
run "$T/lwt" log --format=%s -1
check "in default mode git-ro reads a linked worktree whose main checkout lies outside it" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|main|"
AUDITOR_STRICT=1 run "$T/lwt" log --format=%s -1
check "... and strict mode refuses it" err_is 'git-ro: refused: the working directory keeps its git directory outside the working directory: .'
ln -s "$T/hooks/post-checkout" "$MAINO/.git/hooks/post-checkout"
run "$T/lwt" log --format=%s -1
check "... and a hook installed as a link there changes nothing" test "$RC|$(cat "$T/out")|$(cat "$T/err")" = "0|main|"
check "... and runs no hook" nomarks

# =================================================================================================
# The installation: never inside the working directory, and only a path a quoted call can match.
# =================================================================================================
run "$ROOT" rev-parse HEAD
check "an installation inside the working directory is refused" \
  err_is 'git-ro: refused: the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)'
n=0
for c in '"' '$' '`' '\' "$(printf 'a\nb')"; do
  n=$((n + 1))
  inst="$T/inst$n-$c-x"
  mkdir -p "$inst/scripts/lib"
  cp "$GITRO" "$inst/scripts/git-ro.sh"
  cp "$ROOT/scripts/lib/confine.sh" "$inst/scripts/lib/confine.sh"
  (cd "$WT" && "$BASH" "$inst/scripts/git-ro.sh" rev-parse HEAD) >"$T/out" 2>"$T/err"
  check "an installation path holding $(printf '%s' "$c" | od -An -c | tr -d ' \n') is refused" \
    err_is 'git-ro: refused: the installation path holds a quote, $, a backtick, a backslash or a control character, so its quoted call cannot match as written'
done

# =================================================================================================
# Arguments with control characters, and long ones.
# =================================================================================================
run "$WT" log "$(printf 'a\001b')"
check "an argument with a control character is refused" err_is 'git-ro: refused: an argument holds a control character: a?b'
run "$WT" log "--format=%s$(printf '\033')[31m"
check "... an escape character too" err_is 'git-ro: refused: an argument holds a control character: --format=%s?[31m'
run "$WT" log -- "$(printf 'x\ny')"
check "... after -- as well" err_is 'git-ro: refused: an argument holds a control character: x?y'
long=$(awk 'BEGIN { for (i = 0; i < 4097; i++) printf "a" }')
run "$WT" log -- "$long"
check "an argument longer than 4096 bytes is refused" err_is 'git-ro: refused: an argument is longer than 4096 bytes'
check "nothing in this suite ran a configured program, hook or helper" nomarks

if [ -n "${CONFINE_TRANSCRIPT:-}" ]; then cp "$T/transcript" "$CONFINE_TRANSCRIPT"; fi
echo
echo "git-ro tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
