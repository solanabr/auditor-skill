#!/usr/bin/env bash
# test-git-ro.sh — self-test for scripts/git-ro.sh and the hardened git call in scripts/lib/confine.sh.
# Builds hostile repositories under ${TMPDIR:-/tmp} at test time: config that names programs (pager,
# fsmonitor, external diff, textconv, clean, smudge and process filters, signature programs, a pretty
# alias, aliases, an include, hooks through core.hooksPath and .git/hooks), a submodule whose git
# directory lies outside, and a partial clone whose promisor remote is a custom helper or ext::. Runs the
# case file fixtures/git-ro/cases.txt, every allowed form, the copy and its git version gate, and checks
# the argument order and environment git receives. Every case runs under each bash on the machine
# (/bin/bash and the bash running this suite, when they differ) and must print the same under each.
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
for d in inner-link alt worktree; do mkrepo "$WT/$d"; put "$WT/$d" f.txt "$d"; commit "$WT/$d" -m "$d"; done
ln -s "$O/.git/refs/heads/main" "$WT/inner-link/.git/refs/heads/outside"
printf '%s/.git/objects\n' "$O" > "$WT/alt/.git/objects/info/alternates"
git -C "$WT/worktree" config core.worktree "$O"
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
sane "update-index --really-refresh runs the post-index-change hook" marker hook-post-index-change update-index --really-refresh
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
run_once "$WT" copy . audit_1
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
# Each shell copies into a run directory of its own; the output must match but for that name.
i=0
for sh in "${SHELLS[@]}"; do
  r=$(cd "$WT" && "$RUNDIR" new audit)
  (cd "$WT" && "$sh" "$GITRO" copy . "$r") 2>&1 | sed "s#$r#<R>#g" > "$T/copy.$i"
  i=$((i + 1))
done
check "copy prints the same under each shell" sh -c "[ -z \"\$(cat '$T'/copy.* | sort -u | sed 1,2d)\" ]"

# =================================================================================================
# The case file: hostile argument vectors, each refused with its one line.
# =================================================================================================
ncase=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  want_rc=${line%%$'\t'*}
  rest=${line#*$'\t'}
  want_err=${rest%%$'\t'*}
  rest=${rest#*$'\t'}
  IFS=$'\t' read -r -a args <<< "$rest"
  run "$WT" "${args[@]}"
  ncase=$((ncase + 1))
  if [ "$RC" = "$want_rc" ] && err_is "$want_err" && out_empty; then ok "case: git-ro.sh ${args[*]}"
  else ko "case: git-ro.sh ${args[*]} -> status $RC, stderr: $(cat "$T/err")"; fi
done < "$CASES"
check "the case file has cases ($ncase)" test "$ncase" -gt 200
check "no case ran a configured program, hook or helper" nomarks
run "$WT"
check "no arguments: usage, exit 64" \
  err_is 'git-ro: refused: usage: git-ro.sh [--repo <dir> | --git-dir <R>/src.git] <subcommand> [<arg>...], or copy <dir> <R>, partial [--repo <dir>], tracked <path>'

# =================================================================================================
# Every allowed form runs, prints, and starts nothing the repository's config names.
# =================================================================================================
nallowed=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  want_rc=${line%%$'\t'*}
  IFS=$'\t' read -r -a args <<< "${line#*$'\t'}"
  run "$WT" "${args[@]}"
  nallowed=$((nallowed + 1))
  if [ "$RC" = "$want_rc" ] && { [ "$want_rc" != 0 ] || [ -s "$T/out" ]; } && nomarks; then ok "allowed: git-ro.sh ${args[*]}"
  else ko "allowed: git-ro.sh ${args[*]} -> status $RC, marks: $(ls "$T/marks" | tr '\n' ' ') stderr: $(cat "$T/err")"; fi
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
git -C "$WT" config --unset blame.ignoreRevsFile
for b in 'HEAD -- a.rs' '-L 1,1 HEAD -- a.rs' '-w --reverse HEAD~3..HEAD -- a.rs' '-M -C HEAD -- programs/demo/src/lib.rs'; do
  # shellcheck disable=SC2086
  run "$WT" blame $b
  check "allowed: git-ro.sh blame $b (diff driver, filters and hooks configured)" sh -c "[ '$RC' = 0 ] && [ -s '$T/out' ] && [ -z \"\$(ls -A '$T/marks')\" ]"
done
git -C "$WT" config blame.ignoreRevsFile "$T/outside-revs"
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
printf '%s\n' "$SIGNED control bytes" "$O1 first" > "$T/shortlog.in"
run_in "$T/shortlog.in" "$WT" shortlog -s
check "other subcommands never read standard input (shortlog prints nothing)" test "$RC:$(cat "$T/out")" = 0:
run "$WT" grep -e $'\t' HEAD
check "a TAB in an argument is allowed" test "$RC" != 64
check "no allowed form ran a configured program, hook or helper" nomarks

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
  test -z "$(grep -vxE 'HOME|PATH|TMPDIR|LC_ALL|TZ|GIT_NO_LAZY_FETCH|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_TERMINAL_PROMPT|GIT_OPTIONAL_LOCKS|GIT_CEILING_DIRECTORIES|GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS|PWD|OLDPWD|SHLVL|_' "$T/env.names")"
check "... with GIT_CONFIG_GLOBAL=/dev/null and GIT_CONFIG_NOSYSTEM=1" \
  sh -c "grep -qx 'ENV GIT_CONFIG_GLOBAL=/dev/null' '$T/rec.log' && grep -qx 'ENV GIT_CONFIG_NOSYSTEM=1' '$T/rec.log'"
check "... and GIT_CEILING_DIRECTORIES at the working directory's parent" grep -qx "ENV GIT_CEILING_DIRECTORIES=$T" "$T/rec.log"
clearmarks

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
# copy: the git version gate (a fake git that only answers --version), and an environment that names
# programs and templates.
# =================================================================================================
mkdir -p "$T/oldgit"
printf '#!/bin/sh\nif [ "$1" = --version ]; then cat "%s/oldgit/version"; exit 0; fi\nexec "%s" "$@"\n' "$T" "$REAL_GIT" > "$T/oldgit/git"
chmod +x "$T/oldgit/git"
OLD='git-ro: refused: copy needs git with the May-2024 clone fixes: 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, or 2.46 or later'
for v in 2.39.3 2.40.1 2.41.0 2.42.1 2.43.3 2.44.0 2.45.0 2.38.9 1.9.9 'garbage' '2'; do
  printf 'git version %s\n' "$v" > "$T/oldgit/version"
  before=$(ls "$WT/audit_1" | tr '\n' ' ')
  PATH="$T/oldgit:$PATH" run "$WT" copy . audit_1
  check "copy with git $v: exit 69 and nothing copied" \
    sh -c "[ '$RC' = 69 ] && [ \"\$(cat '$T/err')\" = '$OLD' ] && [ \"\$(ls '$WT/audit_1' | tr '\n' ' ')\" = '$before' ]"
done
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
run "$TRK/inner" log -1
check "... but git-ro never reads that repository's history" \
  err_is 'git-ro: refused: the working directory is not a git repository that git can read (none there, or another user owns it: audit a copy): .'

# =================================================================================================
# The installation: never inside the working directory, and only a path a quoted call can match.
# =================================================================================================
run "$ROOT" rev-parse HEAD
check "an installation inside the working directory is refused" \
  err_is 'git-ro: refused: the installation lies inside the working directory; install it outside the tree under audit (Rule 11e)'
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
