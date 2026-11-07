#!/usr/bin/env bash
# test-post-patch-validation-recipe.sh — run the opt-in post-patch validation recipe of
# templates/patch/VERIFICATION.md §4 exactly as written, with stand-ins for the Trail of Bits runner (uv), for
# scripts/runner/probe.sh, for git-lfs and, logging every clone, for git; the real scripts/git-ro.sh and
# scripts/lib/confine.sh make the copy. It checks:
#   - the gate: the stricter of {R}/exec-mode and AUDITOR_EXEC_MODE must be isolated (none stops it), or native
#     with strict mode on (AUDITOR_STRICT on, or a {R}/strict file), which counts as isolated; probe.sh
#     --only isolation must print the line the real probe.sh prints when nothing is readable (read from it, and
#     both gates compare with it), the vendored runner and uv must be there, and git-ro.sh copy must take the
#     checkout (in strict mode a checkout that borrows objects is refused; default mode copies it with a note,
#     OUTPUT-RULES.md Rule 11c). Each refusal
#     prints its not-run line and runs nothing: no copy, no scratch directory, no clone, no runner call;
#   - the copy and the clone, run from the client checkout's top level (also with TMPDIR ending in /): exactly
#     two clones, git-ro.sh's bare copy into {R} and then
#     `GIT_NO_LAZY_FETCH=1 git clone -q --no-local --no-checkout --template= <copy> <scratch>/repo`; the clone
#     has no work tree checked out and `* !filter` in info/attributes; the runner gets `uv run --no-config`,
#     the clone as --repo, the patch's absolute path and, as --finding-summary, the text of
#     {R}/patches/{FINDING_ID}.summary word for word, though it holds an apostrophe, quotes, $( ) and backticks
#     or a sentence that would close the block's if and run a command, none of which runs. The worktree the
#     stand-in runner adds, locks, unlocks,
#     removes and prunes, and the lock file it keeps, are in the clone only; no git-lfs filter of the caller's
#     config runs there; the client checkout gets no worktree, lock or owner file, runs no hook and stays clean;
#   - the plan guard: a plan.json that names another repository, or no plan, stops the second block before the
#     runner;
#   - the second block's own gate: it runs the plan in a shell call of its own, so it makes the first block's
#     mode and isolation checks again, word for word, before anything else, and each refusal prints the first
#     block's not-run line with no runner call, on a scratch directory whose plan names ../repo;
#   - the controls: the stand-in runner handed a client checkout leaves its lock there and runs its hook, and a
#     worktree of a clone without the attributes line runs the caller's git-lfs filter;
#   - the rule text: one sentence on the tier effect, word for word in the five files that describe the fix
#     tiers; the --post-patch-validation hint; the gate and the copy as /auditor:patch, patch-engineer and both
#     rows name them, with the 11a and 11b notes; one phrase for a finding on any other tier; §4 and
#     patch-engineer have the root-cause sentence written to {R}/patches/{FINDING_ID}.summary, and §4 pastes
#     no {ROOT_CAUSE} into the shell;
#   - the gate's input: /auditor:intake writes the Q46 answer as one word to audit_<n>/exec-mode.
# Without the May-2024 git fixes the copy cases are skipped with a note, and fail on CI (CI=true).
# The real runner is never run, and nothing reaches the network.
# Usage (from the repo root): bash scripts/tests/test-post-patch-validation-recipe.sh
# Needs bash >= 3.2, git with the May-2024 clone fixes (2.45.1 or a matching maintenance release; older git
# skips the copy cases with a note), python3, grep, sed, awk, mktemp.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VER="$ROOT/templates/patch/VERIFICATION.md"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE CDPATH AUDITOR_EXEC_MODE AUDITOR_STRICT
T=$(mktemp -d "${TMPDIR:-/tmp}/ppv-recipe.XXXXXX") || exit 1
trap 'chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"' EXIT
# A TMPDIR that ends in / (as on macOS) leaves // in $T; the checks compare physical paths.
T=$(cd "$T" && pwd -P) || exit 1
export GIT_CEILING_DIRECTORIES="$T" GIT_ALLOW_PROTOCOL=file GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "PASS $*"; }
bad() { failn=$((failn + 1)); echo "FAIL $*"; }
has() { case "$1" in *"$2"*) return 0 ;; esac; return 1; }   # has TEXT PART: TEXT contains PART
REALGIT=$(command -v git) || { echo "git is not on PATH" >&2; exit 1; }

# ---- an installation with stand-ins ---------------------------------------------------------------------------
# $T/root: the real git-ro.sh and confine.sh, a stand-in probe.sh that prints $PROBE_LINE, and a runner file the
# stand-in uv never runs. $T/root-nr is the same without the runner.
# The line scripts/runner/probe.sh --only isolation prints when the self-check finds nothing readable, read from
# probe.sh itself: the stand-in prints it, and both of §4's gates must compare with it, so a new wording there
# that the gates do not follow fails here instead of keeping post-patch validation from ever running.
OKLINE=$(awk -v q="'" '$1 == "isolation)" { on = 1; next }
  on && $1 == "0)" && $2 == "printf" { s = substr($0, index($0, q) + 1); print substr(s, 1, index(s, "\\n" q) - 1); exit }' \
  "$ROOT/scripts/runner/probe.sh")
case "$OKLINE" in
  'isolation: '?*) ;;
  *) echo "cannot read the line probe.sh --only isolation prints when nothing is readable" >&2; exit 1 ;;
esac
SKILL=vendor/trailofbits/plugins/post-patch-validation/skills/post-patch-validation
for r in "$T/root" "$T/root-nr"; do
  mkdir -p "$r/scripts/lib" "$r/scripts/runner" || exit 1
  cp "$ROOT/scripts/git-ro.sh" "$r/scripts/git-ro.sh" && cp "$ROOT/scripts/lib/confine.sh" "$r/scripts/lib/confine.sh" \
    && chmod 755 "$r/scripts/git-ro.sh" || exit 1
  printf '#!/bin/bash\nprintf "%%s\\n" "${PROBE_LINE-}"\n' > "$r/scripts/runner/probe.sh" && chmod 755 "$r/scripts/runner/probe.sh" || exit 1
done
mkdir -p "$T/root/$SKILL/scripts" "$T/bin" "$T/emptybin" "$T/tmp" || exit 1
RUNNER="$T/root/$SKILL/scripts/post_patch_validation.py"
printf 'raise SystemExit("the stand-in uv never runs this file")\n' > "$RUNNER"

# The stand-in git logs each clone, with GIT_NO_LAZY_FETCH, then runs the real git. Its paths are written into it,
# since git-ro.sh runs git under env -i.
cat > "$T/bin/git" <<EOF
#!/bin/bash
for a in "\$@"; do
  if [ "\$a" = clone ]; then
    { printf 'GIT_NO_LAZY_FETCH=%s' "\${GIT_NO_LAZY_FETCH-unset}"; printf ' %s' "\$@"; printf '\n'; } >> "$T/clone.log"
    break
  fi
done
exec "$REALGIT" "\$@"
EOF
# The stand-in git-lfs logs and passes the content through; the caller's global config below names it as a filter.
printf '#!/bin/sh\necho "git-lfs $* in $(pwd -P)" >> "%s/git-lfs.log"\ncat\n' "$T" > "$T/bin/git-lfs"
printf '[filter "lfs"]\n\tsmudge = git-lfs smudge -- %%f\n\tclean = git-lfs clean -- %%f\n\trequired = true\n' > "$T/global.gitconfig"
# The stand-in runner: `uv run --no-config <runner> <subcommand> …`. Each call is logged (its physical working
# directory, one line per argument, the uv variables that steer configuration). scaffold writes a plan naming
# ../repo, as the real scaffold does; run adds a worktree in the repository that plan names, logs the first line
# of its blob.bin, locks, unlocks, removes and prunes it, and keeps post-patch-validation.lock in its git
# directory, as the real runner does.
cat > "$T/bin/uv" <<'UV'
#!/bin/bash
set -u
{ printf 'call cwd=%s\n' "$(pwd -P)"; for a in "$@"; do printf 'arg=%s\n' "$a"; done
  printf 'env UV_CONFIG_FILE=%s UV_NO_CONFIG=%s\n' "${UV_CONFIG_FILE-unset}" "${UV_NO_CONFIG-unset}"; } >> "$UV_LOG"
[ "${1:-}" = run ] && [ "${2:-}" = --no-config ] && [ $# -ge 4 ] || exit 2
sub=$4; shift 4
opt() { # opt NAME ARGS... -> the value that follows NAME
  local n=$1; shift
  while [ $# -gt 0 ]; do if [ "$1" = "$n" ]; then printf '%s' "${2:-}"; return 0; fi; shift; done
  return 1
}
case "$sub" in
  scaffold)
    repo=$(opt --repo "$@") && out=$(opt --output "$@") && patch=$(opt --patch-file "$@") || exit 64
    [ ! -e "$out" ] && [ -f "$patch" ] || exit 64
    git -C "$repo" rev-parse --show-toplevel >/dev/null && git -C "$repo" apply --numstat -z -- "$patch" >/dev/null || exit 64
    printf '{"repository": "../repo"}\n' > "$out" || exit 64 ;;
  validate-plan)
    plan=$(opt --plan "$@") && [ -f "$plan" ] || exit 64 ;;
  run)
    plan=$(opt --plan "$@") && out=$(opt --output "$@") || exit 64
    rel=$(sed -n 's/^{"repository": "\(.*\)"}$/\1/p' "$plan")
    [ -n "$rel" ] && repo=$(cd "${plan%/*}" && cd "$rel" && pwd -P) || exit 64
    common=$(cd "$repo" && cd "$(git rev-parse --git-common-dir)" && pwd -P) || exit 64
    : >> "$common/post-patch-validation.lock" || exit 64
    mkdir -p "$common/post-patch-validation-owners" && : > "$common/post-patch-validation-owners/lease" || exit 64
    wt=$(mktemp -d "${TMPDIR:-/tmp}/ppv-worktree-XXXXXX") || exit 64
    git -C "$repo" worktree add -q --detach "$wt/w" HEAD &&
      printf 'worktree blob.bin: %s\n' "$(sed -n 1p "$wt/w/blob.bin")" >> "$UV_LOG" &&
      git -C "$repo" worktree lock --reason post-patch-validation:lease "$wt/w" &&
      git -C "$repo" worktree unlock "$wt/w" &&
      git -C "$repo" worktree remove --force "$wt/w" &&
      git -C "$repo" worktree prune || exit 64
    rm -f "$common/post-patch-validation-owners/lease" && rmdir "$common/post-patch-validation-owners" || exit 64
    mkdir -p "$out" && printf '{"assessment": {"status": "complete", "findings": [], "gaps": []}}\n' > "$out/result.json" ;;
  *) exit 64 ;;
esac
UV
chmod +x "$T/bin/git" "$T/bin/git-lfs" "$T/bin/uv" || exit 1

# ---- client checkouts --------------------------------------------------------------------------------------------
# client DIR: one commit (lib.rs, an LFS pointer in blob.bin with a .lfsconfig naming an LFS host, and
# .gitattributes marking *.bin for the lfs filter), a post-checkout hook writing DIR.hook, and the run directory
# audit_1 (its .gitignore holding *, exec-mode, patches/F-1.patch), untracked.
client() {
  git -c init.defaultBranch=main init -q "$1" && printf 'v1\n' > "$1/lib.rs" && printf '*.bin filter=lfs -text\n' > "$1/.gitattributes" \
    && printf '[lfs]\n\turl = https://lfs.example.invalid/info/lfs\n' > "$1/.lfsconfig" \
    && printf 'version https://git-lfs.github.com/spec/v1\noid sha256:%064d\nsize 12\n' 0 > "$1/blob.bin" \
    && git -C "$1" add . && git -C "$1" commit -qm v1 || return 1
  printf '#!/bin/sh\necho hook >> "%s.hook"\n' "$1" > "$1/.git/hooks/post-checkout" && chmod +x "$1/.git/hooks/post-checkout" || return 1
  mkdir "$1/audit_1" "$1/audit_1/patches" && printf '*\n' > "$1/audit_1/.gitignore" && printf 'isolated\n' > "$1/audit_1/exec-mode" \
    && printf -- '--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-v1\n+v2\n' > "$1/audit_1/patches/F-1.patch"
}
C="$T/client"
client "$C" || { echo "cannot make the client checkout" >&2; exit 1; }
commit=$(git -C "$C" rev-parse HEAD)

# ---- the recipe, as written --------------------------------------------------------------------------------------
# block N MODE ROOT PPV OUT: VERIFICATION.md §4's Nth bash block with its placeholders filled, written to OUT.
# {ROOT_CAUSE}, which a template that pasted the root-cause sentence into single quotes had, gets the sentence
# isolated() writes to the summary file ($SUMMARY), so such a template fails the summary checks below.
block() {
  SUMMARY="${SUMMARY-a signer check the withdraw path skips}" python3 -I - "$VER" "$1" "$2" "$3" "$4" "$commit" "$5" <<'PY'
import os, re, sys
doc, n, mode, root, ppv, commit, out = sys.argv[1:]
text = open(doc, encoding="utf-8").read()
if "\n## 4. Post-patch validation" not in text:
    sys.exit("VERIFICATION.md has no section 4, Post-patch validation")
sec = text.split("\n## 4. Post-patch validation", 1)[1].split("\n## 5. ", 1)[0]
blocks = re.findall(r"```bash\n(.*?)```", sec, re.S)
if len(blocks) != 2:
    sys.exit("section 4 has %d bash blocks, not 2" % len(blocks))
b = blocks[int(n) - 1]
for k, v in (("<auditor-skill root>", root), ("{MODE}", mode), ("{R}", "audit_1"), ("{FINDING_ID}", "F-1"),
             ("{COMMIT}", commit), ("{ROOT_CAUSE}", os.environ["SUMMARY"]),
             ("{LEVEL}", "runtime"), ("{PPV}", ppv)):
    b = b.replace(k, v)
if "{" in b.replace("${", ""):
    sys.exit("a placeholder is left in block " + n)
open(out, "w", encoding="utf-8").write(b)
PY
}
# run_block FILE TMPDIR AUDITOR_EXEC_MODE PROBE_LINE [PATH] [CLIENT]: run a filled block from the client checkout's
# top level, with the caller's global config naming the lfs filter, and AUDITOR_STRICT set to $STRICT_ENV when that
# is not empty; output in $T/out, exit status in $code.
STRICT_ENV=
run_block() {
  ( cd "${6:-$C}" && env ${3:+AUDITOR_EXEC_MODE=$3} ${STRICT_ENV:+AUDITOR_STRICT=$STRICT_ENV} TMPDIR="$2" PROBE_LINE="$4" PATH="${5:-$T/bin:$PATH}" \
      GIT_CONFIG_GLOBAL="$T/global.gitconfig" UV_LOG="$T/uv.log" "$BASH" "$1" ) > "$T/out" 2>&1
  code=$?
}
nothing_ran() { # nothing_ran CLIENT
  [ ! -e "$T/uv.log" ] && [ ! -s "$T/clone.log" ] && [ -z "$(ls -A "$T/tmp")" ] && [ ! -e "$1/audit_1/src.git" ] && [ ! -e "$1.hook" ]
}
copy_ok=1
v=$(git --version); v=${v#git version }
case "$v" in
  2.[0-9].*|2.[1-3][0-9].*|2.4[0-4].*|2.45.0*) copy_ok=0 ;;
esac
case "$v" in 2.39.[4-9]*|2.40.[2-9]*|2.41.[1-9]*|2.42.[2-9]*|2.43.[4-9]*|2.44.[1-9]*) copy_ok=1 ;; esac

# ---- the gate: each refusal prints its line and runs nothing ------------------------------------------------------
notrun() { # notrun LABEL MODE ENVMODE PROBE ROOT WANT [PATH] [CLIENT] [FIRST]: FIRST is a line git-ro.sh prints first
  local label=$1 cl=${8:-$C} want
  rm -f "$T/uv.log"; : > "$T/clone.log"
  if ! block 1 "$2" "$5" x "$T/a.sh"; then bad "$label: VERIFICATION.md §4's first block cannot be read"; return; fi
  run_block "$T/a.sh" "$T/tmp" "$3" "$4" "${7:-}" "$cl"
  want="post-patch validation: not run: $6"
  [ -n "${9:-}" ] && want="$9
$want"
  if [ "$code" = 0 ] && [ "$(cat "$T/out")" = "$want" ] && nothing_ran "$cl"; then
    ok "$label: \"not run: $6\", and nothing ran"
  else bad "$label: exit $code, output: $(cat "$T/out")"; fi
}
notrun "exec-mode native, AUDITOR_EXEC_MODE unset" native "" "$OKLINE" "$T/root" "needs isolated mode"
notrun "exec-mode empty, AUDITOR_EXEC_MODE unset" "" "" "$OKLINE" "$T/root" "needs isolated mode"
notrun "exec-mode isolated, AUDITOR_EXEC_MODE none" isolated none "$OKLINE" "$T/root" "needs isolated mode"
notrun "exec-mode none, AUDITOR_EXEC_MODE isolated" none isolated "$OKLINE" "$T/root" "needs isolated mode"
notrun "isolated, but probe.sh finds a credential" isolated "" "isolation: readable: SSH keys (1); ~/.ssh/id_ed25519" "$T/root" \
  "this is not the isolated runner (scripts/runner/probe.sh --only isolation)"
notrun "isolated, but probe.sh could not check" isolated "" "isolation: not checked (python3 is not on PATH)" "$T/root" \
  "this is not the isolated runner (scripts/runner/probe.sh --only isolation)"
notrun "isolated, no vendored runner" isolated "" "$OKLINE" "$T/root-nr" "needs the vendored post-patch-validation skill and uv"
notrun "isolated, no uv on PATH" isolated "" "$OKLINE" "$T/root" "needs the vendored post-patch-validation skill and uv" "$T/emptybin"
# Strict mode (OUTPUT-RULES.md Rule 11f) makes native count as isolated, as run.sh takes it: AUDITOR_STRICT on, in
# any letter case and for any value but the off words, or a strict file in the run directory. Such a run reaches the
# isolation check, which a readable credential stops; the off words leave native, and none still stops it.
CRED="isolation: readable: SSH keys (1); ~/.ssh/id_ed25519"
NOTISO="this is not the isolated runner (scripts/runner/probe.sh --only isolation)"
for sv in 1 yes TRUE On maybe; do
  STRICT_ENV=$sv; notrun "exec-mode native, AUDITOR_STRICT=$sv, a credential readable" native "" "$CRED" "$T/root" "$NOTISO"
done
STRICT_ENV=1; notrun "exec-mode empty, AUDITOR_STRICT=1, a credential readable" "" "" "$CRED" "$T/root" "$NOTISO"
for sv in 0 no FALSE Off; do
  STRICT_ENV=$sv; notrun "exec-mode native, AUDITOR_STRICT=$sv" native "" "$OKLINE" "$T/root" "needs isolated mode"
done
STRICT_ENV=1; notrun "exec-mode none, AUDITOR_STRICT=1" none "" "$OKLINE" "$T/root" "needs isolated mode"
STRICT_ENV=1; notrun "exec-mode isolated, AUDITOR_EXEC_MODE none, AUDITOR_STRICT=1" isolated none "$OKLINE" "$T/root" "needs isolated mode"
STRICT_ENV=
if : > "$C/audit_1/strict"; then
  notrun "exec-mode native, a strict file in audit_1, a credential readable" native "" "$CRED" "$T/root" "$NOTISO"
  rm -f "$C/audit_1/strict"
else bad "cannot write audit_1/strict"; fi
CA="$T/client-alt"; OTHER="$T/other"
if client "$CA" && git -c init.defaultBranch=main init -q "$OTHER" \
   && printf '%s/.git/objects\n' "$OTHER" > "$CA/.git/objects/info/alternates"; then
  # strict mode keeps the refusal (Rule 11f); in default mode git-ro.sh copies such a checkout with a note
  STRICT_ENV=1
  notrun "isolated, strict mode, a checkout that borrows objects" isolated "" "$OKLINE" "$T/root" "git-ro.sh copy refused the checkout" "" "$CA" \
    "git-ro: refused: copy's repository borrows objects from another repository (objects/info/alternates); audit a full copy: ."
  STRICT_ENV=
else bad "cannot make the checkout with alternates"; fi

# ---- isolated: the clone of git-ro.sh's copy is the only repository the runner touches ---------------------------
runs=0
isolated() { # isolated LABEL MODE ENVMODE TMPDIR SUMMARY: SUMMARY is the root-cause sentence in audit_1/patches/F-1.summary
  local label=$1 tmp=$4 plan ppv dest repo want2 first got SUMMARY=$5
  rm -f "$T/uv.log" "$T/git-lfs.log"; : > "$T/clone.log"
  printf '%s\n' "$SUMMARY" > "$C/audit_1/patches/F-1.summary" || { bad "$label: cannot write the summary file"; return; }
  block 1 "$2" "$T/root" x "$T/a.sh" || { bad "$label: first block unreadable"; return; }
  run_block "$T/a.sh" "$tmp" "$3" "$OKLINE"
  got=$(sed -n '/^arg=--finding-summary$/{n;s/^arg=//;p;}' "$T/uv.log" 2>/dev/null)
  if [ "$got" = "$SUMMARY" ] && ! grep -q INJECTED-OUTSIDE-THE-GATE "$T/out"; then
    ok "$label: the runner gets the summary file's text as --finding-summary, word for word, and none of it runs"
  else bad "$label: --finding-summary is [$got], not the summary file's text, or a command in it ran: $(cat "$T/out")"; fi
  plan=$(sed -n 's/^post-patch validation: plan at //p' "$T/out")
  ppv=${plan%/plan/plan.json}
  case "$(cd "$ppv" 2>/dev/null && pwd -P)" in
    "$T"/tmp/ppv-F-1.*) ;;
    *) bad "$label: first block: exit $code, no scratch directory under TMPDIR; output: $(cat "$T/out")"; return ;;
  esac
  runs=$((runs + 1))
  dest=src.git; [ "$runs" -gt 1 ] && dest=src-$runs.git
  first=$(sed -n 1p "$T/clone.log")
  want2="GIT_NO_LAZY_FETCH=1 clone -q --no-local --no-checkout --template= $C/audit_1/$dest $ppv/repo"
  if [ "$code" = 0 ] && [ -f "$plan" ] && [ "$(grep -c '' "$T/clone.log")" = 2 ] \
     && has "$first" "GIT_NO_LAZY_FETCH=1 " \
     && [ "${first% clone --no-local --bare --no-recurse-submodules --template= -- $C $C/audit_1/$dest}" != "$first" ] \
     && [ "$(sed -n 2p "$T/clone.log")" = "$want2" ]; then
    ok "$label: two clones, git-ro.sh's bare copy into audit_1/$dest and then: ${want2#GIT_NO_LAZY_FETCH=1 }"
  else bad "$label: first block: exit $code; clones:"; sed 's/^/    /' "$T/clone.log"; cat "$T/out"; fi
  ppv=$(cd "$ppv" && pwd -P)
  if [ "$(cat "$ppv/repo/.git/info/attributes" 2>/dev/null)" = '* !filter' ] && [ ! -e "$ppv/repo/lib.rs" ] \
     && [ "$(git -C "$ppv/repo" config --get remote.origin.url)" = "$C/audit_1/$dest" ]; then
    ok "$label: the clone has no work tree checked out, and * !filter in info/attributes"
  else bad "$label: the clone's attributes, checkout or origin differ"; fi
  repo=$(sed -n '/^arg=--repo$/{n;s/^arg=//;p;}' "$T/uv.log")
  if [ -n "$repo" ] && [ "$(cd "$repo" && pwd -P)" = "$ppv/repo" ] && [ "$(sed -n 2p "$T/uv.log")" = "arg=run" ] \
     && [ "$(sed -n 3p "$T/uv.log")" = "arg=--no-config" ] && [ "$(sed -n 4p "$T/uv.log")" = "arg=$RUNNER" ] \
     && [ "$(sed -n '/^arg=--patch-file$/{n;s/^arg=//;p;}' "$T/uv.log")" = "$C/audit_1/patches/F-1.patch" ]; then
    ok "$label: uv run --no-config runs the vendored runner with the clone as --repo and the patch's absolute path"
  else bad "$label: scaffold call:"; sed 's/^/    /' "$T/uv.log"; fi
  block 2 "$2" "$T/root" "${plan%/plan/plan.json}" "$T/b.sh" || { bad "$label: second block unreadable"; return; }
  run_block "$T/b.sh" "$tmp" "$3" "$OKLINE"
  if [ "$code" = 0 ] && [ -f "$ppv/results/result.json" ] && [ -f "$ppv/repo/.git/post-patch-validation.lock" ]; then
    ok "$label: the second block validates and runs the plan; the runner's lock is in the clone's git directory"
  else bad "$label: second block: exit $code; output: $(cat "$T/out")"; fi
  if [ -z "$(sed -n '/^call cwd=/p' "$T/uv.log" | grep -v -xF "call cwd=$ppv")" ] \
     && [ "$(grep -c '^arg=--no-config$' "$T/uv.log")" = "$(grep -c '^call cwd=' "$T/uv.log")" ]; then
    ok "$label: every runner call is uv run --no-config, from the scratch directory"
  else bad "$label: a runner call started elsewhere or read uv config:"; grep '^call cwd=\|^arg=run$' "$T/uv.log" | sed 's/^/    /'; fi
  if [ ! -s "$T/git-lfs.log" ] && grep -qxF 'worktree blob.bin: version https://git-lfs.github.com/spec/v1' "$T/uv.log"; then
    ok "$label: the caller's git-lfs filter never ran; the runner's worktree kept the LFS pointer"
  else bad "$label: git-lfs ran: $(cat "$T/git-lfs.log" 2>/dev/null)"; fi
  if [ ! -e "$C/.git/post-patch-validation.lock" ] && [ ! -e "$C/.git/post-patch-validation-owners" ] \
     && [ ! -e "$C/.git/worktrees" ] && [ "$(git -C "$C" worktree list | grep -c '')" = 1 ] && [ ! -e "$C.hook" ] \
     && [ -z "$(git -C "$C" status --porcelain)" ] && [ "$(cat "$C/lib.rs")" = v1 ]; then
    ok "$label: the client checkout has no worktree, lock or owner file, ran no hook and is unchanged"
  else
    bad "$label: the client checkout was touched"; ls -a "$C/.git" | sed 's/^/    /'; git -C "$C" status --porcelain
  fi
}
if [ "$copy_ok" = 1 ]; then
  # The sentence comes from the target's code: an apostrophe, quotes, $( ) and backticks, then one written to end
  # the quotes it was once pasted into, close the block's if and run a command of its own.
  isolated "exec-mode isolated" isolated "" "$T/tmp" \
    "the vault's withdraw path skips its \"signer\" check, so \$(echo INJECTED-OUTSIDE-THE-GATE) or \`echo INJECTED-OUTSIDE-THE-GATE\` drains it"
  isolated "exec-mode native, AUDITOR_EXEC_MODE isolated, TMPDIR ending in /" native isolated "$T/tmp/" \
    "x' ; fi ; echo INJECTED-OUTSIDE-THE-GATE ; if false ; then : '"
  extra=$(ls -A "$C/audit_1" | grep -v -x -e .gitignore -e exec-mode -e patches -e src.git -e src-2.git || true)
  if [ -z "$extra" ] && [ -d "$C/audit_1/src.git" ] && [ -d "$C/audit_1/src-2.git" ]; then
    ok "audit_1 holds only its own files and git-ro.sh's two copies"
  else bad "audit_1 holds more: $extra"; fi
  STRICT_ENV=1
  isolated "exec-mode native, AUDITOR_STRICT=1, which counts as isolated" native "" "$T/tmp" "a signer check the withdraw path skips"
  STRICT_ENV=
elif [ "${CI:-}" = true ]; then
  bad "git $v lacks the May-2024 clone fixes, which git-ro.sh copy needs; on CI the copy cases must run"
else
  echo "note: git $v lacks the May-2024 clone fixes, which git-ro.sh copy needs; the copy cases are skipped"
fi

# ---- the plan guard: nothing runs on a plan that names another repository ----------------------------------------
guard() { # guard LABEL CHANGE
  local label=$1 plan ppv
  rm -f "$T/uv.log"; : > "$T/clone.log"
  block 1 isolated "$T/root" x "$T/a.sh" && run_block "$T/a.sh" "$T/tmp" "" "$OKLINE"
  plan=$(sed -n 's/^post-patch validation: plan at //p' "$T/out")
  [ -f "$plan" ] || { bad "$label: no plan to change; $(cat "$T/out")"; return; }
  ppv=${plan%/plan/plan.json}
  case "$2" in
    other) printf '{"repository": "../../../client"}\n' > "$plan" ;;
    absolute) printf '{"repository": "%s"}\n' "$C" > "$plan" ;;
    none) mv "$plan" "$plan.gone" ;;
  esac
  rm -f "$T/uv.log"
  block 2 isolated "$T/root" "$ppv" "$T/b.sh" && run_block "$T/b.sh" "$T/tmp" "" "$OKLINE"
  if [ "$(cat "$T/out")" = "post-patch validation: not run: plan/plan.json must name ../repo, the disposable clone" ] \
     && [ ! -e "$T/uv.log" ] && [ ! -e "$C/.git/post-patch-validation.lock" ]; then
    ok "$label: the second block stops before the runner"
  else bad "$label: exit $code; output: $(cat "$T/out")"; fi
}
if [ "$copy_ok" = 1 ]; then
  runs=$((runs + 1)); guard "plan.json naming another repository" other
  runs=$((runs + 1)); guard "plan.json naming the client checkout by its absolute path" absolute
  runs=$((runs + 1)); guard "no plan.json" none
fi

# ---- the second block's own gate ------------------------------------------------------------------------------
# The second block runs the plan, the target's code, in a shell call of its own, where the first block's verdict
# does not reach: a retry outside the sandbox, or another session. $G is a scratch directory as the first block
# leaves it, its plan naming ../repo. Under each refusal of the first block, the second must print the same line
# and call the runner not at all; the control shows the same directory reaches the runner when the gate passes.
G="$T/ppv-gate"
mkdir -p "$G/plan" && git -c init.defaultBranch=main init -q "$G/repo" && printf 'v1\n' > "$G/repo/lib.rs" \
  && printf 'v1\n' > "$G/repo/blob.bin" && git -C "$G/repo" add lib.rs blob.bin && git -C "$G/repo" commit -qm v1 \
  && printf '{"repository": "../repo"}\n' > "$G/plan/plan.json" \
  || { echo "cannot make the scratch directory for the second block's gate" >&2; exit 1; }
notrun2() { # notrun2 LABEL MODE ENVMODE PROBE WANT
  rm -f "$T/uv.log"
  if ! block 2 "$2" "$T/root" "$G" "$T/b.sh"; then bad "second block, $1: VERIFICATION.md §4's second block cannot be read"; return; fi
  run_block "$T/b.sh" "$T/tmp" "$3" "$4"
  if [ "$code" = 0 ] && [ "$(cat "$T/out")" = "post-patch validation: not run: $5" ] && [ ! -e "$T/uv.log" ] && [ ! -e "$G/results" ]; then
    ok "second block, $1: \"not run: $5\", and the runner never ran"
  else bad "second block, $1: exit $code, runner called: $([ -e "$T/uv.log" ] && echo yes || echo no); output: $(cat "$T/out")"; fi
}
notrun2 "exec-mode native, AUDITOR_EXEC_MODE unset" native "" "$OKLINE" "needs isolated mode"
notrun2 "exec-mode empty, AUDITOR_EXEC_MODE unset" "" "" "$OKLINE" "needs isolated mode"
notrun2 "exec-mode isolated, AUDITOR_EXEC_MODE none" isolated none "$OKLINE" "needs isolated mode"
notrun2 "exec-mode none, AUDITOR_EXEC_MODE isolated" none isolated "$OKLINE" "needs isolated mode"
notrun2 "isolated, but probe.sh finds a credential (a retry outside the sandbox)" isolated "" \
  "isolation: readable: SSH keys (1); ~/.ssh/id_ed25519" "this is not the isolated runner (scripts/runner/probe.sh --only isolation)"
notrun2 "isolated, but probe.sh could not check" isolated "" "isolation: not checked (python3 is not on PATH)" \
  "this is not the isolated runner (scripts/runner/probe.sh --only isolation)"
STRICT_ENV=1; notrun2 "exec-mode native, AUDITOR_STRICT=1, a credential readable (a retry outside the sandbox)" native "" "$CRED" "$NOTISO"
STRICT_ENV=0; notrun2 "exec-mode native, AUDITOR_STRICT=0" native "" "$OKLINE" "needs isolated mode"
STRICT_ENV=1; notrun2 "exec-mode none, AUDITOR_STRICT=1" none "" "$OKLINE" "needs isolated mode"
STRICT_ENV=
if : > "$C/audit_1/strict"; then
  notrun2 "exec-mode native, a strict file in audit_1, a credential readable" native "" "$CRED" "$NOTISO"
  rm -f "$C/audit_1/strict"
else bad "cannot write audit_1/strict"; fi
rm -f "$T/uv.log"
if block 2 isolated "$T/root" "$G" "$T/b.sh"; then
  run_block "$T/b.sh" "$T/tmp" "" "$OKLINE"
  if [ "$code" = 0 ] && grep -qx 'arg=validate-plan' "$T/uv.log" 2>/dev/null && grep -qx 'arg=run' "$T/uv.log" \
     && [ -f "$G/results/result.json" ]; then
    ok "control: with the gate passed, the second block runs the plan of that scratch directory"
  else bad "control: the second block did not run the plan with the gate passed, so the checks above prove nothing: exit $code; $(cat "$T/out")"; fi
else bad "control: VERIFICATION.md §4's second block cannot be read"; fi

# ---- controls -------------------------------------------------------------------------------------------------
C2="$T/client2"
if client "$C2"; then
  mkdir -p "$T/c2/plan" && printf '{"repository": "../../client2"}\n' > "$T/c2/plan/plan.json"
  ( cd "$C2" && env TMPDIR="$T/tmp" UV_LOG="$T/uv-c2.log" "$T/bin/uv" run --no-config "$RUNNER" run \
      --plan "$T/c2/plan/plan.json" --output "$T/results-c2" ) >/dev/null 2>&1
  if [ -e "$C2/.git/post-patch-validation.lock" ] && [ -s "$C2.hook" ]; then
    ok "control: the stand-in runner handed a client checkout leaves its lock there and runs the checkout's hook"
  else bad "control: the stand-in left no mark in the checkout it was handed, so the checks above prove nothing"; fi
  rm -f "$T/git-lfs.log"
  git clone -q --no-local --no-checkout --template= "$C2" "$T/c2/plain" \
    && GIT_CONFIG_GLOBAL="$T/global.gitconfig" PATH="$T/bin:$PATH" git -C "$T/c2/plain" worktree add -q --detach "$T/c2/wt" HEAD 2>/dev/null
  if [ -s "$T/git-lfs.log" ]; then
    ok "control: a worktree of a clone without the attributes line runs the caller's git-lfs filter"
  else bad "control: git-lfs did not run without the attributes line, so the LFS check proves nothing"; fi
else bad "controls: cannot make a second client checkout"; fi

# ---- the rule text -----------------------------------------------------------------------------------------------
S='Opt-in Trail of Bits `post-patch-validation` (`/auditor:patch --post-patch-validation`, isolated mode only, on a disposable clone) is optional evidence that can only lower a tier: a finding in its result turns `[FIX-VERIFIED]` into `[FIX-INSUFFICIENT]`, with that check as the reason; a `[FIX-PROPOSED]` or `[FIX-INSUFFICIENT]` patch keeps its tier and records the finding under Residual, and nothing else in its result changes a tier.'
for f in OUTPUT-RULES.md docs/poc-and-patches.md agents/patch-engineer.md commands/patch.md templates/patch/VERIFICATION.md; do
  if grep -qF -- "$S" "$ROOT/$f"; then ok "$f states the tier effect in the shared sentence"
  else bad "$f does not carry the shared sentence on the tier effect"; fi
done
LOWER='makes a `[FIX-VERIFIED]` tier `[FIX-INSUFFICIENT]` (a `[FIX-PROPOSED]` one keeps its tier and records the finding under Residual)'
COPY='a no-checkout clone, outside the target tree, of the copy `git-ro.sh copy` makes in `<R>`'
GATE='the stricter of the recorded mode (`<R>/exec-mode`, or `intake.md` §8 without it) and `AUDITOR_EXEC_MODE` is'
for f in commands/patch.md agents/patch-engineer.md; do
  if grep -qF -- "$LOWER" "$ROOT/$f" && grep -qF -- "$COPY" "$ROOT/$f" && grep -qF -- "$GATE" "$ROOT/$f" \
     && grep -qF -- '"${CLAUDE_PLUGIN_ROOT}/scripts/runner/probe.sh" --only isolation` finds nothing readable' "$ROOT/$f"; then
    ok "$f: the gate, the copy, and a finding that lowers only [FIX-VERIFIED]"
  else bad "$f lacks the gate, the copy or the tier wording"; fi
done
# Section 4 as one line, so wording that wraps still matches.
sec4=$(awk '/^## 4\. Post-patch validation/ {s = 1} /^## 5\. / {s = 0} s' "$VER" | tr '\n' ' ')
if has "$sec4" 'lowered from `[FIX-VERIFIED]` to `[FIX-INSUFFICIENT]` by `check_id` (kind) | recorded under Residual, tier unchanged: `check_id` (kind)' \
   && has "$sec4" "$LOWER" && has "$sec4" 'change nothing else in `plan.json`' \
   && has "$sec4" 'which the disposable clone does not hold". Never fetch or initialize submodules in the clone.' \
   && has "$sec4" 'record "not run: <its first error line>"' && ! has "$sec4" '§1 copy' && ! has "$sec4" '{CHECKOUT}' \
   && has "$sec4" 'unless the stricter of the recorded mode (`{R}/exec-mode`, or `intake.md` §8 without it) and `AUDITOR_EXEC_MODE` is isolated' \
   && has "$sec4" '`{MODE}` is the word `{R}/exec-mode` holds or, when there is no such file, the mode `{R}/intake.md` §8 records (for an incident, the mode in its ledger header);' \
   && ! has "$sec4" '{PATH_TO}' \
   && grep -qF '**Residual (if any):** {what is still open, for INSUFFICIENT or a post-patch-validation finding — else "none".}' "$VER"
then ok "VERIFICATION.md §4: the gate with its intake.md fallback, its own placeholders, the effect record, the plan rule, the submodule and error lines; §5's Residual"
else bad "VERIFICATION.md §4 or §5 lacks part of its wording"; fi
# The root-cause sentence is written from the target's code, so it reaches the runner from a file, as one argument.
if ! has "$sec4" '{ROOT_CAUSE}' && has "$sec4" 'PPV_SUMMARY="$(cat "{R}/patches/{FINDING_ID}.summary")" &&' \
   && has "$sec4" '--finding-summary "$PPV_SUMMARY"' \
   && has "$sec4" 'write the finding'"'"'s root cause and impact, in one sentence, to `{R}/patches/{FINDING_ID}.summary` with the Write tool' \
   && grep -qF 'to `<R>/patches/<ID>.summary` with the Write tool first, since §4'"'"'s first block hands the runner that file'"'"'s text' "$ROOT/agents/patch-engineer.md"
then ok "VERIFICATION.md §4 and patch-engineer write the root-cause sentence to {R}/patches/{FINDING_ID}.summary, and §4 pastes none of it into the shell"
else bad "VERIFICATION.md §4 pastes the root-cause sentence into the shell, or §4 or patch-engineer does not say where it is written"; fi
# Both gates compare probe.sh's output with the very line probe.sh prints when nothing is readable.
gates=$(grep -cF -e "--only isolation 2>/dev/null)\" != \"$OKLINE\" ]; then" "$VER")
if [ "$gates" = 2 ]; then ok "VERIFICATION.md §4: both gates compare with the line probe.sh prints when nothing is readable"
else bad "VERIFICATION.md §4: $gates gates, not 2, compare with probe.sh's line for nothing readable: $OKLINE"; fi
# The second block opens with the first block's setup and gate, word for word, before any cd or runner call.
if python3 -I - "$VER" <<'PY'
import re, sys
sec = open(sys.argv[1], encoding="utf-8").read().split("\n## 4. Post-patch validation", 1)[1].split("\n## 5. ", 1)[0]
b1, b2 = re.findall(r"```bash\n(.*?)```", sec, re.S)
end = 'echo "post-patch validation: not run: this is not the isolated runner (scripts/runner/probe.sh --only isolation)"\n'
if not b1.startswith('ROOT="<auditor-skill root>"\n') or end not in b1:
    sys.exit("the first block does not open with ROOT= and end its isolation check as expected")
gate = b1[:b1.index(end) + len(end)]
if not b2.startswith(gate):
    sys.exit("the second block does not open with the first block's gate")
rest = b2[len(gate):]
if not rest.startswith("elif ") or "uv run" in gate or 'cd "' in gate:
    sys.exit("the second block's gate is not followed by its own branch")
PY
then
  if has "$sec4" 'so the second block makes the same mode and isolation checks, word for word, before it runs anything'
  then ok "VERIFICATION.md §4: the second block opens with the first block's mode and isolation checks, word for word, and says why"
  else bad "VERIFICATION.md §4 does not say that the second block makes the same mode and isolation checks"; fi
else bad "VERIFICATION.md §4's second block does not open with the first block's mode and isolation checks"; fi
if grep -qxF 'argument-hint: "<finding-id | INC-n.k> [--verify-with-mutation] [--post-patch-validation]"' "$ROOT/commands/patch.md"
then ok "/auditor:patch offers --post-patch-validation"; else bad "/auditor:patch's argument-hint lacks --post-patch-validation"; fi
for f in references/orchestration/boundary-map.md docs/power-tools.md; do
  row=$(awk -F'|' '/^\|/ && NF > 4 && index($3, "`post-patch-validation`") {print; exit}' "$ROOT/$f")
  if [ -n "$row" ] && has "$row" 'ToB plugin installed' && has "$row" 'Isolated mode only' && has "$row" "$COPY" \
     && has "$row" "$GATE isolated and \`probe.sh --only isolation\` finds nothing readable" && has "$row" 'open network' \
     && has "$row" 'git-lfs filter in the caller' && has "$row" '`* !filter`' && has "$row" '11a' && has "$row" '11b' \
     && has "$row" 'turns `[FIX-VERIFIED]` into `[FIX-INSUFFICIENT]`' && has "$row" 'keeps its tier and records the finding under Residual' \
     && ! has "$row" 'as residual'; then
    ok "$f has the post-patch-validation row: entry point, the gate (11a), the copy, the open network and git-lfs (11b), the tier"
  else bad "$f lacks the post-patch-validation row or one of its notes"; fi
done

# ---- the gate's input: intake writes <R>/exec-mode -----------------------------------------------------------------
if grep -qF 'Also write the answer with the Write tool, as one word, `isolated` or `native`, to `audit_<n>/exec-mode`' "$ROOT/commands/intake.md" \
   && grep -qF 'and `audit_<n>/exec-mode` holds `native`' "$ROOT/commands/intake.md" \
   && grep -qF 'the answer is also written as one word to audit_<n>/exec-mode, where' "$ROOT/templates/intake.md" \
   && grep -qF 'templates/poc/run.sh --crate reads it (the stricter of it, AUDITOR_EXEC_MODE and strict mode)' "$ROOT/templates/intake.md"
then ok "/auditor:intake writes the Q46 answer as one word to audit_<n>/exec-mode (native under --auto), as §8 says"
else bad "/auditor:intake does not write audit_<n>/exec-mode as one word, or §8 does not say where run.sh reads it"; fi

echo "---- post-patch validation recipe: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
