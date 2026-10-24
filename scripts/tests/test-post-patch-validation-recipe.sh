#!/usr/bin/env bash
# test-post-patch-validation-recipe.sh — run the opt-in post-patch validation recipe of
# templates/patch/VERIFICATION.md §4 exactly as written, with a stand-in for the Trail of Bits runner, and check:
#   - in native mode it prints "not run: needs isolated mode" and runs nothing: no scratch directory, no clone,
#     no runner call; without the vendored runner, or without uv, it prints its not-run line and runs nothing;
#   - in isolated mode, started from inside the client checkout, the first block makes a new scratch directory
#     outside the target tree, clones the checkout into it with --no-local and hands the runner that clone; the
#     second block validates and runs the plan from that directory. The worktree the stand-in adds, locks,
#     unlocks, removes and prunes, and the lock file it keeps (as the real runner does), are in the clone's
#     git directory only: the client checkout gets no worktree, lock or owner file, runs no hook and keeps a
#     clean working tree. With TMPDIR ending in / as well, as on macOS;
#   - the control: the stand-in handed a client checkout leaves its lock there, so the check above can fail;
#   - the rule text: one sentence on the tier effect, word for word in the five files that describe the fix
#     tiers; the --post-patch-validation hint; the boundary-map and power-tools rows (isolated only, the open
#     network, Rule 11a / 11b).
# The real runner is never run, and nothing reaches the network.
# Usage (from the repo root): bash scripts/tests/test-post-patch-validation-recipe.sh
# Needs bash >= 3.2, git, python3, grep, sed, awk, mktemp.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VER="$ROOT/templates/patch/VERIFICATION.md"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE CDPATH
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

# ---- the stand-in runner -------------------------------------------------------------------------------
# `uv run <runner> <subcommand> …`: each call is logged (its physical working directory, then one line per
# argument). scaffold writes a plan naming the top level of --repo; run adds, locks, unlocks, removes and
# prunes a worktree in that repository and keeps post-patch-validation.lock in its git directory, as the
# real runner does.
mkdir -p "$T/bin" "$T/root/vendor/trailofbits/plugins/post-patch-validation/skills/post-patch-validation/scripts" \
  "$T/noroot" "$T/emptybin" "$T/tmp" || exit 1
RUNNER="$T/root/vendor/trailofbits/plugins/post-patch-validation/skills/post-patch-validation/scripts/post_patch_validation.py"
printf 'raise SystemExit("the stand-in uv never runs this file")\n' > "$RUNNER"
cat > "$T/bin/uv" <<'UV'
#!/bin/bash
set -u
{ printf 'call cwd=%s\n' "$(pwd -P)"; for a in "$@"; do printf 'arg=%s\n' "$a"; done; } >> "$UV_LOG"
[ "${1:-}" = run ] && [ $# -ge 3 ] || exit 2
sub=$3; shift 3
opt() { # opt NAME ARGS... -> the value that follows NAME
  local n=$1; shift
  while [ $# -gt 0 ]; do if [ "$1" = "$n" ]; then printf '%s' "${2:-}"; return 0; fi; shift; done
  return 1
}
case "$sub" in
  scaffold)
    repo=$(opt --repo "$@") && out=$(opt --output "$@") && patch=$(opt --patch-file "$@") || exit 64
    [ ! -e "$out" ] && [ -f "$patch" ] || exit 64
    top=$(git -C "$repo" rev-parse --show-toplevel) || exit 64
    printf '{"repository": "%s"}\n' "$top" > "$out" || exit 64 ;;
  validate-plan)
    plan=$(opt --plan "$@") && [ -f "$plan" ] || exit 64 ;;
  run)
    plan=$(opt --plan "$@") && out=$(opt --output "$@") || exit 64
    repo=$(sed -n 's/^{"repository": "\(.*\)"}$/\1/p' "$plan")
    [ -n "$repo" ] || exit 64
    common=$(cd "$repo" && cd "$(git rev-parse --git-common-dir)" && pwd -P) || exit 64
    : >> "$common/post-patch-validation.lock" || exit 64
    mkdir -p "$common/post-patch-validation-owners" && : > "$common/post-patch-validation-owners/lease" || exit 64
    wt=$(mktemp -d "${TMPDIR:-/tmp}/ppv-worktree-XXXXXX") || exit 64
    git -C "$repo" worktree add -q --detach "$wt/w" HEAD &&
      git -C "$repo" worktree lock --reason post-patch-validation:lease "$wt/w" &&
      git -C "$repo" worktree unlock "$wt/w" &&
      git -C "$repo" worktree remove --force "$wt/w" &&
      git -C "$repo" worktree prune || exit 64
    rm -f "$common/post-patch-validation-owners/lease" && rmdir "$common/post-patch-validation-owners" || exit 64
    mkdir -p "$out" && printf '{"assessment": {"status": "complete", "findings": [], "gaps": []}}\n' > "$out/result.json" ;;
  *) exit 64 ;;
esac
UV
chmod +x "$T/bin/uv" || exit 1

# ---- a client checkout whose hook leaves a marker ------------------------------------------------------
client() { # client DIR -> a repository with one commit and a post-checkout hook writing DIR.hook
  git -c init.defaultBranch=main init -q "$1" && printf 'v1\n' > "$1/lib.rs" && git -C "$1" add lib.rs && git -C "$1" commit -qm v1 || return 1
  printf '#!/bin/sh\necho hook >> "%s.hook"\n' "$1" > "$1/.git/hooks/post-checkout" && chmod +x "$1/.git/hooks/post-checkout"
}
C="$T/client"
client "$C" || { echo "cannot make the client checkout" >&2; exit 1; }
commit=$(git -C "$C" rev-parse HEAD)
printf -- '--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-v1\n+v2\n' > "$T/F-1.patch"

# ---- the recipe, as written ----------------------------------------------------------------------------
# block N MODE ROOT PPV OUT: VERIFICATION.md §4's Nth bash block with its placeholders filled, written to OUT.
block() {
  python3 -I - "$VER" "$1" "$2" "$3" "$4" "$C" "$commit" "$T" "$5" <<'PY'
import re, sys
doc, n, mode, root, ppv, checkout, commit, t, out = sys.argv[1:]
text = open(doc, encoding="utf-8").read()
if "\n## 4. Post-patch validation" not in text:
    sys.exit("VERIFICATION.md has no section 4, Post-patch validation")
sec = text.split("\n## 4. Post-patch validation", 1)[1].split("\n## 5. ", 1)[0]
blocks = re.findall(r"```bash\n(.*?)```", sec, re.S)
if len(blocks) != 2:
    sys.exit("section 4 has %d bash blocks, not 2" % len(blocks))
b = blocks[int(n) - 1]
for k, v in (("<auditor-skill root>", root), ("{MODE}", mode), ("{FINDING_ID}", "F-1"), ("{CHECKOUT}", checkout),
             ("{COMMIT}", commit), ("{PATH_TO}", t), ("{ROOT_CAUSE}", "a signer check the withdraw path skips"),
             ("{LEVEL}", "runtime"), ("{PPV}", ppv)):
    b = b.replace(k, v)
if "{" in b.replace("${", ""):
    sys.exit("a placeholder is left in block " + n)
open(out, "w", encoding="utf-8").write(b)
PY
}
# run_block FILE TMPDIR [PATH]: run a filled block from inside the client checkout; output in $T/out, exit in $code.
run_block() {
  ( cd "$C" && env TMPDIR="$2" PATH="${3:-$T/bin:$PATH}" UV_LOG="$T/uv.log" "$BASH" "$1" ) > "$T/out" 2>&1
  code=$?
}
nothing_ran() { [ ! -e "$T/uv.log" ] && [ -z "$(ls -A "$T/tmp")" ] && [ ! -e "$C.hook" ]; }

# ---- not run ---------------------------------------------------------------------------------------------
if block 1 native "$T/root" x "$T/a-native.sh"; then
  run_block "$T/a-native.sh" "$T/tmp"
  if [ "$code" = 0 ] && [ "$(cat "$T/out")" = "post-patch validation: not run: needs isolated mode" ] && nothing_ran; then
    ok "native mode: the not-run line, and nothing ran (no scratch directory, clone or runner call)"
  else bad "native mode: exit $code, output: $(cat "$T/out")"; fi
else bad "could not read VERIFICATION.md §4's first block"; fi
missing="post-patch validation: not run: needs the vendored post-patch-validation skill and uv"
if block 1 isolated "$T/noroot" x "$T/a-noskill.sh"; then
  run_block "$T/a-noskill.sh" "$T/tmp"
  if [ "$code" = 0 ] && [ "$(cat "$T/out")" = "$missing" ] && nothing_ran; then
    ok "isolated mode without the vendored runner: the not-run line, and nothing ran"
  else bad "isolated, no vendored runner: exit $code, output: $(cat "$T/out")"; fi
  block 1 isolated "$T/root" x "$T/a-nouv.sh" && run_block "$T/a-nouv.sh" "$T/tmp" "$T/emptybin"
  if [ "$code" = 0 ] && [ "$(cat "$T/out")" = "$missing" ] && nothing_ran; then
    ok "isolated mode without uv on PATH: the not-run line, and nothing ran"
  else bad "isolated, no uv: exit $code, output: $(cat "$T/out")"; fi
fi

# ---- isolated: the disposable clone is the only repository the runner touches ---------------------------
isolated() { # isolated TMPDIR LABEL
  local tmp=$1 label=$2 ppv plan repo
  rm -f "$T/uv.log"
  block 1 isolated "$T/root" x "$T/a.sh" || { bad "$label: first block unreadable"; return; }
  run_block "$T/a.sh" "$tmp"
  plan=$(sed -n 's/^post-patch validation: plan at //p' "$T/out")
  ppv=${plan%/plan/plan.json}
  case "$(cd "$ppv" 2>/dev/null && pwd -P)" in
    "$T"/tmp/ppv-F-1.*) ;;
    *) bad "$label: first block: exit $code, no scratch directory under TMPDIR; output: $(cat "$T/out")"; return ;;
  esac
  ppv=$(cd "$ppv" && pwd -P)
  if [ "$code" = 0 ] && [ -f "$plan" ] && [ "$(git -C "$ppv/repo" config --get remote.origin.url)" = "$C" ] \
     && [ "$(git -C "$ppv/repo" rev-parse HEAD)" = "$commit" ]; then
    ok "$label: the first block clones the checkout into a new scratch directory and scaffolds a plan there"
  else bad "$label: first block: exit $code; output: $(cat "$T/out")"; fi
  repo=$(sed -n '/^arg=--repo$/{n;s/^arg=//;p;}' "$T/uv.log")
  if [ -n "$repo" ] && [ "$(cd "$repo" && pwd -P)" = "$ppv/repo" ] \
     && [ "$(sed -n "2p" "$T/uv.log")" = "arg=run" ] && [ "$(sed -n "3p" "$T/uv.log")" = "arg=$RUNNER" ]; then
    ok "$label: the runner, by its vendored path, gets the clone as --repo, never the checkout"
  else bad "$label: scaffold call:"; sed 's/^/    /' "$T/uv.log"; fi
  # The second block's {PPV} is the directory the first one printed.
  block 2 isolated "$T/root" "${plan%/plan/plan.json}" "$T/b.sh" || { bad "$label: second block unreadable"; return; }
  run_block "$T/b.sh" "$tmp"
  if [ "$code" = 0 ] && [ -f "$ppv/results/result.json" ] && [ -f "$ppv/repo/.git/post-patch-validation.lock" ]; then
    ok "$label: the second block validates and runs the plan; the runner's lock is in the clone's git directory"
  else bad "$label: second block: exit $code; output: $(cat "$T/out")"; fi
  if [ -z "$(sed -n '/^call cwd=/p' "$T/uv.log" | grep -v -xF "call cwd=$ppv")" ]; then
    ok "$label: every runner call starts in the scratch directory, outside the target tree"
  else bad "$label: a runner call started elsewhere:"; grep '^call cwd=' "$T/uv.log" | sed 's/^/    /'; fi
  if [ ! -e "$C/.git/post-patch-validation.lock" ] && [ ! -e "$C/.git/post-patch-validation-owners" ] \
     && [ ! -e "$C/.git/worktrees" ] && [ "$(git -C "$C" worktree list | wc -l | tr -d ' ')" = 1 ] \
     && [ ! -e "$C.hook" ] && [ -z "$(git -C "$C" status --porcelain --ignored)" ] && [ "$(cat "$C/lib.rs")" = v1 ]; then
    ok "$label: the client checkout has no worktree, lock or owner file, ran no hook and is unchanged"
  else
    bad "$label: the client checkout was touched"; ls -a "$C/.git" | sed 's/^/    /'; git -C "$C" status --porcelain --ignored
  fi
}
isolated "$T/tmp" "isolated mode"
isolated "$T/tmp/" "isolated mode, TMPDIR ending in /"

# ---- control: handed a client checkout, the stand-in leaves its marks there ---------------------------------
C2="$T/client2"
if client "$C2"; then
  printf '{"repository": "%s"}\n' "$C2" > "$T/plan-c2.json"
  ( cd "$C2" && env TMPDIR="$T/tmp" UV_LOG="$T/uv-c2.log" "$T/bin/uv" run "$RUNNER" run --plan "$T/plan-c2.json" \
      --output "$T/results-c2" ) >/dev/null 2>&1
  if [ -e "$C2/.git/post-patch-validation.lock" ] && [ -s "$C2.hook" ]; then
    ok "control: the stand-in handed a client checkout leaves its lock there and runs the checkout's hook"
  else bad "control: the stand-in left no mark in the checkout it was handed, so the checks above prove nothing"; fi
else bad "control: cannot make a second client checkout"; fi

# ---- the rule text ---------------------------------------------------------------------------------------
S='Opt-in Trail of Bits `post-patch-validation` (`/auditor:patch --post-patch-validation`, isolated mode only, on a disposable clone) is optional evidence that can only lower a tier: a finding in its result turns `[FIX-VERIFIED]` or `[FIX-PROPOSED]` into `[FIX-INSUFFICIENT]`, with that check as the reason, and nothing else in its result changes a tier.'
for f in OUTPUT-RULES.md docs/poc-and-patches.md agents/patch-engineer.md commands/patch.md templates/patch/VERIFICATION.md; do
  if grep -qF -- "$S" "$ROOT/$f"; then ok "$f states the tier effect in the shared sentence"
  else bad "$f does not carry the shared sentence on the tier effect"; fi
done
if grep -qxF 'argument-hint: "<finding-id | INC-n.k> [--verify-with-mutation] [--post-patch-validation]"' "$ROOT/commands/patch.md"
then ok "/auditor:patch offers --post-patch-validation"; else bad "/auditor:patch's argument-hint lacks --post-patch-validation"; fi
for f in references/orchestration/boundary-map.md docs/power-tools.md; do
  row=$(awk -F'|' '/^\|/ && NF > 4 && index($3, "`post-patch-validation`") {print; exit}' "$ROOT/$f")
  if [ -n "$row" ] && has "$row" 'ToB plugin installed' && has "$row" 'Isolated mode only' \
     && has "$row" 'open network' && has "$row" '11a' && has "$row" '11b' && has "$row" 'git clone --no-local'; then
    ok "$f has the post-patch-validation row: entry point, isolated only (11a), the open network (11b)"
  else bad "$f lacks the post-patch-validation row or one of its notes"; fi
done

echo "---- post-patch validation recipe: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
