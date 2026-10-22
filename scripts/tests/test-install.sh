#!/usr/bin/env bash
# test-install.sh — install.sh:
#   - a run without a path installs at $HOME/.claude/skills/auditor-skill, never in the directory it starts in,
#     and stops before anything runs when HOME is not an absolute path;
#   - a run over an earlier install, with or without a path, installs a fresh clone and moves that copy aside
#     without running git in it, so nothing in its repo config (filters, hooks, transport commands) runs;
#   - a path that is a symbolic link, or that holds something other than an install, is refused;
#   - a warning goes to stderr when the install directory is inside a git work tree.
# Run from the repo root: `bash scripts/tests/test-install.sh`.
# Offline: a temp global config maps the canonical URL to local bare upstreams, and GIT_ALLOW_PROTOCOL=file
# refuses every other transport. HOME is a temp dir too. Builds throwaway repos under ${TMPDIR:-/tmp};
# bash >= 3.2.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE GIT_TRACE
T=$(mktemp -d "${TMPDIR:-/tmp}/install-test.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
export GIT_CEILING_DIRECTORIES="$T" GIT_ALLOW_PROTOCOL=file
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid \
  GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
export HOME="$T/home"   # a run that falls back to the default path lands here, never in the real home
mkdir -p "$HOME" || exit 1
pass=0; failn=0

# Fixture upstreams: up.git (a SKILL.md like ours), up2.git (also a vendor/trailofbits submodule).
mkup() { # mkup NAME [submodule]
  git init -q --bare "$T/$1.git" && git -C "$T/$1.git" symbolic-ref HEAD refs/heads/main \
    && git clone -q "$T/$1.git" "$T/$1.seed" 2>/dev/null && git -C "$T/$1.seed" checkout -q -b main \
    && printf -- '---\nname: auditor-skill\n---\n' > "$T/$1.seed/SKILL.md" && git -C "$T/$1.seed" add SKILL.md || return 1
  if [ -n "${2:-}" ]; then git -C "$T/$1.seed" submodule add -q "file://$T/tob" vendor/trailofbits || return 1; fi
  git -C "$T/$1.seed" commit -q -m base && git -C "$T/$1.seed" push -q origin main
}
advance() { # advance NAME FILE: a new upstream commit whose subject is FILE
  echo "$2" > "$T/$1.seed/$2" && git -C "$T/$1.seed" add "$2" && git -C "$T/$1.seed" commit -q -m "$2" \
    && git -C "$T/$1.seed" push -q origin main
}
git init -q "$T/tob" && echo p > "$T/tob/p" && git -C "$T/tob" add p && git -C "$T/tob" commit -q -m p \
  && mkup up && mkup up2 submodule || { echo "could not build the fixture upstreams" >&2; exit 1; }
for u in up up2; do # the user's global config for a run: the canonical URL comes from the local upstream
  printf '[url "file://%s/%s.git"]\n\tinsteadOf = https://github.com/solanabr/auditor-skill.git\n' "$T" "$u" > "$T/$u.gitconfig"
done
printf '#!/bin/sh\ntouch "%s/fired-$1"\nexit 0\n' "$T" > "$T/canary.sh" && chmod +x "$T/canary.sh"
printf '#!/bin/sh\ntouch "%s/fired-gitproxy"\nexit 1\n' "$T" > "$T/gitproxy.sh" && chmod +x "$T/gitproxy.sh"   # run without a shell

run() { # run UPSTREAM DIR ARGS...  (install.sh in DIR; sets rc, $T/out, $T/err)
  local u=$1 d=$2; shift 2
  ( cd "$d" && GIT_CONFIG_GLOBAL="$T/$u.gitconfig" bash "$ROOT/install.sh" "$@" ) > "$T/out" 2> "$T/err"; rc=$?
}
check() { # check NAME TEST...
  local name=$1; shift
  if "$@"; then pass=$((pass + 1)); echo "PASS $name"
  else failn=$((failn + 1)); echo "FAIL $name (rc=$rc)"; sed 's/^/  | /' "$T/err"; fi
}
head_is() { [ "$(git -C "$1" log -1 --format=%s)" = "$2" ]; }
warned() { grep -q 'is inside the git work tree' "$T/err"; }
none_fired() { [ -z "$(ls "$T" | grep '^fired-')" ]; }
installed() { [ "$rc" -eq 0 ] && grep -q 'auditor-skill installed' "$T/out" && [ -f "$1/SKILL.md" ]; }

# 1. explicit path inside a work tree: warns, then installs
git init -q "$T/audited"
run up "$T" "$T/audited/.claude/skills/auditor-skill"
ok1() { installed "$T/audited/.claude/skills/auditor-skill" && warned && head_is "$T/audited/.claude/skills/auditor-skill" base; }
check "explicit path inside a work tree warns and installs" ok1

# 2. explicit path outside any work tree: no warning; the submodule arrives too
mkdir -p "$T/outside"
run up2 "$T" "$T/outside/auditor-skill"
ok2() { installed "$T/outside/auditor-skill" && ! warned && [ -f "$T/outside/auditor-skill/vendor/trailofbits/p" ]; }
check "explicit path outside any work tree is quiet and installs the submodule" ok2

# 3. a run without a path, started inside a work tree: installs at $HOME/.claude/skills/auditor-skill, quietly,
#    and writes nothing into the work tree
git init -q "$T/audited2" && mkdir -p "$T/home3"
HOME="$T/home3" run up "$T/audited2"
ok3() { installed "$T/home3/.claude/skills/auditor-skill" && ! warned && [ ! -e "$T/audited2/.claude" ]; }
check "a run without a path installs under HOME, not in the work tree it starts in" ok3

# 4. a run without a path over an earlier install at the default path, whose repo config sets fsmonitor and a
#    hook: a fresh clone replaces it, the old copy is moved aside untouched, and nothing from its config runs
h4="$T/home4" && d4="$T/home4/.claude/skills/auditor-skill"
mkdir -p "$h4/.claude/skills" && git clone -q "$T/up.git" "$d4" && echo old > "$d4/old-marker" \
  && git -C "$d4" config core.fsmonitor "$T/canary.sh fsmonitor" \
  && printf '#!/bin/sh\ntouch "%s/fired-hook"\n' "$T" > "$d4/.git/hooks/post-merge" && chmod +x "$d4/.git/hooks/post-merge" \
  && advance up four
HOME="$h4" run up "$T/audited2"
ok4() { installed "$d4" && none_fired && head_is "$d4" four && [ ! -e "$d4/old-marker" ] \
  && [ "$(ls -d "$d4".old-* 2>/dev/null | wc -l | tr -d ' ')" = 1 ] && [ -f "$(ls -d "$d4".old-*)/old-marker" ]; }
check "a run without a path replaces an earlier default install with a fresh clone and runs nothing from its config" ok4

# 5. re-running over an earlier install whose repo config names filters, transport commands and hooks: a fresh
#    clone replaces it, the old copy is moved aside untouched, and nothing from its config runs. Its origin
#    stays the local upstream, so any git run in the copy would fetch, check out and set off the canaries.
d5="$T/again/auditor-skill"
mkdir -p "$T/again" && git clone -q "$T/up.git" "$d5" && echo old > "$d5/old-marker" \
  && printf '* filter=sm\nSKILL.md filter=pr\n' > "$d5/.git/info/attributes" \
  && git -C "$d5" config filter.sm.smudge "$T/canary.sh smudge" \
  && git -C "$d5" config filter.pr.process "$T/canary.sh process" \
  && git -C "$d5" config core.sshCommand "$T/canary.sh ssh" \
  && git -C "$d5" config core.gitProxy "$T/gitproxy.sh" \
  && git -C "$d5" config core.alternateRefsCommand "$T/canary.sh altrefs" \
  && echo "$T/up.git/objects" > "$d5/.git/objects/info/alternates" \
  && git -C "$d5" config core.fsmonitor "$T/canary.sh fsmonitor" \
  && git -C "$d5" config core.worktree "$T/elsewhere" \
  && git -C "$d5" config submodule.vendor/trailofbits.update "!$T/canary.sh subupdate" \
  && for h in post-merge post-checkout post-rewrite reference-transaction; do
       printf '#!/bin/sh\ntouch "%s/fired-hook"\n' "$T" > "$d5/.git/hooks/$h" && chmod +x "$d5/.git/hooks/$h"; done \
  && advance up six
run up "$T/again" "$d5"
ok5() { installed "$d5" && none_fired && head_is "$d5" six && [ ! -e "$d5/old-marker" ] && [ ! -e "$T/elsewhere" ] \
  && [ "$(ls -d "$d5".old-* 2>/dev/null | wc -l | tr -d ' ')" = 1 ] && [ -f "$(ls -d "$d5".old-*)/old-marker" ]; }
check "re-running replaces an earlier install with a fresh clone and runs nothing from its config" ok5

# 6. a path that holds something other than an install is left alone
mkdir -p "$T/notours/auditor-skill" && echo mine > "$T/notours/auditor-skill/notes.txt"
run up "$T/notours" "$T/notours/auditor-skill"
ok6() { [ "$rc" -eq 2 ] && grep -q 'is not an auditor-skill install' "$T/err" && [ -f "$T/notours/auditor-skill/notes.txt" ] \
  && [ -z "$(ls -d "$T/notours/auditor-skill".old-* 2>/dev/null)" ] && [ ! -e "$T/notours/auditor-skill/SKILL.md" ]; }
check "a path that is not an install is refused and left alone" ok6

# 7. a path that is a symbolic link is refused
mkdir -p "$T/linked" && git clone -q "$T/up.git" "$T/linked/real" && ln -s "$T/linked/real" "$T/linked/auditor-skill"
run up "$T/linked" "$T/linked/auditor-skill"
ok7() { [ "$rc" -eq 2 ] && [ -L "$T/linked/auditor-skill" ] && head_is "$T/linked/real" "$(git -C "$T/up.seed" log -1 --format=%s)"; }
check "a path that is a symbolic link is refused" ok7

# 8. an empty directory at the path is installed into
mkdir -p "$T/empty/auditor-skill"
run up "$T/empty" "$T/empty/auditor-skill"
ok8() { installed "$T/empty/auditor-skill" && [ -z "$(ls -d "$T/empty/auditor-skill".old-* 2>/dev/null)" ]; }
check "an empty directory at the path is installed into" ok8

# 9. a run without a path and a HOME that is empty, relative or unset stops before any git command or write
mkdir -p "$T/nohome"
ok9() { [ "$rc" -eq 2 ] && grep -q 'HOME is not set to an absolute path' "$T/err" && [ ! -s "$T/trace9" ] \
  && [ -z "$(ls -A "$T/nohome")" ]; }
HOME= GIT_TRACE="$T/trace9" run up "$T/nohome"
check "a run without a path and an empty HOME stops" ok9
HOME=rel GIT_TRACE="$T/trace9" run up "$T/nohome"
check "a run without a path and a relative HOME stops" ok9
if env -u HOME bash -c '[ -z "${HOME+set}" ]'; then   # bash leaves an unset HOME unset
  ( cd "$T/nohome" && unset HOME && GIT_TRACE="$T/trace9" GIT_CONFIG_GLOBAL="$T/up.gitconfig" bash "$ROOT/install.sh" ) \
    > "$T/out" 2> "$T/err"; rc=$?
  check "a run without a path and HOME unset stops" ok9
else
  echo "SKIP a run without a path and HOME unset (this bash sets HOME itself)"
fi

# 10. a run without a path warns when HOME itself is inside a git work tree
git init -q "$T/home10"
HOME="$T/home10" run up "$T"
ok10() { installed "$T/home10/.claude/skills/auditor-skill" && warned; }
check "a run without a path warns when HOME is inside a work tree" ok10

# 11. none of the runs with a path wrote under HOME
ok11() { [ -z "$(ls -A "$HOME")" ]; }
check "runs with a path never write under HOME" ok11

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
