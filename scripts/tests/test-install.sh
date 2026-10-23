#!/usr/bin/env bash
# test-install.sh — install.sh:
#   - a run without a path installs at $HOME/.claude/skills/auditor-skill, never in the directory it starts in,
#     notes a copy at ./.claude/skills/auditor-skill (7.6's default) without touching it, and stops before
#     anything runs when HOME is not an absolute path;
#   - a run over an earlier install, with or without a path, installs a fresh clone and moves that copy, without
#     running git in it, to a backup in a mode-700 directory under XDG_STATE_HOME or ~/.local/state, so nothing
#     in its repo config (filters, hooks, transport commands) runs and nothing is left beside the install; a
#     backup path that exists, or no absolute XDG_STATE_HOME or HOME, stops the run before any git command;
#   - a path that is a symbolic link, or that holds something other than an install, is refused, and so is a
#     backup directory that is a link or lies beside the install;
#   - a download cut short runs nothing and exits non-zero, and a failed clone leaves the earlier install alone;
#   - a warning goes to stderr when the install directory is inside a git work tree.
# Run from the repo root: `bash scripts/tests/test-install.sh`.
# Offline: a temp global config maps the canonical URL to local bare upstreams, and GIT_ALLOW_PROTOCOL=file
# refuses every other transport. HOME is a temp dir too. Builds throwaway repos under ${TMPDIR:-/tmp};
# bash >= 3.2.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE GIT_TRACE XDG_STATE_HOME
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
# backed_up DIR BACKUPS: the earlier copy (old-marker) is the one backup in BACKUPS, which is mode 700; DIR, the
# directory that holds the install, holds nothing else; the run names the backup's full path right after the
# move, before the install is reported, and again at the end.
backed_up() {
  local b; b=$(ls -d "$2"/backup-* 2>/dev/null)
  [ "$(printf '%s\n' "$b" | grep -c .)" = 1 ] && [ -f "$b/old-marker" ] && [ "$(ls -ld "$2" | cut -c1-10)" = drwx------ ] \
    && [ "$(ls -A "$1")" = auditor-skill ] && grep -qxF "  The earlier install is now $b" "$T/out" \
    && awk -v m="→ The earlier install is now $b;" 'index($0, m) == 1 {moved = NR} /auditor-skill installed/ {done = NR}
         END {exit !(moved && moved < done)}' "$T/out"
}

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
#    hook: a fresh clone replaces it, the old copy moves untouched to $HOME/.local/state/auditor-skill (a
#    relative XDG_STATE_HOME is ignored), nothing is left in the skills directory, and nothing from its config runs
h4="$T/home4" && d4="$T/home4/.claude/skills/auditor-skill"
mkdir -p "$h4/.claude/skills" && git clone -q "$T/up.git" "$d4" && echo old > "$d4/old-marker" \
  && git -C "$d4" config core.fsmonitor "$T/canary.sh fsmonitor" \
  && printf '#!/bin/sh\ntouch "%s/fired-hook"\n' "$T" > "$d4/.git/hooks/post-merge" && chmod +x "$d4/.git/hooks/post-merge" \
  && advance up four
HOME="$h4" XDG_STATE_HOME=rel run up "$T/audited2"
ok4() { installed "$d4" && none_fired && head_is "$d4" four && [ ! -e "$d4/old-marker" ] && [ ! -e "$T/audited2/rel" ] \
  && backed_up "$h4/.claude/skills" "$h4/.local/state/auditor-skill"; }
check "a run without a path backs an earlier default install up under HOME/.local/state, not beside it, running nothing from its config" ok4

# 5. re-running over an earlier install in a skills/ directory whose repo config names filters, transport
#    commands and hooks: a fresh clone replaces it, the old copy moves untouched to $XDG_STATE_HOME/auditor-skill,
#    nothing is left in the skills directory, and nothing from its config runs. Its origin stays the local
#    upstream, so any git run in the copy would fetch, check out and set off the canaries.
d5="$T/again/skills/auditor-skill"
mkdir -p "$T/again/skills" && git clone -q "$T/up.git" "$d5" && echo old > "$d5/old-marker" \
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
XDG_STATE_HOME="$T/state5" run up "$T/again" "$d5"
ok5() { installed "$d5" && none_fired && head_is "$d5" six && [ ! -e "$d5/old-marker" ] && [ ! -e "$T/elsewhere" ] \
  && backed_up "$T/again/skills" "$T/state5/auditor-skill"; }
check "re-running backs an earlier install up under XDG_STATE_HOME, not in its skills directory, running nothing from its config" ok5

# 6. a path that holds something other than an install is left alone
mkdir -p "$T/notours/auditor-skill" && echo mine > "$T/notours/auditor-skill/notes.txt"
run up "$T/notours" "$T/notours/auditor-skill"
ok6() { [ "$rc" -eq 2 ] && grep -q 'is not an auditor-skill install' "$T/err" && [ -f "$T/notours/auditor-skill/notes.txt" ] \
  && [ ! -e "$HOME/.local" ] && [ ! -e "$T/notours/auditor-skill/SKILL.md" ]; }
check "a path that is not an install is refused and left alone" ok6

# 7. a path that is a symbolic link is refused
mkdir -p "$T/linked" && git clone -q "$T/up.git" "$T/linked/real" && ln -s "$T/linked/real" "$T/linked/auditor-skill"
run up "$T/linked" "$T/linked/auditor-skill"
ok7() { [ "$rc" -eq 2 ] && grep -q 'neither follows nor replaces' "$T/err" && [ -L "$T/linked/auditor-skill" ] \
  && head_is "$T/linked/real" "$(git -C "$T/up.seed" log -1 --format=%s)"; }
check "a path that is a symbolic link is refused" ok7

# 8. an empty directory at the path is installed into
mkdir -p "$T/empty/auditor-skill"
run up "$T/empty" "$T/empty/auditor-skill"
ok8() { installed "$T/empty/auditor-skill" && [ ! -e "$HOME/.local" ]; }
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

# 12. a backup path that already exists is never written to: the run stops before any git command, and the
#     earlier install stays where it is
d12="$T/twelve/skills/auditor-skill"
mkdir -p "$T/twelve/skills" && git clone -q "$T/up.git" "$d12" && echo old > "$d12/old-marker" \
  && git -C "$d12" config core.fsmonitor "$T/canary.sh fsmonitor"
now=$(date +%s); i=0
while [ "$i" -le 20 ]; do   # every backup name the run can pick in the next 20 seconds
  e=$((now + i)); ts=$(date -r "$e" +%Y%m%d-%H%M%S 2>/dev/null || date -d "@$e" +%Y%m%d-%H%M%S)
  mkdir -p "$T/state12/auditor-skill/backup-$ts" && echo keep > "$T/state12/auditor-skill/backup-$ts/keep"
  i=$((i + 1))
done
XDG_STATE_HOME="$T/state12" GIT_TRACE="$T/trace12" run up "$T/twelve" "$d12"
ok12() { [ "$rc" -eq 2 ] && grep -q 'already exists; run the installer again' "$T/err" && [ ! -s "$T/trace12" ] && none_fired \
  && [ -f "$d12/old-marker" ] && [ "$(ls -A "$T/twelve/skills")" = auditor-skill ] \
  && [ "$(find "$T/state12/auditor-skill" -mindepth 2 | wc -l | tr -d ' ')" = 21 ]; }
check "an existing backup path stops the run before any git command and leaves the earlier install" ok12

# 13. an earlier install needs an absolute XDG_STATE_HOME or HOME to keep its backup under: without one the
#     run stops before any git command or write
d13="$T/thirteen/auditor-skill"
mkdir -p "$T/thirteen" && git clone -q "$T/up.git" "$d13" && echo old > "$d13/old-marker"
HOME= XDG_STATE_HOME=rel GIT_TRACE="$T/trace13" run up "$T/thirteen" "$d13"
ok13() { [ "$rc" -eq 2 ] && grep -q 'neither XDG_STATE_HOME nor HOME is an absolute path' "$T/err" && [ ! -s "$T/trace13" ] \
  && [ -f "$d13/old-marker" ] && [ "$(ls -A "$T/thirteen")" = auditor-skill ]; }
check "an earlier install with no absolute XDG_STATE_HOME or HOME stops the run before anything moves" ok13

# 14. a download cut short (curl … | bash) changes nothing: every prefix of install.sh past its first line, cut at
#     a line end or inside a line, is a syntax error, and the earlier install, HOME and the skills directory stay
#     as they were
h14="$T/home14" && d14="$h14/.claude/skills/auditor-skill"
mkdir -p "$h14/.claude/skills" && git clone -q "$T/up.git" "$d14" && echo old > "$d14/old-marker" \
  && git -C "$d14" config core.fsmonitor "$T/canary.sh fsmonitor"
unchanged14() { [ -f "$d14/old-marker" ] && [ ! -e "$h14/.local" ] && [ "$(ls -A "$h14/.claude/skills")" = auditor-skill ] && none_fired; }
cut14() { # cut14 HEAD-ARGS...: run that prefix of install.sh as `curl … | bash` would; sets rc
  head "$@" "$ROOT/install.sh" > "$T/cut.sh"
  ( cd "$T" && HOME="$h14" GIT_CONFIG_GLOBAL="$T/up.gitconfig" bash < "$T/cut.sh" ) > /dev/null 2>&1; rc=$?
}
size=$(wc -c < "$ROOT/install.sh" | tr -d ' '); lines=$(wc -l < "$ROOT/install.sh" | tr -d ' ')
first=$(head -n 1 "$ROOT/install.sh" | wc -c | tr -d ' '); bad14=""; n=1
while [ "$n" -lt "$lines" ]; do
  cut14 -n "$n"; { [ "$n" -eq 1 ] || [ "$rc" -ne 0 ]; } && unchanged14 || bad14="$bad14 lines=$n:rc=$rc"; n=$((n + 1))
done
n=1
while [ "$n" -lt "$((size - 1))" ]; do   # the whole script without its final newline is complete
  cut14 -c "$n"; { [ "$n" -le "$first" ] || [ "$rc" -ne 0 ]; } && unchanged14 || bad14="$bad14 bytes=$n:rc=$rc"
  if [ "$n" -lt "$((size - 40))" ]; then n=$((n + 53)); else n=$((n + 1)); fi
done
if [ -z "$bad14" ]; then pass=$((pass + 1)); echo "PASS a download cut short anywhere after its first line runs nothing and exits non-zero"
else failn=$((failn + 1)); echo "FAIL a download cut short ran something or exited 0:$bad14"; fi

# 15. a clone that fails stops the run: it exits non-zero, the earlier install stays where it is, and nothing is
#     backed up or left in the skills directory
h15="$T/home15" && d15="$h15/.claude/skills/auditor-skill"
mkdir -p "$h15/.claude/skills" && git clone -q "$T/up.git" "$d15" && echo old > "$d15/old-marker"
printf '[url "file://%s/missing.git"]\n\tinsteadOf = https://github.com/solanabr/auditor-skill.git\n' "$T" > "$T/missing.gitconfig"
HOME="$h15" run missing "$T"
ok15() { [ "$rc" -ne 0 ] && ! grep -q 'auditor-skill installed' "$T/out" && [ -f "$d15/old-marker" ] && [ ! -e "$h15/.local" ] \
  && [ "$(ls -A "$h15/.claude/skills")" = auditor-skill ]; }
check "a failed clone exits non-zero and leaves the earlier install in place, with no backup" ok15

# 16. a default path that is a symbolic link is refused before any git command; link and target stay as they were
h16="$T/home16"; mkdir -p "$h16/.claude/skills" "$T/real16" && git clone -q "$T/up.git" "$T/real16/auditor-skill" \
  && echo old > "$T/real16/auditor-skill/old-marker" && ln -s "$T/real16/auditor-skill" "$h16/.claude/skills/auditor-skill"
HOME="$h16" GIT_TRACE="$T/trace16" run up "$T"
ok16() { [ "$rc" -eq 2 ] && grep -q 'neither follows nor replaces' "$T/err" && [ ! -s "$T/trace16" ] \
  && [ -L "$h16/.claude/skills/auditor-skill" ] && [ -f "$T/real16/auditor-skill/old-marker" ] && [ ! -e "$h16/.local" ]; }
check "a run without a path refuses a linked default path and runs no git" ok16

# 17. a backup directory that is a symbolic link is refused before any git command, so nothing lands where it points
h17="$T/home17"; d17="$h17/.claude/skills/auditor-skill"
mkdir -p "$h17/.claude/skills" "$h17/.local/state" "$T/other17/skills" && git clone -q "$T/up.git" "$d17" && echo old > "$d17/old-marker" \
  && ln -s "$T/other17/skills" "$h17/.local/state/auditor-skill"
HOME="$h17" GIT_TRACE="$T/trace17" run up "$T"
ok17() { [ "$rc" -eq 2 ] && grep -q 'is a symbolic link; backups go only to a real directory' "$T/err" && [ ! -s "$T/trace17" ] \
  && [ -z "$(ls -A "$T/other17/skills")" ] && [ -f "$d17/old-marker" ] && [ "$(ls -A "$h17/.claude/skills")" = auditor-skill ]; }
check "a linked backup directory is refused before any git command" ok17

# 18. a backup directory beside the install is refused before any git command: XDG_STATE_HOME set to the skills
#     directory, and ~/.local/state linked to it
h18="$T/home18"; d18="$h18/.claude/skills/auditor-skill"
mkdir -p "$h18/.claude/skills" && git clone -q "$T/up.git" "$d18" && echo old > "$d18/old-marker"
mode18=$(ls -ld "$d18" | cut -c1-10)
HOME="$h18" XDG_STATE_HOME="$h18/.claude/skills" GIT_TRACE="$T/trace18" run up "$T"
ok18() { [ "$rc" -eq 2 ] && grep -q 'beside the install' "$T/err" && [ ! -s "$T/trace18" ] && [ -f "$d18/old-marker" ] \
  && [ "$(ls -ld "$d18" | cut -c1-10)" = "$mode18" ] && [ "$(ls -A "$h18/.claude/skills")" = auditor-skill ]; }
check "XDG_STATE_HOME inside the skills directory is refused before any git command" ok18
mkdir -p "$h18/.local" && ln -s "$h18/.claude/skills" "$h18/.local/state"
HOME="$h18" GIT_TRACE="$T/trace18" run up "$T"
check "a ~/.local/state linked into the skills directory is refused before any git command" ok18

# 19. a run without a path started where 7.6 installed by default prints a notice about the copy there, and runs
#     no git in it; started from HOME, where that copy is the default install, it prints none
h19="$T/home19"; p19="$T/proj19"; mkdir -p "$h19" "$p19/.claude/skills" && git clone -q "$T/up.git" "$p19/.claude/skills/auditor-skill" \
  && echo old > "$p19/.claude/skills/auditor-skill/old-marker" \
  && git -C "$p19/.claude/skills/auditor-skill" config core.fsmonitor "$T/canary.sh fsmonitor"
HOME="$h19" run up "$p19"
ok19() { installed "$h19/.claude/skills/auditor-skill" && [ "$(grep -c '^note: ' "$T/err")" = 1 ] \
  && grep -q '^note: .*leaves \./\.claude/skills/auditor-skill alone; see "Upgrading from 7\.6 or earlier" in the README\.$' "$T/err" \
  && [ -f "$p19/.claude/skills/auditor-skill/old-marker" ] && none_fired; }
check "a run without a path notes a 7.6 default copy in the directory it starts in, and leaves it alone" ok19
HOME="$p19" run up "$p19"
ok19b() { installed "$p19/.claude/skills/auditor-skill" && ! grep -q '^note: ' "$T/err" && none_fired; }
check "a run without a path from HOME upgrades the default install there without the notice" ok19b

# 20. an earlier install that cannot be moved (its directory is not writable) stops the run: it exits non-zero and
#     leaves the earlier install in place, with nothing new in the skills directory (root can move it anyway)
if [ "$(id -u)" != 0 ]; then
  h20="$T/home20"; d20="$h20/.claude/skills/auditor-skill"
  mkdir -p "$h20/.claude/skills" && git clone -q "$T/up.git" "$d20" && echo old > "$d20/old-marker" && chmod a-w "$d20"
  HOME="$h20" run up "$T"
  chmod u+w "$d20"
  ok20() { [ "$rc" -ne 0 ] && grep -q 'could not move the earlier install out of' "$T/err" && [ -f "$d20/old-marker" ] \
    && [ "$(ls -A "$h20/.claude/skills")" = auditor-skill ] && ! grep -q 'auditor-skill installed' "$T/out"; }
  check "an earlier install that cannot be moved stops the run and stays in place" ok20
fi

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
