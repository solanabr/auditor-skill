#!/usr/bin/env bash
# test-install.sh — install.sh: a run without a path never updates an existing copy and runs no git; an
# explicit path updates that copy with its repo config's fsmonitor, hooks, credential helpers, file:// and
# ext:: transports and submodule update command disabled; and a warning goes to stderr when the install
# directory is inside a git work tree. Run from the repo root: `bash scripts/tests/test-install.sh`.
# Offline: every repository is a local fixture. GIT_ALLOW_PROTOCOL=file lets the test's own local fetches
# through (it takes precedence over install.sh's protocol.file.allow=never) and refuses any https clone.
# Builds throwaway repos under ${TMPDIR:-/tmp}; bash >= 3.2.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE GIT_TRACE
T=$(mktemp -d "${TMPDIR:-/tmp}/install-test.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
export GIT_CEILING_DIRECTORIES="$T" GIT_ALLOW_PROTOCOL=file
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid \
  GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
pass=0; failn=0

# Fixture upstreams: up.git (one file), up2.git (also a vendor/trailofbits submodule from a local repo).
mkup() { # mkup NAME [submodule]
  git init -q --bare "$T/$1.git" && git -C "$T/$1.git" symbolic-ref HEAD refs/heads/main \
    && git clone -q "$T/$1.git" "$T/$1.seed" 2>/dev/null && git -C "$T/$1.seed" checkout -q -b main \
    && echo base > "$T/$1.seed/base" && git -C "$T/$1.seed" add base || return 1
  if [ -n "${2:-}" ]; then git -C "$T/$1.seed" submodule add -q "file://$T/tob" vendor/trailofbits || return 1; fi
  git -C "$T/$1.seed" commit -q -m base && git -C "$T/$1.seed" push -q origin main
}
advance() { # advance NAME FILE: a new upstream commit whose subject is FILE
  echo "$2" > "$T/$1.seed/$2" && git -C "$T/$1.seed" add "$2" && git -C "$T/$1.seed" commit -q -m "$2" \
    && git -C "$T/$1.seed" push -q origin main
}
git init -q "$T/tob" && echo p > "$T/tob/p" && git -C "$T/tob" add p && git -C "$T/tob" commit -q -m p \
  && mkup up && mkup up2 submodule || { echo "could not build the fixture upstreams" >&2; exit 1; }
printf '#!/bin/sh\ntouch "%s/fired-$1"\nexit 0\n' "$T" > "$T/canary.sh" && chmod +x "$T/canary.sh"

run() { # run DIR ARGS...  (install.sh in DIR; sets rc, $T/out, $T/err)
  local d=$1; shift
  ( cd "$d" && bash "$ROOT/install.sh" "$@" ) > "$T/out" 2> "$T/err"; rc=$?
}
run_file_refused() { # like run, without the test's GIT_ALLOW_PROTOCOL: install.sh's own protocol settings apply
  local d=$1; shift
  ( unset GIT_ALLOW_PROTOCOL; cd "$d" && bash "$ROOT/install.sh" "$@" ) > "$T/out" 2> "$T/err"; rc=$?
}
check() { # check NAME TEST...
  local name=$1; shift
  if "$@"; then pass=$((pass + 1)); echo "PASS $name"
  else failn=$((failn + 1)); echo "FAIL $name (rc=$rc)"; sed 's/^/  | /' "$T/err"; fi
}
head_is() { [ "$(git -C "$1" log -1 --format=%s)" = "$2" ]; }
warned() { grep -q 'is inside the git work tree' "$T/err"; }
none_fired() { [ -z "$(ls "$T" | grep '^fired-')" ]; }

# 1. explicit path inside a work tree: warns, then updates
git init -q "$T/audited" && git clone -q "$T/up.git" "$T/audited/.claude/skills/auditor-skill" && advance up two
run "$T" "$T/audited/.claude/skills/auditor-skill"
ok1() { [ "$rc" -eq 0 ] && warned && head_is "$T/audited/.claude/skills/auditor-skill" two && grep -q 'auditor-skill installed' "$T/out"; }
check "explicit path inside a work tree warns and updates" ok1

# 2. explicit path outside any work tree: no warning, updates
mkdir -p "$T/outside" && git clone -q "$T/up.git" "$T/outside/auditor-skill" && advance up three
run "$T" "$T/outside/auditor-skill"
ok2() { [ "$rc" -eq 0 ] && ! warned && head_is "$T/outside/auditor-skill" three; }
check "explicit path outside any work tree is quiet and updates" ok2

# 3. a run without a path over an existing copy whose repo config sets fsmonitor and a hook stops before any git
#    command
git init -q "$T/archive" && d3="$T/archive/.claude/skills/auditor-skill" && git clone -q "$T/up.git" "$d3" \
  && git -C "$d3" config core.fsmonitor "$T/canary.sh fsmonitor" \
  && printf '#!/bin/sh\ntouch "%s/fired-hook"\n' "$T" > "$d3/.git/hooks/post-merge" && chmod +x "$d3/.git/hooks/post-merge" \
  && advance up four
before=$(git -C "$d3" rev-parse HEAD)
GIT_TRACE="$T/trace3" run "$T/archive"
ok3() { [ "$rc" -eq 2 ] && grep -q 'Pass the install path explicitly' "$T/err" && [ ! -s "$T/trace3" ] && none_fired \
  && [ "$(git -C "$d3" rev-parse HEAD)" = "$before" ] && [ ! -e "$d3/.git/FETCH_HEAD" ]; }
check "a run without a path refuses an existing copy and runs no git" ok3

# 4. a run without a path and no existing copy: warns inside a work tree before it clones (the https clone is
#    refused here, so nothing goes over the network)
git init -q "$T/audited2"
run "$T/audited2"
ok4() { [ "$rc" -ne 0 ] && warned && [ ! -e "$T/audited2/.claude/skills/auditor-skill/.git" ]; }
check "a run without a path warns inside a work tree before cloning" ok4

# 5. explicit update of a copy whose repo config sets fsmonitor, a post-merge hook and a submodule update command
d5="$T/hostile/auditor-skill"
mkdir -p "$T/hostile" && git clone -q "$T/up2.git" "$d5" && git -C "$d5" config core.fsmonitor "$T/canary.sh fsmonitor" \
  && git -C "$d5" config submodule.vendor/trailofbits.update "!$T/canary.sh subupdate" \
  && git -C "$d5" config submodule.vendor/trailofbits.url "file://$T/tob" \
  && printf '#!/bin/sh\ntouch "%s/fired-hook"\n' "$T" > "$d5/.git/hooks/post-merge" && chmod +x "$d5/.git/hooks/post-merge" \
  && advance up2 five
run "$T" "$d5"
ok5() { [ "$rc" -eq 0 ] && none_fired && head_is "$d5" five && [ -f "$d5/vendor/trailofbits/p" ]; }
check "explicit update ignores the copy's fsmonitor, hooks and submodule update command" ok5

# 6. explicit update refuses an ext:: remote the copy's config allows
d6="$T/extremote/auditor-skill"
mkdir -p "$T/extremote" && git clone -q "$T/up.git" "$d6" && git -C "$d6" config remote.origin.url "ext::$T/canary.sh ext" \
  && git -C "$d6" config protocol.ext.allow always
run_file_refused "$T" "$d6"
ok6() { [ "$rc" -ne 0 ] && none_fired; }
check "explicit update refuses an ext:: remote" ok6

# 7. explicit update refuses a file:// remote once the test's own allowance is gone
d7="$T/fileremote/auditor-skill"
mkdir -p "$T/fileremote" && git clone -q "$T/up.git" "$d7" && before=$(git -C "$d7" rev-parse HEAD) && advance up seven
run_file_refused "$T" "$d7"
ok7() { [ "$rc" -ne 0 ] && [ "$(git -C "$d7" rev-parse HEAD)" = "$before" ]; }
check "explicit update refuses a file:// remote" ok7

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
