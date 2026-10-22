#!/usr/bin/env bash
# test-install.sh — install.sh warns on stderr when the install directory is inside a git work tree, and
# still installs. Run from the repo root: `bash scripts/tests/test-install.sh`.
# Offline: every destination is pre-cloned from a local fixture, so install.sh takes its update path, and
# GIT_ALLOW_PROTOCOL=file refuses any https clone. Builds throwaway repos under ${TMPDIR:-/tmp}; bash >= 3.2.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE
T=$(mktemp -d "${TMPDIR:-/tmp}/install-test.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
export GIT_CEILING_DIRECTORIES="$T" GIT_ALLOW_PROTOCOL=file
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid \
  GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
pass=0; failn=0

git init -q "$T/origin" && echo x > "$T/origin/COSTS.md" && git -C "$T/origin" add COSTS.md \
  && git -C "$T/origin" commit -q -m fixture || { echo "could not build the fixture origin" >&2; exit 1; }
git init -q "$T/audited" && git init -q "$T/audited2" && mkdir -p "$T/outside"
for d in audited/.claude/skills/auditor-skill audited2/.claude/skills/auditor-skill outside/auditor-skill; do
  git clone -q "$T/origin" "$T/$d" && [ -d "$T/$d/.git" ] || { echo "could not pre-clone $d" >&2; exit 1; }
done

check() { # check NAME WANT_WARNING(yes|no) DIR ARGS...  (runs install.sh in DIR)
  local name=$1 want=$2 dir=$3 rc got=no; shift 3
  ( cd "$dir" && bash "$ROOT/install.sh" "$@" ) > "$T/out" 2> "$T/err"; rc=$?
  grep -q 'is inside the git work tree' "$T/err" && got=yes
  if [ "$rc" -eq 0 ] && [ "$got" = "$want" ] && grep -q 'auditor-skill installed' "$T/out"; then
    pass=$((pass + 1)); echo "PASS $name"
  else
    failn=$((failn + 1)); echo "FAIL $name (rc=$rc, warning=$got, want $want)"; cat "$T/err"
  fi
}
check "path inside a work tree warns" yes "$T" "$T/audited/.claude/skills/auditor-skill"
check "default path inside a work tree warns" yes "$T/audited2"
check "path outside any work tree is quiet" no "$T" "$T/outside/auditor-skill"

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
