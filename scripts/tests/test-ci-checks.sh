#!/usr/bin/env bash
# test-ci-checks.sh — fixture tests for the CI checks that have no suite of their own:
#   1. scripts/check-attribution.sh flags a trailer in a commit message of 1 MiB as well as a short one,
#      and fails on a range git cannot read or one that holds no commits.
# Usage (from the repo root): bash scripts/tests/test-ci-checks.sh   (VERBOSE=1 shows each check's output)
# Builds throwaway files and git repos under ${TMPDIR:-/tmp}; no network; bash >= 3.2.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE
T=$(mktemp -d "${TMPDIR:-/tmp}/ci-checks.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
export GIT_CEILING_DIRECTORIES="$T"   # fixtures never see a repository above the temp dir
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid \
  GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
pass=0; failn=0

expect() { # expect NAME WANT-RC CMD...  (runs CMD, compares its exit status)
  local name=$1 want=$2 got; shift 2
  out=$("$@" 2>&1); got=$?
  if [ "$got" -eq "$want" ]; then pass=$((pass + 1)); echo "PASS $name (rc=$got)"; if [ -n "${VERBOSE:-}" ]; then echo "$out"; fi
  else failn=$((failn + 1)); echo "FAIL $name (rc=$got, want $want)"; echo "$out"; fi
}

# ---- 1. check-attribution.sh ------------------------------------------------------------------------
# The trailer is assembled here so this file does not carry one itself.
TRAILER="Co-Authored-By: $(printf 'Cl%s' aude) <noreply@anthropic.com>"
at="$T/attr"; mkdir -p "$at" && git -C "$at" init -q && echo a > "$at/f" && git -C "$at" add f \
  && git -C "$at" commit -q -m base
attr() { (cd "$at" && bash "$ROOT/scripts/check-attribution.sh" "$@"); }
echo b >> "$at/f" && git -C "$at" commit -q -am "fix: a clean change" && clean=$(git -C "$at" rev-parse HEAD)
expect "attribution: a clean range passes" 0 attr "HEAD~1..HEAD"
# a 1 MiB message with the trailer on line 3: far more than a pipe holds before the reader exits
{ printf 'docs: a long message\n\n%s\n' "$TRAILER"
  awk 'BEGIN { for (i = 0; i < 17000; i++) printf "filler line %05d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", i }'
} > "$T/big-msg"
echo c >> "$at/f" && git -C "$at" commit -q -a -F "$T/big-msg"
if [ "$(wc -c < "$T/big-msg" | tr -d ' ')" -gt 1048576 ]; then pass=$((pass + 1)); echo "PASS attribution: the large message is over 1 MiB"
else failn=$((failn + 1)); echo "FAIL attribution: the large message is under 1 MiB"; fi
expect "attribution: a trailer in a 1 MiB message fails" 1 attr "$clean..HEAD"
git -C "$at" reset -q --hard "$clean"
printf 'docs: a short message\n\n%s\n' "$TRAILER" > "$T/small-msg"
echo d >> "$at/f" && git -C "$at" commit -q -a -F "$T/small-msg"
expect "attribution: a trailer in a short message fails" 1 attr "$clean..HEAD"
expect "attribution: a range git cannot read fails" 1 attr "no-such-ref..HEAD"
expect "attribution: a range with no commits fails" 1 attr "HEAD..HEAD"
expect "attribution: an option in place of a range fails" 1 attr "--all"

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
