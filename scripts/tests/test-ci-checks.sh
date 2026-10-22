#!/usr/bin/env bash
# test-ci-checks.sh — fixture tests for the CI checks that have no suite of their own:
#   1. scripts/check-attribution.sh flags a trailer in a commit message of 1 MiB as well as a short one,
#      and fails on a range git cannot read or one that holds no commits;
#   2. scripts/check-frontmatter.sh passes every real command, agent and SKILL.md and the shapes they use,
#      and fails each case below where Claude Code would read a field differently from what is written.
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

# ---- 2. check-frontmatter.sh -----------------------------------------------------------------------
expect "frontmatter: every real command, agent and SKILL.md passes" 0 bash "$ROOT/scripts/check-frontmatter.sh"
fm() { # fm DIR/NAME WANT LINE...  — a file of '---', the LINEs, '---' and a body; the check must WANT (pass|fail)
  local f="$T/fm/$1" want=$2 got=pass; shift 2
  mkdir -p "$(dirname "$f")"; { echo ---; printf '%s\n' "$@"; echo ---; echo; echo Body.; } > "$f"
  fmrun "${f#"$T/fm/"}" "$want"
}
fmrun() { # fmrun DIR/NAME WANT  — run the check on an existing fixture
  local got=pass
  out=$(bash "$ROOT/scripts/check-frontmatter.sh" "$T/fm/$1" 2>&1) || got=fail
  if [ "$got" = "$2" ]; then pass=$((pass + 1)); echo "PASS frontmatter $2: $1"; if [ -n "${VERBOSE:-}" ]; then echo "$out"; fi
  else failn=$((failn + 1)); echo "FAIL frontmatter $1: got $got, want $2"; echo "$out"; fi
}
N="name: x"; D="description: An agent."; TL="tools: Read, Grep, Glob"; M="model: sonnet"
fm agents/a00-control.md pass "$N" "$D" "$TL" "$M"
fm agents/a01-dashes-plain.md fail "$N" "description: Reads the diff --- then reports." "$TL" "$M"
fm agents/a02-dashes-quoted.md fail "$N" 'description: "Reads the diff --- then reports."' "$TL" "$M"
fm agents/a03-tools-case.md fail "$N" "$D" "Tools: Read, Grep, Glob" "$M"
fm agents/a04-tools-dup.md fail "$N" "$D" "$TL" "$M" "tools: Read, Grep, Glob, Bash, Write, Edit"
fm agents/a05-tools-comment.md fail "$N" "$D" "tools: Read, Grep #, Bash" "$M"
fm agents/a06-tools-star.md fail "$N" "$D" 'tools: "*"' "$M"
fm agents/a07-tools-empty.md fail "$N" "$D" "tools:" "$M"
fm agents/a08-folded.md fail "$N" "description: >-" "  Folded block scalar" "  over two lines." "$TL" "$M"
fm agents/a09-ampersand.md pass "$N" "description: R&D and &anchor-ish text." "$TL" "$M"
fm agents/a10-continuation.md fail "$N" "description: A plain scalar" "  continued on a second line." "$TL" "$M"
fm agents/a11-tools-list.md pass "$N" "$D" "tools:" "  - Read" "  - Grep" "$M"
fm agents/a12-escapes.md fail "$N" 'description: "caf\x41 \N tab\there"' "$TL" "$M"
fm agents/a13-key-space.md fail "$N" "$D" "tools : Read, Grep, Glob" "$M"
fm agents/a14-dashes-end.md fail "$N" "description: Ends with dashes ---" "$TL" "$M"
fm agents/a15-colon-cont.md fail "$N" "description: Plain scalar" "  continued: with a colon." "$TL" "$M"
fm agents/a16-single-quote.md pass "$N" "description: 'it''s quoted: fine'" "$TL" "$M"
fm agents/a17-flow-multiline.md fail "$N" "$D" "tools: [Read," "  Grep]" "$M"
fm agents/a18-doc-end.md fail "$N" "$D" "..." "$TL" "$M"
fm agents/a19-tools-before.md fail "$N" "$TL" "description: Reads the diff --- then reports." "$M"
fm agents/a20-anchor-alias.md fail "$N" "description: &d Anchored." "$TL" "model: *d"
fm agents/flow-empty.md fail "$N" "$D" "tools: []" "$M"
fm agents/list-empty.md fail "$N" "$D" "tools:" "$M"
fm agents/list-star.md fail "$N" "$D" "tools:" "  - Read" "  - '*'" "$M"
fm agents/list-two-in-one.md fail "$N" "$D" "tools:" "  - 'Read, Bash'" "$M"
fm agents/space-separated.md fail "$N" "$D" "tools: Read Grep" "$M"
fm agents/pattern-in-agent.md fail "$N" "$D" "tools: Read, Bash(jq *)" "$M"
fm agents/allowed-tools-in-agent.md fail "$N" "$D" "allowed-tools: Read, Grep" "$M"
fm agents/no-tools.md fail "$N" "$D" "$M"
fm agents/name-number.md fail "name: 3000" "$D" "$TL" "$M"
fm agents/name-boolean.md fail "name: yes" "$D" "$TL" "$M"
fm agents/description-null.md fail "$N" "description: null" "$TL" "$M"
fm agents/no-space.md fail "$N" "$D" "tools:Read, Grep" "$M"
fm agents/blank-line.md fail "$N" "" "$D" "$TL" "$M"
fm agents/comment-line.md fail "$N" "# a comment" "$D" "$TL" "$M"
fm agents/quoted-trailing.md fail "$N" 'description: "An agent." and more' "$TL" "$M"
fm agents/unknown-key.md fail "$N" "$D" "$TL" "$M" "color: blue"
printf '\357\273\277---\n%s\n%s\n%s\n---\n' "$N" "$D" "$TL" > "$T/fm/agents/bom.md"; fmrun agents/bom.md fail
printf -- '---\r\n%s\r\n%s\r\n%s\r\n---\r\n' "$N" "$D" "$TL" > "$T/fm/agents/crlf.md"; fmrun agents/crlf.md fail
printf -- '---\n%s\n%s\n%s\n' "$N" "$D" "$TL" > "$T/fm/agents/no-closing.md"; fmrun agents/no-closing.md fail
: > "$T/fm/agents/empty.md"; fmrun agents/empty.md fail
# commands: the one-line form with ${CLAUDE_PLUGIN_ROOT} in a pattern, and the list form, single-quoted items
C="description: A command."
fm commands/one-line.md pass "name: auditor:hunt" "$C" 'argument-hint: "[<address> ...] [--logs <dir>]"' \
  'allowed-tools: Read, Grep, Glob, Task, Edit(incident_*/**), Bash(jq *), Bash(bash ${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh *)'
fm commands/list-form.md pass "$C" "allowed-tools:" "  - Read" "  - Task" \
  "  - 'Bash(bash \"\${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh\" *)'" "  - 'Bash(echo ''x'' *)'" "  - Edit(incident_*/**)"
fm commands/poc-unfixed.md fail "name: auditor:poc" \
  "description: Generate a PoC. Never hard-fails: on toolchain absence it downgrades." "allowed-tools: Read, Grep, Glob, Bash, Task"
fm commands/no-allowed-tools.md fail "$C" 'argument-hint: "[path]"'
fm commands/tools-key.md fail "$C" "tools: Read, Grep"
fm commands/nested-parens.md fail "$C" "allowed-tools: Read, Bash(echo (x) *)"
fm commands/star-entry.md fail "$C" "allowed-tools: Read, *"
fm commands/empty-entry.md fail "$C" "allowed-tools: Read, , Grep"
fm commands/boolean-ok.md pass "$C" "allowed-tools: Read" "disable-model-invocation: true"
fm commands/boolean-yes.md fail "$C" "allowed-tools: Read" "disable-model-invocation: yes"
fm commands/dashes-in-item.md fail "$C" "allowed-tools:" "  - 'Bash(echo --- *)'"
fm commands/item-without-list.md fail "$C" "allowed-tools: Read" "  - Grep"
fm skill/SKILL.md pass "name: s" 'description: "A skill."'
fm skill-no-name/SKILL.md fail 'description: "A skill."'
fm other/notes.md fail "$N" "$D"
# large input: a 300 KB description and a 1 MiB body read whole by every awk; a --- near the description's end
long=$(awk 'BEGIN { for (i = 0; i < 10000; i++) printf "word%05d and more text here, ", i }')
fm agents/long-description.md pass "$N" "description: ${long}end." "$TL" "$M"
awk 'BEGIN { for (i = 0; i < 17000; i++) printf "body line %05d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", i }' \
  >> "$T/fm/agents/long-description.md"
fmrun agents/long-description.md pass
fm agents/long-dashes.md fail "$N" "description: ${long}then --- end." "$TL" "$M"

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
