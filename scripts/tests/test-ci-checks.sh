#!/usr/bin/env bash
# test-ci-checks.sh — fixture tests for the CI checks that have no suite of their own:
#   1. scripts/check-attribution.sh flags a trailer in a commit message of 1 MiB as well as a short one,
#      and fails on a range git cannot read or one that holds no commits; it and scripts/hooks/commit-msg,
#      which share one pattern, refuse the same trailer with any spacing around its colon, or folded onto
#      the next line; the check also fails a commit whose author or committer is an AI assistant;
#   2. scripts/check-frontmatter.sh passes every real command, agent and SKILL.md and the shapes they use,
#      and fails each case below where Claude Code would read a field differently from what is written;
#   3. scripts/check-pipefail.sh flags each pipe into a reader that can stop early in a script under
#      pipefail, and leaves quoted text, here-documents, waived lines and scripts without pipefail alone.
#      The check scripts, and the suites that test them, must pass it here; CI runs it over every tracked
#      *.sh file;
#   4. .github/workflows: the required job keeps its name; every workflow and job reads contents only; no
#      workflow names pull_request_target or workflow_run outside a comment line, however its trigger is
#      written, and none spells a key YAML reads as on other than as plain on: (quoted in either style, with
#      escapes, a tag, an anchor or another letter case, in block or flow style), or writes an explicit ? key
#      or an alias as a key; no run: script holds a ${{ }} expression; every job has timeout-minutes, every
#      action is pinned by full SHA with its version, and no checkout keeps credentials;
#   5. scripts/check-hygiene.sh fails on each kind of file it names, and on a top-level directory named
#      commands, agents, skills, hooks, bin, monitors or .claude-plugin in another letter case, also when it
#      is the last of 3,000 tracked paths; on each load surface at the plugin root, and on a SKILL.md other
#      than SKILL.md and skills/<name>/SKILL.md in any letter case, unless the allow list names it; and on a
#      manifest key beyond its list, also at the end of a 1 MiB manifest. It passes the repository itself,
#      and fails outside a checkout and without jq;
#   6. scripts/check-entrypoints.sh passes the repository, reading its whole list, and a checkout whose entry
#      points, case files and allow rules all keep the contract; it fails each kind of bad list line (also the
#      last line of a list over 64 KiB), entry point, case file and allow rule, an agent's Bash rule, and an
#      entry point no rule pre-approves; it cannot run outside a checkout or without its list.
# Usage (from the repo root): bash scripts/tests/test-ci-checks.sh   (VERBOSE=1 shows each check's output)
# Builds throwaway files and git repos under ${TMPDIR:-/tmp}; no network; bash >= 3.2.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 1   # check-frontmatter.sh reads a path below the current directory from there
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
for sp in "\t" ""; do   # a tab, or no space, after the colon
  git -C "$at" reset -q --hard "$clean"
  printf "docs: a message\n\nCo-Authored-By:${sp}%s\n" "${TRAILER#Co-Authored-By: }" > "$T/sp-msg"
  echo e >> "$at/f" && git -C "$at" commit -q -a -F "$T/sp-msg"
  expect "attribution: a trailer with '${sp:-no space}' after the colon fails" 1 attr "$clean..HEAD"
done
expect "attribution: a range git cannot read fails" 1 attr "no-such-ref..HEAD"
expect "attribution: a range with no commits fails" 1 attr "HEAD..HEAD"
expect "attribution: an option in place of a range fails" 1 attr "--all"
for sp in " " "\t" ""; do   # the commit-msg hook reads the same pattern
  printf "docs: a message\n\nCo-Authored-By:${sp}%s\n" "${TRAILER#Co-Authored-By: }" > "$T/hook-msg"
  expect "commit-msg hook: a trailer with '${sp:-no space}' after the colon is refused" 1 sh "$ROOT/scripts/hooks/commit-msg" "$T/hook-msg"
done
printf 'docs: a message\n\nCo-Authored-By: A Person <person@example.invalid>\n' > "$T/hook-msg"
expect "commit-msg hook: a co-author trailer that names no assistant is accepted" 0 sh "$ROOT/scripts/hooks/commit-msg" "$T/hook-msg"
# a space or a tab before the colon, and a trailer folded onto the next line, which git reads as the trailer
for form in 'a space before the colon|Co-Authored-By : %s' 'a tab before the colon|Co-Authored-By\t: %s' \
            'the value folded onto a line that starts with a space|Co-Authored-By:\n %s' \
            'the value folded onto a line that starts with a tab|Co-Authored-By:\n\t%s'; do
  printf "docs: a message\n\n${form#*|}\n" "${TRAILER#Co-Authored-By: }" > "$T/form-msg"
  git -C "$at" reset -q --hard "$clean" && echo f >> "$at/f" && git -C "$at" commit -q -a -F "$T/form-msg"
  expect "attribution: a trailer with ${form%%|*} fails" 1 attr "$clean..HEAD"
  expect "commit-msg hook: a trailer with ${form%%|*} is refused" 1 sh "$ROOT/scripts/hooks/commit-msg" "$T/form-msg"
done
printf 'docs: a message\n\nCo-Authored-By:\n A Person <person@example.invalid>\n' > "$T/hook-msg"
expect "commit-msg hook: a folded co-author trailer that names no assistant is accepted" 0 sh "$ROOT/scripts/hooks/commit-msg" "$T/hook-msg"
p1=$(grep -E '^(pattern|unfold)=' "$ROOT/scripts/check-attribution.sh"); p2=$(grep -E '^(pattern|unfold)=' "$ROOT/scripts/hooks/commit-msg")
if [ -n "$p1" ] && [ "$p1" = "$p2" ]; then pass=$((pass + 1)); echo "PASS attribution: the commit-msg hook has check-attribution.sh's pattern and unfolding"
else failn=$((failn + 1)); echo "FAIL attribution: the commit-msg hook and check-attribution.sh differ"; echo "$p1"; echo "$p2"; fi
# an AI assistant as the author or the committer, by name or by email, with a clean message; a person whose
# first name is Claude passes
for who in "author|$(printf 'Cl%s' aude)|noreply@example.invalid|1" "committer|Claude Code|cc@example.invalid|1" \
           "author|A Person|NoReply@Anthropic.com|1" "committer|anthropic|bot@example.invalid|1" \
           "author|Claude Monet|claude@example.invalid|0"; do
  IFS='|' read -r role nm em want <<< "$who"
  git -C "$at" reset -q --hard "$clean" && echo g >> "$at/f"
  if [ "$role" = author ]; then GIT_AUTHOR_NAME=$nm GIT_AUTHOR_EMAIL=$em git -C "$at" commit -q -a -m "fix: a clean message"
  else GIT_COMMITTER_NAME=$nm GIT_COMMITTER_EMAIL=$em git -C "$at" commit -q -a -m "fix: a clean message"; fi
  expect "attribution: a commit whose $role is $nm <$em>" "$want" attr "$clean..HEAD"
done

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
fm agents/case-variant-key.md fail "$N" "$D" "TOOLS: Read" "$M"
# three dots in a plain value, number-like prefixes, and control characters
fm agents/b01-dots-end.md fail "$N" "description: Reads the diff..." "$TL" "$M"
fm agents/b02-dots-mid.md fail "$N" "description: Reads the diff... then reports." "$TL" "$M"
fm agents/b03-dots-four.md fail "$N" "description: Wait.... then reports." "$TL" "$M"
fm agents/b04-model-dots.md fail "$N" "$D" "$TL" "model: sonnet..."
fm agents/b05-name-dots.md fail "name: x..." "$D" "$TL" "$M"
fm agents/b16-dots-dq.md pass "$N" 'description: "Reads the diff... then reports."' "$TL" "$M"
fm agents/b17-dots-sq.md pass "$N" "description: 'Reads the diff... then reports.'" "$TL" "$M"
fm agents/b18-dots-tools-first.md fail "$N" "$TL" "description: Reads the diff..." "$M"
fm agents/b20-two-dots.md pass "$N" "description: Reads the diff.. then reports." "$TL" "$M"
fm agents/number-signs.md fail "name: ++7" "$D" "$TL" "$M"
fm agents/number-sign-dot.md fail "name: +-.5" "$D" "$TL" "$M"
fmbytes() { # fmbytes NAME WANT TEXT  — an agent whose description is TEXT, with its printf escapes as bytes
  mkdir -p "$T/fm/agents"; printf -- "---\n%s\ndescription: $3\n%s\n%s\n---\n" "$N" "$TL" "$M" > "$T/fm/agents/$1.md"
  fmrun "agents/$1.md" "$2"
}
fmbytes b06-nul-before-tools fail 'An agent.\000 More.'
fmbytes b07-nul-hides-hash fail 'An agent.\000 # hidden'
fmbytes b08-del fail 'An\177 agent.'
fmbytes b09-c1-0080 fail 'An\302\200 agent.'
fmbytes b10-nel-0085 fail 'An\302\205 agent.'
fmbytes b11-ls-2028 fail 'An\342\200\250 agent.'
fmbytes b12-ps-2029 fail 'An\342\200\251 agent.'
fmbytes b13-ctl-01 fail 'An\001 agent.'
fmbytes b14-ctl-0c fail 'An\014 agent.'
fmbytes b15-bom-mid pass 'An\357\273\277 agent.'
fmbytes b19-ellipsis-char pass 'Reads the diff\342\200\246 then reports.'
fmbytes utf8-dash-accent pass 'An agent \342\200\224 with a dash and caf\303\251.'
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
fm commands/c01-desc-dots-end.md fail "description: Runs the scan..." "allowed-tools: Read, Grep"
fm commands/c02-hint-dots-plain.md fail "$C" "argument-hint: <path> ..." "allowed-tools: Read, Grep"
fm commands/c03-pattern-dots.md fail "$C" "allowed-tools: Read, Bash(ls ... *)"
fm commands/c04-pattern-dots-end.md fail "$C" "allowed-tools: Read, Bash(ls *)..."
fm commands/plugin-root-items.md pass "$C" "allowed-tools:" "  - Read" "  - Grep" \
  "  - 'Bash(\"\${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh\" *)'" "  - 'Bash(bash \"\${CLAUDE_PLUGIN_ROOT}/scripts/dnr/redact.sh\" *)'"
# the bundled audit-scan and audit-mem only in the forms the confined builds pin, the contract marker in place
TB='${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release'
fm commands/tools-marked.md pass "$C" "allowed-tools:" "  - 'Bash(\"$TB/audit-scan\" --contract=1 *)'" \
  "  - 'Bash(\"$TB/audit-mem\" warm --contract=1 *)'" "  - 'Bash(\"$TB/audit-mem\" invariant --contract=1 *)'" \
  "  - 'Bash(test -x \"$TB/audit-mem\")'" "  - 'Bash(\"$TB/audit-logs\" *)'" "  - 'Read(audit_*/audit-mem.db)'"
fm commands/tools-scan-bare.md fail "$C" "allowed-tools:" "  - 'Bash(\"$TB/audit-scan\" *)'"
fm commands/tools-scan-late.md fail "$C" "allowed-tools:" "  - 'Bash(\"$TB/audit-scan\" . --contract=1 *)'"
fm commands/tools-scan-unquoted.md fail "$C" "allowed-tools:" "  - 'Bash($TB/audit-scan:*)'"
fm commands/tools-scan-glob.md fail "$C" "allowed-tools:" "  - 'Bash(\"$TB/audit-\"*)'"
fm commands/tools-scan-triple.md fail "$C" "allowed-tools:" "  - 'Bash(\"${TB%/release}/x86_64-unknown-linux-gnu/release/audit-scan\" --contract=1 *)'"
fm commands/tools-mem-bare.md fail "$C" "allowed-tools:" "  - 'Bash(\"$TB/audit-mem\" warm *)'"
fm commands/tools-mem-late.md fail "$C" "allowed-tools:" "  - 'Bash(\"$TB/audit-mem\" warm --db x --contract=1 *)'"
fm commands/tools-mem-rule.md fail "$C" "allowed-tools:" "  - 'Bash(\"$TB/audit-mem\" rule --contract=1 *)'"
fm commands/tools-mem-any.md fail "$C" "allowed-tools:" "  - 'Bash(\"$TB/audit-mem\" *)'"
fm commands/tools-mem-root-quoted.md fail "$C" "allowed-tools:" "  - 'Bash(\"\${CLAUDE_PLUGIN_ROOT}\"/tools/auditor-tools/target/release/audit-mem warm --contract=1 *)'"
fm commands/tools-root-glob.md fail "$C" "allowed-tools:" "  - 'Bash(\"\${CLAUDE_PLUGIN_ROOT}/*\" *)'"
fm commands/tools-tools-glob.md fail "$C" "allowed-tools:" "  - 'Bash(\"\${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/*\" *)'"
fm commands/tools-any-glob.md fail "$C" "allowed-tools:" "  - 'Bash(\"*/release/audit-*\" *)'"
fm commands/tools-mem-case.md fail "$C" "allowed-tools:" "  - 'Bash(\"$TB/AUDIT-MEM\" warm --contract=1 *)'"
fm commands/tools-prefix.md pass "$C" "allowed-tools:" "  - 'Bash(git log:*)'" "  - 'Bash(ls:*)'"
fm skill/SKILL.md pass "name: s" 'description: "A skill."'
fm skill-no-name/SKILL.md fail 'description: "A skill."'
fm skills/agents/SKILL.md pass "name: a" 'description: "A skill in a directory named agents."'
# a SKILL.md under skills/ may also have context: fork with an agent of the plugin, background and
# user-invocable, and allowed-tools under a command's rules; one outside skills/ has name and description only
fm agents/responder.md pass "name: responder" "$D" "$TL"
fm agents/misnamed.md pass "name: someone-else" "$D" "$TL"
F="context: fork"; A="agent: auditor:responder"; S='description: "A forked skill."'
fm skills/forked/SKILL.md pass "name: f" "$S" "$F" "$A" "background: false" "user-invocable: false" "allowed-tools:" \
  "  - Read" "  - Edit(incident_*/**)" "  - 'Bash(\"\${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh\" *)'"
fm skills/fork-one-line/SKILL.md pass "name: f1" "$S" "context: 'fork'" 'agent: "auditor:responder"' "background: true" \
  "user-invocable: true" 'allowed-tools: Read, Grep, Bash(bash ${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh *)'
fm Skills/upper-case/SKILL.md pass "name: f2" "$S" "$F" "$A"
fm skills/with-tools/SKILL.md pass "name: t" 'description: "A skill."' "allowed-tools: Read"
fm skills/invocable/SKILL.md pass "name: i" 'description: "A skill."' "user-invocable: false"
fm skills/context-inline/SKILL.md fail "name: c1" "$S" "context: inline" "$A"
fm skills/context-empty/SKILL.md fail "name: c2" "$S" "context: ''" "$A"
fm skills/fork-no-agent/SKILL.md fail "name: c3" "$S" "$F"
fm skills/agent-no-fork/SKILL.md fail "name: c4" "$S" "$A"
fm skills/background-no-fork/SKILL.md fail "name: c5" "$S" "background: false"
fm skills/background-yes/SKILL.md fail "name: c6" "$S" "$F" "$A" "background: yes"
fm skills/invocable-no/SKILL.md fail "name: c7" "$S" "user-invocable: no"
fm skills/invocable-quoted/SKILL.md fail "name: c8" "$S" 'user-invocable: "false"'
fm skills/agent-twice/SKILL.md fail "name: c9" "$S" "$F" "$A" "$A"
i=0
for ag in Explore general-purpose other:responder auditor:Responder auditor: auditor:../responder auditor:a/b \
  auditor:-x auditor:x- auditor:a--b 'auditor:responder #' auditor:nobody auditor:misnamed; do
  i=$((i + 1)); fm "skills/agent-$i/SKILL.md" fail "name: g$i" "$S" "$F" "agent: $ag"
done
for said in "skills/agent-12/SKILL.md:5: agent auditor:nobody names no agent of this plugin: $T/fm/agents/nobody.md is not a file" \
  "skills/agent-13/SKILL.md:5: agent auditor:misnamed: the frontmatter of $T/fm/agents/misnamed.md does not name it misnamed" \
  "skills/fork-no-agent/SKILL.md:4: context: fork needs an agent" "skills/agent-no-fork/SKILL.md:4: agent applies only with context: fork" \
  "skills/background-no-fork/SKILL.md:4: background applies only with context: fork"; do
  file=${said%%:*}
  out=$(bash "$ROOT/scripts/check-frontmatter.sh" "$T/fm/$file" 2>&1)
  case "$out" in *"$T/fm/$said"*) pass=$((pass + 1)); echo "PASS frontmatter: ... $said";;
    *) failn=$((failn + 1)); echo "FAIL frontmatter: not reported: $said"; echo "$out";; esac
done
fm skills/tools-star/SKILL.md fail "name: t1" "$S" "allowed-tools: Read, *"
fm skills/tools-nested/SKILL.md fail "name: t2" "$S" "allowed-tools: Read, Bash(echo (x) *)"
fm skills/tools-empty-entry/SKILL.md fail "name: t3" "$S" "allowed-tools: Read, , Grep"
fm skills/tools-two-in-item/SKILL.md fail "name: t4" "$S" "allowed-tools:" "  - 'Read, Bash'"
fm skills/tools-empty-list/SKILL.md fail "name: t5" "$S" "allowed-tools:"
fm skills/tools-dashes/SKILL.md fail "name: t6" "$S" "allowed-tools:" "  - 'Bash(echo --- *)'"
fm skill-tools/SKILL.md fail "name: r1" 'description: "A skill."' "allowed-tools: Read"
fm skill-fork/SKILL.md fail "name: r2" "$S" "$F" "$A"
fm skill-invocable/SKILL.md fail "name: r3" 'description: "A skill."' "user-invocable: false"
# the root SKILL.md, the one directly in the directory the check runs in, may also list allowed-tools under a
# command's rules, its bundled audit-scan and audit-mem from ${CLAUDE_SKILL_DIR}; it takes no other key
fmroot() { # fmroot NAME WANT LINE...  — a SKILL.md of those LINEs, checked as SKILL.md from its own directory
  local d="$T/fmroot/$1" want=$2 got=pass; shift 2
  mkdir -p "$d"; { echo ---; printf '%s\n' "$@"; echo ---; echo; echo Body.; } > "$d/SKILL.md"
  out=$(cd "$d" && bash "$ROOT/scripts/check-frontmatter.sh" SKILL.md 2>&1) || got=fail
  if [ "$got" = "$want" ]; then pass=$((pass + 1)); echo "PASS frontmatter $want: root SKILL.md, ${d##*/}"
  else failn=$((failn + 1)); echo "FAIL frontmatter root SKILL.md, ${d##*/}: got $got, want $want"; echo "$out"; fi
}
TS='${CLAUDE_SKILL_DIR}/tools/auditor-tools/target/release'
fmroot listed pass "name: r" 'description: "A skill."' "allowed-tools:" "  - Read" "  - Edit(audit_*/**)" \
  "  - 'Bash(\"\${CLAUDE_SKILL_DIR}/scripts/preflight.sh\" *)'" "  - 'Bash(\"$TS/audit-scan\" --contract=1 *)'" \
  "  - 'Bash(\"$TS/audit-mem\" warm --contract=1 *)'" "  - 'Bash(test -x \"$TS/audit-mem\")'"
fmroot one-line pass "name: r" 'description: "A skill."' "allowed-tools: Read, Grep"
fmroot plugin-root fail "name: r" 'description: "A skill."' "allowed-tools:" "  - 'Bash(\"$TB/audit-mem\" warm --contract=1 *)'"
fmroot no-marker fail "name: r" 'description: "A skill."' "allowed-tools:" "  - 'Bash(\"$TS/audit-mem\" check *)'"
fmroot rule fail "name: r" 'description: "A skill."' "allowed-tools:" "  - 'Bash(\"$TS/audit-mem\" rule --contract=1 *)'"
fmroot star fail "name: r" 'description: "A skill."' "allowed-tools: Read, Bash(*)"
fmroot fork fail "name: r" 'description: "A skill."' "context: fork" "allowed-tools: Read"
fmroot invocable fail "name: r" 'description: "A skill."' "user-invocable: false"
# the agent is looked up at the plugin root, the path before skills/, however the skill is named
for at in "$T/fm|skills/forked/SKILL.md" "$T/fm/agents|../skills/forked/SKILL.md" "$ROOT|$T/fm/skills/forked/SKILL.md"; do
  expect "frontmatter: an agent found from ${at%%|*} for ${at#*|}" 0 sh -c 'cd "$1" && bash "$2" "$3"' sh \
    "${at%%|*}" "$ROOT/scripts/check-frontmatter.sh" "${at#*|}"
done
mkdir -p "$T/fm-noagents/skills/forked"; cp "$T/fm/skills/forked/SKILL.md" "$T/fm-noagents/skills/forked/"
expect "frontmatter: an agent of another plugin root does not count" 1 bash "$ROOT/scripts/check-frontmatter.sh" \
  "$T/fm-noagents/skills/forked/SKILL.md"
# a .md under agents/ or commands/ is an agent or a command, also one named SKILL.md: the first of agents/,
# commands/ and skills/ in the path gives the kind
fm agents/skill.md fail "$N" "$D"
fm agents/sub/SKILL.md fail "$N" "$D"
fm agents/tools/SKILL.md pass "$N" "$D" "$TL" "$M"
fm commands/skill.md fail "name: c" "$C"
fm commands/sub/SKILL.md fail "name: c" "$C"
fm skills/s/agents/SKILL.md pass "name: s" 'description: "A skill in a directory named agents, in a skill."'
# with no arguments the check reads every .md at any depth under commands/ and agents/ (dotfiles too),
# the root SKILL.md, and every SKILL.md under skills/, in any letter case; a .MD name fails
lay="$T/layout"; mkdir -p "$lay/scripts" "$lay/commands/sub" "$lay/agents/deep/er" "$lay/skills/s" "$lay/skills/t/u"
cp "$ROOT/scripts/check-frontmatter.sh" "$lay/scripts/"
good_c() { printf -- '---\n%s\n%s\n---\n' "$C" "allowed-tools: Read" > "$1"; }
ga=0; gs=0   # each agent and skill written below gets a name of its own
good_a() { ga=$((ga + 1)); printf -- '---\n%s\n%s\n%s\n---\n' "name: a$ga" "$D" "$TL" > "$1"; }
good_s() { gs=$((gs + 1)); printf -- '---\n%s\n%s\n---\n' "name: s$gs" 'description: "A skill."' > "$1"; }
bad_fm() { printf -- '---\n%s\n%s\n%s\n---\n' "$N" "description: Ends with ---" "$TL" > "$1"; }
good_c "$lay/commands/c.md"; good_a "$lay/agents/a.md"; good_s "$lay/SKILL.md"
bad_fm "$lay/commands/sub/nested.md"; bad_fm "$lay/agents/deep/er/deeper.md"; bad_fm "$lay/agents/.hidden.md"
bad_fm "$lay/skills/s/SKILL.md"; bad_fm "$lay/skills/t/u/skill.md"; good_c "$lay/commands/Upper.MD"
mkdir -p "$lay/agents/as-skill"; good_s "$lay/agents/skill.md"; good_s "$lay/agents/as-skill/SKILL.md"   # no tools
expect "frontmatter: with no arguments, nested, hidden, lower-case and .MD files are read too" 1 bash "$lay/scripts/check-frontmatter.sh"
for want in "commands/sub/nested.md:3: --- inside" "agents/deep/er/deeper.md:3: --- inside" "agents/.hidden.md:3: --- inside" \
            "skills/s/SKILL.md:3: --- inside" "skills/t/u/skill.md:3: --- inside" "commands/Upper.MD: name the file with a lowercase .md" \
            "agents/skill.md:4: missing required key tools" "agents/as-skill/SKILL.md:4: missing required key tools"; do
  case "$out" in *"$want"*) pass=$((pass + 1)); echo "PASS frontmatter: ... $want";;
    *) failn=$((failn + 1)); echo "FAIL frontmatter: the default list missed: $want"; echo "$out";; esac
done
good_c "$lay/commands/sub/nested.md"; good_a "$lay/agents/deep/er/deeper.md"; good_a "$lay/agents/.hidden.md"
good_s "$lay/skills/s/SKILL.md"; good_s "$lay/skills/t/u/skill.md"; mv "$lay/commands/Upper.MD" "$lay/commands/renamed.md"
good_a "$lay/agents/skill.md"; good_a "$lay/agents/as-skill/SKILL.md"
expect "frontmatter: with no arguments, every kind of file passes once fixed" 0 bash "$lay/scripts/check-frontmatter.sh"
case "$out" in *"passed: 11 files"*) pass=$((pass + 1)); echo "PASS frontmatter: ... 11 files read";;
  *) failn=$((failn + 1)); echo "FAIL frontmatter: the default list did not read 11 files"; echo "$out";; esac
printf -- '---\nname: A1\n%s\n%s\n---\n' "$D" "$TL" > "$lay/agents/twin.md"   # agents/a.md is named a1
expect "frontmatter: with no arguments, a second agent named a1 fails" 1 bash "$lay/scripts/check-frontmatter.sh"
case "$out" in *"agents/a.md, agents/twin.md: 2 agents named a1"*) pass=$((pass + 1)); echo "PASS frontmatter: ... both files named";;
  *) failn=$((failn + 1)); echo "FAIL frontmatter: the duplicate name was not reported with both files"; echo "$out";; esac
fm other/notes.md fail "$N" "$D"
# one name for two agents, two commands or two skills fails, compared in any letter case; an agent and a
# command may share one
fm agents/twin-1.md pass "name: twin" "$D" "$TL"
fm agents/twin-2.md pass 'name: "Twin"' "$D" "$TL"
fm commands/twin-1.md pass "name: auditor:twin" "$C" "allowed-tools: Read"
fm commands/twin-2.md pass "name: auditor:twin" "$C" "allowed-tools: Read"
fm commands/twin.md pass "name: twin" "$C" "allowed-tools: Read"
for pair in "agents/twin-1.md agents/twin-2.md|1|2 agents named twin" "commands/twin-1.md commands/twin-2.md|1|2 commands named auditor:twin" \
            "skill/SKILL.md skills/s/agents/SKILL.md|1|2 skills named s" "agents/twin-1.md commands/twin.md|0|passed: 2 files"; do
  files=${pair%%|*}; rest=${pair#*|}; want=${rest%%|*}; text=${rest#*|}
  out=$(cd "$T/fm" && bash "$ROOT/scripts/check-frontmatter.sh" $files 2>&1); got=$?
  case "$got:$out" in "$want:"*"$text"*) pass=$((pass + 1)); echo "PASS frontmatter: $files -> $text";;
    *) failn=$((failn + 1)); echo "FAIL frontmatter: $files (rc=$got, want $want and '$text')"; echo "$out";; esac
done
# FORBIDDEN_ALLOWED_TOOLS holds only for allowed-tools: with bare Bash added to it, a command's bare Bash
# fails while its Bash(pattern) entries and an agent's Bash tool still pass
sed "s/^FORBIDDEN_ALLOWED_TOOLS='\(.*\)'\$/FORBIDDEN_ALLOWED_TOOLS='\1 Bash'/" "$ROOT/scripts/check-frontmatter.sh" > "$T/fm-no-bash.sh"
if grep -q "^FORBIDDEN_ALLOWED_TOOLS='.* Bash'\$" "$T/fm-no-bash.sh"; then pass=$((pass + 1)); echo "PASS frontmatter: FORBIDDEN_ALLOWED_TOOLS is one line to extend"
else failn=$((failn + 1)); echo "FAIL frontmatter: no FORBIDDEN_ALLOWED_TOOLS='…' line in check-frontmatter.sh"; fi
printf -- '---\n%s\n%s\n---\n' "$C" "allowed-tools: Read, Bash, Bash(jq *)" > "$T/fm/commands/bare-bash.md"
expect "frontmatter, with Bash forbidden: a command's bare Bash fails" 1 bash "$T/fm-no-bash.sh" "$T/fm/commands/bare-bash.md"
fm commands/bash-patterns.md pass "$C" "allowed-tools:" "  - Read" "  - 'Bash(jq *)'"
expect "frontmatter, with Bash forbidden: Bash(pattern) entries pass" 0 bash "$T/fm-no-bash.sh" "$T/fm/commands/bash-patterns.md"
expect "frontmatter, with Bash forbidden: an agent's Bash tool passes" 0 bash "$T/fm-no-bash.sh" "$T/fm/agents/a00-control.md" \
  "$ROOT/agents/context-builder.md"
# FORBIDDEN_ALLOWED_TOOLS holds a bare Bash: a command's, a skill's and the root SKILL.md's fail, in either list
# form, and so does a catch-all pattern; Bash(pattern) entries pass
fm commands/bare-bash-real.md fail "$C" "allowed-tools: Read, Bash"
fm commands/bare-bash-item.md fail "$C" "allowed-tools:" "  - Read" "  - Bash"
fm commands/bare-bash-quoted.md fail "$C" "allowed-tools:" "  - 'Bash'"
fm commands/catch-all-real.md fail "$C" "allowed-tools: Read, Bash(*)"
fm skills/bare-bash/SKILL.md fail "name: bb" 'description: "A skill."' "allowed-tools: Read, Bash"
fmroot bare-bash fail "name: r" 'description: "A skill."' "allowed-tools:" "  - Bash"
fm commands/bash-pattern-real.md pass "$C" "allowed-tools: Read, Bash(jq *)"
for all in 'Bash(*)' 'Bash( * )' 'Bash(:*)' 'Bash(**)'; do
  printf -- '---\n%s\n%s\n---\n' "$C" "allowed-tools: Read, $all" > "$T/fm/commands/catch-all.md"
  expect "frontmatter, with Bash forbidden: $all fails" 1 bash "$T/fm-no-bash.sh" "$T/fm/commands/catch-all.md"
done
expect "frontmatter, with Bash forbidden: Bash(\"\${CLAUDE_PLUGIN_ROOT}/…\" *) items pass" 0 bash "$T/fm-no-bash.sh" \
  "$T/fm/commands/plugin-root-items.md"
# large input: a 60 KB description and a 1 MiB body read whole by every awk; a --- near the end of that
# description; a block over 65,536 bytes; more than 256 of [, { and ' - '
long=$(awk 'BEGIN { for (i = 0; i < 2000; i++) printf "word%05d and more text here, ", i }')
fm agents/long-description.md pass "$N" "description: ${long}end." "$TL" "$M"
awk 'BEGIN { for (i = 0; i < 17000; i++) printf "body line %05d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", i }' \
  >> "$T/fm/agents/long-description.md"
fmrun agents/long-description.md pass
fm agents/long-dashes.md fail "$N" "description: ${long}then --- end." "$TL" "$M"
fm agents/over-64k.md fail "$N" "description: ${long}${long}end." "$TL" "$M"
fm agents/many-brackets.md fail "$N" "description: Notes $(awk 'BEGIN { for (i = 0; i < 257; i++) printf "[x] " }')end" "$TL" "$M"

# ---- 3. check-pipefail.sh --------------------------------------------------------------------------
lint() { # lint WANT NAME LINE...  — a script setting pipefail, then the LINEs; the check must WANT (flag|pass)
  local want=$1 f="$T/lint/$2.sh" got=pass; shift 2
  mkdir -p "$T/lint"; { echo '#!/usr/bin/env bash'; echo 'set -euo pipefail'; printf '%s\n' "$@"; } > "$f"
  out=$(bash "$ROOT/scripts/check-pipefail.sh" "$f" 2>&1) || got=flag
  if [ "$got" = "$want" ]; then pass=$((pass + 1)); echo "PASS pipefail $want: $*"; if [ -n "${VERBOSE:-}" ]; then echo "$out"; fi
  else failn=$((failn + 1)); echo "FAIL pipefail $*: got $got, want $want"; echo "$out"; fi
}
lint flag if-grep-q 'if git log -1 --format=%B "$sha" | grep -qiE "$pattern"; then :; fi'
lint flag head-in-subst 'x=$(sed -n "s/a/b/p" f | head -1 | tr -d x)'
lint flag grep-l 'cmd | grep -l x'
lint flag grep-L 'cmd | grep -L x'
lint flag grep-m1 'cmd | grep -m1 x'
lint flag grep-m-1 'cmd | grep -m 1 x'
lint flag grep-quiet 'cmd | grep --quiet x'
lint flag grep-devnull "if cmd | grep -E '\"(hooks|mcpServers)\"' >/dev/null; then :; fi"
lint flag sed-q 'cmd | sed 1q'
lint flag sed-block-q "cmd | sed -n '/x/{p;q;}'"
lint flag awk-exit "cmd | awk '{ print; exit }'"
lint flag read-one 'cmd | read -r first'
lint flag continued 'cmd --flag \' '  | grep -q x'
lint flag trailing-pipe 'cmd |' '  head -n 1'
lint flag pipe-amp 'cmd |& grep -q x'
lint flag env-prefix 'cmd | LC_ALL=C grep -q x'
lint flag full-path 'cmd | /usr/bin/head -1'
lint flag in-function 'f() { cmd | grep -q x; }'
lint flag subshell 'x=$(cmd | (read -r a; echo "$a"))'
lint flag option-after-e 'cmd | grep -e pat -q'
lint flag after-or 'a || b | head -1'
lint pass grep-c 'n=$(cmd | grep -c x)'
lint pass grep-v 'cmd | grep -v x | sort -u'
lint pass sed-range "cmd | sed -n '1,3p'"
lint pass sed-q-in-regex "cmd | sed 's/quote/q/'"
lint pass sh-c 'sh -c "cmd | grep -q x"'
lint pass bash-c "bash -c 'cmd | head -1'"
lint pass waived 'cmd | grep -q x   # pipefail-ok: one line of input'
lint pass heredoc "cat <<'EOF'" 'cmd | head -1' 'EOF' 'echo done'
lint pass noclobber 'cmd 2>|"$err"'
lint pass or-list 'cmd || grep -q x file'
lint pass file-reader 'grep -q x file && head -1 file'
lint pass while-read 'cmd | while read -r l; do :; done'
lint pass comment '# cmd | head -1'
lint pass in-quotes 'echo "a | head -1"'
lint pass stderr-null "cmd | grep -E 'x' 2>/dev/null"
lint pass case-arm 'case "$x" in grep|head) ;; esac'
lint pass arithmetic 'x=$((a | b))'
lint pass e-takes-q 'cmd | grep -e -q file'
# command substitutions inside double quotes, wrapped and quoted command names, long-option prefixes,
# process substitutions, here-document delimiters with other characters, and waivers that are not comments
lint flag dq-subst 'x="$(cmd | head -1)"'
lint flag dq-subst-inner-quote 'x="$(cmd "$a" | head -1)"'
lint flag local-dq 'f() { local v="$(git log | head -1)"; }'
lint flag echo-dq-subst 'echo "$(cmd | grep -m1 x)"'
lint flag dq-backticks 'x="`cmd | head -1`"'
lint flag backslash-cmd 'cmd | \head -1'
lint flag quoted-cmd "cmd | 'grep' -q x"
lint flag gnu-prefixed 'cmd | ghead -1'
lint flag long-prefix 'cmd | grep --qui x'
lint flag if-read 'cmd | if read -r a; then :; fi'
lint flag timeout-head 'cmd | timeout 5 head -1'
lint flag tee-procsub 'cmd | tee >(grep -q x) >/dev/null'
lint flag heredoc-dash-delim "cat <<'END-X'" 'cmd | grep -q y' 'END-X' 'z=$(cmd | head -1)'
lint flag waiver-in-string 'cmd | grep -q "# pipefail-ok: x"'
lint flag waiver-other-stmt 'echo "# pipefail-ok: x"; cmd | head -1'
lint pass regex-in-dbl-bracket '[[ $x =~ grep|head ]] && :'
lint pass dq-plain 'echo "a | head -1 and $(date)"'
lint pass file-option "cmd | grep --file=patterns.txt"
lint pass waived-multiline 'x=$(cmd |' '  head -1)   # pipefail-ok: the first line is all it needs'
for set in 'set -e -o pipefail' 'set -o errexit -o pipefail' 'set -o pipefail -u'; do
  printf '#!/usr/bin/env bash\n%s\ncmd | head -1\n' "$set" > "$T/lint/set-form.sh"
  expect "pipefail: a script that sets '$set' is checked" 1 bash "$ROOT/scripts/check-pipefail.sh" "$T/lint/set-form.sh"
done
printf '#!/usr/bin/env bash\nset -u\ncmd | head -1\n' > "$T/lint/no-pipefail.sh"
expect "pipefail: a script without pipefail is left alone" 0 bash "$ROOT/scripts/check-pipefail.sh" "$T/lint/no-pipefail.sh"
# large input: 20,000 lines with one pipe into head at the end, reported at its own line
{ echo '#!/usr/bin/env bash'; echo 'set -uo pipefail'
  awk 'BEGIN { for (i = 0; i < 20000; i++) printf "echo \"line %05d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\" | grep -c x\n", i }'
  echo 'v=$(cmd | head -1)'; } > "$T/lint/large.sh"
out=$(bash "$ROOT/scripts/check-pipefail.sh" "$T/lint/large.sh" 2>&1)
case "$out" in *"large.sh:20003: a pipe into head"*) pass=$((pass + 1)); echo "PASS pipefail: a 1 MiB script is read to its last line";;
  *) failn=$((failn + 1)); echo "FAIL pipefail: the pipe on the last line of a 1 MiB script was not reported at line 20003"; echo "$out";; esac
expect "pipefail: the CI check scripts and their suites are clean" 0 bash "$ROOT/scripts/check-pipefail.sh" \
  "$ROOT/scripts/check-attribution.sh" "$ROOT/scripts/check-corpus.sh" "$ROOT/scripts/check-frontmatter.sh" \
  "$ROOT/scripts/check-hygiene.sh" "$ROOT/scripts/check-pipefail.sh" "$ROOT/scripts/tob-delta-review.sh" \
  "$ROOT/scripts/tests/test-bundled-paths.sh" "$ROOT/scripts/tests/test-ci-checks.sh" \
  "$ROOT/scripts/tests/test-corpus-pins.sh" "$ROOT/scripts/tests/test-gha-recipes.sh"

# ---- 4. workflows --------------------------------------------------------------------------------------
wfcheck() { # wfcheck FILE -> one line per problem, read byte by byte
  LC_ALL=C awk -v f="$1" -v q="'" '
    # the letter a two-digit hex code names, or \001 for any other code
    function hexchr(h) { h = tolower(h); return (h in letter) ? letter[h] : "\001" }
    # quoted(s, i): the value of the quoted scalar that starts at s[i] (a quote mark), each \x, \u and \U escape
    # of a letter decoded and any other escape read as \001. QEND is the index after its closing quote, or 0
    # when it goes on past the line.
    function quoted(s, i,   c, e, v, j, n, h) {
      c = substr(s, i, 1); v = ""; j = i + 1; QEND = 0
      while (j <= length(s)) {
        e = substr(s, j, 1)
        if (c == q) {
          if (e != q) { v = v e; j++; continue }
          if (substr(s, j + 1, 1) == q) { v = v q; j += 2; continue }
          QEND = j + 1; return v
        }
        if (e == "\"") { QEND = j + 1; return v }
        if (e != "\\") { v = v e; j++; continue }
        e = substr(s, j + 1, 1); n = 0
        if (e == "x") n = 2; else if (e == "u") n = 4; else if (e == "U") n = 8
        h = substr(s, j + 2, n)
        if (n && length(h) == n && h ~ /^[0-9A-Fa-f]+$/ && substr(h, 1, n - 2) ~ /^0*$/) v = v hexchr(substr(h, n - 1))
        else v = v "\001"
        j += 2 + n
      }
      return v
    }
    # keyat(s, i): the key that may start at s[i], after any tag and anchor: an explicit ? key, an alias, or a
    # key YAML reads as on (or On, ON) that is quoted, escaped, tagged or anchored, or in another letter case
    function keyat(s, i,   props, v, j, w, c) {
      if (substr(s, i, 1) == "?" && (i == length(s) || substr(s, i + 1, 1) ~ /[ \t]/)) {
        print f ": an explicit ? key; write each key plainly: " s; return }
      props = 0
      while (substr(s, i, 1) == "!" || substr(s, i, 1) == "&") {
        props = 1
        while (i <= length(s) && substr(s, i, 1) !~ /[ \t]/) i++
        while (substr(s, i, 1) ~ /[ \t]/) i++
      }
      if (substr(s, i, 1) == "*") {
        j = i; while (j <= length(s) && substr(s, j, 1) !~ /[ \t]/) j++
        while (substr(s, j, 1) ~ /[ \t]/) j++
        if (substr(s, j, 1) == ":") print f ": an alias as a key; write each key plainly: " s
        return
      }
      if (substr(s, i, 1) == "\"" || substr(s, i, 1) == q) {
        v = quoted(s, i); if (!QEND) return
        j = QEND; while (substr(s, j, 1) ~ /[ \t]/) j++
        if (substr(s, j, 1) == ":" && tolower(v) == "on") print f ": the on key is quoted; write it as plain on: " s
        return
      }
      w = substr(s, i)
      if (!match(w, /^[^ \t:,{}]+[ \t]*:/)) return
      c = substr(w, RLENGTH + 1, 1)
      if (c != "" && c != " " && c != "\t" && c != "," && c != "}" && c != "]") return
      w = substr(w, 1, RLENGTH); sub(/[ \t]*:$/, "", w)
      if (index(w, "[") || index(w, "]") || tolower(w) != "on") return
      if (props) print f ": the on key has a tag or an anchor; write it as plain on: " s
      else if (w != "on") print f ": the on key is in another letter case; write it as plain on: " s
    }
    # keys(s): every key on the line s: the first, after any - of a sequence, and each after a { [ or , outside
    # a quoted scalar and before a comment
    function keys(s,   i, j, c) {
      i = 1
      while (substr(s, i, 1) ~ /[ \t]/) i++
      while (substr(s, i, 1) == "-" && substr(s, i + 1, 1) ~ /[ \t]/) { i += 2; while (substr(s, i, 1) ~ /[ \t]/) i++ }
      keyat(s, i)
      for (; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "\"" || c == q) { quoted(s, i); if (!QEND) return; i = QEND - 1; continue }
        if (c == "#" && (i == 1 || substr(s, i - 1, 1) ~ /[ \t]/)) return
        if (c == "{" || c == "[" || c == ",") { j = i + 1; while (substr(s, j, 1) ~ /[ \t]/) j++; keyat(s, j) }
      }
    }
    BEGIN { sha = "[0-9a-f]"; for (i = 1; i < 40; i++) sha = sha "[0-9a-f]"
      for (i = 65; i <= 122; i++) if (i <= 90 || i >= 97) letter[sprintf("%02x", i)] = sprintf("%c", i) }
    # the keys of every line outside a block scalar (| or >) and a comment line; the first line without a BOM
    { line = $0; if (NR == 1) sub(/^\357\273\277/, "", line); inside = 0 }
    blk { match(line, /^[ \t]*/)
      if (line ~ /^[ \t]*$/) inside = 1
      else if (contind < 0 && RLENGTH > blkind) { contind = RLENGTH; inside = 1 }
      else if (contind >= 0 && RLENGTH >= contind) inside = 1
      else blk = 0 }
    !inside && line !~ /^[ \t]*#/ { keys(line)
      if (line ~ /(^|[ \t:])[|>][-+0-9]*[ \t]*(#.*)?$/) { match(line, /^[ \t]*(-[ \t]+)*/); blkind = RLENGTH; contind = -1; blk = 1 } }
    /^permissions:/ { if ($0 !~ /^permissions:[ \t]*$/) print f ": permissions is not a block"; perm = 1; next }
    perm == 1 && /^  [^ ]/ { if ($0 !~ /^  contents: read[ \t]*$/) print f ": permissions grants more than contents: read"; next }
    perm == 1 { perm = 2 }
    # a job may narrow nothing further than contents: read either
    /^    permissions:/ { if ($0 !~ /^    permissions:[ \t]*$/) print f ": job " job " permissions is not a block"; jperm = 1; next }
    jperm && /^      [^ ]/ { if ($0 !~ /^      contents: read[ \t]*$/) print f ": job " job " permissions grants more than contents: read"; next }
    jperm { jperm = 0 }
    { t = $0; sub(/^[ \t]*#.*/, "", t) }
    t ~ /(^|[^A-Za-z0-9_])(pull_request_target|workflow_run)([^A-Za-z0-9_]|$)/ {
      print f ": runs on pull_request_target or workflow_run" }
    # run: scripts, one-line or block: an expression there is pasted into the script before it runs
    inrun { match($0, /^[ \t]*/); if (RLENGTH > runind || $0 ~ /^[ \t]*$/) { if (index($0, "${{")) print f ": ${{ }} inside a run: script"; next } inrun = 0 }
    /^[ \t]*(- )?run:/ { match($0, /^[ \t]*(- )?/); runind = RLENGTH; inrun = 1; if (index($0, "${{")) print f ": ${{ }} inside a run: script"; next }
    /^jobs:/ { injobs = 1; next }
    injobs && /^  [A-Za-z0-9_-]+:[ \t]*$/ { if (job != "" && !to) print f ": job " job " has no timeout-minutes"
      job = $1; sub(/:$/, "", job); to = 0; next }
    injobs && /^    timeout-minutes:[ \t]*[1-9][0-9]*[ \t]*$/ { to = 1 }
    /^[ \t-]*uses:/ { if ($0 !~ ("uses:[ \t]*[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@" sha "[ \t]+#[ \t]*v[0-9]"))
      print f ": action not pinned by full SHA with a version comment: " $0 }
    /^[ \t-]*uses:[ \t]*actions\/checkout@/ { co++ }
    /^[ \t]*persist-credentials:[ \t]*false[ \t]*$/ { pc++ }
    END { if (job != "" && !to) print f ": job " job " has no timeout-minutes"
      if (perm == 0) print f ": no top-level permissions"
      if (co != pc) print f ": " co " checkout(s) but " pc + 0 " persist-credentials: false" }' "$1"
}
n=$(grep -c '^    name: counts, index, version, hygiene$' "$ROOT/.github/workflows/corpus-check.yml")
if [ "$n" = 1 ]; then pass=$((pass + 1)); echo "PASS workflows: the required job is still named 'counts, index, version, hygiene'"
else failn=$((failn + 1)); echo "FAIL workflows: corpus-check.yml has $n jobs named 'counts, index, version, hygiene', want 1"; fi
for wf in "$ROOT"/.github/workflows/*.yml; do
  probs=$(wfcheck "$wf")
  if [ -z "$probs" ]; then pass=$((pass + 1)); echo "PASS workflows: ${wf##*/} reads contents only, times out, pins actions, drops credentials"
  else failn=$((failn + 1)); echo "FAIL workflows: ${wf##*/}"; echo "$probs"; fi
done
# the checker itself: a job with no timeout, an action pinned by tag, and a checkout that keeps credentials;
# then a workflow on pull_request_target whose job writes contents and pastes the PR title into a script
printf 'name: x\non: push\npermissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n' \
  > "$T/bad-workflow.yml"
probs=$(wfcheck "$T/bad-workflow.yml")
case "$probs" in *"permissions grants more"*"pinned by full SHA"*"no timeout-minutes"*"1 checkout(s) but 0"*)
    pass=$((pass + 1)); echo "PASS workflows: the checker flags a bad workflow on every count";;
  *) failn=$((failn + 1)); echo "FAIL workflows: the checker missed problems in a bad workflow"; echo "$probs";; esac
{ printf 'name: x\non: pull_request_target\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n'
  printf '    timeout-minutes: 5\n    permissions:\n      contents: write\n      id-token: write\n    steps:\n'
  printf '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n'
  printf '          persist-credentials: false\n      - run: echo "${{ github.event.pull_request.title }}"\n'
  printf '      - name: block\n        run: |\n          echo one\n          echo "${{ github.head_ref }}"\n'
} > "$T/bad-workflow-2.yml"
probs=$(wfcheck "$T/bad-workflow-2.yml")
case "$probs" in *"job a permissions grants more"*"pull_request_target or workflow_run"*|*"pull_request_target or workflow_run"*"job a permissions grants more"*)
    case "$probs" in *'${{ }} inside a run: script'*'${{ }} inside a run: script'*)
        pass=$((pass + 1)); echo "PASS workflows: the checker flags job permissions, the trigger and both scripts";;
      *) failn=$((failn + 1)); echo "FAIL workflows: the checker missed a \${{ }} in a run: script"; echo "$probs";; esac;;
  *) failn=$((failn + 1)); echo "FAIL workflows: the checker missed job permissions or the trigger"; echo "$probs";; esac
trig() { # trig WANT NAME LINE...  — a workflow whose trigger is LINE...; the checker must WANT (flag|pass) it
  local want=$1 name=$2 got=pass; shift 2
  { echo 'name: x'; printf '%s\n' "$@"; printf 'permissions:\n  contents: read\n'; } > "$T/trigger-$name.yml"
  case "$(wfcheck "$T/trigger-$name.yml")" in *"pull_request_target or workflow_run"*) got=flag;; esac
  if [ "$got" = "$want" ]; then pass=$((pass + 1)); echo "PASS workflows: the trigger check gives $want on $name"
  else failn=$((failn + 1)); echo "FAIL workflows: the trigger check gives $got on $name, want $want"; fi
}
trig flag double-quoted-on '"on": [pull_request_target]'
trig flag single-quoted-on "'on': workflow_run"
trig flag flow-mapping 'on:' '  pull_request_target: {types: [opened]}'
trig flag trailing-comment 'on:' '  workflow_run:   # after the build' '    workflows: [build]'
trig flag double-quoted-key 'on:' '  "pull_request_target":' '    types: [opened]'
trig flag single-quoted-item 'on:' "  - 'workflow_run'"
trig flag space-before-colon 'on : pull_request_target'
trig flag null-value 'on:' '  pull_request_target: null'
trig flag tilde-value 'on:' '  workflow_run: ~'
trig flag empty-list-value 'on:' '  pull_request_target: []'
trig flag alias 'on:' '  workflow_dispatch: &t' '  workflow_run: *t'
trig flag wrapped-flow-list 'on: [push,' '  pull_request_target,' '  workflow_dispatch]'
trig flag json-style '{"on": {"pull_request_target": {}}}'
trig flag explicit-key 'on:' '  ? pull_request_target' '  : {types: [opened]}'
trig flag bom "$(printf '\357\273\277on: workflow_run')"
trig pass comment-line '# no job here starts on pull_request_target or workflow_run' 'on: push'
trig pass quoted-on-other-events '"on": [push, pull_request]'
# The trigger key is plain on: only. A key YAML reads as on in any other spelling fails whatever its events,
# and so does an explicit ? key or an alias as a key.
onkey() { # onkey WANT NAME LINE...  — a workflow that starts with LINE...; the checker must WANT (flag|pass) its keys
  local want=$1 name=$2 got=pass; shift 2
  { printf '%s\n' "$@"; printf 'permissions:\n  contents: read\n'; } > "$T/onkey-$name.yml"
  case "$(wfcheck "$T/onkey-$name.yml")" in *"the on key is "*|*"the on key has "*|*"an explicit ? key"*|*"an alias as a key"*) got=flag;; esac
  if [ "$got" = "$want" ]; then pass=$((pass + 1)); echo "PASS workflows: the on-key check gives $want on $name"
  else failn=$((failn + 1)); echo "FAIL workflows: the on-key check gives $got on $name, want $want"; wfcheck "$T/onkey-$name.yml"; fi
}
onkey flag double-quoted '"on": push'
onkey flag single-quoted "'on': push"
onkey flag space-before-colon '"on" : push'
onkey flag tab-before-colon "$(printf '"on"\t: push')"
onkey flag block-value "'on':" '  push:' '    branches: [main]'
onkey flag hex-escape '"o\x6e": push'
onkey flag hex-escapes-upper '"\x6F\x6E": push'
onkey flag unicode-escape '"on": push'
onkey flag long-unicode-escape '"o\U0000006E": push'
onkey flag quoted-other-case '"On": push'
onkey flag plain-other-case 'ON: push'
onkey flag json-style '{"name": "x", "on": "push", "permissions": {"contents": "read"}}'
onkey flag flow-lines '{' '  "name": "x",' "  'on': push" '}'
onkey flag flow-plain-tagged '{name: x, !!str on: push}'
onkey flag in-sequence '- "on": push'
onkey flag explicit-quoted '? "on"' ': push'
onkey flag explicit-plain '? on' ': push'
onkey flag explicit-continued '? "o\' '  n"' ': push'
onkey flag tag-quoted '!!str "on": push'
onkey flag tag-plain '!!str on: push'
onkey flag verbatim-tag "!<tag:yaml.org,2002:str> 'on': push"
onkey flag anchor '&k "on": push'
onkey flag anchor-plain '&k on: push'
onkey flag alias 'events: &k on' '*k : push'
onkey flag bom "$(printf '\357\273\277"on": push')"
onkey flag trailing-comment "'on': push   # the trigger"
onkey pass plain 'on: push'
onkey pass plain-block 'on:' '  push:' '    branches: [main]'
onkey pass quoted-value 'on: "push"'
onkey pass quoted-other-key 'on: push' '"env": {"A": "on"}'
onkey pass in-block-scalar 'on: push' 'jobs:' '  a:' '    steps:' '      - run: |' "          echo '\"on\": x'" "          echo 'on': x" \
  '        shell: bash'
onkey pass in-quoted-value 'on: push' "x: 'jq ''{\"on\": 1}'''"
onkey pass in-comment '# "on": push' 'on: push   # "on": too'
onkey pass value-on 'on: push' 'x: [a, on]'

# ---- 5. check-hygiene.sh ------------------------------------------------------------------------------
HYG="$ROOT/scripts/check-hygiene.sh"
hyrepo() { # hyrepo NAME PATH...  — a repo tracking the script, the real manifests and each PATH as an empty file
  # put straight into the index, so paths in other letter cases stay apart on any file system
  local d="$T/hy/$1" e p; shift
  mkdir -p "$d/scripts" "$d/.claude-plugin" && git -C "$d" init -q && cp "$HYG" "$d/scripts/check-hygiene.sh" \
    && cp "$ROOT/.claude-plugin/plugin.json" "$ROOT/.claude-plugin/marketplace.json" "$d/.claude-plugin/" \
    && git -C "$d" add scripts .claude-plugin && e=$(git -C "$d" hash-object -w --stdin < /dev/null) || return
  for p in "$@"; do git -C "$d" update-index --add --cacheinfo "100644,$e,$p"; done
}
hyrun() { # hyrun NAME WANT  — the check in repo NAME must WANT (pass|fail)
  local got=pass
  out=$(bash "$T/hy/$1/scripts/check-hygiene.sh" 2>&1) || got=fail
  if [ "$got" = "$2" ]; then pass=$((pass + 1)); echo "PASS hygiene $2: $1"; if [ -n "${VERBOSE:-}" ]; then echo "$out"; fi
  else failn=$((failn + 1)); echo "FAIL hygiene $1: got $got, want $2"; echo "$out"; fi
}
hy() { local name=$1 want=$2; shift 2; hyrepo "$name" "$@"; hyrun "$name" "$want"; }   # hy NAME WANT PATH...
hysaid() { # hysaid TEXT  — the last hy output holds TEXT
  case "$out" in *"$1"*) pass=$((pass + 1)); echo "PASS hygiene: ... $1";;
    *) failn=$((failn + 1)); echo "FAIL hygiene: the output lacks: $1"; echo "$out";; esac
}
expect "hygiene: the repository passes" 0 bash "$HYG"
hy clean pass
hy lower-case-dirs pass agents/a.md commands/c.md skills/s/SKILL.md docs/Agents/x.md
for d in Agents COMMANDS Skills Hooks BIN Monitors .Claude-Plugin; do hy "case-$d" fail "$d/x.md"; done
hy case-both fail agents/a.md Agents/b.md; hysaid "Agents/: name it agents/"
hy env fail .env; hy env-example pass .env.example; hy ds-store fail docs/.DS_Store; hy vendor-env pass vendor/x/.env
hy per-user fail .claude/settings.json; hy per-user-case fail .Claude/settings.json; hy cursor-case fail .CURSOR/rules
mkdir -p "$T/hy-nogit/scripts" && cp "$HYG" "$T/hy-nogit/scripts/"
expect "hygiene: outside a checkout fails" 2 bash "$T/hy-nogit/scripts/check-hygiene.sh"
# large input: 3,000 tracked paths, over 64 KiB of names, with a top-level directory in another letter case last
hy big pass
e=$(git -C "$T/hy/big" hash-object -w --stdin < /dev/null)
awk -v e="$e" 'BEGIN { for (i = 0; i < 3000; i++) printf "100644 %s\tdocs/many/file-%05d-xxxxxxxxxxxxxxxxxxxxxxxx.md\n", e, i
  printf "100644 %s\tskILLS/s/SKILL.md\n", e }' | git -C "$T/hy/big" update-index --index-info
expect "hygiene: 3,000 tracked paths, a directory in another letter case last" 1 bash "$T/hy/big/scripts/check-hygiene.sh"
case "$out" in *"skILLS/: name it skills/"*) pass=$((pass + 1)); echo "PASS hygiene: ... the last path is read";;
  *) failn=$((failn + 1)); echo "FAIL hygiene: the last of 3,000 paths was not read"; echo "$out";; esac
# load surfaces at the plugin root, in any letter case, and a .claude/ directory below it
for p in hooks/hooks.json monitors/monitors.json bin/git .mcp.json .LSP.json settings.json Settings.Local.JSON \
         docs/.claude/settings.json references/x/.Claude/skills/y/SKILL.md vendor/x/.claude/settings.json \
         .claude-plugin/hooks.json .claude-plugin/Plugin.json; do
  hy "surface-$(printf '%s' "$p" | tr '/' '_')" fail "$p"
done
hysaid "list it in ALLOWED_LOAD_SURFACES"
hy not-surfaces pass docs/hooks/README.md scripts/bin/tool docs/settings.json tools/x/.mcp.json docs/monitors/x.md
# a SKILL.md other than SKILL.md and skills/<name>/SKILL.md, in any letter case: with "skills": "./" in the
# manifest, Claude Code loads <dir>/SKILL.md when the root holds none, and skills/SKILL.md makes skills/ one skill
hy skill-md-places pass SKILL.md skills/a/SKILL.md skills/B-c/SKILL.md docs/SKILL.md.txt docs/skill-md.md
for p in decoy/SKILL.md references/decoy/SKILL.md templates/a/b/SKILL.md skills/SKILL.md skills/a/b/SKILL.md \
         skills/a/skill.md docs/Skill.MD skill.md vendor/x/skills/y/SKILL.md; do
  hy "skill-md-$(printf '%s' "$p" | tr '/' '_')" fail SKILL.md "$p"
done
hysaid "vendor/x/skills/y/SKILL.md: a SKILL.md other than SKILL.md and skills/<name>/SKILL.md"
sed "s#^ALLOWED_LOAD_SURFACES=''\$#ALLOWED_LOAD_SURFACES='templates/a/b/SKILL.md'#" "$ROOT/scripts/check-hygiene.sh" \
  > "$T/hyg-allow-skill.sh"
HYG="$T/hyg-allow-skill.sh"
hy allow-skill-md pass SKILL.md templates/a/b/SKILL.md; hy allow-skill-md-other fail SKILL.md templates/a/c/SKILL.md
HYG="$ROOT/scripts/check-hygiene.sh"
# ALLOWED_LOAD_SURFACES lets a listed path through, in its exact letter case; a path with a space never matches
sed "s#^ALLOWED_LOAD_SURFACES=''\$#ALLOWED_LOAD_SURFACES='hooks/hooks.json .mcp.json hooks/a hooks/b'#" "$ROOT/scripts/check-hygiene.sh" \
  > "$T/hyg-allow.sh"
if [ "$(grep -c "^ALLOWED_LOAD_SURFACES='hooks/hooks.json .mcp.json hooks/a hooks/b'\$" "$T/hyg-allow.sh")" = 1 ]; then
  pass=$((pass + 1)); echo "PASS hygiene: ALLOWED_LOAD_SURFACES is one line to extend"
else failn=$((failn + 1)); echo "FAIL hygiene: no ALLOWED_LOAD_SURFACES='' line in check-hygiene.sh"; fi
HYG="$T/hyg-allow.sh"
hy allow-listed pass hooks/hooks.json .mcp.json; hy allow-another fail hooks/hooks.json hooks/run.sh
hy allow-other-case fail .MCP.json; hy allow-space fail "hooks/a hooks/b"
HYG="$ROOT/scripts/check-hygiene.sh"
# a manifest key beyond the list fails, however it is spelled in the file; a manifest jq cannot read fails
hym() { # hym NAME MANIFEST JSON TEXT  — the check fails on .claude-plugin/MANIFEST holding JSON, saying TEXT
  hyrepo "$1" && printf '%s\n' "$3" > "$T/hy/$1/.claude-plugin/$2" && hyrun "$1" fail && hysaid "$4"
}
hym m-hooks plugin.json '{"name": "auditor", "hooks": "./hooks.json"}' "plugin.json: key 'hooks'"
hym m-escaped plugin.json '{"name": "auditor", "ho\u006fks": {}}' "plugin.json: key 'hooks'"
hym m-monitors plugin.json '{"name": "auditor", "experimental": {"monitors": [{"name": "m", "command": "x"}]}}' \
  "key 'experimental.monitors'"
hym m-mcp plugin.json '{"name": "auditor", "mcpServers": {"s": {"command": "x"}}}' "key 'mcpServers'"
hym m-nested plugin.json '{"name": "auditor", "author": {"name": "a", "hooks": {}}}' "key 'author.hooks'"
hym m-space plugin.json '{"name version": "auditor"}' "key 'name version'"
hym m-entry marketplace.json '{"name": "auditor", "plugins": [{"name": "auditor", "source": ".", "lspServers": {}}]}' \
  "key 'plugins.[].lspServers'"
hym m-root marketplace.json '{"name": "auditor", "metadata": {"pluginRoot": "./x"}, "plugins": []}' "key 'metadata.pluginRoot'"
hym m-broken plugin.json '{"name": ' "plugin.json: jq cannot read it"
# large input: a 1 MiB plugin.json whose last key is hooks
hyrepo m-large && awk 'BEGIN { printf "{\"name\": \"auditor\", \"description\": \""
  for (i = 0; i < 17000; i++) printf "line %05d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx ", i
  print "\", \"hooks\": {}}" }' > "$T/hy/m-large/.claude-plugin/plugin.json"
hyrun m-large fail; hysaid "plugin.json: key 'hooks'"
mkdir -p "$T/nojq"; for t in git tr dirname; do ln -s "$(command -v "$t")" "$T/nojq/$t"; done
hyrepo no-jq; out=$(PATH="$T/nojq" "$BASH" "$T/hy/no-jq/scripts/check-hygiene.sh" 2>&1); got=$?
case "$got:$out" in 1:*"jq is needed"*) pass=$((pass + 1)); echo "PASS hygiene: without jq the manifests fail";;
  *) failn=$((failn + 1)); echo "FAIL hygiene: without jq (rc=$got)"; echo "$out";; esac

# ---- 6. check-entrypoints.sh -------------------------------------------------------------------------
EPC="$ROOT/scripts/check-entrypoints.sh"
expect "entry points: the repository passes" 0 bash "$EPC"
nep=$(grep -c -v -e '^#' -e '^$' "$ROOT/scripts/entrypoints.txt")
case "$out" in *"passed: $nep entry points"*) pass=$((pass + 1)); echo "PASS entry points: ... all $nep read";;
  *) failn=$((failn + 1)); echo "FAIL entry points: the repository's list was not read whole"; echo "$out";; esac
PR='${CLAUDE_PLUGIN_ROOT}'; SD='${CLAUDE_SKILL_DIR}'; RB='tools/auditor-tools/target/release'
eprepo() { # eprepo NAME  — a checkout whose entry points, case files and rules all pass
  local d="$T/ep/$1"
  mkdir -p "$d/scripts/lib" "$d/scripts/tests/fixtures/ok" "$d/scripts/tests/fixtures/rec" "$d/tools/auditor-tools/logs" \
    "$d/commands" "$d/agents" "$d/skills/s" && git -C "$d" init -q && cp "$EPC" "$d/scripts/check-entrypoints.sh" || return
  printf '# shared checks\n' > "$d/scripts/lib/confine.sh"
  printf '#!/bin/bash\nhere=${0%%/*}\n. "$here/lib/confine.sh" || exit 64\n' > "$d/scripts/ok.sh"
  printf '#!/bin/bash\n  . "${here%%/*}/lib/confine.sh" || exit 2\n' > "$d/scripts/tm.sh"
  printf '#!/usr/bin/env -S python3 -I\nimport sys\n' > "$d/scripts/rec.py"
  chmod 755 "$d/scripts/ok.sh" "$d/scripts/tm.sh" "$d/scripts/rec.py"
  printf '# cases\n64\tok: refused: x\t--x\n' > "$d/scripts/tests/fixtures/ok/cases.txt"
  printf '# cases\nno arguments\nan option\t--x\n' > "$d/scripts/tests/fixtures/rec/hostile-args.txt"
  printf '[package]\nname = "t"\n\n[[bin]]\nname = "audit-scan"\npath = "a.rs"\n\n[[bin]]\nname = "audit-mem"\npath = "b.rs"\n' \
    > "$d/tools/auditor-tools/Cargo.toml"
  printf '[package]\nname = "logs"\n\n[[bin]]\nname = "audit-logs"\npath = "main.rs"\n' > "$d/tools/auditor-tools/logs/Cargo.toml"
  { printf '# the list\nscripts/ok.sh\tscripts/tests/fixtures/ok/cases.txt\n'
    printf 'scripts/tm.sh\tscripts/tests/fixtures/ok/cases.txt\t--detect|--offline\n'
    printf 'scripts/rec.py\tscripts/tests/fixtures/rec/hostile-args.txt\n'
    printf '%s/audit-scan\tscripts/tests/fixtures/ok/cases.txt\t--contract=1\n' "$RB"
    printf '%s/audit-mem\tscripts/tests/fixtures/ok/cases.txt\twarm|check --contract=1\n' "$RB"
    printf '%s/audit-logs\tscripts/tests/fixtures/rec/hostile-args.txt\n' "$RB"; } > "$d/scripts/entrypoints.txt"
  { printf -- "---\ndescription: A command.\nallowed-tools:\n  - Read\n  - Edit(audit_*/**)\n  - 'Bash(\"%s/scripts/ok.sh\" *)'\n" "$PR"
    printf -- "  - 'Bash(\"%s/scripts/ok.sh\")'\n  - 'Bash(\"%s/scripts/tm.sh\" --offline *)'\n" "$PR" "$PR"
    printf -- "  - 'Bash(\"%s/%s/audit-scan\" --contract=1 *)'\n  - 'Bash(\"%s/%s/audit-mem\" check --contract=1 --db x.db)'\n" \
      "$PR" "$RB" "$PR" "$RB"
    printf -- "---\n\nBody.\n"; } > "$d/commands/c.md"
  printf -- "---\ndescription: A one-line command.\nallowed-tools: Read, Bash(\"%s/%s/audit-logs\" profile *), Grep\n---\n" "$PR" "$RB" \
    > "$d/commands/one.md"
  printf -- '---\nname: a\ndescription: An agent.\ntools: Read, Grep, Bash\n---\n' > "$d/agents/a.md"
  printf -- "---\nname: s\ndescription: A skill.\nallowed-tools:\n  - 'Bash(\"%s/scripts/rec.py\" *)'\n---\n" "$PR" > "$d/skills/s/SKILL.md"
  printf -- "---\nname: r\ndescription: The root skill.\nallowed-tools:\n  - 'Bash(\"%s/scripts/ok.sh\" new *)'\n---\n" "$SD" > "$d/SKILL.md"
  git -C "$d" add -A
}
eprun() { # eprun NAME WANT-RC TEXT  — the check in checkout NAME exits WANT-RC and says TEXT
  local got
  out=$(bash "$T/ep/$1/scripts/check-entrypoints.sh" 2>&1); got=$?
  case "$got:$out" in "$2:"*"$3"*) pass=$((pass + 1)); echo "PASS entry points: $1 (rc=$got)"; if [ -n "${VERBOSE:-}" ]; then echo "$out"; fi;;
    *) failn=$((failn + 1)); echo "FAIL entry points: $1 (rc=$got, want $2 and '$3')"; echo "$out";; esac
}
ep() { # ep NAME TEXT SETUP  — a good checkout, changed by the shell code SETUP run in it, fails saying TEXT
  if eprepo "$1" && (cd "$T/ep/$1" && eval "$3" && git add -A); then eprun "$1" 1 "$2"
  else failn=$((failn + 1)); echo "FAIL entry points: cannot build the checkout $1"; fi
}
eprepo good && eprun good 0 "passed: 6 entry points, 8 Bash rules"
# the list
ep list-one-field "want <path><TAB><case file>[<TAB><words>], not 1 fields" 'printf "scripts/ok.sh\n" >> scripts/entrypoints.txt'
ep list-four-fields "not 4 fields" 'printf "scripts/x.sh\ta\tb\tc\n" >> scripts/entrypoints.txt'
ep list-absolute "/etc/x.sh is not a relative path" 'printf "/etc/x.sh\tscripts/tests/fixtures/ok/cases.txt\n" >> scripts/entrypoints.txt'
ep list-dotdot "scripts/../x.sh has an empty, . or .. component" \
  'printf "scripts/../x.sh\tscripts/tests/fixtures/ok/cases.txt\n" >> scripts/entrypoints.txt'
ep list-twice "scripts/ok.sh is listed twice (first at line 2)" 'printf "scripts/ok.sh\tscripts/tests/fixtures/ok/cases.txt\n" >> scripts/entrypoints.txt'
ep list-words-star "the words for scripts/ok.sh are not words" \
  'awk -F"\t" -v OFS="\t" "\$1 == \"scripts/ok.sh\" { \$3 = \"new *\" } { print }" scripts/entrypoints.txt > l && mv l scripts/entrypoints.txt'
ep list-trailing-tab "the words for scripts/ok.sh are not words" \
  'awk "\$1 == \"scripts/ok.sh\" { \$0 = \$0 \"\t\" } { print }" scripts/entrypoints.txt > l && mv l scripts/entrypoints.txt'
ep list-empty "lists no entry point" 'printf "# nothing\n" > scripts/entrypoints.txt'
# each entry point
ep script-untracked "scripts/ok.sh is not a tracked file" 'git rm -q --cached scripts/ok.sh && printf "scripts/ok.sh\n" > .git/info/exclude'
ep script-mode "scripts/ok.sh is mode 100644 in the index, not 100755" 'chmod 644 scripts/ok.sh'
ep script-link "scripts/ok.sh is mode 120000 in the index, not 100755" 'mv scripts/ok.sh scripts/real.sh && ln -s real.sh scripts/ok.sh'
ep script-env-bash "scripts/ok.sh starts with '#!/usr/bin/env bash', not #!/bin/bash" \
  'printf "#!/usr/bin/env bash\n. \"\$here/lib/confine.sh\"\n" > scripts/ok.sh'
ep script-env-python "scripts/rec.py starts with '#!/usr/bin/env python3', not #!/bin/bash" 'printf "#!/usr/bin/env python3\n" > scripts/rec.py'
ep script-crlf "scripts/ok.sh starts with" 'printf "#!/bin/bash\r\n. \"\$here/lib/confine.sh\"\n" > scripts/ok.sh'
ep script-no-confine "scripts/ok.sh does not source scripts/lib/confine.sh" 'printf "#!/bin/bash\n# . \"\$here/lib/confine.sh\"\n" > scripts/ok.sh'
ep script-elsewhere "bin/x.sh is not under scripts/, templates/ or tools/auditor-tools/target/release/" \
  'printf "bin/x.sh\tscripts/tests/fixtures/ok/cases.txt\n" >> scripts/entrypoints.txt'
ep bin-undeclared "audit-x is no binary a crate under tools/auditor-tools declares" \
  "printf '%s/audit-x\tscripts/tests/fixtures/ok/cases.txt\n' '$RB' >> scripts/entrypoints.txt"
ep bin-nested "$RB/sub/audit-scan is not tools/auditor-tools/target/release/<binary>" \
  "printf '%s/sub/audit-scan\tscripts/tests/fixtures/ok/cases.txt\n' '$RB' >> scripts/entrypoints.txt"
ep bin-crate-untracked "audit-logs is no binary a crate under tools/auditor-tools declares" \
  'git rm -q --cached tools/auditor-tools/logs/Cargo.toml && printf "logs/\n" > .git/info/exclude'
ep cases-untracked "the case file scripts/tests/fixtures/rec/hostile-args.txt is not a tracked file" \
  'git rm -q --cached scripts/tests/fixtures/rec/hostile-args.txt && printf "*.txt\n" > .git/info/exclude'
ep cases-empty "the case file scripts/tests/fixtures/rec/hostile-args.txt holds no case" \
  'printf "# only comments\n\n" > scripts/tests/fixtures/rec/hostile-args.txt'
ep cases-no-status "the case file scripts/tests/fixtures/ok/cases.txt: line 3 does not start with an exit status and a tab" \
  'printf "an option\t--x\n" >> scripts/tests/fixtures/ok/cases.txt'
# the allow rules
epcmd() { # epcmd NAME TEXT ENTRY  — the good checkout with the item ENTRY added to commands/c.md's allowed-tools fails saying TEXT
  printf '%s\n' "$3" > "$T/ep-entry"
  ep "$1" "$2" 'awk -v f="$T/ep-entry" "NR == 4 { getline e < f; print \"  - \" e } { print }" commands/c.md > c && mv c commands/c.md'
}
epcmd rule-bare "allowed-tools entry 'Bash' is not Bash(\"\${CLAUDE_PLUGIN_ROOT}/<path>\" ...)" 'Bash'
epcmd rule-catch-all "is not Bash(\"\${CLAUDE_PLUGIN_ROOT}/<path>\"" "'Bash(*)'"
epcmd rule-bash-in-front "is not Bash(\"\${CLAUDE_PLUGIN_ROOT}/<path>\"" "'Bash(bash \"$PR/scripts/ok.sh\" *)'"
epcmd rule-unquoted "is not Bash(\"\${CLAUDE_PLUGIN_ROOT}/<path>\"" "'Bash($PR/scripts/ok.sh *)'"
epcmd rule-half-quoted "is not Bash(\"\${CLAUDE_PLUGIN_ROOT}/<path>\"" "'Bash(\"$PR\"/scripts/ok.sh *)'"
epcmd rule-skill-dir "is not Bash(\"\${CLAUDE_PLUGIN_ROOT}/<path>\"" "'Bash(\"$SD/scripts/ok.sh\" *)'"
epcmd rule-unlisted "names scripts/other.sh, which scripts/entrypoints.txt does not list" "'Bash(\"$PR/scripts/other.sh\" *)'"
epcmd rule-glob "names scripts/*, which scripts/entrypoints.txt does not list" "'Bash(\"$PR/scripts/*\" *)'"
epcmd rule-case "names scripts/OK.sh, which scripts/entrypoints.txt does not list" "'Bash(\"$PR/scripts/OK.sh\" *)'"
epcmd rule-dot "names scripts/./ok.sh, which scripts/entrypoints.txt does not list" "'Bash(\"$PR/scripts/./ok.sh\" *)'"
epcmd rule-no-space "has no space after the quoted path" "'Bash(\"$PR/scripts/ok.sh\"*)'"
epcmd rule-prefix "has no space after the quoted path" "'Bash(\"$PR/scripts/ok.sh\":*)'"
epcmd rule-unclosed "does not close the quoted path" "'Bash(\"$PR/scripts/ok.sh *)'"
epcmd rule-star-inside "the word '*' holds a character other than" "'Bash(\"$PR/scripts/ok.sh\" * --x)'"
epcmd rule-dollar "the word '\$HOME' holds a character other than" "'Bash(\"$PR/scripts/ok.sh\" \$HOME *)'"
epcmd rule-quoted-word "holds a character other than" "'Bash(\"$PR/scripts/ok.sh\" \"\"x\"\" *)'"
epcmd rule-two-spaces "has an empty word" "'Bash(\"$PR/scripts/ok.sh\"  *)'"
epcmd rule-scan-no-marker "does not start with '--contract=1' after the path" "'Bash(\"$PR/$RB/audit-scan\" *)'"
epcmd rule-scan-late-marker "does not start with '--contract=1' after the path" "'Bash(\"$PR/$RB/audit-scan\" . --contract=1 *)'"
epcmd rule-mem-no-marker "does not start with 'warm|check --contract=1' after the path" "'Bash(\"$PR/$RB/audit-mem\" warm *)'"
epcmd rule-mem-other "does not start with 'warm|check --contract=1' after the path" "'Bash(\"$PR/$RB/audit-mem\" rule --contract=1 *)'"
epcmd rule-mem-any "does not start with 'warm|check --contract=1' after the path" "'Bash(\"$PR/$RB/audit-mem\" *)'"
epcmd rule-collector-any "does not start with '--detect|--offline' after the path" "'Bash(\"$PR/scripts/tm.sh\" *)'"
epcmd rule-collector-network "does not start with '--detect|--offline' after the path" "'Bash(\"$PR/scripts/tm.sh\" --network *)'"
ep rule-control "holds a tab, a control character or a byte outside printable ASCII" \
  "printf -- \"---\ndescription: A command.\nallowed-tools:\n  - 'Bash(\\\"%s/scripts/ok.sh\\\" \\033 *)'\n---\n\" '$PR' > commands/esc.md"
ep rule-one-line "commands/one.md:3: allowed-tools entry 'Bash(bash" \
  "sed 's#Bash(\"#Bash(bash \"#' commands/one.md > o && mv o commands/one.md"
ep rule-skill "skills/s/SKILL.md:5: allowed-tools entry" "sed 's#/scripts/rec.py#/scripts/gone.py#' skills/s/SKILL.md > s && mv s skills/s/SKILL.md"
ep rule-root-plugin-root "SKILL.md:5: allowed-tools entry 'Bash(\"\${CLAUDE_PLUGIN_ROOT}/scripts/ok.sh\" new *)' is not Bash(\"\${CLAUDE_SKILL_DIR}/<path>\"" \
  "sed 's#CLAUDE_SKILL_DIR#CLAUDE_PLUGIN_ROOT#' SKILL.md > s && mv s SKILL.md"
ep rule-agent "agents/a.md:4: the agent tools entry 'Bash(git log *)' is a Bash rule" \
  "sed 's#^tools: .*#tools: Read, Bash(git log *)#' agents/a.md > a && mv a agents/a.md"
ep rule-nested-command "commands/sub/n.md:4: allowed-tools entry 'Bash'" \
  "mkdir commands/sub && printf -- '---\ndescription: N.\nallowed-tools:\n  - Bash\n---\n' > commands/sub/n.md"
# every listed entry point is pre-approved somewhere
ep unapproved "scripts/rec.py is listed, but no command, skill or root SKILL.md rule pre-approves it" 'rm skills/s/SKILL.md'
# large input: a list of 3,000 comment lines, over 64 KiB, whose one bad line is last
ep list-large "scripts/entrypoints.txt:3008: want <path><TAB><case file>[<TAB><words>], not 1 fields" \
  'awk "BEGIN { for (i = 0; i < 3000; i++) printf \"# comment line %05d of a long list, padded out to fill it up\n\", i }" >> scripts/entrypoints.txt && printf "scripts/ok.sh\n" >> scripts/entrypoints.txt'
# cannot run: outside a checkout, or with no list
mkdir -p "$T/ep-nogit/scripts" && cp "$EPC" "$T/ep-nogit/scripts/" && printf 'scripts/ok.sh\tx\n' > "$T/ep-nogit/scripts/entrypoints.txt"
expect "entry points: outside a checkout fails" 2 bash "$T/ep-nogit/scripts/check-entrypoints.sh"
if eprepo no-list && rm "$T/ep/no-list/scripts/entrypoints.txt"; then eprun no-list 2 "scripts/entrypoints.txt is not a file"
else failn=$((failn + 1)); echo "FAIL entry points: cannot build the checkout no-list"; fi

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
