#!/usr/bin/env bash
# test-ci-checks.sh — fixture tests for the CI checks that have no suite of their own:
#   1. scripts/check-attribution.sh flags a trailer in a commit message of 1 MiB as well as a short one,
#      and fails on a range git cannot read or one that holds no commits;
#   2. scripts/check-frontmatter.sh passes every real command, agent and SKILL.md and the shapes they use,
#      and fails each case below where Claude Code would read a field differently from what is written;
#   3. scripts/check-pipefail.sh flags each pipe into a reader that can stop early in a script under
#      pipefail, and leaves quoted text, here-documents, waived lines and scripts without pipefail alone.
#      The check scripts, and the suites that test them, must pass it here; CI runs it over every tracked
#      *.sh file;
#   4. .github/workflows: the required job keeps its name, every workflow reads contents only, every job has
#      timeout-minutes, every action is pinned by full SHA with its version, and no checkout keeps credentials.
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
fm skill/SKILL.md pass "name: s" 'description: "A skill."'
fm skill-no-name/SKILL.md fail 'description: "A skill."'
fm skills/agents/SKILL.md pass "name: a" 'description: "A skill in a directory named agents."'
fm skills/forked/SKILL.md fail "name: f" 'description: "A forked skill."' "context: fork"
fm skills/with-tools/SKILL.md fail "name: t" 'description: "A skill."' "allowed-tools: Read"
# with no arguments the check reads every .md at any depth under commands/ and agents/ (dotfiles too),
# the root SKILL.md, and every SKILL.md under skills/, in any letter case; a .MD name fails
lay="$T/layout"; mkdir -p "$lay/scripts" "$lay/commands/sub" "$lay/agents/deep/er" "$lay/skills/s" "$lay/skills/t/u"
cp "$ROOT/scripts/check-frontmatter.sh" "$lay/scripts/"
good_c() { printf -- '---\n%s\n%s\n---\n' "$C" "allowed-tools: Read" > "$1"; }
good_a() { printf -- '---\n%s\n%s\n%s\n---\n' "$N" "$D" "$TL" > "$1"; }
good_s() { printf -- '---\n%s\n%s\n---\n' "name: s" 'description: "A skill."' > "$1"; }
bad_fm() { printf -- '---\n%s\n%s\n%s\n---\n' "$N" "description: Ends with ---" "$TL" > "$1"; }
good_c "$lay/commands/c.md"; good_a "$lay/agents/a.md"; good_s "$lay/SKILL.md"
bad_fm "$lay/commands/sub/nested.md"; bad_fm "$lay/agents/deep/er/deeper.md"; bad_fm "$lay/agents/.hidden.md"
bad_fm "$lay/skills/s/SKILL.md"; bad_fm "$lay/skills/t/u/skill.md"; good_c "$lay/commands/Upper.MD"
expect "frontmatter: with no arguments, nested, hidden, lower-case and .MD files are read too" 1 bash "$lay/scripts/check-frontmatter.sh"
for want in "commands/sub/nested.md:3: --- inside" "agents/deep/er/deeper.md:3: --- inside" "agents/.hidden.md:3: --- inside" \
            "skills/s/SKILL.md:3: --- inside" "skills/t/u/skill.md:3: --- inside" "commands/Upper.MD: name the file with a lowercase .md"; do
  case "$out" in *"$want"*) pass=$((pass + 1)); echo "PASS frontmatter: ... $want";;
    *) failn=$((failn + 1)); echo "FAIL frontmatter: the default list missed: $want"; echo "$out";; esac
done
good_c "$lay/commands/sub/nested.md"; good_a "$lay/agents/deep/er/deeper.md"; good_a "$lay/agents/.hidden.md"
good_s "$lay/skills/s/SKILL.md"; good_s "$lay/skills/t/u/skill.md"; mv "$lay/commands/Upper.MD" "$lay/commands/upper.md"
expect "frontmatter: with no arguments, every kind of file passes once fixed" 0 bash "$lay/scripts/check-frontmatter.sh"
case "$out" in *"passed: 9 files"*) pass=$((pass + 1)); echo "PASS frontmatter: ... 9 files read";;
  *) failn=$((failn + 1)); echo "FAIL frontmatter: the default list did not read 9 files"; echo "$out";; esac
fm other/notes.md fail "$N" "$D"
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
for all in 'Bash(*)' 'Bash( * )' 'Bash(:*)' 'Bash(**)'; do
  printf -- '---\n%s\n%s\n---\n' "$C" "allowed-tools: Read, $all" > "$T/fm/commands/catch-all.md"
  expect "frontmatter, with Bash forbidden: $all fails" 1 bash "$T/fm-no-bash.sh" "$T/fm/commands/catch-all.md"
done
expect "frontmatter, with Bash forbidden: Bash(\"\${CLAUDE_PLUGIN_ROOT}/…\" *) items pass" 0 bash "$T/fm-no-bash.sh" \
  "$T/fm/commands/plugin-root-items.md"
# large input: a 300 KB description and a 1 MiB body read whole by every awk; a --- near the description's end
long=$(awk 'BEGIN { for (i = 0; i < 10000; i++) printf "word%05d and more text here, ", i }')
fm agents/long-description.md pass "$N" "description: ${long}end." "$TL" "$M"
awk 'BEGIN { for (i = 0; i < 17000; i++) printf "body line %05d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", i }' \
  >> "$T/fm/agents/long-description.md"
fmrun agents/long-description.md pass
fm agents/long-dashes.md fail "$N" "description: ${long}then --- end." "$TL" "$M"

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
wfcheck() { # wfcheck FILE -> one line per problem
  awk -v f="$1" 'BEGIN { sha = "[0-9a-f]"; for (i = 1; i < 40; i++) sha = sha "[0-9a-f]" }
    /^permissions:/ { if ($0 !~ /^permissions:[ \t]*$/) print f ": permissions is not a block"; perm = 1; next }
    perm == 1 && /^  [^ ]/ { if ($0 !~ /^  contents: read[ \t]*$/) print f ": permissions grants more than contents: read"; next }
    perm == 1 { perm = 2 }
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
# the checker itself: a job with no timeout, an action pinned by tag, and a checkout that keeps credentials
printf 'name: x\non: push\npermissions:\n  contents: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n' \
  > "$T/bad-workflow.yml"
probs=$(wfcheck "$T/bad-workflow.yml")
case "$probs" in *"permissions grants more"*"pinned by full SHA"*"no timeout-minutes"*"1 checkout(s) but 0"*)
    pass=$((pass + 1)); echo "PASS workflows: the checker flags a bad workflow on every count";;
  *) failn=$((failn + 1)); echo "FAIL workflows: the checker missed problems in a bad workflow"; echo "$probs";; esac

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
