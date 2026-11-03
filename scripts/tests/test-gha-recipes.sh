#!/usr/bin/env bash
# test-gha-recipes.sh — run the GitHub Actions recipes exactly as written against the fixture workflows in
# scripts/tests/fixtures/gha/ and the infrastructure files in its infra/, and check that each recipe flags exactly
# the expected fixtures:
#   R1–R9    discovery/grep-commands.md, section "GitHub Actions (CI trigger trust)";
#   K116-1   KV-116 Step 1 (AI-agent steps);
#   K139-1   KV-139 Step 1 (externally triggerable workflows);
#   K140-6   KV-140 Step 6 (Actions cache writers and restorers);
#   K140-7a  KV-140 Step 7, first command (places that trust GitHub's OIDC issuer);
#   K140-7b  KV-140 Step 7, second command (the subjects and claims trust policies bind);
#   K080-3   KV-080 Step 3 (echo lines that print a secret);
#   K080-6   KV-080 Step 6 (third-party actions, reusable workflows and docker:// images);
#   K080-8a  KV-080 Step 8, first command (jobs on runners GitHub does not host);
#   K080-8b  KV-080 Step 8, second command (runner registrations and runner-group settings).
# A recipe of two commands (R1) flags what the first lists and the second does not; every other line of an R
# recipe must be an echo of a quoted marker, which the suite does not run. The suite also checks that every
# known-vector step that repeats an R recipe carries its lines byte for byte, as one block in the same order,
# and that no recipe flags a fixture's comment lines. R3, R7, R8, R9 and the KV-080 Steps 6 and 8 and KV-140 Step 7
# commands are also checked line by line on their own fixtures, R3 and KV-080 Steps 3 and 6 on trees of their own
# as well, and those that search outside .github/ skip node_modules/ and .terraform/. Every pattern a recipe
# (KV-080 Step 4's first command among them, K080-4a) gives grep must stay inside what GNU grep's DFA runs in a
# UTF-8 locale and hold no backslash inside a bracket, and in a grep call that holds * or + every pattern must
# start at ^. It runs R1 and K139-1 over trigger spellings built at run time (CRLF line ends among them), R1 over
# file names that hold a space or a quote and over decoy names that hold a newline, with the find that the R1 note
# and KV-080 Step 7 give, the R8 note's and KV-116 Step 1's listing over a call neither reads, and R1 over large
# inputs: 2,000 workflows, and two of about 1 MiB. R9 and KV-080 Step 8's first command run over 2,000 workflows,
# and each KV-080 and KV-140 command that pipes into head over more than 64 KiB of its own output. KV-080 Step 4's
# two commands run over pins saved with CRLF line ends, over references R9 does not read as pins, over uses: lines
# whose trailing comment names a pin or a local action, and over comment lines that hold a lone CR or U+2028, which
# end a YAML line but not grep's: each uses: line lands in exactly one of them. Every
# command of every recipe, K080-4a included, must end within 30 s, in a UTF-8 locale where one is installed, on
# files that hold one 1 MiB line of near misses. KV-020 Step 3 and KV-100 Step 4, which list documentation files
# with one recursive grep as R1 does, run over file names that hold a space or a quote, and KV-100's over more than
# 64 KiB of names. Known limits' git listing for the commands that search the whole tree runs over a repository
# that tracks files Claude Code's grep skips.
#
# Usage (from the repo root): bash scripts/tests/test-gha-recipes.sh
# Needs bash >= 3.2, grep, awk, git. No network. The fixtures are copied into a temp dir as .github/workflows/, those
# under actions/ as .github/actions/<name>/action.yml, and those under infra/ as infra/, for the run; nothing is
# written under the repository's own .github/.
set -uo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
doc="$root/discovery/grep-commands.md"
kv="$root/known-vectors"
fixtures="$root/scripts/tests/fixtures/gha"

work=$(mktemp -d "${TMPDIR:-/tmp}/gha-recipes.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT

# install_fixtures <fixture dir> <tree>: the workflows (.yml and .yaml) into <tree>/.github/workflows/, each
# composite action in <fixture dir>/actions/ as <tree>/.github/actions/<name>/action.yml, and the
# infrastructure files in <fixture dir>/infra/ into <tree>/infra/.
install_fixtures() {
  local a n
  mkdir -p "$2/.github/workflows" && cp "$1"/*.yml "$1"/*.yaml "$2/.github/workflows/" || return 1
  for a in "$1"/actions/*.yml; do
    n=${a##*/}; n=${n%.yml}
    mkdir -p "$2/.github/actions/$n" && cp "$a" "$2/.github/actions/$n/action.yml" || return 1
  done
  mkdir -p "$2/infra" && cp "$1"/infra/* "$2/infra/" || return 1
}
install_fixtures "$fixtures" "$work" || exit 1

# The command lines of the code block that follows the "# Rn — …" comment inside the GitHub Actions section of
# the doc.
recipe() {
  awk -v id="$1" '
    /^## GitHub Actions \(CI trigger trust\)/ { sec = 1; next }
    sec && /^## / { exit }
    sec && index($0, "# " id " ") == 1 { grab = 1; next }
    sec && grab && /^```/ { exit }
    sec && grab && /^grep / { print }
  ' "$doc"
}

# Every line of that code block after the comment, the grep lines and any other.
recipe_block() {
  awk -v id="$1" '
    /^## GitHub Actions \(CI trigger trust\)/ { sec = 1; next }
    sec && /^## / { exit }
    sec && index($0, "# " id " ") == 1 { grab = 1; next }
    sec && grab && /^```/ { exit }
    sec && grab { print }
  ' "$doc"
}

# The `grep` lines inside a known vector's "**Step <n>:" block, in order.
kv_step() { # kv_step <vector file> <step>
  awk -v n="$2" '
    index($0, "**Step " n ":") == 1 { s = 1; next }
    s && /^\*\*Step / { exit }
    s && /^grep / { print }
  ' "$kv/$1"
}

# Every line inside the code blocks of that step, in order.
kv_block() { # kv_block <vector file> <step>
  awk -v n="$2" '
    index($0, "**Step " n ":") == 1 { s = 1; next }
    s && /^\*\*Step / { exit }
    s && /^```/ { code = !code; next }
    s && code { print }
  ' "$kv/$1"
}

# Every line of that step outside its code blocks: its bullets.
kv_text() { # kv_text <vector file> <step>
  awk -v n="$2" '
    index($0, "**Step " n ":") == 1 { s = 1; next }
    s && /^\*\*Step / { exit }
    s && /^```/ { code = !code; next }
    s && !code { print }
  ' "$kv/$1"
}

# The note under recipe <id>: the first line that starts with "> " after its code block.
recipe_note() {
  awk -v id="$1" '
    /^## GitHub Actions \(CI trigger trust\)/ { sec = 1; next }
    sec && /^## / { exit }
    sec && index($0, "# " id " ") == 1 { grab = 1; next }
    sec && grab == 1 && /^```/ { grab = 2; next }
    sec && grab == 2 && /^> / { print; exit }
  ' "$doc"
}

# spans <prefix>: each code span (`…`) on standard input that starts with <prefix>, without its backticks.
spans() {
  awk -v p="$1" '{
    s = $0
    while ((i = index(s, "`")) > 0) {
      s = substr(s, i + 1); j = index(s, "`"); if (j == 0) break
      t = substr(s, 1, j - 1); s = substr(s, j + 1)
      if (index(t, p) == 1) print t
    } }'
}

KV080=080-ci-cd-pipeline-injection.md
KV116=116-ai-coding-agent-ci-deploy-key.md
KV139=139-comment-triggered-workflow-author-gating.md
KV140=140-workflow-run-pwn-request-artifact-cache-poisoning.md

# Recipes that live only in a known vector (<id> <vector file> <step> <n>): the step's <n>-th grep line.
KV_RECIPES="K116-1 $KV116 1 1
K139-1 $KV139 1 1
K140-6 $KV140 6 1
K140-7a $KV140 7 1
K140-7b $KV140 7 2
K080-3 $KV080 3 1
K080-4a $KV080 4 1
K080-6 $KV080 6 1
K080-8a $KV080 8 1
K080-8b $KV080 8 2"

# Known-vector steps that repeat an R recipe (<id> <vector file> <step>).
COPIES="R1 $KV080 7
R2 $KV139 3
R3 $KV139 4
R4 $KV140 4
R5 $KV140 5
R7 $KV080 2
R7 $KV140 2
R9 $KV080 4"

IDS="R1 R2 R3 R4 R5 R6 R7 R8 R9 K116-1 K139-1 K140-6 K140-7a K140-7b K080-3 K080-6 K080-8a K080-8b"

# Fixtures each recipe must flag (their two- or three-digit prefixes, ascending). Anything else is a mismatch.
expected() {
  case "$1" in
    R1) echo "01 08 10 16 40 55 56 58 64 65 66 69 108" ;;
    R2) echo "02 04" ;;
    R3) echo "03 12 13 17 25 26 27 28 46 47 48 49 74 104" ;;
    R4) echo "05 06 21 29 30 41" ;;
    R5) echo "06 07 15" ;;
    R6) echo "05 07 08 14 15 16 20 31 32 50 75 105" ;;
    R7) echo "05 07 11 12 15 18 19 20 21 22 23 24 51 52 53 61 62 63 70 71 102 103 105" ;;
    R8) echo "01 08 11 14 33 34 54 57 67 68 72 73 108" ;;
    R9) echo "01 05 07 08 11 12 15 18 19 20 21 22 23 24 35 36 38 39 42 43 44 45 51 52 53 60 61 62 63 70 71 76 98 107" ;;
    K116-1) echo "01 08 11 14 33 34 54 57 67 68 72 73 108" ;;
    K139-1) echo "01 02 03 04 08 10 11 14 16 17 22 23 25 26 33 40 48 49 53 55 56 58 59 62 64 65 66 69 71 74 104 108" ;;
    K140-6) echo "35 36 37 38 39 42 43 44 45" ;;
    K140-7a) echo "80 81 82 83 84 85 93 95 96 97 101" ;;
    K140-7b) echo "80 82 83 84 85 93 95 96 97 101" ;;
    K080-3) echo "" ;;   # no fixture echoes a secret; the tree of its own below does
    K080-6) echo "01 08 14 33 35 37 39 42 43 44 60 76 77 98 107" ;;
    K080-8a) echo "78 98 100 106 109" ;;
    K080-8b) echo "86 87 88 89 90 94" ;;
  esac
}

# The lines each recipe must flag in its own fixtures (<id> <fixture> <line>...); its other fixtures are listed
# whole in expected(), and its near misses are in neither.
LINES="R3 104-denylist-spellings.yml 11 16 21 26 31 36 41
R7 102-input-and-matrix-ref.yml 19 29
R7 actions/103-input-ref-composite-action.yml 13
R7 105-index-syntax-refs.yml 20 30 37 38
R8 108-agent-option-backslash.yml 14
R9 76-pin-forms.yml 11 12 13 14 16 17 19
R9 98-pin-and-runner-yaml-extension.yaml 11
R9 107-pin-key-spellings.yml 14 15
K080-6 76-pin-forms.yml 12 13 14 16 17 19
K080-6 77-pin-near-misses.yml 11 12 13
K080-6 107-pin-key-spellings.yml 12 13 14 15
K080-8a 78-self-hosted-runners.yml 9 13 17 23 27 34
K080-8a 98-pin-and-runner-yaml-extension.yaml 9
K080-8a 100-arc-runner-labels.yml 9 13 17 21 25 29 33
K080-8a 106-runner-key-spellings.yml 10 14 18 22
K080-8a 109-retired-runner-label.yml 9 13 17
K080-8b infra/86-runner-group-public.tf 2 5
K080-8b infra/87-arc-runner-deployment.yaml 11
K080-8b infra/88-arc-scale-set-values.yml 4
K080-8b infra/89-runner-module.hcl 7
K080-8b infra/90-runner-register.sh 3 5
K080-8b infra/94-runner-group.tf.json 3 7
K140-7a infra/80-oidc-aws-repo-wildcard.tf 7 11 16
K140-7a infra/81-oidc-aws-audience-only.json 7 10
K140-7a infra/82-oidc-azure-environment.tf 7
K140-7a infra/83-oidc-gcp-owner.tf 13
K140-7a infra/84-oidc-vault-workflow.tf 4 5
K140-7a infra/85-oidc-cloudformation-default-branch.yaml 11 14 15
K140-7a infra/93-oidc-aws-any-repository.json 7 10 11
K140-7a infra/95-oidc-terragrunt.hcl 7
K140-7a infra/96-oidc-pulumi.yml 12 15
K140-7a infra/97-oidc-provider.sh 4
K140-7a infra/101-oidc-immutable-subject.tf 9 13
K140-7b infra/80-oidc-aws-repo-wildcard.tf 17
K140-7b infra/82-oidc-azure-environment.tf 8 14
K140-7b infra/83-oidc-gcp-owner.tf 11 20 26
K140-7b infra/84-oidc-vault-workflow.tf 14 15
K140-7b infra/85-oidc-cloudformation-default-branch.yaml 15
K140-7b infra/93-oidc-aws-any-repository.json 11
K140-7b infra/95-oidc-terragrunt.hcl 8
K140-7b infra/96-oidc-pulumi.yml 15
K140-7b infra/97-oidc-provider.sh 6
K140-7b infra/101-oidc-immutable-subject.tf 14 25"

# The command lines of recipe <id>.
recipe_lines() {
  local i file step n
  case "$1" in
    R*) recipe "$1" ;;
    *) while read -r i file step n; do
         if [ "$i" = "$1" ]; then kv_step "$file" "$step" | sed -n "${n}p"; fi
       done <<< "$KV_RECIPES" ;;
  esac
}

# run_recipe <tree> <command lines>: what the recipe flags in <tree>. One command: what it prints. Two: the
# lines the first prints that the second does not.
run_recipe() {
  local first second
  { IFS= read -r first; IFS= read -r second; } <<< "$2"
  if [ -z "$second" ]; then
    (cd "$1" && eval "$first" </dev/null 2>/dev/null)
    return
  fi
  (cd "$1" && eval "$second" </dev/null 2>/dev/null) > "$work/second.out"
  (cd "$1" && eval "$first" </dev/null 2>/dev/null) \
    | awk -v f="$work/second.out" 'BEGIN { while ((getline l < f) > 0) seen[l] = 1 } !($0 in seen)'
}

# within <seconds> <tree> <command> [<locale>]: run the command in <tree>, under LC_ALL=<locale> when one is given,
# its output in $work/within.out. Fails, and stops the command, when it is still running after <seconds>.
within() {
  local pid i=0
  (cd "$2" && if [ -n "${4-}" ]; then export LC_ALL="$4"; fi &&
    eval "exec $3" </dev/null > "$work/within.out" 2>/dev/null) &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$i" -ge "$(($1 * 10))" ]; then kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 1; fi
    sleep 0.1; i=$((i + 1))
  done
  wait "$pid" 2>/dev/null
  return 0
}

# same_files <command lines>: the two commands take the same --include options and the same root, so a file
# leaves the first list only by matching the second.
same_files() {
  local first second
  { IFS= read -r first; IFS= read -r second; } <<< "$1"
  [ "${first##* }" = "${second##* }" ] && [ "$(printf '%s\n' "$first" | grep -oE -- "--include='[^']*'")" = \
    "$(printf '%s\n' "$second" | grep -oE -- "--include='[^']*'")" ]
}

# The fixture prefixes (two or three digits) in a recipe's output, in ascending order, on one line. A recipe
# rooted at . prints its paths after ./.
prefixes() {
  sed -E 's#^\./##; s#^(\.github/(workflows|actions)|infra)/##; s#^([0-9][0-9][0-9]?)-.*#\1#' | sort -n -u | tr '\n' ' ' \
    | sed 's/ $//'
}

fail=0; nrec=0
check() { # check <id> <command lines>
  local n=0 l
  nrec=$((nrec + 1))
  if [ -z "$2" ]; then
    echo "FAIL $1: no recipe line found"
    fail=1
    return
  fi
  while IFS= read -r l; do n=$((n + 1)); done <<< "$2"
  if [ "$n" -gt 2 ]; then
    echo "FAIL $1: $n command lines; a recipe has one or two"
    fail=1
    return
  fi
  if [ "$n" -eq 2 ] && ! same_files "$2"; then
    echo "FAIL $1: its two commands search different files (--include options or root)"
    fail=1
    return
  fi
  case "$1" in R*)
    bad=$(recipe_block "$1" | grep -v -e '^grep ' -e "^echo '[^'\$]*'\$" -e '^$')
    if [ -n "$bad" ]; then echo "FAIL $1: a line that is neither a grep call nor an echo of a quoted marker: $bad"; fail=1; return; fi ;;
  esac
  got=$(run_recipe "$work" "$2" | prefixes)
  want=$(expected "$1")
  if [ "$got" = "$want" ]; then
    echo "ok   $1: $got"
  else
    echo "FAIL $1: got [$got] want [$want]"
    fail=1
  fi
}

for id in $IDS; do
  check "$id" "$(recipe_lines "$id")"
done

# Line by line: in each fixture LINES names, the recipe flags exactly the lines listed, so every spelling and
# every alternative of its pattern has a line of its own that it must reach.
nlines=0
while read -r id fx want; do
  nlines=$((nlines + 1))
  case "$fx" in
    infra/*) path=$fx ;;
    actions/*) path=${fx#actions/}; path=.github/actions/${path%.yml}/action.yml ;;
    *) path=.github/workflows/$fx ;;
  esac
  got=$(run_recipe "$work" "$(recipe_lines "$id")" | sed 's#^\./##' | awk -F: -v p="$path" '$1 == p { print $2 }' \
    | sort -n | tr '\n' ' ' | sed 's/ $//')
  if [ "$got" = "$want" ]; then echo "ok   $id in $fx: lines $got"
  else echo "FAIL $id in $fx: got lines [$got] want [$want]"; fail=1; fi
done <<< "$LINES"
# R3 lists a string deny-list whatever its string holds before the association names, a backslash or a letter
# outside ASCII included, and reads contains in any letter case, as GitHub reads a function name: a string
# deny-list, a negated fromJSON list and an actor substring test, each spelled with capitals (a tree of its own,
# so the fixtures' expected lists stay as they are).
r3t="$work/r3-strings"; mkdir -p "$r3t/.github/workflows"
printf '%s\n' 'on: issue_comment' 'jobs:' '  a:' "    if: \${{ !contains('\\OWNER', github.event.comment.author_association) }}" \
  '  b:' "    if: \${{ !contains('$(printf '\303\251') OWNER MEMBER', github.event.comment.author_association) }}" \
  '  c:' "    if: \${{ !CONTAINS('NONE,FIRST_TIMER', github.event.comment.author_association) }}" \
  '  d:' "    if: \${{ !Contains(fromJSON('[\"NONE\"]'), github.event.comment.author_association) }}" \
  '  e:' "    if: \${{ CONTAINS(github.actor, 'dependabot') }}" > "$r3t/.github/workflows/strings.yml"
nlines=$((nlines + 1))
got=$(run_recipe "$r3t" "$(recipe_lines R3)" | sed 's#^\./##' | awk -F: '{ print $2 }' | sort -n | tr '\n' ' ' | sed 's/ $//')
if [ "$got" = "4 6 8 10 12" ]; then
  echo "ok   R3 in a string deny-list holding a backslash or a letter outside ASCII, and in contains in capitals: lines $got"
else
  echo "FAIL R3 in a string deny-list holding a backslash or a letter outside ASCII, or in contains in capitals: got" \
    "lines [$got] want [4 6 8 10 12]"
  fail=1
fi
# KV-080 Step 3 lists an echo line that reads secrets in an expression, as a field, an index or the whole context,
# whatever the expression holds before it (a } of its own included), and one that names a variable whose name holds
# SECRET, TOKEN or KEY, braced or not and digits included; not an echo of another context or variable.
k3="$work/k080-3"; mkdir -p "$k3/.github/workflows"
printf '%s\n' 'on: push' 'jobs:' '  a:' '    runs-on: ubuntu-latest' '    steps:' \
  '      - run: echo "${{ secrets.NPM_TOKEN }}"' "      - run: echo \"\${{ format('{0}', secrets.DEPLOY_KEY) }}\"" \
  "      - run: echo '\${{ toJSON(secrets) }}'" "      - run: echo \"\${{ secrets['NPM_TOKEN'] }}\"" \
  '      - run: echo $DEPLOY_KEY' '      - run: echo "${API_TOKEN}"' '      - run: echo "$AWS_S3_SECRET"' \
  '      - run: echo "${{ github.sha }}" "$HOME"' > "$k3/.github/workflows/echo.yml"
nlines=$((nlines + 1))
got=$(run_recipe "$k3" "$(recipe_lines K080-3)" | awk -F: '{ print $2 }' | sort -n | tr '\n' ' ' | sed 's/ $//')
if [ "$got" = "6 7 8 9 10 11 12" ]; then echo "ok   K080-3 in its echo lines: lines $got"
else echo "FAIL K080-3 in its echo lines: got lines [$got] want [6 7 8 9 10 11 12]"; fail=1; fi
# KV-080 Step 6 lists each uses: in a workflow or a composite action that names neither actions/ nor github/ nor a
# local action: an owner whose name starts with actions, a path below another owner's actions/, a docker:// image, a
# reusable workflow, and a reference whose trailing comment names an official action. A uses: after another key of a
# { } mapping is listed whatever it names, and a commented-out one is not. A line of a flow sequence whose first uses:
# names an official or a local action is left out only when nothing but }, ], commas, blanks or a comment follows it,
# so a second entry on that line is listed. In a file saved with CRLF line ends a third-party uses: is listed on every
# grep, and an official one too under GNU and BSD grep, where the CR is not the end of the line.
k6="$work/k080-6"; mkdir -p "$k6/.github/workflows" "$k6/.github/actions/setup"
printf '%s\n' 'on: push' 'jobs:' '  a:' '    runs-on: ubuntu-latest' '    steps:' \
  '      - uses: actions/checkout@v4' '      - uses: github/codeql-action/init@v3' \
  "      - uses: 'actions/setup-node@v4'" '      - uses: ./.github/actions/setup' \
  '      - uses: example/act@v1' '      - uses: actions-rs/toolchain@v1' \
  '      - uses: example/actions/sub@v1' '      - uses: docker://alpine:3.20' \
  '      - uses: example/act@main # uses: actions/checkout@v4' '      - { name: x, uses: actions/checkout@v4 }' \
  '      # - uses: example/retired@v1' '  b:' '    uses: example/repo/.github/workflows/w.yml@v1' '  c:' \
  '    uses: ./.github/workflows/local.yml' '  d:' '    runs-on: ubuntu-latest' '    steps: [' \
  '      {uses: actions/checkout@v4}, {uses: example/flow-after-official@v1},' \
  '      {uses: ./.github/actions/setup}, {uses: example/flow-after-local@main},' \
  '      {uses: actions/cache@v4},' '      { uses: "github/codeql-action/analyze@v3" },' \
  '      {uses: actions/upload-artifact@v4}, # {uses: example/commented@v1}' '      {run: echo hi}' '    ]' \
  '  e:' '    runs-on: ubuntu-latest' '    steps:' '      - uses: actions/checkout@v4 # example/named@v1' \
  > "$k6/.github/workflows/third-party.yml"
printf '%s\r\n' 'on: push' 'jobs:' '  a:' '    runs-on: ubuntu-latest' '    steps:' '      - uses: actions/checkout@v4' \
  '      - uses: example/crlf@v1' > "$k6/.github/workflows/crlf.yml"
printf '%s\n' 'runs:' '  using: composite' '  steps:' '    - uses: example/composite-dep@v2' \
  '    - uses: actions/cache@v4' > "$k6/.github/actions/setup/action.yml"
nlines=$((nlines + 1))
got=$(run_recipe "$k6" "$(recipe_lines K080-6)" | sed 's#^\.github/##' | awk -F: '{ print $1 ":" $2 }' \
  | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')
want=""
for n in 10 11 12 13 14 15 18 24 25; do want="$want workflows/third-party.yml:$n"; done
case "$got" in
  "actions/setup/action.yml:4 workflows/crlf.yml:6 workflows/crlf.yml:7$want" | \
  "actions/setup/action.yml:4 workflows/crlf.yml:7$want") echo "ok   K080-6 in its uses: lines: $got" ;;
  *) echo "FAIL K080-6 in its uses: lines: got [$got] want [actions/setup/action.yml:4 workflows/crlf.yml:6" \
       "workflows/crlf.yml:7$want] (crlf.yml:6, an official action, is listed under GNU and BSD grep only)"
     fail=1 ;;
esac

# Linear by construction. In a UTF-8 locale GNU grep decides a line in one pass of its DFA only when the pattern
# holds nothing the DFA leaves undecided: a negated bracket such as [^#], a class such as [[:space:]], a range
# other than digits (A-Z), an equivalence class, a back-reference, a word anchor, or a letter in a bracket under -i.
# With one of them, every line that may match goes to its regex matcher, which starts again at each position of the
# line, and one long line takes minutes. So every pattern a recipe gives grep stays out of that list, and holds no
# backslash inside a bracket, which Claude Code's grep (ugrep) reads as an escape. Claude Code's grep has a slow path
# of its own: it tries a pattern that holds * or + and does not start at ^ again from every position of a line, and
# so every pattern of a grep call in which one pattern does not start at ^ (R3 took 60 s on the 1 MiB line below
# with one such pattern beside ten that start at ^, 0.2 s without it). So in a grep call where a pattern holds * or
# +, every pattern starts at ^ and keeps each | inside a group (^.*(a|b), not ^a|b).
patterns_of() { # patterns_of <command line>: "<1 under -i, else 0> <pattern>" for each pattern of each grep it runs,
  # on standard output and, one file per grep call, in $work/inv/
  : > "$work/patterns"; rm -rf "$work/inv"; mkdir -p "$work/inv"
  (
    grep() {
      local a ic=0 next=0 found=0 f
      f=$(mktemp "$work/inv/g.XXXXXX") || return 1
      for a in "$@"; do case "$a" in --*) ;; -*i*) ic=1 ;; esac; done
      for a in "$@"; do
        if [ "$next" -eq 1 ]; then printf '%s %s\n' "$ic" "$a" | tee -a "$f" >> "$work/patterns"; next=0; found=1; continue; fi
        case "$a" in
          -e) next=1 ;;
          -*) ;;
          *) if [ "$found" -eq 0 ]; then printf '%s %s\n' "$ic" "$a" | tee -a "$f" >> "$work/patterns"; found=1; fi ;;
        esac
      done
    }
    eval "$1" </dev/null >/dev/null 2>&1
  )
  cat "$work/patterns"
}
one_pass() { # one_pass <file of one grep call's "<ic> <pattern>" lines>: why Claude Code's grep would retry it, if it would
  LC_ALL=C awk '
    function scan(s,   n, i, c, j, e, depth) {
      star = 0; bar = 0; depth = 0; n = length(s); i = 1
      while (i <= n) {
        c = substr(s, i, 1)
        if (c == "\\") { i += 2; continue }
        if (c == "[") {
          j = i + 1
          if (substr(s, j, 1) == "^") j++
          if (substr(s, j, 1) == "]") j++
          while (j <= n && substr(s, j, 1) != "]") {
            if (substr(s, j, 1) == "[" && index(":.=", substr(s, j + 1, 1)) > 0) {
              e = index(substr(s, j + 2), substr(s, j + 1, 1) "]")
              if (e == 0) { j = n; break }
              j += e + 3; continue
            }
            j++
          }
          i = j + 1; continue
        }
        if (c == "(") depth++
        else if (c == ")") depth--
        else if (c == "|" && depth == 0) bar = 1
        else if (c == "*" || c == "+") star = 1
        else if (c == "{") { e = index(substr(s, i), "}"); if (e > 2 && substr(s, i + e - 2, 1) == ",") star = 1 }
        i++
      }
    }
    { p[NR] = substr($0, 3); scan(p[NR]); bars[NR] = bar; if (star) any = 1 }
    END {
      if (!any) exit
      for (k = 1; k <= NR; k++) {
        if (substr(p[k], 1, 1) != "^") { print "a pattern that does not start at ^, in a grep that holds * or +: " substr(p[k], 1, 100); exit }
        if (bars[k]) { print "a | outside every group, in a grep that holds * or +: " substr(p[k], 1, 100); exit }
      }
    }' "$1"
}
outside_dfa() { # each "<ic> <pattern>" line on stdin that holds a construct outside the subset, with the reason
  LC_ALL=C awk -v esc="wWsSbB<>\`'" '
    { ic = substr($0, 1, 1); p = substr($0, 3); n = length(p); i = 1; why = ""
      while (i <= n && why == "") {
        c = substr(p, i, 1)
        if (c == "\\") {
          d = substr(p, i + 1, 1)
          if (d ~ /[123456789]/) why = "a back-reference"
          else if (d != "" && index(esc, d)) why = "the escape \\" d
          i += 2; continue
        }
        if (c != "[") { i++; continue }
        j = i + 1
        if (substr(p, j, 1) == "^") { why = "a negated bracket"; break }
        first = j
        while (j <= n) {
          d = substr(p, j, 1)
          if (d == "]" && j > first) break
          if (d == "[" && index(":.=", substr(p, j + 1, 1))) { why = "a class in a bracket"; break }
          if (d == "\\") { why = "a backslash in a bracket"; break }
          if (d == "-" && j > first && substr(p, j + 1, 1) != "]") { why = "a range in a bracket"; break }
          if (d > "~") { why = "a byte outside ASCII in a bracket"; break }
          if (ic == "1" && index("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", d)) {
            why = "a letter in a bracket under -i"; break
          }
          j++
        }
        if (why == "" && j > n) why = "an unclosed bracket"
        i = j + 1
      }
      if (why != "") print why ": " substr(p, 1, 100)
    }'
}
nlinear=0; nonlinear=""
for id in $IDS K080-4a; do
  cmds=$(recipe_lines "$id")
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    pats=$(patterns_of "$c")
    bad=$(printf '%s\n' "$pats" | outside_dfa)
    if [ -z "$pats" ]; then bad="no pattern found"; fi
    if [ -z "$bad" ]; then
      for g in "$work/inv"/g.*; do
        if [ -f "$g" ]; then bad=$(one_pass "$g"); fi
        if [ -n "$bad" ]; then break; fi
      done
    fi
    if [ -n "$bad" ]; then nonlinear="$nonlinear $id"; echo "FAIL $id: $(printf '%s\n' "$bad" | sed -n 1p)"; fail=1; fi
  done <<< "$cmds"
  nlinear=$((nlinear + 1))
done
if [ -z "$nonlinear" ]; then
  echo "ok   $nlinear recipes, KV-080 Step 4's first command among them, use only patterns GNU grep's DFA runs" \
    "in a UTF-8 locale, and each grep call that holds * or + starts every pattern at ^"
fi

# The commands that search the whole tree skip node_modules/ and .terraform/, which hold dependencies and
# downloaded modules rather than the repository's own settings.
excl="$work/excluded"; mkdir -p "$excl/node_modules/runner" "$excl/.terraform/modules/oidc" "$excl/infra" || exit 1
for d in node_modules/runner .terraform/modules/oidc infra; do
  printf 'allows_public_repositories = true\nidentifiers = ["token.actions.githubusercontent.com"]\nvalues = ["repo:example/app:*"]\n' \
    > "$excl/$d/main.tf"
done
for id in K080-8b K140-7a K140-7b; do
  got=$(run_recipe "$excl" "$(recipe_lines "$id")" | sed 's#^\./##; s#:.*##' | sort -u | tr '\n' ' ')
  if [ "$got" = "infra/main.tf " ]; then echo "ok   $id skips node_modules/ and .terraform/"
  else echo "FAIL $id outside node_modules/ and .terraform/: got [$got] want [infra/main.tf ]"; fail=1; fi
done

# A copy is the recipe's code lines as one run of whole lines, in order. The step may hold other commands
# around a recipe of one command; a recipe of two is the whole code of its step, so "the first" and "the second"
# name the same lines in both files.
nl='
'
ncopy=0
while read -r id file step; do
  ncopy=$((ncopy + 1))
  want=$(recipe_block "$id")
  have=$(kv_block "$file" "$step")
  same=0
  case "$nl$have$nl" in *"$nl$want$nl"*) same=1 ;; esac
  if [ -z "$(recipe "$id")" ]; then same=0; fi
  if [ "$(recipe "$id" | wc -l | tr -d ' ')" -gt 1 ] && [ "$have" != "$want" ]; then same=0; fi
  if [ "$same" -eq 1 ]; then
    echo "ok   copy of $id in $file step $step"
  else
    echo "FAIL copy of $id in $file step $step differs from discovery/grep-commands.md"
    fail=1
  fi
done <<< "$COPIES"

# The negative controls must stay silent for every recipe, except that R9 lists every full-SHA pin, and fixture
# 60 pins its checkout the way DEP-067 asks, and KV-080 Step 6 lists every third-party action, and fixture 60 uses one.
for id in $IDS; do
  for neg in 09 60; do
    case "$id:$neg" in R9:60|K080-6:60) continue ;; esac
    case " $(expected "$id") " in *" $neg "*) echo "FAIL $id: negative control $neg is expected"; fail=1 ;; esac
  done
done

# Every expected hit comes from a workflow or infrastructure line: no recipe flags the fixtures' comment lines
# on their own.
mkdir -p "$work/comment-lines/actions" "$work/comment-lines/infra"
for f in "$fixtures"/*.yml "$fixtures"/*.yaml "$fixtures"/actions/*.yml "$fixtures"/infra/*; do
  sed -n '/^[[:space:]]*#/p' "$f" > "$work/comment-lines/${f#"$fixtures"/}"
done
install_fixtures "$work/comment-lines" "$work/comments" || exit 1
quiet=1
for id in $IDS; do
  got=$(run_recipe "$work/comments" "$(recipe_lines "$id")" | prefixes)
  if [ -n "$got" ]; then echo "FAIL $id: flags the comment lines of fixtures [$got]"; quiet=0; fail=1; fi
done
if [ "$quiet" -eq 1 ]; then echo "ok   no recipe flags the comment lines of a fixture"; fi

# File names that hold a space, a single quote or a double quote: R1 flags each ungated workflow among them and
# drops none, and the three gated ones, named the same way, stay out.
names="$work/names"; mkdir -p "$names/.github/workflows"
for n in "a space.yml" "b it's.yml" 'c say "hi".yml' "d plain.yml"; do
  printf 'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n' > "$names/.github/workflows/$n"
done
for n in "e gated space.yml" "f gated it's.yml" 'g gated "x".yml'; do
  printf 'on: issue_comment\njobs:\n  a:\n    if: github.event.comment.author_association == %sOWNER%s\n' "'" "'" \
    > "$names/.github/workflows/$n"
done
got=$(run_recipe "$names" "$(recipe R1)" | sed 's#^\.github/workflows/##' | sort | tr '\n' '|')
want='a space.yml|b it'"'"'s.yml|c say "hi".yml|d plain.yml|'
if [ "$got" = "$want" ]; then
  echo "ok   R1 on file names with a space or a quote: the four ungated workflows flagged, the three gated ones not"
else
  echo "FAIL R1 on file names with a space or a quote: got [$got] want [$want]"
  fail=1
fi

# A name that holds a newline prints as two lines. A decoy directory named zz.yml, a newline and .github, holding
# workflows/evil.yml that mentions author_association, puts .github/workflows/evil.yml into R1's second list, and the
# real, ungated workflow of that path drops out of R1 with no other sign. A directory and a workflow named around the
# marker line print a copy of the marker inside the first list. So the R1 note and KV-080 Step 7 run a find for names
# that hold a control character every time: that find, read from each of them, must name both decoys.
forge="$work/forge"; mkdir -p "$forge/.github/workflows"
printf 'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n' > "$forge/.github/workflows/evil.yml"
decoy="$forge/.github/zz.yml
.github/workflows"
forged="$work/forged"; mkdir -p "$forged/.github/workflows"
printf 'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n' > "$forged/.github/workflows/open.yml"
mdir="$forged/.github/a
second list: files under .github"
marker='second list: files under .github/ that mention author_association'
if mkdir -p "$decoy" "$mdir" 2>/dev/null; then
  printf 'x: github.event.comment.author_association\n' > "$decoy/evil.yml"
  printf 'on: issue_comment\n' > "$mdir/ that mention author_association
zz.yml"
  got=$(run_recipe "$forge" "$(recipe R1)" | tr '\n' '|')
  nmark=$( (cd "$forged" && eval "$(recipe_block R1)" </dev/null 2>/dev/null) | grep -c -x -F "$marker")
  if [ -z "$got" ] && [ "$nmark" = 2 ]; then
    echo "ok   R1 loses an ungated workflow to a decoy name holding a newline, and another decoy prints the marker twice"
  else
    echo "FAIL R1 newline-name decoys: R1 listed [$got] (want none: the decoy forges it), the block printed the marker" \
      "$nmark time(s) (want 2)"
    fail=1
  fi
  for src in R1 KV-080-7; do
    case "$src" in
      R1) f=$(recipe_note R1 | spans 'find ') ;;
      *) f=$(kv_text "$KV080" 7 | spans 'find ') ;;
    esac
    n1=$( (cd "$forge" && eval "$f" </dev/null 2>/dev/null) | grep -c '^\.github/zz\.yml$')
    n2=$( (cd "$forged" && eval "$f" </dev/null 2>/dev/null) | grep -c '^\.github/a$')
    if [ -n "$f" ] && [ "$(printf '%s\n' "$f" | wc -l | tr -d ' ')" = 1 ] && [ "$n1" = 1 ] && [ "$n2" -ge 1 ]; then
      echo "ok   the find $src gives names both decoys"
    else
      echo "FAIL $src: its find [${f:-none}] named the decoys $n1 and $n2 time(s) (want 1 and at least 1)"
      fail=1
    fi
  done
else
  echo "SKIP R1 newline-name decoys: this file system refuses a newline in a name"
fi

# An option value that holds a character outside ASCII before -p hides an agent call from R8 (a bracket that held one
# would leave GNU grep's DFA), and from KV-116 Step 1, so R8's note and that step give a plain listing of every
# claude and gemini call. That listing, read from each, must list such a call.
LISTINGS="R8 K116-1"
agent="$work/agent"; mkdir -p "$agent/.github/workflows"
printf 'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n' > "$agent/.github/workflows/agent.yml"
printf '      - run: claude --append-system-prompt "r\303\251ponds en fran\303\247ais" -p "fix it"\n' \
  >> "$agent/.github/workflows/agent.yml"
for src in $LISTINGS; do
  case "$src" in
    K116-1) c=$(kv_text "$KV116" 1 | spans 'grep ') ;;
    *) c=$(recipe_note "$src" | spans 'grep ') ;;
  esac
  got=$( (cd "$agent" && eval "$c" </dev/null 2>/dev/null) | cut -d: -f1,2)
  if [ -n "$c" ] && [ "$(printf '%s\n' "$c" | wc -l | tr -d ' ')" = 1 ] && [ "$got" = .github/workflows/agent.yml:6 ]; then
    echo "ok   the listing that goes with $src lists an agent call whose option value holds a character outside ASCII"
  else
    echo "FAIL $src: the listing that goes with it [${c:-none}] listed [$got], want [.github/workflows/agent.yml:6]"
    fail=1
  fi
done

# Claude Code's grep skips a file an ignore rule names and a file it reads as binary, so Known limits compares, for
# KV-140 Step 7 and KV-080 Step 8's second command, what git tracks with what grep reads. Its grep searches the files
# those commands search, its git listing takes the same globs and leaves out each directory the grep's --exclude-dir
# options skip, at any depth, and the bullets of those two steps give the same git listing. Run as written in a
# repository that tracks a file holding a byte outside UTF-8, one an ignore rule names, and files under node_modules/
# and a nested .terraform/, the git listing names the first two and none of the others.
kl=$(awk '/^## GitHub Actions \(CI trigger trust\)/ { sec = 1; next } sec && /^## / { exit }
  sec && /^\*\*Known limits\.\*\*/ { s = 1; next } s && /^\*\*/ { exit } s' "$doc")
klgrep=$(printf '%s\n' "$kl" | spans 'grep -rl --exclude-dir=')
klgit=$(printf '%s\n' "$kl" | spans "\"<auditor-skill root>/scripts/git-ro.sh\" ls-files -- '")
opts() { printf '%s\n' "$1" | grep -oE -- "--(include|exclude-dir)=[^ ]*" | tr '\n' ' '; }
klok=1
for id in K140-7a K140-7b K080-8b; do
  c=$(recipe_lines "$id"); c=${c%% | *}
  if [ "$(opts "$klgrep")" != "$(opts "$c")" ] || [ "${klgrep##* }" != "${c##* }" ]; then klok=0; fi
done
globs=$(opts "$klgrep" | tr ' ' '\n' | sed -n "s/^--include=//p" | tr '\n' ' ')
excls=$(opts "$klgrep" | tr ' ' '\n' | sed -n "s#^--exclude-dir=\(.*\)#':(exclude,glob)**/\1/**'#p" | tr '\n' ' ')
if [ "$(printf '%s\n' "${klgit#*ls-files -- }" | tr ' ' '\n' | grep . | tr '\n' ' ')" != "$globs$excls" ]; then klok=0; fi
for vs in "$KV140:7" "$KV080:8"; do
  if [ "$(kv_text "${vs%:*}" "${vs#*:}" | spans "\"<auditor-skill root>/scripts/git-ro.sh\" ls-files -- '")" != "$klgit" ]
  then klok=0; fi
done
klrun=${klgit#'"<auditor-skill root>/scripts/git-ro.sh"'}; klrun="\"$root/scripts/git-ro.sh\"$klrun"
klrepo="$work/known-limits"; mkdir -p "$klrepo/infra/.terraform/modules/oidc" "$klrepo/node_modules/runner" "$work/kl-home"
got=$( (cd "$klrepo" && export HOME="$work/kl-home" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid \
  && git init -q . && printf 'infra/ignored.tf\n' > .gitignore \
  && printf 'condition = "repo:example/*"\n' > infra/ignored.tf \
  && printf 'condition = "repo:example/*"\n' > infra/.terraform/modules/oidc/main.tf \
  && printf 'allows_public_repositories = true\n' > node_modules/runner/main.tf \
  && printf '# r\351gion\ncondition = "repo:example/*"\n' > infra/latin1.tf \
  && git add .gitignore infra/latin1.tf infra/.terraform node_modules \
  && git add -f infra/ignored.tf && git commit -qm init && eval "$klrun") </dev/null 2>/dev/null | tr '\n' ' ')
if [ -n "$klgrep" ] && [ -n "$klgit" ] && [ "$klok" -eq 1 ] && [ "$got" = "infra/ignored.tf infra/latin1.tf " ]; then
  echo "ok   Known limits compares, for the commands that search the whole tree, what git tracks with what grep reads"
else
  echo "FAIL Known limits: its grep [${klgrep:-none}] and git listing [${klgit:-none}] (same files, and the same" \
    "listing in KV-140 Step 7 and KV-080 Step 8: $klok) named [$got], want [infra/ignored.tf infra/latin1.tf ]"
  fail=1
fi

# Trigger spellings, one workflow each: a space before a colon, an event key holding null, ~, [], an anchor or an
# alias, a flow list wrapped over lines, a byte-order mark before on:, a JSON document, an indented document, and
# lines that end in CRLF. None has an author gate, so R1 and K139-1 must list every one.
spell="$work/spellings"; mkdir -p "$spell/.github/workflows"
ns=0
while IFS= read -r t; do
  ns=$((ns + 1)); printf '%b\n' "$t" > "$spell/.github/workflows/spelling-$ns.yml"
done <<'SPELLINGS'
on:\n  issue_comment :\n    types: [created]
on : issue_comment
"on" : [issues]
on:\n  issue_comment: null
on:\n  issue_comment: ~
on:\n  issue_comment: []
on:\n  issues: &t\n    types: [opened]
on:\n  workflow_dispatch: &t\n  issue_comment: *t
on: [push,\n  issue_comment,\n  workflow_dispatch]
on: [push,\n  issues]
\0357\0273\0277on: issue_comment
{"on": {"issue_comment": {"types": ["created"]}}, "jobs": {"a": {"runs-on": "ubuntu-latest"}}}
  on: issue_comment\n  jobs:\n    a:\n      runs-on: ubuntu-latest
on:\r\n  issue_comment:\r\n    types: [created]\r
on:\r\n  - push\r\n  - issues\r
on: [push, discussion]\r\njobs:\r\n  a:\r\n    runs-on: ubuntu-latest\r
SPELLINGS
want=""; i=0
while [ "$i" -lt "$ns" ]; do i=$((i + 1)); want="$want $i"; done; want=${want# }
for id in R1 K139-1; do
  got=$(run_recipe "$spell" "$(recipe_lines "$id")" | sed 's#^\.github/workflows/spelling-##; s#\.yml$##' | sort -n | tr '\n' ' ' \
    | sed 's/ $//')
  if [ "$got" = "$want" ]; then echo "ok   $id on $ns trigger spellings: every one listed"
  else echo "FAIL $id on trigger spellings: got [$got] want [$want]"; fail=1; fi
done

# Large inputs: 2,000 gated workflows (each of R1's two lists runs over 64 KiB) and two of about 1 MiB with the
# trigger on their first lines; one has its author_association gate on its last line. R1 must read each file
# whole and flag only the ungated one.
large="$work/large"; mkdir -p "$large/.github/workflows"
awk -v d="$large/.github/workflows" 'BEGIN { for (i = 0; i < 2000; i++) { f = sprintf("%s/small-gated-workflow-%04d.yml", d, i)
  printf "on: issue_comment\njobs:\n  a:\n    if: github.event.comment.author_association == %sOWNER%s\n", "\047", "\047" > f; close(f) } }'
for g in gated ungated; do
  { printf 'on:\n  issue_comment:\n    types: [created]\njobs:\n  big:\n    runs-on: ubuntu-latest\n    steps:\n'
    awk 'BEGIN { for (i = 0; i < 17000; i++) printf "      - run: echo step %05d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", i }'
    if [ "$g" = gated ]; then echo "    if: github.event.comment.author_association == 'MEMBER'"; fi
  } > "$large/.github/workflows/big-$g.yml"
done
size=$(wc -c < "$large/.github/workflows/big-gated.yml" | tr -d ' ')
got=$(run_recipe "$large" "$(recipe R1)" | sed 's#^\.github/workflows/##' | sort | tr '\n' ' ')
if [ "$got" = "big-ungated.yml " ] && [ "$size" -gt 1048576 ]; then
  echo "ok   R1 on large inputs: 2,000 gated workflows and two of $size bytes, only the ungated one flagged"
else
  echo "FAIL R1 on large inputs: got [$got] want [big-ungated.yml ] (big file: $size bytes)"
  fail=1
fi

# Large inputs for R9 and KV-080 Step 8: 2,000 workflows, each with a full-SHA pin and a job on a GitHub-hosted
# image, and one with a job on a self-hosted runner. R9 lists all 2,000 pins in more than 64 KiB of output, and
# the runner command lists only that job after more than 64 KiB of workflow lines have gone through its pipe.
scale="$work/scale"; mkdir -p "$scale/.github/workflows"
awk -v d="$scale/.github/workflows" 'BEGIN { for (i = 0; i < 2000; i++) { f = sprintf("%s/pinned-workflow-%04d.yml", d, i)
  printf "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" > f
  printf "      - uses: example/action-%04d@0123456789abcdef0123456789abcdef01234567 # v1.0.0\n", i > f; close(f) } }'
printf 'on: push\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: make\n' \
  > "$scale/.github/workflows/self-hosted.yml"
(cd "$scale" && eval "$(recipe R9)" </dev/null 2>/dev/null) > "$work/r9.out"
size=$(wc -c < "$work/r9.out" | tr -d ' ')
n=$(grep -c '^\.github/workflows/pinned-workflow-[0-9]*\.yml:8:      - uses: example/action-[0-9]*@0123456789abcdef0123456789abcdef01234567 # v1\.0\.0$' "$work/r9.out")
if [ "$n" = 2000 ] && [ "$(grep -c . "$work/r9.out")" = 2000 ] && [ "$size" -gt 65536 ]; then
  echo "ok   R9 on large inputs: all 2,000 pins listed, $size bytes"
else
  echo "FAIL R9 on large inputs: $n of 2,000 pins in $size bytes"
  fail=1
fi
runners=$(recipe_lines K080-8a)
size=$( (cd "$scale" && eval "${runners%% | *}" </dev/null 2>/dev/null) | wc -c | tr -d ' ')
got=$(run_recipe "$scale" "$runners")
if [ "$got" = '.github/workflows/self-hosted.yml:4:    runs-on: [self-hosted, linux]' ] && [ "$size" -gt 65536 ]; then
  echo "ok   KV-080 Step 8 on large inputs: $size bytes through its pipe, only the self-hosted job listed"
else
  echo "FAIL KV-080 Step 8 on large inputs ($size bytes through its pipe): got [${got:0:300}]"
  fail=1
fi

# KV-080 Step 4: the second command (R9) lists the full-SHA pins it can read, and the first lists every other uses:
# line, so each uses: line that is not a comment and names no local action is in exactly one of them. In a file
# saved with CRLF line ends a bare pin ends in a CR, which GNU and BSD grep do not take for the end of the line
# (Claude Code's grep does, and R9 lists it there); a reference of 41 hex digits and a path holding a + are not pins
# to R9 on any grep. The first command lists all three. Both read the uses key that starts the line: a branch
# reference whose trailing comment names a pin or a local action goes to the first list, and so do a branch reference
# with a blank before the colon and a pin that follows another key of a { } mapping; a pin under a quoted key goes to
# R9's. A lone CR ends a YAML line but not grep's, and so does U+2028 for a YAML 1.1 parser, so a comment line that holds
# one carries the step after it: the first command lists that line, a pin included, since R9 skips every comment line.
step4="$work/step4"; mkdir -p "$step4/.github/workflows"
sha=0123456789abcdef0123456789abcdef01234567
printf 'on: push\r\njobs:\r\n  a:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - uses: example/bare@%s\r\n' "$sha" \
  > "$step4/.github/workflows/crlf.yml"
printf '      - uses: example/versioned@%s # v1.0.0\r\n      - uses: "example/quoted@%s"\r\n      - uses: example/tag@v1\r\n' \
  "$sha" "$sha" >> "$step4/.github/workflows/crlf.yml"
printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example/long@%sf\n' "$sha" \
  > "$step4/.github/workflows/lf.yml"
printf '      - uses: example/odd/pa+th@%s\n      - uses: ./.github/actions/local\n      # - uses: example/retired@%s\n' \
  "$sha" "$sha" >> "$step4/.github/workflows/lf.yml"
printf '      - uses: example/moving@main # uses: example/pinned@%s\n      - uses: example/moving@main # uses: ./x\n' \
  "$sha" >> "$step4/.github/workflows/lf.yml"
printf '      - "uses": example/quoted-key@%s\n      - uses : example/spaced-key@main\n' "$sha" \
  >> "$step4/.github/workflows/lf.yml"
printf '      - { with: { a: 1 }, uses: example/flow-second@%s }\n' "$sha" >> "$step4/.github/workflows/lf.yml"
printf '      # note\r      - uses: example/after-cr@v1\n      # note\r      - uses: example/pin-after-cr@%s # v1.0.0\n' \
  "$sha" >> "$step4/.github/workflows/lf.yml"
printf '      # note \342\200\250      - uses: example/after-ls@v1\n' >> "$step4/.github/workflows/lf.yml"
first4=$(kv_step "$KV080" 4 | sed -n 1p); second4=$(kv_step "$KV080" 4 | sed -n 2p)
got1=$( (cd "$step4" && eval "$first4" </dev/null 2>/dev/null) | tr -d '\r' | sed 's#^\.github/workflows/##' \
  | awk -F: '{ print $1 ":" $2 }' | sort -t: -k1,1 -k2,2n | tr '\n' ' ')
got2=$( (cd "$step4" && eval "$second4" </dev/null 2>/dev/null) | tr -d '\r' | sed 's#^\.github/workflows/##' \
  | awk -F: '{ print $1 ":" $2 }' | sort -t: -k1,1 -k2,2n | tr '\n' ' ')
lf4="lf.yml:6 lf.yml:7 lf.yml:10 lf.yml:11 lf.yml:13 lf.yml:14 lf.yml:15 lf.yml:16 lf.yml:17 "
case "$got1|$got2" in
  "crlf.yml:6 crlf.yml:9 $lf4|crlf.yml:7 crlf.yml:8 lf.yml:12 " | \
  "crlf.yml:9 $lf4|crlf.yml:6 crlf.yml:7 crlf.yml:8 lf.yml:12 ")
    echo "ok   KV-080 Step 4: R9 lists the pins it reads, the first command every other uses: line, CRLF ends and" \
      "a step after a lone CR or U+2028 in a comment line included" ;;
  *) echo "FAIL KV-080 Step 4: first command listed [$got1], want [crlf.yml:6 crlf.yml:9 $lf4]; R9 listed [$got2]," \
       "want [crlf.yml:7 crlf.yml:8 lf.yml:12 ]"
     fail=1 ;;
esac

# Each command of KV-080 and KV-140 that pipes into head, run as written over the same workflows, where what it
# pipes runs over 64 KiB: it prints its head's lines and ends.
nhead=0
for v in "$KV080" "$KV140"; do
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    nhead=$((nhead + 1)); n=${c##*head -}
    size=$( (cd "$scale" && bash -c "${c%' | head -'*}" </dev/null 2>/dev/null) | wc -c | tr -d ' ')
    got=$( (cd "$scale" && bash -c "$c" </dev/null 2>/dev/null) | wc -l | tr -d ' ')
    if [ "$size" -gt 65536 ] && [ "$got" = "$n" ]; then
      echo "ok   $v: a command piping into head -$n prints its $n lines of $size bytes and ends"
    else
      echo "FAIL $v: [$c] over $size bytes printed $got lines, want $n"
      fail=1
    fi
  done <<< "$(awk '/^```/ { code = !code; next } code && / \| head -[0-9]+$/' "$kv/$v")"
done
if [ "$nhead" -eq 0 ]; then echo "FAIL no command of KV-080 or KV-140 pipes into head"; fail=1; fi

# Files holding a 1 MiB line of near misses: one that nearly matches R6 again and again, one that repeats a pin
# with a SHA one digit short, one that repeats a ref: expression whose step output R7 cannot read, one whose only
# author_association follows a #, one that repeats a claude call whose -p follows an &, one that holds an event
# name after a megabyte of blanks, one that repeats an echo of an expression and of a variable that name no secret,
# one whose official uses: is followed by a megabyte of the closing brackets, commas and blanks that KV-080 Step 6
# skips and then one more character, and an infrastructure file that repeats lookalikes of the runner and OIDC
# settings. Each command of every recipe, and KV-080 Step 4's first command, must end within 30 s and flag nothing,
# in a UTF-8 locale where one is installed (C.UTF-8 on GitHub's ubuntu runners): there GNU grep needs minutes for
# such a line when a pattern holds a construct its DFA leaves undecided (see "Linear by construction" above), and
# each line here passes the filter GNU grep runs before that. KV-080 Step 4's first command and Step 6 list the pin
# line, whose run: string holds uses: keys, and the uses: line, and nothing else.
utf8=$(locale -a 2>/dev/null | grep -iE '^(C|en_US)[.]utf-?8$' | sed -n 1p)
long="$work/long"; mkdir -p "$long/.github/workflows" "$long/infra"
{ printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "'
  awk 'BEGIN { for (i = 0; i < 26000; i++) printf "${{ github.event.issue.x contains( ref: " }'
  printf '"\n'; } > "$long/.github/workflows/long.yml"
{ printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "'
  awk 'BEGIN { for (i = 0; i < 19000; i++) printf "uses: example/x@0123456789abcdef0123456789abcdef0123456 " }'
  printf '"\n'; } > "$long/.github/workflows/long-pins.yml"
{ printf 'note = "'
  awk 'BEGIN { for (i = 0; i < 10000; i++)
    printf "config.sh --prefix=x repo:x.y repo: x/y token.actions.githubusercontent.co ephemeral-storage runner group " }'
  printf '"\n'; } > "$long/infra/long.tf"
{ printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "'
  awk 'BEGIN { for (i = 0; i < 28000; i++) printf "xref: ${{ steps.a b.outputs.head_sha " }'
  printf '"\n'; } > "$long/.github/workflows/long-refs.yml"
{ printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "'
  awk 'BEGIN { for (i = 0; i < 33000; i++) printf "the comment author association x " }'
  printf '" # github.event.comment.author_association\n'; } > "$long/.github/workflows/long-gate.yml"
{ printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "'
  awk 'BEGIN { for (i = 0; i < 120000; i++) printf "claude x " }'
  printf '& -p"\n'; } > "$long/.github/workflows/long-agent.yml"
{ printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo hi\n'
  awk 'BEGIN { for (i = 0; i < 1050000; i++) printf " " }'
  printf 'issues xy\n'; } > "$long/.github/workflows/long-trigger.yml"
{ printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "'
  awk 'BEGIN { for (i = 0; i < 36000; i++) printf "echo ${{ x }} secrets $a KEY " }'
  printf '"\n'; } > "$long/.github/workflows/long-echo.yml"
{ printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4'
  awk 'BEGIN { for (i = 0; i < 262500; i++) printf " }, " }'
  printf 'x\n'; } > "$long/.github/workflows/long-uses.yml"
sizes=""; small=0
for f in .github/workflows/long.yml .github/workflows/long-pins.yml .github/workflows/long-refs.yml \
  .github/workflows/long-gate.yml .github/workflows/long-agent.yml \
  .github/workflows/long-trigger.yml .github/workflows/long-echo.yml .github/workflows/long-uses.yml infra/long.tf; do
  s=$(wc -c < "$long/$f" | tr -d ' '); sizes="$sizes $s"
  if [ "$s" -le 1000000 ]; then small=1; fi
done
slow=""; noisy=""
for id in $IDS K080-4a; do
  while IFS= read -r c; do
    if ! within 30 "$long" "$c" "$utf8"; then slow="$slow $id"
    elif [ -s "$work/within.out" ]; then
      case "$id:$(cut -d: -f1 "$work/within.out" | sort -u | tr '\n' ' ')" in
        K080-4a:".github/workflows/long-pins.yml .github/workflows/long-uses.yml ") ;;
        K080-6:".github/workflows/long-pins.yml .github/workflows/long-uses.yml ") ;;
        *) noisy="$noisy $id" ;;
      esac
    fi
  done <<< "$(recipe_lines "$id")"
done
if [ -z "$slow$noisy" ] && [ "$small" -eq 0 ]; then
  echo "ok   every recipe on lines of$sizes bytes of near misses (LC_ALL=${utf8:-unset}): each command done within" \
    "30 s, nothing flagged but the lines that hold a uses: key, by KV-080 Steps 4 and 6"
else
  echo "FAIL lines of$sizes bytes of near misses (LC_ALL=${utf8:-unset}): still running after 30 s [$slow]," \
    "flagged [$noisy]"
  fail=1
fi

# KV-020 Step 3 and KV-100 Step 4 list documentation files with one recursive grep, as R1 does: a file name with a
# space or a quote is listed like any other, a file that is not Markdown is not, and KV-100's head ends the listing
# after five names of more than 64 KiB of them.
docs="$work/docs"; mkdir -p "$docs/docs/sub" || exit 1
printf 'How to upgrade the program\n' > "$docs/docs/upgrade plan.md"
printf 'We deploy with a multisig\n' > "$docs/docs/it's deploy.md"
printf 'Disaster recovery: restore from backup\n' > "$docs/docs/sub/dr \"notes\".md"
printf 'nothing to see\n' > "$docs/README.md"
printf 'upgrade, deploy and recovery\n' > "$docs/notes.txt"
kv020=$(kv_block 020-program-upgrade-hijack.md 3 | grep '^grep ')
kv100=$(kv_block 100-insufficient-backup-disaster-recovery.md 4 | grep '^grep ')
got020=$( (cd "$docs" && bash -c "$kv020" </dev/null 2>/dev/null) | sort | tr '\n' '|')
got100=$( (cd "$docs" && bash -c "$kv100" </dev/null 2>/dev/null) | sort | tr '\n' '|')
if [ "$got020" = "./docs/it's deploy.md|./docs/upgrade plan.md|" ] && [ "$got100" = './docs/sub/dr "notes".md|' ]; then
  echo "ok   KV-020 Step 3 and KV-100 Step 4 list Markdown files whose names hold a space or a quote, and nothing else"
else
  echo "FAIL KV-020 Step 3 / KV-100 Step 4: got [$got020] and [$got100]"
  fail=1
fi
many="$work/many-docs"; mkdir -p "$many" || exit 1
awk -v d="$many" 'BEGIN { for (i = 0; i < 3000; i++) { f = sprintf("%s/disaster recovery notes, part %04d of many.md", d, i)
  print "restore drill" > f; close(f) } }'
(cd "$many" && bash -c "$kv100" </dev/null 2>/dev/null) > "$work/kv100.out"
names=$( (cd "$many" && grep -rliE --include='*.md' 'restore' . </dev/null) | wc -c | tr -d ' ')
if [ "$(grep -c '^\./disaster recovery notes, part [0-9]* of many\.md$' "$work/kv100.out")" = 5 ] \
   && [ "$(grep -c . "$work/kv100.out")" = 5 ] && [ "$names" -gt 65536 ]; then
  echo "ok   KV-100 Step 4 stops after five names of $names bytes of them"
else
  echo "FAIL KV-100 Step 4 over $names bytes of names: $(head -c 300 "$work/kv100.out")"
  fail=1
fi

if [ "$fail" -ne 0 ]; then echo "gha recipe test FAILED" >&2; exit 1; fi
nfix=$(ls "$fixtures"/*.yml "$fixtures"/*.yaml "$fixtures"/actions/*.yml "$fixtures"/infra/* | wc -l | tr -d ' ')
echo "gha recipe test passed: $nrec recipes, $nfix fixtures, $nlines line checks, $ncopy copies, comment lines, trigger spellings, file names, large inputs"
