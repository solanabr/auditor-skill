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
#   K080-8a  KV-080 Step 8, first command (jobs on runners GitHub does not host);
#   K080-8b  KV-080 Step 8, second command (runner registrations and runner-group settings).
# A recipe of two commands (R1) flags what the first lists and the second does not; every other line of an R
# recipe must be an echo of a quoted marker, which the suite does not run. The suite also checks that every
# known-vector step that repeats an R recipe carries its lines byte for byte, as one block in the same order,
# and that no recipe flags a fixture's comment lines. R9 and the KV-080 Step 8 and KV-140 Step 7 commands are
# also checked line by line on their own fixtures, and those that search outside .github/ skip node_modules/
# and .terraform/. It runs R1 and K139-1 over trigger spellings built at run time, R1 over file names that hold
# a space or a quote, and R1 over large inputs: 2,000 workflows, and two of about 1 MiB. Every command of every
# recipe must end within 30 s on a workflow that holds one 1 MiB line of near misses. KV-020 Step 3 and KV-100
# Step 4, which list documentation files with one recursive grep as R1 does, run over file names that hold a
# space or a quote, and KV-100's over more than 64 KiB of names.
#
# Usage (from the repo root): bash scripts/tests/test-gha-recipes.sh
# Needs bash >= 3.2, grep, awk. No network. The fixtures are copied into a temp dir as .github/workflows/, those
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

IDS="R1 R2 R3 R4 R5 R6 R7 R8 R9 K116-1 K139-1 K140-6 K140-7a K140-7b K080-8a K080-8b"

# Fixtures each recipe must flag (two-digit prefixes, ascending). Anything else is a mismatch.
expected() {
  case "$1" in
    R1) echo "01 08 10 16 40 55 56 58 64 65 66 69" ;;
    R2) echo "02 04" ;;
    R3) echo "03 12 13 17 25 26 27 28 46 47 48 49 74" ;;
    R4) echo "05 06 21 29 30 41" ;;
    R5) echo "06 07 15" ;;
    R6) echo "05 07 08 14 15 16 20 31 32 50 75" ;;
    R7) echo "05 07 11 12 15 18 19 20 21 22 23 24 51 52 53 61 62 63 70 71" ;;
    R8) echo "01 08 11 14 33 34 54 57 67 68 72 73" ;;
    R9) echo "01 05 07 08 11 12 15 18 19 20 21 22 23 24 35 36 38 39 42 43 44 45 51 52 53 60 61 62 63 70 71 76 98" ;;
    K116-1) echo "01 08 11 14 33 34 54 57 67 68 72 73" ;;
    K139-1) echo "01 02 03 04 08 10 11 14 16 17 22 23 25 26 33 40 48 49 53 55 56 58 59 62 64 65 66 69 71 74" ;;
    K140-6) echo "35 36 37 38 39 42 43 44 45" ;;
    K140-7a) echo "80 81 82 83 84 85 93 95 96 97" ;;
    K140-7b) echo "80 82 83 84 85 93 95 96 97" ;;
    K080-8a) echo "78 98" ;;
    K080-8b) echo "86 87 88 89 90 94" ;;
  esac
}

# The lines each recipe must flag in its own fixtures (<id> <fixture> <line>...); its other fixtures are listed
# whole in expected(), and its near misses are in neither.
LINES="R9 76-pin-forms.yml 11 12 13 14 16 17 19
R9 98-pin-and-runner-yaml-extension.yaml 11
K080-8a 78-self-hosted-runners.yml 9 13 17 23 27 34
K080-8a 98-pin-and-runner-yaml-extension.yaml 9
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
K140-7b infra/80-oidc-aws-repo-wildcard.tf 17
K140-7b infra/82-oidc-azure-environment.tf 8 14
K140-7b infra/83-oidc-gcp-owner.tf 11 20 26
K140-7b infra/84-oidc-vault-workflow.tf 14 15
K140-7b infra/85-oidc-cloudformation-default-branch.yaml 15
K140-7b infra/93-oidc-aws-any-repository.json 11
K140-7b infra/95-oidc-terragrunt.hcl 8
K140-7b infra/96-oidc-pulumi.yml 15
K140-7b infra/97-oidc-provider.sh 6"

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

# within <seconds> <tree> <command>: run the command in <tree>, its output in $work/within.out. Fails, and stops
# the command, when it is still running after <seconds>.
within() {
  local pid i=0
  (cd "$2" && eval "exec $3" </dev/null > "$work/within.out" 2>/dev/null) &
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

# The two-digit fixture prefixes in a recipe's output, ascending, on one line. A recipe rooted at . prints its
# paths after ./.
prefixes() {
  sed -E 's#^\./##; s#^(\.github/(workflows|actions)|infra)/##; s#^([0-9][0-9])-.*#\1#' | sort -u | tr '\n' ' ' | sed 's/ $//'
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
  case "$fx" in infra/*) path=$fx ;; *) path=.github/workflows/$fx ;; esac
  got=$(run_recipe "$work" "$(recipe_lines "$id")" | sed 's#^\./##' | awk -F: -v p="$path" '$1 == p { print $2 }' \
    | sort -n | tr '\n' ' ' | sed 's/ $//')
  if [ "$got" = "$want" ]; then echo "ok   $id in $fx: lines $got"
  else echo "FAIL $id in $fx: got lines [$got] want [$want]"; fail=1; fi
done <<< "$LINES"

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
# 60 pins its checkout the way DEP-067 asks.
for id in $IDS; do
  for neg in 09 60; do
    case "$id:$neg" in R9:60) continue ;; esac
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

# Trigger spellings, one workflow each: a space before a colon, an event key holding null, ~, [], an anchor or an
# alias, a flow list wrapped over lines, a byte-order mark before on:, a JSON document and an indented document.
# None has an author gate, so R1 and K139-1 must list every one.
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

# One workflow holding a 1 MiB line that nearly matches R6 again and again. Each command of every recipe must end
# within 30 s and flag nothing. GNU grep in a UTF-8 locale backtracks for minutes on such a line when a range such
# as a-z follows .*, which is why R6 spells its letters out.
long="$work/long"; mkdir -p "$long/.github/workflows"
{ printf 'on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "'
  awk 'BEGIN { for (i = 0; i < 26000; i++) printf "${{ github.event.issue.x contains( ref: " }'
  printf '"\n'; } > "$long/.github/workflows/long.yml"
size=$(wc -c < "$long/.github/workflows/long.yml" | tr -d ' ')
slow=""; noisy=""
for id in $IDS; do
  while IFS= read -r c; do
    if ! within 30 "$long" "$c"; then slow="$slow $id"; elif [ -s "$work/within.out" ]; then noisy="$noisy $id"; fi
  done <<< "$(recipe_lines "$id")"
done
if [ -z "$slow$noisy" ] && [ "$size" -gt 1000000 ]; then
  echo "ok   every recipe on a line of $size bytes of near misses: each command done within 30 s, nothing flagged"
else
  echo "FAIL a line of $size bytes of near misses: still running after 30 s [$slow], flagged [$noisy]"
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
