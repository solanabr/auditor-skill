#!/usr/bin/env bash
# test-gha-recipes.sh — run the GitHub Actions recipes exactly as written against the fixture workflows in
# scripts/tests/fixtures/gha/, and check that each recipe flags exactly the expected fixtures:
#   R1–R8    discovery/grep-commands.md, section "GitHub Actions (CI trigger trust)";
#   K116-1   KV-116 Step 1 (AI-agent steps);
#   K139-1   KV-139 Step 1 (externally triggerable workflows);
#   K140-6   KV-140 Step 6 (Actions cache writers and restorers).
# A recipe of two commands (R1) flags what the first lists and the second does not. The suite also checks that
# every known-vector step that repeats an R recipe carries each of its lines byte for byte, and that no recipe
# flags a fixture's comment lines. It runs R1 over file names that hold a space or a quote, and over large
# inputs: 2,000 workflows, and two of about 1 MiB.
#
# Usage (from the repo root): bash scripts/tests/test-gha-recipes.sh
# Needs bash >= 3.2, grep, awk. No network. The fixtures are copied into a temp dir as .github/workflows/, and
# those under actions/ as .github/actions/<name>/action.yml, for the run; nothing is written under the
# repository's own .github/.
set -uo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
doc="$root/discovery/grep-commands.md"
kv="$root/known-vectors"
fixtures="$root/scripts/tests/fixtures/gha"

work=$(mktemp -d "${TMPDIR:-/tmp}/gha-recipes.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT

# install_fixtures <fixture dir> <tree>: the workflows into <tree>/.github/workflows/, and each composite action
# in <fixture dir>/actions/ as <tree>/.github/actions/<name>/action.yml.
install_fixtures() {
  local a n
  mkdir -p "$2/.github/workflows" && cp "$1"/*.yml "$2/.github/workflows/" || return 1
  for a in "$1"/actions/*.yml; do
    n=${a##*/}; n=${n%.yml}
    mkdir -p "$2/.github/actions/$n" && cp "$a" "$2/.github/actions/$n/action.yml" || return 1
  done
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

# The `grep` lines inside a known vector's "**Step <n>:" block, in order.
kv_step() { # kv_step <vector file> <step>
  awk -v n="$2" '
    index($0, "**Step " n ":") == 1 { s = 1; next }
    s && /^\*\*Step / { exit }
    s && /^grep / { print }
  ' "$kv/$1"
}

KV080=080-ci-cd-pipeline-injection.md
KV116=116-ai-coding-agent-ci-deploy-key.md
KV139=139-comment-triggered-workflow-author-gating.md
KV140=140-workflow-run-pwn-request-artifact-cache-poisoning.md

# Recipes that live only in a known vector (<id> <vector file> <step>): the step's first grep line.
KV_RECIPES="K116-1 $KV116 1
K139-1 $KV139 1
K140-6 $KV140 6"

# Known-vector steps that repeat an R recipe (<id> <vector file> <step>).
COPIES="R1 $KV080 7
R2 $KV139 3
R3 $KV139 4
R4 $KV140 4
R5 $KV140 5
R7 $KV080 2
R7 $KV140 2"

IDS="R1 R2 R3 R4 R5 R6 R7 R8 K116-1 K139-1 K140-6"

# Fixtures each recipe must flag (two-digit prefixes, ascending). Anything else is a mismatch.
expected() {
  case "$1" in
    R1) echo "01 08 10 16 40 55 56" ;;
    R2) echo "02 04" ;;
    R3) echo "03 12 13 17 25 26 27 28 46 47 48 49" ;;
    R4) echo "05 06 21 29 30 41" ;;
    R5) echo "06 07 15" ;;
    R6) echo "05 07 08 14 15 16 20 31 32 50" ;;
    R7) echo "05 07 11 12 15 18 19 20 21 22 23 24 51 52 53" ;;
    R8) echo "01 08 11 14 33 34 54 57" ;;
    K116-1) echo "01 08 11 14 33 34 54 57" ;;
    K139-1) echo "01 02 03 04 08 10 11 14 16 17 22 23 25 26 33 40 48 49 53 55 56" ;;
    K140-6) echo "35 36 37 38 39 42 43 44 45" ;;
  esac
}

# The command lines of recipe <id>.
recipe_lines() {
  local i file step
  case "$1" in
    R*) recipe "$1" ;;
    *) while read -r i file step; do
         if [ "$i" = "$1" ]; then kv_step "$file" "$step" | sed -n 1p; fi
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

# The two-digit fixture prefixes in a recipe's output, ascending, on one line.
prefixes() {
  sed -E 's#^\.github/(workflows|actions)/##; s#^([0-9][0-9])-.*#\1#' | sort -u | tr '\n' ' ' | sed 's/ $//'
}

fail=0; nrec=0
check() { # check <id> <command lines>
  nrec=$((nrec + 1))
  if [ -z "$2" ]; then
    echo "FAIL $1: no recipe line found"
    fail=1
    return
  fi
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

ncopy=0
while read -r id file step; do
  ncopy=$((ncopy + 1))
  want=$(recipe "$id")
  steps=$(kv_step "$file" "$step")
  same=0
  if [ -n "$want" ]; then
    same=1
    while IFS= read -r line; do
      grep -qxF -- "$line" <<< "$steps" || same=0
    done <<< "$want"
  fi
  if [ "$same" -eq 1 ]; then
    echo "ok   copy of $id in $file step $step"
  else
    echo "FAIL copy of $id in $file step $step differs from discovery/grep-commands.md"
    fail=1
  fi
done <<< "$COPIES"

# The negative control must stay silent for every recipe.
for id in $IDS; do
  case " $(expected "$id") " in *" 09 "*) echo "FAIL $id: negative control 09 is expected"; fail=1 ;; esac
done

# Every expected hit comes from a workflow line: no recipe flags the fixtures' comment lines on their own.
mkdir -p "$work/comment-lines/actions"
for f in "$fixtures"/*.yml "$fixtures"/actions/*.yml; do
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

if [ "$fail" -ne 0 ]; then echo "gha recipe test FAILED" >&2; exit 1; fi
nfix=$(ls "$fixtures"/*.yml "$fixtures"/actions/*.yml | wc -l | tr -d ' ')
echo "gha recipe test passed: $nrec recipes, $nfix fixtures, $ncopy copies, comment lines, file names, large inputs"
