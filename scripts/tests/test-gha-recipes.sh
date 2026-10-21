#!/usr/bin/env bash
# test-gha-recipes.sh — run the GitHub Actions recipes R1–R8 exactly as written in
# discovery/grep-commands.md ("GitHub Actions (CI trigger trust)") against the fixture workflows in
# scripts/tests/fixtures/gha/, and check that each recipe flags exactly the expected fixtures.
#
# Usage (from the repo root): bash scripts/tests/test-gha-recipes.sh
# Needs bash >= 3.2, grep, awk, xargs. No network. The fixtures are copied into a temp dir as
# .github/workflows/ for the run; nothing is written under the repository's own .github/.
set -uo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
doc="$root/discovery/grep-commands.md"
fixtures="$root/scripts/tests/fixtures/gha"

work=$(mktemp -d "${TMPDIR:-/tmp}/gha-recipes.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/.github/workflows"
cp "$fixtures"/*.yml "$work/.github/workflows/" || exit 1

# The command line that follows the "# Rn — …" comment inside the GitHub Actions section of the doc.
recipe() {
  awk -v id="$1" '
    /^## GitHub Actions \(CI trigger trust\)/ { sec = 1; next }
    sec && /^## / { exit }
    sec && index($0, "# " id " ") == 1 { grab = 1; next }
    sec && grab && /^grep / { print; exit }
  ' "$doc"
}

# Fixtures each recipe must flag (two-digit prefixes, ascending). Anything else is a mismatch.
expected() {
  case "$1" in
    R1) echo "01 08 10 16" ;;
    R2) echo "02 04" ;;
    R3) echo "03 12 13 17" ;;
    R4) echo "05 06" ;;
    R5) echo "06 07 15" ;;
    R6) echo "05 07 08 14 15 16" ;;
    R7) echo "05 07 11 12 15" ;;
    R8) echo "01 08 11 14" ;;
  esac
}

fail=0
for id in R1 R2 R3 R4 R5 R6 R7 R8; do
  cmd=$(recipe "$id")
  if [ -z "$cmd" ]; then
    echo "FAIL $id: no recipe line found in $doc"
    fail=1
    continue
  fi
  got=$(cd "$work" && eval "$cmd" 2>/dev/null \
    | sed -E 's#^\.github/workflows/##; s#^([0-9][0-9])-.*#\1#' | sort -u | tr '\n' ' ' | sed 's/ $//')
  want=$(expected "$id")
  if [ "$got" = "$want" ]; then
    echo "ok   $id: $got"
  else
    echo "FAIL $id: got [$got] want [$want]"
    fail=1
  fi
done

# The negative control must stay silent for every recipe.
for id in R1 R2 R3 R4 R5 R6 R7 R8; do
  case " $(expected "$id") " in *" 09 "*) echo "FAIL $id: negative control 09 is expected"; fail=1 ;; esac
done

if [ "$fail" -ne 0 ]; then echo "gha recipe test FAILED" >&2; exit 1; fi
echo "gha recipe test passed: 8 recipes, $(ls "$fixtures"/*.yml | wc -l | tr -d ' ') fixtures"
