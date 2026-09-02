#!/usr/bin/env bash
# check-corpus.sh — verify that every hardcoded corpus count, index link and version reference agrees
# with the files on disk. Run from anywhere: `bash scripts/check-corpus.sh`. Exit 0 = consistent.
#
# What it checks
#   1. per-checklist item counts (bold **XX-NNN** ids, or table rows `| XX-NNN |` in 16-18) vs the
#      Checklists Reference table in SKILL.md and the folder-structure listing in README.md
#   2. the item total, vector total and methodology count everywhere they are quoted
#   3. every known-vectors/NNN-*.md has an INDEX.md link and a matching frontmatter id
#   4. the version in SKILL.md agrees with plugin.json, marketplace.json, audit-report.md and README.md
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
err() { echo "::error::$*" >&2; fail=1; }
ok()  { echo "ok  $*"; }
expect() { # expect FILE LITERAL
  if grep -qF -- "$2" "$1"; then ok "$1 has '$2'"; else err "$1 is missing '$2'"; fi
}
commas() { echo "$1" | sed -E ':a;s/([0-9])([0-9]{3})($|,)/\1,\2\3/;ta'; }

# ---- 1. per-checklist counts -------------------------------------------------------------------
declare -A actual
total=0
for f in checklists/[0-9][0-9]-*.md; do
  n=$(basename "$f" | cut -c1-2)
  b=$(grep -cE '\*\*[A-Z]{2,5}-[0-9]{3}\*\*' "$f" || true)
  t=$(grep -cE '^\| [A-Z]{2,5}-[0-9]{3} \|' "$f" || true)
  actual[$n]=$((b + t)); total=$((total + b + t))
done
ok "checklists on disk: ${#actual[@]} files, $total items"

while IFS='|' read -r _ num _ cnt _; do
  num=$(echo "$num" | tr -d ' \r'); cnt=$(echo "$cnt" | tr -d ' \r')
  [[ "$num" =~ ^[0-9]{2}$ ]] || continue
  if [[ "${actual[$num]:-?}" != "$cnt" ]]; then
    err "SKILL.md Checklists Reference: checklist $num says $cnt items, file has ${actual[$num]:-?}"
  fi
done < <(grep -E '^\| [0-9]{2} \| ' SKILL.md)

while read -r num cnt; do
  if [[ "${actual[$num]:-?}" != "$cnt" ]]; then
    err "README.md folder structure: checklist $num says $cnt items, file has ${actual[$num]:-?}"
  fi
done < <(sed -nE 's/.*[^0-9]([0-9]{2})-[a-z0-9-]+\.md.*\(([0-9]+) items\).*/\1 \2/p' README.md)

# ---- 2. totals ---------------------------------------------------------------------------------
vec=$(ls known-vectors | grep -cE '^[0-9]{3}-.*\.md$')
meth=$(ls references/methodologies/*.md | wc -l | tr -d ' ')
tc=$(commas "$total")
ok "known vectors on disk: $vec; methodologies: $meth"

expect SKILL.md "$total individual verification items, plus $vec known attack vectors"
expect SKILL.md "**Items:** $tc across ${#actual[@]} checklists (+ $vec known vectors)"
expect SKILL.md "(up to $tc) and all in-scope known vectors (up to $vec)"
expect SKILL.md "| | **Total** | **$tc** | | |"
expect README.md "$tc verification items · $vec known attack vectors"
expect README.md "checks $tc items across ${#actual[@]} security domains, tests against $vec real-world attack vectors"
expect README.md "| **Total** | **${#actual[@]}** | **$tc** |"
expect README.md "$meth protocol methodologies ("
expect README.md "$meth protocol playbooks ("
expect COSTS.md "Checklists (${#actual[@]} files, $tc items)"
expect COSTS.md "Known vectors ($vec procedures)"
expect FULL-AUDIT.md "KV-001..$vec"
expect OUTPUT-RULES.md "KV-001 through KV-$vec"
expect templates/report-template.md "| Total known vectors | $vec |"
expect templates/report-template.md "| | **Total** | **$total** |"
expect templates/report-template.md "...through KV-$vec"
expect templates/audit-report.md "($total-item checklist grid"
expect docs/README.md "$tc items / $vec known attack vectors, $meth protocol methodologies"
expect docs/getting-started.md "all ${#actual[@]} + $vec vectors"
expect .claude-plugin/plugin.json "$tc items / $vec known-vectors"
expect known-vectors/INDEX.md "**Total vector files:** $vec"

# per-checklist "...through XX-NNN" lines in the report template
for f in checklists/[0-9][0-9]-*.md; do
  last=$(grep -oE '\*\*[A-Z]{2,5}-[0-9]{3}\*\*|^\| [A-Z]{2,5}-[0-9]{3} \|' "$f" | grep -oE '[A-Z]{2,5}-[0-9]{3}' | sort -t- -k2 -n | tail -1)
  prefix=${last%-*}
  if grep -qE "through ${prefix}-[0-9]{3}" templates/report-template.md; then
    grep -qF "through $last" templates/report-template.md \
      || err "templates/report-template.md: '...through' line for $prefix does not end at $last"
  fi
done

# ---- 3. vector files ↔ INDEX ↔ frontmatter -----------------------------------------------------
for f in known-vectors/[0-9][0-9][0-9]-*.md; do
  b=$(basename "$f"); id=${b:0:3}
  grep -qF "($b)" known-vectors/INDEX.md || err "known-vectors/INDEX.md has no link to $b"
  fid=$(sed -nE 's/^id: *([0-9]+).*/\1/p' "$f" | head -1 | tr -d '\r')
  [[ -n "$fid" && $((10#$fid)) -eq $((10#$id)) ]] || err "$b: frontmatter id '${fid:-missing}' does not match filename"
done
ok "every vector file is indexed and its frontmatter id matches"

# ---- 4. version agreement ------------------------------------------------------------------------
v=$(sed -nE 's/^> \*\*Version:\*\* *([0-9]+\.[0-9]+).*/\1/p' SKILL.md | tr -d '\r' | head -1)
if [[ -z "$v" ]]; then err "SKILL.md: could not read the Version line"; else
  ok "SKILL.md version $v"
  expect .claude-plugin/plugin.json "\"version\": \"$v."
  expect templates/audit-report.md "auditor-skill v$v"
  expect README.md "## What It Does (v$v)"
  n=$(grep -c "\"version\": \"$v\." .claude-plugin/marketplace.json || true)
  [[ "$n" == "2" ]] || err ".claude-plugin/marketplace.json: expected 2 version references to $v.x, found $n"
fi

if [[ $fail -ne 0 ]]; then echo "corpus check FAILED" >&2; exit 1; fi
echo "corpus check passed: ${#actual[@]} checklists / $tc items / $vec vectors / $meth methodologies / v$v"
