#!/usr/bin/env bash
# tob-delta-review.sh — summarize what moving the vendor/trailofbits pin from OLD to NEW changes, for the
# review in CONTRIBUTING.md §5 ("Bumping vendor/trailofbits"). Prints markdown to stdout.
#
# Usage: bash scripts/tob-delta-review.sh [--fetch] <tob-clone> <old-sha> <new-sha>
#   <tob-clone>  a full (non-shallow) clone of https://github.com/trailofbits/skills
#   --fetch      run `git fetch origin` in <tob-clone> first — the only network access, off by default
#
# Read-only: it reads <tob-clone> with git plumbing and this repo's boundary-map / power-tools tables,
# and writes nothing but a temp dir it removes on exit. The report informs a human reviewer; it is not
# a verdict. Works with bash 3.2.
set -uo pipefail

fetch=0
if [ "${1:-}" = "--fetch" ]; then fetch=1; shift; fi
if [ $# -ne 3 ]; then
  echo "usage: bash scripts/tob-delta-review.sh [--fetch] <tob-clone> <old-sha> <new-sha>" >&2
  exit 2
fi
repo=$(cd "$1" 2>/dev/null && pwd) || { echo "no such directory: $1" >&2; exit 2; }
old=$2; new=$3
cd "$(dirname "$0")/.."

g() { git -C "$repo" "$@"; }
if [ "$fetch" -eq 1 ]; then g fetch --quiet origin || { echo "fetch failed" >&2; exit 2; }; fi
for c in "$old" "$new"; do
  g cat-file -e "$c^{commit}" 2>/dev/null \
    || { echo "commit $c not found in $repo (shallow or stale clone? try --fetch)" >&2; exit 2; }
done
[ "$(g rev-parse --is-shallow-repository)" = "true" ] && echo "warning: $repo is shallow; counts may be incomplete" >&2

tmp=$(mktemp -d "${TMPDIR:-/tmp}/tob-delta.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT

section() { printf '\n### %s\n' "$1"; }
show() { if [ -s "$1" ]; then cat "$1"; else echo "(none)"; fi; }
# "<mode> <path>" for every tree entry, path kept whole (tab-separated in ls-tree output)
entries() { g ls-tree -r --full-tree "$1" | awk -F'\t' '{ split($1, a, " "); print a[1] "\t" $2 }'; }

entries "$old" > "$tmp/old"
entries "$new" > "$tmp/new"
g diff --name-status -M "$old" "$new" > "$tmp/ns"

echo "## trailofbits/skills $(g log -1 --format='%h %cs' "$old") -> $(g log -1 --format='%h %cs' "$new")"
echo
echo "$(g rev-list --count "$old..$new") commits;$(g diff --shortstat "$old" "$new")."
if g merge-base --is-ancestor "$old" "$new"; then echo "NEW descends from OLD."; else echo "**NEW does not descend from OLD.**"; fi

section "Plugins added (+) / removed (-)"
g ls-tree --name-only "$old:plugins" | sort > "$tmp/p_old"
g ls-tree --name-only "$new:plugins" | sort > "$tmp/p_new"
comm -3 "$tmp/p_old" "$tmp/p_new" | awk -F'\t' '{ if ($1 == "") print "+ " $2; else print "- " $1 }' > "$tmp/p"
show "$tmp/p"

section "Load surfaces: nested .claude/, hooks, MCP/LSP, settings, CLAUDE.md/AGENTS.md, Workflow scripts"
grep -E '(^|/|[[:space:]])\.claude/|(^|/|[[:space:]])hooks(/|\.json)|\.mcp\.json|\.lsp\.json|settings[^/]*\.json|(^|/|[[:space:]])(CLAUDE|AGENTS)\.md|workflows/[^/]*\.js' \
  "$tmp/ns" > "$tmp/ls" || true
show "$tmp/ls"

section "Plugin manifests (.claude-plugin/) added or removed"
grep -E '\.claude-plugin/' "$tmp/ns" | grep -vE '^M' > "$tmp/man" || true
show "$tmp/man"
echo "($(grep -cE '^M.*\.claude-plugin/' "$tmp/ns") modified — version and description bumps; inline declarations below)"

section "Manifests that declare hooks, MCP or LSP servers inline (at NEW)"
awk -F'\t' '$2 ~ /\.claude-plugin\/plugin\.json$/ {print $2}' "$tmp/new" | while IFS= read -r f; do
  if g show "$new:$f" | grep -E '"(hooks|mcpServers|lspServers)"' >/dev/null; then echo "$f"; fi
done > "$tmp/inline"
show "$tmp/inline"

section "New executables (mode 100755)"
awk -F'\t' '$1 == "100755" {print $2}' "$tmp/old" | sort > "$tmp/x_old"
awk -F'\t' '$1 == "100755" {print $2}' "$tmp/new" | sort > "$tmp/x_new"
comm -13 "$tmp/x_old" "$tmp/x_new" > "$tmp/x"
show "$tmp/x"

section "Symlinks (120000) and gitlinks (160000) at NEW"
awk -F'\t' '$1 == "120000" || $1 == "160000" {print $1 " " $2}' "$tmp/new" > "$tmp/links"
show "$tmp/links"

section "Hosts in added lines of scripts and config (excluding tests, evals, fixtures and lockfiles)"
g diff -U0 "$old" "$new" -- '*.sh' '*.bash' '*.py' '*.js' '*.mjs' '*.cjs' '*.ts' '*.json' '*.toml' '*.yml' '*.yaml' \
  ':(exclude)*/tests/*' ':(exclude)*/evals/*' ':(exclude)*/evals-extra/*' ':(exclude)*/fixtures/*' \
  ':(exclude)*.lock' ':(exclude)*package-lock.json' \
  | grep -E '^\+' | grep -oE 'https?://[A-Za-z0-9.-]+' | sort | uniq -c | sort -rn > "$tmp/hosts" || true
show "$tmp/hosts"

section "Pipe-to-shell and remote-exec patterns in added lines"
g diff -U0 "$old" "$new" -- . ':(exclude)*.lock' | grep -E '^\+' \
  | grep -E '(curl|wget)[^|]*\|[[:space:]]*(ba|z)?sh|uvx --from git\+|npx -y|pip install git\+|bash <\(curl' > "$tmp/rx" || true
show "$tmp/rx"

section "LICENSE"
if g diff --quiet "$old" "$new" -- LICENSE; then echo "unchanged"; else echo "**CHANGED** — re-check ATTRIBUTION.md"; fi
awk -F'\t' '{print $NF}' "$tmp/ns" | grep -iE '(^|/)(LICEN[CS]E|COPYING|NOTICE)[^/]*$' | grep -vx 'LICENSE' > "$tmp/lic" || true
if [ -s "$tmp/lic" ]; then echo "Other licence files added or changed:"; cat "$tmp/lic"; fi

section "Plugins this repo names (boundary-map.md, power-tools.md): present at NEW?"
{
  awk -F'|' '/^\|/ && NF > 4 {print $3}' references/orchestration/boundary-map.md
  awk -F'|' '/^## Trail of Bits plugins/ {on = 1; next} /^## / {on = 0} on && /^\|/ && NF > 4 {print $3}' docs/power-tools.md
} | grep -oE '`[a-z0-9][a-z0-9-]*`' | tr -d '`' | sort -u > "$tmp/named"
while IFS= read -r p; do
  if g cat-file -e "$new:plugins/$p" 2>/dev/null; then
    st=$(g diff --shortstat "$old" "$new" -- "plugins/$p" | sed 's/^ //')
    printf -- '- %s: present (%s)\n' "$p" "${st:-unchanged}"
  else
    printf -- '- %s: **MISSING at NEW** — update the rows that name it\n' "$p"
  fi
done < "$tmp/named"
