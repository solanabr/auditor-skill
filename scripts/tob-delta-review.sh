#!/usr/bin/env bash
# tob-delta-review.sh — summarize what moving the vendor/trailofbits pin from OLD to NEW changes, for the
# review in CONTRIBUTING.md §5 ("Bumping vendor/trailofbits"). Prints markdown to stdout.
#
# Usage: bash scripts/tob-delta-review.sh [--fetch] <tob-clone> <old-sha> <new-sha>
#   <tob-clone>  a full (non-shallow) clone of https://github.com/trailofbits/skills
#   --fetch      run `git fetch origin` in <tob-clone> first — the only network access, off by default
#
# Read-only: it reads <tob-clone> with git and this repo's boundary-map / power-tools tables, and writes
# nothing but a temp dir it removes on exit. Git runs without a pager or signature display, and every diff,
# log and show without colour, external diff or textconv and with rename detection set on the command
# line, so those settings in the maintainer's ~/.gitconfig or the clone's config never reach the parsers
# below. Upstream's own .gitattributes cannot hide a changed file from the scans either: they diff with
# --text, and read attributes from the empty tree where git supports it (2.40+). The report informs a
# human reviewer; it is not a verdict. Works with bash 3.2.
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

ATTR=()
g() { git --no-pager -c log.showSignature=false -c core.quotePath=false -C "$repo" ${ATTR[@]+"${ATTR[@]}"} "$@"; }
# on every diff, log and show: plain text with fixed a/ b/ prefixes, and no rename or copy detection unless
# the call asks for renames (PAIRED)
DIFFSAFE=(--no-color --no-ext-diff --no-textconv --no-renames --src-prefix=a/ --dst-prefix=b/)
SCAN=("${DIFFSAFE[@]}" --text)   # on every call whose output a scan reads: no file counts as binary
PAIRED=("${SCAN[@]}" -M)         # the file list and the rename lists pair renamed files
# Paths Claude Code loads or runs on its own: nested .claude/, hooks, MCP/LSP, settings, CLAUDE.md / AGENTS.md.
# Path and URL scans match in any letter case, as macOS's default file system and hosts do.
LOADSURF='(^|/|[[:space:]])\.claude/|(^|/|[[:space:]])hooks(/|\.json)|\.mcp\.json|\.lsp\.json|settings[^/]*\.json|(^|/|[[:space:]])(claude|agents)\.md|workflows/[^/]*\.js'
if [ "$fetch" -eq 1 ]; then g fetch --quiet origin || { echo "fetch failed" >&2; exit 2; }; fi
for c in "$old" "$new"; do
  g cat-file -e "$c^{commit}" 2>/dev/null \
    || { echo "commit $c not found in $repo (shallow or stale clone? try --fetch)" >&2; exit 2; }
done
[ "$(g rev-parse --is-shallow-repository)" = "true" ] && echo "warning: $repo is shallow; counts may be incomplete" >&2
empty=$(g hash-object -t tree --no-filters /dev/null)
if g --attr-source="$empty" check-attr diff -- probe.sh >/dev/null 2>&1; then ATTR=(--attr-source="$empty"); fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/tob-delta.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT

section() { printf '\n### %s\n' "$1"; }
show() { if [ -s "$1" ]; then cat "$1"; else echo "(none)"; fi; }
# "<mode> <path>" for every tree entry, path kept whole (tab-separated in ls-tree output)
entries() { g ls-tree -r --full-tree "$1" | awk -F'\t' '{ split($1, a, " "); print a[1] "\t" $2 }'; }

entries "$old" > "$tmp/old"
entries "$new" > "$tmp/new"
g diff "${PAIRED[@]}" --name-status "$old" "$new" > "$tmp/ns"

echo "## trailofbits/skills $(g log "${DIFFSAFE[@]}" -1 --format='%h %cs' "$old") -> $(g log "${DIFFSAFE[@]}" -1 --format='%h %cs' "$new")"
echo
echo "$(g rev-list --count "$old..$new") commits;$(g diff "${DIFFSAFE[@]}" --shortstat "$old" "$new")."
if g merge-base --is-ancestor "$old" "$new"; then echo "NEW descends from OLD."; else echo "**NEW does not descend from OLD.**"; fi

section "Plugins added (+) / removed (-)"
g ls-tree --name-only "$old:plugins" | sort > "$tmp/p_old"
g ls-tree --name-only "$new:plugins" | sort > "$tmp/p_new"
comm -3 "$tmp/p_old" "$tmp/p_new" | awk -F'\t' '{ if ($1 == "") print "+ " $2; else print "- " $1 }' > "$tmp/p"
show "$tmp/p"

section "Load surfaces: nested .claude/, hooks, MCP/LSP, settings, CLAUDE.md/AGENTS.md, Workflow scripts"
grep -iE "$LOADSURF" "$tmp/ns" > "$tmp/ls" || true
show "$tmp/ls"

section "Plugin manifests (.claude-plugin/) added or removed"
grep -iE '\.claude-plugin/' "$tmp/ns" | grep -vE '^M' > "$tmp/man" || true
show "$tmp/man"
echo "($(grep -ciE '^M.*\.claude-plugin/' "$tmp/ns") modified — version and description bumps; inline declarations below)"

section "Manifests (plugin.json, marketplace.json) that declare hooks, MCP or LSP servers inline (at NEW)"
awk -F'\t' 'tolower($2) ~ /(^|\/)\.claude-plugin\/(plugin|marketplace)\.json$/ {print $2}' "$tmp/new" | while IFS= read -r f; do
  # a count, so grep reads the whole manifest and the pipe never closes early
  n=$(g show "${SCAN[@]}" "$new:$f" | grep -ciE '"(hooks|mcpServers|lspServers)"')
  if [ "${n:-0}" -gt 0 ]; then echo "$f"; fi
done > "$tmp/inline"
show "$tmp/inline"

section "Skills and commands per plugin, OLD -> NEW (changed only)"
# "<plugin>\t<SKILL.md count>\t<command count>" for plugins/<p>/skills/<s>/SKILL.md and plugins/<p>/commands/*.md
counts() { awk -F'\t' '{ n = split($2, p, "/") }
  p[1] == "plugins" && n >= 2 { seen[p[2]] = 1 }
  p[1] == "plugins" && n == 5 && p[3] == "skills" && p[5] == "SKILL.md" { s[p[2]]++ }
  p[1] == "plugins" && n == 4 && p[3] == "commands" && p[4] ~ /\.md$/ { c[p[2]]++ }
  END { for (k in seen) printf "%s\t%d\t%d\n", k, s[k], c[k] }' "$1" | sort; }
counts "$tmp/old" > "$tmp/c_old"
counts "$tmp/new" > "$tmp/c_new"
awk -F'\t' 'FILENAME == ARGV[1] { os[$1] = $2; oc[$1] = $3; seen[$1] = 1; next }
  { ns[$1] = $2; nc[$1] = $3; seen[$1] = 1 }
  END { for (k in seen) if (os[k] + 0 != ns[k] + 0 || oc[k] + 0 != nc[k] + 0)
          printf "- %s: skills %d -> %d, commands %d -> %d\n", k, os[k], ns[k], oc[k], nc[k] }' \
  "$tmp/c_old" "$tmp/c_new" | sort > "$tmp/sc"
show "$tmp/sc"
cnt() { awk -F'\t' -v p="$2" -v f="$3" '$1 == p { print $f }' "$1"; } # cnt FILE PLUGIN FIELD

section "New executables (mode 100755)"
awk -F'\t' '$1 == "100755" {print $2}' "$tmp/old" | sort > "$tmp/x_old"
awk -F'\t' '$1 == "100755" {print $2}' "$tmp/new" | sort > "$tmp/x_new"
comm -13 "$tmp/x_old" "$tmp/x_new" > "$tmp/x"
show "$tmp/x"

section "Symlinks (120000) and gitlinks (160000) at NEW"
awk -F'\t' '$1 == "120000" || $1 == "160000" {print $1 " " $2}' "$tmp/new" > "$tmp/links"
show "$tmp/links"

section "Paths git still quotes (a quote, backslash or control character in the name; the scans may miss them): read by hand"
awk -F'\t' 'substr($2, 1, 1) == "\"" {print $2}' "$tmp/new" > "$tmp/quoted"
show "$tmp/quoted"

hosts() { grep -E '^\+' | grep -oiE 'https?://[A-Za-z0-9.-]+' | LC_ALL=C tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn; }
NOTESTS=(':(exclude)*/tests/*' ':(exclude)*/evals/*' ':(exclude)*/evals-extra/*' ':(exclude)*/fixtures/*')
# the paths each added-line scan below reads
CODE=('*.sh' '*.bash' '*.py' '*.js' '*.mjs' '*.cjs' '*.ts' '*.json' '*.toml' '*.yml' '*.yaml' "${NOTESTS[@]}" \
  ':(exclude)*.lock' ':(exclude)*package-lock.json')
MD=('*.md' "${NOTESTS[@]}")
ALL=(. ':(exclude)*.lock')

section "Renamed files, OLD -> NEW (a file moved unchanged, to a path that is not a load surface, is left out of the added-line scans; every other renamed file is scanned whole)"
# Pairs over the whole tree and within each scan's paths: a scan pairs only the files it reads.
renames() { g --icase-pathspecs diff "${PAIRED[@]}" --name-status --diff-filter=R "$old" "$new" -- "$@"; }
{ awk -F'\t' '$1 ~ /^R/' "$tmp/ns"; renames "${CODE[@]}"; renames "${MD[@]}"; renames "${ALL[@]}"; } \
  | awk -F'\t' '{ printf "- %s -> %s (%d%% similar)\n", $2, $3, substr($1, 2) }' | sort -u > "$tmp/ren"
show "$tmp/ren"
# The new paths of files a scan pairs as moved unchanged (R100), outside the load surfaces: the scan skips them.
moved() { renames "$@" | awk -F'\t' -v rx="$LOADSURF" '$1 == "R100" && tolower($3) !~ rx { print $3 }'; }
moved "${CODE[@]}" > "$tmp/mv_code"; moved "${MD[@]}" > "$tmp/mv_md"; moved "${ALL[@]}" > "$tmp/mv_all"
# added() SKIP PATHSPEC...: the -U0 diff a scan reads, every file as added or changed, less the files in SKIP.
# Without rename detection a/ and b/ name the same path, so the path is the header's second half.
added() { local skip=$1; shift
  g --icase-pathspecs diff "${SCAN[@]}" -U0 "$old" "$new" -- "$@" | awk -v skip="$skip" '
    BEGIN { while ((getline p < skip) > 0) s[p] = 1 }
    /^diff --git / { n = (length($0) - 16) / 2; keep = !(substr($0, 14, n) in s) }
    keep'; }

section "Hosts in added lines of scripts and config (excluding tests, evals, fixtures and lockfiles)"
added "$tmp/mv_code" "${CODE[@]}" | hosts > "$tmp/hosts" || true
show "$tmp/hosts"

section "Hosts in added Markdown lines: skill and command text an agent may follow (excluding tests, evals and fixtures)"
added "$tmp/mv_md" "${MD[@]}" | hosts > "$tmp/mdhosts" || true
show "$tmp/mdhosts"

section "Remote-exec patterns in added lines, continuation lines joined, any letter case (pipe to a shell or interpreter, sh -c \"\$(curl …)\", <(curl …), PowerShell irm … | iex and iex (irm …), npx --yes, pip / pipx / uv tool / uvx from git or a URL, cargo install --git, go install …@latest)"
# "<path>: <added line>". An added line ending in a backslash, or in a pipe outside a Markdown table row, is
# joined with the next added line, so a multi-line installer is scanned as one command. A "+++ " line names
# the file only inside a file header, so an added line that starts with "++ " is scanned like any other.
joined() { awk '
  function flush() { if (buf != "") print file ": " buf; buf = "" }
  /^diff --git / { flush(); hdr = 1; next }
  hdr && /^\+\+\+ / { file = substr($0, 5); sub(/^b\//, "", file); next }
  /^@@/ { flush(); hdr = 0; next }
  hdr { next }
  /^\+/ { s = substr($0, 2); if (buf != "") sub(/^[ \t]+/, "", s); buf = (buf == "") ? s : buf " " s
          if (buf ~ /\\[ \t]*$/) { sub(/[ \t]*\\[ \t]*$/, "", buf); next }
          if (buf ~ /[|][ \t]*$/ && s !~ /^[ \t]*[|]/) next
          flush(); next }
  { flush() }
  END { flush() }'; }
# Matched in any letter case: PowerShell ignores case, and so does macOS's default file system.
SHELLS="((ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby|pwsh|powershell|iex|invoke-expression)([[:space:];&|)\"']|\$)"
GET='(curl|wget)([.]exe)?|(^|[^[:alnum:]_-])(irm|iwr|invoke-restmethod|invoke-webrequest)'   # a download command
RX_PIPE="($GET)[[:space:]].*[|][[:space:]]*(sudo([[:space:]]+-[A-Za-z]+([[:space:]]+[A-Za-z0-9_]+)?)*[[:space:]]+)?((/[^[:space:]|]*/)?env([[:space:]]+[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*)*[[:space:]]+)?(/[^[:space:]|]*/)?$SHELLS"
RX_SUBST="((ba|z|da|k)?sh[[:space:]]+-c|eval)[[:space:]]+[\"']?[\$][(][[:space:]]*(curl|wget)[[:space:]]"
RX_PROC='(source|[.]|(ba|z|da|k)?sh)[[:space:]]+<[(][[:space:]]*(curl|wget)[[:space:]]'
IEX='(^|[^[:alnum:]_-])(iex|invoke-expression)[[:space:]]*[$]?[(]'   # PowerShell evaluating a subexpression
RX_IEX="$IEX(.*[^[:alnum:]_-])?(irm|iwr|curl|wget|invoke-restmethod|invoke-webrequest)([^[:alnum:]_-]|\$)|$IEX.*net[.]webclient"
FROM="([^|;&]*[[:space:]=])?[\"']?(git[+]|https?://)"   # an install source from git or a URL, quoted or not
RX_PKG="npx[[:space:]]+(-y|--yes)([[:space:]]|\$)|pip[0-9.]*[[:space:]]+install[[:space:]]+$FROM|(pipx|uv[[:space:]]+tool)[[:space:]]+(install|run)[[:space:]]+$FROM"
RX_PKG="$RX_PKG|uvx[[:space:]]+([^|;&]*[[:space:]])?--from[[:space:]=]+[\"']?(git[+]|https?://)|cargo([[:space:]]+[+][^[:space:]]+)?[[:space:]]+install[[:space:]]+([^|;&]*[[:space:]])?--git([[:space:]=]|\$)"
RX_PKG="$RX_PKG|(^|[^[:alnum:]_.-])go[[:space:]]+(install|run)[[:space:]]+([^|;&]*[[:space:]])?[^[:space:]|;&]+@latest([^[:alnum:]_.-]|\$)"
added "$tmp/mv_all" "${ALL[@]}" | joined \
  | grep -iE "$RX_PIPE|$RX_SUBST|$RX_PROC|$RX_IEX|$RX_PKG" > "$tmp/rx" || true
show "$tmp/rx"

section "LICENSE"
if g diff "${DIFFSAFE[@]}" --quiet "$old" "$new" -- LICENSE; then echo "unchanged"; else echo "**CHANGED** — re-check ATTRIBUTION.md"; fi
awk -F'\t' '{print $NF}' "$tmp/ns" | grep -iE '(^|/)(LICEN[CS]E|COPYING|NOTICE)[^/]*$' | grep -vx 'LICENSE' > "$tmp/lic" || true
if [ -s "$tmp/lic" ]; then echo "Other licence files added or changed:"; cat "$tmp/lic"; fi

section "Plugins this repo names (boundary-map.md, power-tools.md): present at NEW?"
{
  awk -F'|' '/^\|/ && NF > 4 {print $3}' references/orchestration/boundary-map.md
  awk -F'|' '/^## Trail of Bits plugins/ {on = 1; next} /^## / {on = 0} on && /^\|/ && NF > 4 {print $3}' docs/power-tools.md
} | grep -oE '`[a-z0-9][a-z0-9-]*`' | tr -d '`' | sort -u > "$tmp/named"
while IFS= read -r p; do
  if g cat-file -e "$new:plugins/$p" 2>/dev/null; then
    st=$(g diff "${DIFFSAFE[@]}" --shortstat "$old" "$new" -- "plugins/$p" | sed 's/^ //')
    so=$(cnt "$tmp/c_old" "$p" 2); sn=$(cnt "$tmp/c_new" "$p" 2)
    co=$(cnt "$tmp/c_old" "$p" 3); cn=$(cnt "$tmp/c_new" "$p" 3)
    note=""; [ "${so:-0}" -gt 0 ] && [ "${sn:-0}" -eq 0 ] && note=" — **no SKILL.md at NEW**"
    printf -- '- %s: present (skills %s -> %s, commands %s -> %s; %s)%s\n' \
      "$p" "${so:-0}" "${sn:-0}" "${co:-0}" "${cn:-0}" "${st:-unchanged}" "$note"
  else
    printf -- '- %s: **MISSING at NEW** — update the rows that name it\n' "$p"
  fi
done < "$tmp/named"
