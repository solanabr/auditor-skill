#!/usr/bin/env bash
# check-frontmatter.sh — fail when Claude Code would read a frontmatter field differently from what is
# written. Checks the files whose frontmatter Claude Code loads: commands/*.md, agents/*.md, SKILL.md and
# skills/*/SKILL.md (or the files given; the kind comes from the path). The frontmatter must keep to a flat
# subset:
#   - line 1 is exactly '---' and the block ends at the next line that is exactly '---'; no other line of
#     the block contains '---' or is a '...' document end; the file holds no NUL byte, and the block no tab,
#     CR, other control character, U+0085, U+2028 or U+2029;
#   - every line is 'key: value', with a known lowercase key, each key once; tools and allowed-tools may
#     instead be 'key:' followed by '  - item' lines;
#   - a value is plain, 'single-quoted' ('' is the only escape) or "double-quoted" (\" and \\ are the only
#     escapes). A plain value starts with no YAML indicator, holds no ': ', ' #' or '...', does not end in
#     ':' or a space, and is not one YAML reads as a number, boolean or null. disable-model-invocation is
#     true or false;
#   - agents have name, description and tools; commands have description and allowed-tools; a SKILL.md has
#     name and description, and for now no other key;
#   - tools and allowed-tools list 'Name' or 'Name(pattern)' entries (agents: names only, no pattern),
#     separated by ', ' or one per item, none empty; allowed-tools lists none of FORBIDDEN_ALLOWED_TOOLS.
# known-vectors/*.md carry frontmatter too, but Claude Code does not load it (check-corpus.sh reads its id).
# Usage: bash scripts/check-frontmatter.sh [FILE...]. Exit 0 = every file passes. Needs bash >= 3.2, awk.
set -uo pipefail

# Entries the allowed-tools of a command or skill may never list, space-separated, each a whole entry.
# (An agent's tools list tool names only, so * fails there by that rule.)
FORBIDDEN_ALLOWED_TOOLS='*'

if [ $# -eq 0 ]; then
  cd "$(dirname "$0")/.." || exit 2
  set -- commands/*.md agents/*.md SKILL.md
  for f in skills/*/SKILL.md; do if [ -f "$f" ]; then set -- "$@" "$f"; fi; done
fi

PROG='
function bad(m) { printf "::error::%s:%d: %s\n", file, NR, m; st = 1 }
# The string YAML reads for the scalar v (sok = 1), or sok = 0 after saying why v is outside the subset.
function scalar(v, what,   c, s) {
  sok = 0; c = substr(v, 1, 1)
  if (c == "\"") {
    if (v !~ /^"([^"\\]|\\["\\])*"$/) {
      bad(what " is double-quoted but unterminated, followed by text, or escaped other than \\\" and \\\\"); return "" }
    s = substr(v, 2, length(v) - 2); gsub(/\\\\/, "\001", s); gsub(/\\"/, "\"", s); gsub(/\001/, "\\", s)
  } else if (c == q) {
    if (v !~ sqre) { bad(what " is single-quoted but unterminated, followed by text, or holds a lone quote"); return "" }
    s = substr(v, 2, length(v) - 2); gsub(q q, q, s)
  } else {
    if (index("-?:,[]{}#&*!|>%@`", c)) { bad(what " starts with a YAML indicator; quote it"); return "" }
    if (index(v, ": ") || v ~ /:$/) { bad(what " holds a colon and a space, or ends in a colon; quote it"); return "" }
    if (index(v, " #")) { bad(what " holds a space and #, which starts a YAML comment; quote it"); return "" }
    if (v ~ / $/) { bad(what " ends in a space"); return "" }
    if (index(v, "...")) { bad(what " holds ..., which YAML reads as a document end; quote it"); return "" }
    if (v ~ /^(~|null|Null|NULL|true|True|TRUE|false|False|FALSE|yes|Yes|YES|no|No|NO|on|On|ON|off|Off|OFF|[yYnN])$/ \
        || v ~ /^[-+.]*[0-9]/ || v ~ /^[-+]*[.](inf|Inf|INF|nan|NaN|NAN)$/) {
      bad(what " is read as a number, boolean or null; quote it"); return "" }
    s = v
  }
  sok = 1; return s
}
# Split s on commas outside parentheses (one space may follow each), check each entry, return the count.
function entries(s, key,   i, c, depth, cur, n) {
  n = 0; depth = 0; cur = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "(") depth++; else if (c == ")") depth--
    if (c == "," && depth == 0) { entry(cur, key); n++; cur = ""; if (substr(s, i + 1, 1) == " ") i++; continue }
    cur = cur c
  }
  entry(cur, key)
  return n + 1
}
function entry(e, key,   i) {
  if (e == "") { bad(key " has an empty entry"); return }
  if (key == "allowed-tools") for (i in forbid) if (e == forbid[i]) { bad(key " may not list " q e q); return }
  if (kind == "agent" && e !~ /^[A-Z][A-Za-z]*$/) { bad(key " entry " q e q " is not a tool name"); return }
  if (e !~ /^[A-Z][A-Za-z]*(\([^()]+\))?$/)
    bad(key " entry " q e q " is not Name or Name(pattern), with no parentheses inside the pattern")
}
function item(v,   s) {
  s = scalar(v, listkey " item"); if (!sok) return
  nitems++
  if (entries(s, listkey) != 1) bad(listkey " item holds more than one entry; write one per item")
}
function endlist() {
  if (listkey != "" && nitems == 0) { printf "::error::%s:%d: %s is an empty list\n", file, listline, listkey; st = 1 }
  listkey = ""
}
function check_line(   key, rest, s) {
  if (index($0, "---")) bad("--- inside the frontmatter block; reword the line")
  if ($0 ~ /[\t\r]/) bad("tab or carriage return in the frontmatter block")
  if ($0 ~ /[\001-\010\013\014\016-\037\177]|\302[\200-\237]|\342\200[\250\251]/)
    bad("a control character, U+0085, U+2028 or U+2029 in the frontmatter block")
  if (substr($0, 1, 3) == "...") { bad("a ... line inside the frontmatter block"); return }
  if (substr($0, 1, 4) == "  - ") {
    if (listkey == "") bad("list item outside a tools or allowed-tools list"); else item(substr($0, 5))
    return
  }
  endlist()
  if (!match($0, /^[A-Za-z0-9_-]+:/)) { bad("not a key: value line"); return }
  key = substr($0, 1, RLENGTH - 1); rest = substr($0, RLENGTH + 1)
  if (key ~ /[A-Z]/) bad("key " q key q " has a capital letter; keys are lowercase")
  else if (!(key in known)) bad("unknown key " q key q " for " what)
  if (key in seen) bad("second " q key q " key")
  seen[key] = 1
  if (rest == "") {
    if (key in listable) { listkey = key; nitems = 0; listline = NR } else bad(key " has no value")
    return
  }
  if (substr(rest, 1, 1) != " " || substr(rest, 2, 1) == " " || length(rest) == 1) {
    bad("write one space and then the value after " key ":"); return }
  if (key in boolean) { if (substr(rest, 2) !~ /^(true|false)$/) bad(key " must be true or false"); return }
  s = scalar(substr(rest, 2), "the value of " key); if (!sok) return
  if (s == "") { bad(key " has an empty value"); return }
  if (key in listable) entries(s, key)
}
BEGIN {
  sqre = "^" q "([^" q "]|" q q ")*" q "$"
  split(forbidden, forbid, " ")
  listable["tools"] = 1; listable["allowed-tools"] = 1; boolean["disable-model-invocation"] = 1
  if (kind == "agent") { what = "an agent"; keys = "name description tools model"; need = "name description tools" }
  else if (kind == "command") {
    what = "a command"; keys = "name description argument-hint allowed-tools model disable-model-invocation"
    need = "description allowed-tools"
  } else { what = "a SKILL.md"; keys = "name description"; need = "name description" }
  n = split(keys, a, " "); for (i = 1; i <= n; i++) known[a[i]] = 1
}
NR == 1 { if ($0 != "---") { bad("line 1 must be exactly --- (no BOM, CR or trailing text)"); exit } opened = 1; next }
$0 == "---" { closed = 1; exit }
{ check_line() }
END {
  if (NR == 0) bad("empty file: no frontmatter")
  if (!opened) exit st
  if (!closed) { bad("no closing --- line"); exit st }
  endlist()
  n = split(need, r, " "); for (i = 1; i <= n; i++) if (!(r[i] in seen)) bad("missing required key " r[i])
  exit st
}'

fail=0; n=0
for f in "$@"; do
  case "$f" in
    SKILL.md | */SKILL.md) kind=skill ;;
    agents/*.md | */agents/*.md) kind=agent ;;
    commands/*.md | */commands/*.md) kind=command ;;
    *) echo "::error::$f: not under agents/ or commands/ and not a SKILL.md; its keys are unknown" >&2; fail=1; continue ;;
  esac
  if [ ! -f "$f" ]; then echo "::error::$f: no such file" >&2; fail=1; continue; fi
  # awk does not see a NUL byte the same way everywhere, so look for one first
  if [ "$(LC_ALL=C tr -d '\000' < "$f" | wc -c)" -ne "$(wc -c < "$f")" ]; then
    echo "::error::$f: a NUL byte" >&2; fail=1; continue
  fi
  LC_ALL=C awk -v file="$f" -v kind="$kind" -v q="'" -v forbidden="$FORBIDDEN_ALLOWED_TOOLS" "$PROG" "$f" >&2 || fail=1
  n=$((n + 1))
done
if [ "$fail" -ne 0 ]; then echo "frontmatter check FAILED" >&2; exit 1; fi
echo "frontmatter check passed: $n files"
