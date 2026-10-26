#!/usr/bin/env bash
# check-frontmatter.sh — fail when Claude Code would read a frontmatter field differently from what is
# written. With no arguments it checks every file whose frontmatter Claude Code loads: each .md file at any
# depth under commands/ and agents/, and SKILL.md at the root and at any depth under skills/, matching .md and
# SKILL.md in any letter case. Given files, it checks those. The kind comes from the first directory of the
# path, below the current directory, named agents, commands or skills in any letter case, as Claude Code reads
# a plugin root: each .md under agents/ is an agent and each under commands/ a command, also one named
# SKILL.md; a SKILL.md under skills/, or under none of the three, is a skill. The frontmatter must keep to a
# flat subset:
#   - line 1 is exactly '---' and the block ends at the next line that is exactly '---'; no other line of
#     the block contains '---' or is a '...' document end; the file holds no NUL byte, and the block no tab,
#     CR, other control character, U+0085, U+2028 or U+2029;
#   - every line is 'key: value', with a key the check knows, written as listed, each key once; tools and
#     allowed-tools may instead be 'key:' followed by '  - item' lines;
#   - a value is plain, 'single-quoted' ('' is the only escape) or "double-quoted" (\" and \\ are the only
#     escapes). A plain value starts with no YAML indicator, holds no ': ', ' #' or '...', does not end in
#     ':' or a space, and is not one YAML reads as a number, boolean or null. disable-model-invocation,
#     background and user-invocable are true or false;
#   - agents have name, description and tools; commands have description and allowed-tools; a SKILL.md has
#     name and description, and no other key but allowed-tools in the root SKILL.md (the one directly in the
#     current directory; read as a command's, its bundled tools from ${CLAUDE_SKILL_DIR}), unless it is under
#     skills/, where it may also have:
#       - context, only fork, which then needs agent (without one the fork runs as general-purpose, with
#         every tool);
#       - agent, only with context: fork, and only auditor:<name>, where agents/<name>.md at the plugin
#         root (the path before skills/) is a file whose frontmatter names it <name>;
#       - background, only with context: fork, and user-invocable, each true or false;
#       - allowed-tools, read as a command's;
#   - tools and allowed-tools list 'Name' or 'Name(pattern)' entries (agents: names only, no pattern),
#     separated by ', ' or one per item, none empty; allowed-tools lists nothing in FORBIDDEN_ALLOWED_TOOLS;
#   - an allowed-tools entry that can run the bundled audit-scan or audit-mem (a Bash entry naming either as a
#     word, in any letter case, or whose program word holds a *, a final :* aside) takes a form the confined
#     builds pin, with the contract marker --contract=1 where they take it, which a build made before them refuses:
#     Bash("${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-scan" --contract=1 ...) (in the root
#     SKILL.md, ${CLAUDE_SKILL_DIR} in place of ${CLAUDE_PLUGIN_ROOT}),
#     Bash(".../audit-mem" <subcommand> --contract=1 ...) for init, put-finding, check, regressions, warm,
#     profile or invariant (never rule or set-status), or Bash(test -x "<either path>");
#   - the block is at most 65,536 bytes and holds at most 256 of '[', '{' and ' - ';
#   - a file named with .md in another letter case (.MD) fails: name it .md;
#   - two agents, two commands or two skills with the same name, in any letter case, fail.
# known-vectors/*.md carry frontmatter too, but Claude Code does not load it (check-corpus.sh reads its id).
# Usage: bash scripts/check-frontmatter.sh [FILE...]. Exit 0 = every file passes. Needs bash >= 3.2, awk, find.
set -uo pipefail

# Entries the allowed-tools of a command or skill may never list, space-separated. A name also refuses its
# catch-all patterns, such as Bash(*) for Bash. (An agent's tools list names only, so * fails there too.)
FORBIDDEN_ALLOWED_TOOLS='*'

if [ $# -eq 0 ]; then
  cd "$(dirname "$0")/.." || exit 2
  files=$( { find commands agents \( -type f -o -type l \) -iname '*.md' 2>/dev/null
             find skills \( -type f -o -type l \) -iname SKILL.md 2>/dev/null
             find . -maxdepth 1 \( -type f -o -type l \) -iname SKILL.md | sed 's#^[.]/##'; } | LC_ALL=C sort)
  set --
  while IFS= read -r f; do if [ -n "$f" ]; then set -- "$@" "$f"; fi; done <<< "$files"
fi

PROG='
function bad(m) { printf "::error::%s:%d: %s\n", file, NR, m; st = 1 }
function badat(n, m) { printf "::error::%s:%d: %s\n", file, n, m; st = 1 }
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
# A Bash entry that can run the bundled audit-scan or audit-mem: one naming either as a word, in any letter case
# (not audit-mem.db, say), or whose program word holds a * (a final :*, which only ends a prefix, aside).
function runs_tools(e,   l) {
  l = tolower(e)
  sub(/:\*\)$/, ")", l)
  return substr(l, 1, 5) == "bash(" && (l ~ /audit-(scan|mem)([^a-z0-9_.-]|$)/ || l ~ /^bash\([^ ]*[*]/)
}
# Such an entry in a form a rule may take: the quoted path from ${CLAUDE_PLUGIN_ROOT} (in the root SKILL.md, from
# ${CLAUDE_SKILL_DIR}), then the contract marker where the confined builds take it, or a test -x of the path.
function tools_form(e,   var, root) {
  var = (rootskill ? "CLAUDE_SKILL_DIR" : "CLAUDE_PLUGIN_ROOT")
  root = "^Bash\\(\"[$][{]" var "[}]/tools/auditor-tools/target/release/audit-"
  return e ~ (root "scan\" --contract=1( |\\)$)") \
    || e ~ (root "mem\" (init|put-finding|check|regressions|warm|profile|invariant) --contract=1( |\\)$)") \
    || e ~ ("^Bash\\(test -x \"[$][{]" var "[}]/tools/auditor-tools/target/release/audit-(scan|mem)\"\\)$")
}
function entry(e, key,   i, f, p, all, r) {
  if (e == "") { bad(key " has an empty entry"); return }
  # a forbidden entry, or its name with a pattern that is empty once spaces, * and : are removed: Bash(*)
  if (key == "allowed-tools") for (i in forbid) {
    f = forbid[i]; all = 0
    if (substr(e, 1, length(f) + 1) == f "(" && substr(e, length(e)) == ")") {
      p = substr(e, length(f) + 2, length(e) - length(f) - 2); gsub(/[ *:]/, "", p); all = (p == "") }
    if (e == f || all) { bad(key " may not list " q e q); return }
  }
  if (key == "allowed-tools" && runs_tools(e) && !tools_form(e)) {
    r = (rootskill ? "${CLAUDE_SKILL_DIR}" : "${CLAUDE_PLUGIN_ROOT}")
    bad(key " entry " q e q " can run audit-scan or audit-mem in a form the confined builds do not pin: write " \
        "Bash(\"" r "/tools/auditor-tools/target/release/audit-scan\" --contract=1 *), or audit-mem\" " \
        "<subcommand> --contract=1 * for init, put-finding, check, regressions, warm, profile or invariant"); return }
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
function check_line(   key, rest, s, t, k, hit) {
  if (index($0, "---")) bad("--- inside the frontmatter block; reword the line")
  if ($0 ~ /[\t\r]/) bad("tab or carriage return in the frontmatter block")
  if ($0 ~ /[\001-\010\013\014\016-\037\177]|\302[\200-\237]|\342\200[\250\251]/)
    bad("a control character, U+0085, U+2028 or U+2029 in the frontmatter block")
  size += length($0) + 1; t = $0; marks += gsub(/[[{]/, "", t); t = $0; marks += gsub(/ - /, "", t)
  if (substr($0, 1, 3) == "...") { bad("a ... line inside the frontmatter block"); return }
  if (substr($0, 1, 4) == "  - ") {
    if (listkey == "") bad("list item outside a tools or allowed-tools list"); else item(substr($0, 5))
    return
  }
  endlist()
  if (!match($0, /^[A-Za-z0-9_-]+:/)) { bad("not a key: value line"); return }
  key = substr($0, 1, RLENGTH - 1); rest = substr($0, RLENGTH + 1)
  if (!(key in known)) {
    hit = ""; for (k in known) if (tolower(k) == tolower(key)) hit = k
    if (hit != "") bad("key " q key q " differs from " q hit q " only in letter case")
    else bad("unknown key " q key q " for " what)
  }
  if (key in seen) bad("second " q key q " key")
  seen[key] = 1; at[key] = NR
  if (rest == "") {
    if (key in listable) { listkey = key; nitems = 0; listline = NR } else bad(key " has no value")
    return
  }
  if (substr(rest, 1, 1) != " " || substr(rest, 2, 1) == " " || length(rest) == 1) {
    bad("write one space and then the value after " key ":"); return }
  if (key in boolean) { if (substr(rest, 2) !~ /^(true|false)$/) bad(key " must be true or false"); return }
  s = scalar(substr(rest, 2), "the value of " key); if (!sok) return
  if (s == "") { bad(key " has an empty value"); return }
  if (key == "name") nm = s
  if (key in listable) entries(s, key)
  if (!(key in known)) return
  if (key == "context") { if (s == "fork") ctx = s; else bad("context must be fork") }
  # the agent file is checked by the caller, from the agent name this prints to refs
  if (key == "agent") {
    if (s !~ /^auditor:[a-z0-9]+(-[a-z0-9]+)*$/) bad("agent must be auditor:<name>, naming the plugin agent agents/<name>.md")
    else printf "%d\t%s\n", NR, substr(s, 9) > refs
  }
}
BEGIN {
  sqre = "^" q "([^" q "]|" q q ")*" q "$"
  split(forbidden, forbid, " ")
  listable["tools"] = 1; listable["allowed-tools"] = 1
  boolean["disable-model-invocation"] = 1; boolean["background"] = 1; boolean["user-invocable"] = 1
  if (kind == "agent") { what = "an agent"; keys = "name description tools model"; need = "name description tools" }
  else if (kind == "command") {
    what = "a command"; keys = "name description argument-hint allowed-tools model disable-model-invocation"
    need = "description allowed-tools"
  } else if (plugin) {
    what = "a SKILL.md under skills/"; keys = "name description context agent background user-invocable allowed-tools"
    need = "name description"
  } else if (rootskill) { what = "the root SKILL.md"; keys = "name description allowed-tools"; need = "name description"
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
  if (plugin && !("context" in seen)) {
    if ("agent" in seen) badat(at["agent"], "agent applies only with context: fork")
    if ("background" in seen) badat(at["background"], "background applies only with context: fork")
  }
  if (ctx == "fork" && !("agent" in seen))
    badat(at["context"], "context: fork needs an agent; without one the fork runs as general-purpose, with every tool")
  if (size > 65536) bad("the frontmatter block is " size " bytes, over 65,536")
  if (marks > 256) bad("the frontmatter block holds " marks " of [, { and \" - \", over 256")
  if (nm != "") printf "%s\t%s\t%s\n", kind, tolower(nm), file >> names
  exit st
}'

# agent_named <agent file> <name>: status 0 when the file's frontmatter has the line name: <name>, quoted or not
agent_named() {
  LC_ALL=C awk -v want="$2" -v q="'" '
    NR == 1 { if ($0 != "---") exit; next }
    $0 == "---" { closed = 1; exit }
    $0 == "name: " want || $0 == "name: " q want q || $0 == "name: \"" want "\"" { found = 1 }
    END { exit !(closed && found) }' "$1"
}

names=$(mktemp "${TMPDIR:-/tmp}/frontmatter.XXXXXX") || exit 2
refs=$(mktemp "${TMPDIR:-/tmp}/frontmatter-refs.XXXXXX") || { rm -f "$names"; exit 2; }
trap 'rm -f "$names" "$refs"' EXIT
fail=0; n=0
for f in "$@"; do
  rel=$f; case "$f" in "$PWD"/*) rel=${f#"$PWD"/} ;; esac
  low=$(printf '%s' "$rel" | LC_ALL=C tr 'A-Z' 'a-z'); rest=$low; kind=; plugin=; root=; rootskill=
  while :; do   # the first directory named agents, commands or skills gives the kind
    case "$rest" in
      agents/*) case "$low" in *.md) kind=agent ;; esac; break ;;
      commands/*) case "$low" in *.md) kind=command ;; esac; break ;;
      skills/*) case "$low" in */skill.md) kind=skill plugin=1 root=${rel:0:$((${#rel} - ${#rest}))} ;; esac; break ;;
      */*) rest=${rest#*/} ;;
      *) case "$low" in skill.md) kind=skill rootskill=1 ;; */skill.md) kind=skill ;; esac; break ;;
    esac
  done
  if [ -z "$kind" ]; then
    echo "::error::$f: not under agents/ or commands/ and not a SKILL.md; its keys are unknown" >&2; fail=1; continue
  fi
  case "$f" in *.md) ;; *) echo "::error::$f: name the file with a lowercase .md" >&2; fail=1; continue ;; esac
  if [ ! -f "$f" ]; then echo "::error::$f: no such file" >&2; fail=1; continue; fi
  # awk does not see a NUL byte the same way everywhere, so look for one first
  if [ "$(LC_ALL=C tr -d '\000' < "$f" | wc -c)" -ne "$(wc -c < "$f")" ]; then
    echo "::error::$f: a NUL byte" >&2; fail=1; continue
  fi
  : > "$refs"
  LC_ALL=C awk -v file="$f" -v kind="$kind" -v plugin="$plugin" -v rootskill="$rootskill" -v q="'" \
    -v forbidden="$FORBIDDEN_ALLOWED_TOOLS" \
    -v names="$names" -v refs="$refs" "$PROG" "$f" >&2 || fail=1
  while IFS=$'\t' read -r line agent; do   # each agent a skill names: a file at the plugin root, named so
    a="${root}agents/$agent.md"
    if [ ! -f "$a" ]; then
      echo "::error::$f:$line: agent auditor:$agent names no agent of this plugin: $a is not a file" >&2; fail=1
    elif ! agent_named "$a" "$agent"; then
      echo "::error::$f:$line: agent auditor:$agent: the frontmatter of $a does not name it $agent" >&2; fail=1
    fi
  done < "$refs"
  n=$((n + 1))
done
# one name for two files of a kind: Claude Code would load one of them under it
dups=$(LC_ALL=C awk -F'\t' '{ k = $1 "\t" $2; c[k]++; f[k] = f[k] (c[k] > 1 ? ", " : "") substr($0, length(k) + 2) }
  END { for (k in c) if (c[k] > 1) { split(k, a, "\t"); printf "::error::%s: %d %ss named %s\n", f[k], c[k], a[1], a[2] } }' \
  "$names" | LC_ALL=C sort)
if [ -n "$dups" ]; then printf '%s\n' "$dups" >&2; fail=1; fi
if [ "$fail" -ne 0 ]; then echo "frontmatter check FAILED" >&2; exit 1; fi
echo "frontmatter check passed: $n files"
