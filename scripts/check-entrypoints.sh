#!/usr/bin/env bash
# check-entrypoints.sh — fail when an allow rule pre-approves anything but a confined entry point, or when an
# entry point lacks what its pre-approval relies on. scripts/entrypoints.txt lists the entry points; the check
# fails unless:
#   - each line of the list is <path><TAB><case file>[<TAB><words>], every path relative, without . or ..
#     components, and listed once;
#   - each listed script is a tracked file of mode 100755 whose first line is exactly #!/bin/bash or
#     #!/usr/bin/env -S python3 -I, and a bash one sources scripts/lib/confine.sh; each listed
#     tools/auditor-tools/target/release/<name> is a binary that a crate under tools/auditor-tools declares;
#   - each has a tracked case file holding at least one case, every case line with a tab in it;
#   - every allowed-tools entry that names Bash, in a command (any .md under commands/), a skill (any SKILL.md
#     under skills/) or the root SKILL.md, is Bash("${CLAUDE_PLUGIN_ROOT}/<a listed path>") or that path
#     followed by words (in the root SKILL.md, ${CLAUDE_SKILL_DIR} in place of ${CLAUDE_PLUGIN_ROOT}): each word
#     made of letters, digits and _ = . , : / @ % + -, but for a lone * as the last, and the words the list
#     names for that entry point first (the contract marker of audit-scan and audit-mem, the collector's
#     mode); a bare Bash fails, and so does a tools entry naming Bash with a pattern in an agent (any .md under
#     agents/), which gets its approval from the command that spawns it;
#   - every other allowed-tools entry there is a read tool (Read, Grep, Glob), Task, a run-directory edit
#     (Edit(audit_*/**), Edit(incident_*/**)) or one of the plugin's own skills (Skill(auditor:<name> *));
#   - each listed entry point is named by at least one such rule.
# Files are found in any letter case, as check-frontmatter.sh finds them. How the bodies and the corpus call
# each entry point is test-command-forms.sh's check; what each does with hostile arguments is
# test-preapproved-entrypoints.sh's.
# Usage: bash scripts/check-entrypoints.sh. Exit 0 = passes; 1 = a finding; 2 = it cannot run (no checkout,
# no list). Needs bash >= 3.2, git, awk, find.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
LIST=scripts/entrypoints.txt
[ -f "$LIST" ] || { echo "::error::$LIST is not a file" >&2; exit 2; }
T=$(mktemp -d "${TMPDIR:-/tmp}/entrypoints.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
git ls-files -s > "$T/index" 2>"$T/git.err" || { echo "::error::git ls-files failed; run this in the checkout: $(cat "$T/git.err")" >&2; exit 2; }
fail=0
err() { echo "::error::$*" >&2; fail=1; }

# ---- 1. the list ---------------------------------------------------------------------------------------
# One record per good line: <line><TAB><path><TAB><case file><TAB><words>.
LC_ALL=C awk -F'\t' -v list="$LIST" '
  function bad(m) { printf "::error::%s:%d: %s\n", list, FNR, m > "/dev/stderr"; st = 1 }
  function rel(p, what,   n, a, i) {
    if (p == "" || p ~ /^\// || p ~ /[^A-Za-z0-9_.\/-]/) { bad(what " " p " is not a relative path of letters, digits and _ . / -"); return 0 }
    n = split(p, a, "/"); for (i = 1; i <= n; i++) if (a[i] == "" || a[i] == "." || a[i] == "..") { bad(what " " p " has an empty, . or .. component"); return 0 }
    return 1
  }
  /^#/ || /^$/ { next }
  {
    if (NF < 2 || NF > 3) { bad("want <path><TAB><case file>[<TAB><words>], not " NF " fields"); next }
    if (!rel($1, "the entry point") || !rel($2, "the case file")) next
    if (NF == 3 && $3 !~ /^[A-Za-z0-9_=.,:\/@%+|-]+( [A-Za-z0-9_=.,:\/@%+|-]+)*$/) { bad("the words for " $1 " are not words of letters, digits and _ = . , : / @ % + - |, one space apart"); next }
    if ($1 in seen) { bad($1 " is listed twice (first at line " seen[$1] ")"); next }
    seen[$1] = FNR
    printf "%d\t%s\t%s\t%s\n", FNR, $1, $2, (NF == 3 ? $3 : "")
  }
  END { exit st }' "$LIST" > "$T/list" || fail=1
[ -s "$T/list" ] || err "$LIST lists no entry point"

# ---- 2. each entry point and its case file -----------------------------------------------------------
mode_of() { LC_ALL=C awk -v p="$1" '{ m = $1; sub(/^[^\t]*\t/, ""); if ($0 == p) { print m; exit } }' "$T/index"; }
# the binaries the crates under tools/auditor-tools declare, one per line
bins=$(find tools/auditor-tools -maxdepth 2 -name Cargo.toml -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r c; do
  [ -n "$(mode_of "$c")" ] || continue
  LC_ALL=C awk '/^\[/ { inbin = ($0 ~ /^\[\[bin\]\][ \t]*$/) } inbin && /^name[ \t]*=/ { v = $0; sub(/^name[ \t]*=[ \t]*"/, "", v); sub(/".*/, "", v); print v }' "$c"
done)
nl=$'\n'
n=0
while IFS=$'\t' read -r line ep cases words; do
  n=$((n + 1))
  at="$LIST:$line"
  case "$ep" in
    tools/auditor-tools/target/release/*/* | tools/auditor-tools/target/release/) err "$at: $ep is not tools/auditor-tools/target/release/<binary>" ;;
    tools/auditor-tools/target/release/*)
      b=${ep#tools/auditor-tools/target/release/}
      case "$nl$bins$nl" in *"$nl$b$nl"*) ;; *) err "$at: $b is no binary a crate under tools/auditor-tools declares" ;; esac ;;
    scripts/* | templates/*)
      m=$(mode_of "$ep")
      if [ -z "$m" ]; then err "$at: $ep is not a tracked file"
      elif [ "$m" != 100755 ]; then err "$at: $ep is mode $m in the index, not 100755"
      elif [ -L "$ep" ] || [ ! -f "$ep" ]; then err "$at: $ep is not a regular file in the checkout"
      else
        first=""; IFS= read -r first < "$ep" || [ -n "$first" ] || first=""
        case "$first" in
          '#!/bin/bash')
            if ! grep -qE '^[[:space:]]*(\.|source)[[:space:]]+"[^"]*/lib/confine\.sh"' "$ep"; then
              err "$at: $ep does not source scripts/lib/confine.sh"
            fi ;;
          '#!/usr/bin/env -S python3 -I') ;;
          *) err "$at: $ep starts with '$first', not #!/bin/bash or #!/usr/bin/env -S python3 -I" ;;
        esac
      fi ;;
    *) err "$at: $ep is not under scripts/, templates/ or tools/auditor-tools/target/release/" ;;
  esac
  if [ -z "$(mode_of "$cases")" ]; then err "$at: the case file $cases is not a tracked file"
  elif [ -L "$cases" ] || [ ! -f "$cases" ]; then err "$at: the case file $cases is not a regular file in the checkout"
  else
    # a cases.txt line starts with the exit status and a tab; a hostile-args.txt line is a name, then the arguments
    status=""; case "$cases" in */cases.txt) status=1 ;; esac
    LC_ALL=C awk -v at="$at" -v f="$cases" -v status="$status" '/^#/ || /^$/ { next }
      { n++; if (status && $0 !~ /^[0-9]+\t/) { printf "::error::%s: the case file %s: line %d does not start with an exit status and a tab\n", at, f, NR > "/dev/stderr"; st = 1 } }
      END { if (n == 0) { printf "::error::%s: the case file %s holds no case\n", at, f > "/dev/stderr"; st = 1 } exit st }' "$cases" || fail=1
  fi
done < "$T/list"

# ---- 3. the allow rules ------------------------------------------------------------------------------
{ find commands agents \( -type f -o -type l \) -iname '*.md' 2>/dev/null
  find skills \( -type f -o -type l \) -iname SKILL.md 2>/dev/null
  find . -maxdepth 1 \( -type f -o -type l \) -iname SKILL.md | sed 's#^[.]/##'; } | LC_ALL=C sort > "$T/files"
: > "$T/named"
nrules=0
while IFS= read -r f; do
  low=$(printf '%s' "$f" | LC_ALL=C tr 'A-Z' 'a-z')
  case "$low" in
    agents/*) kind=agent ;;
    commands/*) kind=command ;;
    skill.md) kind=root ;;
    *) kind=skill ;;
  esac
  r=$(LC_ALL=C awk -v file="$f" -v kind="$kind" -v listf="$T/list" -v named="$T/named" -v q="'" '
    function bad(n, m) { printf "::error::%s:%d: %s\n", file, n, m > "/dev/stderr"; st = 1 }
    function unq(v,   s) {
      if (length(v) >= 2 && substr(v, 1, 1) == q && substr(v, length(v)) == q) { s = substr(v, 2, length(v) - 2); gsub(q q, q, s); return s }
      if (length(v) >= 2 && substr(v, 1, 1) == "\"" && substr(v, length(v)) == "\"") {
        s = substr(v, 2, length(v) - 2); gsub(/\\\\/, "\001", s); gsub(/\\"/, "\"", s); gsub(/\001/, "\\", s); return s }
      return v
    }
    function each(s, n,   i, c, depth, cur) {   # each entry of a one-line list, split on commas outside parentheses
      depth = 0; cur = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "(") depth++; else if (c == ")") depth--
        if (c == "," && depth == 0) { rule(cur, n); cur = ""; if (substr(s, i + 1, 1) == " ") i++; continue }
        cur = cur c
      }
      rule(cur, n)
    }
    function rule(e, n,   var, pre, rest, ep, k, nw, w, i, j, need, alts, na, hit) {
      if (e !~ /^Bash([^A-Za-z0-9_]|$)/) {
        if (kind != "agent" && e !~ named_re)
          bad(n, "allowed-tools entry " q e q " is no read tool (Read, Grep, Glob), Task, run-directory edit (Edit(audit_*/**), Edit(incident_*/**)), auditor skill (Skill(auditor:<name> *)) or Bash rule for a listed entry point")
        return }
      if (kind == "agent") {   # the Bash tool itself; a pattern would be a rule, which an agent cannot carry
        if (e != "Bash") bad(n, "the agent tools entry " q e q " is a Bash rule; an agent gets its approval from the command that spawns it")
        return }
      rules++
      if (e ~ /[^ -~]/) { bad(n, "allowed-tools entry " q e q " holds a tab, a control character or a byte outside printable ASCII"); return }
      var = (kind == "root" ? "CLAUDE_SKILL_DIR" : "CLAUDE_PLUGIN_ROOT")
      pre = "Bash(\"${" var "}/"
      if (substr(e, 1, length(pre)) != pre || substr(e, length(e)) != ")") {
        bad(n, "allowed-tools entry " q e q " is not Bash(\"${" var "}/<path>\" ...) for a path in scripts/entrypoints.txt"); return }
      rest = substr(e, length(pre) + 1, length(e) - length(pre) - 1)
      k = index(rest, "\"")
      if (k == 0) { bad(n, "allowed-tools entry " q e q " does not close the quoted path"); return }
      ep = substr(rest, 1, k - 1); rest = substr(rest, k + 1)
      if (!(ep in words)) { bad(n, "allowed-tools entry " q e q " names " ep ", which scripts/entrypoints.txt does not list"); return }
      if (rest != "" && substr(rest, 1, 1) != " ") { bad(n, "allowed-tools entry " q e q " has no space after the quoted path"); return }
      nw = split(substr(rest, 2), w, " ")
      if (rest != "" && (nw == 0 || rest ~ /  / || rest ~ / $/)) { bad(n, "allowed-tools entry " q e q " has an empty word"); return }
      for (i = 1; i <= nw; i++) {
        if (w[i] == "*" && i == nw) { nw--; break }
        if (w[i] !~ /^[A-Za-z0-9_=.,:\/@%+-]+$/) {
          bad(n, "allowed-tools entry " q e q ": the word " q w[i] q " holds a character other than letters, digits and _ = . , : / @ % + -, or is a * that is not the last word"); return }
      }
      na = split(words[ep], need, " ")
      for (i = 1; i <= na; i++) {
        split(need[i], alts, "|"); hit = 0
        for (j in alts) if (i <= nw && w[i] == alts[j]) hit = 1
        if (!hit) { bad(n, "allowed-tools entry " q e q " does not start with " q words[ep] q " after the path, as scripts/entrypoints.txt asks for " ep); return }
      }
      print ep >> named
    }
    BEGIN {
      while ((getline l < listf) > 0) { split(l, a, "\t"); words[a[2]] = a[4] }
      named_re = "^(Read|Grep|Glob|Task|Edit[(](audit|incident)_[*]/[*][*][)]|Skill[(]auditor:[a-z0-9]+(-[a-z0-9]+)* [*][)])$"
    }
    NR == 1 { if ($0 != "---") exit; next }
    $0 == "---" { exit }
    substr($0, 1, 4) == "  - " { if (key == "allowed-tools" || key == "tools") rule(unq(substr($0, 5)), NR); next }
    match($0, /^[A-Za-z0-9_-]+:/) {
      key = substr($0, 1, RLENGTH - 1); v = substr($0, RLENGTH + 1); sub(/^ /, "", v)
      if ((key == "allowed-tools" || key == "tools") && v != "") each(unq(v), NR)
    }
    END { print rules + 0; exit st }' "$f") || fail=1
  nrules=$((nrules + ${r:-0}))
done < "$T/files"

# ---- 4. every listed entry point is pre-approved somewhere ----------------------------------------------
while IFS=$'\t' read -r line ep cases words; do
  grep -qxF -- "$ep" "$T/named" || err "$LIST:$line: $ep is listed, but no command, skill or root SKILL.md rule pre-approves it"
done < "$T/list"

if [ "$fail" -ne 0 ]; then echo "entry-point check FAILED" >&2; exit 1; fi
echo "entry-point check passed: $n entry points, $nrules Bash rules"
