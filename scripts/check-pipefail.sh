#!/usr/bin/env bash
# check-pipefail.sh — fail if a shell script that sets pipefail pipes into a reader that can stop before its
# input ends: grep -q, -l, -L or -m, grep with its output sent to /dev/null, head, read, sed with a q
# command, or awk with exit. When such a reader stops early, the command writing into the pipe gets SIGPIPE
# and, under pipefail, the pipeline fails even though the reader found what it wanted; it shows only once
# the input outgrows a pipe (64 KiB). Count with grep -c, print with sed -n '1,Np', or capture the output
# first. A pipe meant to stop early carries "# pipefail-ok: <reason>" on its line.
# Quoted text and here-documents are not read as code: a pipe inside sh -c "…" runs without pipefail.
# Usage: bash scripts/check-pipefail.sh [FILE...]   (default: every tracked *.sh file). Exit 0 = none found.
# Needs bash >= 3.2, awk, grep, and git for the default file list.
set -uo pipefail

PROG='
# One physical line, masked: the text inside quotes becomes _, a comment becomes spaces, and an escaped
# character becomes _, so only unquoted shell syntax is left; same length as the input. qs is the quote
# state carried across lines (0 none, 1 single, 2 double, 3 ANSI-C); cont is set by a trailing backslash.
function mask(t,   i, n, c, o, com) {
  o = ""; n = length(t); cont = 0; com = 0
  for (i = 1; i <= n; i++) {
    c = substr(t, i, 1)
    if (com) { o = o " "; continue }
    if (qs == 1) { if (c == q) { qs = 0; o = o c } else o = o "_"; continue }
    if (qs >= 2) {
      if (c == "\\") { o = o "_"; if (i < n) { o = o "_"; i++ } continue }
      if ((qs == 2 && c == "\"") || (qs == 3 && c == q)) { qs = 0; o = o c } else o = o "_"
      continue
    }
    if (c == "\\") { if (i == n) { cont = 1; o = o " " } else { o = o "__"; i++ } continue }
    if (c == q) { qs = 1; o = o c; continue }
    if (c == "\"") { qs = 2; o = o c; continue }
    if (c == "$" && substr(t, i + 1, 1) == q) { qs = 3; o = o "$" q; i++; continue }
    if (c == "#" && (i == 1 || substr(t, i - 1, 1) ~ /[ \t;&|()]/)) { com = 1; o = o " "; continue }
    o = o c
  }
  return o
}
# The length of the simple command at the start of s: up to ; & && || ) or a newline.
function simple(s,   i, n, c) {
  n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == ";" || c == "\n" || c == ")") return i - 1
    if (c == "|" && substr(s, i + 1, 1) == "|") return i - 1
    if (c == "&" && substr(s, i + 1, 1) != ">" && (i == 1 || substr(s, i - 1, 1) !~ /[<>]/)) return i - 1
  }
  return n
}
# The early-exit reader that the masked stage s (raw text r) starts with, or "".
function reader(s, r,   t, nt, i, j, k, w, o, ch) {
  nt = split(s, t, /[ \t\n]+/); i = 1
  while (i <= nt && (t[i] == "" || t[i] == "!" || t[i] == "{" || t[i] == "(" || t[i] == "env" || t[i] == "command" \
         || t[i] == "exec" || t[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/)) i++
  if (i > nt) return ""
  w = t[i]; sub(/^[({!]+/, "", w); sub(/.*\//, "", w)
  if (w == "head" || w == "read") return w
  if (w ~ /^[ef]?grep$/) {
    for (j = i + 1; j <= nt; j++) {
      o = t[j]
      if (o == "--") break
      if (o ~ /^--(quiet|silent|files-with-matches|files-without-match|max-count)/) return "grep " o
      if (o !~ /^-[A-Za-z]/) continue
      for (k = 2; k <= length(o); k++) {
        ch = substr(o, k, 1)
        if (ch ~ /[qlLm]/) return "grep -" ch
        if (ch ~ /[efABCdD]/) { if (k == length(o)) j++; break }
      }
    }
    if (s ~ /(^|[ \t])(1?>|&>)[ \t]*\/dev\/null/) return "grep with its output sent to /dev/null"
    return ""
  }
  if (w == "sed" && r ~ sedq) return "sed with a q command"
  if (w ~ /^[gmn]?awk$/ && r ~ /(^|[^A-Za-z0-9_])exit([^A-Za-z0-9_]|$)/) return "awk with exit"
  return ""
}
function check(m, r, line,   i, n, np, pos, k, st, en, len, why, pre, opens, closes) {
  if (r ~ /#[ \t]*pipefail-ok:[ \t]*[^ \t\n]/) return
  n = length(m); np = 0
  for (i = 1; i <= n; i++) {
    if (substr(m, i, 1) != "|") continue
    if (substr(m, i + 1, 1) == "|") { i++; continue }
    if (i > 1 && substr(m, i - 1, 1) == ">") continue
    pos[++np] = i
  }
  for (k = 1; k <= np; k++) {
    st = pos[k] + 1; if (substr(m, st, 1) == "&") st++
    while (substr(m, st, 1) ~ /[ \t\n]/) st++
    en = (k < np ? pos[k + 1] : n + 1)
    len = simple(substr(m, st, en - st))
    why = reader(substr(m, st, len), substr(r, st, len))
    if (why == "") continue
    # a case pattern such as grep|head) is not a pipe: its ) closes no ( before the |
    pre = substr(m, 1, pos[k] - 1); opens = gsub(/\(/, "", pre); pre = substr(m, 1, pos[k] - 1); closes = gsub(/\)/, "", pre)
    if (opens <= closes && substr(m, st) ~ /^[A-Za-z0-9_.\/-]+\)/) continue
    pre = substr(r, 1, st); i = gsub(/\n/, "", pre)
    printf "::error::%s:%d: a pipe into %s can stop reading early and fail under pipefail; use grep -c, sed -n 1,Np or captured output, or mark it # pipefail-ok: <reason>\n", file, line + i, why
    found = 1
  }
}
# Queue the delimiters of the here-documents a logical line opens.
function heredocs(m, r,   i, n, j, c, d, dash) {
  if (index(m, "((")) return
  n = length(m)
  for (i = 1; i < n; i++) {
    if (substr(m, i, 2) != "<<") continue
    if (substr(m, i + 2, 1) == "<") { i += 2; continue }
    j = i + 2; dash = 0
    if (substr(r, j, 1) == "-") { dash = 1; j++ }
    while (substr(r, j, 1) == " " || substr(r, j, 1) == "\t") j++
    c = substr(r, j, 1); if (c == q || c == "\"" || c == "\\") j++
    d = ""; while (substr(r, j, 1) ~ /[A-Za-z0-9_]/) { d = d substr(r, j, 1); j++ }
    if (d != "") { hd[++hdn] = d; hdash[hdn] = dash }
    i = j
  }
}
function finish() { check(mbuf, buf, start); heredocs(mbuf, buf); buf = ""; mbuf = ""; open = 0 }
BEGIN {
  qs = 0; hdi = 1; hdn = 0; open = 0; found = 0
  sedq = "(^|[;{}[:space:]0-9$/" q "\"])[qQ]([;}[:space:]" q "\"0-9]|$)"
}
{
  if (hdi <= hdn) { l = $0; if (hdash[hdi]) sub(/^\t+/, "", l); if (l == hd[hdi]) hdi++; next }
  ml = mask($0)
  if (!open) { start = NR; buf = $0; mbuf = ml; open = 1 } else { buf = buf "\n" $0; mbuf = mbuf sep ml }
  if (qs) { sep = "_"; next }
  if (cont) { sep = " "; next }
  t = mbuf; sub(/[ \t]+$/, "", t)
  if (t ~ /(\||&&)$/) { sep = "\n"; next }
  finish()
}
END { if (open) finish(); exit found }'

if [ $# -eq 0 ]; then
  cd "$(dirname "$0")/.." || exit 2
  files=$(git ls-files -- '*.sh') || { echo "::error::not a git checkout; name the files to check" >&2; exit 2; }
  set --
  while IFS= read -r f; do set -- "$@" "$f"; done <<< "$files"
fi

fail=0; n=0
for f in "$@"; do
  [ -n "$f" ] || continue
  if [ ! -f "$f" ]; then echo "::error::$f: no such file" >&2; fail=1; continue; fi
  grep -qE 'set[[:space:]]+-[A-Za-z]*o[[:space:]]+pipefail' "$f" || continue
  n=$((n + 1))
  LC_ALL=C awk -v file="$f" -v q="'" "$PROG" "$f" >&2 || fail=1
done
if [ "$fail" -ne 0 ]; then echo "pipefail check FAILED" >&2; exit 1; fi
echo "pipefail check passed: $n scripts that set pipefail"
