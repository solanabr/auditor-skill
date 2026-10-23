#!/usr/bin/env bash
# check-pipefail.sh — fail if a shell script that uses pipefail pipes into a reader that can stop before its
# input ends: grep -q, -l, -L or -m (or a long form of these), grep with its output sent to /dev/null, head,
# read, sed with a q command, or awk with exit, also behind env, timeout and the like, a GNU g-prefix, quotes
# or a backslash, and in a >( ) process substitution. When such a reader stops early, the command writing into
# the pipe gets SIGPIPE and, under pipefail, the pipeline fails even though the reader found what it wanted;
# it shows only once the input outgrows a pipe (64 KiB). Count with grep -c, print with sed -n '1,Np', or
# capture the output first. A pipe meant to stop early carries a comment "# pipefail-ok: <reason>" on its line.
# Any script that mentions pipefail is checked. Quoted text and here-documents are not read as code (a pipe
# inside sh -c "…" runs without pipefail), but the code of a $( ) or backtick substitution is, inside double
# quotes too; the | of a [[ =~ ]] pattern and of a case pattern is not a pipe.
# Usage: bash scripts/check-pipefail.sh [FILE...]   (default: every tracked *.sh file). Exit 0 = none found.
# Needs bash >= 3.2, awk, grep, and git for the default file list.
set -uo pipefail

PROG='
# One physical line, masked: text inside quotes becomes _, a comment becomes spaces, and an escaped character
# becomes _, so only shell syntax is left, with the same length as the input. The code of a $( ) or backtick
# command substitution stays visible, inside double quotes too. The quote state carries across lines: leaf is
# 1 inside single quotes and 3 inside an ANSI-C string; stk[1..sp] holds the open contexts (c code,
# d double quotes, b backticks) and pd[] the open parentheses of each $( ). cont is set by a trailing
# backslash, and ctext collects the comments.
function mask(t,   i, n, c, o, com, x) {
  o = ""; n = length(t); cont = 0; com = 0
  for (i = 1; i <= n; i++) {
    c = substr(t, i, 1)
    if (com) { o = o " "; continue }
    if (leaf == 1) { if (c == q) { leaf = 0; o = o c } else o = o "_"; continue }
    if (leaf == 3) {
      if (c == "\\") { o = o "_"; if (i < n) { o = o "_"; i++ } continue }
      if (c == q) { leaf = 0; o = o c } else o = o "_"
      continue
    }
    x = stk[sp]
    if (x == "d") {
      if (c == "\\") { o = o "_"; if (i < n) { o = o "_"; i++ } continue }
      if (c == "\"") { sp--; o = o c; continue }
      if (c == "$" && substr(t, i + 1, 1) == "(") { stk[++sp] = "c"; pd[sp] = 1; o = o "$("; i++; continue }
      if (c == "`") { stk[++sp] = "b"; o = o c; continue }
      o = o "_"; continue
    }
    if (c == "\\") { if (i == n) { cont = 1; o = o " " } else { o = o "__"; i++ } continue }
    if (c == q) { leaf = 1; o = o c; continue }
    if (c == "\"") { stk[++sp] = "d"; o = o c; continue }
    if (c == "$" && substr(t, i + 1, 1) == q) { leaf = 3; o = o "$" q; i++; continue }
    if (c == "$" && substr(t, i + 1, 1) == "(") { stk[++sp] = "c"; pd[sp] = 1; o = o "$("; i++; continue }
    if (c == "`") { if (x == "b") sp--; else stk[++sp] = "b"; o = o c; continue }
    if (c == "(" && x == "c" && sp > 1) pd[sp]++
    if (c == ")" && x == "c" && sp > 1 && --pd[sp] == 0) sp--
    if (c == "#" && (i == 1 || substr(t, i - 1, 1) ~ /[ \t;&|()]/)) { com = 1; ctext = ctext substr(t, i) "\n"; o = o " "; continue }
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
# Split the masked stage s into words, with the raw text r of each: tm[1..n], tw[1..n].
function words(s, r,   i, n, c, st) {
  n = 0; st = 0
  for (i = 1; i <= length(s) + 1; i++) {
    c = (i <= length(s)) ? substr(s, i, 1) : " "
    if (c ~ /[ \t\n]/) { if (st) { n++; tm[n] = substr(s, st, i - st); tw[n] = substr(r, st, i - st); st = 0 } }
    else if (!st) st = i
  }
  return n
}
# A GNU long option given in full or by an unambiguous prefix: --qui for --quiet.
function longopt(o,   i, n, f) {
  sub(/=.*/, "", o); n = split("--quiet:3 --silent:3 --files-with-matches:13 --files-without-match:13 --max-count:4", lo, " ")
  for (i = 1; i <= n; i++) { split(lo[i], f, ":"); if (length(o) >= f[2] + 0 && index(f[1], o) == 1) return 1 }
  return 0
}
# The early-exit reader that the masked stage s (raw text r) starts with, or "".
function reader(s, r,   nt, i, j, k, w, o, ch) {
  nt = words(s, r); i = 1
  while (i <= nt) {
    w = tm[i]
    if (w == "!" || w == "{" || w == "(" || w == "if" || w ~ /^[A-Za-z_][A-Za-z0-9_]*=/) { i++; continue }
    if (w ~ /^(env|command|builtin|exec|nohup|time|nice|stdbuf|timeout|sudo)$/) {
      i++; while (i <= nt && (tm[i] ~ /^-/ || tm[i] ~ /^[0-9.]+[smhd]?$/ || tm[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/)) i++
      continue
    }
    break
  }
  if (i > nt) return ""
  w = tw[i]; gsub(unq, "", w); sub(/^[({!]+/, "", w); sub(/.*\//, "", w)
  if (w ~ /^g?head$/ || w == "read") return w
  if (w ~ /^g?[ef]?grep$/) {
    for (j = i + 1; j <= nt; j++) {
      o = tm[j]
      if (o == "--") break
      if (o ~ /^--/) { if (longopt(o)) return "grep " o; continue }
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
  if (w ~ /^g?sed$/ && r ~ sedq) return "sed with a q command"
  if (w ~ /^[gmn]?awk$/ && r ~ /(^|[^A-Za-z0-9_])exit([^A-Za-z0-9_]|$)/) return "awk with exit"
  return ""
}
function check(m, r, line,   i, n, np, pos, k, st, en, len, why, pre, opens, closes, dbl) {
  if (ctext ~ /(^|\n)#[ \t]*pipefail-ok:[ \t]*[^ \t\n]/) return
  n = length(m); np = 0; dbl = 0
  for (i = 1; i <= n; i++) {
    # the | of a regular expression in [[ ... =~ ... ]] is not a pipe
    if (substr(m, i, 2) == "[[" && (i == 1 || substr(m, i - 1, 1) ~ /[ \t;&|(!]/)) { dbl = 1; i++; continue }
    if (substr(m, i, 2) == "]]" && dbl) { dbl = 0; i++; continue }
    if (dbl) continue
    # a process substitution >( ) reads what the command writes into it, as a pipe does
    if (substr(m, i, 2) == ">(") { pos[++np] = i + 1; i++; continue }
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
function heredocs(m, r,   i, n, j, c, d, dash, e) {
  if (index(m, "((")) return
  n = length(m)
  for (i = 1; i < n; i++) {
    if (substr(m, i, 2) != "<<") continue
    if (substr(m, i + 2, 1) == "<") { i += 2; continue }
    j = i + 2; dash = 0
    if (substr(r, j, 1) == "-") { dash = 1; j++ }
    while (substr(r, j, 1) == " " || substr(r, j, 1) == "\t") j++
    c = substr(r, j, 1); d = ""
    if (c == q || c == "\"") { e = index(substr(r, j + 1), c); if (e) d = substr(r, j + 1, e - 1); j += e + 1 }
    else { if (c == "\\") j++; while (j <= n && substr(r, j, 1) !~ /[ \t;&|<>()]/) { d = d substr(r, j, 1); j++ } }
    if (d != "") { hd[++hdn] = d; hdash[hdn] = dash }
    i = j
  }
}
function finish() { check(mbuf, buf, start); heredocs(mbuf, buf); buf = ""; mbuf = ""; ctext = ""; open = 0 }
BEGIN {
  leaf = 0; sp = 1; stk[1] = "c"; hdi = 1; hdn = 0; open = 0; found = 0
  sedq = "(^|[;{}[:space:]0-9$/" q "\"])[qQ]([;}[:space:]" q "\"0-9]|$)"
  unq = "[\\\\\"" q "]"
}
{
  if (hdi <= hdn) { l = $0; if (hdash[hdi]) sub(/^\t+/, "", l); if (l == hd[hdi]) hdi++; next }
  ml = mask($0)
  if (!open) { start = NR; buf = $0; mbuf = ml; open = 1 } else { buf = buf "\n" $0; mbuf = mbuf sep ml }
  if (leaf || sp > 1) { sep = (stk[sp] == "d" || leaf) ? "_" : "\n"; next }
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
  grep -q pipefail "$f" || continue
  n=$((n + 1))
  LC_ALL=C awk -v file="$f" -v q="'" "$PROG" "$f" >&2 || fail=1
done
if [ "$fail" -ne 0 ]; then echo "pipefail check FAILED" >&2; exit 1; fi
echo "pipefail check passed: $n scripts that use pipefail"
