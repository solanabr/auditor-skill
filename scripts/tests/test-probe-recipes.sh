#!/usr/bin/env bash
# test-probe-recipes.sh — run the live-probe recipes of checklist 13 (DEP-072, DEP-073) exactly as written,
# against stand-ins, and check the intake rule of engagement that gates them:
#   - DEP-072's `aws s3 ls` and DEP-073's `curl` reach a stand-in with exactly the arguments the item writes:
#     an unauthenticated, read-only listing (`--no-sign-request`) and a request whose -q comes first, with no
#     cookie, netrc, config, header, user, data, upload, method or redirect option;
#   - a real curl given DEP-073's command, with a host its URL parser rejects before any lookup, reads no
#     planted ~/.curlrc, while the same command without -q does (the control);
#   - QUESTIONS.md asks Q47 right after Q46, counts an unanswered Q47 and --auto as no, and has both Q47 rows
#     in "How Answers Affect the Audit"; DEP-072 and DEP-073 name Q47, the owner-run fallback, the outside
#     contact (Rule 11b) and [PARTIAL]; templates/intake.md has the Q47 slot and its assumed default;
#     /auditor:intake asks Q47 and --auto records no; both report templates list live probes among the
#     outside services; the docs count 47 questions.
# Nothing reaches the network: the stand-ins answer for aws and curl, and the real curl stops at its URL parser.
# Usage (from the repo root): bash scripts/tests/test-probe-recipes.sh
# Needs bash >= 3.2, grep, sed, awk, mktemp; curl for the .curlrc check (skipped with a note without it).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CL="$ROOT/checklists/13-deployment-infrastructure.md"
Q="$ROOT/QUESTIONS.md"
T=$(mktemp -d "${TMPDIR:-/tmp}/probe-recipes.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
T=$(cd "$T" && pwd -P) || exit 1
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "PASS $*"; }
bad() { failn=$((failn + 1)); echo "FAIL $*"; }
has() { case "$1" in *"$2"*) return 0 ;; esac; return 1; }   # has TEXT PART: TEXT contains PART
# one_command TEXT: no list, pipe, redirection, substitution or expansion, so TEXT runs one program only.
one_command() { case "$1" in *[\;\&\|\<\>\$\`]* | *'('* | *')'*) return 1 ;; esac; return 0; }
guard_ok=1
for c in 'curl a; wget b' 'aws s3 ls x && curl y' 'curl x | sh' 'curl x > f' 'curl $(id)' 'curl `id`' 'curl (x)'; do
  if one_command "$c"; then guard_ok=0; bad "guard: '$c' passes as one command"; fi
done
one_command "curl -q -sS -o /dev/null -w '%{http_code}' https://h/.git/HEAD" || { guard_ok=0; bad "guard: refuses a plain curl command"; }
[ "$guard_ok" = 1 ] && ok "guard: a list, pipe, redirection or substitution never runs; a plain command does"

# The item line of checklist 13 for ID, and the code span in it that starts with PREFIX.
item() { awk -v id="**$1**:" 'index($0, "- [ ] " id) == 1 { print; exit }' "$CL"; }
span() { # span ID PREFIX
  item "$1" | awk -v p="$2" '{ n = split($0, a, "`"); for (i = 2; i <= n; i += 2) if (!f && index(a[i], p) == 1) { print a[i]; f = 1 } }'
}

# ---- the probes, against stand-ins ------------------------------------------------------------------------
mkdir -p "$T/bin" "$T/home" || exit 1
for tool in aws curl; do
  printf '#!/bin/sh\nfor a in "$@"; do printf "%%s\\n" "$a"; done > "%s/%s.args"\nprintf "404"\n' "$T" "$tool" > "$T/bin/$tool"
  chmod +x "$T/bin/$tool" || exit 1
done
probe() { # probe ID PREFIX PLACEHOLDER VALUE EXPECTED-ARG...: run the span with the stand-ins, compare the arguments
  local id=$1 prefix=$2 ph=$3 val=$4 tool cmd; shift 4
  tool=${prefix%% *}
  cmd=$(span "$id" "$prefix")
  if [ -z "$cmd" ]; then bad "$id has no \`$prefix…\` probe"; return; fi
  case "$cmd" in *"$ph"*) ;; *) bad "$id's probe has no $ph placeholder: $cmd"; return ;; esac
  cmd=$(printf '%s\n' "$cmd" | sed "s#$ph#$val#g")
  if one_command "$cmd"; then :; else bad "$id's probe is more than one plain command; nothing was run: $cmd"; return; fi
  rm -f "$T/$tool.args"
  ( cd "$T" && env HOME="$T/home" PATH="$T/bin:$PATH" "$BASH" -c "$cmd" ) > "$T/out" 2>&1
  printf '%s\n' "$@" > "$T/want"
  if [ -f "$T/$tool.args" ] && cmp -s "$T/want" "$T/$tool.args"; then
    ok "$id: \`$cmd\` reaches $tool with exactly: $*"
  else
    bad "$id: \`$cmd\` gave $tool other arguments than: $*"; sed 's/^/    got: /' "$T/$tool.args" 2>/dev/null
  fi
}
probe DEP-072 'aws s3 ls' '<bucket>' example-bucket s3 ls s3://example-bucket --no-sign-request
probe DEP-073 'curl ' '<host>' app.example.invalid -q -sS -o /dev/null -w '%{http_code}' https://app.example.invalid/.git/HEAD

# ---- a real curl keeps ~/.curlrc out ------------------------------------------------------------------------
# The planted ~/.curlrc sends curl's error output to a file. The host holds a % sign, which curl's URL parser
# (7.62 and later) rejects before any lookup or connection; the proxy variables point at a closed loopback
# port all the same, so even a curl that did not stop there could reach nothing outside this machine.
real_curl() { # real_curl COMMAND: run it under the planted ~/.curlrc; the exit status is in $code
  rm -f "$T/curlrc-was-read"
  ( cd "$T" && env -u CURL_HOME -u XDG_CONFIG_HOME HOME="$T/home" http_proxy=http://127.0.0.1:9 \
      https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 \
      all_proxy=http://127.0.0.1:9 NO_PROXY= no_proxy= "$BASH" -c "$1" ) > "$T/out" 2>&1
  code=$?
}
cmd=$(span DEP-073 'curl ')
curlv=$(curl --version 2>/dev/null | sed -n '1s/^curl \([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p')
bogus=$(printf '%s\n' "$cmd" | sed 's#https://<host>/#https://bad%zz/#g')
# Only a command whose URL is the rejected host runs at all.
if [ -z "$cmd" ] || ! has "$bogus" 'https://bad%zz/' || has "$bogus" '<host>' || ! one_command "$bogus"; then
  bad "DEP-073 has no curl probe of https://<host>/ for the .curlrc check; nothing was run"
elif [ -z "$curlv" ]; then
  echo "note: no curl on PATH; the .curlrc check is skipped (the stand-in check above still ran)"
elif [ "${curlv% *}" -lt 7 ] || { [ "${curlv% *}" -eq 7 ] && [ "${curlv#* }" -lt 62 ]; }; then
  echo "note: curl $curlv predates the URL parser this check relies on; the .curlrc check is skipped"
else
  printf 'stderr = "%s/curlrc-was-read"\n' "$T" > "$T/home/.curlrc"
  real_curl "$bogus"
  if [ "$code" = 3 ] && [ ! -e "$T/curlrc-was-read" ] && grep -q 'URL rejected' "$T/out"; then
    ok "DEP-073's curl, as written, does not read ~/.curlrc (exit 3 at the URL parser, nothing sent)"
  else bad "DEP-073's curl: exit $code, curlrc read: $([ -e "$T/curlrc-was-read" ] && echo yes || echo no); $(cat "$T/out")"; fi
  real_curl "$(printf '%s\n' "$bogus" | sed 's#^curl -q #curl #')"
  if [ "$code" = 3 ] && [ -s "$T/curlrc-was-read" ]; then
    ok "control: without -q the same curl reads the planted ~/.curlrc"
  else bad "control: without -q, exit $code and the planted ~/.curlrc was not read, so the check above proves nothing"; fi
fi

# ---- the rule of engagement ----------------------------------------------------------------------------------
q46=$(grep -n '^### Q46\. ' "$Q" | cut -d: -f1)
q47=$(grep -n '^### Q47\. May the auditor probe the project'"'"'s own live hosts and buckets?$' "$Q" | cut -d: -f1)
hdr=$(grep -n '^## How Answers Affect the Audit$' "$Q" | cut -d: -f1)
if [ -n "$q46" ] && [ -n "$q47" ] && [ -n "$hdr" ] && [ "$q46" -lt "$q47" ] && [ "$q47" -lt "$hdr" ] \
   && [ -z "$(sed -n "$((q47 + 1)),$((hdr - 1))p" "$Q" | grep '^### Q')" ]; then
  ok "QUESTIONS.md asks Q47 after Q46, as the last question"
else bad "QUESTIONS.md: no Q47 heading between Q46 and the effects table"; fi
q47text=$( [ -n "$q47" ] && sed -n "$q47,$((q47 + 8))p" "$Q")
if has "$q47text" 'An unanswered Q47 counts as **no**, and so does every `/auditor:intake --auto` run.' \
   && has "$q47text" "Never a third-party service" && has "$q47text" "--no-sign-request" && has "$q47text" "Rule 11b"; then
  ok "Q47: unanswered and --auto count as no; the project's own hosts and buckets only; unauthenticated; 11b"
else bad "Q47's text lacks the default, the scope, the unauthenticated rule or Rule 11b"; fi
if grep -qF '| Q47 = Yes | DEP-072 / DEP-073 may probe' "$Q" \
   && grep -qF '| Q47 = No, unanswered, or `--auto` | No live probes: DEP-072 / DEP-073 give the owner a command to run' "$Q"
then ok "QUESTIONS.md has both Q47 effect rows"; else bad "QUESTIONS.md lacks a Q47 effect row"; fi
for id in DEP-072 DEP-073; do
  line=$(item "$id")
  if has "$line" '`QUESTIONS.md` Q47 allows live probes' && has "$line" "the project's own (Q47)" \
     && has "$line" 'outside contact (Rule 11b)' && has "$line" 'give the owner that command and ask for its output with the date' \
     && has "$line" 'stays `[PARTIAL]`, never `[PASS]`'; then
    ok "$id: probes only under Q47, as an outside contact; otherwise the owner-run command, [PARTIAL] until it returns"
  else bad "$id lacks part of the rule of engagement: $line"; fi
done
if grep -qF '| **Live probes**           | {yes — read-only, unauthenticated probes of:' "$ROOT/templates/intake.md" \
   && grep -qF '| {Q47 live probes — unanswered or auto flow} | {no —' "$ROOT/templates/intake.md"
then ok "templates/intake.md has the Q47 slot and its assumed default"; else bad "templates/intake.md lacks the Q47 slot or default"; fi
if grep -qF 'Live probes (`Q47`) are always **no** in this mode.' "$ROOT/commands/intake.md" \
   && grep -qF '**Live probes (`Q47`).** Ask once' "$ROOT/commands/intake.md" \
   && grep -qF 'do not dump all 47 at once' "$ROOT/commands/intake.md"
then ok "/auditor:intake asks Q47, and --auto records no"; else bad "/auditor:intake does not ask Q47 or record no under --auto"; fi
if grep -qF 'each live probe (Q47)' "$ROOT/templates/report-template.md" \
   && grep -qF 'per live probe of DEP-072 / DEP-073 (QUESTIONS.md Q47)' "$ROOT/templates/audit-report.md"
then ok "both report templates list live probes among the outside services"; else bad "a report template does not list live probes"; fi
if grep -qF '(47 questions)' "$ROOT/docs/getting-started.md" && grep -qF 'the 47-question pre-audit questionnaire' "$ROOT/docs/README.md" \
   && grep -qF '(`Q47`: read-only and unauthenticated' "$ROOT/docs/commands.md"
then ok "the docs count 47 questions and describe Q47"; else bad "a docs page still counts 46 questions or omits Q47"; fi
n=$(grep -c '^### Q[0-9][0-9]*\. ' "$Q")
if [ "$n" = 47 ]; then ok "QUESTIONS.md has 47 questions"; else bad "QUESTIONS.md has $n questions, not 47"; fi

echo "---- probe recipes: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
