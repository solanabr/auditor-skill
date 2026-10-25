#!/usr/bin/env bash
# test-probe-recipes.sh — run the live-probe recipes of checklist 13 (DEP-072, DEP-073; the "Live probes" block
# after DEP-077) exactly as written, against stand-ins, and check the intake rule of engagement that gates them:
#   - every command an item quotes is one plain command (quoted &, $ and the like allowed), starts with its
#     tool's bare name, and appears word for word in the block;
#   - the block, run with PATH holding only the stand-ins and env, mkdir and grep, calls the stand-in aws with
#     exactly `s3api list-objects-v2 --bucket <bucket> --page-size 1 --max-items 1 --query KeyCount --output
#     text --no-sign-request --region us-east-1`, the AWS profile, endpoint and CA variables cleared and the config
#     and credentials files /dev/null (canary values are set beforehand), and
#     the stand-in curl with exactly the GCS, Azure, .git/HEAD and made-up-path requests the block writes, each
#     with -q first and --max-time 30;
#   - a host, bucket, Azure account or container outside the grammar (a user, a port, a path, IPv6, a non-ASCII
#     or uppercase name, an underscore, a space, a semicolon, $( ), a leading or trailing . or -, .., a - in an
#     account, a . in a container, a name too short or too long) is refused, and its probe never runs;
#   - the verdict line prints 1 only for a git HEAD body (ref: refs/…, a 40 or 64 hex id), its anchors pinned;
#   - a real curl given DEP-073's command, with a host its URL parser rejects before any lookup, reads no planted
#     ~/.curlrc, while the same command without -q does (the control);
#   - QUESTIONS.md asks Q47 right after Q46, counts an unanswered Q47 and --auto as no, states the grammar and
#     how intake lists hosts, and has both Q47 rows; DEP-072 and DEP-073 name Q47, intake.md §8, the outside
#     contact, the grammar, the owner-run fallback and "never [PASS]"; templates/intake.md has the slot and its
#     default; /auditor:intake asks Q47 and --auto records no; both report templates list live probes; the docs
#     count 47 questions.
# Nothing reaches the network: the stand-ins answer for aws and curl, and the real curl stops at its URL parser.
# Usage (from the repo root): bash scripts/tests/test-probe-recipes.sh
# Needs bash >= 3.2, grep, sed, awk, env, mkdir, mktemp; curl for the .curlrc check (skipped with a note without it).
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

# one_command TEXT: status 0 when TEXT, read as the shell reads it, is one plain command: no ; & | < > ( ) or
# backtick outside quotes, and no $( or backtick inside double quotes. Inside single quotes anything goes.
one_command() {
  local s=$1 i c q=""
  i=0
  while [ "$i" -lt "${#s}" ]; do
    c=${s:$i:1}
    case "$q" in
      "'") [ "$c" = "'" ] && q="" ;;
      '"') case "$c" in
             '"') q="" ;;
             '`') return 1 ;;
             '$') [ "${s:$((i + 1)):1}" = "(" ] && return 1 ;;
           esac ;;
      *) case "$c" in
           "'") q="'" ;;
           '"') q='"' ;;
           ';'|'&'|'|'|'<'|'>'|'('|')'|'`') return 1 ;;
           '$') [ "${s:$((i + 1)):1}" = "(" ] && return 1 ;;
         esac ;;
    esac
    i=$((i + 1))
  done
  [ -z "$q" ]
}
guard_ok=1
for c in 'curl a; wget b' 'aws s3 ls x && curl y' 'curl x | sh' 'curl x > f' 'curl $(id)' 'curl `id`' 'curl (x)' \
         'curl "$(id)"' 'curl "a`id`"' "curl 'unclosed"; do
  if one_command "$c"; then guard_ok=0; bad "guard: '$c' passes as one command"; fi
done
for c in "curl -q -sS -o /dev/null -w '%{http_code}' 'https://h/c?restype=container&comp=list'" \
         "LC_ALL=C grep -cE '^(ref: refs/|[0-9a-f]{40}\$)' f" 'curl -q "https://$h/x"'; do
  one_command "$c" || { guard_ok=0; bad "guard: refuses the plain command $c"; }
done
[ "$guard_ok" = 1 ] && ok "guard: a list, pipe, redirection or substitution never runs; a quoted & or \$ is plain"

# The item line of checklist 13 for ID, and every code span in it that starts with PREFIX.
item() { awk -v id="**$1**:" 'index($0, "- [ ] " id) == 1 { print; exit }' "$CL"; }
spans() { # spans ID PREFIX
  item "$1" | awk -v p="$2" '{ n = split($0, a, "`"); for (i = 2; i <= n; i += 2) if (index(a[i], p) == 1) print a[i] }'
}
# The bash lines of the quoted "Live probes" block that follows DEP-077, "> " removed.
block() {
  awk 'index($0, "> **Live probes (DEP-072, DEP-073).**") == 1 { s = 1; next }
       s && $0 == "> ```" { if (c) exit; c = 1; next }
       s && c { sub(/^> ?/, ""); print }' "$CL"
}
B=$(block)
if [ -n "$B" ]; then ok "checklist 13 has the Live probes block"; else bad "checklist 13 has no Live probes block after DEP-077"; fi

# ---- the commands the items quote -------------------------------------------------------------------------------
want_spans() { # want_spans ID PREFIX COUNT
  local id=$1 prefix=$2 n=$3 got sp all=1
  got=$(spans "$id" "$prefix" | grep -c '' || true)
  if [ "$got" != "$n" ]; then bad "$id quotes $got commands that start with '$prefix', not $n"; return; fi
  while IFS= read -r sp; do
    one_command "$sp" || { all=0; bad "$id: '$sp' is not one plain command"; }
    case "$sp" in curl\ -q\ * | env\ -u\ * | LC_ALL=C\ grep\ *) ;; *) all=0; bad "$id: '$sp' does not start with its tool's bare name" ;; esac
    has "$B" "$sp" || { all=0; bad "$id: '$sp' is not in the Live probes block word for word"; }
  done <<EOF
$(spans "$id" "$prefix")
EOF
  [ "$all" = 1 ] && ok "$id: its $n '$prefix' command(s) are plain, start with the bare tool name and match the block"
}
want_spans DEP-072 'env -u ' 1
want_spans DEP-072 'curl ' 2
want_spans DEP-073 'curl ' 1
want_spans DEP-073 'LC_ALL=C grep ' 1
if [ -n "$B" ] && [ -z "$(printf '%s\n' "$B" | grep -E '(^|[^A-Za-z0-9_-])/[^ ]*/(curl|aws|grep|env)( |$)')" ]; then
  ok "the block calls no tool by an absolute path, so the stand-ins below see every call"
else bad "the block calls a tool by an absolute path"; fi

# ---- the block, against stand-ins -----------------------------------------------------------------------------
# PATH holds only these: stand-in aws and curl, which log their arguments and the environment names that matter,
# and the real env, mkdir and grep. Any other program the block named would not be found.
mkdir -p "$T/bin" "$T/home" "$T/r" || exit 1
for tool in env mkdir grep; do
  p=$(command -v "$tool") && ln -s "$p" "$T/bin/$tool" || { echo "no $tool on PATH" >&2; exit 1; }
done
cat > "$T/bin/aws" <<EOF
#!/bin/sh
{ printf 'call aws\n'; for a in "\$@"; do printf 'arg=%s\n' "\$a"; done
  for v in AWS_PROFILE AWS_DEFAULT_PROFILE AWS_ENDPOINT_URL AWS_ENDPOINT_URL_S3 AWS_CA_BUNDLE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE; do
    eval "printf 'env %s=%s\n' \$v \"\\\${\$v-unset}\""
  done; } >> "$T/calls.log"
printf '0\n'
EOF
cat > "$T/bin/curl" <<EOF
#!/bin/sh
{ printf 'call curl\n'; for a in "\$@"; do printf 'arg=%s\n' "\$a"; done
  printf 'env CURL_HOME=%s\n' "\${CURL_HOME-unset}"; } >> "$T/calls.log"
out=""; prev=""
for a in "\$@"; do [ "\$prev" = -o ] && out=\$a; prev=\$a; done
[ -n "\$out" ] && [ "\$out" != /dev/null ] && printf '%s\n' "\${STANDIN_BODY-}" > "\$out"
printf '200 \n'
EOF
chmod +x "$T/bin/aws" "$T/bin/curl" || exit 1
fill() { # fill BUCKET HOST ACCOUNT CONTAINER > the block with its placeholders filled
  printf '%s\n' "$B" | awk -v b="$1" -v h="$2" -v a="$3" -v c="$4" -v r="$T/r" '
    function rep(s, k, v,   o, i) { o = ""; while ((i = index(s, k)) > 0) { o = o substr(s, 1, i - 1) v; s = substr(s, i + length(k)) } return o s }
    { s = rep($0, "<bucket>", b); s = rep(s, "<host>", h); s = rep(s, "<account>", a); s = rep(s, "<container>", c)
      print rep(s, "<R>", r) }'
}
canary() { # canary FILE: run FILE with PATH limited to $T/bin and canary values in every variable the S3 probe clears
  ( cd "$T" && env HOME="$T/home" CURL_HOME="$T/home" AWS_PROFILE=canary AWS_DEFAULT_PROFILE=canary \
      AWS_ENDPOINT_URL=http://canary.invalid AWS_ENDPOINT_URL_S3=http://canary.invalid AWS_CA_BUNDLE="$T/canary.pem" \
      AWS_CONFIG_FILE="$T/canary-config" AWS_SHARED_CREDENTIALS_FILE="$T/canary-credentials" \
      STANDIN_BODY="ref: refs/heads/main" PATH="$T/bin" "$BASH" "$1" ) > "$T/out" 2>&1
}
rm -f "$T/calls.log"
fill example-bucket app.example.invalid examplestore assets > "$T/good.sh"
canary "$T/good.sh"
{
  printf 'call aws\n'
  printf 'arg=%s\n' s3api list-objects-v2 --bucket example-bucket --page-size 1 --max-items 1 --query KeyCount \
    --output text --no-sign-request --region us-east-1
  printf 'env %s\n' AWS_PROFILE=unset AWS_DEFAULT_PROFILE=unset AWS_ENDPOINT_URL=unset AWS_ENDPOINT_URL_S3=unset \
    AWS_CA_BUNDLE=unset AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 -o /dev/null -w '%{http_code}' 'https://storage.googleapis.com/storage/v1/b/example-bucket/o?maxResults=1'
  printf 'env CURL_HOME=%s\n' "$T/home"
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 -o /dev/null -w '%{http_code}' 'https://examplestore.blob.core.windows.net/assets?restype=container&comp=list&maxresults=1'
  printf 'env CURL_HOME=%s\n' "$T/home"
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 --max-filesize 65536 -o "$T/r/probes/dep-073-app.example.invalid.txt" \
    -w '%{http_code} %{redirect_url}\n' https://app.example.invalid/.git/HEAD
  printf 'env CURL_HOME=%s\n' "$T/home"
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 --max-filesize 65536 -o /dev/null -w '%{http_code}\n' \
    https://app.example.invalid/.git/no-such-file-a7f3
  printf 'env CURL_HOME=%s\n' "$T/home"
} > "$T/want"
if [ -f "$T/calls.log" ] && cmp -s "$T/want" "$T/calls.log"; then
  ok "the block calls aws once (profile, endpoint and CA cleared, config and credentials /dev/null) and curl four times, each exactly as written"
else
  bad "the block's calls differ from what it writes:"; diff "$T/want" "$T/calls.log" 2>&1 | sed 's/^/    /'
fi
if [ "$(sed -n 's/^1$/one/p' "$T/out")" = one ] && ! grep -q refused "$T/out"; then
  ok "with a git HEAD saved, the verdict line prints 1, and no value was refused"
else bad "good values: the verdict line did not print 1, or a value was refused: $(cat "$T/out")"; fi

# ---- values outside the grammar are refused, and their probe never runs ------------------------------------------
# Each value goes in single quotes, so a semicolon or $( ) in it starts nothing. A single quote would end those
# quotes, which no check inside the block can see; the items say to check a value against the rule before filling.
refused() { # refused LABEL BUCKET HOST ACCOUNT CONTAINER MUST-NOT-CALL...
  local label=$1 f; shift
  fill "$1" "$2" "$3" "$4" > "$T/bad.sh"; shift 4
  rm -f "$T/calls.log"
  canary "$T/bad.sh"
  for f in "$@"; do
    if [ -f "$T/calls.log" ] && grep -qF -- "$f" "$T/calls.log"; then bad "$label: '$f' reached a stand-in"; return; fi
  done
  if grep -q 'not found' "$T/out"; then bad "$label: the block tried to run another program: $(cat "$T/out")"; return; fi
  if grep -q '^refused: ' "$T/out"; then ok "$label: refused, and its probe never ran"
  else bad "$label: no refusal printed: $(cat "$T/out")"; fi
}
G=example-bucket; H=app.example.invalid; A=examplestore; K=assets
for b in Example_Bucket 'bucket/prefix' ab "$(printf '%064d' 0 | tr 0 b)" 'my bucket' 'x;y' 'x$(id)' '' \
         .lead trail. -lead trail- 'a..b'; do
  refused "bucket '$b'" "$b" "$H" "$A" "$K" "call aws" "storage/v1/b/$b/o"
done
for h in 'user@app.example.invalid' 'app.example.invalid:8443' '[2001:db8::1]' 'bücher.example' 'app.example.invalid/x' \
         'a b' 'x;y' 'x$(id)' ''; do
  refused "host '$h'" "$G" "$h" "$A" "$K" "arg=https://$h/.git/HEAD" "arg=https://$h/.git/no-such-file-a7f3"
done
for a in Bad_Account ExampleStore ab "$(printf '%025d' 0 | tr 0 a)" ex-store ex.store; do
  refused "Azure account '$a'" "$G" "$H" "$a" "$K" "$a.blob.core.windows.net"
done
for k in Up a.b 'a b' 'a_b'; do
  refused "Azure container '$k'" "$G" "$H" "$A" "$k" "/$k?restype"
done

# ---- the verdict line ------------------------------------------------------------------------------------------
verdict=$(printf '%s\n' "$B" | grep -F 'LC_ALL=C grep -cE ' | sed 's/^host_ok .* && //')
v_check() { # v_check BODY WANT
  printf '%s\n' "$1" > "$T/r/probes/dep-073-v.example.txt"
  got=$(cd "$T" && env PATH="$T/bin" "$BASH" -c "$(printf '%s\n' "$verdict" | sed -e "s#<R>#$T/r#g" -e 's#<host>#v.example#g')" 2>/dev/null)
  [ "$got" = "$2" ]
}
v_all=1
for body in 'ref: refs/heads/main' "$(printf '%040d' 0 | tr 0 a)" "$(printf '%064d' 7)"; do
  v_check "$body" 1 || { v_all=0; bad "verdict: a git HEAD body ($body) does not print 1"; }
done
for body in '<html><body>Welcome</body></html>' 'refs/heads/main' "$(printf '%039d' 0 | tr 0 a)" 'REF: refs/heads/main' \
            '<p>ref: refs/heads/main</p>' "build $(printf '%040d' 0 | tr 0 a)" "$(printf '%040d' 0 | tr 0 a)x" \
            "$(printf '%064d' 0 | tr 0 a)x"; do
  v_check "$body" 0 || { v_all=0; bad "verdict: a body that is not a git HEAD ($body) does not print 0"; }
done
[ -n "$verdict" ] && [ "$v_all" = 1 ] && ok "verdict: 1 only for ref: refs/… or a 40 or 64 hex id, from the start of a line to its end"

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
cmd=$(spans DEP-073 'curl ')
bogus=$(printf '%s\n' "$cmd" | sed -e "s#<R>#$T/r#g" -e 's#https://<host>/#https://bad%zz/#g' -e 's#dep-073-<host>#dep-073-bad#g')
curlv=$(curl --version 2>/dev/null | sed -n '1s/^curl \([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p')
# Only one plain command whose URL is the rejected host runs at all.
if [ -z "$cmd" ] || ! has "$bogus" 'https://bad%zz/' || has "$bogus" '<' || ! one_command "$bogus"; then
  bad "DEP-073 has no plain curl probe of https://<host>/ for the .curlrc check; nothing was run"
elif [ -z "$curlv" ]; then
  echo "note: no curl on PATH; the .curlrc check is skipped (the stand-in checks above still ran)"
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
GRAMMAR='`<host>` is a DNS name or IPv4 address exactly as `intake.md` §8 lists it: ASCII letters, digits, `-` and `.` only (an IDN in its `xn--` form), with no user, port or path. `<bucket>` is 3–63 lowercase letters, digits, `-` and `.`, beginning and ending with a letter or digit, with no `..`. Refuse anything else.'
AZURE='An Azure `<account>` is 3–24 lowercase letters and digits, and its `<container>` lowercase letters, digits and `-`.'
FOUND="show each host or bucket found in the repository's deployment config with its file and line, and list only those the client confirms; nothing found later is added"
NEVER='the item is never `[PASS]`: it is `[PARTIAL]`, or `[FAIL-N]` when the IaC or server config already shows the exposure'
q46=$(grep -n '^### Q46\. ' "$Q" | cut -d: -f1)
q47=$(grep -n '^### Q47\. May the auditor probe the project'"'"'s own live hosts and buckets?$' "$Q" | cut -d: -f1)
hdr=$(grep -n '^## How Answers Affect the Audit$' "$Q" | cut -d: -f1)
if [ -n "$q46" ] && [ -n "$q47" ] && [ -n "$hdr" ] && [ "$q46" -lt "$q47" ] && [ "$q47" -lt "$hdr" ] \
   && [ -z "$(sed -n "$((q47 + 1)),$((hdr - 1))p" "$Q" | grep '^### Q')" ]; then
  ok "QUESTIONS.md asks Q47 after Q46, as the last question"
else bad "QUESTIONS.md: no Q47 heading between Q46 and the effects table"; fi
q47text=$( [ -n "$q47" ] && sed -n "$q47,$((q47 + 8))p" "$Q")
if has "$q47text" 'An unanswered Q47 counts as **no**, and so does every `/auditor:intake --auto` run.' \
   && has "$q47text" "Never a third-party service" && has "$q47text" "$GRAMMAR" && has "$q47text" "$FOUND" \
   && has "$q47text" '(`<app>.vercel.app`) counts when the client names it' && has "$q47text" "Rule 11b"; then
  ok "Q47: unanswered and --auto are no; the grammar; hosts from the config shown with file and line; 11b"
else bad "Q47's text lacks the default, the grammar, the intake listing rule, the platform subdomain rule or 11b"; fi
if grep -qF '| Q47 = Yes | DEP-072 / DEP-073 may probe the hosts and buckets `audit_<n>/intake.md` §8 lists under Live probes' "$Q" \
   && grep -qF '| Q47 = No, unanswered, or `--auto` | No live probes: DEP-072 / DEP-073 give the owner a command to run' "$Q" \
   && grep -qF 'are never `[PASS]` until it arrives: `[PARTIAL]`, or `[FAIL-N]` when the IaC or server config already shows the exposure |' "$Q"
then ok "QUESTIONS.md has both Q47 effect rows"; else bad "QUESTIONS.md lacks a Q47 effect row"; fi
for id in DEP-072 DEP-073; do
  line=$(item "$id")
  if has "$line" '`QUESTIONS.md` Q47 allows live probes' && has "$line" 'that `audit_<n>/intake.md` §8 lists under Live probes' \
     && has "$line" 'outside contact (Rule 11b)' && has "$line" "$GRAMMAR" && has "$line" 'give the owner the' \
     && has "$line" 'with the date' && has "$line" "$NEVER"; then
    ok "$id: probes only under Q47 for what §8 lists, as an outside contact, within the grammar; owner-run otherwise; never [PASS]"
  else bad "$id lacks part of the rule of engagement: $line"; fi
done
if has "$(item DEP-072)" 'how the CLI follows a bucket in another region was not verified offline' \
   && has "$(item DEP-072)" 'prints only a count of keys: `0` or `1`, not `AccessDenied`, means anyone can list it' \
   && has "$(item DEP-072)" "$AZURE"; then
  ok "DEP-072: only a key count, 0 or 1 meaning anyone can list it; the Azure names rule; the region redirect unverified offline"
else bad "DEP-072 lacks the count, the Azure names rule or the unverified-offline note"; fi
pre=$(awk 'index($0, "> **Live probes (DEP-072, DEP-073).**") == 1 { print; exit }' "$CL")
if has "$pre" "$GRAMMAR" && has "$pre" "$AZURE" \
   && has "$pre" 'only this first check catches a single quote; each probe below checks every other value again'; then
  ok "the Live probes block states the grammar, the Azure rule and what only the check before filling catches"
else bad "the Live probes block lacks the grammar, the Azure rule or the single-quote sentence"; fi
line=$(item DEP-073)
if has "$line" 'It is exposed only when the status is `200`' && has "$line" 'confirm it with a made-up path' \
   && has "$line" 'A `3xx` is recorded, and its target is probed only when §8 lists that host too' \
   && has "$line" 'Never print the saved body'; then
  ok "DEP-073: exposed only on 200 with a git HEAD body; a catch-all page is confirmed; a 3xx is followed only to a listed host"
else bad "DEP-073 lacks part of its verdict: $line"; fi
if grep -qF '| **Live probes**           | {yes — read-only, unauthenticated probes of: <each host or bucket the client named, or confirmed from the deployment config at <file>:<line>> / no} (Q47). '"$GRAMMAR"' |' "$ROOT/templates/intake.md" \
   && grep -qF '| {Q47 live probes — unanswered or auto flow} | {no —' "$ROOT/templates/intake.md"
then ok "templates/intake.md has the Q47 slot, with the grammar and file and line, and its assumed default"
else bad "templates/intake.md lacks the Q47 slot, its grammar or its default"; fi
if grep -qF 'Live probes (`Q47`) are always **no** in this mode.' "$ROOT/commands/intake.md" \
   && grep -qF '**Live probes (`Q47`).** Ask once' "$ROOT/commands/intake.md" \
   && grep -qF "${FOUND/the client confirms/the human confirms}" "$ROOT/commands/intake.md" \
   && grep -qF 'do not dump all 47 at once' "$ROOT/commands/intake.md"
then ok "/auditor:intake asks Q47, lists only confirmed hosts and buckets, and --auto records no"
else bad "/auditor:intake does not ask Q47, list confirmed hosts and buckets, or record no under --auto"; fi
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
