#!/usr/bin/env bash
# test-probe-recipes.sh — run the live-probe recipes of checklist 13 (DEP-072, DEP-073; the "Live probes" block
# after DEP-077) exactly as written, against stand-ins, and check the intake rule of engagement that gates them:
#   - every command an item quotes is one plain command (quoted &, $ and the like allowed), starts with its
#     tool's bare name, and appears word for word in the block;
#   - the block, run with PATH holding only the stand-ins and env, mkdir, grep, head and rm, calls the stand-in aws with
#     exactly `s3api list-objects-v2 --bucket <bucket> --no-paginate --query KeyCount --output text
#     --no-sign-request --region us-east-1` and `s3api head-object --bucket <bucket> --key <key> --query
#     ContentLength --output text --no-sign-request --region us-east-1`, the AWS profile, endpoint and CA
#     variables cleared and the config and credentials files /dev/null (canary values are set beforehand), and
#     the stand-in curl with exactly the GCS and Azure listings, the GCS and Azure object reads (headers only),
#     and the .git/HEAD and made-up-path requests the block writes, each with -q first and --max-time 30;
#   - DEP-073 keeps the first 64 KiB of a 1 MiB body that the stand-in curl sends past --max-filesize, as curl
#     before 8.4.0 does with a body whose size the server does not give, in a new file: a link left at the path it
#     saves to is removed, and the file the link names is untouched;
#   - the S3 probes print a key count and an object size: the stand-in aws prints what the AWS CLI v2 prints with
#     --output text, None for a --query outside Contents and CommonPrefixes on a paginated call;
#   - a host, bucket, Azure account or container, or object key, outside the grammar (a user, a port, a path,
#     IPv6, a non-ASCII or uppercase name, an underscore, a space, a semicolon, $( ), a leading or trailing . or -,
#     .., a - in an account, a . in a container, a name too short or too long; a key with a leading /, //, .., a
#     . part, ? # or %) is refused, and its probe never runs;
#   - the verdict line prints 1 only for a git HEAD body (ref: refs/…, a 40 or 64 hex id), its anchors pinned;
#   - a real curl given DEP-073's command, with a host its URL parser rejects before any lookup, reads no planted
#     ~/.curlrc, while the same command without -q does (the control);
#   - QUESTIONS.md asks Q47 right after Q46, counts an unanswered Q47 and --auto as no, states the grammar and
#     how intake lists hosts, and has both Q47 rows; DEP-072 and DEP-073 name Q47, intake.md §8, the outside
#     contact, the grammar, the owner-run fallback and "never [PASS]"; templates/intake.md has the slot and its
#     default; /auditor:intake asks Q47 and --auto records no; both report templates list live probes; the docs
#     count 47 questions.
# It runs docs/power-tools.md's pinned zizmor recipe the same way, against stand-ins for docker, python3, pip and
# zizmor that log where they run and what they get, and checks that:
#   - the container form calls docker with exactly `run --rm --network none -v <checkout>:/src:ro
#     ghcr.io/zizmorcore/zizmor@sha256:<the digest of tag 1.30.1's image index> --offline --no-config --no-ignores
#     --collect=all --persona=auditor /src/.github/workflows`;
#   - the requirement saved for pip is zizmor==1.30.1 with exactly the sha256 of the ten 1.30.1 wheels;
#   - the PyPI lines, started from the checkout, make the environment (python3 -I -m venv) and install into it
#     (pip --require-hashes --only-binary :all: --no-deps) from $HOME, then run zizmor with the container form's
#     flags on .github/workflows from the checkout;
#   - the line that makes the environment, run with the real python3 from a checkout that ships venv.py, runpy.py,
#     ensurepip.py and pip.py, loads none of them;
#   - every zizmor call the docs and the corpus give passes --offline, --no-config, --no-ignores, --collect=all
#     and --persona=auditor, and every docker or podman call names zizmor's image by a sha256 digest;
#   - the check finds power-tools.md's 2 calls, and the 1 call each of discovery/grep-commands.md and
#     references/vuln-classes/github-actions.md;
#   - it reads a call after a $ prompt, a wrapper (sudo, nice, time, command, exec, env), a NAME=value word, or a
#     ;, && or |, and one made through uvx, pipx run or python3 -m.
# Nothing reaches the network: the stand-ins answer for aws, curl, docker, pip and zizmor, the real curl stops at its
# URL parser, and the real python3 sets pip up from the copy it ships with.
# Usage (from the repo root): bash scripts/tests/test-probe-recipes.sh
# Needs bash >= 3.2, grep, sed, awk, env, mkdir, mktemp; curl for the .curlrc check and python3 with venv and
# ensurepip for the environment check (each skipped with a note without it).
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
want_spans DEP-072 'env -u ' 2
want_spans DEP-072 'curl ' 4
want_spans DEP-073 'curl ' 1
want_spans DEP-073 'LC_ALL=C grep ' 1
if [ -n "$B" ] && [ -z "$(printf '%s\n' "$B" | grep -E '(^|[^A-Za-z0-9_-])/[^ ]*/(curl|aws|grep|env)( |$)')" ]; then
  ok "the block calls no tool by an absolute path, so the stand-ins below see every call"
else bad "the block calls a tool by an absolute path"; fi

# ---- the block, against stand-ins -----------------------------------------------------------------------------
# PATH holds only these: stand-in aws and curl, which log their arguments and the environment names that matter,
# and the real env, mkdir and grep. Any other program the block named would not be found.
# The stand-in aws prints what the AWS CLI v2 prints with --output text: list-objects-v2 is paginated unless
# --no-paginate is given, and on a paginated call --query reads each page after the CLI kept only Contents and
# CommonPrefixes, so a query for any other key, KeyCount among them, prints None; head-object is one call.
mkdir -p "$T/bin" "$T/home" "$T/r" || exit 1
for tool in env mkdir grep head rm; do
  p=$(command -v "$tool") && ln -s "$p" "$T/bin/$tool" || { echo "no $tool on PATH" >&2; exit 1; }
done
cat > "$T/bin/aws" <<EOF
#!/bin/sh
{ printf 'call aws\n'; for a in "\$@"; do printf 'arg=%s\n' "\$a"; done
  for v in AWS_PROFILE AWS_DEFAULT_PROFILE AWS_ENDPOINT_URL AWS_ENDPOINT_URL_S3 AWS_CA_BUNDLE AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE; do
    eval "printf 'env %s=%s\n' \$v \"\\\${\$v-unset}\""
  done; } >> "$T/calls.log"
op=""; query=""; paged=1; prev=""
for a in "\$@"; do
  case "\$a" in list-objects-v2|head-object) [ -n "\$op" ] || op=\$a ;; --no-paginate) paged=0 ;; esac
  [ "\$prev" = --query ] && query=\$a
  prev=\$a
done
case "\$op:\$paged:\$query" in
  list-objects-v2:1:Contents*|list-objects-v2:1:CommonPrefixes*) ;;
  list-objects-v2:0:KeyCount) printf '%s\n' "\${STANDIN_KEYCOUNT-0}" ;;
  head-object:*:ContentLength) printf '%s\n' "\${STANDIN_SIZE-0}" ;;
  *) printf 'None\n' ;;
esac
EOF
# The stand-in curl writes the body to the -o file, or to stdout for -o -, and the status to stderr when the -w
# format starts with %{stderr}. Like curl before 8.4.0 with a body whose size the server does not give in advance,
# it ignores --max-filesize: given STANDIN_BODY_FILE, it sends that whole file.
CAT=$(command -v cat) || exit 1
cat > "$T/bin/curl" <<EOF
#!/bin/sh
{ printf 'call curl\n'; for a in "\$@"; do printf 'arg=%s\n' "\$a"; done
  printf 'env CURL_HOME=%s\n' "\${CURL_HOME-unset}"; } >> "$T/calls.log"
out=""; fmt=""; prev=""
for a in "\$@"; do [ "\$prev" = -o ] && out=\$a; [ "\$prev" = -w ] && fmt=\$a; prev=\$a; done
body() { if [ -n "\${STANDIN_BODY_FILE-}" ]; then "$CAT" "\$STANDIN_BODY_FILE"; else printf '%s\n' "\${STANDIN_BODY-}"; fi; }
case "\$out" in
  ''|/dev/null) ;;
  -) body ;;
  *) body > "\$out" ;;
esac
case "\$fmt" in '%{stderr}'*) printf '200 \n' >&2 ;; *) printf '200 \n' ;; esac
EOF
chmod +x "$T/bin/aws" "$T/bin/curl" || exit 1
fill() { # fill BUCKET HOST ACCOUNT CONTAINER KEY > the block with its placeholders filled
  printf '%s\n' "$B" | awk -v b="$1" -v h="$2" -v a="$3" -v c="$4" -v k="$5" -v r="$T/r" '
    function rep(s, k, v,   o, i) { o = ""; while ((i = index(s, k)) > 0) { o = o substr(s, 1, i - 1) v; s = substr(s, i + length(k)) } return o s }
    { s = rep($0, "<bucket>", b); s = rep(s, "<host>", h); s = rep(s, "<account>", a); s = rep(s, "<container>", c)
      s = rep(s, "<key>", k); print rep(s, "<R>", r) }'
}
canary() { # canary FILE: run FILE with PATH limited to $T/bin and canary values in every variable the S3 probes clear
  ( cd "$T" && env HOME="$T/home" CURL_HOME="$T/home" AWS_PROFILE=canary AWS_DEFAULT_PROFILE=canary \
      AWS_ENDPOINT_URL=http://canary.invalid AWS_ENDPOINT_URL_S3=http://canary.invalid AWS_CA_BUNDLE="$T/canary.pem" \
      AWS_CONFIG_FILE="$T/canary-config" AWS_SHARED_CREDENTIALS_FILE="$T/canary-credentials" \
      STANDIN_BODY="ref: refs/heads/main" STANDIN_KEYCOUNT=3 STANDIN_SIZE=17 PATH="$T/bin" "$BASH" "$1" ) > "$T/out" 2>&1
}
aws_env() { # the environment the stand-in aws logs when the probe's env prefix ran
  printf 'env %s\n' AWS_PROFILE=unset AWS_DEFAULT_PROFILE=unset AWS_ENDPOINT_URL=unset AWS_ENDPOINT_URL_S3=unset \
    AWS_CA_BUNDLE=unset AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
}
rm -f "$T/calls.log"
fill example-bucket app.example.invalid examplestore assets static/logo-v2.png > "$T/good.sh"
canary "$T/good.sh"
{
  printf 'call aws\n'
  printf 'arg=%s\n' s3api list-objects-v2 --bucket example-bucket --no-paginate --query KeyCount \
    --output text --no-sign-request --region us-east-1
  aws_env
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 -o /dev/null -w '%{http_code}' 'https://storage.googleapis.com/storage/v1/b/example-bucket/o?maxResults=1'
  printf 'env CURL_HOME=%s\n' "$T/home"
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 -o /dev/null -w '%{http_code}' 'https://examplestore.blob.core.windows.net/assets?restype=container&comp=list&maxresults=1'
  printf 'env CURL_HOME=%s\n' "$T/home"
  printf 'call aws\n'
  printf 'arg=%s\n' s3api head-object --bucket example-bucket --key static/logo-v2.png --query ContentLength \
    --output text --no-sign-request --region us-east-1
  aws_env
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 -I -o /dev/null -w '%{http_code}' 'https://storage.googleapis.com/example-bucket/static/logo-v2.png'
  printf 'env CURL_HOME=%s\n' "$T/home"
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 -I -o /dev/null -w '%{http_code}' 'https://examplestore.blob.core.windows.net/assets/static/logo-v2.png'
  printf 'env CURL_HOME=%s\n' "$T/home"
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 --max-filesize 65536 -o - -w '%{stderr}%{http_code} %{redirect_url}\n' \
    https://app.example.invalid/.git/HEAD
  printf 'env CURL_HOME=%s\n' "$T/home"
  printf 'call curl\n'
  printf 'arg=%s\n' -q -sS --max-time 30 --max-filesize 65536 -o /dev/null -w '%{http_code}\n' \
    https://app.example.invalid/.git/no-such-file-a7f3
  printf 'env CURL_HOME=%s\n' "$T/home"
} > "$T/want"
if [ -f "$T/calls.log" ] && cmp -s "$T/want" "$T/calls.log"; then
  ok "the block calls aws twice (profile, endpoint and CA cleared, config and credentials /dev/null) and curl six times, each exactly as written"
else
  bad "the block's calls differ from what it writes:"; diff "$T/want" "$T/calls.log" 2>&1 | sed 's/^/    /'
fi
if [ "$(sed -n 's/^1$/one/p' "$T/out")" = one ] && ! grep -q refused "$T/out"; then
  ok "with a git HEAD saved, the verdict line prints 1, and no value was refused"
else bad "good values: the verdict line did not print 1, or a value was refused: $(cat "$T/out")"; fi
if grep -qx 3 "$T/out" && grep -qx 17 "$T/out" && ! grep -qx None "$T/out"; then
  ok "the S3 probes print the key count and the object size, as the CLI prints them with these flags, and no None"
else bad "the S3 probes do not print a key count and an object size: $(cat "$T/out")"; fi
# DEP-073 keeps at most 64 KiB of the body whatever the curl version, and never writes through a link left at the
# path it saves to: the stand-in sends 1 MiB past --max-filesize, and that path is a link to a file outside.
awk 'BEGIN { for (i = 0; i < 16384; i++) printf "%063d\n", i }' > "$T/long-body"
printf 'outside\n' > "$T/outside"
saved="$T/r/probes/dep-073-app.example.invalid.txt"
rm -f "$saved" && ln -s "$T/outside" "$saved" || exit 1
( export STANDIN_BODY_FILE="$T/long-body"; canary "$T/good.sh" )
size=$(wc -c < "$saved" 2>/dev/null); size=${size//[!0-9]/}
if [ "$(wc -c < "$T/long-body" | tr -d ' ')" = 1048576 ] && [ "$(cat "$T/outside")" = outside ] && [ -f "$saved" ] \
   && [ ! -L "$saved" ] && [ "${size:-0}" = 65536 ]; then
  ok "DEP-073 keeps the first 64 KiB of a 1 MiB body sent past --max-filesize, in a new file, not through a link at its path"
else bad "DEP-073 on a 1 MiB body with a link at its path: ${size:-no} bytes saved, the link $([ -L "$saved" ] && echo kept || echo removed), outside: $(head -c 40 "$T/outside")"; fi

# ---- values outside the grammar are refused, and their probe never runs ------------------------------------------
# Each value goes in single quotes, so a semicolon or $( ) in it starts nothing. A single quote would end those
# quotes, which no check inside the block can see; the items say to check a value against the rule before filling.
refused() { # refused LABEL BUCKET HOST ACCOUNT CONTAINER KEY MUST-NOT-CALL...
  local label=$1 f; shift
  fill "$1" "$2" "$3" "$4" "$5" > "$T/bad.sh"; shift 5
  rm -f "$T/calls.log"
  canary "$T/bad.sh"
  for f in "$@"; do
    if [ -f "$T/calls.log" ] && grep -qF -- "$f" "$T/calls.log"; then bad "$label: '$f' reached a stand-in"; return; fi
  done
  if grep -q 'not found' "$T/out"; then bad "$label: the block tried to run another program: $(cat "$T/out")"; return; fi
  if grep -q '^refused: ' "$T/out"; then ok "$label: refused, and its probe never ran"
  else bad "$label: no refusal printed: $(cat "$T/out")"; fi
}
G=example-bucket; H=app.example.invalid; A=examplestore; K=assets; O=static/logo-v2.png
for b in Example_Bucket 'bucket/prefix' ab "$(printf '%064d' 0 | tr 0 b)" 'my bucket' 'x;y' 'x$(id)' '' \
         .lead trail. -lead trail- 'a..b'; do
  refused "bucket '$b'" "$b" "$H" "$A" "$K" "$O" "call aws" "storage/v1/b/$b/o" "arg=https://storage.googleapis.com/$b/"
done
for h in 'user@app.example.invalid' 'app.example.invalid:8443' '[2001:db8::1]' 'bücher.example' 'app.example.invalid/x' \
         'a b' 'x;y' 'x$(id)' ''; do
  refused "host '$h'" "$G" "$h" "$A" "$K" "$O" "arg=https://$h/.git/HEAD" "arg=https://$h/.git/no-such-file-a7f3"
done
for a in Bad_Account ExampleStore ab "$(printf '%025d' 0 | tr 0 a)" ex-store ex.store; do
  refused "Azure account '$a'" "$G" "$H" "$a" "$K" "$O" "$a.blob.core.windows.net"
done
for k in Up a.b 'a b' 'a_b'; do
  refused "Azure container '$k'" "$G" "$H" "$A" "$k" "$O" "/$k?restype" "windows.net/$k/"
done
for o in '' /lead 'a//b' 'a/../b' .. 'a..b' . ./a 'a/.' 'a/./b' 'a b' 'x;y' 'x$(id)' 'bücher.png' 'a?b' 'a#b' \
         'a%2e%2e' "$(printf '%01025d' 0 | tr 0 k)"; do
  refused "object key '$(printf '%.40s' "$o")'" "$G" "$H" "$A" "$K" "$o" "arg=head-object" \
    "arg=https://storage.googleapis.com/$G/" "windows.net/$K/"
done
rm -f "$T/calls.log"
fill "$G" "$H" "$A" "$K" "$(printf '%01024d' 0 | tr 0 k)" > "$T/long.sh"
canary "$T/long.sh"
if ! grep -q '^refused: ' "$T/out" && grep -qx 'arg=head-object' "$T/calls.log"; then
  ok "an object key of 1024 characters is taken"
else bad "an object key of 1024 characters is refused: $(head -c 300 "$T/out")"; fi

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
KEY='An object `<key>` is 1–1024 ASCII letters, digits, `.`, `_`, `-` and `/`, with no leading `/`, no `//`, no `..` and no part that is `.`'
if has "$(item DEP-072)" 'how the CLI follows a bucket in another region was not verified offline' \
   && has "$(item DEP-072)" 'makes one request and prints only the number of keys it returned, `0` to `1000`, and no key name: a number, not `AccessDenied`, means anyone can list it' \
   && has "$(item DEP-072)" 'listing a bucket and reading its objects are separate permissions on every provider, so check both' \
   && has "$(item DEP-072)" 'which prints the object'"'"'s size and none of its content: a number, not a `403` or `404` error, means anyone can read it' \
   && has "$(item DEP-072)" 'which fetch its headers only: `200` means anyone can read it' \
   && has "$(item DEP-072)" 'A listing or a read that is refused shows only that this one request was refused, never that the bucket is private: judge public reads from the bucket policy, ACLs or IAM bindings, or the Azure container'"'"'s access level, in the IaC or from the owner' \
   && has "$(item DEP-072)" "$AZURE" && has "$(item DEP-072)" "$KEY"; then
  ok "DEP-072: a key count from one request; one object read, by size or headers; a refusal proves nothing; the Azure and key rules; the region redirect unverified offline"
else bad "DEP-072 lacks the count, the object read, the refusal rule, the Azure or key rule or the unverified-offline note"; fi
pre=$(awk 'index($0, "> **Live probes (DEP-072, DEP-073).**") == 1 { print; exit }' "$CL")
if has "$pre" "$GRAMMAR" && has "$pre" "$AZURE" && has "$pre" "$KEY" \
   && has "$pre" 'only this first check catches a single quote; each probe below checks every other value again'; then
  ok "the Live probes block states the grammar, the Azure and key rules and what only the check before filling catches"
else bad "the Live probes block lacks the grammar, the Azure or key rule or the single-quote sentence"; fi
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

# ---- docs/power-tools.md: the pinned zizmor recipe, against stand-ins --------------------------------------------
# The digest is the one the registry gives for tag 1.30.1 (an image index for linux/amd64 and linux/arm64), the
# hashes the ones PyPI lists for the ten 1.30.1 wheels; another release changes them here too. The stand-ins for
# docker, python3, pip and zizmor log the directory they run in and their arguments; PATH holds only them.
PT="$ROOT/docs/power-tools.md"
ZDIGEST=sha256:a2eb396d886c053073405c7a980f2139ba2248ec172243cfa3841e57196e8101
ZHASHES='17fda74e15fe41a6aa354ea4cf71fc7ff3cd025cda6584bb6d7466b3f1d00fe6 f9eb092f089e35fa9fb3b70aeec0a19eca7dacf2ab161f1d50b18351895f085c
92906f448365672ebb657fb50d36f997290a3aaba8cac723214741ea9054845d 5e8a3d54c3d9d51307371f4d1d49f8f9e56de00205c6cc660c6846a95ad4e135
eee12266b793cb87ad4a7e3af2e72404f8a63e3de5eb099b80bf7b1cfd232a8e 15679642e8c4f825ba3f22537c698b1bbbad19ead23640f62ec45ebbe7abc803
bf63099a27ef3bf1329dbab44bb9d1027124855c71bd0eca864d5c8e1c5c0db1 4a5ef2fa4fbd2984f794cfc2f95790bd03fa0bae801487ed550e044675874e60
42512bb4a1bce4c787d221d1572ff6b691fa52a3d129b2910be8afaf860c5871 06e039fae8e185e2a1a8b002f2d95a6f5c3b548048bdd79e004dcb501fcd0868'
ZFLAGS='--offline --no-config --no-ignores --collect=all --persona=auditor'
zblock() { # zblock INFO N: the Nth block fenced with ```INFO in power-tools.md's zizmor section
  awk -v info="$1" -v n="$2" '
    index($0, "### zizmor ") == 1 { s = 1; next }
    s && index($0, "### ") == 1 { exit }
    s && !b && $0 == ("```" info) { if (++k == n) b = 1; next }
    b && $0 == "```" { exit }
    b { print }' "$PT"
}
zstand() { # zstand FILE NAME: a stand-in NAME that logs the directory it runs in and its arguments
  cat > "$1" <<EOF
#!/bin/sh
{ printf 'call $2 %s\n' "\$(pwd -P)"; for a in "\$@"; do printf 'arg=%s\n' "\$a"; done; } >> "$T/zcalls.log"
EOF
  chmod +x "$1"
}
ZV="$T/zhome/.venvs/zizmor-1.30.1"
mkdir -p "$T/zbin" "$ZV/bin" "$T/zrepo/.github/workflows" || exit 1
zstand "$T/zbin/docker" docker && zstand "$T/zbin/python3" python3 && zstand "$ZV/bin/pip" pip \
  && zstand "$ZV/bin/zizmor" zizmor || exit 1
zrun() { # zrun FILE: run FILE from the checkout, HOME the fake home, PATH the stand-ins only
  rm -f "$T/zcalls.log"
  ( cd "$T/zrepo" && env HOME="$T/zhome" PATH="$T/zbin" "$BASH" "$1" ) > "$T/zout" 2>&1
}
zcheck() { # zcheck WHAT: the calls logged are the ones in $T/zwant
  if [ -f "$T/zcalls.log" ] && cmp -s "$T/zwant" "$T/zcalls.log"; then ok "$1"
  else bad "power-tools.md's zizmor recipe differs from the pinned form ($1):"; diff "$T/zwant" "$T/zcalls.log" 2>&1 | sed 's/^/    /'; fi
}
zblock bash 1 > "$T/zdocker.sh"
zrun "$T/zdocker.sh"
{ printf 'call docker %s\n' "$T/zrepo"
  printf 'arg=%s\n' run --rm --network none -v "$T/zrepo:/src:ro" "ghcr.io/zizmorcore/zizmor@$ZDIGEST" $ZFLAGS /src/.github/workflows
} > "$T/zwant"
zcheck "the container form runs tag 1.30.1's image index by digest, with no network and the checkout read-only, and zizmor with $ZFLAGS"
zreq=$(zblock text 1)
zhs=$(printf '%s\n' "$zreq" | sed -n '2,$p' | sed -e 's/^    --hash=sha256://' -e 's/ \\$//' | sort)
if [ "$(printf '%s\n' "$zreq" | sed -n 1p)" = 'zizmor==1.30.1 \' ] && [ "$(printf '%s\n' "$zreq" | grep -c '')" = 11 ] \
   && [ "$zhs" = "$(printf '%s\n' $ZHASHES | sort)" ] \
   && [ -z "$(printf '%s\n' "$zreq" | sed -n '2,10p' | grep -v '^    --hash=sha256:[0123456789abcdef]* \\$')" ] \
   && [ -z "$(printf '%s\n' "$zreq" | sed -n '11p' | grep -v '^    --hash=sha256:[0123456789abcdef]*$')" ]; then
  ok "the requirement saved for pip is zizmor==1.30.1 with the sha256 of each of the ten 1.30.1 wheels, and nothing else"
else bad "the requirement saved for pip is not zizmor==1.30.1 with exactly the ten 1.30.1 wheel hashes: $zreq"; fi
printf '%s\n' "$zreq" > "$ZV.txt"
zblock bash 2 > "$T/zpypi.sh"
zrun "$T/zpypi.sh"
{ printf 'call python3 %s\n' "$T/zhome"; printf 'arg=%s\n' -I -m venv "$ZV"
  printf 'call pip %s\n' "$T/zhome"; printf 'arg=%s\n' install --require-hashes --only-binary :all: --no-deps -r "$ZV.txt"
  printf 'call zizmor %s\n' "$T/zrepo"; printf 'arg=%s\n' $ZFLAGS .github/workflows
} > "$T/zwant"
zcheck "the PyPI form makes the environment with python3 -I and installs the hash-checked wheel from \$HOME, whatever directory it starts in, then scans the checkout's .github/workflows with the same flags"

# ---- the line that makes zizmor's environment, with the real python3 ------------------------------------------
# Run as written from a checkout that ships modules named as Python's own, each of which leaves a mark and stops:
# python3 -m without -I would load its venv.py, and Python 3.9 before 3.9.14 and 3.10 before 3.10.6 set pip up in a
# child that is not isolated and starts in the working directory, which would load its runpy.py. A python3 that
# cannot make an environment with pip from an empty directory either (no venv or ensurepip) skips this with a note.
# Both runs keep TMPDIR in $T: Python 3.9's ensurepip leaves its CA bundle there.
vline=$(zblock bash 2 | grep -F -- '-m venv ')
if [ -z "$vline" ]; then bad "power-tools.md's PyPI form has no line that runs python3 -m venv"
elif ! (cd "$T" && TMPDIR="$T" python3 -I -m venv "$T/zctl" && [ -x "$T/zctl/bin/pip" ]) > /dev/null 2>&1; then
  echo "note: this python3 cannot make a virtual environment with pip in an empty directory; the environment line ran against the stand-ins only"
else
  mkdir -p "$T/zrepo2" "$T/zhome2" || exit 1
  for m in venv runpy ensurepip pip; do
    printf 'import os\nopen(os.path.join(os.environ["ZMARK"], "zmark-%s"), "w").close()\nraise SystemExit(97)\n' "$m" > "$T/zrepo2/$m.py"
  done
  ( cd "$T/zrepo2" && env HOME="$T/zhome2" ZMARK="$T" TMPDIR="$T" "$BASH" -c "$vline" ) > "$T/zout" 2>&1
  code=$?
  marks=$(cd "$T" && ls zmark-* 2>/dev/null | tr '\n' ' ')
  pyv=$(cd "$T" && python3 -I -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null)
  if [ "$code" = 0 ] && [ -z "$marks" ] && [ -x "$T/zhome2/.venvs/zizmor-1.30.1/bin/pip" ]; then
    ok "the environment line, run with Python $pyv from a checkout that ships venv.py, runpy.py, ensurepip.py and pip.py, loads none of them and makes the environment with pip"
  else bad "the environment line, run with Python $pyv from a checkout with modules of Python's own names: exit $code, loaded from the checkout: ${marks:-none}; $(tail -n 3 "$T/zout")"; fi
fi

# ---- every zizmor call the docs and the corpus give ---------------------------------------------------------------
# A code span, or a code line joined over a trailing \, without its comment, is cut into commands at &&, ||, ; and |.
# A command is a call when, past a "$ " prompt, NAME=value words and the wrappers sudo, nice, time, command, exec and
# env (with their options), it is zizmor (by name or by a path ending in /zizmor), uvx or pipx run with zizmor (or
# zizmor@<version>, zizmor==<version>) as the tool, python or python3 -m zizmor, or docker or podman with
# zizmorcore/zizmor in it, and a word follows zizmor or the container command; a name alone, such as the image's, is
# not, and neither is the requirement line zizmor==<version>. Each call passes these flags, and a container call names
# the image by a sha256 digest. The self-test's calls are made from the same list, so a flag added here is required of
# them too.
ZALL='--offline --no-config --no-ignores --collect=all --persona=auditor'
ZAWK='
function zcall(s, ln,   w, n, i, c, o) {
  sub(/^[ \t(]+/, "", s); sub(/[ \t)]+$/, "", s)
  if (s == "") return
  n = split(s, w, /[ \t]+/)
  i = 1
  while (i <= n) {
    c = w[i]
    if (c == "$" || c ~ /^[A-Za-z_][A-Za-z0-9_]*=/) { i++; continue }
    if (c == "sudo" || c == "nice" || c == "time" || c == "command" || c == "exec" || c == "env") {
      i++
      while (i <= n && substr(w[i], 1, 1) == "-") { o = w[i]; i++; if (o == "-n" || o == "-u" || o == "-g") i++ }
      continue
    }
    break
  }
  if (i > n) return
  c = w[i]
  if (c == "uvx" || (c == "pipx" && w[i + 1] == "run")) {
    i += (c == "pipx") ? 2 : 1
    while (i <= n && substr(w[i], 1, 1) == "-") {
      o = w[i]; i++
      if (o ~ /^(--from|--with|--with-requirements|--python|-p|--spec|--index|--index-url|--default-index|--extra-index-url|-c|--constraints)$/) i++
    }
    if (i > n || w[i] !~ /^zizmor([@=].*)?$/) return
  } else if (c ~ /^python[0-9.]*$/) {
    i++
    while (i <= n && w[i] != "-m" && substr(w[i], 1, 1) == "-") { o = w[i]; i++; if (o == "-W" || o == "-X") i++ }
    if (i >= n || w[i] != "-m" || w[i + 1] != "zizmor") return
    i++
  } else if (!(c == "zizmor" || c ~ /\/zizmor$/ || ((c == "docker" || c == "podman") && index(s, "zizmorcore/zizmor") > 0)))
    return
  if (i >= n) return
  printf "%s:%d\t%s\n", FILENAME, ln, s
}
function seg(s, ln,   p, np, k) {
  sub(/^[ \t]+/, "", s)
  if (s == "" || substr(s, 1, 1) == "#") return
  sub(/[ \t]#.*$/, "", s)
  np = split(s, p, /\|\||&&|;|\|/)
  for (k = 1; k <= np; k++) zcall(p[k], ln)
}
FNR == 1 { fenced = 0; acc = "" }
{
  t = $0; sub(/^[ \t>]*/, "", t)
  if (substr(t, 1, 3) == "```" || substr(t, 1, 3) == "~~~") { fenced = !fenced; acc = ""; next }
  if (fenced) {
    if (acc == "") at = FNR
    if (t ~ /\\$/) { acc = acc substr(t, 1, length(t) - 1) " "; next }
    seg(acc t, at); acc = ""
  } else {
    n = split($0, a, "`")
    for (i = 2; i < n; i += 2) seg(a[i], FNR)
  }
}'
zlacks() { # zlacks CALL: the flags, and for a container call the digest, CALL lacks
  local s=" $1 " f miss=""
  for f in $ZALL; do case "$s" in *" $f "*) ;; *) miss="$miss $f" ;; esac; done
  case "$s" in *" docker "*|*" podman "*)
    [ -n "$(printf '%s\n' "$1" | tr ' \t' '\n\n' | grep -E '^"?ghcr\.io/zizmorcore/zizmor(:[^@]*)?@sha256:[0123456789abcdef]{64}"?$')" ] \
      || miss="$miss a sha256 digest" ;;
  esac
  printf '%s' "$miss"
}
zlist() { # zlist FINDINGS: the file:line of each call that lacks something, one per line
  local at s
  while IFS='	' read -r at s; do [ -n "$at" ] && [ -n "$(zlacks "$s")" ] && printf '%s\n' "$at"; done <<EOF
$1
EOF
}
printf '%s\n' "Run \`zizmor $ZALL .\` but not \`~/v/bin/zizmor --offline .\`." \
  'Nor `(cd ~ && zizmor --no-config .)`, nor `env A=1 zizmor .`; `# zizmor --offline`, `zizmor: ignore[x]`, `zizmor` and `ghcr.io/zizmorcore/zizmor` are names.' \
  '```bash' 'docker run --rm \' "  ghcr.io/zizmorcore/zizmor:1.30.1 $ZALL /src" \
  'zizmor==1.30.1 \' '    --hash=sha256:00' '# zizmor --offline, in a comment' \
  "podman run --rm ghcr.io/zizmorcore/zizmor@sha256:$(printf '%064d' 0) $ZALL /s" \
  '```' 'Wrapped or prefixed, one per line: `uvx zizmor .`' '`uvx zizmor@1.30.1 .github/workflows`' '`pipx run zizmor .`' \
  '`python3 -m zizmor .`' '`sudo zizmor .`' '`nice -n 10 zizmor .`' '`time zizmor .`' '`ZIZMOR_X=1 zizmor .`' \
  '`make lint; zizmor .`' '`true && zizmor .`' '`cat list | zizmor .`' '`$ zizmor .`' '`command zizmor .` and `exec zizmor .`' \
  "Whole: \`uvx --from zizmor==1.30.1 zizmor $ZALL .\`, \`python3 -I -m zizmor $ZALL .\`, \`sudo -E env A=1 zizmor $ZALL .\`." \
  'Names: `uvx zizmor`, `pipx run zizmor`, `python3 -m pip install zizmor`, `pip install zizmor`, `/usr/bin/zizmor`.' \
  '`zizmor --offline --no-ignores . # --no-config --collect=all --persona=auditor` (a flag in the comment does not count)' \
  > "$T/zforms.md"
want="zforms.md:1 zforms.md:2 zforms.md:2 zforms.md:4"
for n in 11 12 13 14 15 16 17 18 19 20 21 22 23 23 26; do want="$want zforms.md:$n"; done
got=$(zlist "$(cd "$T" && awk "$ZAWK" zforms.md)" | tr '\n' ' ')
if [ "$got" = "$want " ]; then
  ok "the zizmor call check flags a call without a flag or a container call without a digest, after cd, env, a prompt, a wrapper, an assignment, ;, && or |, through uvx, pipx run or python3 -m too, and passes the rest"
else bad "the zizmor call check is broken: it flags [$got], not [$want ]"; fi
zfound=$(cd "$ROOT" && find . -name '*.md' -type f ! -path './.git/*' ! -path './vendor/*' ! -path './scripts/tests/fixtures/*' \
  -exec awk "$ZAWK" {} +)
zcount=""
for zf in docs/power-tools.md:2 discovery/grep-commands.md:1 references/vuln-classes/github-actions.md:1; do
  n=$(printf '%s\n' "$zfound" | grep -c "^\./${zf%:*}:")
  if [ "$n" != "${zf##*:}" ]; then zcount="$zcount ${zf%:*} ($n, not ${zf##*:})"; fi
done
if [ -n "$zcount" ]; then bad "the zizmor call check finds another number of calls in:$zcount"
elif [ -z "$(zlist "$zfound")" ]; then
  ok "every zizmor call in the docs and the corpus passes $ZALL, and every container call names the image by digest"
else
  while IFS='	' read -r at s; do
    [ -n "$at" ] && [ -n "$(zlacks "$s")" ] && bad "${at#./}: a zizmor call without$(zlacks "$s"): $s"
  done <<EOF
$zfound
EOF
fi

echo "---- probe recipes: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
