#!/usr/bin/env bash
# test-jq-ro.sh — self-test for scripts/dnr/jq-ro.sh: the case file fixtures/jq-ro/cases.txt; what jq-ro
# passes on (options, values, inputs, jq's own exit status); the environment jq sees ($ENV, env, ~/.jq,
# canaries in the caller's environment); inputs outside a run directory or reached through a link, a ..
# or a second hard link; standard input; a large input; output escaping; the installation and PATH
# entries inside the working directory. Every case runs under each bash on the machine (/bin/bash and the
# bash running this suite, when they differ) and must print the same under each. Needs jq and git; no
# network. Usage (from the repo root): bash scripts/tests/test-jq-ro.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
JQRO="$ROOT/scripts/dnr/jq-ro.sh"
CASES="$ROOT/scripts/tests/fixtures/jq-ro/cases.txt"
T=$(mktemp -d "${TMPDIR:-/tmp}/jq-ro-test.XXXXXX") || exit 1
T=$(cd -P "$T" && pwd -P) || exit 1
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
command -v jq >/dev/null 2>&1 || { echo "FAIL - jq is not on PATH"; exit 1; }

CANARY="jq-ro-canary-$$-$RANDOM"
export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
export JQ_RO_CANARY="$CANARY" RPC_URL="https://rpc.example.invalid/$CANARY"
mkdir -p "$HOME" "$T/bin" "$T/marks" "$T/outside"
printf 'def homejq: "home-jq-%s";\n' "$CANARY" > "$HOME/.jq"

pass=0 fail=0
ok() { pass=$((pass + 1)); echo "ok   - $1"; }
ko() { fail=$((fail + 1)); echo "FAIL - $1"; }
check() { # check <name> <command>...: on a failure, also show the last run
  if "${@:2}"; then ok "$1"; else ko "$1"; echo "#   status ${RC:-} stdout [$(cat "$T/out" 2>/dev/null)] stderr [$(cat "$T/err" 2>/dev/null)]"; fi
}
nomarks() { [ -z "$(ls -A "$T/marks")" ]; }

SHELLS=("$BASH")
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then
  SHELLS+=(/bin/bash)
fi
echo "# shells: ${SHELLS[*]}; jq: $(jq --version 2>&1)"

# run <dir> <arg>...: jq-ro.sh from <dir> under each shell, standard input empty. Output in $T/out, $T/err
# and $RC; every shell must produce the same three, byte for byte.
run() {
  local dir=$1 i=1 rc
  shift
  (cd "$dir" && "${SHELLS[0]}" "$JQRO" "$@") >"$T/out" 2>"$T/err" </dev/null
  RC=$?
  while [ "$i" -lt "${#SHELLS[@]}" ]; do
    (cd "$dir" && "${SHELLS[$i]}" "$JQRO" "$@") >"$T/out.$i" 2>"$T/err.$i" </dev/null
    rc=$?
    if [ "$rc" != "$RC" ] || ! cmp -s "$T/out" "$T/out.$i" || ! cmp -s "$T/err" "$T/err.$i"; then
      ko "the same output under ${SHELLS[0]} and ${SHELLS[$i]}: jq-ro.sh $*"
    fi
    i=$((i + 1))
  done
}
out_is() { [ "$RC" = 0 ] && [ "$(cat "$T/out")" = "$1" ] && [ ! -s "$T/err" ]; }
status_is() { [ "$RC" = "$1" ]; }
refused() { [ "$RC" = 2 ] && [ "$(cat "$T/err")" = "jq-ro: refused: $1" ] && [ ! -s "$T/out" ]; }
no_canary() { ! grep -q -F -e "$CANARY" "$T/out" "$T/err"; }
no_ctl() { [ "$(LC_ALL=C tr -d '\000-\010\013-\037\177' < "$1" | wc -c)" = "$(wc -c < "$1")" ]; }
tree() { (cd "$1" && find . -print | LC_ALL=C sort); }
tgit() { git -c core.fsmonitor=false -c core.hooksPath=/dev/null "$@"; }
mkrun() { mkdir -p "$1" && printf '*\n' > "$1/.gitignore"; }

# =================================================================================================
# The fixture working directory: a repository whose config names a program that must never run.
# =================================================================================================
W="$T/wt"
mkdir -p "$W"
git init -q "$W"
mkrun "$W/incident_1"
mkdir "$W/incident_1/corpus"
printf '{"a":1,"s":"one"}\n{"a":2,"s":"two"}\n' > "$W/incident_1/data.json"
printf '{"slot":10,"transaction":{"signatures":["sig1"]}}\n{"slot":11,"transaction":{"signatures":["sig2"]}}\n' \
  > "$W/incident_1/corpus/transactions.jsonl"
mkrun "$W/audit_1"
printf '{"finding":"F-1"}\n' > "$W/audit_1/data.json"
mkdir "$W/notes"
printf '{"note":true}\n' > "$W/notes/t.json"
printf '{"top":true}\n' > "$W/data.json"
ln -s incident_1 "$W/incident_2"
mkrun "$W/incident_3"
printf '{"a":3}\n' > "$W/incident_3/data.json"
ln -s ../notes/t.json "$W/incident_3/link.json"
mkdir "$W/incident_4"
printf '{"a":4}\n' > "$W/incident_4/data.json"
mkrun "$W/incident_5"
printf '{"a":5}\n' > "$W/incident_5/data.json"
tgit -C "$W" add -f incident_5/.gitignore && tgit -C "$W" commit -q -m fixture
printf '{"secret":"%s"}\n' "$CANARY" > "$T/outside/secret.json"
mkrun "$W/incident_7"
ln "$T/outside/secret.json" "$W/incident_7/hard.json"
mkrun "$W/incident_8"
mkfifo "$W/incident_8/fifo"
mkrun "$W/INCIDENT_9"
printf '{}\n' > "$W/INCIDENT_9/data.json"
mkrun "$W/incident_10"
ln -s "$T/outside" "$W/incident_10/sub"
mkrun "$W/incident_1234567"
printf '{}\n' > "$W/incident_1234567/data.json"
printf '#!/bin/sh\ntouch "%s/marks/fsmonitor"\nexit 0\n' "$T" > "$T/bin/mark-fsmonitor"
chmod +x "$T/bin/mark-fsmonitor"
git -C "$W" config core.fsmonitor "$T/bin/mark-fsmonitor"

# =================================================================================================
# The entry point.
# =================================================================================================
check "jq-ro.sh starts with #!/bin/bash" test "$(sed -n 1p "$JQRO")" = '#!/bin/bash'
check "jq-ro.sh is executable" test -x "$JQRO"
if mode=$(git -C "$ROOT" ls-files -s -- scripts/dnr/jq-ro.sh 2>/dev/null) && [ -n "$mode" ]; then
  check "jq-ro.sh is committed with mode 100755" test "${mode%% *}" = 100755
fi
(cd "$W" && "$JQRO" -c .a incident_1/data.json) >"$T/out" 2>"$T/err"
RC=$?
check "run directly by its path, it prints what jq prints" out_is "$(printf '1\n2')"

# =================================================================================================
# The case file.
# =================================================================================================
tree "$W" > "$T/tree.before"
ncase=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  want_rc=${line%%$'\t'*}
  rest=${line#*$'\t'}
  want_err=${rest%%$'\t'*}
  rest=${rest#*$'\t'}
  IFS=$'\t' read -r -a args <<< "$rest"
  run "$W" "${args[@]}"
  ncase=$((ncase + 1))
  if [ "$RC" = "$want_rc" ] && [ "$(cat "$T/err")" = "$want_err" ] && [ ! -s "$T/out" ]; then ok "case: jq-ro.sh ${args[*]}"
  else ko "case: jq-ro.sh ${args[*]} -> status $RC, stderr: $(cat "$T/err")"; fi
done < "$CASES"
check "the case file has cases ($ncase)" test "$ncase" -gt 100
tree "$W" > "$T/tree.after"
check "no case changed anything in the working directory" cmp -s "$T/tree.before" "$T/tree.after"
check "no case started the program the repository's config names" nomarks
run "$W"
check "no arguments: usage, exit 2" \
  refused 'usage: jq-ro.sh [-c] [-r] [-s] [-e] [-n] [--arg <name> <value>]... [--argjson <name> <json>]... <filter> <file>...'

# =================================================================================================
# Arguments the case file cannot hold.
# =================================================================================================
run "$W" '' incident_1/data.json
check "an empty filter is refused" refused 'the filter is empty'
long=$(printf '%4094s' '')
run "$W" ".a$long" incident_1/data.json
check "a filter of 4096 bytes runs" out_is "$(printf '1\n2')"
run "$W" ".a$long " incident_1/data.json
check "a filter of 4097 bytes is refused" refused 'the filter is longer than 4096 bytes'
run "$W" "$(printf '.a\001')" incident_1/data.json
check "a filter with a control character is refused" refused 'the filter holds a control character other than tab and newline'
run "$W" "$(printf '.a\r')" incident_1/data.json
check "... a carriage return too" refused 'the filter holds a control character other than tab and newline'
run "$W" "$(printf '.a\n|\t.')" incident_1/data.json
check "a filter with a tab and a newline runs" out_is "$(printf '1\n2')"
run "$W" . ''
check "an empty input path is refused" refused 'the input is empty'
run "$W" . "incident_1/$(printf 'x%.0s' $(seq 1 1020))"
check "an input path over 1024 bytes is refused" refused 'the input is longer than 1024 bytes'
run "$W" . "$(printf 'incident_1/a\033b')"
check "an input path with a control character is refused, shown with ?" refused 'the input holds a control character: incident_1/a?b'
run "$W" . "$W/incident_1/data.json"
check "an absolute path into the run directory is refused" refused "the input must be relative to the working directory: $W/incident_1/data.json"
run "$W" --arg "$(printf 'a%.0s' $(seq 1 64))" v -r '$ARGS.named | keys[0] | length' incident_1/data.json
check "a name of 64 bytes is accepted" out_is "$(printf '64\n64')"
run "$W" --arg x '' -c '$x' incident_1/data.json
check "an empty --arg value is passed on" out_is "$(printf '""\n""')"

# =================================================================================================
# What jq-ro passes on.
# =================================================================================================
run "$W" -r .s incident_1/data.json
check "-r prints raw strings" out_is "$(printf 'one\ntwo')"
run "$W" -c -s 'map(.a)' incident_1/data.json
check "-c and -s" out_is '[1,2]'
run "$W" -c -c -s -s 'length' incident_1/data.json
check "an option given twice means the same" out_is '2'
run "$W" -e '.missing' incident_1/data.json
check "-e: jq's status 1 when the last output is null" sh -c "[ $RC = 1 ] && [ \"\$(cat '$T/out')\" = \"\$(printf 'null\\nnull')\" ]"
run "$W" -e 'empty' incident_1/data.json
check "-e: jq's status 4 when there is no output" status_is 4
run "$W" -n -c '[inputs | .a]' incident_1/data.json
check "-n with inputs reads the inputs named" out_is '[1,2]'
run "$W" --arg who -n --argjson n '{"k":[1]}' -c '[$who, $n.k[0]]' incident_1/data.json
check "--arg and --argjson pass their values on; an option-shaped value stays a value" out_is "$(printf '["-n",1]\n["-n",1]')"
run "$W" --arg x 'a"b\c$d `e`' -r '$x' incident_1/data.json
check "a value passes on as written" out_is "$(printf '%s\n%s' 'a"b\c$d `e`' 'a"b\c$d `e`')"
run "$W" -c '{slot, f: input_filename}' incident_1/corpus/transactions.jsonl ./audit_1/data.json incident_1/corpus/transactions.jsonl
check "inputs from two run directories, one named twice, and a leading ./" out_is "$(printf '%s\n' \
  '{"slot":10,"f":"incident_1/corpus/transactions.jsonl"}' '{"slot":11,"f":"incident_1/corpus/transactions.jsonl"}' \
  '{"slot":null,"f":"audit_1/data.json"}' '{"slot":10,"f":"incident_1/corpus/transactions.jsonl"}' \
  '{"slot":11,"f":"incident_1/corpus/transactions.jsonl"}')"
run "$W" '.a |' incident_1/data.json
check "a compile error: jq's status 3, jq's own message" sh -c "[ $RC = 3 ] && grep -q '^jq: 1 compile error' '$T/err' && ! grep -q 'jq-ro: refused' '$T/err'"
run "$W" 'error("boom")' incident_1/data.json
check "a runtime error: jq's status 5" sh -c "[ $RC = 5 ] && grep -q 'boom' '$T/err'"
run "$W" --argjson x '{' '$x' incident_1/data.json
check "--argjson text jq cannot parse: jq's own status 2 and message" sh -c "[ $RC = 2 ] && grep -q -i 'argjson' '$T/err' && ! grep -q 'jq-ro: refused' '$T/err'"

# =================================================================================================
# The environment jq sees.
# =================================================================================================
run "$W" -n -c '$ENV' incident_1/data.json
check "\$ENV holds HOME=/nonexistent and the fixed PATH, and nothing else" out_is '{"HOME":"/nonexistent","PATH":"/usr/bin:/bin"}'
run "$W" -n -c 'env' incident_1/data.json
check "... and so does env" out_is '{"HOME":"/nonexistent","PATH":"/usr/bin:/bin"}'
for f in '$ENV' 'env' '$ENV.JQ_RO_CANARY' 'env.RPC_URL' '[env[]]' '$__loc__' 'input_filename' '$ARGS' \
  'env | tostring | error' '[inputs]' 'builtins | length'; do
  run "$W" -n -c "$f" incident_1/data.json
  check "the caller's canary never prints: $f" no_canary
done
JQ_RO_CANARY="$CANARY" jq -n -r 'homejq' > "$T/out" 2>&1
check "the fixture's ~/.jq is one plain jq loads" grep -q -F "home-jq-$CANARY" "$T/out"
run "$W" -n -r 'homejq' incident_1/data.json
check "jq-ro loads no ~/.jq: the function it defines is unknown (status 3)" sh -c "[ $RC = 3 ] && ! grep -q -F 'home-jq-' '$T/out' '$T/err'"

# =================================================================================================
# Standard input, links, .. and hard links.
# =================================================================================================
printf '{"a":"stdin-%s"}\n' "$CANARY" > "$T/stdin.json"
(cd "$W" && "$JQRO" -n -c '[inputs | .a]' incident_1/data.json) < "$T/stdin.json" >"$T/out" 2>"$T/err"
RC=$?
check "standard input is never read: inputs come from the files named" out_is '[1,2]'
(cd "$W" && "$JQRO" -c .) < "$T/stdin.json" >"$T/out" 2>"$T/err"
RC=$?
check "... and with no file named, it refuses rather than read it" \
  refused 'name at least one file inside a run directory; jq-ro never reads standard input'
for p in incident_10/sub/secret.json incident_1/../../outside/secret.json incident_7/hard.json "$T/outside/secret.json"; do
  run "$W" -c . "$p"
  check "a file outside the working directory is never printed: $p" sh -c "[ $RC = 2 ] && [ ! -s '$T/out' ]"
  check "... nor its canary" no_canary
done

# =================================================================================================
# A large input, and output escaping.
# =================================================================================================
i=0
while [ "$i" -lt 4000 ]; do
  printf '{"n":%d,"pad":"%s"}\n' "$i" 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
  i=$((i + 1))
done > "$W/incident_1/big.jsonl"
check "the large input is over 64 KiB" test "$(wc -c < "$W/incident_1/big.jsonl")" -gt 65536
run "$W" -c '.n' incident_1/big.jsonl
(cd "$W" && jq -c '.n' incident_1/big.jsonl) > "$T/want"
check "a large input: the whole output, as jq prints it" sh -c "[ $RC = 0 ] && cmp -s '$T/out' '$T/want' && [ ! -s '$T/err' ]"
run "$W" -c . incident_1/big.jsonl
check "... and a large output" sh -c "[ $RC = 0 ] && [ \"\$(wc -l < '$T/out' | tr -d ' ')\" = 4000 ]"
printf '{"s":"a\\u001bb\\u0007c\\u0000d\\re\\u007ff\\tg"}\n' > "$W/incident_1/ctl.json"
run "$W" -r '.s' incident_1/ctl.json
printf 'a?b?c?d?e?f\tg\n' > "$T/want"
check "raw output shows each control character but tab and newline as ?" cmp -s "$T/out" "$T/want"
run "$W" '.s | error' incident_1/ctl.json
check "... and so does jq's stderr" sh -c "[ $RC = 5 ] && [ -s '$T/err' ]"
check "... which holds no control character but tab and newline" no_ctl "$T/err"

# =================================================================================================
# The installation and PATH entries inside the working directory.
# =================================================================================================
run "$ROOT" . x
check "an installation inside the working directory is refused" \
  refused 'the installation lies inside the working directory; install it outside the tree under audit (Rule 11e)'
F="$T/fake"
mkrun "$F/incident_1"
printf '{"a":1}\n' > "$F/incident_1/data.json"
mkdir "$F/.bin"
for p in jq env git find tr wc cat; do
  printf '#!/bin/sh\ntouch "%s/marks/wt-%s"\nexit 0\n' "$T" "$p" > "$F/.bin/$p"
  chmod +x "$F/.bin/$p"
done
(cd "$F" && PATH="$F/.bin:.bin:$PATH" "$JQRO" -c .a incident_1/data.json) >"$T/out" 2>"$T/err"
RC=$?
check "programs inside the working directory are never run from PATH" out_is 1
check "... none of them ran, and no configured program either" nomarks

echo
echo "jq-ro tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
