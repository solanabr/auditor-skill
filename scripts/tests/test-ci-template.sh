#!/usr/bin/env bash
# test-ci-template.sh — the CI mode's files in templates/ci/ (docs/ci.md, OUTPUT-RULES.md Rule 11d):
#   1. findings.schema.json and verdict.schema.json parse; verdict.schema.json, which claude -p --json-schema
#      sends as a structured-output schema, uses only types, enums, required, items, descriptions and
#      additionalProperties false, and requires every field it names; the names the two schemas and verdict.jq
#      share agree, and each field the schemas require is one verdict.jq refuses to do without. Where python3
#      has the jsonschema module, both are valid Draft 2020-12 and the samples below match them;
#   2. auditor-pr.yml keeps the decided shape: on pull_request only, and no privileged trigger anywhere outside
#      a comment; permissions contents: read, and no job widens it; every action pinned by a full commit id with
#      its version comment, each one the repository's own workflows pin; credentials dropped at every checkout;
#      no secret in the tools job and exactly one, the API key, in the review job; the review job gated to
#      same-repository pull requests, after the tools job, started with the decided launch line; AUDITOR_STRICT=1
#      and AUDITOR_EXEC_MODE=none for both; the verdict step last, run unless the job is cancelled, deciding
#      through verdict.jq. The workflow checker of test-ci-checks.sh (wfcheck) passes it too;
#   3. findings-to-sarif.jq turns a sample findings.json into SARIF 2.1.0: one run, a rule per checklist or
#      vector id with its security-severity, a result per finding at the level its severity and Rule 5b status
#      give, each location a relative URI with a start line; and it refuses a file without findings;
#   4. verdict.jq passes only a successful result whose structured_output and findings.json agree on pass, for
#      the threshold, mode, command and commits it is given, and its line never holds text from either file;
#   5. the CI's suite loop over scripts/tests/*.sh runs this file.
# Usage (from the repo root): bash scripts/tests/test-ci-template.sh   (VERBOSE=1 lists every check)
# Needs bash >= 3.2, jq, awk, grep, sed, mktemp. No network.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 1
CI=templates/ci
WF=$CI/auditor-pr.yml
pass=0; failn=0
ok()  { pass=$((pass + 1)); if [ -n "${VERBOSE:-}" ]; then echo "ok   $*"; fi; }
bad() { failn=$((failn + 1)); echo "FAIL $*"; }
check() { # check NAME COMMAND...: ok when the command succeeds; its output is dropped
  local name=$1; shift
  if "$@" > /dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}
command -v jq > /dev/null || { echo "FAIL jq is not on PATH"; exit 1; }
T=$(mktemp -d "${TMPDIR:-/tmp}/ci-template.XXXXXX") || exit 1
T=$(cd "$T" && pwd -P) || exit 1
trap 'rm -rf "$T"' EXIT

# ---- 1. the schemas -----------------------------------------------------------------------------------------
for s in "$CI/findings.schema.json" "$CI/verdict.schema.json"; do
  check "$s parses as one JSON object" jq -e 'type == "object"' "$s"
done
SUBSET='
def node_ok:
  type == "object"
  and (keys - ["type", "enum", "required", "properties", "additionalProperties", "items", "description"]) == []
  and (if has("additionalProperties") then .additionalProperties == false else true end)
  and (if has("properties") then .additionalProperties == false and (.required | sort) == (.properties | keys)
         and all(.properties[]; node_ok) else true end)
  and (if has("items") then .items | node_ok else true end);
.type == "object" and node_ok'
check "verdict.schema.json keeps to the structured-output subset and requires every field" \
  jq -e "$SUBSET" "$CI/verdict.schema.json"
an_f=$(jq -c '.["$defs"].analyzer.properties.name.enum' "$CI/findings.schema.json")
an_r=$(jq -c '.properties.analyzers_run.items.enum' "$CI/verdict.schema.json")
an_n=$(jq -c '.properties.analyzers_not_run.items.enum' "$CI/verdict.schema.json")
an_j=$(jq -n -c "$(sed -n '/^def analyzers:/,/;$/p' "$CI/verdict.jq") analyzers")
if [ -n "$an_f" ] && [ "$an_f" = "$an_r" ] && [ "$an_f" = "$an_n" ] && [ "$an_f" = "$an_j" ]; then
  ok "the analyzer names agree: $an_f"
else bad "the analyzer names differ: findings $an_f, run $an_r, not run $an_n, verdict.jq $an_j"; fi
st_f=$(jq -c '.properties.stopped.enum' "$CI/findings.schema.json")
st_v=$(jq -c '.properties.stopped.enum - ["preflight", "run-directory"]' "$CI/verdict.schema.json")
check "the stopped steps agree: a findings file names those after the run directory exists" \
  [ "$st_f" = "$st_v" ]

B=1111111111111111111111111111111111111111
H=2222222222222222222222222222222222222222
# the samples: a diff-audit run in audit_3 whose result says fail on a counted finding (F-1)
printf '%s\n' '{"schema_version":1,"command":"diff-audit","mode":"strict","final":true,"verdict":"fail",' \
  '"threshold":7,"stopped":"none","run":"audit_3","report":"audit_3/PR-REPORT.md",' \
  "\"commits\":{\"base\":\"$B\",\"head\":\"$H\"}," \
  '"analyzers":[{"name":"audit-scan","status":"ran"},{"name":"lock-delta","status":"ran"}],' \
  '"findings":[{"id":"F-1","severity":8,"title":"Withdraw skips the vault owner check","file":"programs/vault/src/lib.rs","line":42,"rule5b":"passed","refs":["AV-015","KV-012"]},' \
  '{"id":"F-2","severity":5,"title":"Fee rounds toward the user","file":"programs/vault/src/fee calc.rs","line":7,"rule5b":"not-required","refs":["AR-010"]},' \
  '{"id":"F-3","severity":9,"title":"Suspected overflow in the share math","file":"programs/vault/src/math.rs","line":3,"rule5b":"unconfirmed","refs":[]}]}' \
  > "$T/fail-findings.json"
printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"F-1 Withdraw skips the vault owner check",' \
  '"structured_output":{"schema_version":1,"command":"diff-audit","mode":"strict","verdict":"fail","threshold":7,"run":3,' \
  '"stopped":"none","analyzers_run":["audit-scan","lock-delta"],"analyzers_not_run":[]}}' > "$T/fail-result.json"
# the same run with F-1 gone: both files say pass
jq '.findings |= map(select(.id != "F-1")) | .verdict = "pass"' "$T/fail-findings.json" > "$T/pass-findings.json"
jq '.structured_output.verdict = "pass"' "$T/fail-result.json" > "$T/pass-result.json"
for f in fail-findings fail-result pass-findings pass-result; do
  [ -s "$T/$f.json" ] || { bad "could not write the sample $f.json"; }
done

if python3 -I -c 'import jsonschema' 2> /dev/null; then
  msg=$(python3 -I -c '
import json, sys
from jsonschema import Draft202012Validator as V
fs, vs = (json.load(open(p, encoding="utf-8")) for p in sys.argv[1:3])
V.check_schema(fs); V.check_schema(vs)
for p in sys.argv[3:5]:
    errs = [e.message for e in V(fs).iter_errors(json.load(open(p, encoding="utf-8")))]
    if errs: sys.exit(p + ": " + errs[0])
for p in sys.argv[5:7]:
    errs = [e.message for e in V(vs).iter_errors(json.load(open(p, encoding="utf-8"))["structured_output"])]
    if errs: sys.exit(p + ": " + errs[0])
' "$CI/findings.schema.json" "$CI/verdict.schema.json" "$T/fail-findings.json" "$T/pass-findings.json" \
    "$T/fail-result.json" "$T/pass-result.json" 2>&1)
  if [ -z "$msg" ]; then ok "jsonschema: both schemas are valid Draft 2020-12, and the samples match them"
  else bad "jsonschema: ${msg##*$'\n'}"; fi
else
  echo "skip the jsonschema checks: python3 has no jsonschema module here (the schemas were read as JSON only)"
fi

# ---- 2. the workflow's shape ----------------------------------------------------------------------------------
[ -f "$WF" ] || { bad "$WF is missing"; echo "---- ci template: $pass passed, $failn failed"; exit 1; }
code=$(grep -v '^[[:space:]]*#' "$WF")   # the workflow without its comment lines
block() { # block KEY INDENT: the lines of the mapping entry KEY at INDENT spaces, up to the next entry there
  awk -v key="$1" -v ind="$2" '
    function lead(s) { match(s, /^ */); return RLENGTH }
    BEGIN { for (i = 0; i < ind; i++) pad = pad " " }
    on && /[^ ]/ && lead($0) <= ind && $0 !~ /^ *#/ { exit }
    !on && $0 == pad key ":" { on = 1; next }
    on { print }' "$WF"
}
top_on=$(block on 0 | grep -v '^[[:space:]]*#' | grep .)
check "on: holds pull_request alone" [ "$top_on" = "  pull_request:" ]
n=$(printf '%s\n' "$code" | grep -c -E 'pull_request_target|workflow_run')
check "no privileged trigger outside a comment" [ "$n" -eq 0 ]
top_perm=$(block permissions 0 | grep -v '^[[:space:]]*#' | grep .)
check "permissions is contents: read alone" [ "$top_perm" = "  contents: read" ]
n=$(printf '%s\n' "$code" | grep -c -E '^ +permissions:')
check "no job or step sets permissions of its own" [ "$n" -eq 0 ]
tools=$(block tools 2)
review=$(block review 2)
if [ -n "$tools" ] && [ -n "$review" ]; then ok "the workflow has a tools job and a review job"
else bad "the workflow lacks its tools job or its review job"; fi
jobs=$(block jobs 0 | grep -E '^  [A-Za-z0-9_-]+:' | tr -d ' :' | tr '\n' ' ')
check "its jobs are tools and review alone" [ "$jobs" = "tools review " ]
top_env=$(block env 0)
for want in '  AUDITOR_STRICT: "1"' '  AUDITOR_EXEC_MODE: none'; do
  n=$(printf '%s\n' "$top_env" | grep -c -x -F -- "$want")
  check "the workflow's env holds ${want#  }" [ "$n" -eq 1 ]
done
n=$(printf '%s\n' "$code" | grep -c -E 'AUDITOR_(STRICT|EXEC_MODE):')
check "nothing else sets AUDITOR_STRICT or AUDITOR_EXEC_MODE" [ "$n" -eq 2 ]
# every uses: is a full commit id with a version comment, and one the repository's own workflows pin
pins=$(grep -h -E '^[[:space:]-]*uses:' .github/workflows/*.yml | sed -E 's/^[[:space:]-]*uses:[[:space:]]*//; s/[[:space:]]+#.*//' | sort -u)
nuses=0
while IFS= read -r l; do
  [ -n "$l" ] || continue
  nuses=$((nuses + 1))
  u=$(printf '%s\n' "$l" | sed -E 's/^[[:space:]-]*uses:[[:space:]]*//')
  ref=${u%%[[:space:]]*}
  case "$u" in
    *@[0-9a-f]*" # v"[0-9]*) ;;
    *) bad "an action without a full commit id and a version comment: $l"; continue ;;
  esac
  if [ "$(printf '%s\n' "${ref##*@}" | grep -c -E '^[0-9a-f]{40}$')" -ne 1 ]; then bad "not a full commit id: $l"
  elif [ "$(printf '%s\n' "$pins" | grep -c -x -F -- "$ref")" -ge 1 ]; then ok "pinned as the repository's own workflows pin it: $ref"
  else bad "a pin the repository's own workflows do not use: $ref"; fi
done < <(printf '%s\n' "$code" | grep -E '^[[:space:]-]*uses:')
check "each job checks out once, with an action" [ "$nuses" -eq 2 ]
nco=$(printf '%s\n' "$code" | grep -c -E '^[[:space:]-]*uses:[[:space:]]*actions/checkout@')
npc=$(printf '%s\n' "$code" | grep -c -E '^[[:space:]]*persist-credentials:[[:space:]]*false[[:space:]]*$')
check "every checkout drops its credentials ($nco checkouts)" [ "$nco" -eq "$npc" ]
n=$(printf '%s\n' "$tools" | grep -v '^[[:space:]]*#' | grep -c -E 'secrets\.|ANTHROPIC')
check "the tools job reads no secret" [ "$n" -eq 0 ]
n=$(printf '%s\n' "$code" | grep -c 'secrets\.')
m=$(printf '%s\n' "$review" | grep -c -x -F '          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}')
check "the one secret is the API key, in a review step's env" [ "$n:$m" = 1:1 ]
n=$(printf '%s\n' "$tools" | grep -c -E '^    if:')
check "the tools job runs for every pull request" [ "$n" -eq 0 ]
n=$(printf '%s\n' "$review" | grep -c -x -F '    if: github.event.pull_request.head.repo.full_name == github.repository')
m=$(printf '%s\n' "$review" | grep -c -E '^    if:')
check "the review job runs for same-repository pull requests only" [ "$n:$m" = 1:1 ]
n=$(printf '%s\n' "$review" | grep -c -x -F '    needs: tools')
check "the review job waits for the tools job" [ "$n" -eq 1 ]
# the launch line: the claude call and its continuation lines, joined
launch=$(printf '%s\n' "$review" | awk '/^ *claude -p / && !done { on = 1 }
  on { sub(/^ +/, ""); line = line $0 " "; if ($0 !~ /\\$/) { on = 0; done = 1 } } END { print line }')
for want in '-p "/auditor:diff-audit $base..$head --ci --fail-on $AUDITOR_FAIL_ON"' '--plugin-dir "$A"' \
            '--setting-sources user' '--strict-mcp-config' '--max-budget-usd "$AUDITOR_MAX_BUDGET_USD"' \
            '--output-format json' '--json-schema "$(cat "$A/templates/ci/verdict.schema.json")"'; do
  case "$launch" in *" $want "*) ok "the launch line passes $want" ;; *) bad "the launch line lacks $want: $launch" ;; esac
done
n=$(printf '%s\n' "$review" | grep -c -E '^ *claude -p ')
check "the review starts Claude Code once" [ "$n" -eq 1 ]
n=$(printf '%s\n' "$code" | grep -c -E -e '--settings|--permission-mode|--dangerously|--allowedTools|bypassPermissions')
check "the launch line adds no settings, permission mode or tool grant" [ "$n" -eq 0 ]
last=$(printf '%s\n' "$review" | awk '/^      - name:/ { s = $0; body = "" } { body = body $0 "\n" } END { printf "%s", body }')
case "$last" in
  *'      - name: Verdict'*"if: \${{ !cancelled() }}"*'-f "$A/templates/ci/verdict.jq"'*'"auditor: verdict: pass ("*) exit 0 ;; *) exit 1 ;; esac'*)
    ok "the last step decides, unless the job was cancelled, through verdict.jq" ;;
  *) bad "the review job's last step is not the verdict step the docs describe" ;;
esac
case "$last" in
  *'-f "$A/templates/ci/findings-to-sarif.jq"'*) ok "the verdict step turns findings.json into SARIF with findings-to-sarif.jq" ;;
  *) bad "the verdict step does not run findings-to-sarif.jq" ;;
esac
n=$(printf '%s\n' "$code" | grep -c -E 'upload-artifact|upload-sarif|code-scanning|gh (pr|issue|api)')
check "the workflow uploads and posts nothing" [ "$n" -eq 0 ]
# the repository's own workflow checker, from test-ci-checks.sh
awk '/^wfcheck\(\) \{/ { on = 1 } on { print } on && /^\}$/ { exit }' scripts/tests/test-ci-checks.sh > "$T/wfcheck.sh"
if grep -q '^wfcheck() {' "$T/wfcheck.sh" && . "$T/wfcheck.sh"; then
  probs=$(wfcheck "$WF")
  if [ -z "$probs" ]; then ok "test-ci-checks.sh's wfcheck passes $WF"; else bad "wfcheck: $probs"; fi
  sed 's/^          set -euo pipefail$/          echo "${{ github.head_ref }}"/' "$WF" > "$T/broken.yml"
  case "$(wfcheck "$T/broken.yml")" in *'inside a run: script'*) ok "wfcheck flags an expression pasted into the template's scripts" ;;
    *) bad "wfcheck did not flag an expression in a run: script of a broken copy" ;; esac
else bad "no wfcheck function in scripts/tests/test-ci-checks.sh"; fi

# ---- 3. findings.json to SARIF 2.1.0 ------------------------------------------------------------------------------
SARIF_OK='
def str: type == "string" and length > 0;
.version == "2.1.0" and (.["$schema"] | str) and (.runs | type == "array" and length == 1)
and (.runs[0] as $r
  | ($r.tool.driver.name | str) and ($r.tool.driver.rules | type == "array")
  and ([$r.tool.driver.rules[].id] | length == (unique | length))
  and all($r.tool.driver.rules[]; (.id | str) and (.shortDescription.text | str)
    and (.properties["security-severity"] | type == "string" and test("^([0-9]|10)[.]0$")))
  and ($r.invocations | type == "array" and length == 1 and (.[0].executionSuccessful | type == "boolean"))
  and ($r.results | type == "array")
  and all($r.results[]; (.ruleId | str) and (.ruleId as $id | any($r.tool.driver.rules[]; .id == $id))
    and (.level | IN("none", "note", "warning", "error")) and (.message.text | str) and (.locations | length == 1)
    and (.locations[0].physicalLocation.artifactLocation.uri | str and (startswith("/") | not))
    and (.locations[0].physicalLocation.region.startLine | type == "number" and . >= 1 and . == floor)))'
if jq -f "$CI/findings-to-sarif.jq" "$T/fail-findings.json" > "$T/out.sarif" 2> "$T/sarif.err"; then
  check "a sample findings.json turns into SARIF 2.1.0 of the expected shape" jq -e "$SARIF_OK" "$T/out.sarif"
  got=$(jq -r '.runs[0] | ([.results[] | "\(.properties["finding-id"]):\(.level):\(.ruleId)"] | join(" ")) + " | "
    + ([.tool.driver.rules[] | "\(.id)=\(.properties["security-severity"])"] | join(" ")) + " | "
    + (.results[1].locations[0].physicalLocation.artifactLocation.uri) + " | "
    + (.invocations[0].executionSuccessful | tostring)' "$T/out.sarif")
  want='F-1:error:AV-015 F-2:warning:AR-010 F-3:note:auditor-skill/unclassified | AR-010=5.0 AV-015=8.0 auditor-skill/unclassified=9.0 | programs/vault/src/fee%20calc.rs | true'
  check "levels, rules, severities, URIs and the invocation are as the findings give them" [ "$got" = "$want" ]
  [ "$got" = "$want" ] || echo "     got: $got"
else bad "findings-to-sarif.jq failed on the sample: $(sed -n 1p "$T/sarif.err")"; fi
jq '.analyzers[1].status = "not-run"' "$T/fail-findings.json" > "$T/notrun-findings.json"
got=$(jq -f "$CI/findings-to-sarif.jq" "$T/notrun-findings.json" | jq -r '.runs[0].invocations[0].executionSuccessful')
check "an analyzer that did not run makes the invocation unsuccessful" [ "$got" = false ]
printf '%s\n' '{"schema_version":1,"command":"diff-audit"}' > "$T/empty.json"
if out=$(jq -f "$CI/findings-to-sarif.jq" "$T/empty.json" 2> /dev/null); then bad "findings-to-sarif.jq accepted a file with no findings"
elif [ -n "$out" ]; then bad "findings-to-sarif.jq printed something for a file with no findings"
else ok "findings-to-sarif.jq refuses a file with no findings, and prints nothing"; fi

# ---- 4. the verdict --------------------------------------------------------------------------------------------
verdict() { # verdict RESULT FINDINGS [THRESHOLD [COMMAND [MODE [PROBLEM]]]]: the line verdict.jq prints
  jq -n -r --slurpfile result "$1" --slurpfile findings "$2" --argjson threshold "${3:-7}" --arg command "${4:-diff-audit}" \
    --arg mode "${5:-strict}" --arg base "$B" --arg head "$H" --arg problem "${6-}" -f "$CI/verdict.jq" 2>&1
}
expect() { # expect NAME WANT GOT
  if [ "$3" = "$2" ]; then ok "$1"; else bad "$1: got '$3', want '$2'"; fi
}
RAN='analyzers run: audit-scan, lock-delta'
expect "pass: both files say pass and no finding counts at 7" "auditor: verdict: pass (threshold 7, $RAN)" \
  "$(verdict "$T/pass-result.json" "$T/pass-findings.json")"
expect "fail: a severity-8 finding that passed the gate" "auditor: verdict: fail (threshold 7, $RAN)" \
  "$(verdict "$T/fail-result.json" "$T/fail-findings.json")"
line=$(verdict "$T/fail-result.json" "$T/fail-findings.json")
case "$line" in *Withdraw*|*owner*|*programs/*|*F-1*|*AV-015*|*" 1 "*) bad "the line holds text from the files: $line" ;;
  *) ok "the line holds no finding text, id, path or count" ;; esac
jq '.structured_output.verdict = "pass"' "$T/fail-result.json" > "$T/v.json"
expect "fail: the result says pass over a counted finding" \
  "auditor: verdict: fail (threshold 7, $RAN; the findings file and the result disagree)" \
  "$(verdict "$T/v.json" "$T/fail-findings.json")"
jq '.verdict = "pass"' "$T/fail-findings.json" > "$T/f.json"
expect "fail: both files say pass over a counted finding" \
  "auditor: verdict: fail (threshold 7, $RAN; the verdict does not follow from the findings file)" \
  "$(verdict "$T/v.json" "$T/f.json")"
jq '.findings += [{"id":"F-4","severity":7,"title":"t","file":"a.rs","line":1,"rule5b":"undetermined","refs":[]}] | .verdict = "fail"' \
  "$T/pass-findings.json" > "$T/f.json"
expect "fail: an [UNDETERMINED] finding counts" "auditor: verdict: fail (threshold 7, $RAN)" \
  "$(verdict "$T/fail-result.json" "$T/f.json")"
jq '.findings[0].rule5b = "partial"' "$T/fail-findings.json" | jq '.verdict = "pass"' > "$T/f.json"
expect "pass: a [PARTIAL] finding does not count" "auditor: verdict: pass (threshold 7, $RAN)" \
  "$(verdict "$T/pass-result.json" "$T/f.json")"
jq '.threshold = 9 | .verdict = "pass"' "$T/fail-findings.json" > "$T/f.json"
jq '.structured_output.threshold = 9 | .structured_output.verdict = "pass"' "$T/fail-result.json" > "$T/v.json"
expect "pass: the severity-8 finding at threshold 9" "auditor: verdict: pass (threshold 9, $RAN)" \
  "$(verdict "$T/v.json" "$T/f.json" 9)"
expect "fail: the result's threshold is not the one given" \
  "auditor: verdict: fail (threshold 7, $RAN; its result names another threshold)" "$(verdict "$T/v.json" "$T/f.json" 7)"
jq '.analyzers[1] = {"name":"deps-artifacts","status":"not-run","reason":"deps: blocker: the download failed"}' \
  "$T/pass-findings.json" | jq '.verdict = "fail"' > "$T/f.json"
jq '.structured_output.analyzers_run = ["audit-scan"] | .structured_output.analyzers_not_run = ["deps-artifacts"]' \
  "$T/fail-result.json" > "$T/v.json"
expect "fail: an analyzer the run called for did not run" \
  "auditor: verdict: fail (threshold 7, analyzers run: audit-scan; not run: deps-artifacts)" "$(verdict "$T/v.json" "$T/f.json")"
jq '.structured_output.analyzers_not_run = []' "$T/v.json" > "$T/v2.json"
expect "fail: the result and the findings file name other analyzers" \
  "auditor: verdict: fail (threshold 7, analyzers run: audit-scan; the findings file and the result name other analyzers)" \
  "$(verdict "$T/v2.json" "$T/f.json")"
jq '.final = false | .verdict = "fail"' "$T/pass-findings.json" > "$T/f.json"
expect "fail: a findings file that never became final" \
  "auditor: verdict: fail (threshold 7, $RAN; the run ended before its last step)" "$(verdict "$T/fail-result.json" "$T/f.json")"
jq '.final = false' "$T/pass-findings.json" > "$T/f.json"
expect "fail: a findings file that says pass while it is not final" \
  "auditor: verdict: fail (threshold 7, $RAN; the run's findings file does not match templates/ci/findings.schema.json)" \
  "$(verdict "$T/pass-result.json" "$T/f.json")"
for sub in error_max_budget_usd error_max_turns error_during_execution error_max_structured_output_retries something_new; do
  case "$sub" in something_new) shown=unknown ;; *) shown=$sub ;; esac
  printf '{"type":"result","subtype":"%s","is_error":true}\n' "$sub" > "$T/v.json"
  expect "fail: a result of subtype $sub" \
    "auditor: verdict: fail (threshold 7, analyzers run: unknown; the review ended early ($shown))" \
    "$(verdict "$T/v.json" "$T/pass-findings.json")"
done
jq '.is_error = true' "$T/pass-result.json" > "$T/v.json"
expect "fail: a success that is an error" \
  "auditor: verdict: fail (threshold 7, $RAN; the review ended in an error)" "$(verdict "$T/v.json" "$T/pass-findings.json")"
expect "fail: no result" "auditor: verdict: fail (threshold 7, analyzers run: unknown; the review returned no result)" \
  "$(verdict /dev/null /dev/null)"
expect "fail: a run directory with no findings file" \
  "auditor: verdict: fail (threshold 7, $RAN; the run's findings file is missing)" "$(verdict "$T/pass-result.json" /dev/null)"
expect "fail: the wrapper's own reason" \
  "auditor: verdict: fail (threshold 7, $RAN; the run directory its result names was there before the review)" \
  "$(verdict "$T/pass-result.json" "$T/pass-findings.json" 7 diff-audit strict 'the run directory its result names was there before the review')"
jq '.structured_output.mode = "default"' "$T/pass-result.json" > "$T/v.json"
expect "fail: preflight named default mode" \
  "auditor: verdict: fail (threshold 7, $RAN; preflight did not name strict mode)" "$(verdict "$T/v.json" "$T/pass-findings.json")"
expect "fail: the result is another command's" \
  "auditor: verdict: fail (threshold 7, $RAN; its result is another command's)" \
  "$(verdict "$T/pass-result.json" "$T/pass-findings.json" 7 quick-scan)"
jq ".commits.head = \"$B\"" "$T/pass-findings.json" > "$T/f.json"
expect "fail: the findings file pins other commits" \
  "auditor: verdict: fail (threshold 7, $RAN; the findings file pins other commits)" "$(verdict "$T/pass-result.json" "$T/f.json")"
jq '.run = "audit_4" | .report = "audit_4/PR-REPORT.md"' "$T/pass-findings.json" > "$T/f.json"
expect "fail: the findings file is another run's" \
  "auditor: verdict: fail (threshold 7, $RAN; the findings file is another run's)" "$(verdict "$T/pass-result.json" "$T/f.json")"
printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"structured_output":{"schema_version":1,' \
  '"command":"diff-audit","mode":"strict","verdict":"fail","threshold":7,"run":0,"stopped":"preflight",' \
  '"analyzers_run":[],"analyzers_not_run":[]}}' > "$T/v.json"
expect "fail: a run that stopped at preflight, with no run directory" \
  "auditor: verdict: fail (threshold 7, analyzers run: none; stopped: preflight)" "$(verdict "$T/v.json" /dev/null)"
jq '.structured_output.stopped = "none"' "$T/v.json" > "$T/v2.json"
expect "fail: a result with no run directory that stopped nowhere" \
  "auditor: verdict: fail (threshold 7, analyzers run: none; its result names no run directory)" "$(verdict "$T/v2.json" /dev/null)"
jq '.structured_output.verdict = "pass"' "$T/v.json" > "$T/v2.json"
expect "fail: a result that says pass for a run that stopped" \
  "auditor: verdict: fail (threshold 7, analyzers run: none; stopped: preflight; its result says pass for a run that stopped)" \
  "$(verdict "$T/v2.json" /dev/null)"
# a result that steps outside the schema prints none of what it holds
for edit in '.structured_output.note = "Withdraw skips the owner check"' \
            '.structured_output.analyzers_run = ["audit-scan; F-1 Withdraw skips the owner check"]' \
            '.structured_output.run = 3.5' '.structured_output.threshold = "7"' '.structured_output = "pass"' \
            '.structured_output.analyzers_not_run = ["audit-scan"]' 'del(.structured_output.stopped)'; do
  jq "$edit" "$T/pass-result.json" > "$T/v.json"
  expect "fail, and nothing of the result shown: $edit" \
    "auditor: verdict: fail (threshold 7, analyzers run: unknown; its result does not match templates/ci/verdict.schema.json)" \
    "$(verdict "$T/v.json" "$T/pass-findings.json")"
done
# each field either schema requires is one verdict.jq refuses to go without, and each value they allow it takes
for k in $(jq -r '.required[]' "$CI/findings.schema.json"); do
  jq "del(.$k)" "$T/pass-findings.json" > "$T/f.json"
  case "$(verdict "$T/pass-result.json" "$T/f.json")" in
    *"does not match templates/ci/findings.schema.json)") ok "verdict.jq refuses a findings file without $k" ;;
    *) bad "verdict.jq takes a findings file without $k" ;;
  esac
done
for k in $(jq -r '.required[]' "$CI/verdict.schema.json"); do
  jq "del(.structured_output.$k)" "$T/pass-result.json" > "$T/v.json"
  case "$(verdict "$T/v.json" "$T/pass-findings.json")" in
    *"does not match templates/ci/verdict.schema.json)") ok "verdict.jq refuses a result without $k" ;;
    *) bad "verdict.jq takes a result without $k" ;;
  esac
done
for k in $(jq -r '.["$defs"].finding.required[]' "$CI/findings.schema.json"); do
  jq "del(.findings[0].$k)" "$T/pass-findings.json" > "$T/f.json"
  case "$(verdict "$T/pass-result.json" "$T/f.json")" in
    *"does not match templates/ci/findings.schema.json)") ok "verdict.jq refuses a finding without $k" ;;
    *) bad "verdict.jq takes a finding without $k" ;;
  esac
done
for s in $(jq -r '.["$defs"].finding.properties.rule5b.enum[]' "$CI/findings.schema.json"); do
  case "$s" in passed) sev=8 ;; *) sev=5 ;; esac
  jq --arg s "$s" --argjson sev "$sev" '.findings[0].rule5b = $s | .findings[0].severity = $sev' "$T/pass-findings.json" > "$T/f.json"
  case "$(verdict "$T/pass-result.json" "$T/f.json")" in
    *"does not match"*|*"is missing)"*|*"another threshold)"*) bad "verdict.jq refuses the Rule 5b status $s, which the schema allows" ;;
    *) ok "verdict.jq takes the Rule 5b status $s" ;;
  esac
done
for pair in '8 not-required' '5 passed'; do
  jq --argjson sev "${pair%% *}" --arg s "${pair#* }" '.findings[0].severity = $sev | .findings[0].rule5b = $s' \
    "$T/pass-findings.json" > "$T/f.json"
  case "$(verdict "$T/pass-result.json" "$T/f.json")" in
    *"does not match templates/ci/findings.schema.json)") ok "verdict.jq refuses severity ${pair% *} with ${pair#* }, as the schema does" ;;
    *) bad "verdict.jq takes severity ${pair% *} with ${pair#* }" ;;
  esac
done
for f in '../outside.rs' '/etc/passwd' 'a/../../b.rs'; do
  jq --arg f "$f" '.findings[0].file = $f' "$T/pass-findings.json" > "$T/f.json"
  case "$(verdict "$T/pass-result.json" "$T/f.json")" in
    *"does not match templates/ci/findings.schema.json)") ok "verdict.jq refuses the finding path $f" ;;
    *) bad "verdict.jq takes the finding path $f" ;;
  esac
done
for n in $(jq -r '.["$defs"].analyzer.properties.name.enum[]' "$CI/findings.schema.json"); do
  jq --arg n "$n" '.analyzers = [{"name": $n, "status": "ran"}]' "$T/pass-findings.json" > "$T/f.json"
  jq --arg n "$n" '.structured_output.analyzers_run = [$n]' "$T/pass-result.json" > "$T/v.json"
  expect "pass, with the analyzer $n" "auditor: verdict: pass (threshold 7, analyzers run: $n)" "$(verdict "$T/v.json" "$T/f.json")"
done
# quick-scan: one commit, its own report name
jq 'del(.commits.base) | .command = "quick-scan" | .report = "audit_3/QUICK-SCAN.md"' "$T/pass-findings.json" > "$T/f.json"
jq '.structured_output.command = "quick-scan"' "$T/pass-result.json" > "$T/v.json"
expect "pass: a quick-scan run" "auditor: verdict: pass (threshold 7, $RAN)" "$(verdict "$T/v.json" "$T/f.json" 7 quick-scan)"
jq '.report = "audit_3/PR-REPORT.md"' "$T/f.json" > "$T/f2.json"
case "$(verdict "$T/v.json" "$T/f2.json" 7 quick-scan)" in
  *"does not match templates/ci/findings.schema.json)") ok "verdict.jq refuses a quick-scan file that names diff-audit's report" ;;
  *) bad "verdict.jq takes a quick-scan file that names diff-audit's report" ;;
esac

# ---- 5. the CI runs this suite -----------------------------------------------------------------------------------
n=$(grep -c -F 'for t in scripts/tests/*.sh; do' .github/workflows/corpus-check.yml)
check "corpus-check.yml's suite loops run every scripts/tests/*.sh, this one included ($n loops)" [ "$n" -ge 1 ]

echo "---- ci template: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
