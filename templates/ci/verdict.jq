# verdict.jq — the CI verdict of one /auditor:diff-audit --ci or /auditor:quick-scan --ci run, as the one line
# templates/ci/auditor-pr.yml prints. Run as
#
#   jq -n -r --slurpfile result <result.json or /dev/null> --slurpfile findings <findings.json or /dev/null> \
#     --argjson threshold <N> --arg command <diff-audit|quick-scan> --arg mode <strict|default> \
#     --arg base <full commit id, or empty> --arg head <full commit id> --arg problem <a fixed reason, or empty> \
#     -f verdict.jq
#
# result.json is what `claude -p --output-format json --json-schema <templates/ci/verdict.schema.json>`
# printed: in Claude Code 2.1.304 an object of type "result" whose subtype is "success" or one of four error
# subtypes, with is_error, and on success the reply checked against the schema as structured_output.
# findings.json is the run's audit_<n>/findings.json (templates/ci/findings.schema.json). The line is
#
#   auditor: verdict: pass|fail (threshold N, analyzers run: <names, or none>[; not run: <names>][; stopped: <step>][; <reason>])
#
# built from the numbers and fixed words both schemas allow and from the reasons written below, never from
# text the review wrote, so on a public repository it shows no finding, count or path (OUTPUT-RULES.md Rule
# 11d). It says pass only when all of these hold:
#   - --arg problem is empty;
#   - the result is a success whose structured_output matches the verdict schema for this command, threshold
#     and mode, and names a run directory (run 1 or more);
#   - the run's findings.json matches the findings schema, is final, and names the same run, command,
#     threshold, mode, stopped step and analyzers, and the commits given;
#   - the verdict follows from it: no finding of severity at least the threshold whose rule5b is passed,
#     undetermined or not-required, no analyzer not run, stopped none;
#   - the result and the file both say pass.
# A run that stopped before it made a run directory (run 0) is a fail with no findings file.

def member($xs): . as $x | any($xs[]; . == $x);
def analyzers: ["audit-scan", "lock-delta", "deps-artifacts", "web3js-history", "semgrep", "static-analysis",
  "grep-scanners", "cargo-audit", "npm-audit"];
def counted: ["passed", "undetermined", "not-required"];
def int_in($lo; $hi): type == "number" and . == floor and . >= $lo and . <= $hi;
def sha: type == "string" and test("^([0-9a-f]{40}|[0-9a-f]{64})$");
def names: type == "array" and all(.[]; member(analyzers)) and length == (unique | length);
def exact_keys($ks): type == "object" and keys == ($ks | sort);
def relpath: type == "string" and length >= 1 and length <= 4096 and (startswith("/") | not)
  and (test("(^|/)[.][.](/|$)") | not) and (test("[[:cntrl:]\\\\]") | not);

def verdict_ok:
  exact_keys(["schema_version", "command", "mode", "verdict", "threshold", "run", "stopped", "analyzers_run",
    "analyzers_not_run"])
  and .schema_version == 1
  and (.command | member(["diff-audit", "quick-scan"]))
  and (.mode | member(["strict", "default"]))
  and (.verdict | member(["pass", "fail"]))
  and (.threshold | int_in(1; 10))
  and (.run | int_in(0; 999999))
  and (.stopped | member(["none", "preflight", "run-directory", "arguments", "changed-set", "denied"]))
  and (.analyzers_run | names)
  and (.analyzers_not_run | names)
  and ([.analyzers_run[], .analyzers_not_run[]] | length == (unique | length));

def finding_ok:
  exact_keys(["id", "severity", "title", "file", "line", "rule5b", "refs"])
  and (.id | type == "string" and test("^F-[0-9]{1,4}$"))
  and (.severity | int_in(1; 10))
  and (.title | type == "string" and length >= 1 and length <= 200)
  and (.file | relpath)
  and (.line | int_in(1; 100000000))
  and (.rule5b | member(["passed", "undetermined", "unconfirmed", "partial", "not-required"]))
  and (.refs | type == "array" and all(.[]; type == "string" and test("^[A-Z]{2,4}-[0-9]{3}$"))
    and length == (unique | length))
  and (if .severity >= 6 then .rule5b != "not-required" else .rule5b != "passed" end);

def analyzer_ok:
  type == "object" and (keys - ["name", "status", "reason"]) == [] and has("name") and has("status")
  and (.name | member(analyzers)) and (.status | member(["ran", "not-run"]))
  and ((has("reason") | not) or (.reason | type == "string"));

def findings_ok:
  exact_keys(["schema_version", "command", "mode", "final", "verdict", "threshold", "stopped", "run", "report",
    "commits", "analyzers", "findings"])
  and .schema_version == 1
  and (.command | member(["diff-audit", "quick-scan"]))
  and (.mode | member(["default", "strict"]))
  and (.final | type == "boolean")
  and (.verdict | member(["pass", "fail"]))
  and (.threshold | int_in(1; 10))
  and (.stopped | member(["none", "arguments", "changed-set", "denied"]))
  and (.run | type == "string" and test("^audit_[0-9]+$"))
  and .report == .run + (if .command == "diff-audit" then "/PR-REPORT.md" else "/QUICK-SCAN.md" end)
  and (.commits | type == "object" and (keys - ["base", "head"]) == [] and (.head | sha)
    and ((has("base") | not) or (.base | sha)))
  and (.commits | has("base")) == (.command == "diff-audit")
  and (.analyzers | type == "array" and all(.[]; analyzer_ok) and (map(.name) | length == (unique | length)))
  and (.findings | type == "array" and all(.[]; finding_ok) and (map(.id) | length == (unique | length)))
  and (.final or .verdict == "fail")
  and (.stopped == "none" or .verdict == "fail");

# the verdict a valid findings file implies at threshold $t
def follows($t):
  if (.final | not) or .stopped != "none" or any(.analyzers[]; .status == "not-run")
    or any(.findings[]; .severity >= $t and (.rule5b | member(counted)))
  then "fail" else "pass" end;

($result | if type == "array" and length == 1 then .[0] else null end) as $r
| ($findings | if type == "array" and length == 1 then .[0] else null end) as $f
| (if ($r | type) == "object" then $r.structured_output else null end) as $v
| ($v | verdict_ok) as $vok
| (if $problem != "" then $problem
  elif ($r | type) != "object" or $r.type != "result" then "the review returned no result"
  elif $r.subtype != "success" then "the review ended early ("
    + ($r.subtype | if member(["error_max_budget_usd", "error_max_turns", "error_during_execution",
        "error_max_structured_output_retries"]) then . else "unknown" end) + ")"
  elif $r.is_error != false then "the review ended in an error"
  elif ($vok | not) then "its result does not match templates/ci/verdict.schema.json"
  elif $v.command != $command then "its result is another command's"
  elif $v.threshold != $threshold then "its result names another threshold"
  elif $v.mode != $mode then "preflight did not name " + $mode + " mode"
  elif $v.run == 0 then
    (if ($v.stopped | member(["preflight", "run-directory", "arguments", "denied"])) | not then
      "its result names no run directory"
    elif $v.verdict != "fail" then "its result says pass for a run that stopped"
    else null end)
  elif $f == null then "the run's findings file is missing"
  elif ($f | findings_ok) | not then "the run's findings file does not match templates/ci/findings.schema.json"
  elif $f.run != "audit_\($v.run)" then "the findings file is another run's"
  elif $f.command != $command or $f.threshold != $threshold or $f.mode != $mode or $f.stopped != $v.stopped then
    "the findings file and the result disagree"
  elif $f.commits.head != $head or ($command == "diff-audit" and $f.commits.base != $base) then
    "the findings file pins other commits"
  elif ($f.final | not) then "the run ended before its last step"
  elif ([$f.analyzers[] | select(.status == "ran") | .name] | sort) != ($v.analyzers_run | sort)
    or ([$f.analyzers[] | select(.status == "not-run") | .name] | sort) != ($v.analyzers_not_run | sort) then
    "the findings file and the result name other analyzers"
  elif ($f | follows($threshold)) != $f.verdict then "the verdict does not follow from the findings file"
  elif $f.verdict != $v.verdict then "the findings file and the result disagree"
  else null end) as $why
| (if $why == null and $vok and $v.verdict == "pass" then "pass" else "fail" end) as $out
| "auditor: verdict: " + $out + " (threshold \($threshold), analyzers run: "
  + (if $vok then ($v.analyzers_run | if length == 0 then "none" else join(", ") end) else "unknown" end)
  + (if $vok and ($v.analyzers_not_run | length) > 0 then "; not run: " + ($v.analyzers_not_run | join(", "))
    else "" end)
  + (if $vok and $v.stopped != "none" then "; stopped: " + $v.stopped else "" end)
  + (if $why != null then "; " + $why else "" end) + ")"
