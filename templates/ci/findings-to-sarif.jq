# findings-to-sarif.jq — a run's audit_<n>/findings.json (templates/ci/findings.schema.json) as SARIF 2.1.0:
#
#   jq -f findings-to-sarif.jq audit_<n>/findings.json > findings.sarif
#
# One run, with one result per finding. A finding's rule is its first checklist or known-vector id, or
# auditor-skill/unclassified when it has none, and the rule's security-severity, which GitHub code scanning
# reads, is the highest severity among its results. A result's level follows its own severity (OUTPUT-RULES.md
# Rule 1): error from 7, warning from 4, note below; an [UNCONFIRMED] or [PARTIAL] one, which never counts
# toward the verdict, is a note. The invocation is successful only for a final file that stopped nowhere and
# whose analyzers all ran. A file without the fields this needs stops jq with an error, and nothing is printed.
# On a public repository the SARIF stays on the runner, as findings.json does (OUTPUT-RULES.md Rule 11d).

def need(cond; $what): if cond then . else error("findings.json: " + $what) end;
def level:
  if .rule5b == "unconfirmed" or .rule5b == "partial" then "note"
  elif .severity >= 7 then "error" elif .severity >= 4 then "warning" else "note" end;
def rule_id: if (.refs | length) > 0 then .refs[0] else "auditor-skill/unclassified" end;
# a relative path as a URI reference: each part percent-encoded, the / between them kept
def uri: split("/") | map(@uri) | join("/");

need(type == "object" and .schema_version == 1; "not a version 1 findings file")
| need((.findings | type) == "array" and (.analyzers | type) == "array"; "findings or analyzers is not a list")
| need(all(.findings[]; type == "object" and (.id | type) == "string" and (.title | type) == "string"
    and (.file | type) == "string" and (.rule5b | type) == "string" and (.refs | type) == "array"
    and (.severity | type == "number" and . == floor and . >= 1 and . <= 10)
    and (.line | type == "number" and . == floor and . >= 1)); "a finding lacks a field, or holds one of the wrong type")
| . as $doc
| [.findings[] | . + {rule: rule_id}] as $fs
| {
    "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "auditor-skill",
          informationUri: "https://github.com/solanabr/auditor-skill",
          rules: [$fs | group_by(.rule)[] | {
            id: .[0].rule,
            shortDescription: {
              text: (if .[0].rule == "auditor-skill/unclassified" then "auditor-skill finding with no checklist or known-vector id"
                else "auditor-skill " + .[0].rule end)
            },
            properties: {"security-severity": ((map(.severity) | max | floor | tostring) + ".0"), tags: ["security"]}
          }]
        }
      },
      automationDetails: {id: ("auditor-skill/" + ($doc.command | tostring) + "/")},
      invocations: [{
        executionSuccessful: ($doc.final == true and $doc.stopped == "none" and all($doc.analyzers[]; .status == "ran"))
      }],
      results: [$fs[] | {
        ruleId: .rule,
        level: level,
        message: {text: .title},
        locations: [{physicalLocation: {artifactLocation: {uri: (.file | uri)}, region: {startLine: .line}}}],
        properties: {"finding-id": .id, severity: .severity, rule5b: .rule5b, refs: .refs}
      }]
    }]
  }
