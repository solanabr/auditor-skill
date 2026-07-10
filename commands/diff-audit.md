---
name: auditor:diff-audit
description: PR / commit-scoped differential audit — audits only changed functions (plus 1-hop callers), flags removed security checks, and prioritizes by risk × blast radius.
argument-hint: "[base..head | PR number]"
allowed-tools: Read, Grep, Glob, Bash, Task
---

# auditor-skill — Differential Audit (Mode 4)

**Arguments:** $ARGUMENTS

1. Compute the changed set: `git diff --name-only <base>..<head>` (default `main..HEAD`).
2. Run Phase 0.5 Context Reconstruction on changed functions + their direct callers/callees (1-hop).
3. Risk-classify changed files (auth / crypto / value-transfer / validation-removal = HIGH). Git-blame removed security code — code deleted in a "fix" / "CVE" commit is a CRITICAL regression.
4. Run only the checklist items + known-vectors matching the changed files' language/domain, through the Rule 5b gate.
5. Emit `audit_<n>/PR-REPORT.md` — changed-surface verdicts + findings only. Reuses the methodology corpus; skips whole-repo discovery.
