# Report Format — auditor-skill

> Load at report assembly / Phase 5 / by `audit-reporter`.

This file holds the report-time layout details factored out of [OUTPUT-RULES.md](../OUTPUT-RULES.md) so the review-time floor stays small. The rules keep their canonical numbers in OUTPUT-RULES.md (Rule 2, Rule 6, Rule 8, Rule 9); their bodies live here and are loaded only when a report is being assembled.

---

## Rule 2 § Executive Summary

Every audit output — regardless of size — MUST start with an **Executive Summary** block. This goes at the very top of the report.

```markdown
## Executive Summary

**Repository:** {org/repo}
**Commit:** {short SHA}
**Date:** {YYYY-MM-DD}
**Scope:** {FULL / PROGRAM / BACKEND / FRONTEND / DEVOPS}
**Repository Risk Score:** {1-10} — {CRITICAL/HIGH/MEDIUM/LOW/MINIMAL}

### What We Found

{2-4 sentences in plain language. What was audited. What is the overall security posture.
Highlight the most important finding(s) if any critical/high exist.
State whether the code is safe to deploy or not.}

### Severity Distribution

| Score | Label | Count |
|-------|-------|-------|
| 10 | 🔴 CRITICAL | 0 |
| 9 | 🔴 CRITICAL | 0 |
| 8 | 🟠 HIGH | 0 |
| 7 | 🟠 HIGH | 0 |
| 6 | 🟡 MEDIUM | 0 |
| 5 | 🟡 MEDIUM | 0 |
| 4 | 🔵 LOW | 0 |
| 3 | 🔵 LOW | 0 |
| 2 | ⚪ INFO | 0 |
| 1 | ⚪ INFO | 0 |
| **Total Findings** | | **0** |

### Items Verified

| Metric | Count |
|--------|-------|
| Total checklist items | {N} |
| PASS | {N} |
| FAIL | {N} |
| PARTIAL | {N} |
| N/A | {N} |
| Completion | {%} |
```

---

## Rule 6 § Report Sections Order

Every full audit report follows this exact section order:

```
1. Executive Summary          (Rule 2 — always first)
2. Scope Coverage             (in-scope checklists / vector groups, items evaluated / total)
3. Scope & Methodology        (languages, files, LOC, checklists applied)
4. Findings                   (severity ≥ 4, full blocks, grouped by severity descending)
5. Detailed Item Results      (all in-scope checklist items, item-by-item verdicts)
6. Known Vector Results       (each in-scope KV, with verdict)
7. Instruction Matrix         (on-chain only — if applicable)
8. State Model Verification   (on-chain only — if applicable)
9. Code Maturity Scorecard    (Phase 4.5 — 9 categories, 0-4)
10. Remediation Roadmap       (by severity; maturity categories scoring <= 1 first)
11. Appendices                (tool versions, environment, disclaimer)
```

---

## Rule 8 § Metric Computation

The report MUST include computed metrics at the end of the Item Results section.

```markdown
### Audit Metrics

| Metric | Value |
|--------|-------|
| Total items evaluated | {N} |
| PASS | {N} ({%}) |
| FAIL | {N} ({%}) |
| PARTIAL | {N} ({%}) |
| N/A | {N} ({%}) |
| **Pass rate** (excl. N/A) | **{%}** |
| Highest severity found | {1-10} |
| Repository Risk Score | **{1-10}** |

### Known Vector Metrics

| Metric | Value |
|--------|-------|
| Total known vectors | 131 |
| PASS | {N} |
| FAIL | {N} |
| PARTIAL | {N} |
| N/A | {N} |
| Completion | {%} |

### Per-Checklist Summary

| # | Checklist | Items | Pass | Fail | Partial | N/A | Pass Rate |
|---|-----------|-------|------|------|---------|-----|-----------|
| 01 | Account Validation | 88 | | | | | % |
| ... | ... | ... | ... | ... | ... | ... | ... |
| **Total** | | **{N}** | | | | | **{%}** |
```

---

## Rule 9 § File Naming

| Output | Filename |
|--------|----------|
| Full audit report | `audit_{N}/REPORT.md` |
| Remediation roadmap | `audit_{N}/roadmap.md` |
| Per-instruction worksheets | `audit_{N}/worksheets/{instruction_name}.md` |
| Checkpoint (session) | session memory: `audit-checkpoint.md` |

Where `{N}` is the next audit number (count existing `audit_*/` directories + 1).
