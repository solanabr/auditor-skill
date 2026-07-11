# Output & Rigor

The severity model, the validation gate that keeps findings honest, and the report conventions. Back to the [docs index](README.md).

Everything here is specified in [`OUTPUT-RULES.md`](../OUTPUT-RULES.md) (mandatory for every audit). This guide is the practical summary.

## Severity: a 1-10 scale

Findings use a numeric severity 1-10, not the C/H/M/L/I letters.

| Score | Label | Meaning |
|-------|-------|---------|
| 10 | CRITICAL | permissionless drain, total fund loss, instant exploit |
| 9 | CRITICAL | fund loss with minimal preconditions; privilege to admin |
| 8 | HIGH | fund loss with specific preconditions; partial drain |
| 7 | HIGH | significant economic damage; privilege escalation; data breach |
| 6 | MEDIUM | state corruption, griefing, DoS, limited economic manipulation |
| 5 | MEDIUM | logic bugs, inconsistent state, moderate info leak |
| 4 | LOW | minor info leak; security-relevant code-quality issue |
| 3 | LOW | missing best practice with theoretical risk |
| 2 | INFO | hardening suggestion |
| 1 | INFO | cosmetic, no security impact |

There is no separate "Suggestion" tier — hardening ideas live at severity 1-2.

### Impact × Likelihood — and principled downgrades

The base number is the **impact**. A high-impact mechanism with a **low-likelihood** trigger lands lower, and the finding **must state which axis drove it** (e.g. "impact 8, but the exploit needs a compromised admin → reported at 6"). Downgrades are never on vibes — you cite a named lever with a worked justification:

- **Self-sacrifice / no incentive** — the attacker burns their own funds, or a cheaper path reaches the same outcome.
- **Economic infeasibility (with numbers)** — show the bound: "the token would need to be worth ~1000× to profit; max gain ≤ 1 lamport at normal state."
- **Recoverable / self-healing** — the harmful state reverses at bounded cost (next epoch clears it).
- **Bounded blast radius** — worst case is a small contained loss, not a drain.
- **Defense-in-depth exceeds norms** — a redundant guard makes the gap non-exploitable in practice.
- **Privilege required** — a role-gated path caps severity; a permissionless variant would score higher.

### Notes & Nitpicks (below severity 1)

Not every observation is a finding. Issues with **no security impact** — style, naming, redundant code, micro-optimizations, doc gaps — are **not** scored 1-10. They go in a separate **Notes & Nitpicks** list: a bulleted `file:line — observation` list, no severity, no remediation-tracking obligation. This keeps the findings table reserved for genuine security issues and prevents nit-inflation from diluting the severity signal. A note graduates to a severity-1 Informational finding only if it carries a concrete (if minor) security implication. `/auditor:triage` performs this split.

### Repository Risk Score (internal only)

After all items are checked, the internal report computes a Repository Risk Score = the max finding severity, banded (any ≥9 → 10 CRITICAL do-not-deploy; ≥7 → HIGH; ≥5 → MEDIUM; ≥3 → LOW; ≤2 → MINIMAL). This is the team's deploy-gate — it stays in the internal template and is **never** presented to a client as a "safe to deploy" verdict (see [report templates](#two-report-templates)).

## The Rule 5b validation gate

Over-reporting is the primary failure mode of an AI auditor, so **any `[FAIL-N]` with N≥6 is provisional** until it carries filled gate blocks. This is what separates a confirmed finding from a guess.

- **N≥6** requires a **Reachability** block + a **Math / State-Bounds** block.
- **N≥7** additionally requires an **Attacker-Model** block.

If the blocks can't be completed with cited evidence (`file:line`), the finding is **downgraded — never left as a bare `[FAIL-N]`**:

- **`[PARTIAL]`** — a real defense-in-depth gap, but the exploit path is unproven.
- **`[UNCONFIRMED]`** — the gate failed on **reachability or bounds** (unreachable / unbounded as written). Reported for manual follow-up; **not counted as a confirmed FAIL** in the metrics.
- **`[UNDETERMINED]`** — distinct: the path **is** reachable but its full impact couldn't be quantified in scope. Carried at its likely severity band with "extent not determined within this assessment" — a real, flagged finding, not a suppressed one. Reachable-but-unquantified ≠ unreachable.

What the blocks contain:

```
Reachability:  entry point @ file:line · signer/authority required · preconditions (each cited)
               · guard analysis (constraints that could block it, and why they don't) · verdict
Math/Bounds:   vulnerable expression @ file:line · input domain · boundary that breaks
               · worked case (concrete numbers or the state sequence) · quantified net effect
Attacker-Model: capability · capital/setup cost · profit/damage · atomicity · net (profitable/griefing/privilege)
```

A **rejected** finding looks like: *"input ≥ 16 and header = 8 ⟹ input − header ≥ 8, so the subtraction cannot underflow. Downgraded `[FAIL-7]` → `[UNCONFIRMED]`."*

**Accepted PoC forms.** A runnable exploit is ideal but not the only proof — for access-control/logic findings a **structured attacker-narrative** (actor → capability → numbered steps → guard bypassed → quantified outcome) is a first-class PoC. And when the missing check is provable at `file:line` but the full exploit math can't be confirmed in the window, you may still report at severity **provided** the finding carries explicit uncertainty phrasing — do not mechanically bury a real syntactic gap as `[UNCONFIRMED]`. Executable evidence is tagged with a `[PoC-*]` tier orthogonal to severity ([poc-and-patches.md](poc-and-patches.md)).

## Every item gets a verdict

The proof the auditor actually checked everything: every in-scope checklist item and every phase-triggered known-vector appears in the report with an explicit verdict, in checklist order (never grouped by verdict).

| Verdict | Rule |
|---------|------|
| `[PASS]` | cite the file/code that proves it secure. One line. |
| `[FAIL-N]` | severity 1-10, `file:line`, impact, fix. ≥3 lines; N≥6 carries the Rule 5b gate. |
| `[PARTIAL]` | what's missing, `file:line`, recommended improvement. |
| `[N/A]` | *why* it doesn't apply. Never bare N/A. |

Honesty tags (Rule 10): `[PASS*]` / `[FAIL-N*]` with a confidence note for less-than-certain calls; `[INCOMPLETE — context lost]`, `[PARTIAL — file truncated]`, `[UNKNOWN — unfamiliar pattern]` where applicable. **Never** mark `[PASS]` without reading the code; **never** mark `[N/A]` just because context ran out.

## Scope-gated loading

auditor-skill does not read its whole corpus up front. It **discovers** (enumerate extensions/markers — cheap, always), **declares scope** (detected languages + `--scope` → the in-scope checklist set), and **loads on demand** (a checklist when its phase begins; a known-vector only when its phase + language/domain trigger reaches it). Out-of-scope checklists and vectors are **never read** — a Rust-only repo never loads the Python checklist or the TS/web vectors.

Completeness is measured **output-side**: the audit is COMPLETE iff every in-scope item + phase-triggered vector has a verdict. Out-of-scope items render `[N/A — out of scope: <reason>]` from the gate (not from reading the file). Every full report includes a **Scope Coverage** table: per checklist and vector group, `IN-SCOPE` (items evaluated / total) or `OUT-OF-SCOPE (reason)`. Details on scopes: [getting-started.md](getting-started.md#scopes-at-a-glance).

## Two report templates

Two documents, two audiences — do not conflate them.

| | Internal (`templates/report-template.md`) | Client-facing (`templates/audit-report.md`) |
|--|-------------------------------------------|----------------------------------------------|
| Used by | `/auditor:audit`, `/auditor:audit-report` | `/auditor:audit-cycle`, `/auditor:audit-assist` |
| Risk score | **keeps** the numeric Repository Risk Score (the team's deploy-gate) | **no** risk score presented as a deploy verdict |
| Shape | Executive Summary → Scope Coverage → Scope & Methodology → Findings → Detailed Item Results → Known Vector Results → Instruction Matrix → State Model → Code Maturity Scorecard → Remediation Roadmap → Appendices | Executive Summary → Scope & Engagement (envelope, commits, in/out of scope) → Methodology → System Overview (§4.4 Trust Model, §4.6 Assumptions & Simplifications, §4.7 Systemic Risks) → Severity Classification → Findings → Code Maturity Assessment → Appendices (incl. Disclaimer) |

The client report follows firm convention: a **maturity narrative** (9-category, 0-4 weakest-link scorecard from Phase 4.5), **trust-model caveats**, a mandatory **Assumptions & Simplifications** section (what the review took as given — trusted admins, honest oracles, upgrade-authority custody, out-of-scope programs — so "no finding here" reads against a stated assumption, not a blanket clearance), an **engagement envelope** (named agents/effort, pinned commit range), an explicit **out-of-scope** list, and a **LOC-vs-budget** note.

## The no-"safe to deploy" convention

Like a real firm, the **client-facing report issues no "safe to deploy" guarantee** — the deployment decision is the client's. The internal template retains the numeric risk score for the team's own gating, but that number is never surfaced to a client as a green light. The honest framing throughout: this is **audit-shaped automation — a rigorous, reproducible first pass**, not a substitute for a human firm audit; pair it with human business-logic, economic-model, and legal-compliance review before mainnet ([SKILL.md → When NOT to Use](../SKILL.md)).

## Report file naming

| Output | File |
|--------|------|
| Full audit report | `audit_<n>/REPORT.md` |
| PR / diff report | `audit_<n>/PR-REPORT.md` |
| Re-audit finding-diff | `audit_<n+1>/RE-AUDIT.md` |
| Intake / threat model | `audit_<n>/intake.md` · `audit_<n>/threat-model.md` |
| Remediation roadmap | `audit_<n>/roadmap.md` |
| Per-instruction worksheets | `audit_<n>/worksheets/{instruction}.md` |

Where `<n>` = count of existing `audit_*/` directories + 1.
