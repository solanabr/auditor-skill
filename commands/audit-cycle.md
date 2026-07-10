---
name: auditor:audit-cycle
description: Flow A — fully automated audit-firm lifecycle. Runs scope → context → tool-assisted first pass → domain-partitioned manual review → independent reconciliation → client report end-to-end, and delivers a professional audit report (MD + optional PDF). Audit-shaped automation, not a substitute for a human firm audit.
argument-hint: "[path] [--scope full|program|backend|frontend]"
allowed-tools: Read, Grep, Glob, Bash, Task
---

# auditor-skill — Flow A: Automated Audit Cycle → Client Report

**Arguments:** $ARGUMENTS

Run the full audit-firm lifecycle autonomously, from intake to a deliverable report. Read `OUTPUT-RULES.md` first (mandatory format, severity 1-10, the **Rule 5b** validation gate) and `references/audit-lifecycle/methodology.md` (the firm-spine → skill-mechanism mapping this flow follows). Do not pause for a human — where a firm would ask the client, use the `QUESTIONS.md` defaults and record the assumption in the report.

## Lifecycle

1. **Scope / intake (Rule 0 + commit-pin).** Discover the repo, declare scope (`SKILL.md` → SCOPE-GATED LOADING), and honor `--scope`. Pin the audited commit (`git rev-parse HEAD`) so the report names exactly what was reviewed. If no human is present to answer intake, apply `QUESTIONS.md` defaults and list every assumed answer under "Scope & Assumptions".

2. **Context reconstruction (Phase 0.5).** Spawn `context-builder` (sonnet). It produces the instruction matrix, state model, and per-function worksheets in `audit_<n>/worksheets/context/`. No verdicts yet — understanding only. These worksheets are the shared substrate every later phase reuses (avoids re-reconstruction cost).

3. **Tool-assisted first pass (shift-left).** If `vendor/trailofbits/plugins` is present (`test -d vendor/trailofbits/plugins`), run ToB `static-analysis` (SAST) over the in-scope languages and fold the SARIF **as evidence that directs manual attention** — not as verdicts (`references/orchestration/boundary-map.md`). If absent, run the `discovery/grep-commands.md` native scanners and note the tooling gap. Load in-scope `references/methodologies/*` per their protocol markers (`SKILL.md` reference table) so domain review has the right playbook.

4. **Domain-partitioned manual review (NOT N identical clones).** Partition the surface by domain and run reviewers **in parallel over disjoint surfaces** — naive N-way fan-out of the same prompt produces ~87% false positives, so each reviewer owns a distinct partition:
   - `vuln-hunter` (opus) — in-scope checklists + phase-triggered known-vectors over the program / language surface.
   - `economic-analyst` (opus) — checklist 06 + economic known-vectors + the loaded `references/methodologies/*` over the value-flow surface.
   
   **Anti-false-positive gate at the leaf.** Each reviewer triages every candidate finding through **Rule 5b** + `references/false-positives.md` **before emitting it**. A finding that cannot complete the Rule 5b Reachability + Math/State-Bounds block (Attacker-Model for N≥7) is downgraded to `[PARTIAL]` / `[UNCONFIRMED]` — no bare high-severity claims cross the boundary.

5. **Independent reconciliation.** Spawn `peer-reviewer` (opus) on the **top-severity survivors**: every confirmed finding at **N≥8**, plus any **N≥7** the primary could not PoC. It re-derives each finding **from the code** (reusing `audit_<n>/worksheets/context/*`), not from the primary's write-up. Reconcile: a `DISPUTE` forces the finding back through Rule 5b or to `[UNCONFIRMED]`; a `DOWNGRADE` re-rates it; disagreement forces re-examination before anything ships.

6. **Synthesis.** Spawn `audit-reporter` (sonnet): deduplicate findings **by root-cause**, classify by severity (1-10), order by **severity / business importance**, and fill the **client-facing** audit report — `templates/audit-report.md` (maturity narrative + trust-model caveats + disclaimers, **no deploy guarantee**). The internal `templates/report-template.md` retains the numeric Repository Risk Score for the team's own gating; the client document never presents a risk score as a "safe to deploy" verdict (`references/audit-lifecycle/methodology.md` §1).

7. **Deliver.** Emit `audit_<n>/REPORT.md` (the deliverable). Then best-effort PDF: if `pandoc` is available, run `scripts/report-to-pdf.sh audit_<n>/REPORT.md` to render `audit_<n>/REPORT.pdf`; if pandoc (or the script) is absent, skip silently — **Markdown is the deliverable**, the PDF is a convenience.

## Honesty clause (state this in the report)

This is **audit-shaped automation — a rigorous, reproducible first pass**, not a substitute for a human audit firm. It does not replace human business-logic, economic-model, and legal-compliance review. Recommend pairing with a human audit before mainnet (`SKILL.md` → When NOT to Use).
