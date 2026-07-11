# auditor-skill — Agent Orchestration

This skill audits with a small team of subagents (see `agents/`) and, when available,
orchestrates Trail of Bits execution tooling vendored at `vendor/trailofbits`.

## Flow (full audit)

0. **Pre-scan (optional, deterministic).** If `tools/auditor-tools/` is built, `audit-scan` emits the instruction/constraint/PDA/arithmetic map at ~$0 and `audit-mem warm <program-id>` loads prior invariants + open false-positive rulings — seeding `context-builder` with a map instead of a blank repo, and letting `vuln-hunter` auto-suppress findings that carry a prior `FALSE_POSITIVE` ruling (`audit-mem check`). Falls back to the grep walk if the toolchain is absent. See [references/orchestration/pre-scan.md](references/orchestration/pre-scan.md).
1. **`context-builder`** (sonnet) — Phase 0 setup + Phase 0.5 context reconstruction. No verdicts; understanding only.
1b. **`threat-modeler`** (opus) — from the context worksheets + `audit_<n>/intake.md`, emits `audit_<n>/threat-model.md` (asset inventory · actor×capability · trust boundaries) that hands the reviewers attacker goals and seeds report §4.4/§4.6/§4.7. No verdicts.
2. **`vuln-hunter`** (opus) — item-by-item walk against in-scope checklists + phase-triggered vectors. Every finding with N ≥ 6 must pass the Rule 5b gate. Delegates SAST / harnesses to Trail of Bits when present (see `references/orchestration/boundary-map.md`).
3. **`economic-analyst`** (opus) — checklist 06 + economic vectors; drives `/economic-sim` (Surfpool mainnet-fork) to quantify profitability for High/Critical economic findings.
4. **`peer-reviewer`** (opus) — independent reconciliation on top-severity findings (N≥8, contested N≥7): re-derives from the code (reusing the context worksheets), delegates to Trail of Bits `second-opinion`/`fp-check` when present; emits CONFIRM / DISPUTE / DOWNGRADE. *(Neodyme independent dual-review.)*
5. **`audit-reporter`** (sonnet) — deterministic assembly: Scope Coverage, findings, Phase 4.5 maturity scorecard, remediation roadmap → `audit_<n>/REPORT.md`.

Between review and reconciliation, **`/triage`** batch-dedups the candidate set (root-cause + `audit-mem` suppression/regression), re-applies Rule 5b, and splits real findings from Notes & Nitpicks. On demand for High/Critical findings, **`poc-engineer`** + **`patch-engineer`** (via `/poc` / `/patch`, or `/audit-cycle --with-poc`) emit executable PoCs + verified fix patches (see [references/orchestration/poc-harness.md](references/orchestration/poc-harness.md)).

Cheap lanes: `/quick-scan` and `/diff-audit` skip the full item-by-item walk.

Full-lifecycle flows: **`/audit-cycle`** (fully automated → client report) and **`/audit-assist`** (human-in-the-loop, iterative); **`/re-audit`** for fix-review. See [references/audit-lifecycle/methodology.md](references/audit-lifecycle/methodology.md).

## Trail of Bits (vendored submodule)

Trail of Bits provides tool **execution** auditor-skill cannot do in prose (CodeQL/Semgrep taint, fuzzing, coverage, mutation, IR-level zeroize/constant-time analysis). It is a **reference, not a copy** — CC-BY-SA stays with Trail of Bits; auditor-skill's own corpus is MIT. Methodology patterns re-implemented natively are credited in `ATTRIBUTION.md`. If the submodule is not initialized, subagents fall back to native grep checks and say so in the report.
