# auditor-skill — Agent Orchestration

This skill audits with a small team of subagents (see `agents/`) and, when available,
orchestrates Trail of Bits execution tooling vendored at `vendor/trailofbits`.

## Flow (full audit)

1. **`context-builder`** (sonnet) — Phase 0 setup + Phase 0.5 context reconstruction. No verdicts; understanding only.
2. **`vuln-hunter`** (opus) — item-by-item walk against in-scope checklists + phase-triggered vectors. Every finding with N ≥ 6 must pass the Rule 5b gate. Delegates SAST / harnesses to Trail of Bits when present (see `references/orchestration/boundary-map.md`).
3. **`economic-analyst`** (opus) — checklist 06 + economic vectors; drives `/economic-sim` (Surfpool mainnet-fork) to quantify profitability for High/Critical economic findings.
4. **`audit-reporter`** (sonnet) — deterministic assembly: Scope Coverage, findings, Phase 4.5 maturity scorecard, remediation roadmap → `audit_<n>/REPORT.md`.

Cheap lanes: `/quick-scan` and `/diff-audit` skip the full item-by-item walk.

## Trail of Bits (vendored submodule)

Trail of Bits provides tool **execution** auditor-skill cannot do in prose (CodeQL/Semgrep taint, fuzzing, coverage, mutation, IR-level zeroize/constant-time analysis). It is a **reference, not a copy** — CC-BY-SA stays with Trail of Bits; auditor-skill's own corpus is MIT. Methodology patterns re-implemented natively are credited in `ATTRIBUTION.md`. If the submodule is not initialized, subagents fall back to native grep checks and say so in the report.
