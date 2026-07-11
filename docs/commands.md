# Command Reference

All 15 commands, grouped by phase. Namespace is `auditor` → invoke as `/auditor:<name>`. Back to the [docs index](README.md).

Each entry lists the argument hint from the command's own frontmatter, when to reach for it, and what it emits. For how they compose into a full engagement, see [audit-flows.md](audit-flows.md).

| Phase | Commands |
|-------|----------|
| Scoping | [`intake`](#auditorintake) · [`threat-model`](#auditorthreat-model) |
| Review | [`audit`](#auditoraudit) · [`quick-scan`](#auditorquick-scan) · [`deep-review`](#auditordeep-review) · [`diff-audit`](#auditordiff-audit) · [`spec-audit`](#auditorspec-audit) · [`audit-cycle`](#auditoraudit-cycle) · [`audit-assist`](#auditoraudit-assist) |
| Validation | [`triage`](#auditortriage) · [`economic-sim`](#auditoreconomic-sim) · [`poc`](#auditorpoc) · [`patch`](#auditorpatch) |
| Reporting | [`audit-report`](#auditoraudit-report) |
| Fix-review | [`re-audit`](#auditorre-audit) |

---

## Scoping

### `/auditor:intake`
Alias `/scope`. **Arg:** `[path] [--auto]`
Turns the passive `QUESTIONS.md` questionnaire into a persisted `audit_<n>/intake.md` — the durable intake artifact both `/auditor:audit-cycle` and `/auditor:audit-assist` read (fixes intake living only in conversation state). Pins the commit (`git rev-parse HEAD`), pre-fills languages/framework/monorepo shape from what the code shows, warms from prior audits via `audit-mem warm` if the tools are built, and captures scope, protocol class, compliance, severity calibration, and the trust-model inputs (who holds admin / upgrade authority / oracle / keeper / LP, and what the review trusts them NOT to do).
**When:** before any serious audit. **Emits:** `audit_<n>/intake.md`.
`--auto` records the applied default for every unanswered question (no-human pipelines); interactive mode asks sharp, answerable questions and skips what the repo already answers.

### `/auditor:threat-model`
**Arg:** `[path] [--auto]`
Builds the pre-review threat model *before* verdicts (analogous to how context reconstruction precedes verdicts): an **asset inventory** (crown-jewel funds/authority/data and where they live), an **actor × capability table** (each actor → what it can do → what it must NOT be able to do — the load-bearing column), and a **trust-boundary map** (every CPI, caller-supplied account, instruction arg, `remaining_accounts`, sysvar that crosses into higher trust, with whether it is validated). Ends with **attacker goals to test**, mapped to the checklists/vectors that hunt them.
**When:** after intake + context, before the manual review. **Emits:** `audit_<n>/threat-model.md` (seeds report §4.4/§4.6/§4.7).
No verdicts, no severities — target enumeration only. `--auto` drives the `threat-modeler` agent; interactive asks the human. Every claim cites `file:line`; banned words → `UNKNOWN — needs manual review`.

---

## Review

### `/auditor:audit`
**Arg:** `[path] [--scope full|program|backend|frontend]`
Full scope-gated audit end-to-end in one session: reads `OUTPUT-RULES.md`, follows `FULL-AUDIT.md` with scope-gated loading, spawns `context-builder` → `vuln-hunter` → `economic-analyst` → `audit-reporter`. Every in-scope item + phase-triggered vector gets `[PASS]`/`[FAIL-N]`/`[PARTIAL]`/`[N/A]`; N≥6 findings pass Rule 5b or downgrade.
**When:** whole-repo audit where you handle triage yourself. **Emits:** `audit_<n>/REPORT.md` (internal template, numeric risk score) with executive summary, Scope Coverage table, findings, Phase 4.5 maturity scorecard, remediation roadmap.
Uses ToB tooling if present, else the grep scanners (noting the gap).

### `/auditor:quick-scan`
**Arg:** (none)
Fast triage: discovery + scope + static analysis (ToB `static-analysis` if present, else `discovery/grep-commands.md`) + only CRITICAL/HIGH known-vectors for the detected domains — not the full set.
**When:** first look, CI gate. **Emits:** findings with severity + `file:line`; explicitly states it is a triage pass and points to `/auditor:audit`.

### `/auditor:deep-review`
**Arg:** `<file> [function|instruction]`
Deep single-unit review: read the file, run Phase 0.5 context reconstruction on the target (purpose, inputs, ≥3 invariants, ≥5 assumptions, ≥3 external-interaction risks, each cited to `L#`), fill the instruction worksheet, cross-reference shared-state code, adversarially model exploitation.
**When:** one handler/endpoint/function needs depth. **Emits:** per-item verdicts + findings for that unit only. N≥6 findings pass Rule 5b.

### `/auditor:diff-audit`
**Arg:** `[base..head | PR number]`
Differential audit (Mode 4). Changed set via `git diff --name-only base..head` (default `main..HEAD`); Phase 0.5 on changed functions + 1-hop callers/callees; risk-classify (auth/crypto/value-transfer/validation-removal = HIGH); git-blame removed security code (deletion in a "fix"/"CVE" commit = CRITICAL regression); run only the matching checklist items + vectors through Rule 5b.
**When:** a PR / commit range, not the whole tree. **Emits:** `audit_<n>/PR-REPORT.md` — changed-surface verdicts only; skips whole-repo discovery.

### `/auditor:spec-audit`
**Arg:** `<spec-file> [program-path]`
Spec-compliance (Mode 5). Extract a requirement list (Spec-IR) from the spec; Phase 0 + Phase 0.5; map each instruction/state field to the spec's stated behavior; build a **Compliance Matrix** — each requirement → `[MET]` / `[VIOLATED-N]` / `[UNIMPLEMENTED]` / `[UNDOCUMENTED-BEHAVIOR]`, cited to code `L#`.
**When:** a spec / whitepaper / RFC is supplied. **Emits:** the Compliance Matrix + findings. `[VIOLATED-N≥6]` passes Rule 5b; `[UNDOCUMENTED-BEHAVIOR]` (code the spec never authorizes) is itself a finding.

### `/auditor:audit-cycle`
**Arg:** `[path] [--scope full|program|backend|frontend]` (+ `--with-poc`)
**Flow A — fully automated audit team.** Runs the whole lifecycle autonomously (scope → context → threat model → tool-assisted pass → domain-partitioned review → triage → independent reconciliation → synthesis) with no human; applies `QUESTIONS.md` defaults and records each assumption.
**When:** hands-off engagement → deliverable. **Emits:** the **client-facing** `audit_<n>/REPORT.md` (maturity narrative + trust-model caveats + disclaimers, **no deploy guarantee**), optional PDF, `harnesses/` if any were generated, and — with `--with-poc` — `poc/` + `patches/` for confirmed N≥7. Full detail: [audit-flows.md](audit-flows.md#flow-a--audit-cycle-automated).

### `/auditor:audit-assist`
**Arg:** `[path] [--scope full|program|backend|frontend]`
**Flow B — human-in-the-loop.** Same lifecycle as `audit-cycle`, but pauses at checkpoints (after scope, context, each review phase, triage, reconciliation) to surface (a) confirmed findings, (b) next-focus plan, (c) the targeted questions only a human can answer, then folds answers back in.
**When:** business-logic / trust-model judgment matters. **Emits:** the same client-facing report, converged iteratively. Detail: [audit-flows.md](audit-flows.md#flow-b--audit-assist-interactive).

---

## Validation

### `/auditor:triage`
**Arg:** `[audit_<n>] [--program-id <id>]`
One consolidated, re-runnable triage checkpoint over the candidate finding set (so calibration is auditable in one place, not diffused across leaf reviewers). De-dups by **root-cause signature** (with `audit-mem check` auto-suppressing prior-ruled false positives and `audit-mem regressions` flagging FIXED→re-observed, when the tools are built), re-applies **Rule 5b** in batch (every N≥6 carries its validation block or is downgraded to `[UNCONFIRMED]`/`[UNDETERMINED]`, every downgrade **quantified**), and splits real findings (severity 1-10) from the **Notes & Nitpicks** list.
**When:** between the review phase and reconciliation; re-run after any new candidates. **Emits:** the triaged set + a **suppression appendix** recording what was withheld and why (idempotent — re-running folds in new candidates without re-litigating settled ones).

### `/auditor:economic-sim`
**Arg:** `<finding-or-instruction>`
Quantifies a candidate economic finding: model capital/setup cost, extractable value, atomicity, flash-loanable ceilings per venue; compute whether profit > cost at 1/5/10% manipulation; if a Surfpool mainnet-fork is available, reproduce deposit→manipulate→withdraw against forked state for a real net P/L.
**When:** a High/Critical economic finding needs the dollar figure Rule 5b requires. **Emits:** the quantified PoC (dollar figures, not yes/no). See [power-tools.md](power-tools.md#surfpool-economic-simulation).

### `/auditor:poc`
**Arg:** `<finding-id | file:line> [--fork] [--fuzz] [--force]`
Turns a *confirmed* finding into a runnable exploit: resolve the finding + its context worksheet, gate on severity (N≥7 by default; `--force` overrides), detect the toolchain (never assume), pick the harness by finding type (Mollusk / LiteSVM / Surfpool `--fork` / Trident-cargo-fuzz `--fuzz`), spawn `poc-engineer` to fill a feature-gated `vulnerable`/`fixed` crate that **asserts** the flaw.
**When:** demonstrate a High/Critical finding executably. **Emits:** `audit_<n>/poc/F-xxx/` (crate + one-command `run.sh`) + the earned `[PoC-*]` tier. Never hard-fails — toolchain absence → `[PoC-ATTEMPTED]` + the prose PoC is kept. Full detail: [poc-and-patches.md](poc-and-patches.md).

### `/auditor:patch`
**Arg:** `<finding-id> [--verify-with-mutation]`
Drafts and verifies a fix: `patch-engineer` writes a **minimal idiomatic** unified diff against the pinned commit that closes *exactly* the cited bound (obeys the Rust/Anchor/Pinocchio rules), applies it to a **scratch worktree** (never the client tree), rebuilds, and **re-runs the finding's PoC** — which must now revert. `--verify-with-mutation` adds `mewt` mutation + a blast-radius check.
**When:** hand the client a proven fix. **Emits:** `audit_<n>/patches/F-xxx.patch` + `VERIFICATION.md` + the `[FIX-*]` tier. Proposal only — `[FIX-VERIFIED]` requires an *executed* revert; no PoC → `[FIX-PROPOSED]` ceiling. Detail: [poc-and-patches.md](poc-and-patches.md).

---

## Reporting

### `/auditor:audit-report`
**Arg:** `[audit-dir]`
Aggregates the session's checkpoints and findings into the final report: de-dup + classify by severity, assemble from `templates/report-template.md` (executive summary with safe-to-deploy verdict, Scope Coverage table, per-checklist verdicts, findings, Phase 4.5 maturity scorecard, remediation roadmap CRITICAL→INFO).
**When:** you ran the walk in pieces and need the report assembled. **Emits:** `audit_<n>/REPORT.md`; flags any in-scope item lacking a verdict as `[INCOMPLETE — in-scope item without verdict]`. (Driven by the `audit-reporter` agent, which does assembly only — no code re-analysis.)

---

## Fix-review

### `/auditor:re-audit`
**Arg:** `[prior-report] [base..head]`
Fix-review / re-audit against a prior `audit_<n>/REPORT.md` (arg 1) and the current tree (delta `base..head`, default `main..HEAD`). Classifies every prior finding **FIXED / PARTIALLY-FIXED / STILL-OPEN / REGRESSED / ACKNOWLEDGED / DISPUTED** — each non-open status citing the **remediation commit/PR hash**, and re-running Rule 5b on the fix (a cosmetic/incomplete patch is not FIXED). Then audits the changed surface for NEW findings (diff-audit path) and runs a **sibling-patch-propagation sweep** for un-patched twins of every fixed anti-pattern (the sweep always emits a result — "no siblings found" is a first-class output).
**When:** the team responded to findings and you verify. **Emits:** `audit_<n+1>/RE-AUDIT.md` — finding-diff table + new findings + sibling sweep + updated deploy verdict.
Verification-verb discipline: use "we re-tested and confirmed" only when *you* verified against the current tree; a client's "we fixed it" stays "client states fixed (unverified)" and is not FIXED until independently confirmed.
