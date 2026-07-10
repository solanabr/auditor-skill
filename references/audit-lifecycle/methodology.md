# Audit Methodology — The Firm Lifecycle, Run by This Skill

> **Load when:** running `/audit-cycle` or `/audit-assist`.
> **Scope:** how auditor-skill executes the professional-firm engagement spine
> (`firm-coverage.md`) using its **existing** mechanisms — no new phases, no renumbering.
> **How to use:** `firm-coverage.md` is the external model; this file is the mapping. Each
> lifecycle phase is performed by a mechanism the skill already has (a `QUESTIONS.md`, an
> `OUTPUT-RULES.md` rule, a `FULL-AUDIT.md` phase, a subagent, a `references/` file, a
> template, or a command). Read it before either flow so the run matches how firms work.
>
> *(Credit: public firm methodologies — see `firm-coverage.md`. Patterns re-implemented natively
> are credited in `ATTRIBUTION.md`.)*

---

## 1. Our method = the firm spine, executed by skill mechanisms

The seven-phase firm spine maps one-to-one onto mechanisms that already exist. Nothing below
introduces a new phase number — Phase 0.5, Phase 4.5, and Rule 5b stay exactly as they are.

| Firm lifecycle phase | Skill mechanism that performs it |
|----------------------|----------------------------------|
| **Scoping / Intake** | `QUESTIONS.md` (project/trust-model/scope intake) + **Rule 0** scope-gating (`OUTPUT-RULES.md`) + **FULL-AUDIT Phase -1 / Phase 0** — the exact **commit is pinned at Phase 0.1** (records program ID, versions, git branch + commit hash) |
| **Context** | **FULL-AUDIT Phase 0.5** context reconstruction, driven by the **`context-builder`** subagent — invariants/assumptions/external-risks per function, every claim cited to `L#`; no verdict may precede it |
| **Tool-assisted pass** | `references/orchestration/boundary-map.md` — when `vendor/trailofbits` is present, ToB **`static-analysis`** emits SARIF that **directs manual attention** to the risky surface; **grep fallback** via `discovery/grep-commands.md` when the submodule is absent |
| **Manual review (PRIMARY)** | Checklists **01–20** walked item-by-item by **`vuln-hunter`**, plus **`economic-analyst`** for checklist 06 + economic vectors, guided by `references/methodologies/*` (AMM, lending, perps, oracles, stablecoin, liquid-staking, governance). **Each finding is self-triaged at the leaf**: it must pass **Rule 5b** and clear `references/false-positives.md` before it counts |
| **Independent reconciliation** | **NEW `peer-reviewer`** subagent — an independent second pass over the **top-severity survivors** only; delegates to vendored ToB **`second-opinion`** / **`fp-check`** when present. This is Neodyme's dual-review pattern, scoped to keep cost bounded |
| **Verification** | The **Rule 5b** gate (Reachability + Math/State-Bounds + Attacker-Model) backed by a real **PoC / harness** — ToB property/fuzz harnesses per `boundary-map.md`, and **Surfpool mainnet-fork** simulation for economic findings (`economic-analyst`) |
| **Synthesis** | **`audit-reporter`** — dedup by **root cause**, classify by **severity**, and order by **importance** (business impact first, per Zellic) |
| **Maturity** | **FULL-AUDIT Phase 4.5** — the 9-category, 0–4 weakest-link code-maturity scorecard |
| **Reporting** | **`templates/audit-report.md`** (client-facing) — follows firm convention: **maturity narrative + trust-model caveats + disclaimers, NO deploy-guarantee**. The internal **`templates/report-template.md`** keeps the numeric **Repository Risk Score** for the team's own gating |
| **Fix-review / re-audit** | **NEW `/re-audit`** — re-checks each prior finding as **FIXED / STILL-OPEN / REGRESSED**, plus a **sibling-patch-propagation sweep** (did the fix leave an unpatched twin elsewhere?). This is the Halborn commit-diff / Zenith delta pattern |

**Two reports, two audiences (do not conflate).** `audit-report.md` is what a client receives —
it mirrors what firms actually deliver (findings + maturity + caveats, deployment left to the
client, per `firm-coverage.md` §4). `report-template.md` is the internal artifact and *retains*
the Repository Risk Score (`OUTPUT-RULES.md` Rule 1) as the team's deploy-gate. The client-facing
document never presents a risk score as a "safe to deploy" verdict.

---

## 2. Flow A — fully-automated agent team

`/audit-cycle`. The team runs the whole spine end-to-end and emits the audit document with no
human in the loop.

**Shape of the run:**

1. **Intake + scope** — `QUESTIONS.md` answers feed Rule 0 scope-gating; Phase -1/0 pins the
   commit and declares the in-scope checklist set.
2. **Context** — `context-builder` reconstructs every non-trivial function (Phase 0.5). No
   verdict is allowed before this exists for the target function.
3. **Tool-directed fan-out** — the fan-out is **domain-partitioned, NOT N identical clones**.
   `vuln-hunter` instances take partitioned checklist/domain slices (account-validation,
   arithmetic, CPI/PDA, state-machine…) and `economic-analyst` takes value-flow / checklist 06;
   ToB `static-analysis` SARIF (or grep) points each at its risky surface first. **Each agent
   self-triages at the leaf** — a candidate finding only survives if it passes **Rule 5b** and
   is not a `false-positives.md` entry.
4. **Reconciliation** — `peer-reviewer` independently re-reviews the **top-severity survivors**
   (delegating to ToB `second-opinion` / `fp-check` when present) and reconciles disputes —
   the Neodyme dual-review step, cost-scoped to the findings that matter.
5. **Report** — `audit-reporter` dedups by root cause, orders by importance, fills Phase 4.5
   maturity, and writes the audit document → **Markdown**, with **optional PDF** export.

**Firm precedent:** tool-first attention (**Sec3** shift-left), independent second pass
(**Neodyme** dual-review), importance-ordered synthesis (**Zellic**).

---

## 3. Flow B — AI-assisted iterative

`/audit-assist`. The same spine, but the human is a checkpoint after **each phase** — the tool
proposes, the human steers, and the two converge on the audit document.

**Shape of the run:**

1. Run one phase (scope → context → tool pass → manual review → reconciliation → synthesis).
2. **Checkpoint** — surface, for that phase: the **confirmed findings** (each already through
   the Rule 5b gate), the **next focus area**, and **open questions on business logic / trust
   model** (which admin is trusted? is this oracle assumed honest? what is the upgrade-authority
   custody?) — the context on-chain code cannot answer by itself.
3. **Human steers** — confirms/deprioritizes findings, answers the trust-model questions,
   redirects scope. Their answers refine severity (per `QUESTIONS.md` → severity calibration)
   and prune false positives before the next phase.
4. **Converge** — iterate until the audit document is complete.
5. **Delta re-review** — subsequent changes go through **`/re-audit`** (FIXED / STILL-OPEN /
   REGRESSED + sibling-propagation sweep), not a full re-run.

**Firm precedent:** periodic client-facing progress updates (**Trail of Bits** weekly reports),
delta/fix re-review across revisions (**Zenith** multi-revision, **Halborn** commit-diff).

---

## 4. What both flows guarantee (and what they don't)

Both flows are the **firm spine**, so both inherit its discipline and its limits:

- **Manual review stays primary** — tooling directs attention (Phase: tool-assisted), it never
  replaces the item-by-item walk. Delegation *augments*, never replaces, a native verdict
  (`boundary-map.md` §Rule).
- **Every finding is verified** — Rule 5b + `false-positives.md` at the leaf; unproven
  high-severity claims are downgraded to `[PARTIAL]` / `[UNCONFIRMED]`, never shipped bare.
- **The deliverable matches firm output** — findings + maturity narrative + trust-model caveats
  + disclaimers. The client-facing `audit-report.md` issues **no "safe to deploy" guarantee**;
  the deployment decision is the client's (`firm-coverage.md` §4).
- **The audit is point-in-time, scoped, and non-exhaustive** — it is a thorough first pass,
  pairable with (not a replacement for) a human firm engagement, exactly as `SKILL.md` →
  *When NOT to Use* states.

---

## Methodology fast pass

- [ ] Commit pinned + scope declared (`QUESTIONS.md` + Rule 0 + Phase 0.1) before any reading (§1)
- [ ] Context reconstructed (`context-builder`, Phase 0.5) before any `[FAIL-N≥6]` (§1)
- [ ] Tooling ran **first to direct attention**, manual walk stayed primary (§1, §4)
- [ ] Fan-out was **domain-partitioned**, not identical clones; each leaf self-triaged via Rule 5b (§2)
- [ ] Top-severity survivors passed **`peer-reviewer`** independent reconciliation (§1, §2)
- [ ] Report dedup'd by root cause, **importance-ordered**, with Phase 4.5 maturity (§1)
- [ ] Client-facing `audit-report.md` used (maturity + caveats, **no deploy guarantee**); risk-score stayed internal (§1)
- [ ] Changes re-reviewed via **`/re-audit`** (FIXED/STILL-OPEN/REGRESSED + sibling sweep), not a full re-run (§1, §3)
