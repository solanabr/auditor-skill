---
name: auditor:threat-model
description: Builds the pre-review threat model as audit_<n>/threat-model.md — an asset inventory (crown-jewel funds/authority/data and where they live), an actor x capability table (each actor → what they can do → what they must NOT be able to do), and a trust-boundary map (which CPIs/accounts/inputs cross a trust boundary). No verdicts — attacker-goal enumeration that seeds report §4.4/§4.6/§4.7 and gives vuln-hunter/economic-analyst concrete goals to falsify. Automated flow drives it via the threat-modeler agent; interactive flow asks the human.
argument-hint: "[path] [--auto]"
allowed-tools: Read, Write, Glob, Grep, Task
---

# auditor-skill — Pre-Review Threat Model

**Arguments:** $ARGUMENTS

Build the threat model **before** the manual review judges anything — analogous to how context reconstruction (Phase 0.5) precedes verdicts. Read `templates/threat-model.md` (the artifact you fill) and the report sections it feeds: `templates/audit-report.md` §4.4 (Trust Model & Actors), §4.6 (Assumptions & Simplifications), §4.7 (Systemic / Thematic Risks). This is target enumeration, **not** a findings document — no severities, no verdicts.

## Inputs

- The in-scope **code** (instructions, accounts, PDAs, CPIs, arithmetic).
- `audit_<n>/intake.md` §6 — the trust-model inputs (who is trusted). The actor list to expand. Read it if present; if absent, run `/auditor:intake` first or reconstruct actors from the code and note intake was unavailable.
- `audit_<n>/worksheets/context/*` — `context-builder`'s invariants, assumptions, and external-interaction risks, if the context phase has run.
- `audit-mem warm <program-id>` prior invariants + open FP rulings, if `tools/auditor-tools` is built (skip cleanly otherwise).

## Mode

- **Automated (`--auto`, the `audit-cycle` path)** — spawn the **`threat-modeler`** agent (opus). It reconstructs the three artifacts from code + context worksheets and emits `audit_<n>/threat-model.md`, every claim cited to `file:line`.
- **Interactive (default)** — ask the human the model questions a tool cannot settle: which assets are the crown jewels, which actors are genuinely trusted vs. untrusted, what each actor must be prevented from doing. Fill the artifact from their answers plus the code.

## What to build

Fill `templates/threat-model.md`:

1. **Asset inventory** — crown-jewel assets by class (funds / authority / data), where each lives (account / PDA), cited to definition/holding site, and the worst case if compromised. Aligns to report §4.2.
2. **Actor × capability table** — for each actor (permissionless user / LP / keeper / admin / upgrade authority / oracle / CPI callee): trust level, what they **can** do (→ the instruction @ `file:line`), and — the load-bearing column — what they must **NOT** be able to do. Column layout aligns to report §4.4 (Privileges / Trust Assumption); the "must NOT" cells are the security properties the reviewers test.
3. **Trust-boundary map** — every CPI, caller-supplied account, instruction arg, `remaining_accounts`, and sysvar that crosses from lower to higher trust, cited, with whether it is validated (cite the guard or mark `✗`). Feeds report §4.6 (what is trusted) and §4.7 (transitive/indirect CPI risk).
4. **Attacker goals to test** — derived from the "must NOT" cells and the unvalidated crossings, each mapped to the checklists / known-vectors that hunt it. These are the goals `vuln-hunter` and `economic-analyst` try to achieve; a goal that turns out reachable becomes a finding downstream through the Rule 5b gate.

## Discipline

- **No verdicts.** An unvalidated crossing is *where to look*, not a bug. Do not rate severity here.
- Every claim cites `file:line`. Banned words: "probably", "might", "seems", "should" — write `UNKNOWN — needs manual review` (cited) instead.
- Model every black-box external (oracle, caller-supplied program, `remaining_accounts`) as adversarial.

## Output

`audit_<n>/threat-model.md`. Synthesis lifts the asset inventory, actor table, and trust boundaries directly into report §4.4/§4.6/§4.7; the attacker-goals list steers the domain-partitioned review.
