---
name: auditor:intake
description: Interactive engagement intake (alias /scope). Walks QUESTIONS.md and persists the answers to audit_<n>/intake.md — the durable intake artifact both audit-cycle and audit-assist read, instead of answers living only in conversation state. Captures scope + commit pin, languages/frameworks, protocol class, compliance, severity calibration, and the trust-model inputs that feed the report's Trust Model and Assumptions sections. Interactive mode asks; automated mode records the applied default.
argument-hint: "[path] [--auto]"
allowed-tools: Read, Write, Glob, Grep
---

# auditor-skill — Engagement Intake / Scope

**Arguments:** $ARGUMENTS

Turn the passive `QUESTIONS.md` questionnaire into a **persisted** `audit_<n>/intake.md`. Read `QUESTIONS.md` first (the source questions + the "How Answers Affect the Audit" table) and `templates/intake.md` (the artifact you fill). This fixes the gap where intake answers lived only in conversation state — both `/auditor:audit-cycle` and `/auditor:audit-assist` read the file you write here.

## Mode

- **Interactive (default)** — walk the human through the questions. Ask sharp, answerable questions; do not dump all 45 at once. Group by section, skip questions the repo already answers (detected language, framework), confirm rather than re-ask.
- **`--auto`** — no human present (the `audit-cycle` path). Apply the `QUESTIONS.md` default for every unanswered question and record each under **Assumed Defaults (Unanswered)** with the exact default applied. Never leave a field blank; never assume silently.

## Steps

1. **Discover.** Enumerate the repo (extensions, `Anchor.toml` / `Cargo.toml` / `package.json` / `.github/`). Pre-fill languages, framework, monorepo shape, and DEX/oracle/CPI hints from what the code shows — do not ask what the code already answers.

2. **Pin the commit.** `git rev-parse HEAD`. Record the full 40-char SHA and branch so the report names exactly what was reviewed.

3. **Warm from prior audits (if available).** If `tools/auditor-tools` is built, `audit-mem warm <program-id>` injects the prior protocol profile and open false-positive rulings — pre-fill from it and confirm rather than re-ask. If absent, skip.

4. **Walk QUESTIONS.md → intake.md.** Fill every section of `templates/intake.md`:
   - **Scope & commit pin** — in/out of scope (honor `Q44` excludes), `--scope` boundary.
   - **Languages & frameworks** (`Q3`–`Q7`) — drives the scope-gated checklist set (`SKILL.md` → SCOPE-GATED LOADING).
   - **Protocol class** (`Q1`, `Q17`–`Q24`) — gates checklist 06 + economic known-vectors when funds are handled.
   - **Compliance** (`Q35`–`Q38`) — gates checklist 18.
   - **Severity calibration** (`Q8`, `Q10`, `Q11`, `Q40`–`Q41`) — record the concrete lever applied (mainnet → +1 on fund findings; TVL > $1M → double-weight criticals; single-wallet upgrade authority → auto Severity 8+), per the QUESTIONS.md effects table. Feeds report §5.
   - **Trust-model inputs (critical)** (`Q11`, `Q14`–`Q16`, `Q23`) — for each of admin / upgrade authority / oracle / keeper / LP / permissionless user, record who holds it, what they can do, and what the review trusts them **NOT** to do. "Untrusted / permissionless" is a valid, important answer. This seeds report §4.4 and §4.6, and is the actor list `/auditor:threat-model` expands.
   - **Security history** (`Q25`–`Q28`).

5. **Record assumed defaults.** In `--auto`, every unanswered question goes in the **Assumed Defaults (Unanswered)** table with the default applied and its basis. Each entry is carried into the report's **§4.6 Assumptions & Simplifications** as an explicit assumption — so "no finding here" reads against a stated default, not a blanket clearance. In interactive mode this table should be empty (everything was asked); if non-empty, it lists only what the human explicitly deferred.

6. **Write `audit_<n>/intake.md`.** `{n}` = count of existing `audit_*/` dirs + 1 (`OUTPUT-RULES.md` Rule 9). This file is the intake of record.

## Output

`audit_<n>/intake.md` — the persisted intake artifact. Confirm the path and note whether it was filled interactively or from defaults. Both flows read this file at their scope/intake step.
