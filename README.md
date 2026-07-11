<p align="center">
  <img src="assets/banner.png" alt="auditor-skill — the best all-in-one security audit skill for Solana programs and applications" width="100%">
</p>

# auditor-skill — Open-Source AI Security Audit Skill

> Production-grade security audit for any codebase, powered by AI agents.
> 20 checklists · 1,346 verification items · 131 known attack vectors · executable PoCs + fix patches
> A full audit-firm lifecycle (automated + interactive) · Benchmarked against CertiK, SOC 2, OWASP Top 10:2025
> Verify COSTS.md as a referecence - Running this audit can burn a lot of credits.

---

## What Is This?

auditor-skill is a **skill file** (a structured prompt + checklists) that turns any LLM agent (Copilot, Cursor, Windsurf, Claude Code, Codex, etc.) into a professional-grade security auditor. It reads your code file by file, checks 1,346 items across 20 security domains, tests against 131 real-world attack vectors, and produces a structured report with severity scores.

**It is not a SaaS product.** It's a folder of markdown files you clone into your repo or give to an AI agent.

> **Adaptation required before use.** This skill was originally developed for a specific Solana/Anchor DeFi project and then generalized. Before running it on your project you must update `discovery/file-map.md` with your actual folder structure, file names, and state variable names. The questionnaire in `QUESTIONS.md` is a blank template — fill it out (or run `/auditor:intake`) for your project before invoking the auditor. Everything else (checklists, known vectors, output rules) is fully portable as-is.

---

## What It Does (v7.0)

- **A full audit-firm lifecycle, two ways.** `/auditor:audit-cycle` runs the whole engagement autonomously (intake → context → threat model → tool-assisted pass → domain-partitioned review → triage → independent peer review → synthesis) and hands back a professional client report. `/auditor:audit-assist` runs the same pipeline **interactively**, pausing at checkpoints for the calls only you can make.
- **Executable proofs, not just prose.** For High/Critical findings, `/auditor:poc` builds a runnable exploit (Mollusk / LiteSVM / Surfpool-fork / fuzz) that *asserts* the vulnerability, and `/auditor:patch` drafts a minimal fix and **proves it reverts the exploit**. Evidence is tiered (`[PoC-REPRODUCED]` … `[PoC-PROSE]`); prose is never dropped when a harness can't be built.
- **Token-efficient by construction.** An optional Rust pre-scanner (`audit-scan`) enumerates the risky surface deterministically (~$0), cutting ~30-40% of input tokens on large programs. A cross-audit memory store (`audit-mem`) gives exact dedup, regression detection, and false-positive suppression across runs.
- **15 commands, 8 specialized agents.** Scoping, threat modeling, deep review, economic simulation, differential/PR audits, spec compliance, triage, fix-review — each a first-class command; the automated flow chains eight purpose-built agents.
- **Deep Solana coverage.** 12 protocol methodologies (AMM/CLMM, lending, perps, oracles, stablecoins, liquid staking, governance, bridges, multisig/custody, Token-2022, NFT marketplaces, launchpads), framework idioms (Anchor/Native/Pinocchio), and a reusable invariant catalog — loaded only when the code triggers them.
- **Rigor gates against AI over-reporting.** A validation gate (reachability + math/state-bounds + attacker-model) every high-severity finding must survive, Impact×Likelihood severity with principled downgrades, and a Notes & Nitpicks tier that keeps the findings table honest.
- **Real tooling, vendored.** Trail of Bits execution plugins (SAST, fuzzing, coverage, mutation) ship as a submodule; the native corpus works fully without them.

### Documentation

| Guide | What's inside |
|-------|---------------|
| [docs/getting-started.md](docs/getting-started.md) | Install, submodule init, build the Rust tools, run your first audit |
| [docs/audit-flows.md](docs/audit-flows.md) | The lifecycle and when to use each flow (`/audit`, `/audit-cycle`, `/audit-assist`, `/re-audit`) |
| [docs/commands.md](docs/commands.md) | Reference for all 15 commands |
| [docs/agents.md](docs/agents.md) | The 8-agent roster and how they chain |
| [docs/power-tools.md](docs/power-tools.md) | `audit-scan`, `audit-mem`, Trail of Bits, Surfpool, PoC/patch harnesses |
| [docs/poc-and-patches.md](docs/poc-and-patches.md) | Executable exploit + fix-patch delivery |
| [docs/output-and-rigor.md](docs/output-and-rigor.md) | Severity, the Rule 5b gate, scope-gated loading, report format |

---

## Supported Languages & Frameworks

| Language | Checklists | Items |
|----------|-----------|-------|
| Rust (Solana/Anchor) | 01-07 | 517 |
| Rust (off-chain services) | 20 | 17 |
| TypeScript / Node.js | 08-09 | 163 |
| React / Next.js | 08, 10 | 136 |
| Python | 14 | 82 |
| Go / Java / Ruby / PHP | 15 | 88 |
| AI / agent components | 19 | 31 |
| **Always applied** (any repo) | 11-13, 16-18 | 372 |
| **Total** | **20** | **1,346** |

---

## Installation

### Option 1: Claude Code plugin marketplace (recommended)

```
/plugin marketplace add solanabr/auditor-skill
/plugin install auditor
```

Registers the marketplace and installs the `auditor` plugin — all 15 `/auditor:*` commands and 8 agents. Then initialize the Trail of Bits execution tooling once (optional but recommended):

```bash
git submodule update --init --recursive
```

### Option 2: Install script (any project)

Drops the skill into your project's `.claude/skills/` and inits the tooling:

```bash
# from your project root — read it first (it's a security tool, after all):
git clone https://github.com/solanabr/auditor-skill.git
./auditor-skill/install.sh                                   # → ./.claude/skills/auditor-skill
./auditor-skill/install.sh ~/.claude/skills/auditor-skill    # or install globally

# one-liner (convenience):
curl -fsSL https://raw.githubusercontent.com/solanabr/auditor-skill/main/install.sh | bash
```

### Option 3: Clone into your project manually

```bash
git clone https://github.com/solanabr/auditor-skill.git .claude/skills/auditor-skill
```

Claude Code auto-discovers skills under `.claude/skills/`; invoke by asking your agent to "audit this repo using the auditor-skill" (use **Option 1** for the `/auditor:*` slash commands). For other agents (Cursor, Windsurf, Copilot, Codex), copy the folder anywhere the agent reads and point it at `SKILL.md`.

### Option 4: Feed files to the API directly

If you're building a service, send `SKILL.md` + `OUTPUT-RULES.md` + `FULL-AUDIT.md` as system context and the target repo files as user content to any LLM API.

### Tool execution (Trail of Bits) + optional Rust tools

auditor-skill vendors **Trail of Bits** as a git submodule (`vendor/trailofbits`) for real tool execution — SAST, fuzzing, coverage, mutation. Options 1 and 2 init it for you; to do it manually:

```bash
git submodule update --init --recursive
```

The native corpus works fully **without** it (it falls back to grep-based checks and notes where deeper tooling would run). With the submodule initialized, the auditor delegates to the vendored tools per [`references/orchestration/boundary-map.md`](references/orchestration/boundary-map.md). For the optional token-efficiency tools (`audit-scan` pre-scanner + `audit-mem` memory), build the Rust CLIs:

```bash
cd tools/auditor-tools && cargo build --release
```

---

## Before Running an Audit

### Scope-Gated Intake (v5.0)

auditor-skill does not bulk-read its whole corpus. It discovers the repo, declares an audit scope ([OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 0), and loads only the in-scope checklists and vectors on demand:

- root docs + `OUTPUT-RULES.md` (always),
- only the `checklists/*.md` the detected languages require (e.g. `14-python-safety.md` only if `.py` is present),
- a `known-vectors/*.md` file only when its phase + language trigger reaches it,
- `discovery/*.md` and `templates/*.md` lazily, at the phase that uses them.

The audit is complete when every **in-scope** item has an explicit verdict; out-of-scope items render `[N/A — out of scope]` from the gate.

1. **Fill out the questionnaire:** Copy [QUESTIONS.md](QUESTIONS.md) and answer all questions. This tells the auditor what checklists to apply, what severity calibration to use, and what compliance frameworks matter.

2. **Review estimated costs:** Check [COSTS.md](COSTS.md) for token/dollar estimates based on your repo size and chosen model.

3. **Choose your scope:**

| Scope | What It Covers | Estimated Time (50K lines) |
|-------|---------------|---------------------------|
| FULL | Everything — all 20 checklists + 131 vectors | 60-90 min |
| PROGRAM | Smart contract only (checklists 01-07) | 20-35 min |
| BACKEND | Backend API (checklists 08-09) | 15-25 min |
| FRONTEND | Frontend (checklists 08, 10) | 15-25 min |
| DEVOPS | Infra + supply chain (checklists 11-13) | 10-15 min |
| QUICK | Known vectors only (grep-based scan) | 5-10 min |

---

## Folder Structure

```
auditor-skill/
├── README.md                ← YOU ARE HERE
├── SKILL.md                 ← Orchestrator — the AI agent reads this first
├── OUTPUT-RULES.md          ← Mandatory output format, severity scale
├── FULL-AUDIT.md            ← Step-by-step execution plan for complete audits
├── QUESTIONS.md             ← Pre-audit questionnaire (fill before running)
├── COSTS.md                 ← Estimated costs by model and repo size
│
├── known-vectors/           ← Individual attack vector files (for contributors)
│   ├── INDEX.md             ← One-line index of all vectors
│   ├── 001-private-key-leak.md
│   ├── 002-flash-loan-price-manipulation.md
│   ├── ...
│   └── 100-insufficient-backup-disaster-recovery.md
│
├── checklists/              ← 20 micro-checklists (the core verification items)
│   ├── 01-program-account-validation.md    (88 items)
│   ├── 02-program-access-control.md        (50 items)
│   ├── 03-program-arithmetic-safety.md     (63 items)
│   ├── 04-program-cpi-pda.md              (70 items)
│   ├── 05-program-state-machine.md         (72 items)
│   ├── 06-program-economic-logic.md        (89 items)
│   ├── 07-program-opsec-governance.md      (85 items)
│   ├── 08-typescript-safety.md             (60 items)
│   ├── 09-backend-security.md             (103 items)
│   ├── 10-frontend-security.md             (76 items)
│   ├── 11-supply-chain.md                  (46 items)
│   ├── 12-secrets-opsec.md                 (53 items)
│   ├── 13-deployment-infrastructure.md     (79 items)
│   ├── 14-python-safety.md                 (82 items)
│   ├── 15-general-language-safety.md       (88 items)
│   ├── 16-formal-verification-testing.md   (71 items)
│   ├── 17-logging-monitoring-incident-response.md (63 items)
│   ├── 18-privacy-compliance-change-management.md (60 items)
│   ├── 19-ai-agent-security.md (31 items) — AI agents on Solana
│   └── 20-rust-offchain-services.md (17 items) — Off-chain Rust (geyser/indexers/keepers)
│
├── discovery/               ← File patterns and search commands
│   ├── file-map.md          ← Maps checklists → target file patterns
│   └── grep-commands.md     ← All grep/terminal commands by category
│
├── references/              ← Progressive-disclosure deep coverage (loaded on trigger)
│   ├── methodologies/       ← 12 protocol playbooks (amm-clmm, lending, perps, oracles,
│   │                          stablecoin, liquid-staking, governance, bridges,
│   │                          wallets-multisig-custody, token-2022, nft-marketplaces, launchpads)
│   ├── framework-idioms/    ← Anchor / Native / Pinocchio validation-order footguns
│   ├── vuln-classes/        ← zk-and-compression
│   ├── invariant-catalog.md ← Reusable harness-ready invariant menus per protocol class
│   ├── false-positives.md   ← Over-reporting triage rules
│   ├── audit-lifecycle/     ← methodology + firm-coverage (how firms actually work)
│   └── orchestration/       ← boundary-map (Trail of Bits) · pre-scan · poc-harness
│
├── commands/                ← 15 slash-commands (/auditor:<name>)
│   ├── audit · quick-scan · deep-review · diff-audit · spec-audit · economic-sim · audit-report
│   ├── audit-cycle · audit-assist · re-audit            ← lifecycle flows
│   ├── intake · threat-model · triage                   ← perimeter
│   └── poc · patch                                      ← executable PoC + fix patches
│
├── agents/                  ← 8 specialized subagents
│   ├── context-builder · threat-modeler · vuln-hunter · economic-analyst
│   └── peer-reviewer · audit-reporter · poc-engineer · patch-engineer
│
├── tools/auditor-tools/     ← Rust CLIs (cargo build --release)
│   ├── audit-scan           ← deterministic pre-scan → JSON risky-surface map (~$0)
│   └── audit-mem            ← SQLite cross-audit memory (dedup · regression · FP-suppression)
│
├── templates/               ← Output + deliverable templates
│   ├── report-template.md   ← Internal item-by-item verdict report
│   ├── audit-report.md      ← Client-facing findings report (no deploy guarantee)
│   ├── context-worksheet.md · instruction-worksheet.md · intake.md · threat-model.md
│   ├── poc/                 ← exploit-harness crate skeleton + shared-test-utils
│   └── patch/               ← patch + VERIFICATION templates
│
├── docs/                    ← Usage guides (start at docs/README.md)
├── scripts/                 ← report-to-pdf.sh + the no-attribution commit hook
├── AGENTS.md                ← Agent-orchestration overview
└── vendor/trailofbits/      ← Trail of Bits execution plugins (git submodule)
```

---

## Audit Flows

Beyond one-shot `/audit`, two flows run a full audit-company lifecycle end-to-end:

- **`/auditor:audit-cycle`** — a **fully automated** audit-agent team (scope → context reconstruction → tool-assisted pass → parallel manual review with leaf-level false-positive gating → independent peer reconciliation → synthesis) that produces a professional client report at `audit_<n>/REPORT.md`. Optional PDF (needs [pandoc](https://pandoc.org/)):
  ```bash
  scripts/report-to-pdf.sh audit_1/REPORT.md   # writes REPORT.pdf if pandoc is installed; MD is always the deliverable
  ```
- **`/auditor:audit-assist`** — an **AI-assisted, human-in-the-loop** flow: it pauses at checkpoints to surface findings and ask the questions only you can answer (business context, trust model, severity calls), iterating until the audit document converges.
- **`/auditor:re-audit`** — **fix-review**: diffs against a prior report (`FIXED` / `STILL-OPEN` / `REGRESSED`) and sweeps for un-patched siblings of each fixed bug.

Every intermediary step is also addressable on its own: `/auditor:intake` (persisted scoping), `/auditor:threat-model` (asset/actor/trust-boundary artifact), `/auditor:triage` (dedup + false-positive calibration), and `/auditor:poc` / `/auditor:patch` (executable exploit + verified fix). Full command reference: [docs/commands.md](docs/commands.md).

The client report follows professional firm convention — executive summary, commit-pinned scope, findings with PoC/reachability, a code-maturity assessment, disclaimers. Like real firms, it does **not** issue a "safe to deploy" guarantee. Method + firm coverage: [references/audit-lifecycle/](references/audit-lifecycle/).

---

## Output Format

The audit produces a structured markdown report with:

1. **Executive Summary** — risk score (1-10), deploy/no-deploy verdict, severity distribution
2. **Instruction Matrix** — every smart contract instruction mapped
3. **State Model** — account structs, PDA seeds, relationships
4. **Per-Item Verdicts** — every in-scope checklist item (up to 1,346) with `[PASS]`, `[FAIL-N]`, `[PARTIAL]`, or `[N/A]`
5. **Known Vectors Results** — each in-scope attack vector (up to 131) with explicit verdict and evidence
6. **Findings** — deduplicated, severity-sorted
7. **Attack Scenarios** — narrative exploitable paths
8. **Aggregate Score** — PASS/PARTIAL/FAIL percentages
9. **Recommendations** — prioritized fix list

For High/Critical findings, an optional `audit_<n>/poc/` (runnable exploits that assert the bug) and `audit_<n>/patches/` (minimal fixes proven to revert the exploit) accompany the report — see [docs/poc-and-patches.md](docs/poc-and-patches.md).

See [OUTPUT-RULES.md](OUTPUT-RULES.md) for the complete specification.

---

## How to Invoke

### VS Code / GitHub Copilot
```
@workspace Audit the entire repository using the auditor-skill
```

### Cursor / Windsurf
```
Read .claude/skills/auditor-skill/SKILL.md then audit this repository following the FULL-AUDIT.md execution plan
```

### Claude Code (CLI)
```
Read the auditor-skill files in .claude/skills/auditor-skill/ and perform a full security audit of this repository
```

### API (programmatic)
```python
# Send SKILL.md + OUTPUT-RULES.md + FULL-AUDIT.md as system prompt
# Send target files as user messages (chunked)
# Collect structured output
```

---

## Contributing

### Adding a New Attack Vector

1. Create `known-vectors/NNN-short-name.md` with the next available number
2. Use this template:

```markdown
---
id: NNN
title: "Your Attack Name"
severity: 7
category: crypto|backend|frontend|devops
---

### NNN — Your Attack Name
**Severity: 7** | **Real: Example Incident ($X, Year)**

Brief description of the attack.

#### Verification Procedure

**Step 1: Description**
\```
grep command or check to perform
\```
- ✅ PASS: What passing looks like
- ❌ FAIL: What failing looks like

**Step 2: ...**
(continue with 3-12 steps)

**Overall verdict:**
- ✅: Full mitigation criteria
- ⚠️: Partial mitigation criteria
- ❌: Vulnerability criteria
```

3. Add the entry to [known-vectors/INDEX.md](known-vectors/INDEX.md)
4. Submit a PR

### Adding Checklist Items

1. Open the relevant checklist in `checklists/`
2. Add new items following the existing format (ID prefix + sequential number)
3. Update the item count in [SKILL.md](SKILL.md)

### Updating Cost Estimates

If model pricing changes, update [COSTS.md](COSTS.md) with new rates.

---

## Benchmarking

This auditor was designed by comparing methodology from:

| Standard | Domain | What We Took |
|----------|--------|-------------|
| **CertiK** | Crypto audit | On-chain vulnerability taxonomy, formal verification approach |
| **EY / SOC 2** | Enterprise IT audit | Control objectives, evidence requirements |
| **OWASP Top 10:2025** | Web security | Attack categories, severity calibration |
| **NIST SP 800-53** | Government security | Control framework structure |
| **COBIT 2019** | IT governance | Process maturity model |
| **GDPR / MiCA / DORA** | EU regulation | Compliance checklist items |

---

## License

MIT — use it, fork it, improve it, sell services built on it. Attribution appreciated but not required.

---

## FAQ

**Q: Does this replace a professional audit?**
A: It covers more items than most paid audits (1,346 plus 131 known-vector checks vs typical 50-200), but an AI auditor cannot do everything a human can (social engineering assessment, business logic review requiring domain expertise, legal compliance opinions). Use this as a first pass, then hire humans for what it flags.

**Q: Which AI model should I use?**
A: See [COSTS.md](COSTS.md). For maximum depth, use Opus 4 or o3. For best value, use Sonnet 4 or GPT-4.1. For CI/CD integration (fast, cheap), use Haiku or o4-mini.

**Q: How long does an audit take?**
A: Depends on repo size and model. A 50K-line repo takes 60-90 minutes with Opus 4. See [COSTS.md](COSTS.md) for full estimates.

**Q: Can I use this in CI/CD?**
A: Yes — run the QUICK scope (known vectors grep scan) on every PR, and FULL scope on release branches.

**Q: Can I use this for non-Solana projects?**
A: Yes — checklists 08-18 are language-agnostic or cover Python/Go/Java/Ruby/PHP. Checklists 01-07 are Solana-specific.

---

## Acknowledgments

auditor-skill stands on the shoulders of two open-source security projects — credited in full in [ATTRIBUTION.md](ATTRIBUTION.md):

- **[Frank Castle](https://github.com/Frankcastleauditor) — [safe-solana-builder](https://github.com/Frankcastleauditor/safe-solana-builder)** (MIT): Solana security depth — reward/staking accounting, Token-2022 extension abuse, framework validation idioms, zero-copy footguns — adapted natively and re-authored audit-side.
- **[Trail of Bits](https://github.com/trailofbits) — [skills](https://github.com/trailofbits/skills)** (CC-BY-SA 4.0): tool-execution methodology (SAST, fuzzing, coverage, mutation, IR analysis), vendored as a git submodule at `vendor/trailofbits` and orchestrated for real execution; methodology patterns re-implemented natively are credited by reference.

All third-party methodology is used by *reference* — no third-party text is copied into this repository.
