---
name: auditor-skill
description: "**AUDIT SKILL** — Comprehensive on-chain Solana program auditor and full-stack security review for ANY programming language. USE FOR: auditing Solana/Anchor programs, reviewing smart contract security, checking for vulnerabilities (missing signers, unchecked accounts, arithmetic overflow, CPI attacks, PDA confusion, type cosplay, reinitialization, flash loan exploits, MEV, governance backdoors, timelock bypass), auditing TypeScript/Python/Go/Java/Ruby/PHP/any language, backend/frontend code review, supply chain safety, operational security (multisig, upgrade authority, deploy process), formal verification and testing quality, logging/monitoring/incident response, data privacy/GDPR/SOC2 compliance, change management, penetration testing methodology, AI/ML security, generating audit reports, running full repository audits. Severity 1-10 scale, 20 micro-checklist domains with 1346 individual verification items, plus 131 known attack vectors, chunked file-by-file execution, item-by-item verdicts. Benchmarked against CertiK (crypto) and EY/SOC2/COBIT (traditional) audit standards. DO NOT USE FOR: writing new features, general coding, non-security reviews."
---

# auditor-skill — Multi-Language Security Audit Skill

> **Version:** 7.0  
> **Items:** 1,346 across 20 checklists (+ 131 known vectors)  
> **Languages:** Rust, TypeScript, Python, Go, Java, Ruby, PHP, + any via general checklist  
> **Severity:** 1–10 numeric scale  
> **Benchmarked against:** CertiK (crypto audit), EY/SOC 2/COBIT (traditional IT audit), OWASP Top 10:2025  
> **Designed for:** Autonomous AI auditor agent or human-guided review

---

## SCOPE-GATED LOADING — Load What The Repo Needs

auditor-skill does not read its whole corpus up front. It discovers the repo, declares a scope, loads only what that scope requires, then guarantees a verdict for every in-scope item.

**Step 1 — Discover (cheap, always).** Enumerate file extensions and markers (`Anchor.toml`, `Cargo.toml`, `package.json`, `*.py`, `.github/`). No checklists or vectors loaded yet.

**Step 2 — Declare scope.** Map detected languages (+ any `--scope`) to the in-scope checklist set:

| Detected | Load checklists |
|----------|-----------------|
| `.rs` / `Anchor.toml` | 01–07 (+ 20 for `.rs` outside `programs/`) |
| `.ts` / `.tsx` | 08 (+ 09 if backend, + 10 if web) |
| `.py` | 14 |
| `.go` / `.java` / `.rb` / `.php` / other | 15 |
| AI / agent components (`.mcp.json`, agent SDKs) | 19 |
| **any repo** | 11, 12, 13, 16, 17, 18 |

Checklists outside this set are **never read** — a Rust-only repo never loads 14 or the TS/web vectors.

**Step 3 — Load on demand.** Load an in-scope checklist when its phase begins; load a known-vector only when its phase + language/domain trigger reaches it (`known-vectors/INDEX.md` groups vectors by `{phase, language, trigger}`).

**Completeness is output-side.** The audit is COMPLETE iff every in-scope item + phase-triggered vector has a verdict. Out-of-scope items render `[N/A — out of scope: <reason>]` from the gate. Every full report includes a **Scope Coverage** table. Full rule: see [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 0.

**Step 4 — Reference layer (progressive disclosure).** Beyond the checklists, load a `references/` file only when its trigger fires — deep coverage at zero cost when irrelevant:

| Reference | Load when (grep markers) |
|-----------|--------------------------|
| `references/framework-idioms/{anchor,native,pinocchio}.md` | that framework is detected |
| `references/framework-idioms/build-and-tooling.md` | build/CI/toolchain errors or PoC-harness setup |
| `references/methodologies/amm-clmm.md` | `tick` · `sqrt_price` · `liquidity_net` · `fee_growth` · `bin_array` |
| `references/methodologies/lending.md` | `obligation` · `reserve` · `liquidation_threshold` · `borrow_index` · `ltv` |
| `references/methodologies/perps.md` | `funding_rate` · `mark_price` · `open_interest` · `maintenance_margin` · `vamm` |
| `references/methodologies/oracles.md` | `pyth` · `switchboard` · `PriceUpdateV2` · `PullFeed` · `confidence` |
| `references/methodologies/stablecoin.md` | `collateral_ratio` · `psm` · `cdp` · `debt_ceiling` · `redeem` · `peg` |
| `references/methodologies/liquid-staking.md` | `stake_pool` · `validator_list` · `exchange_rate` · `staker` · `withdrawer` · `restak` |
| `references/methodologies/governance.md` | `spl-governance` · `realm` · `proposal` · `vote_record` · `voter_weight` · `vsr` |
| `references/methodologies/bridges.md` | `guardian` · `vaa` · `post_vaa` · `verify_signatures` · `emitter` · `sequence` · `lz_receive` · `ism` · `attestation` |
| `references/methodologies/wallets-multisig-custody.md` | `threshold` · `multisig` · `member` · `propose` · `approve` · `execute_transaction` · `vault` · `guardian` · `recovery` · `spending_limit` |
| `references/methodologies/token-2022.md` | `token_2022` · `TokenInterface` · `transfer_hook` · `TransferFee` · `PermanentDelegate` · `ConfidentialTransfer` · `get_extension` · `spl_token_2022` |
| `references/methodologies/nft-marketplaces.md` | `metadata` · `listing` · `escrow` · `royalty` · `merkle` · `MplCore` · `auth_rules` · `collection` |
| `references/methodologies/launchpads.md` | `bonding_curve` · `reserve` · `graduate` · `virtual_reserves` · `route` · `swap` · `curve` |
| `references/invariant-catalog.md` | building an FV/fuzz harness or reconstructing per-function invariants (Phase 0.5) — reusable invariant menus per protocol class |
| `references/vuln-classes/zk-and-compression.md` | `groth16` · `spl-account-compression` · `bubblegum` · `merkle` · `nullifier` · `ConfidentialTransfer` |
| `references/false-positives.md` | triaging any finding before reporting severity ≥ 6 |
| `references/orchestration/boundary-map.md` | delegating to vendored Trail of Bits tooling |
| `references/orchestration/pre-scan.md` | running the deterministic Rust pre-scanner (`audit-scan`) or the cross-audit memory store (`audit-mem`) |
| `references/orchestration/poc-harness.md` | building an executable PoC or fix patch (`/auditor:poc`, `/auditor:patch`) — harness-framework selection or recording a `[PoC-*]` / `[FIX-*]` evidence tier |
| `references/audit-lifecycle/methodology.md` | running `/audit-cycle` or `/audit-assist` (our method) |
| `references/audit-lifecycle/firm-coverage.md` | choosing methodology / understanding firm practice |

---

## Folder Structure

```
auditor-skill/
├── README.md                         ← Start here — setup, usage, contributing guide
├── SKILL.md                          ← YOU ARE HERE (orchestrator — AI agent reads this first)
├── OUTPUT-RULES.md                   ← MANDATORY output format, severity scale, chunked execution
├── FULL-AUDIT.md                     ← Master execution plan for complete repo audits
├── QUESTIONS.md                      ← Pre-audit questionnaire (user fills before running)
├── COSTS.md                          ← Estimated token/dollar costs by model and repo size
│
├── known-vectors/                    ← Individual attack vector files (open-source friendly)
│   ├── INDEX.md                           One-line index of all vectors
│   ├── 001-private-key-leak.md            Severity 10 — crypto
│   ├── 002-flash-loan-price-manipulation.md
│   ├── ...                                (131 individual vector files)
│   └── 100-insufficient-backup-disaster-recovery.md
│
├── checklists/                       ← 20 micro-checklists (the core verification items)
│   ├── 01-program-account-validation.md   (88 items)  — Solana/Anchor
│   ├── 02-program-access-control.md       (50 items)  — Solana/Anchor
│   ├── 03-program-arithmetic-safety.md    (63 items)  — Solana/Anchor
│   ├── 04-program-cpi-pda.md             (70 items)  — Solana/Anchor
│   ├── 05-program-state-machine.md        (72 items)  — Solana/Anchor
│   ├── 06-program-economic-logic.md       (89 items)  — Solana/Anchor
│   ├── 07-program-opsec-governance.md     (85 items)  — Operations
│   ├── 08-typescript-safety.md            (60 items)  — TypeScript
│   ├── 09-backend-security.md            (103 items)  — Express/Node
│   ├── 10-frontend-security.md            (76 items)  — React/Next.js
│   ├── 11-supply-chain.md                 (46 items)  — All languages
│   ├── 12-secrets-opsec.md                (53 items)  — All languages
│   ├── 13-deployment-infrastructure.md    (79 items)  — All languages
│   ├── 14-python-safety.md                (82 items)  — Python
│   ├── 15-general-language-safety.md      (88 items)  — Go/Java/Ruby/PHP/any
│   ├── 16-formal-verification-testing.md  (71 items)  — All languages (CertiK FV + OWASP A10)
│   ├── 17-logging-monitoring-incident-response.md (63 items) — All languages (Skynet + SOC 2 + OWASP A09)
│   ├── 18-privacy-compliance-change-management.md (60 items) — All languages (SOC 2 + EY + GDPR + AI/ML)
│   ├── 19-ai-agent-security.md            (31 items)  — AI agents on Solana (ToB agentic vectors ported)
│   └── 20-rust-offchain-services.md       (17 items)  — Off-chain Rust (geyser/indexers/keeper bots)
│
├── discovery/                        ← File patterns and search commands
│   ├── file-map.md                        Maps checklists → target files/globs
│   └── grep-commands.md                   All grep/terminal commands by category
│
└── templates/                        ← Output templates
    ├── report-template.md                 Full audit report structure (11 sections)
    └── instruction-worksheet.md           Per-instruction deep-review form
```

---

## Severity Scale (1–10)

| Score | Label | Action |
|-------|-------|--------|
| **10** | 🔴 CRITICAL | Permissionless fund drain — **block deploy** |
| **9** | 🔴 CRITICAL | Fund loss, minimal preconditions — **block deploy** |
| **8** | 🟠 HIGH | Partial drain, specific preconditions — **fix before release** |
| **7** | 🟠 HIGH | Significant damage, privilege escalation — **fix before release** |
| **6** | 🟡 MEDIUM | State corruption, DoS, limited economic damage — **fix within 2 weeks** |
| **5** | 🟡 MEDIUM | Logic bugs, moderate info leak — **fix within 2 weeks** |
| **4** | 🔵 LOW | Minor info leak, security-relevant code quality — **next sprint** |
| **3** | 🔵 LOW | Missing best practice, theoretical risk — **next sprint** |
| **2** | ⚪ INFO | Hardening suggestion — **backlog** |
| **1** | ⚪ INFO | Cosmetic, no security impact — **optional** |

Full severity decision guide: see [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 1.

---

## Core Principles

### 1. Walk The Code — Never One-Shot
Repositories can be 10 files or 10,000 files. The auditor reads files **one at a time**, never guesses, and saves checkpoints between chunks. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 3.

### 2. Every Item Gets a Verdict
All in-scope checklist items (up to 1,346) and all in-scope known vectors (up to 131) appear in the report with explicit verdicts. Nothing is silently skipped. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 4.

### 3. Executive Summary First
Every report starts with a plain-language summary: what was audited, what was found, whether it's safe to deploy. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 2.

### 4. Language Auto-Detection
The auditor scans file extensions and applies the correct checklists automatically. No language left behind. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 7.

### 5. Honesty Over Completeness
If context was lost, a file was too large, or a pattern is unfamiliar — say so. Never mark `[PASS]` without reading the code. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 10.

---

## Audit Modes

### Mode 1: FULL Repository Audit

**When to use:** Complete security review of the entire codebase.

**Execution:**
1. Read [OUTPUT-RULES.md](OUTPUT-RULES.md) — the output format is mandatory
2. Read [FULL-AUDIT.md](FULL-AUDIT.md) — follow it from top to bottom
3. Use [discovery/file-map.md](discovery/file-map.md) to locate target files
4. Use [discovery/grep-commands.md](discovery/grep-commands.md) for automated scanning
5. For on-chain instructions, fill [templates/instruction-worksheet.md](templates/instruction-worksheet.md) per instruction
6. Generate the report using [templates/report-template.md](templates/report-template.md)

### Mode 2: Targeted Checklist Audit

**When to use:** Review a specific domain or subset of files.

**Execution:**
1. Read [OUTPUT-RULES.md](OUTPUT-RULES.md)
2. Read the relevant checklist(s) from `checklists/`
3. Walk through target files one at a time
4. Record every item verdict, report findings inline

### Mode 3: Single Instruction / Function Review

**When to use:** Deep-dive into one handler, endpoint, or function.

**Execution:**
1. Read the source file completely
2. Fill out [templates/instruction-worksheet.md](templates/instruction-worksheet.md)
3. Cross-reference with related code that shares state

### Mode 4: Differential / PR-Scoped Audit

**When to use:** A PR, commit range, or branch — not the whole tree. Command: `/auditor:diff-audit`.

**Execution:**
1. Changed set: `git diff --name-only <base>..<head>` (default `main..HEAD`).
2. Phase 0.5 context reconstruction on changed functions + 1-hop callers/callees.
3. Risk-classify changed files (auth / crypto / value-transfer / validation-removal = HIGH); git-blame removed security code — a deletion in a "fix"/"CVE" commit is a CRITICAL regression.
4. Run only the checklist items + known-vectors matching the changed files' language/domain, through the Rule 5b gate.
5. Abbreviated report (`audit_<n>/PR-REPORT.md`) — changed-surface verdicts only. Reuses the methodology corpus; skips whole-repo discovery. *(Pattern credit: Trail of Bits `differential-review`.)*

### Mode 5: Spec-Compliance Audit

**When to use:** A spec / whitepaper / RFC is supplied and you need code-vs-spec conformance. Command: `/auditor:spec-audit`.

**Execution:**
1. Extract a requirement list (Spec-IR) from the spec.
2. Phase 0 setup + Phase 0.5; map each instruction / state field to the spec's stated behavior.
3. Compliance Matrix: each requirement → `[MET]` / `[VIOLATED-N]` / `[UNIMPLEMENTED]` / `[UNDOCUMENTED-BEHAVIOR]`, cited to code `L#`. Any `[VIOLATED-N≥6]` passes the Rule 5b gate; `[UNDOCUMENTED-BEHAVIOR]` (code does something the spec never authorizes) is itself a finding. *(Pattern credit: Trail of Bits `spec-to-code-compliance`.)*

---

## Audit Flows (full engagement lifecycle)

Two flows run the traditional audit-company lifecycle over the skill's **existing** mechanisms (scope-gating → Phase 0.5 context → manual review → Rule 5b verification → Phase 4.5 maturity → report). Method: [references/audit-lifecycle/methodology.md](references/audit-lifecycle/methodology.md); how real firms work: [references/audit-lifecycle/firm-coverage.md](references/audit-lifecycle/firm-coverage.md).

- **`/auditor:audit-cycle`** — *fully automated audit team.* Runs the whole lifecycle autonomously: domain-partitioned `vuln-hunter` + `economic-analyst` (each self-triaging via Rule 5b + `false-positives.md` at the leaf) → independent `peer-reviewer` reconciliation on top-severity findings → `audit-reporter` synthesis → a client-facing report ([templates/audit-report.md](templates/audit-report.md)) at `audit_<n>/REPORT.md` (+ optional PDF via `scripts/report-to-pdf.sh`, pandoc-gated — MD is always the deliverable).
- **`/auditor:audit-assist`** — *AI-assisted, human-in-the-loop.* Same lifecycle, pausing at checkpoints to surface confirmed findings + next-focus + the questions only a human can answer (business context, trust model, severity calls); iterates until the audit document converges.
- **`/auditor:re-audit`** — *fix-review.* Diffs against a prior report: per-finding `FIXED` / `STILL-OPEN` / `REGRESSED`, plus a sibling-patch-propagation sweep (grep the codebase for the same anti-pattern the fix closed).

Honestly scoped: this is audit-shaped automation / a rigorous first pass, not a substitute for a human firm audit. The client report follows firm convention — maturity narrative + trust-model caveats + disclaimer — and does **not** issue a "safe to deploy" guarantee. *(Precedents: Neodyme independent dual-review, Trail of Bits weekly progress reports + code-maturity, Sec3 shift-left, Zellic importance-ordering, Zenith delta review.)*

---

## Rationalizations to Reject

An auditor talks itself out of real findings with lines like these. Treat each as a RED FLAG that demands the Rule 5b gate — not a reason to skip:

- "It's only devnet / a test program." → Audit as if mainnet; devnet code ships.
- "The math can't overflow because values are always small." → Prove the bound (Rule 5b Math/State-Bounds) or report it.
- "`init_if_needed` is fine here." → It permits reinitialization; prove the guard or flag it.
- "Only the admin can call this." → Confirm the signer/authority check exists in code; "should be" is not "is".
- "The client validates it." → On-chain must not trust off-chain validation.
- "This `unwrap()` can't fail." → On user/RPC input it can — that is a DoS (checklist 20).
- "It's the same as a well-known program." → Verify line-by-line; forks drift.

*(Scaffolding pattern credit: Trail of Bits `skill-improver`.)*

## When NOT to Use

- Writing new features or general (non-security) code — this skill only audits.
- As the sole gate for a mainnet launch — it is a thorough first pass; pair it with a human audit for business-logic, economic-model, and legal-compliance review.
- As formal proof of correctness — it flags where proofs/harnesses are missing (and can orchestrate them via `vendor/trailofbits`), but does not itself constitute a machine-checked proof.

---

## Language → Checklist Mapping

| Language | File Extensions | Checklists |
|----------|----------------|------------|
| Rust (Solana/Anchor) | `.rs` | 01–07 |
| TypeScript | `.ts` | 08 |
| TypeScript (backend) | `.ts` (in backend/) | 08 + 09 |
| React/Next.js | `.tsx` | 08 + 10 |
| Python | `.py` | 14 |
| Go | `.go` | 15 (Go section) |
| Java/Kotlin | `.java`, `.kt` | 15 (Java section) |
| Ruby | `.rb` | 15 (Ruby section) |
| PHP | `.php` | 15 (PHP section) |
| Other | any | 15 (sections 15.1–15.8) |
| Rust (off-chain services) | `.rs` outside `programs/` | 20 |
| AI / agent components | `.mcp.json`, agent SDKs, `Keypair` in agent code | 19 |
| **Always applied** | any repo | 11, 12, 13, 16, 17, 18 |

---

## Checklists Reference

| # | Checklist | Items | Domain | File |
|---|-----------|-------|--------|------|
| 01 | Account Validation | 88 | On-chain | [01-program-account-validation.md](checklists/01-program-account-validation.md) |
| 02 | Access Control | 50 | On-chain | [02-program-access-control.md](checklists/02-program-access-control.md) |
| 03 | Arithmetic Safety | 63 | On-chain | [03-program-arithmetic-safety.md](checklists/03-program-arithmetic-safety.md) |
| 04 | CPI & PDA Safety | 70 | On-chain | [04-program-cpi-pda.md](checklists/04-program-cpi-pda.md) |
| 05 | State Machine & Lifecycle | 72 | On-chain | [05-program-state-machine.md](checklists/05-program-state-machine.md) |
| 06 | Economic & Logic Attacks | 89 | On-chain | [06-program-economic-logic.md](checklists/06-program-economic-logic.md) |
| 07 | OpSec & Governance | 85 | Operations | [07-program-opsec-governance.md](checklists/07-program-opsec-governance.md) |
| 08 | TypeScript Safety | 60 | Off-chain | [08-typescript-safety.md](checklists/08-typescript-safety.md) |
| 09 | Backend Security | 103 | Off-chain | [09-backend-security.md](checklists/09-backend-security.md) |
| 10 | Frontend Security | 76 | Off-chain | [10-frontend-security.md](checklists/10-frontend-security.md) |
| 11 | Supply Chain & Dependencies | 46 | DevOps | [11-supply-chain.md](checklists/11-supply-chain.md) |
| 12 | Secrets & Key Management | 53 | DevOps | [12-secrets-opsec.md](checklists/12-secrets-opsec.md) |
| 13 | Deployment & Infrastructure | 79 | DevOps | [13-deployment-infrastructure.md](checklists/13-deployment-infrastructure.md) |
| 14 | Python Safety | 82 | Off-chain | [14-python-safety.md](checklists/14-python-safety.md) |
| 15 | General Language Safety | 88 | Universal | [15-general-language-safety.md](checklists/15-general-language-safety.md) |
| 16 | Formal Verification & Testing | 71 | Universal | [16-formal-verification-testing.md](checklists/16-formal-verification-testing.md) |
| 17 | Logging, Monitoring & IR | 63 | Universal | [17-logging-monitoring-incident-response.md](checklists/17-logging-monitoring-incident-response.md) |
| 18 | Privacy, Compliance & Change Mgmt | 60 | Universal | [18-privacy-compliance-change-management.md](checklists/18-privacy-compliance-change-management.md) |
| 19 | AI Agent Security (Solana × AI) | 31 | AI / Agent | [19-ai-agent-security.md](checklists/19-ai-agent-security.md) |
| 20 | Rust Off-Chain Services | 17 | Off-chain | [20-rust-offchain-services.md](checklists/20-rust-offchain-services.md) |
| | **Total** | **1,346** | | |

---

## How to Use

### Full repository audit
```
Audit the entire repository using the auditor-skill with FULL scope
```

### Program-only audit
```
Audit the Solana program in programs/<your_program>/ using the auditor-skill with PROGRAM scope
```

### Specific checklist
```
Run auditor-skill checklist 03 (Arithmetic Safety) on programs/<your_program>/
```

### Backend audit
```
Run auditor-skill with BACKEND scope on apps/backend/
```

### Python project audit
```
Audit the Python code using auditor-skill checklist 14
```

### Any language
```
Run auditor-skill on this Go/Java/Ruby/PHP project — it will auto-detect and apply the right checklists
```

---

## Recording Format

For every checklist item, record one of:
- `[PASS]` — verified secure, must cite file that proves it
- `[FAIL-N]` — vulnerability found, N = severity 1-10, must include file:line + impact + fix
- `[PARTIAL]` — partially implemented, must describe what's missing
- `[N/A]` — not applicable, must include reason why

Full format rules: see [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 4.

---

## Porting to Another Repository

This entire `auditor-skill/` folder is self-contained and portable:

1. Copy the full `auditor-skill/` directory into the target repository
2. Update `discovery/file-map.md` with the target's folder structure
3. Checklists 01-07: any Solana/Anchor program
4. Checklists 08-10: any TypeScript/Express/Next.js project
5. Checklist 14: any Python project
6. Checklist 15: Go, Java, Ruby, PHP, or any other language
7. Checklists 11-13: universal — any project, any language
8. OUTPUT-RULES.md: universal — applies to all audits regardless of tech stack

---

## References

- [Sealevel Attacks (coral-xyz)](https://github.com/coral-xyz/sealevel-attacks) — canonical Solana exploit examples
- [Neodyme: Common Pitfalls](https://neodyme.io/en/blog/solana_common_pitfalls/) — top 5 Solana contract vulnerabilities
- [Solana Security Course](https://solana.com/developers/courses/program-security) — official security curriculum
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — web application security baseline
- QEDGen SPEC Format — formal verification methodology (create your own SPEC.md following this structure)
- [SOC 2 Trust Service Criteria](https://en.wikipedia.org/wiki/SOC_2) — AICPA 5-category compliance framework
- [COBIT 2019](https://www.isaca.org/resources/cobit) — IT governance and control framework (ISACA)
- [CertiK Audit Methodology](https://www.certik.com/products/security-audit) — manual review + formal verification + Skynet monitoring
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/) — A01-A10 application security risks
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — security and privacy controls catalog
