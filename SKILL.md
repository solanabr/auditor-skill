---
name: AUDITOR
description: "**AUDIT SKILL** — Comprehensive on-chain Solana program auditor and full-stack security review for ANY programming language. USE FOR: auditing Solana/Anchor programs, reviewing smart contract security, checking for vulnerabilities (missing signers, unchecked accounts, arithmetic overflow, CPI attacks, PDA confusion, type cosplay, reinitialization, flash loan exploits, MEV, governance backdoors, timelock bypass), auditing TypeScript/Python/Go/Java/Ruby/PHP/any language, backend/frontend code review, supply chain safety, operational security (multisig, upgrade authority, deploy process), formal verification and testing quality, logging/monitoring/incident response, data privacy/GDPR/SOC2 compliance, change management, penetration testing methodology, AI/ML security, generating audit reports, running full repository audits. Severity 1-10 scale, 18 micro-checklist domains with 1182 individual verification items, plus 100 known attack vectors, chunked file-by-file execution, item-by-item verdicts. Benchmarked against CertiK (crypto) and EY/SOC2/COBIT (traditional) audit standards. DO NOT USE FOR: writing new features, general coding, non-security reviews."
---

# AUDITOR — Multi-Language Security Audit Skill

> **Version:** 4.3  
> **Items:** 1,182 across 18 checklists (+ 100 known vectors)  
> **Languages:** Rust, TypeScript, Python, Go, Java, Ruby, PHP, + any via general checklist  
> **Severity:** 1–10 numeric scale  
> **Benchmarked against:** CertiK (crypto audit), EY/SOC 2/COBIT (traditional IT audit), OWASP Top 10:2025  
> **Designed for:** Autonomous AI auditor agent or human-guided review

---

## BLOCKING REQUIREMENT — FULL AUDITOR CORPUS INTAKE

Before any audit begins, the agent MUST recursively read every markdown file in this folder.

Mandatory load set:

1. Root docs: `README.md`, `SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `QUESTIONS.md`, `COSTS.md`, `TOP-100-HACKS.md` (if present).
2. Discovery docs: all files under `discovery/`.
3. Templates: all files under `templates/`.
4. Checklists: all files under `checklists/`.
5. Known vectors: `known-vectors/INDEX.md` and every vector file `known-vectors/001-*.md` through `known-vectors/100-*.md`.

Hard rules:

- If any AUDITOR markdown file is unread, the audit is INVALID and must be reported as `[INCOMPLETE — missing auditor corpus file load]`.
- Output must include:
    - every checklist item verdict (all 18 checklists),
    - every known-vector verdict (all 100 vectors),
    - corpus coverage evidence table listing all AUDITOR files and load status.
- No "summary-only" audit is valid under this skill.

---

## Folder Structure

```
AUDITOR/
├── README.md                         ← Start here — setup, usage, contributing guide
├── SKILL.md                          ← YOU ARE HERE (orchestrator — AI agent reads this first)
├── OUTPUT-RULES.md                   ← MANDATORY output format, severity scale, chunked execution
├── FULL-AUDIT.md                     ← Master execution plan for complete repo audits
├── QUESTIONS.md                      ← Pre-audit questionnaire (user fills before running)
├── COSTS.md                          ← Estimated token/dollar costs by model and repo size
├── TOP-100-HACKS.md                  ← Compatibility pointer (canonical source is known-vectors/)
│
├── known-vectors/                    ← Individual attack vector files (open-source friendly)
│   ├── INDEX.md                           One-line index of all vectors
│   ├── 001-private-key-leak.md            Severity 10 — crypto
│   ├── 002-flash-loan-price-manipulation.md
│   ├── ...                                (100 individual vector files)
│   └── 100-insufficient-backup-disaster-recovery.md
│
├── checklists/                       ← 18 micro-checklists (the core verification items)
│   ├── 01-program-account-validation.md   (57 items)  — Solana/Anchor
│   ├── 02-program-access-control.md       (50 items)  — Solana/Anchor
│   ├── 03-program-arithmetic-safety.md    (61 items)  — Solana/Anchor
│   ├── 04-program-cpi-pda.md             (63 items)  — Solana/Anchor
│   ├── 05-program-state-machine.md        (56 items)  — Solana/Anchor
│   ├── 06-program-economic-logic.md       (62 items)  — Solana/Anchor
│   ├── 07-program-opsec-governance.md     (75 items)  — Operations
│   ├── 08-typescript-safety.md            (60 items)  — TypeScript
│   ├── 09-backend-security.md            (100 items)  — Express/Node
│   ├── 10-frontend-security.md            (76 items)  — React/Next.js
│   ├── 11-supply-chain.md                 (43 items)  — All languages
│   ├── 12-secrets-opsec.md                (52 items)  — All languages
│   ├── 13-deployment-infrastructure.md    (77 items)  — All languages
│   ├── 14-python-safety.md                (82 items)  — Python
│   ├── 15-general-language-safety.md      (88 items)  — Go/Java/Ruby/PHP/any
│   ├── 16-formal-verification-testing.md  (58 items)  — All languages (CertiK FV + OWASP A10)
│   ├── 17-logging-monitoring-incident-response.md (62 items) — All languages (Skynet + SOC 2 + OWASP A09)
│   └── 18-privacy-compliance-change-management.md (60 items) — All languages (SOC 2 + EY + GDPR + AI/ML)
│
├── discovery/                        ← File patterns and search commands
│   ├── file-map.md                        Maps checklists → target files/globs
│   └── grep-commands.md                   All grep/terminal commands by category
│
└── templates/                        ← Output templates
    ├── report-template.md                 Full audit report structure (9 sections)
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
All 1,182 checklist items and all 100 known vectors appear in the report with explicit verdicts. Nothing is silently skipped. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 4.

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
| **Always applied** | any repo | 11, 12, 13, 16, 17, 18 |

---

## Checklists Reference

| # | Checklist | Items | Domain | File |
|---|-----------|-------|--------|------|
| 01 | Account Validation | 57 | On-chain | [01-program-account-validation.md](checklists/01-program-account-validation.md) |
| 02 | Access Control | 50 | On-chain | [02-program-access-control.md](checklists/02-program-access-control.md) |
| 03 | Arithmetic Safety | 61 | On-chain | [03-program-arithmetic-safety.md](checklists/03-program-arithmetic-safety.md) |
| 04 | CPI & PDA Safety | 63 | On-chain | [04-program-cpi-pda.md](checklists/04-program-cpi-pda.md) |
| 05 | State Machine & Lifecycle | 56 | On-chain | [05-program-state-machine.md](checklists/05-program-state-machine.md) |
| 06 | Economic & Logic Attacks | 62 | On-chain | [06-program-economic-logic.md](checklists/06-program-economic-logic.md) |
| 07 | OpSec & Governance | 75 | Operations | [07-program-opsec-governance.md](checklists/07-program-opsec-governance.md) |
| 08 | TypeScript Safety | 60 | Off-chain | [08-typescript-safety.md](checklists/08-typescript-safety.md) |
| 09 | Backend Security | 100 | Off-chain | [09-backend-security.md](checklists/09-backend-security.md) |
| 10 | Frontend Security | 76 | Off-chain | [10-frontend-security.md](checklists/10-frontend-security.md) |
| 11 | Supply Chain & Dependencies | 43 | DevOps | [11-supply-chain.md](checklists/11-supply-chain.md) |
| 12 | Secrets & Key Management | 52 | DevOps | [12-secrets-opsec.md](checklists/12-secrets-opsec.md) |
| 13 | Deployment & Infrastructure | 77 | DevOps | [13-deployment-infrastructure.md](checklists/13-deployment-infrastructure.md) |
| 14 | Python Safety | 82 | Off-chain | [14-python-safety.md](checklists/14-python-safety.md) |
| 15 | General Language Safety | 88 | Universal | [15-general-language-safety.md](checklists/15-general-language-safety.md) |
| 16 | Formal Verification & Testing | 58 | Universal | [16-formal-verification-testing.md](checklists/16-formal-verification-testing.md) |
| 17 | Logging, Monitoring & IR | 62 | Universal | [17-logging-monitoring-incident-response.md](checklists/17-logging-monitoring-incident-response.md) |
| 18 | Privacy, Compliance & Change Mgmt | 60 | Universal | [18-privacy-compliance-change-management.md](checklists/18-privacy-compliance-change-management.md) |
| | **Total** | **1,182** | | |

---

## How to Use

### Full repository audit
```
Audit the entire repository using the AUDITOR skill with FULL scope
```

### Program-only audit
```
Audit the Solana program in programs/<your_program>/ using the AUDITOR skill with PROGRAM scope
```

### Specific checklist
```
Run AUDITOR checklist 03 (Arithmetic Safety) on programs/<your_program>/
```

### Backend audit
```
Run AUDITOR with BACKEND scope on apps/backend/
```

### Python project audit
```
Audit the Python code using AUDITOR checklist 14
```

### Any language
```
Run AUDITOR on this Go/Java/Ruby/PHP project — it will auto-detect and apply the right checklists
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

This entire `AUDITOR/` folder is self-contained and portable:

1. Copy the full `AUDITOR/` directory into the target repository
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
