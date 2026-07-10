<!--
================================================================================
CLIENT-FACING AUDIT REPORT TEMPLATE
================================================================================
This is the PROFESSIONAL, findings-focused deliverable handed to the client —
structured the way public Solana security reports are (Trail of Bits, OtterSec,
Neodyme, Zellic, Halborn). It is DISTINCT from templates/report-template.md,
which is the INTERNAL item-by-item verdict report (1328-item checklist grid +
1-10 risk score). Use THIS file when producing the report the client reads.

HOW TO USE:
  1. Copy this file to audit_<n>/REPORT.md (see OUTPUT-RULES.md Rule 9).
  2. Fill every {placeholder}. Delete guidance comments (<!-- ... -->) as you go.
  3. Keep the internal per-item verdicts in the internal report; surface only
     confirmed findings here (each must have survived the Rule 5b validation gate).
  4. Order findings by severity descending (Critical -> Informational). Zellic's
     convention of ordering by *importance/impact* rather than raw severity is an
     acceptable alternative — pick one and be consistent.

CONVENTION — NO "SAFE TO DEPLOY" STAMP:
  Real firms do NOT certify code as "safe" or "guaranteed secure." This template
  MUST NOT contain a deploy blessing. Communicate readiness through: (a) the
  code-maturity narrative, (b) finding resolution status, and (c) explicit
  trust-model caveats. An audit is a point-in-time, scoped, non-exhaustive review
  — never a guarantee. This framing is enforced in the Disclaimer appendix.

IP BOUNDARY: use only public-derivable firm conventions. Never reference or quote
the proprietary knowledge base.
================================================================================
-->

# {Protocol / Client Name} — Security Audit Report

<!-- COVER / METADATA -------------------------------------------------------- -->

|                     |                                                        |
| ------------------- | ------------------------------------------------------ |
| **Auditor**         | auditor-skill v6.0                                     |
| **Client**          | {client / organization}                                |
| **Protocol**        | {protocol / product name}                              |
| **Report Title**    | {e.g. "Vault Program Security Assessment"}             |
| **Report Version**  | {e.g. 1.0 — draft / 1.1 — final / 2.0 — post-fix}     |
| **Revision Date**   | {YYYY-MM-DD}                                            |
| **Classification**  | {Confidential — Client Only / Public / Draft}          |

<!--
Revision guidance: bump the version on each material re-issue. Typical lifecycle:
  1.0 Draft (initial findings) -> 1.1 Final (after client review) ->
  2.0 Fix-Review (after remediation, statuses updated, fix commits recorded).
Keep a short revision log if the report goes through several rounds:

  | Version | Date       | Notes                                    |
  | ------- | ---------- | ---------------------------------------- |
  | 1.0     | {date}     | Initial draft delivered                  |
  | 1.1     | {date}     | Client comments incorporated             |
  | 2.0     | {date}     | Fix review; statuses + fix commits added |
-->

---

## 1. Executive Summary

<!--
2-4 sentences: who was engaged, what was reviewed (protocol + scope in one line),
the engagement window, and the headline outcome (counts of Critical/High, overall
maturity). Plain language a non-engineer stakeholder can read. NO deploy blessing.
-->

{auditor-skill was engaged by {client} to perform a security assessment of the
{protocol} {program/codebase}. The review covered {N} program(s) / {LoC} lines over
{duration}. The assessment identified {X} findings: {n} Critical, {n} High, {n}
Medium, {n} Low, and {n} Informational. {One sentence on the dominant theme, e.g.
"The core accounting logic is sound; findings cluster around access-control
hardening and input validation."}}

### 1.1 Findings Summary by Severity

| Severity            | Count | Resolved | Acknowledged | Open |
| ------------------- | :---: | :------: | :----------: | :--: |
| 🔴 Critical         | {n}   | {n}      | {n}          | {n}  |
| 🟠 High             | {n}   | {n}      | {n}          | {n}  |
| 🟡 Medium           | {n}   | {n}      | {n}          | {n}  |
| 🔵 Low              | {n}   | {n}      | {n}          | {n}  |
| ⚪ Informational    | {n}   | {n}      | {n}          | {n}  |
| **Total**           | **{N}** | **{n}** | **{n}**     | **{n}** |

### 1.2 Security Posture & Codebase Maturity

<!--
This is NOT a "safe to deploy" verdict. Mirror how real firms convey readiness:
  - Codebase maturity: overall engineering quality (test coverage, arithmetic
    discipline, account validation rigor, error handling) — reference the Code
    Maturity Assessment in §8 for the scored breakdown.
  - Resolution status: how many of the material findings are fixed vs. open.
  - Trust-model caveats: what the security of the system CURRENTLY depends on
    (e.g. "an honest, non-compromised upgrade authority", "an accurate oracle",
    "a multisig that is actually multi-party"). State these plainly — they are
    the assumptions under which the remaining findings are acceptable.

Write 2-4 short paragraphs. Convey readiness through maturity + resolution +
caveats, never through a blessing. Example framing:

  "The {protocol} codebase demonstrates {strong/moderate/early-stage} engineering
   maturity (see §8). Arithmetic is {consistently checked / mostly checked with
   gaps at ...}; account validation is {rigorous / has the gaps noted in AUD-xx}.
   As of this revision, {all Critical and High findings are resolved / N High
   findings remain open}. The security of the deployed system depends on the
   following trust assumptions holding: {list}. Should any of these assumptions
   change (upgrade authority handoff, oracle swap, parameter change), a re-review
   of the affected surface is recommended."
-->

{maturity + resolution + trust-model narrative}

### 1.3 Key Takeaways

<!-- 3-6 bullets. The most important things the client should walk away knowing. -->

- {e.g. "Critical AUD-01 (permissionless vault drain) has been fixed in {commit}."}
- {e.g. "The program's upgrade authority is a single EOA — recommend a multisig + timelock before mainnet."}
- {e.g. "Test coverage is strong for happy paths but thin on adversarial cases; property tests recommended."}
- {...}

---

## 2. Scope

### 2.1 Repository & Commits

|                            |                                                   |
| -------------------------- | ------------------------------------------------- |
| **Repository**             | {https://github.com/org/repo}                     |
| **Branch**                 | {branch reviewed}                                 |
| **Review Start Commit**    | `{full 40-char SHA}` <!-- state of code at kickoff --> |
| **Fix-Review End Commit**  | `{full 40-char SHA}` <!-- state after remediation; "N/A" if no fix round --> |
| **Lines of Code (in scope)** | {LoC} <!-- exclude tests/generated if you scope them out; note if so --> |
| **Engagement Duration**    | {e.g. 2026-06-15 → 2026-06-26 (2 weeks)}          |
| **Effort**                 | {e.g. ~X person-days}                             |

### 2.2 In Scope

<!-- Explicit list of programs / files / directories that WERE reviewed. -->

| Component | Path | Language | Notes |
| --------- | ---- | -------- | ----- |
| {Program name} | `programs/{name}/src/` | Rust (Anchor {version}) | {on-chain program} |
| {Off-chain service} | `apps/{name}/src/` | TypeScript | {if in scope} |
| {...} | {...} | {...} | {...} |

### 2.3 Out of Scope

<!--
Be explicit. This protects both parties. Typical exclusions: third-party
dependencies, the underlying Solana runtime/SVM, off-chain infra not provided,
front-end UI, deployment keys/opsec, economic/game-theoretic soundness of the
tokenomics beyond code correctness, and any code outside the listed commits.
-->

- {e.g. Third-party programs invoked via CPI (SPL Token, Jupiter) — assumed correct.}
- {e.g. Off-chain keeper / crank infrastructure not included in the repository.}
- {e.g. Front-end / client application (unless separately listed as in scope).}
- {e.g. Deployment process, key custody, and operational security (see Disclaimer).}
- {e.g. Economic model / tokenomics design beyond on-chain code correctness.}
- {Any code outside the commits in §2.1.}

---

## 3. Methodology

<!--
Describe HOW the review was conducted. Real reports state the mix of manual and
automated work, the tools, and the phases. auditor-skill runs a chunked,
file-by-file manual review (never one-shot) augmented by tooling.
-->

The assessment combined **manual, line-by-line human-in-the-loop review** with
**automated tooling**. Manual review is the primary method; tooling is used to
widen coverage and catch mechanical issues.

### 3.1 Approach

- **Manual review** — every in-scope instruction/handler read in full, with
  context reconstruction before any verdict (purpose, invariants, assumptions,
  external-interaction risks per function). Findings are gated for reachability
  and impact before being reported (over-reporting is actively suppressed).
- **Automated analysis** — {list what was actually run, e.g.:}
  - Static analysis / SAST: {e.g. `cargo clippy`, `semgrep`, custom lints}
  - Dependency / supply-chain: {e.g. `cargo audit`, `npm audit`}
  - {Fuzzing / property tests: `cargo-fuzz`, `proptest`, `trident` — if used}
  - {Formal verification: {tool} — if used, else state "not applied in this engagement"}

### 3.2 Phases Executed

<!-- List the phases actually run. Delete rows that don't apply. -->

| Phase | Focus |
| ----- | ----- |
| Scope declaration & discovery | Enumerate languages, programs, entry points |
| Context reconstruction | Per-function purpose, invariants, assumptions |
| On-chain program review | Account validation, access control, arithmetic, CPI/PDA, state machine, economic logic |
| Off-chain review | {TypeScript / backend / frontend — if in scope} |
| DevOps & supply chain | Dependencies, secrets, deployment config |
| Verification & monitoring | Test/fuzz quality, logging, incident response |
| Known-vector sweep | Curated Solana attack-vector checklist |
| Code maturity assessment | 9-category engineering-quality scorecard |

### 3.3 Human-in-the-Loop vs. Automated

<!--
One short paragraph. State clearly that a human/agent reasoned about each finding
(automated tools alone do not close a finding). Reachability and exploitability
claims are human-verified against the source.
-->

{All reported findings were manually verified against the source; automated tool
output was triaged and confirmed by review before inclusion. Findings that could
not be shown reachable and impactful were downgraded or excluded rather than
reported speculatively.}

---

## 4. System Overview

<!--
Give the reader the mental model needed to understand the findings. Derived from
the code, not marketing docs.
-->

### 4.1 Protocol Description

{2-5 sentences describing what the protocol does and its core mechanism.}

### 4.2 Account / PDA Model

<!-- Key accounts, their PDAs (seeds), and what they store. -->

| Account | PDA Seeds | Purpose | Key Fields |
| ------- | --------- | ------- | ---------- |
| {Vault} | `["vault", authority]` | {holds funds} | {authority, bump, balance} |
| {...} | {...} | {...} | {...} |

### 4.3 Trust Model & Actors

<!--
Who are the actors, what privileges do they hold, and what is the system trusting
each one NOT to do. This section frames the severity of privilege-gated findings.
-->

| Actor | Privileges | Trust Assumption |
| ----- | ---------- | ---------------- |
| {Admin / upgrade authority} | {upgrade program, set params} | {assumed honest & key-secure} |
| {Manager} | {...} | {...} |
| {User / depositor} | {deposit, withdraw own funds} | {untrusted — permissionless} |
| {Oracle / external program} | {supplies price} | {assumed accurate & live} |

### 4.4 Key Invariants

<!--
The properties the system must always preserve. Findings often map to a broken
invariant. State them explicitly.
-->

- **INV-1:** {e.g. `total_shares == shares_mint.supply` at all times.}
- **INV-2:** {e.g. Sum of all position balances equals vault token balance.}
- **INV-3:** {e.g. Only the recorded authority can move funds out of a vault.}
- {...}

---

## 5. Severity Classification

<!--
This is the KEY the client uses to read the findings. Five tiers. Keep the
definitions exactly as below (public firm convention). Note the mapping to the
internal 1-10 scale so the two reports reconcile.
-->

Findings are rated on a five-tier severity scale based on **impact** and the
**preconditions** an attacker must satisfy to realize that impact.

| Severity            | Definition |
| ------------------- | ---------- |
| 🔴 **Critical**     | Direct, permissionless loss of funds or complete protocol compromise — exploitable by any caller with no special privilege and minimal preconditions. Must be fixed before deployment. |
| 🟠 **High**         | Loss of funds or equivalent damage that requires attacker-achievable preconditions (a specific but reachable state, a modest capital outlay, or a race). Must be fixed before release. |
| 🟡 **Medium**       | Conditional or amplified impact — state corruption, economic manipulation of limited scope, or denial-of-service on a critical path. Should be fixed. |
| 🔵 **Low**          | Best-practice deviation or defense-in-depth gap with no realistic path to fund loss under the current design. Recommended to address. |
| ⚪ **Informational** | Code quality, documentation, gas/CU, or hardening suggestions with no direct security impact. Optional. |

<!--
INTERNAL MAPPING (keep for reconciliation with templates/report-template.md's 1-10
scale — this is how the numeric internal score collapses onto the client tiers):
    10, 9  -> Critical
     8, 7  -> High
     6, 5  -> Medium
     4, 3  -> Low
     2, 1  -> Informational
Severity of a privilege-gated issue is capped by the privilege required (a bug
only a trusted admin can trigger is not Critical merely because its impact is
large — see the trust model in §4.3).
-->

> The auditor's internal 1–10 numeric severity maps onto these five tiers as
> **10–9 = Critical, 8–7 = High, 6–5 = Medium, 4–3 = Low, 2–1 = Informational**.

---

## 6. Findings

<!--
The core of the report. One block per finding, ordered by severity descending.
Only CONFIRMED findings appear here (each survived the reachability + impact
validation gate). Every finding needs a reproducible root-cause description and
either a concrete PoC or a rigorous reachability argument.

Status values: Fixed | Acknowledged | Risk-Accepted | Open
  - Fixed         — client remediated; record the fix commit.
  - Acknowledged  — client agrees it's valid; fix planned/tracked but not yet in.
  - Risk-Accepted — client accepts the risk (document their stated rationale).
  - Open          — not yet triaged by client (typical in a draft).
-->

### 6.1 Findings Summary Table

| ID     | Title | Severity | Status |
| ------ | ----- | -------- | ------ |
| AUD-01 | {title} | 🔴 Critical | {Fixed} |
| AUD-02 | {title} | 🟠 High     | {Acknowledged} |
| AUD-03 | {title} | 🟡 Medium   | {Open} |
| {...}  | {...}   | {...}       | {...} |

---

### 6.2 Detailed Findings

<!-- ==================== WORKED EXAMPLE (delete before delivery) ============ -->
<!--
The block below is a filled-in EXAMPLE showing the expected shape and rigor.
Delete it in the final report and replace with the real findings.
-->

#### AUD-01 — Missing owner check allows draining any vault

| Field         | Value                                                       |
| ------------- | ----------------------------------------------------------- |
| **Severity**  | 🔴 Critical (internal: 10)                                  |
| **Status**    | Fixed                                                       |
| **Location**  | `programs/vault/src/instructions/withdraw.rs:42`           |
| **Category**  | Access Control / Account Validation                         |

**Description**
The `withdraw` instruction reads the destination token account from
`ctx.accounts.vault_token_account` but never constrains its `authority` to the
signing user, nor verifies the `vault` PDA owns it. The account is typed
`UncheckedAccount` with a `/// CHECK:` comment that does not perform a real check.
As a result the `vault` seeds are derived from a caller-supplied `authority`
argument rather than the signer, so any caller can pass another user's vault.

**Impact**
Any permissionless caller can construct a transaction that withdraws the full
balance of an arbitrary victim vault to an attacker-controlled token account,
resulting in complete loss of all deposited funds across every vault.

**Proof of Concept**
<!-- Concrete, minimal reproduction. For Solana, a failing test / tx sketch is ideal. -->
```rust
// Attacker passes victim_authority as the `authority` arg; signs as themselves.
// Because the vault PDA is derived from the arg (not the signer) and no owner
// check ties vault_token_account to the vault, the transfer succeeds.
let (victim_vault, _) = Pubkey::find_program_address(
    &[b"vault", victim_authority.as_ref()], &program_id);
// withdraw(ctx, amount = victim_vault.balance) -> funds land in attacker ATA
```

**Recommendation**
Derive the `vault` PDA from the **signer** (`authority.key()`), add
`has_one = authority`, and constrain the token account:
```rust
#[account(mut, seeds = [b"vault", authority.key().as_ref()], bump = vault.bump,
          has_one = authority)]
pub vault: Account<'info, Vault>,
#[account(mut, token::authority = vault, token::mint = mint)]
pub vault_token_account: InterfaceAccount<'info, TokenAccount>,
pub authority: Signer<'info>,
```

**Fix Commit:** `{full SHA of the remediation commit}`

<!-- ==================== END WORKED EXAMPLE ================================= -->

---

<!-- ==================== FINDING BLOCK PATTERN (copy per finding) =========== -->

#### AUD-{NN} — {Finding Title}

| Field         | Value                                                       |
| ------------- | ----------------------------------------------------------- |
| **Severity**  | {🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low / ⚪ Informational} (internal: {1-10}) |
| **Status**    | {Fixed / Acknowledged / Risk-Accepted / Open}               |
| **Location**  | `{file.rs:line}` {(+ additional locations if the same root cause recurs)} |
| **Category**  | {e.g. Arithmetic / Access Control / CPI / State Machine / DoS} |

**Description**
<!-- Root cause, specific to the code found. Explain the mechanism, not just the symptom. -->
{...}

**Impact**
<!-- What an attacker achieves; worst case; quantify where possible. -->
{...}

**Proof of Concept**
<!--
Provide ONE of:
  (a) A concrete PoC — minimal code/test/tx steps that demonstrate the issue; OR
  (b) A reachability argument (required when a runnable PoC is impractical):
      - Entry point + required signer/authority
      - Preconditions to reach the vulnerable line (each cited file:line)
      - Why existing guards do NOT block it
      - The boundary that breaks (overflow point / div-by-zero input / bad state)
      - Concrete worked case showing the break
  A finding without either a PoC or a rigorous reachability argument should not
  be reported at High+ — downgrade or exclude it.
-->
```
{PoC code or reachability argument}
```

**Recommendation**
<!-- Specific, actionable fix — concrete code/constraint, not "fix this". -->
```
{recommended fix}
```

**Fix Commit:** {full SHA if Fixed, else "—"}

<!-- ==================== END FINDING BLOCK PATTERN ========================== -->

---

## 7. Findings Summary Table

<!-- Full grid of every finding for at-a-glance scanning. Mirrors §6.1; keep both. -->

| ID     | Title | Severity | Status | Location |
| ------ | ----- | -------- | ------ | -------- |
| AUD-01 | {title} | 🔴 Critical | {Fixed} | `{file:line}` |
| AUD-02 | {title} | 🟠 High     | {Acknowledged} | `{file:line}` |
| {...}  | {...}   | {...}       | {...}  | {...} |

---

## 8. Code Maturity Assessment

<!--
Engineering-quality scorecard, orthogonal to finding severity. 9 categories,
each scored 0-4 (0 absent · 1 ad-hoc · 2 partial · 3 good · 4 strong),
weakest-link. This drives the maturity narrative in §1.2. Cite evidence.
-->

Each category is rated **0–4**: 0 = absent · 1 = ad-hoc · 2 = partial ·
3 = good · 4 = strong (weakest-link scoring).

| # | Category | Score (0–4) | Evidence (file:line / artifact) | Gap to Next Level |
| - | -------- | :---------: | ------------------------------- | ----------------- |
| 1 | Access Controls | {0-4} | {...} | {...} |
| 2 | Arithmetic | {0-4} | {...} | {...} |
| 3 | Account & Type Safety | {0-4} | {...} | {...} |
| 4 | Input Validation | {0-4} | {...} | {...} |
| 5 | Testing | {0-4} | {...} | {...} |
| 6 | Fuzzing & Property Tests | {0-4} | {...} | {...} |
| 7 | Error Handling & DoS Resilience | {0-4} | {...} | {...} |
| 8 | Upgradeability & Governance | {0-4} | {...} | {...} |
| 9 | Monitoring & Incident Response | {0-4} | {...} | {...} |
| | **Overall Maturity** | **{X.X} / 4.0** | | |

<!-- Categories scoring <= 1 warrant priority attention regardless of whether a
     specific finding was written against them. -->

---

## 9. Appendices

### 9.1 Severity Rating Definitions

<!-- Reproduce the §5 tier definitions here as a standalone reference. -->

- **🔴 Critical** — Direct, permissionless fund loss / total compromise; minimal preconditions.
- **🟠 High** — Fund loss under attacker-achievable preconditions.
- **🟡 Medium** — Amplified/conditional impact, or DoS on a critical path.
- **🔵 Low** — Best-practice / defense-in-depth gap; no realistic fund loss.
- **⚪ Informational** — Quality, documentation, or hardening; no direct security impact.

### 9.2 Tools & Versions

<!-- The exact toolchain used, for reproducibility. -->

```
auditor-skill:  v6.0
solana-cli:     {version}
anchor-cli:     {version}
rustc / cargo:  {version}
node / npm:     {version}
cargo-audit:    {version or "n/a"}
{other SAST / fuzz / FV tools}: {version or "n/a"}
```

### 9.3 Disclaimer

<!--
Standard professional disclaimer. Point-in-time, scoped, non-exhaustive, code-only.
The "AWS shared-responsibility" framing: the auditor assesses the code; operational
security (key custody, deployment, monitoring) is the deployer's responsibility.
NO guarantee. Recommend re-audit after material change. Do NOT add any language
that could read as a "safe to deploy" certification.
-->

This report reflects a **point-in-time** security assessment of the code at the
commit(s) identified in §2.1. It is **scoped and non-exhaustive**: only the
components listed as in scope were reviewed, and the absence of findings in any
area is not a proof that no issues exist there. Security assessment is a
best-effort activity; **no audit can guarantee** that a codebase is free of
vulnerabilities, and this report does not constitute such a guarantee, nor any
warranty, nor financial, investment, or legal advice.

The assessment evaluates **the source code only**. Under a shared-responsibility
model, matters outside the code remain the responsibility of the deploying party,
including but not limited to: private-key custody and operational security, the
integrity of the deployment and upgrade process, the configuration of upgrade
authorities / multisigs / timelocks, run-time monitoring and incident response,
and the behavior of third-party programs and off-chain infrastructure that this
code depends on.

Any material change to the code, dependencies, deployment configuration, trust
model, or economic parameters after the reviewed commit **invalidates the
conclusions herein for the affected surface**; a re-review is recommended before
such changes reach production. The findings and their statuses describe the state
of the code as of the revision date and are provided **as-is**.
