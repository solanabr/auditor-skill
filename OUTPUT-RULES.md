# Output Rules — auditor-skill

> This document defines the **mandatory output format** for all audit reports.  
> Every audit — full, targeted, or single-instruction — MUST follow these rules.  
> No exceptions.

---

## Rule 0: Scope Declaration & Scope-Gated Corpus Load

auditor-skill does **not** read its whole corpus up front. It discovers the repo, declares a scope, loads only what that scope needs, and guarantees a verdict for every in-scope item.

1. **Discover** (cheap, always): enumerate file extensions and markers (`Anchor.toml`, `Cargo.toml`, `package.json`, `*.py`, `.github/`). No checklists or vectors loaded yet.
2. **Declare scope**: from detected languages + any `--scope` flag, compute the IN-SCOPE checklist set (see [SKILL.md](SKILL.md) → Scope-Gated Loading). Load this file (`OUTPUT-RULES.md`) once — it is always in scope.
3. **Load on demand**: load an in-scope checklist when its phase begins; load a known-vector only when its phase + language/domain trigger reaches it. Out-of-scope checklists and vectors are **never read**.

Completeness is measured **output-side**, not input-side:

- The audit is COMPLETE iff every IN-SCOPE checklist item and every phase-triggered vector has an explicit verdict.
- If any in-scope item lacks a verdict, report `[INCOMPLETE — in-scope item without verdict]` and finish it before concluding.
- Out-of-scope items render as `[N/A — out of scope: <reason>]`, generated from the scope gate (not from reading the file).

Every full report MUST include a **Scope Coverage** table: for each of the checklists and each vector group, `IN-SCOPE` (with items evaluated / total) or `OUT-OF-SCOPE (reason)`.

---

## Rule 1: Severity Scale (1–10)

All findings use a **numeric severity from 1 to 10**. The old letter scale (C/H/M/L/I) is replaced.

| Score | Label | Color | Meaning | Action Required |
|-------|-------|-------|---------|-----------------|
| **10** | 🔴 CRITICAL | Red | Permissionless drain, total fund loss, instant exploit | **Block deploy. Fix NOW.** |
| **9** | 🔴 CRITICAL | Red | Fund loss with minimal preconditions, privilege to admin | **Block deploy. Fix NOW.** |
| **8** | 🟠 HIGH | Orange | Fund loss with specific preconditions, partial drain | **Fix before any release.** |
| **7** | 🟠 HIGH | Orange | Significant economic damage, privilege escalation, data breach | **Fix before any release.** |
| **6** | 🟡 MEDIUM | Yellow | State corruption, griefing, DoS, economic manipulation (limited) | **Fix within 2 weeks.** |
| **5** | 🟡 MEDIUM | Yellow | Logic bugs, inconsistent state, moderate information leak | **Fix within 2 weeks.** |
| **4** | 🔵 LOW | Blue | Minor information leak, code quality issue with security implications | **Next sprint.** |
| **3** | 🔵 LOW | Blue | Missing best practice with theoretical risk | **Next sprint.** |
| **2** | ⚪ INFO | Gray | Style, optimization, hardening suggestion | **Backlog.** |
| **1** | ⚪ INFO | Gray | Cosmetic, documentation, no security impact | **Optional.** |

### Severity Decision Guide

```
Can an attacker steal funds without any preconditions?
  YES → 10 (or 9 if amount is bounded)
  
Can an attacker steal funds WITH preconditions?
  YES, large amount → 8
  YES, small/bounded amount → 7

Can an attacker corrupt state, cause DoS, or manipulate economics?
  YES, significant impact → 6
  YES, limited impact → 5

Is there a security gap but no clear exploit path?
  YES, data exposed → 4
  YES, theoretical → 3

Is it a hardening suggestion with no vulnerability?
  YES, some value → 2
  YES, cosmetic → 1
```

### Impact × Likelihood — and principled downgrades

The number above is the **impact** score. A high-impact mechanism with a **low-likelihood** trigger lands lower, and the finding MUST state which axis drove it (e.g. "impact 8, but the exploit needs a compromised admin → reported at 6"). Never downgrade on vibes — cite a named lever with a worked justification:

- **Self-sacrifice / no incentive** — the attacker must burn their own funds, or a cheaper path reaches the same outcome.
- **Economic infeasibility (with numbers)** — show the bound: e.g. "the token would need to be worth ~1000× to profit; max gain is ≤ 1 lamport at normal state."
- **Recoverable / self-healing** — the harmful state reverses at bounded cost (merge stake accounts, next epoch clears it).
- **Bounded blast radius** — worst case is a small, contained loss (misdirected rent, one account), not a drain.
- **Defense-in-depth exceeds norms** — a redundant guard makes the gap non-exploitable in practice.
- **Privilege required** — a role-gated path caps severity (Rule 5b Attacker-Model); a permissionless variant would score higher.

There is no separate "Suggestion" tier — hardening ideas live at severity 1-2 (Informational), not as a distinct class.

### Notes & Nitpicks (below severity 1)

Not every observation is a finding. Issues with **no security impact** — style, naming, redundant code, micro-optimizations, documentation gaps — are NOT scored on the 1–10 scale. Collect them in a separate **Notes & Nitpicks** list in the report (mirrors Ackee's *Warning* and Neodyme's *nit-pick* tiers): a bulleted `file:line — observation` list, no severity, no remediation-tracking obligation. This keeps the findings table reserved for genuine security issues and prevents nit-inflation from diluting the severity signal. A note graduates to a severity-1 Informational finding only if it carries a concrete (if minor) security implication.

### Overall Repository Risk Score

After all items are checked, compute the **Repository Risk Score**:

```
If ANY finding ≥ 9:     REPO SCORE = 10 (CRITICAL — do not deploy)
If ANY finding ≥ 7:     REPO SCORE = max(finding) (HIGH — fix first)
If highest finding ≥ 5: REPO SCORE = max(finding) (MEDIUM — fix soon)
If highest finding ≥ 3: REPO SCORE = max(finding) (LOW — acceptable with tracking)
If highest finding ≤ 2: REPO SCORE = max(finding) (MINIMAL — clean)
```

---

## Rule 2: Executive Summary First

→ Report-assembly format moved to [references/report-format.md](references/report-format.md) § Rule 2 — Executive Summary (template + Severity Distribution + Items Verified tables); loaded at report time.

---

## Rule 3: Walk The Code — Never One-Shot

The auditor MUST walk through code files one at a time. Repositories can be any size — from 10 files to 10,000 files. The auditor does NOT guess. It reads every relevant file.

### Chunked Execution Protocol

```
1. DISCOVER: List all files that need auditing (use discovery/file-map.md patterns)
2. CHUNK: Group files into manageable batches:
   - On-chain: 1 instruction file per chunk
   - Backend: 1 route file per chunk (+ its service dependency)
   - Frontend: 2-3 components per chunk
   - Config: all config files in 1 chunk
3. PROCESS: For each chunk:
   a. Read the file(s) completely
   b. Run applicable checklist items against the actual code
   c. Record verdicts inline
   d. Save findings to session memory
4. CHECKPOINT: After each chunk, save progress:
   - Which files have been reviewed
   - Which checklist items have been evaluated
   - Any findings so far
5. RESUME: If context is lost, read the checkpoint and continue from where stopped
6. AGGREGATE: After all chunks processed, compile the full report
```

### Checkpoint Format

After each chunk, save to session memory:

```markdown
## Audit Checkpoint — {timestamp}

### Progress
- Phase: {0/1/2/3/4}
- Files reviewed: {list}
- Files remaining: {list}
- Current checklist: {number}

### Findings So Far
- F-001: [severity 8] {brief description} @ {file:line}
- F-002: [severity 5] {brief description} @ {file:line}

### Next Action
- Read {next file} and continue checklist {XX} from item {YYY}
```

### File Reading Rules

- **NEVER** assume what a file contains — always read it
- **NEVER** mark a checklist item PASS/FAIL without having read the relevant code
- **NEVER** try to process all files at once — respect the chunked protocol
- **ALWAYS** read the full file, not just the first N lines
- **ALWAYS** cross-reference: if file A calls file B, read file B too
- Large files (>300 lines): read in two passes (first half, second half)

---

## Rule 4: Every Item Gets a Verdict

Every single checklist item and every known attack vector MUST appear in the report output with an explicit verdict. No items are skipped silently. This is the proof that the auditor actually checked everything.

### Item Verdict Format

```
[PASS]      AV-001: Account ownership validated via Account<'info, T> typed accounts
[FAIL-8]    AV-015: Token account missing token::authority constraint
              File: programs/<program>/src/instructions/deposit.rs:42
              Impact: Attacker can substitute token account, draining vault
              Fix: Add `token::authority = fund` to account constraint
[PARTIAL]   AV-021: has_one present but missing runtime require_keys_eq! backup
              File: programs/<program>/src/instructions/swap.rs:18
              Impact: Defense-in-depth gap — single point of failure
              Fix: Add require_keys_eq! after has_one check
[N/A]       AV-023: init_if_needed — not used in this program
```

### Rules for Each Verdict

| Verdict | Rules |
|---|---|
| `[PASS]` | Must cite which file/code proves it's secure. One line. |
| `[FAIL-N]` | Must include: severity (1-10), file:line, impact, fix. Minimum 3 lines. |
| `[PARTIAL]` | Must include: what's missing, file:line, recommended improvement. |
| `[N/A]` | Must include: WHY it doesn't apply (e.g., "feature not used"). Never bare N/A. |

### Ordering

Items listed in **checklist order** (AV-001, AV-002, ..., PC-060, AI-001, ..., RS-017), followed by known vectors in order (KV-001 through KV-131). Never reorder or group by verdict.

---

## Rule 5: Findings Are Detailed

Every finding (any item that is `[FAIL-N]` with severity ≥ 4) gets a **full finding block** in the Findings section of the report.

### Finding Block Format

```markdown
#### [F-{number}] {Title}

| Field | Value |
|---|---|
| **Severity** | {1-10} — {🔴/🟠/🟡/🔵/⚪} {CRITICAL/HIGH/MEDIUM/LOW/INFO} |
| **Checklist Item** | {XX-YYY} |
| **Category** | {e.g., Arithmetic, Access Control, Injection} |
| **Language** | {Rust / TypeScript / Python / Go / etc.} |
| **File** | {path/to/file:line} |
| **Status** | Open |

**Description:**
{What is the vulnerability? Be specific to the code found.}

**Impact:**
{What can an attacker do? What is the worst-case scenario? Quantify if possible.}

**Proof of Concept:**
```{language}
// Minimal code/steps that demonstrate the issue
```

**Recommendation:**
```{language}
// Specific code fix — not just "fix this"
```
```

### Findings with severity 1-3 are **not required** to have a full block — the inline verdict line is sufficient. But they CAN have one if the auditor judges it useful.

---

## Rule 5b: High-Severity Findings Must Survive the Validation Gate

Over-reporting is the primary failure mode of an AI auditor. Any `[FAIL-N]` with **N ≥ 6** is *provisional* until it carries a filled **Reachability** block and a **Math / State-Bounds** block. Any `[FAIL-N]` with **N ≥ 7** additionally requires a filled **Attacker-Model** block.

If the gate blocks cannot be completed with cited evidence (`file:line`), the finding MUST be downgraded — never left as a bare `[FAIL-N]`:

- `[PARTIAL]` — a real defense-in-depth gap, but the exploit path is unproven; or
- `[UNCONFIRMED]` — suspected but unreachable / unbounded as written; reported for manual follow-up, not counted as a confirmed FAIL in metrics.

The gate blocks are reproduced in the finding's full block (Rule 5) and summarized in one line at the item verdict (Rule 4). *(Validation-gate pattern credit: Trail of Bits `fp-check` / `second-opinion`.)*

**Reachability** (required if N ≥ 6):

```
- Entry point: {instruction/endpoint} @ {file:line}
- Signer / authority required: {permissionless | user | manager | admin}
- Preconditions to reach the vulnerable line: {state/account conditions, each cited}
- Guard analysis: {constraints / require!s that could block it, and why they don't} @ {file:line}
- Verdict: REACHABLE | GUARDED (-> downgrade) | UNREACHABLE (-> downgrade)
```

**Math / State-Bounds** (required if N ≥ 6):

```
- Vulnerable expression / transition: {code} @ {file:line}
- Input domain: {ranges / types that reach it}
- Boundary that breaks: {overflow point | div-by-zero input | rounding direction | insolvent state}
- Worked case: {concrete numbers showing the break, or the state sequence}
- Net effect: {funds moved | state corrupted | DoS — quantified}
```

**Attacker-Model** (required if N ≥ 7):

```
- Capability: {permissionless caller | one deposit | flash-loanable capital | co-signer | compromised admin}
- Capital / setup cost: {approx}
- Profit / damage: {approx, or "griefing — no direct profit"}
- Atomicity: {single-tx | multi-tx | multi-slot}
- Net: profitable | griefing-only | requires-privilege (privilege caps severity per Rule 1)
```

A *rejected* finding looks like this: "input ≥ 16 and header = 8 ⟹ input − header ≥ 8, so the subtraction cannot underflow. Downgraded `[FAIL-7]` → `[UNCONFIRMED]`."

**Two honest outcomes when you cannot fully prove it:**
- `[UNCONFIRMED]` — the gate failed on **reachability or bounds** (unreachable / unbounded as written). Reported for manual follow-up; not a confirmed FAIL.
- `[UNDETERMINED]` — the path **is reachable** but its full impact could not be quantified within scope. Carry the line "extent not determined within this assessment" and report it at its likely severity band, flagged. Reachable-but-unquantified ≠ unreachable.

**Accepted PoC forms.** A runnable exploit is ideal but not the only proof. For access-control / logic findings a **structured attacker-narrative** is a first-class PoC: *actor → capability → numbered steps → guard bypassed → quantified outcome* (e.g. Alice deposits; Eve substitutes her key at `L88`; drains ~$X). And when the **missing check is provable at `file:line`** but the full exploit math can't be confirmed in the engagement window, you MAY still report at severity **provided** the finding carries explicit uncertainty phrasing and states exactly what remains unproven — do not mechanically bury a real syntactic gap as `[UNCONFIRMED]`.

**PoC-evidence tier (tag the proof, orthogonal to severity).** When an executable PoC is built (via `/auditor:poc` → [references/orchestration/poc-harness.md](references/orchestration/poc-harness.md)), tag the finding with the strongest tier achieved. Executable **outranks** prose, but prose is **never removed** — an unbuildable target still yields a full finding:

| Tier | Meaning |
|------|---------|
| `[PoC-REPRODUCED]` | Executable harness in `poc/F-xxx/` runs (Mollusk/LiteSVM): exploit **succeeds on the `vulnerable` arm and is rejected on `fixed`**. Gold standard. |
| `[PoC-SIM-REPRODUCED]` | Reproduced on a Surfpool mainnet-fork with a **quantified net P/L** (economic/oracle/MEV). |
| `[PoC-FUZZ-REPRODUCED]` | A fuzzer (Trident/cargo-fuzz) produced a committed **crash/invariant-breaking artifact** that deterministically triggers it. |
| `[PoC-ATTEMPTED]` | Harness generated but could not confirm (toolchain absent, could not minimize, fork state unavailable). Blocker named; **prose PoC retained**; severity unchanged. |
| `[PoC-PROSE]` | Structured attacker-narrative only — the accepted default for access-control/logic findings and whenever a harness is impractical. |

**Fix-evidence tier (the patch side).** When `/auditor:patch` proposes a remediation diff, tag its verification (feeds the report's **Auditor Verification** field): `[FIX-VERIFIED]` (patch applied to a scratch worktree; the finding's PoC now reverts — optionally a mutant on the patched line is caught) > `[FIX-INSUFFICIENT]` (residual path still reproduces → mirrors `/re-audit` PARTIALLY-FIXED) > `[FIX-PROPOSED]` (diff is idiomatic and closes the cited bound, but no executable PoC was available to run the revert). Never claim `[FIX-VERIFIED]` without an executed revert.

---

## Rule 6: Report Sections Order

→ Report-assembly format moved to [references/report-format.md](references/report-format.md) § Rule 6 — Report Sections Order; loaded at report time.

---

## Rule 7: Language Detection Is Automatic

The auditor MUST auto-detect all languages present in the repository and apply the correct checklists. Record all detected languages in the report header.

### Detection Method

Language → checklist mapping is authoritative in [SKILL.md](SKILL.md) → Scope-Gated Loading, Step 2 (scope table). Apply it verbatim.

### Unsupported Language Handling

If a language has no dedicated checklist (e.g., Swift, Dart, Elixir):
1. Apply Checklist 15 (General Language Safety) — sections 15.1-15.8
2. Note in the report: "Language {X} audited using general safety checklist — no language-specific checklist available"
3. The audit is still valid — fundamentals (injection, auth, crypto, errors) are universal

---

## Rule 8: Metric Computation

→ Report-assembly format moved to [references/report-format.md](references/report-format.md) § Rule 8 — Metric Computation (Audit Metrics / Known Vector Metrics / Per-Checklist Summary tables); loaded at report time.

---

## Rule 9: File Naming

→ Report-assembly format moved to [references/report-format.md](references/report-format.md) § Rule 9 — File Naming; loaded at report time.

---

## Rule 10: Honesty & Limitations

- **NEVER** mark an item `[PASS]` if you did not read the code
- **NEVER** mark an item `[N/A]` just because you ran out of context
- If context was lost mid-audit, say so: `[INCOMPLETE — context lost, needs re-review]`
- If a file was too large to fully read, say so: `[PARTIAL — file truncated at line X, remaining unreviewed]`
- If the repo uses a pattern the auditor doesn't recognize, say so: `[UNKNOWN — unfamiliar pattern, manual review recommended]`
- The Executive Summary must honestly state if the audit is partial

### Confidence Tagging

For any item where the auditor is less than fully certain:

```
[PASS*]     AV-001: Ownership checked via Account<T> — *confidence: medium, complex macro usage
[FAIL-6*]   AR-015: Division without zero check — *confidence: high, clear in code
```

The `*` suffix + confidence note signals that manual double-checking may be warranted.

### `[UNCONFIRMED]` / `[UNDETERMINED]` — validation-gate outcomes

Both tokens are defined in Rule 5b. Recap: `[UNCONFIRMED]` = the gate failed on reachability or bounds — suspected but unreachable / unbounded as written; reported for manual follow-up, NOT counted as a confirmed FAIL. `[UNDETERMINED]` = reachable but full impact unquantified within scope; reported at its likely severity band, flagged.
