---
name: auditor:patch
description: Draft and verify a fix for a confirmed finding — a MINIMAL idiomatic unified diff against the pinned audited commit, applied to a scratch worktree and proven by re-running the finding's PoC (it must now revert). Proposal only; the auditor stays read-only on the client tree. Optional mutation + blast-radius evidence. Emits [FIX-VERIFIED] / [FIX-INSUFFICIENT] / [FIX-PROPOSED].
argument-hint: "<finding-id> [--verify-with-mutation]"
allowed-tools: Read, Grep, Glob, Bash, Task
---

# auditor-skill — Patch Draft & Verification

**Arguments:** $ARGUMENTS

Produce a *verified fix proposal* for a confirmed finding. Read `OUTPUT-RULES.md` first (severity 1-10, **Rule 5b**) and the finding's block + its `audit_<n>/poc/F-xxx` harness (the executed exploit the fix must now defeat). The patch is a **deliverable, not an application** — the auditor never writes to the client's real tree; it stays read-only on the target and hands back a diff plus a verification record.

## Steps

1. **Resolve the finding.** Read the finding block from `audit_<n>/REPORT.md`, its context worksheet under `worksheets/context/*`, and its `poc/F-xxx` crate if `/auditor:poc` already ran. Pin the audited commit — the diff must apply against **that** commit, not `HEAD`.

2. **Spawn `patch-engineer`.** It writes `audit_<n>/patches/F-xxx.patch`: a **minimal, idiomatic unified diff** that closes *exactly* the cited reachability/bound — no refactor, no drive-by cleanup, nothing beyond the one guard/bound the finding names. It obeys `.claude/rules/{rust,anchor,pinocchio}.md`: checked arithmetic (`checked_add`/`checked_sub`/…), stored canonical bumps (never recalculated), `transfer_checked` (not deprecated `transfer`), no `unwrap()`/`expect()` in program code, validated CPI targets. A cosmetic edit that does not move the Rule 5b bound is **not** a fix.

3. **Verify by execution (mandatory for [FIX-VERIFIED]).** Apply the patch to a **scratch git worktree** (never the client checkout), rebuild, and **re-run the finding's `poc/F-xxx` exploit**. The exploit must now **revert / fail** on the patched build — the previously-succeeding `vulnerable` path is closed. Reading the diff is not verification; only an executed revert earns `[FIX-VERIFIED]`. If no executable PoC exists, the ceiling is `[FIX-PROPOSED]` (verified by re-derivation, not by execution).

4. **Mutation + blast-radius (optional).** With `--verify-with-mutation`, run **`mewt` mutation** on the patched line(s) via Trail of Bits `mutation-testing` (`references/orchestration/boundary-map.md`) — an uncaught mutant on the fix means the guard is under-tested, so record it and do not overstate the verification. Always run a **`differential-review` blast-radius check** (Trail of Bits): apply the *same* diff-vs-behavior comparison to confirm the fix closes the exploit path and leaves every other path unchanged — a fix that breaks an adjacent instruction is `[FIX-INSUFFICIENT]`.

5. **Emit outputs** under `audit_<n>/patches/`:
   - `F-xxx.patch` — the minimal unified diff (deliverable),
   - `VERIFICATION.md` — per-patch: the tier below, the executed revert result (pre-fix exploit succeeded → post-fix reverted), any mutation/blast-radius evidence, and what a maintainer must do to apply it,
   - update the report's **Auditor Verification** line for the finding to reflect the tier.

## Evidence tiers (emit exactly one)

| Tier | Meaning |
|------|---------|
| `[FIX-VERIFIED]` | Diff applied to a scratch worktree, rebuilt, and the finding's PoC **re-ran and now reverts** — closure demonstrated by execution. Optional mutation/blast-radius clean. |
| `[FIX-INSUFFICIENT]` | The diff does **not** fully close the bound — the PoC still exploits a residual path, an uncaught mutant survives on the patched line, or the change breaks an adjacent path (blast-radius regression). State exactly what remains open. |
| `[FIX-PROPOSED]` | A minimal idiomatic diff re-derived from the code closes the cited bound, but **no executable PoC was available** to run the revert. Verified by reasoning, flagged as not-yet-executed — never silently promoted to `[FIX-VERIFIED]`. |

## Discipline (reuse /auditor:re-audit's rule)

A **cosmetic patch ≠ FIXED**. Never claim `[FIX-VERIFIED]` without an *executed* revert of the finding's own exploit; a patch that reads plausibly but was never run against the PoC is `[FIX-PROPOSED]` at most. The patch is proposal-grade evidence for the client to apply and re-test on their side — this command does not touch the client's real tree.
