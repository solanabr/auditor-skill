---
name: auditor:re-audit
description: Fix-review / re-audit. Takes a prior audit report + the current tree and classifies every prior finding FIXED / STILL-OPEN / REGRESSED (re-running Rule 5b on the fix), audits the changed surface for NEW findings via the diff-audit path, and runs a sibling-patch-propagation sweep for un-patched copies of every fixed anti-pattern. Emits a finding-diff.
argument-hint: "[prior-report] [base..head]"
allowed-tools: Read, Grep, Glob, Bash, Task
---

# auditor-skill — Fix Review / Re-Audit

**Arguments:** $ARGUMENTS

Re-audit a codebase after a fix round. **Input:** a prior `audit_<n>/REPORT.md` (arg 1) and the current tree; the delta range is `base..head` (arg 2, default `main..HEAD` — the fix commits). Read `OUTPUT-RULES.md` first (severity 1-10, the **Rule 5b** gate). This is a Zenith/Certora-style fix-review, not a fresh audit — it reuses the prior report as the baseline and reports what changed.

## Steps

1. **Load the baseline.** Parse the prior report's findings (id, severity, `file:line`, root-cause, Rule 5b block). Pin both commits: the prior report's audited commit and the current `head`.

2. **Classify every prior finding.** For each prior finding, read the current code at the (possibly moved) location and assign:
   - **FIXED** — the vulnerable path is gone. **Re-run Rule 5b on the fix**: confirm the fix actually closes the reachability/bound the finding claimed — a cosmetic or incomplete patch is **not** FIXED. Cite the fixing `file:line`.
   - **STILL-OPEN** — the finding survives unchanged (or was never touched). Carry its severity forward.
   - **REGRESSED** — the fix introduced a new problem, or a previously-fixed issue returned, or the "fix" made it worse. Treat as a fresh finding through the full Rule 5b gate; a security check deleted in a fix commit is a CRITICAL regression (git-blame it).

3. **NEW findings on the changed surface.** Run the changed surface through the **diff-audit path** (`/auditor:diff-audit` logic): `git diff --name-only base..head`, Phase 0.5 context reconstruction on changed functions + 1-hop callers/callees, risk-classify (auth / crypto / value-transfer / validation-removal = HIGH), then the matching checklist items + known-vectors through Rule 5b. Fixes routinely introduce new bugs — this catches them. Delegate to `vuln-hunter` for the walk.

4. **Sibling-patch-propagation sweep (variant analysis).** For **every FIXED finding**, extract the anti-pattern signature (the code shape that was the bug — e.g. a missing signer check, an unchecked `*`, a PDA derived without the stored bump) and `grep` the whole codebase for the **same signature elsewhere**. Report every un-patched sibling instruction: a fix applied to one call site but not its twins is a live vulnerability. This is the Certora/ToB variant-analysis discipline — one fix rarely covers all instances.

5. **Emit the finding-diff.** Write `audit_<n+1>/RE-AUDIT.md`:
   - **Finding-diff table:** each prior finding → FIXED / STILL-OPEN / REGRESSED (+ fixing or surviving `file:line`).
   - **New findings** (from step 3), severity-ordered, full Rule 5b blocks.
   - **Sibling sweep** (from step 4): per fixed anti-pattern, the un-patched siblings found (or "no siblings").
   - **Updated safe-to-deploy verdict** reflecting the new state. Spawn `audit-reporter` for assembly.
