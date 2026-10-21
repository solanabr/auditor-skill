# Patch verification — `{FINDING_ID}`

The proof block for `{FINDING_ID}.patch`. It records HOW the fix was proven, not just
that it was written. Emitted to `audit_<n>/patches/VERIFICATION.md` (one block per
patch) and its verdict updates the finding's **Auditor Verification** line in the
report.

Verification is by **execution**, on a throwaway copy. Never write to the client's
real tree: apply the patch to a **scratch git worktree**, build there, run there,
discard it.

## 1. Apply (scratch worktree — never the client checkout)

The rebuild runs target-controlled code (build scripts, proc-macros, toolchain files), so it follows the
execution mode recorded at intake — `OUTPUT-RULES.md` Rule 11a (isolated recommended; native allowed and
stated in the report). If it cannot run in that mode, stop at `[FIX-PROPOSED]`. Create the worktree from a
clone you made yourself; for a checkout the client supplied, follow Rule 11c first.

```bash
git worktree add /tmp/fix-{FINDING_ID} {COMMIT}      # the audited commit the patch targets
cd /tmp/fix-{FINDING_ID}
git apply {PATH_TO}/{FINDING_ID}.patch               # or: git am < ... for format-patch
cargo build-sbf --tools-version v1.54                 # rebuild the patched program
```

- [ ] Patch applied cleanly against `{COMMIT}` (no fuzz, no reject `.rej` files).
- [ ] Patched program builds.

## 2. PoC now reverts (mandatory for [FIX-VERIFIED])

Re-run the finding's own exploit against the **patched** build. The line that
previously succeeded must now fail.

```bash
{PATH_TO}/poc/{FINDING_ID}/run.sh
```

**Re-detonated against:** {patched target build (`VULNERABLE_SO` / `FIXED_SO` overrides — `templates/poc/run.sh`) | minimized model}
— a *patched target build* runs `run.sh` against the unpatched and patched builds of the target itself
(set both overrides or neither); the *minimized model* is the PoC crate's own `vulnerable` / `fixed` arms
with the patch transplanted.

- **Pre-fix (recorded when the PoC was built):** `tests/exploit.rs` SUCCEEDED on the
  `vulnerable` arm — the attack went through. → `[PoC-REPRODUCED]`
- **Post-fix (this step):** transplant the patch onto the PoC's `vulnerable` arm (or
  point the harness at the patched source) and re-run `tests/exploit.rs`. It must now
  **revert / error** — the previously-open path is closed.

- [ ] The finding's exploit **reverts** on the patched build (was Ok → now Err).
- [ ] The legitimate path still works (a positive test for the honest caller passes).

Reading the diff is not verification. Only an executed revert of the finding's own
exploit earns `[FIX-VERIFIED]`. If there is no executable PoC to run, stop at
`[FIX-PROPOSED]` and say so.

## 3. Mutation + blast-radius (optional, strengthens the verdict)

- **Mutation on the patched line** — run `mewt` (Trail of Bits `mutation-testing`,
  see `references/orchestration/boundary-map.md`) on exactly the line(s) the patch
  added. A **surviving mutant** on the fix means the guard is under-tested: the test
  suite would not catch the fix being silently broken later. Record it; do not
  overstate the verification.

  ```bash
  mewt init                                      # once per crate: writes mewt.toml + mewt.sqlite
  mewt mutate {FILE}                             # optional: generate mutants without testing them
  mewt run {FILE}                                # generate the mutants and run the tests
  mewt results --target '{FILE}' --line {LINE}   # uncaught mutants on the patched line
  ```
  Interface as documented by the vendored `mutation-testing` skill (mewt 4.x); `mewt --help`
  is authoritative. A mutation run executes the target's tests, so it follows Rule 11a too.
  - [ ] No surviving mutant on the patched line(s) — or the survivor is recorded and
        the verdict is not overstated.

- **Blast-radius** — run a `differential-review` check (Trail of Bits): confirm the
  diff closes the exploit path and leaves **every other path unchanged**. A fix that
  breaks an adjacent instruction is `[FIX-INSUFFICIENT]`, however well it closes the
  cited bound. Without the vendored tooling, use the differential execution of
  `/auditor:re-audit` step 4b.
  - [ ] No adjacent path regressed.

## 4. Verdict → report's Auditor Verification field

Emit exactly one, and write it to the finding's **Auditor Verification** line:

| Verdict | Condition |
|---------|-----------|
| `[FIX-VERIFIED]` | Patch applied to a scratch worktree, rebuilt, and the finding's PoC **re-ran and now reverts**. Optional mutation/blast-radius clean. |
| `[FIX-INSUFFICIENT]` | The PoC still exploits a residual path, a mutant survives on the patched line, or an adjacent path regressed (blast-radius). State exactly what remains open. |
| `[FIX-PROPOSED]` | A minimal idiomatic diff re-derived from the code closes the cited bound, but **no executable PoC was available** to run the revert. Verified by reasoning, flagged not-yet-executed — never silently promoted. |

**Verdict:** `{FIX-VERIFIED | FIX-INSUFFICIENT | FIX-PROPOSED}`
**What a maintainer must do to apply:** {e.g. `git am < {FINDING_ID}.patch` on `{COMMIT}`, `cargo build-sbf`, run the crate's own tests.}
**Residual (if any):** {what is still open, for INSUFFICIENT — else "none".}

---

A cosmetic patch is **not** a fix. Never claim `[FIX-VERIFIED]` without an executed
revert of the finding's own exploit. This document is proposal-grade evidence for the
client to apply and re-test on their side — the audit does not touch their real tree.
