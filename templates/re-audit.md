# Re-audit — `{PROJECT}` at `{HEAD_SHA}`

The finding-diff `/auditor:re-audit` writes to `audit_<n+1>/RE-AUDIT.md`. Baseline: the prior
`audit_<n>/REPORT.md`, audited at `{AUDITED_SHA}`. Delta: `{BASE}..{HEAD}`. Execution mode for every build
and PoC re-run: `{isolated | native}` (`OUTPUT-RULES.md` Rule 11a; native means target code ran on the
auditor's machine).

## 1. Finding-diff

| Finding | Severity | Status | Remediation commit / PR | `file:line` | PoC re-run (step 4b) | Verification verb |
|---------|----------|--------|-------------------------|-------------|----------------------|-------------------|
| {F-001} | {N} | {FIXED \| PARTIALLY-FIXED \| STILL-OPEN \| REGRESSED \| ACKNOWLEDGED \| DISPUTED} | {hash (PR)} | {fixing or surviving location} | {the field below} | {we re-tested and confirmed \| we re-derived from the code and confirmed \| client states fixed (unverified)} |

**The PoC re-run field.** Every finding with a PoC gets one, in this form:

```
PoC re-run @ {HEAD_SHA} (Re-detonated against: {patched target build (`--vulnerable-so` / `--fixed-so` — `templates/poc/run.sh`) | minimized model}; AUDITOR_EXEC_MODE={isolated | native}): {reverts (<how the fixed arm held>) | still succeeds | inconclusive (<reason>) | not run (<reason>)}
```

A re-run against the client's fix is a *patched target build*: `run.sh` in prebuilt mode with
`--vulnerable-so` = the build of the audited commit and `--fixed-so` = the build of the head commit, after the
crate's `shared-test-utils/src/` is refreshed from the installation. With no build of the head
commit it is the *minimized model*: the crate's `src/fixed.rs` becomes its `src/vulnerable.rs` with the
client's fix transplanted, and `run.sh` runs with no overrides. The value follows `run.sh`:

- **reverts** — exit 0. On a patched target build the final line ends in `(rejected with the pinned
  error) → [PoC-REPRODUCED]` (the head build turns the attack away with the error the PoC pins) or
  `(blocked: failed, account unchanged) → [PoC-REPRODUCED]` (the client's own error, checked with
  `assert_exploit_blocked!` and its positive control). On the minimized model it is the model line, `OK:
  exploit reproduces on 'vulnerable' and is blocked on 'fixed' (… a model, never Leg 3) →
  [PoC-REPRODUCED]`; record `reverts (minimized model)`. Record which, with the final line.
- **still succeeds** — exit 2 whose final line is `FAIL: the fixed arm accepted the attack …` or `FAIL:
  the fixed arm failed the attack, yet the account changed …`: the head build let the attack through.
- **inconclusive (`<reason>`)** — exit 2 whose final line is `FAIL: the fixed arm rejected the attack with
  another error than the pinned one …`: the head build turned the attack away with its own error, which
  the test's message names next to the pinned one. Record `inconclusive (pinned error <X> vs <other>)` and
  re-run with `assert_exploit_blocked!` and its positive control (the form for a fix whose error is not
  known in advance); better still, use that form from the start for a client fix. Every exit 3 is
  inconclusive too, with `run.sh`'s blocker line verbatim as the reason and the flag "PoC re-run needed".
  So is exit 1: the exploit did not reproduce on the audited build, so the run shows nothing about the fix.
- **not run (`<reason>`)** — `run.sh` did not run: no PoC, no execution mode that can run it, or a commit
  that could not be built.

**FIXED needs an executed revert.** A FIXED row whose re-run is `reverts` takes the verb "we re-tested and
confirmed". A FIXED row whose re-run is `inconclusive` or `not run` keeps its status on a read-based
re-derivation, is flagged `⚑ no executed revert`, and takes the verb "we re-derived from the code and
confirmed". A re-run that `still succeeds` contradicts FIXED: do not record FIXED unless a written reason
explains the gap (for example, the PoC exercises a path the fix deliberately left, re-derived from the
code) — otherwise the finding is PARTIALLY-FIXED or STILL-OPEN.

## 2. New findings on the changed surface

{Severity-ordered, each with its full Rule 5b block (`OUTPUT-RULES.md`), from step 3.}

## 3. Sibling sweep

| Swept signature | Globs | Un-patched siblings |
|-----------------|-------|---------------------|
| {the anti-pattern the fix closed} | {globs} | {`file:line` list, or "none found"} |

Every swept signature has a row; "swept `<signature>` across `<globs>` — no siblings found" is a result,
not an omission.

## 4. Safe-to-deploy verdict

{The updated verdict. ACKNOWLEDGED, DISPUTED and STILL-OPEN findings keep their severity, and a FIXED row
flagged `⚑ no executed revert` is named here as resting on a re-derivation.}
