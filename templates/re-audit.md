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
PoC re-run @ {HEAD_SHA} (Re-detonated against: {patched target build (`VULNERABLE_SO` / `FIXED_SO` overrides — `templates/poc/run.sh`) | minimized model}; AUDITOR_EXEC_MODE={isolated | native}): {reverts (<how the fixed arm held>) | still succeeds | inconclusive (<harness error>) | not run (<reason>)}
```

A re-run against the client's fix is a *patched target build*: `run.sh` in prebuilt mode with
`VULNERABLE_SO` = the build of the audited commit and `FIXED_SO` = the build of the head commit, after the
crate's `run.sh` and `shared-test-utils/` are refreshed from the installation. The value follows `run.sh`:

- **reverts** — exit 0, ending in `(rejected with the pinned error) → [PoC-REPRODUCED]` (the head build
  turns the attack away with the error the PoC pins) or `(blocked: failed, account unchanged) →
  [PoC-REPRODUCED]` (the client's own error, checked with `assert_exploit_blocked!` and its positive
  control). Record which, with the final line.
- **still succeeds** — exit 2 where the head build let the attack through: the final line is
  `FAIL: … did not block …`. An exit 2 whose message is instead `attack was expected to be REJECTED with
  <X>, but got: <other error>` is **not** `still succeeds` — the head build turned the attack away with
  its own error, not the one the PoC pins. Record that as `inconclusive (pinned error <X> vs <other>)` and
  re-run with `assert_exploit_blocked!` and its positive control (the form for a fix whose error is not
  known in advance); better still, use that form from the start for a client fix.
- **inconclusive (`<harness error>`)** — exit 3, with `run.sh`'s blocker line verbatim; the finding is
  flagged "PoC re-run needed". Exit 1 is inconclusive too: the exploit did not reproduce on the audited
  build, so the run shows nothing about the fix.
- **not run (`<reason>`)** — no PoC, no execution mode that can run it, no toolchain, or a commit that
  could not be built.

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
