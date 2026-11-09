# {Quick review: diff | Quick scan | Deep review} — `{PROJECT}` at `{HEAD_SHA}`

The report each Quick command writes in its run directory: `/auditor:diff-audit` to `audit_<n>/PR-REPORT.md`,
`/auditor:quick-scan` to `audit_<n>/QUICK-SCAN.md`, `/auditor:deep-review` to `audit_<n>/DEEP-REVIEW-<unit>.md`.
Fill every `{placeholder}` and drop the sections marked for another command. With `--ci`, the same verdict and
findings go to `audit_<n>/findings.json` (`templates/ci/findings.schema.json`); the reply holds no finding text,
count or path (`OUTPUT-RULES.md` Rule 11d).

## Summary

| | |
|---|---|
| **Verdict** | {pass \| fail} at threshold {N} (`--fail-on`, 7 when not given): fail when a finding of severity {N} or more counts (Rule 5b status passed, undetermined or not-required), when an analyzer this run called for did not run, or when the run stopped early. deep-review: {none — it is not a gate} |
| **Highest severity** | {N — CRITICAL / HIGH / MEDIUM / LOW / INFO, or none} |
| **Findings** | {how many at each severity, highest first, e.g. 1 × 8, 2 × 5; or none} |
| **Reviewed** | {diff-audit: `{BASE}..{HEAD}`, {k} changed files and their 1-hop callers and callees · quick-scan: the scope it was given, the checklist sections and vector rows `audit_<n>/scope.md` lists · deep-review: `{file}`, `{function or instruction}`} |
| **Analyzers** | ran: {names, or none} · not run: {names and why, or none} |
| **Mode** | {preflight's first line, as it stands} |

{Two or three plain sentences: what changed or what was looked at, the most important finding if any, and what
to do next. This is a Quick review, not a complete audit: `/auditor:audit` covers every in-scope item.}

## Provenance

- **Command:** `/auditor:{diff-audit | quick-scan | deep-review} {the arguments as given}`
- **Pinned:** {diff-audit: base `{full BASE id}`, head `{full HEAD id}` · quick-scan and deep-review: HEAD
  `{full HEAD id}`}, from `git-ro.sh rev-parse`. The commands read files from the working tree, which can hold
  changes the pinned commit does not have; a finding cites the line it read.
- **Plugin:** auditor-skill {version}
- **Run directory:** `audit_<n>/` {and, with `--ci`, `audit_<n>/findings.json`}

## Findings

{Highest severity first. Each finding of severity 4 or more gets the full block of `OUTPUT-RULES.md` Rule 5,
and each of 6 or more the filled Rule 5b blocks; a finding the gate downgraded keeps its `[UNCONFIRMED]` or
`[PARTIAL]` tag. None: "No findings on the reviewed surface."}

## Verdicts

{Rule 4 lines for what this command evaluated, in checklist order, then the known vectors: diff-audit, the
changed surface; quick-scan, the sections and rows `audit_<n>/scope.md` lists; deep-review, the items of
this unit. Every line names its `file:line` or why it does not apply.}

## Dependency delta

{diff-audit, when its step 5 ran: each changed entry of a manifest or lockfile, the checklist 11 §11.11 verdicts
SC-059..062, and how many changed packages were left without an artifact diff. Otherwise drop this section.}

## Coverage & Limitations

- Preflight's first line, and every `note:` line the bundled tools printed, as they stand (Rule 11f).
- Each analyzer or tool that did not run, and why: denied, failed, not built, or not installed.
- What the command does not cover: quick-scan and diff-audit, what `references/depth-scope.md` leaves out, as
  its §8 renders it; diff-audit, also the code beyond the changed files and their 1-hop neighbours; deep-review,
  one unit.
- The corpus this run read, by checklist section and vector id, and any selected file the Read tool could not
  open, so a reader can tell what each verdict rests on. For quick-scan and diff-audit that is what
  `audit_<n>/scope.md` lists, written before the reads, so a reader can check the selection against
  `references/depth-scope.md` and the reads against the selection.
- Outside services (Rule 11b): each row of `audit_<n>/disclosures.tsv`. A tool adds its row before its first
  request to that service, so a row says what the tool was set to send, not that it went out. Write that it was
  sent only where the tool's own output names that service's address as one it reached, and otherwise that it
  may have been sent. A line saying what a tool loaded or scanned, such as cargo audit's
  `Loaded … security advisories (from <folder>)`, names a local copy and shows no request.

## Notes & Nitpicks

{`file:line` — observation, with no severity (Rule 1); or drop this section.}
