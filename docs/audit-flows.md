# Audit Flows

Which depth to run, what each one reads, and the pipeline it follows, for anyone choosing between a quick look, a module audit and a release audit. Back to the [docs index](README.md).

Contents: [Pick a depth](#pick-a-depth) · [Quick](#quick) ([What Quick reads](#what-quick-reads), [The Quick reports](#the-quick-reports)) · [Standard](#standard) · [Full](#full) · [CI](#ci) · [Outside the depths](#outside-the-depths)

## Pick a depth

auditor-skill has three depths and a CI mode. Pick by what you want checked: what changed, one module, or the release.

| Depth | When | Run | Reads | Writes | [Cost](costs.md#cost-and-time-by-depth) |
|-------|------|-----|-------|--------|------|
| **Quick** | a branch or pull request, a first look at a repository, one function | `/auditor:diff-audit` · `/auditor:quick-scan` (whole repository) · `/auditor:deep-review <file> <fn>` | the changed code + one hop, read against the sections and vectors `references/depth-scope.md` selects · SAST, dependency advisories, and the sections and vectors `references/depth-scope.md` selects · one function | `PR-REPORT.md` · `QUICK-SCAN.md` · `DEEP-REVIEW-<unit>.md` | $2–8 · 4–23 min |
| **Standard** | one module or program before it merges | `/auditor:audit <path> --scope …` | every in-scope item for that path | `REPORT.md`, internal: a risk score and a deploy verdict | $13–19 · 36–56 min |
| **Full** | a release, or a report for someone outside the team | `/auditor:audit-cycle` (unattended) · `/auditor:audit-assist` (you steer) · `/auditor:re-audit` after fixes | everything in scope, a threat model, peer review (re-audit: the fix delta) | `REPORT.md`, client style: no deploy guarantee (audit-cycle adds a PDF when pandoc and a LaTeX engine are installed, and PoCs with `--with-poc`) · `RE-AUDIT.md`, with an updated deploy verdict | about $20 · about 1 h, on a 3K-line program |
| **[CI](ci.md)** | every pull request: the analyzers on all, the review on your own branches' only | `templates/ci/auditor-pr.yml`: a tools job, then `/auditor:diff-audit --ci` | as Quick | `findings.json` and SARIF on the runner; in the log, pass/fail and notes about the tools, never a finding or a count | tools job $0; review about a diff-audit's cost ($2–8), capped at $15 |

Costs and times were measured from 2026-11-08 to 2026-11-10 with `claude-opus-5-5`, on 3K-, 7K- and 12K-line programs. Quick's range covers diff-audit runs of $1.68–8.10 and quick-scan runs of $2.84–7.14. The shipped command text was measured on the 3K-line repository, where a quick-scan cost $6.98 in 23 minutes and a diff-audit of a 7,830-line range, a lockfile change included, $8.10 in 19 minutes, and on the 12K-line program, where a diff-audit of a 1,248-line change with no lockfile cost $3.99 in 9 minutes. The other runs were on earlier drafts, and those under $3 read 16 to 55 vector files and at most one checklist. Full ran once, on the 3K-line program ([docs/costs.md](costs.md#cost-and-time-by-depth)). Outside the depths: `poc`, `patch`, `economic-sim` and `triage` work on one finding; `intake` and `threat-model` are Full's building blocks; `audit-report` assembles the internal report from a walk run in pieces; `spec-audit` checks code against a spec; `hunt` and `respond` are for after an incident ([detection-response.md](detection-response.md)).

Every flow first runs `preflight.sh` on the working tree. Its first line names the mode: in default mode it notes what it finds and the flow goes on; in strict mode, for a repository you do not trust, it refuses project config and the rest [Rule 11f](../OUTPUT-RULES.md#11f--default-and-strict-mode) lists. Then the flow runs its bundled steps without asking: run directories, read-only git, the Rust tools, and the runners that build and test in the execution mode in force, native unless intake, `AUDITOR_EXEC_MODE` or strict mode says otherwise. What still asks, and how to run in strict mode, isolated or in `claude -p`: [permissions-and-isolation.md](permissions-and-isolation.md).

## Quick

These skip the full checklist walk: inside the sections they read, every item still gets a verdict.

### `/auditor:diff-audit`

PR / commit-scoped. Computes the changed set with read-only git (`git-ro.sh diff --name-only base..head`, default `main..HEAD`), runs Phase 0.5 on changed functions + 1-hop callers/callees, risk-classifies changed files (auth / crypto / value-transfer / validation-removal = HIGH), git-blames removed security code (a deletion in a "fix"/"CVE" commit is a CRITICAL regression), reads the checklist sections and known-vector rows `references/depth-scope.md` selects for the kinds of file the change holds, writing that selection to `audit_<n>/scope.md` before it reads any, and gives their findings through Rule 5b ([What Quick reads](#what-quick-reads)).

When a manifest or lockfile changed, it runs checklist 11 §11.11's CI budget: `lock-delta.sh set` finds the new package versions, and `deps.sh lock-budget` checks their publish ages and compares the published code of every key-handling package and at most 40 others. It reviews at most 5,000 changed lines, riskiest first, and counts the rest; `--over-budget fail` fails the review instead. Emits `audit_<n>/PR-REPORT.md`.

It reviews commits, so commit your work first. With no argument it compares the tip of `main` with HEAD, so rebase on `main` first, or changes `main` gained since you branched show up in the review. In CI, the workflow passes the pull request's range.

```
/auditor:diff-audit                 # main..HEAD
/auditor:diff-audit v1.2.0..HEAD
```

### `/auditor:quick-scan`

A first look at a whole repository, or at the path you pass: discovery and scope, static analysis of every in-scope directory (`sast.sh` semgrep; ToB `static-analysis` when semgrep is missing and the plugins are present; else grep scanners), dependency advisories (`deps.sh` cargo-audit and npm-audit), and a reading pass over the checklist sections and known-vector rows `references/depth-scope.md` selects for the detected domains, written to `audit_<n>/scope.md` before any is read: each domain's core sections, the gated ones whose markers occur, the severity 7+ always vectors, and the 9+ marker vectors whose markers occur ([What Quick reads](#what-quick-reads)).

In a repository with more than two on-chain programs, it scans the two largest and names a `/auditor:quick-scan <path>` for each of the others. Writes `audit_<n>/QUICK-SCAN.md`: findings with severity + `file:line`, stated plainly as a triage pass that points to `/auditor:audit` for full coverage. An analyzer that did not run is reported as not run, never counted as clean. Its scope is the path you pass, or else the whole repository.

For a pull request diff-audit reads less code, but it selects more of the corpus: on the 3K-line repository its shipped text read 98 vector files and 43 sections for $8.10, where quick-scan read 38 and 49 for $6.98 ([docs/costs.md](costs.md#cost-and-time-by-depth)).

### `/auditor:deep-review`

One instruction / function, deeply. Reads the file, runs Phase 0.5 context reconstruction on the target, fills the instruction worksheet, adversarially models exploitation, and writes the verdicts for that unit only to `audit_<n>/DEEP-REVIEW-<unit>.md`.

```
/auditor:deep-review programs/vault/src/instructions/withdraw.rs withdraw
```

Quick costs less than a full walk because it reads less: diff-audit what changed and one hop around it, quick-scan the sections and vectors depth-scope.md selects, deep-review one unit. quick-scan and diff-audit also run every step in your session and start no agent, so a scan of the same tree costs about the same from one run to the next.

### What Quick reads

`/auditor:quick-scan` and `/auditor:diff-audit`, interactive and with `--ci`, take their reading from one file, [`references/depth-scope.md`](../references/depth-scope.md), never from judgment. Standard and Full do not use it: they take the whole scope table of `SKILL.md`.

1. **Domains.** Grep finds the domains in the code by their markers: on-chain (a `#[program]` or an `entrypoint!`, or `[programs.` in an `Anchor.toml`), backend, frontend, ai-agent, rust-service, python, keys, workflows, and devops, which every repository has. Tests, docs, vendored code and lockfiles select nothing.
2. **The selection, written first.** Before it reads any checklist section or vector file, the run writes what it will read to `audit_<n>/scope.md`: each domain with the marker and file that detected it, the checklist sections with their line ranges, the known-vector rows, and what it leaves out.
   - quick-scan takes each detected domain's sections (a gated section only when one of its markers occurs), the `always` vector rows of severity 7 or more of those domains, and the marker rows of severity 9 or more whose markers occur.
   - diff-audit takes the sections the kinds of file in the change select: on-chain source, backend or frontend code, a manifest or lockfile, a workflow, a key or `.env` file; a test, a doc or generated code alone selects nothing. Its vector rows are the marker rows at or above a floor of min(`--fail-on`, 7) − 1 whose markers occur in the changed files, and the `always` rows of the domains the changed files detect, a few repository-level rows aside, which it reads only when the change touches their subject.
3. **The reads.** Each section is read from its heading to the next, and each vector file whole. Before the report, the run checks its reads against `scope.md`; a listed file left unread is an early stop (`stopped: corpus-pass`), which fails a CI verdict.
4. **diff-audit's budgets.** It reviews at most 5,000 changed lines, not counting tests, docs, generated code and lockfiles, riskiest first: on-chain source, then files that remove security code, then the auth, crypto and value-transfer files, then the rest by size, each file whole or not at all. Above 5,000 it counts the rest in the report and gives its verdict on what it reviewed; `--over-budget fail` stops the review instead (`stopped: line-budget`). A changed lockfile gets checklist 11 §11.11's CI budget: `lock-delta.sh set` finds the new name@version set, and `deps.sh lock-budget` checks publish ages (`AUDITOR_PUBLISH_AGE`, on by default, which sends the name of each package in the set to its public registry) and compares the published code of every key-handling package and at most 40 others.

What the selection leaves out is outside that depth's declared scope (`OUTPUT-RULES.md` Rules 0 and 4). The report's Coverage & Limitations gives one line for each checklist and vector group left out, and `/auditor:audit` gives their verdicts.

### The Quick reports

Each Quick command writes its report in its run directory, from `templates/pr-report.md`: diff-audit `PR-REPORT.md`, quick-scan `QUICK-SCAN.md`, deep-review `DEEP-REVIEW-<unit>.md`. Each opens with a summary block:

- the verdict, pass or fail at the `--fail-on` threshold (7 when not given); deep-review gives none, since it is not a gate;
- the highest severity, and the findings by severity;
- what was reviewed, and the analyzers that ran and those that did not;
- preflight's mode line.

Then come the command, the pinned commits and the Generated line that `rundir.sh stamp` prints, the findings (each of severity 4 or more with the full block of `OUTPUT-RULES.md` Rule 5, each of 6 or more with the Rule 5b blocks), the verdicts, diff-audit's Dependency delta, and Coverage & Limitations: preflight's notes, the analyzers that did not run, what the depth left out, diff-audit's count of the changed lines it did not review, and the corpus sections and vector files the run read. With `--ci`, the same verdict and findings also go to `audit_<n>/findings.json`.

## Standard

### `/auditor:audit`

Runs the audit end-to-end in the current session: discover → scope-gate → spawn `context-builder`, then `vuln-hunter` for the item-by-item walk, `economic-analyst` for checklist 06 + economic vectors, `audit-reporter` for assembly. Every in-scope item gets a verdict; N≥6 findings pass Rule 5b or downgrade. Emits `audit_<n>/REPORT.md` with the internal template (numeric Repository Risk Score).

```
/auditor:audit ./programs/vault --scope program
```

Use it for a module or program that was never reviewed as a whole, before it merges: every in-scope item is checked once, and you handle triage yourself. A pull request is still Quick. `--scope` picks the part of the repository; [SKILL.md](../SKILL.md#scope-gated-loading--load-what-the-repo-needs) defines each scope.

## Full

The two Full flows and the fix review run the **same lifecycle** over the same corpus. The difference is autonomy: `audit-cycle` runs it to completion, `audit-assist` pauses for you, `re-audit` runs the delta subset.

### The lifecycle (shared spine)

Both `/auditor:audit-cycle` and `/auditor:audit-assist` execute this pipeline. It follows a firm engagement ([`references/audit-lifecycle/methodology.md`](../references/audit-lifecycle/methodology.md)).

```
intake / scope     → declare scope (Rule 0), pin the commit, persist audit_<n>/intake.md
   ↓
context (Phase 0.5)→ context-builder reconstructs invariants/assumptions per function (no verdicts)
   ↓
threat model       → threat-modeler emits assets · actor×capability · trust boundaries · AG-n goals (no verdicts); history-seeded by the bundled collector when a trigger fires
   ↓
tool-assisted pass → sast.sh semgrep (SARIF), clippy, cargo-audit, cargo-outdated through the runners, up-front to clear the mechanical surface; ToB static-analysis adds engines; else grep
   ↓
domain-partitioned → vuln-hunter (checklists + vectors) ∥ economic-analyst (checklist 06 + value flow)
   review              over DISJOINT surfaces — not N identical clones; each self-triages at the leaf
   ↓
triage             → /auditor:triage: de-dup by root cause, re-apply Rule 5b, split findings vs Notes & Nitpicks
   ↓
peer review        → peer-reviewer re-derives top-severity survivors FROM THE CODE (CONFIRM/DISPUTE/DOWNGRADE)
   ↓
synthesis          → audit-reporter dedups, orders by severity/importance, fills the client report
   ↓
deliver            → audit_<n>/REPORT.md (+ optional PDF, + harnesses/, + poc/ & patches/ with --with-poc)
```

Two disciplines run through the whole spine:

- **Design pass before implementation pass.** The economic architecture, oracle-manipulation surface, and state machines are reviewed *first* (a broken incentive on clean code is a finding in its own right), then the line-by-line checklist walk is aimed at the surfaces the design pass flagged.
- **The Rule 5b validation gate at the leaf.** Every finding with severity ≥ 6 must prove reachability + math/state-bounds (+ attacker-model at ≥ 7) before it is emitted, or it is downgraded to `[PARTIAL]` / `[UNCONFIRMED]`. This is the primary defense against AI over-reporting. See [output-and-rigor.md](output-and-rigor.md#the-rule-5b-validation-gate).

Agent roles and model tiers: [agents.md](agents.md).

### Flow A — `/auditor:audit-cycle` (automated)

The fully automated audit team. Runs the whole lifecycle above with **no human in the loop** — where a firm would ask the client, it applies the `QUESTIONS.md` defaults and records each assumption in the report's **Assumptions & Simplifications** section.

```
/auditor:audit-cycle --scope full
/auditor:audit-cycle --scope program --with-poc   # + executable PoCs & patches for confirmed N≥7
```

Delivers the **client-facing** report (`templates/audit-report.md`): executive summary, commit-pinned scope, findings with PoC/reachability, a code-maturity narrative, trust-model caveats, disclaimers — and, like a real firm, **no "safe to deploy" guarantee**. Optional PDF via `<auditor-skill root>/scripts/report-to-pdf.sh`, when pandoc 2.15 or later and a TeX engine are installed; the Markdown is always the deliverable. Generated fuzz/FV harnesses ship to `audit_<n>/harnesses/` with a coverage-gaps note; with `--with-poc`, PoCs land in `audit_<n>/poc/` and patches in `audit_<n>/patches/`.

Use it when you want a reproducible, hands-off first-pass audit and a deliverable document.

### Flow B — `/auditor:audit-assist` (interactive)

The same lifecycle, but it **stops at checkpoints** and lets you steer. At each checkpoint it surfaces:

- **(a)** confirmed findings so far (severity-ordered, already through Rule 5b);
- **(b)** the next-focus plan (which surfaces/vectors are queued and why);
- **(c)** targeted questions only a human can answer — business context, the intended trust model, whether a flagged behavior is intentional, severity calls that depend on off-chain assumptions.

Checkpoints land after scope, after context, after each review phase, after triage, and after reconciliation. Your answers fold back in and each trust-model answer is logged as a stated assumption in the report. After each answer the flow resumes through the Skill tool (`auditor:audit-assist --resume <checkpoint> audit_<n>`), which gives the new turn its pre-approvals back; Manual mode asks about that call unless your user settings allow it ([Turns and resuming](permissions-and-isolation.md#turns-and-resuming)).

```
/auditor:audit-assist --scope full
```

Use it when domain judgment matters — the agent does the mechanical review, you resolve the "is this intended?" calls. After the team changes code, do not re-run this — use `/auditor:re-audit`.

### Fix-review / re-audit

`/auditor:re-audit` takes a prior `audit_<n>/REPORT.md` + the current tree and classifies every prior finding: **FIXED** / **PARTIALLY-FIXED** / **STILL-OPEN** / **REGRESSED** / **ACKNOWLEDGED** / **DISPUTED**. It re-runs Rule 5b on each claimed fix (a cosmetic patch is not FIXED), cites the remediation commit/PR hash, audits the changed surface for NEW findings via the diff-audit path, and runs a **sibling-patch-propagation sweep** — grep the codebase for the same anti-pattern the fix closed, so a fix applied to one call site but not its twins is caught. Where a finding has a PoC, it re-runs it against the head build and records the result per finding (`PoC re-run @ <sha>: reverts | still succeeds | inconclusive | not run`); a FIXED status with no executed revert is flagged, not downgraded. Emits `audit_<n+1>/RE-AUDIT.md`.

```
/auditor:re-audit audit_1/REPORT.md main..HEAD
```

Verification-verb discipline: a client's "we fixed it" is never silently promoted to FIXED — an unverified client fix is at most PARTIALLY-FIXED-pending-verification. See [commands.md](commands.md#auditorre-audit).

## CI

CI runs Quick on pull requests from your own branches, with nobody at the keyboard, and the bundled analyzers on every pull request. Copy `templates/ci/auditor-pr.yml` to `.github/workflows/` and follow [ci.md](ci.md). It runs two jobs:

- **tools**, on every pull request, forks included: the bundled analyzers (semgrep, `cargo audit`, `npm audit`), with no model and no secrets.
- **review**, on pull requests from your repository's own branches, other than Dependabot's: `/auditor:diff-audit --ci` on the pull request's changes, in strict mode, with nothing from the pull request built or run.

`--ci` on `/auditor:diff-audit` and `/auditor:quick-scan` asks nothing, writes `audit_<n>/findings.json`, and ends with one line, `auditor: verdict: pass|fail (threshold N, analyzers run: …)`. The verdict is fail when a finding of severity N or more counts (`--fail-on <N>`, 7 when not given; `[UNCONFIRMED]` and `[PARTIAL]` findings do not count), when an analyzer the run called for did not run, or when the run stopped early ([What the verdict means](ci.md#what-the-verdict-means)). On a public repository the job publishes that line and notes about the tools only, never a finding or a count: the details stay on the runner, you read them by running the same command in a clone of your own, and the job never fails only because no private channel exists (`OUTPUT-RULES.md` Rule 11d; [Public repositories](ci.md#public-repositories)). For a scheduled scan of the default branch, run `/auditor:quick-scan --ci`. Give `claude -p` a `--max-budget-usd` of $15 for quick-scan and diff-audit alike: Claude Code shows the session its budget, and a cap close to a full pass's cost makes it stop reading early ([docs/costs.md](costs.md#cost-and-time-by-depth)).

## Outside the depths

### `/auditor:spec-audit`

Code-vs-spec. Extracts a requirement list from a spec/whitepaper/RFC, then builds a Compliance Matrix mapping each requirement to `[MET]` / `[VIOLATED-N]` / `[UNIMPLEMENTED]` / `[UNDOCUMENTED-BEHAVIOR]`, cited to code. Code that does something the spec never authorizes is itself a finding.

```
/auditor:spec-audit ./SPEC.md ./programs/vault
```

The per-finding commands (`poc`, `patch`, `economic-sim`, `triage`), Full's building blocks (`intake`, `threat-model`) and `audit-report`, which assembles the internal report from a walk run in pieces, can run on their own: [commands.md](commands.md).
