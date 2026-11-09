# Audit Flows

Which depth to run, and the pipeline each one follows. Back to the [docs index](README.md).

## Pick a depth

auditor-skill has three depths and a CI mode. Pick by what you want checked: what changed, one module, or the release.

| Depth | When | Run | Reads | Writes | [Cost](../COSTS.md#cost-and-time-by-depth) |
|-------|------|-----|-------|--------|------|
| **Quick** | a branch or pull request, a first look at a repository, one function | `/auditor:diff-audit` · `/auditor:quick-scan` (whole repository) · `/auditor:deep-review <file> <fn>` | the changed code + one hop of callers and callees · SAST, dependency advisories and the severity 7+ known vectors · one function | `PR-REPORT.md` · `QUICK-SCAN.md` · `DEEP-REVIEW-<unit>.md` | $2–7 · 4–16 min |
| **Standard** | one module or program before it merges | `/auditor:audit <path> --scope …` | every in-scope item for that path | `REPORT.md`, internal: a risk score and a deploy verdict | $13–19 · 35–60 min |
| **Full** | a release, or a report for someone outside the team | `/auditor:audit-cycle` (unattended) · `/auditor:audit-assist` (you steer) · `/auditor:re-audit` after fixes | everything in scope, a threat model, peer review (re-audit: the fix delta) | `REPORT.md`, client style: no deploy guarantee (audit-cycle adds a PDF, and PoCs with `--with-poc`) · `RE-AUDIT.md`, with an updated deploy verdict | about $20 · about 1 h, on a 3K-line program |
| **[CI](ci.md)** | every pull request | `templates/ci/auditor-pr.yml`: a tools job, then `/auditor:diff-audit --ci` | as Quick | `findings.json` and SARIF on the runner, one pass/fail line in the log | tools job $0; review $2–3 a pull request |

Costs and times were measured on 2026-11-08 with `claude-opus-5-5`, on 3K-, 7K- and 12K-line programs; Full ran once, on the 3K-line one ([COSTS.md](../COSTS.md#cost-and-time-by-depth)). Outside the depths: `poc`, `patch`, `economic-sim` and `triage` work on one finding; `intake` and `threat-model` are Full's building blocks; `audit-report` assembles the internal report from a walk run in pieces; `spec-audit` checks code against a spec; `hunt` and `respond` are for after an incident ([detection-response.md](detection-response.md)).

Every flow first runs `preflight.sh` on the working tree. Its first line names the mode: in default mode it notes what it finds and the flow goes on; in strict mode, for a repository you do not trust, it refuses project config and the rest [Rule 11f](../OUTPUT-RULES.md#11f--default-and-strict-mode) lists. Then the flow runs its bundled steps without asking: run directories, read-only git, the Rust tools, and the runners that build and test in the execution mode in force, native unless intake, `AUDITOR_EXEC_MODE` or strict mode says otherwise. What still asks, and how to run in strict mode, isolated or in `claude -p`: [permissions-and-isolation.md](permissions-and-isolation.md).

## Quick

These skip the item-by-item checklist walk.

### `/auditor:diff-audit`

PR / commit-scoped. Computes the changed set with read-only git (`git-ro.sh diff --name-only base..head`, default `main..HEAD`), runs Phase 0.5 on changed functions + 1-hop callers/callees, risk-classifies changed files (auth / crypto / value-transfer / validation-removal = HIGH), git-blames removed security code (a deletion in a "fix"/"CVE" commit is a CRITICAL regression), runs only the checklist items and known vectors that match the changed files' language and domain, through Rule 5b, and adds a dependency lane (checklist 11 §11.11 — the published code delta of each bumped package) when a manifest or lockfile changed. Emits `audit_<n>/PR-REPORT.md`. It reviews commits, so commit your work first. With no argument it compares the tip of `main` with HEAD, so rebase on `main` first, or changes `main` gained since you branched show up in the review. In CI, the workflow passes the pull request's range.

```
/auditor:diff-audit                 # main..HEAD
/auditor:diff-audit v1.2.0..HEAD
```

### `/auditor:quick-scan`

A first look at a whole repository: discovery and scope, static analysis of every in-scope directory (`sast.sh` semgrep; ToB `static-analysis` when semgrep is missing and the plugins are present; else grep scanners), dependency advisories (`deps.sh` cargo-audit and npm-audit), and the high-severity vector pass: the CRITICAL and HIGH known vectors (severity 7 or more) for the detected domains, leaving out those whose markers never occur. Writes `audit_<n>/QUICK-SCAN.md`: findings with severity + `file:line`, stated plainly as a triage pass that points to `/auditor:audit` for full coverage. An analyzer that did not run is reported as not run, never counted as clean. It scans the whole repository each time, so for each pull request diff-audit is the smaller run.

### `/auditor:deep-review`

One instruction / function, deeply. Reads the file, runs Phase 0.5 context reconstruction on the target, fills the instruction worksheet, adversarially models exploitation, and writes the verdicts for that unit only to `audit_<n>/DEEP-REVIEW-<unit>.md`.

```
/auditor:deep-review programs/vault/src/instructions/withdraw.rs withdraw
```

Quick costs less than a full walk because it reads less: diff-audit what changed and one hop around it, quick-scan no checklists, deep-review one unit.

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

Both `/auditor:audit-cycle` and `/auditor:audit-assist` execute this pipeline. It mirrors a professional firm engagement, run by mechanisms the skill already has ([`references/audit-lifecycle/methodology.md`](../references/audit-lifecycle/methodology.md)).

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
triage             → /triage: de-dup by root cause, re-apply Rule 5b, split findings vs Notes & Nitpicks
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

Delivers the **client-facing** report (`templates/audit-report.md`): executive summary, commit-pinned scope, findings with PoC/reachability, a code-maturity narrative, trust-model caveats, disclaimers — and, like a real firm, **no "safe to deploy" guarantee**. Optional PDF via `<auditor-skill root>/scripts/report-to-pdf.sh` (pandoc-gated; Markdown is always the deliverable). Generated fuzz/FV harnesses ship to `audit_<n>/harnesses/` with a coverage-gaps note; with `--with-poc`, PoCs land in `audit_<n>/poc/` and patches in `audit_<n>/patches/`.

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

CI runs Quick on every pull request, with nobody at the keyboard. Copy `templates/ci/auditor-pr.yml` to `.github/workflows/` and follow [ci.md](ci.md). It runs two jobs:

- **tools**, on every pull request, forks included: the bundled analyzers (semgrep, `cargo audit`, `npm audit`), with no model and no secrets.
- **review**, on pull requests from your repository's own branches, other than Dependabot's: `/auditor:diff-audit --ci` on the pull request's changes, in strict mode, with nothing from the pull request built or run.

`--ci` on `/auditor:diff-audit` and `/auditor:quick-scan` asks nothing, writes `audit_<n>/findings.json`, and ends with one line, `auditor: verdict: pass|fail (threshold N, analyzers run: …)`. The verdict is fail when a finding of severity N or more counts (`--fail-on <N>`, 7 when not given; `[UNCONFIRMED]` and `[PARTIAL]` findings do not count), when an analyzer the run called for did not run, or when the run stopped early ([What the verdict means](ci.md#what-the-verdict-means)). On a public repository the job publishes that line only: the details stay on the runner, you read them by running the same command in a clone of your own, and the job never fails only because no private channel exists (`OUTPUT-RULES.md` Rule 11d; [Public repositories](ci.md#public-repositories)). For a scheduled scan of the default branch, run `/auditor:quick-scan --ci`. Give `claude -p` a `--max-budget-usd` of $10 for quick-scan and at least $5 for diff-audit: Claude Code shows the session its budget, and a cap close to a full pass's cost makes it stop reading early ([COSTS.md](../COSTS.md#cost-and-time-by-depth)).

## Outside the depths

### `/auditor:spec-audit`

Code-vs-spec. Extracts a requirement list from a spec/whitepaper/RFC, then builds a Compliance Matrix mapping each requirement to `[MET]` / `[VIOLATED-N]` / `[UNIMPLEMENTED]` / `[UNDOCUMENTED-BEHAVIOR]`, cited to code. Code that does something the spec never authorizes is itself a finding.

```
/auditor:spec-audit ./SPEC.md ./programs/vault
```

The per-finding commands (`poc`, `patch`, `economic-sim`, `triage`), Full's building blocks (`intake`, `threat-model`) and `audit-report`, which assembles the internal report from a walk run in pieces, can run on their own: [commands.md](commands.md).
