# Command Reference

All 17 commands, grouped by phase, for anyone looking up what a command takes and what it writes. Namespace is `auditor` → invoke as `/auditor:<name>`. Back to the [docs index](README.md).

Each entry lists the argument hint from the command's own frontmatter, when to reach for it, and what it emits. Which command runs at which depth (Quick, Standard, Full, CI): [Pick a depth](audit-flows.md#pick-a-depth). For how they compose into a full engagement, see [audit-flows.md](audit-flows.md).

What every command shares:

- **Preflight first.** Each command starts with `preflight.sh`, which in default mode notes what strict mode would refuse and in strict mode refuses it ([OUTPUT-RULES.md Rule 11f](../OUTPUT-RULES.md#11f--default-and-strict-mode)).
- **`--strict`.** In a command's arguments it turns strict mode on. A command that reuses a run directory writes the `strict` file into it, and a resumed command keeps the flag.
- **Pre-approved steps.** Each pre-approves, in its `allowed-tools`, the bundled steps it runs: run directories, read-only git, the Rust tools, the runners and the collectors, each checking its own arguments. Everything else asks, and a non-interactive run denies it and records the step as not run.
- **Resuming.** A command that goes on after your reply invokes itself again through the Skill tool (`--resume`), which Manual mode asks about unless your user settings allow it.

What runs without asking, and why that is safe: [permissions-and-isolation.md](permissions-and-isolation.md).

| Phase | Commands |
|-------|----------|
| Scoping | [`intake`](#auditorintake) · [`threat-model`](#auditorthreat-model) |
| Review | [`audit`](#auditoraudit) · [`quick-scan`](#auditorquick-scan) · [`deep-review`](#auditordeep-review) · [`diff-audit`](#auditordiff-audit) · [`spec-audit`](#auditorspec-audit) · [`audit-cycle`](#auditoraudit-cycle) · [`audit-assist`](#auditoraudit-assist) |
| Validation | [`triage`](#auditortriage) · [`economic-sim`](#auditoreconomic-sim) · [`poc`](#auditorpoc) · [`patch`](#auditorpatch) |
| Reporting | [`audit-report`](#auditoraudit-report) |
| Fix-review | [`re-audit`](#auditorre-audit) |
| Detection & response | [`hunt`](#auditorhunt) · [`respond`](#auditorrespond) |
| Skills that are not commands | [`auditor:auditor-skill`](#auditorauditor-skill) · [`auditor:dnr-analyze`](#auditordnr-analyze) |

---

## Scoping

### `/auditor:intake`
**Arg:** `[path] [--auto] [--strict]`
Turns the passive `QUESTIONS.md` questionnaire into a persisted `audit_<n>/intake.md` — the durable intake artifact both `/auditor:audit-cycle` and `/auditor:audit-assist` read. Pins the commit (`git-ro.sh rev-parse HEAD`), pre-fills languages/framework/monorepo shape from what the code shows, warms from prior audits via `audit-mem warm` if the tools are built, and captures scope, protocol class, compliance, severity calibration, and the trust-model inputs (who holds admin / upgrade authority / oracle / keeper / LP, and what the review trusts them NOT to do). It records where your code lives in the Layout table of `intake.md` §1 (`Q39`, `Q44`): an interactive intake shows the table an earlier run in the same checkout recorded and reuses it only on your yes, and `--auto` never reuses one.
**When:** inside a Full run, which invokes it (`--auto` from `audit-cycle`, interactively from `audit-assist`), or alone before one; Quick and Standard need no intake. **Emits:** `audit_<n>/intake.md`.
`--auto` records the applied default for every unanswered question (no-human pipelines); interactive mode asks sharp, answerable questions and skips what the repo already answers. It also asks once for the execution mode (`Q46`: native, the default / isolated / untrusted source, which turns on strict mode / none — `OUTPUT-RULES.md` Rules 11a and 11f) and writes it to `audit_<n>/exec-mode`, where the runners read it (the stricter of it, `AUDITOR_EXEC_MODE` and strict mode). Nothing asks it again later; `--auto` records native as an assumed default, and the report states it. Then it asks whether DEP-072 / DEP-073 may probe the project's own live hosts and buckets (`Q47`: read-only and unauthenticated, never a third-party service); `--auto`, like an unanswered Q47, records no, and those items give the owner a command to run instead.

### `/auditor:threat-model`
**Arg:** `[path] [--auto] [--bootstrap] [--vulns <file|https-url>] [--seed <threat-model.md>] [--design-doc <file>] [--parent <https-url|path>] [--strict]`
Builds the pre-review threat model *before* verdicts (analogous to how context reconstruction precedes verdicts): an asset inventory (crown-jewel funds/authority/data and where they live), an actor × capability table (each actor → what it can do → what it must NOT be able to do — the column the later phases test), and a trust-boundary map (every CPI, caller-supplied account, instruction arg, `remaining_accounts`, sysvar that crosses into higher trust, with whether it is validated). Ends with attacker goals to test (`AG-n`, each with an Evidence cell), mapped to the checklists/vectors that hunt them.
**When:** after intake + context, before the manual review. **Emits:** `audit_<n>/threat-model.md` (seeds report §4.4/§4.6/§4.7), plus `audit_<n>/bootstrap/` in bootstrap mode.
No verdicts, no severities — target enumeration only. `--auto` drives the `threat-modeler` agent; interactive asks the human. `--bootstrap` (also implied by `--vulns` / `--seed` / `--parent`, and auto-selected offline when intake records a prior audit or incident, a fork is detected, or prior audits / incidents sit next to the target) runs the bundled `<auditor-skill root>/scripts/threat-model/collect.sh` first (never a `scripts/` path relative to the audited repo): keyword commits, reverts, removed and quietly added account guards, churn, an optional fork-parent comparison, and prior audit reports (PDF/MD), post-mortems, lists and `INCIDENTS.json`. Network only for an `https://` URL the user passes in `--parent` / `--vulns`, even with `--auto`; automatic trigger runs stay offline and record a detected parent as not cloned. `--seed` takes a prior `threat-model.md` to re-verify and extend, and `--design-doc` a design document it reads directly. Interactively it drafts first, then interviews the team. Method: [threat-model-bootstrap.md](../references/audit-lifecycle/threat-model-bootstrap.md). Every claim cites `file:line` or its evidence; banned words → `UNKNOWN — needs manual review`.

---

## Review

### `/auditor:audit`
**Arg:** `[path] [--scope full|program|backend|frontend] [--strict]`
The Standard depth: a scope-gated, item-by-item audit end-to-end in one session. Reads `OUTPUT-RULES.md`, follows `FULL-AUDIT.md` with scope-gated loading, spawns `context-builder` → `vuln-hunter` → `economic-analyst` → `audit-reporter`. Every in-scope item + phase-triggered vector gets `[PASS]`/`[FAIL-N]`/`[PARTIAL]`/`[N/A]`; N≥6 findings pass Rule 5b or downgrade.
**When:** a module, a program or the whole repository, every in-scope item checked once, where you handle triage yourself. **Emits:** `audit_<n>/REPORT.md` (internal template, numeric risk score) with executive summary, Scope Coverage table, findings, Phase 4.5 maturity scorecard, remediation roadmap.
Runs SAST with `sast.sh` (semgrep) and the ToB tooling if present, else the grep scanners (noting the gap).

### `/auditor:quick-scan`
**Arg:** `[<path>] [--ci] [--fail-on <N>] [--strict]`
Fast triage: discovery + scope + static analysis (`sast.sh` semgrep with the rulesets in scope; ToB `static-analysis` when semgrep is missing and the plugins are present; else `discovery/grep-commands.md`) + dependency advisories (`deps.sh` cargo-audit and npm-audit) + the checklist sections and known-vector rows `references/depth-scope.md` selects for the detected domains, declared first in `audit_<n>/scope.md` — not the full checklist walk. Its scope is the path you pass, or else the whole repository; with more than two on-chain programs it scans the two largest and names a `/auditor:quick-scan <path>` for each of the others.
**When:** a first look at a whole repository (Quick), or a scheduled scan of the default branch with `--ci`. An analyzer that did not run is reported as not run, never counted as clean. **Emits:** `audit_<n>/QUICK-SCAN.md`, from `templates/pr-report.md` with its summary block first: findings with severity + `file:line`, stated as a triage pass that points to `/auditor:audit`. `--fail-on <N>` (1 to 10, default 7) sets the summary's verdict threshold. With `--ci` it asks nothing, also writes `audit_<n>/findings.json`, names only the report in its reply, and ends with the closing line `auditor: verdict: pass|fail (threshold N, analyzers run: …)`: fail when a counted finding reaches N, when an analyzer it called for did not run, or when the run stopped early. On a public repository, CI publishes that line and notes about the tools only, never a finding or a count, and the details stay on the runner (Rule 11d). Detail: [ci.md](ci.md#what-the-verdict-means).

### `/auditor:deep-review`
**Arg:** `<file> [function|instruction] [--strict]`
Deep single-unit review: read the file, run Phase 0.5 context reconstruction on the target (purpose, inputs, ≥3 invariants, ≥5 assumptions, ≥3 external-interaction risks, each cited to `L#`), fill the instruction worksheet, cross-reference shared-state code, adversarially model exploitation.
**When:** one handler/endpoint/function needs depth (Quick). **Emits:** `audit_<n>/DEEP-REVIEW-<unit>.md`, from `templates/pr-report.md`, and the worksheets: per-item verdicts + findings for that unit only, in the report and in the reply. `<unit>` is the function or instruction name, else the file's name without its extension. N≥6 findings pass Rule 5b.

### `/auditor:diff-audit`
**Arg:** `[base..head] [--ci] [--fail-on <N>] [--over-budget fail] [--strict]`
Differential audit (Mode 4). Changed set via read-only git, `git-ro.sh diff --name-only base..head` (default `main..HEAD`); Phase 0.5 on changed functions + 1-hop callers/callees; risk-classify (auth/crypto/value-transfer/validation-removal = HIGH); git-blame removed security code (deletion in a "fix"/"CVE" commit = CRITICAL regression); read the checklist sections and known-vector rows `references/depth-scope.md` selects for the kinds of file the change holds, declared first in `audit_<n>/scope.md`, and give their findings through Rule 5b. When a manifest or lockfile changed, a dependency lane runs checklist 11 §11.11's CI budget (`lock-delta.sh set` for the new versions, then `deps.sh lock-budget` for their publish ages and the published code of every key-handling package and at most 40 others) and adds a Dependency delta section. It reviews at most 5,000 changed lines, riskiest first, and counts the rest; `--over-budget fail` fails the review instead.
**When:** a branch, a PR or another commit range, not the whole tree (Quick); in CI, the review job of `templates/ci/auditor-pr.yml` runs it with `--ci` on the pull request's two commits ([ci.md](ci.md)). It reviews commits: with no argument it compares the tip of `main` with HEAD, so rebase on `main` first. **Emits:** `audit_<n>/PR-REPORT.md`, from `templates/pr-report.md` with its summary block first — changed-surface verdicts only; skips whole-repo discovery. `--fail-on` and `--ci` work as for `quick-scan`, with `audit_<n>/findings.json` and the same closing line.

### `/auditor:spec-audit`
**Arg:** `<spec-file> [program-path] [--strict]`
Spec-compliance (Mode 5). Extract a requirement list (Spec-IR) from the spec; Phase 0 + Phase 0.5; map each instruction/state field to the spec's stated behavior; build a Compliance Matrix — each requirement → `[MET]` / `[VIOLATED-N]` / `[UNIMPLEMENTED]` / `[UNDOCUMENTED-BEHAVIOR]`, cited to code `L#`.
**When:** a spec / whitepaper / RFC is supplied. **Emits:** the Compliance Matrix + findings. `[VIOLATED-N≥6]` passes Rule 5b; `[UNDOCUMENTED-BEHAVIOR]` (code the spec never authorizes) is itself a finding.

### `/auditor:audit-cycle`
**Arg:** `[path] [--scope full|program|backend|frontend] [--strict]` (+ `--with-poc`)
**Flow A — fully automated audit team.** Runs the whole lifecycle autonomously (scope → context → threat model → tool-assisted pass → domain-partitioned review → triage → independent reconciliation → synthesis) with no human; applies `QUESTIONS.md` defaults and records each assumption.
**When:** hands-off engagement → deliverable. **Emits:** the client-facing `audit_<n>/REPORT.md` (maturity narrative + trust-model caveats + disclaimers, no deploy guarantee), optional PDF, `harnesses/` if any were generated, and — with `--with-poc` — `poc/` + `patches/` for confirmed N≥7. Full detail: [audit-flows.md](audit-flows.md#flow-a--auditoraudit-cycle-automated).

### `/auditor:audit-assist`
**Arg:** `[path] [--scope full|program|backend|frontend] [--strict]`
**Flow B — human-in-the-loop.** Same lifecycle as `audit-cycle`, but pauses at checkpoints (after scope, context, each review phase, triage, reconciliation) to surface (a) confirmed findings, (b) next-focus plan, (c) the targeted questions only a human can answer, then folds answers back in. After each answer it resumes through the Skill tool (`--resume <checkpoint>`), which Manual mode asks about unless your user settings allow it.
**When:** business-logic / trust-model judgment matters. **Emits:** the same client-facing report, converged iteratively. Detail: [audit-flows.md](audit-flows.md#flow-b--auditoraudit-assist-interactive).

---

## Validation

### `/auditor:triage`
**Arg:** `[audit_<n>] [--program-id <id>] [--strict]`
One consolidated, re-runnable triage checkpoint over the candidate finding set (so calibration is auditable in one place, not diffused across leaf reviewers). De-dups by root-cause signature (with `audit-mem check` auto-suppressing prior-ruled false positives and `audit-mem regressions` flagging FIXED→re-observed, when the tools are built), re-applies Rule 5b in batch (every N≥6 carries its validation block or is downgraded to `[UNCONFIRMED]`/`[UNDETERMINED]`, every downgrade quantified), and splits real findings (severity 1-10) from the Notes & Nitpicks list.
**When:** between the review phase and reconciliation; re-run after any new candidates. **Emits:** the triaged set + a suppression appendix recording what was withheld and why (idempotent — re-running folds in new candidates without re-litigating settled ones).

### `/auditor:economic-sim`
**Arg:** `<finding-or-instruction> [--strict]`
Quantifies a candidate economic finding: model capital/setup cost, extractable value, atomicity, flash-loanable ceilings per venue; compute whether profit > cost at 1/5/10% manipulation; if a Surfpool mainnet-fork is available, reproduce deposit→manipulate→withdraw against forked state for a real net P/L.
**When:** a High/Critical economic finding needs the dollar figure Rule 5b requires. **Emits:** the quantified PoC (dollar figures, not yes/no). See [power-tools.md](power-tools.md#surfpool-economic-simulation).

### `/auditor:poc`
**Arg:** `<finding-id | INC-n.k | file:line> [--fork] [--fuzz] [--force] [--strict]`
Turns a *confirmed* finding into a runnable exploit: resolve the finding + its context worksheet, gate on severity (N≥7 by default; `--force` overrides), detect the toolchain with `probe.sh` (never assume), pick the harness by finding type (Mollusk / LiteSVM / Surfpool `--fork` / Trident-cargo-fuzz `--fuzz`), spawn `poc-engineer` to fill a feature-gated `vulnerable`/`fixed` crate that asserts the flaw.
**When:** demonstrate a High/Critical finding executably. **Emits:** `audit_<n>/poc/F-xxx/` (the crate `run.sh --init` made, and the one command that reproduces it, the installation's `run.sh --crate audit_<n>/poc/F-xxx`) + the earned `[PoC-*]` tier. Never hard-fails — toolchain absence → `[PoC-ATTEMPTED]` + the prose PoC is kept. Full detail: [poc-and-patches.md](poc-and-patches.md).

### `/auditor:patch`
**Arg:** `<finding-id | INC-n.k> [--verify-with-mutation] [--post-patch-validation] [--strict]`
Drafts and verifies a fix: `patch-engineer` writes a minimal idiomatic unified diff against the pinned commit that closes *exactly* the cited bound (obeys the Rust/Anchor/Pinocchio rules), builds the program as it is and patched with `target.sh build-sbf`, in a scratch clone (never the client tree), and re-runs the finding's PoC against those builds — which must now revert. `--verify-with-mutation` adds `mewt` mutation + a blast-radius check. `--post-patch-validation` (opt-in) also runs Trail of Bits `post-patch-validation`, only in isolated mode and on a disposable clone; a finding in its result turns `[FIX-VERIFIED]` into `[FIX-INSUFFICIENT]`, or is recorded under Residual on any other tier, and nothing else in it changes a tier.
**When:** hand the client a proven fix. **Emits:** `audit_<n>/patches/F-xxx.patch` + `VERIFICATION.md` + the `[FIX-*]` tier. Proposal only — `[FIX-VERIFIED]` requires an *executed* revert; no PoC → `[FIX-PROPOSED]` ceiling. Detail: [poc-and-patches.md](poc-and-patches.md).

---

## Reporting

### `/auditor:audit-report`
**Arg:** `[audit-dir] [--strict]`
Aggregates the session's checkpoints and findings into the final report: de-dup + classify by severity, assemble from `templates/report-template.md` (executive summary with safe-to-deploy verdict, Scope Coverage table, per-checklist verdicts, findings, Phase 4.5 maturity scorecard, remediation roadmap CRITICAL→INFO).
**When:** you ran the walk in pieces and need the report assembled. **Emits:** `audit_<n>/REPORT.md`; flags any in-scope item lacking a verdict as `[INCOMPLETE — in-scope item without verdict]`. It assembles the report in your session: its steps spawn no agent and re-analyze no code.

---

## Fix-review

### `/auditor:re-audit`
**Arg:** `[prior-report] [base..head] [--strict]`
Fix-review / re-audit against a prior `audit_<n>/REPORT.md` (arg 1) and the current tree (delta `base..head`, default `main..HEAD`). Classifies every prior finding FIXED / PARTIALLY-FIXED / STILL-OPEN / REGRESSED / ACKNOWLEDGED / DISPUTED — each non-open status citing the remediation commit/PR hash, and re-running Rule 5b on the fix (a cosmetic/incomplete patch is not FIXED). Then audits the changed surface for NEW findings (diff-audit path) and runs a sibling-patch-propagation sweep for un-patched twins of every fixed anti-pattern (the sweep always emits a result — "no siblings found" is a result in its own right). Its diff-audit pass includes the dependency lane, and differential execution (step 4b) builds each commit and runs the target's own tests through `target.sh`, in the intake execution mode (Rule 11a).
**When:** the team responded to findings and you verify. **Emits:** `audit_<n+1>/RE-AUDIT.md` (from `<auditor-skill root>/templates/re-audit.md`) — finding-diff table with each finding's step-4b PoC re-run (`reverts | still succeeds | inconclusive | not run`, a FIXED without an executed revert flagged) + new findings + sibling sweep + updated deploy verdict.
Verification-verb discipline: use "we re-tested and confirmed" only when *you* verified against the current tree; a client's "we fixed it" stays "client states fixed (unverified)" and is not FIXED until independently confirmed.

---

## Detection & response

Post-incident only — never part of an audit. Both commands are propose-only: they never sign, send, simulate against a public cluster, pause or freeze anything. They hand all reading and analysis of the incident corpus to the `incident-responder` agent, one phase at a time, through the `auditor:dnr-analyze` skill, which runs it as a fork and pre-approves only the offline analysis tools there; the agent's tool list has no MCP tools, and the commands themselves run in your session, where every connected MCP server stays callable, and call no MCP tool. Before a live incident, disconnect or deny write-capable MCP servers (for example, tools that transfer or stake). Contract: [`references/detection-response/README.md`](../references/detection-response/README.md); orientation: [detection-response.md](detection-response.md).

### `/auditor:hunt`
**Arg:** `[<address> ...] [--logs <dir>] [--repo <path>] [--window <fromUnix>..<toUnix>] [--collect] [--fresh] [--strict]`
Threat hunt with no alert to start from: checks the working tree with `preflight.sh`, snapshots the deployed programs, then baselines a Solana transaction corpus (your own `--logs` export first; otherwise a gated, capped RPC collection that runs only after you confirm the addresses, window and call budget — `--collect` stands in for that yes in non-interactive runs, where the snapshot and the collector are pre-approved and the `--logs` copy is refused), records each hypothesis and its query in a ledger, checks each suspect against the source deployed at the incident slot via `context-builder`, and reproduces it on the program's real bytes via `poc-engineer`. Driven by the `incident-responder` agent, through the `auditor:dnr-analyze` skill. `--window <fromUnix>..<toUnix>` bounds the collection by block time, `--repo` names the source to check suspects against (without it, findings stay `suspected`), and `--fresh` makes a new `incident_<n>/` instead of offering an existing one for reuse.
**When:** you suspect an attack but have no specific lead. **Emits:** `incident_<n>/LEDGER.md`, `INCIDENTS.json`, `INCIDENT_REPORT.md` and the program snapshot under `bin/` (the run directory's first file is a `.gitignore` of `*`). Verdicts follow the [one normative ladder](../references/detection-response/README.md#the-verdict-ladder-the-one-normative-copy).

### `/auditor:respond`
**Arg:** `<INC-n.k | signature | address | 'alert json' | 'free text'> [--logs <dir>] [--repo <path>] [--collect] [--fresh] [--strict]`
Takes one lead — a transaction signature, an address, an alert, an indicator of compromise, or an `INC-<n>.<k>` from a hunt — and widens it by one ring of related accounts and signers; it then settles whether the attack landed, sizes the damage per mint, pins the root cause in the deployed source, reproduces it locally on the real bytes, and drafts containment, remediation and recovery steps for people to carry out. `--logs`, `--repo`, `--collect` and `--fresh` work as for `hunt`; an `INC-<n>.<k>` lead works in the hunt's own `incident_<n>/`.
**When:** an alert fired or funds are known to be gone — after the pause/freeze runbook and a SEAL 911 ticket, never instead of them. **Emits:** the enriched `incident_<n>/INCIDENTS.json` and `RESPONSE-INC-<n>.<k>.md` — a proposed plan that people approve and carry out; the command performs none of it.

---

## Skills that are not commands

### `auditor:auditor-skill`
The root skill, `SKILL.md`. A request in plain words, such as "audit this repo with the auditor-skill", runs it: it runs `preflight.sh` first, as the commands do, and pre-approves the steps `/auditor:audit` runs ([What runs without asking](permissions-and-isolation.md#what-runs-without-asking)). In the plugin it is `auditor:auditor-skill`; with the install script or a clone under `~/.claude/skills/` it is your personal skill `auditor-skill`. It resumes through the Skill tool as the commands do, so give it the rules in [Turns and resuming](permissions-and-isolation.md#turns-and-resuming).

### `auditor:dnr-analyze`
One analysis phase of `/auditor:hunt` or `/auditor:respond`, run as a fork in the `incident-responder` agent over `incident_<n>/` only. It is not for you to invoke: the two commands call it with a phase brief, and its `allowed-tools` pre-approve the offline analysis tools there (`profile.sh`, `frames.py`, `deltas.py`, `jq-ro.sh` and `audit-logs`). Its rule, `Skill(auditor:dnr-analyze *)`, is among the resume rules. Detail: [detection-response.md](detection-response.md).
