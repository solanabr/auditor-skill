# auditor-skill — Documentation

Usage guides for `auditor-skill`, an open-source AI security-audit skill for Solana programs and full-stack code. New here: start with [getting-started.md](getting-started.md), then [Pick a depth](#pick-a-depth). Looking for one thing: [I want to…](#i-want-to--use-this) or [The guides](#the-guides).

## What is auditor-skill

A folder of markdown checklists, slash commands, and subagents — plus three small Rust tools — that turns an LLM agent into a security auditor. It discovers a repo, declares a scope, loads only the checklists that scope needs, walks the code file by file, and emits a severity-ranked report where **every in-scope item carries an explicit verdict**. Corpus: 20 checklists / 1,465 items / 141 known attack vectors, 13 protocol methodologies, framework idioms, and a validation gate that forces high-severity findings to prove reachability before they count. It is a rigorous first pass, not a replacement for a human firm audit.

Commands are namespaced `auditor`, so you invoke them as `/auditor:audit`, `/auditor:audit-cycle`, etc.

### What the corpus covers

- **Checklists** (`checklists/`): seven for on-chain programs (account validation, access control, arithmetic, CPI and PDAs, state machines, economic logic, operations and governance), then TypeScript, backend, frontend, supply chain, secrets, deployment and CI, Python, other languages, formal verification and testing, logging and incident readiness, privacy and change management, AI and agent components, and off-chain Rust services. The scope table in [SKILL.md](../SKILL.md#scope-gated-loading--load-what-the-repo-needs) says which ones a repository gets.
- **Known attack vectors** (`known-vectors/INDEX.md`), each with a verification procedure. Among them: vendored or white-label program drift (KV-137), a slot used as a clock after SIMD-0525 and Alpenglow (KV-138), comment-triggered workflows and pwn requests in CI (KV-139, KV-140), and the host kernel and network of Internet-facing nodes (KV-141).
- **Protocol methodologies** (`references/methodologies/`): AMM/CLMM, lending, perps, oracles, stablecoins, liquid staking, governance, bridges, multisig and custody, Token-2022, NFT marketplaces, launchpads, and token registries.
- **Vulnerability-class playbooks** (`references/vuln-classes/`): GitHub Actions trigger trust, Transaction v1 (SIMD-0385), the host kernel and network attack surface, and ZK and compression.
- **Framework idioms** (`references/framework-idioms/`): Anchor, native, Pinocchio, and build and tooling.

What each release added: [changelog.md](changelog.md).

## Pick a depth

| Depth | When | Run | Reads | Writes | [Cost](../COSTS.md#cost-and-time-by-depth) |
|-------|------|-----|-------|--------|------|
| **Quick** | a branch or pull request, a first look at a repository, one function | `/auditor:diff-audit` · `/auditor:quick-scan` (whole repository) · `/auditor:deep-review <file> <fn>` | the changed code + one hop, read against the sections and vectors `references/depth-scope.md` selects · SAST, dependency advisories, and the sections and vectors `references/depth-scope.md` selects · one function | `PR-REPORT.md` · `QUICK-SCAN.md` · `DEEP-REVIEW-<unit>.md` | $2–8 · 4–23 min |
| **Standard** | one module or program before it merges | `/auditor:audit <path> --scope …` | every in-scope item for that path | `REPORT.md`, internal: a risk score and a deploy verdict | $13–19 · 36–56 min |
| **Full** | a release, or a report for someone outside the team | `/auditor:audit-cycle` (unattended) · `/auditor:audit-assist` (you steer) · `/auditor:re-audit` after fixes | everything in scope, a threat model, peer review (re-audit: the fix delta) | `REPORT.md`, client style: no deploy guarantee (audit-cycle adds a PDF when pandoc and a LaTeX engine are installed, and PoCs with `--with-poc`) · `RE-AUDIT.md`, with an updated deploy verdict | about $20 · about 1 h, on a 3K-line program |
| **[CI](ci.md)** | every pull request: the analyzers on all, the review on your own branches' only | `templates/ci/auditor-pr.yml`: a tools job, then `/auditor:diff-audit --ci` | as Quick | `findings.json` and SARIF on the runner; in the log, pass/fail and notes about the tools, never a finding or a count | tools job $0; review about a diff-audit's cost ($2–8), capped at $15 |

Costs and times were measured from 2026-11-08 to 2026-11-10 with `claude-opus-5-5`, on 3K-, 7K- and 12K-line programs. Quick's range covers diff-audit runs of $1.68–8.10 and quick-scan runs of $2.84–7.14. The shipped command text was measured on the 3K-line repository, where a quick-scan cost $6.98 in 23 minutes and a diff-audit of a 7,830-line range, a lockfile change included, $8.10 in 19 minutes, and on the 12K-line program, where a diff-audit of a 1,248-line change with no lockfile cost $3.99 in 9 minutes. The other runs were on earlier drafts, and those under $3 read 16 to 55 vector files and at most one checklist. Full ran once, on the 3K-line program ([COSTS.md](../COSTS.md#cost-and-time-by-depth)). Outside the depths: `poc`, `patch`, `economic-sim` and `triage` work on one finding; `intake` and `threat-model` are Full's building blocks; `audit-report` assembles the internal report from a walk run in pieces; `spec-audit` checks code against a spec; `hunt` and `respond` are for after an incident. More on each depth: [audit-flows.md](audit-flows.md).

In CI, `--ci` on `/auditor:diff-audit` and `/auditor:quick-scan` asks nothing, writes `audit_<n>/findings.json` and ends with one verdict line. An analyzer that did not run fails the verdict, as does a counted finding at or above `--fail-on` (7 when not given). On a public repository the job publishes pass/fail only ([ci.md](ci.md)).

## I want to… → use this

| Goal | Use | Guide |
|------|-----|-------|
| Quick: what a branch or PR changes (its commits) | `/auditor:diff-audit [base..head]` | [commands.md](commands.md#auditordiff-audit) |
| Quick: a first look at a whole repo (no full checklist walk) | `/auditor:quick-scan` | [commands.md](commands.md#auditorquick-scan) |
| Quick: one instruction / function, deeply | `/auditor:deep-review <file> [fn]` | [commands.md](commands.md#auditordeep-review) |
| Know what a Quick run read, and what it left out | `audit_<n>/scope.md`, and the report's Coverage & Limitations | [audit-flows.md](audit-flows.md#what-quick-reads) |
| Standard: every in-scope item of a module, program or repo | `/auditor:audit [path] [--scope ...]` | [commands.md](commands.md#auditoraudit) |
| Full: unattended engagement → client report | `/auditor:audit-cycle` | [audit-flows.md](audit-flows.md#flow-a--auditoraudit-cycle-automated) |
| Full: you steer at checkpoints | `/auditor:audit-assist` | [audit-flows.md](audit-flows.md#flow-b--auditoraudit-assist-interactive) |
| Full: review a fix round against a prior report | `/auditor:re-audit [prior] [base..head]` | [commands.md](commands.md#auditorre-audit) |
| CI for pull requests | `templates/ci/auditor-pr.yml`: a tools job, then `/auditor:diff-audit --ci` | [ci.md](ci.md) |
| Code-vs-spec conformance | `/auditor:spec-audit <spec> [path]` | [commands.md](commands.md#auditorspec-audit) |
| Set up scope + trust model before a Full run | `/auditor:intake` | [commands.md](commands.md#auditorintake) |
| Enumerate assets / actors / trust boundaries | `/auditor:threat-model` | [commands.md](commands.md#auditorthreat-model) |
| Threat-model a fork or inherited codebase from its history | `/auditor:threat-model --bootstrap` | [commands.md](commands.md#auditorthreat-model) |
| Quantify an economic attack ($ P/L) | `/auditor:economic-sim <finding>` | [commands.md](commands.md#auditoreconomic-sim) |
| Consolidate + de-dup candidate findings | `/auditor:triage` | [commands.md](commands.md#auditortriage) |
| Build a runnable exploit for a finding | `/auditor:poc <finding-id>` | [poc-and-patches.md](poc-and-patches.md) |
| Draft + verify a fix patch | `/auditor:patch <finding-id>` | [poc-and-patches.md](poc-and-patches.md) |
| Assemble a report from checkpoints | `/auditor:audit-report [dir]` | [commands.md](commands.md#auditoraudit-report) |
| Find out whether we were attacked (no alert) | `/auditor:hunt [address…]` | [detection-response.md](detection-response.md) |
| Work an alert or a drained protocol: outcome, damage, next steps | `/auditor:respond <signature / address / INC-n.k>` | [detection-response.md](detection-response.md) |
| Cut audit token cost ~30-40% | build `audit-scan` | [power-tools.md](power-tools.md#audit-scan) |
| Remember findings across audits | build `audit-mem` | [power-tools.md](power-tools.md#audit-mem) |
| Check a repository's GitHub Actions workflows | `audit-scan`'s workflow pass, then pinned zizmor and CodeQL | [power-tools.md](power-tools.md#github-actions-workflow-analysis) |
| Look up a bundled script's arguments and exits | `scripts/…` | [power-tools.md](power-tools.md#bundled-scripts) |
| Run with fewer prompts, in strict mode for code you don't trust, isolated, or in `claude -p` | the user-settings rules, `templates/strict-settings.json`, `AUDITOR_STRICT`, `AUDITOR_EXEC_MODE` | [permissions-and-isolation.md](permissions-and-isolation.md) |

## The guides

**Start**

- **[getting-started.md](getting-started.md)** — the four ways to install, the rules that let a flow resume without a prompt, the Trail of Bits submodule, the three Rust tools, adapting to your repo, your first audit at each depth, and prompts and isolation.
- **[faq.md](faq.md)** — answers to the common questions.
- **[other-agents.md](other-agents.md)** — using the skill from Cursor, Windsurf, Copilot, Codex or an API, with no plugin commands.

**Run an audit**

- **[audit-flows.md](audit-flows.md)** — the three depths and CI, and the pipeline each one follows: Quick, with what it reads and what its reports hold, Standard, the Full lifecycle and the fix review.
- **[commands.md](commands.md)** — reference entry for each of the 17 commands, grouped by phase, and the two skills that are not commands.
- **[agents.md](agents.md)** — the 9-agent roster: role, model tier, when each fires, how they chain.
- **[ci.md](ci.md)** — CI for pull requests: the workflow template, its two jobs, `--ci` and `--fail-on`, what the verdict means, and how to read the details of a public repository's run.

**Read the results**

- **[output-and-rigor.md](output-and-rigor.md)** — severity model, the Rule 5b gate, verdicts and the Quick depth exception, the report templates, the no-"safe to deploy" convention, Rule 11 in summary, and the report files.
- **[poc-and-patches.md](poc-and-patches.md)** — executable PoC + patch delivery, framework matrix, how `run.sh` builds and runs a PoC, evidence and fix tiers.

**Permissions and isolation**

- **[permissions-and-isolation.md](permissions-and-isolation.md)** — default and strict mode, what runs without asking and why that is safe, what still asks, the resume rules, strict mode and isolated runs (container, VM, Claude Code's sandbox), `claude -p`, and the risks that remain.

**Tools and Trail of Bits**

- **[power-tools.md](power-tools.md)** — `audit-scan`, `audit-mem` and `audit-logs`, GitHub Actions workflow analysis (zizmor, CodeQL), the Trail of Bits plugins and the review of a pin bump, Surfpool sim, the PoC/patch stack, and the index of the bundled scripts.
- The bundled scripts, each with its arguments, exits, network use and outputs: [scripts-core.md](scripts-core.md) (`preflight.sh`, `rundir.sh`, `git-ro.sh`), [scripts-audit.md](scripts-audit.md) (the supply-chain recipes, the threat-model collector, `rpc-read.sh`, `report-to-pdf.sh`), [scripts-runners.md](scripts-runners.md) (`probe.sh`, `deps.sh`, `sast.sh`, `target.sh`) and [scripts-incident.md](scripts-incident.md) (the snapshot, the collector and the analysis recipes).

**After an incident**

- **[detection-response.md](detection-response.md)** — post-incident hunting and incident workup: which command, inputs, outputs, what "confirmed" means, safety, prompts and the analysis recipes.

**The project**

- **[repository-layout.md](repository-layout.md)** — what each folder of the repository holds.
- **[changelog.md](changelog.md)** — what each release added.
- **[COSTS.md](../COSTS.md)** — measured cost and time per depth, and what drives them.
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** — how a change gets in: corpus content, tooling, the pin of Trail of Bits, review.
- **[SECURITY.md](../SECURITY.md)** — what counts as a security issue in auditor-skill, and how to report one.
- **[ATTRIBUTION.md](../ATTRIBUTION.md)** — the sources the corpus draws on, and their licences.

## Root references (outside `docs/`)

- [`SKILL.md`](../SKILL.md) — the orchestrator the agent reads first.
- [`OUTPUT-RULES.md`](../OUTPUT-RULES.md) — the mandatory output format, severity scale and operating-safety rules (Rule 11).
- [`FULL-AUDIT.md`](../FULL-AUDIT.md) — the step-by-step plan of a whole-repository audit.
- [`references/depth-scope.md`](../references/depth-scope.md) — what Quick and CI read.
- [`AGENTS.md`](../AGENTS.md) — agent orchestration overview.
- [`QUESTIONS.md`](../QUESTIONS.md) — the 47-question pre-audit questionnaire.
