# auditor-skill — Documentation

Usage guides for `auditor-skill`, an open-source AI security-audit skill for Solana programs and full-stack code.

## What is auditor-skill

A folder of markdown checklists, slash commands, and subagents — plus three small Rust tools — that turns an LLM agent into a security auditor. It discovers a repo, declares a scope, loads only the checklists that scope needs, walks the code file by file, and emits a severity-ranked report where **every in-scope item carries an explicit verdict**. Corpus: 20 checklists / 1,465 items / 141 known attack vectors, 13 protocol methodologies, framework idioms, and a validation gate that forces high-severity findings to prove reachability before they count. It is a rigorous first pass, not a replacement for a human firm audit.

Commands are namespaced `auditor`, so you invoke them as `/auditor:audit`, `/auditor:audit-cycle`, etc.

## Pick a depth

| Depth | When | Run | Reads | Writes | [Cost](../COSTS.md#cost-and-time-by-depth) |
|-------|------|-----|-------|--------|------|
| **Quick** | a branch or pull request, a first look at a repository, one function | `/auditor:diff-audit` · `/auditor:quick-scan` (whole repository) · `/auditor:deep-review <file> <fn>` | the changed code + one hop, read against the sections and vectors `references/depth-scope.md` selects · SAST, dependency advisories, and the sections and vectors `references/depth-scope.md` selects · one function | `PR-REPORT.md` · `QUICK-SCAN.md` · `DEEP-REVIEW-<unit>.md` | $2–8 · 4–23 min |
| **Standard** | one module or program before it merges | `/auditor:audit <path> --scope …` | every in-scope item for that path | `REPORT.md`, internal: a risk score and a deploy verdict | $13–19 · 35–60 min |
| **Full** | a release, or a report for someone outside the team | `/auditor:audit-cycle` (unattended) · `/auditor:audit-assist` (you steer) · `/auditor:re-audit` after fixes | everything in scope, a threat model, peer review (re-audit: the fix delta) | `REPORT.md`, client style: no deploy guarantee (audit-cycle adds a PDF, and PoCs with `--with-poc`) · `RE-AUDIT.md`, with an updated deploy verdict | about $20 · about 1 h, on a 3K-line program |
| **[CI](ci.md)** | every pull request | `templates/ci/auditor-pr.yml`: a tools job, then `/auditor:diff-audit --ci` | as Quick | `findings.json` and SARIF on the runner, one pass/fail line in the log | tools job $0; review $2–8 a pull request, capped at $15 |

Costs and times were measured on 2026-11-08 and 2026-11-09 with `claude-opus-5-5`, on 3K-, 7K- and 12K-line programs. Quick's range covers diff-audit runs of $1.68–8.10 and quick-scan runs of $2.84–7.14. On the final command text, a quick-scan of the 3K-line repository cost $6.98 in 23 minutes, and a diff-audit of a 7,830-line range there, a lockfile change included, $8.10 in 19 minutes. Full ran once, on the 3K-line program ([COSTS.md](../COSTS.md#cost-and-time-by-depth)). Outside the depths: `poc`, `patch`, `economic-sim` and `triage` work on one finding; `intake` and `threat-model` are Full's building blocks; `audit-report` assembles the internal report from a walk run in pieces; `spec-audit` checks code against a spec; `hunt` and `respond` are for after an incident. More on each depth: [audit-flows.md](audit-flows.md).

## I want to… → use this

| Goal | Use | Guide |
|------|-----|-------|
| Quick: what a branch or PR changes (its commits) | `/auditor:diff-audit [base..head]` | [commands.md](commands.md#auditordiff-audit) |
| Quick: a first look at a whole repo (no full checklist walk) | `/auditor:quick-scan` | [commands.md](commands.md#auditorquick-scan) |
| Quick: one instruction / function, deeply | `/auditor:deep-review <file> [fn]` | [commands.md](commands.md#auditordeep-review) |
| Standard: every in-scope item of a module, program or repo | `/auditor:audit [path] [--scope ...]` | [commands.md](commands.md#auditoraudit) |
| Full: unattended engagement → client report | `/auditor:audit-cycle` | [audit-flows.md](audit-flows.md#flow-a--auditoraudit-cycle-automated) |
| Full: you steer at checkpoints | `/auditor:audit-assist` | [audit-flows.md](audit-flows.md#flow-b--auditoraudit-assist-interactive) |
| Full: review a fix round against a prior report | `/auditor:re-audit [prior] [base..head]` | [commands.md](commands.md#auditorre-audit) |
| CI: Quick on every pull request | `templates/ci/auditor-pr.yml`: a tools job, then `/auditor:diff-audit --ci` | [ci.md](ci.md) |
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
| Run with fewer prompts, in strict mode for code you don't trust, isolated, or in `claude -p` | the user-settings rules, `templates/strict-settings.json`, `AUDITOR_STRICT`, `AUDITOR_EXEC_MODE` | [permissions-and-isolation.md](permissions-and-isolation.md) |

In CI, `--ci` on `/auditor:diff-audit` and `/auditor:quick-scan` asks nothing, writes `audit_<n>/findings.json` and ends with one verdict line. An analyzer that did not run fails the verdict, as does a counted finding at or above `--fail-on` (7 when not given). On a public repository the job publishes pass/fail only ([ci.md](ci.md)).

## Guides

- **[getting-started.md](getting-started.md)** — install, submodule, build the Rust tools, run your first audit, the adaptation note.
- **[audit-flows.md](audit-flows.md)** — the three depths and CI, and the pipeline each one follows: Quick, Standard, the Full lifecycle and the fix review.
- **[ci.md](ci.md)** — Quick on every pull request: the workflow template, its two jobs, `--ci` and `--fail-on`, what the verdict means, and how to read the details of a public repository's run.
- **[commands.md](commands.md)** — reference entry for each of the 17 commands, grouped by phase.
- **[agents.md](agents.md)** — the 9-agent roster: role, model tier, when each fires, how they chain.
- **[power-tools.md](power-tools.md)** — `audit-scan`, `audit-mem`, Trail of Bits plugins, Surfpool sim, the PoC/patch stack, the bundled scripts and their flags.
- **[poc-and-patches.md](poc-and-patches.md)** — executable PoC + patch delivery, framework matrix, evidence and fix tiers.
- **[output-and-rigor.md](output-and-rigor.md)** — severity model, the Rule 5b gate, report templates, the no-"safe to deploy" convention.
- **[detection-response.md](detection-response.md)** — post-incident hunting and incident workup.
- **[permissions-and-isolation.md](permissions-and-isolation.md)** — default and strict mode, what runs without asking and why that is safe, what still asks, strict mode and isolated runs (container, VM, Claude Code's sandbox), `claude -p`, and the risks that remain.

## Root references (outside `docs/`)

- [`SKILL.md`](../SKILL.md) — the orchestrator the agent reads first.
- [`OUTPUT-RULES.md`](../OUTPUT-RULES.md) — the mandatory output format, severity scale and operating-safety rules (Rule 11).
- [`AGENTS.md`](../AGENTS.md) — agent orchestration overview.
- [`COSTS.md`](../COSTS.md) — measured cost and time per depth.
- [`QUESTIONS.md`](../QUESTIONS.md) — the 47-question pre-audit questionnaire.
