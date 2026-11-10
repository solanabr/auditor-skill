<p align="center">
  <img src="assets/banner.png" alt="auditor-skill — a security audit skill for Solana programs and the code around them" width="100%">
</p>

<p align="center">
  <a href="https://github.com/solanabr/auditor-skill/actions/workflows/corpus-check.yml"><img src="https://github.com/solanabr/auditor-skill/actions/workflows/corpus-check.yml/badge.svg" alt="corpus-check"></a>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License: MIT">
  <img src="https://img.shields.io/badge/Claude_Code-plugin-purple" alt="Claude Code plugin">
</p>

# auditor-skill

An open-source AI security audit skill for Solana programs and the code around them.

auditor-skill is a Claude Code plugin, and a folder of skill files that any LLM agent can follow. It reads your code file by file, checks 1,465 items across 20 security domains, tests against 141 real-world attack vectors, and produces a structured report with a severity from 1 to 10 for every finding. A confirmed High or Critical finding can get a runnable exploit, and a fix proven to stop it.

It covers the on-chain programs (Anchor, native and Pinocchio) and the rest of the stack: TypeScript and Rust services, web frontends, Python, Go, Java, Ruby and PHP code, CI workflows, deployment and infrastructure, and AI agent components. It is not a SaaS product. You install it for your agent, outside any repository you audit, or send its files to an LLM API.

**What's inside:** 20 checklists · 1,465 verification items · 141 known attack vectors · executable PoCs + fix patches.

## Read this first: what auditor-skill cannot do on its own

> [!WARNING]
> **It is a first pass, not a professional audit.** An AI auditor cannot do everything a human can: social engineering assessment, business-logic review that needs domain expertise, legal compliance opinions. Run it first, and before a mainnet launch pair it with a human audit of the business logic, the economic model and legal compliance. Like a firm's, its client report gives no "safe to deploy" guarantee.
>
> **By default it builds and tests the project on your machine.** In native mode, the default, the project's builds and tests run without a prompt for each run, and building and testing a project runs its own code: build scripts, proc-macros and tests. For code you don't trust, use strict mode, which is opt-in: start Claude Code with the [strict launch line](#permissions-and-isolation). It also keeps your own plugins out: a language-server plugin such as `rust-analyzer-lsp` would otherwise run the project's build scripts outside the auditor's runners.
>
> **The rules that let a flow resume also let Claude start one.** The `Skill(auditor:… *)` rules you add [once, after installing](#once-after-installing) let Claude start any of these flows by itself, in any repository you open, for example when a file it reads tells it to.
>
> **The incident commands only propose.** `/auditor:hunt` and `/auditor:respond` never sign, send, pause or freeze anything. If funds may be moving right now, page your on-call, run the pause or freeze runbook and open a SEAL 911 ticket first.
>
> What remains a risk in each mode: [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#what-remains-a-risk).

## Quick start

Install the plugin in Claude Code:

```
/plugin marketplace add solanabr/auditor-skill
/plugin install auditor
```

Then, in the repository you want to review, check what your branch changed:

```
/auditor:diff-audit
```

With no argument it reviews the commits between the tip of `main` and HEAD, so commit your work and rebase on `main` first. It writes `audit_<n>/PR-REPORT.md`, in a run directory that git ignores.

Next:

- Add the [resume rules](#once-after-installing) to your user settings once, so a flow that stops for your answer goes on without a prompt.
- Choose the depth that answers your question: [Pick a depth](#pick-a-depth).
- Build the optional Rust tools: [Tool execution](#tool-execution-trail-of-bits--optional-rust-tools).

### What a verdict looks like

Every item a run reads gets an explicit verdict. This is the format, with the example `OUTPUT-RULES.md` Rule 4 gives:

```text
[PASS]      AV-001: Account ownership validated via Account<'info, T> typed accounts
[FAIL-8]    AV-015: Token account missing token::authority constraint
              File: programs/<program>/src/instructions/deposit.rs:42
              Impact: Attacker can substitute token account, draining vault
              Fix: Add `token::authority = fund` to account constraint
[N/A]       AV-023: init_if_needed — not used in this program
```

A finding of severity 6 or more must also pass the validation gate before it counts ([output-and-rigor.md](docs/output-and-rigor.md#the-rule-5b-validation-gate)). With `--ci`, diff-audit and quick-scan ask nothing and end with one line, which says nothing about what they found:

```text
auditor: verdict: fail (threshold 7, analyzers run: audit-scan, lock-delta; not run: deps-artifacts)
```

**On this page:** [Features](#what-it-does-v77) · [Corpus](#the-corpus) · [Installation](#installation) · [Usage](#usage) · [Output](#output-format) · [Configuration](#configuration) · [Integrations](#integrations) · [Security model](#security-model-and-limitations) · [Upgrading](#upgrading) · [What's new](#whats-new) · [Docs](#documentation) · [Layout](#folder-structure) · [Contributing](#contributing) · [Credits](#inspirations-and-acknowledgments) · [License](#license)

## What It Does (v7.7)

**Three depths and a CI mode**
- **Quick** reviews what a branch changed, gives a whole repository a first look, or goes deep on one function, and writes a report for each. **Standard** gives every in-scope item of one module a verdict, with a risk score and a deploy verdict. **Full** runs a whole audit-firm engagement, ends in a client report, and reviews the fixes after it. **CI** runs the bundled analyzers on every pull request and a Quick review on those from your own branches, and on a public repository publishes pass or fail only. [Pick a depth](#pick-a-depth) · [Details](docs/audit-flows.md)

**A full audit-firm lifecycle, two ways**
- `/auditor:audit-cycle` runs the whole engagement autonomously (intake → context → threat model → tool-assisted pass → domain-partitioned review → triage → independent peer review → synthesis) and hands back a client report. `/auditor:audit-assist` runs the same pipeline **interactively**, pausing at checkpoints for the calls only you can make. [Details](docs/audit-flows.md#the-lifecycle-shared-spine)
- `/auditor:threat-model --bootstrap` starts the threat model from what already went wrong: removed or quietly added account guards, reverts and fix commits, a fork's distance from its parent, prior audit reports, post-mortems and incident records. [Details](docs/commands.md#auditorthreat-model)

**Rigor gates against AI over-reporting**
- Every finding of severity 6 or more must survive a validation gate (reachability, math and state bounds, and at 7 or more an attacker model), or it is downgraded. Severity is Impact × Likelihood with principled downgrades, and a Notes & Nitpicks tier keeps the findings table honest. [Details](docs/output-and-rigor.md)
- Every in-scope item gets an explicit verdict, so a report shows what was checked, not only what failed. [Details](docs/output-and-rigor.md#every-item-gets-a-verdict)

**Executable proofs, not just prose**
- For High and Critical findings, `/auditor:poc` builds a runnable exploit (Mollusk, LiteSVM, a Surfpool fork or a fuzz target) that *asserts* the vulnerability, and `/auditor:patch` drafts a minimal fix and **proves it reverts the exploit**. Evidence is tiered (`[PoC-REPRODUCED]` … `[PoC-PROSE]`), and the prose is never dropped when a harness can't be built. `--post-patch-validation` adds Trail of Bits' post-patch validation, opt-in and in isolated mode only, and its result can only lower a fix tier. [Details](docs/poc-and-patches.md)

**Deep Solana coverage**
- 13 protocol methodologies (AMM/CLMM, lending, perps, oracles, stablecoins, liquid staking, governance, bridges, multisig/custody, Token-2022, NFT marketplaces, launchpads, token registries & risk signals), framework idioms (Anchor/Native/Pinocchio), and a reusable invariant catalog, each loaded only when the code triggers it. [Details](#the-corpus)
- Playbooks for whole classes of risk: ZK proofs and compression, transaction v1 (SIMD-0385), GitHub Actions trigger trust, and the host kernel and network surface of validators, RPC nodes, keepers and runners.

**Dependency updates**
- Checklist 11 §11.11 reviews what a dependency bump's published code actually changed, not only its version. On a changed lockfile, diff-audit runs it within a budget: it checks the new versions' publish ages and compares the published code of every changed key-handling package and at most 40 others. [Details](checklists/11-supply-chain.md)

**Detection and response, after an incident**
- `/auditor:hunt` looks for an attack with no alert to start from, and `/auditor:respond` works one lead to a verdict, the damage and a proposed response plan. Both start from transaction history, program logs and Geyser or indexer exports, and both only propose. [Details](#after-an-incident)

**Rust tools for cost and memory**
- An optional Rust pre-scanner (`audit-scan`) maps the risky surface (instructions, account constraints, PDAs, arithmetic, panics, CPIs) deterministically, with no model calls, and that map replaces part of the reading ([COSTS.md](COSTS.md#keeping-the-cost-down)). A cross-audit memory store (`audit-mem`) gives exact dedup, regression detection, and false-positive suppression across runs. A third Rust tool, `audit-logs`, runs the incident analysis recipes as one offline binary. [Details](docs/power-tools.md)

**17 commands, 9 specialized agents**
- Scoping, threat modeling, deep review, economic simulation, differential and pull-request audits, spec compliance, triage and fix review are each a command, beside the post-incident track. The automated audit flow chains eight agents; a ninth, incident-responder, drives the post-incident track. [Every command](#every-command) · [The agents](docs/agents.md)

**Real tooling, vendored**
- Trail of Bits execution plugins (SAST, fuzzing, coverage, mutation) ship as a git submodule; the native corpus works fully without them. [Details](#tool-execution-trail-of-bits--optional-rust-tools)

**Operating safety, in two modes**
- By default what strict mode would refuse is a note in the report, apart from the few shapes still refused in both modes, which Rules 11e and 11f list. Strict mode, for code you don't trust, refuses it and builds only in isolated mode. In both modes git only reads, the bundled tools write only into the auditor's own directories, and audit output never reaches git or a public CI log ([OUTPUT-RULES.md Rule 11](OUTPUT-RULES.md#rule-11-operating-safety)). [Details](#security-model-and-limitations)

What each release added: [What's new](#whats-new).

## The corpus

The corpus is Markdown that the agent reads on demand:

- **Checklists:** 20 files, 1,465 verification items in all. Each item is a check an auditor can mark PASS, FAIL or N/A from the code.
- **Known vectors:** 141 attack procedures, each with numbered verification steps and an overall verdict, indexed by phase, language and trigger in [`known-vectors/INDEX.md`](known-vectors/INDEX.md).
- **References:** `references/methodologies/` holds 13 protocol playbooks (amm-clmm, lending, perps, oracles, stablecoin, liquid-staking, governance, bridges, wallets-multisig-custody, token-2022, nft-marketplaces, launchpads, token-registry-risk). Beside them sit the framework idioms (Anchor, Native, Pinocchio, build and tooling), four vulnerability-class playbooks (zk-and-compression, transaction-v1, github-actions, kernel-attack-surface), the invariant catalog, the false-positive rules, the audit lifecycle, the detection & response track, and `references/depth-scope.md`, the selection that quick-scan and diff-audit read.

### Supported languages & frameworks

| Language | Checklists | Items |
|----------|-----------|-------|
| Rust (Solana/Anchor) | 01-07 | 531 |
| Rust (off-chain services) | 20 | 23 |
| TypeScript / Node.js | 08-09 | 197 |
| React / Next.js | 08, 10 | 148 |
| Python | 14 | 82 |
| Go / Java / Ruby / PHP | 15 | 88 |
| AI / agent components | 19 | 39 |
| **Always applied** (any repo, at `--scope full`) | 11-13, 16-18 | 421 |
| **Total** | **20** | **1,465** |

Checklists 01-07 are Solana-specific. Of the others, 08-10 cover TypeScript and web code, 14 Python, 15 Go, Java, Ruby, PHP and any other language, 19 AI agents and 20 off-chain Rust, and 11-13 and 16-18 apply to any repository, so the corpus works for projects outside Solana too.

<details>
<summary>The 20 checklists, with their item counts</summary>

- [`01-program-account-validation.md`](checklists/01-program-account-validation.md) (90 items): account validation, on-chain
- [`02-program-access-control.md`](checklists/02-program-access-control.md) (55 items): access control, on-chain
- [`03-program-arithmetic-safety.md`](checklists/03-program-arithmetic-safety.md) (63 items): arithmetic safety, on-chain
- [`04-program-cpi-pda.md`](checklists/04-program-cpi-pda.md) (70 items): CPI and PDA safety, on-chain
- [`05-program-state-machine.md`](checklists/05-program-state-machine.md) (74 items): state machine and lifecycle, on-chain
- [`06-program-economic-logic.md`](checklists/06-program-economic-logic.md) (92 items): economic and logic attacks, on-chain
- [`07-program-opsec-governance.md`](checklists/07-program-opsec-governance.md) (87 items): operational security and governance
- [`08-typescript-safety.md`](checklists/08-typescript-safety.md) (64 items): TypeScript safety
- [`09-backend-security.md`](checklists/09-backend-security.md) (133 items): backend security
- [`10-frontend-security.md`](checklists/10-frontend-security.md) (84 items): frontend security
- [`11-supply-chain.md`](checklists/11-supply-chain.md) (65 items): supply chain and dependencies
- [`12-secrets-opsec.md`](checklists/12-secrets-opsec.md) (53 items): secrets and key management
- [`13-deployment-infrastructure.md`](checklists/13-deployment-infrastructure.md) (102 items): deployment and infrastructure
- [`14-python-safety.md`](checklists/14-python-safety.md) (82 items): Python safety
- [`15-general-language-safety.md`](checklists/15-general-language-safety.md) (88 items): general language safety
- [`16-formal-verification-testing.md`](checklists/16-formal-verification-testing.md) (73 items): formal verification and testing
- [`17-logging-monitoring-incident-response.md`](checklists/17-logging-monitoring-incident-response.md) (68 items): logging, monitoring and incident response
- [`18-privacy-compliance-change-management.md`](checklists/18-privacy-compliance-change-management.md) (60 items): privacy, compliance and change management
- [`19-ai-agent-security.md`](checklists/19-ai-agent-security.md) (39 items): AI agents on Solana
- [`20-rust-offchain-services.md`](checklists/20-rust-offchain-services.md) (23 items): off-chain Rust (Geyser, indexers, keepers)

</details>

### Scope-gated loading

auditor-skill does not bulk-read its whole corpus. It discovers the repo, declares an audit scope ([OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 0), and loads only the in-scope checklists and vectors on demand:

- root docs + `OUTPUT-RULES.md` (always),
- only the `checklists/*.md` the detected languages require (e.g. `14-python-safety.md` only if `.py` is present),
- a `known-vectors/*.md` file only when its phase + language trigger reaches it,
- `discovery/*.md` and `templates/*.md` lazily, at the phase that uses them.

The audit is complete when every **in-scope** item has an explicit verdict; out-of-scope items render `[N/A — out of scope]` from the gate. quick-scan and diff-audit, in CI too, read a smaller declared selection: the one `references/depth-scope.md` makes, written first to `audit_<n>/scope.md`.

## Installation

Install auditor-skill **outside any repository you audit**: the plugin (Option 1), or a user-level skill such as `install.sh ~/.claude/skills/auditor-skill`. A copy inside the audited repository resolves its scripts, tools and corpus from a tree that repository controls, and that repository's own `.claude/`, `.mcp.json` and `CLAUDE.md` are target-controlled too ([OUTPUT-RULES.md Rule 11e](OUTPUT-RULES.md#11e--bundled-paths)). If an earlier install put a copy inside a repository, see [Upgrading from 7.6.0 or earlier](#upgrading-from-760-or-earlier).

### Option 1: Claude Code plugin marketplace (recommended)

```
/plugin marketplace add solanabr/auditor-skill
/plugin install auditor
```

This registers the marketplace and installs the `auditor` plugin: all 17 `/auditor:*` commands and 9 agents. Claude Code clones the plugin together with its submodules, so this also fetches the vendored Trail of Bits tooling at the pinned commit ([Tool execution](#tool-execution-trail-of-bits--optional-rust-tools)); there is no manual step.

### Option 2: Install script

`install.sh` installs the skill and inits the tooling:

```bash
# read it first (it's a security tool, after all):
git clone https://github.com/solanabr/auditor-skill.git
./auditor-skill/install.sh ~/.claude/skills/auditor-skill    # user-level (also the default), outside any audited repository

# one-liner (convenience), same target:
curl -fsSL https://raw.githubusercontent.com/solanabr/auditor-skill/main/install.sh | bash -s -- ~/.claude/skills/auditor-skill
```

- **Where it installs.** With no argument it installs to `~/.claude/skills/auditor-skill`, a user-level skill, wherever you run it from. To install elsewhere, pass a path outside the repositories you audit. It warns on stderr when the install directory is inside a git work tree.
- **Re-running it** installs a fresh clone at the same path and moves the earlier install, without running git in it, to `$XDG_STATE_HOME/auditor-skill/backup-<timestamp>`, or `~/.local/state/auditor-skill/backup-<timestamp>` when `XDG_STATE_HOME` is unset or not an absolute path. The run prints the backup's path.
- **The backup directory** must lie outside every skills directory, so that Claude Code does not load the old copy as a second skill. The run refuses a backup directory inside the install's parent directory, or one under a directory named `.claude`, `skills`, `commands` or `agents` in any letter case, on its path as given or with links resolved.
- **Old backups stay.** Each upgrade keeps a full copy, including anything built inside it such as the Rust tools' build output, and nothing removes old backups: delete them when you no longer need them.
- **Links.** A symbolic link at the install path or at the backup directory is refused, never followed.

### Option 3: Clone manually

```bash
git clone https://github.com/solanabr/auditor-skill.git ~/.claude/skills/auditor-skill
```

Claude Code auto-discovers user-level skills under `~/.claude/skills/`: invoke it by asking your agent to "audit this repo using the auditor-skill". For the `/auditor:*` slash commands, use Option 1. Claude Code 2.1.157 and later also loads this clone as the `auditor` plugin, commands included, unless managed settings block plugins saved there, with `strictPluginOnlyCustomization` or a `strictKnownMarketplaces` list without `skills-dir`, or an `auditor` plugin installed from a marketplace takes precedence.

This is also Option 2's default path, so a later `install.sh` run without a path upgrades this clone: it installs a fresh clone and moves this one to Option 2's backup directory, without running git in it. A manual clone needs the Trail of Bits submodule step [below](#tool-execution-trail-of-bits--optional-rust-tools). For agents other than Claude Code, see [Other agents](#other-agents).

### Option 4: Feed files to the API directly

If you're building a service, send `SKILL.md` + `OUTPUT-RULES.md` + `FULL-AUDIT.md` as system context and the target repo files as user content to any LLM API.

### Once, after installing

In Manual mode Claude Code asks each time a flow goes on after your reply, since a plugin cannot ship permission rules. Add these rules once to `permissions.allow` in your user settings, `~/.claude/settings.json`, beside the rules already there:

```json
{
  "permissions": {
    "allow": [
      "Skill(auditor:audit-cycle *)", "Skill(auditor:audit-assist *)", "Skill(auditor:intake *)",
      "Skill(auditor:threat-model *)", "Skill(auditor:triage *)", "Skill(auditor:poc *)",
      "Skill(auditor:patch *)", "Skill(auditor:audit-report *)", "Skill(auditor:hunt *)",
      "Skill(auditor:respond *)", "Skill(auditor:dnr-analyze *)", "Skill(auditor:audit *)",
      "Skill(auditor:quick-scan *)", "Skill(auditor:deep-review *)", "Skill(auditor:diff-audit *)",
      "Skill(auditor:spec-audit *)", "Skill(auditor:economic-sim *)", "Skill(auditor:re-audit *)",
      "Skill(auditor:auditor-skill)", "Skill(auditor:auditor-skill *)"
    ]
  }
}
```

With Option 2 or Option 3, add `"Skill(auditor-skill)"` and `"Skill(auditor-skill *)"` too: there the root skill is your personal skill `auditor-skill`.

These rules name no path. They also let Claude start any of these flows by itself, in any repository you open, with no prompt in Manual mode and no classifier check in auto mode, for example when a file it reads tells it to. `/auditor:audit-cycle` started that way builds the project on your machine. To rule that out, set `AUDITOR_EXEC_MODE=isolated` (or `none`) in that file's `env`, or keep the rules in a file you pass with `claude --settings` when you audit ([docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#turns-and-resuming)).

### Tool execution (Trail of Bits) + optional Rust tools

auditor-skill vendors **Trail of Bits** ([trailofbits/skills](https://github.com/trailofbits/skills), CC-BY-SA 4.0) as a git submodule (`vendor/trailofbits`) for real tool execution — SAST, fuzzing, coverage, mutation. Options 1 and 2 both fetch it. For Option 3, or any other clone, run this from the auditor-skill directory (not your project root):

```bash
git submodule update --init --depth 1 -- vendor/trailofbits
```

**Pinned at** [`711af09`](https://github.com/trailofbits/skills/tree/711af095215ad4ecde5b90cd1d0124b3f1c4ca9e) — trailofbits/skills `main` of 2026-11-02. Upstream publishes no tags or releases, so the pin is a commit, and it moves only after a reviewed bump ([CONTRIBUTING.md §5](CONTRIBUTING.md#5-tooling-changes)); CI fails if this line and the submodule disagree, and plugin installs receive a new pin with the next release. To read the pin of any checkout without initializing the submodule: `git ls-tree HEAD vendor/trailofbits`.

The native corpus works fully **without** it: it falls back to grep-based checks and notes where deeper tooling would run. With the submodule initialized, the auditor delegates to the vendored tools per [`references/orchestration/boundary-map.md`](references/orchestration/boundary-map.md). What each plugin is used for, and its native fallback: [docs/power-tools.md](docs/power-tools.md#trail-of-bits-plugins).

For the optional token-efficiency tools (`audit-scan` pre-scanner + `audit-mem` memory, with `audit-logs` for the incident track), build the Rust CLIs; `<auditor-skill root>` is where you installed auditor-skill:

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release --locked
```

- **Build them again after every update**, with `cargo build --release --locked` in the same directory. The flows call them with a contract marker (`--contract=1`) that an older build refuses, and until then they go on as if the tools were absent.
- **They run from the installation.** The auditor runs them, the scripts and the Trail of Bits plugins by absolute path from the installation, never by a path relative to the project it audits ([OUTPUT-RULES.md Rule 11e](OUTPUT-RULES.md#11e--bundled-paths)).
- **A copy inside the repository under audit** (such as `.claude/skills/auditor-skill`, where `install.sh` without a path installed through 7.6.0) builds inside that tree, where cargo and rustup read its `.cargo/config*` and `rust-toolchain*` from every parent directory. Build there only in [Rule 11a](OUTPUT-RULES.md#rule-11-operating-safety) isolated mode, or delete that copy and install a fresh one outside (the plugin, or Option 2 with the path `~/.claude/skills/auditor-skill`) and build that one, as [Upgrading from 7.6.0 or earlier](#upgrading-from-760-or-earlier) says.

### Permissions and isolation

The `/auditor:*` commands run their bundled steps without asking: the working-tree check, run directories, read-only git, the Rust tools, and the runners that build and test the project in the execution mode in force, native unless intake, `AUDITOR_EXEC_MODE` or strict mode says otherwise. Each checks its own arguments and writes only into the auditor's own directories; other calls ask ([docs/getting-started.md](docs/getting-started.md), "Prompts and isolation", gives the whole list). By default what strict mode would refuse is a note in the report, apart from the few shapes still refused in both modes, which Rules 11e and 11f list ([OUTPUT-RULES.md Rule 11f](OUTPUT-RULES.md#11f--default-and-strict-mode)).

Two settings help. The first adds [one risk](docs/permissions-and-isolation.md#what-remains-a-risk): its rules also let Claude start a flow by itself.

- **The resume rules.** Add the `Skill(auditor:… *)` rules from [Once, after installing](#once-after-installing) to your user settings, `~/.claude/settings.json`, so a flow resumes after your reply without a prompt.
- **The strict launch line, for code you don't trust.** Start Claude Code with `claude --setting-sources "" --strict-mcp-config --plugin-dir "<auditor-skill root>" --settings "<auditor-skill root>/templates/strict-settings.json"`, where `<auditor-skill root>` is the folder auditor-skill is installed in ([docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#default-and-strict-mode) says where that is).
  - It loads none of your own settings or plugins: a language-server plugin you enabled, such as `rust-analyzer-lsp`, would otherwise run the project's build scripts on your machine, outside the runners.
  - Strict mode refuses what default mode only notes, and builds only in isolated mode: under the Claude Code sandbox the template turns on, or in a container or a VM.
  - Under the launch line the repository's own `.claude/` config and `.mcp.json` servers do not load. Strict mode still refuses a tree that ships them, because preflight cannot see how Claude Code was started: for such a repository, audit a copy with every `.claude/` and `.mcp.json` deleted.

In native mode, the default, the project's builds and tests run on your machine without a prompt for each run.

## Usage

### Pick a depth

Pick by what you want checked: what changed, one module, or the release. Quick, Standard and Full need nothing beyond installing the plugin.

| Depth | When | Run | [Cost and time](COSTS.md#cost-and-time-by-depth) |
|-------|------|-----|------|
| **Quick** | a branch or pull request, a first look at a repository, one function | `/auditor:diff-audit` · `/auditor:quick-scan` (whole repository) · `/auditor:deep-review <file> <fn>` | $2–8 · 4–23 min |
| **Standard** | one module or program before it merges | `/auditor:audit <path> --scope …` | $13–19 · 36–56 min |
| **Full** | a release, or a report for someone outside the team | `/auditor:audit-cycle` (unattended) · `/auditor:audit-assist` (you steer) · `/auditor:re-audit` after fixes | about $20 · about 1 h, on a 3K-line program |
| **[CI](docs/ci.md)** | every pull request: the analyzers on all of them, the review on those from your own branches | `templates/ci/auditor-pr.yml`: a tools job, then `/auditor:diff-audit --ci` | tools job $0; review about a diff-audit's cost, capped at $15 |

Quick reads the changed code and one hop around it against the selection of `references/depth-scope.md` (diff-audit), a repository's SAST, dependency advisories and that selection (quick-scan), or one function (deep-review). It writes `PR-REPORT.md`, `QUICK-SCAN.md` or `DEEP-REVIEW-<unit>.md`. Standard gives every in-scope item a verdict and writes the internal `REPORT.md`, with a risk score and a deploy verdict. Full adds a threat model and peer review and writes the client `REPORT.md`, which gives no deploy guarantee; `/auditor:re-audit` then writes `RE-AUDIT.md`. What each depth reads and writes, in full: [docs/audit-flows.md](docs/audit-flows.md#pick-a-depth).

The costs and times were measured from 2026-11-08 to 2026-11-10 with `claude-opus-5-5` as the session model, on 3K-, 7K- and 12K-line programs, one run each, so read them as sizes, not quotes. On the 12K-line program, a diff-audit of a narrow change, 1,248 lines with no lockfile, cost $3.99 in 9 minutes. Full ran once, on the 3K-line program, and nothing at 50K lines was measured. Every run, what it read and how it was set up: [COSTS.md](COSTS.md#cost-and-time-by-depth). Which model runs what: [Models and time](#models-and-time).

Outside the depths: `poc`, `patch` and `economic-sim` work on one finding, and `triage` on a run's candidate findings; `intake` and `threat-model` are Full's building blocks; `audit-report` assembles the internal report from a walk run in pieces; `spec-audit` checks code against a spec; `hunt` and `respond` are for [after an incident](#after-an-incident).

### Before running an audit

1. **Intake, for Full only.** Full runs it for you: `/auditor:audit-cycle` with the [QUESTIONS.md](QUESTIONS.md) defaults, each listed in the report, and `/auditor:audit-assist` by asking at its first checkpoint. The answers set the severity calibration, the trust model and which compliance checklists apply. With an agent that has no commands, fill a copy of QUESTIONS.md first. Quick and Standard need no intake.
2. **Check the cost:** [COSTS.md](COSTS.md) has the measured cost and time of each depth.
3. **Choose your scope** for Standard and Full: `--scope full|program|backend|frontend` picks the part of the repository a run reviews. [SKILL.md](SKILL.md#scope-gated-loading--load-what-the-repo-needs) defines each one; the Quick commands take none.

### Claude Code with the plugin

Each depth is a command. Run it from the repository you audit:

```
/auditor:diff-audit                                  # Quick: main's tip against HEAD
/auditor:diff-audit v1.2.0..HEAD                     # Quick: another committed range
/auditor:quick-scan                                  # Quick: a first look at a whole repository
/auditor:deep-review programs/vault/src/instructions/withdraw.rs withdraw   # Quick: one function
/auditor:audit programs/vault --scope program        # Standard: one program, every in-scope item
/auditor:audit-cycle --scope full                    # Full: unattended, ends in a client report
/auditor:audit-assist --scope full                   # Full: pauses for your calls at checkpoints
/auditor:re-audit audit_1/REPORT.md main..HEAD       # Full: after the fixes
```

`diff-audit` reviews commits, so commit your work first. With no argument it compares the tip of `main` with HEAD: rebase on `main` first, or changes `main` gained since you branched show up in the review. Every command and its arguments: [docs/commands.md](docs/commands.md).

### Every command

There are 17 commands, each run as `/auditor:<name>`. Three are Quick, one is Standard, and three make up Full. The others work on one finding, build a Full run's pieces, assemble a report, check code against a spec, or handle an incident.

| Command | Where it fits | What it does | Writes, in `audit_<n>/` |
|---------|---------------|--------------|-------------------------|
| `diff-audit [base..head]` | Quick | reviews the commits of a branch or pull request, with one hop of callers and callees | `PR-REPORT.md` |
| `quick-scan [<path>]` | Quick | a first look at a whole repository: SAST, dependency advisories, and the sections and vectors `references/depth-scope.md` selects | `QUICK-SCAN.md` |
| `deep-review <file> [fn]` | Quick | one function or instruction, in depth | `DEEP-REVIEW-<unit>.md` |
| `audit [path] [--scope …]` | Standard | gives every in-scope item a verdict, item by item | `REPORT.md`, internal |
| `audit-cycle [--with-poc]` | Full | runs the whole lifecycle, unattended | `REPORT.md`, client |
| `audit-assist` | Full | runs the same lifecycle, pausing at checkpoints for your calls | `REPORT.md`, client |
| `re-audit [prior] [base..head]` | Full, after fixes | classifies each prior finding (FIXED, STILL-OPEN, REGRESSED and the rest), reviews the change for new findings, and sweeps for unpatched siblings of each fix | `RE-AUDIT.md`, in `audit_<n+1>/` |
| `intake` | Full's first step | records scope, protocol class, severity calibration, the trust model, the execution mode and whether live probes are allowed | `intake.md` |
| `threat-model [--bootstrap]` | Full's building block | lists assets, actors and what each must not be able to do, trust boundaries and attacker goals; `--bootstrap` seeds them from history | `threat-model.md` |
| `triage` | a set of findings | de-duplicates by root cause, re-applies the validation gate, and splits findings from Notes & Nitpicks | the triaged set and a suppression appendix |
| `economic-sim <finding>` | one finding | puts a dollar profit and loss on an economic attack, on a Surfpool mainnet fork when one is available | the quantified PoC |
| `poc <finding>` | one finding | builds a runnable exploit that asserts the flaw | `poc/F-xxx/` and a `[PoC-*]` tier |
| `patch <finding>` | one finding | drafts a minimal fix and re-runs the exploit against it | `patches/F-xxx.patch`, `VERIFICATION.md` and a `[FIX-*]` tier |
| `audit-report [dir]` | reporting | assembles the internal report from a walk run in pieces | `REPORT.md` |
| `spec-audit <spec> [path]` | outside the depths | checks the code against a spec, a whitepaper or an RFC | a compliance matrix and findings |
| `hunt [<address> …]` | after an incident | looks for an attack with no alert to start from | `INCIDENT_REPORT.md` and `INCIDENTS.json`, in `incident_<n>/` |
| `respond <lead>` | after an incident | works one lead: whether it landed, the damage, the root cause and a proposed plan | `RESPONSE-INC-<n>.<k>.md`, in `incident_<n>/` |

Two skills ship beside them. `auditor:dnr-analyze` runs one analysis phase of `hunt` or `respond` as a fork of the incident-responder agent. The root skill, `auditor:auditor-skill`, runs when you ask in plain words, such as "audit this repo".

### After an incident

`/auditor:hunt` and `/auditor:respond` start from what already happened on chain: transaction history, program logs, and Geyser or indexer exports. They are a track of their own, never part of an audit, and they only propose.

- **`/auditor:hunt [<address> …]`** — no alert to start from. It snapshots the deployed programs, baselines the transaction history, records each hypothesis and its query in a ledger, checks each suspect against the source deployed at the incident slot, and reproduces it on the program's real bytes → `incident_<n>/INCIDENT_REPORT.md` and `INCIDENTS.json`.
- **`/auditor:respond <lead>`** — one lead: a signature, an address, an alert or an `INC-<n>.<k>` from a hunt. It settles whether it landed, the damage per mint and the root cause, and drafts containment, remediation and recovery steps for people to carry out → `RESPONSE-INC-<n>.<k>.md`.

Neither command signs, sends, pauses or freezes anything. If funds may be moving right now, page your on-call, run the pause or freeze runbook and open a SEAL 911 ticket first: these commands are the after-the-fact workup. Guide: [docs/detection-response.md](docs/detection-response.md).

### CI for pull requests

To review every pull request, copy `templates/ci/auditor-pr.yml` into `.github/workflows/` and follow [docs/ci.md](docs/ci.md#setup). The workflow pins auditor-skill by a full commit id: use a `main` commit that holds the template, not a release tag, since no tag holds it yet and patch releases get none ([CONTRIBUTING.md §3](CONTRIBUTING.md#3-branch-and-pr-flow)). The template runs two jobs:

- **The tools job** runs the bundled analyzers (semgrep, `cargo audit`, `npm audit`) on every pull request, forks included, with no model and no secrets. It costs runner minutes only.
- **The review job** runs `/auditor:diff-audit --ci` on pull requests from your own branches, other than Dependabot's, in strict mode with nothing from the pull request built or run. It fails when a counted finding reaches `AUDITOR_FAIL_ON` (7 by default), when an analyzer did not run, or when the review stopped early ([what the verdict means](docs/ci.md#what-the-verdict-means)). A review costs about what a diff-audit of that change costs, and the template caps it at $15.

On a fork's or Dependabot's pull request the review check shows Success with no review, so review those yourself before you merge. On a public repository the job posts pass or fail only, with no finding text or counts: logs, job summaries and uploaded artifacts are readable by any signed-in GitHub user. The details stay on the runner, you read them by running the same command in a clone of your own, and the job never fails only because no private channel exists (OUTPUT-RULES Rule 11d).

For a scheduled scan of the default branch, run `/auditor:quick-scan --ci`, with a `--max-budget-usd` of $15: a cap close to a full pass's cost makes the session stop reading early ([COSTS.md](COSTS.md#cost-and-time-by-depth)). A CI job of your own, such as a Full run on a release branch, is a `claude -p` run: what it needs is in [docs/faq.md](docs/faq.md#can-i-use-this-in-cicd) and [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#non-interactive-runs-claude--p).

### Models and time

Time depends on the depth, the repository's size and the model. Quick scales with the change, Standard with the module, and Full takes longest: six agents carry it from context reconstruction through a threat model and peer review to the report, and `--with-poc` adds two more.

In Claude Code each agent names its own model tier: seven run on Opus, and context-builder and audit-reporter on Sonnet ([docs/agents.md](docs/agents.md)). `/auditor:quick-scan` and `/auditor:diff-audit` start no agent, so your session's model runs them (`/model`, or `claude --model`); an agent that `/auditor:deep-review` starts runs on the tier its definition names. Sonnet as the session model is not measured yet.

## Output format

Every run writes into a run directory, `audit_<n>/` (`incident_<n>/` for the incident track), whose first file is a `.gitignore` holding `*`. The Quick commands write their reports from `templates/pr-report.md`: `PR-REPORT.md`, `QUICK-SCAN.md` or `DEEP-REVIEW-<unit>.md`, each opening with a summary of the verdict, the highest severity, the findings, what was reviewed, the analyzers that ran and the mode.

`/auditor:audit` (Standard) writes the internal report below. `/auditor:audit-cycle` and `/auditor:audit-assist` (Full) write the client report instead, which follows firm convention and gives no deploy guarantee. The internal report is a structured markdown file with:

1. **Executive Summary** — risk score (1-10), deploy/no-deploy verdict, severity distribution
2. **Instruction Matrix** — every smart contract instruction mapped
3. **State Model** — account structs, PDA seeds, relationships
4. **Per-Item Verdicts** — every in-scope checklist item (up to 1,465) with `[PASS]`, `[FAIL-N]`, `[PARTIAL]`, or `[N/A]`
5. **Known Vectors Results** — each in-scope attack vector (up to 141) with explicit verdict and evidence
6. **Findings** — deduplicated, severity-sorted
7. **Attack Scenarios** — narrative exploitable paths
8. **Aggregate Score** — PASS/PARTIAL/FAIL percentages
9. **Recommendations** — prioritized fix list

The client report has an executive summary, a commit-pinned scope, findings with PoC or reachability, a code-maturity assessment, and disclaimers. Like a real firm's, it does **not** issue a "safe to deploy" guarantee. Method and firm coverage: [references/audit-lifecycle/](references/audit-lifecycle/). An optional PDF needs [pandoc](https://pandoc.org/) 2.15 or later and a PDF engine (xelatex, lualatex or pdflatex):

```bash
# from your project; <auditor-skill root> is where auditor-skill is installed
"<auditor-skill root>/scripts/report-to-pdf.sh" audit_1/REPORT.md   # writes REPORT.pdf when pandoc and a PDF engine are installed; MD is always the deliverable
```

For High and Critical findings, an optional `audit_<n>/poc/` (runnable exploits that assert the bug) and `audit_<n>/patches/` (minimal fixes proven to revert the exploit) accompany the report: [docs/poc-and-patches.md](docs/poc-and-patches.md). Every output file, by name: [docs/output-and-rigor.md](docs/output-and-rigor.md#report-file-naming). The complete specification: [OUTPUT-RULES.md](OUTPUT-RULES.md).

## Configuration

auditor-skill reads no configuration file of its own: environment variables, command flags and the intake answers set a run. Strict mode and the execution mode are the settings that matter most. Strict mode is off unless `AUDITOR_STRICT=1`, a command's `--strict` or intake's "Untrusted source" answer turns it on. The execution mode is native unless intake, `AUDITOR_EXEC_MODE` or strict mode says otherwise.

| Setting | Default | What it does |
|---------|---------|--------------|
| `AUDITOR_STRICT=1`, or `--strict` on a command | off | strict mode: refuses what default mode only notes, and raises the execution mode to isolated at least ([Rule 11f](OUTPUT-RULES.md#11f--default-and-strict-mode)) |
| `AUDITOR_EXEC_MODE` | native when nothing is recorded | `native`, `isolated` or `none`: how the runners build and test the project. They take the stricter of it, the run directory's recorded mode (intake's Q46) and strict mode ([Rule 11a](OUTPUT-RULES.md#rule-11-operating-safety)) |
| `AUDITOR_PUBLISH_AGE` | on | for a changed lockfile, asks each package's public registry for its publish times and publishers, once per name in the changed set; `off` sends no such request ([Security model](#security-model-and-limitations)) |
| `--scope full\|program\|backend\|frontend` | `full` | the part of the repository a Standard or Full run reviews ([SKILL.md](SKILL.md#scope-gated-loading--load-what-the-repo-needs)) |
| `--ci`, `--fail-on <N>` | off, 7 | an unattended Quick run that ends in a verdict line, and the severity that fails it ([docs/ci.md](docs/ci.md#running---ci-yourself)) |
| `--over-budget fail` | count | diff-audit fails a change over 5,000 changed lines instead of reviewing its riskiest 5,000 and counting the rest |
| `BASH_DEFAULT_TIMEOUT_MS`, `BASH_MAX_TIMEOUT_MS` | Claude Code's: a call times out after two minutes | raised in your user settings' `env`, they keep a long build or collection inside the command's pre-approvals ([Long steps](docs/permissions-and-isolation.md#long-steps)) |

The CI template's own settings (`AUDITOR_FAIL_ON`, `AUDITOR_MAX_BUDGET_USD`, `AUDITOR_OVER_BUDGET`, `AUDITOR_PUBLISH_AGE`, `SEMGREP_RULESETS` and the tool versions) are in its top-level `env:` block ([docs/ci.md](docs/ci.md#setup)). Every command's flags: [docs/commands.md](docs/commands.md).

### Your project's layout

auditor-skill was first built for one Solana/Anchor DeFi project and then generalized, and `discovery/file-map.md` still assumes that project's layout (`programs/{name}/src/`, `apps/backend/src/`, `apps/web/src/`). For Quick and Standard, pass the range or the path you want reviewed.

For Full, record where your code lives at intake: the in-scope paths under `QUESTIONS.md` Q39 ("Specific files/modules") and the exclusions under Q44 go into the Layout table of `audit_<n>/intake.md` §1. The next interactive intake in the same checkout offers that table again and reuses it only on your yes; `/auditor:audit-cycle` runs intake with `--auto`, which never reuses it. Don't edit `discovery/file-map.md` in a shared or plugin install: the next update overwrites it. Everything else (checklists, known vectors, output rules) is portable as-is ([docs/getting-started.md](docs/getting-started.md), "Adapt to your repo").

## Integrations

### solana-ai-kit

[solana-ai-kit](https://github.com/solanabr/ai-kit) vendors auditor-skill as a skill pack at a pinned commit and never runs `install.sh`, so a release here reaches kit users when the kit moves its pin. The kit's skill registry also records the Trail of Bits pin, and a maintainer tells the kit the new commit after each bump ([CONTRIBUTING.md §5](CONTRIBUTING.md#bumping-vendortrailofbits)).

A project built with the kit ships its own Claude Code config, a `.claude/` and a `.mcp.json`. Claude Code loads that config with the session unless you start it with the strict launch line. In default mode preflight notes it and the run goes on; strict mode refuses such a tree, and [Permissions and isolation](#permissions-and-isolation) says how to audit a copy without it.

### Other agents

An agent without the plugin's commands (VS Code with GitHub Copilot, Cursor, Windsurf, Codex) reads the skill and follows it. Copy the folder anywhere the agent reads, outside the repository you audit, point it at its `SKILL.md`, and ask in plain words:

```text
# VS Code / GitHub Copilot
@workspace Audit the entire repository using the auditor-skill

# Cursor / Windsurf: a full audit
Read ~/.claude/skills/auditor-skill/SKILL.md then audit this repository following that installation's FULL-AUDIT.md execution plan

# Cursor / Windsurf: a first pass on a branch
Read ~/.claude/skills/auditor-skill/SKILL.md then review what this branch changes against main, as its differential mode describes

# Claude Code, in plain words
Read the auditor-skill files in ~/.claude/skills/auditor-skill/ and perform a full security audit of this repository
```

For the API (programmatic), send `SKILL.md` + `OUTPUT-RULES.md` + `FULL-AUDIT.md` as the system prompt and the target files as user messages, chunked, then collect the structured output. More prompts, and what changes without the plugin: [docs/other-agents.md](docs/other-agents.md).

### Surfpool

`/auditor:economic-sim` and `/auditor:poc --fork` reproduce an economic attack on a Surfpool mainnet fork when the `surfpool` CLI and its MCP server, which needs no key, are available. The fork fetches mainnet state from its RPC datasource, which receives the program ids and account addresses the simulation reads, so the report names that provider's domain. Without Surfpool, a PoC falls back to Mollusk or LiteSVM when the logic can be modeled, else to `[PoC-ATTEMPTED]` with the blocker named. The strict launch line's `--strict-mcp-config` drops your own MCP servers, the Surfpool server among them ([docs/power-tools.md](docs/power-tools.md#surfpool-economic-simulation)).

## Security model and limitations

auditor-skill reads the code it audits, and in native mode it builds and tests it. What it does by itself is limited in both modes: git only reads, writes go only into its own run directories, the `audit-mem` store and scratch directories, none of your credentials is used, and every pre-approved tool checks its arguments ([docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#default-and-strict-mode)).

- **Default mode notes; strict mode refuses.** A check that would stop the run in strict mode prints a note in default mode, and the report lists each distinct note once under Coverage & Limitations. Strict mode refuses those, and raises the execution mode to isolated at least.
- **Strict mode is as strong as the way Claude Code starts.** Nothing in the repository can turn strict mode off when Claude Code starts with the strict launch line, or with `AUDITOR_STRICT=1` in managed settings. Started any other way, the repository's own settings (hooks, `env`, `CLAUDE_ENV_FILE`) apply first and can switch it off. `--strict` and intake's answer travel through the agent, so text the repository loads can talk the agent out of them.
- **What default mode leaves open.** In native mode the project's builds and tests run on your machine without a prompt for each run. The isolated-mode self-check knows credentials only by their names and places. Preflight covers neither a session you start in such a tree for other work nor a command that a repository file has replaced; starting Claude Code with the strict launch line, which loads none of the repository's skills, commands or settings, rules both out.
- **Outside services are disclosed, not gated.** The report lists each tool that contacts an outside service, and what it was set to send ([Rule 11b](OUTPUT-RULES.md#11b--outside-service-disclosure)). Trail of Bits' `second-opinion`, which asks before it runs, sends the selected code to an external LLM CLI, OpenAI Codex or Google Antigravity / Gemini.
- **A lockfile review contacts the public registries.** With `AUDITOR_PUBLISH_AGE` on, the default, it sends the name of each package its set holds, new packages and new versions alike, to its public registry (npmjs.org, crates.io's index, pypi.org), and each crate the budget selects to crates.io's record as well. With it off, the review still fetches the published code of the versions its budget selects.
- **Output stays private.** Run directories ignore themselves in git, and CI on a public repository publishes pass or fail only ([Rule 11d](OUTPUT-RULES.md#11d--output-hygiene)).

Everything that remains a risk: [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#what-remains-a-risk). To report a vulnerability in auditor-skill itself, use private vulnerability reporting, as [SECURITY.md](SECURITY.md) explains.

## Upgrading

Plugin users get each change when they update the plugin, a new Trail of Bits pin included. An `install.sh` install gets it on its next run.

**After every update, rebuild the Rust tools:** `cargo build --release --locked` in `tools/auditor-tools`. An older build refuses the `--contract=1` the flows pass, and they go on as if the tools were absent; an `audit-logs` built before a change to the recipes it mirrors or to `confine.sh` exits 4, and the analysis falls back to the scripts until you rebuild.

### Upgrading from 7.6.0 or earlier

Through 7.6.0, `install.sh` without a path installed into the current directory's `.claude/skills/auditor-skill`; it now installs to `~/.claude/skills/auditor-skill`, and a run started next to such a copy notes it and leaves it alone. If your copy sits inside a repository, delete it (`rm -rf .claude/skills/auditor-skill`) and install a fresh copy outside: the plugin (Option 1), or Option 2. Never move or update a copy you find inside a repository: its git config may have come with that repository. Plugin users get this change when they update the plugin.

### Upgrading from 7.6.x or 7.7.0

7.7.2 made the security checks opt-in. By default a check that used to stop the run prints a note, and the report lists it; strict mode keeps the refusals.

- **If you set isolated mode on the old advice.** Before 7.7.2 the docs called isolated mode recommended. On a normal machine, where `~/.ssh` or `~/.config/solana` is readable, it now stops every build and PoC at the isolation self-check, since that machine is not an isolated runner. To build natively, unset `AUDITOR_EXEC_MODE` where Claude Code runs and write `native` to the run directory's `exec-mode`; the self-check's blocker line says so too.
- **To keep the refusals,** turn strict mode on with `AUDITOR_STRICT=1`, `--strict` on a command, or intake's "Untrusted source" answer, and start Claude Code with the strict launch line ([Permissions and isolation](#permissions-and-isolation)).
- **Anchor projects build in the runners.** In 7.7.0 an `anchor` installed through avm did not start in the build's own HOME, Anchor 1.x builds failed at the IDL step, Anchor 1.2 got the wrong platform tools, and anchor-cli 0.31.1 rejected the `--ignore-keys` the runner passed. 7.7.2 fixes all four, and an older `cargo build-sbf` builds natively, offline, in the runners' throwaway home folder.
- **Rebuild the Rust tools,** as after every update: `scripts/lib/confine.sh` changed in 7.7.2, so an older `audit-logs` exits 4 until you rebuild it.
- **"Yes, and don't ask again"** at a prompt no longer breaks the next run inside a git repository: preflight takes an untracked `.claude/settings.local.json` for your own.

Details, in docs/permissions-and-isolation.md: [Default and strict mode](docs/permissions-and-isolation.md#default-and-strict-mode) and [Strict mode and isolated runs](docs/permissions-and-isolation.md#strict-mode-and-isolated-runs).

## What's new

The latest changes, newest first. Each entry in full, with the earlier releases: [docs/changelog.md](docs/changelog.md).

- **7.7.3** — Three depths, Quick, Standard and Full, and a CI mode. `references/depth-scope.md` declares what quick-scan and diff-audit read; diff-audit reviews at most 5,000 changed lines and runs a lockfile budget; `templates/ci/auditor-pr.yml` reviews pull requests; each Quick command writes a named report; every report gets a Generated line from `rundir.sh stamp`, which says no person reviewed it unless `AUDITOR_REVIEW_STATEMENT` says otherwise; COSTS.md gives measured runs.
- **7.7.2** — Strict mode is opt-in: by default the checks that used to stop a run print a note, and builds run natively unless intake, `AUDITOR_EXEC_MODE` or strict mode says otherwise. Anchor builds work in the runners, and an older `cargo build-sbf` builds offline. It also brings the host kernel and network attack surface of validators, RPC nodes, keepers, indexers and runners: a known vector (KV-141), six checklist items (DEP-097..102) and a playbook. Read [how to upgrade from 7.6.x or 7.7.0](#upgrading-from-76x-or-770).
- **7.7.0** — Bundled steps run without asking, `audit-logs` and the incident-analysis fork, opt-in post-patch validation and rules for live probes, the GitHub Actions workflow pass, a per-project layout with a contract marker for the Rust tools, and checks for forensic readiness and from a comparison with Cloudflare's audit skill. It is the minor release that closes the 7.6.x patch series.
- **7.6.1** — New CI checks (an advisory macOS job with bash 3.2 and BSD tools, frontmatter and pipefail checks, a weekly plugin validation), PoC verdicts bound to the assertions that ran, hardened incident collection and recipes, and `install.sh`'s new default path, outside any repository. The Trail of Bits pin moved to `1f68e03`.
- **7.6.0** — Detection and response after an incident, threat models seeded from history, GitHub Actions trigger trust, the operating-safety rules (Rule 11), and a reviewed Trail of Bits pin.
- **7.5.0** — A slot used as a clock after SIMD-0525 and Alpenglow: KV-138 and nine checks.
- **7.4.0** — Vendored-program provenance after the Rain white-label card-contract exploit: KV-137, AC-051..055 and SC-053..058.

## Documentation

| Page | Contents |
|------|----------|
| [docs/getting-started.md](docs/getting-started.md) | Install, submodule init, build the Rust tools, run your first audit |
| [docs/audit-flows.md](docs/audit-flows.md) | The three depths and CI, and the pipeline each one follows (`/diff-audit`, `/audit`, `/audit-cycle`, `/audit-assist`, `/re-audit`) |
| [docs/ci.md](docs/ci.md) | CI for pull requests: the workflow template, its two jobs, `--ci` and `--fail-on`, what the verdict means, and how to read the details of a public repository's run |
| [docs/commands.md](docs/commands.md) | Reference for all 17 commands |
| [docs/agents.md](docs/agents.md) | The 9-agent roster and how they chain |
| [docs/power-tools.md](docs/power-tools.md) | `audit-scan`, `audit-mem`, Trail of Bits, Surfpool, PoC/patch harnesses and the bundled scripts |
| [docs/poc-and-patches.md](docs/poc-and-patches.md) | Executable exploit + fix-patch delivery |
| [docs/output-and-rigor.md](docs/output-and-rigor.md) | Severity, the Rule 5b gate, scope-gated loading, report format |
| [docs/detection-response.md](docs/detection-response.md) | Post-incident hunting + incident workup (`/auditor:hunt`, `/auditor:respond`) |
| [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md) | Default and strict mode, what runs without asking and why that is safe, what still asks, strict mode and isolated runs, `claude -p`, the risks that remain |
| [docs/faq.md](docs/faq.md) | Questions people ask: a professional audit, the model, how long, CI, projects outside Solana |
| [docs/other-agents.md](docs/other-agents.md) | auditor-skill with Copilot, Cursor, Windsurf, Codex or an LLM API: install, prompts, what changes without the plugin |
| [docs/changelog.md](docs/changelog.md) | What each release added |
| [docs/repository-layout.md](docs/repository-layout.md) | Every folder and file of this repository |
| [docs/README.md](docs/README.md) | The docs index, with a goal-to-command table |

The root files the agent reads: [SKILL.md](SKILL.md) (the orchestrator, read first), [OUTPUT-RULES.md](OUTPUT-RULES.md) (the output format, the severity scale and the operating-safety rules), [FULL-AUDIT.md](FULL-AUDIT.md) (the step-by-step plan of a complete audit), [QUESTIONS.md](QUESTIONS.md) (the 47-question intake) and [AGENTS.md](AGENTS.md) (agent orchestration). For people: [COSTS.md](COSTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [ATTRIBUTION.md](ATTRIBUTION.md).

## Folder structure

| Path | What it holds |
|------|---------------|
| `SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `QUESTIONS.md`, `AGENTS.md` | the skill the agent reads, its output rules, the full-audit plan, the intake questionnaire and the agent overview |
| `checklists/` | the 20 checklists |
| `known-vectors/` | the 141 known vectors, and `INDEX.md` |
| `references/` | methodologies, framework idioms, vulnerability classes, the invariant catalog, false-positive rules, the audit lifecycle, detection & response, orchestration, `depth-scope.md` |
| `discovery/` | the file map and the grep commands by category |
| `commands/`, `agents/`, `skills/` | the 17 commands, the 9 agents and the `dnr-analyze` skill |
| `templates/` | report templates, worksheets, the PoC and patch templates, `strict-settings.json` and the CI workflow |
| `tools/auditor-tools/` | the Rust tools `audit-scan`, `audit-mem` and `audit-logs` |
| `scripts/` | preflight, run directories, read-only git, the runners, recipes, collectors, the CI checks and their tests |
| `vendor/trailofbits/` | the Trail of Bits plugins, a pinned git submodule |
| `docs/` | the usage guides |

The full tree, with what each file is for: [docs/repository-layout.md](docs/repository-layout.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first — branch + PR flow (nothing lands on `main` directly), the corpus-count consistency rule enforced by `scripts/check-corpus.sh` in CI, and the no-AI-attribution commit policy (enable the hook with `git config core.hooksPath scripts/hooks`). How to add a known vector, checklist items or a protocol methodology: [CONTRIBUTING.md §4](CONTRIBUTING.md#4-adding-corpus-content). When models or prices change, re-measure and update [COSTS.md](COSTS.md).

## Inspirations and acknowledgments

### Benchmarking

This auditor was designed by comparing methodology from:

| Standard | Domain | What We Took |
|----------|--------|-------------|
| **CertiK** | Crypto audit | On-chain vulnerability taxonomy, formal verification approach |
| **EY / SOC 2** | Enterprise IT audit | Control objectives, evidence requirements |
| **OWASP Top 10:2025** | Web security | Attack categories, severity calibration |
| **NIST SP 800-53** | Government security | Control framework structure |
| **COBIT 2019** | IT governance | Process maturity model |
| **GDPR / MiCA / DORA** | EU regulation | Compliance checklist items |

The Full lifecycle is modelled on how audit firms work: Neodyme's two independent reviews of the same scope, reconciled; Trail of Bits' reasoning from invariants and attacker goals, with a checklist as the floor; Zellic's reports ordered by importance; and Zenith's review across code revisions ([references/audit-lifecycle/firm-coverage.md](references/audit-lifecycle/firm-coverage.md)).

### Acknowledgments

auditor-skill builds on these open-source security projects, credited in full in [ATTRIBUTION.md](ATTRIBUTION.md):

- **[Frank Castle](https://github.com/Frankcastleauditor) — [safe-solana-builder](https://github.com/Frankcastleauditor/safe-solana-builder)** (MIT): Solana security depth — reward/staking accounting, Token-2022 extension abuse, framework validation idioms, zero-copy footguns — adapted natively and re-authored audit-side.
- **[Trail of Bits](https://github.com/trailofbits) — [skills](https://github.com/trailofbits/skills)** (CC-BY-SA 4.0): tool-execution methodology (SAST, fuzzing, coverage, mutation, IR analysis, post-patch validation), vendored as a git submodule at `vendor/trailofbits` and orchestrated for real execution; methodology patterns re-implemented natively are credited by reference.
- **[Anthropic](https://github.com/anthropics) — [defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness)** (Apache-2.0): the detection & response method (a written hypothesis ledger, a three-leg verdict ladder, response plans that people carry out), re-expressed Solana-native in `/auditor:hunt` and `/auditor:respond`; the threat-model bootstrap / bootstrap-then-interview pattern, re-expressed for Solana in `/auditor:threat-model --bootstrap`.
- **[Sentry](https://github.com/getsentry) — [gha-security-review](https://github.com/getsentry/skills/tree/main/skills/gha-security-review)** (Apache-2.0, in [getsentry/skills](https://github.com/getsentry/skills)): the GitHub Actions vector inventory behind `references/vuln-classes/github-actions.md`, re-written natively (no text copied).
- **[Cloudflare](https://github.com/cloudflare) — [security-audit-skill](https://github.com/cloudflare/security-audit-skill)** (MIT): the execution-isolation, output-hygiene and CI-trust principles, paraphrased and adapted natively in `OUTPUT-RULES.md` Rule 11a's isolated mode (opt-in; native is the default) and Rule 11d and in `references/vuln-classes/github-actions.md`; and the ideas behind checklist items SC-063..065, BE-133, RS-022..023 and AI-036..039; see [ATTRIBUTION.md](ATTRIBUTION.md).

ATTRIBUTION.md also lists the skill packs that were assessed and not vendored, with what was taken from each. All third-party methodology is used by *reference* — no third-party text is copied into this repository.

## License

MIT ([LICENSE](LICENSE)) — use it, fork it, improve it, sell services built on it. Attribution appreciated but not required. The Trail of Bits plugins in `vendor/trailofbits` stay under their own CC-BY-SA 4.0 licence: a submodule is a reference, not a copy.
