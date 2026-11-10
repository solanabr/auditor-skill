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

It covers the on-chain programs (Anchor, native and Pinocchio) and the rest of the stack: TypeScript and Rust services, web frontends, Python, Go, Java, Ruby and PHP code, CI workflows, infrastructure and AI agent components. It is not a SaaS product: you install it for your agent, outside any repository you audit, or send its files to an LLM API.

**What's inside:** 20 checklists · 1,465 verification items · 141 known attack vectors · executable PoCs + fix patches.

## Read this first: what auditor-skill cannot do on its own

> [!WARNING]
> **It is a first pass, not a professional audit.** An AI auditor cannot do everything a human can: social engineering assessment, business-logic review that needs domain expertise, legal compliance opinions. Before a mainnet launch, pair it with a human audit. Like a firm's, its client report gives no "safe to deploy" guarantee.
>
> **By default it builds and tests the project on your machine**, which runs the project's own build scripts, proc-macros and tests. For code you don't trust, use strict mode with the [strict launch line](#permissions-and-isolation), which also keeps your own plugins out, such as a language server that would run those build scripts too.
>
> **The resume rules let Claude start a flow by itself**, in any repository you open ([Once, after installing](#once-after-installing)).
>
> **The incident commands only propose.** They never sign, send, pause or freeze anything. If funds may be moving, page your on-call, run the pause or freeze runbook and open a SEAL 911 ticket first.
>
> What remains a risk in each mode: [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#what-remains-a-risk).

## Quick start

Install the plugin in Claude Code:

```
/plugin marketplace add solanabr/auditor-skill
/plugin install auditor
```

Then, in the repository you want to review, check what your branch changed against `main` (commit your work and rebase on `main` first):

```
/auditor:diff-audit
```

It writes `audit_<n>/PR-REPORT.md`, in a run directory that git ignores. Every item a run reads gets a verdict, in the format `OUTPUT-RULES.md` Rule 4 sets (this is its example):

```text
[PASS]      AV-001: Account ownership validated via Account<'info, T> typed accounts
[FAIL-8]    AV-015: Token account missing token::authority constraint
              File: programs/<program>/src/instructions/deposit.rs:42
              Impact: Attacker can substitute token account, draining vault
              Fix: Add `token::authority = fund` to account constraint
```

Next, add the [resume rules](#once-after-installing) once, and [pick a depth](#pick-a-depth).

**On this page:** [Features](#what-it-does-v77) · [Corpus](#the-corpus) · [Installation](#installation) · [Usage](#usage) · [Output](#output-format) · [Configuration](#configuration) · [Integrations](#integrations) · [Security model](#security-model-and-limitations) · [Upgrading](#upgrading) · [What's new](#whats-new) · [Docs](#documentation) · [Layout](#folder-structure) · [Contributing](#contributing) · [Credits](#inspirations-and-acknowledgments) · [License](#license)

## What It Does (v7.7)

- **Three depths and a CI mode:** Quick for a change, Standard for a module, Full for a release, and CI for every pull request ([Pick a depth](#pick-a-depth)).
- **A full audit-firm lifecycle, two ways:** `/auditor:audit-cycle` runs intake → context → threat model → tool-assisted pass → domain-partitioned review → triage → independent peer review → synthesis unattended, and `/auditor:audit-assist` pauses at checkpoints for your calls ([audit-flows.md](docs/audit-flows.md#full)).
- **History-seeded threat models:** `/auditor:threat-model --bootstrap` starts from removed account guards, reverts, a fork's parent, prior audits and incidents ([commands.md](docs/commands.md#auditorthreat-model)).
- **Rigor gates against AI over-reporting:** a finding of severity 6 or more must survive a validation gate or be downgraded, and every in-scope item gets an explicit verdict ([output-and-rigor.md](docs/output-and-rigor.md)).
- **Executable proofs, not just prose:** `/auditor:poc` builds a runnable exploit that asserts the flaw, and `/auditor:patch` drafts a minimal fix and proves it reverts the exploit, with opt-in post-patch validation ([poc-and-patches.md](docs/poc-and-patches.md)).
- **Deep Solana coverage:** 13 protocol methodologies (AMM/CLMM, lending, perps, oracles, stablecoins, liquid staking, governance, bridges, multisig/custody, Token-2022, NFT marketplaces, launchpads, token registries & risk signals), framework idioms (Anchor/Native/Pinocchio) and an invariant catalog, loaded only when the code triggers them ([The corpus](#the-corpus)).
- **Whole classes of risk:** playbooks for ZK proofs and compression, transaction v1, GitHub Actions trigger trust, and the host kernel and network surface of validators, RPC nodes and keepers.
- **Dependency updates:** checklist 11 §11.11 reviews what a bump's published code changed, and diff-audit runs it on a changed lockfile within a budget ([checklist 11](checklists/11-supply-chain.md)).
- **Detection and response, after an incident:** `/auditor:hunt` and `/auditor:respond` work from transaction history and only propose ([After an incident](#after-an-incident)).
- **Rust tools:** `audit-scan` maps the risky surface with no model calls, `audit-mem` remembers findings across audits, and `audit-logs` runs the incident recipes offline ([power-tools.md](docs/power-tools.md)).
- **17 commands, 9 specialized agents:** [every command](#every-command), and [the agents](docs/agents.md).
- **Real tooling, vendored:** Trail of Bits execution plugins (SAST, fuzzing, coverage, mutation) ship as a git submodule; the native corpus works fully without them ([Tool execution](#tool-execution-trail-of-bits--optional-rust-tools)).
- **Operating safety, in two modes:** by default what strict mode would refuse is a note in the report; strict mode, for code you don't trust, refuses it and builds only in isolated mode ([Security model](#security-model-and-limitations)).

What each release added: [What's new](#whats-new).

## The corpus

- **Checklists:** 20 files, 1,465 verification items, each a check an auditor can mark PASS, FAIL or N/A from the code.
- **Known vectors:** 141 attack procedures with numbered verification steps, indexed in [`known-vectors/INDEX.md`](known-vectors/INDEX.md).
- **References:** `references/methodologies/` holds 13 protocol playbooks (amm-clmm, lending, perps, oracles, stablecoin, liquid-staking, governance, bridges, wallets-multisig-custody, token-2022, nft-marketplaces, launchpads, token-registry-risk). Beside them sit the framework idioms, four vulnerability-class playbooks, the invariant catalog, the false-positive rules, the audit lifecycle, the detection & response track, and `references/depth-scope.md`, the selection quick-scan and diff-audit read.

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

Checklists 01-07 are Solana-specific, so the others make the corpus work for projects outside Solana too.

<details>
<summary>The 20 checklists, with their item counts</summary>

- `01-program-account-validation.md` (90 items)
- `02-program-access-control.md` (55 items)
- `03-program-arithmetic-safety.md` (63 items)
- `04-program-cpi-pda.md` (70 items)
- `05-program-state-machine.md` (74 items)
- `06-program-economic-logic.md` (92 items)
- `07-program-opsec-governance.md` (87 items)
- `08-typescript-safety.md` (64 items)
- `09-backend-security.md` (133 items)
- `10-frontend-security.md` (84 items)
- `11-supply-chain.md` (65 items)
- `12-secrets-opsec.md` (53 items)
- `13-deployment-infrastructure.md` (102 items)
- `14-python-safety.md` (82 items)
- `15-general-language-safety.md` (88 items)
- `16-formal-verification-testing.md` (73 items)
- `17-logging-monitoring-incident-response.md` (68 items)
- `18-privacy-compliance-change-management.md` (60 items)
- `19-ai-agent-security.md` (39 items)
- `20-rust-offchain-services.md` (23 items)

</details>

### Scope-gated loading

auditor-skill does not bulk-read its corpus. It declares a scope ([OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 0) and loads root docs and `OUTPUT-RULES.md` always, only the `checklists/*.md` the detected languages require, a `known-vectors/*.md` file when its phase and language trigger reach it, and `discovery/*.md` and `templates/*.md` lazily, at the phase that uses them. An audit is complete when every in-scope item has a verdict; out-of-scope items render `[N/A — out of scope]` ([output-and-rigor.md](docs/output-and-rigor.md#scope-gated-loading)).

## Installation

Install auditor-skill **outside any repository you audit**: a copy inside it runs from a tree that repository controls ([OUTPUT-RULES.md Rule 11e](OUTPUT-RULES.md#11e--bundled-paths)). All four routes in detail: [docs/getting-started.md](docs/getting-started.md), "Install".

**The plugin (recommended).** In Claude Code:

```
/plugin marketplace add solanabr/auditor-skill
/plugin install auditor
```

It installs the 17 `/auditor:*` commands and 9 agents, and fetches the Trail of Bits submodule at the pinned commit.

**The other routes:**

- **The install script**, read first, installs a user-level skill at `~/.claude/skills/auditor-skill` by default:

  ```bash
  git clone https://github.com/solanabr/auditor-skill.git
  ./auditor-skill/install.sh ~/.claude/skills/auditor-skill
  # or: curl -fsSL https://raw.githubusercontent.com/solanabr/auditor-skill/main/install.sh | bash -s -- ~/.claude/skills/auditor-skill
  ```

  Run again, it moves the earlier install, without running git in it, to `$XDG_STATE_HOME/auditor-skill/backup-<timestamp>`, or `~/.local/state/auditor-skill/` when that variable is unset or not absolute, and prints the path. Each backup is a full copy, build output included, and stays until you delete it. The backup directory must lie outside every skills directory: the run refuses one inside the install's parent, or under a directory named `.claude`, `skills`, `commands` or `agents` in any letter case, as given or with links resolved, and refuses a symbolic link at the install path or the backup directory.
- **A clone** at `~/.claude/skills/auditor-skill` is a user-level skill; Claude Code 2.1.157 and later also loads it as the plugin, unless managed settings block that. It needs the submodule step [below](#tool-execution-trail-of-bits--optional-rust-tools).
- **Another agent, or an LLM API:** [Other agents](#other-agents).

### Once, after installing

1. Add these rules, which name no path, to `permissions.allow` in `~/.claude/settings.json`, so a flow resumes after your reply without a prompt in Manual mode:

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

2. With the install script or a clone, add `"Skill(auditor-skill)"` and `"Skill(auditor-skill *)"` too.
3. Know what they allow: Claude can start these flows by itself, in any repository, and `/auditor:audit-cycle` started that way builds the project. To rule that out, set `AUDITOR_EXEC_MODE=isolated` (or `none`) in that file's `env`, or pass the rules with `claude --settings` when you audit ([Turns and resuming](docs/permissions-and-isolation.md#turns-and-resuming)).
4. Build the Rust tools, [below](#tool-execution-trail-of-bits--optional-rust-tools).

### Tool execution (Trail of Bits) + optional Rust tools

auditor-skill vendors **Trail of Bits** ([trailofbits/skills](https://github.com/trailofbits/skills), CC-BY-SA 4.0) as a git submodule (`vendor/trailofbits`) for real tool execution — SAST, fuzzing, coverage, mutation. The plugin and the install script fetch it; for a clone, run `git submodule update --init --depth 1 -- vendor/trailofbits` in the auditor-skill folder.

**Pinned at** [`711af09`](https://github.com/trailofbits/skills/tree/711af095215ad4ecde5b90cd1d0124b3f1c4ca9e) — trailofbits/skills `main` of 2026-11-02. Upstream publishes no tags or releases, so the pin is a commit, and it moves only after a reviewed bump ([CONTRIBUTING.md §5](CONTRIBUTING.md#5-tooling-changes)); CI fails if this line and the submodule disagree, and plugin installs receive a new pin with the next release. To read the pin of any checkout without initializing the submodule: `git ls-tree HEAD vendor/trailofbits`.

Without the submodule the corpus falls back to grep-based checks and notes where deeper tooling would run ([power-tools.md](docs/power-tools.md#trail-of-bits-plugins)). The optional Rust tools, `audit-scan`, `audit-mem` and `audit-logs`, build in the installation (`<auditor-skill root>`), and need a rebuild after every update, since the flows pass a contract marker that an older build refuses ([getting-started.md](docs/getting-started.md), "Build the Rust tools"):

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release --locked
```

### Permissions and isolation

The commands run their bundled steps without asking, each checking its own arguments and writing only into the auditor's own directories; other calls ask. By default what strict mode would refuse is a note in the report, apart from the few shapes Rules 11e and 11f list. For code you don't trust, start Claude Code with the strict launch line, which loads none of your own settings or plugins, refuses what default mode only notes, and builds only in isolated mode ([docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#default-and-strict-mode)):

```bash
claude --setting-sources "" --strict-mcp-config --plugin-dir "<auditor-skill root>" --settings "<auditor-skill root>/templates/strict-settings.json"
```

## Usage

### Pick a depth

Pick by what you want checked: what changed, one module, or the release.

| Depth | When | Run | [Cost and time](COSTS.md#cost-and-time-by-depth) |
|-------|------|-----|------|
| **Quick** | a branch or pull request, a first look at a repository, one function | `/auditor:diff-audit` · `/auditor:quick-scan` (whole repository) · `/auditor:deep-review <file> <fn>` | $2–8 · 4–23 min |
| **Standard** | one module or program before it merges | `/auditor:audit <path> --scope …` | $13–19 · 36–56 min |
| **Full** | a release, or a report for someone outside the team | `/auditor:audit-cycle` (unattended) · `/auditor:audit-assist` (you steer) · `/auditor:re-audit` after fixes | about $20 · about 1 h, on a 3K-line program |
| **[CI](docs/ci.md)** | every pull request: the analyzers on all of them, the review on those from your own branches | `templates/ci/auditor-pr.yml`: a tools job, then `/auditor:diff-audit --ci` | tools job $0; review about a diff-audit's cost, capped at $15 |

Quick and Standard need nothing set; Full starts with intake ([QUESTIONS.md](QUESTIONS.md)), and Standard and Full take a `--scope` ([SKILL.md](SKILL.md#scope-gated-loading--load-what-the-repo-needs)). The costs come from one run each, with `claude-opus-5-5`, on 3K-, 7K- and 12K-line programs, measured from 2026-11-08 to 2026-11-10 ([COSTS.md](COSTS.md)). A diff-audit of a narrow change to the 12K-line program, 1,248 lines with no lockfile, cost $3.99 in 9 minutes. What each depth reads and writes: [audit-flows.md](docs/audit-flows.md#pick-a-depth).

### Claude Code with the plugin

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

`diff-audit` reviews commits, so commit your work and rebase on `main` first. Every command and its arguments: [docs/commands.md](docs/commands.md).

### Every command

There are 17 commands, each run as `/auditor:<name>`. Three are Quick, one is Standard and three make up Full; the others work on findings, build a Full run's pieces, assemble a report, check code against a spec, or handle an incident.

| Command | Where it fits | What it does | Writes, in `audit_<n>/` |
|---------|---------------|--------------|-------------------------|
| `diff-audit [base..head]` | Quick | the commits of a branch or pull request, with one hop of callers and callees | `PR-REPORT.md` |
| `quick-scan [<path>]` | Quick | a first look: SAST, dependency advisories, the selection of `references/depth-scope.md` | `QUICK-SCAN.md` |
| `deep-review <file> [fn]` | Quick | one function or instruction, in depth | `DEEP-REVIEW-<unit>.md` |
| `audit [path] [--scope …]` | Standard | a verdict for every in-scope item | `REPORT.md`, internal |
| `audit-cycle [--with-poc]` | Full | the whole lifecycle, unattended | `REPORT.md`, client |
| `audit-assist` | Full | the same lifecycle, pausing for your calls | `REPORT.md`, client |
| `re-audit [prior] [base..head]` | Full, after fixes | each prior finding's status, new findings in the change, unpatched siblings of each fix | `RE-AUDIT.md`, in `audit_<n+1>/` |
| `intake` | Full's first step | scope, protocol class, severity calibration, trust model, execution mode, live probes | `intake.md` |
| `threat-model [--bootstrap]` | Full's building block | assets, actors, trust boundaries and attacker goals, seeded from history with `--bootstrap` | `threat-model.md` |
| `triage` | a set of findings | de-duplicates by root cause and re-applies the validation gate | the triaged set |
| `economic-sim <finding>` | one finding | the dollar profit and loss of an economic attack, on a Surfpool fork when available | the quantified PoC |
| `poc <finding>` | one finding | a runnable exploit that asserts the flaw | `poc/F-xxx/`, a `[PoC-*]` tier |
| `patch <finding>` | one finding | a minimal fix, checked against the exploit | `patches/F-xxx.patch`, a `[FIX-*]` tier |
| `audit-report [dir]` | reporting | the internal report, from a walk run in pieces | `REPORT.md` |
| `spec-audit <spec> [path]` | outside the depths | the code against a spec, a whitepaper or an RFC | a compliance matrix |
| `hunt [<address> …]` | after an incident | looks for an attack with no alert to start from | `INCIDENT_REPORT.md`, in `incident_<n>/` |
| `respond <lead>` | after an incident | one lead: whether it landed, the damage, the root cause, a plan | `RESPONSE-INC-<n>.<k>.md` |

Two skills ship beside them: `auditor:dnr-analyze` runs one analysis phase of `hunt` or `respond` as a fork of the incident-responder agent, and the root skill, `auditor:auditor-skill`, runs when you ask in plain words.

### After an incident

`/auditor:hunt` looks for an attack with no alert to start from, and `/auditor:respond` works one lead, such as a signature, an address or an alert, to whether it landed, the damage per mint, the root cause and a plan for people to carry out. Both read transaction history, program logs and Geyser or indexer exports, and neither signs, sends, pauses or freezes anything. Run your pause or freeze runbook first: these are the after-the-fact workup ([docs/detection-response.md](docs/detection-response.md)).

### CI for pull requests

Copy `templates/ci/auditor-pr.yml` into `.github/workflows/`, pin it to the full commit id of a `main` commit that holds the template, since no release tag holds it yet, and follow [docs/ci.md](docs/ci.md#setup). Its tools job runs semgrep, `cargo audit` and `npm audit` on every pull request with no secrets. Its review job runs `/auditor:diff-audit --ci` on pull requests from your own branches, other than Dependabot's, capped at $15. On a public repository it publishes pass or fail only.

### Models and time

Seven agents run on Opus, and context-builder and audit-reporter on Sonnet; quick-scan and diff-audit start no agent, so your session's model runs them. Quick scales with the change, Standard with the module, and Full takes longest ([docs/faq.md](docs/faq.md#how-long-does-an-audit-take), [COSTS.md](COSTS.md)).

## Output format

Every run writes into a run directory, `audit_<n>/` or `incident_<n>/`, that git ignores. Quick writes `PR-REPORT.md`, `QUICK-SCAN.md` or `DEEP-REVIEW-<unit>.md`, each opening with a summary. Standard writes the internal `REPORT.md`, with a risk score and a deploy verdict. Full writes the client `REPORT.md`, with a commit-pinned scope, a code-maturity assessment and disclaimers, and no "safe to deploy" guarantee ([output-and-rigor.md](docs/output-and-rigor.md#two-report-templates)). High and Critical findings can add `poc/` and `patches/` ([poc-and-patches.md](docs/poc-and-patches.md)). A PDF needs pandoc 2.15 or later and a PDF engine:

```bash
"<auditor-skill root>/scripts/report-to-pdf.sh" audit_1/REPORT.md   # MD is always the deliverable
```

Every output file: [output-and-rigor.md](docs/output-and-rigor.md#report-file-naming). The specification: [OUTPUT-RULES.md](OUTPUT-RULES.md).

## Configuration

auditor-skill reads no configuration file of its own. Environment variables, command flags and the intake answers set a run:

| Setting | Default | What it does |
|---------|---------|--------------|
| `AUDITOR_STRICT=1`, `--strict` or intake's "Untrusted source" | off | strict mode ([Rule 11f](OUTPUT-RULES.md#11f--default-and-strict-mode)) |
| `AUDITOR_EXEC_MODE` | native | `native`, `isolated` or `none`: how the runners build and test ([Rule 11a](OUTPUT-RULES.md#rule-11-operating-safety)) |
| `AUDITOR_PUBLISH_AGE` | on | `off` stops a lockfile review's publish-age lookups ([docs/ci.md](docs/ci.md#setup)) |
| `BASH_DEFAULT_TIMEOUT_MS`, `BASH_MAX_TIMEOUT_MS` | two minutes | raised, they keep a long build inside the command's pre-approvals ([Long steps](docs/permissions-and-isolation.md#long-steps)) |

The command flags are in [docs/commands.md](docs/commands.md), and the CI template's settings in [docs/ci.md](docs/ci.md#setup). For Full, intake records where your code lives instead of `discovery/file-map.md` ([getting-started.md](docs/getting-started.md), "Adapt to your repo").

## Integrations

### solana-ai-kit

[solana-ai-kit](https://github.com/solanabr/ai-kit) vendors auditor-skill as a skill pack at a pinned commit and never runs `install.sh`, so a release reaches kit users when the kit moves its pin ([CONTRIBUTING.md §5](CONTRIBUTING.md#bumping-vendortrailofbits)). A kit project ships its own `.claude/` and `.mcp.json`: default mode notes them, and strict mode refuses the tree.

### Other agents

An agent without the plugin's commands reads the skill. Copy the folder outside the repository you audit, point the agent at its `SKILL.md`, and ask in plain words; [docs/other-agents.md](docs/other-agents.md) has the prompts for Copilot, Cursor, Windsurf, Codex and the API:

```text
Read ~/.claude/skills/auditor-skill/SKILL.md then audit this repository following that installation's FULL-AUDIT.md execution plan
Read the auditor-skill files in ~/.claude/skills/auditor-skill/ and perform a full security audit of this repository
```

### Surfpool

`/auditor:economic-sim` and `/auditor:poc --fork` replay an economic attack on a Surfpool mainnet fork when the `surfpool` CLI and its MCP server are available ([power-tools.md](docs/power-tools.md#surfpool-economic-simulation)).

## Security model and limitations

- **In both modes** git only reads, the auditor writes only into its run directories, the `audit-mem` store and scratch directories, none of your credentials is used, and every pre-approved tool checks its arguments.
- **Strict mode holds** only when Claude Code starts with the strict launch line, or with `AUDITOR_STRICT=1` in managed settings; otherwise the repository's own settings apply first and can switch it off.
- **Outside services are disclosed, not gated:** the report lists each one, such as the public registries a lockfile review asks while `AUDITOR_PUBLISH_AGE` is on ([Rule 11b](OUTPUT-RULES.md#11b--outside-service-disclosure)).
- **Output stays private:** run directories ignore themselves in git, and CI on a public repository publishes pass or fail only ([Rule 11d](OUTPUT-RULES.md#11d--output-hygiene)).

What remains a risk: [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#what-remains-a-risk). To report a vulnerability in auditor-skill itself, see [SECURITY.md](SECURITY.md).

## Upgrading

Plugin users get each change, a new Trail of Bits pin included, when they update the plugin, and an `install.sh` install on its next run. Rebuild the Rust tools after every update.

### Upgrading from 7.6.0 or earlier

Through 7.6.0, `install.sh` without a path installed into the current directory's `.claude/skills/auditor-skill`; it now installs to `~/.claude/skills/auditor-skill`, and a run started next to such a copy notes it and leaves it alone. If your copy sits inside a repository, delete it (`rm -rf .claude/skills/auditor-skill`) and install a fresh one outside; never move or update a copy you find inside a repository ([getting-started.md](docs/getting-started.md), "Install").

### Upgrading from 7.6.x or 7.7.0

7.7.2 made the security checks opt-in: a check that used to stop the run prints a note, and strict mode keeps the refusals.

- **If you set isolated mode on the old advice,** every build now stops at the isolation self-check on a normal machine: unset `AUDITOR_EXEC_MODE` and write `native` to the run directory's `exec-mode` ([Strict mode and isolated runs](docs/permissions-and-isolation.md#strict-mode-and-isolated-runs)).
- **To keep the refusals,** turn on strict mode and start with the strict launch line.
- **Anchor projects build in the runners:** avm's `anchor`, Anchor 1.x's IDL step, Anchor 1.2's platform tools and anchor-cli 0.31.1 all work since 7.7.2 ([changelog](docs/changelog.md#772-70-and-58-before-it)).
- **Rebuild the Rust tools:** an `audit-logs` built before 7.7.2 exits 4.

## What's new

Newest first; each entry in full, with the earlier releases: [docs/changelog.md](docs/changelog.md).

- **7.7.3** — Three depths and a CI mode: `references/depth-scope.md`, diff-audit's line and lockfile budgets, the `templates/ci/auditor-pr.yml` workflow, a named report from each Quick command, a Generated line in every report (`rundir.sh stamp`) that says no person reviewed it unless `AUDITOR_REVIEW_STATEMENT` says otherwise, and measured costs.
- **7.7.2** — Strict mode is opt-in, builds run natively by default, and Anchor builds work in the runners. It also brings the host kernel and network attack surface: KV-141, DEP-097..102 and a playbook.
- **7.7.0** — Bundled steps run without asking, `audit-logs` and the incident-analysis fork, post-patch validation, rules for live probes, the GitHub Actions workflow pass, a per-project layout, and checks for forensic readiness and from a comparison with Cloudflare's audit skill.
- **7.6.1** — New CI checks, PoC verdicts bound to the assertions that ran, hardened incident recipes, `install.sh` outside any repository, and the Trail of Bits pin `1f68e03`.
- **7.6.0** — Detection and response, history-seeded threat models, GitHub Actions trigger trust, the operating-safety rules, and a reviewed Trail of Bits pin.
- **7.5.0** — A slot used as a clock after SIMD-0525 and Alpenglow: KV-138 and nine checks.
- **7.4.0** — Vendored-program provenance after the Rain white-label exploit: KV-137, AC-051..055 and SC-053..058.

## Documentation

| Page | Contents |
|------|----------|
| [docs/README.md](docs/README.md) | the docs index, with a goal-to-command table |
| [docs/getting-started.md](docs/getting-started.md) | install, the submodule, the Rust tools, a first audit |
| [docs/audit-flows.md](docs/audit-flows.md) | the depths and CI, and the pipeline each follows |
| [docs/commands.md](docs/commands.md), [docs/agents.md](docs/agents.md) | the 17 commands and the 9 agents |
| [docs/ci.md](docs/ci.md) | the pull-request workflow and what its verdict means |
| [docs/output-and-rigor.md](docs/output-and-rigor.md) | severity, the validation gate, the report formats |
| [docs/poc-and-patches.md](docs/poc-and-patches.md) | executable exploits and verified fixes |
| [docs/detection-response.md](docs/detection-response.md) | the post-incident track |
| [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md) | default and strict mode, isolated runs, `claude -p`, what remains a risk |
| [docs/power-tools.md](docs/power-tools.md) | `audit-scan`, `audit-mem`, Trail of Bits, Surfpool, the PoC/patch harnesses, and the index of the bundled scripts, whose reference is on four pages |
| [docs/faq.md](docs/faq.md), [docs/other-agents.md](docs/other-agents.md) | questions people ask; auditor-skill without the plugin |
| [docs/changelog.md](docs/changelog.md), [docs/repository-layout.md](docs/repository-layout.md) | what each release added; every folder and file |

The agent reads [SKILL.md](SKILL.md), [OUTPUT-RULES.md](OUTPUT-RULES.md), [FULL-AUDIT.md](FULL-AUDIT.md), [QUESTIONS.md](QUESTIONS.md) and [AGENTS.md](AGENTS.md). For people: [COSTS.md](COSTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [ATTRIBUTION.md](ATTRIBUTION.md).

## Folder structure

The skill's files sit at the top (`SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `QUESTIONS.md`, `AGENTS.md`), beside `checklists/`, `known-vectors/`, `references/` and `discovery/`, the plugin's `commands/`, `agents/` and `skills/`, the `templates/`, the Rust tools in `tools/auditor-tools/`, the bundled `scripts/`, the Trail of Bits submodule in `vendor/trailofbits/`, and `docs/`. The full tree: [docs/repository-layout.md](docs/repository-layout.md).

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

The Full lifecycle is modelled on how audit firms work ([firm-coverage.md](references/audit-lifecycle/firm-coverage.md)).

### Acknowledgments

auditor-skill builds on these projects, credited in full, with what was taken from each, in [ATTRIBUTION.md](ATTRIBUTION.md):

- **[Frank Castle](https://github.com/Frankcastleauditor) — [safe-solana-builder](https://github.com/Frankcastleauditor/safe-solana-builder)** (MIT): Solana security depth (reward and staking accounting, Token-2022 extension abuse, framework validation idioms, zero-copy footguns), re-authored audit-side.
- **[Trail of Bits](https://github.com/trailofbits) — [skills](https://github.com/trailofbits/skills)** (CC-BY-SA 4.0): tool execution, vendored at `vendor/trailofbits`.
- **[Anthropic](https://github.com/anthropics) — [defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness)** (Apache-2.0): the detection & response method and the threat-model bootstrap, re-expressed for Solana.
- **[Sentry](https://github.com/getsentry) — [gha-security-review](https://github.com/getsentry/skills/tree/main/skills/gha-security-review)** (Apache-2.0): the GitHub Actions vector inventory, re-written natively.
- **[Cloudflare](https://github.com/cloudflare) — [security-audit-skill](https://github.com/cloudflare/security-audit-skill)** (MIT): the isolation, output-hygiene and CI-trust principles, and the ideas behind SC-063..065, BE-133, RS-022..023 and AI-036..039.

All third-party methodology is used by *reference* — no third-party text is copied into this repository.

## License

MIT ([LICENSE](LICENSE)) — use it, fork it, improve it, sell services built on it. Attribution appreciated but not required. The Trail of Bits plugins in `vendor/trailofbits` keep their CC-BY-SA 4.0 licence: a submodule is a reference, not a copy.
