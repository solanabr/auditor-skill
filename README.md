<p align="center">
  <img src="assets/banner.png" alt="auditor-skill — the best all-in-one security audit skill for Solana programs and applications" width="100%">
</p>

# auditor-skill — Open-Source AI Security Audit Skill

auditor-skill is a Claude Code plugin that security-reviews Solana programs and the code around them. Pick a depth:

- **Quick** on a branch or pull request: `/auditor:diff-audit`.
- **Standard** on one module before it merges: `/auditor:audit programs/<name> --scope program`.
- **Full** before a release, with a client-style report: `/auditor:audit-cycle`.

CI runs Quick on every pull request ([docs/ci.md](docs/ci.md)). Quick, Standard and Full need nothing beyond installing the plugin; intake is part of Full only.

| Depth | When | Run | Reads | Writes | [Cost](COSTS.md#cost-and-time-by-depth) |
|-------|------|-----|-------|--------|------|
| **Quick** | a branch or pull request, a first look at a repository, one function | `/auditor:diff-audit` · `/auditor:quick-scan` (whole repository) · `/auditor:deep-review <file> <fn>` | the changed code + one hop, read against the sections and vectors `references/depth-scope.md` selects · SAST, dependency advisories, and the sections and vectors `references/depth-scope.md` selects · one function | `PR-REPORT.md` · `QUICK-SCAN.md` · `DEEP-REVIEW-<unit>.md` | $2–7 · 4–23 min |
| **Standard** | one module or program before it merges | `/auditor:audit <path> --scope …` | every in-scope item for that path | `REPORT.md`, internal: a risk score and a deploy verdict | $13–19 · 35–60 min |
| **Full** | a release, or a report for someone outside the team | `/auditor:audit-cycle` (unattended) · `/auditor:audit-assist` (you steer) · `/auditor:re-audit` after fixes | everything in scope, a threat model, peer review (re-audit: the fix delta) | `REPORT.md`, client style: no deploy guarantee (audit-cycle adds a PDF, and PoCs with `--with-poc`) · `RE-AUDIT.md`, with an updated deploy verdict | about $20 · about 1 h, on a 3K-line program |
| **[CI](docs/ci.md)** | every pull request | `templates/ci/auditor-pr.yml`: a tools job, then `/auditor:diff-audit --ci` | as Quick | `findings.json` and SARIF on the runner, one pass/fail line in the log | tools job $0; review $2–5 a pull request |

Costs and times were measured on 2026-11-08 and 2026-11-09 with `claude-opus-5-5`, on 3K-, 7K- and 12K-line programs. Quick's range covers diff-audit runs of $1.68–2.94 and quick-scan runs of $2.84–7.14; the latest, trial t1, scanned the 3K-line repository with the depth-scope selection for $6.98 in 23 minutes. Full ran once, on the 3K-line program ([COSTS.md](COSTS.md#cost-and-time-by-depth)). Outside the depths: `poc`, `patch`, `economic-sim` and `triage` work on one finding; `intake` and `threat-model` are Full's building blocks; `audit-report` assembles the internal report from a walk run in pieces; `spec-audit` checks code against a spec; `hunt` and `respond` are for [after an incident](#after-an-incident).

**What's inside:** 20 checklists · 1,465 verification items · 141 known attack vectors · executable PoCs + fix patches.

---

## What Is This?

It is also a **skill file** (a structured prompt + checklists) that turns any LLM agent (Copilot, Cursor, Windsurf, Claude Code, Codex, etc.) into a professional-grade security auditor. It reads your code file by file, checks 1,465 items across 20 security domains, tests against 141 real-world attack vectors, and produces a structured report with severity scores.

**It is not a SaaS product.** It's a folder of markdown files you install for your AI agent — outside any repository you audit — or send to an LLM API.

> **If your layout differs.** This skill was originally developed for a specific Solana/Anchor DeFi project and then generalized. `discovery/file-map.md` assumes that project's layout (`programs/{name}/src/`, `apps/backend/src/`, `apps/web/src/`). For Quick and Standard, pass the range or the path you want reviewed. Intake is part of Full only. `/auditor:audit-assist` asks its questions at the first checkpoint, where you record where your code lives: the in-scope paths under `QUESTIONS.md` Q39 ("Specific files/modules") and the exclusions under Q44, which `/auditor:intake` writes to the Layout table of `audit_<n>/intake.md` §1. The next interactive intake in the same checkout offers that table again and reuses it only on your yes. `/auditor:audit-cycle` runs intake with `--auto`: it applies the `QUESTIONS.md` defaults, lists each one in the report, and never reuses an earlier table. An edited `discovery/file-map.md` in a shared or plugin install is lost on the next update. Everything else (checklists, known vectors, output rules) is portable as-is.

---

## What It Does (v7.7)

- **A full audit-firm lifecycle, two ways.** `/auditor:audit-cycle` runs the whole engagement autonomously (intake → context → threat model → tool-assisted pass → domain-partitioned review → triage → independent peer review → synthesis) and hands back a professional client report. `/auditor:audit-assist` runs the same pipeline **interactively**, pausing at checkpoints for the calls only you can make.
- **Executable proofs, not just prose.** For High/Critical findings, `/auditor:poc` builds a runnable exploit (Mollusk / LiteSVM / Surfpool-fork / fuzz) that *asserts* the vulnerability, and `/auditor:patch` drafts a minimal fix and **proves it reverts the exploit**. Evidence is tiered (`[PoC-REPRODUCED]` … `[PoC-PROSE]`); prose is never dropped when a harness can't be built.
- **Token-efficient by construction.** An optional Rust pre-scanner (`audit-scan`) enumerates the risky surface deterministically (~$0), cutting ~30-40% of input tokens on large programs. A cross-audit memory store (`audit-mem`) gives exact dedup, regression detection, and false-positive suppression across runs.
- **17 commands, 9 specialized agents.** Scoping, threat modeling, deep review, economic simulation, differential/PR audits, spec compliance, triage, fix-review — each a first-class command, plus a post-incident detection & response track (hunt + respond over transaction history). The automated audit flow chains eight purpose-built agents; a ninth, incident-responder, drives the post-incident track.
- **Deep Solana coverage.** 13 protocol methodologies (AMM/CLMM, lending, perps, oracles, stablecoins, liquid staking, governance, bridges, multisig/custody, Token-2022, NFT marketplaces, launchpads, token registries & risk signals), framework idioms (Anchor/Native/Pinocchio), and a reusable invariant catalog — loaded only when the code triggers them.
- **Rigor gates against AI over-reporting.** A validation gate (reachability + math/state-bounds + attacker-model) every high-severity finding must survive, Impact×Likelihood severity with principled downgrades, and a Notes & Nitpicks tier that keeps the findings table honest.
- **Real tooling, vendored.** Trail of Bits execution plugins (SAST, fuzzing, coverage, mutation) ship as a submodule; the native corpus works fully without them.
- **Operating safety, in two modes.** By default what strict mode would refuse is a note in the report, apart from the few shapes still refused in both modes, which Rules 11e and 11f list. Strict mode, for code you don't trust, refuses it and builds only in isolated mode. In both modes git only reads, the bundled tools write only into the auditor's own directories, and audit output never reaches git or a public CI log ([OUTPUT-RULES.md Rule 11](OUTPUT-RULES.md#rule-11-operating-safety)).

What each release added: [What's new](#whats-new).

### Documentation

| Guide | What's inside |
|-------|---------------|
| [docs/getting-started.md](docs/getting-started.md) | Install, submodule init, build the Rust tools, run your first audit |
| [docs/audit-flows.md](docs/audit-flows.md) | The three depths and CI, and the pipeline each one follows (`/diff-audit`, `/audit`, `/audit-cycle`, `/audit-assist`, `/re-audit`) |
| [docs/ci.md](docs/ci.md) | Quick on every pull request: the workflow template, its two jobs, `--ci` and `--fail-on`, what the verdict means, and how to read the details of a public repository's run |
| [docs/commands.md](docs/commands.md) | Reference for all 17 commands |
| [docs/agents.md](docs/agents.md) | The 9-agent roster and how they chain |
| [docs/power-tools.md](docs/power-tools.md) | `audit-scan`, `audit-mem`, Trail of Bits, Surfpool, PoC/patch harnesses, the bundled scripts and their flags |
| [docs/poc-and-patches.md](docs/poc-and-patches.md) | Executable exploit + fix-patch delivery |
| [docs/output-and-rigor.md](docs/output-and-rigor.md) | Severity, the Rule 5b gate, scope-gated loading, report format |
| [docs/detection-response.md](docs/detection-response.md) | Post-incident hunting + incident workup (`/auditor:hunt`, `/auditor:respond`) |
| [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md) | Default and strict mode, what runs without asking and why that is safe, what still asks, strict mode and isolated runs, `claude -p`, the risks that remain |

---

## Supported Languages & Frameworks

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

---

## Installation

Install auditor-skill **outside any repository you audit**: the plugin (Option 1), or a user-level skill such as `install.sh ~/.claude/skills/auditor-skill`. A copy inside the audited repository resolves its scripts, tools and corpus from a tree that repository controls, and that repository's own `.claude/`, `.mcp.json` and `CLAUDE.md` are target-controlled too ([OUTPUT-RULES.md Rule 11e](OUTPUT-RULES.md#11e--bundled-paths)).

**Upgrading from 7.6.0 or earlier.** Through 7.6.0, `install.sh` without a path installed into the current directory's `.claude/skills/auditor-skill`; it now installs to `~/.claude/skills/auditor-skill`, and a run started next to such a copy notes it and leaves it alone. If your copy sits inside a repository, delete it (`rm -rf .claude/skills/auditor-skill`) and install a fresh copy outside: the plugin (Option 1), or Option 2. Never move or update a copy you find inside a repository: its git config may have come with that repository. Plugin users get this change when they update the plugin.

### Option 1: Claude Code plugin marketplace (recommended)

```
/plugin marketplace add solanabr/auditor-skill
/plugin install auditor
```

Registers the marketplace and installs the `auditor` plugin — all 17 `/auditor:*` commands and 9 agents. Claude Code clones the plugin together with its submodules, so this also fetches the vendored Trail of Bits tooling at the pinned commit (see [Tool execution](#tool-execution-trail-of-bits--optional-rust-tools)); there is no manual step.

### Option 2: Install script

Installs the skill and inits the tooling. With no argument it installs to `~/.claude/skills/auditor-skill`, a user-level skill, wherever you run it from; to install elsewhere, pass a path outside the repositories you audit. It warns on stderr when the install directory is inside a git work tree. Re-running it installs a fresh clone at the same path and moves the earlier install, without running git in it, to `$XDG_STATE_HOME/auditor-skill/backup-<timestamp>`, or `~/.local/state/auditor-skill/backup-<timestamp>` when `XDG_STATE_HOME` is unset or not an absolute path. That private directory must lie outside every skills directory, so that Claude Code does not load the old copy as a second skill: the run refuses a backup directory inside the install's parent directory, or one under a directory named `.claude`, `skills`, `commands` or `agents` in any letter case, on its path as given or with links resolved. The run prints the backup's path. Each upgrade keeps a full copy there, including anything built inside it such as the Rust tools' build output, and nothing removes old backups: delete them when you no longer need them. A symbolic link at the install path or at the backup directory is refused, never followed:

```bash
# read it first (it's a security tool, after all):
git clone https://github.com/solanabr/auditor-skill.git
./auditor-skill/install.sh ~/.claude/skills/auditor-skill    # user-level (also the default), outside any audited repository

# one-liner (convenience), same target:
curl -fsSL https://raw.githubusercontent.com/solanabr/auditor-skill/main/install.sh | bash -s -- ~/.claude/skills/auditor-skill
```

### Option 3: Clone manually

```bash
git clone https://github.com/solanabr/auditor-skill.git ~/.claude/skills/auditor-skill
```

Claude Code auto-discovers user-level skills under `~/.claude/skills/`; invoke by asking your agent to "audit this repo using the auditor-skill" (use **Option 1** for the `/auditor:*` slash commands; Claude Code 2.1.157 and later also loads this clone as the `auditor` plugin, commands included, unless managed settings block plugins saved there, with `strictPluginOnlyCustomization` or a `strictKnownMarketplaces` list without `skills-dir`, or an `auditor` plugin installed from a marketplace takes precedence). This is also Option 2's default path, so a later `install.sh` run without a path upgrades this clone: it installs a fresh clone and moves this one to Option 2's backup directory, without running git in it. For other agents (Cursor, Windsurf, Copilot, Codex), copy the folder anywhere the agent reads outside the repository you audit, and point it at its `SKILL.md`.

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

These rules also let Claude start any of these flows by itself, in any repository you open, with no prompt in Manual mode and no classifier check in auto mode, for example when a file it reads tells it to. `/auditor:audit-cycle` started that way builds the project on your machine. To rule that out, set `AUDITOR_EXEC_MODE=isolated` (or `none`) in that file's `env`, or keep the rules in a file you pass with `claude --settings` when you audit ([docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#turns-and-resuming)).

### Tool execution (Trail of Bits) + optional Rust tools

auditor-skill vendors **Trail of Bits** ([trailofbits/skills](https://github.com/trailofbits/skills), CC-BY-SA 4.0) as a git submodule (`vendor/trailofbits`) for real tool execution — SAST, fuzzing, coverage, mutation. Options 1 and 2 both fetch it. For Option 3, or any other clone, run this from the auditor-skill directory (not your project root):

```bash
git submodule update --init --depth 1 -- vendor/trailofbits
```

**Pinned at** [`711af09`](https://github.com/trailofbits/skills/tree/711af095215ad4ecde5b90cd1d0124b3f1c4ca9e) — trailofbits/skills `main` of 2026-11-02. Upstream publishes no tags or releases, so the pin is a commit, and it moves only after a reviewed bump ([CONTRIBUTING.md §5](CONTRIBUTING.md#5-tooling-changes)); CI fails if this line and the submodule disagree, and plugin installs receive a new pin with the next release. To read the pin of any checkout without initializing the submodule: `git ls-tree HEAD vendor/trailofbits`.

The native corpus works fully **without** it (it falls back to grep-based checks and notes where deeper tooling would run). With the submodule initialized, the auditor delegates to the vendored tools per [`references/orchestration/boundary-map.md`](references/orchestration/boundary-map.md). For the optional token-efficiency tools (`audit-scan` pre-scanner + `audit-mem` memory), build the Rust CLIs (`<auditor-skill root>` is where you installed auditor-skill):

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release --locked
```

Build them again after every update, with `cargo build --release --locked` in the same directory: the flows call them with a contract marker (`--contract=1`) that an older build refuses, and until then they go on as if the tools were absent. The auditor runs them, the scripts and the Trail of Bits plugins by absolute path from the installation, never by a path relative to the project it audits ([OUTPUT-RULES.md Rule 11e](OUTPUT-RULES.md#11e--bundled-paths)). If the installation sits inside the repository under audit anyway (such as `.claude/skills/auditor-skill`, where `install.sh` without a path installed through 7.6.0), the build runs inside that tree, where cargo and rustup read its `.cargo/config*` and `rust-toolchain*` from every parent directory: build there only in [Rule 11a](OUTPUT-RULES.md#rule-11-operating-safety) isolated mode, or delete that copy and install a fresh one outside (the plugin, or Option 2 with the path `~/.claude/skills/auditor-skill`) and build that one. Never move or update a copy you find inside a repository ([Installation](#installation)).

### Permissions and isolation

The `/auditor:*` commands run their bundled steps without asking: the working-tree check, run directories, read-only git, the Rust tools, and the runners that build and test the project in the execution mode in force, native unless intake, `AUDITOR_EXEC_MODE` or strict mode says otherwise. Each of these checks its own arguments, takes paths inside the working tree (the PoC build cache aside), and writes only into run directories, the `audit-mem` store and scratch directories outside the tree, besides the toolchain caches its downloads fill. Other calls ask, apart from Claude Code's own read-only commands and the file reads the commands pre-approve (Read, Grep and Glob, for any path). By default what strict mode would refuse is a note in the report, apart from the few shapes still refused in both modes, which Rules 11e and 11f list ([OUTPUT-RULES.md Rule 11f](OUTPUT-RULES.md#11f--default-and-strict-mode)). Two settings make a run smooth and safe, but for [one risk the first adds](docs/permissions-and-isolation.md#what-remains-a-risk), since its rules also let Claude start a flow by itself:

- Once, after installing, add the `Skill(auditor:… *)` rules from [Once, after installing](#once-after-installing) to your user settings, `~/.claude/settings.json`, so a flow resumes after your reply without a prompt. They name no path.
- For code you don't trust, start Claude Code with the strict launch line, `claude --setting-sources "" --strict-mcp-config --plugin-dir "<auditor-skill root>" --settings "<auditor-skill root>/templates/strict-settings.json"`, where `<auditor-skill root>` is the folder auditor-skill is installed in ([docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#default-and-strict-mode) says where that is). It loads none of your own settings or plugins: a language-server plugin you enabled, such as `rust-analyzer-lsp`, would otherwise run the project's build scripts on your machine, outside the runners. Strict mode refuses what default mode only notes, and builds only in isolated mode: under the Claude Code sandbox the template turns on, or in a container or a VM ([docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#default-and-strict-mode)). Under the launch line the repository's own `.claude/` config and `.mcp.json` servers do not load. Strict mode still refuses a tree that ships them, because preflight cannot see how Claude Code was started: for such a repository, audit a copy with every `.claude/` and `.mcp.json` deleted. In native mode, the default, the project's builds and tests run on your machine without a prompt for each run.

---

## Before Running an Audit

### Scope-gated loading

auditor-skill does not bulk-read its whole corpus. It discovers the repo, declares an audit scope ([OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 0), and loads only the in-scope checklists and vectors on demand:

- root docs + `OUTPUT-RULES.md` (always),
- only the `checklists/*.md` the detected languages require (e.g. `14-python-safety.md` only if `.py` is present),
- a `known-vectors/*.md` file only when its phase + language trigger reaches it,
- `discovery/*.md` and `templates/*.md` lazily, at the phase that uses them.

The audit is complete when every **in-scope** item has an explicit verdict; out-of-scope items render `[N/A — out of scope]` from the gate.

1. **Intake, for Full only.** Full runs it for you: `/auditor:audit-cycle` with the [QUESTIONS.md](QUESTIONS.md) defaults, each listed in the report, and `/auditor:audit-assist` by asking at its first checkpoint. The answers set the severity calibration, the trust model and which compliance checklists apply. With an agent that has no commands, fill a copy of QUESTIONS.md first. Quick and Standard need no intake.

2. **Check the cost:** [COSTS.md](COSTS.md) has the measured cost and time of each depth.

3. **Choose your scope** for Standard and Full: `--scope full|program|backend|frontend` picks the part of the repository a run reviews. [SKILL.md](SKILL.md#scope-gated-loading--load-what-the-repo-needs) defines each one; the Quick commands take none.

---

## Folder Structure

```
auditor-skill/
├── README.md                ← YOU ARE HERE
├── SKILL.md                 ← Orchestrator — the AI agent reads this first
├── OUTPUT-RULES.md          ← Mandatory output format, severity scale
├── FULL-AUDIT.md            ← Step-by-step execution plan for complete audits
├── QUESTIONS.md             ← Pre-audit questionnaire (intake asks it in a Full run)
├── COSTS.md                 ← Measured cost and time per depth
├── CONTRIBUTING.md          ← Branch / PR flow, corpus-count rules, no AI-attribution policy
├── SECURITY.md              ← Private vulnerability reporting for the skill and its tooling
│
├── known-vectors/           ← Individual attack vector files (for contributors)
│   ├── INDEX.md             ← One-line index of all vectors
│   ├── 001-private-key-leak.md
│   ├── 002-flash-loan-price-manipulation.md
│   ├── ...
│   └── 100-insufficient-backup-disaster-recovery.md
│
├── checklists/              ← 20 micro-checklists (the core verification items)
│   ├── 01-program-account-validation.md    (90 items)
│   ├── 02-program-access-control.md        (55 items)
│   ├── 03-program-arithmetic-safety.md     (63 items)
│   ├── 04-program-cpi-pda.md              (70 items)
│   ├── 05-program-state-machine.md         (74 items)
│   ├── 06-program-economic-logic.md        (92 items)
│   ├── 07-program-opsec-governance.md      (87 items)
│   ├── 08-typescript-safety.md             (64 items)
│   ├── 09-backend-security.md             (133 items)
│   ├── 10-frontend-security.md             (84 items)
│   ├── 11-supply-chain.md                  (65 items)
│   ├── 12-secrets-opsec.md                 (53 items)
│   ├── 13-deployment-infrastructure.md     (102 items)
│   ├── 14-python-safety.md                 (82 items)
│   ├── 15-general-language-safety.md       (88 items)
│   ├── 16-formal-verification-testing.md   (73 items)
│   ├── 17-logging-monitoring-incident-response.md (68 items)
│   ├── 18-privacy-compliance-change-management.md (60 items)
│   ├── 19-ai-agent-security.md (39 items) — AI agents on Solana
│   └── 20-rust-offchain-services.md (23 items) — Off-chain Rust (geyser/indexers/keepers)
│
├── discovery/               ← File patterns and search commands
│   ├── file-map.md          ← Maps checklists → target file patterns
│   └── grep-commands.md     ← All grep/terminal commands by category
│
├── references/              ← Progressive-disclosure deep coverage (loaded on trigger)
│   ├── methodologies/       ← 13 protocol playbooks (amm-clmm, lending, perps, oracles,
│   │                          stablecoin, liquid-staking, governance, bridges,
│   │                          wallets-multisig-custody, token-2022, nft-marketplaces, launchpads,
│   │                          token-registry-risk)
│   ├── framework-idioms/    ← Anchor / Native / Pinocchio validation-order footguns
│   ├── vuln-classes/        ← zk-and-compression · transaction-v1 (SIMD-0385 migration) · github-actions (CI trigger trust) · kernel-attack-surface (host kernel & network surface)
│   ├── invariant-catalog.md ← Reusable harness-ready invariant menus per protocol class
│   ├── false-positives.md   ← Over-reporting triage rules
│   ├── audit-lifecycle/     ← methodology + firm-coverage (how firms work) + threat-model-bootstrap
│   ├── detection-response/  ← post-incident track: rules + verdict ladder, Solana log sources, containment, INCIDENTS.json schema
│   └── orchestration/       ← boundary-map (Trail of Bits) · pre-scan · poc-harness
│
├── commands/                ← 17 slash-commands (/auditor:<name>)
│   ├── audit · quick-scan · deep-review · diff-audit · spec-audit · economic-sim · audit-report
│   ├── audit-cycle · audit-assist · re-audit            ← lifecycle flows
│   ├── intake · threat-model · triage                   ← perimeter
│   ├── poc · patch                                      ← executable PoC + fix patches
│   └── hunt · respond                                   ← post-incident detection & response
│
├── agents/                  ← 9 specialized subagents
│   ├── context-builder · threat-modeler · vuln-hunter · economic-analyst
│   └── peer-reviewer · audit-reporter · poc-engineer · patch-engineer · incident-responder
│
├── skills/
│   └── dnr-analyze/         ← auditor:dnr-analyze: one D&R analysis phase, run as a fork of incident-responder
│
├── tools/auditor-tools/     ← Rust CLIs (cargo build --release --locked)
│   ├── audit-scan           ← deterministic pre-scan → JSON risky-surface map (~$0)
│   ├── audit-mem            ← SQLite cross-audit memory (dedup · regression · FP-suppression)
│   └── audit-logs           ← the D&R analysis recipes as one offline binary (cargo build --release --locked)
│
├── templates/               ← Output + deliverable templates
│   ├── report-template.md   ← Internal item-by-item verdict report
│   ├── audit-report.md      ← Client-facing findings report (no deploy guarantee)
│   ├── re-audit.md          ← Fix-review record (RE-AUDIT.md), with each finding's PoC re-run
│   ├── pr-report.md         ← The Quick commands' report (PR-REPORT.md · QUICK-SCAN.md · DEEP-REVIEW-<unit>.md)
│   ├── strict-settings.json ← Settings for the strict launch line (OUTPUT-RULES Rule 11f)
│   ├── ci/                  ← The pull-request workflow, its two schemas and jq programs (docs/ci.md)
│   ├── context-worksheet.md · instruction-worksheet.md · intake.md · threat-model.md
│   ├── incident-report.md · response-plan.md · hunt-ledger.md
│   ├── poc/                 ← exploit-harness crate skeleton + shared-test-utils
│   └── patch/               ← patch + VERIFICATION templates
│
├── docs/                    ← Usage guides (start at docs/README.md)
├── scripts/                 ← preflight.sh, rundir.sh, git-ro.sh, rpc-read.sh, report-to-pdf.sh, the CI checks (check-*.sh), tob-delta-review.sh + the no-attribution commit hook
│   ├── runner/              ← probe.sh, deps.sh, sast.sh, target.sh: toolchain probes, dependency audits, SAST, and builds and tests in the recorded execution mode
│   ├── recipes/             ← lock-delta.sh, web3js-history.sh: the lockfile changes and known-bad releases in the git history, for the supply-chain checks
│   ├── lib/                 ← confine.sh and isolation.sh, the checks and environment cleaning the entry points share
│   ├── pdf/                 ← no-remote.lua, the pandoc filter report-to-pdf.sh renders with
│   ├── dnr/                 ← detection & response recipes (gated RPC collector, program snapshot, corpus profile, log frames, balance deltas, jq-ro.sh)
│   ├── threat-model/        ← collect.sh — the read-only threat-model bootstrap collector
│   └── tests/               ← script self-tests (+ fixtures/gha/, workflows and a composite action that are never executed)
├── AGENTS.md                ← Agent-orchestration overview
└── vendor/trailofbits/      ← Trail of Bits execution plugins (git submodule, pinned — see Installation)
```

---

## Audit Flows

The Full depth is two flows that run a whole audit-firm engagement end to end, and a fix review after it:

- **`/auditor:audit-cycle`** — a **fully automated** audit-agent team (scope → context reconstruction → tool-assisted pass → parallel manual review with leaf-level false-positive gating → independent peer reconciliation → synthesis) that produces a professional client report at `audit_<n>/REPORT.md`. Optional PDF (needs [pandoc](https://pandoc.org/)):
  ```bash
  # from your project; <auditor-skill root> is where auditor-skill is installed
  "<auditor-skill root>/scripts/report-to-pdf.sh" audit_1/REPORT.md   # writes REPORT.pdf if pandoc is installed; MD is always the deliverable
  ```
- **`/auditor:audit-assist`** — an **AI-assisted, human-in-the-loop** flow: it pauses at checkpoints to surface findings and ask the questions only you can answer (business context, trust model, severity calls), iterating until the audit document converges.
- **`/auditor:re-audit`** — **fix-review**: diffs against a prior report (`FIXED` / `STILL-OPEN` / `REGRESSED`) and sweeps for un-patched siblings of each fixed bug.

Every intermediary step is also addressable on its own: `/auditor:intake` (persisted scoping), `/auditor:threat-model` (asset/actor/trust-boundary artifact; `--bootstrap` seeds it from git history, a fork parent, prior audits and incidents), `/auditor:triage` (dedup + false-positive calibration), and `/auditor:poc` / `/auditor:patch` (executable exploit + verified fix). Full command reference: [docs/commands.md](docs/commands.md).

The client report follows professional firm convention — executive summary, commit-pinned scope, findings with PoC/reachability, a code-maturity assessment, disclaimers. Like real firms, it does **not** issue a "safe to deploy" guarantee. Method + firm coverage: [references/audit-lifecycle/](references/audit-lifecycle/).

---

## After an incident

`/auditor:hunt` and `/auditor:respond` start from what already happened on chain: transaction history, program logs, and Geyser or indexer exports. They are a track of their own, never part of an audit, and they only propose.

- **`/auditor:hunt [<address> …]`** — no alert to start from. It snapshots the deployed programs, baselines the transaction history, records each hypothesis and its query in a ledger, checks each suspect against the source deployed at the incident slot, and reproduces it on the program's real bytes → `incident_<n>/INCIDENT_REPORT.md` and `INCIDENTS.json`.
- **`/auditor:respond <lead>`** — one lead: a signature, an address, an alert or an `INC-<n>.<k>` from a hunt. It settles whether it landed, the damage per mint and the root cause, and drafts containment, remediation and recovery steps for people to carry out → `RESPONSE-INC-<n>.<k>.md`.

Neither command signs, sends, pauses or freezes anything. If funds may be moving right now, page your on-call, run the pause or freeze runbook and open a SEAL 911 ticket first: these commands are the after-the-fact workup. Guide: [docs/detection-response.md](docs/detection-response.md).

---

## Output Format

`/auditor:audit` (Standard) writes the internal report below. `/auditor:audit-cycle` and `/auditor:audit-assist` (Full) write the client report instead, which follows firm convention and gives no deploy guarantee ([Audit Flows](#audit-flows)). The internal report is a structured markdown file with:

1. **Executive Summary** — risk score (1-10), deploy/no-deploy verdict, severity distribution
2. **Instruction Matrix** — every smart contract instruction mapped
3. **State Model** — account structs, PDA seeds, relationships
4. **Per-Item Verdicts** — every in-scope checklist item (up to 1,465) with `[PASS]`, `[FAIL-N]`, `[PARTIAL]`, or `[N/A]`
5. **Known Vectors Results** — each in-scope attack vector (up to 141) with explicit verdict and evidence
6. **Findings** — deduplicated, severity-sorted
7. **Attack Scenarios** — narrative exploitable paths
8. **Aggregate Score** — PASS/PARTIAL/FAIL percentages
9. **Recommendations** — prioritized fix list

For High/Critical findings, an optional `audit_<n>/poc/` (runnable exploits that assert the bug) and `audit_<n>/patches/` (minimal fixes proven to revert the exploit) accompany the report — see [docs/poc-and-patches.md](docs/poc-and-patches.md).

See [OUTPUT-RULES.md](OUTPUT-RULES.md) for the complete specification.

---

## How to Invoke

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

### Other agents

An agent without the plugin's commands reads the skill and follows it. Ask in plain words.

#### VS Code / GitHub Copilot
```
@workspace Audit the entire repository using the auditor-skill
```

#### Cursor / Windsurf
```
Read ~/.claude/skills/auditor-skill/SKILL.md then audit this repository following that installation's FULL-AUDIT.md execution plan
```

For a first pass on a branch instead:
```
Read ~/.claude/skills/auditor-skill/SKILL.md then review what this branch changes against main, as its differential mode describes
```

#### Claude Code, in plain words
```
Read the auditor-skill files in ~/.claude/skills/auditor-skill/ and perform a full security audit of this repository
```

#### API (programmatic)
```python
# Send SKILL.md + OUTPUT-RULES.md + FULL-AUDIT.md as system prompt
# Send target files as user messages (chunked)
# Collect structured output
```

---

## What's new

- **Three depths and a CI mode (v7.7).** The README and docs start from what you want checked: Quick (`/auditor:diff-audit`, `/auditor:quick-scan`, `/auditor:deep-review`), Standard (`/auditor:audit <path> --scope …`) and Full (`/auditor:audit-cycle` or `/auditor:audit-assist`, then `/auditor:re-audit`). The scopes are defined once, in SKILL.md, and intake is part of Full only. Each Quick command writes a report in its run directory (`PR-REPORT.md`, `QUICK-SCAN.md`, `DEEP-REVIEW-<unit>.md`). `--ci` and `--fail-on <N>` on `diff-audit` and `quick-scan` run them unattended: they write `audit_<n>/findings.json` and end with one verdict line, and `templates/ci/auditor-pr.yml` runs Quick on every pull request ([docs/ci.md](docs/ci.md)). On a public repository CI publishes pass/fail only, and no longer fails a job for want of a private channel. COSTS.md now gives the measured cost and time of each depth, in place of April 2026's estimates.
- **Strict mode is opt-in (v7.7).** By default the checks that used to stop a run print a note instead: the run goes on, and the report lists each note under Coverage & Limitations. Only the few shapes still refused in both modes stop it; Rules 11e and 11f list them. Builds and PoCs run natively unless intake, `AUDITOR_EXEC_MODE` or strict mode says otherwise, and nothing asks for the execution mode mid-run. Strict mode, for code you don't trust, keeps the refusals and builds only in isolated mode: `AUDITOR_STRICT=1`, `--strict` on a command, or intake's "Untrusted source" answer turns it on, and the launch line with `templates/strict-settings.json` gives its full effect ([OUTPUT-RULES.md Rule 11f](OUTPUT-RULES.md#11f--default-and-strict-mode)).
- **Per-project layout and a tool contract (v7.7).** Intake records where your code lives in the Layout table of `audit_<n>/intake.md` (Q39, Q44), and the next interactive intake reuses it only on your yes, so `discovery/file-map.md` needs no edit. `audit-scan` and `audit-mem` take a `--contract=1` marker that an older build refuses: rebuild them after every update.
- **Bundled steps run without asking (v7.7).** Each `/auditor:*` command, and the root skill, starts with `scripts/preflight.sh`, which checks the working tree for Claude Code skills, commands, agents, hooks, MCP servers or settings beyond a few harmless keys. By default what strict mode would refuse is a note in the report, apart from the few shapes still refused in both modes, which Rules 11e and 11f list. Each command then pre-approves file reads, for any path, and of the bundled programs only those its steps use: run directories, read-only git, the collectors, the program snapshot, RPC reads, the lockfile recipes, the probe, dependency, SAST and build runners, the PoC runner, the PDF renderer, `audit-scan` and `audit-mem`; the analysis skill in the next entry pre-approves the analysis recipes, `jq-ro.sh` and `audit-logs`. Each of those programs checks its own arguments and itself writes only into run directories, the `audit-mem` store and scratch directories outside the tree, besides the toolchain caches its downloads fill. Runs stay smooth, and the limits are disclosed rather than gated: in native mode, the default unless intake, `AUDITOR_EXEC_MODE` or strict mode says otherwise, the project's builds and tests run on your machine without a prompt for each run; the isolated-mode self-check knows credentials only by their names and places; and preflight covers neither a session you start in such a tree for other work nor a command that a repository file has replaced; starting Claude Code with the strict launch line, which loads none of the repository's skills, commands or settings, rules both out ([Permissions and isolation](#permissions-and-isolation)).
- **`audit-logs` and the D&R analysis fork (v7.7).** `audit-logs`, a third Rust tool, runs the detection & response recipes `profile.sh`, `frames.py` and `deltas.py` as one offline binary that prints what the scripts print, which a CI suite checks; the scripts run in its place when it is not built or its build is stale. `/auditor:hunt` and `/auditor:respond` run each analysis phase in `auditor:dnr-analyze`, a forked skill that runs the `incident-responder` agent; the skill's own list pre-approves only those recipes, `jq-ro.sh` and `audit-logs`.
- **Post-patch validation and live-probe rules (v7.7).** `/auditor:patch --post-patch-validation` adds Trail of Bits post-patch validation. It is opt-in, never pre-approved, and runs only in isolated mode on a disposable clone, never on the client checkout; its result can only lower a fix tier. Intake question Q47 decides whether DEP-072 and DEP-073 may probe the project's live hosts and buckets: read-only, unauthenticated, and only those the client confirmed. Unanswered, or in `--auto`, it means no.
- **GitHub Actions workflow pass and runner procedures (v7.7).** `audit-scan`'s workflow pass (`--workflows .github/workflows`) reads each workflow into trigger → job → step facts with a strict-subset YAML parser, and lists under `unknown` or `skipped` what it did not read instead of guessing. The locator recipes and their copies in KV-080, KV-116, KV-139 and KV-140 now match spellings they missed, such as quoted keys, value-first comparisons and agent CLI options before `-p`; the new R9 lists actions and reusable workflows pinned to a full SHA. The GitHub Actions playbook's §7 turns its pointers into procedures: pins and repointed tags (KV-080 Step 4), self-hosted runners (KV-080 Step 8) and OIDC trust policies (KV-140 Step 7). [docs/power-tools.md](docs/power-tools.md#github-actions-workflow-analysis) pins zizmor by image digest and wheel hashes and describes CodeQL's `actions` queries.
- **Forensic readiness and the Cloudflare comparison (v7.7).** Checklist 17 §17.6 (LM-066..068) checks that an incident can be worked up later: transaction history kept beyond the public RPC window, a deploy log that ties each upgrade to its commit and build hash, and archived account updates for fund-holding PDAs. A comparison with Cloudflare's security-audit skill adds availability review of dependency updates, toolchain pinning and published-file allowlists (SC-063..065), auth, rate and size limits before paid upstream calls (BE-133), retry and fee budgets for keepers and a quarantine for records a consumer cannot process (RS-022..023), and agent checks for signing approvals, MCP tool names, recalled memory and rendered output (AI-036..039).
- **Detection & response, post-incident (v7.6).** `/auditor:hunt` works through transaction history, program logs and Geyser/indexer exports with a written hypothesis ledger; `/auditor:respond` starts from a signature, address or alert and establishes whether the attack landed, how far it reached, and why. Verdicts follow a single [ladder](references/detection-response/README.md#the-verdict-ladder-the-one-normative-copy); the response plan is for humans to carry out — the track acts on nothing. Ported Solana-native from Anthropic's defending-code-reference-harness.
- **History-seeded threat models (v7.6).** `/auditor:threat-model --bootstrap` starts the threat model from what already went wrong: removed or quietly added account guards, reverts and fix commits in the target's history, a fork's distance from its parent, prior audit reports, post-mortems and incident records. One read-only, hardened collector (`scripts/threat-model/collect.sh`) gathers it; non-interactive runs stay offline, and every goal cites its evidence.
- **GitHub Actions trigger trust (v7.6).** A CI playbook (`references/vuln-classes/github-actions.md`) for the shapes an outside account uses to reach a privileged job — comment-triggered commands without per-event author gating, expression and env-file injection, `pull_request_target` / `workflow_run` pwn requests with artifact and cache poisoning, and AI coding agents in CI — with KV-139/140, checklist 13 §13.13 (DEP-090..096), AI-034..035, read-only rules of engagement, and zsh-safe locator recipes backed by a fixture self-test.
- **Operating safety & dependency-update review (v7.6).** A new OUTPUT-RULES Rule 11 covers five things. Target code runs in the execution mode chosen at intake (native by default, with a report caveat; strict mode for code you don't trust). Outside-service use is disclosed. Untrusted `.git/` checkouts are read without letting git run their config. Audit output never reaches git or a public CI log. Bundled scripts and tools run from the installation, never from a path in the audited repository. Checklist 11 §11.11 (SC-059..062) reviews what a dependency bump's *published code* actually changed, wired into `/auditor:diff-audit` and `/auditor:re-audit`. KV-077 and SC-005 now catch the hijacked `@solana/web3.js` 1.95.6 / 1.95.7 releases.
- **Trail of Bits pin, reviewed and visible (v7.6).** `vendor/trailofbits` moves from `cfe5d7b` (2026-06-30) to `82fe822` (2026-09-28) after a full delta review; upstream had since fixed a semgrep path that silently dropped two third-party rulesets and SARIF parsing that read CodeQL severities as zero errors. The pin is shown under Installation, fetched shallow, checked by CI against the gitlink, and moved by a monthly Dependabot PR that a maintainer reviews with `scripts/tob-delta-review.sh`; plugin users receive it with this release.
- **Slot-as-clock coverage (v7.5).** SIMD-0525 halved mainnet slot time to 200 ms (Oct 9, 2026) and Alpenglow (Oct 21, 2026) made `Clock.unix_timestamp` a leader-set value, so every timelock, vesting cliff, cooldown, oracle window, rate limit and interest constant denominated in slots now elapses in half the wall-clock time. KV-138 covers the class (the EVM learned it at the Merge with Compound's `blocksPerYear`; deployed lending programs still carrying `SLOTS_PER_YEAR = 63,072,000`, whether from an old-SDK build of SPL token-lending, the Save fork's literal or Kamino's legacy basis, now accrue 2.5x the configured APR), with SM-073..074, ECON-090..092, OPS-086..087, BE-132 and FV-073 as the per-domain checks.
- **Vendored-program provenance (v7.4).** Coverage for the newest exploited class on Solana — the Rain white-label card-contract exploit (Aug 2026, ~$1.1M across Avici, Tria and other tenants): KV-137 (deployed-program version drift, fleet blast radius, inherited admin surface), off-chain-signed authority-grant checks (AC-051..055 — the `AddCollateralAdmin` signature-bundle failure) and deployed-program provenance checks (SC-053..058) — the layer `cargo audit` / `npm audit` can't see, because the vulnerable artifact is your own deployed program.
- **Transaction v1 readiness (v7.3).** A vuln-class playbook for SIMD-0385 / SIMD-0296 (4,096-byte transactions, message-level compute config, no ComputeBudget instructions, no lookup tables): who breaks and how, per-role worksheets for RPC readers, indexers / Geyser consumers, fee sponsors / co-signers, introspecting programs, senders and wallets; KV-135 (sponsor cap bypass, disabled ComputeBudget gates) and KV-136 (reader wedge, zero-budget indexing); 23 checklist items across on-chain, TypeScript, backend, frontend, deployment, testing, monitoring and off-chain Rust.
- **Token registries & permissioned tokens (v7.2).** A registry / risk-signal methodology (canonical-asset resolution, primary-variant ranking, score farming — grounded in the open-sourced tokens.xyz stack), Token ACL (SRFC-37) gate-program coverage inside the Token-2022 playbook, and web-stack items for hosted auth, API-key issuance, external data providers, Next.js 16, Bun / Turborepo and GCP / Terraform.

---

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first — branch + PR flow (nothing lands on `main` directly), the corpus-count consistency rule enforced by `scripts/check-corpus.sh` in CI, and the no-AI-attribution commit policy (enable the hook with `git config core.hooksPath scripts/hooks`).

### Adding a New Attack Vector

1. Create `known-vectors/NNN-short-name.md` with the next available number
2. Use this template:

```markdown
---
id: NNN
title: "Your Attack Name"
severity: 7
category: crypto|backend|frontend|devops
---

### NNN — Your Attack Name
**Severity: 7** | **Real: Example Incident ($X, Year)**

Brief description of the attack.

#### Verification Procedure

**Step 1: Description**
\```
grep command or check to perform
\```
- ✅ PASS: What passing looks like
- ❌ FAIL: What failing looks like

**Step 2: ...**
(continue with 3-12 steps)

**Overall verdict:**
- ✅: Full mitigation criteria
- ⚠️: Partial mitigation criteria
- ❌: Vulnerability criteria
```

3. Add the entry to [known-vectors/INDEX.md](known-vectors/INDEX.md)
4. Submit a PR

### Adding Checklist Items

1. Open the relevant checklist in `checklists/`
2. Add new items following the existing format (ID prefix + sequential number)
3. Update the item count in [SKILL.md](SKILL.md)

### Updating Costs

When models or prices change, re-measure and update [COSTS.md](COSTS.md).

---

## Benchmarking

This auditor was designed by comparing methodology from:

| Standard | Domain | What We Took |
|----------|--------|-------------|
| **CertiK** | Crypto audit | On-chain vulnerability taxonomy, formal verification approach |
| **EY / SOC 2** | Enterprise IT audit | Control objectives, evidence requirements |
| **OWASP Top 10:2025** | Web security | Attack categories, severity calibration |
| **NIST SP 800-53** | Government security | Control framework structure |
| **COBIT 2019** | IT governance | Process maturity model |
| **GDPR / MiCA / DORA** | EU regulation | Compliance checklist items |

---

## License

MIT — use it, fork it, improve it, sell services built on it. Attribution appreciated but not required.

---

## FAQ

**Q: Does this replace a professional audit?**
A: It covers more items than most paid audits (1,465 plus 141 known-vector checks vs typical 50-200), but an AI auditor cannot do everything a human can (social engineering assessment, business logic review requiring domain expertise, legal compliance opinions). Use this as a first pass, then hire humans for what it flags.

**Q: Which AI model should I use?**
A: In Claude Code each agent names its own model tier: seven run on Opus, and context-builder and audit-reporter on Sonnet ([docs/agents.md](docs/agents.md)). `/auditor:quick-scan` and `/auditor:diff-audit` start no agent, so your session's model runs them (`/model`, or `claude --model`); an agent that `/auditor:deep-review` starts runs on the tier its definition names. [COSTS.md](COSTS.md)'s figures were measured with `claude-opus-5-5` as the session model; Sonnet as the session model is not measured yet.

**Q: How long does an audit take?**
A: It depends on the depth, the repository's size and the model. Quick scales with the change, Standard with the module, and Full takes longest: six agents carry it from context reconstruction through a threat model and peer review to the report, and `--with-poc` adds two more. Measured: Quick 4 to 23 minutes, the longest being trial t1's quick-scan of a whole 3K-line repository; Standard 36 minutes on 3K- and 7K-line programs and 56 on a 12K-line one; Full 61 minutes on the 3K-line one. Nothing at 50K lines was measured ([COSTS.md](COSTS.md)).

**Q: Can I use this in CI/CD?**
A: Yes. CI runs Quick on every pull request: copy `templates/ci/auditor-pr.yml` into `.github/workflows/` and follow [docs/ci.md](docs/ci.md#setup). Its tools job runs the bundled analyzers with no model and no secrets, for fork pull requests too. Its review job runs `/auditor:diff-audit --ci` on pull requests from your own branches, other than Dependabot's, in strict mode with nothing built, and fails when a counted finding reaches `AUDITOR_FAIL_ON` (7 by default), when an analyzer did not run, or when the review stopped early ([what the verdict means](docs/ci.md#what-the-verdict-means)). On a public repository the job posts pass/fail only — no finding text or counts: logs, job summaries and uploaded artifacts are readable by any signed-in GitHub user, so the details stay on the runner, you read them by running the same command in a clone of your own, and the job never fails only because no private channel exists (OUTPUT-RULES Rule 11d). For a scheduled scan of the default branch, run `/auditor:quick-scan --ci`, with a `--max-budget-usd` of $10: a cap close to a full pass's cost makes the session stop reading early ([COSTS.md](COSTS.md#cost-and-time-by-depth)).

For a job of your own, such as a Full run on a release branch: a CI job is a `claude -p` run, and it denies every call that would ask. Quick builds nothing; a Full run builds the project natively unless the job sets `AUDITOR_EXEC_MODE` or `AUDITOR_STRICT=1` (see [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#non-interactive-runs-claude--p)). A pull request can carry `.claude/settings.json` hooks and a `.mcp.json` that `claude -p` runs when it starts, so run pull-request jobs, those from forks above all, in strict mode: export `AUDITOR_STRICT=1` in the job's environment, start Claude Code with the strict launch line's flags, `--setting-sources "" --strict-mcp-config --plugin-dir "<auditor-skill root>" --settings "<auditor-skill root>/templates/strict-settings.json"` (a job that builds nothing, like the template's review job, leaves `--settings` out: [docs/ci.md](docs/ci.md#the-launch-line-flags)), and check that preflight's first line says `mode: strict`, since `claude -p` skips a settings file or entry it cannot use without a word (`claude doctor` lists what it dropped). Under the launch line the pull request's `.claude/` config does not load. Strict mode still refuses a tree that ships it, because preflight cannot see how Claude Code was started, so such a job audits a copy with every `.claude/` and `.mcp.json` deleted.

**Q: Can I use this for non-Solana projects?**
A: Yes — checklists 08-18 are language-agnostic or cover Python/Go/Java/Ruby/PHP. Checklists 01-07 are Solana-specific.

---

## Acknowledgments

auditor-skill stands on the shoulders of these open-source security projects — credited in full in [ATTRIBUTION.md](ATTRIBUTION.md):

- **[Frank Castle](https://github.com/Frankcastleauditor) — [safe-solana-builder](https://github.com/Frankcastleauditor/safe-solana-builder)** (MIT): Solana security depth — reward/staking accounting, Token-2022 extension abuse, framework validation idioms, zero-copy footguns — adapted natively and re-authored audit-side.
- **[Trail of Bits](https://github.com/trailofbits) — [skills](https://github.com/trailofbits/skills)** (CC-BY-SA 4.0): tool-execution methodology (SAST, fuzzing, coverage, mutation, IR analysis, post-patch validation), vendored as a git submodule at `vendor/trailofbits` and orchestrated for real execution; methodology patterns re-implemented natively are credited by reference.
- **[Anthropic](https://github.com/anthropics) — [defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness)** (Apache-2.0): the detection & response method (a written hypothesis ledger, a three-leg verdict ladder, response plans that people carry out), re-expressed Solana-native in `/auditor:hunt` and `/auditor:respond`; the threat-model bootstrap / bootstrap-then-interview pattern, re-expressed for Solana in `/auditor:threat-model --bootstrap`.
- **[Sentry](https://github.com/getsentry) — [gha-security-review](https://github.com/getsentry/skills/tree/main/skills/gha-security-review)** (Apache-2.0, in [getsentry/skills](https://github.com/getsentry/skills)): the GitHub Actions vector inventory behind `references/vuln-classes/github-actions.md`, re-written natively (no text copied).
- **[Cloudflare](https://github.com/cloudflare) — [security-audit-skill](https://github.com/cloudflare/security-audit-skill)** (MIT): the execution-isolation, output-hygiene and CI-trust principles, paraphrased and adapted natively in `OUTPUT-RULES.md` Rule 11a's isolated mode (opt-in; native is the default) and Rule 11d and in `references/vuln-classes/github-actions.md`; and the ideas behind checklist items SC-063..065, BE-133, RS-022..023 and AI-036..039; see [ATTRIBUTION.md](ATTRIBUTION.md).

All third-party methodology is used by *reference* — no third-party text is copied into this repository.
