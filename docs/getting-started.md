# Getting Started

From an install to a first audit, for anyone setting up auditor-skill in Claude Code for the first time. Each step says what it is for and what you can skip. Back to the [docs index](README.md).

Contents: [1. Install](#1-install) · [2. Once, after installing](#2-once-after-installing) · [3. The Trail of Bits submodule](#3-initialize-the-trail-of-bits-submodule-recommended) · [4. The Rust tools](#4-build-the-rust-tools-optional) · [5. Adapt to your repo](#5-adapt-to-your-repo) · [6. Your first audit](#6-run-your-first-audit) · [7. Prompts and isolation](#7-prompts-and-isolation) · [Scopes at a glance](#scopes-at-a-glance) · [Next](#next)

## 1. Install

auditor-skill is a folder of markdown + three small Rust tools — not a SaaS. Keep it **outside any repository you audit** ([`OUTPUT-RULES.md` Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)): a copy inside the target resolves its paths from a tree the target controls. There are four ways to install it.

**The plugin, from the marketplace (recommended).** In Claude Code:

```
/plugin marketplace add solanabr/auditor-skill
/plugin install auditor
```

This installs the `auditor` plugin (its `.claude-plugin/` manifest ships with the repo): the 17 `/auditor:*` commands and the 9 agents. Claude Code clones the plugin with its submodules, so it also fetches the vendored Trail of Bits tooling at the pinned commit. Commands are then available as `/auditor:audit`, `/auditor:audit-cycle`, and so on.

**The install script.** `install.sh` clones the skill and fetches the tooling. With no argument it installs to `~/.claude/skills/auditor-skill`, a user-level skill, wherever you run it from; to install elsewhere, pass a path outside the repositories you audit. It warns when the install directory is inside a git work tree. Run again, it installs a fresh clone at the same path and moves the earlier install to a backup under `$XDG_STATE_HOME/auditor-skill/`, or `~/.local/state/auditor-skill/`, and prints the backup's path; nothing removes old backups. The [README](../README.md#installation) gives its rules for the backup directory. Read the script first:

```bash
git clone https://github.com/solanabr/auditor-skill.git
./auditor-skill/install.sh ~/.claude/skills/auditor-skill    # user-level (also the default), outside any audited repository
```

**A clone, as a user-level skill:**

```bash
git clone https://github.com/solanabr/auditor-skill.git ~/.claude/skills/auditor-skill
```

Claude Code discovers user-level skills under `~/.claude/skills/`, and Claude Code 2.1.157 and later also loads this clone as the `auditor` plugin, commands included, unless managed settings block plugins saved there or an `auditor` plugin installed from a marketplace takes precedence ([permissions-and-isolation.md](permissions-and-isolation.md#what-runs-without-asking)). A clone needs the submodule step in [section 3](#3-initialize-the-trail-of-bits-submodule-recommended). This is also the install script's default path, so a later `install.sh` run without a path upgrades it.

**Another agent, or an API.** For Cursor, Windsurf, Copilot or Codex, copy the folder anywhere the agent reads outside the repository you audit, and point the agent at its `SKILL.md` ([other-agents.md](other-agents.md) has prompts for each). Or feed the files to an API — send `SKILL.md` + `OUTPUT-RULES.md` (+ `FULL-AUDIT.md` for a full run) as system context and the target files as user content.

**Upgrading from 7.6.0 or earlier.** Through 7.6.0, `install.sh` without a path installed into the current directory's `.claude/skills/auditor-skill`, inside whatever repository you ran it in. If your copy sits inside a repository, delete it (`rm -rf .claude/skills/auditor-skill`) and install a fresh copy outside, as above. Never move or update a copy you find inside a repository: its git config may have come with that repository. Plugin users get this change when they update the plugin.

## 2. Once, after installing

In Manual mode Claude Code asks each time a flow goes on after your reply, since a plugin cannot ship permission rules. Add these rules once to `permissions.allow` in your user settings, `~/.claude/settings.json`, beside the rules already there, so a flow resumes after your reply without a prompt. With the install script or a clone under `~/.claude/skills/`, add `"Skill(auditor-skill)"` and `"Skill(auditor-skill *)"` too: there the root skill is your personal skill `auditor-skill`.

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

These rules also let Claude start any of these flows by itself, in any repository you open, and `/auditor:audit-cycle` started that way builds the project on your machine. To rule that out, set `AUDITOR_EXEC_MODE=isolated` (or `none`) in that file's `env`, or keep the rules in a file you pass with `claude --settings` when you audit ([Turns and resuming](permissions-and-isolation.md#turns-and-resuming)).

## 3. Initialize the Trail of Bits submodule (recommended)

The vendored Trail of Bits toolkit (`vendor/trailofbits`) provides real tool execution — SAST, fuzzing, coverage, mutation — that prose and grep cannot do. The plugin install and `install.sh` already fetch it. For a manual clone, pull it from the auditor-skill directory (not your project root):

```bash
cd ~/.claude/skills/auditor-skill    # wherever you cloned it
git submodule update --init --depth 1 -- vendor/trailofbits
```

It is pinned to a reviewed upstream commit; the [README](../README.md#tool-execution-trail-of-bits--optional-rust-tools) names it, and `git ls-tree HEAD vendor/trailofbits` prints it.

The corpus works **fully without it**: agents fall back to `discovery/grep-commands.md` scanners and note the tooling gap in the report. With it initialized, they delegate per [`references/orchestration/boundary-map.md`](../references/orchestration/boundary-map.md). See [power-tools.md](power-tools.md#trail-of-bits-plugins).

## 4. Build the Rust tools (optional)

Three binaries cut audit cost, add cross-audit memory, and run the incident analysis offline. Build them once (`<auditor-skill root>` is where you installed it, e.g. `~/.claude/skills/auditor-skill`):

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release --locked
# binaries: target/release/audit-scan, target/release/audit-mem and target/release/audit-logs
cargo test --locked   # optional: the tests of both packages
```

The agents run them by absolute path from the installation, never from your project ([`OUTPUT-RULES.md` Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)). If auditor-skill sits inside the repository you will audit anyway (such as `.claude/skills/auditor-skill`, where `install.sh` without a path installed through 7.6.0), this build runs inside that tree, where cargo and rustup read its `.cargo/config*` and `rust-toolchain*` from every parent directory: build there only in [Rule 11a](../OUTPUT-RULES.md#rule-11-operating-safety) isolated mode, or delete that copy and install a fresh one outside the repository (the plugin, or `install.sh ~/.claude/skills/auditor-skill`) and build that one. Never move or update a copy you find inside a repository ([section 1](#1-install)).

Build them again after every update of auditor-skill, with `cargo build --release --locked` in the same directory. The flows call them with a contract marker (`--contract=1`) that an older build refuses, and until you rebuild they go on as if the tools were absent. A plugin update installs auditor-skill into a new versioned directory, so the tools need a build there too.

- **`audit-scan`** — deterministic AST pass that emits the risky surface (instructions, account constraints, PDAs, arithmetic, panics, CPIs) as one JSON, at no model cost. Its map replaces part of the reading the audit would otherwise do; how much that saves has not been measured ([COSTS.md](../COSTS.md#keeping-the-cost-down)). It is a *map to verify*, not a set of verdicts. With `--workflows .github/workflows` it also maps each GitHub Actions workflow's triggers, jobs and steps.
- **`audit-mem`** — SQLite store for exact de-dup, FIXED→REGRESSED detection, false-positive suppression, and warm re-audits.
- **`audit-logs`** — the incident analysis recipes `profile.sh`, `frames.py` and `deltas.py` as one offline binary with the same output. `/auditor:hunt` and `/auditor:respond` use it when it is built, and the scripts otherwise.

If `cargo` is absent, skip them — the audit proceeds on the grep walk, and the incident analysis on the scripts. Full detail: [power-tools.md](power-tools.md).

## 5. Adapt to your repo

Quick and Standard need nothing set: pass the range or the path you want reviewed. Before a Full run, two things matter:

1. **Your layout** — `discovery/file-map.md` maps each checklist to the globs it scans, and its defaults assume `programs/{name}/src/`, `apps/backend/src/`, `apps/web/src/`. If your code lives elsewhere, record it at intake (next item): the in-scope paths under `QUESTIONS.md` Q39 ("Specific files/modules") and the exclusions under Q44 go into the Layout table of `audit_<n>/intake.md` §1. The next `/auditor:intake` in the same checkout shows you that table and reuses it only when you answer yes; `--auto` never reuses it, since a layout found in the audited tree could exclude that tree's own code. Do not edit the file-map in a shared or plugin install: an update overwrites it, and the edit is lost. Wrong paths mean the walk looks in the wrong place.
2. **Intake** — the questionnaire drives scope, severity calibration, the trust model and which compliance checklists apply. Full runs it for you: `/auditor:audit-cycle` runs `/auditor:intake --auto`, which records the applied default for every unanswered question, and `/auditor:audit-assist` asks the questions at its first checkpoint. Either way the answers land in `audit_<n>/intake.md`, the durable artifact both flows read. With an agent that reads the skill directly, fill a copy of [`QUESTIONS.md`](../QUESTIONS.md) (47 questions) by hand.

Everything else — checklists, known vectors, output rules — is portable as-is.

## 6. Run your first audit

Start with the cheapest depth that answers your question ([Pick a depth](audit-flows.md#pick-a-depth)).

**Quick** — the commits on your branch, against the tip of `main`. Commit first, and rebase on `main`, so that changes it gained since you branched stay out of the review:

```
/auditor:diff-audit
```

It writes `audit_<n>/PR-REPORT.md`, with a summary block first. For a first look at a whole repository, with no full checklist walk, run `/auditor:quick-scan`, which writes `audit_<n>/QUICK-SCAN.md`; for one function, `/auditor:deep-review <file> <function>`.

**Standard** — one program, every in-scope item:

```
/auditor:audit ./programs/my-program --scope program
```

or in plain language for an agent that reads the skill directly:

```
Audit the Solana program in programs/my-program/ using the auditor-skill with PROGRAM scope
```

**Full** — the engagement, ending in a client report (automated end-to-end):

```
/auditor:audit-cycle --scope full
```

The report lands at `audit_<n>/REPORT.md`, in a new run directory. An existing one is reused only after you confirm which, and never one that git tracks ([Report file naming](output-and-rigor.md#report-file-naming), [Rule 11d](../OUTPUT-RULES.md#11d--output-hygiene)). Review [COSTS.md](../COSTS.md) first: a Full run cost about $20 and an hour on a 3K-line program.

**CI** — to run the analyzers on every pull request and Quick on those from your own branches, copy `templates/ci/auditor-pr.yml` into `.github/workflows/` and follow [ci.md](ci.md). A CI run asks nothing and denies every call that would ask ([section 7](#7-prompts-and-isolation)); an analyzer that did not run fails its verdict.

## 7. Prompts and isolation

The commands run their bundled steps without asking: the working-tree check, run directories, read-only git, the Rust tools, the runners that build and test in the execution mode in force, and the collectors. Each of these checks its own arguments, takes paths inside the working tree (the PoC build cache aside), and writes only into run directories, the `audit-mem` store and scratch directories outside the tree, besides the toolchain caches its downloads fill. Other calls ask, apart from Claude Code's own read-only commands and the file reads the commands pre-approve (Read, Grep and Glob, for any path). [permissions-and-isolation.md](permissions-and-isolation.md) has the full list, and why that is safe.

- **Let flows resume without a prompt.** In Manual mode, a flow that goes on after your reply asks to run its own skill again. Add the `Skill(auditor:… *)` rules from [section 2](#2-once-after-installing) to your user settings once.
- **"Yes, and don't ask again"** at a prompt can save a rule into the audited tree's `.claude/settings.local.json`. Preflight does not refuse that file while git does not track it, so either answer works there (outside a git repository, strict mode counts the file as the repository's, so answer "Yes" in such a workspace); the rules above are what stop the resume prompt for good.
- **Long builds.** A Bash call that outlasts its timeout, two minutes by default, moves to the background, and the flow loses the command's pre-approvals. For long builds and collections, raise `BASH_DEFAULT_TIMEOUT_MS` and `BASH_MAX_TIMEOUT_MS` in your user settings' `env` ([Long steps](permissions-and-isolation.md#long-steps)).
- **For code you don't trust, use strict mode.** Start Claude Code with `claude --setting-sources "" --strict-mcp-config --plugin-dir "<auditor-skill root>" --settings "<auditor-skill root>/templates/strict-settings.json"`, where `<auditor-skill root>` is the folder auditor-skill is installed in ([Default and strict mode](permissions-and-isolation.md#default-and-strict-mode) says where that is). It loads none of your own settings or plugins, so a language-server plugin you enabled cannot run the project's build scripts outside the runners, and the template brings the resume rules your user settings would. Strict mode refuses what default mode only notes, and builds only in isolated mode: under the sandbox the template turns on, or in a container or VM with no credentials ([Strict mode and isolated runs](permissions-and-isolation.md#strict-mode-and-isolated-runs)). Under the launch line the repository's own `.claude/` config does not load, and strict mode still refuses a tree that ships it: audit a clean copy of such a repository ([Default and strict mode](permissions-and-isolation.md#default-and-strict-mode) says why). By default the project's builds and tests run on your machine (native) without a prompt for each run, and the report says so.
- **Non-interactive runs** (`claude -p`, a CI gate) deny every call that would ask, and record it as a step not run: [Non-interactive runs](permissions-and-isolation.md#non-interactive-runs-claude--p).

## Scopes at a glance

`--scope` on `/auditor:audit`, `/auditor:audit-cycle` and `/auditor:audit-assist` picks the part of the repository a run reviews: `full` (the default: the checklists and vectors the repository matches, up to all 20 + 141 vectors), `program`, `backend` or `frontend`. [SKILL.md](../SKILL.md#scope-gated-loading--load-what-the-repo-needs) defines each one. The Quick commands take no scope: they read the selection of `references/depth-scope.md` ([What Quick reads](audit-flows.md#what-quick-reads)).

Scope is enforced by *scope-gated loading*: out-of-scope checklists are never read, and out-of-scope items render `[N/A — out of scope]` from the gate. See [output-and-rigor.md](output-and-rigor.md#scope-gated-loading).

## Next

- The depths and their flows: [audit-flows.md](audit-flows.md)
- CI for pull requests: [ci.md](ci.md)
- Command reference: [commands.md](commands.md)
- What the report guarantees: [output-and-rigor.md](output-and-rigor.md)
- Prompts, isolation and `claude -p`: [permissions-and-isolation.md](permissions-and-isolation.md)
- The optional tools and the bundled scripts: [power-tools.md](power-tools.md)
- After an incident: [detection-response.md](detection-response.md)
- What a run costs: [COSTS.md](../COSTS.md)
