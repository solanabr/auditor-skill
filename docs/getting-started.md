# Getting Started

Get from a clone to a first audit. Back to the [docs index](README.md).

## 1. Install

auditor-skill is a folder of markdown + three small Rust tools — not a SaaS. Clone it, or drop it in as a skill. Keep it **outside any repository you audit** ([`OUTPUT-RULES.md` Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)): a copy inside the target resolves its paths from a tree the target controls.

**Clone it as a user-level skill:**

```bash
git clone https://github.com/solanabr/auditor-skill.git ~/.claude/skills/auditor-skill
```

**Or install it as a plugin** (the `.claude-plugin/` manifest ships with the repo; plugin name is `auditor`). Once installed, commands are available as `/auditor:audit`, `/auditor:audit-cycle`, and so on.

**Or feed the files to an API** — send `SKILL.md` + `OUTPUT-RULES.md` (+ `FULL-AUDIT.md` for a full run) as system context and the target files as user content.

**Once, after installing** (Claude Code): add these rules to `permissions.allow` in your user settings, `~/.claude/settings.json`, so a flow resumes after your reply without a prompt. With a clone under `~/.claude/skills/`, add `"Skill(auditor-skill)"` and `"Skill(auditor-skill *)"` too.

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

## 2. Initialize the Trail of Bits submodule (recommended)

The vendored Trail of Bits toolkit (`vendor/trailofbits`) provides real tool execution — SAST, fuzzing, coverage, mutation — that prose and grep cannot do. The plugin install and `install.sh` already fetch it. For a manual clone, pull it from the auditor-skill directory (not your project root):

```bash
cd ~/.claude/skills/auditor-skill    # wherever you cloned it
git submodule update --init --depth 1 -- vendor/trailofbits
```

It is pinned to a reviewed upstream commit; the [README](../README.md#tool-execution-trail-of-bits--optional-rust-tools) names it, and `git ls-tree HEAD vendor/trailofbits` prints it.

The corpus works **fully without it**: agents fall back to `discovery/grep-commands.md` scanners and note the tooling gap in the report. With it initialized, they delegate per [`references/orchestration/boundary-map.md`](../references/orchestration/boundary-map.md). See [power-tools.md](power-tools.md#trail-of-bits-plugins).

## 3. Build the Rust tools (optional, high value)

Two binaries cut audit cost and add cross-audit memory. Build once (`<auditor-skill root>` is where you installed it, e.g. `~/.claude/skills/auditor-skill`):

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release --locked
# binaries: target/release/audit-scan  and  target/release/audit-mem
cargo test   # optional: scan_fixture + mem_roundtrip
```

The agents run them by absolute path from the installation, never from your project ([`OUTPUT-RULES.md` Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)). If auditor-skill sits inside the repository you will audit anyway (such as `.claude/skills/auditor-skill`, where `install.sh` without a path installed through 7.6.0), this build runs inside that tree, where cargo and rustup read its `.cargo/config*` and `rust-toolchain*` from every parent directory: build there only in [Rule 11a](../OUTPUT-RULES.md#rule-11-operating-safety) isolated mode, or delete that copy and install a fresh one outside the repository (the plugin, or `install.sh ~/.claude/skills/auditor-skill`) and build that one. Never move or update a copy you find inside a repository ([README](../README.md#installation)).

Build them again after every update of auditor-skill, with `cargo build --release --locked` in the same directory. The flows call them with a contract marker (`--contract=1`) that an older build refuses, and until you rebuild they go on as if the tools were absent.

- **`audit-scan`** — deterministic AST pass that emits the risky surface (instructions, account constraints, PDAs, arithmetic, panics, CPIs) as one JSON, at ~$0 LLM cost. On a 50K-line program this removes roughly 200-300K input tokens (~30-40% of the variable cost). It is a *map to verify*, not a set of verdicts.
- **`audit-mem`** — SQLite store for exact de-dup, FIXED→REGRESSED detection, false-positive suppression, and warm re-audits.

If `cargo` is absent, skip both — the audit proceeds on the grep walk. Full detail: [power-tools.md](power-tools.md).

## 4. Adapt to your repo

> auditor-skill was originally built for one Solana/Anchor DeFi project and then generalized. Quick and Standard need nothing set: pass the range or the path you want reviewed. Before a Full run, two things matter:

1. **Your layout** — `discovery/file-map.md` maps each checklist to the globs it scans, and its defaults assume `programs/{name}/src/`, `apps/backend/src/`, `apps/web/src/`. If your code lives elsewhere, record it at intake (next item): the in-scope paths under `QUESTIONS.md` Q39 ("Specific files/modules") and the exclusions under Q44 go into the Layout table of `audit_<n>/intake.md` §1. The next `/auditor:intake` in the same checkout shows you that table and reuses it only when you answer yes; `--auto` never reuses it, since a layout found in the audited tree could exclude that tree's own code. Do not edit the file-map in a shared or plugin install: an update overwrites it, and the edit is lost. Wrong paths mean the walk looks in the wrong place.
2. **Intake** — the questionnaire drives scope, severity calibration, the trust model and which compliance checklists apply. Full runs it for you: `/auditor:audit-cycle` runs `/auditor:intake --auto`, which records the applied default for every unanswered question, and `/auditor:audit-assist` asks the questions at its first checkpoint. Either way the answers land in `audit_<n>/intake.md`, the durable artifact both flows read. With an agent that reads the skill directly, fill a copy of [`QUESTIONS.md`](../QUESTIONS.md) (47 questions) by hand.

Everything else — checklists, known vectors, output rules — is portable as-is.

## 5. Run your first audit

Start with the cheapest depth that answers your question ([Pick a depth](audit-flows.md#pick-a-depth)).

**Quick** — the commits on your branch, against the tip of `main`. Commit first, and rebase on `main`, so that changes it gained since you branched stay out of the review:

```
/auditor:diff-audit
```

For a first look at a whole repository, with no checklist walk, run `/auditor:quick-scan`.

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

The report lands at `audit_<n>/REPORT.md`, in a run directory that `rundir.sh new audit` makes: `<n>` is the next number whose name the repository tracks nothing under, and the directory is created with `mkdir` (not `-p`), stopping if it already exists. An existing `audit_<n>/` is reused only when git does not track it and it holds no symbolic link that leads out of it (in strict mode, none at all), after you confirm which one; nothing is written into a tracked run directory ([Rule 11d](../OUTPUT-RULES.md#11d--output-hygiene)). Review [COSTS.md](../COSTS.md) first — a Full run on a large repo can burn real credits.

**CI** — to run Quick on every pull request, copy `templates/ci/auditor-pr.yml` into `.github/workflows/` and follow [ci.md](ci.md). A CI run asks nothing and denies every call that would ask ([section 6](#6-prompts-and-isolation)); an analyzer that did not run fails its verdict.

## 6. Prompts and isolation

The commands run their bundled steps without asking: the working-tree check, run directories, read-only git, the Rust tools, the runners that build and test in the execution mode in force, and the collectors. Each of these checks its own arguments, takes paths inside the working tree (the PoC build cache aside), and writes only into run directories, the `audit-mem` store and scratch directories outside the tree, besides the toolchain caches its downloads fill. Other calls ask, apart from Claude Code's own read-only commands and the file reads the commands pre-approve (Read, Grep and Glob, for any path). [permissions-and-isolation.md](permissions-and-isolation.md) has the full list, and why that is safe.

- **Let flows resume without a prompt.** In Manual mode, a flow that goes on after your reply asks to run its own skill again. Add the `Skill(auditor:… *)` rules from [section 1](#1-install) to your user settings once.
- **"Yes, and don't ask again"** at a prompt can save a rule into the audited tree's `.claude/settings.local.json`. Preflight does not refuse that file while git does not track it, so either answer works there (outside a git repository, strict mode counts the file as the repository's, so answer "Yes" in such a workspace); the rules above are what stop the resume prompt for good.
- **Long builds.** A Bash call that outlasts its timeout, two minutes by default, moves to the background, and the flow loses the command's pre-approvals. For long builds and collections, raise `BASH_DEFAULT_TIMEOUT_MS` and `BASH_MAX_TIMEOUT_MS` in your user settings' `env` ([Long steps](permissions-and-isolation.md#long-steps)).
- **For code you don't trust, use strict mode.** Start Claude Code with `claude --setting-sources "" --strict-mcp-config --plugin-dir "<auditor-skill root>" --settings "<auditor-skill root>/templates/strict-settings.json"`, where `<auditor-skill root>` is the folder auditor-skill is installed in ([Default and strict mode](permissions-and-isolation.md#default-and-strict-mode) says where that is). It loads none of your own settings or plugins, so a language-server plugin you enabled cannot run the project's build scripts outside the runners, and the template brings the resume rules your user settings would. Strict mode refuses what default mode only notes, and builds only in isolated mode: under the sandbox the template turns on, or in a container or VM with no credentials ([Strict mode and isolated runs](permissions-and-isolation.md#strict-mode-and-isolated-runs)). Under the launch line the repository's own `.claude/` config does not load. Strict mode still refuses a tree that ships it, because preflight cannot see how Claude Code was started: for such a repository, audit a copy with every `.claude/` and `.mcp.json` deleted. By default the project's builds and tests run on your machine (native) without a prompt for each run, and the report says so.
- **Non-interactive runs** (`claude -p`, a CI gate) deny every call that would ask, and record it as a step not run: [Non-interactive runs](permissions-and-isolation.md#non-interactive-runs-claude--p).

## Scopes at a glance

`--scope` on `/auditor:audit`, `/auditor:audit-cycle` and `/auditor:audit-assist` picks the part of the repository a run reviews: `full` (the default: the checklists and vectors the repository matches, up to all 20 + 141 vectors), `program`, `backend` or `frontend`. [SKILL.md](../SKILL.md#scope-gated-loading--load-what-the-repo-needs) defines each one. The Quick commands take no scope.

Scope is enforced by *scope-gated loading*: out-of-scope checklists are never read, and out-of-scope items render `[N/A — out of scope]` from the gate. See [output-and-rigor.md](output-and-rigor.md#scope-gated-loading).

## Next

- The depths and their flows: [audit-flows.md](audit-flows.md)
- Quick on every pull request: [ci.md](ci.md)
- Command reference: [commands.md](commands.md)
- What the report guarantees: [output-and-rigor.md](output-and-rigor.md)
- Prompts, isolation and `claude -p`: [permissions-and-isolation.md](permissions-and-isolation.md)
