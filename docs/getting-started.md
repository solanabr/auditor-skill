# Getting Started

Get from a clone to a first audit. Back to the [docs index](README.md).

## 1. Install

auditor-skill is a folder of markdown + two small Rust tools — not a SaaS. Clone it, or drop it in as a skill. Keep it **outside any repository you audit** ([`OUTPUT-RULES.md` Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)): a copy inside the target resolves its paths from a tree the target controls.

**Clone it as a user-level skill:**

```bash
git clone https://github.com/solanabr/auditor-skill.git ~/.claude/skills/auditor-skill
```

**Or install it as a plugin** (the `.claude-plugin/` manifest ships with the repo; plugin name is `auditor`). Once installed, commands are available as `/auditor:audit`, `/auditor:audit-cycle`, and so on.

**Or feed the files to an API** — send `SKILL.md` + `OUTPUT-RULES.md` (+ `FULL-AUDIT.md` for a full run) as system context and the target files as user content.

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
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release
# binaries: target/release/audit-scan  and  target/release/audit-mem
cargo test   # optional: scan_fixture + mem_roundtrip
```

The agents run them by absolute path from the installation, never from your project ([`OUTPUT-RULES.md` Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)). If auditor-skill sits inside the repository you will audit anyway (such as `.claude/skills/auditor-skill`, where `install.sh` without a path installed through 7.6.0), this build runs inside that tree, where cargo and rustup read its `.cargo/config*` and `rust-toolchain*` from every parent directory: build there only in [Rule 11a](../OUTPUT-RULES.md#rule-11-operating-safety) isolated mode, or delete that copy and install a fresh one outside the repository (the plugin, or `install.sh ~/.claude/skills/auditor-skill`) and build that one. Never move or update a copy you find inside a repository ([README](../README.md#installation)).

Build them again after every update of auditor-skill, with `cargo build --release --locked` in the same directory. The flows call them with a contract marker (`--contract=1`) that an older build refuses, and until you rebuild they go on as if the tools were absent.

- **`audit-scan`** — deterministic AST pass that emits the risky surface (instructions, account constraints, PDAs, arithmetic, panics, CPIs) as one JSON, at ~$0 LLM cost. On a 50K-line program this removes roughly 200-300K input tokens (~30-40% of the variable cost). It is a *map to verify*, not a set of verdicts.
- **`audit-mem`** — SQLite store for exact de-dup, FIXED→REGRESSED detection, false-positive suppression, and warm re-audits.

If `cargo` is absent, skip both — the audit proceeds on the grep walk. Full detail: [power-tools.md](power-tools.md).

## 4. Adapt to your repo (required)

> auditor-skill was originally built for one Solana/Anchor DeFi project and then generalized. Two things must be set before a serious run:

1. **Your layout** — `discovery/file-map.md` maps each checklist to the globs it scans, and its defaults assume `programs/{name}/src/`, `apps/backend/src/`, `apps/web/src/`. If your code lives elsewhere, record it at intake (next item): the in-scope paths under `QUESTIONS.md` Q39 ("Specific files/modules") and the exclusions under Q44 go into `audit_<n>/intake.md` §1. Do not edit the file-map in a shared or plugin install: an update overwrites it, and the edit is lost. Wrong paths mean the walk looks in the wrong place.
2. **Intake** — the questionnaire drives scope, severity calibration, and which compliance checklists apply. Either:
   - fill a copy of [`QUESTIONS.md`](../QUESTIONS.md) (47 questions) by hand, or
   - run `/auditor:intake` (alias `/scope`) to walk the questions interactively and persist the answers to `audit_<n>/intake.md` — the durable artifact both `/auditor:audit-cycle` and `/auditor:audit-assist` read. Use `/auditor:intake --auto` for no-human pipelines (it records the applied default for every unanswered question).

Everything else — checklists, known vectors, output rules — is portable as-is.

## 5. Run your first audit

**Quickest look** (triage, no full item walk — good for a CI gate):

```
/auditor:quick-scan
```

As a CI gate it runs non-interactively, so the run must be able to run its analyzers: a gate whose analyzers did not run fails. A non-interactive run denies every call that would ask ([section 6](#6-prompts-and-isolation)).

**Full one-shot audit** of a program:

```
/auditor:audit ./programs/my-program --scope program
```

or in plain language for an agent that reads the skill directly:

```
Audit the Solana program in programs/my-program/ using the auditor-skill with PROGRAM scope
```

**Full engagement → client report** (automated end-to-end):

```
/auditor:audit-cycle --scope full
```

The report lands at `audit_<n>/REPORT.md`, in a run directory that `rundir.sh new audit` makes: `<n>` is the highest existing `audit_*` number + 1, and the directory is created with `mkdir` (not `-p`), stopping if it already exists. An existing `audit_<n>/` is reused only when git does not track it and it holds no symbolic links, after you confirm which one; nothing is written into a tracked run directory ([Rule 11d](../OUTPUT-RULES.md#11d--output-hygiene)). Review [COSTS.md](../COSTS.md) first — a full Opus run on a large repo can burn real credits.

## 6. Prompts and isolation

The commands run their bundled steps without asking: the working-tree check, run directories, read-only git, the Rust tools, the runners that build and test in the mode you chose, and the collectors. Each of these checks its own arguments, takes paths inside the working tree (the PoC build cache aside), and writes only into run directories, the `audit-mem` store and scratch directories outside the tree, besides the toolchain caches its downloads fill. Other calls ask, apart from Claude Code's own read-only commands. [permissions-and-isolation.md](permissions-and-isolation.md) has the full list, and why that is safe.

- **Answer a prompt with "Yes".** When Claude Code asks during a run, answer **Yes**, not "Yes, and don't ask again": that saves a rule into the audited tree's `.claude/settings.local.json`, and the next run's preflight refuses that file. If a rule was saved there, move the file's `permissions.allow` entries to `~/.claude/settings.json` and delete it.
- **Let flows resume without a prompt.** In Manual mode, a flow that goes on after your reply asks to run its own skill again. Add the `Skill(auditor:… *)` rules from [Turns and resuming](permissions-and-isolation.md#turns-and-resuming) to your user settings once.
- **Long builds.** A Bash call that outlasts its timeout, two minutes by default, moves to the background, and the flow loses the command's pre-approvals. For long builds and collections, raise `BASH_DEFAULT_TIMEOUT_MS` and `BASH_MAX_TIMEOUT_MS` in your user settings' `env` ([Long steps](permissions-and-isolation.md#long-steps)).
- **For code you don't trust, run isolated.** Answer Isolated at intake, set `AUDITOR_EXEC_MODE=isolated` where Claude Code runs, and run in a container or VM with no credentials, or under Claude Code's sandbox ([Running isolated](permissions-and-isolation.md#running-isolated)). In native mode the project's builds and tests run on your machine without a prompt for each run.
- **Non-interactive runs** (`claude -p`, a CI gate) deny every call that would ask, and record it as a step not run: [Non-interactive runs](permissions-and-isolation.md#non-interactive-runs-claude--p).

## Scopes at a glance

| Scope | Covers | Checklists |
|-------|--------|-----------|
| `full` | everything | all 20 + 140 vectors |
| `program` | Solana program only | 01-07 |
| `backend` | backend API | 08-09 |
| `frontend` | frontend | 08, 10 |
| (quick lane) | known vectors only, grep-based | `/auditor:quick-scan` |

Scope is enforced by *scope-gated loading*: out-of-scope checklists are never read, and out-of-scope items render `[N/A — out of scope]` from the gate. See [output-and-rigor.md](output-and-rigor.md#scope-gated-loading).

## Next

- Understand the flows: [audit-flows.md](audit-flows.md)
- Command reference: [commands.md](commands.md)
- What the report guarantees: [output-and-rigor.md](output-and-rigor.md)
- Prompts, isolation and `claude -p`: [permissions-and-isolation.md](permissions-and-isolation.md)
