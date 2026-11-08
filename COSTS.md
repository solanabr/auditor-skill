# What an audit costs

These are measured runs, not estimates. On 2026-11-08 each audit depth ran on three Solana repositories, two public and one private, named here by size only.

- **Claude Code and model:** Claude Code 2.1.304, with `claude-opus-5-5`, the account's default model, at Claude Code's default effort.
- **Plugin, Standard and Full:** auditor-skill 7.7.0 at commit `2be77c4` for the first two repositories, and 7.7.2 at `531a076` for the third. For these commands the two versions differ only in wording, and `OUTPUT-RULES.md` is 1.8 KB longer in 7.7.2.
- **Plugin, Quick and CI:** 7.7.2 with the reworked Quick commands at `15b2de8`, which point quick-scan and diff-audit at the known-vector index. Quick was measured again on it, and the table gives those runs.

The dollar figures are what Claude Code reports as `total_cost_usd`, at Anthropic's list prices. On a Claude subscription, a run uses your plan's allowance instead.

Each figure comes from a single run, so read it as a size, not a quote. What moved the cost most was whether the session started review agents, and a command that names none, like quick-scan, leaves that to the session.

## Cost and time by depth

| Depth | Command | 3K-line program | 7K-line program | 12K-line program |
|---|---|---|---|---|
| Quick | `/auditor:diff-audit <base>..<head>` | $1.29 · 4.5 min | not run (the repository has one commit, so there is no range) | $0.83 · 2.3 min |
| Quick | `/auditor:quick-scan` | $2.96 · 11.3 min | $3.71 · 8.3 min | $2.11 · 4.4 min |
| Standard | `/auditor:audit <path> --scope program` | $13.07 · 36 min | $14.70 · 36 min | $18.83 · 56 min |
| Full | `/auditor:audit-cycle <path> --scope program` | $19.52 · 61 min | not run | not run |
| CI | the tools tier, then the review job's `diff-audit --ci` | tools tier $0; review job $1.72 · 4.9 min | | |

- **quick-scan's coverage:** the whole repository for the 3K- and 7K-line programs, and only the program's directory for the 12K-line one.
- **Before the Quick rework:** diff-audit cost $1.23 and $0.84, and quick-scan $1.46, $2.20 and $3.62.
- **The CI figure:** one dry run of the CI template's review step, `--json-schema` and strict mode included, on the 3K-line program's range.

**A fuller setup may cost somewhat more.** Two things kept these runs lighter than a full one:

- **Effort.** It was Claude Code's default. A session set to a higher effort, such as `xhigh`, spends more on thinking.
- **Static analysis.** semgrep was not installed and the Trail of Bits submodule was empty, so the static-analysis step used the grep fallback. With semgrep installed, quick-scan and the audits also read its results.

In short:

- **Quick** costs about $1 to $4 and takes 2 to 11 minutes.
- **Standard** costs about $13 to $19 and takes 35 to 60 minutes.
- **Full** cost $19.52 and took an hour on the 3K-line program. It ran once, on that program only, without `--with-poc`.
- **CI** runs Quick on each pull request. Its review job cost $1.72 in its dry run, and `diff-audit` on a pull-request-sized range cost about $1, so a `--max-budget-usd` cap of $3 to $5 covers it.

No run reached its cap: $3 for diff-audit, $5 for quick-scan and for the CI review, $25 for Standard and $60 for Full.

## The three repositories

- **The 3K-line program:** 3,006 lines of Anchor in 9 files, with 8,800 more lines of tests. It sits in a mobile-app repository of 1,200 files and 20 commits. The diff range held 7 commits, one of them in the program, with +603 and −22 lines of program source.
- **The 7K-line program:** 7,188 lines of Anchor in 10 files, with 1,900 more lines of tests and examples. It sits in a private repository of 3,900 files and a single commit, which holds about 34K lines of Rust in all.
- **The 12K-line program:** 12,219 lines of Pinocchio in 119 files, with 15,000 more lines of tests. It sits in a TypeScript monorepo of 2,400 files and 717 commits, and every run was limited to the program's directory. The diff range was one merged pull request: 13 commits, 7 of them in the program, with +248 and −27 lines of program source.

## What drives the cost

- **Re-sent context, more than output.** Every turn sends the conversation again, mostly from the prompt cache. Cache reads were 86% to 96% of all tokens in every run, and output was under 3%. In the Opus part of the spend, writing context to the cache took about 33% to 57%, reading it back 14% to 34%, and output, thinking included, 24% to 39%.
- **Agents.** Standard starts four agents: `context-builder` and `audit-reporter` on Sonnet, and `vuln-hunter` and `economic-analyst` on Opus. Each one reads the rules and its share of the code again. Opus took 76% to 86% of the Standard and Full spend. Full adds `threat-modeler` and `peer-reviewer` on Opus, and a triage pass.
- **Code size, less than you might expect.** Standard cost $13.07, $14.70 and $18.83 for the 3K-, 7K- and 12K-line programs, and each run covered the same 604 checklist items.
- **Depth.** On the 3K-line program, Full cost 1.5 times what Standard did and took 1.7 times as long.
- **quick-scan names no agents.** The session decides whether to start any, and on which model. In the measured runs it started none for the 3K-line program, two for the 7K-line repository and three for the 12K-line program, and put some of them on Sonnet. diff-audit started none.

## What a run reads

| Corpus | Size, at about 4 characters a token | What the measured runs read |
|---|---|---|
| `SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md` | ~33K tokens | **Standard and Full:** `OUTPUT-RULES.md` 6 to 9 times a run, once for each agent and once for the session. **quick-scan:** `OUTPUT-RULES.md` up to 3 times. **diff-audit:** none of them. |
| Checklists (20 files, 1,465 items) | ~74K tokens | **Standard and Full:** the in-scope ones only. For a Rust program, Standard took 604 items (checklists 01–07 and 16) and Full took 531 (01–07). **Quick:** none. |
| Known vectors (141 procedures) | ~125K tokens | **Standard:** 57 to 59 of the 140 for a Rust program. **Full:** all 140. Both judged them mostly from `known-vectors/INDEX.md`, and no run read more than two vector files in full. **quick-scan:** `INDEX.md` 1 to 5 times a run, and at most two vector files. **diff-audit:** none. |
| `references/` | ~160K tokens | **Standard and Full:** 2 to 10 files a run, when a marker in the code calls for one. |

So the Quick figures are for sessions that judged the vectors from their index lines and the code, not from the vectors' own procedures. A Quick run that reads each vector it keeps, as quick-scan now asks, will cost more.

## How the runs were set up

- **Command line.** `claude -p "<command>" --setting-sources "" --strict-mcp-config --plugin-dir <auditor-skill> --max-budget-usd <cap> --output-format stream-json --verbose`, with the repository as the working directory.
  - With no setting sources, neither the repository's `.claude/` nor the user's own settings, plugins, skills or `CLAUDE.md` load, so the run sees what a fresh CI runner sees. A `--settings` file still applies.
  - The final event of `stream-json` is the same object that `--output-format json` prints.
- **Nothing from the repositories ran.** Every run had `AUDITOR_EXEC_MODE=none`, so no build, test or PoC from them ran.
- **The CI dry run** used the CI template's environment as well: `AUDITOR_STRICT=1`, with strict preflight before the paid call, and `--output-format json --json-schema` with the verdict schema in place of `stream-json`.
- **Permissions.** No permission mode was set, so Claude Code denied any call the command doesn't pre-approve. Each run had 0 to 26 such denials. They were the session's own extra shell commands, and none of them stopped a run.
  - For `audit-cycle` only, the run passed the `Skill(auditor:…)` rules from [Turns and resuming](docs/permissions-and-isolation.md#turns-and-resuming) with `--settings`, so its intake and triage steps could start.
- **Tools.**
  - The bundled Rust tools in `tools/auditor-tools` were built, so `audit-scan` mapped each program.
  - cargo-audit read a local copy of the RustSec database.
  - For the private repository, the npm, crates.io and GitHub hosts were blocked, so no dependency list left the machine, and npm-audit did not run there.
  - A run can read a program's on-chain account through a public Solana RPC with `rpc-read.sh`, which sends that program's address there; one Standard run did. The Solana RPC hosts were blocked too for the private repository's Quick runs.
  - No LaTeX engine was installed, so `audit-cycle` wrote no PDF.

## Keeping the cost down

- **Match the depth to the question.** Use Quick for each change or pull request, Standard for one module before it merges, and Full before a release.
- **Cap every unattended run.** With `claude -p`, `--max-budget-usd` stops the session after the turn that crosses the cap.
- **Name the path and the scope.** `/auditor:audit programs/<name> --scope program` reads one program, not the whole repository.
- **Build the bundled tools.** `audit-scan`'s map of instructions, constraints and PDAs replaces part of the reading.

## Track your own runs

`claude -p "/auditor:diff-audit main..HEAD" --output-format json --max-budget-usd 5` prints `total_cost_usd`, `duration_ms`, `num_turns` and `usage` when the run ends. Its `modelUsage` splits the cost by model, the agents' share included.

## Not measured yet

- These depths on a large program of 50K lines or more.
- Sonnet as the session's model, and a higher effort.
- quick-scan and the audits with semgrep installed.
- Repeat runs of Standard and Full, to see how far they vary.
- `deep-review`, `audit-assist`, `re-audit`, `audit-cycle --with-poc`, `spec-audit`, and the incident commands `hunt` and `respond`.
