# What an audit costs

These are measured runs, not estimates. On 2026-11-08 each audit depth ran on two public Solana repositories, which are named here by size only. The runs used Claude Code 2.1.304 with `claude-opus-5-5`, the account's default model, at Claude Code's default effort, and auditor-skill 7.7.0 at commit `2be77c4`.

The dollar figures are what Claude Code reports as `total_cost_usd`, at Anthropic's list prices. On a Claude subscription, a run uses your plan's allowance instead.

Each figure comes from a single run, so read it as a size, not a quote. What moved the cost most was whether the session started review agents. A command that names none, like quick-scan, leaves that to the session.

## Cost and time by depth

| Depth | Command | Small program (3K lines) | Medium program (12K lines) |
|---|---|---|---|
| Quick | `/auditor:diff-audit <base>..<head>` | $1.23 · 5 min | $0.84 · 3 min |
| Quick | `/auditor:quick-scan` | $1.46 · 9 min | $3.62 · 8 min |
| Standard | `/auditor:audit <path> --scope program` | $13.07 · 36 min | $18.83 · 56 min |
| Full | `/auditor:audit-cycle <path> --scope program` | $19.52 · 61 min | not run |
| CI | the tools tier, then `diff-audit` in a job | tools tier $0; the review job costs what Quick costs | |

In short:

- **Quick** costs about $1 to $4 and takes under 10 minutes.
- **Standard** costs about $13 to $19 and takes 35 to 60 minutes.
- **Full** cost $19.52 and took an hour on the small program. It ran once, on that program only, without `--with-poc`.
- **CI** runs Quick on each pull request. `diff-audit` on a pull-request-sized range cost about $1, so a `--max-budget-usd` cap of $3 to $5 covers it.

No run reached its cap: $3 for diff-audit, $5 for quick-scan, $25 for Standard and $60 for Full.

## The two repositories

- **Small:** a 3,006-line Anchor program in 9 files, with 8,800 more lines of tests. It sits in a mobile-app repository of 1,200 files and 20 commits. The diff range held 7 commits, one of them in the program: +603 and −22 lines of program source.
- **Medium:** a 12,219-line Pinocchio program in 119 files, with 15,000 more lines of tests. It sits in a TypeScript monorepo of 2,400 files and 717 commits, and every run was limited to the program's directory. The diff range was one merged pull request: 13 commits, 7 of them in the program, +248 and −27 lines of program source.

## What drives the cost

- **Re-sent context, more than output.** Every turn sends the conversation again, mostly from the prompt cache. Cache reads were 89% to 94% of all tokens in every run, and output was under 3%. In the Opus part of the spend, writing context to the cache took about 36% to 52%, reading it back about 18% to 28%, and output, thinking included, about 25% to 39%.
- **Agents.** Standard starts four agents: `context-builder` and `audit-reporter` on Sonnet, and `vuln-hunter` and `economic-analyst` on Opus. Each one reads the rules and its share of the code again. Opus took 76% to 86% of the Standard and Full spend. Full adds `threat-modeler` and `peer-reviewer` on Opus, and a triage pass.
- **Code size, less than you might expect.** Going from 3K to 12K lines of program, Standard cost 1.4 times as much and took 1.5 times as long. Both runs covered the same 604 checklist items.
- **Depth.** On the small program, Full cost 1.5 times what Standard did and took 1.7 times as long.
- **quick-scan names no agents.** The session decides whether to start any, and on which model: two on the medium program, none on the small one. diff-audit started none in either run.

## What a run reads

| Corpus | Size, at about 4 characters a token | Who reads it |
|---|---|---|
| `SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md` | ~33K tokens | every depth, once per session and once per agent |
| Checklists (20 files, 1,465 items) | ~74K tokens | Standard and Full, the in-scope ones only. For a Rust program Standard took 604 items (checklists 01–07 and 16), and Full took 531 (01–07). |
| Known vectors (141 procedures) | ~125K tokens | Quick, the CRITICAL and HIGH ones for the detected domains. Standard took 58 or 59 of the 140 for a Rust program, and Full swept all 140. |
| `references/` | ~160K tokens | when a marker in the code calls for a file |

## How the runs were set up

- **Command line.** `claude -p "<command>" --setting-sources "" --strict-mcp-config --plugin-dir <auditor-skill> --max-budget-usd <cap> --output-format stream-json --verbose`, with the repository as the working directory. With no setting sources, neither the repository's `.claude/` nor the user's own settings, plugins, skills or `CLAUDE.md` load. The run then sees what a fresh CI runner sees. The final event of `stream-json` is the same object that `--output-format json` prints.
- **Nothing from the repositories ran.** Every run had `AUDITOR_EXEC_MODE=none`, so no build, test or PoC from them ran.
- **Permissions.** No permission mode was set, so Claude Code denied any call the command doesn't pre-approve. Each run had 0 to 13 such denials. They were the session's own extra shell commands, and none of them stopped a run. For `audit-cycle` only, the run passed the `Skill(auditor:…)` rules from [Turns and resuming](docs/permissions-and-isolation.md#turns-and-resuming) with `--settings`, so its intake and triage steps could start.
- **Tools.** The bundled Rust tools in `tools/auditor-tools` were built, so `audit-scan` mapped each program. semgrep was not installed and the Trail of Bits submodule was not checked out, so static analysis fell back to the grep scanners. cargo-audit read a local copy of the RustSec database. No LaTeX engine was installed, so `audit-cycle` wrote no PDF.

## Keeping the cost down

- **Match the depth to the question.** Use Quick for each change or pull request, Standard for one module before it merges, and Full before a release.
- **Cap every unattended run.** With `claude -p`, `--max-budget-usd` stops the session after the turn that crosses the cap.
- **Name the path and the scope.** `/auditor:audit programs/<name> --scope program` reads one program, not the whole repository.
- **Build the bundled tools.** `audit-scan`'s map of instructions, constraints and PDAs replaces part of the reading.

## Track your own runs

`claude -p "/auditor:diff-audit main..HEAD" --output-format json --max-budget-usd 5` prints `total_cost_usd`, `duration_ms`, `num_turns` and `usage` when the run ends. Its `modelUsage` splits the cost by model, the agents' share included.

## Not measured yet

- These depths on a large program of 50K lines or more.
- Sonnet as the session's model.
- Repeat runs of Standard and Full, to see how far they vary.
- `deep-review`, `audit-assist`, `re-audit`, `audit-cycle --with-poc`, `spec-audit`, and the incident commands `hunt` and `respond`.
