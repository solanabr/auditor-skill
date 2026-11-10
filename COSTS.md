# What an audit costs

These are measured runs, not estimates. From 2026-11-08 to 2026-11-10, the depths ran on three Solana repositories, two public and one private, named here by size only. Quick and Standard ran on each one where they apply, and Full and the CI dry run on one. In short:

- **Quick** costs about $2 to $8 and takes 4 to 23 minutes.
  - diff-audit cost $8.10 on the final text, for a range that changes 7,830 lines of a program, its app and its tooling, and adds a 787-package npm lockfile. A narrow change, 1,248 lines of the 12K-line program with no lockfile, cost $3.99 in 9 minutes.
  - quick-scan cost $6.98 on the final text, for a whole repository, and about $3 on a draft, for one program.
- **Standard** costs about $13 to $19 and takes 36 to 56 minutes.
- **Full** cost $19.52 and took an hour on the 3K-line program. It ran once, on that program only, without `--with-poc`.
- **CI** reviews each pull request from your own branches, not a fork's or Dependabot's, at about what diff-audit costs on the final text: $3.99 for the narrow change and $8.10 for the large range above. The review job itself is not measured yet.
  - The CI template caps each review at $15, a ceiling, not a charge.
  - Give an unattended quick-scan or diff-audit the same room. Under a $5 cap, expect the early stop below.

Each figure comes from a single run, so read it as a size, not a quote. The dollar figures are what Claude Code reports as `total_cost_usd`, at Anthropic's list prices. On a Claude subscription, a run uses your plan's allowance instead.

The runs used:

- **Claude Code and model:** Claude Code 2.1.304, with `claude-opus-5-5`, the account's default model, at Claude Code's default effort.
- **Plugin, Standard and Full:** two pre-release builds of 7.7.2 from 2026-11-08, one for the 3K- and 12K-line programs and a later one for the 7K-line program. For these commands the two differ only in wording, and `OUTPUT-RULES.md` is 1.8 KB longer in the later one.
- **Plugin, Quick and CI:** the Quick commands as this release ships them, and earlier drafts of them from the same days.
  - **Final** marks a run on the shipped selection: `references/depth-scope.md` and the commands as this release ships them. It reads what `references/depth-scope.md` selects, checklist sections and known-vector rows, and writes that selection to `audit_<n>/scope.md` before it reads any of them.
  - **Draft** marks a run on an earlier text. The drafts kept the severity 7+ vectors of the detected domains whose markers occurred, and their quick-scan read no checklist.
  - Each figure names the `--max-budget-usd` cap it ran with.

## Cost and time by depth

| Depth | Command | 3K-line program | 7K-line program | 12K-line program |
|---|---|---|---|---|
| Quick | `/auditor:diff-audit <base>..<head>` | final: $8.10 · 18.8 min ($15 cap); draft: $4.84 · 10.5 min ($10 cap) | not run (the repository has one commit, so there is no range) | final: $3.99 · 8.7 min ($8 cap); draft: $1.68 · 3.7 min and $1.77 · 3.9 min ($3 cap) |
| Quick | `/auditor:quick-scan` | final: $6.98 · 22.6 min ($10 cap); draft: $6.78 · 16.4 min ($10 cap) | draft: $7.14 · 11.9 min ($10 cap) | draft: $2.84 · 5.5 min ($5 cap) |
| Standard | `/auditor:audit <path> --scope program` | $13.07 · 36 min | $14.70 · 36 min | $18.83 · 56 min |
| Full | `/auditor:audit-cycle <path> --scope program` | $19.52 · 61 min | not run | not run |
| CI | the tools tier, then the review job's `diff-audit --ci` | tools tier $0; review job, draft: $1.72 · 4.9 min ($5 cap) | | |

- **quick-scan's coverage:** the whole repository for the 3K- and 7K-line programs, and only the program's directory for the 12K-line one.
  - The final text, on the 3K-line repository, selected and read 38 vector files and 49 checklist sections.
  - The drafts kept and read 98, 95 and 55 vector files, and no checklist.
- **diff-audit's coverage:** the 3K-line range adds a 787-package npm lockfile.
  - The final text read 98 vector files and 43 checklist sections, every one its selection listed. It ran checklist 11 §11.11's CI budget on the lockfile: a publish-age lookup for each of its 612 new names, in 18 s, then 17 key-handling packages and 11 others fetched and swept.
  - It reviewed 4,772 of the 7,830 changed lines. The rest, a 3,058-line HTML file's deletion, did not fit the 5,000-line budget, and its report names the file.
  - The draft read 58 vector files whole, plus checklists 04 and 06 and checklist 11's §11.11. Its report named the scope table's other checklists as not read, with no verdict on their items.
  - The 12K-line range read 21 and 16 vector files, on drafts.
  - The final text, on that range (36 files, 1,248 changed lines, no lockfile), read 59 vector files and 36 checklist sections whole, every one its selection listed, and reviewed all 310 changed lines of non-test source.
- **The CI figure** is one dry run of the CI template's review step, `--json-schema` and strict mode included, on the 3K-line program's range. It ran on a draft that read no vector file. On the final text the review job should cost about what diff-audit costs; it is not measured yet.
- **Earlier drafts, before the Quick commands read the corpus:**
  - diff-audit cost $1.23, $0.84, $1.29 and $0.83.
  - quick-scan cost $1.46, $2.20 and $3.62, with agents as each session chose. Starting no agent and reading no vector file, it cost $2.67, $2.91 and $2.19.
- **The two final runs on the 3K-line repository had a lighter setup than the drafts.** The bundled tools were not built, so `audit-scan` mapped nothing, and quick-scan's cargo-audit had no advisory database, so it did not run. The final diff-audit on the 12K-line program had both.

**A cap close to the run's cost cuts the review short.** Claude Code shows the session its budget ("USD budget: $spent/$max; $remaining remaining"), and the session plans by it. Under a $5 cap, a draft session rationed: it stopped reading early, and its report said what it skipped.

- At a $5 cap, two whole-repository quick-scans each kept about 80 vector files and read only 14 and 15 of them.
- The 3K-line diff-audit at a $5 cap read its 48 selected vector files, but left its checklists unread "to stay within the USD 5 session cap". It cost $2.94.
- At a $10 cap, quick-scan read every kept file, and that diff-audit read all 58 of its selected vector files without mentioning its budget.
- The shipped commands tell the session never to leave a selected file unread for its budget, and in CI a run that leaves one unread fails.

**A fuller setup may cost somewhat more.** These runs were lighter than a full one in three ways:

- **Effort.** It was Claude Code's default. A session set to a higher effort, such as `xhigh`, spends more on thinking.
- **Static analysis.** semgrep was not installed and the Trail of Bits submodule was empty, so the static-analysis step used the grep fallback. With semgrep installed, quick-scan and the audits also read its results.
- **The bundled tools,** in the final Quick runs, as above.

No run reached its cap: $3, $5, $8, $10 and $15 for diff-audit, $5 and $10 for quick-scan, $5 for the CI review, $25 for Standard and $60 for Full.

## The three repositories

- **The 3K-line program:** 3,006 lines of Anchor in 9 files, with 8,800 more lines of tests. It sits in a mobile-app repository of 1,200 files and 20 commits. The diff range held 7 commits, one of them in the program, with +603 and −22 lines of program source.
- **The 7K-line program:** 7,188 lines of Anchor in 10 files, with 1,900 more lines of tests and examples. It sits in a private repository of 3,900 files and a single commit, which holds about 34K lines of Rust in all.
- **The 12K-line program:** 12,219 lines of Pinocchio in 119 files, with 15,000 more lines of tests. It sits in a TypeScript monorepo of 2,400 files and 717 commits, and every run was limited to the program's directory. The diff range was one merged pull request: 13 commits, 7 of them in the program, with +248 and −27 lines of program source.

## What drives the cost

- **Re-sent context, more than output.** Every turn sends the conversation again, mostly from the prompt cache. Cache reads were 86% to 96% of all tokens in every run, and output was under 3%. In the Opus part of the spend, writing context to the cache took about 33% to 57%, reading it back 14% to 34%, and output, thinking included, 24% to 39%.
- **Agents.** Standard starts four agents: `context-builder` and `audit-reporter` on Sonnet, and `vuln-hunter` and `economic-analyst` on Opus. Each one reads the rules and its share of the code again. Opus took 76% to 86% of the Standard and Full spend. Full adds `threat-modeler` and `peer-reviewer` on Opus, and a triage pass. quick-scan and diff-audit start none, and deep-review may start one.
- **What Quick selects.** On the drafts, quick-scan's cost followed how many vector rows it kept: 55 cost $2.84, and 95 and 98 cost $7.14 and $6.78. The final text keeps fewer vector files and adds checklist sections: on the 3K-line repository, its 38 files and 49 sections cost $6.98, where the draft's 98 files cost $6.78. A whole repository with an app, tools and CI selects the most. diff-audit's final text selects more for a change than quick-scan does for a repository: every `always` vector row of the domains the change touches, and the marker rows of severity 6 or more. On the 3K-line range it read 98 vector files and 43 sections for $8.10, where the draft read 58 files and three checklists for $4.84.
- **Code size, less than you might expect, in Standard.** Standard cost $13.07, $14.70 and $18.83 for the 3K-, 7K- and 12K-line programs, and each run covered the same 604 checklist items.
- **Depth.** On the 3K-line program, Full cost 1.5 times what Standard did and took 1.7 times as long.

## What a run reads

| Corpus | Size, at about 4 characters a token | What the measured runs read |
|---|---|---|
| `SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md` | ~37K tokens | **Standard and Full:** `OUTPUT-RULES.md` 6 to 9 times a run, once for each agent and once for the session. **Quick:** `OUTPUT-RULES.md`. The drafts' diff-audit also read `SKILL.md`'s scope table, which the final text replaces with `references/depth-scope.md`. |
| Checklists (20 files, 1,465 items) | ~76K tokens | **Standard and Full:** the in-scope ones only. For a Rust program, Standard took 604 items (checklists 01–07 and 16) and Full took 531 (01–07). **Quick, final:** the sections `references/depth-scope.md` selects, each read whole: 49 for quick-scan on the 3K-line repository, and 43 for diff-audit on its range. **Quick, drafts:** diff-audit read the scope table's checklists for the changed code, and quick-scan none. |
| Known vectors (141 procedures) | ~128K tokens | **Quick:** `INDEX.md`, then each vector file the selection keeps, whole: 38 for quick-scan and 98 for diff-audit on the final text, and 55 to 98 and 16 to 58 on the drafts. **Standard and Full:** `INDEX.md`, and 0 to 2 vector files a run. Standard judged 57 to 59 vectors for a Rust program, and Full all 140 the corpus then held, from their `INDEX.md` rows rather than their procedures. |
| `references/` | ~170K tokens | **Standard and Full:** 2 to 10 files a run, when a marker in the code calls for one. **Quick, final:** `depth-scope.md`, about 4K tokens. |

## How the runs were set up

- **Command line.** `claude -p "<command>" --setting-sources "" --strict-mcp-config --plugin-dir <auditor-skill> --max-budget-usd <cap> --output-format stream-json --verbose`, with the repository as the working directory.
  - With no setting sources, neither the repository's `.claude/` nor the user's own settings, plugins, skills or `CLAUDE.md` load, so the run sees what a fresh CI runner sees. A `--settings` file still applies.
  - The final event of `stream-json` is the same object that `--output-format json` prints.
- **Nothing from the repositories ran.** Every run had `AUDITOR_EXEC_MODE=none`, so no build, test or PoC from them ran.
- **The CI dry run** used the CI template's environment as well: `AUDITOR_STRICT=1`, with strict preflight before the paid call, and `--output-format json --json-schema` with the verdict schema in place of `stream-json`.
- **Permissions.** No permission mode was set, so Claude Code denied any call the command doesn't pre-approve. Each run had 0 to 26 such denials. They were the session's own extra shell commands, and none of them stopped a run.
  - For `audit-cycle` only, the run passed the `Skill(auditor:…)` rules from [Turns and resuming](docs/permissions-and-isolation.md#turns-and-resuming) with `--settings`, so its intake and triage steps could start. Its command line also carried `--auto`, which is not one of audit-cycle's options.
- **Tools.**
  - The bundled Rust tools in `tools/auditor-tools` were built, so `audit-scan` mapped each program, except in the final Quick runs.
  - cargo-audit read a local copy of the RustSec database, except in the final quick-scan, which had none.
  - For the private repository, the npm, crates.io and GitHub hosts were blocked, so no dependency list left the machine, and npm-audit did not run there.
  - A run can read a program's on-chain account through a public Solana RPC with `rpc-read.sh`, which sends that program's address there; one Standard run did. The Solana RPC hosts were blocked for the later draft Quick runs, and the final runs called none.
  - No LaTeX engine was installed, so `audit-cycle` wrote no PDF.

## Keeping the cost down

- **Match the depth to the question.** Use Quick for each change or pull request, Standard for one module before it merges, and Full before a release.
- **Keep each reviewed change narrow.** diff-audit selects by the kinds of file a change touches: on-chain program source alone selects at most 39 checklist sections, 46 with a manifest or lockfile, a workflow and a key file as well, and a change that touches every kind up to 62. The 3K-line range above touched a program, an app, tooling and a lockfile, and cost $8.10.
- **Cap every unattended run, with room.** With `claude -p`, `--max-budget-usd` stops the session after the turn that crosses the cap. Set the cap well above the figures here, since a session that sees its cap close may cut its pass short.
- **Name the path and the scope.** `/auditor:audit programs/<name> --scope program` reads one program, not the whole repository, and quick-scan on one program selects less.
- **Build the bundled tools.** `audit-scan`'s map of instructions, constraints and PDAs replaces part of the reading.

## Track your own runs

`claude -p "/auditor:diff-audit main..HEAD" --output-format json --max-budget-usd 15` prints `total_cost_usd`, `duration_ms`, `num_turns` and `usage` when the run ends. Its `modelUsage` splits the cost by model, the agents' share included.

## Not measured yet

- These depths on a large program of 50K lines or more.
- quick-scan's final text on the 7K- and 12K-line programs, diff-audit's on the 7K-line one, and the CI template's review job.
- Sonnet as the session's model, and a higher effort.
- quick-scan and the audits with semgrep installed.
- Repeat runs, to see how far each figure varies.
- `deep-review`, `audit-assist`, `re-audit`, `audit-cycle --with-poc`, `spec-audit`, and the incident commands `hunt` and `respond`.
