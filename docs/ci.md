# CI: a Quick review of every pull request

auditor-skill can review every pull request with nobody at the keyboard. The workflow template, `templates/ci/auditor-pr.yml`, runs two jobs: a free one that runs the bundled analyzers on every pull request, forks included, and a review by Claude Code for pull requests from your repository's own branches. Each job ends with one line that says pass or fail and nothing about what it found. On a public repository anyone signed in to GitHub can read a job's log, so the details stay on the runner, and you read them by running the same check yourself.

This is the Quick depth, run unattended. It is not a full audit: `/auditor:audit` covers a module and `/auditor:audit-cycle` a release ([audit-flows.md](audit-flows.md)).

## Setup

1. Copy `templates/ci/auditor-pr.yml`, from the auditor-skill release you use, to `.github/workflows/auditor-pr.yml` in your repository.
2. Pin auditor-skill. Set `AUDITOR_SKILL_COMMIT`, near the top of the file, to the full commit id of that release's tag; `git ls-remote https://github.com/solanabr/auditor-skill refs/tags/<tag>` prints it. Both jobs fetch exactly that commit and stop when it does not match, so a tag that moves later changes nothing. Until you set it, both jobs fail and say so. The file's `actions/checkout` is pinned by commit id as well; Dependabot's `github-actions` updates keep such pins current.
3. Add a repository secret named `ANTHROPIC_API_KEY` (Settings, Secrets and variables, Actions). Only the review job reads it, and only in the step that starts Claude Code. GitHub gives a pull request Dependabot opens its Dependabot secrets only, never the repository's Actions secrets, so the review job skips those pull requests (the `dependabot[bot]` condition in its `if:`); they get the tools job, whose dependency audits are the check that matters for a version bump. To review them too, add the key as a Dependabot secret (Settings, Secrets and variables, Dependabot) and drop that condition.
4. Make the tools job, `auditor tools (no secrets)`, a required check in your branch protection. A job its `if:` skips reports Success and does not block a merge, even as a required check. So you may require the review job, `auditor review (same-repository pull requests)`, as well, but it passes with no review on a fork's pull request, on Dependabot's, and after the tools job fails (which blocks the merge itself). Before you merge a fork's or Dependabot's pull request, review it yourself ([Reading the details](#reading-the-details)).
5. Protect the workflow itself. On `pull_request`, GitHub runs the workflow file as the pull request's merge commit has it, so a pull request that edits `.github/workflows/auditor-pr.yml` runs its own copy, and that copy can pass whatever it likes. List `.github/` in a `CODEOWNERS` file and turn on "Require review from Code Owners", so no such change merges without a maintainer reading it, and read the workflow's diff before you trust a green check on a pull request that changes it.
6. Add no `paths:` or `paths-ignore:` filter to the workflow. GitHub leaves a workflow its path filters skip as Pending, which blocks a pull request that requires one of its checks.

The settings you may change are in the file's top-level `env:` block:

| Variable | Default | What it sets |
|---|---|---|
| `AUDITOR_FAIL_ON` | `7` | the review fails on a finding of this severity or more, from 1 to 10 (`OUTPUT-RULES.md` Rule 1: 7 and 8 are HIGH, 9 and 10 CRITICAL) |
| `AUDITOR_MAX_BUDGET_USD` | `5` | the most one review may spend, in US dollars |
| `SEMGREP_RULESETS` | `p/rust p/trailofbits` | the semgrep rulesets the tools job runs, any of `p/rust`, `p/trailofbits`, `p/typescript`, `p/javascript`, `p/python`, `p/golang`, `p/solidity`, `p/github-actions` and `p/secrets` |
| `SEMGREP_VERSION`, `CARGO_AUDIT_VERSION` | `1.182.1`, `0.22.2` | the releases of semgrep and cargo-audit the tools job installs. Move them to releases at least two weeks old, so a broken one has had time to be pulled. |

Leave `AUDITOR_STRICT` and `AUDITOR_EXEC_MODE` as they are ([below](#strict-mode-and-nothing-built)).

The tools job fails on any semgrep result, and on any vulnerability that cargo audit or npm audit reports, in the whole checkout, not only in what a pull request changes. It goes by their own exit status, so a warning such as an unmaintained or yanked crate does not fail it. If your default branch already has results, every pull request fails until they are fixed, or marked with a `nosemgrep` comment that says why; choose `SEMGREP_RULESETS` with that in mind.

**Cost.** The tools job uses no model, so it costs runner minutes only. A review costs what a Quick review of that change costs, up to `AUDITOR_MAX_BUDGET_USD`; a review that reaches the cap stops and fails, and never passes. A newer push to the same pull request cancels the run still going for it, which stops its spending; a cancelled review still costs what it had spent.

## What each job does

**tools** runs on every pull request, forks included, with no secret and no Claude. On GitHub's merge commit of the pull request it makes a run directory with the bundled `rundir.sh`, then runs:

- semgrep over the checkout, through the bundled `sast.sh`, with `SEMGREP_RULESETS`;
- `cargo audit` on each `Cargo.lock`, through the bundled `deps.sh`;
- `npm audit` on each `package.json` that has an `npm-shrinkwrap.json` or a `package-lock.json` beside it (the shrinkwrap first, as npm reads it), through `deps.sh` too.

It passes only when every analyzer ran and none found anything. An analyzer that could not run is named in the log with its one-line reason, which is about the tool, never about a finding. A lockfile that is a symbolic link is handed on too, and `deps.sh` refuses it, so that audit did not run. The log also names a `Cargo.toml` with no `Cargo.lock`, a `package.json` with no npm lockfile, and semgrep's own notes, such as the `.semgrepignore` files that narrow its scan; none of them names a result.

**review** runs only for pull requests from branches of your repository, other than Dependabot's. It installs Claude Code at the exact version that auditor-skill's own `plugin-validate` workflow pins, from the lockfile there, with each package's integrity checked and no install script run. It builds the bundled Rust tools, removes every `.claude/`, `.mcp.json`, `.claude.json`, `CLAUDE.md` and `CLAUDE.local.md` from its checkout, checks that preflight names strict mode, and then runs:

```bash
# example: the review job's command, with the pull request's base commit and merge commit filled in
claude -p "/auditor:diff-audit <base>..<head> --ci --fail-on 7" \
  --plugin-dir "<auditor-skill root>" --setting-sources "" --strict-mcp-config \
  --max-budget-usd 5 --output-format json --json-schema "<the text of templates/ci/verdict.schema.json>"
```

`<base>` is the commit the pull request merges into and `<head>` GitHub's merge commit, both as full commit ids. Its last step checks what the review returned and exits on it ([What the verdict means](#what-the-verdict-means)).

Every install and build runs from the runner's temp folder, outside the checkout, so no config a pull request ships, such as a `.cargo/config.toml`, applies to them.

## The launch-line flags

- `--plugin-dir "<auditor-skill root>"` loads the plugin from the pinned copy, for this one session. The copy sits in the runner's temp folder: the bundled tools refuse an installation inside the tree they audit.
- `--setting-sources ""` loads no settings file at all. A pull request's `.claude/settings.json` hooks and `env`, its `CLAUDE.md`, rules, skills, commands and agents do not load, and neither do user settings or the plugins enabled there, with their language servers; `--plugin-dir` still loads this one. It is the setting front A's strict launch line uses. Without it, `claude -p` runs a repository's hooks before preflight does anything.
- `--strict-mcp-config`, with no `--mcp-config` beside it, starts no MCP server, so a `.mcp.json` in the pull request starts nothing.
- `--max-budget-usd` caps what the review spends. A review that reaches the cap stops, and the job fails.
- `--output-format json` prints one JSON result, which the job keeps on the runner and never prints.
- `--json-schema` makes Claude Code check the review's reply against `templates/ci/verdict.schema.json` and return it as the result's `structured_output`. Every field there is a fixed word or a number, so the line the job prints from it cannot carry a finding.

Front A's strict launch line for a person at a terminal, `claude --setting-sources "" --strict-mcp-config --plugin-dir "<auditor-skill root>" --settings "<auditor-skill root>/templates/strict-settings.json"`, also passes the installation's strict settings file ([permissions-and-isolation.md](permissions-and-isolation.md#default-and-strict-mode)). The review does not, for three reasons. It builds and runs nothing, so that template's sandbox has nothing to confine. Its sandbox block stops Claude Code wherever Claude Code's sandbox cannot start, for example on a Linux runner without bubblewrap. And its `env` sets `AUDITOR_EXEC_MODE=isolated`, where this job wants `none`. Strict mode comes from the job's own `AUDITOR_STRICT=1`, which no project setting can change, since project settings do not load. A pull request that edits the workflow file itself is another matter ([Setup](#setup), step 5).

## Strict mode, and nothing built

- **`AUDITOR_STRICT=1`.** A pull request's content is an untrusted source, so both jobs run in strict mode (`OUTPUT-RULES.md` Rule 11f). The bundled tools refuse what default mode only notes, such as a link that leads out of the tree, a tracked `audit_*` directory, or a lockfile that names a registry other than crates.io. A refusal fails the job; it never passes it.
- **`AUDITOR_EXEC_MODE=none`.** Nothing from the pull request is built, tested or run: no `build.rs`, proc-macro, test or npm script runs on the runner. The review reads the code and does not execute it.

## What the verdict means

The review job prints one line, for example:

```text
auditor: verdict: pass (threshold 7, analyzers run: audit-scan)
auditor: verdict: fail (threshold 7, analyzers run: audit-scan, lock-delta; not run: deps-artifacts)
```

It is **fail** when any of these holds, and **pass** otherwise:

- **A finding of severity N or more counts**, N being `AUDITOR_FAIL_ON`. A finding counts when it passed the validation gate of `OUTPUT-RULES.md` Rule 5b, when it is `[UNDETERMINED]` (reachable, its full impact not measured), or when its severity is 5 or less, where the gate does not apply. An `[UNCONFIRMED]` or `[PARTIAL]` finding is in the report but does not count.
- **An analyzer the review called for did not run.** These are `audit-scan`, which the job builds; `lock-delta` and `deps-artifacts`, the lockfile delta and the published code of changed dependencies, when the pull request changes a manifest or lockfile; and `web3js-history`, when the review runs it.
- **The review stopped early.** Preflight refused the tree, a call it needs was denied, the range could not be read, a section or vector file its selection lists was left unread (`stopped: corpus-pass`), the change was over the line budget with the owner switch set to fail (`stopped: line-budget`), or it ran out of budget.
- **The review's result and its `findings.json` disagree, or either one does not match its schema.** The last step reads both and works the verdict out again from the findings, so a reply that says pass over a finding that counts fails.
- **The review leaves out an analyzer the change calls for.** The last step works out from the change itself that a changed `.rs` file needs `audit-scan` and a changed `Cargo.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` or `bun.lock` needs `lock-delta`, and fails a result that lists neither as run nor as not run.

When the reason is one of the last three, the line ends with it, in fixed words: for example `; the review ended early (error_max_budget_usd)`.

The tools job's line is simpler: `auditor: tools: pass` when every analyzer ran and found nothing, `fail` otherwise, with the analyzers that ran and those that did not.

What a pass does not tell you:

- It is a Quick review: the changed code and its direct callers and callees, not a whole audit. It reads the checklist sections and known-vector rows that `references/depth-scope.md` selects for the kinds of file the change holds, and at most 5,000 changed lines, riskiest first. PR-REPORT.md counts what that leaves out.
- semgrep honours the repository's own `.semgrepignore` files and `nosemgrep` comments, which a pull request can change. The tools log names each `.semgrepignore` that narrows the scan, and on a pull request from your own branches the review sees such a change in the diff; a fork's pull request gets no review. semgrep's documented defaults also leave out files over 1 MB and, in a repository with no `.semgrepignore`, folders such as `test/`, `tests/`, `vendor/`, `build/` and `dist/`.
- A `yarn.lock`, `pnpm-lock.yaml` or `bun.lock` with no npm lockfile beside it gets no dependency audit in the tools job, and its log says so.
- The review reads the pull request's text, and text written to steer a reviewer can steer it too. The last step catches a reply that contradicts its own findings file, not a review that was talked into missing something.

## Fork pull requests

On `pull_request`, GitHub gives a fork's pull request no secrets, so the review job does not run for it, and it skips Dependabot's the same way ([Setup](#setup), step 3). GitHub shows the job as skipped, and a job its `if:` skips reports Success, so a required review check passes there with no review. Such a pull request gets the tools job only: review it yourself before you merge it ([Reading the details](#reading-the-details)).

Never switch the trigger to `pull_request_target`, or to `workflow_run`, to get the review on forks: both run the fork's changes with your secrets ([github-actions.md](../references/vuln-classes/github-actions.md) §5).

To see what the tools job found, run the same analyzers in your clone, at the pull request's merge commit. `/auditor:quick-scan` in Claude Code runs them and more. Or run the bundled scripts, from the top of your clone:

```bash
# example: what you type; <auditor-skill root> is where auditor-skill is installed
export AUDITOR_STRICT=1
# prints the run directory's name, audit_<n>
"<auditor-skill root>/scripts/rundir.sh" new audit
"<auditor-skill root>/scripts/runner/sast.sh" semgrep --run audit_<n> --path . --ruleset p/rust --ruleset p/trailofbits
"<auditor-skill root>/scripts/runner/deps.sh" cargo-audit --run audit_<n> --manifest Cargo.lock
```

The findings are in `audit_<n>/sast/` and `audit_<n>/deps/`.

## Public repositories

On a public repository anyone signed in to GitHub can read a workflow's logs, its job summaries and its artifacts, and the comments and annotations on a pull request. So the template publishes pass or fail only, as `OUTPUT-RULES.md` Rule 11d asks:

- The log and the summary show the lines above. They name the verdict, the threshold and the analyzers, and nothing a finding says, not even how many there are.
- The review's reply, its report and its findings file stay on the runner, which GitHub discards when the job ends.
- The template uploads nothing: no artifact, no SARIF, no comment.

The job never fails only because you have no private channel for the details. You read them by running the check again yourself.

### Reading the details

The review job's summary names the pull request's two commits. In a clone of your own, check out the pull request's merge commit: `git fetch origin pull/<number>/merge`, then `git checkout --detach FETCH_HEAD`. GitHub makes a new merge commit when the base branch moves, so check that `git rev-parse HEAD` prints the summary's `<head>`; when it does not, the next run reviews the new one, and `HEAD^1..HEAD` is its range. Start Claude Code there with the strict launch line, since the pull request's own `.claude/` config would load otherwise ([permissions-and-isolation.md](permissions-and-isolation.md#default-and-strict-mode)), and run `/auditor:diff-audit <base>..<head>` with the two commits. The report lands in `audit_<n>/PR-REPORT.md`. With the same auditor-skill commit and the same range it reads the same code, though a model's answers can differ from one run to the next.

### Private repositories

The template keeps details out of a private repository's logs too. Anyone who can read the repository can read them, and if it is ever made public, its earlier runs become as readable as its code until they expire. To see details in CI on a private repository, add a step of your own after the verdict step. It can upload `$RUNNER_TEMP/auditor-review/findings.sarif`, the findings as SARIF 2.1.0, to code scanning, with `security-events: write` on that job, or the run directory as an artifact, with an action pinned by commit id either way. Whether GitHub shows a public repository's code scanning results to everyone was not checked for this template, so add no such step there.

## Running `--ci` yourself

`--ci` works outside this workflow too: in another CI system, or at a terminal. `/auditor:diff-audit <base>..<head> --ci` and `/auditor:quick-scan --ci` take `--fail-on <N>`, ask nothing, write `audit_<n>/findings.json` (`templates/ci/findings.schema.json`), keep finding text out of their reply, and end with the closing line above. Without `--ci`, `--fail-on` only sets the threshold of the verdict at the top of the report. For a scheduled scan of your default branch, `/auditor:quick-scan --ci` is the one to run: it scans the whole repository, while diff-audit reads one range.

Give a quick-scan in CI `--max-budget-usd 10`. In measured runs (`claude-opus-5-5`, November 2026) a quick-scan that read every kept vector file cost $2.84 with the 55 of a 12K-line program, and $6.78 with the 98 of a repository holding a 3K-line program and its tooling. The session sees the cap Claude Code gives it: under a $5 cap that repository's scan stopped reading early, with 64 of its 78 kept files unread, to stay under it, and under $10 it read all 98. A run that reaches the cap ends there, and fails.

## The files

| File | What it is |
|---|---|
| `templates/ci/auditor-pr.yml` | the workflow |
| `templates/ci/verdict.schema.json` | the review's result, for `claude -p --json-schema` |
| `templates/ci/findings.schema.json` | `audit_<n>/findings.json`, which `--ci` writes |
| `templates/ci/verdict.jq` | the check the verdict step runs |
| `templates/ci/findings-to-sarif.jq` | `findings.json` as SARIF 2.1.0 |

`scripts/tests/test-ci-template.sh` checks them: both schemas parse, the workflow keeps the shape this page describes, its tools step and its review step do what this page says when run on stubs and a scratch pull request, a sample `findings.json` turns into SARIF 2.1.0, and the verdict step passes only what this page says passes.

## What remains a risk

- The review job holds one secret, the API key, in the step that runs Claude Code. Nothing in that job builds or runs the pull request's code, its bundled tools refuse what strict mode refuses, and Claude Code takes its settings and MCP servers from the runner alone. Use a key made for this job, under a spending limit on your Anthropic account.
- Only people who can push a branch to your repository start a review, and they could change the workflow itself anyway.
- Any pull request, a fork's included, runs its own copy of this workflow, so a green check means something only while `.github/` changes get a maintainer's review ([Setup](#setup), step 5).
- A pull request can still try to steer the review with the text it adds ([What the verdict means](#what-the-verdict-means)).
