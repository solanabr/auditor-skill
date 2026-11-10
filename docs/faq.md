# FAQ

Questions people ask about auditor-skill. Back to the [docs index](README.md) or the [README](../README.md).

## Does this replace a professional audit?

It checks 1,465 items and 141 known vectors, but an AI auditor cannot do everything a human can (social engineering assessment, business logic review requiring domain expertise, legal compliance opinions). Use it as a first pass, and before a mainnet launch pair it with a human audit of the business logic, the economic model and legal compliance ([SKILL.md](../SKILL.md#when-not-to-use), When NOT to Use).

## Which AI model should I use?

In Claude Code each agent names its own model tier: seven run on Opus, and context-builder and audit-reporter on Sonnet ([docs/agents.md](agents.md)). `/auditor:quick-scan` and `/auditor:diff-audit` start no agent, so your session's model runs them (`/model`, or `claude --model`); an agent that `/auditor:deep-review` starts runs on the tier its definition names. [COSTS.md](../COSTS.md)'s figures were measured with `claude-opus-5-5` as the session model; Sonnet as the session model is not measured yet.

## How long does an audit take?

It depends on the depth, the repository's size and the model. Quick scales with the change, Standard with the module, and Full takes longest: six agents carry it from context reconstruction through a threat model and peer review to the report, and `--with-poc` adds two more. Measured: Quick 4 to 23 minutes, the longest a quick-scan of a whole 3K-line repository; Standard 36 minutes on 3K- and 7K-line programs and 56 on a 12K-line one; Full 61 minutes on the 3K-line one. Nothing at 50K lines was measured ([COSTS.md](../COSTS.md)).

## Can I use this in CI/CD?

Yes. CI runs Quick on pull requests from your own branches, and the bundled analyzers on all of them: copy `templates/ci/auditor-pr.yml` into `.github/workflows/` and follow [docs/ci.md](ci.md#setup).

- **The tools job** runs the bundled analyzers with no model and no secrets, for fork pull requests too.
- **The review job** runs `/auditor:diff-audit --ci` on pull requests from your own branches, other than Dependabot's, in strict mode with nothing built. It fails when a counted finding reaches `AUDITOR_FAIL_ON` (7 by default), when an analyzer did not run, or when the review stopped early ([what the verdict means](ci.md#what-the-verdict-means)).
- **Cost.** A diff-audit cost $1.68 to $8.10 in measured runs, and $8.10 on the shipped text for a 7,830-line range. The review job on the shipped text is not measured yet, and the template caps it at $15.
- **Public repositories.** The job posts pass/fail only — no finding text or counts: logs, job summaries and uploaded artifacts are readable by any signed-in GitHub user. So the details stay on the runner, you read them by running the same command in a clone of your own, and the job never fails only because no private channel exists (OUTPUT-RULES Rule 11d).
- **A scheduled scan** of the default branch: run `/auditor:quick-scan --ci`, with a `--max-budget-usd` of $15. A cap close to a full pass's cost makes the session stop reading early ([COSTS.md](../COSTS.md#cost-and-time-by-depth)).

For a job of your own, such as a Full run on a release branch:

- A CI job is a `claude -p` run, and it denies every call that would ask. Quick builds nothing; a Full run builds the project natively unless the job sets `AUDITOR_EXEC_MODE` or `AUDITOR_STRICT=1` (see [docs/permissions-and-isolation.md](permissions-and-isolation.md#non-interactive-runs-claude--p)).
- A pull request can carry `.claude/settings.json` hooks and a `.mcp.json` that `claude -p` runs when it starts, so run pull-request jobs, those from forks above all, in strict mode. Export `AUDITOR_STRICT=1` in the job's environment, and start Claude Code with the strict launch line's flags, `--setting-sources "" --strict-mcp-config --plugin-dir "<auditor-skill root>" --settings "<auditor-skill root>/templates/strict-settings.json"`; a job that builds nothing, like the template's review job, leaves `--settings` out ([docs/ci.md](ci.md#the-launch-line-flags)).
- Check that preflight's first line says `mode: strict`, since `claude -p` skips a settings file or entry it cannot use without a word (`claude doctor` lists what it dropped).
- Under the launch line the pull request's `.claude/` config does not load, but strict mode still refuses a tree that ships it, so such a job audits a copy without it ([permissions-and-isolation.md](permissions-and-isolation.md#default-and-strict-mode)).

## Can I use this for non-Solana projects?

Yes. Checklists 01-07 are Solana-specific. Of the others, 08-10 cover TypeScript and web code, 14 Python, 15 Go, Java, Ruby, PHP and any other language, 19 AI agents and 20 off-chain Rust, and 11-13 and 16-18 apply to any repository ([SKILL.md](../SKILL.md#porting-to-another-repository), Porting to Another Repository).
