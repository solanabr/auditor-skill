# Detection & Response

*Method credited to anthropics/defending-code-reference-harness (dnr-hunt, dnr-respond); see docs/attribution.md.*

Everything else in auditor-skill is pre-deployment — find the flaw before an
attacker does. This track is for the morning after, for a team that suspects an
attack or holds an alert: a protocol may already have been attacked, and the
evidence is in the chain's transaction history. It ships
two commands, `/auditor:hunt` and `/auditor:respond`, one agent,
`incident-responder`, and one skill, `auditor:dnr-analyze`: the commands keep you in
the loop (arguments, approvals, the collector, results), and the agent does all
reading and analysis of the corpus, one phase at a time, as the skill's fork.
Back to the [docs index](README.md).

The normative contract — the hard rules, the verdict ladder, the `incident_<n>/`
layout — is [`references/detection-response/README.md`](../references/detection-response/README.md).
This page shows how to use the track; where the two differ, the contract holds.

Contents: [Not emergency response](#not-emergency-response) · [Which command](#which-command) ·
[Inputs](#inputs) · [Outputs](#outputs) · [What "confirmed" means](#what-confirmed-means) ·
[Telemetry](#the-method-is-only-as-good-as-your-telemetry) · [Safety and limits](#safety-and-limits) ·
[Prompts and pre-approvals](#prompts-and-pre-approvals) · [The analysis recipes](#the-analysis-recipes)

## Not emergency response

If funds are moving **right now**, don't start a write-up. Page your on-call,
trigger the pause/freeze runbook, and open a SEAL 911 ticket through its official
Telegram bot (`@seal_911_bot`). These commands are the after-the-fact workup.

## Which command

| You have | Use |
|----------|-----|
| No alert, just a program you want to check | [`/auditor:hunt [address…]`](commands.md#auditorhunt) |
| A signature, an address, an alert line, or an IOC | [`/auditor:respond <lead>`](commands.md#auditorrespond) |
| A hunt finding to work into a plan | `/auditor:respond INC-<n>.<k>` |

```
/auditor:hunt   →  /auditor:respond  →  /auditor:patch   →  (human runs the plan)
(find it)          (scope + plan)       (fix, verified)
```

## Inputs

- **Your own corpus** (preferred): point `--logs` at a directory of
  `getTransaction` JSONL, a Geyser/indexer export, or service logs. The command
  copies it into `incident_<n>/logs/` first, since the analysis tools read only
  files inside the run directory. The copy is the only step of getting your
  corpus that asks: Claude Code asks about a `cp` with flags from outside the
  working directory whatever the rules say, so an interactive run prompts you
  once for it, and a `claude -p` run is refused it. The copy is then checked for
  symbolic links, and `preflight.sh` runs again on it: in default mode what they
  find is a note in the report, and in strict mode a copy that is or holds a
  link, or that brings Claude Code project config in, stops the run
  ([Rule 11f](../OUTPUT-RULES.md#11f--default-and-strict-mode)). A line the
  recipes cannot read is skipped and counted as a collection gap, never guessed
  at: a non-integer amount, for example, is never rounded.
- **Collected from RPC** (gated): with no `--logs`, the command shows you the
  addresses, window, caps and estimated call count and asks before the one shipped
  collector runs. `--window <fromUnix>..<toUnix>` sets the window, on block
  time. Set `RPC_URL` in the environment (never on the command line);
  the collector finalizes and passes `maxSupportedTransactionVersion: 1`, which is
  mandatory now that v1 transactions are live on mainnet. Non-interactive runs
  collect only with `--collect`, which stands in for your yes to the addresses,
  window and caps. The commands pre-approve the snapshot and the collector, so in
  `claude -p` they run too, within the caps your environment sets; the `--logs`
  copy is refused there (above). Those caps are `AUDITOR_RPC_MAX_PAGES` (pages
  of up to 1,000 signatures per address, default 100), `AUDITOR_RPC_MAX_TX`
  (`getTransaction` calls in all, default 10,000) and `AUDITOR_RPC_MAX_ADDRESSES`
  (default 25). No command line can raise them: a request over one is refused,
  naming the variable to raise, and a run's own defaults are 20 pages per
  address and 2,000 transactions
  ([`collect.sh`](scripts-incident.md#collectsh)). The collection runs in the foreground, with a
  timeout sized from its call count; one that outlasts it moves to the background,
  and the turn its completion starts has none of the command's pre-approvals, so
  the command first invokes itself again, which asks unless your settings allow it
  ([Long steps](permissions-and-isolation.md#long-steps)). One stopped by INT,
  TERM or HUP, or by a failed write, records what it had not fetched as collection
  gaps; for one killed outright, the agent records them from its files.
- **Source** (`--repo`): needed to confirm a flaw and to reach
  `confirmed_exploited`; without it, findings cap at `suspected`.

## Outputs

Everything lands in a per-run `incident_<n>/` directory whose first file is a
`.gitignore` of `*` — raw corpora and off-chain logs carry PII and are never
committed. Each run makes a new one; an existing one is reused only when git does
not track it, it holds no symbolic links, and you confirm it. `--fresh`, and a
run with no one to confirm, always make a new one, and `/auditor:respond` on an
`INC-<n>.<k>` lead works in that incident's own directory:

- `bin/` — the step-1 snapshot of each implicated program (`<id>.so` plus its
  `solana program show` output), taken before anything else so a mid-investigation
  hotfix can't erase the incident binary. A snapshot is never overwritten: a later
  one of a redeployed program is `<id>@<slot>.so`.
- `INCIDENTS.json` — the structured result ([schema](../references/detection-response/incidents-schema.md)).
- `INCIDENT_REPORT.md` — executive summary, timeline, per-incident evidence, and
  the full ledger so a reviewer can retrace every step.
- `RESPONSE-INC-<n>.<k>.md` — the proposed containment / remediation / recovery
  plan. Every action in it is a proposal awaiting a person.

## What "confirmed" means

`confirmed_exploited` requires three independent legs — an on-chain effect, the
flaw in the deployed source, and a local PoC on the real program bytes — and
anything short of all three is `suspected`. The ladder, the exact leg definitions
and the stolen-key cap are kept in one place only:
[the verdict ladder](../references/detection-response/README.md#the-verdict-ladder-the-one-normative-copy).

## The method is only as good as your telemetry

Hunting through raw history with no alert to start from is hard, and a quiet run
does not prove nothing happened. Before trusting it on an unknown, test it on a
known: in a throwaway environment, deploy a deliberately flawed program, attack it
with a script, record the resulting history, and check that `/auditor:hunt`
reconstructs the attack from that history alone. auditor-skill ships no packaged
Solana exercise for this: run the same check on incidents you have already
captured.

## Safety and limits

- **Plans only, no actions.** No signing, sending, pausing, freezing, rotating, or
  contacting anyone — the plan is for a human to run
  ([containment playbook](../references/detection-response/containment-playbook.md)).
- **Local reproduction only.** PoCs run against `127.0.0.1`; the track never sends
  to or simulates against a public cluster.
- **MCP servers stay callable in your session.** `/auditor:hunt` and
  `/auditor:respond` hand all reading and analysis of the incident corpus to the
  `incident-responder` agent, as the fork of the `auditor:dnr-analyze` skill; its
  tool list has no MCP tools, so it cannot call a signing or transfer tool. The
  commands themselves run in your session, where
  every connected MCP server stays callable. They call no MCP tool. Before a live
  incident, disconnect or deny write-capable MCP servers (for example, tools that
  transfer or stake).
- **A clean working directory.** Both commands start with
  `"<auditor-skill root>/scripts/preflight.sh"`, which looks for Claude Code
  project config anywhere in the working tree or in a parent up to the
  repository root:
  - a `.claude` link, a `.claude/` with skills, commands, agents, hooks, output
    styles or workflows in it, or a `scheduled_tasks.json`;
  - a `.claude/settings.json` (or a tracked `settings.local.json`) with any key
    beyond `$schema`, `model`, `cleanupPeriodDays` and `includeCoAuthoredBy`;
  - a `.mcp.json`;
  - a linked git worktree, whose main checkout's `.claude/settings.local.json`
    Claude Code loads too, and that checkout's project skills when the worktree
    has none.

  Claude Code loads the config in the working directory and its parents beside
  the plugin's, and a `.claude/skills` below it, in a folder git does not
  ignore, once the session reads a file there, so a repository's own skill or
  agent could take the place of one of ours, or its config could carry hooks and
  MCP servers. In default mode each one is a note, which the report lists; in
  strict mode it is a refusal
  ([Rule 11f](../OUTPUT-RULES.md#11f--default-and-strict-mode)). `CLAUDE.md` and
  `AGENTS.md` files are listed, not refused; their text is the repository's,
  never instructions.

  The commands need no repository, so an incident workspace of their own is the
  cleanest place to run them. For a repository you do not trust, start Claude
  Code with the strict launch line, under which the repository's own config does
  not load, and run in a clean copy of a repository that ships such config:
  strict mode still refuses it
  ([Default and strict mode](permissions-and-isolation.md#default-and-strict-mode)
  says why, and how to make the copy).

## Prompts and pre-approvals

**What runs without asking.** The commands pre-approve:

- reading, `Task`, edits under `incident_*/`, invoking themselves again and the
  `auditor:dnr-analyze` skill;
- these bundled tools by their paths: the checks `preflight.sh` and
  `rundir.sh`, the program snapshot and the collector (your `RPC_URL` only,
  within the caps your environment sets, after your yes), `rpc-read.sh`,
  `git-ro.sh`, and the runners `probe.sh`, `target.sh` and `run.sh` (in the
  recorded execution mode).

Inside the skill's fork, the offline analysis tools run without a prompt:
`profile.sh`, `frames.py`, `deltas.py`, `jq-ro.sh` (jq over run-directory files,
with an empty environment) and `audit-logs`, each run directly by its path in the
installation and reading only files inside a run directory. `jq` itself, a line
through `redact.sh`, the `--logs` copy, the `solana` CLI and anything else that
executes code still ask.

Pre-approval is not a sandbox: real confinement is an isolated run mode
([`OUTPUT-RULES.md` Rule 11](../OUTPUT-RULES.md#rule-11-operating-safety)); the
RPC provider that received your addresses is disclosed under Rule 11b, from the
rows the snapshot and the collector add to `incident_<n>/disclosures.tsv`.
[permissions-and-isolation.md](permissions-and-isolation.md) has the whole
picture.

**Approving the skill.** A command's pre-approvals last for the turn that
started it. When the command goes on after one of your replies (a yes to a
collection, say), it first invokes itself again through the Skill tool
(`auditor:hunt --resume <step> incident_<n>`, or `auditor:respond …`), which
gives the new turn the command's pre-approvals again, `auditor:dnr-analyze`
among them; Manual mode asks about that resume call. To skip that, add
`"Skill(auditor:hunt *)"`, `"Skill(auditor:respond *)"` and
`"Skill(auditor:dnr-analyze *)"` to `permissions.allow` in your user settings
(`~/.claude/settings.json`), or the whole list in
[Turns and resuming](permissions-and-isolation.md#turns-and-resuming).
Answering "don't ask again" at the prompt can save the rule in a
`.claude/settings.local.json` instead: at the root of the git repository that
holds the working directory (the main checkout's root, for a worktree), or in the
working directory itself outside a repository. `preflight.sh` does not refuse
that file while git does not track it; outside a repository strict mode counts
it as the repository's, so keep such rules in your user settings there. The
fork keeps its own pre-approvals while it runs, after your messages too.

## The analysis recipes

[`scripts/dnr/`](../scripts/dnr/) — profiling, log-frame attribution,
and exact balance deltas, each checked against adversarial fixtures by
`scripts/tests/test-dnr.sh`. They share one input contract: a line they cannot
read is counted, never echoed, and they read only regular files with one name in
`incident_<n>/`, by paths relative to the working directory with no symbolic
link on the way, refusing any other before they read anything. When
[`audit-logs`](power-tools.md#audit-logs) is built in the installation, the
fork runs it first: the same figures from one offline binary, checked against
the scripts by `scripts/tests/test-audit-logs.sh`. Build it again after every
update. Without it, or when it reports a stale build, the fork runs the
scripts. Each script's arguments, exit codes and outputs:
[scripts-incident.md](scripts-incident.md).

**Scripts run from the installation, never from the audited repo.** The fork
runs them by absolute path, `"<auditor-skill root>/scripts/dnr/…"`, with nothing
in front, and the python ones open with a bash front end that runs them as
`python3 -I`, with a `python3` found from `/` on a `PATH` without
working-directory entries, so a same-named script, a `python3`, or a `json.py`
the repo ships in the working directory or on `PYTHONPATH`, never runs in their
place.
