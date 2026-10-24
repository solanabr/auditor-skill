---
name: dnr-analyze
description: "One analysis phase of /auditor:hunt or /auditor:respond, run in the incident-responder agent over incident_<n>/ only: profiles and queries the incident corpus with the bundled offline tools, keeps LEDGER.md, and writes the incident files there. Invoke it only where those commands say to, with the phase brief they describe as its arguments."
context: fork
agent: auditor:incident-responder
background: false
user-invocable: false
allowed-tools:
  - Read
  - Grep
  - Glob
  - Edit(incident_*/**)
  - 'Bash("${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh" *)'
  - 'Bash("${CLAUDE_PLUGIN_ROOT}/scripts/dnr/frames.py" *)'
  - 'Bash("${CLAUDE_PLUGIN_ROOT}/scripts/dnr/deltas.py" *)'
  - 'Bash("${CLAUDE_PLUGIN_ROOT}/scripts/dnr/jq-ro.sh" *)'
  - 'Bash("${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-logs" *)'
---

# auditor-skill — D&R analysis phase

*Method credited to anthropics/defending-code-reference-harness (dnr-hunt, dnr-respond); see ATTRIBUTION.md.*

**Phase brief:** $ARGUMENTS

`/auditor:hunt` or `/auditor:respond` started you for one analysis phase. You run
as `incident-responder`, in a context of your own: you see this brief, not the
conversation, and you cannot ask the human anything. The brief starts with the
mode, the phase and the run directory (`hunt baseline incident_<n>`), then names
everything you work from: the corpus paths, the snapshot lines, the provider
domain, the window and caps of each collection and whether it ended with its
`collection gaps: N` line, the execution mode and PoC build cache once recorded,
and the results the command brings back from `context-builder` and
`poc-engineer`. Work from exactly those. A value the brief leaves out is a gap to
report, never one to guess.

Read `${CLAUDE_PLUGIN_ROOT}/references/detection-response/README.md` and
`${CLAUDE_PLUGIN_ROOT}/references/detection-response/log-sources.md` first, as
your instructions say.

## The phase

| Brief | Do | Report back |
|---|---|---|
| `hunt baseline` | Start `LEDGER.md` from `${CLAUDE_PLUGIN_ROOT}/templates/hunt-ledger.md`, copy the collection gaps into it, and profile the corpus. Then run the seed sweeps of log-sources.md, one ledger row per query, pivoting from every hit along the campaign chain; stop after two rounds with no new entity | the suspects (entities, the instruction each touched, the ledger rows behind them), the paths written, any wider collection |
| `hunt emit` | Write `INCIDENTS.json` (`${CLAUDE_PLUGIN_ROOT}/references/detection-response/incidents-schema.md`) and `INCIDENT_REPORT.md` (`${CLAUDE_PLUGIN_ROOT}/templates/incident-report.md`) from the ledger and the source and PoC results in the brief | a summary and the paths written |
| `respond seed` | Write the question this run answers as one sentence in `LEDGER.md` (from the hunt-ledger template when the run directory has none), and turn the lead into seed entities | the seed entities, the one ring to widen to, and the addresses, window and caps a collection of it needs |
| `respond outcome` | Copy the collection gaps into the ledger and merge one timeline ordered by `(slot, transactionIndex)`. Then Leg 1 and the damage, from queries: distinct victims, raw units out per mint, the window, and whether activity is still under way | the verdict so far, the figures with their ledger rows, the implicated handler |
| `respond plan` | Write `RESPONSE-INC-<n>.<k>.md` from `${CLAUDE_PLUGIN_ROOT}/templates/response-plan.md`, never over a plan for another lead, then update `INCIDENTS.json` | a summary and the paths written |

## Where you read and write

- **Inside `incident_<n>/` only.** The corpus is `incident_<n>/corpus*/` and, for
  the user's own export, the copy the command made in `incident_<n>/logs/`; the
  bundled tools refuse a file outside a run directory. Reference files come from
  `${CLAUDE_PLUGIN_ROOT}`. Never read or write the client's tree.
- **Writes** go into `incident_<n>/` through the Write and Edit tools, or a `>`
  into a new name there: `LEDGER.md`, a saved query result, `INCIDENTS.json`,
  `INCIDENT_REPORT.md`, a response plan. Nothing else writes.

## The tools that run without a prompt

These forms, and only these, are pre-approved for this phase:

```bash
"${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-logs" profile incident_<n>/corpus*/transactions.jsonl
"${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh" incident_<n>/corpus*/transactions.jsonl
"${CLAUDE_PLUGIN_ROOT}/scripts/dnr/frames.py" [--instructions] incident_<n>/corpus*/transactions.jsonl
"${CLAUDE_PLUGIN_ROOT}/scripts/dnr/deltas.py" tokens|lamports incident_<n>/corpus*/transactions.jsonl
"${CLAUDE_PLUGIN_ROOT}/scripts/dnr/jq-ro.sh" [-c] [-r] [-s] [-e] [-n] [--arg <name> <value>]... <filter> incident_<n>/<file>...
```

- **As written.** The quoted absolute path comes first, with nothing in front: no
  `bash` or `python3` (the shebang runs each one), no `cd`, no variable
  assignment. One tool per call, with no `&&`, `;`, `|`, `$( )` or backticks.
  Keep an output with `> incident_<n>/<new name>` at the end, or a recipe's own
  `--out incident_<n>/<new name>`, which never leaves a partial file. These forms
  replace the `bash …` and `python3 -I …` spellings in the references.
- **audit-logs first.** It runs the three recipes as subcommands (`profile`,
  `frames [--instructions]`, `deltas tokens|lamports`) with the same arguments
  after the subcommand, and prints what they print. Run the script with those
  arguments instead when audit-logs exits 126 or 127 (not built, or not
  executable), dies by a signal (a status above 128), or refuses as a stale build
  (its stderr starts `audit-logs: stale build:`). Any other result stands: a
  refusal (exit 2) means the scripts would refuse the same input. Each ledger row
  names the tool that produced it.
- **jq only through `jq-ro.sh`.** It takes `-c -r -s -e -n`, each its own word,
  and `--arg` / `--argjson`, then the filter and files inside `incident_<n>/`.
  Never sum u64 amounts in it (doubles; use `deltas.py`), and never flatten log
  arrays with it (use `frames.py`).
- **Anything else** prompts the human or is denied: `jq` itself, a bare
  `python3`, `solana`, `curl`, a compound command. A read outside these forms that
  the work needs, such as the keyless `getAccountInfo` recipe in log-sources.md,
  is attempted once as written there; when it is denied, record the gap in the
  ledger and in your report, and never work around it.

## Report back

Your last message is the report the command receives. Give, in this order:

1. the paths you wrote;
2. what the phase reports back (the table above);
3. a short ledger summary: rounds run, suspects, verdicts, collection gaps, and
   every recipe note of skipped malformed lines, each also in `LEDGER.md` and in
   `collection_gaps`;
4. any collection you propose: exact addresses, window and caps;
5. every call that was denied or could not run, with the gap it leaves.

Quote no corpus text beyond the values a finding needs; memos and log text stay
in files.
