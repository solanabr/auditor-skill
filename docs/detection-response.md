# Detection & Response

*Method credited to anthropics/defending-code-reference-harness (dnr-hunt, dnr-respond); see ATTRIBUTION.md.*

Everything else in auditor-skill is pre-deployment — find the flaw before an
attacker does. This track is for the morning after: a protocol may already have
been attacked, and the evidence is in the chain's transaction history. It ships
two commands, `/auditor:hunt` and `/auditor:respond`, and one agent,
`incident-responder`. Back to the [docs index](README.md).

The normative contract — the hard rules, the verdict ladder, the `incident_<n>/`
layout — is [`references/detection-response/README.md`](../references/detection-response/README.md).
This page is the orientation.

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
  `getTransaction` JSONL, a Geyser/indexer export, or service logs.
- **Collected from RPC** (gated): with no `--logs`, the command shows you the
  addresses, window, caps and estimated call count and asks before the one shipped
  collector runs. Set `RPC_URL` in the environment (never on the command line);
  the collector finalizes and passes `maxSupportedTransactionVersion: 1`, which is
  mandatory now that v1 transactions are live on mainnet. Non-interactive runs
  collect only with `--collect`.
- **Source** (`--repo`): needed to confirm a flaw and to reach
  `confirmed_exploited`; without it, findings cap at `suspected`.

## Outputs

Everything lands in a per-run `incident_<n>/` directory whose first file is a
`.gitignore` of `*` — raw corpora and off-chain logs carry PII and are never
committed:

- `INCIDENTS.json` — the structured result ([schema](../references/detection-response/incidents-schema.md)).
- `INCIDENT_REPORT.md` — executive summary, timeline, per-incident evidence, and
  the hypothesis ledger as the audit trail.
- `RESPONSE-INC-<n>.<k>.md` — the proposed containment / remediation / recovery
  plan. **Nothing in it has been executed.**

## What "confirmed" means

A finding is `confirmed_exploited` only with all three of:

1. **on-chain effect** — a finalized, successful transaction whose runtime-recorded
   balance or account-state change shows the effect (a program-log line never
   counts on its own — it is something a program *said*, KV-122);
2. **the flaw in source** — at `file:function`, in the code deployed at the incident
   slot;
3. **a local PoC on the real bytes** — fired this session against the dumped on-chain
   program or a hash-matched build, in an in-process SVM or a local surfnet.

Short of that it is `suspected`. A stolen-key incident caps at `suspected`, because
chain data cannot tell theft from authorized use. Everything explained away is
`ruled_out`, with the evidence — triaging the noise is half the job.

## The method is only as good as your telemetry

Open-ended log hunting is genuinely hard, and a clean run is not proof of safety.
Calibrate before you trust it on an unknown: stand up a disposable copy of a
service, plant a known weakness, run a scripted exploit against it, capture the
transaction history, and confirm `/auditor:hunt` finds the chain from the telemetry
alone. A seeded Solana exercise that packages this is a planned follow-up; until
then, the loop is the same on your own captured incidents.

## Safety and limits

- **Propose, never execute.** No signing, sending, pausing, freezing, rotating, or
  contacting anyone — the plan is for a human to run
  ([containment playbook](../references/detection-response/containment-playbook.md)).
- **Local reproduction only.** PoCs run against `127.0.0.1`; the track never sends
  to or simulates against a public cluster.
- **Not a sandbox.** The commands' `allowed-tools` pre-approve read-only, text-only
  work; they are intent, not confinement. Real confinement is an isolated run mode
  ([`OUTPUT-RULES.md` Rule 11](../OUTPUT-RULES.md#rule-11-operating-safety)); the
  RPC provider that received your addresses is disclosed under Rule 11b.
- **Recipes:** [`scripts/dnr/`](../scripts/dnr/) — profiling, log-frame attribution,
  and exact balance deltas, each checked against adversarial fixtures by
  `scripts/tests/test-dnr.sh`.
