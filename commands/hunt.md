---
name: auditor:hunt
description: Post-incident threat hunt over Solana transaction history and program logs with NO alert in hand — profile the corpus, run a written hypothesis ledger, confirm suspects in the deployed source, reproduce locally on the real program bytes, and emit incident_<n>/INCIDENTS.json + INCIDENT_REPORT.md. Proposes; never signs, sends, or acts on-chain.
argument-hint: "[<address> ...] [--logs <dir>] [--repo <path>] [--window <fromUnix>..<toUnix>] [--collect] [--fresh]"
allowed-tools: Read, Grep, Glob, Task, Edit(incident_*/**), Bash(jq *), Bash(bash scripts/dnr/profile.sh *), Bash(python3 scripts/dnr/frames.py *), Bash(python3 scripts/dnr/deltas.py *), Bash(bash scripts/dnr/redact.sh *)
---

# auditor-skill — Threat Hunt (no alert in hand)

*Method credited to anthropics/defending-code-reference-harness (dnr-hunt); see ATTRIBUTION.md.*

**Arguments:** $ARGUMENTS

Sweep a Solana program's recent history for signs it was attacked. Read
`references/detection-response/README.md` first — the seven hard rules, the verdict
ladder and the `incident_<n>/` layout live there and are not restated here. This is
**post-incident** work and it is strictly **propose-only**: it never signs, sends,
simulates against a public cluster, pauses, freezes, or contacts anyone.

> The `allowed-tools` above pre-approve only read-only, text-only work; they are
> **not a sandbox** (README § "allowed-tools is not a sandbox"). `solana`, `curl`,
> `cargo`, `surfpool` and a bare `python3` still prompt. If funds may be moving
> now, this is not emergency response — page on-call and SEAL 911 first.

## Steps

1. **Open the run directory.** `incident_<n>/` where `<n>` = existing `incident_*/`
   + 1 (`--fresh` forces a new one). The **first** write is `incident_<n>/.gitignore`
   containing a single `*` (Rule 11d): raw corpora and off-chain logs carry PII and
   are never committed. Start `LEDGER.md` from `templates/hunt-ledger.md`.

2. **Get the corpus.** The user's own corpus comes first: `--logs <dir>` (a
   `transactions.jsonl`, Geyser/indexer export, or service logs). Otherwise collect
   it — **gated** (README rule 3):
   - Resolve seed addresses: the arguments, else `declare_id!` / `Anchor.toml`, plus
     vault / authority / mint / treasury from `audit_<n>/threat-model.md` or
     `intake.md` §6 if an audit preceded this.
   - Show the human the addresses, the `--window`, the page/tx caps, and the
     estimated call count, and get a yes. In a non-interactive run, collection
     happens only if `--collect` was passed.
   - Then run `scripts/dnr/collect.sh --out incident_<n>/corpus --confirmed …`
     (`$RPC_URL` from the environment, never on the command line; it finalizes and
     passes `maxSupportedTransactionVersion: 1`). This step touches the network, so
     it prompts — approve it once. Disclose the provider **host** (the service
     that received the queried addresses) and the literal `$RPC_URL` in the ledger
     and report (Rule 11b), never a URL with a key.

3. **Baseline (Phase 1).** `scripts/dnr/profile.sh incident_<n>/corpus/transactions.jsonl`
   for outcome/version histograms, window, and signer/program inventories; write
   each number into the ledger. Do not read the corpus into context (README rule 2).

4. **Hunt loop (Phase 2).** Run the seed sweeps in `log-sources.md`, one ledger row
   per query (`deltas.py`, `frames.py`, `jq`). Pivot from every hit along the
   campaign chain. Stop after two rounds with no new entity. A program-log line is a
   hint, never proof (rule 1).

5. **Source confirmation (Phase 3).** For each suspect, spawn `context-builder` on
   the implicated handler in the source **deployed at the incident slot** (`--repo`;
   check the deploy slot per `containment-playbook.md`). Name the flaw or the
   defense at `file:function`. A confirmed defense makes the suspect
   `attempted_not_vulnerable`, written down with its `file:function`.

6. **Reproduce (Phase 4).** For a source-confirmed flaw, spawn `poc-engineer` in
   **incident mode**: reproduce on the program's **real bytes** (dumped ELF or a
   hash-matched build), in an in-process SVM or a local surfnet, signing only with
   harness keys. This is Leg 3. If it can't run on real bytes, the ceiling is
   `suspected` — stated, not hidden.

7. **Emit.** Write `incident_<n>/INCIDENTS.json` (`incidents-schema.md`) and
   `INCIDENT_REPORT.md` (`templates/incident-report.md`): executive summary,
   `(slot, transactionIndex)` timeline, per-incident evidence / source / PoC /
   blast radius, a Ruled-out section, collection gaps, and the ledger as the
   appendix. Then point the user on: `/auditor:respond INC-<n>.<k>`,
   `/auditor:poc INC-<n>.<k>`, `/auditor:patch INC-<n>.<k>`.

## Verdicts

`confirmed_exploited` (all three legs) · `suspected` (short of that) ·
`attempted_not_vulnerable` / `benign` (→ `ruled_out`). Definitions, the three legs,
`outcome` / `root_cause_class`, and the `key_compromise` cap: README.
