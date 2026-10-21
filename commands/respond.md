---
name: auditor:respond
description: Work one incident lead — a signature, an address, an alert line, an IOC, or a /auditor:hunt INC id — across Solana transaction history: scope it, verdict whether it succeeded, quantify blast radius, confirm root cause in the deployed source with a local PoC, and write a proposed (never executed) containment / remediation / recovery plan. Never signs, sends, or acts on-chain.
argument-hint: "<INC-n.k | signature | address | 'alert json' | 'free text'> [--logs <dir>] [--repo <path>] [--collect] [--fresh]"
allowed-tools: Read, Grep, Glob, Task, Edit(incident_*/**), Bash(jq *), Bash(bash scripts/dnr/profile.sh *), Bash(python3 scripts/dnr/frames.py *), Bash(python3 scripts/dnr/deltas.py *), Bash(bash scripts/dnr/redact.sh *)
---

# auditor-skill — Incident Response (lead in hand)

*Method credited to anthropics/defending-code-reference-harness (dnr-respond); see ATTRIBUTION.md.*

**Arguments:** $ARGUMENTS

Take one concrete starting point and answer, in order: what happened, did it
succeed, how far did it reach, and what should the team do. Read
`references/detection-response/README.md` first (hard rules, verdict ladder,
layout). The output is a verdict, a quantified blast radius, a root cause proven on
the real bytes, and a plan that is **proposed, never executed**.

> The first thing this command outputs is a line: **if funds are moving now, run
> the pause/freeze runbook and open a SEAL 911 ticket (`@seal_911_bot`) first — this
> workup is not emergency response.** The `allowed-tools` above are not a sandbox
> (README); the networked collector and anything that executes code still prompt.

## Steps

1. **Open / adopt the run directory.** For an `INC-<n>.<k>` lead, adopt the
   `incident_<n>/` it names and work into that `INCIDENTS.json` (do not mint a new
   dir — it would strand the incident). For any other lead, open a new `incident_<n>/`
   (first write: `.gitignore` = `*`, Rule 11d) or adopt the newest when `--fresh` is
   absent. Start / append `LEDGER.md`.

2. **Parse the lead → seed entities** and state the working question in one
   sentence. `INC-<n>.<k>` → that incident's entities. A signature → its signers,
   programs, accounts. An address / IOC → itself. An alert line → its fields. Free
   text → the observables you can extract.

3. **Scope (Phase 1).** Pull everything the seed entities touched and expand one
   ring (the account a signer used, a second signer on the same program, the
   instruction a session pivoted to). Corpus: `--logs`, else gated collection as in
   `/auditor:hunt` step 2 (disclose the RPC provider host under Rule 11b; never
   write a keyed URL anywhere). Merge into one `(slot, transactionIndex)` timeline.

4. **Verdict & blast radius (Phase 2).** Did it succeed? Status alone doesn't say
   — confirm with Leg 1 (a balance delta, or the four-part account-data check for a
   takeover), at `finalized`. Quantify blast radius from queries: distinct victims,
   raw units out per mint (Python ints), window. Check whether the activity is still
   ongoing (this one read may use `confirmed`, labelled as such). A failed attempt
   still gets written up — say what they were trying and why it failed.

5. **Root cause & PoC (Phase 3).** Spawn `context-builder` on the implicated
   handler in the source deployed at the incident slot, then `poc-engineer` in
   incident mode to reproduce on the real bytes (Leg 3) — in-process SVM / local
   surfnet, harness keys only. No runnable bytes → ceiling `suspected`.
   `key_compromise` is capped at `suspected` unless a human records a custodian
   attestation verbatim (README).

6. **Plan (Phase 4) — proposed, never executed.** Write
   `incident_<n>/RESPONSE-INC-<n>.<k>.md` from `templates/response-plan.md`
   (never overwrite another lead's plan): verdict & summary, timeline, containment,
   eradication & remediation (hand off as `/auditor:patch INC-<n>.<k>`), recovery,
   coordination **drafts**, detection-engineering rules, open questions. Each action
   carries what / why / risk-if-wrong / who-signs / reversible. Use the menu and the
   "do not" list in `containment-playbook.md`. Then enrich `INCIDENTS.json`.

A human reviews and executes or rejects each item; nothing in the plan has been
done. Onward: `/auditor:patch INC-<n>.<k>` for the fix; a human runs the plan.
