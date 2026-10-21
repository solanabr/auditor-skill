# Response plan — INC-{N}.{k}: {title}

<!-- credited to anthropics/defending-code-reference-harness; see ATTRIBUTION.md.
     templates/response-plan.md → incident_<n>/RESPONSE-INC-<n>.<k>.md, written by
     /auditor:respond. One plan per lead; never overwrite another lead's plan.
     Action menu and rules: references/detection-response/containment-playbook.md. -->

> **Every item below is a proposal. None of it has been carried out.** The track
> does not sign, send, pause, freeze, upgrade, rotate, or contact anyone — a human
> reviews each item and executes or rejects it.

> If funds are moving **now**, this write-up is not the response. Page on-call,
> run the pause/freeze runbook, and open a SEAL 911 ticket (`@seal_911_bot`;
> verify any member who contacts you via the bot's keyword step).

## 1. Verdict & summary

{Three sentences: what happened, did it succeed, how far it reached. State the
verdict and the discriminating evidence (at `finalized`).}

## 2. Timeline

{The merged `(slot, transactionIndex)` timeline for this incident's entities.}

## 3. Containment (proposed)

Each row: the evidence line that justifies it, who signs, whether it reverses, and
what breaks if the call is wrong. See `containment-playbook.md` for the menu and
the "do not" list (never `program close`, never `--final`).

| Action | Why (evidence) | Who signs | Reversible | Risk if wrong |
|--------|----------------|-----------|-----------|---------------|
| {pause / freeze / rotate / limit} | {query result} | {authority / multisig} | {yes/partial} | {…} |

## 4. Eradication & remediation (proposed)

- **Code fix:** {file:function; the guard to restore}. Hand off as a
  `/auditor:patch INC-{N}.{k}` vuln entry; verify by re-detonating the stored PoC
  against the current deployed bytes (a rejection means the fix holds).
- **Interim mitigation** if the fix will take time: {the containment row that
  holds the line until then}.

## 5. Recovery (proposed)

- Credentials to rotate: {the queried list — not "everything"}.
- Customers to notify: {the distinct-victim list from the blast-radius query —
  internal; do not publish wallet lists}.
- Confirm-clean signal: {what to watch to know the attacker is out}.

## 6. Coordination & comms (drafts only)

{Draft text for a human to send — SEAL 911, the token issuer/desk for a freeze,
affected protocols, and cited exchanges/bridges on the fund-flow path. The agent
sends nothing. Never attribute an address to a named person.}

## 7. Detection engineering (proposed)

Turn the queries that found this into standing alerts, mapped to checklist 17:
{e.g. LM-030 anomalous withdrawals, LM-037 upgrade-authority change, LM-038
unexpected mint, LM-063 off-chain consumer trusting logs, LM-065 stream liveness}.
Note which existing alerts fired and which were noise.

## 8. Open questions

{What this corpus cannot settle: stolen vs. authorized key use (chain data can't
tell — this is why `key_compromise` caps at `suspected`), earlier history beyond
retention, whether stolen data was used elsewhere.}
