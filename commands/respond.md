---
name: auditor:respond
description: "Investigate one incident lead (a transaction signature, an address, an alert, an indicator of compromise, or an INC id from /auditor:hunt) through Solana transaction history — work out whether the attack landed and how far it reached, pin the root cause in the deployed code and reproduce it locally, then draft containment, remediation and recovery steps for humans to carry out. This command changes nothing on-chain."
argument-hint: "<INC-n.k | signature | address | 'alert json' | 'free text'> [--logs <dir>] [--repo <path>] [--collect] [--fresh]"
allowed-tools: Read, Grep, Glob, Task, Edit(incident_*/**)
---

# auditor-skill — Incident Response (lead in hand)

*Method credited to anthropics/defending-code-reference-harness (dnr-respond); see ATTRIBUTION.md.*

**Arguments:** $ARGUMENTS

Start from a single lead and work outward from it. Four questions drive the run,
in this order: what took place, whether the attacker got what they were after, how
wide the damage spread, and what the team should do next. Read
`${CLAUDE_PLUGIN_ROOT}/references/detection-response/README.md` first — the hard
rules, the verdict ladder and the run-directory layout live there. You come out
with a verdict, damage figures that each trace to a query, a root cause
reproduced on the real program bytes, and a plan for humans. This command
carries out none of that plan.

> Open every run with this line: **if funds are moving right now, run the
> pause/freeze runbook and open a SEAL 911 ticket (`@seal_911_bot`) first — this
> workup comes after, it is not the emergency response.** The `allowed-tools` above
> are not a sandbox (README); every bundled `scripts/dnr` script (collector,
> snapshot, profile, frames, deltas, redact) prompts for approval — none is
> pre-approved — as do `jq` and anything that executes code.

Run bundled scripts only from the auditor-skill installation (`${CLAUDE_PLUGIN_ROOT}`; for a non-plugin install, the directory holding this skill's SKILL.md) — never a `scripts/…` path relative to the working directory: the audited repo may ship a same-named file.
Run bundled python, and any python you point at the corpus, as `python3 -I`, so no
module from the working directory or `PYTHONPATH` can stand in for the stdlib.
Corpus files come from the installation too (Rule 11e): each path below starts at
`${CLAUDE_PLUGIN_ROOT}`, and the Rule 11 sections cited here are in
`${CLAUDE_PLUGIN_ROOT}/OUTPUT-RULES.md`. Never open a same-named file in the working
directory.

## Steps

1. **Run directory, then the program bytes — before anything else.**
   - For a new `incident_<n>/`, `<n>` is the highest existing number + 1; create
     the dir with `mkdir` (not `-p`) and stop if it already exists. Its first file
     is a `.gitignore` holding `*` (Rule 11d). Reuse an existing `incident_*` only if git
     does not track it and it holds no symbolic links, and only after the human
     confirms which one. Never write into a tracked `incident_*`; the bundled
     scripts refuse one, and one that is or holds a symbolic link, with exit 2.
   - For an `INC-<n>.<k>` lead, the lead names the `incident_<n>/` to reuse (naming
     it is the confirmation): adopt it under that rule and work into its
     `INCIDENTS.json`; minting a fresh directory would orphan the incident. For any
     other lead, offer the newest `incident_*` for reuse under the same rule; with
     `--fresh`, or when no one can confirm (a non-interactive run), create a new
     one.
   - **Snapshot every implicated program now:**
     `bash "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/snapshot-program.sh" <program_id> incident_<n>`
     — read-only (`program show` + `program dump`, or `program-v4 show` +
     `program-v4 download` for a loader-v4 program), kept as
     `incident_<n>/bin/<id>@<slot>.so` and never overwritten, with the CLI's error
     text passed through `redact.sh`. Copy the line it prints (last-deployed slot,
     zero-trimmed sha256, file) into `LEDGER.md`. A hotfix shipped
     mid-investigation overwrites the on-chain binary; the copy taken before it is
     what Leg 3 runs on, and this run's snapshot adds `bin/<id>@<new slot>.so` next
     to it.

2. **Turn the lead into seed entities**, and write the question this run must
   answer as a single sentence in the ledger. An `INC-<n>.<k>` contributes that
   incident's entities; a signature, its signers, programs and accounts; an address
   or indicator, itself; an alert, its fields; free text, whatever observables it
   names.

3. **Scope (Phase 1).** Gather everything the seed entities touched, then widen by
   exactly one ring — the account a signer used, another signer on the same
   program, the instruction a session moved to next. Corpus: `--logs`, or the gated
   collection described in `/auditor:hunt` step 2 (name the RPC provider's domain,
   the host's last two DNS labels, under Rule 11b; a keyed URL is never written
   anywhere). Show the human the addresses, the window you chose around the lead,
   the caps and the estimated call count, get a yes, and pass exactly those values:
   the window as `--since <fromUnix> --until <toUnix>`, the caps as
   `--max-pages N --max-tx N`, never a `--window` argument. Copy every row of the
   collector's `collection-gaps.tsv` into the ledger's **Collection gaps** line and
   into `collection_gaps` of the incident in `INCIDENTS.json`. Merge everything into
   one timeline ordered by `(slot, transactionIndex)`.

4. **Outcome and damage (Phase 2).** A status code can't tell you whether it
   worked — Leg 1 can: a balance movement, or for a takeover the four-part
   account-data check, read at `finalized`. Size the damage from queries: distinct
   victims, raw units out per mint (Python ints), the window. Check whether
   activity is still under way; that one read may use `confirmed` if it says so.
   An attempt that failed is still documented: what it went after and what stopped
   it.

5. **Root cause & PoC (Phase 3).** Spawn `context-builder` on the implicated
   handler in the source deployed at the incident slot. Read that revision without
   checking it out: from a `git clone --no-local` copy outside the client's
   checkout, use
   `git --no-pager -c core.fsmonitor=false -c log.showSignature=false show --no-textconv <rev>:<path>`
   (Rule 11c). Never `checkout`, `switch` or `worktree add` in `--repo`. Then spawn
   `poc-engineer` in incident mode to reproduce on the bytes from step 1 (Leg 3) —
   in-process SVM or a local surfnet, harness keys only, asserting the observed
   effect. No usable bytes → the ceiling is `suspected`. Building target code
   needs the Rule 11a mode: ask once (a non-interactive run is native, and the
   report says so), record it in the ledger header, pass it on as
   `AUDITOR_EXEC_MODE`.
   `key_compromise` stays at `suspected` unless a person records a custodian
   attestation word for word (README).

6. **The plan (Phase 4).** Write `incident_<n>/RESPONSE-INC-<n>.<k>.md` from
   `${CLAUDE_PLUGIN_ROOT}/templates/response-plan.md`; a plan written for another
   lead is never overwritten. It covers the verdict, the timeline, containment, the code fix
   (handed off as `/auditor:patch INC-<n>.<k>`), recovery, coordination drafts,
   alerting proposals and the unanswered questions. Each action states what it is, the query
   result behind it, who has to sign, whether it can be undone, and the cost if
   it turns out to be wrong — pick from the menu and respect the "do not" list in
   `${CLAUDE_PLUGIN_ROOT}/references/detection-response/containment-playbook.md`.
   Then update `INCIDENTS.json`.

Each item waits for a person to approve, change or drop it; this command performs
none of them. Next: `/auditor:patch INC-<n>.<k>` for the fix, while people decide
on the plan.
