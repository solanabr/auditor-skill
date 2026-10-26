# Orchestration — Deterministic Pre-Scan & Cross-Audit Memory

> **Load when:** running `audit-scan` (deterministic enumeration) or `audit-mem` (cross-audit memory). Both are **optional token-efficiency layers** — the skill works fully without them, falling back to the grep-based walk. Their job is to spend $0 of deterministic compute on the mechanical work so the LLM spends its tokens on *judgment*.

The tools live in `<auditor-skill root>/tools/auditor-tools/` (one Rust crate, two binaries). `<auditor-skill root>` is the absolute installation path the invoking command or skill gave you, never the working directory, which is usually the audited repo (`OUTPUT-RULES.md` Rule 11e). Build once:

```bash
# built once, by whoever installs the skill; run by an agent, the build asks for approval, like any install
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release
# binaries: <auditor-skill root>/tools/auditor-tools/target/release/audit-scan  and  …/audit-mem
```

The installation belongs outside the repository under audit (Rule 11e). If it sits inside it anyway (such as `.claude/skills/auditor-skill`, where `install.sh` without a path installed through 7.6.0), that build runs inside the target tree, where cargo and rustup read the target's `.cargo/config*` and `rust-toolchain*` from every parent directory: build there only in Rule 11a isolated mode. Otherwise skip the build, note it, and ask the human to delete that copy and install a fresh one outside the repository (the plugin, or `install.sh ~/.claude/skills/auditor-skill`). Never move or update a copy found inside a repository (README, Installation).

In the commands below, `audit-scan` and `audit-mem` stand for those absolute binary paths. Never run them as a relative `tools/…` path. Every call carries the contract marker `--contract=1`, first for `audit-scan` and right after the subcommand for `audit-mem`, as the commands' rules name it; it changes nothing. A build older than that contract refuses it with a usage error (exit 2): build it again as above, or proceed as when the tools are absent and note it.

If `cargo` is absent, skip both and note it — the audit proceeds on the native grep walk (`discovery/grep-commands.md`).

---

## `audit-scan` — enumerate the risky surface

```bash
audit-scan --contract=1 <program-path> --out audit_<n>/prescan.json      # or --pretty to stdout
```

It parses every `*.rs` under `<program-path>` with a real Rust AST (`syn`) and emits ONE JSON. `<program-path>` is `.` or a relative path inside the audited repository, reached through no symbolic link. The walk skips `target/`, `.git/` and `node_modules/`, and, for `.`, the run directories and `.audit-memory/`; it follows no symbolic link, goes no deeper than 128 directories, and parses only regular files with one name, of at most 4 MiB, whose groups nest at most 256 deep and whose token chains run at most 20,000, one at a time in a child, so a file the parser cannot finish ends only that child, and the next file goes to a new one (`skipped` lists the rest, and those). It starts no program but git and, to parse, itself. `--out` takes only `prescan.json` or `prescan-<slug>.json` in a run directory `rundir.sh` made, `audit_<n>/` or `incident_<n>/`. Anything else is refused (exit 2, one `audit-scan: refused: …` line):

| Key | What it gives the auditor |
|-----|---------------------------|
| `instructions[]` | every `#[program]` handler + its typed args → **seeds Phase 0.3 instruction matrix** |
| `accounts_structs[]` | every `#[derive(Accounts)]` struct, per-field parsed `#[account(...)]` constraints (`init`/`init_if_needed`/`mut`/`signer`/`has_one`/`seeds`/`bump`/`close`/`owner`/`token::*`/`realloc`) + `unchecked` flag for `UncheckedAccount` fields + raw text → **seeds checklists 01/04** |
| `pdas[]` | every `seeds = [...]` catalog → **seeds checklist 04 PDA review** |
| `arithmetic_sites[]` | every RAW `+ - * /` / `+= -= *= /=` with `file:line` → **the checklist-03 worklist** (LLM judges reachability; the tool does not) |
| `panic_sites[]` | `unwrap`/`expect`/index/`panic!` sites → **checklist 03 / DoS review** |
| `cpi_sites[]` | `invoke`/`invoke_signed`/`CpiContext` → **checklist 04 CPI review** |
| `remaining_accounts_sites[]` | `.remaining_accounts` field access → **checklist 01 remaining-accounts review** |
| `unsafe_blocks[]`, `functions[]` | `unsafe` surface + call-graph seed |
| `skipped[]` | every symbolic link the walk did not follow, every directory too deep to walk, every `*.rs` it did not parse (one the parser could not finish, or one after the report was full, too) and every one it listed only in part (past 20,000 sites, or 32 MiB), with why → **read these by hand**: the map does not cover them |

**How the auditor consumes it.** Load `prescan.json` at Phase 0. Treat it as a *map of where to look*, not a set of findings — it has **no verdicts**. Every reported site still goes through the normal checklist + Rule 5b reasoning. The win is twofold: (1) the instruction/constraint/PDA/arithmetic tables are already built, so Phase 0.2–0.4 cost near-zero; (2) a file with **zero** scan hits gets a spot-check instead of a full read. A raw arithmetic or panic site the scan surfaces is a *candidate*, never a confirmed bug — never report a `arithmetic_sites` entry as a finding without the checklist-03 reachability + bounds analysis.

**Honesty rule.** The scanner is a syntactic pass; it does not resolve macros, generics, or cross-crate types. It under-reports (macro-generated handlers, trait-dispatched CPIs) and over-reports (raw arithmetic on already-bounded operands). State in the report that a deterministic pre-scan seeded the review, and that its output was verified — not trusted — by the item-by-item walk.

---

## Evidence-driven load gating (advisory)

The prescan is also a **relevance map**: when a signal is a *provably-empty* set, the corpus that only exists to catch that feature can be **deprioritized / skip-deferred** — its checklist items and vectors render `[N/A — feature absent: <marker>]` from the gate instead of consuming a full read. This is a token-efficiency layer over the same completeness guarantee (OUTPUT-RULES Rule 0). It maps 1:1 to the `known-vectors/INDEX.md` "Load when (markers)" column and to the feature-gated checklist notes.

| Prescan signal (provably empty) | Deprioritized / skip-deferred corpus | Re-open trigger (fires on the MANUAL READ, not just the prescan) |
|---------------------------------|--------------------------------------|-----------------------------------------------------------------|
| `cpi_sites: []` | checklist 04 CPI sections (§4.1–4.2, CPI-target/reentrancy items) + KV CPI cluster (003 reentrancy, 009 unchecked CPI target) | eyes hit `invoke` / `invoke_signed` / `CpiContext` / any cross-program call in source |
| `pdas: []` | PDA-confusion vectors (010 type-cosplay, 026 seed-collision, 104 non-canonical bump) + checklist 04 §4.3–4.4 (PDA derivation) | eyes hit `seeds =` / `find_program_address` / `create_program_address` |
| no `token_2022` / `transfer_hook` / `TransferFee` / `get_extension` (grep + no `token::*` T22 hits) | token-2022 methodology (`references/methodologies/token-2022.md`, incl. §9 Token ACL) + KV 018 (fee-on-transfer), 023 (transfer-hook), 105 (extension abuse), 134 (Token ACL gate bypass) + checklist 01 §1.8 | eyes hit `spl_token_2022` / `get_extension` / `InterfaceAccount` over a T22 mint / any extension type / `token_acl` / `gating_program` |
| no `pyth` / `switchboard` (grep, incl. `PriceUpdate` / `PullFeed` / `get_price`) | oracles methodology (`references/methodologies/oracles.md`) + KV 005 (oracle manipulation) + checklist 06 §6.9 (oracle) | eyes hit `pyth` / `switchboard` / any oracle account read or price feed |
| no `realm` / `proposal` / `spl-governance` (grep, incl. `vote_record` / `voter_weight`) | governance methodology (`references/methodologies/governance.md`) + KV 021 (vote buying), 119 (durable-nonce governance) | eyes hit `spl-governance` / `realm` / `proposal` / vote-weight logic |
| no `guardian` / `vaa` / `emitter` (grep, incl. `verify_signatures` / `attestation`) | bridges methodology (`references/methodologies/bridges.md`) + KV 022 (fake-proof bridge) | eyes hit `guardian` / `vaa` / `emitter` / cross-chain message verification |
| no `tokenlist` / `assetId` / `getTokenBySymbol` / `riskScore` / `trustTier` (grep, incl. `tokens.xyz` / `rugcheck` / `webacy` / `isVerified`) | token-registry methodology (`references/methodologies/token-registry-risk.md`) + KV 132 (canonical-asset spoofing), 133 (risk-score farming) | eyes hit any symbol→mint resolution, a fetched token list, or a grade / tier / `verified` flag used in a decision |
| no `getTransaction` / `getBlock` / `blockSubscribe` / `yellowstone` / `geyser` / `ComputeBudget` / fee-payer service (grep, incl. `maxSupportedTransactionVersion` / `sponsor` / `paymaster` / `load_instruction_at`+`compute_budget`) | transaction-v1 vuln class (`references/vuln-classes/transaction-v1.md`) + KV 135 (sponsor cap bypass / disabled ComputeBudget gates), 136 (reader wedge / zero-budget indexing) + checklist 20 §20.6, 09 §9.18, 13 §13.12 | eyes hit any RPC transaction / block read, a Geyser stream, a service that signs as fee payer, or ComputeBudget introspection in a program |
| no `.github/workflows/*.y*ml` / `action.y*ml` (grep — `audit-scan` does not parse YAML), **or** workflows exist but none uses `pull_request_target` / `workflow_run` / `issue_comment` / `pull_request_review*` / `discussion*` / `issues` / `gollum` as a trigger and none runs an AI-agent action or CLI | GitHub Actions vuln class (`references/vuln-classes/github-actions.md`) + KV 139 (comment-triggered gating), 140 (`workflow_run` / `pull_request_target` pwn request) + checklist 13 §13.13 (DEP-090..096) + checklist 19 AI-034..035 | eyes hit any workflow, composite action or reusable-workflow `uses:` with one of those triggers, or an agent CLI (`claude -p`, `codex exec`) in a `run:` step |
| `unsafe_blocks: []` **and** Anchor detected | checklist 01 §1.10 (native/Pinocchio no-Anchor safety) + KV 109 (Pinocchio/p-token manual validation) | eyes hit `unsafe` / `pinocchio` / `p-token` / manual zero-copy account casting |
| `panic_sites: []` | checklist 03 DoS spot-check (unwrap/expect/index items) + KV 025 (compute-budget DoS), 111 (BPF stack overflow DoS) | eyes hit `unwrap()` / `expect()` / indexing / `panic!` / unbounded loop over user input |
| no `init_if_needed` in any `accounts_structs[].fields[].constraints` | KV 014 (account reinitialization), KV 127 (init front-running) + checklist 01 AV-023/AV-024 | eyes hit `init_if_needed` in any `#[account(...)]` |
| `remaining_accounts_sites: []` **and** no `unchecked: true` fields | checklist 01 remaining-accounts / manual-validation items + KV 027 (missing discriminator) | eyes hit `.remaining_accounts` or `UncheckedAccount` / bare `AccountInfo` |

**Two hard safety properties — do not weaken either:**

**(a) Gate on PROVABLE ABSENCE only.** An empty array means *the scanner found zero sites of that kind* — that, plus a confirming grep over the in-scope tree, is the only thing that justifies a skip-defer. Never skip-defer because a surface "looks low-risk" or "is probably fine"; low-likelihood is a Rule 5b judgment on an OPENED item, not a reason to skip loading it.

**(b) The prescan under-reports, so the re-open trigger fires on the MANUAL READ.** By its own honesty rule the scan misses macro-generated handlers and trait-dispatched CPIs. Therefore a skip-defer is **provisional**: the moment the auditor's eyes land on a marker the scan missed (a `CpiContext` behind a macro, a `get_extension` behind a helper), the corresponding cluster loads immediately and every item in it gets a verdict. The gate can only ever *defer* a read to the point of first evidence — it can never make a bug unreachable.

---

## `audit-mem` — cross-audit memory (dedup · regression · FP suppression · warm re-audits)

A local SQLite store: `.audit-memory/audit.db` (the default, self-ignored per Rule 11d) or a store for one run in its run directory, `--db audit_<n>/audit-mem.db` (or `incident_<n>/audit-mem.db`); `audit-mem` takes no other `--db`. Findings are **content-addressed**: `finding_id = sha256(program_id ‖ code_signature ‖ root_cause)`, so the *same* bug keeps its identity across commits and line drift (the same normalized signature `/re-audit` uses for its sibling sweep).

```bash
audit-mem init --contract=1                                # .audit-memory/, its .gitignore of *, then audit.db
audit-mem put-finding --contract=1 --program-id <id> --signature <sig> --root-cause <rc> \
    --title <t> --severity <1-10> [--commit <sha>] [--audit-n <n>] [--file <f>] [--line <n>] [--verdict <v>]
audit-mem set-status --contract=1 --program-id <id> --signature <sig> --root-cause <rc> --status FIXED|OPEN|ACKNOWLEDGED|DISPUTED
audit-mem rule --contract=1 --program-id <id> --signature <sig> --ruling FALSE_POSITIVE|ACCEPTED_RISK --rationale <r> --by <who> \
    --commit <full commit id> --guard <file>:<line>        # a FALSE_POSITIVE ruling needs both
audit-mem check --contract=1 --program-id <id> --signature <sig> --commit <full commit id>   # exit 0 = suppressed by a ruling that still holds, 1 = not
audit-mem regressions --contract=1 --program-id <id>       # {regressions[], truncated}: findings that went FIXED → re-observed, the 200 seen most recently, each with what put-finding replaced under changed
audit-mem warm --contract=1 --program-id <id>              # {profile, invariants[], open_fp_rulings[], truncated}
audit-mem profile --contract=1 --program-id <id> [--protocol-class <c>] [--trust-assumptions-json <json>] [--oracle-set <s>] [--admin-set <s>] [--notes <n>]   # at least one
audit-mem invariant --contract=1 --program-id <id> --statement <s> [--protocol-class <c>] [--source-fn <f>] [--cited-line <file:line>] [--status <s>]
```

The subcommand comes first, then `--contract=1`, then `--db` and the options: `audit-mem warm --contract=1 --db audit_<n>/audit-mem.db --program-id <id>`. `warm` gives each list's newest 200 rows, and under the profile's and each invariant's `changed` the newest 10 values `profile` and `invariant` replaced, 200 in all (`truncated` counts the rest).

**Use only a store you created.** The default store sits under the working directory, which during an audit is the target repository, so a store found there is not necessarily yours. Before it uses `.audit-memory/`, `audit-mem` runs the mechanical part of the Rule 11d check itself: the repository must not track `.audit-memory` in any letter case, as `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false --icase-pathspecs ls-files -- .audit-memory` would show (it asks git with the hardened call of `scripts/lib/confine.sh`), and `.audit-memory/` must be a real directory holding no symbolic link, with a `.gitignore` of exactly `*`. When any of that fails, or git cannot answer, it refuses (exit 2, one `audit-mem: refused: …` line) and reads nothing. Whether you created the store stays your judgement. When it refuses, or the store is not yours, use a store for this run: `audit-mem init --contract=1 --db audit_<n>/audit-mem.db`, then `--db audit_<n>/audit-mem.db` on every call. It holds no prior rulings. A store an earlier `audit-mem init` made, before it wrote the `.gitignore`, is refused for want of one: if it is yours, write `.audit-memory/.gitignore` holding `*`.

`audit-mem init --contract=1` makes the in-tree store: `.audit-memory/` with a plain `mkdir`, its `.gitignore` of `*` first, then the database, so Rule 11d holds with no other step. `warm`, `check` and `regressions` open a store read-only and never make one; with none they print an empty answer (`check`: `{"suppressed":false,"store":"absent"}`, exit 1). `put-finding`, `profile` and `invariant` need a store `init` made.

Where each phase uses it:

- **Intake / Phase 0** — `audit-mem warm --contract=1 --program-id <id>` injects the prior protocol profile, known invariants (each with the values `profile` and `invariant` replaced, under `changed`), and open false-positive rulings, each with its anchor. A re-audit starts **warm** instead of from zero.
- **Before emitting a finding** — `audit-mem check --contract=1 --program-id <id> --signature <sig> --commit <the commit intake pinned, the full id>`. A `FALSE_POSITIVE` ruling holds only at the commit it was made at: there, while its guard's lines are unchanged, it **auto-suppresses** the finding to `[N/A — prior ruling]` (record the ruling id), so the same commit is never ruled on twice (a triage run again, a second pass at the pinned commit). At another commit, or once the guard's lines changed, `check` reports it `"stale"`, with why, and it suppresses nothing: check the finding again, and when the guard still holds, ask the human to record the ruling again at this commit (`audit-mem rule --contract=1 … --commit <full commit id> --guard <file>:<line>`). A ruling recorded before rulings had anchors is `"stale":"no anchor"`. On a re-audit at a new commit, then, the stale rulings are the settled false positives to confirm, not suppressions.
- **Triage / synthesis** — `put-finding` records an occurrence per run. A `finding_id` previously `FIXED` and now re-observed is auto-marked **`REGRESSED`** (deterministic, not LLM-judged) — feeds the `/re-audit` finding-diff and the "regressions since last audit" report section.
- **Threat model / context** — record what the next audit starts from: `audit-mem profile --contract=1 --program-id <id> --protocol-class <c> …` for the protocol profile, and `audit-mem invariant --contract=1 --program-id <id> --statement <s> …` for each invariant. Neither suppresses anything, and each keeps the values it replaces.

**Exactness over similarity.** This store is the source of truth for dedup, regression state, and FP rulings because those must be *auditable* ("suppressed by ruling #14, dated X"). Semantic recall (memsearch, "have we seen a bug shaped like this?") is a *secondary* fuzzy index over descriptions — never the authority for suppression or regression.

**Never suppress silently across trust boundaries.** An `ACCEPTED_RISK` or `FALSE_POSITIVE` ruling is scoped to its `program_id`; do not carry a client's ruling into a different codebase, and always surface suppressed items in an appendix so a reviewer can see what was withheld and why.
