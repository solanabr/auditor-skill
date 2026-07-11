# Orchestration — Deterministic Pre-Scan & Cross-Audit Memory

> **Load when:** running `tools/auditor-tools/audit-scan` (deterministic enumeration) or `audit-mem` (cross-audit memory). Both are **optional token-efficiency layers** — the skill works fully without them, falling back to the grep-based walk. Their job is to spend $0 of deterministic compute on the mechanical work so the LLM spends its tokens on *judgment*.

The tools live in `tools/auditor-tools/` (one Rust crate, two binaries). Build once:

```bash
cd tools/auditor-tools && cargo build --release
# binaries: target/release/audit-scan  and  target/release/audit-mem
```

If `cargo` is absent, skip both and note it — the audit proceeds on the native grep walk (`discovery/grep-commands.md`).

---

## `audit-scan` — enumerate the risky surface

```bash
audit-scan <program-path> --out audit_<n>/prescan.json      # or --pretty to stdout
```

It parses every `*.rs` (skipping `target/`, `.git/`, `node_modules/`) with a real Rust AST (`syn`) and emits ONE JSON:

| Key | What it gives the auditor |
|-----|---------------------------|
| `instructions[]` | every `#[program]` handler + its typed args → **seeds Phase 0.3 instruction matrix** |
| `accounts_structs[]` | every `#[derive(Accounts)]` struct, per-field parsed `#[account(...)]` constraints (`init`/`mut`/`signer`/`has_one`/`seeds`/`bump`/`close`/`owner`/`token::*`/`realloc`) + raw text → **seeds checklists 01/04** |
| `pdas[]` | every `seeds = [...]` catalog → **seeds checklist 04 PDA review** |
| `arithmetic_sites[]` | every RAW `+ - * /` / `+= -= *= /=` with `file:line` → **the checklist-03 worklist** (LLM judges reachability; the tool does not) |
| `panic_sites[]` | `unwrap`/`expect`/index/`panic!` sites → **checklist 03 / DoS review** |
| `cpi_sites[]` | `invoke`/`invoke_signed`/`CpiContext` → **checklist 04 CPI review** |
| `unsafe_blocks[]`, `functions[]` | `unsafe` surface + call-graph seed |

**How the auditor consumes it.** Load `prescan.json` at Phase 0. Treat it as a *map of where to look*, not a set of findings — it has **no verdicts**. Every reported site still goes through the normal checklist + Rule 5b reasoning. The win is twofold: (1) the instruction/constraint/PDA/arithmetic tables are already built, so Phase 0.2–0.4 cost near-zero; (2) a file with **zero** scan hits gets a spot-check instead of a full read. A raw arithmetic or panic site the scan surfaces is a *candidate*, never a confirmed bug — never report a `arithmetic_sites` entry as a finding without the checklist-03 reachability + bounds analysis.

**Honesty rule.** The scanner is a syntactic pass; it does not resolve macros, generics, or cross-crate types. It under-reports (macro-generated handlers, trait-dispatched CPIs) and over-reports (raw arithmetic on already-bounded operands). State in the report that a deterministic pre-scan seeded the review, and that its output was verified — not trusted — by the item-by-item walk.

---

## Evidence-driven load gating (advisory)

The prescan is also a **relevance map**: when a signal is a *provably-empty* set, the corpus that only exists to catch that feature can be **deprioritized / skip-deferred** — its checklist items and vectors render `[N/A — feature absent: <marker>]` from the gate instead of consuming a full read. This is a token-efficiency layer over the same completeness guarantee (OUTPUT-RULES Rule 0). It maps 1:1 to the `known-vectors/INDEX.md` "Load when (markers)" column and to the feature-gated checklist notes.

| Prescan signal (provably empty) | Deprioritized / skip-deferred corpus | Re-open trigger (fires on the MANUAL READ, not just the prescan) |
|---------------------------------|--------------------------------------|-----------------------------------------------------------------|
| `cpi_sites: []` | checklist 04 CPI sections (§4.1–4.2, CPI-target/reentrancy items) + KV CPI cluster (003 reentrancy, 009 unchecked CPI target) | eyes hit `invoke` / `invoke_signed` / `CpiContext` / any cross-program call in source |
| `pdas: []` | PDA-confusion vectors (010 type-cosplay, 026 seed-collision, 104 non-canonical bump) + checklist 04 §4.3–4.4 (PDA derivation) | eyes hit `seeds =` / `find_program_address` / `create_program_address` |
| no `token_2022` / `transfer_hook` / `TransferFee` / `get_extension` (grep + no `token::*` T22 hits) | token-2022 methodology (`references/methodologies/token-2022.md`) + KV 018 (fee-on-transfer), 023 (transfer-hook), 105 (extension abuse) + checklist 01 §1.8 | eyes hit `spl_token_2022` / `get_extension` / `InterfaceAccount` over a T22 mint / any extension type |
| no `pyth` / `switchboard` (grep, incl. `PriceUpdate` / `PullFeed` / `get_price`) | oracles methodology (`references/methodologies/oracles.md`) + KV 005 (oracle manipulation) + checklist 06 §6.9 (oracle) | eyes hit `pyth` / `switchboard` / any oracle account read or price feed |
| no `realm` / `proposal` / `spl-governance` (grep, incl. `vote_record` / `voter_weight`) | governance methodology (`references/methodologies/governance.md`) + KV 021 (vote buying), 119 (durable-nonce governance) | eyes hit `spl-governance` / `realm` / `proposal` / vote-weight logic |
| no `guardian` / `vaa` / `emitter` (grep, incl. `verify_signatures` / `attestation`) | bridges methodology (`references/methodologies/bridges.md`) + KV 022 (fake-proof bridge) | eyes hit `guardian` / `vaa` / `emitter` / cross-chain message verification |
| `unsafe_blocks: []` **and** Anchor detected | checklist 01 §1.10 (native/Pinocchio no-Anchor safety) + KV 109 (Pinocchio/p-token manual validation) | eyes hit `unsafe` / `pinocchio` / `p-token` / manual zero-copy account casting |
| `panic_sites: []` | checklist 03 DoS spot-check (unwrap/expect/index items) + KV 025 (compute-budget DoS), 111 (BPF stack overflow DoS) | eyes hit `unwrap()` / `expect()` / indexing / `panic!` / unbounded loop over user input |

**Two hard safety properties — do not weaken either:**

**(a) Gate on PROVABLE ABSENCE only.** An empty array means *the scanner found zero sites of that kind* — that, plus a confirming grep over the in-scope tree, is the only thing that justifies a skip-defer. Never skip-defer because a surface "looks low-risk" or "is probably fine"; low-likelihood is a Rule 5b judgment on an OPENED item, not a reason to skip loading it.

**(b) The prescan under-reports, so the re-open trigger fires on the MANUAL READ.** By its own honesty rule the scan misses macro-generated handlers and trait-dispatched CPIs. Therefore a skip-defer is **provisional**: the moment the auditor's eyes land on a marker the scan missed (a `CpiContext` behind a macro, a `get_extension` behind a helper), the corresponding cluster loads immediately and every item in it gets a verdict. The gate can only ever *defer* a read to the point of first evidence — it can never make a bug unreachable.

---

## `audit-mem` — cross-audit memory (dedup · regression · FP suppression · warm re-audits)

A local SQLite store (default `.audit-memory/audit.db`, gitignored). Findings are **content-addressed**: `finding_id = sha256(program_id ‖ code_signature ‖ root_cause)`, so the *same* bug keeps its identity across commits and line drift (the same normalized signature `/re-audit` uses for its sibling sweep).

```bash
audit-mem init
audit-mem put-finding --program-id <id> --signature <sig> --root-cause <rc> \
    --title <t> --severity <n> [--commit <sha>] [--audit-n <n>] [--file <f>] [--line <n>] [--verdict <v>]
audit-mem set-status --program-id <id> --signature <sig> --root-cause <rc> --status FIXED|OPEN|ACKNOWLEDGED|DISPUTED
audit-mem rule  --program-id <id> --signature <sig> --ruling FALSE_POSITIVE|ACCEPTED_RISK --rationale <r> --by <who>
audit-mem check --program-id <id> --signature <sig>       # exit 0 = suppressed by a ruling, 1 = not
audit-mem regressions --program-id <id>                    # findings that went FIXED → re-observed
audit-mem warm --program-id <id>                           # {profile, invariants[], open_fp_rulings[]}
```

Where each phase uses it:

- **Intake / Phase 0** — `audit-mem warm <program-id>` injects the prior protocol profile, known invariants, and open false-positive rulings. A re-audit starts **warm** instead of from zero.
- **Before emitting a finding** — `audit-mem check` by signature. An authoritative `FALSE_POSITIVE` ruling **auto-suppresses** the finding to `[N/A — prior ruling]` (record the ruling id). This is the biggest recurring-token saver on re-audits: the opus agents never re-litigate a settled false positive.
- **Triage / synthesis** — `put-finding` records an occurrence per run. A `finding_id` previously `FIXED` and now re-observed is auto-marked **`REGRESSED`** (deterministic, not LLM-judged) — feeds the `/re-audit` finding-diff and the "regressions since last audit" report section.

**Exactness over similarity.** This store is the source of truth for dedup, regression state, and FP rulings because those must be *auditable* ("suppressed by ruling #14, dated X"). Semantic recall (memsearch, "have we seen a bug shaped like this?") is a *secondary* fuzzy index over descriptions — never the authority for suppression or regression.

**Never suppress silently across trust boundaries.** An `ACCEPTED_RISK` or `FALSE_POSITIVE` ruling is scoped to its `program_id`; do not carry a client's ruling into a different codebase, and always surface suppressed items in an appendix so a reviewer can see what was withheld and why.
