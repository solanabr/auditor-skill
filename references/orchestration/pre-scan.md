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
