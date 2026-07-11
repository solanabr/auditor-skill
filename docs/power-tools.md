# Power Tools

The tooling that makes auditor-skill more than a prompt: a deterministic pre-scanner, cross-audit memory, vendored SAST/fuzz/coverage/mutation, mainnet-fork economic sim, and the PoC/patch harness stack. Back to the [docs index](README.md).

Every tool here is an **optional layer**. The corpus works fully without any of them — each one either saves tokens, adds memory, or upgrades an asserted finding to a demonstrated one, and degrades gracefully (with a named blocker) when absent.

| Tool | Buys you | Built/enabled by |
|------|----------|------------------|
| [`audit-scan`](#audit-scan) | ~30-40% fewer input tokens; a map of the risky surface | `cargo build --release` |
| [`audit-mem`](#audit-mem) | exact de-dup, regression detection, FP suppression, warm re-audits | `cargo build --release` |
| [Trail of Bits plugins](#trail-of-bits-plugins) | real SAST, fuzzing, coverage, mutation | `git submodule update --init --recursive` |
| [Surfpool sim](#surfpool-economic-simulation) | a real $ P/L for economic findings | `surfpool` CLI + MCP |
| [PoC/patch harness](#pocpatch-harness-stack) | executable exploits + verified fixes | platform-tools ≥ v1.54 |

---

## audit-scan

A deterministic Rust AST pass (`syn` with `span-locations`, so every hit carries a real line number) that emits the *risky surface* of a Solana/Anchor codebase as one JSON — so the LLM auditor spends tokens on **judgment**, not mechanical enumeration.

### Run it

```bash
cd tools/auditor-tools && cargo build --release        # once
target/release/audit-scan ./programs/my-program/src --pretty --out audit_1/prescan.json
```

Recursively walks `*.rs` (skipping `target/`, `.git/`, `node_modules/`), parses each with `syn::parse_file`, prints one JSON object to stdout or `--out FILE`. Files that fail to parse are skipped (best-effort).

### What it extracts

| Key | Seeds |
|-----|-------|
| `instructions[]` | every `#[program]` handler + typed args (the Anchor `Context<..>` param dropped) → Phase 0.3 instruction matrix |
| `accounts_structs[]` | every `#[derive(Accounts)]` struct; each field's parsed `#[account(...)]` constraints (`init`/`mut`/`signer`/`has_one`/`seeds`/`bump`/`close`/`owner`/`token`/`associated_token`/`realloc`) + raw text → checklists 01/04 |
| `pdas[]` | every `seeds = [...]` catalog → checklist 04 PDA review |
| `arithmetic_sites[]` | every RAW `+ - * /` / `+= -= *= /=` (NOT `.checked_*`) with `file:line` → the checklist-03 worklist |
| `panic_sites[]` | `.unwrap()`/`.expect()`/index `x[y]`/`panic!`/`unreachable!`/`unwrap!` → checklist 03 / DoS review |
| `cpi_sites[]` | `invoke`/`invoke_signed`/`CpiContext` → checklist 04 CPI review |
| `unsafe_blocks[]`, `functions[]` | unsafe surface + call-graph seed |

### The one rule: it is a map, not a verdict

The scan output has **no verdicts**. A raw `arithmetic_sites` or `panic_sites` entry is a *candidate*, never a confirmed bug — it still goes through the checklist + Rule 5b reachability/bounds analysis. Never report a scan hit as a finding on its own.

It is a syntactic pass: it does not resolve macros, generics, or cross-crate types, so it **under-reports** (macro-generated handlers, trait-dispatched CPIs) and **over-reports** (raw arithmetic on already-bounded operands). The report must state that a deterministic pre-scan seeded the review and its output was *verified, not trusted*, by the item-by-item walk.

### The token win

Feed `prescan.json` to the auditor at Phase 0. Two effects: (1) the instruction/constraint/PDA/arithmetic tables are already built, so Phase 0.2-0.4 cost near-zero; (2) a file with **zero** scan hits gets a spot-check instead of a full read. This collapses the mechanical multipliers (checklist cross-ref ~0.3×, discovery ~0.2×, checkpoint re-reads ~0.1×) toward ~0.1× total — on a 50K-line program roughly **200-300K fewer input tokens** (variable multiplier ~1.6× → ~1.0×; e.g. Opus ≈ $32 → ~$20 per [COSTS.md](../COSTS.md)). Used at Phase 0 of the automated flow and by `context-builder`; falls back to the grep walk when `cargo` is absent.

Reference: [`references/orchestration/pre-scan.md`](../references/orchestration/pre-scan.md).

---

## audit-mem

A local SQLite findings store (default `.audit-memory/audit.db`, gitignored; schema created lazily) for cross-audit memory. It is the **authoritative** source for de-dup, regression state, and FP rulings — because those must be *auditable* ("suppressed by ruling #14, dated X").

### Content-addressed identity

```
finding_id = sha256(program_id ‖ code_signature ‖ root_cause)
```

The same bug keeps its identity across commits and line drift — the same normalized signature `/auditor:re-audit` uses for its sibling sweep, and `/auditor:triage` uses for root-cause de-dup.

### The four capabilities

- **Exact de-dup** — two candidates with the same `finding_id` are one finding (all locations recorded). `/auditor:triage` collapses them.
- **Regression detection** — when `put-finding` re-observes a finding whose stored status was `FIXED`, it transitions to `REGRESSED` and prints `REGRESSED <id>` (deterministic, not LLM-judged). `audit-mem regressions --program-id <id>` lists them → the `/auditor:re-audit` finding-diff and the report's "regressions since last audit" section.
- **False-positive suppression** — `audit-mem rule ... --ruling FALSE_POSITIVE` records a ruling; `audit-mem check` gates on it (exit 0 = suppressed). Before emitting a finding, `/auditor:triage` runs `check` by signature — an authoritative ruling auto-suppresses it to `[N/A — prior ruling #<id>]`. The opus agents never re-litigate a settled false positive: the biggest recurring-token saver on re-audits.
- **Warm re-audits** — `audit-mem warm --program-id <id>` returns `{profile, invariants[], open_fp_rulings[]}` so a re-audit starts warm, not from zero. Used at intake / Phase 0 and by `threat-modeler`.

### Lifecycle example

```bash
audit-mem --db .audit-memory/audit.db init

# first observation -> "OPEN <id>"
audit-mem put-finding --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee1 --audit-n audit-1 \
  --file src/withdraw.rs --line 42 --verdict TRUE_POSITIVE

# dev fixes it
audit-mem set-status --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' --status FIXED

# next audit re-observes -> "REGRESSED <id>"
audit-mem put-finding --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee3 --audit-n audit-3

# suppress a known FP, then gate on it
audit-mem rule --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --ruling FALSE_POSITIVE --rationale 'guarded by prior require!' --by auditor
audit-mem check --program-id VaultProg... --signature 'unchecked_sub@vault.balance'
#   -> {"suppressed":true,"ruling":{...}}   (exit 0)
```

### Subcommands

`init` · `put-finding` · `set-status` (`FIXED`|`OPEN`|`ACKNOWLEDGED`|`DISPUTED`) · `rule` (`FALSE_POSITIVE`|`ACCEPTED_RISK`) · `check` · `regressions` · `warm`. `--db` defaults to `.audit-memory/audit.db`. Schema: `findings`, `occurrences`, `fp_rulings`, `invariants`, `protocol_profile`.

### Exactness over similarity

This store is the source of truth *because* suppression and regression must be auditable and deterministic. Semantic recall ("have we seen a bug shaped like this?") is a **secondary fuzzy index** over descriptions — never the authority for suppression or regression. And rulings are **scoped to their `program_id`**: never carry a client's ruling into a different codebase, and always surface suppressed items in an appendix.

Reference: [`references/orchestration/pre-scan.md`](../references/orchestration/pre-scan.md) · [`tools/auditor-tools/README.md`](../tools/auditor-tools/README.md).

---

## Trail of Bits plugins

auditor-skill's corpus is the **knowledge** layer; Trail of Bits (vendored at `vendor/trailofbits`, CC-BY-SA — a reference, not a copy) is the **execution** layer — tools prose + grep cannot run. Initialize:

```bash
git submodule update --init --recursive
test -d vendor/trailofbits/plugins && echo present    # the detection agents use
```

Agents delegate when present, fall back to native grep when absent (and note "deeper tooling available via `git submodule update --init --recursive`" in the report).

### Capability → plugin → who uses it

| Capability | ToB plugin | auditor-skill use | Native fallback |
|------------|------------|-------------------|-----------------|
| Interprocedural SAST (taint) | `static-analysis`, `semgrep-rule-creator`, `variant-analysis` | `vuln-hunter` runs SAST, folds SARIF into verdicts; up-front in `audit-cycle` to clear the mechanical surface | `discovery/grep-commands.md` |
| Property / fuzz harnesses | `testing-handbook-skills`, `property-based-testing` | generate + run a harness for any ≥High arithmetic/economic finding; `/auditor:poc` orchestrates | checklist 16 "does the suite exist" prose |
| Coverage & mutation | `testing-handbook-skills`, `mutation-testing` | evidence-back FV coverage; an uncaught mutant downgrades a PASS; `/auditor:patch --verify-with-mutation` uses a caught mutant as fix evidence | FV items `[PARTIAL — not machine-verified]` |
| Exploitability verify | `second-opinion`, `fp-check` | `peer-reviewer` + `poc-engineer` confirm a finding is real, not a harness artifact | manual re-derivation |
| Secret zeroization (IR) | `zeroize-audit` | verify KV-112 / RS-015 at the IR level | grep `zeroize`/`Zeroizing` |
| Constant-time | `constant-time-analysis` | secret-dependent branches when custom crypto is present | note "manual review needed" |
| Entry-point enumeration | `entry-point-analyzer` | seed the Phase 0 instruction matrix (Solana support) | manual `#[instruction]` enumeration |
| Supply-chain metadata | `supply-chain-risk-auditor` | enrich checklist 11 (SC-044..046) | `npm audit` / `cargo audit` + grep |
| Unit / dimensional analysis | `dimensional-analysis` | propagate units through DeFi value paths (checklist 03/06) — catches mixed-decimals bugs | manual per-quantity tracking |
| Insecure-default trace | `insecure-defaults` | fail-open vs fail-secure trace (checklist 12/13) | grep fallback-secret patterns |
| API misuse / footguns | `sharp-edges` | misuse-resistance review of the program's own CPI interface + config | `references/framework-idioms/*` |

**FV/harness escalation ladder** (from [methodology §6](../references/audit-lifecycle/methodology.md)): manual → proptest on pure fns → **Trident stateful sequences (the primary bug-finder)** → Certora/Kani reserved for the 3-10 catastrophic invariants → MIRAI/Clippy. Skip deductive FV when the target is dominated by an untrusted CPI (the callee is a hole in the proof) — mock the boundary adversarially in Trident instead and note the abstention.

**The rule:** delegation *augments*, never replaces, the native verdict. Every finding still carries an auditor-skill verdict and (if N≥6) a filled Rule 5b gate. Tool output is evidence, not a verdict. Reference: [`references/orchestration/boundary-map.md`](../references/orchestration/boundary-map.md).

---

## Surfpool economic simulation

For economic / oracle / MEV findings, a yes/no isn't proof — Rule 5b wants a dollar figure. `/auditor:economic-sim` (driven by `economic-analyst`) models capital/setup cost, extractable value, atomicity, and flash-loanable ceilings, then — when a Surfpool mainnet-fork is reachable — reproduces **deposit → manipulate → withdraw** against forked real pool state for a recorded net **P/L**.

```
/auditor:economic-sim F-003
/auditor:poc F-003 --fork     # build the executable Surfpool PoC → [PoC-SIM-REPRODUCED]
```

Enabled by the `surfpool` CLI + its MCP (keyless). Absent → fall back to Mollusk/LiteSVM if the logic is modelable, else `[PoC-ATTEMPTED]` with the blocker named ("surfpool CLI + MCP unreachable / fork state unavailable"). See [poc-and-patches.md](poc-and-patches.md#framework-selection).

---

## PoC/patch harness stack

The stack that turns confirmed findings into executable exploits (`/auditor:poc` → `poc-engineer`) and verified fix patches (`/auditor:patch` → `patch-engineer`), writing to `audit_<n>/poc/F-xxx/` and `audit_<n>/patches/F-xxx.patch`.

Frameworks by finding type — **Mollusk** (single-instruction logic/access-control), **LiteSVM** (multi-step lifecycle), **Surfpool** (economic, fork), **Trident/cargo-fuzz** (fuzz-discoverable) — with evidence tiers `[PoC-REPRODUCED]` > `[PoC-SIM-REPRODUCED]` > `[PoC-FUZZ-REPRODUCED]` > `[PoC-ATTEMPTED]` > `[PoC-PROSE]` and fix tiers `[FIX-VERIFIED]` > `[FIX-INSUFFICIENT]` > `[FIX-PROPOSED]`.

Toolchain gate: **`cargo build-sbf` platform-tools ≥ v1.54** (the default v1.51/cargo 1.84 bundle cannot parse the `edition2024` manifests in modern `mollusk-svm`/`litesvm` — pass `--tools-version v1.54`). Never hard-fails: any absence → `[PoC-ATTEMPTED]` + the prose PoC is kept; downgrading the evidence tier never downgrades the finding's severity.

Full walkthrough — layout, framework matrix, tiers, the "executable outranks prose but prose is never removed" rule, toolchain requirements: **[poc-and-patches.md](poc-and-patches.md)**. Reference: [`references/orchestration/poc-harness.md`](../references/orchestration/poc-harness.md).
