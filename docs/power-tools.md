# Power Tools

The tooling that makes auditor-skill more than a prompt: a deterministic pre-scanner, cross-audit memory, vendored SAST/fuzz/coverage/mutation, mainnet-fork economic sim, the PoC/patch harness stack, and the bundled scripts the commands run. Back to the [docs index](README.md).

Every tool here is an **optional layer**. The corpus works fully without any of them — each one either saves tokens, adds memory, or upgrades an asserted finding to a demonstrated one, and degrades gracefully (with a named blocker) when absent.

| Tool | Buys you | Built/enabled by |
|------|----------|------------------|
| [`audit-scan`](#audit-scan) | ~30-40% fewer input tokens; a map of the risky surface | `cargo build --release` |
| [`audit-mem`](#audit-mem) | exact de-dup, regression detection, FP suppression, warm re-audits | `cargo build --release` |
| [`audit-logs`](#audit-logs) | the incident recipes `profile.sh`, `frames.py` and `deltas.py` as one offline binary, with the same output | `cargo build --release --locked` |
| [Trail of Bits plugins](#trail-of-bits-plugins) | real SAST, fuzzing, coverage, mutation | plugin install or `install.sh`; else `git submodule update --init --depth 1 -- vendor/trailofbits` |
| [Surfpool sim](#surfpool-economic-simulation) | a real $ P/L for economic findings | `surfpool` CLI + MCP |
| [PoC/patch harness](#pocpatch-harness-stack) | executable exploits + verified fixes | platform-tools ≥ v1.54 |
| [Bundled scripts](#bundled-scripts) | incident corpus collection and queries, the threat-model history collector, the Trail of Bits bump review | nothing to build: bash ≥ 3.2, plus `jq`, `python3`, `curl` or the `solana` CLI per script |

---

## audit-scan

A deterministic Rust AST pass (`syn` with `span-locations`, so every hit carries a real line number) that emits the *risky surface* of a Solana/Anchor codebase as one JSON — so the LLM auditor spends tokens on **judgment**, not mechanical enumeration.

### Run it

Build once, then run the binary by its absolute path from the repository under audit. `<auditor-skill root>` is the directory auditor-skill is installed in, never a path relative to your project ([`OUTPUT-RULES.md` Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)):

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release        # once
"<auditor-skill root>/tools/auditor-tools/target/release/audit-scan" --contract=1 ./programs/my-program/src --pretty --out audit_1/prescan.json
```

The installation belongs outside the repository under audit. If it sits inside it anyway (such as `.claude/skills/auditor-skill`, where `install.sh` without a path installed through 7.6.0), the build runs inside the target tree, where cargo and rustup read the target's `.cargo/config*` and `rust-toolchain*` from every parent directory. Build there only in [Rule 11a](../OUTPUT-RULES.md#rule-11-operating-safety) isolated mode, or delete that copy and install a fresh one outside the repository (the plugin, or `install.sh ~/.claude/skills/auditor-skill`) and build that one. Never move or update a copy you find inside a repository ([README](../README.md#installation)).

Recursively walks the `*.rs` files under the directory it is given (`.` or a relative path inside the repository, reached through no symbolic link), skipping `target/`, `.git/` and `node_modules/`, and, for `.`, the run directories and `.audit-memory/`. It parses each with `syn::parse_file` and prints one JSON object to stdout, or writes it to `--out audit_<n>/prescan.json` (or `prescan-<slug>.json`) in a run directory. It follows no symbolic link, goes no deeper than 128 directories, and parses only regular files with one name, of at most 4 MiB, whose groups nest at most 256 deep and whose token chains run at most 20,000, each in a child of its own (it starts no program but git and, to parse, itself); `skipped` lists every link and every `*.rs` it did not parse, a file the parser could not finish among them, with why. Any other path is refused with exit 2 and one `audit-scan: refused: …` line ([tools/auditor-tools/README.md](../tools/auditor-tools/README.md#where-it-reads-and-writes)). Every call carries `--contract=1` first; a build older than that contract refuses it: build it again.

### What it extracts

| Key | Seeds |
|-----|-------|
| `instructions[]` | every `#[program]` handler + typed args (the Anchor `Context<..>` param dropped) → Phase 0.3 instruction matrix |
| `accounts_structs[]` | every `#[derive(Accounts)]` struct; each field's parsed `#[account(...)]` constraints (`init`/`init_if_needed`/`mut`/`signer`/`has_one`/`seeds`/`bump`/`close`/`owner`/`token`/`associated_token`/`realloc`) + `unchecked` flag for `UncheckedAccount` fields + raw text → checklists 01/04 |
| `pdas[]` | every `seeds = [...]` catalog → checklist 04 PDA review |
| `arithmetic_sites[]` | every RAW `+ - * /` / `+= -= *= /=` (NOT `.checked_*`) with `file:line` → the checklist-03 worklist |
| `panic_sites[]` | `.unwrap()`/`.expect()`/index `x[y]`/`panic!`/`unreachable!`/`unwrap!` → checklist 03 / DoS review |
| `cpi_sites[]` | `invoke`/`invoke_signed`/`CpiContext` → checklist 04 CPI review |
| `remaining_accounts_sites[]` | `.remaining_accounts` field access → checklist 01 remaining-accounts review |
| `unsafe_blocks[]`, `functions[]` | unsafe surface + call-graph seed |
| `skipped[]` | links not followed, directories too deep to walk and `*.rs` files not parsed (one the parser could not finish too), with why: read them by hand |

### The one rule: it is a map, not a verdict

The scan output has **no verdicts**. A raw `arithmetic_sites` or `panic_sites` entry is a *candidate*, never a confirmed bug — it still goes through the checklist + Rule 5b reachability/bounds analysis. Never report a scan hit as a finding on its own.

It is a syntactic pass: it does not resolve macros, generics, or cross-crate types, so it **under-reports** (macro-generated handlers, trait-dispatched CPIs) and **over-reports** (raw arithmetic on already-bounded operands). The report must state that a deterministic pre-scan seeded the review and its output was *verified, not trusted*, by the item-by-item walk.

### The token win

Feed `prescan.json` to the auditor at Phase 0. Two effects: (1) the instruction/constraint/PDA/arithmetic tables are already built, so Phase 0.2-0.4 cost near-zero; (2) a file with **zero** scan hits gets a spot-check instead of a full read. This collapses the mechanical multipliers (checklist cross-ref ~0.3×, discovery ~0.2×, checkpoint re-reads ~0.1×) toward ~0.1× total — on a 50K-line program roughly **200-300K fewer input tokens** (variable multiplier ~1.6× → ~1.0×; e.g. Opus ≈ $32 → ~$20 per [COSTS.md](../COSTS.md)). Used at Phase 0 of the automated flow and by `context-builder`; falls back to the grep walk when `cargo` is absent.

Reference: [`references/orchestration/pre-scan.md`](../references/orchestration/pre-scan.md).

---

## audit-mem

A local SQLite findings store (`.audit-memory/audit.db` by default, self-ignored ([Rule 11d](../OUTPUT-RULES.md#11d--output-hygiene)), or `audit_<n>/audit-mem.db` for one run; `audit-mem init --contract=1` makes it) for cross-audit memory. It is the **authoritative** source for de-dup, regression state, and FP rulings — because those must be *auditable* ("suppressed by ruling #14, dated X").

### Content-addressed identity

```
finding_id = sha256(program_id ‖ code_signature ‖ root_cause)
```

The same bug keeps its identity across commits and line drift — the same normalized signature `/auditor:re-audit` uses for its sibling sweep, and `/auditor:triage` uses for root-cause de-dup.

### The four capabilities

- **Exact de-dup** — two candidates with the same `finding_id` are one finding (all locations recorded). `/auditor:triage` collapses them.
- **Regression detection** — when `put-finding` re-observes a finding whose stored status was `FIXED`, it transitions to `REGRESSED` and prints `REGRESSED <id>` (deterministic, not LLM-judged). `audit-mem regressions --contract=1 --program-id <id>` lists them, each with the severities and titles a later `put-finding` replaced under `changed` → the `/auditor:re-audit` finding-diff and the report's "regressions since last audit" section.
- **False-positive suppression** — `audit-mem rule --contract=1 ... --ruling FALSE_POSITIVE --commit <full commit id> --guard <file>:<line>` records a ruling anchored to the commit and to the guard that makes it a false positive, with a hash of the guard's lines; `audit-mem check --contract=1 --commit <full commit id>` gates on it (exit 0 = suppressed). A ruling holds only at the commit it was made at: there, while the guard's lines are unchanged, `/auditor:triage`'s `check` by signature auto-suppresses the finding to `[N/A — prior ruling #<id>]`, so the same commit is not ruled on twice. At another commit, or once the guard's lines changed, the ruling is reported `"stale"` and suppresses nothing: on a re-audit it lists the settled false positives to confirm, and to rule again at the new commit.
- **Warm re-audits** — `audit-mem warm --contract=1 --program-id <id>` returns `{profile, invariants[], open_fp_rulings[], truncated}` so a re-audit starts warm, not from zero: the protocol profile `audit-mem profile` recorded, the invariants `audit-mem invariant` recorded (each with the values they replaced, under `changed`, the newest 10 of each), and the rulings with their anchors, each list its newest 200 rows. Used at intake / Phase 0 and by `threat-modeler`.

### Lifecycle example

Use an in-tree store only if you created it. `audit-mem` runs the mechanical part of the [Rule 11d](../OUTPUT-RULES.md#11d--output-hygiene) check itself before every use of `.audit-memory/`: the repository must not track `.audit-memory` in any letter case (what `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false --icase-pathspecs ls-files -- .audit-memory` shows), and the directory must hold no symbolic link and a `.gitignore` of exactly `*`. When that fails, or git cannot answer, it refuses with exit 2; use a store for one run instead, `--db audit_<n>/audit-mem.db`. The example uses the in-tree store, so it runs from the repository under audit; `audit-mem` stands for `"<auditor-skill root>/tools/auditor-tools/target/release/audit-mem"`, and each call carries the contract marker `--contract=1` right after its subcommand.

```bash
audit-mem init --contract=1          # .audit-memory/, its .gitignore of * first, then audit.db

# first observation -> "OPEN <id>"
audit-mem put-finding --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee1 --audit-n audit-1 \
  --file src/withdraw.rs --line 42 --verdict TRUE_POSITIVE

# dev fixes it
audit-mem set-status --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' --status FIXED

# next audit re-observes -> "REGRESSED <id>"
audit-mem put-finding --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee3 --audit-n audit-3

# what the next audit starts from; a value replaced later is kept, and warm lists it under changed
audit-mem profile --contract=1 --program-id VaultProg... --protocol-class vault --oracle-set 'pyth SOL/USD'
audit-mem invariant --contract=1 --program-id VaultProg... --statement 'total_shares == shares_mint.supply' --status Unproven

# rule a known FP at the audited commit, citing its guard, then gate on it
audit-mem rule --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --ruling FALSE_POSITIVE --rationale 'guarded by the require! on line 40' --by auditor \
  --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe --guard src/withdraw.rs:40
audit-mem check --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe
#   -> {"suppressed":true,"ruling":{...}}   (exit 0)
audit-mem check --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --commit c0ffee4c0ffee4c0ffee4c0ffee4c0ffee4c0ffe
#   -> {"suppressed":false,"stale":"ruled at commit c0ffee3…, checked at c0ffee4…",...}   (exit 1)
```

### Subcommands

`init` · `put-finding` · `set-status` (`FIXED`|`OPEN`|`ACKNOWLEDGED`|`DISPUTED`) · `rule` (`FALSE_POSITIVE`|`ACCEPTED_RISK`, with `--commit`, a full commit id, and `--guard`) · `check` (`--commit`) · `regressions` · `warm` · `profile` · `invariant`. The subcommand comes first, then the contract marker `--contract=1` (a build older than the contract refuses it: build it again); `--db` is `.audit-memory/audit.db` (the default) or `audit_<n>/audit-mem.db` (or `incident_<n>/audit-mem.db`), nothing else. `warm`, `check` and `regressions` open the store read-only; `warm` gives the newest 200 rows of each list and `regressions` the 200 regressed findings seen most recently, each item with the newest 10 values replaced in it (`changed`, 200 in all), and `truncated`. Schema: `findings`, `occurrences`, `fp_rulings` (with each ruling's anchor), `invariants`, `protocol_profile`, `history` (the values `profile`, `invariant` and `put-finding` replaced).

### Exactness over similarity

This store is the source of truth *because* suppression and regression must be auditable and deterministic. Semantic recall ("have we seen a bug shaped like this?") is a **secondary fuzzy index** over descriptions — never the authority for suppression or regression. And rulings are **scoped to their `program_id`**: never carry a client's ruling into a different codebase, and always surface suppressed items in an appendix.

Reference: [`references/orchestration/pre-scan.md`](../references/orchestration/pre-scan.md) · [`tools/auditor-tools/README.md`](../tools/auditor-tools/README.md).

---

## audit-logs

The detection & response analysis recipes, [`profile.sh`](#profilesh), [`frames.py`](#framespy) and [`deltas.py`](#deltaspy), as one offline Rust binary. Each subcommand prints what its script prints, with the same `skipped …` notes and exit status, under the same input contract, and refuses the same paths in the same words; `scripts/tests/test-audit-logs.sh` checks that against the scripts. Inside the `auditor:dnr-analyze` fork, where `/auditor:hunt` and `/auditor:respond` run `incident-responder` for each analysis phase, it runs first, and the script runs in its place when it is not built or reports a stale build.

### Run it

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release --locked        # after every install or update
"<auditor-skill root>/tools/auditor-tools/target/release/audit-logs" profile incident_<n>/corpus*/transactions.jsonl
"<auditor-skill root>/tools/auditor-tools/target/release/audit-logs" frames --instructions --out incident_<n>/instructions.jsonl incident_<n>/corpus*/transactions.jsonl
"<auditor-skill root>/tools/auditor-tools/target/release/audit-logs" deltas tokens incident_<n>/corpus*/transactions.jsonl
```

Build it in the installation, never inside the repository under audit, as for `audit-scan`, and build it again after every update. A plugin update installs auditor-skill into a new versioned directory, where the fork runs the scripts until it is built there; an update in place, such as a `git pull` of a clone, leaves the old binary, which refuses to run (exit 4, below) only when the update changed a file it was built from: a recipe it mirrors, `scripts/lib/confine.sh`, or its own `Cargo.toml` or `src/`. `cargo build --release --locked -p audit-logs` builds it alone: it compiles one dependency, `libc`, and needs no C compiler, though cargo still reads the crates.io index for the workspace lockfile.

- **Paths:** as for the scripts: each corpus is a regular file with one name in an `incident_<n>/` run directory whose `.gitignore` holds `*`, named relative to the working directory, with no empty, `.` or `..` component and no symbolic link on the way; each option comes once, before the corpus paths; `--out` names a new `<name>.jsonl`, `.tsv` or `.txt` directly in the run directory. Anything else is refused with exit 2 before any input is read. With no corpus named, `frames` and `deltas` read stdin.
- **Exit:** 0 done · 1 an input that cannot be read, an `--out` that cannot be written, or a failed write · 2 usage, or a refused path · 4 a stale build: it carries a copy of the files it was built from (the three recipes, `scripts/lib/confine.sh`, its `Cargo.toml` and `src/`), and when an installed one differs it writes nothing and prints one line, `audit-logs: stale build: …`; rebuild it, or run the scripts.
- **Pre-approval:** inside the `auditor:dnr-analyze` fork, `audit-logs` runs without a prompt by this path, as do the three recipes and `jq-ro.sh`; no other bundled script is pre-approved, and neither is `jq`. Each refuses a named input outside a run directory before reading anything (exit 2). With no corpus named, `frames` and `deltas` read stdin, which a `<` redirect can fill from any file Claude Code lets the fork read; they print nothing from a line that is not a transaction. A line that holds a `$` or a backtick, inside quotes too, still prompts.
- **Network:** none. **Writes:** stdout, or the `--out` file, through a new temporary file beside it, made, linked and removed through the run directory, opened once.
- **Where it differs from the scripts:** `profile` pads its counts as GNU `uniq -c` does (BSD `uniq -c` pads to 4); a closed stdout, a broken pipe or a stdin that is a directory ends it with another exit status; and it needs none of what `profile.sh` alone refuses to run without (a `TMPDIR` and a `PATH` entry outside the working directory, `jq`, `python3`); see [`tools/auditor-tools/README.md`](../tools/auditor-tools/README.md#where-it-differs-from-the-scripts).

---

## Trail of Bits plugins

auditor-skill's corpus is the **knowledge** layer; Trail of Bits (vendored at `vendor/trailofbits`, CC-BY-SA — a reference, not a copy) is the **execution** layer — tools prose + grep cannot run. The plugin install and `install.sh` fetch it at the pinned commit, which the [README](../README.md#tool-execution-trail-of-bits--optional-rust-tools) names and which moves only through the review in [CONTRIBUTING.md §5](../CONTRIBUTING.md#5-tooling-changes). For any other clone, initialize it from the auditor-skill directory:

```bash
git submodule update --init --depth 1 -- vendor/trailofbits
test -d "<auditor-skill root>/vendor/trailofbits/plugins" && echo present    # the detection agents use
git ls-tree HEAD vendor/trailofbits                   # the pinned commit, initialized or not
```

Agents delegate when present, fall back to native grep when absent (and note "deeper tooling available via `git submodule update --init --depth 1 -- vendor/trailofbits`, run in the auditor-skill directory (plugin and install.sh installs already include it)" in the report).

Rows that build or run target code follow the execution mode recorded at intake ([`OUTPUT-RULES.md` Rule 11a](../OUTPUT-RULES.md#rule-11-operating-safety)); rows that send code or dependency data to an outside service are listed in the report (Rule 11b).

**Instruction files.** Trail of Bits ships a root `CLAUDE.md` that imports its contributor guide (`@AGENTS.md`, ~20 KB). When the submodule sits inside the project you run Claude Code in, that guide loads into the session the first time it reads a file under `vendor/trailofbits/`. To keep it out, add `"claudeMdExcludes": ["**/vendor/trailofbits/CLAUDE.md", "**/vendor/trailofbits/**/AGENTS.md"]` to your own `.claude/settings.local.json` — never to a client's committed `settings.json`.

### Capability → plugin → who uses it

| Capability | ToB plugin | auditor-skill use | Native fallback |
|------------|------------|-------------------|-----------------|
| Interprocedural SAST (taint) | `static-analysis`, `semgrep-rule-creator`, `variant-analysis` | `vuln-hunter` runs SAST, folds SARIF into verdicts; up-front in `audit-cycle` to clear the mechanical surface. A CodeQL build compiles the target (11a) | `discovery/grep-commands.md` |
| Property / fuzz harnesses | `testing-handbook-skills`, `property-based-testing` | generate + run a harness for any ≥High arithmetic/economic finding; `/auditor:poc` orchestrates (11a) | checklist 16 "does the suite exist" prose |
| Coverage & mutation | `testing-handbook-skills`, `mutation-testing` | evidence-back FV coverage; an uncaught mutant downgrades a PASS; `/auditor:patch --verify-with-mutation` uses a caught mutant as fix evidence (11a) | FV items `[PARTIAL — not machine-verified]` |
| Exploitability verify | `fp-check` (local); `second-opinion` sends the selected code to an external LLM CLI — OpenAI Codex or Google Antigravity / Gemini — so the report records it (11b) | `peer-reviewer` + `poc-engineer` confirm a finding is real, not a harness artifact | manual re-derivation |
| Secret zeroization (IR) | `zeroize-audit` | verify KV-112 / RS-015 at the IR level; compiles the target (11a) | grep `zeroize`/`Zeroizing` |
| Constant-time | `constant-time-analysis` | secret-dependent branches when custom crypto is present; compiles the code it checks (11a) | note "manual review needed" |
| Entry-point enumeration | `entry-point-analyzer` | seed the Phase 0 instruction matrix (Solana support); on Solidity, `slither .` compiles the target (11a) | manual `#[instruction]` enumeration |
| Supply-chain metadata | `supply-chain-risk-auditor` | enrich checklist 11 (SC-044..046); npm / PyPI / Go only. Its collector sends the project's dependency names to 8 outside services (OSV, npm registry + downloads API, PyPI, Go module proxy, deps.dev, GitHub API, OpenSSF Scorecard), so the report records it (11b); `--offline` only replays cached responses and is not a privacy control | `npm audit` / `cargo audit` + grep |
| Unit / dimensional analysis | `dimensional-analysis` (needs the ToB plugin installed for its `dimensional-analysis:*` agents; otherwise it reports BLOCKED) | propagate units through DeFi value paths (checklist 03/06) — catches mixed-decimals bugs; writes unit comments into the source and `DIMENSIONAL_*` files at the project root, so run it on a scratch copy without the target's `DIMENSIONAL_*` files | manual per-quantity tracking |
| Insecure-default trace | `insecure-defaults` (a command + Workflow, `/insecure-defaults:audit`, that runs only with the ToB plugin installed; from the vendored tree, read its `references/*.md`) | fail-open vs fail-secure trace (checklist 12/13) | grep fallback-secret patterns |
| API misuse / footguns | `sharp-edges` | misuse-resistance review of the program's own CPI interface + config | `references/framework-idioms/*` |
| Fix blast-radius | `differential-review` | `/auditor:patch` step 4: the fix closes the exploit path and leaves every other path unchanged | `/auditor:re-audit` 4b differential execution (11a) + manual caller / sibling review |
| Post-patch validation | `post-patch-validation` (its runner runs under `uv run` and needs Python ≥ 3.11 and git ≥ 2.36; its `/post-patch-validation:validate-patch` Workflow needs the ToB plugin installed and works against the repository the session runs in, so it is not used) | `/auditor:patch --post-patch-validation` (opt-in): the patch against the finding, root-cause variants and unchanged behavior. Isolated mode only (11a), never native: it runs only when the stricter of the recorded mode (`<R>/exec-mode`, or `intake.md` §8 without it) and `AUDITOR_EXEC_MODE` is isolated and `probe.sh --only isolation` finds nothing readable. It creates, locks and prunes git worktrees in the repository it is given, so it gets a no-checkout clone, outside the target tree, of the copy `git-ro.sh copy` makes in `<R>`, never the client checkout. Its checks build and test the target with the caller's privileges and an open network: package registries, toolchain downloads (`uv` can fetch a Python) and any host the target's code or tests contact; a git-lfs filter in the caller's git config would contact the repository's LFS host on checkout, which the clone's `* !filter` attributes line prevents. The report records them (11b). A finding turns `[FIX-VERIFIED]` into `[FIX-INSUFFICIENT]`; any other tier keeps its tier and records the finding under Residual, and nothing else changes a tier | none needed: `/auditor:patch` steps 3 and 4 |

**FV/harness escalation ladder** (from [methodology §6](../references/audit-lifecycle/methodology.md)): manual → proptest on pure fns → **Trident stateful sequences (the primary bug-finder)** → Certora/Kani reserved for the 3-10 catastrophic invariants → MIRAI/Clippy. Skip deductive FV when the target is dominated by an untrusted CPI (the callee is a hole in the proof) — mock the boundary adversarially in Trident instead and note the abstention.

**The rule:** delegation *augments*, never replaces, the native verdict. Every finding still carries an auditor-skill verdict and (if N≥6) a filled Rule 5b gate. Tool output is evidence, not a verdict. Reference: [`references/orchestration/boundary-map.md`](../references/orchestration/boundary-map.md).

---

## Surfpool economic simulation

For economic / oracle / MEV findings, a yes/no isn't proof — Rule 5b wants a dollar figure. `/auditor:economic-sim` (driven by `economic-analyst`) models capital/setup cost, extractable value, atomicity, and flash-loanable ceilings, then — when a Surfpool mainnet-fork is reachable — reproduces **deposit → manipulate → withdraw** against forked real pool state for a recorded net **P/L**.

```
/auditor:economic-sim F-003
/auditor:poc F-003 --fork     # build the executable Surfpool PoC → [PoC-SIM-REPRODUCED]
```

Enabled by the `surfpool` CLI + its MCP (keyless). The fork fetches mainnet state from its RPC datasource, which receives the program ids and account addresses the simulation reads, so the report names that provider's domain ([Rule 11b](../OUTPUT-RULES.md#11b--outside-service-disclosure)). Absent → fall back to Mollusk/LiteSVM if the logic is modelable, else `[PoC-ATTEMPTED]` with the blocker named ("surfpool CLI + MCP unreachable / fork state unavailable"). See [poc-and-patches.md](poc-and-patches.md#framework-selection).

---

## PoC/patch harness stack

The stack that turns confirmed findings into executable exploits (`/auditor:poc` → `poc-engineer`) and verified fix patches (`/auditor:patch` → `patch-engineer`), writing to `audit_<n>/poc/F-xxx/` and `audit_<n>/patches/F-xxx.patch`.

Frameworks by finding type — **Mollusk** (single-instruction logic/access-control), **LiteSVM** (multi-step lifecycle), **Surfpool** (economic, fork), **Trident/cargo-fuzz** (fuzz-discoverable) — with evidence tiers `[PoC-REPRODUCED]` > `[PoC-SIM-REPRODUCED]` > `[PoC-FUZZ-REPRODUCED]` > `[PoC-ATTEMPTED]` > `[PoC-PROSE]` and fix tiers `[FIX-VERIFIED]` > `[FIX-INSUFFICIENT]` > `[FIX-PROPOSED]`.

Toolchain gate: **`cargo build-sbf` platform-tools ≥ v1.54** (the default v1.51/cargo 1.84 bundle cannot parse the `edition2024` manifests in modern `mollusk-svm`/`litesvm` — pass `--tools-version v1.54`). Never hard-fails: any absence → `[PoC-ATTEMPTED]` + the prose PoC is kept; downgrading the evidence tier never downgrades the finding's severity.

Full walkthrough — layout, framework matrix, tiers, the "executable outranks prose but prose is never removed" rule, toolchain requirements: **[poc-and-patches.md](poc-and-patches.md)**. Reference: [`references/orchestration/poc-harness.md`](../references/orchestration/poc-harness.md).

---

## Bundled scripts

Shell and Python scripts that ship with auditor-skill; there is nothing to build. The commands run them by absolute path from the installation, never by a `scripts/` path relative to the audited repository ([Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)); the Python ones run directly by that path, their first line running them as `python3 -I`. The shell scripts run under bash 3.2 or later. The blocks below give each script's arguments, exit codes, network use and outputs.

### Detection & response recipes (`scripts/dnr/`)

The recipes behind `/auditor:hunt` and `/auditor:respond` ([detection-response.md](detection-response.md); method and hazards: [`scripts/dnr/README.md`](../scripts/dnr/README.md)). They summarise a transaction corpus without reading it into context. Inside the `auditor:dnr-analyze` fork, where `/auditor:hunt` and `/auditor:respond` run `incident-responder` for each analysis phase, [`audit-logs`](#audit-logs) runs first, with the same arguments after its subcommand, and `profile.sh`, `frames.py` or `deltas.py` runs in its place when it is not built or reports a stale build. The two that use the network take the endpoint from `$RPC_URL` in the environment, never from the command line, and hand it to curl or the `solana` CLI through a config, never as an argument.

#### `snapshot-program.sh`

```bash
"<auditor-skill root>/scripts/dnr/snapshot-program.sh" <program_id> incident_<n>
```

Step 1 of every hunt and response: it keeps the deployed program bytes before a hotfix can replace them. It runs `solana program show` and `solana program dump`, or `solana program-v4 show` and `download` for a loader-v4 program. It reads the program again after the dump and dumps once more if the last-deployed slot moved. Every `show` must name the requested id as its Program Id. It checks the ELF header, hashes the dump the way `solana-verify` does (trailing zero padding trimmed, then sha256), and prints a ledger line: `program=… owner=… last_deployed_slot=… authority=… sha256_zero_trimmed=… elf_bytes=… padding_bytes=… file=bin/<id>[@<slot>].so`. A loader-v4 program's line also has `status=…` (`deployed`, `retracted` or `finalized`) after `authority=`. A program on an immutable loader shows `last_deployed_slot=n/a (immutable loader)` and `authority=none`.

Run it directly by its path, from the working directory.

- **Arguments:** exactly two: a base58 program id (32 bytes) and the run directory, `incident_<n>`, relative to the working directory (a leading `./` and a trailing `/` are dropped).
- **Exit:**
  - 0: a new snapshot, or `unchanged`.
  - 2, refused before any CLI call, with one line, `snapshot-program.sh: refused: <reason>`:
    - a usage error, or a third argument;
    - an id that is not base58 or not 32 bytes;
    - no `$RPC_URL`, or one that holds a quote, a backslash, whitespace or a control character;
    - a run directory that is not `incident_<n>` directly in the working directory: an absolute path, a `.` or `..` component, another name;
    - a run directory that is a symbolic link, holds one, is tracked by git in any letter case, has no `.gitignore` holding exactly `*`, or that git or find cannot check (the check fails closed). The check runs again just before the first write, when `bin/` must also be a directory of its own;
    - an `incident_<n>/disclosures.tsv` that is not a regular file with one link and the disclosure header.
  - 3, a named blocker:
    - no `solana` CLI or `python3`;
    - no private temp directory for the CLI config, or a `TMPDIR` inside the working directory;
    - the CLI did not take the keyless config;
    - a disclosure row that could not be added;
    - a CLI error;
    - no program under any loader: one more read (`solana account`, its data written to the temp directory) names the account's owner in the blocker. When a loader owns the account, the blocker says which case it is: a data account of the loader (a program's data account or a buffer: check the id), or an executable account neither `show` could read (a closed program, or a failing endpoint: run the snapshot again);
    - a `show` that names another Program Id;
    - a dump without the ELF magic;
    - a slot that moved during both dumps;
    - a hash that could not be computed;
    - a snapshot name already taken, or a `.show.txt` without its `.so`;
    - a kept file that could not be written;
    - a kept snapshot that is not a regular file with the ELF magic beside a regular `.show.txt`, or later snapshots (`<id>@<slot>.so`) without the first one;
    - bytes on-chain that differ from every kept snapshot, under a last-deployed slot that is not a plain number and so cannot name a new one;
    - bytes on-chain that differ from any snapshot kept at the same or a later last-deployed slot, even when another snapshot matches. Every kept snapshot is checked before any can match.
- **Network:** read-only `solana` CLI calls to `$RPC_URL`, which reaches the CLI through a temporary `-C` config with no usable keypair path; it signs nothing. CLI errors pass through `redact.sh`. Before the CLI reads from the endpoint, one row goes into `incident_<n>/disclosures.tsv` (below).
- **Writes:** in `incident_<n>/bin/`, made when missing:
  - The first snapshot is `<id>.so` with `<id>.show.txt`.
  - If the slot and zero-trimmed sha256 match a kept snapshot, a later run prints `unchanged: …` and that snapshot's line, with the authority and status read now, and writes nothing. A transfer of authority or a loader-v4 finalize changes neither the slot nor the bytes, so a notice on stderr names any change since the snapshot was kept.
  - After a redeploy it keeps the new bytes as `<id>@<slot>.so` with its `.show.txt` and prints the first snapshot's line and the new one.
  - A kept file is never replaced; each is written through the descriptor opened when it was created.
  - One row of `incident_<n>/disclosures.tsv`: the provider's domain and the program id.
- **Needs:** the `solana` CLI and `python3`, which checks the id and hashes the dump as `python3 -I`.

#### `collect.sh`

```bash
"<auditor-skill root>/scripts/dnr/collect.sh" --out incident_<n>/corpus[-<k>] --confirmed [--since <unix>] [--until <unix>] \
  [--before <signature>] [--max-pages N] [--max-tx N] -- <address> [<address> ...]
```

The one gated collector: it pages each address's signature history, failed transactions included (they are evidence of attempts), and fetches every transaction in the window into a local JSONL corpus, newest first. Run it directly by its path, from the working directory; each option is given at most once.

| Flag | Meaning |
|------|---------|
| `--out incident_<n>/corpus[-<k>]` | corpus directory (required): `corpus`, or `corpus-<k>` with 1 to 4 digits, in the run directory `incident_<n>`, relative to the working directory, made there when missing. One that holds `signatures.jsonl`, `transactions.jsonl` or `collection-gaps.tsv`, even an empty one, is refused, so a resume goes into a new directory |
| `--confirmed` | required; the commands pass it only after a person has approved the addresses, the window, the caps and the estimated call count |
| `--since <unix>`, `--until <unix>` | the window, on `blockTime`; `0` (the default) leaves that end open |
| `--before <signature>` | start paging just older than this signature: resume a capped run, or skip activity after the incident |
| `--max-pages N` | pages of up to 1,000 signatures per address (default 20, at most `AUDITOR_RPC_MAX_PAGES`). An empty page ends that address's history; a page of fewer than 1,000 ends it only on the last page the cap allows, since a node can return a short page before the end, so a history that ends inside the cap costs one more call |
| `--max-tx N` | `getTransaction` calls in total, failures included (default 2000, at most `AUDITOR_RPC_MAX_TX`); the oldest signatures are left out first. After 10 failed calls in a row the run stops |
| `-- <address> ...` | the base58 addresses to page, at most `AUDITOR_RPC_MAX_ADDRESSES` |

- **Caps:** no argument can go past the caps set in the environment, where a command line cannot set them: `AUDITOR_RPC_MAX_PAGES` (default 100), `AUDITOR_RPC_MAX_TX` (default 10000) and `AUDITOR_RPC_MAX_ADDRESSES` (default 25). A value over its cap is refused, naming the variable to raise; a default over a cap set lower drops to that cap, and the run's `caps:` line prints the values used.
- **Exit:**
  - 0: done, collection gaps included.
  - 2, refused before anything is written or sent, with one line, `collect.sh: refused: <reason>`:
    - no `--confirmed`;
    - a usage error, an unknown argument, or an option given twice;
    - no `$RPC_URL`, or one that holds a quote, a backslash, whitespace or a control character;
    - an address or `--before` value that is not base58;
    - a number that is not a plain integer of at most 18 digits;
    - a `--max-pages`, `--max-tx` or address count over its cap, or a cap that is not a plain integer;
    - an `--out` other than `incident_<n>/corpus` or `incident_<n>/corpus-<k>`, relative: an absolute path, a `.` or `..` component, another name;
    - a run directory that is a symbolic link, holds one, is tracked by git (in any letter case), has no `.gitignore` holding exactly `*`, or that git or find cannot check;
    - an `incident_<n>/disclosures.tsv` that is not a regular file with one link and the disclosure header;
    - an `--out` that already holds a corpus file, or where the corpus files cannot be created.
  - 3, a named blocker:
    - no curl or jq;
    - a jq that rounds large integers and no working `python3`;
    - no private temp directory, which is made before anything is written, or a `TMPDIR` inside the working directory;
    - a disclosure row that could not be added (nothing was sent);
    - a failed write to a corpus file, to `collection-gaps.tsv`, or to the private signature and fetch lists (a full disk, say). The run stops there: it makes no further call, records what it had not collected as gap rows while `collection-gaps.tsv` still takes them, and prints the blocker in place of the closing lines. When the blocker says `collection-gaps.tsv` is incomplete too, record the gaps as for a run killed outright.
  - 128 + N: stopped by signal N (INT, TERM or HUP), with what was left recorded as collection gaps.
- **Network:** read-only JSON-RPC to `$RPC_URL` (`getSignaturesForAddress`, then `getTransaction` at `finalized` with `maxSupportedTransactionVersion: 1`), and only with `--confirmed`. The URL reaches curl through a config on stdin (`curl -q -K -`), never as an argument. The `provider:` line names the provider's domain (the host's last two labels) for the Rule 11b disclosure; curl errors pass through `redact.sh`.
- **Writes:** `<dir>/signatures.jsonl`, `<dir>/transactions.jsonl` and `<dir>/collection-gaps.tsv`, and before the first call one row of `incident_<n>/disclosures.tsv`: the provider's domain and the addresses, with the `--before` signature when one is given.
  - `transactions.jsonl` is written by jq only when a test round-trip shows jq keeps 64-bit integers exact (a check of behaviour, not of the version); otherwise it is written by `python3 -I`.
  - `collection-gaps.tsv` has one `<signature or address><TAB><reason>` row per gap: a failed `getTransaction`, a failed signature page (older history not collected), a page cap that stopped on a full page, where older history may exist (with the `--before` to resume from), the `--max-tx` cap, or the stop after 10 failed calls in a row.
  - The three files are written only through the descriptors opened when they were created.
  - stdout ends with `transactions fetched: N of M calls -> …` and `collection gaps: N (see …)`, except after a failed write (exit 3), when a `[blocker]` line on stderr takes their place. Notices go to stderr and start with `  ! `.
  - A run stopped by INT, TERM or HUP adds gap rows for the address being paged (naming the `--before` signature to resume from, once one of its pages was read) and each one after it, and one for the signatures listed but not fetched, then prints the closing lines. A run killed outright prints nothing more; then each signature in `signatures.jsonl` with no transaction in `transactions.jsonl` is a gap, and so is every address whose history may not have been paged to its end: the last `queried_address` in `signatures.jsonl` and every address given after it, or every address given when none appears.
- **Run time:** up to addresses × `--max-pages` + `--max-tx` calls, one at a time, each up to 60 seconds. Run a long collection in the background, or with a timeout sized from that count.
- **Needs:** curl and jq; `python3` too when jq rounds large integers (before jq 1.7).

#### `profile.sh`

```bash
"<auditor-skill root>/scripts/dnr/profile.sh" [--out <file>] <corpus.jsonl> [<corpus.jsonl> ...]
```

The baseline of one or more `getTransaction` JSONL corpora, such as every `incident_<n>/corpus*/transactions.jsonl`, counting each signature once. It reads structural fields only, never log text, and reports the succeeded / failed split, the transaction-version histogram (a version that is not a string as its JSON text, with each character of the input contract's fixed list as a `\uNNNN` escape), the `blockTime` window, and the top 20 fee payers, signers and top-level programs. It counts and orders them byte by byte (`sort` and `uniq` run under `LC_ALL=C`), so the figures and the order of ties are the same under every locale. It keeps the first occurrence of each signature and skips malformed lines under the input contract the three recipes share ([`scripts/dnr/README.md`](../scripts/dnr/README.md#input-contract)); closing `-- skipped` lines give both counts, one per input for malformed lines, and are printed on stderr too. Those malformed lines are collection gaps.

- **Arguments:** one or more corpus files, each a regular file with one name in a run directory `incident_<n>/` whose `.gitignore` holds `*`, named relative to the working directory, with no empty, `.` or `..` component and no symbolic link on the way; any other is refused before any input is read. Run it directly by its quoted path, from the working directory: it refuses to run from an installation inside it.
- **`--out <file>`:** a new `.jsonl`, `.tsv` or `.txt` name directly in the run directory; writes the report to a temporary file beside `<file>` and gives it that name once the report is whole, as `frames.py` and `deltas.py` do.
- **Exit:** 0 done · 1 a corpus file that cannot be read, or an `--out` that cannot be written · 2 usage error, or a path the input contract refuses (a missing or non-regular file, one with a second name, one outside a run directory or reached through a symbolic link, an `--out` that is not a new name directly in a run directory), as one `profile.sh: refused: …` line · 3 `jq` or `python3` missing, checked before anything is read (`[blocker] <tool> is not on PATH; profile.sh needs jq and python3.`).
- **Network:** none. **Writes:** stdout, or the `--out` file. Needs `jq` and `python3` (the one-per-signature pass runs as `python3 -I`).

#### `frames.py`

```bash
"<auditor-skill root>/scripts/dnr/frames.py" [--instructions] [--out <file>] [<corpus.jsonl> ...]    # reads stdin when no file is named
```

Attributes each `Program log:`, `Program data:` and `Program return:` line to the program frame that emitted it. It walks the log array one element at a time with anchored patterns, so a newline inside a log payload cannot forge a frame. Output is JSONL on stdout, one `{sig, ok, depth, program, kind, text}` record per line, where `kind` is `log`, `data`, `return`, `truncated` or `unparsed`; a character of the input contract's fixed list is written as a `\uNNNN` escape (a surrogate pair above U+FFFF), never raw. A malformed input line is skipped and counted under the shared input contract, never echoed. A log line is what the program asserted, never proof that state changed.

- **Arguments:** corpus files (several corpora count each signature once), or none for stdin; each named file is checked as for `profile.sh`. Skipped copies, and each input's malformed lines, are reported on stderr.
- **`--instructions`:** prints the instruction records instead; the default output is unchanged without it. An `ix` record for each entry of `message.instructions` and `meta.innerInstructions` gives the program, the top-level and inner index, the stack height, the accounts, and the data as given (or `parsed-only`). An `invoke` record gives each invocation's depth, outcome and the `ix_seq` it ran. No `ix` field comes from log text.
- **`--out <file>`:** writes the records to a temporary file beside `<file>` and gives it that name only when the run completes, so a run cut short never leaves a partial file under that name; a run stopped by TERM, INT or HUP removes its temporary file (a signal the caller ignores stays ignored). `<file>` must be a new `.jsonl`, `.tsv` or `.txt` name directly in the run directory: an output never replaces a file, an input corpus least of all. A `>` into a new name in `incident_<n>/` keeps an output too, but gives a partial file to a run cut short.
- **Exit:** 0 done · 1 a file that cannot be read, or an `--out` that cannot be written, checked before any record is printed · 2 usage error, or a path the input contract refuses, as for `profile.sh`.
- **Network:** none. **Writes:** stdout, or the `--out` file.

#### `deltas.py`

```bash
"<auditor-skill root>/scripts/dnr/deltas.py" lamports|tokens [--by account|owner,mint|mint] [--out <file>] [<corpus.jsonl> ...]    # reads stdin when no file is named
```

Balance movements of successful transactions, computed in Python integers so that amounts above 2^53 stay exact.

- `lamports` prints `signature`, `account`, `delta` for each non-zero lamport change, with the fee added back for the fee payer.
- `tokens` prints one row per token account: `signature`, `owner` (`?` when the corpus names none), `mint`, `delta` in raw units, and the token account.
- `--by` prints exact sums in place of the rows, the most negative first, then by name; a sum of 0 prints no row. `lamports --by account`: `account`, its net. `tokens --by owner,mint`: `owner`, `mint`, the net, and a fourth column, empty unless the corpus names no owner: such balances are summed per token account, which it names. `tokens --by mint`: `mint`, the sum of the owners' negative nets and how many owners had one, then the sum of the positive nets and how many. These are the blast-radius figures: an owner's net movement per mint, and a mint's total loss and number of losers.
- A balance whose index has no account key is printed as `#<index>`. A token balance with no `accountIndex` has nothing to pair its pre and post sides by, so each side is a row of its own, `#?`. A note on stderr counts each kind; neither is ever merged with another account. Such a name stands for an account only within its own transaction, so no `--by` sum holds a lamport row so named, nor a token row with no owner either; a note counts them.

The output is TSV on stdout; tabs, newlines, carriage returns and backslashes inside a field are escaped, and so is every other character of the input contract's fixed list (control characters, line and paragraph separators, bidirectional controls, and the code points Unicode marks default-ignorable, zero-width characters among them; `scripts/dnr/README.md`). Several corpora count each signature once. An amount or balance that is not an exact integer (a float, `1_000`, a non-ASCII digit) makes its line malformed under the shared input contract: the line is skipped and counted, never rounded. Skipped copies, and each input's malformed lines, are reported on stderr; the malformed lines are collection gaps.

- **Arguments:** the mode, then `--by <grouping>` and `--out <file>` (written as `frames.py` writes it), each at most once, then corpus files or none; each named file is checked as for `profile.sh`.
- **Exit:** 0 done · 2 a missing or unknown mode, a grouping the mode does not take, or a path the input contract refuses, as for `profile.sh` · 1 a file that cannot be read, or an `--out` that cannot be written, checked before any row is printed.
- **Network:** none. **Writes:** stdout, or the `--out` file.

#### `redact.sh`

```bash
set -o pipefail; some-command 2>&1 | bash "<auditor-skill root>/scripts/dnr/redact.sh"    # pipefail keeps the command's exit status
```

A filter from stdin to stdout that removes provider credentials. In a URL of any scheme it keeps the scheme and the host's last two DNS labels (`REDACTED.provider.example`; an IP address or a two-label host stays whole), replaces userinfo with `REDACTED@` and replaces the path and query with `/REDACTED`. On curl's own error and verbose lines it shortens bare host names the same way and redacts the request path. A bare `api-key=`, `token=`, `secret=`, `auth=` or `access-token=` value outside a URL is redacted too. It is a convenience, not a guarantee: no RPC URL goes into a ledger, `INCIDENTS.json` or a report in any case. Record the provider's domain, as `collect.sh` prints it, and the literal string `$RPC_URL` instead.

- **Arguments:** none. **Exit:** 0. **Network:** none.

#### `jq-ro.sh`

```bash
"<auditor-skill root>/scripts/dnr/jq-ro.sh" -c 'select(.slot > 301) | .transaction.signatures[0]' incident_<n>/corpus/transactions.jsonl
```

`jq` over files inside a run directory, with nothing else to read. The `auditor:dnr-analyze` fork pre-approves it in place of `jq`, which can print the environment. It runs `jq` as `env -i HOME=/nonexistent PATH=/usr/bin:/bin`, so `$ENV` and `env` hold those two values and no `~/.jq` loads, and it prints every control character but tab and newline as `?`.

- **Arguments:** `-c`, `-r`, `-s`, `-e` and `-n`, each its own word; `--arg <name> <value>` and `--argjson <name> <json>`, each name bound once; then the filter and one or more inputs. Every other option is refused, `--rawfile`, `--slurpfile`, `-f`/`--from-file` and `-L` among them, and so is a filter that holds `import`, `include` or `modulemeta`. Each input is a relative path to a regular file with one link inside `audit_<n>/` or `incident_<n>/`, with no `.`, `..` or symbolic link on the way. Standard input is never read.
- **Exit:** jq's own status, or 2 when it refuses, with one stderr line, `jq-ro: refused: <reason>`. **Network:** none.
- **Pre-approval:** Claude Code asks about a line that holds a `$`, inside quotes too, so write values into the filter as literals rather than as `--arg` variables.

### Threat-model collector

#### `threat-model/collect.sh`

```bash
"<auditor-skill root>/scripts/threat-model/collect.sh" --detect --repo <dir> --out audit_<n>/bootstrap [--pin <rev>]
"<auditor-skill root>/scripts/threat-model/collect.sh" --offline --repo <dir> --out audit_<n>/bootstrap [options]
"<auditor-skill root>/scripts/threat-model/collect.sh" --network --repo <dir> --out audit_<n>/bootstrap [options]
```

The read-only collector behind `/auditor:threat-model --bootstrap` ([method and output contract](../references/audit-lifecycle/threat-model-bootstrap.md)). It gathers commits whose message matches security keywords, reverts, account-guard lines that were removed or quietly added, churn, an optional fork-parent comparison, provenance signals, prior-vulnerability inputs and the `audit-mem` warm block. It never checks out, builds, runs or modifies the target, and it runs git with the Rule 11c hardening (the hardened call in `scripts/lib/confine.sh`: no environment of the caller's, system and global config dropped, no pager, fsmonitor, hooks, signature helpers, textconv, external diff or transport). Run it directly by its path, from the working directory.

The mode is the first argument; a mode anywhere else, as in the older `--repo … --out … --offline`, is refused:

| Mode | Meaning |
|------|---------|
| `--detect` | evaluate triggers T3 and T4 only, print them and exit; writes nothing |
| `--offline` | collect without the network: `--parent` and `--vulns` URLs are recorded, not fetched |
| `--network` | collect, fetching the `https://` URLs given in `--parent` and `--vulns`; the only mode that reads a `--repo`, `--parent` or `--vulns` outside the working directory or through a symbolic link |

In `--detect` and `--offline`, `--repo` and a local `--parent` or `--vulns` are relative to the working directory, with no `.` or `..` component, and reach nothing through a symbolic link; a repository there must keep its git directory inside the working directory, with no link in it and no `objects/info/alternates` or `info/grafts`. A path that fails is refused with a pointer to `--network`.

| Flag | Meaning |
|------|---------|
| `--repo <dir>` | the target (required): the top level of its own repository, or a bare repository. Anything else, a partial clone, or a target whose config git cannot read exits 3 |
| `--out audit_<n>/bootstrap` | the output directory (required), in the run directory `audit_<n>` directly in the working directory: a real directory holding no symbolic link, untracked in any letter case, with a `.gitignore` holding exactly `*` (`rundir.sh new audit` makes one). `bootstrap/` is made when missing. Any other `--out`, or a run directory that fails these checks or that git or find cannot check, exits 2. `--detect` writes nothing, so its run directory need not exist yet |
| `--pin <rev>` | the commit to analyse (default `HEAD`); only its ancestry is mined. Exit 3 if it does not resolve; a value that starts with `-` exits 2 |
| `--paths <pathspec>` | target pathspec, repeatable (default `programs/*.rs` when the commit has a `programs/` directory, else `*.rs`) |
| `--parent <https-url\|dir>` | the fork parent: an `https://` URL, cloned bare into a temp directory that is deleted on exit (`--network` only), or the top level of a local repository. A local path that is not a top level, is a partial clone, or has a config git cannot read is recorded as not used, R5 prints `NOT FOUND`, and the run goes on |
| `--parent-paths <spec>` | parent pathspec, repeatable (default: the same rule, applied to the parent) |
| `--import <rev>` | the target commit that brought the parent's code in (default: the root commit). Pass it when the code arrived after the root commit (a README-only first commit, say), or R5 reports `NOT FOUND`. It must resolve to a commit, else the run exits 2 |
| `--vulns <file\|https-url>` | a prior-vulnerability input, repeatable: PDF, Markdown, text, CSV, JSON, or an `INCIDENTS.json` (allowlisted fields only) |
| `--program-id <id>` | the program id for R8's `audit-mem warm` (needs the built tool and `--audit-mem-db`); at most 200 characters |
| `--audit-mem-db <path>` | the audit-mem store R8 reads: `.audit-memory/audit.db` or `audit_<n>/audit-mem.db`, its `audit_<n>` passing the same checks as `--out`'s run directory, read from the working directory with `audit-mem warm`. There is no default: without it no store is read, and the collector never looks in the target tree. Pass only a store that passes the Rule 11d check |
| `--keywords <ere>` | extra commit-message keywords, as an ERE alternation such as `drain\|bypass`; at most 200 characters |
| `--cap <n>` | rows per section before `TRUNCATED` (default 60); re-run with a higher value when a section is truncated |
| `--small <n>` | changed-line ceiling for an `ADDED-QUIET` (quiet-fix) commit (default 40) |
| `--fix-ceiling <n>` | changed-line ceiling for the `ADDED` rows of a keyword commit (default 300) |
| `-h`, `--help` | print the usage header, flags and exit statuses included (as the only argument) |

Each option is given at most once, except the repeatable `--paths`, `--parent-paths` and `--vulns`; a word after an option that takes a value is that value. `--cap`, `--small` and `--fix-ceiling` take 0 to 10,000, and no value may hold a control character or exceed 1,024 bytes.

- **Exit:** 0 done (a section may print `NOT FOUND`) · 2 refused, with one line, `collect.sh: refused: <reason>`: a mode that is not first, an unknown or repeated option, a value out of bounds, a path the mode does not take, an `--import` that is not a commit, a run directory that fails the checks above or that git or find cannot check, a `TMPDIR` inside the working directory, a disclosure that cannot be recorded, or an output that cannot be written · 3 `--repo` is not the top level of a git repository git can read (or a bare repository), the pin does not resolve, the target is a partial clone (reading it could fetch from its promisor remote), or git cannot read its config.
- **Network:** only in `--network`, for an `https://` URL passed in `--parent` (a bare clone without submodules, credential helpers or other protocols) or in `--vulns` (curl, https only through redirects too, with 60-second and 50 MB limits). Each URL is first recorded as a row of `audit_<n>/disclosures.tsv`, with userinfo, query string and fragment shown as `***`. Never for a URL found in target content. Every git call runs with lazy fetching off and `protocol.allow=never`, the parent's https clone allowing https for that call only, so no remote the target configures is contacted. URLs in `history.md`, `inputs.tsv` and stderr show userinfo, query string and fragment as `***`.
- **Writes:** the output is built in a temporary directory outside the working directory and copied into `<out>` at the end, once the run directory is checked again; every file is created anew and written through the descriptor opened at creation. A re-run first removes the outputs of the run before (`history.md`, `inputs.tsv`, `audit-mem-warm.json`, and `inputs/` and `diffs/` where an `inputs.tsv` marks them). In `<out>`:
  - `history.md`: sections R0 to R8; a "Shallow clone" line when the target is shallow; and which git settings are pinned.
  - `inputs.tsv`: the manifest of every input.
  - `inputs/`: converted or copied inputs.
  - `diffs/`: `target-<sha>.diff` and `parent-<sha>.diff` for up to 20 flagged commits each. Each holds the full id, the date, the subject and up to 20 body lines, then the diff limited to the files its rows name, up to 400 lines. Every cut ends in a `TRUNCATED (…)` line naming `git-ro.sh`'s `show` for the rest: `"<auditor-skill root>/scripts/git-ro.sh" --repo '<dir>' show <full id> -- '<path>' …`, run from the working directory, with `--repo` naming the repository there (none for `.`), each path escaped like other target text and single-quoted (`--no-patch` and no path for a cut message). A repository read in `--network` from outside the working directory is read from a copy made inside it.
  - With `--program-id` and `--audit-mem-db`, `audit-mem-warm.json`.
  - Target text in `history.md` and `inputs.tsv` shows TAB, LF and CR as `\t`, `\n` and `\r`, and other control characters as `?`. Values over 500 characters are cut with `...`.
  - An `incident_*/INCIDENTS.json` that is a symbolic link, sits in a linked directory, or lies in a tracked `incident_*` directory is not read; `inputs.tsv` records it as skipped. No symbolic link in the target's tree is followed, so what one points at is never tested: T4 counts nothing through one, and R6 and `inputs.tsv` name one as a link, not followed. In `--network`, neither is a local `--vulns` path that is a symbolic link or that reaches its file through a directory link inside the target tree. An `incidents` value that is not an array gives an empty extract and a "malformed" status.
  - `--detect` prints `T3 yes|no <signals>` and `T4 yes|no <signals>` to stdout.
- **Needs:** git; `jq` or `python3` for JSON inputs, `pdftotext` to convert PDFs, `curl` for `--vulns` URLs. The environment variable `TM_JSON_TOOL=jq|python3|none` pins the JSON tool; the self-test uses it.

### RPC reads

#### `rpc-read.sh`

```bash
"<auditor-skill root>/scripts/rpc-read.sh" account <address> [--run <R>] [--cluster mainnet-beta|devnet|testnet]
"<auditor-skill root>/scripts/rpc-read.sh" confirm <signature> [--run <R>] [--cluster mainnet-beta|devnet|testnet]
"<auditor-skill root>/scripts/rpc-read.sh" program-show <program_id> [--run <R>] [--cluster mainnet-beta|devnet|testnet]
```

One read-only read from the chain through the `solana` CLI: an account's current value (`getAccountInfo`), one transaction, or a program's metadata such as its upgrade authority. The CLI runs on a throwaway config in a private temp directory, the endpoint in its `json_rpc_url` and a keypair path that names no file, and the read runs only when `solana config get keypair` reports that path back. Run it directly by its path, from the working directory.

- **Endpoint:** `$RPC_URL` from the environment, never an argument; with `--cluster`, one of the public endpoints fixed in the script: `https://api.mainnet-beta.solana.com`, `https://api.devnet.solana.com` or `https://api.testnet.solana.com`.
- **Reads:** `account` runs `solana account <address> --lamports --output-file <temp file>` and prints the address, balance in lamports, owner, executable flag and rent epoch, then the data's length and sha256; the data itself is never printed. `confirm` runs `solana confirm -v <signature>` and drops the CLI's first lines, which name the endpoint and the keypair path. `program-show` runs `solana program show <id>`, or `program-v4 show` for a loader-v4 program, each with a fixed authority so the CLI never looks for a signer, and the output must name the id as its Program Id. The CLI's output and errors pass through `redact.sh`, since its text can name the endpoint, key included. Every control character in what is printed shows as `?`, except TAB and LF.
- **Arguments:** an address or program id is base58 that decodes to 32 bytes, a signature to 64, so none can name a keypair file, a path or an option. `--run <R>` is a run directory, `audit_<n>` or `incident_<n>`, checked as `rundir.sh check` checks one. Each option is given at most once.
- **Exit:** 0 done · 1 the CLI ran and the read failed (its error, through `redact.sh`, on stderr) · 3 a blocker: no `solana` CLI or `python3`, no private temp directory or a `TMPDIR` inside the working directory, the CLI did not take the config, a disclosure row or a kept file that could not be written, or show output naming another Program Id · 64 refused, with one line, `rpc-read: refused: <reason>`, before the CLI runs.
- **Network:** the read-only calls of that one CLI command, to the endpoint above.
- **Writes:** with `--run R`, one row of `R/disclosures.tsv` before the CLI contacts the endpoint (the domain and the id), and in `R/rpc/`, made when missing, what was printed as `<read>-<id>.txt` and an account's data as `account-<address>.data` (`<read>-<id>-2.txt` and so on once a name is taken), each file created anew. Without `--run` nothing is written, and stderr names the service and what it received, for the report's Rule 11b list.
- **Needs:** the `solana` CLI and `python3` (the id check and the hash, as `python3 -I`).

### Report PDF

#### `report-to-pdf.sh`

```bash
"<auditor-skill root>/scripts/report-to-pdf.sh" [audit_<n>/REPORT.md]
```

A best-effort PDF of a report; the Markdown stays the deliverable. The input is `audit_<n>/REPORT.md`, `audit_<n>/RE-AUDIT.md`, `audit_<n>/PR-REPORT.md` or `incident_<n>/INCIDENT_REPORT.md`, relative to the working directory, in a run directory that passes `rundir.sh check`, and a regular file with one link; with no argument it takes the newest `audit_*/REPORT.md`. The PDF is written beside it, `.md` swapped for `.pdf`. Run it directly by its path, from the working directory.

- **Rendering:** the report is copied into a private temp directory outside the working directory and rendered there with `pandoc --sandbox -f markdown-raw_tex-raw_attribute --lua-filter "<auditor-skill root>/scripts/pdf/no-remote.lua" --pdf-engine=<xelatex, lualatex or pdflatex, the first found> --pdf-engine-opt=-no-shell-escape`. `--sandbox` keeps pandoc from reading any file but its input and from fetching anything. The filter turns every image into its alt text, drops every raw block and raw inline, shows math as code, in the metadata too, and leaves every element its identifier and classes but no key=value attribute (the LaTeX writer passes some, such as a figure's `latex-placement`, to the engine as written), so no remote image is fetched and no text of the report reaches the TeX engine as TeX. Raw HTML is still parsed, so the report templates' HTML comments drop out instead of printing. The engine runs with kpathsea's paranoid `openin_any=p` and `openout_any=p` and with `shell_escape=f`; the caller's `TEXMFOUTPUT` is dropped, and pandoc sets its own temp directory. The PDF goes into a new file beside the report and is renamed into place; a PDF already there is replaced only when it is a regular file with one link.
- **Exit:** 0 rendered, or skipped with a message: no report, no pandoc, a pandoc older than 2.15 (no `--sandbox`), no engine, or a render that failed · 2 refused, with one line, `report-to-pdf: refused: <reason>`: another path, two arguments, a run directory that fails the checks, a report that is not a regular file with one link, a PDF in the way that is not one, or a `TMPDIR` inside the working directory.
- **Network:** none. **Writes:** the PDF beside the report.
- **Needs:** pandoc 2.15 or later and a TeX engine, both optional.

### Trail of Bits bump review

#### `tob-delta-review.sh`

```bash
bash "<auditor-skill root>/scripts/tob-delta-review.sh" [--fetch] <tob-clone> <old-sha> <new-sha>
```

The maintainer's report for moving the `vendor/trailofbits` pin ([CONTRIBUTING.md §5](../CONTRIBUTING.md#bumping-vendortrailofbits)). It prints markdown to stdout: the commit count and ancestry, plugins added or removed, load surfaces (nested `.claude/`, hooks, monitors, `bin/`, MCP and LSP servers, settings, `CLAUDE.md` / `AGENTS.md`, workflow scripts), plugin manifests and the ones that declare hooks, monitors or servers inline, skill and command counts per plugin, new executables, symbolic links and gitlinks, paths git still quotes, renamed files, hosts in added script, config and Markdown lines, remote-exec patterns in added lines with continuation lines joined (a download piped to or evaluated by a shell, an interpreter or PowerShell, such as `sh -c "$(curl …)"`, `<(curl …)` or `irm … | iex`; `npx --yes`, `bunx` and `dlx`; `pip`, `pipx`, `uv`, `uvx`, `npm`, `cargo` and `deno` installs from git or a URL; `go install …@latest`), files moved unchanged between ordinary paths with the hosts and remote-exec patterns in them (every other renamed file is scanned whole in the added-line scans), all matched in any letter case, the `LICENSE`, and whether every plugin that `references/orchestration/boundary-map.md` and this page name still exists. Every call sets colour, external diff, textconv, rename detection, path quoting and signature display on the command line, so the maintainer's own config does not change the report. The scans also diff with `--text` and, on git 2.40 or later, read attributes from the empty tree, so upstream's own `.gitattributes` cannot mark a changed file binary. The report informs a human reviewer; it is not a verdict.

- **Arguments:** `<tob-clone>` is a full, non-shallow clone of `https://github.com/trailofbits/skills` (a shallow one draws a warning); `<old-sha>` and `<new-sha>` are the current and proposed pins. `--fetch` runs `git fetch origin` in the clone first.
- **Exit:** 0 report printed · 2 usage error, a missing clone directory, a failed fetch, or a commit the clone does not have.
- **Network:** only with `--fetch`. **Writes:** nothing but a temp directory, removed on exit.
