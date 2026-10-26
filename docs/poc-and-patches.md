# PoC & Patch Delivery

How auditor-skill turns a confirmed finding into an executable exploit and a verified fix patch. Back to the [docs index](README.md).

A finding is *asserted* by the Rule 5b gate (reachability + math/state-bounds, + attacker-model at ≥7). A **PoC** upgrades it to *demonstrated*; a **patch** proposes and proves the fix. Neither invents a finding — Rule 5b must have confirmed it first. Commands: [`/auditor:poc`](commands.md#auditorpoc), [`/auditor:patch`](commands.md#auditorpatch). Agents: [poc-engineer, patch-engineer](agents.md#poc-engineer). Reference: [`references/orchestration/poc-harness.md`](../references/orchestration/poc-harness.md).

## The one rule

> **Executable evidence outranks prose, but prose is never removed.**

An unbuildable or un-forkable target still yields a complete finding — you downgrade the **evidence tier**, never the **severity**. A named blocker with the prose PoC intact is honest; a fabricated green test is not. This principle governs every tier below.

## Output layout

```
audit_<n>/
├── poc/
│   └── F-003/                    ← one directory per finding
│       ├── Cargo.toml            (feature-gated: vulnerable / fixed arms)
│       ├── src/
│       │   ├── lib.rs
│       │   ├── vulnerable.rs     the code at the audited commit
│       │   └── fixed.rs          the guard/bound the finding says is missing
│       ├── tests/
│       │   ├── exploit.rs        asserts the exploit SUCCEEDS on `vulnerable` and leaves its effect
│       │   └── fixed_blocked.rs  asserts the same attack is REJECTED on `fixed` with the guard's error
│       ├── shared-test-utils/    assert_exploit_effect! / assert_exploit_rejected_with! / assert_exploit_blocked!
│       ├── Cargo.lock            the template's pins, plus any pin --update-pins moved
│       ├── harness-repair.diff   the repair pass's diff, when a harness error needed one
│       └── run.sh                the installation's copy, for ./run.sh; run.sh --crate runs the installation's own
└── patches/
    ├── F-003.patch               minimal idiomatic unified diff vs the pinned commit
    └── VERIFICATION.md           the executed-revert record + fix tier
```

The crate the `poc-engineer` fills is copied from `<auditor-skill root>/templates/poc/`, the patch templates from `<auditor-skill root>/templates/patch/` — the installation's copies, never a `templates/` path relative to the audited repo ([Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)). `run.sh` builds each arm to SBF and runs its test (both arms compile to the same `.so`, so they can't coexist — it builds, tests, overwrites), and exits non-zero if the exploit doesn't reproduce on `vulnerable` or isn't blocked on `fixed`. The crate is made with `"<auditor-skill root>/templates/poc/run.sh" --init <R>/poc/<ID>` and run with `"<auditor-skill root>/templates/poc/run.sh" --crate <R>/poc/<ID>`, the installation's copy, run by its quoted path from the working directory. Building the crate runs code — dependency build scripts and proc-macros, then the tests — so every run needs the run's recorded mode ([Rule 11a](../OUTPUT-RULES.md#rule-11-operating-safety)): `run.sh --crate` takes the stricter of `AUDITOR_EXEC_MODE` and the `exec-mode` of every run directory its arguments name, and a copy run as `./run.sh` reads `AUDITOR_EXEC_MODE` and its own `<R>/exec-mode`. Without one `run.sh` exits 3 → `[PoC-ATTEMPTED]` before it compiles anything. The agent writes `<R>/exec-mode`, so if you chose isolated, also set `AUDITOR_EXEC_MODE=isolated` in the environment Claude Code runs in. In isolated mode `run.sh` first checks that no credential is readable on this machine, and every cargo call and test binary runs in a cleaned environment with a throwaway `HOME` and Solana keypair, every build and test offline after the downloads. An incident's crate runs only once `INCIDENTS.json` records its `root_cause_class`, and a `supply_chain_or_ci` incident only in isolated mode on its dumped bytes. It never builds inside the audited repo: it copies the crate to a scratch directory outside the target tree (the path is printed) and builds it with the toolchain pinned, so the target's `.cargo/config*` and `rust-toolchain*` never apply. It refuses a crate holding a symbolic link, a `.cargo/` directory or a `rust-toolchain*` file, and a `path` dependency on target crates must be absolute. The crate keeps to framework crates by default: one copied from the target's manifest runs its build script in the recorded mode, so the PoC adds it only when it needs it. The crate is built and tested only through `run.sh`, which also refuses the crate's own build-time code before anything compiles (a build script, a proc-macro package, a `Cargo.toml` inside the crate that is not a member of its workspace, a `[patch]` or `[replace]` table; a `path` dependency outside the crate is not refused, its build script runs in the recorded mode, and the non-registry line names it) and names the non-registry code it built (the path and git dependencies in `Cargo.lock`, and any source compiled from outside the crate) before its final line. The template ships a `Cargo.lock`: an unmodified template resolves to it, and a PoC that adds crates keeps every pin it does not need to move (`--update-pins "<crate>@<pinned version>"` moves one, in the scratch copy). To reuse compiled dependencies between runs, the engagement gets one cache directory, made with `run.sh --new-cache` (inside the isolated runner in isolated mode) and recorded next to the execution mode; every run gets it as `--cache <dir>` (`run.sh` locks it around each arm, so PoC crates of the same name never hand each other a build), and it is deleted when the engagement ends. `run.sh --crate` reads neither `CARGO_TARGET_DIR` nor `CARGO_BUILD_TARGET_DIR`; for a `./run.sh` run, neither may point inside the target tree or at a directory the agent did not create. A Trident or cargo-fuzz target or a Surfpool scenario has no template: `poc-engineer` writes its runner, which starts with `run.sh`'s mode gate, verbatim, and builds from a scratch copy outside the target tree in the same way ([`poc-harness.md`](../references/orchestration/poc-harness.md) §1). Such a runner is not pre-approved: it asks before it runs, and a non-interactive run denies it.

In either mode an arm counts only when a contract assertion of that arm ran and held on the bytes `run.sh` placed: each assertion runs the attack itself and leaves markers tagged with its test, the runner helpers (`mollusk_for`, `litesvm_for!`) record the hash of every program they load, and a passing test without its marker, one that loaded other bytes, or one whose attack targeted another program, exits 3. A failed test is a verdict only when an assertion of that arm ran and did not hold, whatever another test left: one that failed before any assertion ran, ended mid-assertion, or hit a harness error (a wrong program id, a short account list) on either arm, exits 3 as inconclusive. Every exit 3 is recorded with `run.sh`'s blocker line and "PoC re-run needed"; a harness error first gets one repair pass on the harness setup, never on the assertions or the target. On prebuilt bytes (`--vulnerable-so`, plus `--fixed-so` for the fixed arm, each a file under a run directory's `bin/` or `exec/`) success ends with `OK: reproduced on prebuilt bytes — vulnerable sha256=<…> … → [PoC-REPRODUCED]`, the only line that satisfies Leg 3 of an incident; a LiteSVM PoC reaches it too, and a model built from the crate's own arms never does. Before trusting an `OK` line, the commands compare the crate's `shared-test-utils/` with the installation's (and its `run.sh`, for a `./run.sh` run), and every re-run first refreshes `shared-test-utils/src/`. The markers are a floor, not proof: the assertion is still read.

## `--with-poc` vs on-demand

- **On demand:** run `/auditor:poc <finding-id>` then `/auditor:patch <finding-id>` for a specific finding. Default runs produce PoCs only this way, so baseline audit cost is unchanged.
- **`/auditor:audit-cycle --with-poc`:** after reconciliation, the flow spawns `poc-engineer` on every confirmed **N≥7** finding → `audit_<n>/poc/F-xxx/`, then `patch-engineer` → `audit_<n>/patches/F-xxx.patch` + `VERIFICATION.md`, recording both tiers in the report's finding block.

By default only **High/Critical (N≥7)** findings earn an executable PoC (a runnable exploit is the Rule 5b proof those severities want; spending the harness budget on low-severity items is waste). `--force` overrides the gate. A finding still at `[UNCONFIRMED]`/`[PARTIAL]` is **not** eligible — confirm it through Rule 5b first.

## Framework selection

`/auditor:poc` detects the toolchain (never assumes), then picks the cheapest harness that faithfully reproduces the bug.

| Finding type | Harness | Success tier |
|--------------|---------|--------------|
| logic / access-control / signer / owner / PDA / CPI-target / arithmetic in **one instruction** | **Mollusk** (single `process_instruction`) — fastest, deterministic, in-process | `[PoC-REPRODUCED]` |
| **multi-step lifecycle** — init → mutate → withdraw; reinit; close → revival; cross-instruction state | **LiteSVM** stateful sequence | `[PoC-REPRODUCED]` |
| **economic / oracle / MEV / first-depositor** — value depends on live pool/oracle state or ordering | **Surfpool mainnet-fork** (`--fork`) — deposit→manipulate→withdraw for a real P/L | `[PoC-SIM-REPRODUCED]` |
| **parse / deser / math** that is fuzz-discoverable | **Trident** stateful (default) or **cargo-fuzz** unit (`--fuzz`) — let the fuzzer find the input | `[PoC-FUZZ-REPRODUCED]` |
| **off-chain** TS/Rust client, indexer, keeper, backend | cargo-fuzz / vitest / proptest on the off-chain code | `[PoC-FUZZ-REPRODUCED]` or `[PoC-REPRODUCED]` |

`--fork` / `--fuzz` force the Surfpool / fuzz path when the finding type is ambiguous. Escalation discipline: a stateful Trident sequence is the primary bug-finder for non-trivial programs — proptest-on-pure-functions is a cheap first probe, not the destination; and skip FV entirely when the outcome is decided by a CPI into untrusted code (mock that boundary adversarially in Trident instead).

## Toolchain requirements

| Gate | Detect | Enables | If absent |
|------|--------|---------|-----------|
| **`cargo build-sbf`** — platform-tools **≥ v1.54** / cargo ≥ 1.85 | `cargo build-sbf --version` | Mollusk **and** LiteSVM (both load a compiled `.so`) | `[PoC-ATTEMPTED]`, keep prose. "install Agave platform-tools ≥ v1.54" |
| **Surfpool** (CLI + MCP) | `surfpool --version`; MCP reachable | mainnet-fork economic/oracle/MEV with a real P/L | fall back to Mollusk/LiteSVM if modelable, else `[PoC-ATTEMPTED]` |
| **Trident** | `trident --version` | coverage-guided multi-instruction fuzzing | try `cargo fuzz`; else prose → `[PoC-ATTEMPTED]` |
| **cargo-fuzz** | `cargo fuzz --version` | fuzz a single pure function | hand-written failing unit test on the boundary; else `[PoC-ATTEMPTED]` |

> The default `cargo-build-sbf` bundle is platform-tools **v1.51 / cargo 1.84**, which **cannot** parse the `edition2024` manifests in the modern `mollusk-svm`/`litesvm` dep tree. `run.sh` pins `--tools-version v1.54` (cargo ≥ 1.85) to build the graph with no dependency edits; override via `TOOLS_VERSION=...`. Build/toolchain failures are troubleshooting, not findings — resolve via [`references/framework-idioms/build-and-tooling.md`](../references/framework-idioms/build-and-tooling.md). `"<auditor-skill root>/scripts/runner/probe.sh"` runs these probes from a directory outside the target tree: inside it, the target's `.cargo/config*` can alias `build-sbf` to its own code and its `rust-toolchain*` can swap in its own `cargo`.

## Evidence tiers (PoC)

Award the **highest tier the available tooling actually reached**, then stop. Each rung is a real, reportable finding; the ladder degrades gracefully to prose.

| Tier | Meaning |
|------|---------|
| `[PoC-REPRODUCED]` | Mollusk/LiteSVM executed the exploit: **succeeds on `vulnerable`, rejected on `fixed`**. Deterministic. Gold standard. |
| `[PoC-SIM-REPRODUCED]` | Reproduced on a Surfpool mainnet-fork with a recorded net **P/L** (economic/oracle/MEV). |
| `[PoC-FUZZ-REPRODUCED]` | A Trident/cargo-fuzz target produced the crashing/invariant-breaking input; the corpus/crash artifact is saved. |
| `[PoC-ATTEMPTED]` | A required tool was absent, the recorded execution mode couldn't run it, `run.sh` exited 3 (recorded with its blocker line and "PoC re-run needed"; a harness error after one repair pass), or the flaw couldn't be minimized into a standalone crate. Name the exact blocker, **keep the prose PoC**, record what a maintainer must install. Severity unchanged. |
| `[PoC-PROSE]` | Structured attacker-narrative only (actor → capability → numbered steps → guard bypassed → quantified outcome). The accepted default for access-control/logic findings — a first-class Rule 5b proof form. |

The exploit test must **assert** the vulnerability (`assert_exploit_effect!` on `vulnerable`: the concrete value the attack leaves in the account it targets; `assert_exploit_rejected_with!` on `fixed`: the guard's exact error, never a pattern; `assert_exploit_blocked!`, with its positive control, only to check a fix the team deployed) — a test that compiles and runs but doesn't assert the flaw is not a PoC. **Never fabricate a passing test to climb the ladder.**

## Fix tiers (patch)

After a PoC exists, `/auditor:patch` proposes a minimal idiomatic diff against the pinned commit that closes *exactly* the cited bound — no refactor, no drive-by cleanup — obeying the Rust/Anchor/Pinocchio rules (checked arithmetic, stored canonical bumps, `transfer_checked` not `transfer`, no `unwrap()`/`expect()` in program code, validated CPI targets). It builds the program as it is and with the diff applied, with `target.sh build-sbf` in a scratch clone outside the tree (never the client tree), and re-runs the finding's PoC against those builds.

| Tier | Meaning |
|------|---------|
| `[FIX-VERIFIED]` | Diff applied to a scratch worktree, rebuilt, and the finding's PoC **re-ran and now reverts** — closure shown by execution. Optional `mewt` mutation / blast-radius clean. |
| `[FIX-INSUFFICIENT]` | The diff doesn't fully close the bound: the PoC still exploits a residual path, a mutant survives on the patched line, or an adjacent path regressed. State exactly what remains open. |
| `[FIX-PROPOSED]` | A minimal idiomatic diff re-derived from the code closes the cited bound, but **no executable PoC was available** to run the revert. Verified by reasoning, flagged not-yet-executed. |

The patch is a **proposal, not an application** — the auditor stays read-only on the client's real tree and hands back the diff + `VERIFICATION.md`. **A cosmetic patch ≠ FIXED:** never claim `[FIX-VERIFIED]` without an *executed* revert of the finding's own exploit. `--verify-with-mutation` runs `mewt` mutation on the patched line (a surviving mutant means the guard is under-tested) plus a `differential-review` blast-radius check (a fix that breaks an adjacent instruction is `[FIX-INSUFFICIENT]`). Opt-in Trail of Bits `post-patch-validation` (`/auditor:patch --post-patch-validation`, isolated mode only, on a disposable clone) is optional evidence that can only lower a tier: a finding in its result turns `[FIX-VERIFIED]` into `[FIX-INSUFFICIENT]`, with that check as the reason; a `[FIX-PROPOSED]` or `[FIX-INSUFFICIENT]` patch keeps its tier and records the finding under Residual, and nothing else in its result changes a tier. The fix tier feeds the report's **Auditor Verification** field.

## Where it sits in the flow

1. Rule 5b confirms the finding ([output-and-rigor.md](output-and-rigor.md#the-rule-5b-validation-gate)).
2. `/auditor:poc` → detect gates → pick framework → `poc-engineer` fills a copy of `<auditor-skill root>/templates/poc/` (`run.sh --init`) → `run.sh --crate` → award the highest tier reached.
3. `/auditor:patch` → `patch-engineer` writes the `templates/patch/` diff → `target.sh build-sbf` builds the program as it is and patched, in a scratch clone → re-run the PoC → award a fix tier.
4. `/auditor:audit-cycle` / `/auditor:re-audit` fold both tiers back into the finding block; the report's **Auditor Verification** line carries the fix verdict, and `RE-AUDIT.md` records each finding's step-4b PoC re-run (`<auditor-skill root>/templates/re-audit.md`).
