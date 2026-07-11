# Orchestration — PoC Harness Selection & Evidence Tiers

> **Load when:** building an executable proof-of-concept or a fix patch — i.e. running `/auditor:poc` or `/auditor:patch`, choosing a harness framework for a confirmed finding, or recording a `[PoC-*]` / `[FIX-*]` evidence tier.

A PoC turns an **asserted** finding into a **demonstrated** one. It never invents a
finding — Rule 5b (`OUTPUT-RULES.md`) must already have confirmed the finding with a
filled Reachability + Math/State-Bounds block (Attacker-Model for N ≥ 7). This
reference decides *which* harness reproduces it and *what tier* the result earns.

**Templates:** the crate the `poc-engineer` fills lives at `templates/poc/`
(feature-gated `vulnerable`/`fixed` arms, `tests/exploit.rs` + `tests/fixed_blocked.rs`,
`shared-test-utils`, `run.sh`). The patch templates live at `templates/patch/`.

**One rule above all:** *executable evidence outranks prose, but prose is never
removed.* An unbuildable or un-forkable target still yields a complete finding — you
downgrade the **evidence tier**, never the **severity**. A named blocker with the
prose PoC intact is honest; a fabricated green test is not.

---

## 1. Toolchain gates (detect — never assume)

Probe what is actually installed before choosing a framework. A missing tool is a
*blocker to name in the report*, not a reason to skip the finding or fake a result.

| Gate | Detect | Enables | If absent |
|------|--------|---------|-----------|
| **`cargo build-sbf`** (platform-tools ≥ **v1.54** / cargo ≥ **1.85**) | `cargo build-sbf --version`; check the bundled cargo ≥ 1.85 (default bundle is v1.51/cargo 1.84 and **cannot** parse the edition2024 manifests in the modern `mollusk-svm`/`litesvm` dep tree — pass `--tools-version v1.54`) | Mollusk **and** LiteSVM PoCs (both load a compiled `.so`) | No on-chain executable PoC → `[PoC-ATTEMPTED]`, keep prose. Name it: "install Agave platform-tools ≥ v1.54". |
| **Surfpool** (CLI + MCP) | `surfpool --version` on PATH; the surfpool MCP reachable | mainnet-fork economic/oracle/MEV reproduction with a real P/L | No fork simulation → fall back to Mollusk/LiteSVM if the logic is modelable, else `[PoC-ATTEMPTED]`. Name it: "surfpool CLI + MCP unreachable / fork state unavailable". |
| **Trident** (stateful SVM fuzzer) | `trident --version` on PATH | coverage-guided multi-instruction fuzzing → crash/invariant artifact | Try `cargo fuzz` (below); if neither, keep the prose invariant argument → `[PoC-ATTEMPTED]`. |
| **cargo-fuzz** (libFuzzer unit fuzz) | `cargo fuzz --version` on PATH | fuzzing a single pure function (parse/deser/math) → crashing input | If absent, a hand-written failing unit test on the boundary value is the fallback; else `[PoC-ATTEMPTED]`. |

Record which gates passed in the finding's PoC block. `run.sh` in `templates/poc/`
self-detects `cargo-build-sbf` and exits `3` with a named blocker when it is missing —
mirror that discipline for the other tools.

---

## 2. Framework-selection matrix (finding type → harness)

Pick by what the bug actually *is*. The cheapest harness that faithfully reproduces
the flaw wins — do not reach for a mainnet fork when a single-instruction Mollusk test
proves it deterministically.

| Finding type | Harness | Why | Tier on success |
|--------------|---------|-----|-----------------|
| logic / access-control / **signer** / **owner** / **PDA** / **CPI-target** / arithmetic contained in **one instruction** | **Mollusk** (single `process_instruction`) | fastest, deterministic, in-process; one crafted ix against one `.so` | `[PoC-REPRODUCED]` |
| **multi-step lifecycle** — init → mutate → withdraw; **reinit**; **close → revival**; any bug living in cross-instruction state | **LiteSVM** stateful sequence | replays an ordered instruction sequence and carries state between them, which a single-ix runner cannot | `[PoC-REPRODUCED]` |
| **economic / oracle / MEV / first-depositor** — value depends on live pool/oracle state or ordering | **Surfpool mainnet-fork** | reproduce deposit → manipulate → withdraw against forked real state for a concrete net **P/L** figure | `[PoC-SIM-REPRODUCED]` |
| **parse / deser / math** that is **fuzz-discoverable** (the crashing input is not obvious) | **Trident stateful** (default) or **cargo-fuzz unit** (pure function) | let the fuzzer *find* the input; emit the crashing artifact as the proof | `[PoC-FUZZ-REPRODUCED]` |
| **off-chain** TS/Rust client, indexer, keeper, backend | **cargo-fuzz** / **vitest** / **proptest** on the off-chain code | the bug is not on-chain; prove it where it lives | `[PoC-FUZZ-REPRODUCED]` (fuzz) or `[PoC-REPRODUCED]` (deterministic test) |

Escalation discipline (from `boundary-map.md` §"FV / harness delegation gates"): a
**stateful Trident sequence is the primary bug-finder** for non-trivial programs —
proptest-on-pure-functions is a cheap first probe, not the destination. Do **not**
escalate to deductive FV (Certora/Kani) for a property a stateful fuzzer surfaces in
minutes, and **skip FV entirely when the instruction's outcome is decided by a CPI
into untrusted/foreign code** — mock that boundary adversarially in Trident instead
and note the abstention in the report's Assumptions & Simplifications.

---

## 3. Evidence-tier fallback ladder

Award the **highest tier the available tooling actually reached**, then stop. Each
rung down is a real, reportable finding — the ladder degrades gracefully to prose.

```
[PoC-REPRODUCED]       Mollusk (or LiteSVM) executed the exploit: it SUCCEEDS on the
   (strongest)         vulnerable arm and is REJECTED on the fixed arm. Deterministic.
        │
[PoC-SIM-REPRODUCED]   Reproduced on a Surfpool mainnet-fork with a recorded net P/L
        │              (economic / oracle / MEV — value needs live forked state).
        │
[PoC-FUZZ-REPRODUCED]  A Trident / cargo-fuzz target produced the crashing or
        │              invariant-breaking input; the corpus/crash artifact is saved.
        │
[PoC-ATTEMPTED]        A required tool was absent (no cargo build-sbf, surfpool
        │              unreachable, fork state unavailable) OR the flaw could not be
        │              minimized into a self-contained crate. Name the exact blocker,
        │              KEEP the prose PoC, record what a maintainer must install/provide.
        │
[PoC-PROSE]            No executable attempt applicable/possible; the structured
   (weakest, still      attacker-narrative PoC (actor → capability → steps → guard
    a valid finding)    bypassed → quantified outcome) stands on its own. A prose PoC
                        is a first-class Rule 5b proof form.
```

**Never fabricate a passing test to climb the ladder.** An asserted-only-in-prose
finding recorded as `[PoC-PROSE]`/`[PoC-ATTEMPTED]` is honest; a faked green test is
not. Downgrading the tier never downgrades the finding's severity or removes its prose.

---

## 4. Fix tiers (the patch side)

After a PoC exists, `/auditor:patch` proposes a minimal idiomatic diff and proves it by
re-running that PoC. The verdict maps to the report's **Auditor Verification** field
(templates: `templates/patch/patch.md` + `VERIFICATION.md`).

```
[FIX-VERIFIED]      Diff applied to a SCRATCH worktree, rebuilt, and the finding's PoC
   (strongest)      re-ran and now REVERTS — closure shown by execution. Optional
        │           mewt-mutation / blast-radius clean.
        │
[FIX-INSUFFICIENT]  The diff does not fully close the bound: the PoC still exploits a
        │           residual path, a mutant survives on the patched line, or an
        │           adjacent path regressed (blast-radius). State what remains open.
        │
[FIX-PROPOSED]      A minimal idiomatic diff re-derived from the code closes the cited
   (weakest)        bound, but NO executable PoC was available to run the revert.
                    Verified by reasoning, flagged not-yet-executed — never silently
                    promoted to [FIX-VERIFIED].
```

A cosmetic patch ≠ FIXED. `[FIX-VERIFIED]` requires an *executed* revert of the
finding's own exploit — a diff that merely reads plausibly is `[FIX-PROPOSED]` at most.
The patch is a **proposal**: the auditor stays read-only on the client tree and hands
back the diff plus this verification record for the client to apply and re-test.

---

## 5. Where this sits in the flow

1. Rule 5b confirms the finding (`OUTPUT-RULES.md`).
2. `/auditor:poc` → detect gates (§1) → pick framework (§2) → `poc-engineer` fills
   `templates/poc/` → `run.sh` → award the highest tier reached (§3).
3. `/auditor:patch` → `patch-engineer` writes `templates/patch/` diff → apply to a
   scratch worktree → re-run the PoC → award a fix tier (§4).
4. `audit-cycle` / `re-audit` fold both tiers back into the finding block; the report's
   **Auditor Verification** line carries the fix verdict.

Build/toolchain failures that block any of this are troubleshooting, not findings —
resolve via `references/framework-idioms/build-and-tooling.md` (GLIBC floors, the
`edition2024` / platform-tools pin, the LiteSVM → bankrun/Mollusk GLIBC fallback).
