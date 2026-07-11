---
name: auditor:poc
description: Generate an executable proof-of-concept exploit for a confirmed High/Critical finding — detect the toolchain, pick the harness framework by finding type, spawn poc-engineer, and emit a one-command runnable crate plus the earned [PoC-*] evidence tier. Never hard-fails: on toolchain absence it downgrades to [PoC-ATTEMPTED] and keeps the existing prose PoC.
argument-hint: "<finding-id | file:line> [--fork] [--fuzz] [--force]"
allowed-tools: Read, Grep, Glob, Bash, Task
---

# auditor-skill — Executable Proof-of-Concept

**Arguments:** $ARGUMENTS

Turn a *confirmed* finding into a runnable exploit. Read `OUTPUT-RULES.md` first (severity 1-10, the **Rule 5b** gate — the finding must already carry a filled Reachability + Math/State-Bounds block, Attacker-Model for N≥7) and `references/orchestration/poc-harness.md` (the finding-type → framework matrix and the `[PoC-*]` evidence tiers this command emits). A PoC is *evidence that upgrades an asserted finding to a demonstrated one* — it never invents a finding that Rule 5b did not already confirm.

## Steps

1. **Resolve the finding.** Locate the target: a finding id (`F-xxx`) resolved from the latest `audit_<n>/REPORT.md`, or a raw `file:line`. Read its full finding block **and** its context worksheet under `audit_<n>/worksheets/context/*` (the reconstructed instruction/state model the PoC will drive). Pin the audited commit the report names — the harness reproduces *that* commit, not `HEAD`.

2. **Severity gate.** By default only **High/Critical (N≥7)** findings earn an executable PoC — a runnable exploit is the Rule 5b PoC those severities demand, and spending the harness budget on low-severity items is waste. `--force` overrides the gate for a deliberately-requested lower-severity demonstration. A finding still at `[UNCONFIRMED]` / `[PARTIAL]` is **not** eligible — confirm it through Rule 5b first.

3. **Detect the toolchain (never assume).** Probe what is actually installed:
   - `cargo build-sbf --version` (SBF program build),
   - surfpool MCP reachable (mainnet-fork execution),
   - `trident --version` / `cargo fuzz --version` on PATH (coverage-guided fuzzing).
   Record which are present. A missing tool is a *blocker to name*, not a reason to fabricate.

4. **Pick the framework by finding type** (matrix in `references/orchestration/poc-harness.md`):
   - **logic / access-control / signer / owner / PDA / CPI** → **Mollusk** single-instruction harness (fastest, deterministic, one `process_instruction`).
   - **multi-step lifecycle** (init → mutate → withdraw, cross-instruction state) → **LiteSVM** stateful sequence.
   - **economic / oracle / MEV** → **Surfpool mainnet-fork** (`--fork`) — reproduce deposit→manipulate→withdraw against forked pool state for a real P/L figure.
   - **fuzz-discoverable parse / deser / math** → **Trident / cargo-fuzz** (`--fuzz`) — emit the fuzz target that finds the crashing input.
   `--fork` / `--fuzz` force the Surfpool / fuzz path respectively when the finding type is ambiguous.

5. **Spawn `poc-engineer`.** Hand it the finding block, the context worksheet, the pinned commit, the chosen framework, and the detected toolchain. It copies the matching crate from `templates/poc/` and fills it: a feature-gated `vulnerable` arm the exploit **succeeds** against and a `fixed` arm it is **rejected** against (`assert_exploit_succeeds!` / `assert_exploit_rejected!` from our `shared-test-utils`). The exploit test must **assert** the vulnerability, not merely run.

6. **Emit outputs** under `audit_<n>/poc/F-xxx/`:
   - the filled harness crate (from `templates/poc/`),
   - a one-command **`run.sh`** (`cargo test` / `trident fuzz` / the surfpool scenario) that reproduces the result from a clean checkout,
   - the earned **`[PoC-*]` evidence tier** recorded against the finding (see vocabulary below), which `audit-cycle` / `re-audit` fold back into the report's finding block.

## Evidence tiers (emit exactly one)

| Tier | Meaning |
|------|---------|
| `[PoC-REPRODUCED]` | The exploit ran and **asserted** the flaw — succeeds on the `vulnerable` arm, rejected on the `fixed` arm (Mollusk / LiteSVM). |
| `[PoC-SIM-REPRODUCED]` | Reproduced against a **Surfpool mainnet-fork** with a recorded net P/L (economic / oracle / MEV). |
| `[PoC-FUZZ-REPRODUCED]` | A **Trident / cargo-fuzz** target produced the crashing / invariant-breaking input; the corpus entry is saved. |
| `[PoC-ATTEMPTED]` | A required tool was absent (no `cargo build-sbf`, surfpool unreachable, fork state unavailable) **or** the flaw could not be minimized into a self-contained crate. Name the exact blocker, **keep the existing prose PoC**, and record what a maintainer must install/provide to promote it. |

## Never hard-fail

On any toolchain absence or minimization failure, emit `[PoC-ATTEMPTED]` with the named blocker and **preserve the finding's existing structured attacker-narrative PoC** — a prose PoC is a first-class Rule 5b proof form. Downgrading the evidence tier never downgrades the finding's severity. Do **not** fabricate a passing test to reach `[PoC-REPRODUCED]`; an asserted-only-in-prose finding is honest, a faked green test is not.
