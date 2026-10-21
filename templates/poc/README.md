# PoC — {FINDING_ID}: {ONE_LINE_TITLE}

Runnable proof-of-concept for finding **{FINDING_ID}** ({SEVERITY}, `{FILE}:{LINE}`),
pinned to audited commit `{COMMIT}`. One feature-gated crate: the exploit lands on
the `vulnerable` arm and is turned away on the `fixed` arm.

## Attack narrative

Fill every field. This is the prose the executable proves — it must map 1:1 onto
`tests/exploit.rs`. Vocabulary matches the Rule 5b **Attacker-Model** block in
`OUTPUT-RULES.md`, so it drops straight into the finding.

- **Actor:** {WHO — permissionless caller | one depositor | co-signer | compromised admin}
- **Capability / setup cost:** {what they start with — public keys only | one deposit | flash-loanable capital | ~$X + N accounts}
- **Guard bypassed:** {the single check that is missing or wrong — e.g. `is_signer` never verified on `authority` at `{FILE}:{LINE}`}

**Steps** (each maps to lines in `tests/exploit.rs`):

1. {e.g. attacker reads the public `authority` pubkey from the on-chain config}
2. {e.g. builds `update_authority` with that key supplied but UNSIGNED, self as the only signer}
3. {e.g. submits the tx — the program compares keys, skips `is_signer`, and accepts}
4. {e.g. config authority is now attacker-controlled}

- **Quantified outcome:** {the damage, with a number — "drains the full vault balance (up to u64 deposits)" | "mints unbacked tokens 1:1 with attacker capital" | "griefing: permanent DoS, no direct profit"}
- **Atomicity:** {single-tx | multi-tx | multi-slot}
- **Net:** {profitable | griefing-only | requires-privilege — privilege caps severity per Rule 1}

## Reproduce

```bash
./run.sh
```

Builds both arms with `cargo build-sbf` (platform-tools >= v1.54) and runs both
tests with `SBF_OUT_DIR` wired — never inside the audited repo. A self-contained
crate is copied to a scratch directory under `$TMPDIR` (printed; `KEEP_POC_BUILD=1`
keeps it) and built there with the toolchain pinned, so the target's
`.cargo/config*` and `rust-toolchain*` never apply. A crate that depends on target
crates builds in place only with `AUDITOR_EXEC_MODE=isolated|native`, the run's
recorded mode (`OUTPUT-RULES.md` Rule 11a). Exit `0` means the exploit reproduced on
`vulnerable` **and** was blocked on `fixed`; `1` / `2` mean the PoC is not valid —
see the failing arm's message; `3` is a named blocker (no SBF toolchain, bad
inputs, a build that failed, or no execution mode for a crate that needs one), and
the finding's prose PoC still stands.

**Dependencies — the framework allowlist.** `run.sh` reads the manifests with
`cargo metadata` and accepts only crates.io packages named `solana-*`, `anchor-*`,
`spl-*`, `mollusk-*`, `litesvm*`, `borsh*`, `bytemuck*`, `pinocchio*`, `sha2` or
`thiserror` (`_` counts as `-`), plus path dependencies inside this crate
(`shared-test-utils`). Any other dependency — a crate copied from the target's own
`Cargo.toml`, for instance — would run its build script and proc-macros on the
host, so it needs `AUDITOR_EXEC_MODE` like a target dependency, or `run.sh` exits
`3`. The list lives at the top of `run.sh`; it is a name check, not a review, so
read what the manifest pulls in all the same.

## Contract

| Arm | Test | Asserts | Meaning |
|-----|------|---------|---------|
| `vulnerable` | `tests/exploit.rs` | `assert_exploit_succeeds!` | the flaw is real — the attack goes through |
| `fixed` | `tests/fixed_blocked.rs` | `assert_exploit_rejected!` | the fix closes it — the same attack is turned away |

`src/fixed.rs` is `src/vulnerable.rs` with only the cited guard restored — it is the
patch (`templates/patch/patch.md`) made runnable.

## Evidence tier

A green `./run.sh` earns **`[PoC-REPRODUCED]`** for this finding (Mollusk, deterministic
single-instruction). Record it on the finding block. Other tiers and the fallback
ladder — Surfpool `[PoC-SIM-REPRODUCED]`, fuzz `[PoC-FUZZ-REPRODUCED]`, `[PoC-ATTEMPTED]`,
`[PoC-PROSE]` — are defined in `references/orchestration/poc-harness.md`. A downgraded
tier never downgrades the finding's severity; prose is never removed.
