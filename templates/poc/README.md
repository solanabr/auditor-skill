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
AUDITOR_EXEC_MODE=isolated ./run.sh   # or native: the execution mode recorded for the run
```

Building this crate runs code — dependency build scripts and proc-macros, then the
tests — so every run needs `AUDITOR_EXEC_MODE` set to the execution mode recorded
at intake (`OUTPUT-RULES.md` Rule 11a): `isolated` inside a container, VM or
sandbox with no keys mounted, or `native` on this machine, which the report then
states. Without it, `run.sh` exits `3` before it copies or compiles anything.

Builds both arms with `cargo build-sbf` (platform-tools >= v1.54) and runs both
tests with `SBF_OUT_DIR` wired — never inside the audited repo. The crate is copied
to a scratch directory under `$TMPDIR` (printed; `KEEP_POC_BUILD=1` keeps it) and
built there with the toolchain pinned, so the target's `.cargo/config*` and
`rust-toolchain*` never apply; a crate holding a symbolic link, a `.cargo/`
directory or a `rust-toolchain*` file is refused. Exit `0` means the exploit
reproduced on `vulnerable` **and** was blocked on `fixed`; `1` / `2` mean the PoC
is not valid — see the failing arm's message; `3` is a named blocker (no execution
mode, no SBF toolchain, bad inputs, or a build that failed), and the finding's
prose PoC still stands.

**Dependencies.** Framework crates by default, as in the template. A crate copied
from the target's manifest runs its build script in the recorded mode, so add one
only when the PoC needs it, and read what the manifest pulls in. A `path`
dependency on target crates must be an absolute path: the build runs from the
scratch copy, not from this directory.

**Build cache.** Each run compiles every dependency from cold in its fresh scratch
directory. To reuse compiled dependencies between runs of one audit, create a
directory outside any repository, e.g.
`${XDG_CACHE_HOME:-$HOME/.cache}/auditor-skill/poc-target/<repo-name>-audit_<n>`,
export it as `CARGO_TARGET_DIR`, and delete it when the engagement ends. Never
point `CARGO_TARGET_DIR` inside the target tree or at a directory you did not
create: cargo trusts the build outputs it finds there.

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
