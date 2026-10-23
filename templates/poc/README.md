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

Build and test only through `run.sh`. It builds both arms with `cargo build-sbf`
(platform-tools >= v1.54), builds each arm's test binary and runs it with
`SBF_OUT_DIR` wired — never inside the audited repo. The crate is copied to a scratch
directory under `$TMPDIR` (printed; `KEEP_POC_BUILD=1` keeps it) and built there with
the toolchain pinned, so the target's `.cargo/config*` and `rust-toolchain*` never
apply. Refused before anything compiles, in either mode: a symbolic link, a `.cargo/`
directory or a `rust-toolchain*` file in the crate; build-time code of the crate's
own — a build script (`build = false` turns one off), a proc-macro package, a
`Cargo.toml` inside the crate that is not a member of its workspace, a `[patch]` or
`[replace]` table — so check generated code into the crate instead; and a
`tests/fixtures/{PROGRAM_NAME}.so`, which mollusk would load in place of the arm.

Exit `0` means the exploit reproduced on `vulnerable` **and**, when the fixed arm
runs, was blocked on `fixed`; `1` / `2` mean a contract assertion of that arm ran and
did not hold — see its message, and for `2` the final line, which says whether the
fixed arm accepted the attack, rejected it with another error than the pinned one, or
failed it while the account still changed; `3` is a named blocker (no execution mode,
no SBF toolchain, bad inputs, a build that failed, build-time code in the crate) or an
inconclusive arm (no contract assertion ran, the test failed outside them, the
harness could not decide — a harness error such as a wrong program id or a short
account list, on either arm — or the test loaded other bytes than the placed arm). On
every `3` the finding's prose PoC still stands: record `[PoC-ATTEMPTED]` with the
blocker line, and mark the finding "PoC re-run needed" with that line as the reason.
Only a harness error (an inconclusive arm, or a test that no longer builds against the
refreshed harness copy) gets a repair pass: repair the harness setup once, never the
assertions or the target, and re-run (`references/orchestration/poc-harness.md` §3).
Before its final line, `run.sh` names
the non-registry code in the build: the path and git dependencies in the resolved
`Cargo.lock`, and any source compiled from outside the crate.

`run.sh` and `shared-test-utils/` are the installation's copies; leave them as they
are. Before a command trusts an `OK` line it compares them with the installation's
`templates/poc/` (only the version requirements in `shared-test-utils/Cargo.toml` may
differ), and a re-run first refreshes `run.sh` and `shared-test-utils/src/` from it.
`run.sh` itself refuses a crate that does not depend on its own `shared-test-utils/`
under the import name `shared_test_utils`, one where another dependency takes that
import name (spelled with `-` or `_`), and a build that compiles a `shared_test_utils`
from anywhere else.

**Dependencies.** Framework crates by default, as in the template. A crate copied
from the target's manifest runs its build script in the recorded mode, so add one
only when the PoC needs it, and read what the manifest pulls in. A `path`
dependency on target crates must be an absolute path: the build runs from the
scratch copy, not from this directory. Such a dependency is not refused: its build
script runs in the recorded mode, and the non-registry line names it.

**Pins.** `Cargo.lock` pins the whole dependency graph at releases published at
least 14 days before the template shipped, so an unmodified crate resolves to the
same versions on every run. Keep it with the crate; `run.sh` prints a line when it
is missing. A crate you add keeps every pin it does not need to move. When cargo
reports a conflict with a pinned release, move that pin alone:
`AUDITOR_EXEC_MODE=<mode> UPDATE_PINS="<crate>@<pinned version>" ./run.sh` runs
`cargo update -p` in the scratch copy and brings the moved lock back. Never run
`cargo update` in this directory: inside the target tree it would read the target's
`.cargo/config*`.

**Build cache.** Each run compiles every dependency from cold in its fresh scratch
directory. To reuse compiled dependencies between runs of one engagement, create the
cache once per engagement with `mktemp -d "${TMPDIR:-/tmp}/auditor-poc-target.XXXXXX"`
— inside the isolated runner in isolated mode — record its path next to the execution
mode, pass it to every run as `CARGO_TARGET_DIR`, and delete it when the engagement
ends. Never point `CARGO_TARGET_DIR` or `CARGO_BUILD_TARGET_DIR` inside the target tree
or at a directory you did not create: cargo trusts the build outputs it finds there.
PoC crates of one engagement often share a package name, so their artifacts land on
the same paths in the cache: `run.sh` holds a lock inside the directory cargo builds
into (a `target-dir` in your own cargo config counts too) around each arm's build and
test, and re-stamps its scratch copy under the lock so cargo rebuilds the crate's own
code. A run waits up to `POC_LOCK_WAIT` seconds (default 900) for the lock, then stops
with exit 3. A run that still finds one of its own units reported as already built,
without having built it, stops with exit 3 instead of running it.

## Contract

| Arm | Test | Asserts | Meaning |
|-----|------|---------|---------|
| `vulnerable` | `tests/exploit.rs` | `assert_exploit_effect!` | the flaw is real — the attack goes through and leaves a concrete value in the account it targets, which that account did not hold before |
| `fixed` | `tests/fixed_blocked.rs` | `assert_exploit_rejected_with!` | the fix closes it — the same attack is turned away with the guard's exact error |

Each macro runs the attack itself and returns its result: on Mollusk, the runner, one
instruction and its account list (`mollusk, ix: &ix, accounts: &accounts`); on
LiteSVM, the runner and one signed legacy `Transaction`, with any setup sent before
it (`svm, tx: tx`). Load the program under test through `mollusk_for`, or, for a
LiteSVM PoC (add `litesvm = "0.13"`), through `litesvm_for!`. `src/fixed.rs` is
`src/vulnerable.rs` with only the cited guard restored — it is the patch
(`templates/patch/patch.md`) made runnable.

The expected error is a value compared with `==`, never a pattern. A harness error —
the attack as written does not fit the program, or the runtime could not run it — is
inconclusive on either arm, and so is an effect the account already held before the
attack. When the guard's error is itself harness-class (a fix that now needs an extra
account, say), pin it all the same: the vulnerable arm, running the byte-identical
attack, is its positive control, and the `fixed arm:` line (on prebuilt bytes with
`FIXED_SO`) says so. To check a fix the
team already deployed, whose error you cannot know in advance, swap in the commented
lines in `tests/fixed_blocked.rs`: `assert_exploit_blocked!` with its positive control,
which the macro runs on the same runner. It passes when a legitimate call (the same
instruction, as its rightful caller makes it, to the same program and from the same
state of the account) goes through and changes the account, and the attack then fails
with an error that is not a harness error and leaves the account unchanged. A control
that targets another program, starts from another state, fails or changes nothing is
inconclusive; when no legitimate call can show the change on those bytes, pin the
fix's error with `assert_exploit_rejected_with!` instead, as a new check, not a harness
repair. `assert_exploit_succeeds!` / `assert_exploit_rejected!` take the same runner
and attack, accept any `Ok` / any error that is not a harness error, and fit an
audit-time model only.

**Migrating a PoC from 7.6.0 or earlier.** A PoC written against those macros
(which took the `process_instruction` result, and for the 7.6.0 effect and blocked
forms a `before:` list) no longer builds once its harness copy is refreshed; the build
fails with a `compile_error!` naming the new form.
Rewriting each call into the new form — the runner, the instruction and its account
list (or the LiteSVM runner and the transaction), with the same `account`, `read`,
`expect` / `error` and `why` — is a harness repair: it changes how the attack is run,
not what is asserted, so record it in `harness-repair.diff` like any other repair.

**Markers.** Each contract assertion leaves a marker once its attack has run and
another when it holds, each tagged with its test. An arm counts — in a model run as on
prebuilt bytes — only with a held assertion of that arm, and only when every program
the runner helpers loaded is the `.so` `run.sh` placed, still unchanged after the
test, and the attack targeted one of them; a LiteSVM attack that failed in an
instruction for another program decides nothing. A failed assertion in one test is a verdict even when another test is
inconclusive; a test that fails before any contract assertion ran (the program did
not load, the setup panicked) exits `3` (inconclusive), not `1` or `2`. The markers are
a floor, not proof: read the assertion all the same.

**Prebuilt bytes.** `VULNERABLE_SO=<.so>` runs the exploit arm alone on those bytes;
adding `FIXED_SO=<.so>` runs the fixed arm on others. On prebuilt bytes the vulnerable
arm counts only on `assert_exploit_effect!`, and the fixed arm only on
`assert_exploit_rejected_with!` or `assert_exploit_blocked!`. Success prints the only
line that can stand for Leg 3 of an incident, naming the bytes that ran:

```
OK: reproduced on prebuilt bytes — vulnerable sha256=<zero-trimmed sha256> → [PoC-REPRODUCED]
```

With `FIXED_SO`, the line also names `fixed sha256=<…>` and how the fixed arm held:
`(rejected with the pinned error)` or `(blocked: failed, account unchanged)`. A LiteSVM
PoC reaches the same line when it loads the program through `litesvm_for!` and asserts
with the macros' LiteSVM forms. A run of this crate's own arms prints a different
line: a model is never Leg 3.

## Evidence tier

A green `./run.sh` earns **`[PoC-REPRODUCED]`** for this finding (Mollusk, one
instruction; or LiteSVM, one transaction). Record it on the finding block. An exit `3`
is `[PoC-ATTEMPTED]` with `run.sh`'s blocker line and "PoC re-run needed". Other tiers
and the fallback ladder — Surfpool `[PoC-SIM-REPRODUCED]`, fuzz `[PoC-FUZZ-REPRODUCED]`, `[PoC-ATTEMPTED]`,
`[PoC-PROSE]` — are defined in `references/orchestration/poc-harness.md`. A downgraded
tier never downgrades the finding's severity; prose is never removed.
