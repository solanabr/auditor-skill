//! Support crate for auditor-skill proof-of-concept exploit harnesses.
//!
//! Every per-finding PoC crate copied out of `templates/poc/` links against this
//! crate to get three things, kept deliberately small so a reviewer can read the
//! whole surface in one sitting:
//!
//!   1. `mollusk_for` — stand up a Mollusk runner bound to a program id + compiled
//!      `.so`, the one line of setup every Mollusk-based PoC needs.
//!   2. account fixtures — `program_owned_account`, `system_account`,
//!      `attacker_owned_account` — the three account shapes an access-control /
//!      ownership / signer exploit almost always has to construct.
//!   3. the assertion macros that encode the PoC contract — the attack must go
//!      through on the `vulnerable` build and must be turned away on the `fixed`
//!      build:
//!        - `assert_exploit_effect!`: it went through AND left a concrete value in
//!          the account it targets;
//!        - `assert_exploit_rejected_with!`: it was rejected with this exact error;
//!        - `assert_exploit_blocked!`: it failed, the account is unchanged and the
//!          error is not a harness error (a deployed fix whose error is unknown);
//!        - `assert_exploit_succeeds!` / `assert_exploit_rejected!`: any `Ok` / any
//!          error, for an audit-time model only.
//!
//! The first three leave a marker each time they run and hold (`mark`). On prebuilt
//! bytes `run.sh` accepts an arm only with its marker, so an assertion in a comment,
//! a string or dead code — or one that never ran — does not count. The marker is a
//! floor, not proof: whoever reads the PoC still checks that the assertion states
//! the finding's effect and the guard's error.
//!
//! This file is authored as reusable template source. It is not built when the
//! skill ships; the user's Solana toolchain builds it at audit time once the PoC
//! crate has been filled in (`cargo build-sbf`, then `cargo test`).

use mollusk_svm::result::{InstructionResult, ProgramResult};
use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_rent::Rent;

#[doc(hidden)]
pub use mollusk_svm::result::ProgramResult as __ProgramResult;

/// The System program id, surfaced here so a PoC test never has to import the
/// system-interface crate just to describe a system-owned account.
pub const SYSTEM_PROGRAM_ID: Pubkey = solana_system_interface::program::ID;

// ---------------------------------------------------------------------------
// Runner bring-up
// ---------------------------------------------------------------------------

/// Build a Mollusk runner for a program.
///
/// `program_id` is the id the instruction targets. `so_name` is the base name of
/// the compiled shared object (no `.so` suffix, e.g. `"poc_program"`) that
/// `cargo build-sbf` emitted into `SBF_OUT_DIR` / `target/deploy`. Mollusk loads
/// that bytecode — it does NOT run the `#[test]` binary's own code — so the crate
/// must be built for SBF before the test runs. `run.sh` wires this ordering.
///
/// Kept as a one-liner wrapper on purpose: the indirection means a future Mollusk
/// API change is a single edit here rather than a change in every PoC crate.
pub fn mollusk_for(program_id: Pubkey, so_name: &str) -> Mollusk {
    Mollusk::new(&program_id, so_name)
}

/// A fresh, unique public key for a fixture. Thin alias over `Pubkey::new_unique`
/// so test bodies read as intent ("the attacker", "the vault") rather than API.
pub fn random_pubkey() -> Pubkey {
    Pubkey::new_unique()
}

// ---------------------------------------------------------------------------
// Account fixtures
// ---------------------------------------------------------------------------

/// A data account owned by `program_id`, carrying `data` and funded to the
/// rent-exempt minimum for that data length.
///
/// Use this for the account under attack — the config/vault/state PDA whose owner
/// the program checks (or fails to check). Seed `data` with the serialized state
/// the exploit needs the program to read.
pub fn program_owned_account(program_id: Pubkey, data: Vec<u8>) -> Account {
    let lamports = Rent::default().minimum_balance(data.len());
    Account {
        lamports,
        data,
        owner: program_id,
        executable: false,
        rent_epoch: 0,
    }
}

/// A plain System-owned account holding `lamports` and no data.
///
/// Use this for the wallets in the scenario: the fee payer, the attacker's signer,
/// a fresh recipient. Pass `0` for an account that only needs to exist as a key in
/// the accounts list.
pub fn system_account(lamports: u64) -> Account {
    Account {
        lamports,
        data: vec![],
        owner: SYSTEM_PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

/// An account the attacker fully controls but that *claims* to be owned by
/// `claimed_owner`, carrying attacker-chosen `data`.
///
/// This is the substitution primitive for owner-confusion / type-confusion /
/// fake-PDA exploits: hand the program an account whose `owner` field and bytes
/// the attacker set, and prove the program trusts them without re-deriving or
/// re-checking. (Mechanically identical to a program-owned account — the point is
/// that the bytes and the claimed owner are adversary-supplied, which the call
/// site name makes explicit at the exploit's construction.)
pub fn attacker_owned_account(claimed_owner: Pubkey, data: Vec<u8>) -> Account {
    program_owned_account(claimed_owner, data)
}

// ---------------------------------------------------------------------------
// PoC contract macros
// ---------------------------------------------------------------------------

/// Assert the exploit went through: the program accepted the crafted instruction.
///
/// Feed it the value returned by `mollusk.process_instruction(...)` and a short
/// reason string describing what the acceptance proves. Any `Ok` passes, so this
/// fits an audit-time model only; on prebuilt bytes `run.sh` accepts the vulnerable
/// arm only on `assert_exploit_effect!`, because a program can accept a call and do
/// no harm.
///
/// ```ignore
/// let outcome = mollusk.process_instruction(&ix, &accounts);
/// assert_exploit_succeeds!(outcome, "no signer check let an unsigned admin key through");
/// ```
#[macro_export]
macro_rules! assert_exploit_succeeds {
    ($outcome:expr, $why:expr) => {{
        let outcome = &$outcome;
        assert!(
            outcome.program_result.is_ok(),
            "exploit was expected to SUCCEED ({}), but the program rejected it: {:?}",
            $why,
            outcome.program_result,
        );
    }};
}

/// Assert the fix held: the program rejected the same crafted instruction.
///
/// The mirror of `assert_exploit_succeeds!`: any error passes. That fits an
/// audit-time model only. A rejection for an unrelated reason (a wrong account
/// count, the wrong program id) would pass too, so on prebuilt bytes `run.sh`
/// accepts the fixed arm only on `assert_exploit_rejected_with!` or
/// `assert_exploit_blocked!`.
///
/// ```ignore
/// let outcome = mollusk.process_instruction(&ix, &accounts);
/// assert_exploit_rejected!(outcome, "the added is_signer check turned the unsigned key away");
/// ```
#[macro_export]
macro_rules! assert_exploit_rejected {
    ($outcome:expr, $why:expr) => {{
        let outcome = &$outcome;
        assert!(
            outcome.program_result.is_err(),
            "attack was expected to be REJECTED ({}), but the program accepted it",
            $why,
        );
    }};
}

/// Assert the exploit went through AND left its effect: after the attack, `read`
/// gives `expect` for `account`, and before it, it gave something else.
///
/// - `before`: the account list passed to `process_instruction`;
/// - `account`: the account the attack changes;
/// - `read`: pulls the changed field out of that account the way the program stores
///   it (bytes, lamports, a decoded field), as an owned value;
/// - `expect`: the concrete value the attack leaves there.
///
/// This is the vulnerable-arm assertion prebuilt mode requires: on real bytes `Ok`
/// alone proves nothing, because the program may accept the call and do no harm.
///
/// ```ignore
/// let outcome = mollusk.process_instruction(&ix, &accounts);
/// assert_exploit_effect!(
///     outcome,
///     before: &accounts,
///     account: state_pk,
///     read: |a| a.data[0..32].to_vec(),
///     expect: attacker.to_bytes().to_vec(),
///     why: "the attacker now holds the authority",
/// );
/// ```
#[macro_export]
macro_rules! assert_exploit_effect {
    ($outcome:expr, before: $before:expr, account: $account:expr, read: $read:expr,
     expect: $expect:expr, why: $why:expr $(,)?) => {
        $crate::__assert_effect(&$outcome, $before, &$account, $read, $expect, $why)
    };
}

/// Assert the fix held AND turned the attack away with exactly `expected`, the
/// guard's error, compared with `==`.
///
/// `expected` is a value, never a pattern: `ProgramError::MissingRequiredSignature`,
/// `ProgramError::Custom(6000)`. A wildcard or a binding does not compile, and no
/// `Custom(_)` can stand in for the guard: an Anchor program run under the wrong id
/// rejects every call with `Custom(4100)`, which would otherwise pass for a fix.
/// Any other result fails the test. A harness error (`harness_error`) fails it as
/// inconclusive, which `run.sh` reports as a blocker, not as a broken fix.
///
/// Use it for the fix we propose. For a fix the team deployed, whose error is not
/// known in advance, use `assert_exploit_blocked!`.
///
/// ```ignore
/// use solana_sdk::program_error::ProgramError;
/// let outcome = mollusk.process_instruction(&ix, &accounts);
/// assert_exploit_rejected_with!(
///     outcome,
///     ProgramError::MissingRequiredSignature,
///     "the restored is_signer check rejected the unsigned authority"
/// );
/// ```
#[macro_export]
macro_rules! assert_exploit_rejected_with {
    ($outcome:expr, $expected:expr, $why:expr $(,)?) => {
        $crate::__assert_rejected_with(&$outcome, $crate::__ProgramResult::Failure($expected), $why)
    };
}

/// Assert a fix whose error is not known in advance (a hotfix the team deployed)
/// stopped the attack: the instruction failed, `read` gives `account` the same value
/// after the attack as before it, and the error is not a harness error. Pass the
/// same `account` and `read` as the vulnerable arm's `assert_exploit_effect!`.
///
/// A harness error fails the test as inconclusive. If the fix's own guard returns
/// one of those errors, pin it with `assert_exploit_rejected_with!` instead.
///
/// ```ignore
/// assert_exploit_blocked!(
///     outcome,
///     before: &accounts,
///     account: state_pk,
///     read: |a| a.data[0..32].to_vec(),
///     why: "the deployed hotfix keeps the authority",
/// );
/// ```
#[macro_export]
macro_rules! assert_exploit_blocked {
    ($outcome:expr, before: $before:expr, account: $account:expr, read: $read:expr,
     why: $why:expr $(,)?) => {
        $crate::__assert_blocked(&$outcome, $before, &$account, $read, $why)
    };
}

// ---------------------------------------------------------------------------
// What the contract macros run
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub fn __assert_effect<T, F>(
    outcome: &InstructionResult,
    before: &[(Pubkey, Account)],
    account: &Pubkey,
    read: F,
    expect: T,
    why: &str,
) where
    T: PartialEq + core::fmt::Debug,
    F: Fn(&Account) -> T,
{
    let result = &outcome.program_result;
    assert!(
        result.is_ok(),
        "exploit was expected to SUCCEED and change {account:?} ({why}), but the program returned {result:?}{}",
        harness_note(result),
    );
    let (was, now) = before_and_after(outcome, before, account, &read, why);
    assert!(
        now == expect,
        "after the attack {account:?} reads {now:?}, not {expect:?} ({why})"
    );
    assert!(
        was != expect,
        "{account:?} already read {expect:?} before the attack, so this shows no effect ({why})"
    );
    mark(
        "effect",
        &format!("{account:?}: {was:?} -> {now:?} ({why})"),
    );
}

#[doc(hidden)]
pub fn __assert_rejected_with(outcome: &InstructionResult, expected: ProgramResult, why: &str) {
    let result = &outcome.program_result;
    if *result == expected {
        mark("rejected_with", &format!("{result:?} ({why})"));
        return;
    }
    inconclusive_if_harness(result, why);
    panic!("attack was expected to be REJECTED with {expected:?} ({why}), but got: {result:?}");
}

#[doc(hidden)]
pub fn __assert_blocked<T, F>(
    outcome: &InstructionResult,
    before: &[(Pubkey, Account)],
    account: &Pubkey,
    read: F,
    why: &str,
) where
    T: PartialEq + core::fmt::Debug,
    F: Fn(&Account) -> T,
{
    let result = &outcome.program_result;
    assert!(
        result.is_err(),
        "attack was expected to be BLOCKED ({why}), but the program accepted it"
    );
    inconclusive_if_harness(result, why);
    let (was, now) = before_and_after(outcome, before, account, &read, why);
    assert!(
        now == was,
        "the attack failed with {result:?}, yet {account:?} changed: {was:?} -> {now:?} ({why})"
    );
    mark(
        "blocked",
        &format!("{result:?}; {account:?} unchanged ({why})"),
    );
}

fn before_and_after<T, F: Fn(&Account) -> T>(
    outcome: &InstructionResult,
    before: &[(Pubkey, Account)],
    account: &Pubkey,
    read: &F,
    why: &str,
) -> (T, T) {
    let was = before
        .iter()
        .find(|(key, _)| key == account)
        .map(|(_, acct)| acct)
        .unwrap_or_else(|| {
            panic!("{account:?} is not in the account list given to the instruction ({why})")
        });
    let now = outcome
        .get_account(account)
        .unwrap_or_else(|| panic!("{account:?} is not in the instruction result ({why})"));
    (read(was), read(now))
}

/// Results that show the harness, not a guard, stopped the attack: the attack as
/// written no longer fits the program, or the runtime could not run it. Matched on
/// the printed form, so this crate names no error type and stays correct across
/// solana versions. Custom 3005, 4100, 101 and 102 are Anchor's AccountNotEnoughKeys,
/// DeclaredProgramIdMismatch, InstructionFallbackNotFound and
/// InstructionDidNotDeserialize.
fn harness_error(result: &ProgramResult) -> Option<&'static str> {
    match format!("{result:?}").as_str() {
        "Failure(NotEnoughAccountKeys)"
        | "Failure(Custom(3005))"
        | "UnknownError(MissingAccount)" => {
            Some("the attack's account list does not fit the program")
        }
        "Failure(IncorrectProgramId)" | "Failure(Custom(4100))" => {
            Some("the program runs under the wrong id, or a program account is wrong")
        }
        "Failure(Custom(101))" | "Failure(Custom(102))" => {
            Some("the program does not recognise the instruction or its arguments")
        }
        "UnknownError(UnsupportedProgramId)"
        | "UnknownError(ProgramFailedToCompile)"
        | "UnknownError(ComputationalBudgetExceeded)" => {
            Some("the runtime could not run the instruction as written")
        }
        _ => None,
    }
}

fn harness_note(result: &ProgramResult) -> String {
    harness_error(result)
        .map(|reason| format!(" — a harness error: {reason}"))
        .unwrap_or_default()
}

fn inconclusive_if_harness(result: &ProgramResult, why: &str) {
    if let Some(reason) = harness_error(result) {
        mark("inconclusive", &format!("{result:?}: {reason} ({why})"));
        panic!("INCONCLUSIVE: {result:?} is a harness error, not a guard: {reason} ({why})");
    }
}

/// Record that a contract assertion ran and held, or for "inconclusive", why it
/// could not decide. `run.sh` points AUDITOR_POC_MARKERS at an empty directory per
/// arm and reads it after the arm's test; nothing is written when it is unset.
fn mark(kind: &str, line: &str) {
    let Some(dir) = std::env::var_os("AUDITOR_POC_MARKERS").filter(|dir| !dir.is_empty()) else {
        return;
    };
    let path = std::path::Path::new(&dir).join(kind);
    let line = format!("{}\n", line.replace('\n', " "));
    let written = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, line.as_bytes()));
    if let Err(err) = written {
        eprintln!(
            "shared-test-utils: cannot record the {kind} marker in {}: {err}",
            path.display()
        );
    }
}
