//! Support crate for auditor-skill proof-of-concept exploit harnesses.
//!
//! Every per-finding PoC crate copied out of `templates/poc/` links against this
//! crate to get three things, kept deliberately small so a reviewer can read the
//! whole surface in one sitting:
//!
//!   1. runner bring-up that records which bytes it loaded: `mollusk_for`, a Mollusk
//!      runner for one instruction, and `litesvm_for!`, a LiteSVM runner for a
//!      stateful sequence (the PoC crate then depends on `litesvm` itself).
//!   2. account fixtures — `program_owned_account`, `system_account`,
//!      `attacker_owned_account` — the three account shapes an access-control /
//!      ownership / signer exploit almost always has to construct.
//!   3. the assertion macros that encode the PoC contract — the attack must go
//!      through on the `vulnerable` build and must be turned away on the `fixed`
//!      build. Each runs the attack itself, on the runner you pass, and returns its
//!      result: one instruction with its account list on Mollusk, or one transaction
//!      on LiteSVM, with any setup run before it:
//!        - `assert_exploit_effect!`: it went through AND left a concrete value in
//!          the account it targets, which that account did not hold before;
//!        - `assert_exploit_rejected_with!`: it was rejected with this exact error;
//!        - `assert_exploit_blocked!`: it failed and left the account unchanged,
//!          while a legitimate call from the same state of that account, to the same
//!          program, went through and changed it (a deployed fix whose error is not
//!          known in advance);
//!        - `assert_exploit_succeeds!` / `assert_exploit_rejected!`: the attack
//!          went through / was turned away, with any result, for an audit-time model
//!          only.
//!
//! Each assertion leaves markers (`mark`), tagged with the test that ran it:
//! `attempted` once the attack has run, `held` when the assertion holds, `failed`
//! when it ran and did not hold, and the first three a marker of their own kind; the
//! runner helpers leave a `loaded` marker naming the bytes they loaded. `run.sh`
//! counts an arm only on a contract assertion of that arm that ran and held, and
//! only when every load names the bytes it placed, so an assertion in a comment, a
//! string or dead code — or one that never ran — does not count, a test that fails
//! before any assertion ran decides nothing, and one test's inconclusive result does
//! not hide another test's failed assertion. A test the process ended inside an
//! assertion leaves `attempted` with no `held` and no `failed`, so it decides
//! nothing rather than reading as a failed assertion. An attack that targets a
//! program other than the one `mollusk_for` or `litesvm_for!` loaded, or a LiteSVM
//! attack that failed in an instruction for another program, is inconclusive too,
//! in every macro: the outcome did not come from the placed bytes. A harness error — the attack
//! as written does not fit the program, or the runtime could not run it — makes an
//! arm inconclusive, on either arm, never a verdict. The markers are a floor, not
//! proof: whoever reads the PoC
//! still checks that the assertion states the finding's effect and the guard's
//! error, and that the program under test is loaded only through `mollusk_for` or
//! `litesvm_for!`.
//!
//! This file is authored as reusable template source. It is not built when the
//! skill ships; the crate's `run.sh` builds and tests it at audit time, once the PoC
//! crate has been filled in. Build and test only through `run.sh`.

use mollusk_svm::program::loader_keys::LOADER_V3;
use mollusk_svm::result::{InstructionResult, ProgramResult};
use mollusk_svm::Mollusk;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use std::cell::RefCell;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

#[doc(hidden)]
pub use mollusk_svm::result::ProgramResult as __ProgramResult;
#[doc(hidden)]
pub use mollusk_svm::Mollusk as __Mollusk;

/// The System program id, surfaced here so a PoC test never has to import the
/// system-interface crate just to describe a system-owned account.
pub const SYSTEM_PROGRAM_ID: Pubkey = solana_system_interface::program::ID;

// ---------------------------------------------------------------------------
// Runner bring-up
// ---------------------------------------------------------------------------

/// Build a Mollusk runner for a program.
///
/// `program_id` is the id the instruction targets. `so_name` is the base name of
/// the compiled shared object (no `.so` suffix, e.g. `"poc_program"`) that `run.sh`
/// placed in `SBF_OUT_DIR`. The file is looked up where Mollusk looks —
/// `tests/fixtures`, `BPF_OUT_DIR`, `SBF_OUT_DIR`, then the working directory — and
/// a name holding `/` is refused, so no other path can be named. Mollusk loads that
/// bytecode — it does NOT run the `#[test]` binary's own code — so the arm must be
/// built for SBF before the test runs, which `run.sh` does.
///
/// The file is read once, and those bytes are what Mollusk loads; their path and
/// zero-trimmed sha256 go to the `loaded` marker, which `run.sh` compares with the
/// arm it placed. A refused name, a missing file and bytes the loader rejects fail
/// the test as inconclusive. Load the program under test only here, and never swap
/// it afterwards: what `Mollusk::new` or `add_program` load leaves no marker.
pub fn mollusk_for(program_id: Pubkey, so_name: &str) -> Mollusk {
    let (path, elf) = program_elf(so_name);
    let mut mollusk = Mollusk::default();
    let added = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        mollusk.add_program_with_loader_and_elf(&program_id, &LOADER_V3, &elf)
    }));
    if let Err(panic) = added {
        let reason = format!(
            "{} (sha256 {}) did not load as a program",
            path.display(),
            zero_trimmed_sha256(&elf)
        );
        mark("inconclusive", &reason);
        std::panic::resume_unwind(panic);
    }
    __loaded(&path, &elf);
    __record_target(&format!("{program_id:?}"));
    mollusk
}

/// Build a LiteSVM runner (`litesvm::LiteSVM::new()`) with the program under test
/// added at `program_id`, from the same `<so_name>.so` lookup as `mollusk_for`, and
/// record the bytes it loaded. The PoC crate depends on `litesvm` itself; 0.13 is
/// the release that pairs with this crate's mollusk-svm 0.13. Load the program under
/// test only here; configure the runner and set accounts on what this returns.
///
/// ```ignore
/// let mut svm = shared_test_utils::litesvm_for!(program_id, "{PROGRAM_NAME}");
/// ```
#[macro_export]
macro_rules! litesvm_for {
    ($program_id:expr, $so_name:expr $(,)?) => {{
        let (__path, __elf) = $crate::__program_elf($so_name);
        let mut __svm = ::litesvm::LiteSVM::new();
        match __svm.add_program($program_id, &__elf) {
            ::core::result::Result::Ok(()) => {
                $crate::__loaded(&__path, &__elf);
                $crate::__record_target(&::std::format!("{:?}", $program_id));
            }
            ::core::result::Result::Err(__err) => {
                $crate::__not_loaded(&__path, &__elf, &::std::format!("{:?}", __err))
            }
        }
        __svm
    }};
}

/// A fresh, unique public key for a fixture. Thin alias over `Pubkey::new_unique`
/// so test bodies read as intent ("the attacker", "the vault") rather than API.
pub fn random_pubkey() -> Pubkey {
    Pubkey::new_unique()
}

/// The `<so_name>.so` that `mollusk_for` and `litesvm_for!` load, and its bytes.
fn program_elf(so_name: &str) -> (PathBuf, Vec<u8>) {
    if so_name.contains('/') {
        inconclusive(&format!(
            "the runner helper refuses the program name {so_name:?}: a name holding '/' can reach a file outside the search directories"
        ));
    }
    let file = format!("{so_name}.so");
    let mut dirs = vec![PathBuf::from("tests/fixtures")];
    for var in ["BPF_OUT_DIR", "SBF_OUT_DIR"] {
        if let Some(dir) = std::env::var_os(var) {
            dirs.push(dir.into());
        }
    }
    if let Ok(dir) = std::env::current_dir() {
        dirs.push(dir);
    }
    let found = dirs
        .iter()
        .map(|dir| dir.join(&file))
        .find(|path| path.exists());
    let Some(path) = found else {
        inconclusive(&format!(
            "no {file} in tests/fixtures, BPF_OUT_DIR, SBF_OUT_DIR or the working directory"
        ));
    };
    let path = std::fs::canonicalize(&path).unwrap_or(path);
    match std::fs::read(&path) {
        Ok(elf) => (path, elf),
        Err(err) => inconclusive(&format!("cannot read {}: {err}", path.display())),
    }
}

#[doc(hidden)]
pub fn __program_elf(so_name: &str) -> (PathBuf, Vec<u8>) {
    program_elf(so_name)
}

#[doc(hidden)]
pub fn __loaded(path: &Path, elf: &[u8]) {
    mark(
        "loaded",
        &format!("{} {}", zero_trimmed_sha256(elf), path.display()),
    );
}

#[doc(hidden)]
pub fn __not_loaded(path: &Path, elf: &[u8], error: &str) -> ! {
    inconclusive(&format!(
        "{} (sha256 {}) did not load as a program: {error}",
        path.display(),
        zero_trimmed_sha256(elf)
    ))
}

thread_local! {
    // The program ids this test loaded through mollusk_for / litesvm_for!. A contract
    // macro's attack must target one of them, or the effect, rejection or block came
    // from another program (the runtime registers the System program, and a PoC may
    // add helpers) while the placed bytes never ran.
    static LOADED: RefCell<Vec<String>> = RefCell::new(Vec::new());
}

#[doc(hidden)]
pub fn __record_target(program: &str) {
    LOADED.with(|l| l.borrow_mut().push(program.to_string()));
}

/// The attack must target a program the harness loaded; otherwise the outcome did not
/// come from the placed bytes, so the run decides nothing.
#[doc(hidden)]
pub fn __require_target(targets: &[String], why: &str) {
    LOADED.with(|l| {
        let loaded = l.borrow();
        if loaded.is_empty() {
            inconclusive(&format!(
                "no program was loaded through mollusk_for or litesvm_for!, so the attack cannot be tied to the bytes run.sh placed ({why})"
            ));
        }
        if !targets.iter().any(|t| loaded.iter().any(|x| x == t)) {
            inconclusive(&format!(
                "the attack targets {}, not {} — the program run.sh placed and the harness loaded ({why})",
                targets.join(", "),
                loaded.join(", ")
            ));
        }
    });
}

/// On LiteSVM a transaction can hold several instructions. When the attack failed with
/// an instruction error, that instruction must target a loaded program, or the
/// rejection came from elsewhere. An accepted attack, or a failure outside any
/// instruction, is left to the assertion (a verdict, or a harness error).
#[doc(hidden)]
pub fn __require_error_instruction(error: Option<&str>, programs: &[String], why: &str) {
    let Some(rest) = error.and_then(|err| err.strip_prefix("InstructionError(")) else {
        return;
    };
    let index = rest.split_once(", ").and_then(|(i, _)| i.trim().parse::<usize>().ok());
    match index.and_then(|i| programs.get(i)) {
        Some(program) => __require_target(std::slice::from_ref(program), why),
        None => inconclusive(&format!(
            "the attack failed in an instruction this transaction does not hold ({}) ({why})",
            error.unwrap_or_default()
        )),
    }
}

/// The sha256 `run.sh` (and `solana-verify`) name a program by: trailing zero
/// padding is trimmed first.
fn zero_trimmed_sha256(elf: &[u8]) -> String {
    let end = elf
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    Sha256::digest(&elf[..end])
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

/// Run the attack and assert it went through: the program accepted it.
///
/// Pass the runner and the attack as for `assert_exploit_effect!` — on Mollusk,
/// `mollusk`, `ix: &ix` and `accounts: &accounts`; on LiteSVM, `svm` and `tx: tx` —
/// and a short reason string describing what the acceptance proves. The macro returns
/// that call's result. Any `Ok` passes, so this fits an audit-time model only; on
/// prebuilt bytes `run.sh` accepts the vulnerable arm only on `assert_exploit_effect!`,
/// because a program can accept a call and do no harm. An attack aimed at a program
/// the harness did not load, and a harness error, fail it as inconclusive.
///
/// ```ignore
/// assert_exploit_succeeds!(mollusk, ix: &ix, accounts: &accounts, why: "no signer check let an unsigned admin key through");
/// assert_exploit_succeeds!(svm, tx: tx, why: "no signer check let an unsigned admin key through");
/// ```
#[macro_export]
macro_rules! assert_exploit_succeeds {
    ($svm:expr, tx: $tx:expr, why: $why:expr $(,)?) => {{
        let __svm: &mut ::litesvm::LiteSVM = &mut $svm;
        let __tx = $tx;
        let __programs: ::std::vec::Vec<::std::string::String> =
            __tx.message.program_ids().into_iter().map(|__id| ::std::format!("{:?}", __id)).collect();
        let __result = __svm.send_transaction(__tx);
        let __error = __result.as_ref().err().map(|__f| ::std::format!("{:?}", __f.err));
        $crate::__require_target(&__programs, $why);
        $crate::__require_error_instruction(__error.as_deref(), &__programs, $why);
        $crate::__assert_succeeds_on(__error, $why);
        __result
    }};
    ($mollusk:expr, ix: $ix:expr, accounts: $accounts:expr, why: $why:expr $(,)?) => {{
        let __mollusk: &$crate::__Mollusk = &$mollusk;
        let __ix = $ix;
        let __outcome = __mollusk.process_instruction(__ix, $accounts);
        $crate::__require_target(&[::std::format!("{:?}", __ix.program_id)], $why);
        $crate::__assert_succeeds(&__outcome, $why);
        __outcome
    }};
    ($outcome:expr, $why:expr $(,)?) => {
        ::core::compile_error!(
            "assert_exploit_succeeds! now runs the attack itself and returns its result: \
             assert_exploit_succeeds!(mollusk, ix: &ix, accounts: &accounts, why: …) in place of \
             (outcome, why), without the `let outcome = mollusk.process_instruction(…)` line. \
             On LiteSVM: assert_exploit_succeeds!(svm, tx: tx, why: …)."
        )
    };
}

/// Run the attack and assert the fix held: the program rejected it.
///
/// The mirror of `assert_exploit_succeeds!`, with the same runner and attack: any
/// error that is not a harness error passes. That fits an audit-time model only. A
/// rejection for an unrelated reason would pass too, so on prebuilt bytes `run.sh`
/// accepts the fixed arm only on `assert_exploit_rejected_with!` or
/// `assert_exploit_blocked!`.
///
/// ```ignore
/// assert_exploit_rejected!(mollusk, ix: &ix, accounts: &accounts, why: "the added is_signer check turned the unsigned key away");
/// ```
#[macro_export]
macro_rules! assert_exploit_rejected {
    ($svm:expr, tx: $tx:expr, why: $why:expr $(,)?) => {{
        let __svm: &mut ::litesvm::LiteSVM = &mut $svm;
        let __tx = $tx;
        let __programs: ::std::vec::Vec<::std::string::String> =
            __tx.message.program_ids().into_iter().map(|__id| ::std::format!("{:?}", __id)).collect();
        let __result = __svm.send_transaction(__tx);
        let __error = __result.as_ref().err().map(|__f| ::std::format!("{:?}", __f.err));
        $crate::__require_target(&__programs, $why);
        $crate::__require_error_instruction(__error.as_deref(), &__programs, $why);
        $crate::__assert_rejected_on(__error, $why);
        __result
    }};
    ($mollusk:expr, ix: $ix:expr, accounts: $accounts:expr, why: $why:expr $(,)?) => {{
        let __mollusk: &$crate::__Mollusk = &$mollusk;
        let __ix = $ix;
        let __outcome = __mollusk.process_instruction(__ix, $accounts);
        $crate::__require_target(&[::std::format!("{:?}", __ix.program_id)], $why);
        $crate::__assert_rejected(&__outcome, $why);
        __outcome
    }};
    ($outcome:expr, $why:expr $(,)?) => {
        ::core::compile_error!(
            "assert_exploit_rejected! now runs the attack itself and returns its result: \
             assert_exploit_rejected!(mollusk, ix: &ix, accounts: &accounts, why: …) in place of \
             (outcome, why), without the `let outcome = mollusk.process_instruction(…)` line. \
             On LiteSVM: assert_exploit_rejected!(svm, tx: tx, why: …)."
        )
    };
}

/// Run the attack and assert it went through AND left its effect: after it, `read`
/// gives `expect` for `account`, and before it, it gave something else.
///
/// - the runner and the attack: on Mollusk, `mollusk`, `ix: &ix` and
///   `accounts: &accounts`, one instruction and the account list it runs with; on
///   LiteSVM, `svm` and `tx: tx`, one signed legacy `Transaction` (it may hold
///   several instructions; the setup before it is the attack's starting state);
/// - `account`: the account the attack changes;
/// - `read`: pulls the changed field out of that account the way the program stores
///   it (bytes, lamports, a decoded field), as an owned value;
/// - `expect`: the concrete value the attack leaves there.
///
/// The macro reads `account` before and after the one call it makes, and returns
/// that call's result. This is the vulnerable-arm assertion prebuilt mode requires:
/// on real bytes `Ok` alone proves nothing, because the program may accept the call
/// and do no harm. A harness error, an account already holding `expect` before the
/// attack, and a read that panics fail the test as inconclusive, never as a verdict.
///
/// ```ignore
/// assert_exploit_effect!(
///     mollusk,
///     ix: &ix,
///     accounts: &accounts,
///     account: state_pk,
///     read: |a| a.data[0..32].to_vec(),
///     expect: attacker.to_bytes().to_vec(),
///     why: "the attacker now holds the authority",
/// );
/// ```
#[macro_export]
macro_rules! assert_exploit_effect {
    ($mollusk:expr, ix: $ix:expr, accounts: $accounts:expr, account: $account:expr,
     read: $read:expr, expect: $expect:expr, why: $why:expr $(,)?) => {{
        let __mollusk: &$crate::__Mollusk = &$mollusk;
        let __accounts: &[_] = $accounts;
        let __ix = $ix;
        let __outcome = __mollusk.process_instruction(__ix, __accounts);
        $crate::__require_target(&[::std::format!("{:?}", __ix.program_id)], $why);
        $crate::__assert_effect(&__outcome, __accounts, &$account, $read, $expect, $why);
        __outcome
    }};
    ($svm:expr, tx: $tx:expr, account: $account:expr, read: $read:expr,
     expect: $expect:expr, why: $why:expr $(,)?) => {{
        let __svm: &mut ::litesvm::LiteSVM = &mut $svm;
        let __account = $account;
        let __tx = $tx;
        let __programs: ::std::vec::Vec<::std::string::String> =
            __tx.message.program_ids().into_iter().map(|__id| ::std::format!("{:?}", __id)).collect();
        let __was = __svm.get_account(&__account);
        let __result = __svm.send_transaction(__tx);
        let __now = __svm.get_account(&__account);
        let __error = __result.as_ref().err().map(|__f| ::std::format!("{:?}", __f.err));
        $crate::__require_target(&__programs, $why);
        $crate::__require_error_instruction(__error.as_deref(), &__programs, $why);
        $crate::__assert_effect_on(
            $crate::__Run {
                error: __error,
                was: __was.as_ref(),
                now: __now.as_ref(),
                programs: __programs,
            },
            &__account,
            $read,
            $expect,
            $why,
        );
        __result
    }};
    ($outcome:expr, before: $($rest:tt)*) => {
        ::core::compile_error!(
            "assert_exploit_effect! now runs the attack itself and returns its result. \
             Pass the runner, the instruction and its account list in place of the outcome \
             and `before:` — assert_exploit_effect!(mollusk, ix: &ix, accounts: &accounts, \
             account: …, read: …, expect: …, why: …) — and drop the \
             `let outcome = mollusk.process_instruction(…)` line. On LiteSVM: \
             assert_exploit_effect!(svm, tx: tx, account: …, read: …, expect: …, why: …)."
        )
    };
}

/// Run the attack and assert the fix held AND turned it away with exactly
/// `expected`, the guard's error.
///
/// `expected` is a value, never a pattern: `ProgramError::MissingRequiredSignature`,
/// `ProgramError::Custom(6000)`. A wildcard or a binding does not compile, and no
/// `Custom(_)` can stand in for the guard: an Anchor program run under the wrong id
/// rejects every call with `Custom(4100)`, which would otherwise pass for a fix. On
/// Mollusk the result is compared with `==`; on LiteSVM the instruction error is
/// compared with `expected` by name. Any other result fails the test, and a harness
/// error (`harness_error`) fails it as inconclusive, which `run.sh` reports as a
/// blocker, not as a broken fix.
///
/// When `expected` is itself a harness-class error (a fix that now needs an extra
/// account, say), it holds like any other, and its marker says so: the positive
/// control is then the vulnerable arm, which runs the byte-identical attack and
/// shows it fits the program.
///
/// Use it for the fix we propose. For a fix the team deployed, whose error is not
/// known in advance, use `assert_exploit_blocked!`.
///
/// ```ignore
/// use solana_sdk::program_error::ProgramError;
/// assert_exploit_rejected_with!(
///     mollusk,
///     ix: &ix,
///     accounts: &accounts,
///     error: ProgramError::MissingRequiredSignature,
///     why: "the restored is_signer check rejected the unsigned authority",
/// );
/// ```
#[macro_export]
macro_rules! assert_exploit_rejected_with {
    ($mollusk:expr, ix: $ix:expr, accounts: $accounts:expr, error: $expected:expr,
     why: $why:expr $(,)?) => {{
        let __mollusk: &$crate::__Mollusk = &$mollusk;
        let __expected = $crate::__ProgramResult::Failure($expected);
        let __ix = $ix;
        let __outcome = __mollusk.process_instruction(__ix, $accounts);
        $crate::__require_target(&[::std::format!("{:?}", __ix.program_id)], $why);
        $crate::__assert_rejected_with(&__outcome, __expected, $why);
        __outcome
    }};
    ($svm:expr, tx: $tx:expr, error: $expected:expr, why: $why:expr $(,)?) => {{
        let __svm: &mut ::litesvm::LiteSVM = &mut $svm;
        let __expected = $crate::__ProgramResult::Failure($expected);
        let __tx = $tx;
        let __programs: ::std::vec::Vec<::std::string::String> =
            __tx.message.program_ids().into_iter().map(|__id| ::std::format!("{:?}", __id)).collect();
        let __result = __svm.send_transaction(__tx);
        let __error = __result.as_ref().err().map(|__f| ::std::format!("{:?}", __f.err));
        $crate::__require_target(&__programs, $why);
        $crate::__require_error_instruction(__error.as_deref(), &__programs, $why);
        $crate::__assert_rejected_with_tx(__error, __expected, $why);
        __result
    }};
    ($outcome:expr, $expected:expr, $why:expr $(,)?) => {
        ::core::compile_error!(
            "assert_exploit_rejected_with! now runs the attack itself and returns its result: \
             assert_exploit_rejected_with!(mollusk, ix: &ix, accounts: &accounts, \
             error: ProgramError::…, why: …) in place of (outcome, ProgramError::…, why), \
             without the `let outcome = mollusk.process_instruction(…)` line. On LiteSVM: \
             assert_exploit_rejected_with!(svm, tx: tx, error: …, why: …)."
        )
    };
}

/// Run the attack and a positive control on one runner, and assert that a fix whose
/// error is not known in advance (a hotfix the team deployed) stopped the attack:
///
/// - the control: a legitimate call — the instruction the finding concerns, with
///   valid accounts and signers — that targets the same program and starts from the
///   same state of `account` as the attack. It must go through AND change what
///   `read` gives for `account`: that shows the harness drives this program and that
///   the read sees the effect the attack is after. On LiteSVM it runs on a clone of
///   the runner, so the attack starts from the state the control started from.
/// - the attack must then fail with an error that is not a harness error and leave
///   what `read` gives for `account` unchanged.
///
/// Pass the same `account` and `read` as the vulnerable arm's
/// `assert_exploit_effect!`. A control that targets another program, starts from
/// another state, fails or changes nothing, and a harness error on the attack, fail
/// the test as inconclusive: without the control, a program that fails every call
/// would pass for a fix. When no legitimate call can go through and change that
/// account on these bytes (the fix turned the instruction off, say), pin the fix's
/// error with `assert_exploit_rejected_with!` instead. Returns the attack's result.
///
/// ```ignore
/// assert_exploit_blocked!(
///     mollusk,
///     ix: &ix,
///     accounts: &accounts,
///     control_ix: &legit_ix,
///     control_accounts: &legit_accounts,
///     account: state_pk,
///     read: |a| a.data[0..32].to_vec(),
///     why: "the deployed hotfix keeps the authority",
/// );
/// ```
#[macro_export]
macro_rules! assert_exploit_blocked {
    ($mollusk:expr, ix: $ix:expr, accounts: $accounts:expr, control_ix: $control_ix:expr,
     control_accounts: $control_accounts:expr, account: $account:expr, read: $read:expr,
     why: $why:expr $(,)?) => {{
        let __mollusk: &$crate::__Mollusk = &$mollusk;
        let __ix = $ix;
        let __accounts: &[_] = $accounts;
        let __control_ix = $control_ix;
        let __control_accounts: &[_] = $control_accounts;
        let __control = __mollusk.process_instruction(__control_ix, __control_accounts);
        let __outcome = __mollusk.process_instruction(__ix, __accounts);
        $crate::__require_target(&[::std::format!("{:?}", __ix.program_id)], $why);
        $crate::__assert_blocked(
            (&__outcome, __accounts, &__ix.program_id),
            (&__control, __control_accounts, &__control_ix.program_id),
            &$account,
            $read,
            $why,
        );
        __outcome
    }};
    ($svm:expr, tx: $tx:expr, control_tx: $control_tx:expr, account: $account:expr,
     read: $read:expr, why: $why:expr $(,)?) => {{
        let __svm: &mut ::litesvm::LiteSVM = &mut $svm;
        let __account = $account;
        let __tx = $tx;
        let __control_tx = $control_tx;
        let __programs: ::std::vec::Vec<::std::string::String> = __tx
            .message
            .program_ids()
            .into_iter()
            .map(|__id| ::std::format!("{:?}", __id))
            .collect();
        let __control_programs: ::std::vec::Vec<::std::string::String> = __control_tx
            .message
            .program_ids()
            .into_iter()
            .map(|__id| ::std::format!("{:?}", __id))
            .collect();
        let mut __control_svm = ::core::clone::Clone::clone(&*__svm);
        let __control_was = __control_svm.get_account(&__account);
        let __control = __control_svm.send_transaction(__control_tx);
        let __control_now = __control_svm.get_account(&__account);
        let __was = __svm.get_account(&__account);
        let __result = __svm.send_transaction(__tx);
        let __now = __svm.get_account(&__account);
        let __error = __result.as_ref().err().map(|__f| ::std::format!("{:?}", __f.err));
        $crate::__require_target(&__programs, $why);
        $crate::__require_error_instruction(__error.as_deref(), &__programs, $why);
        $crate::__assert_blocked_on(
            $crate::__Run {
                error: __error,
                was: __was.as_ref(),
                now: __now.as_ref(),
                programs: __programs,
            },
            $crate::__Run {
                error: __control.as_ref().err().map(|__f| ::std::format!("{:?}", __f.err)),
                was: __control_was.as_ref(),
                now: __control_now.as_ref(),
                programs: __control_programs,
            },
            &__account,
            $read,
            $why,
        );
        __result
    }};
    ($outcome:expr, before: $($rest:tt)*) => {
        ::core::compile_error!(
            "assert_exploit_blocked! now runs the attack and its positive control itself, on \
             one runner: assert_exploit_blocked!(mollusk, ix: &ix, accounts: &accounts, \
             control_ix: &legit_ix, control_accounts: &legit_accounts, account: …, read: …, \
             why: …), without the `let outcome = …` and `let control = …` lines. On LiteSVM: \
             assert_exploit_blocked!(svm, tx: tx, control_tx: legit_tx, account: …, read: …, \
             why: …)."
        )
    };
}

// ---------------------------------------------------------------------------
// What the contract macros run
// ---------------------------------------------------------------------------

/// One run of an attack or a control, as the checks below see it, whichever runner
/// ran it.
#[doc(hidden)]
pub struct __Run<'a, A> {
    /// `None` when the program accepted the call; the printed error otherwise.
    pub error: Option<String>,
    /// The checked account before and after the call.
    pub was: Option<&'a A>,
    pub now: Option<&'a A>,
    /// The programs the call invokes, printed.
    pub programs: Vec<String>,
}

/// A Mollusk result's error, printed, or `None` when the program accepted the call.
fn error_of(outcome: &InstructionResult) -> Option<String> {
    let result = &outcome.program_result;
    (!result.is_ok()).then(|| format!("{result:?}"))
}

fn state_in<'a>(accounts: &'a [(Pubkey, Account)], account: &Pubkey) -> Option<&'a Account> {
    accounts
        .iter()
        .find(|(key, _)| key == account)
        .map(|(_, state)| state)
}

fn mollusk_run<'a>(
    outcome: &'a InstructionResult,
    accounts: &'a [(Pubkey, Account)],
    program: &Pubkey,
    account: &Pubkey,
) -> __Run<'a, Account> {
    __Run {
        error: error_of(outcome),
        was: state_in(accounts, account),
        now: outcome.get_account(account),
        programs: vec![format!("{program:?}")],
    }
}

#[doc(hidden)]
pub fn __assert_succeeds(outcome: &InstructionResult, why: &str) {
    __assert_succeeds_on(error_of(outcome), why);
}

#[doc(hidden)]
pub fn __assert_succeeds_on(error: Option<String>, why: &str) {
    attempt("succeeds", why);
    if let Some(error) = error {
        inconclusive_if_harness(&error, why);
        fail("succeeds", "rejected", format!("exploit was expected to SUCCEED ({why}), but the program rejected it: {error}"));
    }
    held("succeeds", why);
}

#[doc(hidden)]
pub fn __assert_rejected(outcome: &InstructionResult, why: &str) {
    __assert_rejected_on(error_of(outcome), why);
}

#[doc(hidden)]
pub fn __assert_rejected_on(error: Option<String>, why: &str) {
    attempt("rejected", why);
    let Some(error) = error else {
        fail("rejected", "accepted", format!("attack was expected to be REJECTED ({why}), but the program accepted it"));
    };
    inconclusive_if_harness(&error, why);
    held("rejected", why);
}

#[doc(hidden)]
pub fn __assert_effect<T, F>(
    outcome: &InstructionResult,
    accounts: &[(Pubkey, Account)],
    account: &Pubkey,
    read: F,
    expect: T,
    why: &str,
) where
    T: PartialEq + Debug,
    F: Fn(&Account) -> T,
{
    let run = __Run {
        error: error_of(outcome),
        was: state_in(accounts, account),
        now: outcome.get_account(account),
        programs: Vec::new(),
    };
    __assert_effect_on(run, account, read, expect, why);
}

#[doc(hidden)]
pub fn __assert_effect_on<A, K, T, F>(run: __Run<'_, A>, account: &K, read: F, expect: T, why: &str)
where
    K: Debug + ?Sized,
    T: PartialEq + Debug,
    F: Fn(&A) -> T,
{
    attempt("effect", why);
    if let Some(error) = &run.error {
        inconclusive_if_harness(error, why);
        fail(
            "effect",
            "rejected",
            format!("exploit was expected to SUCCEED and change {account:?} ({why}), but the program returned {error}"),
        );
    }
    let was = read_state(run.was, &read, account, "before the attack", why);
    let now = read_state(run.now, &read, account, "after the attack", why);
    if was == expect {
        inconclusive(&format!(
            "{account:?} already read {expect:?} before the attack, so this run cannot show an effect ({why})"
        ));
    }
    if now != expect {
        fail(
            "effect",
            "no-effect",
            format!("after the attack {account:?} reads {now:?}, not {expect:?} ({why})"),
        );
    }
    let line = format!("{account:?}: {was:?} -> {now:?} ({why})");
    mark("effect", &line);
    held("effect", &line);
}

#[doc(hidden)]
pub fn __assert_rejected_with(outcome: &InstructionResult, expected: ProgramResult, why: &str) {
    let matched = outcome.program_result == expected;
    rejected_with(error_of(outcome), matched, &format!("{expected:?}"), why);
}

/// LiteSVM: the transaction's instruction error against `expected`, by name.
#[doc(hidden)]
pub fn __assert_rejected_with_tx(error: Option<String>, expected: ProgramResult, why: &str) {
    let expected = format!("{expected:?}");
    let matched = match (error.as_deref().and_then(error_name), error_name(&expected)) {
        (Some(got), Some(want)) => got == want,
        _ => false,
    };
    rejected_with(error, matched, &expected, why);
}

fn rejected_with(error: Option<String>, matched: bool, expected: &str, why: &str) {
    attempt("rejected_with", why);
    let error = match error {
        Some(error) if matched => error,
        other => {
            if let Some(error) = &other {
                inconclusive_if_harness(error, why);
            }
            let outcome = if other.is_some() { "other-error" } else { "accepted" };
            let got = other.as_deref().unwrap_or("Ok, the program accepted it");
            fail("rejected_with", outcome, format!("attack was expected to be REJECTED with {expected} ({why}), but got: {got}"));
        }
    };
    let note = harness_error(&error)
        .map(|reason| {
            format!(
                "; a harness-class error ({reason}), so the vulnerable arm, running the same attack, is its positive control"
            )
        })
        .unwrap_or_default();
    let line = format!("{error} ({why}){note}");
    mark("rejected_with", &line);
    held("rejected_with", &line);
}

#[doc(hidden)]
pub fn __assert_blocked<T, F>(
    attack: (&InstructionResult, &[(Pubkey, Account)], &Pubkey),
    control: (&InstructionResult, &[(Pubkey, Account)], &Pubkey),
    account: &Pubkey,
    read: F,
    why: &str,
) where
    T: PartialEq + Debug,
    F: Fn(&Account) -> T,
{
    __assert_blocked_on(
        mollusk_run(attack.0, attack.1, attack.2, account),
        mollusk_run(control.0, control.1, control.2, account),
        account,
        read,
        why,
    );
}

#[doc(hidden)]
pub fn __assert_blocked_on<A, K, T, F>(
    attack: __Run<'_, A>,
    control: __Run<'_, A>,
    account: &K,
    read: F,
    why: &str,
) where
    A: PartialEq,
    K: Debug + ?Sized,
    T: PartialEq + Debug,
    F: Fn(&A) -> T,
{
    attempt("blocked", why);
    if sorted(&attack.programs) != sorted(&control.programs) {
        inconclusive(&format!(
            "the legitimate call invokes {:?} and the attack {:?}, so the control shows nothing about the program the attack targets ({why})",
            control.programs, attack.programs
        ));
    }
    if attack.was != control.was {
        inconclusive(&format!(
            "the legitimate call starts {account:?} from another state than the attack, so it cannot show what the attack would change ({why})"
        ));
    }
    if let Some(error) = &control.error {
        inconclusive(&format!(
            "the legitimate call failed on these bytes ({error}): the harness does not drive this program, or the fix turned the instruction off; pin the fix's error with assert_exploit_rejected_with! instead ({why})"
        ));
    }
    let control_was = read_state(control.was, &read, account, "before the legitimate call", why);
    let control_now = read_state(control.now, &read, account, "after the legitimate call", why);
    if control_was == control_now {
        inconclusive(&format!(
            "the legitimate call went through but left {account:?} at {control_was:?}, so this read cannot show whether the attack was stopped ({why})"
        ));
    }
    let Some(error) = &attack.error else {
        fail("blocked", "accepted", format!("attack was expected to be BLOCKED ({why}), but the program accepted it"));
    };
    inconclusive_if_harness(error, why);
    let was = read_state(attack.was, &read, account, "before the attack", why);
    let now = read_state(attack.now, &read, account, "after the attack", why);
    if now != was {
        fail(
            "blocked",
            "changed",
            format!("the attack failed with {error}, yet {account:?} changed: {was:?} -> {now:?} ({why})"),
        );
    }
    let line = format!(
        "{error}; {account:?} unchanged, while the legitimate call changed it: {control_was:?} -> {control_now:?} ({why})"
    );
    mark("blocked", &line);
    held("blocked", &line);
}

fn sorted(programs: &[String]) -> Vec<&String> {
    let mut programs: Vec<&String> = programs.iter().collect();
    programs.sort();
    programs.dedup();
    programs
}

/// What `read` gives for one state of `account`. A missing state, or a read that
/// panics on it, fails the test as inconclusive: the read does not fit the account.
fn read_state<A, K, T, F>(state: Option<&A>, read: &F, account: &K, when: &str, why: &str) -> T
where
    K: Debug + ?Sized,
    F: Fn(&A) -> T,
{
    let Some(state) = state else {
        inconclusive(&format!(
            "{account:?} has no state {when}: it is not among the accounts the call ran with ({why})"
        ));
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read(state))) {
        Ok(value) => value,
        Err(_) => inconclusive(&format!(
            "the read of {account:?} {when} panicked, so it does not fit the account ({why})"
        )),
    }
}

/// The error a printed result names: `Failure(<ProgramError>)` and
/// `UnknownError(<InstructionError>)` from Mollusk, `InstructionError(<index>,
/// <InstructionError>)` from LiteSVM. `None` for a transaction-level error, which
/// stopped the transaction before or outside the program.
fn error_name(printed: &str) -> Option<&str> {
    let inner = match printed.strip_prefix("InstructionError(") {
        Some(rest) => rest.split_once(", ")?.1,
        None => printed
            .strip_prefix("Failure(")
            .or_else(|| printed.strip_prefix("UnknownError("))?,
    };
    inner.strip_suffix(')')
}

/// Results that show the harness, not a guard, stopped the attack: the attack as
/// written no longer fits the program, or the runtime could not run it. Matched on
/// the printed form, so this crate names no error type and stays correct across
/// solana versions. Custom 3005, 4100, 101 and 102 are Anchor's AccountNotEnoughKeys,
/// DeclaredProgramIdMismatch, InstructionFallbackNotFound and
/// InstructionDidNotDeserialize. Every macro checks with it.
fn harness_error(printed: &str) -> Option<&'static str> {
    let Some(name) = error_name(printed) else {
        return Some("the transaction failed before or outside the program");
    };
    match name {
        "NotEnoughAccountKeys" | "Custom(3005)" | "MissingAccount" => {
            Some("the attack's account list does not fit the program")
        }
        "IncorrectProgramId" | "Custom(4100)" => {
            Some("the program runs under the wrong id, or a program account is wrong")
        }
        "Custom(101)" | "Custom(102)" => {
            Some("the program does not recognise the instruction or its arguments")
        }
        "ReadonlyDataModified" | "ReadonlyLamportChange" | "ExternalAccountDataModified"
        | "ExecutableDataModified" | "ExecutableLamportChange" | "AccountNotExecutable"
        | "PrivilegeEscalation" => {
            Some("the attack's account list does not fit the program (an account was writable, signed or executable where the runtime did not allow it)")
        }
        "UnsupportedProgramId" | "ProgramFailedToCompile" | "ComputationalBudgetExceeded"
        | "ProgramEnvironmentSetupFailure" => {
            Some("the runtime could not run the instruction as written")
        }
        _ => None,
    }
}

fn inconclusive_if_harness(printed: &str, why: &str) {
    if let Some(reason) = harness_error(printed) {
        inconclusive(&format!(
            "a harness error, not a guard: {printed}: {reason} ({why})"
        ));
    }
}

/// Fail the test as inconclusive: the PoC as written cannot decide its arm, which
/// `run.sh` reports as a blocker, never as a verdict.
fn inconclusive(reason: &str) -> ! {
    mark("inconclusive", reason);
    panic!("INCONCLUSIVE: {reason}");
}

/// Fail the test as a verdict: an assertion of this arm ran and did not hold. It
/// writes a `failed` marker, tagged with the assertion kind and what the program did
/// (`accepted`, `other-error` or `changed` against a fix, `rejected` or `no-effect`
/// against an exploit), before it panics, so `run.sh` tells a verdict (exit 1 or 2)
/// from a test the process ended inside an assertion (which leaves `attempted` but
/// no `held` and no `failed`, and decides nothing), and names what happened in its
/// final line.
fn fail(kind: &str, outcome: &str, message: String) -> ! {
    mark("failed", &format!("{kind} {outcome}: {message}"));
    panic!("{message}");
}

/// A contract assertion's attack has run: `run.sh` counts a failed test as a verdict
/// only when an assertion ran and did not hold.
fn attempt(kind: &str, why: &str) {
    mark("attempted", &format!("{kind} ({why})"));
}

/// A contract assertion held. The three that count on prebuilt bytes have also left
/// a marker of their own kind, which `run.sh` reports.
fn held(kind: &str, line: &str) {
    mark("held", &format!("{kind}: {line}"));
}

/// Append a line to the `kind` marker: `attempted` and `held` for every contract
/// assertion, `failed` when one ran and did not hold, `effect` / `rejected_with` /
/// `blocked` for the three that count on prebuilt bytes, `loaded` for each program
/// the runner helpers load, and `inconclusive` for why a load or an assertion could
/// not decide. Each line starts
/// with the test that wrote it — libtest names each test's thread after the test —
/// and a tab, so `run.sh` decides test by test. `run.sh` points AUDITOR_POC_MARKERS
/// at an empty directory per arm, for the test binary's run only, and reads it after
/// the arm's test; nothing is written when it is unset.
fn mark(kind: &str, line: &str) {
    let Some(dir) = std::env::var_os("AUDITOR_POC_MARKERS").filter(|dir| !dir.is_empty()) else {
        return;
    };
    let thread = std::thread::current();
    let test = thread.name().unwrap_or("?").replace(['\t', '\n'], " ");
    let path = Path::new(&dir).join(kind);
    let line = format!("{test}\t{}\n", line.replace(['\t', '\n'], " "));
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
