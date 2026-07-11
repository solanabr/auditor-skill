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
//!   3. two assertion macros — `assert_exploit_succeeds!` / `assert_exploit_rejected!`
//!      — that encode the PoC contract: the attack must go through on the
//!      `vulnerable` build and must be turned away on the `fixed` build.
//!
//! This file is authored as reusable template source. It is not built when the
//! skill ships; the user's Solana toolchain builds it at audit time once the PoC
//! crate has been filled in (`cargo build-sbf`, then `cargo test`).

use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_rent::Rent;

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
/// reason string describing what the acceptance proves. On the `vulnerable` build
/// this must hold; the reason is echoed on failure so a broken PoC explains itself.
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
/// The mirror of `assert_exploit_succeeds!`. Run the identical attack against the
/// `fixed` build and require an error — any error, because closing the hole is the
/// contract, not returning one specific code. When a PoC must pin the exact error
/// (e.g. `MissingRequiredSignature`), match `outcome.program_result` directly in
/// the test instead of using this macro.
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
