//! {FINDING_ID} — the SAME attack MUST be rejected by the `fixed` arm.
//!
//! Compiled and run only under `--features fixed`. This test body is a copy of
//! `tests/exploit.rs`'s crafted instruction — identical accounts, identical data —
//! with the opposite assertion. Keeping the two attacks byte-identical is what makes
//! the pair a proof: only the guard changed between the arms, so the flipped outcome
//! is attributable to the fix and nothing else.
//!
//! When you edit the crafted instruction in `exploit.rs`, mirror the edit here.

#![cfg(feature = "fixed")]

use borsh::BorshSerialize;
use shared_test_utils::{
    assert_exploit_rejected, mollusk_for, program_owned_account, random_pubkey, system_account,
};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use {PROGRAM_NAME}::State;

#[test]
fn same_attack_rejected_on_fixed() {
    let program_id = random_pubkey();
    let mollusk = mollusk_for(program_id, "{PROGRAM_NAME}");

    let legit_authority = random_pubkey();
    let attacker = random_pubkey();

    let mut state_bytes = Vec::with_capacity(State::LEN);
    State {
        authority: legit_authority,
    }
    .serialize(&mut state_bytes)
    .expect("serialize minimized state");

    let state_pk = random_pubkey();
    let state_acct = program_owned_account(program_id, state_bytes);

    // IDENTICAL to tests/exploit.rs — same craft, only the arm differs.
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(state_pk, false),
            AccountMeta::new_readonly(legit_authority, false),
            AccountMeta::new_readonly(attacker, true),
        ],
        data: vec![],
    };

    let outcome = mollusk.process_instruction(
        &ix,
        &[
            (state_pk, state_acct),
            (legit_authority, system_account(0)),
            (attacker, system_account(1_000_000_000)),
        ],
    );

    // The contract: on the fixed build, the restored guard turns the attack away.
    assert_exploit_rejected!(outcome, "{WHICH_GUARD_BLOCKS_IT}");

    // Optional: to pin the EXACT rejection code, replace the macro above with a
    // direct match, e.g.:
    //   match outcome.program_result {
    //       mollusk_svm::result::ProgramResult::Failure(
    //           solana_sdk::program_error::ProgramError::MissingRequiredSignature,
    //       ) => {}
    //       other => panic!("expected MissingRequiredSignature, got {:?}", other),
    //   }
}
