//! End-to-end scan test against an inline Anchor-style source string.

use auditor_tools::scan;

const FIXTURE: &str = r#"
use anchor_lang::prelude::*;

declare_id!("Fixture1111111111111111111111111111111111");

#[program]
pub mod my_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {
        let a: u64 = 10;
        let b: u64 = 20;
        let total = a + b;
        let vault = &mut ctx.accounts.vault;
        vault.balance = total;
        let first = ctx.remaining_accounts.get(0).unwrap();
        let _ = first;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 40,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}
"#;

#[test]
fn scan_fixture_extracts_expected_surface() {
    let report = scan::scan_source("fixture.rs", FIXTURE).expect("fixture should parse");

    // Exactly one instruction (the fn inside the #[program] mod).
    assert_eq!(
        report.instructions.len(),
        1,
        "expected 1 instruction, got {:?}",
        report.instructions
    );
    let ix = &report.instructions[0];
    assert_eq!(ix.name, "initialize");
    assert_eq!(ix.args.len(), 1, "expected 1 typed arg (amount)");
    assert_eq!(ix.args[0].name, "amount");
    assert_eq!(ix.args[0].ty, "u64");

    // At least one Accounts struct.
    assert!(
        !report.accounts_structs.is_empty(),
        "expected >=1 accounts_struct"
    );
    let init_struct = report
        .accounts_structs
        .iter()
        .find(|s| s.name == "Initialize")
        .expect("Initialize struct should be present");

    // The vault field carries init + seeds + bump.
    let vault_field = init_struct
        .fields
        .iter()
        .find(|f| f.name == "vault")
        .expect("vault field should be present");
    assert!(vault_field.constraints.init, "vault should be init");
    assert!(vault_field.constraints.bump, "vault should have bump");
    assert!(
        !vault_field.constraints.seeds.is_empty(),
        "vault should have seeds"
    );

    // At least one PDA entry, from the seeds constraint.
    assert!(
        report.pdas.iter().any(|p| p.field == "vault"),
        "expected a PDA entry for vault, got {:?}",
        report.pdas
    );

    // At least one raw arithmetic site (a + b).
    assert!(
        report.arithmetic_sites.iter().any(|s| s.op == "+"),
        "expected a '+' arithmetic site, got {:?}",
        report.arithmetic_sites
    );

    // At least one panic site (.unwrap()).
    assert!(
        report.panic_sites.iter().any(|s| s.kind == "unwrap"),
        "expected an unwrap panic site, got {:?}",
        report.panic_sites
    );

    // Line numbers are real (non-zero) thanks to span-locations.
    assert!(ix.line > 0, "instruction line should be > 0");
    assert!(vault_field.constraints.raw.contains("account"));
}
