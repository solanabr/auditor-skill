//! End-to-end scan tests against inline sources: an Anchor-style program, and the
//! cross-program calls and program address derivations of programs without Anchor.

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

    pub fn deposit_extra(
        ctx: Context<DepositExtra>,
        _amount: u64,
    ) -> Result<()> {
        let _ = ctx.accounts.extra;
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

#[derive(Accounts)]
pub struct DepositExtra<'info> {
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + 8,
        seeds = [b"extra", payer.key().as_ref()],
        bump
    )]
    pub extra: Account<'info, ExtraState>,

    /// CHECK: validated in handler before use
    pub oracle: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[account]
pub struct ExtraState {
    pub value: u64,
}
"#;

#[test]
fn scan_fixture_extracts_expected_surface() {
    let report = scan::scan_source("fixture.rs", FIXTURE).expect("fixture should parse");

    // Exactly two instructions (the fns inside the #[program] mod).
    assert_eq!(
        report.instructions.len(),
        2,
        "expected 2 instructions, got {:?}",
        report.instructions
    );
    let ix = report
        .instructions
        .iter()
        .find(|i| i.name == "initialize")
        .expect("initialize instruction should be present");
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

    // The vault field carries init (not init_if_needed) + seeds + bump.
    let vault_field = init_struct
        .fields
        .iter()
        .find(|f| f.name == "vault")
        .expect("vault field should be present");
    assert!(vault_field.constraints.init, "vault should be init");
    assert!(
        !vault_field.constraints.init_if_needed,
        "vault should not be init_if_needed"
    );
    assert!(vault_field.constraints.bump, "vault should have bump");
    assert!(
        !vault_field.constraints.seeds.is_empty(),
        "vault should have seeds"
    );
    assert!(!vault_field.unchecked, "vault should not be unchecked");

    let deposit_struct = report
        .accounts_structs
        .iter()
        .find(|s| s.name == "DepositExtra")
        .expect("DepositExtra struct should be present");

    let extra_field = deposit_struct
        .fields
        .iter()
        .find(|f| f.name == "extra")
        .expect("extra field should be present");
    assert!(!extra_field.constraints.init, "extra should not use init");
    assert!(
        extra_field.constraints.init_if_needed,
        "extra should use init_if_needed"
    );

    let oracle_field = deposit_struct
        .fields
        .iter()
        .find(|f| f.name == "oracle")
        .expect("oracle field should be present");
    assert!(
        oracle_field.unchecked,
        "oracle UncheckedAccount should be flagged unchecked"
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

    // remaining_accounts access in initialize.
    assert!(
        report
            .remaining_accounts_sites
            .iter()
            .any(|s| s.snippet.contains("remaining_accounts")),
        "expected a remaining_accounts site, got {:?}",
        report.remaining_accounts_sites
    );

    // Line numbers are real (non-zero) thanks to span-locations.
    assert!(ix.line > 0, "instruction line should be > 0");
    assert!(vault_field.constraints.raw.contains("account"));
}

/// Every cross-program call form of solana-program, solana-cpi, pinocchio and
/// pinocchio-system, and every program address derivation of solana-program,
/// solana-address, pinocchio and pinocchio-pubkey, in a program without Anchor.
const NATIVE: &str = r#"
use pinocchio::{cpi, pubkey};
use pinocchio_system::instructions::{CreateAccount, Transfer};

pub fn calls(ix: &Instruction, infos: &[&AccountInfo], s: &[Signer], a: &AccountInfo, b: &AccountInfo) -> ProgramResult {
    invoke(ix, infos)?;
    solana_program::program::invoke_signed(ix, infos, &[s])?;
    unsafe { invoke_unchecked(ix, infos) };
    unsafe { solana_cpi::invoke_signed_unchecked(ix, infos, &[s]) };
    cpi::invoke_with_bounds::<8>(ix, infos)?;
    cpi::invoke_signed_with_bounds::<8>(ix, infos, s)?;
    slice_invoke(ix, infos)?;
    slice_invoke_signed(ix, infos, s)?;
    cpi::invoke_with_slice(ix, infos)?;
    cpi::invoke_signed_with_slice(ix, infos, s)?;
    unsafe { sol_invoke_signed_c(ix as *const _ as *const u8, infos.as_ptr() as *const u8, 2, s.as_ptr() as *const u8, 1) };
    unsafe { syscalls::sol_invoke_signed_rust(ix as *const _ as *const u8, infos.as_ptr() as *const u8, 2, s.as_ptr() as *const u8, 1) };
    Transfer { from: a, to: b, lamports: 1 }.invoke()?;
    CreateAccount { from: a, to: b, lamports: 1, space: 8, owner: &ID }.invoke_signed(s)?;
    Ok(())
}

pub fn derivations(user: &AccountInfo, bump: u8, seeds: &[&[u8]]) -> ProgramResult {
    let (vault, vault_bump) = pubkey::find_program_address(&[b"vault", user.key().as_ref()], &crate::ID);
    let found = Pubkey::try_find_program_address(&[b"vault"], &crate::ID);
    let made = Pubkey::create_program_address(&[b"vault", &[bump]], &crate::ID)?;
    let checked = pubkey::checked_create_program_address(seeds, &crate::ID)?;
    let derived = derive_address(&[b"vault", user.key().as_ref()], Some(bump), &crate::ID);
    let constant = pinocchio_pubkey::derive_address_const(&[b"vault"], None, &crate::ID);
    let tried = Address::try_derive_address(&[b"vault"], Some(bump), &crate::ID)?;
    let program = Address::derive_program_address(&[b"vault"], &crate::ID);
    Ok(())
}
"#;

/// The line of `NATIVE` that holds `text`.
fn native_line(text: &str) -> usize {
    NATIVE
        .lines()
        .position(|l| l.contains(text))
        .expect("the line is in the fixture")
        + 1
}

#[test]
fn scan_fixture_lists_the_cross_program_calls_and_derivations_of_a_program_without_anchor() {
    let report = scan::scan_source("native.rs", NATIVE).expect("the fixture parses");

    let calls: Vec<(String, usize)> = report
        .cpi_sites
        .iter()
        .map(|c| (c.kind.clone(), c.line))
        .collect();
    let want: Vec<(String, usize)> = [
        ("invoke", "invoke(ix, infos)"),
        ("invoke_signed", "program::invoke_signed("),
        ("invoke_unchecked", "invoke_unchecked("),
        ("invoke_signed_unchecked", "invoke_signed_unchecked("),
        ("invoke_with_bounds", "cpi::invoke_with_bounds::"),
        ("invoke_signed_with_bounds", "invoke_signed_with_bounds::"),
        ("slice_invoke", "slice_invoke(ix"),
        ("slice_invoke_signed", "slice_invoke_signed("),
        ("invoke_with_slice", "cpi::invoke_with_slice("),
        ("invoke_signed_with_slice", "invoke_signed_with_slice("),
        ("sol_invoke_signed_c", "sol_invoke_signed_c("),
        ("sol_invoke_signed_rust", "sol_invoke_signed_rust("),
        ("method:invoke", ".invoke()"),
        ("method:invoke_signed", ".invoke_signed(s)"),
    ]
    .iter()
    .map(|(kind, text)| (kind.to_string(), native_line(text)))
    .collect();
    assert_eq!(calls, want);
    let transfer = report
        .cpi_sites
        .iter()
        .find(|c| c.kind == "method:invoke")
        .expect("the method call");
    assert_eq!(
        transfer.snippet,
        "Transfer { from : a , to : b , lamports : 1 } . invoke ()"
    );

    let derivations: Vec<(&str, &str, &str, Vec<&str>, usize)> = report
        .pdas
        .iter()
        .map(|p| {
            (
                p.struct_name.as_str(),
                p.field.as_str(),
                p.kind.as_str(),
                p.seeds.iter().map(String::as_str).collect(),
                p.line,
            )
        })
        .collect();
    let user = "user . key () . as_ref ()";
    let vault = "b\"vault\"";
    assert_eq!(
        derivations,
        [
            (
                "",
                "",
                "find_program_address",
                vec![vault, user],
                native_line("pubkey::find_program_address(")
            ),
            (
                "",
                "",
                "try_find_program_address",
                vec![vault],
                native_line("try_find_program_address(")
            ),
            (
                "",
                "",
                "create_program_address",
                vec![vault, "& [bump]"],
                native_line("Pubkey::create_program_address(")
            ),
            (
                "",
                "",
                "checked_create_program_address",
                vec!["seeds"],
                native_line("checked_create_program_address(")
            ),
            (
                "",
                "",
                "derive_address",
                vec![vault, user],
                native_line("= derive_address(")
            ),
            (
                "",
                "",
                "derive_address_const",
                vec![vault],
                native_line("derive_address_const(")
            ),
            (
                "",
                "",
                "try_derive_address",
                vec![vault],
                native_line("try_derive_address(")
            ),
            (
                "",
                "",
                "derive_program_address",
                vec![vault],
                native_line("derive_program_address(")
            ),
        ]
    );

    // The Anchor fixture's PDAs keep their struct and field, with kind `seeds`.
    let anchor = scan::scan_source("fixture.rs", FIXTURE).expect("fixture should parse");
    let kinds: Vec<(&str, &str, &str)> = anchor
        .pdas
        .iter()
        .map(|p| (p.struct_name.as_str(), p.field.as_str(), p.kind.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("Initialize", "vault", "seeds"),
            ("DepositExtra", "extra", "seeds")
        ]
    );
}

/// The line of `source` that holds `text`.
fn line_in(source: &str, text: &str) -> usize {
    source
        .lines()
        .position(|l| l.contains(text))
        .expect("the line is in the source")
        + 1
}

/// An Anchor program's cross-program calls, each made through a `CpiContext`: one
/// from `CpiContext::new` handed to the callee's `cpi` module, one from
/// `CpiContext::new_with_signer` with no type written, one made inside an SPL
/// call, one by its full path, and one taken as a parameter.
const ANCHOR_CPI: &str = r#"
use anchor_lang::prelude::*;
use anchor_spl::token_interface::{transfer_checked, TransferChecked};

#[program]
pub mod caller {
    use super::*;

    pub fn set(ctx: Context<Set>, value: u64) -> Result<()> {
        let accounts = callee::cpi::accounts::SetValue {
            store: ctx.accounts.store.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.callee.key(), accounts);
        callee::cpi::set_value(cpi_ctx, value)
    }

    pub fn set_signed(ctx: Context<Set>, value: u64) -> Result<()> {
        let seeds: &[&[&[u8]]] = &[&[b"authority", &[ctx.bumps.authority]]];
        let accounts = callee::cpi::accounts::SetValue {
            store: ctx.accounts.store.to_account_info(),
        };
        let signed = CpiContext::new_with_signer(ctx.accounts.callee.key(), accounts, seeds);
        callee::cpi::set_value(signed, value)
    }

    pub fn pay(ctx: Context<Pay>, amount: u64) -> Result<()> {
        let decimals = ctx.accounts.mint.decimals;
        transfer_checked(CpiContext::new_with_signer(ctx.accounts.token_program.key(), checked(&ctx), &[]), amount, decimals)?;
        anchor_spl::token::transfer(anchor_lang::context::CpiContext::new(ctx.accounts.token_program.key(), plain(&ctx)), amount)
    }
}

fn forward<'info>(ctx: CpiContext<'_, '_, '_, 'info, SetValue<'info>>) -> Result<()> {
    callee::cpi::set_value(ctx, 1)
}
"#;

#[test]
fn scan_fixture_lists_each_cpi_context_of_an_anchor_program() {
    let report = scan::scan_source("caller.rs", ANCHOR_CPI).expect("the fixture parses");
    let sites: Vec<(&str, usize, &str)> = report
        .cpi_sites
        .iter()
        .map(|c| (c.kind.as_str(), c.line, c.snippet.as_str()))
        .collect();
    let at = |text: &str| line_in(ANCHOR_CPI, text);
    assert_eq!(
        sites,
        [
            (
                "CpiContext",
                at("let cpi_ctx = CpiContext::new("),
                "CpiContext :: new"
            ),
            (
                "CpiContext",
                at("let signed = CpiContext::new_with_signer("),
                "CpiContext :: new_with_signer"
            ),
            (
                "CpiContext",
                at("transfer_checked(CpiContext::new_with_signer("),
                "CpiContext :: new_with_signer"
            ),
            (
                "CpiContext",
                at("anchor_lang::context::CpiContext::new("),
                "anchor_lang :: context :: CpiContext :: new"
            ),
            (
                "CpiContext",
                at("fn forward"),
                "CpiContext <'_ , '_ , '_ , 'info , SetValue <'info >>"
            ),
        ]
    );
    let instructions: Vec<&str> = report
        .instructions
        .iter()
        .map(|i| i.name.as_str())
        .collect();
    assert_eq!(instructions, ["set", "set_signed", "pay"]);
}

/// The names the scan lists, each written as a raw identifier: the program's
/// attribute, the Accounts derive, the cross-program calls as functions and as
/// methods, a `CpiContext`, a derivation, `remaining_accounts`, and the panics.
const RAW: &str = r#"
#[r#program]
pub mod raw_program {
    use super::*;

    pub fn handle(ctx: Context<Handle>, amount: u64) -> Result<()> {
        Ok(())
    }
}

#[r#derive(r#Accounts)]
pub struct Handle<'info> {
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
}

pub fn drain(ix: &Instruction, a: &[AccountInfo], s: &[&[u8]], v: Option<u8>, ctx: Ctx) -> ProgramResult {
    r#invoke_signed(ix, a, &[s])?;
    solana_program::program::r#invoke(ix, a)?;
    unsafe { r#invoke_signed_unchecked(ix, a, &[s]) };
    Transfer { from: a, to: b, lamports: 1 }.r#invoke_signed(&signers)?;
    Transfer { from: a, to: b, lamports: 1 }.r#invoke()?;
    let made = r#CpiContext::new(program, accounts);
    let (pda, bump) = Pubkey::r#find_program_address(&[b"vault"], &crate::ID);
    let rest = ctx.r#remaining_accounts;
    let x = v.r#unwrap();
    let y = v.r#expect("y");
    if x == y { r#panic!("same") }
    r#unreachable!()
}
"#;

#[test]
fn scan_fixture_takes_a_raw_identifier_for_its_name() {
    let report = scan::scan_source("raw.rs", RAW).expect("the fixture parses");
    let at = |text: &str| line_in(RAW, text);

    let instructions: Vec<(&str, usize)> = report
        .instructions
        .iter()
        .map(|i| (i.name.as_str(), i.args.len()))
        .collect();
    assert_eq!(instructions, [("handle", 1)]);
    let structs: Vec<&str> = report
        .accounts_structs
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(structs, ["Handle"]);

    let calls: Vec<(&str, usize, &str)> = report
        .cpi_sites
        .iter()
        .map(|c| (c.kind.as_str(), c.line, c.snippet.as_str()))
        .collect();
    assert_eq!(
        calls,
        [
            (
                "invoke_signed",
                at("r#invoke_signed(ix"),
                "r#invoke_signed (ix , a , & [s])"
            ),
            (
                "invoke",
                at("program::r#invoke(ix"),
                "solana_program :: program :: r#invoke (ix , a)"
            ),
            (
                "invoke_signed_unchecked",
                at("r#invoke_signed_unchecked("),
                "r#invoke_signed_unchecked (ix , a , & [s])"
            ),
            (
                "method:invoke_signed",
                at(".r#invoke_signed(&signers)"),
                "Transfer { from : a , to : b , lamports : 1 } . r#invoke_signed (& signers)"
            ),
            (
                "method:invoke",
                at(".r#invoke()"),
                "Transfer { from : a , to : b , lamports : 1 } . r#invoke ()"
            ),
            (
                "CpiContext",
                at("r#CpiContext::new("),
                "r#CpiContext :: new"
            ),
        ]
    );

    let derivations: Vec<(&str, &str, &str, usize)> = report
        .pdas
        .iter()
        .map(|p| {
            (
                p.struct_name.as_str(),
                p.field.as_str(),
                p.kind.as_str(),
                p.line,
            )
        })
        .collect();
    assert_eq!(
        derivations,
        [
            ("Handle", "vault", "seeds", at("pub vault:")),
            (
                "",
                "",
                "find_program_address",
                at("r#find_program_address(")
            ),
        ]
    );

    let remaining: Vec<(usize, &str)> = report
        .remaining_accounts_sites
        .iter()
        .map(|r| (r.line, r.snippet.as_str()))
        .collect();
    assert_eq!(
        remaining,
        [(at("ctx.r#remaining_accounts"), "ctx . r#remaining_accounts")]
    );

    let panics: Vec<(&str, usize)> = report
        .panic_sites
        .iter()
        .map(|p| (p.kind.as_str(), p.line))
        .collect();
    assert_eq!(
        panics,
        [
            ("unwrap", at("v.r#unwrap()")),
            ("expect", at("v.r#expect(")),
            ("panic", at("r#panic!(")),
            ("panic", at("r#unreachable!()")),
        ]
    );
}

/// Cross-program calls made through helpers named for the call: a Codama-generated
/// client's `…Cpi` with remaining accounts, signed and not, and its builder;
/// spl-token-2022's and spl-transfer-hook-interface's on-chain helpers, which
/// build the instruction and make the call; and a program's own wrapper. Building
/// an instruction without making the call is no site.
const HELPERS: &str = r#"
use spl_token_2022::onchain;

pub fn mint(cpi: CreateV2Cpi, extra: &[(&AccountInfo, bool, bool)], seeds: &[&[&[u8]]]) -> ProgramResult {
    CreateV2Cpi::new(program, accounts, args).invoke_with_remaining_accounts(extra)?;
    cpi.invoke_signed_with_remaining_accounts(seeds, extra)?;
    CreateV2CpiBuilder::new(program).payer(payer).invoke_signed(seeds)?;
    let ix = spl_token_2022::instruction::transfer_checked(&id, &from, &mint, &to, &owner, &[], 1, 6)?;
    spl_token_2022::onchain::invoke_transfer_checked(token, from, mint, to, owner, extra, 1, 6, seeds)?;
    onchain::invoke_transfer_checked_with_fee(token, from, mint, to, owner, extra, 1, 6, 0, seeds)?;
    spl_transfer_hook_interface::onchain::invoke_execute(hook, from, mint, to, owner, extra, 1)?;
    checked_invoke(&ix, extra)?;
    Ok(())
}
"#;

#[test]
fn scan_fixture_lists_each_call_whose_name_holds_invoke() {
    let report = scan::scan_source("helpers.rs", HELPERS).expect("the fixture parses");
    let at = |text: &str| line_in(HELPERS, text);
    let calls: Vec<(&str, usize)> = report
        .cpi_sites
        .iter()
        .map(|c| (c.kind.as_str(), c.line))
        .collect();
    assert_eq!(
        calls,
        [
            (
                "method:invoke_with_remaining_accounts",
                at(".invoke_with_remaining_accounts(")
            ),
            (
                "method:invoke_signed_with_remaining_accounts",
                at(".invoke_signed_with_remaining_accounts(")
            ),
            ("method:invoke_signed", at(".invoke_signed(seeds)")),
            ("invoke_transfer_checked", at("invoke_transfer_checked(")),
            (
                "invoke_transfer_checked_with_fee",
                at("invoke_transfer_checked_with_fee(")
            ),
            ("invoke_execute", at("invoke_execute(")),
            ("checked_invoke", at("checked_invoke(")),
        ]
    );
    let snippets: Vec<&str> = report
        .cpi_sites
        .iter()
        .filter(|c| {
            c.kind == "method:invoke_signed_with_remaining_accounts" || c.kind == "checked_invoke"
        })
        .map(|c| c.snippet.as_str())
        .collect();
    assert_eq!(
        snippets,
        [
            "cpi . invoke_signed_with_remaining_accounts (seeds , extra)",
            "checked_invoke (& ix , extra)",
        ]
    );
}

/// Calls through a path in parentheses, which the compiler makes as calls to the
/// path.
const PARENS: &str = r#"
pub fn relay(ix: &Instruction, infos: &[AccountInfo], seeds: &[&[&[u8]]]) -> ProgramResult {
    (invoke_signed)(ix, infos, seeds)?;
    ((solana_program::program::invoke))(ix, infos)?;
    let (pda, bump) = (Pubkey::find_program_address)(&[b"vault"], &ID);
    Ok(())
}
"#;

#[test]
fn scan_fixture_lists_a_call_through_a_path_in_parentheses() {
    let report = scan::scan_source("parens.rs", PARENS).expect("the fixture parses");
    let at = |text: &str| line_in(PARENS, text);
    let calls: Vec<(&str, usize, &str)> = report
        .cpi_sites
        .iter()
        .map(|c| (c.kind.as_str(), c.line, c.snippet.as_str()))
        .collect();
    assert_eq!(
        calls,
        [
            (
                "invoke_signed",
                at("(invoke_signed)("),
                "(invoke_signed) (ix , infos , seeds)"
            ),
            (
                "invoke",
                at("program::invoke))("),
                "((solana_program :: program :: invoke)) (ix , infos)"
            ),
        ]
    );
    let derivations: Vec<(&str, Vec<&str>, usize)> = report
        .pdas
        .iter()
        .map(|p| {
            (
                p.kind.as_str(),
                p.seeds.iter().map(String::as_str).collect(),
                p.line,
            )
        })
        .collect();
    assert_eq!(
        derivations,
        [(
            "find_program_address",
            vec!["b\"vault\""],
            at("(Pubkey::find_program_address)(")
        )]
    );
}
