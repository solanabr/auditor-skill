# 01 — Account Validation Checklist

> Domain: On-chain Solana Program  
> Severity if missed: CRITICAL to HIGH  
> References: Neodyme "Missing Ownership Check", Sealevel Attacks, Anchor Account Constraints

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 1.1 — Account Ownership Checks

- [ ] **AV-001**: Every account deserialized from `AccountInfo` has its `owner` field validated against the expected program ID
- [ ] **AV-002**: No account in `#[derive(Accounts)]` uses raw `AccountInfo<'info>` (deprecated in Anchor 1.0) — must use `UncheckedAccount<'info>` or typed `Account<'info, T>`
- [ ] **AV-003**: Every `UncheckedAccount<'info>` has a `/// CHECK:` doc comment that describes the ACTUAL runtime validation performed (not just "safe because...")
- [ ] **AV-004**: Every `/// CHECK:` comment corresponds to real code — grep for the validation logic referenced in the comment
- [ ] **AV-005**: Accounts typed as `Account<'info, T>` automatically check owner + discriminator — verify T matches the expected state struct
- [ ] **AV-006**: Token accounts use `Account<'info, TokenAccount>` or `InterfaceAccount<'info, TokenAccount>` — never raw `AccountInfo`
- [ ] **AV-007**: Mint accounts use `Account<'info, Mint>` — never raw `AccountInfo`
- [ ] **AV-008**: System program, token program, rent sysvar are typed with `Program<'info, System>`, `Program<'info, Token>`, `Sysvar<'info, Rent>` — not `AccountInfo`
- [ ] **AV-009**: No account marked as `Account<'info, T>` where T is a different program's state struct without explicit owner override
- [ ] **AV-010**: The program ID declared in `declare_id!()` matches the deployed program ID and the keypair file

## 1.2 — Account Discriminator & Type Cosplay

- [ ] **AV-011**: Every on-chain account uses Anchor's 8-byte discriminator (automatic with `#[account]` macro) — check no manual serialization bypasses it
- [ ] **AV-012**: No instruction accepts an account typed as struct A where struct B has the same memory layout prefix (type cosplay attack)
- [ ] **AV-013**: If `remaining_accounts` are deserialized manually, verify discriminator is checked (e.g., `AccountDeserialize::try_deserialize()`)
- [ ] **AV-014**: If `remaining_accounts` are deserialized, verify the account address matches the expected PDA derivation — **discriminator checks alone are insufficient**
- [ ] **AV-015**: No account struct reuses the first 8 bytes of another account struct's discriminator (collision check)
- [ ] **AV-016**: Account structs use `#[account]` attribute (not manual `BorshSerialize`/`BorshDeserialize` without discriminator)
- [ ] **AV-017**: If accounts are migrated between versions, old discriminators cannot be confused with new ones

## 1.3 — Account Constraint Validation (Anchor `#[account(...)]`)

- [ ] **AV-018**: Every account that should be mutable is marked `#[account(mut)]`
- [ ] **AV-019**: No account is marked `#[account(mut)]` when it should be read-only (unnecessary mutability)
- [ ] **AV-020**: `has_one = field` constraints are used on accounts that reference other accounts (e.g., `has_one = manager`, `has_one = fund`)
- [ ] **AV-021**: `has_one` constraints are ALSO backed by runtime `require_keys_eq!` checks (defense-in-depth)
- [ ] **AV-022**: `init` accounts use `payer`, `space`, and `seeds` + `bump` correctly
- [ ] **AV-023**: `init_if_needed` is NOT used unless explicitly required — it opens reinitialization vectors
- [ ] **AV-024**: If `init_if_needed` IS used, there is a guard against reinitialization (e.g., checking a version/initialized flag)
- [ ] **AV-025**: `close = destination` constraints send lamports to the correct recipient — check destination is constrained
- [ ] **AV-026**: Closed accounts have their data zeroed (Anchor does this automatically with `close`, verify no manual close bypasses it)
- [ ] **AV-027**: `seeds` constraints use all necessary seed components (prevent PDA collision across different entities)
- [ ] **AV-028**: `bump` values are stored in state and reused (`bump = account.bump`) — not re-derived every time
- [ ] **AV-029**: `constraint = <expr>` custom constraints use proper error types, not generic `ConstraintRaw`
- [ ] **AV-030**: `realloc` constraints include `realloc::payer` and `realloc::zero` appropriately
- [ ] **AV-031**: No duplicate mutable accounts without explicit `#[account(mut, dup)]` opt-in (Anchor 1.0 rejects by default)

## 1.4 — Remaining Accounts Validation

- [ ] **AV-032**: All `remaining_accounts` are iterated and validated before use — no blind pass-through
- [ ] **AV-033**: For each remaining account, owner is verified (`account.owner == expected_program`)
- [ ] **AV-034**: For each remaining account used as a token account, mint and authority are verified
- [ ] **AV-035**: For each remaining account used as a PDA, the address is re-derived and compared
- [ ] **AV-036**: The count of remaining_accounts is validated (not more or fewer than expected)
- [ ] **AV-037**: Remaining accounts passed to external CPI (e.g., Jupiter) are at minimum program-ownership validated
- [ ] **AV-038**: No remaining account can be the same as a named account in the struct (duplicate account confusion)
- [ ] **AV-039**: If remaining accounts represent investor positions, each position's fund field matches the current fund

## 1.5 — Account Size & Rent

- [ ] **AV-040**: All `init` accounts allocate sufficient `space` — calculate manually: 8 (discriminator) + each field size
- [ ] **AV-041**: No account can be created with less than rent-exempt minimum lamports
- [ ] **AV-042**: Variable-length fields (Vec, String) in account structs have a maximum length enforced
- [ ] **AV-043**: `realloc` operations check the new size doesn't exceed the maximum allowed account size (10 MB)
- [ ] **AV-044**: No instruction allows reducing account size below the minimum required for its data

## 1.6 — Token Account Validation

- [ ] **AV-045**: Every token account used in transfers has its `mint` field validated against expected mint
- [ ] **AV-046**: Every token account used in transfers has its `owner`/`authority` field validated
- [ ] **AV-047**: Vault token accounts are verified as owned by the expected PDA (fund PDA)
- [ ] **AV-048**: Associated Token Accounts are derived correctly — `getAssociatedTokenAddressSync` or `associated_token::` seed derivation
- [ ] **AV-049**: Token accounts with `delegate` field — verify delegate authorization before using delegated_amount
- [ ] **AV-050**: Token accounts are checked for `frozen` state if freeze authority exists
- [ ] **AV-051**: WSOL (wrapped SOL) accounts use the correct native mint address (`So11111111111111111111111111111111111111112`)
- [ ] **AV-052**: Token-2022 accounts are not confused with original Token Program accounts (different program IDs)

## 1.7 — Reinitialization Protection

- [ ] **AV-053**: No instruction can re-initialize an already-initialized account (check `init` vs `init_if_needed`)
- [ ] **AV-054**: If manual initialization is used (not Anchor `init`), an `is_initialized` flag is checked
- [ ] **AV-055**: After account closure, the same PDA seeds cannot be re-derived to create a new account with stale associations
- [ ] **AV-056**: Revival attack: after `close`, can an attacker send lamports to the closed account address to prevent garbage collection and re-use stale data?
- [ ] **AV-057**: If an account is closed mid-transaction, subsequent instructions in the same transaction cannot access stale data from that account
