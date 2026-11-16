---
id: 142
title: "Variable Rent After SIMD-0437 / SIMD-0392 — Hardcoded Minimums, Excess-Lamport Sweeps and Rent-Priced Deterrents"
severity: 6
category: crypto
---

### 142 — Variable Rent After SIMD-0437 / SIMD-0392 — Hardcoded Minimums, Excess-Lamport Sweeps and Rent-Priced Deterrents

**Severity: 6** | **Real: class of bug, no incident cited. SIMD-0437 ("Incremental rent reduction") lowers `lamports_per_byte` from 6,960 to 696 in five feature-gated steps (6,333 → 5,080 → 2,575 → 1,322 → 696), updating the value "in the bank and rent sysvar" at each activation and the SDK default only afterwards. The first steps ran on testnet from Aug 2026 and the last three (2,575, 1,322, 696) were reported on the Agave v4.5 schedule. Expected date: Anza's v4.5 schedule, as edited 2026-11-10 and marked tentative, targets 2026-12-14 for v4.5 feature activation to begin on mainnet; no date is published per step (Solana Compass, 2026-11-10). SIMD-0392 ("Rent increase adaptations", status Activated) states that the rent value "may vary based on active feature gates and rent policies" and changes the post-execution check to `min(rent_exempt_min_balance, acc.pre_exec_balance)` for an account whose size and owner did not change. Verify the live value before citing a step: `solana -u <cluster> rent 0` and `solana -u <cluster> feature status`.**

For six years the rent-exempt minimum was a constant in practice: `(128 + data_len) × 6,960` lamports, which made 890,880 (empty account), 1,461,600 (mint) and 2,039,280 (token account) appear as literals in programs, clients and tests. It is now a cluster parameter that moves, down by 90% under SIMD-0437 and, by SIMD-0392's own wording, not guaranteed to stay there. SIMD-0437 calls the reduction "strictly a relaxation of existing constraints", which is true for the runtime check and false for three things programs built on top of it:

- **Hardcoded minimums and `Rent::default()`.** A literal or `Rent::default().minimum_balance(len)` is the value the SDK was compiled with, not the cluster's. Before a step activates, a client built against an updated SDK underfunds every account it creates and the transaction fails (`InsufficientFundsForRent`): a liveness failure on init, deposit and open-position paths. After it, an old literal overfunds, which is harmless until the next bullet. A realloc top-up computed as `(new_len - old_len) × rate` is the same bug: under SIMD-0392 an account below a raised minimum cannot grow or change owner until it holds the full current minimum.
- **Excess-lamport sweeps.** Every account funded at 6,960 lamports per byte holds 90% more than the new minimum. Any instruction that pays out `lamports() - minimum_balance(len)` (sweep, collect dust, withdraw excess, rebalance treasury, a close that refunds the "surplus" to the caller) now hands that 90% to whoever the instruction names. Where the payer of the deposit and the recipient of the sweep differ, that is a transfer of the payer's deposit: 1,835,352 lamports per token-account-sized deposit, about 1,835 SOL per million accounts. The instruction was a rounding-dust collector when it was reviewed.
- **Rent used as a price.** Protocols lean on rent as an economic control without saying so: the cost of creating a per-user PDA, an order slot, a ticket or a registry entry is the only thing that bounds spam (KV-127, AC-045, KV-131); the rent refunded on close is the keeper's or liquidator's reward for cranking cleanup; a "listing deposit" is defined as the account's rent. At 696 lamports per byte the first costs a tenth, the second pays a tenth, and the third no longer deters anything. State growth per attacker dollar rises 10x.

> Cross-ref: checklist 01 §1.13 (AV-091: rent read from the sysvar at use time); checklist 06 §6.17 (ECON-093: excess-lamport sweeps; ECON-094: rent-priced deterrents and incentives); FV-074 (tests under the live rent value); KV-123 (lamport donation and RentState transitions: the other way a balance leaves the expected value); KV-127 / AC-045 (account pre-creation and init spam); KV-131 (hot shared accounts); KV-106 (close and revival); `references/invariant-catalog.md` (rent-exempt post-condition).

#### Verification Procedure

**Step 1: Find every place a rent value is assumed instead of read**
```
grep -rn --include="*.rs" -E "Rent::default\(\)|DEFAULT_LAMPORTS_PER_BYTE|DEFAULT_EXEMPTION_THRESHOLD|LAMPORTS_PER_BYTE|lamports_per_byte(_year)?|\b(890_?880|1_?461_?600|2_?039_?280|6_?960|3_?480)\b" programs/ 2>/dev/null
grep -rn -E "\b(890_?880|1_?461_?600|2_?039_?280|0\.00203928|0\.00089088|0\.0014616)\b|getMinimumBalanceForRentExemption|minimum_balance" apps/ packages/ clients/ sdk/ tests/ scripts/ 2>/dev/null
```
- ✅ PASS: on-chain code calls `Rent::get()?.minimum_balance(len)` (or reads a validated `Sysvar<Rent>`) at the point of use; clients call `getMinimumBalanceForRentExemption` per transaction build and do not cache it across sessions
- ❌ FAIL: a literal, a `const` derived from SDK defaults, or `Rent::default()` feeds an account creation, a top-up, a rent-exemption `require!`, or a client-side funding amount
- If no account is created, resized, closed or swept by the program and no client funds accounts, this vector is N/A (record this explicitly)

**Step 2: Realloc and top-up math reads the current minimum for the whole account**
```
grep -rn --include="*.rs" -B4 -A10 -E "realloc\(|\.resize\(|realloc *=" programs/ | grep -iE "lamports|minimum_balance|transfer|rent"
```
- ✅ PASS: the top-up is `Rent::get()?.minimum_balance(new_len).saturating_sub(account.lamports())`, so an account that sits below a changed minimum is brought to the current one before it grows
- ❌ FAIL: the top-up is a delta (`(new_len - old_len) × rate`, or `minimum_balance(new_len) - minimum_balance(old_len)`): correct only while the rate never moved since the account was funded; under SIMD-0392 the grow fails when the account is below the current minimum

**Step 3: Excess-lamport payouts go to the party that funded the deposit**
```
grep -rn --include="*.rs" -B6 -A12 -iE "lamports\(\) *(-|\.checked_sub|\.saturating_sub)|excess|surplus|sweep|dust|withdraw_(sol|lamports)|collect_(rent|fees)" programs/ | grep -iE "minimum_balance|rent|lamports|payer|recipient|destination|authority"
```
- For each hit record: which accounts it can run on, who is allowed to call it, where the lamports go, and who paid the deposit at init (`payer =`)
- ✅ PASS: the surplus above the current minimum returns to the recorded payer (or the account's owner of record), or the instruction is restricted to accounts the protocol itself funded; a `close` returns the full balance to the payer or to a destination the payer chose
- ❌ FAIL: an admin, a keeper or any caller receives `lamports - minimum_balance` from accounts that users funded: after the rent steps that is 90% of every user deposit, taken one transaction at a time

**Step 4: Rent is not the only thing pricing spam, cleanup or listings**
```
grep -rn --include="*.rs" -iE "init(_if_needed)?,|create_account|close *=|close_account|bounty|reward|keeper|crank|listing|deposit" programs/ | grep -iE "payer|rent|lamports|fee"
```
- ✅ PASS: permissionless creation of protocol-indexed accounts (order slots, tickets, positions, registry entries, per-user PDAs that a crank must later iterate) carries an explicit protocol fee, a refundable deposit set in lamports by governance, or a hard per-user / global cap; cleanup incentives are a stated amount, not "whatever rent the closed account held"; the sizing was re-derived at 696 lamports per byte
- ❌ FAIL: the design note or the code relies on "creating an account costs X SOL" as the deterrent, or pays crankers the closed account's rent, with X taken at 6,960 lamports per byte: an attacker fills the structure for a tenth of the modeled cost, or honest keepers stop closing because the reward fell 90%

**Step 5: Tests and deployment configuration use the cluster's value**
```
grep -rn -E "Rent::default\(\)|set_sysvar.*Rent|minimum_balance|\b(890_?880|1_?461_?600|2_?039_?280)\b" tests/ programs/*/tests 2>/dev/null
```
- ✅ PASS: at least one test runs the create / realloc / close / sweep paths with the Rent sysvar set to the lowest scheduled value (696 lamports per byte) and one with the legacy value, and asserts balances against `minimum_balance`, not against a literal (FV-074)
- ❌ FAIL: the suite pins balances to the legacy literals, so it passes while the deployed program misprices or the client underfunds on the day a step activates

**Overall verdict:**
- ✅: Rent is read from the sysvar (on-chain) or the RPC (clients) at use time; top-ups target the full current minimum; no instruction pays one party the surplus of another party's deposit; spam, cleanup and listing economics carry their own explicit price and were re-derived at the reduced rent; tests cover both ends of the schedule
- ⚠️: Rent is read correctly but tests still assert legacy literals, or the anti-spam / keeper economics were never re-derived, or a sweep exists that is admin-only over protocol-funded accounts with no record of who funded them
- ❌: A hardcoded minimum or `Rent::default()` funds or gates an account; or a delta-based realloc top-up; or a sweep / close hands user-funded surplus to an admin, keeper or arbitrary caller; or rent is the only deterrent on a permissionlessly growable structure
- N/A: The program creates, resizes, closes and sweeps no account, and no client in scope funds one
