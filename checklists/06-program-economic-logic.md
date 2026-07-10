# 06 — Economic & Logic Attack Checklist

> Domain: On-chain Solana Program  
> Severity if missed: CRITICAL to HIGH  
> References: DeFi exploit history, MEV research, flash loan attacks, sandwich attacks

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 6.1 — Flash Loan Attacks

- [ ] **ECON-001**: Can an attacker flash-borrow tokens, deposit into the fund, inflate the NAV, and withdraw in the same transaction?
- [ ] **ECON-002**: Is there a deposit cooldown before withdrawal is allowed? (Prevents atomic deposit→withdraw exploitation)
- [ ] **ECON-003**: Is share minting delayed by at least one slot/block from deposit? (Prevents same-slot manipulation)
- [ ] **ECON-004**: Can an attacker flash-borrow SOL, deposit, get shares, and use shares as collateral elsewhere in the same tx?
- [ ] **ECON-005**: NAV attestation — can it be updated and exploited in the same transaction?

## 6.2 — Sandwich & MEV Attacks

- [ ] **ECON-006**: Jupiter swap instructions — do they enforce slippage limits? (User-configurable or hardcoded minimum?)
- [ ] **ECON-007**: Can a validator/MEV searcher sandwich a fund's swap by front-running with a buy and back-running with a sell?
- [ ] **ECON-008**: Manager's swap instruction — is the swap data (route, slippage) determined off-chain? Can it be manipulated?
- [ ] **ECON-009**: Deposit instruction — can it be sandwiched? (attacker deposits before, inflates NAV, depositor gets fewer shares)
- [ ] **ECON-010**: Withdrawal instruction — can it be sandwiched? (attacker manipulates pool prices to reduce withdrawal value)
- [ ] **ECON-011**: Is there a minimum deposit amount to prevent dust attacks that exploit per-transaction costs?
- [ ] **ECON-012**: Is there a minimum withdrawal amount similarly enforced?

## 6.3 — First Depositor / Share Inflation Attack

- [ ] **ECON-013**: When fund has 0 shares and 0 assets — what ratio does the first deposit use?
- [ ] **ECON-014**: Can the first depositor deposit 1 unit, then donate a large amount to the vault, making the second depositor's shares worth nearly nothing?
- [ ] **ECON-015**: Is there a minimum first deposit requirement to prevent the first depositor attack?
- [ ] **ECON-016**: Is there a "virtual shares" or "dead shares" mechanism (mint some minimal shares to address 0) to prevent first-depositor manipulation?
- [ ] **ECON-017**: Share price at creation — is it 1:1 with the deposit? Verify initialization logic

## 6.4 — NAV Manipulation

- [ ] **ECON-018**: Who attests the NAV? Manager? Oracle? Backend?
- [ ] **ECON-019**: If manager attests NAV — manager can inflate NAV before new deposits (dilution vectors)
- [ ] **ECON-020**: If manager attests NAV — manager can deflate NAV before withdrawals (steal from investors)
- [ ] **ECON-021**: Is there a maximum NAV change per attestation? (Rate limiting on NAV changes)
- [ ] **ECON-022**: Is there a verification mechanism for NAV accuracy? (On-chain oracle, multiple attestors, etc.)
- [ ] **ECON-023**: NAV floor: can NAV be set to 0? What happens to share pricing?
- [ ] **ECON-024**: NAV ceiling: can NAV be set to u64::MAX? Integer overflow in downstream calculations?
- [ ] **ECON-025**: Stale NAV: deposits/withdrawals using outdated NAV — is there a freshness requirement?

## 6.5 — Fee Exploitation

- [ ] **ECON-026**: Can the manager set fees to extract more than documented? Verify on-chain max fee enforcement
- [ ] **ECON-027**: Can the manager change fees after deposits are made? (Retroactive fee change)
- [ ] **ECON-028**: Is there a timelock on fee changes? (Allow investors to withdraw before new fees take effect)
- [ ] **ECON-029**: Can the manager extract fees by making wash trades (trade to themselves, charge fees on volume)?
- [ ] **ECON-030**: Management fee accrual — is it time-proportional or charged on operations?
- [ ] **ECON-031**: Performance fee — is the high-water mark tracked to prevent double-charging on recovery?
- [ ] **ECON-032**: Fee extraction order — are fees deducted before or after the investor's share calculation?
- [ ] **ECON-033**: Can fees be extracted from fund assets without going through the fee instruction path? (Direct transfer CPI)

## 6.6 — Manager Trust & Rug Pull Vectors

- [ ] **ECON-034**: Can the manager swap all fund assets to a worthless token? (Protocol risk, not necessarily a bug)
- [ ] **ECON-035**: Can the manager send fund tokens to their personal wallet via `pda_token_transfer`?
- [ ] **ECON-036**: `pda_token_transfer` — are both source and destination constrained to be fund-owned accounts?
- [ ] **ECON-037**: `pda_lamports_transfer` — are destinations constrained? Can manager drain SOL?
- [ ] **ECON-038**: `pda_token_approve` — can manager approve a delegate on fund tokens? What's the limit?
- [ ] **ECON-039**: `token_swap_vault` — can manager extract value via unfavorable swap routes?
- [ ] **ECON-040**: Protocol CPI — can manager CPI into a malicious program to drain assets?
- [ ] **ECON-041**: Is the whitelist for protocol CPI controlled by the same manager? (Fox guarding the henhouse)
- [ ] **ECON-042**: Can manager add their own program to the whitelist and then drain via CPI?
- [ ] **ECON-043**: Is there investor-side protection against manager misbehavior? (Timelock, multi-sig, withdrawal guarantee)

## 6.7 — Token-Related Exploits

- [ ] **ECON-044**: Token-2022 transfer hook: can a malicious token with a transfer hook exploit the fund?
- [ ] **ECON-045**: Token with fee-on-transfer: does the program correctly handle tokens where transfer amount != received amount?
- [ ] **ECON-046**: Rebasing tokens: does the program handle tokens whose balance changes without transfers?
- [ ] **ECON-047**: Tokens with freeze authority: can someone freeze fund's token accounts?
- [ ] **ECON-048**: Tokens with mint authority: can someone inflate token supply after fund buys them?
- [ ] **ECON-049**: Non-standard decimal tokens (e.g., 0 decimals, 18 decimals): does the program handle all decimal ranges?
- [ ] **ECON-050**: WSOL wrapping/unwrapping: correct handling of native SOL ↔ wrapped SOL transitions

## 6.8 — Denial of Service (Economic DoS)

- [ ] **ECON-051**: Can an attacker make transactions too expensive for legitimate users? (Account bloat, compute unit exhaustion)
- [ ] **ECON-052**: Can an attacker create many positions or withdrawals to make batch operations fail (out of compute)?
- [ ] **ECON-053**: `pay_fund_investors` with many remaining_accounts — does it exhaust compute budget?
- [ ] **ECON-054**: Can an attacker spam small deposits to create many positions and bloat state?
- [ ] **ECON-055**: Large Vec or array in state — can it grow unbounded and exceed account size limit?
- [ ] **ECON-056**: Can an attacker lock funds by creating a state that prevents legitimate operations?

## 6.9 — Oracle Manipulation

- [ ] **ECON-057**: If program relies on price oracles — which oracle? Pyth, Switchboard, Chainlink?
- [ ] **ECON-058**: Oracle price staleness check — is there a max age for oracle prices?
- [ ] **ECON-059**: Oracle confidence interval — are wide-confidence prices rejected?
- [ ] **ECON-060**: Can oracle be manipulated by the same party who benefits from the manipulation?
- [ ] **ECON-061**: Multi-oracle: does the program use fallback oracles if primary is stale?
- [ ] **ECON-062**: If no oracle is used (manager-attested NAV) — document the trust assumption and flag

## 6.10 — Staking / Reward Accounting

> Reward math is the most exploited category in staking/yield programs. (adapted from safe-solana-builder shared-base §21)
> Grep hints:
> ```
> grep -rn --include="*.rs" -iE "reward_debt|reward_per_token|acc_reward_per_share|reward_per_share|pending|accrued|total_staked|total_shares" programs/
> ```

- [ ] **ECON-063**: Partial unstake settles first — on any position shrink, is `pending = accrued − reward_debt` computed and paid out BEFORE the principal is reduced, then `reward_debt` reset against the new smaller principal? (PASS: settle-then-shrink; FAIL: `reward_debt` is rescaled proportionally without settling — independent floor divisions let an attacker loop `partial_unstake(1) + claim` to mint rewards with zero elapsed time. (adapted from safe-solana-builder shared-base §21.1))
- [ ] **ECON-064**: The `pending = accrued − reward_debt` formula is applied on EVERY payout path — claim, unstake, restake, compound, withdraw, liquidate, emergency-exit — and each sets `reward_debt = accrued` after paying. (PASS: all paths identical; FAIL: e.g. `claim` subtracts `reward_debt` but `unstake` does not — claim-then-unstake pays the same rewards twice = Critical. (adapted from safe-solana-builder shared-base §21.2))
- [ ] **ECON-065**: The global accumulator (`acc_reward_per_share` / `reward_per_token_stored`) is brought current BEFORE `total_staked` (the denominator) is mutated by any stake/unstake. (PASS: accrue-then-mutate; FAIL: `total_staked` changes first, so already-elapsed rewards are divided by the new stake — over/under-distributing to everyone. Grep for the order of `acc_reward_per_share +=` vs `total_staked +=/-=`.)
- [ ] **ECON-066**: Per-position snapshot vs global accumulator are consistent — the position stores `reward_per_token_paid` (or `reward_debt`) captured at the SAME scale/units as the global accumulator, and both are updated in the same instruction. (PASS: snapshot taken against the just-updated global value; FAIL: position checkpointed against a stale or differently-scaled accumulator — drift accumulates into free or lost yield.)
- [ ] **ECON-067**: Precision — is `acc_reward_per_share` scaled by a large factor (e.g. `1e12`/`PRECISION`) and are intermediate products widened to `u128` before the final divide, following multiply-before-divide? (PASS: `(shares as u128 * acc_per_share) / PRECISION` with checked ops; FAIL: `u64` math or divide-before-multiply — truncation zeroes small stakers' rewards or rounds in the attacker's favor. (adapted from safe-solana-builder shared-base §3.2))
- [ ] **ECON-068**: Share-price / dead-share insolvency — is total owed (sum of positions' claimable) guaranteed `<= available` in the reward source, and does a yield-accrual path raise the accounting numerator (`total_staked += yield`) independently of share supply so the exchange rate actually moves? (PASS: numerator updated on yield + `owed <= available` invariant asserted; FAIL: rewards paid from principal vault, or exchange rate frozen because yield never updates `total_staked` — structurally insolvent from the first claim. (adapted from safe-solana-builder shared-base §21.4 / §21.7))
- [ ] **ECON-069**: First-staker / `total_staked == 0` guard — when stake or reward supply is zero, does the accumulator update short-circuit (skip the `reward / total_staked` divide) and is the first depositor protected via dead shares, a minimum initial stake, or virtual balances? (PASS: zero-guard present AND inflation mitigation; FAIL: division-by-zero panic on first interaction, or first staker dust-stakes then donates to inflate the exchange rate and steals from later stakers via rounding. (adapted from safe-solana-builder shared-base §21.5))
- [ ] **ECON-070**: Settle-before-rate-change — when `reward_rate` (or reward-per-second/emission) is updated, are all positions settled to the current moment (global accumulator flushed) BEFORE the new rate takes effect? (PASS: `update_reward` flushes accumulator to `now`, then writes the new rate — the new rate applies only going forward; FAIL: a single mutable global rate multiplied by `total_elapsed` retroactively re-prices all history — attackers front-run a rate increase to backdate yield. (adapted from safe-solana-builder shared-base §21.3))
