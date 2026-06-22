---
id: 105
title: "Token-2022 Extension Abuse (Permanent Delegate / Frozen-Default / Transfer-Fee / Confidential / Mint-Close)"
severity: 8
category: crypto
---

### 105 — Token-2022 Extension Abuse

**Severity: 8** | **Real: Emerging 2024+ surface — Token-2022 (Token Extensions) mint configs that break protocol assumptions**

KV-023 covers transfer hooks. Token-2022 ships many other mint/account extensions that a protocol accepting arbitrary mints must reason about. Each can silently break an invariant a program assumed under classic SPL Token:

- **Permanent Delegate** — the mint authority can move/burn ANY holder's tokens at will, including the protocol's vault. A "deposited" balance is not safe.
- **Default Account State = Frozen** — newly created token accounts start frozen; transfers out can be blocked at will (griefing / locked withdrawals).
- **Transfer Fee** — the amount received is less than the amount sent; naive `amount`-based accounting over/under-credits (overlaps KV-018, but config-driven and changeable).
- **Confidential Transfer** — balances/amounts are hidden; on-chain `amount` reads are not the economic truth.
- **Interest-Bearing** — UI amount drifts from raw amount over time; valuation logic that assumes 1:1 raw↔display is wrong.
- **Mint Close Authority** — the mint can be closed and the address potentially reused/repurposed.
- **Metadata / Group Pointer** — pointers can reference attacker-controlled accounts if trusted for display or logic.

#### Verification Procedure

**Step 1: Does the protocol accept arbitrary mints or Token-2022?**
```
grep -rn --include="*.rs" -iE "token_2022|spl_token_2022|InterfaceAccount|token_interface|TokenInterface" programs/
```
- If only a fixed allowlist of classic SPL mints (e.g., USDC/SOL): mostly N/A — confirm the allowlist is enforced (Step 2)
- If arbitrary mints / Token-2022 interface: proceed

**Step 2: Enforce a mint allowlist OR inspect extensions**
- ✅ PASS: Only vetted mints are accepted (`address`/allowlist check), excluding hostile extension configs
- ⚠️/❌: Arbitrary mints accepted without inspecting extensions

**Step 3: Reject or handle dangerous extensions**
```
grep -rn --include="*.rs" -iE "permanent_delegate|default_account_state|transfer_fee|confidential|interest_bearing|close_authority|get_extension" programs/
```
- ✅ PASS: Program reads mint extensions and rejects `PermanentDelegate`, `DefaultAccountState::Frozen`, `MintCloseAuthority`, confidential, and unexpected transfer-fee/interest configs (or explicitly supports them with correct accounting)
- ❌ FAIL: No extension inspection — a hostile mint can drain/freeze/misvalue

**Step 4: Amount accounting uses balance deltas, not declared amounts**
- ✅ PASS: Credited amount = vault balance AFTER − BEFORE (handles transfer fees correctly); uses `transfer_checked` with expected decimals
- ❌ FAIL: Credits the requested `amount`, ignoring fees/extensions

**Step 5: Freeze / permanent-delegate exposure on custody**
- ✅ PASS: Custodied funds cannot be frozen or clawed back by a third-party mint authority (or risk is documented and mint is trusted)
- ❌ FAIL: Vault holdings are subject to permanent delegate / freeze by an untrusted mint authority

**Overall verdict:**
- ✅: Allowlisted mints, or full extension inspection + delta-based accounting + transfer_checked
- ⚠️: Some extensions handled (e.g., transfer fee) but others (permanent delegate / frozen-default) unchecked
- ❌: Arbitrary Token-2022 mints accepted with no extension inspection
- N/A: Only classic SPL Token, allowlist enforced
