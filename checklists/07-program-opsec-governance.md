# 07 — OpSec & Governance Checklist

> Domain: Operational Security, Program Deployment, Governance  
> Severity if missed: CRITICAL to HIGH  
> References: Solana program upgrade authority, Squads multisig, timelock patterns

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 7.1 — Program Upgrade Authority

- [ ] **OPS-001**: What is the current upgrade authority of the deployed program? (run `solana program show <PROGRAM_ID>`)
- [ ] **OPS-002**: Is the upgrade authority a multisig (e.g., Squads v3/v4)? If it's a single wallet — flag as HIGH
- [ ] **OPS-003**: How many signers are required on the multisig? Verify threshold (e.g., 2/3, 3/5)
- [ ] **OPS-004**: Who are the individual signers on the multisig? Are they different entities?
- [ ] **OPS-005**: Are the multisig signers on hardware wallets (Ledger, etc.) or hot wallets?
- [ ] **OPS-006**: Is there a timelock on program upgrades? How many hours/days?
- [ ] **OPS-007**: If there is a timelock — is it enforced on-chain or just a team policy?
- [ ] **OPS-008**: Recommended minimum timelock: 24 hours for DeFi programs, 72 hours for critical infrastructure
- [ ] **OPS-009**: Can the upgrade authority be changed? Who can change it?
- [ ] **OPS-010**: Is the program set to non-upgradeable (immutable)? If not, should it be? Document reasoning
- [ ] **OPS-011**: If program is upgradeable — can a malicious upgrade drain all funds? (Yes, by definition — hence multisig + timelock)
- [ ] **OPS-012**: Is there a process for emergency upgrades that bypass the timelock? If yes, what are the safeguards?

## 7.2 — Backdoor Detection

- [ ] **OPS-013**: Search for hidden admin instructions — any instruction that accepts a hardcoded admin pubkey (not visible in docs/IDL)
- [ ] **OPS-014**: Search for "god mode" accounts — any account that can bypass all access control checks
- [ ] **OPS-015**: Search for conditional logic based on specific pubkeys: `if account.key() == Pubkey::new_from_array([...])` hidden checks
- [ ] **OPS-016**: Search for unused instruction handlers that could be invoked — dead code that's still callable
- [ ] **OPS-017**: Verify IDL matches the actual program binary — no undisclosed instructions
- [ ] **OPS-018**: Check for instructions that can modify the Treasury pubkey to redirect fees
- [ ] **OPS-019**: Check for instructions that can modify the Jupiter/DEX program ID to redirect swaps
- [ ] **OPS-020**: Check for instructions that can change fund manager without investor consent
- [ ] **OPS-021**: Check for instructions that can mint shares without deposit (share dilution)
- [ ] **OPS-022**: Check for instructions that can burn shares without withdrawal (theft)
- [ ] **OPS-023**: Search for `unsafe` blocks in Rust code — any usage must be documented and justified
- [ ] **OPS-024**: Search for raw pointer manipulation (`*const`, `*mut`) — should not exist in Anchor programs
- [ ] **OPS-025**: Check `declare_id!` matches between code and Anchor.toml — mismatch could mean wrong program
- [ ] **OPS-026**: Verify program binary matches published source code (verifiable builds)

## 7.3 — Key Management

- [ ] **OPS-027**: Deploy keypair — is it on a hardware wallet for mainnet?
- [ ] **OPS-028**: Deploy keypair — is it stored securely (not in repo, not on dev machine in plaintext)?
- [ ] **OPS-029**: Manager wallets — are they on hardware wallets or multisig for mainnet?
- [ ] **OPS-030**: Backend server wallet (if exists) — is it the minimum-privilege wallet?
- [ ] **OPS-031**: Backend server wallet — does it hold significant SOL/tokens? (Should only hold gas)
- [ ] **OPS-032**: API keys (Helius, Jupiter, etc.) — are they rotated regularly?
- [ ] **OPS-033**: API keys — are they scoped to minimum required permissions?
- [ ] **OPS-034**: RPC endpoint — is it a dedicated RPC (Helius/Triton) not the public endpoint?
- [ ] **OPS-035**: RPC endpoint — is the API key exposed in frontend code?
- [ ] **OPS-036**: Has any key ever been committed to git? Check `git log --all --oneline -S "secret_string"` patterns

## 7.4 — Multisig Configuration

- [ ] **OPS-037**: Is a multisig used for on-chain operations? Which platform? (Squads, Goki, Marinade, custom)
- [ ] **OPS-038**: Multisig threshold — is it > 50% of total signers? (e.g., 2/3 minimum)
- [ ] **OPS-039**: Multisig — does any single signer have disproportionate power?
- [ ] **OPS-040**: Multisig — are there backup signers in case one is compromised or unavailable?
- [ ] **OPS-041**: Multisig — can a single compromised signer change the threshold to 1/N?
- [ ] **OPS-042**: Multisig — is there a proposal expiry? Can old proposals be executed weeks later?
- [ ] **OPS-043**: Multisig — are executed transactions logged and auditable?

## 7.5 — Incident Response

- [ ] **OPS-044**: Is there a documented incident response plan?
- [ ] **OPS-045**: Can the program be paused in an emergency? By whom? How quickly?
- [ ] **OPS-046**: Is there a bug bounty program? (Immunefi, HackerOne, or self-hosted)
- [ ] **OPS-047**: Is there a security contact (security@domain.com, SECURITY.md in repo)?
- [ ] **OPS-048**: Are there monitoring alerts for large value movements from fund PDAs?
- [ ] **OPS-049**: Are there monitoring alerts for program upgrade transactions?
- [ ] **OPS-050**: Are there monitoring alerts for unusual transaction patterns (many withdrawals, large swaps)?
- [ ] **OPS-051**: Is there a war room process? Who needs to be contacted and in what order?
- [ ] **OPS-052**: Post-incident: is there a process for post-mortem analysis?

## 7.6 — Timelock Analysis

- [ ] **OPS-053**: List ALL actions that are time-locked and their durations
- [ ] **OPS-054**: Program upgrades — timelock duration: _____ hours/days
- [ ] **OPS-055**: Fee changes — timelock duration: _____ hours/days (or "none" — flag if none)
- [ ] **OPS-056**: Manager changes — timelock duration: _____ hours/days (or "none")
- [ ] **OPS-057**: Whitelist changes — timelock duration: _____ hours/days (or "none")
- [ ] **OPS-058**: Treasury address changes — timelock duration: _____ hours/days (should be "immutable")
- [ ] **OPS-059**: Emergency bypass for timelock — what triggers it? How many signers?
- [ ] **OPS-060**: Transaction cancellation — can a time-locked transaction be cancelled before execution?
- [ ] **OPS-061**: Users notified of pending time-locked changes? (On-chain event, frontend alert, Discord)

## 7.7 — Access Segregation

- [ ] **OPS-062**: Dev, staging, and production environments use completely separate keys
- [ ] **OPS-063**: No developer has production deploy access from their personal machine
- [ ] **OPS-064**: CI/CD pipeline — does it auto-deploy? If yes, what are the safeguards?
- [ ] **OPS-065**: Server access — SSH keys rotated, 2FA enabled, access logging
- [ ] **OPS-066**: Database access — separate credentials per environment, no shared passwords
- [ ] **OPS-067**: Wallet private keys — never in CI/CD environment variables in plaintext
- [ ] **OPS-068**: Secret manager used? (AWS Secrets Manager, Vault, doppler, etc.)

## 7.8 — Source Code Integrity

- [ ] **OPS-069**: Is the program source code open source?
- [ ] **OPS-070**: Does the published source match the deployed binary? (Verifiable builds via `anchor verify`)
- [ ] **OPS-071**: Can the audit check be reproduced? (`anchor build` produces same binary)
- [ ] **OPS-072**: Is the git history clean? (No force-pushes that remove commit history)
- [ ] **OPS-073**: Are there branch protection rules? (No direct push to main, required reviews)
- [ ] **OPS-074**: Is the CI/CD pipeline itself secured? (No PR can modify CI to skip checks)
- [ ] **OPS-075**: Dependencies are version-pinned (no `^` or `~` in Cargo.toml for critical deps)
