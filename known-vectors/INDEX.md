# Known Attack Vectors — Index

One line per vector. Click to see the full multi-step verification procedure.

## How to Contribute

1. Create a new file: `NNN-short-name.md` (next available number)
2. Follow the existing format: YAML frontmatter + `### N — Title` + severity + real-world example + verification procedure with numbered steps
3. Add your entry to this index
4. Submit a PR

### Crypto / On-Chain (1-30)

| # | Vector | Severity |
|---|--------|----------|
| 1 | [Private Key Leak](001-private-key-leak.md) | 10 |
| 2 | [Flash Loan Price Manipulation](002-flash-loan-price-manipulation.md) | 10 |
| 3 | [Reentrancy (CPI)](003-reentrancy-cpi.md) | 10 |
| 4 | [Missing Access Control](004-missing-access-control.md) | 10 |
| 5 | [Oracle Manipulation](005-oracle-manipulation.md) | 9 |
| 6 | [First Depositor / Share Inflation](006-first-depositor-share-inflation.md) | 9 |
| 7 | [MEV Sandwich Attack](007-mev-sandwich-attack.md) | 7 |
| 8 | [Rug Pull / Admin Backdoor](008-rug-pull-admin-backdoor.md) | 10 |
| 9 | [Unchecked CPI Target](009-unchecked-cpi-target.md) | 9 |
| 10 | [PDA Confusion / Type Cosplay](010-pda-confusion-type-cosplay.md) | 8 |
| 11 | [Integer Overflow / Underflow](011-integer-overflow-underflow.md) | 9 |
| 12 | [Arithmetic Rounding Exploit](012-arithmetic-rounding-exploit.md) | 7 |
| 13 | [Missing Signer Check](013-missing-signer-check.md) | 10 |
| 14 | [Account Reinitialization](014-account-reinitialization.md) | 8 |
| 15 | [Unchecked Account Owner](015-unchecked-account-owner.md) | 9 |
| 16 | [Token Account Mismatch](016-token-account-mismatch.md) | 8 |
| 17 | [Vault Donation Attack](017-vault-donation-attack.md) | 7 |
| 18 | [Fee-on-Transfer Token Exploit](018-fee-on-transfer-token-exploit.md) | 7 |
| 19 | [Freeze Authority Griefing](019-freeze-authority-griefing.md) | 6 |
| 20 | [Program Upgrade Hijack](020-program-upgrade-hijack.md) | 10 |
| 21 | [Governance Attack (Vote Buying)](021-governance-attack-vote-buying.md) | 8 |
| 22 | [Bridge Exploit (Fake Proof)](022-bridge-exploit-fake-proof.md) | 10 |
| 23 | [Token-2022 Transfer Hook Attack](023-token-2022-transfer-hook-attack.md) | 7 |
| 24 | [Stale/Missing Account Close](024-stale-missing-account-close.md) | 5 |
| 25 | [Compute Budget Exhaustion DoS](025-compute-budget-exhaustion-dos.md) | 6 |
| 26 | [PDA Seed Collision](026-pda-seed-collision.md) | 8 |
| 27 | [Missing Discriminator Check](027-missing-discriminator-check.md) | 8 |
| 28 | [Front-Running Transaction](028-front-running-transaction.md) | 6 |
| 29 | [Withdraw-Before-Update Race](029-withdraw-before-update-race.md) | 8 |
| 30 | [Infinite Mint / Uncapped Supply](030-infinite-mint-uncapped-supply.md) | 10 |

### Backend / API (31-55)

| # | Vector | Severity |
|---|--------|----------|
| 31 | [NoSQL Injection (MongoDB)](031-nosql-injection-mongodb.md) | 8 |
| 32 | [SQL Injection](032-sql-injection.md) | 9 |
| 33 | [Mass Assignment (Vibe Coding)](033-mass-assignment-vibe-coding.md) | 7 |
| 34 | [BaaS Auth Bypass (Supabase/Firebase)](034-baas-auth-bypass-supabase-firebase.md) | 9 |
| 35 | [JWT Algorithm Confusion](035-jwt-algorithm-confusion.md) | 8 |
| 36 | [SSRF (Server-Side Request Forgery)](036-ssrf-server-side-request-forgery.md) | 8 |
| 37 | [CORS Misconfiguration](037-cors-misconfiguration.md) | 7 |
| 38 | [IDOR (Insecure Direct Object Reference)](038-idor-insecure-direct-object-reference.md) | 7 |
| 39 | [Rate Limiting Bypass](039-rate-limiting-bypass.md) | 6 |
| 40 | [Command Injection](040-command-injection.md) | 9 |
| 41 | [Path Traversal / LFI](041-path-traversal-lfi.md) | 8 |
| 42 | [XML External Entity (XXE)](042-xml-external-entity-xxe.md) | 7 |
| 43 | [Prototype Pollution](043-prototype-pollution.md) | 7 |
| 44 | [Server-Side Template Injection](044-server-side-template-injection.md) | 8 |
| 45 | [Webhook Forgery](045-webhook-forgery.md) | 7 |
| 46 | [GraphQL Introspection / Depth Attack](046-graphql-introspection-depth-attack.md) | 6 |
| 47 | [WebSocket Hijacking](047-websocket-hijacking.md) | 7 |
| 48 | [ReDoS (Regex Denial of Service)](048-redos-regex-denial-of-service.md) | 6 |
| 49 | [HTTP Response Splitting](049-http-response-splitting.md) | 6 |
| 50 | [Session Fixation](050-session-fixation.md) | 7 |
| 51 | [Account Enumeration](051-account-enumeration.md) | 5 |
| 52 | [Unbounded Request Body DoS](052-unbounded-request-body-dos.md) | 6 |
| 53 | [Missing Wallet Signature Verification](053-missing-wallet-signature-verification.md) | 9 |
| 54 | [Default Credentials in Production](054-default-credentials-in-production.md) | 8 |
| 55 | [Exposed Debug/Admin Endpoints](055-exposed-debug-admin-endpoints.md) | 7 |

### Frontend / Client-Side (56-75)

| # | Vector | Severity |
|---|--------|----------|
| 56 | [XSS via SVG / Image Injection](056-xss-via-svg-image-injection.md) | 7 |
| 57 | [Stored XSS (User Content)](057-stored-xss-user-content.md) | 8 |
| 58 | [DOM-Based XSS](058-dom-based-xss.md) | 7 |
| 59 | [Clickjacking](059-clickjacking.md) | 6 |
| 60 | [OAuth State Forgery (CSRF via OAuth)](060-oauth-state-forgery-csrf-via-oauth.md) | 7 |
| 61 | [Sensitive Data in URL Parameters](061-sensitive-data-in-url-parameters.md) | 5 |
| 62 | [Client-Side Auth Bypass](062-client-side-auth-bypass.md) | 7 |
| 63 | [PostMessage Origin Bypass](063-postmessage-origin-bypass.md) | 6 |
| 64 | [LocalStorage Token Theft](064-localstorage-token-theft.md) | 6 |
| 65 | [Clipboard Hijacking (Crypto Address)](065-clipboard-hijacking-crypto-address.md) | 7 |
| 66 | [CSS Exfiltration](066-css-exfiltration.md) | 5 |
| 67 | [Wallet Blind Signing Exploit](067-wallet-blind-signing-exploit.md) | 8 |
| 68 | [Subresource Integrity Bypass](068-subresource-integrity-bypass.md) | 6 |
| 69 | [Third-Party Script Compromise](069-third-party-script-compromise.md) | 7 |
| 70 | [Open Redirect](070-open-redirect.md) | 5 |
| 71 | [Missing CSP (Content Security Policy)](071-missing-csp-content-security-policy.md) | 6 |
| 72 | [API Key Exposure in Client Bundle](072-api-key-exposure-in-client-bundle.md) | 7 |
| 73 | [Dangling DNS / Subdomain Takeover](073-dangling-dns-subdomain-takeover.md) | 7 |
| 74 | [Insecure External Link (no rel)](074-insecure-external-link-no-rel.md) | 3 |
| 75 | [Console Data Leak in Production](075-console-data-leak-in-production.md) | 4 |

### DevOps / Supply Chain (76-100)

| # | Vector | Severity |
|---|--------|----------|
| 76 | [Dependency Confusion (Substitution Attack)](076-dependency-confusion-substitution-attack.md) | 9 |
| 77 | [Malicious npm Package (Typosquatting)](077-malicious-npm-package-typosquatting.md) | 8 |
| 78 | [Secrets in Git History](078-secrets-in-git-history.md) | 10 |
| 79 | [.env File Committed to Repo](079-env-file-committed-to-repo.md) | 9 |
| 80 | [CI/CD Pipeline Injection](080-ci-cd-pipeline-injection.md) | 9 |
| 81 | [Insecure Docker Configuration](081-insecure-docker-configuration.md) | 7 |
| 82 | [Exposed Admin / Debug Endpoints in Production](082-exposed-admin-debug-endpoints-in-production.md) | 8 |
| 83 | [Missing Rate Limiting on Critical Endpoints](083-missing-rate-limiting-on-critical-endpoints.md) | 7 |
| 84 | [Prototype Pollution](084-prototype-pollution.md) | 7 |
| 85 | [Server-Side Request Forgery (SSRF)](085-server-side-request-forgery-ssrf.md) | 8 |
| 86 | [Insecure Deserialization](086-insecure-deserialization.md) | 8 |
| 87 | [Insufficient Logging & Monitoring](087-insufficient-logging-monitoring.md) | 6 |
| 88 | [Insecure CORS Configuration](088-insecure-cors-configuration.md) | 7 |
| 89 | [Unpatched Server Dependencies](089-unpatched-server-dependencies.md) | 7 |
| 90 | [Missing HTTPS / TLS Misconfiguration](090-missing-https-tls-misconfiguration.md) | 8 |
| 91 | [Upgrade Authority Not Secured](091-upgrade-authority-not-secured.md) | 10 |
| 92 | [DNS Hijacking / Domain Takeover](092-dns-hijacking-domain-takeover.md) | 9 |
| 93 | [Improper Error Handling (Error Leak)](093-improper-error-handling-error-leak.md) | 5 |
| 94 | [Missing Input Length Limits](094-missing-input-length-limits.md) | 6 |
| 95 | [Insecure Randomness](095-insecure-randomness.md) | 7 |
| 96 | [Missing Security Headers](096-missing-security-headers.md) | 5 |
| 97 | [Stale / Leaked Development Credentials](097-stale-leaked-development-credentials.md) | 8 |
| 98 | [Broken Access Control on API Endpoints](098-broken-access-control-on-api-endpoints.md) | 8 |
| 99 | [Insecure WebSocket Connections](099-insecure-websocket-connections.md) | 6 |
| 100 | [Insufficient Backup / Disaster Recovery](100-insufficient-backup-disaster-recovery.md) | 7 |

### On-Chain — Modern Surface (101-109)

> Added in v4.4. Focus: sysvars, precompiles, lookup tables, PDA bump canonicalization, Token-2022 extensions, account revival, ATA assumptions, token decimals, and native/Pinocchio (p-token) programs.

| # | Vector | Severity |
|---|--------|----------|
| 101 | [Sysvar Spoofing & Instructions-Sysvar Introspection](101-sysvar-spoofing-instructions-introspection.md) | 8 |
| 102 | [Precompile Signature Verification Bypass (Ed25519/Secp256k1)](102-precompile-signature-verification-bypass.md) | 9 |
| 103 | [Address Lookup Table (ALT) Manipulation](103-address-lookup-table-manipulation.md) | 7 |
| 104 | [Non-Canonical Bump / PDA Derivation Confusion](104-non-canonical-bump-pda-derivation-confusion.md) | 7 |
| 105 | [Token-2022 Extension Abuse (permanent delegate / frozen-default / fee / confidential / mint-close)](105-token-2022-extension-abuse.md) | 8 |
| 106 | [Account Revival / Zombie After Close](106-account-revival-zombie-after-close.md) | 8 |
| 107 | [Fake / Non-Canonical Associated Token Account (ATA)](107-fake-non-canonical-associated-token-account.md) | 8 |
| 108 | [Token Decimals & Cross-Mint Amount Confusion](108-token-decimals-cross-mint-amount-confusion.md) | 7 |
| 109 | [Pinocchio / p-token — Missing Manual Validation in Zero-Copy Native Programs](109-pinocchio-ptoken-missing-manual-validation.md) | 8 |

---

## Known Duplicates & Consolidation Map

The off-chain set (1-100) contains six near-duplicate pairs (same root cause catalogued under two
categories). They are intentionally retained so both the "Backend" and "DevOps" reading paths stay
complete, but an auditor should **evaluate each pair once and cross-reference the verdict** — do not
double-count them as independent coverage. Severities are aligned to the higher of the pair.

| Canonical | Duplicate of | Topic | Aligned Severity |
|-----------|--------------|-------|------------------|
| 036 | 085 | SSRF | 8 |
| 037 | 088 | CORS misconfiguration | 7 |
| 043 | 084 | Prototype pollution | 7 |
| 055 | 082 | Exposed admin/debug endpoints | 8 |
| 039 | 083 | Rate limiting (bypass / missing) | 7 |
| 047 | 099 | WebSocket security | 7 |

**Distinct concepts:** 103 (109 files − 6 duplicate pairs).

---

**Total vector files:** 109 (100 original + 9 added in v4.4)
**Distinct concepts:** 103 (after consolidating 6 duplicate pairs)
**Categories:** 4 (crypto, backend, frontend, devops)
**Severity range:** 3-10
