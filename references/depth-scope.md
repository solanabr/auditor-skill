# Depth scope: what Quick and CI read

`/auditor:quick-scan` and `/auditor:diff-audit`, interactive and with `--ci`, read this file first, before any checklist section or known-vector file. It is the only place their selection lives. Standard (`/auditor:audit`) and Full (`/auditor:audit-cycle`) do not use it: they take the whole scope table of `SKILL.md`. What a Quick or CI run leaves out is out of that depth's declared scope (`OUTPUT-RULES.md` Rule 0), and the report lists it once (§8).

A run uses it in this order:
1. Work out the domains (§1) and, for diff-audit, the kind of each changed file (§4), with Grep over the code, never by judgment.
2. Write the selection to `audit_<n>/scope.md` in the form of §9, with the Write tool. No checklist section and no vector file is read before it; `known-vectors/INDEX.md`, whose cells select the rows, may be.
3. Read exactly what scope.md lists: each section with the Read tool from its `## ` heading to the next one, which is its Start line with its Lines count as the limit (when the line at Start is not the heading, Grep the file for the heading and read from there to the next `## `); each vector file whole.
4. Before the report, check the reads against scope.md, and read any it lists that is missing. A section or file scope.md lists and the run leaves unread is an early stop (`corpus-pass`).

## 1. Domains and markers

A marker is a backticked token of a Gate cell below, of a row's **Load when (markers)** cell in `known-vectors/INDEX.md`, or of this table. It matches case-insensitively, as a substring, in a file that is not a test, a doc, vendored code or a lockfile. Prose words in a cell never select anything.
- Tests: a path holding `test/`, `tests/`, `__tests__/`, `spec/` or `fixtures/`, or a name holding `_test.`, `.test.` or `.spec.`.
- Docs: `*.md` files, and paths under `docs/`.
- Vendored: paths under `vendor/`, `node_modules/`, `third_party/`, `target/`, `dist/` or `build/`.
- The files searched are those of the scan's scope for quick-scan, and the whole changed files for diff-audit. A changed file's 1-hop neighbours are evidence, never selectors.

| Domain | Detected when |
|---|---|
| on-chain | a `.rs` file holds `#[program]`, `entrypoint!`, `program_entrypoint!` or `lazy_program_entrypoint!`, or an `Anchor.toml` holds `[programs.` |
| backend | a file imports or requires `express`, `fastify`, `koa`, `@nestjs/`, `hono`, `axum`, `actix-web`, `rocket`, `flask`, `fastapi` or `django`, or a path holds `pages/api/` or `app/api/` |
| frontend | a `.tsx`, `.jsx`, `.vue` or `.svelte` file |
| ai-agent | an `.mcp.json` file, or a file holds `@anthropic-ai/sdk`, `openai`, `langchain`, `@modelcontextprotocol/sdk`, `solana-agent-kit` or `elizaos` |
| rust-service | a `.rs` file outside every on-chain crate holds `tokio::main`, `axum` or `actix_web` |
| python | a `.py` file |
| keys | a file holds `Keypair`, `secretKey`, `fromSecretKey`, `secret_key`, `mnemonic`, `bip39`, `derivePath`, `SigningKey`, `read_keypair_file` or `private_key` |
| workflows | a `.github/workflows/*.yml` or `.github/workflows/*.yaml` file, a `.gitlab-ci.yml` or a `Jenkinsfile` inside the scope |
| devops | every repository |

## 2. Quick: checklist sections

quick-scan selects each section of a detected domain. A gated section is selected only when one of its Gate markers occurs. A selected section is read whole, and its verdicts follow from the code: an item the code does not reach shares the section's one N/A line (§8).

| Domain | File | Section | Start | Lines | Gate |
|---|---|---|---|---|---|
| on-chain | `checklists/01-program-account-validation.md` | §1.1 Account Ownership Checks | 21 | 12 |  |
| on-chain | `checklists/01-program-account-validation.md` | §1.2 Account Discriminator & Type Cosplay | 34 | 9 |  |
| on-chain | `checklists/01-program-account-validation.md` | §1.3 Account Constraint Validation (Anchor `#[account(...)]`) | 44 | 16 |  |
| on-chain | `checklists/01-program-account-validation.md` | §1.4 Remaining Accounts Validation | 61 | 10 |  |
| on-chain | `checklists/01-program-account-validation.md` | §1.5 Account Size & Rent | 72 | 7 |  |
| on-chain | `checklists/01-program-account-validation.md` | §1.6 Token Account Validation | 80 | 10 |  |
| on-chain | `checklists/01-program-account-validation.md` | §1.7 Reinitialization Protection | 91 | 7 |  |
| on-chain | `checklists/01-program-account-validation.md` | §1.11 Lamport Donation & Runtime-Level Account Safety | 139 | 6 |  |
| on-chain | `checklists/01-program-account-validation.md` | §1.12 Account Pre-Creation DoS & Unsafe Deserialization | 146 | 6 |  |
| on-chain | `checklists/02-program-access-control.md` | §2.1 Signer Verification | 11 | 12 |  |
| on-chain | `checklists/02-program-access-control.md` | §2.2 Role-Based Access Control | 24 | 11 |  |
| on-chain | `checklists/02-program-access-control.md` | §2.7 Off-Chain-Signed Authority Grants & Admin-Set Mutation | 79 | 9 |  |
| on-chain | `checklists/03-program-arithmetic-safety.md` | §3.1 Overflow & Underflow Prevention | 11 | 11 |  |
| on-chain | `checklists/03-program-arithmetic-safety.md` | §3.3 Division Safety | 34 | 10 |  |
| on-chain | `checklists/03-program-arithmetic-safety.md` | §3.4 Share Math Specific | 45 | 11 |  |
| on-chain | `checklists/03-program-arithmetic-safety.md` | §3.5 Fee Calculation | 57 | 12 |  |
| on-chain | `checklists/04-program-cpi-pda.md` | §4.1 CPI Target Validation | 11 | 12 |  |
| on-chain | `checklists/04-program-cpi-pda.md` | §4.3 PDA Derivation Safety | 44 | 15 |  |
| on-chain | `checklists/04-program-cpi-pda.md` | §4.4 invoke_signed Safety | 60 | 10 |  |
| on-chain | `checklists/04-program-cpi-pda.md` | §4.6 CPI Reentrancy & Composability | 97 | 9 |  |
| on-chain | `checklists/05-program-state-machine.md` | §5.2 Withdrawal Lifecycle | 22 | 20 |  |
| on-chain | `checklists/05-program-state-machine.md` | §5.3 Fund Lifecycle | 43 | 12 |  |
| on-chain | `checklists/05-program-state-machine.md` | §5.5 Transition Guard Consistency | 65 | 8 |  |
| on-chain | `checklists/06-program-economic-logic.md` | §6.2 Sandwich & MEV Attacks | 30 | 9 |  |
| on-chain | `checklists/06-program-economic-logic.md` | §6.3 First Depositor / Share Inflation Attack | 40 | 7 |  |
| on-chain | `checklists/06-program-economic-logic.md` | §6.5 Fee Exploitation | 59 | 10 |  |
| on-chain | `checklists/06-program-economic-logic.md` | §6.6 Manager Trust & Rug Pull Vectors | 70 | 12 |  |
| on-chain | `checklists/06-program-economic-logic.md` | §6.14 Vault & Withdrawal Integrity | 164 | 10 |  |
| on-chain | `checklists/07-program-opsec-governance.md` | §7.1 Program Upgrade Authority | 11 | 14 |  |
| on-chain | `checklists/07-program-opsec-governance.md` | §7.2 Backdoor Detection | 26 | 16 |  |
| on-chain | `checklists/07-program-opsec-governance.md` | §7.4 Multisig Configuration | 56 | 9 |  |
| on-chain | `checklists/07-program-opsec-governance.md` | §7.6 Timelock Analysis | 78 | 11 |  |
| on-chain, gated | `checklists/01-program-account-validation.md` | §1.8 SPL Token & Token-2022 Extension Safety | 99 | 12 | `token_2022` · `spl_token_2022` · `transfer_hook` · `TransferFee` · `get_extension` · `PermanentDelegate` |
| on-chain, gated | `checklists/01-program-account-validation.md` | §1.9 Sysvar & Precompile Account Safety | 112 | 13 | `sysvar` · `instructions_sysvar` · `ed25519` · `secp256k1` · `load_instruction_at` |
| on-chain, gated | `checklists/01-program-account-validation.md` | §1.10 Native / Pinocchio (No-Anchor) Program Safety | 126 | 12 | `pinocchio` · `p-token` · `no_std`, or an on-chain crate with no `anchor_lang` |
| on-chain, gated | `checklists/06-program-economic-logic.md` | §6.1 Flash Loan Attacks | 22 | 7 | `flash` · `flashloan` |
| on-chain, gated | `checklists/06-program-economic-logic.md` | §6.9 Oracle Manipulation | 102 | 9 | `pyth` · `switchboard` · `oracle` · `get_price` · `PriceUpdate` |
| on-chain, gated | `checklists/06-program-economic-logic.md` | §6.13 Bonding-Curve / AMM Integrity | 153 | 10 | `bonding_curve` · `virtual_reserves` · `curve` · `swap` · `reserve` |
| on-chain, gated | `checklists/07-program-opsec-governance.md` | §7.9 Stake & Pre-Signed Governance Safety | 110 | 5 | `stake` · `StakeAuthorize` · `withdrawer` · `durable_nonce` · `advance_nonce` · `nonce_account` |
| backend | `checklists/09-backend-security.md` | §9.1 Authentication & Wallet Verification | 11 | 12 |  |
| backend | `checklists/09-backend-security.md` | §9.2 Input Validation & Injection Prevention | 24 | 12 |  |
| backend | `checklists/09-backend-security.md` | §9.11 IDOR & Mass Assignment | 121 | 7 |  |
| backend | `checklists/09-backend-security.md` | §9.13 Advanced Injection & Protocol Safety | 141 | 12 |  |
| backend | `checklists/09-backend-security.md` | §9.14 Custody, Fund-Moving Auth & Off-Chain/On-Chain Consistency | 154 | 5 |  |
| frontend | `checklists/10-frontend-security.md` | §10.1 Cross-Site Scripting (XSS) Prevention | 11 | 10 |  |
| frontend | `checklists/10-frontend-security.md` | §10.2 Secret & Key Exposure | 22 | 10 |  |
| frontend | `checklists/10-frontend-security.md` | §10.5 Transaction Security (Wallet Integration) | 54 | 13 |  |
| frontend | `checklists/10-frontend-security.md` | §10.8 Third-Party Script Safety | 90 | 8 |  |
| frontend | `checklists/10-frontend-security.md` | §10.10 Advanced Client-Side Attacks | 109 | 9 |  |
| ai-agent | `checklists/19-ai-agent-security.md` | §19.2 Signing Discipline | 23 | 8 |  |
| ai-agent | `checklists/19-ai-agent-security.md` | §19.3 MCP Tool Trust | 32 | 8 |  |
| ai-agent | `checklists/19-ai-agent-security.md` | §19.4 Injection Surface (On-Chain Data → LLM) | 41 | 7 |  |
| rust-service | `checklists/20-rust-offchain-services.md` | §20.1 Panic-as-DoS (Untrusted Input Must Not Crash the Process) | 15 | 10 |  |
| rust-service | `checklists/20-rust-offchain-services.md` | §20.5 Secrets & Key Material | 51 | 7 |  |
| python | `checklists/14-python-safety.md` | §14.1 Injection & Input Handling | 11 | 14 |  |
| every repository | `checklists/12-secrets-opsec.md` | §12.1 No Hardcoded Secrets | 11 | 12 |  |
| every repository | `checklists/12-secrets-opsec.md` | §12.5 Wallet & Program Key Safety | 55 | 10 |  |
| every repository | `checklists/12-secrets-opsec.md` | §12.8 Signing-Key Generation & Signing-Service Integrity | 84 | 3 |  |
| every repository | `checklists/11-supply-chain.md` | §11.1 Known Compromised Packages | 13 | 8 |  |
| every repository | `checklists/11-supply-chain.md` | §11.8 2025 Solana-Targeted Supply-Chain TTPs | 86 | 5 |  |
| workflows | `checklists/13-deployment-infrastructure.md` | §13.9 CI/CD Pipeline Security | 103 | 7 |  |

## 3. Quick: vector rows

quick-scan selects, from `known-vectors/INDEX.md`:
- **The `always (…)` rows of severity 7 or more of the detected domains.** The phase in the cell names the domain: crypto is on-chain, custody is keys, and devops is every repository.
  - crypto: 001, 004, 008, 013, 015, 020, 137;
  - backend: 054, 055;
  - frontend: 062, 072, 073;
  - devops: 076, 077, 078, 079, 082, 083, 089, 091, 092, 097, 098, 100;
  - ai-agent: 110;
  - custody: 124.
- **The marker rows of severity 9 or more whose markers occur:** 002, 003, 005, 006, 009, 011, 022, 030, 032, 034, 040, 053, 080, 102, 116, 119, 139, 140.
- **141**, read as a marker row: its markers are the backticked tokens after "when … infra-as-code:".
- **035** when backend is detected; **021** when §7.9's Gate fires; **130** when one of its markers occurs.
- **001 and 124** whenever keys is detected, whatever else is.

A row's severity is its own Severity column. Of a duplicate pair, read the canonical file once, and give the other the line "see KV-<canonical>": 036 for 085, 037 for 088, 043 for 084, 055 for 082, 039 for 083, and 047 for 099.

## 4. CI: sections by kind of changed file

diff-audit selects, for each kind its changed files hold:

| A changed file that is … | Selects |
|---|---|
| on-chain program source: a `.rs` file in an on-chain crate (§1) | the on-chain sections of §2, and each on-chain gated section whose Gate markers occur in the changed files |
| backend, frontend, ai-agent, rust-service or python code (§1, by the file itself) | that domain's sections of §2 |
| a manifest or lockfile | `checklists/11-supply-chain.md` §11.1 and §11.8 (§2's rows), and §11.11, with the CI budget of §7 |
| a workflow (§1) | `checklists/13-deployment-infrastructure.md` §13.9 (§2's row), and §13.13 |
| a key or keypair file, an `.env*` file, or a file holding `SECRET`, `PRIVATE_KEY`, `api-key=` or `?api-key` | `checklists/12-secrets-opsec.md` §12.1 and §12.5 (§2's rows) |
| a test, a doc or generated code only | nothing: it is counted, not read |

The CI-only rows:

| File | Section | Start | Lines |
|---|---|---|---|
| `checklists/11-supply-chain.md` | §11.11 Dependency-Update Review (Delta) | 112 | 48 |
| `checklists/13-deployment-infrastructure.md` | §13.13 GitHub Actions Trigger Trust | 180 | 11 |

A section is selected once, whatever number of files select it. The most a change can select is 62 sections, about 103 KB, and only when it touches every kind of file. A change to on-chain program source selects at most 39 (41 when a changed file is also a key file), and 46 when it also changes a manifest or lockfile, a workflow and a key file.

## 5. CI: vector rows

- **Floor, on marker rows only:** min(`--fail-on`, 7) − 1, so 6 by default. Rule 1 sets no cap per row: a row of severity 6 can produce a finding of 7.
- **The marker rows at or above the floor** whose markers occur in the changed files.
- **Every `always (…)` row** of the domains the changed files detect (§3's phases), whatever the floor, except the repository-level rows below. Each of those is read only when a changed file holds one of its subject markers. Otherwise the report gives it the fixed line "repository-level; /auditor:quick-scan and /auditor:audit cover it".

| Row | Subject markers, in a changed file's path or text |
|---|---|
| 020, 091 | `Anchor.toml`, `set-upgrade-authority`, `program deploy`, `upgrade_authority`, `BPFLoaderUpgradeab` |
| 092 | `CNAME`, `route53`, `dns` |
| 100 | `backup`, `pg_dump`, `snapshot`, `restore` |
| 137 | `vendor/`, `third_party/`, `[patch` |
| 039, 083, 098 | a route definition: `app.get(`, `app.post(`, `router.`, `Router(`, `@Get(`, `@Post(`, `.route(`, or `rateLimit`, `rate_limit`, `throttle` |
| 055, 082 | `/admin`, `/debug`, `/internal`, `debug=` |

## 6. CI: the changed-code budget

- Count the changed lines with `git-ro.sh diff --numstat <base>..<head>`, leaving out tests, docs, generated code and lockfiles; lockfiles take §7.
- Review at most 5,000 changed lines, in step 3's risk order: on-chain program source first, then files that remove security code, then step 3's HIGH files (auth, crypto, value transfer), then the rest by changed lines, largest first. A file is reviewed whole or not at all.
- Above 5,000, by default: review the first 5,000 in that order, and PR-REPORT.md says "changed lines not reviewed: N of M" and names the files. The verdict is on what was reviewed. With `--over-budget fail`, the run stops instead (`stopped: line-budget`), and the verdict fails.
- The reviewed files are the run's declared scope (Rule 0). The rest render as out of scope.

## 7. CI: the lockfile budget

For a manifest or lockfile, diff-audit runs `checklists/11-supply-chain.md` §11.11 with its CI budget, in place of its steps 2 to 4:
- `lock-delta.sh --run audit_<n> set <base>..<head>`: the name@version set of every changed lockfile, with its marks. No lockfile is read by hand.
- `deps.sh lock-budget --run audit_<n> audit_<n>/deps/lock-set-<k>.tsv`: one publish-age request per public name of the set, new packages and new versions alike (`AUDITOR_PUBLISH_AGE`), then every key handler and at most 40 other entries fetched old and new and swept, counts first.
- Lockfiles add no changed lines to §6's budget. `deps-artifacts` is required when a `Cargo.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` or `bun.lock` changes. Other lockfiles and manifests are checked at metadata level only, and a Go module is never fetched.

## 8. What the selection leaves out (Rules 0 and 4)

- **A selected section's items the code does not reach** share one line per section: `[N/A — no site in scope] <first id>..<last id>`, or the ids when they are not a run.
- **An item of a selected section that needs a call this depth does not make**, such as DEP-067's resolution of an action's SHA to a tag, gets `[N/A at this depth — needs <call>]`.
- **The sections the selection leaves out:** one line per checklist in Coverage & Limitations, "<checklist> §…, §…: outside <depth>'s scope; /auditor:audit gives their verdicts". No verdict per item.
- **The vector rows left out:** one line per INDEX section, "KV-…, KV-…: outside <depth>'s scope (<the rule that left them out>); /auditor:audit gives their verdicts".

<depth> is Quick for quick-scan and CI for diff-audit. This is Rule 4's depth exception (`OUTPUT-RULES.md`).

## 9. The selection file

`audit_<n>/scope.md`, written with the Write tool before any checklist section or vector file is read:

```text
# Scope: <command> <path, or base..head> at <full commit id>
## Domains
<domain>: <marker> in <file>
## Sections
<checklist file> §<n.m> lines <start>-<end>
## Rows
KV-<nnn> <file>
## Left out
<the lines of §8>
## Budget
<diff-audit only> changed lines reviewed: <n> of <m>; lockfile budget: <n> selected of <m>
```
