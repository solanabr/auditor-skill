# Full Repository Audit — Master Execution Plan

> This document is the step-by-step execution plan for auditing an entire repository.  
> The auditor agent reads this file and follows it from top to bottom, producing a complete report.
>
> **MANDATORY**: Read [OUTPUT-RULES.md](OUTPUT-RULES.md) FIRST — it defines the severity scale (1-10),
> the chunked execution protocol, the executive summary format, and the item-by-item output requirement.
> Every rule in OUTPUT-RULES.md overrides anything in this document if there's a conflict.

---

## PRE-FLIGHT

Before starting any phase:
1. Read [OUTPUT-RULES.md](OUTPUT-RULES.md) — the output format is non-negotiable
2. Run discovery and declare the audit SCOPE (Rule 0 in OUTPUT-RULES.md) — do NOT bulk-read the corpus
3. Load only the in-scope checklists/vectors, on demand as each phase reaches them
4. Detect languages in the repo (Rule 7 in OUTPUT-RULES.md) — this determines which checklists to apply
5. Create a session checkpoint file to track progress across chunks (Rule 3 in OUTPUT-RULES.md)
6. Remember: **walk the code file by file — never one-shot** (Rule 3)
7. Apply **Operating Safety** ([OUTPUT-RULES.md Rule 11](OUTPUT-RULES.md#rule-11-operating-safety)) before anything runs: take the execution mode recorded at intake (11a — isolated recommended, native allowed with a report caveat), list every outside service a tool contacts (11b), treat a `.git/` you did not clone yourself as untrusted (11c), and make `.gitignore` containing `*` the first file in `audit_<n>/` (11d)
8. Resolve every bundled path in this file (`tools/`, `templates/`, `scripts/`, `vendor/trailofbits/`, the corpus) from the auditor-skill root, never the working directory, which is the audited repo ([Rule 11e](OUTPUT-RULES.md#11e--bundled-paths)). The root is the absolute path the skill (`${CLAUDE_SKILL_DIR}`) or command (`${CLAUDE_PLUGIN_ROOT}`) gave you; nothing is filled in here, so it is written `<auditor-skill root>` below. The executables this plan runs: `"<auditor-skill root>/tools/auditor-tools/target/release/audit-scan"`, `"<auditor-skill root>/tools/auditor-tools/target/release/audit-mem"`, the runners `"<auditor-skill root>/scripts/runner/deps.sh"` (Step 3.2) and `"<auditor-skill root>/scripts/runner/target.sh"` (Step 3.4), the read-only git `"<auditor-skill root>/scripts/git-ro.sh"` and `"<auditor-skill root>/scripts/recipes/web3js-history.sh"` (Steps 3.2 and 3.3), the RPC reader `"<auditor-skill root>/scripts/rpc-read.sh"` (Step 3.1), and the Trail of Bits plugins when `test -d "<auditor-skill root>/vendor/trailofbits/plugins"` succeeds. A `refused:` line from one of them (exit 64) means that step did not run: record it in Coverage & Limitations, never as a PASS or an N/A. git-ro.sh, the two recipes and `target.sh --src .` refuse a checkout whose git directory holds a symbolic link (a hook installed with `ln -s`), borrows objects or has grafts, or that another user owns: ask the human to audit a fresh clone made outside the working directory, as preflight does for project config

---

## PHASE -1: SCOPE DECLARATION

Declare scope per OUTPUT-RULES Rule 0 + SKILL Scope-Gated Loading; record the Scope Coverage table below (per checklist/vector group: in-scope yes/no + trigger).

| Checklist / vector group | In scope? | Trigger |
|--------------------------|-----------|---------|
| 01–07 on-chain | yes/no | `.rs` / `Anchor.toml` |
| 08–10 off-chain (TS/web) | yes/no | `.ts` / `.tsx` |
| 14 python | yes/no | `.py` |
| 15 general language | yes/no | `.go`/`.java`/`.rb`/`.php` |
| 19 AI-agent | yes/no | `.mcp.json` / agent SDK |
| 20 off-chain Rust | yes/no | `.rs` outside `programs/` |
| 11–13, 16–18 universal | yes | any repo |

---

## PHASE 0: SETUP

### 0.1 — Identify the Repository

```
ACTION: Read the following files to establish context:
  - Anchor.toml (program ID, cluster, provider)
  - Cargo.toml (workspace members, Anchor version, Solana version)
  - package.json (root, all workspaces — dependencies, scripts)
  - .gitignore (verify secrets excluded)
  - README.md (project description, architecture)

RECORD:
  - Program ID: ___
  - Anchor version: ___
  - Solana SDK version: ___
  - Node.js dependencies count: ___
  - Git branch: ___
  - Git commit hash: ___
```

### 0.2 — Map the Codebase

```
ACTION: Use this run's own Layout table (audit_<n>/intake.md §1, Q39/Q44: source paths, test paths, build files, exclusions), and nothing from an earlier run's directory: intake copies an earlier layout into this table only on the human's yes. Without the table, use the defaults in discovery/file-map.md, OR auto-discover:
  1. List all .rs files under programs/
  2. List all .ts/.tsx files under apps/backend/src/
  3. List all .ts/.tsx files under apps/web/src/
  4. List all package.json files in the monorepo
  5. List all .env* files (should be in .gitignore)
  6. List all config files (tsconfig, anchor, cargo, turbo, etc.)

RECORD:
  - Total Rust files: ___
  - Total TS/TSX files: ___
  - Total instruction handlers: ___
  - Total API endpoints (backend routes + frontend API routes): ___
  - Exclusions applied, each with its source from the Layout table (report §2.4 Out of Scope): ___
```

### 0.3 — Build Instruction Matrix

> **Optional deterministic pre-pass.** If the bundled tools are built (`test -x "<auditor-skill root>/tools/auditor-tools/target/release/audit-scan"`, PRE-FLIGHT 8), run `"<auditor-skill root>/tools/auditor-tools/target/release/audit-scan" --contract=1 <program-path> --out audit_<n>/prescan.json` first — it emits this instruction matrix (plus the account-constraint, PDA-seed, arithmetic, and CPI tables) deterministically at ~$0, so Phase 0.2–0.4 collapse to *reading the JSON* and files with zero scan hits get a spot-check instead of a full read. Also run `"<auditor-skill root>/tools/auditor-tools/target/release/audit-mem" warm --contract=1 --program-id <id>` to load the prior protocol profile, invariants + open false-positive rulings. Use `.audit-memory/` only if you created it (`audit-mem init --contract=1` does, `.gitignore` first); `audit-mem` refuses one the repository tracks (the Rule 11d check, `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false --icase-pathspecs ls-files -- .audit-memory`, run by the tool) or one holding a link. Otherwise pass `--db audit_<n>/audit-mem.db` for a store for this run. Each call carries `--contract=1` where shown; a build older than that contract refuses it (exit 2): proceed as without the tools, and note that they need building again. Treat all pre-scan output as a *map to verify*, never as verdicts. See [references/orchestration/pre-scan.md](references/orchestration/pre-scan.md). Absent the toolchain, build the matrix by hand below.

```
ACTION: Read lib.rs → list every #[instruction] or pub fn handler.
For EACH instruction, read the instruction file and record:

| Instruction | Signer | has_one constraints | CPIs | Arithmetic ops | State mutations |
|-------------|--------|-------------------|------|----------------|-----------------|
| ...         | ...    | ...               | ...  | ...            | ...             |

Save this matrix — it's used by checklists 01-06.
```

### 0.4 — Build State Model

```
ACTION: Read every file in state/ directory. For each account struct, record:

| Account | Seeds | Size | Key fields | Mutable by |
|---------|-------|------|------------|------------|
| ...     | ...   | ...  | ...        | ...        |

Map relationships: which accounts reference which.
Identify all enums and their variants.
```

---

## PHASE 0.5: CONTEXT RECONSTRUCTION (before any verdict)

Build understanding before judgment. No checklist item may be marked `[FAIL-N≥6]` against a function that has not first been reconstructed here. *(Pattern credit: Trail of Bits `audit-context-building`.)*

For every non-trivial function (any instruction handler, any value-moving or state-mutating fn, any fn with a CPI or arithmetic), fill `templates/context-worksheet.md`:

- **Purpose** — what the function is supposed to do, from the code (not the docs).
- **Signature** — inputs (args), accounts (+ constraints), state written, each `@ L#`.
- **Block-by-block** — what each block does, what it reads / writes, why it is there.
- **≥ 3 invariants** it must preserve · **≥ 5 assumptions** about inputs / accounts / caller · **≥ 3 external-interaction risks** (CPIs, sysvars, `remaining_accounts`, oracle reads).
- **Cross-function dependencies** — shared state, ordering assumptions.

Anti-hallucination rules (mandatory):

- Every claim cites a line (`L#`).
- The words "probably", "might", "seems", "should" are banned. If you cannot state it from the code, write `UNKNOWN — needs manual review`.
- Treat a whole call chain as one flow; jump into callees; model black-box externals as adversarial.

Output worksheets to `audit_<n>/worksheets/context/{fn}.md`. These feed the Rule 5b validation gate.

---

## PHASE 1: ON-CHAIN PROGRAM AUDIT (Checklists 01-06)

### Execution Strategy

The on-chain audit proceeds **instruction-by-instruction**. For each instruction file:

1. Open the file
2. Run items from checklists 01 (account validation), 02 (access control), 03 (arithmetic), 04 (CPI/PDA) that apply
3. Record findings inline

After all instructions are reviewed individually, run the **cross-cutting** checks:
- Checklist 05 (state machine) — requires full lifecycle view
- Checklist 06 (economic/logic) — requires understanding of all instructions together

### Step 1.1 — Per-Instruction Deep Review

```
FOR EACH instruction file in programs/*/src/instructions/:

  READ the full file (accounts struct + handler function)

  CHECK (from 01-account-validation):
    - Every account type (AccountInfo vs UncheckedAccount vs Account<T>)
    - Every /// CHECK: comment has real validation
    - has_one constraints present and correct
    - seeds + bump for PDA accounts
    - remaining_accounts validation (if used)

  CHECK (from 02-access-control):
    - Signer present for value-moving operations
    - Signer linked to state via has_one
    - Role appropriate (manager/investor/delegate/permissionless)

  CHECK (from 03-arithmetic):
    - Every +, -, *, / operator — is it checked_*?
    - u128 intermediate for multiply-then-divide
    - Division by zero guards
    - Truncation safety (u128 → u64, u64 → u32)

  CHECK (from 04-cpi-pda):
    - CpiContext first arg is Pubkey (Anchor 1.0)
    - CPI targets validated (program ID)
    - from/to/authority/amount correct in each CPI
    - invoke_signed uses correct seeds
    - State mutations BEFORE CPI (checks-effects-interactions)

  RECORD: findings per instruction file
```

### Step 1.2 — Cross-Cutting State Machine Review (Checklist 05)

```
AFTER all individual instructions reviewed:

  1. Draw the withdrawal/redeem lifecycle from code (not docs)
     - Which instruction sets each status variant? (adapt to your status enum name)
     - Are all transitions present? Any dead variants?
     - Can withdrawals get stuck?

  2. Draw the overall protocol lifecycle
     - Creation → deposits → operations → withdrawals → (closure?)
     - Can every created account reach a terminal state?

  3. Verify invariants
     - total_shares == shares_mint.supply
     - total_shares == Σ(investor_position.shares)
     - Event emission for every financial operation

  RECORD: lifecycle diagrams + findings
```

### Step 1.3 — Economic & Logic Attack Review (Checklist 06)

```
AFTER understanding all instructions:

  1. Flash loan attack paths
  2. Sandwich/MEV attack paths
  3. First depositor attack scenario
  4. NAV manipulation scenarios
  5. Fee exploitation vectors
  6. Manager rug pull analysis
  7. Token-specific exploits
  8. DoS attack vectors

  RECORD: attack scenario descriptions + findings
```

---

## PHASE 2: OFF-CHAIN CODE AUDIT (Checklists 08-10)

### Step 2.1 — TypeScript Safety Sweep (Checklist 08)

```
AUTOMATED GREP COMMANDS (run all):

  # any type ban
  grep -rn ": any\b" --include="*.ts" --include="*.tsx" apps/ packages/
  grep -rn "as any" --include="*.ts" --include="*.tsx" apps/ packages/
  grep -rn "catch.*any" --include="*.ts" --include="*.tsx" apps/ packages/

  # error handling
  grep -rn "catch (e)" --include="*.ts" apps/ | grep -v "unknown"
  grep -rn "catch {}" --include="*.ts" apps/
  grep -rn "catch.*{[[:space:]]*}" --include="*.ts" apps/

  # import safety
  grep -rn "@coral-xyz/anchor" --include="*.ts" --include="*.tsx" apps/ packages/
  grep -rn "require(" --include="*.ts" apps/

  # unsafe patterns
  grep -rn "eval(" --include="*.ts" --include="*.tsx" apps/
  grep -rn "Function(" --include="*.ts" --include="*.tsx" apps/
  grep -rn "@ts-ignore\|@ts-nocheck" --include="*.ts" --include="*.tsx" apps/

  RECORD: every match with file:line
```

### Step 2.2 — Backend Security Review (Checklist 09)

```
FOR EACH route file in apps/backend/src/routes/:

  READ the full file

  CHECK:
    - Auth middleware applied (wallet signature verification)
    - Zod schema for request body
    - MongoDB queries use validated input (no raw injection)
    - On-chain verification for financial records
    - Error handling (no empty catches, no stack traces exposed)

FOR middleware/:
    - Auth: signature verification logic correct
    - Rate limiter: configured for all environments
    - Error handler: no stack traces in production

FOR services/:
    - Solana RPC: uses env var, correct commitment
    - Jupiter: API key from env, correct endpoints
    - PnL: arithmetic correctness

FOR index.ts (server entry):
    - Helmet configured
    - CORS whitelist (not *)
    - Env var validation at startup
    - Rate limiting enabled

RECORD: findings per file
```

### Step 2.3 — Frontend Security Review (Checklist 10)

```
AUTOMATED GREP COMMANDS:

  # XSS vectors
  grep -rn "dangerouslySetInnerHTML" --include="*.tsx" apps/web/
  grep -rn "document.write" --include="*.ts" --include="*.tsx" apps/web/

  # Secret exposure
  grep -rn "NEXT_PUBLIC_" apps/web/src/ --include="*.ts" --include="*.tsx"
  # → verify NONE are secrets

  # Console in production
  grep -rn "console.log" --include="*.ts" --include="*.tsx" apps/web/src/

FOR EACH API route in apps/web/src/app/api/:
  CHECK:
    - Body parsing in try-catch
    - Required field validation
    - Proxy response handling (text then parse)
    - Error status codes (400/401/502, not 500)

FOR EACH page/component:
  SPOT-CHECK:
    - next/image usage (not raw <img>)
    - Wallet state cleanup on disconnect
    - Transaction simulation before send

RECORD: findings per file
```

---

## PHASE 3: DEVOPS & OPERATIONS AUDIT (Checklists 07, 11-13)

### Step 3.1 — OpSec & Governance (Checklist 07)

```
ACTIONS (some require terminal):

  # Check upgrade authority: a read-only read through the bundled rpc-read.sh, which keeps the endpoint out
  # of argv, signs nothing and records the read in audit_<n>/disclosures.tsv (Rule 11b); --cluster devnet
  # for a devnet program, and without --cluster the RPC_URL environment variable names the endpoint
  "<auditor-skill root>/scripts/rpc-read.sh" program-show <PROGRAM_ID> --run audit_<n> --cluster mainnet-beta

  # Check for backdoors
  grep -rn "unsafe" --include="*.rs" programs/
  grep -rn "invoke(" --include="*.rs" programs/ | grep -v "invoke_signed"

  # Check IDL matches binary
  # Verify declare_id matches Anchor.toml

  # Timelock analysis — document all time-locked operations

RECORD: governance configuration + findings
```

### Step 3.2 — Supply Chain Audit (Checklist 11)

```
ACTIONS:

  # Check for compromised packages: axios 1.14.1 / 0.30.4 and the hijacked @solana/web3.js
  # 1.95.6 / 1.95.7, as exact pins and resolved versions in package.json, package-lock /
  # npm-shrinkwrap, pnpm (lockfile v5 keys too), yarn v1 + berry and bun, each followed by a
  # character that is not a digit, or at the end of a line
  grep -rnE --exclude-dir=node_modules --include='package.json' --include='package-lock.json' --include='npm-shrinkwrap.json' --include='pnpm-lock.yaml' --include='yarn.lock' --include='bun.lock' -e '(^|[^A-Za-z0-9_.-])axios[@/](npm:)?(1\.14\.1|0\.30\.4)([^0-9]|$)|/axios/-/axios-(1\.14\.1|0\.30\.4)\.tgz|"axios"[[:space:]]*:[[:space:]]*"=?(1\.14\.1|0\.30\.4)"' -e 'web3\.js[@/](npm:)?1\.95\.(6|7)([^0-9]|$)|/web3\.js/-/web3\.js-1\.95\.(6|7)\.tgz|"@solana/web3\.js"[[:space:]]*:[[:space:]]*"=?1\.95\.(6|7)"' .
  # a package-lock.json or npm-shrinkwrap.json written without "resolved" fields names the
  # package only on the entry's key line (or its "name" line, for an alias), with the
  # version on a line below it
  grep -rnE -A2 --exclude-dir=node_modules --include='package-lock.json' --include='npm-shrinkwrap.json' '"(([^"]*/)?node_modules/)?axios": [{]|"name": "axios"' . | grep -E '"version": "(1\.14\.1|0\.30\.4)"'
  grep -rnE -A2 --exclude-dir=node_modules --include='package-lock.json' --include='npm-shrinkwrap.json' '"([^"]*/)?@solana/web3\.js": [{]|"name": "@solana/web3\.js"' . | grep -E '"version": "1\.95\.(6|7)"'
  # history too, both forms: every branch, merge commits (against their first parent) and
  # the root commit, through the read-only git of Rule 11c, with --text, because a committed
  # .gitattributes can mark lockfiles binary, which hides them from -G
  "<auditor-skill root>/scripts/recipes/web3js-history.sh"
  # → known-bad releases (KV-077 Step 2; SC-001, SC-002, SC-005). A hit now is CRITICAL;
  #   a hit in history means rotate every key or credential a build from that window could
  #   read; a `web3js-history: partial clone` or `shallow clone` line, a `refused:` line,
  #   or a `fatal:` line, means the history is incomplete or the step did not run: that
  #   part is INCONCLUSIVE

  # Check version pinning
  cat apps/backend/package.json | grep -E '[\^~]' # should be minimal
  cat apps/web/package.json | grep -E '[\^~]'

  # Audits and registry queries run through the bundled deps.sh, from the working
  # directory by its quoted path, with no cd first. It copies only the manifests and
  # lockfiles it is given into a scratch directory outside the target tree and runs
  # there with the toolchain pinned, so the target's .npmrc / .cargo/config* /
  # rust-toolchain* never steer it (Rule 11a), and it records each outside service it
  # contacts in audit_<n>/disclosures.tsv (Rule 11b). Its last line names the output,
  # audit_<n>/deps/<action>-<k>.txt. Exit 0 = nothing found, 1 = findings,
  # 3 = blocker (the line says why), 64 = refused.
  #   OUTCOME: exit 3 or 64 → that check did not run: never a PASS; copy the line into
  #                           Coverage & Limitations

  # npm audit, one package.json and its lockfile at a time
  "<auditor-skill root>/scripts/runner/deps.sh" npm-audit --run audit_<n> --manifest apps/backend/package.json --manifest apps/backend/package-lock.json
  "<auditor-skill root>/scripts/runner/deps.sh" npm-audit --run audit_<n> --manifest apps/web/package.json --manifest apps/web/package-lock.json

  # Cargo audit (SC-004). The advisory database comes from GitHub (RustSec):
  #   exit 1                               → vulnerabilities found: findings, SC-004 FAIL
  #   exit 3, "no advisory database"       → say so in Coverage & Limitations ("advisory DB
  #                                          unavailable"), or run it again with --no-fetch,
  #                                          which uses the database already in CARGO_HOME
  #   exit 3, "cargo-audit is not on PATH" → SC-004 N/A, and Coverage & Limitations says so
  #   exit 0                               → SC-004 PASS
  "<auditor-skill root>/scripts/runner/deps.sh" cargo-audit --run audit_<n> --manifest Cargo.lock

  # Check quarantine (14-day rule) for newest deps: the publish time of each version
  "<auditor-skill root>/scripts/runner/deps.sh" npm-time --run audit_<n> @anchor-lang/core

  # Dependency changes since the baseline (last audited ref; first audit: last
  # release tag) → checklist 11 §11.11: review the published artifacts' code delta
  # (read-only git, Rule 11c; the same files as §11.11's first lockfile hint)
  "<auditor-skill root>/scripts/git-ro.sh" diff --text --no-color --stat <baseline>..HEAD -- '*.lock' '*-lock.json' '*npm-shrinkwrap.json' '*-lock.yaml' '*go.sum' '*go.mod' '*Cargo.toml' '*package.json' '*pyproject.toml' '*requirements*.txt'

RECORD: dependency audit results
```

### Step 3.3 — Secrets Audit (Checklist 12)

```
ACTIONS:

  # Hardcoded secrets scan
  grep -rn "secret\|private.*key\|mnemonic\|password" --include="*.ts" --include="*.json" --include="*.rs" . \
    | grep -v node_modules | grep -v target | grep -v ".env.example"

  # Keypair files in repo
  find . -name "*keypair*.json" -o -name "*delegate*.json" -o -name "id.json" | grep -v node_modules

  # .env files committed (read-only git, Rule 11c)
  "<auditor-skill root>/scripts/git-ro.sh" ls-files | grep -i ".env"

  # Git history check (read-only git, Rule 11c)
  "<auditor-skill root>/scripts/git-ro.sh" log --all --diff-filter=A --name-only -- "*.env" "*.pem" "*secret*"

  # NEXT_PUBLIC_ audit
  grep -rn "NEXT_PUBLIC_" apps/web/.env* 2>/dev/null
  grep -rn "NEXT_PUBLIC_" apps/web/src/ --include="*.ts" --include="*.tsx"

RECORD: any secret exposure
```

### Step 3.4 — Deployment & Infrastructure (Checklist 13)

```
ACTIONS:

  # Both runs below build and run target-controlled code (build.rs, proc-macros, and
  # Anchor.toml [scripts], which `anchor test` executes). The bundled target.sh runs
  # them in the execution mode recorded at intake — OUTPUT-RULES Rule 11a (isolated
  # recommended; native allowed, with the report caveat): the stricter of
  # audit_<n>/exec-mode and AUDITOR_EXEC_MODE, and with none recorded, or none, it
  # stops (exit 3). It builds a scratch clone of the committed source outside the target
  # tree, offline after its downloads, in a throwaway HOME and Solana keypair. Run it
  # from the working directory by its quoted path, with no cd first. Its last line
  # names the log, audit_<n>/exec/<action>-<k>.log, and the programs' .so files, in
  # audit_<n>/exec/<action>-<k>/. Exit 0 = ok, 1 = the build or the tests failed,
  # 3 = blocker (the line says why), 64 = refused. If they cannot run in that mode,
  # keep the source-level verdicts and add a Rule 10 confidence note.

  # Verify build (--program <name> for one program)
  "<auditor-skill root>/scripts/runner/target.sh" anchor-build --run audit_<n> --src .
  # Check its log for warnings, errors

  # Verify tests pass: the test script runs against no validator, and nothing is deployed
  "<auditor-skill root>/scripts/runner/target.sh" anchor-test --run audit_<n> --src .

  # Check deployment config (render.yaml, fly.toml, docker-compose.yml, etc.)
  # Adapt file names to your deployment platform

  # Verify .gitignore completeness
  cat .gitignore | grep -E "\.env|node_modules|target|keypair"

RECORD: build/deploy configuration + findings
```

---

## PHASE 4: VERIFICATION, MONITORING & COMPLIANCE AUDIT (Checklists 16-18)

### Step 4.1 — Formal Verification & Testing Quality (Checklist 16)

```
ACTIONS:

  # Check for static analysis in CI
  grep -rn "clippy\|eslint\|semgrep\|slither\|cargo-audit\|npm audit" .github/ Makefile* scripts/ --include="*.yml" --include="*.yaml" --include="*.sh" --include="*.mjs"

  # Check test coverage setup
  grep -rn "coverage\|lcov\|istanbul\|tarpaulin" . --include="*.yml" --include="*.yaml" --include="*.json" --include="*.toml" | grep -v node_modules | grep -v target

  # Check for fuzz testing
  find . -name "*fuzz*" -o -name "*proptest*" -o -name "*hypothesis*" | grep -v node_modules | grep -v target

  # Look for property-based tests
  grep -rn "proptest\|quickcheck\|hypothesis\|fc\.\|fast-check" . --include="*.rs" --include="*.ts" --include="*.py" | grep -v node_modules

  # Check for documented invariants
  grep -rn "invariant\|INVARIANT\|property.*test\|conservation" . --include="*.rs" --include="*.ts" --include="*.md" | grep -v node_modules | grep -v target

  # Error handling quality
  grep -rn "catch\s*{}" --include="*.ts" apps/
  grep -rn "\.unwrap()" --include="*.rs" programs/
  grep -rn "except:" --include="*.py" . | grep -v "except Exception\|except (.*Error"

RECORD: verification & testing quality findings
```

### Step 4.2 — Logging, Monitoring & Incident Response (Checklist 17)

```
ACTIONS:

  # Event emissions in on-chain program
  grep -rn "emit!\|msg!\|emit_cpi" --include="*.rs" programs/
  # → compare against state-changing instructions: every instruction should emit

  # Backend logging
  grep -rn "console\.log\|logger\.\|winston\|pino\|bunyan" --include="*.ts" apps/backend/
  grep -rn "\.log\(\|\.warn\(\|\.error\(" --include="*.ts" apps/backend/

  # Log secrets leak check
  grep -rn "log.*password\|log.*secret\|log.*key\|log.*token" --include="*.ts" apps/ | grep -v node_modules

  # Monitoring setup
  grep -rn "sentry\|datadog\|grafana\|prometheus\|newrelic\|alert" . --include="*.ts" --include="*.yml" --include="*.yaml" --include="*.json" | grep -v node_modules

  # Incident response documentation
  find . -name "INCIDENT*" -o -name "RUNBOOK*" -o -name "*incident*" -o -name "*disaster*" -o -name "*recovery*" | grep -v node_modules

  # Emergency pause mechanism
  grep -rn "pause\|freeze\|emergency\|circuit.breaker" --include="*.rs" programs/

  # Backup configuration
  grep -rn "backup\|snapshot\|restore" . --include="*.yml" --include="*.yaml" --include="*.json" --include="*.md" | grep -v node_modules

RECORD: logging, monitoring & IR findings
```

### Step 4.3 — Data Privacy, Compliance & Change Management (Checklist 18)

```
ACTIONS:

  # PII handling
  grep -rn "email\|phone\|name\|address\|ssn\|dob\|birthdate\|passport\|kyc" --include="*.ts" apps/ | grep -v node_modules
  # → identify all PII being collected, check encryption/protection

  # Privacy policy
  find . -name "*privacy*" -o -name "*gdpr*" -o -name "*terms*" | grep -v node_modules

  # Compliance documentation
  find . -name "*compliance*" -o -name "*soc2*" -o -name "*regulatory*" | grep -v node_modules

  # Change management / CI-CD
  ls .github/workflows/ 2>/dev/null
  cat .github/workflows/*.yml 2>/dev/null | grep -E "test|review|approve|deploy"

  # Code review enforcement
  cat .github/CODEOWNERS 2>/dev/null
  # → check if branch protection rules require reviews

  # Changelog maintenance
  find . -name "CHANGELOG*" -o -name "changelog*" | head -5

  # AI/ML components
  grep -rn "openai\|anthropic\|llm\|prompt\|gpt\|completion\|inference" --include="*.ts" --include="*.py" apps/ | grep -v node_modules
  # → if found, apply AI/ML security items PC-051 to PC-060

RECORD: privacy, compliance & change management findings
```

### Step 4.4 — Known Attack Vectors (all in-scope, KV-001..140)

Do NOT bulk-read all 140 vector files — that nullifies the scope gate. Load each in-scope vector **only when its `known-vectors/INDEX.md` trigger fires** (phase + language + the vector's feature markers), driven by the prescan advisory manifest.

```
ACTIONS:

  1. Read known-vectors/INDEX.md — use its "Load when (markers)" column as the trigger table.
  2. For EACH in-scope vector (per Phase -1 scope):
       a. If the vector's markers are `always (<phase>)` → OPEN the vector file and evaluate it.
       b. Else check its feature markers against evidence:
            - the audit-scan prescan array (references/orchestration/pre-scan.md), and
            - a grep over the in-scope tree.
          If EVERY marker is PROVABLY ABSENT (empty prescan array OR zero grep hits) →
            record  [N/A — feature absent: <marker>]  from the gate (an evidence-backed verdict).
          Otherwise → OPEN the vector file and evaluate it.
  3. For each opened vector, record one verdict:
       [PASS] / [FAIL-{1-10}] / [PARTIAL] / [N/A]
  4. Add evidence line(s): file:line, prescan field, or command output reference.

RECORD format:
  - KV-001: [PASS] ...                             (always-load, evaluated)
  - KV-005: [N/A — feature absent: pyth/switchboard/oracle]   (skip-deferred from gate)
  ...
  - KV-136: [FAIL-7] ...

HARD RULE (completeness — OUTPUT-RULES Rule 0):
  Every in-scope KV item still has a verdict. A skip-deferred `[N/A — feature absent]` is an
  evidence-backed verdict, NOT a silent skip — and it REOPENS on demand: because the prescan
  under-reports (macros / trait dispatch, per its honesty rule), the instant a manual file read
  surfaces the missing feature (e.g. a `CpiContext` the scan missed), OPEN and evaluate that
  vector. No bug becomes unreachable. Out-of-scope vectors render
  [N/A — out of scope: <reason>] from the scope gate.

See: known-vectors/INDEX.md (Load-when trigger column) · references/orchestration/pre-scan.md
     (Evidence-driven load gating manifest).
```

---

## PHASE 4.5: MATURITY ASSESSMENT

Orthogonal to the risk score: the risk score is the *deploy gate*; this scorecard is the *engineering-quality gate*. Rate each category 0-4 (0 absent · 1 ad-hoc · 2 partial · 3 good · 4 strong), weakest-link. *(Pattern credit: Trail of Bits `code-maturity-assessor`.)*

| # | Category | Scored on |
|---|----------|-----------|
| 1 | Access Controls | signer/authority coverage, role separation, admin-key custody |
| 2 | Arithmetic | checked math, u128 intermediates, rounding discipline |
| 3 | Account & Type Safety | typed accounts, discriminator/owner checks, PDA canonicalization |
| 4 | Input Validation | bounds, allowlists, `remaining_accounts` validation |
| 5 | Testing | unit/integration coverage, LiteSVM/Mollusk, edge cases |
| 6 | Fuzzing & Property Tests | cargo-fuzz/proptest presence, documented invariants |
| 7 | Error Handling & DoS Resilience | no `unwrap()`/panic on user input, compute/stack bounds |
| 8 | Upgradeability & Governance | upgrade authority, timelock, multisig, emergency pause |
| 9 | Monitoring & Incident Response | event emission coverage, runbooks, alerting |

Emit the scorecard as a dedicated report section (see `templates/report-template.md`). Categories scoring ≤ 1 are prioritized in the Remediation Roadmap regardless of individual finding severity.

---

## PHASE 5: REPORT GENERATION

### Step 5.1 — Aggregate Findings

```
Collect ALL findings from Phases 1-4.
Classify each by severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
De-duplicate (same root cause appearing in multiple checklists)
```

### Step 5.2 — Generate Report

```
Use the template in templates/report-template.md
Fill in:
  - Corpus coverage section (all auditor-skill files)
  - Executive summary with counts
  - Each finding with: ID, severity, location, description, exploit scenario, fix recommendation
  - Checklist summary table
  - Detailed per-item results
  - Known vector results (KV-001 through KV-140, each in-scope one with verdict)

Save report to: audit_{N}/REPORT.md (where N is the next audit number)
```

### Step 5.3 — Generate Roadmap

```
Create a prioritized remediation roadmap:
  1. CRITICAL findings — fix immediately, block deploy
  2. HIGH findings — fix before next release
  3. MEDIUM findings — fix within 2 weeks
  4. LOW findings — address in next sprint
  5. INFO — track in backlog

Save to: audit_{N}/roadmap.md
```

---

## EXECUTION NOTES

### Walk The Code — Never One-Shot

Chunking (chunk sizes per surface: 1 instruction file / 1 route + service / 2-3 components) + checkpoint format → OUTPUT-RULES.md Rule 3. Save a checkpoint after each chunk; if context is lost, resume from the checkpoint's `Next Action`.

### Parallelization
- Steps 2.1, 2.2, 2.3 are independent — can run grep commands in parallel
- Steps 3.1, 3.2, 3.3, 3.4 are independent
- Phase 1 must be sequential (instruction review builds context)

### Scope Control
- `FULL`: All checklists (01-18), all files
- `PROGRAM`: Checklists 01-07, 16 (on-chain + opsec + verification)
- `BACKEND`: Checklists 08-09, 11-12, 14-18 (TypeScript + backend + supply chain + secrets + verification + monitoring + compliance)
- `FRONTEND`: Checklists 08, 10, 12, 16-17 (TypeScript + frontend + secrets + verification + monitoring)
- `DEVOPS`: Checklists 07, 11-13, 16-18 (opsec + supply chain + secrets + deployment + verification + monitoring + compliance)

### Language Auto-Detection
Language → checklist mapping is authoritative in [SKILL.md](SKILL.md) → Scope-Gated Loading, Step 2 (scope table); see also OUTPUT-RULES.md Rule 7. The auditor scans file extensions/markers and applies the correct checklists.
