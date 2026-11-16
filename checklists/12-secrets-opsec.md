# 12 — Secrets & Key Management Checklist

> Domain: Secrets handling, environment variables, key storage  
> Severity if missed: CRITICAL (exposed private key) to MEDIUM (leaked API key)  
> References: Project secrets-safety instructions, OWASP secrets management

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 12.1 — No Hardcoded Secrets

- [ ] **SEC-001**: `grep -rn "private" --include="*.ts" --include="*.tsx" --include="*.json"` — no private keys in source
- [ ] **SEC-002**: `grep -rn "secret" --include="*.ts" --include="*.json" --include="*.env*"` — check all matches
- [ ] **SEC-003**: `grep -rn "mnemonic\|seed phrase" --include="*.ts"` — zero results
- [ ] **SEC-004**: `grep -rn "password" --include="*.ts" --include="*.json"` — only refs to env vars
- [ ] **SEC-005**: No base58-encoded private keys in any file (44-character strings starting with specific patterns)
- [ ] **SEC-006**: No JSON keypair files committed (`.json` files with 64-element integer arrays)
- [ ] **SEC-007**: No Solana keypair files in repo (check for `id.json`, `*-keypair.json`, `*-delegate.json`)
- [ ] **SEC-008**: No `.env` files committed to git — check `"<auditor-skill root>/scripts/git-ro.sh" log --all --name-only | grep -i ".env"` (read-only git, OUTPUT-RULES Rule 11c)
- [ ] **SEC-009**: No API keys hardcoded — check for patterns like `sk-`, `api_`, `key_`, long hex/base64 strings
- [ ] **SEC-010**: No RPC URLs with API keys hardcoded (check for `rpc.helius.xyz`, `rpc.ankr.com` with keys in URL)

## 12.2 — Environment Variable Handling

- [ ] **SEC-011**: All secrets loaded from `process.env.VARIABLE_NAME`
- [ ] **SEC-012**: Startup validation: all required env vars checked at application boot — fails fast if missing
- [ ] **SEC-013**: No default fallback values for secrets: `process.env.SECRET || "default"` is FORBIDDEN
- [ ] **SEC-014**: `NEXT_PUBLIC_` prefix — list all: verify NONE are secrets (these are exposed to browser)
- [ ] **SEC-015**: Backend `.env` variables NOT prefixed with `NEXT_PUBLIC_`
- [ ] **SEC-016**: `.env.example` or `.env.template` exists with variable names but NO actual values
- [ ] **SEC-017**: Different env vars for dev/staging/production — verify no cross-contamination

## 12.3 — Git Hygiene

- [ ] **SEC-018**: `.gitignore` includes: `.env`, `.env.*`, `*.pem`, `*-keypair.json`, `*-delegate.json`, `id.json`
- [ ] **SEC-019**: `.gitignore` includes: `node_modules/`, `target/`, `.anchor/`, `test-ledger/`
- [ ] **SEC-020**: Run `"<auditor-skill root>/scripts/git-ro.sh" log --all --diff-filter=A --name-only` (read-only git, OUTPUT-RULES Rule 11c) — check if secrets were EVER committed (even if now deleted)
- [ ] **SEC-021**: If any secret was ever committed — it MUST be rotated (deleting from git history is not sufficient)
- [ ] **SEC-022**: Pre-commit hooks: is there a secret detection hook? (gitleaks, detect-secrets, etc.)
- [ ] **SEC-023**: No `.env` in any branch (check all branches, not just current)
- [ ] **SEC-024**: Commit messages don't contain secrets or API keys

## 12.4 — RPC & API Key Safety

- [ ] **SEC-025**: Solana RPC URL uses dedicated provider (Helius, Triton, QuickNode) — not `api.mainnet-beta.solana.com`
- [ ] **SEC-026**: RPC API key is in backend `.env` — not exposed in frontend
- [ ] **SEC-027**: If RPC is needed in frontend — proxied through backend API route
- [ ] **SEC-028**: Jupiter API key (`x-api-key` header) — stored in backend env var, not frontend
- [ ] **SEC-029**: MongoDB connection string — in env var, not in code
- [ ] **SEC-030**: Any third-party API keys — all in env vars with startup validation
- [ ] **SEC-031**: API keys are scoped to minimum required permissions (e.g., read-only where possible)
- [ ] **SEC-032**: API key rotation schedule documented (quarterly minimum)

## 12.5 — Wallet & Program Key Safety

- [ ] **SEC-033**: Program deploy keypair — NOT stored on dev machine for mainnet
- [ ] **SEC-034**: Program deploy keypair — on hardware wallet (Ledger) or multisig for mainnet
- [ ] **SEC-035**: Program authority keypair — separate from deploy keypair (defense-in-depth)
- [ ] **SEC-036**: Backend service wallet — holds minimum SOL (only for gas), no other tokens
- [ ] **SEC-037**: Backend service wallet — private key in env var, not in file
- [ ] **SEC-038**: Manager wallets — hardware wallet recommended for production
- [ ] **SEC-039**: Treasury wallet — multisig or hardware wallet
- [ ] **SEC-040**: Test wallets — separate from production, devnet only

## 12.6 — Server & Infrastructure Secrets

- [ ] **SEC-041**: Server SSH keys — key-based auth, password auth disabled
- [ ] **SEC-042**: Server access — 2FA enabled for all admin accounts
- [ ] **SEC-043**: Database credentials — unique per service, not shared
- [ ] **SEC-044**: TLS certificates — valid and auto-renewed (Let's Encrypt or provider-managed)
- [ ] **SEC-045**: Secrets manager used (AWS SSM, Vault, Doppler) or env vars in hosting platform (Render, Vercel)
- [ ] **SEC-046**: No secrets in CI/CD logs — build processes don't echo env vars
- [ ] **SEC-047**: Docker images (if used) — no secrets baked into image layers

## 12.7 — Key Rotation & Incident

- [ ] **SEC-048**: Process exists for emergency key rotation
- [ ] **SEC-049**: If a key is suspected compromised — documented steps for rotation
- [ ] **SEC-050**: After key rotation — all services updated atomically (no partial deployment with mixed keys)
- [ ] **SEC-051**: Revoked/rotated keys are actually deactivated (not just removed from source but still valid)
- [ ] **SEC-052**: Key rotation doesn't break dependent services (graceful transition)

## 12.8 — Signing-Key Generation & Signing-Service Integrity

- [ ] **SEC-053**: Signing keys are generated with a CSPRNG (never predictable or derived from transaction material / timestamps / counters); any custom signing service is reviewed for ECDSA/EdDSA nonce reuse and side-channels, or replaced with a vetted HSM/MPC signer (Upbit $36.8M — private key back-calculated from on-chain signature material)

## 12.9 — Secret Residue Outside the Repository (temp directories, CI workspaces, shell history, sync folders)

> Secret scanning covers the repository and its history. A key spends most of its life elsewhere: in the temp file a deploy script wrote, in the CI workspace the next step uploads, in the shell history line that pasted it, in the copy a sync client made. None of that is in git, and all of it is readable by anything running as the same user. See KV-144. SEC-058 looks at a machine: it is run by the operator, or with the operator's explicit go-ahead, and its commands print paths, modes and counts, never file contents. Grep hints:
> ```
> grep -rn -E "/tmp/|/var/tmp/|os\.tmpdir\(\)|temp_dir\(\)|gettempdir\(\)|mktemp|%TEMP%|RUNNER_TEMP|--private-key|export +[A-Z_]*(PRIVATE_KEY|SECRET|MNEMONIC)=|set -x" --include="*.sh" --include="*.ts" --include="*.js" --include="*.rs" --include="*.py" --include="*.yml" --include="*.yaml" --include="*.md" .
> ```

- [ ] **SEC-054**: No code, script or Makefile writes secret material (keypair, seed, token, `.env`) to a shared or predictable temp path: nothing under `/tmp`, `/var/tmp`, `/dev/shm`, `os.tmpdir()`, `std::env::temp_dir()`, `tempfile.gettempdir()` or `%TEMP%` with a fixed name or default permissions. Secrets travel by environment variable, stdin or file descriptor; an unavoidable file is created 0600 inside a private 0700 directory (`mktemp -d`, `fs.mkdtemp`, the `tempfile` crate) and removed on every exit path (`trap ... EXIT`, `finally`, `defer`). (PASS: no secret reaches a shared temp path, or it does so only in a private directory with cleanup on failure; FAIL: `echo "$KEY" > /tmp/key.json` or its equivalent in any language, readable by every user and left behind when the script fails. CWE-377. Extends PY-068 / PY-069 beyond Python.)
- [ ] **SEC-055**: CI keeps secret files out of the workspace, artifacts and caches: a secret that must be a file is written under `$RUNNER_TEMP`, never `$GITHUB_WORKSPACE`, with mode 0600, and removed in a step marked `if: always()`; no `actions/upload-artifact` or cache `path:` contains it or a parent directory; jobs that hold deploy or upgrade keys run on ephemeral runners, not on a persistent self-hosted runner that pull-request jobs share. (PASS: all four hold; FAIL: the key file sits in the checkout that a later step uploads, caches or copies into a `docker build` context, or survives on a runner the next job inherits. Cross-ref KV-116, KV-139, KV-140, DEP-071.)
- [ ] **SEC-056**: No secret travels on a command line, and no documented command teaches that: scripts, package scripts, Makefiles and runbooks pass `--keypair <path>` or read an environment variable set by a secret manager, never `--private-key <value>`, a seed or token as an argument, or `export PRIVATE_KEY=<value>` typed into a shell; blocks that expand a secret do not run under `set -x`. (PASS: file path, managed environment or prompt only; FAIL: a key on argv is visible in the process list while it runs and stays in `~/.bash_history`, `~/.zsh_history` or PowerShell's history file afterwards. CWE-214.)
- [ ] **SEC-057**: Keystore location and permissions are written down and followed: deploy, upgrade and treasury authorities live on a hardware wallet or multisig; automation keys live in a dedicated file outside the default `~/.config/solana/id.json`, mode 0600 in a 0700 directory (one-user ACL on Windows); no keystore sits inside a Dropbox / OneDrive / iCloud / Google Drive folder, a backup set, `Downloads`, the desktop or the project directory. (PASS: the runbook states it and `Anchor.toml` / deploy scripts agree; FAIL: a mainnet authority at the default keypair path, which is the first file wallet-harvesting malware reads (SC-045), or a keystore that a sync client copies to a third party.)
- [ ] **SEC-058**: A residue inventory has been run on every machine that has held a deploy, upgrade, treasury or automation key (developer laptops, build hosts, servers) and its result recorded: keypair-shaped files in temp, download and desktop locations, keystore modes, whether the keystore path resolves into a synced folder, the count of shell-history lines that look like a pasted secret, editor swap and backup copies beside key files, and the core-dump policy. KV-144 Step 5 gives the read-only commands for Linux, macOS and Windows; they print paths, modes and counts only. (PASS: run, recorded with date and host, repeated on a schedule and when a machine changes hands; FAIL: never run, or run with hits and no follow-up.)
- [ ] **SEC-059**: A key found outside its keystore is rotated, not deleted: the incident runbook treats any key that touched a shared temp directory, a CI workspace, a synced folder, a process argument or shell history as exposed, moves the authority to a new key (`SetAuthority`, multisig member swap, token revoked) and records deletion as cleanup, not remediation. (PASS: rotation documented per authority and applied to every SEC-058 hit; FAIL: the response is `rm`, although flash storage, snapshots, backups and sync clients keep copies nobody can reach. Cross-ref SEC-048..052.)
