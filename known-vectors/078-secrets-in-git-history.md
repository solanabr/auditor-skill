---
id: 78
title: "Secrets in Git History"
severity: 10
category: devops
---

### 78 — Secrets in Git History
**Severity: 10** | **Real: Uber (2016, $100K coverup → $148M fine), thousands of leaked AWS keys daily on GitHub**

Private key or API secret committed even once — even if deleted later, it's in git history forever. Bots scrape GitHub for secrets within seconds.

#### Verification Procedure

**Step 1: Deep scan current codebase for credential patterns**
```
grep -rn --include="*.ts" --include="*.tsx" --include="*.json" --include="*.js" --include="*.env" --include="*.toml" --include="*.yaml" -E \
  "(sk_|pk_|api_key|apikey|secret_key|private_key|PRIVATE_KEY|mnemonic|seed_phrase)" \
  . | grep -v node_modules | grep -v ".git/"
```
- ✅ PASS: Zero matches (all secrets in env vars)
- ❌ FAIL: Any match — credential in tracked file

**Step 2: Scan for Solana keypair patterns**
```
grep -rn --include="*.ts" --include="*.tsx" --include="*.json" -E "\[([0-9]{1,3},){10,}" . | grep -v node_modules | grep -v target/
```
- ✅ PASS: No byte arrays that look like keypairs in source
- ❌ FAIL: Possible keypair array in tracked file

**Step 3: Scan for base58 private key strings**
```
grep -rn --include="*.ts" --include="*.tsx" -E "[1-9A-HJ-NP-Za-km-z]{64,88}" . | grep -v node_modules | grep -v ".git/" | grep -v "\.lock"
```
- ✅ PASS: No base58 strings that could be private keys
- ⚠️ PARTIAL: Some base58 strings exist — verify they're public keys or program IDs only

**Step 4: Scan ALL committed files in git history for dangerous filenames**
```
git log --all --diff-filter=A --name-only --pretty=format: | sort -u | grep -iE "\.env$|\.pem$|id_rsa|keypair|wallet.*\.json|secret|credential|\.key$|delegate\.json"
```
- ✅ PASS: Zero dangerous filenames ever committed
- ❌ FAIL: Dangerous file was committed at some point (even if deleted later — IT IS STILL IN HISTORY)

**Step 5: Search actual git history content for leaked secrets**
```
# Search for private key patterns in ALL historical content:
git log --all -p -S "BEGIN RSA" --diff-filter=ACMR -- . 2>/dev/null | head -20
git log --all -p -S "sk_live" --diff-filter=ACMR -- . 2>/dev/null | head -20
git log --all -p -S "PRIVATE_KEY" --diff-filter=ACMR -- . 2>/dev/null | head -20
git log --all -p -S "mnemonic" --diff-filter=ACMR -- . 2>/dev/null | head -20
```
- ✅ PASS: Zero matches in entire git history
- ❌ FAIL: Any secret found in historical commits — MUST rotate the credential AND consider `git filter-repo` to rewrite history (force push required)

**Step 6: Search git history for Solana keypair arrays**
```
git log --all -p --diff-filter=ACMR -- '*.json' '*.ts' '*.js' 2>/dev/null | grep -E "\[([0-9]{1,3},){20,}" | head -10
```
- ✅ PASS: No keypair-like arrays in history
- ❌ FAIL: Possible keypair in git history — identify commit: `git log --all -p -S '[123,45,67' -- .`

**Step 7: Check for .env files ever tracked**
```
git log --all --diff-filter=A --name-only --pretty=format: | grep -E "^\.env|/\.env"
```
- ✅ PASS: No .env file ever committed
- ❌ FAIL: .env file was committed — secrets in history, rotate ALL env vars

**Step 8: Verify .gitignore completeness**
```
cat .gitignore | grep -E "\.env|keypair|\.pem|\.key|id_rsa|delegate\.json"
```
- ✅ PASS: All sensitive file patterns in .gitignore (.env, *.pem, *keypair*, *-delegate.json, id_rsa)
- ❌ FAIL: Missing patterns — new sensitive files could be committed

**Step 9: Check for currently tracked files that should be ignored**
```
git ls-files | grep -iE "\.env|keypair|secret|credential|\.pem|\.key$|delegate\.json"
```
- ✅ PASS: Zero results — no sensitive files currently tracked
- ❌ FAIL: Sensitive file tracked — remove with `git rm --cached <file>` immediately

**Step 10: Check for pre-commit hooks (prevention)**
```
cat .husky/pre-commit 2>/dev/null; cat .git/hooks/pre-commit 2>/dev/null; cat .pre-commit-config.yaml 2>/dev/null
npm ls --depth=0 2>/dev/null | grep -iE "husky|lint-staged|detect-secrets|gitleaks|trufflehog"
```
- ✅ PASS: Pre-commit hook runs secret scanner (gitleaks, detect-secrets, or trufflehog)
- ⚠️ PARTIAL: Husky installed but no secret scanning hook
- ❌ FAIL: No pre-commit secret scanning at all

**Step 11: Check GitHub repository settings**
```
# Verify: is GitHub push protection / secret scanning enabled?
# Go to: Settings → Code security and analysis → Secret scanning
# Or check via API if available
```
- ✅ PASS: GitHub secret scanning AND push protection enabled
- ⚠️ PARTIAL: Secret scanning enabled but not push protection
- ❌ FAIL: Neither enabled

**Step 12: Check CI/CD for secret scanning**
```
cat .github/workflows/*.yml 2>/dev/null | grep -iE "gitleaks|trufflehog|detect-secrets|secret.*scan"
```
- ✅ PASS: CI pipeline includes secret scanning step
- ❌ FAIL: No automated secret scanning in CI

**Overall verdict:**
- ✅: No secrets in current code or history, .gitignore complete, pre-commit hooks, CI scanning, GitHub push protection
- ⚠️: No current secrets but weak prevention (missing hooks or CI scanning)
- ❌: Secrets found in current code or git history — IMMEDIATE ROTATION REQUIRED
