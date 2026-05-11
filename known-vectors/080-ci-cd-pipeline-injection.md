---
id: 80
title: "CI/CD Pipeline Injection"
severity: 9
category: devops
---

### 80 — CI/CD Pipeline Injection
**Severity: 9** | **Real: Codecov supply chain attack (2021), SolarWinds CI compromise**

Attacker modifies CI workflow or compromises CI tool — injects malicious code into build artifacts deployed to production.

#### Verification Procedure

**Step 1: List all CI workflows**
```
ls -la .github/workflows/ 2>/dev/null
cat .github/workflows/*.yml 2>/dev/null | head -100
```
- Record: All workflow files and their trigger conditions

**Step 2: Check for pull_request_target (dangerous trigger)**
```
grep -rn "pull_request_target" .github/workflows/
```
- ✅ PASS: No `pull_request_target` trigger (or used safely with `actions/checkout@v4` on base ref only)
- ❌ FAIL: `pull_request_target` with `actions/checkout` of PR head — allows forked PRs to run arbitrary code with write permissions

**Step 3: Check for secret exposure in logs**
```
grep -rn "echo.*\$\{\{.*secrets\|echo.*SECRET\|echo.*KEY" .github/workflows/
```
- ✅ PASS: Secrets never echoed in CI logs
- ❌ FAIL: Secrets printed to CI output (visible in logs)

**Step 4: Check action versions (pinned to SHA?)**
```
grep -E "uses:" .github/workflows/*.yml 2>/dev/null | grep -v "@[a-f0-9]{40}"
```
- ✅ PASS: All actions pinned to full SHA (`@abc123...`) — immune to tag tampering
- ⚠️ PARTIAL: Actions pinned to version tag (`@v4`) — better than no pin, but tag can be moved
- ❌ FAIL: Actions referencing `@main` or `@latest`

**Step 5: Check for write permissions**
```
grep -rn "permissions:" .github/workflows/ | head -10
grep -rn "GITHUB_TOKEN" .github/workflows/
```
- ✅ PASS: Minimum permissions declared (e.g., `contents: read`), no unnecessary write access
- ❌ FAIL: Default permissions (full read-write) used

**Step 6: Check for third-party CI tools**
```
grep -rn --include="*.yml" --include="*.yaml" "uses.*/" .github/workflows/ | grep -v "actions/" | grep -v "github/"
```
- ✅ PASS: Only official GitHub Actions or well-known, audited third-party actions
- ⚠️ PARTIAL: Some third-party actions from less-known orgs
- ❌ FAIL: Third-party actions from unknown sources without version pinning

**Overall verdict:**
- ✅: Actions SHA-pinned, minimal permissions, no pull_request_target, secrets protected
- ⚠️: Version-tag pinned, reasonable permissions, known action vendors
- ❌: Unpinned actions, pull_request_target with PR checkout, secrets in logs
