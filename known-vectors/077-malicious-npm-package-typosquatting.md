---
id: 77
title: "Malicious npm Package (Typosquatting)"
severity: 8
category: devops
---

### 77 — Malicious npm Package (Typosquatting)
**Severity: 8** | **Real: event-stream ($3.9M crypto theft, 2018), ua-parser-js (2021), colors.js (2022)**

Developer installs `@solana/web3js` (typo, missing dot) instead of `@solana/web3.js` — malicious package steals private keys.

#### Verification Procedure

**Step 1: Audit all direct dependencies**
```
cat package.json apps/backend/package.json apps/web/package.json | grep -E "\"@|\"[a-z]" | grep -v version | sort -u
```
- Record: Complete dependency list

**Step 2: Check for known compromised packages**
```
# Check against known-bad list:
grep -iE "axios@1\.14\.1|axios@0\.30\.4" package.json apps/*/package.json package-lock.json
```
- ✅ PASS: Zero matches — no known compromised versions
- ❌ FAIL: Compromised package version found — CRITICAL

**Step 3: Run npm audit**
```
npm audit --omit=dev 2>/dev/null | tail -20
```
- ✅ PASS: Zero vulnerabilities, or only low/informational
- ⚠️ PARTIAL: Moderate vulnerabilities
- ❌ FAIL: High/critical vulnerabilities

**Step 4: Check package publish dates (14-day quarantine)**
```
# For recently added packages, verify they're not brand-new:
npm info @anchor-lang/core time --json 2>/dev/null | tail -5
```
- ✅ PASS: All packages' installed versions are >14 days old
- ❌ FAIL: Package version published <14 days ago

**Step 5: Check for unusual package names (typosquatting indicators)**
```
# Look for packages that look similar to popular ones:
cat package.json | grep -iE "solana|anchor|token|wallet" | head -10
```
- ✅ PASS: All packages are from official scopes (`@solana/`, `@anchor-lang/`, etc.)
- ❌ FAIL: Unscoped packages claiming to be from known projects

**Step 6: Check package sizes for anomalies**
```
du -sh node_modules/*/ 2>/dev/null | sort -rh | head -15
```
- ✅ PASS: Package sizes reasonable for their purpose
- ⚠️ PARTIAL: Unusually large package (investigate contents)

**Overall verdict:**
- ✅: No compromised packages, audit clean, all official scopes, 14-day quarantine followed
- ⚠️: Audit shows moderate issues, or some packages not yet 14 days old
- ❌: Compromised package found, or critical audit vulnerabilities
