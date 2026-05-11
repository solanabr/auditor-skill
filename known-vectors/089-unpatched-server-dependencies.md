---
id: 89
title: "Unpatched Server Dependencies"
severity: 7
category: devops
---

### 89 — Unpatched Server Dependencies
**Severity: 7** | **Real: Log4Shell (2021), Left-Pad, any known CVE in deployed deps**

Known vulnerability in production dependency → attacker uses public exploit to compromise server.

#### Verification Procedure

**Step 1: Run npm audit**
```
cd apps/backend && npm audit --omit=dev 2>/dev/null; cd ../..
cd apps/web && npm audit --omit=dev 2>/dev/null; cd ../..
```
- ✅ PASS: Zero high/critical vulnerabilities
- ⚠️ PARTIAL: Only moderate or low vulnerabilities
- ❌ FAIL: High/critical vulnerabilities in production dependencies

**Step 2: Check for outdated packages**
```
npm outdated 2>/dev/null | head -20
```
- ✅ PASS: All packages within 1-2 minor versions of latest
- ⚠️ PARTIAL: Some packages several versions behind
- ❌ FAIL: Major version behind with known security fixes in newer versions

**Step 3: Check Node.js version**
```
node --version
```
- ✅ PASS: Active LTS or Current release (18.x, 20.x, 22.x as of 2025)
- ❌ FAIL: End-of-life Node.js version (16.x, 14.x, etc.)

**Step 4: Check for pinned versions**
```
grep -E "\"[~^]" apps/backend/package.json apps/web/package.json | head -20
```
- ✅ PASS: Critical dependencies pinned to exact versions (no ^/~)
- ⚠️ PARTIAL: Most use ^ (caret) — gets minor updates automatically

**Step 5: Check Cargo audit (Solana program)**
```
cd programs/<your_program> && cargo audit 2>/dev/null | tail -20; cd ../..
```
- ✅ PASS: Zero vulnerabilities in Rust dependencies
- ❌ FAIL: Known CVEs in Rust dependencies

**Overall verdict:**
- ✅: No audit vulnerabilities, packages up to date, LTS Node, pinned versions
- ⚠️: Some moderate vulnerabilities, packages slightly outdated
- ❌: Critical vulnerabilities in production dependencies
