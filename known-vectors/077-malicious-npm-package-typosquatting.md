---
id: 77
title: "Malicious npm Package (Typosquatting)"
severity: 8
category: devops
---

### 77 — Malicious npm Package (Typosquatting)
**Severity: 8** | **Real: event-stream ($3.9M crypto theft, 2018), ua-parser-js (2021), colors.js (2022), `@solana/web3.js` 1.95.6 / 1.95.7 (hijacked release, Dec 2024)**

Developer installs `@solana/web3js` (typo, missing dot) instead of `@solana/web3.js` — malicious package steals private keys.

The same theft also arrives under the *correct* name. When a maintainer's publish credentials are hijacked, the attacker ships a backdoored release of the legitimate package: `@solana/web3.js` 1.95.6 and 1.95.7 (Dec 2024) were published with phished npm credentials and sent private keys from the keypair functions to the attacker (Anza RCA: https://www.anza.xyz/blog/web3-js-exploit-root-cause-analysis). Step 2 checks the known-bad releases; reviewing what a release's code actually changed before merging the bump is checklist 11 §11.11 (SC-059..062).

#### Verification Procedure

**Step 1: Audit all direct dependencies**
```
cat package.json apps/backend/package.json apps/web/package.json | grep -E "\"@|\"[a-z]" | grep -v version | sort -u
```
- Record: Complete dependency list

**Step 2: Check for known compromised packages**
```
# Known-bad releases: axios 1.14.1 / 0.30.4 and the hijacked @solana/web3.js 1.95.6 / 1.95.7. The first grep
# finds exact pins and resolved versions in package.json, package-lock / npm-shrinkwrap, pnpm (lockfile v5 keys
# too), yarn v1 + berry and bun, each followed by a character that is not a digit or at the end of a line; ranges such as "^1.95.7" do
# not match on their own:
grep -rnE --exclude-dir=node_modules --include='package.json' --include='package-lock.json' --include='npm-shrinkwrap.json' --include='pnpm-lock.yaml' --include='yarn.lock' --include='bun.lock' -e '(^|[^A-Za-z0-9_.-])axios[@/](npm:)?(1\.14\.1|0\.30\.4)([^0-9]|$)|/axios/-/axios-(1\.14\.1|0\.30\.4)\.tgz|"axios"[[:space:]]*:[[:space:]]*"=?(1\.14\.1|0\.30\.4)"' -e 'web3\.js[@/](npm:)?1\.95\.(6|7)([^0-9]|$)|/web3\.js/-/web3\.js-1\.95\.(6|7)\.tgz|"@solana/web3\.js"[[:space:]]*:[[:space:]]*"=?1\.95\.(6|7)"' .
# A package-lock.json or npm-shrinkwrap.json written without "resolved" fields names the package only on the
# entry's key line (or its "name" line, for an alias), with the version on a line below it:
grep -rnE -A2 --exclude-dir=node_modules --include='package-lock.json' --include='npm-shrinkwrap.json' '"(([^"]*/)?node_modules/)?axios": [{]|"name": "axios"' . | grep -E '"version": "(1\.14\.1|0\.30\.4)"'
grep -rnE -A2 --exclude-dir=node_modules --include='package-lock.json' --include='npm-shrinkwrap.json' '"([^"]*/)?@solana/web3\.js": [{]|"name": "@solana/web3\.js"' . | grep -E '"version": "1\.95\.(6|7)"'
# ...and anywhere in history, both forms: every branch, merge commits (against their first parent) and the root
# commit, through the read-only git of OUTPUT-RULES Rule 11c, with --text, because a committed .gitattributes can
# mark lockfiles binary, which hides them from -G. Each form prints under its own heading:
"<auditor-skill root>/scripts/recipes/web3js-history.sh"
```
- ✅ PASS: Zero matches in the tree, no `refused:` line, and either no line under either heading of `web3js-history.sh` or evidence that every key or credential a build from that window could read was rotated
- ❌ FAIL: Compromised package version in the tree — CRITICAL; or a hit in history with no evidence of rotation — every key or credential a build containing it could read is exposed: rotate it
- ⚠️ INCONCLUSIVE (history part): a `web3js-history: partial clone` or `web3js-history: shallow clone` line, a `refused:` line, or a `fatal:` line, means the history is incomplete or the step did not run (OUTPUT-RULES Rule 11c), so that part is never a PASS

**Step 3: Run npm audit**
```
# on copies of package.json and its lockfile, outside the target tree (OUTPUT-RULES Rule 11a); dev dependencies
# are audited too, since a malicious one runs its install scripts like any other. The report is in the file the
# last line names
"<auditor-skill root>/scripts/runner/deps.sh" npm-audit --run audit_<n> --manifest package.json --manifest package-lock.json
```
- ✅ PASS: Zero vulnerabilities, or only low/informational
- ⚠️ PARTIAL: Moderate vulnerabilities
- ❌ FAIL: High/critical vulnerabilities

**Step 4: Check package publish dates (14-day quarantine)**
```
# For recently added packages, verify they're not brand-new: the publish time of each version
"<auditor-skill root>/scripts/runner/deps.sh" npm-time --run audit_<n> @anchor-lang/core
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
