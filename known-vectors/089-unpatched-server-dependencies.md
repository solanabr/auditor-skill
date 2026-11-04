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
# npm audit --omit=dev and npm outdated have no bundled runner (deps.sh npm-audit also audits dev
# dependencies), so Steps 1 and 2 ask for approval. They run from a scratch dir OUTSIDE the target
# tree, on copies of the manifest + lockfile, so the target's .npmrc cannot steer them (OUTPUT-RULES
# Rule 11a). $SCRATCH lasts only as long as its shell: run Steps 1 and 2 in one shell. Each step runs
# nothing unless $SCRATCH is an absolute directory outside the working directory, both compared with
# every symbolic link resolved, since `cd "$SCRATCH"` with it empty would stay in the target tree
SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/auditor-scratch.XXXXXX")   # outside the target tree
case "$SCRATCH" in /*) SCRATCH=$(cd "$SCRATCH" && pwd -P) ;; *) SCRATCH= ;; esac   # an absolute path only, links resolved,
case "$SCRATCH/" in "$(pwd -P)"/*) SCRATCH= ;; esac     # never inside the working directory
if [ -z "$SCRATCH" ] || [ ! -d "$SCRATCH" ]; then
  echo "OUTCOME: no scratch copy (check TMPDIR)"
else
  mkdir -p "$SCRATCH/backend" "$SCRATCH/web"
  cp apps/backend/package.json apps/backend/package-lock.json "$SCRATCH/backend/"
  cp apps/web/package.json apps/web/package-lock.json "$SCRATCH/web/"
  (cd "$SCRATCH/backend" && npm audit --omit=dev)
  (cd "$SCRATCH/web" && npm audit --omit=dev)
fi
```
- ✅ PASS: Zero high/critical vulnerabilities
- ⚠️ PARTIAL: Only moderate or low vulnerabilities
- ❌ FAIL: High/critical vulnerabilities in production dependencies
- ⚠️ Not run, never a PASS: `OUTCOME: no scratch copy (check TMPDIR)` — mktemp failed, or gave a relative path or one inside the working directory; point `TMPDIR` at an absolute directory outside the target tree and run the step again

**Step 2: Check for outdated packages**
```
# npm outdated has no bundled runner, so this step asks for approval, like Step 1.
# On the Step 1 copies. They have no node_modules, so Current reads MISSING:
# compare Wanted / Latest with the version the lockfile pins
case "${SCRATCH:-}" in /*) SCRATCH=$(cd "$SCRATCH" && pwd -P) ;; *) SCRATCH= ;; esac   # an absolute path only, links resolved,
case "$SCRATCH/" in "$(pwd -P)"/*) SCRATCH= ;; esac     # never inside the working directory
if [ -z "$SCRATCH" ] || [ ! -d "$SCRATCH" ]; then
  echo "OUTCOME: no scratch copy (run Step 1 first)"
else
  (cd "$SCRATCH/backend" && npm outdated)
  (cd "$SCRATCH/web" && npm outdated)
fi
```
- ✅ PASS: All packages within 1-2 minor versions of latest
- ⚠️ PARTIAL: Some packages several versions behind
- ❌ FAIL: Major version behind with known security fixes in newer versions
- ⚠️ Not run, never a PASS: `OUTCOME: no scratch copy (run Step 1 first)` — run Step 1 and this step in one shell

**Step 3: Check Node.js version**
```
# The runtime the target declares (package.json engines, .nvmrc, .node-version, a Dockerfile's node image),
# not the auditor's own node
grep -n '"node"' package.json apps/backend/package.json apps/web/package.json 2>/dev/null
grep -rH --exclude-dir=node_modules --include=.nvmrc --include=.node-version '' .
grep -rn --include='Dockerfile*' --exclude-dir=node_modules -E '^FROM[[:space:]]+node' . 2>/dev/null
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
# The bundled deps.sh, as FULL-AUDIT Step 3.2 runs it: a copy of Cargo.lock in a scratch directory
# outside the target tree, the toolchain pinned (OUTPUT-RULES Rule 11a)
"<auditor-skill root>/scripts/runner/deps.sh" cargo-audit --run audit_<n> --manifest Cargo.lock
```
- ✅ PASS: exit 0 — zero vulnerabilities in Rust dependencies
- ❌ FAIL: exit 1 — known CVEs in Rust dependencies
- ⚠️ Not run, never a PASS: exit 3 with "no advisory database" (Coverage & Limitations records "advisory DB unavailable", or run it again with `--no-fetch`, which uses the database already in `CARGO_HOME`), exit 3 because cargo-audit is not on PATH (N/A, and Coverage & Limitations says so), or exit 64 (copy its `refused:` line into Coverage & Limitations)

**Overall verdict:**
- ✅: No audit vulnerabilities, packages up to date, LTS Node, pinned versions
- ⚠️: Some moderate vulnerabilities, packages slightly outdated
- ❌: Critical vulnerabilities in production dependencies
