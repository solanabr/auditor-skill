# 11 — Supply Chain & Dependencies Checklist

> Domain: Package management, npm/cargo dependencies  
> Severity if missed: CRITICAL (compromised package) to LOW (outdated)  
> References: Project supply chain safety rules, npm advisory database

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 11.1 — Known Compromised Packages

- [ ] **SC-001**: `axios@1.14.1` is NOT in any `package.json` or `package-lock.json` — **CRITICAL if found**
- [ ] **SC-002**: `axios@0.30.4` is NOT in any `package.json` or `package-lock.json` — **CRITICAL if found**
- [ ] **SC-003**: Run `npm audit` — zero critical or high vulnerabilities
- [ ] **SC-004**: Run `cargo audit` (if installed) — zero advisories
- [ ] **SC-005**: Check for known compromised packages in the npm ecosystem (event-stream, ua-parser-js, etc.)
- [ ] **SC-006**: No packages with known typosquatting risk (e.g., `crossenv` vs `cross-env`)

## 11.2 — 14-Day Quarantine Rule

- [ ] **SC-007**: For EACH direct dependency in `package.json`, verify the installed version was published > 14 days ago
- [ ] **SC-008**: Run `npm info <pkg> time` for any recently updated packages
- [ ] **SC-009**: If any dependency version is < 14 days old — flag and pin to older safe version
- [ ] **SC-010**: Same quarantine check for Cargo.toml dependencies (check crates.io publish dates)
- [ ] **SC-011**: Lock files (`package-lock.json`, `Cargo.lock`) are committed to git
- [ ] **SC-012**: Lock file integrity: `npm ci` produces same results as committed lock file

## 11.3 — Version Pinning

- [ ] **SC-013**: Critical dependencies in `package.json` use exact versions (no `^` or `~`) — check:
  - `@anchor-lang/core`
  - `@solana/web3.js`
  - `@solana/spl-token`
  - Any wallet adapter packages
- [ ] **SC-014**: Cargo.toml dependencies — verify versions are pinned for:
  - `anchor-lang`
  - `anchor-spl`
  - `solana-program`
- [ ] **SC-015**: No `*` version ranges in any dependency
- [ ] **SC-016**: Dev dependencies can use ranges — but production dependencies should be pinned

## 11.4 — Dependency Audit

- [ ] **SC-017**: Total number of direct dependencies: _____ (document — fewer is better)
- [ ] **SC-018**: Any deprecated packages? Run `npm outdated`
- [ ] **SC-019**: Any packages with no recent maintenance (>1 year without update)?
- [ ] **SC-020**: Any packages with very few downloads (<1000/week)? Higher supply chain risk
- [ ] **SC-021**: Any packages with recent ownership transfer? Check npm page for maintainer changes
- [ ] **SC-022**: Package `@coral-xyz/anchor` is NOT installed (discontinued — use `@anchor-lang/core`)
- [ ] **SC-023**: No duplicate packages (same functionality from different packages)
- [ ] **SC-024**: Postinstall scripts — any package runs scripts on install? (`npm ls --json` then check scripts)

## 11.5 — Build Security

- [ ] **SC-025**: `.npmrc` does not contain auth tokens
- [ ] **SC-026**: `package.json` has no `preinstall`/`postinstall` scripts that execute arbitrary code
- [ ] **SC-027**: Build process is deterministic — same source produces same output
- [ ] **SC-028**: Build artifacts are not committed to git (except intentional like IDL)
- [ ] **SC-029**: No `--ignore-scripts` flag needed (all packages are safe to run install scripts)
- [ ] **SC-030**: CI/CD npm install uses `npm ci` (not `npm install`) for reproducibility

## 11.6 — Rust/Cargo Dependencies

- [ ] **SC-031**: Borsh version — let Anchor manage it (no manual pin that conflicts)
- [ ] **SC-032**: `solana-program` version matches the target Solana runtime version
- [ ] **SC-033**: No `git = "..."` dependencies pointing to non-official repositories
- [ ] **SC-034**: No `path = "..."` dependencies pointing outside the repository
- [ ] **SC-035**: `Cargo.lock` is committed and used for builds
- [ ] **SC-036**: Feature flags reviewed — no unexpected features enabled
- [ ] **SC-037**: No `[patch]` section in Cargo.toml that overrides official crates
- [ ] **SC-038**: Build with `--release` for production — verify optimization level

## 11.7 — Transitive Dependencies

- [ ] **SC-039**: Run `npm ls --all` — review tree for unexpected packages
- [ ] **SC-040**: Any transitive dependency that is in the compromised list?
- [ ] **SC-041**: Any transitive dependency pulling in native binary modules? (Higher risk)
- [ ] **SC-042**: Dependency resolution conflicts — any forced resolutions/overrides?
- [ ] **SC-043**: `package-lock.json` reviewed for unexpected URLs or registries

## 11.8 — 2025 Solana-Targeted Supply-Chain TTPs

- [ ] **SC-044**: Lockfile provenance — no `package-lock.json`/`yarn.lock` entry resolves a dependency to a non-registry URL (e.g. a GitHub-Release tarball). A non-registry `resolved`/`resolution` URL bypasses `npm audit`, deprecation, and takedown, and is how the pump.fun-bot `crypto-layout-utils` campaign (2025) shipped malware after the registry pulled the package. (KB VC-26)
- [ ] **SC-045**: Install-hook secret harvesting — review every `postinstall`/`preinstall` script and Python `__init__.py`/`setup.py` for reads of `~/.config/solana/id.json` or other wallet/keypair paths and any outbound exfil (HTTP POST, DNS, webhook). This is the exact behavior of the FakeFix campaign (20 npm + 4 PyPI packages, 2025) that drained Solana keypairs on install. (KB VC-26)
- [ ] **SC-046**: Publish-credential integrity — package publishing enforces FIDO2/hardware-key 2FA or OIDC/trusted-publishing (NOT phishable TOTP), and releases are diffed post-publish against the built artifact. Publisher-credential compromise drove the web3.js $190K incident and the Trust Wallet browser-extension $7M loss. (KB VC-26)
