# 13 — Deployment & Infrastructure Checklist

> Domain: Build process, deploy pipeline, monitoring, verifiable builds  
> Severity if missed: HIGH (unverifiable binary) to LOW (missing monitoring)  
> References: Anchor verifiable builds, Solana deploy process, Render/Vercel config

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 13.1 — Program Build & Deploy

- [ ] **DEP-001**: Program built with `anchor build` — not `cargo build-sbf` directly (ensures Anchor IDL generation)
- [ ] **DEP-002**: Verifiable build: `anchor build --verifiable` or Docker-based verifiable build
- [ ] **DEP-003**: Build produces deterministic output — same source → same binary hash
- [ ] **DEP-004**: Program ID in `declare_id!()` matches `Anchor.toml` and deployed program
- [ ] **DEP-005**: `anchor build --ignore-keys` NOT used for production builds
- [ ] **DEP-006**: Legacy IDL accounts (if upgrading from Anchor 0.x) closed before deploying v1.0
- [ ] **DEP-007**: Deploy command: `solana program deploy` with appropriate options (not `anchor deploy` directly for mainnet)
- [ ] **DEP-008**: Deploy uses dedicated RPC (Helius) — not public mainnet-beta
- [ ] **DEP-009**: Deploy keypair is the correct one (verified before execution)
- [ ] **DEP-010**: Deploy buffer account — funded with sufficient SOL for the binary size
- [ ] **DEP-011**: Post-deploy verification: `anchor verify` or manual binary comparison
- [ ] **DEP-012**: IDL published: `anchor idl init/upgrade` — IDL matches deployed program

## 13.2 — Upgrade Safety

- [ ] **DEP-013**: Pre-upgrade checklist executed (all test suites pass, audit findings addressed)
- [ ] **DEP-014**: Upgrade tested on devnet before mainnet
- [ ] **DEP-015**: Account data migration plan if struct layouts changed
- [ ] **DEP-016**: Account migration tested — existing accounts can be deserialized by new program
- [ ] **DEP-017**: Anchor `Migration<'info, From, To>` account type used for struct changes
- [ ] **DEP-018**: Rollback plan documented — what to do if upgrade fails
- [ ] **DEP-019**: Multisig approval required for upgrade transaction
- [ ] **DEP-020**: Timelock period observed before upgrade execution
- [ ] **DEP-021**: Users notified of upcoming upgrade (changelog, Discord, frontend banner)
- [ ] **DEP-078**: `solana program close` / `--bypass-warning` is NOT used without a documented recovery path — closing a program account permanently locks its funds and bricks it (OptiFi $661K, Aug 2022, permanently frozen)
- [ ] **DEP-079**: Program upgrades preserve state compatibility and provide a migration/forwarding path; upgrade authority is NOT revoked mid-migration (leaving accounts undeserializable by the live program). (KB VC-36)

## 13.3 — Backend Deployment

- [ ] **DEP-022**: Backend deployed via CI/CD (not manual `ssh && git pull`)
- [ ] **DEP-023**: Health check endpoint exists and is monitored
- [ ] **DEP-024**: Zero-downtime deployment (rolling update or blue-green)
- [ ] **DEP-025**: Environment variables set in hosting platform (Render, Railway, etc.) — not in repo
- [ ] **DEP-026**: Auto-scaling configured (if traffic warrants)
- [ ] **DEP-027**: Process manager configured (PM2, systemd, or platform-native)
- [ ] **DEP-028**: Graceful shutdown: server closes connections on SIGTERM
- [ ] **DEP-029**: Database migrations run automatically or as part of deploy pipeline
- [ ] **DEP-030**: Deployment logs retained for incident investigation

## 13.4 — Frontend Deployment

- [ ] **DEP-031**: Frontend deployed via CI/CD (Vercel, Netlify, or similar)
- [ ] **DEP-032**: Build environment variables set correctly (NEXT_PUBLIC_ vars)
- [ ] **DEP-033**: Production build: `next build` succeeds without errors
- [ ] **DEP-034**: No `eslint-disable`/`ts-ignore` that masks build errors
- [ ] **DEP-035**: Source maps configuration: disabled or server-only in production
- [ ] **DEP-036**: Static assets cached with proper `Cache-Control` headers
- [ ] **DEP-037**: Custom domain with valid TLS certificate
- [ ] **DEP-038**: Redirect HTTP → HTTPS enforced

## 13.5 — Monitoring & Alerting

- [ ] **DEP-039**: Uptime monitoring: backend health check polled every 1-5 minutes
- [ ] **DEP-040**: Error rate monitoring: alerts when error rate exceeds threshold
- [ ] **DEP-041**: Response time monitoring: alerts when latency exceeds threshold
- [ ] **DEP-042**: On-chain monitoring: alerts for large value movements from fund PDAs
- [ ] **DEP-043**: On-chain monitoring: alerts for program upgrade authority changes
- [ ] **DEP-044**: On-chain monitoring: alerts when program is upgraded
- [ ] **DEP-045**: Database monitoring: connection pool, query latency, disk usage
- [ ] **DEP-046**: Log aggregation: centralized logging (Datadog, Grafana, CloudWatch, or similar)
- [ ] **DEP-047**: Alert channels: PagerDuty/Slack/Discord for critical alerts

## 13.6 — Disaster Recovery

- [ ] **DEP-048**: Database backups: automated, regular (daily minimum)
- [ ] **DEP-049**: Backup restoration tested (not just backup creation)
- [ ] **DEP-050**: On-chain state: recovery plan if backend database loses sync with on-chain state
- [ ] **DEP-051**: RPG failover: secondary RPC endpoint configured
- [ ] **DEP-052**: Region failover: can the backend be deployed to a different region?
- [ ] **DEP-053**: Contact list: emergency contacts for RPC provider, hosting provider, team members

## 13.7 — Network & DNS

- [ ] **DEP-054**: DNS: DNSSEC enabled if available
- [ ] **DEP-055**: DNS: CAA records restrict which CAs can issue certificates
- [ ] **DEP-056**: No dangling DNS records pointing to deprovisioned infrastructure (subdomain takeover)
- [ ] **DEP-057**: CDN (if used): proper cache invalidation on deploys
- [ ] **DEP-058**: DDoS protection: hosting platform or Cloudflare
- [ ] **DEP-059**: API endpoints not directly exposed (behind reverse proxy or API gateway)

## 13.8 — Testing Infrastructure

- [ ] **DEP-060**: Automated tests run in CI before deploy (all 8 test suites, 258 tests)
- [ ] **DEP-061**: Test environment uses devnet/localnet — NEVER mainnet
- [ ] **DEP-062**: Test wallets are funded from devnet faucet, not from mainnet wallets
- [ ] **DEP-063**: Integration tests cover all critical paths (deposit, withdraw, swap, fee)
- [ ] **DEP-064**: Security tests: fuzzing or property-based testing for program instructions
- [ ] **DEP-065**: Anchor test suite passes with `anchor test` before every deploy
- [ ] **DEP-066**: Test coverage tracked — critical paths have >80% coverage

## 13.9 — CI/CD Pipeline Security

- [ ] **DEP-067**: CI/CD uses pinned action versions with SHA (`actions/checkout@<sha>`) — not floating tags (`@main`, `@latest`)
- [ ] **DEP-068**: CI/CD secrets not accessible in builds triggered by pull requests from forks
- [ ] **DEP-069**: GitHub Actions don't execute attacker-controlled strings: no `${{ github.event.issue.title }}` in `run:` blocks (script injection)
- [ ] **DEP-070**: Third-party CI actions/plugins audited before use — prefer official or verified publishers
- [ ] **DEP-071**: CI pipeline logs don't print secrets (check for `echo $SECRET` or debug output)

## 13.10 — Production Hardening

- [ ] **DEP-072**: Cloud storage buckets (S3, GCS, Azure Blob) are NOT publicly readable or writable — verify with `aws s3 ls` or equivalent
- [ ] **DEP-073**: `.git` directory not accessible in production web server (test: `curl https://domain/.git/HEAD`)
- [ ] **DEP-074**: Backup files (.bak, .sql, .dump, .old, .swp) not accessible via web server
- [ ] **DEP-075**: Docker containers run as non-root user with minimal capabilities and read-only filesystem where possible
- [ ] **DEP-076**: Default credentials changed on ALL services before production deployment (databases, admin panels, queues, caches)
- [ ] **DEP-077**: Subdomain DNS records point to active services — dangling CNAMEs removed to prevent subdomain takeover
