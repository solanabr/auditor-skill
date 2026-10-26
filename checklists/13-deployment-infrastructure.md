# 13 — Deployment & Infrastructure Checklist

> Domain: Build process, deploy pipeline, monitoring, verifiable builds  
> Severity if missed: HIGH (unverifiable binary) to LOW (missing monitoring)  
> References: Anchor verifiable builds, Solana deploy process, Render/Vercel config, GCP Cloud Run / Terraform IaC

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

- [ ] **DEP-067**: CI/CD uses pinned action versions with SHA (`actions/checkout@<sha>`) — not floating tags (`@main`, `@latest`); each SHA resolves to a tag or branch of the named action repository rather than an impostor commit from its fork network (`git ls-remote https://github.com/<owner>/<repo>` lists it (it reaches github.com, so it asks for approval); run it from a scratch dir outside the checkout, so its repo config does not apply, and only for an `owner/repo` slug that matches `^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`) and carries a matching `# vX.Y.Z` comment; pins are kept current by a Dependabot or Renovate `github-actions` updater (no updater = PARTIAL), because an old pin keeps fixed bugs — in `pull_request_target` / `workflow_run` workflows, `actions/checkout` below v2.8.0 / v3.7.0 / v4.4.0 / v5.1.0 / v6.1.0 lacks the fork-PR guard (DEP-093)
- [ ] **DEP-068**: CI/CD secrets not accessible in builds triggered by pull requests from forks (triggers that run with secrets on fork-originated activity — `pull_request_target`, `workflow_run`, comment / review / issue / discussion events — are checked in §13.13)
- [ ] **DEP-069**: GitHub Actions don't execute attacker-controlled strings: no `${{ github.event.issue.title }}` — or any other event text, branch or file name, commit message, or step output derived from them — in `run:` blocks, `actions/github-script` `script:` or composite-action steps (script injection; sources and sinks in `references/vuln-classes/github-actions.md` §4, recipe R6)
- [ ] **DEP-070**: Third-party CI actions/plugins audited before use — prefer official or verified publishers
- [ ] **DEP-071**: CI pipeline logs don't print secrets (check for `echo $SECRET` or debug output)

## 13.10 — Production Hardening

- [ ] **DEP-072**: Cloud storage buckets (S3, GCS, Azure Blob) are NOT publicly readable or writable — check read access with the unauthenticated, read-only listings under "Live probes" below. For S3: `env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ENDPOINT_URL -u AWS_ENDPOINT_URL_S3 -u AWS_CA_BUNDLE AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null aws s3api list-objects-v2 --bucket '<bucket>' --page-size 1 --max-items 1 --query KeyCount --output text --no-sign-request --region us-east-1`, which reads none of the auditor's AWS profiles, endpoints, CA bundle, config or credentials files and prints only a count of keys: `0` or `1`, not `AccessDenied`, means anyone can list it (how the CLI follows a bucket in another region was not verified offline). For GCS: `curl -q -sS --max-time 30 -o /dev/null -w '%{http_code}' 'https://storage.googleapis.com/storage/v1/b/<bucket>/o?maxResults=1'`; for Azure: `curl -q -sS --max-time 30 -o /dev/null -w '%{http_code}' 'https://<account>.blob.core.windows.net/<container>?restype=container&comp=list&maxresults=1'`; `200` means anyone can list it. Run it only when `QUESTIONS.md` Q47 allows live probes, and only for a host or bucket that `audit_<n>/intake.md` §8 lists under Live probes; list it in the report as an outside contact (Rule 11b). `<host>` is a DNS name or IPv4 address exactly as `intake.md` §8 lists it: ASCII letters, digits, `-` and `.` only (an IDN in its `xn--` form), with no user, port or path. `<bucket>` is 3–63 lowercase letters, digits, `-` and `.`, beginning and ending with a letter or digit, with no `..`. Refuse anything else. An Azure `<account>` is 3–24 lowercase letters and digits, and its `<container>` lowercase letters, digits and `-`. Otherwise (Q47 no or unanswered, a bucket §8 does not list, or no `aws` or `curl` to run the probe) give the owner the command and ask for its output with the date; until it arrives the item is never `[PASS]`: it is `[PARTIAL]`, or `[FAIL-N]` when the IaC or server config already shows the exposure. Write access is never probed: judge it from the bucket policy and ACLs, in the IaC or from the owner
- [ ] **DEP-073**: `.git` directory not accessible in production web server — test with the unauthenticated request under "Live probes" below, which reads no cookies, netrc or curl config (`-q` stays first): `curl -q -sS --max-time 30 --max-filesize 65536 -o '<R>/probes/dep-073-<host>.txt' -w '%{http_code} %{redirect_url}\n' 'https://<host>/.git/HEAD'`. It is exposed only when the status is `200` and `LC_ALL=C grep -cE '^(ref: refs/|[0-9a-f]{40}$|[0-9a-f]{64}$)' '<R>/probes/dep-073-<host>.txt'` prints `1`. A `200` with any other body is a page served for any path: confirm it with a made-up path. A `3xx` is recorded, and its target is probed only when §8 lists that host too. Never print the saved body. Run it only when `QUESTIONS.md` Q47 allows live probes, and only for a host or bucket that `audit_<n>/intake.md` §8 lists under Live probes; list it in the report as an outside contact (Rule 11b). `<host>` is a DNS name or IPv4 address exactly as `intake.md` §8 lists it: ASCII letters, digits, `-` and `.` only (an IDN in its `xn--` form), with no user, port or path. `<bucket>` is 3–63 lowercase letters, digits, `-` and `.`, beginning and ending with a letter or digit, with no `..`. Refuse anything else. Otherwise (Q47 no or unanswered, a host §8 does not list, or no `curl` to run the probe) give the owner the same commands and ask for the two lines they print, with the date; until they arrive the item is never `[PASS]`: it is `[PARTIAL]`, or `[FAIL-N]` when the IaC or server config already shows the exposure
- [ ] **DEP-074**: Backup files (.bak, .sql, .dump, .old, .swp) not accessible via web server
- [ ] **DEP-075**: Docker containers run as non-root user with minimal capabilities and read-only filesystem where possible
- [ ] **DEP-076**: Default credentials changed on ALL services before production deployment (databases, admin panels, queues, caches)
- [ ] **DEP-077**: Subdomain DNS records point to active services — dangling CNAMEs removed to prevent subdomain takeover

> **Live probes (DEP-072, DEP-073).** Run a probe only when `QUESTIONS.md` Q47 allows live probes, and only for a host or bucket that `audit_<n>/intake.md` §8 lists under Live probes, each value exactly as listed there. `<host>` is a DNS name or IPv4 address exactly as `intake.md` §8 lists it: ASCII letters, digits, `-` and `.` only (an IDN in its `xn--` form), with no user, port or path. `<bucket>` is 3–63 lowercase letters, digits, `-` and `.`, beginning and ending with a letter or digit, with no `..`. Refuse anything else. Fill in a value only after checking it against that rule, because a value holding a single quote would end the quotes it is written in: only this first check catches a single quote; each probe below checks every other value again and runs nothing when it does not fit. An Azure `<account>` is 3–24 lowercase letters and digits, and its `<container>` lowercase letters, digits and `-`. `<R>` is the run directory, `audit_<n>`. No probe reads the auditor's credentials, cookies or tool config, and the report lists each one that ran as an outside contact (Rule 11b). Each probe asks for approval, since the host or bucket it contacts is chosen at run time and no bundled tool limits it. When an item falls back to the owner, they get the same lines, with any empty directory as `<R>`, and send back what the lines print, with the date.
> ```
> # The checks each probe makes first
> host_ok() {
>   case "$1" in ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-]*) echo "refused: not a host name or IPv4 address: $1"; return 1 ;; esac
> }
> bucket_ok() {
>   case "$1" in ''|*[!abcdefghijklmnopqrstuvwxyz0123456789.-]*) echo "refused: not a bucket name: $1"; return 1 ;; esac
>   case "$1" in .*|*.|-*|*-|*..*) echo "refused: not a bucket name: $1"; return 1 ;; esac
>   [ "${#1}" -ge 3 ] && [ "${#1}" -le 63 ] || { echo "refused: not a bucket name: $1"; return 1; }
> }
> account_ok() {
>   case "$1" in ''|*[!abcdefghijklmnopqrstuvwxyz0123456789]*) echo "refused: not an Azure account name: $1"; return 1 ;; esac
>   [ "${#1}" -ge 3 ] && [ "${#1}" -le 24 ] || { echo "refused: not an Azure account name: $1"; return 1; }
> }
> container_ok() {
>   case "$1" in ''|*[!abcdefghijklmnopqrstuvwxyz0123456789-]*) echo "refused: not an Azure container name: $1"; return 1 ;; esac
> }
> # DEP-072, S3: 0 or 1, not AccessDenied, means anyone can list it; no key name is printed
> bucket_ok '<bucket>' && env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_ENDPOINT_URL -u AWS_ENDPOINT_URL_S3 -u AWS_CA_BUNDLE AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null aws s3api list-objects-v2 --bucket '<bucket>' --page-size 1 --max-items 1 --query KeyCount --output text --no-sign-request --region us-east-1
> # DEP-072, GCS: 200 means anyone can list the bucket
> bucket_ok '<bucket>' && curl -q -sS --max-time 30 -o /dev/null -w '%{http_code}' 'https://storage.googleapis.com/storage/v1/b/<bucket>/o?maxResults=1'
> # DEP-072, Azure Blob: 200 means anyone can list the container
> account_ok '<account>' && container_ok '<container>' && curl -q -sS --max-time 30 -o /dev/null -w '%{http_code}' 'https://<account>.blob.core.windows.net/<container>?restype=container&comp=list&maxresults=1'
> # DEP-073: the status and any redirect target; at most 64 KiB of the body goes to <R>/probes/, never to the screen
> host_ok '<host>' && mkdir -p '<R>/probes' && curl -q -sS --max-time 30 --max-filesize 65536 -o '<R>/probes/dep-073-<host>.txt' -w '%{http_code} %{redirect_url}\n' 'https://<host>/.git/HEAD'
> # DEP-073, after a 200: 1 means the saved body is a git HEAD, so .git/ is exposed
> host_ok '<host>' && LC_ALL=C grep -cE '^(ref: refs/|[0-9a-f]{40}$|[0-9a-f]{64}$)' '<R>/probes/dep-073-<host>.txt'
> # DEP-073, after a 200 with any other body: a made-up path that answers 200 too shows a page served for any path
> host_ok '<host>' && curl -q -sS --max-time 30 --max-filesize 65536 -o /dev/null -w '%{http_code}\n' 'https://<host>/.git/no-such-file-a7f3'
> ```

## 13.11 — Cloud IaC (GCP / AWS) & Terraform

- [ ] **DEP-080**: Internal services (Cloud Run / Lambda / ECS) are NOT invokable by `allUsers` / anonymous principals — ingress is `internal-and-cloud-load-balancing` (or a VPC-only endpoint), the public API sits behind a load balancer / WAF, and the internal hop is authenticated (IAM invoker role or signed service-to-service tokens)
- [ ] **DEP-081**: Managed databases (Cloud SQL / RDS) have no public IP; access is via private VPC, Auth Proxy or IAM database auth; no `0.0.0.0/0` authorized network
- [ ] **DEP-082**: Runtime secrets are injected from Secret Manager / Parameter Store at deploy or start — not baked into container images, `Dockerfile` `ENV`, or Terraform variables (which end up in state)
- [ ] **DEP-083**: Terraform state is remote (GCS / S3 backend) with encryption and locking; `*.tfstate`, `tfplan*`, `.terraform/` and any binary under `terraform/` are gitignored *and* rejected by a repo-hygiene check — state contains secrets and the full resource inventory
- [ ] **DEP-084**: `terraform apply` runs only from the protected default branch via OIDC / workload-identity federation (no long-lived cloud JSON keys in CI secrets); fork PRs get at most a read-only `plan` and cannot reach cloud credentials
- [ ] **DEP-085**: One service account per service with least privilege — nothing runs as the default compute service account, and no service account holds `roles/editor` / `roles/owner`
- [ ] **DEP-086**: Deploys pin image digests (`@sha256:` not `:latest`), and a rollback workflow (previous-revision traffic split) exists and has been exercised at least once

## 13.12 — Runtime Upgrade & Feature-Gate Readiness (Transaction v1)

- [ ] **DEP-087**: Solana client libraries are at or above the minimum for the runtime features active on the target cluster and are pinned in the lockfile — for transaction v1: `@solana/kit` ≥ 8.0.0, `@solana/web3.js` ≥ 3.0.0-rc.3 (1.x ≥ 1.99.0 read-only), Rust `solana-*` ≥ 4.2, `solders` ≥ 0.29.0, `yellowstone-grpc-proto` ≥ 12.6.0 pinned directly, Yellowstone geyser ≥ 15.1.1, `@triton-one/yellowstone-grpc` ≥ 6.0.0, local validator / CLI ≥ 4.2 or Surfpool ≥ 1.5; generated protobuf stubs are regenerated, not just version-bumped
- [ ] **DEP-088**: Tracked feature gates (e.g. `txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL`) are monitored per cluster with an alert on activation; readers and indexers are upgraded **before** the gate activates on the cluster they consume, and the staging validator runs with the gate enabled so the v1 path is exercised pre-mainnet
- [ ] **DEP-089**: Ingress and storage handle the new envelope — relayer / QUIC stream windows accept 4,096-byte transactions, archive and cold-storage read paths round-trip a v1 transaction without downgrading through a v0-only model, and `getSignaturesForAddress`-style paths that are unaffected are documented as such rather than assumed

## 13.13 — GitHub Actions Trigger Trust

> Applies to workflows a non-collaborator can trigger — `issue_comment`, `pull_request_review_comment`, `pull_request_review`, `discussion_comment`, `discussion`, `issues`, `gollum`, `pull_request_target`, `workflow_run` — when the job holds write scopes, secrets, `id-token: write`, an AI agent, or runs PR-controlled code. Playbook: `references/vuln-classes/github-actions.md` (read-only rules of engagement in §0); recipes R1–R8 in `discovery/grep-commands.md`. Mark `[N/A]` when no such workflow exists, and grade an item `[PARTIAL]` while its verdict depends on a hosted setting the source does not show (default token permission, environment reviewers, OIDC trust policy).

- [ ] **DEP-090**: Every job triggered by `issue_comment`, `pull_request_review_comment`, `pull_request_review`, `discussion_comment`, `discussion`, `issues` or `gollum` that holds write scopes, secrets, `id-token: write`, an AI agent or runs PR code gates its job-level `if:` on the triggering object's own `author_association` in {`OWNER`, `MEMBER`, `COLLABORATOR`}, paired per event branch (`comment.*` on comment events, `review.*` on `pull_request_review`, `issue.*` on `issues`, `discussion.*` on `discussion`) and never on an opener field (`issue.` / `pull_request.` / `discussion.author_association`) on a comment or review branch; a mention or command match alone is not a gate, an agent CLI started from `run:` (`claude -p`, `npx @anthropic-ai/claude-code`, `gemini -p`, `codex exec`) has no check of its own, and a job that can deploy or publish (and every `gollum` job, which has no association field) checks the actor's repository permission through the REST API because association is not permission (KV-139; recipes R1–R2)
- [ ] **DEP-091**: Gate comparisons are sound: membership is `==` or `contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), …)`, never string-form `contains('OWNER,MEMBER,…', …)` (a field the event lacks resolves to `''`, which is a substring of every string) and never a deny-list (`!= 'NONE'`, `!contains(fromJSON(…), …)`); `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR` and `FIRST_TIMER` are never allowed; on PR-family and `workflow_run` events no trust decision rests on `github.actor` / `github.triggering_actor` (whoever last acted on the event — use `github.event.pull_request.user.login` plus `head.repo.full_name == github.repository`), while on `issue_comment` `github.actor == '<maintainer>'` is a sound allowlist because the actor is the commenter (`contains(github.actor, …)` is a substring test and sound on no event); bot identities in `github.actor` and REST or webhook `login` comparisons are `<slug>[bot]` (only the gh CLI's JSON output renders them as `app/<slug>`) (recipe R3)
- [ ] **DEP-092**: A comment-, review- or label-gated job that checks out or executes PR code binds the commit that was approved — `github.event.review.commit_id` on `pull_request_review`, `github.event.pull_request.head.sha` on a labeled `pull_request_target`, and on `issue_comment` (whose payload has no `pull_request` object, so `github.event.pull_request.head.sha` is empty) a SHA named in the command that the job checks out exactly and rejects unless it is still the PR head — never `refs/pull/<n>/head`, `head_ref` or a branch name resolved after approval (KV-139 step 5; recipe R7)
- [ ] **DEP-093**: No `pull_request_target` or `workflow_run` job holding write scopes, secrets, OIDC or a deploy path checks out or executes fork-controlled code — no `ref:` to the PR head or merge commit or to `workflow_run.head_branch` / `head_sha`, no `repository: …head.repo.full_name`, no `git fetch … pull/<n>/…` or `gh pr checkout`, no `allow-unsafe-pr-checkout: true`, and no build or install entry point over such code (`npm|yarn|pnpm install`, `pip install` / `pip download` of an sdist, `cargo build` / `build-sbf` → `build.rs` and proc-macros, `anchor build|test` → `Anchor.toml` `[hooks]` / `[scripts]`, `make`, `uses: ./…`); FAIL when PR code is checked out or executed, PASS for a job that checks out only the base ref, PARTIAL when such a job pins `actions/checkout` below the fork-PR guard (v2.8.0 / v3.7.0 / v4.4.0 / v5.1.0 / v6.1.0 / v7.0.0) (KV-140; recipe R7)
- [ ] **DEP-094**: `workflow_run` consumers treat the triggering run as attacker-authored: artifacts are downloaded into `$RUNNER_TEMP`, parsed and validated as data (e.g. a numeric PR number) and never executed, sourced, unpacked over the checkout or written to `$GITHUB_ENV` / `$GITHUB_PATH`; gates use `github.event.workflow_run.event` and `github.event.workflow_run.head_repository.full_name == github.repository`, never `workflow_run.head_branch == 'main'` (a fork branch can carry that name) or `github.repository` (always the base repository on this trigger) (KV-140; recipe R4)
- [ ] **DEP-095**: No value derived from event data, artifacts or untrusted step outputs is written to `$GITHUB_ENV` or `$GITHUB_PATH` in a privileged workflow (`>>`, `tee -a`, `core.exportVariable`, `core.addPath`) — a newline in it defines any variable for every later step, `BASH_ENV` and `LD_PRELOAD` turn that into code execution, and the runner blocks only `NODE_OPTIONS`; multiline `$GITHUB_OUTPUT` / `$GITHUB_ENV` writes use a random per-run delimiter or a file, and event-derived step outputs reach `run:` / `script:` only through a quoted `env:` variable (recipes R5–R6)
- [ ] **DEP-096**: Release, publish and deploy jobs restore no GitHub Actions cache (writers include `actions/cache`, `setup-*` `cache:` and `actions/setup-go`'s default cache, `Swatinem/rust-cache` and `actions-rust-lang/setup-rust-toolchain`, `astral-sh/setup-uv` `enable-cache`, `ruby/setup-ruby` `bundler-cache`, Docker `type=gha`, sccache's GHA backend) that a job running untrusted code in default-branch context can write — `pull_request_target`, `issue_comment`, `issues`, `discussion*`, `workflow_run` and agent jobs all save into the default branch's cache scope, and the 10 GB eviction lets them replace existing entries (Ultralytics 2024, Clinejection 2026; KV-140 step 6)
