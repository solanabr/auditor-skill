# 09 — Backend Security Checklist

> Domain: Express.js backend (apps/backend/)  
> Severity if missed: HIGH to MEDIUM  
> References: OWASP Top 10, project backend-security instructions

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 9.1 — Authentication & Wallet Verification

- [ ] **BE-001**: Every POST/PUT/DELETE endpoint verifies wallet ownership via signature — not just trusting `walletAddress` from body
- [ ] **BE-002**: Signature verification headers present: `x-wallet`, `x-signature`, `x-timestamp`
- [ ] **BE-003**: Signature message format: `${method}:${path}:${timestamp}` — consistent across all endpoints
- [ ] **BE-004**: Verification library: `tweetnacl` or `@noble/ed25519` — correct usage of `sign.detached.verify()`
- [ ] **BE-005**: Replay protection: timestamp checked — reject if > 5 minutes old
- [ ] **BE-006**: Timestamp is compared against server time, not client-supplied time
- [ ] **BE-007**: Nonce or idempotency key used for critical mutations (prevent duplicate submissions)
- [ ] **BE-008**: Admin routes have ADDITIONAL auth beyond wallet signature (IP allowlist, admin wallet list)
- [ ] **BE-009**: No endpoint trusts `req.body.walletAddress` without signature verification for identity
- [ ] **BE-010**: Auth middleware is applied to ALL protected routes — no route accidentally unprotected

## 9.2 — Input Validation & Injection Prevention

- [ ] **BE-011**: Every request body passes through a zod schema before processing
- [ ] **BE-012**: MongoDB queries never use raw user input in `.find()` — validate format first
- [ ] **BE-013**: MongoDB: reject objects/arrays where strings are expected (NoSQL injection: `{ "$gt": "" }` in string fields)
- [ ] **BE-014**: MongoDB: use `$eq` explicitly instead of bare value matching for user-supplied fields
- [ ] **BE-015**: No `eval()`, `Function()`, or dynamic code execution with user input
- [ ] **BE-016**: No path traversal: file paths from user input are sanitized (no `../`)
- [ ] **BE-017**: No command injection: no `child_process.exec()` with user input
- [ ] **BE-018**: No SSRF: no HTTP requests to user-supplied URLs without allowlist
- [ ] **BE-019**: URL parameters validated — no open redirect via unvalidated redirect URLs
- [ ] **BE-020**: Content-Type header validated — only accept `application/json` for JSON endpoints

## 9.3 — On-Chain Verification

- [ ] **BE-021**: Trade records: transaction `signature` is verified as a real confirmed transaction via `connection.getTransaction()`
- [ ] **BE-022**: Trade verification: check that the transaction actually does what it claims (correct program, correct accounts)
- [ ] **BE-023**: Withdrawal records: verify the investor actually signed the withdrawal transaction
- [ ] **BE-024**: Deposit records: verify the deposit transaction signature on-chain before recording in database
- [ ] **BE-025**: Bridge deposits (if applicable): verify EVM transaction receipt via RPC before recording
- [ ] **BE-026**: No trust of off-chain data without on-chain verification for financial records
- [ ] **BE-027**: Transaction confirmation: use `confirmed` or `finalized` commitment — not `processed`
- [ ] **BE-028**: Handle transaction verification failures gracefully — don't record unverified transactions

## 9.4 — Rate Limiting

- [ ] **BE-029**: Rate limiting is enabled in ALL environments (not just production)
- [ ] **BE-030**: Global rate limit exists (e.g., 100 req/min per IP)
- [ ] **BE-031**: Per-endpoint rate limits for financial endpoints: swap, withdraw, trade (5-10 req/hour)
- [ ] **BE-032**: Per-wallet rate limits in addition to per-IP
- [ ] **BE-033**: Rate limit headers returned (`X-RateLimit-Remaining`, `Retry-After`)
- [ ] **BE-034**: Rate limiting cannot be bypassed via proxy/spoofed headers (X-Forwarded-For)
- [ ] **BE-035**: Rate limit store: in-memory works for single instance, Redis for multi-instance

## 9.5 — Error Handling

- [ ] **BE-036**: Custom error classes used: `AppError`, `AuthError`, `ValidationError` (not bare `Error`)
- [ ] **BE-037**: No stack traces exposed in production responses
- [ ] **BE-038**: Error responses use standard format: `{ error: string, code?: string }`
- [ ] **BE-039**: Status codes are correct: 400 validation, 401 auth, 403 forbidden, 404 not found, 429 rate limit, 500 internal
- [ ] **BE-040**: 500 errors are logged with full context (wallet, endpoint, timestamp, stack trace) but NOT returned to client
- [ ] **BE-041**: No `catch (e) { }` empty catch blocks — flag every occurrence
- [ ] **BE-042**: Global error handler (`app.use((err, req, res, next) => ...)`) catches all unhandled errors
- [ ] **BE-043**: Async route handlers wrapped with error-catching middleware (or use express-async-errors)
- [ ] **BE-044**: Database connection errors handled gracefully — don't crash the server

## 9.6 — HTTP Security Headers

- [ ] **BE-045**: Helmet middleware enabled with appropriate CSP
- [ ] **BE-046**: HSTS header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- [ ] **BE-047**: X-Frame-Options: `DENY` or `SAMEORIGIN`
- [ ] **BE-048**: X-Content-Type-Options: `nosniff`
- [ ] **BE-049**: Content-Security-Policy: restrictive, no `unsafe-eval` or `unsafe-inline` unless necessary
- [ ] **BE-050**: Referrer-Policy: `strict-origin-when-cross-origin` or stricter

## 9.7 — CORS Configuration

- [ ] **BE-051**: CORS does NOT use `origin: true` (allows any origin)
- [ ] **BE-052**: CORS does NOT use `origin: '*'` (allows any origin)
- [ ] **BE-053**: CORS uses an explicit allowlist of origins
- [ ] **BE-054**: CORS `credentials: true` only with specific origins (not wildcard)
- [ ] **BE-055**: CORS `methods` restricted to necessary HTTP methods
- [ ] **BE-056**: CORS `allowedHeaders` restricted to necessary headers

## 9.8 — Database Security (MongoDB)

- [ ] **BE-057**: Database connection string does NOT contain credentials in code (uses env var)
- [ ] **BE-058**: Database uses authentication (not anonymous access)
- [ ] **BE-059**: Database user has minimum required permissions (not admin)
- [ ] **BE-060**: Database is not publicly accessible (firewall/security group)
- [ ] **BE-061**: Sensitive data is not logged in debug/info level
- [ ] **BE-062**: Database indexes exist for frequently queried fields (performance + DoS prevention)
- [ ] **BE-063**: No raw string concatenation in MongoDB queries — use parameterized queries
- [ ] **BE-064**: Document size limits enforced (prevent stored DoS via huge documents)

## 9.9 — Environment & Configuration

- [ ] **BE-065**: All required env vars validated at startup — fail fast if missing
- [ ] **BE-066**: No default values for secrets (no `process.env.SECRET || "default"`)
- [ ] **BE-067**: `.env` file is in `.gitignore`
- [ ] **BE-068**: No secrets in `package.json`, `tsconfig.json`, or any config file
- [ ] **BE-069**: Node environment is set correctly: `NODE_ENV=production` in production
- [ ] **BE-070**: Debug endpoints disabled in production (`/debug`, `/test`, `/dev`)

## 9.10 — Logging & Monitoring

- [ ] **BE-071**: Structured logging (JSON format) for machine-parsable logs
- [ ] **BE-072**: Log rotation configured (don't fill disk)
- [ ] **BE-073**: Sensitive data NOT logged: private keys, passwords, full request bodies with secrets
- [ ] **BE-074**: Request logging includes: method, path, wallet (if authed), status code, response time
- [ ] **BE-075**: Failed auth attempts logged with IP and wallet address
- [ ] **BE-076**: Anomaly detection: alerts on >X failed auth attempts from same IP/wallet

## 9.11 — IDOR & Mass Assignment

- [ ] **BE-077**: Every endpoint returning user-specific data verifies the authenticated user owns that resource (no IDOR)
- [ ] **BE-078**: Resource IDs in URLs/params cannot be enumerated to access other users' data (test with another user's ID)
- [ ] **BE-079**: Request body fields are explicitly picked before DB write — never `db.update(req.body)` or spread `...body`
- [ ] **BE-080**: No mass assignment: sending `{ isAdmin: true }` or `{ role: "admin" }` in body has no effect
- [ ] **BE-081**: API responses don't leak fields from other users (verify query filters include auth user constraint)

## 9.12 — BaaS Security (Supabase / Firebase / Appwrite)

- [ ] **BE-082**: If using Supabase: RLS (Row Level Security) is ENABLED on every single table — `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`
- [ ] **BE-083**: RLS policies use `auth.uid() = user_id` (not just role check `authenticated`) — user can only see own rows
- [ ] **BE-084**: RLS policies exist for ALL operations: SELECT, INSERT, UPDATE, DELETE — not just SELECT
- [ ] **BE-085**: `service_role` / admin SDK key is NEVER in client-side code or `NEXT_PUBLIC_` env vars
- [ ] **BE-086**: Supabase Storage bucket policies restrict upload MIME types (no `.html`, `.svg`, `.js` unless intentional)
- [ ] **BE-087**: Database functions marked `security definer` are audited — they bypass RLS
- [ ] **BE-088**: If using Firebase: Firestore/RTDB security rules exist and are not `allow read, write: if true`
- [ ] **BE-089**: Firebase Storage rules validate file type and size — not open to all authenticated users
- [ ] **BE-090**: BaaS anon key (public) can only perform operations explicitly allowed by RLS/rules — test with curl

## 9.13 — Advanced Injection & Protocol Safety

- [ ] **BE-091**: No ReDoS — user-controlled strings not used in regex patterns, or safe regex library used with length limits
- [ ] **BE-092**: GraphQL: introspection disabled in production; query depth and complexity limits enforced
- [ ] **BE-093**: WebSocket connections require authentication on connect; unauthenticated sockets rejected immediately
- [ ] **BE-094**: Webhook endpoints validate cryptographic signatures (e.g., Stripe `constructEvent()`, GitHub HMAC)
- [ ] **BE-095**: Body parser has explicit size limits: `express.json({ limit: '1mb' })` — no unbounded payload acceptance
- [ ] **BE-096**: No XML parsing of user input, or if needed, external entities disabled (XXE prevention: `noent: false`, `dtd: false`)
- [ ] **BE-097**: HTTP response headers don't reflect user input (header injection / response splitting prevention)
- [ ] **BE-098**: Session tokens regenerated after authentication (session fixation prevention)
- [ ] **BE-099**: Login/signup responses don't reveal whether an account exists (consistent timing and messages for enumeration prevention)
- [ ] **BE-100**: No `JSON.parse` on user input used to construct objects with `__proto__` or `constructor` (prototype pollution via deserialization)

## 9.14 — Custody, Fund-Moving Auth & Off-Chain/On-Chain Consistency

- [ ] **BE-101**: Balance/inventory mutations on a shared resource use an atomic conditional update / row-lock (optimistic version or compare-and-set), never a read-modify-write split across an `await` boundary where two concurrent requests both read the old value (Aurory $830K TOCTOU)
- [ ] **BE-102**: Fund-moving endpoints require step-up authorization (fresh signature / 2FA / withdrawal-address allowlist) beyond a valid bearer session token — a leaked session cookie alone must NOT authorize a withdrawal (Thunder Terminal $240K, Banana Gun $3M: leaked session == custody)
- [ ] **BE-103**: Backends that sign an on-chain action after an off-chain check pair the atomic DB claim WITH an on-chain replay/nonce guard as defense-in-depth — a single logical claim cannot execute twice even if the DB row and the chain disagree (cross-ref VC-35; games/airdrops double-claim)
