# 19 — AI Agent Security Checklist (Solana × AI)

> Domain: Autonomous/AI agents that hold keys, sign transactions, use MCP tools, or run in a Solana deploy pipeline
> Severity if missed: CRITICAL (agent hot key drained / malicious upgrade shipped) to MEDIUM (over-scoped delegation)
> References: Trail of Bits agentic-actions-auditor (CI vectors ported below), Solana wallet/signing model, MCP tool-trust model

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

This checklist is NET-NEW: it covers the seam where an AI agent (autonomous trading bot, MCP-driven assistant, or AI coding agent in CI) is given the ability to act on Solana. An agent is *any* non-human actor that can select and submit instructions on behalf of a principal. If the codebase has no such actor, mark the whole checklist `[N/A]`.

---

## 19.1 — Agent Wallet Custody

- [ ] **AI-001**: Agent signing key is NEVER stored in plaintext at rest and NEVER passed as a raw env var / CLI arg the agent process can read back — key lives in a KMS/HSM, enclave, or remote signer; the agent holds a handle, not the bytes (grep for `Keypair.fromSecretKey`, `createKeyPairSignerFromBytes`, `PRIVATE_KEY`, `SECRET_KEY`, `*.json` keypair loads inside agent code)
- [ ] **AI-002**: Per-transaction spend cap enforced BEFORE signing — a single agent-signed tx cannot move more than a hard-coded maximum (lamports + per-mint token amount), checked in code, not merely prompted
- [ ] **AI-003**: Per-epoch / rolling-window spend cap enforced — cumulative value signed over a time window (hour/day/epoch) is bounded and persisted across restarts, so an attacker cannot reset it by crashing the process
- [ ] **AI-004**: Program allowlist — the agent may only sign instructions whose `programId` is on an explicit allowlist; any instruction targeting an unknown program is rejected pre-sign
- [ ] **AI-005**: Instruction allowlist — within allowed programs, only specific instruction discriminators/types are signable (e.g., swap + close, NOT `SetAuthority`, `Upgrade`, `Assign`, `CloseAccount` to arbitrary dest)
- [ ] **AI-006**: Destination allowlist — token/SOL transfer and `close`/rent-recipient destinations are constrained to a known set (self, treasury, whitelisted counterparties); arbitrary destinations rejected
- [ ] **AI-007**: The agent hot wallet holds only working capital; the bulk of funds sits in a separate cold/multisig wallet the agent CANNOT sign for (blast radius = hot balance only)

## 19.2 — Signing Discipline

- [ ] **AI-008**: Every transaction is `simulateTransaction`-ed AND decoded (instructions resolved to program + type + amounts) BEFORE a signature is produced — simulation failure or decode-mismatch aborts signing
- [ ] **AI-009**: No blind bulk signing — `signAllTransactions` / batch signing does not sign an opaque array; each element passes the same allowlist + simulation gate individually (grep for `signAllTransactions`)
- [ ] **AI-010**: Human-in-the-loop threshold — transactions above a configured value (or touching authority-changing instructions) require explicit human approval, not agent auto-approval
- [ ] **AI-011**: Simulation result is actually inspected — writable-account deltas / balance changes from the simulation are compared against the agent's intent, not just checked for `err == null`
- [ ] **AI-012**: The signer is the LAST stage and is isolated — the component that holds the key validates the fully-built tx itself and does not trust an upstream "already validated" flag from the LLM/orchestration layer

## 19.3 — MCP Tool Trust

- [ ] **AI-013**: Every MCP server the agent connects to is pinned by version AND integrity (hash / lockfile / pinned image digest) — not `@latest`, not an unpinned remote URL (inspect `.mcp.json` / MCP client config)
- [ ] **AI-014**: MCP tool *descriptions* are treated as untrusted data — the agent does not auto-execute or auto-sign because a tool's description/annotation instructs it to; descriptions cannot inject control-flow (tool-poisoning defense)
- [ ] **AI-015**: MCP tool *output* is validated/typed before it can influence a signing decision — a tool result is data, never a command; it does not flow unchecked into `eval`, a prompt that then signs, or transaction-construction
- [ ] **AI-016**: MCP server set is allowlisted and least-privilege — the agent cannot silently gain new tools at runtime (no dynamic server discovery that adds signing-capable tools without review)
- [ ] **AI-017**: Sensitive/signing-capable MCP tools require a distinct trust boundary (separate approval, separate credential) from read-only data tools — a poisoned read tool cannot reach the signer

## 19.4 — Injection Surface (On-Chain Data → LLM)

- [ ] **AI-018**: Attacker-controllable on-chain reads — transaction memos, SPL/Metaplex token & NFT metadata (name/symbol/uri and fetched JSON), account data, and program logs — are sanitized / delimited / treated as untrusted before entering the LLM context (grep for memo parsing, `metadata`, `logMessages`, `getParsedTransaction` feeding a prompt)
- [ ] **AI-019**: Retrieved/on-chain data CANNOT alter a tool-call or signing decision without passing a deterministic guardrail (allowlist/cap check) that runs OUTSIDE the LLM — i.e., prompt-injected text can never be the sole authority that triggers a signature
- [ ] **AI-020**: Off-chain content the agent fetches by following on-chain pointers (e.g., an NFT `uri`, a URL in a memo) is fetched in a sandbox and its body is likewise treated as untrusted LLM input, not as instructions

## 19.5 — AI-in-CI (Solana Deploy Pipeline)

> Solana port of Trail of Bits agentic-actions-auditor (9 CI/agent attack vectors), phrased for a program deploy/upgrade pipeline. An AI coding agent (Claude Code Action, Gemini CLI, Codex, etc.) running in CI is the "agent"; attacker-controlled input is PR/issue/comment/commit/log content.

- [ ] **AI-021**: No deploy/upgrade authority in agent reach — the CI AI agent's job/step has NO access to a program deploy keypair or upgrade-authority keypair (no `PROGRAM_DEPLOY_KEY`, `UPGRADE_AUTHORITY`, `id.json` in the agent step's env/secrets/checkout)
- [ ] **AI-022**: Human gate before ship — `solana program deploy`, `anchor deploy`, `anchor upgrade`, `solana program set-upgrade-authority`, and squads/multisig submit steps are NOT reachable from an AI-agent step without an explicit human approval boundary between the agent and the deploy (grep workflows for these commands co-located with an AI action)
- [ ] **AI-023**: (ToB A — Env Var Intermediary) Attacker-controlled event data (`github.event.*.body/title/head_ref`, commit message) does NOT flow through an `env:` block into the agent prompt — prompt cleanliness is not evidence of safety
- [ ] **AI-024**: (ToB B — Direct Expression Injection) No `${{ github.event.* }}` expression is interpolated directly into the AI agent's `prompt`/`system-prompt` field
- [ ] **AI-025**: (ToB C — CLI Data Fetch) Agent prompts do not run `gh issue view` / `gh pr view` / `gh api` (or `solana`/`curl` data fetches) that pull attacker-controlled content into context at runtime
- [ ] **AI-026**: (ToB D — `pull_request_target` + Checkout) No `pull_request_target` trigger combined with checkout of PR-head code feeding an agent that can reach secrets or the deploy pipeline
- [ ] **AI-027**: (ToB E — Error-Log Injection) Build/test/`anchor build` error output and `workflow_dispatch` inputs are not piped into the agent prompt (logs carry attacker payloads from PR code)
- [ ] **AI-028**: (ToB F — Subshell Expansion) Tool allowlists granted to the agent do not include commands that permit subshell expansion (`echo $(...)`, backticks) as an exfiltration bypass of the restriction
- [ ] **AI-029**: (ToB G — Eval of AI Output) The agent's output is not consumed by a later step via `eval`/`exec`/unquoted `$()` — especially any step that then builds or submits a Solana transaction or deploy command
- [ ] **AI-030**: (ToB H — Dangerous Sandbox) No `danger-full-access`, `--allowedTools Bash(*)`, `--yolo`/`--approval-mode=yolo`, or `safety-strategy: unsafe` on the AI action — these turn prompt injection into RCE on a runner that may hold deploy keys
- [ ] **AI-031**: (ToB I — Wildcard Allowlists) No wildcard trigger allowlist (`allowed_non_write_users: "*"`, `allow-users: "*"`) letting any external user invoke the agent
