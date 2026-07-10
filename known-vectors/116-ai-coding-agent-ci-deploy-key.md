---
id: 116
title: "AI Coding Agent in CI Holds Deploy / Upgrade Keys"
severity: 9
category: ai-agent
---

### 116 — AI Coding Agent in CI Holds Deploy / Upgrade Keys

**Severity: 9** | **Real: Solana port of Trail of Bits agentic-actions-auditor — an AI coding agent (Claude Code Action / Gemini CLI / Codex / GitHub AI Inference) running in a CI pipeline that can reach a program deploy or upgrade-authority keypair; a prompt-injected PR/issue/comment makes the pipeline push a malicious program upgrade**

Solana programs are mutable by their upgrade authority. If an AI agent runs in CI with that authority (or a deploy keypair) in reach, prompt injection stops being a code-review nuisance and becomes a supply-chain compromise: the attacker opens a PR / issue / comment whose text steers the agent, and the agent — running with pipeline secrets — builds and ships an attacker-controlled upgrade to a live program. This is the ToB agentic-actions model (attacker input → AI agent with elevated CI permissions) pointed at `solana program deploy` / `anchor upgrade` / a multisig submit.

This vector fuses two conditions that must BOTH be false: (a) the agent can reach deploy/upgrade keys, and (b) attacker input can reach the agent. The nine ToB CI vectors below are the concrete injection paths.

#### Verification Procedure

**Step 1: Inventory workflows and locate AI agent steps**
```
ls -la .github/workflows/ 2>/dev/null
grep -rn -iE "anthropics/claude-code-action|run-gemini-cli|gemini-cli-action|openai/codex-action|actions/ai-inference" .github/workflows/
```
- Record: each workflow, its `on:` triggers, and every AI-agent step

**Step 2: Does an AI-agent step reach deploy / upgrade key material?**
```
grep -rn -iE "PROGRAM_DEPLOY|UPGRADE_AUTHORITY|DEPLOY_KEY|id\.json|keypair|ANCHOR_WALLET|SOLANA_KEYPAIR|secrets\." .github/workflows/
```
- ✅ PASS: The AI-agent job/step has NO deploy/upgrade keypair in its `env`/`secrets`/checked-out files; deploy secrets live only in a separate job the agent cannot influence
- ❌ FAIL: A deploy/upgrade key or `id.json` is available in the same job/step as the AI agent

**Step 3: Is deploy/upgrade reachable from the agent without a human gate?**
```
grep -rn -iE "solana program deploy|anchor deploy|anchor upgrade|solana program set-upgrade-authority|squads|multisig.*submit" .github/workflows/
```
- ✅ PASS: These commands sit behind an explicit human-approval boundary (manual `environment` gate, separate approval job) and are NOT invocable by an AI-agent step or by a step consuming AI output
- ❌ FAIL: An AI-agent step (or a step eval-ing its output) can trigger deploy/upgrade

**Step 4: Nine ToB CI injection vectors (Solana port of Trail of Bits agentic-actions-auditor)**
- **A. Env-var intermediary** — `github.event.*.body/title/head_ref` or commit message flows through an `env:` var into the agent prompt (prompt has no `${{ }}`, still tainted).
  ```
  grep -rn -iE "env:" .github/workflows/ ; grep -rn -iE "github.event.*(body|title|head_ref|message)" .github/workflows/
  ```
- **B. Direct expression injection** — `${{ github.event.* }}` interpolated directly into the agent `prompt`/`system-prompt`.
- **C. CLI data fetch** — prompt runs `gh issue view` / `gh pr view` / `gh api` (or `curl`) to pull attacker content at runtime.
  ```
  grep -rn -iE "gh (issue|pr) view|gh api|curl " .github/workflows/
  ```
- **D. `pull_request_target` + checkout of PR head** — untrusted PR code runs with secrets in reach of the agent.
  ```
  grep -rn -iE "pull_request_target" .github/workflows/
  ```
- **E. Error-log injection** — `anchor build`/test error output or `workflow_dispatch` inputs piped into the agent prompt.
- **F. Subshell expansion** — a "restricted" tool allowlist still permits `echo $(...)` / backticks, bypassing the restriction to read secrets.
- **G. Eval of AI output** — a later step passes `steps.<ai>.outputs.*` through `eval`/`exec`/unquoted `$()`, especially into a deploy/tx command.
  ```
  grep -rn -iE "eval |exec |\$\(.*outputs" .github/workflows/
  ```
- **H. Dangerous sandbox** — `danger-full-access`, `--allowedTools Bash(*)`, `--yolo`/`--approval-mode=yolo`, `safety-strategy: unsafe`.
  ```
  grep -rn -iE "danger-full-access|Bash\(\*\)|--yolo|approval-mode=yolo|safety-strategy:\s*unsafe" .github/workflows/
  ```
- **I. Wildcard allowlist** — `allowed_non_write_users: "*"` / `allow-users: "*"` lets any external user invoke the agent.
  ```
  grep -rn -iE "allowed_non_write_users:\s*[\"']?\*|allow-users:\s*[\"']?\*" .github/workflows/
  ```
- ✅ PASS: None of A–I present on any AI-agent step that shares a job with deploy/upgrade capability
- ❌ FAIL: Any of A–I provides an injection path into an agent that can reach the deploy pipeline

**Step 5: Permissions & least privilege on the agent job**
- ✅ PASS: Agent job declares minimal `permissions:` (`contents: read`), no `id-token`/write scopes it doesn't need, and cannot escalate to deploy
- ❌ FAIL: Default/broad permissions on a job that also holds deploy secrets

**Overall verdict:**
- ✅: Agent job has no deploy/upgrade key, deploy is human-gated, no A–I injection path reaches it, least-privilege permissions
- ⚠️: Deploy is separated but a co-located injection vector (one of A–I) exists on a lower-privilege agent step
- ❌: AI agent shares a job with deploy/upgrade authority AND an A–I path lets attacker input reach it — prompt-injected malicious program upgrade

*(Vectors A–I credited to the Trail of Bits agentic-actions-auditor plugin; phrased here for a Solana program deploy/upgrade pipeline.)*
