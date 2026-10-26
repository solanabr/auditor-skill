---
name: auditor:quick-scan
description: Fast security triage — discovery + static analysis + the highest-severity vector subset, without the full item-by-item walk. Use for a first look or a CI gate.
allowed-tools: Read, Grep, Glob, Bash, Task
---

# auditor-skill — Quick Scan

**Arguments:** $ARGUMENTS

1. Discover the repo and declare scope (`OUTPUT-RULES.md` Rule 0).
2. Run SAST with `"${CLAUDE_PLUGIN_ROOT}/scripts/runner/sast.sh" semgrep --run audit_<n> --path <in-scope directory> --ruleset <id>...`, from the working directory with no `cd` first, with the rulesets for what is in scope (`p/rust`, `p/trailofbits`, `p/typescript`, `p/javascript`, `p/python`, `p/golang`, `p/solidity`, `p/github-actions`, `p/secrets`); its SARIF lands in `audit_<n>/sast/`. When it exits 3 (semgrep is not installed) and the bundled Trail of Bits plugins are present (`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`), run their `static-analysis`; otherwise run the `discovery/grep-commands.md` scanners. Any analyzer that builds the target runs in the execution mode recorded at intake (`OUTPUT-RULES.md` Rule 11a). An analyzer whose command is denied, fails or cannot start did **not run**: name it and the reason in the report, and never count it as clean. As a CI gate, an analyzer that did not run fails the job, so the gate never passes without its analyzers.
3. Evaluate only CRITICAL / HIGH known-vectors for the detected domains — not the full set.
4. Report findings with severity + `file:line`. State clearly this is a triage pass, not a complete audit, and point to `/auditor:audit` for full coverage.
5. **As a CI gate on a public repository** (`OUTPUT-RULES.md` Rule 11d): post pass/fail only — no finding counts, total or per severity — in PR comments, check annotations, the job log and uploaded artifacts alike, since anyone signed in to GitHub can read all of them. Send finding details through a private channel (private vulnerability reporting, a draft security advisory, or a private repository). If that channel is unavailable, fail the job; never fall back to printing findings in the log.
