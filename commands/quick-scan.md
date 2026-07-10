---
name: auditor:quick-scan
description: Fast security triage — discovery + static analysis + the highest-severity vector subset, without the full item-by-item walk. Use for a first look or a CI gate.
allowed-tools: Read, Grep, Glob, Bash, Task
---

# auditor-skill — Quick Scan

**Arguments:** $ARGUMENTS

1. Discover the repo and declare scope (`OUTPUT-RULES.md` Rule 0).
2. If `vendor/trailofbits` is present, run `static-analysis` (SAST) over in-scope languages; otherwise run the `discovery/grep-commands.md` scanners.
3. Evaluate only CRITICAL / HIGH known-vectors for the detected domains — not the full set.
4. Report findings with severity + `file:line`. State clearly this is a triage pass, not a complete audit, and point to `/auditor:audit` for full coverage.
