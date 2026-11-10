# Repository layout

Every folder of auditor-skill, and what each file is for. The README's [Folder structure](../README.md#folder-structure) gives the top level. Each checklist's item count is in SKILL.md's [Checklists Reference](../SKILL.md#checklists-reference) and the README's [checklist list](../README.md#supported-languages--frameworks), which `scripts/check-corpus.sh` checks. Back to the [docs index](README.md).

The paths are relative to the auditor-skill installation, never to the repository under audit ([OUTPUT-RULES.md Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)).

```text
auditor-skill/
├── README.md                ← The front page
├── SKILL.md                 ← Orchestrator — the AI agent reads this first
├── OUTPUT-RULES.md          ← Mandatory output format, severity scale
├── FULL-AUDIT.md            ← Step-by-step execution plan for complete audits
├── QUESTIONS.md             ← Pre-audit questionnaire (intake asks it in a Full run)
├── docs/costs.md                 ← Measured cost and time per depth
├── docs/CONTRIBUTING.md          ← Branch / PR flow, corpus-count rules, no AI-attribution policy
├── docs/SECURITY.md              ← Private vulnerability reporting for the skill and its tooling
├── docs/attribution.md           ← Credits for the third-party methodology, used by reference
├── LICENSE                  ← MIT
├── install.sh               ← The install script (README, Installation, Option 2)
├── .claude-plugin/          ← plugin.json and marketplace.json: the `auditor` plugin and its marketplace
├── .github/                 ← CI workflows (corpus-check, plugin-validate, vendor-delta), Dependabot, the PR template
├── assets/                  ← banner.png
│
├── known-vectors/           ← Individual attack vector files (for contributors)
│   ├── INDEX.md             ← One-line index of all vectors
│   ├── 001-private-key-leak.md
│   ├── 002-flash-loan-price-manipulation.md
│   ├── ...
│   ├── 100-insufficient-backup-disaster-recovery.md
│   ├── ...
│   └── 141-host-kernel-network-attack-surface.md
│
├── checklists/              ← 20 micro-checklists (the core verification items)
│   ├── 01-program-account-validation.md
│   ├── 02-program-access-control.md
│   ├── 03-program-arithmetic-safety.md
│   ├── 04-program-cpi-pda.md
│   ├── 05-program-state-machine.md
│   ├── 06-program-economic-logic.md
│   ├── 07-program-opsec-governance.md
│   ├── 08-typescript-safety.md
│   ├── 09-backend-security.md
│   ├── 10-frontend-security.md
│   ├── 11-supply-chain.md
│   ├── 12-secrets-opsec.md
│   ├── 13-deployment-infrastructure.md
│   ├── 14-python-safety.md
│   ├── 15-general-language-safety.md
│   ├── 16-formal-verification-testing.md
│   ├── 17-logging-monitoring-incident-response.md
│   ├── 18-privacy-compliance-change-management.md
│   ├── 19-ai-agent-security.md            — AI agents on Solana
│   └── 20-rust-offchain-services.md       — Off-chain Rust (geyser/indexers/keepers)
│
├── discovery/               ← File patterns and search commands
│   ├── file-map.md          ← Maps checklists → target file patterns
│   └── grep-commands.md     ← All grep/terminal commands by category
│
├── references/              ← Progressive-disclosure deep coverage (loaded on trigger)
│   ├── methodologies/       ← 13 protocol playbooks (amm-clmm, lending, perps, oracles,
│   │                          stablecoin, liquid-staking, governance, bridges,
│   │                          wallets-multisig-custody, token-2022, nft-marketplaces, launchpads,
│   │                          token-registry-risk)
│   ├── framework-idioms/    ← Anchor / Native / Pinocchio validation-order footguns, build and tooling
│   ├── vuln-classes/        ← zk-and-compression · transaction-v1 (SIMD-0385 migration) · github-actions (CI trigger trust) · kernel-attack-surface (host kernel & network surface)
│   ├── invariant-catalog.md ← Reusable harness-ready invariant menus per protocol class
│   ├── false-positives.md   ← Over-reporting triage rules
│   ├── depth-scope.md       ← What Quick and CI read: checklist sections and vector rows by domain and kind of changed file, and diff-audit's budgets
│   ├── report-format.md     ← How the final report is assembled
│   ├── audit-lifecycle/     ← methodology + firm-coverage (how firms work) + threat-model-bootstrap
│   ├── detection-response/  ← post-incident track: rules + verdict ladder, Solana log sources, containment, INCIDENTS.json schema
│   └── orchestration/       ← boundary-map (Trail of Bits) · pre-scan · poc-harness
│
├── commands/                ← 17 slash-commands (/auditor:<name>)
│   ├── audit · quick-scan · deep-review · diff-audit · spec-audit · economic-sim · audit-report
│   ├── audit-cycle · audit-assist · re-audit            ← lifecycle flows
│   ├── intake · threat-model · triage                   ← perimeter
│   ├── poc · patch                                      ← executable PoC + fix patches
│   └── hunt · respond                                   ← post-incident detection & response
│
├── agents/                  ← 9 specialized subagents
│   ├── context-builder · threat-modeler · vuln-hunter · economic-analyst
│   └── peer-reviewer · audit-reporter · poc-engineer · patch-engineer · incident-responder
│
├── skills/
│   └── dnr-analyze/         ← auditor:dnr-analyze: one D&R analysis phase, run as a fork of incident-responder
│
├── tools/auditor-tools/     ← Rust CLIs (cargo build --release --locked)
│   ├── audit-scan           ← deterministic pre-scan → JSON risky-surface map (~$0)
│   ├── audit-mem            ← SQLite cross-audit memory (dedup · regression · FP-suppression)
│   └── audit-logs           ← the D&R analysis recipes as one offline binary (cargo build --release --locked)
│
├── templates/               ← Output + deliverable templates
│   ├── report-template.md   ← Internal item-by-item verdict report
│   ├── audit-report.md      ← Client-facing findings report (no deploy guarantee)
│   ├── re-audit.md          ← Fix-review record (RE-AUDIT.md), with each finding's PoC re-run
│   ├── pr-report.md         ← The Quick commands' report (PR-REPORT.md · QUICK-SCAN.md · DEEP-REVIEW-<unit>.md)
│   ├── strict-settings.json ← Settings for the strict launch line (OUTPUT-RULES Rule 11f)
│   ├── ci/                  ← The pull-request workflow, its two schemas and jq programs (docs/ci.md)
│   ├── context-worksheet.md · instruction-worksheet.md · intake.md · threat-model.md
│   ├── incident-report.md · response-plan.md · hunt-ledger.md
│   ├── poc/                 ← exploit-harness crate skeleton + shared-test-utils
│   └── patch/               ← patch + VERIFICATION templates
│
├── docs/                    ← Usage guides (start at docs/README.md)
├── scripts/                 ← preflight.sh, rundir.sh, git-ro.sh, rpc-read.sh, report-to-pdf.sh, the CI checks (check-*.sh), tob-delta-review.sh and tob-delta-pr.sh (a Trail of Bits bump's review, and its summary on the pull request) + the no-attribution commit hook
│   ├── runner/              ← probe.sh, deps.sh, sast.sh, target.sh: toolchain probes, dependency audits, SAST, and builds and tests in the recorded execution mode
│   ├── recipes/             ← lock-delta.sh, web3js-history.sh: the lockfile changes (and the CI budget's set of new versions) and known-bad releases in the git history, for the supply-chain checks
│   ├── lib/                 ← confine.sh and isolation.sh, the checks and environment cleaning the entry points share
│   ├── pdf/                 ← no-remote.lua, the pandoc filter report-to-pdf.sh renders with
│   ├── dnr/                 ← detection & response recipes (gated RPC collector, program snapshot, corpus profile, log frames, balance deltas, jq-ro.sh)
│   ├── threat-model/        ← collect.sh — the read-only threat-model bootstrap collector
│   └── tests/               ← script self-tests (+ fixtures/gha/, workflows and a composite action that are never executed)
├── AGENTS.md                ← Agent-orchestration overview
└── vendor/trailofbits/      ← Trail of Bits execution plugins (git submodule, pinned — see the README's Installation)
```

Every bundled script, its arguments and what it may contact: [power-tools.md](power-tools.md#bundled-scripts). The Rust tools: [power-tools.md](power-tools.md) and [`tools/auditor-tools/README.md`](../tools/auditor-tools/README.md). The PoC template: [`templates/poc/README.md`](../templates/poc/README.md).
