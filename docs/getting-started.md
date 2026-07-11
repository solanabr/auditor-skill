# Getting Started

Get from a clone to a first audit. Back to the [docs index](README.md).

## 1. Install

auditor-skill is a folder of markdown + two small Rust tools — not a SaaS. Clone it, or drop it in as a skill.

**Clone into your repo:**

```bash
# from your project root
git clone https://github.com/solanabr/auditor-skill.git .github/skills/auditor-skill
```

**Or install it as a plugin** (the `.claude-plugin/` manifest ships with the repo; plugin name is `auditor`). Once installed, commands are available as `/auditor:audit`, `/auditor:audit-cycle`, and so on.

**Or feed the files to an API** — send `SKILL.md` + `OUTPUT-RULES.md` (+ `FULL-AUDIT.md` for a full run) as system context and the target files as user content.

## 2. Initialize the Trail of Bits submodule (recommended)

The vendored Trail of Bits toolkit (`vendor/trailofbits`) provides real tool execution — SAST, fuzzing, coverage, mutation — that prose and grep cannot do. Pull it:

```bash
git submodule update --init --recursive
```

The corpus works **fully without it**: agents fall back to `discovery/grep-commands.md` scanners and note the tooling gap in the report. With it initialized, they delegate per [`references/orchestration/boundary-map.md`](../references/orchestration/boundary-map.md). See [power-tools.md](power-tools.md#trail-of-bits-plugins).

## 3. Build the Rust tools (optional, high value)

Two binaries cut audit cost and add cross-audit memory. Build once:

```bash
cd tools/auditor-tools && cargo build --release
# binaries: target/release/audit-scan  and  target/release/audit-mem
cargo test   # optional: scan_fixture + mem_roundtrip
```

- **`audit-scan`** — deterministic AST pass that emits the risky surface (instructions, account constraints, PDAs, arithmetic, panics, CPIs) as one JSON, at ~$0 LLM cost. On a 50K-line program this removes roughly 200-300K input tokens (~30-40% of the variable cost). It is a *map to verify*, not a set of verdicts.
- **`audit-mem`** — SQLite store for exact de-dup, FIXED→REGRESSED detection, false-positive suppression, and warm re-audits.

If `cargo` is absent, skip both — the audit proceeds on the grep walk. Full detail: [power-tools.md](power-tools.md).

## 4. Adapt to your repo (required)

> auditor-skill was originally built for one Solana/Anchor DeFi project and then generalized. Two things must be set before a serious run:

1. **`discovery/file-map.md`** — update it with your actual folder structure, file names, and state-variable names. It maps each checklist to the globs it scans; the defaults assume `programs/{name}/src/`, `apps/backend/src/`, `apps/web/src/`. Wrong globs mean the walk looks in the wrong place.
2. **Intake** — the questionnaire drives scope, severity calibration, and which compliance checklists apply. Either:
   - fill a copy of [`QUESTIONS.md`](../QUESTIONS.md) (45 questions) by hand, or
   - run `/auditor:intake` (alias `/scope`) to walk the questions interactively and persist the answers to `audit_<n>/intake.md` — the durable artifact both `/auditor:audit-cycle` and `/auditor:audit-assist` read. Use `/auditor:intake --auto` for no-human pipelines (it records the applied default for every unanswered question).

Everything else — checklists, known vectors, output rules — is portable as-is.

## 5. Run your first audit

**Quickest look** (triage, no full item walk — good for a CI gate):

```
/auditor:quick-scan
```

**Full one-shot audit** of a program:

```
/auditor:audit ./programs/my-program --scope program
```

or in plain language for an agent that reads the skill directly:

```
Audit the Solana program in programs/my-program/ using the auditor-skill with PROGRAM scope
```

**Full engagement → client report** (automated end-to-end):

```
/auditor:audit-cycle --scope full
```

The report lands at `audit_<n>/REPORT.md` (`{n}` = count of existing `audit_*/` dirs + 1). Review [COSTS.md](../COSTS.md) first — a full Opus run on a large repo can burn real credits.

## Scopes at a glance

| Scope | Covers | Checklists |
|-------|--------|-----------|
| `full` | everything | all 20 + 131 vectors |
| `program` | Solana program only | 01-07 |
| `backend` | backend API | 08-09 |
| `frontend` | frontend | 08, 10 |
| (quick lane) | known vectors only, grep-based | `/auditor:quick-scan` |

Scope is enforced by *scope-gated loading*: out-of-scope checklists are never read, and out-of-scope items render `[N/A — out of scope]` from the gate. See [output-and-rigor.md](output-and-rigor.md#scope-gated-loading).

## Next

- Understand the flows: [audit-flows.md](audit-flows.md)
- Command reference: [commands.md](commands.md)
- What the report guarantees: [output-and-rigor.md](output-and-rigor.md)
