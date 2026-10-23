# Contributing to auditor-skill

auditor-skill is a markdown security-audit corpus plus a small amount of tooling. Contributions are
welcome — new known vectors, checklist items, protocol methodologies, fixes to wording, and tooling
improvements. This document is the short version of "how a change gets in".

---

## 1. Ground rules

- **Nothing lands on `main` directly.** Every change — maintainers included — goes through a branch and a
  pull request that is reviewed by someone other than its author. `main` is protected.
- **One theme per PR.** A PR adds *one* coherent thing (a vector, a methodology, a checklist section, a
  tooling change). Split unrelated changes; reviewers cannot meaningfully review a 3,000-line mixed diff.
- **Counts must stay consistent.** Item and vector totals are hardcoded in several files (see §4). CI runs
  `scripts/check-corpus.sh` and fails the PR if any of them disagree with the files on disk.
- **No AI-attribution trailers in commits or PRs.** Commits and PR descriptions must not carry
  `Co-Authored-By: … Claude/Anthropic`, "Generated with …", or similar trailers. A `commit-msg` hook that
  enforces this ships in `scripts/hooks/` (enable it with the command in §2) and CI re-checks every commit
  in the PR range. Using AI tooling to help write a contribution is fine; the author of record is the
  human who opens the PR and takes responsibility for the content.
- **Security issues in this repository** (install script, Rust tools, workflows, or corpus content that
  could mislead an auditor into a dangerous action) go through [SECURITY.md](SECURITY.md), not a public
  issue.

---

## 2. Local setup

```bash
git clone https://github.com/solanabr/auditor-skill.git
cd auditor-skill
git config core.hooksPath scripts/hooks      # enables the attribution-trailer commit-msg hook
bash scripts/check-corpus.sh                 # should print "ok" lines and exit 0 on a clean tree
```

Optional: `git submodule update --init --depth 1 -- vendor/trailofbits` for the vendored Trail of Bits
tooling and `cd tools/auditor-tools && cargo build --release` for the Rust CLIs. Neither is needed for
corpus PRs.

The checks run with the stock tools of macOS (`/bin/bash` 3.2, BSD sed, grep and awk) as well as with bash 5
and GNU tools on Linux. Beyond git they need python3 and jq, plus cargo and rustup for the PoC runner's
real-toolchain checks (`scripts/tests/test-dnr-poc-runner.sh` skips those without them). This is what the
required CI job runs:

```bash
bash scripts/check-corpus.sh
bash scripts/check-frontmatter.sh
bash scripts/check-pipefail.sh
for t in scripts/tests/*.sh; do bash "$t" || echo "FAILED: $t"; done
bash scripts/check-hygiene.sh
bash scripts/check-attribution.sh origin/main..HEAD
```

---

## 3. Branch and PR flow

1. Branch from an up-to-date `main`:
   `git switch -c feat/<topic>-<dd-mm-yyyy>` (prefixes in use: `feat/`, `fix/`, `docs/`, `perf/`, `chore/`).
2. Make the change. Run `bash scripts/check-corpus.sh` before every commit that touches
   `checklists/`, `known-vectors/`, `references/methodologies/`, or any file that quotes a count, and
   `bash scripts/check-frontmatter.sh` before one that touches the frontmatter of `commands/`, `agents/`,
   `skills/` or `SKILL.md`.
3. Commit with a conventional-style subject and a body that says *what* and *why*:
   `feat(corpus): <what> — <why>`, `fix(vector): …`, `docs(readme): …`, `chore(release): bump version to X.Y.Z`.
4. Push the branch and open a PR against `main` using the template. Fill in every section; "n/a" is an
   acceptable answer, an empty section is not.
5. Address review. Prefer new commits over force-pushes during review so reviewers can see what changed.
6. A maintainer merges. Stacked PRs (a branch based on another open PR branch) are fine — say so in the
   description and merge them in order.

Version bumps are their own `chore(release)` PR (or the last commit of a release PR) — content PRs update
counts but leave the version alone, so several content PRs can be open at once without conflicting on the
version line.

A release PR also re-checks every row of ATTRIBUTION.md's "Assessed, not vendored" table against its
re-check trigger and updates the assessed commit.

---

## 4. Adding corpus content

### A known vector

1. Create `known-vectors/NNN-short-name.md` with the next free number. Never renumber existing vectors —
   ranges like `KV-001..NNN` are quoted across the corpus and third-party reports reference the ids.
2. Follow the existing format exactly (see any recent file, e.g. `131-…` or `134-…`):
   YAML frontmatter (`id`, `title`, `severity`, `category`) → `### NNN — Title` → `**Severity: N** | **Real: …**`
   → description → cross-ref block → `#### Verification Procedure` with numbered steps, each with a grep /
   check and ✅ PASS / ❌ FAIL lines → `**Overall verdict:**` with ✅ / ⚠️ / ❌ / N/A.
3. Add a row to `known-vectors/INDEX.md` in the right section with a **Load when (markers)** cell
   (default to `always (<phase>)` unless the vector is provably feature-specific), and update the totals at
   the bottom of the index (`Total vector files`, `Distinct concepts`, the per-version tally).
4. Bump the vector count in every file that quotes it: `SKILL.md` (description + header + "up to N"),
   `README.md`, `FULL-AUDIT.md`, `COSTS.md`, `OUTPUT-RULES.md`, `templates/report-template.md`,
   `docs/README.md`, `docs/getting-started.md`, `.claude-plugin/plugin.json`. `scripts/check-corpus.sh`
   tells you which ones you missed.
5. If the vector is feature-gated, add a row to the advisory table in
   `references/orchestration/pre-scan.md` and, when useful, a grep block in `discovery/grep-commands.md`.

### Checklist items

1. Append to the relevant `checklists/NN-*.md` using the file's id prefix and the **next sequential number**
   (ids are never reused, even if an item is removed). New sections get the next `NN.x` heading.
2. Update the per-checklist counts in `SKILL.md` (Checklists Reference table) and `README.md` (Supported
   Languages table and the folder-structure listing), the totals everywhere the item total is quoted
   (`SKILL.md`, `README.md`, `COSTS.md`, `docs/README.md`, `templates/audit-report.md`,
   `templates/report-template.md`, `.claude-plugin/plugin.json`), and the `...through XX-NNN` line for that
   checklist in `templates/report-template.md`.

### A protocol methodology

1. Create `references/methodologies/<name>.md` following the shape of the existing playbooks: a
   *Load when* block with grep markers, a *Purpose* paragraph, numbered sections (classify first → threat
   model / per-mechanism table → invariant catalog → worksheets → high-density surfaces → detection recipes →
   test / PoC strategy) and a fast-pass checklist at the end.
2. Register it: a row in the `SKILL.md` reference-loading table, a row in the pre-scan advisory table, the
   methodology count and list in `README.md` (two places) and `docs/README.md`, and — if it adds invariants a
   harness can assert — a section in `references/invariant-catalog.md`.

### Wording, evidence and honesty

- Every claim of a real incident must be a public, verifiable one (post-mortem, audit report, advisory).
  Say "class of bug" when you cannot cite an incident. Do not invent dollar figures.
- Items are **verification steps**, not advice: an auditor must be able to mark each one PASS / FAIL / N/A
  from the code. If it cannot be checked, it does not belong in a checklist.
- Prefer grep-able markers and exact identifiers over prose.

---

## 5. Tooling changes

`tools/auditor-tools` (Rust) and `scripts/` have their own conventions: keep `cargo build --release`
warning-free, add or extend a fixture under the tool's test directory for any parser change, and document
new flags in `docs/power-tools.md`. Workflow files pin third-party actions to a full commit SHA with the
version in a trailing comment.

### Shell scripts

- Scripts run under macOS `/bin/bash` 3.2 with BSD tools and under bash 5 with GNU tools: no `declare -A`,
  `mapfile` or `${x,,}`, and no GNU-only sed or grep flags. Quote every expansion.
- Under `set -o pipefail`, never pipe into a reader that can stop before its input ends: `grep -q`, `-l`,
  `-L` or `-m`, grep writing to `/dev/null`, `head`, `read`, `sed` with `q`, `awk` with `exit`. Count with
  `grep -c`, print with `sed -n '1,Np'`, or capture the output first. `scripts/check-pipefail.sh` enforces
  this over every tracked `*.sh` file; a pipe meant to stop early carries `# pipefail-ok: <reason>`.
- A change to a pipeline gets a test with an input larger than a pipe holds (over 64 KiB; 1 MiB is usual).

### Frontmatter of commands, agents and `SKILL.md`

`scripts/check-frontmatter.sh` fails when Claude Code would read a field differently from what is written.
It holds the frontmatter of `commands/*.md`, `agents/*.md`, `SKILL.md` and `skills/*/SKILL.md` to a flat
subset:

- Line 1 is exactly `---`, and the block ends at the next line that is exactly `---`. No other line of the
  block contains `---`, even inside a quoted value, and none is `...`. No tabs or CRs.
- One `key: value` per line, with a lowercase key the check knows, each key once. Agents need `name`,
  `description` and `tools`; commands need `description` and `allowed-tools`; a `SKILL.md` needs `name` and
  `description` and, for now, has no other key. A new key is added to the check's list when it is first
  used.
- Quote a value that starts with a YAML indicator (`-`, `?`, `:`, `,`, `[`, `]`, `{`, `}`, `#`, `&`, `*`,
  `!`, `|`, `>`, `%`, `@` or a backtick), holds `: ` or ` #`, ends in `:`, or would read as a number, a
  boolean or null (`3000`, `yes`, `null`). Double quotes escape only `\"` and `\\`; single quotes double a
  `'`.
- `tools` and `allowed-tools` list `Name` or `Name(pattern)` entries, either on one line separated by `, `
  or one per line as `  - item`; an item may be single-quoted, as in
  `  - 'Bash(bash "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh" *)'`. A pattern holds no parentheses,
  agents list tool names only, and `allowed-tools` lists nothing from `FORBIDDEN_ALLOWED_TOOLS` in the
  script (today `*`).

### CI

- **`corpus-check`, job "counts, index, version, hygiene"**: required by branch protection, so keep its
  name. It runs the commands in §2. Every suite runs before the step fails, and the failed ones are listed.
  It sets `REQUIRE_TOOLCHAIN=1`, so the PoC runner's suite fails when cargo or rustup is missing instead of
  skipping its real-toolchain checks.
- **`corpus-check`, job "macOS, bash 3.2 and BSD tools (advisory)"**: the same checks on `macos-26`, with a
  stock PATH plus `~/.cargo/bin` that its first step asserts. It is not a required check.
- **`plugin-validate`**: weekly and on demand, `claude plugin validate --strict` over the repository
  directory with Claude Code at the exact npm version in `CLAUDE_CODE_VERSION`. Advisory. Bump that
  version by hand after reading the release notes.

### Bumping `vendor/trailofbits`

The Trail of Bits pin ships to every user: Claude Code clones the plugin with its submodules, and
`install.sh` fetches it too. So it moves only after a human has read the upstream delta. Dependabot opens
one `gitsubmodule` PR a month (`.github/dependabot.yml`, 7-day cooldown) and `scripts/check-corpus.sh`
fails that PR until the README pin is updated on the same branch. Never auto-merge it.

1. In a full clone of `https://github.com/trailofbits/skills`, run
   `bash scripts/tob-delta-review.sh <clone> <old-sha> <new-sha>` (read-only; `--fetch` updates the clone
   first). Read every section: plugins added or removed; load surfaces (nested `.claude/`, `.claude-plugin/`
   manifests and any hooks / MCP / LSP servers they declare, `hooks/`, `.mcp.json` / `.lsp.json`, settings,
   `CLAUDE.md` / `AGENTS.md`, `workflows/*.js`); new executables; symlinks (`120000`) and gitlinks
   (`160000`); renamed files, OLD -> NEW (the added-line scans read only the lines a rename changed);
   hosts in added script, config and Markdown lines (tests, evals, fixtures and lockfiles left out);
   remote-exec patterns in added lines, in any letter case and with continuation lines joined (a download
   piped to a shell or interpreter, `sh -c "$(curl …)"`, `<(curl …)`, PowerShell `irm … | iex` and
   `iex (irm …)`, `npx --yes`, `pip`, `pipx`, `uv tool` or `uvx` from git or a URL, `cargo install --git`,
   `go install …@latest`); the `LICENSE` (must be unchanged).
2. The script ends by checking that every plugin named in `references/orchestration/boundary-map.md` and
   `docs/power-tools.md` still exists. For each one that changed (`git diff <old> <new> -- plugins/<name>`),
   update its rows when the entry point, behaviour, execution (`OUTPUT-RULES.md` Rule 11a) or outside
   services it contacts (Rule 11b) changed.
3. Update the README pin line — short SHA, full `…/tree/<sha>` URL, upstream commit date — on the bump
   branch; `bash scripts/check-corpus.sh` must pass.
4. After merge, cut a release (§3): the plugin cache is keyed by version, so plugin users receive a new
   pin only with a release.
5. Tell `solanabr/ai-kit` the new full SHA. Its `skill-registry.json` records our pin under `vendored`, and
   its CI fails until that record moves too.

---

## 6. Review checklist (what a reviewer looks for)

- Does the change do one thing, and is that thing described accurately in the PR?
- Do all counts, index rows, and reference-table rows agree (`scripts/check-corpus.sh` green)?
- Does every command, agent and `SKILL.md` frontmatter pass `scripts/check-frontmatter.sh`?
- Are new vectors / items checkable from code, with a PASS / FAIL shape and a grep?
- Are cited incidents real and public?
- No attribution trailers, no secrets, no `.env` / state / local assistant files tracked.
