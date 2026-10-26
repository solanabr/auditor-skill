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
  `Co-Authored-By: … Claude/Anthropic`, "Generated with …", or similar trailers, and no commit names an AI
  assistant as its author or committer. A `commit-msg` hook that refuses such a trailer ships in
  `scripts/hooks/` (enable it with the command in §2), and CI re-checks every commit in the PR range. Using AI
  tooling to help write a contribution is fine; the author of record is the human who opens the PR and takes
  responsibility for the content.
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
real-toolchain checks (`scripts/tests/test-dnr-poc-runner.sh` skips those without them), and cargo for
`scripts/tests/test-audit-logs.sh`, which builds `audit-logs` (its one dependency, `libc`, comes from the
local cargo cache or crates.io) and is skipped, loudly, without it. This is what the required CI job runs:

```bash
bash scripts/check-corpus.sh
bash scripts/check-frontmatter.sh
bash scripts/check-pipefail.sh
for t in scripts/tests/*.sh; do bash "$t" || echo "FAILED: $t"; done
bash scripts/check-hygiene.sh
bash scripts/check-attribution.sh origin/main..HEAD
```

A change to what `scripts/dnr/profile.sh`, `frames.py` or `deltas.py` prints, accepts or refuses goes into
`tools/auditor-tools/audit-logs` too: `scripts/tests/test-audit-logs.sh` compares the two and fails until
they agree. A binary built before a change to those recipes, to `scripts/lib/confine.sh` or to its own
`Cargo.toml` or `src/` refuses to run (exit 4) until it is rebuilt; a new file in `audit-logs/src/` goes
into the `BUILT_FROM` list in its `main.rs`, which the suite checks. Without cargo that suite is skipped;
CI runs it with `REQUIRE_TOOLCHAIN=1`, where a missing cargo fails it.

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

There are two kinds of bump:
- **Patch (X.Y.Z+1).** The last commit of each PR that ships a step between minor releases. It moves only
  `.claude-plugin/plugin.json` and both `.claude-plugin/marketplace.json` entries, which
  `scripts/check-corpus.sh` holds to one version. The plugin cache is keyed by that version, so plugin users
  receive the change. SKILL.md, the README "What It Does" heading and `templates/audit-report.md` keep X.Y.
  There is no tag or GitHub Release.
- **Minor or major (X.Y+1.0).** Every version reference moves together, the release is tagged with a GitHub
  Release, and the release-only steps below run.

A minor or major release PR also re-checks every row of ATTRIBUTION.md's "Assessed, not vendored" table against its
re-check trigger and updates the assessed commit.

A minor or major release PR also regenerates `templates/poc/Cargo.lock`, the pins every PoC crate starts from. The
release author owns this step; nothing is built, and the only hosts contacted are `index.crates.io` and
`static.crates.io`:

1. Copy `templates/poc/` to a scratch directory, replace `{PROGRAM_NAME}` with `poc_template` in its
   `Cargo.toml`, and use a fresh `CARGO_HOME`.
2. Take the cutoff 14 days before the release date (the SC-007 / SC-010 quarantine), as
   `YYYY-MM-DDT00:00:00Z`, and run `cargo +nightly generate-lockfile -Zunstable-options --publish-time
   <cutoff>` there. The manifests' `rust-version` and resolver 3 keep every release buildable with the
   platform-tools rustc.
3. Check that `cargo update --workspace --locked --offline` leaves the file unchanged, with stable cargo
   and with platform-tools' own cargo (`~/.cache/solana/<tools version>/platform-tools/rust/bin/cargo`,
   `RUSTC` set to its `rustc`).
4. Set the root entry back to `name = "{PROGRAM_NAME}"`, copy the file to `templates/poc/Cargo.lock`, and
   review the lock diff like code (SC-047): every added crate and every moved version, with its publish
   date. Run `bash scripts/tests/test-dnr-poc-runner.sh`.

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
  `-L` or `-m`, grep writing to `/dev/null`, `head`, `read`, `sed` with `q`, `awk` with `exit`, also inside a
  `"$( … )"` or a `>( … )`. Count with `grep -c`, print with `sed -n '1,Np'`, or capture the output first.
  `scripts/check-pipefail.sh` enforces this over every tracked `*.sh` file that mentions pipefail; a pipe
  meant to stop early carries the comment `# pipefail-ok: <reason>` on its line.
- A change to a pipeline gets a test with an input larger than a pipe holds (over 64 KiB; 1 MiB is usual).

### Pre-approved entry points

A command's allow rule names a bundled entry point with any words after it, as in
`Bash("${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" *)`, so such a tool must be safe whatever arguments follow
([docs/permissions-and-isolation.md](docs/permissions-and-isolation.md#why-that-is-safe)). A new one, or a change to
one:

- runs directly by its quoted path: a `#!/bin/bash` or `#!/usr/bin/env -S python3 -I` first line and mode
  `100755`. It refuses to run from an installation inside the working directory, or from a path that holds a
  quote, `$`, a backtick, a backslash or a control character;
- checks every argument against a closed grammar before any effect, and refuses anything else with one stderr
  line, `<tool>: refused: <reason>`;
- takes only relative paths inside the working directory, of the shapes it names, with no `..` and no symbolic
  link on the way;
- writes only into run directories that pass `rundir.sh check`, into the `audit-mem` store, or into its own
  scratch directory outside the working directory, creating each file with no-follow, exclusive creation;
- runs no program that its arguments or the repository name. It runs git only through `hgit` in
  `scripts/lib/confine.sh`, and the project's code only in the recorded mode, in the cleaned environment of
  `scripts/lib/isolation.sh`;
- contacts only a destination fixed in its code or set in the user's environment, within caps set there, and
  adds a row to `<R>/disclosures.tsv` before the first request;
- reads stdin only where its grammar says so, and treats a check that cannot run as a refusal.

A bash entry point sources `scripts/lib/confine.sh` rather than repeating its checks. Each ships a case file of
hostile arguments, `scripts/tests/fixtures/<tool>/cases.txt` (one case per line: the exit status, the one stderr
line, then the arguments, separated by tabs), with a suite that runs under macOS `/bin/bash` 3.2 and under bash 5
with GNU tools. A command pre-approves only such an entry point, in the form its header documents;
`scripts/check-frontmatter.sh` holds rules for `audit-scan` and `audit-mem` to the forms that carry
`--contract=1`.

### Frontmatter of commands, agents and `SKILL.md`

`scripts/check-frontmatter.sh` fails when Claude Code would read a field differently from what is written.
It reads every file whose frontmatter Claude Code loads: each `.md` file at any depth under `commands/` and
`agents/`, the root `SKILL.md`, and every `SKILL.md` under `skills/`, in any letter case. A `.md` under
`agents/` or `commands/` is an agent or a command, even one named `SKILL.md`. Name each file with a lowercase
`.md`, and give each agent, command and skill a `name` of its own. The frontmatter keeps to a flat subset:

- Line 1 is exactly `---`, and the block ends at the next line that is exactly `---`. No other line of the
  block contains `---`, even inside a quoted value, and none is `...`. The file holds no NUL byte; the block
  holds no tab, CR or other control character, and no U+0085, U+2028 or U+2029.
- One `key: value` per line, each key once, written exactly as the check lists it. Agents need `name`,
  `description` and `tools`; commands need `description` and `allowed-tools`; a `SKILL.md` needs `name` and
  `description`. One under `skills/` may also have `context: fork`, which then needs
  `agent: auditor:<name>` naming the plugin agent `agents/<name>.md` (its frontmatter names it `<name>`);
  `background` (with `context: fork`) and `user-invocable`, each `true` or `false`; and `allowed-tools`,
  read as a command's. The root `SKILL.md` has no other key. A new key is added to the check's list when
  it is first used.
- Quote a value that starts with a YAML indicator (`-`, `?`, `:`, `,`, `[`, `]`, `{`, `}`, `#`, `&`, `*`,
  `!`, `|`, `>`, `%`, `@` or a backtick), holds `: `, ` #` or `...`, ends in `:`, or would read as a number,
  a boolean or null (`3000`, `++7`, `yes`, `null`). Double quotes escape only `\"` and `\\`; single quotes
  double a `'`.
- `tools` and `allowed-tools` list `Name` or `Name(pattern)` entries, either on one line separated by `, `
  or one per line as `  - item`; an item may be single-quoted, as in
  `  - 'Bash("${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh" *)'`. A pattern holds no parentheses, and
  agents list tool names only. `allowed-tools` lists nothing from `FORBIDDEN_ALLOWED_TOOLS` in the script
  (today `*`), nor a catch-all pattern of a name in it, such as `Bash(*)` once `Bash` is listed.
- The block is at most 65,536 bytes and holds at most 256 of `[`, `{` and ` - `.

### Load surfaces at the plugin root

`scripts/check-hygiene.sh` fails when the plugin root gains a path Claude Code loads beyond those commands,
agents and `SKILL.md` files: `hooks/`, `monitors/` or `bin/`, or `.mcp.json`, `.lsp.json` or `settings*.json`,
at the root and in any letter case, or a `.claude/` directory below it. It fails too on a `SKILL.md`, in any
letter case, other than the root's and `skills/<name>/SKILL.md`: with `"skills": "./"` in `plugin.json`,
Claude Code loads `<dir>/SKILL.md` one level down when the root holds none, and a `skills/SKILL.md` makes all
of `skills/` one skill. Read such a path like code before you add it to `ALLOWED_LOAD_SURFACES` in the script
(empty today). `.claude-plugin/` holds only `plugin.json` and
`marketplace.json`, and each of their keys is on the script's list; add a key there only once you know what
Claude Code loads from it. A top-level `commands`, `agents`, `skills`, `hooks`, `bin`, `monitors` or
`.claude-plugin` directory named in another letter case fails too: a case-insensitive file system loads it
under the lowercase name.

### CI

- **`corpus-check`, job "counts, index, version, hygiene"**: required by branch protection, so keep its
  name. It runs the commands in §2. Every suite runs before the step fails, and the failed ones are listed.
  It sets `REQUIRE_TOOLCHAIN=1`, so the PoC runner's suite fails when cargo or rustup is missing instead of
  skipping its real-toolchain checks.
- **`corpus-check`, job "macOS, bash 3.2 and BSD tools (advisory)"**: the same checks, except the
  pull-request attribution check, on `macos-26`, with a stock PATH plus `~/.cargo/bin` that its first step
  asserts. It is not a required check. A newer push to the same ref cancels its older run.
- **`corpus-check`, job "auditor-tools build and audit-logs parity"**: builds `tools/auditor-tools` as a
  user does (`cargo build --release --locked`) with warnings denied, runs the unit tests, and runs
  `scripts/tests/test-audit-logs.sh` against that release binary. It is not a required check.
- **`plugin-validate`**: weekly and on demand, `claude plugin validate --strict` over the repository
  directory. Advisory. Claude Code comes from `.github/plugin-validate/`: an exact version in `package.json`,
  every package's integrity hash in `package-lock.json`, installed with `npm ci --ignore-scripts`. The native
  binary is the platform's optional dependency, which the job runs directly; the main package's postinstall
  only copies it over a placeholder. To move to a new version, after reading its release notes, set it in
  `package.json` and, in that directory, run
  `NPM_CONFIG_USERCONFIG=<empty file> npm install --package-lock-only --ignore-scripts`.

### Bumping `vendor/trailofbits`

The Trail of Bits pin ships to every user: Claude Code clones the plugin with its submodules, and
`install.sh` fetches it too. So it moves only after a human has read the upstream delta. Dependabot opens
one `gitsubmodule` PR a month (`.github/dependabot.yml`, 7-day cooldown) and `scripts/check-corpus.sh`
fails that PR until the README pin is updated on the same branch. Never auto-merge it.

1. In a full clone of `https://github.com/trailofbits/skills`, run
   `bash scripts/tob-delta-review.sh <clone> <old-sha> <new-sha>` (read-only; `--fetch` updates the clone
   first). Read every section: plugins added or removed; load surfaces (nested `.claude/`, `.claude-plugin/`
   manifests and any hooks / monitors / MCP / LSP servers they declare, `hooks/`, `monitors/`, `bin/`,
   `.mcp.json` / `.lsp.json`, settings, `CLAUDE.md` / `AGENTS.md`, `workflows/*.js`); new executables;
   symlinks (`120000`) and gitlinks (`160000`); paths git still quotes, to read by hand; renamed files,
   OLD -> NEW; hosts in added script, config and Markdown lines (tests, evals, fixtures and lockfiles left
   out, matched as their names are written); remote-exec patterns in added lines, with continuation lines
   joined (a download piped to or evaluated by a shell, an interpreter or PowerShell, such as
   `sh -c "$(curl …)"`, `<(curl …)` or `irm … | iex`; `npx --yes`, `bunx` and `dlx`; `pip`, `pipx`, `uv`,
   `uvx`, `npm`, `cargo` and `deno` installs from git or a URL; `go install …@latest`); files moved unchanged
   between ordinary paths, with the hosts and remote-exec patterns in them (every other renamed file is
   scanned whole in the added-line scans: one moved out of a test, eval, fixture or lockfile path, or into a
   load surface, a `SKILL.md`, `commands/`, `agents/`, `bin/` or `scripts/`); the `LICENSE` (must be
   unchanged). Paths, hosts and commands match in any letter case.
2. The script ends by checking that every plugin named in `references/orchestration/boundary-map.md` and
   `docs/power-tools.md` still exists. For each one that changed (`git diff <old> <new> -- plugins/<name>`),
   update its rows when the entry point, behaviour, execution (`OUTPUT-RULES.md` Rule 11a) or outside
   services it contacts (Rule 11b) changed.
3. Update the README pin line — short SHA, full `…/tree/<sha>` URL, upstream commit date — on the bump
   branch; `bash scripts/check-corpus.sh` must pass.
4. After merge, bump the version (§3; a patch bump is enough): the plugin cache is keyed by version, so
   plugin users receive a new pin only with a version bump.
5. Tell `solanabr/ai-kit` the new full SHA. Its `skill-registry.json` records our pin under `vendored`, and
   its CI fails until that record moves too.

---

## 6. Review checklist (what a reviewer looks for)

- Does the change do one thing, and is that thing described accurately in the PR?
- Do all counts, index rows, and reference-table rows agree (`scripts/check-corpus.sh` green)?
- Does every command, agent and `SKILL.md` frontmatter pass `scripts/check-frontmatter.sh`?
- Are new vectors / items checkable from code, with a PASS / FAIL shape and a grep?
- Are cited incidents real and public?
- No attribution trailers, no secrets, no `.env` / state / local assistant files tracked, and no new load
  surface at the plugin root (`scripts/check-hygiene.sh`).
