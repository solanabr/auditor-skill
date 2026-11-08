# Output & Rigor

The severity model, the validation gate that keeps findings honest, and the report conventions. Back to the [docs index](README.md).

Everything here is specified in [`OUTPUT-RULES.md`](../OUTPUT-RULES.md) (mandatory for every audit). This guide is the practical summary.

## Severity: a 1-10 scale

Findings use a numeric severity 1-10, not the C/H/M/L/I letters.

| Score | Label | Meaning |
|-------|-------|---------|
| 10 | CRITICAL | permissionless drain, total fund loss, instant exploit |
| 9 | CRITICAL | fund loss with minimal preconditions; privilege to admin |
| 8 | HIGH | fund loss with specific preconditions; partial drain |
| 7 | HIGH | significant economic damage; privilege escalation; data breach |
| 6 | MEDIUM | state corruption, griefing, DoS, limited economic manipulation |
| 5 | MEDIUM | logic bugs, inconsistent state, moderate info leak |
| 4 | LOW | minor info leak; security-relevant code-quality issue |
| 3 | LOW | missing best practice with theoretical risk |
| 2 | INFO | hardening suggestion |
| 1 | INFO | cosmetic, no security impact |

There is no separate "Suggestion" tier — hardening ideas live at severity 1-2.

### Impact × Likelihood — and principled downgrades

The base number is the **impact**. A high-impact mechanism with a **low-likelihood** trigger lands lower, and the finding **must state which axis drove it** (e.g. "impact 8, but the exploit needs a compromised admin → reported at 6"). Downgrades are never on vibes — you cite a named lever with a worked justification:

- **Self-sacrifice / no incentive** — the attacker burns their own funds, or a cheaper path reaches the same outcome.
- **Economic infeasibility (with numbers)** — show the bound: "the token would need to be worth ~1000× to profit; max gain ≤ 1 lamport at normal state."
- **Recoverable / self-healing** — the harmful state reverses at bounded cost (next epoch clears it).
- **Bounded blast radius** — worst case is a small contained loss, not a drain.
- **Defense-in-depth exceeds norms** — a redundant guard makes the gap non-exploitable in practice.
- **Privilege required** — a role-gated path caps severity; a permissionless variant would score higher.

### Notes & Nitpicks (below severity 1)

Not every observation is a finding. Issues with **no security impact** — style, naming, redundant code, micro-optimizations, doc gaps — are **not** scored 1-10. They go in a separate **Notes & Nitpicks** list: a bulleted `file:line — observation` list, no severity, no remediation-tracking obligation. This keeps the findings table reserved for genuine security issues and prevents nit-inflation from diluting the severity signal. A note graduates to a severity-1 Informational finding only if it carries a concrete (if minor) security implication. `/auditor:triage` performs this split.

### Repository Risk Score (internal only)

After all items are checked, the internal report computes a Repository Risk Score = the max finding severity, banded (any ≥9 → 10 CRITICAL do-not-deploy; ≥7 → HIGH; ≥5 → MEDIUM; ≥3 → LOW; ≤2 → MINIMAL). This is the team's deploy-gate — it stays in the internal template and is **never** presented to a client as a "safe to deploy" verdict (see [report templates](#two-report-templates)).

## The Rule 5b validation gate

Over-reporting is the primary failure mode of an AI auditor, so **any `[FAIL-N]` with N≥6 is provisional** until it carries filled gate blocks. This is what separates a confirmed finding from a guess.

- **N≥6** requires a **Reachability** block + a **Math / State-Bounds** block.
- **N≥7** additionally requires an **Attacker-Model** block.

If the blocks can't be completed with cited evidence (`file:line`), the finding is **downgraded — never left as a bare `[FAIL-N]`**:

- **`[PARTIAL]`** — a real defense-in-depth gap, but the exploit path is unproven.
- **`[UNCONFIRMED]`** — the gate failed on **reachability or bounds** (unreachable / unbounded as written). Reported for manual follow-up; **not counted as a confirmed FAIL** in the metrics.
- **`[UNDETERMINED]`** — distinct: the path **is** reachable but its full impact couldn't be quantified in scope. Carried at its likely severity band with "extent not determined within this assessment" — a real, flagged finding, not a suppressed one. Reachable-but-unquantified ≠ unreachable.

What the blocks contain:

```
Reachability:  entry point @ file:line · signer/authority required · preconditions (each cited)
               · guard analysis (constraints that could block it, and why they don't) · verdict
Math/Bounds:   vulnerable expression @ file:line · input domain · boundary that breaks
               · worked case (concrete numbers or the state sequence) · quantified net effect
Attacker-Model: capability · capital/setup cost · profit/damage · atomicity · net (profitable/griefing/privilege)
```

A **rejected** finding looks like: *"input ≥ 16 and header = 8 ⟹ input − header ≥ 8, so the subtraction cannot underflow. Downgraded `[FAIL-7]` → `[UNCONFIRMED]`."*

**Accepted PoC forms.** A runnable exploit is ideal but not the only proof — for access-control/logic findings a **structured attacker-narrative** (actor → capability → numbered steps → guard bypassed → quantified outcome) is a first-class PoC. And when the missing check is provable at `file:line` but the full exploit math can't be confirmed in the window, you may still report at severity **provided** the finding carries explicit uncertainty phrasing — do not mechanically bury a real syntactic gap as `[UNCONFIRMED]`. Executable evidence is tagged with a `[PoC-*]` tier orthogonal to severity ([poc-and-patches.md](poc-and-patches.md)); a PoC run that ends in `run.sh` exit 3 is `[PoC-ATTEMPTED]` with its blocker line and "PoC re-run needed", never a verdict.

## Every item gets a verdict

The proof the auditor actually checked everything: every in-scope checklist item and every phase-triggered known-vector appears in the report with an explicit verdict, in checklist order (never grouped by verdict).

| Verdict | Rule |
|---------|------|
| `[PASS]` | cite the file/code that proves it secure. One line. |
| `[FAIL-N]` | severity 1-10, `file:line`, impact, fix. ≥3 lines; N≥6 carries the Rule 5b gate. |
| `[PARTIAL]` | what's missing, `file:line`, recommended improvement. |
| `[N/A]` | *why* it doesn't apply. Never bare N/A. |

Honesty tags (Rule 10): `[PASS*]` / `[FAIL-N*]` with a confidence note for less-than-certain calls; `[INCOMPLETE — context lost]`, `[PARTIAL — file truncated]`, `[UNKNOWN — unfamiliar pattern]` where applicable. **Never** mark `[PASS]` without reading the code; **never** mark `[N/A]` just because context ran out.

## Scope-gated loading

auditor-skill does not read its whole corpus up front. It **discovers** (enumerate extensions/markers — cheap, always), **declares scope** (detected languages + `--scope` → the in-scope checklist set), and **loads on demand** (a checklist when its phase begins; a known-vector only when its phase + language/domain trigger reaches it). Out-of-scope checklists and vectors are **never read** — a Rust-only repo never loads the Python checklist or the TS/web vectors.

Completeness is measured **output-side**: the audit is COMPLETE iff every in-scope item + phase-triggered vector has a verdict. Out-of-scope items render `[N/A — out of scope: <reason>]` from the gate (not from reading the file). Every full report includes a **Scope Coverage** table: per checklist and vector group, `IN-SCOPE` (items evaluated / total) or `OUT-OF-SCOPE (reason)`. Details on scopes: [getting-started.md](getting-started.md#scopes-at-a-glance).

## Two report templates

Two documents, two audiences — do not conflate them.

| | Internal (`templates/report-template.md`) | Client-facing (`templates/audit-report.md`) |
|--|-------------------------------------------|----------------------------------------------|
| Used by | `/auditor:audit`, `/auditor:audit-report` | `/auditor:audit-cycle`, `/auditor:audit-assist` |
| Risk score | **keeps** the numeric Repository Risk Score (the team's deploy-gate) | **no** risk score presented as a deploy verdict |
| Shape | Executive Summary → Scope Coverage → Scope & Methodology → Findings → Detailed Item Results → Known Vector Results → Instruction Matrix → State Model → Code Maturity Scorecard → Remediation Roadmap → Appendices | Executive Summary → Scope & Engagement (envelope, commits, in/out of scope) → Methodology → System Overview (§4.4 Trust Model, §4.6 Assumptions & Simplifications, §4.7 Systemic Risks) → Severity Classification → Findings → Code Maturity Assessment → Appendices (incl. Disclaimer) |

The client report follows firm convention: a **maturity narrative** (9-category, 0-4 weakest-link scorecard from Phase 4.5), **trust-model caveats**, a mandatory **Assumptions & Simplifications** section (what the review took as given — trusted admins, honest oracles, upgrade-authority custody, out-of-scope programs — so "no finding here" reads against a stated assumption, not a blanket clearance), an **engagement envelope** (named agents/effort, pinned commit range), an explicit **out-of-scope** list, and a **LOC-vs-budget** note.

## The no-"safe to deploy" convention

Like a real firm, the **client-facing report issues no "safe to deploy" guarantee** — the deployment decision is the client's. The internal template retains the numeric risk score for the team's own gating, but that number is never surfaced to a client as a green light. The honest framing throughout: this is **audit-shaped automation — a rigorous, reproducible first pass**, not a substitute for a human firm audit; pair it with human business-logic, economic-model, and legal-compliance review before mainnet ([SKILL.md → When NOT to Use](../SKILL.md)).

## Operating safety (Rule 11)

- **Execution mode (11a).** Target-controlled code — builds, tests, installs, every PoC build, and any `cargo` / `rustc` / `anchor` command started inside the target tree (cargo and rustup read config from every parent directory) — runs through the bundled runners, `target.sh` and `run.sh --crate`, from a scratch copy outside the tree with a pinned toolchain, in the mode set at intake (`Q46`): **native**, the default when nothing is recorded (the report says target code ran on the auditor's machine), or **isolated** (container / VM / sandbox, no keys mounted); **none** runs none of it in the runners, though a plugin you enabled may still run some, such as a language-server plugin that runs build scripts, unless Claude Code starts with the strict launch line (11f). Intake writes the answer to `audit_<n>/exec-mode`, and the runners take the stricter of the `exec-mode` of the run directory they work in, `AUDITOR_EXEC_MODE` and strict mode, which raises it to isolated at least (11f). With no recorded mode they run native, with that caveat, and nothing asks for the mode later. In that mode they build without a prompt for each run: the Q46 answer, or the native default and its caveat, covers them. In isolated mode they first check that no credential is readable, and stop if one is. Every child of `target.sh` and `run.sh --crate` runs in a cleaned environment with a throwaway `HOME` and keypair, and after the downloads with cargo offline and without the proxy variables; a build script can still open a connection itself on an open network, and `run.sh` builds with the real `HOME` when `cargo build-sbf` lacks the options it needs, and says so. Version probes, dependency queries and SAST run outside the tree through `probe.sh`, `deps.sh` and `sast.sh`, which run no target code. Mutation runs and Trail of Bits harnesses that build target code run outside the runners, in the same mode, and ask before they run; so does a Trident, cargo-fuzz or Surfpool runner that `poc-engineer` writes, which starts with the same gate and builds from a scratch copy too. An incident whose root cause is supply chain / CI is never built natively, and its PoC never builds or links the target's crates in any mode: it runs on the dumped program bytes alone. A step that cannot run in the chosen mode, or that Claude Code denies, falls back to `[PoC-ATTEMPTED]` / `[FIX-PROPOSED]` / a source-level verdict with a confidence note.
- **Outside services (11b).** No consent gate. The report lists each tool, the service it contacted, and what it sent: every row the bundled tools that query outside services add to a run directory's `disclosures.tsv` before their first request, then what no row holds: the builds' own downloads, MCP servers, WebFetch and anything run by hand. Live probes of the project's own hosts and buckets (DEP-072, DEP-073) run only when intake allows them (`QUESTIONS.md` Q47; unanswered or `--auto` is no), only for what `audit_<n>/intake.md` §8 lists, read-only and unauthenticated, and the report lists each one as an outside contact.
- **Untrusted git checkouts (11c).** In a `.git/` the auditor did not clone, git runs only through `git-ro.sh`: an empty environment, system and global config dropped, an empty transport allowlist (`GIT_ALLOW_PROTOCOL`: no lazy fetch and no remote helper, on every git version, whatever the checkout's config allows; `protocol.allow=never` is only a backstop), pins for the config keys known to run a program, and a closed list of read-only subcommands. Its definition is the raw form, the rule for git run by hand: `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false <cmd>`, so a read in a partial clone never fetches a missing object from the checkout's promisor remote (git 2.44+; older git ignores the variable, so there nothing reads file contents in a checkout the partial-clone check flags, and the audit works from a full copy); `--no-textconv --no-ext-diff` go on `log -p` / `-S` / `-G`, `show`, `diff` and `blame`; no `--show-signature` or `%G` placeholders; only committed revisions are read (blame names a revision; no `git status` or working-tree diffs); nothing is checked out, merged, committed, fetched, pulled, pushed or `ls-remote`d there. Better: audit the bare copy `git-ro.sh copy` makes in the run directory (by hand, a `GIT_NO_LAZY_FETCH=1 git clone --no-local <checkout> <scratch copy>`), with git 2.45.1+ (or the matching maintenance release); a copy of a partial clone then fails instead of fetching, and `git-ro.sh partial` flags a checkout whose config has `remote.<name>.promisor` or `extensions.partialClone`, which counts as incomplete history.
- **Output hygiene (11d).** Each output directory's first file is a `.gitignore` containing `*`: `rundir.sh new` makes every run directory that way, `rundir.sh check` passes one for reuse, and `audit-mem init --contract=1` writes `.audit-memory/.gitignore` first; CI on a public repo posts pass/fail only, never counts or findings. An `.audit-memory/` store is used only when the auditor created it and `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false --icase-pathspecs ls-files -- .audit-memory` prints nothing and exits 0, which catches a tracked store in any letter case; `audit-mem` runs that check itself before every use, and refuses the store when it fails. A store that fails it, or is not the auditor's, gives way to a store for the run (`--db audit_<n>/audit-mem.db`, given after the subcommand and its `--contract=1`), and a tracked `.audit-memory/.gitignore` is never overwritten.
- **Bundled paths (11e).** Scripts, the Rust tools, templates, the Trail of Bits plugins and corpus files are resolved from the auditor-skill installation root, never the working directory (usually the audited repo): commands and agents write that root as `${CLAUDE_PLUGIN_ROOT}` for what they run, the skill body as `${CLAUDE_SKILL_DIR}`, other files as the absolute root the command or skill gave. Corpus Markdown that command or agent text names by a relative path (`references/`, `templates/*.md`, `OUTPUT-RULES.md`, …) is read from that root as well; if a file is missing there, the auditor says so instead of opening a same-named file in the working directory. A vendored Trail of Bits skill's `{baseDir}` and relative paths point into its own plugin directory there. Each bundled tool runs as one plain command, its quoted path first with nothing in front: the form the commands pre-approve. Every flow first runs `preflight.sh`, whose first line names the mode: in default mode it notes the Claude Code project config a working tree ships, and in strict mode it refuses it; an untracked `.claude/settings.local.json` is the user's own and never refused. The installation never sits inside the audited repository, and that repository's own `.claude/` (skills, commands, agents, settings hooks and env, and `rules/`, at most a patch style reference), `.mcp.json` and `CLAUDE.md` are target-controlled: inspect or remove them, or start the session outside the tree, before trusting the folder.
- **Default and strict mode (11f).** By default a check that finds something in the repository prints a `note:` line and goes on, which the report copies into Coverage & Limitations once per distinct note, as it stands, with preflight's mode line; the few shapes still refused in both modes, such as a named pipe in a `.git` or a link in a git directory outside its hooks, are listed in Rules 11e and 11f. Strict mode, for a source you do not trust, refuses what those notes name and raises the execution mode to isolated at least. `AUDITOR_STRICT=1`, a command's `--strict`, or intake's "Untrusted source" answer turns it on, and a `strict` file in a run directory keeps it on until deleted. Nothing in the repository can turn strict mode off when Claude Code starts with the strict launch line (`claude --setting-sources "" --strict-mcp-config --plugin-dir "<auditor-skill root>" --settings "<auditor-skill root>/templates/strict-settings.json"`), or with `AUDITOR_STRICT=1` in managed settings. Started any other way, the repository's own settings (hooks, `env`, `CLAUDE_ENV_FILE`) apply first and can switch it off. What the auditor itself may do (read-only git, writes only in its run directories, none of the user's credentials, argument checks in every pre-approved tool) is limited in both modes.

## Report file naming

| Output | File |
|--------|------|
| Audit report (Standard: internal; Full: client) | `audit_<n>/REPORT.md` |
| PR / diff report | `audit_<n>/PR-REPORT.md` |
| Quick scan report | `audit_<n>/QUICK-SCAN.md` |
| Deep review report | `audit_<n>/DEEP-REVIEW-<unit>.md` (the function or instruction name, else the file's name; `-2`, `-3` when taken) |
| CI findings (`--ci`) | `audit_<n>/findings.json` (`templates/ci/findings.schema.json`) |
| Re-audit finding-diff | `audit_<n+1>/RE-AUDIT.md` |
| Intake / threat model | `audit_<n>/intake.md` · `audit_<n>/threat-model.md` |
| Threat-model bootstrap evidence | `audit_<n>/bootstrap/` (`history.md` · `inputs.tsv` · `inputs/` · `diffs/`) |
| Remediation roadmap | `audit_<n>/roadmap.md` |
| Per-instruction worksheets | `audit_<n>/worksheets/{instruction}.md` |
| Incident (hunt/respond) | `incident_<n>/INCIDENTS.json` · `INCIDENT_REPORT.md` · `RESPONSE-INC-<n>.<k>.md` · `LEDGER.md` |
| Incident PoC / patch | `incident_<n>/poc/INC-<n>.<k>/` · `incident_<n>/patches/INC-<n>.<k>.patch` |

For `audit_<n>/` and `incident_<n>/` alike, `<auditor-skill root>/scripts/rundir.sh new` makes the directory: `<n>` is the next number whose name the repository tracks nothing under, the directory is created with `mkdir` (not `-p`), stopping if it already exists, and its first file is a `.gitignore` containing `*`. An existing run directory is reused only when git does not track it and it holds no symbolic link that leads out of it or to nothing (in strict mode, none at all), after the human confirms which one; nothing is ever written into a tracked run directory ([Rule 11d](../OUTPUT-RULES.md#11d--output-hygiene)).
