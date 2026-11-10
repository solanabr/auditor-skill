# Power Tools

The tools behind the audit flows, for anyone who wants to set up the optional ones, run one by hand, or check what a command runs: the three Rust tools (`audit-scan`, `audit-mem` and `audit-logs`), workflow analysis for GitHub Actions, the vendored Trail of Bits plugins, Surfpool's mainnet-fork simulation, the PoC and patch stack, and an index of the bundled scripts. Back to the [docs index](README.md).

The Rust tools, the workflow analyzers, Trail of Bits, Surfpool and the PoC toolchain are **optional layers**. The corpus works without any of them: each one saves tokens, adds memory across audits, or turns an asserted finding into a demonstrated one, and a run without it names what was missing. The bundled scripts are different: they ship with auditor-skill, need nothing built, and the commands run them as their own steps.

| Tool | Buys you | Built/enabled by |
|------|----------|------------------|
| [`audit-scan`](#audit-scan) | ~30-40% fewer input tokens; a map of the risky surface | `cargo build --release --locked` |
| [`audit-mem`](#audit-mem) | exact de-dup, regression detection, FP suppression, warm re-audits | `cargo build --release --locked` |
| [`audit-logs`](#audit-logs) | the incident recipes `profile.sh`, `frames.py` and `deltas.py` as one offline binary, with the same output | `cargo build --release --locked` |
| [GitHub Actions workflow analysis](#github-actions-workflow-analysis) | a map of each workflow's triggers, jobs and steps, then pinned zizmor and CodeQL runs | `audit-scan` built; zizmor and CodeQL installed by you |
| [Trail of Bits plugins](#trail-of-bits-plugins) | real SAST, fuzzing, coverage, mutation | plugin install or `install.sh`; else `git submodule update --init --depth 1 -- vendor/trailofbits` |
| [Surfpool sim](#surfpool-economic-simulation) | a real $ P/L for economic findings | `surfpool` CLI + MCP |
| [PoC/patch harness](#pocpatch-harness-stack) | executable exploits + verified fixes | platform-tools ≥ v1.54 |
| [Bundled scripts](#bundled-scripts) | the working-tree check, run directories, read-only git, the lockfile and known-bad release checks of the git history, the runners that build, test, audit dependencies and run SAST, incident corpus collection and queries, the threat-model history collector, RPC reads and the report PDF, each documented on one of four pages | nothing to build: bash ≥ 3.2, plus `git`, `jq`, `python3`, `curl` or the `solana` CLI per script, and the toolchains the runners drive |

---

## audit-scan

A deterministic Rust AST pass (`syn` with `span-locations`, so every hit carries a real line number) that emits the *risky surface* of a Solana/Anchor codebase as one JSON — so the LLM auditor spends tokens on **judgment**, not mechanical enumeration.

### Run it

Build once, then run the binary by its absolute path from the repository under audit. `<auditor-skill root>` is the directory auditor-skill is installed in, never a path relative to your project ([`OUTPUT-RULES.md` Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)):

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release --locked        # once
"<auditor-skill root>/tools/auditor-tools/target/release/audit-scan" --contract=1 ./programs/my-program/src --pretty --out audit_1/prescan.json
```

The installation belongs outside the repository under audit. If it sits inside it anyway (such as `.claude/skills/auditor-skill`, where `install.sh` without a path installed through 7.6.0), the build runs inside the target tree, where cargo and rustup read the target's `.cargo/config*` and `rust-toolchain*` from every parent directory. Build there only in [Rule 11a](../OUTPUT-RULES.md#rule-11-operating-safety) isolated mode, or delete that copy and install a fresh one outside the repository (the plugin, or `install.sh ~/.claude/skills/auditor-skill`) and build that one. Never move or update a copy you find inside a repository ([README](../README.md#installation)).

Recursively walks the `*.rs` files under the directory it is given (`.` or a relative path inside the repository, reached through no symbolic link), skipping `.git/`, `node_modules/` and a `target/` cargo built in (one holding cargo's `CACHEDIR.TAG` or `.rustc_info.json`), and, for `.`, the run directories and the `.audit-memory/` store an audit made (a directory of such a name that the repository tracks is scanned). It parses each with `syn::parse_file` and prints one JSON object to stdout, or writes it to `--out audit_<n>/prescan.json` (or `prescan-<slug>.json`) in a run directory. It follows no symbolic link, goes no deeper than 128 directories, and parses only regular files with one name, of at most 4 MiB, whose groups nest at most 256 deep and whose token chains run at most 20,000, one at a time in a child, a new one after a file it does not finish (it starts no program but git and, to parse, itself); `skipped` lists every directory it did not enter, every link and every `*.rs` it did not parse, a file the parser could not finish or one after the scan's 90 seconds among them, with why. Any other path is refused with exit 2 and one `audit-scan: refused: …` line ([tools/auditor-tools/README.md](../tools/auditor-tools/README.md#where-it-reads-and-writes)). Every call carries `--contract=1` first; a build older than that contract refuses it: build it again.

**Default and strict mode** ([Rule 11f](../OUTPUT-RULES.md#11f--default-and-strict-mode)). `audit-scan` reads the mode as the bundled scripts do. In default mode a missing `--workflows` directory skips that pass, with a `skipped` entry; a `.rs` file with a second name is scanned once, under the first name the walk meets, and each later name gets a `skipped` entry; and a link inside a run directory that resolves inside it, or a run directory git cannot check, or with no git on `PATH`, whose `.gitignore` is `*`, is accepted. Strict mode refuses each of these, and skips both names of such a file. In both modes, when git cannot answer, a scan of `.` passes over the run directories whose `.gitignore` is `*`, and each workflow value or key cut at 200 characters adds an `unknown` entry, so only a workflow with an empty `unknown` was read whole. An `AUDITOR_STRICT` value outside the on and off words prints `audit-scan: note: AUDITOR_STRICT is '<v>', read as on` on stderr, as the scripts do.

### What it extracts

| Key | Seeds |
|-----|-------|
| `instructions[]` | every `#[program]` handler + typed args (the Anchor `Context<..>` param dropped) → Phase 0.3 instruction matrix |
| `accounts_structs[]` | every `#[derive(Accounts)]` struct; each field's parsed `#[account(...)]` constraints (`init`/`init_if_needed`/`mut`/`signer`/`has_one`/`seeds`/`bump`/`close`/`owner`/`token`/`associated_token`/`realloc`) + `unchecked` flag for `UncheckedAccount` fields + raw text → checklists 01/04 |
| `pdas[]` | every `seeds = [...]` catalog, every `find_program_address`/`create_program_address`/`derive_address`-family call with its seeds, and every `get_associated_token_address`-family call with its arguments → checklist 04 PDA review |
| `arithmetic_sites[]` | every RAW `+ - * /` / `+= -= *= /=` (NOT `.checked_*`) with `file:line` → the checklist-03 worklist |
| `panic_sites[]` | `.unwrap()`/`.expect()`/index `x[y]`/`panic!`/`unreachable!`/`unwrap!` → checklist 03 / DoS review |
| `cpi_sites[]` | every function or method called by a name that holds `invoke` (`method:<name>` for a method): `invoke`/`invoke_signed` and their `_unchecked`/`_with_bounds`/`slice_`/`_with_slice` forms, `sol_invoke_signed_*` syscalls, and helpers such as spl-token-2022's `invoke_transfer_checked` and a Codama client's `invoke_signed_with_remaining_accounts`; every path that names `CpiContext` (the type, `CpiContext::new(…)`, `CpiContext::new_with_signer(…)`); and every other path whose name holds `invoke` that is named but not called there, such as a function taken as a value (`let cpi = invoke_signed;`, kind `ref:invoke_signed`), a name written as a raw identifier (`r#invoke`) included → checklist 04 CPI review |
| `remaining_accounts_sites[]` | `.remaining_accounts` field access → checklist 01 remaining-accounts review |
| `unsafe_blocks[]`, `functions[]` | unsafe surface + call-graph seed |
| `skipped[]` | directories not entered, links not followed, `*.rs` files not parsed (one the parser could not finish, or one after the report was full or the scan's 90 seconds, too), files listed only in part (past 20,000 sites, or 32 MiB), and files a parsed one brings in by `#[path]` or `include!` that are not parsed (not named `*.rs`, outside the directory scanned, in a directory the walk did not enter, or not found; for a `#[path]` inside an inline module, at each place rustc may find it; and one whose path leaves a link or another directory the walk did not enter by `..`, named with that directory, as it may lie elsewhere), with why: read them by hand, but for the directories skipped by design (`.git/`, `node_modules/`, a `target/` cargo built in, an audit's own run directories and store), unless one sits where source does; a file in one of them that a parsed file brings in is listed on its own |

### The one rule: it is a map, not a verdict

The scan output has **no verdicts**. A raw `arithmetic_sites` or `panic_sites` entry is a *candidate*, never a confirmed bug — it still goes through the checklist + Rule 5b reachability/bounds analysis. Never report a scan hit as a finding on its own.

It is a syntactic pass: it does not resolve macros, generics, or cross-crate types, so it **under-reports** (macro-generated handlers, trait-dispatched CPIs, calls through an import under another name, a helper whose name does not hold `invoke`, the call through a function value, which `cpi_sites[]` lists where the value is taken as `ref:<name>`, not where it is called, or a derivation through a program's own helper of another name, which `pdas[]` lists where the helper derives, not where it is called) and **over-reports** (raw arithmetic on already-bounded operands, a call whose name only holds `invoke`, a `ref:` site that names a value such as a local `invoke_accounts`). The report must state that a deterministic pre-scan seeded the review and its output was *verified, not trusted*, by the item-by-item walk.

### The token win

Feed `prescan.json` to the auditor at Phase 0. Two effects: (1) the instruction/constraint/PDA/arithmetic tables are already built, so Phase 0.2-0.4 cost near-zero; (2) a file with **zero** scan hits gets a spot-check instead of a full read. This collapses the mechanical multipliers (checklist cross-ref ~0.3×, discovery ~0.2×, checkpoint re-reads ~0.1×) toward ~0.1× total — on a 50K-line program roughly **200-300K fewer input tokens** (variable multiplier ~1.6× → ~1.0×). Used at Phase 0 of the automated flow and by `context-builder`; falls back to the grep walk when `cargo` is absent.

Reference: [`references/orchestration/pre-scan.md`](../references/orchestration/pre-scan.md).

---

## audit-mem

A local SQLite findings store (`.audit-memory/audit.db` by default, self-ignored ([Rule 11d](../OUTPUT-RULES.md#11d--output-hygiene)), or `audit_<n>/audit-mem.db` for one run; `audit-mem init --contract=1` makes it) for cross-audit memory. It is the **authoritative** source for de-dup, regression state, and FP rulings — because those must be *auditable* ("suppressed by ruling #14, dated X").

### Content-addressed identity

```
finding_id = sha256(program_id ‖ code_signature ‖ root_cause)
```

The same bug keeps its identity across commits and line drift — the same normalized signature `/auditor:re-audit` uses for its sibling sweep, and `/auditor:triage` uses for root-cause de-dup.

### The four capabilities

- **Exact de-dup** — two candidates with the same `finding_id` are one finding (all locations recorded). `/auditor:triage` collapses them.
- **Regression detection** — when `put-finding` re-observes a finding whose stored status was `FIXED`, it transitions to `REGRESSED` and prints `REGRESSED <id>` (deterministic, not LLM-judged). `audit-mem regressions --contract=1 --program-id <id>` lists them, each with the severities and titles a later `put-finding` replaced under `changed` → the `/auditor:re-audit` finding-diff and the report's "regressions since last audit" section.
- **False-positive suppression** — `audit-mem rule --contract=1 ... --ruling FALSE_POSITIVE --commit <full commit id> --guard <file>:<line> --site <file>:<line>` records a ruling anchored to the commit and to the guard that makes it a false positive, with a hash of the guard's lines, for the one candidate `--site` names; `audit-mem check --contract=1 --commit <full commit id> --site <file>:<line>` gates on it (exit 0 = suppressed). A sibling with the same signature at another site is another candidate, suppressed only by a ruling of its own: `check` of a site with none, or one that names no site, reports the ruling `"stale"`, and it suppresses nothing. A ruling holds only at the commit it was made at: there, while the guard's lines are unchanged, `/auditor:triage`'s `check` by signature auto-suppresses the finding to `[N/A — prior ruling #<id>]`, so the same commit is not ruled on twice. At another commit, or once the guard's lines changed, the ruling is reported `"stale"` and suppresses nothing: on a re-audit it lists the settled false positives to confirm, and to rule again at the new commit.
- **Warm re-audits** — `audit-mem warm --contract=1 --program-id <id>` returns `{profile, invariants[], open_fp_rulings[], truncated}` so a re-audit starts warm, not from zero: the protocol profile `audit-mem profile` recorded, the invariants `audit-mem invariant` recorded (each with the values they replaced, under `changed`, the newest 10 of each), and the rulings with their anchors, each list its newest 200 rows. Used at intake / Phase 0 and by `threat-modeler`.

### Lifecycle example

Use an in-tree store only if you created it. `audit-mem` runs the mechanical part of the [Rule 11d](../OUTPUT-RULES.md#11d--output-hygiene) check itself before every use of `.audit-memory/`: the repository must not track `.audit-memory` in any letter case (what `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false --icase-pathspecs ls-files -- .audit-memory` shows), and the directory must hold no symbolic link and a `.gitignore` of exactly `*`. When that fails, or git cannot answer, it refuses with exit 2; use a store for one run instead, `--db audit_<n>/audit-mem.db`. In default mode ([Rule 11f](../OUTPUT-RULES.md#11f--default-and-strict-mode)) the readers ask less: `warm`, `check` and `regressions` with no `.audit-memory/` give their empty answer without asking git (`check`'s is `{"suppressed":false,"store":"absent"}`, exit 1); `warm`, `regressions` and `check` read an untracked store that lacks its `.gitignore`; a link inside the store that resolves inside it is accepted; a store for one run is accepted when git cannot answer, or is not on `PATH`, but its run directory's `.gitignore` is `*`; and the tables SQLite's `ANALYZE` makes (`sqlite_stat1` to `sqlite_stat4`) are accepted, each only as SQLite writes it. The writers keep every check, and strict mode keeps them all. The example uses the in-tree store, so it runs from the repository under audit; `audit-mem` stands for `"<auditor-skill root>/tools/auditor-tools/target/release/audit-mem"`, and each call carries the contract marker `--contract=1` right after its subcommand.

```bash
audit-mem init --contract=1          # .audit-memory/, its .gitignore of * first, then audit.db

# first observation -> "OPEN <id>"
audit-mem put-finding --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee1 --audit-n audit-1 \
  --file src/withdraw.rs --line 42 --verdict TRUE_POSITIVE

# dev fixes it
audit-mem set-status --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' --status FIXED

# next audit re-observes -> "REGRESSED <id>"
audit-mem put-finding --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee3 --audit-n audit-3

# what the next audit starts from; a value replaced later is kept, and warm lists it under changed
audit-mem profile --contract=1 --program-id VaultProg... --protocol-class vault --oracle-set 'pyth SOL/USD'
audit-mem invariant --contract=1 --program-id VaultProg... --statement 'total_shares == shares_mint.supply' --status Unproven

# rule a known FP at the audited commit, citing its guard, then gate on it
audit-mem rule --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --ruling FALSE_POSITIVE --rationale 'guarded by the require! on line 40' --by auditor \
  --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe --guard src/withdraw.rs:40 --site src/withdraw.rs:42
audit-mem check --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe --site src/withdraw.rs:42
#   -> {"suppressed":true,"ruling":{...}}   (exit 0)
audit-mem check --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe --site src/liquidate.rs:17
#   -> {"suppressed":false,"stale":"ruled for the site src/withdraw.rs:42, checked for src/liquidate.rs:17",...}   (exit 1)
audit-mem check --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --commit c0ffee4c0ffee4c0ffee4c0ffee4c0ffee4c0ffe --site src/withdraw.rs:42
#   -> {"suppressed":false,"stale":"ruled at commit c0ffee3…, checked at c0ffee4…",...}   (exit 1)
```

### Subcommands

`init` · `put-finding` · `set-status` (`FIXED`|`OPEN`|`ACKNOWLEDGED`|`DISPUTED`) · `rule` (`FALSE_POSITIVE`|`ACCEPTED_RISK`, with `--commit`, a full commit id, `--guard` and `--site`, the candidate's `<file>:<line>`) · `check` (`--commit`, `--site`) · `regressions` · `warm` · `profile` · `invariant`. The subcommand comes first, then the contract marker `--contract=1` (a build older than the contract refuses it: build it again); `--db` is `.audit-memory/audit.db` (the default) or `audit_<n>/audit-mem.db` (or `incident_<n>/audit-mem.db`), nothing else. `warm`, `check` and `regressions` open the store read-only, and read nothing beside a write to it that did not finish (exit 2, naming the `audit-mem init --contract=1` that rolls it back); `warm` gives the newest 200 rows of each list and `regressions` the 200 regressed findings seen most recently, each item with the newest 10 values replaced in it (`changed`, 200 in all), and `truncated`. Schema: `findings`, `occurrences`, `fp_rulings` (with each ruling's anchor and site), `invariants`, `protocol_profile`, `history` (the values `profile`, `invariant` and `put-finding` replaced).

### Exactness over similarity

This store is the source of truth *because* suppression and regression must be auditable and deterministic. Semantic recall ("have we seen a bug shaped like this?") is a **secondary fuzzy index** over descriptions — never the authority for suppression or regression. And rulings are **scoped to their `program_id`**: never carry a client's ruling into a different codebase, and always surface suppressed items in an appendix.

Reference: [`references/orchestration/pre-scan.md`](../references/orchestration/pre-scan.md) · [`tools/auditor-tools/README.md`](../tools/auditor-tools/README.md).

---

## audit-logs

The detection & response analysis recipes, [`profile.sh`](scripts-incident.md#profilesh), [`frames.py`](scripts-incident.md#framespy) and [`deltas.py`](scripts-incident.md#deltaspy), as one offline Rust binary. Each subcommand prints what its script prints, with the same `skipped …` notes and exit status, under the same input contract, and refuses the same paths in the same words; `scripts/tests/test-audit-logs.sh` checks that against the scripts. Inside the `auditor:dnr-analyze` fork, where `/auditor:hunt` and `/auditor:respond` run `incident-responder` for each analysis phase, it runs first, and the script runs in its place when it is not built or reports a stale build.

### Run it

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release --locked        # after every install or update
"<auditor-skill root>/tools/auditor-tools/target/release/audit-logs" profile incident_<n>/corpus*/transactions.jsonl
"<auditor-skill root>/tools/auditor-tools/target/release/audit-logs" frames --instructions --out incident_<n>/instructions.jsonl incident_<n>/corpus*/transactions.jsonl
"<auditor-skill root>/tools/auditor-tools/target/release/audit-logs" deltas tokens incident_<n>/corpus*/transactions.jsonl
```

Build it in the installation, never inside the repository under audit, as for `audit-scan`, and build it again after every update. A plugin update installs auditor-skill into a new versioned directory, where the fork runs the scripts until it is built there; an update in place, such as a `git pull` of a clone, leaves the old binary, which refuses to run (exit 4, below) only when the update changed a file it was built from: a recipe it mirrors, `scripts/lib/confine.sh`, or its own `Cargo.toml` or `src/`. `cargo build --release --locked -p audit-logs` builds it alone: it compiles one dependency, `libc`, and needs no C compiler, though cargo still reads the crates.io index for the workspace lockfile.

- **Paths:** as for the scripts: each corpus is a regular file with one name in an `incident_<n>/` run directory whose `.gitignore` holds `*`, named relative to the working directory, with no empty, `.` or `..` component and no symbolic link on the way; each option comes once, before the corpus paths; `--out` names a new `<name>.jsonl`, `.tsv` or `.txt` directly in the run directory. Anything else is refused with exit 2 before any input is read. With no corpus named, `frames` and `deltas` read stdin.
- **Exit:** 0 done · 1 an input that cannot be read, an `--out` that cannot be written, or a failed write · 2 usage, or a refused path · 4 a stale build: it carries a copy of the files it was built from (the three recipes, `scripts/lib/confine.sh`, its `Cargo.toml` and `src/`), and when an installed one differs it writes nothing and prints one line, `audit-logs: stale build: …`; rebuild it, or run the scripts.
- **Pre-approval:** inside the `auditor:dnr-analyze` fork, `audit-logs` runs without a prompt by this path, as do the three recipes and `jq-ro.sh`; the fork pre-approves no other bundled script, and nothing pre-approves `jq`. Each refuses a named input outside a run directory before reading anything (exit 2). With no corpus named, `frames` and `deltas` read stdin, which a `<` redirect can fill from any file Claude Code lets the fork read; they print nothing from a line that is not a transaction. A line that holds a `$` or a backtick, inside quotes too, still prompts.
- **Network:** none. **Writes:** stdout, or the `--out` file, through a new temporary file beside it, made, linked and removed through the run directory, opened once.
- **Where it differs from the scripts:** `profile` pads its counts as GNU `uniq -c` does (BSD `uniq -c` pads to 4); a closed stdout, a broken pipe or a stdin that is a directory ends it with another exit status; and it needs none of what `profile.sh` alone refuses to run without (a `TMPDIR` and a `PATH` entry outside the working directory, `jq`, `python3`); see [`tools/auditor-tools/README.md`](../tools/auditor-tools/README.md#where-it-differs-from-the-scripts).

---

## GitHub Actions workflow analysis

Three layers, cheapest first. Each is optional; the corpus's GitHub Actions checks (`references/vuln-classes/github-actions.md`, `discovery/grep-commands.md` R1–R9) run without any of them. R9 lists every action and reusable workflow pinned to a full commit SHA, with its version comment, and the playbook's §7 turns pins and repointed tags, self-hosted runners and OIDC trust policies into procedures (KV-080 Steps 4 and 8, KV-140 Step 7).

1. **audit-scan's workflow pass** — bundled, offline, no prompt: `"<auditor-skill root>/tools/auditor-tools/target/release/audit-scan" --contract=1 <program-path> --workflows .github/workflows --out audit_<n>/prescan.json`, the optional pre-pass of FULL-AUDIT.md 0.3 with `--workflows` added. It reads each `*.yml`/`*.yaml` into trigger → job → step facts (`workflows[]`), and lists under each workflow's `unknown[]` what it did not read (only a workflow with an empty `unknown` was read whole), and whole files under `skipped[]` (see [`tools/auditor-tools/README.md`](../tools/auditor-tools/README.md#the-workflow-pass)). It is a **map, not a verdict**: it enumerates the surface the grep rules and the tools below then judge.
2. **zizmor** — a workflow SAST. Third-party, so it is an install plus a run and **prompts by design** ([permissions-and-isolation.md](permissions-and-isolation.md#what-still-asks-and-why)); run it in the recorded execution mode.
3. **CodeQL** — GitHub's `actions` queries. Also third-party, also prompts; mind its licence (below).

### zizmor — run it pinned and without the target's config

Pin the tool **by version and by hash**, and ignore any configuration, ignore comment or ignore file the audited repository ships. Neither pinned command below has been run with its pins, the container by the image digest or the PyPI install with the wheel hashes: the digest was read from the container registry and the hashes from PyPI (**Pinning**, below), and `scripts/tests/test-probe-recipes.sh` runs both forms with stand-ins for docker, pip and zizmor.

```bash
# zizmor 1.30.1: the published container by the digest of its image index, with no network
docker run --rm --network none -v "$PWD":/src:ro \
  ghcr.io/zizmorcore/zizmor@sha256:a2eb396d886c053073405c7a980f2139ba2248ec172243cfa3841e57196e8101 \
  --offline --no-config --no-ignores --collect=all --persona=auditor /src/.github/workflows
```

Without Docker, install the same version from PyPI in pip's hash-checking mode, into a virtual environment outside the checkout; zizmor 1.30.1 needs Python 3.10 or later. Save the requirement, with the sha256 of every 1.30.1 wheel, as `~/.venvs/zizmor-1.30.1.txt`, outside the repository under audit too:

```text
zizmor==1.30.1 \
    --hash=sha256:17fda74e15fe41a6aa354ea4cf71fc7ff3cd025cda6584bb6d7466b3f1d00fe6 \
    --hash=sha256:f9eb092f089e35fa9fb3b70aeec0a19eca7dacf2ab161f1d50b18351895f085c \
    --hash=sha256:92906f448365672ebb657fb50d36f997290a3aaba8cac723214741ea9054845d \
    --hash=sha256:5e8a3d54c3d9d51307371f4d1d49f8f9e56de00205c6cc660c6846a95ad4e135 \
    --hash=sha256:eee12266b793cb87ad4a7e3af2e72404f8a63e3de5eb099b80bf7b1cfd232a8e \
    --hash=sha256:15679642e8c4f825ba3f22537c698b1bbbad19ead23640f62ec45ebbe7abc803 \
    --hash=sha256:bf63099a27ef3bf1329dbab44bb9d1027124855c71bd0eca864d5c8e1c5c0db1 \
    --hash=sha256:4a5ef2fa4fbd2984f794cfc2f95790bd03fa0bae801487ed550e044675874e60 \
    --hash=sha256:42512bb4a1bce4c787d221d1572ff6b691fa52a3d129b2910be8afaf860c5871 \
    --hash=sha256:06e039fae8e185e2a1a8b002f2d95a6f5c3b548048bdd79e004dcb501fcd0868
```

Then run these lines from the checkout's top level, where the last one finds `.github/workflows`. The first two change to your home directory before Python or pip starts, so they work the same from any directory and nothing the checkout holds can run while the environment is made and zizmor installed into it: `python3 -m` puts the working directory first on `sys.path`, so a `venv.py` the repository ships would run in place of Python's own (`python3 -I`, isolated mode, keeps the working directory off it), and Python 3.9 before 3.9.14 and 3.10 before 3.10.6 set pip up, while they make the environment, in a child that is not isolated and starts in the working directory. The last line runs the environment's own zizmor, by its path.

```bash
(cd ~ && python3 -I -m venv ~/.venvs/zizmor-1.30.1)
(cd ~ && ~/.venvs/zizmor-1.30.1/bin/pip install --require-hashes --only-binary :all: --no-deps -r ~/.venvs/zizmor-1.30.1.txt)
~/.venvs/zizmor-1.30.1/bin/zizmor --offline --no-config --no-ignores --collect=all --persona=auditor .github/workflows
```

- **Why `--no-config`.** zizmor discovers a config file at `.github/zizmor.yml`, `.github/zizmor.yaml`, `zizmor.yml` or `zizmor.yaml` from the repository root, and a discovered config can turn audits off (`rules.<id>.disable`) or ignore findings in named files (`rules.<id>.ignore`). Since the repository under audit is untrusted, do not let its config steer the scan: `--no-config` loads no configuration at all (per the docs, "If `--no-config` is passed, no configuration is ever loaded"); `--config <your own file>` or `ZIZMOR_CONFIG` replaces discovery with a file you control. ([docs.zizmor.sh/configuration](https://docs.zizmor.sh/configuration/))
- **Why `--no-ignores`.** A workflow file can also silence a finding itself, with a `# zizmor: ignore[<rule>]` comment on the lines the finding covers, and `--no-config` leaves those comments in force. `--no-ignores`, in zizmor 1.25.0 and later, turns off every ignore, comment and configuration alike, so no comment or configuration in the audited repository hides a finding. ([docs.zizmor.sh/usage](https://docs.zizmor.sh/usage/), "Disabling ignores")
- **Why `--collect=all`.** By default zizmor leaves out of a directory each file that `.gitignore`, or a related file such as `.git/info/exclude`, matches (zizmor 1.5.0 and later), with or without a `.git` directory (1.5.1), and the audited repository writes its own `.gitignore`. A pattern there does not stop GitHub from running a workflow that is already committed (per git's docs, "Files already tracked by Git are not affected"), so the repository could keep one of its own workflows out of the scan. `--collect=all` collects everything "regardless of `.gitignore` patterns". ([docs.zizmor.sh/usage](https://docs.zizmor.sh/usage/), [docs.zizmor.sh/release-notes](https://docs.zizmor.sh/release-notes/), [git-scm.com/docs/gitignore](https://git-scm.com/docs/gitignore))
- **`--offline`** blocks network and remote-repository fetches, and `--network none` gives the container no network at all; **`--persona=auditor`** reports every finding, "even ones that it's not sure about". ([docs.zizmor.sh/usage](https://docs.zizmor.sh/usage/))
- **Pinning.** The published image is `ghcr.io/zizmorcore/zizmor` ([docs.zizmor.sh/installation](https://docs.zizmor.sh/installation/)); its version tags have no `v` (`1.30.1`), and zizmor's install docs show only the unpinned `:latest` pull and unversioned `pip install zizmor` / `uvx zizmor`. The values above were read on 2026-11-03: the registry's anonymous API gives `sha256:a2eb396d…8101` as the digest of tag `1.30.1` (there is no tag `v1.30.1`), an image index for linux/amd64 and linux/arm64 whose revision is `99a054e`, the commit of zizmor's `v1.30.1` release, and whose two image configs name `/usr/bin/zizmor` as the entrypoint; and PyPI's JSON API lists the ten wheel hashes for 1.30.1 and its `requires_python` of `>=3.10`. A digest always names the same image, so the command cannot change under you. To move to another release, take its digest and hashes from the same places, and change them in `scripts/tests/test-probe-recipes.sh` too, which pins them.
- **What it misses.** `github-actions.md` §9 records, for **zizmor 1.30.1** over fixtures 01–17, the gates it did not flag (a mention-only gate, a cross-object OR, deny-lists, event text in an agent prompt input). A clean zizmor run does not close the class.

### CodeQL — the `actions` queries, and the licence

CodeQL analyzes **GitHub Actions** as a language; its query packs are `codeql/actions-queries` and `codeql/actions-all`, matching `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `**/action.yml` and `**/action.yaml`. ([codeql.github.com, supported languages](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/)) Building a CodeQL database for Actions needs no compiler.

**Licence — read before running it on client code.** The CodeQL CLI licence permits analysis only of an "Open Source Codebase" — one "released under an OSI-approved License" (visibility is not the test). It **prohibits** using the tool "in any other context … with any codebase that is not an Open Source Codebase (e.g., code in a private repo in GitHub)"; a **paid GitHub Advanced Security** licence lifts that restriction. So CodeQL is fine for an open-source target, but for closed-source client code it needs that paid licence. ([github/codeql-cli-binaries `LICENSE.md`](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)) This is a plain-language reading of the terms, not legal advice; read the current terms before you rely on it.

---

## Trail of Bits plugins

auditor-skill's corpus is the **knowledge** layer; Trail of Bits (vendored at `vendor/trailofbits`, CC-BY-SA — a reference, not a copy) is the **execution** layer — tools prose + grep cannot run. The plugin install and `install.sh` fetch it at the pinned commit, which the [README](../README.md#tool-execution-trail-of-bits--optional-rust-tools) names and which moves only through the review in [CONTRIBUTING.md §5](../CONTRIBUTING.md#5-tooling-changes). For any other clone, initialize it from the auditor-skill directory:

```bash
git submodule update --init --depth 1 -- vendor/trailofbits
test -d "<auditor-skill root>/vendor/trailofbits/plugins" && echo present    # the detection agents use
git ls-tree HEAD vendor/trailofbits                   # the pinned commit, initialized or not
```

Agents delegate when present, fall back to native grep when absent (and note "deeper tooling available via `git submodule update --init --depth 1 -- vendor/trailofbits`, run in the auditor-skill directory (plugin and install.sh installs already include it)" in the report).

Rows that build or run target code follow the execution mode recorded at intake ([`OUTPUT-RULES.md` Rule 11a](../OUTPUT-RULES.md#rule-11-operating-safety)); rows that send code or dependency data to an outside service are listed in the report (Rule 11b). The commands do not pre-approve these tools: each run asks, and a non-interactive run denies it ([permissions-and-isolation.md](permissions-and-isolation.md#what-still-asks-and-why)). SAST with semgrep runs through the bundled [`sast.sh`](scripts-runners.md#sastsh) instead, which needs no prompt.

**Instruction files.** Trail of Bits ships a root `CLAUDE.md` that imports its contributor guide (`@AGENTS.md`, ~20 KB). When the submodule sits inside the project you run Claude Code in, that guide loads into the session the first time it reads a file under `vendor/trailofbits/`. To keep it out, add `"claudeMdExcludes": ["**/vendor/trailofbits/CLAUDE.md", "**/vendor/trailofbits/**/AGENTS.md"]` to your own `.claude/settings.local.json` — never to a client's committed `settings.json`.

### Capability → plugin → who uses it

| Capability | ToB plugin | auditor-skill use | Native fallback |
|------------|------------|-------------------|-----------------|
| Interprocedural SAST (taint) | `static-analysis`, `semgrep-rule-creator`, `variant-analysis` | `vuln-hunter` runs SAST, folds SARIF into verdicts; up-front in `audit-cycle` to clear the mechanical surface. A CodeQL build compiles the target (11a) | `discovery/grep-commands.md` |
| Property / fuzz harnesses | `testing-handbook-skills`, `property-based-testing` | generate + run a harness for any ≥High arithmetic/economic finding; `/auditor:poc` orchestrates (11a) | checklist 16 "does the suite exist" prose |
| Coverage & mutation | `testing-handbook-skills`, `mutation-testing` | evidence-back FV coverage; an uncaught mutant downgrades a PASS; `/auditor:patch --verify-with-mutation` uses a caught mutant as fix evidence (11a) | FV items `[PARTIAL — not machine-verified]` |
| Exploitability verify | `fp-check` (local); `second-opinion` sends the selected code to an external LLM CLI — OpenAI Codex or Google Antigravity / Gemini — so the report records it (11b) | `peer-reviewer` + `poc-engineer` confirm a finding is real, not a harness artifact | manual re-derivation |
| Secret zeroization (IR) | `zeroize-audit` | verify KV-112 / RS-015 at the IR level; compiles the target (11a) | grep `zeroize`/`Zeroizing` |
| Constant-time | `constant-time-analysis` | secret-dependent branches when custom crypto is present; compiles the code it checks (11a) | note "manual review needed" |
| Entry-point enumeration | `entry-point-analyzer` | seed the Phase 0 instruction matrix (Solana support); on Solidity, `slither .` compiles the target (11a) | manual `#[instruction]` enumeration |
| Supply-chain metadata | `supply-chain-risk-auditor` | enrich checklist 11 (SC-044..046); npm / PyPI / Go only. Its collector sends the project's dependency names to 8 outside services (OSV, npm registry + downloads API, PyPI, Go module proxy, deps.dev, GitHub API, OpenSSF Scorecard), so the report records it (11b); `--offline` only replays cached responses and is not a privacy control | `npm audit` / `cargo audit` + grep |
| Unit / dimensional analysis | `dimensional-analysis` (needs the ToB plugin installed for its `dimensional-analysis:*` agents; otherwise it reports BLOCKED) | propagate units through DeFi value paths (checklist 03/06) — catches mixed-decimals bugs; writes unit comments into the source and `DIMENSIONAL_*` files at the project root, so run it on a scratch copy without the target's `DIMENSIONAL_*` files | manual per-quantity tracking |
| Insecure-default trace | `insecure-defaults` (a command + Workflow, `/insecure-defaults:audit`, that runs only with the ToB plugin installed; from the vendored tree, read its `references/*.md`) | fail-open vs fail-secure trace (checklist 12/13) | grep fallback-secret patterns |
| API misuse / footguns | `sharp-edges` | misuse-resistance review of the program's own CPI interface + config | `references/framework-idioms/*` |
| Fix blast-radius | `differential-review` | `/auditor:patch` step 4: the fix closes the exploit path and leaves every other path unchanged | `/auditor:re-audit` 4b differential execution (11a) + manual caller / sibling review |
| Post-patch validation | `post-patch-validation` (its runner runs under `uv run` and needs Python ≥ 3.11 and git ≥ 2.36; its `/post-patch-validation:validate-patch` Workflow needs the ToB plugin installed and works against the repository the session runs in, so it is not used) | `/auditor:patch --post-patch-validation` (opt-in): the patch against the finding, root-cause variants and unchanged behavior. Isolated mode only (11a), never native: it runs only when the stricter of the recorded mode (`<R>/exec-mode`, or `intake.md` §8 without it) and `AUDITOR_EXEC_MODE` is isolated and `probe.sh --only isolation` finds nothing readable; strict mode (`AUDITOR_STRICT`, or a `<R>/strict` file) makes native count as isolated there, as it does for `run.sh`. It creates, locks and prunes git worktrees in the repository it is given, so it gets a no-checkout clone, outside the target tree, of the copy `git-ro.sh copy` makes in `<R>`, never the client checkout. Its checks build and test the target with the caller's privileges and an open network: package registries, toolchain downloads (`uv` can fetch a Python) and any host the target's code or tests contact; a git-lfs filter in the caller's git config would contact the repository's LFS host on checkout, which the clone's `* !filter` attributes line prevents. The report records them (11b). A finding turns `[FIX-VERIFIED]` into `[FIX-INSUFFICIENT]`; any other tier keeps its tier and records the finding under Residual, and nothing else changes a tier | none needed: `/auditor:patch` steps 3 and 4 |

**FV/harness escalation ladder** (from [methodology §6](../references/audit-lifecycle/methodology.md)): manual → proptest on pure fns → **Trident stateful sequences (the primary bug-finder)** → Certora/Kani reserved for the 3-10 catastrophic invariants → MIRAI/Clippy. Skip deductive FV when the target is dominated by an untrusted CPI (the callee is a hole in the proof) — mock the boundary adversarially in Trident instead and note the abstention.

**The rule:** delegation *augments*, never replaces, the native verdict. Every finding still carries an auditor-skill verdict and (if N≥6) a filled Rule 5b gate. Tool output is evidence, not a verdict. Reference: [`references/orchestration/boundary-map.md`](../references/orchestration/boundary-map.md).

### `tob-delta-review.sh`

```bash
bash "<auditor-skill root>/scripts/tob-delta-review.sh" [--fetch] <tob-clone> <old-sha> <new-sha>
```

The maintainer's report for moving the `vendor/trailofbits` pin ([CONTRIBUTING.md §5](../CONTRIBUTING.md#bumping-vendortrailofbits)). It prints markdown to stdout: the commit count and ancestry, plugins added or removed, load surfaces (nested `.claude/`, hooks, monitors, `bin/`, MCP and LSP servers, settings, `CLAUDE.md` / `AGENTS.md`, workflow scripts), plugin manifests and the ones that declare hooks, monitors or servers inline, skill and command counts per plugin, new executables, symbolic links and gitlinks, paths git still quotes, renamed files, hosts in added script, config and Markdown lines, remote-exec patterns in added lines with continuation lines joined (a download piped to or evaluated by a shell, an interpreter or PowerShell, such as `sh -c "$(curl …)"`, `<(curl …)` or `irm … | iex`; `npx --yes`, `bunx` and `dlx`; `pip`, `pipx`, `uv`, `uvx`, `npm`, `cargo` and `deno` installs from git or a URL; `go install …@latest`), files moved unchanged between ordinary paths with the hosts and remote-exec patterns in them (every other renamed file is scanned whole in the added-line scans), all matched in any letter case, the `LICENSE`, and whether every plugin that `references/orchestration/boundary-map.md` and this page name still exists. Every call sets colour, external diff, textconv, rename detection, path quoting and signature display on the command line, so the maintainer's own config does not change the report. The scans also diff with `--text` and, on git 2.40 or later, read attributes from the empty tree, so upstream's own `.gitattributes` cannot mark a changed file binary. The report informs a human reviewer; it is not a verdict.

- **Arguments:** `<tob-clone>` is a full, non-shallow clone of `https://github.com/trailofbits/skills` (a shallow one draws a warning); `<old-sha>` and `<new-sha>` are the current and proposed pins. `--fetch` runs `git fetch origin` in the clone first.
- **Exit:** 0 report printed · 2 usage error, a missing clone directory, a failed fetch, or a commit the clone does not have.
- **Network:** only with `--fetch`. **Writes:** nothing but a temp directory, removed on exit.

---

## Surfpool economic simulation

For economic / oracle / MEV findings, a yes/no isn't proof — Rule 5b wants a dollar figure. `/auditor:economic-sim` (driven by `economic-analyst`) models capital/setup cost, extractable value, atomicity, and flash-loanable ceilings, then — when a Surfpool mainnet-fork is reachable — reproduces **deposit → manipulate → withdraw** against forked real pool state for a recorded net **P/L**.

```
/auditor:economic-sim F-003
/auditor:poc F-003 --fork     # build the executable Surfpool PoC → [PoC-SIM-REPRODUCED]
```

Enabled by the `surfpool` CLI + its MCP (keyless). The fork fetches mainnet state from its RPC datasource, which receives the program ids and account addresses the simulation reads, so the report names that provider's domain ([Rule 11b](../OUTPUT-RULES.md#11b--outside-service-disclosure)). Absent → fall back to Mollusk/LiteSVM if the logic is modelable, else `[PoC-ATTEMPTED]` with the blocker named ("surfpool CLI + MCP unreachable / fork state unavailable"). See [poc-and-patches.md](poc-and-patches.md#framework-selection).

---

## PoC/patch harness stack

The stack that turns confirmed findings into executable exploits (`/auditor:poc` → `poc-engineer`) and verified fix patches (`/auditor:patch` → `patch-engineer`), writing to `audit_<n>/poc/F-xxx/` and `audit_<n>/patches/F-xxx.patch`.

Frameworks by finding type — **Mollusk** (single-instruction logic/access-control), **LiteSVM** (multi-step lifecycle), **Surfpool** (economic, fork), **Trident/cargo-fuzz** (fuzz-discoverable) — with evidence tiers `[PoC-REPRODUCED]` > `[PoC-SIM-REPRODUCED]` > `[PoC-FUZZ-REPRODUCED]` > `[PoC-ATTEMPTED]` > `[PoC-PROSE]` and fix tiers `[FIX-VERIFIED]` > `[FIX-INSUFFICIENT]` > `[FIX-PROPOSED]`.

Toolchain gate: **`cargo build-sbf` platform-tools ≥ v1.54** (the default v1.51/cargo 1.84 bundle cannot parse the `edition2024` manifests in modern `mollusk-svm`/`litesvm` — pass `--tools-version v1.54`). Never hard-fails: any absence → `[PoC-ATTEMPTED]` + the prose PoC is kept; downgrading the evidence tier never downgrades the finding's severity.

The installation's `templates/poc/run.sh` builds every PoC: `--init <R>/poc/<ID>` makes the crate from the template, `--crate <R>/poc/<ID>` builds and runs it in the run's execution mode, and `--new-cache` makes a build cache for the engagement. `/auditor:patch` and `/auditor:re-audit` build the target itself, as it is and patched, with [`target.sh build-sbf`](scripts-runners.md#targetsh), and hand the `.so` files to `run.sh --vulnerable-so` and `--fixed-so`.

Full walkthrough — layout, framework matrix, tiers, the "executable outranks prose but prose is never removed" rule, toolchain requirements: **[poc-and-patches.md](poc-and-patches.md)**. Reference: [`references/orchestration/poc-harness.md`](../references/orchestration/poc-harness.md).

---

## Bundled scripts

<a id="working-tree-checks"></a><a id="preflightsh"></a><a id="rundirsh"></a><a id="read-only-git"></a><a id="git-rosh"></a><a id="supply-chain-recipes-scriptsrecipes"></a><a id="lock-deltash"></a><a id="web3js-historysh"></a><a id="runners"></a><a id="probesh"></a><a id="depssh"></a><a id="sastsh"></a><a id="targetsh"></a><a id="detection--response-recipes-scriptsdnr"></a><a id="snapshot-programsh"></a><a id="collectsh"></a><a id="profilesh"></a><a id="framespy"></a><a id="deltaspy"></a><a id="redactsh"></a><a id="jq-rosh"></a><a id="threat-model-collector"></a><a id="threat-modelcollectsh"></a><a id="rpc-reads"></a><a id="rpc-readsh"></a><a id="report-pdf"></a><a id="report-to-pdfsh"></a><a id="trail-of-bits-bump-review"></a>

Shell and Python scripts that ship with auditor-skill; there is nothing to build. The commands run them by absolute path from the installation, never by a `scripts/` path relative to the audited repository ([Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)); the Python ones run directly by that path, their first lines, a bash front end, running them as `python3 -I` with a `python3` found from `/` on a `PATH` without empty, relative or working-tree entries. The shell scripts run under bash 3.2 or later. Their pages give each script's arguments, exit codes, network use and outputs.

The commands pre-approve the scripts their steps run, each in the plain form [Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths) gives: the quoted path, from the working directory, with nothing in front. Each checks every argument before it acts and refuses anything outside its grammar with one line ([permissions-and-isolation.md](permissions-and-isolation.md) says which steps run without asking, and why that is safe). The examples on those pages use `<auditor-skill root>` for the directory auditor-skill is installed in; put yours in its place.

They fall into four groups, each with a page of its own:

- **Core scripts**, which every flow runs ([scripts-core.md](scripts-core.md)): [`preflight.sh`](scripts-core.md#preflightsh), the working-tree check that comes first; [`rundir.sh`](scripts-core.md#rundirsh), which makes, checks and reuses run directories; and [`git-ro.sh`](scripts-core.md#git-rosh), read-only git for checkouts the auditor did not create.
- **Audit scripts**, each run for one job ([scripts-audit.md](scripts-audit.md)): the supply-chain recipes [`lock-delta.sh`](scripts-audit.md#lock-deltash), the lockfile changes of a commit range, and [`web3js-history.sh`](scripts-audit.md#web3js-historysh), the commits that add or remove a known-bad release; [`threat-model/collect.sh`](scripts-audit.md#threat-modelcollectsh), the history collector behind `/auditor:threat-model --bootstrap`; [`rpc-read.sh`](scripts-audit.md#rpc-readsh), one read-only read from the chain; and [`report-to-pdf.sh`](scripts-audit.md#report-to-pdfsh), a PDF of a report.
- **Runners**, behind the tool steps ([scripts-runners.md](scripts-runners.md)): [`probe.sh`](scripts-runners.md#probesh), the toolchains on this machine and the isolation self-check; [`deps.sh`](scripts-runners.md#depssh), dependency audits, registry queries and the lockfile CI budget; [`sast.sh`](scripts-runners.md#sastsh), semgrep; and [`target.sh`](scripts-runners.md#targetsh), builds and tests in the run's execution mode.
- **Incident scripts**, behind `/auditor:hunt` and `/auditor:respond` ([scripts-incident.md](scripts-incident.md)): [`snapshot-program.sh`](scripts-incident.md#snapshot-programsh), which keeps a deployed program's bytes; [`collect.sh`](scripts-incident.md#collectsh), the gated transaction collector; the analysis recipes [`profile.sh`](scripts-incident.md#profilesh), [`frames.py`](scripts-incident.md#framespy) and [`deltas.py`](scripts-incident.md#deltaspy); and the helpers [`redact.sh`](scripts-incident.md#redactsh) and [`jq-ro.sh`](scripts-incident.md#jq-rosh).

The maintainer's [`tob-delta-review.sh`](#tob-delta-reviewsh), for a move of the Trail of Bits pin, is under [Trail of Bits plugins](#trail-of-bits-plugins). The PoC runner, `templates/poc/run.sh`, is on [poc-and-patches.md](poc-and-patches.md).
