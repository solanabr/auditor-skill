# Audit scripts: history recipes, the threat-model collector, RPC reads and the PDF

The scripts the audit flows run for one job each: two recipes that read the supply-chain history of the repository, the history collector behind `/auditor:threat-model --bootstrap`, a read-only RPC read, and the PDF renderer. This page gives their arguments, exit codes, network use and outputs. Back to the [docs index](README.md).

How every bundled script is run and checked, and the other script pages: [Bundled scripts](power-tools.md#bundled-scripts). Which of them run without asking, and why that is safe: [permissions-and-isolation.md](permissions-and-isolation.md#what-runs-without-asking).

Contents: [`lock-delta.sh`](#lock-deltash) · [`web3js-history.sh`](#web3js-historysh) · [`threat-model/collect.sh`](#threat-modelcollectsh) · [`rpc-read.sh`](#rpc-readsh) · [`report-to-pdf.sh`](#report-to-pdfsh)

## Supply-chain recipes (`scripts/recipes/`)

Two history checks of the supply-chain walk: the lockfile hints of checklist 11 §11.11, and the history half of the known-bad release check (FULL-AUDIT Step 3.2, KV-077 Step 2). `/auditor:audit`, `/auditor:audit-cycle`, `/auditor:audit-assist`, `/auditor:diff-audit` and `/auditor:re-audit` pre-approve both, as does the skill asked in plain words; `/auditor:quick-scan` pre-approves `web3js-history.sh` only.

Both read committed content only, never the work tree, through the hardened git call of `scripts/lib/confine.sh` that `git-ro.sh` uses. They take the repository as `git-ro.sh` does: `--repo <dir>` (`.` by default, which in default mode is the enclosing repository in a session below its top level, in a folder that holds tracked files, whose lockfiles they then read whole (`:(top)` pathspecs, since a workspace keeps its lockfile at the top)), or `--git-dir <R>/src.git` for a copy `git-ro.sh copy` made. In a partial clone each prints a note under its own name first and fetches nothing, so a missing object fails; in a shallow clone a note says the history before the boundary is missing. Each diff runs with `--text`, three lines of context and the `a/` and `b/` prefixes, whatever the checkout's config sets, so a committed `.gitattributes` that marks a lockfile binary hides nothing. Every control character but tab and newline prints as `?`, and standard input is never read.

### `lock-delta.sh`

```bash
# examples of what you type; <auditor-skill root> is where auditor-skill is installed
"<auditor-skill root>/scripts/recipes/lock-delta.sh" cargo main..HEAD
"<auditor-skill root>/scripts/recipes/lock-delta.sh" --git-dir audit_1/src.git npm v1.2.0..v1.3.0
"<auditor-skill root>/scripts/recipes/lock-delta.sh" --run audit_1 set main..HEAD
```

Each version, source and checksum line that changed in the lockfiles of one kind between two commits, with the name of its package, below each file's `+++ b/<path>` line (`+++ /dev/null` for a file the range deletes).

- **`npm`:** `package-lock.json`, `npm-shrinkwrap.json` and `yarn.lock` (v1 and berry): each changed `version`, `resolved`, `resolution`, `integrity` or `checksum` line after the key of its entry, `?` for a key outside the hunk. **`bun`:** the text `bun.lock`: each changed entry as `-` or `+` and `<name>@<version>`. **`cargo`:** `Cargo.lock`: each changed `version`, `source` or `checksum` line after its package name.
- **`set`**, for checklist 11 §11.11's CI budget: the name@version set difference of every `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1), `bun.lock`, `Cargo.lock`, `uv.lock` and `poetry.lock` the range changes, each read whole at both commits with the manifest beside it at `<head>`. One row per new name@version, and per version whose checksum changed, goes to `<R>/deps/lock-set-<n>.tsv`: its ecosystem, lockfile, name, old and new version, old and new source (`public`, `git`, `url`, `file`, `registry:<host>`, `unnamed` for an npm entry with no resolved URL, or `bundled`; a bun.lock entry with no registry takes the one the committed bunfig.toml or .npmrc beside it names) and its marks (`direct`, `pin`, `key`, `install`, `source-change`, `integrity`, `new-dep=<names>`, `url-mismatch`, `close=<name>`, `known-bad`); each copy of a name@version is kept apart, so a second copy from another source or with another checksum is a row. It prints a summary and the rows to read first, and the file last. A `pnpm-lock.yaml`, a yarn berry `yarn.lock`, a `bun.lockb` and a `go.sum` are named as not compared, with the reason; a lockfile of a kind it reads that it cannot compare (a link, a submodule, over 64 MiB, text it cannot read, or a manifest beside it it cannot read) is too, and `set` then exits 3 with the table kept.
- **Arguments:** `[--repo <dir> | --git-dir <R>/src.git] npm|bun|cargo <base>..<head>`, or `[--repo <dir> | --git-dir <R>/src.git] --run <R> set <base>..<head>`, where `<base>` and `<head>` name commits: letters, digits and `._/~^+-`, starting with a letter or a digit, with no `..`, at most 255 bytes each, and `<R>` is the run directory, `audit_<n>` or `incident_<n>`.
- **Exit:** 0 done, whether or not a line printed · 3 `set` could not compute, compare or keep its table · 64 refused, with one line, `lock-delta: refused: <reason>` · git's own status when git fails (128: a revision it cannot find). **Network:** none. **Writes:** nothing, but `set`'s table in the run directory. **Needs:** git, and python3 for `set`.

### `web3js-history.sh`

```bash
# examples of what you type; <auditor-skill root> is where auditor-skill is installed
"<auditor-skill root>/scripts/recipes/web3js-history.sh"
"<auditor-skill root>/scripts/recipes/web3js-history.sh" --git-dir audit_1/src.git
```

The commits, on every branch, that add or remove the hijacked `@solana/web3.js` 1.95.6 or 1.95.7, or axios 1.14.1 or 0.30.4, in a manifest or a lockfile. Two searches run over every branch, merge commits (against their first parent) and the root commit, each under its own heading:

- **`== single-line form`:** each commit that adds or removes a line naming one of those releases, as a resolved URL, a pnpm, yarn or bun key, or an exact pin, printed as `<commit> <subject>`.
- **`== key-line form`:** a `package-lock.json` or `npm-shrinkwrap.json` written without `resolved` fields names a package only on its entry's key line, with the version on a line below it; each such version line added, removed, or kept under a key that changed, printed as `<commit> <a/ or b/ path> <line>`.

Nothing under a heading means none was found. Another package at one of those versions is not reported.

- **Arguments:** `[--repo <dir> | --git-dir <R>/src.git]`.
- **Exit:** 0 both searches ran, whether or not a line printed · 64 refused, with one line, `web3js-history: refused: <reason>` · git's own status when git fails, once both searches have run. **Network:** none. **Writes:** nothing. **Needs:** git.

## `threat-model/collect.sh`

```bash
"<auditor-skill root>/scripts/threat-model/collect.sh" --detect --repo <dir> --out audit_<n>/bootstrap [--pin <rev>]
"<auditor-skill root>/scripts/threat-model/collect.sh" --offline --repo <dir> --out audit_<n>/bootstrap [options]
"<auditor-skill root>/scripts/threat-model/collect.sh" --network --repo <dir> --out audit_<n>/bootstrap [options]
```

The read-only collector behind `/auditor:threat-model --bootstrap` ([method and output contract](../references/audit-lifecycle/threat-model-bootstrap.md)). It gathers commits whose message matches security keywords, reverts, account-guard lines that were removed or quietly added, churn, an optional fork-parent comparison, provenance signals, prior-vulnerability inputs and the `audit-mem` warm block. It never checks out, builds, runs or modifies the target, and it runs git with the Rule 11c hardening (the hardened call in `scripts/lib/confine.sh`: no environment of the caller's, system and global config dropped, no pager, fsmonitor, hooks, signature helpers, textconv, external diff or transport). Run it directly by its path, from the working directory. `/auditor:threat-model`, `/auditor:audit-cycle` and `/auditor:audit-assist` pre-approve its `--detect` and `--offline` forms; `--network` always asks.

The mode is the first argument; a mode anywhere else, as in the older `--repo … --out … --offline`, is refused:

| Mode | Meaning |
|------|---------|
| `--detect` | evaluate triggers T3 and T4 only, print them and exit; writes nothing |
| `--offline` | collect without the network: `--parent` and `--vulns` URLs are recorded, not fetched |
| `--network` | collect, fetching the `https://` URLs given in `--parent` and `--vulns`; the only mode that reads a `--repo`, `--parent` or `--vulns` outside the working directory or through a symbolic link, except the repository a session below its top level lies in (`--repo .`) |

In `--detect` and `--offline`, `--repo` and a local `--parent` or `--vulns` are relative to the working directory, with no `.` or `..` component, and reach nothing through a symbolic link. A repository there is checked as `git-ro.sh` checks one ([Rule 11c](../OUTPUT-RULES.md#11c--untrusted-git-checkouts)): in strict mode its git directory must lie inside the working directory, with no link in it and no `objects/info/alternates` or `info/grafts`; default mode accepts a git directory outside it that ties back to the tree, as `git-ro.sh` reads one, and a link in a hooks directory, and reads alternates and grafts with a note. A git directory outside that nothing ties back, git's own `--separate-git-dir` layout among them, is refused (exit 2) here, where `git-ro.sh` only notes it. A path that fails is refused with a pointer to `--network`, in both modes: a `--vulns` file is copied into the run directory, and a pre-approved read must not copy a file such as a key from outside the tree into the run folder (the commands pre-approve `--detect` and `--offline`, never `--network`). To use a prior report from elsewhere, copy it into `audit_<n>/` first. In default mode, `--repo .` in a session started below the top level of a repository, in a folder that holds tracked files, reads that repository as git does from the working directory: pathspecs and printed paths are relative to it, and changes and files outside it are left out. Strict mode refuses that session. `--network` reads such a repository: its git directory is searched for named pipes and devices git would open, but not where a link to a directory there leads, nor the object directories `objects/info/alternates` names, so a read that meets one there waits until you stop the run.

| Flag | Meaning |
|------|---------|
| `--repo <dir>` | the target (required): the top level of its own repository, or a bare repository; in default mode also `.` below a top level (above). Anything else exits 3, and so, in strict mode, does a partial clone or a target whose config git cannot read; default mode reads those for what they hold, with a `collect.sh: note:` line, since its git fetches nothing, so history and contents may be incomplete |
| `--out audit_<n>/bootstrap` | the output directory (required), in the run directory `audit_<n>` directly in the working directory: a real directory holding no symbolic link that leads out of it or to nothing (in strict mode, none), untracked in any letter case (in default mode, one git cannot place passes on its `.gitignore`), with a `.gitignore` holding exactly `*` (`rundir.sh new audit` makes one). `bootstrap/` is made when missing. Any other `--out`, or a run directory that fails these checks or that `find`, or in strict mode git, cannot check, exits 2. `--detect` writes nothing, so its run directory need not exist yet |
| `--pin <rev>` | the commit to analyse (default `HEAD`); only its ancestry is mined. Exit 3 if it does not resolve; a value that starts with `-` exits 2 |
| `--paths <pathspec>` | target pathspec, repeatable (default `programs/*.rs` when the commit has a `programs/` directory, else `*.rs`) |
| `--parent <https-url\|dir>` | the fork parent: an `https://` URL, cloned bare into a temp directory that is deleted on exit (`--network` only), or the top level of a local repository. A local path that is not a top level, is a partial clone, or has a config git cannot read is recorded as not used, R5 prints `NOT FOUND`, and the run goes on |
| `--parent-paths <spec>` | parent pathspec, repeatable (default: the same rule, applied to the parent) |
| `--import <rev>` | the target commit that brought the parent's code in (default: the root commit). Pass it when the code arrived after the root commit (a README-only first commit, say), or R5 reports `NOT FOUND`. It must resolve to a commit, else the run exits 2 |
| `--vulns <file\|https-url>` | a prior-vulnerability input, repeatable: PDF, Markdown, text, CSV, JSON, or an `INCIDENTS.json` (allowlisted fields only) |
| `--program-id <id>` | the program id for R8's `audit-mem warm` (needs the built tool and `--audit-mem-db`); at most 200 characters |
| `--audit-mem-db <path>` | the audit-mem store R8 reads: `.audit-memory/audit.db` or `audit_<n>/audit-mem.db`, its `audit_<n>` passing the same checks as `--out`'s run directory, read from the working directory with `audit-mem warm`. There is no default: without it no store is read, and the collector never looks in the target tree. Pass only a store that passes the Rule 11d check |
| `--keywords <ere>` | extra commit-message keywords, as an ERE alternation such as `drain\|bypass`; at most 200 characters |
| `--cap <n>` | rows per section before `TRUNCATED` (default 60); re-run with a higher value when a section is truncated |
| `--small <n>` | changed-line ceiling for an `ADDED-QUIET` (quiet-fix) commit (default 40) |
| `--fix-ceiling <n>` | changed-line ceiling for the `ADDED` rows of a keyword commit (default 300) |
| `-h`, `--help` | print the usage header, flags and exit statuses included (as the only argument) |

Each option is given at most once, except the repeatable `--paths`, `--parent-paths` and `--vulns`; a word after an option that takes a value is that value. `--cap`, `--small` and `--fix-ceiling` take 0 to 10,000, and no value may hold a control character or exceed 1,024 bytes.

- **Exit:** 0 done (a section may print `NOT FOUND`) · 2 refused, with one line, `collect.sh: refused: <reason>`: a mode that is not first, an unknown or repeated option, a value out of bounds, a path the mode does not take, an `--import` that is not a commit, a run directory that fails the checks above, that `find` cannot check or, in strict mode, that git cannot check, a `TMPDIR` inside the working directory, a disclosure that cannot be recorded, or an output that cannot be written · 3 `--repo` is not the top level of a git repository git can read (or a bare repository), the pin does not resolve, or, in strict mode, the target is a partial clone or git cannot read its config (default mode notes either and goes on).
- **Network:** only in `--network`, for an `https://` URL passed in `--parent` (a bare clone without submodules, credential helpers or other protocols) or in `--vulns` (curl, https only through redirects too, with 60-second and 50 MB limits). Each URL is first recorded as a row of `audit_<n>/disclosures.tsv`, with userinfo, query string and fragment shown as `***`. Never for a URL found in target content. Every git call on the target or a local parent runs with lazy fetching off and an empty transport allowlist (`GIT_ALLOW_PROTOCOL`, which the repository's config cannot widen), and the parent's https clone allows https alone (`-c protocol.allow=never -c protocol.https.allow=always`), so no remote the target configures is contacted. URLs in `history.md`, `inputs.tsv` and stderr show userinfo, query string and fragment as `***`.
- **Writes:** the output is built in a temporary directory outside the working directory and copied into `<out>` at the end, once the run directory is checked again; every file is created anew and written through the descriptor opened at creation. A re-run first removes the outputs of the run before (`history.md`, `inputs.tsv`, `audit-mem-warm.json`, and `inputs/` and `diffs/` where an `inputs.tsv` marks them). In `<out>`:
  - `history.md`: sections R0 to R8; a "Shallow clone" line when the target is shallow, and a "Partial clone" line when default mode read one; and which git settings are pinned.
  - `inputs.tsv`: the manifest of every input.
  - `inputs/`: converted or copied inputs.
  - `diffs/`: `target-<sha>.diff` and `parent-<sha>.diff` for up to 20 flagged commits each. Each holds the full id, the date, the subject and up to 20 body lines, then the diff limited to the files its rows name, up to 400 lines. Every cut ends in a `TRUNCATED (…)` line naming `git-ro.sh`'s `show` for the rest: `"<auditor-skill root>/scripts/git-ro.sh" --repo '<dir>' show <full id> -- '<path>' …`, run from the working directory, with `--repo` naming the repository there (none for `.`), each path escaped like other target text and single-quoted (`--no-patch` and no path for a cut message). In a session below the repository's top level, each path is relative to the working directory, as the call reads it there. A repository read in `--network` from outside the working directory is read from a copy made inside it.
  - With `--program-id` and `--audit-mem-db`, `audit-mem-warm.json`.
  - Target text in `history.md` and `inputs.tsv` shows TAB, LF and CR as `\t`, `\n` and `\r`, and other control characters as `?`. Values over 500 characters are cut with `...`.
  - T4, R6 and R7 read each `incident_*` directory at the top of the target, its name in any letter case. An `incident_*/INCIDENTS.json` that is a symbolic link, sits in a linked directory, or lies in a tracked `incident_*` directory is not read; `inputs.tsv` records it as skipped. No symbolic link in the target's tree is followed, so what one points at is never tested: T4 counts nothing through one, and R6 and `inputs.tsv` name one as a link, not followed. In `--network`, neither is a local `--vulns` path that is a symbolic link or that reaches its file through a directory link inside the target tree. An `incidents` value that is not an array gives an empty extract and a "malformed" status.
  - `--detect` prints `T3 yes|no <signals>` and `T4 yes|no <signals>` to stdout.
- **Needs:** git; `jq` or `python3` for JSON inputs, `pdftotext` to convert PDFs, `curl` for `--vulns` URLs. The environment variable `TM_JSON_TOOL=jq|python3|none` pins the JSON tool; the self-test uses it.

## `rpc-read.sh`

```bash
"<auditor-skill root>/scripts/rpc-read.sh" account <address> [--run <R>] [--cluster mainnet-beta|devnet|testnet]
"<auditor-skill root>/scripts/rpc-read.sh" confirm <signature> [--run <R>] [--cluster mainnet-beta|devnet|testnet]
"<auditor-skill root>/scripts/rpc-read.sh" program-show <program_id> [--run <R>] [--cluster mainnet-beta|devnet|testnet]
```

One read-only read from the chain through the `solana` CLI: an account's current value (`getAccountInfo`), one transaction, or a program's metadata such as its upgrade authority. The CLI runs on a throwaway config in a private temp directory, the endpoint in its `json_rpc_url` and a keypair path that names no file, and the read runs only when `solana config get keypair` reports that path back. Run it directly by its path, from the working directory; the commands that read from RPC pre-approve it.

- **Endpoint:** `$RPC_URL` from the environment, never an argument; with `--cluster`, one of the public endpoints fixed in the script: `https://api.mainnet-beta.solana.com`, `https://api.devnet.solana.com` or `https://api.testnet.solana.com`.
- **Reads:** `account` runs `solana account <address> --lamports --output-file <temp file>` and prints the address, balance in lamports, owner, executable flag and rent epoch, then the data's length and sha256; the data itself is never printed. `confirm` runs `solana confirm -v --output json <signature>` and prints the status and the transaction as JSON, which never holds the CLI's error text (solana CLI 2.2.x and older spell the endpoint there, key included, as fields no URL rule matches) nor the endpoint and keypair path the text form starts with; a finalized transaction whose details the CLI could not read is a failed read. `program-show` runs `solana program show <id>`, or `program-v4 show` for a loader-v4 program, each with a fixed authority so the CLI never looks for a signer, and the output must name the id as its Program Id. The CLI's output and errors pass through `redact.sh`, since its text can name the endpoint, key included. The CLI and `python3` run from `/`, so no version file in the working directory (a `.tool-versions` or `.python-version` an asdf, mise or pyenv shim reads) picks the binary. Every control character in what is printed shows as `?`, except TAB and LF.
- **Arguments:** an address or program id is base58 that decodes to 32 bytes, a signature to 64, so none can name a keypair file, a path or an option. `--run <R>` is a run directory, `audit_<n>` or `incident_<n>`, checked as `rundir.sh check` checks one. Each option is given at most once.
- **Exit:** 0 done · 1 the CLI ran and the read failed (its error, through `redact.sh`, on stderr; for `confirm`, also a finalized transaction without its details) · 3 a blocker: no `solana` CLI or `python3`, no private temp directory or a `TMPDIR` inside the working directory, the CLI did not take the config, a disclosure row or a kept file that could not be written, show output naming another Program Id, or a `confirm` answer that is not a JSON object · 64 refused, with one line, `rpc-read: refused: <reason>`, before the CLI runs.
- **Network:** the read-only calls of that one CLI command, to the endpoint above.
- **Writes:** with `--run R`, one row of `R/disclosures.tsv` before the CLI contacts the endpoint (the domain and the id), and in `R/rpc/`, made when missing, what was printed as `<read>-<id>.txt` and an account's data as `account-<address>.data` (`<read>-<id>-2.txt` and so on once a name is taken), each file created anew. Without `--run` nothing is written, and stderr names the service and what it received, for the report's Rule 11b list.
- **Needs:** the `solana` CLI and `python3` (the id check, the hash and the confirm answer's check, as `python3 -I`).

## `report-to-pdf.sh`

```bash
"<auditor-skill root>/scripts/report-to-pdf.sh" [audit_<n>/REPORT.md]
```

A best-effort PDF of a report; the Markdown stays the deliverable. The input is `audit_<n>/REPORT.md`, `audit_<n>/RE-AUDIT.md`, `audit_<n>/PR-REPORT.md` or `incident_<n>/INCIDENT_REPORT.md`, relative to the working directory, in a run directory that passes `rundir.sh check`, and a regular file with one link; with no argument it takes the newest `audit_*/REPORT.md`. The PDF is written beside it, `.md` swapped for `.pdf`. Run it directly by its path, from the working directory; `/auditor:audit-cycle` pre-approves it.

- **Rendering:** the report is copied into a private temp directory outside the working directory and rendered there with `pandoc --sandbox -f markdown-raw_tex-raw_attribute-yaml_metadata_block --lua-filter "<auditor-skill root>/scripts/pdf/no-remote.lua" --pdf-engine=<xelatex, lualatex or pdflatex, the first found> --pdf-engine-opt=-no-shell-escape`. `--sandbox` keeps pandoc from reading any file but its input and from fetching anything. No YAML block in the report is read as metadata, so one quoted from the audited repo prints as text instead of filling the template's variables (the whole body, and font and option slots that reach the engine as TeX, or as Lua under lualatex). The filter turns every image into its alt text, drops every raw block and raw inline, shows math as code, in the metadata too, and leaves every element its identifier and classes but no key=value attribute (the LaTeX writer passes some, such as a figure's `latex-placement`, to the engine as written), so no remote image is fetched and no text of the report reaches the TeX engine as TeX. Raw HTML is still parsed, so the report templates' HTML comments drop out instead of printing; raw HTML that runs across a blank line prints as text instead, since an unclosed `<!--` in quoted text runs to the next `-->`, findings and all (one comment whose `<!--` and `-->` stand on lines of their own, as the templates' long comments do, still drops). The engine runs with kpathsea's paranoid `openin_any=p` and `openout_any=p` and with `shell_escape=f`, and pandoc sets its own temp directory. pandoc, and the engine through it, see none of your environment but `PATH` and `HOME`, so no `RPC_URL` or other key, and no `TEXMFOUTPUT`, reaches them. A TeX setup made only through environment variables (`TEXMFHOME`, `TEXINPUTS`, `TEXMFCNF`) does not reach the engine either, so a render that needs one is skipped. The PDF goes into a new file beside the report and is renamed into place; a PDF already there is replaced only when it is a regular file with one link.
- **Exit:** 0 rendered, or skipped with a message: no report, no pandoc, a pandoc older than 2.15 (no `--sandbox`), no engine, or a render that failed · 2 refused, with one line, `report-to-pdf: refused: <reason>`: another path, two arguments, a run directory that fails the checks, a report that is not a regular file with one link, a PDF in the way that is not one, or a `TMPDIR` inside the working directory.
- **Network:** none. **Writes:** the PDF beside the report.
- **Needs:** pandoc 2.15 or later and a TeX engine, both optional.
