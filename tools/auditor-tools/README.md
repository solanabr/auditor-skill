# auditor-tools

Host-side CLI tools for Solana/Anchor audits and incident response. Three
binaries:

- **`audit-scan`** — parse a codebase and emit the *risky surface* as one JSON
  object, so the LLM auditor spends tokens on judgment instead of mechanical
  enumeration.
- **`audit-mem`** — a SQLite findings store for cross-audit memory: exact dedup,
  regression detection, false-positive suppression, and warm re-audits.
- **`audit-logs`** — the detection & response analysis recipes of `scripts/dnr/`
  (`profile.sh`, `frames.py`, `deltas.py`) in one offline binary with the same
  output.

`audit-scan` and `audit-mem` are built from one library; `audit-logs` is its own
package, `audit-logs/`, with one dependency, `libc`. These are plain synchronous
CLIs — no async runtime, no network. Parsing uses `syn` with `proc-macro2`'s
`span-locations` feature, so every finding carries a real line number
(`node.span().start().line`).

## Build

Build in the auditor-skill installation, never inside a repository under audit:
cargo reads `.cargo/config*` from every parent directory of the build.

```bash
cd "<auditor-skill root>/tools/auditor-tools"
cargo build --release --locked
# binaries at target/release/audit-scan, target/release/audit-mem and target/release/audit-logs
cargo test --locked          # the tests of both packages
```

The `rusqlite` dependency uses the `bundled` feature — it compiles SQLite from
source (`cc` required), so there is no system-library dependency.
`cargo build --release --locked -p audit-logs` builds `audit-logs` alone: it
compiles one dependency, `libc` (whose build script reads the `rustc` version and
sets configuration flags), and needs no C compiler, though cargo still reads the
crates.io index for the workspace lockfile.

A plugin update installs auditor-skill into a new versioned directory, so the
binaries have to be built again after each update. Until `audit-logs` is built
there, the `auditor:dnr-analyze` fork, where `/auditor:hunt` and `/auditor:respond`
run `incident-responder`, runs the scripts in `scripts/dnr/` in its place. An update
in place, such as a `git pull` of a clone, leaves the old `audit-logs` in `target/`,
so build it again after any update: the old binary refuses to run (exit 4, below)
only when the update changed a file it was built from, that is one of the three
recipes, `scripts/lib/confine.sh`, or its own `Cargo.toml` or `src/`.

## `audit-scan`

```
audit-scan <path> [--out FILE] [--pretty]
```

Recursively walks `*.rs` files under `<path>` (skipping `target/`, `.git/`,
`node_modules/`), parses each with `syn::parse_file`, and prints one JSON object
to stdout (or to `--out FILE`). `--pretty` uses `serde_json::to_string_pretty`.
Files that fail to parse are skipped (best-effort).

### JSON schema

```jsonc
{
  "root": "string",
  "files_scanned": 0,

  // fns declared directly inside a `#[program]` module. The leading Anchor
  // `Context<..>` parameter is dropped; args are the caller-supplied
  // instruction data.
  "instructions": [
    { "name": "string", "file": "string", "line": 0,
      "args": [ { "name": "string", "ty": "string" } ] }
  ],

  // structs deriving `Accounts`, with each named field's `#[account(...)]`
  // constraints parsed out plus the raw attribute text.
  "accounts_structs": [
    { "name": "string", "file": "string", "line": 0,
      "fields": [
        { "name": "string", "ty": "string", "unchecked": false,
          "constraints": {
            "init": false, "init_if_needed": false, "mut": false, "signer": false,
            "has_one": ["string"],       // each `has_one = X`
            "seeds": ["string"],         // each element of `seeds = [ ... ]`
            "bump": false,
            "close": "string|null",      // `close = X`
            "owner": "string|null",      // `owner = X`
            "token": false,              // any `token::*` (or bare `token`)
            "associated_token": false,   // any `associated_token::*`
            "realloc": false,            // `realloc` or `realloc::*`
            "raw": "the #[account(...)] text"
          } }
      ] }
  ],

  // one entry per field carrying `seeds = [ ... ]`
  "pdas": [
    { "struct": "string", "field": "string", "seeds": ["string"],
      "file": "string", "line": 0 }
  ],

  // RAW binary/compound-assign arithmetic (NOT `.checked_*`). Every site is
  // reported — the auditor decides reachability/guardedness, not the tool.
  "arithmetic_sites": [
    { "file": "string", "line": 0,
      "op": "+|-|*|/|+=|-=|*=|/=", "snippet": "string" }
  ],

  // `.unwrap()`, `.expect(..)`, index exprs `x[y]`, and the
  // `panic!`/`unreachable!`/`unwrap!` macros.
  "panic_sites": [
    { "file": "string", "line": 0, "kind": "unwrap|expect|index|panic",
      "snippet": "string" }
  ],

  "unsafe_blocks": [ { "file": "string", "line": 0 } ],

  // calls to `invoke` / `invoke_signed`, and any use of `CpiContext`.
  "cpi_sites": [
    { "file": "string", "line": 0, "kind": "invoke|invoke_signed|CpiContext",
      "snippet": "string" }
  ],

  // field access on `remaining_accounts` (e.g. ctx.remaining_accounts.get(..)).
  "remaining_accounts_sites": [
    { "file": "string", "line": 0, "snippet": "string" }
  ],

  // every `ItemFn` and `ImplItemFn`.
  "functions": [
    { "name": "string", "file": "string", "line": 0, "pub": false }
  ]
}
```

Snippets are the pretty-printed token stream of the node, whitespace-collapsed and
truncated to ~80 characters.

### Example

```bash
audit-scan ./programs/my-program/src --pretty --out surface.json
```

## `audit-mem`

```
audit-mem [--db PATH] <subcommand>
```

`--db` defaults to `.audit-memory/audit.db` (parent directory auto-created). The
schema is created lazily on any command, so `init` is optional but explicit.

A finding's identity is
`finding_id = sha256(program_id "\n" code_signature "\n" root_cause)` (hex), which
gives exact deduplication across audits.

### Subcommands

| Subcommand | Purpose |
|---|---|
| `init` | Create the schema. |
| `put-finding` | Upsert a finding + append an occurrence. Prints `<STATUS> <finding_id>`, or `REGRESSED <finding_id>` on regression. |
| `set-status` | Set a finding's status (`FIXED` \| `OPEN` \| `ACKNOWLEDGED` \| `DISPUTED`). |
| `rule` | Record a `FALSE_POSITIVE` \| `ACCEPTED_RISK` ruling with a timestamp. |
| `check` | Print `{"suppressed":bool,"ruling":..}`; exit 0 if suppressed by a `FALSE_POSITIVE` ruling, else exit 1. |
| `regressions` | JSON list of findings with status `REGRESSED`. |
| `warm` | JSON `{profile, invariants[], open_fp_rulings[]}` — the warm-start context block for a re-audit. |

**Regression rule:** when `put-finding` re-observes a finding whose stored status
was `FIXED`, the status transitions to `REGRESSED` and the command prints
`REGRESSED <finding_id>`. Brand-new findings start `OPEN`.

### `put-finding` flags

```
--program-id <PID>   --signature <SIG>   --root-cause <RC>   --title <T>   --severity <N>
[--commit <SHA>] [--audit-n <N>] [--file <PATH>] [--line <N>] [--verdict <V>]
```

### Example lifecycle

```bash
audit-mem --db .audit-memory/audit.db init

# first observation -> "OPEN <id>"
audit-mem --db .audit-memory/audit.db put-finding \
  --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 \
  --commit c0ffee1 --audit-n audit-1 --file src/withdraw.rs --line 42 --verdict TRUE_POSITIVE

# after the dev fixes it
audit-mem set-status --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' --status FIXED

# next audit re-observes it -> "REGRESSED <id>"
audit-mem put-finding --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee3 --audit-n audit-3

# suppress a known false positive, then gate on it
audit-mem rule --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --ruling FALSE_POSITIVE --rationale 'guarded by prior require!' --by auditor
audit-mem check --program-id VaultProg... --signature 'unchecked_sub@vault.balance'
#   -> {"suppressed":true,"ruling":{...}}   (exit 0)
```

### Schema

```
findings(finding_id PK, program_id, first_seen_commit, last_seen_commit,
         severity, root_cause, code_signature, title, status,
         first_audit_n, last_audit_n)
occurrences(finding_id, audit_n, commit_sha, file, line, verdict, rule5b_json)
fp_rulings(ruling_id PK, program_id, code_signature, ruling, rationale,
           ruled_by, ruled_at, scope)
invariants(inv_id PK, program_id, protocol_class, statement, source_fn,
           cited_line, status)
protocol_profile(program_id PK, protocol_class, trust_assumptions_json,
                 oracle_set, admin_set, notes)
```

## `audit-logs`

```
audit-logs profile [--out <file>] <corpus.jsonl>...
audit-logs frames [--instructions] [--out <file>] [<corpus.jsonl>...]
audit-logs deltas lamports|tokens [--out <file>] [<corpus.jsonl>...]
```

Each subcommand prints what its script in `scripts/dnr/` prints, byte for byte:
`profile` the report of `profile.sh`, `frames` the records of `frames.py`, `deltas`
the rows of `deltas.py`, with the same `skipped …` notes on stderr and the same exit
status. It reads its input under the same input contract
(`scripts/dnr/README.md`, "Input contract"): a malformed line is counted and
reported, never echoed and never fatal; a line longer than 64 MiB is malformed, and
is read past without being kept; a line nested more than 128 levels deep,
counted on its text before it is parsed, or holding an integer literal of more than
20 digits or `-0`, is malformed; a lamport balance, the fee or a token amount that
is not a u64 value (0 to 2^64 − 1) makes its line malformed and is never rounded;
every total is exact; a transaction several corpora hold is read once. A key,
program id or string version holding a character of the contract's fixed list (the
C0 and C1 controls, DEL, the line and paragraph separators, the bidirectional
controls, and the code points Unicode marks default-ignorable, U+00AD and
U+E0000–U+E0FFF among them) is malformed, and no subcommand prints such a character
raw: `frames` and `deltas` escape it, and so does `profile` in a version that is not
a string. `deltas` prints a balance whose index has no account key as `#<index>`,
and a token balance with no `accountIndex` as a row of its own, `#?`, and counts
each kind on stderr; neither is merged with another account.
`scripts/tests/test-audit-logs.sh` checks the output against the scripts on every
fixture in `scripts/dnr/fixtures/`, on the crafted input-contract cases of
`test-dnr.sh`, and on a generated corpus of 6,000 transactions. The scripts stay the
reference implementation.

The `auditor:dnr-analyze` fork runs it by its absolute path in the installation,
`"<auditor-skill root>/tools/auditor-tools/target/release/audit-logs"`, and runs the
script in its place when it exits 126 or 127 (not built, or not runnable), or 4 (a
stale build), or is stopped by a signal.

### A stale build

`audit-logs` carries a copy of the files it was built from, read with
`include_bytes!` from the installation it was built in: the three recipes it mirrors
(`scripts/dnr/profile.sh`, `frames.py` and `deltas.py`), `scripts/lib/confine.sh`,
which `profile.sh` sources, and its own `Cargo.toml` and `src/*.rs`. Once it has
checked its installation path (below), and before it reads any argument, it compares
them with the installed files; when one differs, or cannot be read, it writes
nothing and exits 4 with one line:

```
audit-logs: stale build: <file> is not the one it was built from; rebuild it (cargo build --release --locked in tools/auditor-tools) or run the scripts
```

No recipe exits 4, so a caller that sees it runs the scripts. An update that changes
none of those files leaves the old binary running: build it again after every
update all the same.

### Where it reads and writes

It is built to be pre-approved as one `Bash(…)` rule on its absolute path, so it
must be safe whatever arguments follow. It takes and refuses the same paths as the
three recipes, in the same words (`scripts/dnr/README.md`, "Input contract"), and
`test-audit-logs.sh` runs every case of
`scripts/tests/fixtures/audit-logs/hostile-args.txt` with both:

- Every path is relative to the working directory, has no `.`, `..` or empty
  component, passes through no symbolic link (each name on the way is checked with
  `lstat`), and names a file inside an `incident_<n>/` run directory: a real
  directory, directly in the working directory, holding a `.gitignore` of `*`
  (OUTPUT-RULES.md Rule 11d). An input must be a regular file with one name: a
  second name (a hard link) could be a file outside the run directory. Anything
  else is refused, with exit 2, before any input is read. Copy a corpus kept
  elsewhere, such as a `--logs` export, into the run directory first.
- An input is opened through each directory on its way from the working directory
  (`openat`, never following a link) and must still be the regular file with one
  name that was checked. With no corpus named, `frames` and `deltas` read stdin.
- `--out <file>` names a new file directly in the run directory, `<name>.jsonl`,
  `.tsv` or `.txt`; an output never replaces a file, so an existing `<file>` is
  refused. The run directory is opened once, without following a link, and must be
  the directory checked; the temporary file is made in it
  (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600), linked to `<file>` once the output is
  whole (`linkat`, which never replaces a file) and removed (`unlinkat`), all
  through that descriptor, so a run directory moved or replaced by a link mid-run
  never moves the output elsewhere. TERM, INT and HUP remove the temporary file
  before it exits with 128 plus the signal, unless the caller ignores the signal;
  they are held off while the file is made, linked and removed. `profile` checks
  `--out` again and opens its run directory only once its report is whole, as
  `profile.sh` does.
- Each option is given once, before the corpus paths.
- It refuses to run from an installation inside the working directory, or from a
  path, as it was invoked or with its links resolved, holding a quote, `$`, a
  backtick, a backslash or a control character.
- It opens no network connection, runs no other program and reads no environment
  variable. It does not ask git whether it tracks the run directory, and on a
  case-insensitive filesystem a directory named `INCIDENT_1` is read as
  `incident_1/`; `scripts/rundir.sh` makes and checks run directories.

Exit: 0 done · 1 an input that cannot be read, an `--out` that cannot be written,
or a failed write · 2 usage, or a refused path · 4 a stale build.

### Where it differs from the scripts

- `profile` pads the count column to 7 places, as GNU `uniq -c` does; BSD `uniq -c`
  pads to 4. Both count and order keys byte by byte, as `profile.sh` runs `sort` and
  `uniq` under `LC_ALL=C`, so the counts and the order of ties are the same under
  every locale.
- `profile` prints a number in the version or `blockTime` as jq 1.7 does, from the
  literal (`1.0`, `1E+2`, every digit of a large integer), within jq's exponent
  limits (`0e1000000000` as `0E+999999999`). A jq built without decNumber prints a
  rounded double there instead.
- With stdout closed, `audit-logs` writes to `/dev/null` and exits 0, where the
  scripts exit 1. When the reader of a pipe closes it early, `audit-logs` exits 1
  (`Broken pipe`), or 0 when its output was all written before, where `frames.py`
  and `deltas.py` exit 120 and `profile.sh` 141. Read the exit status with stdout
  on a file or a pipe read to the end, or use `--out`.
- With stdin a directory, Python stops as it starts, so the three scripts exit 1
  even when their inputs are named; `audit-logs` reads stdin only when no corpus is
  named, and then exits 1 too.
- `profile.sh` runs `jq` and `python3` and keeps its report in a private temp
  directory, so it alone refuses to run (exit 2) when `TMPDIR` lies inside the
  working directory, when no `PATH` entry is left outside it, or when the working
  directory's path holds a control character, and stops when `TMPDIR` does not
  exist (exit 1) or `jq` or `python3` is missing (exit 3). `audit-logs` needs none
  of these.

## How the auditor agents consume this

These tools are an **optional token-efficiency layer**. The audit skill degrades
gracefully — it works without them; they just save context and add memory.

- **`audit-scan` seeds Phase 0 / 0.5.** Run it once against the target codebase and
  feed the JSON to the auditor as the initial map of instructions, account
  constraints, PDAs, arithmetic, panics, and CPIs. The model then reasons about
  reachability and severity instead of grepping the tree.
- **`audit-logs` profiles an incident corpus.** In the `auditor:dnr-analyze` fork,
  where `/auditor:hunt` and `/auditor:respond` run `incident-responder`, it runs first
  on `incident_<n>/corpus*/transactions.jsonl`, and the scripts in `scripts/dnr/` run
  in its place when it is not built or reports a stale build; both give the same
  figures.
- **`audit-mem` warm-starts re-audits.** On a repeat audit of the same program,
  `warm --program-id` returns the protocol profile, recorded invariants, and any
  standing false-positive/accepted-risk rulings so prior context is not
  re-derived. `check` auto-suppresses findings previously ruled `FALSE_POSITIVE`,
  and `put-finding` + `regressions` surface anything that was fixed and has since
  regressed.
