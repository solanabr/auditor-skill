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
package, `audit-logs/`, with no dependencies. These are plain synchronous CLIs — no
async runtime, no network. Parsing uses `syn` with `proc-macro2`'s
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
compiles no dependency and needs no C compiler, though cargo still reads the
crates.io index once for the workspace lockfile.

A plugin update installs auditor-skill into a new versioned directory, so the
binaries have to be built again after each update. Until `audit-logs` is built
there, `/auditor:hunt`, `/auditor:respond` and `incident-responder` run the scripts
in `scripts/dnr/`.

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
reported, never echoed and never fatal; an amount or balance that is not an exact
integer makes its line malformed and is never rounded; every total is exact at any
size; a transaction several corpora hold is read once. `scripts/tests/test-audit-logs.sh`
checks the output against the scripts on every fixture in `scripts/dnr/fixtures/`,
on the crafted input-contract cases of `test-dnr.sh`, and on a generated corpus of
6,000 transactions. The scripts stay the reference implementation.

The commands run it only by its absolute path in the installation, and only when
that file exists and is executable:
`"<auditor-skill root>/tools/auditor-tools/target/release/audit-logs"`.

### Where it reads and writes

It is built to be pre-approved as one `Bash(…)` rule on its absolute path, so it
must be safe whatever arguments follow:

- Every path is relative to the working directory, has no `.`, `..` or empty
  component, passes through no symbolic link, and names a file inside an
  `incident_<n>/` run directory: a real directory, directly in the working
  directory, holding a `.gitignore` of `*` (OUTPUT-RULES.md Rule 11d). Anything else
  is refused, with exit 2, before any file is opened. Run the scripts on a corpus
  kept elsewhere, such as a `--logs` export.
- An input is opened without following a link and must still be the regular file
  that was checked. With no corpus named, `frames` and `deltas` read stdin.
- `--out <file>` writes a new temporary file beside `<file>`, created exclusively
  and never through a link, and renames it onto `<file>` once the output is whole;
  TERM, INT and HUP remove the temporary file. An existing `<file>` must be a
  regular file with no other name.
- Each option is given once, before the corpus paths.
- It refuses to run from an installation inside the working directory, or from a
  path holding a quote, `$`, a backtick, a backslash or a newline.
- It opens no network connection, runs no other program and reads no environment
  variable.

Exit: 0 done · 1 an input that cannot be read, an `--out` that cannot be written,
or a failed write · 2 usage, or a refused path. `profile` also exits 2 for an input
that is missing or not a regular file, as `profile.sh` does.

### Where it differs from the scripts

- `profile` orders the ties in its top-20 lists by byte value, as `sort` does under
  `LC_ALL=C`; under another locale `profile.sh` orders them by that locale. It pads
  the count column to 7 places, as GNU `uniq -c` does; BSD `uniq -c` pads to 4.
- `profile` prints a number in the version or `blockTime` as jq 1.7 does, from the
  literal (`1.0`, `1E+2`, every digit of a large integer). A jq built without
  decNumber prints a rounded double there instead.
- A line nested more than 256 levels deep (jq's limit) is malformed for all three
  subcommands. Of the scripts, `frames.py` and `deltas.py` read such a line up to
  Python's recursion limit, and `profile.sh` stops partway with jq's parse error.
- An integer of more than 4,300 digits makes its line malformed, as in Python 3.11
  and later (Python's default limit on reading an int). A total of any size is
  printed exactly, where `deltas.py` under Python 3.11 and later stops with a
  traceback on a total of more than 4,300 digits.
- It takes only the paths above, each option once; the scripts also take absolute
  paths, `-` for stdin, and a repeated option.

## How the auditor agents consume this

These tools are an **optional token-efficiency layer**. The audit skill degrades
gracefully — it works without them; they just save context and add memory.

- **`audit-scan` seeds Phase 0 / 0.5.** Run it once against the target codebase and
  feed the JSON to the auditor as the initial map of instructions, account
  constraints, PDAs, arithmetic, panics, and CPIs. The model then reasons about
  reachability and severity instead of grepping the tree.
- **`audit-logs` profiles an incident corpus.** `/auditor:hunt`, `/auditor:respond`
  and `incident-responder` run it on `incident_<n>/corpus*/transactions.jsonl` when
  it is built, and the scripts in `scripts/dnr/` when it is not; both give the same
  figures.
- **`audit-mem` warm-starts re-audits.** On a repeat audit of the same program,
  `warm --program-id` returns the protocol profile, recorded invariants, and any
  standing false-positive/accepted-risk rulings so prior context is not
  re-derived. `check` auto-suppresses findings previously ruled `FALSE_POSITIVE`,
  and `put-finding` + `regressions` surface anything that was fixed and has since
  regressed.
