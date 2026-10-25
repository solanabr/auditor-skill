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
`span-locations` feature, so every finding carries a real line number (the line of
its first token).

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

### The contract marker

`audit-scan` and `audit-mem` keep a contract, the confinement described below, and
mark it with `--contract=1`. Every rule that pre-approves them names the marker,
right after the binary's path for `audit-scan` (`audit-scan --contract=1 <dir> …`)
and right after the subcommand for `audit-mem` (`audit-mem warm --contract=1 …`), and
so does every call the corpus makes. The marker changes nothing: given once in its
place, the call runs as it does without it. Any other word that starts with
`--contract` is refused.

A build made before the contract, which writes wherever `--db` and `--out` say,
refuses the marker with a usage error and exit 2 before it does anything (`error:
unexpected argument '--contract' found`, or `error: unrecognized subcommand` for
`profile` and `invariant`, which it lacks), so a rule that names the marker never
runs it. An installation updated in place, such as a `git pull` of a clone, keeps its
old binaries in `target/release/` until they are built again, and the calls fail
until then. Rebuild:

```bash
cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release --locked
```

A later contract would take `--contract=2`, which this build refuses with a line that
says to rebuild it.

## `audit-scan`

```
audit-scan [--contract=1] <dir> [--out <run dir>/prescan.json | <run dir>/prescan-<slug>.json] [--pretty]
```

Recursively walks the `*.rs` files under `<dir>`, parses each as
`syn::parse_file` does, and prints one JSON object to stdout (or writes it to
`--out`). `--pretty` uses `serde_json::to_string_pretty`. The walk skips `target/`,
`.git/` and `node_modules/` below `<dir>`, and, when `<dir>` is `.`, the run
directories and `.audit-memory/`, which hold an audit's own output. It follows no
symbolic link, goes no deeper than 128 directories below `<dir>`, and parses only
regular files with one name, of at most 4 MiB, in byte order of their names; every
link it meets, every directory it does not enter for its depth, and every `*.rs`
file it does not parse (not a regular file, a second name, larger than 4 MiB,
unreadable, not UTF-8, nested or chained too deeply, or not Rust that `syn`
parses), is listed in `skipped` with the reason.

syn's parser, and the walk of its tree, recurse once for each level the tree
nests, so a file is lexed first (`proc-macro2`'s lexer does not recurse) and is not
parsed, but listed as `nested or chained too deeply to parse`, when its groups
(`(`, `[`, `{`) nest more than 256 deep or it holds a chain of more than 20,000
tokens: the tokens since the last `;`, the last `,` outside an unclosed `<`, an
inner attribute, or the start of an item or statement after a block, counted on
through every group they are nested in. The scan runs on a stack of 512 MiB (64 MiB
where the system grants no more); the deepest tree measured that those limits let
through, 20,000 nested `break`, needs more than 64 MiB and less than 128. Real code
stays far below the limits: in 16,000 files of published crates and the Rust
standard library, the longest chain is 1,714 tokens and the deepest nesting 44
groups.

### Where it reads and writes

It is built to be pre-approved as one `Bash(…)` rule on its absolute path and the
contract marker (`"<root>/tools/auditor-tools/target/release/audit-scan" --contract=1 *`),
so it must be safe whatever arguments follow. Its rules are those of
`scripts/lib/confine.sh`, in `src/confine.rs`, and
`scripts/tests/test-auditor-tools.sh` runs every case of
`scripts/tests/fixtures/audit-scan/cases.txt`:

- `<dir>` is `.` or a relative path inside the working directory: at most 1024
  bytes, no control character, no leading `-` or `~`, no empty, `.` or `..`
  component once one leading `./` is dropped, no symbolic link on the way (each name
  is checked with `lstat`), resolving inside the working directory.
- `--out` is `prescan.json`, or `prescan-<slug>.json` with a slug of 1 to 32 of
  `a-z`, `0-9` and `-`, directly in a run directory, `audit_<n>/` or `incident_<n>/`,
  that passes `scripts/rundir.sh check`: a real directory in the working directory,
  holding no symbolic link, tracked by no repository in any letter case, with a
  `.gitignore` of exactly `*`. The file is made new (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode
  0600) through the run directory, opened once without following a link; a file
  already there is replaced only when it is a regular file with one name, as
  audit-scan's own earlier output is.
- `--contract=1` comes first, or not at all. Each option is given once, `--out
  <file>` or `--out=<file>`; the word after `--out` is its value whatever it looks
  like. Any other word that starts with `-` is refused.
- It asks git whether a run directory is tracked as confine.sh's `hgit` asks it: git
  from a `PATH` with every entry inside the working directory removed, with an
  environment of its own and the repository's config pinned off. When git cannot
  answer, `--out` is refused; with no `--out`, git is not run.
- It refuses to run from an installation inside the working directory, or from a
  path, as it was invoked or with its links resolved, holding a quote, `$`, a
  backtick, a backslash or a control character, and in a working directory whose
  path holds a control character.
- The walk opens each directory from its parent's descriptor, and each file from
  its directory's, never following a link (`openat` with `O_NOFOLLOW`), so a
  directory swapped for a link while the walk runs is not entered.
- It opens no network connection and runs no other program. A control,
  bidirectional or invisible character in a name or snippet is written as a `\u`
  escape.

Exit: 0 done · 1 the output cannot be written · 2 refused, with one stderr line,
`audit-scan: refused: <reason>`.

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
  ],

  // every symbolic link the walk did not follow, every directory it did not
  // enter for its depth, and every `*.rs` file it did not parse, with why.
  "skipped": [
    { "file": "string", "reason": "string" }
  ]
}
```

A snippet is the node's tokens as `proc-macro2` prints the file's own (a space
between two tokens unless the source joins punctuation, as in `::<` or `?;`),
whitespace collapsed and cut after 80 characters with `...`; only what is kept is
rendered, so a long chain costs no more than a short one.

### Example

```bash
audit-scan --contract=1 ./programs/my-program/src --pretty --out audit_1/prescan.json
```

## `audit-mem`

```
audit-mem <subcommand> [--contract=1] [--db <store>] [options]
```

The subcommand comes first, then the contract marker (above), then its options. A store is `.audit-memory/audit.db`
in the working directory (the default) or `<R>/audit-mem.db`, a store for one run in
a run directory, `audit_<n>/` or `incident_<n>/`; nothing else. `init` makes it. The
other subcommands use only a store `init` made, and `warm`, `check` and
`regressions` read it without writing to it.

A finding's identity is
`finding_id = sha256(program_id "\n" code_signature "\n" root_cause)` (hex), which
gives exact deduplication across audits.

### Subcommands

| Subcommand | Purpose |
|---|---|
| `init` | Make the store: for `.audit-memory/audit.db` with no `.audit-memory/`, the directory, its `.gitignore` of `*` first, then the database; in a run directory, the database. On a store that exists, add the tables and columns it lacks. Prints `initialized <store>`. |
| `put-finding` | Upsert a finding + append an occurrence. Prints `<STATUS> <finding_id>`, or `REGRESSED <finding_id>` on regression. A store holding a status audit-mem never sets for the finding is refused, and left as it was. |
| `set-status` | Set a finding's status (`FIXED` \| `OPEN` \| `ACKNOWLEDGED` \| `DISPUTED`). |
| `rule` | Record a `FALSE_POSITIVE` \| `ACCEPTED_RISK` ruling with a timestamp and its anchor: the commit it is made at and the guard it cites (below). A `FALSE_POSITIVE` ruling needs `--commit` and `--guard`. |
| `check` | Print `{"suppressed":bool,"ruling":..}`; exit 0 when the newest `FALSE_POSITIVE` ruling for the signature still holds, else exit 1. A ruling that no longer holds is printed with `"stale":"<why>"` and suppresses nothing. |
| `regressions` | JSON `{regressions[], truncated}`: of the findings with status `REGRESSED`, the 200 seen most recently (by their newest occurrence), the most severe first; `truncated` counts the rest. |
| `warm` | JSON `{profile, invariants[], open_fp_rulings[], truncated}` — the warm-start context block for a re-audit: what `profile` and `invariant` recorded, each with the values they replaced (`changed`, below), and the rulings with their anchors. Each list holds at most 200 rows, the newest; `truncated` counts the rows left out of all of them. |
| `profile` | Record the program's protocol profile. Fields not given keep what the profile holds; a recorded value a field given replaces is kept (below). Prints `profile <program_id> recorded`, then `, replacing <fields> (…)` when it replaced any. |
| `invariant` | Record an invariant of the program, one per statement: the same statement again updates the fields given, and keeps each value it replaces, a status included. Prints `invariant <id> recorded` or `invariant <id> updated`, then `, replacing <fields> (…)` when it replaced any. |

**Regression rule:** when `put-finding` re-observes a finding whose stored status
was `FIXED`, the status transitions to `REGRESSED` and the command prints
`REGRESSED <finding_id>`. Brand-new findings start `OPEN`.

**No value is erased silently.** When `profile` or `invariant` gives a field whose
recorded value is not empty and not the one given, the value it held is kept in the
`history` table, an erased one (`--notes ''`) too, and `warm` lists it under that
profile's or invariant's `changed`, newest first, as
`{"field", "previous", "recorded_at"}`: the field (`notes`, `status`, …), what it
held, and when it was replaced, in unix seconds as `ruled_at`: the newest 200, as
each of `warm`'s lists holds, with `truncated` counting the rest, which the store
keeps. A field set for the first time replaces nothing. A later audit sees what a
trust assumption or an invariant's status was before, and that it changed.

### Options

```
any subcommand  [--contract=1, right after it] [--db .audit-memory/audit.db | <R>/audit-mem.db]
put-finding     --program-id <PID> --signature <SIG> --root-cause <RC> --title <T> --severity <1-10>
                [--commit <SHA>] [--audit-n <N>] [--file <PATH>] [--line <N>] [--verdict <V>]
set-status      --program-id <PID> --signature <SIG> --root-cause <RC> --status <STATUS>
rule            --program-id <PID> --signature <SIG> --ruling <RULING> --rationale <R> --by <WHO>
                [--scope <S>] [--commit <SHA>] [--guard <FILE>:<LINE> | <FILE>:<FIRST>-<LAST>]
check           --program-id <PID> --signature <SIG> [--commit <SHA>]
regressions     --program-id <PID>
warm            --program-id <PID>
profile         --program-id <PID>, and at least one of [--protocol-class <C>]
                [--trust-assumptions-json <JSON>] [--oracle-set <S>] [--admin-set <S>] [--notes <N>]
invariant       --program-id <PID> --statement <S> [--protocol-class <C>] [--source-fn <F>]
                [--cited-line <FILE:LINE>] [--status <S>]
```

Each option is given once, as `--name <value>` or `--name=<value>`; the word after
`--name` is its value, whatever it looks like. A text value is UTF-8, at most 4096
bytes, and holds no control or formatting character: the C0 and C1 controls, DEL,
the line and paragraph separators, the bidirectional controls, and the code points
Unicode marks default-ignorable (audit-logs' list). `--severity` is a whole number
from 1 to 10 and `--line` one from 1. The `--commit` of `rule` and `check` is a full
commit id, 40 or 64 hexadecimal digits, kept in lowercase: an abbreviation could name
another commit. `put-finding`'s is free text. `--trust-assumptions-json` must be JSON,
and each of its keys and strings, its escapes read, is held to the same rule: a
`\u001b` that the rule reads as six characters is the escape character to whoever
reads the JSON.

### Anchored rulings

A false-positive ruling holds for the code it was made on. `rule` records:

- the commit, `--commit`, a full id;
- the guard, `--guard <file>:<line>` or `<file>:<first>-<last>` (at most 200 lines):
  a file of the working tree, read under the confined path rules (relative, no `.`
  or `..`, no symbolic link on the way, a regular file with one name, at most 4 MiB),
  and the sha256 of those lines, each with the newline that ends it.

`check` suppresses only while the newest `FALSE_POSITIVE` ruling for the signature
holds: `--commit` is its commit, the same full id, and the guard's lines, read again
under the same rules, hash as they did. Otherwise it prints the ruling with `stale`,
the reasons joined by `; `, and exits 1: a stale ruling is a finding to check again.
A check with no `--commit` never suppresses. A ruling recorded before rulings had
anchors has none: it is `"stale":"no anchor"` and never suppresses. `warm` lists the
rulings as they were recorded, anchors included; only `check` says whether one still
holds. `init`, or any
subcommand that writes, adds the anchor columns to a store made before them (a new
store is made the same way, so the two read alike), in the transaction it writes
in: one that fails or refuses leaves the store as it was. `warm`, `check` and
`regressions` read such a store as it is.

### Where it reads and writes

It is built so that `warm`, `check`, `regressions`, `init` and `put-finding` can
each be pre-approved as one `Bash(…)` rule on its absolute path, subcommand and the
contract marker (`"<root>/tools/auditor-tools/target/release/audit-mem" warm --contract=1 *`),
safe whatever arguments follow; `profile` and `invariant` follow the same rules. `rule` and
`set-status` decide what later audits suppress, and are never pre-approved. Its
rules are those of `scripts/lib/confine.sh` and `scripts/rundir.sh`, in
`src/confine.rs`, and `scripts/tests/test-auditor-tools.sh` runs every case of
`scripts/tests/fixtures/audit-mem/cases.txt`:

- `--db` is `.audit-memory/audit.db` or `<R>/audit-mem.db`, relative to the working
  directory (one leading `./` allowed), where `<R>` passes `scripts/rundir.sh check`:
  a real directory in the working directory, holding no symbolic link, tracked by no
  repository in any letter case, with a `.gitignore` of exactly `*`.
- Before it uses `.audit-memory/`, it checks it as `scripts/rundir.sh store` does:
  the repository tracks no `.audit-memory` in any letter case, and `.audit-memory/`
  is a real directory holding no symbolic link, with a `.gitignore` of exactly `*`.
  Whether you made the store yourself stays your judgement (OUTPUT-RULES.md
  Rule 11d). A store an earlier `init` made, before it wrote the `.gitignore`, has
  none and is refused: if the store is yours, write `.audit-memory/.gitignore`
  holding `*` (`printf '*\n' > .audit-memory/.gitignore`), and audit-mem uses it
  again.
- It asks git what is tracked as confine.sh's `hgit` asks it: git from a `PATH` with
  every entry inside the working directory removed, with an environment of its own
  and the repository's config pinned off. When git cannot answer, it refuses.
- The database is a regular file with one name, in rollback-journal mode: a database
  in WAL mode is refused, since a read-only open of one makes a file beside it. No
  `-wal` or `-shm` file may sit beside it (audit-mem never makes one, and SQLite would
  open them even to read), and a `-journal`, left by a write that stopped, must be a
  regular file with one name. It holds only audit-mem's tables, each `CREATE TABLE`
  exactly as audit-mem writes it (a column, constraint, default or table option of
  another's is refused), the indexes SQLite makes for their primary keys, and
  `sqlite_sequence` as SQLite makes it; a view, a trigger, a virtual table or any
  other object is refused. SQLite never follows a link (`SQLITE_OPEN_NOFOLLOW`)
  and runs in its defensive mode (`SQLITE_DBCONFIG_DEFENSIVE`), with triggers and views
  off, `trusted_schema` off, temporary tables in memory and no value read or written
  past 1 MiB (`SQLITE_LIMIT_LENGTH`; the writers store at most 4096 bytes a field).
- `warm`, `check` and `regressions` open the store read-only (`SQLITE_OPEN_READ_ONLY`,
  `PRAGMA query_only=ON`) and immutable (`file:<store>?mode=ro&immutable=1`: SQLite
  takes no lock and opens no file beside it), and never make the file or write the
  schema. With no store they print an empty answer: `warm`
  `{"profile":null,"invariants":[],"open_fp_rulings":[],"truncated":0}`, `check`
  `{"suppressed":false,"store":"absent"}` with exit 1, and `regressions`
  `{"regressions":[],"truncated":0}`.
- `init` makes `.audit-memory/` with a plain `mkdir` (mode 0700), its `.gitignore`
  first, then an empty database, each file made exclusively
  (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600) through the directory, opened once
  without following a link. A `.audit-memory/` that already exists must pass the
  check above. The other subcommands that write refuse when there is no store.
- It refuses to run from an installation inside the working directory, or from a
  path, as it was invoked or with its links resolved, holding a quote, `$`, a
  backtick, a backslash or a control character, and in a working directory whose
  path holds a control character. It opens no network connection and runs no
  program but git. Its JSON writes a control, bidirectional or invisible
  character as a `\u` escape.

Exit: 0 done (`check`: suppressed) · 1 `check`: not suppressed · 2 refused, with
one stderr line, `audit-mem: refused: <reason>`, or a store SQLite cannot read or
write (`audit-mem: error: …`).

### Example lifecycle

```bash
audit-mem init --contract=1     # .audit-memory/, its .gitignore of *, then audit.db

# first observation -> "OPEN <id>"
audit-mem put-finding --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 \
  --commit c0ffee1 --audit-n audit-1 --file src/withdraw.rs --line 42 --verdict TRUE_POSITIVE

# after the dev fixes it
audit-mem set-status --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' --status FIXED

# next audit re-observes it -> "REGRESSED <id>"
audit-mem put-finding --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee3 --audit-n audit-3

# the protocol profile and an invariant, which warm returns
audit-mem profile --contract=1 --program-id VaultProg... --protocol-class vault \
  --trust-assumptions-json '{"admin":"3-of-5 multisig"}' --oracle-set 'pyth SOL/USD'
audit-mem invariant --contract=1 --program-id VaultProg... --statement 'total_shares == shares_mint.supply' \
  --status 'Manually verified' --cited-line src/vault.rs:88

# rule a known false positive at the audited commit, citing its guard, then gate on it
audit-mem rule --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --ruling FALSE_POSITIVE --rationale 'guarded by the require! on line 40' --by auditor \
  --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe --guard src/withdraw.rs:40
audit-mem check --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe
#   -> {"suppressed":true,"ruling":{...}}   (exit 0)
audit-mem check --contract=1 --program-id VaultProg... --signature 'unchecked_sub@vault.balance' \
  --commit c0ffee4c0ffee4c0ffee4c0ffee4c0ffee4c0ffe
#   -> {"suppressed":false,"stale":"ruled at commit c0ffee3…, checked at c0ffee4…","ruling":{...}}   (exit 1)

# a store for one run
audit-mem init --contract=1 --db audit_1/audit-mem.db
audit-mem warm --contract=1 --db audit_1/audit-mem.db --program-id VaultProg...
```

### Schema

```
findings(finding_id PK, program_id, first_seen_commit, last_seen_commit,
         severity, root_cause, code_signature, title, status,
         first_audit_n, last_audit_n)
occurrences(finding_id, audit_n, commit_sha, file, line, verdict, rule5b_json)
fp_rulings(ruling_id PK, program_id, code_signature, ruling, rationale,
           ruled_by, ruled_at, scope,
           anchor_commit, guard_file, guard_line, guard_end, guard_hash)
invariants(inv_id PK, program_id, protocol_class, statement, source_fn,
           cited_line, status)
protocol_profile(program_id PK, protocol_class, trust_assumptions_json,
                 oracle_set, admin_set, notes)
history(history_id PK, program_id, inv_id, field, previous, recorded_at)
```

`history` holds each value `profile` (`inv_id` null) and `invariant` replaced; a
store made before it gains it when it is next written, and reads as having replaced
none.

## `audit-logs`

```
audit-logs profile [--out <file>] <corpus.jsonl>...
audit-logs frames [--instructions] [--out <file>] [<corpus.jsonl>...]
audit-logs deltas lamports|tokens [--by account|owner,mint|mint] [--out <file>] [<corpus.jsonl>...]
```

Each subcommand prints what its script in `scripts/dnr/` prints, byte for byte:
`profile` the report of `profile.sh`, `frames` the records of `frames.py`, `deltas`
the rows of `deltas.py`, or with `--by` its sums, with the same `skipped …` notes on stderr and the same exit
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
  `warm --program-id` returns the protocol profile and invariants that `profile`
  and `invariant` recorded, with the values they replaced, and the standing
  false-positive/accepted-risk rulings with their anchors, so prior context is not
  re-derived. A ruling holds only at the commit it was made at: `check --commit`
  suppresses a finding ruled `FALSE_POSITIVE` there while the guard's lines still
  hold, which spares the same commit a second ruling (a triage run again, say), and
  at any other commit reports the ruling stale, a finding to confirm and rule again
  at that commit. `put-finding` + `regressions` surface anything that was fixed and
  has since regressed.
