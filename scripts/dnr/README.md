# scripts/dnr — detection & response recipes

The shipped recipes behind `/auditor:hunt` and `/auditor:respond`. They turn a
Solana transaction corpus into the small aggregates an investigator quotes in a
ledger, **without reading the raw corpus into a context window** — a real corpus
is far larger than any window (one mainnet transaction is ~20 KB of JSON, so
100k transactions runs to gigabytes). Profile and query it; never `cat` it into
the conversation.

Full method and the verdict rules these feed: `references/detection-response/`.

| File | What it does |
|------|--------------|
| `snapshot-program.sh` | Step 1 of every run: read-only `solana program show` + `dump` (loader-v4: `program-v4 show` + `download`) of each implicated program into `incident_<n>/bin/`, from a throwaway CLI config (no URL in argv, no keypair to sign with), printing the last-deployed slot (`n/a (immutable loader)` for BPFLoader2), the zero-trimmed sha256 and, for loader-v4, the `status=` for the ledger — before a hotfix can overwrite the incident binary. The slot is read again after the dump, and every `show` must name the requested id as its Program Id. A snapshot is never overwritten: a later one of a redeployed program is kept as `bin/<id>@<slot>.so`, and a program that has not changed prints `unchanged`. Every kept snapshot is checked first: each must still be a regular ELF file beside a regular `.show.txt`, later ones need the first, and bytes on-chain that differ from any snapshot kept at the same or a later slot stop the run with a blocker, even when another one matches. An `unchanged` line gives the authority and status read now. An id that is not a program stops it with a blocker naming the account's owner; when a loader owns the account, the blocker tells a data account of the loader (check the id) from a program neither `show` could read (run again). Takes exactly `<program_id> incident_<n>`: refuses an id that is not a base58 32-byte key, and any run directory but `incident_<n>`, relative, directly in the working directory, a real directory that holds no symbolic link, is tracked by git in no letter case and has a `.gitignore` holding `*`, or that git or find cannot check; it checks the run directory again just before its first write. Before the CLI reads from the endpoint, one row of `incident_<n>/disclosures.tsv` records the provider domain and the program id. |
| `collect.sh` | The gated collector: pages signature history (failed transactions included — they are attempt evidence) and fetches transactions into a local JSONL corpus, integers exact on any jq. Refuses without `--confirmed`, on any input that is not base58, on a `--max-pages`, `--max-tx` or address count over the caps set in the environment (`AUDITOR_RPC_MAX_PAGES`, `AUDITOR_RPC_MAX_TX`, `AUDITOR_RPC_MAX_ADDRESSES`), when `--out` already holds any corpus file, and on any `--out` but `incident_<n>/corpus` or `incident_<n>/corpus-<k>` in a run directory that passes the same checks as `snapshot-program.sh`'s; records the provider domain and the addresses, and a `--before` signature, in `incident_<n>/disclosures.tsv` before its first call; writes the corpus files only through the descriptors it opened when it created them; read-only RPC only; capped (`--max-tx` counts every `getTransaction` call) and stops after ten failed calls in a row; pages until an empty page (a shorter page ends the history only on the cap's last page); reports when the page cap stops on a full page, where older history may exist, and writes every gap (a failed fetch, that page cap, the `--max-tx` cap, a stop, an interrupted run) to `collection-gaps.tsv`. Ends with `transactions fetched: N of M calls` and `collection gaps: N`; a write to the corpus that fails stops the run, with a `[blocker]` line (exit 3) in place of those two lines. |
| `profile.sh` | Baseline a `transactions.jsonl`: outcome / version histograms, time window, fee-payer, signer and top-level-program inventories — all from structural fields, never from log text. Reads under the input contract (below). |
| `frames.py` | Attribute each `Program log:` / `Program data:` line to the program frame that emitted it, as JSONL. Walks the log array one element at a time with anchored regexes. With `--instructions`, emits the runtime-recorded instructions instead (`ix`: top-level and CPI, program, accounts, data as given) and the runtime invoke lines joined to them (`invoke`), which is how Leg 1 names the instruction that ran. |
| `deltas.py` | `lamports` or `tokens`: per-account / per-(token account, mint) balance movement, with the owner as a label, computed in Python integers, successful transactions only. An amount or balance that is not an exact integer makes its line malformed; it is never rounded. A balance whose index has no account key is printed as `#<index>`, and a token balance with no `accountIndex` as `#?`, each counted in a note, never left out or merged with another account. |
| `redact.sh` | A stderr/stdout filter that strips provider credentials (e.g. `?api-key=…`, a `/v2/<key>` path, a token in a subdomain, curl's verbose request lines) before text reaches the transcript, the ledger, or a report. |
| `fixtures/` | Committed adversarial corpora the self-test and the docs cite. |

## Running them

Always from the auditor-skill installation, by absolute path —
`<auditor-skill root>/scripts/dnr/…`, the root the invoking command gave you
(`OUTPUT-RULES.md` Rule 11e) — and never as a `scripts/…` path relative to the
working directory, which during an incident is usually the
audited repo and may ship a same-named file. Run the three analysis recipes
directly by that quoted path, from the working directory under audit: their
first lines run `profile.sh` under `/bin/bash` and the python recipes as
`python3 -I` (isolated: neither the working directory nor `PYTHONPATH` reaches
`sys.path`), so they import only the stdlib and never a sibling module.
`snapshot-program.sh` hashes with `python3 -I` for the same reason.

```bash
"<auditor-skill root>/scripts/dnr/profile.sh" [--out <file>] <corpus.jsonl>...
"<auditor-skill root>/scripts/dnr/frames.py" [--instructions] [--out <file>] <corpus.jsonl>...
"<auditor-skill root>/scripts/dnr/deltas.py" tokens|lamports [--out <file>] <corpus.jsonl>...
```

Each takes every corpus of an incident at once
(`incident_<n>/corpus*/transactions.jsonl`) and reads a transaction that more
than one of them holds once, by signature, saying how many copies it skipped.

A collection is the slow step: `collect.sh` makes up to addresses ×
`--max-pages` + `--max-tx` calls, one at a time, each up to 60 seconds, and
usually well under one second on a healthy endpoint. No argument raises the caps
set in the environment: `AUDITOR_RPC_MAX_PAGES` (default 100),
`AUDITOR_RPC_MAX_TX` (default 10000) and `AUDITOR_RPC_MAX_ADDRESSES` (default
25); a default over a cap set lower drops to that cap. Run a long one in the
background, or with a timeout sized from that call count; never let a short
tool timeout cut it off unnoticed. A run stopped by INT, TERM or HUP records
what it had not finished as collection gaps and prints its closing lines. A run
whose write to a corpus file fails (a full disk, say) stops there: it records
what it had not finished as gaps while `collection-gaps.tsv` still takes them,
and prints a `[blocker]` line in place of the closing lines (exit 3). A run
killed outright prints nothing more: then every signature in `signatures.jsonl`
with no transaction in `transactions.jsonl` is a gap, and so is every address
whose history may not have been paged to its end: the last `queried_address` in
`signatures.jsonl` and every address given after it, or every address given when
none appears. Record the gaps that way, too, after a blocker that says
`collection-gaps.tsv` is incomplete.

## Input contract

`profile.sh`, `frames.py` and `deltas.py` read their input the same way, through
one block of code that is the same in all three files. It is copied, not shared,
because `python3 -I` keeps a sibling module off `sys.path`;
`scripts/tests/test-dnr.sh` fails when the copies differ.

- **Inputs.** A named file must be a regular file with one name in a run
  directory `incident_<n>/` of the working directory: named by a path relative
  to it, with no empty, `.` or `..` component, reached through no symbolic link,
  in a run directory that is a real directory whose `.gitignore` holds `*`
  (`OUTPUT-RULES.md` Rule 11d). Every named file is checked before anything is
  read, and any other is refused (exit 2): a missing file, a directory or a FIFO,
  a file with a second name (a hard link), a link or a path through one, an
  absolute path, a file outside every run directory or in `audit_<n>/`. An
  approval prompt shows the path, not where it leads or what else names it. A
  regular file that cannot be opened is an error (exit 1). With no file named,
  `frames.py` and `deltas.py` read stdin. Copy a corpus kept elsewhere, such as a
  `--logs` export, into the run directory (`incident_<n>/logs/`) before a recipe
  reads it. A refusal is one line on stderr, `<recipe>: refused: <reason>`, and
  shows a path escaped to printable ASCII and cut at 120 characters, never raw.
  The recipes do not ask git whether it tracks the run directory, and on a
  case-insensitive filesystem a directory named `INCIDENT_1` is read as
  `incident_1/`: make run directories with
  `"<auditor-skill root>/scripts/rundir.sh" new incident`, and check one before
  reusing it with `"<auditor-skill root>/scripts/rundir.sh" check incident_<n>`.
- **Lines.** Input is read as bytes and split on LF only, so a CR is not a line
  break. Surrounding ASCII whitespace is stripped (a CRLF line end is fine), and
  a blank line is skipped without being counted.
- **Text.** A line must be valid UTF-8 and one JSON object. `NaN`, `Infinity`,
  a number too large for a float, and a `\u` escape that leaves a lone surrogate
  each make it malformed. So does an integer literal of more than 20 digits, or
  `-0`, anywhere in the line, in a field a recipe reads or not: an RPC response
  holds neither, and the bound keeps every Python reading the same lines (3.11
  and later refuse to convert an integer of more than 4300 digits). So does
  nesting deeper than 128 (jq gives an object two of its 256 parser slots, so
  it reads at most 128 nested objects, and every recipe stops at that depth):
  the depth is counted on the line's text before it is parsed, as the brackets
  `[` and `{` outside strings, escapes honoured, the top-level object being 1,
  so a deep value that a later duplicate key replaces counts too. A raw CR
  between JSON tokens is whitespace; inside a string it is invalid JSON.
- **Shape.** Every field a recipe reads must have the type it reads it as:
  `meta`, `transaction` and `message` are objects; `signatures`, `accountKeys`,
  `instructions`, `logMessages`, `innerInstructions` and the balance arrays are
  lists, and `preBalances` and `postBalances` have the same length; `blockTime`
  is a JSON integer; the lamport balances and `fee` are JSON integers that a u64
  holds (0 to 2^64 − 1, as in RPC data: a float, a negative number or a larger
  one is never rounded or read); a token `uiTokenAmount.amount` is the decimal
  text of a u64: 1 to 20 ASCII digits, leading zeros allowed, at most 2^64 − 1
  (not `1_000`, `+5`, `1e3`, a non-ASCII digit or a JSON number). These bounds
  keep every delta and sum exact and printable. The account keys are all
  strings, or all objects with a string `pubkey`; every index
  (`programIdIndex`, `accountIndex`, an inner group's `index`,
  `numRequiredSignatures`) is a non-negative integer, and a `programId` is not
  empty. Keys, program ids and a string `version` hold no character of the fixed
  list below, so each prints as one line, as written. `shaped()` in the block is
  the full rule.
- **The fixed character list** (`_UNSAFE` in the block): the C0 controls
  U+0000–U+001F, DEL U+007F, the C1 controls U+0080–U+009F, the line and
  paragraph separators U+2028 and U+2029, the bidirectional controls U+061C,
  U+200E, U+200F, U+202A–U+202E and U+2066–U+2069, and the code points Unicode
  marks default-ignorable, which text shows as nothing, so two keys that differ
  only in one look the same: U+00AD, U+034F, U+061C, U+115F–U+1160,
  U+17B4–U+17B5, U+180B–U+180F, U+200B–U+200F, U+202A–U+202E, U+2060–U+206F,
  U+3164, U+FE00–U+FE0F, U+FEFF, U+FFA0, U+FFF0–U+FFF8, U+1BCA0–U+1BCA3,
  U+1D173–U+1D17A and U+E0000–U+E0FFF. The list is fixed: it does not follow the
  Unicode tables of the Python, jq or OS that runs a recipe, so the same lines
  are malformed and the same characters escaped under every version. Every other
  character, assigned or not, counts as printable.
- **Malformed lines are counted, never echoed and never fatal.** A line that
  breaks a rule above is skipped. Each recipe then prints one note per input on
  stderr (`profile.sh` also closes its report with it):
  `skipped N malformed line(s) in input I (<path>), the first at line L (…)`.
  Those lines are collection gaps: copy each note into the ledger's **Collection
  gaps** line and into `collection_gaps` in `INCIDENTS.json`. The three recipes
  agree on which lines are malformed, wherever a line sits in a file, so a
  profile, a frame list and a delta table describe the same transactions, and no
  exit status depends on line order.
- **Copies.** A transaction is read once, at the first line that carries its
  signature; the copies skipped are counted in a note of their own.
- **A balance with no account key.** In `deltas.py`, a lamport or token balance
  whose index has no account key (the transaction lists fewer keys than
  balances, as an `encoding: json` export without `meta.loadedAddresses` does)
  is still a movement: its row names the account `#<index>`, never leaves it out
  and never merges it with another account, and a note on stderr counts those
  rows: `deltas.py: N row(s) name a balance index that has no account key, as
  #<index>: …`. A token balance with no `accountIndex` has nothing to pair its
  pre and post sides by, so each side is a row of its own named `#?`, the pre
  balance negative and the post balance positive, counted in a note of its own:
  `deltas.py: N row(s) name a token balance that has no accountIndex, as #?: …`.
- **Output.** No recipe prints a character of the fixed list raw, and
  `frames.py` and `deltas.py` write UTF-8 whatever the locale. `deltas.py`
  doubles a backslash and escapes, in every column, a tab, newline and carriage
  return as `\t`, `\n`, `\r`, and every other character of the list as `\xNN`
  below U+0100, `\uNNNN` up to U+FFFF and `\UNNNNNNNN` above (`\x00`, `\x85`,
  `\xad`, `\u2028`, `\u202e`, `\U000e0041`, lowercase hex). `frames.py` writes
  JSON: the encoder escapes the C0 controls, and every other character of the
  list is written as a `\uNNNN` escape (lowercase hex; above U+FFFF, the
  surrogate pair JSON writes, `\udb40\udc41`), so the value read back is
  unchanged. `profile.sh` prints a `version` that is not a string as its JSON
  text, the same way: jq escapes the C0 controls and DEL, and every other
  character of the list becomes a `\uNNNN` escape.
- **Counting.** `profile.sh` counts and orders values byte by byte (`sort` and
  `uniq` run under `LC_ALL=C`), so two keys that differ only in a character a
  locale's collation ignores stay two lines, and ties fall in the same order under
  every locale.
- **Saved output.** To keep an output, pass `--out <file>`, a new `.jsonl`,
  `.tsv` or `.txt` name directly in a run directory (`incident_<n>/<name>`),
  never a shell redirection into `incident_<n>/`. The recipe writes a temporary
  file beside `<file>` and gives it that name only when the run completes, so a
  run that is cut short never leaves a partial output under the final name, and
  one stopped by TERM removes its temporary file. An output never replaces a
  file: an `--out` that already exists (an input corpus among them) is refused
  (exit 2), and so is one that is a symbolic link, in a subdirectory, in a run
  directory that is a link or has no `.gitignore` of `*`, outside every run
  directory, or of another kind. The recipe opens the run directory once, from
  the working directory and never through a symbolic link, makes sure it is the
  directory it checked, and makes, names and removes its files through it: a run
  directory that is moved, or replaced by a link, while the recipe runs never
  moves the output elsewhere. `profile.sh` writes its report into its private
  temp directory first, then checks `--out` again and opens the run directory
  only once the report is whole, so a link that is there by then is refused.
- **Entry points.** Each recipe refuses to run (exit 2) from an installation
  inside the working directory, or from a path holding a quote, `$`, a
  backtick, a backslash or a control character, which its quoted call could not
  match as written. Its options come before the corpus paths, each at most once;
  an unknown or repeated option is refused (exit 2). `profile.sh` sources
  `scripts/lib/confine.sh`, which sets `LC_ALL=C` and `umask 077` and keeps only
  `PATH` entries outside the working directory, and its private temp directory
  must lie outside it too.
- **audit-logs.** `tools/auditor-tools/audit-logs` is the same three recipes as
  one binary, and `scripts/tests/test-audit-logs.sh` fails when its output,
  notes, exit status or refusals differ from these scripts'. A change to what a
  recipe prints, accepts or refuses goes into both; a binary built before such a
  change refuses to run (exit 4, `audit-logs: stale build: …`) until it is
  rebuilt.

## Two hazards these encode, and why

- **A program log can forge a frame.** `Program log:` text is attacker-chosen and
  can contain a newline followed by a counterfeit `Program <id> invoke [1]` line.
  Flattening the log array (`jq -r '.meta.logMessages[]' | grep …`) splits on that
  newline and invents frames — `fixtures/log-newline-injection.jsonl` turns one
  real invoke into two under a naive flatten. `frames.py` reads the JSON array
  element by element, so a newline inside a payload never becomes a new record.
- **u64 amounts overflow a double.** A token amount or lamport balance can exceed
  2^53, and `jq` numbers are IEEE doubles. Over
  `fixtures/token-amount-over-2-53.jsonl`, `jq` reports a true delta of 1 as 0 for
  one row and as 2 for another. `deltas.py` does every total in Python integers,
  reading amounts from their JSON-string form, so the arithmetic is exact.

Both properties are pinned by `scripts/tests/test-dnr.sh`, which also plants a
`json.py` / `re.py` / `hashlib.py` in the working directory and on `PYTHONPATH`
and checks that none of them loads.

## What a log line proves

`Program log:` / `Program data:` lines and `emit_cpi!` event payloads are
**program-asserted**: a (possibly compromised) program said them, and they still
appear when a later instruction in the same transaction fails. They attribute an
utterance to a frame; they never prove a state change happened (KV-122), and an
`Instruction: X` line never proves which instruction ran — `frames.py
--instructions` reads that from the runtime-recorded instruction lists. A verdict
is grounded in runtime-recorded effects — `meta.err`, balance deltas, and the
account's current value — at `finalized`, not in log text. See
`references/detection-response/README.md`.

## Not a sandbox

These scripts run on the auditor's machine and read whatever corpus they are
pointed at; `collect.sh` makes outbound RPC calls. None of them is pre-approved by
the commands' `allowed-tools`, so each run asks for approval; those lists, and these
recipes, shape intent and are not a security boundary (see
`references/detection-response/README.md` § "allowed-tools is not a sandbox"). Confinement, when you need it, is an isolated
run mode (`OUTPUT-RULES.md` Rule 11a).

## Local tooling

`jq`, `python3` (3.8+, stdlib only, run with `-I`) and `curl`. For a corpus too
large for `grep` passes, the same queries translate to DuckDB SQL over the JSONL;
DuckDB is optional and not required by anything here.
