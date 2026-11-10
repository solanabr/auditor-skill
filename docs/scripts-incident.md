# Incident scripts: snapshot, collection and corpus analysis

The scripts behind `/auditor:hunt` and `/auditor:respond`: the program snapshot and the gated transaction collector, the three analysis recipes, and two helpers. This page gives their arguments, exit codes, network use and outputs. Back to the [docs index](README.md); the track itself: [detection-response.md](detection-response.md).

How every bundled script is run and checked, and the other script pages: [Bundled scripts](power-tools.md#bundled-scripts). Which of them run without asking, and why that is safe: [permissions-and-isolation.md](permissions-and-isolation.md#what-runs-without-asking).

Contents: [`snapshot-program.sh`](#snapshot-programsh) · [`collect.sh`](#collectsh) · [`profile.sh`](#profilesh) · [`frames.py`](#framespy) · [`deltas.py`](#deltaspy) · [`redact.sh`](#redactsh) · [`jq-ro.sh`](#jq-rosh)

The recipes behind `/auditor:hunt` and `/auditor:respond` ([detection-response.md](detection-response.md); method and hazards: [`scripts/dnr/README.md`](../scripts/dnr/README.md)). They summarise a transaction corpus without reading it into context. Inside the `auditor:dnr-analyze` fork, where `/auditor:hunt` and `/auditor:respond` run `incident-responder` for each analysis phase, [`audit-logs`](power-tools.md#audit-logs) runs first, with the same arguments after its subcommand, and `profile.sh`, `frames.py` or `deltas.py` runs in its place when it is not built or reports a stale build. The two that use the network take the endpoint from `$RPC_URL` in the environment, never from the command line, and hand it to curl or the `solana` CLI through a config, never as an argument.

## `snapshot-program.sh`

```bash
"<auditor-skill root>/scripts/dnr/snapshot-program.sh" <program_id> incident_<n>
```

Step 1 of every hunt and response: it keeps the deployed program bytes before a hotfix can replace them. It runs `solana program show` and `solana program dump`, or `solana program-v4 show` and `download` for a loader-v4 program. It reads the program again after the dump and dumps once more if the last-deployed slot moved. Every `show` must name the requested id as its Program Id. It checks the ELF header, hashes the dump the way `solana-verify` does (trailing zero padding trimmed, then sha256), and prints a ledger line: `program=… owner=… last_deployed_slot=… authority=… sha256_zero_trimmed=… elf_bytes=… padding_bytes=… file=bin/<id>[@<slot>].so`. A loader-v4 program's line also has `status=…` (`deployed`, `retracted` or `finalized`) after `authority=`. A program on an immutable loader shows `last_deployed_slot=n/a (immutable loader)` and `authority=none`.

Run it directly by its path, from the working directory; `/auditor:hunt` and `/auditor:respond` pre-approve it.

- **Arguments:** exactly two: a base58 program id (32 bytes) and the run directory, `incident_<n>`, relative to the working directory (a leading `./` and a trailing `/` are dropped).
- **Exit:**
  - 0: a new snapshot, or `unchanged`.
  - 2, refused before any CLI call, with one line, `snapshot-program.sh: refused: <reason>`:
    - a usage error, or a third argument;
    - an id that is not base58 or not 32 bytes;
    - no `$RPC_URL`, or one that holds a quote, a backslash, whitespace or a control character;
    - a run directory that is not `incident_<n>` directly in the working directory: an absolute path, a `.` or `..` component, another name;
    - a run directory that is a symbolic link, holds one that leads out of it or to nothing (in strict mode, any), is tracked by git in any letter case, has no `.gitignore` holding exactly `*`, or that `find` cannot check, or in strict mode git (the check fails closed). The check runs again just before the first write, when `bin/` must also be a directory of its own;
    - an `incident_<n>/disclosures.tsv` that is not a regular file with one link and the disclosure header.
  - 3, a named blocker:
    - no `solana` CLI or `python3`;
    - no private temp directory for the CLI config, or a `TMPDIR` inside the working directory;
    - the CLI did not take the keyless config;
    - a disclosure row that could not be added;
    - a CLI error;
    - no program under any loader: one more read (`solana account`, its data written to the temp directory) names the account's owner in the blocker. When a loader owns the account, the blocker says which case it is: a data account of the loader (a program's data account or a buffer: check the id), or an executable account neither `show` could read (a closed program, or a failing endpoint: run the snapshot again);
    - a `show` that names another Program Id;
    - a dump without the ELF magic;
    - a slot that moved during both dumps;
    - a hash that could not be computed;
    - a snapshot name already taken, or a `.show.txt` without its `.so`;
    - a kept file that could not be written;
    - a kept snapshot that is not a regular file with the ELF magic beside a regular `.show.txt`, or later snapshots (`<id>@<slot>.so`) without the first one;
    - bytes on-chain that differ from every kept snapshot, under a last-deployed slot that is not a plain number and so cannot name a new one;
    - bytes on-chain that differ from any snapshot kept at the same or a later last-deployed slot, even when another snapshot matches. Every kept snapshot is checked before any can match.
- **Network:** read-only `solana` CLI calls to `$RPC_URL`, which reaches the CLI through a temporary `-C` config with no usable keypair path; it signs nothing. CLI errors pass through `redact.sh`. Before the CLI reads from the endpoint, one row goes into `incident_<n>/disclosures.tsv` (below).
- **Writes:** in `incident_<n>/bin/`, made when missing:
  - The first snapshot is `<id>.so` with `<id>.show.txt`.
  - If the slot and zero-trimmed sha256 match a kept snapshot, a later run prints `unchanged: …` and that snapshot's line, with the authority and status read now, and writes nothing. A transfer of authority or a loader-v4 finalize changes neither the slot nor the bytes, so a notice on stderr names any change since the snapshot was kept.
  - After a redeploy it keeps the new bytes as `<id>@<slot>.so` with its `.show.txt` and prints the first snapshot's line and the new one.
  - A kept file is never replaced; each is written through the descriptor opened when it was created.
  - One row of `incident_<n>/disclosures.tsv`: the provider's domain and the program id.
- **Needs:** the `solana` CLI and `python3`, which checks the id and hashes the dump as `python3 -I`.

## `collect.sh`

```bash
"<auditor-skill root>/scripts/dnr/collect.sh" --out incident_<n>/corpus[-<k>] --confirmed [--since <unix>] [--until <unix>] \
  [--before <signature>] [--max-pages N] [--max-tx N] -- <address> [<address> ...]
```

The one gated collector: it pages each address's signature history, failed transactions included (they are evidence of attempts), and fetches every transaction in the window into a local JSONL corpus, newest first. Run it directly by its path, from the working directory; each option is given at most once. `/auditor:hunt` and `/auditor:respond` pre-approve it, and run it only with the addresses, window and caps you approved.

| Flag | Meaning |
|------|---------|
| `--out incident_<n>/corpus[-<k>]` | corpus directory (required): `corpus`, or `corpus-<k>` with 1 to 4 digits, in the run directory `incident_<n>`, relative to the working directory, made there when missing. One that holds `signatures.jsonl`, `transactions.jsonl` or `collection-gaps.tsv`, even an empty one, is refused, so a resume goes into a new directory |
| `--confirmed` | required; the commands pass it only after a person has approved the addresses, the window, the caps and the estimated call count |
| `--since <unix>`, `--until <unix>` | the window, on `blockTime`; `0` (the default) leaves that end open |
| `--before <signature>` | start paging just older than this signature: resume a capped run, or skip activity after the incident |
| `--max-pages N` | pages of up to 1,000 signatures per address (default 20, at most `AUDITOR_RPC_MAX_PAGES`). An empty page ends that address's history; a page of fewer than 1,000 ends it only on the last page the cap allows, since a node can return a short page before the end, so a history that ends inside the cap costs one more call |
| `--max-tx N` | `getTransaction` calls in total, failures included (default 2000, at most `AUDITOR_RPC_MAX_TX`); the oldest signatures are left out first. After 10 failed calls in a row the run stops |
| `-- <address> ...` | the base58 addresses to page, at most `AUDITOR_RPC_MAX_ADDRESSES` |

- **Caps:** no argument can go past the caps set in the environment, where a command line cannot set them: `AUDITOR_RPC_MAX_PAGES` (default 100), `AUDITOR_RPC_MAX_TX` (default 10000) and `AUDITOR_RPC_MAX_ADDRESSES` (default 25). A value over its cap is refused, naming the variable to raise; a default over a cap set lower drops to that cap, and the run's `caps:` line prints the values used.
- **Exit:**
  - 0: done, collection gaps included.
  - 2, refused before anything is written or sent, with one line, `collect.sh: refused: <reason>`:
    - no `--confirmed`;
    - a usage error, an unknown argument, or an option given twice;
    - no `$RPC_URL`, or one that holds a quote, a backslash, whitespace or a control character;
    - an address or `--before` value that is not base58;
    - a number that is not a plain integer of at most 18 digits;
    - a `--max-pages`, `--max-tx` or address count over its cap, or a cap that is not a plain integer;
    - an `--out` other than `incident_<n>/corpus` or `incident_<n>/corpus-<k>`, relative: an absolute path, a `.` or `..` component, another name;
    - a run directory that is a symbolic link, holds one, is tracked by git (in any letter case), has no `.gitignore` holding exactly `*`, or that git or find cannot check;
    - an `incident_<n>/disclosures.tsv` that is not a regular file with one link and the disclosure header;
    - an `--out` that already holds a corpus file, or where the corpus files cannot be created.
  - 3, a named blocker:
    - no curl or jq;
    - a jq that rounds large integers and no working `python3`;
    - no private temp directory, which is made before anything is written, or a `TMPDIR` inside the working directory;
    - a disclosure row that could not be added (nothing was sent);
    - a failed write to a corpus file, to `collection-gaps.tsv`, or to the private signature and fetch lists (a full disk, say). The run stops there: it makes no further call, records what it had not collected as gap rows while `collection-gaps.tsv` still takes them, and prints the blocker in place of the closing lines. When the blocker says `collection-gaps.tsv` is incomplete too, record the gaps as for a run killed outright.
  - 128 + N: stopped by signal N (INT, TERM or HUP), with what was left recorded as collection gaps.
- **Network:** read-only JSON-RPC to `$RPC_URL` (`getSignaturesForAddress`, then `getTransaction` at `finalized` with `maxSupportedTransactionVersion: 1`), and only with `--confirmed`. The URL reaches curl through a config on stdin (`curl -q -K -`), never as an argument. The `provider:` line names the provider's domain (the host's last two labels) for the Rule 11b disclosure; curl errors pass through `redact.sh`.
- **Writes:** `<dir>/signatures.jsonl`, `<dir>/transactions.jsonl` and `<dir>/collection-gaps.tsv`, and before the first call one row of `incident_<n>/disclosures.tsv`: the provider's domain and the addresses, with the `--before` signature when one is given.
  - `transactions.jsonl` is written by jq only when a test round-trip shows jq keeps 64-bit integers exact (a check of behaviour, not of the version); otherwise it is written by `python3 -I`.
  - `collection-gaps.tsv` has one `<signature or address><TAB><reason>` row per gap: a failed `getTransaction`, a failed signature page (older history not collected), a page cap that stopped on a full page, where older history may exist (with the `--before` to resume from), the `--max-tx` cap, or the stop after 10 failed calls in a row.
  - The three files are written only through the descriptors opened when they were created.
  - stdout ends with `transactions fetched: N of M calls -> …` and `collection gaps: N (see …)`, except after a failed write (exit 3), when a `[blocker]` line on stderr takes their place. Notices go to stderr and start with `  ! `.
  - A run stopped by INT, TERM or HUP adds gap rows for the address being paged (naming the `--before` signature to resume from, once one of its pages was read) and each one after it, and one for the signatures listed but not fetched, then prints the closing lines. A run killed outright prints nothing more; then each signature in `signatures.jsonl` with no transaction in `transactions.jsonl` is a gap, and so is every address whose history may not have been paged to its end: the last `queried_address` in `signatures.jsonl` and every address given after it, or every address given when none appears.
- **Run time:** up to addresses × `--max-pages` + `--max-tx` calls, one at a time, each up to 60 seconds. The commands run it in the foreground with a timeout sized from that count: a Bash call that outlasts its timeout moves to the background, and the turn its completion starts has none of the command's pre-approvals ([Long steps](permissions-and-isolation.md#long-steps)). Run by hand, a long collection can go in the background.
- **Needs:** curl and jq; `python3` too when jq rounds large integers (before jq 1.7).

## `profile.sh`

```bash
"<auditor-skill root>/scripts/dnr/profile.sh" [--out <file>] <corpus.jsonl> [<corpus.jsonl> ...]
```

The baseline of one or more `getTransaction` JSONL corpora, such as every `incident_<n>/corpus*/transactions.jsonl`, counting each signature once. It reads structural fields only, never log text, and reports the succeeded / failed split, the transaction-version histogram (a version that is not a string as its JSON text, with each character of the input contract's fixed list as a `\uNNNN` escape), the `blockTime` window, and the top 20 fee payers, signers and top-level programs. It counts and orders them byte by byte (`sort` and `uniq` run under `LC_ALL=C`), so the figures and the order of ties are the same under every locale. It keeps the first occurrence of each signature and skips malformed lines under the input contract the three recipes share ([`scripts/dnr/README.md`](../scripts/dnr/README.md#input-contract)); closing `-- skipped` lines give both counts, one per input for malformed lines, and are printed on stderr too. Those malformed lines are collection gaps.

- **Arguments:** one or more corpus files, each a regular file with one name in a run directory `incident_<n>/` whose `.gitignore` holds `*`, named relative to the working directory, with no empty, `.` or `..` component and no symbolic link on the way; any other is refused before any input is read. Run it directly by its quoted path, from the working directory: it refuses to run from an installation inside it.
- **`--out <file>`:** a new `.jsonl`, `.tsv` or `.txt` name directly in the run directory; writes the report to a temporary file beside `<file>` and gives it that name once the report is whole, as `frames.py` and `deltas.py` do.
- **Exit:** 0 done · 1 a corpus file that cannot be read, or an `--out` that cannot be written · 2 usage error, or a path the input contract refuses (a missing or non-regular file, one with a second name, one outside a run directory or reached through a symbolic link, an `--out` that is not a new name directly in a run directory), or a `python3` that lies inside the working directory, as one `profile.sh: refused: …` line · 3 `jq` or `python3` missing, or a `python3` that does not run, checked before anything is read (`[blocker] <tool> is not on PATH; profile.sh needs jq and python3.`).
- **Network:** none. **Writes:** stdout, or the `--out` file. Needs `jq` and `python3` (the one-per-signature pass runs as `python3 -I`).

## `frames.py`

```bash
"<auditor-skill root>/scripts/dnr/frames.py" [--instructions] [--out <file>] [<corpus.jsonl> ...]    # reads stdin when no file is named
```

Attributes each `Program log:`, `Program data:` and `Program return:` line to the program frame that emitted it. It walks the log array one element at a time with anchored patterns, so a newline inside a log payload cannot forge a frame. Output is JSONL on stdout, one `{sig, ok, depth, program, kind, text}` record per line, where `kind` is `log`, `data`, `return`, `truncated` or `unparsed`; a character of the input contract's fixed list is written as a `\uNNNN` escape (a surrogate pair above U+FFFF), never raw. A malformed input line is skipped and counted under the shared input contract, never echoed. A log line is what the program asserted, never proof that state changed.

- **Arguments:** corpus files (several corpora count each signature once), or none for stdin; each named file is checked as for `profile.sh`. Skipped copies, and each input's malformed lines, are reported on stderr.
- **`--instructions`:** prints the instruction records instead; the default output is unchanged without it. An `ix` record for each entry of `message.instructions` and `meta.innerInstructions` gives the program, the top-level and inner index, the stack height, the accounts, and the data as given (or `parsed-only`). An `invoke` record gives each invocation's depth, outcome and the `ix_seq` it ran. No `ix` field comes from log text.
- **`--out <file>`:** writes the records to a temporary file beside `<file>` and gives it that name only when the run completes, so a run cut short never leaves a partial file under that name; a run stopped by TERM, INT or HUP removes its temporary file (a signal the caller ignores stays ignored). `<file>` must be a new `.jsonl`, `.tsv` or `.txt` name directly in the run directory: an output never replaces a file, an input corpus least of all. A `>` into a new name in `incident_<n>/` keeps an output too, but gives a partial file to a run cut short.
- **Exit:** 0 done · 1 a file that cannot be read, or an `--out` that cannot be written, checked before any record is printed · 2 usage error, or a path the input contract refuses, as for `profile.sh`, or a `python3` that lies inside the working directory · 3 no `python3` on `PATH` that runs, before anything is read (`[blocker] python3 is not on PATH, or does not run; frames.py needs python3.`).
- **Network:** none. **Writes:** stdout, or the `--out` file.

## `deltas.py`

```bash
"<auditor-skill root>/scripts/dnr/deltas.py" lamports|tokens [--by account|owner,mint|mint] [--out <file>] [<corpus.jsonl> ...]    # reads stdin when no file is named
```

Balance movements of successful transactions, computed in Python integers so that amounts above 2^53 stay exact.

- `lamports` prints `signature`, `account`, `delta` for each non-zero lamport change, with the fee added back for the fee payer.
- `tokens` prints one row per token account: `signature`, `owner` (`?` when the corpus names none), `mint`, `delta` in raw units, and the token account.
- `--by` prints exact sums in place of the rows, the most negative first, then by name; a sum of 0 prints no row. `lamports --by account`: `account`, its net. `tokens --by owner,mint`: `owner`, `mint`, the net, and a fourth column, empty unless the corpus names no owner: such balances are summed per token account, which it names. `tokens --by mint`: `mint`, the sum of the owners' negative nets and how many owners had one, then the sum of the positive nets and how many. These are the blast-radius figures: an owner's net movement per mint, and a mint's total loss and number of losers.
- A balance whose index has no account key is printed as `#<index>`. A token balance with no `accountIndex` has nothing to pair its pre and post sides by, so each side is a row of its own, `#?`. A note on stderr counts each kind; neither is ever merged with another account. Such a name stands for an account only within its own transaction, so no `--by` sum holds a lamport row so named, nor a token row with no owner either; a note counts them.

The output is TSV on stdout; tabs, newlines, carriage returns and backslashes inside a field are escaped, and so is every other character of the input contract's fixed list (control characters, line and paragraph separators, bidirectional controls, and the code points Unicode marks default-ignorable, zero-width characters among them; `scripts/dnr/README.md`). Several corpora count each signature once. An amount or balance that is not an exact integer (a float, `1_000`, a non-ASCII digit) makes its line malformed under the shared input contract: the line is skipped and counted, never rounded. Skipped copies, and each input's malformed lines, are reported on stderr; the malformed lines are collection gaps.

- **Arguments:** the mode, then `--by <grouping>` and `--out <file>` (written as `frames.py` writes it), each at most once, then corpus files or none; each named file is checked as for `profile.sh`.
- **Exit:** 0 done · 2 a missing or unknown mode, a grouping the mode does not take, or a path the input contract refuses, as for `profile.sh`, or a `python3` that lies inside the working directory · 1 a file that cannot be read, or an `--out` that cannot be written, checked before any row is printed · 3 no `python3` on `PATH` that runs, before anything is read (`[blocker] python3 is not on PATH, or does not run; deltas.py needs python3.`).
- **Network:** none. **Writes:** stdout, or the `--out` file.

## `redact.sh`

```bash
set -o pipefail; some-command 2>&1 | bash "<auditor-skill root>/scripts/dnr/redact.sh"    # pipefail keeps the command's exit status
```

A filter from stdin to stdout that removes provider credentials. In a URL of any scheme it keeps the scheme and the host's last two DNS labels (`REDACTED.provider.example`; an IP address or a two-label host stays whole), replaces userinfo with `REDACTED@` and replaces the path and query with `/REDACTED`. On curl's own error and verbose lines it shortens bare host names the same way and redacts the request path. A bare `api-key=`, `token=`, `secret=`, `auth=` or `access-token=` value outside a URL is redacted too. It is a convenience, not a guarantee: no RPC URL goes into a ledger, `INCIDENTS.json` or a report in any case. Record the provider's domain, as `collect.sh` prints it, and the literal string `$RPC_URL` instead.

- **Arguments:** none. **Exit:** 0. **Network:** none.

## `jq-ro.sh`

```bash
"<auditor-skill root>/scripts/dnr/jq-ro.sh" -c 'select(.slot > 301) | .transaction.signatures[0]' incident_<n>/corpus/transactions.jsonl
```

`jq` over files inside a run directory, with nothing else to read. The `auditor:dnr-analyze` fork pre-approves it in place of `jq`, which can print the environment. It runs `jq` as `env -i HOME=/nonexistent PATH=/usr/bin:/bin`, so `$ENV` and `env` hold those two values and no `~/.jq` loads, and it prints every control character but tab and newline as `?`.

- **Arguments:** `-c`, `-r`, `-s`, `-e` and `-n`, each its own word; `--arg <name> <value>` and `--argjson <name> <json>`, each name bound once; then the filter and one or more inputs. Every other option is refused, `--rawfile`, `--slurpfile`, `-f`/`--from-file` and `-L` among them, and so is a filter that holds `import`, `include` or `modulemeta`. Each input is a relative path to a regular file with one link inside `audit_<n>/` or `incident_<n>/`, with no `.`, `..` or symbolic link on the way. Standard input is never read.
- **Exit:** jq's own status, or 2 when it refuses, with one stderr line, `jq-ro: refused: <reason>`. **Network:** none.
- **Pre-approval:** Claude Code asks about a line that holds a `$`, inside quotes too, so write values into the filter as literals rather than as `--arg` variables.
