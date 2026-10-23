#!/usr/bin/env python3
"""deltas.py — compute balance movements from a getTransaction JSONL corpus, with
every total done in Python integers.

Input: one getTransaction result object per line (`jsonParsed` or `json`), on
stdin or in files named as args — every corpus of an incident at once
(`incident_<n>/corpus*/transactions.jsonl`). Lines are read under the input
contract that profile.sh and frames.py share (scripts/dnr/README.md): a malformed
line, an amount or balance that is not an exact integer among them, is skipped and
counted, never echoed. A transaction is counted once however many inputs hold it:
the first occurrence of each signature wins. Both counts are reported on stderr,
the malformed lines per input, as collection gaps. The corpus is streamed one
transaction at a time, and every named file (and the --out path) is checked
before the first row is written: one that cannot be read or written exits 1, and
one that is a symbolic link, or reached through one inside the working directory,
or an --out that already exists, exits 2, with no output either way.

Two modes:
  deltas.py lamports [--out <file>] [files...]
                                  per (signature, account) non-zero lamport delta;
                                  the fee is added back for the fee payer (index 0),
                                  so the row reflects movement, not the fee. A balance
                                  whose index has no account key is printed as
                                  #<index>, and counted in a note on stderr.
  deltas.py tokens [--out <file>] [files...]
                                  per (signature, token account, mint) raw-unit
                                  token delta; columns: signature, owner (a label,
                                  `?` when the RPC gave none), mint, delta, token
                                  account.

Output: TSV on stdout, or with `--out <file>` (a new name) in a temporary file
beside it that becomes <file> only once the run is complete; UTF-8 whatever the
locale.
Signatures, owners and mints are base58 in real RPC data and deltas are decimal
integers; any tab, newline, carriage return or backslash in a string field is
escaped (`\\t`, `\\n`, `\\r`, `\\\\`), so a crafted corpus cannot forge a row, and so
is every other character of the input contract's fixed list (control characters,
line and paragraph separators, bidirectional controls, zero-width characters:
`\\x00`, `\\x85`, `\\u2028`, `\\u202e`, `\\u200b`, …); any other character is
printed as itself, whichever Python runs it.
Token deltas are per token account (its `accountIndex` resolved through the
transaction's account keys) and mint, so two accounts never share a bucket, even
when the RPC gives no owner; sum the rows per owner for an owner's net, which nets
a move between one owner's accounts to zero and adds up a drain across several.
Aggregate further in Python ints — never in jq or awk, whose numbers are doubles.

Why Python ints, not jq: a u64 token amount or a lamport balance can exceed 2^53,
and jq numbers are IEEE doubles. Over the adversarial fixture
`token-amount-over-2-53.jsonl`, `jq` reports a delta of 2 for a true 1 and drops
a true 1 entirely. Python's `int` is arbitrary precision, and these amounts arrive
as JSON strings of ASCII digits (`uiTokenAmount.amount`) or as JSON integers that
Python parses losslessly, so the arithmetic is exact. Each must be a u64 value, as
in RPC data; anything else in those fields (a float, `1_000`, a sign, a non-ASCII
digit, a value above 2^64 - 1) makes the line malformed rather than being rounded
or read as a number, and keeps every delta far inside what Python prints.

Success-only: a failed transaction commits no instruction state (atomic revert —
`references/false-positives.md` FP-4), so a delta from a failed tx would be a
phantom. Both modes skip `meta.err != null`.

Account indexing note: in `jsonParsed`, `accountKeys` already includes
lookup-table-loaded addresses, so it lines up 1:1 with pre/postBalances. With
`encoding: json`, append `meta.loadedAddresses.writable` then `.readonly` to the
static keys before indexing; this script handles both.

Run it as `python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/deltas.py" tokens|lamports
<corpus.jsonl>`. Isolated mode keeps the working directory (usually the audited
repo) and PYTHONPATH off sys.path, so it imports nothing beyond the stdlib — keep
it that way: no sibling modules.

No network. python3 stdlib only.
"""

from __future__ import annotations

import errno
import json
import math
import os
import re
import signal
import stat
import sys
import tempfile
from collections import OrderedDict


def _account_keys(tx: dict) -> list[str]:
    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = []
    for k in msg.get("accountKeys") or []:
        keys.append(k["pubkey"] if isinstance(k, dict) else k)
    # encoding: json keeps loaded (ALT) addresses out of accountKeys; jsonParsed
    # already folds them in. Append only when they are not already present.
    loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
    if loaded and len(keys) < len(((tx.get("meta") or {}).get("preBalances")) or []):
        keys += list(loaded.get("writable") or [])
        keys += list(loaded.get("readonly") or [])
    return keys


def _ok(tx: dict) -> bool:
    return (tx.get("meta") or {}).get("err") is None


_TSV = {"\t": "\\t", "\n": "\\n", "\r": "\\r"}


def _escape(m) -> str:
    c = m.group()
    return _TSV.get(c) or ("\\x%02x" % ord(c) if ord(c) < 0x100 else "\\u%04x" % ord(c))


def _clean(s) -> str:
    """Escape what could break a TSV row, or hide in one. Real RPC data carries
    base58 here, but a corpus can come from an untrusted export: a backslash is
    doubled, and each character of the contract's fixed _UNSAFE list is written as
    an escape (\\t, \\n, \\r; else \\xNN below U+0100 and \\uNNNN above), so a key or
    mint cannot forge an extra row or column, or hide a control character in one."""
    return _UNSAFE.sub(_escape, str(s).replace("\\", "\\\\"))


def _lamports(txs, out):
    """Write the rows; return how many name a balance index that has no account key."""
    keyless = 0
    for tx in txs:
        if not _ok(tx):
            continue
        meta = tx.get("meta") or {}
        pre = meta.get("preBalances") or []
        post = meta.get("postBalances") or []
        fee = meta.get("fee") or 0
        keys = _account_keys(tx)
        sig = ((tx.get("transaction") or {}).get("signatures") or ["?"])[0]
        # pre and post are the same length (the input contract). A balance whose
        # index has no account key is still a movement: it is printed as #<index>.
        for i in range(len(pre)):
            d = post[i] - pre[i] + (fee if i == 0 else 0)
            if d != 0:
                if i < len(keys):
                    account = keys[i]
                else:
                    account = "#%d" % i
                    keyless += 1
                out.write(f"{_clean(sig)}\t{_clean(account)}\t{d}\n".encode("utf-8"))
    return keyless


def _tokens(txs, out):
    for tx in txs:
        if not _ok(tx):
            continue
        meta = tx.get("meta") or {}
        sig = ((tx.get("transaction") or {}).get("signatures") or ["?"])[0]
        keys = _account_keys(tx)
        acc: "OrderedDict[tuple[str, str], list[int]]" = OrderedDict()
        labels: dict = {}

        def fold(entries, slot):
            for b in entries or []:
                owner = b.get("owner") or "?"
                mint = b.get("mint") or "?"
                amt = (b.get("uiTokenAmount") or {}).get("amount")
                # amount is the decimal STRING of a u64 in ASCII digits (the input
                # contract makes anything else malformed); int() is exact.
                val = int(amt) if amt is not None else 0
                # Keyed by the token account, so two accounts never merge — not even
                # two owner-less ones. Without a usable accountIndex the owner is the
                # key; SUM, never assign, in that bucket. Fixtures: same-owner-move.jsonl
                # (two legs, net 0 for the owner), same-owner-drain.jsonl (-140 for
                # the owner, over two accounts).
                idx = b.get("accountIndex")
                account = keys[idx] if type(idx) is int and 0 <= idx < len(keys) else None
                key = (account if account is not None else "owner:" + owner, mint)
                acc.setdefault(key, [0, 0])[slot] += val
                if key not in labels or b.get("owner"):
                    labels[key] = (owner, account or "?")

        fold(meta.get("preTokenBalances"), 0)
        fold(meta.get("postTokenBalances"), 1)
        for key, (p, q) in acc.items():
            d = q - p
            if d != 0:
                owner, account = labels[key]
                out.write(f"{_clean(sig)}\t{_clean(owner)}\t{_clean(key[1])}\t{d}\t{_clean(account)}\n"
                          .encode("utf-8"))


# ---- input contract (scripts/dnr/README.md); the same block is in profile.sh, frames.py, deltas.py
_NONE = type(None)
_DIGITS = re.compile("[0-9]+")
_SURROGATE_ESCAPE = re.compile(r"\\u[dD][89a-fA-F]")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
# Brackets may nest this deep, the top-level object being 1: well below the 256 that
# jq reads, so profile.sh never meets a line its queries cannot parse. The depth is
# counted on the text of the line, before it is parsed.
_DEPTH = 200
# One JSON string (its escapes included) or one bracket: what that count reads.
_TOKEN = re.compile(r"\"[^\"\\]*(?:\\.[^\"\\]*)*\"|[\[\]{}]", re.S)
# The characters no key, program id or string version may hold, and that no recipe
# prints raw: the C0 controls, DEL, the C1 controls, the line and paragraph
# separators, the bidirectional controls (U+061C, U+200E-200F, U+202A-202E,
# U+2066-2069) and the zero-width characters (U+200B-200D, U+FEFF). The list is
# fixed, so the same lines are malformed under every Python, whatever Unicode
# version it knows; every other character, assigned or not, prints as itself.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")
# Lamport balances, the fee and token amounts are u64 values in RPC data; bounding
# them keeps every computed delta and sum far inside what Python prints.
_U64 = 2 ** 64 - 1


def _no_constant(name):
    raise ValueError("not a JSON number: " + name)


def _finite(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("not a finite number")
    return value


_DECODER = json.JSONDecoder(parse_constant=_no_constant, parse_float=_finite)


def shown(text, cap=120):
    """text for a message: printable ASCII, every other character escaped, cut at cap."""
    s = str(text).encode("unicode_escape").decode("ascii")
    return s if len(s) <= cap else s[:cap] + "..."


def linked(path):
    """True when path is a symbolic link, or reaches its file through a directory that
    is a symbolic link inside the working directory. Links above it are followed."""
    if os.path.islink(path):
        return True
    here = os.getcwd()
    cur = os.sep if os.path.isabs(path) else here
    for part in path.split(os.sep)[:-1]:
        if not part:
            continue
        step = os.path.join(cur, part)
        if os.path.islink(step):
            parent = os.path.realpath(cur)
            if parent == here or parent.startswith(here.rstrip(os.sep) + os.sep):
                return True
        cur = step
    return False


def opened(path):
    """One named input, opened for reading: never through a final symbolic link, and
    only a regular file (a FIFO or a device is not opened for a blocking read)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def unusable(paths):
    """None when every named input can be read, else (exit status, message) for the
    first one that cannot: 2 for a symbolic link, 1 for anything else."""
    for n, path in enumerate(paths, 1):
        if path == "-":
            continue
        try:
            if linked(path):
                return 2, ("input %d (%s) is a symbolic link, or is reached through one inside the"
                           " working directory; refusing it" % (n, shown(path)))
            opened(path).close()
        except OSError as e:
            return 1, "cannot read input %d (%s): %s" % (n, shown(path), shown(e.strerror or e))
    return None


def unwritable(path):
    """None when --out path can take a new output file, else (exit status, message): 2
    for a symbolic link, a path reached through one inside the working directory, or
    a path that exists (an output never replaces a file, an input corpus least of
    all), 1 for a path whose directory does not exist."""
    try:
        if linked(path):
            return 2, ("--out %s is a symbolic link, or is reached through one inside the working"
                       " directory; refusing it" % shown(path))
        if os.path.lexists(path):
            return 2, "--out %s already exists, and an output never replaces a file: name a new one" % shown(path)
        if not os.path.isdir(os.path.dirname(path) or "."):
            return 1, "cannot write --out %s: its directory does not exist" % shown(path)
    except OSError as e:
        return 1, "cannot write --out %s: %s" % (shown(path), shown(e.strerror or e))
    return None


class Output:
    """Where the output goes: stdout, or for --out a new temporary file beside the path
    that done() links to the path once it is whole, so the path never holds a partial
    output, and never replaces a file that appeared in the meantime. close() removes
    a temporary file done() did not link; SIGTERM exits through it, and is held off
    while the temporary file is made, so its name is always known."""

    def __init__(self, path):
        self.path, self.temp, self.fh = path, None, sys.stdout.buffer
        if path is None:
            return
        signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(128 + signum))
        held = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
        try:
            fd, self.temp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                                             prefix="." + os.path.basename(path) + ".", suffix=".partial")
            self.fh = os.fdopen(fd, "wb")
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, held)
            except BaseException:
                self.close()
                raise

    def write(self, data):
        self.fh.write(data)

    def done(self):
        self.fh.flush()
        if self.temp is not None:
            self.fh.close()
            os.link(self.temp, self.path)
            os.unlink(self.temp)
            self.temp = None

    def close(self):
        if self.temp is not None:
            self.fh.close()
            try:
                os.unlink(self.temp)
            except OSError:
                pass
            self.temp = None


def _lone_surrogate(obj):
    stack = [obj]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if _LONE_SURROGATE.search(v):
                return True
        elif isinstance(v, dict):
            for k, x in v.items():
                if _LONE_SURROGATE.search(k):
                    return True
                stack.append(x)
        elif isinstance(v, list):
            stack.extend(v)
    return False


def _too_deep(text):
    """True when the brackets outside strings in a line nest deeper than _DEPTH. It
    reads the text, not the parsed value, so a deep value that a later duplicate key
    replaces counts too."""
    if text.count("[") + text.count("{") <= _DEPTH:
        return False
    depth = 0
    for m in _TOKEN.finditer(text):
        c = m.group()
        if c == "[" or c == "{":
            depth += 1
            if depth > _DEPTH:
                return True
        elif c == "]" or c == "}":
            depth -= 1
    return False


def _of(v, *types):
    """v is null (or absent), or exactly one of types: a bool is not an int."""
    return type(v) in types + (_NONE,)


def _index(v):
    """null (or absent), or an integer index from 0: a negative one would count back
    from the end in jq and in Python, but name no account in the recipes."""
    return v is None or (type(v) is int and v >= 0)


def _plain(v):
    """A string with no _UNSAFE character, so it prints as one line, as written."""
    return type(v) is str and not _UNSAFE.search(v)


def _u64(v):
    """An integer a u64 holds, as a lamport balance and the fee are."""
    return type(v) is int and 0 <= v <= _U64


def _amount(v):
    """A raw token amount: the decimal text of a u64, in ASCII digits."""
    return type(v) is str and len(v) <= 20 and bool(_DIGITS.fullmatch(v)) and int(v) <= _U64


def _instruction(ix):
    return (type(ix) is dict and _index(ix.get("programIdIndex")) and _of(ix.get("accounts"), list)
            and (ix.get("programId") is None or (_plain(ix.get("programId")) and ix.get("programId") != "")))


def _token_balance(b):
    if type(b) is not dict or not (_index(b.get("accountIndex")) and _of(b.get("owner"), str)
                                   and _of(b.get("mint"), str) and _of(b.get("uiTokenAmount"), dict)):
        return False
    amount = (b.get("uiTokenAmount") or {}).get("amount")
    return amount is None or _amount(amount)


def shaped(tx):
    """True when every field the three recipes read has the type they read it as, and
    every key, program id and version profile.sh prints is one line."""
    if type(tx) is not dict:
        return False
    t, meta, version = tx.get("transaction"), tx.get("meta"), tx.get("version")
    if not (_of(t, dict) and _of(meta, dict) and _of(tx.get("blockTime"), int)
            and (type(version) is not str or _plain(version))):
        return False
    t, meta = t or {}, meta or {}
    m, sigs = t.get("message"), t.get("signatures")
    if not (_of(m, dict) and _of(sigs, list) and all(type(s) is str for s in sigs or [])):
        return False
    m = m or {}
    keys, header, ixs = m.get("accountKeys"), m.get("header"), m.get("instructions")
    if not (_of(keys, list) and _of(header, dict) and _of(ixs, list)
            and _index((header or {}).get("numRequiredSignatures"))
            and all(_instruction(ix) for ix in ixs or [])):
        return False
    if keys and not (all(_plain(k) for k in keys)
                     or all(type(k) is dict and _plain(k.get("pubkey")) for k in keys)):
        return False
    groups, loaded, logs = meta.get("innerInstructions"), meta.get("loadedAddresses"), meta.get("logMessages")
    if not (_of(groups, list) and _of(loaded, dict) and _of(logs, list)
            and (meta.get("fee") is None or _u64(meta.get("fee")))
            and all(type(s) is str for s in logs or [])):
        return False
    for g in groups or []:
        if not (type(g) is dict and g.get("index") is not None and _index(g.get("index"))
                and _of(g.get("instructions"), list)
                and all(_instruction(ix) for ix in g.get("instructions") or [])):
            return False
    for name in ("writable", "readonly"):
        v = (loaded or {}).get(name)
        if not (_of(v, list) and all(type(a) is str for a in v or [])):
            return False
    for name in ("preBalances", "postBalances"):
        v = meta.get(name)
        if not (_of(v, list) and all(_u64(x) for x in v or [])):
            return False
    if len(meta.get("preBalances") or []) != len(meta.get("postBalances") or []):
        return False
    for name in ("preTokenBalances", "postTokenBalances"):
        v = meta.get(name)
        if not (_of(v, list) and all(_token_balance(b) for b in v or [])):
            return False
    return True


def parsed(line):
    """The transaction one stripped line holds, or None when the line is malformed."""
    try:
        text = line.decode("utf-8")
    except ValueError:
        return None
    if _too_deep(text):
        return None
    try:
        tx = _DECODER.decode(text)
    except (ValueError, RecursionError):
        return None
    if _SURROGATE_ESCAPE.search(text) and _lone_surrogate(tx):
        return None
    return tx if shaped(tx) else None


def records(paths, stats):
    """Yield (line, tx) for each well-formed line of the named inputs (stdin when none
    is named, or for "-"), once per signature. stats["dupes"] counts the later copies
    skipped, and stats["bad"] gets [input, count, first line] for each input that had
    malformed lines."""
    seen = set()
    for n, path in enumerate(paths or ["-"], 1):
        label = "stdin" if path == "-" else "input %d (%s)" % (n, shown(path))
        fh = sys.stdin.buffer if path == "-" else opened(path)
        bad = None
        try:
            for i, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line:
                    continue
                tx = parsed(line)
                if tx is None:
                    if bad is None:
                        bad = [label, 0, i]
                        stats["bad"].append(bad)
                    bad[1] += 1
                    continue
                sigs = (tx.get("transaction") or {}).get("signatures")
                if sigs:
                    if sigs[0] in seen:
                        stats["dupes"] += 1
                        continue
                    seen.add(sigs[0])
                yield line, tx
        finally:
            if path != "-":
                fh.close()


def skipped(stats):
    """What was skipped, each phrase to follow the word "skipped": the later copies of a
    transaction, then the malformed lines of each input, which are collection gaps."""
    notes = []
    if stats["dupes"]:
        notes.append("%d transaction(s) already read under the same signature" % stats["dupes"])
    for label, count, first in stats["bad"]:
        notes.append("%d malformed line(s) in %s, the first at line %d (not a getTransaction JSON object"
                     " the recipes can read)" % (count, label, first))
    return notes
# ---- end of input contract ----


def main(argv: list[str]) -> int:
    usage = "usage: deltas.py lamports|tokens [--out <file>] [<corpus.jsonl> ...]"
    if not argv or argv[0] not in ("lamports", "tokens"):
        print(usage, file=sys.stderr)
        return 2
    mode, files, out_path = argv[0], argv[1:], None
    if files[:1] == ["--out"]:
        if len(files) < 2:
            print(usage, file=sys.stderr)
            return 2
        out_path, files = files[1], files[2:]
    problem = unusable(files)
    if problem is None and out_path is not None:
        problem = unwritable(out_path)
    if problem:
        print("deltas.py: " + problem[1], file=sys.stderr)
        return problem[0]
    stats = {"dupes": 0, "bad": []}
    out, keyless = None, 0
    try:
        out = Output(out_path)
        txs = (tx for _line, tx in records(files, stats))
        if mode == "lamports":
            keyless = _lamports(txs, out)
        else:
            _tokens(txs, out)
        out.done()
    except OSError as e:
        print("deltas.py: " + shown(e), file=sys.stderr)
        return 1
    finally:
        if out is not None:
            out.close()
    for note in skipped(stats):
        print("deltas.py: skipped " + note, file=sys.stderr)
    if keyless:
        print("deltas.py: %d row(s) name a balance index that has no account key, as #<index>: the "
              "transaction lists fewer keys than balances (an encoding json export without "
              "meta.loadedAddresses, say)" % keyless, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
