#!/usr/bin/env -S python3 -I
"""frames.py — attribute each program-emitted log line to the program frame that
emitted it, reading a getTransaction JSONL corpus.

Input: one getTransaction result object per line (the `result` field of an RPC
response, encoding `jsonParsed` or `json`), on stdin or in files named as args —
every corpus of an incident at once (`incident_<n>/corpus*/transactions.jsonl`).
Lines are read under the input contract that profile.sh and deltas.py share
(scripts/dnr/README.md): a malformed line is skipped and counted, never echoed.
A named input must be a regular file with one name in a run directory
incident_<n>/ of the working directory, named relative to it and reached through
no symbolic link. Each signature is read once: a later copy of the same
transaction is skipped. Both counts are reported on stderr, the malformed lines
per input, as collection gaps.
Output: JSONL on stdout, or with `--out <file>` (a new .jsonl, .tsv or .txt name
directly in the run directory) in a temporary file beside it that becomes <file>
only once the run is complete, both made through the run directory, opened once.
One record per emitted log line:

    {"sig": "...", "ok": true, "depth": 2, "program": "<id|?>",
     "kind": "log|data|return|truncated|unparsed", "text": "..."}

With `--instructions`, it emits instead what the runtime recorded about each
instruction, for Leg 1's "which instruction ran":

    {"sig", "ok", "kind": "ix", "seq": k, "top": i, "inner": j|null,
     "stack_height": h|null, "program": "<id|?>", "data": "<base58 as given>"|null,
     "data_status": "raw|parsed-only|absent", "accounts": [...]}
        one per instruction, from the transaction's own instruction lists:
        `transaction.message.instructions[i]` (inner = null) and
        `meta.innerInstructions[*].instructions[j]` of top-level instruction i
        (a CPI), in execution order (seq). `data` is exactly what the RPC gave;
        a jsonParsed instruction decoded by the RPC carries `parsed` and
        `program_name` instead, marked "parsed-only". No field of an `ix` record
        comes from the logs.
    {"sig", "ok", "kind": "invoke", "seq": m, "program": "<id>", "depth": N,
     "outcome": "success|failed: ...|null", "ix_seq": k|null}
        one per runtime `Program <id> invoke [N]` line, with the outcome its
        matching success / failed line gave (null when the log ends first), and
        the `ix` record it ran: matched in order on program id and depth (stack
        height); an instruction with no invoke line is passed over.

Design rules, each forced by a real failure mode:

  * Walk `logMessages` one element at a time. Never flatten the array into one
    string and grep it: a `\\n` inside a `Program log:` payload would then forge
    frame lines (adversarial fixture `log-newline-injection.jsonl` turns 2 logs
    into 4 apparent frames under `jq -r '.[]' | grep`). JSON arrays keep each log
    a single element no matter what bytes it contains, so the newline never
    splits a record here.
  * Match invoke / success / failure lines ANCHORED at start-of-string with the
    base58 program-id shape. A program can emit `Program log: ... invoke [1]`
    (Anchor's own client carries a regression test for exactly that string); an
    unanchored contains-match would pop the frame stack on it.
  * A `Program log:` / `Program data:` line is PROGRAM-ASSERTED. It attributes an
    utterance to a frame; it is never proof that a state change happened (KV-122).
    Downstream verdict logic must treat `kind in {log,data,return}` as a hint.
  * Output is JSONL with the raw text in a JSON string, so tabs/newlines inside a
    payload are escaped by the encoder and can never break a column; every other
    character of the input contract's fixed list (DEL, C1 controls, line and
    paragraph separators, bidirectional controls, default-ignorable code points)
    is written as a \\uNNNN escape too (a surrogate pair above U+FFFF, as JSON
    writes one), so none prints raw and the value read back is the same. It is
    written as UTF-8 whatever the locale.

Run it directly by its quoted absolute path, from the working directory under
audit: `"${CLAUDE_PLUGIN_ROOT}/scripts/dnr/frames.py" [--instructions] [--out <file>]
<corpus.jsonl>...`; its first line runs it as `python3 -I`.
Isolated mode keeps the working directory (usually the audited repo) and
PYTHONPATH off sys.path, so it imports nothing beyond the stdlib — keep it that
way: no sibling modules. That is why the input-contract block below is a copy,
kept the same in all three recipes (scripts/tests/test-dnr.sh compares them).

Exit: 0 done · 1 a named input that cannot be read, an --out that cannot be
written, or a write that failed · 2 usage, or a path the input contract refuses (a
missing or non-regular file, one with a second name, one outside a run directory
or reached through a symbolic link, an --out that is not a new name directly in a
run directory). Every input and the --out path are checked before the first
record is written.

No network. stdlib only.
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

# base58 (Bitcoin alphabet) pubkey, 32..44 chars — the shape of a program id. The
# runtime's own lines are matched whole, with ASCII digits only, and an invoke
# depth of at most 9 digits, so reading it as an int can never fail.
_B58 = r"[1-9A-HJ-NP-Za-km-z]{32,44}"
_INVOKE = re.compile(rf"^Program ({_B58}) invoke \[([0-9]{{1,9}})\]\Z")
_EXIT = re.compile(rf"^Program ({_B58}) (success|failed: .*)\Z")
_LOG = "Program log: "
_DATA = "Program data: "
_RETURN = re.compile(rf"^Program return: ({_B58}) (.*)\Z")
_CONSUMED = re.compile(rf"^Program ({_B58}) consumed [0-9]+ of [0-9]+ compute units\Z")


def _rows(tx: dict):
    meta = tx.get("meta") or {}
    txn = tx.get("transaction") or {}
    sigs = txn.get("signatures") or []
    sig = sigs[0] if sigs else "?"
    ok = meta.get("err") is None
    stack: list[str] = []
    for msg in meta.get("logMessages") or []:
        if not isinstance(msg, str):
            continue
        m = _INVOKE.match(msg)
        if m:
            stack.append(m.group(1))
            continue
        if _EXIT.match(msg):
            if stack:
                stack.pop()
            continue
        if _CONSUMED.match(msg):
            continue
        depth = len(stack)
        prog = stack[-1] if stack else "?"
        if msg == "Log truncated":
            yield {"sig": sig, "ok": ok, "depth": depth, "program": prog,
                   "kind": "truncated", "text": ""}
        elif msg.startswith(_LOG):
            yield {"sig": sig, "ok": ok, "depth": depth, "program": prog,
                   "kind": "log", "text": msg[len(_LOG):]}
        elif msg.startswith(_DATA):
            yield {"sig": sig, "ok": ok, "depth": depth, "program": prog,
                   "kind": "data", "text": msg[len(_DATA):]}
        elif (r := _RETURN.match(msg)):
            yield {"sig": sig, "ok": ok, "depth": depth, "program": r.group(1),
                   "kind": "return", "text": r.group(2)}
        else:
            # A runtime diagnostic with no program prefix (e.g. a bare
            # "<pubkey> signer_key().is_none()" before a failure). Keep it,
            # attributed to the open frame, flagged so it is never mistaken for
            # a program-asserted log.
            yield {"sig": sig, "ok": ok, "depth": depth, "program": prog,
                   "kind": "unparsed", "text": msg}


def _keys(tx: dict) -> list:
    """The transaction's account keys, in index order: jsonParsed folds lookup-table
    addresses in; encoding json lists them in meta.loadedAddresses."""
    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = [k.get("pubkey") if isinstance(k, dict) else k for k in msg.get("accountKeys") or []]
    loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
    if isinstance(loaded, dict) and loaded and not any(isinstance(k, dict) for k in msg.get("accountKeys") or []):
        keys += list(loaded.get("writable") or []) + list(loaded.get("readonly") or [])
    return keys


def _ix_record(ix, keys, sig, ok, seq, top, inner):
    if not isinstance(ix, dict):
        ix = {}
    pidx = ix.get("programIdIndex")
    program = ix.get("programId")
    if program is None and type(pidx) is int and 0 <= pidx < len(keys):
        program = keys[pidx]
    accounts = []
    for a in ix.get("accounts") or []:
        accounts.append(keys[a] if type(a) is int and 0 <= a < len(keys) else a)
    rec = {"sig": sig, "ok": ok, "kind": "ix", "seq": seq, "top": top, "inner": inner,
           "stack_height": ix.get("stackHeight"), "program": program or "?",
           "data": ix.get("data") if isinstance(ix.get("data"), str) else None}
    if rec["data"] is not None:
        rec["data_status"] = "raw"
    elif "parsed" in ix:
        rec["data_status"] = "parsed-only"
        rec["program_name"] = ix.get("program")
        rec["parsed"] = ix.get("parsed")
    else:
        rec["data_status"] = "absent"
    rec["accounts"] = accounts
    return rec


def _instruction_rows(tx: dict):
    """`ix` records from the instruction lists, then `invoke` records from the
    runtime's invoke / success / failed lines, each joined to the `ix` it ran."""
    meta = tx.get("meta") or {}
    txn = tx.get("transaction") or {}
    sigs = txn.get("signatures") or []
    sig = sigs[0] if sigs else "?"
    ok = meta.get("err") is None
    keys = _keys(tx)
    inner_by_top: dict = {}
    for group in meta.get("innerInstructions") or []:
        if isinstance(group, dict) and type(group.get("index")) is int:
            inner_by_top.setdefault(group["index"], []).extend(group.get("instructions") or [])
    ixs = []
    for i, ix in enumerate((txn.get("message") or {}).get("instructions") or []):
        ixs.append(_ix_record(ix, keys, sig, ok, len(ixs), i, None))
        for j, inner in enumerate(inner_by_top.get(i, [])):
            ixs.append(_ix_record(inner, keys, sig, ok, len(ixs), i, j))
    yield from ixs
    invokes, stack, ptr = [], [], 0
    for msg in meta.get("logMessages") or []:
        if not isinstance(msg, str):
            continue
        m = _INVOKE.match(msg)
        if m:
            program, depth = m.group(1), int(m.group(2))
            match = None
            while ptr < len(ixs):
                cand = ixs[ptr]
                ptr += 1
                want = 1 if cand["inner"] is None else cand["stack_height"]
                if cand["program"] == program and (depth == want or (want is None and depth >= 2)):
                    match = cand["seq"]
                    break
            rec = {"sig": sig, "ok": ok, "kind": "invoke", "seq": len(invokes), "program": program,
                   "depth": depth, "outcome": None, "ix_seq": match}
            invokes.append(rec)
            stack.append(rec)
            continue
        e = _EXIT.match(msg)
        if e and stack:
            stack.pop()["outcome"] = e.group(2)
    yield from invokes


def _json_escape(m) -> str:
    """A character as a JSON \\uNNNN escape, or a surrogate pair of them above U+FFFF."""
    o = ord(m.group())
    if o < 0x10000:
        return "\\u%04x" % o
    o -= 0x10000
    return "\\u%04x\\u%04x" % (0xD800 + (o >> 10), 0xDC00 + (o & 0x3FF))


def _json_line(row) -> bytes:
    """One record as a JSON line: JSON escapes the C0 controls, and every other
    character of the contract's fixed _UNSAFE list becomes a \\uNNNN escape."""
    text = json.dumps(row, ensure_ascii=False)
    return (_UNSAFE.sub(_json_escape, text) + "\n").encode("utf-8")


# ---- input contract (scripts/dnr/README.md); the same block is in profile.sh, frames.py, deltas.py
_NONE = type(None)
_DIGITS = re.compile("[0-9]+")
_SURROGATE_ESCAPE = re.compile(r"\\u[dD][89a-fA-F]")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
# Brackets may nest this deep, the top-level object being 1. The parser of jq has
# 256 slots and an object takes two of them, so jq reads 128 nested objects and no
# more: at this depth profile.sh never meets a line its queries cannot parse. The
# depth is counted on the text of the line, before it is parsed.
_DEPTH = 128
# One JSON string (its escapes included) or one bracket: what that count reads. The
# closing quote is optional, so a string that never ends is one token, read in one
# pass to the end of the line, and the parser then refuses the line.
_TOKEN = re.compile(r"\"[^\"\\]*(?:\\.[^\"\\]*)*\"?|[\[\]{}]", re.S)
# The characters no key, program id or string version may hold, and that no recipe
# prints raw: the C0 controls, DEL, the C1 controls, the line and paragraph
# separators, the bidirectional controls (U+061C, U+200E-200F, U+202A-202E,
# U+2066-2069), and the code points Unicode marks default-ignorable, which text
# shows as nothing: U+00AD, U+034F, U+061C, U+115F-1160, U+17B4-17B5, U+180B-180F,
# U+200B-200F, U+202A-202E, U+2060-206F, U+3164, U+FE00-FE0F, U+FEFF, U+FFA0,
# U+FFF0-FFF8, U+1BCA0-1BCA3, U+1D173-1D17A and U+E0000-E0FFF. The list is fixed,
# so the same lines are malformed under every Python, whatever Unicode version it
# knows; every other character, assigned or not, prints as itself.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f-\x9f\xad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff]")
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


def _integer(text):
    """A JSON integer, from its literal: at most 20 digits, and never -0, which no RPC
    value is. Every integer of a line is checked, read or not, so every Python reads
    the same lines (3.11 and later refuse to convert more than 4300 digits)."""
    if text == "-0" or len(text.lstrip("-")) > 20:
        raise ValueError("not an integer an RPC response holds")
    return int(text)


_DECODER = json.JSONDecoder(parse_constant=_no_constant, parse_float=_finite, parse_int=_integer)


def shown(text, cap=120):
    """text for a message: printable ASCII, every other character escaped, cut at cap."""
    s = str(text).encode("unicode_escape").decode("ascii")
    return s if len(s) <= cap else s[:cap] + "..."


def installed(path):
    """None when the recipe at path may run, else (2, message): its path holds a quote,
    $, a backtick, a backslash or a control character, so its quoted call cannot match
    as written, or it lies inside the working directory (OUTPUT-RULES.md Rule 11e)."""
    try:
        here, real, given = os.getcwd(), os.path.realpath(path), os.path.abspath(path)
    except OSError as e:
        return 2, "refused: cannot resolve the working directory: %s" % shown(e.strerror or e)
    for p in (given, real):
        if any(c in "\"$`\\" or ord(c) < 0x20 or ord(c) == 0x7f for c in p):
            return 2, ("refused: the installation path holds a quote, $, a backtick, a backslash or a"
                       " control character, so its quoted call cannot match as written")
    if real.startswith(here.rstrip(os.sep) + os.sep):
        return 2, ("refused: the installation lies inside the working directory; install it outside the"
                   " tree under audit (Rule 11e)")
    return None


def refusal(why, usage):
    """(2, message) for arguments outside a recipe grammar."""
    return 2, "refused: %s (usage: %s)" % (why, usage)


# Where a recipe reads and writes: a path names a file in a run directory incident_<n>/
# of the working directory, relative to it, with no empty, . or .. component and no
# symbolic link on the way. An --out file is a new name directly in the run directory,
# of the kinds a recipe writes.
_RUN_DIR = re.compile(rb"incident_[0-9]{1,6}")
_OUT_NAME = re.compile(rb"[A-Za-z0-9][A-Za-z0-9._-]*[.](?:jsonl|tsv|txt)")
# The run directory of each --out path that unwritable() passed, as lstat found it.
_CHECKED = {}


def _parts(path, label):
    """(the components of path as bytes, None) when it has the shape of a path in a run
    directory, else (None, (2, the refusal))."""
    raw = os.fsencode(path)
    parts = (raw[2:] if raw.startswith(b"./") else raw).split(b"/")
    if not raw or len(raw) > 1024:
        why = "is empty or longer than 1024 bytes"
    elif any(c < 0x20 or c == 0x7f for c in raw):
        why = "holds a control character"
    elif raw[:1] in (b"/", b"-", b"~"):
        why = "is not a relative path inside the working directory"
    elif any(p in (b"", b".", b"..") for p in parts):
        why = "has an empty, . or .. component"
    elif len(parts) < 2 or not _RUN_DIR.fullmatch(parts[0]):
        why = "is not a file inside an incident_<n>/ run directory"
    else:
        return parts, None
    return None, (2, "refused: %s %s" % (label, why))


def _inside(path):
    """True when path (bytes, relative) resolves inside the working directory."""
    return os.path.realpath(path).startswith(os.fsencode(os.getcwd()).rstrip(b"/") + b"/")


def _run_dir(name, label):
    """(its lstat, None) when the run directory name (bytes) is a real directory whose
    .gitignore holds * (OUTPUT-RULES.md Rule 11d), else (None, (2, the refusal))."""
    where = "refused: %s is in %s, which" % (label, shown(os.fsdecode(name)))
    try:
        st = os.lstat(name)
    except FileNotFoundError:
        return None, (2, where + " does not exist")
    except OSError as e:
        return None, (2, "%s cannot be checked: %s" % (where, shown(e.strerror or e)))
    if not stat.S_ISDIR(st.st_mode):
        return None, (2, where + " is not a real directory (a symbolic link is not one)")
    text = None
    try:
        if stat.S_ISREG(os.lstat(name + b"/.gitignore").st_mode):
            fd = os.open(name + b"/.gitignore", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    text = os.read(fd, 16)
            finally:
                os.close(fd)
    except OSError:
        pass
    if text not in (b"*", b"*\n"):
        return None, (2, "refused: %s is in %s, whose .gitignore does not hold * (OUTPUT-RULES.md Rule 11d)"
                      % (label, shown(os.fsdecode(name))))
    return st, None


def _confined(path, label):
    """None when path names a regular file with one name in a run directory, reached
    through no symbolic link and resolving inside the working directory, else (2, the
    refusal). Each name on the way is checked with lstat, so a link is refused before
    anything is read through it."""
    parts, problem = _parts(path, label)
    if problem is None:
        problem = _run_dir(parts[0], label)[1]
    if problem is not None:
        return problem
    cur = parts[0]
    for part in parts[1:]:
        cur += b"/" + part
        try:
            st = os.lstat(cur)
        except (FileNotFoundError, NotADirectoryError):
            return 2, "refused: %s does not exist" % label
        except OSError as e:
            return 2, "refused: %s cannot be checked: %s" % (label, shown(e.strerror or e))
        if stat.S_ISLNK(st.st_mode):
            return 2, "refused: %s is a symbolic link, or is reached through one inside the working directory" % label
    if not stat.S_ISREG(st.st_mode):
        return 2, "refused: %s is not a regular file" % label
    if st.st_nlink != 1:
        return 2, "refused: %s has more than one name (a hard link)" % label
    if not _inside(cur):
        return 2, "refused: %s resolves outside the working directory" % label
    return None


def opened(path):
    """One named input, opened for reading through each directory on its way from the
    working directory, none of them followed if it is a symbolic link, and only a
    regular file with one name (a FIFO or a device is not opened for a blocking read)."""
    raw = os.fsencode(path)
    parts = (raw[2:] if raw.startswith(b"./") else raw).split(b"/")
    fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            step = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = step
        f = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)
    try:
        st = os.fstat(f)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise OSError(errno.EINVAL, "not a regular file with one name")
        return os.fdopen(f, "rb")
    except BaseException:
        os.close(f)
        raise


def unusable(paths):
    """None when every named input can be read, else (exit status, message) for the
    first one that cannot: 2 for a path the contract refuses, 1 for a file that cannot
    be opened."""
    for n, path in enumerate(paths, 1):
        label = "input %d (%s)" % (n, shown(path))
        problem = _confined(path, label)
        if problem is not None:
            return problem
        try:
            opened(path).close()
        except OSError as e:
            return 1, "cannot read %s: %s" % (label, shown(e.strerror or e))
    return None


def unwritable(path):
    """None when --out path can take a new output file, else (exit status, message): 2
    for a path that is not a new .jsonl, .tsv or .txt name directly in a run directory
    (an output never replaces a file, an input corpus least of all), 1 for one that
    cannot be checked."""
    label = "--out " + shown(path)
    parts, problem = _parts(path, label)
    if problem is not None:
        return problem
    if len(parts) != 2 or len(parts[1]) > 128 or not _OUT_NAME.fullmatch(parts[1]):
        return 2, "refused: %s is not a .jsonl, .tsv or .txt file directly in the run directory" % label
    st, problem = _run_dir(parts[0], label)
    if problem is not None:
        return problem
    try:
        found = os.lstat(parts[0] + b"/" + parts[1])
    except FileNotFoundError:
        found = None
    except OSError as e:
        return 1, "cannot write %s: %s" % (label, shown(e.strerror or e))
    if found is not None and stat.S_ISLNK(found.st_mode):
        return 2, "refused: %s is a symbolic link" % label
    if found is not None:
        return 2, "refused: %s already exists, and an output never replaces a file: name a new one" % label
    if not _inside(parts[0]):
        return 2, "refused: %s resolves outside the working directory" % label
    _CHECKED[path] = st
    return None


def pinned(path):
    """The run directory of --out path, opened from the working directory without
    following a symbolic link, and the directory unwritable() checked. The output is
    made, named and removed through this descriptor, so a name on its way that is later
    moved or replaced by a link never moves the output elsewhere."""
    raw = os.fsencode(path)
    name = (raw[2:] if raw.startswith(b"./") else raw).split(b"/")[0]
    here = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=here)
    finally:
        os.close(here)
    st, want = os.fstat(fd), _CHECKED.get(path)
    if want is None or (st.st_dev, st.st_ino) != (want.st_dev, want.st_ino):
        os.close(fd)
        raise OSError(errno.EINVAL, "the run directory changed after it was checked")
    return fd


class Output:
    """Where the output goes: stdout, or for --out a new temporary file in the directory
    of the path, which done() links to the path once it is whole, so the path never
    holds a partial output, and never replaces a file that appeared in the meantime.
    That directory is opened once (pinned()), and the temporary file is made, linked
    and removed through it. close() removes a temporary file done() did not link;
    SIGTERM exits through it, and is held off while the temporary file is made, so its
    name is always known."""

    def __init__(self, path):
        self.path, self.dir, self.temp, self.fh = path, None, None, sys.stdout.buffer
        if path is None:
            return
        signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(128 + signum))
        held = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
        try:
            self.dir = pinned(path)
            while self.temp is None:
                temp = ".%s.%s.partial" % (os.path.basename(path), os.urandom(6).hex())
                try:
                    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.dir)
                except FileExistsError:
                    continue
                self.temp = temp
            self.fh = os.fdopen(fd, "wb")
        except BaseException:
            self.close()
            raise
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
            os.link(self.temp, os.path.basename(self.path), src_dir_fd=self.dir, dst_dir_fd=self.dir,
                    follow_symlinks=False)
            os.unlink(self.temp, dir_fd=self.dir)
            self.temp = None

    def close(self):
        if self.temp is not None:
            if self.fh is not sys.stdout.buffer:
                self.fh.close()
            try:
                os.unlink(self.temp, dir_fd=self.dir)
            except OSError:
                pass
            self.temp = None
        if self.dir is not None:
            os.close(self.dir)
            self.dir = None


def _lone_surrogate(text):
    """True when a string of the line, a key or a value (one a later duplicate key
    replaces too), holds a \\u escape that leaves a lone surrogate: jq refuses a lone
    high one wherever it is."""
    for m in _TOKEN.finditer(text):
        s = m.group()
        if s[:1] == "\"" and _SURROGATE_ESCAPE.search(s):
            try:
                if _LONE_SURROGATE.search(_DECODER.decode(s)):
                    return True
            except ValueError:
                return True
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
    if _SURROGATE_ESCAPE.search(text) and _lone_surrogate(text):
        return None
    return tx if shaped(tx) else None


# The longest line read as a transaction, in bytes, its LF left out. A longer one is
# malformed, and is read past to its LF without being kept.
_LINE = 64 << 20


def _lines(fh):
    """Each line of fh without its LF, or None for a line longer than _LINE bytes."""
    while True:
        raw = fh.readline(_LINE + 1)
        if raw.endswith(b"\n"):
            yield raw[:-1]
        elif len(raw) <= _LINE:
            if raw:
                yield raw
            return
        else:
            while raw and not raw.endswith(b"\n"):
                raw = fh.readline(1 << 20)
            yield None


def records(paths, stats):
    """Yield (line, tx) for each well-formed line of the named inputs, which unusable()
    has checked (stdin when none is named), once per signature. stats["dupes"] counts
    the later copies skipped, and stats["bad"] gets [input, count, first line] for each
    input that had malformed lines."""
    seen = set()
    for n, path in enumerate(paths or ["-"], 1):
        label = "stdin" if path == "-" else "input %d (%s)" % (n, shown(path))
        fh = sys.stdin.buffer if path == "-" else opened(path)
        bad = None
        try:
            for i, raw in enumerate(_lines(fh), 1):
                line = raw.strip() if raw is not None else None
                if line == b"":
                    continue
                tx = parsed(line) if line is not None else None
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
    usage = "frames.py [--instructions] [--out <file>] [<corpus.jsonl> ...]"
    problem = installed(__file__)
    rows, out_path, given = _rows, None, set()
    while problem is None and argv[:1] and argv[0].startswith("-"):
        if argv[0] == "--instructions" and argv[0] not in given:
            rows, argv = _instruction_rows, argv[1:]
            given.add("--instructions")
        elif argv[0] == "--out" and argv[0] not in given:
            if len(argv) < 2:
                problem = refusal("--out needs a file", usage)
                break
            out_path, argv = argv[1], argv[2:]
            given.add("--out")
        else:
            problem = refusal("option %s is unknown here or given twice" % shown(argv[0]), usage)
    if problem is None:
        problem = unusable(argv)
    if problem is None and out_path is not None:
        problem = unwritable(out_path)
    if problem:
        print("frames.py: " + problem[1], file=sys.stderr)
        return problem[0]
    stats = {"dupes": 0, "bad": []}
    out = None
    try:
        out = Output(out_path)
        for _line, tx in records(argv, stats):
            for row in rows(tx):
                out.write(_json_line(row))
        out.done()
    except OSError as e:
        print("frames.py: " + shown(e), file=sys.stderr)
        return 1
    finally:
        if out is not None:
            out.close()
    for note in skipped(stats):
        print("frames.py: skipped " + note, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
