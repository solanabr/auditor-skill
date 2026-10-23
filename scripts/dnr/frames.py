#!/usr/bin/env python3
"""frames.py — attribute each program-emitted log line to the program frame that
emitted it, reading a getTransaction JSONL corpus.

Input: one getTransaction result object per line (the `result` field of an RPC
response, encoding `jsonParsed` or `json`), on stdin or in files named as args —
every corpus of an incident at once (`incident_<n>/corpus*/transactions.jsonl`).
Lines are read under the input contract that profile.sh and deltas.py share
(scripts/dnr/README.md): a malformed line is skipped and counted, never echoed,
and a named input that is a symbolic link is refused. Each signature is read
once: a later copy of the same transaction is skipped. Both counts are reported
on stderr, the malformed lines per input, as collection gaps.
Output: JSONL on stdout, or with `--out <file>` in a temporary file beside it
that replaces <file> only once the run is complete. One record per emitted log
line:

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
    payload are escaped by the encoder and can never break a column. It is
    written as UTF-8 whatever the locale.

Run it as `python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/frames.py" [--instructions] [--out <file>] <corpus.jsonl>...`.
Isolated mode keeps the working directory (usually the audited repo) and
PYTHONPATH off sys.path, so it imports nothing beyond the stdlib — keep it that
way: no sibling modules. That is why the input-contract block below is a copy,
kept the same in all three recipes (scripts/tests/test-dnr.sh compares them).

Exit: 0 done · 1 a named input that cannot be read, an --out that cannot be
written, or a write that failed · 2 usage, or a named input or --out that is a
symbolic link, or reached through one inside the working directory. Every input
and the --out path are checked before the first record is written.

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
import tempfile

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


# ---- input contract (scripts/dnr/README.md); the same block is in profile.sh, frames.py, deltas.py
_NONE = type(None)
_DIGITS = re.compile("[0-9]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SURROGATE_ESCAPE = re.compile(r"\\u[dD][89a-fA-F]")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


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
    """None when --out path can take an output file, else (exit status, message): 2 for
    a symbolic link, or a path reached through one inside the working directory, 1
    for a path that is not a regular file or whose directory does not exist."""
    try:
        if linked(path):
            return 2, ("--out %s is a symbolic link, or is reached through one inside the working"
                       " directory; refusing it" % shown(path))
        if os.path.lexists(path) and not os.path.isfile(path):
            return 1, "cannot write --out %s: not a regular file" % shown(path)
        if not os.path.isdir(os.path.dirname(path) or "."):
            return 1, "cannot write --out %s: its directory does not exist" % shown(path)
    except OSError as e:
        return 1, "cannot write --out %s: %s" % (shown(path), shown(e.strerror or e))
    return None


class Output:
    """Where the output goes: stdout, or for --out a new temporary file beside the path
    that done() renames onto it once it is whole, so the path never holds a partial
    output. close() removes a temporary file done() did not rename; SIGTERM exits
    through it."""

    def __init__(self, path):
        self.path, self.temp, self.fh = path, None, sys.stdout.buffer
        if path is not None:
            signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(128 + signum))
            fd, self.temp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                                             prefix="." + os.path.basename(path) + ".", suffix=".partial")
            self.fh = os.fdopen(fd, "wb")

    def write(self, data):
        self.fh.write(data)

    def done(self):
        self.fh.flush()
        if self.temp is not None:
            self.fh.close()
            os.replace(self.temp, self.path)
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


def _of(v, *types):
    """v is null (or absent), or exactly one of types: a bool is not an int."""
    return type(v) in types + (_NONE,)


def _plain(v):
    """A string with no control character, so it prints as one line."""
    return type(v) is str and not _CONTROL.search(v)


def _amount(v):
    """A raw token amount: a string of ASCII digits that Python reads as an int."""
    if type(v) is not str or not _DIGITS.fullmatch(v):
        return False
    try:
        int(v)
    except ValueError:
        return False
    return True


def _instruction(ix):
    return (type(ix) is dict and _of(ix.get("programIdIndex"), int) and _of(ix.get("accounts"), list)
            and (ix.get("programId") is None or _plain(ix.get("programId"))))


def _token_balance(b):
    if type(b) is not dict or not (_of(b.get("accountIndex"), int) and _of(b.get("owner"), str)
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
            and _of((header or {}).get("numRequiredSignatures"), int)
            and all(_instruction(ix) for ix in ixs or [])):
        return False
    if keys and not (all(_plain(k) for k in keys)
                     or all(type(k) is dict and _plain(k.get("pubkey")) for k in keys)):
        return False
    groups, loaded, logs = meta.get("innerInstructions"), meta.get("loadedAddresses"), meta.get("logMessages")
    if not (_of(groups, list) and _of(loaded, dict) and _of(logs, list) and _of(meta.get("fee"), int)
            and all(type(s) is str for s in logs or [])):
        return False
    for g in groups or []:
        if not (type(g) is dict and type(g.get("index")) is int and _of(g.get("instructions"), list)
                and all(_instruction(ix) for ix in g.get("instructions") or [])):
            return False
    for name in ("writable", "readonly"):
        v = (loaded or {}).get(name)
        if not (_of(v, list) and all(type(a) is str for a in v or [])):
            return False
    for name in ("preBalances", "postBalances"):
        v = meta.get(name)
        if not (_of(v, list) and all(type(x) is int for x in v or [])):
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
    rows, out_path = _rows, None
    while argv[:1] in (["--instructions"], ["--out"]):
        if argv[0] == "--instructions":
            rows, argv = _instruction_rows, argv[1:]
        elif len(argv) > 1:
            out_path, argv = argv[1], argv[2:]
        else:
            print("usage: frames.py [--instructions] [--out <file>] [<corpus.jsonl> ...]", file=sys.stderr)
            return 2
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
                out.write((json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8"))
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
