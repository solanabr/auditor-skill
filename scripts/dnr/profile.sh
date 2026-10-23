#!/usr/bin/env bash
# profile.sh — baseline a getTransaction JSONL corpus WITHOUT reading it into a
# context window. Prints a handful of small aggregates: the numbers you quote in
# the ledger, each the output of one query over the corpus.
#
#   bash "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh" <corpus.jsonl> [<corpus.jsonl> ...]
#
# Give it every corpus of an incident at once (incident_<n>/corpus*/transactions.jsonl):
# each transaction is counted once, at the first line that carries its signature, and
# the number of later copies skipped is reported at the end. Lines are read under the
# input contract that frames.py and deltas.py share (README.md): a malformed line is
# skipped and counted too, never echoed, instead of stopping the profile, and a file
# that is a symbolic link, or reached through one inside the working directory, is
# refused. The closing "-- skipped" lines are printed on stderr as well, before any
# query runs; the malformed lines of each input are collection gaps.
#
# What it reports (all from structural fields, never from log text):
#   - transaction count and the finalized/failed split (meta.err)
#   - version histogram (legacy / 0 / 1)
#   - time window (min/max blockTime, when present)
#   - fee-payer inventory: accountKeys[0].pubkey, top 20 by count
#   - signer inventory: every accountKeys[].signer == true, top 20 by count
#   - top-level program inventory: instructions[].programId (jsonParsed) or
#     programIdIndex resolved through accountKeys (encoding: json), top 20 by
#     count  (the ACTUAL invoked programs, read from the instruction list — NOT
#     parsed out of logMessages, where a program-emitted line can forge an
#     "invoke" entry; see frames.py for log attribution)
#
# It deliberately does NOT touch logMessages or balances: those go through
# frames.py and deltas.py, which handle the newline-forgery and >2^53 hazards.
#
# Top-20 lists end in `sed -n '1,20p'`, never `head`: under `set -o pipefail` a
# reader that exits early hands `sort` a SIGPIPE once the list outgrows the pipe
# buffer, and the script would stop with 141 halfway through the profile.
#
# Uses jq per line. jq is fine for counting scalars and grouping base58 strings;
# it is only unsafe for u64 ARITHMETIC (see deltas.py) and for flattening the log
# array (see frames.py). The one-per-signature pass runs as `python3 -I` and keeps
# each well-formed line byte for byte, less surrounding whitespace.
#
# Exit: 0 done · 1 a corpus file that cannot be read · 2 usage, no such file, or a
# file that is a symbolic link, or reached through one inside the working directory
# · 3 jq or python3 missing (a named blocker). Every file is checked before anything
# is printed. bash >= 3.2, jq, python3, no network.

set -euo pipefail

usage() { echo "usage: profile.sh <corpus.jsonl> [<corpus.jsonl> ...]" >&2; exit 2; }
[ "$#" -gt 0 ] || usage
for f in "$@"; do [[ "$f" != - && -f "$f" ]] || usage; done
for tool in jq python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "[blocker] $tool is not on PATH; profile.sh needs jq and python3." >&2; exit 3; }
done

# One pass keeps the first line of each signature, across every file given, in a
# private temp file that the queries below read, leaving out malformed lines under
# the input contract that frames.py and deltas.py share (README.md). It checks every
# input first, writes the report's header line with each path escaped, and writes
# the closing "-- skipped" lines, which it also prints on stderr before any query
# runs.
tmpd="$(mktemp -d "${TMPDIR:-/tmp}/dnr_profile.XXXXXX")"
trap 'rm -rf "$tmpd"' EXIT
corpus="$tmpd/corpus.jsonl"
python3 -I -c 'import errno, json, math, os, re, stat, sys
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

tmpd, paths = sys.argv[1], sys.argv[2:]
problem = unusable(paths)
if problem:
    print("profile.sh: " + problem[1], file=sys.stderr)
    sys.exit(problem[0])
stats = {"dupes": 0, "bad": []}
with open(os.path.join(tmpd, "corpus.jsonl"), "wb") as out:
    for line, tx in records(paths, stats):
        out.write(line + b"\n")
with open(os.path.join(tmpd, "header"), "w") as out:
    out.write("== corpus: " + " ".join(shown(p) for p in paths) + "\n")
with open(os.path.join(tmpd, "notes"), "w") as out:
    for note in skipped(stats):
        out.write("-- skipped: " + note + "\n")
        print("profile.sh: skipped " + note, file=sys.stderr)' "$tmpd" "$@"

# report: the profile, from the deduplicated corpus.
report() {
cat "$tmpd/header"
echo "-- transactions / outcome"
jq -r 'if (.meta.err == null) then "ok" else "failed" end' "$corpus" | sort | uniq -c
echo "-- version"
jq -r '(.version // "legacy") | tostring' "$corpus" | sort | uniq -c
echo "-- time window (blockTime)"
jq -r '.blockTime // empty' "$corpus" | sort -n | awk '
  NR==1 {min=$0} {max=$0} END {
    if (NR) printf "   first=%s  last=%s  spanning=%d entries with a blockTime\n", min, max, NR
    else    print "   (no blockTime on these entries)"
  }'
# accountKeys are objects ({pubkey, signer, ...}) in jsonParsed and plain strings in
# encoding: json; every query below normalises with `key`.
KEYDEF='def key: if type == "object" then .pubkey else . end;'
echo "-- fee payers (accountKeys[0], top 20)"
jq -r "$KEYDEF"' (.transaction.message.accountKeys[0] // empty) | key' "$corpus" \
  | sort | uniq -c | sort -rn | sed -n '1,20p'
echo "-- signers (top 20)"
# jsonParsed marks each key's `signer`; encoding: json puts the signers first, the
# count in message.header.numRequiredSignatures.
jq -r "$KEYDEF"'
  .transaction.message as $m
  | ($m.accountKeys // []) as $ak
  | if (($ak[0] // null) | type) == "object"
    then ($ak[] | select((.signer // false) == true) | .pubkey)
    else ($ak[0:($m.header.numRequiredSignatures // 1)][] | key)
    end' "$corpus" \
  | sort | uniq -c | sort -rn | sed -n '1,20p'
echo "-- top-level programs invoked (instructions[].programId / programIdIndex, top 20)"
# jsonParsed carries `programId`; encoding: json carries `programIdIndex` into the
# static accountKeys (a top-level program id is always a static key, never one
# loaded from a lookup table), so resolve the index when the id is absent.
jq -r "$KEYDEF"'
  .transaction.message as $m
  | (($m.accountKeys // []) | map(key)) as $keys
  | $m.instructions[]?
  | (.programId // (if .programIdIndex != null then $keys[.programIdIndex] else empty end)) // empty' "$corpus" \
  | sort | uniq -c | sort -rn | sed -n '1,20p'
cat "$tmpd/notes"
}
report
