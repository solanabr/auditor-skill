#!/bin/bash
# profile.sh — baseline a getTransaction JSONL corpus WITHOUT reading it into a
# context window. Prints a handful of small aggregates: the numbers you quote in
# the ledger, each the output of one query over the corpus.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh" [--out <file>] <corpus.jsonl> [<corpus.jsonl> ...]
#
# Run it directly by its quoted absolute path, from the working directory under audit.
# Give it every corpus of an incident at once (incident_<n>/corpus*/transactions.jsonl):
# each transaction is counted once, at the first line that carries its signature, and
# the number of later copies skipped is reported at the end. Lines are read under the
# input contract that frames.py and deltas.py share (README.md): a malformed line is
# skipped and counted too, never echoed, instead of stopping the profile. Every path is
# relative to the working directory and names a regular file with one name in a run
# directory incident_<n>/ there, reached through no symbolic link; any other is refused
# before any input is read. The closing "-- skipped" lines are printed on stderr as
# well, before any query runs; the malformed lines of each input are collection gaps.
# With --out, the finished report goes to a new .jsonl, .tsv or .txt file directly in
# the run directory, through a temporary file beside it that gets the report's name
# only once it is whole; the run directory is opened once, never through a symbolic
# link.
#
# What it reports (all from structural fields, never from log text):
#   - transaction count and the finalized/failed split (meta.err)
#   - version histogram (legacy / 0 / 1; a version that is not a string as its JSON
#     text, with no character of the contract's fixed list raw)
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
# each well-formed line byte for byte, less surrounding whitespace. scripts/lib/
# confine.sh sets LC_ALL=C and umask 077 and keeps only PATH entries outside the
# working directory; the private temp directory must lie outside it too.
#
# Exit: 0 done · 1 a corpus file that cannot be read, or an --out that cannot be
# written · 2 usage, or a refused path: a missing or non-regular file, one with a
# second name, one outside a run directory or reached through a symbolic link, or
# an --out that is not a new name directly in a run directory · 3 jq or python3
# missing (a named blocker). Every file is checked before anything is printed.
# bash >= 3.2, jq, python3, no network.

set -euo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { echo "profile.sh: refused: the installation cannot be resolved" >&2; exit 2; }
. "${here%/*}/lib/confine.sh" || { echo "profile.sh: refused: scripts/lib/confine.sh cannot be read" >&2; exit 2; }
# Every recipe refuses with exit 2 (README.md, Input contract), confine.sh with 64.
confine_refuse() { printf '%s: refused: %s\n' "$CONFINE_TOOL" "$1" >&2; exit 2; }
confine_init profile.sh "${here%/*/*}"
for tool in jq python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "[blocker] $tool is not on PATH; profile.sh needs jq and python3." >&2; exit 3; }
done

# One pass keeps the first line of each signature, across every file given, in a
# private temp file that the queries below read, leaving out malformed lines under
# the input contract that frames.py and deltas.py share (README.md). It checks the
# arguments, every input and the --out path first, writes the report's header line
# with each path escaped, and writes the closing "-- skipped" lines, which it also
# prints on stderr before any query runs. The same program, run as "publish", writes
# the finished report to --out.
tmpd="$(mktemp -d "${TMPDIR:-/tmp}/dnr_profile.XXXXXX")"
trap 'rm -rf "$tmpd"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
confine_phys "$tmpd" || confine_refuse "its temp directory cannot be resolved"
case "$CONFINE_PHYS/" in
  "${CONFINE_WT%/}/"*) confine_refuse "its temp directory lies inside the working directory; set TMPDIR outside it" ;;
esac
corpus="$tmpd/corpus.jsonl"
recipe='import errno, json, math, os, re, signal, stat, sys
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
# The device and inode of each input _confined() passed, as lstat found it: opened()
# reads only that file.
_INPUTS = {}


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
    _INPUTS[path] = (st.st_dev, st.st_ino)
    return None


def opened(path):
    """One named input, opened for reading through each directory on its way from the
    working directory, none of them followed if it is a symbolic link, and only the
    regular file with one name that _confined() checked (a FIFO or a device is not
    opened for a blocking read)."""
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
        if _INPUTS.get(path) != (st.st_dev, st.st_ino):
            raise OSError(errno.EINVAL, "it changed after it was checked")
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
    SIGTERM, SIGINT and SIGHUP exit through it, unless the caller ignores them, and are
    held off while the temporary file is made, so its name is always known."""

    def __init__(self, path):
        self.path, self.dir, self.temp, self.fh = path, None, None, sys.stdout.buffer
        if path is None:
            return
        stops = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]
        held = signal.pthread_sigmask(signal.SIG_BLOCK, stops)
        for s in stops:
            if signal.getsignal(s) != signal.SIG_IGN:
                signal.signal(s, lambda signum, frame: sys.exit(128 + signum))
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
    has checked (stdin when none is named; a closed stdin reads as empty), once per
    signature. stats["dupes"] counts the later copies skipped, and stats["bad"] gets
    [input, count, first line] for each input that had malformed lines. An input that
    cannot be opened again raises an OSError whose strerror names it."""
    seen = set()
    for n, path in enumerate(paths or ["-"], 1):
        label = "stdin" if path == "-" else "input %d (%s)" % (n, shown(path))
        if path == "-":
            fh = sys.stdin.buffer if sys.stdin is not None else None
        else:
            try:
                fh = opened(path)
            except OSError as e:
                raise OSError(e.errno, "cannot read %s: %s" % (label, shown(e.strerror or e))) from None
        bad = None
        try:
            for i, raw in enumerate(_lines(fh) if fh is not None else (), 1):
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


def call(argv):
    """(the --out path or None, the corpus paths, None) from the arguments of
    profile.sh, else (None, None, the refusal)."""
    usage = "profile.sh [--out <file>] <corpus.jsonl> [<corpus.jsonl> ...]"
    out_path = None
    if argv[:1] == ["--out"]:
        if len(argv) < 2:
            return None, None, refusal("--out needs a file", usage)
        out_path, argv = argv[1], argv[2:]
    if argv[:1] and argv[0].startswith("-"):
        return None, None, refusal("option %s is unknown here or given twice" % shown(argv[0]), usage)
    if not argv:
        return None, None, refusal("profile needs at least one corpus", usage)
    return out_path, argv, None


step, tmpd, script = sys.argv[1:4]
out_path, paths, problem = None, [], installed(script)
if problem is None:
    out_path, paths, problem = call(sys.argv[4:])
if problem is None and step == "check":
    problem = unusable(paths)
if problem is None and out_path is not None:
    problem = unwritable(out_path)
if problem:
    print("profile.sh: " + problem[1], file=sys.stderr)
    sys.exit(problem[0])
if step == "publish":
    # The finished report, from the private temp directory to --out through Output,
    # after the --out path is checked again.
    out = None
    try:
        out = Output(out_path)
        with open(os.path.join(tmpd, "report"), "rb") as report:
            out.write(report.read())
        out.done()
    except OSError as e:
        sys.exit("profile.sh: cannot write --out: " + shown(e.strerror or e))
    finally:
        if out is not None:
            out.close()
    sys.exit(0)
stats = {"dupes": 0, "bad": []}
try:
    with open(os.path.join(tmpd, "corpus.jsonl"), "wb") as out:
        for line, tx in records(paths, stats):
            out.write(line + b"\n")
except OSError as e:
    sys.exit("profile.sh: " + (e.strerror or shown(e)))
with open(os.path.join(tmpd, "header"), "w") as out:
    out.write("== corpus: " + " ".join(shown(p) for p in paths) + "\n")
with open(os.path.join(tmpd, "notes"), "w") as out:
    for note in skipped(stats):
        out.write("-- skipped: " + note + "\n")
        print("profile.sh: skipped " + note, file=sys.stderr)'
python3 -I -c "$recipe" check "$tmpd" "$here/profile.sh" "$@"

# report: the profile, from the deduplicated corpus. Every sort and uniq runs under
# LC_ALL=C and compares bytes: under a UTF-8 locale, sort and uniq can count two keys
# that differ only in a character the collation ignores (U+00A0, say) as one line,
# and order ties by that locale. Under C, each key is its own line and every tie
# falls in the same order wherever the profile runs.
report() {
cat "$tmpd/header"
echo "-- transactions / outcome"
jq -r 'if (.meta.err == null) then "ok" else "failed" end' "$corpus" | LC_ALL=C sort | LC_ALL=C uniq -c
echo "-- version"
# A version that is not a string prints as its JSON text (tostring), where jq escapes
# the C0 controls and DEL; every other character of the fixed _UNSAFE list becomes a
# \uNNNN escape too (lowercase hex; a surrogate pair above U+FFFF), as frames.py
# writes it, so none prints raw. `unsafe` holds _UNSAFE's code points, in decimal.
jq -r '
  def hex4: [(. / 4096 | floor), (. / 256 | floor) % 16, (. / 16 | floor) % 16, . % 16]
    | map("0123456789abcdef"[.:. + 1]) | add;
  def escape: if . < 65536 then "\\u" + hex4
    else (. - 65536) as $c
    | "\\u" + (55296 + ($c / 1024 | floor) | hex4) + "\\u" + (56320 + $c % 1024 | hex4) end;
  def unsafe: . < 32 or (. >= 127 and . < 160) or . == 173 or . == 847 or . == 1564
    or . == 4447 or . == 4448 or . == 6068 or . == 6069 or (. >= 6155 and . < 6160)
    or (. >= 8203 and . < 8208) or (. >= 8232 and . < 8239) or (. >= 8288 and . < 8304)
    or . == 12644 or (. >= 65024 and . < 65040) or . == 65279 or . == 65440
    or (. >= 65520 and . < 65529) or (. >= 113824 and . < 113828)
    or (. >= 119155 and . < 119163) or (. >= 917504 and . < 921600);
  (.version // "legacy")
  | if type == "string" then .
    else [tostring | explode[] | if unsafe then (escape | explode[]) else . end] | implode
    end' "$corpus" | LC_ALL=C sort | LC_ALL=C uniq -c
echo "-- time window (blockTime)"
jq -r '.blockTime // empty' "$corpus" | LC_ALL=C sort -n | awk '
  NR==1 {min=$0} {max=$0} END {
    if (NR) printf "   first=%s  last=%s  spanning=%d entries with a blockTime\n", min, max, NR
    else    print "   (no blockTime on these entries)"
  }'
# accountKeys are objects ({pubkey, signer, ...}) in jsonParsed and plain strings in
# encoding: json; every query below normalises with `key`.
KEYDEF='def key: if type == "object" then .pubkey else . end;'
echo "-- fee payers (accountKeys[0], top 20)"
jq -r "$KEYDEF"' (.transaction.message.accountKeys[0] // empty) | key' "$corpus" \
  | LC_ALL=C sort | LC_ALL=C uniq -c | LC_ALL=C sort -rn | sed -n '1,20p'
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
  | LC_ALL=C sort | LC_ALL=C uniq -c | LC_ALL=C sort -rn | sed -n '1,20p'
echo "-- top-level programs invoked (instructions[].programId / programIdIndex, top 20)"
# jsonParsed carries `programId`; encoding: json carries `programIdIndex` into the
# static accountKeys (a top-level program id is always a static key, never one
# loaded from a lookup table), so resolve the index when the id is absent.
jq -r "$KEYDEF"'
  .transaction.message as $m
  | (($m.accountKeys // []) | map(key)) as $keys
  | $m.instructions[]?
  | (.programId // (if .programIdIndex != null then $keys[.programIdIndex] else empty end)) // empty' "$corpus" \
  | LC_ALL=C sort | LC_ALL=C uniq -c | LC_ALL=C sort -rn | sed -n '1,20p'
cat "$tmpd/notes"
}

# With --out (only ever the first word, once the check has passed), the report is
# written whole into the private temp directory first, then to a temporary file beside
# <file>, which is linked to <file>; a link never replaces a file that appeared in the
# meantime.
if [ "${1-}" != --out ]; then
  report
else
  report > "$tmpd/report"
  python3 -I -c "$recipe" publish "$tmpd" "$here/profile.sh" "$@"
fi
