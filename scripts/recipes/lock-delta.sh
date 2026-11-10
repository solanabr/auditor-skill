#!/bin/bash
# lock-delta.sh — the lockfile hints of checklists/11-supply-chain.md §11.11: each version, source and checksum
# line that changed in the lockfiles between two commits, with the name of its package; and, for its CI budget,
# the set of name@version entries those lockfiles add.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/recipes/lock-delta.sh" [--repo <dir> | --git-dir <R>/src[-<k>].git] npm|bun|cargo <base>..<head>
#   "${CLAUDE_PLUGIN_ROOT}/scripts/recipes/lock-delta.sh" [--repo <dir> | --git-dir <R>/src[-<k>].git] --run <R> set <base>..<head>
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under audit.
# Its checks hold whatever words follow, and a refusal is one stderr line, "lock-delta: refused: <reason>", with
# exit 64, before git reads the history.
#
# What it prints, for the lockfiles of that kind anywhere in the tree, below each file's "+++ b/<path>" line
# ("+++ /dev/null" for a file the range deletes):
#   npm    package-lock.json, npm-shrinkwrap.json and yarn.lock (v1 and berry): each changed version, resolved,
#          resolution, integrity or checksum line after the key of its entry (an npm alias: after its "name"
#          line), as "<key> <line>", with "?" for a key that lies outside the hunk;
#   bun    the text bun.lock: each changed entry as "<- or +> <name>@<version>";
#   cargo  Cargo.lock: each changed version, source or checksum line after its package name, as "<name> <line>".
#   set    the name@version set difference of each package-lock.json, npm-shrinkwrap.json, yarn.lock (v1),
#          bun.lock, Cargo.lock, uv.lock and poetry.lock the range changes, each read whole at both commits, with
#          the manifest beside it (package.json, Cargo.toml, pyproject.toml) at <head>. One row for each new
#          name@version, and for each version whose checksum changed, goes to <R>/deps/lock-set-<n>.tsv, with the
#          columns eco (npm, crates or pypi), lockfile, name, old (the version it replaces, or -), new, oldsource,
#          source and marks; stdout gets a summary and the rows to read first, and the file on its last line,
#          "lock-set: <R>/deps/lock-set-<n>.tsv (<rows> rows)". A source is public (registry.npmjs.org or
#          registry.yarnpkg.com, crates.io, pypi.org), git, url, file, registry:<host>, unnamed (an npm or yarn
#          entry with no resolved URL, whose registry npm takes from config outside the lockfile) or bundled
#          (inside another package's tarball). A bun.lock entry that names no registry takes the one the
#          bunfig.toml or .npmrc beside it names at that commit (its scope's first), else registry.npmjs.org; a
#          bun.lock whose bunfig.toml or .npmrc changed is compared too, though it did not change. A registry
#          set outside the repository (the environment, user or global config) is not seen. The marks: direct (a
#          dependency the lockfile's root or workspace entries, or the manifest beside it, name), pin (an
#          override, resolution, [patch] or [replace] entry, or a uv override or constraint), key (the closed list
#          of checklist 11 §11.11's CI budget), install (npm's hasInstallScript), source-change (now from the
#          public registry, before from elsewhere), integrity (another copy of a version already there, from
#          another source or with a new or missing checksum),
#          new-dep=<names> (a new version that adds dependencies), url-mismatch (a resolved tarball or a file
#          whose name is not the entry's name and version), close=<name> (a new package one edit away from a
#          name on the closed list) and known-bad (KV-077 Step 2's releases). pnpm-lock.yaml, a yarn berry
#          yarn.lock, bun.lockb and go.sum are named as not compared, with the reason. A lockfile of a kind set
#          reads that it cannot compare (larger than 64 MiB, a link, a submodule, text it cannot read, or a
#          manifest beside it that is a link, over 4 MiB or, for package.json, not a JSON object) is named the
#          same way, and set then exits 3 with the table kept: it is incomplete. Each copy of a name@version is
#          kept apart, so a second copy from another source or with another checksum is a row. Needs python3
#          as well.
#
# --repo <dir> is "." (the default) or a path relative to the working directory, with no "..", and no symbolic
# link on the way, that is the top level of a repository whose git directory lies inside the working directory
# (scripts/lib/confine.sh, as scripts/git-ro.sh takes it, in default and in strict mode). In default mode "." may
# also lie below the top level of a repository that tracks something there: the recipe then reads the lockfiles
# and manifests of that whole repository, as a workspace keeps them at its top. --git-dir names a copy that scripts/git-ro.sh copy
# made in a run directory <R>, audit_<n> or incident_<n>. <base> and <head> name commits: letters, digits and
# ._/~^+-, starting with a letter or a digit, with no "..", at most 255 bytes each.
#
# git runs through the hardened call of scripts/lib/confine.sh (OUTPUT-RULES.md Rule 11c; scripts/git-ro.sh's
# header lists what it switches off), as
#   git diff --no-textconv --no-ext-diff --ignore-submodules=none --text --no-color -U3 <base>..<head> -- <lockfiles>
# with every hunk kept apart, three lines of context and the a/ and b/ prefixes, whatever the checkout's config
# sets, so neither a committed .gitattributes that marks lockfiles binary or -diff nor the checkout's colour,
# context or prefix settings change a line. It reads committed content only, never the work tree. In a partial
# clone a note goes to stderr first ("lock-delta: partial clone: ..."), nothing is fetched and a missing object
# fails; in a shallow clone a note says the history before the boundary is missing.
#
# --run <R>, for set only, is the run directory, audit_<n> or incident_<n>, that the table goes to.
#
# Output: every control character other than TAB and LF, NUL included, prints as ?, on stdout and stderr; a CR
# that ends a lockfile line is dropped first for npm. Standard input is never read.
# Exit: 0 done, whether or not a line printed · 3 set could not compute, compare or keep its table · 64 refused · git's
# own status when git fails (128: a revision it cannot find). Needs bash >= 3.2 and git; env, find, wc, od, tr,
# awk, sed, mktemp and rmdir.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'lock-delta: refused: the installation cannot be resolved\n' >&2; exit 64; }
case "$here" in
  */scripts/recipes) root=${here%/scripts/recipes} ;;
  *) printf 'lock-delta: refused: lock-delta.sh runs from <auditor-skill root>/scripts/recipes\n' >&2; exit 64 ;;
esac
. "$root/scripts/lib/confine.sh" || { printf 'lock-delta: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
confine_init lock-delta "$root"
confine_need env git find wc od tr awk sed mktemp rmdir
exec </dev/null
WT=$CONFINE_WT
REPO=""
RUN=""
SET_S=""

USAGE='usage: lock-delta.sh [--repo <dir> | --git-dir <R>/src.git] npm|bun|cargo <base>..<head>, or [--repo <dir> | --git-dir <R>/src.git] --run <R> set <base>..<head>'

# The npm / yarn hint: a key is an entry's "<name>": { line, its "name" line, or a yarn key at the start of a
# line; each changed field line below it prints after the key the hunk last showed, old (-) or new (+).
NPM_AWK='{sub(/\r$/, "")} /^[+][+][+] /{print} /^@@/{o=n="?"}
  /^[-+ ][[:space:]]*"[^"]*": [{]$/ || /^[-+ ][[:space:]]+"name": / || /^[-+ ][^[:space:]#].*:$/ {k=$0; sub(/^[-+ ][[:space:]]*/, "", k)
    sub(/(: [{]|:|,)$/, "", k); if (/^-/) o=k; else if (/^[+]/) n=k; else o=n=k}
  /^-[[:space:]]+"?(version|resolved|resolution|integrity|checksum)"?:?[[:space:]]/{print o, $0}
  /^[+][[:space:]]+"?(version|resolved|resolution|integrity|checksum)"?:?[[:space:]]/{print n, $0}'
# The text bun.lock: the first array element of an entry is name@version.
BUN_SED='/^\+\+\+ /p; s/^([-+])[[:space:]]+"[^"]+": \["([^"]+)".*/\1 \2/p'
# Cargo.lock: the name line of each [[package]] comes before its version, source and checksum lines.
CARGO_AWK='{sub(/\r$/, "")} /^[+][+][+] /{print} /^@@/{o=n="?"} /^ name = /{o=n=$3} /^-name = /{o=$3} /^[+]name = /{n=$3}
  /^-(version|source|checksum) = /{print o, $0} /^[+](version|source|checksum) = /{print n, $0}'

# set: the set difference, computed from the lockfiles copied into a scratch directory (SET_PY, below).
SET_LOCKS='package-lock.json npm-shrinkwrap.json yarn.lock bun.lock Cargo.lock uv.lock poetry.lock pnpm-lock.yaml bun.lockb go.sum'
SET_MAX=67108864
SET_PY='import json, os, re, sys

# The closed list of key-handling packages (checklist 11 SC-062, with SC-013 and SC-014): a new version of one
# is marked key, and a new name one edit away from one is marked close.
KEY = {
    "npm": ("@solana/web3.js", "@solana/kit", "@solana/keys", "@solana/signers", "@solana/spl-token", "@anchor-lang/core",
            "@coral-xyz/anchor", "tweetnacl", "bip39", "ed25519-hd-key"),
    "crates": ("anchor-lang", "anchor-spl", "solana-program", "solana-sdk", "solana-keypair", "solana-signer",
               "ed25519-dalek", "curve25519-dalek"),
}
KEY_PREFIX = {"npm": ("@solana/wallet-adapter-", "@noble/"), "crates": ()}
# KV-077 Step 2: the known-bad releases.
KNOWN_BAD = {("npm", "axios", "1.14.1"), ("npm", "axios", "0.30.4"), ("npm", "@solana/web3.js", "1.95.6"),
             ("npm", "@solana/web3.js", "1.95.7")}
NPM_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com")
CRATES_SOURCES = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")
PYPI_INDEXES = ("https://pypi.org/simple", "https://pypi.org/simple/")
KINDS = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn", "bun.lock": "bun",
         "Cargo.lock": "cargo", "uv.lock": "uv", "poetry.lock": "poetry"}
NOT_COMPARED = {"pnpm-lock.yaml": "pnpm-lock.yaml needs a YAML parser", "bun.lockb": "bun.lockb is binary: bun itself prints it",
                "go.sum": "Go modules are checked at metadata level only, never fetched"}
ECO = {"npm": "npm", "yarn": "npm", "bun": "npm", "cargo": "crates", "uv": "pypi", "poetry": "pypi"}
MANIFEST = {"npm": "package.json", "yarn": "package.json", "bun": "package.json", "cargo": "Cargo.toml",
            "uv": "pyproject.toml", "poetry": "pyproject.toml"}
Q1 = chr(39)
CTRL = re.compile(r"[\x00-\x1f\x7f]")


def shown(text):
    return CTRL.sub("?", str(text))


class Unread(Exception):
    pass


class Entry:
    def __init__(self, name, version, source, integrity="", deps=(), install=False, files=()):
        self.name, self.version, self.source = name, version, source
        self.integrity, self.deps, self.install, self.files = integrity, set(deps), install, list(files)


# ---- a reader for the TOML that cargo, uv and poetry write ---------------------------------------------
class Toml:
    def __init__(self, text):
        self.s, self.i, self.n = text, 0, len(text)

    def line(self):
        return self.s.count("\n", 0, self.i) + 1

    def bad(self, why):
        raise Unread("line %d: %s" % (self.line(), why))

    def peek(self, k=0):
        j = self.i + k
        return self.s[j] if j < self.n else ""

    def blank(self, newlines):
        while self.i < self.n:
            c = self.s[self.i]
            if c in " \t" or (newlines and c in "\r\n"):
                self.i += 1
            elif c == "#":
                while self.i < self.n and self.s[self.i] != "\n":
                    self.i += 1
            else:
                break

    def key(self):
        parts = []
        while True:
            self.blank(False)
            c = self.peek()
            if c == chr(34) or c == Q1:
                parts.append(self.string())
            else:
                m = re.compile(r"[A-Za-z0-9_-]+").match(self.s, self.i)
                if not m:
                    self.bad("a key is expected")
                parts.append(m.group(0))
                self.i = m.end()
            self.blank(False)
            if self.peek() != ".":
                return parts
            self.i += 1

    def string(self):
        q = self.s[self.i]
        if self.s.startswith(q * 3, self.i):
            end = self.s.find(q * 3, self.i + 3)
            if end < 0:
                self.bad("a string has no end")
            raw = self.s[self.i + 3:end]
            self.i = end + 3
            if raw.startswith("\n"):
                raw = raw[1:]
            return raw if q == Q1 else self.unescape(re.sub(r"\\[ \t]*\r?\n[ \t\r\n]*", "", raw))
        if q == Q1:
            end = self.s.find(Q1, self.i + 1)
            if end < 0 or "\n" in self.s[self.i:end]:
                self.bad("a string has no end")
            raw = self.s[self.i + 1:end]
            self.i = end + 1
            return raw
        j = self.i + 1
        while j < self.n and self.s[j] != chr(34):
            if self.s[j] == "\n":
                self.bad("a string has no end")
            j += 2 if self.s[j] == "\\" else 1
        if j >= self.n:
            self.bad("a string has no end")
        raw = self.s[self.i + 1:j]
        self.i = j + 1
        return self.unescape(raw)

    def unescape(self, raw):
        simple = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", chr(34): chr(34), "\\": "\\"}

        def one(m):
            e = m.group(1)
            if e in simple:
                return simple[e]
            try:
                return chr(int(e[1:], 16))
            except ValueError:
                self.bad("a string has an escape that is not TOML")
        return re.sub(r"\\(u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)", one, raw)

    def value(self, depth=0):
        if depth > 32:
            self.bad("values nest too deep")
        self.blank(False)
        c = self.peek()
        if c == chr(34) or c == Q1:
            return self.string()
        if c == "[":
            self.i += 1
            out = []
            while True:
                self.blank(True)
                if self.peek() == "]":
                    self.i += 1
                    return out
                out.append(self.value(depth + 1))
                self.blank(True)
                if self.peek() == ",":
                    self.i += 1
                elif self.peek() != "]":
                    self.bad("an array is not closed")
        if c == "{":
            self.i += 1
            out = {}
            self.blank(False)
            if self.peek() == "}":
                self.i += 1
                return out
            while True:
                k = self.key()
                if self.peek() != "=":
                    self.bad("an inline table has no =")
                self.i += 1
                self.put(out, k, self.value(depth + 1))
                self.blank(False)
                if self.peek() == ",":
                    self.i += 1
                elif self.peek() == "}":
                    self.i += 1
                    return out
                else:
                    self.bad("an inline table is not closed")
        m = re.compile(r"[A-Za-z0-9_:.+-]+(?:[ T][0-9:.+Z-]+)?").match(self.s, self.i)
        if not m:
            self.bad("a value is expected")
        self.i = m.end()
        return m.group(0)

    def put(self, table, key, value):
        for k in key[:-1]:
            table = table.setdefault(k, {})
            if isinstance(table, list):
                table = table[-1]
            if not isinstance(table, dict):
                self.bad("a key is defined twice")
        table[key[-1]] = value

    def walk(self, root, key, array):
        table = root
        for k in key[:-1]:
            nxt = table.setdefault(k, {})
            if isinstance(nxt, list):
                nxt = nxt[-1] if nxt else self.bad("a table names an empty array")
            if not isinstance(nxt, dict):
                self.bad("a table header names a value")
            table = nxt
        last = key[-1]
        if array:
            arr = table.setdefault(last, [])
            if not isinstance(arr, list):
                self.bad("an array of tables names a table")
            arr.append({})
            return arr[-1]
        nxt = table.setdefault(last, {})
        if isinstance(nxt, list):
            nxt = nxt[-1]
        if not isinstance(nxt, dict):
            self.bad("a table header names a value")
        return nxt

    def document(self):
        root = cur = {}
        while True:
            self.blank(True)
            if self.i >= self.n:
                return root
            if self.peek() == "[":
                array = self.peek(1) == "["
                self.i += 2 if array else 1
                k = self.key()
                if not self.s.startswith("]]" if array else "]", self.i):
                    self.bad("a table header is not closed")
                self.i += 2 if array else 1
                cur = self.walk(root, k, array)
            else:
                k = self.key()
                if self.peek() != "=":
                    self.bad("a key has no =")
                self.i += 1
                self.put(cur, k, self.value())
            self.blank(False)
            if self.i < self.n and self.peek() not in "\r\n":
                self.bad("something follows a value on its line")


def toml(text):
    return Toml(text).document()


# ---- names, versions and sources ------------------------------------------------------------------------
def vkey(v):
    return tuple((0, int(p), "") if re.fullmatch(r"[0-9]+", p) else (1, 0, p) for p in re.split(r"[.+-]", v))


def pypi_name(n):
    return re.sub(r"[-_.]+", "-", n).lower()


def spec_name(spec):
    # an npm spec, name@range: the name ends at the first @ after a scope
    spec = spec.strip().strip(chr(34))
    at = spec.find("@", 1)
    if at < 0:
        return spec, ""
    name, rng = spec[:at], spec[at + 1:]
    if rng.startswith("npm:"):
        real = rng[4:]
        at = real.find("@", 1)
        return (real[:at], real[at + 1:]) if at > 0 else (real, "")
    return name, rng


def spec_source(v):
    # the kind of a version written as a source (git, file or url), or "" for a version number
    if v.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:", "ssh:")):
        return "git"
    if v.startswith(("file:", "link:", "workspace:", "portal:")):
        return "file"
    return "url" if v.startswith(("http:", "https:")) else ""


def registry_kind(url):
    # public for the npm registry and its yarn mirror, registry:<host> for any other
    m = re.match(r"^https?://([^/:@]+)", url or "")
    if not m:
        return "url"
    host = m.group(1).lower()
    return "public" if host in NPM_HOSTS else "registry:" + host


def npm_source(resolved, version, bundled=False):
    # An entry with no resolved URL names no registry: npm then takes the one its config gives, set outside
    # the lockfile (omit-lockfile-registry-resolved), so it is not known to be public. One bundled inside
    # another package ships in that tarball.
    r = resolved or ""
    v = version or ""
    kind = spec_source(r or v)
    if kind in ("git", "file"):
        return kind
    if not r:
        return kind or ("bundled" if bundled else "unnamed")
    m = re.match(r"^https?://([^/:@]+)(?::[0-9]+)?/", r)
    if not m:
        return "url"
    host = m.group(1).lower()
    if host in NPM_HOSTS:
        return "public"
    return "registry:" + host if "/-/" in r else "url"


def npm_url_ok(url, name, version):
    if not url:
        return True
    u = re.sub(r"[#?].*$", "", url)
    m = re.match(r"^https?://[^/]+/(.+)/-/([^/]+)$", u)
    if not m:
        return False
    listed = re.sub(r"%2[fF]", "/", m.group(1))
    return listed == name and m.group(2) == "%s-%s.tgz" % (name.split("/")[-1], version)


def pypi_file_ok(filename, name, version):
    f = filename.rsplit("/", 1)[-1]
    f = re.sub(r"[#?].*$", "", f)
    if f.endswith(".whl"):
        parts = f[:-4].split("-")
        if len(parts) < 3:
            return False
        dist, ver = parts[0], parts[1]
    else:
        stem = re.sub(r"\.(tar\.gz|tar\.bz2|tar\.xz|tgz|zip|tar)$", "", f)
        if stem == f or "-" not in stem:
            return False
        dist, ver = stem.rsplit("-", 1)
    return pypi_name(dist) == pypi_name(name) and ver.lower() == version.lower()


def one_edit(a, b):
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    i = 0
    while i < min(la, lb) and a[i] == b[i]:
        i += 1
    if la == lb:
        if a[i + 1:] == b[i + 1:]:
            return True
        return i + 1 < la and a[i] == b[i + 1] and a[i + 1] == b[i] and a[i + 2:] == b[i + 2:]
    if la > lb:
        return a[i + 1:] == b[i:]
    return b[i + 1:] == a[i:]


def is_key(eco, name):
    if eco == "crates":
        name = name.replace("_", "-")
    return name in KEY.get(eco, ()) or name.startswith(KEY_PREFIX.get(eco, ()))


def close_to(eco, name):
    if is_key(eco, name):
        return ""
    if eco == "crates":
        n = name.replace("_", "-")
        for k in KEY["crates"]:
            if n != k and one_edit(n, k):
                return k
        return ""
    flat = name.lstrip("@").replace("/", "-")
    for k in KEY.get(eco, ()):
        kf = k.lstrip("@").replace("/", "-")
        if one_edit(name, k) or flat == kf or one_edit(flat, kf):
            return k
    return ""


def dep_names(e, fields=("dependencies", "optionalDependencies", "peerDependencies")):
    out = set()
    for f in fields:
        d = e.get(f)
        if isinstance(d, dict):
            out.update(str(k) for k in d)
    return out


# ---- manifests: direct dependencies and pins --------------------------------------------------------------
def package_json(text):
    direct, pins = set(), set()
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        return direct, pins
    if not isinstance(data, dict):
        return direct, pins
    direct = dep_names(data, ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"))

    def keys(d):
        if isinstance(d, dict):
            for k, v in d.items():
                yield str(k)
                for kk in keys(v):
                    yield kk
    over = list(keys(data.get("overrides")))
    pnpm = data.get("pnpm")
    if isinstance(pnpm, dict):
        over += list(keys(pnpm.get("overrides")))
    for k in over:
        for part in k.split(">"):
            n, _ = spec_name(part)
            if n and n != ".":
                pins.add(n)
    for k in keys(data.get("resolutions")):
        segs = [s for s in k.split("/") if s and s != "**"]
        names, j = [], 0
        while j < len(segs):
            if segs[j].startswith("@") and j + 1 < len(segs):
                names.append(segs[j] + "/" + segs[j + 1])
                j += 2
            else:
                names.append(segs[j])
                j += 1
        if names:
            pins.add(spec_name(names[-1])[0])
    return direct, pins


def cargo_toml_pins(text):
    pins, section = set(), ""
    for line in (text or "").splitlines():
        s = line.strip()
        m = re.match(r"^\[\s*([^\]]+?)\s*\]\s*(#.*)?$", s)
        if m:
            section = m.group(1)
            sub = re.match(r"^patch\.(?:" + chr(34) + r"[^" + chr(34) + r"]*" + chr(34) + r"|[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$", section)
            if sub:
                pins.add(sub.group(1))
            continue
        if section.startswith("patch.") or section == "replace":
            k = re.match(r"^" + chr(34) + r"?([A-Za-z0-9_-]+)", s)
            if k and "=" in s:
                pins.add(k.group(1))
    return pins


def pyproject_direct(text):
    try:
        doc = toml(text or "")
    except Unread:
        return set()

    def table(d, k):
        v = d.get(k) if isinstance(d, dict) else None
        return v if isinstance(v, dict) else {}
    out = set()
    poetry = table(table(doc, "tool"), "poetry")
    groups = [poetry] + [g for g in table(poetry, "group").values() if isinstance(g, dict)]
    for g in groups:
        for key in ("dependencies", "dev-dependencies"):
            out |= {pypi_name(k) for k in table(g, key) if k.lower() != "python"}
    project = table(doc, "project")
    reqs = list(project.get("dependencies") or []) if isinstance(project.get("dependencies"), list) else []
    for v in list(table(project, "optional-dependencies").values()) + list(table(doc, "dependency-groups").values()):
        if isinstance(v, list):
            reqs += v
    for r in reqs:
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", r) if isinstance(r, str) else None
        if m:
            out.add(pypi_name(m.group(1)))
    return out


# ---- lockfile readers: each returns ({(name, version): Entry}, direct names, pin names) ------------------
def add(out, e):
    # one entry per copy: two copies of a name@version from another source or with another checksum stay apart
    k = (e.name, e.version, e.source, e.integrity)
    if k in out:
        o = out[k]
        o.install = o.install or e.install
        o.deps |= e.deps
        o.files += [f for f in e.files if f not in o.files]
    else:
        out[k] = e


def read_npm(text, man, conf=None):
    try:
        data = json.loads(text)
    except ValueError as why:
        raise Unread("not JSON: %s" % why)
    if not isinstance(data, dict):
        raise Unread("not a JSON object")
    out = {}
    direct, pins = package_json(man)
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, e in packages.items():
            if not isinstance(e, dict):
                continue
            key = str(key)
            if not re.search(r"(^|/)node_modules/", key):
                direct |= dep_names(e, ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"))
                continue
            if e.get("link"):
                continue
            name = e.get("name") if isinstance(e.get("name"), str) and e.get("name") else key.rsplit("node_modules/", 1)[1]
            version = e.get("version")
            if not isinstance(version, str) or not name:
                continue
            resolved = e.get("resolved") if isinstance(e.get("resolved"), str) else ""
            add(out, Entry(name, version, npm_source(resolved, version, bool(e.get("inBundle"))), str(e.get("integrity") or ""),
                           dep_names(e), bool(e.get("hasInstallScript")), [resolved] if resolved else []))
    elif isinstance(data.get("dependencies"), dict):
        stack = [data["dependencies"]]
        while stack:
            deps = stack.pop()
            for name, e in deps.items():
                if not isinstance(e, dict) or not isinstance(e.get("version"), str):
                    continue
                name, version = str(name), e["version"]
                if version.startswith("npm:"):
                    name, version = spec_name(version[4:])
                resolved = e.get("resolved") if isinstance(e.get("resolved"), str) else ""
                req = e.get("requires")
                add(out, Entry(name, version, npm_source(resolved, version, bool(e.get("bundled"))), str(e.get("integrity") or ""),
                               [str(k) for k in req] if isinstance(req, dict) else [], False, [resolved] if resolved else []))
                if isinstance(e.get("dependencies"), dict):
                    stack.append(e["dependencies"])
    else:
        raise Unread("neither packages nor dependencies")
    return out, direct, pins


def read_yarn(text, man, conf=None):
    out, cur, sub = {}, None, None
    if re.search(r"(?m)^__metadata:", text) and not re.search(r"(?m)^  version \x22", text):
        return None
    entries = []
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            if not line.endswith(":"):
                raise Unread("an entry line does not end with a colon: %s" % shown(line[:80]))
            name, _ = spec_name(line[:-1].split(",")[0])
            cur = {"name": name, "version": "", "resolved": "", "integrity": "", "deps": set()}
            entries.append(cur)
            sub = None
            continue
        if cur is None:
            raise Unread("a field comes before any entry")
        ind = len(line) - len(line.lstrip())
        s = line.strip()
        if ind <= 2:
            sub = None
            m = re.match(r"^(version|resolved|integrity)\s+" + chr(34) + r"?([^" + chr(34) + r"]*)" + chr(34) + r"?$", s)
            if m:
                cur[m.group(1)] = m.group(2)
            elif s in ("dependencies:", "optionalDependencies:"):
                sub = cur["deps"]
        elif sub is not None:
            m = re.match(r"^" + chr(34) + r"?([^" + chr(34) + r"\s]+)" + chr(34) + r"?\s", s)
            if m:
                sub.add(m.group(1))
    direct, pins = package_json(man)
    for c in entries:
        if c["name"] and c["version"]:
            add(out, Entry(c["name"], c["version"], npm_source(c["resolved"], c["version"]), c["integrity"], c["deps"],
                           False, [c["resolved"]] if c["resolved"] else []))
    return out, direct, pins


def jsonc(text):
    # JSON with trailing commas and comments, as bun reads bun.lock
    out, i, n, inside = [], 0, len(text), False
    while i < n:
        c = text[i]
        if not inside and text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if not inside and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ValueError("a comment has no end")
            i = j + 2
            continue
        if inside:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == chr(34):
                inside = False
        elif c == chr(34):
            inside = True
            out.append(c)
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(c)
        else:
            out.append(c)
        i += 1
    return json.loads("".join(out))


def bun_registries(conf):
    # the default registry and the registry of each scope that bun takes from the bunfig.toml and .npmrc beside
    # bun.lock; bunfig.toml first. A registry set outside the repository (the environment, user config) is not seen.
    default, scopes = "", {}
    try:
        doc = toml((conf or {}).get("bunfig", ""))
    except Unread:
        doc = {}
    install = doc.get("install") if isinstance(doc.get("install"), dict) else {}

    def url_of(v):
        if isinstance(v, dict):
            v = v.get("url")
        return v if isinstance(v, str) else ""
    default = url_of(install.get("registry"))
    for k, v in (install.get("scopes") if isinstance(install.get("scopes"), dict) else {}).items():
        if url_of(v):
            scopes["@" + str(k).lstrip("@")] = url_of(v)
    for line in (conf or {}).get("npmrc", "").splitlines():
        m = re.match(r"^\s*(@[^:=\s]+:)?registry\s*=\s*(\S+)", line)
        if not m:
            continue
        if m.group(1):
            scopes.setdefault(m.group(1)[:-1], m.group(2).strip(chr(34) + chr(39)))
        elif not default:
            default = m.group(2).strip(chr(34) + chr(39))
    return default, scopes


def read_bun(text, man, conf=None):
    try:
        data = jsonc(text)
    except ValueError as why:
        raise Unread("not JSON: %s" % why)
    if not isinstance(data, dict) or not isinstance(data.get("packages"), dict):
        raise Unread("no packages")
    out = {}
    direct, pins = package_json(man)
    for ws in (data.get("workspaces") or {}).values():
        if isinstance(ws, dict):
            direct |= dep_names(ws, ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"))
    if isinstance(data.get("overrides"), dict):
        pins |= {spec_name(k)[0] for k in data["overrides"]}
    default, scopes = bun_registries(conf)
    for arr in data["packages"].values():
        if not isinstance(arr, list) or not arr or not isinstance(arr[0], str):
            continue
        spec = arr[0]
        at = spec.find("@", 1)
        if at < 0:
            continue
        name, version = spec[:at], spec[at + 1:]
        if version.startswith("workspace:"):
            continue
        source = spec_source(version)
        if not source:
            # the registry the entry names, or "" for the default: that of its scope, else the default the committed
            # config gives, else registry.npmjs.org, as bun has it
            named = arr[1] if len(arr) > 1 and isinstance(arr[1], str) else ""
            scope = name.split("/")[0] if name.startswith("@") else ""
            source = registry_kind(named or scopes.get(scope) or default or "https://registry.npmjs.org/")
        meta = arr[2] if len(arr) > 2 and isinstance(arr[2], dict) else {}
        integ = arr[-1] if isinstance(arr[-1], str) and arr[-1].startswith("sha") else ""
        add(out, Entry(name, version, source, integ, dep_names(meta)))
    return out, direct, pins


def read_cargo(text, man, conf=None):
    doc = toml(text)
    out, direct = {}, set()
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    for p in doc.get("package") or []:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not isinstance(p.get("version"), str):
            continue
        name, version, src = p["name"], p["version"], p.get("source")
        deps = {str(d).split(" ")[0] for d in p.get("dependencies") or [] if isinstance(d, str)}
        if not isinstance(src, str):
            direct |= deps
            continue
        if src in CRATES_SOURCES:
            kind = "public"
        elif src.startswith("git+"):
            kind = "git"
        elif src.startswith(("registry+", "sparse+")):
            h = re.match(r"^[a-z]+\+[a-z]+://([^/:@]+)", src)
            kind = "registry:" + (h.group(1).lower() if h else "?")
        else:
            kind = "url"
        checksum = p.get("checksum") or meta.get("checksum %s %s (%s)" % (name, version, src)) or ""
        add(out, Entry(name, version, kind, str(checksum), deps))
    return out, direct, cargo_toml_pins(man)


def uv_source(src):
    if not isinstance(src, dict):
        return "local"
    if "registry" in src:
        reg = str(src["registry"])
        if reg in PYPI_INDEXES:
            return "public"
        h = re.match(r"^https?://([^/:@]+)", reg)
        return "registry:" + (h.group(1).lower() if h else "?")
    if "git" in src:
        return "git"
    if "url" in src:
        return "url"
    return "local"


def read_uv(text, man, conf=None):
    doc = toml(text)
    out, direct, pins = {}, set(), set()
    manifest = doc.get("manifest") if isinstance(doc.get("manifest"), dict) else {}
    for k in ("overrides", "constraints"):
        for d in manifest.get(k) or []:
            if isinstance(d, dict) and isinstance(d.get("name"), str):
                pins.add(pypi_name(d["name"]))

    def names(v):
        return {pypi_name(d["name"]) for d in v or [] if isinstance(d, dict) and isinstance(d.get("name"), str)}
    for p in doc.get("package") or []:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str):
            continue
        deps = names(p.get("dependencies"))
        kind = uv_source(p.get("source"))
        if kind == "local":
            direct |= deps
            for group in ("optional-dependencies", "dev-dependencies"):
                g = p.get(group)
                if isinstance(g, dict):
                    for v in g.values():
                        direct |= names(v)
            continue
        if not isinstance(p.get("version"), str):
            continue
        files, hashes = [], []
        sd = p.get("sdist")
        for f in ([sd] if isinstance(sd, dict) else []) + [w for w in p.get("wheels") or [] if isinstance(w, dict)]:
            if isinstance(f.get("url"), str):
                files.append(f["url"])
            if isinstance(f.get("hash"), str):
                hashes.append(f["hash"])
        add(out, Entry(pypi_name(p["name"]), p["version"], kind, " ".join(sorted(hashes)), deps, False, files))
    return out, direct, pins


def read_poetry(text, man, conf=None):
    doc = toml(text)
    out = {}
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    old_files = meta.get("files") if isinstance(meta.get("files"), dict) else {}
    for p in doc.get("package") or []:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not isinstance(p.get("version"), str):
            continue
        src = p.get("source")
        kind = "public"
        if isinstance(src, dict):
            t = str(src.get("type") or "")
            url = str(src.get("url") or "")
            if t == "git":
                kind = "git"
            elif t in ("file", "directory"):
                kind = "file"
            elif t == "url":
                kind = "url"
            else:
                h = re.match(r"^https?://([^/:@]+)", url)
                host = h.group(1).lower() if h else "?"
                kind = "public" if url.rstrip("/") in [x.rstrip("/") for x in PYPI_INDEXES] else "registry:" + host
        files = [f for f in (p.get("files") or old_files.get(p["name"]) or []) if isinstance(f, dict)]
        deps = p.get("dependencies") if isinstance(p.get("dependencies"), dict) else {}
        add(out, Entry(pypi_name(p["name"]), p["version"], kind,
                       " ".join(sorted(str(f.get("hash")) for f in files if f.get("hash"))),
                       {pypi_name(k) for k in deps}, False, [str(f.get("file")) for f in files if f.get("file")]))
    return out, pyproject_direct(man), set()


READERS = {"npm": read_npm, "yarn": read_yarn, "bun": read_bun, "cargo": read_cargo, "uv": read_uv, "poetry": read_poetry}


# ---- the set difference ------------------------------------------------------------------------------------
def nearest(old_versions, v):
    below = [o for o in old_versions if vkey(o.version) < vkey(v)]
    if below:
        return max(below, key=lambda o: vkey(o.version))
    return min(old_versions, key=lambda o: vkey(o.version)) if old_versions else None


def compare(kind, path, old, new):
    eco = ECO[kind]
    o_entries, _, _ = old
    n_entries, direct, pins = new
    if eco == "pypi":
        direct = {pypi_name(d) for d in direct}
    by_name, by_version = {}, {}
    for e in o_entries.values():
        by_name.setdefault(e.name, []).append(e)
        by_version.setdefault((e.name, e.version), []).append(e)
    rows, removed = [], 0
    names_new = {e.name for e in n_entries.values()}
    removed = len({(e.name, e.version) for e in o_entries.values() if e.name not in names_new})
    for key, e in n_entries.items():
        if key in o_entries:
            continue
        name, version = e.name, e.version
        marks = []
        same = by_version.get((name, version))
        if same:
            # the same version, another copy: its source or its checksum changed, or the checksum is gone
            o = next((x for x in same if x.source == e.source), same[0])
            marks.append("integrity")
        else:
            o = nearest(by_name.get(name, []), version)
        if name in direct:
            marks.append("direct")
        if name in pins:
            marks.append("pin")
        if is_key(eco, name):
            marks.append("key")
        if e.install:
            marks.append("install")
        if o is not None and e.source == "public" and o.source != "public":
            marks.append("source-change")
        if o is not None and o.version != version:
            added = sorted(e.deps - o.deps)
            if added:
                marks.append("new-dep=" + ";".join(added[:20]) + (";+%d" % (len(added) - 20) if len(added) > 20 else ""))
        if e.source == "public":
            if eco == "npm" and not all(npm_url_ok(u, name, version) for u in e.files):
                marks.append("url-mismatch")
            if eco == "pypi" and not all(pypi_file_ok(u, name, version) for u in e.files):
                marks.append("url-mismatch")
        c = close_to(eco, name)
        if c and o is None:
            marks.append("close=" + c)
        if (eco, name, version) in KNOWN_BAD:
            marks.append("known-bad")
        rows.append((eco, path, name, o.version if o is not None else "-", version,
                     o.source if o is not None else "-", e.source, ",".join(marks) or "-"))
    return rows, removed


def main(scratch, out_tsv, summary_out, fatal_out):
    # not_compared: the lockfiles set names with a reason; fatal: those of a kind set reads, which it could not
    rows, compared, not_compared, removed, fatal = [], [], [], 0, []
    with open(os.path.join(scratch, "list"), encoding="utf-8") as f:
        listing = [line.rstrip("\n").split("\t") for line in f if line.strip()]
    for k, status, m1, m2 in listing:
        with open(os.path.join(scratch, k + ".path"), "rb") as f:
            path = shown(f.read().decode("utf-8", "replace"))
        base = path.rsplit("/", 1)[-1]
        if base in NOT_COMPARED:
            not_compared.append((path, NOT_COMPARED[base]))
            continue
        kind = KINDS.get(base)
        if kind is None:
            continue
        why = ""
        for m in (m1, m2):
            if m == "120000":
                why = "a symbolic link"
            elif m == "160000":
                why = "a submodule"
        if why:
            not_compared.append((path, why))
            fatal.append((path, why))
            continue
        if os.path.exists(os.path.join(scratch, k + ".old.big")) or os.path.exists(os.path.join(scratch, k + ".new.big")):
            why = "larger than 64 MiB"
        mname = MANIFEST[kind]
        if os.path.exists(os.path.join(scratch, k + ".man.link")):
            why = why or "the %s beside it is a symbolic link" % mname
        if os.path.exists(os.path.join(scratch, k + ".man.big")):
            why = why or "the %s beside it is larger than 4 MiB" % mname
        man = ""
        mp = os.path.join(scratch, k + ".man")
        if not why and os.path.exists(mp):
            try:
                with open(mp, encoding="utf-8-sig") as f:
                    man = f.read()
            except UnicodeDecodeError:
                why = "the %s beside it is not UTF-8" % mname
            if not why and mname == "package.json":
                try:
                    ok = isinstance(json.loads(man), dict)
                except (ValueError, RecursionError):
                    ok = False
                if not ok:
                    why = "the package.json beside it is not a JSON object"
        confs = {}
        for side in ("old", "new"):
            confs[side] = {}
            for cname, cfile in (("bunfig", "bunfig.toml"), ("npmrc", ".npmrc")):
                cp = os.path.join(scratch, "%s.%s.%s" % (k, cname, side))
                if os.path.exists(cp + ".link"):
                    why = why or "the %s beside it is a symbolic link" % cfile
                elif os.path.exists(cp + ".big"):
                    why = why or "the %s beside it is larger than 4 MiB" % cfile
                elif os.path.exists(cp):
                    with open(cp, encoding="utf-8-sig", errors="replace") as f:
                        confs[side][cname] = f.read()
        if why:
            not_compared.append((path, why))
            fatal.append((path, why))
            continue
        sides = []
        try:
            for side in ("old", "new"):
                p = os.path.join(scratch, k + "." + side)
                if not os.path.exists(p):
                    sides.append(({}, set(), set()))
                    continue
                with open(p, encoding="utf-8-sig") as f:
                    text = f.read()
                got = READERS[kind](text, man if side == "new" else "", confs[side])
                if got is None:
                    raise Unread("yarn berry")
                sides.append(got)
        except Unread as why:
            if str(why) == "yarn berry":
                not_compared.append((path, "yarn berry yarn.lock needs a YAML parser"))
            else:
                not_compared.append((path, "cannot be read: %s" % shown(why)[:200]))
                fatal.append(not_compared[-1])
            continue
        except (UnicodeDecodeError, RecursionError) as why:
            not_compared.append((path, "cannot be read: %s" % (shown(why)[:200] or type(why).__name__)))
            fatal.append(not_compared[-1])
            continue
        r, gone = compare(kind, path, sides[0], sides[1])
        rows += r
        removed += gone
        compared.append((path, kind, {"A": "added", "D": "deleted", "C": "its registry config changed"}.get(status, "changed"), len(r)))
    with open(fatal_out, "w", encoding="utf-8", errors="backslashreplace") as f:
        for path, why in fatal:
            f.write(shown("%s (%s)" % (path, why)) + "\n")
    with open(out_tsv, "w", encoding="utf-8", errors="backslashreplace") as f:
        f.write("eco\tlockfile\tname\told\tnew\toldsource\tsource\tmarks\n")
        for r in rows:
            f.write("\t".join(shown(x) for x in r) + "\n")
    lines = []
    if compared:
        lines.append("lockfiles compared: " + "; ".join("%s (%s, %s, %d rows)" % c for c in compared))
    else:
        lines.append("lockfiles compared: none")
    for path, why in not_compared:
        lines.append("not compared: %s (%s)" % (path, why))
    names = {(r[0], r[2]) for r in rows}
    bumps = sum(1 for r in rows if r[3] != "-" and r[3] != r[4])
    same = sum(1 for r in rows if r[3] == r[4])
    lines.append("entries: %d (%d new packages, %d new versions of a package, %d copies of a version already there, from another source or with another checksum); %d names; %d packages removed"
                 % (len(rows), len(rows) - bumps - same, bumps, same, len(names), removed))
    kinds = {}
    for r in rows:
        if r[6] not in ("public", "bundled"):
            kinds[r[6].split(":")[0]] = kinds.get(r[6].split(":")[0], 0) + 1
    off = sum(kinds.values())
    bundled = sum(1 for r in rows if r[6] == "bundled")
    lines.append("sources: %d from the public registry; %d not public%s%s" % (len(rows) - off - bundled, off,
                 " (" + ", ".join("%s %d" % kv for kv in sorted(kinds.items())) + "): SC-061, never fetched" if off else "",
                 "; %d bundled inside another package, never fetched" % bundled if bundled else ""))
    count = {}
    for r in rows:
        for m in r[7].split(","):
            if m != "-":
                count[m.split("=")[0]] = count.get(m.split("=")[0], 0) + 1
    order = ("direct", "pin", "key", "install", "source-change", "integrity", "new-dep", "url-mismatch", "close", "known-bad")
    lines.append("marks: " + ", ".join("%s %d" % (m, count.get(m, 0)) for m in order))
    rank = {"known-bad": 0, "url-mismatch": 1, "integrity": 2, "close": 3, "new-dep": 5}

    def strongest(r):
        ms = [rank[m.split("=")[0]] for m in r[7].split(",") if m.split("=")[0] in rank]
        if r[6] not in ("public", "bundled"):
            ms.append(4)
        return min(ms) if ms else None
    flagged = sorted((r for r in rows if strongest(r) is not None), key=strongest)
    for r in flagged[:100]:
        lines.append("  %s %s %s -> %s (%s; source %s%s) %s" % (r[0], r[2], r[3], r[4], r[1], r[6],
                     "" if r[5] in ("-", r[6]) else ", was " + r[5], r[7]))
    if len(flagged) > 100:
        lines.append("  ... %d more flagged rows in the set" % (len(flagged) - 100))
    with open(summary_out, "w", encoding="utf-8", errors="backslashreplace") as f:
        f.write("\n".join(shown(x) for x in lines) + "\n")


try:
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
except SystemExit:
    raise
except BaseException as why:
    print(shown("the set cannot be computed: %s" % (str(why) or type(why).__name__))[:300])
    sys.exit(3)
'

refuse() { confine_refuse "$1"; }
blocker() { printf 'lock-delta: %s\n' "$1" >&2; exit 3; }

check_rev() { # check_rev <name>: status 0 for a commit name of the grammar above
  case "$1" in
    ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._/~^+-]*|*..*) return 1 ;;
  esac
  [ "${#1}" -le 255 ]
}

open_copy() { # open_copy <R>/src[-<k>].git: a copy that git-ro.sh copy made, as git-ro.sh opens it
  local v=${1#./} r rest k shown
  shown=$(confine_text "$1")
  r=${v%%/*}
  rest=${v#*/}
  [ "$r" != "$v" ] || refuse "--git-dir takes <R>/src.git or <R>/src-<k>.git: $shown"
  case "$rest" in
    src.git) ;;
    src-*.git)
      k=${rest#src-}
      k=${k%.git}
      case "$k" in ''|*[!0-9]*) refuse "--git-dir takes <R>/src.git or <R>/src-<k>.git: $shown" ;; esac ;;
    *) refuse "--git-dir takes <R>/src.git or <R>/src-<k>.git: $shown" ;;
  esac
  confine_rundir "$r" "--git-dir's run directory"
  [ -d "$WT/$r/$rest" ] && [ -f "$WT/$r/$rest/auditor-copy" ] ||
    refuse "--git-dir names no copy that git-ro.sh copy made: $shown"
  confine_repo "$r/$rest" "--git-dir"
  [ "$CONFINE_BARE" = true ] || refuse "--git-dir is not a bare repository: $shown"
}

note_history() { # the notes for a partial or a shallow clone
  confine_partial_clone "$REPO" >/dev/null
  case $? in
    0) printf '%s\n' 'lock-delta: partial clone: missing objects are not fetched; history and contents may be incomplete (Rule 11c)' >&2 ;;
    2) refuse "git cannot read the repository's config, so a partial clone cannot be ruled out" ;;
  esac
  if [ -e "$CONFINE_COMMON_DIR/shallow" ]; then
    printf '%s\n' 'lock-delta: shallow clone: history before the shallow boundary is missing (Rule 11c)' >&2
  fi
}

# set_blob <object> <file> <limit>: the blob into <file>, or an empty <file>.big when it is larger than <limit>
set_blob() {
  local size
  size=$(hgit_tree "$REPO" cat-file -s "$1") || return
  case "$size" in ''|*[!0-9]*) return 128 ;; esac
  if [ "$size" -gt "$3" ]; then : > "$2.big"; return 0; fi
  hgit_tree "$REPO" cat-file blob "$1" > "$2"
}

# tree_entry <commit> <path>: TE_MODE and TE_OID of <path> in <commit>, all zeros when it is not there
tree_entry() {
  local entry
  entry=$(hgit_tree "$REPO" ls-tree --full-tree -z "$1" -- "$2" | tr '\000' '\n') || return
  TE_MODE=000000 TE_OID=0000000000000000000000000000000000000000
  [ -n "$entry" ] || return 0
  TE_MODE=${entry%% *}
  entry=${entry#* }
  entry=${entry#* }
  TE_OID=${entry%%$'\t'*}
}

# set_beside <commit> <path> <file>: the file at <path> in <commit> into <file> when it is a regular file of at
# most 4 MiB; an empty <file>.big when it is larger, <file>.link when it is a link; nothing when it is not there.
set_beside() {
  tree_entry "$1" "$2" || return
  case "$TE_MODE" in
    100644|100755) set_blob "$TE_OID" "$3" 4194304 ;;
    120000) : > "$3.link" ;;
  esac
}

# set_entry <path> <status> <mode at base> <mode at head> <object at base> <object at head>: one lockfile, whole,
# into the scratch directory, with the manifest beside it at <head> and, for bun.lock, the registry config bun
# reads beside it at each commit
set_entry() {
  local path=$1 m1=$3 m2=$4 o1=$5 o2=$6 side o m man dir rev
  k=$((k + 1))
  printf '%s' "$path" > "$S/$k.path"
  printf '%s\t%s\t%s\t%s\n' "$k" "${2:0:1}" "$m1" "$m2" >> "$S/list"
  for side in old new; do
    if [ "$side" = old ]; then o=$o1 m=$m1; else o=$o2 m=$m2; fi
    case "$o" in *[!0]*) ;; *) continue ;; esac
    case "$m" in 100644|100755) set_blob "$o" "$S/$k.$side" "$SET_MAX" || return ;; esac
  done
  case "${path##*/}" in
    package-lock.json|npm-shrinkwrap.json|yarn.lock|bun.lock) man=package.json ;;
    Cargo.lock) man=Cargo.toml ;;
    uv.lock|poetry.lock) man=pyproject.toml ;;
    *) man="" ;;
  esac
  case "$path" in */*) dir=${path%/*}/ ;; *) dir="" ;; esac
  if [ -n "$man" ] && [ -e "$S/$k.new" ]; then
    set_beside "$H" "$dir$man" "$S/$k.man" || return
  fi
  if [ "${path##*/}" = bun.lock ]; then
    for side in old new; do
      [ -e "$S/$k.$side" ] || continue
      if [ "$side" = old ]; then rev=$B; else rev=$H; fi
      set_beside "$rev" "${dir}bunfig.toml" "$S/$k.bunfig.$side" || return
      set_beside "$rev" "${dir}.npmrc" "$S/$k.npmrc.$side" || return
    done
  fi
}

# run_set <base> <head> <scratch>: each changed lockfile into <scratch>, as set_entry puts it, and each bun.lock
# whose registry config changed when it did not; the set difference computed there; its rows kept in
# <R>/deps/lock-set-<n>.tsv.
run_set() {
  local B H S=$3 k=0 meta path n D rc dir p listed="" confdirs="" m1 o1
  local -a specs=()
  B=$(hgit_tree "$REPO" rev-parse --verify --end-of-options "$1^{commit}") || exit
  H=$(hgit_tree "$REPO" rev-parse --verify --end-of-options "$2^{commit}") || exit
  for n in $SET_LOCKS bunfig.toml .npmrc; do specs+=("$top*$n"); done
  hgit_text_tree "$REPO" diff --raw -z --no-abbrev --no-renames --no-textconv --no-ext-diff --ignore-submodules=none \
    --end-of-options "$B" "$H" -- "${specs[@]}" > "$S/raw" || exit
  : > "$S/list"
  while IFS= read -r -d '' meta && IFS= read -r -d '' path; do
    set -- $meta
    case "${path##*/}" in
      bunfig.toml|.npmrc)
        case "$path" in */*) confdirs=$confdirs${path%/*}/$'\n' ;; *) confdirs=$confdirs$'\n' ;; esac
        continue ;;
    esac
    listed=$listed$path$'\n'
    set_entry "$path" "$5" "${1#:}" "$2" "$3" "$4" || exit
  done < "$S/raw"
  # a bun.lock whose registry config changed while it did not: its entries may now come from another registry
  printf '%s' "$confdirs" > "$S/confdirs"
  while IFS= read -r dir || [ -n "$dir" ]; do
    p=${dir}bun.lock
    case $'\n'$listed in *$'\n'"$p"$'\n'*) continue ;; esac
    listed=$listed$p$'\n'
    tree_entry "$B" "$p" || exit
    m1=$TE_MODE o1=$TE_OID
    tree_entry "$H" "$p" || exit
    case "$o1$TE_OID" in *[!0]*) set_entry "$p" C "$m1" "$TE_MODE" "$o1" "$TE_OID" || exit ;; esac
  done < "$S/confdirs"
  (cd / && exec python3 -I -c "$SET_PY" "$S" "$S/set.tsv" "$S/summary" "$S/fatal") || blocker "the set cannot be computed"
  D=$WT/$RUN/deps
  if [ ! -d "$D" ] && [ ! -L "$D" ]; then confine_mkdir "$D" || blocker "cannot create $RUN/deps"; fi
  [ -d "$D" ] && [ ! -L "$D" ] || blocker "$RUN/deps is not a directory of its own"
  n=1
  while [ -e "$D/lock-set-$n.tsv" ] || [ -L "$D/lock-set-$n.tsv" ]; do
    n=$((n + 1))
    [ "$n" -le 9999 ] || blocker "$RUN/deps holds 9999 sets"
  done
  confine_new_copy "$S/set.tsv" "$D/lock-set-$n.tsv" || blocker "cannot write $RUN/deps/lock-set-$n.tsv"
  cat "$S/summary"
  rc=$(($(wc -l < "$S/set.tsv") - 1))
  printf 'lock-set: %s/deps/lock-set-%s.tsv (%s rows)\n' "$RUN" "$n" "$rc"
  # a lockfile of a kind set reads that it could not compare: the set is incomplete, and lock-delta did not run
  if [ -s "$S/fatal" ]; then
    blocker "set could not compare $(wc -l < "$S/fatal" | tr -d ' ') of the lockfiles it reads, so the set is incomplete: $(sed -n 1p "$S/fatal")"
  fi
}

delta() { # delta <range> <pathspec>...: the diff the lines are read from
  local range=$1
  shift
  hgit_text_tree "$REPO" -c diff.noprefix=false -c diff.mnemonicPrefix=false -c diff.srcPrefix=a/ -c diff.dstPrefix=b/ \
    diff --no-textconv --no-ext-diff --ignore-submodules=none --text --no-color -U3 --end-of-options "$range" \
    -- "$@" </dev/null
}

main() {
  local a repo=. given=0 gitdir="" what="the working directory" kind range base head top="" run=""
  local -a st=()
  for a in "$@"; do
    case "$a" in *[[:cntrl:]]*) refuse "an argument holds a control character: $(confine_text "$a")" ;; esac
    [ "${#a}" -le 4096 ] || refuse "an argument is longer than 4096 bytes"
  done
  while [ $# -gt 0 ]; do
    case "$1" in
      --repo|--git-dir)
        [ "$given" -eq 0 ] || refuse "give --repo or --git-dir once"
        [ $# -ge 2 ] || refuse "$1 needs a value"
        [ -n "$2" ] || refuse "$1 is empty"
        if [ "$1" = --repo ]; then repo=$2 what=--repo; else gitdir=$2; fi
        given=1
        shift 2 ;;
      --run)
        [ -z "$run" ] || refuse "give --run once"
        [ $# -ge 2 ] || refuse "--run needs a value"
        [ -n "$2" ] || refuse "--run is empty"
        run=$2
        shift 2 ;;
      *) break ;;
    esac
  done
  [ $# -eq 2 ] || refuse "$USAGE"
  kind=$1 range=$2
  case "$kind" in
    npm|bun|cargo) [ -z "$run" ] || refuse "--run is for set, which keeps its table in the run directory" ;;
    set) [ -n "$run" ] || refuse "set needs --run <R>, the run directory its table goes to" ;;
    *) refuse "$USAGE" ;;
  esac
  case "$range" in
    *..*) base=${range%%..*} head=${range#*..} ;;
    *) refuse "the range is <base>..<head>, two commits joined by ..: $(confine_text "$range")" ;;
  esac
  check_rev "$base" && check_rev "$head" ||
    refuse "<base> and <head> name commits: letters, digits and ._/~^+-, starting with a letter or a digit, with no .., at most 255 bytes each: $(confine_text "$range")"
  if [ "$kind" = set ]; then
    confine_rundir "$run" "--run"
    RUN=$CONFINE_RUN
    confine_need python3
    confine_scratch auditor-lockset
    case $? in
      0) ;;
      2) refuse "TMPDIR lies inside the working directory; point it outside the tree under audit" ;;
      *) refuse "no scratch directory can be made under TMPDIR" ;;
    esac
    SET_S=$CONFINE_SCRATCH
    trap 'rm -rf "$SET_S"' EXIT
  fi
  if [ -n "$gitdir" ]; then open_copy "$gitdir"; else confine_repo "$repo" "$what" 0; fi
  REPO=$CONFINE_REPO
  # In a session below the repository's top level, the lockfiles of the whole repository: a workspace
  # keeps them at its top.
  [ -z "$CONFINE_PREFIX" ] || top=':(top)'
  note_history
  if [ "$kind" = set ]; then
    run_set "$base" "$head" "$SET_S"
    exit 0
  fi
  case "$kind" in
    npm) delta "$range" "$top*package-lock.json" "$top*npm-shrinkwrap.json" "$top*yarn.lock" | awk "$NPM_AWK" ;;
    bun) delta "$range" "$top*bun.lock" | sed -nE "$BUN_SED" ;;
    cargo) delta "$range" "$top*Cargo.lock" | awk "$CARGO_AWK" ;;
  esac
  st=("${PIPESTATUS[@]}")
  [ "${st[0]}" -eq 0 ] || exit "${st[0]}"
  exit "${st[1]}"
}

# What git and the parsers print, errors included, goes out with every control character but TAB and LF, NUL
# too, as ?.
CTRL='\000-\010\013-\037\177'
{ main "$@" 2>&1 1>&3 3>&- | tr "$CTRL" '?' 1>&2 3>&-; } 3>&1 | tr "$CTRL" '?'
