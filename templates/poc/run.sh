#!/usr/bin/env bash
# One-command proof-of-concept runner for the crate in this directory.
#
# Reproduces the finding from a clean checkout of THIS crate:
#   1. builds the `vulnerable` arm to SBF, runs tests/exploit.rs      → exploit must SUCCEED
#   2. builds the `fixed`      arm to SBF, runs tests/fixed_blocked.rs → same attack must be REJECTED
# Exit 0: the exploit reproduces on `vulnerable` and, when the fixed arm runs, is
# blocked on `fixed` — the evidence that earns [PoC-REPRODUCED]. Exit 1: the exploit
# did not reproduce. Exit 2: the fixed arm did not block it. Exits 1 and 2 need a
# contract assertion of that arm (shared-test-utils) that ran and did not hold.
# Exit 3: a named blocker (toolchain, inputs, a build that failed, the execution
# mode below, build-time code in the crate) or an inconclusive arm (no contract
# assertion ran, the test failed outside them, the harness could not decide — a
# harness error such as a wrong program id or a short account list, on either arm
# — or other bytes ran). Record [PoC-ATTEMPTED] with that line, mark the finding
# "PoC re-run needed", and keep the prose PoC.
#
# This file is the installation's templates/poc/run.sh, unedited: nothing in it is
# filled in (the program name comes from Cargo.toml), so a copy can be compared
# with the installation's byte for byte before an OK line is trusted, and
# refreshed from it before a re-run.
#
# Why two build+test passes and not one: both arms compile to the SAME `.so`
# filename (<crate>.so), so they cannot coexist in SBF_OUT_DIR. Build an arm, test
# it, then overwrite with the other arm. Mollusk loads the `.so`, never the host
# test binary — so the SBF build MUST precede each test run.
#
# Toolchain: cargo-build-sbf's default bundle is platform-tools v1.51 / cargo 1.84,
# which cannot parse the edition2024 manifests in the mollusk-svm dep tree. We pin
# --tools-version v1.54 (cargo >= 1.85) to build the graph with no dependency edits.
# Override via TOOLS_VERSION=... if the target repo standardizes on a newer one.
#
# EXECUTION MODE. Building this crate runs code on the machine that builds it: the
# build scripts and proc-macros of every dependency, then the tests. So every run
# needs the execution mode recorded for the audit or incident (OUTPUT-RULES.md Rule
# 11a, QUESTIONS.md Q46): AUDITOR_EXEC_MODE=isolated inside the isolated runner, or
# AUDITOR_EXEC_MODE=native (the report then states that the PoC build ran on this
# host). Without it, run.sh exits 3 before it copies or compiles anything.
#
# WHERE IT BUILDS. This crate normally sits inside the audited repo
# (audit_<n>/poc/…, incident_<n>/poc/…). Built there, cargo would read the target's
# .cargo/config* from every parent directory (rustc-wrapper, runner, linker,
# rustflags, an alias that shadows `build-sbf`), and rustup its rust-toolchain*
# (which can name a `path` toolchain, i.e. any binaries). So, in either mode:
#   * a crate that holds a symbolic link, a .cargo/ directory or a rust-toolchain*
#     file is refused (exit 3): the copy below never takes them.
#   * the crate is copied (without target/) into a fresh scratch directory,
#     `mktemp -d "${TMPDIR:-/tmp}/auditor-poc.XXXXXX"`, and built and tested there
#     with RUSTUP_TOOLCHAIN pinned to the caller's value, else rustup's default. The
#     directory is printed, and removed on exit unless KEEP_POC_BUILD=1; the resolved
#     Cargo.lock is copied back next to this file. A `path` dependency that leaves
#     the crate must therefore be absolute.
#   * the crate's own build-time code is refused (exit 3) before anything compiles:
#     `cargo metadata --no-deps`, run in the scratch copy, lists the crate's packages
#     (the crate, shared-test-utils, any other member), and a build script (`build =
#     false` turns one off), a proc-macro package, a Cargo.toml that is not a member,
#     or a [patch] or [replace] table in a manifest stops the run. Check code that is
#     generated at build time into the crate instead.
#   * the build cache: to reuse compiled dependencies between runs of one
#     engagement, create a directory once per engagement with
#     `mktemp -d "${TMPDIR:-/tmp}/auditor-poc-target.XXXXXX"` (inside the isolated
#     runner in isolated mode), record it next to the execution mode, and pass it to
#     every run as CARGO_TARGET_DIR. Never point CARGO_TARGET_DIR or
#     CARGO_BUILD_TARGET_DIR inside the target tree or at a directory you did not
#     create: cargo trusts the build outputs it finds there. The copy below gets fresh
#     timestamps, so cargo rebuilds the crate's own code on every run and the cache
#     serves only its dependencies. SBF_OUT_DIR stays in the scratch copy either way.
#   * mollusk looks for <crate>.so in tests/fixtures/ and BPF_OUT_DIR before
#     SBF_OUT_DIR, so run.sh unsets BPF_OUT_DIR and refuses a crate holding
#     tests/fixtures/<crate>.so: the bytes that run are the arm run.sh placed.
#
# DEPENDENCY PINS. The template ships a Cargo.lock; keep it with the crate (run.sh
# prints a line when the crate has none, and cargo then resolves every dependency
# to its newest compatible release). A crate the PoC adds keeps every pin it does
# not need to move. When cargo reports a conflict with a pinned release, name that
# pin and run.sh moves it alone, in the scratch copy, before it builds:
#     UPDATE_PINS="solana-program@3.0.0" ./run.sh      # cargo update -p solana-program@3.0.0
# (several pins: separate them with spaces). The moved lock comes back next to this
# file with the rest. Never run cargo update in the crate itself: inside the target
# tree it would read the target's .cargo/config*.
#
# HOW AN ARM IS DECIDED, in either mode:
#   * each arm's test binary is built with `cargo test --no-run` and then run
#     directly, from the package root with CARGO_MANIFEST_DIR and the dynamic
#     library path set as `cargo test` sets them. Only that run gets
#     AUDITOR_POC_MARKERS, a fresh directory per arm; an inherited value is cleared.
#   * every contract assertion leaves markers tagged with the test that ran it. An
#     arm counts only on a contract assertion of that arm that RAN AND HELD, and only
#     when every program the runner helpers (mollusk_for, litesvm_for!) loaded is the
#     .so run.sh placed, unchanged after the test (exit 3 otherwise): load the
#     program under test only through them. A test that passes without one exits 3.
#   * an assertion of the arm that ran and did not hold, in any test, is a verdict
#     (exit 1 or 2), whatever another test left. A test that failed before any
#     assertion ran, or after every one held, and an assertion that could not decide
#     (a harness error, on either arm), exit 3. The markers are a floor, not proof:
#     read the assertion all the same.
#   * before the final line, run.sh prints the non-registry code in the build: the
#     path and git dependencies in the resolved Cargo.lock.
#
# PREBUILT BYTES (incidents under references/detection-response/, or a re-run
# against the target's own builds). Leg 3 of `confirmed_exploited` needs the exploit
# to run on the REAL program bytes, not on this crate's minimized arms:
#     VULNERABLE_SO=/path/to/deployed-or-vulnerable.so ./run.sh
# runs the exploit arm alone on those bytes, and adding
#     FIXED_SO=/path/to/patched-or-current.so
# also runs the fixed arm, on the FIXED_SO bytes. FIXED_SO without VULNERABLE_SO
# exits 3.
#   * a bad path, a file without the ELF magic, or a missing `cargo` or `python3`
#     exits 3 (a named precondition failure, never a bare `cp` error).
#   * the vulnerable arm counts only on assert_exploit_effect!, and the fixed arm
#     only on assert_exploit_rejected_with! (our fix: the guard's exact error) or
#     assert_exploit_blocked! (a fix the team deployed, checked against a
#     legitimate call on the same bytes); the any-result forms count in a model run
#     only.
#   * success prints the one line that can stand for Leg 3, naming the zero-trimmed
#     sha256 of the bytes that ran:
#       OK: reproduced on prebuilt bytes — vulnerable sha256=<64 hex> → [PoC-REPRODUCED]
#     or, with FIXED_SO, "... vulnerable sha256=<…> fixed sha256=<…> (<how the
#     fixed arm held>) → [PoC-REPRODUCED]". A build of this crate's own arms prints
#     another line, and a model is never Leg 3.
#   * an incident whose root cause is supply chain / CI is never built natively, and
#     its PoC never builds or links the target's crates in any mode (they may be the
#     payload): it runs on the dumped ELF here, with the template's own crates
#     (OUTPUT-RULES.md Rule 11a).

set -euo pipefail

TOOLS_VERSION="${TOOLS_VERSION:-v1.54}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# Only the test binary runs below get a marker directory, one run.sh makes.
unset AUDITOR_POC_MARKERS

# ── Execution mode (see EXECUTION MODE above) ───────────────────────────────────
case "${AUDITOR_EXEC_MODE:-}" in
  isolated|native) ;;
  *)
    echo "[PoC-ATTEMPTED] blocker: AUDITOR_EXEC_MODE is '${AUDITOR_EXEC_MODE:-}', not isolated or native — nothing was copied or built." >&2
    echo "Building this crate runs code (dependency build scripts and proc-macros, then the tests), so every run needs the execution mode recorded at intake (OUTPUT-RULES.md Rule 11a, QUESTIONS.md Q46): AUDITOR_EXEC_MODE=isolated inside the isolated runner, or AUDITOR_EXEC_MODE=native (the report then states that the PoC build ran on this host)." >&2
    exit 3
    ;;
esac

VULNERABLE_SO="${VULNERABLE_SO:-}"
FIXED_SO="${FIXED_SO:-}"
PREBUILT=0
if [[ -n "${FIXED_SO}" && -z "${VULNERABLE_SO}" ]]; then
  echo "[PoC-ATTEMPTED] blocker: FIXED_SO needs VULNERABLE_SO — the fixed bytes are checked against the exploit on the vulnerable ones." >&2
  exit 3
fi
if [[ -n "${VULNERABLE_SO}" ]]; then
  for arm in vulnerable fixed; do
    if [[ "${arm}" == vulnerable ]]; then path="${VULNERABLE_SO}"; else path="${FIXED_SO}"; fi
    [[ -n "${path}" ]] || continue
    if [[ ! -f "${path}" ]]; then
      echo "[PoC-ATTEMPTED] blocker: ${arm} .so not found at '${path}'." >&2
      exit 3
    fi
    # ELF magic: 0x7f 'E' 'L' 'F'. A dump that is actually an RPC error or base64
    # text fails here with a named blocker instead of a silent bad run.
    magic="$(head -c 4 "${path}" | od -An -tx1 | tr -d ' \n')"
    if [[ "${magic}" != "7f454c46" ]]; then
      echo "[PoC-ATTEMPTED] blocker: ${arm} file '${path}' is not an ELF (magic=${magic:-empty}); supply the dumped program .so." >&2
      exit 3
    fi
  done
  # The build runs from a scratch directory, so pin the paths absolute now.
  abs_path() {
    local p="$1" d f
    case "${p}" in */*) d="${p%/*}"; f="${p##*/}" ;; *) d="."; f="${p}" ;; esac
    d="$(cd "${d:-/}" && pwd -P)"
    [[ "${d}" == "/" ]] && d=""
    printf '%s/%s\n' "${d}" "${f}"
  }
  VULNERABLE_SO="$(abs_path "${VULNERABLE_SO}")"
  if [[ -n "${FIXED_SO}" ]]; then FIXED_SO="$(abs_path "${FIXED_SO}")"; fi
  PREBUILT=1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[PoC-ATTEMPTED] blocker: python3 not on PATH — run.sh reads cargo's output, the crate's manifests and the markers with python3, and names the zero-trimmed sha256 of the bytes it ran." >&2
  exit 3
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "[PoC-ATTEMPTED] blocker: cargo not on PATH — the host test binary cannot be built here." >&2
  echo "The finding's prose PoC stands." >&2
  exit 3
fi
if [[ "${PREBUILT}" -eq 0 ]] && ! command -v cargo-build-sbf >/dev/null 2>&1; then
  echo "[PoC-ATTEMPTED] blocker: cargo-build-sbf not on PATH — install the Solana/Agave toolchain (platform-tools >= ${TOOLS_VERSION}), or pass VULNERABLE_SO/FIXED_SO to run against prebuilt bytes." >&2
  echo "The finding's prose PoC stands; this crate could not be built here." >&2
  exit 3
fi

# The pins to move (see DEPENDENCY PINS above): each a crate name, optionally
# @<the version Cargo.lock pins>, and nothing else.
PIN_SPEC='^[A-Za-z][A-Za-z0-9_-]*(@[0-9][0-9A-Za-z.+-]*)?$'
set -f
for spec in ${UPDATE_PINS:-}; do
  if [[ ! "${spec}" =~ ${PIN_SPEC} ]]; then
    echo "[PoC-ATTEMPTED] blocker: UPDATE_PINS entry '${spec}' is not <crate> or <crate>@<pinned version> — nothing was copied or built." >&2
    exit 3
  fi
done
set +f

# ── What python3 reads for run.sh ───────────────────────────────────────────────
# `harness hash <file>`: the zero-trimmed sha256 (the loader pads a program account
# well past the ELF — a live JUP6 dump carried ~892 KB of it — so trailing zeros are
# trimmed before hashing, and the digest matches `solana-verify`). `harness crate`:
# the program name, from cargo metadata, after the build-time-code and manifest
# checks (exit 3 and the reason otherwise). `harness exe`: the test binary in
# cargo's JSON output. `harness settle`: an arm's verdict from its markers.
# `harness nonregistry`: the path and git dependencies in Cargo.lock. python3 runs
# isolated (-I): `python3 -c` would otherwise import modules such as hashlib.py from
# the working directory, or from PYTHONPATH, in place of the stdlib.
HARNESS_PY='import hashlib, json, os, re, sys


def zhash(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read().rstrip(b"\0")).hexdigest()


def flat(text):
    return re.sub(r"[\t\r\n]+", " ", text)


def refuse(text):
    print(flat(text))
    sys.exit(3)


def json_lines(path):
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except ValueError:
                    pass


# A TOML key as it can start a table header or a key/value line: bare, "basic" or
# literal (chr 39 quotes). [patch] and [replace] are found by their first key.
KEY = "(?:[A-Za-z0-9_-]+|\"(?:[^\"\\\\]|\\\\.)*\"|\x27[^\x27]*\x27)"
HEAD = re.compile(r"\s*\[\[?\s*(" + KEY + ")")
PAIR = re.compile(r"\s*(" + KEY + r")\s*[.=]")
ESC = re.compile(r"\\(u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2}|.)")


def unquote(key):
    if key[:1] == "\x27":
        return key[1:-1]
    if key[:1] == "\"":
        return ESC.sub(lambda m: chr(int(m.group(1)[1:], 16)) if len(m.group(1)) > 1 else m.group(1), key[1:-1])
    return key


def crate(meta_path, root):
    root = os.path.realpath(root)
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    members, lib = {}, None
    for pkg in meta.get("packages", []):
        manifest = os.path.realpath(pkg["manifest_path"])
        members[manifest] = pkg["name"]
        for target in pkg.get("targets", []):
            kinds, src = target.get("kind", []), os.path.relpath(target.get("src_path", "?"), root)
            if "custom-build" in kinds:
                refuse("%s is a build script of %s: run.sh refuses build-time code in the crate, in either mode. Check what it generates into the crate instead." % (src, pkg["name"]))
            if "proc-macro" in kinds:
                refuse("%s (%s) is a proc-macro package: run.sh refuses build-time code in the crate, in either mode." % (pkg["name"], src))
            if manifest == os.path.join(root, "Cargo.toml") and ("lib" in kinds or "cdylib" in kinds):
                lib = target.get("name", "")
    for top, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not (top == root and d in ("target", "markers"))]
        if "Cargo.toml" in files and os.path.realpath(os.path.join(top, "Cargo.toml")) not in members:
            refuse("%s is not a member of the workspace this crate defines, so these checks do not cover it: make it a member or remove it." % os.path.relpath(os.path.join(top, "Cargo.toml"), root))
    for manifest in sorted(members):
        try:
            with open(manifest, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            refuse("cannot read %s." % os.path.relpath(manifest, root))
        for number, line in enumerate(text.lstrip("﻿").splitlines(), 1):
            m = HEAD.match(line) or PAIR.match(line)
            if m and unquote(m.group(1)) in ("patch", "replace"):
                refuse("%s:%d holds a [patch] or [replace] table, which builds other code in place of a dependency: run.sh refuses it in either mode. Depend on the crate itself, at the version you need." % (os.path.relpath(manifest, root), number))
    if not lib or not re.match(r"^[A-Za-z0-9_]+$", lib):
        refuse("Cargo.toml has no [lib] target with a plain name, so run.sh cannot name the program it places.")
    print(lib)


def executable(path, test):
    found = set()
    for msg in json_lines(path):
        target = msg.get("target") or {}
        if msg.get("reason") == "compiler-artifact" and "test" in target.get("kind", []) and target.get("name") == test and msg.get("executable"):
            found.add(msg["executable"])
    if len(found) != 1:
        sys.exit(1)
    print(found.pop())


SUCCEEDS = {"vulnerable": ("effect", "succeeds"), "fixed": ("rejected_with", "blocked", "rejected")}
COUNTS = {"vulnerable": ("effect",), "fixed": ("rejected_with", "blocked")}
MISSING = {
    ("vulnerable", "1"): "tests/exploit.rs passed on the prebuilt bytes, but no assert_exploit_effect! ran and held — Ok alone proves nothing on real bytes; assert the effect the attack leaves (shared-test-utils).",
    ("fixed", "1"): "tests/fixed_blocked.rs passed on the prebuilt bytes, but neither assert_exploit_rejected_with! nor assert_exploit_blocked! ran and held — any Err is not a fix on real bytes.",
    ("vulnerable", "0"): "tests/exploit.rs passed, but no assertion that the exploit goes through (assert_exploit_effect! or assert_exploit_succeeds!) ran and held, so it shows nothing.",
    ("fixed", "0"): "tests/fixed_blocked.rs passed, but no assertion that the attack is turned away (assert_exploit_rejected_with!, assert_exploit_blocked! or assert_exploit_rejected!) ran and held, so it shows nothing.",
}


def markers(directory, kind):
    out, path = [], os.path.join(directory, kind)
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                test, tab, text = line.rstrip("\n").partition("\t")
                out.append((test, text) if tab else ("?", test))
    return out


def kind_of(text):
    return re.split(r"[ :]", text, maxsplit=1)[0]


def settle(directory, arm, status, prebuilt, placed_so, placed):
    attempted, held, stuck = (markers(directory, k) for k in ("attempted", "held", "inconclusive"))
    tests = {}
    for slot, found in enumerate((attempted, held, stuck)):
        for test, text in found:
            tests.setdefault(test, ([], [], []))[slot].append(kind_of(text) if slot < 2 else text)

    def unheld(test):
        ran, rest = tests[test][0], list(tests[test][1])
        out = []
        for kind in ran:
            if kind in rest:
                rest.remove(kind)
            else:
                out.append(kind)
        return out

    def bytes_differ():
        loads = markers(directory, "loaded")
        if not loads:
            return "no program was loaded through mollusk_for or litesvm_for!, so which bytes ran is unknown"
        for test, text in loads:
            if text.split(" ", 1)[0] != placed:
                return "the test loaded bytes other than the ones run.sh placed (sha256 and path: %s)" % text
        if not os.path.isfile(placed_so) or zhash(placed_so) != placed:
            return "the placed .so changed while the test ran"
        return None

    def say(*fields):
        print("\t".join(flat(field) for field in fields))

    if status != "0":
        failed = [t for t in sorted(tests) if not tests[t][2] and any(k in SUCCEEDS[arm] for k in unheld(t))]
        if failed:
            why = bytes_differ()
            return say("inconclusive", why) if why else say("fail", failed[0])
        if stuck:
            return say("inconclusive", "%s (test %s)" % (stuck[0][1], stuck[0][0]))
        if not attempted:
            return say("inconclusive", "no contract assertion ran; the test failed before one (did the program load?)")
        if any(unheld(t) for t in tests):
            return say("inconclusive", "the assertion that did not hold is not one this arm counts")
        return say("inconclusive", "every contract assertion that ran held, so the test failed outside them")
    if stuck:
        return say("inconclusive", "%s (test %s)" % (stuck[0][1], stuck[0][0]))
    if any(unheld(t) for t in tests):
        return say("inconclusive", "a contract assertion ran and did not hold, yet the test passed")
    counts = COUNTS[arm] if prebuilt == "1" else SUCCEEDS[arm]
    shown = [(kind_of(text), "%s (test %s)" % (text.split(": ", 1)[-1], test)) for test, text in held if kind_of(text) in counts]
    if not shown:
        return say("blocker", MISSING[(arm, prebuilt)])
    why = bytes_differ()
    if why:
        return say("inconclusive", why)
    say("pass", *shown[0])


def nonregistry(lock, meta_path, builds):
    members, paths, found, package = set(), {}, [], None
    with open(meta_path, encoding="utf-8") as f:
        for pkg in json.load(f).get("packages", []):
            members.add((pkg["name"], pkg["version"]))
    for build in builds:
        for msg in json_lines(build):
            pid, manifest = msg.get("package_id", ""), msg.get("manifest_path")
            if msg.get("reason") == "compiler-artifact" and manifest and pid.startswith("path+"):
                fragment = pid.rsplit("#", 1)[-1]
                name, at, version = fragment.rpartition("@")
                paths[(name if at else os.path.basename(os.path.dirname(manifest)), version)] = os.path.dirname(manifest)
    with open(lock, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "[[package]]":
                package = {}
                found.append(package)
            elif package is not None:
                m = re.match(r"^(name|version|source) = \"(.*)\"$", line)
                if m:
                    package[m.group(1)] = m.group(2)
    out = []
    for package in found:
        key = (package.get("name", "?"), package.get("version", "?"))
        source = package.get("source")
        if source is None and key not in members:
            out.append("%s %s (path%s)" % (key[0], key[1], " " + paths[key] if key in paths else ""))
        elif source is not None and source.startswith("git+"):
            out.append("%s %s (%s)" % (key[0], key[1], source))
    print(flat(", ".join(out)) if out else "none: every dependency comes from a registry")


command, args = sys.argv[1], sys.argv[2:]
if command == "hash":
    print(zhash(args[0]))
elif command == "crate":
    crate(*args)
elif command == "exe":
    executable(*args)
elif command == "settle":
    settle(*args)
elif command == "nonregistry":
    nonregistry(args[0], args[1], args[2:])
else:
    sys.exit(2)
'
harness() { python3 -I -c "${HARNESS_PY}" "$@"; }

# ── Where to build (see WHERE IT BUILDS above) ──────────────────────────────────
# No here-documents or here-strings below: bash 3.2 may put their temp files in the
# working directory (it does under a sandbox that denies /tmp), where a listing of
# the crate would pick them up.

# The first symbolic link, .cargo/ or rust-toolchain* inside the crate; prints
# nothing when there is none. copy_crate takes none of them, so a crate holding one
# is refused rather than built in a shape it was not written in.
crate_extra() {
  local found
  found="$(cd "${HERE}" && find . \( -name target -type d \) -prune -o \( -type l -o -name .cargo -o -name 'rust-toolchain*' \) -print)"
  if [[ -n "${found}" ]]; then echo "${found%%$'\n'*}"; fi
  return 0
}

# The first cargo/rustup config file at or above <dir> (the user's own CARGO_HOME
# config excepted), so a scratch directory never inherits one.
inherited_config() {
  local d="$1" f home_cargo="${CARGO_HOME:-${HOME:-/nonexistent}/.cargo}"
  while :; do
    for f in "${d}/.cargo/config" "${d}/.cargo/config.toml" "${d}/rust-toolchain" "${d}/rust-toolchain.toml"; do
      [[ -e "${f}" ]] || continue
      [[ "${f}" == "${home_cargo}/config" || "${f}" == "${home_cargo}/config.toml" ]] && continue
      echo "${f}"; return 0
    done
    [[ "${d}" == "/" ]] && return 0
    d="$(dirname "${d}")"
  done
}

# copy_crate <dest> : the crate's files, never target/, .cargo/ or rust-toolchain*. The
# copies are stamped with the time of the copy, never the originals': with a shared
# CARGO_TARGET_DIR, cargo would otherwise count a build of another crate of the same
# name, made after these files were last changed, as this crate's own.
copy_crate() {
  local list rel IFS=$'\n'
  list="$(cd "${HERE}" && find . \( \( -name target -type d \) -o -name .cargo -o -name 'rust-toolchain*' -o -name .git \) -prune -o -type f -print)" || return 1
  set -f
  for rel in ${list}; do
    if ! { mkdir -p "$1/$(dirname "${rel}")" && cp "${HERE}/${rel}" "$1/${rel}"; }; then
      set +f; return 1
    fi
  done
  set +f
  return 0
}

finish() {  # keep the resolved Cargo.lock with the crate; drop the scratch directory
  if [[ -f "${BUILD_DIR}/Cargo.lock" ]]; then
    cp -p "${BUILD_DIR}/Cargo.lock" "${HERE}/Cargo.lock" 2>/dev/null || true
  fi
  case "${BUILD_DIR}" in
    */auditor-poc.*) if [[ "${KEEP_POC_BUILD:-0}" != 1 ]]; then rm -rf "${BUILD_DIR}" || true; fi ;;
  esac
  return 0
}

extra="$(crate_extra)"
if [[ -n "${extra}" ]]; then
  echo "[PoC-ATTEMPTED] blocker: ${extra#./} inside the crate is a symbolic link, a .cargo/ directory or a rust-toolchain* file. run.sh builds a copy of the crate outside the target tree and never copies these; remove it (for a link, copy in the file itself)." >&2
  exit 3
fi
if ! BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/auditor-poc.XXXXXX")"; then
  echo "[PoC-ATTEMPTED] blocker: cannot create a scratch build directory under ${TMPDIR:-/tmp}." >&2
  exit 3
fi
BUILD_DIR="$(cd "${BUILD_DIR}" && pwd -P)"
trap finish EXIT
inherited="$(inherited_config "${BUILD_DIR}")"
if [[ -n "${inherited}" ]]; then
  echo "[PoC-ATTEMPTED] blocker: the scratch build directory ${BUILD_DIR} would inherit ${inherited}; point TMPDIR outside any repository." >&2
  exit 3
fi
if ! copy_crate "${BUILD_DIR}"; then
  echo "[PoC-ATTEMPTED] blocker: could not copy the crate into ${BUILD_DIR}." >&2
  exit 3
fi
# run.sh's own files: cargo's metadata and JSON output, and one marker directory per arm.
RUN_DIR="${BUILD_DIR}/markers"
if ! { rm -rf "${RUN_DIR}" && mkdir -p "${RUN_DIR}"; }; then
  echo "[PoC-ATTEMPTED] blocker: cannot prepare ${RUN_DIR}." >&2
  exit 3
fi
# Pin the toolchain instead of letting rustup look for a rust-toolchain file.
if [[ -z "${RUSTUP_TOOLCHAIN:-}" ]] && command -v rustup >/dev/null 2>&1; then
  default_tc="$(cd "${BUILD_DIR}" && rustup default 2>/dev/null || true)"
  case "${default_tc}" in
    *"(default)"*) export RUSTUP_TOOLCHAIN="${default_tc%% *}" ;;
    *) echo "[PoC-ATTEMPTED] blocker: no Rust toolchain to pin — set RUSTUP_TOOLCHAIN or a rustup default." >&2
       exit 3 ;;
  esac
fi
# mollusk reads BPF_OUT_DIR before SBF_OUT_DIR; only the arm placed below may load.
unset BPF_OUT_DIR
export SBF_OUT_DIR="${BUILD_DIR}/target/deploy"
if ! { cd "${BUILD_DIR}" && mkdir -p "${SBF_OUT_DIR}"; }; then
  echo "[PoC-ATTEMPTED] blocker: cannot prepare ${SBF_OUT_DIR}." >&2
  exit 3
fi
echo ">> build dir: ${BUILD_DIR} (scratch copy outside the target tree; AUDITOR_EXEC_MODE=${AUDITOR_EXEC_MODE}; toolchain ${RUSTUP_TOOLCHAIN:-unpinned: no rustup}; $([[ "${KEEP_POC_BUILD:-0}" == 1 ]] && echo kept || echo removed on exit))"

# What the crate builds, from its manifests: nothing compiles in these steps.
if ! cargo metadata --no-deps --format-version 1 --manifest-path "${BUILD_DIR}/Cargo.toml" > "${RUN_DIR}/metadata.json"; then
  echo "[PoC-ATTEMPTED] blocker: cargo could not read the crate's manifests — see the cargo output above." >&2
  exit 3
fi
rc=0
CRATE="$(harness crate "${RUN_DIR}/metadata.json" "${BUILD_DIR}")" || rc=$?
if [[ "${rc}" -ne 0 ]]; then
  if [[ "${rc}" -ne 3 ]]; then CRATE="could not read cargo metadata for the crate."; fi
  echo "[PoC-ATTEMPTED] blocker: ${CRATE}" >&2
  exit 3
fi
if [[ -e "${BUILD_DIR}/tests/fixtures/${CRATE}.so" ]]; then
  echo "[PoC-ATTEMPTED] blocker: tests/fixtures/${CRATE}.so would load in place of the arm run.sh puts in SBF_OUT_DIR (mollusk looks in tests/fixtures first); remove it." >&2
  exit 3
fi

# Dependency pins (see DEPENDENCY PINS above).
if [[ ! -f "${HERE}/Cargo.lock" ]]; then
  echo ">> no Cargo.lock in the crate: cargo resolves every dependency to its newest compatible release now; the resolved lock is kept next to run.sh"
fi
set -f
for spec in ${UPDATE_PINS:-}; do
  echo ">> moving the ${spec} pin: cargo update -p ${spec}, in the scratch copy"
  if ! cargo update --manifest-path "${BUILD_DIR}/Cargo.toml" --package "${spec}"; then
    echo "[PoC-ATTEMPTED] blocker: cargo update -p ${spec} failed — see the cargo output above." >&2
    exit 3
  fi
done
set +f

# The dynamic library path `cargo test` gives a test binary: its deps directory, the
# directory above, the toolchain's target libdir, then what the caller had.
case "$(uname -s 2>/dev/null || true)" in
  Darwin) LIBPATH_VAR=DYLD_FALLBACK_LIBRARY_PATH; LIBPATH_REST="${DYLD_FALLBACK_LIBRARY_PATH:-${HOME:-/nonexistent}/lib:/usr/local/lib:/usr/lib}" ;;
  *) LIBPATH_VAR=LD_LIBRARY_PATH; LIBPATH_REST="${LD_LIBRARY_PATH:-}" ;;
esac
SYSROOT_LIB="$("${RUSTC:-rustc}" --print target-libdir 2>/dev/null || true)"

place_arm() {  # place_arm <arm> : put <crate>.so in SBF_OUT_DIR for this arm; PLACED_HASH names its bytes
  local arm="$1" so="${SBF_OUT_DIR}/${CRATE}.so"
  if [[ "${PREBUILT}" -eq 1 ]]; then
    local src; [[ "${arm}" == "vulnerable" ]] && src="${VULNERABLE_SO}" || src="${FIXED_SO}"
    if ! cp -f "${src}" "${so}"; then
      echo "[PoC-ATTEMPTED] blocker: could not place the ${arm} .so from ${src}." >&2
      exit 3
    fi
    echo ">> ${arm} arm: prebuilt ${src}"
  else
    echo ">> building '${arm}' arm to SBF (${CRATE}.so)"
    if ! cargo build-sbf \
      --tools-version "${TOOLS_VERSION}" \
      --manifest-path "${BUILD_DIR}/Cargo.toml" \
      --no-default-features --features "${arm}" \
      --sbf-out-dir "${SBF_OUT_DIR}"; then
      echo "[PoC-ATTEMPTED] blocker: SBF build failed for the ${arm} arm — see the cargo output above." >&2
      exit 3
    fi
  fi
  PLACED_HASH="$(harness hash "${so}")" || PLACED_HASH=""
  if [[ ! "${PLACED_HASH}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "[PoC-ATTEMPTED] blocker: could not hash the placed ${arm} .so ${so}." >&2
    exit 3
  fi
  echo "   ${arm} .so: ${so}"
  echo "   ${arm} sha256 (zero-trimmed): ${PLACED_HASH}"
}

build_tests() {  # build_tests <arm> <test>: the arm's test binary, EXE; one that does not compile is a blocker, not a verdict
  local json="${RUN_DIR}/build-$1.json" rc=0
  if ! cargo test --manifest-path "${BUILD_DIR}/Cargo.toml" \
        --no-default-features --features "$1" --test "$2" --no-run \
        --message-format=json-render-diagnostics > "${json}"; then
    echo "[PoC-ATTEMPTED] blocker: tests/$2.rs failed to build for the $1 arm — see the cargo output above." >&2
    exit 3
  fi
  EXE="$(harness exe "${json}" "$2")" || rc=$?
  if [[ "${rc}" -ne 0 || ! -x "${EXE}" ]]; then
    echo "[PoC-ATTEMPTED] blocker: cargo reported no single test binary for tests/$2.rs on the $1 arm." >&2
    exit 3
  fi
}

run_tests() {  # run_tests <arm>: the arm's test binary, run as `cargo test` runs it, with an empty marker directory of its own
  local dir="${RUN_DIR}/$1" deps
  if ! { rm -rf "${dir}" && mkdir -p "${dir}"; }; then
    echo "[PoC-ATTEMPTED] blocker: cannot prepare the marker directory ${dir}." >&2
    exit 3
  fi
  deps="$(dirname "${EXE}")"
  env "AUDITOR_POC_MARKERS=${dir}" "CARGO_MANIFEST_DIR=${BUILD_DIR}" \
    "${LIBPATH_VAR}=${deps}:$(dirname "${deps}")${SYSROOT_LIB:+:${SYSROOT_LIB}}${LIBPATH_REST:+:${LIBPATH_REST}}" \
    "${EXE}" --nocapture
}

inconclusive() {  # inconclusive <arm> <reason>: the arm decided nothing — a blocker, never a verdict
  local what="whether the fix holds"
  [[ "$1" == vulnerable ]] && what="whether the exploit reproduces"
  echo "[PoC-ATTEMPTED] blocker: the $1 arm is inconclusive: $2. This run does not show ${what}; repair the PoC's harness setup and re-run." >&2
  exit 3
}

# settle <arm> <status>: the verdict on an arm from its test's exit status and the
# markers each test left. Returns 0 when the arm held (HELD_KIND and HELD_LINE say
# how) and 1 for a verdict against it — an assertion of the arm ran and did not hold,
# on the placed bytes; exits 3 for everything else.
settle() {
  local out verdict rc=0 tab=$'\t'
  out="$(harness settle "${RUN_DIR}/$1" "$1" "$2" "${PREBUILT}" "${SBF_OUT_DIR}/${CRATE}.so" "${PLACED_HASH}")" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    echo "[PoC-ATTEMPTED] blocker: could not read the $1 arm's markers." >&2
    exit 3
  fi
  verdict="${out%%"${tab}"*}"; out="${out#*"${tab}"}"
  case "${verdict}" in
    pass) HELD_KIND="${out%%"${tab}"*}"; HELD_LINE="${out#*"${tab}"}"; return 0 ;;
    fail) echo "   failed: test ${out}"; return 1 ;;
    inconclusive) inconclusive "$1" "${out}" ;;
    *) echo "[PoC-ATTEMPTED] blocker: ${out}" >&2; exit 3 ;;
  esac
}

nonregistry() {  # the path and git dependencies in the resolved Cargo.lock: code that came from no registry
  local line
  if line="$(harness nonregistry "${BUILD_DIR}/Cargo.lock" "${RUN_DIR}/metadata.json" "${RUN_DIR}"/build-*.json)"; then
    echo "   non-registry code: ${line}"
  else
    echo "   non-registry code: unknown — ${BUILD_DIR}/Cargo.lock could not be read"
  fi
}

HELD_KIND=""
HELD_LINE=""

# 1. vulnerable arm — the exploit must land.
place_arm vulnerable
VULNERABLE_HASH="${PLACED_HASH}"
build_tests vulnerable exploit
echo ">> running exploit against 'vulnerable' (expect: SUCCEEDS)"
status=0
run_tests vulnerable || status=$?
if ! settle vulnerable "${status}"; then
  nonregistry
  echo "FAIL: exploit did not reproduce on the vulnerable arm — PoC is not valid." >&2
  exit 1
fi
if [[ "${PREBUILT}" -eq 1 ]]; then
  echo "   effect: ${HELD_LINE}"
  if [[ -z "${FIXED_SO}" ]]; then
    nonregistry
    echo "OK: reproduced on prebuilt bytes — vulnerable sha256=${VULNERABLE_HASH} → [PoC-REPRODUCED]"
    exit 0
  fi
fi

# 2. fixed arm — the same attack must be turned away.
place_arm fixed
build_tests fixed fixed_blocked
echo ">> running same attack against 'fixed' (expect: REJECTED)"
status=0
run_tests fixed || status=$?
if ! settle fixed "${status}"; then
  nonregistry
  echo "FAIL: the fixed arm did not block the attack — fix is incomplete." >&2
  exit 2
fi
nonregistry
if [[ "${PREBUILT}" -eq 0 ]]; then
  echo "OK: exploit reproduces on 'vulnerable' and is blocked on 'fixed' (this crate's own arms: a model, never Leg 3)  → [PoC-REPRODUCED]"
  exit 0
fi
how="blocked: failed, account unchanged"
if [[ "${HELD_KIND}" == rejected_with ]]; then how="rejected with the pinned error"; fi
echo "   fixed arm: ${HELD_LINE}"
echo "OK: reproduced on prebuilt bytes — vulnerable sha256=${VULNERABLE_HASH} fixed sha256=${PLACED_HASH} (${how}) → [PoC-REPRODUCED]"
