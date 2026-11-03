#!/usr/bin/env bash
# test-dnr-poc-runner.sh — self-test for templates/poc/run.sh and the PoC contract
# assertions in templates/poc/shared-test-utils:
#   * the execution mode every run needs (without AUDITOR_EXEC_MODE=isolated|native it
#     exits 3 before anything is copied or compiled, whatever the crate holds), and the
#     same gate, shown verbatim in the docs, for the runners poc-engineer writes;
#   * prebuilt bytes: VULNERABLE_SO alone runs the exploit arm, FIXED_SO adds the
#     fixed arm and needs VULNERABLE_SO; an arm counts only on the marker its contract
#     assertion leaves when it runs and holds; success prints the Leg 3 line with the
#     zero-trimmed hashes (computed with `python3 -I`, so a hashlib.py in the working
#     directory never loads);
#   * verdicts, in either mode: a failed test is exit 1 / 2 only when a contract
#     assertion of that arm ran and did not hold; one that failed before any assertion
#     ran (the program did not load, the setup panicked), after every assertion held,
#     or on a harness error, on either arm, is inconclusive (exit 3); a passing test
#     counts only with a held assertion of its arm; markers carry the test that wrote
#     them, so one test's inconclusive result does not hide another test's failed
#     assertion; exit 2's final line says whether the fixed arm accepted the attack,
#     rejected it with another error than the pinned one, or failed it while the
#     account changed;
#   * how an arm runs: its test binary is built with `cargo test --no-run`, found in
#     cargo's JSON output (a large one too) and run directly, from the package root
#     with CARGO_MANIFEST_DIR and the dynamic library path set; only that run gets
#     AUDITOR_POC_MARKERS, and an inherited value never reaches cargo;
#   * every build of both arms (SBF builds or prebuilt bytes, and test binaries) comes
#     before either test runs, so what a test writes in the scratch copy (src/lib.rs,
#     with real cargo) reaches no build and prebuilt bytes rewritten meanwhile do not
#     run; an arm's bytes or test binary that changed after its build stop the run;
#   * the bytes that ran: an arm counts only when every program the runner helpers
#     loaded is the .so run.sh placed, unchanged after the test, and the Leg 3 line
#     names it;
#   * the crate's own build-time code (a build script, a proc-macro package, a
#     Cargo.toml that is not a member, a [patch] or [replace] table) is refused before
#     anything compiles; `build = false` is honoured;
#     so is a crate that is not its own workspace root;
#     so is a cargo-features key;
#     so are a target other than the library and the tests (a bin, an example, a bench,
#     a dylib, a staticlib, another member's cdylib), and in the crate's own Rust code a
#     crate-level #![feature], inline assembly and the link attribute, a macro argument
#     that names one included, while a comment or a string that mentions them passes;
#   * the harness binding: the crate depends on its own shared-test-utils/ under the
#     import name shared_test_utils, no other dependency takes that name in either
#     spelling, and each arm's build compiles that copy and no other;
#   * the harness copy: --crate stops before anything is copied when shared-test-utils/
#     holds a file other than Cargo.toml and src/lib.rs, or a Cargo.toml changed beyond
#     its dependency version requirements; every build compiles the installation's
#     src/lib.rs, a missing or changed one too, and the >> harness: line says which;
#   * the non-registry line before the final line: the path and git dependencies in
#     the resolved Cargo.lock and those from a registry other than crates.io, and each
#     file from outside the crate that the dep-info of the crate's own units lists, of
#     any kind, an arm's SBF build's included (a member that build alone compiles too,
#     never an older dep-info of a crate of the same name in a build cache); a file of
#     the crate the build read, under any name, that holds inline assembly stops the
#     run before any test, and so does a build that read one of run.sh's own files;
#   * the macros run the attack themselves; their old forms do not compile and say how
#     to migrate; an effect present before the attack, a read that panics, and a
#     positive control for another program or from another state are inconclusive;
#     the LiteSVM forms reach the same lines; every form, in a model run as on
#     prebuilt bytes, is bound to the program run.sh placed, and a LiteSVM attack that
#     failed in another program's instruction is inconclusive;
#   * the deployed-hotfix check holds only with its positive control: a legitimate
#     call that goes through on the same bytes and changes the account;
#   * where the crate builds (always a scratch copy outside the target tree with a
#     pinned toolchain; a crate holding a symbolic link, .cargo/, rust-toolchain*, a
#     version manager's file, a name that is not printable ASCII or
#     tests/fixtures/<crate>.so is refused; run.sh starts
#     every python3 of its own from /; BPF_OUT_DIR is cleared; an inherited
#     CARGO_TARGET_DIR is honoured), and the exit codes (a failed build is 3, a failed
#     verdict 1/2; a refusal prints one blocker line; a run that stops anywhere else,
#     an unset variable included, exits 3);
#   * the build lock: it goes in the directory cargo metadata reports (a target-dir in
#     cargo's own config included); a stale one is broken by one run at a time; a run
#     drops only a lock that still names it; POC_LOCK_WAIT is whole seconds, never
#     evaluated;
#   * dependency pins: the crate's Cargo.lock is what resolves; a crate without one
#     gets a line saying so; UPDATE_PINS moves only the named pins, with cargo update
#     -p in the scratch copy before anything is built, and refuses any other entry;
#   * run.sh holds no placeholder, so a PoC's copy is the installation's byte for byte;
#   * the installation's copy, run by its path with the crate as an argument (--crate,
#     --init, --new-cache): every argument is checked before anything is copied, by the
#     case file fixtures/poc-run/cases.txt among others, and long values (a --cache
#     over 1024 bytes, --update-pins over 1024 bytes or 32 pins) are refused at once;
#     --init copies the template byte for byte; --cache takes only a directory
#     --new-cache made; the mode is the stricter of AUDITOR_EXEC_MODE and the
#     exec-mode of every run directory an argument names, and --mode must match it;
#     ./run.sh in a crate at <R>/poc/<ID> reads <R>/exec-mode as well; the
#     installation's template never builds itself;
#   * an incident's crate runs only once incident_<n>/INCIDENTS.json records its
#     root_cause_class (a file, an incident or a class that cannot be read stops it,
#     a nested or large file included), read by scripts/lib/isolation.sh's
#     iso_incident_class, whose python3 starts from /, as each one run.sh starts before
#     it leaves the working directory does; supply_chain_or_ci refuses native mode, a
#     run without --vulnerable-so, path, git and other-registry dependencies (from the
#     manifests, and from the resolved Cargo.lock before anything compiles) and sources
#     outside the crate, and a build that compiled code from outside it;
#     in native mode no crate runs, an audit's included, while the INCIDENTS.json of
#     any incident_* directory in the working directory, in any letter case, records
#     such an incident or cannot be read (a path past PATH_MAX, a working directory
#     that cannot be listed), as iso_incident_class's no-id form (pinned) reports it: a
#     directory without that file, or whose file records no incident, counts for
#     nothing;
#   * the isolation self-check (scripts/lib/isolation.sh): in isolated mode, a fake HOME
#     holding any credential it reads stops the run before anything is copied, and so
#     does a check that cannot finish; in native mode it is a warning. Through a driver,
#     on the homes it is given: the Solana CLI's keypair, linked and deep directories,
#     the entry budget, the places the environment names (a Claude Code login under
#     CLAUDE_CONFIG_DIR and Anthropic profiles too), git, AWS and Terraform config
#     files by what they hold (a credential helper, git's store and cache by their file
#     and socket, an askpass program, a cookie file,
#     an HTTP header, a URL or a proxy with a login, an include; a credential_process
#     or a key; a credentials block), Claude Code's settings, state and managed
#     settings by what they hold (a credential helper, a token, a passphrase or a list of
#     headers in an env block, a credential or key header, a key in a URL's login, query
#     or path, or in an MCP server's arguments), Docker's TLS client keys, the
#     variable names that
#     look like credentials, and agent, container daemon (a tcp:// one too) and git
#     credential sockets
#     (serving one needs a machine that allows it: on CI a machine that does not fails
#     the run, anywhere else one SKIP line says so). On CI the runner's own home must
#     pass the check, so that the checks that isolated mode passes run there. Its
#     python3, and the watchdog's, starts from /: a .python-version in the working
#     directory picks no interpreter, and a relative path in a variable it reads is
#     taken from /; the Python it runs holds only ASCII;
#   * environment cleaning: canary variables in the caller's environment reach no cargo
#     call, no build script and no test binary; HOME is a throwaway one with a fresh
#     Solana keypair, but for cargo build-sbf --install-only; only cargo fetch, cargo
#     update and that install see the proxy, and every build and test after them runs
#     offline (a cargo build-sbf without those options builds as before, and says so);
#   * the resolved Cargo.lock comes back into the crate in place of a regular file only;
#   * scripts/runner/probe.sh: fixed version queries from a scratch directory in the
#     cleaned environment, each killed when it gives no answer in PROBE_WAIT seconds,
#     the isolation line (kinds, then at most 20 paths), --only and its case file
#     fixtures/probe/cases.txt;
#   * the patch verification recipe (templates/patch/VERIFICATION.md §1): exactly the two
#     target.sh build-sbf lines, the quoted installation path first, with no cd and no $.
#
# No Solana toolchain and no network needed. A temp copy of run.sh runs with a `cargo`
# shim, whose `--no-run` build reports a stand-in test binary, or with a PATH that has
# no cargo at all; the installation's copy runs with the same shim. When real cargo and
# rustup are present, the template's own
# tests/exploit.rs and tests/fixed_blocked.rs and its shared-test-utils are built and
# run through run.sh against small stand-in crates (mollusk-svm, litesvm, solana-sdk,
# borsh, ...) whose program behaviour is the text after the ELF magic in the prebuilt
# .so (model runs get theirs from a stand-in cargo-build-sbf): path dependencies only,
# offline. bash >= 3.2; uses only standard POSIX tools +
# python3. Exits non-zero if any assertion fails. With REQUIRE_TOOLCHAIN=1 (CI sets
# it), a missing cargo or rustup fails the run instead of skipping the real-toolchain
# checks.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/../../templates/poc"
fails=0
ok()  { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1" >&2; fails=$((fails+1)); }

T="$(mktemp -d "${TMPDIR:-/tmp}/dnr_runner.XXXXXX")" || exit 1
trap 'rm -rf "$T"' EXIT
# run.sh reports physical paths (pwd -P); compare against the same.
T="$(cd "$T" && pwd -P)" || exit 1

mk_crate() {  # mk_crate <dir>: run.sh, a manifest, the installation's shared-test-utils/ and the template's tests (the shim never compiles them)
  mkdir -p "$1/tests" "$1/shared-test-utils/src"
  cp "$TEMPLATE/run.sh" "$1/run.sh"
  printf '[package]\nname = "poc_shim"\nversion = "0.1.0"\nedition = "2021"\n' > "$1/Cargo.toml"
  cp "$TEMPLATE/shared-test-utils/Cargo.toml" "$1/shared-test-utils/Cargo.toml"
  cp "$TEMPLATE/shared-test-utils/src/lib.rs" "$1/shared-test-utils/src/lib.rs"
  cp "$TEMPLATE/tests/exploit.rs" "$TEMPLATE/tests/fixed_blocked.rs" "$1/tests/"
}
mk_crate "$T/inc"

# Program-byte fixtures: an ELF with 4 KiB of trailing zero padding, a file that is
# a loader-v3 ProgramData account WITH its 45-byte header (wrong for run.sh — the
# magic is not at offset 0), and a non-binary. The stand-in programs further down
# read their behaviour from the text after the magic.
python3 -I - "$T" <<'PY'
import sys
d = sys.argv[1]
elf = b"\x7fELF" + bytes(range(1, 60))
open(f"{d}/vuln.so", "wb").write(elf + b"\x00" * 4096)
open(f"{d}/fixed.so", "wb").write(elf[:-1] + b"\x99" + b"\x00" * 128)
open(f"{d}/with-header.bin", "wb").write((3).to_bytes(4, "little") + b"\x00" * 41 + elf)
open(f"{d}/text.so", "w").write("not an elf\n")
for name in ["takeover", "noop", "reject:MissingRequiredSignature", "reject:Custom(6001)", "reject:Custom(4100)",
             "reject:InvalidInstructionData", "reject:NotEnoughAccountKeys", "dirty-reject", "guard:Custom(6001)",
             "guard:Custom(4100)", "dirty-guard", "ro-modified", "unloadable"]:
    stem = name.replace(":", "-").replace("(", "").replace(")", "")
    open(f"{d}/sb-{stem}.so", "wb").write(b"\x7fELF" + name.encode() + b"\x00" * 64)
PY

# The cargo shim, and a PATH with it first. The shim logs the two lookups that make an
# in-tree build dangerous, the way cargo and rustup do them: a .cargo/config.toml in
# the working directory or any parent (the user's CARGO_HOME excepted), and a
# rust-toolchain.toml there when RUSTUP_TOOLCHAIN is not pinned. With SHIM_CALLS set it
# also logs every call, tab-separated: working directory, CARGO_TARGET_DIR,
# SBF_OUT_DIR, BPF_OUT_DIR, AUDITOR_POC_MARKERS, arguments. `metadata` lists every
# Cargo.toml under the crate as a member, and one under markers/ or target/ that the
# root manifest names on a `members = [...]` line, the root package named SHIM_CRATE
# (poc_shim), with a test target for each tests/*.rs and the features of a [features]
# table in its manifest, and a dependency on the crate's own shared-test-utils/ (SHIM_STU=none drops it, and
# SHIM_STU=<name>,<rename>,<path> sets another, @copy standing for that directory);
# SHIM_DEP=<name>,<path or git+ source> adds a dependency, SHIM_LIB_SRC sets the root lib's
# source; SHIM_META=build-script gives the root a build script and SHIM_META=proc-macro makes
# its lib a proc-macro. `build-sbf` writes the arm's .so; `build-sbf --help` lists
# --install-only, --offline and --skip-tools-install (none of them with
# SHIM_SBF_HELP=old), and `build-sbf --install-only` builds nothing. `test --no-run` writes a
# Cargo.lock when the crate has none (SHIM_LOCK adds name@version@path|<git source>
# entries), prints SHIM_JSON_PAD other artifacts, the shared_test_utils lib of the
# crate's own shared-test-utils/ (SHIM_STU_BUILD=elsewhere: of another copy; =none: no
# such lib), then the stand-in test binary $T/shim/bin/<test> (none for
# SHIM_FAIL=no-exe:<test>). SHIM_FAIL makes one step fail (build-sbf, update, metadata,
# fetch, install-only) with cargo's own exit code, 101.
# SHIM_WS_ROOT sets the workspace root `metadata` reports.
# `fetch` writes that Cargo.lock too, as cargo resolves one before anything builds; a
# SHIM_DEP or SHIM_LOCK source may also be registry+ or sparse+. With SHIM_DEPINFO=<file>,
# `test --no-run` also reports the root's own lib, whose dep-info in <target
# dir>/debug/deps/ is that file with @ROOT@ standing for the crate; with
# SHIM_SBF_DEPINFO=<file>, `build-sbf` puts that file in <target
# dir>/sbpf-solana-solana/release/deps/ as the arm's dep-info (named SHIM_SBF_DEPINFO_AS,
# <crate>.d by default). SHIM_TARGET=<kind> gives the root package another target, of
# that kind, named poc_shim_extra (src/extra.rs); SHIM_MEMBER_KIND=<kind> makes
# shared-test-utils' library that kind.
#
# The stand-in test binary logs its run to SHIM_CALLS as well (arguments "testbin
# <test> ..."; SHIM_CALLS.env gets CARGO_MANIFEST_DIR and the dynamic library path) and
# leaves the markers SHIM_MARKERS names for its test, as shared-test-utils does: by
# default those of a test whose assertions all ran and held on the placed bytes, and
# none for SHIM_MARKERS=none. An entry is <test>:<marker>[=<assertion>][@<test name>]:
# attempted and held name the assertion (effect on exploit, rejected_with on
# fixed_blocked, unless =<assertion> says otherwise; a failed marker's =<assertion> may
# end in +<outcome>, what the program did), and each line starts with the test name
# (<test>_case unless @ gives one). Marker `loaded` records the zero-trimmed hash
# of the .so in SBF_OUT_DIR, as mollusk_for does; `loaded-other` records other bytes;
# `tamper` changes the placed .so; `spoil` appends a line to each file SHIM_SPOIL names (an
# absolute path, or one in run.sh's own files, the marker directory's parent);
# `relock` makes the build lock in CARGO_TARGET_DIR
# name SHIM_RELOCK_PID; `relink` puts a symbolic link to SHIM_RELINK_TO at SHIM_RELINK;
# `relocate` moves the directory SHIM_RELOCATE aside and puts a link to SHIM_RELOCATE_TO there.
# SHIM_FAIL=<test> makes that test binary fail. SHIM_PLANT=<path>|<text> has the vulnerable arm's test
# build append <text> (\n a newline) to <path> in the scratch copy, as a dependency's build script could
# (several, separated by ||). SHIM_UNIT=<arm>|<package dir>|<target>|<kinds>|<source> has that arm's test
# build also report a compiled target of the package in <package dir> of the crate (kinds separated by commas).
#
# The installation's copy of run.sh hands the shim and the test binaries a cleaned
# environment, with no SHIM_ variable in it. So each of them first records the
# environment it was given (to SHIM_ENV_DUMP, a block per call headed "== <what> <its
# arguments>"), then reads $T/shim/settings.env, where shim_settings puts the settings
# for such runs. SHIM_WALLET_COPY=<prefix> has each test binary copy the Solana keypair
# in its HOME to <prefix>.<test>.
mkdir -p "$T/shim/bin"
cat > "$T/shim/cargo" <<'SH'
#!/bin/sh
here="$(cd "$(dirname "$0")" && pwd)"
start_env="$(env)"
if [ -f "$here/settings.env" ]; then . "$here/settings.env"; fi
if [ -n "${SHIM_ENV_DUMP:-}" ]; then printf '== cargo %s\n%s\n' "$*" "$start_env" >> "$SHIM_ENV_DUMP"; fi
if [ -n "${SHIM_CALLS:-}" ]; then
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$PWD" "${CARGO_TARGET_DIR:-}" "${SBF_OUT_DIR:-}" \
    "${BPF_OUT_DIR:-}" "${AUDITOR_POC_MARKERS:-}" "$*" >> "$SHIM_CALLS"
fi
d="$PWD"
while :; do
  if [ -f "$d/.cargo/config.toml" ] && [ "$d/.cargo" != "${CARGO_HOME:-$HOME/.cargo}" ]; then
    echo "config $d" >> "${SHIM_LOG:-/dev/null}"
  fi
  if [ -z "${RUSTUP_TOOLCHAIN:-}" ] && [ -f "$d/rust-toolchain.toml" ]; then
    echo "toolchain $d" >> "${SHIM_LOG:-/dev/null}"
  fi
  [ "$d" = / ] && break
  d="$(dirname "$d")"
done
manifest="$PWD/Cargo.toml"; out=""; features=""; prev=""
for a in "$@"; do
  case "$prev" in --manifest-path) manifest="$a" ;; --sbf-out-dir) out="$a" ;; --features) features="$a" ;; esac
  prev="$a"
done
case "${SHIM_FAIL:-}" in
  build-sbf|update|metadata|fetch) if [ "${1:-}" = "$SHIM_FAIL" ]; then echo "[shim cargo: $SHIM_FAIL fails]" >&2; exit 101; fi ;;
esac
case "${1:-} $*" in
  "build-sbf "*" --help"*)
    if [ "${SHIM_SBF_HELP:-}" != old ]; then printf '        --install-only\n        --offline\n        --skip-tools-install\n'; fi
    printf '        --tools-version <STRING>\n'; exit 0 ;;
  "build-sbf "*" --install-only"*)
    if [ "${SHIM_FAIL:-}" = install-only ]; then echo "[shim cargo: install-only fails]" >&2; exit 101; fi
    echo "[shim cargo build-sbf --install-only]"; exit 0 ;;
esac
case "${1:-}" in
  metadata) exec python3 -I "$here/meta.py" "$(dirname "$manifest")" ;;
  fetch) python3 -I "$here/build.py" "$(dirname "$manifest")" --lock-only || exit 101; echo "[shim cargo $*]"; exit 0 ;;
  build-sbf)
    printf '\177ELFmodel-%s' "$features" > "$out/${SHIM_CRATE:-poc_shim}.so"
    if [ -n "${SHIM_SBF_DEPINFO:-}" ]; then
      d="${CARGO_TARGET_DIR:-${CARGO_BUILD_TARGET_DIR:-${SHIM_TARGET_DIR:-$(dirname "$manifest")/target}}}/sbpf-solana-solana/release/deps"
      mkdir -p "$d" && cp "$SHIM_SBF_DEPINFO" "$d/${SHIM_SBF_DEPINFO_AS:-${SHIM_CRATE:-poc_shim}.d}"
    fi
    echo "[shim cargo build-sbf $features]"; exit 0 ;;
  test) case " $* " in *" --no-run "*) exec python3 -I "$here/build.py" "$(dirname "$manifest")" "$@" ;; esac ;;
esac
echo "[shim cargo $*]"; exit 0
SH
cat > "$T/shim/meta.py" <<'PY'
import json, os, re, sys
root, crate, meta = sys.argv[1], os.environ.get("SHIM_CRATE", "poc_shim"), os.environ.get("SHIM_META", "")
try:
    manifest_text = open(os.path.join(root, "Cargo.toml")).read()
except OSError:
    manifest_text = ""
features, in_features = {}, False
for line in manifest_text.splitlines():
    if line.strip().startswith("["):
        in_features = line.strip() == "[features]"
    elif in_features and re.match(r"\s*[A-Za-z0-9_-]+\s*=\s*\[.*\]\s*$", line):
        key, value = line.split("=", 1)
        features[key.strip()] = re.findall(r"\x22([^\x22]*)\x22", value)
named = [rel for m in re.finditer(r"(?m)^\s*members\s*=\s*\[(.*)\]", manifest_text) for rel in re.findall(r"\x22([^\x22]*)\x22", m.group(1))]
stu = os.environ.get("SHIM_STU", "shared-test-utils,,@copy")
deps = []
if stu != "none":
    name, rename, path = stu.split(",", 2)
    path = os.path.join(root, "shared-test-utils") if path == "@copy" else path
    deps.append({"name": name, "rename": rename or None, "path": path or None, "kind": "dev",
                 "source": None if path else "registry+https://github.com/rust-lang/crates.io-index"})
if os.environ.get("SHIM_DEP"):
    name, spec = os.environ["SHIM_DEP"].split(",", 1)
    source = spec if spec.startswith(("git+", "registry+", "sparse+")) else None
    index = spec.split("+", 1)[1] if spec.startswith(("registry+", "sparse+")) and "crates.io" not in spec else None
    deps.append({"name": name, "rename": None, "path": None if source else spec, "kind": None, "source": source, "registry": index})
packages, tops = [], []
for top, dirs, files in os.walk(root):
    dirs[:] = sorted(d for d in dirs if not (top == root and d in ("target", "markers")))
    if "Cargo.toml" in files:
        tops.append(top)
tops += [os.path.join(root, rel) for rel in named if rel.split("/")[0] in ("target", "markers") and os.path.isfile(os.path.join(root, rel, "Cargo.toml"))]
for top in tops:
    name = crate if top == root else os.path.basename(top)
    kind = [os.environ.get("SHIM_MEMBER_KIND") or "lib"] if top != root else ["proc-macro"] if meta == "proc-macro" else ["cdylib", "lib"]
    src = os.environ.get("SHIM_LIB_SRC") if top == root and os.environ.get("SHIM_LIB_SRC") else os.path.join(top, "src", "lib.rs")
    targets = [{"name": name.replace("-", "_"), "kind": kind, "crate_types": kind, "src_path": src}]
    if top == root and os.environ.get("SHIM_TARGET"):
        extra = [os.environ["SHIM_TARGET"]]
        targets.append({"name": "poc_shim_extra", "kind": extra, "crate_types": extra, "src_path": os.path.join(top, "src", "extra.rs")})
    if top == root and meta == "build-script":
        targets.append({"name": "build-script-build", "kind": ["custom-build"], "crate_types": ["bin"], "src_path": os.path.join(top, "build.rs")})
    if top == root and os.path.isdir(os.path.join(top, "tests")):
        targets += [{"name": test[:-3], "kind": ["test"], "crate_types": ["bin"], "src_path": os.path.join(top, "tests", test)}
                    for test in sorted(os.listdir(os.path.join(top, "tests"))) if test.endswith(".rs")]
    packages.append({"name": name, "version": "0.1.0", "id": "path+file://%s#%s@0.1.0" % (top, name), "manifest_path": os.path.join(top, "Cargo.toml"),
                     "targets": targets, "features": features if top == root else {}, "dependencies": deps if top == root else []})
# The directory cargo builds into: CARGO_TARGET_DIR, CARGO_BUILD_TARGET_DIR, then
# SHIM_TARGET_DIR, which stands for a target-dir set in cargo's own config.
target = os.environ.get("CARGO_TARGET_DIR") or os.environ.get("CARGO_BUILD_TARGET_DIR") or os.environ.get("SHIM_TARGET_DIR") or os.path.join(root, "target")
print(json.dumps({"packages": packages, "workspace_members": [p["id"] for p in packages], "workspace_root": os.environ.get("SHIM_WS_ROOT") or root,
                  "target_directory": target, "version": 1}))
PY
cat > "$T/shim/build.py" <<'PY'
import json, os, sys
root, args = sys.argv[1], sys.argv[2:]
lock = os.path.join(root, "Cargo.lock")
if not os.path.exists(lock):
    entries = ['[[package]]\nname = "%s"\nversion = "0.1.0"\n' % os.environ.get("SHIM_CRATE", "poc_shim")]
    for spec in os.environ.get("SHIM_LOCK", "").split():
        name, version, source = spec.split("@", 2)
        entries.append('[[package]]\nname = "%s"\nversion = "%s"\n%s' % (name, version, "" if source == "path" else 'source = "%s"\n' % source))
    open(lock, "w").write("# shim lock\nversion = 4\n\n" + "\n".join(entries))
if args == ["--lock-only"]:
    sys.exit(0)
test, fail = args[args.index("--test") + 1], os.environ.get("SHIM_FAIL", "")
if fail == "no-run:" + test:
    print("[shim cargo: test build fails]", file=sys.stderr)
    sys.exit(101)
if os.environ.get("SHIM_PLANT") and "vulnerable" in args:
    for plant in os.environ["SHIM_PLANT"].split("||"):
        rel, text = plant.split("|", 1)
        os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
        with open(os.path.join(root, rel), "a") as f:
            f.write(text.replace("\\n", "\n"))
for n in range(int(os.environ.get("SHIM_JSON_PAD", "0"))):
    print(json.dumps({"reason": "compiler-artifact", "package_id": "registry+https://github.com/rust-lang/crates.io-index#pad%d@1.0.0" % n,
                      "manifest_path": "/registry/pad%d/Cargo.toml" % n, "target": {"kind": ["lib"], "crate_types": ["lib"], "name": "pad%d" % n,
                      "src_path": "/registry/pad%d/src/lib.rs" % n}, "profile": {"test": False}, "features": [],
                      "filenames": ["/target/debug/deps/libpad%d.rlib" % n], "executable": None, "fresh": True}))
# SHIM_FRESH=1 reports the crate's own lib and test as already built (fresh) without
# this run compiling them — a build cache shared with another same-named crate — so
# the fresh check in `harness checkbuild` can be exercised without real cargo.
fresh = os.environ.get("SHIM_FRESH", "") == "1"
if fresh:
    print(json.dumps({"reason": "compiler-artifact", "package_id": "path+file://%s#poc_shim@0.1.0" % root, "manifest_path": os.path.join(root, "Cargo.toml"),
                      "target": {"kind": ["cdylib", "lib"], "crate_types": ["cdylib", "lib"], "name": "poc_shim", "src_path": os.path.join(root, "src", "lib.rs")},
                      "profile": {"test": False}, "features": [], "filenames": ["/cache/debug/deps/libpoc_shim-shared.rlib"], "executable": None, "fresh": True}))
if os.environ.get("SHIM_DEPINFO"):
    deps = os.path.join(os.environ.get("CARGO_TARGET_DIR") or os.environ.get("CARGO_BUILD_TARGET_DIR") or os.environ.get("SHIM_TARGET_DIR")
                        or os.path.join(root, "target"), "debug", "deps")
    os.makedirs(deps, exist_ok=True)
    name = os.environ.get("SHIM_CRATE", "poc_shim")
    with open(os.environ["SHIM_DEPINFO"]) as f:
        open(os.path.join(deps, name + ".d"), "w").write(f.read().replace("@ROOT@", root))
    print(json.dumps({"reason": "compiler-artifact", "package_id": "path+file://%s#%s@0.1.0" % (root, name), "manifest_path": os.path.join(root, "Cargo.toml"),
                      "target": {"kind": ["cdylib", "lib"], "crate_types": ["cdylib", "lib"], "name": name, "src_path": os.path.join(root, "src", "lib.rs")},
                      "profile": {"test": False}, "features": [], "filenames": [os.path.join(deps, "lib%s.rlib" % name)], "executable": None, "fresh": False}))
stu_build = os.environ.get("SHIM_STU_BUILD", "copy")
if stu_build != "none":
    stu_root = os.path.join(root, "shared-test-utils") if stu_build == "copy" else "/elsewhere/shared-test-utils"
    print(json.dumps({"reason": "compiler-artifact", "package_id": "path+file://%s#shared-test-utils@0.1.0" % stu_root, "manifest_path": os.path.join(stu_root, "Cargo.toml"),
                      "target": {"kind": ["lib"], "crate_types": ["lib"], "name": "shared_test_utils", "src_path": os.path.join(stu_root, "src", "lib.rs")},
                      "profile": {"test": False}, "features": [], "filenames": ["/target/debug/deps/libshared_test_utils-shim.rlib"], "executable": None, "fresh": False}))
if os.environ.get("SHIM_UNIT"):
    arm, package, name, kinds, src = os.environ["SHIM_UNIT"].split("|")
    if arm in args:
        top, kinds = os.path.normpath(os.path.join(root, package)), kinds.split(",")
        print(json.dumps({"reason": "compiler-artifact", "package_id": "path+file://%s#%s@0.1.0" % (top, os.path.basename(top)), "manifest_path": os.path.join(top, "Cargo.toml"),
                          "target": {"kind": kinds, "crate_types": kinds, "name": name, "src_path": os.path.join(root, src)},
                          "profile": {"test": False}, "features": [], "filenames": [os.path.join(root, "target", "debug", "deps", "lib%s-shim.rlib" % name)],
                          "executable": None, "fresh": False}))
if fail != "no-exe:" + test:
    exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", test)
    print(json.dumps({"reason": "compiler-artifact", "package_id": "path+file://%s#poc_shim@0.1.0" % root, "manifest_path": os.path.join(root, "Cargo.toml"),
                      "target": {"kind": ["test"], "crate_types": ["bin"], "name": test, "src_path": os.path.join(root, "tests", test + ".rs")},
                      "profile": {"test": True}, "features": [], "filenames": [exe], "executable": exe, "fresh": fresh}))
print(json.dumps({"reason": "build-finished", "success": True}))
PY
cat > "$T/shim/bin/exploit" <<'SH'
#!/bin/sh
t="$(basename "$0")"
here="$(cd "$(dirname "$0")/.." && pwd)"
start_env="$(env)"
if [ -f "$here/settings.env" ]; then . "$here/settings.env"; fi
if [ -n "${SHIM_ENV_DUMP:-}" ]; then printf '== testbin %s %s\n%s\n' "$t" "$*" "$start_env" >> "$SHIM_ENV_DUMP"; fi
if [ -n "${SHIM_WALLET_COPY:-}" ] && [ -f "${HOME:-/nonexistent}/.config/solana/id.json" ]; then
  cp "$HOME/.config/solana/id.json" "$SHIM_WALLET_COPY.$t"
fi
if [ -n "${SHIM_CALLS:-}" ]; then
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$PWD" "${CARGO_TARGET_DIR:-}" "${SBF_OUT_DIR:-}" \
    "${BPF_OUT_DIR:-}" "${AUDITOR_POC_MARKERS:-}" "testbin $t $*" >> "$SHIM_CALLS"
  printf '%s\t%s\t%s\n' "$t" "${CARGO_MANIFEST_DIR:-}" "${LD_LIBRARY_PATH:-}" >> "$SHIM_CALLS.env"
fi
for m in ${SHIM_MARKERS-exploit:attempted exploit:held exploit:effect exploit:loaded fixed_blocked:attempted fixed_blocked:held fixed_blocked:rejected_with fixed_blocked:loaded}; do
  [ "${m%%:*}" = "$t" ] && [ -n "${AUDITOR_POC_MARKERS:-}" ] || continue
  rest="${m#*:}"; tag="${t}_case"
  case "$rest" in *@*) tag="${rest#*@}"; rest="${rest%%@*}" ;; esac
  kind="${rest%%=*}"; assertion=effect
  [ "$t" = fixed_blocked ] && assertion=rejected_with
  case "$rest" in *=*) assertion="${rest#*=}" ;; esac
  case "$kind" in
    loaded)
      for so in "${SBF_OUT_DIR:-/nonexistent}"/*.so; do
        [ -f "$so" ] || continue
        h="$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\x00")).hexdigest())' "$so")"
        printf '%s\t%s %s\n' "$tag" "$h" "$so" >> "$AUDITOR_POC_MARKERS/loaded"
      done ;;
    loaded-other) printf '%s\t%064d %s\n' "$tag" 0 /elsewhere/other.so >> "$AUDITOR_POC_MARKERS/loaded" ;;
    tamper) for so in "${SBF_OUT_DIR:-/nonexistent}"/*.so; do [ -f "$so" ] && printf 'x' >> "$so"; done ;;
    spoil) for f in ${SHIM_SPOIL:-}; do case "$f" in /*) ;; *) f="$AUDITOR_POC_MARKERS/../$f" ;; esac; printf '\n# spoiled\n' >> "$f"; done ;;
    relock) printf '%s\n' "${SHIM_RELOCK_PID:-}" > "${CARGO_TARGET_DIR:-/nonexistent}/.auditor-poc-build.lock/pid" ;;
    relink) rm -f "$SHIM_RELINK" && ln -s "$SHIM_RELINK_TO" "$SHIM_RELINK" ;;
    relocate) mv "$SHIM_RELOCATE" "$SHIM_RELOCATE.moved" && ln -s "$SHIM_RELOCATE_TO" "$SHIM_RELOCATE" ;;
    attempted) printf '%s\t%s (shim)\n' "$tag" "$assertion" >> "$AUDITOR_POC_MARKERS/attempted" ;;
    held) printf '%s\t%s: shim\n' "$tag" "$assertion" >> "$AUDITOR_POC_MARKERS/held" ;;
    failed) printf '%s\t%s: shim did not hold\n' "$tag" "$(printf '%s' "$assertion" | tr '+' ' ')" >> "$AUDITOR_POC_MARKERS/failed" ;;
    *) printf '%s\tshim %s\n' "$tag" "$kind" >> "$AUDITOR_POC_MARKERS/$kind" ;;
  esac
done
case " ${SHIM_FAIL:-} " in *" $t "*) echo "[shim test $t fails]"; exit 101 ;; esac
echo "[shim test $t]"; exit 0
SH
cp "$T/shim/bin/exploit" "$T/shim/bin/fixed_blocked"
chmod +x "$T/shim/cargo" "$T/shim/bin/exploit" "$T/shim/bin/fixed_blocked"
printf '#!/bin/sh\nexit 0\n' > "$T/shim/cargo-build-sbf"; chmod +x "$T/shim/cargo-build-sbf"

# PATHs with the tools run.sh needs but NO cargo, and with the cargo shim but no python3.
mkdir -p "$T/nocargo" "$T/nopython"
for tool in bash sh mkdir dirname head od tr grep cp python3 cat rm env; do
  p="$(command -v "$tool" 2>/dev/null)" && ln -sf "$p" "$T/nocargo/$tool"
done
for tool in bash sh mkdir dirname head od tr grep cp cat rm env find mktemp pwd sed awk; do
  p="$(command -v "$tool" 2>/dev/null)" && ln -sf "$p" "$T/nopython/$tool"
done
ln -sf "$T/shim/cargo" "$T/nopython/cargo"; ln -sf "$T/shim/cargo-build-sbf" "$T/nopython/cargo-build-sbf"

run() {  # run <crate> <PATH> [VAR=val ...] -> exit code; output in $T/out
  local crate="$1" path="$2"; shift 2
  ( cd "$crate" && env -i HOME="$HOME" PATH="$path" TMPDIR="${TMPDIR:-/tmp}" "$@" bash ./run.sh ) >"$T/out" 2>&1
  echo $?
}
SP="$T/shim:$PATH"
NATIVE=AUDITOR_EXEC_MODE=native   # the recorded mode most runs below pass
VULN="VULNERABLE_SO=$T/vuln.so"; FIX="FIXED_SO=$T/fixed.so"

# gate: a shim run with the call log on and an empty TMPDIR of its own, so
# nothing_ran can tell that no cargo command started and no scratch directory appeared.
gate() {  # gate <crate> [VAR=val ...] -> exit code
  local crate="$1"; shift
  rm -rf "$T/calls" "$T/calls.env" "$T/tmp-gate"; mkdir -p "$T/tmp-gate"
  run "$crate" "$SP" SHIM_CALLS="$T/calls" TMPDIR="$T/tmp-gate" "$@"
}
nothing_ran() { [ ! -e "$T/calls" ] && [ -z "$(ls -A "$T/tmp-gate")" ] && ! grep -q '^>> build dir' "$T/out"; }
# nothing_built: refused after the copy, from the manifests alone: cargo ran only
# `metadata`, no test binary ran, and the scratch directory is gone.
nothing_built() {
  [ -z "$(ls -A "$T/tmp-gate")" ] && { [ ! -e "$T/calls" ] || awk -F'\t' '$6 !~ /^metadata / { b = 1 } END { exit b }' "$T/calls"; }
}
build_dir() { sed -n 's/^>> build dir: \([^ ]*\).*/\1/p' "$T/out" | sed -n 1p; }
# one_blocker: the run named its blocker once. A refusal found inside a command
# substitution is reported by its caller only, never next to the generic line the
# ERR trap prints (bash 3.2 runs that trap inside the substitution too).
one_blocker() { [ "$(grep -c '^\[PoC-ATTEMPTED\]' "$T/out")" = 1 ]; }
# from_scratch <dir>: <dir> is a scratch copy under the gate's TMPDIR, and every
# logged cargo call and test binary run started from it.
from_scratch() {
  case "$1" in "$T/tmp-gate"/auditor-poc.*) ;; *) return 1 ;; esac
  awk -F'\t' -v d="$1" '{ n++ } $1 == d { g++ } END { exit !(n > 0 && n == g) }' "$T/calls"
}
zhash() { python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\x00")).hexdigest())' "$1"; }
LEG3='OK: reproduced on prebuilt bytes — vulnerable sha256='
# Shim marker sets for one test whose contract assertion ran and held on the placed
# bytes: the exploit's effect, the fixed arm's pinned error, a deployed fix's block.
EV="exploit:attempted exploit:held exploit:effect exploit:loaded"
FR="fixed_blocked:attempted fixed_blocked:held fixed_blocked:rejected_with fixed_blocked:loaded"
FB="fixed_blocked:attempted=blocked fixed_blocked:held=blocked fixed_blocked:blocked fixed_blocked:loaded"

# ---------------------------------------------------------------------------
# The execution mode. Without AUDITOR_EXEC_MODE=isolated|native, run.sh exits 3
# before it copies or compiles anything — a dependency-free crate included.
# ---------------------------------------------------------------------------
code="$(gate "$T/inc" "$VULN" "$FIX")"
[ "$code" = 3 ] && grep -q 'AUDITOR_EXEC_MODE' "$T/out" && grep -q 'Rule 11a' "$T/out" && grep -q 'Q46' "$T/out" && nothing_ran \
  && ok "no execution mode, dependency-free crate (prebuilt) -> exit 3 pointing to Rule 11a / Q46, no cargo call, no scratch dir" \
  || { bad "no execution mode, prebuilt: exit $code"; cat "$T/out" >&2; }
code="$(gate "$T/inc")"
[ "$code" = 3 ] && nothing_ran && ok "no execution mode, build mode -> exit 3 before any SBF build" || bad "no execution mode, build mode: exit $code"
code="$(gate "$T/inc" AUDITOR_EXEC_MODE= "$VULN" "$FIX")"
[ "$code" = 3 ] && nothing_ran && ok "an empty AUDITOR_EXEC_MODE -> exit 3" || bad "AUDITOR_EXEC_MODE empty: exit $code"
code="$(gate "$T/inc" AUDITOR_EXEC_MODE=yes "$VULN" "$FIX")"
[ "$code" = 3 ] && grep -q "AUDITOR_EXEC_MODE is 'yes'" "$T/out" && nothing_ran && ok "an unknown AUDITOR_EXEC_MODE value -> exit 3" || bad "AUDITOR_EXEC_MODE=yes: exit $code"
code="$(gate "$T/inc" AUDITOR_EXEC_MODE=isolated "$VULN" "$FIX")"
bd="$(build_dir)"
[ "$code" = 0 ] && from_scratch "$bd" && grep -q '^>> build dir: .*AUDITOR_EXEC_MODE=isolated;' "$T/out" \
  && ok "AUDITOR_EXEC_MODE=isolated -> builds and tests the scratch copy, and says which mode ran" || bad "isolated: exit $code, build dir '$bd'"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX")"
bd="$(build_dir)"
[ "$code" = 0 ] && from_scratch "$bd" && grep -q '^>> build dir: .*AUDITOR_EXEC_MODE=native;' "$T/out" \
  && ok "AUDITOR_EXEC_MODE=native -> builds and tests the scratch copy, and says which mode ran" || bad "native: exit $code, build dir '$bd'"

# A runner poc-engineer writes (a Trident or cargo-fuzz target, a Surfpool scenario)
# starts with run.sh's mode gate, copied from the docs: the lines poc-harness.md and
# poc-engineer.md show are run.sh's own, and as a runner's first lines they stop a run
# with no recorded mode.
gate_lines() {  # gate_lines <file>: the mode gate, from its `case` line to its `esac`
  awk 'index($0, "case \"${AUDITOR_EXEC_MODE:-}\" in") == 1 { on = 1 } on { print } on && $0 == "esac" { exit }' "$1"
}
want_gate="$(gate_lines "$TEMPLATE/run.sh")"
for doc in references/orchestration/poc-harness.md agents/poc-engineer.md; do
  if [ -n "$want_gate" ] && [ "$(gate_lines "$HERE/../../$doc")" = "$want_gate" ]; then
    ok "$doc shows run.sh's mode gate verbatim for the runners poc-engineer writes"
  else
    bad "$doc: the mode gate for agent-written runners differs from run.sh's"
  fi
done
printf '#!/usr/bin/env bash\nset -euo pipefail\n%s\necho "past the gate"\n' "$(gate_lines "$HERE/../../references/orchestration/poc-harness.md")" > "$T/runner.sh"
code="$( (cd "$T" && env -i PATH="$PATH" bash ./runner.sh) >"$T/out" 2>&1; echo $?)"
[ "$code" = 3 ] && grep -q 'nothing was copied or built' "$T/out" && ! grep -q 'past the gate' "$T/out" \
  && ok "the documented gate as a runner's first lines: no AUDITOR_EXEC_MODE -> exit 3 before anything else" || bad "documented gate, no mode: exit $code"
code="$( (cd "$T" && env -i PATH="$PATH" AUDITOR_EXEC_MODE=isolated bash ./runner.sh) >"$T/out" 2>&1; echo $?)"
[ "$code" = 0 ] && grep -q 'past the gate' "$T/out" && ok "the documented gate lets a run with a recorded mode through" || bad "documented gate, isolated: exit $code"

# The installation's run.sh is what each PoC holds: nothing in it is filled in, so the
# commands can compare a PoC's copy with it byte for byte, and refresh it.
placeholders="$(grep -nE '(^|[^$])\{[A-Z][A-Z_]*\}' "$TEMPLATE/run.sh")"
if [ -z "$placeholders" ]; then
  ok "run.sh holds no placeholder: a PoC's copy is the installation's byte for byte"
else
  bad "run.sh holds a placeholder: ${placeholders%%$'\n'*}"
fi

# ---------------------------------------------------------------------------
# Prebuilt bytes, under the mode: inputs, the vulnerable-only run, the markers each
# arm needs, an inconclusive fixed arm, and the Leg 3 line.
# ---------------------------------------------------------------------------
code="$(gate "$T/inc" "$NATIVE" "$FIX")"
[ "$code" = 3 ] && grep -q 'FIXED_SO needs VULNERABLE_SO' "$T/out" && nothing_ran && ok "FIXED_SO without VULNERABLE_SO -> exit 3, nothing built" || bad "FIXED_SO alone: exit $code"

code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" FIXED_SO="$T/missing.so")"
[ "$code" = 3 ] && grep -q 'fixed .so not found' "$T/out" && ok "missing FIXED_SO path -> exit 3" || bad "missing fixed path: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/missing.so")"
[ "$code" = 3 ] && grep -q 'vulnerable .so not found' "$T/out" && ok "missing VULNERABLE_SO path -> exit 3" || bad "missing vulnerable path: exit $code"

code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" FIXED_SO="$T/text.so")"
[ "$code" = 3 ] && grep -q 'not an ELF' "$T/out" && ok "non-ELF .so -> exit 3" || bad "non-ELF: exit $code"

code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/with-header.bin")"
[ "$code" = 3 ] && grep -q 'not an ELF' "$T/out" && ok "ProgramData dump still carrying its 45-byte header -> exit 3" || bad "header-prefixed dump: exit $code"

code="$(run "$T/inc" "$T/nocargo" "$NATIVE" "$VULN" "$FIX")"
[ "$code" = 3 ] && grep -q 'cargo not on PATH' "$T/out" && ok "no cargo on PATH -> exit 3" || bad "no cargo: exit $code"

code="$(run "$T/inc" "$T/nopython" "$NATIVE" "$VULN")"
[ "$code" = 3 ] && grep -q 'python3 not on PATH' "$T/out" && ok "no python3 on PATH, prebuilt bytes -> exit 3 naming python3 (the Leg 3 line needs the hash)" || { bad "no python3: exit $code"; cat "$T/out" >&2; }
code="$(run "$T/inc" "$T/nopython" "$NATIVE")"
[ "$code" = 3 ] && grep -q 'python3 not on PATH' "$T/out" && ok "no python3 on PATH, build mode -> exit 3 too (run.sh reads the markers and cargo's output with it)" || bad "no python3, build mode: exit $code"

want="$(zhash "$T/vuln.so")"; wantf="$(zhash "$T/fixed.so")"
code="$(gate "$T/inc" "$NATIVE" "$VULN")"
if [ "$code" = 0 ] && grep -qx "${LEG3}${want} → \[PoC-REPRODUCED\]" "$T/out" && ! grep -q 'running same attack' "$T/out" \
   && awk -F'\t' '$6 ~ /--test fixed_blocked|^testbin fixed_blocked/ { f = 1 } END { exit f }' "$T/calls"; then
  ok "VULNERABLE_SO alone -> the exploit arm only, then the Leg 3 line naming its zero-trimmed hash"
else
  bad "VULNERABLE_SO alone: exit $code"; cat "$T/out" >&2
fi

code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX")"
if [ "$code" = 0 ] && grep -qx "${LEG3}${want} fixed sha256=${wantf} (rejected with the pinned error) → \[PoC-REPRODUCED\]" "$T/out"; then
  ok "both arms on prebuilt bytes -> the Leg 3 line names both hashes and the pinned-error result"
else
  bad "both prebuilt arms: exit $code"; cat "$T/out" >&2
fi
# Each arm's test binary runs with its own marker directory; no cargo call gets one.
if awk -F'\t' '$6 ~ /^testbin exploit / && $5 !~ /\/markers\/vulnerable$/ { bad = 1 } $6 ~ /^testbin fixed_blocked / && $5 !~ /\/markers\/fixed$/ { bad = 1 } $6 !~ /^testbin / && $5 != "" { bad = 1 } END { exit bad }' "$T/calls" \
   && [ "$(awk -F'\t' '$6 ~ /^testbin /' "$T/calls" | wc -l | tr -d ' ')" = 2 ]; then
  ok "each arm's test binary gets AUDITOR_POC_MARKERS=<scratch>/markers/<arm>; no cargo call gets one"
else
  bad "marker directories"; cat "$T/calls" >&2
fi
# The test binary runs the way cargo test runs it: from the package root, with
# CARGO_MANIFEST_DIR set to it, and the dynamic library path led by the binary's
# directory (macOS keeps DYLD_* away from a /bin/sh stand-in, so there only the real
# binaries below can show the library path).
bd="$(build_dir)"
if awk -F'\t' -v d="$bd" -v lib="$T/shim/bin:" -v linux="$( [ "$(uname -s)" = Darwin ] && echo 0 || echo 1)" \
     '{ n++ } $2 != d { bad = 1 } linux == 1 && index($3, lib) != 1 { bad = 1 } END { exit bad || n != 2 }' "$T/calls.env"; then
  ok "each test binary runs from the package root with CARGO_MANIFEST_DIR and the dynamic library path set as cargo sets them"
else
  bad "test binary environment"; cat "$T/calls.env" >&2
fi
# An inherited AUDITOR_POC_MARKERS reaches no cargo call, and what it holds counts for
# nothing: the stand-in tests below leave no marker, so the run decides nothing.
mkdir -p "$T/inherited"; printf 'exploit_case\teffect (planted)\n' > "$T/inherited/attempted"
printf 'exploit_case\teffect: planted\n' > "$T/inherited/held"; cp "$T/inherited/held" "$T/inherited/effect"
code="$(gate "$T/inc" "$NATIVE" "$VULN" AUDITOR_POC_MARKERS="$T/inherited" SHIM_MARKERS=none)"
[ "$code" = 3 ] && ! awk -F'\t' -v m="$T/inherited" '$5 == m { f = 1 } END { exit !f }' "$T/calls" && ! grep -q "^$LEG3" "$T/out" \
  && ok "an inherited AUDITOR_POC_MARKERS never reaches cargo or the test binary, and its markers count for nothing" || { bad "inherited AUDITOR_POC_MARKERS: exit $code"; cat "$T/calls" >&2; }

code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_MARKERS=exploit:loaded)"
[ "$code" = 3 ] && grep -q 'no assert_exploit_effect! ran and held' "$T/out" && ! grep -q 'running same attack' "$T/out" \
  && ok "exploit test passes but leaves no effect marker -> exit 3 before the fixed arm" || bad "no effect marker: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_MARKERS="exploit:attempted=succeeds exploit:held=succeeds exploit:loaded")"
[ "$code" = 3 ] && grep -q 'no assert_exploit_effect! ran and held' "$T/out" \
  && ok "prebuilt bytes: an exploit test that holds only the any-Ok assertion -> exit 3" || bad "prebuilt any-Ok: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_MARKERS="$EV fixed_blocked:loaded")"
[ "$code" = 3 ] && grep -q 'neither assert_exploit_rejected_with! nor assert_exploit_blocked! ran and held' "$T/out" \
  && ok "fixed test passes but leaves no rejection marker -> exit 3" || bad "no fixed marker: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_MARKERS="$EV $FB")"
[ "$code" = 0 ] && grep -qx "${LEG3}${want} fixed sha256=${wantf} (blocked: failed, account unchanged) → \[PoC-REPRODUCED\]" "$T/out" \
  && ok "a blocked marker (a deployed fix) -> exit 0, and the line says blocked, not pinned" || bad "blocked marker: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:attempted fixed_blocked:loaded fixed_blocked:inconclusive")"
[ "$code" = 3 ] && grep -q 'the fixed arm is inconclusive: shim inconclusive' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
  && ok "a fixed arm whose assertion could not decide (an inconclusive marker) -> exit 3, not 2" || bad "inconclusive: exit $code"

# A model run (the crate's own arms) needs a held assertion of each arm too, and prints
# the model line, never the Leg 3 line.
code="$(gate "$T/inc" "$NATIVE")"
[ "$code" = 0 ] && grep -q "(this crate's own arms: a model, never Leg 3)" "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "build mode with each arm's assertion held -> the model line, never the Leg 3 line" || bad "build mode: exit $code"
code="$(gate "$T/inc" "$NATIVE" SHIM_MARKERS=none)"
[ "$code" = 3 ] && grep -q 'tests/exploit.rs passed, but no assertion that the exploit goes through' "$T/out" && ! grep -q '^OK' "$T/out" \
  && ok "build mode: a passing test that ran no contract assertion -> exit 3, no OK line" || bad "build mode without markers: exit $code"
code="$(gate "$T/inc" "$NATIVE" SHIM_MARKERS="exploit:attempted=rejected exploit:held=rejected exploit:loaded $FR")"
[ "$code" = 3 ] && grep -q 'no assertion that the exploit goes through' "$T/out" \
  && ok "build mode: a vulnerable arm that holds only a rejection assertion -> exit 3" || bad "build mode, wrong assertion: exit $code"
code="$(gate "$T/inc" "$NATIVE" SHIM_MARKERS="$EV fixed_blocked:attempted=rejected fixed_blocked:held=rejected fixed_blocked:loaded")"
[ "$code" = 0 ] && grep -q '^OK: exploit reproduces' "$T/out" \
  && ok "build mode: the any-error assertion counts for a model's fixed arm" || bad "build mode, any-error fixed arm: exit $code"
code="$(gate "$T/inc" "$NATIVE" SHIM_MARKERS="exploit:attempted exploit:held exploit:effect $FR")"
[ "$code" = 3 ] && grep -q 'no program was loaded through mollusk_for or litesvm_for!' "$T/out" \
  && ok "build mode: a test that loaded no program through the runner helpers -> exit 3" || bad "build mode, no loaded marker: exit $code"
code="$(gate "$T/inc" "$NATIVE" SHIM_MARKERS="$EV exploit:loaded-other $FR")"
[ "$code" = 3 ] && grep -q 'loaded bytes other than the ones run.sh placed' "$T/out" \
  && ok "build mode: a test that loaded other bytes than the built arm -> exit 3" || bad "build mode, other bytes: exit $code"

# A failed test is a verdict (exit 1 / 2) only when a contract assertion of the arm ran
# and did not hold. One that failed before any assertion ran (the program did not load,
# the setup panicked), or after every assertion held, is inconclusive: exit 3.
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:loaded")"
[ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
  && ok "a fixed-arm test that fails before any contract assertion ran -> exit 3 (inconclusive), not 2" || bad "fixed arm, no assertion ran: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_FAIL=exploit SHIM_MARKERS=none)"
[ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
  && ok "an exploit test that fails before any contract assertion ran -> exit 3, not 1" || bad "exploit, no assertion ran: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV $FR")"
[ "$code" = 3 ] && grep -q 'every contract assertion that ran held' "$T/out" \
  && ok "a fixed-arm test that fails after its contract assertion held -> exit 3, not 2" || bad "fixed arm fails after it held: exit $code"
# A test the process ended inside an assertion (attempted, no held and no failed) is
# not a verdict: the macros write `failed` only when an assertion ran and did not hold,
# so a process that dies between an assertion's start and its result decides nothing.
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_FAIL=exploit SHIM_MARKERS="exploit:attempted exploit:loaded")"
[ "$code" = 3 ] && grep -q 'the process ended mid-assertion' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
  && ok "a vulnerable test that ends inside an assertion (no failed marker) -> exit 3, not 1" || bad "vulnerable arm, died mid-assertion: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:attempted fixed_blocked:loaded")"
[ "$code" = 3 ] && grep -q 'the process ended mid-assertion' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
  && ok "a fixed test that ends inside an assertion (no failed marker) -> exit 3, not 2" || bad "fixed arm, died mid-assertion: exit $code"
code="$(gate "$T/inc" "$NATIVE" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV")"
[ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" \
  && ok "build mode too: a fixed-arm failure with no contract assertion run -> exit 3" || bad "build mode, no assertion ran: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_FAIL=exploit SHIM_MARKERS="exploit:attempted=rejected_with exploit:failed=rejected_with exploit:loaded")"
[ "$code" = 3 ] && grep -q 'is not one this arm counts' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
  && ok "an exploit test that fails in another arm's assertion -> exit 3, not 1" || bad "exploit fails in another arm's assertion: exit $code"
# An any-result assertion counts neither for nor against an arm on prebuilt bytes; in
# a model run it still decides.
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_FAIL=exploit SHIM_MARKERS="exploit:attempted=succeeds exploit:failed=succeeds exploit:loaded")"
[ "$code" = 3 ] && grep -q 'is not one this arm counts' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
  && ok "prebuilt bytes: a failed assert_exploit_succeeds! -> exit 3, not 1" || bad "prebuilt, failed any-result assertion: exit $code"
code="$(gate "$T/inc" "$NATIVE" SHIM_FAIL=exploit SHIM_MARKERS="exploit:attempted=succeeds exploit:failed=succeeds exploit:loaded")"
[ "$code" = 1 ] && grep -q 'did not reproduce' "$T/out" \
  && ok "build mode: a failed assert_exploit_succeeds! is a verdict, exit 1" || bad "build mode, failed any-result assertion: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_MARKERS="$EV exploit:attempted")"
[ "$code" = 3 ] && grep -q 'ran and did not hold, yet the test passed' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "prebuilt bytes: a passing test with a contract assertion that did not hold -> exit 3" || bad "pass with an unheld assertion: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_MARKERS="$EV exploit:inconclusive")"
[ "$code" = 3 ] && grep -q 'the vulnerable arm is inconclusive: shim inconclusive' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "a passing test that left an inconclusive marker -> exit 3" || bad "pass with an inconclusive marker: exit $code"

# Markers are decided test by test: one test's inconclusive result does not hide another
# test's assertion that ran and did not hold; within one test, inconclusive stands.
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked \
  SHIM_MARKERS="$EV fixed_blocked:attempted@guard fixed_blocked:failed@guard fixed_blocked:loaded@guard fixed_blocked:attempted@other fixed_blocked:inconclusive@other fixed_blocked:loaded@other")"
[ "$code" = 2 ] && grep -q 'fix is incomplete' "$T/out" && grep -q '^   failed: test guard$' "$T/out" \
  && ok "a fixed arm where one test's assertion did not hold and another is inconclusive -> exit 2, naming the test" || { bad "fixed arm, failed next to inconclusive: exit $code"; cat "$T/out" >&2; }
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_FAIL=exploit \
  SHIM_MARKERS="exploit:attempted@main exploit:failed@main exploit:loaded@main exploit:attempted@other exploit:inconclusive@other exploit:loaded@other")"
[ "$code" = 1 ] && grep -q 'did not reproduce' "$T/out" \
  && ok "a vulnerable arm where one test's assertion did not hold and another is inconclusive -> exit 1" || bad "vulnerable arm, failed next to inconclusive: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked \
  SHIM_MARKERS="$EV fixed_blocked:attempted@one fixed_blocked:failed@one fixed_blocked:inconclusive@one fixed_blocked:loaded@one")"
[ "$code" = 3 ] && grep -q 'the fixed arm is inconclusive' "$T/out" \
  && ok "one test with both an assertion that did not hold and an inconclusive one -> exit 3" || bad "same test, failed and inconclusive: exit $code"

# The bytes that ran: every program the runner helpers load must be the .so run.sh
# placed, still unchanged after the test, or the arm decides nothing.
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_MARKERS="exploit:attempted exploit:held exploit:effect")"
[ "$code" = 3 ] && grep -q 'no program was loaded through mollusk_for' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "no program loaded through mollusk_for -> exit 3, no Leg 3 line" || bad "no loaded marker: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_MARKERS="$EV exploit:loaded-other")"
[ "$code" = 3 ] && grep -q 'loaded bytes other than the ones run.sh placed' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "an exploit test that also loads other bytes -> exit 3, no Leg 3 line" || bad "vulnerable arm, other bytes: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_MARKERS="$EV $FR fixed_blocked:loaded-other")"
[ "$code" = 3 ] && grep -q 'loaded bytes other than the ones run.sh placed' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "a fixed-arm test that also loads other bytes -> exit 3, no Leg 3 line" || bad "fixed arm, other bytes: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:attempted fixed_blocked:failed fixed_blocked:loaded-other")"
[ "$code" = 3 ] && grep -q 'loaded bytes other than the ones run.sh placed' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
  && ok "a fixed-arm assertion that fails on other bytes -> exit 3, not 2" || bad "fixed arm fails on other bytes: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_MARKERS="$EV exploit:tamper")"
[ "$code" = 3 ] && grep -q 'the placed .so changed while the test ran' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "a placed .so that changes while the test runs -> exit 3, no Leg 3 line" || bad "placed .so changed: exit $code"
# Every build comes before any test: both arms' bytes (SBF builds or prebuilt files) and test binaries, then
# the check of what the builds compiled. A test runs the PoC's code with the scratch copy as
# CARGO_MANIFEST_DIR, so nothing it writes there is compiled; prebuilt bytes are read before it runs; and an
# arm's bytes kept for its test, or its test binary, that changed after the build stop the run before that
# arm's test runs.
for order_run in model prebuilt; do
  if [ "$order_run" = model ]; then code="$(gate "$T/inc" "$NATIVE")"; else code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX")"; fi
  [ "$code" = 0 ] && [ "$(awk -F'\t' '$6 ~ /^testbin /' "$T/calls" | wc -l | tr -d ' ')" = 2 ] \
    && awk -F'\t' '$6 ~ /^testbin / { t = 1 } t && $6 ~ /^(build-sbf|test) / { late = 1 } END { exit late }' "$T/calls" \
    && ok "every build of both arms comes before either test runs ($order_run run)" || { bad "build order, $order_run run: exit $code"; cat "$T/calls" >&2; }
done
cp "$T/fixed.so" "$T/fixed-rewritten.so"
code="$(gate "$T/inc" "$NATIVE" "$VULN" FIXED_SO="$T/fixed-rewritten.so" SHIM_MARKERS="$EV exploit:spoil $FR" SHIM_SPOIL="$T/fixed-rewritten.so")"
[ "$code" = 0 ] && grep -qx "${LEG3}${want} fixed sha256=${wantf} (rejected with the pinned error) → \[PoC-REPRODUCED\]" "$T/out" \
  && [ "$(zhash "$T/fixed-rewritten.so")" != "$wantf" ] \
  && ok "FIXED_SO rewritten while the vulnerable arm's test runs -> the fixed arm runs on the bytes read before it, which the Leg 3 line names" \
  || { bad "FIXED_SO rewritten during the vulnerable arm's test: exit $code"; cat "$T/out" >&2; }
code="$(gate "$T/inc" "$NATIVE" SHIM_MARKERS="$EV exploit:spoil $FR" SHIM_SPOIL=fixed.so)"
[ "$code" = 3 ] && grep -q "^\[PoC-ATTEMPTED\] blocker: the fixed arm's .so changed between its build and its test" "$T/out" && one_blocker \
  && ! awk -F'\t' '$6 ~ /^testbin fixed_blocked/ { f = 1 } END { exit !f }' "$T/calls" && ! grep -q '^OK' "$T/out" \
  && ok "the fixed arm's built bytes, rewritten in the scratch copy by the vulnerable arm's test -> exit 3, the fixed test never runs" \
  || { bad "the fixed arm's kept bytes rewritten: exit $code"; cat "$T/out" >&2; }
cp -p "$T/shim/bin/fixed_blocked" "$T/fixed_blocked.kept"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_MARKERS="$EV exploit:spoil $FR" SHIM_SPOIL="$T/shim/bin/fixed_blocked")"
cp -p "$T/fixed_blocked.kept" "$T/shim/bin/fixed_blocked"
[ "$code" = 3 ] && grep -q "^\[PoC-ATTEMPTED\] blocker: the fixed arm's test binary .* changed between its build and its run" "$T/out" && one_blocker \
  && ! awk -F'\t' '$6 ~ /^testbin fixed_blocked/ { f = 1 } END { exit !f }' "$T/calls" && ! grep -q "^$LEG3" "$T/out" \
  && ok "the fixed arm's test binary, rewritten by the vulnerable arm's test -> exit 3, it never runs" \
  || { bad "the fixed arm's test binary rewritten: exit $code"; cat "$T/out" >&2; }
# The vulnerable arm's builds run its dependencies' build scripts and proc macros in the scratch copy, so the
# checks of the crate run there again right before the fixed arm builds, and cargo metadata must list what it
# listed first: what the checks refuse, written meanwhile, and another package, target, feature or dependency
# stop the run before anything of the fixed arm is built or any test runs; any other change passes. A member
# under markers/ or target/ (which the checks of the crate do not walk) is one such package.
CHANGED="the crate changed in the scratch copy while the vulnerable arm built (its dependencies' build scripts and proc macros run there), and run.sh builds the fixed arm only from the crate it checked:"
while IFS='	' read -r plant_run plant want_plant plant_label; do
  [ -n "$plant_run" ] || continue
  plant_label="${plant_label:-${plant%%|*}}"
  if [ "$plant_run" = model ]; then code="$(gate "$T/inc" "$NATIVE" "SHIM_PLANT=$plant")"; else code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" "SHIM_PLANT=$plant")"; fi
  [ "$code" = 3 ] && grep -qF "[PoC-ATTEMPTED] blocker: $CHANGED $want_plant" "$T/out" && one_blocker \
    && ! awk -F'\t' '$6 ~ /^testbin / || $6 ~ /^(build-sbf|test) .*--features fixed/ { f = 1 } END { exit !f }' "$T/calls" \
    && ok "a $plant_run run whose vulnerable-arm build writes $plant_label into the scratch copy -> exit 3 before the fixed arm builds or a test runs" \
    || { bad "a $plant_run run whose vulnerable-arm build writes $plant_label: exit $code"; cat "$T/out" >&2; }
done <<'CASES'
model	Cargo.toml|\n[patch.crates-io]\nborsh = { path = "/elsewhere/borsh" }\n	Cargo.toml:6 holds a [patch] or [replace] table
model	src/lib.rs|\ncore::arch::global_asm!("");\n	src/lib.rs:2 names global_asm, inline assembly
prebuilt	.cargo/config.toml|[build]\nrustc-wrapper = "/elsewhere/wrapper"\n	it now holds .cargo, a symbolic link, a .cargo/ directory
model	tests/fixtures/poc_shim.so|\177ELFother	it now holds tests/fixtures/poc_shim.so, which mollusk would load in place of the arm
model	../.cargo/config.toml|[build]\nrustc-wrapper = "/elsewhere/wrapper"\n	it would now inherit /
model	Cargo.toml|\nmembers = ["markers/evil"]\n||markers/evil/Cargo.toml|[package]\nname = "evil"\n||markers/evil/src/lib.rs|mod inner;\n||markers/evil/src/inner.rs|core::arch::global_asm!("");\n	its manifests now name the package evil (markers/evil/Cargo.toml), which they did not name when run.sh checked them — nothing of the fixed arm was built.	a workspace member under markers/ (named in Cargo.toml) whose module holds global_asm
prebuilt	evil/Cargo.toml|[package]\nname = "evil"\n	its manifests now name the package evil (evil/Cargo.toml), which they did not name when run.sh checked them — nothing of the fixed arm was built.	a new workspace member, evil/Cargo.toml
model	tests/extra.rs|#[test]\nfn extra() {}\n	its package poc_shim (Cargo.toml) differs from the one run.sh checked, in its targets — nothing of the fixed arm was built.	a new test target, tests/extra.rs
model	Cargo.toml|\n[features]\nfixed = ["vulnerable"]\n	its package poc_shim (Cargo.toml) differs from the one run.sh checked, in its features — nothing of the fixed arm was built.	a [features] table whose fixed feature turns on vulnerable
CASES
# A test build that compiled a target of the crate that the first cargo metadata did not list (the crate
# changed in the scratch copy during the builds, inside an arm too: a member under markers/ that the library
# came to depend on, a bin cargo found in src/bin/, the library from another source) stops the run right
# after that build, before anything else builds or any test runs: what reads the builds afterwards (the SBF
# dep-info, the files the builds read) works from that first listing.
UNLISTED="which cargo metadata did not list when run.sh checked the crate: the crate changed in the scratch copy during the builds (its dependencies' build scripts and proc macros run there), and run.sh builds only the crate it checked."
while IFS='	' read -r unit_run unit want_unit; do
  [ -n "$unit_run" ] || continue
  if [ "$unit_run" = model ]; then code="$(gate "$T/inc" "$NATIVE" "SHIM_UNIT=$unit")"; else code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" "SHIM_UNIT=$unit")"; fi
  after='$6 ~ /^testbin /'; [ "${unit%%|*}" = vulnerable ] && after='$6 ~ /^testbin / || $6 ~ /^(build-sbf|test) .*--features fixed/'
  [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: the build compiled $want_unit, $UNLISTED" "$T/out" && one_blocker \
    && ! awk -F'\t' "$after { f = 1 } END { exit !f }" "$T/calls" \
    && ok "a $unit_run run whose ${unit%%|*} arm's test build compiled $want_unit, unlisted -> exit 3 right after that build, before any test" \
    || { bad "a $unit_run run whose ${unit%%|*} arm's test build compiled $want_unit: exit $code"; cat "$T/out" >&2; }
done <<'CASES'
model	vulnerable|markers/evil|evil|lib|markers/evil/src/lib.rs	the lib target evil (markers/evil/src/lib.rs) of markers/evil/Cargo.toml
prebuilt	fixed|.|poc_shim_bin|bin|src/bin/poc_shim_bin.rs	the bin target poc_shim_bin (src/bin/poc_shim_bin.rs) of Cargo.toml
model	vulnerable|.|poc_shim|cdylib,lib|src/other.rs	the cdylib/lib target poc_shim (src/other.rs) of Cargo.toml
CASES
code="$(gate "$T/inc" "$NATIVE" "SHIM_PLANT=src/notes.txt|written by a build script\n")"
[ "$code" = 0 ] && grep -q '^OK: exploit reproduces' "$T/out" && ok "a model run whose vulnerable-arm build writes a file the checks do not refuse runs" \
  || { bad "a model run whose vulnerable-arm build writes src/notes.txt: exit $code"; cat "$T/out" >&2; }

code="$(gate "$T/inc" "$NATIVE" "$VULN" BPF_OUT_DIR="$T")"
[ "$code" = 0 ] && awk -F'\t' '$4 != "" { bad = 1 } END { exit bad }' "$T/calls" && ok "a caller's BPF_OUT_DIR never reaches cargo (mollusk would look there before SBF_OUT_DIR)" || bad "BPF_OUT_DIR: exit $code"
mk_crate "$T/fixture"; mkdir -p "$T/fixture/tests/fixtures"; cp "$T/vuln.so" "$T/fixture/tests/fixtures/poc_shim.so"
code="$(gate "$T/fixture" "$NATIVE" "$VULN")"
[ "$code" = 3 ] && grep -q 'tests/fixtures/poc_shim.so would load in place of the arm' "$T/out" && nothing_built \
  && ok "tests/fixtures/<crate>.so in the crate -> refused before anything is built" || bad "tests/fixtures shadow: exit $code"

# cargo's JSON output names the test binary; a large one (well above a 64 KiB pipe
# buffer) is read whole, and a build that names none is a blocker.
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_JSON_PAD=1500 KEEP_POC_BUILD=1)"
bd="$(build_dir)"; size="$(wc -c < "$bd/markers/build-vulnerable.json" 2>/dev/null | tr -d ' ')"
[ "$code" = 0 ] && [ "${size:-0}" -gt 65536 ] && grep -q "^$LEG3" "$T/out" \
  && ok "a ${size}-byte JSON build output -> the test binary is still found, exit 0" || bad "large JSON output: exit $code, ${size:-0} bytes"
[ -n "$bd" ] && rm -rf "$bd"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_FAIL=no-exe:exploit)"
[ "$code" = 3 ] && grep -q 'cargo reported 0 test binaries for tests/exploit.rs in this crate' "$T/out" && one_blocker \
  && ok "a test build that names no test binary -> exit 3, one blocker line" || bad "no test binary: exit $code"

# The non-registry line: before the final line, the path and git dependencies in the
# resolved Cargo.lock; "none" when every dependency comes from a registry.
mk_crate "$T/nonreg"
code="$(gate "$T/nonreg" "$NATIVE" "$VULN" "SHIM_LOCK=vault@0.2.0@path helper@1.0.0@git+https://example.invalid/helper.git#abc borsh@1.8.1@registry+https://github.com/rust-lang/crates.io-index")"
line="$(grep -n -m 1 '^   non-registry code: ' "$T/out")"; okline="$(grep -n -m 1 "^$LEG3" "$T/out")"
[ "$code" = 0 ] && [ "${line#*:}" = "   non-registry code: vault 0.2.0 (path), helper 1.0.0 (git+https://example.invalid/helper.git#abc)" ] \
  && [ "${line%%:*}" -lt "${okline%%:*}" ] \
  && ok "the path and git dependencies in Cargo.lock are named before the OK line" || { bad "non-registry line: exit $code, '$line'"; cat "$T/out" >&2; }
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_FAIL=exploit SHIM_MARKERS="exploit:attempted exploit:failed exploit:loaded")"
[ "$code" = 1 ] && grep -q '^   non-registry code: none' "$T/out" && ok "a verdict line also comes after the non-registry line" || bad "non-registry line on a verdict: exit $code"
# The non-registry line from the dep-info (.d) files of the crate's own units, read by run.sh's harness
# code on its own: every file from outside the crate that the library, a test or the harness copy compiled
# or read, of any kind, by an absolute path or a relative one (taken from the workspace root, where cargo
# runs rustc for them), and an SBF build's dep-info; a dependency from a registry other than crates.io;
# but no build output named as a rule's target (in a build cache outside the crate here), no file of
# crates.io's sources, and no dependency's own dep-info.
python3 -I -c 'import sys; src = open(sys.argv[1], encoding="utf-8").read(); sys.stdout.write(src.split("\nHARNESS_PY=\x27", 1)[1].split("\n\x27\n", 1)[0])' "$TEMPLATE/run.sh" > "$T/harness-nr.py"
NR="$T/nr"; NO="$T/nr-outside"; NCH="$T/nr-cargo-home"; ND="$T/nr-cache/debug/deps"
mkdir -p "$NR/src" "$NR/tests" "$NR/shared-test-utils/src" "$NO" "$ND" "$NCH/registry/src"
python3 -I - "$NR" "$NO" "$NCH" "$ND" "$T/nr-sbf.d" <<'PY'
import json, os, sys
nr, no, ch, nd, sbf = sys.argv[1:]
crates_io = ch + "/registry/src/index.crates.io-0123456789abcdef"
def depinfo(path, outputs, files):
    files = [f.replace(" ", "\\ ") for f in files]
    with open(path, "w") as f:
        for out in outputs:
            f.write("%s: %s\n\n" % (out, " ".join(files)))
        for name in files:
            f.write("%s:\n" % name)
        f.write("\n# env-dep:CARGO_PKG_NAME=x\n")
def artifact(manifest, name, kind, filenames, exe=None):
    return json.dumps({"reason": "compiler-artifact", "package_id": "path+file://%s#%s@0.1.0" % (os.path.dirname(manifest), name),
                       "manifest_path": manifest, "target": {"kind": kind, "crate_types": kind, "name": name,
                       "src_path": os.path.join(os.path.dirname(manifest), "src", "lib.rs")}, "profile": {"test": False},
                       "features": [], "filenames": filenames, "executable": exe, "fresh": False})
for m in (nr, nr + "/shared-test-utils"):
    open(m + "/Cargo.toml", "w").write("[package]\n")
json.dump({"packages": [{"name": "poc_nr", "version": "0.1.0", "manifest_path": nr + "/Cargo.toml", "targets": [], "dependencies": []},
                        {"name": "shared-test-utils", "version": "0.1.0", "manifest_path": nr + "/shared-test-utils/Cargo.toml",
                         "targets": [], "dependencies": []}], "workspace_root": nr}, open(nr + "-meta.json", "w"))
lock = [("poc_nr", "0.1.0", None), ("shared-test-utils", "0.1.0", None), ("vault", "0.2.0", None),
        ("helper", "1.0.0", "git+https://example.invalid/helper.git#abc"), ("borsh", "1.8.1", "registry+https://github.com/rust-lang/crates.io-index"),
        ("sbor", "1.0.0", "sparse+https://index.crates.io/"), ("evil", "0.1.0", "registry+file:///nr/index")]
with open(nr + "/Cargo.lock", "w") as f:
    f.write("version = 4\n")
    for name, version, source in lock:
        f.write('\n[[package]]\nname = "%s"\nversion = "%s"\n%s' % (name, version, 'source = "%s"\n' % source if source else ""))
with open(nr + "-build.json", "w") as f:
    f.write(artifact(nr + "/Cargo.toml", "poc_nr", ["cdylib", "lib"], [nd + "/libpoc_nr.dylib", nd + "/libpoc_nr.rlib"]) + "\n")
    f.write(artifact(nr + "/Cargo.toml", "exploit", ["test"], [nd + "/exploit-0a1b"], nd + "/exploit-0a1b") + "\n")
    f.write(artifact(nr + "/shared-test-utils/Cargo.toml", "shared_test_utils", ["lib"], [nd + "/libshared_test_utils-5e6f.rlib"]) + "\n")
    f.write(artifact(crates_io + "/borsh-1.8.1/Cargo.toml", "borsh", ["lib"], [nd + "/libborsh-7a8b.rlib"]) + "\n")
depinfo(nd + "/poc_nr.d", [nd + "/poc_nr.d", nd + "/libpoc_nr.dylib", nd + "/libpoc_nr.rlib"],
        ["src/lib.rs", no + "/state.rs", no + "/payload.inc", no + "/with space.txt", crates_io + "/serde-1.0.0/src/data.json",
         ch + "/registry/src/evil.example-0123456789abcdef/x-1.0.0/src/lib.rs", ch + "/git/checkouts/x-0123/abc/src/lib.rs"])
depinfo(nd + "/exploit-0a1b.d", [nd + "/exploit-0a1b.d", nd + "/exploit-0a1b"], ["tests/exploit.rs", "tests/../../nr-outside/helper.rs", no + "/key.json"])
depinfo(nd + "/shared_test_utils-5e6f.d", [nd + "/shared_test_utils-5e6f.d"], ["shared-test-utils/src/lib.rs"])
depinfo(nd + "/borsh-7a8b.d", [nd + "/borsh-7a8b.d"], [no + "/not-ours.rs"])
depinfo(sbf, ["/target/sbpf-solana-solana/release/deps/poc_nr.d"], ["src/lib.rs", no + "/sbf-only.rs"])
PY
out="$(env -i PATH="$PATH" CARGO_HOME="$NCH" python3 -I "$T/harness-nr.py" nonregistry "$NR" "$NR/Cargo.lock" "$NR-meta.json" "$NR-build.json" "$T/nr-sbf.d")"; rc=$?
want_nr="vault 0.2.0 (path), helper 1.0.0 (git+https://example.invalid/helper.git#abc), evil 0.1.0 (registry+file:///nr/index, not crates.io), $NO/helper.rs (compiled in), $NO/key.json (compiled in), $NO/state.rs (compiled in), $NO/payload.inc (compiled in), $NO/with space.txt (compiled in), $NCH/registry/src/evil.example-0123456789abcdef/x-1.0.0/src/lib.rs (compiled in), $NCH/git/checkouts/x-0123/abc/src/lib.rs (compiled in), $NO/sbf-only.rs (compiled in)"
[ "$rc" = 0 ] && [ "$out" = "$want_nr" ] \
  && ok "the non-registry line names every outside file the crate's own units read (any kind, absolute or relative, the SBF build's too) and another registry's crates" \
  || { bad "harness nonregistry on the crate's own dep-info: $rc"; printf 'got:  %s\nwant: %s\n' "$out" "$want_nr" >&2; }
# The same through run.sh, before the final line: the library's dep-info in a build (prebuilt bytes), and an
# arm's SBF build in a model run.
DI="$T/di-outside"; mkdir -p "$DI"
printf '@ROOT@/target/debug/deps/poc_shim.d: src/lib.rs %s/state.rs %s/payload.inc\n\nsrc/lib.rs:\n%s/state.rs:\n%s/payload.inc:\n' "$DI" "$DI" "$DI" "$DI" > "$T/di-lib.d"
printf '/target/sbpf-solana-solana/release/deps/poc_shim.d: src/lib.rs %s/sbf-only.rs\n\nsrc/lib.rs:\n%s/sbf-only.rs:\n' "$DI" "$DI" > "$T/di-sbf.d"
mk_crate "$T/di"
code="$(gate "$T/di" "$NATIVE" "$VULN" SHIM_DEPINFO="$T/di-lib.d")"
line="$(grep -n -m 1 '^   non-registry code: ' "$T/out")"; okline="$(grep -n -m 1 "^$LEG3" "$T/out")"
[ "$code" = 0 ] && [ "${line#*:}" = "   non-registry code: $DI/state.rs (compiled in), $DI/payload.inc (compiled in)" ] && [ "${line%%:*}" -lt "${okline%%:*}" ] \
  && ok "a #[path] module and an include! of a non-.rs file in the library are named before the OK line" || { bad "the library's dep-info: exit $code, '$line'"; cat "$T/out" >&2; }
code="$(gate "$T/di" "$NATIVE" SHIM_SBF_DEPINFO="$T/di-sbf.d")"
[ "$code" = 0 ] && grep -qxF "   non-registry code: $DI/sbf-only.rs (compiled in)" "$T/out" && grep -q '^OK: exploit reproduces' "$T/out" \
  && ok "a module only the SBF build compiles is named on the non-registry line of a model run" || { bad "the SBF build's dep-info: exit $code"; cat "$T/out" >&2; }
# A member the crate's library depends on for the SBF target alone is compiled by that build only: the
# dep-info this run's build wrote for it there is read, and an older one of a crate of the same name, left in
# a shared build cache, is not.
DC="$T/di-cache"; DCD="$DC/sbpf-solana-solana/release/deps"; mkdir -p "$DCD"
printf '%s/libshared_test_utils-0123456789abcdef.rlib: shared-test-utils/src/lib.rs %s/stale.rs\n\nshared-test-utils/src/lib.rs:\n%s/stale.rs:\n' "$DCD" "$DI" "$DI" > "$DCD/shared_test_utils-0123456789abcdef.d"
touch -t 202001010000 "$DCD/shared_test_utils-0123456789abcdef.d"
printf '/target/sbpf-solana-solana/release/deps/shared_test_utils-0a1b2c3d4e5f6071.d: shared-test-utils/src/lib.rs %s/sbf-member.rs\n\nshared-test-utils/src/lib.rs:\n%s/sbf-member.rs:\n' "$DI" "$DI" > "$T/di-sbf-member.d"
code="$(gate "$T/di" "$NATIVE" CARGO_TARGET_DIR="$DC" SHIM_SBF_DEPINFO="$T/di-sbf-member.d" SHIM_SBF_DEPINFO_AS=shared_test_utils-0a1b2c3d4e5f6071.d)"
[ "$code" = 0 ] && grep -qxF "   non-registry code: $DI/sbf-member.rs (compiled in)" "$T/out" && grep -q '^OK: exploit reproduces' "$T/out" \
  && ok "a member only the SBF build compiles is named; an older dep-info of that name in the build cache is not" || { bad "an SBF-only member's dep-info: exit $code"; cat "$T/out" >&2; }
# A file of the crate that the build read under a name not ending in .rs is read as the crate's .rs files
# are: inline assembly in it (an include! takes it in as Rust code) stops the run after the build, before
# the test runs; data whose strings only mention such words passes.
mk_crate "$T/di-inc"; mkdir -p "$T/di-inc/src"
printf 'core::arch::global_asm!(".incbin \\"%s/blob.bin\\"");\n' "$DI" > "$T/di-inc/src/payload.txt"
printf '{"note": "a link to the asm notes", "keys": [1, 2]}\n' > "$T/di-inc/src/data.json"
printf '@ROOT@/target/debug/deps/poc_shim.d: src/lib.rs src/data.json src/payload.txt\n\nsrc/lib.rs:\nsrc/data.json:\nsrc/payload.txt:\n' > "$T/di-inc.d"
printf '@ROOT@/target/debug/deps/poc_shim.d: src/lib.rs src/data.json\n\nsrc/lib.rs:\nsrc/data.json:\n' > "$T/di-data.d"
code="$(gate "$T/di-inc" "$NATIVE" "$VULN" SHIM_DEPINFO="$T/di-inc.d")"
[ "$code" = 3 ] && grep -qF '[PoC-ATTEMPTED] blocker: src/payload.txt:1 names global_asm, inline assembly' "$T/out" && one_blocker \
  && ! awk -F'\t' '$6 ~ /^testbin / { f = 1 } END { exit !f }' "$T/calls" \
  && ok "inline assembly in a file of the crate the build read as src/payload.txt -> exit 3 after the build, the test never runs" \
  || { bad "a file of the crate with inline assembly, read under another name than .rs: exit $code"; cat "$T/out" >&2; }
code="$(gate "$T/di-inc" "$NATIVE" "$VULN" SHIM_DEPINFO="$T/di-data.d")"
[ "$code" = 0 ] && grep -qxF '   non-registry code: none: every dependency comes from a registry' "$T/out" \
  && ok "data of the crate the build read (src/data.json), whose strings mention link and asm -> not refused" || { bad "a data file of the crate: exit $code"; cat "$T/out" >&2; }
# Every file of the crate the build read is read again once the builds are done, a .rs one too: one that
# appeared or changed during the build (here under target/, which the crate check never reads). A build that
# read one of run.sh's own files in the scratch copy (markers/) is refused too. The harness code on its own.
NR2="$T/nr2"; mkdir -p "$NR2/target/gen" "$NR2/markers/tmp" "$NR2/src"
printf 'core::arch::global_asm!(".incbin \\"%s/blob.bin\\"");\n' "$DI" > "$NR2/target/gen/planted.rs"
printf 'pub const NOTE: u8 = 1;\n' > "$NR2/markers/tmp/note.rs"; printf 'pub fn f() {}\n' > "$NR2/src/lib.rs"
printf '[package]\n' > "$NR2/Cargo.toml"; printf 'version = 4\n' > "$NR2/Cargo.lock"
printf '{"packages": [{"name": "poc_nr2", "version": "0.1.0", "manifest_path": "%s/Cargo.toml", "targets": [], "dependencies": []}], "workspace_root": "%s"}\n' "$NR2" "$NR2" > "$NR2-meta.json"
while IFS='|' read -r nr2_file nr2_rc nr2_says; do
  [ -n "$nr2_file" ] || continue
  printf '/x/deps/poc_nr2.d: src/lib.rs %s\n\nsrc/lib.rs:\n%s:\n' "$nr2_file" "$nr2_file" > "$T/nr2.d"
  out="$(env -i PATH="$PATH" python3 -I "$T/harness-nr.py" nonregistry "$NR2" "$NR2/Cargo.lock" "$NR2-meta.json" "$T/nr2.d")"; rc=$?
  [ "$rc" = "$nr2_rc" ] && case "$out" in "$nr2_says"*) true ;; *) false ;; esac \
    && ok "harness nonregistry, the build read the crate's $nr2_file -> exit $nr2_rc, '$nr2_says'" || bad "harness nonregistry, $nr2_file: $rc '$out'"
done <<'CASES'
src/lib.rs|0|none: every dependency comes from a registry
target/gen/planted.rs|3|target/gen/planted.rs:1 names global_asm, inline assembly
markers/tmp/note.rs|3|the build read markers/tmp/note.rs, one of run.sh's own files in the scratch copy (markers/)
CASES
# The re-check's comparison of cargo metadata with its first reading, on its own: the same reading passes,
# and a package gone or another value of a workspace field is named.
python3 -I - "$NR2" <<'PY'
import json, sys
root = sys.argv[1]
pkg = lambda name, at: {"name": name, "version": "0.1.0", "manifest_path": root + at, "targets": [], "features": {}, "dependencies": []}
first = {"packages": [pkg("poc_nr2", "/Cargo.toml"), pkg("shared-test-utils", "/shared-test-utils/Cargo.toml")], "workspace_root": root, "target_directory": root + "/target"}
json.dump(first, open(root + "-first.json", "w"))
json.dump(first, open(root + "-same.json", "w"))
json.dump(dict(first, packages=first["packages"][:1]), open(root + "-gone.json", "w"))
json.dump(dict(first, target_directory="/elsewhere/target"), open(root + "-dir.json", "w"))
PY
while IFS='|' read -r sc_again sc_what sc_rc sc_says; do
  [ -n "$sc_again" ] || continue
  out="$(env -i PATH="$PATH" python3 -I "$T/harness-nr.py" samecrate "$NR2-first.json" "$NR2-$sc_again.json")"; rc=$?
  [ "$rc" = "$sc_rc" ] && [ "$out" = "$sc_says" ] && ok "harness samecrate, a second reading $sc_what -> exit $sc_rc${sc_says:+, '$sc_says'}" \
    || bad "harness samecrate, a second reading $sc_what: $rc '$out'"
done <<'CASES'
same|equal to the first|0|
gone|without one of the packages|3|its manifests no longer name the package shared-test-utils (shared-test-utils/Cargo.toml), which they named when run.sh checked them
dir|with another target directory|3|cargo metadata gives it another target_directory than when run.sh checked it
CASES

# A hashlib.py planted in the crate, which the scratch copy holds too, and on PYTHONPATH
# must not load when run.sh hashes the bytes; the control shows it would without -I.
mk_crate "$T/hostile"
MARK="$T/shadow.marker"
printf 'open(%s, "a").write("hashlib\\n")\n' "'$MARK'" > "$T/hostile/hashlib.py"
( cd "$T/hostile" && printf 'import hashlib\n' | python3 - >/dev/null 2>&1 )
[ -s "$MARK" ] && ok "isolation control: without -I, the crate dir's hashlib.py replaces the stdlib" || bad "isolation control: planted hashlib.py did not load, so the next check proves nothing"
rm -f "$MARK"
code="$(run "$T/hostile" "$SP" "$NATIVE" "$VULN" "$FIX" PYTHONPATH="$T/hostile")"
if [ "$code" = 0 ] && grep -q "vulnerable sha256 (zero-trimmed): $want" "$T/out" && grep -q "^${LEG3}${want} " "$T/out" && [ ! -e "$MARK" ]; then
  ok "hash under a planted hashlib.py (cwd + PYTHONPATH) is correct and the module never ran"
else
  bad "planted hashlib.py: exit $code, marker $( [ -e "$MARK" ] && echo present || echo absent )"; cat "$T/out" >&2
fi
# Every python3 run.sh starts to read cargo's output, the manifests, the markers and the bytes starts from
# /, with absolute paths: a version manager's shim picks the interpreter from the directory it starts in,
# and the scratch copy holds the crate's files. A python3 stand-in first on PATH records where each of
# those calls started.
PYH="$T/pyh-bin"; mkdir -p "$PYH"
printf '#!/bin/sh\ncase "$4" in hash|crate|samecrate|targetdir|checkbuild|settle|nonregistry|sbfdeps|stucopy) printf "%%s %%s\\n" "$(pwd -P)" "$4" >> "%s" ;; esac\nexec "%s" "$@"\n' \
  "$T/pyh.log" "$(command -v python3)" > "$PYH/python3"
chmod +x "$PYH/python3"
for how in "prebuilt bytes" "a model run"; do
  rm -f "$T/pyh.log"
  want_calls="checkbuild crate hash nonregistry samecrate settle targetdir "
  if [ "$how" = "a model run" ]; then
    want_calls="checkbuild crate hash nonregistry samecrate sbfdeps settle targetdir "; code="$(gate "$T/inc" "$NATIVE" PATH="$PYH:$SP")"
  else code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" PATH="$PYH:$SP")"; fi
  calls="$(awk '{ print $NF }' "$T/pyh.log" 2>/dev/null | LC_ALL=C sort -u | tr '\n' ' ')"
  [ "$code" = 0 ] && [ "$calls" = "$want_calls" ] && ! grep -qvE '^/ [a-z]+$' "$T/pyh.log" \
    && ok "run.sh's own python3 calls ($calls) all start from /, $how" \
    || { bad "run.sh's python3 calls, $how: exit $code, started in: $(sed 's/ [a-z]*$//' "$T/pyh.log" 2>/dev/null | LC_ALL=C sort -u | tr '\n' ' ')"; cat "$T/out" >&2; }
done

# ---------------------------------------------------------------------------
# The crate's own build-time code, refused in either mode from the manifests alone:
# nothing compiles, and the scratch copy is removed.
# ---------------------------------------------------------------------------
for meta in build-script proc-macro; do
  want_text='is a build script of poc_shim'; [ "$meta" = proc-macro ] && want_text='is a proc-macro package'
  for mode in "$VULN" "VULNERABLE_SO="; do
    label=prebuilt; [ "$mode" = "VULNERABLE_SO=" ] && label=build
    code="$(gate "$T/inc" "$NATIVE" "$mode" SHIM_META="$meta")"
    [ "$code" = 3 ] && grep -q "$want_text" "$T/out" && nothing_built && one_blocker \
      && ok "a $meta in the crate ($label mode) -> exit 3 before anything compiles, one blocker line" || { bad "$meta, $label mode: exit $code"; cat "$T/out" >&2; }
  done
done
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_FAIL=metadata)"
[ "$code" = 3 ] && grep -q "cargo could not read the crate's manifests" "$T/out" && nothing_built \
  && ok "a manifest cargo cannot read -> exit 3 before anything compiles" || bad "cargo metadata fails: exit $code"
# [patch] and [replace] tables, in every TOML spelling of their first key, in the root
# manifest or a member's; a comment, a string or another key that only mentions them
# passes.
mk_patched() {  # mk_patched <dir> <manifest> <text appended>
  mk_crate "$1"; mkdir -p "$1/shared-test-utils/src"
  printf '[package]\nname = "shared-test-utils"\nversion = "0.1.0"\n' > "$1/shared-test-utils/Cargo.toml"
  printf '%s\n' "$3" >> "$1/$2"
}
n=0
while IFS='|' read -r where text; do
  [ -n "$where" ] || continue
  n=$((n + 1)); body="$(printf '%b' "$text")"; first="${body%%$'\n'*}"
  mk_patched "$T/patch-$n" "$where" "$body"
  code="$(gate "$T/patch-$n" "$NATIVE" "$VULN")"
  [ "$code" = 3 ] && grep -q 'holds a \[patch\] or \[replace\] table' "$T/out" && nothing_built && one_blocker \
    && ok "refused before anything compiles: $where gets $first" || { bad "$where with $first: exit $code"; cat "$T/out" >&2; }
done <<'CASES'
Cargo.toml|[patch.crates-io]\nborsh = { path = "/elsewhere/borsh" }
Cargo.toml|[ patch . "crates-io" ]\nborsh = { path = "/elsewhere/borsh" }
Cargo.toml|["\\u0070atch".crates-io]\nborsh = { path = "/elsewhere/borsh" }
Cargo.toml|['patch'.crates-io]\nborsh = { path = "/elsewhere/borsh" }
Cargo.toml|[replace]\n"borsh:1.0.0" = { path = "/elsewhere/borsh" }
Cargo.toml|[[patch.crates-io]]
shared-test-utils/Cargo.toml|[patch.crates-io]\nmollusk-svm = { path = "/elsewhere/mollusk" }
CASES
for text in 'patch.crates-io.borsh = { path = "/elsewhere/borsh" }' 'patch = { crates-io = { borsh = { path = "/elsewhere/borsh" } } }'; do
  mk_crate "$T/patch-root"; printf '%s\n%s\n' "$text" "$(cat "$T/patch-root/Cargo.toml")" > "$T/patch-root/Cargo.toml.new" && mv "$T/patch-root/Cargo.toml.new" "$T/patch-root/Cargo.toml"
  code="$(gate "$T/patch-root" "$NATIVE" "$VULN")"
  [ "$code" = 3 ] && grep -q 'Cargo.toml:1 holds a \[patch\] or \[replace\] table' "$T/out" && ok "refused: a top-level key, $text" || bad "top-level $text: exit $code"
  rm -rf "$T/patch-root"
done
# A manifest that cargo can read under another letter case is checked like one.
mk_crate "$T/lc-manifest"; mkdir -p "$T/lc-manifest/inner/src"
printf '[package]\nname = "inner"\nversion = "0.1.0"\n' > "$T/lc-manifest/inner/cargo.toml"
code="$(gate "$T/lc-manifest" "$NATIVE" "$VULN")"
[ "$code" = 3 ] && grep -q 'inner/cargo.toml is not a member' "$T/out" && nothing_built \
  && ok "a cargo.toml outside the workspace, spelled in another letter case -> refused before anything compiles" || bad "lower-case manifest: exit $code"
# The harness binding, from the manifests: the crate depends on its own
# shared-test-utils/, imported as shared_test_utils, and no other dependency takes that
# import name, spelled with - or _. Each of these is refused before anything compiles.
while IFS='|' read -r stu text; do
  [ -n "$stu" ] || continue
  code="$(gate "$T/inc" "$NATIVE" "$VULN" "SHIM_STU=$stu")"
  [ "$code" = 3 ] && grep -qF "$text" "$T/out" && nothing_built && one_blocker \
    && ok "harness binding: the dependency '$stu' -> refused before anything compiles" || { bad "harness binding '$stu': exit $code"; cat "$T/out" >&2; }
done <<'CASES'
none|does not depend on its own shared-test-utils/
evil-harness,shared_test_utils,/elsewhere/eh|imports evil-harness as shared_test_utils
evil-harness,shared-test-utils,/elsewhere/eh|imports evil-harness as shared_test_utils
shared_test_utils,,/elsewhere/eh|imports shared_test_utils as shared_test_utils
shared-test-utils,harness,@copy|imports its shared-test-utils dependency as harness
shared-test-utils,,|names a shared-test-utils dependency at a registry
CASES
code="$(gate "$T/inc" "$NATIVE" "$VULN" "SHIM_STU=shared-test-utils,shared_test_utils,@copy")"
[ "$code" = 0 ] && grep -q "^$LEG3" "$T/out" && ok "harness binding: the crate's own copy keyed as shared_test_utils -> accepted" || { bad "harness binding, own copy keyed with _: exit $code"; cat "$T/out" >&2; }
# And from each arm's build: a shared_test_utils compiled from anywhere but the copy,
# or none at all, stops the run before its test binary runs.
for stu in none elsewhere; do
  want_text='compiled no shared_test_utils'; [ "$stu" = elsewhere ] && want_text='outside the copied harness'
  code="$(gate "$T/inc" "$NATIVE" "$VULN" "SHIM_STU_BUILD=$stu")"
  [ "$code" = 3 ] && grep -q "$want_text" "$T/out" && one_blocker && ! awk -F'\t' '$6 ~ /^testbin / { f = 1 } END { exit !f }' "$T/calls" \
    && ok "harness binding: a build with $stu shared_test_utils -> exit 3, no test binary run" || { bad "harness binding, build $stu: exit $code"; cat "$T/out" >&2; }
done
mk_patched "$T/patch-mention" Cargo.toml "$(printf '# [patch.crates-io]\n[package.metadata.notes]\ntext = "see [patch.crates-io]"\npatch-level = 1')"
code="$(gate "$T/patch-mention" "$NATIVE" "$VULN")"
[ "$code" = 0 ] && ok "a comment, a string and a patch-level key that only mention [patch] -> not refused" || { bad "mentions of [patch]: exit $code"; cat "$T/out" >&2; }
# A cargo-features key, with which a nightly cargo lets the manifest choose code that runs at build time (a
# linker in [profile] rustflags, a codegen backend), in any TOML spelling, in the root manifest or a
# member's, is refused before anything compiles; a comment, a string or another key that only mentions it
# passes.
n=0
while IFS='|' read -r where text; do
  [ -n "$where" ] || continue
  n=$((n + 1)); mk_patched "$T/cf-$n" Cargo.toml ""
  printf '%s\n%s\n' "$text" "$(cat "$T/cf-$n/$where")" > "$T/cf-$n/$where.new" && mv "$T/cf-$n/$where.new" "$T/cf-$n/$where"
  code="$(gate "$T/cf-$n" "$NATIVE" "$VULN")"
  [ "$code" = 3 ] && grep -qF "$where:1 holds a cargo-features key" "$T/out" && nothing_built && one_blocker \
    && ok "refused before anything compiles: $where starts with $text" || { bad "$where with $text: exit $code"; cat "$T/out" >&2; }
done <<'CASES'
Cargo.toml|cargo-features = ["profile-rustflags"]
Cargo.toml|"cargo-features" = ["codegen-backend"]
Cargo.toml|'cargo-features' = ["profile-rustflags"]
Cargo.toml|"cargo-features" = ["profile-rustflags"]
shared-test-utils/Cargo.toml|cargo-features = ["profile-rustflags"]
CASES
mk_patched "$T/cf-mention" Cargo.toml "$(printf '# cargo-features = ["profile-rustflags"]\n[package.metadata.notes]\ntext = "cargo-features"\ncargo-features-note = 1')"
code="$(gate "$T/cf-mention" "$NATIVE" "$VULN")"
[ "$code" = 0 ] && ok "a comment, a string and a key that only mention cargo-features -> not refused" || { bad "mentions of cargo-features: exit $code"; cat "$T/out" >&2; }
# The crate is its own workspace root: one that belongs to an outside workspace (a workspace key under
# [package]) would build into that workspace's target directory under its [patch], which these checks
# never read. cargo metadata names the root; any other than the scratch copy is refused before anything
# compiles.
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_WS_ROOT=/elsewhere/ws)"
[ "$code" = 3 ] && grep -qF 'the crate belongs to the workspace at /elsewhere/ws, not to its own' "$T/out" && nothing_built && one_blocker \
  && ok "a crate whose workspace root is outside it -> refused before anything compiles" || { bad "outside workspace root: exit $code"; cat "$T/out" >&2; }
# A PoC crate builds its library and its tests. Any other target of a member is refused before anything
# compiles: a bin, which cargo builds with every integration test; an example or a bench; a dylib or a
# staticlib, which cargo places outside the deps directory whose dep-info run.sh reads; and a cdylib of a
# member other than the crate.
while IFS='|' read -r var named; do
  [ -n "$var" ] || continue
  code="$(gate "$T/inc" "$NATIVE" "$VULN" "$var")"
  [ "$code" = 3 ] && grep -qF "blocker: the $named: a PoC crate builds its library" "$T/out" && nothing_built && one_blocker \
    && ok "refused before anything compiles: the $named" || { bad "$var: exit $code"; cat "$T/out" >&2; }
done <<'CASES'
SHIM_TARGET=bin|bin target poc_shim_extra (src/extra.rs) of poc_shim
SHIM_TARGET=example|example target poc_shim_extra (src/extra.rs) of poc_shim
SHIM_TARGET=bench|bench target poc_shim_extra (src/extra.rs) of poc_shim
SHIM_TARGET=dylib|dylib target poc_shim_extra (src/extra.rs) of poc_shim
SHIM_TARGET=staticlib|staticlib target poc_shim_extra (src/extra.rs) of poc_shim
SHIM_MEMBER_KIND=dylib|dylib target shared_test_utils (shared-test-utils/src/lib.rs) of shared-test-utils
SHIM_MEMBER_KIND=cdylib|cdylib target shared_test_utils (shared-test-utils/src/lib.rs) of shared-test-utils
CASES
# The crate's own Rust code, read before anything compiles, in either mode: a crate-level feature (with it a
# nightly or platform-tools rustc lets the source pick linker arguments), inline assembly (its .incbin and
# .include read files that rustc's dep-info never lists) and the link attribute (a native library that the
# dep-info does not list either), in any .rs file of the crate, named directly or through a macro argument,
# are refused, also where an edition before 2021 reads cr"..." as the identifier cr and an ordinary string;
# so is a feature in a target's source outside the crate. A comment, a string, a character and a name that
# only mention them pass.
n=0
while IFS='|' read -r where text named; do
  [ -n "$where" ] || continue
  n=$((n + 1)); mk_crate "$T/oc-$n"; mkdir -p "$(dirname "$T/oc-$n/$where")"
  printf '%b\n' "$text" > "$T/oc-$n/$where"
  code="$(gate "$T/oc-$n" "$NATIVE" "$VULN")"
  [ "$code" = 3 ] && grep -qF "blocker: $named" "$T/out" && grep -qF "run.sh refuses it in the crate's own code, in either mode." "$T/out" \
    && nothing_built && one_blocker && ok "refused before anything compiles: $named" || { bad "$where holding $text: exit $code"; cat "$T/out" >&2; }
done <<'CASES'
src/lib.rs|#![feature(link_arg_attribute)]\npub fn f() {}|src/lib.rs:1 turns on unstable rustc features
src/lib.rs|#![cfg_attr(all(), feature (link_arg_attribute))]|src/lib.rs:1 turns on unstable rustc features
src/lib.rs|// the library\ncore::arch::global_asm!(".globl x");|src/lib.rs:2 names global_asm, inline assembly
tests/helper.rs|use std::arch::asm;|tests/helper.rs:1 names asm, inline assembly
src/deep/mod.rs|pub use core::arch::naked_asm as n;|src/deep/mod.rs:1 names naked_asm, inline assembly
src/lib.rs|macro_rules! g { ($a:ident) => { core::arch::$a!(".globl x"); } }\ng!(global_asm);|src/lib.rs:2 names global_asm, inline assembly
src/lib.rs|#[link(name = "c")]\nextern "C" {}|src/lib.rs:1 names link, the attribute that links a native library
src/lib.rs|macro_rules! m { ($a:ident) => { #[$a(name = "c")] extern "C" {} } }\nm!(r#link);|src/lib.rs:2 names link, the attribute that links a native library
src/lib.rs|macro_rules! m { ($a:ident $b:literal) => {}; }\nm!(cr"\\""); core::arch::global_asm!(".globl x");|src/lib.rs:2 names global_asm, inline assembly
CASES
mk_crate "$T/oc-out"; printf '#![feature(link_arg_attribute)]\n' > "$T/oc-outside-lib.rs"
code="$(gate "$T/oc-out" "$NATIVE" "$VULN" SHIM_LIB_SRC="$T/oc-outside-lib.rs")"
[ "$code" = 3 ] && grep -qF "blocker: $T/oc-outside-lib.rs:1 turns on unstable rustc features" "$T/out" && nothing_built && one_blocker \
  && ok "refused before anything compiles: a feature in the library's source outside the crate" || { bad "a feature in an outside target source: exit $code"; cat "$T/out" >&2; }
mk_crate "$T/oc-mention"; mkdir -p "$T/oc-mention/src"
cat > "$T/oc-mention/src/lib.rs" <<'RS'
//! Mentions only: global_asm!, asm!, naked_asm!, #[link(name = "c")] and #![feature(x)].
/* core::arch::global_asm!(".incbin"); /* nested */ #[link(name = "c")] feature(x) */
#![cfg_attr(feature = "fixed", allow(dead_code))]
pub const NOTE: &str = "global_asm! link #![feature(x)] \" asm";
pub const RAW: &str = r##"asm "# link"##;
pub const QUOTE: char = '"';
pub const BYTES: &[u8] = b"naked_asm";
#[link_section = ".data"]
pub static LINKED: u8 = 0;
pub fn wasm<'a>(feature_set: &'a str) -> &'a str { let symlink = feature_set; symlink }
RS
code="$(gate "$T/oc-mention" "$NATIVE" "$VULN")"
[ "$code" = 0 ] && grep -q "^$LEG3" "$T/out" && ok "comments, strings, a character and names that only mention a feature, inline assembly or link -> not refused" \
  || { bad "mentions in the crate's own code: exit $code"; cat "$T/out" >&2; }

# ---------------------------------------------------------------------------
# Where the crate builds. A hostile target tree: its .cargo/config.toml names a
# rustc-wrapper and its rust-toolchain.toml a `path` toolchain, each of which leaves
# a marker if it runs. The PoC crate sits inside it, as audit_<n>/ and incident_<n>/
# crates do.
# ---------------------------------------------------------------------------
R="$T/repo"; MK="$T/hostile.marker"; LOG="$T/shim.log"
mkdir -p "$R/.cargo" "$T/faketc/bin"
printf '#!/bin/sh\necho wrapper >> "%s"\nexec "$@"\n' "$MK" > "$T/wrap.sh"; chmod +x "$T/wrap.sh"
for b in cargo rustc; do printf '#!/bin/sh\necho toolchain >> "%s"\nexit 0\n' "$MK" > "$T/faketc/bin/$b"; chmod +x "$T/faketc/bin/$b"; done
printf '[build]\nrustc-wrapper = "%s"\n' "$T/wrap.sh" > "$R/.cargo/config.toml"
printf '[toolchain]\npath = "%s"\n' "$T/faketc" > "$R/rust-toolchain.toml"

# Shim: the control shows the shim sees the hostile files in place; run.sh must not.
mk_crate "$R/incident_1/poc/INC-1.1"
( cd "$R/incident_1/poc/INC-1.1" && SHIM_LOG="$LOG" RUSTUP_TOOLCHAIN= "$T/shim/cargo" test >/dev/null )
if grep -q '^config ' "$LOG" && grep -q '^toolchain ' "$LOG"; then ok "control: in place, cargo would read the target's .cargo/config.toml and rust-toolchain.toml"; else bad "control: the shim did not see the hostile tree"; fi
rm -f "$LOG"
code="$(run "$R/incident_1/poc/INC-1.1" "$SP" "$NATIVE" "$VULN" "$FIX" SHIM_LOG="$LOG")"
bd="$(build_dir)"
case "$bd" in
  "$R"/*|"") bad "build dir '$bd' is not a scratch copy outside the target tree" ;;
  *) [ "$code" = 0 ] && ok "the crate builds in a scratch copy outside the target tree ($bd)" || bad "scratch copy: exit $code" ;;
esac
if [ -s "$LOG" ]; then bad "run.sh let cargo/rustup see the target's config: $(tr '\n' ' ' < "$LOG")"; else ok "neither the target's .cargo/config.toml nor its rust-toolchain.toml was in reach of cargo"; fi
[ -n "$bd" ] && [ ! -e "$bd" ] && ok "scratch build dir removed on exit" || bad "scratch build dir '$bd' left behind"
if command -v rustup >/dev/null 2>&1; then
  tc="$(rustup default 2>/dev/null | sed -n 's/ (default)$//p')"
  grep -q "^>> build dir: .*toolchain ${tc};" "$T/out" && ok "toolchain pinned to rustup's default (${tc}), not left to a rust-toolchain file" || bad "toolchain not pinned (want ${tc})"
elif [ "${REQUIRE_TOOLCHAIN:-}" = 1 ]; then
  bad "REQUIRE_TOOLCHAIN=1, but rustup is not on PATH: the toolchain pin check cannot run"
fi
rm -f "$LOG"
code="$(run "$R/incident_1/poc/INC-1.1" "$SP" "$NATIVE" "$VULN" "$FIX" KEEP_POC_BUILD=1)"
bd="$(build_dir)"
if [ "$code" = 0 ] && [ -d "$bd" ]; then ok "KEEP_POC_BUILD=1 keeps the scratch build dir"; rm -rf "$bd"; else bad "KEEP_POC_BUILD=1: exit $code, dir '$bd'"; fi
mkdir -p "$R/tmp"
code="$(run "$R/incident_1/poc/INC-1.1" "$SP" "$NATIVE" "$VULN" "$FIX" TMPDIR="$R/tmp")"
[ "$code" = 3 ] && grep -q 'would inherit' "$T/out" && ok "a scratch dir that would inherit the target's config (TMPDIR inside the tree) -> exit 3" || bad "TMPDIR inside the target tree: exit $code"

# Relative .so paths still resolve once the build moves to the scratch copy.
code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO=../vuln.so FIXED_SO=../fixed.so)"
[ "$code" = 0 ] && grep -q "vulnerable sha256 (zero-trimmed): $want" "$T/out" && ok "relative VULNERABLE_SO/FIXED_SO resolve from the caller's directory" || bad "relative .so paths: exit $code"

# Crate shapes that reach for target code — a path dependency (one of them inside the
# hostile tree), a git dependency, a workspace-inherited one — and the shipped
# template itself. Each needs the mode; with it, each is built and tested from a
# scratch copy, never in place, so the target's config stays out of reach.
mk_dep() {  # mk_dep <dir> <Cargo.toml dependency line>
  mk_crate "$1"
  printf '[package]\nname = "p"\nversion = "0.1.0"\n\n[dependencies]\n%s\n' "$2" > "$1/Cargo.toml"
}
mk_dep "$T/d-path" 'vault = { path = "../../../programs/vault" }'
mk_dep "$T/d-git" 'vault = { git = "https://example.invalid/vault.git" }'
mk_dep "$T/d-ws" 'anchor-lang = { workspace = true }'
mk_dep "$R/incident_1/poc/INC-1.3" "vault = { path = \"$R/programs/vault\" }"
mkdir -p "$T/tmpl"; cp -R "$TEMPLATE/." "$T/tmpl/"
sed 's/{PROGRAM_NAME}/poc_tmpl/' "$TEMPLATE/Cargo.toml" > "$T/tmpl/Cargo.toml"
for c in "$T/d-path" "$T/d-git" "$T/d-ws" "$T/tmpl" "$R/incident_1/poc/INC-1.3"; do
  label="${c#"$T"/}"
  code="$(gate "$c" "$VULN" "$FIX")"
  [ "$code" = 3 ] && nothing_ran && ok "$label, no execution mode -> exit 3, nothing copied or compiled" || bad "$label without a mode: exit $code"
  rm -f "$LOG"
  code="$(gate "$c" "$NATIVE" "$VULN" "$FIX" SHIM_LOG="$LOG")"
  bd="$(build_dir)"
  if [ "$code" = 0 ] && from_scratch "$bd" && [ ! -s "$LOG" ]; then
    ok "$label under native -> built and tested from a scratch copy, the target's config out of reach"
  else
    bad "$label under native: exit $code, build dir '$bd'"; cat "$T/out" >&2
  fi
done

# Refusals, in either mode: the copy never takes a symbolic link, .cargo/ or
# rust-toolchain*, so a crate holding one is refused before anything is copied.
refused() {  # refused <crate> <entry the message names> <label>
  code="$(gate "$1" "$NATIVE" "$VULN" "$FIX")"
  [ "$code" = 3 ] && grep -qF "$2 inside the crate" "$T/out" && nothing_ran \
    && ok "$3 -> refused under native: exit 3, nothing copied or compiled" || bad "$3: exit $code"
}
mk_crate "$T/d-link"; ln -s "$R" "$T/d-link/target-src"
refused "$T/d-link" target-src "a symbolic link inside the crate"
mk_crate "$T/d-cargo"; mkdir -p "$T/d-cargo/.cargo"
printf '[build]\nrustc-wrapper = "%s"\n' "$T/wrap.sh" > "$T/d-cargo/.cargo/config.toml"
refused "$T/d-cargo" .cargo "a .cargo/ directory inside the crate"
mk_crate "$T/d-tc"
printf '[toolchain]\npath = "%s"\n' "$T/faketc" > "$T/d-tc/rust-toolchain.toml"
refused "$T/d-tc" rust-toolchain.toml "a rust-toolchain.toml inside the crate"
# The same names in any letter case: a filesystem that ignores case lets cargo and
# rustup read .CARGO/ as .cargo/ and Rust-Toolchain.toml as rust-toolchain.toml.
mk_crate "$T/d-cargo-uc"; mkdir -p "$T/d-cargo-uc/.CARGO"
printf '[build]\nrustc-wrapper = "%s"\n' "$T/wrap.sh" > "$T/d-cargo-uc/.CARGO/config.toml"
refused "$T/d-cargo-uc" .CARGO "a .CARGO/ directory inside the crate"
mk_crate "$T/d-tc-uc"
printf '[toolchain]\npath = "%s"\n' "$T/faketc" > "$T/d-tc-uc/Rust-Toolchain.toml"
refused "$T/d-tc-uc" Rust-Toolchain.toml "a Rust-Toolchain.toml inside the crate"
# A version manager's file is refused the same way, at any depth and in any letter case: a shim of asdf,
# mise, pyenv or proto picks the cargo, rustc or python3 it runs from the directory it starts in, and
# asdf's `path:` version names any program. The message names the first entry found, a directory before
# its files.
while IFS='|' read -r entry named; do
  [ -n "$entry" ] || continue
  mk_crate "$T/d-vm"; mkdir -p "$T/d-vm/$(dirname "$entry")"
  printf 'rust path:%s\npython path:%s\n' "$T/vm-tool" "$T/vm-tool" > "$T/d-vm/$entry"
  refused "$T/d-vm" "$named" "a version manager's $entry inside the crate"
  rm -rf "$T/d-vm"
done <<'CASES'
.tool-versions|.tool-versions
.python-version|.python-version
mise.toml|mise.toml
.mise.toml|.mise.toml
mise.local.toml|mise.local.toml
.mise.ci.toml|.mise.ci.toml
.miserc.toml|.miserc.toml
.config/mise.toml|.config
mise/config.toml|mise
.mise/conf.d/a.toml|.mise
.prototools|.prototools
tests/.Tool-Versions|tests/.Tool-Versions
CASES
# A name that is not printable ASCII is refused the same way, at any depth and on any filesystem: macOS,
# which folds case, reads .tool-versions with a long s (U+017F) in place of an s as .tool-versions, which
# the copy would take. The message shows each byte outside printable ASCII, a newline in a name too, as ?.
while IFS='|' read -r entry named; do
  [ -n "$entry" ] || continue
  e="$(printf "$entry")"; mk_crate "$T/d-na"; mkdir -p "$T/d-na/$(dirname "$e")"
  printf 'rust path:%s\npython path:%s\n' "$T/vm-tool" "$T/vm-tool" > "$T/d-na/$e"
  refused "$T/d-na" "$named" "an entry named $named (not printable ASCII) inside the crate"
  rm -rf "$T/d-na"
done <<'CASES'
.tool-ver\305\277ions|.tool-ver??ions
mi\305\277e.toml|mi??e.toml
.python-ver\305\277ion|.python-ver??ion
tests/donn\303\251es/a.txt|tests/donn??es
a\nb.txt|a?b.txt
CASES
# A target directory, in any letter case, is never copied: cargo would take the build
# outputs in it for its own.
mk_crate "$T/d-target"; mkdir -p "$T/d-target/TARGET/debug"; printf 'shipped\n' > "$T/d-target/TARGET/debug/shipped.txt"
code="$(gate "$T/d-target" "$NATIVE" "$VULN" KEEP_POC_BUILD=1)"
bd="$(build_dir)"
[ "$code" = 0 ] && [ -n "$bd" ] && [ ! -e "$bd/TARGET/debug/shipped.txt" ] && [ ! -e "$bd/target/debug/shipped.txt" ] \
  && ok "a TARGET/ directory in the crate is not copied into the scratch build" || bad "TARGET/ directory: exit $code"
[ -n "$bd" ] && rm -rf "$bd"

# A build cache: an inherited CARGO_TARGET_DIR reaches every cargo call unchanged,
# while SBF_OUT_DIR, and the --sbf-out-dir the SBF builds get, stay in the scratch copy.
mkdir -p "$T/cache"
code="$(gate "$T/inc" "$NATIVE" CARGO_TARGET_DIR="$T/cache")"
bd="$(build_dir)"
if [ "$code" = 0 ] && from_scratch "$bd" \
   && awk -F'\t' -v t="$T/cache" -v s="$bd/target/deploy" '{ n++ } $2 == t && $3 == s { g++ } END { exit !(n > 0 && n == g) }' "$T/calls" \
   && grep -qF -- "--sbf-out-dir $bd/target/deploy" "$T/calls"; then
  ok "an inherited CARGO_TARGET_DIR is honoured; SBF_OUT_DIR stays in the scratch copy"
else
  bad "CARGO_TARGET_DIR: exit $code, build dir '$bd'"; cat "$T/calls" >&2
fi

# A shared build cache. run.sh holds a lock inside the cache from its first build until
# its last test, and `harness checkbuild` refuses an arm when cargo reports one of the
# crate's own units already built without this run compiling it (the stand-in reports
# that with SHIM_FRESH=1). The lock dir lands in the cache and is gone afterwards.
code="$(gate "$T/inc" "$NATIVE" "$VULN" CARGO_TARGET_DIR="$T/cache" SHIM_FRESH=1)"
[ "$code" = 3 ] && grep -q 'already built without this run compiling it' "$T/out" && one_blocker \
  && ok "a crate unit reported fresh that this run did not build -> exit 3 (a cache shared with a same-named crate), one blocker line" || { bad "shared-cache fresh guard: exit $code"; cat "$T/out" >&2; }
rm -rf "$T/lockcache"; mkdir -p "$T/lockcache"
code="$(gate "$T/inc" "$NATIVE" "$VULN" CARGO_TARGET_DIR="$T/lockcache")"
[ "$code" = 0 ] && [ ! -e "$T/lockcache/.auditor-poc-build.lock" ] \
  && ok "the build lock is taken inside the shared cache and removed on exit" || bad "build lock not released: exit $code"
# A stale lock (its holder gone) is broken; a lock held by a live process makes the
# run wait and then block, never silently reuse. A short dead-pid loop supplies a pid
# that is certainly not running.
dead=$( (exec sh -c 'echo $$') ); rm -rf "$T/lockcache/.auditor-poc-build.lock"; mkdir -p "$T/lockcache/.auditor-poc-build.lock"; echo "$dead" > "$T/lockcache/.auditor-poc-build.lock/pid"
code="$(gate "$T/inc" "$NATIVE" "$VULN" CARGO_TARGET_DIR="$T/lockcache")"
[ "$code" = 0 ] && ok "a stale build lock (holder gone) is broken, and the run proceeds" || { bad "stale lock not broken: exit $code"; cat "$T/out" >&2; }
sleep 30 & live=$!
rm -rf "$T/lockcache/.auditor-poc-build.lock"; mkdir -p "$T/lockcache/.auditor-poc-build.lock"; echo "$live" > "$T/lockcache/.auditor-poc-build.lock/pid"
code="$(gate "$T/inc" "$NATIVE" "$VULN" CARGO_TARGET_DIR="$T/lockcache" POC_LOCK_WAIT=1)"
kill "$live" 2>/dev/null; wait "$live" 2>/dev/null
[ "$code" = 3 ] && grep -q 'could not take the build lock' "$T/out" \
  && ok "a build lock held by a live process -> exit 3 after the wait, never a silent reuse" || { bad "held lock not honoured: exit $code"; cat "$T/out" >&2; }
rm -rf "$T/lockcache/.auditor-poc-build.lock"
# A stale lock is broken by one run at a time: while another run's .break directory
# stands beside it, the run waits, and the lock is left as it was.
mkdir -p "$T/lockcache/.auditor-poc-build.lock" "$T/lockcache/.auditor-poc-build.lock.break"; echo "$dead" > "$T/lockcache/.auditor-poc-build.lock/pid"
code="$(gate "$T/inc" "$NATIVE" "$VULN" CARGO_TARGET_DIR="$T/lockcache" POC_LOCK_WAIT=1)"
[ "$code" = 3 ] && grep -q 'could not take the build lock' "$T/out" && [ "$(cat "$T/lockcache/.auditor-poc-build.lock/pid" 2>/dev/null)" = "$dead" ] \
  && ok "a stale lock another run is breaking (its .break directory stands) -> the run waits, then exit 3, the lock untouched" || { bad "stale lock while another run breaks it: exit $code"; cat "$T/out" >&2; }
rm -rf "$T/lockcache/.auditor-poc-build.lock" "$T/lockcache/.auditor-poc-build.lock.break"
# A run drops the lock only while it still names this run: here the stand-in test makes
# it name another live process, whose lock stays.
sleep 30 & live=$!
code="$(gate "$T/inc" "$NATIVE" "$VULN" CARGO_TARGET_DIR="$T/lockcache" SHIM_RELOCK_PID="$live" SHIM_MARKERS="$EV exploit:relock")"
[ "$code" = 0 ] && [ "$(cat "$T/lockcache/.auditor-poc-build.lock/pid" 2>/dev/null)" = "$live" ] \
  && ok "a lock that names another run by release time is left in place" || { bad "release of a lock naming another run: exit $code"; cat "$T/out" >&2; }
kill "$live" 2>/dev/null; wait "$live" 2>/dev/null
rm -rf "$T/lockcache/.auditor-poc-build.lock"
# POC_LOCK_WAIT is whole seconds, checked before anything is copied and never evaluated
# (a lock held by a live process makes the run wait, where it is read).
sleep 30 & live=$!
mkdir -p "$T/lockcache/.auditor-poc-build.lock"; echo "$live" > "$T/lockcache/.auditor-poc-build.lock/pid"
for wait_spec in "HOME[\$(touch $T/lockwait.marker)]" 08 -1 1.5 ' 1'; do
  rm -f "$T/lockwait.marker"
  code="$(gate "$T/inc" "$NATIVE" "$VULN" CARGO_TARGET_DIR="$T/lockcache" "POC_LOCK_WAIT=$wait_spec")"
  [ "$code" = 3 ] && grep -q 'POC_LOCK_WAIT is' "$T/out" && nothing_ran && [ ! -e "$T/lockwait.marker" ] \
    && ok "POC_LOCK_WAIT='$wait_spec' -> refused before anything is copied, never evaluated" || { bad "POC_LOCK_WAIT '$wait_spec': exit $code"; cat "$T/out" >&2; }
done
kill "$live" 2>/dev/null; wait "$live" 2>/dev/null
rm -rf "$T/lockcache/.auditor-poc-build.lock"
# The lock goes in the directory cargo reports it builds into, which a target-dir in
# cargo's own config sets as well as CARGO_TARGET_DIR (the stand-in reads it from
# SHIM_TARGET_DIR): a live lock there holds the run.
rm -rf "$T/cfgcache"; mkdir -p "$T/cfgcache"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_TARGET_DIR="$T/cfgcache")"
[ "$code" = 0 ] && grep -qF ">> target dir: $T/cfgcache " "$T/out" && [ ! -e "$T/cfgcache/.auditor-poc-build.lock" ] \
  && ok "a target directory from cargo's config -> run.sh names it and takes and drops its lock there" || { bad "target dir from cargo's config: exit $code"; cat "$T/out" >&2; }
sleep 30 & live=$!
mkdir -p "$T/cfgcache/.auditor-poc-build.lock"; echo "$live" > "$T/cfgcache/.auditor-poc-build.lock/pid"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_TARGET_DIR="$T/cfgcache" POC_LOCK_WAIT=1)"
kill "$live" 2>/dev/null; wait "$live" 2>/dev/null
[ "$code" = 3 ] && grep -qF "could not take the build lock in $T/cfgcache " "$T/out" \
  && ok "a live lock in the target directory cargo's config names -> exit 3, the run never builds beside it" || { bad "lock in the configured target dir: exit $code"; cat "$T/out" >&2; }
rm -rf "$T/cfgcache/.auditor-poc-build.lock"

# An unreadable VULNERABLE_SO is a blocker, not a verdict: the ELF-magic read fails
# under set -e and the run exits 3, never 1.
cp "$T/vuln.so" "$T/unreadable.so"; chmod 000 "$T/unreadable.so"
if [ -r "$T/unreadable.so" ]; then
  echo "note: cannot drop read permission here (running as root?); the unreadable-input check is skipped"
else
  code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/unreadable.so")"
  [ "$code" = 3 ] && ! grep -q 'did not reproduce' "$T/out" && one_blocker \
    && ok "an unreadable VULNERABLE_SO -> exit 3 (a blocker), never a verdict, one blocker line" || { bad "unreadable VULNERABLE_SO: exit $code"; cat "$T/out" >&2; }
fi
chmod 644 "$T/unreadable.so" 2>/dev/null || true

# Dependency pins: a crate without Cargo.lock gets a line saying so; UPDATE_PINS moves
# only the named pins, with cargo update -p in the scratch copy, before anything is
# built; an entry that is not <crate>[@<version>] is refused before anything is copied.
mk_crate "$T/nolock"
code="$(gate "$T/nolock" "$NATIVE" "$VULN")"
[ "$code" = 0 ] && grep -q '^>> no Cargo.lock in the crate' "$T/out" && ok "a crate without Cargo.lock -> a line says cargo resolves every dependency now" || bad "no Cargo.lock line: exit $code"
mk_crate "$T/locked"; printf '# a lock\n' > "$T/locked/Cargo.lock"
code="$(gate "$T/locked" "$NATIVE" "$VULN")"
[ "$code" = 0 ] && ! grep -q 'no Cargo.lock' "$T/out" && ok "a crate with its Cargo.lock -> no such line" || bad "crate with a lock: exit $code"
code="$(gate "$T/locked" "$NATIVE" "$VULN" "UPDATE_PINS=solana-program@3.0.0 borsh")"
bd="$(build_dir)"
if [ "$code" = 0 ] && from_scratch "$bd" \
   && awk -F'\t' '$6 ~ /^metadata / { next } $6 ~ /^update / { u++; if (b) late = 1; next } { b = 1 } END { exit !(u == 2 && !late) }' "$T/calls" \
   && grep -qF "update --manifest-path $bd/Cargo.toml --package solana-program@3.0.0" "$T/calls" \
   && grep -qF "update --manifest-path $bd/Cargo.toml --package borsh" "$T/calls"; then
  ok "UPDATE_PINS -> cargo update -p <each pin> in the scratch copy, before any build"
else
  bad "UPDATE_PINS: exit $code"; cat "$T/calls" >&2
fi
code="$(gate "$T/locked" "$NATIVE" "$VULN" UPDATE_PINS=borsh SHIM_FAIL=update)"
[ "$code" = 3 ] && grep -q 'cargo update -p borsh failed' "$T/out" && ! awk -F'\t' '$6 ~ /^(build-sbf|test|testbin) / { f = 1 } END { exit !f }' "$T/calls" \
  && ok "a cargo update that fails -> exit 3, nothing built" || bad "failing UPDATE_PINS: exit $code"
for spec in '--config=build.rustc-wrapper="x"' 'borsh;true' '../borsh' 'b*' 'borsh@' 'borsh@=3.0.0' '-p'; do
  code="$(gate "$T/locked" "$NATIVE" "$VULN" "UPDATE_PINS=borsh $spec")"
  [ "$code" = 3 ] && grep -q 'UPDATE_PINS entry' "$T/out" && nothing_ran && ok "UPDATE_PINS entry '$spec' -> refused before anything is copied" || bad "UPDATE_PINS '$spec': exit $code"
done

# The resolved Cargo.lock comes back into the crate in place of a regular file only: a symbolic link put
# there while the test ran is left as it is, and its target is untouched.
mk_crate "$T/relink"; printf 'kept\n' > "$T/relink-target"
code="$(gate "$T/relink" "$NATIVE" "$VULN" SHIM_MARKERS="$EV exploit:relink" SHIM_RELINK="$T/relink/Cargo.lock" SHIM_RELINK_TO="$T/relink-target")"
[ "$code" = 0 ] && [ -L "$T/relink/Cargo.lock" ] && [ "$(cat "$T/relink-target")" = kept ] \
  && ok "a Cargo.lock that became a symbolic link during the run is not written through" || { bad "Cargo.lock turned into a link: exit $code, target holds '$(cat "$T/relink-target")'"; cat "$T/out" >&2; }
mk_crate "$T/relocate"; mkdir -p "$T/relocate-elsewhere"
code="$(gate "$T/relocate" "$NATIVE" "$VULN" SHIM_MARKERS="$EV exploit:relocate" SHIM_RELOCATE="$T/relocate" SHIM_RELOCATE_TO="$T/relocate-elsewhere")"
[ "$code" = 0 ] && [ -z "$(ls -A "$T/relocate-elsewhere")" ] \
  && ok "a crate directory replaced by a symbolic link during the run gets no Cargo.lock through it" || { bad "crate directory turned into a link: exit $code, elsewhere holds '$(ls -A "$T/relocate-elsewhere")'"; cat "$T/out" >&2; }

# Exit codes: a build that fails is a blocker (3); only the test verdicts are 1 and 2.
code="$(run "$T/inc" "$SP" "$NATIVE" SHIM_FAIL=build-sbf)"
[ "$code" = 3 ] && grep -q 'SBF build failed' "$T/out" && ok "cargo build-sbf failing (101) -> exit 3" || bad "build-sbf failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=no-run:exploit)"
[ "$code" = 3 ] && grep -q 'tests/exploit.rs failed to build for the vulnerable arm' "$T/out" && ok "an exploit test that does not compile -> exit 3" || bad "exploit test build failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=no-run:fixed_blocked)"
[ "$code" = 3 ] && grep -q 'tests/fixed_blocked.rs failed to build for the fixed arm' "$T/out" && ok "a fixed-arm test that does not compile -> exit 3" || bad "fixed test build failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=exploit SHIM_MARKERS="exploit:attempted exploit:failed exploit:loaded")"
[ "$code" = 1 ] && grep -q 'did not reproduce' "$T/out" && ok "exploit test failing in its contract assertion -> exit 1" || bad "exploit failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:attempted fixed_blocked:failed fixed_blocked:loaded")"
[ "$code" = 2 ] && grep -q 'fix is incomplete' "$T/out" && ok "fixed-arm test failing in its contract assertion -> exit 2" || bad "fixed-arm failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:attempted fixed_blocked:failed fixed_blocked:loaded")"
[ "$code" = 2 ] && grep -q 'fix is incomplete' "$T/out" && ok "build mode: fixed-arm test failing in its contract assertion -> exit 2" || bad "build mode fixed-arm failure: exit $code"
# Exit 2's final line says what the fixed arm did, from the outcome its failed
# assertion wrote: it accepted the attack, rejected it with another error than the
# pinned one, or failed it while the account changed.
while IFS='|' read -r assertion how line; do
  [ -n "$assertion" ] || continue
  code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:attempted=$assertion fixed_blocked:failed=$assertion+$how fixed_blocked:loaded")"
  [ "$code" = 2 ] && [ "$(tail -n 1 "$T/out")" = "$line" ] \
    && ok "a fixed arm whose $assertion assertion failed with '$how' -> exit 2, the final line saying so" || { bad "exit 2 line for $assertion/$how: exit $code"; cat "$T/out" >&2; }
done <<'CASES'
rejected_with|accepted|FAIL: the fixed arm accepted the attack — fix is incomplete.
rejected_with|other-error|FAIL: the fixed arm rejected the attack with another error than the pinned one — the test's message names both.
blocked|accepted|FAIL: the fixed arm accepted the attack — fix is incomplete.
blocked|changed|FAIL: the fixed arm failed the attack, yet the account changed — fix is incomplete.
CASES
code="$(run "$T/inc" "$SP" "$NATIVE")"
[ "$code" = 0 ] && grep -q "building 'fixed' arm to SBF" "$T/out" && ok "build mode (no prebuilt bytes) runs both arms -> exit 0" || bad "build mode: exit $code"
# A run that stops anywhere but at a verdict or a named blocker exits 3, never 0, 1 or
# 2: here a copy of run.sh meets an unset variable under set -u (bash 3.2 hands the
# EXIT trap status 0 for it) once the scratch copy exists.
mk_crate "$T/stop"
python3 -I -c 'import sys; p = sys.argv[1]; s = open(p).read(); a = "\n# Dependency pins (see DEPENDENCY PINS above)."; assert s.count(a) == 1; open(p, "w").write(s.replace(a, "\n: \"${AUDITOR_TEST_UNSET}\"" + a))' "$T/stop/run.sh"
code="$(gate "$T/stop" "$NATIVE" "$VULN")"
[ "$code" = 3 ] && grep -q 'stopped before a verdict' "$T/out" && ! grep -q '^OK' "$T/out" && [ -z "$(ls -A "$T/tmp-gate")" ] \
  && ok "a run that stops on an unset variable -> exit 3 with a blocker line, the scratch copy removed" || { bad "stop on an unset variable: exit $code"; cat "$T/out" >&2; }

# ---------------------------------------------------------------------------
# The installation's copy, with the crate as an argument: run.sh --crate, --init and
# --new-cache. Every argument is checked before anything is copied; the mode is the
# stricter of <R>/exec-mode and AUDITOR_EXEC_MODE; isolated mode runs the credential
# self-check first; and every child runs in the cleaned environment of
# scripts/lib/isolation.sh. The fixture working directory $WT holds the run
# directories audit_1 and incident_1 (made by rundir.sh), the shim crate
# audit_1/poc/F-1, prebuilt bytes in audit_1/exec/build-sbf-1/ and incident_1/bin/, a
# file a.rs, a directory src/ and a symbolic link linkdir to audit_1.
# ---------------------------------------------------------------------------
ROOT="$(cd "$HERE/../.." && pwd -P)"
RUNSH="$ROOT/templates/poc/run.sh"
PROBE="$ROOT/scripts/runner/probe.sh"
NT="$T/tmp-new"; NTC="$T/tmp-cache"; WT="$T/wt"; CLEANHOME="$T/home-clean"
# The runs below get an empty HOME, so they name the real cargo and rustup homes.
TOOL_HOMES=(CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}")
mkdir -p "$NT" "$WT/src" "$CLEANHOME"
( cd "$WT" && "$ROOT/scripts/rundir.sh" new audit && "$ROOT/scripts/rundir.sh" new incident ) >/dev/null || bad "rundir.sh could not make the fixture's run directories"
mk_crate "$WT/audit_1/poc/F-1"
mkdir -p "$WT/audit_1/exec/build-sbf-1"
cp "$T/vuln.so" "$T/fixed.so" "$WT/audit_1/exec/build-sbf-1/"
cp "$T/vuln.so" "$WT/incident_1/bin/program.so"
printf 'notes\n' > "$WT/audit_1/exec/build-sbf-1/notes.txt"
printf 'fn a() {}\n' > "$WT/a.rs"
ln -s audit_1 "$WT/linkdir"
printf 'native\n' > "$WT/audit_1/exec-mode"
NVULN=(--vulnerable-so audit_1/exec/build-sbf-1/vuln.so)
NFIX=(--fixed-so audit_1/exec/build-sbf-1/fixed.so)
SHIM_EXTRA=()

shim_settings() {  # shim_settings [VAR=val ...]: the settings the shim and its test binaries read in a cleaned environment
  local kv
  : > "$T/shim/settings.env"
  for kv in "$@"; do
    case "$kv" in *"'"*) bad "a shim setting holds a quote: $kv" ;; esac
    printf "export %s='%s'\n" "${kv%%=*}" "${kv#*=}" >> "$T/shim/settings.env"
  done
}
# nrun <dir> [VAR=val ...] -- <argument>...: the installation's run.sh, run directly by its path from
# <dir> with the shim first on PATH and an empty HOME -> exit code; output in $T/out
nrun() {
  local dir="$1"; shift
  local -a vars=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do vars+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  ( cd "$dir" && env -i HOME="$CLEANHOME" "${TOOL_HOMES[@]}" PATH="$SP" TMPDIR="$NT" ${vars[@]+"${vars[@]}"} "$RUNSH" "$@" ) >"$T/out" 2>&1 </dev/null
  echo $?
}
# ngate [VAR=val ...] -- <argument>...: nrun in $WT, with the call log and the environment dumps on and
# an empty TMPDIR, so new_nothing_ran can tell that no cargo command started and no scratch appeared.
ngate() {
  rm -rf "$T/calls" "$T/calls.env" "$T/envdump" "$NT"; mkdir -p "$NT"
  shim_settings SHIM_CALLS="$T/calls" SHIM_ENV_DUMP="$T/envdump" ${SHIM_EXTRA[@]+"${SHIM_EXTRA[@]}"}
  nrun "$WT" "$@"
}
new_nothing_ran() { [ ! -e "$T/calls" ] && [ -z "$(ls -A "$NT")" ] && ! grep -q '^>> build dir' "$T/out"; }
new_build_dir() { sed -n 's/^>> build dir: \([^ ]*\).*/\1/p' "$T/out" | sed -n 1p; }
# in_blocks <header ERE> <line ERE>: every environment-dump block whose header matches (one at least)
# holds a matching line. none_in_blocks: none of those blocks does.
in_blocks() {
  awk -v h="$1" -v w="$2" '/^== / { if (on && !f) bad = 1; on = ($0 ~ h); f = 0; n += on; next } on && $0 ~ w { f = 1 } END { if (on && !f) bad = 1; exit (bad || n == 0) }' "$T/envdump"
}
none_in_blocks() {
  awk -v h="$1" -v w="$2" '/^== / { on = ($0 ~ h); n += on; next } on && $0 ~ w { bad = 1 } END { exit (bad || n == 0) }' "$T/envdump"
}
tree_of() { (cd "$1" && find . -print | LC_ALL=C sort); }
# A driver for scripts/lib/isolation.sh's functions, sourced as the runners source them.
cat > "$T/iso-driver.sh" <<'SH'
set -uo pipefail
root=$1; shift
. "$root/scripts/lib/confine.sh"
. "$root/scripts/lib/isolation.sh"
confine_init iso-driver "$root"
case "$1" in
  homes) iso_homes ;;
  creds) shift; iso_credentials "$@"; rc=$?
         case "$rc" in
           1) printf 'kinds: %s\n%s\n' "$ISO_KINDS" "$ISO_READABLE" ;;
           2) printf 'why: %s\n' "$ISO_WHY" ;;
         esac
         exit "$rc" ;;
  names) iso_cred_names; printf '%s\n' "$ISO_NAMES" ;;
  run-eq) mkdir -p "$2"; iso_env "$2" keep-home || exit 9; iso_run A=1 "$3/x=y/prog"; echo "rc=$?" ;;
  env) iso_env "$2" || exit 9; printf '%s\n' "${ISO_ENV[@]}"; printf 'net %s\n' ${ISO_NET[@]+"${ISO_NET[@]}"}
       printf 'home %s\n' "$ISO_HOME" ;;
  keep) iso_env "$2" keep-home || exit 9; printf 'home %s\n' "$ISO_HOME" ;;
  scratch) trap 'case "${ISO_SCRATCH:-}" in */auditor-driver.*) rm -rf "$ISO_SCRATCH" ;; esac' EXIT; iso_scratch driver; printf '%s\n' "$ISO_SCRATCH" ;;
  watch) mkdir -p "$2"; iso_env "$2" keep-home || exit 9; iso_watch 5 "$2/report" "$2" /bin/sh -c 'exit 0'; echo "rc=$?" ;;
esac
SH

# The entry point: run directly by its path, with a #!/bin/bash shebang.
[ "$(sed -n 1p "$RUNSH")" = '#!/bin/bash' ] && [ -x "$RUNSH" ] && ok "run.sh starts with #!/bin/bash and is executable" || bad "run.sh shebang or mode"
if command -v git >/dev/null 2>&1 && mode="$(git -C "$ROOT" ls-files -s -- templates/poc/run.sh 2>/dev/null)" && [ -n "$mode" ]; then
  [ "${mode%% *}" = 100755 ] && ok "git records run.sh as 100755" || bad "git records run.sh as ${mode%% *}"
fi

# A copy that is not the installation's takes no arguments, and the installation's template does not
# build itself: each exits 3 before anything is copied.
code="$( (cd "$T/inc" && env -i HOME="$HOME" PATH="$SP" TMPDIR="$T/tmp-gate" "$NATIVE" bash ./run.sh --crate audit_1/poc/F-1) >"$T/out" 2>&1; echo $?)"
[ "$code" = 3 ] && grep -q "^\[PoC-ATTEMPTED\] blocker: run.sh refused: only the installation's copy, <auditor-skill root>/templates/poc/run.sh, takes arguments; in a crate, run ./run.sh — nothing was copied or built.$" "$T/out" && one_blocker \
  && ok "a crate's own run.sh with arguments -> exit 3: only the installation's copy takes them" || { bad "crate copy with arguments: exit $code"; cat "$T/out" >&2; }
rm -rf "$NT"; mkdir -p "$NT"
code="$(nrun "$WT" AUDITOR_EXEC_MODE=native VULNERABLE_SO="$T/vuln.so" --)"
[ "$code" = 3 ] && grep -q "is the installation's template, not a PoC crate" "$T/out" && one_blocker && [ -z "$(ls -A "$NT")" ] \
  && ok "the installation's run.sh with no arguments -> exit 3, it never builds its own template" || { bad "installation run.sh with no arguments: exit $code"; cat "$T/out" >&2; }

# --init: the template's files, byte for byte, in a new run subpath, and nothing else.
rm -rf "$NT"; mkdir -p "$NT"
code="$(nrun "$WT" -- --init incident_1/poc/INC-1.2)"
C="$WT/incident_1/poc/INC-1.2"
if command -v git >/dev/null 2>&1 && files="$(git -C "$ROOT" ls-files -- templates/poc 2>/dev/null)" && [ -n "$files" ]; then
  files="$(printf '%s\n' "$files" | sed 's#^templates/poc/##' | LC_ALL=C sort)"
else
  files="$(cd "$ROOT/templates/poc" && find . -type f ! -path './target/*' | sed 's#^\./##' | LC_ALL=C sort)"
fi
made="$(cd "$C" 2>/dev/null && find . -type f | sed 's#^\./##' | LC_ALL=C sort)"
same=1; for f in $files; do cmp -s "$ROOT/templates/poc/$f" "$C/$f" || same=0; done
[ "$code" = 0 ] && [ "$(cat "$T/out")" = incident_1/poc/INC-1.2 ] && [ "$made" = "$files" ] && [ "$same" = 1 ] && [ -x "$C/run.sh" ] \
  && [ -z "$(ls -A "$NT")" ] && ok "--init copies exactly the template's files, byte for byte, prints the crate, exit 0" || { bad "--init: exit $code"; cat "$T/out" >&2; }
before="$(tree_of "$WT")"
code="$(nrun "$WT" -- --init incident_1/poc/INC-1.2)"
[ "$code" = 3 ] && grep -q 'run.sh refused: --init makes a crate in a new or empty directory, and incident_1/poc/INC-1.2 holds files' "$T/out" && [ "$(tree_of "$WT")" = "$before" ] \
  && ok "--init into a crate that exists -> exit 3, nothing changed" || { bad "--init twice: exit $code"; cat "$T/out" >&2; }
( cd "$WT" && "$ROOT/scripts/rundir.sh" sub audit_1 poc/F-7 ) >/dev/null
code="$(nrun "$WT" -- --init audit_1/poc/F-7)"
[ "$code" = 0 ] && [ -f "$WT/audit_1/poc/F-7/tests/exploit.rs" ] && ok "--init into the empty directory rundir.sh sub made -> the crate" || { bad "--init into an empty directory: exit $code"; cat "$T/out" >&2; }
rm -rf "$WT/audit_1/poc/F-7"

# --new-cache: a directory in TMPDIR, mode 0700, with its marker; --cache takes only such a one.
for tmp in "$NT" "$NT/"; do
  rm -rf "$NT"; mkdir -p "$NT"
  code="$( (cd "$WT" && env -i HOME="$CLEANHOME" PATH="$SP" TMPDIR="$tmp" "$RUNSH" --new-cache) 2>"$T/err")"
  case "$code" in "$NT"/auditor-poc-target.??????) cache="$code" ;; *) cache="" ;; esac
  if [ -n "$cache" ] && [ -d "$cache" ] && [ -n "$(find "$cache" -prune -perm 0700 -print)" ] \
     && [ "$(cat "$cache/.auditor-poc-cache")" = auditor-poc-target ] && [ ! -s "$T/err" ]; then
    ok "--new-cache (TMPDIR '$tmp') prints a new physical \$TMPDIR/auditor-poc-target.XXXXXX, mode 0700, with its marker"
  else
    bad "--new-cache with TMPDIR '$tmp': printed '$code'"; cat "$T/err" >&2
  fi
done
mkdir -p "$NTC"
CACHE="$( (cd "$WT" && env -i HOME="$CLEANHOME" PATH="$SP" TMPDIR="$NTC" "$RUNSH" --new-cache) 2>/dev/null)"
code="$(ngate TMPDIR="$NTC" -- --crate audit_1/poc/F-1 "${NVULN[@]}" --cache "$CACHE")"
if [ "$code" = 0 ] && awk -F'\t' -v t="$CACHE" '{ n++ } $2 == t { g++ } END { exit !(n > 0 && n == g) }' "$T/calls" \
   && grep -qF ">> target dir: $CACHE " "$T/out" && [ ! -e "$CACHE/.auditor-poc-build.lock" ]; then
  ok "--cache <a --new-cache directory> -> every cargo call builds into it, and the build lock is there and gone"
else
  bad "--cache: exit $code"; cat "$T/out" >&2
fi
mkdir -p "$NTC/auditor-poc-target.nomark" "$NTC/auditor-poc-target.mode75" "$NTC/auditor-poc-target.badmrk"
chmod 700 "$NTC/auditor-poc-target.nomark" "$NTC/auditor-poc-target.badmrk"; chmod 755 "$NTC/auditor-poc-target.mode75"
printf 'auditor-poc-target\n' > "$NTC/auditor-poc-target.mode75/.auditor-poc-cache"
printf 'something else\n' > "$NTC/auditor-poc-target.badmrk/.auditor-poc-cache"
ln -s "$CACHE" "$NTC/auditor-poc-target.linked"
mkdir -p "$T/elsewhere"; cp -R "$CACHE" "$T/elsewhere/"
cache_nothing_ran() { [ ! -e "$T/calls" ] && [ -z "$(find "$NTC" -name 'auditor-poc.*' -prune -print)" ] && ! grep -q '^>> build dir' "$T/out"; }
while IFS='|' read -r value text; do
  [ -n "$value" ] || continue
  code="$(ngate TMPDIR="$NTC" -- --crate audit_1/poc/F-1 "${NVULN[@]}" --cache "$value")"
  [ "$code" = 3 ] && grep -qF "run.sh refused: $text" "$T/out" && cache_nothing_ran && one_blocker \
    && ok "--cache $value -> refused before anything is copied: $text" || { bad "--cache $value: exit $code"; cat "$T/out" >&2; }
done <<CASES
$NTC/auditor-poc-target.nomark|--cache holds no .auditor-poc-cache marker, so --new-cache did not make it
$NTC/auditor-poc-target.badmrk|--cache holds no .auditor-poc-cache marker, so --new-cache did not make it
$NTC/auditor-poc-target.mode75|--cache is not mode 0700
$NTC/auditor-poc-target.linked|--cache is not a directory --new-cache made
$T/elsewhere/${CACHE##*/}|--cache is not in TMPDIR, where --new-cache makes it
${CACHE#/}|--cache takes a directory --new-cache made
$NTC/auditor-poc-target.ab|--cache takes a directory --new-cache made
$NTC/auditor-poc-target.abc-ef|--cache takes a directory --new-cache made
$CACHE/|--cache takes a directory --new-cache made
$NTC|--cache takes a directory --new-cache made
CASES
# Long values are refused at once, before anything reads them whole: a --cache over 1024 bytes, and
# --update-pins over 1024 bytes or with more than 32 pins.
long="$(python3 -I -c 'print("/" + "a" * 120000)')"
pins="$(python3 -I -c 'print("b" * 2000)')"
for spec in "--cache|$long|--cache takes a directory --new-cache made, \$TMPDIR/auditor-poc-target.XXXXXX, not /aaaa" \
  "--update-pins|$pins|--update-pins holds more than 1024 bytes"; do
  opt="${spec%%|*}"; rest="${spec#*|}"; value="${rest%%|*}"; text="${rest#*|}"
  start=$SECONDS
  code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}" "$opt" "$value")"
  took=$((SECONDS - start))
  [ "$code" = 3 ] && grep -qF "run.sh refused: $text" "$T/out" && new_nothing_ran && [ "$took" -le 2 ] \
    && ok "$opt with a value of ${#value} bytes -> refused in ${took}s" || { bad "$opt, a long value: exit $code after ${took}s"; cut -c1-300 "$T/out" >&2; }
done

# The execution mode: the stricter of <R>/exec-mode and AUDITOR_EXEC_MODE (none, then isolated, then
# native). Missing or none exits 3 before anything is copied, and so does a --mode that is not it.
# Isolated runs can pass only where no credential the self-check reads is readable, here in an empty
# HOME and the account's home directory; the driver says whether this machine's is. A CI runner must be
# such a machine, so that those checks run there.
readable="$(cd "$WT" && env -i HOME="$CLEANHOME" "${TOOL_HOMES[@]}" PATH="$PATH" bash "$T/iso-driver.sh" "$ROOT" creds 2>&1)"; rc=$?
ISOLATED_OK=0
if [ "$rc" = 0 ]; then
  ISOLATED_OK=1
  ok "this machine passes the isolation self-check, so the checks that isolated mode passes run"
elif [ "${CI:-}" = true ]; then
  bad "this CI runner does not pass the isolation self-check (${readable%%$'\n'*}), so the checks that isolated mode passes cannot run"
  printf '%s\n' "${readable#*$'\n'}" | sed 's/^/  found: /' >&2
else
  echo "note: this machine is not an isolated runner (${readable%%$'\n'*}); the checks that isolated mode passes are skipped"
fi
while IFS='|' read -r file env expect_mode; do
  [ -n "$expect_mode" ] || continue
  if [ -n "$file" ]; then printf '%s\n' "$file" > "$WT/audit_1/exec-mode"; else rm -f "$WT/audit_1/exec-mode"; fi
  set -- ; [ -n "$env" ] && set -- "AUDITOR_EXEC_MODE=$env"
  code="$(ngate "$@" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  label="exec-mode '${file:-absent}', AUDITOR_EXEC_MODE '${env:-unset}'"
  case "$expect_mode" in
    isolated|native)
      if [ "$expect_mode" = isolated ] && [ "$ISOLATED_OK" = 0 ]; then continue; fi
      [ "$code" = 0 ] && grep -q "^>> execution mode: $expect_mode (the stricter of audit_1/exec-mode: ${file:-absent}; AUDITOR_EXEC_MODE: ${env:-unset})$" "$T/out" \
        && grep -q "^>> build dir: .*AUDITOR_EXEC_MODE=$expect_mode;" "$T/out" \
        && ok "$label -> runs in $expect_mode mode" || { bad "$label: exit $code, want $expect_mode"; cat "$T/out" >&2; } ;;
    none)
      [ "$code" = 3 ] && grep -q 'blocker: the recorded execution mode is none' "$T/out" && new_nothing_ran && one_blocker \
        && ok "$label -> none: exit 3, nothing copied or built" || { bad "$label: exit $code, want none"; cat "$T/out" >&2; } ;;
    missing)
      [ "$code" = 3 ] && grep -q 'blocker: no recorded mode: audit_1/exec-mode is missing and AUDITOR_EXEC_MODE is not set' "$T/out" && new_nothing_ran && one_blocker \
        && ok "$label -> no recorded mode: exit 3, nothing copied or built" || { bad "$label: exit $code, want missing"; cat "$T/out" >&2; } ;;
  esac
done <<'CASES'
native||native
isolated||isolated
|native|native
|isolated|isolated
native|isolated|isolated
isolated|native|isolated
none||none
|none|none
none|native|none
native|none|none
none|isolated|none
||missing
CASES
printf 'native\n' > "$WT/audit_1/exec-mode"
for spec in 'native|native|0' 'native|isolated|3' 'native|none|3' 'isolated|native|3'; do
  file="${spec%%|*}"; rest="${spec#*|}"; mode="${rest%%|*}"; expect_rc="${rest#*|}"
  printf '%s\n' "$file" > "$WT/audit_1/exec-mode"
  code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}" --mode "$mode")"
  if [ "$expect_rc" = 0 ]; then
    [ "$code" = 0 ] && ok "--mode $mode with the recorded mode $file -> runs" || { bad "--mode $mode, recorded $file: exit $code"; cat "$T/out" >&2; }
  else
    [ "$code" = 3 ] && grep -q "blocker: --mode is $mode, but the recorded execution mode is $file " "$T/out" && new_nothing_ran && one_blocker \
      && ok "--mode $mode with the recorded mode $file -> exit 3 before anything is copied" || { bad "--mode $mode, recorded $file: exit $code"; cat "$T/out" >&2; }
  fi
done
while IFS='|' read -r content text; do
  [ -n "$text" ] || continue
  printf "$content" > "$WT/audit_1/exec-mode"
  code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 3 ] && grep -qF "run.sh refused: $text" "$T/out" && new_nothing_ran && one_blocker \
    && ok "exec-mode holding '$content' -> refused before anything is copied" || { bad "exec-mode '$content': exit $code"; cat "$T/out" >&2; }
done <<'CASES'
yes\n|audit_1/exec-mode holds something other than one word, none, isolated or native
Native\n|audit_1/exec-mode holds something other than one word, none, isolated or native
native\n\n|audit_1/exec-mode holds something other than one word, none, isolated or native
native isolated\n|audit_1/exec-mode holds something other than one word, none, isolated or native
\n|audit_1/exec-mode holds something other than one word, none, isolated or native
native\r\n|audit_1/exec-mode holds something other than one word, none, isolated or native
CASES
rm -f "$WT/audit_1/exec-mode"; mkdir "$WT/audit_1/exec-mode"
code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
[ "$code" = 3 ] && grep -qF 'run.sh refused: audit_1/exec-mode is not a regular file' "$T/out" && new_nothing_ran \
  && ok "an exec-mode that is a directory -> refused" || { bad "exec-mode directory: exit $code"; cat "$T/out" >&2; }
rmdir "$WT/audit_1/exec-mode"; printf 'native\n' > "$WT/audit_1/exec-mode"
code="$(ngate AUDITOR_EXEC_MODE=yes -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
[ "$code" = 3 ] && grep -qF "run.sh refused: AUDITOR_EXEC_MODE is 'yes', not none, isolated or native" "$T/out" && new_nothing_ran \
  && ok "AUDITOR_EXEC_MODE=yes -> refused, even with a recorded mode" || { bad "AUDITOR_EXEC_MODE=yes: exit $code"; cat "$T/out" >&2; }

# The harness copy: run.sh --crate checks the crate's shared-test-utils/ before anything is copied, and every
# build compiles the installation's src/lib.rs whatever the crate holds; its >> harness: line says whether the
# crate's copy matched. A copy that holds another file, or a Cargo.toml changed beyond the version
# requirements of its dependencies, stops the run.
STU="$WT/audit_1/poc/F-1/shared-test-utils"
cp "$STU/Cargo.toml" "$T/stu-cargo.keep"
code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
[ "$code" = 0 ] && grep -qxF ">> harness: the crate's shared-test-utils/ is the installation's (its dependency version requirements aside)" "$T/out" \
  && ok "--crate with the installation's harness copy -> the build runs, and the harness line says the copy matched" || { bad "harness copy, unchanged: exit $code"; cat "$T/out" >&2; }
printf '// changed in the crate\n' >> "$STU/src/lib.rs"
code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}" --keep)"; bd="$(new_build_dir)"
[ "$code" = 0 ] && grep -qxF ">> harness: the crate's shared-test-utils/src/lib.rs differs from the installation's; this build used the installation's, so record the difference" "$T/out" \
  && [ -n "$bd" ] && cmp -s "$bd/shared-test-utils/src/lib.rs" "$TEMPLATE/shared-test-utils/src/lib.rs" \
  && ok "--crate with a changed shared-test-utils/src/lib.rs -> the build compiles the installation's, and the harness line says the copy differed" \
  || { bad "harness copy, src/lib.rs changed: exit $code, build dir '$bd'"; cat "$T/out" >&2; }
[ -z "$bd" ] || rm -rf "$bd"
rm "$STU/src/lib.rs"
code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
[ "$code" = 0 ] && grep -qxF ">> harness: the crate has no shared-test-utils/src/lib.rs; this build used the installation's" "$T/out" \
  && ok "--crate with no shared-test-utils/src/lib.rs -> the build compiles the installation's, and says so" || { bad "harness copy, no src/lib.rs: exit $code"; cat "$T/out" >&2; }
cp "$TEMPLATE/shared-test-utils/src/lib.rs" "$STU/src/lib.rs"
sed 's/^mollusk-svm = "[^"]*"/mollusk-svm = "0.99"/' "$T/stu-cargo.keep" > "$STU/Cargo.toml"
code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
[ "$code" = 0 ] && ! cmp -s "$STU/Cargo.toml" "$T/stu-cargo.keep" \
  && grep -qxF ">> harness: the crate's shared-test-utils/ is the installation's (its dependency version requirements aside)" "$T/out" \
  && ok "--crate with a dependency version requirement changed in shared-test-utils/Cargo.toml -> the build runs" || { bad "harness copy, a version requirement: exit $code"; cat "$T/out" >&2; }
while IFS='|' read -r how what text; do
  [ -n "$how" ] || continue
  cp "$T/stu-cargo.keep" "$STU/Cargo.toml"
  case "$how" in
    dependency) printf 'evil = { path = "/tmp/evil" }\n' >> "$STU/Cargo.toml" ;;
    feature) sed 's/^sha2 = "0.10"/sha2 = { version = "0.10", features = ["asm"] }/' "$T/stu-cargo.keep" > "$STU/Cargo.toml" ;;
    package) sed 's/^edition = "2021"/edition = "2024"/' "$T/stu-cargo.keep" > "$STU/Cargo.toml" ;;
    build-script) printf 'fn main() {}\n' > "$STU/build.rs" ;;
    module) printf 'pub fn x() {}\n' > "$STU/src/other.rs" ;;
    no-manifest) rm "$STU/Cargo.toml" ;;
  esac
  code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 3 ] && grep -qF "[PoC-ATTEMPTED] blocker: the crate's $text" "$T/out" && new_nothing_ran && one_blocker \
    && ok "--crate with a harness copy $what -> exit 3 before anything is copied: $text" || { bad "harness copy $what: exit $code"; cat "$T/out" >&2; }
  rm -f "$STU/build.rs" "$STU/src/other.rs"
done <<CASES
dependency|that adds a dependency|shared-test-utils/Cargo.toml differs from the installation copy beyond the version requirements of its dependencies, from line
feature|that turns on a feature|shared-test-utils/Cargo.toml differs from the installation copy beyond the version requirements of its dependencies, from line
package|that changes the package's edition|shared-test-utils/Cargo.toml differs from the installation copy beyond the version requirements of its dependencies, from line
build-script|that holds a build script|shared-test-utils/ holds build.rs, which the installation copy does not
module|that holds another source file|shared-test-utils/ holds src/other.rs, which the installation copy does not
no-manifest|without its Cargo.toml|shared-test-utils/ has no Cargo.toml
CASES
cp "$T/stu-cargo.keep" "$STU/Cargo.toml"
# Right before the fixed arm builds, the re-check compares the scratch copy's harness copy with the
# installation's again: a vulnerable-arm build that changes it stops the run before the fixed arm builds.
for plant in "shared-test-utils/src/lib.rs|// changed by a build script\n" "shared-test-utils/build.rs|fn main() {}\n"; do
  SHIM_EXTRA=("SHIM_PLANT=$plant")
  code="$(ngate AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1)"
  SHIM_EXTRA=()
  want_plant="its shared-test-utils/src/lib.rs is no longer the installation's"
  [ "${plant%%|*}" = shared-test-utils/build.rs ] && want_plant="its shared-test-utils/ holds build.rs, which the installation copy does not"
  [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: $CHANGED $want_plant — nothing of the fixed arm was built." "$T/out" && one_blocker \
    && ! awk -F'\t' '$6 ~ /^testbin / || $6 ~ /^(build-sbf|test) .*--features fixed/ { f = 1 } END { exit !f }' "$T/calls" \
    && ok "--crate, a model run whose vulnerable-arm build writes ${plant%%|*} into the scratch copy -> exit 3 before the fixed arm builds" \
    || { bad "--crate, a vulnerable-arm build that writes ${plant%%|*}: exit $code"; cat "$T/out" >&2; }
done

# Every run directory an argument names counts: here --vulnerable-so and --fixed-so under audit_2/exec/.
( cd "$WT" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null || bad "rundir.sh could not make audit_2"
mkdir -p "$WT/audit_2/exec/b"; cp "$T/vuln.so" "$T/fixed.so" "$WT/audit_2/exec/b/"
while IFS='|' read -r one two expect; do
  [ -n "$expect" ] || continue
  if [ -n "$one" ]; then printf '%s\n' "$one" > "$WT/audit_1/exec-mode"; else rm -f "$WT/audit_1/exec-mode"; fi
  if [ -n "$two" ]; then printf '%s\n' "$two" > "$WT/audit_2/exec-mode"; else rm -f "$WT/audit_2/exec-mode"; fi
  code="$(ngate -- --crate audit_1/poc/F-1 --vulnerable-so audit_2/exec/b/vuln.so --fixed-so audit_2/exec/b/fixed.so)"
  label="audit_1/exec-mode '${one:-absent}', audit_2/exec-mode '${two:-absent}'"
  sources="audit_1/exec-mode: ${one:-absent}; audit_2/exec-mode: ${two:-absent}; AUDITOR_EXEC_MODE: unset"
  case "$expect" in
    none) [ "$code" = 3 ] && grep -qF "blocker: the recorded execution mode is none ($sources)" "$T/out" && new_nothing_ran \
            && ok "$label -> none, from the run directory of the prebuilt bytes: exit 3" || { bad "$label: exit $code"; cat "$T/out" >&2; } ;;
    *) grep -qxF ">> execution mode: $expect (the stricter of $sources)" "$T/out" && { [ "$code" = 0 ] || [ "$expect" = isolated ]; } \
         && ok "$label -> $expect, the stricter over both run directories" || { bad "$label: exit $code"; cat "$T/out" >&2; } ;;
  esac
done <<'CASES'
native|isolated|isolated
isolated|native|isolated
native|none|none
|native|native
CASES
rm -rf "$WT/audit_2"
printf 'native\n' > "$WT/audit_1/exec-mode"

# ./run.sh in a crate at <R>/poc/<ID> takes the stricter of <R>/exec-mode and AUDITOR_EXEC_MODE as well;
# a crate anywhere else, or an exec-mode it cannot use, leaves the mode gate to decide from the environment.
while IFS='|' read -r file env expect; do
  [ -n "$expect" ] || continue
  if [ -n "$file" ]; then printf '%s\n' "$file" > "$WT/audit_1/exec-mode"; else rm -f "$WT/audit_1/exec-mode"; fi
  set -- "$VULN"; [ -n "$env" ] && set -- "$@" "AUDITOR_EXEC_MODE=$env"
  code="$(gate "$WT/audit_1/poc/F-1" "$@")"
  label="./run.sh with exec-mode '${file:-absent}', AUDITOR_EXEC_MODE '${env:-unset}'"
  case "$expect" in
    isolated|native)
      [ "$code" = 0 ] && grep -q "^>> build dir: .*AUDITOR_EXEC_MODE=$expect;" "$T/out" \
        && { [ -z "$file" ] || grep -qxF ">> execution mode: $expect (the stricter of audit_1/exec-mode: $file; AUDITOR_EXEC_MODE: ${env:-unset})" "$T/out"; } \
        && ok "$label -> runs in $expect mode" || { bad "$label: exit $code, want $expect"; cat "$T/out" >&2; } ;;
    none)
      [ "$code" = 3 ] && grep -qF "blocker: the recorded execution mode is none (audit_1/exec-mode: $file; AUDITOR_EXEC_MODE: ${env:-unset})" "$T/out" && nothing_ran && one_blocker \
        && ok "$label -> none: exit 3, nothing copied or built" || { bad "$label: exit $code, want none"; cat "$T/out" >&2; } ;;
    gate)
      [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: AUDITOR_EXEC_MODE is '$env', not isolated or native — nothing was copied or built." "$T/out" && nothing_ran \
        && ok "$label -> the mode gate's own blocker" || { bad "$label: exit $code, want the gate"; cat "$T/out" >&2; } ;;
    refused)
      [ "$code" = 3 ] && grep -qF "run.sh refused: audit_1/exec-mode holds something other than one word, none, isolated or native — nothing was copied or built." "$T/out" && nothing_ran \
        && ok "$label -> refused: exit 3" || { bad "$label: exit $code, want refused"; cat "$T/out" >&2; } ;;
  esac
done <<'CASES'
none|native|none
native|none|none
none||none
isolated|native|isolated
native|isolated|isolated
native||native
|native|native
||gate
native|yes|gate
yes|native|refused
CASES
mkdir -p "$T/not-a-run/poc"; cp -R "$WT/audit_1/poc/F-1" "$T/not-a-run/poc/F-1"; printf 'none\n' > "$T/not-a-run/exec-mode"
code="$(gate "$T/not-a-run/poc/F-1" "$VULN" "$NATIVE")"
[ "$code" = 0 ] && ! grep -q '^>> execution mode:' "$T/out" && ok "./run.sh in a crate outside a run directory reads no exec-mode" || { bad "./run.sh outside a run directory: exit $code"; cat "$T/out" >&2; }
printf 'native\n' > "$WT/audit_1/exec-mode"

# The isolation self-check. In isolated mode, a fake HOME holding any one credential the check reads
# stops the run before anything is copied, naming its kind, and so does a check that cannot finish; in
# native mode it is a warning. Neither line names a path. The driver, given that home alone, counts the
# credential under its kind and prints it under ~, the gcloud account as <account>.
printf 'isolated\n' > "$WT/audit_1/exec-mode"
n=0
while IFS='|' read -r cred kind; do
  [ -n "$cred" ] || continue
  n=$((n + 1)); FH="$T/fh-$n"; mkdir -p "$(dirname "$FH/$cred")"; printf 'secret\n' > "$FH/$cred"
  shown="~/$(printf '%s' "$cred" | sed 's#legacy_credentials/[^/]*#legacy_credentials/<account>#')"
  out="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" "$BASH" "$T/iso-driver.sh" "$ROOT" creds "$FH")"; rc=$?
  [ "$rc" = 1 ] && [ "$out" = "$(printf 'kinds: %s (1)\n%s' "$kind" "$shown")" ] \
    && ok "~/$cred is read, and counts as $kind" || bad "the check on ~/$cred: $rc '$out'"
  code="$(ngate HOME="$FH" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  line="$(grep '^\[PoC-ATTEMPTED\] blocker: isolated mode, but these are readable here: ' "$T/out")"
  [ "$code" = 3 ] && case "$line" in *"$kind ("*"; this is not the isolated runner (Rule 11a), and scripts/runner/probe.sh --only isolation lists them — nothing was copied or built.") true ;; *) false ;; esac \
    && new_nothing_ran && one_blocker && ok "isolated mode with a readable ~/$cred -> exit 3 naming $kind, nothing copied" || { bad "isolated, ~/$cred: exit $code"; cat "$T/out" >&2; }
done <<'CREDS'
.ssh/id_ed25519|SSH keys
.ssh/work/deploy_key|SSH keys
.ssh/a/b/c/id_rsa|SSH keys
.config/solana/id.json|Solana keypairs or CLI config
.config/solana/deployer.json|Solana keypairs or CLI config
.config/solana/cli/config.yml|Solana keypairs or CLI config
.aws/credentials|cloud credentials
.aws/sso/cache/0123abcd.json|cloud credentials
.aws/cli/cache/0123abcd.json|cloud credentials
.config/gcloud/credentials.db|cloud credentials
.config/gcloud/access_tokens.db|cloud credentials
.config/gcloud/application_default_credentials.json|cloud credentials
.config/gcloud/legacy_credentials/me@example.invalid/adc.json|cloud credentials
.azure/accessTokens.json|cloud credentials
.azure/msal_token_cache.json|cloud credentials
.azure/msal_token_cache.bin|cloud credentials
.azure/service_principal_entries.json|cloud credentials
.azure/service_principal_entries.bin|cloud credentials
.kube/config|Kubernetes or Docker config
.docker/config.json|Kubernetes or Docker config
.npmrc|package registry tokens
.yarnrc.yml|package registry tokens
.gem/credentials|package registry tokens
.pypirc|package registry tokens
.cargo/credentials|package registry tokens
.cargo/credentials.toml|package registry tokens
.git-credentials|git or HTTP credentials
.config/git/credentials|git or HTTP credentials
.netrc|git or HTTP credentials
.config/gh/hosts.yml|git or HTTP credentials
.gnupg/private-keys-v1.d/0123456789ABCDEF.key|GnuPG private keys
.claude/.credentials.json|Claude Code credentials
.vault-token|cloud credentials
.terraform.d/credentials.tfrc.json|cloud credentials
.claude-work/.credentials.json|Claude Code credentials
.config/anthropic/credentials/default.json|Claude Code credentials
.config/anthropic/configs/default.json|Claude Code credentials
.docker/key.pem|Kubernetes or Docker config
.docker/contexts/tls/0123abcd/docker/key.pem|Kubernetes or Docker config
.gitcookies|git or HTTP credentials
CREDS
# The same for a Claude Code login only where CLAUDE_CONFIG_DIR keeps it, outside HOME, for an API key only in
# the env block of ~/.claude/settings.json, and for a git credential helper only, in ~/.gitconfig, in the form
# Dev Containers use to forward the host's git login.
mkdir -p "$T/cc-dir"; printf 'secret\n' > "$T/cc-dir/.credentials.json"
code="$(ngate HOME="$CLEANHOME" CLAUDE_CONFIG_DIR="$T/cc-dir" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
line="$(grep '^\[PoC-ATTEMPTED\] blocker: isolated mode, but these are readable here: ' "$T/out")"
[ "$code" = 3 ] && case "$line" in *"Claude Code credentials ("*) true ;; *) false ;; esac && new_nothing_ran && one_blocker \
  && ok "isolated mode with a Claude Code login only under CLAUDE_CONFIG_DIR, outside HOME -> exit 3 naming Claude Code credentials, nothing copied" \
  || { bad "isolated, a login under CLAUDE_CONFIG_DIR: exit $code"; cat "$T/out" >&2; }
FH="$T/fh-ccsettings"; mkdir -p "$FH/.claude"; printf '{"env":{"ANTHROPIC_API_KEY":"x"}}\n' > "$FH/.claude/settings.json"
code="$(ngate HOME="$FH" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
line="$(grep '^\[PoC-ATTEMPTED\] blocker: isolated mode, but these are readable here: ' "$T/out")"
[ "$code" = 3 ] && case "$line" in *"Claude Code credentials ("*) true ;; *) false ;; esac && new_nothing_ran && one_blocker \
  && ok "isolated mode with an API key only in the env block of ~/.claude/settings.json -> exit 3 naming Claude Code credentials, nothing copied" \
  || { bad "isolated, an API key in Claude Code's settings: exit $code"; cat "$T/out" >&2; }
FH="$T/fh-cchead"; mkdir -p "$FH/.claude"; printf '{"env":{"ANTHROPIC_CUSTOM_HEADERS":"X-Org-Route: prod\\nX-Api-Key: x"}}\n' > "$FH/.claude/settings.json"
code="$(ngate HOME="$FH" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
line="$(grep '^\[PoC-ATTEMPTED\] blocker: isolated mode, but these are readable here: ' "$T/out")"
[ "$code" = 3 ] && case "$line" in *"Claude Code credentials ("*) true ;; *) false ;; esac && new_nothing_ran && one_blocker \
  && ok "isolated mode with a gateway key only in ANTHROPIC_CUSTOM_HEADERS, in the env block of ~/.claude/settings.json -> exit 3 naming Claude Code credentials, nothing copied" \
  || { bad "isolated, a gateway key in ANTHROPIC_CUSTOM_HEADERS: exit $code"; cat "$T/out" >&2; }
FH="$T/fh-gitcred"; mkdir -p "$FH"
printf '[credential]\n\thelper = "!f() { node /tmp/vscode-remote-containers-0.js git-credential-helper $*; }; f"\n' > "$FH/.gitconfig"
code="$(ngate HOME="$FH" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
line="$(grep '^\[PoC-ATTEMPTED\] blocker: isolated mode, but these are readable here: ' "$T/out")"
[ "$code" = 3 ] && case "$line" in *"git or HTTP credentials ("*) true ;; *) false ;; esac && new_nothing_ran && one_blocker \
  && ok "isolated mode with only a git credential helper in ~/.gitconfig, as Dev Containers set one -> exit 3 naming git or HTTP credentials, nothing copied" \
  || { bad "isolated, a git credential helper: exit $code"; cat "$T/out" >&2; }
FH="$T/fh-many"; mkdir -p "$FH/.ssh" "$FH/.gnupg/private-keys-v1.d"; printf 'secret\n' > "$FH/.gnupg/private-keys-v1.d/ABC.key"
i=0; while [ "$i" -le 5000 ]; do : > "$FH/.ssh/known_hosts.$i"; i=$((i + 1)); done
code="$(ngate HOME="$FH" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
[ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: isolated mode, but the credential self-check could not finish (more than 5000 entries in the directories it lists), so run.sh cannot tell that this is the isolated runner (Rule 11a) — nothing was copied or built." "$T/out" \
  && new_nothing_ran && one_blocker && ok "isolated mode with more than 5000 entries to list -> exit 3: the check cannot tell, nothing copied" || { bad "isolated, a check that cannot finish: exit $code"; cat "$T/out" >&2; }
FH="$T/fh-native"; mkdir -p "$FH/.aws" "$FH/.config/gcloud/legacy_credentials/me@example.invalid"; printf 'secret\n' > "$FH/.aws/credentials"
printf 'secret\n' > "$FH/.config/gcloud/legacy_credentials/me@example.invalid/adc.json"
printf 'native\n' > "$WT/audit_1/exec-mode"
code="$(ngate HOME="$FH" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
line="$(grep '^>> warning: native mode, and these are readable here, to the code this run builds and runs too: ' "$T/out")"
[ "$code" = 0 ] && case "$line" in *"cloud credentials ("*" (Rule 11a)") true ;; *) false ;; esac && case "$line" in */*|*@*) false ;; *) true ;; esac \
  && ok "native mode with readable credentials -> a warning naming their kinds and counts, never a path or an account, and the run goes on" || { bad "native with a credential: exit $code"; cat "$T/out" >&2; }

# The check on its own, through the driver: the homes it is given (never the passwd home) and the places
# the environment names.
# dcreds [VAR=val ...] -- <home>...: iso_credentials on those homes, with only an empty HOME, PATH and the
# variables given in the environment -> its status; what the driver printed in $T/creds.out
dcreds() {
  local -a vars=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do vars+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  (cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" ${vars[@]+"${vars[@]}"} "$BASH" "$T/iso-driver.sh" "$ROOT" creds "$@") >"$T/creds.out" 2>&1
  echo $?
}
lines_are() {  # lines_are <kinds> <line>...: $T/creds.out holds those kinds, then exactly these lines, in any order,
  local line   # each cut after 300 characters as the check prints a path, so that a long TMPDIR passes too
  [ "$(sed -n 1p "$T/creds.out")" = "kinds: $1" ] || return 1
  shift
  sed 1d "$T/creds.out" > "$T/creds.paths"
  [ "$(grep -c . "$T/creds.paths")" = "$#" ] || return 1
  for line in "$@"; do grep -qxF -- "${line:0:300}" "$T/creds.paths" || return 1; done
}
X="$T/fx"; mkdir -p "$X/sol/.config/solana/cli" "$X/keys" "$X/sol2/.config/solana/cli" "$X/sol2/wallets"
printf 'k\n' > "$X/keys/deploy.json"; printf 'k\n' > "$X/sol2/wallets/main.json"
printf 'json_rpc_url: "https://rpc.invalid/key"\nkeypair_path: %s/keys/deploy.json # the deployer\n' "$X" > "$X/sol/.config/solana/cli/config.yml"
printf "keypair_path: '~/wallets/main.json'\n" > "$X/sol2/.config/solana/cli/config.yml"
code="$(dcreds -- "$X/sol" "$X/sol2")"
[ "$code" = 1 ] && lines_are "Solana keypairs or CLI config (4)" "~/.config/solana/cli/config.yml" "$X/keys/deploy.json" "~/.config/solana/cli/config.yml" "~/wallets/main.json" \
  && ok "the keypair the Solana CLI config names counts wherever it is ('~' being that home), and so does the config" || { bad "the CLI config's keypair: $code"; cat "$T/creds.out" >&2; }
mkdir -p "$X/lnk/.ssh" "$X/keys-elsewhere"; printf 'k\n' > "$X/keys-elsewhere/deploy_key"
ln -s "$X/keys-elsewhere" "$X/lnk/.ssh/work"; ln -s . "$X/lnk/.ssh/loop"; printf 'public\n' > "$X/lnk/.ssh/known_hosts"
code="$(dcreds -- "$X/lnk")"
[ "$code" = 1 ] && lines_are "SSH keys (1)" "~/.ssh/work/deploy_key" \
  && ok "a key in a directory a link in ~/.ssh names counts, and a link back to ~/.ssh is listed once" || { bad "linked directories: $code"; cat "$T/creds.out" >&2; }
code="$(dcreds -- "$T/fh-many")"
[ "$code" = 2 ] && [ "$(cat "$T/creds.out")" = "why: more than 5000 entries in the directories it lists" ] \
  && ok "past 5000 entries in the directories it lists, the check stops and cannot tell (status 2)" || { bad "the entry budget: $code"; cat "$T/creds.out" >&2; }
E="$T/fe"; mkdir -p "$E/aws" "$E/kube" "$E/docker" "$E/gcloud/legacy_credentials/me@example.invalid" "$E/azure" \
  "$E/gnupg/private-keys-v1.d" "$E/xdg/gh" "$E/xdg/git" "$E/ghdir" "$E/cargo"
for f in aws/creds kube/a kube/b docker/config.json gcloud/credentials.db gcloud/legacy_credentials/me@example.invalid/adc.json \
  azure/msal_token_cache.json gnupg/private-keys-v1.d/K.key xdg/gh/hosts.yml xdg/git/credentials ghdir/hosts.yml \
  cargo/credentials.toml npmrc-upper npmrc-lower netrc service-account.json; do printf 'secret\n' > "$E/$f"; done
code="$(dcreds AWS_SHARED_CREDENTIALS_FILE="$E/aws/creds" KUBECONFIG="$E/kube/a:$E/kube/b" DOCKER_CONFIG="$E/docker" \
  CLOUDSDK_CONFIG="$E/gcloud" AZURE_CONFIG_DIR="$E/azure" GNUPGHOME="$E/gnupg" XDG_CONFIG_HOME="$E/xdg" GH_CONFIG_DIR="$E/ghdir" \
  CARGO_HOME="$E/cargo" NPM_CONFIG_USERCONFIG="$E/npmrc-upper" npm_config_userconfig="$E/npmrc-lower" NETRC="$E/netrc" \
  GOOGLE_APPLICATION_CREDENTIALS="$E/service-account.json" -- "$CLEANHOME")"
[ "$code" = 1 ] && lines_are "cloud credentials (5), Kubernetes or Docker config (3), package registry tokens (3), git or HTTP credentials (4), GnuPG private keys (1)" \
  "$E/aws/creds" "$E/kube/a" "$E/kube/b" "$E/docker/config.json" "$E/gcloud/credentials.db" \
  "$E/gcloud/legacy_credentials/<account>/adc.json" "$E/azure/msal_token_cache.json" "$E/gnupg/private-keys-v1.d/K.key" \
  "$E/xdg/gh/hosts.yml" "$E/xdg/git/credentials" "$E/ghdir/hosts.yml" "$E/cargo/credentials.toml" "$E/npmrc-upper" "$E/npmrc-lower" \
  "$E/netrc" "$E/service-account.json" \
  && ok "the credential files the environment's variables name count (KUBECONFIG, CLOUDSDK_CONFIG, GNUPGHOME, CARGO_HOME and the rest)" || { bad "credentials the environment names: $code"; cat "$T/creds.out" >&2; }
# Where the environment puts a Claude Code login (CLAUDE_CONFIG_DIR, with its settings and state files), the
# Anthropic profiles (ANTHROPIC_CONFIG_DIR) and their federation token file.
EC="$T/fe-claude"; mkdir -p "$EC/claude" "$EC/anthropic/credentials"
for f in claude/.credentials.json anthropic/credentials/default.json id-token; do printf 'secret\n' > "$EC/$f"; done
printf '{"apiKeyHelper":"/opt/k.sh"}\n' > "$EC/claude/settings.json"; printf '{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"t"}}}}\n' > "$EC/claude/.claude.json"
code="$(dcreds CLAUDE_CONFIG_DIR="$EC/claude" ANTHROPIC_CONFIG_DIR="$EC/anthropic" ANTHROPIC_IDENTITY_TOKEN_FILE="$EC/id-token" -- "$CLEANHOME")"
[ "$code" = 1 ] && lines_are "Claude Code credentials (5)" "$EC/claude/.credentials.json" "$EC/claude/settings.json" "$EC/claude/.claude.json" \
  "$EC/anthropic/credentials/default.json" "$EC/id-token" \
  && ok "a Claude Code login, settings and state, and Anthropic profiles where the environment puts them count (CLAUDE_CONFIG_DIR, ANTHROPIC_CONFIG_DIR, ANTHROPIC_IDENTITY_TOKEN_FILE)" \
  || { bad "a Claude Code login the environment moves: $code"; cat "$T/creds.out" >&2; }
# Claude Code's managed settings count in default mode, read as its settings are. The check reads them in the
# system directories, so a copy of isolation.sh reads them in the suite's own; it runs where this machine
# passes the check, as on CI. A hidden file and one not ending in .json in managed-settings.d/ do not count.
if [ "$ISOLATED_OK" = 1 ]; then
  MS="$T/managed"; MR="$T/iso-managed"; mkdir -p "$MS/managed-settings.d" "$MR/scripts/lib"
  cp "$ROOT/scripts/lib/confine.sh" "$MR/scripts/lib/"
  sed "s#^MANAGED = .*#MANAGED = (\"$MS\",)#" "$ROOT/scripts/lib/isolation.sh" > "$MR/scripts/lib/isolation.sh"
  printf '{"apiKeyHelper":"/opt/k.sh"}\n' > "$MS/managed-settings.json"; printf '{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"t"}}}}\n' > "$MS/managed-mcp.json"
  for f in 20-key.json .hidden.json notes.txt; do printf '{"env":{"ANTHROPIC_API_KEY":"x"}}\n' > "$MS/managed-settings.d/$f"; done
  (cd "$WT" && env -i HOME="$CLEANHOME" "${TOOL_HOMES[@]}" PATH="$PATH" bash "$T/iso-driver.sh" "$MR" creds) >"$T/creds.out" 2>&1; code=$?
  [ "$code" = 1 ] && lines_are "Claude Code credentials (3)" "$MS/managed-settings.json" "$MS/managed-settings.d/20-key.json" "$MS/managed-mcp.json" \
    && ok "Claude Code's managed settings count in default mode (managed-settings.json, managed-settings.d/*.json, managed-mcp.json)" \
    || { bad "Claude Code's managed settings: $code"; cat "$T/creds.out" >&2; }
fi
# The askpass programs the environment names, and the git and AWS config files it names, which count for what
# they hold.
EG="$T/fe-git"; mkdir -p "$EG/xdg/git"
for f in askpass ssh-askpass; do printf 'secret\n' > "$EG/$f"; done
printf '[credential]\n\thelper = manager\n' > "$EG/gitconfig-global"; printf '[core]\n\taskpass = /x\n' > "$EG/gitconfig-system"
printf '[http]\n\textraheader = AUTHORIZATION: basic eA==\n' > "$EG/xdg/git/config"; printf '[default]\naws_session_token = x\n' > "$EG/aws-config"
printf 'credentials "app.terraform.io" {\n  token = "x"\n}\n' > "$EG/cli.tfrc"
code="$(dcreds GIT_ASKPASS="$EG/askpass" SSH_ASKPASS="$EG/ssh-askpass" GIT_CONFIG_GLOBAL="$EG/gitconfig-global" \
  GIT_CONFIG_SYSTEM="$EG/gitconfig-system" XDG_CONFIG_HOME="$EG/xdg" AWS_CONFIG_FILE="$EG/aws-config" TF_CLI_CONFIG_FILE="$EG/cli.tfrc" -- "$CLEANHOME")"
[ "$code" = 1 ] && lines_are "cloud credentials (2), git or HTTP credentials (5)" "$EG/askpass" "$EG/ssh-askpass" \
  "$EG/gitconfig-global" "$EG/gitconfig-system" "$EG/xdg/git/config" "$EG/aws-config" "$EG/cli.tfrc" \
  && ok "the askpass programs, git config, AWS config and Terraform CLI config the environment names count (GIT_ASKPASS, GIT_CONFIG_GLOBAL, AWS_CONFIG_FILE, TF_CLI_CONFIG_FILE and the rest)" \
  || { bad "the askpass and config places the environment names: $code"; cat "$T/creds.out" >&2; }
# The Docker TLS client keys the environment names: key.pem in DOCKER_CERT_PATH, and the context keys under
# DOCKER_CONFIG. The certificates beside them do not count.
ED="$T/fe-docker"; mkdir -p "$ED/certs" "$ED/config/contexts/tls/0123abcd/docker"
for f in certs/key.pem config/contexts/tls/0123abcd/docker/key.pem; do printf 'secret\n' > "$ED/$f"; done
printf 'public\n' > "$ED/certs/cert.pem"; printf 'public\n' > "$ED/config/contexts/tls/0123abcd/docker/ca.pem"
code="$(dcreds DOCKER_CERT_PATH="$ED/certs" DOCKER_CONFIG="$ED/config" -- "$CLEANHOME")"
[ "$code" = 1 ] && lines_are "Kubernetes or Docker config (2)" "$ED/certs/key.pem" "$ED/config/contexts/tls/0123abcd/docker/key.pem" \
  && ok "the Docker TLS client keys the environment names count (DOCKER_CERT_PATH, DOCKER_CONFIG's contexts)" \
  || { bad "the Docker TLS client keys the environment names: $code"; cat "$T/creds.out" >&2; }
# A git config or an AWS config in a home counts for what it holds. In a git config: a credential helper
# (osxkeychain, manager, the one gh auth setup-git writes, and git's store or cache written with shell
# syntax), an askpass program, a cookie file, an HTTP header, an http(s) URL or a proxy with a login, in any
# letter case, on a section's own line or after several headers on one, and after a byte order mark too; in
# an AWS config: a credential_process or a key, after = or :; in ~/.terraformrc, a credentials or
# credentials_helper block. A helper reset to nothing, git's store and cache with their default file and
# socket (which count on their own) or with a --file or --socket that holds nothing, a user name with an ssh
# URL, a proxy without a login, a region alone and a Terraform plugin cache do not count. A store or cache
# written with a variable counts even with an absolute path. So do Claude Code's settings and state files (in
# ~/.claude*, ~/.claude.json and its backups): a command that prints a credential (an MCP server's
# headersHelper too), a token or a passphrase in an env block (of the file or of an MCP server), a URL with a
# login, a key-named query parameter or a key in its path there, a credential header in a list of headers
# there (ANTHROPIC_CUSTOM_HEADERS lines, an MCP server's JSON object; any *-Authorization, and a name whose last
# part is KEY or AUTH), any header in the OTLP exporter's lists, an MCP server's Authorization or key header,
# and a key in an MCP server's or a hook's URL (its login, its query or its path) or in an MCP server's
# arguments (an option, NAME=value, a header option, a URL). Settings that only refer to a variable, and names
# that do not look like credentials, do not count; nor do an ssh URL with a user name only, arguments that name
# no credential, a public RPC URL, a skip-auth switch, a public key, a --no- option, and a version, a date or a
# local file in a URL's path.
n=0
while IFS='|' read -r file text kind; do
  [ -n "$file" ] || continue
  n=$((n + 1)); FH="$T/fc-$n"; mkdir -p "$(dirname "$FH/$file")"; printf "$text" > "$FH/$file"
  code="$(dcreds -- "$FH")"
  if [ -n "$kind" ]; then
    [ "$code" = 1 ] && lines_are "$kind (1)" "~/$file" && ok "~/$file holding $text counts as $kind" || { bad "~/$file holding $text: $code"; cat "$T/creds.out" >&2; }
  else
    [ "$code" = 0 ] && [ ! -s "$T/creds.out" ] && ok "~/$file holding $text does not count" || { bad "~/$file holding $text: $code"; cat "$T/creds.out" >&2; }
  fi
done <<'CONFIGS'
.gitconfig|[credential]\n\thelper = store\n|
.gitconfig|[credential]\n\thelper = cache --timeout=3600\n|
.gitconfig|[credential]\n\thelper = store --file ~/.no-such-store\n|
.gitconfig|[credential]\n\thelper = /usr/libexec/git-core/git-credential-cache --socket /nonexistent.invalid/socket\n|
.gitconfig|[credential]\n\thelper = store --file=$HOME/.git-store\n|git or HTTP credentials
.gitconfig|[credential]\n\thelper = store --file /nonexistent.invalid/s && /opt/other-helper\n|git or HTTP credentials
.gitconfig|[credential]\n\thelper = store --file .git-store\n|git or HTTP credentials
.gitconfig|[credential "https://github.com"]\n\thelper =\n\thelper = !/opt/homebrew/bin/gh auth git-credential\n|git or HTTP credentials
.gitconfig|[credential "https://github.com"]\n\thelper = "!f() { node /tmp/vscode-remote-containers-0.js git-credential-helper $*; }; f"\n|git or HTTP credentials
.gitconfig|[Credential] Helper = osxkeychain\n|git or HTTP credentials
.config/git/config|[core]\n\taskPass = /usr/libexec/askpass\n|git or HTTP credentials
.gitconfig|[http "https://github.com/"]\n\textraHeader = AUTHORIZATION: basic eA==\n|git or HTTP credentials
.gitconfig|[url "https://x-access-token:t@github.com/"]\n\tinsteadOf = https://github.com/\n|git or HTTP credentials
.gitconfig|[credential]\n\thelper =\n\thelper = "" # reset\n|
.gitconfig|[user]\n\tname = n\n[url "ssh://git@github.com/"]\n\tinsteadOf = https://github.com/\n|
.aws/config|[profile ci]\ncredential_process = /usr/local/bin/creds\n|cloud credentials
.aws/config|[default]\naws_secret_access_key = x\n|cloud credentials
.aws/config|[default]\nregion = eu-west-1\n|
.gitconfig|\xef\xbb\xbf[credential]\n\thelper = osxkeychain\n|git or HTTP credentials
.gitconfig|[core] [credential] helper = manager\n|git or HTTP credentials
.gitconfig|[http]\n\tproxy = http://u:p@proxy.invalid:3128\n|git or HTTP credentials
.gitconfig|[remote "origin"]\n\tproxy = u:p@proxy.invalid\n|git or HTTP credentials
.gitconfig|[http "https://review.example.invalid/"]\n\tcookieFile = ~/.gitcookies\n|git or HTTP credentials
.gitconfig|[http]\n\tproxy = http://proxy.invalid:3128\n|
.aws/config|[default]\naws_secret_access_key: x\n|cloud credentials
.terraformrc|credentials "app.terraform.io" {\n  token = "x"\n}\n|cloud credentials
.terraformrc|credentials_helper "example" {\n  args = []\n}\n|cloud credentials
.terraformrc|plugin_cache_dir = "/tmp/plugins"\n|
.claude/settings.json|{"env":{"CLAUDE_CODE_OAUTH_TOKEN":"x"}}\n|Claude Code credentials
.claude/settings.local.json|{"apiKeyHelper":"/opt/k.sh"}\n|Claude Code credentials
.claude-work/remote-settings.json|{"awsCredentialExport":"/opt/aws-export.sh"}\n|Claude Code credentials
.claude/settings.json|{"env":{"HTTPS_PROXY":"http://u:p@proxy.invalid:3128"}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"gh":{"command":"x","env":{"GITHUB_TOKEN":"t"}}}}\n|Claude Code credentials
.claude.json|{"projects":{"/w":{"mcpServers":{"api":{"type":"http","headers":{"Authorization":"Bearer t"}}}}}}\n|Claude Code credentials
.claude/backups/.claude.json.backup.1|{"mcpServers":{"gh":{"env":{"GITHUB_TOKEN":"t"}}}}\n|Claude Code credentials
.claude/settings.json|{"env":{"AUDITOR_EXEC_MODE":"isolated","MAX_MCP_OUTPUT_TOKENS":"1","GITHUB_TOKEN":"${GITHUB_TOKEN}"},"apiKeyHelper":""}\n|
.claude.json|{"oauthAccount":{"emailAddress":"a@b.invalid"},"mcpServers":{"api":{"headers":{"Authorization":"Bearer ${API_TOKEN}","X-Client":"c"}}}}\n|
.claude/settings.json|{"env":{"ANTHROPIC_CUSTOM_HEADERS":"X-Org-Route: prod\\nx-api-key: x"}}\n|Claude Code credentials
.claude/settings.json|{"env":{"OTEL_EXPORTER_OTLP_HEADERS":"Authorization=Bearer x"}}\n|Claude Code credentials
.claude/settings.json|{"env":{"DATABASE_URL":"postgres://u:p@db.invalid/x"}}\n|Claude Code credentials
.claude/settings.json|{"env":{"RPC_ENDPOINT":"https://rpc.example.invalid/?api-key=x"}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"rpc":{"type":"ws","url":"wss://t@mcp.example.invalid/ws"}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"rpc":{"type":"http","url":"https://mcp.example.invalid/mcp?api-key=x"}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"rpc":{"type":"sse","url":"https://u:p@mcp.example.invalid/sse"}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"rpc":{"command":"npx","args":["-y","x-mcp","--api-key","x"]}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"rpc":{"command":"x-mcp","args":["--authToken","x"]}}}\n|Claude Code credentials
.claude.json|{"projects":{"/w":{"mcpServers":{"gh":{"command":"docker","args":["run","-i","-e","GITHUB_PERSONAL_ACCESS_TOKEN=x","img"]}}}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"remote":{"command":"npx","args":["mcp-remote","https://mcp.example.invalid/sse","--header","Authorization: Bearer x"]}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"api":{"type":"http","url":"https://mcp.example.invalid/mcp","headersHelper":"/opt/h.sh"}}}\n|Claude Code credentials
.claude/settings.json|{"env":{"ANTHROPIC_CUSTOM_HEADERS":"X-Org-Route: prod\\nX-Tenant: t","OTEL_EXPORTER_OTLP_HEADERS":"Authorization=Bearer ${OTEL_TOKEN}","GIT_URL":"ssh://git@github.com/o/r.git"}}\n|
.claude.json|{"mcpServers":{"api":{"type":"http","url":"https://mcp.example.invalid/mcp?api-key=${API_KEY}&page=2"},"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/w","--header","X-Client: c"]},"gh":{"command":"docker","args":["run","-e","GITHUB_PERSONAL_ACCESS_TOKEN","img"]}}}\n|
.gitconfig|[credential]\n\thelper = store --file /nonexistent.invalid/$USER\n|git or HTTP credentials
.claude/settings.json|{"env":{"ANTHROPIC_CUSTOM_HEADERS":"cf-aig-authorization: Bearer x"}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"maps":{"type":"http","url":"https://maps.example.invalid/mcp?key=x"}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"blob":{"type":"http","url":"https://acct.blob.example.invalid/mcp?sv=2024-11-04&sig=x"}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"remote":{"command":"npx","args":["mcp-remote","https://mcp.example.invalid/sse","-H","Authorization: Bearer x"]}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"db":{"command":"npx","args":["-y","@bytebase/dbhub","--dsn","postgresql://readonly:p@db.invalid:5432/x"]}}}\n|Claude Code credentials
.claude/settings.json|{"env":{"ANTHROPIC_CUSTOM_HEADERS":"X-Org-Route: prod\\nOcp-Apim-Subscription-Key: x"}}\n|Claude Code credentials
.claude/settings.json|{"env":{"ANTHROPIC_CUSTOM_HEADERS":"Helicone-Auth: Bearer x"}}\n|Claude Code credentials
.claude/settings.json|{"env":{"OTEL_EXPORTER_OTLP_HEADERS":"x-honeycomb-team=x"}}\n|Claude Code credentials
.claude/settings.json|{"env":{"OTEL_EXPORTER_OTLP_LOGS_HEADERS":"x-honeycomb-team=x"}}\n|Claude Code credentials
.claude/settings.json|{"env":{"CLAUDE_CODE_CLIENT_KEY_PASSPHRASE":"x"}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"notion":{"command":"npx","args":["-y","@notionhq/notion-mcp-server"],"env":{"OPENAPI_MCP_HEADERS":"{\\"Authorization\\": \\"Bearer x\\", \\"Notion-Version\\": \\"2025-09-03\\"}"}}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"apim":{"type":"http","url":"https://contoso.azure-api.net/weather/mcp","headers":{"Ocp-Apim-Subscription-Key":"x"}}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"apim":{"type":"http","url":"https://contoso.azure-api.net/weather/mcp?subscription-key=x"}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"w":{"command":"w-mcp","args":["--key","x"]}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"w":{"command":"w-mcp","args":["--auth=x"]}}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"remote":{"command":"npx","args":["mcp-remote","https://mcp.example.invalid/sse","--header","Ocp-Apim-Subscription-Key: x"]}}}\n|Claude Code credentials
.claude/settings.json|{"env":{"ANTHROPIC_BEDROCK_BASE_URL":"https://llm-gateway.example.invalid/bedrock","CLAUDE_CODE_SKIP_BEDROCK_AUTH":"1","OTEL_EXPORTER_OTLP_HEADERS":"x-honeycomb-team=${HONEYCOMB_KEY}","OPENAPI_MCP_HEADERS":"{\\"Notion-Version\\": \\"2025-09-03\\"}"}}\n|
.claude.json|{"mcpServers":{"sol":{"command":"npx","args":["solana-mcp","--public-key","9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin","--no-auth","server.js"]}}}\n|
.claude/settings.json|{"env":{"ANTHROPIC_BASE_URL":"https://anthropic.helicone.ai/sk-helicone-0a1b2c3-d4e5f6a-b7c8d9e-f0a1b2c"}}\n|Claude Code credentials
.claude/settings.json|{"env":{"SOLANA_RPC_URL":"https://example.solana-mainnet.quiknode.pro/0123456789abcdef0123456789abcdef01234567/"}}\n|Claude Code credentials
.claude/settings.json|{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"https://hooks.example.invalid/services/T0/B0/Xa1b2C3d4E5f6G7h8I9j0K1l"}]}]}}\n|Claude Code credentials
.claude.json|{"mcpServers":{"rpc":{"command":"npx","args":["solana-mcp","--rpc-url","https://x.solana-mainnet.quiknode.pro/0123456789abcdef0123456789abcdef01234567/"]}}}\n|Claude Code credentials
.claude/settings.json|{"env":{"SOLANA_RPC_URL":"https://api.devnet.solana.com","RPC_URL":"https://solana-mainnet.g.alchemy.com/v2/docs-demo"}}\n|
.claude.json|{"mcpServers":{"sol":{"command":"npx","args":["solana-mcp","--rpc-url","https://api.devnet.solana.com"]},"docs":{"type":"http","url":"https://mcp.example.invalid/v1/claude-3-5-sonnet-20241022/sse"},"repo":{"command":"uvx","args":["--from","git+https://github.com/o/solana-mcp-server-2025","x","file:///w/notes-a1b2c3d4e5f6a7b8c9d0"]}}}\n|
CONFIGS
# git's store counts by the file its --file names, when that file is readable: the file counts, not the git
# config, as the code here could read it without git. "~" as a word of its own is the home; the helper may be
# named by an absolute path, and the option by an abbreviation, as git takes it (--fi).
FH="$T/fc-store"; mkdir -p "$FH"; printf 'https://u:t@example.invalid\n' > "$FH/.store-x"; printf 'https://u:t@example.invalid\n' > "$T/store-abs"
printf '[credential]\n\thelper = store --file ~/.store-x\n\thelper = /usr/libexec/git-core/git-credential-store --fi=%s\n' "$T/store-abs" > "$FH/.gitconfig"
code="$(dcreds -- "$FH")"
[ "$code" = 1 ] && lines_are "git or HTTP credentials (2)" "~/.store-x" "$T/store-abs" \
  && ok "git's store counts by the file its --file names when that file is readable" || { bad "git's store with a readable --file: $code"; cat "$T/creds.out" >&2; }
FH="$T/fc-include"; mkdir -p "$FH/.gitconfig.d"
printf '[include]\n\tpath = .gitconfig\n\tpath = .gitconfig.d/more\n[includeIf "gitdir:/nowhere/"]\n\tpath = ~/.gitconfig.d/cond\n' > "$FH/.gitconfig"
printf '[credential]\n\thelper = osxkeychain\n' > "$FH/.gitconfig.d/more"; printf '[core]\n\taskPass = /x\n' > "$FH/.gitconfig.d/cond"
code="$(dcreds -- "$FH")"
[ "$code" = 1 ] && lines_are "git or HTTP credentials (2)" "~/.gitconfig.d/more" "~/.gitconfig.d/cond" \
  && ok "a helper or askpass program in a file a git config includes counts, whatever the includeIf condition, and an include of itself ends" \
  || { bad "git config includes: $code"; cat "$T/creds.out" >&2; }
# What does not count: the public parts of ~/.ssh, a file this user cannot read, an empty file, a FIFO
# (which must not stall the check) and an SSH_AUTH_SOCK that names no socket.
FH="$T/fh-clean"; mkdir -p "$FH/.ssh" "$FH/.aws" "$FH/.kube"
for f in known_hosts known_hosts.old config id_ed25519.pub authorized_keys authorized_keys2; do printf 'public\n' > "$FH/.ssh/$f"; done
: > "$FH/.aws/credentials"; printf 'secret\n' > "$FH/.kube/config"; chmod 000 "$FH/.kube/config"
mkfifo "$FH/.npmrc" 2>/dev/null || true
printf 'x\n' > "$T/not-a-socket"
if [ -r "$FH/.kube/config" ]; then echo "note: cannot drop read permission here (running as root?); the unreadable credential is left out"; rm -f "$FH/.kube/config"; fi
code="$(dcreds SSH_AUTH_SOCK="$T/not-a-socket" -- "$FH")"
[ "$code" = 0 ] && [ -z "$(cat "$T/creds.out")" ] \
  && ok "public ~/.ssh files, an unreadable or empty credential, a FIFO and a non-socket SSH_AUTH_SOCK do not count" || { bad "nothing readable: $code"; cat "$T/creds.out" >&2; }
chmod 600 "$FH/.kube/config" 2>/dev/null || true
FH="$T/fh-link"; mkdir -p "$FH"; printf 'secret\n' > "$T/npmrc-elsewhere"; ln -s "$T/npmrc-elsewhere" "$FH/.npmrc"
code="$(dcreds -- "$FH")"
[ "$code" = 1 ] && lines_are "package registry tokens (1)" "~/.npmrc" && ok "a symbolic link to a readable file counts" || { bad "a linked credential: $code"; cat "$T/creds.out" >&2; }
out="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" GITHUB_TOKEN=x AWS_SECRET_ACCESS_KEY=x HELIUS_API_KEY=x SOLANA_RPC_URL=x \
  DB_PASSWORD=x MAX_MCP_OUTPUT_TOKENS=1 TOKENIZER_PATH=x SSH_AUTH_SOCK=x npm_config__authToken=x "$BASH" "$T/iso-driver.sh" "$ROOT" names)"
[ "$out" = "AWS_SECRET_ACCESS_KEY, DB_PASSWORD, GITHUB_TOKEN, HELIUS_API_KEY, SOLANA_RPC_URL, npm_config__authToken" ] \
  && ok "iso_cred_names names the variables that look like credentials (a name in mixed case too), and no others" || bad "iso_cred_names: '$out'"
# Agent sockets count when they accept a connection: SSH_AUTH_SOCK, sockets in ~/.ssh and ~/.gnupg, in
# GNUPGHOME, ssh-*/agent.* under TMPDIR, and in the runtime directory's gnupg/. So do container daemon sockets
# and the sockets that answer git's credential requests with a login (the one a git cache helper's --socket
# names too), and a container daemon a tcp:// DOCKER_HOST or CONTAINER_HOST reaches. A socket nothing listens
# on does not. Serving one needs a machine that
# allows it: on CI a machine that does not fails the run, and anywhere else one SKIP line says the checks did
# not run. Each socket path stays under 104 bytes, the macOS limit, with the runner's TMPDIR.
SK="$T/k"; mkdir -p "$SK/.ssh" "$SK/.gnupg" "$T/g" "$T/t/ssh-a" "$T/r/gnupg" "$T/q/.ssh"
mkdir -p "$T/H/.docker/run" "$T/H/.colima/x" "$T/H/.rd" "$T/H/.lima/x/sock" "$T/c/git/credential" "$T/t2/podman" "$T/r2/podman"
python3 -I -c 'import socket, sys, time
keep = []
for path in sys.argv[1:]:
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
    s.listen(5)
    keep.append(s)
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(16)
keep.append(s)
with open(sys.argv[1] + "-port", "w") as f:
    f.write("%d" % s.getsockname()[1])
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1] + "-stale")
s.close()
time.sleep(120)' "$T/a" "$SK/.ssh/agent" "$SK/.gnupg/S.gpg-agent" "$T/g/S.gpg-agent.ssh" "$T/t/ssh-a/agent.1" "$T/r/gnupg/S.gpg-agent" \
  "$T/H/.docker/run/docker.sock" "$T/H/.colima/x/docker.sock" "$T/H/.rd/docker.sock" "$T/H/.lima/x/sock/docker.sock" \
  "$T/H/.lima/x/sock/podman.sock" "$T/d.sock" "$T/p.sock" "$T/v.sock" "$T/rc.sock" \
  "$T/c/git/credential/socket" "$T/t2/vscode-git-1.sock" "$T/t2/podman/m.sock" "$T/r2/docker.sock" "$T/r2/podman/podman.sock" \
  "$T/r2/vscode-git-2.sock" 2>/dev/null &
agent=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$T/a-stale" ] && break; kill -0 "$agent" 2>/dev/null || break; sleep 1; done
if [ -S "$T/a-stale" ] && python3 -I -c 'import socket, sys; socket.socket(socket.AF_UNIX).connect(sys.argv[1])' "$T/a" 2>/dev/null; then
  code="$(dcreds SSH_AUTH_SOCK="$T/a" -- "$CLEANHOME")"
  [ "$code" = 1 ] && lines_are "agent sockets (1)" "$T/a (SSH_AUTH_SOCK)" && ok "an SSH_AUTH_SOCK that accepts a connection counts" || { bad "SSH_AUTH_SOCK: $code"; cat "$T/creds.out" >&2; }
  code="$(dcreds SSH_AUTH_SOCK="$T/a-stale" -- "$CLEANHOME")"
  [ "$code" = 0 ] && ok "an SSH_AUTH_SOCK nothing listens on does not count" || { bad "a stale SSH_AUTH_SOCK: $code"; cat "$T/creds.out" >&2; }
  code="$(dcreds GNUPGHOME="$T/g" TMPDIR="$T/t" XDG_RUNTIME_DIR="$T/r" -- "$SK")"
  [ "$code" = 1 ] && lines_are "agent sockets (5)" "~/.ssh/agent" "~/.gnupg/S.gpg-agent" "$T/g/S.gpg-agent.ssh" "$T/t/ssh-a/agent.1" "$T/r/gnupg/S.gpg-agent" \
    && ok "agent sockets in ~/.ssh, ~/.gnupg, GNUPGHOME, TMPDIR/ssh-*/ and the runtime directory count" || { bad "agent sockets: $code"; cat "$T/creds.out" >&2; }
  code="$(dcreds DOCKER_HOST="unix://$T/d.sock" CONTAINER_HOST="unix://$T/p.sock" VSCODE_GIT_IPC_HANDLE="$T/v.sock" \
    REMOTE_CONTAINERS_IPC="$T/rc.sock" XDG_CACHE_HOME="$T/c" TMPDIR="$T/t2" XDG_RUNTIME_DIR="$T/r2" -- "$T/H")"
  [ "$code" = 1 ] && lines_are "container daemon sockets (10), git or HTTP credentials (5)" "~/.docker/run/docker.sock" \
    "~/.colima/x/docker.sock" "~/.rd/docker.sock" "~/.lima/x/sock/docker.sock" "~/.lima/x/sock/podman.sock" "$T/d.sock" "$T/p.sock" \
    "$T/t2/podman/m.sock" "$T/r2/docker.sock" "$T/r2/podman/podman.sock" "$T/v.sock" "$T/rc.sock" "$T/c/git/credential/socket" \
    "$T/t2/vscode-git-1.sock" "$T/r2/vscode-git-2.sock" \
    && ok "container daemon sockets (Docker Desktop, Colima, Rancher Desktop, Lima, DOCKER_HOST, CONTAINER_HOST, rootless, a Podman machine) and the sockets that answer git with a login (VS Code, Dev Containers, git's credential cache) count" \
    || { bad "container daemon and git credential sockets: $code"; cat "$T/creds.out" >&2; }
  printf '[credential]\n\thelper = cache --socket %s\n\thelper = cache --timeout=60 --socket=%s\n' "$T/a" "$T/a-stale" > "$T/q/.gitconfig"
  code="$(dcreds -- "$T/q")"
  [ "$code" = 1 ] && lines_are "git or HTTP credentials (1)" "$T/a" \
    && ok "git's cache counts by the socket its --socket names when that socket accepts a connection, not when nothing listens there" \
    || { bad "git's cache with a --socket: $code"; cat "$T/creds.out" >&2; }
  port="$(cat "$T/a-port" 2>/dev/null)"
  code="$(dcreds DOCKER_HOST="tcp://127.0.0.1:$port" CONTAINER_HOST="tcp://localhost:$port" -- "$CLEANHOME")"
  [ -n "$port" ] && [ "$code" = 1 ] && lines_are "container daemon sockets (2)" "tcp://127.0.0.1:$port" "tcp://localhost:$port" \
    && ok "a tcp:// DOCKER_HOST or CONTAINER_HOST that accepts a TCP connection counts" || { bad "a tcp:// daemon address: $code, port '$port'"; cat "$T/creds.out" >&2; }
  code="$(dcreds DOCKER_HOST="tcp://127.0.0.1:$port" DOCKER_TLS_VERIFY=1 -- "$CLEANHOME")"
  [ "$code" = 0 ] && ok "a tcp:// DOCKER_HOST with DOCKER_TLS_VERIFY set does not count by itself: that daemon takes the TLS client key, which counts" \
    || { bad "a tcp:// DOCKER_HOST with TLS: $code"; cat "$T/creds.out" >&2; }
  code="$(dcreds DOCKER_HOST="unix://$T/a-stale" CONTAINER_HOST="tcp://127.0.0.1:9" -- "$CLEANHOME")"
  [ "$code" = 0 ] && ok "a DOCKER_HOST socket and a tcp:// CONTAINER_HOST nothing listens on do not count" || { bad "a stale DOCKER_HOST: $code"; cat "$T/creds.out" >&2; }
  printf 'isolated\n' > "$WT/audit_1/exec-mode"
  code="$(ngate HOME="$CLEANHOME" SSH_AUTH_SOCK="$T/a" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 3 ] && grep -q '^\[PoC-ATTEMPTED\] blocker: isolated mode, but these are readable here: .*agent sockets (' "$T/out" && new_nothing_ran \
    && ok "isolated mode with an SSH agent that accepts a connection -> exit 3 naming agent sockets" || { bad "isolated, SSH agent: exit $code"; cat "$T/out" >&2; }
  code="$(ngate HOME="$CLEANHOME" DOCKER_HOST="unix://$T/d.sock" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 3 ] && grep -q '^\[PoC-ATTEMPTED\] blocker: isolated mode, but these are readable here: .*container daemon sockets (' "$T/out" && new_nothing_ran \
    && ok "isolated mode with a container daemon socket that accepts a connection -> exit 3 naming container daemon sockets" || { bad "isolated, a container daemon socket: exit $code"; cat "$T/out" >&2; }
  printf 'native\n' > "$WT/audit_1/exec-mode"
  ok "the agent socket checks ran, on Unix sockets this machine serves"
elif [ "${CI:-}" = true ]; then
  bad "the agent socket checks cannot run: this machine does not let the suite serve a Unix socket"
else
  echo "SKIP the agent socket checks did not run: this machine does not let the suite serve a Unix socket (on CI this fails)"
fi
kill "$agent" 2>/dev/null; wait "$agent" 2>/dev/null

# Isolated runs that pass the check, where nothing the check reads is readable on this machine.
printf 'isolated\n' > "$WT/audit_1/exec-mode"
FH="$T/fh-cargo-home"; mkdir -p "$FH" "$T/other-cargo-home"; printf 'token\n' > "$T/other-cargo-home/credentials.toml"
code="$(ngate HOME="$FH" CARGO_HOME="$T/other-cargo-home" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
[ "$code" = 3 ] && grep -q '^\[PoC-ATTEMPTED\] blocker: isolated mode, but these are readable here: .*package registry tokens (' "$T/out" && new_nothing_ran \
  && ok "isolated mode with a readable \$CARGO_HOME/credentials.toml -> exit 3 naming package registry tokens" || { bad "isolated, CARGO_HOME credentials: exit $code"; cat "$T/out" >&2; }
if [ "$ISOLATED_OK" = 1 ]; then
  chmod 000 "$T/fh-clean/.kube/config" 2>/dev/null || true
  code="$(ngate HOME="$T/fh-clean" SSH_AUTH_SOCK="$T/not-a-socket" GITHUB_TOKEN=canary-n1 -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  chmod 600 "$T/fh-clean/.kube/config" 2>/dev/null || true
  [ "$code" = 0 ] && grep -q '^>> execution mode: isolated ' "$T/out" \
    && grep -qxF ">> warning: isolated mode, and these variables of run.sh's own environment look like credentials: GITHUB_TOKEN. No child of run.sh gets them, but code running as this user can read another process's environment (on Linux, in /proc/<pid>/environ) (Rule 11a)" "$T/out" \
    && ok "isolated mode with nothing readable runs, and names the variables of its environment that look like credentials" || { bad "isolated, nothing readable: exit $code"; cat "$T/out" >&2; }
fi
printf 'native\n' > "$WT/audit_1/exec-mode"

# Environment cleaning. Canary variables in the caller's environment reach no cargo call and no test
# binary; neither do the inputs ./run.sh reads from it (here VULNERABLE_SO, KEEP_POC_BUILD, UPDATE_PINS,
# CARGO_TARGET_DIR: the run builds both arms, moves no pin and leaves nothing behind). HOME is the
# throwaway one with a fresh Solana keypair, but for cargo build-sbf --install-only; only cargo fetch and
# that install see the proxy, every build and test after them runs offline; and a cargo on PATH inside
# the working directory never runs. The dyld canary names a fallback path, not an inserted library: on
# a macOS with SIP off, as on the CI runner, dyld acts on DYLD_INSERT_LIBRARIES in the first process
# this starts, and a library that does not exist aborts it before run.sh cleans anything.
mkdir -p "$WT/.bin"; printf '#!/bin/sh\necho ran > "%s"\nexit 0\n' "$T/wt-cargo.marker" > "$WT/.bin/cargo"; chmod +x "$WT/.bin/cargo"
: > "$T/canary-v17"
SHIM_EXTRA=(SHIM_WALLET_COPY="$T/wallet")
rm -f "$T"/wallet.* "$T/wt-cargo.marker"
code="$(ngate PATH="$WT/.bin:$SP" AUDITOR_CANARY=canary-v01 GITHUB_TOKEN=canary-v02 RPC_URL=https://rpc.invalid/canary-v03 \
  AWS_SECRET_ACCESS_KEY=canary-v04 CARGO_REGISTRY_TOKEN=canary-v05 SSH_AUTH_SOCK="$T/canary-v06.sock" RUSTC_WRAPPER="$T/canary-v07" \
  RUSTFLAGS=--cfg=canary_v08 CARGO_BUILD_RUSTC_WRAPPER="$T/canary-v09" GIT_SSH_COMMAND=canary-v10 CARGO_TARGET_DIR="$T/canary-v11" \
  CARGO_BUILD_TARGET_DIR="$T/canary-v12" BPF_OUT_DIR="$T/canary-v13" RUSTC="$T/canary-v14" LD_PRELOAD="$T/canary-v15.so" \
  DYLD_FALLBACK_FRAMEWORK_PATH="$T/canary-v16" BASH_ENV="$T/canary-v17" XDG_CONFIG_HOME="$T/canary-v18" GH_TOKEN=canary-v19 \
  HTTPS_PROXY=http://proxy.invalid:3128 VULNERABLE_SO="$T/vuln.so" KEEP_POC_BUILD=1 UPDATE_PINS=borsh -- --crate audit_1/poc/F-1)"
SHIM_EXTRA=()
bd="$(new_build_dir)"
[ "$code" = 0 ] && grep -q "building 'vulnerable' arm" "$T/out" && grep -q '^OK: exploit reproduces' "$T/out" \
  && ok "the environment's VULNERABLE_SO is not read: the run builds the crate's own arms" || { bad "environment cleaning run: exit $code"; cat "$T/out" >&2; }
[ -s "$T/envdump" ] && ! grep -q canary "$T/envdump" && ok "no canary variable reaches any cargo call or test binary" || { bad "a canary reached a child"; grep -n canary "$T/envdump" >&2; }
[ -n "$bd" ] && [ ! -e "$bd" ] && [ -z "$(ls -A "$NT")" ] && ok "the environment's KEEP_POC_BUILD is not read: the scratch copy is gone" || bad "KEEP_POC_BUILD from the environment kept '$bd'"
! awk -F'\t' '$6 ~ /^update / { f = 1 } END { exit !f }' "$T/calls" && ok "the environment's UPDATE_PINS is not read: no cargo update" || bad "UPDATE_PINS from the environment ran cargo update"
none_in_blocks '.' '^CARGO_TARGET_DIR=' && [ ! -e "$T/canary-v11" ] && ok "the environment's CARGO_TARGET_DIR reaches no child" || bad "CARGO_TARGET_DIR reached a child"
in_blocks '^== (cargo (metadata|fetch|test|build-sbf --skip-tools-install)|testbin)' "^HOME=$bd/markers/home\$" \
  && in_blocks '^== cargo build-sbf --install-only' "^HOME=$CLEANHOME\$" \
  && ok "HOME is the throwaway $bd/markers/home, but for cargo build-sbf --install-only, which installs the tools in the real one" || { bad "HOME in the children"; grep -n '^== \|^HOME=' "$T/envdump" >&2; }
in_blocks '.' "^TMPDIR=$bd/markers/tmp\$" && in_blocks '.' '^LC_ALL=C$' && none_in_blocks '.' '^SBF_OUT_DIR=$' \
  && in_blocks '^== (cargo (build-sbf|test)|testbin)' "^SBF_OUT_DIR=$bd/target/deploy\$" \
  && ok "every child gets TMPDIR in the scratch copy, LC_ALL=C and the SBF_OUT_DIR run.sh set" || { bad "TMPDIR, LC_ALL or SBF_OUT_DIR in the children"; cat "$T/envdump" >&2; }
in_blocks '^== cargo (fetch|build-sbf --install-only)' '^HTTPS_PROXY=http://proxy.invalid:3128$' \
  && none_in_blocks '^== (testbin|cargo (metadata|test|build-sbf --help|build-sbf --skip-tools-install))' '^HTTPS_PROXY=' \
  && ok "the proxy reaches cargo fetch and the platform-tools install, never a build, a test or cargo metadata" || { bad "proxy variables in the children"; grep -n '^== \|PROXY' "$T/envdump" >&2; }
steps="$(awk -F'\t' '{ split($6, a, " "); s = a[1] } s == "build-sbf" { s = ($6 ~ /--install-only/) ? "install" : ($6 ~ /--help/) ? "help" : ($6 ~ /^build-sbf --skip-tools-install --offline /) ? "arm" : "other" }
  s == "test" { s = ($6 ~ /^test --offline /) ? "test" : "other" } s != "metadata" && s != "testbin" { printf "%s ", s }' "$T/calls")"
[ "$steps" = "fetch help install arm test arm test " ] && in_blocks '^== cargo build-sbf --skip-tools-install' '^CARGO_NET_OFFLINE=true$' \
  && ok "cargo fetch first, then the install, then each arm built with --skip-tools-install --offline and tested with --offline" || { bad "the build steps: '$steps'"; cat "$T/calls" >&2; }
none_in_blocks '.' "$WT/.bin" && [ ! -e "$T/wt-cargo.marker" ] && ok "a cargo on PATH inside the working directory never runs, and that PATH entry reaches no child" || bad "PATH inside the working directory"
w="$T/wallet.exploit"
if [ -f "$w" ] && python3 -I -c 'import json, sys; k = json.load(open(sys.argv[1])); sys.exit(not (isinstance(k, list) and len(k) == 64 and all(isinstance(b, int) and 0 <= b < 256 for b in k)))' "$w"; then
  ok "the test binary's HOME holds a throwaway Solana keypair, 64 bytes as solana-keygen writes it"
  if command -v solana-keygen >/dev/null 2>&1 && pub="$(solana-keygen pubkey "$w" 2>/dev/null)"; then
    solana-keygen verify "$pub" "$w" >/dev/null 2>&1 && ok "solana-keygen verifies the throwaway keypair ($pub)" || bad "solana-keygen does not verify the throwaway keypair"
  fi
else
  bad "no throwaway keypair in the test binary's HOME"
fi
rm -rf "$WT/.bin"

# A cargo build-sbf whose --help lists none of --install-only, --skip-tools-install and --offline builds
# each arm as before, with the real HOME and the proxy, and says so; an install or a fetch that fails is a
# blocker before any arm builds.
SHIM_EXTRA=(SHIM_SBF_HELP=old)
code="$(ngate HTTPS_PROXY=http://proxy.invalid:3128 -- --crate audit_1/poc/F-1)"
SHIM_EXTRA=()
[ "$code" = 0 ] && grep -qxF ">> this cargo build-sbf has no --install-only, --skip-tools-install or --offline: each arm builds with the real HOME and the proxy variables" "$T/out" \
  && in_blocks '^== cargo build-sbf --tools-version' "^HOME=$CLEANHOME\$" && in_blocks '^== cargo build-sbf --tools-version' '^HTTPS_PROXY=http://proxy.invalid:3128$' \
  && ! awk -F'\t' '$6 ~ /^build-sbf --install-only/ { f = 1 } END { exit !f }' "$T/calls" \
  && ok "a cargo build-sbf without --install-only and --skip-tools-install -> each arm builds as before, and run.sh says so" || { bad "an older cargo build-sbf: exit $code"; cat "$T/out" >&2; }
# The README every PoC crate carries says so too, next to the cleaning it describes.
python3 -I -c 'import re, sys; text = re.sub(r"\s+", " ", open(sys.argv[1], encoding="utf-8").read()); sys.exit(sys.argv[2] not in text)' "$ROOT/templates/poc/README.md" \
  'A `cargo build-sbf` that lacks any of `--install-only`, `--skip-tools-install` and `--offline` (an older Agave release) cannot split the install from the build: with it, each arm builds with the real `HOME` and the proxy variables, and `run.sh` prints a line saying so' \
  && ok "the template's README says an older cargo build-sbf builds each arm with the real HOME and the proxy variables" || bad "the template's README does not state the older cargo build-sbf fallback"
for spec in 'install-only|cargo build-sbf --install-only could not install the platform tools v1.54' 'fetch|cargo fetch could not download the crate'"'"'s dependencies'; do
  SHIM_EXTRA=(SHIM_FAIL="${spec%%|*}")
  code="$(ngate -- --crate audit_1/poc/F-1)"
  SHIM_EXTRA=()
  [ "$code" = 3 ] && grep -qF "[PoC-ATTEMPTED] blocker: ${spec#*|} — see the cargo output above." "$T/out" && one_blocker \
    && ! awk -F'\t' '$6 ~ /^(build-sbf --skip|build-sbf --tools|test |testbin )/ { f = 1 } END { exit !f }' "$T/calls" \
    && ok "a failed ${spec%%|*} -> exit 3 before any arm builds" || { bad "a failed ${spec%%|*}: exit $code"; cat "$T/out" >&2; }
done

# The resolved Cargo.lock comes back into the crate in place of a regular file only: a symbolic link
# planted there while the test ran is left as it is, and its target untouched.
printf 'kept\n' > "$T/lock-target"
SHIM_EXTRA=(SHIM_MARKERS="$EV exploit:relink" SHIM_RELINK="$WT/audit_1/poc/F-1/Cargo.lock" SHIM_RELINK_TO="$T/lock-target")
code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
SHIM_EXTRA=()
[ "$code" = 0 ] && [ -L "$WT/audit_1/poc/F-1/Cargo.lock" ] && [ "$(cat "$T/lock-target")" = kept ] \
  && ok "a Cargo.lock that became a symbolic link during the run is not written through" || { bad "Cargo.lock link: exit $code"; cat "$T/out" >&2; }
rm -f "$WT/audit_1/poc/F-1/Cargo.lock"
code="$(ngate -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
[ "$code" = 0 ] && [ -f "$WT/audit_1/poc/F-1/Cargo.lock" ] && [ ! -L "$WT/audit_1/poc/F-1/Cargo.lock" ] && [ -z "$(ls -a "$WT/audit_1/poc/F-1" | grep '^\.Cargo\.lock\.')" ] \
  && ok "the resolved Cargo.lock comes back into the crate, with no temporary file left" || { bad "Cargo.lock back into the crate: exit $code"; cat "$T/out" >&2; }

# Prebuilt bytes from incident_1/bin, a cache, a pin and --keep: the arguments become the inputs.
code="$(ngate -- --crate audit_1/poc/F-1 --vulnerable-so incident_1/bin/program.so "${NFIX[@]}" --update-pins 'solana-program@3.0.0 borsh' --keep)"
bd="$(new_build_dir)"
if [ "$code" = 0 ] && grep -qx "${LEG3}${want} fixed sha256=${wantf} (rejected with the pinned error) → \[PoC-REPRODUCED\]" "$T/out" \
   && awk -F'\t' '$6 ~ /^update / { u++ } END { exit !(u == 2) }' "$T/calls" && [ -n "$bd" ] && [ -d "$bd" ]; then
  ok "--vulnerable-so incident_1/bin/…, --fixed-so audit_1/exec/…, --update-pins and --keep -> the Leg 3 line, two pins moved, the scratch copy kept"
else
  bad "arguments as inputs: exit $code"; cat "$T/out" >&2
fi
[ -n "$bd" ] && rm -rf "$bd"

# An incident's crate runs only once incident_<n>/INCIDENTS.json records its root_cause_class: a file, an
# incident or a class that cannot be read stops the run before anything is copied. supply_chain_or_ci
# refuses native mode and a run without --vulnerable-so; in isolated mode it refuses a dependency on a path
# outside the crate or on git, a target built from outside the crate, and a build that compiled code from
# outside the crate, before its test runs.
mk_crate "$WT/incident_1/poc/INC-1.1"
IJ="$WT/incident_1/INCIDENTS.json"
IVULN=(--vulnerable-so incident_1/bin/program.so)
incidents() {  # incidents <class> [<id>...]: an INCIDENTS.json whose incidents have those ids (INC-1.1 by default) and that class
  local class="$1" id sep="" list=""
  shift
  [ $# -gt 0 ] || set -- INC-1.1
  for id in "$@"; do list="$list$sep{\"id\": \"$id\", \"verdict\": \"confirmed_exploited\", \"root_cause_class\": \"$class\"}"; sep=", "; done
  printf '{"schema": "auditor-incidents/1", "target": "t", "incidents": [%s]}\n' "$list" > "$IJ"
}
while IFS='|' read -r how reason; do
  [ -n "$how" ] || continue
  rm -rf "$IJ"
  case "$how" in
    missing) ;;
    directory) mkdir "$IJ" ;;
    not-json) printf '{"incidents": [\n' > "$IJ" ;;
    no-list) printf '{"incidents": {"id": "INC-1.1"}}\n' > "$IJ" ;;
    not-object) printf '{"incidents": ["INC-1.1", {"id": "INC-1.1", "root_cause_class": "code_flaw"}]}\n' > "$IJ" ;;
    other) incidents code_flaw INC-1.2 ;;
    twice) incidents code_flaw INC-1.1 INC-1.1 ;;
    bad-class) incidents bogus ;;
    no-class) printf '{"incidents": [{"id": "INC-1.1"}]}\n' > "$IJ" ;;
    nested) python3 -I -c 'import sys; open(sys.argv[1], "w").write("[" * 200000 + "]" * 200000)' "$IJ" ;;
    large) python3 -I -c 'import sys; open(sys.argv[1], "w").write("{\"incidents\": []}" + " " * (4 * 1024 * 1024))' "$IJ" ;;
  esac
  code="$(ngate AUDITOR_EXEC_MODE=native -- --crate incident_1/poc/INC-1.1 "${IVULN[@]}")"
  [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: incident_1/INCIDENTS.json $reason: an incident's PoC runs only once incident_1/INCIDENTS.json records its root_cause_class (OUTPUT-RULES.md Rule 11a, references/detection-response/incidents-schema.md) — nothing was copied or built." "$T/out" \
    && new_nothing_ran && one_blocker && ok "an incident crate with an INCIDENTS.json that $reason -> exit 3, nothing copied" || { bad "INCIDENTS.json $how: exit $code"; cat "$T/out" >&2; }
done <<'CASES'
missing|is missing
directory|is not a regular file
not-json|cannot be read as JSON
no-list|holds no incidents list
not-object|holds an incident that is not an object
other|records no incident INC-1.1
twice|records INC-1.1 more than once
bad-class|gives INC-1.1 no root_cause_class from incidents-schema.md
no-class|gives INC-1.1 no root_cause_class from incidents-schema.md
nested|cannot be read as JSON
large|is larger than 4 MiB
CASES
rm -rf "$IJ"; incidents code_flaw
code="$(ngate AUDITOR_EXEC_MODE=native -- --crate incident_1/poc/INC-1.1 "${IVULN[@]}")"
[ "$code" = 0 ] && grep -qxF '>> incident INC-1.1: root_cause_class code_flaw (incident_1/INCIDENTS.json)' "$T/out" && grep -q "^$LEG3" "$T/out" \
  && ok "an incident crate whose root_cause_class is code_flaw runs on its dumped bytes, and says so" || { bad "incident, code_flaw: exit $code"; cat "$T/out" >&2; }
code="$(ngate AUDITOR_EXEC_MODE=native -- --crate incident_1/poc/INC-1.1)"
[ "$code" = 0 ] && grep -q '^OK: exploit reproduces' "$T/out" && ok "an incident crate whose root_cause_class is code_flaw may run its own arms" || { bad "incident, code_flaw, a model run: exit $code"; cat "$T/out" >&2; }
incidents supply_chain_or_ci
code="$(ngate AUDITOR_EXEC_MODE=native -- --crate incident_1/poc/INC-1.1 "${IVULN[@]}")"
[ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: the root_cause_class of INC-1.1 is supply_chain_or_ci, and such an incident is never built natively (OUTPUT-RULES.md Rule 11a); run it in isolated mode — nothing was copied or built." "$T/out" \
  && new_nothing_ran && one_blocker && ok "supply_chain_or_ci in native mode -> exit 3, nothing copied" || { bad "supply_chain_or_ci, native: exit $code"; cat "$T/out" >&2; }
code="$(ngate AUDITOR_EXEC_MODE=isolated -- --crate incident_1/poc/INC-1.1)"
[ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: the root_cause_class of INC-1.1 is supply_chain_or_ci, so its PoC runs only on the dumped program bytes (OUTPUT-RULES.md Rule 11a): give --vulnerable-so incident_1/bin/<program>.so — nothing was copied or built." "$T/out" \
  && new_nothing_ran && one_blocker && ok "supply_chain_or_ci without --vulnerable-so -> exit 3, nothing copied" || { bad "supply_chain_or_ci, a model run: exit $code"; cat "$T/out" >&2; }
# A run directory whose INCIDENTS.json records a supply_chain_or_ci incident builds none of its incident
# crates natively, another incident's included: each builds from the same target tree. Native mode stops
# before anything is copied, and so it does when another incident's class cannot be read; isolated mode
# runs.
mk_crate "$WT/incident_1/poc/INC-1.2"
for how in supply_chain_or_ci bogus; do
  printf '{"incidents": [{"id": "INC-1.1", "root_cause_class": "%s"}, {"id": "INC-1.2", "root_cause_class": "code_flaw"}]}\n' "$how" > "$IJ"
  want_dc="incident_1/INCIDENTS.json records an incident whose root_cause_class is supply_chain_or_ci, so nothing from this working directory is built natively, for an audit run or an incident run (OUTPUT-RULES.md Rule 11a); run it in isolated mode — nothing was copied or built."
  [ "$how" = bogus ] && want_dc="incident_1/INCIDENTS.json gives an incident no root_cause_class from incidents-schema.md: nothing from this working directory is built natively until every incident_*/INCIDENTS.json in it records the root_cause_class of each of its incidents (OUTPUT-RULES.md Rule 11a, references/detection-response/incidents-schema.md) — nothing was copied or built."
  code="$(ngate AUDITOR_EXEC_MODE=native -- --crate incident_1/poc/INC-1.2 "${IVULN[@]}")"
  [ "$code" = 3 ] && grep -qxF '>> incident INC-1.2: root_cause_class code_flaw (incident_1/INCIDENTS.json)' "$T/out" \
    && grep -qxF "[PoC-ATTEMPTED] blocker: $want_dc" "$T/out" && new_nothing_ran && one_blocker \
    && ok "a code_flaw incident's crate in native mode, beside an incident whose class is $how -> exit 3, nothing copied" \
    || { bad "a code_flaw incident's crate beside one whose class is $how, native: exit $code"; cat "$T/out" >&2; }
done
if [ "$ISOLATED_OK" = 1 ]; then
  printf '{"incidents": [{"id": "INC-1.1", "root_cause_class": "supply_chain_or_ci"}, {"id": "INC-1.2", "root_cause_class": "code_flaw"}]}\n' > "$IJ"
  code="$(ngate AUDITOR_EXEC_MODE=isolated -- --crate incident_1/poc/INC-1.2 "${IVULN[@]}")"
  [ "$code" = 0 ] && grep -q "^$LEG3" "$T/out" && ok "a code_flaw incident's crate beside a supply_chain_or_ci incident runs in isolated mode" || { bad "a code_flaw incident's crate beside a supply_chain_or_ci one, isolated: exit $code"; cat "$T/out" >&2; }
fi
# That refusal reads iso_incident_class (scripts/lib/isolation.sh) with no incident id, which must print
# supply_chain_or_ci when any incident has that class, wherever it sits in the list, and other when none does,
# and return 3 with the reason when a class cannot be read. A change to that form would undo the refusal
# without a word, so it is pinned here, on its own and through run.sh: a code_flaw incident's crate is refused
# natively beside a supply_chain_or_ci incident listed after it, and runs beside every other class.
cat > "$T/class-driver.sh" <<'SH'
root=$1; shift
. "$root/scripts/lib/confine.sh" && . "$root/scripts/lib/isolation.sh" || exit 9
confine_init class-driver "$root"
rc=0; iso_incident_class "$@" || rc=$?
printf '%s %s\n' "$rc" "$ISO_CLASS"
SH
class_list() {  # class_list <class>...: an INCIDENTS.json whose incidents INC-1.1, INC-1.2, ... have those classes
  local class list="" sep="" n=0
  for class in "$@"; do n=$((n + 1)); list="$list$sep{\"id\": \"INC-1.$n\", \"root_cause_class\": \"$class\"}"; sep=", "; done
  printf '{"incidents": [%s]}\n' "$list" > "$IJ"
}
while IFS='|' read -r pin_classes pin_says; do
  [ -n "$pin_classes" ] || continue
  class_list $pin_classes
  pin_got="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" bash "$T/class-driver.sh" "$ROOT" "$IJ" 2>&1)"
  [ "$pin_got" = "$pin_says" ] && ok "iso_incident_class with no id, incidents of class $pin_classes -> '$pin_says'" || bad "iso_incident_class with no id, $pin_classes: '$pin_got', want '$pin_says'"
done <<'CASES'
code_flaw key_compromise oracle_or_dependency economic_design off_chain unknown|0 other
code_flaw key_compromise supply_chain_or_ci|0 supply_chain_or_ci
supply_chain_or_ci code_flaw|0 supply_chain_or_ci
code_flaw bogus|3 gives an incident no root_cause_class from incidents-schema.md
CASES
class_list key_compromise code_flaw supply_chain_or_ci
code="$(ngate AUDITOR_EXEC_MODE=native -- --crate incident_1/poc/INC-1.2 "${IVULN[@]}")"
[ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: incident_1/INCIDENTS.json records an incident whose root_cause_class is supply_chain_or_ci, so nothing from this working directory is built natively, for an audit run or an incident run (OUTPUT-RULES.md Rule 11a); run it in isolated mode — nothing was copied or built." "$T/out" \
  && new_nothing_ran && one_blocker && ok "a code_flaw incident's crate in native mode, beside a supply_chain_or_ci incident listed after it -> exit 3, nothing copied" \
  || { bad "a code_flaw incident's crate before a supply_chain_or_ci one, native: exit $code"; cat "$T/out" >&2; }
class_list key_compromise code_flaw oracle_or_dependency economic_design off_chain unknown
code="$(ngate AUDITOR_EXEC_MODE=native -- --crate incident_1/poc/INC-1.2 "${IVULN[@]}")"
[ "$code" = 0 ] && grep -q "^$LEG3" "$T/out" && ok "a code_flaw incident's crate beside an incident of every other class runs in native mode" \
  || { bad "a code_flaw incident's crate beside the other classes, native: exit $code"; cat "$T/out" >&2; }
# Native mode counts an INCIDENTS.json that records no incident (a hunt that ruled everything out) for nothing,
# by the no-id form's 'records no incident'; any other reason stops the run.
printf '{"incidents": []}\n' > "$T/ij-empty.json"
pin_got="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" bash "$T/class-driver.sh" "$ROOT" "$T/ij-empty.json" 2>&1)"
rm -f "$T/ij-empty.json"
[ "$pin_got" = "3 records no incident" ] && ok "iso_incident_class with no id, an empty incidents list -> '3 records no incident'" || bad "iso_incident_class with no id, an empty incidents list: '$pin_got', want '3 records no incident'"

# Native mode reads the INCIDENTS.json of every incident_* directory in the working directory, whichever run
# directory the crate is in: while one records a supply_chain_or_ci incident or cannot be read, nothing from
# the working directory is built natively, an audit's crate included, since any PoC can build the target's
# crates. A directory without that file, or whose file records no incident, counts for nothing; one that
# cannot be searched is read, and a linked one is read through. Isolated mode reads none of them.
( cd "$WT" && "$ROOT/scripts/rundir.sh" new incident ) >/dev/null || bad "rundir.sh could not make incident_2"
IJ2="$WT/incident_2/INCIDENTS.json"
want_sc="records an incident whose root_cause_class is supply_chain_or_ci, so nothing from this working directory is built natively, for an audit run or an incident run (OUTPUT-RULES.md Rule 11a); run it in isolated mode — nothing was copied or built."
want_un="nothing from this working directory is built natively until every incident_*/INCIDENTS.json in it records the root_cause_class of each of its incidents (OUTPUT-RULES.md Rule 11a, references/detection-response/incidents-schema.md) — nothing was copied or built."
printf '{"incidents": [{"id": "INC-2.1", "root_cause_class": "supply_chain_or_ci"}]}\n' > "$IJ2"
code="$(ngate AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
[ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: incident_2/INCIDENTS.json $want_sc" "$T/out" && new_nothing_ran && one_blocker \
  && ok "an audit's crate in native mode while another run directory's INCIDENTS.json records a supply_chain_or_ci incident -> exit 3, nothing copied" \
  || { bad "an audit's crate beside incident_2's supply_chain_or_ci incident, native: exit $code"; cat "$T/out" >&2; }
code="$(ngate AUDITOR_EXEC_MODE=native -- --crate incident_1/poc/INC-1.2 "${IVULN[@]}")"
[ "$code" = 3 ] && grep -qxF '>> incident INC-1.2: root_cause_class code_flaw (incident_1/INCIDENTS.json)' "$T/out" \
  && grep -qxF "[PoC-ATTEMPTED] blocker: incident_2/INCIDENTS.json $want_sc" "$T/out" && new_nothing_ran && one_blocker \
  && ok "an incident's crate in native mode while another incident run directory records a supply_chain_or_ci incident -> exit 3, nothing copied" \
  || { bad "INC-1.2 beside incident_2's supply_chain_or_ci incident, native: exit $code"; cat "$T/out" >&2; }
while IFS='|' read -r how reason; do
  [ -n "$how" ] || continue
  rm -rf "$IJ2"
  case "$how" in
    not-json) printf '{"incidents": [\n' > "$IJ2" ;;
    bad-class) printf '{"incidents": [{"id": "INC-2.1", "root_cause_class": "code_flaw"}, {"id": "INC-2.2", "root_cause_class": "bogus"}]}\n' > "$IJ2" ;;
    no-list) printf '{"incidents": {"id": "INC-2.1"}}\n' > "$IJ2" ;;
    directory) mkdir "$IJ2" ;;
    link) printf '{"incidents": [{"id": "INC-2.1", "root_cause_class": "code_flaw"}]}\n' > "$T/ij2-target.json"; ln -s "$T/ij2-target.json" "$IJ2" ;;
  esac
  code="$(ngate AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: incident_2/INCIDENTS.json $reason: $want_un" "$T/out" \
    && new_nothing_ran && one_blocker && ok "an audit's crate in native mode while incident_2/INCIDENTS.json $reason -> exit 3, nothing copied" \
    || { bad "an audit's crate beside incident_2/INCIDENTS.json ($how), native: exit $code"; cat "$T/out" >&2; }
done <<'CASES'
not-json|cannot be read as JSON
bad-class|gives an incident no root_cause_class from incidents-schema.md
no-list|holds no incidents list
directory|is not a regular file
link|is not a regular file
CASES
rm -rf "$IJ2" "$T/ij2-target.json"
if [ "$(id -u)" != 0 ]; then
  printf '{"incidents": [{"id": "INC-2.1", "root_cause_class": "code_flaw"}]}\n' > "$IJ2"; chmod 000 "$WT/incident_2"
  code="$(ngate AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  chmod 700 "$WT/incident_2"; rm -f "$IJ2"
  [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: incident_2/INCIDENTS.json cannot be read: $want_un" "$T/out" \
    && new_nothing_ran && one_blocker && ok "an audit's crate in native mode beside an incident_* directory that cannot be searched -> exit 3, nothing copied" \
    || { bad "an audit's crate beside an unsearchable incident_2, native: exit $code"; cat "$T/out" >&2; }
fi
for how in absent empty; do
  rm -f "$IJ2"; [ "$how" = empty ] && printf '{"schema": "auditor-incidents/1", "incidents": [], "ruled_out": []}\n' > "$IJ2"
  code="$(ngate AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 0 ] && grep -q "^$LEG3" "$T/out" && ok "an audit's crate in native mode beside an incident_* directory whose INCIDENTS.json is $how runs" \
    || { bad "an audit's crate beside incident_2 with an INCIDENTS.json that is $how, native: exit $code"; cat "$T/out" >&2; }
done
rm -f "$IJ2"
mkdir -p "$T/elsewhere-run" "$WT/incident_old"
printf '{"incidents": [{"id": "INC-3.1", "root_cause_class": "supply_chain_or_ci"}]}\n' > "$T/elsewhere-run/INCIDENTS.json"
cp "$T/elsewhere-run/INCIDENTS.json" "$WT/incident_old/INCIDENTS.json"
for odd in incident_old incident_3; do
  [ "$odd" = incident_3 ] && { rm -rf "$WT/incident_old"; ln -s "$T/elsewhere-run" "$WT/incident_3"; }
  code="$(ngate AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: $odd/INCIDENTS.json $want_sc" "$T/out" && new_nothing_ran && one_blocker \
    && ok "an audit's crate in native mode beside $odd/ ($([ "$odd" = incident_3 ] && echo a link to a directory outside || echo a directory)) whose INCIDENTS.json records a supply_chain_or_ci incident -> exit 3" \
    || { bad "an audit's crate beside $odd/, native: exit $code"; cat "$T/out" >&2; }
done
rm -f "$WT/incident_3"
if [ "$ISOLATED_OK" = 1 ]; then
  printf '{"incidents": [{"id": "INC-2.1", "root_cause_class": "supply_chain_or_ci"}]}\n' > "$IJ2"
  code="$(ngate AUDITOR_EXEC_MODE=isolated -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 0 ] && grep -q "^$LEG3" "$T/out" && ok "an audit's crate beside another run directory's supply_chain_or_ci incident runs in isolated mode" \
    || { bad "an audit's crate beside incident_2's supply_chain_or_ci incident, isolated: exit $code"; cat "$T/out" >&2; }
fi
# Only python3 tells that an INCIDENTS.json is missing, so a stat that fails for another reason stops the run:
# a path past PATH_MAX (1024 bytes on macOS, 4096 on Linux) hides no run directory. In a working directory
# PATH_MAX-22 bytes long incident_1/INCIDENTS.json lies past it (a model run there, since a --vulnerable-so
# path would too); in one PATH_MAX-200 bytes long, a run moved aside under a long name, whose INCIDENTS.json (a
# name of 190 bytes) or which itself (230) lies past it. Each file is written through a relative path and
# records a supply_chain_or_ci incident. The incident_* directories are read in any letter case, since a volume
# that ignores case finds incident_2 under INCIDENT_2, and a working directory that cannot be listed stops the
# run too.
PM="$(getconf PATH_MAX / 2>/dev/null)"
case "$PM" in ''|*[!0-9]*) PM=1024 ;; esac
long() { printf '%*s' "$1" '' | tr ' ' "$2"; }
deep_dir() {  # deep_dir <length>: prints a new directory below $T whose physical path is <length> bytes, holding audit_1 (exec-mode native)
  local cur c
  mkdir "$T/deep-$1" && cd "$T/deep-$1" || return 1
  cur="$(pwd -P)"
  while [ $(( ${#cur} + 201 )) -lt "$1" ]; do
    c="d$(long 199 0)"; mkdir "$c" && cd "$c" || return 1; cur="$(pwd -P)"
  done
  c="e$(long $(( $1 - ${#cur} - 2 )) 0)"; mkdir "$c" && cd "$c" || return 1
  mkdir -p audit_1/poc/F-1 && printf '*\n' > audit_1/.gitignore && printf 'native\n' > audit_1/exec-mode
  pwd -P
}
dgate() {  # dgate <dir> [VAR=val ...] -- <argument>...: ngate, from <dir> in place of $WT
  local dir="$1"; shift
  rm -rf "$T/calls" "$T/calls.env" "$T/envdump" "$NT"; mkdir -p "$NT"
  shim_settings SHIM_CALLS="$T/calls" SHIM_ENV_DUMP="$T/envdump" ${SHIM_EXTRA[@]+"${SHIM_EXTRA[@]}"}
  nrun "$dir" "$@"
}
SCJ='{"incidents": [{"id": "INC-1.1", "root_cause_class": "supply_chain_or_ci"}]}'
if DW="$(deep_dir $((PM - 22)))" && [ "${#DW}" = $((PM - 22)) ]; then
  ( cd "$DW" && mkdir incident_1 && printf '*\n' > incident_1/.gitignore && printf '%s\n' "$SCJ" > incident_1/INCIDENTS.json )
  code="$(dgate "$DW" AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1)"
  [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: incident_1/INCIDENTS.json cannot be read: $want_un" "$T/out" && new_nothing_ran && one_blocker \
    && ok "an audit's crate in native mode, in a working directory of $((PM - 22)) bytes whose incident_1/INCIDENTS.json lies past PATH_MAX ($PM) -> exit 3, nothing copied" \
    || { bad "an audit's crate beside an incident_1/INCIDENTS.json past PATH_MAX, native: exit $code"; cat "$T/out" >&2; }
else
  bad "no working directory of $((PM - 22)) bytes could be made below $T"
fi
if DW="$(deep_dir $((PM - 200)))" && [ "${#DW}" = $((PM - 200)) ]; then
  mk_crate "$DW/audit_1/poc/F-1"
  mkdir -p "$DW/audit_1/exec/build-sbf-1" && cp "$T/vuln.so" "$T/fixed.so" "$DW/audit_1/exec/build-sbf-1/"
  n2="incident_1.$(long 179 x)"; n3="incident_1.$(long 219 y)"
  ( cd "$DW" && mkdir "$n2" && printf '%s\n' "$SCJ" > "$n2/INCIDENTS.json" )
  code="$(dgate "$DW" AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: $n2/INCIDENTS.json cannot be read: $want_un" "$T/out" && new_nothing_ran && one_blocker \
    && ok "an audit's crate in native mode beside a run moved aside under a name of 190 bytes, its INCIDENTS.json past PATH_MAX -> exit 3, nothing copied" \
    || { bad "an audit's crate beside a long-named run whose INCIDENTS.json lies past PATH_MAX, native: exit $code"; cat "$T/out" >&2; }
  ( cd "$DW" && mv "$n2" "$n3" )
  code="$(dgate "$DW" AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: ${n3:0:200}.../INCIDENTS.json cannot be read: $want_un" "$T/out" && new_nothing_ran && one_blocker \
    && ok "... and under a name of 230 bytes, the run itself past PATH_MAX -> exit 3, the name cut after 200 bytes" \
    || { bad "an audit's crate beside a run whose own path lies past PATH_MAX, native: exit $code"; cat "$T/out" >&2; }
  ( cd "$DW" && rm -rf "$n3" )
  code="$(dgate "$DW" AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
  [ "$code" = 0 ] && grep -q "^$LEG3" "$T/out" && ok "... and with that run gone the same crate runs" \
    || { bad "an audit's crate in a working directory of $((PM - 200)) bytes, native: exit $code"; cat "$T/out" >&2; }
  for spelled in INCIDENT_2 Incident_2; do
    ( cd "$DW" && mkdir "$spelled" && printf '%s\n' "$SCJ" > "$spelled/INCIDENTS.json" )
    code="$(dgate "$DW" AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
    ( cd "$DW" && rm -rf "$spelled" )
    [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: $spelled/INCIDENTS.json $want_sc" "$T/out" && new_nothing_ran && one_blocker \
      && ok "an audit's crate in native mode beside a run spelled $spelled whose INCIDENTS.json records a supply_chain_or_ci incident -> exit 3, nothing copied" \
      || { bad "an audit's crate beside $spelled/, native: exit $code"; cat "$T/out" >&2; }
  done
  if [ "$(id -u)" != 0 ]; then
    ( cd "$DW" && mkdir incident_1 && printf '%s\n' "$SCJ" > incident_1/INCIDENTS.json )
    chmod 300 "$DW"
    code="$(dgate "$DW" AUDITOR_EXEC_MODE=native -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
    chmod 700 "$DW"
    [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: the working directory cannot be listed: $want_un" "$T/out" && new_nothing_ran && one_blocker \
      && ok "an audit's crate in native mode in a working directory that cannot be listed -> exit 3, nothing copied" \
      || { bad "an audit's crate in a working directory that cannot be listed, native: exit $code"; cat "$T/out" >&2; }
  fi
else
  bad "no working directory of $((PM - 200)) bytes could be made below $T"
fi
rm -rf "$WT/incident_2" "$T/elsewhere-run" "$T/deep-$((PM - 22))" "$T/deep-$((PM - 200))"
rm -rf "$WT/incident_1/poc/INC-1.2"; incidents supply_chain_or_ci
# The crate check on its own, run from run.sh's harness code: under supply_chain_or_ci it refuses what
# the target's crates could come through, and without the rule it accepts the same crate.
python3 -I -c 'import sys; src = open(sys.argv[1], encoding="utf-8").read(); sys.stdout.write(src.split("\nHARNESS_PY=\x27", 1)[1].split("\n\x27\n", 1)[0])' "$RUNSH" > "$T/harness.py"
SC="$T/sc-crate"; mk_crate "$SC"; mkdir -p "$T/target-crates/vault/src"
while IFS='|' read -r setting reason; do
  [ -n "$setting" ] || continue
  ( cd "$SC" && env -i PATH="$PATH" "$setting" python3 -I "$T/shim/meta.py" "$SC" ) > "$T/sc-meta.json"
  out="$(python3 -I "$T/harness.py" crate "$T/sc-meta.json" "$SC" supply-chain)"; rc=$?
  out2="$(python3 -I "$T/harness.py" crate "$T/sc-meta.json" "$SC" "")"; rc2=$?
  [ "$rc" = 3 ] && case "$out" in *"$reason"*"supply_chain_or_ci"*) true ;; *) false ;; esac && [ "$rc2" = 0 ] && [ "$out2" = poc_shim ] \
    && ok "under supply_chain_or_ci the crate check refuses $setting, which it accepts otherwise" || bad "the crate check, $setting: $rc '$out', without the rule $rc2 '$out2'"
done <<CASES
SHIM_DEP=vault,$T/target-crates/vault|poc_shim depends on vault at $T/target-crates/vault, outside the crate
SHIM_DEP=vault,git+https://example.invalid/vault|poc_shim depends on vault from git+https://example.invalid/vault
SHIM_LIB_SRC=$T/target-crates/lib.rs|poc_shim builds poc_shim from $T/target-crates/lib.rs, outside the crate
SHIM_DEP=evil,registry+file:///target/index|poc_shim depends on evil from file:///target/index, a registry other than crates.io
SHIM_DEP=evil,sparse+https://registry.example.invalid/index/|poc_shim depends on evil from https://registry.example.invalid/index/, a registry other than crates.io
CASES
for spec in registry+https://github.com/rust-lang/crates.io-index sparse+https://index.crates.io/; do
  ( cd "$SC" && env -i PATH="$PATH" "SHIM_DEP=borsh,$spec" python3 -I "$T/shim/meta.py" "$SC" ) > "$T/sc-meta.json"
  out="$(python3 -I "$T/harness.py" crate "$T/sc-meta.json" "$SC" supply-chain)"; rc=$?
  [ "$rc" = 0 ] && [ "$out" = poc_shim ] && ok "under supply_chain_or_ci the crate check accepts a dependency from crates.io ($spec)" || bad "the crate check, crates.io as $spec: $rc '$out'"
done
if [ "$ISOLATED_OK" = 1 ]; then
  code="$(ngate AUDITOR_EXEC_MODE=isolated -- --crate incident_1/poc/INC-1.1 "${IVULN[@]}")"
  [ "$code" = 0 ] && grep -q "^$LEG3" "$T/out" && ok "supply_chain_or_ci in isolated mode on the dumped bytes runs" || { bad "supply_chain_or_ci, isolated: exit $code"; cat "$T/out" >&2; }
  SHIM_EXTRA=("SHIM_DEP=vault,$T/target-crates/vault")
  code="$(ngate AUDITOR_EXEC_MODE=isolated -- --crate incident_1/poc/INC-1.1 "${IVULN[@]}")"
  SHIM_EXTRA=()
  [ "$code" = 3 ] && grep -qF "poc_shim depends on vault at $T/target-crates/vault, outside the crate" "$T/out" && [ -z "$(ls -A "$NT")" ] \
    && awk -F'\t' '$6 !~ /^metadata / { b = 1 } END { exit b }' "$T/calls" \
    && ok "supply_chain_or_ci with a path dependency outside the crate -> exit 3 before anything compiles" || { bad "supply_chain_or_ci, a path dependency: exit $code"; cat "$T/out" >&2; }
  # The resolved Cargo.lock is read again after the downloads: a path dependency, or one from another
  # registry than crates.io, that cargo resolved stops the run before anything compiles.
  for spec in 'vault@0.1.0@path|vault 0.1.0 (path)' 'evil@0.1.0@registry+file:///target/index|evil 0.1.0 (registry+file:///target/index, not crates.io)'; do
    rm -f "$WT/incident_1/poc/INC-1.1/Cargo.lock"
    SHIM_EXTRA=("SHIM_LOCK=${spec%%|*}")
    code="$(ngate AUDITOR_EXEC_MODE=isolated -- --crate incident_1/poc/INC-1.1 "${IVULN[@]}")"
    SHIM_EXTRA=()
    [ "$code" = 3 ] && grep -qxF "[PoC-ATTEMPTED] blocker: the resolved Cargo.lock names code from outside the crate (${spec#*|}), and the PoC of an incident whose root_cause_class is supply_chain_or_ci builds none of the target crates (OUTPUT-RULES.md Rule 11a); nothing was built." "$T/out" \
      && ! awk -F'\t' '$6 ~ /^(test |testbin )/ { f = 1 } END { exit !f }' "$T/calls" \
      && ok "supply_chain_or_ci with ${spec#*|} in the resolved Cargo.lock -> exit 3 before anything compiles" || { bad "supply_chain_or_ci, ${spec#*|} in the lock: exit $code"; cat "$T/out" >&2; }
  done
  # And a build that compiled a file from outside the crate, which only its dep-info names, stops before
  # its test runs.
  rm -f "$WT/incident_1/poc/INC-1.1/Cargo.lock"
  SHIM_EXTRA=(SHIM_DEPINFO="$T/di-lib.d")
  code="$(ngate AUDITOR_EXEC_MODE=isolated -- --crate incident_1/poc/INC-1.1 "${IVULN[@]}")"
  SHIM_EXTRA=()
  [ "$code" = 3 ] && grep -qF "[PoC-ATTEMPTED] blocker: the build compiled code from outside the crate ($DI/state.rs (compiled in), $DI/payload.inc (compiled in))" "$T/out" \
    && ! awk -F'\t' '$6 ~ /^testbin / { f = 1 } END { exit !f }' "$T/calls" \
    && ok "supply_chain_or_ci with a #[path] module and an include! from outside the crate in the build -> exit 3, the test never runs" || { bad "supply_chain_or_ci, a build with outside code: exit $code"; cat "$T/out" >&2; }
fi
rm -rf "$IJ" "$WT/incident_1/poc/INC-1.1"

# Every refusal in the case file, under each bash on the machine: one stderr line, exit 3, nothing on
# stdout, nothing copied, nothing changed in the working directory, and the same under each shell.
SHELLS=("$BASH"); if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then SHELLS+=(/bin/bash); fi
case_file() {  # case_file <cases.txt> <program> <dir>: run every case under each shell
  local file="$1" prog="$2" dir="$3" line want_rc want_err rest sh i ncase=0
  local -a args
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    want_rc=${line%%$'\t'*}; rest=${line#*$'\t'}; want_err=${rest%%$'\t'*}; rest=${rest#*$'\t'}
    IFS=$'\t' read -r -a args <<< "$rest"
    ncase=$((ncase + 1)); i=0
    for sh in "${SHELLS[@]}"; do
      rm -rf "$NT"; mkdir -p "$NT"; rm -f "$T/shim/settings.env"
      ( cd "$dir" && env -i HOME="$CLEANHOME" PATH="$SP" TMPDIR="$NT" "$sh" "$prog" "${args[@]}" ) >"$T/case.out.$i" 2>"$T/case.err.$i" </dev/null
      echo $? > "$T/case.rc.$i"
      i=$((i + 1))
    done
    if [ "$(cat "$T/case.rc.0")" = "$want_rc" ] && [ "$(cat "$T/case.err.0")" = "$want_err" ] && [ ! -s "$T/case.out.0" ] && [ -z "$(ls -A "$NT")" ]; then
      ok "case: ${prog##*/} ${args[*]}"
    else
      bad "case: ${prog##*/} ${args[*]} -> status $(cat "$T/case.rc.0"), stderr: $(cat "$T/case.err.0"), stdout: $(cat "$T/case.out.0")"
    fi
    if [ "$i" -gt 1 ] && { ! cmp -s "$T/case.rc.0" "$T/case.rc.1" || ! cmp -s "$T/case.err.0" "$T/case.err.1" || ! cmp -s "$T/case.out.0" "$T/case.out.1"; }; then
      bad "case: ${prog##*/} ${args[*]} prints differently under ${SHELLS[0]} and ${SHELLS[1]}"
    fi
  done < "$file"
  CASES_RUN=$ncase
}
printf 'native\n' > "$WT/audit_1/exec-mode"
before="$(tree_of "$WT")"
case_file "$HERE/fixtures/poc-run/cases.txt" "$RUNSH" "$WT"
[ "$CASES_RUN" -gt 50 ] && ok "the run.sh case file has cases ($CASES_RUN)" || bad "the run.sh case file has $CASES_RUN cases"
[ "$(tree_of "$WT")" = "$before" ] && ok "no run.sh case changed anything in the working directory" || bad "a run.sh case changed the working directory"
rm -f "$T/shim/settings.env"

# scripts/lib/isolation.sh on its own: the homes it reads, iso_run's refusal of a program path holding
# "=", the throwaway HOME (a keypair of mode 0600) and keep-home, and the scratch directory rules.
for sh in "${SHELLS[@]}"; do
  out="$(cd "$WT" && env -i HOME="$T/fake-home" PATH="$PATH" "$sh" "$T/iso-driver.sh" "$ROOT" homes)"
  account="$(python3 -I -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
  [ "$out" = "$(printf '%s\n%s' "$T/fake-home" "$account")" ] && ok "iso_homes ($sh): \$HOME, then the passwd home" || bad "iso_homes ($sh): '$out'"
  FH="$T/fh-a"; FH2="$T/fh-b"; mkdir -p "$FH/.aws" "$FH2/.docker"; printf 'a\n' > "$FH/.aws/credentials"; printf 'b\n' > "$FH2/.docker/config.json"
  out="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" "$sh" "$T/iso-driver.sh" "$ROOT" creds "$FH" "$FH2")"; rc=$?
  [ "$rc" = 1 ] && [ "$out" = "$(printf '%s\n%s\n%s' 'kinds: cloud credentials (1), Kubernetes or Docker config (1)' '~/.aws/credentials' '~/.docker/config.json')" ] \
    && ok "iso_credentials ($sh) reads every home it is given, and counts each kind" || bad "iso_credentials ($sh): $rc '$out'"
  mkdir -p "$T/fh-odd/.ssh"; printf 'k\n' > "$T/fh-odd/.ssh/$(printf 'id\tx\001y')"
  out="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" "$sh" "$T/iso-driver.sh" "$ROOT" creds "$T/fh-odd")"
  [ "$out" = "$(printf '%s\n%s' 'kinds: SSH keys (1)' '~/.ssh/id?x?y')" ] && ok "iso_credentials ($sh) prints a path's control characters as ?" || bad "iso_credentials ($sh), control characters: '$out'"
  rm -rf "$T/fh-odd"
  rm -rf "$T/iso-env" "$T/eq-marker"; mkdir -p "$T/iso-env"
  out="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" "$sh" "$T/iso-driver.sh" "$ROOT" run-eq "$T/iso-env" "$T")"
  [ "$out" = "rc=126" ] && ok "iso_run ($sh): a program path holding '=' -> 126, nothing run" || bad "iso_run ($sh) with '=': '$out'"
  rm -rf "$T/iso-env"; mkdir -p "$T/iso-env"
  out="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" TMPDIR="$NT" USER=u LANG=C.UTF-8 HTTPS_PROXY=http://p.invalid:1 GITHUB_TOKEN=canary-i1 "$sh" "$T/iso-driver.sh" "$ROOT" env "$T/iso-env")"
  key="$T/iso-env/home/.config/solana/id.json"
  if grep -qx "HOME=$T/iso-env/home" <<< "$out" && grep -qx "TMPDIR=$T/iso-env/tmp" <<< "$out" \
     && grep -qx 'net HTTPS_PROXY=http://p.invalid:1' <<< "$out" && ! grep -q '^HTTPS_PROXY=' <<< "$out" \
     && ! grep -q canary <<< "$out" && grep -qx 'USER=u' <<< "$out" \
     && [ -n "$(find "$key" -prune -perm 0600 -type f -print 2>/dev/null)" ]; then
    ok "iso_env ($sh): a throwaway HOME with a keypair of mode 0600, TMPDIR, the proxy apart, no token"
  else
    bad "iso_env ($sh)"; printf '%s\n' "$out" >&2
  fi
  rm -rf "$T/iso-env"; mkdir -p "$T/iso-env"
  out="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" "$sh" "$T/iso-driver.sh" "$ROOT" keep "$T/iso-env")"
  [ "$out" = "home $CLEANHOME" ] && [ ! -e "$T/iso-env/home" ] && ok "iso_env keep-home ($sh): the real HOME, no throwaway one made" || bad "iso_env keep-home ($sh): '$out'"
  mkdir -p "$WT/tmp-inside"
  out="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" TMPDIR="$WT/tmp-inside" "$sh" "$T/iso-driver.sh" "$ROOT" scratch 2>&1)"; rc=$?
  [ "$rc" = 64 ] && case "$out" in "iso-driver: refused: the scratch directory $WT/tmp-inside/auditor-driver."*" lies inside the working directory; point TMPDIR outside it") true ;; *) false ;; esac \
    && [ -z "$(ls -A "$WT/tmp-inside")" ] && ok "iso_scratch ($sh): a TMPDIR inside the working directory -> refused, and the scratch directory removed" || bad "iso_scratch ($sh) inside WT: $rc '$out'"
  rmdir "$WT/tmp-inside"
  # Where the volume folds case, a TMPDIR spelled in other letters than the names on disk is still inside
  # the working directory: the check compares directories, not spellings.
  up="$(printf '%s' "$WT" | tr '[:lower:]' '[:upper:]')"
  if [ "$up" != "$WT" ] && [ "$up" -ef "$WT" ]; then
    mkdir -p "$WT/tmp-inside"
    out="$(cd "$up" && env -i HOME="$CLEANHOME" PATH="$PATH" TMPDIR="$up/tmp-inside" "$sh" "$T/iso-driver.sh" "$ROOT" scratch 2>&1)"; rc=$?
    [ "$rc" = 64 ] && case "$out" in "iso-driver: refused: the scratch directory "*" lies inside the working directory; point TMPDIR outside it") true ;; *) false ;; esac \
      && [ -z "$(ls -A "$WT/tmp-inside")" ] && ok "iso_scratch ($sh): a TMPDIR inside the working directory, spelled in other letters -> refused" || bad "iso_scratch ($sh) inside WT, other letters: $rc '$out'"
    rmdir "$WT/tmp-inside"
  fi
  mkdir -p "$T/cfgparent/.cargo" "$T/cfgparent/tmp"; printf '[build]\n' > "$T/cfgparent/.cargo/config.toml"
  out="$(cd "$WT" && env -i HOME="$CLEANHOME" PATH="$PATH" TMPDIR="$T/cfgparent/tmp" "$sh" "$T/iso-driver.sh" "$ROOT" scratch 2>&1)"; rc=$?
  [ "$rc" = 64 ] && case "$out" in *"would inherit $T/cfgparent/.cargo/config.toml; point TMPDIR outside any repository") true ;; *) false ;; esac \
    && [ -z "$(ls -A "$T/cfgparent/tmp")" ] && ok "iso_scratch ($sh): a scratch directory under a .cargo/config.toml -> refused" || bad "iso_scratch ($sh) under a cargo config: $rc '$out'"
done
# The Python programs isolation.sh runs hold only ASCII, an escape standing for any other character, so that
# python3 reads the same program whatever the locale decodes its arguments with.
progs="$(. "$ROOT/scripts/lib/isolation.sh" && printf '%s' "$ISO_PY$ISO_WATCH_PY$ISO_INCIDENT_PY")"
[ -n "$progs" ] && printf '%s' "$progs" | python3 -I -c 'import sys; sys.exit(any(b > 127 for b in sys.stdin.buffer.read()))' \
  && ok "the Python programs isolation.sh runs hold only ASCII, so python3 reads them the same in any locale" \
  || bad "a Python program isolation.sh runs holds a byte outside ASCII"

# isolation.sh starts each python3 from /: a .python-version in the working directory, which a pyenv shim
# reads to pick the interpreter, picks none, and a relative path in a variable the check reads (KUBECONFIG
# here) is taken from /, never from the tree under audit. A python3 stand-in first on PATH records the
# directory of each run that finds a .python-version there; the watchdog's run is checked by its report, and
# the directory it runs its program in, which in use is the copy of the tree, holds a .python-version too.
PV="$T/pv-wt"; PVBIN="$T/pv-bin"; mkdir -p "$PV" "$PVBIN" "$T/pv-home"
printf 'from-the-tree\n' > "$PV/.python-version"; printf 'apiVersion: v1\n' > "$PV/kube.cfg"
printf '#!/bin/sh\n[ -e .python-version ] && pwd >> "%s"\nexec "%s" "$@"\n' "$T/pv-picked" "$(command -v python3)" > "$PVBIN/python3"
chmod +x "$PVBIN/python3"
for sh in "${SHELLS[@]}"; do
  rm -f "$T/pv-picked"; rm -rf "$T/pv-env" "$T/pv-watch"; mkdir -p "$T/pv-env" "$T/pv-watch"
  printf 'from-the-tree\n' > "$T/pv-watch/.python-version"
  for what in homes names creds "env $T/pv-env" "watch $T/pv-watch"; do
    (cd "$PV" && env -i HOME="$CLEANHOME" PATH="$PVBIN:$PATH" "$sh" "$T/iso-driver.sh" "$ROOT" $what) >/dev/null 2>&1
  done
  [ ! -e "$T/pv-picked" ] && [ -f "$T/pv-env/home/.config/solana/id.json" ] && [ "$(cat "$T/pv-watch/report" 2>/dev/null)" = "exit 0" ] \
    && ok "isolation.sh ($sh): homes, names, creds, the keypair and the watchdog run python3 from /, so the working directory's .python-version picks no interpreter" \
    || bad "isolation.sh ($sh): python3 ran where the working directory's .python-version picks it: $(cat "$T/pv-picked" 2>/dev/null)"
  out="$(cd "$PV" && env -i HOME="$CLEANHOME" KUBECONFIG=kube.cfg PATH="$PATH" "$sh" "$T/iso-driver.sh" "$ROOT" creds "$T/pv-home")"; rc=$?
  [ "$rc" = 0 ] && [ -z "$out" ] && ok "iso_credentials ($sh): a relative KUBECONFIG is taken from /, so the tree's kube.cfg does not count" \
    || bad "iso_credentials ($sh), a relative KUBECONFIG: $rc '$out'"
done
# run.sh --crate for an incident reads INCIDENTS.json with the same python3 from / (iso_incident_class), and
# every other python3 it starts before it leaves the working directory starts from / too.
mk_crate "$WT/incident_1/poc/INC-1.1"; incidents code_flaw; printf 'from-the-tree\n' > "$WT/.python-version"; rm -f "$T/pv-picked"
code="$(ngate AUDITOR_EXEC_MODE=native PATH="$PVBIN:$SP" -- --crate incident_1/poc/INC-1.1 "${IVULN[@]}")"
[ "$code" = 0 ] && grep -qF '>> incident INC-1.1: root_cause_class code_flaw (incident_1/INCIDENTS.json)' "$T/out" && [ ! -e "$T/pv-picked" ] \
  && ok "run.sh --crate for an incident: the incident check and the self-check run python3 from /, so the working directory's .python-version picks no interpreter" \
  || { bad "run.sh --crate for an incident with a .python-version: exit $code, python3 ran in: $(cat "$T/pv-picked" 2>/dev/null)"; cat "$T/out" >&2; }
rm -rf "$IJ" "$WT/incident_1/poc/INC-1.1" "$WT/.python-version"
# And every python3 run.sh --crate starts for its own reading, the check of the harness copy included,
# starts from / (the python3 stand-in from the shim runs above records where).
rm -f "$T/pyh.log"
code="$(ngate PATH="$PYH:$SP" -- --crate audit_1/poc/F-1 "${NVULN[@]}")"
calls="$(awk '{ print $NF }' "$T/pyh.log" 2>/dev/null | LC_ALL=C sort -u | tr '\n' ' ')"
[ "$code" = 0 ] && [ "$calls" = "checkbuild crate hash nonregistry settle stucopy targetdir " ] && ! grep -qvE '^/ [a-z]+$' "$T/pyh.log" \
  && ok "run.sh --crate: its own python3 calls ($calls) all start from /" \
  || { bad "run.sh --crate, its python3 calls: exit $code, started in: $(sed 's/ [a-z]*$//' "$T/pyh.log" 2>/dev/null | LC_ALL=C sort -u | tr '\n' ' ')"; cat "$T/out" >&2; }

# scripts/runner/probe.sh: fixed version queries from a scratch directory, in the cleaned environment
# with the real HOME, the proxy at a closed port, standard input closed; absent and unusable tools; the
# isolation line; --only; its case file; and where it refuses to run.
[ "$(sed -n 1p "$PROBE")" = '#!/bin/bash' ] && [ -x "$PROBE" ] && ok "probe.sh starts with #!/bin/bash and is executable" || bad "probe.sh shebang or mode"
if command -v git >/dev/null 2>&1 && mode="$(git -C "$ROOT" ls-files -s -- scripts/runner/probe.sh 2>/dev/null)" && [ -n "$mode" ]; then
  [ "${mode%% *}" = 100755 ] && ok "git records probe.sh as 100755" || bad "git records probe.sh as ${mode%% *}"
fi
PB="$T/probe-bin"; PS="$T/probe-sys"; PH="$T/probe-home"; PT="$T/tmp-probe"; mkdir -p "$PB" "$PS" "$PH" "$PT"
for tool in env mkdir mktemp rm sleep; do p="$(command -v "$tool")" && ln -sf "$p" "$PS/$tool"; done
ln -sf "$(python3 -I -c 'import sys; print(sys.executable)')" "$PS/python3"
fake() {  # fake <name> <script body>: a stand-in tool that logs how it was run, then runs the body
  printf '#!/bin/sh\n{ echo "== %s $*"; echo "PWD=$PWD"; if read -r x; then echo "stdin: data"; else echo "stdin: closed"; fi; /usr/bin/env; } >> "%s" 2>&1\n%s\n' \
    "$1" "$T/probe.log" "$2" > "$PB/$1"
  chmod +x "$PB/$1"
}
fake cargo 'case "$1" in build-sbf) echo "solana-cargo-build-sbf 9.9.9 (fake)" ;; *) echo "cargo 9.9.9 (fake)" ;; esac'
fake cargo-build-sbf 'exit 0'
fake rustup 'case "$1" in default) echo "fake-toolchain (default)" ;; *) echo "rustup 9.9.9 (fake)"; echo "info: more" >&2 ;; esac'
fake anchor 'echo "anchor broke" >&2; exit 1'
fake solana 'echo "solana-cli 9.9.9 (fake, on stderr)" >&2'
fake surfpool 'echo "surfpool 9.9.9 (fake)"; i=0; while [ $i -lt 2000 ]; do echo "padding line $i of the long output a tool can print, past a pipe buffer"; i=$((i + 1)); done'
fake semgrep 'exit 0'
probe_run() {  # probe_run [VAR=val ...] -- <argument>... -> exit code; stdout in $T/out, stderr in $T/err
  local -a vars=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do vars+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  rm -f "$T/probe.log"
  ( cd "$WT" && env -i HOME="$PH" PATH="$PB:$PS" TMPDIR="$PT" ${vars[@]+"${vars[@]}"} "$PROBE" "$@" ) >"$T/out" 2>"$T/err" </dev/null
  echo $?
}
code="$(probe_run GITHUB_TOKEN=canary-p1 HTTPS_PROXY=http://proxy.invalid:3128 AUDITOR_CANARY=canary-p2 --)"
expect="$(printf '%s\n' 'cargo: cargo 9.9.9 (fake)' 'rustup: rustup 9.9.9 (fake)' 'cargo-build-sbf: solana-cargo-build-sbf 9.9.9 (fake)' \
  'cargo-fuzz: absent' 'trident: absent' 'anchor: unusable (exit 1)' 'solana: solana-cli 9.9.9 (fake, on stderr)' 'surfpool: surfpool 9.9.9 (fake)' \
  'semgrep: unusable (no version printed)' 'pandoc: absent')"
got="$(sed -n '1,10p' "$T/out")"
[ "$code" = 0 ] && [ "$got" = "$expect" ] && grep -q '^python3: Python 3\.' "$T/out" && grep -q '^isolation: ' "$T/out" && [ "$(wc -l < "$T/out" | tr -d ' ')" = 12 ] && [ ! -s "$T/err" ] \
  && ok "probe.sh: one line per tool in order (a version, absent or unusable, stderr when stdout is empty, a long output read whole)" || { bad "probe.sh output: exit $code"; cat "$T/out" "$T/err" >&2; }
if [ -s "$T/probe.log" ] && ! grep -q canary "$T/probe.log" && ! grep -q 'proxy.invalid' "$T/probe.log" \
   && [ "$(grep -c '^HTTPS_PROXY=http://127.0.0.1:9$' "$T/probe.log")" = "$(grep -c '^== ' "$T/probe.log")" ] \
   && [ "$(grep -c "^HOME=$PH\$" "$T/probe.log")" = "$(grep -c '^== ' "$T/probe.log")" ] \
   && [ "$(grep -c '^stdin: closed$' "$T/probe.log")" = "$(grep -c '^== ' "$T/probe.log")" ] \
   && [ "$(grep -c '^CARGO_NET_OFFLINE=true$' "$T/probe.log")" = "$(grep -c '^== ' "$T/probe.log")" ] \
   && grep -q '^RUSTUP_TOOLCHAIN=fake-toolchain$' "$T/probe.log" \
   && [ "$(grep -c "^PWD=$PT/auditor-probe\." "$T/probe.log")" -ge "$(grep -c '^== ' "$T/probe.log")" ] \
   && [ -z "$(grep '^PWD=' "$T/probe.log" | grep -v "^PWD=$PT/auditor-probe\.")" ]; then
  ok "probe.sh runs each query from its scratch directory in the cleaned environment: real HOME, closed proxy, offline cargo, pinned toolchain, stdin closed, no token"
else
  bad "probe.sh environment"; cat "$T/probe.log" >&2
fi
[ -z "$(ls -A "$PT")" ] && ok "probe.sh removes its scratch directory" || bad "probe.sh left $(ls -A "$PT")"
code="$(probe_run -- --only solana,cargo)"
[ "$code" = 0 ] && [ "$(cat "$T/out")" = "$(printf '%s\n%s' 'cargo: cargo 9.9.9 (fake)' 'solana: solana-cli 9.9.9 (fake, on stderr)')" ] \
  && ok "probe.sh --only solana,cargo -> those two, in probe.sh's order" || { bad "probe.sh --only: exit $code"; cat "$T/out" >&2; }
# A query that gives no answer within PROBE_WAIT seconds is killed, and the tool is unusable. PROBE_WAIT=4
# leaves the stand-in time to start on a loaded machine. A pid file it never wrote means it never ran, so
# nothing was left behind; otherwise the killed query must be gone within about 2 s (a killed process stays
# in the process table until it is reaped).
fake trident "echo \$\$ > '$T/trident.pid'; exec sleep 60"
rm -f "$T/trident.pid"
start=$SECONDS
code="$(probe_run PROBE_WAIT=4 -- --only trident,python3)"
took=$((SECONDS - start))
left=""
tp=$(cat "$T/trident.pid" 2>/dev/null) || tp=""
case "$tp" in
  ''|*[!0-9]*) ;;
  *) i=0
     while kill -0 "$tp" 2>/dev/null; do
       [ "$i" -lt 20 ] || { left=$tp; break; }
       sleep 0.1
       i=$((i + 1))
     done ;;
esac
[ "$code" = 0 ] && [ "$(sed -n 1p "$T/out")" = 'trident: unusable (no answer in 4 seconds)' ] && grep -q '^python3: Python 3\.' "$T/out" \
  && [ "$took" -ge 4 ] && [ "$took" -le 20 ] && [ -z "$left" ] \
  && ok "probe.sh: a query with no answer in PROBE_WAIT seconds is killed, and the next one runs (${took}s)" || { bad "probe.sh, a query that hangs: exit $code after ${took}s${left:+, process $left still there}"; cat "$T/out" "$T/err" >&2; }
rm -f "$PB/trident"
for value in 0 601 030 abc 1.5; do
  code="$(probe_run PROBE_WAIT="$value" --)"
  [ "$code" = 64 ] && [ "$(cat "$T/err")" = "probe: refused: PROBE_WAIT is '$value', not a whole number of seconds from 1 to 600" ] && [ ! -s "$T/out" ] \
    && ok "probe.sh with PROBE_WAIT=$value -> 64" || { bad "probe.sh, PROBE_WAIT=$value: exit $code"; cat "$T/err" >&2; }
done
mkdir -p "$PH/.aws"; printf 'secret\n' > "$PH/.aws/credentials"
code="$(probe_run -- --only isolation)"
[ "$code" = 0 ] && case "$(cat "$T/out")" in "isolation: readable: "*"cloud credentials ("*"; ~/.aws/credentials"*) true ;; *) false ;; esac \
  && ok "probe.sh --only isolation names the kinds, then the readable paths under ~" || { bad "probe.sh isolation line: exit $code"; cat "$T/out" >&2; }
mkdir -p "$PH/.config/solana"; i=0; while [ "$i" -lt 25 ]; do printf 'k\n' > "$PH/.config/solana/key$i.json"; i=$((i + 1)); done
code="$(probe_run -- --only isolation)"
listed="$(sed -n 's/^isolation: readable: [^;]*; //p' "$T/out")"
more="$(printf '%s' "$listed" | sed -n 's/.*, and \([0-9][0-9]*\) more$/\1/p')"
[ "$code" = 0 ] && [ -n "$more" ] && [ "$more" -ge 5 ] && [ "$(printf '%s' "${listed%, and * more}" | tr ',' '\n' | grep -c .)" = 20 ] \
  && ok "probe.sh lists the first 20 readable paths, then how many more ($more)" || { bad "probe.sh, a long list: exit $code"; cat "$T/out" >&2; }
rm -rf "$PH/.aws" "$PH/.config"
rm -f "$PS/python3"
code="$(probe_run -- --only python3,isolation)"
[ "$code" = 0 ] && [ "$(cat "$T/out")" = "$(printf '%s\n%s' 'python3: absent' 'isolation: not checked (python3 is not on PATH)')" ] \
  && ok "probe.sh without python3: python3 absent, isolation not checked" || { bad "probe.sh without python3: exit $code"; cat "$T/out" >&2; }
ln -sf "$(python3 -I -c 'import sys; print(sys.executable)')" "$PS/python3"
mkdir -p "$WT/tmp-inside"
code="$(probe_run TMPDIR="$WT/tmp-inside" --)"
[ "$code" = 64 ] && grep -q "^probe: refused: the scratch directory $WT/tmp-inside/auditor-probe\..* lies inside the working directory; point TMPDIR outside it\$" "$T/err" \
  && [ ! -s "$T/out" ] && [ -z "$(ls -A "$WT/tmp-inside")" ] && ok "probe.sh with TMPDIR inside the working directory -> 64, nothing left" || { bad "probe.sh TMPDIR inside WT: exit $code"; cat "$T/err" >&2; }
rmdir "$WT/tmp-inside"
code="$(probe_run TMPDIR="$T/cfgparent/tmp" --)"
[ "$code" = 64 ] && grep -q "would inherit $T/cfgparent/.cargo/config.toml" "$T/err" && [ -z "$(ls -A "$T/cfgparent/tmp")" ] \
  && ok "probe.sh with a scratch directory under a .cargo/config.toml -> 64" || { bad "probe.sh under a cargo config: exit $code"; cat "$T/err" >&2; }
mkdir -p "$T/probe-copy"; cp "$PROBE" "$T/probe-copy/probe.sh"
code="$( (cd "$WT" && env -i HOME="$PH" PATH="$PB:$PS" TMPDIR="$PT" /bin/bash "$T/probe-copy/probe.sh") >"$T/out" 2>"$T/err"; echo $?)"
[ "$code" = 64 ] && [ "$(cat "$T/err")" = 'probe: refused: probe.sh runs from <auditor-skill root>/scripts/runner' ] \
  && ok "a copy of probe.sh outside scripts/runner -> 64" || { bad "probe.sh copy: exit $code"; cat "$T/err" >&2; }
case_file "$HERE/fixtures/probe/cases.txt" "$PROBE" "$WT"
[ "$CASES_RUN" -gt 10 ] && ok "the probe.sh case file has cases ($CASES_RUN)" || bad "the probe.sh case file has $CASES_RUN cases"

# ---------------------------------------------------------------------------
# Real cargo and rustup, when present: the template's own tests and shared-test-utils,
# built and run through run.sh against stand-in crates. The stand-in mollusk loads the
# bytes it is given (Mollusk::new finds <crate>.so the way mollusk does: tests/fixtures,
# BPF_OUT_DIR, SBF_OUT_DIR, the working directory) and acts out the text after the ELF
# magic: "takeover" writes the instruction's third account key into the first writable
# account's bytes 0..32 (the authority hand-over of the template's example); "guard:<error>"
# does that only when the second account signs and otherwise fails with <error>;
# "dirty-reject" (always) and "dirty-guard" (unsigned) fail with Custom(6001) yet keep
# the change; "noop" accepts and changes nothing; "reject:<error>" fails every call;
# "unloadable" makes the loader panic. The stand-in litesvm runs each instruction of a
# transaction through the stand-in mollusk and keeps the accounts of a transaction that
# went through. The stand-in sha2 is a plain SHA-256.
# ---------------------------------------------------------------------------
mk_standins() {  # mk_standins <dir>
  local S="$1"
  sc() {  # sc <dir> <package> <version> <[dependencies] lines>; lib.rs on stdin
    mkdir -p "$S/$1/src" && printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\npublish = false\n\n[dependencies]\n%s' "$2" "$3" "$4" > "$S/$1/Cargo.toml" && cat > "$S/$1/src/lib.rs"
  }
  dep() { printf '%s = { path = "%s/%s" }\n' "$1" "$S" "$2"; }
  sc pubkey solana-pubkey 4.0.0 '' <<'RS'
use std::sync::atomic::{AtomicU32, Ordering};
static NEXT: AtomicU32 = AtomicU32::new(1);
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pubkey(pub [u8; 32]);
impl Pubkey {
    pub fn new_unique() -> Self {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        Pubkey(b)
    }
    pub fn to_bytes(&self) -> [u8; 32] { self.0 }
}
impl AsRef<[u8]> for Pubkey { fn as_ref(&self) -> &[u8] { &self.0 } }
RS
  sc account solana-account 3.0.0 "$(dep solana-pubkey pubkey)" <<'RS'
use solana_pubkey::Pubkey;
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account { pub lamports: u64, pub data: Vec<u8>, pub owner: Pubkey, pub executable: bool, pub rent_epoch: u64 }
RS
  sc rent solana-rent 3.0.0 '' <<'RS'
#[derive(Default)]
pub struct Rent;
impl Rent { pub fn minimum_balance(&self, len: usize) -> u64 { 890_880 + 6_960 * len as u64 } }
RS
  sc sysif solana-system-interface 3.0.0 "$(dep solana-pubkey pubkey)" <<'RS'
pub mod program { pub const ID: solana_pubkey::Pubkey = solana_pubkey::Pubkey([0; 32]); }
RS
  sc progerr solana-program-error 3.0.0 '' <<'RS'
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProgramError {
    Custom(u32), InvalidArgument, InvalidInstructionData, InvalidAccountData, IncorrectProgramId,
    MissingRequiredSignature, NotEnoughAccountKeys, IllegalOwner, ArithmeticOverflow,
}
RS
  sc instr solana-instruction 3.0.0 "$(dep solana-pubkey pubkey)" <<'RS'
use solana_pubkey::Pubkey;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMeta { pub pubkey: Pubkey, pub is_signer: bool, pub is_writable: bool }
impl AccountMeta {
    pub fn new(pubkey: Pubkey, is_signer: bool) -> Self { Self { pubkey, is_signer, is_writable: true } }
    pub fn new_readonly(pubkey: Pubkey, is_signer: bool) -> Self { Self { pubkey, is_signer, is_writable: false } }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction { pub program_id: Pubkey, pub accounts: Vec<AccountMeta>, pub data: Vec<u8> }
RS
  sc sdk solana-sdk 3.0.0 "$(dep solana-pubkey pubkey; dep solana-instruction instr; dep solana-program-error progerr)" <<'RS'
pub use solana_instruction as instruction;
pub use solana_program_error as program_error;
pub use solana_pubkey as pubkey;
pub mod transaction {
    use solana_instruction::Instruction;
    use solana_pubkey::Pubkey;
    #[derive(Clone, Debug)]
    pub struct Message { pub instructions: Vec<Instruction>, pub payer: Option<Pubkey> }
    impl Message {
        pub fn program_ids(&self) -> Vec<&Pubkey> {
            self.instructions.iter().map(|ix| &ix.program_id).collect()
        }
    }
    #[derive(Clone, Debug)]
    pub struct Transaction { pub message: Message }
    impl Transaction {
        pub fn new_with_payer(instructions: &[Instruction], payer: Option<&Pubkey>) -> Self {
            Transaction { message: Message { instructions: instructions.to_vec(), payer: payer.copied() } }
        }
    }
}
RS
  sc borsh borsh 1.0.0 '' <<'RS'
pub trait BorshSerialize {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()>;
}
RS
  sc mollusk mollusk-svm 0.13.0 "$(dep solana-pubkey pubkey; dep solana-account account; dep solana-instruction instr; dep solana-program-error progerr)" <<'RS'
pub mod result {
    use solana_account::Account;
    use solana_program_error::ProgramError;
    use solana_pubkey::Pubkey;
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum InstructionError { MissingAccount, UnsupportedProgramId, ComputationalBudgetExceeded, ReadonlyDataModified }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ProgramResult { Success, Failure(ProgramError), UnknownError(InstructionError) }
    impl ProgramResult {
        pub fn is_ok(&self) -> bool { matches!(self, ProgramResult::Success) }
        pub fn is_err(&self) -> bool { !self.is_ok() }
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct InstructionResult { pub program_result: ProgramResult, pub resulting_accounts: Vec<(Pubkey, Account)> }
    impl InstructionResult {
        pub fn get_account(&self, pubkey: &Pubkey) -> Option<&Account> {
            self.resulting_accounts.iter().find(|(k, _)| k == pubkey).map(|(_, a)| a)
        }
    }
}
pub mod program {
    pub mod loader_keys { pub const LOADER_V3: solana_pubkey::Pubkey = solana_pubkey::Pubkey([3; 32]); }
}
use result::{InstructionResult, ProgramResult};
use solana_account::Account;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
#[derive(Clone, Default)]
pub struct Mollusk { behaviour: String }
impl Mollusk {
    pub fn new(program_id: &Pubkey, so_name: &str) -> Self {
        let file = format!("{so_name}.so");
        let mut dirs = vec![std::path::PathBuf::from("tests/fixtures")];
        for var in ["BPF_OUT_DIR", "SBF_OUT_DIR"] {
            if let Ok(dir) = std::env::var(var) { dirs.push(dir.into()); }
        }
        if let Ok(dir) = std::env::current_dir() { dirs.push(dir); }
        let path = dirs.iter().map(|d| d.join(&file)).find(|p| p.exists())
            .unwrap_or_else(|| panic!("stand-in mollusk: {file} not found"));
        let mut mollusk = Self::default();
        let elf = std::fs::read(&path).expect("read the program");
        mollusk.add_program_with_loader_and_elf(program_id, &program::loader_keys::LOADER_V3, &elf);
        mollusk
    }
    pub fn add_program_with_loader_and_elf(&mut self, _program_id: &Pubkey, _loader_key: &Pubkey, elf: &[u8]) {
        let tag: Vec<u8> = elf[4..].iter().copied().take_while(|b| *b != 0).collect();
        let behaviour = String::from_utf8(tag).expect("utf-8 behaviour");
        assert!(behaviour != "unloadable", "stand-in mollusk: the loader rejects these bytes");
        self.behaviour = behaviour;
    }
    pub fn process_instruction(&self, ix: &Instruction, accounts: &[(Pubkey, Account)]) -> InstructionResult {
        let mut out = accounts.to_vec();
        let take_over = |out: &mut Vec<(Pubkey, Account)>| {
            let next = ix.accounts.get(2).expect("a third account").pubkey;
            let target = ix.accounts.iter().find(|m| m.is_writable).expect("a writable account").pubkey;
            let acct = out.iter_mut().find(|(k, _)| *k == target).map(|(_, a)| a).expect("the target account");
            acct.data[0..32].copy_from_slice(next.as_ref());
        };
        let signed = ix.accounts.get(1).map_or(false, |m| m.is_signer);
        let b = self.behaviour.as_str();
        let program_result = if b == "takeover" || (signed && (b == "dirty-guard" || b.starts_with("guard:"))) {
            take_over(&mut out);
            ProgramResult::Success
        } else if b == "dirty-reject" || b == "dirty-guard" {
            // Fails, yet leaves the change in place, as a runtime that did not roll back would.
            take_over(&mut out);
            return InstructionResult { program_result: ProgramResult::Failure(ProgramError::Custom(6001)), resulting_accounts: out };
        } else if b == "noop" {
            ProgramResult::Success
        } else if b == "ro-modified" {
            // The runtime stops the instruction: a read-only account was written. Mollusk
            // surfaces it as UnknownError, like the other account-list mismatches.
            ProgramResult::UnknownError(result::InstructionError::ReadonlyDataModified)
        } else if let Some(name) = b.strip_prefix("guard:").or_else(|| b.strip_prefix("reject:")) {
            ProgramResult::Failure(error(name))
        } else {
            panic!("stand-in mollusk: unknown behaviour {b:?}");
        };
        if program_result.is_err() { out = accounts.to_vec(); }
        InstructionResult { program_result, resulting_accounts: out }
    }
}
fn error(name: &str) -> ProgramError {
    match name {
        "MissingRequiredSignature" => ProgramError::MissingRequiredSignature,
        "InvalidInstructionData" => ProgramError::InvalidInstructionData,
        "NotEnoughAccountKeys" => ProgramError::NotEnoughAccountKeys,
        other => match other.strip_prefix("Custom(").and_then(|s| s.strip_suffix(')')) {
            Some(code) => ProgramError::Custom(code.parse().expect("a code")),
            None => panic!("stand-in mollusk: unknown error {other:?}"),
        },
    }
}
RS
  sc litesvm litesvm 0.13.0 "$(dep solana-pubkey pubkey; dep solana-account account; dep solana-sdk sdk; dep mollusk-svm mollusk)" <<'RS'
use mollusk_svm::result::ProgramResult;
use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_sdk::transaction::Transaction;
#[derive(Debug)]
pub struct LiteSVMError(pub String);
pub struct InstructionError(String);
impl std::fmt::Debug for InstructionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}
#[derive(Debug)]
pub enum TransactionError { InstructionError(u8, InstructionError), AccountNotFound }
#[derive(Debug, Default)]
pub struct TransactionMetadata { pub logs: Vec<String> }
#[derive(Debug)]
pub struct FailedTransactionMetadata { pub err: TransactionError, pub meta: TransactionMetadata }
pub type TransactionResult = Result<TransactionMetadata, FailedTransactionMetadata>;
#[derive(Clone, Default)]
pub struct LiteSVM { programs: Vec<(Pubkey, Mollusk)>, accounts: Vec<(Pubkey, Account)> }
impl LiteSVM {
    pub fn new() -> Self { Self::default() }
    pub fn add_program(&mut self, program_id: impl Into<Pubkey>, bytes: &[u8]) -> Result<(), LiteSVMError> {
        let program_id = program_id.into();
        if bytes.get(4..).map_or(true, |tag| tag.starts_with(b"unloadable")) {
            return Err(LiteSVMError("the loader rejects these bytes".to_string()));
        }
        let mut mollusk = Mollusk::default();
        mollusk.add_program_with_loader_and_elf(&program_id, &mollusk_svm::program::loader_keys::LOADER_V3, bytes);
        self.programs.retain(|(id, _)| *id != program_id);
        self.programs.push((program_id, mollusk));
        Ok(())
    }
    pub fn set_account(&mut self, address: Pubkey, account: Account) -> Result<(), LiteSVMError> {
        self.accounts.retain(|(key, _)| *key != address);
        self.accounts.push((address, account));
        Ok(())
    }
    pub fn get_account(&self, address: &Pubkey) -> Option<Account> {
        self.accounts.iter().find(|(key, _)| key == address).map(|(_, account)| account.clone())
    }
    pub fn send_transaction(&mut self, tx: impl Into<Transaction>) -> TransactionResult {
        let tx = tx.into();
        let mut accounts = self.accounts.clone();
        for (index, ix) in tx.message.instructions.iter().enumerate() {
            let fail = |name: String| FailedTransactionMetadata {
                err: TransactionError::InstructionError(index as u8, InstructionError(name)),
                meta: TransactionMetadata::default(),
            };
            let Some((_, mollusk)) = self.programs.iter().find(|(id, _)| *id == ix.program_id) else {
                return Err(fail("UnsupportedProgramId".to_string()));
            };
            let given: Vec<(Pubkey, Account)> = ix.accounts.iter()
                .map(|meta| (meta.pubkey, accounts.iter().find(|(key, _)| *key == meta.pubkey).map(|(_, a)| a.clone()).unwrap_or_default()))
                .collect();
            let result = mollusk.process_instruction(ix, &given);
            match result.program_result {
                ProgramResult::Success => {
                    for (key, account) in result.resulting_accounts {
                        accounts.retain(|(k, _)| *k != key);
                        accounts.push((key, account));
                    }
                }
                ProgramResult::Failure(error) => return Err(fail(format!("{error:?}"))),
                ProgramResult::UnknownError(error) => return Err(fail(format!("{error:?}"))),
            }
        }
        self.accounts = accounts;
        Ok(TransactionMetadata::default())
    }
}
RS
  sc sha2 sha2 0.10.0 '' <<'RS'
pub trait Digest {
    fn digest(data: impl AsRef<[u8]>) -> [u8; 32];
}
pub struct Sha256;
impl Digest for Sha256 {
    fn digest(data: impl AsRef<[u8]>) -> [u8; 32] {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        let mut h: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        let mut msg = data.as_ref().to_vec();
        let bits = (msg.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 { msg.push(0); }
        msg.extend_from_slice(&bits.to_be_bytes());
        for block in msg.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..64 {
                w[i] = if i < 16 {
                    u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]])
                } else {
                    let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                    let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                    w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1)
                };
            }
            let mut v = h;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                v = [t1.wrapping_add(s0.wrapping_add(maj)), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
            }
            for i in 0..8 { h[i] = h[i].wrapping_add(v[i]); }
        }
        let mut out = [0u8; 32];
        for i in 0..8 { out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes()); }
        out
    }
}
RS
}

# mk_e2e <dir>: a PoC crate made of the template's tests, shared-test-utils and run.sh,
# with stand-in dependencies by absolute path (the crate builds from a scratch copy).
mk_e2e() {
  local P="$1" S="$T/si"
  mkdir -p "$P/src" "$P/tests" "$P/shared-test-utils/src"
  cp "$TEMPLATE/run.sh" "$P/run.sh"
  for f in exploit fixed_blocked; do sed 's/{PROGRAM_NAME}/poc_e2e/g' "$TEMPLATE/tests/$f.rs" > "$P/tests/$f.rs"; done
  cp "$TEMPLATE/shared-test-utils/src/lib.rs" "$P/shared-test-utils/src/lib.rs"
  printf '[package]\nname = "poc_e2e"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n\n[workspace]\n\n[features]\ndefault = ["fixed"]\nvulnerable = []\nfixed = []\n\n[dependencies]\nborsh = { path = "%s/borsh" }\nsolana-pubkey = { path = "%s/pubkey" }\n\n[dev-dependencies]\nmollusk-svm = { path = "%s/mollusk" }\nsolana-sdk = { path = "%s/sdk" }\nshared-test-utils = { path = "shared-test-utils" }\n' "$S" "$S" "$S" "$S" > "$P/Cargo.toml"
  printf '[package]\nname = "shared-test-utils"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n\n[dependencies]\nmollusk-svm = { path = "%s/mollusk" }\nsolana-account = { path = "%s/account" }\nsolana-pubkey = { path = "%s/pubkey" }\nsolana-rent = { path = "%s/rent" }\nsolana-system-interface = { path = "%s/sysif" }\nsha2 = { path = "%s/sha2" }\n' "$S" "$S" "$S" "$S" "$S" "$S" > "$P/shared-test-utils/Cargo.toml"
  printf 'use solana_pubkey::Pubkey;\npub struct State {\n    pub authority: Pubkey,\n}\nimpl State {\n    pub const LEN: usize = 32;\n}\nimpl borsh::BorshSerialize for State {\n    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {\n        writer.write_all(self.authority.as_ref())\n    }\n}\n' > "$P/src/lib.rs"
}
# swap <file> <awk program>: rewrite a test file in place
swap() { awk "$2" "$1" > "$1.new" && mv "$1.new" "$1"; }
# Drop the assertion block that starts at the line matching <regex> (through "    );").
DROP='BEGIN { re = ARGV[2]; ARGV[2] = "" } $0 ~ re { skip = 1 } skip { if ($0 == "    );") skip = 0; next } { print }'
drop_block() { awk "$DROP" "$1" "$2" > "$1.new" && mv "$1.new" "$1"; }
# subst <file> <old> <new>: replace the one occurrence of <old>, literally
subst() { python3 -I -c 'import sys; p, a, b = sys.argv[1:]; s = open(p).read(); assert s.count(a) == 1, a; open(p, "w").write(s.replace(a, b))' "$1" "$2" "$3"; }

if command -v cargo >/dev/null 2>&1 && command -v rustup >/dev/null 2>&1; then
  mk_standins "$T/si"
  SB="$T/sb"   # prefix of the stand-in program fixtures
  E2E=( CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$T/e2e-target" )
  e2e() {  # e2e <crate> [VAR=val ...] -> exit code, real cargo under native
    local crate="$1"; shift
    run "$crate" "$PATH" "$NATIVE" "${E2E[@]}" "$@"
  }
  RC="$R/incident_1/poc/INC-1.2"; mk_e2e "$RC"
  tc="$(rustup default 2>/dev/null | sed -n 's/ (default)$//p')"
  rm -f "$MK"
  ( cd "$RC" && RUSTUP_TOOLCHAIN="$tc" CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$T/ctl-target" cargo build -q >/dev/null 2>&1 ) || true
  if grep -q wrapper "$MK" 2>/dev/null; then ok "control (real cargo): in place, the target's rustc-wrapper runs"; else bad "control (real cargo): the rustc-wrapper did not run in place, so the next check proves nothing"; fi
  rm -f "$MK"
  ( cd "$RC" && env -u RUSTUP_TOOLCHAIN cargo --version >/dev/null 2>&1 ) || true
  if grep -q toolchain "$MK" 2>/dev/null; then ok "control (real rustup): in place, the target's path toolchain runs"; else echo "note: this rustup does not honour a path toolchain in rust-toolchain.toml; that control is skipped"; fi
  rm -f "$MK" "$RC/Cargo.lock"
  code="$(run "$RC" "$PATH" CARGO_NET_OFFLINE=true VULNERABLE_SO="$SB-takeover.so")"
  if [ "$code" = 3 ] && [ ! -e "$MK" ] && [ ! -e "$RC/Cargo.lock" ]; then
    ok "real cargo, no execution mode: exit 3 and nothing compiled (no Cargo.lock, no wrapper or toolchain run)"
  else
    bad "real cargo, no execution mode: exit $code, marker: $(tr '\n' ' ' < "$MK" 2>/dev/null)"
  fi

  # The template as shipped, in the hostile tree: both arms on prebuilt bytes.
  code="$(run "$RC" "$PATH" "$NATIVE" CARGO_NET_OFFLINE=true VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  if [ "$code" = 0 ] && [ ! -e "$MK" ] \
     && grep -qx "${LEG3}$(zhash "$SB-takeover.so") fixed sha256=$(zhash "$SB-reject-MissingRequiredSignature.so") (rejected with the pinned error) → \[PoC-REPRODUCED\]" "$T/out"; then
    ok "real cargo: the template's tests and macros reproduce on prebuilt bytes from the scratch copy, the Leg 3 line printed, no wrapper or path toolchain run"
  else
    bad "real cargo, template: exit $code, marker: $(tr '\n' ' ' < "$MK" 2>/dev/null)"; cat "$T/out" >&2
  fi
  [ -f "$RC/Cargo.lock" ] && ok "real cargo: the resolved Cargo.lock is kept with the crate" || bad "real cargo: Cargo.lock not copied back"
  grep -q "^   non-registry code: .*mollusk-svm 0.13.0 (path $T/si/mollusk)" "$T/out" \
    && ok "real cargo: the non-registry line names the stand-in path dependencies with their directories" || { bad "real cargo: non-registry line"; grep 'non-registry' "$T/out" >&2; }
  # The first run into the shared target dir: it must hold the build afterwards.
  code="$(e2e "$RC" VULNERABLE_SO="$SB-takeover.so")"
  if [ "$code" = 0 ] && grep -qx "${LEG3}$(zhash "$SB-takeover.so") → \[PoC-REPRODUCED\]" "$T/out" && ! grep -q 'running same attack' "$T/out" && [ -d "$T/e2e-target/debug" ]; then
    ok "real cargo: VULNERABLE_SO alone reaches the Leg 3 line, built into an inherited CARGO_TARGET_DIR"
  else
    bad "real cargo, VULNERABLE_SO alone: exit $code"; cat "$T/out" >&2
  fi
  # A target-dir in cargo's own config (here the CARGO_HOME config, which run.sh keeps)
  # is where cargo builds, so the build lock goes there too: a live lock in it holds
  # the run.
  CF="$T/cfg-home"; mkdir -p "$CF" "$T/cfg-target"
  printf '[build]\ntarget-dir = "%s"\n' "$T/cfg-target" > "$CF/config.toml"
  sleep 30 & live=$!
  mkdir -p "$T/cfg-target/.auditor-poc-build.lock"; echo "$live" > "$T/cfg-target/.auditor-poc-build.lock/pid"
  code="$(run "$RC" "$PATH" "$NATIVE" CARGO_NET_OFFLINE=true CARGO_HOME="$CF" POC_LOCK_WAIT=1 VULNERABLE_SO="$SB-takeover.so")"
  kill "$live" 2>/dev/null; wait "$live" 2>/dev/null
  [ "$code" = 3 ] && grep -qF "could not take the build lock in $T/cfg-target " "$T/out" \
    && ok "real cargo: a target-dir in cargo's own config is where the build lock goes" || { bad "real cargo, target-dir from cargo's config: exit $code"; cat "$T/out" >&2; }
  rm -rf "$T/cfg-target/.auditor-poc-build.lock"

  # Dependency pins with real cargo, against a vendored directory registry that stands
  # in for crates.io (the user's own CARGO_HOME config, which run.sh keeps): the
  # crate's Cargo.lock is what resolves, a newer compatible release stays out until
  # UPDATE_PINS moves that pin alone, and a crate without a lock says so.
  V="$T/vendored"; CH="$T/cargo-home"
  mk_vendored() {  # mk_vendored <version>: the stand-in crate `pinme` at <version>
    mkdir -p "$V/pinme-$1/src"
    printf '[package]\nname = "pinme"\nversion = "%s"\nedition = "2021"\n' "$1" > "$V/pinme-$1/Cargo.toml"
    printf 'pub const VERSION: &str = "%s";\n' "$1" > "$V/pinme-$1/src/lib.rs"
    printf '{"files":{},"package":null}\n' > "$V/pinme-$1/.cargo-checksum.json"
  }
  pinned() { sed -n '/^name = "pinme"$/{n;s/^version = "\(.*\)"$/\1/p;}' "$1"; }
  mk_vendored 1.0.0
  mkdir -p "$CH"; printf '[source.crates-io]\nreplace-with = "vendored"\n\n[source.vendored]\ndirectory = "%s"\n' "$V" > "$CH/config.toml"
  mk_e2e "$T/e-lock"; printf 'pinme = "1"\n' >> "$T/e-lock/Cargo.toml"
  code="$(e2e "$T/e-lock" CARGO_HOME="$CH" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 0 ] && grep -q '^>> no Cargo.lock in the crate' "$T/out" && [ "$(pinned "$T/e-lock/Cargo.lock")" = 1.0.0 ] \
    && ok "real cargo: a crate without a lock says so, and the lock it resolves (pinme 1.0.0) comes back with it" || { bad "real cargo, first lock: exit $code"; cat "$T/out" >&2; }
  mk_vendored 1.1.0
  code="$(e2e "$T/e-lock" CARGO_HOME="$CH" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 0 ] && ! grep -q 'no Cargo.lock' "$T/out" && [ "$(pinned "$T/e-lock/Cargo.lock")" = 1.0.0 ] \
    && ok "real cargo: the crate's lock is what resolves: pinme stays at 1.0.0 with 1.1.0 available" || { bad "real cargo, kept pin: exit $code"; cat "$T/out" >&2; }
  code="$(e2e "$T/e-lock" CARGO_HOME="$CH" VULNERABLE_SO="$SB-takeover.so" UPDATE_PINS=pinme@1.0.0)"
  [ "$code" = 0 ] && grep -q '^>> moving the pinme@1.0.0 pin' "$T/out" && [ "$(pinned "$T/e-lock/Cargo.lock")" = 1.1.0 ] \
    && ok "real cargo: UPDATE_PINS=pinme@1.0.0 moves that pin (to 1.1.0) in the scratch copy, and the moved lock comes back" || { bad "real cargo, UPDATE_PINS: exit $code"; cat "$T/out" >&2; }

  # Two crates of the same name share a CARGO_TARGET_DIR: each run builds and runs its
  # own tests, even when the other crate was built after this one's files last changed.
  mk_e2e "$T/e-twin-old"; mk_e2e "$T/e-twin-new"
  swap "$T/e-twin-new/tests/fixed_blocked.rs" '/^        error: ProgramError::MissingRequiredSignature,$/ { print "        error: ProgramError::Custom(6001),"; next } { print }'
  find "$T/e-twin-old" -type f -exec touch -t 202001010000 {} +
  code="$(e2e "$T/e-twin-new" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom6001.so")"
  code2="$(e2e "$T/e-twin-old" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom6001.so")"
  [ "$code" = 0 ] && [ "$code2" = 2 ] && grep -q 'REJECTED with Failure(MissingRequiredSignature)' "$T/out" \
    && ok "real cargo: a crate whose files predate another same-named crate's build in the shared cache still runs its own tests" || { bad "real cargo, same-named crates in one cache: exit $code then $code2"; cat "$T/out" >&2; }

  # The test binary runs as cargo test runs it: CARGO_MANIFEST_DIR is the package
  # root it starts in, and the dynamic library path starts with its own directory.
  mk_e2e "$T/e-env"
  subst "$T/e-env/tests/exploit.rs" '    assert_exploit_effect!(' '    let lib_var = if cfg!(target_os = "macos") { "DYLD_FALLBACK_LIBRARY_PATH" } else { "LD_LIBRARY_PATH" };
    let first = std::env::var_os(lib_var).and_then(|v| std::env::split_paths(&v).next()).and_then(|p| std::fs::canonicalize(p).ok());
    let own = std::env::current_exe().ok().and_then(|p| p.parent().and_then(|d| std::fs::canonicalize(d).ok()));
    assert!(first.is_some() && first == own, "dynamic library path {first:?}, test binary in {own:?}");
    let root = std::env::var_os("CARGO_MANIFEST_DIR").map(std::path::PathBuf::from);
    assert_eq!(root, std::env::current_dir().ok(), "CARGO_MANIFEST_DIR is the package root the test starts in");
    assert_exploit_effect!('
  code="$(e2e "$T/e-env" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 0 ] && ok "real cargo: the test binary runs from the package root, with CARGO_MANIFEST_DIR and the dynamic library path cargo gives it" || { bad "real cargo, test binary environment: exit $code"; cat "$T/out" >&2; }

  # Results the contract must turn down, outside the hostile tree.
  mk_e2e "$T/e-base"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-noop.so")"
  [ "$code" = 1 ] && grep -q 'after the attack .* reads' "$T/out" && ok "real cargo: bytes that accept the call but change nothing -> exit 1 (Ok is not the effect)" || bad "real cargo, noop bytes: exit $code"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-dirty-reject.so")"
  [ "$code" = 1 ] && grep -q 'expected to SUCCEED and change' "$T/out" && ok "real cargo: an exploit that fails, even with the account changed, -> exit 1 (the effect needs success)" || bad "real cargo, failed exploit with a change: exit $code"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-takeover.so")"
  [ "$code" = 2 ] && grep -q '^FAIL: the fixed arm accepted the attack' "$T/out" && ok "real cargo: fixed bytes that let the attack through -> exit 2, 'the fixed arm accepted the attack'" || bad "real cargo, fix lets it through: exit $code"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom6001.so")"
  [ "$code" = 2 ] && grep -q 'REJECTED with Failure(MissingRequiredSignature)' "$T/out" && grep -q '^FAIL: the fixed arm rejected the attack with another error than the pinned one' "$T/out" \
    && ok "real cargo: a rejection with another error than the pinned one -> exit 2, a final line of its own" || bad "real cargo, other error: exit $code"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom4100.so")"
  [ "$code" = 3 ] && grep -q 'inconclusive: a harness error, not a guard: Failure(Custom(4100))' "$T/out" && ok "real cargo: Custom(4100) (wrong program id) on the fixed arm -> inconclusive, exit 3" || bad "real cargo, 4100: exit $code"
  # A harness error is inconclusive on the vulnerable arm too: never "did not reproduce".
  # ro-modified returns UnknownError(ReadonlyDataModified), one of the account-list
  # mismatches the classifier now also catches.
  for name in Custom4100 NotEnoughAccountKeys; do
    code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-reject-$name.so")"
    [ "$code" = 3 ] && grep -q 'the vulnerable arm is inconclusive: a harness error, not a guard' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
      && ok "real cargo: a harness error ($name) on the vulnerable arm -> inconclusive, exit 3, not 1" || { bad "real cargo, vulnerable $name: exit $code"; cat "$T/out" >&2; }
  done
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-ro-modified.so")"
  [ "$code" = 3 ] && grep -q 'inconclusive: a harness error, not a guard: UnknownError(ReadonlyDataModified)' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
    && ok "real cargo: UnknownError(ReadonlyDataModified) on the vulnerable arm -> inconclusive, exit 3" || { bad "real cargo, ReadonlyDataModified: exit $code"; cat "$T/out" >&2; }
  mkdir -p "$T/bpf"; cp "$SB-takeover.so" "$T/bpf/poc_e2e.so"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-noop.so" BPF_OUT_DIR="$T/bpf")"
  [ "$code" = 1 ] && ok "real cargo: a caller's BPF_OUT_DIR holding other bytes is not what runs (exit 1 on the no-op bytes)" || bad "real cargo, BPF_OUT_DIR: exit $code"

  # Assertions that do not run or do not pin anything leave no marker.
  mk_e2e "$T/e-dead"
  drop_block "$T/e-dead/tests/exploit.rs" '^    assert_exploit_effect!\($'
  swap "$T/e-dead/tests/exploit.rs" '/^    let _ = SYSTEM_PROGRAM_ID;/ {
    print "    // assert_exploit_effect!(mollusk, ix: &ix, accounts: &accounts, ...)"
    print "    let _ = \"assert_exploit_effect!(mollusk)\";"
    print "    if accounts.is_empty() {"
    print "        assert_exploit_effect!(mollusk, ix: &ix, accounts: &accounts, account: state_pk,"
    print "            read: |a| a.data[0..32].to_vec(), expect: attacker.to_bytes().to_vec(), why: \"never runs\");"
    print "    }"
    print "    shared_test_utils::assert_exploit_succeeds!(mollusk, ix: &ix, accounts: &accounts, why: \"Ok only\");"
  } { print }'
  code="$(e2e "$T/e-dead" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'no assert_exploit_effect! ran and held' "$T/out" \
    && ok "real cargo: the effect assertion only in a comment, a string and dead code, plus the any-Ok one -> exit 3" || { bad "real cargo, dead effect assertion: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-any"
  drop_block "$T/e-any/tests/fixed_blocked.rs" '^    assert_exploit_rejected_with!\($'
  swap "$T/e-any/tests/fixed_blocked.rs" '/^    \/\/ A hotfix the team already deployed/ { print "    shared_test_utils::assert_exploit_rejected!(mollusk, ix: &ix, accounts: &accounts, why: \"any error\");" } { print }'
  code="$(e2e "$T/e-any" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'neither assert_exploit_rejected_with! nor assert_exploit_blocked! ran and held' "$T/out" \
    && ok "real cargo: the any-error assertion on the fixed arm -> exit 3" || { bad "real cargo, any-error fixed arm: exit $code"; cat "$T/out" >&2; }
  # An effect the account already held before the attack shows nothing: inconclusive,
  # whether the expected value was there from the start or a setup run of the same
  # attack put it there.
  mk_e2e "$T/e-same"
  swap "$T/e-same/tests/exploit.rs" '/^        expect: attacker.to_bytes\(\).to_vec\(\),$/ { print "        expect: legit_authority.to_bytes().to_vec(),"; next } { print }'
  code="$(e2e "$T/e-same" VULNERABLE_SO="$SB-noop.so")"
  [ "$code" = 3 ] && grep -q 'before the attack, so this run cannot show an effect' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
    && ok "real cargo: an expected value the account already held -> exit 3 (inconclusive), not 1" || { bad "real cargo, unchanged expectation: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-replay"
  subst "$T/e-replay/tests/exploit.rs" '    assert_exploit_effect!(' '    let setup = mollusk.process_instruction(&ix, &accounts);
    let accounts = setup.resulting_accounts.clone();
    assert_exploit_effect!('
  code="$(e2e "$T/e-replay" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'before the attack, so this run cannot show an effect' "$T/out" \
    && ok "real cargo: the attack's result handed to the macro as its starting state -> exit 3, no effect shown" || { bad "real cargo, replayed setup: exit $code"; cat "$T/out" >&2; }
  # A runner panic inside the macro happens before its attempted marker: exit 3, not 1.
  mk_e2e "$T/e-short"
  subst "$T/e-short/tests/exploit.rs" '            AccountMeta::new_readonly(attacker, true),         // attacker submits the tx
' ''
  code="$(e2e "$T/e-short" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
    && ok "real cargo: a runner that panics inside the macro (too few accounts) -> exit 3, not 1" || { bad "real cargo, runner panic: exit $code"; cat "$T/out" >&2; }
  # A read that panics on the account decides nothing either.
  mk_e2e "$T/e-read"
  swap "$T/e-read/tests/exploit.rs" '/^        read: \|a\| a.data\[0..32\].to_vec\(\),$/ { print "        read: |a| a.data[64..96].to_vec(),"; next } { print }'
  code="$(e2e "$T/e-read" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'panicked, so it does not fit the account' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
    && ok "real cargo: a read that panics on the account -> exit 3, not 1" || { bad "real cargo, panicking read: exit $code"; cat "$T/out" >&2; }
  for pat in '_' 'ProgramError::Custom(_)'; do
    mk_e2e "$T/e-pat"
    swap "$T/e-pat/tests/fixed_blocked.rs" '/^        error: ProgramError::MissingRequiredSignature,$/ { print "        error: '"$pat"',"; next } { print }'
    code="$(e2e "$T/e-pat" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
    [ "$code" = 3 ] && grep -q 'tests/fixed_blocked.rs failed to build' "$T/out" \
      && ok "real cargo: a pattern ($pat) as the expected error does not compile -> exit 3" || { bad "real cargo, pattern $pat: exit $code"; cat "$T/out" >&2; }
    rm -rf "$T/e-pat"
  done
  # A pinned harness-class error holds, and its marker says the vulnerable arm, running
  # the same attack, is its positive control.
  mk_e2e "$T/e-pinned"
  swap "$T/e-pinned/tests/fixed_blocked.rs" '/^        error: ProgramError::MissingRequiredSignature,$/ { print "        error: ProgramError::NotEnoughAccountKeys,"; next } { print }'
  code="$(e2e "$T/e-pinned" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-NotEnoughAccountKeys.so")"
  [ "$code" = 0 ] && grep -q '^   fixed arm: .*a harness-class error .* is its positive control' "$T/out" && grep -q '(rejected with the pinned error)' "$T/out" \
    && ok "real cargo: a pinned harness-class error holds, and the run output names the vulnerable arm as its control" || { bad "real cargo, pinned harness-class error: exit $code"; cat "$T/out" >&2; }

  # The old macro forms, which took a result and before-state from the test, no longer
  # compile; the error says how to migrate.
  mk_e2e "$T/e-old"
  subst "$T/e-old/tests/exploit.rs" '    assert_exploit_effect!(
        mollusk,
        ix: &ix,
        accounts: &accounts,' '    let outcome = mollusk.process_instruction(&ix, &accounts);
    assert_exploit_effect!(
        outcome,
        before: &accounts,'
  code="$(e2e "$T/e-old" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'tests/exploit.rs failed to build' "$T/out" && grep -q 'assert_exploit_effect! now runs the attack itself' "$T/out" \
    && ok "real cargo: the old assert_exploit_effect!(outcome, before: ...) form fails to build with the migration -> exit 3" || { bad "real cargo, old effect form: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-old"
  subst "$T/e-old/tests/fixed_blocked.rs" '    assert_exploit_rejected_with!(
        mollusk,
        ix: &ix,
        accounts: &accounts,
        error: ProgramError::MissingRequiredSignature,
        why: "{WHICH_GUARD_BLOCKS_IT}",
    );' '    let outcome = mollusk.process_instruction(&ix, &accounts);
    assert_exploit_rejected_with!(outcome, ProgramError::MissingRequiredSignature, "old form");'
  code="$(e2e "$T/e-old" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'tests/fixed_blocked.rs failed to build' "$T/out" && grep -q 'assert_exploit_rejected_with! now runs the attack itself' "$T/out" \
    && ok "real cargo: the old assert_exploit_rejected_with!(outcome, error, why) form fails to build with the migration -> exit 3" || { bad "real cargo, old rejected_with form: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-old"
  subst "$T/e-old/tests/fixed_blocked.rs" '    assert_exploit_rejected_with!(
        mollusk,
        ix: &ix,
        accounts: &accounts,
        error: ProgramError::MissingRequiredSignature,
        why: "{WHICH_GUARD_BLOCKS_IT}",
    );' '    let outcome = mollusk.process_instruction(&ix, &accounts);
    shared_test_utils::assert_exploit_blocked!(outcome, before: &accounts, control: outcome.clone(),
        control_before: &accounts, account: state_pk, read: |a| a.data[0..32].to_vec(), why: "old form");
    let _ = ProgramError::MissingRequiredSignature;'
  code="$(e2e "$T/e-old" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'assert_exploit_blocked! now runs the attack and its positive control itself' "$T/out" \
    && ok "real cargo: the old assert_exploit_blocked!(outcome, before: ...) form fails to build with the migration -> exit 3" || { bad "real cargo, old blocked form: exit $code"; cat "$T/out" >&2; }
  # The any-result forms ran on a result the test handed them, too; that form is gone.
  mk_e2e "$T/e-old"
  subst "$T/e-old/tests/exploit.rs" '    assert_exploit_effect!(' '    let outcome = mollusk.process_instruction(&ix, &accounts);
    shared_test_utils::assert_exploit_succeeds!(outcome, "old form");
    assert_exploit_effect!('
  code="$(e2e "$T/e-old" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'tests/exploit.rs failed to build' "$T/out" && grep -q 'assert_exploit_succeeds! now runs the attack itself' "$T/out" \
    && ok "real cargo: the old assert_exploit_succeeds!(outcome, why) form fails to build with the migration -> exit 3" || { bad "real cargo, old succeeds form: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-old"
  subst "$T/e-old/tests/fixed_blocked.rs" '    assert_exploit_rejected_with!(' '    let outcome = mollusk.process_instruction(&ix, &accounts);
    shared_test_utils::assert_exploit_rejected!(outcome, "old form");
    assert_exploit_rejected_with!('
  code="$(e2e "$T/e-old" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'tests/fixed_blocked.rs failed to build' "$T/out" && grep -q 'assert_exploit_rejected! now runs the attack itself' "$T/out" \
    && ok "real cargo: the old assert_exploit_rejected!(outcome, why) form fails to build with the migration -> exit 3" || { bad "real cargo, old rejected form: exit $code"; cat "$T/out" >&2; }

  # One test's inconclusive result does not hide another test's failed assertion.
  mk_e2e "$T/e-mask"
  cat >> "$T/e-mask/tests/fixed_blocked.rs" <<'RS'

#[test]
fn another_test_that_cannot_decide() {
    let _ = shared_test_utils::mollusk_for(shared_test_utils::random_pubkey(), "elsewhere/poc_e2e");
}
RS
  code="$(e2e "$T/e-mask" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-takeover.so")"
  [ "$code" = 2 ] && grep -q 'fix is incomplete' "$T/out" && grep -q '^   failed: test same_attack_rejected_on_fixed$' "$T/out" \
    && ok "real cargo: a fixed arm whose pinned-error test fails next to an inconclusive test -> exit 2, naming the test" || { bad "real cargo, failed next to inconclusive: exit $code"; cat "$T/out" >&2; }

  # A program that does not load, or a test that fails before its contract assertion
  # ran, decides nothing: exit 3, never 1 or 2.
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-unloadable.so")"
  [ "$code" = 3 ] && grep -q 'did not load as a program' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
    && ok "real cargo: fixed bytes the loader rejects -> inconclusive, exit 3, not 2" || { bad "real cargo, unloadable fixed bytes: exit $code"; cat "$T/out" >&2; }
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-unloadable.so")"
  [ "$code" = 3 ] && grep -q 'did not load as a program' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
    && ok "real cargo: vulnerable bytes the loader rejects -> inconclusive, exit 3, not 1" || { bad "real cargo, unloadable vulnerable bytes: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-panic"
  subst "$T/e-panic/tests/fixed_blocked.rs" '    assert_exploit_rejected_with!(' '    panic!("the setup failed");
    #[allow(unreachable_code)]
    assert_exploit_rejected_with!('
  code="$(e2e "$T/e-panic" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
    && ok "real cargo: a fixed-arm test that panics before its contract assertion -> exit 3, not 2" || { bad "real cargo, panic before the assertion: exit $code"; cat "$T/out" >&2; }

  # The Leg 3 line names the bytes that ran: a test that loads other bytes than the
  # placed arm — another file, a path, a runner made without mollusk_for — gets none.
  mk_e2e "$T/e-other"; cp "$SB-takeover.so" "$T/e-other/other.so"
  subst "$T/e-other/tests/exploit.rs" 'mollusk_for(program_id, "poc_e2e")' 'mollusk_for(program_id, "other")'
  code="$(e2e "$T/e-other" VULNERABLE_SO="$SB-noop.so")"
  [ "$code" = 3 ] && grep -q 'loaded bytes other than the ones run.sh placed' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
    && ok "real cargo: an exploit run on another .so than the placed one -> exit 3, no Leg 3 line" || { bad "real cargo, other .so: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-abs"
  subst "$T/e-abs/tests/exploit.rs" 'mollusk_for(program_id, "poc_e2e")' "mollusk_for(program_id, \"$SB-takeover\")"
  code="$(e2e "$T/e-abs" VULNERABLE_SO="$SB-noop.so")"
  [ "$code" = 3 ] && grep -q 'refuses the program name' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
    && ok "real cargo: mollusk_for refuses a program name holding '/' -> exit 3, no Leg 3 line" || { bad "real cargo, a path as the name: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-direct"
  subst "$T/e-direct/tests/exploit.rs" 'mollusk_for(program_id, "poc_e2e")' "mollusk_svm::Mollusk::new(&program_id, \"$SB-takeover\")"
  code="$(e2e "$T/e-direct" VULNERABLE_SO="$SB-noop.so")"
  [ "$code" = 3 ] && grep -q 'no program was loaded through mollusk_for' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
    && ok "real cargo: a runner made with Mollusk::new, not mollusk_for -> exit 3, no Leg 3 line" || { bad "real cargo, Mollusk::new: exit $code"; cat "$T/out" >&2; }
  # The attack must target the program mollusk_for loaded: an instruction aimed at a
  # different program id is inconclusive, even though the stand-in would act on it.
  mk_e2e "$T/e-wrongprog"
  subst "$T/e-wrongprog/tests/exploit.rs" '    let ix = Instruction {
        program_id,' '    let elsewhere = random_pubkey();
    let ix = Instruction {
        program_id: elsewhere,'
  code="$(e2e "$T/e-wrongprog" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'the attack targets .* not .* the program run.sh placed and the harness loaded' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
    && ok "real cargo: an attack aimed at a program mollusk_for did not load -> exit 3, no Leg 3 line" || { bad "real cargo, attack on another program: exit $code"; cat "$T/out" >&2; }

  # The crate's own build-time code, with real cargo metadata: a build script that would
  # leave a file never runs, whether it is the crate's, a member's, or that of a path
  # dependency kept out of the workspace; a proc-macro member is refused too, and
  # `build = false` is honoured. The control shows the script runs in an ordinary build.
  BUILT="$T/build-script.ran"
  bs() { printf 'fn main() { let _ = std::fs::write("%s", "ran"); }\n' "$BUILT" > "$1"; }
  mk_e2e "$T/e-bs"; bs "$T/e-bs/build.rs"
  rm -f "$BUILT"; ( cd "$T/e-bs" && CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$T/ctl-target" cargo build -q >/dev/null 2>&1 ) || true
  [ -e "$BUILT" ] && ok "control (real cargo): built in place, the crate's build script runs" || bad "control (real cargo): the build script did not run in place, so the next checks prove nothing"
  rm -f "$BUILT" "$T/e-bs/Cargo.lock"
  code="$(e2e "$T/e-bs" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'build.rs is a build script of poc_e2e' "$T/out" && [ ! -e "$BUILT" ] \
    && ok "real cargo: the crate's build.rs -> refused before anything compiles; it never ran" || { bad "real cargo, crate build.rs: exit $code"; cat "$T/out" >&2; }
  subst "$T/e-bs/Cargo.toml" 'publish = false' 'publish = false
build = false'
  code="$(e2e "$T/e-bs" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 0 ] && [ ! -e "$BUILT" ] && ok "real cargo: build = false is honoured: the run goes ahead and the script never runs" || { bad "real cargo, build = false: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-bs2"; bs "$T/e-bs2/shared-test-utils/build.rs"
  code="$(e2e "$T/e-bs2" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'shared-test-utils/build.rs is a build script of shared-test-utils' "$T/out" && [ ! -e "$BUILT" ] \
    && ok "real cargo: a member's build.rs (shared-test-utils) -> refused; it never ran" || { bad "real cargo, member build.rs: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-out"; mkdir -p "$T/e-out/inner/src"; bs "$T/e-out/inner/build.rs"; : > "$T/e-out/inner/src/lib.rs"
  printf '[package]\nname = "inner"\nversion = "0.1.0"\nedition = "2021"\n' > "$T/e-out/inner/Cargo.toml"
  subst "$T/e-out/Cargo.toml" '[workspace]' '[workspace]
exclude = ["inner"]'
  printf 'inner = { path = "inner" }\n' >> "$T/e-out/Cargo.toml"
  code="$(e2e "$T/e-out" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'inner/Cargo.toml is not a member' "$T/out" && [ ! -e "$BUILT" ] \
    && ok "real cargo: a path dependency in the crate kept out of the workspace -> refused; its build script never ran" || { bad "real cargo, excluded path dependency: exit $code"; cat "$T/out" >&2; }
  for spelling in proc-macro proc_macro; do
    mk_e2e "$T/e-pm"; mkdir -p "$T/e-pm/pm/src"; : > "$T/e-pm/pm/src/lib.rs"
    printf '[package]\nname = "pm"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\n%s = true\n' "$spelling" > "$T/e-pm/pm/Cargo.toml"
    printf 'pm = { path = "pm" }\n' >> "$T/e-pm/Cargo.toml"
    code="$(e2e "$T/e-pm" VULNERABLE_SO="$SB-takeover.so")"
    [ "$code" = 3 ] && grep -q 'pm (pm/src/lib.rs) is a proc-macro package' "$T/out" \
      && ok "real cargo: a proc-macro member ($spelling = true) -> refused before anything compiles" || { bad "real cargo, proc-macro ($spelling): exit $code"; cat "$T/out" >&2; }
    rm -rf "$T/e-pm"
  done
  mk_e2e "$T/e-patch"; printf '\n[patch.crates-io]\npinme = { path = "%s/pinme-1.0.0" }\n' "$V" >> "$T/e-patch/Cargo.toml"
  code="$(e2e "$T/e-patch" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'holds a \[patch\] or \[replace\] table' "$T/out" \
    && ok "real cargo: a [patch] table cargo accepts -> refused before anything compiles" || { bad "real cargo, [patch]: exit $code"; cat "$T/out" >&2; }

  # The deployed-hotfix check: the template's commented replacement, swapped in as
  # written. It counts only with its positive control: the legitimate call goes through
  # on the same bytes and changes the account, for the same program, from the same state.
  mk_e2e "$T/e-hotfix"
  drop_block "$T/e-hotfix/tests/fixed_blocked.rs" '^    assert_exploit_rejected_with!\($'
  swap "$T/e-hotfix/tests/fixed_blocked.rs" 'index($0, "    //   // {LEGITIMATE_CALL}") == 1 { on = 1 } on { line = $0; sub(/^    \/\/   /, "    ", line); print line; if ($0 ~ /^    \/\/   \);$/) on = 0; next } { print }'
  if grep -q '^        control_ix: &legit_ix,$' "$T/e-hotfix/tests/fixed_blocked.rs" \
     && grep -q '^    shared_test_utils::assert_exploit_blocked!($' "$T/e-hotfix/tests/fixed_blocked.rs" \
     && ! grep -q '^    assert_exploit_rejected_with!' "$T/e-hotfix/tests/fixed_blocked.rs"; then
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-guard-Custom6001.so")"
    [ "$code" = 0 ] && grep -qx "${LEG3}$(zhash "$SB-takeover.so") fixed sha256=$(zhash "$SB-guard-Custom6001.so") (blocked: failed, account unchanged) → \[PoC-REPRODUCED\]" "$T/out" \
      && ok "real cargo: the template's hotfix replacement compiles, and a hotfix with its own error (Custom(6001)) whose legitimate call goes through counts as blocked" || { bad "real cargo, hotfix guard Custom(6001): exit $code"; cat "$T/out" >&2; }
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-InvalidInstructionData.so" KEEP_POC_BUILD=1)"
    bd="$(build_dir)"
    if [ "$code" = 3 ] && grep -q 'inconclusive: the legitimate call failed on these bytes (Failure(InvalidInstructionData))' "$T/out" \
       && [ -n "$bd" ] && [ -s "$bd/markers/fixed/attempted" ] && [ ! -e "$bd/markers/fixed/blocked" ] && ! grep -q "^$LEG3" "$T/out"; then
      ok "real cargo: a fixed program that fails every call, the legitimate one too, is not blocked -> exit 3, no blocked marker"
    else
      bad "real cargo, hotfix failing every call: exit $code"; cat "$T/out" >&2
    fi
    [ -n "$bd" ] && rm -rf "$bd"
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-noop.so")"
    [ "$code" = 3 ] && grep -q 'the legitimate call went through but left' "$T/out" \
      && ok "real cargo: a hotfix check whose legitimate call changes nothing -> inconclusive, exit 3" || { bad "real cargo, hotfix no-op control: exit $code"; cat "$T/out" >&2; }
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-takeover.so")"
    [ "$code" = 2 ] && grep -q 'expected to be BLOCKED' "$T/out" && grep -q '^FAIL: the fixed arm accepted the attack' "$T/out" && ok "real cargo: a hotfix that lets the attack through -> exit 2" || bad "real cargo, hotfix lets it through: exit $code"
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-dirty-guard.so")"
    [ "$code" = 2 ] && grep -q 'yet .* changed' "$T/out" && grep -q '^FAIL: the fixed arm failed the attack, yet the account changed' "$T/out" \
      && ok "real cargo: a hotfix run that fails but still changes the account is not blocked -> exit 2, a final line of its own" || bad "real cargo, hotfix fails with a change: exit $code"
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-guard-Custom4100.so")"
    [ "$code" = 3 ] && grep -q 'inconclusive: a harness error, not a guard' "$T/out" && ok "real cargo: a hotfix check whose attack fails on Custom(4100) -> inconclusive, exit 3" || bad "real cargo, hotfix 4100: exit $code"
    cp -R "$T/e-hotfix" "$T/e-ctl-id"
    subst "$T/e-ctl-id/tests/fixed_blocked.rs" '    let legit_ix = Instruction {
        program_id,' '    let legit_ix = Instruction {
        program_id: random_pubkey(),'
    code="$(e2e "$T/e-ctl-id" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-guard-Custom6001.so")"
    [ "$code" = 3 ] && grep -q 'the control shows nothing about the program the attack targets' "$T/out" \
      && ok "real cargo: a positive control for another program id -> inconclusive, exit 3" || { bad "real cargo, control for another program: exit $code"; cat "$T/out" >&2; }
    cp -R "$T/e-hotfix" "$T/e-ctl-state"
    subst "$T/e-ctl-state/tests/fixed_blocked.rs" '        accounts[0].clone(),' '        (state_pk, program_owned_account(program_id, vec![7; State::LEN])),'
    code="$(e2e "$T/e-ctl-state" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-guard-Custom6001.so")"
    [ "$code" = 3 ] && grep -q 'from another state than the attack' "$T/out" \
      && ok "real cargo: a positive control from another state of the account -> inconclusive, exit 3" || { bad "real cargo, control from another state: exit $code"; cat "$T/out" >&2; }
  else
    bad "real cargo: could not swap in the template's commented assert_exploit_blocked! replacement"
  fi

  # The LiteSVM forms: litesvm_for! loads and records the bytes, and the macros send one
  # transaction, read the account before and after, and leave the same markers, so a
  # LiteSVM PoC reaches the same lines, the Leg 3 line included.
  mk_lite() {  # mk_lite <dir> <fixed-arm assertion: rejected_with | blocked>
    mk_e2e "$1"
    printf 'litesvm = { path = "%s/litesvm" }\n' "$T/si" >> "$1/Cargo.toml"
    cat > "$1/tests/exploit.rs" <<'RS'
#![cfg(feature = "vulnerable")]
use shared_test_utils::{assert_exploit_effect, litesvm_for, program_owned_account, random_pubkey, system_account};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::transaction::Transaction;

#[test]
fn exploit_succeeds_on_vulnerable() {
    let program_id = random_pubkey();
    let mut svm = litesvm_for!(program_id, "poc_e2e");
    let (legit_authority, attacker, state_pk) = (random_pubkey(), random_pubkey(), random_pubkey());
    svm.set_account(state_pk, program_owned_account(program_id, legit_authority.to_bytes().to_vec())).expect("state");
    svm.set_account(attacker, system_account(1_000_000_000)).expect("attacker");
    let ix = Instruction {
        program_id: TARGET,
        accounts: vec![
            AccountMeta::new(state_pk, false),
            AccountMeta::new_readonly(legit_authority, false),
            AccountMeta::new_readonly(attacker, true),
        ],
        data: vec![],
    };
    assert_exploit_effect!(svm, tx: Transaction::new_with_payer(&[ix], Some(&attacker)), account: state_pk,
        read: |a| a.data[0..32].to_vec(), expect: attacker.to_bytes().to_vec(), why: "the attacker holds the authority");
}
RS
    subst "$1/tests/exploit.rs" 'program_id: TARGET,' 'program_id,'
    cat > "$1/tests/fixed_blocked.rs" <<'RS'
#![cfg(feature = "fixed")]
use shared_test_utils::{litesvm_for, program_owned_account, random_pubkey, system_account};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::program_error::ProgramError;
use solana_sdk::transaction::Transaction;

#[test]
fn same_attack_rejected_on_fixed() {
    let program_id = random_pubkey();
    let mut svm = litesvm_for!(program_id, "poc_e2e");
    let (legit_authority, attacker, state_pk) = (random_pubkey(), random_pubkey(), random_pubkey());
    svm.set_account(state_pk, program_owned_account(program_id, legit_authority.to_bytes().to_vec())).expect("state");
    svm.set_account(attacker, system_account(1_000_000_000)).expect("attacker");
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(state_pk, false),
            AccountMeta::new_readonly(legit_authority, false),
            AccountMeta::new_readonly(attacker, true),
        ],
        data: vec![],
    };
    let next_authority = random_pubkey();
    let legit_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(state_pk, false),
            AccountMeta::new_readonly(legit_authority, true),
            AccountMeta::new_readonly(next_authority, false),
        ],
        data: vec![],
    };
    let _ = (&legit_ix, ProgramError::MissingRequiredSignature);
    ASSERTION
}
RS
    if [ "$2" = rejected_with ]; then
      subst "$1/tests/fixed_blocked.rs" '    ASSERTION' '    shared_test_utils::assert_exploit_rejected_with!(svm, tx: Transaction::new_with_payer(&[ix], Some(&attacker)),
        error: ProgramError::MissingRequiredSignature, why: "the restored signer check");'
    else
      subst "$1/tests/fixed_blocked.rs" '    ASSERTION' '    shared_test_utils::assert_exploit_blocked!(svm, tx: Transaction::new_with_payer(&[ix], Some(&attacker)),
        control_tx: Transaction::new_with_payer(&[legit_ix], Some(&legit_authority)), account: state_pk,
        read: |a| a.data[0..32].to_vec(), why: "the deployed hotfix keeps the authority");'
    fi
  }
  mk_lite "$T/e-lite" rejected_with
  code="$(e2e "$T/e-lite" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 0 ] && grep -qx "${LEG3}$(zhash "$SB-takeover.so") fixed sha256=$(zhash "$SB-reject-MissingRequiredSignature.so") (rejected with the pinned error) → \[PoC-REPRODUCED\]" "$T/out" \
    && ok "real cargo, LiteSVM: litesvm_for! and the transaction forms reach the Leg 3 line with the pinned error" || { bad "real cargo, LiteSVM: exit $code"; cat "$T/out" >&2; }
  code="$(e2e "$T/e-lite" VULNERABLE_SO="$SB-noop.so")"
  [ "$code" = 1 ] && grep -q 'after the attack .* reads' "$T/out" && ok "real cargo, LiteSVM: bytes that change nothing -> exit 1" || { bad "real cargo, LiteSVM noop: exit $code"; cat "$T/out" >&2; }
  code="$(e2e "$T/e-lite" VULNERABLE_SO="$SB-reject-Custom4100.so")"
  [ "$code" = 3 ] && grep -q 'a harness error, not a guard: InstructionError(0, Custom(4100))' "$T/out" \
    && ok "real cargo, LiteSVM: a harness error on the vulnerable arm -> exit 3, not 1" || { bad "real cargo, LiteSVM 4100: exit $code"; cat "$T/out" >&2; }
  code="$(e2e "$T/e-lite" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom6001.so")"
  [ "$code" = 2 ] && grep -q 'REJECTED with Failure(MissingRequiredSignature)' "$T/out" && grep -q '^FAIL: the fixed arm rejected the attack with another error than the pinned one' "$T/out" \
    && ok "real cargo, LiteSVM: a rejection with another error than the pinned one -> exit 2" || { bad "real cargo, LiteSVM other error: exit $code"; cat "$T/out" >&2; }
  code="$(e2e "$T/e-lite" VULNERABLE_SO="$SB-unloadable.so")"
  [ "$code" = 3 ] && grep -q 'did not load as a program' "$T/out" && ok "real cargo, LiteSVM: bytes litesvm_for! cannot load -> exit 3" || { bad "real cargo, LiteSVM unloadable: exit $code"; cat "$T/out" >&2; }
  mk_lite "$T/e-lite-other" rejected_with
  subst "$T/e-lite-other/tests/exploit.rs" '        program_id,
        accounts: vec![' '        program_id: random_pubkey(),
        accounts: vec!['
  code="$(e2e "$T/e-lite-other" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'the vulnerable arm is inconclusive: the attack targets .* not .* the program run.sh placed' "$T/out" \
    && ok "real cargo, LiteSVM: an attack on a program the runner does not hold -> exit 3" || { bad "real cargo, LiteSVM unknown program: exit $code"; cat "$T/out" >&2; }
  mk_lite "$T/e-lite-hotfix" blocked
  code="$(e2e "$T/e-lite-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-guard-Custom6001.so")"
  [ "$code" = 0 ] && grep -q '(blocked: failed, account unchanged) → \[PoC-REPRODUCED\]' "$T/out" \
    && ok "real cargo, LiteSVM: the blocked form runs its control on a clone of the runner and counts as blocked" || { bad "real cargo, LiteSVM hotfix: exit $code"; cat "$T/out" >&2; }
  code="$(e2e "$T/e-lite-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-takeover.so")"
  [ "$code" = 2 ] && grep -q 'expected to be BLOCKED' "$T/out" && grep -q '^FAIL: the fixed arm accepted the attack' "$T/out" && ok "real cargo, LiteSVM: a hotfix that lets the attack through -> exit 2" || { bad "real cargo, LiteSVM hotfix through: exit $code"; cat "$T/out" >&2; }
  code="$(e2e "$T/e-lite-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-InvalidInstructionData.so")"
  [ "$code" = 3 ] && grep -q 'the legitimate call failed on these bytes (InstructionError(0, InvalidInstructionData))' "$T/out" \
    && ok "real cargo, LiteSVM: a control that fails -> exit 3" || { bad "real cargo, LiteSVM failing control: exit $code"; cat "$T/out" >&2; }

  # The LiteSVM effect form binds the instruction that failed: a failure in an
  # instruction for another program, which the test added itself, says nothing about
  # the placed one.
  mk_lite "$T/e-lite-ix" rejected_with
  subst "$T/e-lite-ix/tests/exploit.rs" '    assert_exploit_effect!(svm, tx: Transaction::new_with_payer(&[ix], Some(&attacker)), account: state_pk,' "    let other = random_pubkey();
    svm.add_program(other, &std::fs::read(\"$SB-reject-Custom6001.so\").expect(\"other program\")).expect(\"add other program\");
    let other_ix = Instruction { program_id: other, accounts: vec![AccountMeta::new_readonly(attacker, true)], data: vec![] };
    assert_exploit_effect!(svm, tx: Transaction::new_with_payer(&[ix, other_ix], Some(&attacker)), account: state_pk,"
  code="$(e2e "$T/e-lite-ix" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -q 'the vulnerable arm is inconclusive: the attack targets .* not .* the program run.sh placed' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
    && ok "real cargo, LiteSVM: an effect assertion whose transaction failed in another program's instruction -> exit 3, not 1" || { bad "real cargo, LiteSVM failure in another program: exit $code"; cat "$T/out" >&2; }

  # Model runs: the crate's own arms, built by a stand-in cargo-build-sbf that writes
  # each arm's stand-in program (SBF_VULNERABLE, default takeover; SBF_FIXED, default
  # reject:MissingRequiredSignature). The any-result forms count here, and every form
  # is bound to the program run.sh placed.
  mkdir -p "$T/sbf"
  cat > "$T/sbf/cargo-build-sbf" <<'SH'
#!/bin/sh
out=""; features=""; prev=""
for a in "$@"; do
  case "$prev" in --sbf-out-dir) out="$a" ;; --features) features="$a" ;; esac
  prev="$a"
done
case "$features" in
  vulnerable) b="${SBF_VULNERABLE:-takeover}" ;;
  *) b="${SBF_FIXED:-reject:MissingRequiredSignature}" ;;
esac
printf '\177ELF%s' "$b" > "$out/poc_e2e.so"
SH
  chmod +x "$T/sbf/cargo-build-sbf"
  e2e_model() {  # e2e_model <crate> [VAR=val ...] -> exit code, real cargo, each arm built by the stand-in
    local crate="$1"; shift
    run "$crate" "$T/sbf:$PATH" "$NATIVE" "${E2E[@]}" "$@"
  }
  MODEL="OK: exploit reproduces on 'vulnerable' and is blocked on 'fixed'"
  mk_e2e "$T/m-base"
  code="$(e2e_model "$T/m-base")"
  [ "$code" = 0 ] && grep -q "^$MODEL" "$T/out" && ! grep -q "^$LEG3" "$T/out" \
    && ok "real cargo, model run: the template's own arms reproduce, and the model line, never the Leg 3 line, is printed" || { bad "real cargo, model run: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/m-any"
  drop_block "$T/m-any/tests/exploit.rs" '^    assert_exploit_effect!\($'
  swap "$T/m-any/tests/exploit.rs" '/^    let _ = SYSTEM_PROGRAM_ID;/ { print "    shared_test_utils::assert_exploit_succeeds!(mollusk, ix: &ix, accounts: &accounts, why: \"the model accepts it\");" } { print }'
  drop_block "$T/m-any/tests/fixed_blocked.rs" '^    assert_exploit_rejected_with!\($'
  swap "$T/m-any/tests/fixed_blocked.rs" '/^    \/\/ A hotfix the team already deployed/ { print "    shared_test_utils::assert_exploit_rejected!(mollusk, ix: &ix, accounts: &accounts, why: \"the model rejects it\");" } { print }'
  code="$(e2e_model "$T/m-any")"
  [ "$code" = 0 ] && grep -q "^$MODEL" "$T/out" \
    && ok "real cargo, model run: the any-result forms run the attack on the placed program and count" || { bad "real cargo, model run with the any-result forms: exit $code"; cat "$T/out" >&2; }
  cp -R "$T/m-any" "$T/m-any-other"
  subst "$T/m-any-other/tests/exploit.rs" '    let ix = Instruction {
        program_id,' '    let ix = Instruction {
        program_id: random_pubkey(),'
  code="$(e2e_model "$T/m-any-other")"
  [ "$code" = 3 ] && grep -q 'the vulnerable arm is inconclusive: the attack targets .* not .* the program run.sh placed' "$T/out" && ! grep -q '^OK' "$T/out" \
    && ok "real cargo, model run: assert_exploit_succeeds! aimed at another program id -> exit 3, no OK line" || { bad "real cargo, model run, any-result form on another program: exit $code"; cat "$T/out" >&2; }
  # On LiteSVM too: transactions that only call another program the tests added
  # themselves decide nothing, whatever they return.
  mk_lite "$T/m-lite-other" rejected_with
  for arm in vulnerable fixed; do
    if [ "$arm" = vulnerable ]; then f=exploit; tname=exploit_succeeds_on_vulnerable; other=noop; form=assert_exploit_succeeds
    else f=fixed_blocked; tname=same_attack_rejected_on_fixed; other=reject-Custom6001; form=assert_exploit_rejected; fi
    cat > "$T/m-lite-other/tests/$f.rs" <<RS
#![cfg(feature = "$arm")]
use shared_test_utils::{litesvm_for, random_pubkey, system_account};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::transaction::Transaction;

#[test]
fn $tname() {
    let program_id = random_pubkey();
    let mut svm = litesvm_for!(program_id, "poc_e2e");
    let other = random_pubkey();
    svm.add_program(other, &std::fs::read("$SB-$other.so").expect("other program")).expect("add other program");
    let attacker = random_pubkey();
    svm.set_account(attacker, system_account(1_000_000_000)).expect("attacker");
    let ix = Instruction { program_id: other, accounts: vec![AccountMeta::new_readonly(attacker, true)], data: vec![] };
    shared_test_utils::$form!(svm, tx: Transaction::new_with_payer(&[ix], Some(&attacker)), why: "another program");
}
RS
  done
  code="$(e2e_model "$T/m-lite-other")"
  [ "$code" = 3 ] && grep -q 'the vulnerable arm is inconclusive: the attack targets .* not .* the program run.sh placed' "$T/out" && ! grep -q '^OK' "$T/out" \
    && ok "real cargo, LiteSVM model run: any-result transactions that never call the placed program -> exit 3, no OK line" || { bad "real cargo, LiteSVM model run on another program: exit $code"; cat "$T/out" >&2; }

  # A shared build cache, two crates of the same name. Crate B is the template (pins
  # MissingRequiredSignature); crate A pins Custom(6001). A cargo wrapper builds A's
  # fixed-arm test into the shared cache while B is between its copy and its build —
  # what a concurrent run of A does. With the lock and the re-stamp, B rebuilds and
  # runs its OWN test (exit 2, B's pin does not match the Custom(6001) bytes); it never
  # exits 0 on A's binary. The wrapper fires once, on B's first cargo call.
  mk_e2e "$T/cache-A"; mk_e2e "$T/cache-B"
  swap "$T/cache-A/tests/fixed_blocked.rs" '/^        error: ProgramError::MissingRequiredSignature,$/ { print "        error: ProgramError::Custom(6001),"; next } { print }'
  REAL_CARGO="$(command -v cargo)"; mkdir -p "$T/cache-wrap"
  cat > "$T/cache-wrap/cargo" <<SH
#!/bin/sh
if [ ! -e "$T/cache-A.built" ]; then
  : > "$T/cache-A.built"
  acopy="\$(mktemp -d "$T/cache-A.copy.XXXXXX")"; cp -R "$T/cache-A/." "\$acopy/"
  "$REAL_CARGO" test --manifest-path "\$acopy/Cargo.toml" --no-default-features --features fixed \\
    --test fixed_blocked --no-run --message-format=json-render-diagnostics >/dev/null 2>&1 || true
fi
exec "$REAL_CARGO" "\$@"
SH
  chmod +x "$T/cache-wrap/cargo"
  rm -f "$T/cache-A.built"; rm -rf "$T/cache-shared"
  code="$(run "$T/cache-B" "$T/cache-wrap:$PATH" "$NATIVE" CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$T/cache-shared" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom6001.so")"
  if [ "$code" != 0 ] && ! grep -q "(rejected with the pinned error) → \[PoC-REPRODUCED\]" "$T/out"; then
    ok "real cargo: a same-named crate built into the shared cache between this run's copy and build does not hand over its result ($(grep -cE '^(FAIL|\[PoC-ATTEMPTED\])' "$T/out" >/dev/null && echo "blocked/exit $code"))"
  else
    bad "real cargo, shared-cache handover: exit $code"; cat "$T/out" >&2
  fi

  # The harness-copy check binds the build to the copied shared-test-utils. The crate's
  # own shared-test-utils/ stays byte-identical to the installation's, while the root
  # manifest points the dependency at another copy outside the crate: refused (exit 3).
  mk_e2e "$T/e-hc"; mkdir -p "$T/e-hc-elsewhere/stu/src"
  sed 's/^version = "0.1.0"/version = "0.1.1"/' "$T/e-hc/shared-test-utils/Cargo.toml" > "$T/e-hc-elsewhere/stu/Cargo.toml"
  { echo "// another copy of the harness, outside the crate"; cat "$T/e-hc/shared-test-utils/src/lib.rs"; } > "$T/e-hc-elsewhere/stu/src/lib.rs"
  subst "$T/e-hc/Cargo.toml" 'shared-test-utils = { path = "shared-test-utils" }' "shared-test-utils = { path = \"$T/e-hc-elsewhere/stu\" }"
  subst "$T/e-hc/Cargo.toml" '[workspace]' "[workspace]
members = [\"shared-test-utils\"]"
  cmp -s "$TEMPLATE/shared-test-utils/src/lib.rs" "$T/e-hc/shared-test-utils/src/lib.rs" || bad "harness-copy setup: the crate's shared-test-utils/src/lib.rs is not the installation's"
  code="$(e2e "$T/e-hc" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'shared-test-utils dependency' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
    && ok "real cargo: a shared-test-utils dependency pointed outside the crate (copy byte-identical) -> exit 3" || { bad "real cargo, harness-copy bind: exit $code"; cat "$T/out" >&2; }
  # The same binding against an import-name rename: the crate keeps its own
  # shared-test-utils/ as a member, byte-identical, while its manifest imports another
  # package as shared_test_utils, the key spelled with _.
  mk_e2e "$T/e-hc2"; mkdir -p "$T/e-hc2-elsewhere/eh/src"
  sed 's/^name = "shared-test-utils"/name = "evil-harness"/' "$T/e-hc2/shared-test-utils/Cargo.toml" > "$T/e-hc2-elsewhere/eh/Cargo.toml"
  cp "$T/e-hc2/shared-test-utils/src/lib.rs" "$T/e-hc2-elsewhere/eh/src/lib.rs"
  subst "$T/e-hc2/Cargo.toml" 'shared-test-utils = { path = "shared-test-utils" }' "shared_test_utils = { package = \"evil-harness\", path = \"$T/e-hc2-elsewhere/eh\" }"
  subst "$T/e-hc2/Cargo.toml" '[workspace]' "[workspace]
members = [\"shared-test-utils\"]"
  code="$(e2e "$T/e-hc2" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'imports evil-harness as shared_test_utils' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
    && ok "real cargo: another package imported as shared_test_utils, its own copy kept as a member -> exit 3" || { bad "real cargo, import-name rename: exit $code"; cat "$T/out" >&2; }

  # Code from outside the crate without a dependency: a test module by absolute #[path]
  # and the lib target's own out-of-tree path both compile; the non-registry line names
  # them, so an OK line never hides them.
  mk_e2e "$T/e-oot"; mkdir -p "$T/e-oot-outside"
  printf 'pub fn note() -> u8 { 1 }\n' > "$T/e-oot-outside/helper.rs"
  subst "$T/e-oot/tests/exploit.rs" '#![cfg(feature = "vulnerable")]' "#![cfg(feature = \"vulnerable\")]
#[path = \"$T/e-oot-outside/helper.rs\"]
mod helper;"
  subst "$T/e-oot/tests/exploit.rs" '    assert_exploit_effect!(' '    let _ = helper::note();
    assert_exploit_effect!('
  cp "$T/e-oot/src/lib.rs" "$T/e-oot-outside/lib.rs"; : > "$T/e-oot/src/lib.rs"
  subst "$T/e-oot/Cargo.toml" '[workspace]' "[lib]
path = \"$T/e-oot-outside/lib.rs\"

[workspace]"
  code="$(e2e "$T/e-oot" VULNERABLE_SO="$SB-takeover.so")"
  if [ "$code" = 0 ] && grep -q "non-registry code: .*$T/e-oot-outside/lib.rs" "$T/out" && grep -q "non-registry code: .*$T/e-oot-outside/helper.rs" "$T/out"; then
    ok "real cargo: a [lib] path and a #[path] module from outside the crate are named on the non-registry line"
  else
    bad "real cargo, out-of-tree sources: exit $code"; grep 'non-registry' "$T/out" >&2
  fi
  # The template's shape, a cdylib and lib, pulling in outside files of every kind: an absolute #[path]
  # module and an include! of a non-.rs file in the library, and in the test an include_str! of a non-.rs
  # file and a relative #[path] that climbs out of the scratch copy. rustc's dep-info for the library and
  # the test lists each one, and the non-registry line names it.
  mk_e2e "$T/e-inc"; O2="$T/e-inc-outside"; ET="$T/e-inc-tmp"; mkdir -p "$O2" "$ET/rel-outside"
  printf 'pub fn state() -> u8 { 7 }\n' > "$O2/state.rs"; printf 'pub fn from_payload() -> u8 { 41 }\n' > "$O2/payload.inc"
  printf 'outside bytes\n' > "$O2/key.txt"; printf 'pub fn helper() -> u8 { 5 }\n' > "$ET/rel-outside/helper.rs"
  subst "$T/e-inc/Cargo.toml" '[workspace]' '[lib]
crate-type = ["cdylib", "lib"]

[workspace]'
  printf '#[path = "%s/state.rs"]\npub mod outside_state;\ninclude!("%s/payload.inc");\n' "$O2" "$O2" >> "$T/e-inc/src/lib.rs"
  subst "$T/e-inc/tests/exploit.rs" '#![cfg(feature = "vulnerable")]' "#![cfg(feature = \"vulnerable\")]
#[path = \"../../rel-outside/helper.rs\"]
mod rel_helper;
const OUTSIDE_BYTES: &str = include_str!(\"$O2/key.txt\");"
  subst "$T/e-inc/tests/exploit.rs" '    assert_exploit_effect!(' '    let _ = (rel_helper::helper(), OUTSIDE_BYTES.len(), poc_e2e::outside_state::state(), poc_e2e::from_payload());
    assert_exploit_effect!('
  code="$(e2e "$T/e-inc" VULNERABLE_SO="$SB-takeover.so" TMPDIR="$ET")"
  line="$(grep -m 1 '^   non-registry code: ' "$T/out")"; named=1
  for f in "$O2/state.rs" "$O2/payload.inc" "$O2/key.txt" "$ET/rel-outside/helper.rs"; do
    case "$line" in *"$f (compiled in)"*) ;; *) named=0 ;; esac
  done
  [ "$code" = 0 ] && [ "$named" = 1 ] && grep -q "^$LEG3" "$T/out" \
    && ok "real cargo: an outside #[path] module, include! and include_str! of any file, and a relative path out of the scratch copy are named on the non-registry line" \
    || { bad "real cargo, outside includes: exit $code, '$line'"; cat "$T/out" >&2; }
  # A crate that joins an outside workspace (a workspace key under [package]) whose root lists the scratch
  # copies by a glob, and patches a dependency there: cargo metadata names that root, and the run stops
  # before anything compiles, with nothing built into that workspace or locked there.
  WSR="$T/e-ws-root"; WST="$T/e-ws-tmp"; mkdir -p "$WSR/vendor/xdep/src" "$WST"
  printf '[workspace]\nresolver = "2"\nmembers = ["%s/auditor-poc.*"]\n\n[patch.crates-io]\nxdep = { path = "vendor/xdep" }\n' "$WST" > "$WSR/Cargo.toml"
  printf '[package]\nname = "xdep"\nversion = "0.1.5"\nedition = "2021"\n' > "$WSR/vendor/xdep/Cargo.toml"; printf 'pub fn x() {}\n' > "$WSR/vendor/xdep/src/lib.rs"
  mk_e2e "$T/e-ws"
  subst "$T/e-ws/Cargo.toml" '[workspace]
' ''
  subst "$T/e-ws/Cargo.toml" 'publish = false
' "publish = false
workspace = \"$WSR\"
"
  code="$(run "$T/e-ws" "$PATH" "$NATIVE" CARGO_NET_OFFLINE=true TMPDIR="$WST" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -qF "the crate belongs to the workspace at $WSR, not to its own" "$T/out" && one_blocker \
    && [ ! -e "$WSR/target" ] && [ ! -e "$WSR/Cargo.lock" ] && ! grep -q 'Compiling' "$T/out" \
    && ok "real cargo: a crate that joins an outside workspace -> exit 3 before anything compiles, nothing built or locked there" \
    || { bad "real cargo, an outside workspace: exit $code"; cat "$T/out" >&2; }
  # On a nightly cargo a manifest's cargo-features can choose a linker or rustflags: the crate check refuses
  # the key before anything compiles. (A stable cargo refuses the manifest itself.)
  if [ "$(rustup toolchain list 2>/dev/null | grep -c '^nightly')" -gt 0 ]; then
    mk_e2e "$T/e-cf"
    printf 'cargo-features = ["profile-rustflags"]\n\n%s\n\n[profile.dev]\nrustflags = ["--cfg", "poc_canary"]\n' "$(cat "$T/e-cf/Cargo.toml")" > "$T/e-cf/Cargo.toml.new" \
      && mv "$T/e-cf/Cargo.toml.new" "$T/e-cf/Cargo.toml"
    code="$(e2e "$T/e-cf" VULNERABLE_SO="$SB-takeover.so" RUSTUP_TOOLCHAIN=nightly)"
    [ "$code" = 3 ] && grep -qF 'Cargo.toml:1 holds a cargo-features key' "$T/out" && one_blocker && ! grep -q 'Compiling' "$T/out" \
      && ok "real cargo, nightly: a manifest with cargo-features -> exit 3 before anything compiles" || { bad "real cargo, nightly cargo-features: exit $code"; cat "$T/out" >&2; }
  else
    echo "note: no nightly toolchain; the real-cargo cargo-features check is skipped (the shim checks above still ran)"
  fi
  # A bin target with an outside #[path] module, a dylib member whose module is outside, and inline assembly
  # whose .incbin reads an outside file: built, each compiles the outside file in while the dep-info run.sh
  # reads names none of them. cargo metadata names the first two, the crate's own source the third, and
  # each run stops before anything compiles.
  O3="$T/e-own-outside"; mkdir -p "$O3"; printf 'pub fn run() -> u8 { 9 }\n' > "$O3/evil.rs"; printf 'outside bytes\n' > "$O3/blob.bin"
  mk_e2e "$T/e-bin"; printf '#[path = "%s/evil.rs"]\nmod evil;\nfn main() { std::process::exit(evil::run() as i32); }\n' "$O3" > "$T/e-bin/src/main.rs"
  mk_e2e "$T/e-dylib"; mkdir -p "$T/e-dylib/helper/src"
  printf '[package]\nname = "helper"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n\n[lib]\ncrate-type = ["dylib"]\n' > "$T/e-dylib/helper/Cargo.toml"
  printf '#[path = "%s/evil.rs"]\npub mod evil;\n' "$O3" > "$T/e-dylib/helper/src/lib.rs"
  subst "$T/e-dylib/Cargo.toml" 'shared-test-utils = { path = "shared-test-utils" }' 'shared-test-utils = { path = "shared-test-utils" }
helper = { path = "helper" }'
  mk_e2e "$T/e-asm"; printf 'core::arch::global_asm!(".globl poc_blob\\npoc_blob:\\n.incbin \\"%s/blob.bin\\"");\n' "$O3" >> "$T/e-asm/src/lib.rs"
  for c in 'e-bin|the bin target poc_e2e (src/main.rs) of poc_e2e' 'e-dylib|the dylib target helper (helper/src/lib.rs) of helper' \
           'e-asm|names global_asm, inline assembly'; do
    code="$(e2e "$T/${c%%|*}" VULNERABLE_SO="$SB-takeover.so")"
    [ "$code" = 3 ] && grep -qF "${c#*|}" "$T/out" && one_blocker && ! grep -q 'Compiling' "$T/out" \
      && ok "real cargo: ${c#*|} -> exit 3 before anything compiles" || { bad "real cargo, ${c%%|*}: exit $code"; cat "$T/out" >&2; }
  done
  # The same inline assembly in a file of the crate named other than .rs, which the library include!s: it
  # compiles, and rustc's dep-info lists the file but not what its .incbin reads. run.sh reads the file after
  # the build and stops before the test runs.
  mk_e2e "$T/e-inctxt"
  printf 'core::arch::global_asm!(".globl poc_blob\\npoc_blob:\\n.incbin \\"%s/blob.bin\\"");\n' "$O3" > "$T/e-inctxt/src/payload.txt"
  printf 'include!("payload.txt");\n' >> "$T/e-inctxt/src/lib.rs"
  code="$(e2e "$T/e-inctxt" VULNERABLE_SO="$SB-takeover.so")"
  [ "$code" = 3 ] && grep -qF 'blocker: src/payload.txt:1 names global_asm, inline assembly' "$T/out" && one_blocker && grep -q 'Compiling poc_e2e' "$T/out" \
    && ! grep -q "^$LEG3" "$T/out" && ! grep -q '^>> running exploit' "$T/out" \
    && ok "real cargo: inline assembly in an include!d src/payload.txt -> exit 3 after the build, before the test" \
    || { bad "real cargo, inline assembly in an include!d .txt: exit $code"; cat "$T/out" >&2; }
  # The vulnerable arm's test runs the PoC's code with the scratch copy as CARGO_MANIFEST_DIR. Both arms are
  # built before it runs, so what it writes there reaches no build: here it turns the crate's src/lib.rs into
  # a compile_error!, which a build of the fixed arm after it would stop on.
  mk_e2e "$T/e-rewrite"
  subst "$T/e-rewrite/tests/exploit.rs" '    assert_exploit_effect!(' '    std::fs::write(std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/lib.rs"), "compile_error!(\"rewritten by the vulnerable arm test\");\n").unwrap();
    assert_exploit_effect!('
  code="$(e2e_model "$T/e-rewrite" KEEP_POC_BUILD=1)"
  bd="$(build_dir)"
  [ "$code" = 0 ] && grep -q "^$MODEL" "$T/out" && [ -n "$bd" ] && grep -q 'rewritten by the vulnerable arm test' "$bd/src/lib.rs" \
    && ! grep -q 'failed to build for the fixed arm' "$T/out" \
    && ok "real cargo, model run: a vulnerable-arm test that rewrites the crate's source in the scratch copy changes nothing the fixed arm builds" \
    || { bad "real cargo, a test that rewrites the scratch copy: exit $code"; cat "$T/out" >&2; }
  [ -n "$bd" ] && rm -rf "$bd"

  # The installation's copy with real cargo. The crate sits in a run directory, its prebuilt bytes under
  # exec/, and it depends on a path crate outside it whose build script records the environment it is
  # built in; the caller's environment holds canary variables. The build gets none of them, a
  # throwaway HOME and TMPDIR in the scratch copy, and the real CARGO_HOME; an inherited
  # CARGO_TARGET_DIR, RUSTFLAGS and RUSTC_WRAPPER are not used.
  RW="$T/wt-real"; mkdir -p "$RW"
  ( cd "$RW" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null || bad "rundir.sh new audit for the real-cargo fixture"
  printf 'native\n' > "$RW/audit_1/exec-mode"
  mk_e2e "$RW/audit_1/poc/F-1"
  mkdir -p "$RW/audit_1/exec/sb"; cp "$SB-takeover.so" "$SB-reject-MissingRequiredSignature.so" "$RW/audit_1/exec/sb/"
  mkdir -p "$T/envdep/src"; printf 'pub fn note() {}\n' > "$T/envdep/src/lib.rs"
  printf '[package]\nname = "envdep"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n' > "$T/envdep/Cargo.toml"
  printf 'fn main() {\n    let mut text = String::new();\n    for (k, v) in std::env::vars() {\n        text.push_str(&format!("{k}={v}\\n"));\n    }\n    std::fs::write("%s", text).expect("record the environment");\n}\n' "$T/envdep.env" > "$T/envdep/build.rs"
  printf 'envdep = { path = "%s" }\n' "$T/envdep" >> "$RW/audit_1/poc/F-1/Cargo.toml"
  REAL=(HOME="$CLEANHOME" "${TOOL_HOMES[@]}" PATH="$PATH" TMPDIR="$NT" CARGO_NET_OFFLINE=true)
  # --crate builds only a harness copy whose Cargo.toml is the installation's but for its dependency version
  # requirements, and this crate's names the stand-in crates by path: these runs use a copy of the
  # installation (its scripts/lib/ and templates/) whose harness Cargo.toml is the crate's.
  IR="$T/inst-real"; mkdir -p "$IR/scripts" && cp -R "$ROOT/scripts/lib" "$IR/scripts/" && cp -R "$ROOT/templates" "$IR/" \
    && cp "$RW/audit_1/poc/F-1/shared-test-utils/Cargo.toml" "$IR/templates/poc/shared-test-utils/Cargo.toml" \
    || bad "cannot copy the installation for the real-cargo runs"
  rr() {  # rr [VAR=val ...] -- <argument>...: that copy's run.sh with real cargo, from $RW -> exit code
    local -a vars=()
    while [ $# -gt 0 ] && [ "$1" != -- ]; do vars+=("$1"); shift; done
    [ $# -gt 0 ] && shift
    rm -rf "$NT"; mkdir -p "$NT"
    ( cd "$RW" && env -i "${REAL[@]}" ${vars[@]+"${vars[@]}"} "$IR/templates/poc/run.sh" "$@" ) >"$T/out" 2>&1 </dev/null
    echo $?
  }
  RSO=(--vulnerable-so audit_1/exec/sb/sb-takeover.so --fixed-so audit_1/exec/sb/sb-reject-MissingRequiredSignature.so)
  rm -f "$T/envdep.env"
  code="$(rr AUDITOR_CANARY=canary-r1 GITHUB_TOKEN=canary-r2 CARGO_TARGET_DIR="$T/canary-r3" RUSTFLAGS=--cfg=canary_r4 \
    RUSTC_WRAPPER="$T/canary-r5" CARGO_REGISTRY_TOKEN=canary-r6 RPC_URL=https://rpc.invalid/canary-r7 \
    HTTPS_PROXY=http://user:canary-r9@127.0.0.1:9 https_proxy=http://user:canary-r9@127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 \
    NO_PROXY=canary-r10.invalid -- --crate audit_1/poc/F-1 "${RSO[@]}")"
  if [ "$code" = 0 ] && grep -qx "${LEG3}$(zhash "$SB-takeover.so") fixed sha256=$(zhash "$SB-reject-MissingRequiredSignature.so") (rejected with the pinned error) → \[PoC-REPRODUCED\]" "$T/out"; then
    ok "real cargo, the installation's copy: --crate with prebuilt bytes under exec/ reaches the Leg 3 line"
  else
    bad "real cargo, --crate: exit $code"; cat "$T/out" >&2
  fi
  if [ -s "$T/envdep.env" ] && ! grep -q canary "$T/envdep.env" && [ ! -e "$T/canary-r3" ] \
     && ! grep -qi '^[a-z_]*proxy=' "$T/envdep.env" && ! grep -qF "=$CLEANHOME" "$T/envdep.env" \
     && grep -q "^HOME=$NT/auditor-poc\.[A-Za-z0-9]*/markers/home\$" "$T/envdep.env" \
     && grep -q "^TMPDIR=$NT/auditor-poc\.[A-Za-z0-9]*/markers/tmp\$" "$T/envdep.env" \
     && grep -qx "CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}" "$T/envdep.env" && ! grep -q '^RUSTC_WRAPPER=' "$T/envdep.env"; then
    ok "real cargo: a build script in the build sees no canary and no proxy variable, the throwaway HOME (never the real one) and TMPDIR, the real CARGO_HOME"
  else
    bad "real cargo: the build script's environment"; cat "$T/envdep.env" >&2
  fi
  grep -q "^   non-registry code: .*envdep 0.1.0 (path $T/envdep)" "$T/out" && [ -f "$RW/audit_1/poc/F-1/Cargo.lock" ] \
    && ok "real cargo: the non-registry line names the path crate, and the resolved Cargo.lock is back in the crate" || { bad "real cargo: non-registry line or Cargo.lock"; grep 'non-registry' "$T/out" >&2; }
  # A build cache from --new-cache, in a TMPDIR of its own: the second run builds into it as well.
  mkdir -p "$NTC"
  RCACHE="$( (cd "$RW" && env -i "${REAL[@]}" TMPDIR="$NTC" "$RUNSH" --new-cache) 2>/dev/null)"
  code="$(rr TMPDIR="$NTC" -- --crate audit_1/poc/F-1 "${RSO[@]}" --cache "$RCACHE")"
  code2="$(rr TMPDIR="$NTC" -- --crate audit_1/poc/F-1 "${RSO[@]}" --cache "$RCACHE")"
  [ "$code" = 0 ] && [ "$code2" = 0 ] && [ -d "$RCACHE/debug" ] && grep -qF ">> target dir: $RCACHE " "$T/out" && [ ! -e "$RCACHE/.auditor-poc-build.lock" ] \
    && ok "real cargo: --cache <a --new-cache directory> -> both runs build into it, and its lock is gone" || { bad "real cargo, --cache: exit $code then $code2"; cat "$T/out" >&2; }
  # A model run: the crate's own arms, built by a stand-in cargo-build-sbf that records the
  # environment and arguments of each call. The install alone gets the real HOME and the proxy;
  # each arm builds with --skip-tools-install --offline in the throwaway HOME, whose
  # .cache/solana links to the real one; no call gets a canary.
  mkdir -p "$T/sbf-env"
  cat > "$T/sbf-env/cargo-build-sbf" <<'SH'
#!/bin/sh
log=@LOG@
case " $* " in
  *" --help "*) printf '        --install-only\n        --offline\n        --skip-tools-install\n'; exit 0 ;;
  *" --install-only "*) { /usr/bin/env; echo "args: $*"; } > "$log.install"; exit 0 ;;
esac
{ /usr/bin/env; echo "args: $*"; echo "tools: $(readlink "$HOME/.cache/solana" 2>/dev/null)"; } > "$log"
out=""; features=""; prev=""
for a in "$@"; do
  case "$prev" in --sbf-out-dir) out="$a" ;; --features) features="$a" ;; esac
  prev="$a"
done
case "$features" in vulnerable) b=takeover ;; *) b=reject:MissingRequiredSignature ;; esac
printf '\177ELF%s' "$b" > "$out/poc_e2e.so"
SH
  sed "s#@LOG@#'$T/sbf-env.env'#" "$T/sbf-env/cargo-build-sbf" > "$T/sbf-env/cargo-build-sbf.new" && mv "$T/sbf-env/cargo-build-sbf.new" "$T/sbf-env/cargo-build-sbf"
  chmod +x "$T/sbf-env/cargo-build-sbf"
  REAL=(HOME="$CLEANHOME" "${TOOL_HOMES[@]}" PATH="$T/sbf-env:$PATH" TMPDIR="$NT" CARGO_NET_OFFLINE=true)
  rm -f "$T/sbf-env.env" "$T/sbf-env.env.install"
  code="$(rr TMPDIR="$NTC" AUDITOR_CANARY=canary-r8 HTTPS_PROXY=http://user:secret-r11@127.0.0.1:9 -- --crate audit_1/poc/F-1 --cache "$RCACHE")"
  [ "$code" = 0 ] && grep -q "^$MODEL" "$T/out" && ! grep -q canary "$T/sbf-env.env" "$T/sbf-env.env.install" \
    && grep -qx "HOME=$CLEANHOME" "$T/sbf-env.env.install" && grep -qx 'HTTPS_PROXY=http://user:secret-r11@127.0.0.1:9' "$T/sbf-env.env.install" \
    && grep -qx 'args: build-sbf --install-only --tools-version v1.54' "$T/sbf-env.env.install" \
    && grep -q "^HOME=$NTC/auditor-poc\.[A-Za-z0-9]*/markers/home\$" "$T/sbf-env.env" && ! grep -qi '^[a-z_]*proxy=' "$T/sbf-env.env" \
    && grep -qx 'CARGO_NET_OFFLINE=true' "$T/sbf-env.env" && grep -q '^args: build-sbf --skip-tools-install --offline --tools-version v1.54 ' "$T/sbf-env.env" \
    && grep -qx "tools: $CLEANHOME/.cache/solana" "$T/sbf-env.env" \
    && ok "real cargo, model run: the crate's own arms reproduce; the install alone gets the real HOME and the proxy, each arm builds offline in the throwaway HOME" || { bad "real cargo, model run, the installation's copy: exit $code"; cat "$T/out" "$T/sbf-env.env" "$T/sbf-env.env.install" >&2; }
elif [ "${REQUIRE_TOOLCHAIN:-}" = 1 ]; then
  bad "REQUIRE_TOOLCHAIN=1, but cargo or rustup is not on PATH: the real-toolchain checks cannot run"
else
  echo "note: cargo or rustup not on PATH; the real-toolchain checks are skipped (the shim checks above still ran)"
fi

# ---------------------------------------------------------------------------
# The patch verification recipe (templates/patch/VERIFICATION.md §1) builds through
# the bundled target.sh, which makes its own scratch clone outside the target tree:
# the block is the unpatched build and the patched one, exactly two target.sh
# build-sbf lines, each a plain call with the quoted installation path first and no
# cd or $. test-runners.sh runs target.sh build-sbf (the scratch clone, --rev,
# --patch, no hook of the source repository), and test-recipes.sh runs both lines as
# written.
# ---------------------------------------------------------------------------
if python3 -I - "$TEMPLATE/../patch/VERIFICATION.md" >"$T/out" 2>&1 <<'PY2'
import re, sys
doc = open(sys.argv[1], encoding="utf-8").read()
block = doc.split("## 1. Apply", 1)[1].split("```bash\n", 1)[1].split("```", 1)[0]
calls = [l for l in block.splitlines() if l.strip() and not l.lstrip().startswith("#")]
held = [l for l in calls if "$" in l or re.search(r"(^|[;&|(])\s*cd\s", l)]
assert not held, "a line holds a $ or a cd: %r" % held
ts = '"<auditor-skill root>/scripts/runner/target.sh" build-sbf --run {PATH_TO} --src . --rev {COMMIT}'
want = [ts, ts + " --patch {PATH_TO}/patches/{FINDING_ID}.patch"]
assert calls == want, "the block is not the two target.sh build-sbf lines: %r" % calls
PY2
then ok "VERIFICATION.md §1: exactly the two target.sh build-sbf lines, the quoted installation path first, no cd and no \$"
else bad "VERIFICATION.md §1 is not the two target.sh build-sbf lines"; cat "$T/out" >&2; fi

if [ "$fails" -ne 0 ]; then
  echo "test-dnr-poc-runner: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr-poc-runner: all assertions passed"
