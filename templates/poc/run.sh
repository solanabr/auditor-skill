#!/bin/bash
# One-command proof-of-concept runner for a PoC crate.
#
#   "<auditor-skill root>/templates/poc/run.sh" --crate <R>/poc/<ID> [--vulnerable-so <file>]
#       [--fixed-so <file>] [--update-pins "<pin> ..."] [--cache <dir>] [--keep] [--mode <mode>]
#   "<auditor-skill root>/templates/poc/run.sh" --init <R>/poc/<ID>   a new crate from this template
#   "<auditor-skill root>/templates/poc/run.sh" --new-cache           a new build cache; prints its path
#   ./run.sh                                                          the crate this copy sits in
#
# The installation's copy, run directly by its quoted absolute path from the working
# directory under audit, takes the crate and its inputs as arguments (ARGUMENTS below):
# that is the form a command pre-approves. A copy inside a crate, run as ./run.sh, builds
# the crate it sits in and reads its inputs from the environment: AUDITOR_EXEC_MODE,
# VULNERABLE_SO, FIXED_SO, UPDATE_PINS, CARGO_TARGET_DIR and KEEP_POC_BUILD. Both read
# TOOLS_VERSION and POC_LOCK_WAIT from the environment.
#
# Reproduces the finding from a clean checkout of THIS crate:
#   1. builds the `vulnerable` arm to SBF, runs tests/exploit.rs      → exploit must SUCCEED
#   2. builds the `fixed`      arm to SBF, runs tests/fixed_blocked.rs → same attack must be REJECTED
# Exit 0: the exploit reproduces on `vulnerable` and, when the fixed arm runs, is
# blocked on `fixed` — the evidence that earns [PoC-REPRODUCED]. Exit 1: the exploit
# did not reproduce. Exit 2: the fixed arm did not block it; the final line says
# whether that arm accepted the attack, rejected it with another error than the
# pinned one, or failed it while the account still changed. Exits 1 and 2 need a
# contract assertion of that arm (shared-test-utils) that ran and did not hold.
# Exit 3: a named blocker (toolchain, inputs, a build that failed, the execution
# mode below, build-time code in the crate) or an inconclusive arm (no contract
# assertion ran, the test failed outside them, the harness could not decide — a
# harness error such as a wrong program id or a short account list, on either arm
# — or other bytes ran). Record every exit 3 as [PoC-ATTEMPTED] with that line, mark
# the finding "PoC re-run needed" with that line as the reason, and keep the prose
# PoC. Only a harness error gets a repair pass, on the harness setup alone, never on
# the assertions or the target (references/orchestration/poc-harness.md §3).
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
# ARGUMENTS. The installation's copy checks every argument before anything is copied or
# built. Refused input is a blocker (exit 3) on one line, "[PoC-ATTEMPTED] blocker:
# run.sh refused: <reason> — nothing was copied or built.", flagged "PoC re-run needed"
# like every exit 3:
#   * <R> is a run directory as scripts/rundir.sh makes it: audit_<n> or incident_<n>
#     in the working directory, holding no symbolic link, tracked by no repository,
#     with a .gitignore of *. <ID> is F-<1-4 digits> or INC-<1-6 digits>.<1-4 digits>.
#     --crate names an existing crate there. --init makes one: the template's files,
#     byte for byte, in a new or empty <R>/poc/<ID>, to fill in with the Write and Edit
#     tools; it prints the crate's path and exits 0.
#   * --vulnerable-so and --fixed-so stand for VULNERABLE_SO and FIXED_SO (PREBUILT
#     BYTES below). Each names a regular file under a run directory's bin/ or exec/ (a
#     snapshot, or a build a runner made), by a relative path with no symbolic link.
#   * --update-pins stands for UPDATE_PINS (DEPENDENCY PINS below): one argument, the
#     pins separated by spaces. --keep stands for KEEP_POC_BUILD=1.
#   * --cache stands for CARGO_TARGET_DIR (the build cache below) and takes only a
#     directory --new-cache made: $TMPDIR/auditor-poc-target.XXXXXX, outside the
#     working directory, yours, mode 0700, holding the marker file .auditor-poc-cache.
#     --new-cache prints its path and exits 0; record it next to the execution mode.
#   * the execution mode is the stricter of <R>/exec-mode (one word, none, isolated or
#     native, written when the human answers Q46) and AUDITOR_EXEC_MODE, none being
#     the strictest and native the least. With neither set, with none, or with a
#     --mode that names another mode than that, run.sh exits 3 before it copies
#     anything; --mode catches a mode that changed without the human.
#   * in isolated mode the credential self-check of scripts/lib/isolation.sh runs
#     first: a readable key, cloud or registry credential, or a reachable agent socket
#     means this is not the isolated runner, and the run stops with exit 3, as it does
#     when the check cannot finish. Variables of run.sh's own environment whose names
#     look like credentials get a warning line. In native mode the same check prints,
#     as a warning, what the code this run builds can read, by kind and count; neither
#     line names a path.
#   * every cargo call and test binary runs under env -i with only what
#     scripts/lib/isolation.sh passes: a throwaway HOME holding a fresh Solana keypair,
#     TMPDIR in the scratch copy, the cleaned PATH and the user's CARGO_HOME and
#     RUSTUP_HOME. No token, RPC_URL, SSH agent or default wallet reaches the crate's
#     code. Only cargo's downloads get the proxy variables, and only cargo build-sbf
#     the real HOME, where it keeps its platform tools and the SDK's toolchain link.
#     VULNERABLE_SO, FIXED_SO, UPDATE_PINS, KEEP_POC_BUILD, CARGO_TARGET_DIR,
#     CARGO_BUILD_TARGET_DIR and RUSTC are not read from the environment, and
#     TOOLS_VERSION must be v<n>.<n> or v<n>.<n>.<n>.
# ./run.sh in the installation's own template refuses to run: it is not a PoC crate.
#
# EXECUTION MODE. Building this crate runs code on the machine that builds it: the
# build scripts and proc-macros of every dependency, then the tests. So every run
# needs the execution mode recorded for the audit or incident (OUTPUT-RULES.md Rule
# 11a, QUESTIONS.md Q46): AUDITOR_EXEC_MODE=isolated inside the isolated runner, or
# AUDITOR_EXEC_MODE=native (the report then states that the PoC build ran on this
# host); the installation's copy takes the stricter of it and <R>/exec-mode
# (ARGUMENTS). Without it, run.sh exits 3 before it copies or compiles anything.
#
# WHERE IT BUILDS. This crate normally sits inside the audited repo
# (audit_<n>/poc/…, incident_<n>/poc/…). Built there, cargo would read the target's
# .cargo/config* from every parent directory (rustc-wrapper, runner, linker,
# rustflags, an alias that shadows `build-sbf`), and rustup its rust-toolchain*
# (which can name a `path` toolchain, i.e. any binaries). So, in either mode:
#   * a crate that holds a symbolic link, a .cargo/ directory or a rust-toolchain*
#     file, in any letter case (a filesystem that ignores case lets cargo and
#     rustup read .CARGO/ as .cargo/), is refused (exit 3): the copy below never
#     takes them.
#   * the crate is copied, without a target/ directory in any letter case, into a
#     fresh scratch directory,
#     `mktemp -d "${TMPDIR:-/tmp}/auditor-poc.XXXXXX"`, and built and tested there
#     with RUSTUP_TOOLCHAIN pinned to the caller's value, else rustup's default. The
#     directory is printed, and removed on exit unless KEEP_POC_BUILD=1 (--keep); the
#     resolved Cargo.lock is copied back next to the crate's manifest, in place of a
#     regular file only, never through a link. A `path` dependency that leaves
#     the crate must therefore be absolute.
#   * the crate's own build-time code is refused (exit 3) before anything compiles:
#     `cargo metadata --no-deps`, run in the scratch copy, lists the crate's packages
#     (the crate, shared-test-utils, any other member), and a build script (`build =
#     false` turns one off), a proc-macro package, a Cargo.toml inside the crate that
#     is not a member, or a [patch] or [replace] table in a manifest stops the run. A
#     path dependency outside the crate is not refused: its build script runs in the
#     recorded mode, and the non-registry line names it. Check code that is
#     generated at build time into the crate instead. The contract macros must come
#     from the harness copy that was checked, so the crate depends on its own
#     shared-test-utils/ under the import name shared_test_utils; a crate without
#     that dependency, one that imports it under another name, another dependency
#     imported as shared_test_utils (with - or _), and a build that compiles a
#     shared_test_utils from anywhere else, or none, stop it too.
#   * the build cache: to reuse compiled dependencies between runs of one
#     engagement, create a directory once per engagement with run.sh --new-cache, or
#     for ./run.sh with `mktemp -d "${TMPDIR:-/tmp}/auditor-poc-target.XXXXXX"` (inside
#     the isolated runner in isolated mode), record it next to the execution mode, and
#     pass it to every run as --cache or CARGO_TARGET_DIR. Never point CARGO_TARGET_DIR or
#     CARGO_BUILD_TARGET_DIR inside the target tree or at a directory you did not
#     create: cargo trusts the build outputs it finds there. Two crates of the same
#     name resolve to the same cached artifact path, so run.sh holds a lock inside
#     the directory cargo builds into (cargo metadata's target_directory, which a
#     target-dir in cargo's own config sets too) around each arm's build and test
#     and re-stamps the scratch copy under the lock; cargo then rebuilds this
#     crate's own code and the cache serves only its dependencies. A run waits up
#     to POC_LOCK_WAIT seconds (default 900) for the lock, then stops with exit 3.
#     If a stale artifact is handed over anyway, the fresh check in `harness
#     checkbuild` makes the run a blocker, not a verdict. SBF_OUT_DIR stays in the
#     scratch copy either way.
#   * mollusk looks for <crate>.so in tests/fixtures/ and BPF_OUT_DIR before
#     SBF_OUT_DIR, so run.sh unsets BPF_OUT_DIR and refuses a crate holding
#     tests/fixtures/<crate>.so: the bytes that run are the arm run.sh placed.
#
# DEPENDENCY PINS. The template ships a Cargo.lock; keep it with the crate (run.sh
# prints a line when the crate has none, and cargo then resolves every dependency
# to its newest compatible release). A crate the PoC adds keeps every pin it does
# not need to move. When cargo reports a conflict with a pinned release, name that
# pin and run.sh moves it alone, in the scratch copy, before it builds:
#     AUDITOR_EXEC_MODE=<mode> UPDATE_PINS="solana-program@3.0.0" ./run.sh   # cargo update -p solana-program@3.0.0
# or --update-pins "solana-program@3.0.0" for the installation's copy (several pins:
# separate them with spaces). The moved lock comes back next to the crate's manifest
# with the rest. Never run cargo update in the crate itself: inside the target
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
#     .so run.sh placed, unchanged after the test, and the attack targeted one of
#     those programs (exit 3 otherwise): load the program under test only through
#     them. A test that passes without one exits 3.
#   * an assertion of the arm that ran and did not hold, in any test, is a verdict
#     (exit 1 or 2), whatever another test left. A test that failed before any
#     assertion ran, after every one held, or between an assertion's start and its
#     result (the process died mid-assertion), and an assertion that could not decide
#     (a harness error, on either arm), exit 3. The markers are a floor, not proof:
#     read the assertion all the same.
#   * before the final line, run.sh prints the non-registry code in the build: the
#     path and git dependencies in the resolved Cargo.lock, a `[lib] path` or
#     `#[path]` source compiled from outside the crate, and the like.
#
# PREBUILT BYTES (incidents under references/detection-response/, or a re-run
# against the target's own builds). Leg 3 of `confirmed_exploited` needs the exploit
# to run on the REAL program bytes, not on this crate's minimized arms:
#     VULNERABLE_SO=/path/to/deployed-or-vulnerable.so ./run.sh
# runs the exploit arm alone on those bytes, and adding
#     FIXED_SO=/path/to/patched-or-current.so
# also runs the fixed arm, on the FIXED_SO bytes. FIXED_SO without VULNERABLE_SO
# exits 3. The installation's copy takes them as --vulnerable-so and --fixed-so.
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

set -Eeuo pipefail
# Only an assertion that ran and did not hold gives a verdict (exit 1 or 2). Any
# other command that fails — an unreadable input, a failed path resolution, a step
# that errors under set -e — is a blocker, never a verdict: this trap turns it into
# exit 3. The explicit `exit 1` / `exit 2` below are the only verdicts. Inside a
# command substitution (bash 3.2 runs the trap there too) it only passes the status
# up, and the caller names the blocker.
trap 'rc=$?; [ "${BASH_SUBSHELL:-0}" -gt 0 ] && exit "${rc}"; echo "[PoC-ATTEMPTED] blocker: run.sh could not finish (unexpected error, status ${rc}); this run decides nothing." >&2; exit 3' ERR
# Every way out ends in on_exit. It drops the build lock this run holds and the
# scratch copy, keeping the resolved Cargo.lock with the crate. A run that stops
# anywhere but at a verdict (VERDICT names the exit 0, 1 or 2 taken) or a named
# blocker (exit 3) exits 3 as well: an unset variable under set -u, say, which bash
# 3.2 hands this trap as status 0.
VERDICT=""
BUILD_DIR=""
LOCK_HELD=0
# keep_lock: the resolved Cargo.lock goes back next to the crate's manifest, written to a
# new file and renamed over the old one, and only in place of a regular file: a link or
# a directory there is left as it is, and so is a crate directory that no longer
# resolves to where it was.
keep_lock() {
  local dst="${HERE}/Cargo.lock" tmp="${HERE}/.Cargo.lock.$$"
  [[ "$(cd "${HERE}" 2>/dev/null && pwd -P)" == "${HERE}" ]] || return 0
  if [[ -L "${dst}" ]] || { [[ -e "${dst}" ]] && [[ ! -f "${dst}" ]]; }; then return 0; fi
  if ( set -C; cat "${BUILD_DIR}/Cargo.lock" > "${tmp}" ) 2>/dev/null; then
    mv -f "${tmp}" "${dst}" 2>/dev/null || rm -f "${tmp}" 2>/dev/null || true
  fi
  return 0
}
on_exit() {
  local rc="$1"
  if [[ "${LOCK_HELD}" == 1 ]]; then release_lock; fi
  if [[ -n "${BUILD_DIR}" ]]; then
    if [[ -f "${BUILD_DIR}/Cargo.lock" ]]; then keep_lock; fi
    case "${BUILD_DIR}" in
      */auditor-poc.*) if [[ "${KEEP_POC_BUILD:-0}" != 1 ]]; then rm -rf "${BUILD_DIR}" || true; fi ;;
    esac
  fi
  if [[ "${rc}" != 3 && "${rc}" != "${VERDICT}" ]]; then
    echo "[PoC-ATTEMPTED] blocker: run.sh stopped before a verdict (status ${rc}); this run decides nothing." >&2
    exit 3
  fi
  exit "${rc}"
}
trap 'on_exit "$?"' EXIT

# ── How run.sh was called (see ARGUMENTS above) ─────────────────────────────────
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# 1 for the installation's copy: every child runs in the cleaned environment.
CLEAN=0
PINS_FROM=UPDATE_PINS
CACHE_MARK=.auditor-poc-cache
# The template's files, the ones --init copies.
TEMPLATE_FILES="Cargo.toml Cargo.lock README.md run.sh shared-test-utils/Cargo.toml shared-test-utils/src/lib.rs src/lib.rs src/vulnerable.rs src/fixed.rs tests/exploit.rs tests/fixed_blocked.rs"
USAGE="--crate <R>/poc/<ID> [--vulnerable-so <file>] [--fixed-so <file>] [--update-pins <pins>] [--cache <dir>] [--keep] [--mode <mode>], --init <R>/poc/<ID>, or --new-cache"
# The pins to move (see DEPENDENCY PINS above): each a crate name, optionally
# @<the version Cargo.lock pins>, and nothing else.
PIN_SPEC='^[A-Za-z][A-Za-z0-9_-]*(@[0-9][0-9A-Za-z.+-]*)?$'
TOOLS_SPEC='^v[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?$'

blocker() {  # blocker <text>: a named blocker, exit 3
  echo "[PoC-ATTEMPTED] blocker: $1" >&2
  exit 3
}
refuse() {  # refuse <reason>: refused input, a blocker named before anything is copied or built
  blocker "run.sh refused: $1 — nothing was copied or built."
}
digits() {  # digits <s> <n>: status 0 when <s> is 1 to <n> digits
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [[ "${#1}" -le "$2" ]]
}

# crate_arg <option> <path> dir|new: <path> is <R>/poc/<ID> in a run directory, and an
# existing crate (dir) or a place for a new one (new: nothing there, or an empty
# directory). Sets CRATE_REL and CRATE_RUN.
crate_arg() {
  local opt="$1" want="$3" shown rel kind id n entries
  confine_shown "$2"; shown="${CONFINE_SHOWN}"
  confine_path "$2" "${opt}" any
  rel="${CONFINE_REL}"; kind="${CONFINE_TYPE}"
  id="${rel#*/poc/}"
  case "${id}" in
    F-*) digits "${id#F-}" 4 || id="" ;;
    INC-*.*) n="${id#INC-}"; { digits "${n%%.*}" 6 && digits "${n#*.}" 4; } || id="" ;;
    *) id="" ;;
  esac
  if [[ -z "${id}" || "${rel}" != "${rel%%/*}/poc/${id}" ]]; then
    refuse "${opt} takes <R>/poc/<ID>, with <ID> F-<n> or INC-<n>.<k>, not ${shown}"
  fi
  confine_rundir "${rel%%/*}" "the run directory of ${opt}"
  case "${want}:${kind}" in
    dir:dir|new:none) ;;
    new:dir)
      entries="$(find "${WT}/${rel}" -mindepth 1 -maxdepth 1 -print 2>/dev/null)" || refuse "${shown} cannot be listed"
      [[ -z "${entries}" ]] || refuse "${opt} makes a crate in a new or empty directory, and ${shown} holds files" ;;
    dir:*) refuse "${opt} is not an existing crate directory: ${shown}" ;;
    *) refuse "${opt} makes a crate in a new or empty directory, and ${shown} is a file" ;;
  esac
  CRATE_REL="${rel}"; CRATE_RUN="${CONFINE_RUN}"
}

# so_arg <option> <path>: a regular file under a run directory's bin/ or exec/. Sets
# SO_PATH to its physical path.
so_arg() {
  local opt="$1" shown rel kind
  confine_shown "$2"; shown="${CONFINE_SHOWN}"
  confine_path "$2" "${opt}" any
  rel="${CONFINE_REL}"; kind="${CONFINE_TYPE}"
  case "${rel#*/}" in
    bin/?*|exec/?*) ;;
    *) refuse "${opt} takes a file under a run directory's bin/ or exec/, not ${shown}" ;;
  esac
  confine_rundir "${rel%%/*}" "the run directory of ${opt}"
  [[ "${kind}" == file ]] || refuse "${opt} is not an existing regular file: ${shown}"
  SO_PATH="${WT}/${rel}"
}

tmp_base() {  # tmp_base: TMP_BASE is TMPDIR (else /tmp), physical, and outside the working directory
  local t="${TMPDIR:-/tmp}"
  while [[ "${t}" == */ && "${t}" != / ]]; do t="${t%/}"; done
  confine_phys "${t}" || refuse "TMPDIR cannot be resolved: $(confine_text "${t}")"
  TMP_BASE="${CONFINE_PHYS}"
  case "${TMP_BASE}/" in
    "${WT%/}/"*) refuse "TMPDIR lies inside the working directory; point it outside the tree under audit" ;;
  esac
}

# cache_arg <dir>: a build cache --new-cache made, in TMPDIR, yours, mode 0700, holding
# the marker. Sets CACHE_DIR.
cache_arg() {
  local v="$1" shown name parent size
  confine_shown "${v}"; shown="${CONFINE_SHOWN}"
  name="${v##*/}"; parent="${v%/*}"
  case "${v}:${name}" in
    *[[:cntrl:]]*) refuse "--cache holds a control character: ${shown}" ;;
    /*:auditor-poc-target.??????) ;;
    *) refuse "--cache takes a directory --new-cache made, \$TMPDIR/auditor-poc-target.XXXXXX, not ${shown}" ;;
  esac
  case "${name#auditor-poc-target.}" in
    *[!A-Za-z0-9]*) refuse "--cache takes a directory --new-cache made, \$TMPDIR/auditor-poc-target.XXXXXX, not ${shown}" ;;
  esac
  tmp_base
  { confine_phys "${parent:-/}" && [[ "${CONFINE_PHYS}" == "${TMP_BASE}" ]]; } ||
    refuse "--cache is not in TMPDIR, where --new-cache makes it: ${shown}"
  [[ -d "${v}" && ! -L "${v}" ]] || refuse "--cache is not a directory --new-cache made: ${shown}"
  [[ -O "${v}" ]] || refuse "--cache is not yours: ${shown}"
  [[ -n "$(find "${v}" -prune -perm 0700 -print 2>/dev/null)" ]] || refuse "--cache is not mode 0700: ${shown}"
  { [[ -f "${v}/${CACHE_MARK}" && ! -L "${v}/${CACHE_MARK}" ]] && size="$(wc -c < "${v}/${CACHE_MARK}")" &&
    [[ "${size//[!0-9]/}" == 19 && "$(cat -- "${v}/${CACHE_MARK}")" == "auditor-poc-target" ]]; } ||
    refuse "--cache holds no ${CACHE_MARK} marker, so --new-cache did not make it: ${shown}"
  CACHE_DIR="${TMP_BASE%/}/${name}"
}

# exec_mode <--mode value or nothing>: MODE becomes the stricter of <R>/exec-mode and
# AUDITOR_EXEC_MODE (none, then isolated, then native), and must be --mode when that is
# given.
exec_mode() {
  local want="$1" file="${WT}/${CRATE_RUN}/exec-mode" size text=""
  ENV_MODE="${AUDITOR_EXEC_MODE:-}"; FILE_MODE=""
  case "${ENV_MODE}" in
    ''|none|isolated|native) ;;
    *) refuse "AUDITOR_EXEC_MODE is '$(confine_text "${ENV_MODE}")', not none, isolated or native" ;;
  esac
  if [[ -e "${file}" || -L "${file}" ]]; then
    [[ -f "${file}" && ! -L "${file}" ]] || refuse "${CRATE_RUN}/exec-mode is not a regular file"
    size="$(wc -c < "${file}")" || refuse "${CRATE_RUN}/exec-mode cannot be read"
    size="${size//[!0-9]/}"
    if [[ "${size}" -le 9 ]]; then text="$(cat -- "${file}")" || refuse "${CRATE_RUN}/exec-mode cannot be read"; fi
    case "${text}" in
      none|isolated|native) [[ "${size}" -le $(( ${#text} + 1 )) ]] || text="" ;;
      *) text="" ;;
    esac
    [[ -n "${text}" ]] || refuse "${CRATE_RUN}/exec-mode holds something other than one word, none, isolated or native"
    FILE_MODE="${text}"
  fi
  if [[ -z "${FILE_MODE}${ENV_MODE}" ]]; then
    blocker "no recorded mode: ${CRATE_RUN}/exec-mode is missing and AUDITOR_EXEC_MODE is not set (OUTPUT-RULES.md Rule 11a, QUESTIONS.md Q46). Record the human's answer in ${CRATE_RUN}/exec-mode and run this again — nothing was copied or built."
  fi
  case " ${FILE_MODE} ${ENV_MODE} " in
    *" none "*) MODE=none ;;
    *" isolated "*) MODE=isolated ;;
    *) MODE=native ;;
  esac
  MODE_SOURCES="${CRATE_RUN}/exec-mode: ${FILE_MODE:-absent}; AUDITOR_EXEC_MODE: ${ENV_MODE:-unset}"
  if [[ "${MODE}" == none ]]; then
    blocker "the recorded execution mode is none (${MODE_SOURCES}): no target code is built or run for this engagement (OUTPUT-RULES.md Rule 11a) — nothing was copied or built."
  fi
  if [[ -n "${want}" && "${want}" != "${MODE}" ]]; then
    blocker "--mode is ${want}, but the recorded execution mode is ${MODE} (${MODE_SOURCES}); the mode changes only when the human answers again — nothing was copied or built."
  fi
}

# self_check: in isolated mode nothing the credential check reads may be readable, and
# variables of run.sh's own environment that look like credentials are named; in native
# mode what is readable is printed as a warning.
self_check() {
  local rc=0
  iso_credentials || rc=$?
  case "${MODE}:${rc}" in
    *:0) ;;
    isolated:1) blocker "isolated mode, but these are readable here: ${ISO_KINDS}; this is not the isolated runner (Rule 11a), and scripts/runner/probe.sh --only isolation lists them — nothing was copied or built." ;;
    isolated:*) blocker "isolated mode, but the credential self-check could not finish (${ISO_WHY}), so run.sh cannot tell that this is the isolated runner (Rule 11a) — nothing was copied or built." ;;
    *:1) echo ">> warning: native mode, and these are readable here, to the code this run builds and runs too: ${ISO_KINDS} (Rule 11a)" ;;
    *) echo ">> warning: native mode, and the credential check could not finish (${ISO_WHY}), so what the code this run builds can read here is not known (Rule 11a)" ;;
  esac
  [[ "${MODE}" == isolated ]] || return 0
  iso_cred_names
  if [[ -n "${ISO_NAMES}" ]]; then
    echo ">> warning: isolated mode, and these variables of run.sh's own environment look like credentials: ${ISO_NAMES}. No child of run.sh gets them, but code running as this user can read another process's environment (on Linux, in /proc/<pid>/environ) (Rule 11a)"
  fi
}

new_cache() {  # new_cache: a build cache in TMPDIR, with its marker; prints its path
  local dir
  tmp_base
  dir="$(mktemp -d "${TMP_BASE%/}/auditor-poc-target.XXXXXX" 2>/dev/null)" ||
    blocker "cannot create a build cache in $(confine_text "${TMP_BASE}"); nothing was made."
  confine_phys "${dir}" || blocker "cannot resolve the new build cache $(confine_text "${dir}")."
  dir="${CONFINE_PHYS}"
  confine_new_file "${dir}/${CACHE_MARK}" "auditor-poc-target"$'\n' || blocker "could not write ${CACHE_MARK} in ${dir}."
  echo "${dir}"
  VERDICT=0; exit 0
}

init_crate() {  # init_crate <R>/poc/<ID>: the template's files, byte for byte, in a new run subpath
  local f d
  crate_arg --init "$1" new
  set -f
  for f in ${TEMPLATE_FILES}; do
    [[ -f "${SELF}/${f}" && ! -L "${SELF}/${f}" ]] || blocker "the installation's template has no regular file ${f}; nothing was copied."
  done
  if [[ ! -d "${WT}/${CRATE_RUN}/poc" ]]; then confine_mkdir "${WT}/${CRATE_RUN}/poc" || refuse "cannot create ${CRATE_RUN}/poc"; fi
  if [[ ! -d "${WT}/${CRATE_REL}" ]]; then confine_mkdir "${WT}/${CRATE_REL}" || refuse "cannot create ${CRATE_REL}"; fi
  for d in src tests shared-test-utils shared-test-utils/src; do
    confine_mkdir "${WT}/${CRATE_REL}/${d}" || blocker "could not create ${CRATE_REL}/${d}; remove ${CRATE_REL} and run --init again."
  done
  for f in ${TEMPLATE_FILES}; do
    ( set -C; exec 9>"${WT}/${CRATE_REL}/${f}" && cat -- "${SELF}/${f}" >&9 ) 2>/dev/null ||
      blocker "could not copy ${f} into ${CRATE_REL}; remove ${CRATE_REL} and run --init again."
  done
  set +f
  chmod 700 "${WT}/${CRATE_REL}/run.sh" 2>/dev/null || true
  echo "${CRATE_REL}"
  VERDICT=0; exit 0
}

# take_args <argument>...: the installation's copy. Every argument is checked before
# anything is copied or built, then the inputs the steps below read are set from the
# arguments and <R>/exec-mode, never from the environment's VULNERABLE_SO and the rest.
take_args() {
  local root opt seen=" " crate="" vso="" fso="" pins="" cache="" mode="" init="" keep=0 spec n=0
  case "${SELF}" in
    */templates/poc) root="${SELF%/templates/poc}" ;;
    *) refuse "only the installation's copy, <auditor-skill root>/templates/poc/run.sh, takes arguments; in a crate, run ./run.sh" ;;
  esac
  [[ -f "${root}/scripts/lib/confine.sh" && -f "${root}/scripts/lib/isolation.sh" ]] ||
    refuse "only the installation's copy, <auditor-skill root>/templates/poc/run.sh, takes arguments: scripts/lib/ is not beside this one"
  . "${root}/scripts/lib/confine.sh" || refuse "scripts/lib/confine.sh cannot be read"
  . "${root}/scripts/lib/isolation.sh" || refuse "scripts/lib/isolation.sh cannot be read"
  confine_refuse() { refuse "$1"; }
  confine_init run.sh "${root}"
  WT="${CONFINE_WT}"
  while [[ $# -gt 0 ]]; do
    opt="$1"; shift
    case "${opt}" in
      --crate|--vulnerable-so|--fixed-so|--update-pins|--cache|--mode|--init)
        [[ $# -gt 0 ]] || refuse "${opt} needs a value" ;;
      --keep|--new-cache) ;;
      *) refuse "$(confine_text "${opt}") is not an argument run.sh takes (${USAGE})" ;;
    esac
    case "${seen}" in *" ${opt} "*) refuse "give ${opt} once" ;; esac
    seen="${seen}${opt} "
    case "${opt}" in
      --crate) crate="$1"; shift ;;
      --vulnerable-so) vso="$1"; shift ;;
      --fixed-so) fso="$1"; shift ;;
      --update-pins) pins="$1"; shift ;;
      --cache) cache="$1"; shift ;;
      --mode) mode="$1"; shift ;;
      --init) init="$1"; shift ;;
      --keep) keep=1 ;;
    esac
  done
  case "${seen}" in
    " --new-cache ") new_cache ;;
    *" --new-cache "*) refuse "--new-cache takes no other argument" ;;
    " --init ") init_crate "${init}" ;;
    *" --init "*) refuse "--init takes no other argument" ;;
    *" --crate "*) ;;
    *) refuse "give --crate, --init or --new-cache (${USAGE})" ;;
  esac
  crate_arg --crate "${crate}" dir
  VULNERABLE_SO=""; FIXED_SO=""
  case "${seen}" in
    *" --fixed-so "*) case "${seen}" in *" --vulnerable-so "*) ;; *) refuse "--fixed-so needs --vulnerable-so: the fixed bytes are checked against the exploit on the vulnerable ones" ;; esac ;;
  esac
  case "${seen}" in *" --vulnerable-so "*) so_arg --vulnerable-so "${vso}"; VULNERABLE_SO="${SO_PATH}" ;; esac
  case "${seen}" in *" --fixed-so "*) so_arg --fixed-so "${fso}"; FIXED_SO="${SO_PATH}" ;; esac
  case "${seen}" in
    *" --update-pins "*)
      case "${pins}" in *[[:cntrl:]]*) refuse "--update-pins holds a control character" ;; esac
      set -f
      for spec in ${pins}; do
        [[ "${spec}" =~ ${PIN_SPEC} ]] || refuse "--update-pins entry '$(confine_text "${spec}")' is not <crate> or <crate>@<pinned version>"
        n=$((n + 1))
      done
      set +f
      [[ "${n}" -gt 0 ]] || refuse "--update-pins names no pin" ;;
  esac
  CACHE_DIR=""
  case "${seen}" in *" --cache "*) cache_arg "${cache}" ;; esac
  case "${seen}" in
    *" --mode "*)
      case "${mode}" in
        none|isolated|native) ;;
        *) refuse "--mode takes none, isolated or native, not '$(confine_text "${mode}")'" ;;
      esac ;;
  esac
  if [[ -n "${TOOLS_VERSION:-}" && ! "${TOOLS_VERSION}" =~ ${TOOLS_SPEC} ]]; then
    refuse "TOOLS_VERSION is '$(confine_text "${TOOLS_VERSION}")', not v<n>.<n> or v<n>.<n>.<n>"
  fi
  exec_mode "${mode}"
  echo ">> execution mode: ${MODE} (the stricter of ${MODE_SOURCES})"
  self_check
  HERE="${WT}/${CRATE_REL}"
  AUDITOR_EXEC_MODE="${MODE}"
  UPDATE_PINS="${pins}"
  PINS_FROM=--update-pins
  KEEP_POC_BUILD="${keep}"
  unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR RUSTC BPF_OUT_DIR SBF_OUT_DIR
  CLEAN=1
}

# child / child_net / child_sbf [NAME=value...] <program> [<arg>...]: how run.sh starts a
# cargo call or a test binary. ./run.sh hands it its own environment. The installation's
# copy runs it under env -i with only what scripts/lib/isolation.sh passes; child_net adds
# the proxy variables, for cargo's downloads, and child_sbf the real HOME as well, where
# cargo build-sbf keeps its platform tools and the SDK's toolchain link.
child() { if [[ "${CLEAN}" == 1 ]]; then iso_run "$@"; else env "$@"; fi; }
child_net() { if [[ "${CLEAN}" == 1 ]]; then iso_net "$@"; else env "$@"; fi; }
child_sbf() { if [[ "${CLEAN}" == 1 ]]; then iso_net "HOME=${ISO_REAL_HOME}" "$@"; else env "$@"; fi; }

if [[ $# -gt 0 ]]; then
  take_args "$@"
elif [[ "${SELF}" == */templates/poc && -f "${SELF%/templates/poc}/scripts/lib/confine.sh" ]]; then
  blocker "this run.sh is the installation's template, not a PoC crate: run it with --crate <R>/poc/<ID> (--init <R>/poc/<ID> makes one) — nothing was copied or built."
else
  HERE="${SELF}"
fi

TOOLS_VERSION="${TOOLS_VERSION:-v1.54}"
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

# The pins to move: PIN_SPEC above.
set -f
for spec in ${UPDATE_PINS:-}; do
  if [[ ! "${spec}" =~ ${PIN_SPEC} ]]; then
    echo "[PoC-ATTEMPTED] blocker: ${PINS_FROM} entry '${spec}' is not <crate> or <crate>@<pinned version> — nothing was copied or built." >&2
    exit 3
  fi
done
set +f
# How long a run waits for the build lock (see the build cache under WHERE IT BUILDS):
# whole seconds, compared as a number and never evaluated.
LOCK_WAIT="${POC_LOCK_WAIT:-900}"
LOCK_WAIT_SPEC='^(0|[1-9][0-9]{0,5})$'
if [[ ! "${LOCK_WAIT}" =~ ${LOCK_WAIT_SPEC} ]]; then
  echo "[PoC-ATTEMPTED] blocker: POC_LOCK_WAIT is '${LOCK_WAIT}', not a whole number of seconds (at most 999999) — nothing was copied or built." >&2
  exit 3
fi

# ── What python3 reads for run.sh ───────────────────────────────────────────────
# `harness hash <file>`: the zero-trimmed sha256 (the loader pads a program account
# well past the ELF — a live JUP6 dump carried ~892 KB of it — so trailing zeros are
# trimmed before hashing, and the digest matches `solana-verify`). `harness crate`:
# the program name, from cargo metadata, after the build-time-code and manifest
# checks (exit 3 and the reason otherwise). `harness targetdir`: the directory cargo
# builds into, from cargo metadata. `harness checkbuild`: the test binary in cargo's
# JSON output. `harness settle`: an arm's verdict from its markers.
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


def identity(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def under(path, root):
    root = os.path.realpath(root)
    path = os.path.realpath(path)
    return path == root or path.startswith(root + os.sep)


def crate(meta_path, root):
    root = os.path.realpath(root)
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    members, lib, root_pkg = {}, None, None
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
        if manifest == os.path.join(root, "Cargo.toml"):
            root_pkg = pkg
    # The harness the markers come from must be the copied one. The crate depends on
    # the path member at <root>/shared-test-utils, imported as shared_test_utils, and
    # no other dependency takes that import name. Cargo reads - and _ in a dependency
    # key as one import name, so both spellings are compared.
    stu_dir = os.path.join(root, "shared-test-utils")
    bound = False
    for dep in (root_pkg or {}).get("dependencies", []):
        name, rename, path = dep.get("name") or "", dep.get("rename"), dep.get("path")
        imported = (rename or name).replace("-", "_")
        if name == "shared-test-utils":
            if imported != "shared_test_utils":
                refuse("the crate imports its shared-test-utils dependency as %s; keep the import name shared_test_utils, so the macros come from the copied harness." % rename)
            if not path or not identity(path) or identity(path) != identity(stu_dir):
                refuse("the crate names a shared-test-utils dependency at %s, not the copied %s: the contract macros must come from the harness that run.sh checked." % (path or "a registry", os.path.relpath(stu_dir, root)))
            bound = True
        elif imported == "shared_test_utils":
            refuse("the crate imports %s as shared_test_utils; the contract macros must come from the copied harness." % name)
    if not bound:
        refuse("the crate does not depend on its own shared-test-utils/ (shared-test-utils = { path = \"shared-test-utils\" }): the contract macros must come from the harness that run.sh checked.")
    # A manifest in any letter case, matched to the members by file identity: a
    # filesystem that ignores case lets cargo read cargo.toml as Cargo.toml.
    known = set(identity(manifest) for manifest in members)
    for top, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not (top == root and d in ("target", "markers"))]
        for name in files:
            path = os.path.join(top, name)
            if name.lower() == "cargo.toml" and identity(path) not in known:
                refuse("%s is not a member of the workspace this crate defines, so these checks do not cover it: make it a member or remove it." % os.path.relpath(path, root))
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


LIBS = ("lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro")


def checkbuild(root, build_json, built_file, test):
    # The cargo-test --no-run output for one arm: refuse (exit 3) when a unit of the
    # crate own workspace is reported fresh without this run having built it (a
    # shared build cache handing over another same-named crate artifact), or when
    # this build compiled a shared_test_utils from anywhere but the copied harness,
    # or none at all; then print the arm own test binary. built_file carries, across
    # arms, the artifacts this run built fresh, so a dependency reused between arms
    # (shared-test-utils) stays allowed.
    root = os.path.realpath(root)
    try:
        with open(built_file, encoding="utf-8") as f:
            built = set(line.rstrip("\n") for line in f)
    except OSError:
        built = set()
    fresh_reused, new_built, exe, stu_srcs = [], [], set(), []
    for msg in json_lines(build_json):
        if msg.get("reason") != "compiler-artifact":
            continue
        target = msg.get("target") or {}
        manifest = msg.get("manifest_path", "")
        names = msg.get("filenames") or []
        if under(manifest, root):
            if msg.get("fresh") and not any(n in built for n in names):
                fresh_reused.append(target.get("name", "?"))
            if not msg.get("fresh"):
                new_built.extend(names)
        if target.get("name") == "shared_test_utils" and any(k in LIBS for k in target.get("kind", [])):
            stu_srcs.append(target.get("src_path", ""))
        if (manifest == os.path.join(root, "Cargo.toml") and "test" in target.get("kind", [])
                and target.get("name") == test and msg.get("executable")):
            exe.add(msg["executable"])
    if fresh_reused:
        refuse("cargo reported %s as already built without this run compiling it — a build cache shared with another crate of the same name handed over its artifact. Give this run its own CARGO_TARGET_DIR, or run PoCs one at a time." % ", ".join(sorted(set(fresh_reused))))
    elsewhere = [src for src in stu_srcs if not under(src, os.path.join(root, "shared-test-utils"))]
    if elsewhere:
        refuse("the shared_test_utils this build compiled is %s, outside the copied harness: the contract macros must come from the copy run.sh made." % elsewhere[0])
    if not stu_srcs:
        refuse("this build compiled no shared_test_utils from the copied harness: the contract macros must come from the copy run.sh made.")
    try:
        with open(built_file, "a", encoding="utf-8") as f:
            for n in new_built:
                f.write(n + "\n")
    except OSError:
        pass
    if len(exe) != 1:
        refuse("cargo reported %d test binaries for tests/%s.rs in this crate, not one." % (len(exe), test))
    print(exe.pop())


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


def outcome_of(text):
    # A failed marker reads "<kind> <outcome>: <message>": what the program did.
    head = text.split(":", 1)[0].split(" ")
    return head[1] if len(head) == 2 and re.match(r"^[a-z-]+$", head[1]) else ""


def settle(directory, arm, status, prebuilt, placed_so, placed):
    # Per test: the kinds it started (attempted), held, and failed (ran and did not
    # hold), and the inconclusive lines it left. A failed marker is what the contract
    # macros write just before their verdict panic; an attempted kind with neither a
    # held nor a failed marker is an assertion the process stopped inside — the test
    # died mid-assertion, which decides nothing.
    attempted, held, failed, stuck = (markers(directory, k) for k in ("attempted", "held", "failed", "inconclusive"))
    tests = {}
    for slot, found in enumerate((attempted, held, failed)):
        for test, text in found:
            tests.setdefault(test, ([], [], [], []))[slot].append(kind_of(text))
    for test, text in stuck:
        tests.setdefault(test, ([], [], [], []))[3].append(text)
    counts = COUNTS[arm] if prebuilt == "1" else SUCCEEDS[arm]

    def pending(test):
        # attempted kinds with no matching held or failed: the assertion did not resolve.
        resolved = list(tests[test][1]) + list(tests[test][2])
        out = []
        for kind in tests[test][0]:
            if kind in resolved:
                resolved.remove(kind)
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

    any_failed = any(tests[t][2] for t in tests)
    any_pending = any(pending(t) for t in tests)
    if status != "0":
        verdict = [t for t in sorted(tests) if not tests[t][3] and any(k in counts for k in tests[t][2])]
        if verdict:
            why = bytes_differ()
            if why:
                return say("inconclusive", why)
            how = [outcome_of(text) for test, text in failed if test == verdict[0] and kind_of(text) in counts]
            return say("fail", verdict[0], how[0] if how else "")
        if stuck:
            return say("inconclusive", "%s (test %s)" % (stuck[0][1], stuck[0][0]))
        if any_pending:
            return say("inconclusive", "the test stopped between a contract assertion start and its result; the process ended mid-assertion")
        if not attempted:
            return say("inconclusive", "no contract assertion ran; the test failed before one (did the program load?)")
        if any_failed:
            return say("inconclusive", "the assertion that did not hold is not one this arm counts")
        return say("inconclusive", "every contract assertion that ran held, so the test failed outside them")
    if stuck:
        return say("inconclusive", "%s (test %s)" % (stuck[0][1], stuck[0][0]))
    if any_failed or any_pending:
        return say("inconclusive", "a contract assertion ran and did not hold, yet the test passed")
    shown = [(kind_of(text), "%s (test %s)" % (text.split(": ", 1)[-1], test)) for test, text in held if kind_of(text) in counts]
    if not shown:
        return say("blocker", MISSING[(arm, prebuilt)])
    why = bytes_differ()
    if why:
        return say("inconclusive", why)
    say("pass", *shown[0])


def nonregistry(root, lock, meta_path, builds):
    # The code the run compiled or linked that did not come from a registry: path and
    # git dependencies from Cargo.lock, a target whose source sits outside the crate
    # (a `[lib] path` or a `#[path]` module that a lockfile entry never names), and
    # any such source listed in a compiled binary dep-info (.d) file.
    root = os.path.realpath(root)
    members, paths, found, package = set(), {}, [], None
    out, seen = [], set()

    def note(text):
        if text not in seen:
            seen.add(text)
            out.append(text)

    registry = os.path.realpath(os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo")))
    sysroot = os.path.realpath(os.environ.get("AUDITOR_SYSROOT", "/nonexistent"))

    def outside(path):
        return path and not under(path, root) and not under(path, registry) and not under(path, sysroot)

    with open(meta_path, encoding="utf-8") as f:
        for pkg in json.load(f).get("packages", []):
            members.add((pkg["name"], pkg["version"]))
    depfiles = []
    for build in builds:
        for msg in json_lines(build):
            if msg.get("reason") != "compiler-artifact":
                continue
            pid, manifest = msg.get("package_id", ""), msg.get("manifest_path")
            if manifest and pid.startswith("path+"):
                fragment = pid.rsplit("#", 1)[-1]
                name, at, version = fragment.rpartition("@")
                paths[(name if at else os.path.basename(os.path.dirname(manifest)), version)] = os.path.dirname(manifest)
            target = msg.get("target") or {}
            src = target.get("src_path")
            if manifest == os.path.join(root, "Cargo.toml") and src and outside(src):
                note("%s (path %s)" % (target.get("name", "?"), src))
            for name in msg.get("filenames") or []:
                if name and not name.endswith((".rlib", ".rmeta", ".so", ".dylib", ".dll")):
                    depfiles.append(name + ".d")
            if msg.get("executable"):
                depfiles.append(msg["executable"] + ".d")
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
    for package in found:
        key = (package.get("name", "?"), package.get("version", "?"))
        source = package.get("source")
        if source is None and key not in members:
            note("%s %s (path%s)" % (key[0], key[1], " " + paths[key] if key in paths else ""))
        elif source is not None and source.startswith("git+"):
            note("%s %s (%s)" % (key[0], key[1], source))
    for depfile in set(depfiles):
        try:
            with open(depfile, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for token in re.split(r"(?<!\\)[ \n]+", text.split(":", 1)[-1]):
            token = token.replace("\\ ", " ").strip()
            if token.startswith("/") and os.path.splitext(token)[1] == ".rs" and outside(token):
                note("%s (compiled in)" % token)
    print(flat(", ".join(out)) if out else "none: every dependency comes from a registry")


command, args = sys.argv[1], sys.argv[2:]
if command == "hash":
    print(zhash(args[0]))
elif command == "crate":
    crate(*args)
elif command == "targetdir":
    with open(args[0], encoding="utf-8") as f:
        print(json.load(f).get("target_directory") or "")
elif command == "checkbuild":
    checkbuild(*args)
elif command == "settle":
    settle(*args)
elif command == "nonregistry":
    nonregistry(args[0], args[1], args[2], args[3:])
else:
    sys.exit(2)
'
harness() { python3 -I -c "${HARNESS_PY}" "$@"; }

# ── Where to build (see WHERE IT BUILDS above) ──────────────────────────────────
# No here-documents or here-strings below: bash 3.2 may put their temp files in the
# working directory (it does under a sandbox that denies /tmp), where a listing of
# the crate would pick them up.

# The first symbolic link, .cargo/ or rust-toolchain* inside the crate, in any letter
# case; prints nothing when there is none. copy_crate takes none of them, so a crate
# holding one is refused rather than built in a shape it was not written in.
crate_extra() {
  local found
  found="$(cd "${HERE}" && find . \( -iname target -type d \) -prune -o \( -type l -o -iname .cargo -o -iname 'rust-toolchain*' \) -print)"
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

# copy_crate <dest> : the crate's files, never target/, .cargo/ or rust-toolchain* in any
# letter case (cargo would take build outputs in a TARGET/ copy for its own). The
# copies are stamped with the time of the copy, never the originals': with a shared
# CARGO_TARGET_DIR, cargo would otherwise count a build of another crate of the same
# name, made after these files were last changed, as this crate's own.
copy_crate() {
  local list rel IFS=$'\n'
  list="$(cd "${HERE}" && find . \( \( -iname target -type d \) -o -iname .cargo -o -iname 'rust-toolchain*' -o -iname .git \) -prune -o -type f -print)" || return 1
  set -f
  for rel in ${list}; do
    if ! { mkdir -p "$1/$(dirname "${rel}")" && cp "${HERE}/${rel}" "$1/${rel}"; }; then
      set +f; return 1
    fi
  done
  set +f
  return 0
}

# The build lock. When the target directory is shared between runs (a build cache),
# two crates of the same name resolve to the same cached artifact path, so this run
# holds a lock inside that directory from just before each arm's build until its
# test binary exits, and re-stamps the scratch copy under the lock so cargo rebuilds
# this crate's own code rather than reuse another run's. With a private target
# directory the lock is uncontended. The fresh check in `harness checkbuild` is a
# second guard. (With no shared cache this is one empty directory made and removed.)
# The lock names its holder's pid. A lock whose holder is gone is broken by one run at
# a time (the .break directory beside it), and only while it still names that holder;
# a run drops the lock only while it still names this run.
restamp() {  # give the scratch copy's own files the current time, under the lock
  find "${BUILD_DIR}" \( \( -iname target -type d \) -o -path "${RUN_DIR}" \) -prune -o -type f -exec touch {} + 2>/dev/null || true
  return 0
}
lock_holder() {  # the pid the lock names, or nothing
  local pid
  pid="$(cat "${LOCK}/pid" 2>/dev/null || true)"
  if [[ "${pid}" =~ ^[0-9]+$ ]]; then echo "${pid}"; fi
  return 0
}
acquire_lock() {  # take the build lock, then re-stamp; 0 on success, non-zero to block
  local waited=0 holder broken
  mkdir -p "${EFFECTIVE_TARGET}" 2>/dev/null || return 1
  while ! mkdir "${LOCK}" 2>/dev/null; do
    holder="$(lock_holder)"
    if [[ -n "${holder}" ]] && ! kill -0 "${holder}" 2>/dev/null && mkdir "${LOCK}.break" 2>/dev/null; then
      broken=0
      if [[ "$(lock_holder)" == "${holder}" ]]; then rm -rf "${LOCK}" 2>/dev/null || broken=1; fi
      rmdir "${LOCK}.break" 2>/dev/null || true
      [[ "${broken}" -eq 0 ]] || return 1
      continue
    fi
    waited=$((waited + 1))
    if [[ "${waited}" -gt "${LOCK_WAIT}" ]]; then return 2; fi
    sleep 1
  done
  # The pid is written aside and renamed in, so no run reads a partial one.
  if ! { echo "$$" > "${LOCK}/pid.$$" && mv -f "${LOCK}/pid.$$" "${LOCK}/pid"; } 2>/dev/null; then
    rm -rf "${LOCK}" 2>/dev/null || true
    return 1
  fi
  LOCK_HELD=1
  restamp
  return 0
}
release_lock() {
  if [[ "${LOCK_HELD}" == 1 ]]; then
    if [[ "$(lock_holder)" == "$$" ]]; then rm -rf "${LOCK}" 2>/dev/null || true; fi
    LOCK_HELD=0
  fi
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
if [[ "${CLEAN}" == 1 ]]; then
  case "${BUILD_DIR}/" in
    "${WT%/}/"*) echo "[PoC-ATTEMPTED] blocker: the scratch build directory ${BUILD_DIR} lies inside the working directory; point TMPDIR outside it." >&2
                 exit 3 ;;
  esac
fi
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
# The installation's copy: a throwaway HOME and TMPDIR in run.sh's own files, and the
# cleaned environment every child gets (scripts/lib/isolation.sh).
if [[ "${CLEAN}" == 1 ]]; then
  if ! iso_env "${RUN_DIR}"; then
    echo "[PoC-ATTEMPTED] blocker: cannot prepare the cleaned environment (a throwaway HOME and TMPDIR) in ${RUN_DIR}." >&2
    exit 3
  fi
  if [[ -n "${CACHE_DIR}" ]]; then ISO_ENV+=("CARGO_TARGET_DIR=${CACHE_DIR}"); fi
  echo ">> environment: env -i; HOME ${ISO_HOME} (throwaway, with a fresh Solana keypair); TMPDIR ${ISO_TMP}"
fi
# Pin the toolchain instead of letting rustup look for a rust-toolchain file.
if [[ -z "${RUSTUP_TOOLCHAIN:-}" ]] && command -v rustup >/dev/null 2>&1; then
  default_tc="$(cd "${BUILD_DIR}" && child rustup default 2>/dev/null || true)"
  case "${default_tc}" in
    *"(default)"*) export RUSTUP_TOOLCHAIN="${default_tc%% *}" ;;
    *) echo "[PoC-ATTEMPTED] blocker: no Rust toolchain to pin — set RUSTUP_TOOLCHAIN or a rustup default." >&2
       exit 3 ;;
  esac
fi
# mollusk reads BPF_OUT_DIR before SBF_OUT_DIR; only the arm placed below may load.
unset BPF_OUT_DIR
export SBF_OUT_DIR="${BUILD_DIR}/target/deploy"
if [[ "${CLEAN}" == 1 ]]; then
  ISO_ENV+=("SBF_OUT_DIR=${SBF_OUT_DIR}")
  if [[ -n "${RUSTUP_TOOLCHAIN:-}" ]]; then ISO_ENV+=("RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN}"); fi
fi
if ! { cd "${BUILD_DIR}" && mkdir -p "${SBF_OUT_DIR}"; }; then
  echo "[PoC-ATTEMPTED] blocker: cannot prepare ${SBF_OUT_DIR}." >&2
  exit 3
fi
# The set of artifacts this run compiles fresh (the fresh check in `harness
# checkbuild` reads it across arms).
: > "${RUN_DIR}/built" || true
echo ">> build dir: ${BUILD_DIR} (scratch copy outside the target tree; AUDITOR_EXEC_MODE=${AUDITOR_EXEC_MODE}; toolchain ${RUSTUP_TOOLCHAIN:-unpinned: no rustup}; $([[ "${KEEP_POC_BUILD:-0}" == 1 ]] && echo kept || echo removed on exit))"

# What the crate builds, from its manifests: nothing compiles in these steps.
if ! child cargo metadata --no-deps --format-version 1 --manifest-path "${BUILD_DIR}/Cargo.toml" > "${RUN_DIR}/metadata.json"; then
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
# The directory cargo builds into, as cargo metadata reports it — CARGO_TARGET_DIR,
# CARGO_BUILD_TARGET_DIR or a target-dir in cargo's own config (a shared cache), else
# this run's own — and the build lock inside it.
EFFECTIVE_TARGET="$(harness targetdir "${RUN_DIR}/metadata.json")" || EFFECTIVE_TARGET=""
if [[ "${EFFECTIVE_TARGET}" != /* ]]; then
  echo "[PoC-ATTEMPTED] blocker: cargo metadata names no target directory for the crate, so run.sh cannot place its build lock." >&2
  exit 3
fi
LOCK="${EFFECTIVE_TARGET}/.auditor-poc-build.lock"
echo ">> target dir: ${EFFECTIVE_TARGET} (the build lock goes here)"

# Dependency pins (see DEPENDENCY PINS above).
if [[ ! -f "${HERE}/Cargo.lock" ]]; then
  echo ">> no Cargo.lock in the crate: cargo resolves every dependency to its newest compatible release now; the resolved lock is kept with the crate"
fi
set -f
for spec in ${UPDATE_PINS:-}; do
  echo ">> moving the ${spec} pin: cargo update -p ${spec}, in the scratch copy"
  if ! child_net cargo update --manifest-path "${BUILD_DIR}/Cargo.toml" --package "${spec}"; then
    echo "[PoC-ATTEMPTED] blocker: cargo update -p ${spec} failed — see the cargo output above." >&2
    exit 3
  fi
done
set +f

# The dynamic library path `cargo test` gives a test binary: its deps directory, the
# directory above, the toolchain's target libdir, then what the caller had.
# In the cleaned environment there is nothing the caller had: cargo's own default.
case "$(uname -s 2>/dev/null || true)" in
  Darwin) LIBPATH_VAR=DYLD_FALLBACK_LIBRARY_PATH; LIBPATH_REST="${DYLD_FALLBACK_LIBRARY_PATH:-${HOME:-/nonexistent}/lib:/usr/local/lib:/usr/lib}"
          if [[ "${CLEAN}" == 1 ]]; then LIBPATH_REST="${ISO_HOME}/lib:/usr/local/lib:/usr/lib"; fi ;;
  *) LIBPATH_VAR=LD_LIBRARY_PATH; LIBPATH_REST="${LD_LIBRARY_PATH:-}"
     if [[ "${CLEAN}" == 1 ]]; then LIBPATH_REST=""; fi ;;
esac
SYSROOT_LIB="$(child "${RUSTC:-rustc}" --print target-libdir 2>/dev/null || true)"
# The toolchain's own source, so `harness nonregistry` does not read the standard
# library as out-of-tree code.
export AUDITOR_SYSROOT="$(child "${RUSTC:-rustc}" --print sysroot 2>/dev/null || echo /nonexistent)"

place_arm() {  # place_arm <arm> : put <crate>.so in SBF_OUT_DIR for this arm; PLACED_HASH names its bytes
  local arm="$1" so="${SBF_OUT_DIR}/${CRATE}.so"
  # Drop the other arm's bytes first, so a build that writes nothing cannot leave them.
  rm -f "${so}" 2>/dev/null || true
  if [[ "${PREBUILT}" -eq 1 ]]; then
    local src; [[ "${arm}" == "vulnerable" ]] && src="${VULNERABLE_SO}" || src="${FIXED_SO}"
    if ! cp -f "${src}" "${so}"; then
      echo "[PoC-ATTEMPTED] blocker: could not place the ${arm} .so from ${src}." >&2
      exit 3
    fi
    echo ">> ${arm} arm: prebuilt ${src}"
  else
    echo ">> building '${arm}' arm to SBF (${CRATE}.so)"
    if ! child_sbf cargo build-sbf \
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
  if ! child_net cargo test --manifest-path "${BUILD_DIR}/Cargo.toml" \
        --no-default-features --features "$1" --test "$2" --no-run \
        --message-format=json-render-diagnostics > "${json}"; then
    echo "[PoC-ATTEMPTED] blocker: tests/$2.rs failed to build for the $1 arm — see the cargo output above." >&2
    exit 3
  fi
  # checkbuild prints the arm's own test binary, or refuses (exit 3): a crate unit
  # reported fresh that this run never built (a shared cache handed it over), a
  # shared_test_utils compiled from outside the copied harness or none at all, or no
  # single test.
  EXE="$(harness checkbuild "${BUILD_DIR}" "${json}" "${RUN_DIR}/built" "$2")" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    if [[ "${rc}" -eq 3 ]]; then echo "[PoC-ATTEMPTED] blocker: ${EXE}" >&2
    else echo "[PoC-ATTEMPTED] blocker: could not read the $1 build output for tests/$2.rs." >&2; fi
    exit 3
  fi
  if [[ ! -x "${EXE}" ]]; then
    echo "[PoC-ATTEMPTED] blocker: the test binary cargo named for tests/$2.rs is not executable (${EXE})." >&2
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
  child "AUDITOR_POC_MARKERS=${dir}" "CARGO_MANIFEST_DIR=${BUILD_DIR}" \
    "${LIBPATH_VAR}=${deps}:$(dirname "${deps}")${SYSROOT_LIB:+:${SYSROOT_LIB}}${LIBPATH_REST:+:${LIBPATH_REST}}" \
    "${EXE}" --nocapture
}

inconclusive() {  # inconclusive <arm> <reason>: the arm decided nothing — a blocker, never a verdict
  local what="whether the fix holds"
  [[ "$1" == vulnerable ]] && what="whether the exploit reproduces"
  echo "[PoC-ATTEMPTED] blocker: the $1 arm is inconclusive: $2. This run does not show ${what}; repair the PoC's harness setup, never its assertions or the target, and re-run." >&2
  exit 3
}

# settle <arm> <status>: the verdict on an arm from its test's exit status and the
# markers each test left. Returns 0 when the arm held (HELD_KIND and HELD_LINE say
# how) and 1 for a verdict against it — an assertion of the arm ran and did not hold,
# on the placed bytes, and FAILED_HOW names what the program did; exits 3 for
# everything else.
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
    fail) FAILED_HOW="${out#*"${tab}"}"; echo "   failed: test ${out%%"${tab}"*}"; return 1 ;;
    inconclusive) inconclusive "$1" "${out}" ;;
    *) echo "[PoC-ATTEMPTED] blocker: ${out}" >&2; exit 3 ;;
  esac
}

NONREG=""
capture_nonreg() {  # the non-registry code, read right after a build (before a test can rewrite the lock)
  NONREG="$(harness nonregistry "${BUILD_DIR}" "${BUILD_DIR}/Cargo.lock" "${RUN_DIR}/metadata.json" "${RUN_DIR}"/build-*.json 2>/dev/null)" \
    || NONREG="unknown — ${BUILD_DIR}/Cargo.lock could not be read"
}
nonregistry() {  # the path and git dependencies and out-of-tree sources the build pulled in
  echo "   non-registry code: ${NONREG:-unknown — no build was read}"
}

HELD_KIND=""
HELD_LINE=""
FAILED_HOW=""

# 1. vulnerable arm — the exploit must land. The lock spans the build and the test.
acquire_lock || { echo "[PoC-ATTEMPTED] blocker: could not take the build lock in ${EFFECTIVE_TARGET} (another PoC run may hold it, or the directory is not writable)." >&2; exit 3; }
place_arm vulnerable
VULNERABLE_HASH="${PLACED_HASH}"
build_tests vulnerable exploit
capture_nonreg
echo ">> running exploit against 'vulnerable' (expect: SUCCEEDS)"
status=0
run_tests vulnerable || status=$?
release_lock
if ! settle vulnerable "${status}"; then
  nonregistry
  echo "FAIL: exploit did not reproduce on the vulnerable arm — PoC is not valid." >&2
  VERDICT=1; exit 1
fi
if [[ "${PREBUILT}" -eq 1 ]]; then
  echo "   effect: ${HELD_LINE}"
  if [[ -z "${FIXED_SO}" ]]; then
    nonregistry
    echo "OK: reproduced on prebuilt bytes — vulnerable sha256=${VULNERABLE_HASH} → [PoC-REPRODUCED]"
    VERDICT=0; exit 0
  fi
fi

# 2. fixed arm — the same attack must be turned away.
acquire_lock || { echo "[PoC-ATTEMPTED] blocker: could not take the build lock in ${EFFECTIVE_TARGET} (another PoC run may hold it, or the directory is not writable)." >&2; exit 3; }
place_arm fixed
build_tests fixed fixed_blocked
capture_nonreg
echo ">> running same attack against 'fixed' (expect: REJECTED)"
status=0
run_tests fixed || status=$?
release_lock
if ! settle fixed "${status}"; then
  nonregistry
  case "${FAILED_HOW}" in
    accepted) echo "FAIL: the fixed arm accepted the attack — fix is incomplete." >&2 ;;
    changed) echo "FAIL: the fixed arm failed the attack, yet the account changed — fix is incomplete." >&2 ;;
    other-error) echo "FAIL: the fixed arm rejected the attack with another error than the pinned one — the test's message names both." >&2 ;;
    *) echo "FAIL: the fixed arm did not block the attack — fix is incomplete." >&2 ;;
  esac
  VERDICT=2; exit 2
fi
nonregistry
if [[ "${PREBUILT}" -eq 0 ]]; then
  echo "OK: exploit reproduces on 'vulnerable' and is blocked on 'fixed' (this crate's own arms: a model, never Leg 3)  → [PoC-REPRODUCED]"
  VERDICT=0; exit 0
fi
how="blocked: failed, account unchanged"
if [[ "${HELD_KIND}" == rejected_with ]]; then how="rejected with the pinned error"; fi
echo "   fixed arm: ${HELD_LINE}"
echo "OK: reproduced on prebuilt bytes — vulnerable sha256=${VULNERABLE_HASH} fixed sha256=${PLACED_HASH} (${how}) → [PoC-REPRODUCED]"
VERDICT=0; exit 0
