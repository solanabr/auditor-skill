#!/usr/bin/env bash
# {FINDING_ID} — one-command proof-of-concept runner.
#
# Reproduces the finding from a clean checkout of THIS crate:
#   1. builds the `vulnerable` arm to SBF, runs tests/exploit.rs      → exploit must SUCCEED
#   2. builds the `fixed`      arm to SBF, runs tests/fixed_blocked.rs → same attack must be REJECTED
# Exit 0: the exploit reproduces on `vulnerable` and is blocked on `fixed` — the
# evidence that earns [PoC-REPRODUCED]. Exit 1: the exploit did not reproduce. Exit 2:
# the fixed arm did not block it. Exit 3: a named blocker (toolchain, inputs, or the
# execution mode below) — record [PoC-ATTEMPTED] and keep the prose PoC.
#
# Why two build+test passes and not one: both arms compile to the SAME `.so`
# filename ({PROGRAM_NAME}.so), so they cannot coexist in SBF_OUT_DIR. Build an arm,
# test it, then overwrite with the other arm. Mollusk loads the `.so`, never the
# host test binary — so the SBF build MUST precede each `cargo test`.
#
# Toolchain: cargo-build-sbf's default bundle is platform-tools v1.51 / cargo 1.84,
# which cannot parse the edition2024 manifests in the mollusk-svm dep tree. We pin
# --tools-version v1.54 (cargo >= 1.85) to build the graph with no dependency edits.
# Override via TOOLS_VERSION=... if the target repo standardizes on a newer one.
#
# WHERE IT BUILDS. This crate normally sits inside the audited repo
# (audit_<n>/poc/…, incident_<n>/poc/…). Built there, cargo would read the target's
# .cargo/config* from every parent directory (rustc-wrapper, runner, linker,
# rustflags, an alias that shadows `build-sbf`), and rustup its rust-toolchain*
# (which can name a `path` toolchain, i.e. any binaries) — target-controlled code at
# build time, even for a crate that depends on nothing of the target's. So:
#   * a self-contained crate — no git dependency, no manifest path that leaves this
#     directory, no `workspace = true`, no symlink, no .cargo/ or rust-toolchain* of
#     its own — is copied (without target/) into a fresh scratch directory,
#     `mktemp -d "${TMPDIR:-/tmp}/auditor-poc.XXXXXX"`, and built and tested there
#     with RUSTUP_TOOLCHAIN pinned to the caller's value, else rustup's default. The
#     directory is printed, and removed on exit unless KEEP_POC_BUILD=1; the resolved
#     Cargo.lock is copied back next to this file. To reuse compiled dependencies
#     across runs, export CARGO_TARGET_DIR to a cache directory outside any repository.
#   * a crate that depends on target code is target-controlled however it is built.
#     It builds in place only when the caller passes the execution mode recorded for
#     the run, AUDITOR_EXEC_MODE=isolated|native (OUTPUT-RULES.md Rule 11a);
#     otherwise it exits 3.
#
# INCIDENT MODE (detection & response, references/detection-response/): Leg 3 of
# `confirmed_exploited` requires the REAL program bytes, not a minimized replica.
# Set BOTH of these to run each arm against a prebuilt .so instead of building:
#     VULNERABLE_SO=/path/to/deployed-or-vulnerable.so  \
#     FIXED_SO=/path/to/patched-or-current.so           ./run.sh
#   * both-or-neither: setting only one exits 3.
#   * a bad path, a file without the ELF magic, or a missing `cargo` all exit 3
#     (a named precondition failure, never a bare `cp` error).
#   * the tests must be in incident form, or it exits 3: tests/exploit.rs asserts
#     the observed effect via `outcome.get_account(&pk)`, and tests/fixed_blocked.rs
#     pins the guard's error with `assert_exploit_rejected_with!`.
#   * the incident commit is built natively ONLY when its root cause is not supply
#     chain / CI; otherwise supply the dumped ELF here (OUTPUT-RULES.md Rule 11a).

set -euo pipefail

# ── Fill in ─────────────────────────────────────────────────────────────────────
CRATE="{PROGRAM_NAME}"          # package name == compiled .so base name
# ────────────────────────────────────────────────────────────────────────────────

TOOLS_VERSION="${TOOLS_VERSION:-v1.54}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

VULNERABLE_SO="${VULNERABLE_SO:-}"
FIXED_SO="${FIXED_SO:-}"
PREBUILT=0
if [[ -n "${VULNERABLE_SO}" || -n "${FIXED_SO}" ]]; then
  # both-or-neither
  if [[ -z "${VULNERABLE_SO}" || -z "${FIXED_SO}" ]]; then
    echo "[PoC-ATTEMPTED] blocker: VULNERABLE_SO and FIXED_SO are both-or-neither — set both or neither." >&2
    exit 3
  fi
  for pair in "vulnerable:${VULNERABLE_SO}" "fixed:${FIXED_SO}"; do
    arm="${pair%%:*}"; path="${pair#*:}"
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
  # The build may run from a scratch directory, so pin both paths absolute now.
  abs_path() {
    local p="$1" d f
    case "${p}" in */*) d="${p%/*}"; f="${p##*/}" ;; *) d="."; f="${p}" ;; esac
    d="$(cd "${d:-/}" && pwd -P)"
    [[ "${d}" == "/" ]] && d=""
    printf '%s/%s\n' "${d}" "${f}"
  }
  VULNERABLE_SO="$(abs_path "${VULNERABLE_SO}")"
  FIXED_SO="$(abs_path "${FIXED_SO}")"
  # On real bytes, `Ok` / "any Err" prove nothing about the incident. Incident mode
  # therefore requires, in live (non-comment) code:
  #   * tests/exploit.rs asserts the observed Leg-1 effect through
  #     `outcome.get_account(&pk)` — the account the attack changed, as seen on-chain;
  #   * tests/fixed_blocked.rs pins the guard's error with
  #     `assert_exploit_rejected_with!`, not the any-error form.
  live() {  # live <file> <regex> : a match on a line that is not a // comment
    grep -E "$2" "$1" 2>/dev/null | grep -Ev '^[[:space:]]*//' | grep -q .
  }
  if ! live "${HERE}/tests/exploit.rs" 'get_account[[:space:]]*\('; then
    echo "[PoC-ATTEMPTED] blocker: prebuilt (incident) mode needs tests/exploit.rs to assert the observed effect via outcome.get_account(&pk) — Ok alone proves nothing on real bytes." >&2
    exit 3
  fi
  if ! live "${HERE}/tests/fixed_blocked.rs" 'assert_exploit_rejected_with!'; then
    echo "[PoC-ATTEMPTED] blocker: prebuilt (incident) mode needs tests/fixed_blocked.rs to pin the guard's error with assert_exploit_rejected_with! — any Err is not a fix." >&2
    exit 3
  fi
  PREBUILT=1
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

# ── Where to build (see WHERE IT BUILDS above) ──────────────────────────────────
# No here-documents or here-strings below: bash 3.2 may put their temp files in the
# working directory (it does under a sandbox that denies /tmp), where a listing of
# the crate would pick them up.

# Prints why the crate reaches outside its own directory; prints nothing when it is
# self-contained. Comments are stripped first; a false positive only asks for the
# execution mode.
target_dependency() {
  local found list m body IFS=$'\n'
  local re_git='(^|[^[:alnum:]_-])git[[:space:]]*='
  local re_out="=[[:space:]]*[\"'](/|([^\"']*/)?\\.\\.(/|[\"']))"
  local re_ws='workspace[[:space:]]*=[[:space:]]*true'
  found="$(cd "${HERE}" && find . \( -name target -type d \) -prune -o \( -type l -o -name .cargo -o -name 'rust-toolchain*' \) -print)"
  if [[ -n "${found}" ]]; then
    echo "${found%%$'\n'*} inside the crate (symlink, .cargo/ or rust-toolchain)"
    return 0
  fi
  list="$(cd "${HERE}" && find . \( -name target -type d \) -prune -o -name Cargo.toml -type f -print)"
  set -f
  for m in ${list}; do
    body="$(sed 's/#.*//' "${HERE}/${m}")"
    if [[ "${body}" =~ ${re_git} ]]; then echo "a git dependency in ${m#./}"; break; fi
    if [[ "${body}" =~ ${re_out} ]]; then echo "a path that leaves the crate in ${m#./}"; break; fi
    if [[ "${body}" =~ ${re_ws} ]]; then echo "a workspace-inherited dependency in ${m#./}"; break; fi
  done
  set +f
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

copy_crate() {  # copy_crate <dest> : the crate's files, never target/, .cargo/ or rust-toolchain*
  local list rel IFS=$'\n'
  list="$(cd "${HERE}" && find . \( \( -name target -type d \) -o -name .cargo -o -name 'rust-toolchain*' -o -name .git \) -prune -o -type f -print)" || return 1
  set -f
  for rel in ${list}; do
    if ! { mkdir -p "$1/$(dirname "${rel}")" && cp -p "${HERE}/${rel}" "$1/${rel}"; }; then
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

dep_reason="$(target_dependency)"
if [[ -n "${dep_reason}" ]]; then
  case "${AUDITOR_EXEC_MODE:-}" in
    isolated|native)
      echo ">> target-dependent crate (${dep_reason}): building in place under AUDITOR_EXEC_MODE=${AUDITOR_EXEC_MODE} (OUTPUT-RULES.md Rule 11a); the target's .cargo/config and rust-toolchain apply."
      BUILD_DIR="${HERE}"
      ;;
    *)
      echo "[PoC-ATTEMPTED] blocker: this PoC crate depends on target code (${dep_reason}), so building it runs target-controlled code (build scripts, proc-macros, the target's .cargo/config and rust-toolchain). Run it in the execution mode recorded for this run — AUDITOR_EXEC_MODE=isolated inside the isolated runner, or AUDITOR_EXEC_MODE=native (the report then states that target code ran on this host). OUTPUT-RULES.md Rule 11a." >&2
      exit 3
      ;;
  esac
else
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
  # Pin the toolchain instead of letting rustup look for a rust-toolchain file.
  if [[ -z "${RUSTUP_TOOLCHAIN:-}" ]] && command -v rustup >/dev/null 2>&1; then
    default_tc="$(cd "${BUILD_DIR}" && rustup default 2>/dev/null || true)"
    case "${default_tc}" in
      *"(default)"*) export RUSTUP_TOOLCHAIN="${default_tc%% *}" ;;
      *) echo "[PoC-ATTEMPTED] blocker: no Rust toolchain to pin — set RUSTUP_TOOLCHAIN or a rustup default." >&2
         exit 3 ;;
    esac
  fi
fi
cd "${BUILD_DIR}"
export SBF_OUT_DIR="${BUILD_DIR}/target/deploy"
mkdir -p "${SBF_OUT_DIR}"
if [[ "${BUILD_DIR}" == "${HERE}" ]]; then
  echo ">> build dir: ${BUILD_DIR} (in place)"
else
  echo ">> build dir: ${BUILD_DIR} (scratch copy outside the target tree; toolchain ${RUSTUP_TOOLCHAIN:-unpinned: no rustup}; $([[ "${KEEP_POC_BUILD:-0}" == 1 ]] && echo kept || echo removed on exit))"
fi

# Print the .so path and a solana-verify-style hash: trailing zero padding (the
# loader pads a program account well past the ELF — a live JUP6 dump carried
# ~892 KB of it) is trimmed before hashing, so the digest matches `solana-verify`.
# python3 runs isolated (-I): `python3 -` would otherwise import a hashlib.py from
# the caller's working directory, or from PYTHONPATH, in place of the stdlib.
elf_hash() {
  local path="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 -I - "$path" <<'PY'
import hashlib, sys
b = open(sys.argv[1], "rb").read().rstrip(b"\x00")
print(hashlib.sha256(b).hexdigest())
PY
  else
    echo "(hash unavailable: python3 not found)"
  fi
}

place_arm() {  # place_arm <arm> : put {CRATE}.so in SBF_OUT_DIR for this arm
  local arm="$1" so="${SBF_OUT_DIR}/${CRATE}.so"
  if [[ "${PREBUILT}" -eq 1 ]]; then
    local src; [[ "${arm}" == "vulnerable" ]] && src="${VULNERABLE_SO}" || src="${FIXED_SO}"
    cp -f "${src}" "${so}"
    echo ">> ${arm} arm: prebuilt ${src}"
  else
    echo ">> building '${arm}' arm to SBF (${CRATE}.so)"
    cargo build-sbf \
      --tools-version "${TOOLS_VERSION}" \
      --manifest-path "${BUILD_DIR}/Cargo.toml" \
      --no-default-features --features "${arm}" \
      --sbf-out-dir "${SBF_OUT_DIR}"
  fi
  echo "   ${arm} .so: ${so}"
  echo "   ${arm} sha256 (zero-trimmed): $(elf_hash "${so}")"
}

# 1. vulnerable arm — the exploit must land.
place_arm vulnerable
echo ">> running exploit against 'vulnerable' (expect: SUCCEEDS)"
if ! cargo test --manifest-path "${BUILD_DIR}/Cargo.toml" \
      --no-default-features --features vulnerable \
      --test exploit -- --nocapture; then
  echo "FAIL: exploit did not reproduce on the vulnerable arm — PoC is not valid." >&2
  exit 1
fi

# 2. fixed arm — the same attack must be turned away.
place_arm fixed
echo ">> running same attack against 'fixed' (expect: REJECTED)"
if ! cargo test --manifest-path "${BUILD_DIR}/Cargo.toml" \
      --no-default-features --features fixed \
      --test fixed_blocked -- --nocapture; then
  echo "FAIL: the fixed arm did not block the attack — fix is incomplete." >&2
  exit 2
fi

echo "OK: exploit reproduces on 'vulnerable' and is blocked on 'fixed'  → [PoC-REPRODUCED]"
