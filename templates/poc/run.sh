#!/usr/bin/env bash
# {FINDING_ID} — one-command proof-of-concept runner.
#
# Reproduces the finding from a clean checkout of THIS crate:
#   1. builds the `vulnerable` arm to SBF, runs tests/exploit.rs      → exploit must SUCCEED
#   2. builds the `fixed`      arm to SBF, runs tests/fixed_blocked.rs → same attack must be REJECTED
# Exits non-zero if the exploit does not reproduce on `vulnerable`, or is not blocked
# on `fixed`. A green run is the evidence that earns the [PoC-REPRODUCED] tier.
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
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SBF_OUT_DIR="${HERE}/target/deploy"
mkdir -p "${SBF_OUT_DIR}"

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

# Print the .so path and a solana-verify-style hash: trailing zero padding (the
# loader pads a program account well past the ELF — a live JUP6 dump carried
# ~892 KB of it) is trimmed before hashing, so the digest matches `solana-verify`.
elf_hash() {
  local path="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$path" <<'PY'
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
      --manifest-path "${HERE}/Cargo.toml" \
      --no-default-features --features "${arm}" \
      --sbf-out-dir "${SBF_OUT_DIR}"
  fi
  echo "   ${arm} .so: ${so}"
  echo "   ${arm} sha256 (zero-trimmed): $(elf_hash "${so}")"
}

# 1. vulnerable arm — the exploit must land.
place_arm vulnerable
echo ">> running exploit against 'vulnerable' (expect: SUCCEEDS)"
if ! cargo test --manifest-path "${HERE}/Cargo.toml" \
      --no-default-features --features vulnerable \
      --test exploit -- --nocapture; then
  echo "FAIL: exploit did not reproduce on the vulnerable arm — PoC is not valid." >&2
  exit 1
fi

# 2. fixed arm — the same attack must be turned away.
place_arm fixed
echo ">> running same attack against 'fixed' (expect: REJECTED)"
if ! cargo test --manifest-path "${HERE}/Cargo.toml" \
      --no-default-features --features fixed \
      --test fixed_blocked -- --nocapture; then
  echo "FAIL: the fixed arm did not block the attack — fix is incomplete." >&2
  exit 2
fi

echo "OK: exploit reproduces on 'vulnerable' and is blocked on 'fixed'  → [PoC-REPRODUCED]"
