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

set -euo pipefail

# ── Fill in ─────────────────────────────────────────────────────────────────────
CRATE="{PROGRAM_NAME}"          # package name == compiled .so base name
# ────────────────────────────────────────────────────────────────────────────────

TOOLS_VERSION="${TOOLS_VERSION:-v1.54}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SBF_OUT_DIR="${HERE}/target/deploy"
mkdir -p "${SBF_OUT_DIR}"

if ! command -v cargo-build-sbf >/dev/null 2>&1; then
  echo "[PoC-ATTEMPTED] blocker: cargo-build-sbf not on PATH — install the Solana/Agave toolchain (platform-tools >= ${TOOLS_VERSION})." >&2
  echo "The finding's prose PoC stands; this crate could not be built here." >&2
  exit 3
fi

build_arm() {
  local arm="$1"
  echo ">> building '${arm}' arm to SBF (${CRATE}.so)"
  cargo build-sbf \
    --tools-version "${TOOLS_VERSION}" \
    --manifest-path "${HERE}/Cargo.toml" \
    --no-default-features --features "${arm}" \
    --sbf-out-dir "${SBF_OUT_DIR}"
}

# 1. vulnerable arm — the exploit must land.
build_arm vulnerable
echo ">> running exploit against 'vulnerable' (expect: SUCCEEDS)"
if ! cargo test --manifest-path "${HERE}/Cargo.toml" \
      --no-default-features --features vulnerable \
      --test exploit -- --nocapture; then
  echo "FAIL: exploit did not reproduce on the vulnerable arm — PoC is not valid." >&2
  exit 1
fi

# 2. fixed arm — the same attack must be turned away.
build_arm fixed
echo ">> running same attack against 'fixed' (expect: REJECTED)"
if ! cargo test --manifest-path "${HERE}/Cargo.toml" \
      --no-default-features --features fixed \
      --test fixed_blocked -- --nocapture; then
  echo "FAIL: the fixed arm did not block the attack — fix is incomplete." >&2
  exit 2
fi

echo "OK: exploit reproduces on 'vulnerable' and is blocked on 'fixed'  → [PoC-REPRODUCED]"
