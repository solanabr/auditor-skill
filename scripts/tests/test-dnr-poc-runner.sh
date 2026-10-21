#!/usr/bin/env bash
# test-dnr-poc-runner.sh — self-test for templates/poc/run.sh's incident (prebuilt)
# mode: the VULNERABLE_SO / FIXED_SO preconditions and the zero-trimmed hash, which
# is computed with `python3 -I` so a hashlib.py in the working directory never loads.
#
# No Solana toolchain and no network needed: a temp copy of the template runs with a
# `cargo` shim (always exits 0) or with a PATH that has no cargo at all. bash >= 3.2;
# uses only standard POSIX tools + python3. Exits non-zero on the first failure.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/../../templates/poc"
fails=0
ok()  { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1" >&2; fails=$((fails+1)); }

T="$(mktemp -d "${TMPDIR:-/tmp}/dnr_runner.XXXXXX")"
trap 'rm -rf "$T"' EXIT

# A crate copy whose tests are in incident form (live get_account + live
# assert_exploit_rejected_with!), and one left in the template's audit form.
mk_crate() {  # mk_crate <dir> incident|audit
  mkdir -p "$1/tests"
  cp "$TEMPLATE/run.sh" "$1/run.sh"
  if [ "$2" = incident ]; then
    printf '    let post = outcome.get_account(&state_pk).expect("x");\n' > "$1/tests/exploit.rs"
    printf '    assert_exploit_rejected_with!(outcome, ProgramResult::Failure(e), "g");\n' > "$1/tests/fixed_blocked.rs"
  else
    cp "$TEMPLATE/tests/exploit.rs" "$1/tests/exploit.rs"
    cp "$TEMPLATE/tests/fixed_blocked.rs" "$1/tests/fixed_blocked.rs"
  fi
}
mk_crate "$T/inc" incident
mk_crate "$T/aud" audit

# Program-byte fixtures: an ELF with 4 KiB of trailing zero padding, a file that is
# a loader-v3 ProgramData account WITH its 45-byte header (wrong for run.sh — the
# magic is not at offset 0), and a non-binary.
python3 -I - "$T" <<'PY'
import sys
d = sys.argv[1]
elf = b"\x7fELF" + bytes(range(1, 60))
open(f"{d}/vuln.so", "wb").write(elf + b"\x00" * 4096)
open(f"{d}/fixed.so", "wb").write(elf[:-1] + b"\x99" + b"\x00" * 128)
open(f"{d}/with-header.bin", "wb").write((3).to_bytes(4, "little") + b"\x00" * 41 + elf)
open(f"{d}/text.so", "w").write("not an elf\n")
PY

# cargo shim + a PATH with the shim first.
mkdir -p "$T/shim"
printf '#!/bin/sh\necho "[shim cargo $*]"; exit 0\n' > "$T/shim/cargo"; chmod +x "$T/shim/cargo"

# A PATH with the tools run.sh needs but NO cargo.
mkdir -p "$T/nocargo"
for tool in bash sh mkdir dirname head od tr grep cp python3 cat rm env; do
  p="$(command -v "$tool" 2>/dev/null)" && ln -sf "$p" "$T/nocargo/$tool"
done

run() {  # run <crate> <PATH> [VAR=val ...] -> exit code; output in $T/out
  local crate="$1" path="$2"; shift 2
  ( cd "$crate" && env -i HOME="$HOME" PATH="$path" TMPDIR="${TMPDIR:-/tmp}" "$@" bash ./run.sh ) >"$T/out" 2>&1
  echo $?
}
SP="$T/shim:$PATH"

code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so")"
[ "$code" = 3 ] && grep -q 'both-or-neither' "$T/out" && ok "only one *_SO set -> exit 3 (both-or-neither)" || bad "only one *_SO set: exit $code"

code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/missing.so")"
[ "$code" = 3 ] && grep -q 'not found' "$T/out" && ok "missing .so path -> exit 3" || bad "missing path: exit $code"

code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/text.so")"
[ "$code" = 3 ] && grep -q 'not an ELF' "$T/out" && ok "non-ELF .so -> exit 3" || bad "non-ELF: exit $code"

code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/with-header.bin" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'not an ELF' "$T/out" && ok "ProgramData dump still carrying its 45-byte header -> exit 3" || bad "header-prefixed dump: exit $code"

code="$(run "$T/aud" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'get_account' "$T/out" && ok "audit-form tests (no live get_account) refused in prebuilt mode -> exit 3" || bad "audit-form tests: exit $code"

# exploit.rs fixed, fixed_blocked.rs only has the macro in a comment -> refused.
mk_crate "$T/half" incident
printf '    // assert_exploit_rejected_with!(outcome, ..., "g");\n    assert_exploit_rejected!(outcome, "any");\n' > "$T/half/tests/fixed_blocked.rs"
code="$(run "$T/half" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'assert_exploit_rejected_with' "$T/out" && ok "specific-error macro only in a comment -> exit 3" || bad "commented macro: exit $code"

code="$(run "$T/inc" "$T/nocargo" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'cargo not on PATH' "$T/out" && ok "no cargo on PATH -> exit 3" || bad "no cargo: exit $code"

code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
want="$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\x00")).hexdigest())' "$T/vuln.so")"
if [ "$code" = 0 ] && grep -q "vulnerable sha256 (zero-trimmed): $want" "$T/out"; then
  ok "prebuilt happy path (cargo shim) -> exit 0, zero-trimmed hash printed"
else
  bad "happy path: exit $code (want hash $want)"; cat "$T/out" >&2
fi

# The hash runs with the crate dir as its working directory. A hashlib.py planted
# there (and on PYTHONPATH) must not load; the control shows it would without -I.
mk_crate "$T/hostile" incident
MARK="$T/shadow.marker"
printf 'open(%s, "a").write("hashlib\\n")\n' "'$MARK'" > "$T/hostile/hashlib.py"
( cd "$T/hostile" && printf 'import hashlib\n' | python3 - >/dev/null 2>&1 )
[ -s "$MARK" ] && ok "isolation control: without -I, the crate dir's hashlib.py replaces the stdlib" || bad "isolation control: planted hashlib.py did not load, so the next check proves nothing"
rm -f "$MARK"
code="$(run "$T/hostile" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" PYTHONPATH="$T/hostile")"
if [ "$code" = 0 ] && grep -q "vulnerable sha256 (zero-trimmed): $want" "$T/out" && [ ! -e "$MARK" ]; then
  ok "hash under a planted hashlib.py (cwd + PYTHONPATH) is correct and the module never ran"
else
  bad "planted hashlib.py: exit $code, marker $( [ -e "$MARK" ] && echo present || echo absent )"; cat "$T/out" >&2
fi

if [ "$fails" -ne 0 ]; then
  echo "test-dnr-poc-runner: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr-poc-runner: all assertions passed"
