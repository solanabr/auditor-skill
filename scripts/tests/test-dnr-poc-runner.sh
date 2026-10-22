#!/usr/bin/env bash
# test-dnr-poc-runner.sh — self-test for templates/poc/run.sh: the execution mode every
# run needs (without AUDITOR_EXEC_MODE=isolated|native it exits 3 before anything is
# copied or compiled, whatever the crate holds), the incident (prebuilt) mode's
# VULNERABLE_SO / FIXED_SO preconditions, the zero-trimmed hash (computed with
# `python3 -I`, so a hashlib.py in the working directory never loads), where the crate
# builds (always a scratch copy outside the target tree with a pinned toolchain; a
# crate holding a symbolic link, .cargo/ or rust-toolchain* is refused; an inherited
# CARGO_TARGET_DIR is honoured), and the exit codes (a failed build is 3, a failed
# verdict 1/2).
#
# No Solana toolchain and no network needed: a temp copy of the template runs with a
# `cargo` shim or with a PATH that has no cargo at all; real cargo, when present, is
# used for one dependency-free build. bash >= 3.2; uses only standard POSIX tools +
# python3. Exits non-zero if any assertion fails.

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

# cargo shim + a PATH with the shim first. The shim logs the two lookups that make an
# in-tree build dangerous, the way cargo and rustup do them: a .cargo/config.toml in
# the working directory or any parent (the user's CARGO_HOME excepted), and a
# rust-toolchain.toml there when RUSTUP_TOOLCHAIN is not pinned. With SHIM_CALLS set it
# also logs every call, tab-separated: working directory, CARGO_TARGET_DIR,
# SBF_OUT_DIR, arguments. SHIM_FAIL makes one step fail with cargo's own exit code, 101.
mkdir -p "$T/shim"
cat > "$T/shim/cargo" <<'SH'
#!/bin/sh
if [ -n "${SHIM_CALLS:-}" ]; then
  printf '%s\t%s\t%s\t%s\n' "$PWD" "${CARGO_TARGET_DIR:-}" "${SBF_OUT_DIR:-}" "$*" >> "$SHIM_CALLS"
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
case "${SHIM_FAIL:-}" in
  build-sbf) if [ "${1:-}" = build-sbf ]; then echo "[shim cargo: build-sbf fails]"; exit 101; fi ;;
  no-run:*)
    case " $* " in *" --no-run "*)
      case " $* " in *" --test ${SHIM_FAIL#no-run:} "*) echo "[shim cargo: test build fails]"; exit 101 ;; esac ;;
    esac ;;
  exploit|fixed_blocked)
    case " $* " in *" --no-run "*) ;; *" --test $SHIM_FAIL "*) echo "[shim cargo: test fails]"; exit 101 ;; esac ;;
esac
echo "[shim cargo $*]"; exit 0
SH
chmod +x "$T/shim/cargo"
printf '#!/bin/sh\nexit 0\n' > "$T/shim/cargo-build-sbf"; chmod +x "$T/shim/cargo-build-sbf"

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
NATIVE=AUDITOR_EXEC_MODE=native   # the recorded mode most runs below pass

# gate: a shim run with the call log on and an empty TMPDIR of its own, so
# nothing_ran can tell that no cargo command started and no scratch directory appeared.
gate() {  # gate <crate> [VAR=val ...] -> exit code
  local crate="$1"; shift
  rm -rf "$T/calls" "$T/tmp-gate"; mkdir -p "$T/tmp-gate"
  run "$crate" "$SP" SHIM_CALLS="$T/calls" TMPDIR="$T/tmp-gate" "$@"
}
nothing_ran() { [ ! -e "$T/calls" ] && [ -z "$(ls -A "$T/tmp-gate")" ] && ! grep -q '^>> build dir' "$T/out"; }
build_dir() { sed -n 's/^>> build dir: \([^ ]*\).*/\1/p' "$T/out" | head -n 1; }
# from_scratch <dir>: <dir> is a scratch copy under the gate's TMPDIR, and every
# logged cargo call ran from it.
from_scratch() {
  case "$1" in "$T/tmp-gate"/auditor-poc.*) ;; *) return 1 ;; esac
  awk -F'\t' -v d="$1" '{ n++ } $1 == d { g++ } END { exit !(n > 0 && n == g) }' "$T/calls"
}

# ---------------------------------------------------------------------------
# The execution mode. Without AUDITOR_EXEC_MODE=isolated|native, run.sh exits 3
# before it copies or compiles anything — a dependency-free crate included.
# ---------------------------------------------------------------------------
code="$(gate "$T/inc" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'AUDITOR_EXEC_MODE' "$T/out" && grep -q 'Rule 11a' "$T/out" && grep -q 'Q46' "$T/out" && nothing_ran \
  && ok "no execution mode, dependency-free crate (prebuilt) -> exit 3 pointing to Rule 11a / Q46, no cargo call, no scratch dir" \
  || { bad "no execution mode, prebuilt: exit $code"; cat "$T/out" >&2; }
code="$(gate "$T/inc")"
[ "$code" = 3 ] && nothing_ran && ok "no execution mode, build mode -> exit 3 before any SBF build" || bad "no execution mode, build mode: exit $code"
code="$(gate "$T/inc" AUDITOR_EXEC_MODE= VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && nothing_ran && ok "an empty AUDITOR_EXEC_MODE -> exit 3" || bad "AUDITOR_EXEC_MODE empty: exit $code"
code="$(gate "$T/inc" AUDITOR_EXEC_MODE=yes VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q "AUDITOR_EXEC_MODE is 'yes'" "$T/out" && nothing_ran && ok "an unknown AUDITOR_EXEC_MODE value -> exit 3" || bad "AUDITOR_EXEC_MODE=yes: exit $code"
code="$(gate "$T/inc" AUDITOR_EXEC_MODE=isolated VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
bd="$(build_dir)"
[ "$code" = 0 ] && from_scratch "$bd" && grep -q '^>> build dir: .*AUDITOR_EXEC_MODE=isolated;' "$T/out" \
  && ok "AUDITOR_EXEC_MODE=isolated -> builds and tests the scratch copy, and says which mode ran" || bad "isolated: exit $code, build dir '$bd'"
code="$(gate "$T/inc" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
bd="$(build_dir)"
[ "$code" = 0 ] && from_scratch "$bd" && grep -q '^>> build dir: .*AUDITOR_EXEC_MODE=native;' "$T/out" \
  && ok "AUDITOR_EXEC_MODE=native -> builds and tests the scratch copy, and says which mode ran" || bad "native: exit $code, build dir '$bd'"

# ---------------------------------------------------------------------------
# Prebuilt (incident) mode preconditions, under the mode.
# ---------------------------------------------------------------------------
code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so")"
[ "$code" = 3 ] && grep -q 'both-or-neither' "$T/out" && ok "only one *_SO set -> exit 3 (both-or-neither)" || bad "only one *_SO set: exit $code"

code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/missing.so")"
[ "$code" = 3 ] && grep -q 'not found' "$T/out" && ok "missing .so path -> exit 3" || bad "missing path: exit $code"

code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/text.so")"
[ "$code" = 3 ] && grep -q 'not an ELF' "$T/out" && ok "non-ELF .so -> exit 3" || bad "non-ELF: exit $code"

code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/with-header.bin" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'not an ELF' "$T/out" && ok "ProgramData dump still carrying its 45-byte header -> exit 3" || bad "header-prefixed dump: exit $code"

code="$(run "$T/aud" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'get_account' "$T/out" && ok "audit-form tests (no live get_account) refused in prebuilt mode -> exit 3" || bad "audit-form tests: exit $code"

# exploit.rs fixed, fixed_blocked.rs only has the macro in a comment -> refused.
mk_crate "$T/half" incident
printf '    // assert_exploit_rejected_with!(outcome, ..., "g");\n    assert_exploit_rejected!(outcome, "any");\n' > "$T/half/tests/fixed_blocked.rs"
code="$(run "$T/half" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'assert_exploit_rejected_with' "$T/out" && ok "specific-error macro only in a comment -> exit 3" || bad "commented macro: exit $code"

# live() reads every line. Test files far past the pipe buffer, with the required
# call on every line, still count as live: an early-exit `grep -q` would lose the
# match to SIGPIPE under pipefail and refuse the crate.
mk_crate "$T/big" incident
python3 -I -c 'for _ in range(40000): print("    let post = outcome.get_account(&state_pk).expect(\"x\");")' > "$T/big/tests/exploit.rs"
python3 -I -c 'for _ in range(40000): print("    assert_exploit_rejected_with!(outcome, ProgramResult::Failure(e), \"g\");")' > "$T/big/tests/fixed_blocked.rs"
code="$(run "$T/big" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 0 ] && ok "40,000-line test files still count as live (no SIGPIPE refusal) -> exit 0" || { bad "large test files: exit $code"; grep blocker "$T/out" >&2; }

code="$(run "$T/inc" "$T/nocargo" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'cargo not on PATH' "$T/out" && ok "no cargo on PATH -> exit 3" || bad "no cargo: exit $code"

code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
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
code="$(run "$T/hostile" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" PYTHONPATH="$T/hostile")"
if [ "$code" = 0 ] && grep -q "vulnerable sha256 (zero-trimmed): $want" "$T/out" && [ ! -e "$MARK" ]; then
  ok "hash under a planted hashlib.py (cwd + PYTHONPATH) is correct and the module never ran"
else
  bad "planted hashlib.py: exit $code, marker $( [ -e "$MARK" ] && echo present || echo absent )"; cat "$T/out" >&2
fi

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
mk_crate "$R/incident_1/poc/INC-1.1" incident
( cd "$R/incident_1/poc/INC-1.1" && SHIM_LOG="$LOG" RUSTUP_TOOLCHAIN= "$T/shim/cargo" test >/dev/null )
if grep -q '^config ' "$LOG" && grep -q '^toolchain ' "$LOG"; then ok "control: in place, cargo would read the target's .cargo/config.toml and rust-toolchain.toml"; else bad "control: the shim did not see the hostile tree"; fi
rm -f "$LOG"
code="$(run "$R/incident_1/poc/INC-1.1" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_LOG="$LOG")"
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
fi
rm -f "$LOG"
code="$(run "$R/incident_1/poc/INC-1.1" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" KEEP_POC_BUILD=1)"
bd="$(build_dir)"
if [ "$code" = 0 ] && [ -d "$bd" ]; then ok "KEEP_POC_BUILD=1 keeps the scratch build dir"; rm -rf "$bd"; else bad "KEEP_POC_BUILD=1: exit $code, dir '$bd'"; fi
mkdir -p "$R/tmp"
code="$(run "$R/incident_1/poc/INC-1.1" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" TMPDIR="$R/tmp")"
[ "$code" = 3 ] && grep -q 'would inherit' "$T/out" && ok "a scratch dir that would inherit the target's config (TMPDIR inside the tree) -> exit 3" || bad "TMPDIR inside the target tree: exit $code"

# Relative .so paths still resolve once the build moves to the scratch copy.
code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO=../vuln.so FIXED_SO=../fixed.so)"
[ "$code" = 0 ] && grep -q "vulnerable sha256 (zero-trimmed): $want" "$T/out" && ok "relative VULNERABLE_SO/FIXED_SO resolve from the caller's directory" || bad "relative .so paths: exit $code"

# Crate shapes that reach for target code — a path dependency (one of them inside the
# hostile tree), a git dependency, a workspace-inherited one — and the shipped
# template itself. Each needs the mode; with it, each is built and tested from a
# scratch copy, never in place, so the target's config stays out of reach.
mk_dep() {  # mk_dep <dir> <Cargo.toml dependency line>
  mk_crate "$1" incident
  printf '[package]\nname = "p"\nversion = "0.1.0"\n\n[dependencies]\n%s\n' "$2" > "$1/Cargo.toml"
}
mk_dep "$T/d-path" 'vault = { path = "../../../programs/vault" }'
mk_dep "$T/d-git" 'vault = { git = "https://example.invalid/vault.git" }'
mk_dep "$T/d-ws" 'anchor-lang = { workspace = true }'
mk_dep "$R/incident_1/poc/INC-1.3" "vault = { path = \"$R/programs/vault\" }"
mkdir -p "$T/tmpl"; cp -R "$TEMPLATE/." "$T/tmpl/"
sed 's/{PROGRAM_NAME}/poc_tmpl/' "$TEMPLATE/Cargo.toml" > "$T/tmpl/Cargo.toml"
mk_crate "$T/tmpl" incident
for c in "$T/d-path" "$T/d-git" "$T/d-ws" "$T/tmpl" "$R/incident_1/poc/INC-1.3"; do
  label="${c#"$T"/}"
  code="$(gate "$c" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
  [ "$code" = 3 ] && nothing_ran && ok "$label, no execution mode -> exit 3, nothing copied or compiled" || bad "$label without a mode: exit $code"
  rm -f "$LOG"
  code="$(gate "$c" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_LOG="$LOG")"
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
  code="$(gate "$1" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
  [ "$code" = 3 ] && grep -qF "$2 inside the crate" "$T/out" && nothing_ran \
    && ok "$3 -> refused under native: exit 3, nothing copied or compiled" || bad "$3: exit $code"
}
mk_crate "$T/d-link" incident; ln -s "$R" "$T/d-link/target-src"
refused "$T/d-link" target-src "a symbolic link inside the crate"
mk_crate "$T/d-cargo" incident; mkdir -p "$T/d-cargo/.cargo"
printf '[build]\nrustc-wrapper = "%s"\n' "$T/wrap.sh" > "$T/d-cargo/.cargo/config.toml"
refused "$T/d-cargo" .cargo "a .cargo/ directory inside the crate"
mk_crate "$T/d-tc" incident
printf '[toolchain]\npath = "%s"\n' "$T/faketc" > "$T/d-tc/rust-toolchain.toml"
refused "$T/d-tc" rust-toolchain.toml "a rust-toolchain.toml inside the crate"

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

# Exit codes: a build that fails is a blocker (3); only the test verdicts are 1 and 2.
code="$(run "$T/inc" "$SP" "$NATIVE" SHIM_FAIL=build-sbf)"
[ "$code" = 3 ] && grep -q 'SBF build failed' "$T/out" && ok "cargo build-sbf failing (101) -> exit 3" || bad "build-sbf failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_FAIL=no-run:exploit)"
[ "$code" = 3 ] && grep -q 'tests/exploit.rs failed to build for the vulnerable arm' "$T/out" && ok "an exploit test that does not compile -> exit 3" || bad "exploit test build failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_FAIL=no-run:fixed_blocked)"
[ "$code" = 3 ] && grep -q 'tests/fixed_blocked.rs failed to build for the fixed arm' "$T/out" && ok "a fixed-arm test that does not compile -> exit 3" || bad "fixed test build failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_FAIL=exploit)"
[ "$code" = 1 ] && ok "exploit test failing -> exit 1" || bad "exploit failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_FAIL=fixed_blocked)"
[ "$code" = 2 ] && ok "fixed-arm test failing -> exit 2" || bad "fixed-arm failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE")"
[ "$code" = 0 ] && grep -q "building 'fixed' arm to SBF" "$T/out" && ok "build mode (no prebuilt bytes) runs both arms -> exit 0" || bad "build mode: exit $code"

# Real cargo and rustup, when present: the same hostile tree, a crate that really
# compiles (no dependencies, so no network), prebuilt bytes so no SBF toolchain.
if command -v cargo >/dev/null 2>&1 && command -v rustup >/dev/null 2>&1; then
  RC="$R/incident_1/poc/INC-1.2"; mk_crate "$RC" incident; mkdir -p "$RC/src"
  printf '[package]\nname = "dnr_runner_real"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n\n[workspace]\n\n[features]\ndefault = []\nvulnerable = []\nfixed = []\n' > "$RC/Cargo.toml"
  : > "$RC/src/lib.rs"
  printf 'struct Outcome;\nimpl Outcome { fn get_account(&self, _pk: &u8) -> Option<u8> { Some(1) } }\n#[test]\nfn exploit() {\n    let outcome = Outcome;\n    let state_pk = 0u8;\n    assert_eq!(outcome.get_account(&state_pk), Some(1));\n}\n' > "$RC/tests/exploit.rs"
  printf 'macro_rules! assert_exploit_rejected_with { ($o:expr, $p:pat, $w:expr) => { let _ = &$o; let _ = $w; }; }\n#[test]\nfn fixed_blocked() {\n    let outcome = 0u8;\n    assert_exploit_rejected_with!(outcome, _, "guard");\n}\n' > "$RC/tests/fixed_blocked.rs"
  tc="$(rustup default 2>/dev/null | sed -n 's/ (default)$//p')"
  rm -f "$MK"
  ( cd "$RC" && RUSTUP_TOOLCHAIN="$tc" CARGO_TARGET_DIR="$T/ctl-target" cargo build -q --offline >/dev/null 2>&1 ) || true
  if grep -q wrapper "$MK" 2>/dev/null; then ok "control (real cargo): in place, the target's rustc-wrapper runs"; else bad "control (real cargo): the rustc-wrapper did not run in place, so the next check proves nothing"; fi
  rm -f "$MK"
  ( cd "$RC" && env -u RUSTUP_TOOLCHAIN cargo --version >/dev/null 2>&1 ) || true
  if grep -q toolchain "$MK" 2>/dev/null; then ok "control (real rustup): in place, the target's path toolchain runs"; else echo "note: this rustup does not honour a path toolchain in rust-toolchain.toml; that control is skipped"; fi
  rm -f "$MK" "$RC/Cargo.lock"
  code="$(run "$RC" "$PATH" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
  if [ "$code" = 3 ] && [ ! -e "$MK" ] && [ ! -e "$RC/Cargo.lock" ]; then
    ok "real cargo, no execution mode: exit 3 and nothing compiled (no Cargo.lock, no wrapper or toolchain run)"
  else
    bad "real cargo, no execution mode: exit $code, marker: $(tr '\n' ' ' < "$MK" 2>/dev/null)"
  fi
  code="$(run "$RC" "$PATH" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
  if [ "$code" = 0 ] && [ ! -e "$MK" ]; then
    ok "real cargo: tests pass from the scratch copy and neither the wrapper nor the path toolchain ran"
  else
    bad "real cargo: exit $code, marker: $(tr '\n' ' ' < "$MK" 2>/dev/null)"; cat "$T/out" >&2
  fi
  [ -f "$RC/Cargo.lock" ] && ok "real cargo: the resolved Cargo.lock is kept with the crate" || bad "real cargo: Cargo.lock not copied back"
  code="$(run "$RC" "$PATH" "$NATIVE" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" CARGO_TARGET_DIR="$T/real-cache")"
  if [ "$code" = 0 ] && [ -d "$T/real-cache/debug" ] && [ ! -e "$MK" ]; then
    ok "real cargo: an inherited CARGO_TARGET_DIR holds the build"
  else
    bad "real cargo, CARGO_TARGET_DIR: exit $code"; cat "$T/out" >&2
  fi
else
  echo "note: cargo or rustup not on PATH; the real-toolchain checks are skipped (the shim checks above still ran)"
fi

if [ "$fails" -ne 0 ]; then
  echo "test-dnr-poc-runner: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr-poc-runner: all assertions passed"
