#!/usr/bin/env bash
# test-dnr-poc-runner.sh — self-test for templates/poc/run.sh and the PoC contract
# assertions in templates/poc/shared-test-utils:
#   * the execution mode every run needs (without AUDITOR_EXEC_MODE=isolated|native it
#     exits 3 before anything is copied or compiled, whatever the crate holds);
#   * prebuilt bytes: VULNERABLE_SO alone runs the exploit arm, FIXED_SO adds the
#     fixed arm and needs VULNERABLE_SO; an arm counts only on the marker its contract
#     assertion leaves when it runs and holds; a fixed arm that fails on a harness
#     error is inconclusive (exit 3); success prints the Leg 3 line with the
#     zero-trimmed hashes (computed with `python3 -I`, so a hashlib.py in the working
#     directory never loads);
#   * verdicts: a failed test is exit 1 / 2 only when a contract assertion ran and did
#     not hold; one that failed before any assertion ran (the program did not load,
#     the setup panicked) or after every assertion held is inconclusive (exit 3);
#   * where the crate builds (always a scratch copy outside the target tree with a
#     pinned toolchain; a crate holding a symbolic link, .cargo/, rust-toolchain* or
#     tests/fixtures/<crate>.so is refused; BPF_OUT_DIR is cleared; an inherited
#     CARGO_TARGET_DIR is honoured), and the exit codes (a failed build is 3, a failed
#     verdict 1/2).
#
# No Solana toolchain and no network needed. A temp copy of run.sh runs with a `cargo`
# shim, or with a PATH that has no cargo at all. When real cargo and rustup are
# present, the template's own tests/exploit.rs and tests/fixed_blocked.rs and its
# shared-test-utils are built and run through run.sh against small stand-in crates
# (mollusk-svm, solana-sdk, borsh, ...) whose program behaviour is the text after the
# ELF magic in the prebuilt .so: path dependencies only, offline. bash >= 3.2; uses
# only standard POSIX tools + python3. Exits non-zero if any assertion fails.

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

mk_crate() {  # mk_crate <dir>: run.sh and the template's tests (the shim never reads them)
  mkdir -p "$1/tests"
  cp "$TEMPLATE/run.sh" "$1/run.sh"
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
             "dirty-reject", "unloadable"]:
    stem = name.replace(":", "-").replace("(", "").replace(")", "")
    open(f"{d}/sb-{stem}.so", "wb").write(b"\x7fELF" + name.encode() + b"\x00" * 64)
PY

# cargo shim + a PATH with the shim first. The shim logs the two lookups that make an
# in-tree build dangerous, the way cargo and rustup do them: a .cargo/config.toml in
# the working directory or any parent (the user's CARGO_HOME excepted), and a
# rust-toolchain.toml there when RUSTUP_TOOLCHAIN is not pinned. With SHIM_CALLS set it
# also logs every call, tab-separated: working directory, CARGO_TARGET_DIR,
# SBF_OUT_DIR, BPF_OUT_DIR, AUDITOR_POC_MARKERS, arguments. A test run (not --no-run)
# leaves the markers SHIM_MARKERS names for its test (<test>:<kind>), as
# shared-test-utils does: by default those of a PoC whose assertions all ran and
# held, and none for SHIM_MARKERS=none. SHIM_FAIL makes one step fail with cargo's
# own exit code, 101.
mkdir -p "$T/shim"
cat > "$T/shim/cargo" <<'SH'
#!/bin/sh
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
case " $* " in
  *" --no-run "*) ;;
  *" --test "*)
    t="$*"; t="${t##*--test }"; t="${t%% *}"
    for m in ${SHIM_MARKERS-exploit:attempted exploit:held exploit:effect fixed_blocked:attempted fixed_blocked:held fixed_blocked:rejected_with}; do
      if [ "${m%%:*}" = "$t" ] && [ -n "${AUDITOR_POC_MARKERS:-}" ]; then
        echo "shim ${m#*:}" >> "$AUDITOR_POC_MARKERS/${m#*:}"
      fi
    done ;;
esac
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
zhash() { python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\x00")).hexdigest())' "$1"; }
LEG3='OK: reproduced on prebuilt bytes — vulnerable sha256='
# Shim marker sets for one test whose contract assertion ran and held: the
# exploit's effect, the fixed arm's pinned error, a deployed fix's block.
EV="exploit:attempted exploit:held exploit:effect"
FR="fixed_blocked:attempted fixed_blocked:held fixed_blocked:rejected_with"
FB="fixed_blocked:attempted fixed_blocked:held fixed_blocked:blocked"

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

want="$(zhash "$T/vuln.so")"; wantf="$(zhash "$T/fixed.so")"
code="$(gate "$T/inc" "$NATIVE" "$VULN")"
if [ "$code" = 0 ] && grep -qx "${LEG3}${want} → \[PoC-REPRODUCED\]" "$T/out" && ! grep -q 'running same attack' "$T/out" \
   && awk -F'\t' '$6 ~ /--test fixed_blocked/ { f = 1 } END { exit f }' "$T/calls"; then
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
# Each arm's test runs with its own marker directory; the build steps get none.
if awk -F'\t' '$6 ~ /--test exploit -- / && $5 !~ /\/markers\/vulnerable$/ { bad = 1 } $6 ~ /--test fixed_blocked -- / && $5 !~ /\/markers\/fixed$/ { bad = 1 } $6 ~ /--no-run/ && $5 != "" { bad = 1 } END { exit bad }' "$T/calls" \
   && [ "$(awk -F'\t' '$6 ~ /--test (exploit|fixed_blocked) -- /' "$T/calls" | wc -l | tr -d ' ')" = 2 ]; then
  ok "each arm's test gets AUDITOR_POC_MARKERS=<scratch>/markers/<arm>; the build steps get none"
else
  bad "marker directories"; cat "$T/calls" >&2
fi

code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_MARKERS=none)"
[ "$code" = 3 ] && grep -q 'no assert_exploit_effect! ran and held' "$T/out" && ! grep -q 'running same attack' "$T/out" \
  && ok "exploit test passes but leaves no effect marker -> exit 3 before the fixed arm" || bad "no effect marker: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_MARKERS="$EV")"
[ "$code" = 3 ] && grep -q 'neither assert_exploit_rejected_with! nor assert_exploit_blocked! ran and held' "$T/out" \
  && ok "fixed test passes but leaves no rejection marker -> exit 3" || bad "no fixed marker: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_MARKERS="$EV $FB")"
[ "$code" = 0 ] && grep -qx "${LEG3}${want} fixed sha256=${wantf} (blocked: failed, account unchanged) → \[PoC-REPRODUCED\]" "$T/out" \
  && ok "a blocked marker (a deployed fix) -> exit 0, and the line says blocked, not pinned" || bad "blocked marker: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:attempted fixed_blocked:inconclusive")"
[ "$code" = 3 ] && grep -q 'the fixed arm is inconclusive: shim inconclusive' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
  && ok "a fixed arm whose assertion could not decide (an inconclusive marker) -> exit 3, not 2" || bad "inconclusive: exit $code"
code="$(gate "$T/inc" "$NATIVE" SHIM_MARKERS=none)"
[ "$code" = 0 ] && grep -q "(this crate's own arms: a model, never Leg 3)" "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "build mode needs no marker and prints the model line, never the Leg 3 line" || bad "build mode without markers: exit $code"

# A failed test is a verdict (exit 1 / 2) only when a contract assertion ran and did
# not hold. One that failed before any assertion ran (the program did not load, the
# setup panicked), or after every assertion held, is inconclusive: exit 3.
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV")"
[ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
  && ok "a fixed-arm test that fails before any contract assertion ran -> exit 3 (inconclusive), not 2" || bad "fixed arm, no assertion ran: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_FAIL=exploit SHIM_MARKERS=none)"
[ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
  && ok "an exploit test that fails before any contract assertion ran -> exit 3, not 1" || bad "exploit, no assertion ran: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV $FR")"
[ "$code" = 3 ] && grep -q 'every contract assertion that ran held' "$T/out" \
  && ok "a fixed-arm test that fails after its contract assertion held -> exit 3, not 2" || bad "fixed arm fails after it held: exit $code"
code="$(gate "$T/inc" "$NATIVE" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV")"
[ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" \
  && ok "build mode too: a fixed-arm failure with no contract assertion run -> exit 3" || bad "build mode, no assertion ran: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_MARKERS="$EV exploit:attempted")"
[ "$code" = 3 ] && grep -q 'ran and did not hold, yet the test passed' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "prebuilt bytes: a passing test with a contract assertion that did not hold -> exit 3" || bad "pass with an unheld assertion: exit $code"
code="$(gate "$T/inc" "$NATIVE" "$VULN" SHIM_MARKERS="$EV exploit:inconclusive")"
[ "$code" = 3 ] && grep -q 'the vulnerable arm is inconclusive: shim inconclusive' "$T/out" && ! grep -q "^$LEG3" "$T/out" \
  && ok "a passing test that left an inconclusive marker -> exit 3" || bad "pass with an inconclusive marker: exit $code"

code="$(gate "$T/inc" "$NATIVE" "$VULN" BPF_OUT_DIR="$T")"
[ "$code" = 0 ] && awk -F'\t' '$4 != "" { bad = 1 } END { exit bad }' "$T/calls" && ok "a caller's BPF_OUT_DIR never reaches cargo (mollusk would look there before SBF_OUT_DIR)" || bad "BPF_OUT_DIR: exit $code"
mk_crate "$T/fixture"; mkdir -p "$T/fixture/tests/fixtures"; cp "$T/vuln.so" "$T/fixture/tests/fixtures/{PROGRAM_NAME}.so"
code="$(gate "$T/fixture" "$NATIVE" "$VULN")"
[ "$code" = 3 ] && grep -q 'tests/fixtures/{PROGRAM_NAME}.so would load in place of the arm' "$T/out" && nothing_ran \
  && ok "tests/fixtures/<crate>.so in the crate -> refused before anything is built" || bad "tests/fixtures shadow: exit $code"

# The hash runs with the crate dir as its working directory. A hashlib.py planted
# there (and on PYTHONPATH) must not load; the control shows it would without -I.
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
code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=no-run:exploit)"
[ "$code" = 3 ] && grep -q 'tests/exploit.rs failed to build for the vulnerable arm' "$T/out" && ok "an exploit test that does not compile -> exit 3" || bad "exploit test build failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=no-run:fixed_blocked)"
[ "$code" = 3 ] && grep -q 'tests/fixed_blocked.rs failed to build for the fixed arm' "$T/out" && ok "a fixed-arm test that does not compile -> exit 3" || bad "fixed test build failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=exploit SHIM_MARKERS=exploit:attempted)"
[ "$code" = 1 ] && grep -q 'did not reproduce' "$T/out" && ok "exploit test failing in its contract assertion -> exit 1" || bad "exploit failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" "$VULN" "$FIX" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:attempted")"
[ "$code" = 2 ] && grep -q 'fix is incomplete' "$T/out" && ok "fixed-arm test failing in its contract assertion -> exit 2" || bad "fixed-arm failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE" SHIM_FAIL=fixed_blocked SHIM_MARKERS="$EV fixed_blocked:attempted")"
[ "$code" = 2 ] && grep -q 'fix is incomplete' "$T/out" && ok "build mode: fixed-arm test failing in its contract assertion -> exit 2" || bad "build mode fixed-arm failure: exit $code"
code="$(run "$T/inc" "$SP" "$NATIVE")"
[ "$code" = 0 ] && grep -q "building 'fixed' arm to SBF" "$T/out" && ok "build mode (no prebuilt bytes) runs both arms -> exit 0" || bad "build mode: exit $code"

# ---------------------------------------------------------------------------
# Real cargo and rustup, when present: the template's own tests and shared-test-utils,
# built and run through run.sh against stand-in crates. The stand-in mollusk finds
# <crate>.so the way mollusk does (tests/fixtures, BPF_OUT_DIR, SBF_OUT_DIR, the
# working directory) and acts out the text after the ELF magic: "takeover" writes the
# first signer's key into the first writable account's bytes 0..32, "noop" accepts and
# changes nothing, "reject:<error>" fails with that error, "unloadable" makes the
# loader panic.
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
    pub enum InstructionError { MissingAccount, UnsupportedProgramId, ComputationalBudgetExceeded }
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
use result::{InstructionResult, ProgramResult};
use solana_account::Account;
use solana_instruction::Instruction;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
pub struct Mollusk { behaviour: String }
impl Mollusk {
    pub fn new(_program_id: &Pubkey, so_name: &str) -> Self {
        let file = format!("{so_name}.so");
        let mut dirs = vec![std::path::PathBuf::from("tests/fixtures")];
        for var in ["BPF_OUT_DIR", "SBF_OUT_DIR"] {
            if let Ok(dir) = std::env::var(var) { dirs.push(dir.into()); }
        }
        if let Ok(dir) = std::env::current_dir() { dirs.push(dir); }
        let path = dirs.iter().map(|d| d.join(&file)).find(|p| p.exists())
            .unwrap_or_else(|| panic!("stand-in mollusk: {file} not found"));
        let bytes = std::fs::read(&path).expect("read the program");
        let tag: Vec<u8> = bytes[4..].iter().copied().take_while(|b| *b != 0).collect();
        let behaviour = String::from_utf8(tag).expect("utf-8 behaviour");
        // As mollusk's loader panics on bytes it cannot load.
        assert!(behaviour != "unloadable", "stand-in mollusk: the loader rejects these bytes");
        Mollusk { behaviour }
    }
    pub fn process_instruction(&self, ix: &Instruction, accounts: &[(Pubkey, Account)]) -> InstructionResult {
        let mut out = accounts.to_vec();
        let take_over = |out: &mut Vec<(Pubkey, Account)>| {
            let signer = ix.accounts.iter().find(|m| m.is_signer).expect("a signer").pubkey;
            let target = ix.accounts.iter().find(|m| m.is_writable).expect("a writable account").pubkey;
            let acct = out.iter_mut().find(|(k, _)| *k == target).map(|(_, a)| a).expect("the target account");
            acct.data[0..32].copy_from_slice(signer.as_ref());
        };
        let program_result = match self.behaviour.as_str() {
            "takeover" => {
                take_over(&mut out);
                ProgramResult::Success
            }
            // Fails, yet leaves the change in place, as a runtime that did not roll back would.
            "dirty-reject" => {
                take_over(&mut out);
                return InstructionResult { program_result: ProgramResult::Failure(ProgramError::Custom(6001)), resulting_accounts: out };
            }
            "noop" => ProgramResult::Success,
            "reject:MissingRequiredSignature" => ProgramResult::Failure(ProgramError::MissingRequiredSignature),
            other => match other.strip_prefix("reject:Custom(").and_then(|s| s.strip_suffix(')')) {
                Some(code) => ProgramResult::Failure(ProgramError::Custom(code.parse().expect("a code"))),
                None => panic!("stand-in mollusk: unknown behaviour {other:?}"),
            },
        };
        if program_result.is_err() { out = accounts.to_vec(); }
        InstructionResult { program_result, resulting_accounts: out }
    }
}
RS
}

# mk_e2e <dir>: a PoC crate made of the template's tests, shared-test-utils and run.sh,
# with stand-in dependencies by absolute path (the crate builds from a scratch copy).
mk_e2e() {
  local P="$1" S="$T/si"
  mkdir -p "$P/src" "$P/tests" "$P/shared-test-utils/src"
  sed 's/^CRATE="{PROGRAM_NAME}"/CRATE="poc_e2e"/' "$TEMPLATE/run.sh" > "$P/run.sh"
  for f in exploit fixed_blocked; do sed 's/{PROGRAM_NAME}/poc_e2e/g' "$TEMPLATE/tests/$f.rs" > "$P/tests/$f.rs"; done
  cp "$TEMPLATE/shared-test-utils/src/lib.rs" "$P/shared-test-utils/src/lib.rs"
  printf '[package]\nname = "poc_e2e"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n\n[workspace]\n\n[features]\ndefault = ["fixed"]\nvulnerable = []\nfixed = []\n\n[dependencies]\nborsh = { path = "%s/borsh" }\nsolana-pubkey = { path = "%s/pubkey" }\n\n[dev-dependencies]\nmollusk-svm = { path = "%s/mollusk" }\nsolana-sdk = { path = "%s/sdk" }\nshared-test-utils = { path = "shared-test-utils" }\n' "$S" "$S" "$S" "$S" > "$P/Cargo.toml"
  printf '[package]\nname = "shared-test-utils"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n\n[dependencies]\nmollusk-svm = { path = "%s/mollusk" }\nsolana-account = { path = "%s/account" }\nsolana-pubkey = { path = "%s/pubkey" }\nsolana-rent = { path = "%s/rent" }\nsolana-system-interface = { path = "%s/sysif" }\n' "$S" "$S" "$S" "$S" "$S" > "$P/shared-test-utils/Cargo.toml"
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
  # The first run into the shared target dir: it must hold the build afterwards.
  code="$(e2e "$RC" VULNERABLE_SO="$SB-takeover.so")"
  if [ "$code" = 0 ] && grep -qx "${LEG3}$(zhash "$SB-takeover.so") → \[PoC-REPRODUCED\]" "$T/out" && ! grep -q 'running same attack' "$T/out" && [ -d "$T/e2e-target/debug" ]; then
    ok "real cargo: VULNERABLE_SO alone reaches the Leg 3 line, built into an inherited CARGO_TARGET_DIR"
  else
    bad "real cargo, VULNERABLE_SO alone: exit $code"; cat "$T/out" >&2
  fi

  # Results the contract must turn down, outside the hostile tree.
  mk_e2e "$T/e-base"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-noop.so")"
  [ "$code" = 1 ] && grep -q 'after the attack .* reads' "$T/out" && ok "real cargo: bytes that accept the call but change nothing -> exit 1 (Ok is not the effect)" || bad "real cargo, noop bytes: exit $code"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-dirty-reject.so")"
  [ "$code" = 1 ] && grep -q 'expected to SUCCEED and change' "$T/out" && ok "real cargo: an exploit that fails, even with the account changed, -> exit 1 (the effect needs success)" || bad "real cargo, failed exploit with a change: exit $code"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-takeover.so")"
  [ "$code" = 2 ] && ok "real cargo: fixed bytes that let the attack through -> exit 2" || bad "real cargo, fix lets it through: exit $code"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom6001.so")"
  [ "$code" = 2 ] && grep -q 'REJECTED with Failure(MissingRequiredSignature)' "$T/out" && ok "real cargo: a rejection with another error than the pinned one -> exit 2" || bad "real cargo, other error: exit $code"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom4100.so")"
  [ "$code" = 3 ] && grep -q 'inconclusive: a harness error, not a guard: Failure(Custom(4100))' "$T/out" && ok "real cargo: Custom(4100) (wrong program id) on the fixed arm -> inconclusive, exit 3" || bad "real cargo, 4100: exit $code"
  mkdir -p "$T/bpf"; cp "$SB-takeover.so" "$T/bpf/poc_e2e.so"
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-noop.so" BPF_OUT_DIR="$T/bpf")"
  [ "$code" = 1 ] && ok "real cargo: a caller's BPF_OUT_DIR holding other bytes is not what runs (exit 1 on the no-op bytes)" || bad "real cargo, BPF_OUT_DIR: exit $code"

  # Assertions that do not run or do not pin anything leave no marker.
  mk_e2e "$T/e-dead"
  drop_block "$T/e-dead/tests/exploit.rs" '^    assert_exploit_effect!\($'
  swap "$T/e-dead/tests/exploit.rs" '/^    let _ = SYSTEM_PROGRAM_ID;/ {
    print "    // assert_exploit_effect!(outcome, before: &accounts, ...)"
    print "    let _ = \"assert_exploit_effect!(outcome)\";"
    print "    let _ = outcome.get_account(&state_pk);"
    print "    if accounts.is_empty() {"
    print "        assert_exploit_effect!(outcome, before: &accounts, account: state_pk,"
    print "            read: |a| a.data[0..32].to_vec(), expect: attacker.to_bytes().to_vec(), why: \"never runs\");"
    print "    }"
    print "    shared_test_utils::assert_exploit_succeeds!(outcome, \"Ok only\");"
  } { print }'
  code="$(e2e "$T/e-dead" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'no assert_exploit_effect! ran and held' "$T/out" \
    && ok "real cargo: the effect assertion only in a comment, a string and dead code, plus an empty get_account -> exit 3" || { bad "real cargo, dead effect assertion: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-any"
  drop_block "$T/e-any/tests/fixed_blocked.rs" '^    assert_exploit_rejected_with!\($'
  swap "$T/e-any/tests/fixed_blocked.rs" '/^    \/\/ A hotfix the team already deployed/ { print "    shared_test_utils::assert_exploit_rejected!(outcome, \"any error\");" } { print }'
  code="$(e2e "$T/e-any" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'neither assert_exploit_rejected_with! nor assert_exploit_blocked! ran and held' "$T/out" \
    && ok "real cargo: the any-error assertion on the fixed arm -> exit 3" || { bad "real cargo, any-error fixed arm: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-same"
  swap "$T/e-same/tests/exploit.rs" '/^        expect: attacker.to_bytes\(\).to_vec\(\),$/ { print "        expect: legit_authority.to_bytes().to_vec(),"; next } { print }'
  code="$(e2e "$T/e-same" VULNERABLE_SO="$SB-noop.so")"
  [ "$code" = 1 ] && grep -q 'before the attack, so this shows no effect' "$T/out" \
    && ok "real cargo: an expected value the account already held -> exit 1 (no effect shown)" || { bad "real cargo, unchanged expectation: exit $code"; cat "$T/out" >&2; }
  for pat in '_' 'ProgramError::Custom(_)'; do
    mk_e2e "$T/e-pat"
    swap "$T/e-pat/tests/fixed_blocked.rs" '/^        ProgramError::MissingRequiredSignature,$/ { print "        '"$pat"',"; next } { print }'
    code="$(e2e "$T/e-pat" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
    [ "$code" = 3 ] && grep -q 'tests/fixed_blocked.rs failed to build' "$T/out" \
      && ok "real cargo: a pattern ($pat) as the expected error does not compile -> exit 3" || { bad "real cargo, pattern $pat: exit $code"; cat "$T/out" >&2; }
    rm -rf "$T/e-pat"
  done

  # A program that does not load, or a test that fails before its contract assertion
  # ran, decides nothing: exit 3, never 1 or 2.
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-unloadable.so")"
  [ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
    && ok "real cargo: fixed bytes the loader rejects -> inconclusive, exit 3, not 2" || { bad "real cargo, unloadable fixed bytes: exit $code"; cat "$T/out" >&2; }
  code="$(e2e "$T/e-base" VULNERABLE_SO="$SB-unloadable.so")"
  [ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" && ! grep -q 'did not reproduce' "$T/out" \
    && ok "real cargo: vulnerable bytes the loader rejects -> inconclusive, exit 3, not 1" || { bad "real cargo, unloadable vulnerable bytes: exit $code"; cat "$T/out" >&2; }
  mk_e2e "$T/e-panic"
  subst "$T/e-panic/tests/fixed_blocked.rs" '    let outcome = mollusk.process_instruction(&ix, &accounts);' '    panic!("the setup failed");
    let outcome = mollusk.process_instruction(&ix, &accounts);'
  code="$(e2e "$T/e-panic" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-MissingRequiredSignature.so")"
  [ "$code" = 3 ] && grep -q 'inconclusive: no contract assertion ran' "$T/out" && ! grep -q 'fix is incomplete' "$T/out" \
    && ok "real cargo: a fixed-arm test that panics before its contract assertion -> exit 3, not 2" || { bad "real cargo, panic before the assertion: exit $code"; cat "$T/out" >&2; }

  # The deployed-hotfix check: the template's commented replacement, swapped in as written.
  mk_e2e "$T/e-hotfix"
  drop_block "$T/e-hotfix/tests/fixed_blocked.rs" '^    assert_exploit_rejected_with!\($'
  swap "$T/e-hotfix/tests/fixed_blocked.rs" '/^    \/\/   shared_test_utils::assert_exploit_blocked!\($/ { on = 1 } on { line = $0; sub(/^    \/\/   /, "    ", line); print line; if ($0 ~ /^    \/\/   \);$/) on = 0; next } { print }'
  if grep -q '^    shared_test_utils::assert_exploit_blocked!($' "$T/e-hotfix/tests/fixed_blocked.rs" && ! grep -q '^    assert_exploit_rejected_with!' "$T/e-hotfix/tests/fixed_blocked.rs"; then
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom6001.so")"
    [ "$code" = 0 ] && grep -qx "${LEG3}$(zhash "$SB-takeover.so") fixed sha256=$(zhash "$SB-reject-Custom6001.so") (blocked: failed, account unchanged) → \[PoC-REPRODUCED\]" "$T/out" \
      && ok "real cargo: the template's hotfix replacement compiles, and a hotfix with its own error (Custom(6001)) counts as blocked" || { bad "real cargo, hotfix Custom(6001): exit $code"; cat "$T/out" >&2; }
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-takeover.so")"
    [ "$code" = 2 ] && ok "real cargo: a hotfix that lets the attack through -> exit 2" || bad "real cargo, hotfix lets it through: exit $code"
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-dirty-reject.so")"
    [ "$code" = 2 ] && grep -q 'yet .* changed' "$T/out" && ok "real cargo: a hotfix run that fails but still changes the account is not blocked -> exit 2" || bad "real cargo, hotfix fails with a change: exit $code"
    code="$(e2e "$T/e-hotfix" VULNERABLE_SO="$SB-takeover.so" FIXED_SO="$SB-reject-Custom4100.so")"
    [ "$code" = 3 ] && grep -q 'inconclusive: a harness error, not a guard' "$T/out" && ok "real cargo: a hotfix check that fails on Custom(4100) -> inconclusive, exit 3" || bad "real cargo, hotfix 4100: exit $code"
  else
    bad "real cargo: could not swap in the template's commented assert_exploit_blocked! replacement"
  fi
else
  echo "note: cargo or rustup not on PATH; the real-toolchain checks are skipped (the shim checks above still ran)"
fi

if [ "$fails" -ne 0 ]; then
  echo "test-dnr-poc-runner: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr-poc-runner: all assertions passed"
