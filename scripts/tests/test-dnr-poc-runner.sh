#!/usr/bin/env bash
# test-dnr-poc-runner.sh — self-test for templates/poc/run.sh: the incident (prebuilt)
# mode's VULNERABLE_SO / FIXED_SO preconditions, the zero-trimmed hash (computed with
# `python3 -I`, so a hashlib.py in the working directory never loads), and where the
# crate builds: a self-contained crate in a scratch copy outside the target tree with
# a pinned toolchain, a target-dependent one only under AUDITOR_EXEC_MODE; the
# dependency allowlist; and the exit codes (a failed build is 3, a failed verdict 1/2).
#
# No Solana toolchain and no network needed: a temp copy of the template runs with a
# `cargo` shim or with a PATH that has no cargo at all; real cargo, when present, is
# used for `cargo metadata` and for one dependency-free build. bash >= 3.2; uses only
# standard POSIX tools + python3. Exits non-zero on the first failure.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/../../templates/poc"
REAL_CARGO="$(command -v cargo 2>/dev/null || true)"
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

# cargo shim + a PATH with the shim first. The shim logs the two lookups that make an
# in-tree build dangerous, the way cargo and rustup do them: a .cargo/config.toml in
# the working directory or any parent (the user's CARGO_HOME excepted), and a
# rust-toolchain.toml there when RUSTUP_TOOLCHAIN is not pinned. `cargo metadata`
# answers from SHIM_METADATA (a JSON file), from real cargo (SHIM_REAL_CARGO), or
# with no packages; SHIM_FAIL makes one step fail with cargo's own exit code, 101.
mkdir -p "$T/shim"
cat > "$T/shim/cargo" <<'SH'
#!/bin/sh
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
if [ "${1:-}" = metadata ]; then
  if [ -n "${SHIM_REAL_CARGO:-}" ]; then exec "$SHIM_REAL_CARGO" "$@"; fi
  if [ -n "${SHIM_METADATA:-}" ]; then cat "$SHIM_METADATA"; else echo '{"packages":[]}'; fi
  exit 0
fi
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

# live() reads every line. Test files far past the pipe buffer, with the required
# call on every line, still count as live: an early-exit `grep -q` would lose the
# match to SIGPIPE under pipefail and refuse the crate.
mk_crate "$T/big" incident
python3 -I -c 'for _ in range(40000): print("    let post = outcome.get_account(&state_pk).expect(\"x\");")' > "$T/big/tests/exploit.rs"
python3 -I -c 'for _ in range(40000): print("    assert_exploit_rejected_with!(outcome, ProgramResult::Failure(e), \"g\");")' > "$T/big/tests/fixed_blocked.rs"
code="$(run "$T/big" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 0 ] && ok "40,000-line test files still count as live (no SIGPIPE refusal) -> exit 0" || { bad "large test files: exit $code"; grep blocker "$T/out" >&2; }

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
build_dir() { sed -n 's/^>> build dir: \([^ ]*\).*/\1/p' "$T/out" | head -n 1; }

# Shim: the control shows the shim sees the hostile files in place; run.sh must not.
mk_crate "$R/incident_1/poc/INC-1.1" incident
( cd "$R/incident_1/poc/INC-1.1" && SHIM_LOG="$LOG" RUSTUP_TOOLCHAIN= "$T/shim/cargo" test >/dev/null )
if grep -q '^config ' "$LOG" && grep -q '^toolchain ' "$LOG"; then ok "control: in place, cargo would read the target's .cargo/config.toml and rust-toolchain.toml"; else bad "control: the shim did not see the hostile tree"; fi
rm -f "$LOG"
code="$(run "$R/incident_1/poc/INC-1.1" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_LOG="$LOG")"
bd="$(build_dir)"
case "$bd" in
  "$R"/*|"") bad "self-contained crate: build dir '$bd' is not a scratch copy outside the target tree" ;;
  *) [ "$code" = 0 ] && ok "self-contained crate builds in a scratch copy outside the target tree ($bd)" || bad "self-contained crate: exit $code" ;;
esac
if [ -s "$LOG" ]; then bad "run.sh let cargo/rustup see the target's config: $(tr '\n' ' ' < "$LOG")"; else ok "neither the target's .cargo/config.toml nor its rust-toolchain.toml was in reach of cargo"; fi
[ -n "$bd" ] && [ ! -e "$bd" ] && ok "scratch build dir removed on exit" || bad "scratch build dir '$bd' left behind"
if command -v rustup >/dev/null 2>&1; then
  tc="$(rustup default 2>/dev/null | sed -n 's/ (default)$//p')"
  grep -q "^>> build dir: .*toolchain ${tc};" "$T/out" && ok "toolchain pinned to rustup's default (${tc}), not left to a rust-toolchain file" || bad "toolchain not pinned (want ${tc})"
fi
rm -f "$LOG"
code="$(run "$R/incident_1/poc/INC-1.1" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" KEEP_POC_BUILD=1)"
bd="$(build_dir)"
if [ "$code" = 0 ] && [ -d "$bd" ]; then ok "KEEP_POC_BUILD=1 keeps the scratch build dir"; rm -rf "$bd"; else bad "KEEP_POC_BUILD=1: exit $code, dir '$bd'"; fi
mkdir -p "$R/tmp"
code="$(run "$R/incident_1/poc/INC-1.1" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" TMPDIR="$R/tmp")"
[ "$code" = 3 ] && grep -q 'would inherit' "$T/out" && ok "a scratch dir that would inherit the target's config (TMPDIR inside the tree) -> exit 3" || bad "TMPDIR inside the target tree: exit $code"

# Relative .so paths still resolve once the build moves to the scratch copy.
code="$(run "$T/inc" "$SP" VULNERABLE_SO=../vuln.so FIXED_SO=../fixed.so)"
[ "$code" = 0 ] && grep -q "vulnerable sha256 (zero-trimmed): $want" "$T/out" && ok "relative VULNERABLE_SO/FIXED_SO resolve from the caller's directory" || bad "relative .so paths: exit $code"

# Target-dependency detection: a path, git or workspace-inherited dependency, or a
# symlink, makes the crate target-dependent; comments and in-crate paths do not.
mk_dep() {  # mk_dep <dir> <Cargo.toml dependency line>
  mk_crate "$1" incident
  printf '[package]\nname = "p"\nversion = "0.1.0"\n\n[dependencies]\n%s\n' "$2" > "$1/Cargo.toml"
}
mk_dep "$T/d-path" 'vault = { path = "../../../programs/vault" }'
code="$(run "$T/d-path" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'AUDITOR_EXEC_MODE' "$T/out" && grep -q 'Rule 11a' "$T/out" && ! grep -q '^>> build dir' "$T/out" && ok "path dependency outside the crate, no execution mode -> exit 3 pointing to Rule 11a" || bad "path dependency: exit $code"
code="$(run "$T/d-path" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" AUDITOR_EXEC_MODE=native)"
[ "$code" = 0 ] && grep -q 'building in place under AUDITOR_EXEC_MODE=native' "$T/out" && ok "path dependency with AUDITOR_EXEC_MODE=native -> builds in place, with a notice" || bad "path dependency + native: exit $code"
code="$(run "$T/d-path" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" AUDITOR_EXEC_MODE=yes)"
[ "$code" = 3 ] && ok "an unknown AUDITOR_EXEC_MODE value -> exit 3" || bad "AUDITOR_EXEC_MODE=yes: exit $code"
mk_dep "$T/d-git" 'vault = { git = "https://example.invalid/vault.git" }'
code="$(run "$T/d-git" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'git dependency' "$T/out" && ok "git dependency -> exit 3" || bad "git dependency: exit $code"
mk_dep "$T/d-ws" 'anchor-lang = { workspace = true }'
code="$(run "$T/d-ws" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'workspace-inherited' "$T/out" && ok "workspace-inherited dependency -> exit 3" || bad "workspace = true: exit $code"
mk_crate "$T/d-link" incident; ln -s "$R" "$T/d-link/target-src"
code="$(run "$T/d-link" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 3 ] && grep -q 'symlink' "$T/out" && ok "a symlink inside the crate -> exit 3" || bad "symlink: exit $code"
mk_dep "$T/d-comment" '# old = { git = "https://example.invalid/x.git", path = "../../x" }'
code="$(run "$T/d-comment" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
[ "$code" = 0 ] && grep -q '^>> build dir: .*scratch copy' "$T/out" && ok "a commented-out dependency does not count" || bad "commented dependency: exit $code"
# The shipped template itself (in-crate path dependency on shared-test-utils, framework
# crates only) is self-contained and inside the allowlist, so it is relocated and run.
# With real cargo present, `cargo metadata` reads its manifests for the allowlist.
mkdir -p "$T/tmpl"; cp -R "$TEMPLATE/." "$T/tmpl/"
sed 's/{PROGRAM_NAME}/poc_tmpl/' "$TEMPLATE/Cargo.toml" > "$T/tmpl/Cargo.toml"
mk_crate "$T/tmpl" incident
code="$(run "$T/tmpl" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_REAL_CARGO="$REAL_CARGO")"
[ "$code" = 0 ] && grep -q '^>> build dir: .*scratch copy' "$T/out" && ! grep -q 'allowlist' "$T/out" && ok "the template's own manifests pass every check (relocated, allowlist clean${REAL_CARGO:+, real cargo metadata})" || { bad "template manifests: exit $code"; cat "$T/out" >&2; }

# adv-14: strings the old `= "..."` pattern missed — a multi-line literal string, an
# array value, a unicode escape, and a '#' inside a string that a naive comment cut
# would truncate — each make the crate target-dependent.
chk_dep() {  # chk_dep <dir> <expected message fragment> <label>
  code="$(run "$1" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
  [ "$code" = 3 ] && grep -q "$2" "$T/out" && ok "$3 -> exit 3" || bad "$3: exit $code"
}
mk_dep "$T/d-ml" "vault = { path = '''/abs/target/prog''' }"
chk_dep "$T/d-ml" 'escaped or multi-line TOML string' "multi-line literal string path"
mk_dep "$T/d-abs" 'vault = { path = "/abs/target/prog" }'
chk_dep "$T/d-abs" 'a path that leaves the crate' "absolute path"
mk_crate "$T/d-arr" incident
printf '[package]\nname = "p"\nversion = "0.1.0"\n\n[workspace]\nmembers = ["/abs/target/prog"]\n' > "$T/d-arr/Cargo.toml"
chk_dep "$T/d-arr" 'a path that leaves the crate' "absolute path inside an array"
mk_dep "$T/d-uesc" 'vault = { path = "\u002Fabs/target/prog" }'
chk_dep "$T/d-uesc" 'escaped or multi-line TOML string' "unicode-escaped path"
mk_dep "$T/d-hash" 'vault = { path = "x#/../../../programs/vault" }'
chk_dep "$T/d-hash" 'a path that leaves the crate' "a '#' inside the path string"

# adv-15: registry dependencies outside the framework allowlist (as `cargo metadata`
# reports them) need the execution mode; framework crates, `_` spellings included, do not.
md() { printf '{"packages":[{"name":"p","targets":%s,"dependencies":[%s]}]}\n' "$2" "$3" > "$T/$1.json"; }
CIO='"source":"registry+https://github.com/rust-lang/crates.io-index","registry":null'
md md-itoa '[]' '{"name":"itoa",'"$CIO"'}'
md md-renamed '[]' '{"name":"evil-crate","rename":"solana-program",'"$CIO"'}'
md md-under '[]' '{"name":"solana_program",'"$CIO"'},{"name":"sha2",'"$CIO"'}'
md md-altreg '[]' '{"name":"solana-program","source":"registry+https://example.invalid/index","registry":"https://example.invalid/index"}'
md md-target '[{"name":"t","src_path":"/elsewhere/lib.rs"}]' ''
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_METADATA="$T/md-itoa.json")"
[ "$code" = 3 ] && grep -q 'outside the framework allowlist (itoa)' "$T/out" && grep -q 'Rule 11a' "$T/out" && ok "a crates.io dependency outside the allowlist, no execution mode -> exit 3" || bad "non-allowlisted dependency: exit $code"
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_METADATA="$T/md-itoa.json" AUDITOR_EXEC_MODE=isolated)"
[ "$code" = 0 ] && grep -q 'building the scratch copy under AUDITOR_EXEC_MODE=isolated' "$T/out" && ok "the same with AUDITOR_EXEC_MODE=isolated -> builds the scratch copy, with a notice" || bad "non-allowlisted + isolated: exit $code"
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_METADATA="$T/md-renamed.json")"
[ "$code" = 3 ] && grep -q '(evil-crate)' "$T/out" && ok "a renamed dependency is judged by its real package name -> exit 3" || bad "renamed dependency: exit $code"
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_METADATA="$T/md-under.json")"
[ "$code" = 0 ] && ok "framework crates pass the allowlist (solana_program, sha2)" || bad "allowlisted dependencies: exit $code"
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_METADATA="$T/md-altreg.json")"
[ "$code" = 3 ] && grep -q 'not from crates.io' "$T/out" && ok "a framework name from another registry -> exit 3" || bad "alternate registry: exit $code"
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_METADATA="$T/md-target.json")"
[ "$code" = 3 ] && grep -q 'source outside the crate' "$T/out" && ok "a build target whose source is outside the crate -> exit 3" || bad "outside target source: exit $code"
if [ -n "$REAL_CARGO" ]; then
  mk_real() {  # mk_real <dir> <dependency line>: a manifest real `cargo metadata` can read
    mk_crate "$1" incident; mkdir -p "$1/src"; : > "$1/src/lib.rs"
    printf '[package]\nname = "p"\nversion = "0.1.0"\nedition = "2021"\n\n[workspace]\n\n[features]\nvulnerable = []\nfixed = []\n\n[dependencies]\n%s\n' "$2" > "$1/Cargo.toml"
  }
  mk_real "$T/r-itoa" 'itoa = "1"'
  code="$(run "$T/r-itoa" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_REAL_CARGO="$REAL_CARGO")"
  [ "$code" = 3 ] && grep -q 'allowlist (itoa)' "$T/out" && ok "real cargo metadata: itoa is outside the allowlist -> exit 3" || bad "real cargo, itoa: exit $code"
  mk_real "$T/r-renamed" 'solana-program = { package = "itoa", version = "1" }'
  code="$(run "$T/r-renamed" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_REAL_CARGO="$REAL_CARGO")"
  [ "$code" = 3 ] && grep -q 'allowlist (itoa)' "$T/out" && ok "real cargo metadata: a solana-program alias for itoa is caught -> exit 3" || bad "real cargo, renamed: exit $code"
fi

# Exit codes: a build that fails is a blocker (3); only the test verdicts are 1 and 2.
code="$(run "$T/inc" "$SP" SHIM_FAIL=build-sbf)"
[ "$code" = 3 ] && grep -q 'SBF build failed' "$T/out" && ok "cargo build-sbf failing (101) -> exit 3" || bad "build-sbf failure: exit $code"
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_FAIL=no-run:exploit)"
[ "$code" = 3 ] && grep -q 'tests/exploit.rs failed to build for the vulnerable arm' "$T/out" && ok "an exploit test that does not compile -> exit 3" || bad "exploit test build failure: exit $code"
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_FAIL=no-run:fixed_blocked)"
[ "$code" = 3 ] && grep -q 'tests/fixed_blocked.rs failed to build for the fixed arm' "$T/out" && ok "a fixed-arm test that does not compile -> exit 3" || bad "fixed test build failure: exit $code"
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_FAIL=exploit)"
[ "$code" = 1 ] && ok "exploit test failing -> exit 1" || bad "exploit failure: exit $code"
code="$(run "$T/inc" "$SP" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so" SHIM_FAIL=fixed_blocked)"
[ "$code" = 2 ] && ok "fixed-arm test failing -> exit 2" || bad "fixed-arm failure: exit $code"
code="$(run "$T/inc" "$SP")"
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
  rm -f "$MK"
  code="$(run "$RC" "$PATH" VULNERABLE_SO="$T/vuln.so" FIXED_SO="$T/fixed.so")"
  if [ "$code" = 0 ] && [ ! -e "$MK" ]; then
    ok "real cargo: tests pass from the scratch copy and neither the wrapper nor the path toolchain ran"
  else
    bad "real cargo: exit $code, marker: $(tr '\n' ' ' < "$MK" 2>/dev/null)"; cat "$T/out" >&2
  fi
  [ -f "$RC/Cargo.lock" ] && ok "real cargo: the resolved Cargo.lock is kept with the crate" || bad "real cargo: Cargo.lock not copied back"
else
  echo "note: cargo or rustup not on PATH; the real-toolchain checks are skipped (the shim checks above still ran)"
fi

if [ "$fails" -ne 0 ]; then
  echo "test-dnr-poc-runner: $fails assertion(s) FAILED" >&2
  exit 1
fi
echo "test-dnr-poc-runner: all assertions passed"
