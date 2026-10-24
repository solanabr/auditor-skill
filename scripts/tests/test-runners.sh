#!/usr/bin/env bash
# test-runners.sh — self-test for scripts/runner/target.sh, deps.sh and sast.sh: each case file under
# fixtures/{target,deps,sast}/ under each bash on the machine (/bin/bash and the bash running this suite,
# when they differ), then each runner against stand-in toolchains (fixtures/runners/fake-tool.sh as cargo,
# cargo-build-sbf, cargo-audit, cargo-outdated, anchor, npm, node, semgrep, curl and rustup) that record
# their arguments, working directory, HOME, ulimit -t and -f and environment: the fixed command lines, the
# scratch copy outside the working directory, the mode rule with none, the isolated self-check, the proxy
# and HOME split, canary variables, the watchdog and the caps, patches, revisions, submodules, artifacts,
# disclosure rows and large inputs. Then one case with the real tool for each action whose tool is
# installed: cargo test and cargo clippy, cargo build-sbf (when its platform tools are installed, so that
# nothing is downloaded), npm ci, cargo audit --no-fetch and cargo tree, all offline. With REQUIRE_TOOLCHAIN=1
# (CI sets it), a missing cargo or rustup fails the run instead of skipping those. Needs git and python3;
# no network. Usage (from the repo root): bash scripts/tests/test-runners.sh
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
for pair in "target:$TARGET" "deps:$DEPS" "sast:$SAST"; do
  name=${pair%%:*}
  prog=${pair#*:}
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
    label="$name ${args[*]}"
    label=${label//[[:cntrl:]]/?}
    [ "${#label}" -le 160 ] || label="${label:0:160}..."
    i=0
    for sh in "${SHELLS[@]}"; do
      rm -rf "$NT"
      mkdir -p "$NT"
      ( cd "$WT" && env -i HOME="$CLEANHOME" PATH="$FPATH" TMPDIR="$NT" "$sh" "$prog" "${args[@]}" ) \
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
  check "the $name case file has cases ($ncase)" test "$ncase" -gt 20
  check "no $name case changed anything in the working directory" test "$(tree_of "$WT")" = "$before"
  check "no $name case ran a configured program or hook of the repository" test -z "$(ls -A "$T/marks")"
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
while IFS='|' read -r file env want; do
  [ -n "$want" ] || continue
  if [ -n "$file" ]; then printf '%s\n' "$file" > "$WT/audit_1/exec-mode"; else rm -f "$WT/audit_1/exec-mode"; fi
  set --
  [ -z "$env" ] || set -- "AUDITOR_EXEC_MODE=$env"
  run "$TARGET" "$WT" "$@" -- cargo-test --run audit_1 --src .
  label="exec-mode '${file:-absent}', AUDITOR_EXEC_MODE '${env:-unset}'"
  case "$want" in
    native|isolated)
      if [ "$want" = isolated ] && [ "$ISOLATED_OK" = 0 ]; then continue; fi
      check "$label: runs in $want mode" sh -c "[ '$RC' = 0 ] && grep -qxF '>> execution mode: $want (the stricter of audit_1/exec-mode: ${file:-absent}; AUDITOR_EXEC_MODE: ${env:-unset})' '$T/out'" ;;
    none)
      check "$label: none, exit 3 before anything is copied" sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: the recorded execution mode is none (' '$T/err' && [ ! -s '$T/out' ] && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]" ;;
    missing)
      check "$label: no recorded mode, exit 3 before anything is copied" sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: no recorded mode: audit_1/exec-mode is missing and AUDITOR_EXEC_MODE is not set' '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]" ;;
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
native|none|none
none|native|none
isolated|none|none
||missing
CASES
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
run "$TARGET" "$WT" HOME="$CREDHOME" -- cargo-test --run audit_1 --src .
check "native mode with a readable SSH key: a warning by kind and count, and the run goes on" \
  sh -c "[ '$RC' = 0 ] && grep -q '^>> warning: native mode, and these are readable here, to the code this run builds and runs too: SSH keys (1)' '$T/out' && ! grep -q 'id_rsa' '$T/out'"
mkdir -p "$T/sys-nopy"
for f in "$T/sys/"*; do [ "${f##*/}" = python3 ] || ln -s "$(readlink "$f")" "$T/sys-nopy/${f##*/}"; done
run "$TARGET" "$WT" PATH="$T/fake:$T/sys-nopy" AUDITOR_EXEC_MODE=isolated -- cargo-test --run audit_1 --src .
check "isolated mode where the self-check cannot run (no python3): exit 3, nothing copied" \
  sh -c "[ '$RC' = 3 ] && grep -qF 'target: blocker: isolated mode, but the credential self-check could not finish (python3 is not on PATH)' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
run "$TARGET" "$WT" PATH="$T/fake:$T/sys-nopy" -- cargo-test --run audit_1 --src .
check "native mode without python3: a blocker before anything is copied" \
  sh -c "[ '$RC' = 3 ] && grep -qF 'target: blocker: python3 is not on PATH, so cargo-test cannot run here — nothing was copied or built.' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
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
run "$TARGET" "$WT" TOOLS_VERSION=v1.54 -- build-sbf --run audit_1 --src . --package demo
check "--package builds that member, and TOOLS_VERSION goes to the install and the build" calls_are \
  "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo build-sbf --help|cargo build-sbf --install-only --tools-version v1.54|cargo metadata --no-deps --format-version 1 --offline --manifest-path $S/src/Cargo.toml|cargo build-sbf --skip-tools-install --offline --sbf-out-dir $S/out --tools-version v1.54 --manifest-path $S/src/programs/demo/Cargo.toml|"
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src . --package nope
check "a --package the workspace does not have: exit 3, nothing built" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: the workspace at the top of the copy has no member package nope' '$T/err' && ! grep -q '^== cargo build-sbf --skip' '$T/calls'"
settings FAKE_SBF_HELP=old
run "$TARGET" "$WT" -- build-sbf --run audit_1 --src .
check "a cargo build-sbf without --install-only and --skip-tools-install: exit 3, nothing installed or built" \
  sh -c "[ '$RC' = 3 ] && grep -q 'has no --install-only, --skip-tools-install or --offline' '$T/err' && ! grep -q '^== cargo build-sbf --install' '$T/calls' && ! grep -q '^== cargo build-sbf --skip' '$T/calls'"
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
check "anchor-build: the downloads, then anchor build --ignore-keys -p <program> -- --skip-tools-install --offline" \
  calls_are "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo build-sbf --help|cargo build-sbf --install-only|anchor build --ignore-keys -p demo -- --skip-tools-install --offline|"
check "... and the program's .so is kept from target/deploy" sh -c "grep -q '1 .so in audit_1/exec/anchor-build-1/: demo.so' '$T/out'"
check "... the build in the throwaway HOME, with its keypair" in_blocks '^== anchor build' '^keypair: yes$'
run "$TARGET" "$WT" HTTPS_PROXY="$PROXY" -- anchor-test --run audit_1 --src .
check "anchor-test: npm ci --ignore-scripts first, then the build, then anchor test against no validator and no deploy" \
  calls_are "rustup default|cargo fetch --manifest-path $S/src/Cargo.toml|cargo build-sbf --help|cargo build-sbf --install-only|npm ci --ignore-scripts --no-audit --no-fund|anchor build --ignore-keys -- --skip-tools-install --offline|anchor test --skip-build --skip-deploy --skip-local-validator --provider.cluster localnet --provider.wallet $S/home/.config/solana/id.json|"
check "... npm ci gets the proxy, its own empty config files and the git on PATH" \
  sh -c "awk '/^== npm ci/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk' && grep -qxF 'env: npm_config_userconfig=$S/npm/userconfig' '$T/blk' && grep -qxF 'env: npm_config_globalconfig=$S/npm/globalconfig' '$T/blk' && grep -qxF 'env: npm_config_git=$T/sys/git' '$T/blk' && grep -qxF 'env: npm_config_ignore_scripts=true' '$T/blk' && grep -qxF 'userconfig-bytes: 0' '$T/blk'"
check "... anchor test runs without the proxy" none_in_blocks '^== anchor test' '^env: [A-Za-z_]*[Pp][Rr][Oo][Xx][Yy]='
run "$TARGET" "$WT" -- anchor-test --run audit_1 --src . --dir app
check "anchor-test where the lockfile is yarn's: no install, and a note says so" \
  sh -c "[ '$RC' = 0 ] && grep -q '^>> note: app holds a yarn, pnpm or bun lockfile' '$T/out' && ! grep -q '^== npm' '$T/calls'"
settings FAKE_ANCHOR_TEST_RC=1
run "$TARGET" "$WT" -- anchor-test --run audit_1 --src .
check "anchor-test whose tests fail: exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> anchor-test: anchor test failed (exit 1)' '$T/out'"
settings
run "$TARGET" "$WT" HTTPS_PROXY="$PROXY" -- npm-ci --run audit_1 --src .
check "npm-ci: npm ci --ignore-scripts --no-audit --no-fund in the copy, and no Rust toolchain asked for" \
  calls_are "npm ci --ignore-scripts --no-audit --no-fund|"
check "... in the copy, with the proxy" sh -c "awk '/^== npm ci/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'cwd: $S/src' '$T/blk' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk' && grep -qxF 'lock: yes' '$T/blk'"
settings FAKE_NPM_CI_RC=1
run "$TARGET" "$WT" -- npm-ci --run audit_1 --src .
check "npm ci that fails (a lockfile out of step with package.json): exit 1" sh -c "[ '$RC' = 1 ] && grep -q '^>> npm-ci: npm ci --ignore-scripts failed (exit 1)' '$T/out'"
settings

# =================================================================================================
# target.sh: the watchdog, signals and large output.
# =================================================================================================
settings FAKE_SLEEP=60
t0=$(date +%s)
run "$TARGET" "$WT" AUDITOR_RUN_TIMEOUT=3 -- cargo-test --run audit_1 --src .
t1=$(date +%s)
check "AUDITOR_RUN_TIMEOUT: a step past the limit is killed, exit 3 ($((t1 - t0)) s)" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: cargo test: the run passed its 3-second limit (AUDITOR_RUN_TIMEOUT or --timeout) and was killed; log ' '$T/err' && [ $((t1 - t0)) -lt 30 ]"
gc=$(cat "$T/grandchild.pid" 2>/dev/null)
check "... and so is the process the step started in the background" sh -c "[ -n '$gc' ] && ! kill -0 '$gc' 2>/dev/null"
check "... and the scratch directory is gone" sh -c "[ '$RC' = 3 ] && [ -z \"\$(ls -A '$NT')\" ]"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src . --timeout 2
check "--timeout lowers the limit" sh -c "[ '$RC' = 3 ] && grep -q 'the run passed its 2-second limit' '$T/err'"
check "... and ulimit -t follows it" in_blocks '^== cargo test' '^ulimit: [1-8] 4194304$'
settings FAKE_LEFTOVER=1
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src .
lo=$(cat "$T/leftover.pid" 2>/dev/null)
check "a process a step leaves behind is killed when the step ends" sh -c "[ '$RC' = 0 ] && [ -n '$lo' ] && sleep 1 && ! kill -0 '$lo' 2>/dev/null"
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
check "SIGTERM to target.sh stops the step at once ($((t1 - t0)) s), kills what it started, and removes the scratch directory" \
  sh -c "[ '$RC' = 143 ] && [ $((t1 - t0)) -lt 15 ] && [ -n '$gc' ] && ! kill -0 '$gc' 2>/dev/null && [ -z \"\$(ls -A '$NT')\" ]"
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
# $T/plain is not a repository: a package with target/, sub/TARGET/, node_modules/ and sub/node_modules/
# directories, a run directory, the store, a top-level audit_notes.md, a link and a FIFO.
P=$T/plain
mkdir -p "$P/src" "$P/target" "$P/sub/TARGET" "$P/node_modules/x" "$P/sub/node_modules" "$P/sub/keep" "$P/.audit-memory"
printf '[package]\nname = "plainpkg"\nversion = "0.1.0"\n' > "$P/Cargo.toml"
printf 'fn p() {}\n' > "$P/src/lib.rs"
printf 'built\n' > "$P/target/out"; printf 'built\n' > "$P/sub/TARGET/out"; printf 'js\n' > "$P/sub/node_modules/y"
printf 'kept\n' > "$P/sub/keep/file"; printf 'db\n' > "$P/.audit-memory/audit.db"; printf 'notes\n' > "$P/audit_notes.md"
ln -s /etc/hosts "$P/lnk"
mkfifo "$P/pipe" 2>/dev/null || true
( cd "$P" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$P/audit_1/exec-mode"
settings FAKE_LIST=1
run "$TARGET" "$P" -- cargo-test --run audit_1 --src .
check "a source that is not a repository is copied file by file" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'listing: . ./Cargo.toml ./lnk ./src ./src/lib.rs ./sub ./sub/keep ./sub/keep/file ' '$T/calls'"
check "... its links kept as links, never followed" grep -qxF 'link: ./lnk -> /etc/hosts' "$T/calls"
run "$TARGET" "$P" -- cargo-test --run audit_1 --src . --rev HEAD
check "--rev with a source that is not a repository is refused" sh -c "[ '$RC' = 64 ] && grep -qxF 'target: refused: --rev needs a repository --src, and . is not the top level of one' '$T/err'"
run "$TARGET" "$WT" -- cargo-test --run audit_1 --src programs
check "a directory inside a repository, not its top, is copied as files" \
  sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: no Cargo.toml at the top of the copy' '$T/err'"
settings
# A repository whose commit has a submodule.
SM=$T/subwt
tgit init -q "$SM" && tgit -C "$SM" symbolic-ref HEAD refs/heads/main
printf '[package]\nname = "sm"\nversion = "0.1.0"\n' > "$SM/Cargo.toml"
tgit -C "$SM" add Cargo.toml
tgit -C "$SM" update-index --add --cacheinfo "160000,$V1,vendor/sub"
tgit -C "$SM" commit -qm 'with a submodule'
( cd "$SM" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$SM/audit_1/exec-mode"
run "$TARGET" "$SM" -- cargo-test --run audit_1 --src .
check "a revision with a submodule: exit 3, nothing fetched or built" \
  sh -c "[ '$RC' = 3 ] && grep -q 'has submodules (vendor/sub), and target.sh never fetches them' '$T/err' && ! grep -q '^== cargo' '$T/calls'"
# A partial clone.
PC=$T/partwt
tgit clone -q --no-local "$WT" "$PC" 2>/dev/null
tgit -C "$PC" config extensions.partialClone origin
( cd "$PC" && "$ROOT/scripts/rundir.sh" new audit ) >/dev/null && printf 'native\n' > "$PC/audit_1/exec-mode"
run "$TARGET" "$PC" -- cargo-test --run audit_1 --src .
check "a partial clone: exit 3 before anything is copied" sh -c "[ '$RC' = 3 ] && grep -q '^target: blocker: . is a partial clone' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
# git without the May-2024 clone fixes.
mkdir -p "$T/oldgit"
printf '#!/bin/sh\n[ "$1" = --version ] && { echo "git version 2.39.3"; exit 0; }\nexec %s "$@"\n' "$(command -v git)" > "$T/oldgit/git"
chmod +x "$T/oldgit/git"
run "$TARGET" "$WT" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src .
check "git 2.39.3 cannot clone the source: exit 3" sh -c "[ '$RC' = 3 ] && grep -q 'cloning --src needs git with the May-2024 clone fixes' '$T/err' && [ -z \"\$(ls -A '$NT')\" ]"
run "$TARGET" "$P" PATH="$T/oldgit:$FPATH" -- cargo-test --run audit_1 --src .
check "... while a source that is copied file by file needs no clone" test "$RC" = 0
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
  sh -c "[ '$RC' = 0 ] && ! grep -q '^== rustup' '$T/calls' && grep -qxF 'env: RUSTUP_TOOLCHAIN=1.85.0' '$T/calls'"
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

# =================================================================================================
# target.sh in an incident's run directory: INCIDENTS.json must give the root cause, and
# supply_chain_or_ci is never built natively.
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
run "$TARGET" "$WT" -- build-sbf --run incident_1 --src . --patch incident_1/patches/INC-1.2.patch
check "--patch of another incident of the run, a code flaw: only its class counts, and it builds" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '>> incident INC-1.2: root_cause_class code_flaw (incident_1/INCIDENTS.json)' '$T/out'"
if [ "$ISOLATED_OK" = 1 ]; then
  run "$TARGET" "$WT" AUDITOR_EXEC_MODE=isolated -- build-sbf --run incident_1 --src .
  check "isolated mode builds a supply_chain_or_ci incident's code" test "$RC" = 0
fi
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

# cargo-tree and cargo-outdated: stub targets, sources from crates.io only, and a git that fetches nothing.
mkdir -p "$WT/stubs"
printf '[package]\nname = "stubs"\nversion = "0.1.0"\nbuild = "build.rs"\n\n[lib]\npath = "lib/main.rs"\n\n[[bin]]\nname = "tool"\n\n[[test]]\nname = "it"\npath = "checks/it.rs"\n' > "$WT/stubs/Cargo.toml"
r0=$(rows)
run "$DEPS" "$WT" HTTPS_PROXY="$PROXY" -- cargo-tree --run audit_1 --manifest Cargo.toml --manifest programs/demo/Cargo.toml --manifest Cargo.lock
check "cargo-tree: cargo metadata offline on the copies, then cargo tree --workspace --color never --locked" calls_are \
  "rustup default|cargo metadata --no-deps --format-version 1 --offline --manifest-path $S/w/Cargo.toml|cargo tree --workspace --color never --locked --manifest-path $S/w/Cargo.toml|"
check "... on the named manifests, each package manifest with an empty src/lib.rs beside it" \
  grep -qxF 'copies: ./Cargo.lock ./Cargo.toml ./programs/demo/Cargo.toml ./programs/demo/src/lib.rs ' "$T/calls"
check "... cargo told to fetch git sources with a git that refuses them" \
  sh -c "awk '/^== cargo tree/{on=1;next} /^== /{on=0} on' '$T/calls' > '$T/blk' && grep -qxF 'git: $S/nogit/git deps.sh: git sources are not fetched' '$T/blk' && grep -qxF 'env: CARGO_NET_GIT_FETCH_WITH_CLI=true' '$T/blk' && grep -qxF 'env: HTTPS_PROXY=$PROXY' '$T/blk'"
check "... the metadata read offline, without the proxy" none_in_blocks '^== cargo metadata' '^env: [A-Za-z_]*[Pp][Rr][Oo][Xx][Yy]='
check "... and one disclosure row naming the three manifests" \
  sh -c "[ \$(( \$(wc -l < '$DT') - 1 - $r0 )) = 1 ] && sed -n '\$p' '$DT' | grep -q '	crates.io	the crate names and version requirements in these manifests (cargo-tree resolves them with the crates.io index and downloads): Cargo.toml programs/demo/Cargo.toml Cargo.lock	3\$'"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml
check "the stub targets follow the manifest: its lib path, build script, bins and tests" \
  grep -qxF 'copies: ./Cargo.toml ./build.rs ./checks/it.rs ./lib/main.rs ./src/bin/tool.rs ./src/lib.rs ' "$T/calls"
check "... and without a Cargo.lock, no --locked" has_call "cargo tree --workspace --color never --manifest-path $S/w/stubs/Cargo.toml"
printf '[package]\nname = "out"\nversion = "0.1.0"\n\n[lib]\npath = "../../outside.rs"\n' > "$WT/stubs/Cargo.toml"
run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml
check "a target path outside the manifest's directory: exit 3, cargo never runs" \
  sh -c "[ '$RC' = 3 ] && grep -q '^deps: blocker: stubs/Cargo.toml names a target outside its directory: ../../outside.rs' '$T/err' && ! grep -q '^== cargo' '$T/calls'"
for table in '[patch.crates-io]\nserde = { version = "1", registry-index = "sparse+https://evil.invalid/" }' \
  'patch.crates-io.serde = { git = "https://evil.invalid/serde" }' '[replace]\n"serde:1.0.0" = { path = "/tmp" }'; do
  printf "[package]\nname = \"pt\"\nversion = \"0.1.0\"\n\n$table\n" > "$WT/stubs/Cargo.toml"
  r0=$(rows)
  run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest stubs/Cargo.toml
  check "a manifest with $(printf "$table" | sed -n 1p | cut -c1-40): exit 3, cargo never runs, nothing disclosed" \
    sh -c "[ '$RC' = 3 ] && grep -qxF 'deps: blocker: stubs/Cargo.toml holds a [patch] or [replace] table, which deps.sh does not resolve: it can name any host; output audit_1/deps/cargo-tree-'\"\$(sed -n 's/.*cargo-tree-\([0-9]*\)[.]txt\$/\1/p' '$T/err')\"'.txt' '$T/err' && ! grep -q '^== cargo' '$T/calls' && [ \"\$(( \$(wc -l < '$DT') - 1 ))\" = '$r0' ]"
done
for dep in '{"name":"evil","source":"git+https://evil.invalid/x","registry":null}|from git+https://evil.invalid/x, not crates.io' \
  '{"name":"alt","source":"registry+https://alt.invalid/index","registry":"https://alt.invalid/index"}|from another registry than crates.io' \
  '{"name":"far","source":null,"registry":null,"path":"/etc"}|at a path outside the copied manifests'; do
  settings FAKE_META_DEP="${dep%%|*}"
  r0=$(rows)
  run "$DEPS" "$WT" -- cargo-tree --run audit_1 --manifest Cargo.toml --manifest programs/demo/Cargo.toml
  check "a dependency ${dep#*|}: exit 3, nothing resolved or disclosed" \
    sh -c "[ '$RC' = 3 ] && grep -q '${dep#*|}' '$T/err' && ! grep -q '^== cargo tree' '$T/calls' && [ \"\$(( \$(wc -l < '$DT') - 1 ))\" = '$r0' ]"
done
settings FAKE_OUTDATED_RC=1
run "$DEPS" "$WT" -- cargo-outdated --run audit_1 --manifest Cargo.toml --manifest programs/demo/Cargo.toml --manifest Cargo.lock
check "cargo-outdated: cargo outdated --workspace --exit-code 1 --color never, and outdated dependencies are exit 1" \
  sh -c "[ '$RC' = 1 ] && grep -qx '== cargo outdated --workspace --exit-code 1 --color never --manifest-path $S/w/Cargo.toml' '$T/calls' && grep -q '^>> cargo-outdated: outdated dependencies found (exit 1): ' '$T/out'"
settings FAKE_OUTDATED_RC=2
run "$DEPS" "$WT" -- cargo-outdated --run audit_1 --manifest Cargo.toml --manifest programs/demo/Cargo.toml
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
import base64, hashlib, io, json, os, sys, tarfile, zipfile
fix = sys.argv[1]
def put(url, data, status=None):
    key = url.replace("/", "_").replace(":", "_").replace("%", "_").replace("@", "_")
    open(os.path.join(fix, key), "wb").write(data if isinstance(data, bytes) else data.encode())
    if status:
        open(os.path.join(fix, key + ".status"), "w").write(str(status))
def tgz(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
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
npm = tgz([("package/package.json", "file", b"{\"name\": \"left-pad\"}\n"), ("package/index.js", "file", b"module.exports = 1\n")])
integrity = "sha512-" + base64.b64encode(hashlib.sha512(npm).digest()).decode()
put("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", npm)
put("https://registry.npmjs.org/left-pad/1.3.0", json.dumps({"name": "left-pad", "version": "1.3.0", "dist": {
    "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "integrity": integrity}}))
put("https://registry.npmjs.org/left-pad/1.4.0", json.dumps({"name": "left-pad", "version": "1.4.0", "dist": {
    "tarball": "https://evil.invalid/left-pad-1.4.0.tgz", "integrity": integrity}}))
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
check "fetch-artifact npm: the tarball at the URL the registry's name gives, its sha512 integrity checked" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'url: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz' '$T/calls' && [ -f '$WT/audit_1/deps/fetch-artifact-$n/files/package/index.js' ] && grep -q '^digest: sha512 ' '$WT/audit_1/deps/fetch-artifact-$n.txt'"
run "$DEPS" "$WT" -- fetch-artifact --run audit_1 npm left-pad 1.4.0
check "an npm record whose tarball is elsewhere: exit 3, nothing downloaded" \
  sh -c "[ '$RC' = 3 ] && grep -q 'names the tarball at https://evil.invalid/left-pad-1.4.0.tgz' '$T/err' && ! grep -q 'url: https://evil' '$T/calls'"
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
  sh -c "[ '$RC' = 3 ] && grep -q 'holds 50001 entries, more than 50000' '$T/err' && [ -z \"\$(find '$WT/audit_1/deps' -path '*/files/many' -print)\" ]"
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
mkdir -p "$WT/src/inner"
ln -s ../lib.rs "$WT/src/inner/near.rs"
run "$SAST" "$WT" -- semgrep --run audit_1 --path src --ruleset p/rust
check "a link under --path that stays inside it is fine" test "$RC" = 0
ln -s ../../a.rs "$WT/src/inner/out.rs"
run "$SAST" "$WT" -- semgrep --run audit_1 --path src --ruleset p/rust
check "a link under --path to another part of the working directory is refused" \
  sh -c "[ '$RC' = 64 ] && grep -qxF 'sast: refused: --path holds a symbolic link that resolves outside it, src/inner/out.rs; semgrep could read and quote what it points to, so scan a directory without it' '$T/err'"
run "$SAST" "$WT" -- semgrep --run audit_1 --path . --ruleset p/rust
check "... and the same link is fine when --path holds what it points to" test "$RC" = 0
rm -f "$WT/src/inner/out.rs"
ln -s "$CREDHOME/.ssh/id_rsa" "$WT/src/inner/key.rs"
run "$SAST" "$WT" -- semgrep --run audit_1 --path . --ruleset p/secrets
check "a link that resolves outside the working directory is refused before anything is sent" \
  sh -c "[ '$RC' = 64 ] && grep -qxF 'sast: refused: --path holds a symbolic link that resolves outside it, src/inner/key.rs; semgrep could read and quote what it points to, so scan a directory without it' '$T/err' && [ ! -s '$T/calls' ] && [ -z \"\$(ls -A '$NT')\" ]"
rm -rf "$WT/src/inner"
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
