#!/bin/sh
# A stand-in for cargo, cargo-build-sbf, cargo-audit, cargo-outdated, anchor, npm, node, semgrep, curl and
# rustup, for scripts/tests/test-runners.sh. The suite copies it under each name with @T@ replaced by its
# temporary directory. The runners hand it a cleaned environment, so it reads its settings from @T@/fake/settings
# (shell assignments the suite writes), and it appends one block per call to @T@/calls:
#   == <name> <arguments>
#   cwd: <working directory>
#   home: <HOME>
#   ulimit: <ulimit -t> <ulimit -f>
#   env: <NAME=value>       one line per variable, sorted
# followed by the lines each behaviour below adds. FAKE_* settings choose the behaviour: exit statuses, what a
# build writes, files to show, a listing of the working directory, output to print, time to sleep.
T=@T@
name=${0##*/}
[ -f "$T/fake/settings" ] && . "$T/fake/settings"
{
  printf '== %s %s\n' "$name" "$*"
  printf 'cwd: %s\n' "$PWD"
  printf 'home: %s\n' "${HOME:-}"
  printf 'ulimit: %s %s\n' "$(ulimit -t)" "$(ulimit -f)"
  env | LC_ALL=C sort | sed 's/^/env: /'
} >> "$T/calls"
say() { printf '%s\n' "$*" >> "$T/calls"; }
arg_after() { # arg_after <option> <arguments>...: the word after <option>
  o=$1; shift; p=""
  for a in "$@"; do [ "$p" = "$o" ] && { printf '%s' "$a"; return 0; }; p=$a; done
  return 1
}
case "$name" in
  rustup)
    case "$1" in default) [ "${FAKE_RUSTUP_DEFAULT:-}" = none ] && exit 1; echo "stable-fake (default)" ;; esac
    exit 0 ;;
  node) exit 0 ;;
  cargo-build-sbf|cargo-audit|cargo-outdated) exit 0 ;;
  curl)
    out=$(arg_after -o "$@"); url=""; dash=0
    for a in "$@"; do [ "$dash" = 1 ] && url=$a; [ "$a" = -- ] && dash=1; done
    say "url: $url"
    [ -n "${FAKE_CURL_RC:-}" ] && { echo "curl: (7) Failed to connect" >&2; exit "$FAKE_CURL_RC"; }
    key=$(printf '%s' "$url" | tr '/:%@' '____')
    if [ -f "$T/fix/$key" ]; then
      cp "$T/fix/$key" "$out"
      code=200
      [ -f "$T/fix/$key.status" ] && code=$(cat "$T/fix/$key.status")
    else
      printf '{"error":"Not found"}' > "$out"
      code=404
    fi
    printf '%s' "$code"
    exit 0 ;;
  semgrep)
    out=$(arg_after --output "$@")
    say "settings-file: ${SEMGREP_SETTINGS_FILE:-}"
    [ -n "${FAKE_SLEEP:-}" ] && sleep "$FAKE_SLEEP"
    echo "semgrep: scanning"
    if [ "${FAKE_SARIF:-}" != none ] && [ -n "$out" ]; then
      python3 -I -c 'import json, sys
n = int(sys.argv[2])
json.dump({"version": "2.1.0", "runs": [{"results": [{"ruleId": "r%d" % i} for i in range(n)]}]}, open(sys.argv[1], "w"))' "$out" "${FAKE_RESULTS:-0}"
    fi
    exit "${FAKE_SEMGREP_RC:-0}" ;;
  anchor)
    say "keypair: $([ -f "$HOME/.config/solana/id.json" ] && echo yes || echo no)"
    case "$1" in
      build)
        mkdir -p target/deploy && printf '\177ELFanchor' > target/deploy/demo.so
        exit "${FAKE_ANCHOR_BUILD_RC:-0}" ;;
      test) exit "${FAKE_ANCHOR_TEST_RC:-0}" ;;
    esac
    exit 0 ;;
  npm)
    case "$1" in
      ci)
        say "lock: $([ -f package-lock.json ] && echo yes || echo no)"
        say "userconfig-bytes: $(wc -c < "${npm_config_userconfig:-/nonexistent}" 2>/dev/null | tr -d ' ')"
        exit "${FAKE_NPM_CI_RC:-0}" ;;
      audit)
        say "npmrc: $(tr '\n' '|' < .npmrc 2>/dev/null)"
        say "userconfig-bytes: $(wc -c < "${npm_config_userconfig:-/nonexistent}" 2>/dev/null | tr -d ' ')"
        say "files: $(ls -A | tr '\n' ' ')"
        [ -n "${FAKE_NPM_AUDIT_OUT:-}" ] && cat "$FAKE_NPM_AUDIT_OUT"
        exit "${FAKE_NPM_AUDIT_RC:-0}" ;;
    esac
    exit 0 ;;
esac
# cargo
case "$1" in
  --version) echo "cargo 1.0.0-fake"; exit 0 ;;
  fetch)
    say "cargo-config-here: $([ -e .cargo ] && echo yes || echo no)"
    exit "${FAKE_FETCH_RC:-0}" ;;
  build-sbf)
    case "$*" in
      *--help*) [ "${FAKE_SBF_HELP:-}" = old ] && { echo "--offline"; exit 0; }
                echo "--install-only --skip-tools-install --offline"; exit 0 ;;
      *--install-only*) exit "${FAKE_INSTALL_RC:-0}" ;;
    esac
    say "keypair: $([ -f "$HOME/.config/solana/id.json" ] && echo yes || echo no)"
    say "tools: $( [ -L "$HOME/.cache/solana" ] && ls -l "$HOME/.cache/solana" | sed 's/.* -> //')"
    [ -n "${FAKE_SHOW:-}" ] && say "show: $(cat "$FAKE_SHOW" 2>/dev/null)"
    out=$(arg_after --sbf-out-dir "$@")
    if [ -n "$out" ]; then
      for so in ${FAKE_SO_NAMES:-demo}; do printf '\177ELF%s' "$so" > "$out/$so.so"; done
      [ -n "${FAKE_SO_LINK:-}" ] && ln -s "$FAKE_SO_LINK" "$out/linked.so"
      [ -n "${FAKE_SO_BIG:-}" ] && dd if=/dev/zero of="$out/big.so" bs=1 count=0 seek="$FAKE_SO_BIG" 2>/dev/null
      printf 'notes\n' > "$out/notes.txt"
    fi
    exit "${FAKE_BUILD_RC:-0}" ;;
  test)
    [ -n "${FAKE_SHOW:-}" ] && say "show: $(cat "$FAKE_SHOW" 2>/dev/null)"
    if [ -n "${FAKE_LIST:-}" ]; then
      say "listing: $(find . -print | LC_ALL=C sort | tr '\n' ' ')"
      for l in $(find . -type l -print); do say "link: $l -> $(ls -l "$l" | sed 's/.* -> //')"; done
    fi
    [ -n "${FAKE_BIG:-}" ] && head -c "$FAKE_BIG" /dev/zero | tr '\0' 'x'
    if [ -n "${FAKE_SLEEP:-}" ]; then
      sleep 300 &
      echo $! > "$T/grandchild.pid"
      sleep "$FAKE_SLEEP"
    fi
    [ -n "${FAKE_LEFTOVER:-}" ] && { sleep 300 & echo $! > "$T/leftover.pid"; }
    echo "test result: ok"
    exit "${FAKE_TEST_RC:-0}" ;;
  clippy)
    case "$*" in *--version*) [ "${FAKE_CLIPPY:-}" = missing ] && exit 1; echo "clippy 0.1.0-fake"; exit 0 ;; esac
    echo "warning: one"; echo "warning: two"
    exit "${FAKE_CLIPPY_RC:-0}" ;;
  metadata)
    mp=$(arg_after --manifest-path "$@")
    python3 -I -c 'import json, os, re, sys
top = os.path.dirname(sys.argv[1])
pkgs = []
for d, dirs, files in os.walk(top):
    dirs[:] = [x for x in dirs if x not in ("target", ".git")]
    if "Cargo.toml" in files:
        text = open(os.path.join(d, "Cargo.toml")).read()
        m = re.search(r"(?ms)^\[package\].*?^name\s*=\s*\"([^\"]+)\"", text)
        if m:
            v = re.search(r"(?ms)^\[package\].*?^version\s*=\s*\"([^\"]+)\"", text)
            ver = v.group(1) if v else "0.1.0"
            pid = "path+file://%s#%s@%s" % (d, m.group(1), ver)
            pkgs.append({"name": m.group(1), "version": ver, "edition": "2021", "id": pid,
                         "manifest_path": os.path.join(d, "Cargo.toml"), "dependencies": [], "features": {}})
extra = os.environ.get("FAKE_META_DEP", "")
if extra and pkgs:
    val = json.loads(extra)
    pkgs[0]["dependencies"].extend(val if isinstance(val, list) else [val])
print(json.dumps({"packages": pkgs, "workspace_members": [p["id"] for p in pkgs], "workspace_root": top}))' "$mp"
    exit 0 ;;
  audit)
    say "files: $(ls -A | tr '\n' ' ')"
    [ -n "${FAKE_SLEEP:-}" ] && sleep "$FAKE_SLEEP"
    [ -n "${FAKE_AUDIT_OUT:-}" ] && cat "$FAKE_AUDIT_OUT"
    exit "${FAKE_AUDIT_RC:-0}" ;;
  tree|outdated)
    mp=$(arg_after --manifest-path "$@")
    say "manifest: $mp"
    say "copies: $(cd "$(dirname "$mp")" && find . -type f -print | LC_ALL=C sort | tr '\n' ' ')"
    say "git: $(command -v git) $(git fetch 2>&1)"
    # The manifests cargo was handed, one grepped line per interesting line of every Cargo.toml under them, so
    # the suite can see what the rebuild produced.
    [ -z "${SHIM_DUMP:-}" ] || find "$(dirname "$mp")" -name Cargo.toml -exec grep -hE '^\[|^[A-Za-z0-9_-]+ = ' {} + | sed 's/^/rebuilt| /' >> "$T/calls"
    echo "demo v0.1.0"
    [ "$1" = tree ] && exit "${FAKE_TREE_RC:-0}"
    exit "${FAKE_OUTDATED_RC:-0}" ;;
esac
exit 0
