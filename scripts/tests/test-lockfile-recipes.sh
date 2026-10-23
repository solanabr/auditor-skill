#!/usr/bin/env bash
# test-lockfile-recipes.sh — run the dependency recipes exactly as the corpus writes them, against throwaway
# repositories, and check what they print:
#   - checklist 11 §11.11: the npm / yarn lockfile hint prints each changed version, resolved, integrity or
#     checksum line after the key of its entry (package-lock.json and npm-shrinkwrap.json with and without
#     resolved fields, lockfile v1, an npm alias, yarn v1 and berry), and "?" when the key is outside the
#     hunk; every hint prints the same under a checkout config that sets colour and zero context lines;
#     step 4's sweep deletes every entry that is neither a regular file nor a directory;
#   - the @solana/web3.js 1.95.6 / 1.95.7 check, FULL-AUDIT Step 3.2 and KV-077 Step 2 (the same commands
#     in both): resolved-field shapes, and the key-line form in the tree and in history (added, removed, a
#     changed key, an alias, a merged side branch), but not another package at that version; above 64 KiB;
#   - the scratch-directory recipes, FULL-AUDIT Step 3.2 and KV-089 Steps 1, 2 and 5: with $SCRATCH unset,
#     empty or missing, or mktemp failing, they print OUTCOME: no scratch copy and run nothing; otherwise
#     npm, cargo and rustup run only inside the scratch directory;
#   - KV-137 Step 2: the upstream comparison runs in a scratch copy and nothing from the checkout's config.
# Usage (from the repo root): bash scripts/tests/test-lockfile-recipes.sh
# Needs bash >= 3.2, git, grep, sed, awk, find, mkfifo. No network: the upstream is a local path.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CL="$ROOT/checklists/11-supply-chain.md"
FA="$ROOT/FULL-AUDIT.md"
KV077="$ROOT/known-vectors/077-malicious-npm-package-typosquatting.md"
KV089="$ROOT/known-vectors/089-unpatched-server-dependencies.md"
KV137="$ROOT/known-vectors/137-vendored-program-version-drift.md"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE SCRATCH
T=$(mktemp -d "${TMPDIR:-/tmp}/lockfile-recipes.XXXXXX") || exit 1
trap 'chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"' EXIT
export GIT_CEILING_DIRECTORIES="$T" GIT_ALLOW_PROTOCOL=file GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
  GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "PASS $*"; }
bad() { failn=$((failn + 1)); echo "FAIL $*"; }
has() { grep -qxF -- "$2" "$1"; }   # has FILE LINE: FILE holds LINE exactly

# ---- recipe extraction ----------------------------------------------------------------------------------
# The command under the "> # <marker>" comment of a quoted code block in checklist 11, "> " removed.
cl_hint() {
  awk -v m="> # $1" '
    index($0, m) == 1 { g = 1; next }
    g && /^> #/ && !s { next }
    g && (/^> #/ || /^> ```/) { exit }
    g { s = 1; sub(/^> /, ""); print }
  ' "$CL"
}
# The web3.js check: from the W3= line to the end of the history awk, comments dropped, indentation removed.
w3_block() { awk '/^ *W3=/ {g = 1} g && !/^ *#/ {sub(/^ */, ""); print} g && /print c, f, \$0}'"'"'$/ {exit}' "$1"; }
# A known vector's step: the lines of the first code block after "**Step <n>:".
kv_step() { awk -v n="$2" 'index($0, "**Step " n ":") == 1 {s = 1; next} s && /^```$/ {if (c) exit; c = 1; next} s && c' "$1"; }
# FULL-AUDIT Step 3.2's scratch block, from SCRATCH= to its closing fi, block indentation removed.
fa_scratch() { awk '/^  SCRATCH=\$\(mktemp -d/ {g = 1} g {sub(/^  /, ""); print} g && /^fi$/ {exit}' "$FA"; }

# ---- fixtures: npm / yarn lockfiles ---------------------------------------------------------------------
npm_lock() { # npm_lock WEB3VER WEB3INT BABELINT SWINT RESOLVED(0|1) — lockfileVersion 3, with an alias entry
  printf '{\n  "name": "app",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "requires": true,\n  "packages": {\n'
  printf '    "": {\n      "name": "app",\n      "version": "1.0.0",\n      "dependencies": {\n'
  printf '        "@solana/web3.js": "^1.95.5",\n        "string-width-cjs": "npm:string-width@^4.2.0"\n      }\n    },\n'
  printf '    "node_modules/@babel/runtime": {\n      "version": "7.25.0",\n'
  [ "$5" = 1 ] && printf '      "resolved": "https://registry.npmjs.org/@babel/runtime/-/runtime-7.25.0.tgz",\n'
  printf '      "integrity": "sha512-%s",\n      "license": "MIT"\n    },\n' "$3"
  printf '    "node_modules/@solana/web3.js": {\n      "version": "%s",\n' "$1"
  [ "$5" = 1 ] && printf '      "resolved": "https://registry.npmjs.org/@solana/web3.js/-/web3.js-%s.tgz",\n' "$1"
  printf '      "integrity": "sha512-%s",\n      "license": "MIT",\n      "dependencies": {\n' "$2"
  printf '        "@babel/runtime": "^7.25.0"\n      }\n    },\n'
  printf '    "node_modules/string-width-cjs": {\n      "name": "string-width",\n      "version": "4.2.3",\n'
  [ "$5" = 1 ] && printf '      "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz",\n'
  printf '      "integrity": "sha512-%s",\n      "license": "MIT"\n    }\n  }\n}\n' "$4"
}
v1_lock() { # v1_lock WEB3VER WEB3INT BABELINT
  printf '{\n  "name": "app",\n  "version": "1.0.0",\n  "lockfileVersion": 1,\n  "requires": true,\n  "dependencies": {\n'
  printf '    "@babel/runtime": {\n      "version": "7.25.0",\n      "integrity": "sha512-%s"\n    },\n' "$3"
  printf '    "@solana/web3.js": {\n      "version": "%s",\n      "integrity": "sha512-%s",\n' "$1" "$2"
  printf '      "requires": {\n        "@babel/runtime": "^7.25.0"\n      }\n    }\n  }\n}\n'
}
yarn1_lock() { # yarn1_lock WEB3VER WEB3INT BABELINT
  printf '# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n'
  printf '"@babel/runtime@^7.25.0":\n  version "7.25.0"\n'
  printf '  resolved "https://registry.yarnpkg.com/@babel/runtime/-/runtime-7.25.0.tgz#bbbb"\n  integrity sha512-%s\n\n' "$3"
  printf '"@solana/web3.js@^1.95.5":\n  version "%s"\n' "$1"
  printf '  resolved "https://registry.yarnpkg.com/@solana/web3.js/-/web3.js-%s.tgz#aaaa"\n  integrity sha512-%s\n' "$1" "$2"
  printf '  dependencies:\n    "@babel/runtime" "^7.25.0"\n'
}
berry_lock() { # berry_lock WEB3VER WEB3SUM BABELSUM — @babel/runtime's checksum sits below 7 dependency lines
  printf '# This file is generated by running "yarn install" inside your project.\n'
  printf '# Manual changes might be lost - proceed with caution!\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n'
  printf '"@babel/runtime@npm:^7.25.0":\n  version: 7.25.0\n  resolution: "@babel/runtime@npm:7.25.0"\n  dependencies:\n'
  for d in regenerator-runtime a b c d e f; do printf '    %s: "npm:^1.0.0"\n' "$d"; done
  printf '  checksum: 10c0/%s\n  languageName: node\n  linkType: hard\n\n' "$3"
  printf '"@solana/web3.js@npm:^1.95.5":\n  version: %s\n  resolution: "@solana/web3.js@npm:%s"\n' "$1" "$1"
  printf '  dependencies:\n    "@babel/runtime": "npm:^7.25.0"\n  checksum: 10c0/%s\n  languageName: node\n  linkType: hard\n' "$2"
}
other_locks() { # other_locks WEB3VER INT ANCHORVER ANCHORSUM BORSHSUM — pnpm, bun and Cargo.lock
  printf "lockfileVersion: '9.0'\n\npackages:\n\n  '@solana/web3.js@%s':\n    resolution: {integrity: sha512-%s}\n" \
    "$1" "$2" > pnpm-lock.yaml
  printf '{\n  "lockfileVersion": 1,\n  "packages": {\n    "@solana/web3.js": ["@solana/web3.js@%s", "", {}, "sha512-%s"],\n  }\n}\n' \
    "$1" "$2" > bun.lock
  printf '# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = "anchor-lang"\n' > Cargo.lock
  printf 'version = "%s"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%s"\n' "$3" "$4" >> Cargo.lock
  printf 'dependencies = [\n "borsh",\n]\n\n[[package]]\nname = "borsh"\nversion = "1.5.1"\n' >> Cargo.lock
  printf 'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%s"\n' "$5" >> Cargo.lock
}
H="$T/hints"
git init -q "$H" && mkdir -p "$H/rez" "$H/norez" "$H/v1" "$H/shrink" "$H/yarn1" "$H/berry" || exit 1
locks() { # locks WEB3VER A B C — every lockfile of the hints fixture
  ( cd "$H" && npm_lock "$1" "$2" "$3" "$4" 1 > rez/package-lock.json && npm_lock "$1" "$2" "$3" "$4" 0 > norez/package-lock.json \
    && npm_lock "$1" "$2" "$3" "$4" 0 > shrink/npm-shrinkwrap.json && v1_lock "$1" "$2" "$3" > v1/package-lock.json \
    && yarn1_lock "$1" "$2" "$3" > yarn1/yarn.lock && berry_lock "$1" "$2" "$3" > berry/yarn.lock )
}
locks 1.95.5 AAAA BBBB CCCC && (cd "$H" && other_locks 1.95.5 AAAA 0.30.1 aaaa bbbb) \
  && git -C "$H" add -A && git -C "$H" commit -qm base && git -C "$H" tag rev-base \
  && locks 1.95.6 DDDD EEEE FFFF && (cd "$H" && other_locks 1.95.6 DDDD 0.31.0 dddd eeee) \
  && git -C "$H" commit -qam head && git -C "$H" tag rev-head || { echo "could not build the hints fixture" >&2; exit 1; }

# ---- 1. §11.11 lockfile hints -----------------------------------------------------------------------------
run_hint() { # run_hint MARKER OUT: the hint, <base>..<head> filled in, run in the fixture
  cl_hint "$1" | sed 's/<base>\.\.<head>/rev-base..rev-head/' > "$T/hint.sh"
  if [ ! -s "$T/hint.sh" ]; then : > "$2"; return 1; fi
  ( cd "$H" && bash "$T/hint.sh" ) > "$2" 2> "$T/hint.err"
}
NPM='npm (package-lock.json, npm-shrinkwrap.json)'
run_hint "$NPM" "$T/npm.out"
for want in \
  '+++ b/norez/package-lock.json' \
  '"node_modules/@solana/web3.js" -      "version": "1.95.5",' \
  '"node_modules/@solana/web3.js" +      "version": "1.95.6",' \
  '"node_modules/@babel/runtime" +      "integrity": "sha512-EEEE",' \
  '"name": "string-width" +      "integrity": "sha512-FFFF",' \
  '+++ b/shrink/npm-shrinkwrap.json' \
  '"node_modules/@solana/web3.js" +      "resolved": "https://registry.npmjs.org/@solana/web3.js/-/web3.js-1.95.6.tgz",' \
  '"@solana/web3.js" +      "version": "1.95.6",' \
  '"@solana/web3.js@^1.95.5" +  version "1.95.6"' \
  '"@babel/runtime@^7.25.0" +  integrity sha512-EEEE' \
  '"@solana/web3.js@npm:^1.95.5" +  resolution: "@solana/web3.js@npm:1.95.6"' \
  '? +  checksum: 10c0/EEEE'; do
  if has "$T/npm.out" "$want"; then ok "npm/yarn hint prints: $want"; else bad "npm/yarn hint lacks: $want"; fi
done
n=$(grep -cv -e '^+++ ' -e '^"' -e '^? ' "$T/npm.out")
if [ -s "$T/npm.out" ] && [ "$n" = 0 ]; then ok "npm/yarn hint: every changed line carries a key or ?"
else bad "npm/yarn hint: no output, or $n lines without a key or ?"; sed 's/^/  | /' "$T/npm.out"; fi

for m in 'changed manifests and lockfiles' "$NPM" 'pnpm (pnpm-lock.yaml)' 'bun (text bun.lock)' 'Cargo.lock: each'; do
  run_hint "$m" "$T/plain.out"; git -C "$H" config color.ui always; git -C "$H" config diff.context 0
  run_hint "$m" "$T/hostile.out"; git -C "$H" config --unset color.ui; git -C "$H" config --unset diff.context
  if [ -s "$T/plain.out" ] && grep -qE '1\.95\.6|0\.31\.0|shrinkwrap' "$T/plain.out" && cmp -s "$T/plain.out" "$T/hostile.out"; then
    ok "hint '$m' prints the same under color.ui=always and diff.context=0"
  else bad "hint '$m' output changes with the checkout's colour or context config"; fi
done
has "$T/plain.out" '"borsh" +checksum = "eeee"' && ok "Cargo.lock hint names a checksum-only change" \
  || bad "Cargo.lock hint lost the name of a checksum-only change"

# step 4: the sweep before any diff or grep, over an artifact whose directories are 0555 and 0000, then the
# check that only files and directories are left, then the diff
sweep=$(sed -n 's/.*Before any `diff` or `grep`, run `\([^`]*\)`.*/\1/p' "$CL")
confirm=$(sed -n 's/.*Then confirm that `\([^`]*\)` prints nothing.*/\1/p' "$CL")
A="$T/art"; mkdir -p "$A/old/pkg" "$A/new/pkg/sub" "$A/new/pkg/ro" "$A/new/pkg/hidden"
echo a > "$A/old/pkg/a.js"; echo b > "$A/new/pkg/a.js"; echo keep > "$T/linked-file"; chmod 444 "$T/linked-file"
ln -s "$T/linked-file" "$A/new/pkg/link"; ln -s sub "$A/new/pkg/dirlink"
mkfifo "$A/new/pkg/sub/fifo" "$A/old/pkg/fifo" "$A/new/pkg/ro/fifo"
echo 'require("child_process")' > "$A/new/pkg/hidden/run.js"; ln -s "$T/linked-file" "$A/new/pkg/hidden/link"
chmod 555 "$A/new/pkg/ro"; chmod 000 "$A/new/pkg/hidden"
( cd "$A" && eval "$sweep" ) > "$T/sweep.out" 2>&1
left=$(cd "$A" && eval "$confirm" 2>&1)
( cd "$A" && diff -ruN old/ new/ ) > "$T/sweep.diff" 2> "$T/sweep.err"
if [ -n "$sweep" ] && [ -n "$confirm" ] && [ -z "$left" ] && [ "$(wc -l < "$T/sweep.out" | tr -d ' ')" = 6 ] \
   && ! grep -q 'Permission denied' "$T/sweep.err" && grep -q 'child_process' "$T/sweep.diff" \
   && [ -f "$A/old/pkg/a.js" ] && [ -d "$A/new/pkg/sub" ] && [ "$(ls -l "$T/linked-file" | cut -c1-10)" = -r--r--r-- ]; then
  ok "step 4 opens 0555 and 0000 directories, deletes and lists links and FIFOs, and changes no link target"
else bad "step 4 ('$sweep', then '$confirm') left: $left"; sed 's/^/  | /' "$T/sweep.out" "$T/sweep.err"; fi

# ---- 2. the @solana/web3.js 1.95.6 / 1.95.7 check -------------------------------------------------------
w3_block "$FA" > "$T/w3-fa.sh"; w3_block "$KV077" > "$T/w3-kv.sh"
if [ -s "$T/w3-fa.sh" ] && cmp -s "$T/w3-fa.sh" "$T/w3-kv.sh"; then ok "FULL-AUDIT Step 3.2 and KV-077 Step 2 run the same web3.js check"
else bad "the web3.js check differs between FULL-AUDIT Step 3.2 and KV-077 Step 2"; fi
run_w3() { ( cd "$1" && bash "$T/w3-fa.sh" ) > "$T/w3.out" 2>&1; }

# resolved-field shapes, in the hints fixture at rev-head
run_w3 "$H"
for want in \
  './rez/package-lock.json:23:      "resolved": "https://registry.npmjs.org/@solana/web3.js/-/web3.js-1.95.6.tgz",' \
  './berry/yarn.lock:25:  resolution: "@solana/web3.js@npm:1.95.6"' \
  "./pnpm-lock.yaml:5:  '@solana/web3.js@1.95.6':" \
  './norez/package-lock.json-21-      "version": "1.95.6",' \
  './shrink/npm-shrinkwrap.json-21-      "version": "1.95.6",' \
  './v1/package-lock.json-12-      "version": "1.95.6",'; do
  if has "$T/w3.out" "$want"; then ok "web3.js check, tree: $want"; else bad "web3.js check, tree, missing: $want"; fi
done

# the key-line form in history: npm lockfiles without resolved fields
W="$T/w3"
pl() { # pl FILE WEB3VER [ALIASVER] [DECOYVER] [FILLER]: FILLER entries come first, so the file passes 64 KiB
  {
    printf '{\n  "name": "web",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "requires": true,\n  "packages": {\n'
    printf '    "": {\n      "name": "web",\n      "version": "1.0.0"\n    },\n'
    i=0; while [ "$i" -lt "${5:-0}" ]; do
      printf '    "node_modules/filler-%s": {\n      "version": "1.95.6",\n      "integrity": "sha512-f%s"\n    },\n' "$i" "$i"
      i=$((i + 1)); done
    if [ -n "${4:-}" ]; then printf '    "node_modules/decoy": {\n      "version": "%s",\n      "integrity": "sha512-x"\n    },\n' "$4"; fi
    printf '    "node_modules/@solana/web3.js": {\n      "version": "%s",\n      "integrity": "sha512-w"\n    }' "$2"
    if [ -n "${3:-}" ]; then
      printf ',\n    "node_modules/web3-alias": {\n      "name": "@solana/web3.js",\n      "version": "%s",\n' "$3"
      printf '      "integrity": "sha512-a"\n    }'; fi
    printf '\n  }\n}\n'
  } > "$1"
}
git init -q -b main "$W" && mkdir -p "$W/apps/web" && cd "$W" || exit 1
c() { git add -A && git commit -qm "$1" && git rev-parse --short HEAD; }
pl apps/web/package-lock.json 1.95.6 "" "" 1500; C1=$(c root-1.95.6)
pl apps/web/package-lock.json 1.95.5 "" "" 1500; C2=$(c web3-1.95.5)
pl apps/web/package-lock.json 1.95.8 "" 1.95.6 1500; C3=$(c web3-1.95.8-decoy-1.95.6)
git checkout -qb side && pl apps/web/package-lock.json 1.95.7 "" 1.95.6 1500 && C4=$(c side-1.95.7) \
  && pl apps/web/package-lock.json 1.95.8 "" 1.95.6 1500 && C5=$(c side-back) && git checkout -q main \
  && echo x > other && C6=$(c main-other) && git merge -q --no-edit side && git branch -qD side
pl apps/web/npm-shrinkwrap.json 1.95.8 1.95.7 1.95.6 1500; C7=$(c shrinkwrap-alias-1.95.7)
cd "$ROOT" || exit 1
size=$(wc -c < "$W/apps/web/package-lock.json" | tr -d ' ')
git -C "$W" config color.ui always; git -C "$W" config diff.context 0; git -C "$W" config log.showRoot false
run_w3 "$W"
f=b/apps/web/package-lock.json
if grep -qx '\./apps/web/npm-shrinkwrap\.json-[0-9]*-      "version": "1\.95\.7",' "$T/w3.out"; then
  ok "web3.js check, tree: the alias entry in npm-shrinkwrap.json"
else bad "web3.js check, tree: the alias entry in npm-shrinkwrap.json is missing"; fi
for want in \
  "$C1 $f +      \"version\": \"1.95.6\"," \
  "$C2 $f -      \"version\": \"1.95.6\"," \
  "$C4 $f +      \"version\": \"1.95.7\"," \
  "$C5 $f -      \"version\": \"1.95.7\"," \
  "$C7 b/apps/web/npm-shrinkwrap.json +      \"version\": \"1.95.7\","; do
  if has "$T/w3.out" "$want"; then ok "web3.js check, key-line form: $want"; else bad "web3.js check, key-line form, missing: $want"; fi
done
if [ "$size" -gt 65536 ] && [ "$(grep -c '1\.95\.6' "$T/w3.out")" = 2 ]; then
  ok "web3.js check passes over filler and the decoy at 1.95.6 ($size-byte lockfile)"
else bad "web3.js check reports another package at 1.95.6, or the lockfile is under 64 KiB ($size bytes)"; sed 's/^/  | /' "$T/w3.out"; fi
# a key that changes while the version line stays the same
git init -q "$T/w3k" && mkdir -p "$T/w3k/a" && printf '{\n  "packages": {\n    "node_modules/@solana/web3.js": {\n      "version": "1.95.6",\n      "integrity": "sha512-w"\n    }\n  }\n}\n' > "$T/w3k/a/package-lock.json" \
  && K1=$(cd "$T/w3k" && c add) \
  && printf '{\n  "packages": {\n    "node_modules/other": {\n      "version": "1.95.6",\n      "integrity": "sha512-w"\n    }\n  }\n}\n' > "$T/w3k/a/package-lock.json" \
  && K2=$(cd "$T/w3k" && c rename)
run_w3 "$T/w3k"
if grep -q "^$K2 b/a/package-lock.json  *\"version\": \"1.95.6\",$" "$T/w3.out" && grep -q "^$K1 " "$T/w3.out"; then
  ok "web3.js check, history: a commit that changes the key beside an unchanged version line"
else bad "web3.js check, history: the changed key is not reported"; sed 's/^/  | /' "$T/w3.out"; fi

# ---- 3. scratch-directory recipes -----------------------------------------------------------------------
kv_step "$KV089" 1 > "$T/kv1.sh"; kv_step "$KV089" 2 > "$T/kv2.sh"; kv_step "$KV089" 5 > "$T/kv5.sh"; fa_scratch > "$T/fa.sh"
cat "$T/kv1.sh" "$T/kv2.sh" "$T/kv5.sh" > "$T/kv125.sh"
mkdir -p "$T/stub" "$T/tgt/apps/backend" "$T/tgt/apps/web" "$T/tmp"
for p in apps/backend apps/web; do echo '{}' > "$T/tgt/$p/package.json"; echo '{}' > "$T/tgt/$p/package-lock.json"; done
echo '# lock' > "$T/tgt/Cargo.lock"
for s in npm cargo rustup; do
  printf '#!/bin/sh\necho "%s $PWD" >> "%s/ran"\n[ "$1" = default ] && echo "stable-x (default)"\nexit 0\n' "$s" "$T" > "$T/stub/$s"
done
chmod +x "$T/stub/npm" "$T/stub/cargo" "$T/stub/rustup"
scratch_case() { # scratch_case NAME SCRIPT WANT [env assignment...]: WANT is the expected OUTCOME line, or "" for a run
  local name=$1 script=$2 want=$3; shift 3
  : > "$T/ran"
  ( cd "$T/tgt" && env "$@" PATH="$T/stub:$PATH" bash "$script" ) > "$T/sc.out" 2>&1
  if [ -n "$want" ]; then
    if grep -qxF "$want" "$T/sc.out" && [ ! -s "$T/ran" ] && [ -z "$(ls -A "$T/tmp")" ]; then ok "$name: prints '$want' and runs nothing"
    else bad "$name"; sed 's/^/  | /' "$T/sc.out" "$T/ran"; fi
  else
    if [ -s "$T/ran" ] && ! grep -q 'OUTCOME: no scratch copy' "$T/sc.out" && ! grep -qvF " $T/tmp/auditor-scratch." "$T/ran"; then
      ok "$name: npm, cargo and rustup run only in the scratch directory"
    else bad "$name"; sed 's/^/  | /' "$T/sc.out" "$T/ran"; fi
  fi
}
scratch_case "KV-089 Step 2, SCRATCH unset" "$T/kv2.sh" "OUTCOME: no scratch copy (run Step 1 first)" -u SCRATCH TMPDIR="$T/tmp"
scratch_case "KV-089 Step 2, SCRATCH empty" "$T/kv2.sh" "OUTCOME: no scratch copy (run Step 1 first)" SCRATCH= TMPDIR="$T/tmp"
scratch_case "KV-089 Step 5, SCRATCH unset" "$T/kv5.sh" "OUTCOME: no scratch copy (run Step 1 first)" -u SCRATCH TMPDIR="$T/tmp"
scratch_case "KV-089 Step 5, SCRATCH a missing directory" "$T/kv5.sh" "OUTCOME: no scratch copy (run Step 1 first)" \
  SCRATCH="$T/missing" TMPDIR="$T/tmp"
scratch_case "KV-089 Step 1, mktemp fails" "$T/kv1.sh" "OUTCOME: no scratch copy (mktemp failed)" TMPDIR="$T/missing"
scratch_case "FULL-AUDIT Step 3.2, mktemp fails" "$T/fa.sh" "OUTCOME: no scratch copy (create it first)" TMPDIR="$T/missing"
scratch_case "KV-089 Steps 1, 2 and 5 in one shell" "$T/kv125.sh" "" TMPDIR="$T/tmp"
scratch_case "FULL-AUDIT Step 3.2" "$T/fa.sh" "" TMPDIR="$T/tmp"

# ---- 4. KV-137 Step 2: upstream fetched into a scratch copy -----------------------------------------------
U="$T/kv137"
git init -q -b main "$U/up" && mkdir -p "$U/up/programs/p" && echo v1 > "$U/up/programs/p/lib.rs" \
  && (cd "$U/up" && c v1 > /dev/null) && git clone -q "$U/up" "$U/client" \
  && echo fix > "$U/up/programs/p/fix.rs" && (cd "$U/up" && c "upstream security fix" > /dev/null) \
  && echo t > "$U/client/tenant" && (cd "$U/client" && c tenant > /dev/null) || exit 1
printf '#!/bin/sh\ntouch "%s/fired-$1"\n' "$U" > "$U/canary.sh" && chmod +x "$U/canary.sh"
git -C "$U/client" config core.fsmonitor "$U/canary.sh fsmonitor"
for h in post-checkout reference-transaction; do
  printf '#!/bin/sh\ntouch "%s/fired-%s"\n' "$U" "$h" > "$U/client/.git/hooks/$h"; chmod +x "$U/client/.git/hooks/$h"
done
refs_before=$(git -C "$U/client" for-each-ref | wc -l | tr -d ' ')
deployed=$(git -C "$U/up" rev-list --max-parents=0 HEAD)
awk '/^\*\*Step 2:/ {s = 1} s && /^SCRATCH=/ {g = 1} g {print} g && /\| head -40 \)$/ {exit}' "$KV137" \
  | sed -e "s#<checkout>#$U/client#; s#<UPSTREAM_REPO>#$U/up#; s#<deployed_commit>#$deployed#" > "$T/kv137.sh"
( cd "$U/client" && TMPDIR="$T/tmp" bash "$T/kv137.sh" ) > "$T/kv137.out" 2>&1
if grep -q ' upstream security fix$' "$T/kv137.out" && [ -z "$(ls "$U" | grep '^fired-')" ] \
   && [ "$(git -C "$U/client" for-each-ref | wc -l | tr -d ' ')" = "$refs_before" ]; then
  ok "KV-137 Step 2 lists the upstream fix from a scratch copy and leaves the checkout alone"
else bad "KV-137 Step 2"; sed 's/^/  | /' "$T/kv137.out"; fi

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
