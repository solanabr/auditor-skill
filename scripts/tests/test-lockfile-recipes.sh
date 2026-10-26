#!/usr/bin/env bash
# test-lockfile-recipes.sh — run the dependency recipes exactly as the corpus writes them, against throwaway
# repositories, and check what they print:
#   - checklist 11 §11.11, through scripts/git-ro.sh and scripts/recipes/lock-delta.sh as the corpus calls them:
#     the npm / yarn lockfile hint prints each changed version, resolved, integrity or checksum line after the
#     key of its entry (package-lock.json and npm-shrinkwrap.json with and without resolved fields, lockfile
#     v1, an npm alias, yarn v1 and berry), and "?" when the key is outside the hunk, in tab-indented and CRLF
#     lockfiles too; every hint prints the same under a checkout config that sets colour and zero context
#     lines; the changed-files hint, which FULL-AUDIT Step 3.2 repeats, lists a go.mod change; step 4's sweep
#     deletes every entry that is neither a regular file nor a directory, in 0555 and 0000 directories too;
#   - the known-bad release check for axios 1.14.1 / 0.30.4 and @solana/web3.js 1.95.6 / 1.95.7, the same
#     commands in FULL-AUDIT Step 3.2, KV-077 Step 2 and (its tree part) discovery/grep-commands.md, its history
#     through scripts/recipes/web3js-history.sh: the single-line shapes (resolved URLs, pnpm v5 and v9 keys, yarn
#     berry, bun, exact pins), and the key-line form in the tree and in history (added, removed, a changed key,
#     an alias, a deleted lockfile, a merged side branch, a merge commit, tab and CRLF lockfiles), but not
#     another package at those versions; the single-line history search; above 64 KiB;
#   - the scratch-directory recipes, KV-089 Steps 1, 2 and 5: with $SCRATCH unset, empty, missing, relative or
#     inside the working directory, or mktemp failing, they print OUTCOME: no scratch copy and run nothing;
#     otherwise npm, cargo and rustup run only inside the scratch directory. FULL-AUDIT Step 3.2 runs its audits
#     and registry queries through scripts/runner/deps.sh, with no scratch block of its own;
#   - KV-137 Steps 1 and 2: the upstream comparison runs in the bare copy scripts/git-ro.sh copy makes in a run
#     directory, against upstream's default branch whatever its name, and nothing from the checkout's config
#     runs; a TMPDIR inside the working directory stops the copy. Step 2 takes an https:// URL only and fetches
#     over https only: an option-shaped remote.upstream.url that Step 1 prints, a local path or a file:// URL
#     fetches nothing and fires no canary, and an option-shaped deployed commit is refused, never read as an
#     option; its log, above 64 KiB, is cut at 40 lines; SC-054 names the same fetch.
# Usage (from the repo root): bash scripts/tests/test-lockfile-recipes.sh
# Needs bash >= 3.2, git, grep, sed, awk, find, mkfifo. No network: the test's git config rewrites the
# upstream's https URL to a local path.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CL="$ROOT/checklists/11-supply-chain.md"
FA="$ROOT/FULL-AUDIT.md"
KV077="$ROOT/known-vectors/077-malicious-npm-package-typosquatting.md"
KV089="$ROOT/known-vectors/089-unpatched-server-dependencies.md"
KV137="$ROOT/known-vectors/137-vendored-program-version-drift.md"
GC="$ROOT/discovery/grep-commands.md"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE SCRATCH
T=$(mktemp -d "${TMPDIR:-/tmp}/lockfile-recipes.XXXXXX") || exit 1
trap 'chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"' EXIT
# A TMPDIR that ends in / (as on macOS) leaves // in $T, which cd drops from $PWD. The recipes compare
# paths with $PWD, so the suite uses the physical path.
T=$(cd "$T" && pwd -P) || exit 1
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
# The known-bad check: from its first grep to the web3js-history.sh call, comments dropped, indentation removed;
# its tree part is the first 3 of those lines.
kb_block() { awk '/^ *grep -rnE --exclude-dir=node_modules --include=.package\.json./ {g = 1} g && !/^ *#/ {sub(/^ */, ""); print} g && /web3js-history\.sh"$/ {exit}' "$1"; }
kb_tree() { awk '/^ *grep -rnE --exclude-dir=node_modules --include=.package\.json./ {g = 1} g && !/^ *#/ {sub(/^ */, ""); print; if (++n == 3) exit}' "$1"; }
# A known vector's step: the lines of the first code block after "**Step <n>:".
kv_step() { awk -v n="$2" 'index($0, "**Step " n ":") == 1 {s = 1; next} s && /^```$/ {if (c) exit; c = 1; next} s && c' "$1"; }
# FULL-AUDIT Step 3.2, from its heading to the next step's, block indentation removed.
fa_step32() { awk '/^### Step 3\.2 /{g = 1; next} g && /^### /{exit} g {sub(/^  /, ""); print}' "$FA"; }

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
other_locks() { # other_locks WEB3VER INT ANCHORVER ANCHORSUM BORSHSUM — pnpm, bun, Cargo.lock and go.mod
  printf "lockfileVersion: '9.0'\n\npackages:\n\n  '@solana/web3.js@%s':\n    resolution: {integrity: sha512-%s}\n" \
    "$1" "$2" > pnpm-lock.yaml
  printf '{\n  "lockfileVersion": 1,\n  "packages": {\n    "@solana/web3.js": ["@solana/web3.js@%s", "", {}, "sha512-%s"],\n  }\n}\n' \
    "$1" "$2" > bun.lock
  printf '# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = "anchor-lang"\n' > Cargo.lock
  printf 'version = "%s"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%s"\n' "$3" "$4" >> Cargo.lock
  printf 'dependencies = [\n "borsh",\n]\n\n[[package]]\nname = "borsh"\nversion = "1.5.1"\n' >> Cargo.lock
  printf 'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%s"\n' "$5" >> Cargo.lock
  printf 'module example.invalid/app\n\ngo 1.22\n\nrequire example.invalid/anchor v%s\n' "$3" > go.mod
}
H="$T/hints"
git init -q "$H" && mkdir -p "$H/rez" "$H/norez" "$H/v1" "$H/shrink" "$H/yarn1" "$H/berry" "$H/tabcrlf" "$H/yarncrlf" \
  "$H/pnpm5" || exit 1
locks() { # locks WEB3VER A B C — every lockfile of the hints fixture
  ( cd "$H" && npm_lock "$1" "$2" "$3" "$4" 1 > rez/package-lock.json && npm_lock "$1" "$2" "$3" "$4" 0 > norez/package-lock.json \
    && npm_lock "$1" "$2" "$3" "$4" 0 > shrink/npm-shrinkwrap.json && v1_lock "$1" "$2" "$3" > v1/package-lock.json \
    && yarn1_lock "$1" "$2" "$3" > yarn1/yarn.lock && berry_lock "$1" "$2" "$3" > berry/yarn.lock \
    && npm_lock "$1" "$2" "$3" "$4" 0 | awk '{gsub(/  /, "\t"); printf "%s\r\n", $0}' > tabcrlf/package-lock.json \
    && yarn1_lock "$1" "$2" "$3" | awk '{printf "%s\r\n", $0}' > yarncrlf/yarn.lock \
    && printf 'lockfileVersion: 5.4\n\npackages:\n\n  /@solana/web3.js/%s:\n    resolution: {integrity: sha512-%s}\n' \
         "$1" "$2" > pnpm5/pnpm-lock.yaml )
}
locks 1.95.5 AAAA BBBB CCCC && (cd "$H" && other_locks 1.95.5 AAAA 0.30.1 aaaa bbbb) \
  && git -C "$H" add -A && git -C "$H" commit -qm base && git -C "$H" tag rev-base \
  && locks 1.95.6 DDDD EEEE FFFF && (cd "$H" && other_locks 1.95.6 DDDD 0.31.0 dddd eeee) \
  && git -C "$H" commit -qam head && git -C "$H" tag rev-head || { echo "could not build the hints fixture" >&2; exit 1; }

# ---- 1. §11.11 lockfile hints -----------------------------------------------------------------------------
run_hint() { # run_hint MARKER OUT: the hint, <base>..<head> and the installation filled in, run in the fixture
  cl_hint "$1" | sed -e 's/<base>\.\.<head>/rev-base..rev-head/' -e "s#<auditor-skill root>#$ROOT#g" > "$T/hint.sh"
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
  '? +  checksum: 10c0/EEEE' \
  "$(printf '"node_modules/@solana/web3.js" +\t\t\t"version": "1.95.6",')" \
  "$(printf '"node_modules/@babel/runtime" +\t\t\t"integrity": "sha512-EEEE",')"; do
  if has "$T/npm.out" "$want"; then ok "npm/yarn hint prints: $want"; else bad "npm/yarn hint lacks: $want"; fi
done
if [ "$(grep -cxF '"@babel/runtime@^7.25.0" +  integrity sha512-EEEE' "$T/npm.out")" = 2 ]; then
  ok "npm/yarn hint names an integrity-only change in a CRLF yarn.lock"
else bad "npm/yarn hint lost the name of an integrity-only change in a CRLF yarn.lock"; fi
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
# FULL-AUDIT Step 3.2's list of changed dependency files: the same flags and files as the first hint
stat_args() { tr -d '>\\' | tr -s ' \n' '\n\n' | grep -E -e "^--" -e "^'"; }
cl_hint 'changed manifests and lockfiles' | stat_args > "$T/stat-cl"
awk '/^  # Dependency changes since the baseline/ {g = 1} g && /git-ro\.sh" diff / {print} g && /requirements/ {exit}' "$FA" \
  | stat_args > "$T/stat-fa"
if [ -s "$T/stat-cl" ] && cmp -s "$T/stat-cl" "$T/stat-fa"; then ok "FULL-AUDIT Step 3.2 lists the same dependency files as §11.11"
else bad "FULL-AUDIT Step 3.2's dependency-change list differs from §11.11's"; diff "$T/stat-cl" "$T/stat-fa" | sed 's/^/  | /'; fi
# a go.mod edit (a require or replace line) need not change go.sum, so the list names go.mod too
run_hint 'changed manifests and lockfiles' "$T/stat.out"
if grep -q '^ go\.mod ' "$T/stat.out"; then ok "the changed-files hint lists a go.mod change"
else bad "the changed-files hint does not list a go.mod change"; sed 's/^/  | /' "$T/stat.out"; fi

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

# ---- 2. the known-bad release check ---------------------------------------------------------------------
kb_block "$FA" > "$T/kb-fa.sh"; kb_block "$KV077" > "$T/kb-kv.sh"; kb_tree "$KV077" > "$T/kbt-kv.sh"; kb_tree "$GC" > "$T/kbt-gc.sh"
sed "s#<auditor-skill root>#$ROOT#g" "$T/kb-fa.sh" > "$T/kb-run.sh"
if [ -s "$T/kb-fa.sh" ] && cmp -s "$T/kb-fa.sh" "$T/kb-kv.sh" && [ "$(wc -l < "$T/kbt-kv.sh" | tr -d ' ')" = 3 ] \
   && cmp -s "$T/kbt-kv.sh" "$T/kbt-gc.sh"; then
  ok "FULL-AUDIT Step 3.2, KV-077 Step 2 and discovery/grep-commands.md carry the same known-bad check"
else bad "the known-bad check differs between FULL-AUDIT Step 3.2, KV-077 Step 2 and discovery/grep-commands.md"; fi
run_kb() { ( cd "$1" && bash "$T/kb-run.sh" ) > "$T/kb.out" 2>&1; }
c() { git add -A && git commit -qm "$1" && git rev-parse --short HEAD; }

# single-line shapes and the key-line form in the hints fixture, at rev-head
run_kb "$H"
hc=$(git -C "$H" rev-parse --short rev-head)
for want in \
  './rez/package-lock.json:23:      "resolved": "https://registry.npmjs.org/@solana/web3.js/-/web3.js-1.95.6.tgz",' \
  './berry/yarn.lock:25:  resolution: "@solana/web3.js@npm:1.95.6"' \
  "./pnpm-lock.yaml:5:  '@solana/web3.js@1.95.6':" \
  './pnpm5/pnpm-lock.yaml:5:  /@solana/web3.js/1.95.6:' \
  './norez/package-lock.json-21-      "version": "1.95.6",' \
  './shrink/npm-shrinkwrap.json-21-      "version": "1.95.6",' \
  './v1/package-lock.json-12-      "version": "1.95.6",' \
  "$hc head" \
  "$hc b/norez/package-lock.json +      \"version\": \"1.95.6\"," \
  "$(printf '%s b/tabcrlf/package-lock.json +\t\t\t"version": "1.95.6",' "$hc")"; do
  if has "$T/kb.out" "$want"; then ok "known-bad check: $want"; else bad "known-bad check, missing: $want"; fi
done
if grep -q '^\./tabcrlf/package-lock\.json-[0-9]*-' "$T/kb.out"; then ok "known-bad check, tree: a tab-indented CRLF lockfile"
else bad "known-bad check, tree: the tab-indented CRLF lockfile is missed"; fi

# the key-line form in history: npm lockfiles without resolved fields, filler above 64 KiB, a merged side branch
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
git -C "$W" config log.diffMerges cc
run_kb "$W"
f=b/apps/web/package-lock.json
if grep -qx '\./apps/web/npm-shrinkwrap\.json-[0-9]*-      "version": "1\.95\.7",' "$T/kb.out"; then
  ok "known-bad check, tree: the alias entry in npm-shrinkwrap.json"
else bad "known-bad check, tree: the alias entry in npm-shrinkwrap.json is missing"; fi
for want in \
  "$C1 $f +      \"version\": \"1.95.6\"," \
  "$C2 $f -      \"version\": \"1.95.6\"," \
  "$C4 $f +      \"version\": \"1.95.7\"," \
  "$C5 $f -      \"version\": \"1.95.7\"," \
  "$C7 b/apps/web/npm-shrinkwrap.json +      \"version\": \"1.95.7\","; do
  if has "$T/kb.out" "$want"; then ok "known-bad check, key-line form: $want"; else bad "known-bad check, key-line form, missing: $want"; fi
done
if [ "$size" -gt 65536 ] && [ "$(grep -c '1\.95\.6' "$T/kb.out")" = 2 ]; then
  ok "known-bad check passes over filler and the decoy at 1.95.6 ($size-byte lockfile)"
else bad "known-bad check reports another package at 1.95.6, or the lockfile is under 64 KiB ($size bytes)"; sed 's/^/  | /' "$T/kb.out"; fi

# a key that changes beside an unchanged version line, and a deleted lockfile
git init -q "$T/w3k" && mkdir -p "$T/w3k/a" && printf '{\n  "packages": {\n    "node_modules/@solana/web3.js": {\n      "version": "1.95.6",\n      "integrity": "sha512-w"\n    }\n  }\n}\n' > "$T/w3k/a/package-lock.json" \
  && K1=$(cd "$T/w3k" && c add) \
  && printf '{\n  "packages": {\n    "node_modules/other": {\n      "version": "1.95.6",\n      "integrity": "sha512-w"\n    }\n  }\n}\n' > "$T/w3k/a/package-lock.json" \
  && K2=$(cd "$T/w3k" && c rename) && pl "$T/w3k/a/npm-shrinkwrap.json" 1.95.7 && K3=$(cd "$T/w3k" && c shrinkwrap) \
  && rm "$T/w3k/a/npm-shrinkwrap.json" && K4=$(cd "$T/w3k" && c drop)
run_kb "$T/w3k"
if grep -q "^$K2 b/a/package-lock.json  *\"version\": \"1.95.6\",$" "$T/kb.out" && grep -q "^$K1 " "$T/kb.out"; then
  ok "known-bad check, history: a commit that changes the key beside an unchanged version line"
else bad "known-bad check, history: the changed key is not reported"; sed 's/^/  | /' "$T/kb.out"; fi
if has "$T/kb.out" "$K4 a/a/npm-shrinkwrap.json -      \"version\": \"1.95.7\","; then
  ok "known-bad check, history: a commit that deletes the lockfile, under its a/ path"
else bad "known-bad check, history: the deleted lockfile is not reported under its a/ path"; sed 's/^/  | /' "$T/kb.out"; fi

# a version only a merge commit brings in (a lockfile regenerated while resolving a conflict), and a pnpm v5 key
M="$T/kbm"
git init -q -b main "$M" && mkdir -p "$M/app" && cd "$M" || exit 1
yl() { printf '"@solana/web3.js@^1.95.5":\n  version "%s"\n  resolved "https://registry.yarnpkg.com/@solana/web3.js/-/web3.js-%s.tgz#a"\n' "$1" "$1" > app/yarn.lock; }
yl 1.95.5; pl app/package-lock.json 1.95.5; echo a > app/x; c base > /dev/null
git checkout -qb feat && echo b > app/x && c feat > /dev/null && git checkout -q main && echo c > app/y && c main-y > /dev/null
git checkout -qb release && git merge -q --no-commit feat > /dev/null 2>&1; yl 1.95.6; pl app/package-lock.json 1.95.6
MM=$(c "merge feat") && git checkout -q main
printf 'lockfileVersion: 5.4\n\npackages:\n\n  /@solana/web3.js/1.95.7:\n    resolution: {integrity: sha512-p}\n' > app/pnpm-lock.yaml
M5=$(c pnpm5)
cd "$ROOT" || exit 1
git -C "$M" config log.diffMerges cc
run_kb "$M"
for want in "$MM merge feat" "$MM b/app/package-lock.json +      \"version\": \"1.95.6\"," "$M5 pnpm5"; do
  if has "$T/kb.out" "$want"; then ok "known-bad check, history: $want"; else bad "known-bad check, history, missing: $want"; fi
done

# axios 1.14.1 / 0.30.4 in every shape, beside packages that must not match
X="$T/ax"
git init -q -b main "$X" && cd "$X" && mkdir -p p1 p2 p3 p4 p5 p6 p7 p8 d1 d3 || exit 1
printf '{\n  "dependencies": {\n    "axios": "1.14.1"\n  }\n}\n' > p1/package.json
printf '{\n  "packages": {\n    "node_modules/axios": {\n      "version": "1.14.1",\n      "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz",\n      "integrity": "sha512-a"\n    }\n  }\n}\n' > p2/package-lock.json
ax3() { printf '{\n  "packages": {\n    "node_modules/axios": {\n      "version": "%s",\n      "integrity": "sha512-a"\n    },\n    "node_modules/@solana/web3.js": {\n      "version": "0.30.4",\n      "integrity": "sha512-w"\n    }\n  }\n}\n' "$1" > p3/package-lock.json; }
ax3 0.30.4
printf '{\n  "packages": {\n    "node_modules/my-axios": {\n      "name": "axios",\n      "version": "1.14.1",\n      "integrity": "sha512-a"\n    }\n  }\n}\n' > p4/npm-shrinkwrap.json
printf 'axios@^1.14.0:\n  version "1.14.1"\n  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz#abc"\n  integrity sha512-a\n' > p5/yarn.lock
printf '"axios@npm:^1.14.0":\n  version: 1.14.1\n  resolution: "axios@npm:1.14.1"\n  checksum: 10c0/abc\n' > p6/yarn.lock
printf 'packages:\n\n  axios@1.14.1:\n    resolution: {integrity: sha512-a}\n\n  /axios/0.30.4:\n    resolution: {integrity: sha512-b}\n' > p7/pnpm-lock.yaml
printf '{\n  "packages": {\n    "axios": ["axios@1.14.1", "", {}, "sha512-a"],\n  }\n}\n' > p8/bun.lock
printf '{\n  "packages": {\n    "node_modules/vue-axios": {\n      "version": "1.14.1",\n      "resolved": "https://registry.npmjs.org/vue-axios/-/vue-axios-1.14.1.tgz"\n    },\n    "node_modules/@nuxtjs/axios": {\n      "version": "0.30.4"\n    }\n  }\n}\n' > d1/package-lock.json
printf 'packages:\n\n  vue-axios@1.14.1:\n    resolution: {integrity: sha512-v}\n' > d1/pnpm-lock.yaml
printf '{\n  "packages": {\n    "node_modules/axios": {\n      "version": "1.14.2"\n    }\n  }\n}\n' > d3/package-lock.json
XA=$(c all) && ax3 0.30.5 && XB=$(c bump) && git checkout -q "$XA"
cd "$ROOT" || exit 1
run_kb "$X"
for want in \
  './p1/package.json:3:    "axios": "1.14.1"' \
  './p2/package-lock.json:5:      "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz",' \
  './p5/yarn.lock:3:  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz#abc"' \
  './p6/yarn.lock:3:  resolution: "axios@npm:1.14.1"' \
  './p7/pnpm-lock.yaml:3:  axios@1.14.1:' \
  './p7/pnpm-lock.yaml:6:  /axios/0.30.4:' \
  './p8/bun.lock:3:    "axios": ["axios@1.14.1", "", {}, "sha512-a"],' \
  './p3/package-lock.json-4-      "version": "0.30.4",' \
  './p4/npm-shrinkwrap.json-5-      "version": "1.14.1",' \
  "$XA all" \
  "$XA b/p4/npm-shrinkwrap.json +      \"version\": \"1.14.1\"," \
  "$XB b/p3/package-lock.json -      \"version\": \"0.30.4\","; do
  if has "$T/kb.out" "$want"; then ok "known-bad check, axios: $want"; else bad "known-bad check, axios, missing: $want"; fi
done
if ! grep -q -e '/d1/' -e '/d3/' -e ' b/d1/' -e ' b/d3/' "$T/kb.out" && [ "$(grep -c 'p3/package-lock' "$T/kb.out")" = 3 ]; then
  ok "known-bad check skips vue-axios, @nuxtjs/axios, axios 1.14.2 and @solana/web3.js at an axios version"
else bad "known-bad check reports a package it should skip"; sed 's/^/  | /' "$T/kb.out"; fi

# ---- 3. scratch-directory recipes -----------------------------------------------------------------------
kv_step "$KV089" 1 > "$T/kv1.sh"; kv_step "$KV089" 2 > "$T/kv2.sh"; kv_step "$KV089" 5 > "$T/kv5.sh"
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
scratch_case "KV-089 Step 1, mktemp fails" "$T/kv1.sh" "OUTCOME: no scratch copy (check TMPDIR)" TMPDIR="$T/missing"
mkdir -p "$T/tgt/rel" "$T/tgt/inside" "$T/tgt/tmpin" "$T/tgt/reltmp"
scratch_case "KV-089 Step 2, SCRATCH a relative path" "$T/kv2.sh" "OUTCOME: no scratch copy (run Step 1 first)" SCRATCH=rel \
  TMPDIR="$T/tmp"
scratch_case "KV-089 Step 5, SCRATCH inside the working directory" "$T/kv5.sh" "OUTCOME: no scratch copy (run Step 1 first)" \
  SCRATCH="$T/tgt/inside" TMPDIR="$T/tmp"
scratch_case "KV-089 Step 1, TMPDIR a relative path" "$T/kv1.sh" "OUTCOME: no scratch copy (check TMPDIR)" TMPDIR=reltmp
scratch_case "KV-089 Steps 1, 2 and 5 in one shell" "$T/kv125.sh" "" TMPDIR="$T/tmp"
# FULL-AUDIT Step 3.2: npm audit, cargo audit and the quarantine query run through deps.sh, and nothing in the
# step makes a scratch directory, changes directory or runs npm, cargo or rustup itself.
fa_step32 > "$T/fa32.txt"; grep -v '^ *#' "$T/fa32.txt" > "$T/fa32-code.txt"
deps=$(grep -cE '^"<auditor-skill root>/scripts/runner/deps\.sh" (npm-audit|cargo-audit|npm-time) --run audit_<n> ' "$T/fa32.txt")
if [ "$deps" = 4 ] && ! grep -qE 'SCRATCH|mktemp|(^|[ ;&|(])cd |^ *[(]?(npm|cargo|rustup) ' "$T/fa32-code.txt"; then
  ok "FULL-AUDIT Step 3.2 runs npm audit, cargo audit and the quarantine query through deps.sh, with no scratch block"
else bad "FULL-AUDIT Step 3.2: $deps deps.sh lines, or a scratch block or a plain npm, cargo or rustup call is left"; fi

# ---- 4. KV-137 Steps 1 and 2: upstream fetched into a git-ro.sh copy --------------------------------------
U="$T/kv137"
filler137() { # 400 upstream commits under programs/ with long subjects, so the log Step 2 cuts at 40 lines passes 64 KiB
  local i=1 pad
  pad=$(printf '%0200d' 0)
  while [ "$i" -le 400 ]; do
    printf 'commit refs/heads/trunk\ncommitter t <t@example.invalid> %s +0000\ndata <<EOT\nfiller %s %s\nEOT\n' \
      "$((1700000000 + i))" "$i" "$pad"
    if [ "$i" = 1 ]; then printf 'from refs/heads/trunk^0\n'; fi
    printf 'M 100644 inline programs/p/filler.rs\ndata <<EOT\n%s\nEOT\n\n' "$i"
    i=$((i + 1))
  done | git -C "$U/up" fast-import --quiet
}
git init -q -b trunk "$U/up" && mkdir -p "$U/up/programs/p" && echo v1 > "$U/up/programs/p/lib.rs" \
  && (cd "$U/up" && c v1 > /dev/null) && git clone -q "$U/up" "$U/client" && filler137 && git -C "$U/up" reset -q --hard \
  && echo fix > "$U/up/programs/p/fix.rs" && (cd "$U/up" && c "upstream security fix" > /dev/null) \
  && echo t > "$U/client/tenant" && (cd "$U/client" && c tenant > /dev/null) || exit 1
printf '#!/bin/sh\ntouch "%s/fired-$1"\n' "$U" > "$U/canary.sh" && chmod +x "$U/canary.sh"
git -C "$U/client" config core.fsmonitor "$U/canary.sh fsmonitor"
for h in post-checkout reference-transaction; do
  printf '#!/bin/sh\ntouch "%s/fired-%s"\n' "$U" "$h" > "$U/client/.git/hooks/$h"; chmod +x "$U/client/.git/hooks/$h"
done
# The upstream's https URL, which the test's git config rewrites to the local upstream, and a solana-verify stub
# that records its arguments, one per line.
URL=https://upstream.example.invalid/vendor/program
printf '[url "%s"]\n\tinsteadOf = %s\n' "$U/up" "$URL" > "$U/gitconfig"
mkdir -p "$U/bin" && printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s/verify-args"\n' "$U" > "$U/bin/solana-verify" \
  && chmod +x "$U/bin/solana-verify" || exit 1
refs_before=$(git -C "$U/client" for-each-ref | wc -l | tr -d ' ')
deployed=$(git -C "$U/up" rev-list --max-parents=0 HEAD)
logsize=$(git -C "$U/up" log --oneline "$deployed..HEAD" -- programs/ | wc -c | tr -d ' ')
step137() { # step137 UPSTREAM_REPO DEPLOYED: Step 2 up to its log line, placeholders filled, for a new run directory
  R137=$(cd "$U/client" && "$ROOT/scripts/rundir.sh" new audit) || { bad "rundir.sh new audit failed in the KV-137 fixture"; return 1; }
  awk '/^\*\*Step 2:/ {s = 1} s && !g && /^```$/ {g = 1; next} g {print} g && /FETCH_HEAD -- programs\/ \| head -40$/ {exit}' "$KV137" \
    | sed -e "s#<auditor-skill root>#$ROOT#g; s#<copy>#$R137/src.git#g; s#audit_<n>#$R137#g; s#<UPSTREAM_REPO>#$1#" \
          -e "s#<deployed_commit>#$2#; s#<PROGRAM_ID>#Prog1111#" > "$T/kv137.sh"
}
copy137() { [ -f "$U/client/$R137/src.git/auditor-copy" ]; }   # the run directory holds the copy git-ro.sh made
run137() { # run137 [env argument...]: run it in the checkout, the stub first on PATH, with no canary or record left
  rm -f "$U"/fired-* "$U/verify-args"
  ( cd "$U/client" && env "$@" GIT_CONFIG_GLOBAL="$U/gitconfig" PATH="$U/bin:$PATH" bash "$T/kv137.sh" ) \
    > "$T/kv137.out" 2>&1
}
fired() { ls "$U" | grep '^fired-'; }
NOFETCH='OUTCOME: upstream URL is not an https:// URL; not fetched'
mkdir -p "$T/tmp137" "$U/client/rel"

step137 "$URL" "$deployed"; run137 TMPDIR="$T/tmp137"
if grep -q ' upstream security fix$' "$T/kv137.out" && [ -z "$(fired)" ] && [ "$logsize" -gt 65536 ] \
   && [ "$(grep -cE '^[0-9a-f]{7,} (filler [0-9]+ 0+|upstream security fix)$' "$T/kv137.out")" = 40 ] \
   && [ "$(git -C "$U/client" for-each-ref | wc -l | tr -d ' ')" = "$refs_before" ] \
   && copy137 && [ -f "$U/client/$R137/src.git/FETCH_HEAD" ] \
   && [ "$(git --git-dir="$U/client/$R137/src.git" rev-parse --is-bare-repository)" = true ] \
   && [ "$(cat "$U/verify-args" 2>/dev/null)" = "$(printf 'verify-from-repo\n-um\n--program-id\nProg1111\n%s' "$URL")" ]; then
  ok "KV-137 Step 2 lists the fix on upstream's default branch, cut at 40 lines from a $logsize-byte log, from a bare copy in the run directory, gives solana-verify the URL as one argument, and leaves the checkout alone"
else bad "KV-137 Step 2 (log of $logsize bytes)"; sed 's/^/  | /' "$T/kv137.out"; fi
step137 "$URL" "$deployed"; run137 -u GIT_ALLOW_PROTOCOL TMPDIR="$T/tmp137"
if grep -q "transport 'file' not allowed" "$T/kv137.out" && ! grep -q ' upstream security fix$' "$T/kv137.out" \
   && copy137 && [ -z "$(fired)" ]; then
  ok "KV-137 Step 2 fetches over https only: git config that rewrites the URL to a local repository does not get it fetched"
else bad "KV-137 Step 2 fetched over a transport other than https"; sed 's/^/  | /' "$T/kv137.out"; fi
step137 "$URL" "$deployed"; run137 TMPDIR=rel
if has "$T/kv137.out" "git-ro: refused: the scratch directory (TMPDIR) lies inside the working directory" \
   && [ ! -e "$U/client/$R137/src.git" ] && ! grep -q ' upstream security fix$' "$T/kv137.out"; then
  ok "KV-137 Step 2 with a TMPDIR inside the working directory: git-ro.sh copy refuses, and nothing is fetched or read"
else bad "KV-137 Step 2 with a TMPDIR inside the working directory"; sed 's/^/  | /' "$T/kv137.out"; fi

# an option-shaped remote.upstream.url in the checkout's config: Step 1 prints it, and Step 2 gets it as written
opt="--upload-pack=touch $U/fired-upload-pack;:"
git -C "$U/client" config remote.upstream.url "$opt"
kv_step "$KV137" 1 | sed "s#<auditor-skill root>#$ROOT#g" > "$T/kv137-1.sh"; rm -f "$U"/fired-*
( cd "$U/client" && bash "$T/kv137-1.sh" ) > "$T/kv137-1.out" 2>&1
if has "$T/kv137-1.out" "$opt" && [ -z "$(fired)" ]; then ok "KV-137 Step 1 prints the checkout's remote.upstream.url as data"
else bad "KV-137 Step 1 with an option-shaped remote.upstream.url"; sed 's/^/  | /' "$T/kv137-1.out"; fi
step137 "$opt" "$deployed"; run137 TMPDIR="$T/tmp137"
if has "$T/kv137.out" "$NOFETCH" && [ -z "$(fired)" ] && [ ! -e "$U/verify-args" ] \
   && copy137 && [ ! -e "$U/client/$R137/src.git/FETCH_HEAD" ]; then
  ok "KV-137 Step 2 drops an option-shaped upstream URL: no canary fires, and neither solana-verify nor git runs on it"
else bad "KV-137 Step 2 with an option-shaped upstream URL"; fired | sed 's/^/  | fired: /'; sed 's/^/  | /' "$T/kv137.out"; fi
for v in "$U/up" "file://$U/up"; do
  case "$v" in file:*) what="a file:// URL" ;; *) what="a local path" ;; esac
  step137 "$v" "$deployed"; run137 TMPDIR="$T/tmp137"
  if has "$T/kv137.out" "$NOFETCH" && ! grep -q ' upstream security fix$' "$T/kv137.out" && [ ! -e "$U/verify-args" ]; then
    ok "KV-137 Step 2 fetches nothing from $what"
  else bad "KV-137 Step 2 used $what as the upstream"; sed 's/^/  | /' "$T/kv137.out"; fi
done
# an option-shaped deployed commit is refused before git reads it, never taken as a git log option
step137 "$URL" "--output=$U/fired-output"; run137 TMPDIR="$T/tmp137"
if [ -z "$(fired)" ] && ! grep -q ' upstream security fix$' "$T/kv137.out" \
   && grep -q '^git-ro: refused: log does not allow --output=' "$T/kv137.out" && [ -f "$U/client/$R137/src.git/FETCH_HEAD" ]; then
  ok "KV-137 Step 2 refuses an option-shaped deployed commit, and git never takes it as an option"
else bad "KV-137 Step 2 with an option-shaped deployed commit"; fired | sed 's/^/  | fired: /'; sed 's/^/  | /' "$T/kv137.out"; fi
# SC-054 names the fetch and log forms Step 2 runs
sc054=$(grep -F '**SC-054**' "$CL"); st137=$(kv_step "$KV137" 2); miss=
for w in '-c protocol.allow=never -c protocol.https.allow=always' 'fetch --no-tags --end-of-options "$UPSTREAM" HEAD' \
         'log --oneline --end-of-options <deployed' 'https://'; do
  case "$sc054" in *"$w"*) ;; *) miss="$miss SC-054:'$w'" ;; esac
  case "$st137" in *"$w"*) ;; *) miss="$miss Step-2:'$w'" ;; esac
done
if [ -z "$miss" ]; then ok "SC-054 names the https-only fetch and the log form KV-137 Step 2 runs"
else bad "SC-054 and KV-137 Step 2 differ, missing:$miss"; fi

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
