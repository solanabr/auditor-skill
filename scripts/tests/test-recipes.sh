#!/usr/bin/env bash
# test-recipes.sh — self-test for the bundled read recipes, scripts/recipes/lock-delta.sh and
# scripts/recipes/web3js-history.sh, against throwaway repositories:
#   - each runs directly by its path: #!/bin/bash, executable, and mode 100755 in the index;
#   - lock-delta.sh: the npm, bun and Cargo.lock lines that changed between two commits, with their package
#     names (a CRLF lockfile too); control characters as ?; --repo and --git-dir (a copy git-ro.sh copy made);
#     the notes for a partial and a shallow clone; git's status for a revision it cannot find; the same output
#     under a checkout config and attributes that set colour, context, inter-hunk context and prefixes and name
#     a textconv driver, an external diff, a pager and an fsmonitor hook, none of which runs; above 64 KiB,
#     whole, and cut early by head;
#   - web3js-history.sh: both headings and both searches; --repo and --git-dir; the notes; git's status for a
#     missing object, with both searches run; the same output under that config, decorations and a pretty
#     format too, with no program it names started;
#   - the case files fixtures/recipes/<tool>/cases.txt, under each bash on the machine (/bin/bash and the bash
#     running this suite, when they differ), which must print the same: each case exits as written with its
#     one stderr line, prints nothing on stdout, starts no program the fixture's config names and changes
#     nothing in the working directory.
# Usage (from the repo root): bash scripts/tests/test-recipes.sh
# Needs bash >= 3.2, git, awk, sed, grep, find, cmp. No network.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
LD="$ROOT/scripts/recipes/lock-delta.sh"
WH="$ROOT/scripts/recipes/web3js-history.sh"
GITRO="$ROOT/scripts/git-ro.sh"
RUNDIR="$ROOT/scripts/rundir.sh"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE CDPATH
T=$(mktemp -d "${TMPDIR:-/tmp}/recipes-test.XXXXXX") || exit 1
# A TMPDIR that ends in / (as on macOS) leaves // in $T; the checks compare physical paths.
T=$(cd "$T" && pwd -P) || exit 1
trap 'chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_AUTHOR_NAME=t \
  GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid

pass=0 fail=0 skip=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
ko()  { fail=$((fail + 1)); echo "FAIL - $1"; }
skp() { skip=$((skip + 1)); echo "skip - $1"; }
check() { # check <name> <command>...: on a failure, also show the last run
  if "${@:2}"; then ok "$1"; else
    ko "$1"; echo "#   status ${RC:-} stdout [$(head -c 3000 "$T/out" 2>/dev/null)] stderr [$(head -c 3000 "$T/err" 2>/dev/null)]"
  fi
}
has()  { grep -qxF -- "$2" "$1"; }   # has <file> <line>: <file> holds <line> exactly
same() { cmp -s "$1" "$2"; }
# run <dir> <script> [<arg>...]: the script run directly from <dir>, standard input closed; $T/out, $T/err, $RC.
run() { local d=$1 s=$2; shift 2; (cd "$d" && "$s" "$@") >"$T/out" 2>"$T/err" </dev/null; RC=$?; }
c() { git add -A && git commit -qm "$1" && git rev-parse --short HEAD; }   # c <subject>: commit all, print its short id

# A program the hostile config names: it leaves $T/fired-<name> and copies the file git names (a textconv
# driver's input), or standard input when git names none (a pager's).
printf '#!/bin/sh\ntouch "%s/fired-$1"\nexec cat "${2:--}"\n' "$T" > "$T/canary" && chmod +x "$T/canary" || exit 1
fired() { find "$T" -maxdepth 1 -name 'fired-*' -print; }
# hostile <repo>: settings that change how git prints a diff or a log, attributes that mark lockfiles -diff and
# send them to a textconv driver, and config that names programs for git to start.
hostile() {
  local r=$1 k v
  while IFS='=' read -r k v; do
    git -C "$r" config "$k" "$v" || return 1
  done <<EOF
core.pager=$T/canary pager
core.fsmonitor=$T/canary fsmonitor
diff.external=$T/canary external
diff.lock.textconv=$T/canary textconv
diff.lock.command=$T/canary command
gpg.program=$T/canary gpg
log.showSignature=true
color.ui=always
color.diff=always
diff.context=0
diff.interHunkContext=20
diff.noprefix=true
diff.srcPrefix=X/
diff.dstPrefix=Y/
diff.mnemonicPrefix=true
log.decorate=full
format.pretty=%H %an
core.attributesFile=$T/attrs
EOF
  printf '* diff=lock\n' > "$T/attrs"
  mkdir -p "$r/.git/info" && printf '*.lock diff=lock\n*.json diff=lock\n*.json -diff\n' >> "$r/.git/info/attributes"
}

# =================================================================================================
# The entry points
# =================================================================================================
for s in "$LD" "$WH"; do
  n=${s#"$ROOT/"}
  check "$n starts with #!/bin/bash" test "$(sed -n 1p "$s" 2>/dev/null)" = '#!/bin/bash'
  check "$n is executable" test -x "$s"
  if mode=$(git -C "$ROOT" ls-files -s -- "$n" 2>/dev/null) && [ -n "$mode" ]; then
    check "$n is mode 100755 in the index" test "${mode%% *}" = 100755
  else skp "$n: not in a git index here"; fi
done

# =================================================================================================
# lock-delta.sh
# =================================================================================================
H="$T/h"
npm_lock() { # npm_lock <version> <integrity> [crlf]: a package-lock.json of one package
  local nl='\n'
  [ "${3:-}" = crlf ] && nl='\r\n'
  printf "{${nl}  \"name\": \"app\",${nl}  \"lockfileVersion\": 3,${nl}  \"packages\": {${nl}"
  printf "    \"node_modules/left-pad\": {${nl}      \"version\": \"%s\",${nl}" "$1"
  printf "      \"resolved\": \"https://registry.npmjs.org/left-pad/-/left-pad-%s.tgz\",${nl}" "$1"
  printf "      \"integrity\": \"sha512-%s\"${nl}    }${nl}  }${nl}}${nl}" "$2"
}
lock_files() { # lock_files <version> <integrity> <cargo version> <checksum>: every lockfile of the fixture
  npm_lock "$1" "$2" > npm/package-lock.json && npm_lock "$1" "$2" crlf > crlf/package-lock.json \
    && printf '{\n  "packages": {\n    "node_modules/x": {\n      "version": "%s\033[2J\007"\n    }\n  }\n}\n' "$1" \
         > ctl/package-lock.json \
    && printf '{\n  "lockfileVersion": 1,\n  "packages": {\n    "left-pad": ["left-pad@%s", "", {}, "sha512-%s"],\n  }\n}\n' \
         "$1" "$2" > bun/bun.lock \
    && printf '# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = "anchor-lang"\nversion = "%s"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%s"\n' \
         "$3" "$4" > cargo/Cargo.lock
}
git init -q "$H" && mkdir -p "$H/npm" "$H/crlf" "$H/ctl" "$H/bun" "$H/cargo" && cd "$H" \
  && lock_files 1.3.0 AAAA 0.30.1 aaaa && c base >/dev/null && git tag t-base \
  && lock_files 1.3.1 BBBB 0.31.0 bbbb && c head >/dev/null && git tag t-head || { echo "could not build the lock-delta fixture" >&2; exit 1; }
cd "$ROOT" || exit 1

run "$H" "$LD" npm t-base..t-head; cp "$T/out" "$T/npm.plain"
for want in \
  '+++ b/npm/package-lock.json' \
  '"node_modules/left-pad" -      "version": "1.3.0",' \
  '"node_modules/left-pad" -      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",' \
  '"node_modules/left-pad" -      "integrity": "sha512-AAAA"' \
  '"node_modules/left-pad" +      "version": "1.3.1",' \
  '"node_modules/left-pad" +      "integrity": "sha512-BBBB"' \
  '+++ b/crlf/package-lock.json' \
  '+++ b/ctl/package-lock.json' \
  '"node_modules/x" +      "version": "1.3.1?[2J?"'; do
  check "lock-delta npm prints: $want" has "$T/npm.plain" "$want"
done
check "lock-delta npm: exit 0, nothing on stderr" test "$RC" = 0 -a ! -s "$T/err"
check "lock-delta npm: a CRLF lockfile prints its lines without the CR" \
  test "$(grep -c '^"node_modules/left-pad" [-+]      "version": "1\.3\.[01]",$' "$T/npm.plain")" = 4
check "lock-delta npm: no control character reaches the output" test -z "$(LC_ALL=C tr -d '\n\t -~' < "$T/npm.plain")"
run "$H" "$LD" bun t-base..t-head
printf '%s\n' '+++ b/bun/bun.lock' '- left-pad@1.3.0' '+ left-pad@1.3.1' > "$T/bun.want"
check "lock-delta bun: each changed entry as name@version" sh -c "[ '$RC' = 0 ] && cmp -s '$T/bun.want' '$T/out'"
run "$H" "$LD" cargo t-base..t-head; cp "$T/out" "$T/cargo.plain"
printf '%s\n' '+++ b/cargo/Cargo.lock' '"anchor-lang" -version = "0.30.1"' '"anchor-lang" +version = "0.31.0"' \
  '"anchor-lang" -checksum = "aaaa"' '"anchor-lang" +checksum = "bbbb"' > "$T/cargo.want"
check "lock-delta cargo: each changed line after its package name" sh -c "[ '$RC' = 0 ] && cmp -s '$T/cargo.want' '$T/out'"
run "$H" "$LD" npm t-base..nosuch
check "lock-delta: a revision git cannot find gives git's status (128) and its fatal: line" \
  sh -c "[ '$RC' = 128 ] && grep -q '^fatal: ' '$T/err' && [ ! -s '$T/out' ]"
run "$H" "$LD" npm t-head..t-base
check "lock-delta: the range read the other way round prints the change the other way round" \
  has "$T/out" '"node_modules/left-pad" +      "version": "1.3.0",'

# --repo: a repository below the working directory, at its own top level
git init -q "$H/sub" && mkdir -p "$H/sub/web" && (cd "$H/sub" && npm_lock 2.0.0 CCCC > web/package-lock.json && c one >/dev/null \
  && git tag one && npm_lock 2.0.1 DDDD > web/package-lock.json && c two >/dev/null && git tag two) || exit 1
run "$H" "$LD" --repo sub npm one..two
check "lock-delta --repo: reads that repository" \
  sh -c "[ '$RC' = 0 ] && grep -qxF '+++ b/web/package-lock.json' '$T/out' && ! grep -q 'npm/package-lock' '$T/out'"

# the hostile config: the same lines, and none of the programs it names runs
hostile "$H" || exit 1
rm -f "$T"/fired-*
run "$H" "$LD" npm t-base..t-head; cp "$T/out" "$T/npm.hostile"; cp "$T/err" "$T/npm.hostile.err"
run "$H" "$LD" cargo t-base..t-head; cp "$T/out" "$T/cargo.hostile"
check "lock-delta: the same npm and cargo lines under the checkout's colour, context, prefix and attribute settings" \
  sh -c "cmp -s '$T/npm.plain' '$T/npm.hostile' && cmp -s '$T/cargo.plain' '$T/cargo.hostile' && [ ! -s '$T/npm.hostile.err' ]"
check "lock-delta: no pager, fsmonitor hook, textconv driver or external diff the config names ran" test -z "$(fired)"
# the control: plain git on the same repository runs them and prints the lines in another shape
(cd "$H" && git diff t-base..t-head -- npm/package-lock.json) > "$T/ctl.out" 2>&1 </dev/null
(cd "$H" && git log -p -1 t-head -- cargo/Cargo.lock) >> "$T/ctl.out" 2>&1 </dev/null
check "control: plain git diff and log -p there start the external diff and the textconv driver" \
  sh -c "[ -n \"\$(find '$T' -maxdepth 1 \\( -name fired-external -o -name fired-textconv \\) -print)\" ]"
rm -f "$T"/fired-*

# --git-dir: a copy git-ro.sh copy made in a run directory
A=$(cd "$H" && "$RUNDIR" new audit) || { ko "rundir.sh new audit failed in the lock-delta fixture"; A=""; }
if [ -n "$A" ]; then
  (cd "$H" && "$GITRO" copy . "$A") >"$T/copy.out" 2>"$T/copy.err"; crc=$?
  if [ "$crc" = 0 ]; then
    run "$H" "$LD" --git-dir "$(cat "$T/copy.out")" npm t-base..t-head
    check "lock-delta --git-dir: the copy prints the same lines as the checkout" same "$T/out" "$T/npm.plain"
  elif [ "$crc" = 69 ]; then
    if [ "${CI:-}" = true ]; then ko "git-ro.sh copy needs git with the May-2024 clone fixes, and CI has none"
    else skp "lock-delta --git-dir: this git lacks the May-2024 clone fixes, so git-ro.sh copy refuses"; fi
  else ko "git-ro.sh copy failed in the lock-delta fixture: $(cat "$T/copy.err")"; fi
fi

# a partial clone and a shallow clone: a note on stderr first
P="$T/partial"
git clone -q --no-local "$H" "$P" && git -C "$P" config core.repositoryformatversion 1 \
  && git -C "$P" config extensions.partialClone origin && git -C "$P" config remote.origin.promisor true || exit 1
run "$P" "$LD" npm origin/HEAD~1..origin/HEAD
check "lock-delta: a partial clone prints its note first, and the diff still runs" \
  sh -c "[ '$RC' = 0 ] && [ \"\$(sed -n 1p '$T/err')\" = 'lock-delta: partial clone: missing objects are not fetched; history and contents may be incomplete (Rule 11c)' ] && grep -qxF '+++ b/npm/package-lock.json' '$T/out'"
S="$T/shallow"
git clone -q --depth 1 "file://$H" "$S" && [ -f "$S/.git/shallow" ] || { echo "could not make a shallow clone" >&2; exit 1; }
run "$S" "$LD" cargo HEAD..HEAD
check "lock-delta: a shallow clone prints its note, and a range inside the history it holds runs" \
  sh -c "[ '$RC' = 0 ] && grep -qxF 'lock-delta: shallow clone: history before the shallow boundary is missing (Rule 11c)' '$T/err'"

# above 64 KiB: every changed line of a large lockfile, and a reader that stops after the first line
L="$T/large"
big_lock() { # big_lock <version>: 3000 packages
  printf '{\n  "packages": {\n'
  i=0; while [ "$i" -lt 3000 ]; do
    printf '    "node_modules/pkg-%s": {\n      "version": "%s",\n      "integrity": "sha512-x%s"\n    },\n' "$i" "$1" "$i"
    i=$((i + 1)); done
  printf '    "": {}\n  }\n}\n'
}
git init -q "$L" && (cd "$L" && big_lock 1.0.0 > package-lock.json && c one >/dev/null && git tag one \
  && big_lock 1.0.1 > package-lock.json && c two >/dev/null && git tag two) || exit 1
run "$L" "$LD" npm one..two
check "lock-delta: a lockfile diff above 64 KiB prints every changed line ($(wc -c < "$T/out" | tr -d ' ') bytes)" \
  sh -c "[ '$RC' = 0 ] && [ \$(wc -c < '$T/out') -gt 65536 ] && [ \"\$(grep -c '^\"node_modules/pkg-[0-9]*\" +      \"version\": \"1\\.0\\.1\",\$' '$T/out')\" = 3000 ] && grep -qxF '\"node_modules/pkg-2999\" +      \"version\": \"1.0.1\",' '$T/out'"
first=$(cd "$L" && "$LD" npm one..two 2>/dev/null </dev/null | sed -n 1p)   # sed reads to the end
check "lock-delta: its output read to the end by sed starts with the file's +++ line" test "$first" = '+++ b/package-lock.json'
first=$(cd "$L" && "$LD" npm one..two 2>/dev/null </dev/null | head -n 1)   # pipefail-ok: head stops the reader early on purpose
check "lock-delta: a reader that stops after the first line ends the run with that line" test "$first" = '+++ b/package-lock.json'

# =================================================================================================
# web3js-history.sh
# =================================================================================================
X="$T/w3"
w3_files() { # w3_files <version>: a package-lock.json without resolved fields and a yarn.lock
  printf '{\n  "packages": {\n    "node_modules/@solana/web3.js": {\n      "version": "%s",\n      "integrity": "sha512-w"\n    }\n  }\n}\n' "$1" \
    > app/package-lock.json
  printf '"@solana/web3.js@^1.95.5":\n  version "%s"\n  resolved "https://registry.yarnpkg.com/@solana/web3.js/-/web3.js-%s.tgz#a"\n' "$1" "$1" \
    > app/yarn.lock
}
git init -q "$X" && mkdir -p "$X/app" "$X/p" && cd "$X" && w3_files 1.95.5 && X1=$(c base) && w3_files 1.95.6 && X2=$(c bump) \
  && printf '{\n  "dependencies": {\n    "axios": "1.14.1"\n  }\n}\n' > p/package.json && X3=$(c "$(printf 'axios\033[31m')") \
  && w3_files 1.95.5 && X4=$(c revert) || { echo "could not build the web3js-history fixture" >&2; exit 1; }
cd "$ROOT" || exit 1
H1='== single-line form: <commit> <subject> of each commit that adds or removes a known-bad release'
H2='== key-line form: <commit> <file> <line> of each version line under a known-bad entry'
printf '%s\n' "$H1" "$X4 revert" "$X3 axios?[31m" "$X2 bump" "$H2" \
  "$X4 b/app/package-lock.json -      \"version\": \"1.95.6\"," "$X2 b/app/package-lock.json +      \"version\": \"1.95.6\"," > "$T/w3.want"
run "$X" "$WH"; cp "$T/out" "$T/w3.plain"
check "web3js-history: both headings, the commits of the single-line form, then the key-line form's lines" \
  sh -c "[ '$RC' = 0 ] && [ ! -s '$T/err' ] && cmp -s '$T/w3.want' '$T/w3.plain'"
check "web3js-history: the base commit, at a release that is not known-bad, is not reported" \
  sh -c "! grep -q '^$X1 ' '$T/w3.plain'"
run "$X" "$WH" --repo .
check "web3js-history --repo .: the same as no --repo" same "$T/out" "$T/w3.plain"
M="$T/w3missing"
cp -R "$X" "$M" || exit 1   # a copy that keeps the loose objects, before the hostile config

hostile "$X" || exit 1
rm -f "$T"/fired-*
run "$X" "$WH"
check "web3js-history: the same lines under the checkout's colour, context, prefix, decoration, pretty-format and attribute settings" \
  sh -c "cmp -s '$T/w3.plain' '$T/out' && [ ! -s '$T/err' ]"
check "web3js-history: no pager, fsmonitor hook, textconv driver, external diff or signature program the config names ran" \
  test -z "$(fired)"
(cd "$X" && git log -p -2 -- app/yarn.lock) > "$T/ctl.out" 2>&1 </dev/null
check "control: plain git log -p there starts the configured diff programs" \
  sh -c "[ -n \"\$(find '$T' -maxdepth 1 -name 'fired-*' -print)\" ]"
rm -f "$T"/fired-*

A=$(cd "$X" && "$RUNDIR" new audit) || { ko "rundir.sh new audit failed in the web3js-history fixture"; A=""; }
if [ -n "$A" ]; then
  (cd "$X" && "$GITRO" copy . "$A") >"$T/copy.out" 2>"$T/copy.err"; crc=$?
  if [ "$crc" = 0 ]; then
    run "$X" "$WH" --git-dir "$(cat "$T/copy.out")"
    check "web3js-history --git-dir: the copy prints the same as the checkout" same "$T/out" "$T/w3.plain"
  elif [ "$crc" = 69 ]; then
    if [ "${CI:-}" = true ]; then ko "git-ro.sh copy needs git with the May-2024 clone fixes, and CI has none"
    else skp "web3js-history --git-dir: this git lacks the May-2024 clone fixes, so git-ro.sh copy refuses"; fi
  else ko "git-ro.sh copy failed in the web3js-history fixture: $(cat "$T/copy.err")"; fi
fi

# a missing object: git fails (its status and its fatal: line), and both searches still run
blob=$(git -C "$M" rev-parse "$X2:app/package-lock.json") && obj="$M/.git/objects/${blob%"${blob#??}"}/${blob#??}"
if [ -f "$obj" ]; then
  rm -f "$obj"
  run "$M" "$WH"
  check "web3js-history: a missing object gives git's status and a fatal: line, under both headings" \
    sh -c "[ '$RC' != 0 ] && [ '$RC' != 64 ] && grep -q 'fatal: ' '$T/err' && grep -qxF '$H1' '$T/out' && grep -qxF '$H2' '$T/out'"
else skp "web3js-history, missing object: the clone holds no loose object to remove"; fi

run "$P" "$WH"
check "web3js-history: a partial clone prints its note first" \
  test "$(sed -n 1p "$T/err")" = 'web3js-history: partial clone: missing objects are not fetched; history and contents may be incomplete (Rule 11c)'
run "$S" "$WH"
check "web3js-history: a shallow clone prints its note" \
  has "$T/err" 'web3js-history: shallow clone: history before the shallow boundary is missing (Rule 11c)'

# =================================================================================================
# The case files, under each bash on the machine.
# =================================================================================================
SHELLS=("$BASH")
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then
  SHELLS+=(/bin/bash)
fi
echo "# shells: ${SHELLS[*]}"
CW="$T/cases-wt"
git init -q "$CW" && mkdir -p "$CW/programs/p" "$CW/notes" "$CW/notarun" && echo x > "$CW/a.rs" \
  && echo y > "$CW/programs/p/lib.rs" && (cd "$CW" && c base >/dev/null) && hostile "$CW" \
  && (cd "$CW" && "$RUNDIR" new audit >/dev/null) && ln -s audit_1 "$CW/audit_2" && ln -s . "$CW/link" \
  || { ko "could not build the case fixture"; exit 1; }
tree() { (cd "$1" && find . -path ./.git -prune -o -print | LC_ALL=C sort); }
tree "$CW" > "$T/ctree.before"; rm -f "$T"/fired-*
for tool in lock-delta web3js-history; do
  cases="$ROOT/scripts/tests/fixtures/recipes/$tool/cases.txt"
  ncase=0
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    want_rc=${line%%$'\t'*}
    rest=${line#*$'\t'}
    want_err=${rest%%$'\t'*}
    args=()
    case "$rest" in *$'\t'*) rest=${rest#*$'\t'}; IFS=$'\t' read -r -a args <<< "$rest" ;; esac
    ncase=$((ncase + 1))
    i=0
    for sh in "${SHELLS[@]}"; do
      (cd "$CW" && "$sh" "$ROOT/scripts/recipes/$tool.sh" ${args[@]+"${args[@]}"}) >"$T/out" 2>"$T/err" </dev/null
      RC=$?
      if [ "$RC" = "$want_rc" ] && [ "$(cat "$T/err")" = "$want_err" ] && [ ! -s "$T/out" ]; then
        [ "$i" -gt 0 ] || ok "case: $tool.sh $(printf '%s\n' "${args[*]+"${args[*]}"}" | cut -c1-120 | tr -d '\033')"
      else
        ko "case ($sh): $tool.sh $(printf '%s\n' "${args[*]+"${args[*]}"}" | cut -c1-120 | tr -d '\033') -> status $RC, stderr: $(head -c 400 "$T/err")"
      fi
      i=$((i + 1))
    done
  done < "$cases"
  check "the $tool case file has cases ($ncase)" test "$ncase" -gt 25
done
tree "$CW" > "$T/ctree.after"
check "no case changed anything in the working directory" cmp -s "$T/ctree.before" "$T/ctree.after"
check "no case started a program the fixture's config names" test -z "$(fired)"

echo
echo "recipes tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
