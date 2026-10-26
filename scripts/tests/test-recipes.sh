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

# =================================================================================================
# The corpus. Every code line and code span of FULL-AUDIT.md, checklists/, known-vectors/, discovery/,
# references/ and templates/ that starts with "<auditor-skill root>/scripts/..." is one plain command, the form a
# command's rule pre-approves: the quoted path first, no $ or backtick anywhere (a $ stops a rule from
# matching, quoted or not), no &&, || or ;, and a pipe only into grep, head, tail, sort, uniq, cut or wc. No code
# line runs a bundled script any other way (bash, cd or an assignment in front, or inside $( )). The calls of
# git-ro.sh, the recipes, the runners, rpc-read.sh and rundir.sh then run as written, their placeholders
# filled, in a fixture with no cargo, npm, curl or solana on PATH: git-ro.sh, the recipes and rundir.sh do
# their work, and each runner reaches the blocker it gives when its tool or the recorded mode is missing, so
# none is refused.
# =================================================================================================
FORMS="$T/forms.tsv"
python3 -I - "$ROOT" "$FORMS" > "$T/forms.err" 2>&1 <<'PY'
import os, re, shlex, sys

root, out = sys.argv[1], sys.argv[2]
os.chdir(root)
files = ["FULL-AUDIT.md"]
for d in ("checklists", "known-vectors", "discovery"):
    files += sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith(".md"))
for d in ("references", "templates"):
    for dp, dn, fn in sorted(os.walk(d)):
        files += sorted(os.path.join(dp, f) for f in fn if f.endswith(".md"))
Q = '"<auditor-skill root>/scripts/'
RUN = ("git-ro.sh", "recipes/", "runner/deps.sh", "runner/target.sh", "rpc-read.sh", "rundir.sh")
READERS = {"grep", "head", "tail", "sort", "uniq", "cut", "wc"}
FILL = [("<auditor-skill root>", root), ("audit_<n>", "audit_1"), ("incident_<n>", "incident_1"),
        ("incident_<k>", "incident_1"), ("<base>..<head>", "t-base..t-head"), ("<baseline>..HEAD", "t-base..HEAD"),
        ("<PROGRAM_ID>", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        ("<address>", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
        ("<signature>", "5h6xBEauJ3PK6SWCZ1PGjBvj8vDdWG3KpwATGy1ARAXFSDwt8GFXM7W5Ncn16wmqokgpiKRLuS83KUxyZyv2sUYv"),
        ("crates|npm|pypi", "npm"), ("<pkg>", "left-pad"), ("<ver>", "1.3.0"), ("<crate>", "anchor-lang"),
        ("<package>", "left-pad"), ("<version>", "1.3.0"), ("<rev>:<path>", "t-head:package.json"),
        ("<checkout>", "."), ("<repo>", "."), ("<copy>", "audit_1/src.git"), ("<deployed_commit>", "t-base"), ("<deployed>", "t-base"),
        ("{PATH_TO}", "audit_1"), ("{COMMIT}", "t-head"), ("{FINDING_ID}", "F-1"), ("<R>", "audit_1"),
        ("<ID>", "F-1"), ("<in-scope directory>", "."), ("<dir>", ".")]
# Spans that show a call's shape with optional parts, not a call to run.
SHAPES = {"\"<auditor-skill root>/scripts/git-ro.sh\" [--repo '<dir>'] show <full id> -- '<path>'"}
bad = []
rows = []
def form(f, n, cmd, code):
    if "$" in cmd or "`" in cmd:
        bad.append(f"{f}:{n}: holds a $ or a backtick: {cmd}")
        return
    filled = cmd
    for a, b in FILL:
        filled = filled.replace(a, b)
    # A placeholder left (a call's shape) is one word for the check of operators below.
    shape = re.sub(r"<[A-Za-z][^<>]*>", "PLACEHOLDER", filled)
    try:
        lex = shlex.shlex(shape, posix=True, punctuation_chars=True)
        lex.commenters = "#"
        toks = list(lex)
    except ValueError as e:
        bad.append(f"{f}:{n}: cannot be read as shell words ({e}): {cmd}")
        return
    parts, cur = [], []
    for t in toks:
        if t in ("&&", "||", ";", "&", ";;", "|&", ">", ">>", "<", "2>", ">&"):
            bad.append(f"{f}:{n}: {t} in a pre-approved call: {cmd}")
            return
        if t == "|":
            parts.append(cur); cur = []
        else:
            cur.append(t)
    parts.append(cur)
    for p in parts[1:]:
        if not p or p[0] not in READERS:
            bad.append(f"{f}:{n}: a pipe into {p[0] if p else 'nothing'}, not a read-only reader: {cmd}")
            return
    tool = parts[0][0].split("/scripts/", 1)[1] if "/scripts/" in parts[0][0] else ""
    # A code line is a call; a code span with no argument names the script in prose.
    run = (code or len(parts[0]) > 1) and any(tool.startswith(r) for r in RUN) and cmd not in SHAPES
    if run and (re.search(r"<[A-Za-z][^>]*>", filled) or re.search(r"\{[A-Z_]+\}", filled)):
        bad.append(f"{f}:{n}: a placeholder this test cannot fill: {cmd}")
        return
    rows.append((f, str(n), tool, "run" if run else "form", filled))
for f in files:
    fence = False
    for n, line in enumerate(open(f, encoding="utf-8"), 1):
        body = re.sub(r"^(> ?)+", "", line.rstrip("\n"))
        if body.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            s = body.lstrip()
            if s.startswith(Q):
                form(f, n, s, True)
            elif "<auditor-skill root>/scripts/" in s and not s.startswith("#"):
                bad.append(f"{f}:{n}: a bundled script run other than by its quoted path first: {s}")
        else:
            for m in re.finditer(r"`([^`]*)`", body):
                if m.group(1).startswith(Q):
                    form(f, n, m.group(1), False)
with open(out, "w", encoding="utf-8") as o:
    for r in rows:
        o.write("\t".join(r) + "\n")
for b in bad:
    print(b)
sys.exit(1 if bad else 0)
PY
prc=$?
check "every rooted bundled call in the corpus is one plain command (no \$, no &&, ; or ||, pipes into readers only)" \
  sh -c "[ '$prc' = 0 ] && [ -s '$FORMS' ]"
[ "$prc" = 0 ] || sed 's/^/#   /' "$T/forms.err"
nform=$(grep -c . "$FORMS" 2>/dev/null); nrun=$(grep -c "	run	" "$FORMS" 2>/dev/null)
check "the corpus holds rooted calls to check ($nform, $nrun of them run below)" test "${nrun:-0}" -gt 40

# The fixture they run in: a repository with the manifests and lockfiles the calls name, tags t-base and t-head,
# a run directory of each kind with a patch, a git-ro.sh copy holding a FETCH_HEAD, and a PATH with git and the
# basic tools but no cargo, npm, curl or solana.
F="$T/forms-wt"
git init -q "$F" && mkdir -p "$F/apps/backend" "$F/apps/web" "$F/programs/p/src" && cd "$F" \
  && for d in . apps/backend apps/web; do printf '{"name": "x", "version": "1.0.0"}\n' > "$d/package.json"; \
       npm_lock 1.3.0 AAAA > "$d/package-lock.json"; done \
  && printf '[package]\nname = "p"\nversion = "0.1.0"\n' > Cargo.toml \
  && printf '# lock\nversion = 3\n\n[[package]]\nname = "p"\nversion = "0.1.0"\n' > Cargo.lock \
  && echo 'pub fn f() {}' > programs/p/src/lib.rs && c base >/dev/null && git tag t-base \
  && npm_lock 1.3.1 BBBB > package-lock.json && c head >/dev/null && git tag t-head \
  && git config remote.upstream.url https://upstream.example.invalid/vendor/program \
  && "$RUNDIR" new audit >/dev/null && "$RUNDIR" new incident >/dev/null && mkdir -p audit_1/patches \
  && printf 'diff --git a/x b/x\n' > audit_1/patches/F-1.patch || { ko "could not build the corpus fixture"; }
# git-ro.sh copy needs git with the May-2024 clone fixes (exit 69 otherwise): without them the calls that make or
# read a copy are skipped with a note, and fail on CI.
"$GITRO" copy . audit_1 >/dev/null 2>&1; crc=$?
if [ "$crc" = 0 ]; then git rev-parse t-head > audit_1/src.git/FETCH_HEAD || ko "could not give the corpus fixture's copy a FETCH_HEAD"
elif [ "$crc" != 69 ]; then ko "git-ro.sh copy failed in the corpus fixture (status $crc)"; fi
cd "$ROOT" || exit 1
MP="$T/minpath"; mkdir -p "$MP"
for t in bash sh env git find grep sed awk tr wc od cat sort uniq head tail cut mkdir mktemp rm rmdir chmod cp ln \
         mv date python3 sleep ls dirname basename readlink stat touch id uname kill printf; do
  p=$(type -P "$t" 2>/dev/null) && ln -s "$p" "$MP/$t"
done
nok=0 ncopy=0
while IFS=$'\t' read -r f n tool how cmd; do
  [ "$how" = run ] || continue
  case "$crc:$cmd" in
    69:*" copy "*|69:*" --git-dir "*)
      if [ "${CI:-}" = true ]; then ko "$f:$n: needs git-ro.sh copy, and this git lacks the May-2024 clone fixes"
      else ncopy=$((ncopy + 1)); nok=$((nok + 1)); fi
      continue ;;
  esac
  (cd "$F" && env -i HOME="$T/home" PATH="$MP" TMPDIR="$T" RPC_URL=https://rpc.example.invalid/ LC_ALL=C \
    "$MP/bash" -c "$cmd"$'\n''exit "${PIPESTATUS[0]}"') >"$T/out" 2>"$T/err" </dev/null
  RC=$?   # the bundled tool's own status, not that of a reader it pipes into
  case "$tool" in
    git-ro.sh) good=""; case "$RC" in 0|1|141) grep -q -e 'refused:' -e '^fatal:' "$T/err" || good=y ;; esac ;;
    recipes/*|rundir.sh) good=$( [ "$RC" = 0 ] && ! grep -q 'refused:' "$T/err" && echo y) ;;
    runner/deps.sh) good=$( [ "$RC" = 3 ] && grep -q '^deps: blocker: .* is not on PATH' "$T/err" && echo y) ;;
    runner/target.sh) good=$( [ "$RC" = 3 ] && grep -q '^target: blocker: no recorded mode' "$T/err" && echo y) ;;
    rpc-read.sh) good=$( [ "$RC" = 3 ] && grep -q '^\[blocker\] solana CLI not on PATH' "$T/err" && echo y) ;;
    *) good="" ;;
  esac
  if [ -n "$good" ]; then nok=$((nok + 1)); else
    ko "$f:$n: the call does not run as written (status $RC): $(printf '%s' "$cmd" | cut -c1-200) — $(head -c 300 "$T/err")"
  fi
done < "$FORMS"
[ "$ncopy" = 0 ] || skp "$ncopy calls that make or read a git-ro.sh copy: this git lacks the May-2024 clone fixes"
check "every rooted call of git-ro.sh, the recipes, the runners, rpc-read.sh and rundir.sh runs as written ($nok)" \
  test "$nok" = "${nrun:-x}"

# Plain git: no code line of these files runs git itself, and the Rule 11c prefix is left only where the text
# says what a tool runs, except the calls listed here, each of which says why it asks for approval.
python3 -I - "$ROOT" > "$T/plain-git.txt" 2>&1 <<'PY'
import os, re, sys

os.chdir(sys.argv[1])
files = ["FULL-AUDIT.md"]
for d in ("checklists", "known-vectors", "discovery"):
    files += sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith(".md"))
for d in ("references", "templates"):
    for dp, dn, fn in sorted(os.walk(d)):
        files += sorted(os.path.join(dp, f) for f in fn if f.endswith(".md"))
# (file, text): a call that asks, and why
KEEP = [
    # KV-137 Step 2: the upstream fetch, whose URL is chosen at run time
    ("known-vectors/137-vendored-program-version-drift.md",
     'git --git-dir=<copy> -c protocol.allow=never -c protocol.https.allow=always fetch --no-tags --end-of-options "$UPSTREAM" HEAD'),
    # form A of a patch file, from a fix commit
    ("templates/patch/patch.md", "git format-patch -1 <fix-commit> --stdout > {FINDING_ID}.patch"),
    # §4: the clone the Trail of Bits runner works in
    ("templates/patch/VERIFICATION.md",
     'GIT_NO_LAZY_FETCH=1 git clone -q --no-local --no-checkout --template= "$PPV_SRC" "$PPV/repo" &&'),
    # §1: the scratch worktree rebuild
    ("templates/patch/VERIFICATION.md", 'GIT_NO_LAZY_FETCH=1 git clone --no-local {CHECKOUT} "$SCRATCH/copy" &&'),
    ("templates/patch/VERIFICATION.md", 'git -C "$SCRATCH/copy" worktree add "$SCRATCH/fix" {COMMIT} &&'),
    ("templates/patch/VERIFICATION.md", "git apply {PATH_TO}/{FINDING_ID}.patch &&"),
]
# (file, text): prose that names the prefix as part of what a tool runs, or a call that asks
PROSE = [
    ("FULL-AUDIT.md", "(the Rule 11d check, `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false --icase-pathspecs ls-files -- .audit-memory`, run by the tool)"),
    ("references/orchestration/pre-scan.md", "as `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false --icase-pathspecs ls-files -- .audit-memory` would show"),
    ("references/detection-response/README.md", "`GIT_NO_LAZY_FETCH=1 git clone --no-local <checkout> <scratch copy>` and read with"),
    ("references/detection-response/README.md", "`GIT_NO_LAZY_FETCH=1 git -C <scratch copy> --no-pager -c core.fsmonitor=false -c log.showSignature=false show --no-textconv --no-ext-diff <rev>:<path>`,"),
    ("templates/patch/VERIFICATION.md", "copy you made yourself, `GIT_NO_LAZY_FETCH=1 git clone --no-local <checkout> <scratch copy>` (Rule 11c),"),
]
def bare(line):  # the line without its comment, and with each quoted string emptied
    out, q, esc = [], None, False
    for i, ch in enumerate(line):
        if q == '"' and esc: esc = False
        elif q == '"' and ch == "\\": esc = True
        elif q:
            if ch == q: q = None; out.append(ch)
        elif ch in "'\"": q = ch; out.append(ch)
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"): break
        else: out.append(ch)
    return "".join(out)
def uncomment(line):
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q: q = None
        elif ch in "'\"": q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"): return line[:i]
    return line
GIT = re.compile(r"(?:^|[|;&(]|\b(?:then|do|else|if)\s)\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*git\s")
seen, bad = set(), []
for f in files:
    code = False
    for n, line in enumerate(open(f, encoding="utf-8"), 1):
        if line.lstrip().startswith("```"):
            code = not code
            continue
        text = line.strip()
        if code and GIT.search(bare(line)):
            k = (f, uncomment(line).strip())
            if k in KEEP: seen.add(k)
            else: bad.append(f"{f}:{n}: runs git itself: {text[:160]}")
        elif "GIT_NO_LAZY_FETCH=1 git" in line:
            hit = [p for p in PROSE if p[0] == f and p[1] in line]
            if hit: seen.update(hit)
            else: bad.append(f"{f}:{n}: names the Rule 11c prefix as a recipe: {text[:160]}")
for k in KEEP + PROSE:
    if k not in seen: bad.append(f"{k[0]}: the listed text is gone, so the list needs updating: {k[1][:120]}")
print("\n".join(bad))
sys.exit(1 if bad else 0)
PY
if [ "$?" = 0 ]; then ok "no corpus recipe runs plain git, and the Rule 11c prefix is left only in the listed text"
else ko "a corpus recipe runs plain git, or the Rule 11c prefix is left outside the listed text"; sed 's/^/#   /' "$T/plain-git.txt" | cut -c1-220; fi

# Calls that ask: a code line that runs a tool no command pre-approves (npm, cargo, curl, dig, gh, uv, plain git
# and the like) sits in a step whose text says it asks for approval: the step's own lines, from its heading or
# its bold **Step** line through the paragraph after the block. The fixes a developer runs on their own machine
# (build-and-tooling.md) are no audit step.
python3 -I - "$ROOT" > "$T/asks.txt" 2>&1 <<'PY'
import os, re, sys

os.chdir(sys.argv[1])
files = ["FULL-AUDIT.md"]
for d in ("checklists", "known-vectors", "discovery"):
    files += sorted(os.path.join(d, f) for f in os.listdir(d) if f.endswith(".md"))
for d in ("references", "templates"):
    for dp, dn, fn in sorted(os.walk(d)):
        files += sorted(os.path.join(dp, f) for f in fn if f.endswith(".md"))
files.remove("references/framework-idioms/build-and-tooling.md")
# (file, text): code lines that run nothing, or that a change elsewhere replaces
NOT_STEPS = [
    ("templates/audit-report.md", "node / npm:     {version}"),
    # VERIFICATION.md §1's scratch worktree rebuild
    ("templates/patch/VERIFICATION.md", 'GIT_NO_LAZY_FETCH=1 git clone --no-local {CHECKOUT} "$SCRATCH/copy" &&  # the Rule 11c copy'),
    ("templates/patch/VERIFICATION.md", 'git -C "$SCRATCH/copy" worktree add "$SCRATCH/fix" {COMMIT} &&  # the audited commit the patch targets'),
    ("templates/patch/VERIFICATION.md", "git apply {PATH_TO}/{FINDING_ID}.patch &&                       # or: git am < ... for format-patch"),
    ("templates/patch/VERIFICATION.md", "cargo build-sbf --tools-version v1.54                           # rebuild the patched program"),
]
TOOLS = ("npm|npx|yarn|pnpm|bun|node|cargo|anchor|solana|solana-verify|solana-keygen|rustup|avm|pip|pip-audit|safety|"
         "bandit|uv|curl|wget|dig|nslookup|whois|openssl|gh|aws|gsutil|gcloud|az|docker|git")
ENV = r"(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:env(?:\s+-u\s+\S+)*\s+(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*)?"
CALL = re.compile(r"(?:^|[|;&(]|\b(?:then|do|else|if)\s)\s*" + ENV + r"(" + TOOLS + r")(?=\s|$)")
ASKS = re.compile(r"asks? for approval", re.I)
SHELL = {"", "bash", "sh", "shell", "console", "zsh"}
def bare(line):  # the line without its comment, and with each quoted string emptied
    out, q, esc = [], None, False
    for i, ch in enumerate(line):
        if q == '"' and esc: esc = False
        elif q == '"' and ch == "\\": esc = True
        elif q:
            if ch == q: q = None; out.append(ch)
        elif ch in "'\"": q = ch; out.append(ch)
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"): break
        else: out.append(ch)
    return "".join(out)
def text(line):
    return line[2:] if line.startswith("> ") else ("" if line == ">" else line)
bad, seen = [], set()
for f in files:
    lines = [text(l.rstrip("\n")) for l in open(f, encoding="utf-8")]
    fence, start = [], 0
    for i, l in enumerate(lines):
        if l.lstrip().startswith("```"):
            fence.append(i)
    heads = [i for i, l in enumerate(lines) if (l.startswith("#") or l.lstrip().startswith("**Step")) and
             sum(1 for x in fence if x < i) % 2 == 0]
    for a, b in zip(fence[0::2], fence[1::2]):
        if lines[a].lstrip()[3:].strip().lower() not in SHELL:
            continue
        top = max([h for h in heads if h < a], default=-1) + 1
        end = b + 1
        while end < len(lines) and not lines[end].strip(): end += 1
        while end < len(lines) and lines[end].strip() and not lines[end].lstrip().startswith("```"): end += 1
        context = "\n".join(lines[top:end])
        for n in range(a + 1, b):
            m = CALL.search(bare(lines[n]))
            if not m:
                continue
            k = (f, lines[n].strip())
            if k in NOT_STEPS:
                seen.add(k)
            elif not ASKS.search(context):
                bad.append(f"{f}:{n + 1}: runs {m.group(1)}, and its step does not say it asks for approval: {lines[n].strip()[:120]}")
for k in NOT_STEPS:
    if k not in seen: bad.append(f"{k[0]}: the listed line is gone, so the list needs updating: {k[1][:100]}")
print("\n".join(bad))
sys.exit(1 if bad else 0)
PY
if [ "$?" = 0 ]; then ok "every corpus call of a tool no command pre-approves sits in a step that says it asks for approval"
else ko "a corpus call of a tool no command pre-approves sits in a step that does not say it asks for approval"; sed 's/^/#   /' "$T/asks.txt" | cut -c1-220; fi

# Above 64 KiB: each corpus call of git-ro.sh that pipes into head, run as written over a history of 400 commits
# whose matching output passes 64 KiB, prints its head's lines and ends.
B="$T/big-history"
git init -q "$B" && git -C "$B" symbolic-ref HEAD refs/heads/big || exit 1
pad=$(printf '%0180d' 0)
arr=$(i=0; while [ "$i" -lt 64 ]; do printf '%s,' "$((i * 3))"; i=$((i + 1)); done)
i=1
while [ "$i" -le 400 ]; do
  printf 'commit refs/heads/big\ncommitter t <t@example.invalid> %s +0000\ndata <<EOT\nsecret private fixture %s %s\nEOT\n' \
    "$((1700000000 + i))" "$i" "$pad"
  printf 'M 100644 inline programs/p/k%s.rs\ndata <<EOT\n// %s BEGIN RSA PRIVATE BEGIN EC PRIVATE mnemonic sk_live PRIVATE_KEY private secret %s\nEOT\n' "$i" "$i" "$pad"
  printf 'M 100644 inline keys/k%s.json\ndata <<EOT\n{"k": [%s1], "note": "BEGIN RSA PRIVATE mnemonic %s"}\nEOT\n' "$i" "$arr" "$i"
  printf 'M 100644 inline src/k%s.ts\ndata <<EOT\nconst mnemonic = "%s %s";\nEOT\n\n' "$i" "$i" "$pad"
  i=$((i + 1))
done | git -C "$B" fast-import --quiet || exit 1
git -C "$B" tag t-base big~399 && git -C "$B" tag t-head big && (cd "$B" && "$RUNDIR" new audit >/dev/null) || exit 1
(cd "$B" && "$GITRO" copy . audit_1 >/dev/null 2>&1); bcrc=$?
if [ "$bcrc" = 0 ]; then git -C "$B" rev-parse t-head > "$B/audit_1/src.git/FETCH_HEAD" || exit 1
elif [ "$bcrc" != 69 ]; then ko "git-ro.sh copy failed in the large history (status $bcrc)"; fi
nbig=0 nbigcopy=0
while IFS=$'\t' read -r f n tool how cmd; do
  [ "$tool:$how" = git-ro.sh:run ] || continue
  case "$cmd" in *' | head -'[0-9]*) ;; *) continue ;; esac
  case "$bcrc:$cmd" in
    69:*" copy "*|69:*" --git-dir "*)
      if [ "${CI:-}" = true ]; then ko "$f:$n: needs git-ro.sh copy, and this git lacks the May-2024 clone fixes"
      else nbigcopy=$((nbigcopy + 1)); nbig=$((nbig + 1)); fi
      continue ;;
  esac
  want=$(printf '%s\n' "$cmd" | sed -n 's/.* | head -\([0-9][0-9]*\).*/\1/p')
  producer=${cmd%%' | head -'*}
  size=$( (cd "$B" && bash -c "$producer" </dev/null 2>/dev/null) | wc -c | tr -d ' ')
  got=$( (cd "$B" && bash -c "$cmd" </dev/null 2>/dev/null) | wc -l | tr -d ' ')
  nbig=$((nbig + 1))
  check "$f:$n: over $size bytes, the call ends with its head's $want lines" sh -c "[ '$size' -gt 65536 ] && [ '$got' = '$want' ]"
done < "$FORMS"
[ "$nbigcopy" = 0 ] || skp "$nbigcopy large-history calls that read a git-ro.sh copy: this git lacks the May-2024 clone fixes"
check "the corpus has git-ro.sh calls that pipe into head ($nbig)" test "$nbig" -gt 8
echo
echo "recipes tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
