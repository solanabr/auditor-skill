#!/bin/bash
# deps.sh — dependency audits and registry queries for the audit (checklist 11; OUTPUT-RULES.md Rules 11a and
# 11b), on copies of the manifests and lockfiles, with every host fixed in code. It runs no code from the
# working directory, so it needs no execution mode.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/runner/deps.sh" <action> --run <R> [--manifest <path>]... [--no-fetch] [<word>...]
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under
# audit. A refusal is one stderr line, "deps: refused: <reason>", with exit 64, before anything is copied or
# sent; a blocker is one stderr line, "deps: blocker: <reason>", with exit 3.
#
# The actions:
#   cargo-audit     --manifest <dir>/Cargo.lock [--no-fetch]: cargo audit --color never. The advisory
#                   database comes from GitHub (RustSec) into CARGO_HOME, and cargo audit asks the crates.io
#                   index which releases were yanked. A lockfile that names a registry other than crates.io,
#                   which a check for yanked releases could ask, or that deps.sh cannot read (an escape cargo
#                   never writes, text that is not UTF-8), stops the run in strict mode (OUTPUT-RULES.md Rule
#                   11f); otherwise cargo audit runs with --no-yanked, and a note says so. With --no-fetch it
#                   adds --no-fetch --no-yanked: the database already in CARGO_HOME, and nothing leaves the
#                   machine.
#   cargo-outdated  --manifest <dir>/Cargo.toml, more Cargo.toml files of the workspace, and at most one
#                   Cargo.lock beside the first: cargo outdated --workspace --exit-code 1 --color never
#   cargo-tree      the same manifests: cargo tree --workspace --color never
#   npm-audit       --manifest <dir>/package.json and --manifest <dir>/package-lock.json (or
#                   npm-shrinkwrap.json): npm audit
#   npm-view        <package> [<version>]: the npm registry's record of that version, the latest without one
#   npm-time        <package>: the publish time of each version of the package
#   crate-info      <crate> [<version>]: crates.io's record of the crate, or of that version
#   pypi-info       <project> [<version>]: PyPI's record of the project, or of that version
#   fetch-artifact  crates|npm|pypi <package> <version>: the published artifact (a .crate, the npm tarball,
#                   or the sdist, else a pure-Python wheel), its digest checked against the registry's
#                   (crates.io's sha256 checksum, npm's sha512 integrity, PyPI's sha256; npm's legacy sha1
#                   shasum only when the version has no integrity, and the output then says it is weak),
#                   unpacked without running anything
#                   into <R>/deps/fetch-artifact-<n>/files/ next to the artifact itself (checklist 11 §11.11).
#                   Only regular files and directories are unpacked, with modes 0600 and 0700; every other
#                   entry, and every name that is absolute, has a .. component or a control character, is
#                   left out and listed, as an SC-060 hit. At most 50000 entries and 512 MiB unpacked; a
#                   tar with more than 4 MiB of pax and GNU long-name headers, more than 8 of them in a
#                   row, more than 128 bytes of global pax headers, a sparse file or a size below zero,
#                   compressed with anything but gzip, bzip2 or xz (zstd), or in an xz stream whose
#                   decompressor would need more than 128 MiB, and a zip whose central directory takes
#                   more than 16 MiB or with an entry compressed with anything but deflate, are refused.
#   lock-budget     <R>/deps/lock-set-<n>.tsv: the CI budget of checklist 11 §11.11 over a set that
#                   scripts/recipes/lock-delta.sh set wrote, in one run. First the publish age: one request
#                   for each distinct name of the set from a public registry (the npm registry's record of the
#                   package, the crate's entry in the crates.io index at index.crates.io, PyPI's record of the
#                   project), in the budget's order, at most 8 at a time, 1000 requests and 300 seconds; a
#                   lookup that still fails after one retry, the rest past those bounds and a version with no
#                   publish time are "not checked", which fails nothing. For each new version: its publish
#                   time, its publisher (for a crate, from crates.io's record, one request a second, asked
#                   only for the crates the budget selects) and the publishers of earlier versions, flagging
#                   one under 14 days old, a first release under 14 days old, a publisher that published no
#                   earlier version (a person to "GitHub Actions", trusted publishing, apart, at low
#                   severity), a yanked version and one the registry does not list (a package it has no record
#                   of included). AUDITOR_PUBLISH_AGE=off (the default is on) leaves this out. Then the
#                   budget: each key handler (lock-delta.sh's key mark) whose version changed, first and
#                   outside the budget, then at most 40 of the other npm and crates rows whose version
#                   changed, in this order: direct dependencies, pins, install scripts, versions under 14
#                   days, sources now on the public registry; PyPI rows and the rest are metadata only. Each
#                   entry's new and old artifacts are fetched as fetch-artifact fetches one, its digest
#                   checked before it is kept, with one retry (none for an artifact past a bound), at most 50
#                   MB a download and 500 MB unpacked in the whole call (one past either counts as failed, and
#                   once the 500 MB is spent no later artifact is asked for), into
#                   <R>/deps/lock-budget-<n>/<k>/new and old, and compared: the files added, changed and
#                   removed, the added lines matched against SC-059's and SC-060's patterns, binary files and
#                   entries left out of the unpacked files, counts first. The sweep reads a line at a time and
#                   keeps an old file's lines as hashes when it is at most 2 MB; in a newer copy of a larger
#                   one every line counts as added. A row from a source that is not public is never sent or
#                   fetched, and a scoped npm package the public registry does not list (a 404) is taken as
#                   private: never fetched, reported, and no failure; a registry set outside the repository is
#                   not seen, as the output says. The report goes to <R>/deps/lock-budget-<n>.txt, the publish
#                   ages to lock-budget-<n>/ages.tsv and each request to lock-budget-<n>/requests.txt. Exit 1
#                   when anything is flagged; 3 when an artifact the budget selects is not fetched, or an
#                   entry is not compared in time, once the rest are compared, the last line giving the
#                   counts. The whole call ends by 540 seconds, or AUDITOR_RUN_TIMEOUT when that is less,
#                   inside the 600 a Bash tool call may take: its requests, unpacking and sweep stop 10
#                   seconds before that end, so its report is written in time, and an entry it has not
#                   compared by then counts as failed.
#
# Manifests. Each --manifest is a confined regular file of at most 50 MB under the working directory, named
# as its action takes it: Cargo.lock, Cargo.toml, package.json, package-lock.json or npm-shrinkwrap.json,
# never .npmrc, .yarnrc*, rust-toolchain* or anything under a .cargo directory. Only these files are
# copied, each at the path it has under the working directory, into a scratch directory outside it. cargo
# reads no manifest without a target, so cargo-outdated and cargo-tree put an empty file at src/lib.rs and
# at each target path a copied package manifest names, then read it with cargo metadata --no-deps --offline
# (which resolves and fetches nothing) and rebuild, in a second scratch directory, a workspace of only the
# names, versions, editions, features and dependency entries metadata reports. cargo tree and cargo outdated
# run on the rebuilt workspace, never on the copy, so no [patch], [replace] or other table of the copy
# reaches the resolving cargo, whatever its spelling, and the reported tree is the un-patched one. A
# dependency from git or from a registry other than crates.io, and a path dependency on a non-member, stop
# the run (cargo would fetch from a host the manifest chose); so does a workspace member outside the
# workspace root's directory (cargo takes one that names the root with package.workspace), since the rebuild
# keeps every file it writes under its scratch directory; cargo is told to fetch git sources with the git
# CLI, and the git on its PATH refuses every fetch. A plainly spelled [patch.<registry>] or [replace] table
# runs, with a note on stderr and in the output naming the crates it patches (the reported tree leaves them
# unpatched). As a second line, a manifest spelled as no Cargo.toml needs stops the run: a [patch] or
# [replace] table header with a quoted first key or as an array of tables, a table header with a \u, \U or
# \x escape, or anything before the first table header but comments and a one-line cargo-features; and so
# does a copied Cargo.lock with such an escape. A lockfile's git or other-registry sources and its
# [[patch.unused]] entries do not stop the run: cargo resolves the rebuilt workspace from crates.io and
# fetches none of them. The first Cargo.toml is the one cargo runs on. npm-audit runs npm with its own .npmrc in the
# copy (registry https://registry.npmjs.org/, ignore-scripts, no fund or update notices), empty user and
# global config files, and its cache and logs in the scratch directory: no auth reaches it. Where npm is
# Corepack's shim, COREPACK_ENABLE_PROJECT_SPEC=0 keeps the copied package.json's packageManager field from
# choosing which npm release runs.
#
# Names. npm: [@<scope>/]<name>, of letters, digits and -._~, not starting with . or _, at most 214
# bytes; crates: a letter, then letters, digits, - and _, at most 64; PyPI: letters, digits and -._,
# starting and ending with a letter or digit, at most 100. Versions: <n>.<n>.<n>, with an optional
# -<pre-release> and +<build>, for npm and crates; for PyPI, a digit, then digits, letters and .!+_-.
#
# Hosts. registry.npmjs.org; crates.io, index.crates.io and static.crates.io; pypi.org, and the
# files.pythonhosted.org URLs PyPI's record names; github.com, for the RustSec database. Registry queries
# run curl -q (no .curlrc), https only, with no redirects and at most 100 MiB. Before the first request to
# each service, one row goes to <R>/disclosures.tsv: time, tool, service, what was sent, and a count;
# lock-budget writes one row per service for its whole run, naming the set.
#
# Environment. Every tool runs in the cleaned environment of scripts/lib/isolation.sh: env -i, a throwaway
# HOME, TMPDIR in the scratch directory, the cleaned PATH, the user's CARGO_HOME and RUSTUP_HOME, and the
# proxy variables, since none of these tools runs code from the copies. cargo runs with RUSTUP_TOOLCHAIN
# pinned to the caller's value, else rustup's default, read in the scratch directory. AUDITOR_RUN_TIMEOUT
# (whole seconds, 1 to 86400, default 1800) bounds the run: each step runs under the watchdog of
# isolation.sh's iso_watch.
#
# Output: <R>/deps/<action>-<n>.txt, the tool's output (stdout and stderr) or the registry's answer, and
# the last stdout line says how the action ended. The scratch directory is removed on exit.
#
# Exit: 0 done, nothing found · 1 findings: vulnerabilities (cargo-audit, npm-audit), outdated dependencies
# (cargo-outdated), or a package or version the registry does not have (npm-view, npm-time, crate-info,
# pypi-info, fetch-artifact) · 3 blocker (a tool missing, a download or query that failed, a digest that
# does not match, the watchdog) · 64 refused. Needs bash >= 3.2, python3, env, find, grep, mkdir, mktemp,
# rm, chmod, cat, wc and date; cargo, cargo-audit, cargo-outdated, npm or curl as the action needs.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'deps: refused: the installation cannot be resolved\n' >&2; exit 64; }
case "$here" in
  */scripts/runner) root=${here%/scripts/runner} ;;
  *) printf 'deps: refused: deps.sh runs from <auditor-skill root>/scripts/runner\n' >&2; exit 64 ;;
esac
. "$root/scripts/lib/confine.sh" || { printf 'deps: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
. "$root/scripts/lib/isolation.sh" || { printf 'deps: refused: scripts/lib/isolation.sh cannot be read\n' >&2; exit 64; }
# confine.sh's own notes (an AUDITOR_STRICT value read as on) print as deps.sh's do, on stdout, so stderr holds
# only the blocker or refusal.
confine_note() { printf '>> note: %s\n' "$1"; }
confine_init deps "$root"
confine_need env git find grep mkdir mktemp rm chmod cat wc date
WT=$CONFINE_WT

USAGE='usage: deps.sh <action> --run <R> [--manifest <path>]... [--no-fetch] [<word>...], with the actions cargo-audit, cargo-outdated, cargo-tree, npm-audit, npm-view, npm-time, crate-info, pypi-info, fetch-artifact and lock-budget'
TOOL=scripts/runner/deps.sh
NPM_SPEC='^(@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$'
CRATE_SPEC='^[A-Za-z][A-Za-z0-9_-]{0,63}$'
PYPI_SPEC='^[A-Za-z0-9]([A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$'
SEMVER_SPEC='^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})(-[0-9A-Za-z.-]{1,64})?(\+[0-9A-Za-z.-]{1,64})?$'
PEP440_SPEC='^[0-9][0-9A-Za-z.!+_-]{0,63}$'
MANIFEST_SIZE=52428800
GET_MAX=104857600
UA='auditor-skill deps.sh (https://github.com/solanabr/auditor-skill)'

refuse() { confine_refuse "$1"; }
blocker() { printf 'deps: blocker: %s\n' "$1" >&2; exit 3; }

# ---- arguments (all checked before anything is copied or sent) ----------------------------------------
[ $# -gt 0 ] || refuse "$USAGE"
ACTION=$1
shift
case "$ACTION" in
  cargo-audit|cargo-outdated|cargo-tree|npm-audit|npm-view|npm-time|crate-info|pypi-info|fetch-artifact|lock-budget) ;;
  *) refuse "$USAGE" ;;
esac
RUN_ARG="" NO_FETCH=0 seen=" "
MANIFESTS=()
POS=()
while [ $# -gt 0 ]; do
  w=$1
  shift
  case "$w" in
    --run)
      [ $# -gt 0 ] || refuse "--run needs a value"
      case "$seen" in *" --run "*) refuse "give --run once" ;; esac
      seen="$seen--run "
      RUN_ARG=$1
      shift ;;
    --manifest)
      [ $# -gt 0 ] || refuse "--manifest needs a value"
      [ "${#MANIFESTS[@]}" -lt 256 ] || refuse "more than 256 --manifest files"
      MANIFESTS+=("$1")
      shift ;;
    --no-fetch)
      [ "$NO_FETCH" = 0 ] || refuse "give --no-fetch once"
      NO_FETCH=1 ;;
    -*) refuse "$(confine_text "$w") is not an argument deps.sh takes ($USAGE)" ;;
    *)
      [ "${#POS[@]}" -lt 3 ] || refuse "$ACTION takes no more words: $(confine_text "$w")"
      POS+=("$w") ;;
  esac
done
case "$seen" in *" --run "*) ;; *) refuse "give --run <R>, the run directory ($USAGE)" ;; esac
confine_rundir "$RUN_ARG" "--run"
R=$CONFINE_RUN
[ "$NO_FETCH" = 0 ] || [ "$ACTION" = cargo-audit ] || refuse "--no-fetch is for cargo-audit"

# The manifests: confined regular files of the names the action takes, each once, at most 50 MB.
MAN=()
case "$ACTION" in
  cargo-audit) TAKES='Cargo.lock' ;;
  cargo-outdated|cargo-tree) TAKES='Cargo.toml Cargo.lock' ;;
  npm-audit) TAKES='package.json package-lock.json npm-shrinkwrap.json' ;;
  *) TAKES='' ;;
esac
NAMES=${TAKES// /, }
case "$NAMES" in *", "*) NAMES="${NAMES%, *} or ${NAMES##*, }" ;; esac
if [ "${#MANIFESTS[@]}" -gt 0 ]; then
  [ -n "$TAKES" ] || refuse "$ACTION takes no --manifest"
  for m in "${MANIFESTS[@]}"; do
    confine_path "$m" "--manifest" any
    rel=$CONFINE_REL
    base=${rel##*/}
    case " $TAKES " in *" $base "*) ;; *) refuse "--manifest for $ACTION takes a file named $NAMES, not $(confine_text "$m")" ;; esac
    case "/$rel" in */[.][Cc][Aa][Rr][Gg][Oo]/*) refuse "--manifest is under a .cargo directory: $(confine_text "$m")" ;; esac
    [ "$CONFINE_TYPE" = file ] || refuse "--manifest is not an existing regular file: $(confine_text "$m")"
    [ -z "$(find "$WT/$rel" -prune -size +"${MANIFEST_SIZE}"c -print 2>/dev/null)" ] ||
      refuse "--manifest is larger than 50 MB: $(confine_text "$m")"
    for d in ${MAN[@]+"${MAN[@]}"}; do
      [ "$d" != "$rel" ] || refuse "--manifest names $(confine_text "$rel") twice"
    done
    MAN+=("$rel")
  done
fi
dir_of() { case "$1" in */*) printf '%s' "${1%/*}" ;; *) printf '.' ;; esac; }
TOML="" LOCK=""
case "$ACTION" in
  cargo-audit)
    [ "${#MAN[@]}" = 1 ] || refuse "cargo-audit takes one --manifest, a Cargo.lock"
    LOCK=${MAN[0]} ;;
  cargo-outdated|cargo-tree)
    for rel in ${MAN[@]+"${MAN[@]}"}; do
      case "$rel" in
        Cargo.lock|*/Cargo.lock) [ -z "$LOCK" ] || refuse "$ACTION takes at most one Cargo.lock"; LOCK=$rel ;;
        *) [ -n "$TOML" ] || TOML=$rel ;;
      esac
    done
    [ -n "$TOML" ] || refuse "$ACTION takes --manifest <dir>/Cargo.toml, the one cargo runs on, first"
    [ -z "$LOCK" ] || [ "$(dir_of "$LOCK")" = "$(dir_of "$TOML")" ] ||
      refuse "the Cargo.lock goes beside the first Cargo.toml, $(confine_text "$TOML")" ;;
  npm-audit)
    [ "${#MAN[@]}" = 2 ] || refuse "npm-audit takes two --manifest files: package.json and package-lock.json (or npm-shrinkwrap.json)"
    for rel in "${MAN[@]}"; do
      case "${rel##*/}" in package.json) TOML=$rel ;; *) LOCK=$rel ;; esac
    done
    [ -n "$TOML" ] && [ -n "$LOCK" ] || refuse "npm-audit takes package.json and package-lock.json (or npm-shrinkwrap.json)"
    [ "$(dir_of "$LOCK")" = "$(dir_of "$TOML")" ] || refuse "package.json and its lockfile must sit in one directory" ;;
esac

# The words: names and versions, checked against each ecosystem's grammar.
NAME="" VER="" ECO=""
npm_name() {
  [[ "$1" =~ $NPM_SPEC ]] && [ "${#1}" -le 214 ] || refuse "an npm package name is [@<scope>/]<name>, of letters, digits and -._~, at most 214 bytes, not $(confine_text "$1")"
}
crate_name() {
  [[ "$1" =~ $CRATE_SPEC ]] || refuse "a crate name is a letter, then letters, digits, - and _, at most 64, not $(confine_text "$1")"
}
pypi_name() {
  [[ "$1" =~ $PYPI_SPEC ]] || refuse "a PyPI project name is letters, digits and -._, starting and ending with a letter or digit, at most 100, not $(confine_text "$1")"
}
semver() {
  [[ "$1" =~ $SEMVER_SPEC ]] || refuse "a version is <n>.<n>.<n>, with an optional -<pre-release> and +<build>, not $(confine_text "$1")"
}
pep440() {
  [[ "$1" =~ $PEP440_SPEC ]] || refuse "a PyPI version is a digit, then digits, letters and .!+_-, at most 64, not $(confine_text "$1")"
}
n=${#POS[@]}
case "$ACTION" in
  cargo-audit|cargo-outdated|cargo-tree|npm-audit)
    [ "$n" = 0 ] || refuse "$ACTION takes no package name: $(confine_text "${POS[0]}")" ;;
  npm-view|crate-info|pypi-info)
    [ "$n" -ge 1 ] && [ "$n" -le 2 ] || refuse "$ACTION takes <package> [<version>]"
    NAME=${POS[0]}
    [ "$n" = 1 ] || VER=${POS[1]}
    case "$ACTION" in
      npm-view) npm_name "$NAME"; [ -z "$VER" ] || semver "$VER" ;;
      crate-info) crate_name "$NAME"; [ -z "$VER" ] || semver "$VER" ;;
      pypi-info) pypi_name "$NAME"; [ -z "$VER" ] || pep440 "$VER" ;;
    esac ;;
  npm-time)
    [ "$n" = 1 ] || refuse "npm-time takes one package name"
    NAME=${POS[0]}
    npm_name "$NAME" ;;
  fetch-artifact)
    [ "$n" = 3 ] || refuse "fetch-artifact takes crates|npm|pypi, a package name and a version"
    ECO=${POS[0]} NAME=${POS[1]} VER=${POS[2]}
    case "$ECO" in
      crates) crate_name "$NAME"; semver "$VER" ;;
      npm) npm_name "$NAME"; semver "$VER" ;;
      pypi) pypi_name "$NAME"; pep440 "$VER" ;;
      *) refuse "fetch-artifact takes crates, npm or pypi, not $(confine_text "$ECO")" ;;
    esac ;;
  lock-budget)
    [ "$n" = 1 ] || refuse "lock-budget takes one word: the set lock-delta.sh set wrote, <R>/deps/lock-set-<n>.tsv"
    SETF=${POS[0]#./}
    case "$SETF" in
      "$R"/deps/lock-set-[1-9]*.tsv) k=${SETF#"$R"/deps/lock-set-}; k=${k%.tsv} ;;
      *) k=x ;;
    esac
    case "$k" in ''|*[!0-9]*) refuse "lock-budget takes a set in this run, $R/deps/lock-set-<n>.tsv, not $(confine_text "${POS[0]}")" ;; esac
    confine_path "$SETF" "the set" any
    [ "$CONFINE_TYPE" = file ] || refuse "the set is not an existing regular file: $(confine_text "$SETF")"
    [ -z "$(find "$WT/$SETF" -prune -size +67108864c -print 2>/dev/null)" ] || refuse "the set is larger than 64 MiB: $(confine_text "$SETF")"
    AGE=${AUDITOR_PUBLISH_AGE:-on}
    case "$AGE" in on|off) ;; *) refuse "AUDITOR_PUBLISH_AGE is '$(confine_text "$AGE")', not on or off" ;; esac ;;
esac

CAP=${AUDITOR_RUN_TIMEOUT:-1800}
{ case "$CAP" in ''|*[!0-9]*) false ;; *) [ "${#CAP}" -le 5 ] && [ "$CAP" -ge 1 ] && [ "$CAP" -le 86400 ] ;; esac; } ||
  refuse "AUDITOR_RUN_TIMEOUT is '$(confine_text "$CAP")', not a whole number of seconds from 1 to 86400"
LIMIT=$((10#$CAP))
iso_tmp_outside
confine_disclosures_ok "$R" || refuse "$R/disclosures.tsv is not a regular file with one link whose first line is the header, so no row can be added to it"

# ---- the tools -----------------------------------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || blocker "$1 is not on PATH, so $ACTION cannot run here — nothing was copied or sent."; }
need python3
case "$ACTION" in
  cargo-audit) need cargo; need cargo-audit ;;
  cargo-outdated) need cargo; need cargo-outdated ;;
  cargo-tree) need cargo ;;
  npm-audit) need npm; need node ;;
  *) need curl ;;
esac

# ---- scratch, the output and the watchdog -------------------------------------------------------------
S=""
cleanup() {
  case "${ISO_SCRATCH:-}" in */auditor-deps.??????) chmod -R u+rwX "$ISO_SCRATCH" 2>/dev/null; rm -rf "$ISO_SCRATCH" 2>/dev/null ;; esac
}
on_signal() {
  if [ -n "${ISO_WATCH_PID:-}" ]; then
    kill -TERM "$ISO_WATCH_PID" 2>/dev/null
    wait "$ISO_WATCH_PID" 2>/dev/null
  fi
  exit "$1"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
iso_scratch deps
S=$ISO_SCRATCH
cd / || blocker "cannot leave the working directory for /"
iso_env "$S" || blocker "cannot prepare the cleaned environment (a throwaway HOME and TMPDIR) in $S — nothing was sent."
DEADLINE=$(($(date +%s) + LIMIT))
NET=(${ISO_NET[@]+"${ISO_NET[@]}"})
DEPS=$WT/$R/deps
OUT=$S/out.txt
: > "$OUT" || blocker "cannot write in $S"
exec 9>>"$OUT"
KEPT=""

# keep [<file>]: <file> (the output by default) as R/deps/<action>-<n>.txt; sets KEPT, its path, and N.
keep() {
  local src=${1:-$OUT}
  N=1
  if [ ! -d "$DEPS" ]; then confine_mkdir "$DEPS" || blocker "cannot create $R/deps"; fi
  [ ! -L "$DEPS" ] || blocker "$R/deps is a symbolic link"
  while :; do
    while [ -e "$DEPS/$ACTION-$N.txt" ] || [ -L "$DEPS/$ACTION-$N.txt" ] || [ -e "$DEPS/$ACTION-$N" ] || [ -L "$DEPS/$ACTION-$N" ]; do
      N=$((N + 1))
      [ "$N" -le 9999 ] || blocker "$R/deps holds 9999 runs of $ACTION"
    done
    iso_copy_new "$src" "$DEPS/$ACTION-$N.txt" && break
    [ -e "$DEPS/$ACTION-$N.txt" ] || blocker "cannot write $R/deps/$ACTION-$N.txt"
  done
  KEPT=$R/deps/$ACTION-$N.txt
}
# done_with <status> <line>: keep the output, print <line> with where it is (stdout for 0 and 1, a blocker
# on stderr for 3), exit <status>.
done_with() {
  exec 9>&-
  [ -n "$KEPT" ] || keep
  case "$1" in
    0|1) printf '>> %s: %s: %s\n' "$ACTION" "$2" "$KEPT" ;;
    *) printf 'deps: blocker: %s; output %s\n' "$2" "$KEPT" >&2 ;;
  esac
  exit "$1"
}

# step <dir> [NAME=value...] <program> [<arg>...]: one step under the watchdog, its output on fd 9 (or its
# stdout in STEP_OUT when that names a file). Sets STEP_END, the watchdog's line.
STEP=0
STEP_OUT=""
step() {
  local left now rc w
  now=$(date +%s) || now=$DEADLINE
  left=$((DEADLINE - now))
  STEP=$((STEP + 1))
  if [ "$left" -lt 1 ]; then STEP_END=timeout; return 124; fi
  printf '>>'
  for w in "${@:2}"; do
    case "$w" in [A-Za-z_]*=*) case "${w%%=*}" in *[!A-Za-z0-9_]*) ;; *) continue ;; esac ;; esac
    printf ' %s' "$w"
  done
  printf '\n'
  if [ -n "$STEP_OUT" ]; then
    iso_watch "$left" "$S/step-$STEP" "$@" > "$STEP_OUT"
  else
    iso_watch "$left" "$S/step-$STEP" "$@"
  fi
  rc=$?
  STEP_END=$(cat "$S/step-$STEP" 2>/dev/null) || STEP_END=""
  [ -n "$STEP_END" ] || STEP_END="exit $rc"
  return "$rc"
} >&9 2>&9
stopped() { # stopped: a reason when the last step did not just exit with a status; empty otherwise
  case "$STEP_END" in
    timeout) printf 'it passed the %s-second limit (AUDITOR_RUN_TIMEOUT) and was killed' "$LIMIT" ;;
    'signal 24') printf 'it passed its CPU time limit (ulimit -t)' ;;
    'signal 25') printf 'it wrote a file past 4 GiB (ulimit -f)' ;;
    'signal '*|'cannot start:'*|'stopped by signal'*) printf '%s' "$(confine_text "$STEP_END")" ;;
  esac
}
disclose() { # disclose <service> <kind> <value>...: the row before the first request to <service>
  confine_disclose "$R" "$TOOL" "$@" || blocker "cannot add a row to $R/disclosures.tsv, so nothing was sent"
}
# get <url> <file> [json]: one https GET into <file> (no redirects, at most 100 MiB); sets HTTP, the status
# code. A transfer that does not finish is a blocker.
get() {
  local -a accept=()
  [ "${3:-}" != json ] || accept=(-H 'Accept: application/json')
  STEP_OUT=$S/code
  step "$S" ${NET[@]+"${NET[@]}"} curl -q --proto =https --proto-redir =https --tlsv1.2 -sS --connect-timeout 30 \
    --max-filesize "$GET_MAX" -A "$UA" ${accept[@]+"${accept[@]}"} -o "$2" -w '%{http_code}' -- "$1"
  STEP_OUT=""
  HTTP=$(cat "$S/code" 2>/dev/null) || HTTP=""
  case "$STEP_END" in
    'exit 0') ;;
    *) local why
       why=$(stopped)
       done_with 3 "the request to $1 did not finish (${why:-curl $STEP_END})" ;;
  esac
  case "$HTTP" in [0-9][0-9][0-9]) ;; *) done_with 3 "the request to $1 gave no HTTP status" ;; esac
}

# Rust: the pinned toolchain, read in scratch, and the copies with their stub targets.
pin_rust() {
  local tc
  if [ -z "${RUSTUP_TOOLCHAIN:-}" ] && command -v rustup >/dev/null 2>&1; then
    tc=$(cd "$S" && iso_run rustup default 2>/dev/null </dev/null) || tc=""
    case "$tc" in
      *"(default)"*) ISO_ENV+=("RUSTUP_TOOLCHAIN=${tc%% *}") ;;
      *) done_with 3 "no Rust toolchain to pin: set RUSTUP_TOOLCHAIN or a rustup default" ;;
    esac
  fi
  ISO_ENV+=(RUSTUP_AUTO_INSTALL=0 CARGO_TERM_COLOR=never)
}
copy_manifests() {
  local rel d
  mkdir "$S/w" || done_with 3 "cannot create the copies in $S"
  for rel in "${MAN[@]}"; do
    d=$(dir_of "$rel")
    [ "$d" = . ] || mkdir -p -- "$S/w/$d" || done_with 3 "cannot create $S/w/$d"
    iso_copy_new "$WT/$rel" "$S/w/$rel" || done_with 3 "cannot copy $rel"
  done
}

# What the cargo actions run with python3 -I, all from /. "backstop <crate spec> <top> <manifest>...": the
# second line after the rebuild; refuse a [patch]/[replace] table header spelled as no Cargo.toml needs (a
# quoted first key, an array of tables, or anything but [patch.<registry>], [patch.<registry>.<crate>],
# [replace] and [replace.<spec>]), a table header with a \u, \U or \x escape, anything before the first table
# header but comments and a one-line cargo-features (a root key, or a multi-line string that can hide one), and
# text that is not UTF-8; print one ">> note:" line for each manifest that holds a plainly spelled table, with
# the crate names it patches that match <crate spec> (at most 20) and never a value. "locksource <top>
# <lockfile> [registries]": refuse a Cargo.lock with such an escape (cargo writes none) or that is not UTF-8,
# and with "registries" one that names a registry other than crates.io (registry+ or sparse+); git and path
# sources and [[patch.unused]] pass. "stubs <top> <manifest>...": an empty file at src/lib.rs and at
# each target path of each package manifest, so cargo metadata parses it. "vet <metadata> <top>": the
# dependencies cargo metadata lists come from crates.io or are paths inside <top> (exit 3 with the first that
# is not). "rebuild <metadata> <top> <dest>": write under <dest> a workspace of only the package names,
# versions, editions, features and dependency entries cargo metadata reports (a path dependency on a
# non-member, and a member outside the workspace root's directory, are refused, so nothing is written
# outside <dest>), so no [patch], [replace] or other table of the copy reaches the resolving cargo, whatever
# its spelling; prints the rebuilt root manifest path.
CARGO_PY='import json, os, re, sys

SECTION = re.compile(r"^\s*\[\[?\s*([A-Za-z0-9_.\-]+)\s*\]\]?\s*(#.*)?$")
KEY = re.compile(r"^\s*(name|path|build)\s*=\s*\x22([^\x22\\]*)\x22\s*(#.*)?$")
DEFAULT = {"bin": "src/bin/%s.rs", "example": "examples/%s.rs", "test": "tests/%s.rs", "bench": "benches/%s.rs"}
OVR_HEADER = re.compile(r"^\s*\[\[?\s*[\x22\x27]?(patch|replace)\b")
OVR_ROOTKEY = re.compile(r"^\s*[\x22\x27]?(patch|replace)[\x22\x27]?\s*[.=]")
OVR_OPEN = re.compile(r"^\s*\[")
ESCAPE = re.compile(r"\\[uUx]")
CARGO_FEATURES = re.compile(r"cargo-features[ \t]*=[ \t]*\[[A-Za-z0-9_\x22, \t-]*\][ \t]*(#.*)?")
LOCK_SOURCE = re.compile(r"^\s*[\x22\x27]?source[\x22\x27]?\s*=\s*[\x22\x27]([^\x22\x27]*)")
CRATES = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")
SEG = r"(?:[A-Za-z0-9_-]+|\x22[^\x22\\]*\x22|\x27[^\x27]*\x27)"
PLAIN_PATCH = re.compile(r"\s*\[\s*patch\s*\.\s*(" + SEG + r")\s*(?:\.\s*(" + SEG + r")\s*)?\]\s*(?:#.*)?")
PLAIN_REPLACE = re.compile(r"\s*\[\s*replace\s*(?:\.\s*(" + SEG + r")\s*)?\]\s*(?:#.*)?")
ENTRY_KEY = re.compile(r"^\s*(" + SEG + r")\s*[.=]")
NAMES_SHOWN = 20
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def fail(text):
    print(text)
    sys.exit(3)


def shown(text):
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(text))[:200]


def relative(rel):
    return bool(rel) and not rel.startswith("/") and ".." not in rel.split("/")


def inside(path, top):
    return path == top or path.startswith(top.rstrip(os.sep) + os.sep)


def create(path, text):
    # A new file, never one that exists or a symbolic link, written through the descriptor its creation opened.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def read_lines(path, rel):
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return raw.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        fail("%s is not UTF-8 text" % shown(rel))


def q(s):
    return "\x22" + str(s).replace("\\", "\\\\").replace("\x22", "\\\x22") + "\x22"


def unquote(seg):
    return seg[1:-1] if seg[:1] in ("\x22", "\x27") else seg


def spec_name(spec):
    # The crate name of a package-id spec: name, name:version, name@version, or <url>#name[:version]; a spec
    # that is only a URL gives none.
    if "#" in spec:
        spec = spec.rsplit("#", 1)[1]
    elif "/" in spec:
        return None
    return re.split(r"[:@]", spec, maxsplit=1)[0]


def backstop(crate_spec, top, manifests):
    # The second line after the rebuild, which already keeps every [patch] and [replace] table away from the
    # resolving cargo: a plainly spelled table passes, with a note, and a manifest the line scan cannot read
    # with confidence is refused. A table header with a \u, \U or \x escape can spell any key, and anything
    # before the first table header but blank lines, comments and a one-line cargo-features is a root key, or
    # a multi-line string that can hide one; cargo reads both. The note names only crates whose names match
    # crate_spec, and never prints a value (a path, URL or registry).
    grammar = re.compile(crate_spec)
    notes = []
    for rel in manifests:
        root, region, tables, named, unnamed = True, None, 0, [], set()
        def entry(raw, name):
            if name is not None and grammar.match(name):
                if name not in named:
                    named.append(name)
            else:
                unnamed.add(raw)
        for line in read_lines(os.path.join(top, rel), rel):
            if OVR_OPEN.match(line):
                if ESCAPE.search(line):
                    fail("%s has a table header with a \\u, \\U or \\x escape, which can spell any key; deps.sh does not read one" % shown(rel))
                root, region = False, None
                if not OVR_HEADER.match(line):
                    continue
                if re.match(r"\s*\[\s*\[", line):
                    fail("%s holds an array of [patch] or [replace] tables ([[...]]), which no Cargo.toml needs; deps.sh does not read one" % shown(rel))
                if re.match(r"\s*\[\s*[\x22\x27]", line):
                    fail("%s spells a [patch] or [replace] table header with a quoted key, which no Cargo.toml needs; deps.sh does not read one" % shown(rel))
                m = PLAIN_PATCH.fullmatch(line)
                if m:
                    tables += 1
                    if m.group(2):
                        entry(unquote(m.group(2)), unquote(m.group(2)))
                    else:
                        region = "patch"
                    continue
                m = PLAIN_REPLACE.fullmatch(line)
                if m:
                    tables += 1
                    if m.group(1):
                        entry(unquote(m.group(1)), spec_name(unquote(m.group(1))))
                    else:
                        region = "replace"
                    continue
                fail("%s has a [patch] or [replace] table header deps.sh does not read; [patch.<registry>], [patch.<registry>.<crate>], [replace] and [replace.<spec>] are fine" % shown(rel))
            elif region:
                k = ENTRY_KEY.match(line)
                if k:
                    raw = unquote(k.group(1))
                    entry(raw, raw if region == "patch" else spec_name(raw))
            elif root:
                if OVR_ROOTKEY.match(line):
                    fail("%s sets a root patch or replace key, which can name any host; deps.sh does not resolve one" % shown(rel))
                text = line.strip()
                if text and not text.startswith("#") and not CARGO_FEATURES.fullmatch(text):
                    fail("%s has a key before its first table header, which deps.sh does not read" % shown(rel))
        if tables:
            listed = named[:NAMES_SHOWN]
            more = len(named) - len(listed) + len(unnamed)
            if listed:
                what = ", ".join(listed) + (" and %d more" % more if more else "")
            elif more:
                what = "%d %s whose %s not printed" % (more, "entry" if more == 1 else "entries", "name is" if more == 1 else "names are")
            else:
                what = "no entries"
            notes.append(">> note: %s holds a [patch] or [replace] table, which this tree does not apply: %s" % (shown(rel), what))
    for note in notes:
        print(note)


def locksource(top, rel, registries):
    # cargo writes no \u, \U or \x escape into a Cargo.lock, so one is refused. With registries (cargo audit,
    # when it asks a registry which releases were yanked), so is a source from a registry other than
    # crates.io, the one kind of source such a check could ask. Git and path sources and [[patch.unused]]
    # pass: cargo resolves the rebuilt workspace from crates.io and fetches none of them, and cargo audit
    # does not query them.
    for line in read_lines(os.path.join(top, rel), rel):
        if ESCAPE.search(line):
            fail("the lockfile has a \\u, \\U or \\x escape, which cargo never writes; deps.sh does not read one")
        m = LOCK_SOURCE.match(line)
        if registries and m and m.group(1).startswith(("registry+", "sparse+")) and m.group(1) not in CRATES:
            fail("the lockfile names a registry other than crates.io, %s, which a check for yanked releases could ask; --no-fetch audits it offline" % shown(m.group(1)))


def stubs(top, manifests):
    for rel in manifests:
        path = os.path.join(top, rel)
        base = os.path.dirname(path)
        lines = read_lines(path, rel)
        if not any(re.match(r"^\s*\[package\]", line) for line in lines):
            continue
        want, cur, kind = ["src/lib.rs"], None, None
        for line in lines:
            m = SECTION.match(line)
            if m:
                kind = m.group(1)
                cur = {"kind": kind, "name": None, "path": None} if kind in ("lib", "bin", "example", "test", "bench") else None
                if cur is not None:
                    want.append(cur)
                continue
            k = KEY.match(line)
            if not k:
                continue
            if kind == "package" and k.group(1) == "build":
                want.append(k.group(2))
            elif cur is not None and k.group(1) in ("name", "path"):
                cur[k.group(1)] = k.group(2)
        for item in want:
            if isinstance(item, dict):
                p = item["path"] or ("src/lib.rs" if item["kind"] == "lib" else DEFAULT[item["kind"]] % (item["name"] or "stub"))
            else:
                p = item
            if not relative(p):
                fail("%s names a target outside its directory: %s" % (shown(rel), shown(p)))
            target = os.path.join(base, p)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if not os.path.lexists(target):
                os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600))


def vet(meta, top):
    data = json.load(open(meta, encoding="utf-8"))
    top = os.path.realpath(top) + os.sep
    for pkg in data.get("packages", []):
        for dep in pkg.get("dependencies", []):
            name, source = dep.get("name", "?"), dep.get("source")
            if dep.get("registry"):
                fail("%s depends on %s from another registry than crates.io (%s)" % (pkg.get("name"), name, shown(dep["registry"])))
            if source and not (source.startswith(CRATES[0]) or source.startswith(CRATES[1])):
                fail("%s depends on %s from %s, not crates.io" % (pkg.get("name"), name, shown(source)))
            if dep.get("path") and not (os.path.realpath(dep["path"]) + os.sep).startswith(top):
                fail("%s depends on %s at a path outside the copied manifests" % (pkg.get("name"), name))


def q_target(t):
    if re.match(r"^[A-Za-z0-9_.\-]+$", t):
        return t
    if "\x27" not in t:
        return "\x27" + t + "\x27"
    return q(t)


def toml_key(name):
    return name if re.match(r"^[A-Za-z0-9_\-]+$", name) else q(name)


def dep_table(deps, by, members, dest_dir, dest_root):
    for d in deps:
        key = d.get("rename") or d["name"]
        parts = []
        path = d.get("path")
        if path is not None:
            tgt = os.path.realpath(path)
            if tgt not in members:
                fail("%s is a path dependency on a crate that is not a workspace member" % d.get("name"))
            parts.append("path = %s" % q(os.path.relpath(os.path.join(dest_root, members[tgt]), dest_dir)))
            if d.get("req") and d["req"] != "*":
                parts.append("version = %s" % q(d["req"]))
        else:
            parts.append("version = %s" % q(d.get("req") or "*"))
        if d.get("rename"):
            parts.append("package = %s" % q(d["name"]))
        if d.get("optional"):
            parts.append("optional = true")
        if not d.get("uses_default_features", True):
            parts.append("default-features = false")
        if d.get("features"):
            parts.append("features = [%s]" % ", ".join(q(f) for f in d["features"]))
        table = {None: "dependencies", "dev": "dev-dependencies", "build": "build-dependencies"}.get(d.get("kind"), "dependencies")
        by.setdefault((d.get("target"), table), []).append("%s = { %s }" % (toml_key(key), ", ".join(parts)))


def member_dir(p):
    return os.path.realpath(os.path.dirname(p["manifest_path"]))


def rebuild(meta, top, dest):
    # Every write lands under dest by construction: the workspace root lies among the copies, each member lies
    # under the root (cargo also takes a member elsewhere that names the root with package.workspace; the
    # rebuild refuses one), each directory is checked inside dest before and after it is made, and each file
    # is a new one.
    data = json.load(open(meta, encoding="utf-8"))
    top, dest = os.path.realpath(top), os.path.realpath(dest)
    root = os.path.realpath(data["workspace_root"])
    if not inside(root, top):
        fail("cargo metadata names a workspace root outside the copied manifests")
    ids = set(data.get("workspace_members") or [])
    pkgs = [p for p in data.get("packages", []) if p.get("id") in ids]
    if not pkgs:
        fail("cargo metadata lists no workspace member to rebuild")
    members = {}
    for p in pkgs:
        d = member_dir(p)
        if not inside(d, root):
            fail("the workspace member %s lies outside the workspace root, %s; deps.sh rebuilds only members under the root" % (shown(os.path.relpath(d, top)), shown(os.path.relpath(root, top))))
        members[d] = os.path.relpath(d, root)
    rels = sorted(members.values())
    have_root_pkg = False
    for p in pkgs:
        rel = members[member_dir(p)]
        d = os.path.normpath(os.path.join(dest, rel))
        if not inside(d, dest):
            fail("the rebuilt manifest of %s would land outside the scratch directory" % shown(rel))
        os.makedirs(d, exist_ok=True)
        if not inside(os.path.realpath(d), dest):
            fail("the rebuilt manifest of %s would land outside the scratch directory" % shown(rel))
        create(os.path.join(d, "lib.rs"), "")
        head = []
        if rel == ".":
            have_root_pkg = True
            head = ["[workspace]", "members = [%s]" % ", ".join(q(r) for r in rels if r != "."), "resolver = \x224\x22".replace("4", "2"), ""]
        lines = head + ["[package]", "name = %s" % q(p["name"]), "version = %s" % q(p.get("version") or "0.0.0"),
                        "edition = %s" % q(p.get("edition") or "2021"), "", "[lib]", "path = %s" % q("lib.rs"), ""]
        by = {}
        dep_table(p.get("dependencies", []), by, members, d, dest)
        for (target, table) in sorted(by, key=lambda t: ((t[0] or ""), t[1])):
            lines.append("[%s]" % table if target is None else "[target.%s.%s]" % (q_target(target), table))
            lines += by[(target, table)]
            lines.append("")
        feats = p.get("features") or {}
        if feats:
            lines.append("[features]")
            for name in sorted(feats):
                lines.append("%s = [%s]" % (toml_key(name), ", ".join(q(x) for x in feats[name])))
            lines.append("")
        create(os.path.join(d, "Cargo.toml"), "\n".join(lines) + "\n")
    if not have_root_pkg:
        create(os.path.join(dest, "Cargo.toml"), "[workspace]\nmembers = [%s]\nresolver = %s\n" % (", ".join(q(r) for r in rels), q("2")))
    print(os.path.join(dest, "Cargo.toml"))


try:
    cmd = sys.argv[1]
    if cmd == "stubs":
        stubs(sys.argv[2], sys.argv[3:])
    elif cmd == "backstop":
        backstop(sys.argv[2], sys.argv[3], sys.argv[4:])
    elif cmd == "locksource":
        locksource(sys.argv[2], sys.argv[3], sys.argv[4:] == ["registries"])
    elif cmd == "vet":
        vet(sys.argv[2], sys.argv[3])
    elif cmd == "rebuild":
        rebuild(sys.argv[2], sys.argv[3], sys.argv[4])
except SystemExit:
    raise
except BaseException as why:
    fail("cannot read or rebuild the manifests: %s" % shown(why))
'
cargo_py() { (cd / && exec python3 -I -c "$CARGO_PY" "$@"); }

# What the registry actions run with python3 -I. "time <packument> <out>": the name, dist-tags and time of an
# npm packument. "artifact <eco> <name> <version> <record>": the artifact's URL, digest algorithm, digest
# and file name, tab-separated, from the registry's record (exit 3 with the reason). "verify <archive>
# <algo> <digest>": the file's digest is the registry's (exit 3 with both otherwise). "unpack <archive>
# <file name> <algo> <digest> <dir>": verify, then unpack the regular files and directories into <dir>, as
# a zip for a .whl or .zip name and as a tar otherwise (exit 3 with the reason); prints what it did and
# what it left out.
REGISTRY_PY='import base64, hashlib, io, json, os, re, stat, sys, tarfile, time, zipfile

try:
    import lzma
except ImportError:
    lzma = None

FILES, BYTES = 50000, 512 * 1024 * 1024
# What an unpack may take, and what it says past that: BYTES, or for lock-budget what its call has left.
CAP = [BYTES, "the artifact unpacks to more than 512 MiB"]
# When lock-budget must stop starting work (a time.time() value), or None: unpack checks it before each entry.
STOP = [None]
LATE = "the call reached its time limit"
# A failure a retry cannot change: a bound the artifact passes, or the time limit of the call.
FINAL = re.compile(r"^the call reached its time limit|is larger than [0-9]+ MB|unpacks? to more than|holds? more than|takes more than|needs more than")
ROOM = "the artifacts of this call would unpack to more than %d MB"
# What a tar may hold in pax and GNU long-name headers in all, and in global pax headers; what a zip
# central directory may take.
EXTENDED, GLOBAL, CENTRAL = 4 * 1024 * 1024, 128, 16 * 1024 * 1024
# How many pax, GNU long-name and global headers may come in a row, before the member they describe (an
# archive needs two or three), and what the decompressor of an xz stream may take (every xz preset needs at
# most 65 MiB).
CHAIN, XZ_MEMORY = 8, 128 * 1024 * 1024
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def shown(text):
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(text))[:300]


def fail(text):
    print(shown(text))
    sys.exit(3)


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def npm_time(packument, out):
    data = load(packument)
    keep = {"name": data.get("name"), "dist-tags": data.get("dist-tags"), "time": data.get("time")}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(keep, f, indent=2, sort_keys=True)
        f.write("\n")


def artifact(eco, name, version, record):
    data = load(record)
    if eco == "crates":
        v = data.get("version") or {}
        if v.get("num") != version or v.get("crate") != name:
            fail("crates.io answered for another crate or version")
        digest = v.get("checksum") or ""
        if not re.match(r"^[0-9a-f]{64}$", digest):
            fail("crates.io gives %s %s no sha256 checksum" % (name, version))
        url = "https://static.crates.io/crates/%s/%s-%s.crate" % (name, name, version)
        print("\t".join((url, "sha256", digest, "%s-%s.crate" % (name, version))))
    elif eco == "npm":
        if data.get("name") != name or data.get("version") != version:
            fail("the npm registry answered for another package or version")
        dist = data.get("dist") or {}
        base = name.split("/")[-1]
        url = "https://registry.npmjs.org/%s/-/%s-%s.tgz" % (name, base, version)
        if dist.get("tarball") != url:
            fail("the npm registry names the tarball at %s, not %s" % (dist.get("tarball"), url))
        integrity = [i for i in str(dist.get("integrity") or "").split() if i.startswith("sha512-")]
        if integrity:
            print("\t".join((url, "sha512", integrity[0][len("sha512-"):], "%s-%s.tgz" % (base, version))))
        elif re.match(r"^[0-9a-f]{40}$", str(dist.get("shasum") or "")):
            print("\t".join((url, "sha1", dist["shasum"], "%s-%s.tgz" % (base, version))))
        else:
            fail("the npm registry gives %s@%s no sha512 integrity and no shasum" % (name, version))
    else:
        urls = data.get("urls") or []
        pick = [u for u in urls if u.get("packagetype") == "sdist"] or \
            [u for u in urls if str(u.get("filename", "")).endswith("-none-any.whl")]
        if not pick:
            fail("PyPI lists no sdist and no pure-Python wheel for %s %s" % (name, version))
        u = pick[0]
        url, filename = str(u.get("url", "")), str(u.get("filename", ""))
        digest = str((u.get("digests") or {}).get("sha256") or "")
        if not re.match(r"^https://files\.pythonhosted\.org/packages/[A-Za-z0-9/._+%-]+$", url):
            fail("PyPI names the file at %s, not under https://files.pythonhosted.org/packages/" % url)
        if not re.match(r"^[A-Za-z0-9._+!-]{1,255}$", filename) or not re.match(r"^[0-9a-f]{64}$", digest):
            fail("PyPI gives the file an odd name or no sha256 digest")
        print("\t".join((url, "sha256", digest, filename)))


def verify(archive, algo, expected):
    h = hashlib.new(algo)
    with open(archive, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    got = base64.b64encode(h.digest()).decode() if algo == "sha512" else h.hexdigest()
    if got != expected:
        fail("the digest does not match: the registry gives %s %s, the file has %s" % (algo, expected, got))
    return got


def zip_kind(info):
    mode = (info.external_attr >> 16) & 0o170000
    if info.filename.endswith("/"):
        return "dir"
    if mode in (0, stat.S_IFREG):
        return "file"
    return "symbolic link" if mode == stat.S_IFLNK else "special file"


def tar_kind(m):
    return "file" if m.isfile() else "dir" if m.isdir() else "symbolic link" if m.issym() else \
        "hard link" if m.islnk() else "special file"


class Capped(tarfile.TarInfo):
    # tarfile reads each header of the tar through this class, which checks it before tarfile reads what it
    # announces, so what tarfile keeps for the members already read stays bounded while the caps count them:
    # no size below zero, at most EXTENDED bytes of pax and GNU long-name headers in all and CHAIN of them in a
    # row (an empty one adds no bytes, and each still costs a parse), at most GLOBAL bytes of global pax
    # headers (tarfile gives every later member its own copy of their keys, and of some of their values), and
    # no sparse file, whose map tarfile reads from the data that follows with no bound (in the methods below
    # that refuse one). The size field of every other header counts toward BYTES as well: tarfile reads through
    # the data that field gives before it applies a global pax size, which can report the entry as smaller.
    HOOKS = ("_proc_member", "_proc_sparse", "_proc_gnusparse_00", "_proc_gnusparse_01", "_proc_gnusparse_10")
    EXTENSIONS = (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.XHDTYPE, tarfile.XGLTYPE,
                  tarfile.SOLARIS_XHDTYPE)

    def _proc_member(self, tf):
        if self.size < 0:
            fail("the artifact gives an entry a size below zero")
        if self.type in self.EXTENSIONS:
            tf.chain = getattr(tf, "chain", 0) + 1
            if tf.chain > CHAIN:
                fail("the artifact holds more than %d pax and GNU long-name headers in a row" % CHAIN)
            tf.extended_bytes = getattr(tf, "extended_bytes", 0) + self.size
            if tf.extended_bytes > EXTENDED:
                fail("the pax and GNU long-name headers of the artifact hold more than 4 MiB")
        else:
            tf.chain = 0
            tf.data_bytes = getattr(tf, "data_bytes", 0) + self.size
            if tf.data_bytes > CAP[0]:
                fail(CAP[1])
        if self.type == tarfile.XGLTYPE:
            tf.global_bytes = getattr(tf, "global_bytes", 0) + self.size
            if tf.global_bytes > GLOBAL:
                fail("the global pax headers of the artifact hold more than 128 bytes")
        return super()._proc_member(tf)

    def _proc_sparse(self, *args):
        fail("the artifact holds a sparse file")

    _proc_gnusparse_00 = _proc_gnusparse_01 = _proc_gnusparse_10 = _proc_sparse


def bound_memory():
    # A backstop for what the caps do not count: at most 2 GiB of address space, where the system enforces
    # the limit (Linux; macOS refuses to set it).
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        want = 2 << 30
        if hard != resource.RLIM_INFINITY and hard < want:
            want = hard
        if soft == resource.RLIM_INFINITY or soft > want:
            resource.setrlimit(resource.RLIMIT_AS, (want, hard))
    except (ImportError, AttributeError, ValueError, OSError):
        pass


class Unxz(io.RawIOBase):
    # An xz stream, read for tarfile as gzip.GzipFile reads a gzip one: forward through the stream, and from its
    # start again for a seek back. Its decompressor may take XZ_MEMORY, and each call hands back at most what
    # the read asks for. Another stream may follow, after zero padding, as in files xz concatenates.
    def __init__(self, path):
        super().__init__()
        self.src = open(path, "rb")
        self.restart()

    def restart(self):
        self.src.seek(0)
        self.dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMORY)
        self.pos = 0

    def close(self):
        if not self.closed:
            self.src.close()
        super().close()

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def readinto(self, buf):
        if not len(buf):
            return 0
        data = b""
        try:
            while not data:
                if self.dec.eof:
                    rest = self.dec.unused_data.lstrip(b"\0")
                    while not rest:
                        more = self.src.read(1 << 16)
                        if not more:
                            return 0
                        rest = more.lstrip(b"\0")
                    self.dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMORY)
                elif self.dec.needs_input:
                    rest = self.src.read(1 << 16)
                    if not rest:
                        fail("the xz stream of the artifact is cut short")
                else:
                    rest = b""
                data = self.dec.decompress(rest, max_length=len(buf))
        except lzma.LZMAError as why:
            if "Memory usage limit" in str(why):
                fail("the xz stream of the artifact needs more than %d MiB to decompress" % (XZ_MEMORY >> 20))
            fail("the xz stream of the artifact cannot be read: %s" % why)
        buf[:len(data)] = data
        self.pos += len(data)
        return len(data)

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_CUR:
            offset += self.pos
        elif whence != io.SEEK_SET:
            raise io.UnsupportedOperation("an xz stream is read from its start")
        if offset < self.pos:
            self.restart()
        skip = memoryview(bytearray(1 << 20))
        while self.pos < offset and self.readinto(skip[:min(offset - self.pos, len(skip))]):
            pass
        return self.pos


class Counted(zipfile.ZipInfo):
    # What zipfile builds for each record of a central directory as it reads them: past FILES the read stops,
    # before the rest are built.
    __slots__ = ()
    made = 0

    def __init__(self, *args, **kwargs):
        Counted.made += 1
        if Counted.made > FILES:
            fail("the artifact holds more than %d entries" % FILES)
        super().__init__(*args, **kwargs)


def unpack(archive, filename, algo, expected, dest):
    got = verify(archive, algo, expected)
    weak = "" if algo != "sha1" else " (weak: the npm registry offered no sha512 integrity for this version, only a sha1 shasum; sha1 is collision-weak, so this is not a strong content check)"
    print("digest: %s %s, as the registry gives it%s" % (algo, got, weak))
    bound_memory()
    entries, skipped, declared = [], [], 0
    # The caps hold while the archive is read: the headers of a tar are read one at a time, through Capped, and
    # the read stops at the first entry past FILES, or the first that takes the declared sizes past BYTES (of
    # every entry: tarfile reads through the data of one it does not know as well), so the list never grows
    # past the cap; a zip central directory, which zipfile reads whole, is measured first, and zipfile stops at
    # its record FILES + 1, through Counted. Nothing is unpacked until the whole list is within the caps. Only
    # decompressors whose memory has a fixed bound run: gzip and bzip2 for a tar, and xz with its decompressor
    # held to XZ_MEMORY (an xz stream chooses the window its decompressor keeps; a zstd one is not read),
    # deflate for a zip (zipfile hands bzip2 and LZMA a whole read of compressed bytes, with no bound on what
    # comes out).
    if filename.endswith((".whl", ".zip")):
        with open(archive, "rb") as f:
            end = zipfile._EndRecData(f)
        if end and end[zipfile._ECD_SIZE] > CENTRAL:
            fail("the central directory of the artifact takes more than 16 MiB")
        real, zipfile.ZipInfo = zipfile.ZipInfo, Counted
        try:
            z = zipfile.ZipFile(archive)
        finally:
            zipfile.ZipInfo = real
        if len(z.filelist) > FILES:
            fail("the artifact holds more than %d entries" % FILES)
        if any(i.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) for i in z.filelist):
            fail("an entry of the artifact is compressed with a method other than deflate, which deps.sh does not unpack")
        listing = ((i.filename, zip_kind(i), i.file_size, i) for i in z.infolist())
        opener = lambda e: z.open(e[3])
    else:
        if not all(hasattr(tarfile.TarInfo, h) for h in Capped.HOOKS):
            fail("the tarfile module of this python3 lacks a method deps.sh replaces to bound what it reads")
        with open(archive, "rb") as f:
            head = f.read(262)
        if head.startswith(b"\x28\xb5\x2f\xfd"):
            fail("the artifact is compressed with zstd, which deps.sh does not unpack (a tar is read plain, or through gzip, bzip2 or xz)")
        if head.startswith(b"\xfd7zXZ\x00"):
            if lzma is None:
                fail("the artifact is compressed with xz, and this python3 has no lzma module to read it")
            t = tarfile.open(fileobj=io.BufferedReader(Unxz(archive)), mode="r:", tarinfo=Capped)
        else:
            mode = "r:" if head[257:] == b"ustar" else "r:gz" if head[:2] == b"\x1f\x8b" else "r:bz2" if head[:3] == b"BZh" else "r:"
            t = tarfile.open(archive, mode, tarinfo=Capped)
        listing = ((m.name, tar_kind(m), m.size, m) for m in t)
        opener = lambda e: t.extractfile(e[3])
    for name, kind, declared_size, ref in listing:
        if len(entries) == FILES:
            fail("the artifact holds more than %d entries" % FILES)
        if declared_size < 0:
            fail("the artifact gives an entry a size below zero")
        declared += declared_size
        if declared > CAP[0]:
            fail(CAP[1])
        entries.append((name, kind, declared_size if kind == "file" else 0, ref))
    files = dirs = size = 0
    for e in entries:
        if STOP[0] is not None and time.time() > STOP[0]:
            fail(LATE)
        name, kind = e[0], e[1]
        parts = [p for p in name.split("/") if p not in ("", ".")]
        if name.startswith("/") or ".." in parts or not parts or re.search(r"[\x00-\x1f\x7f\\\\]", name):
            skipped.append((name, "unsafe name"))
            continue
        if kind not in ("file", "dir"):
            skipped.append((name, kind))
            continue
        cur = dest
        why = None
        for p in parts[:-1] if kind == "file" else parts:
            cur = os.path.join(cur, p)
            try:
                os.mkdir(cur, 0o700)
                dirs += 1
            except FileExistsError:
                if not stat.S_ISDIR(os.lstat(cur).st_mode):
                    why = "a file stands where its directory goes"
                    break
            except OSError as e:
                why = "cannot be written: %s" % e.strerror
                break
        if why:
            skipped.append((name, why))
            continue
        if kind == "dir":
            continue
        target = os.path.join(cur, parts[-1])
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600)
        except FileExistsError:
            skipped.append((name, "the name is taken (given twice, or the same in another letter case)"))
            continue
        except OSError as e:
            skipped.append((name, "cannot be written: %s" % e.strerror))
            continue
        with os.fdopen(fd, "wb") as out:
            src = opener(e)
            for chunk in iter(lambda: src.read(1 << 20), b""):
                out.write(chunk)
                size += len(chunk)
        files += 1
    print("unpacked: %d files, %d bytes, %d directories" % (files, size, dirs))
    print("left out: %d entries%s" % (len(skipped), " (each an SC-060 hit when it is a link, a special file or an unsafe name)" if skipped else ""))
    for name, why in skipped:
        print("  %s: %s" % (shown(name), why))


# ---- lock-budget: the CI budget of checklist 11 §11.11 over a set lock-delta.sh set wrote ------------------
SET_HEADER = "eco\tlockfile\tname\told\tnew\toldsource\tsource\tmarks"
SET_ECOS = {"npm": (r"^(@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$", 214),
            "crates": (r"^[A-Za-z][A-Za-z0-9_-]{0,63}$", 64),
            "pypi": (r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$", 100)}
SEMVER = r"^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})(-[0-9A-Za-z.-]{1,64})?(\+[0-9A-Za-z.-]{1,64})?$"
PEP440 = r"^[0-9][0-9A-Za-z.!+_-]{0,63}$"
# The order of the 40-entry budget. A key handler, which lock-delta.sh marks key, is compared whatever the budget, first.
CATEGORY = (("direct", 1), ("pin", 2), ("install", 3), ("young", 4), ("source-change", 5))
MARKS = (("key", 0),) + CATEGORY
# One call stays inside the 600 seconds a Bash tool call may take: the publish ages stop at 300 seconds, and the
# whole call at 540. Its work stops MARGIN seconds before that end: no request, unpack or sweep runs past it, and
# what is left is not compared, so the report is written in time.
BUDGET, ASK_CAP, ASK_SECONDS, CALL_SECONDS, CRATES_GAP, QUARANTINE = 40, 1000, 300, 540, 1.0, 14
MARGIN = 10
# At most this many publish-age requests in flight. The crates.io API, asked only for the publishers of the
# crates the budget selects, takes one request a second.
IN_FLIGHT = 8
# At most this much a download of the budget, and this much unpacked in one call.
ARTIFACT_MAX, CALL_UNPACKED = 50 * 1000 * 1000, 500 * 1000 * 1000
# What a scoped npm package the public registry does not list is taken for: never fetched, never a failure.
PRIVATE = "the public registry does not list this scoped package; it may be private"
# The publisher the npm registry names for a release made by trusted publishing from GitHub Actions.
CI_PUBLISHER = "GitHub Actions"


def clean(text):
    # shown, without its cut: the report and its summary lines are long by design
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(text))


def set_rows(path):
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    if not lines or lines[0] != SET_HEADER:
        fail("%s is not a set lock-delta.sh set wrote: its first line is not the header" % path)
    rows, odd = [], 0
    for i, line in enumerate(lines[1:]):
        if not line:
            continue
        cells = line.split("\t")
        if len(cells) != 8:
            odd += 1
            continue
        eco, lockfile, name, old, new, oldsource, source, marks = cells
        spec = SET_ECOS.get(eco)
        vspec = PEP440 if eco == "pypi" else SEMVER
        if spec is None or not re.match(spec[0], name) or len(name) > spec[1]:
            odd += 1
            continue
        public = source == "public" and bool(re.match(vspec, new))
        if old != "-" and not re.match(vspec, old):
            old, oldsource = "-", "-"
        rows.append({"i": i, "eco": eco, "lockfile": lockfile, "name": name, "old": old, "new": new,
                     "oldsource": oldsource, "source": source, "public": public,
                     "marks": {m.split("=")[0] for m in marks.split(",") if m and m != "-"}})
    return rows, odd


def rank(row):
    # 0 for a key handler, 1 to 5 for the order of the budget, 7 for a row the budget does not select
    if "key" in row["marks"]:
        return 0
    got = [c for m, c in CATEGORY if m in row["marks"]]
    return min(got) if got else 7


def services(path, age):
    rows, _ = set_rows(path)
    out = []
    for eco, host in (("npm", "npmjs.org"), ("crates", "crates.io"), ("pypi", "pypi.org")):
        mine = [r for r in rows if r["eco"] == eco and r["public"]]
        if not mine:
            continue
        if age == "on" or (eco != "pypi" and any(rank(r) < 7 and r["old"] != r["new"] for r in mine)):
            out.append(host)
    print("\n".join(out))


class Fetcher:
    # curl, one request at a time per thread; safe to call from several threads
    def __init__(self, scratch, deadline, maxsize, agent, log):
        import threading
        self.scratch, self.deadline, self.maxsize, self.agent, self.log = scratch, deadline, maxsize, agent, log
        self.count, self.last_crates, self.k, self.unpacked = 0, 0.0, 0, 0
        self.lock, self.crates_lock = threading.Lock(), threading.Lock()

    def get(self, url, accept_json=False, compressed=False, most=120, size=None):
        import subprocess, time
        if url.startswith("https://crates.io/"):
            with self.crates_lock:
                wait = self.last_crates + CRATES_GAP - time.time()
                if wait > 0:
                    time.sleep(wait)
                self.last_crates = time.time()
        left = int(self.deadline - time.time())
        if left < 5:
            return None, "the call reached its time limit (%d seconds, or AUDITOR_RUN_TIMEOUT when that is less)" % CALL_SECONDS
        with self.lock:
            self.k += 1
            self.count += 1
            out = os.path.join(self.scratch, "get-%d" % self.k)
        args = ["curl", "-q", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "-sS", "--connect-timeout", "30",
                "--max-time", str(min(left - 2, most)), "--max-filesize", str(size or self.maxsize), "-A", self.agent]
        if accept_json:
            args += ["-H", "Accept: application/json"]
        if compressed:
            args += ["--compressed"]
        args += ["-o", out, "-w", "%{http_code}", "--", url]
        p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        code = p.stdout.decode("ascii", "replace")[-3:]
        with self.lock:
            self.log.write("GET %s -> %s\n" % (url, code if p.returncode == 0 else "curl exit %d" % p.returncode))
        if p.returncode == 63 and size:
            return None, "the artifact at %s is larger than %d MB" % (url, size // 1000000)
        if p.returncode != 0:
            return None, "the request to %s did not finish (curl exit %d: %s)" % (url, p.returncode, shown(p.stderr.decode("utf-8", "replace").strip())[:200])
        if not re.match(r"^[0-9]{3}$", code):
            return None, "the request to %s gave no HTTP status" % url
        if code != "200":
            return None, "HTTP %s from %s" % (code, url)
        if size and os.path.getsize(out) > size:
            os.remove(out)
            return None, "the artifact at %s is larger than %d MB" % (url, size // 1000000)
        return out, ""


def when(text):
    import calendar
    m = re.match(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[T ]([0-9]{2}):([0-9]{2}):([0-9]{2})", str(text or ""))
    if not m:
        return None
    t = calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0))
    off = re.search(r"([+-])([0-9]{2}):?([0-9]{2})$", str(text))
    if off and not str(text).endswith("Z"):
        t -= (1 if off.group(1) == "+" else -1) * (int(off.group(2)) * 3600 + int(off.group(3)) * 60)
    return t


def history(eco, name, path, wanted):
    # {version: (published, publisher, yanked)}, and the records fetch-artifact reads for the versions in
    # <wanted>, from one registry answer
    if eco == "crates-index":
        with open(path, encoding="utf-8") as f:
            data = [line for line in f.read().split("\n") if line.strip()]
    else:
        data = load(path)
    hist, records = {}, {}
    if eco == "npm":
        times = data.get("time") if isinstance(data.get("time"), dict) else {}
        versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
        for v, rec in versions.items():
            if not isinstance(rec, dict):
                continue
            user = rec.get("_npmUser") if isinstance(rec.get("_npmUser"), dict) else {}
            hist[v] = (when(times.get(v)), str(user.get("name") or "") or None, False)
            if v in wanted:
                records[v] = {"name": rec.get("name"), "version": rec.get("version"), "dist": rec.get("dist")}
    elif eco == "crates":
        for rec in data.get("versions") or []:
            if not isinstance(rec, dict) or not isinstance(rec.get("num"), str):
                continue
            by = rec.get("published_by") if isinstance(rec.get("published_by"), dict) else {}
            hist[rec["num"]] = (when(rec.get("created_at")), str(by.get("login") or "") or None, bool(rec.get("yanked")))
            if rec["num"] in wanted:
                records[rec["num"]] = {"version": {"num": rec["num"], "crate": rec.get("crate") or name, "checksum": rec.get("checksum")}}
    elif eco == "crates-index":
        # the crates.io index: one JSON line per version, its pubtime where crates.io records one
        read = 0
        for line in data:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict) or not isinstance(rec.get("vers"), str) or str(rec.get("name", "")).lower() != name.lower():
                continue
            read += 1
            v = rec["vers"]
            hist[v] = (when(rec.get("pubtime")), None, bool(rec.get("yanked")))
            if v in wanted and isinstance(rec.get("cksum"), str):
                records[v] = {"version": {"num": v, "crate": name, "checksum": rec["cksum"]}}
        if not read:
            raise ValueError("the index entry holds no version of %s" % name)
    else:
        for v, files in (data.get("releases") or {}).items():
            if not isinstance(files, list):
                continue
            stamps = [when(f.get("upload_time_iso_8601") or f.get("upload_time")) for f in files if isinstance(f, dict)]
            stamps = [s for s in stamps if s is not None]
            hist[v] = (min(stamps) if stamps else None, None, bool(files) and all(isinstance(f, dict) and f.get("yanked") for f in files))
    return hist, records


def npm_url_path(name):
    return name.replace("/", "%2F") if name.startswith("@") else name


def index_path(name):
    # where the crates.io index keeps a crate: by the length of its lowercase name, then its first letters
    n = name.lower()
    if len(n) <= 2:
        return "%d/%s" % (len(n), n)
    if len(n) == 3:
        return "3/%s/%s" % (n[0], n)
    return "%s/%s/%s" % (n[:2], n[2:4], n)


def age_check(rows, fetcher, now, log):
    import time
    from concurrent.futures import ThreadPoolExecutor
    names, seen = [], set()
    for r in sorted((r for r in rows if r["public"]), key=lambda r: (rank(r), r["i"])):
        k = (r["eco"], r["name"])
        if k not in seen:
            seen.add(k)
            names.append(k)
    wanted = {}
    for r in rows:
        wanted.setdefault((r["eco"], r["name"]), set()).update((r["new"], r["old"]))
    start = time.time()

    def ask(eco, name):
        # one registry record, with one retry: (history, records, why not checked)
        url = {"npm": "https://registry.npmjs.org/" + npm_url_path(name), "crates": "https://index.crates.io/" + index_path(name),
               "pypi": "https://pypi.org/pypi/%s/json" % name}[eco]
        why = ""
        for attempt in (1, 2):
            if time.time() - start > ASK_SECONDS:
                return None, None, why or "the 300-second bound"
            got, why = fetcher.get(url, eco != "crates", eco != "pypi", 60)
            if not got and why.startswith("HTTP 404 "):
                # the registry has no such package: a scoped npm one may be private to its organization;
                # every version of any other is one the registry does not list
                return ({}, {}, PRIVATE) if eco == "npm" and name.startswith("@") else ({}, {}, "")
            if got:
                try:
                    hist, recs = history("crates-index" if eco == "crates" else eco, name, got, wanted.get((eco, name), set()))
                    return hist, recs, ""
                except BaseException as e:
                    why = "the answer cannot be read: %s" % (str(e) or type(e).__name__)
                finally:
                    os.remove(got)
            if "time limit" in why:
                break
            if attempt == 1:
                time.sleep(1)
        return None, None, why

    results, records, not_checked = {}, {}, {}
    asking = names[:ASK_CAP]
    for k in names[ASK_CAP:]:
        not_checked[k] = "the 1,000-request cap"
    with ThreadPoolExecutor(max_workers=IN_FLIGHT) as pool:
        answers = list(pool.map(lambda k: ask(*k), asking))
    private = set()
    for k, (hist, recs, why) in zip(asking, answers):
        if why == PRIVATE:
            private.add(k)
            continue
        if why:
            not_checked[k] = why
            continue
        results[k] = hist
        for v, rec in recs.items():
            records[(k[0], k[1], v)] = rec
    asked = len(asking)
    out = {}
    for r in rows:
        if not r["public"]:
            continue
        k = (r["eco"], r["name"])
        if k in private:
            out[r["i"]] = {"private": True}
            continue
        if k in not_checked:
            out[r["i"]] = {"why": not_checked[k]}
            continue
        hist = results.get(k, {})
        if r["new"] not in hist:
            out[r["i"]] = {"flags": ["unlisted"], "why": "the registry does not list %s" % r["new"]}
            continue
        published, publisher, yanked = hist[r["new"]]
        if published is None:
            out[r["i"]] = {"why": "no publish time"}
            continue
        flags = []
        earlier = sorted({p for v, (t, p, y) in hist.items() if p and t is not None and published is not None and t < published})
        older = [v for v, (t, p, y) in hist.items() if t is not None and published is not None and t < published]
        if published is not None and (now - published) < QUARANTINE * 86400:
            flags.append("young")
        if published is not None and not older and "young" in flags:
            flags.append("first-release")
        if publisher and earlier and publisher not in earlier:
            # a person to trusted publishing is reported plainly, at low severity; any other change is SC-061
            flags.append("ci-publishing" if publisher == CI_PUBLISHER else "publisher-change")
        if yanked:
            flags.append("yanked")
        out[r["i"]] = {"published": published, "publisher": publisher, "earlier": earlier, "flags": flags}
    return out, records, asked, time.time() - start, not_checked


def crate_publishers(chosen, ages, fetcher):
    # the record crates.io keeps of each crate the budget selects, one request a second with one retry: the publisher of
    # each version, for SC-061. The index gives no publisher, and no other crate is asked.
    import time
    names = []
    for r in chosen:
        if r["eco"] == "crates" and r["name"] not in names:
            names.append(r["name"])
    hists, whys = {}, {}
    for name in names:
        why = ""
        for attempt in (1, 2):
            got, why = fetcher.get("https://crates.io/api/v1/crates/" + name, True, False, 60)
            if got:
                try:
                    hists[name] = history("crates", name, got, set())[0]
                    why = ""
                except BaseException as e:
                    why = "the answer cannot be read: %s" % (str(e) or type(e).__name__)
                finally:
                    os.remove(got)
                if not why:
                    break
            if "time limit" in why or why.startswith("HTTP 404 "):
                break
            if attempt == 1:
                time.sleep(1)
        if why:
            whys[name] = why
    unchecked = 0
    for r in chosen:
        a = ages.get(r["i"])
        if r["eco"] != "crates" or a is None or "flags" not in a:
            continue
        hist = hists.get(r["name"])
        mine = hist.get(r["new"]) if hist else None
        if not mine:
            a["publisher_why"] = whys.get(r["name"], "crates.io lists no %s" % r["new"])
            unchecked += 1
            continue
        published, publisher = mine[0], mine[1]
        earlier = sorted({p for v, (s, p, y) in hist.items() if p and s is not None and published is not None and s < published})
        a["publisher"], a["earlier"] = publisher, earlier
        if publisher and earlier and publisher not in earlier:
            a["flags"].append("publisher-change")
    return len(names), unchecked


def tree_files(top):
    # [(path below the first folder of the archive, path below files/, absolute path)] of every file, in a fixed
    # order. npm and cargo drop the first folder of each entry as they unpack, so two entries can land on one
    # path.
    out = []
    for d, dirs, files in os.walk(top):
        dirs.sort()
        for f in sorted(files):
            full = os.path.join(d, f)
            rel = os.path.relpath(full, top).split(os.sep)
            out.append(("/".join(rel[1:]) if len(rel) > 1 else rel[0], "/".join(rel), full))
    return out


SC059_PATH = re.compile(r"(^|/)(build\.rs|setup\.py|binding\.gyp)$")
SC059_LINE = re.compile(r"\x22(preinstall|install|postinstall|prepare)\x22\s*:|proc-macro\s*=\s*true|build-backend")
SC060_LINE = re.compile(r"(child_process|execSync|spawn\(|Command::new|std::process|os\.system|subprocess|eval\(|new Function|vm\.run|fetch\(|https?://|TcpStream|reqwest|env::var|process\.env|\.config/solana|id\.json|[A-Za-z0-9+/=]{120,})")


# The sweep reads a file a line at a time, at most LINE_PIECE bytes at once, so what it holds is bounded whatever
# an archive unpacks to. It remembers the lines of an old file of at most OLD_LINES bytes, as a count of each
# hash of the line; in a newer copy of a larger one, every line counts as added. It keeps at most HITS_FILE hit lines
# a file and HITS_ENTRY an entry, and counts them all.
LINE_PIECE, OLD_LINES, HITS_FILE, HITS_ENTRY = 1 << 20, 2 * 1000 * 1000, 30, 300


def is_binary(path):
    with open(path, "rb") as f:
        return b"\0" in f.read(8192)


def file_digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def pieces(path):
    # each line of <path> with its number, a line longer than LINE_PIECE bytes in pieces of that size, each
    # with the number of the line
    with open(path, "rb") as f:
        n, whole = 0, True
        for raw in iter(lambda: f.readline(LINE_PIECE), b""):
            if whole:
                n += 1
            whole = raw.endswith(b"\n")
            yield n, raw.rstrip(b"\r\n")


def line_counts(path):
    # how many times each line of <path> occurs, by its hash; None when the file is larger than OLD_LINES
    import collections
    if os.path.getsize(path) > OLD_LINES or is_binary(path):
        return None
    counts = collections.Counter()
    for n, line in pieces(path):
        counts[hashlib.blake2b(line, digest_size=8).digest()] += 1
    return counts


class Late(Exception):
    pass


def sweep(old_top, new_top, left_out, first, stop=None):
    # the files added, changed and removed between two unpacked artifacts, by the path the package manager
    # gives each, and the added lines that match SC-059 or SC-060. <first> is the folder the registry puts
    # every entry under: an entry elsewhere, or two entries on one path, is an SC-060 hit, and every copy on a
    # shared path is read whole. Past <stop>, a time.time() value, it raises Late.
    old, new = {}, {}
    for p, rel, full in tree_files(old_top) if old_top else []:
        old.setdefault(p, []).append(full)
    for p, rel, full in tree_files(new_top):
        new.setdefault(p, []).append((rel, full))
    hits, count, binary, added, changed = [], {"SC-059": 0, "SC-060": 0}, [], 0, 0
    kept = {}

    def hit(kind, where, n, text):
        count[kind] += 1
        if kept.get(where, 0) < HITS_FILE and len(hits) < HITS_ENTRY:
            kept[where] = kept.get(where, 0) + 1
            hits.append((kind, where, n, text[:300]))
    for p in sorted(new):
        copies = new[p]
        if len(copies) > 1:
            hit("SC-060", p, 0, "%d entries of the artifact unpack to this path, and the package manager keeps one: %s"
                % (len(copies), ", ".join(rel for rel, _ in copies[:5])))
        for rel, full in copies:
            if stop is not None and time.time() > stop:
                raise Late()
            if rel.split("/")[0] != first:
                hit("SC-060", rel, 0, "an entry outside the %s/ folder the registry puts every entry under" % first)
            before = old.get(p, [])
            counts = None
            if len(copies) == 1 and len(before) == 1:
                if os.path.getsize(before[0]) == os.path.getsize(full) and file_digest(before[0]) == file_digest(full):
                    continue
                changed += 1
                was = "changed"
                counts = line_counts(before[0])
            else:
                added += 1
                was = "added"
            if SC059_PATH.search(p):
                hit("SC-059", rel, 0, "a %s file %s" % (p.rsplit("/", 1)[-1], was))
            if is_binary(full):
                binary.append(rel)
                continue
            for n, raw in pieces(full):
                if stop is not None and (n % 1000 == 0 or len(raw) > 65536) and time.time() > stop:
                    raise Late()
                if counts:
                    key = hashlib.blake2b(raw, digest_size=8).digest()
                    if counts[key] > 0:
                        counts[key] -= 1
                        continue
                line = raw.decode("utf-8", "replace")
                if SC059_LINE.search(line):
                    hit("SC-059", rel, n, line)
                if SC060_LINE.search(line):
                    hit("SC-060", rel, n, line)
    for entry in left_out:
        hit("SC-060", entry, 0, "an entry left out of the unpacked files: a link, a special file or an unsafe name")
    return {"added": added, "changed": changed, "removed": sum(1 for p in old if p not in new), "hits": hits, "count": count,
            "binary": binary}


def fetch_one(fetcher, eco, name, version, records, dest):
    # the record (from the publish-age answer when there is one), the artifact, its digest, the unpacked files;
    # nothing is asked once the call has unpacked all it may
    import contextlib, shutil
    if fetcher.unpacked >= CALL_UNPACKED:
        return False, ROOM % (CALL_UNPACKED // 1000000), []
    rec = records.get((eco, name, version))
    recfile = os.path.join(fetcher.scratch, "record.json")
    if rec is not None:
        with open(recfile, "w", encoding="utf-8") as f:
            json.dump(rec, f)
    else:
        url = ("https://registry.npmjs.org/%s/%s" % (npm_url_path(name), version) if eco == "npm"
               else "https://crates.io/api/v1/crates/%s/%s" % (name, version))
        got, why = fetcher.get(url, True)
        if not got and why.startswith("HTTP 404 ") and eco == "npm" and name.startswith("@"):
            return None, PRIVATE, []
        if not got:
            return False, why, []
        shutil.move(got, recfile)

    def quiet(fn, *args):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                return True, fn(*args), buf.getvalue()
        except SystemExit:
            return False, None, buf.getvalue()
        except Exception as why:
            return False, None, buf.getvalue() + "cannot read the answer or the artifact: %s\n" % (str(why) or type(why).__name__)
    ok, _, said = quiet(artifact, "crates" if eco == "crates" else "npm", name, version, recfile)
    if not ok:
        return False, said.strip().split("\n")[-1], []
    parts = said.strip().split("\n")[-1].split("\t")
    if len(parts) != 4:
        return False, "the registry record names no artifact", []
    url, algo, digest, filename = parts
    got, why = fetcher.get(url, size=ARTIFACT_MAX)
    if not got:
        return False, why, []
    # the digest first, so an artifact that does not match is neither kept nor unpacked
    ok, _, said = quiet(verify, got, algo, digest)
    if not ok:
        os.remove(got)
        return False, said.strip().split("\n")[-1], []
    os.mkdir(dest, 0o700)
    shutil.copyfile(got, os.path.join(dest, filename))
    os.mkdir(os.path.join(dest, "files"), 0o700)
    room = CALL_UNPACKED - fetcher.unpacked
    CAP[:] = [min(BYTES, room), "the artifact unpacks to more than 512 MiB" if room >= BYTES else ROOM % (CALL_UNPACKED // 1000000)]
    STOP[0] = fetcher.deadline
    try:
        if time.time() > STOP[0]:
            ok, said = False, LATE
        else:
            ok, _, said = quiet(unpack, got, filename, algo, digest, os.path.join(dest, "files"))
    finally:
        CAP[:] = [BYTES, "the artifact unpacks to more than 512 MiB"]
        STOP[0] = None
        os.remove(got)
    if not ok:
        shutil.rmtree(dest, ignore_errors=True)
        return False, said.strip().split("\n")[-1], []
    m = re.search(r"^unpacked: [0-9]+ files, ([0-9]+) bytes", said, re.M)
    fetcher.unpacked += int(m.group(1)) if m else 0
    left = [shown(l.strip()).split(": ")[0] for l in said.split("\n") if l.startswith("  ")]
    return True, said.strip().split("\n")[0], left


def budget(setfile, setname, scratch, outdir, outname, report, age, deadline, maxsize, agent):
    import time
    now = time.time()
    rows, odd = set_rows(setfile)
    log = open(os.path.join(outdir, "requests.txt"), "w", encoding="utf-8", errors="backslashreplace")
    fetcher = Fetcher(scratch, min(float(deadline), now + CALL_SECONDS) - MARGIN, int(maxsize), agent, log)
    out, summary = [], []
    out.append("lock-budget: %s: %d rows%s" % (setname, len(rows), "; %d lines that are not a row of the set, never sent" % odd if odd else ""))
    ages, records, asked, took, not_checked = {}, {}, 0, 0.0, {}
    if age == "on":
        ages, records, asked, took, not_checked = age_check(rows, fetcher, now, log)
    private = [r for r in rows if ages.get(r["i"], {}).get("private")]
    for r in private:
        r["public"], r["private"] = False, True
    for r in rows:
        if "young" in ages.get(r["i"], {}).get("flags", []):
            r["marks"].add("young")
    candidates, seen = [], set()
    for r in sorted((r for r in rows if r["public"] and r["eco"] in ("npm", "crates") and r["old"] != r["new"]),
                    key=lambda r: (rank(r), r["i"])):
        k = (r["eco"], r["name"], r["old"], r["new"])
        if k not in seen:
            seen.add(k)
            candidates.append(r)
    keys = [r for r in candidates if rank(r) == 0]
    pool = [r for r in candidates if 0 < rank(r) < 7]
    chosen, over = keys + pool[:BUDGET], pool[BUDGET:]
    by = {}
    for r in pool[:BUDGET]:
        name = dict((c, m) for m, c in CATEGORY)[rank(r)]
        by[name] = by.get(name, 0) + 1
    crate_asked = crate_unchecked = 0
    if age == "on":
        crate_asked, crate_unchecked = crate_publishers(chosen, ages, fetcher)
    flagged = {f: [r for r in rows if f in ages.get(r["i"], {}).get("flags", [])] for f in ("young", "first-release", "publisher-change", "ci-publishing", "yanked", "unlisted")}
    unchecked = sum(1 for r in rows if r["public"] and "why" in ages.get(r["i"], {}) and "flags" not in ages.get(r["i"], {}))
    public = [r for r in rows if r["public"]]
    if age == "on":
        line = ("publish age: %d names asked in %d s; not checked: %d of %d rows%s; under %d days: %d; first releases: %d; publisher changes: %d; from a person to CI publishing: %d; yanked: %d; not listed by the registry: %d"
                % (asked, took, unchecked, len(public), (" (" + ", ".join(sorted({a["why"] for a in ages.values() if "why" in a and "flags" not in a})[:5]) + ")") if unchecked else "",
                   QUARANTINE, len(flagged["young"]), len(flagged["first-release"]), len(flagged["publisher-change"]), len(flagged["ci-publishing"]),
                   len(flagged["yanked"]), len(flagged["unlisted"])))
        if crate_asked:
            line += "; crate publishers, the selected crates only: %d asked, %d not checked" % (crate_asked, crate_unchecked)
        if private:
            line += "; scoped packages the public registry does not list, maybe private, never fetched: %d" % len(private)
    else:
        line = "publish age: off (AUDITOR_PUBLISH_AGE=off): not checked: %d of %d rows" % (len(public), len(public))
    out.append(line)
    summary.append(line)
    if any(r["eco"] == "npm" for r in rows):
        line = "note: a registry set outside the repository (the environment, user or global npm or bun config) is not seen"
        out.append(line)
        summary.append(line)
    for r in private[:50]:
        out.append("  %s: %s %s %s (%s)" % (PRIVATE, r["eco"], r["name"], r["new"], r["lockfile"]))
    with open(os.path.join(outdir, "ages.tsv"), "w", encoding="utf-8", errors="backslashreplace") as f:
        f.write("eco\tname\tversion\tpublished\tage_days\tpublisher\tearlier_publishers\tflags\n")
        for r in public:
            a = ages.get(r["i"], {})
            t = a.get("published")
            f.write("\t".join(shown(x) for x in (r["eco"], r["name"], r["new"],
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if t else "-",
                    "%d" % ((now - t) // 86400) if t else "-", a.get("publisher") or "-",
                    ",".join(a.get("earlier", [])[:20]) or "-", ",".join(a.get("flags", [])) or a.get("why", "-"))) + "\n")
    for f, title in (("unlisted", "not listed by the registry"), ("publisher-change", "published by an account that published no earlier version"),
                     ("ci-publishing", "publisher changed from a person to CI publishing (trusted publishing; low severity)"),
                     ("first-release", "the first release of the package"), ("young", "published under %d days ago" % QUARANTINE), ("yanked", "yanked")):
        for r in flagged[f][:50]:
            a = ages[r["i"]]
            extra = ""
            if f in ("publisher-change", "ci-publishing"):
                extra = ": %s (earlier: %s)" % (a.get("publisher"), ", ".join(a.get("earlier", [])[:5]))
            out.append("  %s: %s %s %s (%s)%s" % (title, r["eco"], r["name"], r["new"], r["lockfile"], extra))
        if len(flagged[f]) > 50:
            out.append("  %s: %d more in %s/ages.tsv" % (title, len(flagged[f]) - 50, outname))
    line = ("budget: %d key handlers to compare, outside the %d-entry budget; %d entries to compare (%s); over the %d-entry budget: %d; metadata only: %d; PyPI rows, metadata only: %d; same version with a new checksum: %d; not public, never fetched (SC-061): %d; a version outside its registry grammar, never sent: %d"
            % (len(keys), BUDGET, len(pool[:BUDGET]), ", ".join("%s %d" % (m, by.get(m, 0)) for m, _ in CATEGORY), BUDGET, len(over),
               len(candidates) - len(keys) - len(pool),
               sum(1 for r in rows if r["eco"] == "pypi" and r["public"] and r["old"] != r["new"]), sum(1 for r in rows if r["old"] == r["new"]),
               sum(1 for r in rows if r["source"] != "public"), sum(1 for r in rows if r["source"] == "public" and not r["public"] and not r.get("private"))))
    out.append(line)
    summary.append(line)
    fetched = failed = 0
    failures, results, privates, late, why_not = [], [], [], [], {}
    for k, r in enumerate(chosen, 1):
        if time.time() > fetcher.deadline:
            late.append(r)
            why_not[k] = LATE
            results.append((k, r, None))
            continue
        sides = [("new", r["new"])] + ([("old", r["old"])] if r["old"] != "-" and r["oldsource"] == "public" else [])
        got = {}
        os.mkdir(os.path.join(outdir, str(k)), 0o700)
        for side, version in sides:
            dest = os.path.join(outdir, str(k), side)
            ok, said, left = fetch_one(fetcher, r["eco"], r["name"], version, records, dest)
            if ok is False and not FINAL.search(said) and fetcher.deadline - time.time() > 10:
                time.sleep(2)
                if os.path.exists(dest):
                    shutil_rm(dest)
                ok, said, left = fetch_one(fetcher, r["eco"], r["name"], version, records, dest)
            if ok is None or (not ok and said.startswith(LATE)):
                break
            if ok:
                fetched += 1
                got[side] = (os.path.join(dest, "files"), left)
            else:
                failed += 1
                failures.append("%s %s %s: %s" % (r["eco"], r["name"], version, said))
        s = None
        if ok is None:
            privates.append(r)
            why_not[k] = PRIVATE
        elif not ok and said.startswith(LATE):
            why_not[k] = LATE
        elif "new" in got and ("old" in got or len(sides) == 1):
            try:
                if time.time() > fetcher.deadline:
                    raise Late()
                s = sweep(got["old"][0] if "old" in got else None, got["new"][0], got["new"][1],
                          "package" if r["eco"] == "npm" else "%s-%s" % (r["name"], r["new"]), fetcher.deadline)
            except Late:
                why_not[k] = LATE
        if why_not.get(k) == LATE:
            late.append(r)
        results.append((k, r, s))
    line = "artifacts: %d entries, %d artifacts fetched, %d failed" % (len(chosen), fetched, failed)
    if late:
        line += "; %d entries not compared: %s" % (len(late), LATE)
    if privates:
        line += "; %d scoped packages the public registry does not list, maybe private, never fetched" % len(privates)
    out.append(line)
    summary.append(line)
    for f in failures:
        out.append("  not fetched: %s" % f)
    for k, r, s in results:
        if k in why_not:
            out.append("  not %s: %s %s %s: %s" % ("fetched" if why_not[k] == PRIVATE else "compared", r["eco"], r["name"], r["new"], why_not[k]))
    tot59 = sum(s["count"]["SC-059"] for _, _, s in results if s)
    tot60 = sum(s["count"]["SC-060"] for _, _, s in results if s)
    totbin = sum(len(s["binary"]) for _, _, s in results if s)
    line = ("sweep: SC-059 %d hits in %d entries, SC-060 %d hits in %d entries, binary files added or changed %d in %d entries; the hits are in the report"
            % (tot59, sum(1 for _, _, s in results if s and s["count"]["SC-059"]),
               tot60, sum(1 for _, _, s in results if s and s["count"]["SC-060"]),
               totbin, sum(1 for _, _, s in results if s and s["binary"])))
    out.append(line)
    summary.append(line)
    out.append("")
    out.append("== the entries compared, counts first (files under %s/<n>/new/files and old/files)" % outname)
    for k, r, s in results:
        cats = ",".join(m for m, _ in MARKS if m in r["marks"])
        if s is None:
            out.append("%d. %s %s %s -> %s [%s] not compared: %s" % (k, r["eco"], r["name"], r["old"], r["new"], cats,
                                                                     why_not.get(k, "an artifact was not fetched")))
            continue
        out.append("%d. %s %s %s -> %s [%s] SC-059 %d, SC-060 %d, binary %d; files +%d ~%d -%d%s"
                   % (k, r["eco"], r["name"], r["old"], r["new"], cats, s["count"]["SC-059"],
                      s["count"]["SC-060"], len(s["binary"]), s["added"], s["changed"], s["removed"],
                      "" if r["old"] != "-" and r["oldsource"] == "public" else "; no earlier public version: every file is new"))
    if over:
        out.append("")
        out.append("== over the %d-entry budget, metadata only" % BUDGET)
        for r in over[:200]:
            out.append("  %s %s %s -> %s [%s]" % (r["eco"], r["name"], r["old"], r["new"], ",".join(m for m, _ in MARKS if m in r["marks"])))
        if len(over) > 200:
            out.append("  ... %d more" % (len(over) - 200))
    out.append("")
    out.append("== the hits, by entry (at most 30 lines a file and 300 an entry)")
    for k, r, s in results:
        if not s or not (s["hits"] or s["binary"]):
            continue
        out.append("-- %d. %s %s %s -> %s" % (k, r["eco"], r["name"], r["old"], r["new"]))
        for kind, p, n, text in s["hits"]:
            out.append("%s %s:%d: %s" % (kind, shown(p), n, shown(text.strip())[:240]))
        for p in s["binary"][:30]:
            out.append("binary %s" % shown(p))
        extra = s["count"]["SC-059"] + s["count"]["SC-060"] - len(s["hits"])
        if extra > 0:
            out.append("  ... %d more hits in this entry" % extra)
    log.close()
    with open(report, "w", encoding="utf-8", errors="backslashreplace") as f:
        f.write("\n".join(clean(x) if x else "" for x in out) + "\n")
    for line in summary:
        print(">> " + clean(line))
    if late or failed:
        said = []
        if late:
            said.append("%d of %d selected entries were not compared: %s" % (len(late), len(chosen), LATE))
        if failed:
            said.append("%d of %d selected artifacts could not be fetched" % (failed, failed + fetched))
        print("; ".join(said))
        sys.exit(3)
    flags = tot59 + tot60 + totbin + sum(len(v) for v in flagged.values())
    sys.exit(1 if flags else 0)


def shutil_rm(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


try:
    what = sys.argv[1]
    if what == "time":
        npm_time(sys.argv[2], sys.argv[3])
    elif what == "artifact":
        artifact(*sys.argv[2:6])
    elif what == "verify":
        verify(*sys.argv[2:5])
    elif what == "unpack":
        unpack(*sys.argv[2:7])
    elif what == "plan":
        services(sys.argv[2], sys.argv[3])
    elif what == "budget":
        budget(*sys.argv[2:12])
except SystemExit:
    raise
except BaseException as why:
    fail("cannot read the answer or the artifact: %s" % (str(why) or type(why).__name__))
'
registry_py() { (cd / && exec python3 -I -c "$REGISTRY_PY" "$@"); }
# registry_watched <out> <argument>...: registry_py under the watchdog, for the steps that read an artifact
# (a gzip stream can unpack to far more than it weighs); its output in <out>, STEP_END set.
registry_watched() {
  local out=$1
  shift
  STEP_OUT=$out
  step / python3 -I -c "$REGISTRY_PY" "$@"
  STEP_OUT=""
  [ "$STEP_END" = "exit 0" ]
}

# npm names in a URL path: a scoped name's / as %2F.
npm_path() { case "$1" in @*/*) printf '%s%%2F%s' "${1%%/*}" "${1#*/}" ;; *) printf '%s' "$1" ;; esac; }

# ---- the actions --------------------------------------------------------------------------------------
# lock_note <why>: the lockfile check of cargo-audit stopped on <why>. Strict mode stops the run there
# (OUTPUT-RULES.md Rule 11f); otherwise cargo audit runs without its check for yanked releases, the one
# request a lockfile's registry could get, and a note, on stdout and in the output, says so.
lock_note() {
  local note
  [ "$CONFINE_STRICT" = 0 ] || done_with 3 "${1:-cannot read the lockfile}"
  case "$1" in
    'the lockfile names a registry other than crates.io, '*)
      note=${1#the lockfile names a registry other than crates.io, }
      note="the lockfile names a registry other than crates.io (${note%%, which a check for yanked releases could ask*}), so cargo audit ran without its yanked check, which would ask that registry" ;;
    *) note="${1:-deps.sh cannot read the lockfile}, so cargo audit ran without its yanked check, which could ask a registry the lockfile names" ;;
  esac
  [ "$NO_FETCH" = 0 ] || note="${1:-deps.sh cannot read the lockfile}; cargo audit ran offline (--no-fetch), so it asks no registry"
  printf '>> note: %s; strict mode stops here (Rule 11f)\n' "$note"
  printf '>> note: %s; strict mode stops here (Rule 11f)\n' "$note" >&9
  YANKED=0
}
case "$ACTION" in
  cargo-audit)
    pin_rust
    copy_manifests
    AUD=(cargo audit --color never)
    YANKED=1
    if [ "$NO_FETCH" = 1 ]; then
      why=$(cargo_py locksource "$S/w" "$LOCK") || lock_note "$why"
      AUD+=(--no-fetch --no-yanked)
    else
      why=$(cargo_py locksource "$S/w" "$LOCK" registries) || lock_note "$why"
      [ "$YANKED" = 1 ] || AUD+=(--no-yanked)
      disclose github.com "advisory database (git fetch of the RustSec database)" https://github.com/RustSec/advisory-db
      [ "$YANKED" = 0 ] ||
        disclose crates.io "every crates.io package name in this lockfile (cargo audit's check for yanked releases, the crates.io index)" "$LOCK"
    fi
    step "$S/w/$(dir_of "$LOCK")" ${NET[@]+"${NET[@]}"} "${AUD[@]}"
    why=$(stopped)
    [ -z "$why" ] || done_with 3 "cargo audit stopped: $why"
    if [ "$STEP_END" = "exit 0" ]; then done_with 0 "no vulnerability found (exit 0)"; fi
    found=$(grep -cE '^error: [0-9]+ vulnerabilit(y|ies) found' "$OUT")
    [ "${found:-0}" = 0 ] || done_with 1 "vulnerabilities found ($STEP_END)"
    done_with 3 "cargo audit failed ($STEP_END): no advisory database, or a lockfile it cannot read" ;;
  cargo-outdated|cargo-tree)
    pin_rust
    copy_manifests
    TOMLS=()
    for rel in "${MAN[@]}"; do case "$rel" in Cargo.toml|*/Cargo.toml) TOMLS+=("$rel") ;; esac; done
    # Second line (the rebuild below is the first): refuse a manifest the line scan cannot read with
    # confidence, and note a plainly spelled [patch] or [replace] table, which the rebuilt tree does not apply.
    notes=$(cargo_py backstop "$CRATE_SPEC" "$S/w" "${TOMLS[@]}") || done_with 3 "${notes:-cannot read the manifests}"
    if [ -n "$notes" ]; then
      printf '%s\n' "$notes" >&2
      printf '%s\n' "$notes" >&9
    fi
    [ -z "$LOCK" ] || { why=$(cargo_py locksource "$S/w" "$LOCK") || done_with 3 "${why:-cannot read the lockfile}"; }
    why=$(cargo_py stubs "$S/w" "${TOMLS[@]}") || done_with 3 "${why:-cannot prepare the copies}"
    STEP_OUT=$S/metadata.json
    step "$S" CARGO_NET_OFFLINE=true cargo metadata --no-deps --format-version 1 --offline --manifest-path "$S/w/$TOML"
    STEP_OUT=""
    [ "$STEP_END" = "exit 0" ] || done_with 3 "cargo cannot read the copied manifests ($STEP_END)"
    why=$(cargo_py vet "$S/metadata.json" "$S/w") || done_with 3 "${why:-cannot read cargo metadata}"
    # Rebuild a workspace of only the names, versions and dependency entries cargo metadata reports, so no
    # [patch], [replace] or other table of the copy reaches the resolving cargo. cargo runs on it, never on
    # the copy. The lockfile is a preference, not enforced: the rebuild drops any [patch] the lock reflects.
    mkdir "$S/rebuilt" || done_with 3 "cannot create the rebuilt manifests in $S"
    RTOML=$(cargo_py rebuild "$S/metadata.json" "$S/w" "$S/rebuilt") || done_with 3 "${RTOML:-cannot rebuild the manifests}"
    [ -z "$LOCK" ] || iso_copy_new "$S/w/$LOCK" "$S/rebuilt/Cargo.lock" || done_with 3 "cannot copy the lockfile"
    mkdir "$S/nogit" && printf '#!/bin/sh\necho "deps.sh: git sources are not fetched" >&2\nexit 1\n' > "$S/nogit/git" && chmod 700 "$S/nogit/git" ||
      done_with 3 "cannot prepare the git that refuses fetches"
    disclose crates.io "the crate names and version requirements in these manifests ($ACTION resolves them with the crates.io index and downloads)" "${MAN[@]}"
    GITLESS=("PATH=$S/nogit:$PATH" CARGO_NET_GIT_FETCH_WITH_CLI=true)
    if [ "$ACTION" = cargo-tree ]; then
      step "$S" ${NET[@]+"${NET[@]}"} "${GITLESS[@]}" cargo tree --workspace --color never --manifest-path "$RTOML"
      why=$(stopped)
      [ -z "$why" ] || done_with 3 "cargo tree stopped: $why"
      [ "$STEP_END" = "exit 0" ] && done_with 0 "the dependency tree, from the rebuilt manifests (exit 0)"
      done_with 3 "cargo tree failed ($STEP_END)"
    fi
    step "$S" ${NET[@]+"${NET[@]}"} "${GITLESS[@]}" cargo outdated --workspace --exit-code 1 --color never --manifest-path "$RTOML"
    why=$(stopped)
    [ -z "$why" ] || done_with 3 "cargo outdated stopped: $why"
    case "$STEP_END" in
      'exit 0') done_with 0 "no outdated dependency, from the rebuilt manifests (exit 0)" ;;
      'exit 1') done_with 1 "outdated dependencies found, from the rebuilt manifests (exit 1)" ;;
      *) done_with 3 "cargo outdated failed ($STEP_END)" ;;
    esac ;;
  npm-audit)
    copy_manifests
    W=$S/w/$(dir_of "$TOML")
    mkdir "$S/npm" && : > "$S/npm/userconfig" && : > "$S/npm/globalconfig" &&
      printf 'registry=https://registry.npmjs.org/\nignore-scripts=true\nfund=false\nupdate-notifier=false\n' > "$W/.npmrc" ||
      done_with 3 "cannot write npm's config in $S"
    disclose npmjs.org "every package name and version in this lockfile (npm audit's bulk advisory request)" "$LOCK"
    step "$W" ${NET[@]+"${NET[@]}"} npm_config_userconfig="$S/npm/userconfig" npm_config_globalconfig="$S/npm/globalconfig" \
      npm_config_registry=https://registry.npmjs.org/ npm_config_cache="$S/npm/cache" npm_config_logs_dir="$S/npm/logs" \
      npm_config_update_notifier=false npm_config_fund=false npm_config_ignore_scripts=true COREPACK_ENABLE_PROJECT_SPEC=0 npm audit
    why=$(stopped)
    [ -z "$why" ] || done_with 3 "npm audit stopped: $why"
    [ "$STEP_END" != "exit 0" ] || done_with 0 "no vulnerability found (exit 0)"
    found=$(grep -c '^# npm audit report' "$OUT")
    [ "${found:-0}" = 0 ] || done_with 1 "vulnerabilities found ($STEP_END)"
    done_with 3 "npm audit failed ($STEP_END)" ;;
  npm-view|npm-time)
    if [ "$ACTION" = npm-time ]; then
      disclose npmjs.org "package name (the registry's record, for its publish times)" "$NAME"
      get "https://registry.npmjs.org/$(npm_path "$NAME")" "$S/body" json
      what=$NAME
    else
      if [ -n "$VER" ]; then
        disclose npmjs.org "package name and version (the registry's record)" "$NAME@$VER"
        get "https://registry.npmjs.org/$(npm_path "$NAME")/$VER" "$S/body" json
        what=$NAME@$VER
      else
        disclose npmjs.org "package name (the registry's record of its latest version)" "$NAME"
        get "https://registry.npmjs.org/$(npm_path "$NAME")/latest" "$S/body" json
        what=$NAME
      fi
    fi
    if [ "$HTTP" = 200 ] && [ "$ACTION" = npm-time ]; then
      why=$(registry_py time "$S/body" "$S/time.json") || done_with 3 "the registry's answer cannot be read: $why"
      keep "$S/time.json"
      done_with 0 "the publish times of $what (HTTP 200)"
    fi
    [ -e "$S/body" ] || : > "$S/body"
    keep "$S/body"
    case "$HTTP" in
      200) done_with 0 "$what (HTTP 200)" ;;
      404) done_with 1 "the npm registry has no $what (HTTP 404)" ;;
      *) done_with 3 "the npm registry answered HTTP $HTTP for $what" ;;
    esac ;;
  crate-info|pypi-info)
    if [ "$ACTION" = crate-info ]; then
      if [ -n "$VER" ]; then
        disclose crates.io "crate name and version (the crates.io API)" "$NAME@$VER"
        get "https://crates.io/api/v1/crates/$NAME/$VER" "$S/body" json
      else
        disclose crates.io "crate name (the crates.io API)" "$NAME"
        get "https://crates.io/api/v1/crates/$NAME" "$S/body" json
      fi
      reg=crates.io
    else
      if [ -n "$VER" ]; then
        disclose pypi.org "project name and version (the PyPI JSON API)" "$NAME@$VER"
        get "https://pypi.org/pypi/$NAME/$VER/json" "$S/body" json
      else
        disclose pypi.org "project name (the PyPI JSON API)" "$NAME"
        get "https://pypi.org/pypi/$NAME/json" "$S/body" json
      fi
      reg=PyPI
    fi
    what=$NAME${VER:+@$VER}
    [ -e "$S/body" ] || : > "$S/body"
    keep "$S/body"
    case "$HTTP" in
      200) done_with 0 "$what (HTTP 200)" ;;
      404) done_with 1 "$reg has no $what (HTTP 404)" ;;
      *) done_with 3 "$reg answered HTTP $HTTP for $what" ;;
    esac ;;
  fetch-artifact)
    case "$ECO" in
      crates)
        disclose crates.io "crate name and version (the crates.io API, then the .crate download)" "$NAME@$VER"
        get "https://crates.io/api/v1/crates/$NAME/$VER" "$S/record" json
        reg=crates.io ;;
      npm)
        disclose npmjs.org "package name and version (the registry's record, then the tarball)" "$NAME@$VER"
        get "https://registry.npmjs.org/$(npm_path "$NAME")/$VER" "$S/record" json
        reg="the npm registry" ;;
      pypi)
        disclose pypi.org "project name and version (the PyPI JSON API)" "$NAME@$VER"
        get "https://pypi.org/pypi/$NAME/$VER/json" "$S/record" json
        reg=PyPI ;;
    esac
    case "$HTTP" in
      200) ;;
      404) printf 'HTTP 404: %s has no %s %s\n' "$reg" "$NAME" "$VER" > "$S/report"; keep "$S/report"; done_with 1 "$reg has no $NAME $VER (HTTP 404)" ;;
      *) printf 'HTTP %s from %s for %s %s\n' "$HTTP" "$reg" "$NAME" "$VER" > "$S/report"; keep "$S/report"; done_with 3 "$reg answered HTTP $HTTP for $NAME $VER" ;;
    esac
    line=$(registry_py artifact "$ECO" "$NAME" "$VER" "$S/record") || { printf '%s\n' "$line" > "$S/report"; keep "$S/report"; done_with 3 "$line"; }
    aurl=${line%%$'\t'*}; rest=${line#*$'\t'}
    algo=${rest%%$'\t'*}; rest=${rest#*$'\t'}
    digest=${rest%%$'\t'*}; afile=${rest#*$'\t'}
    [ -n "$afile" ] || done_with 3 "the registry's record names no artifact"
    [ "$ECO" != pypi ] || disclose pythonhosted.org "the release file (download)" "$afile"
    get "$aurl" "$S/artifact"
    [ "$HTTP" = 200 ] || { printf 'HTTP %s for %s\n' "$HTTP" "$aurl" > "$S/report"; keep "$S/report"; done_with 3 "the download of $aurl answered HTTP $HTTP"; }
    { printf 'artifact: %s %s %s\n' "$ECO" "$NAME" "$VER"; printf 'from: %s\n' "$aurl"; } > "$S/report"
    if ! registry_watched "$S/verify" verify "$S/artifact" "$algo" "$digest"; then
      why=$(stopped)
      [ -n "$why" ] || why=$(cat "$S/verify" 2>/dev/null)
      printf '%s\n' "$why" >> "$S/report"
      keep "$S/report"
      done_with 3 "${why:-the digest could not be checked}"
    fi
    keep "$S/report"
    AD=$DEPS/$ACTION-$N
    confine_mkdir "$AD" && confine_mkdir "$AD/files" || done_with 3 "cannot create $R/deps/$ACTION-$N"
    iso_copy_new "$S/artifact" "$AD/$afile" || done_with 3 "cannot keep the artifact in $R/deps/$ACTION-$N"
    registry_watched "$S/unpacked" unpack "$S/artifact" "$afile" "$algo" "$digest" "$AD/files" && rc=0 || rc=1
    result=$(cat "$S/unpacked" 2>/dev/null)
    why=$(stopped)
    [ -z "$why" ] || result=${result:+$result$'\n'}"the unpack $why"
    printf '%s\n' "$result" >> "$DEPS/$ACTION-$N.txt"
    [ "$rc" = 0 ] || done_with 3 "${result##*$'\n'}"
    done_with 0 "$NAME $VER, its $algo digest as $reg gives it, unpacked into $R/deps/$ACTION-$N/files" ;;
  lock-budget)
    plan=$(registry_py plan "$WT/$SETF" "$AGE") || done_with 3 "${plan:-the set cannot be read}"
    for svc in $plan; do
      case "$svc:$AGE" in
        npmjs.org:on) disclose npmjs.org "the name of each new npm package in this set (its registry record: publish times and publishers), then the tarballs of the versions its budget selects" "$SETF" ;;
        npmjs.org:off) disclose npmjs.org "the npm versions this set's budget selects (each version's registry record, then its tarball)" "$SETF" ;;
        crates.io:on) disclose crates.io "the name of each new crate in this set (its entry in the crates.io index, for publish times; crates.io's record of the crates its budget selects, for their publishers), then the .crate files of the versions it selects" "$SETF" ;;
        crates.io:off) disclose crates.io "the crate versions this set's budget selects (each version's crates.io record, then its .crate download)" "$SETF" ;;
        pypi.org:on) disclose pypi.org "the name of each new PyPI project in this set (its PyPI JSON record: upload times)" "$SETF" ;;
      esac
    done
    : > "$S/head"
    keep "$S/head"
    AD=$DEPS/$ACTION-$N
    confine_mkdir "$AD" || done_with 3 "cannot create $R/deps/$ACTION-$N"
    STEP_OUT=$S/summary
    step / ${NET[@]+"${NET[@]}"} python3 -I -c "$REGISTRY_PY" budget "$WT/$SETF" "$SETF" "$S" "$AD" "$R/deps/$ACTION-$N" "$S/report" "$AGE" "$DEADLINE" "$GET_MAX" "$UA"
    STEP_OUT=""
    [ ! -f "$S/report" ] || cat "$S/report" >> "$DEPS/$ACTION-$N.txt"
    [ ! -f "$S/summary" ] || grep '^>> ' "$S/summary"
    why=$(stopped)
    [ -z "$why" ] || done_with 3 "lock-budget stopped: $why"
    case "$STEP_END" in
      'exit 0') done_with 0 "nothing flagged" ;;
      'exit 1') done_with 1 "rows or hits flagged, counts first in the report" ;;
      *) last=$(tail -n 1 "$S/summary" 2>/dev/null); done_with 3 "${last:-lock-budget failed ($STEP_END)}" ;;
    esac ;;
esac
