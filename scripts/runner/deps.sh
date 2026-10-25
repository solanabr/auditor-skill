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
#                   index which releases were yanked. With --no-fetch it adds --no-fetch --no-yanked: the
#                   database already in CARGO_HOME, and nothing leaves the machine.
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
#                   left out and listed, as an SC-060 hit. At most 50000 entries and 512 MiB unpacked.
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
# the run (cargo would fetch from a host the manifest chose); cargo is told to fetch git sources with the git
# CLI, and the git on its PATH refuses every fetch. A plainly spelled [patch.<registry>] or [replace] table
# runs, with a note on stderr and in the output naming the crates it patches (the reported tree leaves them
# unpatched). As a second line, a manifest spelled as no Cargo.toml needs stops the run: a [patch] or
# [replace] table header with a quoted first key or as an array of tables, a table header with a \u, \U or
# \x escape, or anything before the first table header but comments and a one-line cargo-features; and so
# does a copied Cargo.lock that names a source other than crates.io, holds a patch table or has such an
# escape. The first Cargo.toml is the one cargo runs on. npm-audit runs npm with its own .npmrc in the
# copy (registry https://registry.npmjs.org/, ignore-scripts, no fund or update notices), empty user and
# global config files, and its cache and logs in the scratch directory: no auth reaches it.
#
# Names. npm: [@<scope>/]<name>, of letters, digits and -._~, not starting with . or _, at most 214
# bytes; crates: a letter, then letters, digits, - and _, at most 64; PyPI: letters, digits and -._,
# starting and ending with a letter or digit, at most 100. Versions: <n>.<n>.<n>, with an optional
# -<pre-release> and +<build>, for npm and crates; for PyPI, a digit, then digits, letters and .!+_-.
#
# Hosts. registry.npmjs.org; crates.io, index.crates.io and static.crates.io; pypi.org, and the
# files.pythonhosted.org URLs PyPI's record names; github.com, for the RustSec database. Registry queries
# run curl -q (no .curlrc), https only, with no redirects and at most 100 MiB. Before the first request to
# each service, one row goes to <R>/disclosures.tsv: time, tool, service, what was sent, and a count.
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
confine_init deps "$root"
confine_need env git find grep mkdir mktemp rm chmod cat wc date
WT=$CONFINE_WT

USAGE='usage: deps.sh <action> --run <R> [--manifest <path>]... [--no-fetch] [<word>...], with the actions cargo-audit, cargo-outdated, cargo-tree, npm-audit, npm-view, npm-time, crate-info, pypi-info and fetch-artifact'
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
  cargo-audit|cargo-outdated|cargo-tree|npm-audit|npm-view|npm-time|crate-info|pypi-info|fetch-artifact) ;;
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
esac

CAP=${AUDITOR_RUN_TIMEOUT:-1800}
{ case "$CAP" in ''|*[!0-9]*) false ;; *) [ "${#CAP}" -le 5 ] && [ "$CAP" -ge 1 ] && [ "$CAP" -le 86400 ] ;; esac; } ||
  refuse "AUDITOR_RUN_TIMEOUT is '$(confine_text "$CAP")', not a whole number of seconds from 1 to 86400"
LIMIT=$((10#$CAP))
iso_tmp_outside
iso_disclosures_ok "$R" || refuse "$R/disclosures.tsv is not a regular file with one link whose first line is the header, so no row can be added to it"

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
  iso_disclose "$R" "$TOOL" "$@" || blocker "cannot add a row to $R/disclosures.tsv, so nothing was sent"
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
# <lockfile>": refuse a Cargo.lock that names a source other than crates.io, holds a patch/replace table, or
# has such an escape. "stubs <top> <manifest>...": an empty file at src/lib.rs and at
# each target path of each package manifest, so cargo metadata parses it. "vet <metadata> <top>": the
# dependencies cargo metadata lists come from crates.io or are paths inside <top> (exit 3 with the first that
# is not). "rebuild <metadata> <top> <dest>": write under <dest> a workspace of only the package names,
# versions, editions, features and dependency entries cargo metadata reports (a path dependency on a
# non-member is refused), so no [patch], [replace] or other table of the copy reaches the resolving cargo,
# whatever its spelling; prints the rebuilt root manifest path.
CARGO_PY='import json, os, re, sys

SECTION = re.compile(r"^\s*\[\[?\s*([A-Za-z0-9_.\-]+)\s*\]\]?\s*(#.*)?$")
KEY = re.compile(r"^\s*(name|path|build)\s*=\s*\x22([^\x22\\]*)\x22\s*(#.*)?$")
DEFAULT = {"bin": "src/bin/%s.rs", "example": "examples/%s.rs", "test": "tests/%s.rs", "bench": "benches/%s.rs"}
OVR_HEADER = re.compile(r"^\s*\[\[?\s*[\x22\x27]?(patch|replace)\b")
OVR_ROOTKEY = re.compile(r"^\s*[\x22\x27]?(patch|replace)[\x22\x27]?\s*[.=]")
OVR_OPEN = re.compile(r"^\s*\[")
ESCAPE = re.compile(r"\\[uUx]")
CARGO_FEATURES = re.compile(r"cargo-features[ \t]*=[ \t]*\[[A-Za-z0-9_\x22, \t-]*\][ \t]*(#.*)?")
LOCK_PATCH = re.compile(r"^\s*\[\[?\s*[\x22\x27]?(patch|replace)\b")
LOCK_SOURCE = re.compile(r"^\s*[\x22\x27]?source[\x22\x27]?\s*=\s*[\x22\x27]([^\x22\x27]*)")
CRATES = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")
SEG = r"(?:[A-Za-z0-9_-]+|\x22[^\x22\\]*\x22|\x27[^\x27]*\x27)"
PLAIN_PATCH = re.compile(r"\s*\[\s*patch\s*\.\s*(" + SEG + r")\s*(?:\.\s*(" + SEG + r")\s*)?\]\s*(?:#.*)?")
PLAIN_REPLACE = re.compile(r"\s*\[\s*replace\s*(?:\.\s*(" + SEG + r")\s*)?\]\s*(?:#.*)?")
ENTRY_KEY = re.compile(r"^\s*(" + SEG + r")\s*[.=]")
NAMES_SHOWN = 20


def fail(text):
    print(text)
    sys.exit(3)


def shown(text):
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(text))[:200]


def relative(rel):
    return bool(rel) and not rel.startswith("/") and ".." not in rel.split("/")


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
    return re.split(r"[:@]", spec, 1)[0]


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


def locksource(top, rel):
    # Refuse a Cargo.lock that names a source other than crates.io, holds a patch/replace table, or has a \u,
    # \U or \x escape (cargo writes none): with the rebuilt manifest cargo re-resolves such an entry to
    # crates.io, but refusing it keeps the lock to the same hosts.
    for line in read_lines(os.path.join(top, rel), rel):
        if ESCAPE.search(line):
            fail("the lockfile has a \\u, \\U or \\x escape, which cargo never writes; deps.sh does not read one")
        if LOCK_PATCH.match(line):
            fail("the lockfile holds a patch or replace table")
        m = LOCK_SOURCE.match(line)
        if m and m.group(1) and m.group(1) not in CRATES:
            fail("the lockfile names a source other than crates.io: %s" % shown(m.group(1)))


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
    data = json.load(open(meta, encoding="utf-8"))
    root = os.path.realpath(data["workspace_root"])
    ids = set(data.get("workspace_members") or [])
    pkgs = [p for p in data.get("packages", []) if p.get("id") in ids]
    if not pkgs:
        fail("cargo metadata lists no workspace member to rebuild")
    members = {}
    for p in pkgs:
        members[member_dir(p)] = os.path.relpath(member_dir(p), root)
    rels = sorted(members.values())
    have_root_pkg = False
    for p in pkgs:
        rel = members[member_dir(p)]
        d = os.path.join(dest, rel)
        os.makedirs(d, exist_ok=True)
        os.close(os.open(os.path.join(d, "lib.rs"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
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
        with open(os.path.join(d, "Cargo.toml"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    if not have_root_pkg:
        with open(os.path.join(dest, "Cargo.toml"), "w", encoding="utf-8") as f:
            f.write("[workspace]\nmembers = [%s]\nresolver = %s\n" % (", ".join(q(r) for r in rels), q("2")))
    print(os.path.join(dest, "Cargo.toml"))


try:
    cmd = sys.argv[1]
    if cmd == "stubs":
        stubs(sys.argv[2], sys.argv[3:])
    elif cmd == "backstop":
        backstop(sys.argv[2], sys.argv[3], sys.argv[4:])
    elif cmd == "locksource":
        locksource(sys.argv[2], sys.argv[3])
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
REGISTRY_PY='import base64, hashlib, json, os, re, stat, sys, tarfile, zipfile

FILES, BYTES = 50000, 512 * 1024 * 1024
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


def unpack(archive, filename, algo, expected, dest):
    got = verify(archive, algo, expected)
    weak = "" if algo != "sha1" else " (weak: the npm registry offered no sha512 integrity for this version, only a sha1 shasum; sha1 is collision-weak, so this is not a strong content check)"
    print("digest: %s %s, as the registry gives it%s" % (algo, got, weak))
    entries, skipped = [], []
    if filename.endswith((".whl", ".zip")):
        z = zipfile.ZipFile(archive)
        for info in z.infolist():
            mode = (info.external_attr >> 16) & 0o170000
            if info.filename.endswith("/"):
                kind = "dir"
            elif mode in (0, stat.S_IFREG):
                kind = "file"
            else:
                kind = "symbolic link" if mode == stat.S_IFLNK else "special file"
            entries.append((info.filename, kind, info.file_size, info))
        opener = lambda e: z.open(e[3])
    else:
        t = tarfile.open(archive, "r:*")
        for m in t.getmembers():
            kind = "file" if m.isfile() else "dir" if m.isdir() else "symbolic link" if m.issym() else \
                "hard link" if m.islnk() else "special file"
            entries.append((m.name, kind, m.size if m.isfile() else 0, m))
        opener = lambda e: t.extractfile(e[3])
    if len(entries) > FILES:
        fail("the artifact holds %d entries, more than %d" % (len(entries), FILES))
    if sum(e[2] for e in entries if e[1] == "file") > BYTES:
        fail("the artifact unpacks to more than 512 MiB")
    files = dirs = size = 0
    for e in entries:
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
except SystemExit:
    raise
except BaseException as why:
    fail("cannot read the answer or the artifact: %s" % why)
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
case "$ACTION" in
  cargo-audit)
    pin_rust
    copy_manifests
    AUD=(cargo audit --color never)
    if [ "$NO_FETCH" = 1 ]; then
      AUD+=(--no-fetch --no-yanked)
    else
      disclose github.com "advisory database (git fetch of the RustSec database)" https://github.com/RustSec/advisory-db
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
      npm_config_update_notifier=false npm_config_fund=false npm_config_ignore_scripts=true npm audit
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
esac
