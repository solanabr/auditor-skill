#!/bin/bash
# target.sh — builds and tests the code under audit in the execution mode recorded for the run
# (OUTPUT-RULES.md Rule 11a, QUESTIONS.md Q46), from a scratch copy outside the working directory.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/runner/target.sh" <action> --run <R> --src <dir | <R>/src[-<k>].git>
#       [--rev <commit>] [--dir <path>] [--patch <R>/patches/<ID>.patch] [--package <name>]
#       [--program <name>] [--timeout <seconds>] [--mode none|isolated|native]
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under
# audit. A refusal is one stderr line, "target: refused: <reason>", with exit 64, before anything is
# copied; a blocker is one stderr line, "target: blocker: <reason>", with exit 3.
#
# The actions. Each runs a fixed command line in the copy, at --dir or at its top:
#   anchor-build  anchor build --ignore-keys --no-idl [--tools-version <v>] [-p <program>] -- --skip-tools-install
#                 --offline. --ignore-keys only where anchor build --help lists it (Anchor 1.0 and later); --no-idl
#                 where this anchor builds its IDL with cargo test (anchor build --help lists --no-idl and anchor
#                 idl build --help --out-ts: Anchor 0.30 and later). <v> is anchor build's own --tools-version
#                 where it has one (Anchor 1.2 and later), else it goes after --
#   anchor-test   npm ci --ignore-scripts --no-audit --no-fund when that directory holds package-lock.json,
#                 then the anchor-build command, then, where --no-idl was used, anchor idl build -p <program> -o
#                 target/idl/<program>.json -t target/types/<program>.ts for each program built, in a step with
#                 no build-sbf options and no RUSTUP_TOOLCHAIN (the pin goes into a rust-toolchain.toml that
#                 target.sh writes at the top of the copy, once the copy's own rust-toolchain files are
#                 removed), then anchor test --skip-build --skip-deploy --skip-local-validator --provider.cluster
#                 localnet --provider.wallet <the throwaway keypair> [-p <program>]: the test script runs against
#                 no validator and nothing is deployed
#   build-sbf     cargo build-sbf --skip-tools-install --offline --sbf-out-dir <scratch> [--tools-version <v>]
#                 [--manifest-path <the Cargo.toml of --package>]
#   cargo-test    cargo test --offline, with -p <package> or --workspace
#   clippy        cargo clippy --offline --all-targets, with -p <package> or --workspace, -- -W clippy::all
#                 -W clippy::pedantic
#   npm-ci        npm ci --ignore-scripts --no-audit --no-fund (checklist 11 SC-012)
# --package names a cargo package (build-sbf, cargo-test, clippy) and --program an Anchor program
# (anchor-build, anchor-test). <v> is TOOLS_VERSION from the environment, v<n>.<n> or v<n>.<n>.<n>; without
# it cargo build-sbf uses its own default, except that for an anchor action target.sh installs the platform
# tools that anchor asks cargo build-sbf for, learned from one anchor build --no-idl with a recording
# cargo-build-sbf first on PATH (Anchor 1.2 asks for v1.57). A build that then finds no core crate for its
# target stops (exit 3) and names TOOLS_VERSION.
#
# The mode is the stricter of <R>/exec-mode (one word, none, isolated or native, written when the human
# answers Q46), AUDITOR_EXEC_MODE and strict mode (OUTPUT-RULES.md Rule 11f), which counts as isolated: none,
# then isolated, then native. With none of them it is native, and a note says so. With none, or with a
# --mode that names another mode, target.sh stops (exit 3) before it copies anything. In isolated mode the
# credential self-check of scripts/lib/isolation.sh runs first: something it reads that is readable, or a
# check that cannot finish, stops the run, and the blocker says what the human changes to build natively
# instead, or in strict mode why it cannot. In native mode the same check prints, as a warning, what the
# code the run builds can read, by kind and count, never a path. An incident's code (--run incident_<n>) is
# built only once incident_<n>/INCIDENTS.json (a regular file of at most 4 MiB) records the root_cause_class
# of the incident --patch names (INC-<n>.<k>), or of every incident without one. In native mode it needs
# every incident's, whatever --patch names, and builds nothing while any incident is supply_chain_or_ci: a
# patch of one incident builds the same tree as the others. And natively nothing is built, whatever --run
# names, while the INCIDENTS.json of any run directory of the auditor's in the working directory
# (incident_<n>, with the .gitignore of exactly * that scripts/rundir.sh writes) records a
# supply_chain_or_ci incident or cannot be read, or the working directory cannot be listed, since every
# --src is the working tree or a copy of it; a run directory without INCIDENTS.json, or whose file records no
# incident, counts for nothing, and any other incident_* directory (a client's Incident_Response/, a run
# moved aside) is passed over, with a note (OUTPUT-RULES.md Rule 11a).
#
# The copy, in a scratch directory outside the working directory. A --src that is the top level of a git
# repository as scripts/lib/confine.sh's confine_repo takes it, or a copy git-ro.sh copy made in <R>, is
# cloned with --no-local, no hooks and no submodules, system and global git config dropped, so git's ownership
# check stays on in both modes. confine_repo takes a git directory inside the working directory that holds no
# symbolic link, borrows no objects (objects/info/alternates) and rewrites no parents (info/grafts); outside
# strict mode it also takes a separate git directory that git's own layout ties back to the work tree, a link
# in a hooks directory, and alternates and grafts, each of the last two with a note, while a separate git
# directory that nothing ties back is refused in both modes. A partial clone stops the run. Outside strict
# mode, --src . in a session started below the top level of a repository takes that repository, as
# scripts/lib/confine.sh's confine_repo accepts it, and --dir is then a path from its top. --rev (HEAD when
# absent) must name a commit, which is checked out; --patch, a file in <R>/patches/ of at most 16 MiB, is
# applied with git apply --index. With a git that lacks the May-2024 clone fixes, or a source another user
# owns (which that check refuses), target.sh never clones: outside strict mode it writes the tracked files of
# that commit itself, from git ls-tree and git cat-file --batch through hgit_tree (no path with an empty, . or
# .. component or a .git, none written through a symbolic link), into a new repository that holds no commit,
# and applies --patch with git apply, and a note says so, since a copy never runs the source repository's
# configured code; strict mode stops (exit 3) at the old git, and refuses a source another user owns
# (exit 64). A revision that has submodules stops the run in strict mode, since target.sh never fetches them;
# outside it, a note says so and the build sees them as empty directories. Any other directory --src names is
# copied file by file, symbolic links kept as links, without audit_*, incident_* and .audit-memory at its top,
# and without target/ or node_modules/ directories, each name in any letter case; --rev and --patch need a
# repository. --dir is a path inside the copy with no symbolic link on the way.
#
# The environment of every step is the cleaned one of scripts/lib/isolation.sh: env -i, a throwaway HOME
# holding a fresh Solana keypair, TMPDIR in the scratch directory, the cleaned PATH, the user's CARGO_HOME,
# RUSTUP_HOME and AVM_HOME, and RUSTUP_TOOLCHAIN pinned to the caller's value, with RUSTUP_AUTO_INSTALL=0.
# Without one it is rustup's default, except outside strict mode when the copy's top-level rust-toolchain (or,
# without it, rust-toolchain.toml) names a plain channel, and no path, that rustup has installed: then that
# channel, and a note says so, as it does when the channel is not installed or the file names no plain
# channel. The downloads come first, and none of them runs code from the copy: cargo fetch, started outside
# the copy so that the copy's .cargo/config is not read either; cargo build-sbf --install-only, with the real
# HOME, where the platform tools live; and npm ci --ignore-scripts, with npm's user and global config files
# empty, its cache and logs in the scratch directory and its git the one on PATH, and no setting from a .npmrc
# of the target but its registries: npm takes a project's settings from the package root it finds from --dir
# up and expands ${VAR} in them from its environment, so target.sh removes each .npmrc from the top of the copy
# down to --dir first, and says which, except that outside strict mode it keeps the registry= and
# @<scope>:registry= lines whose value is an https URL with no space or $ in it, and says which; and a
# module NODE_OPTIONS preloads lets npm start no program but git and node, since npm 10 runs the prepare
# script of a git or directory dependency despite --ignore-scripts (so npm ci stops at such a dependency, and
# a note says so), and ends at once the npm install npm runs in a git dependency's checkout, which would read
# that checkout's .npmrc (with scripts ignored it has nothing to prepare, and a git dependency's
# bundleDependencies stay out).
# A Corepack npm shim takes no npm release from the copy's packageManager field. Only these get the proxy
# variables.
# Every build and test after them runs offline (CARGO_NET_OFFLINE=true), without the proxy variables, in
# the throwaway HOME, whose .cache/solana links to the real one, and so, for the anchor actions, does its
# .avm. Anchor.toml's [toolchain] can still make anchor fetch another Solana or Anchor release; that would
# land in the throwaway HOME, and offline it fails. With a cargo build-sbf that lacks any of --install-only,
# --skip-tools-install and --offline, the build (cargo build-sbf, or anchor build) runs without those options,
# and a note says how. In native mode it runs offline in the throwaway HOME as well, which links only the
# version directory of the platform tools it uses from ~/.cache/solana: the version cargo build-sbf --version
# names, or TOOLS_VERSION, which must be there, or the run stops (exit 3) and says how to install it. In
# isolated mode it runs with the real HOME and the proxy variables, cargo not held offline, as
# templates/poc/run.sh builds each arm then.
#
# The watchdog. AUDITOR_RUN_TIMEOUT (whole seconds, 1 to 86400, default 1800) bounds the whole run, and a
# --timeout no higher than it lowers the bound. Each step runs in a session of its own, under ulimit -t of
# four times the bound and ulimit -f of 4 GiB; at the bound every process of the step is killed, and so is
# every process a step leaves behind.
#
# What it leaves. The log of every step goes to <R>/exec/<action>-<n>.log (its last 16 MiB when it is
# longer), whatever the outcome, and the regular *.so files the build made (at most 64, each at most
# 100 MiB) go to <R>/exec/<action>-<n>/, for templates/poc/run.sh --vulnerable-so and --fixed-so. The last
# stdout line says how the action ended and where these are. The scratch directory is removed on exit.
#
# Exit: 0 the action succeeded · 1 it ran and failed · 3 blocker (mode none, the self-check, a tool missing
# or, in native mode, a cargo build-sbf without --install-only whose platform tools are not installed, a
# revision or package not found, a patch that does not apply, in strict mode a git without the May-2024
# clone fixes or submodules, a download that failed, the watchdog, an incident whose root cause an
# INCIDENTS.json does not give or that keeps the build from native mode) · 64 refused. Needs bash >= 3.2,
# git, python3, env, find, grep, mkdir, mktemp, rm, chmod, cp, ln, cat, wc, tail and date; cargo,
# cargo-build-sbf, anchor or npm as the action needs.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'target: refused: the installation cannot be resolved\n' >&2; exit 64; }
case "$here" in
  */scripts/runner) root=${here%/scripts/runner} ;;
  *) printf 'target: refused: target.sh runs from <auditor-skill root>/scripts/runner\n' >&2; exit 64 ;;
esac
. "$root/scripts/lib/confine.sh" || { printf 'target: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
. "$root/scripts/lib/isolation.sh" || { printf 'target: refused: scripts/lib/isolation.sh cannot be read\n' >&2; exit 64; }
# confine.sh's own notes (an AUDITOR_STRICT value read as on; outside strict mode, a --src repository's
# alternates or grafts) print as target.sh's do, on stdout, so stderr holds only the blocker or refusal.
confine_note() { printf '>> note: %s\n' "$1"; }
confine_init target "$root"
confine_need env git find grep mkdir mktemp rm chmod cp ln cat wc tail date
WT=$CONFINE_WT

USAGE='usage: target.sh <action> --run <R> --src <dir> [--rev <commit>] [--dir <path>] [--patch <R>/patches/<ID>.patch] [--package <name>] [--program <name>] [--timeout <seconds>] [--mode <mode>], with the actions anchor-build, anchor-test, build-sbf, cargo-test, clippy and npm-ci'
TOOLS_SPEC='^v[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?$'
NAME_SPEC='^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$'
REV_SPEC='^[A-Za-z0-9][A-Za-z0-9._/~^+-]{0,254}$'
LOG_KEEP=16777216
SO_MAX=64
SO_SIZE=104857600
PATCH_SIZE=16777216

refuse() { confine_refuse "$1"; }
blocker() { printf 'target: blocker: %s\n' "$1" >&2; exit 3; }

digits() { # digits <s> <n>: status 0 when <s> is 1 to <n> digits
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ "${#1}" -le "$2" ]
}

# ---- arguments (all checked before anything is copied) ------------------------------------------------
[ $# -gt 0 ] || refuse "$USAGE"
ACTION=$1
shift
case "$ACTION" in
  anchor-build|anchor-test|build-sbf|cargo-test|clippy|npm-ci) ;;
  *) refuse "$USAGE" ;;
esac
RUN_ARG="" SRC_ARG="" REV="" DIR_ARG="" PATCH_ARG="" PACKAGE="" PROGRAM="" TIMEOUT_ARG="" MODE_ARG=""
seen=" "
while [ $# -gt 0 ]; do
  opt=$1
  shift
  case "$opt" in
    --run|--src|--rev|--dir|--patch|--package|--program|--timeout|--mode) [ $# -gt 0 ] || refuse "$opt needs a value" ;;
    *) refuse "$(confine_text "$opt") is not an argument target.sh takes ($USAGE)" ;;
  esac
  case "$seen" in *" $opt "*) refuse "give $opt once" ;; esac
  seen="$seen$opt "
  case "$opt" in
    --run) RUN_ARG=$1 ;;
    --src) SRC_ARG=$1 ;;
    --rev) REV=$1 ;;
    --dir) DIR_ARG=$1 ;;
    --patch) PATCH_ARG=$1 ;;
    --package) PACKAGE=$1 ;;
    --program) PROGRAM=$1 ;;
    --timeout) TIMEOUT_ARG=$1 ;;
    --mode) MODE_ARG=$1 ;;
  esac
  shift
done
case "$seen" in *" --run "*) ;; *) refuse "give --run <R>, the run directory ($USAGE)" ;; esac
case "$seen" in *" --src "*) ;; *) refuse "give --src, the source to copy ($USAGE)" ;; esac

confine_rundir "$RUN_ARG" "--run"
R=$CONFINE_RUN

# src_enclosing: for --src . outside strict mode, in a session started below the top level of a repository,
# that repository (SRC_KIND repo), when confine_repo . takes it and sets CONFINE_PREFIX; status 1 otherwise,
# and the tree is then copied file by file. Tried in a subshell first, since confine_repo refuses.
src_enclosing() {
  [ "$CONFINE_REL" = . ] && [ "$CONFINE_STRICT" = 0 ] || return 1
  ( confine_repo . "--src" ) >/dev/null 2>&1 || return 1
  confine_repo . "--src"
  [ -n "${CONFINE_PREFIX:-}" ] || return 1
  SRC_KIND=repo
  SRC_ABS=$CONFINE_REPO
}
# src_arg <value>: a copy git-ro.sh copy made in R, the top level of a repository (SRC_KIND repo), or a
# directory whose files are copied (SRC_KIND tree). Sets SRC_ABS (physical) and SRC_SHOWN.
src_arg() {
  local v=${1#./} first rest k abs phys out top
  confine_shown "$1"
  SRC_SHOWN=$CONFINE_SHOWN
  first=${v%%/*}
  if confine_rundir_name "$first"; then
    rest=${v#*/}
    [ "$rest" != "$v" ] || refuse "--src is a run directory; give the source tree, or a copy git-ro.sh copy made: $SRC_SHOWN"
    case "$rest" in
      src.git) ;;
      src-*.git)
        k=${rest#src-}
        k=${k%.git}
        digits "$k" 4 || refuse "--src in a run directory takes only <R>/src.git or <R>/src-<k>.git, a copy git-ro.sh copy made: $SRC_SHOWN" ;;
      *) refuse "--src in a run directory takes only <R>/src.git or <R>/src-<k>.git, a copy git-ro.sh copy made: $SRC_SHOWN" ;;
    esac
    [ "$first" = "$R" ] || refuse "--src names a copy in $first, not in --run's $R: $SRC_SHOWN"
    { [ -d "$WT/$R/$rest" ] && [ ! -L "$WT/$R/$rest" ] && [ -f "$WT/$R/$rest/auditor-copy" ] && [ ! -L "$WT/$R/$rest/auditor-copy" ]; } ||
      refuse "--src names no copy that git-ro.sh copy made: $SRC_SHOWN"
    confine_repo "$R/$rest" "--src"
    [ "$CONFINE_BARE" = true ] || refuse "--src is not a bare repository: $SRC_SHOWN"
    SRC_KIND=repo
    SRC_ABS=$CONFINE_REPO
    return 0
  fi
  case "$first" in
    .audit-memory) refuse "--src is the audit-mem store, not a source tree: $SRC_SHOWN" ;;
  esac
  confine_path "$1" "--src" dir
  if [ "$CONFINE_REL" = . ]; then abs=$WT; else abs=$WT/$CONFINE_REL; fi
  confine_phys "$abs" || refuse "--src cannot be resolved: $SRC_SHOWN"
  phys=$CONFINE_PHYS
  # In this shell, so a file git would wait on is refused for what it is, and the call below finds it checked.
  confine_git_files "$phys"
  if out=$(hgit "$phys" rev-parse --is-bare-repository 2>&1); then
    case "$out" in
      true) ;;
      false)
        top=$(hgit "$phys" rev-parse --show-toplevel 2>/dev/null) || refuse "git cannot describe the repository at --src: $SRC_SHOWN"
        if ! confine_phys "$top" || [ "$CONFINE_PHYS" != "$phys" ]; then
          src_enclosing && return 0
          SRC_KIND=tree
          SRC_ABS=$phys
          return 0
        fi ;;
      *) refuse "git cannot describe the repository at --src: $SRC_SHOWN" ;;
    esac
    confine_repo "$1" "--src"
    SRC_KIND=repo
    SRC_ABS=$CONFINE_REPO
    return 0
  elif confine_no_repo "$?" "$out"; then
    src_enclosing && return 0
    SRC_KIND=tree
    SRC_ABS=$phys
  else
    refuse "git cannot tell whether --src is a repository (none there, or another user owns it: audit a copy): $SRC_SHOWN"
  fi
}
src_arg "$SRC_ARG"

if [ -n "$REV" ]; then
  [ "$SRC_KIND" = repo ] || refuse "--rev needs a repository --src, and $SRC_SHOWN is not the top level of one"
  if [[ ! "$REV" =~ $REV_SPEC ]] || [[ "$REV" == *..* ]] || [[ "$REV" == *@\{* ]]; then
    refuse "--rev takes a commit, a branch or a tag name (letters, digits and ._/~^+-, at most 255), not $(confine_text "$REV")"
  fi
fi

if [ -n "$DIR_ARG" ]; then
  case "$DIR_ARG" in
    *[!A-Za-z0-9._/-]*|-*|/*|*/|*//*) refuse "--dir takes a relative path inside the source, of letters, digits and ._-, not $(confine_text "$DIR_ARG")" ;;
  esac
  [ "${#DIR_ARG}" -le 1024 ] || refuse "--dir is longer than 1024 bytes"
  case "/$DIR_ARG/" in */./*|*/../*) refuse "--dir has a . or .. component: $(confine_text "$DIR_ARG")" ;; esac
fi

PATCH_REL=""
if [ -n "$PATCH_ARG" ]; then
  [ "$SRC_KIND" = repo ] || refuse "--patch needs a repository --src, and $SRC_SHOWN is not the top level of one"
  confine_path "$PATCH_ARG" "--patch" any
  pid=${CONFINE_REL#"$R"/patches/}
  pid=${pid%.patch}
  case "$CONFINE_REL" in "$R"/patches/*.patch) ;; *) pid="" ;; esac
  case "$pid" in
    F-*) digits "${pid#F-}" 4 || pid="" ;;
    INC-*.*) n=${pid#INC-}; { digits "${n%%.*}" 6 && digits "${n#*.}" 4; } || pid="" ;;
    *) pid="" ;;
  esac
  [ -n "$pid" ] || refuse "--patch takes $R/patches/<ID>.patch, <ID> F-<n> or INC-<n>.<k>, not $(confine_text "$PATCH_ARG")"
  [ "$CONFINE_TYPE" = file ] || refuse "--patch is not an existing regular file: $(confine_text "$PATCH_ARG")"
  [ -z "$(find "$WT/$CONFINE_REL" -prune -size +"${PATCH_SIZE}"c -print 2>/dev/null)" ] ||
    refuse "--patch is larger than 16 MiB: $(confine_text "$PATCH_ARG")"
  PATCH_REL=$CONFINE_REL
fi

if [ -n "$PACKAGE" ]; then
  case "$ACTION" in
    build-sbf|cargo-test|clippy) ;;
    anchor-*) refuse "--package is for build-sbf, cargo-test and clippy; $ACTION takes --program" ;;
    *) refuse "--package is for build-sbf, cargo-test and clippy" ;;
  esac
  [[ "$PACKAGE" =~ $NAME_SPEC ]] || refuse "--package takes a package name (letters, digits, _ and -, at most 64), not $(confine_text "$PACKAGE")"
fi
if [ -n "$PROGRAM" ]; then
  case "$ACTION" in anchor-build|anchor-test) ;; *) refuse "--program is for anchor-build and anchor-test" ;; esac
  [[ "$PROGRAM" =~ $NAME_SPEC ]] || refuse "--program takes a program name (letters, digits, _ and -, at most 64), not $(confine_text "$PROGRAM")"
fi

CAP=${AUDITOR_RUN_TIMEOUT:-1800}
{ digits "$CAP" 5 && [ "$CAP" -ge 1 ] && [ "$CAP" -le 86400 ]; } ||
  refuse "AUDITOR_RUN_TIMEOUT is '$(confine_text "$CAP")', not a whole number of seconds from 1 to 86400"
CAP=$((10#$CAP))
LIMIT=$CAP
if [ -n "$TIMEOUT_ARG" ]; then
  { digits "$TIMEOUT_ARG" 5 && [ "$TIMEOUT_ARG" -ge 1 ]; } ||
    refuse "--timeout takes a whole number of seconds, not $(confine_text "$TIMEOUT_ARG")"
  [ "$((10#$TIMEOUT_ARG))" -le "$CAP" ] ||
    refuse "--timeout is $((10#$TIMEOUT_ARG)) seconds, more than AUDITOR_RUN_TIMEOUT ($CAP); the user raises AUDITOR_RUN_TIMEOUT where Claude Code runs"
  LIMIT=$((10#$TIMEOUT_ARG))
fi
case "$MODE_ARG" in
  ''|none|isolated|native) ;;
  *) refuse "--mode takes none, isolated or native, not '$(confine_text "$MODE_ARG")'" ;;
esac
if [ -n "${TOOLS_VERSION:-}" ] && [[ ! "$TOOLS_VERSION" =~ $TOOLS_SPEC ]]; then
  refuse "TOOLS_VERSION is '$(confine_text "$TOOLS_VERSION")', not v<n>.<n> or v<n>.<n>.<n>"
fi
ENV_MODE=${AUDITOR_EXEC_MODE:-}
case "$ENV_MODE" in
  ''|none|isolated|native) ;;
  *) refuse "AUDITOR_EXEC_MODE is '$(confine_text "$ENV_MODE")', not none, isolated or native" ;;
esac
iso_tmp_outside

# R/exec-mode: one word, none, isolated or native, and one optional newline; anything else is refused.
FILE_MODE=""
mf=$WT/$R/exec-mode
if [ -e "$mf" ] || [ -L "$mf" ]; then
  [ -f "$mf" ] && [ ! -L "$mf" ] || refuse "$R/exec-mode is not a regular file"
  size=$(wc -c < "$mf") || refuse "$R/exec-mode cannot be read"
  size=${size//[!0-9]/}
  if [ "$size" -le 9 ]; then FILE_MODE=$(cat -- "$mf") || refuse "$R/exec-mode cannot be read"; fi
  case "$FILE_MODE" in
    none|isolated|native) [ "$size" -le $((${#FILE_MODE} + 1)) ] || FILE_MODE="" ;;
    *) FILE_MODE="" ;;
  esac
  [ -n "$FILE_MODE" ] || refuse "$R/exec-mode holds something other than one word, none, isolated or native"
fi

# ---- the mode and the self-check -----------------------------------------------------------------------
# Strict mode (OUTPUT-RULES.md Rule 11f) counts as isolated; with nothing recorded the mode is native.
STRICT_MODE="" STRICT_SAYS=off
if [ "$CONFINE_STRICT" = 1 ]; then STRICT_MODE=isolated STRICT_SAYS="on ($(confine_text "$CONFINE_MODE_WHY"))"; fi
SOURCES="$R/exec-mode: ${FILE_MODE:-absent}; AUDITOR_EXEC_MODE: ${ENV_MODE:-unset}; strict mode: $STRICT_SAYS"
case " $FILE_MODE $ENV_MODE $STRICT_MODE " in
  *" none "*) MODE=none ;;
  *" isolated "*) MODE=isolated ;;
  *) MODE=native ;;
esac
if [ "$MODE" = none ]; then
  blocker "the recorded execution mode is none ($SOURCES): no target code is built or run for this engagement (OUTPUT-RULES.md Rule 11a) — nothing was copied or built."
fi
if [ -n "$MODE_ARG" ] && [ "$MODE_ARG" != "$MODE" ]; then
  blocker "--mode is $MODE_ARG, but the recorded execution mode is $MODE ($SOURCES); the mode changes only when the human answers again — nothing was copied or built."
fi
echo ">> execution mode: $MODE (the stricter of $SOURCES; native when none is recorded)"
[ -n "$FILE_MODE$ENV_MODE$STRICT_MODE" ] ||
  echo ">> note: no execution mode is recorded, so target.sh builds natively, on this machine (OUTPUT-RULES.md Rule 11a)"

# incident_class [<INC-n.k>]: sets cls to the root_cause_class $json records for that incident, or, with no
# id, to supply_chain_or_ci when any incident has it; a blocker when it cannot be read.
incident_class() {
  local rc=0
  iso_incident_class "$WT/$json" "${1:-}" || rc=$?
  cls=$ISO_CLASS
  [ "$rc" = 0 ] && return 0
  [ "$rc" = 3 ] && [ -n "$cls" ] || cls="cannot be read"
  blocker "$json $cls: an incident's code is built only once $json records its root_cause_class (OUTPUT-RULES.md Rule 11a, references/detection-response/incidents-schema.md) — nothing was copied or built."
}
case "$R" in
  incident_*)
    inc=""
    case "$PATCH_REL" in */INC-*.patch) inc=${PATCH_REL##*/}; inc=${inc%.patch} ;; esac
    json=$R/INCIDENTS.json
    command -v python3 >/dev/null 2>&1 ||
      blocker "python3 is not on PATH, so target.sh cannot read the root_cause_class in $json (OUTPUT-RULES.md Rule 11a) — nothing was copied or built."
    if [ -n "$inc" ]; then
      incident_class "$inc"
      echo ">> incident $inc: root_cause_class $cls ($json)"
      if [ "$cls" = supply_chain_or_ci ] && [ "$MODE" = native ]; then
        blocker "the root_cause_class of $inc is supply_chain_or_ci, and such an incident's code is never built natively (OUTPUT-RULES.md Rule 11a); run it in isolated mode — nothing was copied or built."
      fi
    fi
    # Natively every incident of the run counts, whatever --patch names: a patch of one incident builds the
    # same tree as the others, which a supply_chain_or_ci root cause makes suspect.
    if [ -z "$inc" ] || [ "$MODE" = native ]; then
      incident_class
      if [ "$cls" = supply_chain_or_ci ] && [ "$MODE" = native ]; then
        also=""
        [ -z "$inc" ] || also=", nor is a patch of $inc, which builds the same tree"
        blocker "$json records an incident whose root_cause_class is supply_chain_or_ci, and such an incident's code is never built natively (OUTPUT-RULES.md Rule 11a)$also; run it in isolated mode — nothing was copied or built."
      fi
    fi ;;
esac
# Natively an incident recorded anywhere in the working directory counts too, whatever --run names: every --src
# is the working tree or a copy of it. iso_incident_runs reads each incident_*/INCIDENTS.json there; a run
# without one, or whose file records no incident (a hunt that ruled everything out), counts for nothing.
if [ "$MODE" = native ]; then
  rc=0
  iso_incident_runs "$WT" || rc=$?
  json=$ISO_INCIDENTS
  case "$rc:$ISO_CLASS" in
    0:supply_chain_or_ci)
      blocker "$json records an incident whose root_cause_class is supply_chain_or_ci, so nothing from this working directory is built natively, for an audit run or an incident run (OUTPUT-RULES.md Rule 11a); run it in isolated mode — nothing was copied or built." ;;
    0:*)
      [ -z "$ISO_PASSED" ] ||
        echo ">> note: the incident rule counts only the run directories the auditor made (incident_<n>, with a .gitignore of exactly *), so it passed over $ISO_PASSED (Rule 11a)" ;;
    2:*) blocker "python3 is not on PATH, so target.sh cannot tell whether ${json%/INCIDENTS.json} holds an INCIDENTS.json, or read the root_cause_class one records (OUTPUT-RULES.md Rule 11a) — nothing was copied or built." ;;
    '3:cannot be listed') blocker "the working directory cannot be listed, so target.sh cannot tell whether an incident_* directory in it records a supply_chain_or_ci incident, and nothing from it is built natively until it can be listed (OUTPUT-RULES.md Rule 11a) — nothing was copied or built." ;;
    *) blocker "$json $ISO_CLASS: nothing from this working directory is built natively until every incident_*/INCIDENTS.json in it records the root_cause_class of each of its incidents (OUTPUT-RULES.md Rule 11a, references/detection-response/incidents-schema.md) — nothing was copied or built." ;;
  esac
fi
# python3 starts from /, so nothing in the working directory picks the interpreter.
cd / || blocker "cannot leave the working directory for /"
# The isolated blockers end with how to build natively instead, from what recorded isolated, as the human's
# step (the agent copies these lines, and a mode is the human's answer); in strict mode, with why isolated
# is the only way.
if [ "$CONFINE_STRICT" = 1 ]; then
  native=". Strict mode is on ($(confine_text "$CONFINE_MODE_WHY")), so target.sh builds only on an isolated runner (Rule 11f)"
else
  steps=""
  [ "$ENV_MODE" != isolated ] || steps="unsets AUDITOR_EXEC_MODE where Claude Code runs"
  [ "$FILE_MODE" != isolated ] || steps="${steps:+$steps and }writes native to $R/exec-mode"
  native=". To build natively instead, on this machine, the human $steps"
fi
rc=0
iso_credentials || rc=$?
case "$MODE:$rc" in
  *:0) ;;
  isolated:1) blocker "isolated mode, but these are readable here: $ISO_KINDS; this is not the isolated runner (Rule 11a), and scripts/runner/probe.sh --only isolation lists them$native — nothing was copied or built." ;;
  isolated:*) blocker "isolated mode, but the credential self-check could not finish ($ISO_WHY), so target.sh cannot tell that this is the isolated runner (Rule 11a)$native — nothing was copied or built." ;;
  *:1) echo ">> warning: native mode, and these are readable here, to the code this run builds and runs too: $ISO_KINDS (Rule 11a)" ;;
  *) echo ">> warning: native mode, and the credential check could not finish ($ISO_WHY), so what the code this run builds can read here is not known (Rule 11a)" ;;
esac
if [ "$MODE" = isolated ]; then
  iso_cred_names
  if [ -n "$ISO_NAMES" ]; then
    echo ">> warning: isolated mode, and these variables of target.sh's own environment look like credentials: $ISO_NAMES. No child of target.sh gets them, but code running as this user can read another process's environment (on Linux, in /proc/<pid>/environ) (Rule 11a)"
  fi
fi

# ---- the tools the action needs ------------------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || blocker "$1 is not on PATH, so $ACTION cannot run here — nothing was copied or built."; }
need python3
case "$ACTION" in
  anchor-build|anchor-test) need anchor; need cargo; need cargo-build-sbf ;;
  build-sbf) need cargo; need cargo-build-sbf ;;
  cargo-test|clippy) need cargo ;;
  npm-ci) need npm; need node ;;
esac
GIT=$(command -v git)
CLONE=1 EXPORT_WHY=""
# partial_complete <commit>: status 0 when the repository at SRC_ABS holds the commit's tree and every object
# in it, as git rev-list --objects --no-walk --missing=print says, which prints a missing object as ?<id>
# and fetches nothing (hgit sets GIT_NO_LAZY_FETCH), as git-ro.sh copy asks it.
partial_complete() {
  local out
  out=$(hgit_tree "$SRC_ABS" rev-list --objects --no-walk --missing=print "$1" 2>/dev/null </dev/null) || return 1
  case "$out" in '?'*|*$'\n?'*) return 1 ;; esac
}
if [ "$SRC_KIND" = repo ]; then
  # The May-2024 clone fixes (CVE-2024-32004, CVE-2024-32465), as git-ro.sh copy requires them. Without them
  # target.sh never clones: strict mode stops, and otherwise the copy is written from git's read-only
  # plumbing (export_tree, below).
  gv=$(env -i PATH="$PATH" git --version 2>/dev/null) || gv=""
  gv=${gv#git version }
  gv=${gv%% *}
  gvs=$(confine_text "$gv")
  maj=${gv%%.*}; gv=${gv#"$maj"}; gv=${gv#.}
  min=${gv%%.*}; gv=${gv#"$min"}; gv=${gv#.}
  pat=${gv%%.*}
  maj=${maj%%[!0-9]*}; min=${min%%[!0-9]*}; pat=${pat%%[!0-9]*}
  [ -n "$pat" ] || pat=0
  ok=0
  if [ -n "$maj" ] && [ -n "$min" ]; then
    if [ "$maj" -gt 2 ]; then ok=1
    elif [ "$maj" -eq 2 ]; then
      case "$min" in
        39|43) [ "$pat" -ge 4 ] && ok=1 ;;
        40|42) [ "$pat" -ge 2 ] && ok=1 ;;
        41|44|45) [ "$pat" -ge 1 ] && ok=1 ;;
        *) [ "$min" -ge 46 ] && ok=1 ;;
      esac
    fi
  fi
  if [ "$ok" != 1 ]; then
    [ "$CONFINE_STRICT" = 0 ] ||
      blocker "cloning --src needs git with the May-2024 clone fixes: 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, or 2.46 or later — nothing was copied or built."
    # Decided from git --version alone, which a distribution's build with the fixes backported can still
    # report: the note says what the version shows.
    case "$maj.$min" in
      2.39) fix=2.39.4 ;; 2.40) fix=2.40.2 ;; 2.41) fix=2.41.1 ;; 2.42) fix=2.42.2 ;; 2.43) fix=2.43.4 ;;
      2.44) fix=2.44.1 ;; 2.45) fix=2.45.1 ;; *) fix="" ;;
    esac
    if [ -z "$maj" ] || [ -z "$min" ]; then
      EXPORT_WHY="this git reports no version number"
    elif [ -n "$fix" ]; then
      EXPORT_WHY="this git reports $gvs, older than $fix, that line's May-2024 fixed release"
    else
      EXPORT_WHY="this git reports $gvs, older than 2.39.4, the oldest May-2024 fixed release"
    fi
    CLONE=0
    echo ">> note: $EXPORT_WHY, so target.sh copies the tracked files of the commit with git's read-only plumbing instead of cloning; strict mode stops here (Rule 11f)"
  fi
  # The clone runs upload-pack in the source with none of hgit's -c pins (git's local transport clears
  # GIT_CONFIG_PARAMETERS for it), so it keeps git's ownership check on: no global config. A source git
  # reads here only through the safe-directory file of default mode is one that check refuses, as another
  # user's: it is copied through the plumbing as well. Strict mode never reads it (src_arg refuses).
  if [ "$CLONE" = 1 ] && [ "$CONFINE_STRICT" = 0 ] &&
    ! CONFINE_GIT_GLOBAL=/dev/null hgit "$SRC_ABS" rev-parse --git-dir </dev/null >/dev/null 2>&1; then
    CLONE=0
    EXPORT_WHY="another user owns it"
    echo ">> note: --src $SRC_SHOWN belongs to another user, so git would not clone it with its ownership check on; target.sh copies the tracked files of the commit with git's read-only plumbing instead, which runs nothing the repository's config names; strict mode refuses it (Rule 11f)"
  fi
  confine_partial_clone "$SRC_ABS" >/dev/null
  case $? in
    0)
      [ "$CONFINE_STRICT" = 0 ] ||
        blocker "$SRC_SHOWN is a partial clone: a copy would lack the objects it never fetched, and nothing is fetched (Rule 11c) — nothing was copied or built."
      # Outside strict mode the revision's files can all be there (a blobless clone holds those of its
      # checkout): then the copy is written from git's plumbing, which fetches nothing.
      PSHA=$(hgit_tree "$SRC_ABS" rev-parse --verify --quiet --end-of-options "${REV:-HEAD}^{commit}" 2>/dev/null </dev/null) &&
        [ -n "$PSHA" ] || blocker "$(confine_text "${REV:-HEAD}") is not a commit in $SRC_SHOWN — nothing was copied or built."
      partial_complete "$PSHA" ||
        blocker "$SRC_SHOWN is a partial clone that lacks files of $PSHA it never fetched, and nothing is fetched (Rule 11c) — nothing was copied or built."
      if [ "$CLONE" = 1 ]; then
        CLONE=0
        EXPORT_WHY="it is a partial clone, and every file of $PSHA is in it"
      fi
      echo ">> note: --src $SRC_SHOWN is a partial clone, and every file of $PSHA is in it, so target.sh copies the tracked files of the commit with git's read-only plumbing, fetching nothing; strict mode stops here (Rule 11f)" ;;
    2) blocker "git cannot read the config of $SRC_SHOWN, so a partial clone cannot be ruled out — nothing was copied or built." ;;
  esac
fi

# ---- scratch, the log and the watchdog ------------------------------------------------------------------
S=""
cleanup() {
  case "${ISO_SCRATCH:-}" in */auditor-target.??????) chmod -R u+rwX "$ISO_SCRATCH" 2>/dev/null; rm -rf "$ISO_SCRATCH" 2>/dev/null ;; esac
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
iso_scratch target
S=$ISO_SCRATCH
cd / || blocker "cannot leave the working directory for /"
iso_env "$S" || blocker "cannot prepare the cleaned environment (a throwaway HOME and TMPDIR) in $S — nothing was built."
exec 9>"$S/log" || blocker "cannot write the log in $S — nothing was built."
DEADLINE=$(($(date +%s) + LIMIT))
EX=$WT/$R/exec
SO_FROM=""

# finish <status> <line>: keep the log in R/exec/<action>-<n>.log and, for status 0 or 1, the *.so files of
# SO_FROM in R/exec/<action>-<n>/; print <line> and where they are, on stdout for 0 and 1 and as a blocker
# on stderr for 3; exit <status>.
finish() {
  local status=$1 line=$2 n=1 src size f name kept="" count=0 skipped=0 where
  exec 9>&-
  if [ ! -d "$EX" ]; then confine_mkdir "$EX" || blocker "$line; and the log could not be kept: cannot create $R/exec"; fi
  [ ! -L "$EX" ] || blocker "$line; and the log could not be kept: $R/exec is a symbolic link"
  src=$S/log
  size=$(wc -c < "$S/log" 2>/dev/null) || size=0
  size=${size//[!0-9]/}
  if [ "${size:-0}" -gt "$LOG_KEEP" ]; then
    { printf '>> the log holds %s bytes; target.sh kept its last %s\n' "$size" "$LOG_KEEP"; tail -c "$LOG_KEEP" "$S/log"; } > "$S/log.kept" 2>/dev/null
    src=$S/log.kept
  fi
  while :; do
    while [ -e "$EX/$ACTION-$n.log" ] || [ -L "$EX/$ACTION-$n.log" ] || [ -e "$EX/$ACTION-$n" ] || [ -L "$EX/$ACTION-$n" ]; do
      n=$((n + 1))
      [ "$n" -le 9999 ] || blocker "$line; and the log could not be kept: $R/exec holds 9999 runs of $ACTION"
    done
    iso_copy_new "$src" "$EX/$ACTION-$n.log" && break
    [ -e "$EX/$ACTION-$n.log" ] || blocker "$line; and the log could not be kept in $R/exec"
  done
  where="log $R/exec/$ACTION-$n.log"
  if [ "$status" -le 1 ] && [ -n "$SO_FROM" ] && [ -d "$SO_FROM" ]; then
    # The glob gives the names in byte order (LC_ALL=C), whatever order the directory lists them in (ext4
    # hashes them), so the line below and the first $SO_MAX kept are the same on every filesystem. dotglob
    # lists the names that start with a dot as well, which are not kept, and a glob keeps a name that
    # holds a line end whole.
    shopt -s dotglob
    for f in "$SO_FROM"/*.so; do
      [ -L "$f" ] || [ -f "$f" ] || continue
      name=${f##*/}
      case "$name" in *[[:cntrl:]]*|.*|'') skipped=$((skipped + 1)); continue ;; esac
      if [ ! -f "$f" ] || [ -L "$f" ] || [ "$count" -ge "$SO_MAX" ] ||
        [ -n "$(find "$f" -prune -size +"${SO_SIZE}"c -print 2>/dev/null)" ]; then
        skipped=$((skipped + 1))
        continue
      fi
      if [ "$count" = 0 ]; then confine_mkdir "$EX/$ACTION-$n" || { skipped=$((skipped + 1)); break; }; fi
      if iso_copy_new "$f" "$EX/$ACTION-$n/$name"; then
        count=$((count + 1))
        kept=${kept:+$kept, }$name
      else
        skipped=$((skipped + 1))
      fi
    done
    shopt -u dotglob
    if [ "$count" -gt 0 ]; then where="$where; $count .so in $R/exec/$ACTION-$n/: $kept"; else where="$where; no .so to keep"; fi
    case "$skipped" in
      0) ;;
      1) where="$where; 1 other .so not kept (a symbolic link, larger than 100 MiB, past $SO_MAX, or an odd name)" ;;
      *) where="$where; $skipped other .so not kept (symbolic links, larger than 100 MiB, past $SO_MAX, or odd names)" ;;
    esac
  fi
  case "$status" in
    0|1) printf '>> %s: %s; %s\n' "$ACTION" "$line" "$where" ;;
    *) printf 'target: blocker: %s; %s\n' "$line" "$where" >&2 ;;
  esac
  exit "$status"
}

# step <dir> [NAME=value...] <program> [<arg>...]: one step under the watchdog, its output in the log (or in
# STEP_OUT when that names a file). Sets STEP_RC and STEP_END (the watchdog's line).
STEP=0
STEP_OUT=""
step() {
  local left now w
  now=$(date +%s) || now=$DEADLINE
  left=$((DEADLINE - now))
  STEP=$((STEP + 1))
  if [ "$left" -lt 1 ]; then STEP_RC=124; STEP_END=timeout; return 124; fi
  printf '\n>>'
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
  STEP_RC=$?
  STEP_END=$(cat "$S/step-$STEP" 2>/dev/null) || STEP_END=""
  [ -n "$STEP_END" ] || STEP_END="exit $STEP_RC"
  return "$STEP_RC"
} >&9 2>&9

# why_stopped: the end of a step that did not just exit with a status, as a reason; empty otherwise.
why_stopped() {
  case "$STEP_END" in
    timeout) printf 'the run passed its %s-second limit (AUDITOR_RUN_TIMEOUT or --timeout) and was killed' "$LIMIT" ;;
    'signal 24') printf 'a process passed its CPU time limit (ulimit -t)' ;;
    'signal 25') printf 'a process wrote a file past 4 GiB (ulimit -f)' ;;
    'cannot start:'*) printf '%s' "$(confine_text "$STEP_END")" ;;
    'stopped by signal'*) printf 'the watchdog was %s' "$STEP_END" ;;
  esac
}
# fetched <what>: a download or preparation step must have exited 0; anything else is a blocker.
fetched() {
  [ "$STEP_END" = "exit 0" ] && return 0
  local why
  why=$(why_stopped)
  finish 3 "$1 ${why:-failed (${STEP_END})}"
}
# outcome <what>: the action's own step: exit 0 succeeds, another exit or a signal is a failure, the watchdog a blocker.
outcome() {
  local why
  why=$(why_stopped)
  case "$STEP_END" in
    'exit 0') return 0 ;;
    timeout|'signal 24'|'signal 25'|'cannot start:'*|'stopped by signal'*) finish 3 "$1: $why" ;;
    *) finish 1 "$1 failed (${STEP_END})" ;;
  esac
}

NET=(${ISO_NET[@]+"${ISO_NET[@]}"})
OFF=(CARGO_NET_OFFLINE=true)
# The module NODE_OPTIONS preloads into each node process of the npm step (npm's node-options names it too:
# set anywhere, it would replace NODE_OPTIONS for npm's children) does two things. npm prepares a git
# dependency that has workspaces or an install, build or prepare script with an npm install in the
# dependency's checkout, and that npm reads the checkout's .npmrc, ${VAR} expansion included; with scripts
# ignored it has nothing to prepare, so the module ends it (pacote marks it with _PACOTE_NO_PREPARE_) before
# it reads a setting. And npm 10 runs the prepare script of a git dependency, or of a package the lockfile
# resolves to a directory, despite --ignore-scripts, through a shell it may find in that package's own
# node_modules/.bin: the module lets child_process start only git and node, so no script runs, and npm ci
# stops at such a dependency. npm's script-shell is false as well. Where npm is Corepack's shim (corepack enable
# npm), COREPACK_ENABLE_PROJECT_SPEC=0 keeps the packageManager field of the copy's package.json from choosing
# which npm release Corepack fetches and runs.
FALSE=$(type -P false) || FALSE=/usr/bin/false
[ -x "$FALSE" ] || FALSE=/bin/false
mkdir "$S/npm" && : > "$S/npm/userconfig" && : > "$S/npm/globalconfig" &&
  printf '%s\n' 'if (process.env._PACOTE_NO_PREPARE_ !== undefined) process.exit(0)' \
    'const { ChildProcess } = require("child_process")' \
    'const start = ChildProcess.prototype.spawn' \
    'const allowed = [process.execPath, process.env.npm_config_git].filter(Boolean)' \
    'ChildProcess.prototype.spawn = function (options) {' \
    '  const file = options && options.file' \
    '  if (!allowed.includes(file)) throw new Error("target.sh: npm starts no program here but git and node, not " + file)' \
    '  return start.call(this, options)' \
    '}' > "$S/npm/preload.js" || finish 3 "cannot prepare npm's config files and preload in $S"
PRELOAD="--require=\"$S/npm/preload.js\""
NPM=(npm_config_userconfig="$S/npm/userconfig" npm_config_globalconfig="$S/npm/globalconfig"
  npm_config_cache="$S/npm/cache" npm_config_logs_dir="$S/npm/logs" npm_config_update_notifier=false
  npm_config_fund=false npm_config_audit=false npm_config_ignore_scripts=true npm_config_git="$GIT"
  "NODE_OPTIONS=$PRELOAD" "npm_config_node_options=$PRELOAD" "npm_config_script_shell=$FALSE" COREPACK_ENABLE_PROJECT_SPEC=0)
ISO_ENV+=(RUSTUP_AUTO_INSTALL=0 CARGO_TERM_COLOR=never)
TC_DEFAULT=""
case "$ACTION" in
  npm-ci) ;;
  *)
    if [ -z "${RUSTUP_TOOLCHAIN:-}" ] && command -v rustup >/dev/null 2>&1; then
      tc=$(cd "$S" && iso_run rustup default 2>/dev/null </dev/null) || tc=""
      case "$tc" in
        *"(default)"*) TC_DEFAULT=${tc%% *}; ISO_ENV+=("RUSTUP_TOOLCHAIN=$TC_DEFAULT") ;;
        *) finish 3 "no Rust toolchain to pin: set RUSTUP_TOOLCHAIN or a rustup default" ;;
      esac
    fi ;;
esac
printf '>> target.sh %s, execution mode %s; HOME %s (throwaway, with a fresh Solana keypair); TMPDIR %s\n' \
  "$ACTION" "$MODE" "$ISO_HOME" "$ISO_TMP" >&9

# ---- the copy ------------------------------------------------------------------------------------------
# What export_tree runs with python3 -I, from /. "plan <ls-tree -r -z> <oids>": writes the object of each blob
# entry to <oids>, one a line, for git cat-file --batch, and prints the path of each submodule (a gitlink),
# one a line; exit 3 with the reason for an entry git checkout would not write (a path with an empty, . or
# .. component, or a .git component in any letter case, also with the characters HFS+ leaves out of a name or
# trailing dots and spaces) or that is no file, link or gitlink. "write <ls-tree -r -z> <dest>": reads
# git cat-file --batch's answer for those objects on stdin and writes each entry under <dest>, a new file
# (O_EXCL), a symbolic link, or for a gitlink an empty directory, as git checkout does, through descriptors of
# its directories opened with O_NOFOLLOW, so nothing is written through a link; exit 3 with the reason when
# an entry cannot be written there (two names of one file on a volume that ignores letter case, say).
EXPORT_PY='import os, re, sys

IGNORED = re.compile("[‌-‏‪-‮⁪-⁯﻿]")
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def fail(text):
    print(text)
    sys.exit(3)


def shown(path):
    return re.sub(r"[\x00-\x1f\x7f]", "?", path.decode("utf-8", "replace"))[:200]


def entries(listing):
    with open(listing, "rb") as f:
        for rec in f.read().split(b"\0"):
            if rec:
                head, _, path = rec.partition(b"\t")
                mode, kind, oid = head.decode("ascii").split(" ")
                yield mode, kind, oid, path


def plan(listing, oids):
    subs = []
    with open(oids, "w") as out:
        for mode, kind, oid, path in entries(listing):
            for part in path.split(b"/"):
                name = IGNORED.sub("", part.decode("utf-8", "replace")).rstrip(". ").lower()
                if part in (b"", b".", b"..") or name == ".git":
                    fail("holds a path git checkout does not write: %s" % shown(path))
            if mode == "160000" and kind == "commit":
                subs.append(shown(path))
            elif mode in ("100644", "100664", "100755", "120000") and kind == "blob":
                out.write(oid + "\n")
            else:
                fail("holds an entry of mode %s, which target.sh does not copy: %s" % (mode, shown(path)))
    for name in subs:
        print(name)


def write(listing, dest):
    batch = sys.stdin.buffer
    chain = [(None, os.open(dest, os.O_RDONLY | DIRECTORY))]
    for mode, kind, oid, path in entries(listing):
        parts = path.split(b"/")
        keep = 1
        while keep < len(chain) and keep <= len(parts) - 1 and chain[keep][0] == parts[keep - 1]:
            keep += 1
        while len(chain) > keep:
            os.close(chain.pop()[1])
        try:
            for part in parts[len(chain) - 1:-1]:
                try:
                    os.mkdir(part, 0o755, dir_fd=chain[-1][1])
                except FileExistsError:
                    pass
                chain.append((part, os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW, dir_fd=chain[-1][1])))
            at, name = chain[-1][1], parts[-1]
            if mode == "160000":
                os.mkdir(name, 0o755, dir_fd=at)
                continue
            head = batch.readline().split()
            if len(head) != 3 or head[0] != oid.encode() or head[1] != b"blob":
                fail("git cat-file did not give the object of %s" % shown(path))
            left = int(head[2])
            if mode == "120000":
                os.symlink(batch.read(left), name, dir_fd=at)
            else:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o755 if mode == "100755" else 0o644,
                             dir_fd=at)
                with os.fdopen(fd, "wb") as f:
                    while left > 0:
                        data = batch.read(min(left, 1048576))
                        if not data:
                            fail("git cat-file stopped in the object of %s" % shown(path))
                        f.write(data)
                        left -= len(data)
            if batch.read(1) != b"\n":
                fail("git cat-file did not give the object of %s" % shown(path))
        except FileExistsError:
            fail("%s names a file another path took already, as on a volume that ignores letter case" % shown(path))
        except OSError as why:
            fail("%s cannot be written there (%s), as when a directory on its way is a symbolic link" % (shown(path), why.strerror or why))


try:
    if sys.argv[1] == "plan":
        plan(sys.argv[2], sys.argv[3])
    else:
        write(sys.argv[2], sys.argv[3])
except SystemExit:
    raise
except BaseException as why:
    fail("%s: %s" % ("cannot be read from git" if sys.argv[1] == "plan" else "git gave an answer that cannot be read",
                     str(why) or type(why).__name__))
'
# submodules <names>: the revision has gitlinks, which target.sh never fetches. Strict mode stops; otherwise a
# note says so, and the build sees each as the empty directory a checkout leaves.
submodules() {
  [ "$CONFINE_STRICT" = 0 ] || finish 3 "$SHA has submodules ($(confine_text "$1")), and target.sh never fetches them"
  echo ">> note: $SHA has submodules ($(confine_text "$1")), which target.sh never fetches: the build sees them as empty directories; strict mode stops here (Rule 11f)"
  printf '>> submodules, not fetched: %s\n' "$(confine_text "$1")" >&9
}
# export_tree: the copy for a git without the May-2024 clone fixes, or of a source another user owns, outside
# strict mode: the tracked files of SHA, read through hgit_tree and written by EXPORT_PY into S/src, which
# becomes a repository with no commit, so that git stops there and finds no other above it.
export_tree() {
  local why
  hgit_tree "$SRC_ABS" ls-tree -r -z --full-tree "$SHA" > "$S/tree.z" 2>&9 || finish 3 "git could not list the files of $SHA"
  names=$( (cd / && exec python3 -I -c "$EXPORT_PY" plan "$S/tree.z" "$S/oids") 2>&9) ||
    finish 3 "$SHA ${names:-cannot be read from git}"
  [ -z "$names" ] || submodules "${names//$'\n'/, }"
  mkdir "$S/src" || finish 3 "cannot create the copy in $S"
  why=$(hgit_tree "$SRC_ABS" cat-file --batch < "$S/oids" 2>&9 | (cd / && exec python3 -I -c "$EXPORT_PY" write "$S/tree.z" "$S/src") 2>&9) ||
    finish 3 "could not copy the tracked files of $SHA: ${why:-git cat-file failed}"
  CONFINE_CEILING=${S%/*} hgit "$S" init --quiet --template= -- "$S/src" </dev/null >&9 2>&9 ||
    finish 3 "git could not make a repository of the copy"
}
if [ "$SRC_KIND" = repo ]; then
  if [ "$CLONE" = 1 ]; then
    printf '>> git clone --no-local --no-checkout --no-recurse-submodules --template= %s\n' "$SRC_SHOWN" >&9
    CONFINE_GIT_GLOBAL=/dev/null CONFINE_ALLOW_PROTOCOL=file CONFINE_CEILING=${S%/*} hgit "$S" -c protocol.file.allow=always \
      clone --no-local --no-checkout --no-recurse-submodules --template= -- "$SRC_ABS" "$S/src" </dev/null >&9 2>&9 ||
      finish 3 "git could not clone $SRC_SHOWN"
    SHA=$(hgit "$S/src" rev-parse --verify --quiet --end-of-options "${REV:-HEAD}^{commit}" 2>&9) && [ -n "$SHA" ] ||
      finish 3 "$(confine_text "${REV:-HEAD}") is not a commit in $SRC_SHOWN"
    printf '>> git checkout --detach %s\n' "$SHA" >&9
    hgit "$S/src" -c advice.detachedHead=false checkout --quiet --detach "$SHA" </dev/null >&9 2>&9 ||
      finish 3 "git could not check out $SHA"
    hgit "$S/src" ls-tree -r "$SHA" > "$S/tree" 2>&9 || finish 3 "git could not list the files of $SHA"
    subs=$(grep -c '^160000 ' "$S/tree")
    if [ "${subs:-0}" -gt 0 ]; then
      names=""
      grep '^160000 ' "$S/tree" > "$S/gitlinks"
      while IFS= read -r line; do names=${names:+$names, }$(confine_text "${line#*$'\t'}"); done < "$S/gitlinks"
      submodules "$names"
    fi
    APPLY=(apply --index)
    how=""
  else
    printf '>> git ls-tree -r and git cat-file --batch of %s, not git clone: %s\n' "$SRC_SHOWN" "$EXPORT_WHY" >&9
    SHA=$(hgit_tree "$SRC_ABS" rev-parse --verify --quiet --end-of-options "${REV:-HEAD}^{commit}" 2>&9) && [ -n "$SHA" ] ||
      finish 3 "$(confine_text "${REV:-HEAD}") is not a commit in $SRC_SHOWN"
    export_tree
    APPLY=(apply)
    how=", its tracked files written from git ls-tree and git cat-file --batch"
  fi
  if [ -n "$PATCH_REL" ]; then
    iso_copy_new "$WT/$PATCH_REL" "$S/patch" || finish 3 "$PATCH_REL cannot be read"
    printf '>> git %s %s\n' "${APPLY[*]}" "$PATCH_REL" >&9
    hgit "$S/src" "${APPLY[@]}" --whitespace=nowarn -- "$S/patch" </dev/null >&9 2>&9 ||
      finish 3 "$PATCH_REL does not apply to $SHA"
  fi
  printf '>> the copy: %s at %s%s%s\n' "$SRC_SHOWN" "$SHA" "$how" "${CONFINE_PREFIX:+; the working directory is ${CONFINE_PREFIX%/} in it}" >&9
else
  printf '>> the copy: the files of %s, links as links, without run directories, the store, target/ and node_modules/\n' "$SRC_SHOWN" >&9
  # Each name in any letter case: a volume that ignores case finds audit_1 under the name AUDIT_1.
  (cd "$SRC_ABS" && find . \( -path './[Aa][Uu][Dd][Ii][Tt]_*' -o -path './[Ii][Nn][Cc][Ii][Dd][Ee][Nn][Tt]_*' -o \
    -path './.[Aa][Uu][Dd][Ii][Tt]-[Mm][Ee][Mm][Oo][Rr][Yy]' -o \( -type d \( -iname target -o -iname node_modules \) \) \) -prune -o \
    \( -type d -o -type f -o -type l \) -print0) \
    > "$S/list" 2>&9 || finish 3 "find cannot list all of $SRC_SHOWN"
  mkdir "$S/src" || finish 3 "cannot create the copy in $S"
  while IFS= read -r -d '' rel; do
    [ "$rel" != . ] || continue
    if [ -L "$SRC_ABS/$rel" ]; then cp -RP -- "$SRC_ABS/$rel" "$S/src/$rel" 2>&9
    elif [ -d "$SRC_ABS/$rel" ]; then mkdir -- "$S/src/$rel" 2>&9
    elif [ -f "$SRC_ABS/$rel" ]; then cp -p -- "$SRC_ABS/$rel" "$S/src/$rel" 2>&9
    else continue
    fi || finish 3 "could not copy $(confine_text "${rel#./}") from $SRC_SHOWN"
  done < "$S/list"
fi
AD=$S/src
if [ -n "$DIR_ARG" ]; then
  rest=$DIR_ARG
  while :; do
    AD=$AD/${rest%%/*}
    { [ ! -L "$AD" ] && [ -d "$AD" ]; } || finish 3 "--dir $DIR_ARG is not a directory in the copy (or passes through a symbolic link)"
    case "$rest" in */*) rest=${rest#*/} ;; *) break ;; esac
  done
fi
at=${DIR_ARG:-the top of the copy}
real_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
note() { echo ">> note: $1"; printf '>> note: %s\n' "$1" >&9; }

# What rust_toolchain runs with python3 -I, from /: "<file>" prints the plain channel a rust-toolchain file
# names, the one line of its legacy form or the channel of its [toolchain] table; exit 1 for anything else:
# a file that is not regular or over 64 KiB, a path key (a toolchain of the copy's own), a channel that is no
# plain name, or a line it cannot read.
TOOLCHAIN_PY='import os, re, stat, sys

CHANNEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}")
HEADER = re.compile(r"\[\s*([A-Za-z0-9_.-]+)\s*\]\s*(#.*)?")
KEY = re.compile(r"([A-Za-z0-9_.-]+)\s*=\s*(.*)")
STRING = re.compile(r"\x22([^\x22\\]*)\x22\s*(#.*)?|\x27([^\x27]*)\x27\s*(#.*)?")
try:
    st = os.lstat(sys.argv[1])
    if not stat.S_ISREG(st.st_mode) or st.st_size > 65536:
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        lines = [l.strip() for l in f.read().decode("utf-8-sig").splitlines()]
except (OSError, UnicodeDecodeError):
    sys.exit(1)
lines = [l for l in lines if l and not l.startswith("#")]
if not any(l.startswith("[") or "=" in l for l in lines):
    if len(lines) == 1 and CHANNEL.fullmatch(lines[0]):
        print(lines[0])
        sys.exit(0)
    sys.exit(1)
table, channel, depth = "", None, 0
for line in lines:
    if depth > 0:
        depth += line.count("[") - line.count("]")
        continue
    m = HEADER.fullmatch(line)
    if m:
        table = m.group(1)
        continue
    m = KEY.fullmatch(line)
    if not m:
        sys.exit(1)
    key, value = m.group(1), m.group(2)
    if value.startswith("["):
        depth = value.count("[") - value.count("]")
    if table == "" and key.startswith("toolchain."):
        key = key[len("toolchain."):]
    elif table != "toolchain":
        continue
    if key == "path":
        sys.exit(1)
    if key == "channel":
        v = STRING.fullmatch(value)
        if not v:
            sys.exit(1)
        channel = v.group(1) if v.group(1) is not None else v.group(3)
if channel is None or not CHANNEL.fullmatch(channel):
    sys.exit(1)
print(channel)
'
# rust_toolchain: outside strict mode, when target.sh pinned rustup's default (no RUSTUP_TOOLCHAIN from the
# caller), the plain channel the copy's top-level rust-toolchain names, else its rust-toolchain.toml (rustup
# reads the first when both are there): pinned instead when rustup has it installed. A note says which.
rust_toolchain() {
  local f c
  for f in rust-toolchain rust-toolchain.toml; do
    [ -e "$S/src/$f" ] || [ -L "$S/src/$f" ] || continue
    c=$( (cd / && exec python3 -I -c "$TOOLCHAIN_PY" "$S/src/$f") 2>/dev/null) || c=""
    if [ -z "$c" ]; then
      note "the copy's $f names a toolchain by path, or no plain channel, which target.sh does not take; building with $TC_DEFAULT"
    elif (cd "$S" && iso_run rustup which --toolchain "$c" cargo) >/dev/null 2>&1 </dev/null; then
      ISO_ENV+=("RUSTUP_TOOLCHAIN=$c")
      note "the copy's $f pins $c; building with it"
    else
      note "the copy pins $c, which rustup has not installed; building with $TC_DEFAULT (rustup toolchain install $c adds it)"
    fi
    return 0
  done
}
[ "$CONFINE_STRICT" = 1 ] || [ -z "$TC_DEFAULT" ] || rust_toolchain
# What no_npmrc runs with python3 -I, from /, outside strict mode: "<.npmrc>" rewrites a regular file of at
# most 1 MiB to hold only its registry= and @<scope>:registry= lines whose value is an https URL with no
# space, control character or $ (npm expands ${VAR} from its environment), as key=value, and prints them,
# each cut after 200 characters, joined with ", "; exit 1, the file as it was, when no line is kept.
NPMRC_PY='import os, re, stat, sys

LINE = re.compile(r"\s*(registry|@[A-Za-z0-9._~-]+:registry)\s*=\s*(https://[^\s$\x00-\x1f\x7f]+)\s*")
path = sys.argv[1]
try:
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_size > 1048576:
        sys.exit(1)
    with open(path, "rb") as f:
        lines = f.read().decode("utf-8").splitlines()
except (OSError, UnicodeDecodeError):
    sys.exit(1)
kept = ["%s=%s" % m.groups() for m in map(LINE.fullmatch, lines) if m]
if not kept:
    sys.exit(1)
os.unlink(path)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
with os.fdopen(fd, "w") as f:
    f.write("\n".join(kept) + "\n")
print(", ".join(k[:200] for k in kept))
'
# no_npmrc: npm takes a project's settings from the .npmrc of the package root it finds from its working
# directory up (a workspace's root above it among them), and expands ${VAR} in them from its environment, the
# proxy variables included. Before npm ci, every .npmrc from the top of the copy down to AD goes, of any kind,
# but outside strict mode the plain https registry lines of each stay (NPMRC_PY), and a note names them.
no_npmrc() {
  local d=$S/src rel="" rest=$DIR_ARG gone="" kept
  while :; do
    if [ -e "$d/.npmrc" ] || [ -L "$d/.npmrc" ]; then
      kept=""
      [ "$CONFINE_STRICT" = 1 ] || kept=$( (cd / && exec python3 -I -c "$NPMRC_PY" "$d/.npmrc") 2>/dev/null) || kept=""
      if [ -n "$kept" ]; then
        note "npm ci takes only the https registry lines of ${rel}.npmrc from the code under audit: target.sh kept $kept, and removed every other line"
      else
        rm -rf -- "$d/.npmrc" 2>&9
        { [ ! -e "$d/.npmrc" ] && [ ! -L "$d/.npmrc" ]; } || finish 3 "cannot remove ${rel}.npmrc from the copy before npm ci"
        gone=${gone:+$gone, }${rel}.npmrc
      fi
    fi
    [ -n "$rest" ] || break
    d=$d/${rest%%/*}
    rel=$rel${rest%%/*}/
    case "$rest" in */*) rest=${rest#*/} ;; *) rest="" ;; esac
  done
  [ -n "$gone" ] || return 0
  echo ">> note: npm ci takes no settings from the code under audit: target.sh removed these from the copy, and the registry and other settings they name do not apply: $gone"
  printf '>> removed from the copy before npm ci: %s\n' "$gone" >&9
}
# npm_ci: npm ci --ignore-scripts in AD, a download, after no_npmrc; a note when it stopped at a script npm
# tried to run. NODE_OPTIONS quotes the path of the preload, and it cannot quote a double quote or a backslash.
npm_ci() {
  case "$S" in *[\"\\]*) finish 3 "the scratch directory's path holds a double quote or a backslash, which NODE_OPTIONS cannot carry to npm; point TMPDIR elsewhere" ;; esac
  no_npmrc
  step "$AD" ${NET[@]+"${NET[@]}"} ${NPM[@]+"${NPM[@]}"} npm ci --ignore-scripts --no-audit --no-fund
  [ "$STEP_END" != "exit 0" ] || return 0
  if grep -qF -e "target.sh: npm starts no program here" -e "command $FALSE -c " "$S/log" 2>/dev/null; then
    echo ">> note: npm tried to run a dependency's script (npm 10 runs the prepare script of a git or directory dependency despite --ignore-scripts), and no script runs in target.sh's npm step, so npm ci stopped there"
  fi
}

# ---- the downloads -------------------------------------------------------------------------------------
case "$ACTION" in
  npm-ci)
    real_file "$AD/package.json" && { real_file "$AD/package-lock.json" || real_file "$AD/npm-shrinkwrap.json"; } ||
      finish 3 "npm ci needs package.json and package-lock.json (or npm-shrinkwrap.json) at $at" ;;
  *)
    real_file "$AD/Cargo.toml" || finish 3 "no Cargo.toml at $at"
    case "$ACTION" in anchor-*) real_file "$AD/Anchor.toml" || finish 3 "no Anchor.toml at $at" ;; esac
    step "$S" ${NET[@]+"${NET[@]}"} cargo fetch --manifest-path "$AD/Cargo.toml"
    fetched "cargo fetch, the download of the dependencies," ;;
esac
TV=()
[ -z "${TOOLS_VERSION:-}" ] || TV=(--tools-version "$TOOLS_VERSION")
# SBF_SPLIT=1: cargo build-sbf --install-only puts the platform tools in the real HOME, and the build runs
# offline in the throwaway HOME. A cargo build-sbf without those options (SBF_SPLIT=0) builds without them,
# with SBF_ENV: natively offline in the throwaway HOME still, so its build's code gets neither the real home
# folder nor the network, and the platform tools must already be in ~/.cache/solana (sbf_tools); in isolated
# mode with the real HOME and the proxy variables, as templates/poc/run.sh builds each arm then.
link_tools() {
  { confine_mkdir "$ISO_HOME/.cache" && ln -s "$ISO_REAL_HOME/.cache/solana" "$ISO_HOME/.cache/solana"; } ||
    finish 3 "cannot link the platform tools into the throwaway HOME $ISO_HOME"
}
# sbf_tools: the platform tools such a cargo build-sbf builds with natively, TOOLS_VERSION or the version its
# --version names, which the offline build cannot fetch: sets TOOLS ("platform-tools v1.43") when
# ~/.cache/solana holds them; otherwise the run stops and names the install.
sbf_tools() {
  local v="" kind="" k line out lacks="this cargo build-sbf has no --install-only, --skip-tools-install or --offline, so in native mode it builds offline in the throwaway HOME, with only the platform tools already in ~/.cache/solana"
  if [ -n "${TOOLS_VERSION:-}" ]; then
    v=$TOOLS_VERSION
  else
    out=$(cd "$S" && iso_run cargo build-sbf --version 2>/dev/null </dev/null) || out=""
    # Line by line with no here-string: bash 3.2 writes a here-string to a file in the working directory.
    while [ -n "$out" ]; do
      line=${out%%$'\n'*}
      case "$out" in *$'\n'*) out=${out#*$'\n'} ;; *) out="" ;; esac
      case "$line" in
        'platform-tools v'*|'sbf-tools v'*|'bpf-tools v'*) kind=${line%% *}; v=${line#* }; v=${v%% *}; break ;;
      esac
    done
  fi
  [[ "$v" =~ $TOOLS_SPEC ]] ||
    finish 3 "$lacks, and its --version names no platform tools version to look for there; set TOOLS_VERSION to the one it uses"
  for k in ${kind:-platform-tools sbf-tools bpf-tools}; do
    if [ -d "$ISO_REAL_HOME/.cache/solana/$v/$k" ]; then TOOLS="$k $v"; return 0; fi
  done
  finish 3 "$lacks, and ${kind:-platform-tools} $v is not there; install it once outside the audit (cargo build-sbf --tools-version $v in any program crate downloads it), then run this again"
}
# iso_value <NAME>: the value the cleaned environment gives NAME (its last entry), or nothing.
iso_value() {
  local e v=""
  for e in ${ISO_ENV[@]+"${ISO_ENV[@]}"}; do case "$e" in "$1="*) v=${e#*=} ;; esac; done
  printf '%s' "$v"
}
# anchor_options: what this anchor takes, from its own help (anchor, not the copy's code): AB, anchor build
# with --ignore-keys where it has one (Anchor 1.0 and later; 0.31 has none), ANCHOR_NOIDL=1 when anchor build
# has --no-idl and anchor idl build has --out-ts (Anchor 0.30 and later, whose IDL build runs cargo test),
# ANCHOR_TV=1 when anchor build has its own --tools-version (Anchor 1.2 and later).
anchor_options() {
  local h i
  h=$(cd "$AD" && iso_run "${OFF[@]}" anchor build --help 2>/dev/null </dev/null) || h=""
  i=$(cd "$AD" && iso_run "${OFF[@]}" anchor idl build --help 2>/dev/null </dev/null) || i=""
  ANCHOR_NOIDL=0 ANCHOR_TV=0 AB=(anchor build)
  case "$h" in *--ignore-keys*) AB+=(--ignore-keys) ;; esac
  case "$h" in *--no-idl*) case "$i" in *--out-ts*) ANCHOR_NOIDL=1 ;; esac ;; esac
  case "$h" in *'--tools-version <'*) ANCHOR_TV=1 ;; esac
  printf '>> anchor build --help: --no-idl and anchor idl build %s; its own --tools-version %s\n' \
    "$([ "$ANCHOR_NOIDL" = 1 ] && echo yes || echo no)" "$([ "$ANCHOR_TV" = 1 ] && echo yes || echo no)" >&9
}
# anchor_tools: with no TOOLS_VERSION, the platform tools this anchor asks cargo build-sbf for (Anchor 1.2 asks
# for v1.57 with --arch v3, past cargo build-sbf's own default), learned from one anchor build --no-idl with a
# cargo-build-sbf first on PATH that records its options and builds nothing (it passes --version and --help to
# the real one). INSTALL_TV then installs that version. Learning nothing leaves cargo build-sbf's default.
anchor_tools() {
  local real line rest v=""
  [ -z "${TOOLS_VERSION:-}" ] && [ "$ANCHOR_NOIDL" = 1 ] || return 0
  real=$(command -v cargo-build-sbf) || return 0
  { mkdir "$S/rec" &&
    printf '#!/bin/sh\ncase " $* " in *" --version "*|*" --help "*|*" -V "*|*" -h "*) exec "%s" "$@" ;; esac\nprintf "%%s\\n" "$*" >> "%s/rec/args"\nexit 0\n' \
      "$real" "$S" > "$S/rec/cargo-build-sbf" && chmod +x "$S/rec/cargo-build-sbf"; } ||
    finish 3 "cannot write the recording cargo-build-sbf in $S"
  step "$AD" "${OFF[@]}" "PATH=$S/rec:$(iso_value PATH)" "${AB[@]}" --no-idl ${PKG[@]+"${PKG[@]}"} -- --skip-tools-install --offline
  if [ -f "$S/rec/args" ]; then
    while IFS= read -r line; do
      case " $line " in *" --tools-version "*) rest=${line#*--tools-version }; v=${rest%% *}; break ;; esac
    done < "$S/rec/args"
  fi
  if [[ "$v" =~ $TOOLS_SPEC ]]; then
    INSTALL_TV=(--tools-version "$v")
    printf '>> anchor asks cargo build-sbf for platform tools %s, so target.sh installs that version\n' "$v" >&9
  else
    printf '>> anchor named no platform tools version (%s), so cargo build-sbf installs its own default\n' "$STEP_END" >&9
  fi
}
# avm's anchor shim looks for its releases in AVM_HOME (isolation.sh sets it), and avm releases that predate
# it look in ~/.avm: the throwaway HOME links the real one.
INSTALL_TV=(${TV[@]+"${TV[@]}"})
PKG=()
case "$ACTION" in
  anchor-*)
    if [ -d "$ISO_REAL_HOME/.avm" ]; then
      ln -s "$ISO_REAL_HOME/.avm" "$ISO_HOME/.avm" || finish 3 "cannot link ~/.avm into the throwaway HOME $ISO_HOME"
    fi
    [ -z "$PROGRAM" ] || PKG=(-p "$PROGRAM")
    anchor_options ;;
esac
SBF_SPLIT=1
SBF_ENV=()
case "$ACTION" in
  anchor-*|build-sbf)
    sbf_help=$(cd "$S" && iso_run cargo build-sbf --help 2>/dev/null </dev/null) || sbf_help=""
    [[ "$sbf_help" == *--install-only* && "$sbf_help" == *--skip-tools-install* && "$sbf_help" == *--offline* ]] || SBF_SPLIT=0
    [ -n "$ISO_REAL_HOME" ] || finish 3 "HOME is not set, and cargo build-sbf keeps its platform tools there"
    if [ "$SBF_SPLIT" = 1 ]; then
      [ "$ACTION" = build-sbf ] || anchor_tools
      step "$S" ${NET[@]+"${NET[@]}"} "HOME=$ISO_REAL_HOME" cargo build-sbf --install-only ${INSTALL_TV[@]+"${INSTALL_TV[@]}"}
      fetched "cargo build-sbf --install-only, the install of the platform tools,"
      link_tools
    elif [ "$MODE" = native ]; then
      sbf_tools
      # Only that version's directory is linked: such a cargo build-sbf that finds its tools unusable removes
      # their version directory to install them again (Agave 2.1.15 does, with v1.51's), which then removes the
      # link, not the real tools.
      { confine_mkdir "$ISO_HOME/.cache" && confine_mkdir "$ISO_HOME/.cache/solana" &&
        ln -s "$ISO_REAL_HOME/.cache/solana/${TOOLS#* }" "$ISO_HOME/.cache/solana/${TOOLS#* }"; } ||
        finish 3 "cannot link the platform tools into the throwaway HOME $ISO_HOME"
      SBF_ENV=("${OFF[@]}")
      note "this cargo build-sbf has no --install-only, --skip-tools-install or --offline: in native mode the build runs offline in the throwaway HOME, with $TOOLS from ~/.cache/solana"
    else
      SBF_ENV=(${NET[@]+"${NET[@]}"} "HOME=$ISO_REAL_HOME")
      echo ">> note: this cargo build-sbf has no --install-only, --skip-tools-install or --offline: in isolated mode the build runs with the real HOME and the proxy variables"
      printf '>> no --install-only: the build runs with the real HOME and the proxy variables\n' >&9
    fi ;;
esac
if [ "$ACTION" = anchor-test ]; then
  if real_file "$AD/package-lock.json" || real_file "$AD/npm-shrinkwrap.json"; then
    command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1 || finish 3 "$at holds a package lock, and npm or node is not on PATH"
    npm_ci
    fetched "npm ci --ignore-scripts, the install of the JavaScript dependencies,"
  elif real_file "$AD/yarn.lock" || real_file "$AD/pnpm-lock.yaml" || real_file "$AD/bun.lock"; then
    echo ">> note: $at holds a yarn, pnpm or bun lockfile; target.sh installs JavaScript dependencies only from package-lock.json, so a test script that needs node_modules fails"
    printf '>> note: no JavaScript dependencies installed: target.sh installs them only from package-lock.json\n' >&9
  fi
fi

# idl_build: for anchor-test, the IDL of each program the build made, for test scripts that import
# target/types: anchor idl build, in a step of its own, with no build-sbf options and no RUSTUP_TOOLCHAIN,
# which anchor-cli 1.1 and 1.2 mishandle (they try to install the toolchain, then run "cargo +{toolchain}").
# The pinned toolchain goes instead into a rust-toolchain.toml at the top of the copy, once every
# rust-toolchain file the copy holds is removed, so that no toolchain path comes from the repository.
idl_build() {
  local so name pin e
  local -a saved=() kept=()
  [ "$ANCHOR_NOIDL" = 1 ] || return 0
  saved=(${ISO_ENV[@]+"${ISO_ENV[@]}"})
  for e in ${ISO_ENV[@]+"${ISO_ENV[@]}"}; do case "$e" in RUSTUP_TOOLCHAIN=*) ;; *) kept+=("$e") ;; esac; done
  pin=$(iso_value RUSTUP_TOOLCHAIN)
  if [ -n "$pin" ]; then
    [[ "$pin" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$ ]] ||
      finish 3 "the pinned toolchain $(confine_text "$pin") is no plain channel name, which a rust-toolchain.toml would need"
    find "$S/src" -path "$S/src/.git" -prune -o \( -name rust-toolchain -o -name rust-toolchain.toml \) \( -type f -o -type l \) \
      -exec rm -f -- {} + 2>&9 || finish 3 "cannot remove the copy's rust-toolchain files"
    printf '[toolchain]\nchannel = "%s"\n' "$pin" > "$S/src/rust-toolchain.toml" ||
      finish 3 "cannot write a rust-toolchain.toml at the top of the copy"
    printf '>> the copy'"'"'s rust-toolchain files removed, and a rust-toolchain.toml at its top names %s\n' "$pin" >&9
  fi
  { mkdir -p "$AD/target/idl" && mkdir -p "$AD/target/types"; } 2>&9 || finish 3 "cannot create target/idl and target/types at $at"
  ISO_ENV=(${kept[@]+"${kept[@]}"})
  for so in "$AD/target/deploy/"*.so; do
    [ -f "$so" ] || continue
    name=${so##*/}
    name=${name%.so}
    step "$AD" "${OFF[@]}" anchor idl build -p "$name" -o "$AD/target/idl/$name.json" -t "$AD/target/types/$name.ts"
    outcome "anchor idl build"
  done
  ISO_ENV=(${saved[@]+"${saved[@]}"})
}

# ---- the action ----------------------------------------------------------------------------------------
case "$ACTION" in
  build-sbf)
    MP=()
    if [ -n "$PACKAGE" ]; then
      STEP_OUT=$S/metadata.json
      step "$S" "${OFF[@]}" cargo metadata --no-deps --format-version 1 --offline --manifest-path "$AD/Cargo.toml"
      STEP_OUT=""
      fetched "cargo metadata, the list of the workspace's packages,"
      mp=$( (cd / && exec python3 -I -c 'import json, os, sys
meta, name, top = sys.argv[1:4]
with open(meta, encoding="utf-8") as f:
    data = json.load(f)
members = set(data.get("workspace_members") or [])
found = [p.get("manifest_path", "") for p in data.get("packages", []) if p.get("name") == name and p.get("id") in members]
if len(found) != 1:
    sys.exit(3)
path = os.path.realpath(found[0])
if not path.startswith(os.path.realpath(top) + os.sep):
    sys.exit(3)
print(path)' "$S/metadata.json" "$PACKAGE" "$S/src") 2>/dev/null) && [ -n "$mp" ] ||
        finish 3 "the workspace at $at has no member package $PACKAGE"
      MP=(--manifest-path "$mp")
    fi
    mkdir "$S/out" || finish 3 "cannot create the build output directory in $S"
    SO_FROM=$S/out
    if [ "$SBF_SPLIT" = 1 ]; then
      step "$AD" "${OFF[@]}" cargo build-sbf --skip-tools-install --offline --sbf-out-dir "$S/out" ${TV[@]+"${TV[@]}"} ${MP[@]+"${MP[@]}"}
    else
      step "$AD" ${SBF_ENV[@]+"${SBF_ENV[@]}"} cargo build-sbf --sbf-out-dir "$S/out" ${TV[@]+"${TV[@]}"} ${MP[@]+"${MP[@]}"}
    fi
    outcome "cargo build-sbf"
    finish 0 "ok (exit 0)" ;;
  cargo-test|clippy)
    if [ -n "$PACKAGE" ]; then PKG=(-p "$PACKAGE"); else PKG=(--workspace); fi
    if [ "$ACTION" = cargo-test ]; then
      step "$AD" "${OFF[@]}" cargo test --offline "${PKG[@]}"
      outcome "cargo test"
      finish 0 "ok (exit 0)"
    fi
    (cd "$S" && iso_run cargo clippy --version) >/dev/null 2>&1 </dev/null ||
      finish 3 "clippy is not installed for the pinned toolchain (rustup component add clippy)"
    step "$AD" "${OFF[@]}" cargo clippy --offline --all-targets "${PKG[@]}" -- -W clippy::all -W clippy::pedantic
    outcome "cargo clippy"
    warnings=$(grep -c '^warning: ' "$S/log")
    finish 0 "ok (exit 0), ${warnings:-0} warning lines" ;;
  anchor-build|anchor-test)
    SO_FROM=$AD/target/deploy
    # --no-idl where this anchor builds its IDL with cargo test (anchor_options), which would get the build-sbf
    # options after -- and the RUSTUP_TOOLCHAIN pin: anchor-test builds the IDL in a step of its own
    # (idl_build). TOOLS_VERSION is anchor build's own --tools-version where it has one, else after --.
    [ "$ANCHOR_NOIDL" = 0 ] || AB+=(--no-idl)
    SBF_ARGS=()
    if [ -n "${TV[*]-}" ]; then
      if [ "$ANCHOR_TV" = 1 ]; then AB+=("${TV[@]}"); else SBF_ARGS=("${TV[@]}"); fi
    fi
    if [ "$SBF_SPLIT" = 1 ]; then
      step "$AD" "${OFF[@]}" "${AB[@]}" ${PKG[@]+"${PKG[@]}"} -- --skip-tools-install --offline ${SBF_ARGS[@]+"${SBF_ARGS[@]}"}
    else
      [ "${#SBF_ARGS[@]}" = 0 ] || SBF_ARGS=(-- "${SBF_ARGS[@]}")
      step "$AD" ${SBF_ENV[@]+"${SBF_ENV[@]}"} "${AB[@]}" ${PKG[@]+"${PKG[@]}"} ${SBF_ARGS[@]+"${SBF_ARGS[@]}"}
    fi
    # Platform tools that lack the program's target: rustc finds no core crate for it.
    if [ "$STEP_END" != "exit 0" ] && grep -q "can't find crate for \`core\`" "$S/log"; then
      tools=${INSTALL_TV[1]:-}
      [ -n "$tools" ] || tools="the default of cargo build-sbf"
      finish 3 "anchor build found no core crate for the program's target: the platform tools it built with ($tools) lack that target; set TOOLS_VERSION to the platform tools version this Anchor asks for (Anchor 1.2 asks for v1.57) and run this again"
    fi
    outcome "anchor build"
    [ "$ACTION" = anchor-test ] || finish 0 "ok (exit 0)"
    idl_build
    step "$AD" "${OFF[@]}" anchor test --skip-build --skip-deploy --skip-local-validator --provider.cluster localnet \
      --provider.wallet "$ISO_HOME/.config/solana/id.json" ${PKG[@]+"${PKG[@]}"}
    outcome "anchor test"
    finish 0 "ok (exit 0)" ;;
  npm-ci)
    npm_ci
    outcome "npm ci --ignore-scripts"
    finish 0 "ok (exit 0)" ;;
esac
