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
#   anchor-build  anchor build --ignore-keys [-p <program>] -- --skip-tools-install --offline [--tools-version <v>]
#   anchor-test   npm ci --ignore-scripts --no-audit --no-fund when that directory holds package-lock.json,
#                 then the anchor-build command, then anchor test --skip-build --skip-deploy
#                 --skip-local-validator --provider.cluster localnet --provider.wallet <the throwaway keypair>
#                 [-p <program>]: the test script runs against no validator and nothing is deployed
#   build-sbf     cargo build-sbf --skip-tools-install --offline --sbf-out-dir <scratch> [--tools-version <v>]
#                 [--manifest-path <the Cargo.toml of --package>]
#   cargo-test    cargo test --offline, with -p <package> or --workspace
#   clippy        cargo clippy --offline --all-targets, with -p <package> or --workspace, -- -W clippy::all
#                 -W clippy::pedantic
#   npm-ci        npm ci --ignore-scripts --no-audit --no-fund (checklist 11 SC-012)
# --package names a cargo package (build-sbf, cargo-test, clippy) and --program an Anchor program
# (anchor-build, anchor-test). <v> is TOOLS_VERSION from the environment, v<n>.<n> or v<n>.<n>.<n>; without
# it cargo build-sbf uses its own default.
#
# The mode is the stricter of <R>/exec-mode (one word, none, isolated or native, written when the human
# answers Q46) and AUDITOR_EXEC_MODE: none, then isolated, then native. With neither, with none, or with a
# --mode that names another mode, target.sh stops (exit 3) before it copies anything. In isolated mode the
# credential self-check of scripts/lib/isolation.sh runs first: something it reads that is readable, or a
# check that cannot finish, stops the run. In native mode the same check prints, as a warning, what the code
# the run builds can read, by kind and count, never a path. An incident's code (--run incident_<n>) is built
# only once incident_<n>/INCIDENTS.json (a regular file of at most 4 MiB) records the root_cause_class of the
# incident --patch names (INC-<n>.<k>), or of every incident without one; supply_chain_or_ci is never built
# natively (OUTPUT-RULES.md Rule 11a).
#
# The copy, in a scratch directory outside the working directory. A --src that is the top level of a git
# repository (its git directory inside the working directory, holding no symbolic link, borrowing no objects
# and rewriting no parents, and not a partial clone), or a copy git-ro.sh copy made in <R>, is cloned with
# --no-local, no hooks and no submodules, system and global git config dropped. --rev (HEAD when absent)
# must name a commit, which is checked out; --patch, a file in <R>/patches/ of at most 16 MiB, is applied
# with git apply --index. A revision that has submodules stops the run: target.sh never fetches them. Any
# other directory --src names is copied file by file, symbolic links kept as links, without audit_*,
# incident_* and .audit-memory at its top, and without target/ or node_modules/ directories; --rev and
# --patch need a repository. --dir is a path inside the copy with no symbolic link on the way.
#
# The environment of every step is the cleaned one of scripts/lib/isolation.sh: env -i, a throwaway HOME
# holding a fresh Solana keypair, TMPDIR in the scratch directory, the cleaned PATH, the user's CARGO_HOME and
# RUSTUP_HOME, and RUSTUP_TOOLCHAIN pinned to the caller's value, else rustup's default, with
# RUSTUP_AUTO_INSTALL=0: the copy's rust-toolchain file is not read. The downloads come first, and none of
# them runs code from the copy: cargo fetch, started outside the copy so that the copy's .cargo/config is
# not read either; cargo build-sbf --install-only, with the real HOME, where the platform tools live; and
# npm ci --ignore-scripts, with npm's user and global config files empty, its cache and logs in the scratch
# directory and its git the one on PATH. Only these get the proxy variables. Every build and test after them
# runs offline (CARGO_NET_OFFLINE=true), without the proxy variables, in the throwaway HOME, whose
# .cache/solana links to the real one. Anchor.toml's [toolchain] can still make anchor fetch another Solana
# or Anchor release; that would land in the throwaway HOME, and offline it fails.
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
# Exit: 0 the action succeeded · 1 it ran and failed · 3 blocker (no mode or mode none, the self-check, a tool
# missing, a revision or package not found, a patch that does not apply, submodules, a download that failed,
# the watchdog, an incident whose root cause INCIDENTS.json does not give or that may not build natively) ·
# 64 refused. Needs bash >= 3.2, git, python3, env, find, grep, mkdir, mktemp, rm, chmod, cp,
# ln, cat, wc, tail and date; cargo, cargo-build-sbf, anchor or npm as the action needs.

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
  if out=$(hgit "$phys" rev-parse --is-bare-repository 2>&1); then
    case "$out" in
      true) ;;
      false)
        top=$(hgit "$phys" rev-parse --show-toplevel 2>/dev/null) || refuse "git cannot describe the repository at --src: $SRC_SHOWN"
        if ! confine_phys "$top" || [ "$CONFINE_PHYS" != "$phys" ]; then
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
  fi
  case "$out" in
    *'not a git repository'*) SRC_KIND=tree; SRC_ABS=$phys ;;
    *) refuse "git cannot tell whether --src is a repository (none there, or another user owns it: audit a copy): $SRC_SHOWN" ;;
  esac
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
SOURCES="$R/exec-mode: ${FILE_MODE:-absent}; AUDITOR_EXEC_MODE: ${ENV_MODE:-unset}"
if [ -z "$FILE_MODE$ENV_MODE" ]; then
  blocker "no recorded mode: $R/exec-mode is missing and AUDITOR_EXEC_MODE is not set (OUTPUT-RULES.md Rule 11a, QUESTIONS.md Q46). Record the human's answer in $R/exec-mode and run this again — nothing was copied or built."
fi
case " $FILE_MODE $ENV_MODE " in
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
echo ">> execution mode: $MODE (the stricter of $SOURCES)"

# What the incident check runs with python3 -I: "<INCIDENTS.json> [<INC-n.k>]" prints that incident's
# root_cause_class, or with no id supply_chain_or_ci when any incident has it and "other" otherwise; exit 3
# with the reason when the file, an incident or a class cannot be read.
INCIDENT_PY='import json, os, stat, sys

CLASSES = ("code_flaw", "key_compromise", "oracle_or_dependency", "economic_design", "off_chain",
           "supply_chain_or_ci", "unknown")
LIMIT = 4 * 1024 * 1024


def say(text, status):
    print(text)
    sys.exit(status)


path, wanted = sys.argv[1], sys.argv[2]
try:
    st = os.lstat(path)
except FileNotFoundError:
    say("is missing", 3)
except OSError:
    say("cannot be read", 3)
if not stat.S_ISREG(st.st_mode):
    say("is not a regular file", 3)
if st.st_size > LIMIT:
    say("is larger than 4 MiB", 3)
try:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NOCTTY", 0))
    with os.fdopen(fd, "rb") as f:
        data = json.loads(f.read(LIMIT + 1).decode("utf-8"))
except (OSError, UnicodeDecodeError, ValueError, RecursionError):
    say("cannot be read as JSON", 3)
incidents = data.get("incidents") if isinstance(data, dict) else None
if not isinstance(incidents, list):
    say("holds no incidents list", 3)
incidents = [i for i in incidents if isinstance(i, dict)]
if wanted:
    incidents = [i for i in incidents if i.get("id") == wanted]
    if not incidents:
        say("records no incident %s" % wanted, 3)
    if len(incidents) > 1:
        say("records %s more than once" % wanted, 3)
if not incidents:
    say("records no incident", 3)
for i in incidents:
    if i.get("root_cause_class") not in CLASSES:
        say("gives %s no root_cause_class from incidents-schema.md" % (wanted or "an incident"), 3)
if wanted:
    say(incidents[0]["root_cause_class"], 0)
say("supply_chain_or_ci" if any(i["root_cause_class"] == "supply_chain_or_ci" for i in incidents) else "other", 0)
'
case "$R" in
  incident_*)
    inc=""
    case "$PATCH_REL" in */INC-*.patch) inc=${PATCH_REL##*/}; inc=${inc%.patch} ;; esac
    json=$R/INCIDENTS.json
    command -v python3 >/dev/null 2>&1 ||
      blocker "python3 is not on PATH, so target.sh cannot read the root_cause_class in $json (OUTPUT-RULES.md Rule 11a) — nothing was copied or built."
    rc=0
    cls=$( (cd / && exec python3 -I -c "$INCIDENT_PY" "$WT/$json" "$inc") ) || rc=$?
    if [ "$rc" != 0 ]; then
      [ "$rc" = 3 ] && [ -n "$cls" ] || cls="cannot be read"
      blocker "$json $cls: an incident's code is built only once $json records its root_cause_class (OUTPUT-RULES.md Rule 11a, references/detection-response/incidents-schema.md) — nothing was copied or built."
    fi
    if [ -n "$inc" ]; then echo ">> incident $inc: root_cause_class $cls ($json)"; fi
    if [ "$cls" = supply_chain_or_ci ] && [ "$MODE" = native ]; then
      if [ -n "$inc" ]; then what="the root_cause_class of $inc is supply_chain_or_ci"; else what="$json records an incident whose root_cause_class is supply_chain_or_ci"; fi
      blocker "$what, and such an incident's code is never built natively (OUTPUT-RULES.md Rule 11a); run it in isolated mode — nothing was copied or built."
    fi ;;
esac
# python3 starts from /, so nothing in the working directory picks the interpreter.
cd / || blocker "cannot leave the working directory for /"
rc=0
iso_credentials || rc=$?
case "$MODE:$rc" in
  *:0) ;;
  isolated:1) blocker "isolated mode, but these are readable here: $ISO_KINDS; this is not the isolated runner (Rule 11a), and scripts/runner/probe.sh --only isolation lists them — nothing was copied or built." ;;
  isolated:*) blocker "isolated mode, but the credential self-check could not finish ($ISO_WHY), so target.sh cannot tell that this is the isolated runner (Rule 11a) — nothing was copied or built." ;;
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
if [ "$SRC_KIND" = repo ]; then
  # The May-2024 clone fixes (CVE-2024-32004, CVE-2024-32465), as git-ro.sh copy requires them.
  gv=$(env -i PATH="$PATH" git --version 2>/dev/null) || gv=""
  gv=${gv#git version }
  gv=${gv%% *}
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
  [ "$ok" = 1 ] || blocker "cloning --src needs git with the May-2024 clone fixes: 2.39.4, 2.40.2, 2.41.1, 2.42.2, 2.43.4, 2.44.1, 2.45.1, or 2.46 or later — nothing was copied or built."
  confine_partial_clone "$SRC_ABS" >/dev/null
  case $? in
    0) blocker "$SRC_SHOWN is a partial clone: a copy would lack the objects it never fetched, and nothing is fetched (Rule 11c) — nothing was copied or built." ;;
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
    find "$SO_FROM" -maxdepth 1 -name '*.so' \( -type f -o -type l \) -print > "$S/so-list" 2>/dev/null || : > "$S/so-list"
    while IFS= read -r f; do
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
    done < "$S/so-list"
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
mkdir "$S/npm" && : > "$S/npm/userconfig" && : > "$S/npm/globalconfig" ||
  finish 3 "cannot prepare npm's empty config files in $S"
NPM=(npm_config_userconfig="$S/npm/userconfig" npm_config_globalconfig="$S/npm/globalconfig"
  npm_config_cache="$S/npm/cache" npm_config_logs_dir="$S/npm/logs" npm_config_update_notifier=false
  npm_config_fund=false npm_config_audit=false npm_config_ignore_scripts=true npm_config_git="$GIT")
ISO_ENV+=(RUSTUP_AUTO_INSTALL=0 CARGO_TERM_COLOR=never)
case "$ACTION" in
  npm-ci) ;;
  *)
    if [ -z "${RUSTUP_TOOLCHAIN:-}" ] && command -v rustup >/dev/null 2>&1; then
      tc=$(cd "$S" && iso_run rustup default 2>/dev/null </dev/null) || tc=""
      case "$tc" in
        *"(default)"*) ISO_ENV+=("RUSTUP_TOOLCHAIN=${tc%% *}") ;;
        *) finish 3 "no Rust toolchain to pin: set RUSTUP_TOOLCHAIN or a rustup default" ;;
      esac
    fi ;;
esac
printf '>> target.sh %s, execution mode %s; HOME %s (throwaway, with a fresh Solana keypair); TMPDIR %s\n' \
  "$ACTION" "$MODE" "$ISO_HOME" "$ISO_TMP" >&9

# ---- the copy ------------------------------------------------------------------------------------------
if [ "$SRC_KIND" = repo ]; then
  printf '>> git clone --no-local --no-checkout --no-recurse-submodules --template= %s\n' "$SRC_SHOWN" >&9
  CONFINE_CEILING=${S%/*} hgit "$S" -c protocol.file.allow=always \
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
    finish 3 "$SHA has submodules ($(confine_text "$names")), and target.sh never fetches them"
  fi
  if [ -n "$PATCH_REL" ]; then
    iso_copy_new "$WT/$PATCH_REL" "$S/patch" || finish 3 "$PATCH_REL cannot be read"
    printf '>> git apply --index %s\n' "$PATCH_REL" >&9
    hgit "$S/src" apply --index --whitespace=nowarn -- "$S/patch" </dev/null >&9 2>&9 ||
      finish 3 "$PATCH_REL does not apply to $SHA"
  fi
  printf '>> the copy: %s at %s\n' "$SRC_SHOWN" "$SHA" >&9
else
  printf '>> the copy: the files of %s, links as links, without run directories, the store, target/ and node_modules/\n' "$SRC_SHOWN" >&9
  (cd "$SRC_ABS" && find . \( -path './audit_*' -o -path './incident_*' -o -path './.audit-memory' -o \
    \( -type d \( -iname target -o -name node_modules \) \) \) -prune -o \( -type d -o -type f -o -type l \) -print0) \
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
case "$ACTION" in
  anchor-*|build-sbf)
    sbf_help=$(cd "$S" && iso_run cargo build-sbf --help 2>/dev/null </dev/null) || sbf_help=""
    [[ "$sbf_help" == *--install-only* && "$sbf_help" == *--skip-tools-install* && "$sbf_help" == *--offline* ]] ||
      finish 3 "this cargo build-sbf has no --install-only, --skip-tools-install or --offline, which target.sh needs to keep the real HOME and the proxy variables away from the build"
    [ -n "$ISO_REAL_HOME" ] || finish 3 "HOME is not set, and cargo build-sbf keeps its platform tools there"
    step "$S" ${NET[@]+"${NET[@]}"} "HOME=$ISO_REAL_HOME" cargo build-sbf --install-only ${TV[@]+"${TV[@]}"}
    fetched "cargo build-sbf --install-only, the install of the platform tools,"
    { confine_mkdir "$ISO_HOME/.cache" && ln -s "$ISO_REAL_HOME/.cache/solana" "$ISO_HOME/.cache/solana"; } ||
      finish 3 "cannot link the platform tools into the throwaway HOME $ISO_HOME" ;;
esac
if [ "$ACTION" = anchor-test ]; then
  if real_file "$AD/package-lock.json" || real_file "$AD/npm-shrinkwrap.json"; then
    command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1 || finish 3 "$at holds a package lock, and npm or node is not on PATH"
    step "$AD" ${NET[@]+"${NET[@]}"} ${NPM[@]+"${NPM[@]}"} npm ci --ignore-scripts --no-audit --no-fund
    fetched "npm ci --ignore-scripts, the install of the JavaScript dependencies,"
  elif real_file "$AD/yarn.lock" || real_file "$AD/pnpm-lock.yaml" || real_file "$AD/bun.lock"; then
    echo ">> note: $at holds a yarn, pnpm or bun lockfile; target.sh installs JavaScript dependencies only from package-lock.json, so a test script that needs node_modules fails"
    printf '>> note: no JavaScript dependencies installed: target.sh installs them only from package-lock.json\n' >&9
  fi
fi

# ---- the action ----------------------------------------------------------------------------------------
PKG=()
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
    step "$AD" "${OFF[@]}" cargo build-sbf --skip-tools-install --offline --sbf-out-dir "$S/out" ${TV[@]+"${TV[@]}"} ${MP[@]+"${MP[@]}"}
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
    [ -z "$PROGRAM" ] || PKG=(-p "$PROGRAM")
    SO_FROM=$AD/target/deploy
    step "$AD" "${OFF[@]}" anchor build --ignore-keys ${PKG[@]+"${PKG[@]}"} -- --skip-tools-install --offline ${TV[@]+"${TV[@]}"}
    outcome "anchor build"
    [ "$ACTION" = anchor-test ] || finish 0 "ok (exit 0)"
    step "$AD" "${OFF[@]}" anchor test --skip-build --skip-deploy --skip-local-validator --provider.cluster localnet \
      --provider.wallet "$ISO_HOME/.config/solana/id.json" ${PKG[@]+"${PKG[@]}"}
    outcome "anchor test"
    finish 0 "ok (exit 0)" ;;
  npm-ci)
    step "$AD" ${NET[@]+"${NET[@]}"} ${NPM[@]+"${NPM[@]}"} npm ci --ignore-scripts --no-audit --no-fund
    outcome "npm ci --ignore-scripts"
    finish 0 "ok (exit 0)" ;;
esac
