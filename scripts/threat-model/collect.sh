#!/bin/bash
# collect.sh — threat-model bootstrap collector (read-only on the target repository).
#
# Gathers history-derived leads for /auditor:threat-model: security-keyword commits, reverts, removed
# or quietly added account guards, churn, an optional fork-parent comparison, provenance signals,
# prior-vulnerability inputs and the audit-mem warm block. It never checks out, builds, runs, fetches
# into or modifies the target: lazy fetching and transport protocols are off, and a partial clone is
# refused. Output contract: references/audit-lifecycle/threat-model-bootstrap.md.
# Git hardening follows OUTPUT-RULES.md Rule 11c (the hardened call in scripts/lib/confine.sh); the
# output directory follows Rule 11d.
#
# Usage: run it directly by its quoted path in the installation, from the working directory, never as a
# scripts/ path relative to the working directory. The mode comes first:
#   "${CLAUDE_PLUGIN_ROOT}/scripts/threat-model/collect.sh" --detect --repo <dir> --out audit_<n>/bootstrap [--pin <rev>]
#   "${CLAUDE_PLUGIN_ROOT}/scripts/threat-model/collect.sh" --offline --repo <dir> --out audit_<n>/bootstrap [options]
#   "${CLAUDE_PLUGIN_ROOT}/scripts/threat-model/collect.sh" --network --repo <dir> --out audit_<n>/bootstrap [options]
# A mode after other options is refused (exit 2), as in the older form
#   bash "${CLAUDE_PLUGIN_ROOT}/scripts/threat-model/collect.sh" --repo <dir> --out audit_<n>/bootstrap --offline
#
# Modes:
#   --detect    only evaluate triggers T3 and T4, print them and exit (writes nothing)
#   --offline   collect without the network: --parent / --vulns URLs are recorded, not fetched
#   --network   collect, fetching the https URLs given in --parent and --vulns; the only mode that reads
#               a --repo, --parent or --vulns outside the working directory or through a symbolic link
# In --detect and --offline, --repo and a local --parent or --vulns are relative to the working
# directory, with no "." or ".." component, and reach nothing through a symbolic link; --repo, and a
# --parent, is the top level of a repository whose git directory lies inside the working directory,
# holds no symbolic link and borrows no objects (alternates) or parents (info/grafts). A local path that
# fails this is refused (exit 2), naming --network.
#
# Options (each at most once, except the repeatable --paths, --parent-paths and --vulns; a value is
# at most 1024 bytes, with no control character):
#   --repo <dir>              (required) the target: the top level of its repository, or a bare one
#   --out audit_<n>/bootstrap (required) the output directory, in the run directory audit_<n> (below)
#   --pin <rev>               commit to analyse (default HEAD); only its ancestry is mined
#   --paths <pathspec>        target pathspec, repeatable (default 'programs/*.rs' when the commit has
#                             a programs/ dir, else '*.rs'); pass the in-scope program dirs
#   --parent <https-url|dir>  fork parent: https URL (bare clone into a temp dir, --network only) or the
#                             top level of a local repository
#   --parent-paths <spec>     parent pathspec, repeatable (default: the same rule, applied to the parent)
#   --import <rev>            target commit that imported the parent code (default: the root commit);
#                             pass it when the code arrived after the root commit, or R5 finds no match
#   --vulns <file|https-url>  prior-vulnerability input, repeatable: PDF, Markdown, text, CSV, JSON,
#                             or INCIDENTS.json (schema auditor-incidents/1; allowlisted fields only); in
#                             --network, a local path that is a symbolic link, or passes through a
#                             directory link in the target tree, is skipped
#   --program-id <id>         save `audit-mem warm --program-id <id>` from the --audit-mem-db store
#                             (needs the built tool); at most 200 characters
#   --audit-mem-db <path>     the store --program-id reads: .audit-memory/audit.db or
#                             audit_<n>/audit-mem.db; nothing is read without it (the collector never
#                             looks for a store on its own)
#   --keywords <ere>          extra commit-message keywords, an ERE alternation such as 'drain|bypass';
#                             at most 200 characters
#   --cap <n>                 rows per section before TRUNCATED (default 60)
#   --small <n>               changed-line ceiling for a quiet-fix candidate commit (default 40)
#   --fix-ceiling <n>         changed-line ceiling for a keyword commit's ADDED rows (default 300)
#                             (--cap, --small and --fix-ceiling: 0 to 10000)
#   -h, --help                print this header (as the only argument)
#
# Run directory (OUTPUT-RULES.md Rule 11d): audit_<n> sits directly in the working directory, is a real
# directory holding no symbolic link, is tracked by no repository in any letter case, and has a
# .gitignore holding exactly "*" ("${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" new audit makes one).
# bootstrap/ is made in it when missing. The output is built in a temporary directory and copied in at
# the end, after the run directory is checked again: every file is created anew with noclobber and
# written through the descriptor opened at creation, and a re-run replaces the outputs of the run before.
# In --network, each URL is recorded in audit_<n>/disclosures.tsv before it is fetched (OUTPUT-RULES.md
# Rule 11b; the format is in scripts/lib/confine.sh).
#
# Exit status: 0 done (sections may print NOT FOUND), 2 usage error or rejected input (one line,
#              "collect.sh: refused: <reason>": a mode that is not first, an unknown or repeated option,
#              a value out of bounds, a path the mode does not take, an --import that is not a commit, a
#              run directory that fails the checks above or that git or find cannot check, a disclosure
#              that cannot be recorded, or an output that cannot be written),
#              3 --repo is not the top level of a git repository that git can read (or a bare
#              repository), the pin does not resolve, or the target is a partial clone (reading it could
#              fetch from its promisor remote) or git cannot read its config.

set -uo pipefail
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES CDPATH
# No git call may fetch a missing object from a promisor remote (partial clones are refused below too).
export GIT_NO_LAZY_FETCH=1 LC_ALL=C

case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'collect.sh: refused: the installation cannot be resolved\n' >&2; exit 2; }
SCRIPTS=${here%/*}
SKILL_ROOT=${SCRIPTS%/*}
. "$SCRIPTS/lib/confine.sh" || { printf 'collect.sh: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 2; }
confine_init collect.sh "$SKILL_ROOT" 2
confine_need env git find wc cat sed awk sort uniq cut tr head tail grep mktemp rm mkdir date
WT=$CONFINE_WT
COLLECTOR_VERSION=1
exec </dev/null

die() { confine_refuse "$*"; }

# ---- arguments ------------------------------------------------------------------------------------
if [ $# -eq 1 ]; then case "$1" in -h|--help) sed -n '2,/^$/p' "$0"; exit 0 ;; esac; fi
MODE=${1-}
case "$MODE" in
  --detect|--offline|--network) shift ;;
  *) die "the mode comes first: --detect, --offline or --network, then --repo <dir> --out audit_<n>/bootstrap [options] (see --help)" ;;
esac
OFFLINE=1
[ "$MODE" = --network ] && OFFLINE=0
# In --detect and --offline a refused local path names the mode that may read it.
NET_HINT="only --network reads outside the working directory or through a symbolic link"

REPO="" OUT="" PIN="" PARENT="" IMPORT="" PROGRAM_ID="" AUDIT_MEM_DB="" EXTRA_KW="" CAP="" SMALL="" FIX_CEILING=""
TPATHS_NL="" PPATHS_NL="" VULNS_NL="" SEEN=" "
nl=$'\n'

value() { # value <option> <args...>: sets V to the option's value; an absent or empty one, a control character or more than 1024 bytes is refused
  [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"
  case "$2" in *[[:cntrl:]]*) die "$1 takes no control character: $(confine_text "$2")" ;; esac
  [ "${#2}" -le 1024 ] || die "$1 is longer than 1024 bytes"
  V=$2
}
once() { # once <option>: refuse an option given before
  case "$SEEN" in *" $1 "*) die "$1 is given twice" ;; esac
  SEEN="$SEEN$1 "
}
while [ $# -gt 0 ]; do
  case "$1" in
    --repo)          once "$1"; value "$@"; REPO=$V; shift 2 ;;
    --out)           once "$1"; value "$@"; OUT=$V; shift 2 ;;
    --pin)           once "$1"; value "$@"; PIN=$V; shift 2 ;;
    --paths)         value "$@"; TPATHS_NL="$TPATHS_NL$V$nl"; shift 2 ;;
    --parent)        once "$1"; value "$@"; PARENT=$V; shift 2 ;;
    --parent-paths)  value "$@"; PPATHS_NL="$PPATHS_NL$V$nl"; shift 2 ;;
    --import)        once "$1"; value "$@"; IMPORT=$V; shift 2 ;;
    --vulns)         value "$@"; VULNS_NL="$VULNS_NL$V$nl"; shift 2 ;;
    --program-id)    once "$1"; value "$@"; PROGRAM_ID=$V; shift 2 ;;
    --audit-mem-db)  once "$1"; value "$@"; AUDIT_MEM_DB=$V; shift 2 ;;
    --keywords)      once "$1"; value "$@"; EXTRA_KW=$V; shift 2 ;;
    --cap)           once "$1"; value "$@"; CAP=$V; shift 2 ;;
    --small)         once "$1"; value "$@"; SMALL=$V; shift 2 ;;
    --fix-ceiling)   once "$1"; value "$@"; FIX_CEILING=$V; shift 2 ;;
    --detect|--offline|--network) die "the mode is given once, as the first argument: $1" ;;
    *)               die "unknown argument: $(confine_text "$1") (see --help)" ;;
  esac
done
[ -n "$REPO" ] || die "--repo is required"
[ -n "$OUT" ]  || die "--out is required"
bound() { # bound <option> <value> <default>: sets B to the value, or the default when none was given: 0 to 10000
  local v=${2:-$3}
  case "$v" in ''|*[!0-9]*) die "$1 must be a number from 0 to 10000" ;; esac
  [ "${#v}" -le 5 ] && [ "$((10#$v))" -le 10000 ] || die "$1 must be a number from 0 to 10000"
  B=$((10#$v))
}
bound --cap "$CAP" 60; CAP=$B
bound --small "$SMALL" 40; SMALL=$B
bound --fix-ceiling "$FIX_CEILING" 300; FIX_CEILING=$B
[ "${#EXTRA_KW}" -le 200 ] || die "--keywords is longer than 200 characters"
[ "${#PROGRAM_ID}" -le 200 ] || die "--program-id is longer than 200 characters"
PIN=${PIN:-HEAD}
# A revision reaches git only after the subcommand and its options, as "<rev>^{commit}"; one that looks
# like an option is refused here.
case "$PIN" in -*) die "--pin takes a revision, not an option: $(confine_text "$PIN")" ;; esac
case "$IMPORT" in -*) die "--import takes a revision, not an option: $(confine_text "$IMPORT")" ;; esac

# --out is audit_<n>/bootstrap, relative (a leading ./ and trailing slashes are dropped).
OUT_REL=${OUT#./}
while [ "${OUT_REL%/}" != "$OUT_REL" ]; do OUT_REL=${OUT_REL%/}; done
RUN=""
case "$OUT_REL" in */bootstrap) RUN=${OUT_REL%/bootstrap} ;; esac
if [ -z "$RUN" ] || ! confine_rundir_name "$RUN"; then
  die "--out must be audit_<n>/bootstrap, in a run directory audit_<n> directly in the working directory: $(confine_text "$OUT")"
fi
case "$RUN" in audit_*) ;; *) die "--out must be audit_<n>/bootstrap, in a run directory audit_<n> directly in the working directory: $(confine_text "$OUT")" ;; esac
# --detect writes nothing, so its --out only names the current run; the others check the run directory.
confine_path "$OUT_REL" --out any
case "$CONFINE_TYPE" in file) die "--out is not a directory: $(confine_text "$OUT")" ;; esac
if [ "$MODE" != --detect ]; then
  confine_rundir "$RUN" "the run directory"
fi

# Only https URLs are ever fetched, and only when the user passed them explicitly. Any other scheme,
# and scp-style "host:path" (a colon before the first slash), is rejected. Anything else is a local
# file or repository path. Pure parameter expansion: no pipeline whose early exit could flip the answer.
classify_source() {
  case "$1" in
    https://*) echo url ;;
    *://*)     echo rejected ;;
    *)         case "${1%%/*}" in *:*) echo rejected ;; *) echo path ;; esac ;;
  esac
}
# URLs are written to history.md, inputs.tsv and stderr without the parts that carry credentials or
# signed tokens: the userinfo, the query string and the fragment of a URL become ***. redact_urls
# filters text (any URL at the start of a line or after a space); redact does one value.
redact_urls() {
  sed -E -e 's%(^|[[:space:]])([A-Za-z][A-Za-z0-9+.-]*://)[^/@?#[:space:]]*@%\1\2***@%g' \
         -e 's%(^|[[:space:]])([A-Za-z][A-Za-z0-9+.-]*://[^?#[:space:]]*)[?][^#[:space:]]*%\1\2?***%g' \
         -e 's%(^|[[:space:]])([A-Za-z][A-Za-z0-9+.-]*://[^#[:space:]]*)[#][^[:space:]]*%\1\2#***%g'
}
redact() { printf '%s\n' "$1" | redact_urls | awk 'NR > 1 { printf "\n" } { printf "%s", $0 }'; }
if [ -n "$PARENT" ] && [ "$(classify_source "$PARENT")" = rejected ]; then
  die "--parent accepts an https:// URL or a local path, not: $(redact "$PARENT")"
fi
while IFS= read -r v; do
  [ -z "$v" ] && continue
  [ "$(classify_source "$v")" = rejected ] && die "--vulns accepts a file or an https:// URL, not: $(redact "$v")"
done <<< "$VULNS_NL"

# --audit-mem-db names the in-tree store or a store for one run, and is read from the working directory.
DB_REL=""
if [ -n "$AUDIT_MEM_DB" ]; then
  DB_REL=${AUDIT_MEM_DB#./}
  case "$DB_REL" in
    .audit-memory/audit.db) ;;
    audit_*/audit-mem.db) confine_rundir_name "${DB_REL%/audit-mem.db}" || DB_REL="" ;;
    *) DB_REL="" ;;
  esac
  [ -n "$DB_REL" ] || die "--audit-mem-db must be .audit-memory/audit.db or audit_<n>/audit-mem.db: $(confine_text "$AUDIT_MEM_DB")"
  confine_path "$DB_REL" --audit-mem-db any
fi

# ---- the target, and the local parent and inputs -------------------------------------------------
# hgit_text is the hardened git call (scripts/lib/confine.sh): the target's .git/config, attributes and
# hooks are attacker-controlled, so it runs git with no environment of the caller's and with the
# system and global config dropped, never pages, never runs fsmonitor, hooks, signature helpers or
# external diffs, allows no transport protocol, and pins the output-shaping settings (grep line
# numbers and columns, pattern type, colour, path quoting, log encoding, the big-file threshold, hunk
# fusing, root-commit diffs, replace refs) so the parsers below see plain text. Every log/show gets
# --no-textconv --no-ext-diff with fixed diff prefixes. Nothing is ever checked out, so no smudge or
# clean filter can run, and no remote the target configures is ever contacted (the one https clone of
# a user-given --parent URL below allows https for that call only). Every diff runs with --text and
# every git grep with -a, so neither an attribute (-diff, diff=<driver> with binary set) nor a size
# threshold turns a change into "Binary files differ" or hides a file from a search.
G() { hgit_text "$@"; }
DIFFSAFE=(--text --no-textconv --no-ext-diff --no-color --src-prefix=a/ --dst-prefix=b/)
abspath() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$WT" "$1" ;; esac; }
not_a_repo() {
  echo "collect.sh: not the top level of a git repository that git can read (none there, or another user owns it: collect from a copy you made), nor a bare repository: $(confine_text "$REPO")" >&2
  exit 3
}
# REPO_ABS is the target's physical path; REPO_REL its path inside the working directory ("" outside it).
if [ "$OFFLINE" -eq 1 ]; then
  CONFINE_HINT=$NET_HINT
  confine_path "$REPO" --repo dir
  CONFINE_HINT=""
  REPO_REL=$CONFINE_REL
  if [ "$REPO_REL" = . ]; then REPO_ABS=$WT; else REPO_ABS=$WT/$REPO_REL; fi
  confine_phys "$REPO_ABS" || not_a_repo
  REPO_ABS=$CONFINE_PHYS
else
  confine_phys "$(abspath "$REPO")" || not_a_repo
  REPO_ABS=$CONFINE_PHYS
  REPO_REL=""
  case "$REPO_ABS" in
    "$WT") REPO_REL=. ;;
    "$WT"/*) REPO_REL=${REPO_ABS#"$WT"/} ;;
  esac
fi
confine_repo_top "$REPO_ABS" || not_a_repo
confine_partial_clone "$REPO_ABS" >/dev/null
case $? in
  0) echo "collect.sh: the target is a partial clone: reading missing objects would fetch from its promisor remote. Make a full copy you control first (OUTPUT-RULES Rule 11c)." >&2
     exit 3 ;;
  2) echo "collect.sh: git cannot read the target's config, so a partial clone cannot be ruled out: $(confine_text "$REPO")" >&2
     exit 3 ;;
esac
if [ "$OFFLINE" -eq 1 ]; then
  CONFINE_HINT=$NET_HINT
  confine_repo "$REPO_REL" --repo
  CONFINE_HINT=""
fi
REPO=$REPO_ABS
REPO_PHYS=$REPO_ABS
PIN_SHA=$(G "$REPO" rev-parse --verify --quiet "$PIN^{commit}") || { echo "collect.sh: pin does not resolve: $(confine_text "$PIN")" >&2; exit 3; }
# --import reaches git only as the full commit id it resolves to, never as the string given.
if [ -n "$IMPORT" ]; then
  IMPORT_SHA=$(G "$REPO" rev-parse --verify --quiet "$IMPORT^{commit}") || die "--import does not resolve to a commit: $(confine_text "$IMPORT")"
  IMPORT=$IMPORT_SHA
fi

# A local --parent: in --detect and --offline a confined path, whose git directory, at a top level,
# passes the same checks as the target's; in --network any directory. One that is not a top level, is a
# partial clone, or whose config git cannot read is recorded as not used, and the run goes on.
PDIR="" PARENT_STATUS="none" PARENT_REL="" pphys=""
if [ -n "$PARENT" ] && [ "$(classify_source "$PARENT")" = path ]; then
  if [ "$OFFLINE" -eq 1 ]; then
    CONFINE_HINT=$NET_HINT
    confine_path "$PARENT" --parent any
    CONFINE_HINT=""
    PARENT_REL=$CONFINE_REL
    PARENT=$(abspath "$PARENT_REL")
  else
    PARENT=$(abspath "$PARENT")
  fi
  if confine_phys "$PARENT"; then pphys=$CONFINE_PHYS; fi
  if [ -z "$pphys" ] || ! confine_repo_top "$pphys"; then
    PARENT_STATUS="not a git repository (or not its top level)"
  else
    PARENT=$pphys
    confine_partial_clone "$PARENT" >/dev/null
    case $? in
      0) PARENT_STATUS="the parent is a partial clone, not used (reading it could fetch from its promisor remote)" ;;
      2) PARENT_STATUS="git cannot read the parent's config, not used" ;;
      *) if [ "$OFFLINE" -eq 1 ]; then
           CONFINE_HINT=$NET_HINT
           confine_repo "$PARENT_REL" --parent
           CONFINE_HINT=""
         fi
         PDIR=$PARENT; PARENT_STATUS="local repository" ;;
    esac
  fi
  if [ "$OFFLINE" -eq 0 ]; then
    case "$PARENT" in
      "$WT") PARENT_REL=. ;;
      "$WT"/*) PARENT_REL=${PARENT#"$WT"/} ;;
    esac
  fi
fi
# Local --vulns paths: in --detect and --offline, confined (a regular file, a directory or nothing:
# R7 records what is not a readable file); in --network, absolute paths, checked for links in R7.
abs_vulns=""
while IFS= read -r v; do
  [ -z "$v" ] && continue
  if [ "$(classify_source "$v")" = path ]; then
    if [ "$OFFLINE" -eq 1 ]; then
      CONFINE_HINT=$NET_HINT
      confine_path "$v" --vulns any
      CONFINE_HINT=""
      v=$WT/$CONFINE_REL
    else
      v=$(abspath "$v")
    fi
  fi
  abs_vulns="$abs_vulns$v$nl"
done <<< "$VULNS_NL"
VULNS_NL=$abs_vulns
# Every URL --network fetches is first recorded in audit_<n>/disclosures.tsv.
if [ "$MODE" = --network ] && ! confine_disclosures_ok "$RUN"; then
  die "$RUN/disclosures.tsv is not a regular file of its own with the disclosure header, so no fetch could be recorded"
fi
# disclose <url> <how>: the row for one URL, before it is fetched.
disclose() {
  confine_service "$1"
  confine_disclose "$RUN" scripts/threat-model/collect.sh "$CONFINE_SERVICE" "https URL ($2)" "$(redact "$1")" ||
    die "cannot record the fetch of a URL in $RUN/disclosures.tsv, so it was not fetched"
}

# The current run directory, physical, when it exists: --detect does not count it as a prior audit, and
# R6 does not list it.
CUR_RUN=""
if [ -d "$WT/$RUN" ]; then CUR_RUN=$WT/$RUN; fi

SHALLOW=$(G "$REPO" rev-parse --is-shallow-repository 2>/dev/null)
EMPTY_TREE=$(G "$REPO" hash-object -t tree /dev/null)
# Where this git has --attr-source, R4 reads gitattributes from the empty tree instead of the target's
# .gitattributes; an older git has no such option and keeps reading them.
ATTR_SRC=""
G "$REPO" --attr-source="$EMPTY_TREE" check-attr diff -- probe.rs >/dev/null 2>&1 && ATTR_SRC=$EMPTY_TREE

# Default pathspec: an Anchor-style programs/ tree when the commit has one, else every Rust file.
default_paths() { # default_paths <repo> <commit>
  if G "$1" cat-file -e "$2:programs" 2>/dev/null; then echo 'programs/*.rs'; else echo '*.rs'; fi
}
[ -n "$TPATHS_NL" ] || TPATHS_NL="$(default_paths "$REPO" "$PIN_SHA")$nl"
TPATHS=()
while IFS= read -r p; do [ -n "$p" ] && TPATHS+=("$p"); done <<< "$TPATHS_NL"

# The collector works from a private temporary directory outside the working directory, so no tool picks
# up a module or config file from the tree; the output is staged there and copied into --out at the end.
confine_scratch tm-collect
case $? in
  0) TMPD=$CONFINE_SCRATCH ;;
  2) die "TMPDIR lies inside the working directory; set it to a directory outside the tree" ;;
  *) die "cannot create a temp dir" ;;
esac
trap 'rm -rf "$TMPD"' EXIT
STAGE="$TMPD/stage"
mkdir "$STAGE" "$STAGE/inputs" "$STAGE/diffs" || die "cannot create a temp dir"
cd "$TMPD" || die "cannot enter the temp dir"

# ---- vocabulary -----------------------------------------------------------------------------------
# Base set (cve-, security, vuln, fix, exploit) plus Solana-stack terms, matched on the WHOLE message.
KW='cve-|security|vuln|fix|exploit|audit|signer|owner|authority|overflow|underflow|reinit|rounding|slippage|oracle'
[ -n "$EXTRA_KW" ] && KW="$KW|$EXTRA_KW"
# -G picks candidate commits (POSIX ERE inside git); the awk filters decide which lines are guards.
GUARD_G='require(_keys)?(_eq|_neq|_gt|_gte)?!|has_one|constraint[[:space:]]*=|is_signer|is_writable|Signer<|token::(authority|mint)|associated_token::(authority|mint)|mint::authority|owner\(?\)?[[:space:]]*[!=]=|key\(\)[[:space:]]*[!=]=|(address|seeds|bump|close|owner)[[:space:]]*='
# Awk receives these through ENVIRON, where "\t" is not an escape, so they carry a real tab.
TAB=$'\t'
export TM_ALWAYS_RE="require(_keys)?(_eq|_neq|_gt|_gte)?!|has_one|constraint[ $TAB]*=|is_signer|is_writable|Signer<|token::(authority|mint)|associated_token::(authority|mint)|mint::authority|owner\\(?\\)?[ $TAB]*[!=]=|key\\(\\)[ $TAB]*[!=]="
# address/seeds/bump/close/owner count only in attribute position: at line start or after "(" or ",",
# never on a `let` line or a line ending in ";" (variable names, not constraints).
export TM_ATTR_RE="(^|[(,])[ $TAB]*(address|seeds|bump|close|owner)[ $TAB]*=[^=]"
# git's built-in rust hunk-header pattern, passed to git for R4 so the target's config cannot redefine it.
RUST_FUNC="^[$TAB ]*((pub(\\([^\\)]+\\))?[$TAB ]+)?((async|const|unsafe|extern([$TAB ]+\"[^\"]+\"))[$TAB ]+)?(struct|enum|union|mod|trait|fn|impl|macro_rules!)[< $TAB]+[^;]*)\$"

# Target text reaches inputs.tsv and history.md as one value per cell and one row per line: TAB, LF and
# CR are shown as \t, \n and \r, every other control character (C0 and DEL) as ?, and a value longer
# than 500 characters is cut, ending in "...".
CLEAN_AWK='
  BEGIN { for (i = 1; i < 32; i++) esc[sprintf("%c", i)] = "?"
          esc["\t"] = "\\t"; esc["\n"] = "\\n"; esc["\r"] = "\\r"; esc[sprintf("%c", 127)] = "?" }
  function clean(s,   out, i, n, c) {
    n = length(s); if (n > 600) n = 600
    out = ""
    for (i = 1; i <= n; i++) { c = substr(s, i, 1); out = out ((c in esc) ? esc[c] : c) }
    if (length(out) > 500 || length(s) > 600) out = substr(out, 1, 500) "..."
    return out }'
clean()       { CLEAN_IN=$1 awk "$CLEAN_AWK"' BEGIN { printf "%s", clean(ENVIRON["CLEAN_IN"]) }'; }
clean_lines() { awk "$CLEAN_AWK"' { print clean($0) }'; }

# An empty section prints NOT FOUND and a capped one TRUNCATED, so "no rows" never reads as "clean".
emit_capped() { # emit_capped <file> <what was searched>
  local f=$1 what=$2 n
  n=$(wc -l < "$f" | tr -d ' ')
  if [ "$n" -eq 0 ]; then echo "NOT FOUND ($what)"; return 0; fi
  head -n "$CAP" "$f" | clean_lines
  if [ "$n" -gt "$CAP" ]; then echo "TRUNCATED (+$((n - CAP)) more rows; raise --cap)"; fi
  return 0
}
section() { printf '\n## %s\n\n%s\n\n```text\n' "$1" "$2"; }
endsec()  { printf '```\n'; }
strip_pin() { sed "s#^$PIN_SHA:##"; }

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else echo unavailable; fi
}

# guard_rows <repo> <rev-range> <pathspec...>
# One row per net guard-text change per commit:
#   "<short> <date> <TAG> x<count> <file[,file...]>: <text>    # <subject>"
# REMOVED always prints. ADDED prints for commits whose whole message matches a keyword and that change
# <= FIX_CEILING lines in the pathspec; ADDED-QUIET for keyword-free commits of <= SMALL lines. Within a
# commit, identical guard text (after trimming) is netted across all its files, and renames are detected
# (-M), so a guard moved unchanged (a git mv, a file split, a directory rename) prints nothing. An edited
# guard prints its old text as REMOVED, with the files it left, and its new text, with the files it
# entered, when the commit qualifies. Identical text removed in one file and added in another also nets
# out, even where the two guard different things.
# A commit's changed-line count comes from its own patch, which --pickaxe-all prints for every file in
# the pathspec (a --numstat count would be zero for a file git treats as binary).
# Each row starts with the commit's full id (for git; rows show the short one); with GR_SIZE=1 the
# commit's changed-line count follows it (a sort key for R5d). With GR_FILES=<file>, "<full id><TAB><path>"
# is appended there for every file a printed row names, so a saved diff can be limited to those files.
guard_rows() {
  local repo=$1 range=$2 kwfile; shift 2
  kwfile="$TMPD/kw.$RANDOM"
  G "$repo" log "${DIFFSAFE[@]}" -i -E --grep="$KW" --format=%H "$range" -- "$@" > "$kwfile" 2>/dev/null
  G "$repo" log "${DIFFSAFE[@]}" --min-parents=1 -p -U0 -M --pickaxe-all -G"$GUARD_G" \
      --format='__C__ %H %h %ad %s' --date=short "$range" -- "$@" 2>/dev/null |
  awk -v small="$SMALL" -v ceil="$FIX_CEILING" -v kwfile="$kwfile" -v filesout="${GR_FILES:-/dev/null}" '
    BEGIN { always = ENVIRON["TM_ALWAYS_RE"]; attr = ENVIRON["TM_ATTR_RE"]
            while ((getline l < kwfile) > 0) kw[l] = 1 }
    function isguard(s) {
      if (s ~ always) return 1
      if (s ~ attr && s !~ /(^|[^A-Za-z0-9_])let[ \t]/ && s !~ /;[ \t]*$/) return 1
      return 0 }
    function note(side, t, f,   had) {   # the files a guard text left ("-") or entered ("+") in this commit
      if (f == "" || ((side, t, f) in seen)) return
      seen[side, t, f] = 1
      had = ((side, t) in files)
      files[side, t] = had ? files[side, t] "," f : f
      path[side, t, ++npath[side, t]] = f }
    function paths(side, t,   k) { for (k = 1; k <= npath[side, t]; k++) print full "\t" path[side, t, k] > filesout }
    function flush(   t, n) {
      if (full == "") return
      for (t in net) {
        n = net[t]
        if (n < 0) {
          printf "%06d %s %d %s %s REMOVED x%d %s: %s    # %s\n", ci, full, size, short, date, -n, files["-", t], t, subj
          paths("-", t)
        } else if (n > 0 && (full in kw) && size <= ceil + 0) {
          printf "%06d %s %d %s %s ADDED x%d %s: %s    # %s\n", ci, full, size, short, date, n, files["+", t], t, subj
          paths("+", t)
        } else if (n > 0 && !(full in kw) && size <= small + 0) {
          printf "%06d %s %d %s %s ADDED-QUIET x%d %s: %s    # %s\n", ci, full, size, short, date, n, files["+", t], t, subj
          paths("+", t)
        }
      }
      delete net; delete files; delete seen; delete path; delete npath }
    /^__C__ / { flush(); ci++; full = $2; short = $3; date = $4; size = 0
                subj = $0; sub(/^__C__ [^ ]+ [^ ]+ [^ ]+ ?/, "", subj); inhdr = 0; next }
    /^diff --git / { inhdr = 1; oldp = ""; newp = ""; next }
    inhdr && /^--- a\// { oldp = substr($0, 7); next }
    inhdr && /^\+\+\+ b\// { newp = substr($0, 7); next }
    /^@@/ { inhdr = 0; next }
    inhdr { next }
    /^[-+]/ { size++; s = substr($0, 2)
              if (!isguard(s)) next
              t = s; gsub(/^[ \t]+|[ \t]+$/, "", t)
              if (substr($0, 1, 1) == "+") { net[t]++; note("+", t, newp) } else { net[t]--; note("-", t, oldp) } }
    END { flush() }' | sort -k1,1n -k6 | cut -d' ' -f"$([ "${GR_SIZE:-0}" = 1 ] && echo 2- || echo 2,4-)"
}

# shell_word <text>: the text as one shell word that runs nothing when pasted: escaped and cut like any
# other target text, then single-quoted.
shell_word() { printf "'%s'" "$(clean "$1" | sed "s/'/'\\\\''/g")"; }
# The command a TRUNCATED line names for the rest of a saved diff: scripts/git-ro.sh, the read-only git of
# Rule 11c, by its quoted path in this installation. git_ro_for <repository path inside the working
# directory, or "">: sets SHOW_REST to its show call for that repository; one outside the working
# directory (read in --network) or cloned from a URL is read from a copy made inside it.
GIT_RO="\"$SKILL_ROOT/scripts/git-ro.sh\""
git_ro_for() {
  case "$1" in
    .)  SHOW_REST="the rest: $GIT_RO show" ;;
    '') SHOW_REST="the rest, from a copy of the repository inside the working directory, named with --repo: $GIT_RO show" ;;
    *)  SHOW_REST="the rest: $GIT_RO --repo $(shell_word "$1") show" ;;
  esac
}

# save_diff <repo> <its path inside the working directory, or ""> <full id> <out file> <path list> <fallback pathspec...>
# Writes the commit's id, date, subject and at most 20 body lines, then its diff limited to the paths in
# <path list> (one per line; the fallback pathspec when it is empty), at most 400 lines. Each cut ends in a
# TRUNCATED line that names the git-ro.sh show call for the rest, with every path as a quoted shell word.
save_diff() {
  local repo=$1 c=$3 out=$4 plist=$5 p n shown="" specs nspec=0
  git_ro_for "$2"
  shift 5
  specs=()
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    specs+=(":(literal)$p"); shown="$shown $(shell_word "$p")"; nspec=$((nspec + 1))
  done < "$plist"
  if [ "$nspec" -eq 0 ]; then
    specs=("$@")
    for p in "$@"; do shown="$shown $(shell_word "$p")"; done
  fi
  {
    G "$repo" log -1 --format='commit %H%n%ad%n%n%s' --date=short "$c" 2>/dev/null
    G "$repo" log -1 --format=%b "$c" 2>/dev/null | sed -e '$!b' -e '/^$/d' > "$TMPD/save.body"
    n=$(wc -l < "$TMPD/save.body" | tr -d ' ')
    if [ "$n" -gt 0 ]; then echo; head -n 20 "$TMPD/save.body"; fi
    if [ "$n" -gt 20 ]; then
      echo "TRUNCATED ($((n - 20)) more message lines; ${SHOW_REST/#the rest/the whole message} --no-patch $c)"
    fi
    echo
    G "$repo" show "${DIFFSAFE[@]}" --format= "$c" -- "${specs[@]}" 2>/dev/null | sed '/./,$!d' > "$TMPD/save.diff"
    n=$(wc -l < "$TMPD/save.diff" | tr -d ' ')
    head -n 400 "$TMPD/save.diff"
    if [ "$n" -gt 400 ]; then
      echo "TRUNCATED ($((n - 400)) more lines; $SHOW_REST $c --$shown)"
    fi
  } > "$out"
}

# remote_urls: one "remote.<name>.url <value>" line per configured remote URL. Config is read NUL-separated,
# so a newline inside a value stays on its line, shown as \n.
remote_urls() {
  G "$REPO" config -z --get-regexp '^remote\..*\.url$' 2>/dev/null | tr '\n\000' '\001\n' |
    awk '{ i = index($0, "\001"); if (i) $0 = substr($0, 1, i - 1) " " substr($0, i + 1)
           out = ""; while ((i = index($0, "\001")) > 0) { out = out substr($0, 1, i - 1) "\\n"; $0 = substr($0, i + 1) }
           print out $0 }'
}

# ---- triggers T3 (provenance) and T4 (prior reports, incidents) ---------------------------------------
# T2 (intake §7 records a prior audit or an incident) is read by the command, not here.
FORK_PHRASES='fork(ed)? (of|from)|white[- ]?label'
REPORT_RE='audit|post-?mortem|incident'   # in any path component of a .pdf / .md file
norm_url() { tr 'A-Z' 'a-z' | sed -E 's#^[a-z+]+://##; s#^git@##; s#:#/#; s#\.git$##; s#/$##'; }
# Under pipefail a pipeline that ends in an early-exit reader (grep -q, head) can report the writer's
# SIGPIPE instead of the match, so every check whose status matters here counts, or reads a string.
eval_triggers() {
  local t3="" t4="" src remotes s d n
  G "$REPO" grep -a -i -q -E "$FORK_PHRASES" "$PIN_SHA" -- 'README*' '*/README*' 'docs/*' 2>/dev/null && t3="readme-phrase"
  src=$(G "$REPO" grep -h -a -E 'source_code[[:space:]]*:' "$PIN_SHA" -- '*.rs' 2>/dev/null |
        sed -nE 's/.*source_code[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' | sed -n '1,3p')
  remotes=$(remote_urls | awk '{print $2}' | norm_url)
  # One string per line, read as written: target strings are never word-split or glob-expanded.
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    grep -qxF -- "$(printf '%s' "$s" | norm_url)" <<< "$remotes" || { t3="${t3:+$t3,}security_txt-source_code"; break; }
  done <<< "$src"
  # Nothing counts through a symbolic link: what one points at is never tested.
  for d in "$REPO_ABS"/audit_*; do
    [ ! -L "$d" ] && [ -d "$d" ] && [ ! -L "$d/REPORT.md" ] && [ -f "$d/REPORT.md" ] || continue
    [ "$d" != "$CUR_RUN" ] || continue
    t4="prior-audit-dir"; break
  done
  n=$(G "$REPO" ls-tree -r --name-only "$PIN_SHA" 2>/dev/null | grep -iE '\.(pdf|md)$' | grep -ciE "$REPORT_RE")
  if [ "${n:-0}" -gt 0 ]; then t4="${t4:+$t4,}in-tree-report"; fi
  for d in "$REPO_ABS"/incident_*; do
    [ ! -L "$d" ] && [ ! -L "$d/INCIDENTS.json" ] && [ -f "$d/INCIDENTS.json" ] || continue
    t4="${t4:+$t4,}incidents-json"; break
  done
  echo "T3 $([ -n "$t3" ] && echo yes || echo no) ${t3:-none}"
  echo "T4 $([ -n "$t4" ] && echo yes || echo no) ${t4:-none}"
}

if [ "$MODE" = --detect ]; then eval_triggers; exit 0; fi

# ---- staged output -----------------------------------------------------------------------------------
# Everything is written into $STAGE first and copied into --out at the end (publish, below).
H="$STAGE/history.md"
printf 'n\tsource\tformat\tsha256\tstored_as\tstatus\n' > "$STAGE/inputs.tsv"

# ---- R5 parent acquisition (before the header, which names it) ----------------------------------------
# A local parent was checked with the target, above; a URL is cloned only in --network, once it is recorded
# in disclosures.tsv.
PHEAD=""
if [ -n "$PARENT" ]; then
  if [ "$(classify_source "$PARENT")" = url ]; then
    if [ "$OFFLINE" -eq 1 ]; then
      PARENT_STATUS="given, not cloned (offline)"
    elif disclose "$PARENT" "git clone" && GIT_ASKPASS= SSH_ASKPASS= GIT_TERMINAL_PROMPT=0 git -c protocol.allow=never -c protocol.https.allow=always \
           -c protocol.file.allow=never -c credential.helper= -c http.extraHeader= -c core.askPass= -c core.fsmonitor=false \
           clone --quiet --bare --no-recurse-submodules -- "$PARENT" "$TMPD/parent.git" >/dev/null 2>&1; then
      PDIR="$TMPD/parent.git"; PARENT_STATUS="cloned (bare, temp dir, deleted on exit)"
    else
      PARENT_STATUS="clone failed"
    fi
  fi
  if [ -n "$PDIR" ]; then PHEAD=$(G "$PDIR" rev-parse --verify --quiet 'HEAD^{commit}'); fi
fi
# Parent pathspec: --parent-paths, else the parent's own default (a fork may rename its program dir).
if [ -z "$PPATHS_NL" ]; then
  if [ -n "$PHEAD" ]; then PPATHS_NL="$(default_paths "$PDIR" "$PHEAD")$nl"; else PPATHS_NL=$TPATHS_NL; fi
fi
PPATHS=()
while IFS= read -r p; do [ -n "$p" ] && PPATHS+=("$p"); done <<< "$PPATHS_NL"

{
  echo "# Threat-model bootstrap — collector output"
  echo
  echo "| | |"
  echo "|---|---|"
  echo "| Target | \`$(clean "$REPO_ABS")\` |"
  echo "| Pinned commit | \`$PIN_SHA\` |"
  echo "| Target paths | \`$(clean "${TPATHS[*]}")\` |"
  if [ -n "$PARENT" ]; then echo "| Parent | $(clean "$(redact "$PARENT")") — $PARENT_STATUS${PHEAD:+ @ \`$PHEAD\`} |"; else echo "| Parent | none |"; fi
  echo "| Parent paths | \`$(clean "${PPATHS[*]}")\` |"
  echo "| Network | $([ "$OFFLINE" -eq 1 ] && echo 'offline' || echo 'explicit https URLs only, each recorded in disclosures.tsv') |"
  echo "| Collector | scripts/threat-model/collect.sh v$COLLECTOR_VERSION, cap $CAP rows, quiet-fix ceiling $SMALL lines, fix ceiling $FIX_CEILING lines |"
  echo
  echo "Leads, not findings: every row points at history to re-derive from the code at the pinned commit."
  echo "Git ran with the system and global config dropped and without pager, fsmonitor, hooks, signature helpers, textconv or external diff (OUTPUT-RULES.md Rule 11c), with lazy fetching and every transport protocol off (a partial clone is refused), and with its grep, colour, path-quoting, log-encoding, big-file, hunk-fusing and root-commit settings pinned."
  if [ "$SHALLOW" = true ]; then
    echo "Shallow clone: history before the shallow boundary is missing, so a NOT FOUND or a short list below may only mean that history is cut."
  fi
  echo "Every diff and search runs as text, so no attribute (committed or in .git/info/attributes) or setting of the target makes git skip a file as binary; a matching line from a binary file is shown escaped and cut like all target text."
  if [ -n "$ATTR_SRC" ]; then
    echo "R4 function names use git's rust hunk-header pattern, pinned. The target's .gitattributes are ignored there (--attr-source); its .git/info/attributes still apply, and R4 counts the .rs files they send to another diff driver."
  else
    echo "R4 function names use git's rust hunk-header pattern, pinned. This git has no --attr-source, so the target's .gitattributes and .git/info/attributes still apply there; R4 counts the .rs files they send to another diff driver."
  fi
  echo "An empty section prints NOT FOUND; a capped one prints TRUNCATED (+n)."
} > "$H"

# ---- R0 preflight ---------------------------------------------------------------------------------
{
  section "R0 Preflight" "Shallow clones hide history. T3/T4 are the triggers this script can evaluate offline."
  echo "shallow: $SHALLOW"
  echo "commits in the pin ancestry touching the target paths: $(G "$REPO" rev-list --count "$PIN_SHA" -- "${TPATHS[@]}" 2>/dev/null)"
  eval_triggers
  endsec
} >> "$H"

# ---- R1 keyword commits (whole message) --------------------------------------------------------------
G "$REPO" log "${DIFFSAFE[@]}" -i -E --grep="$KW" --format='%h %ad %s' --date=short "$PIN_SHA" -- "${TPATHS[@]}" > "$TMPD/r1" 2>/dev/null
{ section "R1 Commits whose message matches security keywords" "Case-insensitive, whole commit message: \`$(clean "$KW")\`"
  emit_capped "$TMPD/r1" "no commit message in the pin ancestry matches"; endsec; } >> "$H"

# ---- R2 reverts ------------------------------------------------------------------------------------
G "$REPO" log "${DIFFSAFE[@]}" -E --grep='^Revert "|This reverts commit [0-9a-f]{7,40}' --format='%H %h %ad %s' --date=short "$PIN_SHA" -- "${TPATHS[@]}" 2>/dev/null |
while read -r full short date subj; do
  rev=$(G "$REPO" log "${DIFFSAFE[@]}" -1 --format=%B "$full" 2>/dev/null | grep -oE 'reverts commit [0-9a-f]{7,40}' | sed -n 1p | awk '{print substr($3, 1, 10)}')
  echo "$short $date $subj  -> reverts ${rev:-unknown}"
done > "$TMPD/r2"
{ section "R2 Reverts" "A reverted fix, or a revert of a revert, marks a surface someone changed their mind about."
  emit_capped "$TMPD/r2" "no revert commit in the pin ancestry"; endsec; } >> "$H"

# ---- R3 guard lines removed / added ------------------------------------------------------------------
GR_FILES="$TMPD/r3.paths" guard_rows "$REPO" "$PIN_SHA" "${TPATHS[@]}" > "$TMPD/r3ids"
cut -d' ' -f2- "$TMPD/r3ids" > "$TMPD/r3"
grep -E ' REMOVED x' "$TMPD/r3" > "$TMPD/r3a"
grep -E ' ADDED-QUIET x' "$TMPD/r3" > "$TMPD/r3b"
grep -E ' ADDED x' "$TMPD/r3" > "$TMPD/r3c"
{ section "R3 Account-guard lines removed or added" \
"Guard text a commit removed from the target paths (REMOVED), or added in a keyword-free commit changing <= $SMALL lines (ADDED-QUIET) or in a commit of <= $FIX_CEILING lines whose message matches a keyword (ADDED). Each commit nets identical guard text across its files: a guard moved unchanged prints nothing, an edited one prints its old text as REMOVED. Blind spots: flipped comparisons, changed inputs to an unchanged guard, plain \`if ... { return Err(...) }\` checks, merge resolutions, identical text removed in one file and added in another by the same commit."
  echo "--- R3a REMOVED ---"
  emit_capped "$TMPD/r3a" "no guard text removed in the pin ancestry"
  echo "--- R3b ADDED-QUIET (quiet-fix candidates) ---"
  emit_capped "$TMPD/r3b" "no guard text added by a small keyword-free commit"
  echo "--- R3c ADDED in keyword commits ---"
  emit_capped "$TMPD/r3c" "no guard text added by a keyword commit"
  endsec; } >> "$H"
# Saved diffs name the commit by its full id (a short id could also be the name of a ref) and hold only
# the files the commit's rows name.
grep -E ' (REMOVED|ADDED-QUIET) x' "$TMPD/r3ids" | awk '!s[$1]++ { print $1, $2 }' | sed -n '1,20p' |
while read -r full c; do
  awk -F '\t' -v c="$full" '$1 == c && !s[$2]++ { print $2 }' "$TMPD/r3.paths" > "$TMPD/save.paths"
  save_diff "$REPO" "$REPO_REL" "$full" "$STAGE/diffs/target-$c.diff" "$TMPD/save.paths" "${TPATHS[@]}"
done

# ---- R4 churn --------------------------------------------------------------------------------------
G "$REPO" log "${DIFFSAFE[@]}" --no-renames --format= --name-only "$PIN_SHA" -- "${TPATHS[@]}" 2>/dev/null | sed '/^$/d' | sort | uniq -c | sort -k1,1nr -k2 > "$TMPD/r4a"
# Function names come from hunk headers: *.rs maps to the rust driver, whose pattern is passed on the
# command line, and with ATTR_SRC the target's .gitattributes are not read. Its .git/info/attributes
# still are; the .rs files they send to another driver are counted in a note.
printf '*.rs diff=rust\n' > "$TMPD/rs.attributes"
R4_GIT=(${ATTR_SRC:+"--attr-source=$ATTR_SRC"} -c core.attributesFile="$TMPD/rs.attributes" -c diff.rust.xfuncname="$RUST_FUNC")
G "$REPO" "${R4_GIT[@]}" log "${DIFFSAFE[@]}" -p -U0 --no-renames \
    --format='__C__ %h' "$PIN_SHA" -- "${TPATHS[@]}" 2>/dev/null | awk '
  /^__C__ / { c = $2; next }
  /^@@ / { s = $0; sub(/^@@ [^@]*@@ ?/, "", s)
           if (match(s, /fn [A-Za-z0-9_]+/)) { f = substr(s, RSTART + 3, RLENGTH - 3)
             if (!seen[c SUBSEP f]++) cnt[f]++ } }
  END { for (f in cnt) printf "%4d %s\n", cnt[f], f }' | sort -k1,1nr -k2 > "$TMPD/r4b"
R4_OTHER=$(sed -E 's/^ *[0-9]+ //' "$TMPD/r4a" | grep -E '\.rs"?$' |
  G "$REPO" "${R4_GIT[@]}" check-attr --stdin diff 2>/dev/null | grep -vc ': diff: rust$')
{ section "R4 Churn" "Files, then functions (hunk headers from git's rust pattern, pinned), by number of commits touching them."
  emit_capped "$TMPD/r4a" "no file in the target paths changed"
  echo "--- functions ---"
  if [ "${R4_OTHER:-0}" -gt 0 ]; then
    echo "note: the target's attributes send $R4_OTHER .rs file(s) above to another diff driver; their hunks may name no function, or one that driver chose"
  fi
  emit_capped "$TMPD/r4b" "no rust function header in the diffs"; endsec; } >> "$H"

# ---- R5 fork parent --------------------------------------------------------------------------------
{
  section "R5 Fork parent" "Hints only: a fork point and the parent's later guard additions (absent rows and smaller commits first). Neither proves a fix was or was not carried."
  if [ -z "$PARENT" ]; then
    echo "NOT FOUND (no --parent given; a URL found in target content is never fetched)"
  elif [ -z "$PDIR" ] || [ -z "$PHEAD" ]; then
    echo "NOT FOUND (parent $(clean "$(redact "$PARENT")"): $PARENT_STATUS)"
  else
    G "$PDIR" rev-list --all > "$TMPD/parent.revs" 2>/dev/null
    # The fork point is looked for on the target's first-parent line first: a parent commit reached only
    # through a merge (one made with -s ours records the parent's history without its code) must not
    # move the fork point past fixes the target never applied. R5d then tags each later parent guard
    # present or absent at the pin. Without a shared commit on that line, the whole ancestry is searched.
    FORK="" METHOD="shared history, first-parent line"
    if [ -s "$TMPD/parent.revs" ]; then
      G "$REPO" rev-list --first-parent "$PIN_SHA" > "$TMPD/target.revs" 2>/dev/null
      FORK=$(awk 'NR == FNR { p[$1] = 1; next } ($1 in p) { print; exit }' "$TMPD/parent.revs" "$TMPD/target.revs")
      if [ -z "$FORK" ]; then
        METHOD="shared history"
        G "$REPO" rev-list "$PIN_SHA" > "$TMPD/target.revs" 2>/dev/null
        FORK=$(awk 'NR == FNR { p[$1] = 1; next } ($1 in p) { print; exit }' "$TMPD/parent.revs" "$TMPD/target.revs")
      fi
    fi
    if [ -z "$FORK" ]; then
      METHOD="blob identity"
      [ -n "$IMPORT" ] || IMPORT=$(G "$REPO" rev-list --max-parents=0 "$PIN_SHA" | tail -n 1)
      # ls-tree takes literal paths, not globs; a diff from the empty tree honours the pathspec.
      G "$REPO" diff-tree "${DIFFSAFE[@]}" -r --no-renames "$EMPTY_TREE" "$IMPORT" -- "${TPATHS[@]}" 2>/dev/null |
        awk '/^:/ { print $4 }' | sort -u | sed -n '1,2000p' > "$TMPD/import.blobs"
      if [ -s "$TMPD/import.blobs" ]; then
        G "$PDIR" log "${DIFFSAFE[@]}" --all --no-renames --raw --no-abbrev --format='__C__ %ct %H' -- "${PPATHS[@]}" 2>/dev/null |
          awk 'NR == FNR { want[$1] = 1; total++; next }
               /^__C__ / { ct = $2; h = $3; next }
               /^:/ { if ($4 in want) intro[$4] = ct " " h }
               END { for (b in intro) { split(intro[b], a, " "); m++; if (a[1] + 0 > best + 0) { best = a[1]; bh = a[2] } }
                     if (m > 0) printf "%s %d %d\n", bh, m, total }' "$TMPD/import.blobs" - > "$TMPD/blobmatch"
        FORK=$(awk '{print $1}' "$TMPD/blobmatch")
        [ -n "$FORK" ] && METHOD="blob identity: $(awk '{print $2 " of " $3}' "$TMPD/blobmatch") import blobs found in the parent"
      fi
    fi
    if [ -z "$FORK" ]; then
      echo "NOT FOUND (no shared commit and no identical file content between the target import and the parent)"
    else
      echo "fork point: $(clean "$(G "$PDIR" log "${DIFFSAFE[@]}" -1 --format='%h %ad %s' --date=short "$FORK")") — $METHOD"
      echo "parent head: $(clean "$(G "$PDIR" log "${DIFFSAFE[@]}" -1 --format='%h %ad %s' --date=short "$PHEAD")")"
      if [ "$(G "$PDIR" rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
        echo "note: the parent is a shallow clone; its history before the shallow boundary is missing"
      fi
      echo
      echo "--- R5c parent commits after the fork point whose whole message matches a keyword ---"
      G "$PDIR" log "${DIFFSAFE[@]}" -i -E --grep="$KW" --format='%h %ad %s' --date=short "$FORK..$PHEAD" -- "${PPATHS[@]}" > "$TMPD/r5c" 2>/dev/null
      emit_capped "$TMPD/r5c" "no keyword commit in the parent after the fork point"
      echo
      echo "--- R5d guard lines the parent added after the fork point, looked up in the target @ pin ---"
      G "$REPO" grep -h -a -e '' "$PIN_SHA" -- "${TPATHS[@]}" 2>/dev/null | awk '{ gsub(/[ \t]/, ""); print }' > "$TMPD/target.lines"
      echo "__no_line_matches_this__" >> "$TMPD/target.lines"   # keeps the join below two-file even for an empty tree
      # Absent rows first, then smaller commits, then commit order: a real fix should not fall past
      # the cap behind feature releases.
      GR_FILES="$TMPD/r5.paths" GR_SIZE=1 guard_rows "$PDIR" "$FORK..$PHEAD" "${PPATHS[@]}" | grep -E ' ADDED(-QUIET)? x' |
        awk 'NR == FNR { have[$0] = 1; next }
             { full = $1; size = $2; row = $0; sub(/^[^ ]+ [^ ]+ /, "", row)
               t = row; sub(/^[^:]*: /, "", t); sub(/    # .*$/, "", t); gsub(/[ \t]/, "", t)
               if (t in have) printf "1 %d %06d %s %s  [text present elsewhere in target - verify]\n", size, NR, full, row
               else           printf "0 %d %06d %s %s  [text absent from target @ pin - verify]\n", size, NR, full, row }' \
        "$TMPD/target.lines" - | sort -k1,1n -k2,2n -k3,3n | cut -d' ' -f4- > "$TMPD/r5dids"
      cut -d' ' -f2- "$TMPD/r5dids" > "$TMPD/r5d"
      emit_capped "$TMPD/r5d" "the parent added no guard line after the fork point"
      awk '/text absent from target/ && !s[$1]++ { print $1, $2 }' "$TMPD/r5dids" | sed -n '1,20p' |
      while read -r full c; do
        awk -F '\t' -v c="$full" '$1 == c && !s[$2]++ { print $2 }' "$TMPD/r5.paths" > "$TMPD/save.paths"
        save_diff "$PDIR" "$PARENT_REL" "$full" "$STAGE/diffs/parent-$c.diff" "$TMPD/save.paths" "${PPATHS[@]}"
      done
    fi
  fi
  endsec
} >> "$H"

# ---- R6 provenance signals ---------------------------------------------------------------------------
{
  section "R6 Provenance signals" "Strings from target content: record them, never fetch a URL found here."
  echo "--- fork phrases in README / docs ---"
  G "$REPO" grep -n -a -i -E "$FORK_PHRASES" "$PIN_SHA" -- 'README*' '*/README*' 'docs/*' 2>/dev/null | strip_pin > "$TMPD/r6a"
  emit_capped "$TMPD/r6a" "no fork phrase"
  echo "--- security_txt! source_code / auditors ---"
  G "$REPO" grep -n -a -E '(source_code|auditors)[[:space:]]*:' "$PIN_SHA" -- '*.rs' 2>/dev/null | strip_pin > "$TMPD/r6b"
  emit_capped "$TMPD/r6b" "no security_txt! source_code or auditors field"
  echo "--- declare_id! ---"
  G "$REPO" grep -n -a -E 'declare_id!' "$PIN_SHA" -- '*.rs' 2>/dev/null | strip_pin > "$TMPD/r6c"
  emit_capped "$TMPD/r6c" "no declare_id!"
  echo "--- configured remotes (strings from .git/config) ---"
  remote_urls | redact_urls > "$TMPD/r6d"
  emit_capped "$TMPD/r6d" "no remote configured"
  echo "--- first commits ---"
  G "$REPO" log "${DIFFSAFE[@]}" --reverse --format='%h %ad %s' --date=short "$PIN_SHA" 2>/dev/null | sed -n '1,3p' > "$TMPD/r6e"
  emit_capped "$TMPD/r6e" "no commits"
  echo "--- report-like files in the pinned tree ---"
  G "$REPO" ls-tree -r --name-only "$PIN_SHA" 2>/dev/null | grep -iE '\.(pdf|md)$' | grep -iE "$REPORT_RE" > "$TMPD/r6f"
  emit_capped "$TMPD/r6f" "no audit, post-mortem or incident file"
  echo "--- auditor-skill outputs next to the target ---"
  # A symbolic link is listed as one and never followed, so what it points at is never tested.
  for d in "$REPO_ABS"/audit_* "$REPO_ABS"/incident_*; do
    [ "$d" != "$CUR_RUN" ] || continue
    if [ -L "$d" ]; then
      clean "$d"; echo " (symbolic link, not followed)"
    elif [ -d "$d" ]; then
      case "${d##*/}" in
        audit_*) clean "$d/"; echo ;;
        *) if [ -L "$d/INCIDENTS.json" ]; then clean "$d/INCIDENTS.json"; echo " (symbolic link, not followed)"
           elif [ -e "$d/INCIDENTS.json" ]; then clean "$d/INCIDENTS.json"; echo; fi ;;
      esac
    fi
  done > "$TMPD/r6g"
  emit_capped "$TMPD/r6g" "no audit_*/ or incident_*/INCIDENTS.json"
  endsec
} >> "$H"

# ---- R7 inputs -------------------------------------------------------------------------------------
INPUT_N=0
record() { # record <source> <format> <sha256> <stored_as> <status>
  INPUT_N=$((INPUT_N + 1))
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$INPUT_N" "$(clean "$(redact "$1")")" "$2" "$3" "$4" "$(clean "$5")" >> "$STAGE/inputs.tsv"
}
# JSON tools in order of preference. When jq is missing, too old, or fails on a file, python3 takes
# over; with neither, JSON inputs are recorded but never copied. TM_JSON_TOOL (jq | python3 | none)
# pins the choice for tests.
case "${TM_JSON_TOOL:-}" in
  jq) JSON_TOOLS="jq" ;; python3) JSON_TOOLS="python3" ;; none) JSON_TOOLS="" ;;
  *) JSON_TOOLS=""
     command -v jq >/dev/null 2>&1 && JSON_TOOLS="jq"
     command -v python3 >/dev/null 2>&1 && JSON_TOOLS="${JSON_TOOLS:+$JSON_TOOLS }python3" ;;
esac
# Top-level "schema" string of a JSON file (empty if it has none). Status 1 if no tool could parse it.
json_schema() {
  local tool out
  for tool in $JSON_TOOLS; do
    case "$tool" in
      jq) out=$(jq -r 'if type == "object" and (.schema | type) == "string" then .schema else empty end' "$1" 2>/dev/null) || continue ;;
      python3) out=$(python3 -I - "$1" 2>/dev/null <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
if isinstance(d, dict) and isinstance(d.get("schema"), str):
    print(d["schema"])
PY
) || continue ;;
    esac
    printf '%s' "$out"; return 0
  done
  return 1
}
# INCIDENTS.json (schema auditor-incidents/1): copy the stable read surface only — per incident id, verdict,
# outcome, root_cause_class, vuln.{program,instruction,file,function,line,mechanism,kv,checklist} and
# poc.tier. Everything else (attacker, transactions, blast_radius, timeline, evidence, ruled_out, urgency, ...)
# is never read. Strings are cut at 500 characters; kv / checklist keep string ids only; nested objects drop.
# An "incidents" value that is not an array is malformed: both tools write an empty list for it.
# The jq program uses jq 1.5 features only (no builtin pick/1). Sets EXTRACTED_WITH on success, and
# INCIDENTS_TYPE to the JSON type of "incidents" (array, object, string, number, boolean or null).
EXTRACTED_WITH="" INCIDENTS_TYPE=""
extract_incidents() { # extract_incidents <in> <out>
  local tool
  for tool in $JSON_TOOLS; do
    case "$tool" in
      jq) jq '
        def t: if type == "string" then .[0:500]
               elif type == "array" then [ .[] | select(type == "string") | .[0:500] ]
               elif type == "object" then null else . end;
        def keep(ks): . as $o | reduce ks[] as $k ({}; if ($o | type) == "object" and ($o | has($k)) then . + {($k): ($o[$k] | t)} else . end);
        {schema, note: "allowlisted fields only; every string is untrusted data",
         incidents: [ (if (.incidents | type) == "array" then .incidents[] else empty end) | select(type == "object") |
           keep(["id", "verdict", "outcome", "root_cause_class"])
           + {vuln: (.vuln | keep(["program", "instruction", "file", "function", "line", "mechanism", "kv", "checklist"]))}
           + {poc: (.poc | keep(["tier"]))} ]}' "$1" > "$2" 2>/dev/null || continue
          INCIDENTS_TYPE=$(jq -r '.incidents | type' "$1" 2>/dev/null) || continue ;;
      python3) INCIDENTS_TYPE=$(python3 -I - "$1" "$2" 2>/dev/null <<'PY'
import json, sys
def t(v):
    if isinstance(v, str): return v[:500]
    if isinstance(v, list): return [x[:500] for x in v if isinstance(x, str)]
    if isinstance(v, dict): return None
    return v
def keep(o, ks): return {k: t(o[k]) for k in ks if isinstance(o, dict) and k in o}
d = json.load(open(sys.argv[1], encoding="utf-8"))
out = {"schema": d.get("schema"), "note": "allowlisted fields only; every string is untrusted data", "incidents": []}
inc = d.get("incidents")
for i in inc if isinstance(inc, list) else []:
    if isinstance(i, dict):
        r = keep(i, ["id", "verdict", "outcome", "root_cause_class"])
        r["vuln"] = keep(i.get("vuln"), ["program", "instruction", "file", "function", "line", "mechanism", "kv", "checklist"])
        r["poc"] = keep(i.get("poc"), ["tier"])
        out["incidents"].append(r)
json.dump(out, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
kinds = ((bool, "boolean"), (int, "number"), (float, "number"), (str, "string"), (list, "array"), (dict, "object"))
print(next((name for cls, name in kinds if isinstance(inc, cls)), "null"))
PY
) || continue ;;
    esac
    EXTRACTED_WITH=$tool; return 0
  done
  rm -f "$2"; return 1
}
ingest() { # ingest <source label> <local file> <dest base name>
  local src=$1 f=$2 dest="inputs/$3" sum magic schema lsrc
  if [ ! -f "$f" ] || [ ! -r "$f" ]; then record "$src" "-" "-" "-" "missing or unreadable"; return 0; fi
  sum=$(sha256_of "$f")
  magic=$(head -c 5 "$f" 2>/dev/null | tr -d '\000')
  if [ "$magic" = "%PDF-" ]; then
    if command -v pdftotext >/dev/null 2>&1 && pdftotext -layout -enc UTF-8 "$f" "$STAGE/$dest.txt" 2>/dev/null; then
      record "$src" pdf "$sum" "$dest.txt" "converted (pdftotext -layout)"
    else
      record "$src" pdf "$sum" "-" "not converted: read the PDF with Read (<= 20 pages per call) or ask for a Markdown/text export"
    fi
    return 0
  fi
  case "$f" in
    *.json|*.JSON)
      if ! schema=$(json_schema "$f"); then
        record "$src" json "$sum" "-" "not copied: no working jq or python3 parsed it (or invalid JSON)"
      elif [ "$schema" = "auditor-incidents/1" ]; then
        if ! extract_incidents "$f" "$STAGE/$dest"; then record "$src" incidents "$sum" "-" "not extracted: no working jq or python3"
        elif [ "$INCIDENTS_TYPE" = array ]; then record "$src" incidents "$sum" "$dest" "allowlisted fields extracted ($EXTRACTED_WITH)"
        else record "$src" incidents "$sum" "$dest" "malformed: incidents is $INCIDENTS_TYPE, not an array; empty extract ($EXTRACTED_WITH)"; fi
      elif [ -n "$schema" ]; then
        record "$src" json "$sum" "-" "skipped: schema \"$schema\" is not auditor-incidents/1"
      elif lsrc=$(printf '%s' "$src" | tr 'A-Z' 'a-z'); [ "${lsrc#*incident}" != "$lsrc" ]; then
        record "$src" json "$sum" "-" "not copied: could not confirm it is not an incident file"
      else
        cp "$f" "$STAGE/$dest" && record "$src" json "$sum" "$dest" "copied (list)"
      fi ;;
    *.csv|*.CSV)          cp "$f" "$STAGE/$dest" && record "$src" csv "$sum" "$dest" "copied (list)" ;;
    *.md|*.MD|*.markdown) cp "$f" "$STAGE/$dest" && record "$src" markdown "$sum" "$dest" "copied" ;;
    *.txt|*.TXT|*.lst)    cp "$f" "$STAGE/$dest" && record "$src" text "$sum" "$dest" "copied" ;;
    *)                    record "$src" unknown "$sum" "-" "unsupported format; supply PDF, Markdown, text, CSV or JSON" ;;
  esac
}
safe_name() { printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]/_/g'; }
# A local --vulns path is read only when it is not a symbolic link and reaches its file through no directory
# link inside the target tree: the target controls those, and a link can point anywhere (a keypair, a .env).
# Links outside the tree, such as /tmp on macOS or the caller's own, are followed.
tree_link() { # tree_link <absolute path>: status 0 when the path is a symbolic link, or passes through a
              # directory link that sits inside the target tree or whose place cannot be resolved
  local rest=${1#/} cur="" comp phys
  [ -L "$1" ] && return 0
  while :; do
    case "$rest" in */*) comp=${rest%%/*}; rest=${rest#*/} ;; *) return 1 ;; esac
    if [ -n "$comp" ] && [ -L "$cur/$comp" ]; then
      phys=$(cd "${cur:-/}" 2>/dev/null && pwd -P) || return 0
      case "$phys/" in "$REPO_PHYS"/*) return 0 ;; esac
    fi
    cur="$cur/$comp"
  done
}
vi=0
while IFS= read -r v; do
  [ -z "$v" ] && continue
  vi=$((vi + 1))
  if [ "$(classify_source "$v")" = url ]; then
    if [ "$OFFLINE" -eq 1 ]; then record "$v" url "-" "-" "recorded, not fetched (offline)"; continue; fi
    if ! command -v curl >/dev/null 2>&1; then record "$v" url "-" "-" "not fetched: curl unavailable"; continue; fi
    name=$(safe_name "$(printf '%s' "${v%%[?#]*}" | sed 's#.*/##')")
    [ -n "$name" ] || name=download
    disclose "$v" "download"
    if curl -q --proto '=https' --proto-redir '=https' -fsSL --max-time 60 --max-filesize 52428800 \
         -A 'auditor-skill-threat-model' -o "$TMPD/fetch-$vi-$name" "$v" 2>/dev/null; then
      ingest "$v" "$TMPD/fetch-$vi-$name" "v$vi-$name"
    else
      record "$v" url "-" "-" "fetch failed"
    fi
  elif tree_link "$v"; then
    record "$v" "-" "-" "-" "skipped: symbolic link (the file, or a directory on its path inside the target tree)"
  else
    ingest "$v" "$v" "v$vi-$(safe_name "$(basename "$v")")"
  fi
done <<< "$VULNS_NL"
# An incident file counts only where an auditor run wrote it: not a symbolic link, not inside a linked
# directory, and not in an incident_* directory the target tracks. A link is recorded as one and never
# followed, so what it points at is never tested.
ii=0
for d in "$REPO_ABS"/incident_*; do
  f=$d/INCIDENTS.json
  if [ -L "$d" ]; then record "$d" "-" "-" "-" "skipped: symbolic link (directory), not followed"; continue; fi
  [ -d "$d" ] || continue
  if [ -L "$f" ]; then record "$f" "-" "-" "-" "skipped: symbolic link (file), not followed"; continue; fi
  [ -f "$f" ] || continue
  if ! listed=$(G "$REPO_ABS" --icase-pathspecs ls-files -- "$(basename "$d")" 2>/dev/null) || [ -n "$listed" ]; then
    record "$f" "-" "-" "-" "skipped: tracked by the target, not written by an auditor run"; continue
  fi
  ii=$((ii + 1)); ingest "$f" "$f" "incident$ii-INCIDENTS.json"
done
ri=0
sort -r "$TMPD/r6f" > "$TMPD/r6f.newest"   # reverse name order: dated report names come newest first
while IFS= read -r p; do
  [ -z "$p" ] && continue
  ri=$((ri + 1))
  if [ "$ri" -gt 20 ]; then record "(further in-tree reports)" "-" "-" "-" "skipped: cap of 20 in-tree reports, listed in R6"; break; fi
  tmp="$TMPD/tree$ri-$(safe_name "$(basename "$p")")"
  G "$REPO" cat-file blob "$PIN_SHA:$p" > "$tmp" 2>/dev/null && ingest "pinned tree: $p" "$tmp" "tree$ri-$(safe_name "$(basename "$p")")"
done < "$TMPD/r6f.newest"
{
  section "R7 Inputs" "Every --vulns source, incident_*/INCIDENTS.json and in-tree report; the full manifest is inputs.tsv."
  awk -F '\t' 'NR > 1 { printf "%s. %s [%s] -> %s: %s\n", $1, $2, $3, $5, $6 }' "$STAGE/inputs.tsv" > "$TMPD/r7"
  emit_capped "$TMPD/r7" "no prior-vulnerability input"
  endsec
} >> "$H"

# ---- R8 audit-mem warm ------------------------------------------------------------------------------
# Only a store passed with --audit-mem-db is read, through audit-mem warm, run from the working directory.
# The collector never looks for one in the target tree: whether a store there can be trusted
# (OUTPUT-RULES.md Rule 11d) is the caller's check.
{
  section "R8 audit-mem warm" "Standing rulings for this program id from the findings store passed with --audit-mem-db."
  BIN="$SKILL_ROOT/tools/auditor-tools/target/release/audit-mem"
  if [ -z "$PROGRAM_ID" ]; then echo "NOT FOUND (no --program-id given)"
  elif [ -z "$DB_REL" ]; then echo "NOT FOUND (no --audit-mem-db given; the collector never looks for a store on its own)"
  elif [ ! -x "$BIN" ]; then echo "NOT FOUND (tools/auditor-tools is not built)"
  elif [ -L "$WT/$DB_REL" ] || [ ! -f "$WT/$DB_REL" ]; then echo "NOT FOUND (no database at $(clean "$DB_REL"))"
  elif (cd "$WT" && "$BIN" warm --db "$DB_REL" --program-id="$PROGRAM_ID") > "$STAGE/audit-mem-warm.json" 2>/dev/null; then
    echo "saved: audit-mem-warm.json"
  else
    rm -f "$STAGE/audit-mem-warm.json"; echo "NOT FOUND (audit-mem warm failed)"
  fi
  endsec
} >> "$H"

# ---- publish (OUTPUT-RULES.md Rule 11d) ---------------------------------------------------------------
# The run directory is checked again, since the run takes a while, and the staged output is copied into
# --out: every file is created anew with noclobber and written through the descriptor opened at creation.
# A re-run first removes the outputs of the run before: history.md, inputs.tsv and audit-mem-warm.json,
# and inputs/ and diffs/ where an inputs.tsv marks them as this collector's.
confine_rundir "$RUN" "the run directory"
confine_path "$OUT_REL" --out any
DEST=$WT/$OUT_REL
case "$CONFINE_TYPE" in
  file) die "--out is not a directory: $(confine_text "$OUT")" ;;
  none) confine_mkdir "$DEST" || die "cannot create $OUT_REL" ;;
esac
if [ -f "$DEST/inputs.tsv" ]; then
  rm -rf "$DEST/inputs" "$DEST/diffs" || die "cannot remove the inputs/ and diffs/ of the run before in $OUT_REL"
fi
rm -f "$DEST/history.md" "$DEST/inputs.tsv" "$DEST/audit-mem-warm.json" || die "cannot remove the output of the run before in $OUT_REL"
for d in inputs diffs; do
  if [ -L "$DEST/$d" ] || { [ -e "$DEST/$d" ] && [ ! -d "$DEST/$d" ]; }; then die "$OUT_REL/$d is not a directory of its own"; fi
  [ -d "$DEST/$d" ] || confine_mkdir "$DEST/$d" || die "cannot create $OUT_REL/$d"
done
for f in "$STAGE"/inputs/* "$STAGE"/diffs/* "$STAGE/inputs.tsv" "$STAGE/audit-mem-warm.json" "$STAGE/history.md"; do
  [ -f "$f" ] || continue
  rel=${f#"$STAGE"/}
  confine_new_copy "$f" "$DEST/$rel" || die "cannot write $OUT_REL/$rel (a file of that name appeared, or the directory is not writable)"
done
echo "collect.sh: wrote $OUT_REL/history.md" >&2
exit 0
