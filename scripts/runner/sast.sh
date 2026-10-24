#!/bin/bash
# sast.sh — static analysis of the code under audit with semgrep, which parses the code and never runs it, so
# it needs no execution mode (OUTPUT-RULES.md Rules 11a and 11b).
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/runner/sast.sh" semgrep --run <R> --path <path> --ruleset <id> [--ruleset <id>]...
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under
# audit. A refusal is one stderr line, "sast: refused: <reason>", with exit 64, before anything is sent; a
# blocker is one stderr line, "sast: blocker: <reason>", with exit 3.
#
# --path is a confined directory or regular file under the working directory. Each --ruleset is one of
# p/rust, p/trailofbits, p/typescript, p/javascript, p/python, p/golang, p/secrets, p/github-actions and
# p/solidity, each at most once. The scan runs
#   semgrep scan --config <id>... --metrics=off --disable-version-check --sarif --output <scratch> --error -- <path>
# from a scratch directory outside the working directory, in the cleaned environment of
# scripts/lib/isolation.sh with the real HOME kept (semgrep's own install may live there), its settings file
# in the scratch directory, no version check and no metrics, and the proxy variables: semgrep downloads the
# rulesets from semgrep.dev, and before that one row goes to <R>/disclosures.tsv. A .semgrepignore or
# .gitignore under <path> narrows what semgrep reads; the last line names the .semgrepignore files it
# found. AUDITOR_RUN_TIMEOUT (whole seconds, 1 to 86400, default 1800) bounds the scan, under the watchdog
# of isolation.sh's iso_watch.
#
# Output: the SARIF in <R>/sast/semgrep-<n>.sarif and semgrep's own messages in <R>/sast/semgrep-<n>.log.
# The last stdout line gives the number of results and where they are. The scratch directory is removed on
# exit.
#
# Exit: 0 no results · 1 results · 3 blocker (semgrep missing or failing, no SARIF, the watchdog) ·
# 64 refused. Needs bash >= 3.2, semgrep, python3, git, env, find, mkdir, mktemp, rm, chmod, cat and date.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'sast: refused: the installation cannot be resolved\n' >&2; exit 64; }
case "$here" in
  */scripts/runner) root=${here%/scripts/runner} ;;
  *) printf 'sast: refused: sast.sh runs from <auditor-skill root>/scripts/runner\n' >&2; exit 64 ;;
esac
. "$root/scripts/lib/confine.sh" || { printf 'sast: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
. "$root/scripts/lib/isolation.sh" || { printf 'sast: refused: scripts/lib/isolation.sh cannot be read\n' >&2; exit 64; }
confine_init sast "$root"
confine_need env git find mkdir mktemp rm chmod cat date
WT=$CONFINE_WT

RULESETS='p/rust p/trailofbits p/typescript p/javascript p/python p/golang p/secrets p/github-actions p/solidity'
USAGE="usage: sast.sh semgrep --run <R> --path <path> --ruleset <id> [--ruleset <id>]..., with the rulesets ${RULESETS// /, }"
TOOL=scripts/runner/sast.sh

refuse() { confine_refuse "$1"; }
blocker() { printf 'sast: blocker: %s\n' "$1" >&2; exit 3; }

# ---- arguments (all checked before anything is sent) --------------------------------------------------
[ $# -gt 0 ] && [ "$1" = semgrep ] || refuse "$USAGE"
shift
RUN_ARG="" PATH_ARG="" seen=" "
SETS=()
while [ $# -gt 0 ]; do
  opt=$1
  shift
  case "$opt" in
    --run|--path|--ruleset) [ $# -gt 0 ] || refuse "$opt needs a value" ;;
    *) refuse "$(confine_text "$opt") is not an argument sast.sh takes ($USAGE)" ;;
  esac
  case "$opt" in
    --ruleset)
      case "$1" in *[!a-z/-]*|'') refuse "--ruleset takes one of ${RULESETS// /, }, not $(confine_text "$1")" ;; esac
      case " $RULESETS " in *" $1 "*) ;; *) refuse "--ruleset takes one of ${RULESETS// /, }, not $(confine_text "$1")" ;; esac
      for s in ${SETS[@]+"${SETS[@]}"}; do [ "$s" != "$1" ] || refuse "give --ruleset $1 once"; done
      SETS+=("$1") ;;
    *)
      case "$seen" in *" $opt "*) refuse "give $opt once" ;; esac
      seen="$seen$opt "
      case "$opt" in --run) RUN_ARG=$1 ;; --path) PATH_ARG=$1 ;; esac ;;
  esac
  shift
done
case "$seen" in *" --run "*) ;; *) refuse "give --run <R>, the run directory ($USAGE)" ;; esac
case "$seen" in *" --path "*) ;; *) refuse "give --path, the directory or file to scan ($USAGE)" ;; esac
[ "${#SETS[@]}" -gt 0 ] || refuse "give at least one --ruleset ($USAGE)"
confine_rundir "$RUN_ARG" "--run"
R=$CONFINE_RUN
if [ "$PATH_ARG" = . ]; then
  PATH_REL=.
else
  confine_path "$PATH_ARG" "--path" any
  [ "$CONFINE_TYPE" != none ] || refuse "--path does not exist: $(confine_text "$PATH_ARG")"
  PATH_REL=$CONFINE_REL
fi
if [ "$PATH_REL" = . ]; then TARGET=$WT; else TARGET=$WT/$PATH_REL; fi
CAP=${AUDITOR_RUN_TIMEOUT:-1800}
{ case "$CAP" in ''|*[!0-9]*) false ;; *) [ "${#CAP}" -le 5 ] && [ "$CAP" -ge 1 ] && [ "$CAP" -le 86400 ] ;; esac; } ||
  refuse "AUDITOR_RUN_TIMEOUT is '$(confine_text "$CAP")', not a whole number of seconds from 1 to 86400"
LIMIT=$((10#$CAP))
iso_tmp_outside
iso_disclosures_ok "$R" || refuse "$R/disclosures.tsv is not a regular file with one link whose first line is the header, so no row can be added to it"

# ---- the tools, scratch and the watchdog -------------------------------------------------------------
command -v semgrep >/dev/null 2>&1 || blocker "semgrep is not on PATH, so the scan cannot run here — nothing was sent."
command -v python3 >/dev/null 2>&1 || blocker "python3 is not on PATH — nothing was sent."
S=""
cleanup() {
  case "${ISO_SCRATCH:-}" in */auditor-sast.??????) chmod -R u+rwX "$ISO_SCRATCH" 2>/dev/null; rm -rf "$ISO_SCRATCH" 2>/dev/null ;; esac
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
iso_scratch sast
S=$ISO_SCRATCH
cd / || blocker "cannot leave the working directory for /"
iso_env "$S" keep-home || blocker "cannot prepare the cleaned environment in $S — nothing was sent."
ISO_ENV+=("SEMGREP_SETTINGS_FILE=$S/semgrep-settings.yml" "SEMGREP_LOG_FILE=$S/semgrep.log" SEMGREP_ENABLE_VERSION_CHECK=0
  SEMGREP_SEND_METRICS=off)

# The .semgrepignore files under the path, which narrow the scan; find's own failure only hides the note.
ignores=""
if [ -d "$TARGET" ]; then
  find "$TARGET" \( -name .git -o -name node_modules \) -prune -o -name .semgrepignore -type f -print > "$S/ignores" 2>/dev/null || : > "$S/ignores"
  while IFS= read -r f; do
    f=${f#"$WT"/}
    ignores=${ignores:+$ignores, }$(confine_text "$f")
  done < "$S/ignores"
fi

CONFIGS=()
for s in "${SETS[@]}"; do CONFIGS+=(--config "$s"); done
iso_disclose "$R" "$TOOL" semgrep.dev "ruleset ids (the semgrep registry, for the rules)" "${SETS[@]}" ||
  blocker "cannot add a row to $R/disclosures.tsv, so nothing was sent"
: > "$S/out.log" || blocker "cannot write in $S"
printf '>> semgrep scan %s --metrics=off --disable-version-check --sarif --output <scratch> --error -- %s\n' \
  "${CONFIGS[*]}" "$PATH_REL" > "$S/out.log"
rc=0
iso_watch "$LIMIT" "$S/watch" "$S" ${ISO_NET[@]+"${ISO_NET[@]}"} semgrep scan "${CONFIGS[@]}" --metrics=off \
  --disable-version-check --sarif --output "$S/out.sarif" --error -- "$TARGET" >> "$S/out.log" 2>&1 || rc=$?
END=$(cat "$S/watch" 2>/dev/null) || END=""
[ -n "$END" ] || END="exit $rc"

# keep: the SARIF (when there is one) and the log as R/sast/semgrep-<n>.{sarif,log}; sets N.
SAST=$WT/$R/sast
if [ ! -d "$SAST" ]; then confine_mkdir "$SAST" || blocker "cannot create $R/sast"; fi
[ ! -L "$SAST" ] || blocker "$R/sast is a symbolic link"
N=1
while :; do
  while [ -e "$SAST/semgrep-$N.sarif" ] || [ -L "$SAST/semgrep-$N.sarif" ] || [ -e "$SAST/semgrep-$N.log" ] || [ -L "$SAST/semgrep-$N.log" ]; do
    N=$((N + 1))
    [ "$N" -le 9999 ] || blocker "$R/sast holds 9999 scans"
  done
  iso_copy_new "$S/out.log" "$SAST/semgrep-$N.log" && break
  [ -e "$SAST/semgrep-$N.log" ] || blocker "cannot write $R/sast/semgrep-$N.log"
done
LOG=$R/sast/semgrep-$N.log
note=""
[ -z "$ignores" ] || note="; note: .semgrepignore files narrow the scan: $ignores"
case "$END" in
  'exit 0'|'exit 1') ;;
  timeout) blocker "semgrep passed the $LIMIT-second limit (AUDITOR_RUN_TIMEOUT) and was killed; log $LOG" ;;
  *) blocker "semgrep failed ($(confine_text "$END")): no rules fetched, a target it cannot read, or another error; log $LOG" ;;
esac
[ -f "$S/out.sarif" ] && [ ! -L "$S/out.sarif" ] && [ -s "$S/out.sarif" ] || blocker "semgrep wrote no SARIF; log $LOG"
iso_copy_new "$S/out.sarif" "$SAST/semgrep-$N.sarif" || blocker "cannot write $R/sast/semgrep-$N.sarif; log $LOG"
results=$( (cd / && exec python3 -I -c 'import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
print(sum(len(run.get("results") or []) for run in data.get("runs") or []))' "$S/out.sarif") 2>/dev/null) ||
  blocker "the SARIF semgrep wrote cannot be read: $R/sast/semgrep-$N.sarif; log $LOG"
case "$END" in
  'exit 0') printf '>> semgrep: %s results (exit 0): %s; log %s%s\n' "$results" "$R/sast/semgrep-$N.sarif" "$LOG" "$note"; exit 0 ;;
  *) printf '>> semgrep: %s results (exit 1): %s; log %s%s\n' "$results" "$R/sast/semgrep-$N.sarif" "$LOG" "$note"; exit 1 ;;
esac
