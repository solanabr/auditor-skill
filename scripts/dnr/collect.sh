#!/bin/bash
# collect.sh — the ONE gated collector for the detection & response track. Pages
# signature history for one or more addresses and fetches each transaction, into a
# local JSONL corpus. Besides snapshot-program.sh (one program account, via the
# solana CLI) and scripts/rpc-read.sh (single reads), it is the only recipe in the
# track that touches the network.
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/collect.sh" --out incident_<n>/corpus[-<k>] --confirmed \
#        [--since <unix>] [--until <unix>] [--before <signature>] \
#        [--max-pages N] [--max-tx N] -- <address> [<address> ...]
#
# $RPC_URL must already be exported; never type the URL on the command line. Run it
# directly by its quoted path in the installation, from the working directory,
# never as a relative scripts/ path: the audited repo may ship a same-named file.
# Each option is given at most once, and an option-shaped word after one that takes
# a value is that value.
#
# GATING (do not relax — this is how "plans only, no actions" stays true for the
# corpus collection):
#   * REFUSES unless --confirmed is passed. `/auditor:hunt` and `/auditor:respond`
#     pass it only AFTER showing the human the addresses, the window, the caps and
#     the estimated call count, and getting a yes. Without it the script exits 2
#     before any network call.
#   * READ-ONLY RPC only: getSignaturesForAddress and getTransaction. Never a send,
#     a simulate, or a write method.
#   * CAPPED: --max-pages (default 20 → up to 20000 signatures per address) and
#     --max-tx (default 2000) bound the work and the spend. Raise them deliberately.
#     --max-tx counts getTransaction calls, failed ones included, so a run makes at
#     most addresses × max-pages + max-tx calls. No argument can go past the caps
#     the user sets in the environment: AUDITOR_RPC_MAX_PAGES (default 100),
#     AUDITOR_RPC_MAX_TX (default 10000) and AUDITOR_RPC_MAX_ADDRESSES (default 25,
#     the addresses after --). A value over its cap is refused (exit 2) with the
#     variable to raise, and a default over a cap set lower drops to that cap; a
#     cap that is not a plain integer is refused too.
#   * DISCLOSED: before the first call, one row goes into
#     incident_<n>/disclosures.tsv (OUTPUT-RULES.md Rule 11b; the format is in
#     scripts/lib/confine.sh): the provider domain and the addresses queried, with
#     the --before signature when one is given. A run directory whose
#     disclosures.tsv cannot take the row is refused before any call.
#   * STOPS ON A FAILING ENDPOINT: after 10 getTransaction calls in a row fail
#     (rate limit, outage, or history the endpoint does not serve), it fetches
#     nothing more and records the stop as a collection gap.
#
# WHAT IS KEPT: every signature in the window, FAILED ones included. A failed
# transaction moves no state, but it is evidence of an attempt — probing before a
# success, or a `suspected` incident whose attack has not landed yet. Filtering
# failures out would make those undetectable. Use `meta.err` downstream.
#
# RUN DIRECTORY: --out is incident_<n>/corpus or incident_<n>/corpus-<k> (k of 1 to 4
# digits), relative to the working directory (a leading ./ and trailing slashes are
# dropped). incident_<n> (OUTPUT-RULES.md Rule 11d) sits directly in the working
# directory, is a real directory holding no symbolic link, is tracked by no
# repository in any letter case, and has a .gitignore holding exactly "*"
# ("${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" new incident makes one). The corpus
# directory is made in it when missing. Any other --out, an absolute one included,
# and a run directory that fails these checks or that git or find cannot check, is
# refused with exit 2 before anything is written or sent.
#
# --before <sig> starts paging just older than that signature (resume a capped run,
# or skip activity newer than the incident) — always into a new --out: an --out that
# already holds signatures.jsonl, transactions.jsonl or collection-gaps.tsv, even an
# empty one, is refused, and the script creates its files with noclobber (`set -C`),
# so a resume never erases the first pass. It writes them only through the
# descriptors opened when it created them, and reads the signature list back from a
# private copy. Every address and --before value must be base58, and every number a
# plain integer, before anything is written or sent.
#
# PAGING: an empty page is the end of the address's history, and so is a page that
# crosses --since. A page shorter than the 1000 signatures asked for is not, except
# on the last page --max-pages allows: a node can return a short page before the end
# (for example when its archive backend fails), so paging goes on. That costs one
# more call when the history did end there, never more calls than --max-pages. When
# the page cap stops paging on a full page before --since was crossed, whatever
# --since and --until are, the script says so ("older history may exist") with the
# --before to resume from: the corpus may then be incomplete for that address, a
# collection gap to record in the ledger. Signatures are fetched newest first (by
# slot, across all addresses; within a slot, in the order the RPC returned them), so
# --max-tx drops the oldest. The script runs under LC_ALL=C, so neither that order
# nor any character range depends on the caller's locale.
#
# COLLECTION GAPS: every gap is also a row of <dir>/collection-gaps.tsv,
# `<signature or address><TAB><reason>`: a getTransaction that failed (transport
# error, RPC error or null result), a signature page that failed, a page cap that
# stopped on a full page (older history may exist), the --max-tx cap, and the stop
# on a failing endpoint (the last two name the first signature not fetched). The
# run ends with "transactions fetched: N of M calls -> <dir>/transactions.jsonl" and
# "collection gaps: N (see <dir>/collection-gaps.tsv)". Gaps leave the exit status at
# 0; copy each row into LEDGER.md and INCIDENTS.json `collection_gaps`.
#
# INTERRUPTED: an INT, TERM or HUP ends the run with the same record. The address
# being paged (with the --before signature to resume from, once one of its pages was
# read) and each address after it, and the signatures listed but not fetched (one
# row naming the first), become gap rows; the closing lines are printed; the exit
# status is 128 + the signal number (130, 143, 129). A run killed outright
# (SIGKILL) writes nothing more: then each signature in signatures.jsonl with no
# transaction in transactions.jsonl is a gap, and so is every address whose history
# may not have been paged to its end: the last queried_address in signatures.jsonl
# and every address given after it, or every address given when none appears. A run
# makes up to addresses × --max-pages + --max-tx calls, each up to 60 s, so run a
# long one in the background, or with a timeout sized from that count. A stdout or
# stderr that stops taking output (a reader that exited, a closed terminal) loses the
# messages, never the run: the collection goes on, and its corpus files are whole.
#
# A WRITE THAT FAILS: every write to the three corpus files, and to the private copies
# of the signature and fetch lists, is checked (a full disk, a file-size limit). One
# that fails stops the run where it is: no further call is made, what was left becomes
# gap rows as for an interrupted run, while the gap file still takes them, and a
# "[blocker] a write to <file> failed" line takes the place of the closing lines (exit
# 3). The corpus is then incomplete; when a gap row could not be written either, the
# blocker says so, and the gaps are recorded as for a run killed outright.
#
# SECRETS: the endpoint comes from $RPC_URL and is NEVER echoed. curl runs with -q
# (no ~/.curlrc) and reads the URL from a config on stdin (-K -), so the key stays
# out of its argv; an $RPC_URL holding a quote, a backslash, whitespace or a control
# character is refused. curl's stderr is captured to a temp file and passed through
# redact.sh. Output files carry no URL, and the "provider" line carries the host's
# last two DNS labels only, since some providers put an endpoint token in a
# subdomain.
#
# Transactions are fetched jsonParsed, commitment finalized, with
# maxSupportedTransactionVersion:1 — mandatory, since v1 transactions are live on
# mainnet and a v1 fetch without the opt-in returns RPC error -32015.
#
# EXACT INTEGERS: lamport balances and jsonParsed amounts pass 2^53, and jq < 1.7
# re-encodes every number as a double. jq writes transactions.jsonl only when it
# keeps a 2^64-1 literal exact; otherwise `python3 -I` does (its json module keeps
# integers exact), one compact JSON object per line either way. Signature pages
# carry only slots, block times and small error codes, and jq writes them.
#
# Exit: 0 done (collection gaps included) · 2 refused, one stderr line "collect.sh:
# refused: <reason>": usage, an input or cap, $RPC_URL, the run directory or its
# disclosures.tsv, or an --out that holds a corpus file or where they cannot be created · 3
# named blocker (no curl or jq; a jq that rounds large integers and no working
# python3; no private temp directory, which is made before anything is written; a
# write that failed, which ends the run without its closing lines) · 128 + N stopped
# by signal N (INT, TERM or HUP), with what was left recorded as gaps.
# bash >= 3.2, curl, jq (and python3 with jq < 1.7). Output: <dir>/signatures.jsonl,
# <dir>/transactions.jsonl, <dir>/collection-gaps.tsv, and a row of
# incident_<n>/disclosures.tsv.

# -C (noclobber): no redirection in this script replaces an existing file.
set -Cuo pipefail
export LC_ALL=C
# No cd may search $CDPATH, and no git call may use a repository named in the
# environment instead of the directory it is pointed at.
unset CDPATH GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

case "$0" in */*) HERE=${0%/*} ;; *) HERE=. ;; esac
HERE=$(cd -P -- "$HERE" 2>/dev/null && pwd -P) || { printf 'collect.sh: refused: the installation cannot be resolved\n' >&2; exit 2; }
SCRIPTS=${HERE%/*}
. "$SCRIPTS/lib/confine.sh" || { printf 'collect.sh: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 2; }
# The checks of the working directory, the installation and PATH, and every refusal: exit 2.
confine_init collect.sh "${SCRIPTS%/*}" 2
confine_need env git find wc cat sed awk sort grep tr mktemp rm mkdir date
REDACT="$HERE/redact.sh"
exec </dev/null

USAGE='usage: collect.sh --out incident_<n>/corpus[-<k>] --confirmed [--since U] [--until U] [--before SIG] [--max-pages N] [--max-tx N] -- <address>...'
out=""; confirmed=0; since=0; until=0; before_start=""; max_pages=20; max_tx=2000
addrs=(); seen=" "
# once <option>: refuse an option given before. take <option> <args...>: the value
# after the option; an absent one is refused.
once() {
  case "$seen" in *" $1 "*) confine_refuse "$1 is given twice" ;; esac
  seen="$seen$1 "
}
take() { [ $# -ge 2 ] || confine_refuse "$1 needs a value"; once "$1"; V=$2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --out) take "$@"; out=$V; shift 2 ;;
    --confirmed) once "$1"; confirmed=1; shift ;;
    --since) take "$@"; since=$V; shift 2 ;;
    --until) take "$@"; until=$V; shift 2 ;;
    --before) take "$@"; before_start=$V; shift 2 ;;
    --max-pages) take "$@"; max_pages=$V; shift 2 ;;
    --max-tx) take "$@"; max_tx=$V; shift 2 ;;
    --) shift; addrs=("$@"); break ;;
    *) confine_refuse "unknown argument: $(confine_text "$1")" ;;
  esac
done

if [ "$confirmed" -ne 1 ]; then
  confine_refuse "pass --confirmed (the command confirms addresses, window and caps with the human first)"
fi
if [ -z "$out" ] || [ ${#addrs[@]} -eq 0 ]; then
  confine_refuse "$USAGE"
fi
if [ -z "${RPC_URL:-}" ]; then
  confine_refuse "set \$RPC_URL in the environment (never on the command line, so it stays out of history and ledgers)"
fi
# The URL goes into a quoted curl config line: refuse what could end or escape it.
case "$RPC_URL" in
  *[[:space:][:cntrl:]\"\\]*)
    confine_refuse "\$RPC_URL holds a quote, a backslash, whitespace or a control character" ;;
esac
# Addresses and --before are spliced into JSON request bodies and usually come from
# target content (declare_id!, Anchor.toml): accept base58 only.
for addr in "${addrs[@]}"; do
  if ! [[ "$addr" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]]; then
    confine_refuse "'$(confine_text "$addr")' is not a base58 address (32-44 characters of [1-9A-HJ-NP-Za-km-z])"
  fi
done
if [ -n "$before_start" ] && ! [[ "$before_start" =~ ^[1-9A-HJ-NP-Za-km-z]{32,88}$ ]]; then
  confine_refuse "--before '$(confine_text "$before_start")' is not a base58 signature"
fi
for n in "$since" "$until" "$max_pages" "$max_tx"; do
  if ! [[ "$n" =~ ^[0-9]{1,18}$ ]]; then
    confine_refuse "'$(confine_text "$n")' is not a non-negative integer of at most 18 digits (--since, --until, --max-pages, --max-tx)"
  fi
done
since=$((10#$since)); until=$((10#$until)); max_pages=$((10#$max_pages)); max_tx=$((10#$max_tx))
# cap <variable> <default>: sets CAP to the cap the user set in the environment, or
# the default; one that is not a plain integer is refused.
cap() {
  CAP=$(eval "printf '%s' \"\${$1:-}\"")
  [ -n "$CAP" ] || CAP=$2
  [[ "$CAP" =~ ^[0-9]{1,18}$ ]] || confine_refuse "$1 in the environment is not a plain integer: $(confine_text "$CAP")"
  CAP=$((10#$CAP))
}
# A value given over its cap is refused; a default over a cap set lower drops to that cap.
cap AUDITOR_RPC_MAX_PAGES 100
if [ "$max_pages" -gt "$CAP" ]; then
  case "$seen" in
    *" --max-pages "*) confine_refuse "--max-pages $max_pages is over the cap of $CAP pages per address; to allow more, raise AUDITOR_RPC_MAX_PAGES in the environment" ;;
  esac
  max_pages=$CAP
fi
cap AUDITOR_RPC_MAX_TX 10000
if [ "$max_tx" -gt "$CAP" ]; then
  case "$seen" in
    *" --max-tx "*) confine_refuse "--max-tx $max_tx is over the cap of $CAP getTransaction calls; to allow more, raise AUDITOR_RPC_MAX_TX in the environment" ;;
  esac
  max_tx=$CAP
fi
cap AUDITOR_RPC_MAX_ADDRESSES 25
[ "${#addrs[@]}" -le "$CAP" ] ||
  confine_refuse "${#addrs[@]} addresses are over the cap of $CAP; to allow more, raise AUDITOR_RPC_MAX_ADDRESSES in the environment"

# --out: incident_<n>/corpus or incident_<n>/corpus-<k>, relative. The run directory
# is checked as a whole (scripts/lib/confine.sh: no link in it, untracked in any
# letter case, a .gitignore of "*"), and so is every directory on the way to --out.
out=${out#./}
while [ "${out%/}" != "$out" ]; do out=${out%/}; done
run_dir=${out%%/*}
corpus=${out#*/}
ok=0
case "$run_dir" in incident_*) ;; *) run_dir="" ;; esac
if [ -n "$run_dir" ] && [ "$run_dir" != "$out" ] && confine_rundir_name "$run_dir"; then
  case "$corpus" in
    corpus) ok=1 ;;
    corpus-*) case "${corpus#corpus-}" in ''|*[!0-9]*) ;; *) [ "${#corpus}" -le 11 ] && ok=1 ;; esac ;;
  esac
fi
[ "$ok" -eq 1 ] || confine_refuse "--out must be incident_<n>/corpus or incident_<n>/corpus-<k>, relative to the working directory: $(confine_text "$out")"
confine_rundir "$run_dir" "the run directory"
confine_path "$out" --out any
case "$CONFINE_TYPE" in file) confine_refuse "--out is not a directory: $(confine_text "$out")" ;; esac
confine_disclosures_ok "$run_dir" ||
  confine_refuse "$run_dir/disclosures.tsv is not a regular file of its own with the disclosure header, so the collection could not be recorded"
# A second pass into the same --out would mix into, or truncate, the first one's corpus.
for f in signatures.jsonl transactions.jsonl collection-gaps.tsv; do
  if [ -e "$out/$f" ] || [ -L "$out/$f" ]; then
    confine_refuse "$out already holds a collected corpus ($f); use a new --out (resume there with --before)"
  fi
done

for tool in curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[blocker] $tool is not on PATH; collect.sh needs curl and jq." >&2
    exit 3
  fi
done
# result_line: the JSON-RPC response on stdin -> its .result object as one compact
# line, every integer exact (EXACT INTEGERS above).
probe='{"result":{"n":[18446744073709551615,-9007199254740993]}}'
want='{"n":[18446744073709551615,-9007199254740993]}'
if [ "$(printf '%s' "$probe" | jq -c '.result' 2>/dev/null)" = "$want" ]; then
  result_line() { jq -c '.result'; }
else
  result_line() {
    python3 -I -c 'import json, sys
r = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace"))["result"]
if not isinstance(r, dict):
    sys.exit(1)
out = json.dumps(r, ensure_ascii=False, separators=(",", ":"))
sys.stdout.buffer.write(out.encode("utf-8", "backslashreplace") + b"\n")' 2>/dev/null
  }
  if [ "$(printf '%s' "$probe" | result_line)" != "$want" ]; then
    echo "[blocker] this jq rounds integers above 2^53 (jq < 1.7) and python3 -I is not available to write the corpus instead; install jq >= 1.7 or python3." >&2
    exit 3
  fi
fi

# mktemp -d creates the directory with mode 0700, before anything is written; curl's
# stderr, a copy of the signature list (written through descriptor 6) and the fetch
# list live there.
if confine_scratch dnr_collect; then
  tmp=$CONFINE_SCRATCH
elif [ $? -eq 2 ]; then
  echo "[blocker] cannot create a private temp directory: TMPDIR lies inside the working directory; set it to a directory outside the tree." >&2; exit 3
else
  echo "[blocker] cannot create a private temp directory." >&2; exit 3
fi
trap 'rm -rf "$tmp"' EXIT
errf="$tmp/stderr"; sig_copy="$tmp/signatures.jsonl"; todo="$tmp/signatures.todo"
exec 6>"$sig_copy"

if [ ! -d "$out" ]; then
  confine_mkdir "$out" || confine_refuse "cannot create $out"
fi
# The corpus files are created here (set -C: never over an existing file) and written
# only through these descriptors (3: signatures, 4: transactions, 5: gaps), never
# reopened by name.
sig_file="$out/signatures.jsonl"; tx_file="$out/transactions.jsonl"; gaps="$out/collection-gaps.tsv"
if ! { exec 3>"$sig_file" 4>"$tx_file" 5>"$gaps"; } 2>/dev/null; then
  confine_refuse "cannot create the corpus files in $out (it is not writable, or one of them appeared after the check); use a new --out"
fi
ngaps=0; gaps_whole=1; wfail=""
# say <text>: one line on stdout, or where the caller sends it, written by a subshell.
# Once the corpus files are open, every message goes through it: a write that fails
# (a reader that exited, a closed terminal) ends only that subshell, so it never stops
# the collection, and bash 3.2, which keeps the text of a failed write and flushes it
# with a later one, never carries that text into a corpus file.
say() { ( printf '%s\n' "$*" ) 2>/dev/null; }
# put <descriptor> <text>: <text> and a newline, written to an open descriptor by a
# subshell whose output is that descriptor, and that INT, TERM and HUP do not stop.
# Every write to the corpus, the gap file and the private copy goes through it: its
# status says whether the write succeeded, and the text of a write that failed ends
# with the subshell, never in another file.
put() { ( trap '' INT TERM HUP; printf '%s\n' "$2" ) >&"$1"; }

# Provider domain, for disclosure under OUTPUT-RULES.md Rule 11b: the host's last two
# DNS labels (an IP address, or a host of one or two labels, is kept whole), with no
# scheme, userinfo, path, query or fragment.
confine_service "$RPC_URL"
provider=$CONFINE_SERVICE
# Rule 11b: the row goes into incident_<n>/disclosures.tsv before the first call.
if ! confine_disclose "$run_dir" scripts/dnr/collect.sh "$provider" \
     "account addresses (getSignaturesForAddress, then getTransaction for their signatures)${before_start:+; before signature $before_start}" \
     "${addrs[@]}"; then
  echo "[blocker] cannot add the collection's row to $run_dir/disclosures.tsv, so nothing was sent; the corpus files in $out are empty: collect into a new --out once the file is fixed." >&2
  exit 3
fi
say "provider: $provider   (Rule 11b: this provider received the queried addresses)"
say "addresses: ${#addrs[@]}   window: since=$since until=$until before=${before_start:-<newest>}   caps: max_pages=$max_pages max_tx=$max_tx"

rpc() {  # rpc <method> <params-json> -> the whole JSON response on stdout; returns curl's status
  local rc
  rm -f "$errf"
  # -q comes first so no ~/.curlrc is read; the URL arrives on stdin, the body (no
  # secret in it) as --data-raw.
  printf 'url = "%s"\n' "$RPC_URL" | curl -q -K - -sS -m 60 -A auditor-skill-research -X POST \
    -H 'Content-Type: application/json' \
    --data-raw "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" 2>"$errf"
  rc=$?
  if [ -s "$errf" ]; then "$REDACT" <"$errf" >&2; fi
  return "$rc"
}
failure() {  # failure <curl status> <response> -> why the call returned no usable result
  local kind code
  if [ "$1" -ne 0 ]; then echo "transport error (curl exit $1)"; return; fi
  kind="$(printf '%s' "$2" | jq -r 'if type != "object" then "unreadable"
    elif has("error") then "error \(.error.code? // "")" elif .result == null then "null"
    else "unreadable" end' 2>/dev/null)"
  case "$kind" in
    error*) code="${kind#error}"; code="${code//[!0-9-]/}"; echo "RPC error${code:+ $code}" ;;
    null) echo "null result" ;;
    *) echo "unreadable response" ;;
  esac
}
# gap <signature or address> <reason>: one row per thing the corpus lacks. A row that
# cannot be written leaves the gap file incomplete: status 1.
gap() {
  if put 5 "$1$(printf '\t')$(printf '%s' "$2" | tr '\t\r\n' '   ')"; then
    ngaps=$((ngaps + 1))
  else
    gaps_whole=0; [ -n "$wfail" ] || wfail="collection-gaps.tsv"
    return 1
  fi
}
# fetch_list: the signatures to fetch, newest first, into $todo (step 2 below), from
# the first $collected lines of the private copy: the pages written whole to both.
fetch_list() {
  awk -v n="$collected" 'NR <= n' "$sig_copy" | jq -r --argjson s "$since" --argjson u "$until" '
    select(($s == 0) or ((.blockTime // 0) >= $s))
    | select(($u == 0) or ((.blockTime // 0) <= $u))
    | "\(.slot // 0) \(.signature)"' | sort -s -k1,1nr | awk '!seen[$2]++ { print $2 }' >| "$todo"
}
# cut_short <why> <exit status>: an INT, TERM or HUP, or a write that failed, ends
# the run here. What it had not finished becomes collection gaps: the address being
# paged and every address after it, and the signatures listed but not fetched (one
# row, naming the first). It writes every row, and computes every count, before it
# prints anything: its output may go to a pipe that is already closed, so SIGPIPE is
# ignored and a failed write comes last. Then it prints the closing lines and exits
# with the status given; once a write has failed, here or before, it prints a blocker
# instead of the closing lines and exits 3.
phase=paging; addrs_done=0; page=0; handled=0; fetched=0; calls=0; collected=0; total=0
said_collected=0; closed=0
cut_short() {
  local why="$1" k=0 a next first="" listed=1
  trap '' INT TERM HUP PIPE
  if [ "$phase" = paging ]; then
    for a in "${addrs[@]}"; do
      k=$((k + 1))
      if [ "$k" -eq $((addrs_done + 1)) ]; then
        gap "$a" "getSignaturesForAddress page $page: $why; older history not collected${before:+; resume into a new --out with --before $before}"
      elif [ "$k" -gt $((addrs_done + 1)) ]; then
        gap "$a" "not paged: $why"
      fi
    done
  fi
  if [ "$phase" = paging ] || [ "$phase" = listed ]; then
    if fetch_list; then
      total="$(grep -c . "$todo")"
    else
      listed=0; gaps_whole=0; [ -n "$wfail" ] || wfail="the private fetch list"
    fi
    handled=0
  fi
  case "$total" in ''|*[!0-9]*) total=0 ;; esac
  next=$((handled + 1))
  if [ "$phase" != done ] && [ "$listed" = 1 ]; then
    first="$(sed -n "${next}p" "$todo")"
    [ -z "$first" ] || gap "$first" "not fetched: $why; this and $((total - next)) older signatures in signatures.jsonl were not fetched"
  fi
  if [ -n "$wfail" ]; then
    if [ "$gaps_whole" = 1 ]; then
      say "[blocker] a write to $wfail failed (see the error above), so the run stopped, and the corpus in $out is incomplete: $gaps records what it had not collected. Fix the cause (a full disk, say), then collect the rest into a new --out." >&2
    else
      say "[blocker] a write to $wfail failed (see the error above), so the run stopped, and the corpus in $out is incomplete, and so is $gaps: record the gaps as for a run killed outright. Fix the cause (a full disk, say), then collect the rest into a new --out." >&2
    fi
    exit 3
  fi
  [ "$said_collected" = 1 ] || say "signatures collected: $collected -> $sig_file"
  [ -z "$first" ] || say "  ! $why: $((total - next + 1)) signatures listed in signatures.jsonl were not fetched — recorded as a collection gap" >&2
  [ "$closed" = 1 ] || close_run
  exit "$2"
}
# failed_write <name>: a write to <name> failed, so the run stops (exit 3).
failed_write() { [ -n "$wfail" ] || wfail="$1"; cut_short "a write to $1 failed" 3; }
# close_run: the closing lines.
close_run() {
  say "transactions fetched: $fetched of $calls calls -> $tx_file"
  say "collection gaps: $ngaps (see $gaps)"
}
trap 'cut_short "the run was interrupted (INT)" 130' INT
trap 'cut_short "the run was interrupted (TERM)" 143' TERM
trap 'cut_short "the run was interrupted (HUP)" 129' HUP

# 1. signature history, newest -> oldest, bounded by --since and --max-pages. An
#    empty page ends the address's history. A page shorter than the 1000 asked for
#    ends it only on the cap's last page: a node can return a short page before the
#    end, so paging goes on. A cap that stops paging on a full page, before --since
#    was crossed, may have left older history out.
for addr in "${addrs[@]}"; do
  before="$before_start"; page=0; oldest=0; ended=0
  while [ "$page" -lt "$max_pages" ]; do
    cfg="{\"limit\":1000,\"commitment\":\"finalized\"${before:+,\"before\":\"$before\"}}"
    resp="$(rpc getSignaturesForAddress "[\"$addr\",$cfg]")"; rc=$?
    if [ "$rc" -ne 0 ] || ! printf '%s' "$resp" | jq -e '.result | arrays' >/dev/null 2>&1; then
      reason="$(failure "$rc" "$resp")"
      say "  ! paging $addr (page $page) failed: $reason — recorded as a collection gap" >&2
      gap "$addr" "getSignaturesForAddress page $page: $reason; older history not collected" \
        || failed_write "collection-gaps.tsv"
      ended=1; break
    fi
    n="$(printf '%s' "$resp" | jq '.result | length')"
    if [ "$n" -gt 0 ]; then
      lines="$(printf '%s' "$resp" | jq -c --arg a "$addr" '.result[] | . + {queried_address:$a}')"
      # The private copy first, then signatures.jsonl: once both hold the page, it
      # counts as listed (fetch_list reads the first $collected lines of the copy).
      put 6 "$lines" || failed_write "the private copy of the signature list"
      put 3 "$lines" || failed_write "signatures.jsonl"
      collected=$((collected + n))
      before="$(printf '%s' "$resp" | jq -r '.result[-1].signature')"
      oldest="$(printf '%s' "$resp" | jq -r '.result[-1].blockTime // 0')"
    fi
    page=$((page + 1))
    if [ "$n" -eq 0 ]; then ended=1; break; fi
    if [ "$since" -gt 0 ] && [ "$oldest" -gt 0 ] && [ "$oldest" -lt "$since" ]; then ended=1; break; fi
    if [ "$n" -lt 1000 ] && [ "$page" -ge "$max_pages" ]; then ended=1; break; fi
  done
  if [ "$ended" -eq 0 ]; then
    if [ "$page" -eq 0 ]; then
      stop="--max-pages 0 fetched no page"
    else
      stop="the page cap (--max-pages $max_pages) stopped on a full page at blockTime $oldest"
      if [ "$since" -gt 0 ]; then
        stop="$stop, still after --since $since"
      elif [ "$until" -gt 0 ] && [ "$oldest" -gt "$until" ]; then
        stop="$stop, still after --until $until, so nothing inside the window was collected"
      fi
    fi
    resume="${before:+resume into a new --out with --before $before, or }raise --max-pages"
    say "  ! older history may exist for $addr: $stop — $resume; recorded as a collection gap" >&2
    gap "$addr" "older history may exist: $stop; $resume" || failed_write "collection-gaps.tsv"
  fi
  addrs_done=$((addrs_done + 1)); page=0; before="$before_start"
done
phase=listed
say "signatures collected: $collected -> $sig_file"
said_collected=1

# 2. unique signatures within [since, until] — failed ones included — newest first
#    across every address (slot, descending), so a --max-tx cap keeps the most recent
#    activity; a signature seen under two addresses is kept once, at its first place.
#    The sort is stable: within a slot the RPC's own newest-first order stands.
#    Read from the private copy of signatures.jsonl (fetch_list, above), and then
#    from a file (not a pipe) so the counters survive the loop.
fetch_list || failed_write "the private fetch list"
total="$(grep -c . "$todo")"
phase=fetching

# 3. fetch. Every getTransaction call counts against --max-tx, and max_failed calls
#    failing in a row stop the run: the endpoint is failing, and the rest would too.
max_failed=10
failed=0; i=0
while IFS= read -r sig; do
  [ -z "$sig" ] && continue
  i=$((i + 1))
  if [ "$failed" -ge "$max_failed" ]; then
    gap "$sig" "not fetched: stopped after $max_failed getTransaction calls in a row failed (last: $reason); this and $((total - i)) older signatures in signatures.jsonl were not fetched" \
      || failed_write "collection-gaps.tsv"
    handled=$total
    say "  ! stopped: $max_failed getTransaction calls in a row failed (last: $reason) — the endpoint is failing (rate limit or outage, or it does not serve this history); collected $fetched, collection gaps $ngaps; $((total - i + 1)) signatures not fetched — recorded as a collection gap" >&2
    break
  fi
  if [ "$calls" -ge "$max_tx" ]; then
    gap "$sig" "not fetched: --max-tx=$max_tx calls reached; this and $((total - i)) older signatures in signatures.jsonl were not fetched" \
      || failed_write "collection-gaps.tsv"
    handled=$total
    say "  ! reached --max-tx=$max_tx getTransaction calls; $((total - i + 1)) signatures not fetched — recorded as a collection gap" >&2
    break
  fi
  calls=$((calls + 1))
  resp="$(rpc getTransaction "[\"$sig\",{\"encoding\":\"jsonParsed\",\"maxSupportedTransactionVersion\":1,\"commitment\":\"finalized\"}]")"; rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$resp" | jq -e '.result | objects' >/dev/null 2>&1 \
     && line="$(printf '%s' "$resp" | result_line)" && [ -n "$line" ]; then
    put 4 "$line" || failed_write "transactions.jsonl"
    handled=$i; fetched=$((fetched + 1)); failed=0
  else
    reason="$(failure "$rc" "$resp")"
    gap "$sig" "getTransaction: $reason" || failed_write "collection-gaps.tsv"
    handled=$i; failed=$((failed + 1))
    say "  ! getTransaction failed for a signature: $reason — recorded as a collection gap" >&2
  fi
done < "$todo"
phase=done
close_run
closed=1
