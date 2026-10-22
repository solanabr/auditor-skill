#!/usr/bin/env bash
# collect.sh — the ONE gated collector for the detection & response track. Pages
# signature history for one or more addresses and fetches each transaction, into a
# local JSONL corpus. Besides snapshot-program.sh (one program account, via the
# solana CLI), it is the only recipe in the track that touches the network.
#
#   bash "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/collect.sh" --out <dir> --confirmed \
#        [--since <unix>] [--until <unix>] [--before <signature>] \
#        [--max-pages N] [--max-tx N] -- <address> [<address> ...]
#
# $RPC_URL must already be exported; never type the URL on the command line. Run it
# from the installation, never as a relative scripts/ path: the audited repo may
# ship a same-named file.
#
# GATING (do not relax — this is how "plans only, no actions" stays true for the
# corpus collection):
#   * REFUSES unless --confirmed is passed. `/auditor:hunt` and `/auditor:respond`
#     pass it only AFTER showing the human the addresses, the window, the caps and
#     the estimated call count, and getting a yes. Without it the script exits 2
#     before any network call.
#   * READ-ONLY RPC only: getSignaturesForAddress and getTransaction. Never a send,
#     a simulate, or a write method.
#   * CAPPED: --max-pages (default 20; a page is one getSignaturesForAddress call of
#     up to 1000 signatures, per address) and --max-tx (default 2000 getTransaction
#     CALLS, failed ones included) bound the work and the spend, so a run makes at
#     most addresses x max-pages + max-tx calls. After 10 getTransaction calls in a
#     row fail (a rate limit or an outage), the run stops fetching and says so.
#     Raise the caps deliberately.
#
# WHAT IS KEPT: every signature in the window, FAILED ones included. A failed
# transaction moves no state, but it is evidence of an attempt — probing before a
# success, or a `suspected` incident whose attack has not landed yet. Filtering
# failures out would make those undetectable. Use `meta.err` downstream.
#
# RUN DIRECTORY: --out, and the nearest incident_* directory at or above it, must be
# a directory this run may write into. Either one that is a symbolic link, holds a
# symbolic link, or is tracked by git is refused with exit 2 before anything is
# written or sent.
#
# --before <sig> starts paging just older than that signature (resume a capped run,
# or skip activity newer than the incident) — always into a new --out: an --out that
# already holds signatures is refused, so a resume never erases the first pass. Every
# address and --before value must be base58, and every number a plain integer,
# before anything is written or sent. Paging an address ends when its history does
# (a page shorter than 1000) or once --since is crossed; when --max-pages stops it
# first, with a full last page, the history is truncated and the script says so
# ("truncated by --max-pages", with the --before cursor that resumes it): a
# collection gap to record in the ledger. Signatures are fetched newest first (by
# slot, across all addresses), so --max-tx drops the oldest.
#
# COLLECTION GAPS: every gap is also a row of <dir>/collection-gaps.tsv,
# `<signature or address><TAB><reason>`: a getTransaction that failed (transport
# error, RPC error or null result), a signature page that failed, a history truncated
# by --max-pages, the --max-tx cap, and a stop after consecutive failures. The run
# ends with
# "collection gaps: N (see <dir>/collection-gaps.tsv)". Gaps leave the exit status
# at 0; copy each row into LEDGER.md and INCIDENTS.json `collection_gaps`.
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
# mainnet and a v1 fetch without the opt-in returns RPC error -32015. Each one is
# written to the corpus by `python3 -I`, never re-encoded by jq: jq before 1.7 turns
# every number into a double, which rounds lamport balances and other u64 fields
# above 2^53.
#
# bash >= 3.2, curl, jq, python3. Output: <dir>/signatures.jsonl,
# <dir>/transactions.jsonl, <dir>/collection-gaps.tsv.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDACT="$HERE/redact.sh"

out=""; confirmed=0; since=0; until=0; before_start=""; max_pages=20; max_tx=2000
addrs=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --confirmed) confirmed=1; shift ;;
    --since) since="$2"; shift 2 ;;
    --until) until="$2"; shift 2 ;;
    --before) before_start="$2"; shift 2 ;;
    --max-pages) max_pages="$2"; shift 2 ;;
    --max-tx) max_tx="$2"; shift 2 ;;
    --) shift; addrs=("$@"); break ;;
    *) echo "collect.sh: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

if [ "$confirmed" -ne 1 ]; then
  echo "collect.sh: refusing — pass --confirmed (the command confirms addresses, window and caps with the human first)." >&2
  exit 2
fi
if [ -z "$out" ] || [ ${#addrs[@]} -eq 0 ]; then
  echo "usage: collect.sh --out <dir> --confirmed [--since U] [--until U] [--before SIG] [--max-pages N] [--max-tx N] -- <address>..." >&2
  exit 2
fi
if [ -z "${RPC_URL:-}" ]; then
  echo "collect.sh: set \$RPC_URL in the environment (never on the command line, so it stays out of history and ledgers)." >&2
  exit 2
fi
# The URL goes into a quoted curl config line: refuse what could end or escape it.
case "$RPC_URL" in
  *[[:space:][:cntrl:]\"\\]*)
    echo "collect.sh: \$RPC_URL holds a quote, a backslash, whitespace or a control character; refusing it." >&2
    exit 2 ;;
esac
# Addresses and --before are spliced into JSON request bodies and usually come from
# target content (declare_id!, Anchor.toml): accept base58 only.
for addr in "${addrs[@]}"; do
  if ! [[ "$addr" =~ ^[1-9A-HJ-NP-Za-km-z]{32,44}$ ]]; then
    echo "collect.sh: '$addr' is not a base58 address (32-44 characters of [1-9A-HJ-NP-Za-km-z])." >&2
    exit 2
  fi
done
if [ -n "$before_start" ] && ! [[ "$before_start" =~ ^[1-9A-HJ-NP-Za-km-z]{32,88}$ ]]; then
  echo "collect.sh: --before '$before_start' is not a base58 signature." >&2
  exit 2
fi
for n in "$since" "$until" "$max_pages" "$max_tx"; do
  if ! [[ "$n" =~ ^[0-9]+$ ]]; then
    echo "collect.sh: '$n' is not a non-negative integer (--since, --until, --max-pages, --max-tx)." >&2
    exit 2
  fi
done
for tool in curl jq python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "collect.sh: $tool is not on PATH." >&2; exit 2; }
done
case "$out" in */) out="${out%"${out##*[!/]}"}"; [ -n "$out" ] || out=/ ;; esac

# refuse_planted <dir>: exit 2 unless <dir> is safe to write into — not a symbolic
# link, holding none, and not tracked by git. The git calls carry the Rule 11c flags,
# because the tree is usually the audited one. Outside a work tree nothing is tracked;
# inside one, a path git cannot classify is refused.
refuse_planted() {
  local listed
  if [ -L "$1" ]; then
    echo "${0##*/}: refusing $1: it is a symbolic link — use a new run directory." >&2; exit 2
  fi
  if [ -d "$1" ] && [ -n "$(find "$1" -type l -print -quit 2>/dev/null)" ]; then
    echo "${0##*/}: refusing $1: it contains a symbolic link — use a new run directory." >&2; exit 2
  fi
  [ -d "$(dirname "$1")" ] || return 0
  [ "$(git --no-pager -c core.fsmonitor=false -c log.showSignature=false -C "$(dirname "$1")" \
        rev-parse --is-inside-work-tree 2>/dev/null)" = true ] || return 0
  if ! listed="$(git --no-pager -c core.fsmonitor=false -c log.showSignature=false -C "$(dirname "$1")" \
        ls-files -- ":(literal,icase)$(basename "$1")" 2>/dev/null)"; then
    echo "${0##*/}: refusing $1: git cannot tell whether it is tracked." >&2; exit 2
  fi
  if [ -n "$listed" ]; then
    echo "${0##*/}: refusing $1: git tracks it, so it is not a run directory to write into." >&2; exit 2
  fi
  return 0
}
# --out, and the nearest incident_* directory above it, checked as a whole.
refuse_planted "$out"
run_dir="$out"
while :; do
  case "$(basename "$run_dir")" in incident_*) [ "$run_dir" = "$out" ] || refuse_planted "$run_dir"; break ;; esac
  case "$run_dir" in .|/) break ;; esac
  run_dir="$(dirname "$run_dir")"
done
# A second pass into the same --out would truncate the first one's corpus.
if [ -s "$out/signatures.jsonl" ]; then
  echo "collect.sh: $out already holds a collected corpus — use a new --out (resume there with --before)." >&2
  exit 2
fi

mkdir -p "$out" || exit 2
# Rule 11d: an incident_<n>/ directory (the --out itself or its parent) ignores itself
# when it has no .gitignore of its own, so the corpus never shows in git status.
for d in "$out" "$(dirname "$out")"; do
  case "$(basename "$d")" in
    incident_*) [ -e "$d/.gitignore" ] || printf '*\n' > "$d/.gitignore" ;;
  esac
done
sig_file="$out/signatures.jsonl"; : > "$sig_file"
tx_file="$out/transactions.jsonl"; : > "$tx_file"
gaps="$out/collection-gaps.tsv"; : > "$gaps"; ngaps=0
todo="$out/.signatures.todo"
errf="$(mktemp "${TMPDIR:-/tmp}/dnr_collect.XXXXXX")"
trap 'rm -f "$errf" "$todo"' EXIT

# Provider domain, for disclosure under OUTPUT-RULES.md Rule 11b: strip the scheme,
# any userinfo, path, query and fragment, then keep the host's last two DNS labels (an
# IP address, or a host of one or two labels, is kept whole).
provider="$(printf '%s' "$RPC_URL" | sed -E -e 's|^[A-Za-z][A-Za-z0-9+.-]*://||' -e 's|^[^/?#]*@||' \
  -e 's|[/?#].*$||' -e 's|^.*\.([^.]+\.[A-Za-z][^.:]*)\.?(:[0-9]*)?$|\1\2|')"
echo "provider: $provider   (Rule 11b: this provider received the queried addresses)"
echo "addresses: ${#addrs[@]}   window: since=$since until=$until before=${before_start:-<newest>}   caps: max_pages=$max_pages max_tx=$max_tx"

rpc() {  # rpc <method> <params-json> -> the whole JSON response on stdout; returns curl's status
  local rc
  : > "$errf"
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
# A getTransaction response goes to the corpus through python3 -I, whose json keeps
# integers exact (jq before 1.7 rounds every number above 2^53). Exit 0: the result
# object was appended to the file in argv[1] as one compact line. Exit 1: it printed
# why the response holds no transaction.
TX_PY='import json, sys
try:
    r = json.loads(sys.stdin.buffer.read())
except ValueError:
    r = None
if not isinstance(r, dict):
    print("unreadable response"); sys.exit(1)
res = r.get("result")
if isinstance(res, dict):
    with open(sys.argv[1], "a", encoding="utf-8") as f:
        f.write(json.dumps(res, separators=(",", ":")) + "\n")
    sys.exit(0)
if "error" in r:
    e = r["error"]
    c = e.get("code") if isinstance(e, dict) else None
    print("RPC error %d" % c if type(c) is int else "RPC error")
elif res is None:
    print("null result")
else:
    print("unreadable response")
sys.exit(1)'
gap() {  # gap <signature or address> <reason>: one row per thing the corpus lacks
  printf '%s\t%s\n' "$1" "$(printf '%s' "$2" | tr '\t\r\n' '   ')" >> "$gaps"
  ngaps=$((ngaps + 1))
}

# 1. signature history, newest -> oldest, one page of up to $LIMIT per call. Paging an
#    address ends with its history (a page shorter than $LIMIT), once --since is
#    crossed, or on a failed page; --max-pages stopping it after a full page leaves
#    older history uncollected, which is reported with the cursor that resumes it.
LIMIT=1000
collected=0
for addr in "${addrs[@]}"; do
  before="$before_start"; page=0; oldest=0; got=0; ended=0
  while [ "$page" -lt "$max_pages" ]; do
    cfg="{\"limit\":$LIMIT,\"commitment\":\"finalized\"${before:+,\"before\":\"$before\"}}"
    resp="$(rpc getSignaturesForAddress "[\"$addr\",$cfg]")"; rc=$?
    if [ "$rc" -ne 0 ] || ! printf '%s' "$resp" | jq -e '.result | arrays' >/dev/null 2>&1; then
      reason="$(failure "$rc" "$resp")"
      echo "  ! paging $addr (page $page) failed: $reason — recorded as a collection gap" >&2
      gap "$addr" "getSignaturesForAddress page $page: $reason; older history not collected"
      ended=1; break
    fi
    n="$(printf '%s' "$resp" | jq '.result | length')"
    page=$((page + 1))
    if [ "$n" -gt 0 ]; then
      printf '%s' "$resp" | jq -c --arg a "$addr" '.result[] | . + {queried_address:$a}' >> "$sig_file"
      before="$(printf '%s' "$resp" | jq -r '.result[-1].signature')"
      oldest="$(printf '%s' "$resp" | jq -r '.result[-1].blockTime // 0')"
      got=$((got + n)); collected=$((collected + n))
    fi
    if [ "$n" -lt "$LIMIT" ]; then ended=1; break; fi
    if [ "$since" -gt 0 ] && [ "$oldest" -gt 0 ] && [ "$oldest" -lt "$since" ]; then ended=1; break; fi
  done
  if [ "$ended" -eq 0 ]; then
    resume="resume into a new --out with --before $before"
    [ -n "$before" ] || resume="raise --max-pages"
    inside=""
    if [ "$until" -gt 0 ] && [ "$oldest" -gt "$until" ]; then inside=", so nothing at or before --until $until was collected"; fi
    echo "  ! history of $addr truncated by --max-pages=$max_pages after $got signatures (oldest blockTime $oldest)$inside — $resume; recorded as a collection gap" >&2
    gap "$addr" "history truncated by --max-pages=$max_pages after $got signatures (oldest blockTime $oldest)$inside; $resume"
  fi
done
echo "signatures collected: $collected -> $sig_file"

# 2. unique signatures within [since, until] — failed ones included — newest first
#    across every address (slot, descending), so a --max-tx cap keeps the most recent
#    activity; a signature seen under two addresses is kept once, at its first place.
#    Read from a file (not a pipe) so the counter survives the loop.
jq -r --argjson s "$since" --argjson u "$until" '
  select(($s == 0) or ((.blockTime // 0) >= $s))
  | select(($u == 0) or ((.blockTime // 0) <= $u))
  | "\(.slot // 0) \(.signature)"' "$sig_file" | sort -k1,1nr | awk '!seen[$2]++ { print $2 }' > "$todo"

# 3. one getTransaction call per signature. --max-tx counts calls, failed ones
#    included; MAX_FAILS calls failing in a row (a rate limit or an outage) stop the
#    run, since every further call would fail the same way.
MAX_FAILS=10
calls=0; fetched=0; streak=0; total="$(grep -c . "$todo")"; i=0
while IFS= read -r sig; do
  [ -z "$sig" ] && continue
  i=$((i + 1))
  if [ "$calls" -ge "$max_tx" ]; then
    echo "  ! reached --max-tx=$max_tx getTransaction calls; $((total - i + 1)) signatures not fetched — recorded as a collection gap" >&2
    gap "$sig" "not fetched: --max-tx=$max_tx calls reached; this and $((total - i)) older signatures in signatures.jsonl were not fetched"
    break
  fi
  if [ "$streak" -ge "$MAX_FAILS" ]; then
    gap "$sig" "not fetched: $MAX_FAILS getTransaction calls in a row failed (rate limit or outage); this and $((total - i)) older signatures in signatures.jsonl were not fetched"
    echo "  ! endpoint failing (rate limit or outage): $MAX_FAILS getTransaction calls in a row failed, so the run stops — $fetched transactions collected, $ngaps collection gaps" >&2
    break
  fi
  calls=$((calls + 1))
  resp="$(rpc getTransaction "[\"$sig\",{\"encoding\":\"jsonParsed\",\"maxSupportedTransactionVersion\":1,\"commitment\":\"finalized\"}]")"; rc=$?
  if [ "$rc" -ne 0 ]; then
    reason="transport error (curl exit $rc)"
  elif reason="$(printf '%s' "$resp" | python3 -I -c "$TX_PY" "$tx_file")"; then
    fetched=$((fetched + 1)); streak=0; continue
  fi
  streak=$((streak + 1))
  echo "  ! getTransaction failed for a signature: $reason — recorded as a collection gap" >&2
  gap "$sig" "getTransaction: $reason"
done < "$todo"
echo "transactions fetched: $fetched of $calls calls -> $tx_file"
echo "collection gaps: $ngaps (see $gaps)"
