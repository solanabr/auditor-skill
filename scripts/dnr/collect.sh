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
#   * CAPPED: --max-pages (default 20 → up to 20000 signatures per address) and
#     --max-tx (default 2000) bound the work and the spend. Raise them deliberately.
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
# before anything is written or sent. When the page cap stops paging before
# --since was reached — or, with only --until set, while still above --until — the
# script says so ("window not reached"): the corpus is then incomplete for that
# address, a collection gap to record in the ledger. Signatures are fetched newest
# first (by slot, across all addresses), so --max-tx drops the oldest.
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
# bash >= 3.2, curl, jq. Output: <dir>/signatures.jsonl, <dir>/transactions.jsonl.

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
  if [ -d "$1" ] && [ -n "$(find "$1" -type l -print 2>/dev/null | sed -n 1p)" ]; then
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

rpc() {  # rpc <method> <params-json> -> the whole JSON response on stdout
  : > "$errf"
  # -q comes first so no ~/.curlrc is read; the URL arrives on stdin, the body (no
  # secret in it) as --data-raw.
  printf 'url = "%s"\n' "$RPC_URL" | curl -q -K - -sS -m 60 -A auditor-skill-research -X POST \
    -H 'Content-Type: application/json' \
    --data-raw "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" 2>"$errf"
  if [ -s "$errf" ]; then "$REDACT" <"$errf" >&2; fi
}

# 1. signature history, newest -> oldest, bounded by --since and --max-pages.
collected=0
for addr in "${addrs[@]}"; do
  before="$before_start"; page=0; oldest=0; reached=0
  while [ "$page" -lt "$max_pages" ]; do
    cfg="{\"limit\":1000,\"commitment\":\"finalized\"${before:+,\"before\":\"$before\"}}"
    resp="$(rpc getSignaturesForAddress "[\"$addr\",$cfg]")"
    if ! printf '%s' "$resp" | jq -e '.result' >/dev/null 2>&1; then
      echo "  ! RPC error paging $addr (page $page) — recorded as a collection gap" >&2
      reached=1; break
    fi
    n="$(printf '%s' "$resp" | jq '.result | length')"
    if [ "$n" -eq 0 ]; then reached=1; break; fi
    printf '%s' "$resp" | jq -c --arg a "$addr" '.result[] | . + {queried_address:$a}' >> "$sig_file"
    before="$(printf '%s' "$resp" | jq -r '.result[-1].signature')"
    oldest="$(printf '%s' "$resp" | jq -r '.result[-1].blockTime // 0')"
    page=$((page + 1)); collected=$((collected + n))
    if [ "$since" -gt 0 ] && [ "$oldest" -gt 0 ] && [ "$oldest" -lt "$since" ]; then reached=1; break; fi
  done
  if [ "$reached" -eq 0 ] && [ "$since" -gt 0 ]; then
    echo "  ! window not reached for $addr (oldest=$oldest, since=$since): page cap hit — resume into a new --out with --before $before, or raise --max-pages; record as a collection gap" >&2
  elif [ "$reached" -eq 0 ] && [ "$until" -gt 0 ] && [ "$oldest" -gt "$until" ]; then
    echo "  ! window not reached for $addr (oldest=$oldest, until=$until): the page cap stopped paging above --until, so nothing inside the window was collected — resume into a new --out with --before $before, or raise --max-pages; record as a collection gap" >&2
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

fetched=0
while IFS= read -r sig; do
  [ -z "$sig" ] && continue
  if [ "$fetched" -ge "$max_tx" ]; then
    echo "  ! reached --max-tx=$max_tx; remaining signatures not fetched — record as a collection gap" >&2
    break
  fi
  resp="$(rpc getTransaction "[\"$sig\",{\"encoding\":\"jsonParsed\",\"maxSupportedTransactionVersion\":1,\"commitment\":\"finalized\"}]")"
  if printf '%s' "$resp" | jq -e '.result' >/dev/null 2>&1; then
    printf '%s' "$resp" | jq -c '.result' >> "$tx_file"
    fetched=$((fetched + 1))
  else
    echo "  ! getTransaction failed for a signature — recorded as a collection gap" >&2
  fi
done < "$todo"
echo "transactions fetched: $fetched -> $tx_file"
