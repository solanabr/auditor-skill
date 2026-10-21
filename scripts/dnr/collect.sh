#!/usr/bin/env bash
# collect.sh — the ONE gated collector for the detection & response track. Pages
# signature history for one or more addresses and fetches each transaction, into a
# local JSONL corpus. It is the only recipe in the track that touches the network.
#
#   RPC_URL=https://<provider>/... \
#     collect.sh --out <dir> --confirmed [--since <unix>] [--until <unix>] \
#                [--before <signature>] [--max-pages N] [--max-tx N] \
#                -- <address> [<address> ...]
#
# GATING (do not relax — this is how "plans only, no actions" stays true for the
# one networked step):
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
# --before <sig> starts paging just older than that signature (resume a capped run,
# or skip activity newer than the incident). When the page cap stops paging before
# --since was reached, the script says so ("window not reached") — the corpus is
# then incomplete for that address, a collection gap to record in the ledger.
#
# SECRETS: the endpoint comes from $RPC_URL and is NEVER echoed. curl's stderr is
# captured to a temp file and passed through redact.sh. Output files and the
# "provider" line carry the HOST only.
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

mkdir -p "$out"
sig_file="$out/signatures.jsonl"; : > "$sig_file"
tx_file="$out/transactions.jsonl"; : > "$tx_file"
todo="$out/.signatures.todo"
errf="$(mktemp "${TMPDIR:-/tmp}/dnr_collect.XXXXXX")"
trap 'rm -f "$errf" "$todo"' EXIT

# Host only, for disclosure under OUTPUT-RULES.md Rule 11b. Strip scheme, path and
# any userinfo.
provider="$(printf '%s' "$RPC_URL" | sed -E 's#^[a-zA-Z]+://##; s#[/?].*$##; s#^[^@]*@##')"
echo "provider: $provider   (Rule 11b: this host received the queried addresses)"
echo "addresses: ${#addrs[@]}   window: since=$since until=$until before=${before_start:-<newest>}   caps: max_pages=$max_pages max_tx=$max_tx"

rpc() {  # rpc <method> <params-json> -> the whole JSON response on stdout
  : > "$errf"
  curl -sS -m 60 -A auditor-skill-research -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" \
    "$RPC_URL" 2>"$errf"
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
    echo "  ! window not reached for $addr (oldest=$oldest, since=$since): page cap hit — resume with --before $before, or raise --max-pages; record as a collection gap" >&2
  fi
done
echo "signatures collected: $collected -> $sig_file"

# 2. unique signatures within [since, until] — failed ones included — capped, then
#    fetched as transactions. Dedup with sort -u; read from a file (not a pipe) so
#    the counter survives the loop.
jq -r --argjson s "$since" --argjson u "$until" '
  select(($s == 0) or ((.blockTime // 0) >= $s))
  | select(($u == 0) or ((.blockTime // 0) <= $u))
  | .signature' "$sig_file" | sort -u > "$todo"

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
