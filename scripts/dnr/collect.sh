#!/usr/bin/env bash
# collect.sh — the ONE gated collector for the detection & response track. Pages
# signature history for one or more addresses and fetches each transaction, into a
# local JSONL corpus. It is the only script in the track that touches the network.
#
#   RPC_URL=https://<provider>/... \
#     collect.sh --out <dir> --confirmed [--since <unix>] [--until <unix>] \
#                [--max-pages N] [--max-tx N] -- <address> [<address> ...]
#
# GATING (do not relax — this is how "propose, never execute" stays true for the
# one networked step):
#   * REFUSES unless --confirmed is passed. `/auditor:hunt` and `/auditor:respond`
#     pass it only AFTER showing the human the addresses, the window, the caps and
#     the estimated call count, and getting a yes. A non-interactive run without
#     --confirmed exits 2.
#   * READ-ONLY RPC only: getSignaturesForAddress and getTransaction. Never a send,
#     a simulate, or any `surfnet_*`/write method.
#   * CAPPED: --max-pages (default 20 → <=20000 signatures/address) and --max-tx
#     (default 2000) bound the work and the spend. Raise them deliberately.
#
# SECRETS:
#   * The RPC endpoint comes from $RPC_URL and is NEVER echoed. All curl stderr is
#     piped through redact.sh. The corpus and the stdout "provider" line carry the
#     HOST ONLY, never the key.
#
# TRANSACTIONS are fetched jsonParsed, commitment finalized, with
# maxSupportedTransactionVersion:1 — mandatory, since v1 is live on mainnet and a
# v1 tx without the opt-in returns RPC error -32015 (verified against mainnet).
#
# bash >= 4 (associative dedup). git/jq/curl. Output: <dir>/signatures.jsonl and
# <dir>/transactions.jsonl.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDACT="$HERE/redact.sh"

out=""; confirmed=0; since=0; until=0; max_pages=20; max_tx=2000
addrs=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --confirmed) confirmed=1; shift ;;
    --since) since="$2"; shift 2 ;;
    --until) until="$2"; shift 2 ;;
    --max-pages) max_pages="$2"; shift 2 ;;
    --max-tx) max_tx="$2"; shift 2 ;;
    --) shift; addrs=("$@"); break ;;
    *) echo "collect.sh: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

if [[ "$confirmed" -ne 1 ]]; then
  echo "collect.sh: refusing — pass --confirmed (the command confirms addresses, window and caps with the human first)." >&2
  exit 2
fi
if [[ -z "$out" || ${#addrs[@]} -eq 0 ]]; then
  echo "usage: collect.sh --out <dir> --confirmed [--since U] [--until U] [--max-pages N] [--max-tx N] -- <address>..." >&2
  exit 2
fi
if [[ -z "${RPC_URL:-}" ]]; then
  echo "collect.sh: set \$RPC_URL (never passed on the command line, so it stays out of history and ledgers)." >&2
  exit 2
fi

mkdir -p "$out"
sig_file="$out/signatures.jsonl"; : > "$sig_file"
tx_file="$out/transactions.jsonl"; : > "$tx_file"

# Host only, for disclosure under Rule 11b. Strip scheme, path and any userinfo.
provider="$(printf '%s' "$RPC_URL" | sed -E 's#^[a-z]+://##; s#[/?].*$##; s#^[^@]*@##')"
echo "provider: $provider   (Rule 11b: this host received the queried addresses)"
echo "addresses: ${#addrs[@]}   window: since=$since until=$until   caps: max_pages=$max_pages max_tx=$max_tx"

rpc() {  # rpc <method> <params-json>  -> prints the whole JSON response
  curl -sS -m 60 -A auditor-skill-research -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" \
    "$RPC_URL" 2> >("$REDACT" >&2)
}

# 1. signature history, newest -> oldest, bounded by --since and --max-pages.
collected=0
for addr in "${addrs[@]}"; do
  before=""; page=0
  while (( page < max_pages )); do
    cfg="{\"limit\":1000,\"commitment\":\"finalized\"${before:+,\"before\":\"$before\"}}"
    resp="$(rpc getSignaturesForAddress "[\"$addr\",$cfg]")"
    if ! printf '%s' "$resp" | jq -e '.result' >/dev/null 2>&1; then
      echo "  ! RPC error paging $addr (page $page) — see redacted stderr; recorded as a collection gap" >&2
      break
    fi
    n="$(printf '%s' "$resp" | jq '.result | length')"
    (( n == 0 )) && break
    printf '%s' "$resp" | jq -c --arg a "$addr" '.result[] | . + {queried_address:$a}' >> "$sig_file"
    before="$(printf '%s' "$resp" | jq -r '.result[-1].signature')"
    oldest="$(printf '%s' "$resp" | jq -r '.result[-1].blockTime // 0')"
    page=$((page+1)); collected=$((collected+n))
    (( since > 0 && oldest > 0 && oldest < since )) && break
  done
done
echo "signatures collected: $collected -> $sig_file"

# 2. unique signatures within [since,until], capped, fetched as transactions.
declare -A seen
mapfile -t sigs < <(jq -r --argjson s "$since" --argjson u "$until" '
  select(.err == null)
  | select(($s == 0) or ((.blockTime // 0) >= $s))
  | select(($u == 0) or ((.blockTime // 0) <= $u))
  | .signature' "$sig_file")

fetched=0
for sig in "${sigs[@]}"; do
  [[ -n "${seen[$sig]:-}" ]] && continue
  seen[$sig]=1
  (( fetched >= max_tx )) && { echo "  reached --max-tx=$max_tx; stopping (record remaining as a gap)"; break; }
  resp="$(rpc getTransaction "[\"$sig\",{\"encoding\":\"jsonParsed\",\"maxSupportedTransactionVersion\":1,\"commitment\":\"finalized\"}]")"
  if printf '%s' "$resp" | jq -e '.result' >/dev/null 2>&1; then
    printf '%s' "$resp" | jq -c '.result' >> "$tx_file"
    fetched=$((fetched+1))
  else
    echo "  ! getTransaction failed for a signature — recorded as a collection gap" >&2
  fi
done
echo "transactions fetched: $fetched -> $tx_file"
