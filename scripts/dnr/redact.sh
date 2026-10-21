#!/usr/bin/env bash
# redact.sh — a stderr/stdout filter that strips provider credentials from text
# before it reaches the transcript, a ledger, or a report.
#
# Why this exists: a read-only RPC call can still leak its key. `solana ... --url
# "https://x.rpc/?api-key=SECRET"` echoes the full URL (key included) in its own
# error text, and provider URLs routinely carry the key in the path or query. Pipe
# any command that may print a URL through this filter:
#
#     some-cmd 2> >("$(dirname "$0")/redact.sh" >&2)
#     some-cmd 2>&1 | "$(dirname "$0")/redact.sh"
#
# It is a convenience, not a guarantee (a novel key format slips through), so the
# real rule still holds: never put an RPC URL in INCIDENTS.json, LEDGER.md, or any
# output. Record only the provider's host, and the literal string "$RPC_URL".
#
# Pure sed. bash >= 3.2, no network.

set -uo pipefail

sed -E \
  -e 's/([?&](api[-_]?key|apikey|access[-_]?token|token|key|secret|auth)=)[^[:space:]&"'\''`]+/\1REDACTED/gI' \
  -e 's#(https?://[^[:space:]/"'\''`]*:)[^@[:space:]/"'\''`]+@#\1REDACTED@#g' \
  -e 's#(https?://[A-Za-z0-9._-]*[?/])[A-Za-z0-9_-]{24,}#\1REDACTED#g'
