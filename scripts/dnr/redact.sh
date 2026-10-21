#!/usr/bin/env bash
# redact.sh — a filter that strips provider credentials from text before it reaches
# the transcript, a ledger, or a report.
#
# Why this exists: a read-only RPC call can still leak its key. `solana ... --url
# "https://x.rpc/?api-key=SECRET"` echoes the full URL (key included) in its own
# error text, and providers put the key in the query (`?api-key=`), in a path
# segment (`/v2/<key>`, `/solana/<key>`), or in userinfo (`user:key@host`).
#
# Usage: capture the output to a file first, then filter it. Process substitution
# (`2> >(...)`) is not used anywhere in this track: it needs /dev/fd, which some
# sandboxes deny.
#
#     err="$(mktemp)"; some-cmd 2>"$err"; bash "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/redact.sh" <"$err" >&2; rm -f "$err"
#     some-cmd 2>&1 | bash "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/redact.sh"
#
# Always the installation's copy, never a relative scripts/ path: the audited repo
# may ship a same-named file.
#
# What it does to a URL: keeps the scheme and host, replaces userinfo with
# REDACTED@, and replaces everything after the host (path and query) with
# /REDACTED. A trailing ')' or quote that merely ends the URL in prose is kept.
# A bare `api-key=VALUE` outside a URL is also redacted.
#
# It is a convenience, not a guarantee (a novel key format can slip through), so the
# rule still holds: never put an RPC URL in INCIDENTS.json, LEDGER.md, or any
# output. Record the provider host and the literal string "$RPC_URL".
#
# Portability: POSIX ERE via `sed -E` only — bracket classes, `?`/`+`/`*`, groups and
# `\1` backreferences, the `g` flag. No GNU-only extensions and no case-insensitive
# flag, so BSD and GNU sed read these expressions the same way. bash >= 3.2.

set -uo pipefail

q="'"
# Characters that end a URL or a key in surrounding text: whitespace, quotes,
# backtick, closing paren.
end="[:space:]\"${q}\`)"

sed -E \
  -e "s#(https?://)[^@/?${end}]*@#\\1REDACTED@#g" \
  -e "s#(https?://[^/?${end}]+)[/?][^${end}]*#\\1/REDACTED#g" \
  -e "s/((api[-_]?key|apikey|access[-_]?token|token|secret|auth)=)[^&${end}]+/\\1REDACTED/g"
