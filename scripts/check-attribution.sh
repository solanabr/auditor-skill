#!/usr/bin/env bash
# check-attribution.sh — fail if any commit in RANGE carries an AI-attribution trailer.
# Usage: bash scripts/check-attribution.sh "origin/main..HEAD"
# Same pattern as scripts/hooks/commit-msg, applied to a commit range (used by CI on pull requests).
# A range git cannot read, or one that holds no commits, fails: there is nothing to vouch for.
set -uo pipefail
range=${1:-"origin/main..HEAD"}
pattern='^(Co-Authored-By: .*(Claude|Anthropic|noreply@anthropic\.com))|(Generated with .*Claude)|(🤖 Generated)'

case "$range" in -*) echo "::error::'$range' is not a commit range" >&2; exit 1 ;; esac
commits=$(git rev-list "$range" --) || { echo "::error::cannot read the commit range '$range'" >&2; exit 1; }
[[ -n "$commits" ]] || { echo "::error::the commit range '$range' holds no commits" >&2; exit 1; }

bad=0
while read -r sha; do
  msg=$(git -c log.showSignature=false log -1 --format=%B "$sha") \
    || { echo "::error::cannot read the message of commit $sha" >&2; bad=1; continue; }
  # count the matches: grep -c reads the whole message, however long, so nothing ends the pipe early
  n=$(printf '%s\n' "$msg" | grep -ciE "$pattern")
  if [[ "${n:-0}" -gt 0 ]]; then
    echo "::error::commit $sha carries an AI-attribution trailer — remove it (see CONTRIBUTING.md §1)" >&2
    bad=1
  fi
done <<< "$commits"

if [[ $bad -ne 0 ]]; then exit 1; fi
echo "attribution check passed for $range ($(printf '%s\n' "$commits" | wc -l | tr -d ' ') commits)"
