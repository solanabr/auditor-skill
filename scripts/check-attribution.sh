#!/usr/bin/env bash
# check-attribution.sh — fail if any commit in RANGE carries an AI-attribution trailer, or names an AI
# assistant as its author or committer.
# Usage: bash scripts/check-attribution.sh "origin/main..HEAD"
# Same pattern and unfolding as scripts/hooks/commit-msg, applied to a commit range (used by CI on pull
# requests): any spacing around the colon of "Co-Authored-By:", and a trailer folded onto the next line, as git
# reads trailers. An author or committer named Claude, Claude Code or Anthropic, or with the email
# noreply@anthropic.com, fails too, in any letter case.
# A range git cannot read, or one that holds no commits, fails: there is nothing to vouch for.
set -uo pipefail
range=${1:-"origin/main..HEAD"}
pattern='^(Co-Authored-By[[:space:]]*:.*(Claude|Anthropic|noreply@anthropic\.com))|(Generated with .*Claude)|(🤖 Generated)'
# a line that starts with a space or a tab continues the one before it, as in a git trailer
unfold='NR > 1 && /^[ \t]/ { sub(/^[ \t]+/, " "); line = line $0; next } NR > 1 { print line } { line = $0 } END { if (NR) print line }'
ident='^(Claude|Claude Code|Anthropic) <|<noreply@anthropic\.com>'

case "$range" in -*) echo "::error::'$range' is not a commit range" >&2; exit 1 ;; esac
commits=$(git rev-list "$range" --) || { echo "::error::cannot read the commit range '$range'" >&2; exit 1; }
[[ -n "$commits" ]] || { echo "::error::the commit range '$range' holds no commits" >&2; exit 1; }

bad=0
while read -r sha; do
  msg=$(git -c log.showSignature=false log -1 --format=%B "$sha") \
    || { echo "::error::cannot read the message of commit $sha" >&2; bad=1; continue; }
  # count the matches: grep -c reads the whole message, however long, so nothing ends the pipe early
  n=$(printf '%s\n' "$msg" | awk "$unfold" | grep -ciE "$pattern")
  if [[ "${n:-0}" -gt 0 ]]; then
    echo "::error::commit $sha carries an AI-attribution trailer — remove it (see CONTRIBUTING.md §1)" >&2
    bad=1
  fi
  who=$(git -c log.showSignature=false log -1 --format='%an <%ae>%n%cn <%ce>' "$sha") \
    || { echo "::error::cannot read the author of commit $sha" >&2; bad=1; continue; }
  n=$(printf '%s\n' "$who" | grep -ciE "$ident")
  if [[ "${n:-0}" -gt 0 ]]; then
    echo "::error::commit $sha names an AI assistant as its author or committer — commit as yourself (see CONTRIBUTING.md §1)" >&2
    bad=1
  fi
done <<< "$commits"

if [[ $bad -ne 0 ]]; then exit 1; fi
echo "attribution check passed for $range ($(printf '%s\n' "$commits" | wc -l | tr -d ' ') commits)"
