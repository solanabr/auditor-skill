#!/usr/bin/env bash
# tob-delta-pr.sh — the upstream delta of a pull request that moves the vendor/trailofbits gitlink, as Markdown
# for the PR's job summary (.github/workflows/vendor-delta.yml). Prints it to stdout. The summary counts only for
# a PR that changes nothing but the gitlink and the README pin line (CONTRIBUTING.md §5, "Bumping
# vendor/trailofbits"): its first line says so, and its second whether this PR changes other files.
#
# Usage: bash scripts/tob-delta-pr.sh <base> <head>
#   <base> <head>  commits of the repository in the current directory: the PR's base and the commit CI checks
#                  out. A pull_request run checks out the PR's merge commit, whose first parent is the base,
#                  so the workflow passes HEAD^1 HEAD.
#
# The move and the other paths come from git diff-tree --raw between the two commits with
# --ignore-submodules=none, so neither the config nor the checked-out .gitmodules hides a gitlink. The upstream
# is the https://github.com/trailofbits/skills entry of SUBMODULE_URLS in <base>'s scripts/check-corpus.sh,
# never a URL from .gitmodules. Its default branch (HEAD), branches and tags are fetched by name into a temp dir,
# never a commit by its SHA, so a commit that none of them reaches, such as one that exists only in a fork, is not
# found; the summary says whether NEW is on the default branch. The fetch runs with no credential helper,
# askpass program or terminal prompt. scripts/tob-delta-review.sh reads that clone. Its report, and the paths
# the PR changes besides the gitlink and the README pin line, go inside one fenced code block: the fence is
# longer than the number of backticks on any line inside it, ASCII control characters other than tab show as
# ?, a line longer than WIDTH bytes is cut there and marked, and the whole output stays within CAP bytes
# (GitHub refuses a step summary over 1 MiB). A note after the block says when lines are left out or cut.
# Exit: 0 printed, also when the PR does not move the gitlink · 2 nothing printed: a usage error, a commit this
# repository lacks, a gitlink added, removed or replaced, a failed fetch, a commit that no branch or tag of the
# upstream reaches, a failed review, or any other step that fails. Writes nothing but a temp dir it removes on
# exit. Works with bash 3.2.
set -uo pipefail
export LC_ALL=C

PIN=vendor/trailofbits
UPSTREAM=https://github.com/trailofbits/skills
CAP=300000    # bytes printed in all: a third of GitHub's 1 MiB is left even if each byte became a 3-byte U+FFFD
WIDTH=2000    # bytes kept of one line of the block

usage() { echo "usage: bash scripts/tob-delta-pr.sh <base> <head>" >&2; exit 2; }
die() { echo "tob-delta-pr: $*" >&2; exit 2; }
[ $# -eq 2 ] || usage
for a in "$1" "$2"; do case "$a" in ''|-*) usage ;; esac; done
here=$(cd "$(dirname "$0")" && pwd) || exit 2
rgit() { git --no-pager -c core.quotePath=true "$@"; }
base=$(rgit rev-parse --verify -q "$1^{commit}") || die "commit $1 not found in this repository"
head=$(rgit rev-parse --verify -q "$2^{commit}") || die "commit $2 not found in this repository"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/tob-delta-pr.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT

# pin: "<old mode> <new mode> <old sha> <new sha>" of the gitlink; readme: README.md changed in place; other:
# "<status> <path>" for every other path, quoted as git quotes it
rgit diff-tree -r --raw --no-abbrev --no-renames --ignore-submodules=none "$base" "$head" > "$tmp/raw" \
  || die "git diff-tree failed"
awk -F'\t' -v pin="$PIN" -v d="$tmp" '
  { split($1, m, " "); om = substr(m[1], 2); nm = m[2]; st = substr(m[5], 1, 1) }
  $2 == pin { print om, nm, m[3], m[4] > (d "/pin"); next }
  $2 == "README.md" && st == "M" && om == nm { print st > (d "/readme"); next }
  { print st " " $2 > (d "/other") }' "$tmp/raw" || die "reading the git diff-tree output failed"
if [ ! -s "$tmp/pin" ]; then
  printf 'This PR does not move the `%s` gitlink, so there is no upstream delta to summarise.\n' "$PIN"
  exit 0
fi
read -r omode nmode old new < "$tmp/pin"
[ "$omode" = 160000 ] && [ "$nmode" = 160000 ] \
  || die "$PIN is not a gitlink at both commits (mode $omode -> $nmode), so there is no delta to summarise"

# README.md counts as the pin line alone when its pin line, the first that starts with **Pinned at**, has the
# same number at both commits, holds no control character, and is the same once its commit hashes and dates are
# left out, and every other line is the same byte for byte. pinnorm FILE prints that number, then FILE with each
# hash on its pin line replaced by byte 001 and each date by byte 002, which that line cannot hold; status 1
# when FILE has no such pin line, 2 when a step fails.
pinnorm() {
  local f=$1 k n
  k=$(awk '/^\*\*Pinned at\*\*/ { print NR; exit }' "$f") || return 2
  [ -n "$k" ] || return 1
  head -n "$k" "$f" | tail -n 1 > "$f.pin" || return 2
  n=$(tr -d '\012\040-\176\200-\377' < "$f.pin" | wc -c | tr -d ' ') || return 2
  [ "$n" = 0 ] || return 1
  echo "$k"
  if [ "$k" -gt 1 ]; then head -n "$((k - 1))" "$f" || return 2; fi
  awk '{ gsub(/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]+/, "\001")
    gsub(/20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]/, "\002"); print }' "$f.pin" || return 2
  tail -n "+$((k + 1))" "$f" || return 2
}
readme=unchanged
if [ -s "$tmp/readme" ]; then
  { rgit cat-file blob "$base:README.md" > "$tmp/readme.base" && rgit cat-file blob "$head:README.md" > "$tmp/readme.head"; } \
    || die "cannot read README.md"
  pinnorm "$tmp/readme.base" > "$tmp/readme.base.n"; rb=$?
  pinnorm "$tmp/readme.head" > "$tmp/readme.head.n"; rh=$?
  [ "$rb" -ne 2 ] && [ "$rh" -ne 2 ] || die "reading the README.md pin line failed"
  if [ "$rb" -eq 0 ] && [ "$rh" -eq 0 ] && cmp -s "$tmp/readme.base.n" "$tmp/readme.head.n"; then readme=pin
  else echo "M README.md (more than the commit hashes and dates on its pin line)" >> "$tmp/other"; fi
fi

urls=$(rgit cat-file blob "$base:scripts/check-corpus.sh" | sed -n "s/^SUBMODULE_URLS='\([^']*\)'\$/\1/p") \
  || die "cannot read scripts/check-corpus.sh at $base"
case " $(printf '%s' "$urls" | tr '\n' ' ') " in
  *" $UPSTREAM "*) url=$UPSTREAM ;;
  *) die "SUBMODULE_URLS in scripts/check-corpus.sh at $base does not list $UPSTREAM" ;;
esac
clone=$tmp/upstream
git init -q "$clone" || die "git init failed"
# HEAD, the default branch, goes to refs/default, outside the namespaces the branch and tag refspecs write
GIT_TERMINAL_PROMPT=0 GIT_ASKPASS='' git --no-pager -C "$clone" -c credential.helper= fetch --quiet --no-tags "$url" \
  '+HEAD:refs/default' '+refs/heads/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*' \
  || die "fetching the branches and tags of $url failed"
for c in "$old" "$new"; do
  git -C "$clone" cat-file -e "$c^{commit}" 2>/dev/null || die "commit $c is on no branch or tag of $url"
done
git -C "$clone" for-each-ref --contains "$new" --format='%(refname)' refs/remotes/origin refs/tags > "$tmp/refs" \
  || die "git for-each-ref failed"
[ -s "$tmp/refs" ] || die "commit $new is on no branch or tag of $url"
# a branch or tag named HEAD can stand in for HEAD when the upstream advertises none
if git -C "$clone" rev-parse -q --verify refs/remotes/origin/HEAD > /dev/null \
  || git -C "$clone" rev-parse -q --verify refs/tags/HEAD > /dev/null; then
  dflt="The upstream has a branch or tag named HEAD, so whether NEW is on its default branch is not known."
elif git -C "$clone" merge-base --is-ancestor "$new" refs/default 2>/dev/null; then
  dflt="NEW is on its default branch (HEAD)."
else
  dflt="NEW is not on its default branch (HEAD)."
fi
bash "$here/tob-delta-review.sh" "$clone" "$old" "$new" > "$tmp/review" || die "scripts/tob-delta-review.sh failed"

{
  if [ -s "$tmp/other" ]; then
    echo "Other files this PR changes:"
    awk 'NR <= 100 { print "  " $0 } END { if (NR > 100) printf "  ... and %d more\n", NR - 100 }' "$tmp/other"
    echo
  fi
  awk -v url="$url" -v dflt="$dflt" '{ sub(/^refs\/remotes\/origin\//, "branch "); sub(/^refs\/tags\//, "tag ") }
    NR <= 10 { s = s (NR > 1 ? ", " : "") $0 }
    END { if (NR > 10) s = s sprintf(" and %d more", NR - 10)
      print "Fetched from " url " by the names of its default branch (HEAD), branches and tags. " dflt
      print "Branches and tags that hold NEW: " s "." }' "$tmp/refs"
  echo
  cat "$tmp/review"
} > "$tmp/body"

first="**\`$PIN\` upstream delta.** This summary counts only when the PR's file list shows nothing but the gitlink and the README pin line; for any other change, this workflow and its scripts included, run the delta review locally instead (CONTRIBUTING.md §5)."
if [ -s "$tmp/other" ]; then
  second="**This PR changes other files too, so this summary does not count.** The block below lists them first."
elif [ "$readme" = pin ]; then
  second="This PR changes nothing else but the README pin line."
else
  second="This PR changes nothing else."
fi
# The block gets what is left of CAP after the two paragraphs, two fences of at most WIDTH + 1 backticks and the
# note. A line longer than WIDTH bytes is cut where a UTF-8 character starts, whole lines are kept while they
# fit, and the fence is longer than the number of backticks on any line, so no run of them closes it even if
# the characters between them were dropped.
hbytes=$(printf '%s\n\n%s\n\n' "$first" "$second" | wc -c | tr -d ' ')
budget=$((CAP - hbytes - 2 * (WIDTH + 2) - 200))
: > "$tmp/kept"
stats=$(tr '\000-\010\013-\037\177' '?' < "$tmp/body" | awk -v width="$WIDTH" -v budget="$budget" -v out="$tmp/kept" '
  BEGIN { for (i = 128; i < 192; i++) cont = cont sprintf("%c", i) }
  { line = $0; n = length(line); c = 0
    if (n > width) { w = width; while (w > width - 3 && index(cont, substr(line, w + 1, 1))) w--
      line = substr(line, 1, w) " [... " (n - w) " more bytes]"; c = 1 }
    if (full || used + length(line) + 1 > budget) { full = 1; left += n + 1; next }
    print line > out; used += length(line) + 1; cut += c
    s = line; k = gsub(/`/, "", s); if (k > run) run = k }
  END { print run + 0, used + 0, left + 0, cut + 0 }') || die "formatting the summary failed"
read -r run used left cut <<EOF
$stats
EOF
fence='```'
while [ "${#fence}" -le "$run" ]; do fence="$fence\`"; done
{
  printf '%s\n\n%s\n\n%s\n' "$first" "$second" "$fence"
  cat "$tmp/kept"
  printf '%s\n' "$fence"
  if [ "$left" -gt 0 ] || [ "$cut" -gt 0 ]; then
    printf '\nThe block is cut: %d bytes of the review are left out, and %d lines are cut at %d bytes. Run the review locally to read it whole (CONTRIBUTING.md §5).\n' \
      "$left" "$cut" "$WIDTH"
  fi
} > "$tmp/out" || die "writing the summary failed"
cat "$tmp/out"
