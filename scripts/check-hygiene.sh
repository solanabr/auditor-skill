#!/usr/bin/env bash
# check-hygiene.sh — fail if the repository tracks files that must never be committed:
# environment files with secrets, Terraform state / plans, per-user assistant settings, OS junk.
# It also fails on a top-level directory named commands, agents, skills, hooks, bin, monitors or .claude-plugin
# in another letter case: a case-insensitive file system, macOS's default, loads it under the lowercase name,
# while on Linux no check reads it. Paths come from git ls-files; a run outside a checkout fails.
# Usage: bash scripts/check-hygiene.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

bad=0
flag() { echo "::error::tracked file must not be committed: $1" >&2; bad=1; }

git ls-files -z >/dev/null || { echo "::error::git ls-files failed; run this in the checkout" >&2; exit 2; }
cased=" "   # the directories reported for their letter case
while IFS= read -r -d '' f <&3 && IFS= read -r -d '' low <&4; do
  case "$f" in
    */*) top=${f%%/*}; ltop=${low%%/*}
      case "$ltop" in commands | agents | skills | hooks | bin | monitors | .claude-plugin)
        case "$top:$cased" in "$ltop":* | *" $top/ "*) ;;
          *) cased="$cased$top/ "; bad=1
             echo "::error::$top/: name it $ltop/; a case-insensitive file system loads it as $ltop/" >&2 ;;
        esac ;;
      esac ;;
  esac
  case "$f" in
    vendor/*) continue ;;
  esac
  base=${f##*/}
  case "$base" in
    .env|.env.*)            [[ "$base" == *.example ]] || flag "$f" ;;
    *.tfstate|*.tfstate.*)  flag "$f" ;;
    tfplan*|*.tfplan)       flag "$f" ;;
    settings.local.json)    flag "$f" ;;
    .DS_Store|Thumbs.db)    flag "$f" ;;
    id.json)                flag "$f (looks like a Solana keypair)" ;;
  esac
  case "$low" in
    .claude/*|.cursor/*|.agents/*) flag "$f (per-user assistant configuration)" ;;
  esac
done 3< <(git ls-files -z) 4< <(git ls-files -z | LC_ALL=C tr 'A-Z' 'a-z')

if [[ $bad -ne 0 ]]; then exit 1; fi
echo "hygiene check passed"
