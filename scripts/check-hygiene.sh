#!/usr/bin/env bash
# check-hygiene.sh — fail if the repository tracks files that must never be committed:
# environment files with secrets, Terraform state / plans, per-user assistant settings, OS junk.
# It also fails on a top-level directory named commands, agents, skills, hooks, bin, monitors or .claude-plugin
# in another letter case: a case-insensitive file system, macOS's default, loads it under the lowercase name,
# while on Linux no check reads it. And it fails when the plugin root gains a load surface beyond the
# commands, agents and SKILL.md files check-frontmatter.sh reads, unless ALLOWED_LOAD_SURFACES lists it:
#   - hooks/, monitors/ or bin/, .mcp.json, .lsp.json or settings*.json at the root, in any letter case, or a
#     .claude/ directory below the root;
#   - in .claude-plugin/, a file other than plugin.json and marketplace.json, or a key in either beyond
#     PLUGIN_KEYS and MARKETPLACE_KEYS (read with jq; a manifest jq cannot read fails);
#   - a SKILL.md, in any letter case, other than SKILL.md and skills/<name>/SKILL.md: with "skills": "./" in
#     plugin.json, Claude Code loads <dir>/SKILL.md when the root holds none, and a skills/SKILL.md makes all of
#     skills/ one skill.
# Paths come from git ls-files; a run outside a checkout fails.
# Usage: bash scripts/check-hygiene.sh. Needs bash >= 3.2, git and jq.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

# Tracked paths that may be a load surface, space-separated. Read a path like code before you list it.
ALLOWED_LOAD_SURFACES=''
# The keys each manifest may hold, as dotted paths ([] is an array element). A key is added when it is first
# used, once what Claude Code loads from it is known.
PLUGIN_KEYS='name version description author author.name author.url skills'
MARKETPLACE_KEYS="name owner owner.name owner.url metadata metadata.version metadata.description plugins plugins.[] \
plugins.[].name plugins.[].version plugins.[].description plugins.[].author plugins.[].author.name plugins.[].author.url \
plugins.[].source"

bad=0
flag() { echo "::error::tracked file must not be committed: $1" >&2; bad=1; }
surface() { # surface PATH WHY  — a load surface fails unless ALLOWED_LOAD_SURFACES lists PATH
  case "$1" in *" "*) ;; *) case " $ALLOWED_LOAD_SURFACES " in *" $1 "*) return ;; esac ;; esac
  echo "::error::$1: $2; once it is reviewed, list it in ALLOWED_LOAD_SURFACES in scripts/check-hygiene.sh" >&2; bad=1
}
keys() { # keys MANIFEST KNOWN  — every key path in MANIFEST must be one of KNOWN
  local out k
  out=$(jq -r 'paths | map(if type == "number" then "[]" else tostring end) | join(".")' "$1" 2>&1) \
    || { echo "::error::$1: jq cannot read it: $out" >&2; bad=1; return; }
  while IFS= read -r k; do
    case "$k" in *" "*) ;; *) case " $2 " in *" $k "*) continue ;; esac ;; esac
    echo "::error::$1: key '$k' is not in the list in scripts/check-hygiene.sh; add it once what Claude Code loads from it is reviewed" >&2
    bad=1
  done <<< "$out"
}

git ls-files -z >/dev/null || { echo "::error::git ls-files failed; run this in the checkout" >&2; exit 2; }
cased=" "   # the directories reported for their letter case
manifests=""
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
  case "$low" in
    hooks/* | monitors/* | bin/*) surface "$f" "Claude Code loads ${f%%/*}/ from the plugin root" ;;
    ?*/.claude/*) surface "$f" "a .claude/ directory below the root" ;;
    */*) ;;
    .mcp.json | .lsp.json | settings*.json) surface "$f" "Claude Code loads it from the plugin root" ;;
  esac
  case "$low" in skill.md | */skill.md)
    why="a SKILL.md other than SKILL.md and skills/<name>/SKILL.md, which Claude Code may load as a skill"
    case "$f" in
      SKILL.md) ;;
      skills/*/*/*) surface "$f" "$why" ;;
      skills/*/SKILL.md) ;;
      *) surface "$f" "$why" ;;
    esac ;;
  esac
  case "$f" in
    .claude-plugin/plugin.json | .claude-plugin/marketplace.json) manifests="$manifests $f" ;;
    *) case "$low" in .claude-plugin/*) surface "$f" ".claude-plugin/ holds plugin.json and marketplace.json" ;; esac ;;
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

if [ -n "$manifests" ] && ! command -v jq >/dev/null; then
  echo "::error::jq is needed to read the keys of$manifests" >&2; bad=1; manifests=""
fi
for m in $manifests; do
  case "$m" in */plugin.json) keys "$m" "$PLUGIN_KEYS" ;; *) keys "$m" "$MARKETPLACE_KEYS" ;; esac
done

if [[ $bad -ne 0 ]]; then exit 1; fi
echo "hygiene check passed"
