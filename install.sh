#!/usr/bin/env bash
# auditor-skill installer — drops the skill into a project's .claude/skills/
#
# Usage:
#   ./install.sh                                   # → ./.claude/skills/auditor-skill
#   ./install.sh <target-dir>                      # custom location
#   ./install.sh ~/.claude/skills/auditor-skill    # install globally (all projects)
#   curl -fsSL https://raw.githubusercontent.com/solanabr/auditor-skill/main/install.sh | bash
set -euo pipefail

REPO="https://github.com/solanabr/auditor-skill.git"
DEST="${1:-.claude/skills/auditor-skill}"

echo "→ Installing auditor-skill into: $DEST"
mkdir -p "$(dirname "$DEST")"

if [ -d "$DEST/.git" ]; then
  echo "→ Already present — updating"
  git -C "$DEST" pull --ff-only
else
  git clone --depth 1 "$REPO" "$DEST"
fi

# Shallow, and only our own submodule: a fetch-by-SHA at depth 1 works when the pin is not upstream's tip,
# and not recursing keeps any submodule Trail of Bits might add from arriving at a commit nobody reviewed.
echo "→ Initializing Trail of Bits execution tooling (optional, shallow, at the pinned commit)"
git -C "$DEST" submodule update --init --depth 1 -- vendor/trailofbits \
  || echo "  (skipped — the native corpus works without it)"

cat <<EOF

✓ auditor-skill installed → $DEST

Next steps:
  • For the /auditor:* slash commands, install as a Claude Code plugin:
      /plugin marketplace add solanabr/auditor-skill
      /plugin install auditor
  • Or use it as a skill: ask your agent to "audit this repo using the auditor-skill".
  • Optional token-efficiency tools (Rust):
      cd "$DEST/tools/auditor-tools" && cargo build --release
    Build them only from an install outside any repository you audit, or under
    OUTPUT-RULES.md Rule 11a isolated mode: cargo reads config from every parent directory.
  • Review estimated costs before a full run: $DEST/COSTS.md
EOF
