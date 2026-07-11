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

echo "→ Initializing Trail of Bits execution tooling (optional)"
git -C "$DEST" submodule update --init --recursive \
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
  • Review estimated costs before a full run: $DEST/COSTS.md
EOF
