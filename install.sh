#!/usr/bin/env bash
# auditor-skill installer — clones the skill to a directory and fetches the pinned Trail of Bits tooling.
# Install it outside any repository you audit (OUTPUT-RULES.md Rule 11e).
#
# Usage:
#   ./install.sh ~/.claude/skills/auditor-skill    # user-level: every project, outside the repositories you audit
#   ./install.sh <target-dir>                      # any other location outside the repositories you audit
#   ./install.sh                                   # → ./.claude/skills/auditor-skill — only outside a repository you will audit
#   curl -fsSL https://raw.githubusercontent.com/solanabr/auditor-skill/main/install.sh | bash -s -- ~/.claude/skills/auditor-skill
#
# Re-running with the same explicit path updates that copy. A run without a path never updates: it stops
# when ./.claude/skills/auditor-skill already exists.
set -euo pipefail

REPO="https://github.com/solanabr/auditor-skill.git"
DEST="${1:-.claude/skills/auditor-skill}"

# The default path can sit in a tree someone else shipped, .git/ included: a run without a path runs no git
# in an existing copy there.
if [ -z "${1:-}" ] && { [ -e "$DEST" ] || [ -L "$DEST" ]; }; then
  echo "error: $DEST already exists, and a run without a path never updates it." >&2
  echo "  Pass the install path explicitly, e.g. ./install.sh ~/.claude/skills/auditor-skill" >&2
  exit 2
fi

echo "→ Installing auditor-skill into: $DEST"
mkdir -p "$(dirname "$DEST")"

# A copy inside a repository you audit resolves its scripts, tools and corpus from a tree that
# repository controls. Warn, and leave the choice to the user.
if top=$(git --no-pager -c core.fsmonitor=false -C "$(dirname "$DEST")" rev-parse --show-toplevel 2>/dev/null); then
  {
    echo "warning: $DEST is inside the git work tree $top."
    echo "  If you will audit that repository, install outside it instead, e.g. ./install.sh ~/.claude/skills/auditor-skill"
    echo "  (OUTPUT-RULES.md Rule 11e)."
  } >&2
fi

# Git in $DEST does not trust that copy's own repo config: no fsmonitor, hooks or credential helpers, and
# no file:// or ext:: transport.
gd() {
  git -C "$DEST" -c core.fsmonitor=false -c core.hooksPath=/dev/null -c credential.helper= \
    -c protocol.file.allow=never -c protocol.ext.allow=never "$@"
}

if [ -d "$DEST/.git" ]; then
  echo "→ Already present — updating"
  gd pull --ff-only
else
  git clone --depth 1 "$REPO" "$DEST"
fi

# Shallow, and only our own submodule: a fetch-by-SHA at depth 1 works when the pin is not upstream's tip,
# and not recursing keeps any submodule Trail of Bits might add from arriving at a commit nobody reviewed.
# --checkout ignores any submodule.<name>.update command in the repo config.
echo "→ Initializing Trail of Bits execution tooling (optional, shallow, at the pinned commit)"
gd submodule update --init --checkout --depth 1 -- vendor/trailofbits \
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
