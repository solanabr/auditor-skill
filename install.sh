#!/usr/bin/env bash
{
# auditor-skill installer — clones the skill to a directory and fetches the pinned Trail of Bits tooling.
# Install it outside any repository you audit (OUTPUT-RULES.md Rule 11e).
#
# Usage:
#   ./install.sh                                   # → ~/.claude/skills/auditor-skill: user-level, every project
#   ./install.sh <target-dir>                      # any other location outside the repositories you audit
#   curl -fsSL https://raw.githubusercontent.com/solanabr/auditor-skill/main/install.sh | bash
#
# Re-running installs a fresh clone at the same path and moves the earlier install to
# ${XDG_STATE_HOME:-~/.local/state}/auditor-skill/backup-<timestamp>. No git command ever runs inside an
# existing copy, and nothing from it is reused.
#
# Everything from the line after #! to the last line is one brace group, which bash reads to its end before
# running any of it: a download cut short (curl … | bash) is a syntax error and changes nothing.
set -euo pipefail
# No cd may search $CDPATH, and no git call may use a repository named in the environment instead of the
# directory it is pointed at.
unset CDPATH GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

REPO="https://github.com/solanabr/auditor-skill.git"

# physical PATH: PATH with its longest existing directory prefix resolved through any links (cd -P).
physical() {
  local p=$1 rest=""
  while [ ! -d "$p" ]; do rest="/${p##*/}$rest"; p=$(dirname "$p"); done
  printf '%s%s\n' "$(cd -P "$p" && pwd)" "$rest"
}

# no_claude_dir: refuse a backup directory under a directory named .claude, skills, commands or agents, in any
# letter case, on its path as given or with links resolved: Claude Code could load the copy kept there.
no_claude_dir() {
  local p
  for p in "$backups" "$(physical "$backups")"; do
    case "/$(printf '%s' "$p" | LC_ALL=C tr '[:upper:]' '[:lower:]')/" in
      */.claude/*|*/skills/*|*/commands/*|*/agents/*)
        echo "error: the backup directory $backups lies inside a .claude, skills, commands or agents directory; set XDG_STATE_HOME elsewhere." >&2
        exit 2 ;;
    esac
  done
}

main() {
  if [ -n "${1:-}" ]; then
    DEST=$1
  else
    # The default is a user-level skill path, so it does not depend on where the run starts.
    case "${HOME:-}" in
      /*) DEST="${HOME%/}/.claude/skills/auditor-skill" ;;
      *) echo "error: HOME is not set to an absolute path; pass the install directory explicitly." >&2; exit 2 ;;
    esac
    # Through 7.6.0 a run without a path installed into ./.claude/skills/auditor-skill; a copy there stays as it is.
    if { [ -e .claude/skills/auditor-skill ] || [ -L .claude/skills/auditor-skill ]; } \
       && [ "$(physical .claude/skills/auditor-skill)" != "$(physical "$DEST")" ]; then
      echo "note: this run installs to $DEST and leaves ./.claude/skills/auditor-skill alone; see \"Upgrading from 7.6.0 or earlier\" in the README." >&2
    fi
  fi
  while [ "$DEST" != "/" ] && [ "${DEST%/}" != "$DEST" ]; do DEST="${DEST%/}"; done
  case "$DEST" in
    ''|/|.|..|*/.|*/..) echo "error: pass the install directory by name, not '$DEST'." >&2; exit 2 ;;
  esac

  # An existing copy is never opened with git, since its repo config can name filters and commands for git to
  # run. An earlier install (a directory with .git/ and our SKILL.md) is moved, once the fresh clone is ready,
  # to a backup in a private directory outside every skills directory: left next to the install, Claude Code
  # could load it as a second skill. Anything else is left alone.
  old=""
  if [ -L "$DEST" ]; then
    echo "error: $DEST is a symbolic link, which the installer neither follows nor replaces; remove the link or pass another path." >&2
    exit 2
  elif [ -d "$DEST" ] && [ -z "$(ls -A "$DEST")" ]; then
    rmdir "$DEST"
  elif [ -e "$DEST" ]; then
    if ! { [ -d "$DEST/.git" ] && [ -f "$DEST/SKILL.md" ] && grep -qxE 'name: (auditor-skill|AUDITOR)' "$DEST/SKILL.md"; }; then
      echo "error: $DEST exists and is not an auditor-skill install; remove it or pass another path." >&2
      exit 2
    fi
    case "${XDG_STATE_HOME:-}" in   # a relative XDG_STATE_HOME is ignored, as the XDG spec says
      /*) state=$XDG_STATE_HOME ;;
      *) case "${HOME:-}" in
           /*) state="${HOME%/}/.local/state" ;;
           *) echo "error: $DEST holds an earlier install, and neither XDG_STATE_HOME nor HOME is an absolute path to back it up under." >&2
              exit 2 ;;
         esac ;;
    esac
    backups="${state%/}/auditor-skill"
    if [ -L "$backups" ]; then
      echo "error: $backups is a symbolic link; backups go only to a real directory. Remove the link or set XDG_STATE_HOME elsewhere." >&2
      exit 2
    fi
    case "$(physical "$backups")/" in
      "$(physical "$(dirname "$DEST")")"/*)
        echo "error: the backup directory $backups lies inside $(dirname "$DEST"), beside the install; set XDG_STATE_HOME elsewhere." >&2
        exit 2 ;;
    esac
    no_claude_dir
    old="$backups/backup-$(date +%Y%m%d-%H%M%S)"
    if [ -e "$old" ] || [ -L "$old" ]; then
      echo "error: $old already exists; run the installer again in a second." >&2
      exit 2
    fi
  fi

  echo "→ Installing auditor-skill into: $DEST"
  mkdir -p "$(dirname "$DEST")"

  # A copy inside a repository you audit resolves its scripts, tools and corpus from a tree that
  # repository controls. Warn, and leave the choice to the user.
  if top=$(git --no-pager -c core.fsmonitor=false -C "$(dirname "$DEST")" rev-parse --show-toplevel 2>/dev/null); then
    {
      echo "warning: $DEST is inside the git work tree $top."
      echo "  If you will audit that repository, install outside it instead (OUTPUT-RULES.md Rule 11e)."
    } >&2
  fi

  # Clone into a private directory next to DEST, on the same filesystem, and move it into place when it is complete.
  tmp=$(mktemp -d "$(dirname "$DEST")/.auditor-skill-install.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT
  git clone --depth 1 "$REPO" "$tmp/auditor-skill"

  # Shallow, and only our own submodule: a fetch-by-SHA at depth 1 works when the pin is not upstream's tip,
  # and not recursing keeps any submodule Trail of Bits might add from arriving at a commit nobody reviewed.
  echo "→ Initializing Trail of Bits execution tooling (optional, shallow, at the pinned commit)"
  git -C "$tmp/auditor-skill" submodule update --init --depth 1 -- vendor/trailofbits \
    || echo "  (skipped — the native corpus works without it)"

  if [ -n "$old" ]; then swap; else mv "$tmp/auditor-skill" "$DEST"; fi
  if [ ! -f "$DEST/SKILL.md" ]; then
    echo "error: $DEST holds no SKILL.md after the install." >&2
    exit 1
  fi

  cat <<EOF

✓ auditor-skill installed → $DEST
EOF
  if [ -n "$old" ]; then
    echo "  The earlier install is now $old"
    echo "  Nothing from it is reused; delete it when you no longer need it."
  fi
  cat <<EOF

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
}

# swap: the fresh clone in $tmp becomes DEST, and the earlier install becomes $old. The earlier install is first
# renamed into a private directory beside DEST and the clone renamed into place, both on DEST's filesystem; only
# then does the earlier install move to the state directory, which may sit on another volume.
swap() {
  if [ -L "$backups" ]; then   # checked again before anything is created there
    echo "error: $backups is a symbolic link; backups go only to a real directory." >&2
    exit 2
  fi
  no_claude_dir   # checked again too: a link on its path can appear while the clone runs
  (umask 077; mkdir -p "$backups")
  chmod 700 "$backups"
  if [ -e "$old" ] || [ -L "$old" ]; then   # checked again: mv onto an existing directory would move into it
    echo "error: $old already exists; run the installer again in a second." >&2
    exit 2
  fi
  hold=$(mktemp -d "$(dirname "$DEST")/.auditor-skill-old.XXXXXX")
  if ! mv "$DEST" "$hold/auditor-skill"; then
    rmdir "$hold"
    echo "error: could not move the earlier install out of $DEST; it is unchanged." >&2
    exit 1
  fi
  if ! mv "$tmp/auditor-skill" "$DEST"; then
    if mv "$hold/auditor-skill" "$DEST"; then
      rmdir "$hold"
      echo "error: could not move the fresh clone into place; the earlier install is back at $DEST." >&2
    else
      echo "error: could not move the fresh clone into place; the earlier install is at $hold/auditor-skill." >&2
    fi
    exit 1
  fi
  if ! mv "$hold/auditor-skill" "$old"; then
    echo "error: $DEST holds the new install, but the earlier one could not move to $old; it is at $hold/auditor-skill." >&2
    exit 1
  fi
  rmdir "$hold"
  echo "→ The earlier install is now $old; nothing from it is reused. Delete it when you no longer need it."
}

main "$@"
}
