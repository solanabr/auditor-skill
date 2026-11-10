# Other agents

How to use auditor-skill without the Claude Code plugin: with VS Code and GitHub Copilot, Cursor, Windsurf or Codex, or through an LLM API. Back to the [docs index](README.md).

The plugin is the recommended install: it brings the `/auditor:*` commands, the agents and the bundled steps' pre-approvals ([README, Installation](../README.md#installation)). Another agent reads the skill and follows it.

## Install

Clone the whole folder anywhere the agent reads, outside the repository you audit ([`OUTPUT-RULES.md` Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)): a copy inside the target resolves its scripts, tools and corpus from a tree the target controls. The prompts below assume the README's path:

```bash
git clone https://github.com/solanabr/auditor-skill.git ~/.claude/skills/auditor-skill
```

Then initialize the Trail of Bits submodule from that folder, as the README's [Tool execution](../README.md#tool-execution-trail-of-bits--optional-rust-tools) says. Point the agent at the folder's `SKILL.md`.

## What changes without the plugin

- **No commands.** Ask in plain words. SKILL.md maps a request to its depth and mode ([Audit Modes](../SKILL.md#audit-modes)), the same way the commands do.
- **Intake by hand.** Before a Full run, fill a copy of [`QUESTIONS.md`](../QUESTIONS.md) (47 questions): the answers set the severity calibration, the trust model and which compliance checklists apply ([getting-started.md](getting-started.md), "Adapt to your repo").
- **No pre-approvals.** The commands and skills pre-approve their bundled steps in their `allowed-tools`, which Claude Code reads ([permissions-and-isolation.md](permissions-and-isolation.md#what-runs-without-asking)).
- **Paths from the installation.** Every script, tool and template the skill names is relative to the auditor-skill folder, never to the working directory, which is usually the repository under audit ([Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)).

## Prompts

```text
# VS Code / GitHub Copilot
@workspace Audit the entire repository using the auditor-skill

# Cursor / Windsurf: a full audit
Read ~/.claude/skills/auditor-skill/SKILL.md then audit this repository following that installation's FULL-AUDIT.md execution plan

# Cursor / Windsurf: a first pass on a branch
Read ~/.claude/skills/auditor-skill/SKILL.md then review what this branch changes against main, as its differential mode describes

# Claude Code, in plain words
Read the auditor-skill files in ~/.claude/skills/auditor-skill/ and perform a full security audit of this repository
```

By depth and scope, as [SKILL.md's How to Use](../SKILL.md#how-to-use) gives them:

```text
Review what this branch changes against main using the auditor-skill
Audit the Solana program in programs/<your_program>/ using the auditor-skill with PROGRAM scope
Audit the entire repository using the auditor-skill with FULL scope
Run the auditor-skill audit cycle on this repository and write the client report
Run auditor-skill checklist 03 (Arithmetic Safety) on programs/<your_program>/
Run auditor-skill with BACKEND scope on apps/backend/
Audit the Python code using auditor-skill checklist 14
Run auditor-skill on this Go/Java/Ruby/PHP project — it will auto-detect and apply the right checklists
```

## Through an LLM API

For a service of your own, send `SKILL.md` + `OUTPUT-RULES.md` as system context, with `FULL-AUDIT.md` for a full run, and the target repository's files as user messages, chunked; then collect the structured output, in the format `OUTPUT-RULES.md` sets.
