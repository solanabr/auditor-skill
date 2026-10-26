# Permissions & Isolation

What runs without asking during an audit, what still asks and why, how to run on code you don't trust (in a container, a VM or Claude Code's sandbox), what to do in `claude -p`, and what remains a risk. Back to the [docs index](README.md).

The rules behind this page are [`OUTPUT-RULES.md` Rule 11](../OUTPUT-RULES.md#rule-11-operating-safety).

## What runs without asking

Each `/auditor:*` command pre-approves, in its `allowed-tools`, the bundled steps it runs, and nothing else:

| Step | Entry point |
|------|-------------|
| Check the working tree before anything reads it (every flow's first step) | `scripts/preflight.sh` |
| Make, check and reuse run directories | `scripts/rundir.sh` |
| Read git history and make a copy of a checkout you did not create | `scripts/git-ro.sh` |
| Pre-scan, and cross-audit memory | `audit-scan --contract=1`; `audit-mem` `init`, `warm`, `check`, `regressions` and `put-finding`, each with `--contract=1` |
| Gather the threat model's history | `scripts/threat-model/collect.sh` with `--detect` or `--offline` first |
| Probe the toolchains, audit dependencies, run SAST | `scripts/runner/probe.sh`, `deps.sh`, `sast.sh` |
| Build and test the project, build and run PoCs | `scripts/runner/target.sh`, `templates/poc/run.sh` |
| Read one account, transaction or program from RPC | `scripts/rpc-read.sh` |
| Render the report as PDF | `scripts/report-to-pdf.sh` |
| Snapshot an incident's programs, and collect its transactions | `scripts/dnr/snapshot-program.sh`, `scripts/dnr/collect.sh` |
| Analyze an incident corpus, inside the `auditor:dnr-analyze` fork | `profile.sh`, `frames.py`, `deltas.py`, `jq-ro.sh`, `audit-logs` |

The commands also pre-approve reading (`Read`, `Grep`, `Glob`), starting their agents (`Task`), and writing files under `audit_*/` and `incident_*/` with the Write and Edit tools. Each command pre-approves only the rows its own steps use. Details of each tool: [power-tools.md](power-tools.md).

### Why that is safe

A rule such as `Bash("${CLAUDE_PLUGIN_ROOT}/scripts/git-ro.sh" *)` approves that one program, with any words after it. Claude Code matches a rule only as written: another path, `bash` in front, a `cd`, a `VAR=value` prefix or a `$` anywhere stops the match, and it needs a rule for every part of a line it splits at `&&`, `;` or a pipe. A call that matches no rule asks. So each entry point is built to be safe whatever words follow:

- It runs from the installation, outside the tree under audit, by its absolute path.
- It checks every argument against a closed grammar before it does anything, and refuses anything else with one stderr line that names the tool and the reason.
- It takes only relative paths inside the working directory, with no `..` and no symbolic link, and it refuses to run from an installation inside the working directory.
- It writes only into run directories (`audit_<n>/`, `incident_<n>/`) or the `audit-mem` store, creating each file new and never writing through a link.
- It runs no program that its arguments or the repository name. git runs through a hardened call that runs none of the programs the repository's config names and reaches no network. The project's own code runs only inside `target.sh` and `run.sh`, in the execution mode you chose.
- It contacts only the services fixed in its code, or the endpoint and caps you set in your environment (`RPC_URL`, `AUDITOR_RPC_MAX_PAGES`, `AUDITOR_RPC_MAX_TX`, `AUDITOR_RPC_MAX_ADDRESSES`), which a command line cannot change. Each contact adds a row to the run directory's `disclosures.tsv`, and the report lists them (Rule 11b).
- A check that cannot run is a refusal.

Their suites run them on hostile arguments under macOS `/bin/bash` 3.2 and under bash 5 with GNU tools.

Each decision is asked once, in the flow, and not again as a permission prompt:

- **Running the project's code** is your answer to `QUESTIONS.md` Q46 at intake. In the mode you chose, the runners build and test without asking again for each run.
- **An RPC collection** is your yes to the addresses, time window, caps and call estimate that `/auditor:hunt` and `/auditor:respond` show you (`--collect` in a non-interactive run). The collector then runs with exactly those values.
- **An outside service** is listed in the report, not gated (Rule 11b).

## What still asks, and why

| Call | Why it asks |
|------|-------------|
| A URL chosen at run time: the threat-model collector's `--network`, the KV-137 and SC-054 upstream fetches, `solana-verify verify-from-repo`, WebFetch | A URL can carry data out, and no bundled tool can limit it. The prompt shows the exact URL. |
| Trail of Bits scripts and other tools the plugin does not wrap: CodeQL, slither, zeroize-audit, constant-time and dimensional analysis, `second-opinion`, `supply-chain-risk-auditor`, `post-patch-validation`, mewt, Trident, `cargo fuzz`, Surfpool | We don't control their code or what they reach. Several compile the project's code or contact services. |
| Runners the agent writes (a Trident or cargo-fuzz target, a Surfpool scenario), and `python3 -c`, `awk` or `bash -c` code | They can hold any code at all. |
| `audit-mem rule` and `audit-mem set-status` | They change what later audits suppress: a ruling is your decision. |
| A path outside the working directory: `--logs ~/export`, a `--repo` or `--parent` outside it, the copy of an export into `incident_<n>/logs/` | That is the boundary. The prompt shows the path you gave. |
| Installs: rustup, avm, `cargo install`, `npx`, `pip` | They change your system. |
| Plain `git`, `cargo`, `anchor`, `npm` or `jq`, and a line that pipes into `redact.sh` | The flows run the confined tools above instead; a plain call has none of their checks. |
| The Skill call that resumes a flow, in Manual mode | See [Turns and resuming](#turns-and-resuming). |

What happens to these depends on the permission mode:

- **Manual mode** asks you.
- **Auto mode**, the default for terminal sessions in recent Claude Code, sends them to its classifier. The commands' own rules are decided first, so the bundled steps run without the classifier.
- **`claude -p`** starts in Manual mode and denies every call that would ask. The flow records each denied step as not run, under Coverage & Limitations.

## Turns and resuming

A command's pre-approvals last for the turn that invoked it. Claude Code clears them at your next message, and a turn that starts when a background agent finishes gets none (both measured with Claude Code 2.1.304). So when a flow goes on after you reply (a checkpoint answer, a yes to a collection, a mode choice), it first invokes its own command again through the Skill tool, as `auditor:<name> --resume <step>`, which gives the new turn the same pre-approvals. A resumed flow never repeats a step it finished.

The Skill tool needs permission, and a plugin cannot ship permission rules, so Manual mode asks each time a flow resumes. To stop that, add these rules to `permissions.allow` in your user settings, `~/.claude/settings.json`, beside any rules you already have there:

```json
{
  "permissions": {
    "allow": [
      "Skill(auditor:audit-cycle *)", "Skill(auditor:audit-assist *)", "Skill(auditor:intake *)",
      "Skill(auditor:threat-model *)", "Skill(auditor:triage *)", "Skill(auditor:poc *)",
      "Skill(auditor:patch *)", "Skill(auditor:audit-report *)", "Skill(auditor:hunt *)",
      "Skill(auditor:respond *)", "Skill(auditor:dnr-analyze *)"
    ]
  }
}
```

These rules name the plugin's skills and no path or version. What each skill then pre-approves stays inside the plugin, and changes with it.

Don't answer "Yes, and don't ask again" at that prompt instead. It saves the rule into the audited repository's `.claude/settings.local.json`: a file in the client's tree, at the root of the git repository that holds the working directory, or in the working directory itself outside a repository. `preflight.sh` refuses that file on the next run, since a `permissions` key is not one a clean tree may carry. If you already did, move its `permissions.allow` entries to `~/.claude/settings.json` and delete the file.

A `claude -p` run is one turn, so its command's pre-approvals cover the whole run, its agents included, and nothing resumes.

## Running isolated

Isolated mode means the project's code runs where nothing of yours can be read: no keys, no wallets, no cloud, registry or git credentials. To use it:

1. Answer **Isolated** at intake (Q46). Intake writes `isolated` to `audit_<n>/exec-mode`.
2. Set `AUDITOR_EXEC_MODE=isolated` in the environment Claude Code runs in. The runners take the stricter of that variable and the `exec-mode` file, so if the file is ever changed, the variable still holds.
3. Run in one of the three places below.

In isolated mode the runners first check that none of the credentials a host keeps is readable, and stop if one is: SSH keys and agent sockets, Solana keypairs and CLI config, cloud, registry and git credentials, GnuPG keys, Claude Code's own credentials. `scripts/lib/isolation.sh` has the full list. To see what the check finds on a machine (an example of what you type; `<auditor-skill root>` is where auditor-skill is installed):

```bash
# example: what you type, with your own installation path
"<auditor-skill root>/scripts/runner/probe.sh" --only isolation
```

`AUDITOR_EXEC_MODE=none` is the third choice: no code of the project's runs at all, and each step that needs it is recorded as not run.

### A container or a VM

The container or VM is the boundary, so it suits builds of untrusted code best.

- Put the toolchains the audit needs in the image: git with the May-2024 clone fixes (2.45.1 or later, or the matching maintenance release), Rust with rustup, the Agave release whose `cargo build-sbf` has `--install-only` and `--skip-tools-install`, and Anchor, Node, semgrep and the `solana` CLI as the audit needs. Install auditor-skill in the image and build its Rust tools there.
- Mount no credentials: no `~/.ssh`, `~/.config/solana`, `~/.aws` or other cloud configuration, no registry tokens, and no SSH agent socket.
- Give Claude Code an API key in the environment rather than a login: a login stored in `~/.claude/.credentials.json` fails the self-check, since the project's code could read it. The runners' children never get the key, but on Linux code that runs as the same user can read another process's environment, so use a key you can revoke.
- Give it a copy of the repository, not your own checkout ([Rule 11e](../OUTPUT-RULES.md#11e--bundled-paths)).
- Set `AUDITOR_EXEC_MODE=isolated` in the image, and run Claude Code as a user other than root: it refuses `bypassPermissions` as root.

Inside the container, `--permission-mode bypassPermissions` is the one mode in which nothing asks. Limit the container's network to the registries and your RPC provider if you can.

### Claude Code's sandbox

Claude Code's sandbox runs every shell command it starts in an operating-system sandbox (Seatbelt on macOS, bubblewrap on Linux). By default a sandboxed command can still read most of your machine, and Claude Code keeps no list of credentials to hide, so the block below denies the ones the self-check looks for. Put it in your user settings, `~/.claude/settings.json`, where it applies to every repository you audit: a project's own settings are the client's, and `preflight.sh` refuses a project settings file that holds these keys.

```json
{
  "env": {
    "AUDITOR_EXEC_MODE": "isolated"
  },
  "permissions": {
    "blockReadsOutsideWorkingDirectories": true,
    "ask": ["Bash(dangerouslyDisableSandbox:true)"]
  },
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "filesystem": {
      "allowRead": ["~/.cargo", "~/.rustup", "~/.local/share/solana", "~/.cache/solana", "~/.avm"]
    },
    "network": {
      "allowedDomains": [
        "crates.io", "index.crates.io", "static.crates.io", "registry.npmjs.org",
        "pypi.org", "files.pythonhosted.org", "github.com", "semgrep.dev"
      ]
    },
    "credentials": {
      "files": [
        { "path": "~/.ssh", "mode": "deny" },
        { "path": "~/.config/solana", "mode": "deny" },
        { "path": "~/.aws", "mode": "deny" },
        { "path": "~/.config/gcloud", "mode": "deny" },
        { "path": "~/.azure", "mode": "deny" },
        { "path": "~/.kube", "mode": "deny" },
        { "path": "~/.docker/config.json", "mode": "deny" },
        { "path": "~/.npmrc", "mode": "deny" },
        { "path": "~/.yarnrc.yml", "mode": "deny" },
        { "path": "~/.gem", "mode": "deny" },
        { "path": "~/.pypirc", "mode": "deny" },
        { "path": "~/.cargo/credentials", "mode": "deny" },
        { "path": "~/.cargo/credentials.toml", "mode": "deny" },
        { "path": "~/.git-credentials", "mode": "deny" },
        { "path": "~/.config/git/credentials", "mode": "deny" },
        { "path": "~/.netrc", "mode": "deny" },
        { "path": "~/.config/gh", "mode": "deny" },
        { "path": "~/.gnupg", "mode": "deny" },
        { "path": "~/.claude/.credentials.json", "mode": "deny" },
        { "path": "~/.1password", "mode": "deny" },
        { "path": "~/Library/Group Containers/2BUA8C4S2C.com.1password", "mode": "deny" }
      ]
    }
  }
}
```

What each part does:

- **`allowUnsandboxedCommands: false`** turns on strict sandbox mode. Without it, a command that fails in the sandbox can be retried outside it, and an allow rule that matches the command also approves the retry: a pre-approved runner would then run unsandboxed. The ask rule on `Bash(dangerouslyDisableSandbox:true)` is a second guard. `failIfUnavailable` keeps Claude Code from starting unsandboxed when the sandbox cannot run.
- **`credentials`** denies sandboxed commands the files the self-check reads. If a variable points one of them elsewhere (`CARGO_HOME`, `XDG_CONFIG_HOME`, `GNUPGHOME`, `KUBECONFIG`, `DOCKER_CONFIG`, `AWS_SHARED_CREDENTIALS_FILE` and the others `scripts/lib/isolation.sh` names), or your Solana CLI config names a keypair outside `~/.config/solana`, deny that path too. The sandbox also refuses connections to Unix sockets, so an SSH or GnuPG agent stays out of reach.
- **`allowedDomains`** are the hosts the runners reach: crates.io and its index and download hosts, npm, PyPI, github.com (cargo audit's RustSec database) and semgrep.dev. Add your RPC provider's host, and the registries and git hosts the project's own builds fetch from. Another host asks in Manual mode, and is refused in `claude -p` and in auto mode unless the classifier approves it. `bypassPermissions` mode lets any host through, so don't use it with this block.
- **`blockReadsOutsideWorkingDirectories`** stops Claude's file tools, and with the sandbox its shell commands too, from reading outside the working directory: without it, read-only commands such as `cat` and `grep` read anywhere you can, without asking, in every mode. Your skills and plugins under `~/.claude` stay readable, so install auditor-skill as the plugin or under `~/.claude/skills/`. `allowRead` gives the sandbox back your toolchains; add the directories where yours live.

**Builds under the sandbox.** A sandboxed command may write only the working directory and the temp directory. cargo keeps the crates it downloads in `~/.cargo/registry` and `~/.cargo/git`, and `cargo build-sbf --install-only` installs the platform tools under `~/.cache/solana`, so a build that has to download or install there stops with a blocker, and its step is recorded as not run. Adding those directories to `sandbox.filesystem.allowWrite` lets such builds run, but then the code under audit, which runs in the same sandbox, can change what later builds on your machine compile. For builds of untrusted code, a container or VM, whose caches you throw away, is the safer place.

## Non-interactive runs (`claude -p`)

A run is one turn, so the command's pre-approvals cover the whole run, its agents included. It needs a recorded mode: `/auditor:intake --auto` writes `native`, the documented default, unless `AUDITOR_EXEC_MODE` is stricter. An incident collection needs `--collect`, which stands for your yes to the addresses, window and caps.

```bash
# Examples of what you type. They need the claude CLI and the plugin installed.

# Default: the bundled steps run; anything else is denied and recorded as a tooling gap.
# The project's code runs natively unless intake or AUDITOR_EXEC_MODE says otherwise.
claude -p "/auditor:audit-cycle ."

# Recommended for untrusted code: inside a container or VM with no credentials mounted,
# whose environment sets AUDITOR_EXEC_MODE=isolated. The runners' self-check refuses if keys are readable.
claude -p "/auditor:audit-cycle ." --permission-mode bypassPermissions

# On a host, with the classifier for the steps that are not pre-approved
claude -p "/auditor:audit-cycle ." --permission-mode auto

# Extra rules: only rules with no path (skill names, MCP tool names), never an absolute Bash path
claude -p "/auditor:hunt <program> --collect" --allowedTools "Skill(auditor:dnr-analyze *)"
```

**The default builds on your host.** `claude -p "/auditor:audit-cycle ."` on your own machine records native mode and builds and tests the project there without asking. For code you don't trust, set `AUDITOR_EXEC_MODE=isolated`, so that a host with readable keys refuses the builds, or `AUDITOR_EXEC_MODE=none`, so that nothing of the project's runs.

An absolute Bash path in your own rules would approve a program whatever words follow it, and the plugin's path changes with each version. Keep extra rules to names.

## Optional hardening

```json
{
  "env": {
    "CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR": "1"
  },
  "permissions": {
    "ask": ["Bash(git *)"]
  }
}
```

- **`CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR=1`** starts every shell command in the project directory, so a `cd` never carries over to the next command.
- **An ask rule for `Bash(git *)`** makes plain git ask every time, while `git-ro.sh` stays pre-approved.

## Organizations with managed permission rules

If your organization sets `allowManagedPermissionRulesOnly` in managed settings, Claude Code ignores the allow rules in your own settings (the snippet above included) and `--allowedTools`, hides "don't ask again", and ignores the `allowed-tools` of skills and plugins from the sources that setting's reference lists, such as a skill installed under `~/.claude/skills/`. Steps that would run without asking then ask, and `claude -p` denies them. Ask your administrator to add the rules to managed settings, or run in a container or VM.

## What remains a risk

- **Native mode runs the project's code on your host, unasked.** In native mode the runners build and test the project, and run the exploits the agent writes, on your machine without a prompt for each run: your Q46 answer is the consent. Each child starts with a cleaned environment and a throwaway `HOME` and wallet, so no token, `RPC_URL` or default keypair reaches it, but a build script can still read any file you can. A non-interactive run records native unless `AUDITOR_EXEC_MODE` says otherwise.
- **The `exec-mode` file is the agent's to write.** A hijacked agent could turn isolated into native there. The runners take the stricter of the file and `AUDITOR_EXEC_MODE`, and the report states the mode, so if you chose isolated, set `AUDITOR_EXEC_MODE=isolated` too.
- **Pre-approved calls skip auto mode's classifier.** It gives no second opinion on a runner call; the runners' own checks and the recorded mode are what bound it.
- **Read-only commands read outside the working directory.** `cat`, `grep` and the rest run without a prompt in every mode, outside the tree too, unless `blockReadsOutsideWorkingDirectories` is on or a sandbox denies the read.
- **A collection you did not approve.** A hijacked agent could run the collector with other addresses. The endpoint and caps come from your environment and the RPC methods are read-only, so what it can spend is bounded by your caps, in your provider's credits.
- **Memory noise.** `put-finding` can record findings that a later audit sees. They stay visible, and suppressing anything (`rule`, `set-status`) still asks.
- **Tool lookup.** git, jq, pandoc, cargo, semgrep and python3 come from your `PATH`, with relative and working-tree entries removed. A version manager on your `PATH` can still choose which installed `python3` runs from a file in the tree, and a `PATH` set by a project's `.claude/settings.json` is outside what the tools can check, which is one reason preflight refuses such settings.
- **Claude Code's own git calls** in an untrusted checkout, such as the status line, are outside the plugin's control: audit a clean copy (Rule 11e).
- **Parsers.** TeX, pandoc and SQLite still parse hostile input, under the restrictions [power-tools.md](power-tools.md) gives for `report-to-pdf.sh` and `audit-mem`.
- **"You created the store"** stays your judgement: `audit-mem` checks the mechanics only.
- **Races.** Only code running alongside the tools, such as a native build, could change a file between their checks and its use; they create every file exclusively and never write through a link.
- **Claude Code's behavior.** Where its permission rules behave otherwise than measured here (Claude Code 2.1.304), a step asks: you lose the smoothness, not the safety.
