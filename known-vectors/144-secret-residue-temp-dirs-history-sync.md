---
id: 144
title: "Secret Residue Outside the Repository — Temp Directories, CI Workspaces, Shell History and Sync Folders"
severity: 8
category: devops
---

### 144 — Secret Residue Outside the Repository — Temp Directories, CI Workspaces, Shell History and Sync Folders

**Severity: 8** | **Real: Slope wallet, Aug 2022: seed phrases were sent in plaintext to a Sentry logging endpoint and about 9,000 Solana wallets were drained (~$4.5M), a key that left the place it was meant to live through a side channel nobody reviewed. FakeFix, 2025: 20 npm and 4 PyPI packages read `~/.config/solana/id.json` and other wallet paths from install hooks (SC-045), which shows that malware goes straight to the well-known locations on a developer machine. The temp-file and process-argument forms are catalogued weaknesses: CWE-377 (insecure temporary file), CWE-214 (sensitive information visible in process invocation), CWE-532 (sensitive information in log files). No incident is cited for the temp-directory form itself; this entry covers the class.**

Secret scanning looks at the repository and its history (KV-001, KV-078). A key spends most of its life somewhere else: in the file a deploy script wrote before calling the CLI, in the CI workspace that the next step uploads as an artifact, in the shell history line that pasted it, in the copy the editor or the sync client made. None of those places is in git, all of them are readable by anything that runs as the same user, and several are readable by every user on the host. The auditor checks two things: that the code in scope does not create the residue, and that the team has looked for residue already there.

- **Temp files written by code and scripts.** `echo "$KEY" > /tmp/key.json`, `fs.writeFileSync(path.join(os.tmpdir(), 'keypair.json'), ...)`, `std::env::temp_dir().join("id.json")`, `tempfile.gettempdir()`. `/tmp` and `/var/tmp` are shared by every user and process on a Linux host, the name is predictable, the default mode is world-readable, and nothing deletes the file when the script fails halfway. A pre-created symlink at the predictable path turns the write into an overwrite of another file (CWE-377).
- **CI workspaces, artifacts and caches.** A secret written under `$GITHUB_WORKSPACE` is inside the directory that `actions/upload-artifact`, `actions/cache` and a later `docker build .` read. On a self-hosted runner the workspace and `/tmp` survive the job, so the next job, including one triggered by a pull request, finds the file (KV-139, KV-140).
- **Process arguments and shell history.** A key, seed or API token passed as a command-line argument is visible to every user through the process list while the command runs (CWE-214), and stays in `~/.bash_history` / `~/.zsh_history` / PowerShell's `ConsoleHost_history.txt` afterwards. Runbooks and READMEs that show `--private-key <base58>` or `export PRIVATE_KEY=...` teach the team to do it.
- **Keystores in the wrong place.** The deploy or upgrade authority sitting at the default `~/.config/solana/id.json` (the first path malware reads), a keypair file with group or world read permission, a keystore inside a Dropbox / OneDrive / iCloud / Google Drive folder (a copy now exists on a third party's servers and on every synced device), or a keypair in `Downloads`, the desktop or the project directory beside `.gitignore`.
- **Copies made by tools.** Editor swap and backup files (`.swp`, `~`, `.bak`), core dumps and crash reports of a signer process (KV-112), terminal scrollback logs, clipboard managers.

Deleting a found file is not the fix. Flash storage, snapshots, backups and sync clients keep copies the operator cannot reach, so a key that touched a shared or synced location is treated as exposed and rotated.

Rules of engagement: Steps 1 to 4 and 6 are static reads of the repository. Step 5 looks at a machine and is run by its operator, or by the auditor only with the operator's explicit go-ahead. Every command in it prints paths, modes, sizes, dates or counts, never file contents; the auditor does not open, copy or transmit a file that may hold a key, and a hit is reported as a path and a mode.

> Cross-ref: checklist 12 §12.9 (SEC-054..059); KV-001 / KV-078 (secrets in the repo and its history: the in-git half of this vector); SC-045 (install hooks that harvest wallet paths); KV-112 (in-memory secrets, core dumps and swap); KV-116 (deploy keys within reach of a CI agent); DEP-071 / LM-016 / RS-016 (secrets in logs); PY-068 / PY-069 (Python temp files and permissions); KV-139 / KV-140 (who can run a job on the runner that holds the residue); `references/methodologies/wallets-multisig-custody.md` W13.

#### Verification Procedure

**Step 1: Code and scripts do not write secret material to a shared or predictable temp path**
```
grep -rn -E "/tmp/|/var/tmp/|/dev/shm/|os\.tmpdir\(\)|temp_dir\(\)|gettempdir\(\)|mkstemp|mktemp|TMPDIR|%TEMP%|\$env:TEMP|GetTempPath|RUNNER_TEMP" --include="*.sh" --include="*.ts" --include="*.js" --include="*.mjs" --include="*.rs" --include="*.py" --include="*.go" --include="*.ps1" --include="*.yml" --include="*.yaml" --include="Makefile" --include="Dockerfile*" . 2>/dev/null | grep -iE "key|secret|seed|mnemonic|wallet|token|credential|\.pem|\.env|id\.json|password"
```
- ✅ PASS: secret material is passed by environment variable, stdin or file descriptor; where a file is unavoidable it is created with mode 0600 inside a private directory (`mktemp -d`, 0700; `tempfile.NamedTemporaryFile`, `fs.mkdtemp`, the `tempfile` crate), outside any shared path, and removed on every exit path (`trap ... EXIT`, `finally`, `defer`)
- ❌ FAIL: a key, seed, token or `.env` is written to a fixed name under `/tmp`, `/var/tmp`, `os.tmpdir()` or `%TEMP%`, or with default permissions, or without cleanup on failure
- If no code, script or workflow in scope handles secret material, record that and continue with Step 4

**Step 2: CI keeps secret files out of the workspace, artifacts and caches, and cleans up**
```
grep -rnE --include='*.yml' --include='*.yaml' -B2 -A6 '>[[:space:]]*"?[^|&]*\.(json|pem|key|env)|base64 (-d|--decode)|tee [^|]*\.(json|pem|key|env)|solana-keygen|\$\{\{ *secrets\.' .github/ .gitlab-ci.yml .circleci/ 2>/dev/null | grep -iE "upload-artifact|path:|cache|GITHUB_WORKSPACE|RUNNER_TEMP|rm -f|shred|if: *always|\.(json|pem|key|env)"
```
- ✅ PASS: a secret that must be a file is written under `$RUNNER_TEMP` (never the workspace), with mode 0600, and removed in a step marked `if: always()`; no `upload-artifact` or cache `path:` includes it or a parent directory; jobs that hold deploy or upgrade keys run on ephemeral runners
- ❌ FAIL: the file is written into the checkout, or a later step uploads or caches a directory that contains it, or there is no cleanup on failure, or the job runs on a persistent self-hosted runner that pull-request jobs also use

**Step 3: No secret travels on a command line, and no documented command teaches that**
```
grep -rn -iE "\-\-(private-key|secret(-key)?|seed|mnemonic|password|api-key|token)[ =]|export +[A-Z_]*(PRIVATE_KEY|SECRET|MNEMONIC|SEED|API_KEY|TOKEN)=|PRIVATE_KEY=[A-Za-z0-9]|set -x|set -o xtrace" --include="*.sh" --include="*.md" --include="*.yml" --include="*.yaml" --include="Makefile" --include="package.json" --include="*.ps1" . 2>/dev/null
```
- ✅ PASS: tools read secrets from a file path, an environment variable set by a secret manager, or a prompt; runbooks show `--keypair <path>` and never a literal key; scripts that handle secrets do not enable `set -x`
- ❌ FAIL: a script, Makefile, package script or runbook passes a key, seed or token as an argument, or documents `export PRIVATE_KEY=<value>` typed into a shell, or traces (`set -x`) a block that expands a secret

**Step 4: Keystore location and permissions are specified**
```
grep -rn -iE "id\.json|keypair|\.config/solana|keystore|wallet path|--keypair|ANCHOR_WALLET|provider\.wallet|chmod|icacls|dropbox|onedrive|icloud|google ?drive|backup" Anchor.toml docs/ runbooks/ README.md scripts/ .github/ 2>/dev/null
```
- ✅ PASS: the runbook names where each key lives (hardware wallet or multisig for deploy / upgrade / treasury authorities; a dedicated file outside the default path for automation), requires mode 0600 in a 0700 directory (or an ACL limited to one user on Windows), and forbids keystores inside sync folders, backup sets, `Downloads`, the desktop and the project directory
- ❌ FAIL: `Anchor.toml` or a deploy script points at `~/.config/solana/id.json` for a mainnet authority, or no document says where keys live and with which permissions

**Step 5: A residue inventory has been run on developer machines and servers (operator-run, paths and counts only)**
```
# Linux / macOS: candidate files in temp and drop locations (paths, modes and dates only)
find "${TMPDIR:-/tmp}" /tmp /var/tmp /dev/shm "$HOME/Downloads" "$HOME/Desktop" -maxdepth 4 -type f \( -iname '*keypair*.json' -o -iname 'id.json' -o -iname '*.pem' -o -iname '*.key' -o -iname '.env*' -o -iname '*mnemonic*' -o -iname '*seed*phrase*' -o -iname '*wallet*.json' \) -ls 2>/dev/null
# keypair-shaped JSON (an array of 64 numbers) anywhere in those places: file names only
grep -rlE '^\[([0-9]{1,3}, ?){63}[0-9]{1,3}\]$' "${TMPDIR:-/tmp}" /var/tmp "$HOME/Downloads" "$HOME/Desktop" 2>/dev/null
# keystore mode, and whether it sits in a synced folder
ls -ld "$HOME/.config/solana" "$HOME/.config/solana/"*.json 2>/dev/null
cd "$HOME/.config/solana" 2>/dev/null && pwd -P | grep -iE 'dropbox|onedrive|icloud|google ?drive|mobile documents'
# shell history: number of lines that look like a pasted secret (counts only)
grep -ciE 'private[-_]?key|mnemonic|seed phrase|solana-keygen recover|PRIVATE_KEY=' "$HOME/.bash_history" "$HOME/.zsh_history" 2>/dev/null
# editor copies beside key files, and core-dump policy
find "$HOME" -maxdepth 4 \( -name '*.json.swp' -o -name '*keypair*~' -o -name '*.pem.bak' -o -name '.env.swp' \) -ls 2>/dev/null
ulimit -c; cat /proc/sys/kernel/core_pattern 2>/dev/null
```
```
# Windows (PowerShell): names, sizes and dates only
Get-ChildItem $env:TEMP,"$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop" -Recurse -File -Depth 3 -Include *keypair*.json,id.json,*.pem,*.key,.env* -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime
(Select-String -Path (Get-PSReadLineOption).HistorySavePath -Pattern 'private[-_]?key|mnemonic|PRIVATE_KEY=' -ErrorAction SilentlyContinue).Count
```
- ✅ PASS: the team ran the inventory on every machine that has held a deploy, upgrade, treasury or automation key, recorded the result (date, host, hits as paths and modes), and repeats it on a schedule and when a machine changes hands
- ❌ FAIL: no inventory was ever run; or it found a keypair-shaped file in a temp, download or synced location, a keystore readable by group or others, or history lines with a pasted secret, and nothing followed

**Step 6: A key found outside its keystore is rotated, not deleted**
```
grep -rn -iE "rotat|revok|compromis|exposed|leak" docs/ runbooks/ SECURITY.md 2>/dev/null | grep -iE "key|keypair|authority|secret|token"
```
- ✅ PASS: the incident runbook treats any key that touched a shared temp directory, a CI workspace, a synced folder, a process argument or shell history as exposed: the authority is moved to a new key (`SetAuthority`, multisig member swap, API token revoked), the old key is retired, and deletion is recorded as cleanup, not as remediation
- ❌ FAIL: the response to a found key file is `rm`, or there is no rotation procedure for the authority that key holds (cross-ref SEC-048..052)

**Overall verdict:**
- ✅: No code, script or workflow writes secret material to a shared, predictable or uploaded path; secrets never travel as arguments; keystore location and permissions are specified and keep mainnet authorities off the default path and out of sync folders; a residue inventory has been run and recorded; found keys are rotated
- ⚠️: Code and CI are clean, but no inventory was ever run on the machines that held keys, or keystore rules exist only as habit, or rotation is undocumented
- ❌: A key, seed or token is written to `/tmp`, `os.tmpdir()`, `%TEMP%` or the CI workspace with a fixed name or default permissions, or is uploaded or cached, or is passed on a command line; or a mainnet authority sits at the default keypair path or inside a synced folder; or residue was found and only deleted
- N/A: The project holds no secret anywhere (no keypair, token or credential on a developer machine, server or CI); rare, and recorded explicitly when claimed
