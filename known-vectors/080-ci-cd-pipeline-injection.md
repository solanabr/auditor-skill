---
id: 80
title: "CI/CD Pipeline Injection"
severity: 9
category: devops
---

### 80 — CI/CD Pipeline Injection
**Severity: 9** | **Real: Codecov supply chain attack (2021), SolarWinds CI compromise; on GitHub Actions: Ultralytics (Dec 2024, `pull_request_target` branch-name injection plus cache poisoning), tj-actions/changed-files tag repointing (CVE-2025-30066, Mar 2025), Nx "s1ngularity" (Aug 2025, `pull_request_target` PR-title injection)**

Attacker modifies CI workflow or compromises CI tool — injects malicious code into build artifacts deployed to production.

> Cross-ref: checklist 13 §13.9 (DEP-067..071) and §13.13 (DEP-090..096); KV-139 (comment-triggered workflow without per-event author gating); KV-140 (`workflow_run` / `pull_request_target` pwn request incl. artifact and cache poisoning); KV-116 (AI agent in CI holding deploy keys); `references/vuln-classes/github-actions.md`; recipes R1–R9 in `discovery/grep-commands.md` ("GitHub Actions (CI trigger trust)").

#### Verification Procedure

**Step 1: List all CI workflows**
```
find .github -name '*.yml' -o -name '*.yaml' 2>/dev/null
grep -rn -A 12 --include='*.yml' --include='*.yaml' '^on:' .github/workflows/ 2>/dev/null | head -150
```
- Record: All workflow files and their trigger conditions

**Step 2: Check privileged triggers (`pull_request_target`, `workflow_run`) for fork-controlled checkouts**
```
grep -rnE --include='*.yml' --include='*.yaml' 'pull_request_target|workflow_run' .github/
grep -rnE --include='*.yml' --include='*.yaml' '^(ref:[ 	]*(.?\$\{\{.*((env|needs|steps|inputs|matrix)\.|\[)|[|>])|.*([ 	{,]ref:[ 	]*(.?\$\{\{.*((env|needs|steps|inputs|matrix)\.|\[)|[|>])|ref:[ 	]*.?\$\{\{.*(github\.event\.(pull_request\.(head\.(sha|ref)|merge_commit_sha)|workflow_run\.head_(sha|branch))|github\.head_ref|steps\.[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-]+\.outputs\.head_(sha|ref)|from(JSON|Json|json)\(steps\.[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-]+\.outputs\.[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_]+\)\.head\.(sha|ref))|repository:[ 	]*.?\$\{\{.*(github\.event\.pull_request\.head\.repo\.full_name|\[)|refs/pull/|gh pr checkout|git (fetch|pull|checkout).*(pull/|[Hh][Ee][Aa][Dd][._]([Ss][Hh][Aa]|[Rr][Ee][Ff]))|allow-unsafe-pr-checkout))' .github/
```
- ✅ PASS: No privileged trigger, or the privileged job checks out only the base ref with an `actions/checkout` that carries the fork-PR guard (v2.8.0 / v3.7.0 / v4.4.0 / v5.1.0 / v6.1.0 / v7.0.0 or later)
- ❌ FAIL: `pull_request_target` or `workflow_run` with a checkout or fetch of the PR / run head, or `allow-unsafe-pr-checkout: true` — forked PRs run arbitrary code with the base repository's secrets and write token. Full procedure: KV-140

**Step 3: Check for secret exposure in logs**
```
grep -rnE --include='*.yml' --include='*.yaml' '^.*echo.*(\$\{\{.*secrets[ 	]*(\.|\[|\))|\$\{?[ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*(SECRET|TOKEN|KEY))' .github/
```
- It lists each `echo` line that reads `secrets` inside a `${{ }}` expression (a field, an index, or the whole context, as `toJSON(secrets)` does), or that names a variable whose name holds `SECRET`, `TOKEN` or `KEY` (`$NPM_TOKEN`, `${NPM_TOKEN}`). A hit is a line to read: the expression may have closed before `secrets` (`echo "${{ github.sha }}" > secrets.txt`).
- ✅ PASS: Secrets never echoed in CI logs
- ❌ FAIL: Secrets printed to CI output (visible in logs)

**Step 4: Check action versions (pinned to SHA?), the release behind each SHA, and repointed tags**
```
grep -rnv --include='*.yml' --include='*.yaml' '^[ 	]*#[][	 !"#$%&'\''()*+,./0123456789:;<=>?@^_`abcdefghijklmnopqrstuvwxyz{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZ-]*$' .github/ | grep -aE '^.*uses["'\'']?[ 	]*:' | grep -avE '^[][	 !"#$%&'\''()*+,./0123456789;<=>?@^_`abcdefghijklmnopqrstuvwxyz{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZ-]*:[0123456789]+:[ 	]*(-[ 	]*)?(\{[ 	]*)?["'\'']?uses["'\'']?[ 	]*:[ 	]*.?[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]+/[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]+(/[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-]*)?@[0123456789abcdef]{40}([] 	"'\'',}]|$)' | grep -avE '^[][	 !"#$%&'\''()*+,./0123456789;<=>?@^_`abcdefghijklmnopqrstuvwxyz{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZ-]*:[0123456789]+:[ 	]*(-[ 	]*)?(\{[ 	]*)?["'\'']?uses["'\'']?[ 	]*:[ 	]*["'\'']?\./'
grep -rnv --include='*.yml' --include='*.yaml' '^[ 	]*#' .github/ | grep -aE '^[][	 !"#$%&'\''()*+,./0123456789;<=>?@^_`abcdefghijklmnopqrstuvwxyz{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZ-]*:[0123456789]+:[ 	]*(-[ 	]*)?(\{[ 	]*)?["'\'']?uses["'\'']?[ 	]*:[ 	]*.?[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]+/[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]+(/[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-]*)?@[0123456789abcdef]{40}([] 	"'\'',}]|$)'
```
- The second command (recipe R9) lists every action and reusable workflow pinned to a full SHA, with its version comment. The first lists every other `uses:` line: tags, branches, short SHAs, `docker://` images, and a pin R9 cannot read (one in a `{ … }` mapping after another key, a path holding a character other than a letter, a digit, `.`, `_`, `-` or `/`, or, under GNU or BSD grep, a bare SHA that ends a line of a file saved with CRLF line ends), which you grade by hand. Both read the value of the `uses` key that starts the line, quoted or not, so a trailing comment that names a pin or a local action moves nothing between them: a `uses:` line is in exactly one of the two unless it names a local action (`./`) or is commented out.
- A lone CR ends a YAML line but not a grep line, and so do U+0085, U+2028 and U+2029 for a YAML 1.1 parser, so the step after one shares the grep line of what comes before it. The first command skips a comment line only when it holds nothing but printable ASCII other than `\`, so it lists a step that follows such a character on a comment line, a pin included, since R9 skips every comment line. A step that follows one in the trailing comment of a local action is in neither list (Step 6 lists it). The cost is noise: a commented-out `uses:` on a line that also holds a letter outside ASCII or a `\` is listed, and so, under GNU or BSD grep, is one in a file saved with CRLF line ends.
- ✅ PASS: All actions pinned to full SHA (`@abc123...`), each the release its comment names (below), and kept current by a Dependabot or Renovate `github-actions` updater (DEP-067)
- ⚠️ PARTIAL: Actions pinned to version tag (`@v4`) — better than no pin, but tag can be moved
- ❌ FAIL: Actions referencing `@main` or `@latest`

**The release behind each SHA.** GitHub serves a commit that exists only in a fork through the parent's `owner/repo` slug, so a pin can carry a real version comment and still run code the action's maintainers never merged: an impostor commit (Chainguard, 2023). Check each repository the second command lists once, for all its pins:
- Run `d=$(mktemp -d "${TMPDIR:-/tmp}/ls-remote.XXXXXX") && HOME="$d" GIT_CEILING_DIRECTORIES="${d%/*}" GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C "$d" -c credential.helper= ls-remote --tags https://github.com/<owner>/<repo>`, with `<owner>/<repo>` the first two segments of the `uses:` value, and only when they match `^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`.
- It runs in a new empty directory, and stops when that cannot be made. `GIT_CEILING_DIRECTORIES` keeps git from reading the config of any repository that holds the directory, so no `url.<base>.insteadOf` sends the request elsewhere or answers it with refs of its own. The other settings keep the auditor's credentials out of a request for a repository the target chose: when GitHub asks for a login, no credential helper, askpass program, `~/.netrc` entry or terminal prompt answers.
- It asks for approval, because the URL comes from the target's workflows. A non-interactive run denies it: grade those pins `[PARTIAL]` (not verified).
- List github.com and the slugs sent in the report's outside-service list (OUTPUT-RULES Rule 11b).

In its output each line is `<sha>`, a tab and `refs/tags/<tag>`, and an annotated tag adds a `refs/tags/<tag>^{}` line that holds its commit. Grade each pin:
- ✅ PASS: the pinned SHA is on the line of the tag its comment names (`# v4.2.2`, `# tag=v4.2.2` or `# pin@v4.2.2`), or on that tag's `^{}` line.
- ⚠️ PARTIAL: it is not. `ls-remote` lists ref tips only, so a commit inside a branch's history is legitimate and unlisted, and a commit that exists only in a fork looks the same; telling them apart needs a fetch. Record which case it is: no version comment; a comment that names a moving tag (`v4`) or a branch; the SHA under another tag than the comment names (correct the comment); or the named tag at another commit (next paragraph).

**A repointed tag.** When an advisory reports that an action's tags were repointed (tj-actions/changed-files and reviewdog in 2025, trivy-action in 2026), or the tag a comment names lists another commit than the pin:
- ❌ FAIL: a workflow references that action by a tag or branch, so each run takes whatever the tag points to when the job starts; or a SHA pin is a commit the advisory names as malicious.
- ⚠️ PARTIAL: what the source cannot show. Without an advisory, the pin and the tag disagree because the tag moved after the pin was taken, or because the pin never was that release: name both commits for the owner to check against the action's releases. With one, which runs took the repointed commit, and what they could reach, is in the run history: name the runs in the advisory's window; the secrets and OIDC roles those jobs held (to rotate); their logs, public on a public repository (to delete); and the caches, artifacts and releases they wrote (to discard).
- The fix pins the SHA that `ls-remote` lists under a release the advisory names as clean.

**Step 5: Check for write permissions**
```
grep -rn "permissions:" .github/workflows/ | head -10
grep -rn "GITHUB_TOKEN" .github/workflows/
```
- ✅ PASS: Minimum permissions declared (e.g., `contents: read`), no unnecessary write access
- ❌ FAIL: Default permissions (full read-write) used
- ⚠️ PARTIAL: No `permissions:` block, so the scope depends on the repository's default-token setting, which the source does not show

**Step 6: Check for third-party CI tools**
```
grep -rnv --include='*.yml' --include='*.yaml' '^[ 	]*#' .github/ | grep -aE '^.*uses["'\'']?[ 	]*:' | grep -avE '^[][	 !"#$%&'\''()*+,./0123456789;<=>?@^_`abcdefghijklmnopqrstuvwxyz{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZ-]*:[0123456789]+:[ 	]*(-[ 	]*)?(\{[ 	]*)?["'\'']?uses["'\'']?[ 	]*:[ 	]*["'\'']?(actions/|github/|\./)[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/@-]*["'\'']?[] 	},]*([ 	]#.*)?$'
```
- It lists every `uses:` under `.github/`, in workflows and composite actions alike, that names neither an action of GitHub's `actions/` or `github/` organization nor a local action (`./`): third-party actions and reusable workflows, and `docker://` images. Like Step 4, it reads the value of the `uses` key that starts the line, quoted or not, and it leaves a line out only when nothing but blanks, a `}`, a `]`, a comma or a comment follows an official or local value. So a trailing comment that names an official action hides nothing, and a line that holds more is listed whatever it names: another entry of a flow sequence (`{uses: actions/checkout@v4}, {uses: example/x@v1}`), another key, or a `uses:` after another key of a `{ … }` mapping. Under GNU or BSD grep an official `uses:` line of a file saved with CRLF line ends is listed too. A key spelled with an escape inside quotes, or as a `? ` complex key, is read neither here nor in Step 4.
- A local action runs whatever the workspace holds at its path when its step starts: check that no earlier step fills that path with code from elsewhere (an `actions/checkout` with `repository:` and `path:`, a downloaded artifact or cache), and grade an action filled that way as a third-party one, pinned only as far as that checkout's `ref:` pins it.
- ✅ PASS: Only official GitHub Actions or well-known, audited third-party actions
- ⚠️ PARTIAL: Some third-party actions from less-known orgs
- ❌ FAIL: Third-party actions from unknown sources without version pinning

**Step 7: Check comment- and issue-triggered jobs for an author gate**
```
grep -rlE --include='*.yml' --include='*.yaml' -e '^[ 	]*-?[ 	]*(issue_comment|pull_request_review_comment|pull_request_review|discussion_comment|discussion|issues)[ 	]*(:[ 	]*([{[&*~]|null|(#.*)?.?$)|[],]|(#.*)?.?$)' -e "^.{0,3}[\"']?on[\"']?[ 	]*:.*(issue_comment|pull_request_review|discussion|issues)" -e "^[ 	]*-?[ 	]*[\"'](issue_comment|pull_request_review_comment|pull_request_review|discussion_comment|discussion|issues)[\"']" .github/
echo 'second list: files under .github/ that mention author_association'
grep -rl --include='*.yml' --include='*.yaml' '^[][	 !"$%&'\''()*+,./0123456789:;<=>?@^_`abcdefghijklmnopqrstuvwxyz{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZ-]*author_association' .github/
```
- Read each file in the first list and not in the second: it has one of these triggers and no line that mentions `author_association` after nothing but printable ASCII other than `#` and `\` (so not inside a comment)
- Run `find .github -name '*[[:cntrl:]]*'` too: a file or directory name holding a newline can forge lines in both lists, so any output means reading every workflow
- ✅ PASS: Every privileged job on these triggers gates on the triggering object's own `author_association`, paired per event
- ❌ FAIL: A privileged job starts on a mention or command alone, or reads the opener's association on a comment event. Full procedure: KV-139

**Step 8: Check self-hosted runners: who can start a job on them, and what one job leaves for the next**
```
grep -rnv --include='*.yml' --include='*.yaml' '^[ 	]*#' .github/ | grep -aE '^.*runs-on["'\'']?[ 	]*:' | grep -avE '^[][	 !"#$%&'\''()*+,./0123456789;<=>?@^_`abcdefghijklmnopqrstuvwxyz{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZ-]*:[0123456789]+:[ 	]*["'\'']?runs-on["'\'']?[ 	]*:[ 	]*["'\''[]?(ubuntu-(latest|slim|(22|24|26)\.04(-arm)?)|windows-(latest|2022|2025|2025-vs2026|11-arm|11-vs2026-arm)|macos-(latest|15|26)(-large|-xlarge)?|macos-(15|26)-intel|xcode-27(-xlarge)?)[]"'\'']?[ 	]*(#.*)?$'
grep -rnv --exclude-dir=node_modules --exclude-dir=.terraform --include='*.tf' --include='*.hcl' --include='*.json' --include='*.yml' --include='*.yaml' --include='*.sh' '^[ 	]*#' . | grep -aE '^.*(config\.sh.*--(url|token)|--jitconfig|ephemeral(_runners)?"?[ 	]*[:=]|allows_public_repositories|runner_?[Gg]roup)'
```
- The first command lists each `runs-on:` that is not one of GitHub's standard hosted labels or macOS larger-runner labels (as docs.github.com listed them on 2026-11-03: `ubuntu-latest`, `ubuntu-slim`, `ubuntu-22.04`/`24.04`/`26.04` and their `-arm` forms, `windows-latest`, `windows-2022`, `windows-2025`, `windows-2025-vs2026`, `windows-11-arm`, `windows-11-vs2026-arm`, `macos-latest`, `macos-15`, `macos-26` and their `-large`/`-xlarge` forms, `macos-15-intel`, `macos-26-intel`, `xcode-27`, `xcode-27-xlarge`): `self-hosted`, a `group:`, a custom label (an Actions Runner Controller scale set is addressed by its name, which may well start with `ubuntu-`), an Ubuntu or Windows larger runner (GitHub-hosted, but addressed by the name its organization gave it), a label GitHub added since, an expression, or a value on the lines below. A label GitHub retires stays excluded until this list is edited, so compare the list with docs.github.com's before relying on it. Confirm with the owner which listed labels are self-hosted. It reads the label after the `runs-on` key that starts the line, quoted or not and with or without blanks before its colon, so a trailing comment that names a hosted label hides nothing, and a `runs-on` anywhere else on a line (inside a `{ … }` mapping, say) is listed whatever it holds. A key spelled with an escape inside quotes, or as a `? ` complex key, is not read: read the `runs-on` of every job that a fork pull request, a comment or an issue can start. Under GNU or BSD grep a bare label that ends a line of a file saved with CRLF line ends is listed too. The second lists runner registrations and runner-group settings in the repository's infrastructure code; runner infrastructure often lives in another repository, so run it there too when the owner names one. Claude Code's grep skips every file an ignore rule names and every file it reads as binary, so also read each infrastructure file that `"<auditor-skill root>/scripts/git-ro.sh" ls-files -- '*.tf' '*.hcl' '*.json' '*.yml' '*.yaml' '*.sh' ':(exclude,glob)**/node_modules/**' ':(exclude,glob)**/.terraform/**'` lists and the session's grep does not read (`discovery/grep-commands.md`, Known limits, gives the grep to compare with). GNU grep in a UTF-8 locale prints no line that holds a byte that is not UTF-8, only a note on stderr that a binary file matches, so also read whole each file such a note names.
- Record per listed job: its trigger (Step 1), whether the repository is public, and who can start it (fork pull requests, comments, issues: `references/vuln-classes/github-actions.md` §2.4).
- ✅ PASS: no job runs on a self-hosted runner; or every self-hosted runner a job reaches is ephemeral (registered with `config.sh --ephemeral`, started with `run.sh --jitconfig`, or an Actions Runner Controller scale set), and its runner group admits no public repository and only the workflows that need it.
- ❌ FAIL: on a public repository, a job that a fork pull request, a comment or an issue can start runs on a persistent self-hosted runner; or the infrastructure code registers persistent runners (no `--ephemeral`, `ephemeral: false`, `enable_ephemeral_runners = false`) into a runner group with `allows_public_repositories = true`. A persistent runner keeps files, processes and its own registration credentials from one job to the next, so one job can leave code that a later release job runs (the PyTorch research, Stawinski and Khan, 2024).
- ⚠️ PARTIAL: a persistent runner that only collaborators' jobs reach, which is a hardening gap (release and deploy jobs get runners of their own); and what GitHub's settings hold when the source does not show it: whether a runner is ephemeral, which repositories and workflows its group admits, and the fork pull request approval policy. Name each for the owner to confirm.

**Overall verdict:**
- ✅: Actions SHA-pinned to the releases their comments name, minimal permissions, no fork-controlled code in privileged triggers, comment triggers author-gated, secrets protected, self-hosted runners ephemeral and closed to public repositories
- ⚠️: Version-tag pinned, reasonable permissions, known action vendors; pins or runner settings not yet verified
- ❌: Unpinned actions, privileged trigger with PR checkout, ungated comment-triggered privileged job, secrets in logs, a tag reference to an action whose tags were repointed, a persistent self-hosted runner that outside accounts can reach
