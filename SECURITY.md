# Security Policy

auditor-skill is a security tool, so defects in it can cause harm twice: once to the projects audited with
it, and once to the machines that run it.

## What counts as a security issue here

- **Tooling that runs on a contributor's or user's machine**: `install.sh`, `scripts/*`, the Rust CLIs
  under `tools/auditor-tools`, the vendored submodule wiring, and the GitHub workflows. Anything that
  could execute unintended code, read or exfiltrate secrets, or write outside the expected paths.
- **The steps the commands run without asking**: the bundled entry points their `allowed-tools` pre-approve
  (`scripts/preflight.sh`, `rundir.sh`, `git-ro.sh`, the runners in `scripts/runner/`, the collectors,
  `audit-scan`, `audit-mem` and the rest [docs/permissions-and-isolation.md](docs/permissions-and-isolation.md)
  lists). Each is meant to be safe whatever arguments it gets. A way to make one write outside a run directory
  or the `audit-mem` store, run a program its arguments or the audited repository name, take a path outside
  the working directory, reach a host its documentation does not name, or run the project's code outside the
  recorded execution mode is a security issue. So is an allow rule that reaches a program outside that set.
- **Corpus content that could steer an auditor or an AI agent into a dangerous action** — for example a
  "verification step" that instructs running a destructive command, sending data to an external
  endpoint, or that materially misdescribes a vulnerability so that a real finding is dismissed.
- **Supply-chain concerns**: dependencies of the Rust tools, action pins in workflows, the install
  one-liner.

Ordinary corpus mistakes (a wrong severity, a missing check, a stale reference) are not security issues —
open a normal issue or a PR for those.

## How to report

Use GitHub's **private vulnerability reporting** on this repository (Security tab → "Report a
vulnerability"). Do not open a public issue or PR for a security problem.

Please include:

- a clear description of the issue and the affected file(s) or component;
- steps to reproduce or a proof of concept;
- impact as you understand it;
- a suggested fix if you have one.

Redact any credentials, keys or personal data from your report.

## What to expect

- Acknowledgement within a few business days.
- Validation, impact assessment and a fix prepared on a private branch, then released through the normal
  PR flow with credit to the reporter (unless you prefer to stay anonymous).
- Please hold public disclosure until a fix or mitigation is available; we will coordinate timing with you.

## Scope note

Findings *produced by* auditor-skill against third-party codebases are those projects' responsibility to
disclose. If you used this skill and found a vulnerability in someone else's software, report it to that
project through its own security process.
