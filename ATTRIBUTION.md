# Attribution & Credits

auditor-skill ships original, natively-authored content. Where it draws on external
security methodology it does so by *reference* — no third-party text is copied
into this repository — and credits the source here.

## Trail of Bits — audit skills (CC-BY-SA 4.0)

Source: https://github.com/trailofbits/skills

Vendored as a git submodule at `vendor/trailofbits` and invoked at runtime for
tool **execution** (static analysis, fuzzing, coverage, mutation, IR-level
analysis). A submodule is a reference (gitlink), not a copy, so no CC-BY-SA
ShareAlike obligation attaches to auditor-skill's own MIT-licensed corpus.

Several Trail of Bits *methodology patterns* are additionally re-implemented
natively, in our own words (not copied), and credited inline where used:

| Trail of Bits skill | auditor-skill implementation |
|---------------------|------------------------|
| `fp-check` / `second-opinion` | `OUTPUT-RULES.md` Rule 5b — Validation Gate |
| `audit-context-building` | `FULL-AUDIT.md` Phase 0.5 — Context Reconstruction |
| `code-maturity-assessor` | `FULL-AUDIT.md` Phase 4.5 — Maturity Assessment |
| `differential-review` | Mode 4 — Differential Audit |
| `spec-to-code-compliance` | Mode 5 — Spec Compliance |
| `agentic-actions-auditor` | `checklists/19-ai-agent-security.md` (Solana-ported CI vectors) |

## safe-solana-builder (MIT)

Source: https://github.com/frankcastleauditor/safe-solana-builder

Solana-specific secure-coding guidance was **adapted** — re-framed from build-time
to audit-time and re-expressed in our own words — into native auditor-skill content:

| safe-solana-builder reference | auditor-skill implementation |
|-------------------------------|------------------------|
| `shared-base.md §21` (reward accounting) | `checklists/06` §6.10 |
| `§23` + `anchor.md §4.1` (Token-2022) | `known-vectors/105` + `checklists/04` |
| `anchor.md` / `native-rust.md` / `pinocchio.md` idioms | `references/framework-idioms/*` |
| `litesvm.md` (test patterns) | `checklists/16` (test-suite verification) |
| `shared-base.md §25` (BPF stack frame) | `known-vectors/111` |
| `shared-base.md §5.3–5.5` (CPI trust boundary) | `checklists/04` RE-006/007 + `references/framework-idioms/anchor.md` |

## Knowledge sources

Taxonomy structure, exploit→vector mappings, and severity calibration were
informed by public post-mortems and publicly disclosed audit reports, and
re-expressed in our own words. No proprietary or trade-secret material is
included in this repository.
