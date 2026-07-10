# Orchestration Boundary — AUDITOR × Trail of Bits

AUDITOR's native corpus is the **knowledge** layer (checklists, vectors, severity, gates).
Trail of Bits (vendored at `vendor/trailofbits`) is the **execution** layer — real tools that
AUDITOR's prose + grep cannot run. Subagents delegate to it when present, and fall back to
native grep checks when a clone has not initialized the submodule.

## Detection

Before delegating, confirm the submodule is present:

```
test -d vendor/trailofbits/plugins && echo present
```

If absent (submodule not initialized), run the native fallback and note in the report:
"deeper tooling available via `git submodule update --init --recursive`".

## Capability → plugin map

| Capability | ToB plugin (`vendor/trailofbits/plugins/…`) | AUDITOR use | Native fallback |
|------------|---------------------------------------------|-------------|-----------------|
| Interprocedural SAST (taint) | `static-analysis`, `semgrep-rule-creator`, `variant-analysis` | `vuln-hunter` runs SAST over in-scope languages; fold SARIF into verdicts | `discovery/grep-commands.md` scanners |
| Property / fuzz harnesses | `testing-handbook-skills`, `property-based-testing` | generate + run a harness for any ≥High arithmetic/economic finding (the Rule 5b PoC) | checklist 16 "does the suite exist" prose checks |
| Coverage & mutation | `testing-handbook-skills`, `mutation-testing` | evidence-back FV coverage items; an uncaught mutant downgrades the corresponding checklist PASS | FV items marked `[PARTIAL — not machine-verified]` |
| Secret zeroization (IR-level) | `zeroize-audit` | verify KV-112 / RS-015 at the IR level | grep `zeroize`/`Zeroizing` on secret-bearing types |
| Constant-time (custom crypto) | `constant-time-analysis` | check secret-dependent branches when custom crypto is present | note "manual constant-time review needed" |
| Entry-point enumeration | `entry-point-analyzer` | seed the Phase 0 instruction matrix (has native Solana support) | manual `#[instruction]` enumeration |
| Supply-chain metadata | `supply-chain-risk-auditor` | enrich checklist 11 | `npm audit` / `cargo audit` + grep |

## Rule

Delegation **augments**, never replaces, the native verdict. Every finding still carries an
AUDITOR verdict and (if N ≥ 6) a filled Rule 5b gate. Tool output is *evidence*, not a verdict.
