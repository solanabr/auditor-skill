# Orchestration Boundary — auditor-skill × Trail of Bits

auditor-skill's native corpus is the **knowledge** layer (checklists, vectors, severity, gates).
Trail of Bits (vendored at `vendor/trailofbits`) is the **execution** layer — real tools that
auditor-skill's prose + grep cannot run. Subagents delegate to it when present, and fall back to
native grep checks when a clone has not initialized the submodule.

## Detection

Before delegating, confirm the submodule is present:

```
test -d vendor/trailofbits/plugins && echo present
```

If absent (submodule not initialized), run the native fallback and note in the report:
"deeper tooling available via `git submodule update --init --recursive`".

## Capability → plugin map

| Capability | ToB plugin (`vendor/trailofbits/plugins/…`) | auditor-skill use | Native fallback |
|------------|---------------------------------------------|-------------|-----------------|
| Interprocedural SAST (taint) | `static-analysis`, `semgrep-rule-creator`, `variant-analysis` | `vuln-hunter` runs SAST over in-scope languages; fold SARIF into verdicts | `discovery/grep-commands.md` scanners |
| Property / fuzz harnesses | `testing-handbook-skills`, `property-based-testing` | generate + run a harness for any ≥High arithmetic/economic finding (the Rule 5b PoC); `/auditor:poc` orchestrates this | checklist 16 "does the suite exist" prose checks |
| Coverage & mutation | `testing-handbook-skills`, `mutation-testing` | evidence-back FV coverage items; an uncaught mutant downgrades the corresponding checklist PASS; `/auditor:patch --verify-with-mutation` uses a caught mutant on the patched line as fix evidence | FV items marked `[PARTIAL — not machine-verified]` |
| Secret zeroization (IR-level) | `zeroize-audit` | verify KV-112 / RS-015 at the IR level | grep `zeroize`/`Zeroizing` on secret-bearing types |
| Constant-time (custom crypto) | `constant-time-analysis` | check secret-dependent branches when custom crypto is present | note "manual constant-time review needed" |
| Entry-point enumeration | `entry-point-analyzer` | seed the Phase 0 instruction matrix (has native Solana support) | manual `#[instruction]` enumeration |
| Supply-chain metadata | `supply-chain-risk-auditor` | enrich checklist 11 (SC-044..046) | `npm audit` / `cargo audit` + grep |
| Dimensional / unit analysis | `dimensional-analysis` | annotate + propagate units through DeFi value paths (checklist 03/06) — catches mixed-decimals / wrong-scale bugs | manual per-quantity unit tracking |
| Insecure-default trace | `insecure-defaults` | fail-open vs fail-secure path trace for suspected weak defaults (checklist 12/13) | grep fallback-secret patterns |
| API misuse / footguns | `sharp-edges` | misuse-resistance review of a program's own public/CPI interface + config schema | `references/framework-idioms/*` footgun catalog |

## FV / harness delegation gates

Before delegating an FV/fuzz harness (the `property-based-testing` / `testing-handbook-skills` /
`mutation-testing` rows above), apply the ladder in `references/audit-lifecycle/methodology.md` §6:

- **Trident stateful sequences first.** The default harness for any non-trivial program is
  **multi-instruction stateful** fuzzing (Trident / SVM-level), because most real Solana logic bugs
  live in cross-instruction state (ordering, accumulation, stale-state, multi-user interleaving), not
  in a single pure function. Delegate proptest-on-pure-functions as the cheap first probe, but treat
  the stateful Trident sequence as the **primary bug-finder** — do **not** escalate to deductive FV
  (Certora/Kani) for a property a stateful fuzzer would surface in minutes. Reserve Certora/Kani for
  the 3–10 invariants whose single counterexample is catastrophic.
- **Skip FV if the target is CPI-dominated.** Deductive/BMC proof reasons only about code you have.
  When an instruction's outcome is decided mainly by a **cross-program invocation into
  untrusted/foreign code** (aggregator swap, arbitrary callee, external program whose post-state
  cannot be modeled), FV cannot conclude anything useful — **do not spend the FV budget on it**.
  Fall back to Trident sequences that mock the CPI boundary adversarially plus manual CPI-trust review
  (`references/framework-idioms/anchor.md` per-CPI checklist). Note this abstention explicitly in the
  report's Assumptions & Simplifications section.

## Rule

Delegation **augments**, never replaces, the native verdict. Every finding still carries an
auditor-skill verdict and (if N ≥ 6) a filled Rule 5b gate. Tool output is *evidence*, not a verdict.
