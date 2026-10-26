# Patch verification — `{FINDING_ID}`

The proof block for `{FINDING_ID}.patch`. It records HOW the fix was proven, not just
that it was written. Emitted to `audit_<n>/patches/VERIFICATION.md` (one block per
patch) and its verdict updates the finding's **Auditor Verification** line in the
report.

Verification is by **execution**, on a throwaway copy. Never write to the client's
real tree: apply the patch to a **scratch git worktree**, build there, run there,
discard it.

## 1. Apply (scratch worktree — never the client checkout)

The rebuild runs target-controlled code (build scripts, proc-macros, toolchain files), so it follows the
execution mode recorded at intake — `OUTPUT-RULES.md` Rule 11a (isolated recommended; native allowed and
stated in the report). If it cannot run in that mode, stop at `[FIX-PROPOSED]`. The bundled runner builds in
a scratch clone it makes outside the target tree (Rule 11c): no git command runs in the client checkout, and
nothing is written in it but the run directory. `{PATH_TO}` is the run directory, `audit_<n>` or
`incident_<n>`, relative to the working directory; `{COMMIT}` is the audited commit. Run each line from the
working directory, with no `cd` first.

```bash
# the unpatched build, then the patched one; each keeps its .so in {PATH_TO}/exec/build-sbf-<k>/
"<auditor-skill root>/scripts/runner/target.sh" build-sbf --run {PATH_TO} --src . --rev {COMMIT}
"<auditor-skill root>/scripts/runner/target.sh" build-sbf --run {PATH_TO} --src . --rev {COMMIT} --patch {PATH_TO}/patches/{FINDING_ID}.patch
```

Exit 3 ending `does not apply to <commit>` means the patch does not apply; exit 1 means the patched program
does not build. The last line names the log, `{PATH_TO}/exec/build-sbf-<k>.log`, and the `.so`.

- [ ] Patch applied cleanly against `{COMMIT}` (no fuzz, no reject `.rej` files).
- [ ] Patched program builds.

## 2. PoC now reverts (mandatory for [FIX-VERIFIED])

Re-run the finding's own exploit against the **patched** build. The line that
previously succeeded must now fail. Refresh the crate's harness from the installation
first, so the run is the installation's `run.sh` and assertions, and run the crate only
through that `run.sh`.

```bash
cp "<auditor-skill root>/templates/poc/shared-test-utils/src/lib.rs" {PATH_TO}/poc/{FINDING_ID}/shared-test-utils/src/lib.rs
# {PATH_TO}: the run directory, audit_<n> or incident_<n>, relative to the working directory; its
# exec-mode file holds the execution mode recorded at intake (OUTPUT-RULES.md Rule 11a)
"<auditor-skill root>/templates/poc/run.sh" --crate {PATH_TO}/poc/{FINDING_ID}    # minimized model (src/fixed.rs: the patch on src/vulnerable.rs)
"<auditor-skill root>/templates/poc/run.sh" --crate {PATH_TO}/poc/{FINDING_ID} --vulnerable-so {UNPATCHED_SO} --fixed-so {PATCHED_SO}   # patched target build: files under {PATH_TO}/exec/
```

**Re-detonated against:** {patched target build (`--vulnerable-so` / `--fixed-so` — `templates/poc/run.sh`) | minimized model}
— a *patched target build* runs `run.sh` with `--vulnerable-so` = the unpatched build and `--fixed-so` = the
patched build of the target itself. That is `run.sh`'s prebuilt mode: it exits 3 unless both files are ELF
programs and each arm's contract assertion ran and held on the bytes `run.sh` placed (loaded through
`mollusk_for` or `litesvm_for!`) — `assert_exploit_effect!` in `tests/exploit.rs` on the unpatched bytes,
`assert_exploit_rejected_with!` (the guard's exact error) in `tests/fixed_blocked.rs` on the patched ones.
Only a final line ending in `(rejected with the pinned error) → [PoC-REPRODUCED]` verifies our patch. An exit
2 ending `FAIL: the fixed arm accepted the attack …` means it did not block the attack; one ending `FAIL: the
fixed arm rejected the attack with another error than the pinned one …` means the patched build stops it with
another error than the guard's, which is no revert of the cited guard. Exit 3 decides nothing (no contract
assertion ran, the harness could not decide — a harness error, on either arm — or other bytes ran): record
`run.sh`'s blocker line verbatim with the flag "PoC re-run needed", never as a revert. A PoC written with the any-result `assert_exploit_succeeds!` /
`assert_exploit_rejected!` switches to these first. The PoC must also use the program's real id, since an
Anchor program checks its own `declare_id!`; `run.sh` does not check that. The *minimized model* is the PoC
crate's own arms, with `src/fixed.rs` made from `src/vulnerable.rs` with the patch transplanted (it must equal
the `fixed` arm `patch.md` describes): `run.sh` with no overrides must exit 0, ending in the model line.

- **Pre-fix (recorded when the PoC was built):** `tests/exploit.rs` SUCCEEDED on the
  `vulnerable` arm — the attack went through. → `[PoC-REPRODUCED]`
- **Post-fix (this step):** with the patch transplanted onto `src/vulnerable.rs` as
  `src/fixed.rs`, or with the patched target build as `--fixed-so`, the same attack in
  `tests/fixed_blocked.rs` must now be **rejected** on the fixed arm: `run.sh` exits 0 —
  the previously-open path is closed.

- [ ] The finding's exploit **reverts** on the patched build (`run.sh` exit 0: was Ok → now Err).
- [ ] The legitimate path still works (a positive test for the honest caller passes).

Reading the diff is not verification. Only an executed revert of the finding's own
exploit earns `[FIX-VERIFIED]`. If there is no executable PoC to run, stop at
`[FIX-PROPOSED]` and say so.

## 3. Mutation + blast-radius (optional, strengthens the verdict)

- **Mutation on the patched line** — run `mewt` (Trail of Bits `mutation-testing`,
  see `references/orchestration/boundary-map.md`) on exactly the line(s) the patch
  added. A **surviving mutant** on the fix means the guard is under-tested: the test
  suite would not catch the fix being silently broken later. Record it; do not
  overstate the verification.

  ```bash
  mewt init                                      # once per crate: writes mewt.toml + mewt.sqlite
  mewt mutate {FILE}                             # optional: generate mutants without testing them
  mewt run {FILE}                                # generate the mutants and run the tests
  mewt results --target '{FILE}' --line {LINE}   # uncaught mutants on the patched line
  ```
  Interface as documented by the vendored `mutation-testing` skill (mewt 4.x); `mewt --help`
  is authoritative. A mutation run executes the target's tests, so it follows Rule 11a too.
  - [ ] No surviving mutant on the patched line(s) — or the survivor is recorded and
        the verdict is not overstated.

- **Blast-radius** — run a `differential-review` check (Trail of Bits): confirm the
  diff closes the exploit path and leaves **every other path unchanged**. A fix that
  breaks an adjacent instruction is `[FIX-INSUFFICIENT]`, however well it closes the
  cited bound. Without the vendored tooling, use the differential execution of
  `/auditor:re-audit` step 4b.
  - [ ] No adjacent path regressed.

## 4. Post-patch validation (opt-in, isolated mode only)

Only with `/auditor:patch --post-patch-validation`. Trail of Bits `post-patch-validation` checks the patch
against the finding, variants of its root cause and behavior that should not change. Its runner creates, locks
and prunes git worktrees in the repository it is given, and its checks build and run the target with the
caller's privileges and an open network. So it runs only in Rule 11a **isolated** mode, on the isolated
runner, and on a no-checkout clone, outside the target tree, of the copy `git-ro.sh copy` makes in `{R}`:
never on the client checkout. Run the first block from the top level of the repository under audit. It runs
nothing, and prints the line to record, unless the stricter of the recorded mode (`{R}/exec-mode`, or
`intake.md` §8 without it) and `AUDITOR_EXEC_MODE` is isolated (`none` stops it, as it stops `run.sh`),
`probe.sh --only isolation` finds none of the credentials it checks readable, the vendored skill and `uv` are
there, and `git-ro.sh copy` takes the checkout. That copy refuses a partial clone, a git without the May-2024
clone fixes, borrowed objects (alternates) and links. When a block stops on an error instead, record "not run:
<its first error line>". Each block asks for approval: it is shell code, and it runs the Trail of Bits
runner, which no bundled tool wraps.

The placeholders here are this section's own. `{R}` is the run directory, `audit_<n>` or `incident_<n>`,
relative to the working directory; `{MODE}` is the word `{R}/exec-mode` holds or, when there is no such file,
the mode `{R}/intake.md` §8 records (for an incident, the mode in its ledger header); `{FINDING_ID}` is the
finding or incident id; `{COMMIT}` is the commit the patch targets; `{ROOT_CAUSE}` is the finding's root cause
and impact in one sentence, without a single quote; `{LEVEL}` is the highest evidence level the checks will
honestly reach (`source`, `build` or `runtime`, as the skill defines them).

```bash
ROOT="<auditor-skill root>"
PPV_RUNNER="$ROOT/vendor/trailofbits/plugins/post-patch-validation/skills/post-patch-validation/scripts/post_patch_validation.py"
case " {MODE} ${AUDITOR_EXEC_MODE:-} " in       # the stricter of the recorded mode and AUDITOR_EXEC_MODE, as run.sh takes it
  *" none "*) PPV_MODE=none ;;
  *" isolated "*) PPV_MODE=isolated ;;
  *) PPV_MODE=native ;;
esac
if [ "$PPV_MODE" != isolated ]; then
  echo "post-patch validation: not run: needs isolated mode"
elif [ "$("$ROOT/scripts/runner/probe.sh" --only isolation 2>/dev/null)" != "isolation: none of the credentials the self-check reads is readable" ]; then
  echo "post-patch validation: not run: this is not the isolated runner (scripts/runner/probe.sh --only isolation)"
elif [ ! -f "$PPV_RUNNER" ] || ! command -v uv >/dev/null 2>&1; then
  echo "post-patch validation: not run: needs the vendored post-patch-validation skill and uv"
elif ! PPV_SRC="$("$ROOT/scripts/git-ro.sh" copy . "{R}")"; then
  echo "post-patch validation: not run: git-ro.sh copy refused the checkout"
else
  PPV_SRC="$(pwd -P)/$PPV_SRC" && PPV_PATCH="$(pwd -P)/{R}/patches/{FINDING_ID}.patch" &&
    PPV="$(mktemp -d "${TMPDIR:-/tmp}/ppv-{FINDING_ID}.XXXXXX")" &&
    cd "$PPV" &&
    GIT_NO_LAZY_FETCH=1 git clone -q --no-local --no-checkout --template= "$PPV_SRC" "$PPV/repo" &&
    mkdir -p "$PPV/repo/.git/info" && printf '* !filter\n' > "$PPV/repo/.git/info/attributes" &&
    mkdir "$PPV/plan" &&
    uv run --no-config "$PPV_RUNNER" scaffold --repo "$PPV/repo" --base-ref {COMMIT} \
      --patch-file "$PPV_PATCH" --finding-id {FINDING_ID} --finding-summary '{ROOT_CAUSE}' \
      --evidence-level {LEVEL} --output "$PPV/plan/plan.json" &&
    echo "post-patch validation: plan at $PPV/plan/plan.json"
fi
```

The clone has no work tree checked out. The `* !filter` line in its `info/attributes`, which the runner's
worktrees read too, turns every clean and smudge filter off, so a git-lfs filter in the caller's own git config
never runs on a checkout there and never contacts the LFS host the repository names. `uv run --no-config`
reads no `uv.toml` or `pyproject.toml` above the scratch directory.

Fill in the plan's checks as the skill's `SKILL.md` describes, at least one of every kind, with any helper
files under `{PPV}/plan/checks/`, and change nothing else in `plan.json`; `{PPV}` is the directory the first
block printed. Run the runner only through these two blocks: the skill's own examples pass `--repo .`, which
during an audit is the client checkout. Then run the plan; nothing runs unless `plan.json` still names the
clone:

```bash
PPV_RUNNER="<auditor-skill root>/vendor/trailofbits/plugins/post-patch-validation/skills/post-patch-validation/scripts/post_patch_validation.py"
cd "{PPV}" && if [ -d repo/.git ] &&                                   # outside the target tree, as above
    [ "$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["repository"])' plan/plan.json 2>/dev/null)" = ../repo ]; then
  uv run --no-config "$PPV_RUNNER" validate-plan --plan "{PPV}/plan/plan.json" &&
    uv run --no-config "$PPV_RUNNER" run --plan "{PPV}/plan/plan.json" --output "{PPV}/results"   # exit 0, 1 or 10 leaves results/result.json
else
  echo "post-patch validation: not run: plan/plan.json must name ../repo, the disposable clone"
fi
```

If the runner stops on a submodule, record "not run: the patch touches submodule <path>, which the disposable
clone does not hold". Never fetch or initialize submodules in the clone.

**Post-patch validation:** {not run: <the line a block printed, or its first error line> | ran: evidence level <source / build / runtime>, assessment <complete / incomplete>}
- **Findings:** {each `check_id` (kind): message, as `results/result.json` gives it | none}
- **Gaps:** {each `check_id`: reason | none}
- **Effect on the verdict:** {none | lowered from `[FIX-VERIFIED]` to `[FIX-INSUFFICIENT]` by `check_id` (kind) | recorded under Residual, tier unchanged: `check_id` (kind)}

The result is optional evidence and can only lower the verdict. A finding, a failure it attributes to the
patched revision (a root-cause variant the patch leaves open, a behavior it changes, a regression it brings
in), makes a `[FIX-VERIFIED]` tier `[FIX-INSUFFICIENT]` (a `[FIX-PROPOSED]` one keeps its tier and records the
finding under Residual), with that check as what remains open. Read the check and its saved logs first: the runner shows
that a check behaved as written, not that it is the right check. Passing checks and gaps change nothing, and a
passing run never stands in for §2's executed revert. List what its checks contacted (package registries,
toolchain downloads, hosts the target's code or tests reach) under outside services in the report (Rule 11b).
Discard `{PPV}` once this section is filled in.

## 5. Verdict → report's Auditor Verification field

Emit exactly one, and write it to the finding's **Auditor Verification** line:

| Verdict | Condition |
|---------|-----------|
| `[FIX-VERIFIED]` | Patch applied to a scratch worktree, rebuilt, and the finding's PoC **re-ran and now reverts**. Optional mutation/blast-radius clean. |
| `[FIX-INSUFFICIENT]` | The PoC still exploits a residual path, a mutant survives on the patched line, or an adjacent path regressed (blast-radius). State exactly what remains open. |
| `[FIX-PROPOSED]` | A minimal idiomatic diff re-derived from the code closes the cited bound, but **no executable PoC was available** to run the revert. Verified by reasoning, flagged not-yet-executed — never silently promoted. |

Opt-in Trail of Bits `post-patch-validation` (`/auditor:patch --post-patch-validation`, isolated mode only, on a disposable clone) is optional evidence that can only lower a tier: a finding in its result turns `[FIX-VERIFIED]` into `[FIX-INSUFFICIENT]`, with that check as the reason; a `[FIX-PROPOSED]` or `[FIX-INSUFFICIENT]` patch keeps its tier and records the finding under Residual, and nothing else in its result changes a tier.

**Verdict:** `{FIX-VERIFIED | FIX-INSUFFICIENT | FIX-PROPOSED}`
**What a maintainer must do to apply:** {e.g. `git am < {FINDING_ID}.patch` on `{COMMIT}`, `cargo build-sbf`, run the crate's own tests.}
**Residual (if any):** {what is still open, for INSUFFICIENT or a post-patch-validation finding — else "none".}

---

A cosmetic patch is **not** a fix. Never claim `[FIX-VERIFIED]` without an executed
revert of the finding's own exploit. This document is proposal-grade evidence for the
client to apply and re-test on their side — the audit does not touch their real tree.
