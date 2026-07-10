# Framework Idioms — Anchor (Audit Checks)

> **Purpose:** What to verify and what fails when auditing an Anchor program.
> **Scope:** Anchor 0.30 → 1.x. Read alongside `.claude/rules/anchor.md` (build-side conventions).
> **How to use:** Each idiom below is framed as an auditor check — the *safe shape*, the
> *failure mode*, and the *grep* to find it. These are Anchor-specific footguns; the
> language-agnostic checks live in `checklists/01`–`07`.
>
> *(Adapted from safe-solana-builder `references/anchor.md`.)*

---

## 1. Account-type wrappers — the wrong wrapper skips a check

Anchor's typed wrappers do owner + discriminator + signer + executable checks *for free*.
The vulnerability is almost always the **downgrade**: a developer reaches for
`AccountInfo` / `UncheckedAccount` and then hand-parses, silently dropping the checks
Anchor would have enforced.

| Wrapper | Checks Anchor performs | What its absence means |
|---|---|---|
| `Account<'info, T>` | owner == declaring program, 8-byte discriminator == `T`, deserializes `T` | Raw bytes trusted as `T` → **type cosplay** |
| `Signer<'info>` | `is_signer == true` | Authority assumed, never proven |
| `SystemAccount<'info>` | owner == System Program | Wrong-owner account accepted |
| `Program<'info, T>` | executable + program ID == `T::id()` | Arbitrary program substituted in a CPI |
| `InterfaceAccount<'info, T>` | owner ∈ {Token, Token-2022}, discriminator | Token-2022 mint mis-handled |
| `UncheckedAccount` / `AccountInfo` | **NONE** | Everything is manual — must be audited by hand |

**Auditor check**
- ✅ PASS: every account holding typed program data uses `Account<'info, T>` (or the
  `InterfaceAccount` form). Every `UncheckedAccount` / `AccountInfo` has a
  `/// CHECK:` comment that states a *specific, verifiable* reason, and the body actually
  performs the check that comment promises.
- ❌ FAIL: `AccountInfo`/`UncheckedAccount` used for data that is later deserialized, with
  no manual owner/discriminator check — or a `/// CHECK:` comment that is boilerplate
  ("this is safe") rather than an argument.

```
grep -rn -E "UncheckedAccount|AccountInfo<" programs/
grep -rn -B2 "CHECK" programs/          # inspect every safety comment for a real reason
```

---

## 2. `has_one` — declare relationships, and back critical ones with a runtime assert

`has_one = authority` makes Anchor verify `account.authority == ctx.accounts.authority.key()`
at deserialization. This *replaces* manual pubkey comparison inside the handler and is the
correct first line of defense.

**Where it silently does nothing:**
- `has_one = x` only checks equality against a **field named `x`** on the deserialized
  struct. If the field is misnamed, or the relationship is between two *other* accounts
  (not a field of this one), `has_one` cannot express it — the check must be manual.
- `has_one` verifies *linkage*, not *authorization*. It proves `authority` is the stored
  authority; it does **not** prove that account signed. Pair it with `Signer<'info>` or a
  `require!(...is_signer)`.

**Defense-in-depth idiom (verify both layers exist for money-movement / admin paths):**

```rust
#[account(mut, has_one = authority @ ErrorCode::AuthorityMismatch)]
pub vault: Account<'info, Vault>,
pub authority: Signer<'info>,
// ...and in the handler, for the highest-value operations, a redundant guard:
require_keys_eq!(ctx.accounts.vault.authority, ctx.accounts.authority.key(),
                 ErrorCode::AuthorityMismatch);
```

The runtime `require_keys_eq!` is deliberate redundancy: it survives a later refactor that
accidentally drops the constraint, and it documents intent at the call site.

**Auditor check**
- ✅ PASS: every "belongs-to" relationship is enforced by `has_one` (or an explicit
  `require_keys_eq!`), and privileged paths also assert the linked account **signed**.
- ❌ FAIL: relationship enforced only by a comment; or `has_one` present but no signer
  requirement on the linked authority; or the handler re-derives/compares keys with `==`
  instead of `require_keys_eq!` (raw `==` that ignores the result is a classic miss).

```
grep -rn "has_one" programs/
grep -rn -E "\.key\(\) ==|\.key\(\) !=" programs/   # manual compares that should be has_one / require_keys_eq!
```

---

## 3. `init_if_needed` — the reinitialization trap

`init` creates the account and **fails if it already exists** — this is what makes an
initializer callable exactly once (it sets discriminator + owner atomically).

`init_if_needed` creates *or silently reuses* an existing account. That is a footgun:
an attacker can **pre-create the account with attacker-chosen state**, then call your
"initialize" and have your handler operate on their malicious pre-image. The
discriminator/owner are already set, so nothing trips.

**Auditor check**
- ✅ PASS: initializers use `init`. Any `init_if_needed` is justified in a comment **and**
  the handler explicitly re-validates the pre-existing state before trusting it — e.g.
  gates on an `initialized` flag or asserts the stored authority equals the caller:
  ```rust
  require!(!state.initialized || state.authority == ctx.accounts.user.key(),
           ErrorCode::AlreadyInitialized);
  ```
- ❌ FAIL: `init_if_needed` with no post-conditions — the handler assumes a fresh account.
- ⚠️ Also confirm the `init-if-needed` Cargo feature is enabled deliberately, not pulled in
  transitively, and that the program does not conflate "create" and "update" logic in one
  path.

```
grep -rn "init_if_needed" programs/
grep -rn 'features *=.*"init-if-needed"' programs/*/Cargo.toml
```

---

## 4. `.reload()` after CPI — mandatory, not optional

Anchor deserializes account data **once**, at instruction entry, and caches the struct in
memory. A CPI that mutates that account does **not** update Anchor's cached copy. Any read
after the CPI sees **stale data**. Making a balance/authority/state decision on the stale
copy is exploitable (e.g. an accounting check that passes because it reads the pre-transfer
balance).

**Auditor check**
- ✅ PASS: after every CPI that can modify an account whose data is read again later,
  `ctx.accounts.<acct>.reload()?` is called *before* the next read.
- ❌ FAIL: a value deserialized before a CPI is used in a `require!`/branch/return after the
  CPI without an intervening `.reload()?`. Treat every CPI as a black box that may have
  changed state — including CPIs back into the same program.

```
grep -rn -E "transfer_checked|mint_to|burn|::invoke|CpiContext" programs/
grep -rn "\.reload()" programs/     # cross-reference: is there a reload after each mutating CPI whose result is reused?
```

---

## 5. Constraint semantics & footguns (quick reference)

Constraints are evaluated at deserialization — but only if you write them correctly. The
common failures are *silent no-ops*, not compile errors.

| Constraint | Correct use | Silent-failure / footgun |
|---|---|---|
| `bump` | `seeds = [...], bump = stored.bump` — verifies PDA against the **stored canonical** bump | `bump` **alone** (no `seeds`) does nothing; a **user-supplied** bump lets a non-canonical PDA pass |
| `seeds` | seeds must include a discriminating value (owner pubkey, mint) so accounts can't collide | Constant-only seeds → all users share one PDA; seed collisions across account types |
| `close = dst` | zeroes data, drains lamports, reassigns to System Program in one op | Manual "drain lamports" without realloc/reassign → **revival / re-init** attack; `close` to a *user-supplied* destination on an admin path |
| `realloc` | `realloc::zero = true` when a grow can follow a shrink in the same tx | Grow-after-shrink without zeroing → **stale bytes read as valid data** |
| `constraint = expr @ Err` | boolean expression evaluated pre-handler | An `expr` with side effects, or one that reads an account field before its own `has_one`/owner check has run |
| duplicate mutable accounts | Anchor 0.31+ rejects by default; older needs an explicit distinctness check | Two `mut` accounts that may alias the same address → double-spend / accounting corruption |

**Auditor check**
- ✅ PASS: every PDA constraint pairs `seeds` + a stored `bump`; seeds are collision-safe;
  `close`/`realloc` use the safe forms above; no user input feeds a `bump`.
- ❌ FAIL: any row's right-hand column is present in the program.

```
grep -rn -E "bump[^=]" programs/            # bump used without an = stored value?
grep -rn -E "seeds *= *\[b\"" programs/     # inspect seeds for a discriminating component
grep -rn -E "realloc" programs/             # is realloc::zero set on grow-after-shrink?
grep -rn -E "close *=" programs/            # is the close destination trusted?
```

---

## 6. Error surface — specific codes, not panics

Anchor's `#[error_code]` enum with `#[msg("…")]` is the intended error surface. Generic
`ProgramError::Custom(0)`, `panic!`, or `unwrap()`/`expect()` in a handler both leak nothing
useful to an auditor **and** can abort in ways that mask the true failure. Anchor 1.x allows
only **one** `#[error_code]` enum per program.

**Auditor check**
- ✅ PASS: all validation uses `require!` / `require_keys_eq!` / `require_gt!` returning a
  descriptive program-specific error; no `unwrap()`/`expect()` in instruction handlers.
- ❌ FAIL: `unwrap()`/`expect()` in a handler, `panic!`, or catch-all custom codes.

```
grep -rn -E "unwrap\(\)|expect\(|panic!" programs/*/src
```

---

## Anchor idiom checklist (fast pass)

- [ ] No `AccountInfo`/`UncheckedAccount` for typed data without a real `/// CHECK:` + manual check (§1)
- [ ] Every ownership relationship enforced by `has_one`; privileged paths also require the authority **signed**, ideally with a redundant `require_keys_eq!` (§2)
- [ ] Initializers use `init`; every `init_if_needed` has an explicit reinit guard (§3)
- [ ] `.reload()?` after every mutating CPI whose account is read again (§4)
- [ ] Every PDA constraint = `seeds` + stored canonical `bump`; no user-supplied bump (§5)
- [ ] `close` / `realloc` use the safe forms; close destination is trusted (§5)
- [ ] No duplicate-mutable-account aliasing (§5)
- [ ] Descriptive `#[error_code]`; no `unwrap()`/`expect()`/`panic!` in handlers (§6)
