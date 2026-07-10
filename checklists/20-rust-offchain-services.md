# 20 — Off-Chain Rust Services Checklist

> Domain: Off-chain Rust — Geyser plugins, indexers, keeper/liquidator bots, signer services, RPC middleware  
> Severity if missed: HIGH (signer/keeper services handle live funds) to MEDIUM  
> References: safe-solana-builder native-rust.md (panic-safety, unsafe UB), shared-base §25; cross-links `known-vectors/112-in-memory-secret-non-zeroization.md`

This checklist covers **server-side Rust that runs off-chain** and interacts with Solana: Geyser/Yellowstone plugins, transaction/account indexers, keeper and liquidation bots, and services that hold hot-wallet keys to sign and submit transactions. It is distinct from the on-chain program rules (checklists 01-07) and from the general Rust-in-programs guidance: here the threat is a **long-running process** exposed to untrusted network input (RPC responses, gRPC streams, user requests) that must not panic, corrupt memory, wrap arithmetic, deadlock, or leak keys.

If the codebase has no off-chain Rust service, mark this whole checklist `[N/A]`.

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 20.1 — Panic-as-DoS (Untrusted Input Must Not Crash the Process)

> In a long-running service, a panic on a request-handling thread/task is a denial of service: it can abort the process (or, worse, poison a `Mutex` and wedge every other task). Every fallible operation on network, RPC, or user input must return a `Result` — never panic. (safe-solana-builder native-rust §7.2.)

- [ ] **RS-001**: No `.unwrap()` or `.expect()` on any value derived from network / RPC / gRPC / user input — deserialized payloads, RPC responses, header/query values use `?`, `ok_or`, or explicit `match` (`unwrap` in tests / startup-only config is acceptable)
- [ ] **RS-002**: No `panic!`, `unreachable!`, `todo!`, `unimplemented!`, or `assert!`/`assert_eq!` reachable from a request/stream handler with attacker-influenced operands
- [ ] **RS-003**: No slice/array/`Vec` indexing (`buf[i]`, `data[a..b]`) or `.remove()/.swap_remove()` on untrusted-length input without a prior bounds check — use `.get(i)` / `.get(a..b)` and handle `None`
- [ ] **RS-004**: No integer division or remainder (`/`, `%`) where the divisor comes from untrusted input without a zero check (divide-by-zero panics)
- [ ] **RS-005**: A panic boundary exists at each request/task edge — `std::panic::catch_unwind` around handler bodies (or the framework's equivalent, e.g. Tower/Axum panic layer, `tokio::task` join-error handling) so one panic degrades one request, not the whole service
- [ ] **RS-006**: `Mutex`/`RwLock` poisoning is handled — a panic while a lock is held does not permanently wedge the service (recover from `PoisonError`, or use a non-poisoning lock such as `parking_lot`)

## 20.2 — Unsafe Code & Undefined Behavior

> `unsafe` disables the compiler's guarantees; on untrusted bytes it becomes exploitable memory corruption, not just a bug. Prefer safe deserialization (`borsh`, `bytemuck` with validation) over raw casts. (safe-solana-builder native-rust §2.1.)

- [ ] **RS-007**: No `std::mem::transmute` (or `transmute_copy`) to reinterpret untrusted bytes as a typed struct — use validated deserialization; casts must go through `bytemuck::try_from_bytes` (checks size + alignment) or `zerocopy`, never `&*(ptr as *const T)`
- [ ] **RS-008**: No raw-pointer aliasing / `from_raw_parts` / `.add()`/`.offset()` pointer math on buffer data without a documented safety invariant and a preceding length + alignment guard (unaligned reads on `#[repr(C)]`/packed types are UB)
- [ ] **RS-009**: No `String::from_utf8_unchecked` / `str::from_utf8_unchecked` on bytes from the network or user — use checked `from_utf8` and handle the error (invalid UTF-8 downstream is UB)

## 20.3 — Release-Mode Integer Wrapping

> Rust's overflow checks are **on in debug, off in `--release`** (`overflow-checks = false` by default). Arithmetic that panics safely in `cargo test` will **silently wrap** in the deployed release binary — a keeper computing amounts/prices can wrap `u64` to a tiny value and submit a wrong transaction. Tests do not catch this. (Ripples the on-chain "checked arithmetic" rule into off-chain code.)

- [ ] **RS-010**: All financially-meaningful arithmetic (amounts, prices, fees, slot/time math, indices) uses explicit `checked_*` / `saturating_*` / `try_into()` — **not** bare `+ - * <<` relying on debug overflow panics that vanish in `--release`
- [ ] **RS-011**: Either `overflow-checks = true` is set in the release profile (`[profile.release]` in `Cargo.toml`) **or** every hot-path computation is provably wrap-safe via `checked_*` — the choice is deliberate and documented, not accidental

## 20.4 — Async Safety (Tokio / Cancellation / Backpressure)

> Async services fail in ways sync ones don't: a future dropped mid-`.await` (cancellation, `select!` loser, timeout) can leave shared state half-updated; holding a `std::sync` lock across `.await` deadlocks; unbounded channels and unbounded `spawn` let a fast producer OOM the process.

- [ ] **RS-012**: No non-async lock (`std::sync::Mutex`/`RwLock`, `parking_lot`) held across an `.await` point — use `tokio::sync::Mutex` for guards that must span awaits, or scope the guard so it drops before the await; and confirm cancellation-safety: dropping a future mid-`.await` (via `select!`/timeout) leaves no shared state partially mutated
- [ ] **RS-013**: All channels between producers and consumers are **bounded** (`mpsc::channel(n)`, not `unbounded_channel`) so backpressure propagates; unbounded task spawning (`tokio::spawn` in a per-message loop) is capped via a semaphore, bounded worker pool, or `JoinSet` with a limit
- [ ] **RS-014**: Every external call (RPC, gRPC/Geyser stream, HTTP, DB) has a timeout and a lock-ordering / no-cyclic-wait discipline — no two tasks can each hold a resource the other needs (`select!` on `tokio::time::timeout`; consistent acquisition order for multiple locks)

## 20.5 — Secrets & Key Material

> Signer and keeper services hold live private keys in process memory. Keys must be zeroized on drop, never logged, and the service must fail **closed** (refuse to start / refuse to sign) if key loading fails — never fall back to an empty/default/zero key. See `known-vectors/112-in-memory-secret-non-zeroization.md`.

- [ ] **RS-015**: Every in-memory secret (private key, seed, mnemonic, entropy) is wrapped in `Zeroizing<...>` / `secrecy::Secret*` or held in a `#[derive(ZeroizeOnDrop)]` struct — not a bare `Vec<u8>`/`String`/array (cross-ref KV-112)
- [ ] **RS-016**: Secrets are never logged, `Debug`-printed, or included in error messages / spans — secret-holding types have a redacting `Debug` impl (or `secrecy`'s), and no `tracing`/`log` call takes a key as a field
- [ ] **RS-017**: Key loading fails **secure**: a missing/unreadable/malformed keyfile or env var aborts startup (or the sign path) with an error — the service never proceeds with a default, empty, all-zero, or attacker-supplyable key, and keys are read from env/secret store/file (mode `600`), never a committed constant

---

## How to Use This Checklist

1. **Scope-gate first**: if there is no off-chain Rust service (`grep -rn "tokio::main\|geyser\|GeyserPlugin\|yellowstone\|RpcClient\|Keypair" --include="*.rs"` returns nothing in a server crate), mark the whole checklist `[N/A]`.
2. **Always apply 20.1–20.3** to any off-chain Rust binary — they are input-safety and arithmetic invariants that hold even for a read-only indexer.
3. **Apply 20.4** to any `async`/Tokio service.
4. **Apply 20.5** only to services that hold signing keys (signer services, keeper/liquidator bots, hot-wallet automation). Read-only indexers with no key → mark 20.5 `[N/A]`.
5. Pair RS-010/RS-011 with checklist 03 (on-chain arithmetic) — the same class of bug, different default (debug-only checks off-chain).
6. Pair 20.5 with `known-vectors/112` and checklist 12 (secrets & opsec) for the storage/rotation side.
