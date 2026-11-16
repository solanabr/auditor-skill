---
id: 143
title: "Address-Translation Changes (SIMD-0460) — Cross-Region Access, Out-of-Length Reads and Stack-Layout Assumptions in Native, Zero-Copy and Unsafe Code"
severity: 7
category: dos
---

### 143 — Address-Translation Changes (SIMD-0460) — Cross-Region Access, Out-of-Length Reads and Stack-Layout Assumptions in Native, Zero-Copy and Unsafe Code

**Severity: 7** | **Real: class of bug, no incident cited. SIMD-0460 ("Virtual address space adjustments", status Review, feature key not yet assigned in the document) is the address-translation half split off from SIMD-0219, which it supersedes. It was reported on the Agave v4.5 schedule under the feature name `virtual_address_space_adjustments`, and on 2026-11-10 a Solana Foundation developer-relations engineer asked builders to "test all [your] programs with the feature virtual_address_space_adjustments enabled. Either locally or against devnet", noting that some programs still diverge (Solana Compass, 2026-11-10). Expected date: Anza's v4.5 schedule, as edited 2026-11-10 and marked tentative, targets 2026-12-14 for v4.5 feature activation to begin on mainnet, with activations on testnet and devnet resuming from 2026-11-19; no date is published for this gate alone. The SIMD's own Security Considerations name the programs at risk: those that "rely on the address space layout of the stack". Verify activation per cluster with `solana -u <cluster> feature status`; never assume it from a date.**

A program does not see memory; it sees a virtual address space the VM translates on every access. SIMD-0460 tightens that translation, so behaviour that today returns bytes or silently succeeds becomes an error raised by the access itself. Nothing in the program's source changes and no build is required: a deployed binary that performs one of these accesses starts failing when the feature activates. If the failing access is on a withdrawal, liquidation or close path, funds stay where they are until an upgrade lands, and an immutable program has no upgrade. The rules, quoted from the SIMD:

- **Reads stop at the account's current length.** "The access is completely within the current length of the account", otherwise `AccountDataTooSmall`. Code that reads past `data_len()` into the bytes that follow the account data in the input buffer (the realloc padding), by a hand-rolled offset, a fixed-size `from_raw_parts` over a shorter account, or an off-by-one on a tail field, gets bytes today and an error afterwards.
- **An access may not span regions.** Accesses spanning memory-mapping regions are "considered access violations", and multi-region operations such as `memcpy` "have to be split into multiple separate accesses". One `sol_memcpy` / `copy_nonoverlapping` / slice built from a pointer in one account to an end in the next, or from account data into instruction data, fails.
- **Writes are checked against the account's status and limits.** The account must be "flagged as writable", otherwise `ReadonlyDataModified`; "owned by the currently executed program", otherwise `ExternalAccountDataModified`; the access must be "completely within the maximum account length" and "within the rest of the account growth budget", otherwise `InvalidRealloc`. A write beyond the current length but inside those limits extends the account with zeros. Code that uses a non-writable or foreign account's buffer as scratch space and restores it, or that writes a trailer past the current length without an explicit resize, is in this group.
- **The stack moves.** "Stack frame gaps must be deactivated globally", including for existing SBPFv0 programs, and the frame bump on `call` / `callx` is lowered from 8 KiB to 4 KiB, compacting the stack address space by two. Programs with absolute stack addresses, pointers carried across frames by arithmetic, or inline assembly that knows the frame layout diverge. A frame overrun that used to land in an unmapped gap (KV-111) may now land in the adjacent frame: until tested under the feature, treat every KV-111 hit as possible memory corruption, not only a fault.

Anchor programs written in safe Rust are mostly out of scope: `Account<T>`, Borsh and `AccountInfo::try_borrow_data` stay inside one account's current length. The exposure is native and Pinocchio programs that parse the input buffer themselves, zero-copy layouts with manual offsets, any `unsafe` pointer arithmetic over account data, C or assembly programs, and vendored math or serialization crates that do the same under a safe-looking API.

> Cross-ref: checklist 01 §1.13 (AV-092: account-data accesses stay in one region and inside the current length; AV-093: no stack-layout dependence); FV-074 (suite runs with the feature active); KV-109 (Pinocchio / p-token manual validation); KV-111 (BPF stack frame overflow); AV-080 / AV-088 (zero-copy bounds, unsafe deserialization); KV-137 (a vendored or forked program inherits the fork parent's unsafe code); DEP-088 (feature gates tracked per cluster); `references/framework-idioms/native.md` and `pinocchio.md`.

#### Verification Procedure

**Step 1: Classify the program: does any code touch account memory outside safe, bounds-checked APIs?**
```
grep -rn --include="*.rs" -E "unsafe *(\{|fn|impl)|from_raw_parts(_mut)?|\.as_(mut_)?ptr\(\)|\.(add|offset|sub)\(|ptr::(read|write|copy|copy_nonoverlapping)|transmute|sol_mem(cpy|move|set|cmp)|pinocchio|no_std|#\[zero_copy|bytemuck|zerocopy|asm!|global_asm!" programs/ 2>/dev/null
ls programs/*/src/*.c programs/*/src/*.s programs/*/src/*.S 2>/dev/null
```
- Record each hit with the account(s) or buffer it touches. Include vendored and path / git dependencies that contain `unsafe` over caller-supplied slices (`cargo tree` names them; read them as in-scope code, KV-137)
- If there is no hit and the program is Anchor or safe-Rust native code throughout, this vector is N/A for Steps 2 to 5 (record this explicitly) and only Step 6 applies

**Step 2: No read goes past the account's current length**
```
grep -rn --include="*.rs" -B3 -A8 -E "from_raw_parts(_mut)?|bytemuck::(from_bytes|try_from_bytes|cast)|\.get_unchecked|&data\[[^]]*\.\.[^]]*\]|ptr::read" programs/ | grep -iE "len|size_of|LEN|offset|data"
```
- ✅ PASS: every raw or zero-copy read is preceded by a check of the live length (`data_len() >= OFFSET + size_of::<T>()`), and no read targets the bytes after `data_len()` (realloc padding, the next account's header)
- ❌ FAIL: a fixed-size view over an account whose length is not checked, an offset computed from an attacker-supplied count without a bound against `data_len()`, or a deliberate read of the padding: bytes today, `AccountDataTooSmall` under SIMD-0460, on every call that reaches it

**Step 3: No single access spans two regions**
```
grep -rn --include="*.rs" -B4 -A6 -E "sol_mem(cpy|move|set|cmp)|copy_nonoverlapping|ptr::copy|copy_from_slice|copy_within" programs/
```
- ✅ PASS: source and destination ranges each lie inside one account's data (or one of: instruction data, stack, heap), with lengths derived from that region's own length
- ❌ FAIL: a copy, compare or slice whose range starts in one account and ends in another, runs from account data into instruction data, or treats the serialized input buffer as one contiguous array ("accounts are adjacent, so one memcpy moves both"): an access violation under SIMD-0460

**Step 4: No write to an account that is not writable and owned, and no implicit growth**
```
grep -rn --include="*.rs" -B3 -A8 -E "try_borrow_mut_data|borrow_mut_data_unchecked|as_mut_ptr|from_raw_parts_mut|data_mut" programs/ | grep -iE "is_writable|owner|realloc|resize|len"
```
- ✅ PASS: every mutable access is to an account the instruction requires to be writable and owned by this program; any write past the current length is preceded by an explicit `realloc` / `resize` that the instruction funds (KV-142 Step 2)
- ❌ FAIL: a read-only or foreign-owned account's buffer is written and restored within the instruction (scratch use), or a trailer is written past `data_len()` relying on padding: `ReadonlyDataModified` / `ExternalAccountDataModified` on the access, or an unintended zero-extension of the account that must then be rent-exempt at its new size

**Step 5: No dependence on the stack's address layout**
```
grep -rn --include="*.rs" -E "0x2000[0-9a-fA-F_]{5,}|MM_STACK_START|STACK_FRAME_SIZE|asm!|global_asm!|#\[naked\]|\[u8; *[0-9_]{4,}\]|\[[A-Za-z0-9_:<>]+; *[0-9_]{4,}\]" programs/ 2>/dev/null
```
- ✅ PASS: no absolute stack address, no pointer to a caller's or callee's frame derived by arithmetic, no assembly that assumes an 8 KiB frame bump or a gap between frames; large locals are boxed or heap-allocated (KV-111 passes)
- ❌ FAIL: any of those. A KV-111 failure (a frame that can exceed 4 KiB) is upgraded here: with frame gaps removed the overrun may write into the adjacent frame, so the finding is memory corruption until a test under the feature shows otherwise

**Step 6: The program has been executed with the feature active**
```
grep -rn -iE "virtual_address_space_adjustments|feature_set|FeatureSet::|deactivate_feature|--deactivate-feature|activate_feature|add_feature|with_feature" tests/ programs/*/tests Anchor.toml .github/ scripts/ 2>/dev/null
```
- ✅ PASS: the in-process suite (LiteSVM, Mollusk, `solana-program-test`) or a local validator run executes every instruction, including failure and cleanup paths, with `virtual_address_space_adjustments` active, and the run is recorded (toolchain version, feature set); for a deployed program, the same suite was run against devnet after the gate activated there
- ❌ FAIL: no run with the feature active; for a program with any Step 1 hit this alone is a finding, because the SIMD's impact is decided by executing the binary, not by reading the source

**Overall verdict:**
- ✅: Every raw or zero-copy access is bounds-checked against the live length, stays inside one region, writes only to writable program-owned accounts with explicit resizes, assumes nothing about stack addresses, and the full suite passes with the feature active
- ⚠️: No violating access found by reading, but the suite has not run with the feature active; or the program is safe Rust and a vendored dependency with `unsafe` over account slices was not read
- ❌: A read past `data_len()`, an access spanning two regions, a write to a read-only or foreign account, an implicit growth by writing past the length, or a stack-layout dependence exists on any path; severity follows the path it blocks (withdraw, liquidate, close on an immutable or slow-to-upgrade program is High)
- N/A: Safe-Rust Anchor or native code throughout, no `unsafe`, zero-copy, assembly or vendored unsafe dependency over account data, and Step 6 passes
