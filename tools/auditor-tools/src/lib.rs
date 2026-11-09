//! `auditor-tools` — host-side static analysis for Solana/Anchor codebases.
//!
//! Two capabilities, exposed as separate binaries but sharing this library:
//!
//! * [`scan`] — parse a codebase and emit the risky surface (instructions,
//!   `#[derive(Accounts)]` structs and their constraints, PDAs, raw arithmetic,
//!   panic sites, unsafe blocks, CPIs, remaining-accounts access, and every
//!   function) as one JSON object; with `--workflows` it also reads
//!   `.github/workflows/*.yml` into trigger → job → step facts ([`workflow`]).
//! * [`mem`] — a SQLite findings store for cross-audit memory: exact dedup,
//!   regression detection, false-positive suppression, and warm re-audits.
//!
//! This is a plain synchronous CLI library — no async runtime, no network.
//! [`confine`] holds where both binaries may read and write.

pub mod confine;
pub mod mem;
pub mod scan;
pub mod workflow;

pub use scan::{scan_path, scan_source, ScanReport};
pub use workflow::{scan_workflows, Workflow};
