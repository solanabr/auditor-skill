//! A file whose PDAs repeat a long struct name: the parse child stops listing it
//! once its answer would pass 32 MiB, before it builds more. One test, so that the
//! largest of this process's children is the scan, or its child.

mod common;

use common::{run, Wt};
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_audit-scan");

/// The most memory a child of this process that has ended held, its own children
/// included.
fn largest_child() -> u64 {
    // SAFETY: an all-zero rusage is valid; getrusage only writes it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a rusage this function owns.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) },
        0
    );
    let rss = u64::try_from(usage.ru_maxrss).expect("a size");
    // In bytes on macOS, in KiB elsewhere.
    if cfg!(target_os = "macos") {
        rss
    } else {
        rss * 1024
    }
}

#[test]
fn a_long_name_that_each_pda_repeats_is_not_built_past_32_mib() {
    let wt = Wt::repo();
    // A 2 MiB name with 9,999 PDA fields, 2,816,014 bytes: listed whole, about 20 GB
    // of JSON.
    let name = format!("S{}", "a".repeat(2 << 20));
    let source = common::pda_struct(&name, 9_999);
    assert_eq!(source.len(), 2_816_014);
    wt.write("src/pda.rs", source.as_bytes());
    let out = run(BIN, &wt.dir, &["src"]);
    assert_eq!(out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&out.stdout).expect("a JSON report");
    assert_eq!(report["accounts_structs"], json!([]));
    assert_eq!(report["pdas"], json!([]));
    assert_eq!(
        report["skipped"],
        json!([{"file": "src/pda.rs", "reason": "lists only the sites that fit in 32 MiB"}])
    );
    let largest = largest_child();
    assert!(largest < 256 << 20, "a child held {} MiB", largest >> 20);
}
