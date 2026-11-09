//! A `#[path]` that goes down 20,000 directories and back up: the walk places it
//! in memory that grows with its length, not with its length times its depth. One
//! test, so that the largest of this process's children is the scan, or its child.

mod common;

use common::{run, Wt};
use serde_json::Value;

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
fn a_long_path_brought_in_is_placed_in_memory_its_length_bounds() {
    let wt = Wt::repo();
    // Kept whole for each directory a .. leaves, its 20,000 leading directories
    // would take about 800 MB.
    let path = format!("{}{}x.rs", "a/".repeat(20_000), "../".repeat(20_000));
    wt.write(
        "src/lib.rs",
        format!("#[path = \"{path}\"]\nmod x;\n").as_bytes(),
    );
    let out = run(BIN, &wt.dir, &["."]);
    assert_eq!(out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&out.stdout).expect("a JSON report");
    let entry = report["skipped"]
        .as_array()
        .expect("skipped")
        .iter()
        .find(|s| s["file"] == "./src/x.rs")
        .expect("the file it brings in is listed");
    let reason = entry["reason"].as_str().unwrap_or_default();
    let deepest = format!("./src/{}", ["a"; 20_000].join("/"));
    assert_eq!(
        reason,
        format!(
            "not parsed: its path leaves {deepest} by .., a directory the walk did not find; \
             ./src/lib.rs brings it in (#[path], line 2)"
        )
    );
    let largest = largest_child();
    assert!(largest < 256 << 20, "a child held {} MiB", largest >> 20);
}
