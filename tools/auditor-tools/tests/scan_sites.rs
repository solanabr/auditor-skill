//! The 4 MiB file of index chains, 1,379,310 sites in all: the parse child lists
//! the first 20,000 and builds nothing past them, so the file takes its child less
//! CPU than the 10 s a file is given, and the report stays small. The child is
//! given more time than audit-scan gives it, and what it used is counted in CPU, so
//! a loaded host that runs it slowly fails nothing. One test, since it enters the
//! tree it scans and counts the CPU of this process's children.

mod common;

use std::path::Path;
use std::time::Duration;

use auditor_tools::confine::{Parser, PARSE_TIME};
use auditor_tools::scan::{scan_path_with, MAX_REPORT};
use common::Wt;
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_audit-scan");

/// The CPU time of the children of this process that have ended, their own
/// children included.
fn children_cpu() -> Duration {
    // SAFETY: an all-zero rusage is valid; getrusage only writes it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a rusage this function owns.
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) },
        0
    );
    let time = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec.try_into().unwrap())
            + Duration::from_micros(t.tv_usec.try_into().unwrap())
    };
    time(usage.ru_utime) + time(usage.ru_stime)
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "a debug build's child takes about the 10 s a file is given to parse this one"
)]
fn lists_the_first_twenty_thousand_sites_of_a_4_mib_file_within_its_cpu_time() {
    let wt = Wt::new();
    // 69 statements of 19,990 indexes each: 4,138,988 bytes, 1,379,310 index sites.
    let statement = format!("    let x = a{};\n", "[0]".repeat(19_990));
    let amp = format!("pub fn f(a: &[u8]) {{\n{}}}\n", statement.repeat(69));
    assert_eq!(amp.len(), 4_138_988);
    wt.write("src/amp.rs", amp.as_bytes());
    wt.write("src/lib.rs", b"fn ok() { let y = v[1]; }\n");
    std::env::set_current_dir(&wt.dir).expect("enter the tree");
    let before = children_cpu();
    let report = {
        let mut parser = Parser::new(Path::new(BIN));
        scan_path_with(
            Path::new("src"),
            MAX_REPORT,
            Duration::from_secs(300),
            &mut |bytes| parser.parse(bytes, Duration::from_secs(300)),
        )
        // The parser ends here: its child, at the end of its stdin, ends and is
        // reaped, so its CPU is counted.
    };
    let used = children_cpu() - before;
    assert!(used < PARSE_TIME, "the child used {used:?} of CPU");

    let printed = serde_json::to_string(&report).expect("the report prints");
    assert!(printed.len() < 4 << 20, "{} bytes", printed.len());
    let report: Value = serde_json::from_str(&printed).expect("a JSON report");
    assert_eq!(report["files_scanned"], 2);
    let from = |key: &str, file: &str| {
        report[key].as_array().map_or(0, |items| {
            items.iter().filter(|i| i["file"] == file).count()
        })
    };
    let listed: usize = [
        "instructions",
        "accounts_structs",
        "pdas",
        "arithmetic_sites",
        "panic_sites",
        "unsafe_blocks",
        "cpi_sites",
        "remaining_accounts_sites",
        "functions",
    ]
    .iter()
    .map(|key| from(key, "src/amp.rs"))
    .sum();
    assert_eq!(listed, 20_000);
    assert_eq!(
        from("panic_sites", "src/lib.rs"),
        1,
        "the next file is listed whole"
    );
    assert_eq!(
        report["skipped"],
        json!([{"file": "src/amp.rs", "reason": "lists only the first 20,000 sites"}])
    );
}
