//! audit-scan's walk with parsers that die and hang: the file a parser does not
//! finish is skipped, the next file goes to a new child, and the scan goes on;
//! and with a report that fills up. One test, since it enters the tree it scans.

mod common;

use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, Instant};

use auditor_tools::confine::{Parser, PARSE_TIME};
use auditor_tools::scan::scan_path_with;
use common::Wt;

const BIN: &str = env!("CARGO_BIN_EXE_audit-scan");

#[test]
fn a_file_whose_parser_dies_or_hangs_is_skipped_and_the_scan_goes_on() {
    let wt = Wt::repo();
    wt.write("src/a.rs", b"fn a() { let x = 1 + 2; }\n");
    wt.write("src/b.rs", b"// dies\nfn b() {}\n");
    wt.write("src/c.rs", b"// hangs\nfn c() {}\n");
    wt.write("src/d.rs", b"fn d() { v.unwrap(); }\n");
    wt.write("src/e.rs", b"// dies\nfn e() {}\n");
    wt.write("src/f.rs", b"fn f() { w.expect(\"w\"); }\n");
    std::env::set_current_dir(&wt.dir).expect("enter the tree");
    let mut real = Parser::new(Path::new(BIN));
    let mut dies = Parser::with(
        Path::new("/bin/sh"),
        &[OsStr::new("-c"), OsStr::new("kill -s SEGV $$")],
    );
    let mut hangs = Parser::with(Path::new("/bin/sleep"), &[OsStr::new("30")]);
    let started = Instant::now();
    let report = scan_path_with(
        Path::new("src"),
        auditor_tools::scan::MAX_REPORT,
        &mut |bytes| {
            if bytes.starts_with(b"// dies") {
                dies.parse(bytes, PARSE_TIME)
            } else if bytes.starts_with(b"// hangs") {
                hangs.parse(bytes, Duration::from_secs(1))
            } else {
                real.parse(bytes, PARSE_TIME)
            }
        },
    );
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(1) && took < Duration::from_secs(8),
        "took {took:?}"
    );
    assert_eq!(report.files_scanned, 3);
    let skipped: Vec<(&str, &str)> = report
        .skipped
        .iter()
        .map(|s| (s.file.as_str(), s.reason.as_str()))
        .collect();
    let why = "the parser could not finish";
    assert_eq!(
        skipped,
        [("src/b.rs", why), ("src/c.rs", why), ("src/e.rs", why)]
    );
    let functions: Vec<(&str, &str)> = report
        .functions
        .iter()
        .map(|f| (f.name.as_str(), f.file.as_str()))
        .collect();
    assert_eq!(
        functions,
        [("a", "src/a.rs"), ("d", "src/d.rs"), ("f", "src/f.rs")]
    );
    let panics: Vec<(&str, &str)> = report
        .panic_sites
        .iter()
        .map(|p| (p.kind.as_str(), p.file.as_str()))
        .collect();
    assert_eq!(panics, [("unwrap", "src/d.rs"), ("expect", "src/f.rs")]);
    assert_eq!(report.arithmetic_sites[0].file, "src/a.rs");

    // A report has a cap: the file that would take it past the cap, and each file
    // after it, is not parsed.
    wt.write("cap/a.rs", b"fn a() {}\n");
    let sums = format!("fn b() {{ {} }}\n", "let x = 1 + 2; ".repeat(1_000));
    wt.write("cap/b.rs", sums.as_bytes());
    wt.write("cap/c.rs", b"fn c() {}\n");
    let report = scan_path_with(Path::new("cap"), 10_000, &mut |bytes| {
        real.parse(bytes, PARSE_TIME)
    });
    assert_eq!(report.files_scanned, 1);
    assert_eq!(report.functions.len(), 1);
    assert_eq!(report.functions[0].file, "cap/a.rs");
    let skipped: Vec<(&str, &str)> = report
        .skipped
        .iter()
        .map(|s| (s.file.as_str(), s.reason.as_str()))
        .collect();
    let full = "not parsed: the report is full";
    assert_eq!(skipped, [("cap/b.rs", full), ("cap/c.rs", full)]);
}
