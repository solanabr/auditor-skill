//! audit-scan as a command: what it reads, where it writes, and what it refuses.

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use common::{refused, refused_with, run, shown, stdout, Wt};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_audit-scan");

fn json(out: &std::process::Output) -> Value {
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        common::stderr(out)
    );
    serde_json::from_slice(&out.stdout).expect("audit-scan prints JSON")
}

fn files(report: &Value, key: &str) -> Vec<String> {
    report[key]
        .as_array()
        .expect("an array")
        .iter()
        .map(|v| v["file"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn scans_a_confined_directory_and_follows_no_link() {
    let wt = Wt::repo();
    wt.write("src/lib.rs", b"fn a() { let x = 1 + 2; }\n");
    wt.write("../outside/secret.rs", b"fn secret() { let y = 3 * 4; }\n");
    wt.link(&wt.outside().join("secret.rs"), "src/linked.rs");
    wt.link(&wt.outside(), "src/linked-dir");
    let report = json(&run(BIN, &wt.dir, &["src"]));
    assert_eq!(report["files_scanned"], 1);
    assert_eq!(files(&report, "functions"), vec!["src/lib.rs"]);
    let skipped = report["skipped"].as_array().expect("skipped");
    let mut seen: Vec<(String, String)> = skipped
        .iter()
        .map(|s| {
            (
                s["file"].as_str().unwrap_or_default().into(),
                s["reason"].as_str().unwrap_or_default().into(),
            )
        })
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![
            (
                "src/linked-dir".into(),
                "a symbolic link, not followed".into()
            ),
            (
                "src/linked.rs".into(),
                "a symbolic link, not followed".into()
            ),
        ]
    );
    assert!(!stdout(&run(BIN, &wt.dir, &["."])).contains("secret"));
}

/// What `skipped` says of each file, by name.
fn skipped(report: &Value) -> Vec<(String, String)> {
    let mut seen: Vec<(String, String)> = report["skipped"]
        .as_array()
        .expect("skipped")
        .iter()
        .map(|s| {
            (
                s["file"].as_str().unwrap_or_default().into(),
                s["reason"].as_str().unwrap_or_default().into(),
            )
        })
        .collect();
    seen.sort();
    seen
}

#[test]
fn skips_a_file_nested_or_chained_too_deeply_and_scans_the_rest_in_time() {
    let wt = Wt::repo();
    let parens = format!(
        "fn f() {{ let x = {}1{}; }}\n",
        "(".repeat(5000),
        ")".repeat(5000)
    );
    let nots = format!("fn f() {{ let x = {}true; }}\n", "!".repeat(20000));
    let sum = format!("fn f() {{ let x = 1{}; }}\n", " + 1".repeat(20000));
    wt.write("src/parens.rs", parens.as_bytes());
    wt.write("src/nots.rs", nots.as_bytes());
    wt.write("src/sum.rs", sum.as_bytes());
    wt.write("src/lib.rs", b"fn ok() { let y = a + b; }\n");
    let started = std::time::Instant::now();
    let report = json(&run(BIN, &wt.dir, &["src"]));
    let took = started.elapsed();
    assert!(took.as_secs_f64() < 2.0, "took {took:?}");
    assert_eq!(report["files_scanned"], 1);
    assert_eq!(files(&report, "functions"), vec!["src/lib.rs"]);
    let why = "nested or chained too deeply to parse";
    assert_eq!(
        skipped(&report),
        [
            ("src/nots.rs".into(), why.into()),
            ("src/parens.rs".into(), why.into()),
            ("src/sum.rs".into(), why.into()),
        ]
    );
}

#[test]
fn renders_the_snippets_of_a_long_chain_in_time() {
    let wt = Wt::repo();
    let sum = format!("fn f() {{ let x = 1{}; }}\n", " + 1".repeat(9000));
    wt.write("src/sum.rs", sum.as_bytes());
    let started = std::time::Instant::now();
    let report = json(&run(BIN, &wt.dir, &["src"]));
    let took = started.elapsed();
    assert!(took.as_secs_f64() < 2.0, "took {took:?}");
    let sites = report["arithmetic_sites"].as_array().expect("sites");
    assert_eq!(sites.len(), 9000);
    let first =
        "1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + ...";
    assert_eq!(sites[0]["snippet"], first);
    assert_eq!(sites[8999]["snippet"], "1 + 1");
}

#[test]
fn does_not_walk_below_its_depth_limit() {
    let wt = Wt::repo();
    let mut deep = String::from("src");
    for _ in 0..129 {
        deep.push_str("/d");
    }
    wt.write(&format!("{deep}/deep.rs"), b"fn deep() {}\n");
    wt.write("src/d/near.rs", b"fn near() {}\n");
    let report = json(&run(BIN, &wt.dir, &["src"]));
    assert_eq!(files(&report, "functions"), vec!["src/d/near.rs"]);
    assert_eq!(
        skipped(&report),
        [(deep.clone(), "nested too deeply to walk".into())]
    );
}

#[test]
fn enters_no_directory_swapped_for_a_link_while_it_walks() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let wt = Wt::repo();
    // Files the walk parses before it reaches sub/, while sub/ is swapped.
    for i in 0..300 {
        wt.write(
            &format!("src/a{i:03}.rs"),
            format!("fn a{i}() {{}}\n").as_bytes(),
        );
    }
    wt.write("src/sub/inside.rs", b"fn inside_fn() {}\n");
    wt.write(
        "../outside/target/outside.rs",
        b"fn outside_marker_fn() {}\n",
    );
    wt.link(&wt.outside().join("target"), "src/sublink");
    let stop = Arc::new(AtomicBool::new(false));
    let src = wt.path("src");
    let swapper = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::rename(src.join("sub"), src.join("subreal"));
                let _ = fs::rename(src.join("sublink"), src.join("sub"));
                let _ = fs::rename(src.join("sub"), src.join("sublink"));
                let _ = fs::rename(src.join("subreal"), src.join("sub"));
            }
        })
    };
    let started = std::time::Instant::now();
    let mut scans = 0;
    let mut leaked = 0;
    while scans < 300 && started.elapsed().as_secs() < 6 {
        let out = run(BIN, &wt.dir, &["src"]);
        assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
        if stdout(&out).contains("outside_marker_fn") {
            leaked += 1;
        }
        scans += 1;
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().expect("the swapper stops");
    assert!(scans >= 30, "only {scans} scans ran");
    assert_eq!(
        leaked, 0,
        "{leaked} of {scans} scans read the directory outside"
    );
}

#[test]
fn skips_large_irregular_and_unparsable_files() {
    let wt = Wt::new();
    wt.write("big.rs", &vec![b' '; (4 << 20) + 1]);
    wt.write(
        "edge.rs",
        &[vec![b' '; (4 << 20) - 10], b"fn e(){}\n".to_vec()].concat(),
    );
    wt.write("bad.rs", b"fn (");
    wt.write("latin1.rs", b"// \xe9\nfn l() {}\n");
    wt.write("../outside/private.rs", b"fn private() {}\n");
    fs::hard_link(wt.outside().join("private.rs"), wt.path("linked.rs")).expect("ln");
    let fifo = wt.path("pipe.rs");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    let report = json(&run(BIN, &wt.dir, &["."]));
    assert_eq!(
        report["files_scanned"], 1,
        "only edge.rs, of exactly 4 MiB less one byte"
    );
    let reasons: Vec<String> = report["skipped"]
        .as_array()
        .expect("skipped")
        .iter()
        .map(|s| {
            format!(
                "{} {}",
                s["file"].as_str().unwrap_or(""),
                s["reason"].as_str().unwrap_or("")
            )
        })
        .collect();
    assert_eq!(
        reasons,
        vec![
            "./bad.rs does not parse as Rust",
            "./big.rs larger than 4 MiB",
            "./latin1.rs not UTF-8",
            "./linked.rs has more than one name (a hard link)",
            "./pipe.rs not a regular file",
        ]
    );
}

#[test]
fn prunes_run_directories_and_the_store_at_the_top_only() {
    let wt = Wt::new();
    wt.write("src/lib.rs", b"fn a() {}\n");
    wt.run_dir("audit_1");
    wt.write("audit_1/poc/F-1/src/lib.rs", b"fn poc() {}\n");
    wt.write(".audit-memory/x.rs", b"fn mem() {}\n");
    wt.write("target/debug/build.rs", b"fn built() {}\n");
    wt.write("programs/p/audit_2/lib.rs", b"fn kept() {}\n");
    let report = json(&run(BIN, &wt.dir, &["."]));
    assert_eq!(
        files(&report, "functions"),
        vec!["./programs/p/audit_2/lib.rs", "./src/lib.rs"]
    );
    let poc = json(&run(BIN, &wt.dir, &["audit_1/poc"]));
    assert_eq!(files(&poc, "functions"), vec!["audit_1/poc/F-1/src/lib.rs"]);
}

#[test]
fn gives_each_file_its_own_line_numbers() {
    let wt = Wt::new();
    for name in ["a", "b", "c"] {
        wt.write(
            &format!("src/{name}.rs"),
            b"// one\n// two\nfn f(x: u64) -> u64 { x + 1 }\n",
        );
    }
    wt.write("src/d.rs", b"fn (");
    wt.write("src/e.rs", b"\n\n\n\nfn g() { y.unwrap(); }\n");
    let report = json(&run(BIN, &wt.dir, &["src"]));
    let lines: Vec<String> = report["arithmetic_sites"]
        .as_array()
        .expect("sites")
        .iter()
        .chain(report["panic_sites"].as_array().expect("sites"))
        .map(|s| format!("{}:{}", s["file"].as_str().unwrap_or(""), s["line"]))
        .collect();
    assert_eq!(
        lines,
        vec!["src/a.rs:3", "src/b.rs:3", "src/c.rs:3", "src/e.rs:5"]
    );
}

#[test]
fn refuses_paths_outside_the_working_tree() {
    let wt = Wt::new();
    wt.write("src/lib.rs", b"fn a() {}\n");
    wt.link(&wt.outside(), "out");
    wt.link(&wt.path("src"), "src-link");
    let d = "the directory to scan";
    let outside = wt.outside().display().to_string();
    for (arg, why) in [
        (
            outside.as_str(),
            format!(
                "{d} must be relative to the working directory: {}",
                shown(&outside)
            ),
        ),
        (
            "../outside",
            format!("{d} has an empty, . or .. component: ../outside"),
        ),
        (
            "src/../..",
            format!("{d} has an empty, . or .. component: src/../.."),
        ),
        ("~/x", format!("{d} may not start with - or ~: ~/x")),
        ("out", format!("{d} passes through a symbolic link: out")),
        (
            "src-link",
            format!("{d} passes through a symbolic link: src-link"),
        ),
        (
            "out/x",
            format!("{d} passes through a symbolic link: out/x"),
        ),
        (
            "src/lib.rs",
            format!("{d} is not an existing directory: src/lib.rs"),
        ),
        (
            "missing",
            format!("{d} is not an existing directory: missing"),
        ),
        (
            "src//x",
            format!("{d} has an empty, . or .. component: src//x"),
        ),
        ("a\nb", format!("{d} holds a control character: a?b")),
    ] {
        refused(&run(BIN, &wt.dir, &[arg]), "audit-scan", &why);
    }
}

#[test]
fn refuses_a_grammar_it_does_not_have() {
    let wt = Wt::new();
    wt.run_dir("audit_1");
    let usage = "usage: audit-scan <dir> [--out <run dir>/prescan.json | <run dir>/prescan-<slug>.json] [--pretty]";
    for (args, why) in [
        (vec![], "no directory to scan"),
        (vec![".", "."], "it takes one directory"),
        (
            vec![".", "--pretty", "--pretty"],
            "--pretty is given more than once",
        ),
        (
            vec![
                ".",
                "--out",
                "audit_1/prescan.json",
                "--out=audit_1/prescan.json",
            ],
            "--out is given more than once",
        ),
        (vec![".", "--out"], "--out needs a file"),
        (vec![".", "--help"], "unknown option --help"),
        (vec!["-h"], "unknown option -h"),
        (vec![".", "--"], "unknown option --"),
        (vec![".", "--pretty=yes"], "unknown option --pretty=yes"),
    ] {
        refused(
            &run(BIN, &wt.dir, &args),
            "audit-scan",
            &format!("{why} ({usage})"),
        );
    }
    // The word after --out is its value, whatever it looks like.
    refused_with(
        &run(BIN, &wt.dir, &[".", "--out", "--pretty"]),
        "audit-scan",
        "--out may not start with - or ~: --pretty",
    );
}

#[test]
fn writes_out_only_into_a_run_directory() {
    let wt = Wt::repo();
    wt.write("src/lib.rs", b"fn a() {}\n");
    wt.run_dir("audit_1");
    wt.run_dir("incident_2");
    let o = run(BIN, &wt.dir, &["src", "--out", "audit_1/prescan.json"]);
    assert_eq!(o.status.code(), Some(0), "{}", common::stderr(&o));
    assert_eq!(stdout(&o), "");
    let md = fs::symlink_metadata(wt.path("audit_1/prescan.json")).expect("made");
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
    let first: Value = serde_json::from_slice(&wt.read("audit_1/prescan.json")).expect("JSON");
    assert_eq!(first["files_scanned"], 1);
    // Its own output is replaced in place.
    wt.write("src/more.rs", b"fn b() {}\n");
    let o = run(
        BIN,
        &wt.dir,
        &["src", "--out=./audit_1/prescan.json", "--pretty"],
    );
    assert_eq!(o.status.code(), Some(0), "{}", common::stderr(&o));
    let again: Value = serde_json::from_slice(&wt.read("audit_1/prescan.json")).expect("JSON");
    assert_eq!(again["files_scanned"], 2);
    let o = run(
        BIN,
        &wt.dir,
        &[".", "--out", "incident_2/prescan-lib-2.json"],
    );
    assert_eq!(o.status.code(), Some(0), "{}", common::stderr(&o));
    assert!(wt.exists("incident_2/prescan-lib-2.json"));
}

#[test]
fn refuses_an_out_it_may_not_write() {
    let wt = Wt::repo();
    wt.write("src/lib.rs", b"fn a() {}\n");
    wt.run_dir("audit_1");
    wt.mkdir("audit_2");
    wt.link(&wt.path("audit_1"), "audit_3");
    wt.run_dir("audit_4");
    wt.git(&["add", "-f", "audit_4/.gitignore"]);
    wt.run_dir("audit_5");
    wt.link(&wt.outside(), "audit_5/elsewhere");
    wt.run_dir("audit_6");
    wt.write("../outside/protected.json", b"protected\n");
    wt.link(&wt.outside().join("protected.json"), "audit_6/prescan.json");
    wt.run_dir("audit_7");
    fs::hard_link(
        wt.outside().join("protected.json"),
        wt.path("audit_7/prescan.json"),
    )
    .expect("hard link");
    wt.run_dir("audit_8");
    wt.mkdir("audit_8/prescan.json");
    let before = wt.snapshot();
    let shape = "--out must be audit_<n>/prescan.json or audit_<n>/prescan-<slug>.json, or the same in incident_<n>/, with a slug of 1 to 32 of a-z, 0-9 and -";
    let abs = wt.path("audit_1/prescan.json").display().to_string();
    for (out, why) in [
        (
            abs.as_str(),
            format!(
                "--out must be relative to the working directory: {}",
                shown(&abs)
            ),
        ),
        ("prescan.json", format!("{shape}: prescan.json")),
        (
            "audit_1/report.json",
            format!("{shape}: audit_1/report.json"),
        ),
        (
            "audit_1/prescan-UP.json",
            format!("{shape}: audit_1/prescan-UP.json"),
        ),
        (
            "audit_1/prescan-.json",
            format!("{shape}: audit_1/prescan-.json"),
        ),
        (
            "audit_1/x/prescan.json",
            format!("{shape}: audit_1/x/prescan.json"),
        ),
        ("src/prescan.json", format!("{shape}: src/prescan.json")),
        (
            "audit_1/../prescan.json",
            "--out has an empty, . or .. component: audit_1/../prescan.json".into(),
        ),
        (
            "audit_9/prescan.json",
            "--out is not an existing directory: audit_9".into(),
        ),
        (
            "audit_2/prescan.json",
            "--out has no .gitignore holding exactly *: audit_2".into(),
        ),
        (
            "audit_3/prescan.json",
            "--out is a symbolic link: audit_3".into(),
        ),
        (
            "audit_4/prescan.json",
            "--out is tracked by git: audit_4".into(),
        ),
        (
            "audit_5/prescan.json",
            "--out holds a symbolic link: audit_5".into(),
        ),
        (
            "audit_6/prescan.json",
            "--out holds a symbolic link: audit_6".into(),
        ),
        (
            "audit_7/prescan.json",
            "--out has more than one name (a hard link): audit_7/prescan.json".into(),
        ),
        (
            "audit_8/prescan.json",
            "--out is not a regular file: audit_8/prescan.json".into(),
        ),
    ] {
        refused(
            &run(BIN, &wt.dir, &["src", "--out", out]),
            "audit-scan",
            &why,
        );
    }
    assert_eq!(wt.snapshot(), before, "a refused call changes nothing");
    assert_eq!(
        fs::read(wt.outside().join("protected.json")).ok(),
        Some(b"protected\n".to_vec())
    );
    let md = fs::metadata(wt.outside().join("protected.json")).expect("stat");
    assert_eq!(md.nlink(), 2);
}

#[test]
fn refuses_an_out_when_git_cannot_answer() {
    let wt = Wt::repo();
    wt.run_dir("audit_1");
    wt.write(".git/index", b"not an index");
    refused(
        &run(BIN, &wt.dir, &[".", "--out", "audit_1/prescan.json"]),
        "audit-scan",
        "git cannot tell whether --out is tracked: audit_1",
    );
    assert!(!wt.exists("audit_1/prescan.json"));
    // Printing to stdout asks git nothing.
    assert_eq!(run(BIN, &wt.dir, &["."]).status.code(), Some(0));
}

#[test]
fn refuses_to_run_from_inside_the_working_tree() {
    let wt = Wt::new();
    wt.mkdir("tools/auditor-tools/target/release");
    let inside = wt.path("tools/auditor-tools/target/release/audit-scan");
    fs::copy(BIN, &inside).expect("copy the binary");
    let o = run(inside.to_str().expect("UTF-8"), &wt.dir, &["."]);
    refused(
        &o,
        "audit-scan",
        "the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)",
    );
    let quoted = wt.outside().join("a$b");
    fs::create_dir(&quoted).expect("mkdir");
    fs::copy(BIN, quoted.join("audit-scan")).expect("copy the binary");
    let o = run(
        quoted.join("audit-scan").to_str().expect("UTF-8"),
        &wt.dir,
        &["."],
    );
    refused(
        &o,
        "audit-scan",
        "the installation path holds a quote, $, a backtick, a backslash or a control character, so its quoted call cannot match as written",
    );
}

#[test]
fn refuses_a_working_directory_whose_path_holds_a_control_character() {
    let wt = Wt::new();
    for name in ["a\nb", "a\tb", "a\u{1b}b"] {
        wt.mkdir(name);
        refused(
            &run(BIN, &wt.path(name), &["."]),
            "audit-scan",
            "the working directory path holds a control character",
        );
    }
}

#[test]
fn escapes_formatting_characters_in_its_output() {
    let wt = Wt::new();
    wt.write(
        "src/a\u{202e}b.rs",
        "fn a() { let v = m[\"\u{202e}k\"]; }\n".as_bytes(),
    );
    let o = run(BIN, &wt.dir, &["src"]);
    let text = stdout(&o);
    assert!(!text.contains('\u{202e}'), "{text}");
    let report: Value = serde_json::from_str(&text).expect("still JSON");
    assert_eq!(report["functions"][0]["file"], "src/a\u{202e}b.rs");
    assert!(text.contains("src/a\\u202eb.rs"), "{text}");
    assert!(text.contains("\\u202ek"), "{text}");
}
