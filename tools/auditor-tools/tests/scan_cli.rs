//! audit-scan as a command: what it reads, where it writes, and what it refuses.

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

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
fn skips_each_closure_chain_in_time() {
    let wt = Wt::repo();
    let shapes = [
        (
            "pairs",
            format!("pub fn f() {{ let x = {}1; }}\n", "|a, b| ".repeat(200_000)),
        ),
        (
            "moves",
            format!(
                "pub fn f() {{ let x = {}1; }}\n",
                "move |a, b| ".repeat(150_000)
            ),
        ),
        (
            "calls",
            format!("pub fn f() {{ g({}1) }}\n", "|a, b| ".repeat(150_000)),
        ),
        (
            "typed",
            format!(
                "pub fn f() {{ let x = {}1; }}\n",
                "|a: u8, b: u8| ".repeat(100_000)
            ),
        ),
        (
            "tuples",
            format!(
                "pub fn f() {{ let x = {}1; }}\n",
                "|(a, b), c| ".repeat(100_000)
            ),
        ),
    ];
    for (dir, text) in &shapes {
        wt.write(&format!("src/{dir}/x.rs"), text.as_bytes());
        let started = std::time::Instant::now();
        let report = json(&run(BIN, &wt.dir, &[&format!("src/{dir}")]));
        let took = started.elapsed();
        assert!(took.as_secs_f64() < 2.0, "{dir} took {took:?}");
        assert_eq!(report["files_scanned"], 0, "{dir}");
        assert_eq!(
            skipped(&report),
            [(
                format!("src/{dir}/x.rs"),
                "nested or chained too deeply to parse".into()
            )],
            "{dir}"
        );
    }
    wt.write(
        "src/ok/x.rs",
        b"fn ok() { let f = |a, b| a + b; let g = move |(a, b), c| a; h(|a, b| a, |c, d| d); }\n",
    );
    let report = json(&run(BIN, &wt.dir, &["src/ok"]));
    assert_eq!(report["files_scanned"], 1);
}

#[test]
fn reads_an_item_after_any_number_of_doc_comments_and_attributes() {
    let wt = Wt::repo();
    let docs = format!(
        "{}pub fn documented() {{}}\n",
        "/// a line of documentation\n".repeat(12_000)
    );
    let attrs = format!(
        "{}pub fn attributed() {{}}\n",
        "#[allow(dead_code)]\n".repeat(30_000)
    );
    // An attribute inside an expression starts no item: the chain goes on.
    let inside = format!(
        "fn f() {{ let x = 1{}; }}\n",
        " + #[a] #[a] 1".repeat(5_000)
    );
    wt.write("src/docs.rs", docs.as_bytes());
    wt.write("src/attrs.rs", attrs.as_bytes());
    wt.write("src/inside.rs", inside.as_bytes());
    let report = json(&run(BIN, &wt.dir, &["src"]));
    assert_eq!(report["files_scanned"], 2);
    let mut found = files(&report, "functions");
    found.sort();
    assert_eq!(found, ["src/attrs.rs", "src/docs.rs"]);
    assert_eq!(
        skipped(&report),
        [(
            "src/inside.rs".into(),
            "nested or chained too deeply to parse".into()
        )]
    );
}

#[test]
fn its_child_answers_each_file_in_a_frame_and_names_none() {
    use std::io::Write;
    let frame = |bytes: &[u8]| [&(bytes.len() as u64).to_le_bytes()[..], bytes].concat();
    let input = [
        frame(b"fn a() { let x = 1 + 2; }\n"),
        frame(&[0xff, 0xfe]),
        frame(b"fn (\n"),
    ]
    .concat();
    let mut child = Command::new(BIN)
        .arg("--internal-parse-stdin")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the child");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&input)
        .expect("write the frames");
    let out = child.wait_with_output().expect("the child ends");
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    let mut rest = &out.stdout[..];
    let mut answers = Vec::new();
    while !rest.is_empty() {
        let len = u64::from_le_bytes(rest[..8].try_into().expect("a length")) as usize;
        answers.push(serde_json::from_slice::<Value>(&rest[8..8 + len]).expect("JSON"));
        rest = &rest[8 + len..];
    }
    assert_eq!(answers.len(), 3);
    assert_eq!(answers[0]["files_scanned"], 1);
    assert_eq!(answers[0]["arithmetic_sites"][0]["file"], "");
    assert_eq!(answers[0]["arithmetic_sites"][0]["snippet"], "1 + 2");
    assert_eq!(answers[1]["files_scanned"], 0);
    assert_eq!(answers[1]["skipped"][0]["reason"], "not UTF-8");
    assert_eq!(answers[2]["skipped"][0]["reason"], "does not parse as Rust");

    // A frame longer than a file may be ends it, with nothing said.
    let mut child = Command::new(BIN)
        .arg("--internal-parse-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the child");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&(5u64 << 20).to_le_bytes())
        .expect("write the length");
    let out = child.wait_with_output().expect("the child ends");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

#[test]
fn lists_at_most_twenty_thousand_items_a_file() {
    let wt = Wt::repo();
    // 2 statements of 19,990 indexes each: 119,993 bytes, 39,980 index sites. The
    // 4 MiB file of 69 such statements is scan_sites.rs's, which gives its child
    // more time than audit-scan does.
    let statement = format!("    let x = a{};\n", "[0]".repeat(19_990));
    let amp = format!("pub fn f(a: &[u8]) {{\n{}}}\n", statement.repeat(2));
    assert_eq!(amp.len(), 119_993);
    wt.write("src/amp.rs", amp.as_bytes());
    wt.write("src/lib.rs", b"fn ok() { let y = v[1]; }\n");
    let out = run(BIN, &wt.dir, &["src"]);
    let report = json(&out);
    assert!(out.stdout.len() < 4 << 20, "{} bytes", out.stdout.len());
    assert_eq!(report["files_scanned"], 2);
    let from = |key: &str, file: &str| files(&report, key).iter().filter(|f| *f == file).count();
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
        skipped(&report),
        [(
            "src/amp.rs".into(),
            "lists only the first 20,000 sites".into()
        )]
    );
}

#[test]
fn lists_only_what_fits_in_an_answer_of_32_mib_a_file() {
    let wt = Wt::repo();
    // A 1 MiB name that each of the struct's 40 PDAs repeats, about 41 MiB as JSON:
    // neither the struct nor what follows it in the file is listed.
    let name = format!("S{}", "a".repeat(1 << 20));
    let pda = format!(
        "fn before() {{}}\n{}fn after() {{}}\n",
        common::pda_struct(&name, 40)
    );
    wt.write("src/pda.rs", pda.as_bytes());
    wt.write("src/lib.rs", b"fn ok() { let y = v[1]; }\n");
    let out = run(BIN, &wt.dir, &["src"]);
    let report = json(&out);
    assert!(out.stdout.len() < 64 << 10, "{} bytes", out.stdout.len());
    assert_eq!(report["files_scanned"], 2);
    let names: Vec<&str> = report["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|f| f["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(names, ["ok", "before"]);
    assert!(files(&report, "accounts_structs").is_empty());
    assert!(files(&report, "pdas").is_empty());
    assert_eq!(files(&report, "panic_sites"), ["src/lib.rs"]);
    assert_eq!(
        skipped(&report),
        [(
            "src/pda.rs".into(),
            "lists only the sites that fit in 32 MiB".into()
        )]
    );
}

#[test]
fn an_answer_near_32_mib_is_taken_whole() {
    let wt = Wt::repo();
    // Three structs, each a 1 MiB name and 14 PDAs, about 15 MiB as JSON: the first
    // two fit in the answer, about 30 MiB, and the third does not.
    let source: String = ["A", "B", "C"]
        .iter()
        .map(|c| common::pda_struct(&c.repeat(1 << 20), 14))
        .collect();
    assert!(source.len() < 4 << 20);
    wt.write("src/three.rs", source.as_bytes());
    let out = run(BIN, &wt.dir, &["src"]);
    let report = json(&out);
    assert!(out.stdout.len() > 30 << 20, "{} bytes", out.stdout.len());
    let first: Vec<char> = report["accounts_structs"]
        .as_array()
        .expect("accounts_structs")
        .iter()
        .map(|s| {
            s["name"]
                .as_str()
                .and_then(|n| n.chars().next())
                .expect("a name")
        })
        .collect();
    assert_eq!(first, ['A', 'B']);
    assert_eq!(files(&report, "pdas").len(), 28);
    assert_eq!(
        skipped(&report),
        [(
            "src/three.rs".into(),
            "lists only the sites that fit in 32 MiB".into()
        )]
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
fn renders_the_snippets_that_start_at_a_long_literal_in_time() {
    let wt = Wt::repo();
    // A literal of a million spaces that each of 9,990 sites' snippets starts at.
    let sum = format!(
        "fn f() {{ let x = \"{}\"{}; }}\n",
        " ".repeat(1_000_000),
        " + a".repeat(9_990)
    );
    wt.write("src/sum.rs", sum.as_bytes());
    let started = std::time::Instant::now();
    let report = json(&run(BIN, &wt.dir, &["src"]));
    let took = started.elapsed();
    assert_eq!(skipped(&report), []);
    let sites = report["arithmetic_sites"].as_array().expect("sites");
    assert_eq!(sites.len(), 9_990);
    // 80 characters, then the cut.
    let first = format!("\" \"{} ...", " + a".repeat(19));
    assert_eq!(sites[0]["snippet"], first);
    assert_eq!(sites[9_989]["snippet"], "\" \" + a");
    assert!(took.as_secs_f64() < 5.0, "took {took:?}");
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
    // At least 30 scans, however long a loaded host takes for them (up to two
    // minutes), and more, up to 300, while the first 6 seconds last.
    let started = std::time::Instant::now();
    let mut scans = 0;
    let mut leaked = 0;
    while scans < 300
        && (started.elapsed().as_secs() < 6 || (scans < 30 && started.elapsed().as_secs() < 120))
    {
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

const RUN_DIR: &str = "a run directory (a .gitignore of * and nothing tracked), not scanned";
const STORE: &str = "the audit-mem store (a .gitignore of * and nothing tracked), not scanned";
const BUILD: &str =
    "a target/ directory cargo built in (it holds CACHEDIR.TAG or .rustc_info.json), not scanned";

/// The `CACHEDIR.TAG` cargo writes in a target directory it makes.
const CARGO_TAG: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55\n\
# This file is a cache directory tag created by cargo.\n\
# For information about cache directory tags see https://bford.info/cachedir/\n";

/// A `.rustc_info.json` as cargo writes it in each target directory it builds in,
/// its start as cargo 1.85 and 1.99 write it.
const RUSTC_INFO: &[u8] =
    b"{\"rustc_fingerprint\":16663139784161297601,\"outputs\":{},\"successes\":{}}";

#[test]
fn prunes_a_target_directory_cargo_built_in_without_making_it() {
    // A target/ made before cargo's first build, as `anchor` can make
    // target/deploy, holds the .rustc_info.json cargo writes but no CACHEDIR.TAG.
    let wt = Wt::new();
    wt.write("src/lib.rs", b"fn a() {}\n");
    wt.write("target/.rustc_info.json", RUSTC_INFO);
    wt.mkdir("target/deploy");
    wt.write(
        "target/release/build/g-1/out/generated.rs",
        b"fn generated() {}\n",
    );
    // One whose .rustc_info.json is not cargo's, and one where it is a FIFO,
    // which the scan does not wait on, are scanned.
    wt.write("programs/p/target/.rustc_info.json", b"{\"outputs\":{}}");
    wt.write("programs/p/target/lib.rs", b"fn near_miss() {}\n");
    wt.mkdir("programs/q/target");
    let status = Command::new("mkfifo")
        .arg(wt.path("programs/q/target/.rustc_info.json"))
        .status()
        .expect("mkfifo");
    assert!(status.success());
    wt.write("programs/q/target/lib.rs", b"fn fifo() {}\n");
    let report = json(&run(BIN, &wt.dir, &["."]));
    assert_eq!(
        files(&report, "functions"),
        vec![
            "./programs/p/target/lib.rs",
            "./programs/q/target/lib.rs",
            "./src/lib.rs",
        ]
    );
    assert_eq!(skipped(&report), [("./target".into(), BUILD.into())]);
}

#[test]
fn prunes_the_run_directories_and_store_an_audit_made_at_the_top_only() {
    let wt = Wt::repo();
    wt.write("src/lib.rs", b"fn a() {}\n");
    wt.run_dir("audit_1");
    wt.write("audit_1/poc/F-1/src/lib.rs", b"fn poc() {}\n");
    wt.run_dir(".audit-memory");
    wt.write(".audit-memory/x.rs", b"fn mem() {}\n");
    wt.write("target/CACHEDIR.TAG", CARGO_TAG);
    wt.write("target/debug/build.rs", b"fn built() {}\n");
    // A directory named target without cargo's tag, such as a source module, and
    // one whose tag is not cargo's, are scanned.
    wt.write("src/target/mod.rs", b"fn module() {}\n");
    wt.write(
        "programs/p/target/CACHEDIR.TAG",
        b"Signature: 8a477f597d28d172789f06886806bc5\n",
    );
    wt.write("programs/p/target/lib.rs", b"fn near_miss() {}\n");
    wt.write("app/node_modules/m/lib.rs", b"fn installed() {}\n");
    wt.write("programs/p/audit_2/lib.rs", b"fn kept() {}\n");
    // Target code under a run directory's name, tracked or without the
    // .gitignore of * a run directory holds, is scanned.
    wt.write("audit_7/src/lib.rs", b"fn tracked() {}\n");
    wt.git(&["add", "audit_7"]);
    wt.run_dir("audit_8");
    wt.write("audit_8/src/lib.rs", b"fn marked_but_tracked() {}\n");
    wt.git(&["add", "-f", "audit_8"]);
    wt.write("incident_42/src/lib.rs", b"fn unmarked() {}\n");
    let report = json(&run(BIN, &wt.dir, &["."]));
    assert_eq!(
        files(&report, "functions"),
        vec![
            "./audit_7/src/lib.rs",
            "./audit_8/src/lib.rs",
            "./incident_42/src/lib.rs",
            "./programs/p/audit_2/lib.rs",
            "./programs/p/target/lib.rs",
            "./src/lib.rs",
            "./src/target/mod.rs",
        ]
    );
    assert_eq!(
        skipped(&report),
        [
            ("./.audit-memory".into(), STORE.into()),
            (
                "./.git".into(),
                "a .git/ directory (git's own), not scanned".into()
            ),
            (
                "./app/node_modules".into(),
                "a node_modules/ directory (installed packages), not scanned".into()
            ),
            ("./audit_1".into(), RUN_DIR.into()),
            ("./target".into(), BUILD.into()),
        ]
    );
    let poc = json(&run(BIN, &wt.dir, &["audit_1/poc"]));
    assert_eq!(files(&poc, "functions"), vec!["audit_1/poc/F-1/src/lib.rs"]);
}

#[test]
fn scans_a_store_the_repository_tracks_and_a_tree_outside_git_by_its_marks() {
    let wt = Wt::repo();
    wt.run_dir(".audit-memory");
    wt.write(".audit-memory/src/lib.rs", b"fn tracked_store() {}\n");
    wt.git(&["add", "-f", ".audit-memory"]);
    let report = json(&run(BIN, &wt.dir, &["."]));
    assert_eq!(
        files(&report, "functions"),
        vec!["./.audit-memory/src/lib.rs"]
    );
    // Outside any repository, only the mark tells: audit_3 holds it, audit_7 not.
    let copy = Wt::new();
    copy.run_dir("audit_3");
    copy.write("audit_3/poc/lib.rs", b"fn poc() {}\n");
    copy.write("audit_7/src/lib.rs", b"fn delivered() {}\n");
    let report = json(&run(BIN, &copy.dir, &["."]));
    assert_eq!(files(&report, "functions"), vec!["./audit_7/src/lib.rs"]);
    assert_eq!(skipped(&report), [("./audit_3".into(), RUN_DIR.into())]);
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
    let usage = "usage: audit-scan [--contract=1] <dir> [--workflows <dir>] [--out <run dir>/prescan.json | <run dir>/prescan-<slug>.json] [--pretty]";
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
        (vec![".", "--workflows"], "--workflows needs a directory"),
        (
            vec![".", "--workflows", "src", "--workflows=src"],
            "--workflows is given more than once",
        ),
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
fn takes_the_contract_marker_first_and_refuses_any_other() {
    let wt = Wt::repo();
    wt.write("src/lib.rs", b"fn a() { let x = 1 + 2; }\n");
    wt.run_dir("audit_1");
    let plain = stdout(&run(BIN, &wt.dir, &["src"]));
    assert_eq!(stdout(&run(BIN, &wt.dir, &["--contract=1", "src"])), plain);
    let out = run(
        BIN,
        &wt.dir,
        &["--contract=1", "src", "--out", "audit_1/prescan.json"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(wt.read("audit_1/prescan.json"), plain.as_bytes());
    let usage = "usage: audit-scan [--contract=1] <dir> [--workflows <dir>] [--out <run dir>/prescan.json | <run dir>/prescan-<slug>.json] [--pretty]";
    let other =
        "names a contract this build does not keep (it keeps --contract=1); rebuild it with \
                 cargo build --release --locked in tools/auditor-tools";
    let before = wt.snapshot();
    for (args, why) in [
        (
            vec!["src", "--contract=1"],
            "--contract=1 comes first, once".to_string(),
        ),
        (
            vec!["--contract=1", "--contract=1", "src"],
            "--contract=1 comes first, once".to_string(),
        ),
        (vec!["--contract=2", "src"], format!("--contract=2 {other}")),
        (vec!["--contract", "src"], format!("--contract {other}")),
        (
            vec!["--contract=1 ", "src"],
            format!("--contract=1  {other}"),
        ),
        (vec!["src", "--contracts"], format!("--contracts {other}")),
    ] {
        refused(
            &run(BIN, &wt.dir, &args),
            "audit-scan",
            &format!("{why} ({usage})"),
        );
    }
    assert_eq!(wt.snapshot(), before);
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
    // Printing to stdout needs no answer from git: a run directory git cannot
    // answer for is scanned.
    wt.write("audit_1/poc/F-1/src/lib.rs", b"fn poc() {}\n");
    let report = json(&run(BIN, &wt.dir, &["."]));
    assert_eq!(
        files(&report, "functions"),
        vec!["./audit_1/poc/F-1/src/lib.rs"]
    );
}

#[test]
fn asks_git_no_more_once_it_has_not_answered() {
    let wt = Wt::new();
    for name in ["audit_1", "audit_2", "audit_3"] {
        wt.run_dir(name);
        wt.write(&format!("{name}/poc/lib.rs"), b"fn poc() {}\n");
    }
    // A git first on PATH, outside the working tree, that notes each call and
    // answers none.
    let bin = wt.outside().join("bin");
    fs::create_dir(&bin).expect("mkdir");
    let calls = wt.outside().join("calls");
    write_script(
        &bin.join("git"),
        &format!("#!/bin/sh\necho \"$1\" >> '{}'\nexit 1\n", calls.display()),
    );
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let report = json(&common::run_env(BIN, &wt.dir, &["."], &[("PATH", &path)]));
    assert_eq!(
        files(&report, "functions"),
        vec![
            "./audit_1/poc/lib.rs",
            "./audit_2/poc/lib.rs",
            "./audit_3/poc/lib.rs",
        ]
    );
    assert_eq!(skipped(&report), []);
    let asked = fs::read_to_string(&calls).expect("git was asked");
    assert_eq!(asked.lines().count(), 1, "{asked}");
}

/// An executable script at `to`, written by `/bin/sh`, not by this process, for
/// the reason `copy_binary` gives.
fn write_script(to: &Path, text: &str) {
    let status = Command::new("/bin/sh")
        .args([
            "-c",
            "printf '%s' \"$1\" > \"$2\" && chmod 755 \"$2\"",
            "sh",
        ])
        .arg(text)
        .arg(to)
        .stdin(Stdio::null())
        .status()
        .expect("run sh");
    assert!(status.success(), "write {}", to.display());
}

/// A copy of the binary at `to`, written by `cp`. This process never holds the
/// copy open for writing, so no child another test starts meanwhile inherits such a
/// descriptor, which on Linux makes running the copy fail with ETXTBSY (`Text file
/// busy`) until that child execs.
fn copy_binary(to: &Path) {
    let status = Command::new("cp")
        .arg(BIN)
        .arg(to)
        .stdin(Stdio::null())
        .status()
        .expect("run cp");
    assert!(status.success(), "cp {BIN} {}", to.display());
}

#[test]
fn refuses_to_run_from_inside_the_working_tree() {
    let wt = Wt::new();
    wt.mkdir("tools/auditor-tools/target/release");
    let inside = wt.path("tools/auditor-tools/target/release/audit-scan");
    copy_binary(&inside);
    let o = run(inside.to_str().expect("UTF-8"), &wt.dir, &["."]);
    refused(
        &o,
        "audit-scan",
        "the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)",
    );
    let quoted = wt.outside().join("a$b");
    fs::create_dir(&quoted).expect("mkdir");
    copy_binary(&quoted.join("audit-scan"));
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

#[test]
fn waits_once_for_a_git_that_does_not_answer() {
    use auditor_tools::confine::GIT_TIME;
    let wt = Wt::repo();
    for name in ["audit_1", "audit_2", "audit_3"] {
        wt.run_dir(name);
        wt.write(&format!("{name}/poc/lib.rs"), b"fn poc() {}\n");
    }
    // A git that never answers (here one first on PATH that sleeps), as one
    // blocked opening a file would be: it is killed when its time is up.
    let slow = wt.outside().join("slow");
    fs::create_dir(&slow).expect("make the slow git's directory");
    write_script(&slow.join("git"), "#!/bin/sh\nexec /bin/sleep 60\n");
    let path = format!("{}:/usr/bin:/bin", slow.display());
    let started = std::time::Instant::now();
    let report = json(&common::run_env(BIN, &wt.dir, &["."], &[("PATH", &path)]));
    let took = started.elapsed();
    assert_eq!(
        files(&report, "functions"),
        vec![
            "./audit_1/poc/lib.rs",
            "./audit_2/poc/lib.rs",
            "./audit_3/poc/lib.rs",
        ]
    );
    assert!(took >= GIT_TIME && took < GIT_TIME * 2, "took {took:?}");
}

#[test]
fn scans_the_run_directories_at_once_when_head_is_a_named_pipe() {
    use auditor_tools::confine::GIT_TIME;
    let wt = Wt::repo();
    for name in ["audit_1", "audit_2", "audit_3"] {
        wt.run_dir(name);
        wt.write(&format!("{name}/poc/lib.rs"), b"fn poc() {}\n");
    }
    // A named pipe as HEAD, which git would wait on for good when it opens it:
    // no git is started, so nothing waits, and each run directory is scanned.
    fs::remove_file(wt.path(".git/HEAD")).expect("remove HEAD");
    let status = Command::new("mkfifo")
        .arg(wt.path(".git/HEAD"))
        .status()
        .expect("mkfifo");
    assert!(status.success());
    let started = std::time::Instant::now();
    let report = json(&run(BIN, &wt.dir, &["."]));
    let took = started.elapsed();
    assert_eq!(
        files(&report, "functions"),
        vec![
            "./audit_1/poc/lib.rs",
            "./audit_2/poc/lib.rs",
            "./audit_3/poc/lib.rs",
        ]
    );
    assert!(took < GIT_TIME / 2, "took {took:?}");
}

const NODE_MODULES: &str = "a node_modules/ directory (installed packages), not scanned";

#[test]
fn lists_each_file_a_parsed_file_brings_in_that_it_does_not_parse() {
    let wt = Wt::repo();
    wt.write(
        "src/lib.rs",
        b"#[path = \"cpi.inc\"]\nmod cpi;\n#[path = \"real.rs\"]\nmod real;\n\
          #[path = \"../../outside/x.rs\"]\nmod out;\n\
          #[cfg_attr(unix, path = \"unix.inc\")]\n#[cfg_attr(windows, path = \"win.rs\")]\nmod os;\n\
          #[path = \"thread_files\"]\nmod thread {\n    #[path = \"tls.in\"]\n    mod local_data;\n}\n\
          include!(\"more.in\");\n\
          pub fn f() -> u8 {\n    include!(concat!(env!(\"OUT_DIR\"), \"/gen.rs\"))\n}\n\
          #[path = \"node_modules/hide.rs\"]\nmod hide;\n#[path = \"target/gen.rs\"]\nmod gen;\n\
          #[path = \"linked/l.rs\"]\nmod linked;\n#[path = \"../audit_1/poc.rs\"]\nmod poc;\n\
          #[path = \"a/early.rs\"]\nmod early;\n#[path = \"ln.rs\"]\nmod ln;\n",
    );
    wt.write(
        "src/a/b.rs",
        b"mod inline {\n    #[path = \"deep.in\"]\n    mod d;\n}\n#[path = \"../c.inc\"]\nmod c;\n",
    );
    wt.write("src/real.rs", b"fn r() {}\n");
    // Files the walk parses before the file that brings them in (a/early.rs) or
    // after it (real.rs) get no entry, nor one it lists for itself (ln.rs, a link);
    // those in a directory it does not enter (one it prunes, a link, a run
    // directory) and one it does not find (win.rs) do.
    wt.write("src/a/early.rs", b"fn e() {}\n");
    wt.write("../outside/ln.rs", b"fn ln() {}\n");
    wt.link(&wt.outside().join("ln.rs"), "src/ln.rs");
    wt.write(
        "src/node_modules/hide.rs",
        b"fn h() { invoke_signed(&ix, &a, &[]); }\n",
    );
    wt.write("src/target/CACHEDIR.TAG", CARGO_TAG);
    wt.write("src/target/gen.rs", b"fn g() { invoke(&ix, &a); }\n");
    wt.write("../outside/linked/l.rs", b"fn l() {}\n");
    wt.link(&wt.outside().join("linked"), "src/linked");
    wt.run_dir("audit_1");
    wt.write("audit_1/poc.rs", b"fn p() {}\n");
    for (root, at) in [("src", "src"), (".", "./src")] {
        let report = json(&run(BIN, &wt.dir, &[root]));
        assert_eq!(report.get("brought_in"), None, "{root}: never printed");
        assert_eq!(report["files_scanned"], 4, "{root}");
        assert_eq!(report["cpi_sites"], serde_json::json!([]), "{root}");
        let by = |file: &str, how: &str, line: u32| {
            format!("{at}/{file} brings it in ({how}, line {line})")
        };
        let unentered = |file: &str, line: u32| {
            (
                format!("{at}/{file}"),
                format!(
                    "not parsed: in a directory the walk did not enter; {}",
                    by("lib.rs", "#[path]", line)
                ),
            )
        };
        let mut want =
            vec![
            (
                format!("{at}/a/b/inline/deep.in"),
                format!("not parsed: not named *.rs; {}", by("a/b.rs", "#[path]", 3)),
            ),
            (
                format!("{at}/c.inc"),
                format!("not parsed: not named *.rs; {}", by("a/b.rs", "#[path]", 6)),
            ),
            (
                format!("{at}/cpi.inc"),
                format!("not parsed: not named *.rs; {}", by("lib.rs", "#[path]", 2)),
            ),
            (
                "../outside/x.rs".to_string(),
                format!(
                    "not parsed: outside the directory scanned; {}",
                    by("lib.rs", "#[path]", 6)
                ),
            ),
            (
                format!("{at}/unix.inc"),
                format!("not parsed: not named *.rs; {}", by("lib.rs", "#[path]", 9)),
            ),
            (
                format!("{at}/thread_files/tls.in"),
                format!("not parsed: not named *.rs; {}", by("lib.rs", "#[path]", 13)),
            ),
            (
                format!("{at}/more.in"),
                format!("not parsed: not named *.rs; {}", by("lib.rs", "include!", 15)),
            ),
            (
                format!("{at}/lib.rs"),
                "brings in a file it names with no string literal (include!, line 17), which is \
                 not parsed"
                    .to_string(),
            ),
            (
                format!("{at}/win.rs"),
                format!(
                    "not parsed: the walk found no such file; {}",
                    by("lib.rs", "#[path]", 9)
                ),
            ),
            unentered("node_modules/hide.rs", 20),
            (format!("{at}/node_modules"), NODE_MODULES.to_string()),
            unentered("target/gen.rs", 22),
            (format!("{at}/target"), BUILD.to_string()),
            unentered("linked/l.rs", 24),
            (
                format!("{at}/linked"),
                "a symbolic link, not followed".to_string(),
            ),
            (
                format!("{at}/ln.rs"),
                "a symbolic link, not followed".to_string(),
            ),
        ];
        if root == "." {
            want.push((
                "./.git".to_string(),
                "a .git/ directory (git's own), not scanned".to_string(),
            ));
            want.push(("./audit_1".to_string(), RUN_DIR.to_string()));
            want.push((
                "./audit_1/poc.rs".to_string(),
                format!(
                    "not parsed: in a directory the walk did not enter; {}",
                    by("lib.rs", "#[path]", 26)
                ),
            ));
        } else {
            want.push((
                "audit_1/poc.rs".to_string(),
                format!(
                    "not parsed: outside the directory scanned; {}",
                    by("lib.rs", "#[path]", 26)
                ),
            ));
        }
        want.sort();
        assert_eq!(skipped(&report), want, "{root}");
    }

    // A program that brings code in from its node_modules/ and from a target/
    // cargo built in, both beside its src/, by #[path] and by include!: each file
    // is listed, beside the directory the walk prunes.
    let wt = Wt::repo();
    wt.write(
        "programs/foo/src/lib.rs",
        b"#[path = \"../node_modules/hide.rs\"]\nmod hide;\n\
          #[path = \"../target/gen.rs\"]\nmod gen;\ninclude!(\"../target/inc.rs\");\n",
    );
    wt.write(
        "programs/foo/node_modules/hide.rs",
        b"fn h() { invoke_signed(&ix, &a, &[]); }\n",
    );
    wt.write("programs/foo/target/CACHEDIR.TAG", CARGO_TAG);
    wt.write(
        "programs/foo/target/gen.rs",
        b"fn g() { invoke(&ix, &a); }\n",
    );
    wt.write(
        "programs/foo/target/inc.rs",
        b"fn i() { invoke(&ix, &a); }\n",
    );
    for (root, at) in [("programs/foo", "programs/foo"), (".", "./programs/foo")] {
        let report = json(&run(BIN, &wt.dir, &[root]));
        assert_eq!(report["files_scanned"], 1, "{root}");
        assert_eq!(report["cpi_sites"], serde_json::json!([]), "{root}");
        let unentered = |file: &str, how: &str, line: u32| {
            (
                format!("{at}/{file}"),
                format!(
                    "not parsed: in a directory the walk did not enter; {at}/src/lib.rs brings \
                     it in ({how}, line {line})"
                ),
            )
        };
        let mut want = vec![
            (format!("{at}/node_modules"), NODE_MODULES.to_string()),
            unentered("node_modules/hide.rs", "#[path]", 2),
            (format!("{at}/target"), BUILD.to_string()),
            unentered("target/gen.rs", "#[path]", 4),
            unentered("target/inc.rs", "include!", 5),
        ];
        if root == "." {
            want.push((
                "./.git".to_string(),
                "a .git/ directory (git's own), not scanned".to_string(),
            ));
        }
        want.sort();
        assert_eq!(skipped(&report), want, "{root}");
    }
}
