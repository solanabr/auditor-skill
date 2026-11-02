//! The `--workflows` pass as a command: the facts it reads, the files it skips,
//! and the workflows directory it refuses.

mod common;

use std::collections::HashMap;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::{refused, refused_with, run, shown, stdout, Wt};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_audit-scan");

/// A pull_request_target job that checks out the PR head, for the tests that
/// expect it to be read after what comes before it.
const PRT_JOBS: &str = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: ./build.sh\n";

/// A repository with `src/lib.rs`, a run directory, and the given
/// `.github/workflows/<name>` files.
fn repo_with(files: &[(&str, &[u8])]) -> Wt {
    let wt = Wt::repo();
    wt.write("src/lib.rs", b"fn a() {}\n");
    wt.run_dir("audit_1");
    for (name, body) in files {
        wt.write(&format!(".github/workflows/{name}"), body);
    }
    wt
}

fn report(wt: &Wt, args: &[&str]) -> Value {
    let out = run(BIN, &wt.dir, args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        common::stderr(&out)
    );
    serde_json::from_slice(&out.stdout).expect("audit-scan prints JSON")
}

/// A representative workflow, built line by line so each line's indentation is
/// explicit (a `\`-continuation in a Rust string would eat it).
fn ci() -> Vec<u8> {
    [
        "name: ci",
        "on:",
        "  pull_request_target:",
        "    types: [opened, synchronize]",
        "permissions:",
        "  contents: write",
        "jobs:",
        "  build:",
        "    if: github.actor != 'dependabot[bot]'",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v5",
        "        with:",
        "          ref: ${{ github.event.pull_request.head.sha }}",
        "      - run: echo ${{ github.event.pull_request.title }}",
        "",
    ]
    .join("\n")
    .into_bytes()
}

#[test]
fn parses_workflows_into_trigger_job_step_facts() {
    let wt = repo_with(&[("ci.yml", &ci())]);
    let r = report(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
    );
    assert_eq!(r["skipped"].as_array().unwrap().len(), 0);
    let wfs = r["workflows"].as_array().unwrap();
    assert_eq!(wfs.len(), 1);
    let w = &wfs[0];
    assert_eq!(w["file"], ".github/workflows/ci.yml");
    assert_eq!(w["name"], "ci");
    assert_eq!(w["triggers"][0], "pull_request_target");
    assert_eq!(w["permissions"][0], "contents: write");
    let job = &w["jobs"][0];
    assert_eq!(job["id"], "build");
    assert_eq!(job["if"], "github.actor != 'dependabot[bot]'");
    let steps = job["steps"].as_array().unwrap();
    assert_eq!(steps[0]["uses"], "actions/checkout@v5");
    assert_eq!(steps[0]["with"][0]["key"], "ref");
    assert_eq!(
        steps[0]["with"][0]["value"],
        "${{ github.event.pull_request.head.sha }}"
    );
    assert_eq!(
        steps[1]["run"],
        "echo ${{ github.event.pull_request.title }}"
    );
    assert!(w["unknown"].as_array().unwrap().is_empty());
}

#[test]
fn the_workflows_key_is_empty_without_the_flag() {
    let wt = repo_with(&[("ci.yml", &ci())]);
    let r = report(&wt, &["--contract=1", "./src"]);
    assert_eq!(r["workflows"].as_array().unwrap().len(), 0);
}

#[test]
fn reads_both_yml_and_yaml_in_byte_order() {
    let wt = repo_with(&[("b.yaml", b"on: push\n"), ("a.yml", b"on: pull_request\n")]);
    let r = report(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
    );
    let names: Vec<&str> = r["workflows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["file"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [".github/workflows/a.yml", ".github/workflows/b.yaml"]
    );
}

#[test]
fn marks_constructs_outside_the_subset_unknown_without_expanding() {
    let wt = repo_with(&[("anchor.yml", b"on: push\nx: &a value\ny: *a\n")]);
    let r = report(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
    );
    // The file is parsed (not skipped); its triggers are read, and the anchor
    // and alias are listed as unknown rather than expanded.
    assert_eq!(r["skipped"].as_array().unwrap().len(), 0);
    let w = &r["workflows"][0];
    assert_eq!(w["triggers"][0], "push");
    let unknown: Vec<&str> = w["unknown"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["what"].as_str().unwrap())
        .collect();
    assert!(unknown.iter().any(|u| u.contains("anchor")), "{unknown:?}");
    assert!(unknown.iter().any(|u| u.contains("alias")), "{unknown:?}");
}

#[test]
fn skips_a_file_it_cannot_parse() {
    let wt = repo_with(&[
        ("two-docs.yml", b"on: push\n---\non: pull_request\n"),
        ("not-a-map.yml", b"- one\n- two\n"),
    ]);
    wt.write(
        ".github/workflows/binary.yml",
        &[0x6f, 0x6e, 0x3a, 0xff, 0xfe],
    );
    let r = report(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
    );
    let mut skipped: Vec<(String, String)> = r["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["file"].as_str().unwrap().to_string(),
                s["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    skipped.sort();
    assert_eq!(
        skipped,
        [
            (
                ".github/workflows/binary.yml".to_string(),
                "not UTF-8".to_string()
            ),
            (
                ".github/workflows/not-a-map.yml".to_string(),
                "not a YAML mapping".to_string()
            ),
            (
                ".github/workflows/two-docs.yml".to_string(),
                "holds more than one YAML document".to_string()
            ),
        ]
    );
}

#[test]
fn a_file_larger_than_four_mib_is_skipped() {
    let wt = Wt::repo();
    wt.write("src/lib.rs", b"fn a() {}\n");
    let mut big = b"on: push\n".to_vec();
    big.resize(4 * 1024 * 1024 + 1, b'\n');
    wt.write(".github/workflows/big.yml", &big);
    let r = report(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
    );
    assert_eq!(r["workflows"].as_array().unwrap().len(), 0);
    assert_eq!(r["skipped"][0]["file"], ".github/workflows/big.yml");
    assert_eq!(r["skipped"][0]["reason"], "larger than 4 MiB");
}

#[test]
fn over_deep_yaml_is_marked_unknown_and_does_not_crash() {
    let mut src = String::from("a:\n");
    for i in 0..60 {
        src.push_str(&"  ".repeat(i + 1));
        src.push_str("b:\n");
    }
    let wt = repo_with(&[("deep.yml", src.as_bytes())]);
    let r = report(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
    );
    assert_eq!(r["skipped"].as_array().unwrap().len(), 0);
    let unknown: Vec<&str> = r["workflows"][0]["unknown"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["what"].as_str().unwrap())
        .collect();
    assert!(
        unknown.iter().any(|u| u.contains("nested too deeply")),
        "{unknown:?}"
    );
}

#[test]
fn a_link_or_non_regular_file_is_listed_not_followed() {
    let wt = repo_with(&[("real.yml", b"on: push\n")]);
    wt.write("../outside/secret.yml", b"on: pull_request\n");
    wt.link(
        &wt.outside().join("secret.yml"),
        ".github/workflows/link.yml",
    );
    // A FIFO named like a workflow.
    std::process::Command::new("mkfifo")
        .arg(wt.path(".github/workflows/fifo.yml"))
        .status()
        .expect("mkfifo");
    let r = report(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
    );
    assert_eq!(r["workflows"].as_array().unwrap().len(), 1);
    assert_eq!(r["workflows"][0]["file"], ".github/workflows/real.yml");
    let mut skipped: Vec<(String, String)> = r["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["file"].as_str().unwrap().to_string(),
                s["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    skipped.sort();
    assert_eq!(
        skipped,
        [
            (
                ".github/workflows/fifo.yml".to_string(),
                "not a regular file".to_string()
            ),
            (
                ".github/workflows/link.yml".to_string(),
                "a symbolic link, not followed".to_string()
            ),
        ]
    );
    // The file outside, reachable only through the link, was not read.
    assert!(!stdout(&run(
        BIN,
        &wt.dir,
        &["--contract=1", "./src", "--workflows", ".github/workflows"]
    ))
    .contains("pull_request"));
}

#[test]
fn refuses_a_workflows_directory_outside_the_grammar() {
    let wt = repo_with(&[("ci.yml", &ci())]);
    wt.write("notes.txt", b"x\n");
    wt.link(&wt.outside().to_path_buf(), "linkdir");
    for (arg, why) in [
        ("absent", "--workflows is not an existing directory: absent"),
        (
            "notes.txt",
            "--workflows is not an existing directory: notes.txt",
        ),
        (
            "linkdir",
            "--workflows passes through a symbolic link: linkdir",
        ),
        (
            "../outside",
            "--workflows has an empty, . or .. component: ../outside",
        ),
    ] {
        refused(
            &run(BIN, &wt.dir, &["--contract=1", "./src", "--workflows", arg]),
            "audit-scan",
            why,
        );
    }
    // An absolute path, and a leading dash, are refused before anything is read.
    let abs = wt.dir.as_os_str().as_bytes();
    refused(
        &run(
            BIN,
            &wt.dir,
            &[
                "--contract=1",
                "./src",
                "--workflows",
                &String::from_utf8_lossy(abs),
            ],
        ),
        "audit-scan",
        &format!(
            "--workflows must be relative to the working directory: {}",
            shown(&wt.dir.display().to_string())
        ),
    );
    refused_with(
        &run(BIN, &wt.dir, &["--contract=1", ".", "--workflows=--pretty"]),
        "audit-scan",
        "--workflows may not start with - or ~: --pretty",
    );
}

/// audit-scan run from `dir`, killed and failed if it has not ended within
/// `limit`: a parse that does not finish must not hold up the scan.
fn run_within(wt: &Wt, args: &[&str], limit: Duration) -> Output {
    let out = wt.outside().join("run.out");
    let err = wt.outside().join("run.err");
    let mut child = Command::new(BIN)
        .args(args)
        .current_dir(&wt.dir)
        .stdin(Stdio::null())
        .stdout(File::create(&out).expect("make run.out"))
        .stderr(File::create(&err).expect("make run.err"))
        .spawn()
        .expect("start audit-scan");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll audit-scan") {
            break status;
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("audit-scan did not end within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: fs::read(out).expect("read run.out"),
        stderr: fs::read(err).expect("read run.err"),
    }
}

/// Each workflow's facts by the file's name, from a `--workflows` report.
fn by_name(r: &Value) -> HashMap<String, Value> {
    r["workflows"]
        .as_array()
        .expect("workflows")
        .iter()
        .map(|w| {
            let file = w["file"].as_str().expect("file");
            let name = file.rsplit('/').next().expect("a name").to_string();
            (name, w.clone())
        })
        .collect()
}

fn unknown_of(w: &Value) -> Vec<(u64, String)> {
    w["unknown"]
        .as_array()
        .expect("unknown")
        .iter()
        .map(|u| {
            (
                u["line"].as_u64().expect("line"),
                u["what"].as_str().expect("what").to_string(),
            )
        })
        .collect()
}

/// The PR-head checkout job of `PRT_JOBS`, as a report lists it.
fn assert_prt_job(w: &Value) {
    let jobs = w["jobs"].as_array().expect("jobs");
    let job = jobs
        .iter()
        .find(|j| j["id"] == "b")
        .unwrap_or_else(|| panic!("no job b: {w}"));
    let steps = job["steps"].as_array().expect("steps");
    assert_eq!(steps.len(), 2, "{w}");
    assert_eq!(steps[0]["uses"], "actions/checkout@v4", "{w}");
    assert_eq!(
        steps[0]["with"][0]["value"], "${{ github.event.pull_request.head.sha }}",
        "{w}"
    );
    assert_eq!(steps[1]["run"], "./build.sh", "{w}");
    assert!(
        w["triggers"]
            .as_array()
            .expect("triggers")
            .iter()
            .any(|t| t == "pull_request_target"),
        "{w}"
    );
}

#[test]
fn what_follows_a_construct_the_parser_does_not_read_is_still_read() {
    let mut deep = String::from("on: pull_request_target\nx:\n");
    for i in 0..40 {
        deep.push_str(&"  ".repeat(i + 1));
        deep.push_str("y:\n");
    }
    deep.push_str(PRT_JOBS);
    let anchor = "on: pull_request_target\njobs:\n  a:\n    env: &env_vars\n      NODE_ENV: production\n    steps:\n      - run: echo one\n  b:\n    env: *env_vars\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: ./build.sh\n";
    let wrapped = format!("name: Build and\n  test\non: pull_request_target\n{PRT_JOBS}");
    let quoted = format!("name: \"Build\n  and test\"\non: pull_request_target\n{PRT_JOBS}");
    let flow =
        format!("on: [push,\n  pull_request_target]\nx: {{a: 1,\n  b: [2,\n    3]}}\n{PRT_JOBS}");
    let tag = format!("on: pull_request_target\nx: !custom\n  a: 1\n{PRT_JOBS}");
    let explicit = format!("? x\n: y\non: pull_request_target\n{PRT_JOBS}");
    let merge = format!(
        "on: pull_request_target\nd: &d\n  runs-on: x\n{}",
        PRT_JOBS.replacen("    steps:", "    <<: *d\n    steps:", 1)
    );
    let wt = repo_with(&[
        ("anchor.yml", anchor.as_bytes()),
        ("deep.yml", deep.as_bytes()),
        ("explicit.yml", explicit.as_bytes()),
        ("flow.yml", flow.as_bytes()),
        ("merge.yml", merge.as_bytes()),
        ("quoted.yml", quoted.as_bytes()),
        ("tag.yml", tag.as_bytes()),
        ("wrapped.yml", wrapped.as_bytes()),
    ]);
    let r = report(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
    );
    assert_eq!(r["skipped"].as_array().unwrap().len(), 0, "{r}");
    let wfs = by_name(&r);
    assert_eq!(wfs.len(), 8);
    for w in wfs.values() {
        assert_prt_job(w);
    }
    assert_eq!(wfs["wrapped.yml"]["name"], "Build and test");
    assert_eq!(wfs["quoted.yml"]["name"], "Build and test");
    for read_whole in ["wrapped.yml", "quoted.yml", "flow.yml"] {
        assert_eq!(unknown_of(&wfs[read_whole]), [], "{read_whole}");
    }
    assert_eq!(
        unknown_of(&wfs["anchor.yml"]),
        [
            (
                4,
                "an anchor (&env_vars): its node is read; an alias to it is not expanded"
                    .to_string()
            ),
            (9, "an alias (*env_vars), not expanded".to_string()),
        ]
    );
    assert_eq!(
        unknown_of(&wfs["deep.yml"]),
        [(34, "nested too deeply: lines 34-42 not read".to_string())]
    );
    assert_eq!(
        unknown_of(&wfs["tag.yml"]),
        [(2, "a tag (!custom): lines 2-3 not read".to_string())]
    );
    assert_eq!(
        unknown_of(&wfs["explicit.yml"]),
        [(1, "an explicit key (?): lines 1-2 not read".to_string())]
    );
    assert_eq!(
        unknown_of(&wfs["merge.yml"]),
        [
            (
                2,
                "an anchor (&d): its node is read; an alias to it is not expanded".to_string()
            ),
            (6, "a merge key (<<): line 6 not read".to_string()),
        ]
    );
}

#[test]
fn what_cannot_be_placed_ends_only_that_files_read_and_says_from_where() {
    let wt = repo_with(&[
        ("a-mismatched.yml", b"x: {a]\non: push\n"),
        ("b-typo.yml", b"on: pull_request_target\nbranches: [main}\njobs: {}\n"),
        (
            "c-escaped-break.yml",
            b"on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: x\n        with:\n          a: [\"\\\n",
        ),
        (
            "d-short-line.yml",
            "on: pull_request_target\nx: |\n      a\n   \u{e9}\u{e9}\u{e9}\njobs:\n  b:\n    steps:\n      - run: echo hi\n".as_bytes(),
        ),
        ("e-escaped-key.yml", format!("\"\\x6fn\": pull_request_target\n{PRT_JOBS}").as_bytes()),
        ("f-tab.yml", b"on: pull_request_target\njobs:\n\tb:\n    steps: []\n"),
        ("g-ci.yml", &ci()),
    ]);
    let r = run_within(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
        Duration::from_secs(30),
    );
    assert_eq!(r.status.code(), Some(0), "stderr: {}", common::stderr(&r));
    let r: Value = serde_json::from_slice(&r.stdout).expect("audit-scan prints JSON");
    assert_eq!(r["skipped"].as_array().unwrap().len(), 0, "{r}");
    let wfs = by_name(&r);
    let unread = |name: &str, line: u64, what: &str| {
        assert_eq!(
            unknown_of(&wfs[name]),
            [(
                line,
                format!("{what}: not read from line {line} to the end")
            )],
            "{name}"
        );
    };
    unread(
        "a-mismatched.yml",
        1,
        "a flow mapping entry not followed by , or }",
    );
    unread(
        "b-typo.yml",
        2,
        "a flow sequence entry not followed by , or ]",
    );
    unread(
        "c-escaped-break.yml",
        7,
        "a quoted scalar that does not close",
    );
    unread(
        "d-short-line.yml",
        4,
        "a block scalar line indented less than its first",
    );
    unread("f-tab.yml", 3, "a tab in indentation");
    assert_eq!(wfs["b-typo.yml"]["triggers"][0], "pull_request_target");
    assert_prt_job(&wfs["e-escaped-key.yml"]);
    assert_eq!(unknown_of(&wfs["e-escaped-key.yml"]), []);
    assert_eq!(unknown_of(&wfs["g-ci.yml"]), []);
    assert_eq!(
        wfs["g-ci.yml"]["jobs"][0]["steps"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}
