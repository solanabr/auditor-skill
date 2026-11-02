//! The `--workflows` pass as a command: the facts it reads, the files it skips,
//! the workflows directory it refuses, the child each file is parsed in, and the
//! facts of every workflow fixture in `scripts/tests/fixtures/gha/`.

mod common;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use auditor_tools::confine::{json_text, Parser, PARSE_TIME};
use auditor_tools::workflow::{parse_workflow, scan_workflows_with, PARSE_WORKFLOWS};
use common::{refused, refused_with, run, shown, stdout, Wt};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_audit-scan");

const USAGE: &str = "usage: audit-scan [--contract=1] <dir> [--workflows <dir>] \
[--out <run dir>/prescan.json | <run dir>/prescan-<slug>.json] [--pretty]";

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
    // The report --pretty lays out holds them too.
    let r = report(
        &wt,
        &[
            "--contract=1",
            "./src",
            "--workflows",
            ".github/workflows",
            "--pretty",
        ],
    );
    assert_eq!(r["workflows"].as_array().unwrap().len(), 2);
    assert_eq!(r["skipped"].as_array().unwrap().len(), 0);
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

#[test]
fn its_workflow_child_answers_each_file_in_a_frame_and_names_none() {
    let frame = |bytes: &[u8]| [&(bytes.len() as u64).to_le_bytes()[..], bytes].concat();
    let input = [
        frame(b"on: push\njobs:\n  b:\n    steps:\n      - run: x\n"),
        frame(&[0xff, 0xfe]),
        frame(b"- a\n- b\n"),
        frame(b"on: push\nx: {a]\n"),
    ]
    .concat();
    let mut child = Command::new(BIN)
        .arg(PARSE_WORKFLOWS)
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
    assert_eq!(answers.len(), 4);
    assert_eq!(answers[0]["workflow"]["file"], "");
    assert_eq!(answers[0]["workflow"]["triggers"][0], "push");
    assert_eq!(answers[0]["workflow"]["jobs"][0]["steps"][0]["run"], "x");
    assert_eq!(answers[1]["skipped"], "not UTF-8");
    assert_eq!(answers[2]["skipped"], "not a YAML mapping");
    assert_eq!(
        answers[3]["workflow"]["unknown"][0]["what"],
        "a flow mapping entry not followed by , or }: not read from line 2 to the end"
    );

    // A frame longer than a file may be ends it, with nothing said.
    let mut child = Command::new(BIN)
        .arg(PARSE_WORKFLOWS)
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
fn the_workflow_child_word_is_refused_anywhere_but_alone() {
    let wt = repo_with(&[("ci.yml", &ci())]);
    for args in [
        &["--contract=1", PARSE_WORKFLOWS][..],
        &[".", PARSE_WORKFLOWS],
        &[PARSE_WORKFLOWS, "."],
        &[
            "--contract=1",
            ".",
            "--workflows",
            ".github/workflows",
            PARSE_WORKFLOWS,
        ],
    ] {
        refused(
            &run(BIN, &wt.dir, args),
            "audit-scan",
            &format!("unknown option {PARSE_WORKFLOWS} ({USAGE})"),
        );
    }
}

/// The pass with parsers that die and hang, with a report that fills up, and with
/// the scan's time spent: the file a parser does not finish is skipped, the next
/// file goes to a new child, and the pass goes on. One test, since it enters the
/// tree it reads.
#[test]
fn a_workflow_whose_parser_dies_or_hangs_is_skipped_and_the_caps_and_the_scans_time_hold() {
    let wt = Wt::repo();
    wt.write(".github/workflows/a.yml", b"on: push\n");
    wt.write(".github/workflows/b.yml", b"# dies\non: push\n");
    wt.write(".github/workflows/c.yml", b"# hangs\non: push\n");
    wt.write(".github/workflows/d.yml", b"on: pull_request\n");
    wt.write(".github/workflows/e.yml", b"- not\n- a mapping\n");
    std::env::set_current_dir(&wt.dir).expect("enter the tree");
    let mut real = Parser::with(Path::new(BIN), &[OsStr::new(PARSE_WORKFLOWS)]);
    let mut dies = Parser::with(
        Path::new("/bin/sh"),
        &[OsStr::new("-c"), OsStr::new("kill -s SEGV $$")],
    );
    let mut hangs = Parser::with(Path::new("/bin/sleep"), &[OsStr::new("30")]);
    let started = Instant::now();
    let (workflows, skipped) = scan_workflows_with(
        Path::new(".github/workflows"),
        usize::MAX,
        false,
        None,
        &mut |bytes| {
            if bytes.starts_with(b"# dies") {
                dies.parse(bytes, PARSE_TIME)
            } else if bytes.starts_with(b"# hangs") {
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
    let files: Vec<(&str, &str)> = workflows
        .iter()
        .map(|w| (w.file.as_str(), w.triggers[0].as_str()))
        .collect();
    assert_eq!(
        files,
        [
            (".github/workflows/a.yml", "push"),
            (".github/workflows/d.yml", "pull_request")
        ]
    );
    let skipped: Vec<(&str, &str)> = skipped
        .iter()
        .map(|s| (s.file.as_str(), s.reason.as_str()))
        .collect();
    let why = "the parser could not finish";
    assert_eq!(
        skipped,
        [
            (".github/workflows/b.yml", why),
            (".github/workflows/c.yml", why),
            (".github/workflows/e.yml", "not a YAML mapping")
        ]
    );

    // The workflows have a cap: the file whose facts would take them past it, and
    // each file after it, is not parsed.
    let steps: String = (0..100)
        .map(|i| format!("      - run: step {i}\n"))
        .collect();
    wt.write("cap/a.yml", b"on: push\n");
    wt.write(
        "cap/b.yml",
        format!("on: push\njobs:\n  b:\n    steps:\n{steps}").as_bytes(),
    );
    wt.write("cap/c.yml", b"on: push\n");
    let (workflows, skipped) =
        scan_workflows_with(Path::new("cap"), 1_000, false, None, &mut |bytes| {
            real.parse(bytes, PARSE_TIME)
        });
    assert_eq!(workflows.len(), 1);
    assert_eq!(workflows[0].file, "cap/a.yml");
    let skipped: Vec<(&str, &str)> = skipped
        .iter()
        .map(|s| (s.file.as_str(), s.reason.as_str()))
        .collect();
    let full = "not parsed: the report is full";
    assert_eq!(skipped, [("cap/b.yml", full), ("cap/c.yml", full)]);

    // The cap counts the facts as audit-scan prints them: a DEL, written \x7f in
    // YAML, takes one byte as serde_json writes it and six printed, and --pretty
    // lays out each line.
    let src = format!(
        "on: push\njobs:\n  b:\n    steps:\n      - run: x\n        env:\n          K: \"{}\"\n",
        "\\x7f".repeat(200)
    );
    wt.write("del/a.yml", src.as_bytes());
    wt.write("del/b.yml", src.as_bytes());
    let compact =
        serde_json::to_string(&parse_workflow("del/a.yml", &src).expect("parses")).expect("JSON");
    let printed = json_text(compact.clone()).len();
    assert_eq!(printed, compact.len() + 1000);
    // Each workflow takes what it prints and the comma after it.
    let mut files = |cap: usize, pretty: bool| {
        let (workflows, skipped) =
            scan_workflows_with(Path::new("del"), cap, pretty, None, &mut |b| {
                real.parse(b, PARSE_TIME)
            });
        let mut out: Vec<String> = workflows
            .iter()
            .map(|w| format!("{} read", w.file))
            .collect();
        out.extend(skipped.iter().map(|s| format!("{}: {}", s.file, s.reason)));
        out
    };
    let both = 2 * (printed + 1);
    assert_eq!(files(both, false), ["del/a.yml read", "del/b.yml read"]);
    assert_eq!(
        files(both - 1, false),
        [
            "del/a.yml read",
            "del/b.yml: not parsed: the report is full"
        ]
    );
    assert_eq!(
        files(printed + 1, true),
        [
            "del/a.yml: not parsed: the report is full",
            "del/b.yml: not parsed: the report is full"
        ]
    );

    // No file is handed to its parser once the scan's time is spent; one handed to
    // it before then is still read.
    let spent = "not parsed: the scan's time is spent";
    let mut files = |until: Instant| {
        let (workflows, skipped) =
            scan_workflows_with(Path::new("cap"), usize::MAX, false, Some(until), &mut |b| {
                // The first file takes the scan past its time.
                while Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(50));
                }
                real.parse(b, PARSE_TIME)
            });
        let mut out: Vec<String> = workflows
            .iter()
            .map(|w| format!("{} read", w.file))
            .collect();
        out.extend(skipped.iter().map(|s| format!("{}: {}", s.file, s.reason)));
        out
    };
    assert_eq!(
        files(Instant::now()),
        [
            format!("cap/a.yml: {spent}"),
            format!("cap/b.yml: {spent}"),
            format!("cap/c.yml: {spent}")
        ]
    );
    assert_eq!(
        files(Instant::now() + Duration::from_secs(1)),
        [
            "cap/a.yml read".to_string(),
            format!("cap/b.yml: {spent}"),
            format!("cap/c.yml: {spent}")
        ]
    );
}

/// #31's acceptance: every workflow fixture in `scripts/tests/fixtures/gha/` (the
/// `*.yml` and `*.yaml` files the pass reads there; it does not recurse into
/// `actions/` or `infra/`) gives the facts checked in for it, read whole, under
/// `scripts/tests/fixtures/audit-scan/gha-facts/<fixture>.json`. A fixture with
/// no expected facts fails, naming it; so does an expectation with no fixture.
#[test]
fn every_gha_fixture_gives_the_facts_checked_in_for_it() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/tests/fixtures");
    let gha = fixtures.join("gha");
    let facts = fixtures.join("audit-scan/gha-facts");
    let mut names: Vec<String> = fs::read_dir(&gha)
        .expect("read the gha fixtures")
        .map(|e| e.expect("a fixture entry"))
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        .collect();
    names.sort();
    assert!(names.len() >= 79, "only {} gha fixtures", names.len());
    let wt = Wt::repo();
    wt.write("src/lib.rs", b"fn a() {}\n");
    for n in &names {
        wt.write(
            &format!(".github/workflows/{n}"),
            &fs::read(gha.join(n)).expect("read a fixture"),
        );
    }
    let r = report(
        &wt,
        &["--contract=1", "./src", "--workflows", ".github/workflows"],
    );
    assert_eq!(r["skipped"], Value::Array(Vec::new()), "{}", r["skipped"]);
    let mut got = by_name(&r);
    let mut problems = Vec::new();
    for n in &names {
        let mut facts_of = got.remove(n).unwrap_or(Value::Null);
        if let Some(w) = facts_of.as_object_mut() {
            w.remove("file");
        }
        let shown = serde_json::to_string_pretty(&facts_of).expect("JSON");
        let path = facts.join(format!("{n}.json"));
        match fs::read(&path) {
            Err(_) => problems.push(format!(
                "{n}: no expected facts. Check each fact below against the fixture; if all hold, save them as {}:\n{shown}",
                path.display()
            )),
            Ok(bytes) => {
                let want: Value = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|e| panic!("{}: not JSON: {e}", path.display()));
                if want != facts_of {
                    problems.push(format!(
                        "{n}: the facts differ from {}. Read now:\n{shown}",
                        path.display()
                    ));
                }
            }
        }
    }
    for e in fs::read_dir(&facts).expect("read the expected facts") {
        let file = e
            .expect("an entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        let fixture = file.strip_suffix(".json").unwrap_or(&file);
        if !names.iter().any(|n| n == fixture) {
            problems.push(format!(
                "{file}: expected facts for no fixture in {}",
                gha.display()
            ));
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n\n"));
}
