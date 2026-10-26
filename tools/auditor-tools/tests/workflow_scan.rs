//! The `--workflows` pass as a command: the facts it reads, the files it skips,
//! and the workflows directory it refuses.

mod common;

use std::os::unix::ffi::OsStrExt;

use common::{refused, refused_with, run, shown, stdout, Wt};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_audit-scan");

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
