//! audit-mem as a command: which store it uses, how it opens it, what it refuses,
//! and the profile, invariant and anchored-ruling behaviour warm and check report.

mod common;

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::{refused, run, run_env, shown, stderr, stdout, Wt};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_audit-mem");
const P: &str = "VaultProg1111";
const SIG: &str = "unchecked_sub@vault.balance";
const USE_R: &str = "; use <R>/audit-mem.db";
/// Full commit ids, as rule and check take them.
const C1: &str = "c0ffee1c0ffee1c0ffee1c0ffee1c0ffee1c0ffe";
const C2: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

fn mem(wt: &Wt, args: &[&str]) -> Output {
    run(BIN, &wt.dir, args)
}

fn ok(o: &Output) -> String {
    assert_eq!(o.status.code(), Some(0), "stderr: {}", stderr(o));
    assert_eq!(stderr(o), "");
    stdout(o)
}

fn json(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).expect("audit-mem prints JSON")
}

/// A repository with an in-tree store made by `init`, and a guarded file.
fn store() -> Wt {
    let wt = Wt::repo();
    wt.write(
        "src/withdraw.rs",
        b"fn withdraw() {\n    require!(vault.balance >= amount);\n    vault.balance -= amount;\n}\n",
    );
    assert_eq!(
        ok(&mem(&wt, &["init"])),
        "initialized .audit-memory/audit.db\n"
    );
    wt
}

fn rule(wt: &Wt, extra: &[&str]) -> Output {
    let mut args = vec![
        "rule",
        "--program-id",
        P,
        "--signature",
        SIG,
        "--ruling",
        "FALSE_POSITIVE",
        "--rationale",
        "guarded by the require! above it",
        "--by",
        "auditor",
    ];
    args.extend_from_slice(extra);
    mem(wt, &args)
}

fn check(wt: &Wt, extra: &[&str]) -> (Option<i32>, Value) {
    let mut args = vec!["check", "--program-id", P, "--signature", SIG];
    args.extend_from_slice(extra);
    let o = mem(wt, &args);
    assert_eq!(stderr(&o), "");
    (o.status.code(), json(&o))
}

/// Makes a SQLite file at `path` with `sql`, outside audit-mem.
fn craft(path: &Path, sql: &str) {
    let conn = rusqlite::Connection::open(path).expect("open a crafted database");
    conn.execute_batch(sql).expect("craft the database");
}

/// The schema audit-mem made before rulings had anchors, as it wrote it.
const OLD_SCHEMA: &str = r#"
        CREATE TABLE IF NOT EXISTS findings (
            finding_id        TEXT PRIMARY KEY,
            program_id        TEXT,
            first_seen_commit TEXT,
            last_seen_commit  TEXT,
            severity          INTEGER,
            root_cause        TEXT,
            code_signature    TEXT,
            title             TEXT,
            status            TEXT,
            first_audit_n     TEXT,
            last_audit_n      TEXT
        );

        CREATE TABLE IF NOT EXISTS occurrences (
            finding_id TEXT,
            audit_n    TEXT,
            commit_sha TEXT,
            file       TEXT,
            line       INTEGER,
            verdict    TEXT,
            rule5b_json TEXT
        );

        CREATE TABLE IF NOT EXISTS fp_rulings (
            ruling_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id     TEXT,
            code_signature TEXT,
            ruling         TEXT,
            rationale      TEXT,
            ruled_by       TEXT,
            ruled_at       TEXT,
            scope          TEXT
        );

        CREATE TABLE IF NOT EXISTS invariants (
            inv_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id     TEXT,
            protocol_class TEXT,
            statement      TEXT,
            source_fn      TEXT,
            cited_line     TEXT,
            status         TEXT
        );

        CREATE TABLE IF NOT EXISTS protocol_profile (
            program_id            TEXT PRIMARY KEY,
            protocol_class        TEXT,
            trust_assumptions_json TEXT,
            oracle_set            TEXT,
            admin_set             TEXT,
            notes                 TEXT
        );
"#;

#[test]
fn takes_the_contract_marker_right_after_the_subcommand() {
    let wt = Wt::repo();
    wt.write("src/withdraw.rs", b"fn withdraw() {\n    require!(x);\n}\n");
    let c = "--contract=1";
    assert_eq!(
        ok(&mem(&wt, &["init", c])),
        "initialized .audit-memory/audit.db\n"
    );
    let finding = [
        "--program-id",
        P,
        "--signature",
        SIG,
        "--root-cause",
        "rc",
        "--title",
        "t",
        "--severity",
        "3",
    ];
    let line = ok(&mem(&wt, &[&["put-finding", c][..], &finding].concat()));
    assert!(line.starts_with("OPEN "), "{line}");
    let status = [
        "--program-id",
        P,
        "--signature",
        SIG,
        "--root-cause",
        "rc",
        "--status",
        "FIXED",
    ];
    assert_eq!(
        ok(&mem(&wt, &[&["set-status", c][..], &status].concat())),
        "updated 1 row(s) -> FIXED\n"
    );
    let line = ok(&mem(&wt, &[&["put-finding", c][..], &finding].concat()));
    assert!(line.starts_with("REGRESSED "), "{line}");
    let ruling = [
        "--program-id",
        P,
        "--signature",
        SIG,
        "--ruling",
        "FALSE_POSITIVE",
        "--rationale",
        "r",
        "--by",
        "a",
        "--commit",
        C1,
        "--guard",
        "src/withdraw.rs:2",
    ];
    assert_eq!(
        ok(&mem(&wt, &[&["rule", c][..], &ruling].concat())),
        "ruling 1 recorded (FALSE_POSITIVE)\n"
    );
    assert_eq!(
        ok(&mem(
            &wt,
            &["profile", c, "--program-id", P, "--notes", "n"]
        )),
        format!("profile {P} recorded\n")
    );
    assert_eq!(
        ok(&mem(
            &wt,
            &["invariant", c, "--program-id", P, "--statement", "s"]
        )),
        "invariant 1 recorded\n"
    );
    let marked = mem(
        &wt,
        &[
            "check",
            c,
            "--program-id",
            P,
            "--signature",
            SIG,
            "--commit",
            C1,
        ],
    );
    assert_eq!(marked.status.code(), Some(0), "{}", stderr(&marked));
    for (sub, rest) in [
        ("warm", vec!["--program-id", P]),
        ("regressions", vec!["--program-id", P]),
        (
            "check",
            vec!["--program-id", P, "--signature", SIG, "--commit", C1],
        ),
    ] {
        let with = mem(&wt, &[&[sub, c][..], &rest].concat());
        let without = mem(&wt, &[&[sub][..], &rest].concat());
        assert_eq!(with.status.code(), without.status.code(), "{sub}");
        assert_eq!(stdout(&with), stdout(&without), "{sub}");
    }
    let usage = "usage: audit-mem <subcommand> [--contract=1] [--db <store>] [options], the subcommand \
                 being init, put-finding, set-status, rule, check, regressions, warm, profile or invariant";
    let other =
        "names a contract this build does not keep (it keeps --contract=1); rebuild it with \
                 cargo build --release --locked in tools/auditor-tools";
    let place = "--contract=1 comes right after the subcommand, once";
    let before = wt.snapshot();
    for (args, why) in [
        (
            vec![c, "warm", "--program-id", P],
            format!("{place} ({usage})"),
        ),
        (
            vec!["--contract=2", "warm", "--program-id", P],
            format!("--contract=2 {other} ({usage})"),
        ),
        (vec!["warm", "--program-id", P, c], place.to_string()),
        (vec!["warm", c, c, "--program-id", P], place.to_string()),
        (
            vec!["warm", "--contract=2", "--program-id", P],
            format!("--contract=2 {other}"),
        ),
        (vec!["init", "--contract"], format!("--contract {other}")),
        (
            vec!["regressions", "--contract=1x", "--program-id", P],
            format!("--contract=1x {other}"),
        ),
    ] {
        refused(&mem(&wt, &args), "audit-mem", &why);
    }
    assert_eq!(wt.snapshot(), before);
    // The word after an option is its value, whatever it looks like.
    let o = mem(&wt, &["warm", "--program-id", c]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
}

#[test]
fn reads_no_store_as_empty_and_never_makes_one() {
    for wt in [Wt::new(), Wt::repo()] {
        assert_eq!(
            ok(&mem(&wt, &["warm", "--program-id", P])),
            "{\"profile\":null,\"invariants\":[],\"open_fp_rulings\":[],\"truncated\":0}\n"
        );
        assert_eq!(
            ok(&mem(&wt, &["regressions", "--program-id", P])),
            "{\"regressions\":[],\"truncated\":0}\n"
        );
        let o = mem(&wt, &["check", "--program-id", P, "--signature", SIG]);
        assert_eq!(o.status.code(), Some(1));
        assert_eq!(stdout(&o), "{\"suppressed\":false,\"store\":\"absent\"}\n");
        assert!(!wt.exists(".audit-memory"), "a read makes no store");
        refused(
            &mem(
                &wt,
                &[
                    "put-finding",
                    "--program-id",
                    P,
                    "--signature",
                    SIG,
                    "--root-cause",
                    "r",
                    "--title",
                    "t",
                    "--severity",
                    "3",
                ],
            ),
            "audit-mem",
            "there is no store at .audit-memory/audit.db; audit-mem init makes it",
        );
        assert!(!wt.exists(".audit-memory"), "a writer makes no store");
    }
    let wt = Wt::repo();
    wt.mkdir(".audit-memory");
    wt.write(".audit-memory/.gitignore", b"*\n");
    ok(&mem(&wt, &["warm", "--program-id", P]));
    assert!(
        !wt.exists(".audit-memory/audit.db"),
        "warm does not make the database"
    );
    wt.run_dir("audit_1");
    let o = mem(
        &wt,
        &[
            "check",
            "--db",
            "audit_1/audit-mem.db",
            "--program-id",
            P,
            "--signature",
            SIG,
        ],
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(!wt.exists("audit_1/audit-mem.db"));
}

#[test]
fn init_makes_the_directory_its_gitignore_first_then_the_database() {
    let wt = Wt::repo();
    assert_eq!(
        ok(&mem(&wt, &["init"])),
        "initialized .audit-memory/audit.db\n"
    );
    let dir = fs::symlink_metadata(wt.path(".audit-memory")).expect("made");
    assert!(dir.is_dir());
    assert_eq!(dir.permissions().mode() & 0o777, 0o700);
    assert_eq!(wt.read(".audit-memory/.gitignore"), b"*\n");
    let db = fs::metadata(wt.path(".audit-memory/audit.db")).expect("stat");
    assert_eq!(db.permissions().mode() & 0o777, 0o600);
    assert!(wt
        .read(".audit-memory/audit.db")
        .starts_with(b"SQLite format 3\0"));
    // Rule 11d holds with no other step: git ignores the store.
    let st = Command::new("git")
        .args(["status", "--porcelain", "--ignored=no"])
        .current_dir(&wt.dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("git status");
    assert_eq!(String::from_utf8_lossy(&st.stdout), "");
    // Again, on the store it made.
    assert_eq!(
        ok(&mem(&wt, &["init"])),
        "initialized .audit-memory/audit.db\n"
    );
    // A store for one run.
    wt.run_dir("audit_3");
    assert_eq!(
        ok(&mem(&wt, &["init", "--db", "./audit_3/audit-mem.db"])),
        "initialized audit_3/audit-mem.db\n"
    );
    assert!(wt
        .read("audit_3/audit-mem.db")
        .starts_with(b"SQLite format 3\0"));
    // An empty database is an init that did not finish: init completes it.
    wt.run_dir("incident_4");
    wt.write("incident_4/audit-mem.db", b"");
    refused(
        &mem(
            &wt,
            &["warm", "--db", "incident_4/audit-mem.db", "--program-id", P],
        ),
        "audit-mem",
        "incident_4/audit-mem.db is empty; audit-mem init makes the store",
    );
    ok(&mem(&wt, &["init", "--db", "incident_4/audit-mem.db"]));
    ok(&mem(
        &wt,
        &["warm", "--db", "incident_4/audit-mem.db", "--program-id", P],
    ));
}

#[test]
fn init_never_writes_through_a_link_or_over_a_file() {
    let wt = Wt::repo();
    wt.link(&wt.outside(), ".audit-memory");
    refused(
        &mem(&wt, &["init"]),
        "audit-mem",
        &format!(".audit-memory is a symbolic link{USE_R}"),
    );
    assert_eq!(fs::read_dir(wt.outside()).expect("list").count(), 0);
    fs::remove_file(wt.path(".audit-memory")).expect("rm");
    wt.write(".audit-memory", b"x\n");
    refused(
        &mem(&wt, &["init"]),
        "audit-mem",
        &format!(".audit-memory is not a directory{USE_R}"),
    );
    fs::remove_file(wt.path(".audit-memory")).expect("rm");
    wt.mkdir(".audit-memory");
    refused(
        &mem(&wt, &["init"]),
        "audit-mem",
        &format!(".audit-memory has no .gitignore holding exactly *{USE_R}"),
    );
    assert!(
        !wt.exists(".audit-memory/.gitignore"),
        "init does not adopt a directory it did not make"
    );
    wt.write(".audit-memory/.gitignore", b"*\n!audit.db\n");
    refused(
        &mem(&wt, &["init"]),
        "audit-mem",
        &format!(".audit-memory has no .gitignore holding exactly *{USE_R}"),
    );
    wt.write(".audit-memory/.gitignore", b"*\n");
    wt.write("../outside/other.db", b"");
    wt.link(&wt.outside().join("other.db"), ".audit-memory/audit.db");
    refused(
        &mem(&wt, &["init"]),
        "audit-mem",
        &format!(".audit-memory holds a symbolic link{USE_R}"),
    );
    fs::remove_file(wt.path(".audit-memory/audit.db")).expect("rm");
    fs::hard_link(
        wt.outside().join("other.db"),
        wt.path(".audit-memory/audit.db"),
    )
    .expect("ln");
    refused(
        &mem(&wt, &["init"]),
        "audit-mem",
        &format!(".audit-memory/audit.db has more than one name (a hard link){USE_R}"),
    );
    assert_eq!(
        fs::read(wt.outside().join("other.db")).ok(),
        Some(Vec::new())
    );
    fs::remove_file(wt.path(".audit-memory/audit.db")).expect("rm");
    wt.mkdir(".audit-memory/audit.db");
    refused(
        &mem(&wt, &["init"]),
        "audit-mem",
        &format!(".audit-memory/audit.db is not a regular file{USE_R}"),
    );
}

#[test]
fn checks_the_in_tree_store_with_git() {
    let wt = store();
    let tracked = Wt::repo();
    tracked.write(".Audit-Memory/audit.db", b"tracked\n");
    tracked.git(&["add", "-f", ".Audit-Memory/audit.db"]);
    for args in [vec!["warm", "--program-id", P], vec!["init"]] {
        refused(
            &mem(&tracked, &args),
            "audit-mem",
            &format!("the repository tracks .audit-memory (in some letter case){USE_R}"),
        );
    }
    // A store the repository tracks, missing from the working tree, is refused too.
    let gone = Wt::repo();
    gone.write(".audit-memory/audit.db", b"tracked\n");
    gone.git(&["add", "-f", ".audit-memory/audit.db"]);
    fs::remove_dir_all(gone.path(".audit-memory")).expect("rm");
    refused(
        &mem(&gone, &["init"]),
        "audit-mem",
        &format!("the repository tracks .audit-memory (in some letter case){USE_R}"),
    );
    assert!(!gone.exists(".audit-memory"));
    // git that cannot answer is a refusal: here its index is unreadable.
    let broken = Wt::repo();
    broken.write(".git/index", b"not an index");
    for args in [vec!["warm", "--program-id", P], vec!["init"]] {
        refused(
            &mem(&broken, &args),
            "audit-mem",
            "git cannot tell whether .audit-memory is tracked",
        );
    }
    assert!(!broken.exists(".audit-memory"));
    broken.run_dir("audit_1");
    refused(
        &mem(&broken, &["init", "--db", "audit_1/audit-mem.db"]),
        "audit-mem",
        "git cannot tell whether --db is tracked: audit_1",
    );
    // No git: a refusal, before anything is read.
    let empty = wt.outside();
    let o = run_env(
        BIN,
        &wt.dir,
        &["warm", "--program-id", P],
        &[("PATH", empty.to_str().unwrap_or("/x"))],
    );
    refused(&o, "audit-mem", "git is not on PATH");
    // A PATH whose every entry is inside the working tree.
    wt.mkdir("bin");
    let inside = wt.path("bin");
    let o = run_env(
        BIN,
        &wt.dir,
        &["warm", "--program-id", P],
        &[("PATH", inside.to_str().unwrap_or("/x"))],
    );
    refused(
        &o,
        "audit-mem",
        "no PATH entry is left outside the working directory",
    );
    // A git inside the working tree is never run, even first on PATH.
    let marker = wt.outside().join("ran");
    wt.write(
        "bin/git",
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()).as_bytes(),
    );
    wt.chmod("bin/git", 0o755);
    let path = format!(
        "{}:{}",
        inside.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let o = run_env(
        BIN,
        &wt.dir,
        &["warm", "--program-id", P],
        &[("PATH", &path)],
    );
    ok(&o);
    assert!(
        !marker.exists(),
        "the git inside the working tree did not run"
    );
}

#[test]
fn refuses_a_working_directory_whose_path_holds_a_control_character() {
    let wt = Wt::new();
    for name in ["a\nb", "a\u{7f}b"] {
        wt.mkdir(name);
        for args in [vec!["warm", "--program-id", P], vec!["init"]] {
            refused(
                &run(BIN, &wt.path(name), &args),
                "audit-mem",
                "the working directory path holds a control character",
            );
        }
        assert!(!wt.exists(&format!("{name}/.audit-memory")));
    }
}

#[test]
fn takes_db_only_as_one_of_two_stores() {
    let wt = Wt::repo();
    wt.run_dir("audit_1");
    wt.mkdir("audit_2");
    wt.link(&wt.path("audit_1"), "audit_3");
    wt.run_dir("audit_4");
    wt.git(&["add", "-f", "audit_4/.gitignore"]);
    wt.run_dir("audit_5");
    wt.link(&wt.outside(), "audit_5/out");
    wt.run_dir("audit_6");
    wt.mkdir("audit_6/audit-mem.db");
    let shape =
        "--db must be .audit-memory/audit.db, audit_<n>/audit-mem.db or incident_<n>/audit-mem.db";
    let abs = wt.path(".audit-memory/audit.db").display().to_string();
    let outside = wt.outside().join("x.db").display().to_string();
    for (db, why) in [
        (abs.as_str(), format!("{shape}: {}", shown(&abs))),
        (outside.as_str(), format!("{shape}: {}", shown(&outside))),
        ("../outside/x.db", format!("{shape}: ../outside/x.db")),
        (
            ".audit-memory/other.db",
            format!("{shape}: .audit-memory/other.db"),
        ),
        (
            ".audit-memory/../.audit-memory/audit.db",
            format!("{shape}: .audit-memory/../.audit-memory/audit.db"),
        ),
        ("audit.db", format!("{shape}: audit.db")),
        ("audit_1/other.db", format!("{shape}: audit_1/other.db")),
        (
            "audit_1/x/audit-mem.db",
            format!("{shape}: audit_1/x/audit-mem.db"),
        ),
        ("src/audit-mem.db", format!("{shape}: src/audit-mem.db")),
        (
            "Audit_1/audit-mem.db",
            format!("{shape}: Audit_1/audit-mem.db"),
        ),
        (
            "audit_1234567/audit-mem.db",
            format!("{shape}: audit_1234567/audit-mem.db"),
        ),
        ("~/audit-mem.db", format!("{shape}: ~/audit-mem.db")),
        ("", format!("{shape}: ")),
        (
            "audit_9/audit-mem.db",
            "--db is not an existing directory: audit_9".into(),
        ),
        (
            "audit_2/audit-mem.db",
            "--db has no .gitignore holding exactly *: audit_2".into(),
        ),
        (
            "audit_3/audit-mem.db",
            "--db is a symbolic link: audit_3".into(),
        ),
        (
            "audit_4/audit-mem.db",
            "--db is tracked by git: audit_4".into(),
        ),
        (
            "audit_5/audit-mem.db",
            "--db holds a symbolic link: audit_5".into(),
        ),
        (
            "audit_6/audit-mem.db",
            "audit_6/audit-mem.db is not a regular file".into(),
        ),
    ] {
        for sub in [vec!["warm", "--program-id", P], vec!["init"]] {
            let mut args = sub.clone();
            args.extend(["--db", db]);
            refused(&mem(&wt, &args), "audit-mem", &why);
        }
    }
    assert!(!wt.exists(".audit-memory") && !wt.exists("audit_1/audit-mem.db"));
    assert_eq!(fs::read_dir(wt.outside()).expect("list").count(), 0);
}

#[test]
fn refuses_options_before_the_subcommand_and_any_it_does_not_take() {
    let wt = store();
    let usage = "usage: audit-mem <subcommand> [--contract=1] [--db <store>] [options], the subcommand being init, put-finding, set-status, rule, check, regressions, warm, profile or invariant";
    for (args, why) in [
        (vec![], format!("no subcommand ({usage})")),
        (
            vec!["--db", ".audit-memory/audit.db", "warm", "--program-id", P],
            format!("--db is not a subcommand, and the subcommand comes first ({usage})"),
        ),
        (
            vec!["Warm"],
            format!("Warm is not a subcommand, and the subcommand comes first ({usage})"),
        ),
        (
            vec!["--help"],
            format!("--help is not a subcommand, and the subcommand comes first ({usage})"),
        ),
        (vec!["warm"], "warm needs --program-id".into()),
        (
            vec!["warm", "--program-id", P, "rule"],
            "warm takes no argument rule".into(),
        ),
        (
            vec!["warm", "--program-id", P, "--"],
            "warm takes no argument --".into(),
        ),
        (
            vec!["warm", "--program-id", P, "-h"],
            "warm takes no argument -h".into(),
        ),
        (
            vec!["warm", "--program-id", P, "--signature", SIG],
            "warm takes no option --signature".into(),
        ),
        (
            vec!["warm", "--program-id", P, "--program-id", P],
            "--program-id is given more than once".into(),
        ),
        (
            vec![
                "warm",
                "--program-id",
                P,
                "--db",
                ".audit-memory/audit.db",
                "--db=.audit-memory/audit.db",
            ],
            "--db is given more than once".into(),
        ),
        (
            vec!["warm", "--program-id"],
            "--program-id needs a value".into(),
        ),
        (
            vec!["warm", "--program-id", ""],
            "--program-id is empty".into(),
        ),
        (
            vec!["init", "--program-id", P],
            "init takes no option --program-id".into(),
        ),
        (
            vec!["check", "--program-id", P],
            "check needs --signature".into(),
        ),
        (
            vec![
                "check",
                "--program-id",
                P,
                "--signature",
                SIG,
                "--commit",
                "xyz1234",
            ],
            "--commit must be a full commit id, 40 or 64 hexadecimal digits: xyz1234".into(),
        ),
        (
            vec!["check", "--program-id", P, "--signature", SIG, "--commit", "abc123"],
            "--commit must be a full commit id, 40 or 64 hexadecimal digits: abc123".into(),
        ),
        (
            vec![
                "set-status",
                "--program-id",
                P,
                "--signature",
                SIG,
                "--root-cause",
                "r",
                "--status",
                "REGRESSED",
            ],
            "--status must be one of FIXED, OPEN, ACKNOWLEDGED, DISPUTED: REGRESSED".into(),
        ),
        (
            vec![
                "rule",
                "--program-id",
                P,
                "--signature",
                SIG,
                "--ruling",
                "fp",
                "--rationale",
                "r",
                "--by",
                "a",
            ],
            "--ruling must be one of FALSE_POSITIVE, ACCEPTED_RISK: fp".into(),
        ),
        (
            vec!["profile", "--program-id", P],
            "profile needs at least one of --protocol-class, --trust-assumptions-json, --oracle-set, --admin-set, --notes".into(),
        ),
        (
            vec![
                "profile",
                "--program-id",
                P,
                "--trust-assumptions-json",
                "admin is trusted",
            ],
            "--trust-assumptions-json is not JSON".into(),
        ),
        (
            vec!["invariant", "--program-id", P],
            "invariant needs --statement".into(),
        ),
    ] {
        refused(&mem(&wt, &args), "audit-mem", &why);
    }
    // The word after an option is its value, whatever it looks like; --name=value too.
    let o = mem(&wt, &["warm", "--program-id", "--db"]);
    assert_eq!(json(&o)["profile"], Value::Null, "{}", stderr(&o));
    ok(&mem(
        &wt,
        &[
            "warm",
            "--db",
            ".audit-memory/audit.db",
            "--program-id=--db",
        ],
    ));
    ok(&mem(&wt, &["warm", "--program-id=x=y"]));
}

#[test]
fn caps_each_field_and_refuses_control_characters() {
    let wt = store();
    let put = |title: &str, extra: &[&str]| {
        let mut args = vec![
            "put-finding",
            "--program-id",
            P,
            "--signature",
            SIG,
            "--root-cause",
            "r",
            "--title",
            title,
            "--severity",
            "3",
        ];
        args.extend_from_slice(extra);
        mem(&wt, &args)
    };
    let full = "t".repeat(4096);
    assert!(ok(&put(&full, &[])).starts_with("OPEN "));
    refused(
        &put(&"t".repeat(4097), &[]),
        "audit-mem",
        "--title is longer than 4096 bytes",
    );
    for (title, shown) in [
        ("a\x1bb", "a?b"),
        ("a\tb", "a?b"),
        ("a\nb", "a?b"),
        ("a\u{7f}b", "a?b"),
        ("a\u{202e}b", "a?b"),
        ("a\u{200b}b", "a?b"),
        ("a\u{85}b", "a?b"),
    ] {
        refused(
            &put(title, &[]),
            "audit-mem",
            &format!("--title holds a control or formatting character: {shown}"),
        );
    }
    for (extra, why) in [
        (
            vec!["--severity", "11"],
            "--severity is given more than once",
        ),
        (
            vec!["--commit", "c0ffee1\n"],
            "--commit holds a control or formatting character: c0ffee1?",
        ),
        (
            vec!["--line", "0"],
            "--line must be a whole number from 1 to 999999999: 0",
        ),
        (
            vec!["--line", "-3"],
            "--line must be a whole number from 1 to 999999999: -3",
        ),
        (
            vec!["--line", "+3"],
            "--line must be a whole number from 1 to 999999999: +3",
        ),
        (
            vec!["--line", "1e3"],
            "--line must be a whole number from 1 to 999999999: 1e3",
        ),
        (
            vec!["--file", &"f".repeat(4097)],
            "--file is longer than 4096 bytes",
        ),
        (
            vec!["--verdict", "\u{2066}x"],
            "--verdict holds a control or formatting character: ?x",
        ),
    ] {
        refused(&put("t", &extra), "audit-mem", why);
    }
    for (severity, ok_) in [
        ("1", true),
        ("10", true),
        ("0", false),
        ("11", false),
        ("3.5", false),
        (" 3", false),
        ("", false),
    ] {
        let o = mem(
            &wt,
            &[
                "put-finding",
                "--program-id",
                P,
                "--signature",
                "sig-2",
                "--root-cause",
                "r",
                "--title",
                "t",
                "--severity",
                severity,
            ],
        );
        assert_eq!(
            o.status.code() == Some(0),
            ok_,
            "--severity {severity:?}: {}",
            stderr(&o)
        );
    }
    let mut bad = b"t".to_vec();
    bad.push(0xff);
    let o = Command::new(BIN)
        .args([
            "put-finding",
            "--program-id",
            P,
            "--signature",
            SIG,
            "--root-cause",
            "r",
            "--severity",
            "3",
            "--title",
        ])
        .arg(OsString::from_vec(bad))
        .current_dir(&wt.dir)
        .stdin(Stdio::null())
        .output()
        .expect("run");
    refused(&o, "audit-mem", "--title is not UTF-8");
    // Every value is checked before the store is touched.
    let before = wt.snapshot();
    refused(
        &put("t", &["--line", "x"]),
        "audit-mem",
        "--line must be a whole number from 1 to 999999999: x",
    );
    assert_eq!(wt.snapshot(), before);
}

#[test]
fn opens_a_store_read_only_for_warm_check_and_regressions() {
    let wt = store();
    ok(&mem(
        &wt,
        &[
            "put-finding",
            "--program-id",
            P,
            "--signature",
            SIG,
            "--root-cause",
            "r",
            "--title",
            "t",
            "--severity",
            "3",
        ],
    ));
    ok(&rule(
        &wt,
        &["--commit", C1, "--guard", "src/withdraw.rs:2"],
    ));
    ok(&mem(
        &wt,
        &["profile", "--program-id", P, "--protocol-class", "vault"],
    ));
    let db = wt.path(".audit-memory/audit.db");
    fs::set_permissions(&db, fs::Permissions::from_mode(0o400)).expect("chmod");
    let before = wt.snapshot();
    let mtime = fs::metadata(&db).expect("stat").mtime_nsec();
    ok(&mem(&wt, &["warm", "--program-id", P]));
    ok(&mem(&wt, &["regressions", "--program-id", P]));
    let (code, _) = check(&wt, &["--commit", C1]);
    assert_eq!(code, Some(0));
    assert_eq!(
        wt.snapshot(),
        before,
        "no file changed, and no journal, -wal or -shm was made"
    );
    assert_eq!(fs::metadata(&db).expect("stat").mtime_nsec(), mtime);
    // A writer needs write access, which a read-only open never asks for.
    let o = mem(&wt, &["profile", "--program-id", P, "--notes", "n"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        stderr(&o).starts_with("audit-mem: error: .audit-memory/audit.db: "),
        "{}",
        stderr(&o)
    );
}

#[test]
fn refuses_a_crafted_store() {
    let wt = Wt::repo();
    let cases: [(&str, &str, &str); 9] = [
        ("audit_1", "PRAGMA journal_mode=WAL; CREATE TABLE t(x);", "audit_1/audit-mem.db is not in rollback-journal mode (a WAL database, say), which audit-mem never sets"),
        ("audit_2", "CREATE TABLE IF NOT EXISTS x(y); CREATE VIEW v AS SELECT 1;", "audit_2/audit-mem.db: it holds the table x, which audit-mem never makes, so it is not a store audit-mem wrote"),
        ("audit_3", "CREATE VIEW findings AS SELECT 1 AS finding_id;", "audit_3/audit-mem.db: it holds the view findings, which audit-mem never makes, so it is not a store audit-mem wrote"),
        ("audit_4", "CREATE VIRTUAL TABLE findings USING fts5(finding_id);", "audit_4/audit-mem.db: its findings table is not the one audit-mem makes, so it is not a store audit-mem wrote"),
        ("audit_5", "CREATE TRIGGER t AFTER INSERT ON fp_rulings BEGIN DELETE FROM fp_rulings; END;", "audit_5/audit-mem.db: it holds the trigger t, which audit-mem never makes, so it is not a store audit-mem wrote"),
        ("audit_6", "CREATE INDEX i ON findings(title);", "audit_6/audit-mem.db: it holds the index i, which audit-mem never makes, so it is not a store audit-mem wrote"),
        ("audit_7", "DROP TABLE invariants;", "audit_7/audit-mem.db: it has no invariants table, so it is not a store audit-mem wrote; audit-mem init makes the tables"),
        ("audit_8", "", ""),
        ("audit_9", "", ""),
    ];
    for (dir, sql, why) in cases {
        wt.run_dir(dir);
        let db = wt.path(&format!("{dir}/audit-mem.db"));
        match dir {
            "audit_8" => fs::write(&db, b"not a database: plain text, long enough to fill the 100 bytes of a SQLite header and then go on for a while longer").expect("write"),
            "audit_9" => fs::write(&db, b"SQLite format 3\0short").expect("write"),
            "audit_1" | "audit_3" | "audit_4" => craft(&db, sql),
            _ => {
                craft(&db, OLD_SCHEMA);
                craft(&db, sql);
            }
        }
        let path = format!("{dir}/audit-mem.db");
        let before = wt.snapshot();
        for args in [
            vec!["warm", "--db", &path, "--program-id", P],
            vec![
                "check",
                "--db",
                &path,
                "--program-id",
                P,
                "--signature",
                SIG,
            ],
            vec!["regressions", "--db", &path, "--program-id", P],
            vec![
                "put-finding",
                "--db",
                &path,
                "--program-id",
                P,
                "--signature",
                SIG,
                "--root-cause",
                "r",
                "--title",
                "t",
                "--severity",
                "3",
            ],
        ] {
            let o = mem(&wt, &args);
            let want = match dir {
                "audit_8" | "audit_9" => {
                    format!("{path} is not a SQLite database, so it is not a store audit-mem wrote")
                }
                "audit_7" if args[0] == "put-finding" => {
                    // A writer adds the missing table; the read-only subcommands refuse.
                    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
                    continue;
                }
                _ => why.to_string(),
            };
            refused(&o, "audit-mem", &want);
        }
        if dir != "audit_7" {
            assert_eq!(
                wt.snapshot(),
                before,
                "{dir}: a refused store is left as it was"
            );
        }
    }
}

#[test]
fn refuses_a_table_that_is_not_the_one_audit_mem_makes() {
    let wt = Wt::repo();
    let title = "            title             TEXT,\n";
    let status = "            status            TEXT,\n";
    let scope = "            scope          TEXT\n        );";
    let cases: Vec<(&str, String)> = vec![
        (
            "findings",
            OLD_SCHEMA.replace(
                title,
                &format!("{title}            loud TEXT GENERATED ALWAYS AS (upper(title)),\n"),
            ),
        ),
        (
            "findings",
            OLD_SCHEMA.replace(
                status,
                "            status            TEXT CHECK (length(status) < 9),\n",
            ),
        ),
        (
            "findings",
            OLD_SCHEMA.replace(
                status,
                "            status            TEXT DEFAULT 'OPEN',\n",
            ),
        ),
        (
            "findings",
            OLD_SCHEMA.replace(
                title,
                &format!("{title}            extra TEXT DEFAULT 'x',\n"),
            ),
        ),
        (
            "findings",
            OLD_SCHEMA.replacen(
                "            last_audit_n      TEXT\n        );",
                "            last_audit_n      TEXT\n        ) WITHOUT ROWID;",
                1,
            ),
        ),
        (
            "findings",
            OLD_SCHEMA.replace(
                "finding_id        TEXT PRIMARY KEY",
                "finding_id       TEXT PRIMARY KEY",
            ),
        ),
        (
            "fp_rulings",
            format!("{OLD_SCHEMA}\nALTER TABLE fp_rulings ADD COLUMN anchor_commit TEXT;"),
        ),
        (
            "fp_rulings",
            OLD_SCHEMA.replace(
                scope,
                "            scope          TEXT,\n            anchor_commit  TEXT\n        );",
            ),
        ),
    ];
    for (n, (table, sql)) in cases.iter().enumerate() {
        assert_ne!(sql, OLD_SCHEMA, "case {n} changes the schema");
        let dir = format!("audit_{}", n + 1);
        wt.run_dir(&dir);
        let path = format!("{dir}/audit-mem.db");
        craft(&wt.path(&path), sql);
        let before = wt.snapshot();
        let why = format!("{path}: its {table} table is not the one audit-mem makes, so it is not a store audit-mem wrote");
        for args in [
            vec!["warm", "--db", &path, "--program-id", P],
            vec!["regressions", "--db", &path, "--program-id", P],
            vec!["profile", "--db", &path, "--program-id", P, "--notes", "n"],
        ] {
            refused(&mem(&wt, &args), "audit-mem", &why);
        }
        assert_eq!(
            wt.snapshot(),
            before,
            "case {n}: the store is left as it was"
        );
    }
    // The schema as audit-mem made it before rulings had anchors reads, and gains them.
    wt.run_dir("audit_20");
    craft(&wt.path("audit_20/audit-mem.db"), OLD_SCHEMA);
    ok(&mem(
        &wt,
        &["warm", "--db", "audit_20/audit-mem.db", "--program-id", P],
    ));
    ok(&mem(
        &wt,
        &[
            "profile",
            "--db",
            "audit_20/audit-mem.db",
            "--program-id",
            P,
            "--notes",
            "n",
        ],
    ));
    ok(&mem(
        &wt,
        &["warm", "--db", "audit_20/audit-mem.db", "--program-id", P],
    ));
    // A store init makes takes the form a migrated one has.
    wt.run_dir("audit_21");
    ok(&mem(&wt, &["init", "--db", "audit_21/audit-mem.db"]));
    let made = |dir: &str| -> String {
        rusqlite::Connection::open(wt.path(&format!("{dir}/audit-mem.db")))
            .expect("open")
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name = 'fp_rulings'",
                [],
                |r| r.get(0),
            )
            .expect("fp_rulings")
    };
    assert_eq!(made("audit_21"), made("audit_20"));
    assert!(made("audit_21").ends_with("\n        , anchor_commit TEXT, guard_file TEXT, guard_line INTEGER, guard_end INTEGER, guard_hash TEXT)"));
}

#[test]
fn refuses_a_crafted_sqlite_sequence_and_reads_no_value_past_a_mebibyte() {
    let wt = Wt::repo();
    wt.run_dir("audit_1");
    wt.run_dir("audit_2");
    ok(&mem(&wt, &["init", "--db", "audit_1/audit-mem.db"]));
    ok(&mem(&wt, &["init", "--db", "audit_2/audit-mem.db"]));
    // sqlite_sequence under another definition, written with writable_schema.
    let conn = rusqlite::Connection::open(wt.path("audit_1/audit-mem.db")).expect("open");
    conn.execute_batch(
        "INSERT INTO fp_rulings (program_id) VALUES ('p'); PRAGMA writable_schema = ON; \
         UPDATE sqlite_schema SET sql = 'CREATE TABLE sqlite_sequence(name,seq,extra)' \
         WHERE name = 'sqlite_sequence'; PRAGMA writable_schema = OFF;",
    )
    .expect("craft");
    drop(conn);
    for args in [
        vec!["warm", "--db", "audit_1/audit-mem.db", "--program-id", P],
        vec![
            "invariant",
            "--db",
            "audit_1/audit-mem.db",
            "--program-id",
            P,
            "--statement",
            "s",
        ],
    ] {
        refused(
            &mem(&wt, &args),
            "audit-mem",
            "audit_1/audit-mem.db: it holds the table sqlite_sequence, which audit-mem never makes, so it is not a store audit-mem wrote",
        );
    }
    // A value of 2 MiB, which no writer stores, is not read.
    let conn = rusqlite::Connection::open(wt.path("audit_2/audit-mem.db")).expect("open");
    conn.execute(
        "INSERT INTO fp_rulings (program_id, code_signature, ruling, rationale, ruled_by, ruled_at, scope) \
         VALUES (?1, ?2, 'FALSE_POSITIVE', ?3, 'a', '1', 'program')",
        rusqlite::params![P, SIG, "x".repeat(2 << 20)],
    )
    .expect("craft");
    drop(conn);
    let o = mem(
        &wt,
        &["warm", "--db", "audit_2/audit-mem.db", "--program-id", P],
    );
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(stdout(&o), "");
    assert!(
        stderr(&o).starts_with("audit-mem: error: audit_2/audit-mem.db: string or blob too big"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn refuses_a_store_with_sqlite_files_beside_it() {
    let wt = store();
    wt.run_dir("audit_1");
    ok(&mem(&wt, &["init", "--db", "audit_1/audit-mem.db"]));
    for (db, tail) in [
        (".audit-memory/audit.db", USE_R),
        ("audit_1/audit-mem.db", ""),
    ] {
        let calls = [
            vec!["warm", "--db", db, "--program-id", P],
            vec!["check", "--db", db, "--program-id", P, "--signature", SIG],
            vec!["regressions", "--db", db, "--program-id", P],
            vec!["init", "--db", db],
        ];
        for suffix in ["-wal", "-shm"] {
            let side = format!("{db}{suffix}");
            wt.write(&side, b"");
            let before = wt.snapshot();
            for args in &calls {
                refused(
                    &mem(&wt, args),
                    "audit-mem",
                    &format!(
                        "{db} has a {suffix} file beside it, which audit-mem never makes{tail}"
                    ),
                );
            }
            assert_eq!(wt.snapshot(), before, "{side}: nothing is made beside it");
            fs::remove_file(wt.path(&side)).expect("rm");
        }
        // A -journal, left by a write that stopped, must be a regular file with one name.
        let journal = format!("{db}-journal");
        fs::hard_link(wt.path("src/withdraw.rs"), wt.path(&journal)).expect("ln");
        refused(
            &mem(&wt, &calls[0]),
            "audit-mem",
            &format!("{journal} is not a regular file with one name{tail}"),
        );
        fs::remove_file(wt.path(&journal)).expect("rm");
        let status = Command::new("mkfifo")
            .arg(wt.path(&journal))
            .status()
            .expect("mkfifo");
        assert!(status.success());
        refused(
            &mem(&wt, &calls[3]),
            "audit-mem",
            &format!("{journal} is not a regular file with one name{tail}"),
        );
        fs::remove_file(wt.path(&journal)).expect("rm");
        wt.write(&journal, b"");
        let before = wt.snapshot();
        ok(&mem(&wt, &calls[0]));
        assert_eq!(wt.snapshot(), before, "a read leaves the journal as it was");
        fs::remove_file(wt.path(&journal)).expect("rm");
    }
}

#[test]
fn a_read_only_open_is_immutable_and_opens_nothing_beside_the_store() {
    let wt = store();
    // A WAL file another database wrote, planted beside the store: a plain
    // read-only open would apply it and make a -shm file.
    let other = wt.outside().join("other.db");
    let conn = rusqlite::Connection::open(&other).expect("open");
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; CREATE TABLE planted(x); INSERT INTO planted VALUES (1);",
    )
    .expect("write the WAL");
    fs::copy(
        wt.outside().join("other.db-wal"),
        wt.path(".audit-memory/audit.db-wal"),
    )
    .expect("copy the WAL");
    drop(conn);
    let before = wt.snapshot();
    // The CLI refuses the store.
    refused(
        &mem(&wt, &["warm", "--program-id", P]),
        "audit-mem",
        &format!(
            ".audit-memory/audit.db has a -wal file beside it, which audit-mem never makes{USE_R}"
        ),
    );
    // The open itself, with that check left out, reads the store as it is.
    let db = wt.path(".audit-memory/audit.db");
    let conn = auditor_tools::mem::open_read_only(&db).expect("open read-only");
    let warm = auditor_tools::mem::warm(&conn, P).expect("read");
    assert!(warm.profile.is_none());
    drop(conn);
    assert!(!wt.exists(".audit-memory/audit.db-shm"), "no -shm is made");
    assert_eq!(wt.snapshot(), before, "nothing changed beside the store");
}

#[test]
fn profile_and_invariant_record_what_warm_returns() {
    let wt = store();
    assert_eq!(
        ok(&mem(
            &wt,
            &[
                "profile",
                "--program-id",
                P,
                "--protocol-class",
                "vault",
                "--trust-assumptions-json",
                "{\"admin\":\"multisig\"}",
                "--oracle-set",
                "pyth SOL/USD"
            ]
        )),
        format!("profile {P} recorded\n")
    );
    ok(&mem(
        &wt,
        &[
            "profile",
            "--program-id",
            P,
            "--notes",
            "upgrade authority held by a 3-of-5",
        ],
    ));
    assert_eq!(
        ok(&mem(
            &wt,
            &[
                "invariant",
                "--program-id",
                P,
                "--statement",
                "total_shares == shares_mint.supply",
                "--protocol-class",
                "vault",
                "--status",
                "Unproven"
            ]
        )),
        "invariant 1 recorded\n"
    );
    assert_eq!(
        ok(&mem(
            &wt,
            &[
                "invariant",
                "--program-id",
                P,
                "--statement",
                "total_shares == shares_mint.supply",
                "--status",
                "Manually verified",
                "--cited-line",
                "src/vault.rs:88",
                "--source-fn",
                "deposit"
            ]
        )),
        "invariant 1 updated, replacing status (warm lists what it held under changed)\n"
    );
    ok(&mem(
        &wt,
        &[
            "invariant",
            "--program-id",
            P,
            "--statement",
            "only the authority moves funds",
        ],
    ));
    let warm = json(&mem(&wt, &["warm", "--program-id", P]));
    assert_eq!(warm["profile"]["protocol_class"], "vault");
    assert_eq!(
        warm["profile"]["trust_assumptions_json"],
        "{\"admin\":\"multisig\"}"
    );
    assert_eq!(warm["profile"]["oracle_set"], "pyth SOL/USD");
    assert_eq!(
        warm["profile"]["notes"],
        "upgrade authority held by a 3-of-5"
    );
    assert_eq!(warm["invariants"].as_array().map(Vec::len), Some(2));
    assert_eq!(warm["invariants"][0]["status"], "Manually verified");
    assert_eq!(warm["invariants"][0]["protocol_class"], "vault");
    assert_eq!(warm["invariants"][0]["source_fn"], "deposit");
    assert_eq!(
        warm["invariants"][1]["statement"],
        "only the authority moves funds"
    );
    assert_eq!(warm["invariants"][0]["changed"][0]["field"], "status");
    assert_eq!(warm["invariants"][0]["changed"][0]["previous"], "Unproven");
    assert_eq!(warm["invariants"][1]["changed"], Value::Array(Vec::new()));
    assert_eq!(warm["profile"]["changed"], Value::Array(Vec::new()));
    // A value replaced is kept, an erased one too, and warm lists them, newest first.
    assert_eq!(
        ok(&mem(
            &wt,
            &[
                "profile",
                "--program-id",
                P,
                "--trust-assumptions-json",
                "{\"admin\":\"fully trusted; admin-key findings are out of scope\"}",
                "--notes",
                ""
            ]
        )),
        format!(
            "profile {P} recorded, replacing trust_assumptions_json, notes (warm lists what it held under changed)\n"
        )
    );
    let warm = json(&mem(&wt, &["warm", "--program-id", P]));
    let changed: Vec<(String, String)> = warm["profile"]["changed"]
        .as_array()
        .expect("changed")
        .iter()
        .map(|c| {
            (
                c["field"].as_str().unwrap_or_default().into(),
                c["previous"].as_str().unwrap_or_default().into(),
            )
        })
        .collect();
    assert_eq!(
        changed,
        [
            (
                "notes".to_string(),
                "upgrade authority held by a 3-of-5".to_string()
            ),
            (
                "trust_assumptions_json".to_string(),
                "{\"admin\":\"multisig\"}".to_string()
            ),
        ]
    );
    assert_eq!(warm["truncated"], 0);
    // Neither writer suppresses anything.
    let (code, result) = check(&wt, &["--commit", C1]);
    assert_eq!(
        (code, result["suppressed"].clone()),
        (Some(1), Value::Bool(false))
    );
    // They follow put-finding's field rules.
    refused(
        &mem(
            &wt,
            &["invariant", "--program-id", P, "--statement", "a\u{202e}b"],
        ),
        "audit-mem",
        "--statement holds a control or formatting character: a?b",
    );
    refused(
        &mem(
            &wt,
            &["profile", "--program-id", P, "--notes", &"n".repeat(4097)],
        ),
        "audit-mem",
        "--notes is longer than 4096 bytes",
    );
}

#[test]
fn a_ruling_is_anchored_and_check_reports_it_stale_when_the_anchor_changes() {
    let wt = store();
    // A FALSE_POSITIVE ruling needs its commit and the guard that makes it one.
    let needs = "a FALSE_POSITIVE ruling needs --commit, the commit it is made at, and --guard, the <file>:<line> or <file>:<first>-<last> that makes it one, so that check can tell when it goes stale";
    refused(&rule(&wt, &["--commit", C1]), "audit-mem", needs);
    refused(
        &rule(&wt, &["--guard", "src/withdraw.rs:2"]),
        "audit-mem",
        needs,
    );
    // Only a full commit id: an abbreviation could name another commit.
    for abbreviated in [
        "c0ffee1",
        &C1[..39],
        "c0ffee1c0ffee1c0ffee1c0ffee1c0ffee1c0ffe1",
    ] {
        refused(
            &rule(
                &wt,
                &["--commit", abbreviated, "--guard", "src/withdraw.rs:2"],
            ),
            "audit-mem",
            &format!(
                "--commit must be a full commit id, 40 or 64 hexadecimal digits: {abbreviated}"
            ),
        );
        let o = mem(
            &wt,
            &[
                "check",
                "--program-id",
                P,
                "--signature",
                SIG,
                "--commit",
                abbreviated,
            ],
        );
        assert_eq!(o.status.code(), Some(2), "{abbreviated}");
    }
    wt.link(&wt.outside(), "outlink");
    wt.write("../outside/x.rs", b"x\n");
    let abs = wt.path("src/withdraw.rs").display().to_string();
    let g = "--guard's file";
    for (guard, why) in [
        ("src/withdraw.rs", "--guard must be <file>:<line> or <file>:<first>-<last>, at most 200 lines: src/withdraw.rs".to_string()),
        ("src/withdraw.rs:0", "--guard must be <file>:<line> or <file>:<first>-<last>, at most 200 lines: src/withdraw.rs:0".into()),
        ("src/withdraw.rs:3-2", "--guard must be <file>:<line> or <file>:<first>-<last>, at most 200 lines: src/withdraw.rs:3-2".into()),
        ("src/withdraw.rs:1-201", "--guard must be <file>:<line> or <file>:<first>-<last>, at most 200 lines: src/withdraw.rs:1-201".into()),
        ("src/withdraw.rs:x", "--guard must be <file>:<line> or <file>:<first>-<last>, at most 200 lines: src/withdraw.rs:x".into()),
        ("src/withdraw.rs:9", "--guard names line 9, and the file has 4 line(s): src/withdraw.rs:9".into()),
        (&format!("{abs}:2"), format!("{g} must be relative to the working directory: {}", shown(&abs))),
        ("../outside/x.rs:1", format!("{g} has an empty, . or .. component: ../outside/x.rs")),
        ("outlink/x.rs:1", format!("{g} passes through a symbolic link: outlink/x.rs")),
        ("src:1", format!("{g} is not an existing regular file: src")),
        ("src/missing.rs:1", format!("{g} is not an existing regular file: src/missing.rs")),
    ] {
        refused(&rule(&wt, &["--commit", C1, "--guard", guard]), "audit-mem", &why);
    }
    // Recorded at a commit, with the guard's lines hashed.
    assert_eq!(
        ok(&rule(
            &wt,
            &[
                "--commit",
                "C0FFEE1C0FFEE1C0FFEE1C0FFEE1C0FFEE1C0FFE",
                "--guard",
                "src/withdraw.rs:2"
            ]
        )),
        "ruling 1 recorded (FALSE_POSITIVE)\n"
    );
    let (code, r) = check(&wt, &["--commit", C1]);
    assert_eq!(code, Some(0), "{r}");
    assert_eq!(r["suppressed"], true);
    assert!(r.get("stale").is_none());
    assert_eq!(r["ruling"]["commit"], C1);
    assert_eq!(r["ruling"]["guard"], "src/withdraw.rs:2");
    assert_eq!(r["ruling"]["guard_hash"].as_str().map(str::len), Some(64));
    // The commit changes: stale, not suppressed.
    let (code, r) = check(&wt, &["--commit", C2]);
    assert_eq!(
        (code, r["suppressed"].clone()),
        (Some(1), Value::Bool(false))
    );
    assert_eq!(r["stale"], format!("ruled at commit {C1}, checked at {C2}"));
    let (code, r) = check(&wt, &[]);
    assert_eq!(code, Some(1));
    assert_eq!(
        r["stale"],
        format!("ruled at commit {C1}, and no --commit was given to compare")
    );
    // The guard's lines change, or move.
    let original = wt.read("src/withdraw.rs");
    wt.write("src/withdraw.rs", b"fn withdraw() {\n    require!(vault.balance > amount);\n    vault.balance -= amount;\n}\n");
    let (code, r) = check(&wt, &["--commit", C1]);
    assert_eq!(code, Some(1));
    assert_eq!(
        r["stale"],
        "the guard at src/withdraw.rs:2 no longer holds the lines ruled on"
    );
    wt.write(
        "src/withdraw.rs",
        &[b"// a new first line\n".to_vec(), original.clone()].concat(),
    );
    assert_eq!(check(&wt, &["--commit", C1]).0, Some(1));
    // The guard's file is gone, or replaced by a link: never read through it.
    fs::remove_file(wt.path("src/withdraw.rs")).expect("rm");
    let (_, r) = check(&wt, &["--commit", C1]);
    assert_eq!(
        r["stale"],
        "the guard at src/withdraw.rs:2 cannot be read: it does not exist"
    );
    wt.write("../outside/withdraw.rs", &original);
    wt.link(&wt.outside().join("withdraw.rs"), "src/withdraw.rs");
    let (code, r) = check(&wt, &["--commit", C1]);
    assert_eq!(code, Some(1));
    assert_eq!(r["stale"], "the guard at src/withdraw.rs:2 cannot be read: it passes through a symbolic link: src/withdraw.rs");
    fs::remove_file(wt.path("src/withdraw.rs")).expect("rm");
    wt.write("src/withdraw.rs", &original);
    assert_eq!(
        check(&wt, &["--commit", C1]).0,
        Some(0),
        "as it was, it holds again"
    );
    // A newer ruling decides; an ACCEPTED_RISK ruling never suppresses.
    ok(&mem(
        &wt,
        &[
            "rule",
            "--program-id",
            P,
            "--signature",
            SIG,
            "--ruling",
            "ACCEPTED_RISK",
            "--rationale",
            "r",
            "--by",
            "a",
        ],
    ));
    assert_eq!(check(&wt, &["--commit", C1]).0, Some(0));
    ok(&rule(
        &wt,
        &[
            "--commit",
            "c0ffee2c0ffee2c0ffee2c0ffee2c0ffee2c0ffe",
            "--guard",
            "src/withdraw.rs:2-3",
        ],
    ));
    let (code, r) = check(&wt, &["--commit", C1]);
    assert_eq!(code, Some(1));
    assert_eq!(r["ruling"]["ruling_id"], 3);
    assert_eq!(r["ruling"]["guard"], "src/withdraw.rs:2-3");
    let warm = json(&mem(&wt, &["warm", "--program-id", P]));
    assert_eq!(warm["open_fp_rulings"].as_array().map(Vec::len), Some(3));
    assert_eq!(warm["open_fp_rulings"][2]["commit"], C1);
}

#[test]
fn a_store_made_before_anchors_reports_its_rulings_stale_and_migrates() {
    let wt = Wt::repo();
    wt.write("src/withdraw.rs", b"fn w() {\n    require!(ok);\n}\n");
    wt.mkdir(".audit-memory");
    wt.write(".audit-memory/.gitignore", b"*\n");
    let db = wt.path(".audit-memory/audit.db");
    craft(&db, OLD_SCHEMA);
    craft(
        &db,
        &format!(
            "INSERT INTO fp_rulings (program_id, code_signature, ruling, rationale, ruled_by, ruled_at, scope) \
             VALUES ('{P}', '{SIG}', 'FALSE_POSITIVE', 'guarded', 'auditor', '1700000000', 'program');"
        ),
    );
    let before = wt.read(".audit-memory/audit.db");
    // Read-only: the old ruling has no anchor, so it is stale and suppresses nothing.
    let (code, r) = check(&wt, &["--commit", C1]);
    assert_eq!(code, Some(1));
    assert_eq!(r["suppressed"], false);
    assert_eq!(r["stale"], "no anchor");
    assert_eq!(r["ruling"]["commit"], Value::Null);
    assert_eq!(r["ruling"]["guard"], Value::Null);
    let warm = json(&mem(&wt, &["warm", "--program-id", P]));
    assert_eq!(warm["open_fp_rulings"][0]["rationale"], "guarded");
    assert_eq!(
        wt.read(".audit-memory/audit.db"),
        before,
        "a read leaves the old store as it was"
    );
    // init migrates it: the anchor columns are added and the old ruling stays unanchored.
    ok(&mem(&wt, &["init"]));
    let conn = rusqlite::Connection::open(&db).expect("open");
    let columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('fp_rulings')")
        .and_then(|mut s| s.query_map([], |r| r.get(0))?.collect())
        .expect("columns");
    for c in [
        "anchor_commit",
        "guard_file",
        "guard_line",
        "guard_end",
        "guard_hash",
    ] {
        assert!(columns.iter().any(|x| x == c), "{c} in {columns:?}");
    }
    drop(conn);
    assert_eq!(check(&wt, &["--commit", C1]).1["stale"], "no anchor");
    // rule migrates a store too, and a new anchored ruling suppresses.
    let wt2 = Wt::repo();
    wt2.write("src/withdraw.rs", b"fn w() {\n    require!(ok);\n}\n");
    wt2.run_dir("audit_1");
    craft(&wt2.path("audit_1/audit-mem.db"), OLD_SCHEMA);
    let o = mem(
        &wt2,
        &[
            "rule",
            "--db",
            "audit_1/audit-mem.db",
            "--program-id",
            P,
            "--signature",
            SIG,
            "--ruling",
            "FALSE_POSITIVE",
            "--rationale",
            "r",
            "--by",
            "a",
            "--commit",
            C1,
            "--guard",
            "src/withdraw.rs:2",
        ],
    );
    assert_eq!(ok(&o), "ruling 1 recorded (FALSE_POSITIVE)\n");
    let o = mem(
        &wt2,
        &[
            "check",
            "--db",
            "audit_1/audit-mem.db",
            "--program-id",
            P,
            "--signature",
            SIG,
            "--commit",
            C1,
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
}
