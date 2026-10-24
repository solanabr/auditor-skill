//! audit-mem as a command: which store it uses, how it opens it, and what it
//! refuses.

mod common;

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::{refused, run, run_env, stderr, stdout, Wt};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_audit-mem");
const P: &str = "VaultProg1111";
const SIG: &str = "unchecked_sub@vault.balance";
const USE_R: &str = "; use <R>/audit-mem.db";

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

/// The schema audit-mem made before rulings had anchors.
const OLD_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS findings (finding_id TEXT PRIMARY KEY, program_id TEXT, first_seen_commit TEXT,
    last_seen_commit TEXT, severity INTEGER, root_cause TEXT, code_signature TEXT, title TEXT, status TEXT,
    first_audit_n TEXT, last_audit_n TEXT);
CREATE TABLE IF NOT EXISTS occurrences (finding_id TEXT, audit_n TEXT, commit_sha TEXT, file TEXT, line INTEGER,
    verdict TEXT, rule5b_json TEXT);
CREATE TABLE IF NOT EXISTS fp_rulings (ruling_id INTEGER PRIMARY KEY AUTOINCREMENT, program_id TEXT,
    code_signature TEXT, ruling TEXT, rationale TEXT, ruled_by TEXT, ruled_at TEXT, scope TEXT);
CREATE TABLE IF NOT EXISTS invariants (inv_id INTEGER PRIMARY KEY AUTOINCREMENT, program_id TEXT,
    protocol_class TEXT, statement TEXT, source_fn TEXT, cited_line TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS protocol_profile (program_id TEXT PRIMARY KEY, protocol_class TEXT,
    trust_assumptions_json TEXT, oracle_set TEXT, admin_set TEXT, notes TEXT);
"#;

#[test]
fn reads_no_store_as_empty_and_never_makes_one() {
    for wt in [Wt::new(), Wt::repo()] {
        assert_eq!(
            ok(&mem(&wt, &["warm", "--program-id", P])),
            "{\"profile\":null,\"invariants\":[],\"open_fp_rulings\":[]}\n"
        );
        assert_eq!(ok(&mem(&wt, &["regressions", "--program-id", P])), "[]\n");
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
        (abs.as_str(), format!("{shape}: {abs}")),
        (outside.as_str(), format!("{shape}: {outside}")),
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
    let usage = "usage: audit-mem <subcommand> [--db <store>] [options], the subcommand being init, put-finding, set-status, rule, check, regressions or warm";
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
    ok(&rule(&wt, &[]));
    let db = wt.path(".audit-memory/audit.db");
    fs::set_permissions(&db, fs::Permissions::from_mode(0o400)).expect("chmod");
    let before = wt.snapshot();
    let mtime = fs::metadata(&db).expect("stat").mtime_nsec();
    ok(&mem(&wt, &["warm", "--program-id", P]));
    ok(&mem(&wt, &["regressions", "--program-id", P]));
    let (code, _) = check(&wt, &[]);
    assert_eq!(code, Some(0));
    assert_eq!(
        wt.snapshot(),
        before,
        "no file changed, and no journal, -wal or -shm was made"
    );
    assert_eq!(fs::metadata(&db).expect("stat").mtime_nsec(), mtime);
    // A writer needs write access, which a read-only open never asks for.
    let o = mem(
        &wt,
        &[
            "set-status",
            "--program-id",
            P,
            "--signature",
            SIG,
            "--root-cause",
            "r",
            "--status",
            "FIXED",
        ],
    );
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
        ("audit_4", "CREATE VIRTUAL TABLE findings USING fts5(finding_id);", "audit_4/audit-mem.db: it holds the table findings, which audit-mem never makes, so it is not a store audit-mem wrote"),
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
