//! confine.rs against scripts/lib/confine.sh: every case of the case file
//! test-confine.sh runs `confine_path` over, run through `confine::rel` and
//! `confine::check` in the same tree, must come out as the shell's does; and
//! git, asked whether a path is tracked, runs with the same arguments and the
//! same environment from both.

mod common;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use auditor_tools::confine::{self, Kind, Stop};
use common::Wt;

const CASES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/tests/fixtures/confine/paths.txt"
);

/// The tree test-confine.sh runs the case file in, as its header describes it.
fn tree() -> Wt {
    let wt = Wt::new();
    wt.write("a.rs", b"fn a() {}\n");
    wt.write("src/lib.rs", b"fn lib() {}\n");
    wt.write("src/deep/x.rs", b"fn x() {}\n");
    wt.mkdir("bin");
    wt.link("a.rs".as_ref(), "link");
    wt.link("src".as_ref(), "linkdir");
    wt.link("nowhere".as_ref(), "dangling");
    wt.link(&wt.outside(), "out");
    wt.link("../a.rs".as_ref(), "src/inner");
    let made = Command::new("mkfifo")
        .arg(wt.path("fifo"))
        .status()
        .expect("run mkfifo");
    assert!(made.success(), "mkfifo");
    wt.mkdir("src/locked");
    wt.chmod("src/locked", 0o000);
    wt
}

/// A field of the case file with its placeholders filled in (its header lists
/// them), as test-confine.sh fills them.
fn fill(field: &str) -> String {
    if field == "@EMPTY@" {
        return String::new();
    }
    let mut out = String::new();
    let mut rest = field;
    while let Some(start) = rest.find('@') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('@') else {
            break;
        };
        out.push_str(&rest[..start]);
        let name = &after[..end];
        match name {
            "SOH" => out.push('\u{1}'),
            "TAB" => out.push('\t'),
            "NL" => out.push('\n'),
            "ESC" => out.push('\u{1b}'),
            "DEL" => out.push('\u{7f}'),
            _ => match name
                .strip_prefix("LONG:")
                .and_then(|n| n.parse::<usize>().ok())
            {
                Some(n) => out.push_str(&"a".repeat(n)),
                None => {
                    out.push('@');
                    out.push_str(name);
                    out.push('@');
                }
            },
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// What `confine_path <path> "the path" <want>` prints, by way of confine.rs: on
/// success `CONFINE_REL CONFINE_TYPE`, else its refusal line. What `want` adds to
/// the path rules (a directory, or a name not yet taken) is the caller's, as it
/// is in confine.sh.
fn confined(wt: &Wt, want: &str, path: &str) -> (u8, String) {
    let got = (|| -> Result<String, Stop> {
        let r = confine::rel("the path", OsStr::new(path), want == "dir")?;
        let kind = confine::check(&wt.dir, &r, "the path")?;
        let s = r.shown();
        match (want, kind) {
            ("dir", Kind::Dir) | ("any", _) | ("new", Kind::Absent) => {}
            ("dir", _) => {
                return Err(confine::refuse(format!(
                    "the path is not an existing directory: {s}"
                )))
            }
            ("new", _) => return Err(confine::refuse(format!("the path already exists: {s}"))),
            _ => {}
        }
        let kind = match kind {
            Kind::Dir => "dir",
            Kind::File => "file",
            Kind::Absent => "none",
        };
        Ok(format!("{} {kind}", String::from_utf8_lossy(&r.raw)))
    })();
    match got {
        Ok(out) => (0, out),
        Err(Stop(_, why)) => (64, format!("test: {why}")),
    }
}

#[test]
fn confine_rs_reads_every_path_case_as_confine_sh_does() {
    let wt = tree();
    let cases = std::fs::read_to_string(CASES).expect("read the case file");
    let mut n = 0;
    let mut differ = Vec::new();
    for line in cases.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        let [want, path, status, expect] = fields[..] else {
            panic!("a case line has four fields: {line:?}");
        };
        let want = match want.strip_prefix("noroot:") {
            // SAFETY: geteuid only reads this process's effective user id.
            Some(_) if unsafe { libc::geteuid() } == 0 => continue,
            Some(want) => want,
            None => want,
        };
        n += 1;
        let (path, expect) = (fill(path), fill(expect));
        let (got_status, got) = confined(&wt, want, &path);
        if got_status.to_string() != status || got != expect {
            differ.push(format!(
                "{want} {path:?}: confine.sh {status} {expect:?}, confine.rs {got_status} {got:?}"
            ));
        }
    }
    assert!(n > 40, "only {n} cases read");
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

/// A `git` in `dir` that runs nothing: each call keeps its environment and its
/// arguments, one per line, in `dir/log/<pid>.env` and `.args`, and answers as
/// git does when nothing asked about is tracked: nothing, exit 0.
fn recording_git(dir: &Path) {
    fs::create_dir_all(dir.join("log")).expect("make the log directory");
    let git = dir.join("git");
    fs::write(
        &git,
        "#!/bin/sh\nlog=${0%/*}/log/$$\n/usr/bin/env > \"$log.env\"\n\
         for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$log.args\"\nexit 0\n",
    )
    .expect("write the recording git");
    fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).expect("chmod it");
}

/// Each call `recording_git` kept, by its arguments: its environment, sorted,
/// less what the shell running it adds (PWD, OLDPWD, SHLVL and _).
fn git_calls(dir: &Path) -> BTreeMap<String, Vec<String>> {
    let mut calls = BTreeMap::new();
    for entry in fs::read_dir(dir.join("log")).expect("read the log") {
        let args = entry.expect("a log entry").path();
        if args.extension() != Some(OsStr::new("args")) {
            continue;
        }
        let env = fs::read_to_string(args.with_extension("env")).expect("read an environment");
        let mut env: Vec<String> = env
            .lines()
            .filter(|v| !matches!(v.split('=').next(), Some("PWD" | "OLDPWD" | "SHLVL" | "_")))
            .map(str::to_string)
            .collect();
        env.sort();
        calls.insert(fs::read_to_string(&args).expect("read the arguments"), env);
    }
    calls
}

#[test]
fn confine_rs_runs_git_as_hgit_does() {
    let wt = Wt::repo();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root resolves");
    // One recording git for both, on one PATH, so that both clean the same PATH;
    // the shell's calls are read before audit-mem runs, and moved aside.
    let rec = wt.outside().join("rec");
    recording_git(&rec);
    let path = format!("{}:/usr/bin:/bin", rec.display());
    // confine.sh asks it with confine_tracked, as rundir.sh store does.
    let shell = Command::new("bash")
        .args([
            "-c",
            ". \"$1/scripts/lib/confine.sh\" && confine_init agree \"$1\" && \
             confine_tracked .audit-memory",
            "agree",
        ])
        .arg(&root)
        .current_dir(&wt.dir)
        .env("PATH", &path)
        .env_remove("CONFINE_ALLOW_PROTOCOL")
        .stdin(Stdio::null())
        .output()
        .expect("run bash");
    assert!(
        shell.status.success(),
        "confine_tracked: {}",
        String::from_utf8_lossy(&shell.stderr)
    );
    let sh = git_calls(&rec);
    fs::rename(rec.join("log"), wt.outside().join("log-sh")).expect("move the shell's calls");
    fs::create_dir(rec.join("log")).expect("make the log directory again");
    // confine.rs asks it with Git::tracked, as audit-mem does of its in-tree store.
    let rust = Command::new(env!("CARGO_BIN_EXE_audit-mem"))
        .args(["warm", "--program-id", "VaultProg1111"])
        .current_dir(&wt.dir)
        .env("PATH", &path)
        .stdin(Stdio::null())
        .output()
        .expect("run audit-mem");
    assert!(
        rust.status.success(),
        "audit-mem: {}",
        String::from_utf8_lossy(&rust.stderr)
    );
    let rs = git_calls(&rec);
    assert_eq!(sh.len(), 2, "hgit runs git twice: {sh:#?}");
    assert_eq!(
        rs, sh,
        "confine.rs gives git the arguments and the environment hgit gives it"
    );
    for env in rs.values() {
        assert!(
            env.iter().any(|v| v == "GIT_ALLOW_PROTOCOL="),
            "no transport is allowed: {env:#?}"
        );
    }
}
