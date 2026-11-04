//! confine.rs against scripts/lib/confine.sh: every case of the case file
//! test-confine.sh runs `confine_path` over, run through `confine::rel` and
//! `confine::check` in the same tree, must come out as the shell's does; and
//! git, asked whether a path is tracked, runs with the same arguments and the
//! same environment from both.

mod common;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
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
/// git does when nothing asked about is tracked: nothing, exit 0. The script is
/// written by `/bin/sh`, not by this process: on Linux, a child another test
/// starts while this process holds the file open for writing inherits that
/// descriptor, and running the file then fails with ETXTBSY (`Text file busy`)
/// until that child execs.
fn recording_git(dir: &Path) {
    fs::create_dir_all(dir.join("log")).expect("make the log directory");
    let git = dir.join("git");
    let status = Command::new("/bin/sh")
        .args([
            "-c",
            "printf '%s' \"$1\" > \"$2\" && chmod 755 \"$2\"",
            "sh",
            "#!/bin/sh\nlog=${0%/*}/log/$$\n/usr/bin/env > \"$log.env\"\n\
             for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$log.args\"\nexit 0\n",
        ])
        .arg(&git)
        .stdin(Stdio::null())
        .status()
        .expect("run sh");
    assert!(status.success(), "write the recording git");
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

#[test]
fn confine_rs_drops_the_path_entries_of_the_tree_as_confine_init_does() {
    // The working directory is one program of a tree, and holds an empty .git,
    // which git walks past. The tree's node_modules/.bin, above it, holds a
    // recording git that must never run: both sides take the outermost directory
    // holding a .git as the tree, drop that entry, and run the git after it.
    let wt = Wt::repo();
    wt.mkdir("programs/v/.git");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root resolves");
    let inner = wt.path("node_modules/.bin");
    recording_git(&inner);
    let rec = wt.outside().join("rec");
    recording_git(&rec);
    let path = format!("{}:{}:/usr/bin:/bin", inner.display(), rec.display());
    let v = wt.path("programs/v");
    let shell = Command::new("bash")
        .args([
            "-c",
            ". \"$1/scripts/lib/confine.sh\" && confine_init agree \"$1\" && \
             confine_tracked .audit-memory",
            "agree",
        ])
        .arg(&root)
        .current_dir(&v)
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
    let rust = Command::new(env!("CARGO_BIN_EXE_audit-mem"))
        .args(["warm", "--program-id", "VaultProg1111"])
        .current_dir(&v)
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
    assert!(
        git_calls(&inner).is_empty(),
        "the git inside the tree never runs"
    );
    assert_eq!(sh.len(), 2, "hgit runs git twice: {sh:#?}");
    assert_eq!(
        rs, sh,
        "confine.rs cleans PATH of the tree's entries as confine_init does"
    );
}

#[test]
fn confine_rs_lists_what_a_config_includes_as_hgit_does() {
    // A config that includes a file: before its questions, each side asks git
    // what the config includes, in the same words and the same environment.
    let wt = Wt::repo();
    let config = wt.read(".git/config");
    wt.write(
        ".git/config",
        &[&config[..], &b"[include]\n\tpath = extra.cfg\n"[..]].concat(),
    );
    wt.write(".git/extra.cfg", b"[core]\n");
    let rec = wt.outside().join("rec");
    recording_git(&rec);
    let path = format!("{}:/usr/bin:/bin", rec.display());
    let shell = Command::new("bash")
        .args([
            "-c",
            ". \"$1/scripts/lib/confine.sh\" && confine_init agree \"$1\" && \
             confine_tracked .audit-memory",
            "agree",
        ])
        .arg(root())
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
    assert_eq!(
        sh.len(),
        3,
        "the include listing, then two questions: {sh:#?}"
    );
    assert!(
        sh.keys()
            .any(|a| a.contains("--git-dir=/dev/null\nconfig\n--file\n")),
        "{sh:#?}"
    );
    assert_eq!(rs, sh, "confine.rs lists the includes as confine.sh does");
}

/// The repository root, where scripts/lib/confine.sh is.
fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root resolves")
}

#[test]
fn confine_rs_refuses_what_git_would_wait_on_in_confine_sh_s_words() {
    // Each tree holds a named pipe git would open on its way to the repository.
    // confine_git_files, as confine_rundir runs it, and audit-mem init --db, as
    // it checks the run directory, refuse it before git starts, for the same
    // reason in the same words; a tree with none passes both.
    let mkfifo = |p: &Path| {
        let made = Command::new("mkfifo").arg(p).status().expect("run mkfifo");
        assert!(made.success(), "mkfifo {}", p.display());
    };
    let cases = [
        "none",
        "HEAD",
        "commondir",
        "include",
        "include in turn",
        "linked git directory",
        "linked config",
        "above a decoy",
        "above a decoy git does not take",
        "link in the git directory",
        "gitfile",
        "gitfile with a NUL",
        "unreadable directory",
    ];
    let mut differ = Vec::new();
    for case in cases {
        // SAFETY: geteuid only reads this process's effective user id.
        if case == "unreadable directory" && unsafe { libc::geteuid() } == 0 {
            continue;
        }
        let wt = Wt::repo();
        let mut from = wt.dir.clone();
        let mut pipes = Vec::new();
        match case {
            "HEAD" => {
                fs::remove_file(wt.path(".git/HEAD")).expect("rm HEAD");
                pipes.push(wt.path(".git/HEAD"));
            }
            "commondir" => pipes.push(wt.path(".git/commondir")),
            "include" | "include in turn" => {
                let config = wt.read(".git/config");
                let first = if case == "include" {
                    "../pipe"
                } else {
                    "../cfg/more.cfg"
                };
                wt.write(
                    ".git/config",
                    &[
                        &config[..],
                        format!("[include]\n\tpath = {first}\n").as_bytes(),
                    ]
                    .concat(),
                );
                wt.write(
                    "cfg/more.cfg",
                    b"[includeIf \"gitdir:**\"]\n\tpath = ../pipe\n",
                );
                pipes.push(wt.path("pipe"));
            }
            "linked git directory" | "linked config" => {
                fs::rename(wt.path(".git"), wt.path(".realgit")).expect("move .git");
                wt.link(".realgit".as_ref(), ".git");
                if case == "linked config" {
                    fs::rename(wt.path(".realgit/config"), wt.path("config.kept")).expect("mv");
                    pipes.push(wt.path(".realgit/config"));
                } else {
                    pipes.push(wt.path(".realgit/info/attributes"));
                }
            }
            "above a decoy" | "above a decoy git does not take" => {
                fs::remove_file(wt.path(".git/HEAD")).expect("rm HEAD");
                if case == "above a decoy" {
                    wt.write("sub/.git/HEAD", b"ref: refs/heads/main\n");
                } else {
                    // objects and refs, and a vertical tab after "ref:", which git's
                    // isspace() does not take for a blank: git walks past it.
                    wt.mkdir("sub/.git/objects");
                    wt.mkdir("sub/.git/refs");
                    wt.write("sub/.git/HEAD", b"ref:\x0brefs/heads/main\n");
                }
                from = wt.path("sub");
                pipes.push(wt.path(".git/HEAD"));
            }
            "link in the git directory" => {
                wt.link("../../pipe".as_ref(), ".git/hooks/post-checkout");
                pipes.push(wt.path("pipe"));
            }
            "gitfile" | "gitfile with a NUL" => {
                let gd = wt.outside().join("gd");
                fs::rename(wt.path(".git"), &gd).expect("move .git");
                let nul = if case == "gitfile" { "" } else { "\0" };
                wt.write(
                    ".git",
                    format!("gitdir: {}{nul}\n", gd.display()).as_bytes(),
                );
                if case == "gitfile" {
                    fs::remove_file(gd.join("HEAD")).expect("rm HEAD");
                    pipes.push(gd.join("HEAD"));
                }
            }
            "unreadable directory" => {
                wt.chmod(".git/info", 0o311);
            }
            _ => {}
        }
        for p in &pipes {
            mkfifo(p);
        }
        let run_dir = if from == wt.dir {
            "audit_1"
        } else {
            "sub/audit_1"
        };
        wt.run_dir(run_dir);
        let shell = Command::new("bash")
            .args([
                "-c",
                ". \"$1/scripts/lib/confine.sh\" && confine_init agree \"$1\" && \
                 CONFINE_CEILING='' confine_git_files \"$CONFINE_WT\"",
                "agree",
            ])
            .arg(root())
            .current_dir(&from)
            .stdin(Stdio::null())
            .output()
            .expect("run bash");
        let rust = Command::new(env!("CARGO_BIN_EXE_audit-mem"))
            .args(["init", "--db", "audit_1/audit-mem.db"])
            .current_dir(&from)
            .stdin(Stdio::null())
            .output()
            .expect("run audit-mem");
        let said = |o: &std::process::Output, tool: &str| {
            let err = String::from_utf8_lossy(&o.stderr).into_owned();
            match o.status.code() {
                Some(0) => "passes".to_string(),
                _ => err
                    .strip_prefix(&format!("{tool}: refused: "))
                    .unwrap_or(&err)
                    .trim_end()
                    .to_string(),
            }
        };
        let (sh, rs) = (said(&shell, "agree"), said(&rust, "audit-mem"));
        if case == "none" {
            assert_eq!((sh.as_str(), rs.as_str()), ("passes", "passes"), "{case}");
        } else if sh != rs || sh == "passes" {
            differ.push(format!("{case}: confine.sh {sh:?}, confine.rs {rs:?}"));
        }
        if case == "unreadable directory" {
            wt.chmod(".git/info", 0o755);
        }
    }
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

/// A `git` in `dir` that answers every call as git does when it gives up:
/// `message` on stderr, then exit `status`. Written by `/bin/sh`, as
/// `recording_git` is; the message is read from a file beside it.
fn failing_git(dir: &Path, message: &str, status: u8) {
    fs::create_dir_all(dir).expect("make the failing git's directory");
    fs::write(dir.join("msg"), format!("{message}\n")).expect("write the message");
    let made = Command::new("/bin/sh")
        .args([
            "-c",
            "printf '#!/bin/sh\\ncat \"%s\" >&2\\nexit %s\\n' \"$1\" \"$2\" > \"$3\" && chmod 755 \"$3\"",
            "sh",
        ])
        .arg(dir.join("msg"))
        .arg(status.to_string())
        .arg(dir.join("git"))
        .stdin(Stdio::null())
        .status()
        .expect("run sh");
    assert!(made.success(), "write the failing git");
}

#[test]
fn confine_rs_takes_only_git_s_own_answer_for_no_repository_as_confine_sh_does() {
    // Asked whether WT is in a work tree, git fails. Only its own "not a git
    // repository" first, or git 2.56's "gitfile does not point to a valid
    // repository" for a .git file naming none, with exit 128, means no repository
    // and so nothing tracked; those words inside another of its messages (another
    // user owns a repository named so), or with another status, leave both sides
    // unable to tell, and audit-mem refuses its in-tree store; so do the words git
    // 2.54 and later stop with at a .git that is neither a regular file nor a
    // directory, or that stat cannot read, since a repository above may track it.
    let own = "fatal: not a git repository (or any of the parent directories): .git";
    let gitfile = "fatal: gitfile does not point to a valid repository: /x/.git";
    let quoted = "fatal: detected dubious ownership in repository at '/x/not a git repository'";
    let notfile = "fatal: not a regular file: '/x/.git'";
    let unread = "fatal: error reading '/x/.git'";
    for (case, message, status, no_repo) in [
        ("own", own, 128, true),
        ("gitfile", gitfile, 128, true),
        ("quoted", quoted, 128, false),
        ("status", own, 1, false),
        ("notfile", notfile, 128, false),
        ("unread", unread, 128, false),
    ] {
        let wt = Wt::new();
        let fake = wt.outside().join("fake");
        failing_git(&fake, message, status);
        let path = format!("{}:/usr/bin:/bin", fake.display());
        let shell = Command::new("bash")
            .args([
                "-c",
                ". \"$1/scripts/lib/confine.sh\" && confine_init agree \"$1\" && \
                 confine_tracked .audit-memory",
                "agree",
            ])
            .arg(root())
            .current_dir(&wt.dir)
            .env("PATH", &path)
            .env_remove("CONFINE_ALLOW_PROTOCOL")
            .stdin(Stdio::null())
            .output()
            .expect("run bash");
        let rust = Command::new(env!("CARGO_BIN_EXE_audit-mem"))
            .args(["warm", "--program-id", "VaultProg1111"])
            .current_dir(&wt.dir)
            .env("PATH", &path)
            .stdin(Stdio::null())
            .output()
            .expect("run audit-mem");
        let err = String::from_utf8_lossy(&rust.stderr);
        if no_repo {
            assert_eq!(shell.status.code(), Some(0), "{case}: confine_tracked");
            assert!(rust.status.success(), "{case}: audit-mem: {err}");
        } else {
            assert_eq!(shell.status.code(), Some(2), "{case}: confine_tracked");
            assert!(
                !rust.status.success()
                    && err.contains("git cannot tell whether .audit-memory is tracked"),
                "{case}: audit-mem: {err}"
            );
        }
    }
}
