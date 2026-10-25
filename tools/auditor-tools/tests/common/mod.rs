//! A temporary working tree for the CLI tests: a directory under the system's
//! temporary directory, by its physical path, removed when the test ends.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

pub struct Wt {
    pub root: PathBuf,
    pub dir: PathBuf,
}

impl Drop for Wt {
    fn drop(&mut self) {
        let _ = Command::new("chmod")
            .args(["-R", "u+rwx"])
            .arg(&self.root)
            .status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Wt {
    /// A new, empty working tree, `<tmp>/auditor-tools-test.<pid>.<n>/wt`, beside
    /// an `outside/` directory.
    pub fn new() -> Wt {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory resolves");
        let root = base.join(format!("auditor-tools-test.{}.{n}", std::process::id()));
        fs::create_dir(&root).expect("make the test directory");
        fs::create_dir(root.join("wt")).expect("make wt");
        fs::create_dir(root.join("outside")).expect("make outside");
        let dir = root.join("wt");
        Wt { root, dir }
    }

    /// A new working tree that is a git repository.
    pub fn repo() -> Wt {
        let wt = Wt::new();
        wt.git(&["init", "-q", "."]);
        wt
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    pub fn outside(&self) -> PathBuf {
        self.root.join("outside")
    }

    pub fn write(&self, rel: &str, text: &[u8]) {
        let p = self.path(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).expect("make the parent directory");
        }
        fs::write(p, text).expect("write a fixture file");
    }

    pub fn mkdir(&self, rel: &str) {
        fs::create_dir_all(self.path(rel)).expect("make a fixture directory");
    }

    pub fn link(&self, target: &Path, rel: &str) {
        symlink(target, self.path(rel)).expect("make a fixture link");
    }

    /// A run directory as `rundir.sh new` leaves it: a directory with a
    /// `.gitignore` of `*`.
    pub fn run_dir(&self, name: &str) {
        self.mkdir(name);
        self.write(&format!("{name}/.gitignore"), b"*\n");
    }

    pub fn exists(&self, rel: &str) -> bool {
        fs::symlink_metadata(self.path(rel)).is_ok()
    }

    pub fn read(&self, rel: &str) -> Vec<u8> {
        fs::read(self.path(rel)).expect("read a fixture file")
    }

    pub fn chmod(&self, rel: &str, mode: u32) {
        fs::set_permissions(self.path(rel), fs::Permissions::from_mode(mode))
            .expect("chmod a fixture");
    }

    /// git in the working tree, with the caller's git config left out.
    pub fn git(&self, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(&self.dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run git");
        assert!(status.success(), "git {args:?}");
    }

    /// Every path under the working tree, never following a link, with its type,
    /// size and bytes: what a refused call must leave as it was.
    pub fn snapshot(&self) -> Vec<(PathBuf, String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut todo = vec![self.dir.clone()];
        while let Some(d) = todo.pop() {
            let mut names: Vec<_> = match fs::read_dir(&d) {
                Ok(rd) => rd.filter_map(Result::ok).map(|e| e.path()).collect(),
                Err(_) => continue,
            };
            names.sort();
            for p in names {
                let md = fs::symlink_metadata(&p).expect("lstat a fixture path");
                let kind = if md.file_type().is_symlink() {
                    format!("link {}", fs::read_link(&p).unwrap_or_default().display())
                } else if md.is_dir() {
                    todo.push(p.clone());
                    "dir".to_string()
                } else {
                    format!("file {}", md.len())
                };
                let bytes = if md.is_file() {
                    fs::read(&p).unwrap_or_default()
                } else {
                    Vec::new()
                };
                out.push((p, kind, bytes));
            }
        }
        out.sort();
        out
    }
}

/// A `#[derive(Accounts)]` struct called `name` with `pdas` fields, each with
/// seeds: each of its PDAs repeats `name` in a report.
pub fn pda_struct(name: &str, pdas: usize) -> String {
    let fields: String = (0..pdas)
        .map(|i| {
            format!("    #[account(seeds = [b\"x\"], bump)]\n    pub f{i}: AccountInfo<'info>,\n")
        })
        .collect();
    format!("#[derive(Accounts)]\npub struct {name}<'info> {{\n{fields}}}\n")
}

/// A binary run from `dir`, with stdin from /dev/null and the caller's
/// environment.
pub fn run(bin: &str, dir: &Path, args: &[&str]) -> Output {
    run_env(bin, dir, args, &[])
}

pub fn run_env(bin: &str, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin);
    cmd.args(args).current_dir(dir).stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run the binary")
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A path as the binaries show a value in a message: cut after 200 bytes, then
/// `...`. A temporary directory with a long path makes the trees' paths long.
pub fn shown(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if out.len() + c.len_utf8() > 200 {
            out.push_str("...");
            break;
        }
        out.push(c);
    }
    out
}

/// The call was refused: exit 2, nothing on stdout, and one stderr line
/// `<tool>: refused: <why>`.
pub fn refused(o: &Output, tool: &str, why: &str) {
    assert_eq!(
        o.status.code(),
        Some(2),
        "exit status; stderr: {}",
        stderr(o)
    );
    assert_eq!(stdout(o), "", "stdout");
    assert_eq!(stderr(o), format!("{tool}: refused: {why}\n"), "stderr");
}

/// The call was refused with a reason that starts with `why`.
pub fn refused_with(o: &Output, tool: &str, why: &str) {
    assert_eq!(
        o.status.code(),
        Some(2),
        "exit status; stderr: {}",
        stderr(o)
    );
    assert_eq!(stdout(o), "", "stdout");
    let err = stderr(o);
    assert!(
        err.starts_with(&format!("{tool}: refused: {why}")) && err.lines().count() == 1,
        "stderr: {err}"
    );
}
