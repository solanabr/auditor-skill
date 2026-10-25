//! `audit-scan <dir> [--out <R>/prescan.json | <R>/prescan-<slug>.json] [--pretty]`
//!
//! Recursively parses `*.rs` files under `<dir>` and prints one JSON object
//! describing the risky audit surface to stdout (or `--out`).
//!
//! It is built to be pre-approved as one rule on its absolute path, so it is safe
//! whatever arguments follow (`confine.rs`): `<dir>` is `.` or a directory inside
//! the working directory, named by a relative path with no `.` or `..` component
//! and reached through no symbolic link, and the walk follows no link. `--out` is
//! `prescan.json` or `prescan-<slug>.json` (slug: 1 to 32 of `a-z`, `0-9`, `-`) in
//! a run directory, `audit_<n>/` or `incident_<n>/`, that passes
//! `scripts/rundir.sh check`; it is made new, or replaces audit-scan's own earlier
//! output there: a regular file with one name. Each option is given once.
//! Exit: 0 done · 1 the output cannot be written · 2 refused.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;

use auditor_tools::confine::{self, os_message, refuse, Dir, Git, Kind, Rel, Stop};
use auditor_tools::scan;

const USAGE: &str =
    "usage: audit-scan <dir> [--out <run dir>/prescan.json | <run dir>/prescan-<slug>.json] [--pretty]";

struct Call {
    dir: OsString,
    out: Option<OsString>,
    pretty: bool,
}

fn usage(why: &str) -> Stop {
    refuse(format!("{why} ({USAGE})"))
}

/// The closed grammar: one directory, `--out <file>` or `--out=<file>` and
/// `--pretty`, each at most once, in any order. The word after `--out` is its
/// value whatever it looks like; any other word that starts with `-` is refused.
fn parse(args: &[OsString]) -> Result<Call, Stop> {
    let mut dir = None;
    let mut out = None;
    let mut pretty = false;
    let mut rest = args;
    while let Some(word) = rest.first() {
        let w = word.as_bytes();
        let value = if w == b"--out" {
            let v = rest.get(1).ok_or_else(|| usage("--out needs a file"))?;
            rest = &rest[2..];
            Some(v.clone())
        } else if let Some(v) = w.strip_prefix(b"--out=") {
            rest = &rest[1..];
            Some(OsStr::from_bytes(v).to_os_string())
        } else {
            rest = &rest[1..];
            None
        };
        if let Some(v) = value {
            if out.replace(v).is_some() {
                return Err(usage("--out is given more than once"));
            }
        } else if w == b"--pretty" {
            if pretty {
                return Err(usage("--pretty is given more than once"));
            }
            pretty = true;
        } else if w.starts_with(b"-") {
            return Err(usage(&format!("unknown option {}", confine::shown(w))));
        } else if dir.replace(word.clone()).is_some() {
            return Err(usage("it takes one directory"));
        }
    }
    let dir = dir.ok_or_else(|| usage("no directory to scan"))?;
    Ok(Call { dir, out, pretty })
}

/// `--out`'s name in its run directory: `prescan.json`, or `prescan-<slug>.json`.
fn out_name(name: &[u8]) -> bool {
    if name == b"prescan.json" {
        return true;
    }
    match name
        .strip_prefix(b"prescan-")
        .and_then(|n| n.strip_suffix(b".json"))
    {
        Some(slug) => {
            (1..=32).contains(&slug.len())
                && slug
                    .iter()
                    .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        }
        None => false,
    }
}

/// Where `--out` goes, checked: its run directory, as lstat found it, and the
/// file's name there.
struct Out {
    rel: Rel,
    dir_md: std::fs::Metadata,
}

fn check_out(wt: &Path, arg: &OsStr) -> Result<Out, Stop> {
    let shape = || {
        refuse(format!(
            "--out must be audit_<n>/prescan.json or audit_<n>/prescan-<slug>.json, or the same in \
             incident_<n>/, with a slug of 1 to 32 of a-z, 0-9 and -: {}",
            confine::shown(arg.as_bytes())
        ))
    };
    let rel = confine::rel("--out", arg, false)?;
    let [dir, name] = rel.parts.as_slice() else {
        return Err(shape());
    };
    if !confine::is_run_dir_name(dir) || !out_name(name) {
        return Err(shape());
    }
    let mut git = Git::new(wt);
    let dir_md = confine::run_dir(wt, &mut git, dir, "--out")?;
    let s = rel.shown();
    match std::fs::symlink_metadata(rel.full(wt)) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(refuse(format!("--out is a symbolic link: {s}")))
        }
        Ok(md) if !md.file_type().is_file() => {
            return Err(refuse(format!("--out is not a regular file: {s}")))
        }
        Ok(md) if std::os::unix::fs::MetadataExt::nlink(&md) != 1 => {
            return Err(refuse(format!(
                "--out has more than one name (a hard link): {s}"
            )))
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(refuse(format!(
                "--out cannot be checked ({}): {s}",
                os_message(&e)
            )))
        }
    }
    Ok(Out { rel, dir_md })
}

/// Writes the output through its run directory, opened once without following a
/// link: a new file, made exclusively, or else the file that is there when it is
/// a regular file with one name, emptied first.
fn write_out(out: &Out, bytes: &[u8]) -> io::Result<()> {
    let dir = Dir::open(&out.rel.parts[0], &out.dir_md)?;
    let name = &out.rel.parts[1];
    let mut file = match dir.create(name) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let f = dir.open_regular(name, true)?;
            f.set_len(0)?;
            f
        }
        Err(e) => return Err(e),
    };
    file.write_all(bytes)?;
    file.flush()
}

fn run(args: &[OsString]) -> Result<(), Stop> {
    let wt = confine::working_tree()?;
    confine::plain_working_tree(&wt)?;
    confine::self_check(&wt)?;
    let call = parse(args)?;
    let dir = confine::rel("the directory to scan", &call.dir, true)?;
    if confine::check(&wt, &dir, "the directory to scan")? != Kind::Dir {
        return Err(refuse(format!(
            "the directory to scan is not an existing directory: {}",
            dir.shown()
        )));
    }
    let out = match &call.out {
        Some(arg) => Some(check_out(&wt, arg)?),
        None => None,
    };

    let report = scan::scan_path(dir.path());
    let json = if call.pretty {
        serde_json::to_string_pretty(&report)
    } else {
        serde_json::to_string(&report)
    }
    .map_err(|e| Stop(1, format!("cannot write the report: {e}")))?;
    let mut text = confine::json_text(json);
    text.push('\n');

    match &out {
        Some(out) => write_out(out, text.as_bytes()).map_err(|e| {
            Stop(
                1,
                format!("cannot write --out {}: {}", out.rel.shown(), os_message(&e)),
            )
        }),
        None => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| Stop(1, format!("cannot write the report: {}", os_message(&e))))
        }
    }
}

fn main() -> ExitCode {
    // SAFETY: umask only sets this process's file-mode mask.
    unsafe {
        libc::umask(0o077);
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Stop(code, message)) => {
            eprintln!("audit-scan: {message}");
            ExitCode::from(code)
        }
    }
}
