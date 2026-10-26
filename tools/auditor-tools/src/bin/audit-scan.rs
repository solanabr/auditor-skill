//! `audit-scan [--contract=1] <dir> [--workflows <dir>] [--out <R>/prescan.json | <R>/prescan-<slug>.json] [--pretty]`
//!
//! Recursively parses `*.rs` files under `<dir>` and prints one JSON object
//! describing the risky audit surface to stdout (or `--out`). With `--workflows
//! <dir>` it also reads the `*.yml`/`*.yaml` files directly in `<dir>` (usually
//! `.github/workflows`) into the report's `workflows` key, each as trigger → job
//! → step facts; `<dir>` is a confined directory like the one to scan, and the
//! files are read with the same walk (no link, a regular file of at most 4 MiB).
//!
//! It is built to be pre-approved as one rule on its absolute path followed by
//! `--contract=1`, the marker of its contract, which a build made before it
//! refuses; the marker comes first and changes nothing. It is safe whatever
//! arguments follow (`confine.rs`): `<dir>` is `.` or a directory inside
//! the working directory, named by a relative path with no `.` or `..` component
//! and reached through no symbolic link, and the walk follows no link. `--out` is
//! `prescan.json` or `prescan-<slug>.json` (slug: 1 to 32 of `a-z`, `0-9`, `-`) in
//! a run directory, `audit_<n>/` or `incident_<n>/`, that passes
//! `scripts/rundir.sh check`; it is made new, or replaces audit-scan's own earlier
//! output there: a regular file with one name. Each option is given once.
//! Each file is parsed in a child of this binary, started by the path it runs
//! from with `confine::PARSE_STDIN` as its only argument: the file's bytes on its
//! stdin, no environment, killed past `confine::PARSE_TIME`. A file whose child
//! does not finish is skipped, and the scan goes on.
//! Exit: 0 done · 1 the output cannot be written · 2 refused.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;

use auditor_tools::confine::{self, os_message, refuse, Dir, Git, Kind, Rel, Stop};
use auditor_tools::{scan, workflow};

const USAGE: &str = "usage: audit-scan [--contract=1] <dir> [--workflows <dir>] \
[--out <run dir>/prescan.json | <run dir>/prescan-<slug>.json] [--pretty]";

struct Call {
    dir: OsString,
    workflows: Option<OsString>,
    out: Option<OsString>,
    pretty: bool,
}

fn usage(why: &str) -> Stop {
    refuse(format!("{why} ({USAGE})"))
}

/// The closed grammar: `--contract=1` first, or not at all, then one directory,
/// `--workflows <dir>`, `--out <file>` (either as `--opt value` or `--opt=value`)
/// and `--pretty`, each at most once, in any order. The word after `--workflows`
/// or `--out` is its value whatever it looks like; any other word that starts
/// with `-` is refused, another `--contract…` word with it.
fn parse(args: &[OsString]) -> Result<Call, Stop> {
    let mut dir = None;
    let mut workflows = None;
    let mut out = None;
    let mut pretty = false;
    let mut rest = args;
    if rest
        .first()
        .is_some_and(|w| w.as_bytes() == confine::CONTRACT.as_bytes())
    {
        rest = &rest[1..];
    }
    while !rest.is_empty() {
        let word = rest[0].clone();
        let w = word.as_bytes();
        if w.starts_with(b"--contract") {
            return Err(usage(&confine::contract_word(w, "first")));
        }
        if w == b"--out" {
            let v = rest
                .get(1)
                .ok_or_else(|| usage("--out needs a file"))?
                .clone();
            rest = &rest[2..];
            if out.replace(v).is_some() {
                return Err(usage("--out is given more than once"));
            }
        } else if let Some(v) = w.strip_prefix(b"--out=") {
            let v = OsStr::from_bytes(v).to_os_string();
            rest = &rest[1..];
            if out.replace(v).is_some() {
                return Err(usage("--out is given more than once"));
            }
        } else if w == b"--workflows" {
            let v = rest
                .get(1)
                .ok_or_else(|| usage("--workflows needs a directory"))?
                .clone();
            rest = &rest[2..];
            if workflows.replace(v).is_some() {
                return Err(usage("--workflows is given more than once"));
            }
        } else if let Some(v) = w.strip_prefix(b"--workflows=") {
            let v = OsStr::from_bytes(v).to_os_string();
            rest = &rest[1..];
            if workflows.replace(v).is_some() {
                return Err(usage("--workflows is given more than once"));
            }
        } else if w == b"--pretty" {
            rest = &rest[1..];
            if pretty {
                return Err(usage("--pretty is given more than once"));
            }
            pretty = true;
        } else if w.starts_with(b"-") {
            return Err(usage(&format!("unknown option {}", confine::shown(w))));
        } else {
            rest = &rest[1..];
            if dir.replace(word).is_some() {
                return Err(usage("it takes one directory"));
            }
        }
    }
    let dir = dir.ok_or_else(|| usage("no directory to scan"))?;
    Ok(Call {
        dir,
        workflows,
        out,
        pretty,
    })
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
    let workflows = match &call.workflows {
        Some(arg) => {
            let wdir = confine::rel("--workflows", arg, false)?;
            if confine::check(&wt, &wdir, "--workflows")? != Kind::Dir {
                return Err(refuse(format!(
                    "--workflows is not an existing directory: {}",
                    wdir.shown()
                )));
            }
            Some(wdir)
        }
        None => None,
    };
    let out = match &call.out {
        Some(arg) => Some(check_out(&wt, arg)?),
        None => None,
    };

    let mut report = scan::scan_path(dir.path())
        .map_err(|e| Stop(1, format!("cannot start the scan: {}", os_message(&e))))?;
    if let Some(wdir) = &workflows {
        let (parsed, skipped) = workflow::scan_workflows(wdir.path());
        report.workflows = parsed;
        report.skipped.extend(skipped);
    }
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
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if let [word] = args.as_slice() {
        if word.as_bytes() == confine::PARSE_STDIN.as_bytes() {
            return match scan::parse_stdin() {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(1),
            };
        }
    }
    // SAFETY: umask only sets this process's file-mode mask.
    unsafe {
        libc::umask(0o077);
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Stop(code, message)) => {
            eprintln!("audit-scan: {message}");
            ExitCode::from(code)
        }
    }
}
