//! `audit-logs` — the detection & response analysis recipes of `scripts/dnr/`
//! (`profile.sh`, `frames.py`, `deltas.py`) in one offline binary, with the same
//! output, the same input contract and the same exit statuses.
//!
//! ```text
//! audit-logs profile [--out <file>] <corpus.jsonl>...
//! audit-logs frames [--instructions] [--out <file>] [<corpus.jsonl>...]
//! audit-logs deltas lamports|tokens [--out <file>] [<corpus.jsonl>...]
//! ```
//!
//! Every path is relative to the working directory and inside an
//! `incident_<n>/` run directory (`confine.rs`). With no corpus named, frames
//! and deltas read stdin. Exit: 0 done · 1 an input that cannot be read, an
//! `--out` that cannot be written, or a failed write · 2 usage, or a refused
//! path (a symbolic link on the way, an absolute path, `..`, a path outside a
//! run directory); profile also exits 2 for an input that is missing or not a
//! regular file, as profile.sh does.

mod confine;
mod contract;
mod deltas;
mod frames;
mod json;
mod num;
mod profile;

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use confine::{Confined, Found, Refusal, Sink};
use contract::{for_each_record, shown, Input, Source, Stats};

const USAGE: &str = "usage: audit-logs profile [--out <file>] <corpus.jsonl>... | \
frames [--instructions] [--out <file>] [<corpus.jsonl>...] | \
deltas lamports|tokens [--out <file>] [<corpus.jsonl>...]";

#[derive(Clone, Copy, PartialEq)]
enum Recipe {
    Profile,
    Frames,
    Instructions,
    Lamports,
    Tokens,
}

struct Call {
    recipe: Recipe,
    out: Option<OsString>,
    files: Vec<OsString>,
}

/// Ends the run with a status and one stderr line.
struct Stop(u8, String);

fn usage(why: &str) -> Stop {
    Stop(2, format!("refused: {why} ({USAGE})"))
}

/// The closed grammar: a subcommand, its options (each at most once) before any
/// corpus path, then the paths. Anything else is refused before any file is opened.
fn parse(args: &[OsString]) -> Result<Call, Stop> {
    let Some(sub) = args.first().and_then(|a| a.to_str()) else {
        return Err(usage("no subcommand"));
    };
    let mut rest = &args[1..];
    let mut recipe = match sub {
        "profile" => Recipe::Profile,
        "frames" => Recipe::Frames,
        "deltas" => {
            let mode = rest.first().and_then(|a| a.to_str());
            rest = rest.get(1..).unwrap_or(&[]);
            match mode {
                Some("lamports") => Recipe::Lamports,
                Some("tokens") => Recipe::Tokens,
                _ => return Err(usage("deltas takes lamports or tokens")),
            }
        }
        _ => {
            return Err(usage(&format!(
                "unknown subcommand {}",
                shown(sub.as_bytes())
            )))
        }
    };
    let mut out = None;
    let mut instructions = false;
    while let Some(word) = rest.first().and_then(|a| a.to_str()) {
        match word {
            "--out" if out.is_none() => {
                let value = rest.get(1).ok_or_else(|| usage("--out needs a file"))?;
                out = Some(value.clone());
                rest = &rest[2..];
            }
            "--instructions" if recipe == Recipe::Frames && !instructions => {
                instructions = true;
                rest = &rest[1..];
            }
            w if w.starts_with('-') => {
                return Err(usage(&format!(
                    "option {} is unknown here or given twice",
                    shown(w.as_bytes())
                )))
            }
            _ => break,
        }
    }
    if instructions {
        recipe = Recipe::Instructions;
    }
    if recipe == Recipe::Profile && rest.is_empty() {
        return Err(usage("profile needs at least one corpus"));
    }
    Ok(Call {
        recipe,
        out,
        files: rest.to_vec(),
    })
}

fn refused(r: Refusal) -> Stop {
    Stop(2, format!("refused: {}", r.0))
}

/// Checks every named input, in the scripts' order, and returns them unopened:
/// each is opened again when its turn comes, and must still be the file checked.
fn inputs(wt: &Path, call: &Call, checked: &[Confined]) -> Result<Vec<Input>, Stop> {
    for c in checked {
        confine::check_run_dir(wt, c).map_err(refused)?;
    }
    // profile.sh's own test: every corpus must be a regular file (after links)
    // before any is read, else a usage error.
    if call.recipe == Recipe::Profile {
        for (n, c) in checked.iter().enumerate() {
            if !fs::metadata(c.full(wt)).is_ok_and(|md| md.is_file()) {
                return Err(usage(&format!(
                    "input {} ({}) is not a regular file",
                    n + 1,
                    c.shown()
                )));
            }
        }
    }
    let mut out = Vec::new();
    for (n, c) in checked.iter().enumerate() {
        let label = format!("input {} ({})", n + 1, c.shown());
        let full = c.full(wt);
        let cannot = |why: String| Stop(1, format!("cannot read {label}: {why}"));
        let md = match confine::walk(wt, c) {
            Found::Link => {
                return Err(Stop(
                    2,
                    format!(
                        "refused: {label} is a symbolic link, or is reached through one inside the working directory"
                    ),
                ));
            }
            Found::Missing(_) => return Err(cannot("No such file or directory".into())),
            Found::Unreadable(e) => return Err(cannot(confine::os_message(&e))),
            Found::File(md) => md,
        };
        if !md.file_type().is_file() {
            return Err(cannot("not a regular file".into()));
        }
        if !confine::stays_inside(wt, &full) {
            return Err(Stop(
                2,
                format!("refused: {label} resolves outside the working directory"),
            ));
        }
        confine::open_checked(&full, &md).map_err(|e| cannot(confine::os_message(&e)))?;
        out.push(Input {
            label,
            source: Source::File(full, md),
        });
    }
    if call.files.is_empty() {
        out.push(Input {
            label: "stdin".into(),
            source: Source::Stdin,
        });
    }
    Ok(out)
}

/// Checks the `--out` path as the scripts do: a new name, not a link and not
/// reached through one, in a directory that exists.
fn out_path(wt: &Path, c: &Confined) -> Result<PathBuf, Stop> {
    confine::check_run_dir(wt, c).map_err(refused)?;
    let shown = c.shown();
    let full = c.full(wt);
    match confine::walk(wt, c) {
        Found::Link => Err(Stop(
            2,
            format!("refused: --out {shown} is a symbolic link, or is reached through one inside the working directory"),
        )),
        Found::Missing(n) if n + 1 < c.depth() => Err(Stop(
            1,
            format!("cannot write --out {shown}: its directory does not exist"),
        )),
        Found::Missing(_) => Ok(()),
        Found::Unreadable(e) => Err(Stop(
            1,
            format!("cannot write --out {shown}: {}", confine::os_message(&e)),
        )),
        Found::File(_) => Err(Stop(
            2,
            format!(
                "refused: --out {shown} already exists, and an output never replaces a file: name a new one"
            ),
        )),
    }?;
    let parent = full.parent().map(Path::to_path_buf).unwrap_or_default();
    if !confine::stays_inside(wt, &parent) {
        return Err(Stop(
            2,
            format!("refused: --out {shown} resolves outside the working directory"),
        ));
    }
    Ok(full)
}

fn run(args: &[OsString]) -> Result<(), Stop> {
    let call = parse(args)?;
    let mut checked = Vec::new();
    for (n, arg) in call.files.iter().enumerate() {
        checked.push(confine::confine(&format!("input {}", n + 1), arg).map_err(refused)?);
    }
    let out_arg = match &call.out {
        Some(arg) => {
            let c = confine::confine("--out", arg).map_err(refused)?;
            if !c.is_output() {
                return Err(Stop(
                    2,
                    format!(
                        "refused: --out {} is not a .jsonl, .tsv or .txt file directly in the run directory",
                        c.shown()
                    ),
                ));
            }
            Some(c)
        }
        None => None,
    };
    let wt = confine::working_tree().map_err(refused)?;
    confine::self_check(&wt).map_err(refused)?;
    let inputs = inputs(&wt, &call, &checked)?;
    let out = match &out_arg {
        Some(c) => Some(out_path(&wt, c)?),
        None => None,
    };

    let mut sink = match out {
        Some(path) => Sink::temp(path).map_err(|e| {
            Stop(
                1,
                format!("cannot write --out: {}", confine::os_message(&e)),
            )
        })?,
        None => Sink::stdout(),
    };
    let failed = |e: io::Error| Stop(1, confine::os_message(&e));
    // The --out path is checked again just before the output takes its name.
    let recheck = || match &out_arg {
        Some(c) => out_path(&wt, c).map(|_| ()),
        None => Ok(()),
    };
    let mut stats = Stats::default();
    match call.recipe {
        Recipe::Profile => {
            let header = format!(
                "== corpus: {}",
                call.files
                    .iter()
                    .map(|f| shown(std::os::unix::ffi::OsStrExt::as_bytes(f.as_os_str())))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            let mut prof = profile::Profile::default();
            for_each_record(inputs, &mut stats, |tx| {
                prof.add(tx);
                Ok(())
            })
            .map_err(failed)?;
            let notes = stats.notes();
            for note in &notes {
                eprintln!("audit-logs: skipped {note}");
            }
            sink.write_all(prof.report(&header, &notes).as_bytes())
                .map_err(failed)?;
            recheck()?;
            sink.finish().map_err(failed)?;
        }
        recipe => {
            let mut buf = String::new();
            let mut keyless = 0;
            for_each_record(inputs, &mut stats, |tx| {
                buf.clear();
                match recipe {
                    Recipe::Frames => frames::rows(tx, &mut buf),
                    Recipe::Instructions => frames::instruction_rows(tx, &mut buf),
                    Recipe::Lamports => keyless += deltas::lamports(tx, &mut buf),
                    _ => deltas::tokens(tx, &mut buf),
                }
                sink.write_all(buf.as_bytes())
            })
            .map_err(failed)?;
            recheck()?;
            sink.finish().map_err(failed)?;
            for note in stats.notes() {
                eprintln!("audit-logs: skipped {note}");
            }
            if keyless > 0 {
                eprintln!(
                    "audit-logs: {keyless} row(s) name a balance index that has no account key, as #<index>: \
                     the transaction lists fewer keys than balances (an encoding json export without \
                     meta.loadedAddresses, say)"
                );
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Stop(code, message)) => {
            eprintln!("audit-logs: {message}");
            ExitCode::from(code)
        }
    }
}
