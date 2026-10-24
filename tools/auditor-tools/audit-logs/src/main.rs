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
//! Every path is relative to the working directory and names a regular file with
//! one name in an `incident_<n>/` run directory there, reached through no
//! symbolic link; `--out` is a new `.jsonl`, `.tsv` or `.txt` name directly in a
//! run directory (`confine.rs`). With no corpus named, frames and deltas read
//! stdin. Exit: 0 done · 1 an input that cannot be read, an `--out` that cannot be
//! written, or a failed write · 2 usage, or a path the input contract refuses, as
//! the recipes refuse it.

mod confine;
mod contract;
mod deltas;
mod frames;
mod json;
mod num;
mod profile;

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;

use confine::{os_message, Confined, Sink, Stop};
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

fn usage(why: &str) -> Stop {
    Stop(2, format!("refused: {why} ({USAGE})"))
}

/// The closed grammar: a subcommand, its options (each at most once) before any
/// corpus path, then the paths, in the recipes' words. Anything else is refused
/// before any file is opened.
fn parse(args: &[OsString]) -> Result<Call, Stop> {
    let Some(sub) = args.first() else {
        return Err(usage("no subcommand"));
    };
    let mut rest = &args[1..];
    let mut recipe = match sub.as_bytes() {
        b"profile" => Recipe::Profile,
        b"frames" => Recipe::Frames,
        b"deltas" => {
            let mode = rest.first().map(|a| a.as_bytes());
            rest = rest.get(1..).unwrap_or(&[]);
            match mode {
                Some(b"lamports") => Recipe::Lamports,
                Some(b"tokens") => Recipe::Tokens,
                _ => return Err(usage("deltas takes lamports or tokens")),
            }
        }
        other => return Err(usage(&format!("unknown subcommand {}", shown(other)))),
    };
    let mut out = None;
    let mut instructions = false;
    while let Some(word) = rest.first().map(|a| a.as_bytes()) {
        match word {
            b"--out" if out.is_none() => {
                let value = rest.get(1).ok_or_else(|| usage("--out needs a file"))?;
                out = Some(value.clone());
                rest = &rest[2..];
            }
            b"--instructions" if recipe == Recipe::Frames && !instructions => {
                instructions = true;
                rest = &rest[1..];
            }
            w if w.starts_with(b"-") => {
                return Err(usage(&format!(
                    "option {} is unknown here or given twice",
                    shown(w)
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

fn run(args: &[OsString]) -> Result<(), Stop> {
    let wt = confine::working_tree()?;
    confine::self_check(&wt)?;
    let call = parse(args)?;
    // Every input, then --out, each checked in full before the next, as the recipes'
    // unusable() and unwritable() check them; nothing is read before all pass.
    let mut inputs = Vec::new();
    for (n, arg) in call.files.iter().enumerate() {
        let c = confine::confine(&format!("input {}", n + 1), arg)?;
        let md = confine::input(&wt, &c)?;
        inputs.push(Input {
            label: c.label().to_string(),
            source: Source::File(c.full(&wt), md),
        });
    }
    if call.files.is_empty() {
        inputs.push(Input {
            label: "stdin".into(),
            source: Source::Stdin,
        });
    }
    let out: Option<(Confined, PathBuf)> = match &call.out {
        Some(arg) => {
            let c = confine::confine("--out", arg)?;
            let path = confine::output(&wt, &c)?;
            Some((c, path))
        }
        None => None,
    };
    let sink = |out: &Option<(Confined, PathBuf)>| match out {
        Some((_, path)) => Sink::temp(path.clone())
            .map_err(|e| Stop(1, format!("cannot write --out: {}", os_message(&e)))),
        None => Ok(Sink::stdout()),
    };
    let failed = |e: io::Error| Stop(1, os_message(&e));
    let mut stats = Stats::default();
    match call.recipe {
        Recipe::Profile => {
            let header = format!(
                "== corpus: {}",
                call.files
                    .iter()
                    .map(|f| shown(f.as_bytes()))
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
            let report = prof.report(&header, &notes);
            // As profile.sh does: the report is whole before --out is checked again
            // and its directory opened.
            if let Some((c, _)) = &out {
                confine::output(&wt, c)?;
            }
            let mut sink = sink(&out)?;
            sink.write_all(report.as_bytes()).map_err(failed)?;
            sink.finish().map_err(failed)?;
        }
        recipe => {
            let mut sink = sink(&out)?;
            let mut buf = String::new();
            let (mut keyless, mut indexless) = (0, 0);
            for_each_record(inputs, &mut stats, |tx| {
                buf.clear();
                match recipe {
                    Recipe::Frames => frames::rows(tx, &mut buf),
                    Recipe::Instructions => frames::instruction_rows(tx, &mut buf),
                    Recipe::Lamports => keyless += deltas::lamports(tx, &mut buf),
                    _ => {
                        let (k, i) = deltas::tokens(tx, &mut buf);
                        keyless += k;
                        indexless += i;
                    }
                }
                sink.write_all(buf.as_bytes())
            })
            .map_err(failed)?;
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
            if indexless > 0 {
                eprintln!(
                    "audit-logs: {indexless} row(s) name a token balance that has no accountIndex, as #?: \
                     nothing pairs it with its other side, so a pre balance is a row of its own with a \
                     negative delta, and a post balance one with a positive delta"
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
