//! `audit-mem <subcommand> [--db <store>] [options]` — SQLite findings store for
//! cross-audit memory.
//!
//! Subcommands: `init`, `put-finding`, `set-status`, `rule`, `check`,
//! `regressions`, `warm`, `profile`, `invariant`. See the crate README for full
//! usage.
//!
//! It is built so that `warm`, `check`, `regressions`, `init` and `put-finding`
//! (and `profile` and `invariant`) can be pre-approved, each as a rule on its
//! absolute path and subcommand, safe whatever arguments follow (`confine.rs`):
//! - The subcommand comes first; each option is given once, as `--name <value>`
//!   or `--name=<value>`, and the word after `--name` is its value whatever it
//!   looks like. Every text value is UTF-8, at most 4096 bytes, and holds no
//!   control or formatting character.
//! - `--db` is `.audit-memory/audit.db` (the default) or `<R>/audit-mem.db`, where
//!   `<R>` is a run directory, `audit_<n>` or `incident_<n>`, that passes
//!   `scripts/rundir.sh check`. Before it uses the in-tree store, audit-mem checks
//!   it as `scripts/rundir.sh store` does: untracked in any letter case (asked of
//!   git as confine.sh's `hgit` asks it), a real directory holding no symbolic
//!   link, with a `.gitignore` of exactly `*`; git that cannot answer is a
//!   refusal. The database is a regular file with one name.
//! - `warm`, `check` and `regressions` open the store read-only and never make
//!   it; with no store they print an empty answer. `init` makes the store: the
//!   `.audit-memory/` directory with a plain mkdir, its `.gitignore` first, then
//!   the database, each made exclusively and never through a link. The other
//!   subcommands write only a store that `init` made.
//!
//! Exit: 0 done (`check`: suppressed) · 1 `check`: not suppressed · 2 refused, or
//! the store cannot be read or written.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;
use std::process::ExitCode;

use auditor_tools::confine::{self, os_message, refuse, shown, unsafe_char, Dir, Git, Kind, Stop};
use auditor_tools::mem;
use rusqlite::Connection;

const USAGE: &str = "usage: audit-mem <subcommand> [--db <store>] [options], the subcommand \
being init, put-finding, set-status, rule, check, regressions, warm, profile or invariant";

/// The longest text value accepted, in bytes.
const MAX_FIELD: usize = 4096;

/// The in-tree store.
const IN_TREE: &[u8] = b".audit-memory/audit.db";
const STORE_DIR: &[u8] = b".audit-memory";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sub {
    Init,
    PutFinding,
    SetStatus,
    Rule,
    Check,
    Regressions,
    Warm,
    Profile,
    Invariant,
}

impl Sub {
    fn parse(word: &[u8]) -> Option<Sub> {
        Some(match word {
            b"init" => Sub::Init,
            b"put-finding" => Sub::PutFinding,
            b"set-status" => Sub::SetStatus,
            b"rule" => Sub::Rule,
            b"check" => Sub::Check,
            b"regressions" => Sub::Regressions,
            b"warm" => Sub::Warm,
            b"profile" => Sub::Profile,
            b"invariant" => Sub::Invariant,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Sub::Init => "init",
            Sub::PutFinding => "put-finding",
            Sub::SetStatus => "set-status",
            Sub::Rule => "rule",
            Sub::Check => "check",
            Sub::Regressions => "regressions",
            Sub::Warm => "warm",
            Sub::Profile => "profile",
            Sub::Invariant => "invariant",
        }
    }

    /// The options it takes besides `--db`, the ones it needs first.
    fn options(self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Sub::Init => (&[], &[]),
            Sub::PutFinding => (
                &["program-id", "signature", "root-cause", "title", "severity"],
                &["commit", "audit-n", "file", "line", "verdict"],
            ),
            Sub::SetStatus => (&["program-id", "signature", "root-cause", "status"], &[]),
            Sub::Rule => (
                &["program-id", "signature", "ruling", "rationale", "by"],
                &["scope", "commit", "guard"],
            ),
            Sub::Check => (&["program-id", "signature"], &["commit"]),
            Sub::Regressions | Sub::Warm => (&["program-id"], &[]),
            Sub::Profile => (
                &["program-id"],
                &[
                    "protocol-class",
                    "trust-assumptions-json",
                    "oracle-set",
                    "admin-set",
                    "notes",
                ],
            ),
            Sub::Invariant => (
                &["program-id", "statement"],
                &["protocol-class", "source-fn", "cited-line", "status"],
            ),
        }
    }

    /// Whether it only reads the store.
    fn reads_only(self) -> bool {
        matches!(self, Sub::Check | Sub::Regressions | Sub::Warm)
    }
}

/// A call that passed the grammar: the subcommand, `--db` as given (or the
/// default), and each other option's value, by name.
struct Call {
    sub: Sub,
    db: OsString,
    values: Vec<(&'static str, OsString)>,
}

impl Call {
    fn raw(&self, name: &str) -> Option<&OsStr> {
        self.values
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_os_str())
    }

    /// A text value under the field rule: UTF-8, non-empty when the subcommand
    /// needs the option, at most 4096 bytes, and no control or formatting
    /// character (`confine::unsafe_char`).
    fn text(&self, name: &str) -> Result<Option<String>, Stop> {
        let Some(v) = self.raw(name) else {
            return Ok(None);
        };
        let Some(s) = v.to_str() else {
            return Err(refuse(format!("--{name} is not UTF-8")));
        };
        if s.is_empty() && self.sub.options().0.contains(&name) {
            return Err(refuse(format!("--{name} is empty")));
        }
        if s.len() > MAX_FIELD {
            return Err(refuse(format!("--{name} is longer than {MAX_FIELD} bytes")));
        }
        if s.chars().any(unsafe_char) {
            return Err(refuse(format!(
                "--{name} holds a control or formatting character: {}",
                shown(s.as_bytes())
            )));
        }
        Ok(Some(s.to_string()))
    }

    /// A text value the subcommand needs (the grammar has made sure it is given).
    fn need(&self, name: &str) -> Result<String, Stop> {
        self.text(name)?
            .ok_or_else(|| refuse(format!("{} needs --{name}", self.sub.name())))
    }

    /// One of a fixed set of words.
    fn word(&self, name: &str, allowed: &[&str]) -> Result<String, Stop> {
        let v = self.need(name)?;
        if allowed.contains(&v.as_str()) {
            Ok(v)
        } else {
            Err(refuse(format!(
                "--{name} must be one of {}: {}",
                allowed.join(", "),
                shown(v.as_bytes())
            )))
        }
    }

    /// A decimal number within `range`, digits only.
    fn number(
        &self,
        name: &str,
        range: std::ops::RangeInclusive<i64>,
    ) -> Result<Option<i64>, Stop> {
        let Some(v) = self.text(name)? else {
            return Ok(None);
        };
        let n = (!v.is_empty() && v.len() <= 10 && v.bytes().all(|c| c.is_ascii_digit()))
            .then(|| v.parse::<i64>().ok())
            .flatten()
            .filter(|n| range.contains(n));
        n.map(Some).ok_or_else(|| {
            refuse(format!(
                "--{name} must be a whole number from {} to {}: {}",
                range.start(),
                range.end(),
                shown(v.as_bytes())
            ))
        })
    }

    /// A commit id, 7 to 64 hexadecimal digits, in lowercase.
    fn commit(&self) -> Result<Option<String>, Stop> {
        let Some(v) = self.text("commit")? else {
            return Ok(None);
        };
        if (7..=64).contains(&v.len()) && v.bytes().all(|c| c.is_ascii_hexdigit()) {
            Ok(Some(v.to_ascii_lowercase()))
        } else {
            Err(refuse(format!(
                "--commit must be a commit id of 7 to 64 hexadecimal digits: {}",
                shown(v.as_bytes())
            )))
        }
    }
}

fn usage(why: &str) -> Stop {
    refuse(format!("{why} ({USAGE})"))
}

/// The closed grammar: the subcommand first, then its options, each once.
fn parse(args: &[OsString]) -> Result<Call, Stop> {
    let Some(first) = args.first() else {
        return Err(usage("no subcommand"));
    };
    let sub = Sub::parse(first.as_bytes()).ok_or_else(|| {
        usage(&format!(
            "{} is not a subcommand, and the subcommand comes first",
            shown(first.as_bytes())
        ))
    })?;
    let (needed, optional) = sub.options();
    let mut db = None;
    let mut values: Vec<(&'static str, OsString)> = Vec::new();
    let mut rest = &args[1..];
    while let Some(word) = rest.first() {
        let w = word.as_bytes();
        let Some(opt) = w.strip_prefix(b"--").filter(|o| !o.is_empty()) else {
            return Err(refuse(format!(
                "{} takes no argument {}",
                sub.name(),
                shown(w)
            )));
        };
        let (name, value) = match opt.iter().position(|&c| c == b'=') {
            Some(i) => {
                rest = &rest[1..];
                (&opt[..i], OsStr::from_bytes(&opt[i + 1..]).to_os_string())
            }
            None => {
                let v = rest
                    .get(1)
                    .ok_or_else(|| refuse(format!("--{} needs a value", shown(opt))))?;
                rest = &rest[2..];
                (opt, v.clone())
            }
        };
        if name == b"db" {
            if db.replace(value).is_some() {
                return Err(refuse("--db is given more than once".into()));
            }
            continue;
        }
        let Some(&known) = needed
            .iter()
            .chain(optional.iter())
            .find(|n| n.as_bytes() == name)
        else {
            return Err(refuse(format!(
                "{} takes no option --{}",
                sub.name(),
                shown(name)
            )));
        };
        if values.iter().any(|(n, _)| *n == known) {
            return Err(refuse(format!("--{known} is given more than once")));
        }
        values.push((known, value));
    }
    for name in needed {
        if !values.iter().any(|(n, _)| n == name) {
            return Err(refuse(format!("{} needs --{name}", sub.name())));
        }
    }
    if sub == Sub::Profile && values.len() < 2 {
        return Err(refuse(format!(
            "profile needs at least one of --{}",
            optional.join(", --")
        )));
    }
    Ok(Call {
        sub,
        db: db.unwrap_or_else(|| OsStr::from_bytes(IN_TREE).to_os_string()),
        values,
    })
}

/// What the store's database file is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Db {
    /// No file (or, for the in-tree store, no `.audit-memory/`).
    Absent,
    /// A file of no bytes: an `init` that did not finish.
    Empty,
    /// A SQLite database in rollback-journal mode.
    Sqlite,
}

/// A store that passed its checks: its path relative to WT, its directory (a run
/// directory or `.audit-memory`) and lstat, when the directory exists, the
/// database's name there, and what the file is.
struct Store {
    path: Vec<u8>,
    dir: Vec<u8>,
    dir_md: Option<fs::Metadata>,
    name: &'static [u8],
    db: Db,
    in_tree: bool,
}

impl Store {
    fn shown(&self) -> String {
        shown(&self.path)
    }

    fn path(&self) -> &Path {
        Path::new(OsStr::from_bytes(&self.path))
    }
}

/// Checks `--db` and its store before anything is opened: the path's shape, then
/// the run directory as `rundir.sh check` checks it, or the in-tree store as
/// `rundir.sh store` checks it, in their words, then the database file.
fn check_store(wt: &Path, arg: &OsStr) -> Result<Store, Stop> {
    let raw = arg.as_bytes();
    let path = raw.strip_prefix(b"./").unwrap_or(raw);
    let mut git = Git::new(wt);
    let mut store = if path == IN_TREE {
        in_tree_store(wt, &mut git)?
    } else {
        let run = path
            .strip_suffix(b"/audit-mem.db")
            .filter(|r| confine::is_run_dir_name(r))
            .ok_or_else(|| {
                refuse(format!(
                    "--db must be .audit-memory/audit.db, audit_<n>/audit-mem.db or \
                     incident_<n>/audit-mem.db: {}",
                    shown(raw)
                ))
            })?;
        let md = confine::run_dir(wt, &mut git, run, "--db")?;
        Store {
            path: path.to_vec(),
            dir: run.to_vec(),
            dir_md: Some(md),
            name: b"audit-mem.db",
            db: Db::Absent,
            in_tree: false,
        }
    };
    store.db = match &store.dir_md {
        Some(md) => database(wt, &store, md)?,
        None => Db::Absent,
    };
    Ok(store)
}

/// The in-tree store, checked as `rundir.sh store` checks it, in its words.
fn in_tree_store(wt: &Path, git: &mut Git) -> Result<Store, Stop> {
    let d = ".audit-memory";
    git.need()?;
    match git.tracked(STORE_DIR) {
        Some(listed) if listed.is_empty() => {}
        Some(_) => {
            return Err(refuse(format!(
                "the repository tracks {d} (in some letter case); use <R>/audit-mem.db"
            )))
        }
        None => return Err(refuse(format!("git cannot tell whether {d} is tracked"))),
    }
    let mut store = Store {
        path: IN_TREE.to_vec(),
        dir: STORE_DIR.to_vec(),
        dir_md: None,
        name: b"audit.db",
        db: Db::Absent,
        in_tree: true,
    };
    let dir = wt.join(d);
    let md = match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(store),
        Err(e) => {
            return Err(refuse(format!(
                "{d} cannot be checked ({}); use <R>/audit-mem.db",
                os_message(&e)
            )))
        }
        Ok(md) if md.file_type().is_symlink() => {
            return Err(refuse(format!(
                "{d} is a symbolic link; use <R>/audit-mem.db"
            )))
        }
        Ok(md) if !md.is_dir() => {
            return Err(refuse(format!(
                "{d} is not a directory; use <R>/audit-mem.db"
            )))
        }
        Ok(md) => md,
    };
    match confine::holds_link(&dir) {
        Ok(false) => {}
        Ok(true) => {
            return Err(refuse(format!(
                "{d} holds a symbolic link; use <R>/audit-mem.db"
            )))
        }
        Err(_) => {
            return Err(refuse(format!(
                "{d} cannot be fully read; use <R>/audit-mem.db"
            )))
        }
    }
    if !confine::ignores_all(&dir.join(".gitignore")) {
        return Err(refuse(format!(
            "{d} has no .gitignore holding exactly *; use <R>/audit-mem.db"
        )));
    }
    store.dir_md = Some(md);
    Ok(store)
}

/// What the database file is: absent, empty, or a SQLite database in
/// rollback-journal mode (the header's magic, and 1 in its bytes 18 and 19). A
/// file that is not regular, has a second name, or holds anything else is
/// refused; so is a database in WAL mode, which audit-mem never sets and whose
/// read-only open would make a file beside it. Beside it, SQLite's own files
/// are checked first: a `-wal` or `-shm` file, which audit-mem never makes and
/// which SQLite would open (and a `-shm` write) even for a read, is refused, and
/// a `-journal`, left by a write that stopped, must be a regular file with one
/// name.
fn database(wt: &Path, store: &Store, dir_md: &fs::Metadata) -> Result<Db, Stop> {
    let s = store.shown();
    let tail = if store.in_tree {
        "; use <R>/audit-mem.db"
    } else {
        ""
    };
    for suffix in ["-wal", "-shm", "-journal"] {
        let side = wt.join(OsStr::from_bytes(
            &[&store.path[..], suffix.as_bytes()].concat(),
        ));
        match fs::symlink_metadata(side) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(refuse(format!(
                    "{s}{suffix} cannot be checked ({}){tail}",
                    os_message(&e)
                )))
            }
            Ok(_) if suffix != "-journal" => {
                return Err(refuse(format!(
                    "{s} has a {suffix} file beside it, which audit-mem never makes{tail}"
                )))
            }
            Ok(md) if !md.file_type().is_file() || md.nlink() != 1 => {
                return Err(refuse(format!(
                    "{s}{suffix} is not a regular file with one name{tail}"
                )))
            }
            Ok(_) => {}
        }
    }
    match fs::symlink_metadata(wt.join(store.path())) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Db::Absent),
        Err(e) => {
            return Err(refuse(format!(
                "{s} cannot be checked ({}){tail}",
                os_message(&e)
            )))
        }
        Ok(md) if !md.file_type().is_file() => {
            return Err(refuse(format!("{s} is not a regular file{tail}")))
        }
        Ok(md) if md.nlink() != 1 => {
            return Err(refuse(format!(
                "{s} has more than one name (a hard link){tail}"
            )))
        }
        Ok(_) => {}
    }
    let mut head = Vec::new();
    Dir::open(&store.dir, dir_md)
        .and_then(|dir| dir.open_regular(store.name, false))
        .and_then(|f| f.take(100).read_to_end(&mut head))
        .map_err(|e| refuse(format!("{s} cannot be read: {}", os_message(&e))))?;
    if head.is_empty() {
        return Ok(Db::Empty);
    }
    if head.len() < 100 || !head.starts_with(b"SQLite format 3\0") {
        return Err(refuse(format!(
            "{s} is not a SQLite database, so it is not a store audit-mem wrote{tail}"
        )));
    }
    if head[18] != 1 || head[19] != 1 {
        return Err(refuse(format!(
            "{s} is not in rollback-journal mode (a WAL database, say), which audit-mem never sets{tail}"
        )));
    }
    Ok(Db::Sqlite)
}

/// Makes what `init` needs of the store: for the in-tree store with no
/// `.audit-memory/`, the directory with a plain mkdir (mode 0700), its
/// `.gitignore` of `*` first, then an empty database; in a directory that exists
/// with no database, the database. Each file is made through the directory,
/// opened once without following a link, exclusively.
fn make_store(wt: &Path, store: &Store) -> Result<(), Stop> {
    let s = store.shown();
    let failed = |e: io::Error| Stop(2, format!("error: cannot make {s}: {}", os_message(&e)));
    let md = match &store.dir_md {
        Some(md) => md.clone(),
        None => {
            let dir = wt.join(OsStr::from_bytes(&store.dir));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(failed)?;
            let md = fs::symlink_metadata(&dir).map_err(failed)?;
            let made = Dir::open(&store.dir, &md).map_err(failed)?;
            made.create(b".gitignore")
                .and_then(|mut f| f.write_all(b"*\n").and_then(|()| f.flush()))
                .map_err(failed)?;
            md
        }
    };
    if store.db == Db::Absent {
        Dir::open(&store.dir, &md)
            .and_then(|dir| dir.create(store.name))
            .map_err(failed)?;
    }
    Ok(())
}

/// A store error as one line: a store audit-mem refuses (`mem::Refusal`) as a
/// refusal, naming the store; anything SQLite says as an error.
fn store_error(store: &Store) -> impl Fn(anyhow::Error) -> Stop + '_ {
    move |e: anyhow::Error| match e.downcast_ref::<mem::Refusal>() {
        Some(r) => refuse(format!("{}: {r}", store.shown())),
        None => Stop(
            2,
            format!(
                "error: {}: {}",
                store.shown(),
                shown(format!("{e:#}").as_bytes())
            ),
        ),
    }
}

/// The text of a guard file under the confined path rules, for `check`: a
/// relative path inside WT, through no symbolic link, to a regular file with one
/// name of at most 4 MiB; `Err` says why it cannot be read.
fn guard_text(wt: &Path, file: &str) -> Result<Vec<u8>, String> {
    let reason = |Stop(_, m): Stop| m.trim_start_matches("refused: ").to_string();
    let r = confine::rel("it", OsStr::new(file), false).map_err(reason)?;
    match confine::check(wt, &r, "it").map_err(reason)? {
        Kind::File => confine::read_file(&r),
        Kind::Dir => Err("it is not a regular file".into()),
        Kind::Absent => Err("it does not exist".into()),
    }
}

/// `--guard <file>:<line>` or `<file>:<first>-<last>` (at most 200 lines), its
/// file read under the confined path rules and its lines hashed.
fn guard(wt: &Path, call: &Call) -> Result<Option<mem::Guard>, Stop> {
    let Some(v) = call.text("guard")? else {
        return Ok(None);
    };
    let shape = || {
        refuse(format!(
            "--guard must be <file>:<line> or <file>:<first>-<last>, at most 200 lines: {}",
            shown(v.as_bytes())
        ))
    };
    let (file, lines) = v.rsplit_once(':').ok_or_else(shape)?;
    let number = |s: &str| {
        (s.len() <= 9 && s.bytes().all(|c| c.is_ascii_digit()) && !s.starts_with('0'))
            .then(|| s.parse::<u32>().ok())
            .flatten()
    };
    let (first, last) = match lines.split_once('-') {
        Some((a, b)) => (number(a), number(b)),
        None => (number(lines), number(lines)),
    };
    let (Some(first), Some(last)) = (first, last) else {
        return Err(shape());
    };
    if last < first || last - first >= 200 {
        return Err(shape());
    }
    let what = "--guard's file";
    let r = confine::rel(what, OsStr::new(file), false)?;
    match confine::check(wt, &r, what)? {
        Kind::File => {}
        _ => {
            return Err(refuse(format!(
                "{what} is not an existing regular file: {}",
                r.shown()
            )))
        }
    }
    let text = confine::read_file(&r)
        .map_err(|e| refuse(format!("{what} cannot be read ({e}): {}", r.shown())))?;
    let hash = mem::guard_hash(&text, first, last)
        .map_err(|e| refuse(format!("--guard {e}: {}", shown(v.as_bytes()))))?;
    Ok(Some(mem::Guard {
        file: String::from_utf8_lossy(&r.raw).into_owned(),
        first,
        last,
        hash,
    }))
}

/// A subcommand with every value it takes checked.
enum Action {
    Init,
    PutFinding {
        signature: String,
        root_cause: String,
        title: String,
        severity: i64,
        commit: Option<String>,
        audit_n: Option<String>,
        file: Option<String>,
        line: Option<i64>,
        verdict: Option<String>,
    },
    SetStatus {
        signature: String,
        root_cause: String,
        status: String,
    },
    Rule {
        signature: String,
        ruling: String,
        rationale: String,
        by: String,
        scope: Option<String>,
        commit: Option<String>,
        guard: Option<mem::Guard>,
    },
    Check {
        signature: String,
        commit: Option<String>,
    },
    Regressions,
    Warm,
    Profile {
        protocol_class: Option<String>,
        trust_assumptions_json: Option<String>,
        oracle_set: Option<String>,
        admin_set: Option<String>,
        notes: Option<String>,
    },
    Invariant {
        statement: String,
        protocol_class: Option<String>,
        source_fn: Option<String>,
        cited_line: Option<String>,
        status: Option<String>,
    },
}

/// Checks every value of the call, before the store is looked at.
fn action(wt: &Path, call: &Call) -> Result<Action, Stop> {
    Ok(match call.sub {
        Sub::Init => Action::Init,
        Sub::PutFinding => Action::PutFinding {
            signature: call.need("signature")?,
            root_cause: call.need("root-cause")?,
            title: call.need("title")?,
            severity: call
                .number("severity", 1..=10)?
                .ok_or_else(|| refuse("put-finding needs --severity".into()))?,
            commit: call.text("commit")?,
            audit_n: call.text("audit-n")?,
            file: call.text("file")?,
            line: call.number("line", 1..=999_999_999)?,
            verdict: call.text("verdict")?,
        },
        Sub::SetStatus => Action::SetStatus {
            signature: call.need("signature")?,
            root_cause: call.need("root-cause")?,
            status: call.word("status", &["FIXED", "OPEN", "ACKNOWLEDGED", "DISPUTED"])?,
        },
        Sub::Rule => {
            let signature = call.need("signature")?;
            let ruling = call.word("ruling", &["FALSE_POSITIVE", "ACCEPTED_RISK"])?;
            let rationale = call.need("rationale")?;
            let by = call.need("by")?;
            let scope = call.text("scope")?;
            let commit = call.commit()?;
            let guard = guard(wt, call)?;
            if ruling == "FALSE_POSITIVE" && guard.is_none() {
                return Err(refuse(
                    "a FALSE_POSITIVE ruling needs --guard, the <file>:<line> or \
                     <file>:<first>-<last> that makes it one, so that check can tell when it \
                     goes stale"
                        .into(),
                ));
            }
            Action::Rule {
                signature,
                ruling,
                rationale,
                by,
                scope,
                commit,
                guard,
            }
        }
        Sub::Check => Action::Check {
            signature: call.need("signature")?,
            commit: call.commit()?,
        },
        Sub::Regressions => Action::Regressions,
        Sub::Warm => Action::Warm,
        Sub::Profile => {
            let trust_assumptions_json = call.text("trust-assumptions-json")?;
            if let Some(json) = &trust_assumptions_json {
                if serde_json::from_str::<serde_json::Value>(json).is_err() {
                    return Err(refuse("--trust-assumptions-json is not JSON".into()));
                }
            }
            Action::Profile {
                protocol_class: call.text("protocol-class")?,
                trust_assumptions_json,
                oracle_set: call.text("oracle-set")?,
                admin_set: call.text("admin-set")?,
                notes: call.text("notes")?,
            }
        }
        Sub::Invariant => Action::Invariant {
            statement: call.need("statement")?,
            protocol_class: call.text("protocol-class")?,
            source_fn: call.text("source-fn")?,
            cited_line: call.text("cited-line")?,
            status: call.text("status")?,
        },
    })
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), Stop> {
    let json = serde_json::to_string(value).map_err(|e| Stop(2, format!("error: {e}")))?;
    out(&confine::json_text(json))
}

fn out(line: &str) -> Result<(), Stop> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|e| {
            Stop(
                2,
                format!("error: cannot write the answer: {}", os_message(&e)),
            )
        })
}

/// `warm`, `check` and `regressions`: the store opened read-only, or the empty
/// answer when there is none.
fn read(wt: &Path, store: &Store, pid: &str, action: &Action) -> Result<ExitCode, Stop> {
    if store.db == Db::Empty {
        return Err(refuse(format!(
            "{} is empty; audit-mem init makes the store",
            store.shown()
        )));
    }
    let failed = store_error(store);
    let conn = match store.db {
        Db::Sqlite => Some(mem::open_read_only(store.path()).map_err(&failed)?),
        _ => None,
    };
    match (action, conn) {
        (Action::Warm, None) => print_json(&mem::WarmContext::default())?,
        (Action::Warm, Some(c)) => print_json(&mem::warm(&c, pid).map_err(&failed)?)?,
        (Action::Regressions, None) => out("[]")?,
        (Action::Regressions, Some(c)) => print_json(&mem::regressions(&c, pid).map_err(&failed)?)?,
        (Action::Check { .. }, None) => {
            out(r#"{"suppressed":false,"store":"absent"}"#)?;
            return Ok(ExitCode::FAILURE);
        }
        (Action::Check { signature, commit }, Some(c)) => {
            let read = |file: &str| guard_text(wt, file);
            let result =
                mem::check(&c, pid, signature, commit.as_deref(), &read).map_err(&failed)?;
            print_json(&result)?;
            if !result.suppressed {
                return Ok(ExitCode::FAILURE);
            }
        }
        _ => return Err(refuse("this subcommand does not read the store".into())),
    }
    Ok(ExitCode::SUCCESS)
}

/// The subcommands that write: `init` makes the store when it is missing; the
/// others write only a store `init` made. Returns the line to print.
fn write(wt: &Path, store: &Store, pid: &str, action: Action) -> Result<String, Stop> {
    if matches!(action, Action::Init) {
        make_store(wt, store)?;
    } else if store.db != Db::Sqlite {
        return Err(refuse(format!(
            "there is no store at {}; audit-mem init makes it",
            store.shown()
        )));
    }
    let failed = store_error(store);
    let conn: Connection = mem::open_read_write(store.path()).map_err(&failed)?;
    Ok(match action {
        Action::PutFinding {
            signature,
            root_cause,
            title,
            severity,
            commit,
            audit_n,
            file,
            line,
            verdict,
        } => {
            let outcome = mem::put_finding(
                &conn,
                &mem::PutFinding {
                    program_id: pid,
                    signature: &signature,
                    root_cause: &root_cause,
                    title: &title,
                    severity,
                    commit: commit.as_deref(),
                    audit_n: audit_n.as_deref(),
                    file: file.as_deref(),
                    line,
                    verdict: verdict.as_deref(),
                },
            )
            .map_err(&failed)?;
            if outcome.regressed {
                format!("REGRESSED {}", outcome.finding_id)
            } else {
                format!("{} {}", outcome.status, outcome.finding_id)
            }
        }
        Action::SetStatus {
            signature,
            root_cause,
            status,
        } => {
            let changed =
                mem::set_status(&conn, pid, &signature, &root_cause, &status).map_err(&failed)?;
            format!("updated {} row(s) -> {}", changed, status)
        }
        Action::Rule {
            signature,
            ruling,
            rationale,
            by,
            scope,
            commit,
            guard,
        } => {
            let id = mem::add_ruling(
                &conn,
                &mem::NewRuling {
                    program_id: pid,
                    signature: &signature,
                    ruling: &ruling,
                    rationale: &rationale,
                    by: &by,
                    scope: scope.as_deref(),
                    commit: commit.as_deref(),
                    guard: guard.as_ref(),
                },
            )
            .map_err(&failed)?;
            format!("ruling {} recorded ({})", id, ruling)
        }
        Action::Profile {
            protocol_class,
            trust_assumptions_json,
            oracle_set,
            admin_set,
            notes,
        } => {
            mem::put_profile(
                &conn,
                pid,
                &mem::ProfileFields {
                    protocol_class: protocol_class.as_deref(),
                    trust_assumptions_json: trust_assumptions_json.as_deref(),
                    oracle_set: oracle_set.as_deref(),
                    admin_set: admin_set.as_deref(),
                    notes: notes.as_deref(),
                },
            )
            .map_err(&failed)?;
            format!("profile {} recorded", pid)
        }
        Action::Invariant {
            statement,
            protocol_class,
            source_fn,
            cited_line,
            status,
        } => {
            let (id, new) = mem::put_invariant(
                &conn,
                pid,
                &statement,
                &mem::InvariantFields {
                    protocol_class: protocol_class.as_deref(),
                    source_fn: source_fn.as_deref(),
                    cited_line: cited_line.as_deref(),
                    status: status.as_deref(),
                },
            )
            .map_err(&failed)?;
            format!(
                "invariant {} {}",
                id,
                if new { "recorded" } else { "updated" }
            )
        }
        Action::Init => format!("initialized {}", store.shown()),
        Action::Check { .. } | Action::Regressions | Action::Warm => {
            return Err(refuse("this subcommand does not write the store".into()))
        }
    })
}

fn run(args: &[OsString]) -> Result<ExitCode, Stop> {
    let wt = confine::working_tree()?;
    confine::self_check(&wt)?;
    let call = parse(args)?;
    let pid = match call.sub {
        Sub::Init => String::new(),
        _ => call.need("program-id")?,
    };
    let action = action(&wt, &call)?;
    let store = check_store(&wt, &call.db)?;
    if call.sub.reads_only() {
        return read(&wt, &store, &pid, &action);
    }
    out(&write(&wt, &store, &pid, action)?)?;
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    // SAFETY: umask only sets this process's file-mode mask.
    unsafe {
        libc::umask(0o077);
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(Stop(code, message)) => {
            eprintln!("audit-mem: {message}");
            ExitCode::from(code)
        }
    }
}
