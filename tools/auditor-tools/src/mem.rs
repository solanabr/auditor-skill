//! Cross-audit findings memory backed by SQLite (bundled `rusqlite`).
//!
//! Provides exact-dedup of findings, regression detection (a `FIXED` finding
//! re-observed becomes `REGRESSED`), false-positive suppression rulings anchored
//! to the commit and the guard lines they cite, the protocol profile and
//! invariants of a program, and a warm-start context block for re-audits.
//!
//! A store is opened only when it exists: read-only for the subcommands that read
//! it ([`open_read_only`]), for reading and writing for the ones that write it
//! ([`open_read_write`]). Either way it must hold only the tables audit-mem makes,
//! and SQLite runs in its defensive mode, with triggers and views off and
//! `trusted_schema` off, so a crafted store cannot run anything through its
//! schema.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::confine::shown;

/// The tables of a store, as `ensure_schema` makes them.
pub const TABLES: [&str; 5] = [
    "findings",
    "occurrences",
    "fp_rulings",
    "invariants",
    "protocol_profile",
];

/// The columns that anchor a ruling, added to `fp_rulings` by `ensure_schema`
/// when a store made before them is next written.
const ANCHOR_COLUMNS: [(&str, &str); 5] = [
    ("anchor_commit", "TEXT"),
    ("guard_file", "TEXT"),
    ("guard_line", "INTEGER"),
    ("guard_end", "INTEGER"),
    ("guard_hash", "TEXT"),
];

/// A store audit-mem refuses to use: not one it wrote, or one its schema check
/// refuses. The CLI prints it as a refusal.
#[derive(Debug)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

fn refusal(why: String) -> anyhow::Error {
    anyhow::Error::new(Refusal(why))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

/// Compute the stable finding id: `sha256(program_id \n code_signature \n root_cause)`.
pub fn finding_id(program_id: &str, code_signature: &str, root_cause: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(program_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(code_signature.as_bytes());
    hasher.update(b"\n");
    hasher.update(root_cause.as_bytes());
    hex(&hasher.finalize())
}

/// Current unix timestamp (seconds) as a string. Fine in a compiled binary.
fn now_ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs.to_string()
}

/// SQLite's defensive mode, with triggers, views and `trusted_schema` off and
/// temporary tables in memory: what a store's schema holds can run nothing, and
/// no file is made outside the store.
fn harden(conn: &Connection) -> Result<()> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    conn.execute_batch(
        "PRAGMA trusted_schema = OFF; PRAGMA temp_store = MEMORY; PRAGMA cell_size_check = ON;",
    )?;
    Ok(())
}

/// Refuses a store holding anything but audit-mem's tables, their automatic
/// indexes and `sqlite_sequence`: a view, a trigger, a virtual table, an index of
/// its own or another table. Returns the tables of audit-mem's it holds.
fn verify_schema(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut tables = Vec::new();
    for row in rows {
        let (kind, name, table, sql) = row?;
        let ours = TABLES.contains(&table.as_str());
        let plain_table = sql.as_deref().is_some_and(|s| {
            s.get(..13)
                .is_some_and(|head| head.eq_ignore_ascii_case("CREATE TABLE "))
        });
        let ok = match kind.as_str() {
            "table" => (ours && name == table && plain_table) || name == "sqlite_sequence",
            "index" => ours && name.starts_with("sqlite_autoindex_") && sql.is_none(),
            _ => false,
        };
        if !ok {
            return Err(refusal(format!(
                "it holds the {} {}, which audit-mem never makes, so it is not a store audit-mem wrote",
                shown(kind.as_bytes()),
                shown(name.as_bytes())
            )));
        }
        if kind == "table" && ours {
            tables.push(name);
        }
    }
    Ok(tables)
}

/// Opens a store that exists for reading only: read-only, through no symbolic
/// link, never made or written (`query_only`), hardened as `harden` does. It is
/// opened as immutable (`file:<path>?mode=ro&immutable=1`), so SQLite takes no
/// lock and opens no `-wal`, `-shm` or `-journal` file beside it. It must hold
/// every table of audit-mem's and nothing else. `path` is relative, of the
/// letters, digits and `._/-` that a store's path holds.
pub fn open_read_only(path: &Path) -> Result<Connection> {
    let name = path
        .to_str()
        .filter(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
        })
        .ok_or_else(|| refusal("its path cannot be written as a SQLite URI".to_string()))?;
    let conn = Connection::open_with_flags(
        format!("file:{name}?mode=ro&immutable=1"),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    harden(&conn)?;
    conn.execute_batch("PRAGMA query_only = ON;")?;
    let tables = verify_schema(&conn)?;
    for table in TABLES {
        if !tables.iter().any(|t| t == table) {
            return Err(refusal(format!(
                "it has no {table} table, so it is not a store audit-mem wrote; audit-mem init makes the tables"
            )));
        }
    }
    Ok(conn)
}

/// Opens a store that exists for reading and writing, through no symbolic link
/// and never making the file, hardened as `harden` does; it must hold nothing but
/// audit-mem's tables, and gets every table and column it lacks
/// (`ensure_schema`).
pub fn open_read_write(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    harden(&conn)?;
    verify_schema(&conn)?;
    ensure_schema(&conn)?;
    Ok(conn)
}

/// Open an in-memory database with the schema applied (used by tests).
pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    harden(&conn)?;
    ensure_schema(&conn)?;
    Ok(conn)
}

/// The columns `fp_rulings` has.
fn ruling_columns(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_info('fp_rulings')")?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(names)
}

/// Create all tables if they do not already exist, and add the anchor columns to
/// an `fp_rulings` made before them (its rulings then have no anchor). Safe to
/// call repeatedly; one transaction.
pub fn ensure_schema(conn: &Connection) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        r#"
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
            scope          TEXT,
            anchor_commit  TEXT,
            guard_file     TEXT,
            guard_line     INTEGER,
            guard_end      INTEGER,
            guard_hash     TEXT
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
        "#,
    )?;
    let have = ruling_columns(&tx)?;
    for (column, kind) in ANCHOR_COLUMNS {
        if !have.iter().any(|c| c == column) {
            tx.execute_batch(&format!(
                "ALTER TABLE fp_rulings ADD COLUMN {column} {kind};"
            ))?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Arguments for [`put_finding`].
pub struct PutFinding<'a> {
    pub program_id: &'a str,
    pub signature: &'a str,
    pub root_cause: &'a str,
    pub title: &'a str,
    pub severity: i64,
    pub commit: Option<&'a str>,
    pub audit_n: Option<&'a str>,
    pub file: Option<&'a str>,
    pub line: Option<i64>,
    pub verdict: Option<&'a str>,
}

/// Outcome of a [`put_finding`] call, for the CLI to report.
pub struct PutOutcome {
    pub finding_id: String,
    pub status: String,
    pub regressed: bool,
}

/// Upsert a finding and append an occurrence.
///
/// Regression rule: if the finding already existed with status `FIXED` and this
/// call re-observes it, the status transitions to `REGRESSED`. Brand-new
/// findings start `OPEN`.
pub fn put_finding(conn: &Connection, f: &PutFinding) -> Result<PutOutcome> {
    let id = finding_id(f.program_id, f.signature, f.root_cause);
    let commit = f.commit.unwrap_or("");
    let audit_n = f.audit_n.unwrap_or("");

    let existing_status: Option<String> = conn
        .query_row(
            "SELECT status FROM findings WHERE finding_id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()?;

    let (new_status, regressed) = match existing_status.as_deref() {
        None => ("OPEN".to_string(), false),
        Some("FIXED") => ("REGRESSED".to_string(), true),
        Some(other) => (other.to_string(), false),
    };

    if existing_status.is_none() {
        conn.execute(
            "INSERT INTO findings (finding_id, program_id, first_seen_commit, last_seen_commit, \
             severity, root_cause, code_signature, title, status, first_audit_n, last_audit_n) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                f.program_id,
                commit,
                commit,
                f.severity,
                f.root_cause,
                f.signature,
                f.title,
                new_status,
                audit_n,
                audit_n,
            ],
        )?;
    } else {
        conn.execute(
            "UPDATE findings SET last_seen_commit = ?2, last_audit_n = ?3, status = ?4, \
             severity = ?5, title = ?6 WHERE finding_id = ?1",
            params![id, commit, audit_n, new_status, f.severity, f.title],
        )?;
    }

    conn.execute(
        "INSERT INTO occurrences (finding_id, audit_n, commit_sha, file, line, verdict, rule5b_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            audit_n,
            commit,
            f.file.unwrap_or(""),
            f.line,
            f.verdict.unwrap_or(""),
            "",
        ],
    )?;

    Ok(PutOutcome {
        finding_id: id,
        status: new_status,
        regressed,
    })
}

/// Update the status of a finding identified by (program_id, signature, root_cause).
/// Returns the number of rows changed.
pub fn set_status(
    conn: &Connection,
    program_id: &str,
    signature: &str,
    root_cause: &str,
    status: &str,
) -> Result<usize> {
    let id = finding_id(program_id, signature, root_cause);
    let changed = conn.execute(
        "UPDATE findings SET status = ?2 WHERE finding_id = ?1",
        params![id, status],
    )?;
    Ok(changed)
}

/// The guard a ruling cites: a file relative to the working directory and a
/// range of its lines (1-based, inclusive), with the sha256 of those lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guard {
    pub file: String,
    pub first: u32,
    pub last: u32,
    pub hash: String,
}

impl Guard {
    /// `file:line`, or `file:first-last`.
    pub fn label(&self) -> String {
        guard_label(&self.file, i64::from(self.first), i64::from(self.last))
    }
}

fn guard_label(file: &str, first: i64, last: i64) -> String {
    if first == last {
        format!("{file}:{first}")
    } else {
        format!("{file}:{first}-{last}")
    }
}

/// The sha256 (hex) of lines `first..=last` of `text`, each with the newline that
/// ends it, as a ruling's anchor records them; `Err` says why they cannot be read.
pub fn guard_hash(text: &[u8], first: u32, last: u32) -> std::result::Result<String, String> {
    if first == 0 || last < first {
        return Err("is not a range of lines".to_string());
    }
    let lines: Vec<&[u8]> = text.split_inclusive(|&b| b == b'\n').collect();
    if last as usize > lines.len() {
        return Err(format!(
            "names line {last}, and the file has {} line(s)",
            lines.len()
        ));
    }
    let mut hasher = Sha256::new();
    for line in &lines[first as usize - 1..last as usize] {
        hasher.update(line);
    }
    Ok(hex(&hasher.finalize()))
}

/// Arguments for [`add_ruling`].
pub struct NewRuling<'a> {
    pub program_id: &'a str,
    pub signature: &'a str,
    pub ruling: &'a str,
    pub rationale: &'a str,
    pub by: &'a str,
    pub scope: Option<&'a str>,
    /// The commit the ruling is made at.
    pub commit: Option<&'a str>,
    /// The guard it cites, hashed as `guard_hash` hashes it.
    pub guard: Option<&'a Guard>,
}

/// Insert a false-positive / accepted-risk ruling with a timestamp and its
/// anchor: the commit, and the guard's file, lines and hash.
pub fn add_ruling(conn: &Connection, r: &NewRuling) -> Result<i64> {
    conn.execute(
        "INSERT INTO fp_rulings (program_id, code_signature, ruling, rationale, ruled_by, ruled_at, scope, \
         anchor_commit, guard_file, guard_line, guard_end, guard_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            r.program_id,
            r.signature,
            r.ruling,
            r.rationale,
            r.by,
            now_ts(),
            r.scope.unwrap_or("program"),
            r.commit,
            r.guard.map(|g| g.file.as_str()),
            r.guard.map(|g| g.first),
            r.guard.map(|g| g.last),
            r.guard.map(|g| g.hash.as_str()),
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Result of a suppression [`check`]: suppressed only by a `FALSE_POSITIVE`
/// ruling whose anchor still holds. A ruling whose anchor changed, or that has
/// none, is `stale`, with the reasons, and suppresses nothing.
#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<String>,
    pub ruling: Option<RulingRow>,
}

#[derive(Debug, Serialize)]
pub struct RulingRow {
    pub ruling_id: i64,
    pub program_id: String,
    pub code_signature: String,
    pub ruling: String,
    pub rationale: String,
    pub ruled_by: String,
    pub ruled_at: String,
    pub scope: String,
    /// The commit the ruling was made at.
    pub commit: Option<String>,
    /// The guard it cites, `file:line` or `file:first-last`.
    pub guard: Option<String>,
    /// The sha256 of the guard's lines when it was made.
    pub guard_hash: Option<String>,
    #[serde(skip)]
    anchor: Option<(String, i64, i64)>,
}

/// The rulings of `fp_rulings` matching `filter` (an SQL condition on
/// `program_id = ?1`, and `code_signature = ?2` when `signature` is given),
/// newest first. A store made before the anchor columns reads as rulings with no
/// anchor.
fn rulings(
    conn: &Connection,
    filter: &str,
    program_id: &str,
    signature: Option<&str>,
    limit: Option<u32>,
) -> Result<Vec<RulingRow>> {
    let anchored = {
        let have = ruling_columns(conn)?;
        ANCHOR_COLUMNS
            .iter()
            .all(|(column, _)| have.iter().any(|c| c == column))
    };
    let anchor = if anchored {
        "anchor_commit, guard_file, guard_line, guard_end, guard_hash"
    } else {
        "NULL, NULL, NULL, NULL, NULL"
    };
    let sql = format!(
        "SELECT ruling_id, program_id, code_signature, ruling, rationale, ruled_by, ruled_at, scope, {anchor} \
         FROM fp_rulings WHERE {filter} ORDER BY ruling_id DESC{}",
        limit.map(|n| format!(" LIMIT {n}")).unwrap_or_default()
    );
    let mut stmt = conn.prepare(&sql)?;
    let map = |r: &rusqlite::Row| {
        let file: Option<String> = r.get(9)?;
        let first: Option<i64> = r.get(10)?;
        let last: Option<i64> = r.get(11)?;
        let anchor = match (file, first, last) {
            (Some(f), Some(a), Some(b)) => Some((f, a, b)),
            _ => None,
        };
        Ok(RulingRow {
            ruling_id: r.get(0)?,
            program_id: r.get(1)?,
            code_signature: r.get(2)?,
            ruling: r.get(3)?,
            rationale: r.get(4)?,
            ruled_by: r.get(5)?,
            ruled_at: r.get(6)?,
            scope: r.get(7)?,
            commit: r.get(8)?,
            guard: anchor.as_ref().map(|(f, a, b)| guard_label(f, *a, *b)),
            guard_hash: r.get(12)?,
            anchor,
        })
    };
    let rows = match signature {
        Some(sig) => stmt.query_map(params![program_id, sig], map)?,
        None => stmt.query_map(params![program_id], map)?,
    }
    .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Two commit ids name the same commit when one is a prefix of the other (both
/// are 7 to 64 lowercase hexadecimal digits, as the CLI takes them).
fn same_commit(a: &str, b: &str) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Why a ruling's anchor no longer holds, given the commit the check is made at
/// and a reader of a guard file's current text; empty when it holds. A ruling
/// with no guard has no anchor.
pub fn staleness(
    r: &RulingRow,
    commit: Option<&str>,
    read: &dyn Fn(&str) -> std::result::Result<Vec<u8>, String>,
) -> Vec<String> {
    let (Some((file, first, last)), Some(hash)) = (&r.anchor, &r.guard_hash) else {
        return vec!["no anchor".to_string()];
    };
    let mut why = Vec::new();
    match (r.commit.as_deref(), commit) {
        (None, None) => {}
        (Some(was), Some(now)) if same_commit(was, now) => {}
        (Some(was), None) => why.push(format!(
            "ruled at commit {}, and no --commit was given to compare",
            shown(was.as_bytes())
        )),
        (None, Some(now)) => why.push(format!("ruled with no commit, checked at {now}")),
        (Some(was), Some(now)) => why.push(format!(
            "ruled at commit {}, checked at {now}",
            shown(was.as_bytes())
        )),
    }
    let label = shown(guard_label(file, *first, *last).as_bytes());
    let (Ok(first), Ok(last)) = (u32::try_from(*first), u32::try_from(*last)) else {
        why.push(format!("the guard at {label} is not a range of lines"));
        return why;
    };
    match read(file).and_then(|text| guard_hash(&text, first, last)) {
        Ok(now) if &now == hash => {}
        Ok(_) => why.push(format!(
            "the guard at {label} no longer holds the lines ruled on"
        )),
        Err(e) => why.push(format!("the guard at {label} cannot be read: {e}")),
    }
    why
}

/// Check whether a (program_id, signature) pair is suppressed: by its most
/// recent `FALSE_POSITIVE` ruling, when that ruling's anchor holds at `commit`
/// (`staleness`, with `read` reading the guard's file). A stale ruling is
/// returned with the reasons, unsuppressed.
pub fn check(
    conn: &Connection,
    program_id: &str,
    signature: &str,
    commit: Option<&str>,
    read: &dyn Fn(&str) -> std::result::Result<Vec<u8>, String>,
) -> Result<CheckResult> {
    let row = rulings(
        conn,
        "program_id = ?1 AND code_signature = ?2 AND ruling = 'FALSE_POSITIVE'",
        program_id,
        Some(signature),
        Some(1),
    )?
    .into_iter()
    .next();
    let Some(row) = row else {
        return Ok(CheckResult {
            suppressed: false,
            stale: None,
            ruling: None,
        });
    };
    let why = staleness(&row, commit, read);
    Ok(CheckResult {
        suppressed: why.is_empty(),
        stale: (!why.is_empty()).then(|| why.join("; ")),
        ruling: Some(row),
    })
}

#[derive(Debug, Serialize)]
pub struct FindingRow {
    pub finding_id: String,
    pub program_id: String,
    pub severity: i64,
    pub root_cause: String,
    pub code_signature: String,
    pub title: String,
    pub status: String,
}

/// List findings for a program whose status is `REGRESSED`.
pub fn regressions(conn: &Connection, program_id: &str) -> Result<Vec<FindingRow>> {
    let mut stmt = conn.prepare(
        "SELECT finding_id, program_id, severity, root_cause, code_signature, title, status \
         FROM findings WHERE program_id = ?1 AND status = 'REGRESSED' ORDER BY severity DESC",
    )?;
    let rows = stmt
        .query_map(params![program_id], |r| {
            Ok(FindingRow {
                finding_id: r.get(0)?,
                program_id: r.get(1)?,
                severity: r.get(2)?,
                root_cause: r.get(3)?,
                code_signature: r.get(4)?,
                title: r.get(5)?,
                status: r.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[derive(Debug, Serialize)]
pub struct ProtocolProfile {
    pub program_id: String,
    pub protocol_class: String,
    pub trust_assumptions_json: String,
    pub oracle_set: String,
    pub admin_set: String,
    pub notes: String,
}

/// The fields [`put_profile`] sets; `None` keeps what the profile holds.
#[derive(Default)]
pub struct ProfileFields<'a> {
    pub protocol_class: Option<&'a str>,
    pub trust_assumptions_json: Option<&'a str>,
    pub oracle_set: Option<&'a str>,
    pub admin_set: Option<&'a str>,
    pub notes: Option<&'a str>,
}

/// Record a program's protocol profile: a new profile takes the fields given and
/// empty text for the rest; an existing one takes the fields given and keeps the
/// others. One transaction.
pub fn put_profile(conn: &Connection, program_id: &str, f: &ProfileFields) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT OR IGNORE INTO protocol_profile (program_id, protocol_class, trust_assumptions_json, \
         oracle_set, admin_set, notes) VALUES (?1, '', '', '', '', '')",
        params![program_id],
    )?;
    tx.execute(
        "UPDATE protocol_profile SET protocol_class = COALESCE(?2, protocol_class), \
         trust_assumptions_json = COALESCE(?3, trust_assumptions_json), \
         oracle_set = COALESCE(?4, oracle_set), admin_set = COALESCE(?5, admin_set), \
         notes = COALESCE(?6, notes) WHERE program_id = ?1",
        params![
            program_id,
            f.protocol_class,
            f.trust_assumptions_json,
            f.oracle_set,
            f.admin_set,
            f.notes
        ],
    )?;
    tx.commit()?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct InvariantRow {
    pub inv_id: i64,
    pub program_id: String,
    pub protocol_class: String,
    pub statement: String,
    pub source_fn: String,
    pub cited_line: String,
    pub status: String,
}

/// The fields [`put_invariant`] sets besides the statement; `None` keeps what an
/// existing invariant holds.
#[derive(Default)]
pub struct InvariantFields<'a> {
    pub protocol_class: Option<&'a str>,
    pub source_fn: Option<&'a str>,
    pub cited_line: Option<&'a str>,
    pub status: Option<&'a str>,
}

/// Record an invariant of a program: one per (program_id, statement). A new one
/// takes the fields given and empty text for the rest; recording the same
/// statement again updates the fields given. Returns its id, and whether it is
/// new. One transaction.
pub fn put_invariant(
    conn: &Connection,
    program_id: &str,
    statement: &str,
    f: &InvariantFields,
) -> Result<(i64, bool)> {
    let tx = conn.unchecked_transaction()?;
    let existing: Option<i64> = tx
        .query_row(
            "SELECT inv_id FROM invariants WHERE program_id = ?1 AND statement = ?2 \
             ORDER BY inv_id LIMIT 1",
            params![program_id, statement],
            |r| r.get(0),
        )
        .optional()?;
    let outcome = match existing {
        Some(id) => {
            tx.execute(
                "UPDATE invariants SET protocol_class = COALESCE(?2, protocol_class), \
                 source_fn = COALESCE(?3, source_fn), cited_line = COALESCE(?4, cited_line), \
                 status = COALESCE(?5, status) WHERE inv_id = ?1",
                params![id, f.protocol_class, f.source_fn, f.cited_line, f.status],
            )?;
            (id, false)
        }
        None => {
            tx.execute(
                "INSERT INTO invariants (program_id, protocol_class, statement, source_fn, cited_line, status) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    program_id,
                    f.protocol_class.unwrap_or(""),
                    statement,
                    f.source_fn.unwrap_or(""),
                    f.cited_line.unwrap_or(""),
                    f.status.unwrap_or(""),
                ],
            )?;
            (tx.last_insert_rowid(), true)
        }
    };
    tx.commit()?;
    Ok(outcome)
}

/// The warm-start context block returned for a re-audit.
#[derive(Debug, Serialize, Default)]
pub struct WarmContext {
    pub profile: Option<ProtocolProfile>,
    pub invariants: Vec<InvariantRow>,
    pub open_fp_rulings: Vec<RulingRow>,
}

/// Assemble the warm-start context for `program_id`: its protocol profile,
/// recorded invariants, and any standing false-positive/accepted-risk rulings,
/// each with its anchor.
pub fn warm(conn: &Connection, program_id: &str) -> Result<WarmContext> {
    let profile = conn
        .query_row(
            "SELECT program_id, protocol_class, trust_assumptions_json, oracle_set, admin_set, notes \
             FROM protocol_profile WHERE program_id = ?1",
            params![program_id],
            |r| {
                Ok(ProtocolProfile {
                    program_id: r.get(0)?,
                    protocol_class: r.get(1)?,
                    trust_assumptions_json: r.get(2)?,
                    oracle_set: r.get(3)?,
                    admin_set: r.get(4)?,
                    notes: r.get(5)?,
                })
            },
        )
        .optional()?;

    let mut inv_stmt = conn.prepare(
        "SELECT inv_id, program_id, protocol_class, statement, source_fn, cited_line, status \
         FROM invariants WHERE program_id = ?1 ORDER BY inv_id",
    )?;
    let invariants = inv_stmt
        .query_map(params![program_id], |r| {
            Ok(InvariantRow {
                inv_id: r.get(0)?,
                program_id: r.get(1)?,
                protocol_class: r.get(2)?,
                statement: r.get(3)?,
                source_fn: r.get(4)?,
                cited_line: r.get(5)?,
                status: r.get(6)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let open_fp_rulings = rulings(conn, "program_id = ?1", program_id, None, None)?;

    Ok(WarmContext {
        profile,
        invariants,
        open_fp_rulings,
    })
}
