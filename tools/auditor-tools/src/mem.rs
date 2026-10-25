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

/// Each table with the text `ensure_schema` makes it with, what follows `CREATE
/// TABLE IF NOT EXISTS `: SQLite keeps it as the table's `sql`, after `CREATE TABLE `.
/// The first five are the text audit-mem has made them with since its first
/// release, so a store made then reads as it did. `history` keeps each value
/// `profile`, `invariant` and `put-finding` replace; a store made before it gains
/// it when it is next written, and reads as having replaced none.
const SCHEMA: [(&str, &str); 6] = [
    (
        "findings",
        "findings (
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
        )",
    ),
    (
        "occurrences",
        "occurrences (
            finding_id TEXT,
            audit_n    TEXT,
            commit_sha TEXT,
            file       TEXT,
            line       INTEGER,
            verdict    TEXT,
            rule5b_json TEXT
        )",
    ),
    (
        "fp_rulings",
        "fp_rulings (
            ruling_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id     TEXT,
            code_signature TEXT,
            ruling         TEXT,
            rationale      TEXT,
            ruled_by       TEXT,
            ruled_at       TEXT,
            scope          TEXT
        )",
    ),
    (
        "invariants",
        "invariants (
            inv_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id     TEXT,
            protocol_class TEXT,
            statement      TEXT,
            source_fn      TEXT,
            cited_line     TEXT,
            status         TEXT
        )",
    ),
    (
        "protocol_profile",
        "protocol_profile (
            program_id            TEXT PRIMARY KEY,
            protocol_class        TEXT,
            trust_assumptions_json TEXT,
            oracle_set            TEXT,
            admin_set             TEXT,
            notes                 TEXT
        )",
    ),
    (
        "history",
        "history (
            history_id  INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id  TEXT,
            inv_id      INTEGER,
            finding_id  TEXT,
            field       TEXT,
            previous    TEXT,
            recorded_at TEXT
        )",
    ),
];

/// The most rows a list of `warm`'s or `regressions`' answer holds: the newest,
/// with `truncated` counting the rest.
const ROWS: u32 = 200;

/// The indexes SQLite makes for the tables' primary keys, by name and table.
const AUTO_INDEXES: [(&str, &str); 2] = [
    ("sqlite_autoindex_findings_1", "findings"),
    ("sqlite_autoindex_protocol_profile_1", "protocol_profile"),
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

/// The longest string or row SQLite reads or writes for audit-mem, in bytes: far
/// above what the writers store (4096 bytes a field), so only a crafted store
/// meets it.
const MAX_VALUE: i32 = 1 << 20;

/// SQLite's defensive mode, with triggers, views and `trusted_schema` off,
/// temporary tables in memory and values of at most `MAX_VALUE` bytes: what a
/// store's schema holds can run nothing, no file is made outside the store, and
/// no value it holds can flood the output.
fn harden(conn: &Connection) -> Result<()> {
    // SAFETY: the handle is this connection's own, open for the whole call.
    unsafe {
        rusqlite::ffi::sqlite3_limit(conn.handle(), rusqlite::ffi::SQLITE_LIMIT_LENGTH, MAX_VALUE);
    }
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    conn.execute_batch(
        "PRAGMA trusted_schema = OFF; PRAGMA temp_store = MEMORY; PRAGMA cell_size_check = ON;",
    )?;
    Ok(())
}

/// The `sql` SQLite keeps for a table of audit-mem's: the text `ensure_schema`
/// makes it with, and for `fp_rulings` that text with the anchor columns it adds
/// as `ALTER TABLE … ADD COLUMN` (SQLite writes each one before the closing
/// parenthesis), the form a store made since takes too. None for another table.
fn table_sql(name: &str) -> Option<Vec<String>> {
    let (_, text) = SCHEMA.iter().find(|(table, _)| *table == name)?;
    let made = format!("CREATE TABLE {text}");
    if name != "fp_rulings" {
        return Some(vec![made]);
    }
    let added: Vec<String> = ANCHOR_COLUMNS
        .iter()
        .map(|(column, kind)| format!("{column} {kind}"))
        .collect();
    let anchored = format!("{}, {})", made.strip_suffix(')')?, added.join(", "));
    Some(vec![made, anchored])
}

/// Refuses a store holding anything but audit-mem's tables as `ensure_schema`
/// makes them, the text of each `CREATE TABLE` exactly, the indexes SQLite makes
/// for their primary keys and `sqlite_sequence` as SQLite makes it: a table of
/// its name with another column, constraint, default or option, a view, a
/// trigger, a virtual table, an index of its own or another table. Returns the
/// tables of audit-mem's it holds.
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
        let forms = table_sql(&name);
        let ok = match kind.as_str() {
            "table" if name == "sqlite_sequence" => {
                table == name && sql.as_deref() == Some("CREATE TABLE sqlite_sequence(name,seq)")
            }
            "table" if forms.is_some() && name == table => {
                if !forms
                    .as_ref()
                    .is_some_and(|f| sql.as_ref().is_some_and(|s| f.contains(s)))
                {
                    return Err(refusal(format!(
                        "its {} table is not the one audit-mem makes, so it is not a store audit-mem wrote",
                        shown(name.as_bytes())
                    )));
                }
                true
            }
            "index" => AUTO_INDEXES.contains(&(name.as_str(), table.as_str())) && sql.is_none(),
            _ => false,
        };
        if !ok {
            return Err(refusal(format!(
                "it holds the {} {}, which audit-mem never makes, so it is not a store audit-mem wrote",
                shown(kind.as_bytes()),
                shown(name.as_bytes())
            )));
        }
        if kind == "table" && forms.is_some() {
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
/// audit-mem's tables. Each writer adds the tables and columns it lacks
/// (`migrate`) in the transaction it writes in, so a writer that fails or refuses
/// leaves the store as it was.
pub fn open_read_write(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    harden(&conn)?;
    verify_schema(&conn)?;
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
/// `fp_rulings` when it lacks them: a store made before them has rulings with no
/// anchor, and a new one is made the same way, so both read alike. Safe to call
/// repeatedly; one transaction.
pub fn ensure_schema(conn: &Connection) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    migrate(&tx)?;
    tx.commit()?;
    Ok(())
}

/// What `ensure_schema` does, in the transaction a writer writes in.
fn migrate(tx: &Connection) -> Result<()> {
    for (_, text) in SCHEMA {
        tx.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {text};"))?;
    }
    let have = ruling_columns(tx)?;
    for (column, kind) in ANCHOR_COLUMNS {
        if !have.iter().any(|c| c == column) {
            tx.execute_batch(&format!(
                "ALTER TABLE fp_rulings ADD COLUMN {column} {kind};"
            ))?;
        }
    }
    Ok(())
}

/// The statuses a finding can hold: the ones `set-status` takes, `OPEN` for a new
/// one and `REGRESSED` for a `FIXED` one seen again.
const STATUSES: [&str; 5] = ["OPEN", "FIXED", "ACKNOWLEDGED", "DISPUTED", "REGRESSED"];

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
/// findings start `OPEN`. A severity or a title it replaces is kept in `history`,
/// and `regressions` lists it under the finding's `changed`. A store holding a status audit-mem never sets is
/// refused (a `Refusal`), and is left as it was. One transaction.
pub fn put_finding(conn: &Connection, f: &PutFinding) -> Result<PutOutcome> {
    let id = finding_id(f.program_id, f.signature, f.root_cause);
    let commit = f.commit.unwrap_or("");
    let audit_n = f.audit_n.unwrap_or("");

    let tx = conn.unchecked_transaction()?;
    migrate(&tx)?;
    let existing: Option<(String, Option<i64>, Option<String>)> = tx
        .query_row(
            "SELECT status, severity, title FROM findings WHERE finding_id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;

    let (new_status, regressed) = match existing.as_ref().map(|e| e.0.as_str()) {
        None => ("OPEN".to_string(), false),
        Some("FIXED") => ("REGRESSED".to_string(), true),
        Some(kept) if STATUSES.contains(&kept) => (kept.to_string(), false),
        Some(other) => {
            return Err(refusal(format!(
                "it holds the status {} for this finding, which audit-mem never sets, so it is not a store audit-mem wrote",
                shown(other.as_bytes())
            )))
        }
    };

    if let Some((_, severity, title)) = existing {
        let given = f.severity.to_string();
        keep_replaced(
            &tx,
            f.program_id,
            Owner::Finding(&id),
            &[
                (
                    "severity",
                    Some(&given),
                    severity.map(|s| s.to_string()).unwrap_or_default(),
                ),
                ("title", Some(f.title), title.unwrap_or_default()),
            ],
        )?;
        tx.execute(
            "UPDATE findings SET last_seen_commit = ?2, last_audit_n = ?3, status = ?4, \
             severity = ?5, title = ?6 WHERE finding_id = ?1",
            params![id, commit, audit_n, new_status, f.severity, f.title],
        )?;
    } else {
        tx.execute(
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
    }

    tx.execute(
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
    tx.commit()?;

    Ok(PutOutcome {
        finding_id: id,
        status: new_status,
        regressed,
    })
}

/// Update the status of a finding identified by (program_id, signature, root_cause).
/// Returns the number of rows changed. One transaction.
pub fn set_status(
    conn: &Connection,
    program_id: &str,
    signature: &str,
    root_cause: &str,
    status: &str,
) -> Result<usize> {
    let id = finding_id(program_id, signature, root_cause);
    let tx = conn.unchecked_transaction()?;
    migrate(&tx)?;
    let changed = tx.execute(
        "UPDATE findings SET status = ?2 WHERE finding_id = ?1",
        params![id, status],
    )?;
    tx.commit()?;
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
/// anchor: the commit, and the guard's file, lines and hash. One transaction.
pub fn add_ruling(conn: &Connection, r: &NewRuling) -> Result<i64> {
    let tx = conn.unchecked_transaction()?;
    migrate(&tx)?;
    tx.execute(
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
    let id = tx.last_insert_rowid();
    tx.commit()?;
    Ok(id)
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

/// Why a ruling's anchor no longer holds, given the commit the check is made at
/// and a reader of a guard file's current text; empty when it holds. A ruling
/// with no guard has no anchor; one with no commit, or checked with none, or at
/// another commit (the full ids compared, as the CLI takes them), is stale.
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
        (Some(was), Some(now)) if was == now => {}
        (Some(was), Some(now)) => why.push(format!(
            "ruled at commit {}, checked at {now}",
            shown(was.as_bytes())
        )),
        (Some(was), None) => why.push(format!(
            "ruled at commit {}, and no --commit was given to compare",
            shown(was.as_bytes())
        )),
        (None, _) => why.push("ruled with no commit".to_string()),
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
    /// The severities and titles `put-finding` replaced, newest first.
    pub changed: Vec<Change>,
}

/// `regressions`' answer: of the findings of a program whose status is
/// `REGRESSED`, the `ROWS` seen most recently (by their newest occurrence), the
/// most severe first and the most recently seen first among equals, each with the
/// severities and titles replaced in it, and how many more rows there are.
#[derive(Debug, Serialize, Default)]
pub struct Regressions {
    pub regressions: Vec<FindingRow>,
    pub truncated: u64,
}

/// The findings of a program whose status is `REGRESSED`, as [`Regressions`].
pub fn regressions(conn: &Connection, program_id: &str) -> Result<Regressions> {
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM findings WHERE program_id = ?1 AND status = 'REGRESSED'",
        params![program_id],
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare(
        "SELECT finding_id, program_id, severity, root_cause, code_signature, title, status FROM \
         (SELECT f.finding_id, f.program_id, f.severity, f.root_cause, f.code_signature, f.title, \
         f.status, max(o.rowid) AS seen, f.rowid AS made \
         FROM findings f LEFT JOIN occurrences o ON o.finding_id = f.finding_id \
         WHERE f.program_id = ?1 AND f.status = 'REGRESSED' \
         GROUP BY f.rowid ORDER BY seen DESC, made DESC LIMIT ?2) \
         ORDER BY severity DESC, seen DESC, made DESC",
    )?;
    let rows = stmt
        .query_map(params![program_id, ROWS], |r| {
            Ok(FindingRow {
                finding_id: r.get(0)?,
                program_id: r.get(1)?,
                severity: r.get(2)?,
                root_cause: r.get(3)?,
                code_signature: r.get(4)?,
                title: r.get(5)?,
                status: r.get(6)?,
                changed: Vec::new(),
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut rows = rows;
    let mut truncated = left(total, rows.len());
    if has_history(conn)? {
        for row in &mut rows {
            let (changed, more) = changes(conn, program_id, Owner::Finding(&row.finding_id))?;
            row.changed = changed;
            truncated += more;
        }
    }
    Ok(Regressions {
        truncated,
        regressions: rows,
    })
}

/// How many of `total` rows a list of `shown` leaves out.
fn left(total: i64, shown: usize) -> u64 {
    u64::try_from(total)
        .unwrap_or(0)
        .saturating_sub(u64::try_from(shown).unwrap_or(u64::MAX))
}

/// A value `profile`, `invariant` or `put-finding` replaced: the field, what it
/// held, and when it was replaced (unix seconds, as `ruled_at`).
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct Change {
    pub field: String,
    pub previous: String,
    pub recorded_at: String,
}

/// Whether a store holds `history` (one made before it holds none until it is
/// next written).
fn has_history(conn: &Connection) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'history'",
        [],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Whose values a `history` row keeps: the program's profile, one of its
/// invariants, or one of its findings.
#[derive(Clone, Copy)]
enum Owner<'a> {
    Profile,
    Invariant(i64),
    Finding(&'a str),
}

impl Owner<'_> {
    /// The row's `inv_id` and `finding_id`.
    fn ids(self) -> (Option<i64>, Option<String>) {
        match self {
            Owner::Profile => (None, None),
            Owner::Invariant(id) => (Some(id), None),
            Owner::Finding(id) => (None, Some(id.to_string())),
        }
    }
}

/// The values replaced in one owner, newest first, at most `ROWS`, and how many
/// more there are.
fn changes(conn: &Connection, program_id: &str, owner: Owner) -> Result<(Vec<Change>, u64)> {
    let (inv_id, finding_id) = owner.ids();
    let total: i64 = conn.query_row(
        "SELECT count(*) FROM history WHERE program_id = ?1 AND inv_id IS ?2 AND finding_id IS ?3",
        params![program_id, inv_id, finding_id],
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare(
        "SELECT field, previous, recorded_at FROM history \
         WHERE program_id = ?1 AND inv_id IS ?2 AND finding_id IS ?3 \
         ORDER BY history_id DESC LIMIT ?4",
    )?;
    let text = |r: &rusqlite::Row, i: usize| -> rusqlite::Result<String> {
        Ok(r.get::<_, Option<String>>(i)?.unwrap_or_default())
    };
    let rows = stmt
        .query_map(params![program_id, inv_id, finding_id, ROWS], |r| {
            Ok(Change {
                field: text(r, 0)?,
                previous: text(r, 1)?,
                recorded_at: text(r, 2)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let more = left(total, rows.len());
    Ok((rows, more))
}

/// Keeps, in `history`, each value of `old` that `new` replaces in `owner`: a
/// field given (`Some`) whose recorded value is not empty and not the one given.
/// Returns the names of those fields.
fn keep_replaced(
    tx: &Connection,
    program_id: &str,
    owner: Owner,
    fields: &[(&'static str, Option<&str>, String)],
) -> Result<Vec<&'static str>> {
    let (inv_id, finding_id) = owner.ids();
    let now = now_ts();
    let mut replaced = Vec::new();
    for (field, new, old) in fields {
        let Some(new) = new else { continue };
        if old.is_empty() || old == new {
            continue;
        }
        tx.execute(
            "INSERT INTO history (program_id, inv_id, finding_id, field, previous, recorded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![program_id, inv_id, finding_id, field, old, now],
        )?;
        replaced.push(*field);
    }
    Ok(replaced)
}

#[derive(Debug, Serialize)]
pub struct ProtocolProfile {
    pub program_id: String,
    pub protocol_class: String,
    pub trust_assumptions_json: String,
    pub oracle_set: String,
    pub admin_set: String,
    pub notes: String,
    /// The values replaced since each field was first recorded, newest first.
    pub changed: Vec<Change>,
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
/// others, and each recorded value a field given replaces is kept in `history`,
/// so none is lost. Returns the fields replaced. One transaction.
pub fn put_profile(
    conn: &Connection,
    program_id: &str,
    f: &ProfileFields,
) -> Result<Vec<&'static str>> {
    let tx = conn.unchecked_transaction()?;
    migrate(&tx)?;
    let old: Option<[String; 5]> = tx
        .query_row(
            "SELECT protocol_class, trust_assumptions_json, oracle_set, admin_set, notes \
             FROM protocol_profile WHERE program_id = ?1",
            params![program_id],
            |r| {
                let text = |i: usize| -> rusqlite::Result<String> {
                    Ok(r.get::<_, Option<String>>(i)?.unwrap_or_default())
                };
                Ok([text(0)?, text(1)?, text(2)?, text(3)?, text(4)?])
            },
        )
        .optional()?;
    let replaced = match old {
        Some([class, trust, oracles, admins, notes]) => keep_replaced(
            &tx,
            program_id,
            Owner::Profile,
            &[
                ("protocol_class", f.protocol_class, class),
                ("trust_assumptions_json", f.trust_assumptions_json, trust),
                ("oracle_set", f.oracle_set, oracles),
                ("admin_set", f.admin_set, admins),
                ("notes", f.notes, notes),
            ],
        )?,
        None => Vec::new(),
    };
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
    Ok(replaced)
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
    /// The values replaced since each field was first recorded, newest first: a
    /// status the invariant had, say.
    pub changed: Vec<Change>,
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
/// statement again updates the fields given, and each recorded value a field
/// given replaces, a status included, is kept in `history`. Returns its id,
/// whether it is new, and the fields replaced. One transaction.
pub fn put_invariant(
    conn: &Connection,
    program_id: &str,
    statement: &str,
    f: &InvariantFields,
) -> Result<(i64, bool, Vec<&'static str>)> {
    let tx = conn.unchecked_transaction()?;
    migrate(&tx)?;
    let existing: Option<(i64, [String; 4])> = tx
        .query_row(
            "SELECT inv_id, protocol_class, source_fn, cited_line, status FROM invariants \
             WHERE program_id = ?1 AND statement = ?2 ORDER BY inv_id LIMIT 1",
            params![program_id, statement],
            |r| {
                let text = |i: usize| -> rusqlite::Result<String> {
                    Ok(r.get::<_, Option<String>>(i)?.unwrap_or_default())
                };
                Ok((r.get(0)?, [text(1)?, text(2)?, text(3)?, text(4)?]))
            },
        )
        .optional()?;
    let outcome = match existing {
        Some((id, [class, source_fn, cited_line, status])) => {
            let replaced = keep_replaced(
                &tx,
                program_id,
                Owner::Invariant(id),
                &[
                    ("protocol_class", f.protocol_class, class),
                    ("source_fn", f.source_fn, source_fn),
                    ("cited_line", f.cited_line, cited_line),
                    ("status", f.status, status),
                ],
            )?;
            tx.execute(
                "UPDATE invariants SET protocol_class = COALESCE(?2, protocol_class), \
                 source_fn = COALESCE(?3, source_fn), cited_line = COALESCE(?4, cited_line), \
                 status = COALESCE(?5, status) WHERE inv_id = ?1",
                params![id, f.protocol_class, f.source_fn, f.cited_line, f.status],
            )?;
            (id, false, replaced)
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
            (tx.last_insert_rowid(), true, Vec::new())
        }
    };
    tx.commit()?;
    Ok(outcome)
}

/// The warm-start context block returned for a re-audit. Each list holds at most
/// `ROWS` rows, the newest; `truncated` counts the rows left out of all of them.
#[derive(Debug, Serialize, Default)]
pub struct WarmContext {
    pub profile: Option<ProtocolProfile>,
    pub invariants: Vec<InvariantRow>,
    pub open_fp_rulings: Vec<RulingRow>,
    pub truncated: u64,
}

/// Assemble the warm-start context for `program_id`: its protocol profile, its
/// newest recorded invariants (in the order they were recorded), each with the
/// values replaced in it, and its newest standing false-positive/accepted-risk
/// rulings, each with its anchor.
pub fn warm(conn: &Connection, program_id: &str) -> Result<WarmContext> {
    let history = has_history(conn)?;
    let mut truncated = 0;
    let mut profile = conn
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
                    changed: Vec::new(),
                })
            },
        )
        .optional()?;
    if let (Some(p), true) = (profile.as_mut(), history) {
        let (changed, more) = changes(conn, program_id, Owner::Profile)?;
        p.changed = changed;
        truncated += more;
    }

    let total: i64 = conn.query_row(
        "SELECT count(*) FROM invariants WHERE program_id = ?1",
        params![program_id],
        |r| r.get(0),
    )?;
    let mut inv_stmt = conn.prepare(
        "SELECT inv_id, program_id, protocol_class, statement, source_fn, cited_line, status \
         FROM invariants WHERE program_id = ?1 ORDER BY inv_id DESC LIMIT ?2",
    )?;
    let mut invariants = inv_stmt
        .query_map(params![program_id, ROWS], |r| {
            Ok(InvariantRow {
                inv_id: r.get(0)?,
                program_id: r.get(1)?,
                protocol_class: r.get(2)?,
                statement: r.get(3)?,
                source_fn: r.get(4)?,
                cited_line: r.get(5)?,
                status: r.get(6)?,
                changed: Vec::new(),
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    invariants.reverse();
    truncated += left(total, invariants.len());
    if history {
        for invariant in &mut invariants {
            let (changed, more) = changes(conn, program_id, Owner::Invariant(invariant.inv_id))?;
            invariant.changed = changed;
            truncated += more;
        }
    }

    let total: i64 = conn.query_row(
        "SELECT count(*) FROM fp_rulings WHERE program_id = ?1",
        params![program_id],
        |r| r.get(0),
    )?;
    let open_fp_rulings = rulings(conn, "program_id = ?1", program_id, None, Some(ROWS))?;
    truncated += left(total, open_fp_rulings.len());

    Ok(WarmContext {
        profile,
        invariants,
        open_fp_rulings,
        truncated,
    })
}
