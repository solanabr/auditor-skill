//! Where audit-logs may read and write. A path argument is relative to the
//! physical working directory (WT), has no `.`, `..` or empty component, passes
//! through no symbolic link, and lies inside an `incident_<n>/` run directory
//! that is a real directory holding a `.gitignore` of `*`. Inputs are opened
//! without following a link and must be the regular file that was checked;
//! output goes to a new temporary file, created exclusively beside the named
//! file, which takes that new name, never replacing a file, once the output is
//! complete. Nothing here reads the environment.

use std::ffi::{CString, OsStr};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract::shown;

/// The longest path argument accepted, in bytes.
const MAX_PATH: usize = 1024;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod flags {
    pub const O_NOFOLLOW: i32 = 0x100;
    pub const O_NONBLOCK: i32 = 0x4;
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "loongarch64"
    )
))]
mod flags {
    pub const O_NOFOLLOW: i32 = 0x20000;
    pub const O_NONBLOCK: i32 = 0x800;
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )
))]
mod flags {
    pub const O_NOFOLLOW: i32 = 0x8000;
    pub const O_NONBLOCK: i32 = 0x800;
}

// Any other target opens without these flags; the device and inode check after
// opening still refuses a file that is not the one checked.
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "s390x",
            target_arch = "loongarch64",
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        )
    )
)))]
mod flags {
    pub const O_NOFOLLOW: i32 = 0;
    pub const O_NONBLOCK: i32 = 0;
}

mod sys {
    use std::os::raw::{c_char, c_int};

    extern "C" {
        pub fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
        pub fn unlink(path: *const c_char) -> c_int;
        pub fn _exit(status: c_int) -> !;
    }

    pub const SIGHUP: c_int = 1;
    pub const SIGINT: c_int = 2;
    pub const SIGTERM: c_int = 15;
}

/// Ends a run with an exit status and one stderr line: 2 for a refusal, 1 for a
/// file that cannot be read or written.
pub struct Stop(pub u8, pub String);

/// A refusal (exit 2): `refused: <why>`.
pub fn refuse(why: String) -> Stop {
    Stop(2, format!("refused: {why}"))
}

/// The physical working directory, resolved once (a link above it is the
/// operator's and is followed here, and only here).
pub fn working_tree() -> Result<PathBuf, Stop> {
    std::env::current_dir()
        .and_then(|d| d.canonicalize())
        .map_err(|e| {
            refuse(format!(
                "cannot resolve the working directory: {}",
                os_message(&e)
            ))
        })
}

/// Refuses to run from a path that a quoted `Bash("<root>/…")` rule could not match
/// as written, or from an installation inside the working directory (Rule 11e),
/// in the words of `scripts/lib/confine.sh`.
pub fn self_check(wt: &Path) -> Result<(), Stop> {
    let exe = std::env::current_exe()
        .map_err(|e| refuse(format!("cannot resolve its own path: {}", os_message(&e))))?;
    let real = exe
        .canonicalize()
        .map_err(|e| refuse(format!("cannot resolve its own path: {}", os_message(&e))))?;
    for p in [&exe, &real] {
        if p.as_os_str()
            .as_bytes()
            .iter()
            .any(|&c| matches!(c, b'"' | b'$' | b'`' | b'\\') || c < 0x20 || c == 0x7F)
        {
            return Err(refuse(
                "the installation path holds a quote, $, a backtick, a backslash or a control \
                 character, so its quoted call cannot match as written"
                    .into(),
            ));
        }
    }
    if real.starts_with(wt) {
        return Err(refuse(
            "the installation lies inside the working directory; install it outside the tree \
             under audit (Rule 11e)"
                .into(),
        ));
    }
    Ok(())
}

/// A path argument that passed the grammar: its components, relative to WT, and
/// how messages name it (`input N (<path>)` or `--out <path>`).
pub struct Confined {
    label: String,
    parts: Vec<Vec<u8>>,
}

impl Confined {
    pub fn label(&self) -> &str {
        &self.label
    }

    fn prefix(&self, wt: &Path, n: usize) -> PathBuf {
        let mut p = wt.to_path_buf();
        for part in &self.parts[..n] {
            p.push(OsStr::from_bytes(part));
        }
        p
    }

    pub fn full(&self, wt: &Path) -> PathBuf {
        self.prefix(wt, self.parts.len())
    }

    /// An output audit-logs may create: a file directly in the run directory,
    /// named `[A-Za-z0-9][A-Za-z0-9._-]*` with a `.jsonl`, `.tsv` or `.txt`
    /// extension, at most 128 bytes. A corpus in `corpus*/`, a snapshot in `bin/`,
    /// the ledger and the run directory's own files are never outputs.
    pub fn is_output(&self) -> bool {
        let [_, name] = self.parts.as_slice() else {
            return false;
        };
        let stem_ok = name.len() <= 128
            && name.first().is_some_and(u8::is_ascii_alphanumeric)
            && name
                .iter()
                .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
        stem_ok
            && [&b".jsonl"[..], b".tsv", b".txt"]
                .iter()
                .any(|ext| name.ends_with(ext) && name.len() > ext.len())
    }
}

fn run_dir_name(part: &[u8]) -> bool {
    match part.strip_prefix(b"incident_") {
        Some(n) => (1..=6).contains(&n.len()) && n.iter().all(u8::is_ascii_digit),
        None => false,
    }
}

/// The grammar every path argument must meet before anything is opened, as the
/// recipes' `_parts()`: relative, inside an `incident_<n>/` run directory, with no
/// empty, `.` or `..` component. `what` is `input N` or `--out`.
pub fn confine(what: &str, arg: &OsStr) -> Result<Confined, Stop> {
    let raw = arg.as_bytes();
    let label = if what == "--out" {
        format!("--out {}", shown(raw))
    } else {
        format!("{what} ({})", shown(raw))
    };
    let rel = raw.strip_prefix(b"./").unwrap_or(raw);
    let parts: Vec<Vec<u8>> = rel.split(|&c| c == b'/').map(<[u8]>::to_vec).collect();
    let why = if raw.is_empty() || raw.len() > MAX_PATH {
        format!("is empty or longer than {MAX_PATH} bytes")
    } else if raw.iter().any(|&c| c < 0x20 || c == 0x7F) {
        "holds a control character".into()
    } else if matches!(raw[0], b'/' | b'-' | b'~') {
        "is not a relative path inside the working directory".into()
    } else if parts
        .iter()
        .any(|p| p.is_empty() || p == b"." || p == b"..")
    {
        "has an empty, . or .. component".into()
    } else if parts.len() < 2 || !run_dir_name(&parts[0]) {
        "is not a file inside an incident_<n>/ run directory".into()
    } else {
        return Ok(Confined { label, parts });
    };
    Err(refuse(format!("{label} {why}")))
}

/// The run directory a path is in: a real directory, not a link, holding a
/// regular `.gitignore` of `*` (Rule 11d). Returns its lstat.
fn run_dir(wt: &Path, c: &Confined) -> Result<Metadata, Stop> {
    let dir = c.prefix(wt, 1);
    let where_ = format!("{} is in {}, which", c.label, shown(&c.parts[0]));
    let md = match fs::symlink_metadata(&dir) {
        Ok(md) if md.file_type().is_dir() => md,
        Ok(_) => {
            return Err(refuse(format!(
                "{where_} is not a real directory (a symbolic link is not one)"
            )))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(refuse(format!("{where_} does not exist")))
        }
        Err(e) => {
            return Err(refuse(format!(
                "{where_} cannot be checked: {}",
                os_message(&e)
            )))
        }
    };
    let gi = dir.join(".gitignore");
    let ok = match fs::symlink_metadata(&gi) {
        Ok(gmd) if gmd.file_type().is_file() => {
            let mut text = Vec::new();
            open_checked(&gi, &gmd, false)
                .and_then(|f| f.take(16).read_to_end(&mut text))
                .is_ok()
                && (text == b"*" || text == b"*\n")
        }
        _ => false,
    };
    if ok {
        Ok(md)
    } else {
        Err(refuse(format!(
            "{} is in {}, whose .gitignore does not hold * (OUTPUT-RULES.md Rule 11d)",
            c.label,
            shown(&c.parts[0])
        )))
    }
}

/// Checks a named input as the recipes' `_confined()` and `unusable()` do, and
/// returns its lstat: a regular file with one name in a run directory, every name
/// on the way checked with lstat (so a link is refused before anything is read
/// through it), resolving inside WT, and one that opens.
pub fn input(wt: &Path, c: &Confined) -> Result<Metadata, Stop> {
    run_dir(wt, c)?;
    let label = &c.label;
    let mut last = None;
    for n in 2..=c.parts.len() {
        if last
            .as_ref()
            .is_some_and(|md: &Metadata| !md.file_type().is_dir())
        {
            return Err(refuse(format!("{label} does not exist")));
        }
        match fs::symlink_metadata(c.prefix(wt, n)) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(refuse(format!(
                    "{label} is a symbolic link, or is reached through one inside the working directory"
                )))
            }
            Ok(md) => last = Some(md),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(refuse(format!("{label} does not exist")))
            }
            Err(e) => {
                return Err(refuse(format!(
                    "{label} cannot be checked: {}",
                    os_message(&e)
                )))
            }
        }
    }
    let Some(md) = last else {
        return Err(refuse(format!("{label} does not exist")));
    };
    if !md.file_type().is_file() {
        return Err(refuse(format!("{label} is not a regular file")));
    }
    if md.nlink() != 1 {
        return Err(refuse(format!(
            "{label} has more than one name (a hard link)"
        )));
    }
    let full = c.full(wt);
    if !stays_inside(wt, &full) {
        return Err(refuse(format!(
            "{label} resolves outside the working directory"
        )));
    }
    open_checked(&full, &md, true)
        .map_err(|e| Stop(1, format!("cannot read {label}: {}", os_message(&e))))?;
    Ok(md)
}

/// Checks the `--out` path as the recipes' `unwritable()` does: a new `.jsonl`,
/// `.tsv` or `.txt` name directly in a run directory, which resolves inside WT.
pub fn output(wt: &Path, c: &Confined) -> Result<PathBuf, Stop> {
    let label = &c.label;
    if !c.is_output() {
        return Err(refuse(format!(
            "{label} is not a .jsonl, .tsv or .txt file directly in the run directory"
        )));
    }
    run_dir(wt, c)?;
    let full = c.full(wt);
    match fs::symlink_metadata(&full) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(refuse(format!("{label} is a symbolic link")))
        }
        Ok(_) => {
            return Err(refuse(format!(
                "{label} already exists, and an output never replaces a file: name a new one"
            )))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(Stop(1, format!("cannot write {label}: {}", os_message(&e)))),
    }
    if !stays_inside(wt, &c.prefix(wt, 1)) {
        return Err(refuse(format!(
            "{label} resolves outside the working directory"
        )));
    }
    Ok(full)
}

/// Opens a file for reading without following a final link and without blocking
/// on a FIFO, then makes sure it is the regular file `md` describes, and, for an
/// input (`one_name`), that it has one name.
pub fn open_checked(path: &Path, md: &Metadata, one_name: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags::O_NOFOLLOW | flags::O_NONBLOCK)
        .open(path)?;
    let now = file.metadata()?;
    if !now.file_type().is_file() || (one_name && now.nlink() != 1) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file with one name",
        ));
    }
    if now.dev() != md.dev() || now.ino() != md.ino() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "changed while it was checked",
        ));
    }
    Ok(file)
}

/// `realpath(WT/p)` must stay under WT.
pub fn stays_inside(wt: &Path, path: &Path) -> bool {
    match path.canonicalize() {
        Ok(real) => real.starts_with(wt) && real != wt,
        Err(_) => false,
    }
}

/// An OS error's text without Rust's " (os error N)" suffix, as Python's
/// `strerror` reads.
pub fn os_message(e: &io::Error) -> String {
    let text = e.to_string();
    match text.find(" (os error ") {
        Some(i) => text[..i].to_string(),
        None => text,
    }
}

/// The temporary file a signal handler removes before exiting.
static TEMP: AtomicPtr<c_char> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn on_signal(sig: c_int) {
    let p = TEMP.load(Ordering::SeqCst);
    // SAFETY: `p` is null or a NUL-terminated path leaked by `Sink::temp` and never
    // freed; unlink and _exit are async-signal-safe.
    unsafe {
        if !p.is_null() {
            sys::unlink(p);
        }
        sys::_exit(128 + sig);
    }
}

/// Where a subcommand's output goes: stdout, or a temporary file beside the
/// `--out` path that takes that name only once the output is whole.
pub enum Sink {
    Stdout(BufWriter<io::Stdout>),
    Temp {
        file: BufWriter<File>,
        temp: PathBuf,
        path: PathBuf,
        done: bool,
    },
}

impl Sink {
    pub fn stdout() -> Sink {
        Sink::Stdout(BufWriter::with_capacity(1 << 16, io::stdout()))
    }

    /// A new file `.<name>.<suffix>.partial` beside `path`, created exclusively
    /// (never through a link, never over an existing file), mode 0600. TERM, INT
    /// and HUP remove it before exiting with 128 + the signal: the handlers are in
    /// place, and the name is known to them, before the file is created.
    pub fn temp(path: PathBuf) -> io::Result<Sink> {
        // SAFETY: on_signal only calls async-signal-safe functions.
        unsafe {
            for sig in [sys::SIGTERM, sys::SIGINT, sys::SIGHUP] {
                sys::signal(sig, on_signal);
            }
        }
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        let name = path
            .file_name()
            .map(|n| n.as_bytes().to_vec())
            .unwrap_or_default();
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        for attempt in 0u32..100 {
            let mut leaf = b".".to_vec();
            leaf.extend_from_slice(&name);
            leaf.extend_from_slice(
                format!(
                    ".{}{:08x}.partial",
                    std::process::id(),
                    seed ^ attempt.wrapping_mul(0x9E37_79B9)
                )
                .as_bytes(),
            );
            let temp = dir.join(OsStr::from_bytes(&leaf));
            let c = CString::new(temp.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in the path"))?;
            TEMP.store(c.into_raw(), Ordering::SeqCst);
            let opened = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(flags::O_NOFOLLOW)
                .open(&temp);
            match opened {
                Ok(file) => {
                    let file = BufWriter::with_capacity(1 << 16, file);
                    return Ok(Sink::Temp {
                        file,
                        temp,
                        path,
                        done: false,
                    });
                }
                Err(e) => {
                    TEMP.store(std::ptr::null_mut(), Ordering::SeqCst);
                    if e.kind() != io::ErrorKind::AlreadyExists {
                        return Err(e);
                    }
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "no free temporary file name",
        ))
    }

    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Sink::Stdout(w) => w.write_all(data),
            Sink::Temp { file, .. } => file.write_all(data),
        }
    }

    /// Flushes, and gives a temporary file its path: a hard link, which fails
    /// rather than replace a file that appeared in the meantime, then the
    /// temporary name is removed.
    pub fn finish(&mut self) -> io::Result<()> {
        match self {
            Sink::Stdout(w) => w.flush(),
            Sink::Temp {
                file,
                temp,
                path,
                done,
            } => {
                file.flush()?;
                fs::hard_link(&*temp, &*path)?;
                *done = true;
                let removed = fs::remove_file(&*temp);
                TEMP.store(std::ptr::null_mut(), Ordering::SeqCst);
                removed
            }
        }
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        if let Sink::Temp {
            temp, done: false, ..
        } = self
        {
            TEMP.store(std::ptr::null_mut(), Ordering::SeqCst);
            let _ = fs::remove_file(&*temp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(s: &str) -> Option<Confined> {
        confine("input 1", OsStr::new(s)).ok()
    }

    #[test]
    fn path_grammar() {
        assert!(path("incident_1/corpus/transactions.jsonl").is_some());
        assert!(path("./incident_123456/x").is_some());
        let long = format!("incident_1/{}", "a".repeat(1100));
        for bad in [
            "",
            "/abs/incident_1/x",
            "-x",
            "~/x",
            "incident_1",
            "incident_1/",
            "incident_1//x",
            "incident_1/./x",
            "incident_1/../x",
            "././incident_1/x",
            "audit_1/x",
            "incident_1234567/x",
            "INCIDENT_1/x",
            "incident_/x",
            "x/incident_1/y",
            "incident_1/a\nb",
            "incident_1/a\u{7f}b",
            &long,
        ] {
            assert!(path(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn output_names() {
        for good in [
            "incident_1/frames.jsonl",
            "incident_1/d-1.tsv",
            "incident_1/P_2.txt",
        ] {
            assert!(path(good).is_some_and(|c| c.is_output()), "{good}");
        }
        for bad in [
            "incident_1/corpus/transactions.jsonl",
            "incident_1/LEDGER.md",
            "incident_1/INCIDENTS.json",
            "incident_1/.gitignore",
            "incident_1/.x.txt",
            "incident_1/.jsonl",
            "incident_1/a b.txt",
            "incident_1/x.jsonl.partial",
        ] {
            assert!(!path(bad).is_some_and(|c| c.is_output()), "{bad}");
        }
    }
}
