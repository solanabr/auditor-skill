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

/// Why a path is refused (exit 2).
pub struct Refusal(pub String);

/// The physical working directory, resolved once (a link above it is the
/// operator's and is followed here, and only here).
pub fn working_tree() -> Result<PathBuf, Refusal> {
    std::env::current_dir()
        .and_then(|d| d.canonicalize())
        .map_err(|e| {
            Refusal(format!(
                "cannot resolve the working directory: {}",
                os_message(&e)
            ))
        })
}

/// Refuses to run from an installation inside the working directory, or from a
/// path that a quoted `Bash("<root>/…")` rule could not match as written.
pub fn self_check(wt: &Path) -> Result<(), Refusal> {
    let exe = std::env::current_exe()
        .map_err(|e| Refusal(format!("cannot resolve its own path: {}", os_message(&e))))?;
    let real = exe
        .canonicalize()
        .map_err(|e| Refusal(format!("cannot resolve its own path: {}", os_message(&e))))?;
    for p in [&exe, &real] {
        if p.as_os_str()
            .as_bytes()
            .iter()
            .any(|c| matches!(c, b'"' | b'$' | b'`' | b'\\' | b'\n'))
        {
            return Err(Refusal(format!(
                "its installation path {} holds a quote, $, backtick, backslash or newline",
                shown(p.as_os_str().as_bytes())
            )));
        }
    }
    if real.starts_with(wt) {
        return Err(Refusal(
            "it is installed inside the working directory; run it from an installation outside the tree under audit".into(),
        ));
    }
    Ok(())
}

/// A path argument that passed the grammar: its components, relative to WT.
pub struct Confined {
    arg: Vec<u8>,
    parts: Vec<Vec<u8>>,
}

impl Confined {
    pub fn shown(&self) -> String {
        shown(&self.arg)
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

    /// The number of components.
    pub fn depth(&self) -> usize {
        self.parts.len()
    }

    /// An output audit-logs may create or regenerate: a file directly in the run
    /// directory, named `[A-Za-z0-9][A-Za-z0-9._-]*` with a `.jsonl`, `.tsv` or `.txt`
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
                .any(|ext| name.ends_with(ext))
    }
}

fn run_dir_name(part: &[u8]) -> bool {
    match part.strip_prefix(b"incident_") {
        Some(n) => (1..=6).contains(&n.len()) && n.iter().all(u8::is_ascii_digit),
        None => false,
    }
}

/// The grammar every path argument must meet before anything is opened.
pub fn confine(what: &str, arg: &OsStr) -> Result<Confined, Refusal> {
    let raw = arg.as_bytes();
    // An input is named as the scripts name it, "input N (path)"; --out as "--out path".
    let name = if what == "--out" {
        format!("--out {}", shown(raw))
    } else {
        format!("{what} ({})", shown(raw))
    };
    let refuse = |why: &str| Err(Refusal(format!("{name} {why}")));
    if raw.is_empty() || raw.len() > MAX_PATH {
        return refuse(&format!("is empty or longer than {MAX_PATH} bytes"));
    }
    if raw.iter().any(|&c| c < 0x20 || c == 0x7F) {
        return refuse("holds a control character");
    }
    if matches!(raw[0], b'/' | b'-' | b'~') {
        return refuse("is not a relative path inside the working directory");
    }
    let rel = raw.strip_prefix(b"./").unwrap_or(raw);
    let parts: Vec<Vec<u8>> = rel.split(|&c| c == b'/').map(<[u8]>::to_vec).collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || p == b"." || p == b"..")
    {
        return refuse("has an empty, . or .. component");
    }
    if parts.len() < 2 || !run_dir_name(&parts[0]) {
        return refuse("is not a file inside an incident_<n>/ run directory");
    }
    Ok(Confined {
        arg: raw.to_vec(),
        parts,
    })
}

/// What `lstat` found along a path.
pub enum Found {
    /// Every component exists and none is a link; the last one's metadata.
    File(Metadata),
    /// A component does not exist (the index of the first missing one).
    Missing(usize),
    /// A component is a symbolic link.
    Link,
    /// A component could not be checked.
    Unreadable(io::Error),
}

/// Walks the path from WT one component at a time with `lstat`.
pub fn walk(wt: &Path, c: &Confined) -> Found {
    let mut last = None;
    for n in 1..=c.parts.len() {
        match fs::symlink_metadata(c.prefix(wt, n)) {
            Ok(md) if md.file_type().is_symlink() => return Found::Link,
            Ok(md) => last = Some(md),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Found::Missing(n - 1),
            Err(e) => return Found::Unreadable(e),
        }
    }
    match last {
        Some(md) => Found::File(md),
        None => Found::Missing(0),
    }
}

/// The run directory a path is inside: a real directory, not a link, holding a
/// regular `.gitignore` of `*` (Rule 11d).
pub fn check_run_dir(wt: &Path, c: &Confined) -> Result<(), Refusal> {
    let dir = c.prefix(wt, 1);
    let name = shown(&c.parts[0]);
    match fs::symlink_metadata(&dir) {
        Ok(md) if md.file_type().is_dir() => {}
        Ok(_) => {
            return Err(Refusal(format!(
                "{name} is not a directory (a symbolic link is not one)"
            )))
        }
        Err(e) => {
            return Err(Refusal(format!(
                "{name} cannot be checked: {}",
                os_message(&e)
            )))
        }
    }
    let gi = dir.join(".gitignore");
    let ok = match fs::symlink_metadata(&gi) {
        Ok(md) if md.file_type().is_file() => {
            let mut text = Vec::new();
            open_checked(&gi, &md)
                .and_then(|f| f.take(16).read_to_end(&mut text))
                .is_ok()
                && (text == b"*" || text == b"*\n")
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(Refusal(format!(
            "{name} has no .gitignore holding * (OUTPUT-RULES.md Rule 11d)"
        )))
    }
}

/// Opens a file for reading without following a final link and without blocking
/// on a FIFO, then makes sure it is the regular file `md` describes.
pub fn open_checked(path: &Path, md: &Metadata) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags::O_NOFOLLOW | flags::O_NONBLOCK)
        .open(path)?;
    let now = file.metadata()?;
    if !now.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
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
