//! Where audit-logs may read and write. A path argument is relative to the
//! physical working directory (WT), has no `.`, `..` or empty component, passes
//! through no symbolic link, and lies inside an `incident_<n>/` run directory
//! that is a real directory holding a `.gitignore` of `*`. An input is opened
//! through each directory on its way, none followed if it is a link, and must be
//! the regular file with one name that was checked. Output goes to a new
//! temporary file in the run directory, made, linked to its new name (never
//! replacing a file) and removed through that directory, opened once. Nothing
//! here reads the environment.

use std::ffi::{CString, OsStr};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::contract::shown;

/// The longest path argument accepted, in bytes.
const MAX_PATH: usize = 1024;

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
    let mut text = Vec::new();
    let ok = fs::symlink_metadata(&gi).is_ok_and(|gmd| gmd.file_type().is_file())
        && OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&gi)
            .and_then(|f| {
                if f.metadata()?.file_type().is_file() {
                    f.take(16).read_to_end(&mut text)
                } else {
                    Ok(0)
                }
            })
            .is_ok()
        && (text == b"*" || text == b"*\n");
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

/// A named input that passed its checks: opened again when its turn comes, and
/// read only if it is still the file checked.
pub struct Checked {
    parts: Vec<Vec<u8>>,
    md: Metadata,
}

impl Checked {
    /// Opens the input through each directory on its way from WT, none of them
    /// followed if it is a symbolic link, and the file itself without following a
    /// link or blocking on a FIFO; it must be the regular file with one name that
    /// was checked.
    pub fn open(&self) -> io::Result<File> {
        let mut dir = open_at(libc::AT_FDCWD, b".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let (last, on_the_way) = self
            .parts
            .split_last()
            .ok_or_else(|| invalid("an empty path"))?;
        for part in on_the_way {
            dir = open_at(
                dir.as_raw_fd(),
                part,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
            )?;
        }
        let file = File::from(open_at(
            dir.as_raw_fd(),
            last,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        )?);
        let now = file.metadata()?;
        if !now.file_type().is_file() || now.nlink() != 1 {
            return Err(invalid("not a regular file with one name"));
        }
        if now.dev() != self.md.dev() || now.ino() != self.md.ino() {
            return Err(invalid("it changed after it was checked"));
        }
        Ok(file)
    }
}

/// Checks a named input as the recipes' `_confined()` and `unusable()` do: a
/// regular file with one name in a run directory, every name on the way checked
/// with lstat (so a link is refused before anything is read through it),
/// resolving inside WT, and one that opens.
pub fn input(wt: &Path, c: &Confined) -> Result<Checked, Stop> {
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
    if !stays_inside(wt, &c.full(wt)) {
        return Err(refuse(format!(
            "{label} resolves outside the working directory"
        )));
    }
    let checked = Checked {
        parts: c.parts.clone(),
        md,
    };
    checked
        .open()
        .map_err(|e| Stop(1, format!("cannot read {label}: {}", os_message(&e))))?;
    Ok(checked)
}

/// An `--out` path that passed its checks: its run directory, as lstat found it,
/// and the name to create there.
pub struct Output {
    dir: Vec<u8>,
    dir_md: Metadata,
    name: Vec<u8>,
}

/// Checks the `--out` path as the recipes' `unwritable()` does: a new `.jsonl`,
/// `.tsv` or `.txt` name directly in a run directory, which resolves inside WT.
pub fn output(wt: &Path, c: &Confined) -> Result<Output, Stop> {
    let label = &c.label;
    if !c.is_output() {
        return Err(refuse(format!(
            "{label} is not a .jsonl, .tsv or .txt file directly in the run directory"
        )));
    }
    let dir_md = run_dir(wt, c)?;
    match fs::symlink_metadata(c.full(wt)) {
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
    Ok(Output {
        dir: c.parts[0].clone(),
        dir_md,
        name: c.parts[1].clone(),
    })
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

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why.to_string())
}

fn c_name(name: &[u8]) -> io::Result<CString> {
    CString::new(name).map_err(|_| invalid("a NUL in a name"))
}

/// `openat(dir, name, flags | O_CLOEXEC, mode)`.
fn open_at(dir: RawFd, name: &[u8], flags: c_int, mode: libc::c_uint) -> io::Result<OwnedFd> {
    let name = c_name(name)?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call, and `dir` is
    // AT_FDCWD or a descriptor the caller holds open.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor openat just returned, owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The run directory and the temporary file a signal handler removes before
/// exiting: the directory's descriptor, then the file's name in it.
static TEMP_DIR: AtomicI32 = AtomicI32::new(-1);
static TEMP_NAME: AtomicPtr<libc::c_char> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn on_signal(sig: c_int) {
    let name = TEMP_NAME.load(Ordering::SeqCst);
    // SAFETY: `name` is null or a NUL-terminated name owned by the live `Sink`, which
    // clears it before freeing it and before closing the directory TEMP_DIR names;
    // unlinkat and _exit are async-signal-safe.
    unsafe {
        if !name.is_null() {
            libc::unlinkat(TEMP_DIR.load(Ordering::SeqCst), name, 0);
        }
        libc::_exit(128 + sig);
    }
}

/// Holds TERM, INT and HUP off while it lives; one that arrives meanwhile is
/// delivered when it is dropped.
struct Held(libc::sigset_t);

impl Held {
    fn new() -> Held {
        // SAFETY: plain calls on sigset_t values this function owns.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::sigaddset(&mut set, sig);
            }
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
            Held(old)
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        // SAFETY: restores the mask Held::new saved.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut());
        }
    }
}

/// Where a subcommand's output goes: stdout, or a temporary file in the run
/// directory of `--out` that takes the `--out` name only once the output is whole.
pub enum Sink {
    Stdout(BufWriter<io::Stdout>),
    Temp {
        file: BufWriter<File>,
        dir: OwnedFd,
        temp: CString,
        name: CString,
        done: bool,
    },
}

impl Sink {
    pub fn stdout() -> Sink {
        Sink::Stdout(BufWriter::with_capacity(1 << 16, io::stdout()))
    }

    /// Opens the run directory of `out` once, from WT and without following a link,
    /// and makes sure it is the directory checked; then a new file
    /// `.<name>.<suffix>.partial` in it, created exclusively (never through a link,
    /// never over an existing file), mode 0600. TERM, INT and HUP remove it before
    /// exiting with 128 + the signal: they are held off while it is made, so its
    /// name is always known to the handler when one arrives.
    pub fn temp(out: &Output) -> io::Result<Sink> {
        let dir = open_at(
            libc::AT_FDCWD,
            &out.dir,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )?;
        let st = File::from(dir.try_clone()?).metadata()?;
        if st.dev() != out.dir_md.dev() || st.ino() != out.dir_md.ino() {
            return Err(invalid("the run directory changed after it was checked"));
        }
        let name = c_name(&out.name)?;
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let held = Held::new();
        // SAFETY: on_signal only calls async-signal-safe functions.
        unsafe {
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::signal(sig, on_signal as extern "C" fn(c_int) as libc::sighandler_t);
            }
        }
        for attempt in 0u32..100 {
            let mut leaf = b".".to_vec();
            leaf.extend_from_slice(&out.name);
            leaf.extend_from_slice(
                format!(
                    ".{}{:08x}.partial",
                    std::process::id(),
                    seed ^ attempt.wrapping_mul(0x9E37_79B9)
                )
                .as_bytes(),
            );
            match open_at(
                dir.as_raw_fd(),
                &leaf,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                0o600,
            ) {
                Ok(fd) => {
                    let temp = c_name(&leaf)?;
                    TEMP_DIR.store(dir.as_raw_fd(), Ordering::SeqCst);
                    TEMP_NAME.store(temp.as_ptr().cast_mut(), Ordering::SeqCst);
                    drop(held);
                    return Ok(Sink::Temp {
                        file: BufWriter::with_capacity(1 << 16, File::from(fd)),
                        dir,
                        temp,
                        name,
                        done: false,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
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

    /// Flushes, and gives a temporary file its name, through the run directory: a
    /// hard link, which fails rather than replace a file that appeared in the
    /// meantime, then the temporary name is removed.
    pub fn finish(&mut self) -> io::Result<()> {
        match self {
            Sink::Stdout(w) => w.flush(),
            Sink::Temp {
                file,
                dir,
                temp,
                name,
                done,
            } => {
                file.flush()?;
                let d = dir.as_raw_fd();
                // SAFETY: both names are NUL-terminated and live; `d` is open.
                if unsafe { libc::linkat(d, temp.as_ptr(), d, name.as_ptr(), 0) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                *done = true;
                TEMP_NAME.store(std::ptr::null_mut(), Ordering::SeqCst);
                // SAFETY: as above.
                if unsafe { libc::unlinkat(d, temp.as_ptr(), 0) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }
        }
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        if let Sink::Temp {
            dir, temp, done, ..
        } = self
        {
            TEMP_NAME.store(std::ptr::null_mut(), Ordering::SeqCst);
            if !*done {
                // SAFETY: `temp` is NUL-terminated and `dir` is still open.
                unsafe {
                    libc::unlinkat(dir.as_raw_fd(), temp.as_ptr(), 0);
                }
            }
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
