//! Where audit-scan and audit-mem may read and write: the rules of
//! `scripts/lib/confine.sh`, which the bundled shell entry points source, in its
//! words. The items audit-logs' `confine.rs` holds too (`Stop`, `refuse`,
//! `working_tree`, `self_check`, `stays_inside`, `os_message`, `invalid`, `c_name`
//! and `open_at`) are copied from it unchanged, and `hgit`'s pins are the ones
//! confine.sh's `hgit` passes; `scripts/tests/test-auditor-tools.sh` checks both.
//!
//! The working tree (WT) is the physical working directory, resolved once. A path
//! argument is relative, non-empty, at most 1024 bytes and free of control
//! characters; it does not start with `-` or `~`, has no empty, `.` or `..`
//! component once one leading `./` is dropped, passes through no symbolic link and
//! resolves inside WT. A run directory is `audit_<n>` or `incident_<n>` (n of 1 to
//! 6 digits) directly in WT: a real directory, holding no symbolic link, tracked by
//! no repository in any letter case, whose `.gitignore` holds exactly `*`, as
//! `scripts/rundir.sh check` checks it. git runs only as `hgit` runs it: found on
//! a PATH with every entry inside WT removed, with an environment of its own, and
//! with the repository's config pinned off. A file is made through its
//! directory's descriptor, never through a link and never over a name that exists.

use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_int;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
use libc::__errno as errno_location;
#[cfg(any(target_os = "linux", target_os = "emscripten"))]
use libc::__errno_location as errno_location;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
use libc::__error as errno_location;
use walkdir::WalkDir;

/// The longest path argument accepted, in bytes.
pub const MAX_PATH: usize = 1024;

/// The largest file read whole: a source file audit-scan parses, or a guard
/// audit-mem hashes.
pub const MAX_FILE: u64 = 4 << 20;

/// The marker of the contract this build keeps. Every call a rule pre-approves
/// names it (`audit-scan --contract=1 …`, `audit-mem <subcommand> --contract=1
/// …`), and a build made before the contract refuses it, so such a rule never
/// runs one. It changes nothing; a later contract would be `--contract=2`, which
/// this build refuses.
pub const CONTRACT: &str = "--contract=1";

/// Why a word that starts with `--contract` is refused where it stands: this
/// build's marker out of its place (`place` says where it goes), or a contract
/// this build does not keep.
pub fn contract_word(word: &[u8], place: &str) -> String {
    if word == CONTRACT.as_bytes() {
        format!("{CONTRACT} comes {place}, once")
    } else {
        format!(
            "{} names a contract this build does not keep (it keeps {CONTRACT}); rebuild it with \
             cargo build --release --locked in tools/auditor-tools",
            shown(word)
        )
    }
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

/// Refuses a working directory whose physical path holds a control character,
/// in the words of `scripts/lib/confine.sh`, which refuses it too.
pub fn plain_working_tree(wt: &Path) -> Result<(), Stop> {
    if wt
        .as_os_str()
        .as_bytes()
        .iter()
        .any(|&c| c < 0x20 || c == 0x7F)
    {
        return Err(refuse(
            "the working directory path holds a control character".into(),
        ));
    }
    Ok(())
}

/// Refuses to run from a path that a quoted `Bash("<root>/…")` rule could not match
/// as written, or from an installation inside the working directory (Rule 11e),
/// in the words of `scripts/lib/confine.sh`. The path is checked as it was invoked
/// (argv[0], when it names a path), as the system names the executable, and with
/// every link resolved, as the recipes check theirs.
pub fn self_check(wt: &Path) -> Result<(), Stop> {
    let exe = std::env::current_exe()
        .map_err(|e| refuse(format!("cannot resolve its own path: {}", os_message(&e))))?;
    let real = exe
        .canonicalize()
        .map_err(|e| refuse(format!("cannot resolve its own path: {}", os_message(&e))))?;
    let invoked = std::env::args_os()
        .next()
        .map(PathBuf::from)
        .filter(|p| p.as_os_str().as_bytes().contains(&b'/'))
        .map(|p| wt.join(p))
        .unwrap_or_else(|| exe.clone());
    for p in [&invoked, &exe, &real] {
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
             under audit, or run from a directory that does not contain it (Rule 11e)"
                .into(),
        ));
    }
    Ok(())
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

/// A character never accepted in a stored field and never printed raw: a C0
/// control, DEL, a C1 control, the line and paragraph separators, a bidirectional
/// control, or a code point Unicode marks default-ignorable. The list is
/// audit-logs' `unsafe_char`, the recipes' `_UNSAFE`.
pub fn unsafe_char(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{1f}'
        | '\u{7f}'..='\u{9f}'
        | '\u{ad}'
        | '\u{34f}'
        | '\u{61c}'
        | '\u{115f}'..='\u{1160}'
        | '\u{17b4}'..='\u{17b5}'
        | '\u{180b}'..='\u{180f}'
        | '\u{200b}'..='\u{200f}'
        | '\u{2028}'..='\u{202e}'
        | '\u{2060}'..='\u{206f}'
        | '\u{3164}'
        | '\u{fe00}'..='\u{fe0f}'
        | '\u{feff}'
        | '\u{ffa0}'
        | '\u{fff0}'..='\u{fff8}'
        | '\u{1bca0}'..='\u{1bca3}'
        | '\u{1d173}'..='\u{1d17a}'
        | '\u{e0000}'..='\u{e0fff}')
}

/// Text for a message, as confine.sh's `confine_shown` prints it: each control
/// character (and each byte that is not UTF-8, and each character `unsafe_char`
/// lists) as `?`, cut after 200 bytes.
pub fn shown(raw: &[u8]) -> String {
    let mut s = String::new();
    for c in String::from_utf8_lossy(raw).chars() {
        let c = if unsafe_char(c) || c == char::REPLACEMENT_CHARACTER {
            '?'
        } else {
            c
        };
        if s.len() + c.len_utf8() > 200 {
            s.push_str("...");
            break;
        }
        s.push(c);
    }
    s
}

/// JSON text with every character `unsafe_char` lists from DEL up written as a
/// `\u` escape, so no output prints one raw. serde_json escapes the C0 controls in
/// strings already (a newline left is the layout of `--pretty`); this adds DEL,
/// the C1 controls, the bidirectional and the invisible ones. They occur only
/// inside strings, where an escape stands for the same character.
pub fn json_text(json: String) -> String {
    let escaped = |c: char| c >= '\u{7f}' && unsafe_char(c);
    if !json.chars().any(escaped) {
        return json;
    }
    let mut out = String::with_capacity(json.len() + 16);
    for c in json.chars() {
        if escaped(c) {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A path argument that passed the grammar: as given, less one leading `./`, and
/// its components (none for `.`, the working directory itself).
pub struct Rel {
    pub raw: Vec<u8>,
    pub parts: Vec<Vec<u8>>,
}

impl Rel {
    /// The path relative to WT, `.` for WT itself.
    pub fn path(&self) -> &Path {
        Path::new(OsStr::from_bytes(&self.raw))
    }

    pub fn shown(&self) -> String {
        shown(&self.raw)
    }

    pub fn full(&self, wt: &Path) -> PathBuf {
        self.prefix(wt, self.parts.len())
    }

    fn prefix(&self, wt: &Path, n: usize) -> PathBuf {
        let mut p = wt.to_path_buf();
        for part in &self.parts[..n] {
            p.push(OsStr::from_bytes(part));
        }
        p
    }
}

/// The grammar every path argument must meet before anything is looked up, as
/// `confine_path` checks it, in its words. `what` names the argument in a
/// message; `dot` accepts `.` for the working directory.
pub fn rel(what: &str, arg: &OsStr, dot: bool) -> Result<Rel, Stop> {
    let raw = arg.as_bytes();
    if dot && raw == b"." {
        return Ok(Rel {
            raw: raw.to_vec(),
            parts: Vec::new(),
        });
    }
    let s = shown(raw);
    if raw.is_empty() {
        return Err(refuse(format!("{what} is empty")));
    }
    if raw.len() > MAX_PATH {
        return Err(refuse(format!("{what} is longer than {MAX_PATH} bytes")));
    }
    if raw.iter().any(|&c| c < 0x20 || c == 0x7F) {
        return Err(refuse(format!("{what} holds a control character: {s}")));
    }
    if raw[0] == b'/' {
        return Err(refuse(format!(
            "{what} must be relative to the working directory: {s}"
        )));
    }
    if matches!(raw[0], b'-' | b'~') {
        return Err(refuse(format!("{what} may not start with - or ~: {s}")));
    }
    let p = raw.strip_prefix(b"./").unwrap_or(raw);
    let parts: Vec<Vec<u8>> = p.split(|&c| c == b'/').map(<[u8]>::to_vec).collect();
    if parts
        .iter()
        .any(|c| c.is_empty() || c == b"." || c == b"..")
    {
        return Err(refuse(format!(
            "{what} has an empty, . or .. component: {s}"
        )));
    }
    Ok(Rel {
        raw: p.to_vec(),
        parts,
    })
}

/// What a confined path names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Dir,
    File,
    Absent,
}

/// Checks a path that passed `rel` against the tree, as `confine_path` does:
/// every name on the way is checked with lstat and must not be a symbolic link,
/// every name before the last must be a directory, an existing last name must be a
/// regular file or a directory, and what it names (or, when absent, the directory
/// it would be made in) must resolve inside WT. A name that cannot be checked is a
/// refusal.
pub fn check(wt: &Path, r: &Rel, what: &str) -> Result<Kind, Stop> {
    let s = r.shown();
    let mut kind = Kind::Dir;
    let mut resolve = wt.to_path_buf();
    for n in 1..=r.parts.len() {
        let here = r.prefix(wt, n);
        match fs::symlink_metadata(&here) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(refuse(format!(
                    "{what} passes through a symbolic link: {s}"
                )))
            }
            Ok(md) if n < r.parts.len() => {
                if !md.is_dir() {
                    return Err(refuse(format!(
                        "{what} has a component that is not a directory: {s}"
                    )));
                }
                resolve = here;
            }
            Ok(md) => {
                if md.is_dir() {
                    kind = Kind::Dir;
                    resolve = here;
                } else if md.is_file() {
                    kind = Kind::File;
                } else {
                    return Err(refuse(format!(
                        "{what} is not a regular file or a directory: {s}"
                    )));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                kind = Kind::Absent;
                break;
            }
            Err(e) => {
                return Err(refuse(format!(
                    "{what} cannot be checked ({}): {s}",
                    os_message(&e)
                )))
            }
        }
    }
    let real = resolve
        .canonicalize()
        .map_err(|_| refuse(format!("{what} cannot be resolved: {s}")))?;
    if !real.starts_with(wt) {
        return Err(refuse(format!(
            "{what} resolves outside the working directory: {s}"
        )));
    }
    Ok(kind)
}

/// `audit_<n>` or `incident_<n>`, n of 1 to 6 digits (`confine_rundir_name`).
pub fn is_run_dir_name(part: &[u8]) -> bool {
    let n = part
        .strip_prefix(b"audit_")
        .or_else(|| part.strip_prefix(b"incident_"));
    match n {
        Some(n) => (1..=6).contains(&n.len()) && n.iter().all(u8::is_ascii_digit),
        None => false,
    }
}

/// A regular file, not a link, holding exactly `*`, one newline allowed after it
/// (`confine_ignore_all`).
pub fn ignores_all(path: &Path) -> bool {
    let regular = fs::symlink_metadata(path).is_ok_and(|md| md.file_type().is_file());
    let mut text = Vec::new();
    regular
        && fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .and_then(|f| f.take(16).read_to_end(&mut text))
            .is_ok()
        && (text == b"*" || text == b"*\n")
}

/// Whether the tree under `dir` holds a symbolic link, never following one
/// (`find <dir> -type l`); an entry that cannot be read is an error.
pub fn holds_link(dir: &Path) -> io::Result<bool> {
    for entry in WalkDir::new(dir).follow_links(false) {
        let entry = entry.map_err(io::Error::from)?;
        if entry.path_is_symlink() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Checks a run directory as `confine_rundir` does, in its words, with `what`
/// naming the argument it came from: the name, then a real directory, holding no
/// symbolic link, tracked by no repository in any letter case, with a
/// `.gitignore` of exactly `*`. Returns its lstat.
pub fn run_dir(wt: &Path, git: &mut Git, name: &[u8], what: &str) -> Result<Metadata, Stop> {
    git.need()?;
    let s = shown(name);
    if !is_run_dir_name(name) {
        return Err(refuse(format!(
            "{what} must be a run directory named audit_<n> or incident_<n> in the working directory: {s}"
        )));
    }
    let dir = wt.join(OsStr::from_bytes(name));
    let md = match fs::symlink_metadata(&dir) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(refuse(format!("{what} is a symbolic link: {s}")))
        }
        Ok(md) if md.is_dir() => md,
        _ => return Err(refuse(format!("{what} is not an existing directory: {s}"))),
    };
    match holds_link(&dir) {
        Ok(false) => {}
        Ok(true) => return Err(refuse(format!("{what} holds a symbolic link: {s}"))),
        Err(_) => return Err(refuse(format!("{what} cannot be fully read: {s}"))),
    }
    match git.tracked(name) {
        Some(listed) if listed.is_empty() => {}
        Some(_) => return Err(refuse(format!("{what} is tracked by git: {s}"))),
        None => {
            return Err(refuse(format!(
                "git cannot tell whether {what} is tracked: {s}"
            )))
        }
    }
    if !ignores_all(&dir.join(".gitignore")) {
        return Err(refuse(format!(
            "{what} has no .gitignore holding exactly *: {s}"
        )));
    }
    Ok(md)
}

/// The `-c` pins of confine.sh's `hgit`, in its order.
pub const HGIT_PINS: &[&str] = &[
    "core.fsmonitor=false",
    "core.pager=cat",
    "core.hooksPath=/dev/null",
    "core.untrackedCache=false",
    "log.showSignature=false",
    "gpg.program=false",
    "gpg.ssh.program=false",
    "gpg.x509.program=false",
    "protocol.allow=never",
    "diff.external=",
    "core.bigFileThreshold=512m",
    "core.attributesFile=/dev/null",
    "core.excludesFile=/dev/null",
    "diff.orderFile=/dev/null",
    "mailmap.file=/dev/null",
    "color.ui=never",
    "color.diff=never",
    "color.grep=never",
    "color.decorate=never",
    "core.quotePath=false",
    "i18n.logOutputEncoding=UTF-8",
    "format.pretty=medium",
    "log.diffMerges=separate",
    "submodule.recurse=false",
    "diff.submodule=short",
    "grep.patternType=basic",
    "grep.extendedRegexp=false",
    "log.showRoot=true",
    "core.useReplaceRefs=false",
    "core.commitGraph=false",
];

/// git, run as confine.sh's `hgit` runs it. Found on first use: on a PATH that
/// keeps only absolute entries resolving outside WT, as `confine_init` cleans it.
pub struct Git {
    wt: PathBuf,
    found: Option<(PathBuf, OsString)>,
}

impl Git {
    pub fn new(wt: &Path) -> Git {
        Git {
            wt: wt.to_path_buf(),
            found: None,
        }
    }

    /// Refuses, in confine.sh's words, when no PATH entry is left outside WT or
    /// git is not on what is left. Call it before any other method.
    pub fn need(&mut self) -> Result<(), Stop> {
        if self.found.is_none() {
            self.found = Some(self.find()?);
        }
        Ok(())
    }

    fn find(&self) -> Result<(PathBuf, OsString), Stop> {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut clean: Vec<PathBuf> = Vec::new();
        for entry in path.as_bytes().split(|&c| c == b':') {
            if entry.first() != Some(&b'/') {
                continue;
            }
            let Ok(real) = Path::new(OsStr::from_bytes(entry)).canonicalize() else {
                continue;
            };
            if !real.is_dir()
                || real
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .any(|&c| c < 0x20 || c == 0x7F)
                || real.starts_with(&self.wt)
            {
                continue;
            }
            clean.push(real);
        }
        if clean.is_empty() {
            return Err(refuse(
                "no PATH entry is left outside the working directory".into(),
            ));
        }
        let exe = clean
            .iter()
            .map(|d| d.join("git"))
            .find(|g| {
                fs::metadata(g).is_ok_and(|md| md.is_file() && md.permissions().mode() & 0o111 != 0)
            })
            .ok_or_else(|| refuse("git is not on PATH".into()))?;
        let joined = OsString::from_vec(
            clean
                .iter()
                .map(|d| d.as_os_str().as_bytes().to_vec())
                .collect::<Vec<_>>()
                .join(&b':'),
        );
        Ok((exe, joined))
    }

    /// `hgit <WT> <args>` with GIT_CEILING_DIRECTORIES set to `ceiling`: no
    /// environment but its own, the repository's config pinned off.
    fn run(&self, ceiling: &OsStr, args: &[&OsStr]) -> io::Result<std::process::Output> {
        let (exe, path) = self
            .found
            .as_ref()
            .ok_or_else(|| invalid("git was not looked for"))?;
        let mut cmd = Command::new(exe);
        cmd.env_clear();
        if let Some(home) = std::env::var_os("HOME") {
            cmd.env("HOME", home);
        }
        cmd.env("PATH", path)
            .env(
                "TMPDIR",
                std::env::var_os("TMPDIR")
                    .filter(|t| !t.is_empty())
                    .unwrap_or_else(|| "/tmp".into()),
            )
            .env("LC_ALL", "C")
            .env(
                "TZ",
                std::env::var_os("TZ")
                    .filter(|t| !t.is_empty())
                    .unwrap_or_else(|| "UTC".into()),
            )
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_CEILING_DIRECTORIES", ceiling)
            .env("GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS", "true")
            .arg("--no-pager")
            .arg("-C")
            .arg(&self.wt);
        for pin in HGIT_PINS {
            cmd.arg("-c").arg(pin);
        }
        cmd.args(args)
            .current_dir(&self.wt)
            .stdin(Stdio::null())
            .output()
    }

    /// What git tracks at `path` (relative to WT), in any letter case, as
    /// `confine_tracked` asks it: outside every repository nothing is tracked, and
    /// discovery may go above WT for this one question, since a repository there
    /// decides it. `None` when git cannot tell, or cannot be run.
    pub fn tracked(&self, path: &[u8]) -> Option<Vec<u8>> {
        let none = OsStr::new("");
        let inside = self
            .run(
                none,
                &[OsStr::new("rev-parse"), OsStr::new("--is-inside-work-tree")],
            )
            .ok()?;
        if !inside.status.success() {
            let err = String::from_utf8_lossy(&inside.stderr);
            return err.contains("not a git repository").then(Vec::new);
        }
        let spec = OsString::from_vec([&b":(literal,icase)"[..], path].concat());
        let listed = self
            .run(
                none,
                &[
                    OsStr::new("--icase-pathspecs"),
                    OsStr::new("ls-files"),
                    OsStr::new("--"),
                    &spec,
                ],
            )
            .ok()?;
        listed.status.success().then_some(listed.stdout)
    }
}

/// A directory directly in WT (a run directory, or the store's), opened once
/// without following a link and checked to be the directory that was checked; the
/// files below are made and opened through it.
pub struct Dir {
    fd: OwnedFd,
}

impl Dir {
    pub fn open(name: &[u8], checked: &Metadata) -> io::Result<Dir> {
        let fd = open_at(
            libc::AT_FDCWD,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )?;
        let st = File::from(fd.try_clone()?).metadata()?;
        if st.dev() != checked.dev() || st.ino() != checked.ino() {
            return Err(invalid("the directory changed after it was checked"));
        }
        Ok(Dir { fd })
    }

    /// A new file, made exclusively (never through a link, never over a name that
    /// exists), mode 0600, open for writing.
    pub fn create(&self, name: &[u8]) -> io::Result<File> {
        open_at(
            self.fd.as_raw_fd(),
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )
        .map(File::from)
    }

    /// A file that exists, opened without following a link or blocking on a FIFO,
    /// read-only or for reading and writing; it must be a regular file with one
    /// name, so nothing written to it reaches another name.
    pub fn open_regular(&self, name: &[u8], write: bool) -> io::Result<File> {
        let mode = if write { libc::O_RDWR } else { libc::O_RDONLY };
        let file = File::from(open_at(
            self.fd.as_raw_fd(),
            name,
            mode | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        )?);
        let md = file.metadata()?;
        if !md.file_type().is_file() {
            return Err(invalid("not a regular file"));
        }
        if md.nlink() != 1 {
            return Err(invalid("it has more than one name (a hard link)"));
        }
        Ok(file)
    }
}

/// A directory in the directory `dir` (a descriptor, or `libc::AT_FDCWD` for the
/// working directory), opened without following a link.
pub fn open_dir(dir: RawFd, name: &[u8]) -> io::Result<OwnedFd> {
    open_at(
        dir,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )
}

/// A file in the directory `dir`, opened read-only without following a link or
/// blocking on a FIFO.
pub fn open_file(dir: RawFd, name: &[u8]) -> io::Result<File> {
    open_at(
        dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )
    .map(File::from)
}

/// The file type (`S_IFMT` bits) of a name in the directory `dir`, a link read
/// as a link.
pub fn kind_at(dir: RawFd, name: &[u8]) -> io::Result<libc::mode_t> {
    let name = c_name(name)?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is NUL-terminated, `st` is room for one stat, and `dir` is a
    // descriptor the caller holds open.
    let r = unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat succeeded, so it filled `st`.
    Ok(unsafe { st.assume_init() }.st_mode & libc::S_IFMT)
}

/// The names in the directory `dir`, but `.` and `..`, in byte order, read
/// through a second descriptor so that `dir` stays open for the names below it.
pub fn names(dir: &OwnedFd) -> io::Result<Vec<Vec<u8>>> {
    // SAFETY: dup only copies a descriptor the caller holds open.
    let fd = unsafe { libc::dup(dir.as_raw_fd()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor dup just returned; fdopendir takes it over.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so `fd` is still this function's to close.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    let mut names = Vec::new();
    let result = loop {
        // SAFETY: errno is this thread's; it is cleared to tell the end of the
        // directory (NULL, errno untouched) from an error (NULL, errno set).
        unsafe { *errno_location() = 0 };
        // SAFETY: `stream` is open until the closedir below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let e = io::Error::last_os_error();
            break if e.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(e)
            };
        }
        // SAFETY: readdir returned an entry whose name is NUL-terminated, valid
        // until the next readdir on this stream.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    };
    // SAFETY: `stream` came from fdopendir and is closed once, with its descriptor.
    unsafe { libc::closedir(stream) };
    result?;
    names.sort();
    Ok(names)
}

/// A file inside WT read whole, at most `MAX_FILE` bytes: `r` passed `rel`, and
/// each directory on its way is opened from WT without following a link, then
/// the file itself, which must be a regular file with one name. `Err` says why
/// it cannot be read.
pub fn read_file(r: &Rel) -> Result<Vec<u8>, String> {
    let (last, on_the_way) = r
        .parts
        .split_last()
        .ok_or_else(|| "it is the working directory".to_string())?;
    let failed = |e: io::Error| match e.raw_os_error() {
        Some(libc::ELOOP) => "it is, or is reached through, a symbolic link".to_string(),
        Some(libc::ENOTDIR) => "a name on its way is not a directory".to_string(),
        Some(libc::ENOENT) => "it does not exist".to_string(),
        _ => os_message(&e),
    };
    let mut dir =
        open_at(libc::AT_FDCWD, b".", libc::O_RDONLY | libc::O_DIRECTORY, 0).map_err(failed)?;
    for part in on_the_way {
        dir = open_at(
            dir.as_raw_fd(),
            part,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )
        .map_err(failed)?;
    }
    let file = File::from(
        open_at(
            dir.as_raw_fd(),
            last,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
        )
        .map_err(failed)?,
    );
    let md = file.metadata().map_err(failed)?;
    if !md.file_type().is_file() {
        return Err("it is not a regular file".into());
    }
    if md.nlink() != 1 {
        return Err("it has more than one name (a hard link)".into());
    }
    if md.len() > MAX_FILE {
        return Err("it is larger than 4 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("it is larger than 4 MiB".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> bool {
        rel("p", OsStr::new(s), true).is_ok()
    }

    #[test]
    fn path_grammar() {
        for good in [
            ".",
            "a",
            "./a",
            "a/b.rs",
            "audit_1/prescan.json",
            "a..b",
            ".hidden",
        ] {
            assert!(ok(good), "{good}");
        }
        let long = "a".repeat(MAX_PATH + 1);
        for bad in [
            "", "/abs", "-x", "~", "~/x", "./", "./.", "a//b", "a/", "a/./b", "a/../b", "..",
            "././a", "a\nb", "a\u{7f}b", &long,
        ] {
            assert!(!ok(bad), "{bad:?}");
        }
        assert!(rel("p", OsStr::new("."), false).is_err());
        assert_eq!(
            rel("p", OsStr::new("./a/b"), false).ok().map(|r| r.raw),
            Some(b"a/b".to_vec())
        );
    }

    #[test]
    fn refusal_words() {
        let why = |s: &str| match rel("--out", OsStr::new(s), false) {
            Err(Stop(2, m)) => m,
            _ => String::new(),
        };
        assert_eq!(why(""), "refused: --out is empty");
        assert_eq!(
            why("/x"),
            "refused: --out must be relative to the working directory: /x"
        );
        assert_eq!(why("-x"), "refused: --out may not start with - or ~: -x");
        assert_eq!(
            why("a/../b"),
            "refused: --out has an empty, . or .. component: a/../b"
        );
        assert_eq!(why("a\tb"), "refused: --out holds a control character: a?b");
    }

    #[test]
    fn run_dir_names() {
        for good in ["audit_1", "incident_123456", "audit_007"] {
            assert!(is_run_dir_name(good.as_bytes()), "{good}");
        }
        for bad in [
            "audit_",
            "audit_1234567",
            "Audit_1",
            "audit_1a",
            "audit_-1",
            "report_1",
            "audit_1/",
        ] {
            assert!(!is_run_dir_name(bad.as_bytes()), "{bad}");
        }
    }

    #[test]
    fn shown_text() {
        assert_eq!(shown(b"a\x1b[31mb"), "a?[31mb");
        assert_eq!(shown("x\u{202e}y".as_bytes()), "x?y");
        assert_eq!(shown(b"\xff"), "?");
        let long = shown("é".repeat(150).as_bytes());
        assert!(long.ends_with("...") && long.len() <= 203);
    }

    #[test]
    fn json_escapes() {
        assert_eq!(json_text("\"a\u{202e}b\"".into()), "\"a\\u202eb\"");
        assert_eq!(json_text("\"\u{e0041}\"".into()), "\"\\udb40\\udc41\"");
        assert_eq!(json_text("\"\u{7f}\"".into()), "\"\\u007f\"");
        assert_eq!(json_text("plain".into()), "plain");
        assert_eq!(
            json_text("{\n  \"a\": \"\u{85}\"\n}".into()),
            "{\n  \"a\": \"\\u0085\"\n}"
        );
    }
}
