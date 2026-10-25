//! confine.rs against scripts/lib/confine.sh: every case of the case file
//! test-confine.sh runs `confine_path` over, run through `confine::rel` and
//! `confine::check` in the same tree, must come out as the shell's does.

mod common;

use std::ffi::OsStr;
use std::process::Command;

use auditor_tools::confine::{self, Kind, Stop};
use common::Wt;

const CASES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/tests/fixtures/confine/paths.txt"
);

/// The tree test-confine.sh runs the case file in, as its header describes it.
fn tree() -> Wt {
    let wt = Wt::new();
    wt.write("a.rs", b"fn a() {}\n");
    wt.write("src/lib.rs", b"fn lib() {}\n");
    wt.write("src/deep/x.rs", b"fn x() {}\n");
    wt.mkdir("bin");
    wt.link("a.rs".as_ref(), "link");
    wt.link("src".as_ref(), "linkdir");
    wt.link("nowhere".as_ref(), "dangling");
    wt.link(&wt.outside(), "out");
    wt.link("../a.rs".as_ref(), "src/inner");
    let made = Command::new("mkfifo")
        .arg(wt.path("fifo"))
        .status()
        .expect("run mkfifo");
    assert!(made.success(), "mkfifo");
    wt
}

/// A field of the case file with its placeholders filled in (its header lists
/// them), as test-confine.sh fills them.
fn fill(field: &str) -> String {
    if field == "@EMPTY@" {
        return String::new();
    }
    let mut out = String::new();
    let mut rest = field;
    while let Some(start) = rest.find('@') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('@') else {
            break;
        };
        out.push_str(&rest[..start]);
        let name = &after[..end];
        match name {
            "SOH" => out.push('\u{1}'),
            "TAB" => out.push('\t'),
            "NL" => out.push('\n'),
            "ESC" => out.push('\u{1b}'),
            "DEL" => out.push('\u{7f}'),
            _ => match name
                .strip_prefix("LONG:")
                .and_then(|n| n.parse::<usize>().ok())
            {
                Some(n) => out.push_str(&"a".repeat(n)),
                None => {
                    out.push('@');
                    out.push_str(name);
                    out.push('@');
                }
            },
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// What `confine_path <path> "the path" <want>` prints, by way of confine.rs: on
/// success `CONFINE_REL CONFINE_TYPE`, else its refusal line. What `want` adds to
/// the path rules (a directory, or a name not yet taken) is the caller's, as it
/// is in confine.sh.
fn confined(wt: &Wt, want: &str, path: &str) -> (u8, String) {
    let got = (|| -> Result<String, Stop> {
        let r = confine::rel("the path", OsStr::new(path), want == "dir")?;
        let kind = confine::check(&wt.dir, &r, "the path")?;
        let s = r.shown();
        match (want, kind) {
            ("dir", Kind::Dir) | ("any", _) | ("new", Kind::Absent) => {}
            ("dir", _) => {
                return Err(confine::refuse(format!(
                    "the path is not an existing directory: {s}"
                )))
            }
            ("new", _) => return Err(confine::refuse(format!("the path already exists: {s}"))),
            _ => {}
        }
        let kind = match kind {
            Kind::Dir => "dir",
            Kind::File => "file",
            Kind::Absent => "none",
        };
        Ok(format!("{} {kind}", String::from_utf8_lossy(&r.raw)))
    })();
    match got {
        Ok(out) => (0, out),
        Err(Stop(_, why)) => (64, format!("test: {why}")),
    }
}

#[test]
fn confine_rs_reads_every_path_case_as_confine_sh_does() {
    let wt = tree();
    let cases = std::fs::read_to_string(CASES).expect("read the case file");
    let mut n = 0;
    let mut differ = Vec::new();
    for line in cases.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        let [want, path, status, expect] = fields[..] else {
            panic!("a case line has four fields: {line:?}");
        };
        n += 1;
        let (path, expect) = (fill(path), fill(expect));
        let (got_status, got) = confined(&wt, want, &path);
        if got_status.to_string() != status || got != expect {
            differ.push(format!(
                "{want} {path:?}: confine.sh {status} {expect:?}, confine.rs {got_status} {got:?}"
            ));
        }
    }
    assert!(n > 40, "only {n} cases read");
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}
