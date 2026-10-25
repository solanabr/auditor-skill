//! The parse child's CPU limit: before each file, the CPU it has used and the
//! file's share more, so a child left parsing with no parent to kill it dies,
//! while one that answers each file within its share goes on. One test, which runs
//! itself as that child, with a share of a second and SIGXCPU ignored.

mod common;

use std::io::{self, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use auditor_tools::scan;
use common::Wt;

const TEST: &str = "a_child_dies_once_one_file_has_used_its_share_of_cpu";
const CHILD: &str = "AUDITOR_TOOLS_TEST_CPU_CHILD";

/// This process's CPU time.
fn cpu() -> Duration {
    // SAFETY: an all-zero rusage is valid; getrusage only writes it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a rusage this function owns.
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
    let time = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec.try_into().unwrap())
            + Duration::from_micros(t.tv_usec.try_into().unwrap())
    };
    time(usage.ru_utime) + time(usage.ru_stime)
}

/// Frames of one small file: `left` of them, each read after 0.7 s of CPU, more
/// than half a share, then one whose reading uses CPU until the process ends. The
/// CPU goes to user code, with few system calls between: macOS ends a process at
/// its limit while it runs user code, and one that runs system call after system
/// call can go past it.
struct Slow {
    left: usize,
    frame: Vec<u8>,
    at: usize,
}

impl Read for Slow {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.at == 0 {
            let until = if self.left == 0 {
                Duration::MAX
            } else {
                cpu() + Duration::from_millis(700)
            };
            let mut n = 0u64;
            while cpu() < until {
                for _ in 0..1_000_000 {
                    n = std::hint::black_box(n.wrapping_add(1));
                }
            }
            self.left -= 1;
        }
        let n = buf.len().min(self.frame.len() - self.at);
        buf[..n].copy_from_slice(&self.frame[self.at..self.at + n]);
        self.at = (self.at + n) % self.frame.len();
        Ok(n)
    }
}

#[test]
fn a_child_dies_once_one_file_has_used_its_share_of_cpu() {
    if let Some(answers) = std::env::var_os(CHILD) {
        let file = b"fn a() { let x = 1 + 2; }\n";
        let mut input = Slow {
            left: 4,
            frame: [&(file.len() as u64).to_le_bytes()[..], file].concat(),
            at: 0,
        };
        let mut output = std::fs::File::create(answers).expect("make the answers file");
        let end = scan::parse_frames(&mut input, &mut output, Duration::from_secs(1));
        panic!("the child's frames ended: {end:?}");
    }
    let wt = Wt::new();
    let answers = wt.path("answers");
    let started = Instant::now();
    let mut command = Command::new(std::env::current_exe().expect("this test's path"));
    command
        .args(["--exact", TEST, "--test-threads=1"])
        .env(CHILD, &answers)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: signal is async-signal-safe. An ignored signal stays ignored across
    // exec, as a parent may leave it.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGXCPU, libc::SIG_IGN);
            Ok(())
        });
    }
    let mut child = command.spawn().expect("start the child");
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait for the child") {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the child still ran after 60 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.signal(), Some(libc::SIGXCPU), "{status:?}");

    // Four files at 0.7 s each: more than the first share, so the limit moved on
    // with each file; the fifth used all of its share.
    let mut got = &std::fs::read(&answers).expect("read the answers")[..];
    let mut functions = Vec::new();
    while let Some((head, rest)) = got.split_first_chunk::<8>() {
        let len = usize::try_from(u64::from_le_bytes(*head)).unwrap();
        let report: scan::ScanReport = serde_json::from_slice(&rest[..len]).expect("an answer");
        functions.push(report.functions.len());
        got = &rest[len..];
    }
    assert_eq!(functions, [1, 1, 1, 1]);
}
