#!/usr/bin/env bash
# test-auditor-tools.sh — audit-scan and audit-mem (tools/auditor-tools) against the confinement contract that lets
# a command pre-approve them by their absolute path, whatever arguments follow.
#   1. The sources: no network API; git, run only by src/confine.rs, is the one program either binary starts, and
#      confine.rs alone reads the environment (PATH, HOME, TMPDIR and TZ, for git); the items confine.rs copies
#      from audit-logs (Stop, refuse, working_tree, self_check, stays_inside, os_message, invalid, c_name, open_at,
#      and unsafe_char from its contract.rs) are unchanged copies; and hgit's -c pins are those of
#      scripts/lib/confine.sh's hgit, in its order.
#   2. Every case in fixtures/audit-scan/cases.txt and fixtures/audit-mem/cases.txt, in the working directory each
#      header describes: the exit status and the one stderr line as written, nothing on stdout, no file changed
#      inside or outside the working directory, and no canary text printed. Then scripts/rundir.sh and the binaries
#      over the same run directories and stores: rundir.sh check and audit-scan --out, and rundir.sh store and
#      audit-mem, accept the same ones and refuse the others in the same words.
#   3. The documented forms work, each with the contract marker --contract=1 where a rule names it: audit-scan to
#      stdout and into a run directory (an output of more than 64 KiB, the same both ways), and audit-mem's lifecycle
#      from init to warm, with the profile, an invariant and an anchored ruling, a ruling going stale, and init's
#      .gitignore. A call without the marker works as it did.
#   4. An installation inside the working directory, or under a path a quoted rule cannot match, is refused.
#   5. With AUDITOR_TOOLS_OLD_BIN=<dir> naming a build made before the contract (82edf43's target/release), that
#      build refuses --contract=1 in every form a rule pre-approves, before any effect; without it, a loud SKIP.
# Builds both binaries from tools/auditor-tools (cargo build --release --locked, into a temporary target
# directory), or tests the ones in AUDITOR_TOOLS_BIN=<dir> (CI's release build). Without cargo the suite is
# skipped, loudly; with REQUIRE_TOOLCHAIN=1 (CI) that is a failure.
# bash >= 3.2, git, python3, cmp. No network beyond cargo's own fetch of the locked crates.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PKG="$ROOT/tools/auditor-tools"
fails=0
ok()  { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1" >&2; fails=$((fails + 1)); }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$3', got '$2'"; fi; }
finish() {
  if [ "$fails" -ne 0 ]; then echo "test-auditor-tools: $fails assertion(s) FAILED" >&2; exit 1; fi
  echo "test-auditor-tools: all assertions passed"; exit 0
}

for tool in git python3 cmp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "test-auditor-tools: missing required tool: $tool" >&2; exit 3; }
done
T="$(mktemp -d "${TMPDIR:-/tmp}/auditor_tools_test.XXXXXX")" || exit 1
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
T="$(cd "$T" && pwd -P)" || exit 1
export GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
fgit() { GIT_CONFIG_GLOBAL=/dev/null git -c core.hooksPath=/dev/null "$@"; }

# ---------------------------------------------------------------------------
# 1. The sources.
# ---------------------------------------------------------------------------
if grep -nE 'std::net|TcpStream|UdpSocket|libc::(socket|connect|bind|listen|accept|exec[a-z]*|posix_spawn[a-z]*|fork|vfork|system|popen)\b' \
    "$PKG"/src/*.rs "$PKG"/src/bin/*.rs > "$T/apis"; then
  bad "source: auditor-tools names a network or process API ($(tr '\n' ' ' < "$T/apis"))"
else
  ok "source: auditor-tools names no network or process API of libc or std::net"
fi
others="$(grep -lE 'process::Command|Command::new|env::var|set_var|env::vars|libc::(getenv|setenv|putenv)' \
  "$PKG"/src/*.rs "$PKG"/src/bin/*.rs | sed 's#.*/tools/auditor-tools/##' | tr '\n' ' ')"
eq "source: only src/confine.rs starts a program (git) or reads the environment" "$others" "src/confine.rs "
python3 -I - "$PKG/src/confine.rs" "$PKG/audit-logs/src/confine.rs" "$PKG/audit-logs/src/contract.rs" \
  "$ROOT/scripts/lib/confine.sh" > "$T/agree" 2>&1 <<'PY'
import re, shlex, sys
ours, logs, contract, shell = (open(p, encoding="utf-8").read() for p in sys.argv[1:5])
def items(src):
    """Each top-level item with its doc comment and attributes, by name."""
    lines, out, i = src.split("\n"), {}, 0
    while i < len(lines):
        m = re.match(r"^(?:pub )?(?:fn|struct|const|static|enum) ([A-Za-z_0-9]+)", lines[i])
        if not m:
            i += 1
            continue
        start = i
        while start > 0 and lines[start - 1].startswith(("///", "#[")):
            start -= 1
        end = i
        if not lines[i].rstrip().endswith(";"):
            while not lines[end].startswith(("}", "];")):
                end += 1
        out[m.group(1)] = "\n".join(lines[start:end + 1])
        i = end + 1
    return out
a, b, c = items(ours), items(logs), items(contract)
bad = [n for n in ["Stop", "refuse", "working_tree", "self_check", "stays_inside", "os_message", "invalid",
                   "c_name", "open_at"] if n not in a or a.get(n) != b.get(n)]
body = lambda s: s[s.index("matches!"):] if s and "matches!" in s else None
if body(a.get("unsafe_char")) is None or body(a.get("unsafe_char")) != body(c.get("unsafe_char")):
    bad.append("unsafe_char")
print("differ:" + " ".join(bad))
hgit = shell[shell.index("hgit() {"):]
hgit = hgit[:hgit.index("\n}\n")]
words = shlex.split(hgit.replace("\\\n", " "), comments=False)
pins_sh = [words[i + 1] for i, w in enumerate(words) if w == "-c"]
start = ours.index("pub const HGIT_PINS")
pins_rs = re.findall(r'^    "([^"]*)",$', ours[start:ours.index("];", start)], re.M)
print("pins:" + ("same" if pins_sh == pins_rs and pins_sh else "sh=%s rs=%s" % (pins_sh, pins_rs)))
PY
eq "source: confine.rs's copies of audit-logs' items are unchanged" "$(sed -n 's/^differ://p' "$T/agree")" ""
eq "source: hgit's pins are confine.sh's, in its order" "$(sed -n 's/^pins://p' "$T/agree")" "same"

# ---------------------------------------------------------------------------
# 2. The binaries: AUDITOR_TOOLS_BIN when given, else a release build of the
#    package into a temporary target directory, with no warning.
# ---------------------------------------------------------------------------
if [ -n "${AUDITOR_TOOLS_BIN:-}" ]; then
  case "$AUDITOR_TOOLS_BIN" in /*) BIN="$AUDITOR_TOOLS_BIN" ;; *) BIN="$PWD/$AUDITOR_TOOLS_BIN" ;; esac
  for b in audit-scan audit-mem; do
    [ -f "$BIN/$b" ] && [ -x "$BIN/$b" ] || { echo "test-auditor-tools: $BIN/$b is not an executable file" >&2; exit 1; }
  done
  ok "build: testing the binaries in AUDITOR_TOOLS_BIN"
elif command -v cargo >/dev/null 2>&1; then
  if cargo build --release --locked --manifest-path "$PKG/Cargo.toml" --target-dir "$T/target" -p auditor-tools \
      > "$T/build.log" 2>&1; then
    BIN="$T/target/release"
    # A cargo config that names a build target puts the binaries under target/<triple>/.
    for b in "$T"/target/*/release/audit-mem; do [ -x "$BIN/audit-mem" ] || [ ! -x "$b" ] || BIN="${b%/audit-mem}"; done
    if grep -q '^warning' "$T/build.log"; then bad "build: cargo build --release printed warnings"; sed -n '1,40p' "$T/build.log" >&2
    else ok "build: cargo build --release --locked, with no warning"; fi
  else
    sed -n '1,60p' "$T/build.log" >&2
    bad "build: cargo build --release failed"
    finish
  fi
elif [ "${REQUIRE_TOOLCHAIN:-}" = 1 ]; then
  bad "REQUIRE_TOOLCHAIN=1, but cargo is not on PATH: audit-scan and audit-mem cannot be built, so their confinement is not checked"
  finish
else
  echo "SKIP test-auditor-tools: cargo is not on PATH, so audit-scan and audit-mem are not built and their confinement is NOT checked"
  exit 0
fi
SCAN="$BIN/audit-scan"
MEM="$BIN/audit-mem"

# ---------------------------------------------------------------------------
# 3. The case files. snapshot <dir>: every path under <dir>, never following a
#    link: type, size, link target and a hash of each regular file. expand <case
#    file> <out dir> <wt> <outside>: one file per case, its status, its stderr line
#    and each argument, NUL-terminated, the placeholders filled in.
# ---------------------------------------------------------------------------
CANARY="SEKRET4f1c9e2a"
snapshot() {
  python3 -I - "$1" <<'PY'
import hashlib, os, stat, sys
root = sys.argv[1]
for top, dirs, files in os.walk(root):
    dirs.sort()
    for name in sorted(dirs + files):
        p = os.path.join(top, name)
        st = os.lstat(p)
        line = [os.path.relpath(p, root), oct(stat.S_IFMT(st.st_mode)), str(st.st_size), str(st.st_nlink)]
        if stat.S_ISLNK(st.st_mode):
            line.append(os.readlink(p))
        elif stat.S_ISREG(st.st_mode):
            with open(p, "rb") as f:
                line.append(hashlib.sha256(f.read()).hexdigest())
        print("\t".join(line))
PY
}
expand() {
  mkdir "$2"
  python3 -I - "$1" "$2" "$3" "$4" <<'PY'
import os, re, sys
cases, out, wt, outside = sys.argv[1:5]
def plain(a):
    for k, v in (("@WT@", wt), ("@OUT@", outside), ("@NL@", "\n"), ("@ESC@", "\x1b"), ("@TAB@", "\t"),
                 ("@DEL@", "\x7f"), ("@RLO@", "\u202e"), ("@ZWSP@", "\u200b")):
        a = a.replace(k, v)
    return re.sub(r"@LONG:([0-9]+)@", lambda m: "a" * int(m.group(1)), a)
def shown(s):
    # As the binaries show a value in a message: cut after 200 bytes, then "...".
    t = ""
    for c in s:
        if len((t + c).encode("utf-8")) > 200:
            return t + "..."
        t += c
    return t
def fill(a):
    if a == "@EMPTY@":
        return ""
    parts = re.split(r"@SHOWN\((.*?)\)@", a)
    return "".join(shown(plain(p)) if i % 2 else plain(p) for i, p in enumerate(parts))
n = 0
with open(cases, encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        with open(os.path.join(out, "%03d" % n), "wb") as g:
            for word in fields[:1] + [fill(a) for a in fields[1:]]:
                g.write(os.fsencode(word) + b"\0")
        n += 1
PY
}
# shown <s>: <s> for a test line: control characters as ?, cut after 200 bytes.
shown() {
  local s=${1//[[:cntrl:]]/?}
  if [ "${#s}" -gt 200 ]; then s="${s:0:200}..."; fi
  printf '%s' "$s"
}
# run_cases <binary> <case file> <dir holding wt/ and outside/>: every case, from wt/, stdin from /dev/null.
run_cases() {
  local bin=$1 cases=$2 h=$3 name=${1##*/} n=0 cf want_rc want_err args word why rc
  expand "$cases" "$T/cases-$name" "$h/wt" "$h/outside"
  snapshot "$h" > "$T/$name.before"
  for cf in "$T/cases-$name"/*; do
    want_rc="" want_err="" args=()
    while IFS= read -r -d '' word; do
      if [ -z "$want_rc" ]; then want_rc=$word
      elif [ -z "$want_err" ]; then want_err=$word
      else args+=("$word"); fi
    done < "$cf"
    ( cd "$h/wt" && exec "$bin" ${args[@]+"${args[@]}"} ) < /dev/null > "$T/c.out" 2> "$T/c.err"
    rc=$?
    snapshot "$h" > "$T/$name.after"
    why=""
    [ "$rc" = "$want_rc" ] || why="$why exit $rc, not $want_rc;"
    [ "$(cat "$T/c.err")" = "$want_err" ] || why="$why stderr: $(shown "$(cat "$T/c.err")");"
    [ "$(grep -c '' "$T/c.err")" = 1 ] || why="$why stderr is not one line;"
    [ ! -s "$T/c.out" ] || why="$why printed on stdout;"
    cmp -s "$T/$name.before" "$T/$name.after" || why="$why changed files;"
    if grep -q "$CANARY" "$T/c.out" "$T/c.err"; then why="$why printed the canary;"; fi
    if [ -z "$why" ]; then ok "$name case: $(shown "${args[*]+${args[*]}}")"; else bad "$name case: $(shown "${args[*]+${args[*]}}"):$why"; fi
    cp "$T/$name.after" "$T/$name.before"
    n=$((n + 1))
  done
  NCASES=$n
}
# layout_common <dir>: <dir>/wt, a git repository, and <dir>/outside, holding the canary.
layout_common() {
  mkdir -p "$1/wt/src" "$1/outside"
  printf 'fn secret() { let k = "%s"; }\n' "$CANARY" > "$1/outside/secret.rs"
  printf 'protected\n' > "$1/outside/protected"
  fgit init -q "$1/wt"
  ln -s ../../outside/secret.rs "$1/wt/src/link.rs"
  ln -s ../outside "$1/wt/linkdir"
  mkfifo "$1/wt/fifo"
}
# run_dir <dir>: a run directory as rundir.sh new leaves it.
run_dir() { mkdir -p "$1" && printf '*\n' > "$1/.gitignore"; }

# audit-scan's working directory (fixtures/audit-scan/cases.txt).
H="$T/scan"
layout_common "$H"
W="$H/wt"
printf 'fn a() {}\n' > "$W/a.rs"
printf 'fn lib() { let x = 1 + 2; }\n' > "$W/src/lib.rs"
mv "$W/src/link.rs" "$W/src/linked.rs"
for d in audit_1 incident_1 audit_4 audit_5 audit_6 audit_7 audit_8; do run_dir "$W/$d"; done
mkdir "$W/audit_2"
ln -s audit_1 "$W/audit_3"
fgit -C "$W" add -f audit_4/.gitignore
ln -s ../../outside "$W/audit_5/out"
ln -s ../../outside/protected "$W/audit_6/prescan.json"
ln "$H/outside/protected" "$W/audit_7/prescan.json"
mkdir "$W/audit_8/prescan.json"
run_cases "$SCAN" "$HERE/fixtures/audit-scan/cases.txt" "$H"
if [ "$NCASES" -ge 80 ]; then ok "audit-scan: $NCASES cases"; else bad "audit-scan: only $NCASES cases read"; fi
eq "audit-scan: the file outside with a second name in the working tree is unchanged" "$(cat "$H/outside/protected")" protected

# audit-mem's working directory (fixtures/audit-mem/cases.txt).
H="$T/mem"
layout_common "$H"
W="$H/wt"
printf 'fn withdraw() {\n    require!(vault.balance >= amount);\n    vault.balance -= amount;\n}\n' > "$W/src/withdraw.rs"
( cd "$W" && "$MEM" init && "$MEM" put-finding --program-id VaultProg1111 --signature unchecked_sub@vault.balance \
    --root-cause 'unchecked subtraction' --title 'Vault underflow' --severity 3 \
  && "$MEM" rule --program-id VaultProg1111 --signature unchecked_sub@vault.balance --ruling FALSE_POSITIVE \
    --rationale guarded --by auditor --commit c0ffee1c0ffee1c0ffee1c0ffee1c0ffee1c0ffe --guard src/withdraw.rs:2 ) > "$T/mem.setup" 2>&1 \
  || { cat "$T/mem.setup" >&2; bad "audit-mem: the fixture store cannot be made"; finish; }
for d in audit_1 audit_4 audit_5 audit_6 audit_7 audit_8 audit_10 audit_11 audit_12 audit_13 incident_1 incident_2; do run_dir "$W/$d"; done
mkdir "$W/audit_2"
ln -s audit_1 "$W/audit_3"
fgit -C "$W" add -f audit_4/.gitignore
ln -s ../../outside "$W/audit_5/out"
mkdir "$W/audit_6/audit-mem.db"
ln "$H/outside/protected" "$W/audit_7/audit-mem.db"
for d in audit_1 audit_10 audit_12 audit_13; do
  ( cd "$W" && "$MEM" init --db "$d/audit-mem.db" ) > /dev/null || bad "audit-mem: init --db $d/audit-mem.db"
done
( cd "$W" && "$MEM" put-finding --db audit_13/audit-mem.db --program-id VaultProg1111 --signature s --root-cause r \
    --title t --severity 3 ) > /dev/null || bad "audit-mem: put-finding --db audit_13/audit-mem.db"
python3 -I - "$W" <<'PY'
import os, sqlite3, sys
wt = sys.argv[1]
c = sqlite3.connect(wt + "/audit_8/audit-mem.db")
c.execute("PRAGMA journal_mode=WAL")
c.execute("CREATE TABLE findings (finding_id TEXT PRIMARY KEY)")
c.commit()
c.close()
# A system SQLite may keep the WAL files after the close; this database is the
# header case only.
for side in ("-wal", "-shm"):
    if os.path.exists(wt + "/audit_8/audit-mem.db" + side):
        os.remove(wt + "/audit_8/audit-mem.db" + side)
open(wt + "/audit_12/audit-mem.db-wal", "w").close()
c = sqlite3.connect(wt + "/audit_10/audit-mem.db")
c.execute("CREATE VIEW v AS SELECT 1")
c.commit()
c.close()
c = sqlite3.connect(wt + "/audit_13/audit-mem.db")
c.execute("UPDATE findings SET status = ?", ("\x1b]0;x\x07",))
c.commit()
c.close()
with open(wt + "/audit_11/audit-mem.db", "w") as f:
    f.write("a findings list, not a database: " + "x" * 100 + "\n")
open(wt + "/incident_1/audit-mem.db", "w").close()
PY
run_cases "$MEM" "$HERE/fixtures/audit-mem/cases.txt" "$H"
if [ "$NCASES" -ge 120 ]; then ok "audit-mem: $NCASES cases"; else bad "audit-mem: only $NCASES cases read"; fi
eq "audit-mem: the file outside with a second name in the working tree is unchanged" "$(cat "$H/outside/protected")" protected

# ---------------------------------------------------------------------------
# 3b. Run directories and stores as scripts/rundir.sh sees them: rundir.sh
#     check <R> and audit-scan --out <R>/prescan.json accept the same run
#     directories and refuse the others for the same reason, in the same words;
#     so do rundir.sh store and audit-mem warm, for the in-tree store.
# ---------------------------------------------------------------------------
RUNDIR="$ROOT/scripts/rundir.sh"
H="$T/rundirs"
mkdir -p "$H/wt" "$H/outside"
fgit init -q "$H/wt"
W="$H/wt"
for d in audit_1 audit_3 audit_4 audit_5 audit_6 audit_7 audit_8 audit_9 audit_10 audit_13 audit_15 audit_16 incident_1; do
  mkdir "$W/$d"
done
mkdir "$W/audit_2"
printf '*\n' > "$W/audit_1/.gitignore"
printf '*' > "$W/audit_3/.gitignore"
printf '*\000' > "$W/audit_4/.gitignore"
printf '**' > "$W/audit_5/.gitignore"
printf '* ' > "$W/audit_6/.gitignore"
printf '*\r\n' > "$W/audit_7/.gitignore"
printf '*\n\n' > "$W/audit_8/.gitignore"
printf '*\n' > "$H/outside/gitignore"
ln -s ../../outside/gitignore "$W/audit_9/.gitignore"
printf '*\n' > "$W/audit_10/.gitignore"
ln -s ../../outside "$W/audit_10/out"
ln -s audit_1 "$W/audit_11"
printf 'x\n' > "$W/audit_12"
printf '*\n' > "$W/audit_13/.gitignore"
fgit -C "$W" add -f audit_13/.gitignore
mkdir "$W/audit_15/.gitignore"
printf '*\n' > "$W/audit_16/.gitignore"
printf '*\n' > "$W/incident_1/.gitignore"
dirs="audit_1 audit_2 audit_3 audit_4 audit_5 audit_6 audit_7 audit_8 audit_9 audit_10 audit_11 audit_12 audit_13 audit_14 audit_15 incident_1"
if [ "$(id -u)" -ne 0 ]; then
  mkdir "$W/audit_16/locked"
  chmod 000 "$W/audit_16/locked"
  dirs="$dirs audit_16"
fi
# said <file> <prefix>: the refusal line with its tool's prefix taken off, or "ok".
said() { if [ -s "$1" ]; then sed -e "s/^$2//" "$1"; else printf 'ok'; fi; }
for r in $dirs; do
  ( cd "$W" && "$RUNDIR" check "$r" ) > "$T/a.out" 2> "$T/a.err" < /dev/null
  [ $? -eq 0 ] && [ "$(cat "$T/a.out")" != "ok $r" ] && printf 'odd: %s\n' "$(cat "$T/a.out")" > "$T/a.err"
  ( cd "$W" && "$SCAN" --contract=1 . --out "$r/prescan.json" ) > /dev/null 2> "$T/b.err" < /dev/null
  eq "rundir.sh check and audit-scan --out agree on $r" \
    "$(said "$T/b.err" 'audit-scan: refused: --out ')" "$(said "$T/a.err" 'rundir: refused: the run directory ')"
done
[ "$(id -u)" -ne 0 ] && chmod 700 "$W/audit_16/locked"
for c in absent ok no-gitignore nul-gitignore link holds-link not-a-directory tracked database-a-directory; do
  S="$T/store-$c"
  mkdir -p "$S/wt" "$S/real"
  fgit init -q "$S/wt"
  case $c in
    link) printf '*\n' > "$S/real/.gitignore"; ln -s ../real "$S/wt/.audit-memory" ;;
    not-a-directory) printf 'x\n' > "$S/wt/.audit-memory" ;;
    absent) ;;
    *) mkdir "$S/wt/.audit-memory" ;;
  esac
  case $c in ok|holds-link|tracked|database-a-directory) printf '*\n' > "$S/wt/.audit-memory/.gitignore" ;; esac
  case $c in
    nul-gitignore) printf '*\000' > "$S/wt/.audit-memory/.gitignore" ;;
    holds-link) ln -s ../../real "$S/wt/.audit-memory/out" ;;
    tracked) fgit -C "$S/wt" add -f .audit-memory/.gitignore ;;
    database-a-directory) mkdir "$S/wt/.audit-memory/audit.db" ;;
  esac
  ( cd "$S/wt" && "$RUNDIR" store ) > /dev/null 2> "$T/a.err" < /dev/null
  ( cd "$S/wt" && "$MEM" warm --contract=1 --program-id VaultProg1111 ) > /dev/null 2> "$T/b.err" < /dev/null
  eq "rundir.sh store and audit-mem agree on an in-tree store: $c" \
    "$(said "$T/b.err" 'audit-mem: refused: ')" "$(said "$T/a.err" 'rundir: refused: ')"
done

# ---------------------------------------------------------------------------
# 4. The documented forms.
# ---------------------------------------------------------------------------
D="$T/docs"
layout_common "$D"
W="$D/wt"
python3 -I - "$W/src/big.rs" <<'PY'
import sys
with open(sys.argv[1], "w") as f:
    for i in range(3000):
        f.write("fn f%d(a: u64, b: u64) -> u64 { a + b * %d }\n" % (i, i))
PY
run_dir "$W/audit_1"
( cd "$W" && "$SCAN" --contract=1 ./src ) > "$T/scan.stdout" 2> "$T/scan.err"
eq "audit-scan: a directory to stdout, exit 0, nothing on stderr" "$?:$(cat "$T/scan.err")" "0:"
size=$(wc -c < "$T/scan.stdout" | tr -d ' ')
if [ "$size" -gt 65536 ]; then ok "audit-scan: the report is larger than a pipe buffer ($size bytes)"; else bad "audit-scan: the report is only $size bytes"; fi
( cd "$W" && "$SCAN" --contract=1 ./src --out audit_1/prescan.json ) > "$T/scan.out2" 2>&1
eq "audit-scan: --out audit_1/prescan.json, exit 0, prints nothing" "$?:$(cat "$T/scan.out2")" "0:"
if cmp -s "$T/scan.stdout" "$W/audit_1/prescan.json"; then ok "audit-scan: --out holds what stdout printed"
else bad "audit-scan: --out differs from stdout"; fi
( cd "$W" && "$SCAN" --contract=1 ./src | cat ) > "$T/scan.piped" 2>&1
if cmp -s "$T/scan.stdout" "$T/scan.piped"; then ok "audit-scan: the whole report goes through a pipe"; else bad "audit-scan: the piped report differs"; fi
( cd "$W" && "$SCAN" ./src ) > "$T/scan.bare" 2>&1
if cmp -s "$T/scan.stdout" "$T/scan.bare"; then ok "audit-scan: without --contract=1 it works as it did"; else bad "audit-scan: without --contract=1 the report differs"; fi
( cd "$W" && "$SCAN" --contract=1 . --out audit_1/prescan.json --pretty ) > /dev/null 2>&1
eq "audit-scan: its own output is replaced" "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["files_scanned"])' "$W/audit_1/prescan.json")" 1
eq "audit-scan: a link in the tree is listed, not followed" \
  "$(python3 -I -c 'import json,sys; print(" ".join(s["file"] for s in json.load(open(sys.argv[1]))["skipped"]))' "$W/audit_1/prescan.json")" \
  "./linkdir ./src/link.rs"

P=VaultProg1111
S=unchecked_sub@vault.balance
printf 'fn withdraw() {\n    require!(vault.balance >= amount);\n    vault.balance -= amount;\n}\n' > "$W/src/withdraw.rs"
mem() { local sub=$1; shift; ( cd "$W" && "$MEM" "$sub" --contract=1 "$@" ) 2>&1; }
eq "audit-mem: warm with no store prints an empty context" "$(mem warm --program-id "$P")" '{"profile":null,"invariants":[],"open_fp_rulings":[],"truncated":0}'
eq "audit-mem: ... and so it does without --contract=1" "$( ( cd "$W" && "$MEM" warm --program-id "$P" ) 2>&1)" '{"profile":null,"invariants":[],"open_fp_rulings":[],"truncated":0}'
eq "audit-mem: init makes the store" "$(mem init)" "initialized .audit-memory/audit.db"
eq "audit-mem: ... with its .gitignore of *" "$(cat "$W/.audit-memory/.gitignore")" "*"
eq "audit-mem: ... which git ignores, with no other step" "$(fgit -C "$W" status --porcelain -- .audit-memory)" ""
out=$(mem put-finding --program-id "$P" --signature "$S" --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee1 --audit-n audit-1 --file src/withdraw.rs --line 3 --verdict TRUE_POSITIVE)
eq "audit-mem: put-finding records a new finding OPEN" "${out%% *}" OPEN
mem set-status --program-id "$P" --signature "$S" --root-cause 'unchecked subtraction can underflow vault balance' --status FIXED > /dev/null
out=$(mem put-finding --program-id "$P" --signature "$S" --root-cause 'unchecked subtraction can underflow vault balance' \
  --title 'Vault balance underflow' --severity 3 --commit c0ffee3 --audit-n audit-3)
eq "audit-mem: a FIXED finding seen again is REGRESSED" "${out%% *}" REGRESSED
eq "audit-mem: profile records the protocol profile" \
  "$(mem profile --program-id "$P" --protocol-class vault --trust-assumptions-json '{"admin":"3-of-5 multisig"}' --oracle-set 'pyth SOL/USD')" \
  "profile $P recorded"
eq "audit-mem: invariant records an invariant" \
  "$(mem invariant --program-id "$P" --statement 'total_shares == shares_mint.supply' --status Unproven --cited-line src/vault.rs:88)" \
  "invariant 1 recorded"
eq "audit-mem: rule records an anchored ruling" \
  "$(mem rule --program-id "$P" --signature "$S" --ruling FALSE_POSITIVE --rationale 'guarded by the require! above it' --by auditor --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe --guard src/withdraw.rs:2)" \
  "ruling 1 recorded (FALSE_POSITIVE)"
( cd "$W" && "$MEM" check --contract=1 --program-id "$P" --signature "$S" --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe ) > "$T/check.out" 2>&1
eq "audit-mem: check at the ruling's commit, the guard unchanged: suppressed (exit 0)" \
  "$?:$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["suppressed"])' "$T/check.out")" "0:True"
( cd "$W" && "$MEM" check --contract=1 --program-id "$P" --signature "$S" --commit c0ffee4c0ffee4c0ffee4c0ffee4c0ffee4c0ffe ) > "$T/check.out" 2>&1
eq "audit-mem: check at another commit: stale, not suppressed (exit 1)" \
  "$?:$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["stale"])' "$T/check.out")" \
  "1:ruled at commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe, checked at c0ffee4c0ffee4c0ffee4c0ffee4c0ffee4c0ffe"
printf 'fn withdraw() {\n    require!(vault.balance > amount);\n    vault.balance -= amount;\n}\n' > "$W/src/withdraw.rs"
( cd "$W" && "$MEM" check --contract=1 --program-id "$P" --signature "$S" --commit c0ffee3c0ffee3c0ffee3c0ffee3c0ffee3c0ffe ) > "$T/check.out" 2>&1
eq "audit-mem: check after the guard changed: stale, not suppressed (exit 1)" \
  "$?:$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["stale"])' "$T/check.out")" \
  "1:the guard at src/withdraw.rs:2 no longer holds the lines ruled on"
eq "audit-mem: regressions lists the regressed finding" \
  "$(mem regressions --program-id "$P" | python3 -I -c 'import json,sys; r=json.load(sys.stdin); print(len(r["regressions"]), r["truncated"])')" "1 0"
eq "audit-mem: profile keeps a value it replaces" \
  "$(mem profile --program-id "$P" --trust-assumptions-json '{"admin":"fully trusted"}')" \
  "profile $P recorded, replacing trust_assumptions_json (warm lists what it held under changed)"
mem warm --db .audit-memory/audit.db --program-id "$P" > "$T/warm.out"
eq "audit-mem: warm returns the profile, the invariant and the ruling" \
  "$(python3 -I -c 'import json,sys; w=json.load(open(sys.argv[1])); print(w["profile"]["protocol_class"], len(w["invariants"]), w["open_fp_rulings"][0]["guard"])' "$T/warm.out")" \
  "vault 1 src/withdraw.rs:2"
eq "audit-mem: ... with the value the profile replaced" \
  "$(python3 -I -c 'import json,sys; c=json.load(open(sys.argv[1]))["profile"]["changed"][0]; print(c["field"], c["previous"])' "$T/warm.out")" \
  'trust_assumptions_json {"admin":"3-of-5 multisig"}'

# ---------------------------------------------------------------------------
# 5. Where it runs from: never from inside the working directory, nor from a
#    path a quoted rule cannot match.
# ---------------------------------------------------------------------------
mkdir -p "$W/tools/auditor-tools/target/release" "$T/dollar\$dir" "$T/quote\"dir"
for b in audit-scan audit-mem; do
  cp "$BIN/$b" "$W/tools/auditor-tools/target/release/$b"
  cp "$BIN/$b" "$T/dollar\$dir/$b"
  cp "$BIN/$b" "$T/quote\"dir/$b"
  for c in "inside the working directory|$W/tools/auditor-tools/target/release/$b" \
           "under a path holding \$|$T/dollar\$dir/$b" "under a path holding a quote|$T/quote\"dir/$b"; do
    case "$b" in audit-scan) set -- . ;; *) set -- warm --program-id "$P" ;; esac
    ( cd "$W" && "${c#*|}" "$@" ) > "$T/c1.out" 2> "$T/c1.err"
    code=$?
    if [ "$code" = 2 ] && [ ! -s "$T/c1.out" ] && [ "$(grep -c "^$b: refused: " "$T/c1.err")" = 1 ]; then
      ok "$b: an installation ${c%%|*} is refused (exit 2, no output)"
    else
      bad "$b: an installation ${c%%|*} -> exit $code ($(tr '\n' ' ' < "$T/c1.err"))"
    fi
  done
  ( cd "$W" && "$W/tools/auditor-tools/target/release/$b" "$@" ) > /dev/null 2> "$T/c1.err"
  eq "$b: an installation inside the working directory is refused in the words of scripts/lib/confine.sh" "$(cat "$T/c1.err")" \
    "$b: refused: the installation lies inside the working directory; install it outside the tree under audit, or run from a directory that does not contain it (Rule 11e)"
done

# ---------------------------------------------------------------------------
# 6. A build made before the contract: AUDITOR_TOOLS_OLD_BIN=<dir> names one
#    (82edf43's target/release, which writes wherever --db and --out say). In
#    every form a rule pre-approves, with --contract=1 where the rule puts it and
#    paths it would write outside the working directory, it refuses the marker:
#    exit 2, nothing on stdout, nothing made or changed. This build makes or
#    changes nothing either: it refuses each call that names such a path, and
#    runs the one that names none (exit 0 here).
# ---------------------------------------------------------------------------
if [ -n "${AUDITOR_TOOLS_OLD_BIN:-}" ]; then
  case "$AUDITOR_TOOLS_OLD_BIN" in /*) OLD="$AUDITOR_TOOLS_OLD_BIN" ;; *) OLD="$PWD/$AUDITOR_TOOLS_OLD_BIN" ;; esac
  for b in audit-scan audit-mem; do
    [ -f "$OLD/$b" ] && [ -x "$OLD/$b" ] || { bad "old build: $OLD/$b is not an executable file"; finish; }
  done
  H="$T/old"
  layout_common "$H"
  W="$H/wt"
  run_dir "$W/audit_1"
  printf 'kept\n' > "$H/outside/sentinel.txt"
  nforms=0
  while IFS='|' read -r b now form; do
    [ -n "$b" ] || continue
    form=${form//@OUT@/$H/outside}
    read -r -a words <<< "$form"
    snapshot "$H" > "$T/old.before"
    ( cd "$W" && exec "$OLD/$b" "${words[@]}" ) < /dev/null > "$T/old.out" 2> "$T/old.err"
    code=$?
    snapshot "$H" > "$T/old.after"
    if [ "$code" = 2 ] && [ ! -s "$T/old.out" ] && [ -s "$T/old.err" ] && cmp -s "$T/old.before" "$T/old.after"; then
      ok "the build made before the contract refuses $b $form (exit 2, nothing made)"
    else
      bad "the build made before the contract: $b $form -> exit $code, $(wc -c < "$T/old.out" | tr -d ' ') bytes on stdout$(cmp -s "$T/old.before" "$T/old.after" || printf ', files changed')"
    fi
    ( cd "$W" && exec "$BIN/$b" "${words[@]}" ) < /dev/null > "$T/old.out" 2> "$T/old.err"
    code=$?
    snapshot "$H" > "$T/old.after"
    if [ "$code" = "$now" ] && cmp -s "$T/old.before" "$T/old.after"; then
      ok "this build: $b $form -> exit $now, nothing made"
    else
      bad "this build: $b $form -> exit $code, not $now$(cmp -s "$T/old.before" "$T/old.after" || printf ', files changed')"
    fi
    nforms=$((nforms + 1))
  done <<'FORMS'
audit-scan|2|--contract=1 . --out @OUT@/sentinel.txt
audit-scan|0|--contract=1 .
audit-mem|2|init --contract=1 --db @OUT@/made-by-init/x.db
audit-mem|2|warm --contract=1 --db @OUT@/made-by-warm/x.db --program-id p
audit-mem|2|check --contract=1 --db @OUT@/made-by-check/x.db --program-id p --signature s
audit-mem|2|regressions --contract=1 --db @OUT@/made-by-regressions/x.db --program-id p
audit-mem|2|put-finding --contract=1 --db @OUT@/elsewhere/deep/x.db --program-id p --signature s --root-cause r --title t --severity 3
audit-mem|2|profile --contract=1 --db @OUT@/made-by-profile/x.db --program-id p --notes n
audit-mem|2|invariant --contract=1 --db @OUT@/made-by-invariant/x.db --program-id p --statement s
FORMS
  eq "old build: the forms tried" "$nforms" 9
  eq "old build: the file outside is unchanged" "$(cat "$H/outside/sentinel.txt")" kept
else
  echo "SKIP old build: AUDITOR_TOOLS_OLD_BIN is not set, so it is NOT checked that a build made before the contract refuses --contract=1 (build 82edf43 and name its tools/auditor-tools/target/release)"
fi

finish
