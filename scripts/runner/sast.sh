#!/bin/bash
# sast.sh — static analysis of the code under audit with semgrep, which parses the code and runs none of it,
# and whose git never reads the repository's config (below), so it needs no execution mode (OUTPUT-RULES.md
# Rules 11a and 11b).
#
#   "${CLAUDE_PLUGIN_ROOT}/scripts/runner/sast.sh" semgrep --run <R> --path <path> --ruleset <id> [--ruleset <id>]...
#
# Run it directly by its quoted absolute path, with no bash in front, from the working directory under
# audit. A refusal is one stderr line, "sast: refused: <reason>", with exit 64, before anything is sent; a
# blocker is one stderr line, "sast: blocker: <reason>", with exit 3.
#
# --path is a confined directory or regular file under the working directory. semgrep could read and quote
# what a symbolic link under it points to: strict mode (OUTPUT-RULES.md Rule 11f) refuses a link that
# resolves outside --path, and a folder past 500000 entries or that cannot be read in full. Otherwise a link
# that resolves outside the working directory is left out, and so are a link to a folder that leads to one
# and what the check cannot read; any other link is scanned as semgrep finds it. semgrep then scans, instead
# of --path, the entries of each folder on the way to what is left out, never that (node_modules and target
# folders, which the check walks last, are left out whole when they hold it), in several calls when they are
# too many for one, and the last line names what was left out. Past 500000 entries the check stops, and the
# scan goes on with a note. Each --ruleset is one of
# p/rust, p/trailofbits, p/typescript, p/javascript, p/python, p/golang, p/secrets, p/github-actions and
# p/solidity, each at most once. The scan runs
#   semgrep scan --config <id>... --metrics=off --disable-version-check --sarif --output <scratch> --error -- <path>
# from a scratch directory outside the working directory, in the cleaned environment of
# scripts/lib/isolation.sh with the real HOME kept (semgrep's own install may live there), its settings file
# in the scratch directory, no version check and no metrics, and the proxy variables: semgrep downloads the
# rulesets from semgrep.dev, and before that one row goes to <R>/disclosures.tsv. semgrep lists the files of a
# folder in a git project with git, and the git it starts would read the repository's config, which can name
# a program for git to run; so every git semgrep starts gets GIT_DIR, never the repository's own: a copy of
# its index and info/exclude under a config of sast.sh's own (the index alone when info/exclude cannot be
# copied, which the last line then says), or, where sast.sh makes no copy, a path that does not exist (git
# fails, and semgrep lists the files itself, ignored ones included, which the last line then says, with the
# reason). git's ignore rules leave out untracked files only. semgrep (1.117.0 and later) also reads every
# .semgrepignore of its project, the nearest folder at or above <path> holding a .git (or a .hg, _darcs or
# .svn folder), else <path>: for a folder, the last line names each one from the project down to <path> and
# under it; a file given as <path> is scanned whatever they say.
# AUDITOR_RUN_TIMEOUT (whole seconds, 1 to 86400, default 1800) bounds the scan, all its calls together, under
# the watchdog of isolation.sh's iso_watch.
#
# Output: the SARIF in <R>/sast/semgrep-<n>.sarif, with one run for each call, and semgrep's own messages in
# <R>/sast/semgrep-<n>.log.
# The last stdout line gives the number of results and where they are. The scratch directory is removed on
# exit.
#
# Exit: 0 no results · 1 results · 3 blocker (semgrep missing or failing, no SARIF, the watchdog) ·
# 64 refused. Needs bash >= 3.2, semgrep, python3, git, env, find, mkdir, mktemp, rm, chmod, cat and date.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'sast: refused: the installation cannot be resolved\n' >&2; exit 64; }
case "$here" in
  */scripts/runner) root=${here%/scripts/runner} ;;
  *) printf 'sast: refused: sast.sh runs from <auditor-skill root>/scripts/runner\n' >&2; exit 64 ;;
esac
. "$root/scripts/lib/confine.sh" || { printf 'sast: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 64; }
. "$root/scripts/lib/isolation.sh" || { printf 'sast: refused: scripts/lib/isolation.sh cannot be read\n' >&2; exit 64; }
confine_init sast "$root"
confine_need env git find mkdir mktemp rm chmod cat date
WT=$CONFINE_WT

RULESETS='p/rust p/trailofbits p/typescript p/javascript p/python p/golang p/secrets p/github-actions p/solidity'
USAGE="usage: sast.sh semgrep --run <R> --path <path> --ruleset <id> [--ruleset <id>]..., with the rulesets ${RULESETS// /, }"
TOOL=scripts/runner/sast.sh

refuse() { confine_refuse "$1"; }
blocker() { printf 'sast: blocker: %s\n' "$1" >&2; exit 3; }

# ---- arguments (all checked before anything is sent) --------------------------------------------------
[ $# -gt 0 ] && [ "$1" = semgrep ] || refuse "$USAGE"
shift
RUN_ARG="" PATH_ARG="" seen=" "
SETS=()
while [ $# -gt 0 ]; do
  opt=$1
  shift
  case "$opt" in
    --run|--path|--ruleset) [ $# -gt 0 ] || refuse "$opt needs a value" ;;
    *) refuse "$(confine_text "$opt") is not an argument sast.sh takes ($USAGE)" ;;
  esac
  case "$opt" in
    --ruleset)
      case "$1" in *[!a-z/-]*|'') refuse "--ruleset takes one of ${RULESETS// /, }, not $(confine_text "$1")" ;; esac
      case " $RULESETS " in *" $1 "*) ;; *) refuse "--ruleset takes one of ${RULESETS// /, }, not $(confine_text "$1")" ;; esac
      for s in ${SETS[@]+"${SETS[@]}"}; do [ "$s" != "$1" ] || refuse "give --ruleset $1 once"; done
      SETS+=("$1") ;;
    *)
      case "$seen" in *" $opt "*) refuse "give $opt once" ;; esac
      seen="$seen$opt "
      case "$opt" in --run) RUN_ARG=$1 ;; --path) PATH_ARG=$1 ;; esac ;;
  esac
  shift
done
case "$seen" in *" --run "*) ;; *) refuse "give --run <R>, the run directory ($USAGE)" ;; esac
case "$seen" in *" --path "*) ;; *) refuse "give --path, the directory or file to scan ($USAGE)" ;; esac
[ "${#SETS[@]}" -gt 0 ] || refuse "give at least one --ruleset ($USAGE)"
confine_rundir "$RUN_ARG" "--run"
R=$CONFINE_RUN
if [ "$PATH_ARG" = . ]; then
  PATH_REL=.
else
  confine_path "$PATH_ARG" "--path" any
  [ "$CONFINE_TYPE" != none ] || refuse "--path does not exist: $(confine_text "$PATH_ARG")"
  PATH_REL=$CONFINE_REL
fi
if [ "$PATH_REL" = . ]; then TARGET=$WT; else TARGET=$WT/$PATH_REL; fi
# A symbolic link under the path that resolves outside it would let semgrep read, and quote into the SARIF,
# a file the audit never named (a key, say), or reach one through another directory. .git is not scanned and
# not looked in. Strict mode (OUTPUT-RULES.md Rule 11f) refuses such a link here; otherwise the scan leaves out
# the links that resolve outside the working directory (LINKS_PY, below).
if [ -d "$TARGET" ] && [ "$CONFINE_STRICT" = 1 ]; then
  command -v python3 >/dev/null 2>&1 || refuse "python3 is not on PATH, so the links under --path cannot be checked"
  out=$( (cd / && exec python3 -I -c 'import os, re, sys
top = sys.argv[1]
inside = os.path.realpath(top) + os.sep
n = 0
for d, dirs, files in os.walk(top, onerror=lambda e: (print("cannot be read"), sys.exit(2))):
    dirs[:] = [x for x in dirs if x != ".git"]
    for name in dirs + files:
        n += 1
        if n > 500000:
            print("holds more than 500000 entries")
            sys.exit(2)
        p = os.path.join(d, name)
        if os.path.islink(p) and not (os.path.realpath(p) + os.sep).startswith(inside):
            print(re.sub(r"[\x00-\x1f\x7f]", "?", os.path.relpath(p, sys.argv[2]))[:200])
            sys.exit(1)' "$TARGET" "$WT") 2>/dev/null)
  case $? in
    0) ;;
    1) refuse "--path holds a symbolic link that resolves outside it, $out; semgrep could read and quote what it points to, so scan a directory without it" ;;
    *) refuse "the links under --path cannot be checked: it ${out:-cannot be read}" ;;
  esac
fi
CAP=${AUDITOR_RUN_TIMEOUT:-1800}
{ case "$CAP" in ''|*[!0-9]*) false ;; *) [ "${#CAP}" -le 5 ] && [ "$CAP" -ge 1 ] && [ "$CAP" -le 86400 ] ;; esac; } ||
  refuse "AUDITOR_RUN_TIMEOUT is '$(confine_text "$CAP")', not a whole number of seconds from 1 to 86400"
LIMIT=$((10#$CAP))
iso_tmp_outside
confine_disclosures_ok "$R" || refuse "$R/disclosures.tsv is not a regular file with one link whose first line is the header, so no row can be added to it"

# ---- the tools, scratch and the watchdog -------------------------------------------------------------
command -v semgrep >/dev/null 2>&1 || blocker "semgrep is not on PATH, so the scan cannot run here — nothing was sent."
command -v python3 >/dev/null 2>&1 || blocker "python3 is not on PATH — nothing was sent."
S=""
cleanup() {
  case "${ISO_SCRATCH:-}" in */auditor-sast.??????) chmod -R u+rwX "$ISO_SCRATCH" 2>/dev/null; rm -rf "$ISO_SCRATCH" 2>/dev/null ;; esac
}
on_signal() {
  if [ -n "${ISO_WATCH_PID:-}" ]; then
    kill -TERM "$ISO_WATCH_PID" 2>/dev/null
    wait "$ISO_WATCH_PID" 2>/dev/null
  fi
  exit "$1"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
iso_scratch sast
S=$ISO_SCRATCH
cd / || blocker "cannot leave the working directory for /"
iso_env "$S" keep-home || blocker "cannot prepare the cleaned environment in $S — nothing was sent."
ISO_ENV+=("SEMGREP_SETTINGS_FILE=$S/semgrep-settings.yml" "SEMGREP_LOG_FILE=$S/semgrep.log" SEMGREP_ENABLE_VERSION_CHECK=0
  SEMGREP_SEND_METRICS=off)

# What the links check runs outside strict mode, with python3 -I, from /: "<scan root> <working directory>
# <targets>". It walks real folders only, each once (.git aside, node_modules and target folders after the
# rest), at most 500000 entries in all: the scan root, then each folder inside the working directory that a
# link names, since semgrep can reach what lies there through the link. It finds the symbolic links that
# resolve outside the working directory, the links to a folder that leads to one (through any number of such
# links), and the folders and entries it cannot read. Under the scan root those are left out; with none it
# exits 0. Otherwise it writes to <targets>, NUL-separated, the paths semgrep scans instead of the root: the
# entries of each folder on the way to what is left out, so semgrep never gets a path that is or passes
# through it. A node_modules or target folder on the way is left out whole, and when that list passes 5000
# paths or 256 KiB, every folder on the way below the root is. That list goes to <targets>.1, or, when the
# entries of the root alone pass those bounds, to <targets>.1 to <targets>.<k>, one for each semgrep call;
# exit 1. Each line it prints is a tab-separated note for the last line: left, through, whole or unread,
# each with <n> <first five>, stopped <entries>, and calls <k> <paths>. Exit 2, with the reason, when the
# root cannot be read or none is left.
LINKS_PY='import bisect, os, re, sys

# Real paths throughout, as os.path.realpath gives the folders links name.
top, wt, out = os.path.realpath(sys.argv[1]), os.path.realpath(sys.argv[2]), sys.argv[3]
LIMIT, MOST, BYTES = 500000, 5000, 262144
LATER = ("node_modules", "target")
inside = wt + os.sep


def shown(p):
    return re.sub(r"[\x00-\x1f\x7f]", "?", os.path.relpath(p, wt))[:200]


def few(paths):
    more = len(paths) - 5
    return ", ".join(shown(p) for p in paths[:5]) + (" and %d more" % more if more > 0 else "")


def listed(d):
    with os.scandir(d) as it:
        return sorted((e for e in it if e.name != ".git"), key=lambda e: e.name)


def below(p, d):
    return p.startswith(d + os.sep)


n, stopped, seen = 0, False, set()
outside, unread, jumps = [], [], {}
roots = [top]
while roots and not stopped:
    pending, later = [roots.pop(0)], []
    for first in (True, False):
        while pending and not stopped:
            d = pending.pop()
            try:
                st = os.stat(d)
                if (st.st_dev, st.st_ino) in seen:
                    continue
                seen.add((st.st_dev, st.st_ino))
                entries = listed(d)
            except OSError:
                unread.append(d)
                continue
            for e in reversed(entries):
                n += 1
                if n > LIMIT:
                    stopped = True
                    break
                try:
                    if e.is_symlink():
                        real = os.path.realpath(e.path)
                        if not (real + os.sep).startswith(inside):
                            outside.append(e.path)
                        elif os.path.isdir(real):
                            jumps[e.path] = real
                            roots.append(real)
                    elif e.is_dir(follow_symlinks=False):
                        (later if first and e.name in LATER else pending).append(e.path)
                except OSError:
                    unread.append(e.path)
        pending, later = later, []
if top in unread:
    print("--path cannot be read, so its symbolic links cannot be checked")
    sys.exit(2)
# A link to a folder that holds, at any depth, what is left out is left out too, until nothing changes.
bad = sorted(set(outside) | set(unread))
through = set()


def holds_bad(d):
    i = bisect.bisect_left(bad, d)
    j = bisect.bisect_left(bad, d + os.sep)
    return (i < len(bad) and bad[i] == d) or (j < len(bad) and below(bad[j], d))


changed = True
while changed:
    changed = False
    for link, real in sorted(jumps.items()):
        if link not in through and holds_bad(real):
            through.add(link)
            bisect.insort(bad, link)
            changed = True
gone = set(p for p in bad if below(p, top))
notes = []
if stopped:
    notes.append("stopped\t%d" % LIMIT)
if not gone:
    print("\n".join(notes))
    sys.exit(0)
way = set()
for p in gone:
    p = os.path.dirname(p)
    while below(p, top):
        way.add(p)
        p = os.path.dirname(p)


class Over(Exception):
    pass


def cover(d, deep, targets, whole):
    for e in listed(d):
        if e.path in gone:
            continue
        if e.path in way and deep and e.name not in LATER:
            try:
                cover(e.path, deep, targets, whole)
            except OSError:
                whole.append(e.path)
        elif e.path in way:
            whole.append(e.path)
        else:
            targets.append(e.path)
            if deep and len(targets) > MOST:
                raise Over


# The deep list when it fits one semgrep call; otherwise the shallow one, whatever its length.
for deep in (True, False):
    targets, whole = [], []
    try:
        cover(top, deep, targets, whole)
    except Over:
        continue
    except OSError:
        print("--path cannot be listed again to leave out its links")
        sys.exit(2)
    if not deep or sum(len(os.fsencode(t)) + 1 for t in targets) <= BYTES:
        break
if not targets:
    print("nothing under --path is left to scan once what the link check leaves out (%s) is left out" % few(sorted(gone)))
    sys.exit(2)
# One file of paths for each semgrep call, each within MOST paths and BYTES bytes.
calls, size = [[]], 0
for t in targets:
    b = len(os.fsencode(t)) + 1
    if calls[-1] and (len(calls[-1]) == MOST or size + b > BYTES):
        calls.append([])
        size = 0
    calls[-1].append(t)
    size += b
for i, call in enumerate(calls, 1):
    with open("%s.%d" % (out, i), "wb") as f:
        for t in call:
            f.write(os.fsencode(t) + b"\0")
said = [("left", sorted(p for p in outside if p in gone)), ("through", sorted(p for p in through if p in gone)),
        ("whole", whole), ("unread", sorted(p for p in unread if p in gone))]
notes.append("calls\t%d\t%d" % (len(calls), len(targets)))
print("\n".join(["%s\t%d\t%s" % (k, len(v), few(v)) for k, v in said if v] + notes))
sys.exit(1)
'
# What merges the SARIF of several semgrep calls, with python3 -I, from /: "<out> <sarif>...": each a regular
# file holding a SARIF log, whose runs go, in order, into one log written to <out>; exit 1 when one is not.
MERGE_PY='import json, os, stat, sys

out, parts = sys.argv[1], sys.argv[2:]
merged = None
for p in parts:
    st = os.lstat(p)
    if not stat.S_ISREG(st.st_mode) or not st.st_size:
        sys.exit(1)
    with open(p, encoding="utf-8") as f:
        log = json.load(f)
    if not isinstance(log, dict) or not isinstance(log.get("runs"), list):
        sys.exit(1)
    if merged is None:
        merged = log
    else:
        merged["runs"].extend(log["runs"])
with open(out, "x", encoding="utf-8") as f:
    json.dump(merged, f)
'
TARGETS=("$TARGET")
LINKS_NOTE=""
CALLS=1 PATHS=1
# targets_of <i>: TARGETS from the link check's list for semgrep call <i>.
targets_of() {
  TARGETS=()
  while IFS= read -r -d '' t; do TARGETS+=("$t"); done < "$S/targets.$1"
}
if [ -d "$TARGET" ] && [ "$CONFINE_STRICT" = 0 ]; then
  rc=0
  report=$( (cd / && exec python3 -I -c "$LINKS_PY" "$TARGET" "$WT" "$S/targets") 2>/dev/null) || rc=$?
  case "$rc" in
    0|1) ;;
    2) blocker "$report — nothing was sent." ;;
    *) blocker "the links under --path cannot be checked (python3 stopped with status $rc) — nothing was sent." ;;
  esac
  # Line by line with no here-string: bash 3.2 writes a here-string to a file in the working directory.
  while [ -n "$report" ]; do
    line=${report%%$'\n'*}
    case "$report" in *$'\n'*) report=${report#*$'\n'} ;; *) report="" ;; esac
    key=${line%%$'\t'*} list=${line#*$'\t'}
    count=${list%%$'\t'*} list=${list#*$'\t'}
    case "$key:$count" in
      left:1) LINKS_NOTE="$LINKS_NOTE; note: left out 1 symbolic link that resolves outside the working directory: $list" ;;
      left:*) LINKS_NOTE="$LINKS_NOTE; note: left out $count symbolic links that resolve outside the working directory: $list" ;;
      through:1) LINKS_NOTE="$LINKS_NOTE; note: left out 1 symbolic link to a folder that leads to such a link: $list" ;;
      through:*) LINKS_NOTE="$LINKS_NOTE; note: left out $count symbolic links to folders that lead to such links: $list" ;;
      whole:1) LINKS_NOTE="$LINKS_NOTE; note: left out whole 1 folder that holds such a link: $list" ;;
      whole:*) LINKS_NOTE="$LINKS_NOTE; note: left out whole $count folders that hold such links: $list" ;;
      unread:1) LINKS_NOTE="$LINKS_NOTE; note: left out 1 folder or entry the link check could not read: $list" ;;
      unread:*) LINKS_NOTE="$LINKS_NOTE; note: left out $count folders or entries the link check could not read: $list" ;;
      stopped:*) LINKS_NOTE="$LINKS_NOTE; note: the link check stopped at $count entries" ;;
      calls:*) CALLS=$count PATHS=$list ;;
    esac
  done
  [ "$rc" != 1 ] || targets_of 1
fi

# semgrep's project, found as semgrep finds it (Semgrepignore v2): the nearest folder at or above the scan root
# (a file's folder, for a file) holding a .git, or a .hg, _darcs or .svn folder, else that folder itself.
d=$TARGET
[ -d "$d" ] || d=${d%/*}
p=$d PROJ=$d VCS=none
while :; do
  if [ -e "$p/.git" ]; then PROJ=${p:-/} VCS=git; break; fi
  if [ -d "$p/.hg" ] || [ -d "$p/_darcs" ] || [ -d "$p/.svn" ]; then PROJ=${p:-/} VCS=other; break; fi
  [ -n "$p" ] || break
  p=${p%/*}
done

# semgrep's git. For a folder in a git project semgrep lists the files with "git -C <scan root> ls-files", the
# git on its PATH, whatever --no-git-ignore says (src/targeting/Find_targets.ml in its source), and that git
# would read the repository's config, which can name a program for git to run (core.fsmonitor, hooks, a
# filter). So every git semgrep starts gets GIT_DIR, which stops git looking for a repository: when the
# project is the working directory or a folder in it, and its .git a directory, a repository in the scratch
# directory holding a copy of the index (whose entries must all lie inside the project) and info/exclude under
# a config of sast.sh's own, with GIT_WORK_TREE the project, so git lists the same tracked and untracked files
# (an info/exclude that cannot be copied stays out, and git lists as the project's own git does when it
# cannot read one); otherwise a path that does not exist, so git fails and semgrep walks the folders itself.
# GIT_CONFIG_NOSYSTEM and GIT_CONFIG_GLOBAL keep the machine's and the user's git config out too, so the only
# config such a git reads is sast.sh's.
copy_ok() { # copy_ok <file> <bytes>: <file> is absent, or a regular file, not a link, of at most <bytes>
  if [ ! -e "$1" ] && [ ! -L "$1" ]; then return 0; fi
  [ -f "$1" ] && [ ! -L "$1" ] && [ -z "$(find "$1" -prune -size +"$2"c -print 2>/dev/null)" ]
}
# can_read <file>: <file> can be read, or is absent and its folder is missing or can be searched (in a folder
# that cannot be searched, a file only looks absent).
can_read() {
  if [ -e "$1" ]; then [ -r "$1" ]; else [ ! -d "${1%/*}" ] || [ -x "${1%/*}" ]; fi
}
# index_inside: the copied index, read by git under sast.sh's config, names only paths inside the project (an
# entry that is absolute or has an empty, . or .. component would have git list a file outside --path); exit 1
# when one does not, and git's own status when it cannot read the copy.
index_inside() {
  (cd / && exec env -i PATH="$PATH" HOME="$S" LC_ALL=C GIT_DIR="$S/git" GIT_WORK_TREE="$PROJ" GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null git ls-files -z --cached 2>/dev/null) | (cd / && exec python3 -I -c 'import sys
for p in sys.stdin.buffer.read().split(b"\0"):
    if p and (p.startswith(b"/") or set(p.split(b"/")) & {b"", b".", b".."}):
        sys.exit(1)')
}
GITENV=("GIT_DIR=$S/no-repo") NOCOPY="" NOEXCL=""
G=$PROJ/.git
# The two keys git init sets from the filesystem, which change what git lists: ignorecase where letter case
# does not tell names apart (seen without writing in the tree: .GIT is then the same folder as .git), and
# precomposeUnicode on macOS.
GCONF=$'[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfsmonitor = false\n\thooksPath = /dev/null\n\tuntrackedCache = false\n'
if [ "$PROJ/.GIT" -ef "$G" ] && [ ! -L "$PROJ/.GIT" ]; then GCONF+=$'\tignorecase = true\n'; fi
case "${OSTYPE:-}" in darwin*) GCONF+=$'\tprecomposeUnicode = true\n' ;; esac
# NOCOPY: for a git project, why semgrep's git gets no copy, for the last line. NOEXCL: why the copy holds the
# index without info/exclude, which git then lists without, as the project's own git does when it cannot read
# that file.
if [ "$VCS" = git ]; then
  case "$PROJ/" in
    "${WT%/}/"*)
      if [ ! -d "$G" ] || [ -L "$G" ]; then NOCOPY="its .git is a file or a link"
      elif ! copy_ok "$G/index" 268435456; then NOCOPY="its index is a link, not a regular file, or over 256 MiB"
      elif ! can_read "$G/index"; then NOCOPY="its index cannot be read"
      elif ! { confine_mkdir "$S/git" && confine_mkdir "$S/git/objects" && confine_mkdir "$S/git/refs" &&
        confine_mkdir "$S/git/info" && confine_new_file "$S/git/HEAD" $'ref: refs/heads/main\n' &&
        confine_new_file "$S/git/config" "$GCONF"; }; then
        NOCOPY="the scratch directory could not hold the copy"
      else
        if [ -L "$G/info" ]; then NOEXCL="its .git/info is a link"
        elif ! copy_ok "$G/info/exclude" 1048576; then NOEXCL="its info/exclude is a link, not a regular file, or over 1 MiB"
        elif ! can_read "$G/info/exclude"; then NOEXCL="its info/exclude cannot be read"
        fi
        if ! { { [ ! -e "$G/index" ] || iso_copy_new "$G/index" "$S/git/index"; } &&
          { [ -n "$NOEXCL" ] || [ ! -e "$G/info/exclude" ] || iso_copy_new "$G/info/exclude" "$S/git/info/exclude"; }; }; then
          NOCOPY="its index or info/exclude could not be copied into the scratch directory"
        else
          index_inside
          case $? in
            0) GITENV=("GIT_DIR=$S/git" "GIT_WORK_TREE=$PROJ") ;;
            1) NOCOPY="its index names a path outside the repository" ;;
            *) NOCOPY="git cannot read its index from a copy, as with a split index or a sha256 repository" ;;
          esac
        fi
      fi ;;
    *) NOCOPY="the repository lies above the working directory" ;;
  esac
fi
ISO_ENV+=("${GITENV[@]}" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null)
# Where git lists nothing for a folder in a git project, the last line says that semgrep chose the files, and why.
walked=""
if [ -n "$NOCOPY" ] && [ -d "$TARGET" ]; then
  walked="; note: semgrep listed the files itself, not with git (no copy of the repository index: $NOCOPY), so files a .gitignore leaves out can be in the scan"
elif [ -n "$NOEXCL" ] && [ -d "$TARGET" ]; then
  walked="; note: semgrep's git read the repository index without its info/exclude ($NOEXCL), so files only that file leaves out can be in the scan"
fi

# The .semgrepignore files that narrow the scan of a folder: semgrep reads every one in its project, so each one
# from the project down to the scan root, then each one under it; find's own failure only hides the note.
ignores=""
if [ -d "$TARGET" ]; then
  : > "$S/ignores"
  rest=${TARGET#"${PROJ%/}"} cur=${PROJ%/}
  while [ -n "$rest" ]; do
    [ ! -f "$cur/.semgrepignore" ] || printf '%s\n' "$cur/.semgrepignore" >> "$S/ignores"
    rest=${rest#/}
    cur=$cur/${rest%%/*}
    case "$rest" in */*) rest=/${rest#*/} ;; *) rest="" ;; esac
  done
  find "$TARGET" \( -name .git -o -name node_modules \) -prune -o -name .semgrepignore \( -type f -o -type l \) -print >> "$S/ignores" 2>/dev/null || : > "$S/ignores"
  while IFS= read -r f; do
    f=${f#"$WT"/}
    ignores=${ignores:+$ignores, }$(confine_text "$f")
  done < "$S/ignores"
fi

CONFIGS=()
for s in "${SETS[@]}"; do CONFIGS+=(--config "$s"); done
confine_disclose "$R" "$TOOL" semgrep.dev "ruleset ids (the semgrep registry, for the rules)" "${SETS[@]}" ||
  blocker "cannot add a row to $R/disclosures.tsv, so nothing was sent"
: > "$S/out.log" || blocker "cannot write in $S"
# One semgrep call, or one for each list of the link check (CALLS), all of them within LIMIT. END says how
# the last one ended, and FOUND that one of them found something.
FOUND=0 START=$SECONDS i=1
while [ "$i" -le "$CALLS" ]; do
  sarif=$S/out.sarif watch=$S/watch scanned=$PATH_REL
  if [ "$CALLS" -gt 1 ]; then
    targets_of "$i"
    sarif=$S/out.$i.sarif watch=$S/watch.$i
    scanned="$PATH_REL, call $i of $CALLS: ${#TARGETS[@]} of the $PATHS paths under it that leave out its symbolic links out of the working directory"
  elif [ "${#TARGETS[@]}" != 1 ] || [ "${TARGETS[0]}" != "$TARGET" ]; then
    scanned="$PATH_REL, as ${#TARGETS[@]} paths under it that leave out its symbolic links out of the working directory"
  fi
  left=$((LIMIT - (SECONDS - START)))
  [ "$left" -ge 1 ] || left=1
  printf '>> semgrep scan %s --metrics=off --disable-version-check --sarif --output <scratch> --error -- %s\n' \
    "${CONFIGS[*]}" "$scanned" >> "$S/out.log"
  rc=0
  iso_watch "$left" "$watch" "$S" ${ISO_NET[@]+"${ISO_NET[@]}"} semgrep scan "${CONFIGS[@]}" --metrics=off \
    --disable-version-check --sarif --output "$sarif" --error -- "${TARGETS[@]}" >> "$S/out.log" 2>&1 || rc=$?
  END=$(cat "$watch" 2>/dev/null) || END=""
  [ -n "$END" ] || END="exit $rc"
  case "$END" in
    'exit 0') ;;
    'exit 1') FOUND=1 ;;
    *) break ;;
  esac
  i=$((i + 1))
done
[ "$END" != 'exit 0' ] || [ "$FOUND" = 0 ] || END='exit 1'

# keep: the SARIF (when there is one) and the log as R/sast/semgrep-<n>.{sarif,log}; sets N.
SAST=$WT/$R/sast
if [ ! -d "$SAST" ]; then confine_mkdir "$SAST" || blocker "cannot create $R/sast"; fi
[ ! -L "$SAST" ] || blocker "$R/sast is a symbolic link"
N=1
while :; do
  while [ -e "$SAST/semgrep-$N.sarif" ] || [ -L "$SAST/semgrep-$N.sarif" ] || [ -e "$SAST/semgrep-$N.log" ] || [ -L "$SAST/semgrep-$N.log" ]; do
    N=$((N + 1))
    [ "$N" -le 9999 ] || blocker "$R/sast holds 9999 scans"
  done
  iso_copy_new "$S/out.log" "$SAST/semgrep-$N.log" && break
  [ -e "$SAST/semgrep-$N.log" ] || blocker "cannot write $R/sast/semgrep-$N.log"
done
LOG=$R/sast/semgrep-$N.log
note=$walked
[ -z "$ignores" ] || note="$note; note: .semgrepignore files narrow the scan: $ignores"
note=$note$LINKS_NOTE
case "$END" in
  'exit 0'|'exit 1') ;;
  timeout) blocker "semgrep passed the $LIMIT-second limit (AUDITOR_RUN_TIMEOUT) and was killed; log $LOG" ;;
  *) blocker "semgrep failed ($(confine_text "$END")): no rules fetched, a target it cannot read, or another error; log $LOG" ;;
esac
if [ "$CALLS" -gt 1 ]; then
  parts=()
  i=1
  while [ "$i" -le "$CALLS" ]; do parts+=("$S/out.$i.sarif"); i=$((i + 1)); done
  (cd / && exec python3 -I -c "$MERGE_PY" "$S/out.sarif" "${parts[@]}") 2>/dev/null ||
    blocker "one of the $CALLS semgrep calls wrote no SARIF, or one that cannot be read; log $LOG"
  note="$note; note: the $PATHS paths were too many for one semgrep call, so it ran $CALLS times, on at most 5000 each, and the SARIF holds one run for each"
fi
[ -f "$S/out.sarif" ] && [ ! -L "$S/out.sarif" ] && [ -s "$S/out.sarif" ] || blocker "semgrep wrote no SARIF; log $LOG"
iso_copy_new "$S/out.sarif" "$SAST/semgrep-$N.sarif" || blocker "cannot write $R/sast/semgrep-$N.sarif; log $LOG"
results=$( (cd / && exec python3 -I -c 'import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
print(sum(len(run.get("results") or []) for run in data.get("runs") or []))' "$S/out.sarif") 2>/dev/null) ||
  blocker "the SARIF semgrep wrote cannot be read: $R/sast/semgrep-$N.sarif; log $LOG"
case "$END" in
  'exit 0') printf '>> semgrep: %s results (exit 0): %s; log %s%s\n' "$results" "$R/sast/semgrep-$N.sarif" "$LOG" "$note"; exit 0 ;;
  *) printf '>> semgrep: %s results (exit 1): %s; log %s%s\n' "$results" "$R/sast/semgrep-$N.sarif" "$LOG" "$note"; exit 1 ;;
esac
