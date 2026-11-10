#!/usr/bin/env bash
# test-command-forms.sh — the commands, agents and skills, and the corpus they send the agent to, run each
# bundled entry point in the one form its allow rules pre-approve: Claude Code approves a call without asking
# only when its text starts with the quoted path the rule names and holds no $ other than the root it
# substitutes (OUTPUT-RULES.md Rule 11e).
#   C1  In commands/*.md, agents/*.md, skills/*/SKILL.md and SKILL.md, every code span and code line that names
#       a bundled entry point from the root names it as "${CLAUDE_PLUGIN_ROOT}/<path>" (in the root SKILL.md,
#       "${CLAUDE_SKILL_DIR}/<path>"), quoted, first in the command, or as the file a test -x, -f or -e reads (a
#       cmp or diff of it asks, since it lies outside the working directory); with no bash, cd, env or VAR=value
#       in front, no other $, no backtick, no ;, &&, ||, no & but in a redirect (2>&1, &>), no process
#       substitution, no pipe (a | with a space beside it, or one straight into a path or a program such as sh
#       or tee; a|b in a usage line is a choice), no line continuation, and no file redirect but into a run
#       directory (audit_<n>/ or incident_<n>/, with no .. in the path) or /dev/null. A placeholder the bodies
#       use (<n>, <R>/poc/<ID> and the rest of PLACEHOLDERS) is a word there; any other <...> is read as
#       written, so <x>/tmp/evil redirects. No bundled entry point is named outside a code span or fenced block,
#       and no span names the root as <auditor-skill root>/ or as $CLAUDE_PLUGIN_ROOT or $CLAUDE_SKILL_DIR
#       without braces, which Claude Code does not fill in.
#   C2  Every Bash allow rule that names a path from the root names it as its quoted first word (after an
#       optional test -x), and that path is a tracked file of mode 100755 whose first line is a #! line, or a
#       binary a crate under tools/auditor-tools declares, executable when it is built. What an allow rule may
#       pre-approve at all (an entry point scripts/entrypoints.txt lists, with the words it names, or a read
#       tool, Task, a run-directory edit or an auditor skill) is scripts/check-entrypoints.sh's check.
#   C3  Every call of audit-scan carries --contract=1 as its first argument, names the directory it scans and
#       passes no option audit-scan refuses, and every call of audit-mem --contract=1 right after its subcommand:
#       in the rules, in rooted calls, and in code spans and code lines whose simple commands (each after a list
#       operator, a pipe, or a ) that closes a subshell, a case pattern or a function's () too, and none in a
#       comment, from a # that starts a word) run the bare name behind a shell prompt ($ or %), a reserved word
#       that opens a command (if, then, elif, else, while, until, do, !) and a ( or { after it, assignments and
#       wrappers (env, sudo, doas, nice, timeout, xargs, stdbuf, taskset, chroot and the like, named alone or by
#       their path, with their short options, a value at the end of a cluster, their long options and the words
#       they take), and pass arguments (a span naming only the tool, the tool and a subcommand, or audit-scan and
#       its marker, is a mention, and so is a lookup or a listing, such as command -v or sudo -l), in the bodies
#       and in the corpus C6 reads alike. A command inside $( ) or backticks, in a quoted bash -c string, or in
#       the body of a function written as function <name> { ... }, with no (), is not read.
#   C4  Every command, and the root SKILL.md, runs preflight.sh as step 0: the first entry point its body names
#       is "<root>/scripts/preflight.sh", with no arguments (the --strict form a user's --strict asks for comes
#       after it), in a paragraph that starts "0. **Preflight" (in the root SKILL.md, "**Step 0 — Preflight") and
#       says that a refusal, and a call that is denied, stop the run, in both modes (OUTPUT-RULES.md Rule 11e);
#       its body says that a resumed invocation (--resume) runs step 0 again; and the allowed-tools of every
#       command, and of the root SKILL.md, pre-approve that call.
#   C5  Every rooted call in a command's body, and in the bodies of the agents it spawns, is one of that
#       command's Bash rules: the same path, then the rule's fixed words (all of them, for a rule with no *). The
#       command spawns an agent that a code span names, as auditor:<agent> or bare, after spawn, delegate or run
#       in the sentence, or after hand, start, launch, use, invoke or "the Task tool" in a sentence that names no
#       auditor: skill (work handed on through a skill is the skill's), or that starts a list item under such a
#       paragraph, but not in a list item about another command. A fork skill's calls, and its agent's, are its
#       own rules', and so are the root SKILL.md's. A call is an entry point first in a code span with words
#       after it, or first on a fenced code line; one whose span ", which asks" follows straight away is a
#       documented prompt.
#   C6  In the corpus (FULL-AUDIT.md, checklists/, known-vectors/, discovery/, and every .md under references/,
#       templates/ and docs/), every call of an entry point names it as "<auditor-skill root>/<path>", quoted,
#       first in the command or as the file a test -x, -f or -e reads, with no other $ or backtick in it: no
#       bash, sh, env, cd or VAR=value in front, and not ${CLAUDE_PLUGIN_ROOT}, which only a command body
#       substitutes. A call is a code span with words after the path, or a line of a shell code block (bash,
#       sh, shell, zsh, console or none named) that is not a comment; a quoted block counts too, and a span
#       that starts Bash( names a rule.
#   C7  No file of the corpus, command, agent or skill runs an entry point by a path relative to the working
#       directory (scripts/rundir.sh new, ./scripts/..., bash scripts/..., $ scripts/..., in any of the simple
#       commands C3 reads, behind the reserved words and wrappers it reads past), where the tree under audit can
#       put a file of its own; a span holding the path alone names the file.
#   C8  Every command, skill and the root SKILL.md names each of the plugin's agents by its plugin-scoped name,
#       auditor:<agent>, in every code span that names one: a project agent cannot hold a : in its name, so a
#       bare name is one a repository's .claude/agents/<agent>.md answers to, ahead of the plugin's agent. An
#       agent's own body, which starts no agent, may name one bare.
#   P   Wording the flows depend on stays in place (the PINS list): what keeps a long call, and the turn after
#       it, inside a command's grant; that Q46 is asked at intake only, a run directory's recorded mode being
#       used as it stands since the runners take the stricter of it, AUDITOR_EXEC_MODE and strict mode, while
#       Q47 and the scope confirmations are still asked again for a reused one; that a mode only an older run
#       directory's intake.md §8 or ledger header records is written to the exec-mode file the runners read (in
#       respond's and hunt's wrapped steps too, each read as one line); how the resume prompt is answered, and
#       that a resumed invocation keeps the user's --strict.
#       Every command that starts agents keeps them in the foreground and resumes in the turn an agent's result
#       arrives in; wording that asked Q46 again, called isolated recommended, copied an earlier run's mode
#       forward, wrote only native, or passed the file's mode as run.sh --mode, stays gone (the GONE list); and
#       no body names the environment form of a PoC run (VULNERABLE_SO and the rest), which run.sh --crate does
#       not read. diff-audit and quick-scan keep their --ci and --fail-on, the findings file that starts as a
#       failing record, the Rule 5b statuses that count, a reply without finding text, and the closing line;
#       each of the three Quick commands names the report it writes from templates/pr-report.md, writes it in
#       its own session (quick-scan and diff-audit start no agent at all, so their cost holds still, and
#       deep-review leaves an agent's model to its definition), runs no cd, after which the bundled tools would
#       look for the run directory in the wrong folder, and reads the corpus from the root, each verdict naming
#       what it rests on: quick-scan and diff-audit the selection of references/depth-scope.md, written to
#       audit_<n>/scope.md before any section or vector file is read, each section read by its start line and
#       line count (diff-audit within its 5,000-line changed-code budget, with its vector floor), deep-review
#       the checklists SKILL.md's scope table names; quick-scan's old severity-7 vector step, diff-audit's
#       scope-table checklist reading and their cost figures stay gone; diff-audit's PR-number form,
#       quick-scan's "fail the job" without a private channel, its vector step that named no file, the Task
#       grant of both, and the write-rule reason for no cd stay gone (docs/ci.md). Every command, skill and the
#       root SKILL.md grants its run-directory edit with a leading /, Edit(/audit_*/**) or
#       Edit(/incident_*/**), and none the bare form, which a cd moves to another folder's audit_*.
#   G   The lines agents/poc-engineer.md gives a runner it writes, run as the first lines of such a runner in a
#       crate, from the working directory and from the crate, find <R> from the runner's path and take the
#       stricter of <R>/exec-mode, AUDITOR_EXEC_MODE and strict mode (AUDITOR_STRICT, or a strict entry in their
#       own <R>) as run.sh --crate does, native when none of them says anything; they stop on none, on an
#       exec-mode that is not a regular file holding one word and at most one newline, and on an
#       AUDITOR_EXEC_MODE that names no mode, and in isolated mode unless probe.sh --only isolation finds nothing
#       readable. poc-harness.md §1 shows the same lines.
#   I   Every python3 call in the bodies and the corpus, in a code span or a code line that starts with python3
#       (after a "(cd <dir> &&", "cd <dir> &&" or "env" in front) and passes two words more, runs isolated: -I
#       comes before its first word that is not an option.
# The entry points are the tracked files under scripts/ (but scripts/tests/) and templates/ of mode 100755 that
# start with a direct-exec shebang (#!/bin/bash or #!/usr/bin/env -S python3 -I), the binaries the crates
# under tools/auditor-tools declare, and every path scripts/entrypoints.txt lists. Each check first runs on
# known-good and known-bad fixture files, one of them over 64 KiB with its one bad line last, so a broken check
# fails the test. KNOWN lists the findings the tree has until the edits that fix them land.
# Usage (from the repo root): bash scripts/tests/test-command-forms.sh [<tree>]   (VERBOSE=1 lists every check)
#   <tree>: a git checkout to check instead of this one, such as an older commit's.
# Needs bash >= 3.2, git and python3. No network.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P) || exit 1
TREE=$ROOT
if [ $# -gt 0 ]; then TREE=$(cd "$1" && pwd -P) || { echo "FAIL cannot enter $1"; exit 1; }; fi
export LC_ALL=C
pass=0; failn=0
ok()  { pass=$((pass + 1)); if [ -n "${VERBOSE:-}" ]; then echo "ok   $*"; fi; }
bad() { failn=$((failn + 1)); echo "FAIL $*"; }
command -v python3 >/dev/null 2>&1 || { echo "FAIL python3 is not on PATH"; exit 1; }
command -v git >/dev/null 2>&1 || { echo "FAIL git is not on PATH"; exit 1; }
T=$(mktemp -d "${TMPDIR:-/tmp}/command-forms.XXXXXX") || exit 1
T=$(cd "$T" && pwd -P) || exit 1
trap 'rm -rf "$T"' EXIT

# The checker: python3 -I -c "$PY" <tree> <index file> <file>...; one line per finding,
# "<check><TAB><file>:<line><TAB><what>", and exit 0; exit 2 when it cannot read an input.
PY=
IFS= read -r -d '' PY <<'EOF' || true
import os, re, sys

tree, index_file, files = sys.argv[1], sys.argv[2], sys.argv[3:]
DIRECT = ("#!/bin/bash", "#!/usr/bin/env -S python3 -I")
ROOTED = re.compile(r'\$\{(CLAUDE_PLUGIN_ROOT|CLAUDE_SKILL_DIR)\}("?)/([A-Za-z0-9_./-]+)')
CALL = re.compile(r'^\s*"\$\{(CLAUDE_PLUGIN_ROOT|CLAUDE_SKILL_DIR)\}/([A-Za-z0-9_./-]+)"(.*)$')
READERS = ("test -x", "test -f", "test -e")
RELEASE = "tools/auditor-tools/target/release/"
# Programs a | with no space beside it still pipes into; any other a|b is a choice in a usage line.
PIPE_INTO = set("sh bash zsh dash ksh fish python python3 perl ruby node tee xargs env eval exec source nc ncat "
                "socat curl wget dd cat head tail grep egrep fgrep sed awk gawk mawk jq sort uniq cut tr wc base64 "
                "openssl ssh scp".split())
SPAWN = re.compile(r'(?i)\b(spawns?|delegates?|runs?)\b')
# Other words that hand an agent work; a sentence that names a skill (auditor:<name>) hands it to that skill.
SPAWN_OTHER = re.compile(r'(?i)\b(hands?|starts?|launch(es)?|uses?|invokes?)\b|\bthe Task tool\b')
# The corpus names the installation root as <auditor-skill root>; a call there, from any root, is read in code
# spans and in shell code blocks.
CORPUS_ROOT = "<auditor-skill root>"
ANY_ROOT = re.compile(r'("?)(<auditor-skill root>|\$\{CLAUDE_PLUGIN_ROOT\}|\$CLAUDE_PLUGIN_ROOT|\$\{CLAUDE_SKILL_DIR\}|'
                      r'\$CLAUDE_SKILL_DIR)("?)/([A-Za-z0-9_./-]+)("?)')
SHELL_FENCES = ("", "bash", "sh", "shell", "zsh", "console")
# What a call can have in front of it in its simple command: a shell prompt ($ or %), the OPENERS (a reserved
# word that opens a command, as in `if audit-scan ...; then`, `do` or `!`, and a ( or { that opens a subshell or a
# group), assignments, and any interpreter or wrapper, named alone or by its path, with its options
# and the words it takes. Each wrapper gives the letters of its short options that take a value (sudo -u <user>,
# and sudo -Eu <user> too), its long options that take the next word (sudo --user <user>), how many words it takes
# before the command (timeout's duration, chroot's directory, taskset's mask), and the letters and the long
# options with which it runs nothing but only looks the command up or lists it (command -v, sudo -l).
WRAPPERS = {
    "bash": ("", (), 0, "", ()), "sh": ("", (), 0, "", ()), "zsh": ("", (), 0, "", ()), "dash": ("", (), 0, "", ()),
    "ksh": ("", (), 0, "", ()), "python": ("", (), 0, "", ()), "python3": ("", (), 0, "", ()),
    "env": ("uCPS", ("unset", "chdir", "split-string"), 0, "", ()),
    "exec": ("a", (), 0, "", ()), "command": ("", (), 0, "vV", ()), "nohup": ("", (), 0, "", ()),
    "time": ("fo", ("format", "output"), 0, "", ()),
    "sudo": ("gpCDrRtTuU", ("group", "prompt", "close-from", "chdir", "role", "type", "user", "other-user",
                            "command-timeout", "chroot", "host"), 0,
             "lveVK", ("list", "validate", "edit", "version", "remove-timestamp")),
    "doas": ("aCu", (), 0, "C", ()), "nice": ("n", ("adjustment",), 0, "", ()),
    "xargs": ("adEIJLnPRs", ("arg-file", "delimiter", "max-args", "max-procs", "max-chars", "process-slot-var"), 0,
              "", ()),
    "timeout": ("ks", ("kill-after", "signal"), 1, "", ()), "chroot": ("", ("userspec", "groups"), 1, "", ()),
    "stdbuf": ("ioe", ("input", "output", "error"), 0, "", ()), "taskset": ("", (), 1, "p", ("pid",)),
}
OPENERS = ("!", "if", "then", "elif", "else", "while", "until", "do", "(", "{")

def pieces(seg):
    """(start, end) of each simple command of a code span or line: it ends at a list operator, a pipe, a & that
    runs it in the background or a ) that closes a subshell, a case pattern or a function's (), outside quotes;
    the & of a redirect, 2>&1 or &>, ends nothing. A # that starts a word outside quotes starts a comment, which
    runs nothing, so it ends the last one."""
    out, start, q, i = [], 0, None, 0
    while i < len(seg):
        c = seg[i]
        if q:
            if c == q:
                q = None
            elif c == "\\" and q == '"':
                i += 1
        elif c in "'\"":
            q = c
        elif c == "#" and (i == 0 or seg[i - 1].isspace() or seg[i - 1] in ";&|(<>"):
            break
        elif seg.startswith(("&&", "||", "|&"), i):
            out.append((start, i))
            start = i = i + 2
            continue
        elif c in ";|)" or (c == "&" and seg[i - 1:i] not in ("<", ">") and seg[i + 1:i + 2] != ">"):
            out.append((start, i))
            start = i + 1
        i += 1
    out.append((start, min(i, len(seg))))
    return out

def call_at(seg, start, end):
    """Where the command that seg[start:end] runs starts, past the OPENERS, assignments and what WRAPPERS describes
    in front of it; None when it runs none, or a wrapper there only looks the command up or lists it."""
    s = start + re.match(r'\s*(?:[({]\s*)*', seg[start:end]).end()
    toks = [(s + m.start(), m.group(0)) for m in re.finditer(r'\(|[^\s(]\S*', seg[s:end])]
    i = 1 if toks and toks[0][1] in ("$", "%") else 0
    while i < len(toks):
        word = toks[i][1]
        if word in OPENERS or re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', word):
            i += 1
            continue
        spec = WRAPPERS.get(word.rsplit("/", 1)[-1])
        if spec is None:
            return toks[i][0]
        values, long_values, takes, lookups, long_lookups = spec
        i += 1
        while i < len(toks) and toks[i][1].startswith("-") and toks[i][1] != "-":
            opt = toks[i][1]
            i += 1
            if opt == "--":
                break
            if opt.startswith("--"):
                name = opt[2:].split("=", 1)[0]
                if name in long_lookups:
                    return None
                if "=" not in opt and name in long_values:
                    i += 1
                continue
            for k, c in enumerate(opt[1:]):
                if c in lookups:
                    return None
                if c in values:
                    if k == len(opt) - 2:
                        i += 1          # its value is the next word; otherwise it is the rest of this one
                    break
        i += takes
    return None
ASKS = re.compile(r'^\s*,?\s*which asks\b')
# The placeholders the bodies write in their calls, each a word to the redirect scan (<R>/poc/<ID> is a path);
# any other <...> is read as written, so `<x>/tmp/evil` is a redirect. A body that writes a new one adds it here.
PLACEHOLDERS = ("ID", "R", "address", "audited commit", "base", "changed program directory", "commit", "file",
                "filter", "fromUnix", "head", "id", "in-scope directory", "in-scope program dir", "json", "k",
                "line", "n+1", "n", "name", "package", "path", "program directory", "program-path", "program_id",
                "repo", "rev", "sha from intake", "sha", "sig", "signature", "store intake recorded", "target",
                "the file's directory", "the full commit id intake pinned", "the full id of head", "toUnix",
                "value", "version")
PLACEHOLDER = re.compile(r'<(?:' + "|".join(re.escape(p) for p in sorted(PLACEHOLDERS, key=len, reverse=True)) +
                         r')>(?!\.\./)')

modes = {}
with open(index_file, encoding="utf-8", errors="replace") as f:
    for line in f:
        meta, _, path = line.rstrip("\n").partition("\t")
        if path:
            modes[path] = meta.split(" ")[0]

def first_line(path):
    try:
        with open(os.path.join(tree, path), "rb") as f:
            return f.readline(512).rstrip(b"\r\n").decode("utf-8", "replace")
    except OSError:
        return ""

bins = set()
for path in modes:
    if path.startswith("tools/auditor-tools/") and path.endswith("Cargo.toml") and path.count("/") <= 3:
        try:
            text = open(os.path.join(tree, path), encoding="utf-8").read()
        except OSError:
            continue
        for block in re.split(r'(?m)^\[', text):
            if block.startswith("[bin]]"):
                m = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
                if m:
                    bins.add(m.group(1))

entry = set(RELEASE + b for b in bins)
for path, mode in modes.items():
    if mode == "100755" and path.startswith(("scripts/", "templates/")) and not path.startswith("scripts/tests/"):
        if first_line(path) in DIRECT:
            entry.add(path)
try:
    with open(os.path.join(tree, "scripts/entrypoints.txt"), encoding="utf-8", errors="replace") as fh:
        entry.update(l.split("\t", 1)[0].strip() for l in fh if l.strip() and not l.startswith("#"))
except OSError:
    pass
# A call by a path relative to the working directory, after any interpreter, cd, env or assignment in front.
REL = re.compile(r'^"?(?:\./)?(' + "|".join(re.escape(p) for p in sorted(entry, key=len, reverse=True)) +
                 r')(?![A-Za-z0-9_.-])"?')

out = []
def finding(check, f, n, what):
    out.append("%s\t%s:%d\t%s" % (check, f, n, what))

def unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == "'" and v[-1] == "'":
        return v[1:-1].replace("''", "'")
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v

def split_commas(s):
    parts, depth, cur = [], 0, ""
    for c in s:
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(cur.strip()); cur = ""
        else:
            cur += c
    if cur.strip():
        parts.append(cur.strip())
    return parts

def read(path):
    with open(os.path.join(tree, path), encoding="utf-8") as f:
        return f.read()

def split_doc(text):
    """(frontmatter lines, body lines, the body's first line number)"""
    lines = text.split("\n")
    if lines and lines[0] == "---":
        for i in range(1, len(lines)):
            if lines[i] == "---":
                return lines[1:i], lines[i + 1:], i + 2
    return [], lines, 1

def value(fm, key):
    for l in fm:
        if l.startswith(key + ":"):
            return unquote(l[len(key) + 1:])
    return ""

def rules_of(fm):
    rules, key = [], None
    for n, l in enumerate(fm, start=2):
        if l.startswith("  - "):
            if key == "allowed-tools":
                rules.append((n, unquote(l[4:])))
            continue
        m = re.match(r'^([A-Za-z0-9_-]+):(.*)$', l)
        if m:
            key = m.group(1)
            if key == "allowed-tools" and m.group(2).strip():
                rules.extend((n, e) for e in split_commas(unquote(m.group(2))))
    return rules

def parse_rule(e):
    """None for a rule naming no path from the root; False for one not naming it as its quoted first word;
    else (test -x?, root variable, path, the fixed words after it, whether a * ends it)."""
    if not (e.startswith("Bash(") and e.endswith(")")) or "${CLAUDE_" not in e:
        return None
    m = re.match(r'^(test -x )?"\$\{(CLAUDE_PLUGIN_ROOT|CLAUDE_SKILL_DIR)\}/([^"]+)"(?: (.*))?$', e[5:-1])
    if not m:
        return False
    words = (m.group(4) or "").split()
    star = bool(words) and words[-1] == "*"
    return (bool(m.group(1)), m.group(2), m.group(3), words[:-1] if star else words, star)

def operators(s):
    found, q, i = [], None, 0
    while i < len(s):
        c = s[i]
        if q == "'":
            if c == "'":
                q = None
        elif q == '"':
            if c == "\\":
                i += 1
            elif c == '"':
                q = None
        elif c in "'\"":
            q = c
        elif c == "`":
            found.append("a backtick")
        elif c == "\\" and s[i + 1:].strip() == "":
            found.append("a line continuation")
        elif c == ";":
            found.append(";")
        elif s.startswith("<(", i) or s.startswith(">(", i):
            found.append("a process substitution")
        elif s.startswith("&&", i) or s.startswith("||", i) or s.startswith("|&", i):
            found.append(s[i:i + 2]); i += 1
        elif c == "&":
            # a & that is no part of a redirect (2>&1, &>) runs what comes before it in the background
            if (s[i - 1] if i > 0 else " ") not in "<>" and s[i + 1:i + 2] != ">":
                found.append("&")
        elif c == "|" and (s[i - 1] if i > 0 else " ") != ">":
            after = s[i + 1] if i + 1 < len(s) else " "
            word = re.match(r'[A-Za-z0-9_.-]*', s[i + 1:]).group(0)
            if (s[i - 1] if i > 0 else " ").isspace() or after.isspace() or after in "/.~'\"$({\\" \
                    or word in PIPE_INTO:
                found.append("a pipe")
        i += 1
    return found

def redirects(s):
    """The target of each file redirect outside quotes that does not lead into a run directory (or /dev/null)."""
    s = PLACEHOLDER.sub('P', s)
    bad, q, i = [], None, 0
    while i < len(s):
        c = s[i]
        if q:
            if c == q:
                q = None
            elif c == "\\" and q == '"':
                i += 1
        elif c in "'\"":
            q = c
        elif c in "<>" and not s.startswith("<(", i) and not s.startswith(">(", i):
            j = i
            while j < len(s) and s[j] in "<>|&":
                j += 1
            op = s[i:j]
            if op.startswith("<<"):
                i = j; continue                    # here-documents and here-strings
            target = re.match(r'\s*([^\s;&|<>]*)', s[j:]).group(1)
            if op.endswith("&") and re.match(r'^(\d+|-)$', target):
                i = j; continue                    # a descriptor copy, such as 2>&1
            if target != "/dev/null" and (not re.match(r'^(\./)?(audit|incident)_[^/\s]*/', target)
                                          or ".." in target.split("/")):
                bad.append(target or "(no target)")
            i = j; continue
        i += 1
    return bad

def segments(body, first, infos=None):
    """(line number, text, first line of its paragraph, the paragraph, where the code ends in it, fenced?) for
    every inline code span and fenced code line. infos, when given, gets each fenced line's info string."""
    fence, para, info = None, [], ""
    def spans(para):
        text = "\n".join(l for _, l in para)
        starts, pos = [], 0
        for n, l in para:
            starts.append((pos, n)); pos += len(l) + 1
        def line_at(off):
            n = para[0][0]
            for p, ln in starts:
                if p <= off:
                    n = ln
            return n
        i = 0
        while i < len(text):
            if text[i] != "`":
                i += 1; continue
            j = i
            while j < len(text) and text[j] == "`":
                j += 1
            run, k, close = j - i, j, -1
            while k < len(text):
                if text[k] == "`":
                    l = k
                    while l < len(text) and text[l] == "`":
                        l += 1
                    if l - k == run:
                        close = k; break
                    k = l
                else:
                    k += 1
            if close < 0:
                i = j; continue
            yield line_at(j), text[j:close].replace("\n", " "), para[0][1], text, close + run, False
            i = close + run
    for idx, line in enumerate(body):
        n = first + idx
        m = re.match(r'^\s*(`{3,}|~{3,})(.*)$', line)
        if fence:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not m.group(2).strip():
                fence = None
            else:
                if infos is not None:
                    infos[n] = info
                yield n, line.strip(), line, line, len(line), True
            continue
        if m:
            for s in spans(para):
                yield s
            para = []
            fence = m.group(1)
            info = (m.group(2).split() or [""])[0].lower()
            continue
        if line.strip() == "" or re.match(r'^\s*(\d+[a-z]?[.)]|[-*+])\s', line):
            for s in spans(para):
                yield s
            para = []
        if line.strip():
            para.append((n, line))
    for s in spans(para):
        yield s

def scan_refused(rest):
    """Why audit-scan's grammar refuses the words after its --contract=1, or None: they name the directory, and
    no option but --out and --workflows, which take the next word or a value after =, and --pretty; audit-scan
    refuses any other word that starts with -, -- too. The first other word is the directory (a placeholder, an
    ellipsis or a rule's * stands for one). A pipe or a list operator ends the call, and a redirect is no word of
    it."""
    words = re.sub(r'<[^<>]*>', 'P', re.sub(r'\s#.*$', '', rest)).split()
    i, found = 0, False
    while i < len(words):
        w = words[i]
        if w in ("|", "||", "&&", ";") or w.startswith("|"):
            break
        if w in ("--out", "--workflows", ">", ">>", "<", "2>", "&>"):
            i += 2
        elif w == "--pretty" or w.startswith(("--out=", "--workflows=")) or re.match(r'^(\d*|&)[<>]', w):
            i += 1
        elif w.startswith("-"):
            return "with an option it refuses (%s)" % w
        else:
            found, i = True, i + 1
    return None if found else "with no directory to scan"

def marker(check_file, n, tool, rest, where):
    words = rest.split()
    why = tool == "audit-scan" and len(words) > 1 and scan_refused(" ".join(words[1:]))
    if tool == "audit-scan" and words and words[0] != "--contract=1":
        finding("C3", check_file, n, "audit-scan %s without --contract=1 as its first argument: %s" % (where, rest[:120]))
    elif why:
        finding("C3", check_file, n, "audit-scan %s %s after --contract=1: %s" % (where, why, rest[:120]))
    if tool == "audit-mem" and len(words) >= 1 and (len(words) < 2 or words[1] != "--contract=1"):
        finding("C3", check_file, n, "audit-mem %s without --contract=1 right after its subcommand: %s" % (where, rest[:120]))

def bare(check_file, n, seg):
    """C3 for each simple command of a span or code line that runs the tool by its bare name and passes it
    arguments, past anything call_at() reads in front of it (a shell prompt, an assignment, a wrapper)."""
    if "${" in seg:
        return
    for start, end in pieces(seg):
        at = call_at(seg, start, end)
        words = seg[at:end].split() if at is not None else []
        if words and words[0] in ("audit-scan", "audit-mem"):
            if (words[0] == "audit-scan" and len(words) >= 2) or (words[0] == "audit-mem" and len(words) >= 3):
                marker(check_file, n, words[0], " ".join(words[1:]), "call")

# The plugin's agents, by the name their frontmatter gives, and the fork skills, by the agent they run as.
agents, forks = {}, {}
for d, pattern in (("agents", None), ("skills", None)):
    if not os.path.isdir(os.path.join(tree, d)):
        continue
    for name in sorted(os.listdir(os.path.join(tree, d))):
        path = "%s/%s" % (d, name) if d == "agents" else "%s/%s/SKILL.md" % (d, name)
        if d == "agents" and not name.endswith(".md"):
            continue
        if not os.path.isfile(os.path.join(tree, path)):
            continue
        try:
            fm, body, first = split_doc(read(path))
        except (OSError, UnicodeDecodeError):
            continue
        if d == "agents":
            agents[value(fm, "name")] = (path, body, first)
        elif value(fm, "agent").startswith("auditor:"):
            forks[path] = value(fm, "agent")[len("auditor:"):]

# A code span that names one of the plugin's agents, by its plugin-scoped name or bare.
AGENT_SPAN = r'`(?:auditor:)?([a-z][a-z0-9-]*)`'

def spawned(body):
    """The agents a command spawns: each code span naming an agent (AGENT_SPAN) after spawn, delegate or run in
    its sentence, or after another word that hands it work (SPAWN_OTHER) in a sentence that names no auditor:
    skill, and the agent each list item under such a paragraph starts with. A list item that starts with
    another command's name describes that command."""
    names, spawns = set(), False
    for para in re.split(r'\n\s*\n|\n(?=\s*(?:\d+[a-z]?[.)]|[-*+])\s)', "\n".join(body)):
        item = re.match(r'^\s+[-*+]\s+' + AGENT_SPAN, para)
        if spawns and item and item.group(1) in agents:
            names.add(item.group(1))
            continue
        spawns = False
        if re.match(r'^\s*[-*+]\s+\**`/', para):
            continue
        for sentence in re.split(r'(?<=[.!?])\s+', para):
            m = SPAWN.search(sentence)
            if not m and all(s in agents for s in re.findall(r'`auditor:([a-z][a-z0-9-]*)', sentence)):
                m = SPAWN_OTHER.search(sentence)
            if m:
                spawns = True
                names.update(a for a in re.findall(AGENT_SPAN, sentence[m.end():]) if a in agents)
    return names

def asks(rest):
    """Whether the text right after a call's span says it asks: ", which asks", with nothing before it."""
    return bool(ASKS.match(rest))

def calls(body, first):
    """(line, path, words, text) for each rooted call: an entry point first in a code span with words after
    it, or first on a fenced code line. A call whose own clause says it asks is a documented prompt."""
    res = []
    for n, seg, para, ptext, end, fenced in segments(body, first):
        m = CALL.match(seg)
        if not m or m.group(2) not in entry:
            continue
        words = m.group(3).split()
        if not words and not fenced:
            continue
        if not fenced and asks(ptext[end:]):
            continue
        res.append((n, m.group(2), words, seg))
    return res

def covered(rules, path, words):
    for r in rules:
        if not r or r[0] or r[2] != path:
            continue
        if (r[4] and words[:len(r[3])] == r[3]) or (not r[4] and words == r[3]):
            return True
    return False

def check_calls(owner, rules, sources):
    parsed = [parse_rule(e) for _, e in rules]
    for src, body, first in sources:
        for n, path, words, seg in calls(body, first):
            if not covered(parsed, path, words):
                finding("C5", src, n, "%s does not pre-approve this call: %s" % (owner, seg[:160]))

def relative(f, n, seg, fenced, root):
    """C7: a call of an entry point by a path relative to the working directory, in any simple command of seg."""
    for start, end in pieces(seg):
        at = call_at(seg, start, end)
        if at is None:
            continue
        rest = seg[at:]
        m = REL.match(rest)
        if m and (fenced or rest[m.end():].strip(' "')):
            finding("C7", f, n, 'runs %s by a path relative to the working directory, where the tree under audit can '
                    'put a file of its own; name it as "%s/%s": %s' % (m.group(1), root, m.group(1), seg[:160]))
            return

def corpus(f, body, first):
    """C6 and C7 for a corpus file: every call, in a code span with words after the path or on a line of a shell
    code block (not a comment line), names the entry point as "<auditor-skill root>/<path>", quoted, first, with
    no $ or backtick in the call."""
    infos = {}
    body = [re.sub(r'^(> ?)+', '', l) for l in body]
    for n, seg, para, ptext, end, fenced in segments(body, first, infos):
        if fenced and (infos.get(n, "") not in SHELL_FENCES or seg.startswith("#")):
            continue
        if seg.startswith("Bash("):
            continue   # a rule, as a command lists it
        for m in ANY_ROOT.finditer(seg):
            path = m.group(4)
            if path not in entry or (not fenced and not seg[m.end():].strip()):
                continue   # not an entry point, or the path alone names it
            what = []
            if m.group(2) != CORPUS_ROOT:
                what.append("the root is %s, which only a command body substitutes; the corpus writes %s" % (m.group(2), CORPUS_ROOT))
            if not (m.group(1) == '"' and m.group(5) == '"' and not m.group(3)):
                what.append('not quoted as "%s/%s"' % (CORPUS_ROOT, path))
            lead = seg[:m.start()].strip()
            if lead and lead not in READERS:
                what.append("%r in front of it" % lead)
            if "$" in seg:
                what.append("a $ in the call")
            if "`" in seg:
                what.append("a backtick in the call")
            if what:
                finding("C6", f, n, "%s: %s" % ("; ".join(what), seg[:160]))
            elif not lead and path.startswith(RELEASE):
                marker(f, n, path[len(RELEASE):], seg[m.end():], "call")
        bare(f, n, seg)
        relative(f, n, seg, fenced, CORPUS_ROOT)

for f in files:
    try:
        text = read(f)
    except (OSError, UnicodeDecodeError) as e:
        print("cannot read %s: %s" % (f, e), file=sys.stderr); sys.exit(2)
    fm, body, first = split_doc(text)
    root_skill = f == "SKILL.md"
    command = f.startswith("commands/")
    var = "CLAUDE_SKILL_DIR" if root_skill else "CLAUDE_PLUGIN_ROOT"
    if not (command or root_skill or f.startswith(("agents/", "skills/"))):
        corpus(f, body, first)
        continue

    # allowed-tools rules
    rules = rules_of(fm)
    for n, e in rules:
        r = parse_rule(e)
        if r is None:
            continue
        if r is False:
            finding("C2", f, n, "the rule names a path from the root, but not as its quoted first word: %s" % e)
            continue
        test_x, rvar, path, fixed, star = r
        if rvar != var:
            finding("C2", f, n, "the rule names the root as ${%s}, not ${%s}: %s" % (rvar, var, e))
        full = os.path.join(tree, path)
        if path.startswith(RELEASE):
            if path[len(RELEASE):] not in bins:
                finding("C2", f, n, "%s is no binary a crate under tools/auditor-tools declares" % path)
            elif os.path.lexists(full) and not (os.path.isfile(full) and os.access(full, os.X_OK)):
                finding("C2", f, n, "%s is built but is not an executable file" % path)
        elif path not in modes:
            finding("C2", f, n, "%s is no tracked file" % path)
        elif modes[path] != "100755":
            finding("C2", f, n, "%s is mode %s, not 100755" % (path, modes[path]))
        elif not first_line(path).startswith("#!"):
            finding("C2", f, n, "%s has no #! line" % path)
        if not test_x and path.startswith(RELEASE):
            marker(f, n, path[len(RELEASE):], " ".join(fixed + (["*"] if star else [])), "rule")
    preflight_rule = 'Bash("${%s}/scripts/preflight.sh" *)' % var
    if (command or root_skill) and preflight_rule not in [e for _, e in rules]:
        finding("C4", f, 1, "allowed-tools does not pre-approve %s" % preflight_rule)

    # the body
    first_entry = None
    for n, seg, para, ptext, end, fenced in segments(body, first):
        if not (fenced and seg.startswith("#")):
            relative(f, n, seg, fenced, "${%s}" % var)
        bare(f, n, seg)
        if re.search(r'<auditor-skill root>/|\$CLAUDE_(PLUGIN_ROOT|SKILL_DIR)\b', seg):
            finding("C1", f, n, "the root is written so that Claude Code does not fill it in: %s" % seg[:120])
        for m in ROOTED.finditer(seg):
            path = m.group(3)
            if path not in entry:
                continue
            if first_entry is None:
                first_entry = (n, seg, para, ptext, path)
            what = []
            s, e = m.start(), m.end()
            quoted = s > 0 and seg[s - 1] == '"' and seg[e:e + 1] == '"' and not m.group(2)
            if not quoted:
                what.append("not quoted as \"${%s}/%s\"" % (var, path))
            if m.group(1) != var:
                what.append("the root is ${%s}, not ${%s}" % (m.group(1), var))
            lead = seg[:s - 1 if quoted else s].strip()
            if lead and lead not in READERS:
                what.append("%r in front of it" % lead)
            if "$" in seg.replace("${CLAUDE_PLUGIN_ROOT}", "").replace("${CLAUDE_SKILL_DIR}", ""):
                what.append("a $ beside the root")
            what.extend(sorted(set(operators(seg))))
            what.extend("a redirect outside a run directory: %s" % t for t in redirects(seg))
            if what:
                finding("C1", f, n, "%s: %s" % ("; ".join(what), seg[:160]))
            elif not lead and path.startswith(RELEASE):
                marker(f, n, path[len(RELEASE):], seg[e + 1:], "call")
    # an entry point named outside a code span or fenced block
    flat, fence = [], None
    for line in body:
        fm_ = re.match(r'^\s*(`{3,}|~{3,})', line)
        if fence:
            if fm_ and fm_.group(1)[0] == fence[0]:
                fence = None
            flat.append("")
            continue
        if fm_:
            fence = fm_.group(1); flat.append(""); continue
        flat.append(line)
    flat = re.sub(r'(`+)(.+?)\1', lambda mm: re.sub(r'[^\n]', ' ', mm.group(0)), "\n".join(flat), flags=re.S)
    for i, line in enumerate(flat.split("\n")):
        for mm in ROOTED.finditer(line):
            if mm.group(3) in entry:
                finding("C1", f, first + i, "a bundled entry point outside a code span or fenced block: %s" % line.strip()[:120])
    if command or root_skill:
        want = (r'^\*\*Step 0 — Preflight' if root_skill else r'^\s*0\. \*\*Preflight')
        if first_entry is None:
            finding("C4", f, 1, "the body runs no preflight.sh as step 0")
        else:
            n, seg, para, ptext, path = first_entry
            if path != "scripts/preflight.sh":
                finding("C4", f, n, "the first entry point the body names is %s, not scripts/preflight.sh in step 0" % path)
            elif seg.strip() != '"${%s}/scripts/preflight.sh"' % var:
                finding("C4", f, n, "step 0 runs preflight.sh with something beside it: %s" % seg)
            elif not re.match(want, para):
                finding("C4", f, n, "preflight.sh first appears outside a paragraph that starts %s" % want.replace("\\", ""))
            elif not re.search(r'(?i)refus', ptext) or not re.search(r'(?i)denied', ptext):
                finding("C4", f, n, "step 0 does not say that a refusal and a denied call both stop the run")
        if not re.search(r'(?i)\bstep 0 again\b', "\n".join(body)):
            finding("C4", f, 1, "the body does not say that a resumed invocation runs step 0 again")

    # every call in the body, and in the bodies of the agents it spawns (or, for a fork skill, the agent it runs
    # as), is one of its own rules: the path, then the rule's fixed words
    if command or root_skill or f in forks:
        sources = [(f, body, first)]
        names = {forks[f]} if f in forks else spawned(body)
        sources.extend(agents[a] for a in sorted(names) if a in agents)
        check_calls(f, rules, sources)

    # C8: a command, a skill and the root SKILL.md name each of the plugin's agents as auditor:<agent>
    if command or root_skill or f.startswith("skills/"):
        for n, seg, para, ptext, end, fenced in segments(body, first):
            if not fenced and seg.strip() in agents:
                finding("C8", f, n, "names the agent %s bare: a project's .claude/agents/%s.md answers to that name "
                        "ahead of the plugin's agent; write auditor:%s" % (seg.strip(), seg.strip(), seg.strip()))

for line in out:
    print(line)
EOF

# check <tree> <file>...: the checker's findings for those files of <tree>, on stdout; status 2 when it fails
check() {
  local tree=$1; shift
  git -C "$tree" ls-files -s -- scripts templates tools > "$T/index" || return 2
  (cd / && exec python3 -I -c "$PY" "$tree" "$T/index" "$@")
}

# ---- 0. the checks themselves ---------------------------------------------------------------------------------
fx="$T/fx"
mkdir -p "$fx/scripts/tests" "$fx/scripts/lib" "$fx/templates/poc" "$fx/tools/auditor-tools/src/bin" \
  "$fx/commands" "$fx/agents" "$fx/skills/s"
printf '#!/bin/bash\nexit 0\n' > "$fx/scripts/ok.sh"
printf '#!/bin/bash\nexit 0\n' > "$fx/scripts/preflight.sh"
printf '#!/usr/bin/env -S python3 -I\n' > "$fx/scripts/rec.py"
printf '#!/bin/bash\nexit 0\n' > "$fx/scripts/plain.sh"
printf 'exit 0\n' > "$fx/scripts/noshebang.sh"
printf '#!/usr/bin/env bash\ncat\n' > "$fx/scripts/filter.sh"
printf '#!/bin/bash\n' > "$fx/scripts/tests/t.sh"
printf '#!/bin/bash\n' > "$fx/templates/poc/run.sh"
printf '[package]\nname = "t"\n\n[[bin]]\nname = "audit-scan"\npath = "src/bin/audit-scan.rs"\n\n[[bin]]\nname = "audit-mem"\npath = "src/bin/audit-mem.rs"\n' \
  > "$fx/tools/auditor-tools/Cargo.toml"
: > "$fx/tools/auditor-tools/src/bin/audit-scan.rs"; : > "$fx/tools/auditor-tools/src/bin/audit-mem.rs"
chmod 755 "$fx/scripts/ok.sh" "$fx/scripts/preflight.sh" "$fx/scripts/rec.py" "$fx/scripts/noshebang.sh" \
  "$fx/scripts/filter.sh" "$fx/scripts/tests/t.sh" "$fx/templates/poc/run.sh"
chmod 644 "$fx/scripts/plain.sh"

R='${CLAUDE_PLUGIN_ROOT}'
B="$R/tools/auditor-tools/target/release"
STEP0="0. **Preflight.** Run \`\"$R/scripts/preflight.sh\"\`, with no arguments. On a refusal, stop; a call that is denied stops the run too. A resumed invocation runs step 0 again."
# cmd <name> <rule>... -- <body line>...: a command whose allowed-tools pre-approve preflight.sh, ok.sh and the rules
cmd() {
  local f="$fx/commands/$1.md"; shift
  { printf -- '---\ndescription: "A command."\nallowed-tools:\n  - Read\n'
    printf "  - 'Bash(\"%s/scripts/preflight.sh\" *)'\n  - 'Bash(\"%s/scripts/ok.sh\" *)'\n" "$R" "$R"
    while [ $# -gt 0 ] && [ "$1" != -- ]; do printf '  - %s\n' "$1"; shift; done
    printf -- '---\n\n'; [ $# -gt 0 ] && shift
    printf '%s\n' "$STEP0"
    while [ $# -gt 0 ]; do printf '%s\n' "$1"; shift; done; } > "$f"
}
cmd good "'Bash(\"$R/scripts/rec.py\" *)'" "'Bash(\"$B/audit-scan\" --contract=1 *)'" \
  "'Bash(\"$B/audit-mem\" warm --contract=1 *)'" "'Bash(\"$R/templates/poc/run.sh\" *)'" \
  "'Bash(test -x \"$B/audit-mem\")'" "Edit(/audit_*/**)" -- \
  "1. Run \`\"$R/scripts/ok.sh\" new audit\` and \`\"$R/scripts/rec.py\" tokens|lamports [--by owner,mint|mint] incident_<n>/corpus*/x.jsonl > incident_<n>/out.txt\`." \
  "2. When built (\`test -x \"$B/audit-scan\"\`), \`\"$B/audit-scan\" --contract=1 . --out audit_<n>/prescan.json\` and" \
  "   \`\"$B/audit-mem\" warm --contract=1 --program-id <id>\`; \`audit-mem warm --contract=1 --program-id <id>\`, \`audit-mem init\`." \
  "3. Check \`test -f \"$R/templates/poc/run.sh\"\`; mention \`\"$B/audit-mem\"\` alone; read \`$R/references/x.md\`." \
  "4. Prose names \`run.sh --crate\` and \`\"$R/scripts/filter.sh\"\` behind \`x 2>&1 | bash \"$R/scripts/filter.sh\"\`." \
  "5. Keep \`\"$R/scripts/ok.sh\" check x > audit_<n>/out.txt 2>/dev/null\` and \`\"$R/scripts/ok.sh\" check x 2>&1\`, \`\"$R/scripts/ok.sh\" check <in-scope directory> &> incident_<n>/log.txt\`." \
  "6. Spawn \`auditor:fx-runner\` on it; \`\"$R/templates/poc/run.sh\" --crate <R>/poc/<ID>\` runs it, and \`\"$R/scripts/rec.py\" --crate x\`, which asks, does not." \
  "" '```bash' "\"$R/scripts/ok.sh\" check audit_<n> --cluster mainnet-beta" '```'
cmd c1-bash -- "1. \`bash \"$R/scripts/ok.sh\" new audit\`"
cmd c1-cd -- "1. \`cd sub && \"$R/scripts/ok.sh\"\`"
cmd c1-env -- "1. \`FOO=1 \"$R/scripts/ok.sh\" new audit\`"
cmd c1-unquoted -- "1. \`$R/scripts/ok.sh new audit\`"
cmd c1-half-quoted -- "1. \`\"$R\"/scripts/ok.sh new audit\`"
cmd c1-dollar -- "1. \`\"$R/scripts/ok.sh\" --run \"\$RUN\"\`"
cmd c1-pipe -- "1. \`\"$R/scripts/ok.sh\" check x | head -1\`"
cmd c1-semicolon -- "1. \`\"$R/scripts/ok.sh\" check x; echo done\`"
cmd c1-and -- "1. \`\"$R/scripts/ok.sh\" check x && true\`"
cmd c1-skill-dir -- "1. \`\"\${CLAUDE_SKILL_DIR}/scripts/ok.sh\" check x\`"
cmd c1-continued -- '```bash' "\"$R/scripts/ok.sh\" check audit_<n> \\" "  --more" '```'
cmd c1-wrapped-span -- "1. Run \`\"$R/scripts/ok.sh\" check" "   x | tail -1\` across a line break."
cmd c1-cmp -- "1. Compare with \`cmp \"$R/templates/poc/run.sh\" <crate>/run.sh\`."
cmd c1-diff -- "1. Compare with \`diff \"$R/templates/poc/run.sh\" <crate>/run.sh\`."
cmd c1-procsub -- "1. \`\"$R/scripts/ok.sh\" diff <(cat x)\`"
cmd c1-redirect -- "1. \`\"$R/scripts/ok.sh\" log > ../../.zshrc\`"
cmd c1-redirect-in -- "1. \`\"$R/scripts/ok.sh\" check < /etc/hosts\`"
cmd c1-pipe-tight -- "1. \`\"$R/scripts/ok.sh\" log|sh\`"
cmd c1-pipe-path -- "1. \`\"$R/scripts/ok.sh\" log|/bin/sh\`"
cmd c1-amp-tight -- "1. \`\"$R/scripts/ok.sh\" log&curl x\`"
cmd c1-redirect-dotdot -- "1. \`\"$R/scripts/ok.sh\" log > audit_1/../../.zshrc\`"
cmd c1-redirect-dup -- "1. \`\"$R/scripts/ok.sh\" log >& ../x\`"
cmd c1-redirect-masked -- "1. \`\"$R/scripts/ok.sh\" log <x >../../.zshrc\`"
cmd c1-redirect-tight -- "1. \`\"$R/scripts/ok.sh\" log <x>../../.zshrc\`"
cmd c1-placeholder-slash -- "1. \`\"$R/scripts/ok.sh\" log <x>/tmp/evil\`"
cmd c1-placeholder-space -- "1. \`\"$R/scripts/ok.sh\" log <x> ../../.zshrc\`"
cmd c1-placeholder-tilde -- "1. \`\"$R/scripts/ok.sh\" log <x>~/.zshrc\`"
cmd c1-prose -- "1. Run $R/scripts/ok.sh new audit before anything else."
cmd c1-indented -- "1. Run this:" "" "    \"$R/scripts/ok.sh\" new audit"
cmd c1-corpus-root -- "1. \`\"<auditor-skill root>/scripts/ok.sh\" new audit\`"
cmd c1-unbraced-root -- "1. \`\"\$CLAUDE_PLUGIN_ROOT/scripts/ok.sh\" new audit\`"
cmd c2-missing "'Bash(\"$R/scripts/gone.sh\" *)'" --
cmd c2-mode "'Bash(\"$R/scripts/plain.sh\" *)'" --
cmd c2-shebang "'Bash(\"$R/scripts/noshebang.sh\" *)'" --
cmd c2-bin "'Bash(\"$B/audit-logs\" *)'" --
cmd c2-bash-rule "'Bash(bash \"$R/scripts/ok.sh\" *)'" --
cmd c3-scan-rule "'Bash(\"$B/audit-scan\" *)'" --
cmd c3-mem-rule "'Bash(\"$B/audit-mem\" warm *)'" --
cmd c3-scan-call "'Bash(\"$B/audit-scan\" --contract=1 *)'" -- "1. \`\"$B/audit-scan\" . --out audit_<n>/prescan.json\`"
cmd c3-mem-call "'Bash(\"$B/audit-mem\" check --contract=1 *)'" -- "1. \`\"$B/audit-mem\" check --program-id <id> --contract=1\`"
cmd c3-mem-bare -- "1. \`audit-mem warm --program-id <id>\`"
cmd c3-scan-fenced "'Bash(\"$B/audit-scan\" --contract=1 *)'" -- '```bash' "\"$B/audit-scan\" --pretty ." '```'
cmd c3-scan-no-dir "'Bash(\"$B/audit-scan\" --contract=1 *)'" -- "1. \`\"$B/audit-scan\" --contract=1 --workflows .github/workflows\`"
cmd c3-scan-unknown "'Bash(\"$B/audit-scan\" --contract=1 *)'" -- "1. \`\"$B/audit-scan\" --contract=1 . -v\`"
cmd c3-do-body -- "1. \`while :; do audit-mem warm --program-id <id>; done\`"
# C5: each call is one of its command's rules, the agents it spawns too; a call its sentence says asks is not
cmd c5-unlisted -- "1. Run \`\"$R/templates/poc/run.sh\" --crate audit_<n>/poc/F-1\`."
cmd c5-agent -- "1. Spawn \`auditor:fx-runner\` on the crate."
cmd c5-agent-covered "'Bash(\"$R/scripts/rec.py\" *)'" -- "1. Delegate the walk to \`auditor:fx-runner\`."
cmd c5-agent-mention -- "1. Read what \`auditor:fx-runner\` wrote into the run directory."
cmd c5-agent-list -- "1. Run the reviewers in parallel:" "   - \`auditor:fx-other\` over the program." "   - \`auditor:fx-runner\` over the value flow."
cmd c5-agent-and -- "1. Run \`auditor:fx-other\` (checklists) and \`auditor:fx-runner\` (vectors) over their surfaces."
cmd c5-other-command -- "- **\`/auditor:other\`** runs \`auditor:fx-runner\` over the tree."
cmd c5-asks -- "1. Run \`\"$R/templates/poc/run.sh\" --crate x\`, which asks."
cmd c5-asks-later -- "1. Run \`\"$R/templates/poc/run.sh\" --crate x\`; a copy from outside it asks."
cmd c5-asks-next -- "1. Run \`\"$R/templates/poc/run.sh\" --crate x\`, then \`\"$R/scripts/rec.py\" y\`, which asks."
cmd c5-asks-never -- "1. Run \`\"$R/templates/poc/run.sh\" --crate audit_<n>/poc/F-1\`, which never asks."
cmd c5-asks-else -- "1. Run \`\"$R/templates/poc/run.sh\" --crate audit_<n>/poc/F-1\` as given, and anything else asks."
cmd c5-prompts -- "1. Run \`\"$R/templates/poc/run.sh\" --crate audit_<n>/poc/F-1\`: it prompts for nothing."
cmd c5-hand -- "1. Hand each finding to \`auditor:fx-runner\`."
cmd c5-use -- "1. Use the \`auditor:fx-runner\` agent on the crate."
cmd c5-task-tool -- "1. Start \`auditor:fx-runner\` with the Task tool."
cmd c5-skill-hand -- "1. Hand the crate to \`auditor:fx-runner\` through \`auditor:poc\`."
# C8: a command, a skill and the root SKILL.md name an agent as auditor:<agent> in every span, a mention too; an
# agent's own body may name one bare
cmd c8-bare -- "1. Spawn \`fx-other\` over the program."
cmd c8-bold -- "1. Spawn the **\`fx-other\`** agent over the program."
cmd c8-mention -- "1. Read what \`fx-other\` wrote into the run directory."
mkdir -p "$fx/skills/s8" && printf -- '---\nname: s8\ndescription: "A skill."\n---\n\nHand the tree to `fx-other`.\n' > "$fx/skills/s8/SKILL.md"
printf -- '---\nname: c8\ndescription: "An agent."\ntools: Read\n---\n\nRead what `fx-other` wrote.\n' > "$fx/agents/c8.md"
printf -- '---\ndescription: "A command."\nallowed-tools:\n  - '"'"'Bash("%s/scripts/preflight.sh" *)'"'"'\n  - '"'"'Bash("%s/scripts/ok.sh" new *)'"'"'\n  - '"'"'Bash("%s/scripts/rec.py" x)'"'"'\n---\n\n%s\n1. `"%s/scripts/ok.sh" new audit`, `"%s/scripts/rec.py" x`, then `"%s/scripts/ok.sh" check audit_1`.\n' \
  "$R" "$R" "$R" "$STEP0" "$R" "$R" "$R" > "$fx/commands/c5-fixed-word.md"
sed -e 's#`"${CLAUDE_PLUGIN_ROOT}/scripts/ok.sh" check audit_1`#`"${CLAUDE_PLUGIN_ROOT}/scripts/rec.py" x y`#' \
  "$fx/commands/c5-fixed-word.md" > "$fx/commands/c5-exact.md"
printf -- '---\ndescription: "A command."\nallowed-tools: Read\n---\n\n%s\n' "$STEP0" > "$fx/commands/c4-no-rule.md"
printf -- '---\ndescription: "A command."\nallowed-tools:\n  - '"'"'Bash("%s/scripts/preflight.sh" *)'"'"'\n---\n\n1. Read the tree.\n' "$R" \
  > "$fx/commands/c4-no-step.md"
cmd c4-late -- "1. \`\"$R/scripts/ok.sh\" new audit\`" "2. Then \`\"$R/scripts/preflight.sh\"\` again."
sed -e '/^0\. \*\*Preflight/d' "$fx/commands/c4-late.md" > "$fx/commands/c4-late.md.new" && mv "$fx/commands/c4-late.md.new" "$fx/commands/c4-late.md"
sed -e 's#^0\. \*\*Preflight\.\*\*#Step zero:#' "$fx/commands/good.md" > "$fx/commands/c4-paragraph.md"
sed -e 's#preflight\.sh"`, with#preflight.sh" --fast`, with#' "$fx/commands/good.md" > "$fx/commands/c4-args.md"
sed -e 's#; a call that is denied stops the run too\.#.#' "$fx/commands/good.md" > "$fx/commands/c4-no-denial.md"
sed -e 's# A resumed invocation runs step 0 again\.##' "$fx/commands/good.md" > "$fx/commands/c4-no-resume.md"
# agents and skills have no step 0; the root SKILL.md has it, from ${CLAUDE_SKILL_DIR}
printf -- '---\nname: fx-runner\ndescription: "An agent."\ntools: Read, Bash\n---\n\nRun `"%s/scripts/rec.py" x`.\n' "$R" \
  > "$fx/agents/fx-runner.md"
printf -- '---\nname: fx-other\ndescription: "An agent."\ntools: Read\n---\n\nRead the tree.\n' > "$fx/agents/fx-other.md"
mkdir -p "$fx/skills/fork"
printf -- '---\nname: f\ndescription: "A fork."\ncontext: fork\nagent: auditor:fx-runner\nallowed-tools: Read\n---\n\nRun as the agent.\n' \
  > "$fx/skills/fork/SKILL.md"
printf -- '---\nname: a\ndescription: "An agent."\ntools: Read, Bash\n---\n\nRun `"%s/scripts/ok.sh" check x`.\n' "$R" > "$fx/agents/good.md"
printf -- '---\nname: a\ndescription: "An agent."\ntools: Read, Bash\n---\n\nRun `bash "%s/scripts/ok.sh"`.\n' "$R" > "$fx/agents/c1.md"
printf -- '---\nname: s\ndescription: "A skill."\nallowed-tools:\n  - '"'"'Bash("%s/scripts/rec.py" *)'"'"'\n---\n\nRun `"%s/scripts/rec.py" x` or `"%s/scripts/rec.py" x | wc -l`.\n' "$R" "$R" "$R" \
  > "$fx/skills/s/SKILL.md"
printf -- '---\nname: x\ndescription: "A skill."\nallowed-tools:\n  - '"'"'Bash("${CLAUDE_SKILL_DIR}/scripts/preflight.sh" *)'"'"'\n  - '"'"'Bash("${CLAUDE_SKILL_DIR}/scripts/ok.sh" *)'"'"'\n---\n\n**Step 0 — Preflight.** Run `"${CLAUDE_SKILL_DIR}/scripts/preflight.sh"`; a refusal, or a denied call, stops the run. A resumed invocation runs Step 0 again.\nThen `"${CLAUDE_SKILL_DIR}/scripts/ok.sh" check x`.\n' \
  > "$fx/SKILL.md"
sed -e 's#CLAUDE_SKILL_DIR}/scripts/ok#CLAUDE_PLUGIN_ROOT}/scripts/ok#' "$fx/SKILL.md" > "$fx/skill-root.md"
# over 64 KiB, the one bad line last
{ sed -n '1,/^0\. \*\*Preflight/p' "$fx/commands/good.md"
  awk 'BEGIN { for (i = 0; i < 1400; i++) printf "Prose line %05d of a long command body, padded out with words to fill it up.\n", i }'
  printf '1. `bash "%s/scripts/ok.sh"`\n' "$R"; } > "$fx/commands/c1-large.md"
# C6 and C7: the corpus calls each entry point as "<auditor-skill root>/<path>", in a code span with words after
# it or on a line of a shell code block, and no file calls one by a path relative to the working directory
Q='<auditor-skill root>'
corp() { local f="$fx/$1"; shift; mkdir -p "$(dirname "$f")" && printf '%s\n' "$@" > "$f"; }
corp references/r/good.md "# Good" \
  "Run \`\"$Q/scripts/ok.sh\" new audit\`, then \`\"$Q/scripts/ok.sh\" check audit_1 | head -5\`." \
  "When built (\`test -x \"$Q/tools/auditor-tools/target/release/audit-scan\"\`), name \`$Q/scripts/ok.sh\` or \`scripts/ok.sh\` alone." \
  "A rule reads \`Bash(\"\${CLAUDE_PLUGIN_ROOT}/scripts/ok.sh\" *)\`; \`scripts/ok.sh\` and \`templates/poc/run.sh\` are files." \
  '```bash' "\"$Q/scripts/ok.sh\" check audit_1 2>/dev/null | wc -l" '# scripts/ok.sh check x, in a comment' '```' \
  '```json' "{\"command\": \"$Q/scripts/ok.sh check x\"}" '```' \
  '```bash' 'ROOT="<auditor-skill root>"' 'x=$("$ROOT/scripts/ok.sh" check audit_1)' '```' \
  "> \`\"$Q/scripts/ok.sh\" check x\` in a quote, and \`\"$Q/templates/poc/run.sh\" --crate audit_1/poc/F-1\`." \
  "Scan with \`\"$Q/tools/auditor-tools/target/release/audit-scan\" --contract=1 . --workflows .github/workflows --out audit_<n>/prescan.json\`," \
  "or \`audit-scan --contract=1 . --out audit_<n>/prescan.json\`; \`audit-mem warm --contract=1 --program-id <id>\`; \`audit-scan\` and \`audit-mem warm\` alone are names." \
  '```bash' "\"$Q/tools/auditor-tools/target/release/audit-mem\" regressions --contract=1 --program-id <id>" '# audit-scan --workflows .github/workflows, in a comment' '```' \
  '```json' '{"command": "audit-scan --workflows .github/workflows"}' '```' \
  "Its options go in any order (\`audit-scan --contract=1 --workflows .github/workflows .\`), a placeholder is one word" \
  "(\`audit-scan --contract=1 <changed program directory> --pretty\`), and \`audit-scan --contract=1\` alone is a name." \
  "Wrappers pass with their options: \`timeout -s KILL 60 audit-mem warm --contract=1 --program-id <id>\`, \`sudo -E audit-scan --contract=1 .\`," \
  "\`xargs -n 1 audit-mem warm --contract=1 --program-id\`, \`env -u HOME audit-scan --contract=1 . --out=audit_1/prescan.json 2>&1 | head\`;" \
  "\`command -v audit-scan\` and \`cargo build --release --bin audit-scan --bin audit-mem\` are no calls; nor are a lookup or a listing," \
  "\`command -v audit-scan audit-mem\`, \`command -V audit-mem warm x\`, \`sudo -l audit-scan --pretty .\`, \`sudo --list audit-mem warm x\`." \
  "Wrappers by path, long options and clusters pass with the marker: \`/usr/bin/env FOO=1 audit-scan --contract=1 .\`," \
  "\`/usr/bin/sudo -Eu me audit-scan --contract=1 .\`, \`sudo --user me audit-scan --contract=1 .\`, \`doas -u me audit-scan --contract=1 .\`," \
  "\`timeout --signal KILL 30 audit-mem warm --contract=1 --program-id <id>\`, \`chroot /srv audit-scan --contract=1 .\`," \
  "\`stdbuf -oL audit-scan --contract=1 .\`, \`taskset -c 0 audit-scan --contract=1 .\`, \`true && audit-scan --contract=1 . | head\`." \
  "Reserved words, and a ( or { after them, pass with the marker: \`if audit-scan --contract=1 . --out audit_1/prescan.json; then echo ok; fi\`," \
  "\`while :; do audit-mem warm --contract=1 --program-id <id>; done\`, \`until ! audit-mem check --contract=1 --program-id <id>; do :; done\`," \
  "\`if (audit-scan --contract=1 . --pretty); then { audit-mem warm --contract=1 --program-id <id>; }; fi\`, \`true || ! audit-scan --contract=1 .\`;" \
  "a ) ends a command: \`(audit-scan --contract=1 . --pretty)\`, \`(cd sub && audit-scan --contract=1 . --pretty)\`." \
  '```bash' 'case "$1" in scan) audit-scan --contract=1 . --pretty ;; esac' 'scan() { audit-scan --contract=1 . --pretty; }' \
  'audit-scan --contract=1 . --pretty   # slow; audit-mem warm first' "\"$Q/scripts/ok.sh\" check x   # or; scripts/ok.sh new" '```' \
  '```console' '$ audit-scan --contract=1 . --out audit_1/prescan.json' '$ env audit-mem warm --contract=1 --program-id <id>' \
  '% audit-scan --contract=1 --pretty .' '$ sudo -u me nice -n 5 audit-mem warm --contract=1 --program-id <id>' '```'
corp references/r/c6-bash.md "Run \`bash \"$Q/scripts/ok.sh\" new audit\`."
corp references/r/c6-cd.md '```bash' "cd sub && \"$Q/scripts/ok.sh\" check x" '```'
corp references/r/c6-env.md "Run \`FOO=1 \"$Q/scripts/ok.sh\" new\`."
corp references/r/c6-env-word.md "Run \`env \"$Q/scripts/ok.sh\" new\`."
corp references/r/c6-dollar.md "Run \`\"$Q/scripts/ok.sh\" --run \"\$RUN\"\`."
corp references/r/c6-unquoted.md "Run \`$Q/scripts/ok.sh new\`."
corp references/r/c6-half-quoted.md "Run \`\"$Q\"/scripts/ok.sh new\`."
corp references/r/c6-plugin-root.md "Run \`\"\${CLAUDE_PLUGIN_ROOT}/scripts/ok.sh\" new\`."
corp references/r/c6-backtick.md '```' "\"$Q/scripts/ok.sh\" check \`cat x\`" '```'
corp references/r/c6-quoted-fence.md '> ```sh' "> bash \"$Q/scripts/ok.sh\" check x" '> ```'
corp references/r/c6-wrapped.md "Run \`bash" "\"$Q/scripts/ok.sh\" new\` across a line break."
corp references/r/c6-tool.md "Run \`\"$Q/tools/auditor-tools/target/release/audit-mem\" warm --contract=1 --db \$DB\`."
# C3 in the corpus: a call of audit-scan or audit-mem without its marker, rooted or by its bare name
corp references/r/c3-span.md "Cross-check with \`audit-scan --workflows .github/workflows\` first."
corp references/r/c3-late.md "Run \`audit-scan . --contract=1 --out audit_<n>/prescan.json\`."
corp references/r/c3-rooted.md "Run \`\"$Q/tools/auditor-tools/target/release/audit-scan\" . --out audit_<n>/prescan.json\`."
corp references/r/c3-mem-fenced.md '```bash' "\"$Q/tools/auditor-tools/target/release/audit-mem\" warm --program-id <id>" '```'
corp docs/c3-bare-fenced.md '```sh' 'audit-mem init --db audit_1/audit-mem.db' '```'
corp templates/t/c3-mem-order.md "Run \`audit-mem --contract=1 regressions --program-id <id>\`."
corp references/r/c3-prompt.md '```console' '$ audit-scan --workflows .github/workflows' '```'
corp references/r/c3-env.md "Run \`env audit-scan --workflows .github/workflows\` first."
corp references/r/c3-no-dir.md "Run \`audit-scan --contract=1 --workflows .github/workflows --out audit_<n>/prescan.json\`."
corp references/r/c3-rooted-no-dir.md "Run \`\"$Q/tools/auditor-tools/target/release/audit-scan\" --contract=1 --pretty\`."
corp references/r/c3-mem-prompt.md '```console' '$ audit-mem warm --program-id <id>' '```'
corp references/r/c3-sudo.md "Run \`sudo -u me audit-scan --workflows .github/workflows\` first."
corp references/r/c3-sudo-flag.md "Run \`sudo -E audit-mem warm --program-id <id>\` first."
corp references/r/c3-nice.md '```bash' 'nice -n 5 audit-scan . --out audit_1/prescan.json' '```'
corp references/r/c3-xargs.md "Run \`xargs audit-scan --workflows .github/workflows\`."
corp references/r/c3-zsh-prompt.md '```console' '% audit-mem warm --program-id <id>' '```'
corp references/r/c3-dashdash.md "Run \`audit-scan --contract=1 --out audit_<n>/prescan.json -- .\`."
corp references/r/c3-unknown.md "Run \`audit-scan --contract=1 . --workflow .github/workflows\`."
# ... behind the wrappers the table above lacked, a long option, a cluster, a path, or another command
corp references/r/c3-doas.md "Run \`doas -u me audit-scan --workflows .github/workflows\` first."
corp references/r/c3-chroot.md "Run \`chroot /srv audit-scan . --out audit_<n>/prescan.json\`."
corp references/r/c3-stdbuf.md "Run \`stdbuf -oL audit-mem warm --program-id <id>\`."
corp references/r/c3-taskset.md "Run \`taskset -c 0 audit-scan . --pretty\`."
corp references/r/c3-sudo-long.md "Run \`sudo --user me audit-scan . --pretty\`."
corp references/r/c3-timeout-long.md "Run \`timeout --signal KILL 30 audit-mem warm --program-id <id>\`."
corp references/r/c3-sudo-cluster.md "Run \`sudo -Eu me audit-scan . --pretty\`."
corp references/r/c3-env-path.md "Run \`/usr/bin/env FOO=1 audit-scan . --pretty\`."
corp references/r/c3-after-and.md "Run \`true && audit-scan . --pretty\`."
corp references/r/c3-after-pipe.md '```bash' 'printf x | audit-mem warm --program-id <id>' '```'
# ... after a reserved word that opens a command, a ( or { after it, a case pattern or a function's ()
corp references/r/c3-while.md "Run \`while :; do audit-mem warm --program-id <id>; done\`."
corp references/r/c3-if.md '```bash' 'if audit-scan . --out audit_1/prescan.json; then echo ok; fi' '```'
corp references/r/c3-for.md "Run \`for p in a b; do audit-mem warm --program-id <id>; done\`."
corp references/r/c3-if-not.md "Run \`if ! audit-scan . --pretty; then exit 1; fi\`."
corp references/r/c3-or-not.md "Run \`true || ! audit-scan . --pretty\`."
corp references/r/c3-until.md '```bash' 'until audit-mem check --program-id <id>; do :; done' '```'
corp references/r/c3-elif.md "Run \`if false; then :; elif audit-scan . --pretty; then :; fi\`."
corp references/r/c3-else.md '```sh' 'if false; then :; else audit-mem warm --program-id <id>; fi' '```'
corp references/r/c3-then-group.md "Run \`if true; then { audit-scan . --pretty; }; fi\`."
corp references/r/c3-if-subshell.md '```bash' 'if (audit-scan . --pretty); then :; fi' '```'
corp references/r/c3-case.md '```bash' 'case "$1" in scan) audit-scan . --pretty ;; esac' '```'
corp references/r/c3-function.md '```bash' 'scan() { audit-scan . --pretty; }' '```'
corp docs/c6.md "Run \`sh \"$Q/scripts/ok.sh\" new\`."
corp FULL-AUDIT.md '```bash' "X=1 \"$Q/scripts/ok.sh\" check x" '```'
corp references/r/c7-span.md "Run \`scripts/ok.sh new audit\`."
corp references/r/c7-dot.md "Run \`./scripts/ok.sh new\`."
corp references/r/c7-bash.md "Run \`bash scripts/ok.sh new\`."
corp references/r/c7-quoted.md "Run \`\"scripts/ok.sh\" new\`."
corp references/r/c7-fenced.md '```bash' 'scripts/ok.sh check x' '```'
corp references/r/c7-prompt.md '```console' '$ scripts/ok.sh check x' '```'
corp references/r/c7-zsh-prompt.md '```console' '% scripts/ok.sh check x' '```'
corp references/r/c7-nice.md "Run \`nice -n 5 scripts/ok.sh check x\`."
corp references/r/c7-template.md "Run \`templates/poc/run.sh --crate x\`."
corp references/r/c7-after-and.md "Run \`true && scripts/ok.sh check x\`."
corp references/r/c7-env-path.md "Run \`/usr/bin/env scripts/ok.sh check x\`."
corp references/r/c7-doas.md "Run \`doas scripts/ok.sh check x\`."
corp references/r/c7-if.md "Run \`if scripts/ok.sh check x; then :; fi\`."
corp references/r/c7-while.md '```bash' 'while :; do scripts/ok.sh check x; done' '```'
corp references/r/c7-not.md "Run \`! ./scripts/ok.sh check x\`."
corp references/r/c7-subshell.md '```bash' 'if true; then (scripts/ok.sh check x); fi' '```'
corp templates/t/c7-cd.md '```' 'cd sub; scripts/ok.sh check x' '```'
cmd c7-relative -- "1. Run \`scripts/ok.sh new audit\`."
cmd c7-if-body -- "1. Run \`if scripts/ok.sh check x; then :; fi\`."
printf -- '---\nname: a\ndescription: "An agent."\ntools: Read, Bash\n---\n\nRun `bash ./scripts/ok.sh check x`.\n' > "$fx/agents/c7.md"
# over 64 KiB, the one bad line last
{ awk 'BEGIN { for (i = 0; i < 1400; i++) printf "Prose line %05d of a long reference, padded out with words to fill it up.\n", i }'
  printf 'Run `bash "%s/scripts/ok.sh" new`.\n' "$Q"; } > "$fx/references/r/c6-large.md"
git -C "$fx" init -q 2>/dev/null && git -C "$fx" add -- . 2>/dev/null || { bad "cannot make the fixture repository"; }
size=$(wc -c < "$fx/commands/c1-large.md"); size=${size//[!0-9]/}
[ "${size:-0}" -gt 65536 ] && ok "the large fixture is ${size} bytes" || bad "the large fixture is only ${size:-0} bytes"

# expect <file> <checks>: the checker's findings for that fixture file are exactly those check ids
expect() {
  local f=$1 want=$2 got
  got=$(check "$fx" "$f") || { bad "the checker failed on $f"; return; }
  got=$(printf '%s\n' "$got" | cut -f1 | LC_ALL=C sort -u | tr '\n' ' ' | sed 's/ *$//')
  if [ "$got" = "$want" ]; then ok "fixture $f: [${want}]"
  else bad "fixture $f: findings [${got}], want [${want}]: $(check "$fx" "$f" | sed -n '1,3p')"; fi
}
expect commands/good.md ""
for c in bash cd env unquoted half-quoted dollar pipe semicolon and skill-dir continued wrapped-span cmp diff \
    procsub redirect redirect-in pipe-tight pipe-path amp-tight redirect-dotdot redirect-dup redirect-masked \
    redirect-tight placeholder-slash placeholder-space placeholder-tilde prose indented corpus-root \
    unbraced-root large; do
  expect "commands/c1-$c.md" C1
done
expect commands/c2-missing.md C2; expect commands/c2-mode.md C2; expect commands/c2-shebang.md C2
expect commands/c2-bin.md C2; expect commands/c2-bash-rule.md C2
# a rooted call without the marker is also no call its marked rule pre-approves
expect commands/c3-scan-rule.md C3; expect commands/c3-mem-rule.md C3; expect commands/c3-scan-call.md "C3 C5"
expect commands/c3-mem-call.md "C3 C5"; expect commands/c3-mem-bare.md C3; expect commands/c3-scan-fenced.md "C3 C5"
expect commands/c3-scan-no-dir.md C3; expect commands/c3-scan-unknown.md C3; expect commands/c3-do-body.md C3
expect commands/c5-unlisted.md C5; expect commands/c5-agent.md C5; expect commands/c5-agent-covered.md ""
expect commands/c5-agent-mention.md ""; expect commands/c5-asks.md ""; expect commands/c5-fixed-word.md C5
expect commands/c5-asks-later.md C5; expect commands/c5-asks-next.md C5
expect commands/c5-agent-list.md C5; expect commands/c5-agent-and.md C5; expect commands/c5-other-command.md ""
expect commands/c5-exact.md C5; expect skills/fork/SKILL.md C5
for c in asks-never asks-else prompts hand use task-tool; do expect "commands/c5-$c.md" C5; done
expect commands/c5-skill-hand.md ""
expect commands/c8-bare.md C8; expect commands/c8-bold.md C8; expect commands/c8-mention.md C8; expect skills/s8/SKILL.md C8
expect agents/c8.md ""
expect commands/c4-no-rule.md C4; expect commands/c4-no-step.md C4; expect commands/c4-late.md C4
expect commands/c4-paragraph.md C4; expect commands/c4-args.md C4; expect commands/c4-no-denial.md C4
expect commands/c4-no-resume.md C4
expect agents/good.md ""; expect agents/c1.md C1; expect skills/s/SKILL.md C1; expect SKILL.md ""
expect references/r/good.md ""
for c in bash cd env env-word dollar unquoted half-quoted plugin-root backtick quoted-fence wrapped tool large; do
  expect "references/r/c6-$c.md" C6
done
expect docs/c6.md C6; expect FULL-AUDIT.md C6
for c in span late rooted mem-fenced prompt env no-dir rooted-no-dir mem-prompt sudo sudo-flag nice xargs zsh-prompt \
    dashdash unknown doas chroot stdbuf taskset sudo-long timeout-long sudo-cluster env-path after-and after-pipe \
    while if for if-not or-not until elif else then-group if-subshell case function; do
  expect "references/r/c3-$c.md" C3
done
expect docs/c3-bare-fenced.md C3; expect templates/t/c3-mem-order.md C3
for c in span dot bash quoted fenced template prompt zsh-prompt nice after-and env-path doas if while not subshell; do
  expect "references/r/c7-$c.md" C7
done
expect templates/t/c7-cd.md C7; expect commands/c7-relative.md C7; expect commands/c7-if-body.md C7; expect agents/c7.md C7
line=$(check "$fx" references/r/c6-large.md | cut -f2)
total=$(wc -l < "$fx/references/r/c6-large.md"); total=${total//[!0-9]/}
[ "$line" = "references/r/c6-large.md:$total" ] && ok "the large corpus fixture is read to its last line ($total)" \
  || bad "the large corpus fixture's finding is at [$line], want references/r/c6-large.md:$total"
# the large fixture's finding is its last line
line=$(check "$fx" commands/c1-large.md | cut -f2)
total=$(wc -l < "$fx/commands/c1-large.md"); total=${total//[!0-9]/}
[ "$line" = "commands/c1-large.md:$total" ] && ok "the large fixture is read to its last line ($total)" \
  || bad "the large fixture's finding is at [$line], want commands/c1-large.md:$total"
# the root SKILL.md runs its entry points from ${CLAUDE_SKILL_DIR}: from ${CLAUDE_PLUGIN_ROOT} is a finding there, in
# its body (C1) and in its rules (C2)
cp "$fx/skill-root.md" "$fx/SKILL.md"; git -C "$fx" add -- SKILL.md 2>/dev/null
expect SKILL.md "C1 C2"
# and its calls are its own rules': rec.py is not one of them
{ sed -e 's#CLAUDE_PLUGIN_ROOT}/scripts/ok#CLAUDE_SKILL_DIR}/scripts/ok#' "$fx/skill-root.md"
  printf 'Also `"${CLAUDE_SKILL_DIR}/scripts/rec.py" x`.\n'; } > "$fx/SKILL.md"
expect SKILL.md C5
# and a resumed invocation of it runs step 0 again, as each command's does
sed -e 's#CLAUDE_PLUGIN_ROOT}/scripts/ok#CLAUDE_SKILL_DIR}/scripts/ok#' -e 's# A resumed invocation runs Step 0 again\.##' \
  "$fx/skill-root.md" > "$fx/SKILL.md"
expect SKILL.md C4

# ---- 1-4. the tree ----------------------------------------------------------------------------------------------
cd "$TREE" || exit 1
set --
for f in commands/*.md agents/*.md skills/*/SKILL.md SKILL.md; do [ -f "$f" ] && set -- "$@" "$f"; done
[ $# -gt 0 ] || { bad "no command, agent or skill files in $TREE"; }
nbodies=$#
for f in FULL-AUDIT.md checklists/*.md known-vectors/*.md discovery/*.md; do [ -f "$f" ] && set -- "$@" "$f"; done
find references templates docs -type f -name '*.md' 2>/dev/null | LC_ALL=C sort > "$T/corpus-files"
while IFS= read -r f; do set -- "$@" "$f"; done < "$T/corpus-files"
[ $# -gt $((nbodies + 100)) ] || bad "only $(($# - nbodies)) corpus files in $TREE"
# Findings the tree has until the edits that fix them land, one to a line, each <check> <file> <the text it
# shows>: the check fails on any other finding, and on a listed one it no longer makes, whose line is then to
# be deleted here.
KNOWN='
C6	docs/output-and-rigor.md	not quoted as "<auditor-skill root>/scripts/rundir.sh": <auditor-skill root>/scripts/rundir.sh new
'
found=$(check "$TREE" "$@"); rc=$?
if [ "$rc" -ne 0 ]; then bad "the checker failed on $TREE (status $rc)"
else
  n=0; seen=""
  while IFS='	' read -r id at what; do
    [ -n "$id" ] || continue
    k=""
    while IFS='	' read -r kid kfile ktext; do
      [ -n "$kid" ] && [ "$id" = "$kid" ] && [ "${at%:*}" = "$kfile" ] && case "$what" in *"$ktext"*) k=y ;; esac
    done <<EOF2
$KNOWN
EOF2
    if [ -n "$k" ]; then seen="$seen$id ${at%:*};"; ok "known until its edit lands: $id $at"; continue; fi
    n=$((n + 1)); bad "$id $at: $what"
  done <<EOF
$found
EOF
  while IFS='	' read -r kid kfile ktext; do
    [ -n "$kid" ] || continue
    case "$seen" in *"$kid $kfile;"*) ;; *) bad "$kid $kfile is fixed: delete it from KNOWN in scripts/tests/test-command-forms.sh" ;; esac
  done <<EOF
$KNOWN
EOF
  [ "$n" -eq 0 ] && ok "$nbodies bodies and $(($# - nbodies)) corpus files: every entry point in the one form its rule pre-approves, none by a relative path, and preflight.sh as step 0"
fi

# ---- 5. wording the flows depend on ------------------------------------------------------------------------
# file <TAB> text that must stay in it, on one line of the file.
while IFS='	' read -r f want; do
  [ -n "$f" ] || continue
  if [ -f "$f" ] && grep -qF -- "$want" "$f"; then ok "pin $f: $want"; else bad "P $f lost: $want"; fi
done <<'PINS'
commands/hunt.md	Run it in the foreground, never with `run_in_background`, and give the Bash
commands/hunt.md	invoke `auditor:hunt --resume 3 incident_<n>` through the Skill tool once it
commands/hunt.md	background command's completion notice starts has none, so spawn every agent in
commands/respond.md	foreground, never with `run_in_background`, and give the Bash call a timeout
commands/respond.md	`auditor:respond --resume 4 incident_<n>` through the Skill tool once it
commands/respond.md	background command's completion notice starts has none, so spawn every agent in
commands/audit-cycle.md	a turn that a background agent's or background command's completion notice starts has none
commands/audit-assist.md	a turn that a background agent's or background command's completion notice starts has none
commands/threat-model.md	a turn that a background agent's or background command's completion notice starts has none
commands/poc.md	a turn that a background agent's or background command's completion notice starts has none
commands/patch.md	a turn that a background agent's or background command's completion notice starts has none
SKILL.md	a turn that a background agent's or background command's completion notice starts has none
commands/audit.md	Give each runner call (`target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/audit-cycle.md	Give each runner call (`run.sh`, `target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/audit-assist.md	Give each runner call (`run.sh`, `target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/diff-audit.md	Give each runner call (`target.sh`, `deps.sh`) and the `git-ro.sh copy` call the Bash tool's longest timeout
commands/quick-scan.md	Give each runner call (`deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/re-audit.md	Give each runner call (`run.sh`, `target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/poc.md	Give each runner call (`run.sh`, `target.sh`) the Bash tool's longest timeout
commands/patch.md	Give each runner call (`run.sh`, `target.sh`) the Bash tool's longest timeout
SKILL.md	Give each runner call (`target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
agents/poc-engineer.md	Give each `run.sh` call and the `git-ro.sh copy` call the Bash tool's longest timeout
agents/patch-engineer.md	Give each runner call (`run.sh`, `target.sh`) the Bash tool's longest timeout
agents/vuln-hunter.md	Give each `sast.sh` call the Bash tool's longest timeout
commands/hunt.md	Give each runner call (`run.sh`, `target.sh`) and the `git-ro.sh copy` call
commands/hunt.md	the Bash tool's longest timeout, in the foreground, never with `run_in_background`:
commands/respond.md	Give each runner call (`run.sh`, `target.sh`) and the `git-ro.sh copy` call
commands/respond.md	the Bash tool's longest timeout, in the foreground, never with `run_in_background`:
commands/threat-model.md	Give it the Bash tool's longest timeout, in the foreground, never with `run_in_background`: on a long history it can outlast the two-minute default
commands/audit.md	ask `QUESTIONS.md` Q47 again, confirm §5 and §6 with the human, and write the answers in their place before a step uses them.
commands/audit.md	Its `exec-mode` stays as it is, and nothing asks Q46 again: the runners take the stricter of that file, `AUDITOR_EXEC_MODE` and strict mode, so a `native` there loosens nothing
commands/threat-model.md	ask `QUESTIONS.md` Q47 again, confirm §5 and §6 with the human, and write the answers in their place before a step uses them.
commands/threat-model.md	Its `exec-mode` stays as it is, and nothing asks Q46 again: the runners take the stricter of that file, `AUDITOR_EXEC_MODE` and strict mode, so a `native` there loosens nothing
commands/intake.md	ask Q47 again, and confirm §5 and §6 with the human, before writing them as this run's.
commands/intake.md	Also write the answer with the Write tool, as one word, `native`, `isolated` or `none`, to `audit_<n>/exec-mode`
commands/intake.md	("untrusted source" writes `isolated`, and `audit_<n>/strict` too, a file holding the word `strict`)
commands/hunt.md	directory's `exec-mode` stands as it is, and nothing asks for the mode again
commands/respond.md	`ok incident_<n>`. A reused incident directory's `exec-mode` stands as it is,
commands/poc.md	Read that file, and hand `auditor:poc-engineer` `isolated` or `none` when it says so, and `native` otherwise.
commands/poc.md	so a `native` there, from any session, loosens nothing, and nothing asks `QUESTIONS.md` Q46 again
commands/poc.md	When `<R>` has no `exec-mode` but its `intake.md` §8, or a ledger header in the older form (one word, with no `recorded:` part), records a mode (a run directory made before 7.7.0), first write that mode to `<R>/exec-mode` with the Write tool, as one word
commands/poc.md	a ledger header's `in force:` part is never written back.
commands/patch.md	a ledger header's `in force:` part is never written back.
commands/patch.md	Settle it as `/auditor:poc` step 5 does: Read `<R>/exec-mode`, and hand `isolated` or `none` when it says so, and `native` otherwise
commands/patch.md	so a `native` there, from any session, loosens nothing, and nothing asks `QUESTIONS.md` Q46 again
commands/patch.md	First settle the execution mode that the rebuild and every PoC re-run in step 3 use
commands/patch.md	`auditor:patch-engineer` runs them itself, with the mode you hand it, and never asks.
commands/re-audit.md	check it with `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" check audit_<n>`: unless it prints `ok audit_<n>`, nothing is written in it
commands/re-audit.md	write the mode `audit_<n>` records (its `exec-mode`, or its `intake.md` §8 without it), when it records one, to `audit_<n+1>/exec-mode`
commands/re-audit.md	In strict mode (preflight's first line says which), first have the human confirm that `audit_<n>` is a run directory they made, not one that came with the tree
commands/re-audit.md	no crate of `audit_<n>` runs and nothing is written in it
QUESTIONS.md	Asked once, at intake; nothing asks it again later.
QUESTIONS.md	for this and every later audit in this directory, until you delete the `strict` files
agents/poc-engineer.md	When the command handed you `isolated`, pass `--mode isolated`, so a run whose recorded mode has since become less strict stops; with `native`, pass no `--mode`
agents/patch-engineer.md	adding `--mode isolated` when the command handed you `isolated`, as `poc-engineer` does
commands/intake.md	so the report states the mode their `>> execution mode:` line shows
scripts/runner/probe.sh	0) printf 'isolation: none of the credentials the self-check reads is readable\n' ;;
agents/poc-engineer.md	!= 'isolation: none of the credentials the self-check reads is readable' ]; then
commands/audit-assist.md	only into `grep`, `head`, `tail` or `wc`
commands/audit-cycle.md	only into `grep`, `head`, `tail` or `wc`
commands/audit.md	only into `grep`, `head`, `tail` or `wc`
commands/deep-review.md	only into `grep`, `head`, `tail` or `wc`
commands/diff-audit.md	only into `grep`, `head`, `tail` or `wc`
commands/economic-sim.md	only into `grep`, `head`, `tail` or `wc`
commands/hunt.md	only into `grep`, `head`, `tail` or `wc`
commands/intake.md	only into `grep`, `head`, `tail` or `wc`
commands/patch.md	only into `grep`, `head`, `tail` or `wc`
commands/poc.md	only into `grep`, `head`, `tail` or `wc`
commands/quick-scan.md	only into `grep`, `head`, `tail` or `wc`
commands/diff-audit.md	argument-hint: "[base..head] [--ci] [--fail-on <N>] [--over-budget fail] [--strict]"
commands/quick-scan.md	argument-hint: "[<path>] [--ci] [--fail-on <N>] [--strict]"
commands/diff-audit.md	`auditor: verdict: <pass|fail> (threshold <N>, analyzers run: <names, or none>[; not run: <names>][; stopped: <step>])`
commands/quick-scan.md	`auditor: verdict: <pass|fail> (threshold <N>, analyzers run: <names, or none>[; not run: <names>][; stopped: <step>])`
commands/diff-audit.md	with `"final": false` and `"verdict": "fail"`, so a run that ends early leaves a failing record
commands/quick-scan.md	with `"final": false` and `"verdict": "fail"`, so a run that ends early leaves a failing record
commands/diff-audit.md	(its Rule 5b status is `passed`, `undetermined` or `not-required`; an `[UNCONFIRMED]` or `[PARTIAL]` one does not)
commands/quick-scan.md	(its Rule 5b status is `passed`, `undetermined` or `not-required`; an `[UNCONFIRMED]` or `[PARTIAL]` one does not)
commands/diff-audit.md	Keep finding text, counts and paths out of the reply (Rule 11d)
commands/quick-scan.md	Keep finding text, counts and paths out of the reply (Rule 11d)
commands/diff-audit.md	Write `audit_<n>/PR-REPORT.md` from `${CLAUDE_PLUGIN_ROOT}/templates/pr-report.md`
commands/quick-scan.md	Write `audit_<n>/QUICK-SCAN.md` from `${CLAUDE_PLUGIN_ROOT}/templates/pr-report.md`
commands/deep-review.md	`audit_<n>/DEEP-REVIEW-<unit>.md`, from `${CLAUDE_PLUGIN_ROOT}/templates/pr-report.md`
commands/quick-scan.md	Read `${CLAUDE_PLUGIN_ROOT}/references/depth-scope.md` and `${CLAUDE_PLUGIN_ROOT}/known-vectors/INDEX.md` with the Read tool
commands/quick-scan.md	select the checklist sections of its §2 and the vector rows of its §3, exactly as those tables say: none is chosen by judgment
commands/quick-scan.md	The DevOps and supply-chain rows apply to every repository.
docs/ci.md	That is at most 62 sections, about 104 KB, for a change that touches every kind of file, and at most 39 for a change to on-chain program source alone
commands/quick-scan.md	Write the selection to `audit_<n>/scope.md`, in the form of its §9, with the Write tool, before you read any checklist section or vector file.
commands/quick-scan.md	each section with the Read tool from its `## ` heading to the next one: at its start line, with its line count as the limit, or, when that line is not the heading, from the line Grep finds the heading on to the next `## `; and each vector file, `${CLAUDE_PLUGIN_ROOT}/known-vectors/<its file>`, whole, with no line limit
commands/diff-audit.md	each section with the Read tool from its `## ` heading to the next one: at its start line, with its line count as the limit, or, when that line is not the heading, from the line Grep finds the heading on to the next `## `; and each vector file
references/depth-scope.md	(when the line at Start is not the heading, Grep the file for the heading and read from there to the next `## `)
checklists/11-supply-chain.md	> **CI budget** (`/auditor:diff-audit`, interactive and `--ci`, in place of steps 2 to 4; Standard and Full keep them).
checklists/11-supply-chain.md	is never sent or fetched, whatever its marks: it is an SC-061 finding to grade, counted apart.
checklists/11-supply-chain.md	The `lock-budget` call is the `deps-artifacts` analyzer: it ran when the call ends 0 or 1, an empty budget included
checklists/11-supply-chain.md	A hit is a lead: read it at its file and line
checklists/11-supply-chain.md	Every key handler below whose version changed is compared first, outside the budget.
references/depth-scope.md	then every key handler and at most 40 other entries fetched old and new and swept, counts first.
commands/diff-audit.md	on the dependency delta with its CI budget, in place of its steps 2 to 4.
commands/diff-audit.md	with the Bash tool's timeout at 600000
commands/diff-audit.md	`deps-artifacts` is the `lock-budget` call: it ran when the call ends 0 or 1, an empty budget included
references/depth-scope.md	`deps-artifacts` is required when a `Cargo.lock`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` or `bun.lock` changes.
docs/ci.md	needs `lock-delta` and `deps-artifacts`
OUTPUT-RULES.md	for `lock-budget`, the name of each package of the set it was given that comes from a public registry, new packages and new versions alike (a name from another source is never sent), one row per service for its whole run.
commands/quick-scan.md	an item that needs a call this scan does not make, which gets `[N/A at this depth — needs <call>]`
commands/diff-audit.md	an item that needs a call this review does not make, which gets `[N/A at this depth — needs <call>]`
commands/quick-scan.md	except the items no site in scope reaches, which share the section's one N/A line, and an item
commands/quick-scan.md	scan the two with the most source lines, and in Coverage & Limitations give each other one its own line, `/auditor:quick-scan <its path>`
commands/quick-scan.md	A section or vector file that `audit_<n>/scope.md` lists and the run leaves unread is an early stop: give findings.json `"stopped": "corpus-pass"`
commands/quick-scan.md	otherwise run the scanners of `${CLAUDE_PLUGIN_ROOT}/discovery/grep-commands.md`
commands/diff-audit.md	Read `${CLAUDE_PLUGIN_ROOT}/references/depth-scope.md` and `${CLAUDE_PLUGIN_ROOT}/known-vectors/INDEX.md` first, with the Read tool
commands/diff-audit.md	then select the checklist sections of its §4 and the vector rows of its §5, exactly as those tables say: none is chosen by judgment
commands/diff-audit.md	The floor of §5 is min(`--fail-on`, 7) − 1, so 6 by default, and it applies to marker rows only
commands/diff-audit.md	Write the selection to `audit_<n>/scope.md`, in the form of its §9, with the Write tool, before you read any checklist section or vector file.
commands/diff-audit.md	A repository-level row that no changed file touches gets §5's fixed line instead.
commands/diff-audit.md	Then apply the changed-code budget of §6 of `${CLAUDE_PLUGIN_ROOT}/references/depth-scope.md`
commands/diff-audit.md	and the report counts the rest as "changed lines not reviewed: N of M"
commands/diff-audit.md	With `--over-budget fail`, a change over the budget of step 1 stops the run (`"stopped": "line-budget"`)
commands/diff-audit.md	A section or vector file that `audit_<n>/scope.md` lists and the run leaves unread is an early stop: give findings.json `"stopped": "corpus-pass"`
commands/diff-audit.md	on the changed functions of the kept files and their direct callers and callees (1-hop) inside the changed programs
commands/diff-audit.md	each vector file, `${CLAUDE_PLUGIN_ROOT}/known-vectors/<its file>`, whole, with no line limit, several in each message
commands/diff-audit.md	run §11.11 of `${CLAUDE_PLUGIN_ROOT}/checklists/11-supply-chain.md`
commands/deep-review.md	reading each one's file, `${CLAUDE_PLUGIN_ROOT}/known-vectors/<its file>`, before its verdict
commands/quick-scan.md	Steps 2 to 4 run in this session: start no agent, so a scan costs the same from one run to the next.
commands/quick-scan.md	Write it yourself, in this session.
commands/quick-scan.md	Run no `cd` in this session, not even before a plain `grep`
commands/diff-audit.md	Run no `cd` in this session, not even before a plain `grep`
commands/deep-review.md	Run no `cd` in this session, not even before a plain `grep`
commands/deep-review.md	If you start an agent, set no model for it
commands/quick-scan.md	Judge no vector by its index row alone
commands/quick-scan.md	about ten in each message, and every one before you give any verdict
commands/quick-scan.md	Before you start the report, check what you read against scope.md, and read anything it lists that you missed.
commands/quick-scan.md	gives the lines of depth-scope.md §8 for what the selection leaves out
commands/diff-audit.md	Read every selected file before you start the report: first check what you read against scope.md, and read anything it lists that you missed.
commands/diff-audit.md	Coverage & Limitations gives the lines of depth-scope.md §8 for what the selection leaves out
templates/pr-report.md	`audit_<n>/scope.md` lists, written before the reads, so a reader can check the selection against
templates/pr-report.md	request to that service, so a row says what the tool was set to send, not that it went out
templates/pr-report.md	sent only where the tool's own output names that service's address as one it reached, and otherwise that it
templates/pr-report.md	`Loaded … security advisories (from <folder>)`, names a local copy and shows no request.
commands/diff-audit.md	(`deps.sh` adds a row to `audit_<n>/disclosures.tsv` before its first request to each service)
commands/quick-scan.md	Skip nothing scope.md lists and cut nothing short by choice, not even to save cost or time; Coverage & Limitations names only a file the Read tool could not open
commands/diff-audit.md	Skip nothing scope.md lists and cut nothing short by choice, not even to save cost or time; name there only one the Read tool could not open.
commands/quick-scan.md	Measured scans cost USD 2.84 to 7.14 in all; this selection cost USD 6.98 on a whole repository, reading 38 vector files and 49 sections.
commands/diff-audit.md	Measured reviews cost USD 1.68 to 8.10 in all; this selection cost USD 8.10 on a range of 7,830 changed lines that adds a 787-package lockfile.
docs/ci.md	The top figure is the shipped text, measured on the 3K-line repository only: the selection of `references/depth-scope.md` on a range of 7,830 changed lines that adds a 787-package lockfile, under a $15 cap.
docs/ci.md	It read every file its selection lists and named no spending cap. The lower figures are earlier drafts, and the review job on the shipped text is not measured yet.
docs/ci.md	On a fork's or Dependabot's pull request the review check shows Success with no review
docs/ci.md	a cargo audit or npm audit advisory has no exception here, so fix or replace that dependency before you require the tools job
docs/ci.md	Delete every `.claude/`, `.mcp.json`, `.claude.json`, `CLAUDE.md` and `CLAUDE.local.md` from that checkout, as the review job does
docs/ci.md	the review stops at it, after the response that crosses it, so its last response can take it a little over
templates/report-template.md	so a row says what the tool was set to send, not that it went out
templates/audit-report.md	so a row says what the tool was set to send, not that it went out
templates/incident-report.md	so a row says what the tool was set to send, not that it went out
templates/pr-report.md	- diff-audit: "changed lines not reviewed: {N} of {M}" and the files they are in (`references/depth-scope.md` §6),
docs/ci.md	`git ls-remote https://github.com/solanabr/auditor-skill refs/heads/main` prints the current one
docs/ci.md	`git ls-remote https://github.com/solanabr/auditor-skill 'refs/tags/<tag>^{}'` prints the commit that tag names
templates/ci/auditor-pr.yml	# auditor-skill at one commit: the full id of a commit on its main branch
commands/diff-audit.md	Right before you write the report, run `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` as a Bash call of its own, and put the line it prints, as it stands, in the report's Generated field (`OUTPUT-RULES.md` Rule 9).
commands/quick-scan.md	Right before you write the report, run `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` as a Bash call of its own, and put the line it prints, as it stands, in the report's Generated field (`OUTPUT-RULES.md` Rule 9).
commands/deep-review.md	Right before you write the report, run `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` as a Bash call of its own, and put the line it prints, as it stands, in the report's Generated field (`OUTPUT-RULES.md` Rule 9).
commands/audit-report.md	Right before you write the report, run `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` as a Bash call of its own, and put the line it prints, as it stands, in the report's Generated field (`OUTPUT-RULES.md` Rule 9).
commands/audit-cycle.md	Right before you write the report, run `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` as a Bash call of its own, and put the line it prints, as it stands, in the report's Generated field (`OUTPUT-RULES.md` Rule 9).
commands/audit-assist.md	Right before you write the report, run `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` as a Bash call of its own, and put the line it prints, as it stands, in the report's Generated field (`OUTPUT-RULES.md` Rule 9).
commands/audit.md	Right before you write the report, run `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` as a Bash call of its own, and put the line it prints, as it stands, in the report's Generated field (`OUTPUT-RULES.md` Rule 9).
commands/re-audit.md	Right before you write the report, run `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` as a Bash call of its own, and put the line it prints, as it stands, in the report's Generated field (`OUTPUT-RULES.md` Rule 9).
commands/audit-report.md	  - 'Bash("${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" *)'
skills/dnr-analyze/SKILL.md	  - 'Bash("${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp)'
skills/dnr-analyze/SKILL.md	its Generated field holding the line `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` prints, run as a Bash call of its own right before you write it |
skills/dnr-analyze/SKILL.md	its Generated field holding the line `"${CLAUDE_PLUGIN_ROOT}/scripts/rundir.sh" stamp` prints, run as a Bash call of its own right before you write it,
OUTPUT-RULES.md	Every report carries, in its Generated field, the line `rundir.sh stamp` printed right before it was written, and claims no more review by a person than that line's statement says
docs/ci.md	| `AUDITOR_REVIEW_STATEMENT` | empty | the last sentence of the Generated line each review's report carries
templates/report-template.md	the line `"<auditor-skill root>/scripts/rundir.sh" stamp` printed right before this report was written, as it stands
templates/pr-report.md	the line `"<auditor-skill root>/scripts/rundir.sh" stamp` printed right before this report was written, as it stands
templates/incident-report.md	the line `"<auditor-skill root>/scripts/rundir.sh" stamp` printed right before this report was written, as it stands
templates/audit-report.md	the line `"<auditor-skill root>/scripts/rundir.sh" stamp` printed right before this report was written, as it stands
templates/re-audit.md	the line `"<auditor-skill root>/scripts/rundir.sh" stamp` printed right before this report was written, as it stands
templates/response-plan.md	the line `"<auditor-skill root>/scripts/rundir.sh" stamp` printed right before this report was written, as it stands
docs/ci.md	Under a $10 cap, the depth-scope selection read 38 vector files and 49 checklist sections in that repository, for $6.98.
commands/quick-scan.md	A USD budget Claude Code shows you is a backstop, not a plan: Claude Code ends the session itself at the cap, and a CI run it ends fails anyway.
commands/diff-audit.md	A USD budget Claude Code shows you is a backstop, not a plan: Claude Code ends the session itself at the cap, and a CI run it ends fails anyway.
commands/quick-scan.md	never stop reading early to save spend, and never give a budget, turn or time limit as the reason a file went unread
commands/diff-audit.md	never stop reading early to save spend, and never give a budget, turn or time limit as the reason a file went unread
docs/ci.md	Give a quick-scan in CI `--max-budget-usd 15`, a backstop, not a budget to plan by.
docs/ci.md	a section or vector file its selection lists was left unread (`stopped: corpus-pass`)
docs/ci.md	It reads the checklist sections and known-vector rows that `references/depth-scope.md` selects for the kinds of file the change holds
commands/diff-audit.md	first, with the Read tool, before any verdict of this step, whatever the size of the change
commands/diff-audit.md	Each verdict names the checklist item id or the vector step it rests on
commands/deep-review.md	Each verdict names the checklist item id or the vector step it rests on
commands/diff-audit.md	Write it yourself, in this session.
commands/diff-audit.md	Steps 2 to 6 run in this session: start no agent, so a review of the same range costs the same from one run to the next.
commands/deep-review.md	Write it yourself, in this session, from what any agent you started returned
commands/quick-scan.md	but the job never fails only because none exists, and never falls back to printing findings in the log
commands/re-audit.md	only into `grep`, `head`, `tail` or `wc`
commands/respond.md	only into `grep`, `head`, `tail` or `wc`
commands/spec-audit.md	only into `grep`, `head`, `tail` or `wc`
commands/threat-model.md	only into `grep`, `head`, `tail` or `wc`
commands/triage.md	only into `grep`, `head`, `tail` or `wc`
agents/vuln-hunter.md	only into `grep`, `head`, `tail` or `wc`
agents/poc-engineer.md	only into `grep`, `head`, `tail` or `wc`
agents/patch-engineer.md	only into `grep`, `head`, `tail` or `wc`
SKILL.md	only into `grep`, `head`, `tail` or `wc`
agents/context-builder.md	only into `grep`, `head`, `tail` or `wc`
agents/economic-analyst.md	only into `grep`, `head`, `tail` or `wc`
agents/peer-reviewer.md	only into `grep`, `head`, `tail` or `wc`
commands/audit-assist.md	  - Edit(/audit_*/**)
commands/audit-cycle.md	  - Edit(/audit_*/**)
commands/audit-report.md	  - Edit(/audit_*/**)
commands/audit.md	  - Edit(/audit_*/**)
commands/deep-review.md	  - Edit(/audit_*/**)
commands/diff-audit.md	  - Edit(/audit_*/**)
commands/economic-sim.md	  - Edit(/audit_*/**)
commands/hunt.md	  - Edit(/incident_*/**)
commands/intake.md	  - Edit(/audit_*/**)
commands/patch.md	  - Edit(/audit_*/**)
commands/patch.md	  - Edit(/incident_*/**)
commands/poc.md	  - Edit(/audit_*/**)
commands/poc.md	  - Edit(/incident_*/**)
commands/quick-scan.md	  - Edit(/audit_*/**)
commands/re-audit.md	  - Edit(/audit_*/**)
commands/respond.md	  - Edit(/incident_*/**)
commands/spec-audit.md	  - Edit(/audit_*/**)
commands/threat-model.md	  - Edit(/audit_*/**)
commands/triage.md	  - Edit(/audit_*/**)
skills/dnr-analyze/SKILL.md	  - Edit(/incident_*/**)
SKILL.md	  - Edit(/audit_*/**)
AGENTS.md	under the command's `Edit(/audit_*/**)` or `Edit(/incident_*/**)` grant
OUTPUT-RULES.md	the report lists each tool, the service it was set to contact, and what it was set to send
docs/permissions-and-isolation.md	Both rules begin with a `/`, which keeps them on the folder Claude Code started in
OUTPUT-RULES.md	A Quick or CI run (`/auditor:quick-scan`, `/auditor:diff-audit`) declares a smaller scope instead: the selection of [references/depth-scope.md](references/depth-scope.md)
OUTPUT-RULES.md	In a Quick or CI report they render once per left-out section or row group, as Rule 4's depth exception says.
OUTPUT-RULES.md	outside <depth>'s scope; /auditor:audit gives their verdicts
OUTPUT-RULES.md	an item that needs a call the depth does not make gets `[N/A at this depth — needs <call>]`
checklists/06-program-economic-logic.md	A Quick or CI run reads only the sections `references/depth-scope.md` selects
known-vectors/INDEX.md	A Quick or CI run's declared scope (`references/depth-scope.md`) may leave an `always` row out
known-vectors/INDEX.md	its report lists the row once, as outside that depth's scope (`OUTPUT-RULES.md` Rule 4's depth exception).
PINS
# Claude Code fills $ARGUMENTS and a $ followed by digits and then no letter, digit or _ (its pattern,
# \$ARGUMENTS\[\d+\]|\$ARGUMENTS|\$\d+(?!\w)) with the invocation's arguments, in a command's or a skill's
# body, so a cost written as $1-2 or $2.84 would print an argument; the bodies write USD 2.84.
for f in commands/*.md skills/*/SKILL.md SKILL.md; do
  [ -f "$f" ] || continue
  n=$(grep -c -E '[$][0-9]+([^A-Za-z0-9_]|$)' "$f")
  if [ "$n" = 0 ]; then ok "$f holds no \$<digits> that Claude Code would fill with an argument"
  else bad "$f holds a \$<digits> that Claude Code fills with an argument: $(grep -n -m 1 -E '[$][0-9]+([^A-Za-z0-9_]|$)' "$f" | cut -c1-120)"; fi
done
# A run-directory edit stays anchored at the folder the session started in, Edit(/audit_*/**) or
# Edit(/incident_*/**): after a cd, the bare form matches the new folder's audit_*, not the run directory.
for f in commands/*.md skills/*/SKILL.md SKILL.md; do
  [ -f "$f" ] || continue
  n=$(sed -n '2,/^---$/p' "$f" | grep -c -x -e '  - Edit(audit_\*/\*\*)' -e '  - Edit(incident_\*/\*\*)')
  if [ "$n" = 0 ]; then ok "$f grants no run-directory edit in the bare form"
  else bad "$f grants Edit(audit_*/**) or Edit(incident_*/**): write it with a leading /, as every command does"; fi
done

# Wording that must not come back, file <TAB> text: an agent never hands run.sh the file's mode as --mode, which
# stops every run a stricter AUDITOR_EXEC_MODE holds to isolated mode, and the older wording that copied a mode
# forward, wrote only native, or let a non-interactive run loosen a recorded mode stays gone. Since 7.7.2 nothing
# asks Q46 after intake, for a run directory an earlier session made or mid-run (spec §4.7, CMD-03): the runners
# take the stricter of <R>/exec-mode, AUDITOR_EXEC_MODE and strict mode, so a native there loosens nothing, and
# isolated is no longer the recommended answer.
while IFS='	' read -r f gone; do
  [ -n "$f" ] || continue
  if [ -f "$f" ] && ! grep -qF -- "$gone" "$f"; then ok "gone from $f: $gone"; else bad "P $f says: $gone"; fi
done <<'GONE'
commands/re-audit.md	write the mode recorded at intake into
agents/poc-engineer.md	--mode <the mode the command handed you>
agents/patch-engineer.md	--mode <the mode the command hands you>
commands/patch.md	auditor:patch --resume 3
commands/poc.md	naming `<R>` (a non-interactive run is native
commands/patch.md	naming `<R>` (a non-interactive run is native
commands/re-audit.md	Q46 again (a non-interactive run is native
commands/re-audit.md	and the mode `audit_<n>/exec-mode` records to
commands/poc.md	writes `native` only when no mode is recorded
commands/patch.md	writes `native` only when no mode is recorded
commands/audit.md	ask `QUESTIONS.md` Q46 and Q47 again
commands/threat-model.md	ask `QUESTIONS.md` Q46 and Q47 again
commands/intake.md	ask Q46 and Q47 again
commands/intake.md	(recommended:
commands/re-audit.md	ask `QUESTIONS.md` Q46 again
commands/re-audit.md	isolated recommended
commands/poc.md	ask `QUESTIONS.md` Q46 once
commands/patch.md	ask `QUESTIONS.md` Q46 once
commands/poc.md	auditor:poc --resume 5
commands/patch.md	auditor:patch --resume 2
commands/hunt.md	ask for the mode again
commands/respond.md	ask for the mode again
commands/audit-assist.md	ask once at Checkpoint 1
SKILL.md	isolated recommended
QUESTIONS.md	and again before a later session uses a run directory an earlier one made
QUESTIONS.md	**Isolated** (recommended)
commands/diff-audit.md	PR number
commands/quick-scan.md	If that channel is unavailable, fail the job
commands/quick-scan.md	As a CI gate, a refusal fails the job
commands/quick-scan.md	Evaluate only CRITICAL / HIGH known-vectors for the detected domains
commands/quick-scan.md	run the `discovery/grep-commands.md` scanners
commands/quick-scan.md	  - Task
commands/quick-scan.md	spawn every agent in the foreground
commands/diff-audit.md	  - Task
commands/diff-audit.md	spawn every agent in the foreground
commands/diff-audit.md	If you start an agent
commands/quick-scan.md	no longer matches the write rule for `audit_*/`
commands/quick-scan.md	list the kept files in a message of your own
commands/quick-scan.md	write the kept list as text in a message
commands/diff-audit.md	write the selected list as text in a message
templates/pr-report.md	Outside services the run contacted
templates/pr-report.md	that nothing went out where the output shows the tool used
commands/diff-audit.md	records each service it contacts
commands/quick-scan.md	so one still running has reached none
commands/diff-audit.md	so one still running has reached none
commands/quick-scan.md	adds about USD 1–2 to a scan, even at 80 files
commands/quick-scan.md	take the rows whose Severity is 7 or more
commands/diff-audit.md	the scope table of `${CLAUDE_PLUGIN_ROOT}/SKILL.md` (Scope-Gated Loading, Step 2)
commands/diff-audit.md	Reading and checking every selected vector file added under USD 1
commands/quick-scan.md	Reading and checking every kept file adds about USD 1–4
commands/quick-scan.md	The high-severity vector pass
templates/pr-report.md	quick-scan evaluates the CRITICAL and HIGH vectors only
commands/diff-audit.md	adds about USD 1–2 at most, even at 80 files
commands/diff-audit.md	no longer matches the write rule for `audit_*/`
commands/deep-review.md	no longer matches the write rule for `audit_*/`
AGENTS.md	`Edit(audit_*/**)` or `Edit(incident_*/**)` grant
OUTPUT-RULES.md	the report lists each tool, the service it contacted, and what it sent.
docs/ci.md	front A
docs/ci.md	Front A
docs/ci.md	owner switch
docs/ci.md	named no budget
templates/ci/auditor-pr.yml	no finding, count or path
docs/ci.md	a change to on-chain code alone
references/depth-scope.md	a change to on-chain code alone selects at most 46
OUTPUT-RULES.md	the name of each new package of the set
docs/ci.md	from the auditor-skill release you use
docs/ci.md	the full commit id of that release's tag
templates/ci/auditor-pr.yml	the release tag you install
templates/ci/auditor-pr.yml	the commit of the auditor-skill release you use
templates/pr-report.md	- **Plugin:** auditor-skill {version}
templates/report-template.md	**Date:** <!-- YYYY-MM-DD -->
templates/incident-report.md	**Date:** {ISO}
GONE

# respond's step 5 and hunt's step 6 settle the mode as poc's step 5 does, each step read as one line so wording
# that wraps still matches: nothing asks Q46 there, the runners take the stricter of the incident directory's
# exec-mode, AUDITOR_EXEC_MODE and strict mode, and a mode only its ledger header records (a directory older than
# that file) is written to the exec-mode file run.sh and target.sh read. The ask, and the wording that let a
# non-interactive run fall back to native over a recorded mode, stay gone.
INC_MODE='runs in the Rule 11a mode in force, and nothing asks Q46 for it: the runners take the stricter of `incident_<n>/exec-mode`, `AUDITOR_EXEC_MODE` and strict mode, native when none of them says anything, so a `native` there loosens nothing. When `incident_<n>` has no `exec-mode` but its ledger header records a mode in the older form, one word with no `recorded:` part (a run directory made before 7.7.0), first write that mode as one word to `incident_<n>/exec-mode` with the Write tool,'
INC_REC='(`recorded:`, or `none recorded`) and the mode the runners'"'"' `>> execution mode:` line shows (`in force:`), which is never written back'
for fs in 'commands/respond.md|5' 'commands/hunt.md|6'; do
  f=${fs%|*}; s=${fs#*|}
  step=$(awk -v s="$s. **" 'index($0, s) == 1 { on = 1 } on && /^[0-9]+[a-z]?\. \*\*/ && index($0, s) != 1 { exit } on' "$f" |
    tr '\n' ' ' | tr -s ' ')
  case "$step" in
    *"$INC_MODE"*) ok "$f step $s: the incident directory's mode is used as recorded, and nothing asks for it" ;;
    *) bad "P $f step $s lost: $INC_MODE" ;;
  esac
  case "$step" in
    *"$INC_REC"*) ok "$f step $s: the ledger keeps the recorded mode apart from the mode in force" ;;
    *) bad "P $f step $s lost: $INC_REC" ;;
  esac
  for gone in 'ask once (a non-interactive run is native' 'writes `native` only when no mode is recorded' \
              'mode: ask Q46 once' 'that Q46 was not asked again'; do
    case "$(tr '\n' ' ' < "$f" | tr -s ' ')" in
      *"$gone"*) bad "P $f says: $gone" ;;
      *) ok "gone from $f: $gone" ;;
    esac
  done
done

# Each command's resume text, and the root SKILL.md's, says what stops the prompt its re-invocation brings (the
# user-level rules), and that "Yes, and don't ask again" no longer breaks the resumed invocation, whose step 0 runs
# again: preflight takes an untracked .claude/settings.local.json for the user's own (spec §4.8, Rule 11e). The old
# advice, which told the human to avoid that answer because step 0 refused the file, stays gone.
for f in commands/*.md SKILL.md; do
  if grep -qiF -- 'That invocation asks unless the user-level rules in' "$f"; then ok "$f: the resume text names the rules that stop its prompt"
  else bad "P $f: the resume text does not name the user-level rules that stop its prompt"; fi
  if grep -qiF -- 'which step 0 no longer refuses while git does not track it' "$f"; then ok "$f: the saved rule's file no longer stops the resumed invocation"
  else bad "P $f: the resume text does not say that step 0 no longer refuses the saved rule's untracked file"; fi
  for gone in 'tell the human to answer "Yes", not "don'"'"'t ask again"' 'a file step 0 refuses, from that resumed invocation on'; do
    if grep -qiF -- "$gone" "$f"; then bad "P $f says: $gone"; else ok "gone from $f: $gone"; fi
  done
  # A resumed invocation keeps the user's --strict, so its step 0 and its rundir.sh new stay strict (Rule 11f).
  keep='and `--strict` when the user'"'"'s arguments held it'
  [ "$f" = SKILL.md ] && keep='and `--strict` when the user'"'"'s request held it or asked for strict mode'
  if grep -qF -- "$keep" "$f"; then ok "$f: the resumed invocation keeps --strict"
  else bad "P $f: the resume text does not carry --strict: $keep"; fi
done
# Each command that starts agents (Task in its allowed-tools), and the root SKILL.md, keeps them in the foreground,
# and resumes in the turn that brings an agent's result when Claude Code ran it in the background anyway (it cannot
# wait while fork mode is on and background tasks are allowed, the default in interactive sessions): that turn has
# none of the command's grant.
for f in commands/*.md SKILL.md; do
  [ "$(sed -n '2,/^---$/p' "$f" | grep -cx '  - Task')" -gt 0 ] || continue
  for want in 'the foreground and wait for its result, never with `run_in_background`' 'result arrives in a later turn'; do
    if grep -qF -- "$want" "$f"; then ok "$f: $want"; else bad "P $f starts agents but does not say: $want"; fi
  done
done
# run.sh --crate reads its inputs from arguments only, so no body names the environment form of a PoC run.
for f in commands/*.md agents/*.md skills/*/SKILL.md SKILL.md; do
  [ -f "$f" ] || continue
  for v in VULNERABLE_SO FIXED_SO UPDATE_PINS KEEP_POC_BUILD CARGO_TARGET_DIR; do
    if grep -qF -- "$v" "$f"; then bad "P $f names $v, which run.sh --crate does not read"; else ok "no $v in $f"; fi
  done
done


# I: every python3 call a body or the corpus gives runs isolated. A code line, or a code span, that starts with
# python3 (or python) and two words more is a call, read past a leading "(cd <dir> &&", "cd <dir> &&" or
# "env [NAME=value...]", and -I, alone or in a group of flags, comes before its first word that is not an
# option: run from the tree under audit, python3 -m and -c put the working directory first on sys.path, so a
# module of the tree's own would load in place of Python's.
PYI=
IFS= read -r -d '' PYI <<'EOF' || true
import re, sys
for f in sys.argv[1:]:
    fenced = False
    with open(f, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            text = re.sub(r"^[\s>]*", "", line.rstrip("\n"))
            if text.startswith(("```", "~~~")):
                fenced = not fenced
                continue
            for seg in ([text] if fenced else re.findall(r"`([^`]+)`", line)):
                words = seg.split()
                while words:
                    if words[0].lstrip("(") == "cd" and len(words) > 2 and words[2] == "&&":
                        words = words[3:]
                    elif words[0] == "env":
                        words = words[1:]
                        while words and "=" in words[0] and not words[0].startswith("-"):
                            words = words[1:]
                    else:
                        break
                if len(words) < 3 or words[0] not in ("python", "python3"):
                    continue
                opts = []
                for w in words[1:]:
                    if not w.startswith("-"):
                        break
                    opts.append(w)
                if not any(re.match(r"-[A-Za-z]*I", w) for w in opts):
                    print("%s:%d\t%s" % (f, n, seg[:120]))
EOF
printf '%s\n' 'Run `python3 -I -m venv /x/env` or `python3 -I "/r/scripts/dnr/frames.py" a.jsonl`; `python3 -c` and `python3 -` are names.' \
  'Not `python3 -m venv /x/env`, nor `python -c '"'"'import x'"'"' y`.' '```bash' 'python3 -Im venv ~/env' 'python3 -m venv ~/env' \
  '# python3 -m venv ~/env, in a comment' '(cd ~ && python3 -I -m venv ~/env)' '(cd ~ && python3 -m venv ~/env)' \
  'env PYTHONSAFEPATH=1 python3 -c pass' '```' > "$T/py-forms.md"
got=$( (cd "$T" && python3 -I -c "$PYI" py-forms.md) | cut -f1 | tr '\n' ' ')
if [ "$got" = "py-forms.md:2 py-forms.md:2 py-forms.md:5 py-forms.md:8 py-forms.md:9 " ]; then
  ok "I flags a python3 call without -I, after a cd or env too, and passes the rest"
else bad "I is broken: it flags [$got], not py-forms.md:2 twice, py-forms.md:5, :8 and :9"; fi
if found=$(python3 -I -c "$PYI" "$@"); then
  if [ -z "$found" ]; then ok "every python3 call in the bodies and the corpus passes -I"
  else
    while IFS='	' read -r at seg; do bad "I $at: python3 without -I, so it would import from the tree under audit: $seg"; done <<EOF
$found
EOF
  fi
else bad "the python3 -I check could not read the tree"; fi

# ---- 6. the mode lines a runner poc-engineer writes starts with -------------------------------------------
# Run as the first lines of a runner in a crate at audit_1/poc/F-1, started from the working directory and from
# the crate itself, with a stand-in installation whose probe.sh prints the isolation line FAKE_ISOLATION holds:
# like run.sh --crate, they take the stricter of <R>/exec-mode, AUDITOR_EXEC_MODE and strict mode (AUDITOR_STRICT,
# read as Rule 11f reads it, with a note for a value that is no word for on or off, or a strict entry of any kind
# in their own <R>, not in another run directory), native when none of them says anything (spec §4.7); they stop
# on none, on an exec-mode that is not a regular file holding one word and at most one newline (run.sh's
# mode_file reads it so), and on an AUDITOR_EXEC_MODE that names no mode, and in isolated mode unless the
# self-check finds nothing readable. poc-harness.md §1 shows the same lines, with the corpus's name for the root.
G="$T/gate"
mkdir -p "$G/inst/scripts/runner" "$G/ws/audit_1/poc/F-1" "$G/home"
printf '#!/bin/bash\nprintf "%%s\\n" "${FAKE_ISOLATION:-isolation: readable: SSH keys (1); ~/.ssh/id_ed25519}"\n' \
  > "$G/inst/scripts/runner/probe.sh"
chmod 755 "$G/inst/scripts/runner/probe.sh"
runner_lines() {  # runner_lines <file>: the lines of the code block under its "Runners you write." paragraph
  awk '/^\*\*Runners you write\.\*\*/ { on = 1; next }
    on && !inb && /^```bash$/ { inb = 1; next }
    inb && /^```$/ { exit }
    inb { print }' "$1"
}
runner_lines "$TREE/agents/poc-engineer.md" > "$G/lines"
runner_lines "$TREE/references/orchestration/poc-harness.md" > "$G/harness-lines"
root_line="AUDITOR_ROOT='\${CLAUDE_PLUGIN_ROOT}'"
if [ -s "$G/lines" ] && grep -qxF -- "$root_line" "$G/lines" &&
   [ "$(sed "s#^AUDITOR_ROOT='<auditor-skill root>'\$#$root_line#" "$G/harness-lines")" = "$(cat "$G/lines")" ]; then
  ok "references/orchestration/poc-harness.md shows the runner lines agents/poc-engineer.md gives, with the corpus's root"
else
  bad "references/orchestration/poc-harness.md: the runner lines differ from agents/poc-engineer.md's beyond the AUDITOR_ROOT line"
fi
{ printf '#!/usr/bin/env bash\nset -euo pipefail\n'
  awk -v root="$G/inst" '$0 == "AUDITOR_ROOT=\047${CLAUDE_PLUGIN_ROOT}\047" { print "AUDITOR_ROOT=\047" root "\047"; next } { print }' "$G/lines"
  printf 'echo "past the gate: $AUDITOR_EXEC_MODE"\n'; } > "$G/ws/audit_1/poc/F-1/run.sh"
CLEAN='isolation: none of the credentials the self-check reads is readable'
# <exec-mode>|<AUDITOR_EXEC_MODE>|<AUDITOR_STRICT>|<marker>|<self-check>|<want>|<note>: an empty exec-mode is none
# at all, @dir a directory, @link:<word> a symbolic link to a file that holds <word>, @bytes:<format> the bytes
# printf writes from <format> (\n a newline), and any other a file that holds the word and one newline. The
# marker is audit_1/strict as an empty file, a directory or a dangling link, or (other) incident_1/strict, which is
# not this runner's <R>. A run that goes on prints <note>, when given, on the line before the gate's.
while IFS='|' read -r file env strict marker iso want note; do
  [ -n "$want" ] || continue
  rm -rf "$G/ws/audit_1/exec-mode" "$G/ws/audit_1/linked" "$G/ws/audit_1/strict" "$G/ws/incident_1"
  case "$file" in
    '') ;;
    @dir) mkdir "$G/ws/audit_1/exec-mode" ;;
    @link:*) printf '%s\n' "${file#@link:}" > "$G/ws/audit_1/linked"; ln -s linked "$G/ws/audit_1/exec-mode" ;;
    @bytes:*) printf -- "${file#@bytes:}" > "$G/ws/audit_1/exec-mode" ;;
    *) printf '%s\n' "$file" > "$G/ws/audit_1/exec-mode" ;;
  esac
  case "$marker" in
    file) : > "$G/ws/audit_1/strict" ;;
    dir) mkdir "$G/ws/audit_1/strict" ;;
    dangling) ln -s nowhere "$G/ws/audit_1/strict" ;;
    other) mkdir -p "$G/ws/incident_1" && : > "$G/ws/incident_1/strict" ;;
  esac
  set -- FAKE_ISOLATION="$CLEAN"
  [ "$iso" = readable ] && set -- FAKE_ISOLATION="isolation: readable: SSH keys (1); ~/.ssh/id_ed25519"
  [ -n "$env" ] && set -- "$@" AUDITOR_EXEC_MODE="$env"
  [ -n "$strict" ] && set -- "$@" AUDITOR_STRICT="$strict"
  expect="past the gate: $want"
  [ -n "$note" ] && expect="$note
$expect"
  for from in 'working directory' crate; do
    if [ "$from" = crate ]; then
      out=$(cd "$G/ws/audit_1/poc/F-1" && env -i PATH="$PATH" HOME="$G/home" "$@" bash ./run.sh 2>&1); rc=$?
    else
      out=$(cd "$G/ws" && env -i PATH="$PATH" HOME="$G/home" "$@" bash audit_1/poc/F-1/run.sh 2>&1); rc=$?
    fi
    label="runner gate, started from the $from: exec-mode '${file:-absent}', AUDITOR_EXEC_MODE '${env:-unset}', AUDITOR_STRICT '${strict:-unset}', strict marker ${marker:-none}, self-check $iso"
    case "$want" in
      stop) if [ "$rc" = 3 ] && [ "${out#*past the gate}" = "$out" ] && [ "${out#*'[PoC-ATTEMPTED] blocker:'}" != "$out" ]; then
              ok "$label -> exit 3, nothing past the gate"
            else bad "$label: exit $rc, want 3 before anything else: ${out:0:300}"; fi ;;
      *)    if [ "$rc" = 0 ] && [ "$out" = "$expect" ]; then ok "$label -> runs in $want mode"
            else bad "$label: exit $rc, want a run in $want mode: ${out:0:300}"; fi ;;
    esac
  done
done <<'CASES'
native||||clean|native
|native|||clean|native
||||clean|native
none|native|||clean|stop
native|none|||clean|stop
isolated|native|||clean|isolated
isolated|native|||readable|stop
native|isolated|||readable|stop
native|isolated|||clean|isolated
|isolated|||readable|stop
native|Isolated|||clean|stop
native|NONE|||clean|stop
isolated|isolate|||clean|stop
|Isolated|||clean|stop
Isolated|native|||clean|stop
isolated native|native|||clean|stop
@dir|native|||clean|stop
@link:native|native|||clean|stop
@link:isolated||||clean|stop
@bytes:native||||clean|native
@bytes:native\n\n||||clean|stop
@bytes:native\n\n\n\nnone||||clean|stop
@bytes:native\n\n\n\nisolated||||clean|stop
@bytes:isolated\n\n|native|||clean|stop
||1||clean|isolated
||1||readable|stop
native||1||clean|isolated
|native|yes||clean|isolated
none||1||clean|stop
||0||clean|native
||OFF||clean|native
||maybe||clean|isolated|>> note: AUDITOR_STRICT is 'maybe', read as on
native|||file|clean|isolated
native|||dir|clean|isolated
native|||dangling|clean|isolated
native|||file|readable|stop
native|||other|clean|native
|Isolated|1||clean|stop
CASES

echo "---- command forms: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
