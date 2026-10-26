#!/usr/bin/env bash
# test-command-forms.sh — the commands, agents and skills run each bundled entry point in the one form their
# allow rules pre-approve: Claude Code approves a call without asking only when its text starts with the quoted
# path the rule names and holds no $ other than the root it substitutes (OUTPUT-RULES.md Rule 11e).
#   C1  In commands/*.md, agents/*.md, skills/*/SKILL.md and SKILL.md, every code span and code line that names
#       a bundled entry point from the root names it as "${CLAUDE_PLUGIN_ROOT}/<path>" (in the root SKILL.md,
#       "${CLAUDE_SKILL_DIR}/<path>"), quoted, first in the command, or as the file a test -x, -f or -e reads (a
#       cmp or diff of it asks, since it lies outside the working directory); with no bash, cd, env or VAR=value
#       in front, no other $, no backtick, no ;, &&, ||, &, no process substitution, no pipe (a | with a space
#       beside it, or one straight into a program such as sh or tee; a|b in a usage line is a choice), no line
#       continuation, and no file redirect but into a run directory (audit_<n>/ or incident_<n>/) or /dev/null.
#   C2  Every Bash allow rule that names a path from the root names it as its quoted first word (after an
#       optional test -x), and that path is a tracked file of mode 100755 whose first line is a #! line, or a
#       binary a crate under tools/auditor-tools declares, executable when it is built.
#   C3  Every call of audit-scan carries --contract=1 as its first argument, and every call of audit-mem
#       --contract=1 right after its subcommand: in the rules, in rooted calls, and in code spans that start
#       with the bare name and pass arguments (a span naming only the tool, or the tool and a subcommand, is a
#       mention).
#   C4  Every command, and the root SKILL.md, runs preflight.sh as step 0: the first entry point its body names
#       is "<root>/scripts/preflight.sh", with no arguments, in a paragraph that starts "0. **Preflight" (in the
#       root SKILL.md, "**Step 0 — Preflight") and says that a refusal, and a call that is denied, stop the run;
#       and the allowed-tools of every command, and of the root SKILL.md, pre-approve that call.
#   C5  Every rooted call in a command's body, and in the bodies of the agents it spawns (a code span naming the
#       agent after spawn or delegate in the sentence, or right after run), is one of that command's Bash rules:
#       the same path, then the rule's fixed words (all of them, for a rule with no *). A fork skill's calls,
#       and its agent's, are its own rules', and so are the root SKILL.md's. A call is an entry point first in a
#       code span with words after it, or first on a fenced code line; one the rest of its sentence says asks
#       is a documented prompt.
#   P   Wording the flows depend on stays in place (the PINS list): what keeps a long call, and the turn after
#       it, inside a command's grant; and no body names the environment form of a PoC run (VULNERABLE_SO and the
#       rest), which run.sh --crate does not read.
# The entry points are the tracked files under scripts/ (but scripts/tests/) and templates/ of mode 100755 that
# start with a direct-exec shebang (#!/bin/bash or #!/usr/bin/env -S python3 -I), and the binaries the crates
# under tools/auditor-tools declare. Each check first runs on known-good and known-bad fixture files, one of
# them over 64 KiB with its one bad line last, so a broken check fails the test.
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
SPAWN = re.compile(r'(?i)\b(spawns?|delegates?)\b')
RUN_AGENT = re.compile(r'(?i)\bruns?\s+(?:the\s+)?\**`([a-z][a-z0-9-]*)`')
ASKS = re.compile(r'\b(asks|prompts)\b')

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
        elif c in "|&":
            before = s[i - 1] if i > 0 else " "
            after = s[i + 1] if i + 1 < len(s) else " "
            word = re.match(r'[A-Za-z0-9_.-]*', s[i + 1:]).group(0)
            if before.isspace() or after.isspace() or (c == "|" and word in PIPE_INTO):
                found.append("a pipe" if c == "|" else "&")
        i += 1
    return found

def redirects(s):
    """The target of each file redirect outside quotes that does not lead into a run directory (or /dev/null)."""
    s = re.sub(r'<[^<>(\s][^<>]*>', 'P', s)       # placeholders such as <R>/poc/<ID>
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
            if op.startswith("<<") or op.endswith("&") or op.startswith(">&") or op.startswith("<&"):
                i = j; continue                    # here-documents and strings, and descriptor copies
            target = re.match(r'\s*([^\s;&|<>]*)', s[j:]).group(1)
            if target != "/dev/null" and not re.match(r'^(\./)?(audit|incident)_[^/\s]*/', target):
                bad.append(target or "(no target)")
            i = j; continue
        i += 1
    return bad

def segments(body, first):
    """(line number, text, first line of its paragraph, the paragraph, where the code ends in it, fenced?) for
    every inline code span and fenced code line."""
    fence, para = None, []
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
                yield n, line.strip(), line, line, len(line), True
            continue
        if m:
            for s in spans(para):
                yield s
            para = []
            fence = m.group(1)
            continue
        if line.strip() == "" or re.match(r'^\s*(\d+[a-z]?[.)]|[-*+])\s', line):
            for s in spans(para):
                yield s
            para = []
        if line.strip():
            para.append((n, line))
    for s in spans(para):
        yield s

def marker(check_file, n, tool, rest, where):
    words = rest.split()
    if tool == "audit-scan" and words and words[0] != "--contract=1":
        finding("C3", check_file, n, "audit-scan %s without --contract=1 as its first argument: %s" % (where, rest[:120]))
    if tool == "audit-mem" and len(words) >= 1 and (len(words) < 2 or words[1] != "--contract=1"):
        finding("C3", check_file, n, "audit-mem %s without --contract=1 right after its subcommand: %s" % (where, rest[:120]))

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

def spawned(body):
    """The agents a body spawns: each code span naming an agent after spawn or delegate in its sentence, and
    one right after run."""
    names = set()
    for para in re.split(r'\n\s*\n|\n(?=\s*(?:\d+[a-z]?[.)]|[-*+])\s)', "\n".join(body)):
        for sentence in re.split(r'(?<=[.!?])\s+', para):
            m = SPAWN.search(sentence)
            if m:
                names.update(a for a in re.findall(r'`([a-z][a-z0-9-]*)`', sentence[m.end():]) if a in agents)
            names.update(a for a in RUN_AGENT.findall(sentence) if a in agents)
    return names

def calls(body, first):
    """(line, path, words, text) for each rooted call: an entry point first in a code span with words after
    it, or first on a fenced code line. A call the rest of its sentence says asks is a documented prompt."""
    res = []
    for n, seg, para, ptext, end, fenced in segments(body, first):
        m = CALL.match(seg)
        if not m or m.group(2) not in entry:
            continue
        words = m.group(3).split()
        if not words and not fenced:
            continue
        if not fenced and ASKS.search(re.split(r'(?<=[.!?])\s', ptext[end:], 1)[0]):
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

for f in files:
    try:
        text = read(f)
    except (OSError, UnicodeDecodeError) as e:
        print("cannot read %s: %s" % (f, e), file=sys.stderr); sys.exit(2)
    fm, body, first = split_doc(text)
    root_skill = f == "SKILL.md"
    command = f.startswith("commands/")
    var = "CLAUDE_SKILL_DIR" if root_skill else "CLAUDE_PLUGIN_ROOT"

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
        words = seg.split()
        if words and words[0] in ("audit-scan", "audit-mem") and "${" not in seg:
            if (words[0] == "audit-scan" and len(words) >= 2) or (words[0] == "audit-mem" and len(words) >= 3):
                marker(f, n, words[0], " ".join(words[1:]), "call")
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

    # every call in the body, and in the bodies of the agents it spawns (or, for a fork skill, the agent it runs
    # as), is one of its own rules: the path, then the rule's fixed words
    if command or root_skill or f in forks:
        sources = [(f, body, first)]
        names = spawned(body) | ({forks[f]} if f in forks else set())
        sources.extend(agents[a] for a in sorted(names) if a in agents)
        check_calls(f, rules, sources)

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
STEP0="0. **Preflight.** Run \`\"$R/scripts/preflight.sh\"\`, with no arguments. On a refusal, stop; a call that is denied stops the run too."
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
  "'Bash(test -x \"$B/audit-mem\")'" "'Bash(git log:*)'" "Edit(audit_*/**)" -- \
  "1. Run \`\"$R/scripts/ok.sh\" new audit\` and \`\"$R/scripts/rec.py\" tokens|lamports [--by owner,mint|mint] incident_<n>/corpus*/x.jsonl > incident_<n>/out.txt\`." \
  "2. When built (\`test -x \"$B/audit-scan\"\`), \`\"$B/audit-scan\" --contract=1 . --out audit_<n>/prescan.json\` and" \
  "   \`\"$B/audit-mem\" warm --contract=1 --program-id <id>\`; \`audit-mem warm --contract=1 --program-id <id>\`, \`audit-mem init\`." \
  "3. Check \`test -f \"$R/templates/poc/run.sh\"\`; mention \`\"$B/audit-mem\"\` alone; read \`$R/references/x.md\`." \
  "4. Prose names \`run.sh --crate\` and \`\"$R/scripts/filter.sh\"\` behind \`x 2>&1 | bash \"$R/scripts/filter.sh\"\`." \
  "5. Keep \`\"$R/scripts/ok.sh\" check x > audit_<n>/out.txt 2>/dev/null\` and \`\"$R/scripts/ok.sh\" check x 2>&1\`." \
  "6. Spawn \`fx-runner\` on it; \`\"$R/templates/poc/run.sh\" --crate <R>/poc/<ID>\` runs it, and \`\"$R/scripts/rec.py\" --crate x\`, which asks, does not." \
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
# C5: each call is one of its command's rules, the agents it spawns too; a call its sentence says asks is not
cmd c5-unlisted -- "1. Run \`\"$R/templates/poc/run.sh\" --crate audit_<n>/poc/F-1\`."
cmd c5-agent -- "1. Spawn \`fx-runner\` on the crate."
cmd c5-agent-covered "'Bash(\"$R/scripts/rec.py\" *)'" -- "1. Delegate the walk to \`fx-runner\`."
cmd c5-agent-mention -- "1. Read what \`fx-runner\` wrote into the run directory."
cmd c5-asks -- "1. Run \`\"$R/templates/poc/run.sh\" --crate x\`, which asks."
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
# agents and skills have no step 0; the root SKILL.md has it, from ${CLAUDE_SKILL_DIR}
printf -- '---\nname: fx-runner\ndescription: "An agent."\ntools: Read, Bash\n---\n\nRun `"%s/scripts/rec.py" x`.\n' "$R" \
  > "$fx/agents/fx-runner.md"
mkdir -p "$fx/skills/fork"
printf -- '---\nname: f\ndescription: "A fork."\ncontext: fork\nagent: auditor:fx-runner\nallowed-tools: Read\n---\n\nRun as the agent.\n' \
  > "$fx/skills/fork/SKILL.md"
printf -- '---\nname: a\ndescription: "An agent."\ntools: Read, Bash\n---\n\nRun `"%s/scripts/ok.sh" check x`.\n' "$R" > "$fx/agents/good.md"
printf -- '---\nname: a\ndescription: "An agent."\ntools: Read, Bash\n---\n\nRun `bash "%s/scripts/ok.sh"`.\n' "$R" > "$fx/agents/c1.md"
printf -- '---\nname: s\ndescription: "A skill."\nallowed-tools:\n  - '"'"'Bash("%s/scripts/rec.py" *)'"'"'\n---\n\nRun `"%s/scripts/rec.py" x` or `"%s/scripts/rec.py" x | wc -l`.\n' "$R" "$R" "$R" \
  > "$fx/skills/s/SKILL.md"
printf -- '---\nname: x\ndescription: "A skill."\nallowed-tools:\n  - '"'"'Bash("${CLAUDE_SKILL_DIR}/scripts/preflight.sh" *)'"'"'\n  - '"'"'Bash("${CLAUDE_SKILL_DIR}/scripts/ok.sh" *)'"'"'\n---\n\n**Step 0 — Preflight.** Run `"${CLAUDE_SKILL_DIR}/scripts/preflight.sh"`; a refusal, or a denied call, stops the run.\nThen `"${CLAUDE_SKILL_DIR}/scripts/ok.sh" check x`.\n' \
  > "$fx/SKILL.md"
sed -e 's#CLAUDE_SKILL_DIR}/scripts/ok#CLAUDE_PLUGIN_ROOT}/scripts/ok#' "$fx/SKILL.md" > "$fx/skill-root.md"
# over 64 KiB, the one bad line last
{ sed -n '1,/^0\. \*\*Preflight/p' "$fx/commands/good.md"
  awk 'BEGIN { for (i = 0; i < 1400; i++) printf "Prose line %05d of a long command body, padded out with words to fill it up.\n", i }'
  printf '1. `bash "%s/scripts/ok.sh"`\n' "$R"; } > "$fx/commands/c1-large.md"
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
    procsub redirect redirect-in pipe-tight large; do
  expect "commands/c1-$c.md" C1
done
expect commands/c2-missing.md C2; expect commands/c2-mode.md C2; expect commands/c2-shebang.md C2
expect commands/c2-bin.md C2; expect commands/c2-bash-rule.md C2
# a rooted call without the marker is also no call its marked rule pre-approves
expect commands/c3-scan-rule.md C3; expect commands/c3-mem-rule.md C3; expect commands/c3-scan-call.md "C3 C5"
expect commands/c3-mem-call.md "C3 C5"; expect commands/c3-mem-bare.md C3; expect commands/c3-scan-fenced.md "C3 C5"
expect commands/c5-unlisted.md C5; expect commands/c5-agent.md C5; expect commands/c5-agent-covered.md ""
expect commands/c5-agent-mention.md ""; expect commands/c5-asks.md ""; expect commands/c5-fixed-word.md C5
expect commands/c5-exact.md C5; expect skills/fork/SKILL.md C5
expect commands/c4-no-rule.md C4; expect commands/c4-no-step.md C4; expect commands/c4-late.md C4
expect commands/c4-paragraph.md C4; expect commands/c4-args.md C4; expect commands/c4-no-denial.md C4
expect agents/good.md ""; expect agents/c1.md C1; expect skills/s/SKILL.md C1; expect SKILL.md ""
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

# ---- 1-4. the tree ----------------------------------------------------------------------------------------------
cd "$TREE" || exit 1
set --
for f in commands/*.md agents/*.md skills/*/SKILL.md SKILL.md; do [ -f "$f" ] && set -- "$@" "$f"; done
[ $# -gt 0 ] || { bad "no command, agent or skill files in $TREE"; }
found=$(check "$TREE" "$@"); rc=$?
if [ "$rc" -ne 0 ]; then bad "the checker failed on $TREE (status $rc)"
else
  n=0
  while IFS='	' read -r id at what; do
    [ -n "$id" ] || continue
    n=$((n + 1)); bad "$id $at: $what"
  done <<EOF
$found
EOF
  [ "$n" -eq 0 ] && ok "$# files: every entry point in the one form its rule pre-approves, and preflight.sh as step 0"
fi

# ---- 5. wording the flows depend on ------------------------------------------------------------------------
# file <TAB> text that must stay in it, on one line of the file.
while IFS='	' read -r f want; do
  [ -n "$f" ] || continue
  if [ -f "$f" ] && grep -qF -- "$want" "$f"; then ok "pin $f: $want"; else bad "P $f lost: $want"; fi
done <<'PINS'
commands/hunt.md	Run it in the foreground, never with `run_in_background`, and give the Bash
commands/hunt.md	invoke `auditor:hunt --resume 2 incident_<n>` through the Skill tool once it
commands/hunt.md	background command's completion notice starts has none, so spawn every agent in
commands/respond.md	foreground, never with `run_in_background`, and give the Bash call a timeout
commands/respond.md	`auditor:respond --resume 3 incident_<n>` through the Skill tool once it
commands/respond.md	background command's completion notice starts has none, so spawn every agent in
commands/audit-cycle.md	a turn that a background agent's or background command's completion notice starts has none
commands/audit-assist.md	a turn that a background agent's or background command's completion notice starts has none
commands/threat-model.md	a turn that a background agent's or background command's completion notice starts has none
commands/poc.md	a turn that a background agent's or background command's completion notice starts has none
commands/patch.md	a turn that a background agent's or background command's completion notice starts has none
commands/audit.md	Give each runner call (`target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/audit-cycle.md	Give each runner call (`run.sh`, `target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/audit-assist.md	Give each runner call (`run.sh`, `target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/diff-audit.md	Give each runner call (`target.sh`, `deps.sh`) the Bash tool's longest timeout
commands/quick-scan.md	Give each runner call (`deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/re-audit.md	Give each runner call (`run.sh`, `target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
commands/poc.md	Give each runner call (`run.sh`, `target.sh`) the Bash tool's longest timeout
commands/patch.md	Give each runner call (`run.sh`, `target.sh`) the Bash tool's longest timeout
SKILL.md	Give each runner call (`target.sh`, `deps.sh`, `sast.sh`) the Bash tool's longest timeout
agents/poc-engineer.md	Give each `run.sh` call the Bash tool's longest timeout
agents/patch-engineer.md	Give each runner call (`run.sh`, `target.sh`) the Bash tool's longest timeout
agents/vuln-hunter.md	Give each `sast.sh` call the Bash tool's longest timeout
commands/hunt.md	Give each runner call (`run.sh`, `target.sh`) the Bash tool's longest timeout, in the
commands/respond.md	Give each runner call (`run.sh`, `target.sh`) the Bash tool's longest timeout, in the
PINS

# Each command's resume text says how to answer the prompt its re-invocation brings.
for f in commands/*.md; do
  if grep -qF -- 'tell the human to answer "Yes", not "don'"'"'t ask again"' "$f"; then ok "$f: the resume text names the answer"
  else bad "P $f: the resume text does not tell the human to answer \"Yes\", not \"don't ask again\""; fi
done
# run.sh --crate reads its inputs from arguments only, so no body names the environment form of a PoC run.
for f in commands/*.md agents/*.md skills/*/SKILL.md SKILL.md; do
  [ -f "$f" ] || continue
  for v in VULNERABLE_SO FIXED_SO UPDATE_PINS KEEP_POC_BUILD CARGO_TARGET_DIR; do
    if grep -qF -- "$v" "$f"; then bad "P $f names $v, which run.sh --crate does not read"; else ok "no $v in $f"; fi
  done
done

echo "---- command forms: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
