#!/usr/bin/env bash
# test-depth-scope.sh — references/depth-scope.md, the one table the Quick and CI commands take their selection
# from, names only what exists, and names it where it is:
#   1. each section row (§2, and §4's CI-only rows) names a checklist file whose line <Start> is that section's
#      "## <n.m> — <title>" heading, and whose <Lines> run to the section's last line before the next heading;
#      each gated row's Gate cell holds backticked markers, and every other row's cell is empty;
#   2. §3's always rows are every always row of known-vectors/INDEX.md of severity 7 or more but 141, each under
#      its own phase; its marker rows are every marker row of severity 9 or more; 141, 035, 021, 130, 001 and 124
#      are rows of the index; the duplicate pairs are the index's consolidation map;
#   3. §5's repository-level rows are always rows of the index;
#   4. §4's bound ("The most a change can select is <N> sections") is the number of sections a change can select:
#      every domain's §2 rows, §2's 11.1, 11.8, 12.1, 12.5 and 13.9, and §4's CI-only rows.
# A checklist edit that moves a heading, or an index edit that adds a row of severity 7 or more, fails here until
# the table follows.
# Usage (from the repo root): bash scripts/tests/test-depth-scope.sh   (VERBOSE=1 lists every check)
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P) || exit 1
cd "$ROOT" || exit 1
pass=0; failn=0
ok()  { pass=$((pass + 1)); if [ -n "${VERBOSE:-}" ]; then echo "ok   $*"; fi; }
bad() { failn=$((failn + 1)); echo "FAIL $*"; }

T=$(mktemp -d "${TMPDIR:-/tmp}/depth-scope.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
python3 -I - references/depth-scope.md known-vectors/INDEX.md > "$T/out" 2>&1 <<'PY'
import re, sys, pathlib
table, index = pathlib.Path(sys.argv[1]).read_text(), pathlib.Path(sys.argv[2]).read_text()
def say(ok, what):
    print(("ok\t" if ok else "bad\t") + what)

def heading_span(path, start):
    lines = pathlib.Path(path).read_text().split("\n")
    if start < 1 or start > len(lines):
        return None, None
    head = lines[start - 1]
    j = start
    while j < len(lines) and not lines[j].startswith("## "):
        j += 1
    end = j
    while end > start and lines[end - 1].strip() in ("", "---"):
        end -= 1
    return head, end - start + 1

def section(md, title):
    m = re.search(r"(?ms)^## " + re.escape(title) + r".*?(?=^## |\Z)", md)
    return m.group(0) if m else ""

rows = []
for line in section(table, "2. Quick").split("\n"):
    c = [x.strip() for x in line.strip().strip("|").split("|")]
    if len(c) == 6 and c[1].startswith("`checklists/"):
        rows.append(("§2", c[0], c[1].strip("`"), c[2], c[3], c[4], c[5]))
for line in section(table, "4. CI").split("\n"):
    c = [x.strip() for x in line.strip().strip("|").split("|")]
    if len(c) == 4 and c[0].startswith("`checklists/"):
        rows.append(("§4", "ci", c[0].strip("`"), c[1], c[2], c[3], ""))
say(len(rows) > 50, f"the table has {len(rows)} section rows")
seen = set()
for part, dom, f, sec, start, n, gate in rows:
    m = re.match(r"§(\d+\.\d+) (.*)$", sec)
    if not m or not start.isdigit() or not n.isdigit():
        say(False, f"{part} row {f} {sec}: not '§<n.m> <title>' with a numeric start and count"); continue
    sid, title = m.group(1), m.group(2)
    seen.add((f, sid))
    if not pathlib.Path(f).is_file():
        say(False, f"{part} {sec}: {f} is no file"); continue
    head, span = heading_span(f, int(start))
    want = f"## {sid} — {title}"
    say(head == want, f"{part} {f}:{start} is the heading '{want}'" + ("" if head == want else f" (it is {head!r})"))
    say(span == int(n), f"{part} {f} §{sid} runs {n} lines" + ("" if span == int(n) else f" (it runs {span})"))
    gated = dom.endswith("gated")
    if gated:
        say("`" in gate, f"{part} §{sid} (gated) names backticked markers")
    else:
        say(gate == "", f"{part} §{sid} (not gated) has an empty Gate cell")

# the most a change can select: every domain's §2 rows, the §2 rows §4 names for manifests, workflows and keys,
# and §4's CI-only rows
ci = {(f, re.match(r"§(\d+\.\d+)", sec).group(1)) for part, dom, f, sec, start, n, gate in rows
      if part == "§4" or dom in ("on-chain", "on-chain, gated", "backend", "frontend", "ai-agent", "rust-service", "python")
      or re.match(r"§(11\.1|11\.8|12\.1|12\.5|13\.9) ", sec)}
bound = re.search(r"The most a change can select is (\d+) sections", table)
say(bool(bound) and int(bound.group(1)) == len(ci), f"§4's bound is the {len(ci)} sections a change can select" + ("" if bound else " (no bound sentence)") + ("" if not bound or int(bound.group(1)) == len(ci) else f" (it says {bound.group(1)})"))
# ...and their size, read at each row's Start for its Lines, in thousands of bytes
spans = {(f, re.match(r"§(\d+\.\d+)", sec).group(1)): (int(start), int(n)) for part, dom, f, sec, start, n, gate in rows}
size = 0
for key in ci:
    start, n = spans[key]
    size += sum(len(l.encode()) + 1 for l in pathlib.Path(key[0]).read_text().split("\n")[start - 1:start - 1 + n])
kb = re.search(r"The most a change can select is \d+ sections, about (\d+) KB", table)
say(bool(kb) and int(kb.group(1)) == round(size / 1000), f"§4's size is about {round(size / 1000)} KB ({size} bytes)" + ("" if kb else " (no size)") + ("" if not kb or int(kb.group(1)) == round(size / 1000) else f" (it says {kb.group(1)})"))

idx = {}
for line in index.split("\n"):
    m = re.match(r"\| (\d+) \| \[(.*?)\]\((.*?)\) \| (\d+) \| (.*) \|$", line)
    if m:
        idx[int(m.group(1))] = (int(m.group(4)), m.group(5))
s3 = section(table, "3. Quick")
alw = {}
for m in re.finditer(r"^  - (crypto|backend|frontend|devops|ai-agent|custody): ([0-9, ]+)[;.]$", s3, re.M):
    alw[m.group(1)] = sorted(int(x) for x in m.group(2).split(", "))
want_alw = {}
for n, (sev, cell) in idx.items():
    m = re.match(r"always \(([a-z-]+)\)", cell)
    if m and sev >= 7 and n != 141:
        want_alw.setdefault(m.group(1), []).append(n)
want_alw = {k: sorted(v) for k, v in want_alw.items()}
say(alw == want_alw, "§3's always rows are the index's always rows of 7 or more, but 141, each under its phase" + ("" if alw == want_alw else f": table {alw}, index {want_alw}"))
mk = re.search(r"\*\*The marker rows of severity 9 or more whose markers occur:\*\* ([0-9, ]+)\.", s3)
got_mk = sorted(int(x) for x in mk.group(1).split(", ")) if mk else []
want_mk = sorted(n for n, (sev, cell) in idx.items() if sev >= 9 and not cell.startswith("always"))
say(got_mk == want_mk, "§3's marker rows are the index's marker rows of 9 or more" + ("" if got_mk == want_mk else f": table {got_mk}, index {want_mk}"))
for n in (141, 35, 21, 130, 1, 124):
    say(n in idx, f"§3 names row {n:03d}, which the index has")
say(141 in idx and idx[141][1].startswith("always (devops) when"), "141 is the conditional always row §3 reads as a marker row")
pairs = sorted((int(a), int(b)) for a, b in re.findall(r"(\d{3}) for (\d{3})", s3))
want_pairs = sorted((int(a), int(b)) for a, b in re.findall(r"^\| (\d{3}) \| (\d{3}) \|", index, re.M))
say(pairs == want_pairs and len(pairs) == 6, "§3's duplicate pairs are the index's consolidation map" + ("" if pairs == want_pairs else f": table {pairs}, index {want_pairs}"))
s5 = section(table, "5. CI")
repo = sorted({int(x) for cell in re.findall(r"^\| ([0-9, ]+) \|", s5, re.M) for x in cell.split(", ")})
say(len(repo) == 10, f"§5 names 10 repository-level rows ({repo})")
# the on-chain-only bound §4 states: the on-chain and gated rows of §2, and §4's rows for manifests, workflows and keys
onchain = {(f, re.match(r"§(\d+\.\d+)", sec).group(1)) for part, dom, f, sec, start, n, gate in rows
           if part == "§4" or dom in ("on-chain", "on-chain, gated") or re.match(r"§(11\.1|11\.8|12\.1|12\.5|13\.9) ", sec)}
oc = re.search(r"a change to on-chain code alone selects at most (\d+)", table)
say(bool(oc) and int(oc.group(1)) == len(onchain), f"§4's on-chain-only bound is the {len(onchain)} sections such a change can select" + ("" if oc else " (no sentence)"))
for n in repo:
    say(n in idx and idx[n][1].startswith("always ("), f"§5's repository-level row {n:03d} is an always row of the index")
PY
[ $? -eq 0 ] || bad "the table check could not run: $(sed -n 1,5p "$T/out")"
while IFS='	' read -r verdict what; do
  [ -n "$verdict" ] || continue
  if [ "$verdict" = ok ]; then ok "$what"; else bad "$what"; fi
done < "$T/out"

echo "---- depth scope: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
