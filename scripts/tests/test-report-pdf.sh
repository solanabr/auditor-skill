#!/usr/bin/env bash
# test-report-pdf.sh — self-test for scripts/report-to-pdf.sh and scripts/pdf/no-remote.lua: the reports
# it takes (run-directory paths only) and the PDFs it may replace, the skips that keep it best-effort, the
# sandboxed pandoc call with the filter and the paranoid TeX settings, rendering in scratch, and the case
# file fixtures/report-pdf/cases.txt, run under each bash on the machine (/bin/bash and the bash running
# this suite, when they differ), which must print the same. Stand-ins take the place of pandoc and of the
# TeX engines; where pandoc 2.15 or later is installed, the filter also runs in the real pandoc against
# remote-image, raw-TeX, YAML and unclosed-comment fixtures, and where a TeX engine is installed, a probe
# shows that the engine, given the flag and settings report-to-pdf.sh gives it, runs no shell command and
# writes no file at an absolute path (each skipped, never failed, without the tool). Needs git; no network.
# Usage (from the repo root): bash scripts/tests/test-report-pdf.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
PDF="$ROOT/scripts/report-to-pdf.sh"
FILTER="$ROOT/scripts/pdf/no-remote.lua"
RUNDIR="$ROOT/scripts/rundir.sh"
CASES="$ROOT/scripts/tests/fixtures/report-pdf/cases.txt"
# The reader report-to-pdf.sh gives pandoc: Markdown without raw TeX, raw attributes or YAML metadata.
SPEC=markdown-raw_tex-raw_attribute-yaml_metadata_block
T=$(mktemp -d "${TMPDIR:-/tmp}/report-pdf-test.XXXXXX") || exit 1
T=$(cd -P "$T" && pwd -P) || exit 1
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
mkdir -p "$HOME"

pass=0 fail=0 skip=0
ok()   { pass=$((pass + 1)); echo "ok   - $1"; }
ko()   { fail=$((fail + 1)); echo "FAIL - $1"; }
skp()  { skip=$((skip + 1)); echo "skip - $1"; }
check() { # check <name> <command>...: on a failure, also show the last run
  if "${@:2}"; then ok "$1"; else ko "$1"; echo "#   status ${RC:-} stdout [$(cat "$T/out" 2>/dev/null)] stderr [$(cat "$T/err" 2>/dev/null)]"; fi
}
has()   { grep -qF -- "$2" "$1"; }
hasnt() { ! grep -qF -- "$2" "$1"; }

# $T/tools: the programs report-to-pdf.sh and the stand-ins use, linked one by one, so that no pandoc or
# TeX engine installed on this machine is reachable. Each scenario puts its stand-ins in front.
mkdir -p "$T/tools"
for t in bash sh env git find wc cat sed mktemp rm mv cp date tr awk sort grep ls basename dirname pwd mkdir chmod head od; do
  p=$(command -v "$t" 2>/dev/null) && case "$p" in /*) ln -s "$p" "$T/tools/$t" ;; esac
done
# The pandoc stand-in: --version prints $FAKE_PANDOC_VERSION (default 3.1.9); a render records its
# arguments, its working directory and the TeX settings of its environment in $FAKE_LOG, then writes a
# PDF to its -o file unless FAKE_PANDOC_FAIL is set.
mkdir -p "$T/pandoc-fake"
cat > "$T/pandoc-fake/pandoc" <<'EOF'
#!/bin/sh
if [ "$1" = --version ]; then printf 'pandoc %s\nFeatures: +server +lua\n' "${FAKE_PANDOC_VERSION:-3.1.9}"; exit 0; fi
{ printf 'pandoc'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'
  printf 'pwd %s\n' "$(pwd -P)"
  printf 'env openin_any=%s openout_any=%s shell_escape=%s TEXMFOUTPUT=%s TMPDIR=%s\n' \
    "${openin_any-unset}" "${openout_any-unset}" "${shell_escape-unset}" "${TEXMFOUTPUT-unset}" "${TMPDIR-unset}"
  [ -f report.md ] && printf 'input %s\n' "$(cat report.md)"; } >> "$FAKE_LOG"
out=""; prev=""
for a in "$@"; do [ "$prev" = -o ] && out=$a; prev=$a; done
[ -z "${FAKE_PANDOC_FAIL:-}" ] || exit 1
printf '%%PDF-1.4 stand-in for %s\n' "$out" > "$out"
EOF
# The engine stand-in, as xelatex, lualatex or pdflatex: it records its arguments and the TeX settings
# of its environment, keeps the .tex it was given in $FAKE_TEX, and writes <outdir>/<name>.pdf. Given
# FAKE_ENGINE_TOUCH, it also creates that file, as an engine that wrote outside its directory would.
cat > "$T/engine" <<'EOF'
#!/bin/sh
{ printf '%s' "${0##*/}"; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'
  printf 'env openin_any=%s openout_any=%s shell_escape=%s\n' "${openin_any-unset}" "${openout_any-unset}" "${shell_escape-unset}"; } >> "$FAKE_LOG"
[ -z "${FAKE_ENGINE_TOUCH:-}" ] || : > "$FAKE_ENGINE_TOUCH"
outdir=.; last=""
while [ $# -gt 0 ]; do
  case "$1" in -output-directory) outdir=$2; shift 2 ;; *) last=$1; shift ;; esac
done
cp "$last" "$FAKE_TEX" 2>/dev/null
base=${last##*/}; base=${base%.tex}
printf '%%PDF-1.4 engine stand-in\n' > "$outdir/$base.pdf"
printf 'engine stand-in log\n' > "$outdir/$base.log"
EOF
chmod +x "$T/pandoc-fake/pandoc" "$T/engine"
mkdir -p "$T/xe" "$T/lua" "$T/pdftex" "$T/oldpandoc"
ln -s "$T/engine" "$T/xe/xelatex"; ln -s "$T/engine" "$T/lua/lualatex"; ln -s "$T/engine" "$T/pdftex/pdflatex"
export FAKE_LOG="$T/fake.log" FAKE_TEX="$T/engine-input.tex"
FAKE_PATH="$T/pandoc-fake:$T/xe:$T/lua:$T/pdftex:$T/tools"

W="$T/wt"; mkdir -p "$W"
R=$(cd "$W" && "$RUNDIR" new audit) || { ko "rundir.sh new audit failed"; exit 1; }
I=$(cd "$W" && "$RUNDIR" new incident) || { ko "rundir.sh new incident failed"; exit 1; }
printf '# Audit report\n\nFindings.\n' > "$W/$R/REPORT.md"
# run <PATH> <args...>: report-to-pdf.sh run directly from $W; output in $T/out, $T/err and $RC.
run() { local p=$1; shift; (cd "$W" && PATH=$p TEXMFOUTPUT=/tmp/caller-texmfoutput "$PDF" "$@") >"$T/out" 2>"$T/err" </dev/null; RC=$?; }
refused() { [ "$RC" = 2 ] && [ "$(cat "$T/err")" = "report-to-pdf: refused: $1" ] && [ ! -s "$T/out" ]; }
tree() { (cd "$1" && find . -print | LC_ALL=C sort); }

# =================================================================================================
# The entry point, and the reports it takes.
# =================================================================================================
check "report-to-pdf.sh starts with #!/bin/bash" test "$(sed -n 1p "$PDF")" = '#!/bin/bash'
check "report-to-pdf.sh is executable" test -x "$PDF"
SHAPES='audit_<n>/REPORT.md, audit_<n>/RE-AUDIT.md, audit_<n>/PR-REPORT.md or incident_<n>/INCIDENT_REPORT.md'
mkdir "$W/audit_0"; printf '# r\n' > "$W/audit_0/REPORT.md"; ln -s "$R" "$W/audit_00"
mkdir "$W/notes"; printf '# n\n' > "$W/notes/REPORT.md"; printf '# o\n' > "$W/$R/notes.md"
: > "$FAKE_LOG"; tree "$W" > "$T/tree.before"
for bad in "$W/$R/REPORT.md" "/tmp/$R/REPORT.md" "../wt/$R/REPORT.md" "$R/notes.md" "$R/REPORT.markdown" "$R/report.md" \
           "$R/../$R/REPORT.md" "$R/./REPORT.md" "$R//REPORT.md" "notes/REPORT.md" "REPORT.md" "$R/sub/REPORT.md" \
           "$I/REPORT.md" "$R/INCIDENT_REPORT.md" "audit_x/REPORT.md" "Audit_1/REPORT.md" "-$R/REPORT.md"; do
  run "$FAKE_PATH" "$bad"
  check "the report $bad is refused (exit 2)" test "$RC" = 2
done
check "... with one line saying what it takes" refused "the report must be $SHAPES, relative to the working directory: -$R/REPORT.md"
run "$FAKE_PATH" "$R/REPORT.md" "$R/REPORT.md"
check "two arguments are refused (exit 2)" refused "usage: report-to-pdf.sh [path/to/REPORT.md], one of $SHAPES"
run "$FAKE_PATH" audit_0/REPORT.md
check "a run directory without its .gitignore of * is refused" refused "the run directory has no .gitignore holding exactly *: audit_0"
run "$FAKE_PATH" audit_00/REPORT.md
check "a run directory that is a symbolic link is refused" refused "the run directory is a symbolic link: audit_00"
check "no refusal ran pandoc" test ! -s "$FAKE_LOG"
tree "$W" > "$T/tree.after"
check "no refusal changed anything in the working directory" cmp -s "$T/tree.before" "$T/tree.after"
L=$(cd "$W" && "$RUNDIR" new audit); printf '# outside\n' > "$T/outside.md"; ln -s "$T/outside.md" "$W/$L/REPORT.md"
run "$FAKE_PATH" "$L/REPORT.md"
check "a report that is a symbolic link is refused" refused "the run directory holds a symbolic link: $L"
rm "$W/$L/REPORT.md"; mkdir "$W/$L/REPORT.md"
run "$FAKE_PATH" "$L/REPORT.md"
check "a report that is a directory is refused" refused "the report is not a regular file: $L/REPORT.md"
rmdir "$W/$L/REPORT.md"
if ln "$T/outside.md" "$W/$L/REPORT.md" 2>/dev/null; then
  run "$FAKE_PATH" "$L/REPORT.md"
  check "a report with a second link is refused" refused "the report is not a regular file with one link: $L/REPORT.md"
  rm "$W/$L/REPORT.md"
else
  skp "a hard link into the working directory could not be made here"
fi
printf '# r\n' > "$W/$L/REPORT.md"; ln -s "$T/elsewhere.pdf" "$W/$L/REPORT.pdf"
run "$FAKE_PATH" "$L/REPORT.md"
check "a REPORT.pdf that is a symbolic link is not replaced (refused)" refused "the run directory holds a symbolic link: $L"
check "... and nothing is written where it points" test ! -e "$T/elsewhere.pdf"
rm "$W/$L/REPORT.pdf"; mkdir "$W/$L/REPORT.pdf"
run "$FAKE_PATH" "$L/REPORT.md"
check "a REPORT.pdf that is a directory is not replaced (refused)" refused "$L/REPORT.pdf exists and is not a regular file with one link, so it is not replaced"
rmdir "$W/$L/REPORT.pdf"; printf 'other\n' > "$T/other.pdf"
if ln "$T/other.pdf" "$W/$L/REPORT.pdf" 2>/dev/null; then
  run "$FAKE_PATH" "$L/REPORT.md"
  check "a REPORT.pdf with a second link is not replaced (refused)" refused "$L/REPORT.pdf exists and is not a regular file with one link, so it is not replaced"
  check "... and the file it shares is untouched" test "$(cat "$T/other.pdf")" = other
  rm "$W/$L/REPORT.pdf"
else
  skp "a hard link into the working directory could not be made here"
fi
run "$FAKE_PATH" audit_999/REPORT.md
check "a report whose run directory does not exist is skipped (exit 0)" sh -c "[ $RC = 0 ] && grep -q 'input file not found: audit_999/REPORT.md' '$T/err'"
run "$FAKE_PATH" "$I/INCIDENT_REPORT.md"
check "a report that does not exist is skipped (exit 0)" sh -c "[ $RC = 0 ] && grep -q 'input file not found' '$T/err'"
(cd "$ROOT" && PATH=$FAKE_PATH "$PDF") >"$T/out" 2>"$T/err"; RC=$?
check "the installation inside the working directory is refused (exit 2)" \
  sh -c "[ $RC = 2 ] && grep -q 'the installation lies inside the working directory' '$T/err'"

# =================================================================================================
# Best effort: no pandoc, an old pandoc, no engine, a failing render: a message, exit 0, no PDF.
# =================================================================================================
run "$T/tools" "$R/REPORT.md"
check "no pandoc: skipped (exit 0) with the install hint" sh -c "[ $RC = 0 ] && grep -q 'pandoc not found — skipping PDF generation (non-fatal)' '$T/out'"
check "... and no PDF" test ! -e "$W/$R/REPORT.pdf"
for v in 2.14.2 2.9 1.19.2.4 'x.y'; do
  (cd "$W" && PATH=$FAKE_PATH FAKE_PANDOC_VERSION=$v "$PDF" "$R/REPORT.md") >"$T/out" 2>"$T/err"; RC=$?
  check "pandoc $v: skipped (exit 0), --sandbox is missing" sh -c "[ $RC = 0 ] && grep -q 'is older than 2.15, which added --sandbox' '$T/out' && [ ! -e '$W/$R/REPORT.pdf' ]"
done
run "$T/pandoc-fake:$T/tools" "$R/REPORT.md"
check "no engine: skipped (exit 0), naming the three engines" \
  sh -c "[ $RC = 0 ] && grep -q 'no PDF engine (xelatex, lualatex or pdflatex) found' '$T/out' && [ ! -e '$W/$R/REPORT.pdf' ]"
(cd "$W" && PATH=$FAKE_PATH FAKE_PANDOC_FAIL=1 "$PDF" "$R/REPORT.md") >"$T/out" 2>"$T/err"; RC=$?
check "a render that fails: exit 0, the failure named" sh -c "[ $RC = 0 ] && grep -q 'pandoc failed to render PDF (non-fatal)' '$T/err'"
check "... no PDF and no partial file beside the report" sh -c "[ -z \"\$(ls '$W/$R' | grep -i pdf)\" ]"
mkdir -p "$W/tmpin"
(cd "$W" && TMPDIR="$W/tmpin" PATH=$FAKE_PATH "$PDF" "$R/REPORT.md") >"$T/out" 2>"$T/err"; RC=$?
check "a TMPDIR inside the working directory is refused (exit 2), with nothing made there" \
  sh -c "[ $RC = 2 ] && [ -z \"\$(ls -A '$W/tmpin')\" ] && grep -q 'TMPDIR lies inside the working directory' '$T/err'"
rmdir "$W/tmpin"

# =================================================================================================
# Rendering, with the stand-in pandoc: the sandboxed call, the filter, the paranoid TeX settings, the
# report copied into scratch, and the PDF renamed into place beside it.
# =================================================================================================
: > "$FAKE_LOG"
run "$FAKE_PATH" "$R/REPORT.md"
check "render: exit 0" test "$RC" = 0
check "render: it says what it wrote" sh -c "grep -qx 'report-to-pdf: rendering $R/REPORT.md -> $R/REPORT.pdf' '$T/out' && grep -qx 'report-to-pdf: wrote $R/REPORT.pdf' '$T/out'"
check "render: the PDF beside the report is the one pandoc made" sh -c "grep -q '^%PDF-1.4 stand-in for ' '$W/$R/REPORT.pdf'"
check "render: the PDF is readable by its owner only" test "$(ls -l "$W/$R/REPORT.pdf" | cut -c1-10)" = '-rw-------'
check "render: no partial file is left beside it" sh -c "[ -z \"\$(ls -A '$W/$R' | grep 'part')\" ]"
PLINE=$(grep '^pandoc ' "$FAKE_LOG")
SCRATCH=$(sed -n 's/^pwd //p' "$FAKE_LOG")
check "render: pandoc runs in a scratch directory outside the working directory" \
  sh -c "case '$SCRATCH' in '$W'|'$W'/*|'') exit 1 ;; esac"
check "render: ... which is removed afterwards" test ! -e "$SCRATCH"
check "render: the call is pandoc --sandbox with raw TeX, raw attributes and YAML metadata off, the filter and the first engine found" \
  test "$PLINE" = "pandoc [--sandbox] [-f] [$SPEC] [--lua-filter] [$FILTER] [--pdf-engine=xelatex] [--pdf-engine-opt=-no-shell-escape] [-o] [$SCRATCH/report.pdf] [report.md]"
check "render: pandoc reads a copy of the report, in scratch" has "$FAKE_LOG" "input # Audit report"
check "render: the engine's settings are paranoid, the caller's TEXMFOUTPUT dropped, TMPDIR the scratch directory" \
  has "$FAKE_LOG" "env openin_any=p openout_any=p shell_escape=f TEXMFOUTPUT=unset TMPDIR=$SCRATCH"
check "render: the filter ships beside the script" test -s "$FILTER"
run "$FAKE_PATH" "$R/REPORT.md"
check "render again: the PDF of the run before, a regular file with one link, is replaced" \
  sh -c "[ $RC = 0 ] && grep -q '^%PDF-1.4 stand-in' '$W/$R/REPORT.pdf'"
: > "$FAKE_LOG"
run "$T/pandoc-fake:$T/lua:$T/pdftex:$T/tools" "$R/REPORT.md"
check "render: without xelatex, lualatex is taken" has "$FAKE_LOG" "[--pdf-engine=lualatex]"
: > "$FAKE_LOG"
run "$T/pandoc-fake:$T/pdftex:$T/tools" "$R/REPORT.md"
check "render: with pdflatex alone, pdflatex" has "$FAKE_LOG" "[--pdf-engine=pdflatex]"
for f in RE-AUDIT PR-REPORT; do
  printf '# %s\n' "$f" > "$W/$R/$f.md"
  run "$FAKE_PATH" "./$R/$f.md"
  check "render: $R/$f.md gives $R/$f.pdf" sh -c "[ $RC = 0 ] && [ -s '$W/$R/$f.pdf' ]"
done
printf '# Incident report\n' > "$W/$I/INCIDENT_REPORT.md"
run "$FAKE_PATH" "$I/INCIDENT_REPORT.md"
check "render: $I/INCIDENT_REPORT.md gives $I/INCIDENT_REPORT.pdf" sh -c "[ $RC = 0 ] && [ -s '$W/$I/INCIDENT_REPORT.pdf' ]"
# With no argument: the newest audit_*/REPORT.md of a real run directory.
N2=$(cd "$W" && "$RUNDIR" new audit); printf '# newest\n' > "$W/$N2/REPORT.md"
touch -t 200001010000 "$W/$R/REPORT.md"; touch -t 200101010000 "$W/audit_0/REPORT.md"
: > "$FAKE_LOG"
run "$FAKE_PATH"
check "no argument: the newest audit_*/REPORT.md is rendered" \
  sh -c "[ $RC = 0 ] && grep -qx 'report-to-pdf: no input given; using newest report: $N2/REPORT.md' '$T/out' && [ -s '$W/$N2/REPORT.pdf' ]"
touch -t 203001010000 "$W/$R/REPORT.md"
run "$FAKE_PATH"
check "no argument: ... by modification time" grep -qx "report-to-pdf: no input given; using newest report: $R/REPORT.md" "$T/out"
EMPTYW="$T/empty-wt"; mkdir -p "$EMPTYW"
(cd "$EMPTYW" && PATH=$FAKE_PATH "$PDF") >"$T/out" 2>"$T/err"; RC=$?
check "no argument and no report: skipped (exit 0)" sh -c "[ $RC = 0 ] && grep -q 'no input given and no audit_\*/REPORT.md found' '$T/err'"

# =================================================================================================
# The filter, in the real pandoc: images become their alt text, raw blocks and inlines are dropped,
# math shows as code, in the body and in the metadata alike, and every element keeps its identifier and
# classes but no key=value attribute, so neither a remote image nor raw TeX reaches the engine. A YAML
# block anywhere in the report prints as text and sets no template variable.
# =================================================================================================
REALPANDOC=$(command -v pandoc 2>/dev/null)
pv=""; [ -n "$REALPANDOC" ] && pv=$("$REALPANDOC" --version 2>/dev/null | sed -n '1s/^[^ ]* //p')
pmaj=${pv%%.*}; pmin=${pv#*.}; pmin=${pmin%%.*}
real_ok=0
case "$pmaj.$pmin" in
  *[!0-9.]*|.*|*.) ;;
  *) if [ "$pmaj" -gt 2 ] || { [ "$pmaj" -eq 2 ] && [ "$pmin" -ge 15 ]; }; then real_ok=1; fi ;;
esac
if [ "$real_ok" -ne 1 ]; then
  skp "the filter in a real pandoc: no pandoc 2.15 or later on PATH (found: ${pv:-none})"
else
  echo "# real pandoc: $REALPANDOC $pv"
  F="$T/hostile.md"
  cat > "$F" <<'EOF'
% Report $\special{pdf:title}$ <b>bold</b>

<!-- a template comment -->
# Findings

![tracking pixel](https://example.invalid/track.png "t") and ![local](../../../etc/hosts)

![figure alt](https://example.invalid/figure.png)

<img src="https://example.invalid/raw.png"> and \input{/etc/passwd} and \write18{touch pwned}

```{=latex}
\immediate\write18{touch pwned-block}
```

`\special{pdf:inline}`{=latex} and $\input{/etc/shells}$ and $$\openin1=/etc/hosts$$

<div>inner *text*</div>

![placed figure](x.png){#fig:placed latex-placement="htbp]\input{/etc/hosts}"}

```{#cb1 .haskell .numberLines startFrom="1]\input{/etc/hosts}"}
main = pure ()
```

::: {#d1 .note lang="en]\input{/etc/hosts}" dir="rtl"}
div text
:::

[span text]{#s1 .mark lang="de]\input{/etc/hosts}"} and `code`{.c key="v1"} and [a link](https://example.invalid/){key="v2"}

## A heading {#h2 data-x="v3"}
EOF
  "$REALPANDOC" --sandbox -f "$SPEC" --lua-filter "$FILTER" -t native -s "$F" > "$T/native.txt" 2>"$T/native.err"
  check "real pandoc: the filtered document parses (exit 0)" test "$?" = 0
  check "real pandoc: no Image is left" hasnt "$T/native.txt" "Image"
  check "real pandoc: no raw block or inline is left" sh -c "! grep -q 'RawBlock\|RawInline' '$T/native.txt'"
  check "real pandoc: no Math is left" hasnt "$T/native.txt" "Math"
  check "real pandoc: an image's alt text stays" sh -c "grep -q 'tracking' '$T/native.txt' && grep -q 'figure' '$T/native.txt'"
  check "real pandoc: math stays as code, its source visible" has "$T/native.txt" 'Code ( "" , [] , [] ) "\\input{/etc/shells}"'
  check "real pandoc: math in the metadata is code too" has "$T/native.txt" 'Code ( "" , [] , [] ) "\\special{pdf:title}"'
  check "real pandoc: an HTML comment drops out rather than printing" hasnt "$T/native.txt" "template comment"
  check "real pandoc: no URL of an image survives" sh -c "! grep -q 'track.png\|figure.png\|raw.png' '$T/native.txt'"
  check "real pandoc: no key=value attribute is left on any element" \
    sh -c "! grep -q -e 'latex-placement' -e 'startFrom' -e '\"lang\"' -e '\"dir\"' -e '\"key\"' -e 'data-x' '$T/native.txt'"
  check "real pandoc: identifiers and classes stay" \
    sh -c "grep -q '\"fig:placed\"' '$T/native.txt' && grep -q '\"numberLines\"' '$T/native.txt' && grep -q '\"mark\"' '$T/native.txt' && grep -q '\"h2\"' '$T/native.txt'"
  "$REALPANDOC" --sandbox -f "$SPEC" --lua-filter "$FILTER" -t latex -s "$F" > "$T/out.tex" 2>/dev/null
  check "real pandoc: the LaTeX has no \\includegraphics" hasnt "$T/out.tex" '\includegraphics'
  check "real pandoc: a figure gets no placement option" sh -c "grep -q 'begin{figure}' '$T/out.tex' && ! grep -qF '\\begin{figure}[' '$T/out.tex'"
  check "real pandoc: ... and keeps its label" has "$T/out.tex" '\label{fig:placed}'
  check "real pandoc: no raw \\input, \\write18, \\special or \\openin reaches the LaTeX" \
    sh -c "! grep -qF -e '\\input{/etc' -e '\\write18' -e '\\special{' -e '\\openin1' '$T/out.tex'"
  # pandoc spells the backslash \textbackslash{} or "\textbackslash " depending on its version and what follows.
  raw_as_text() { has "$1" '\textbackslash{}input\{/etc/passwd\}' || has "$1" '\textbackslash input\{/etc/passwd\}'; }
  check "real pandoc: the text of the raw TeX prints as text" raw_as_text "$T/out.tex"
  # An unclosed "<!--" in quoted text runs to the next "-->": inline, at a line's start and in a table
  # cell, closed by a template's comment or by a second quoted string. What it spans prints as text, so
  # no finding drops out; a template's long comment, "<!--" and "-->" on lines of their own, still drops.
  cat > "$T/swallow.md" <<'EOF'
# R

A commit subject: fix: escape <!-- in docs

## C-01 Critical first

Body one.

<!-- a template note -->

<!-- quoted at a line's start

## C-02 High second

Body two.

and a second quoted string -->

| commit | note |
|--------|------|
| a1     | x <!-- y |

## C-03 Medium third

<!-- t -->

<!--
A template's long comment.

Its second paragraph.
-->

## C-04 Low fourth
EOF
  "$REALPANDOC" --sandbox -f "$SPEC" --lua-filter "$FILTER" -t plain --wrap=none "$T/swallow.md" > "$T/swallow.txt" 2>/dev/null
  check "real pandoc: an unclosed <!-- hides no finding, inline, at a line's start or in a table cell" \
    sh -c "for f in C-01 C-02 C-03 C-04 'Body one' 'Body two'; do grep -q \"\$f\" '$T/swallow.txt' || exit 1; done"
  check "real pandoc: ... what it spans prints as text" sh -c "grep -q 'escape <!-- in docs' '$T/swallow.txt' && grep -q 'second quoted string -->' '$T/swallow.txt'"
  check "real pandoc: a template's long comment, <!-- and --> on lines of their own, still drops" \
    sh -c "! grep -q 'long comment\|second paragraph' '$T/swallow.txt'"
  # The whole run, with the real pandoc and the engine stand-in.
  mkdir -p "$T/realbin"; ln -s "$REALPANDOC" "$T/realbin/pandoc"
  cp "$F" "$W/$R/REPORT.md"; : > "$FAKE_LOG"; rm -f "$FAKE_TEX" "$W/$R/REPORT.pdf"
  tree "$W" > "$T/w.before"; tree "$HOME" > "$T/home.before"
  run "$T/realbin:$T/xe:$T/tools" "$R/REPORT.md"
  check "real pandoc: the report renders (exit 0) with the engine stand-in" sh -c "[ $RC = 0 ] && grep -q '^%PDF-1.4 engine stand-in' '$W/$R/REPORT.pdf'"
  check "real pandoc: the engine got -no-shell-escape" sh -c "grep '^xelatex ' '$FAKE_LOG' | grep -qF '[-no-shell-escape]'"
  check "real pandoc: ... and the paranoid settings" has "$FAKE_LOG" "env openin_any=p openout_any=p shell_escape=f"
  check "real pandoc: the .tex the engine got has no image, raw TeX or math from the report" \
    sh -c "[ -s '$FAKE_TEX' ] && ! grep -qF -e '\\includegraphics' -e '\\write18' -e '\\special{' -e '\\input{/etc' '$FAKE_TEX'"
  # What the run left outside its scratch directory, which it removes: the PDF beside the report, and
  # nothing else. The comparison must see a file the engine writes in the working directory, as the
  # stand-in does given FAKE_ENGINE_TOUCH.
  changed() { diff "$1" "$2" | sed -n 's/^[<>] //p' | LC_ALL=C sort | tr '\n' ' '; }
  tree "$W" > "$T/w.after"; tree "$HOME" > "$T/home.after"
  check "real pandoc: the run adds REPORT.pdf and nothing else to the working directory" \
    test "$(changed "$T/w.before" "$T/w.after")" = "./$R/REPORT.pdf "
  check "real pandoc: ... and nothing to HOME" cmp -s "$T/home.before" "$T/home.after"
  rm -f "$W/$R/REPORT.pdf"; tree "$W" > "$T/w.before"
  FAKE_ENGINE_TOUCH="$W/planted" run "$T/realbin:$T/xe:$T/tools" "$R/REPORT.md"
  tree "$W" > "$T/w.after"
  check "real pandoc: ... a comparison that sees a file the engine writes there" \
    test "$(changed "$T/w.before" "$T/w.after")" = "./$R/REPORT.pdf ./planted "
  rm -f "$W/planted"
  # YAML blocks quoted from the audited repo, in a blockquote and at the top level: as metadata they would
  # replace the body, put Lua into \directlua through a font fallback, and set the document class and
  # the PDF trailer.
  cat > "$W/$R/REPORT.md" <<'EOF'
# Audit report

### C-01 Critical: missing signer check

The commit that removed the check says:

> Refactor withdraw
>
> ---
> body: 'No findings.'
> mainfont: 'Latin Modern Roman'
> mainfontfallback: ['x\" , print(\"fixture\") , \"y']
> ---

A log line from the target's CI:

---
documentclass: standalone
pdf-trailer-id: '(a) (b) ] /Root 1 0 R /X ['
---

### H-01 High: unchecked arithmetic
EOF
  : > "$FAKE_LOG"; rm -f "$FAKE_TEX" "$W/$R/REPORT.pdf"
  run "$T/realbin:$T/xe:$T/tools" "$R/REPORT.md"
  check "real pandoc, YAML in the report: it renders (exit 0)" sh -c "[ $RC = 0 ] && [ -s '$FAKE_TEX' ]"
  check "real pandoc, YAML in the report: the findings stay the body" \
    sh -c "grep -q 'C-01 Critical' '$FAKE_TEX' && grep -q 'H-01 High' '$FAKE_TEX'"
  check "real pandoc, YAML in the report: no font fallback reaches \\directlua" hasnt "$FAKE_TEX" 'directlua'
  sed '/^\\begin{document}/,$d' "$FAKE_TEX" > "$T/preamble.tex"
  check "real pandoc, YAML in the report: the document class and the PDF trailer stay the template's" \
    sh -c "[ -s '$T/preamble.tex' ] && ! grep -q -e '{standalone}' -e 'trailer' '$T/preamble.tex'"
  check "real pandoc, YAML in the report: it prints as text" sh -c "grep -q 'body:' '$FAKE_TEX' && grep -q 'documentclass:' '$FAKE_TEX'"
fi

# =================================================================================================
# The engine's own guard, where a TeX engine is installed: a .tex that runs a shell command and opens a
# file at an absolute path for writing, compiled with the flag and settings report-to-pdf.sh gives the
# engine (checked above), writes neither file. Each check counts only when the same .tex, compiled with
# shell escape on and openout_any=a, does write its file; otherwise it is skipped.
# =================================================================================================
ENG=""
for e in xelatex lualatex pdflatex; do
  p=$(command -v "$e" 2>/dev/null) && case "$p" in /*) ENG=$p; break ;; esac
done
if [ -z "$ENG" ]; then
  skp "the engine's own guard: no xelatex, lualatex or pdflatex on PATH"
elif case "$T" in *[!A-Za-z0-9_./-]*) true ;; *) false ;; esac; then
  skp "the engine's own guard: the temp path holds a character TeX would read as markup: $T"
else
  # probe <dir> <shell_escape> <openout_any> <shell-escape flag>: compile probe.tex in <dir>.
  probe() {
    rm -rf "$T/outside" && mkdir -p "$1" "$T/outside" || return 1
    cat > "$1/probe.tex" <<EOF
\documentclass{article}
\begin{document}
\immediate\write18{touch $T/outside/shell}
\newwrite\probeout
\immediate\openout\probeout=$T/outside/openout.tex
\immediate\write\probeout{x}
\immediate\closeout\probeout
probe
\end{document}
EOF
    (cd "$1" && unset TEXMFOUTPUT && export openin_any=p openout_any="$3" shell_escape="$2" TMPDIR="$1" &&
      exec "$ENG" "$4" -interaction=nonstopmode -halt-on-error probe.tex) >/dev/null 2>&1 </dev/null
  }
  probe "$T/probe-open" t a -shell-escape
  opened=""
  [ -e "$T/outside/shell" ] && opened="shell"
  [ -e "$T/outside/openout.tex" ] && opened="$opened openout"
  probe "$T/probe-shut" f p -no-shell-escape
  case "$opened" in
    *shell*) check "the engine's own guard (${ENG##*/}): no shell command runs" test ! -e "$T/outside/shell" ;;
    *) skp "the engine's own guard: ${ENG##*/} ran no shell command even with shell escape on" ;;
  esac
  case "$opened" in
    *openout*) check "the engine's own guard (${ENG##*/}): no file is written at an absolute path" test ! -e "$T/outside/openout.tex" ;;
    *) skp "the engine's own guard: ${ENG##*/} wrote no file at an absolute path even with openout_any=a" ;;
  esac
fi

# =================================================================================================
# The case file, under each bash on the machine.
# =================================================================================================
SHELLS=("$BASH")
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then
  SHELLS+=(/bin/bash)
fi
echo "# shells: ${SHELLS[*]}"
CW="$T/cases-wt"; mkdir -p "$CW"
(cd "$CW" && "$RUNDIR" new audit >/dev/null && "$RUNDIR" new incident >/dev/null)
printf '# r\n' > "$CW/audit_1/REPORT.md"; ln -s audit_1 "$CW/audit_2"; mkdir "$CW/audit_3"; printf '# r\n' > "$CW/audit_3/REPORT.md"
tree "$CW" > "$T/ctree.before"; : > "$FAKE_LOG"
ncase=0
while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  want_rc=${line%%$'\t'*}
  rest=${line#*$'\t'}
  want_err=${rest%%$'\t'*}
  rest=${rest#*$'\t'}
  IFS=$'\t' read -r -a args <<< "$rest"
  ncase=$((ncase + 1))
  i=0
  for sh in "${SHELLS[@]}"; do
    (cd "$CW" && PATH=$FAKE_PATH "$sh" "$PDF" "${args[@]}") >"$T/out" 2>"$T/err" </dev/null
    RC=$?
    if [ "$RC" = "$want_rc" ] && [ "$(cat "$T/err")" = "$want_err" ] && [ ! -s "$T/out" ]; then
      [ "$i" -gt 0 ] || ok "case: report-to-pdf.sh ${args[*]}"
    else
      ko "case ($sh): report-to-pdf.sh ${args[*]} -> status $RC, stderr: $(cat "$T/err")"
    fi
    i=$((i + 1))
  done
done < "$CASES"
check "the case file has cases ($ncase)" test "$ncase" -gt 20
tree "$CW" > "$T/ctree.after"
check "no case changed anything in the working directory" cmp -s "$T/ctree.before" "$T/ctree.after"
check "no case ran pandoc" test ! -s "$FAKE_LOG"

echo
echo "report-to-pdf tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
