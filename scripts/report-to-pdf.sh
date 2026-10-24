#!/bin/bash
# report-to-pdf.sh — best-effort Markdown -> PDF for audit and incident reports.
#
# The Markdown report is ALWAYS the primary deliverable. PDF is a convenience.
# This script is NEVER a hard dependency: if pandoc 2.15 or later, or a PDF engine,
# is not installed it prints a clear message and exits 0 (success), so it can be
# wired into any pipeline without ever breaking a build.
#
# Usage (by the installation's absolute path, never one relative to the audited repo,
# and from the working directory):
#   "${CLAUDE_PLUGIN_ROOT}/scripts/report-to-pdf.sh" [path/to/REPORT.md]
#
# The path is audit_<n>/REPORT.md, audit_<n>/RE-AUDIT.md, audit_<n>/PR-REPORT.md or
# incident_<n>/INCIDENT_REPORT.md, relative to the working directory, in a run
# directory (scripts/lib/confine.sh: directly in the working directory, holding no
# symbolic link, untracked in any letter case, with a .gitignore holding exactly "*"),
# and a regular file with one link. If no argument is given, it defaults to the newest
# audit_*/REPORT.md. Any other path is refused: one stderr line, "report-to-pdf:
# refused: <reason>", and exit 2.
# Output PDF is written next to the input, with the .md extension swapped for .pdf; a
# PDF already there is replaced only when it is a regular file with one link.
#
# Rendering: the report is copied into a private temp directory outside the working
# directory and rendered there, with
#   pandoc --sandbox -f markdown-raw_tex-raw_attribute --lua-filter scripts/pdf/no-remote.lua \
#          --pdf-engine=<xelatex|lualatex|pdflatex, the first found> --pdf-engine-opt=-no-shell-escape
# --sandbox keeps pandoc from reading any file but its input and from fetching
# anything. The filter turns every image into its alt text, drops every raw block and
# raw inline, shows math as code, and leaves every element its identifier and classes
# but no key=value attribute (the LaTeX writer passes some, such as a figure's
# latex-placement, to the engine as written), so no text of the report reaches the
# TeX engine as TeX. Raw HTML is still parsed, so the HTML comments of the report
# templates drop out with it rather than printing as text. The engine gets kpathsea's
# paranoid settings (openin_any=p, openout_any=p: no absolute path outside pandoc's
# own temp directory, no "..", no dotfile) and shell_escape=f; the caller's
# TEXMFOUTPUT is dropped, and pandoc sets its own temp directory. The PDF is copied
# into a new file beside the report and renamed into place.
#
# Exit: 0 rendered or skipped (no report, no pandoc, a pandoc older than 2.15, no
# engine, or a render that failed) · 2 refused.

set -uo pipefail
unset CDPATH
case "$0" in */*) here=${0%/*} ;; *) here=. ;; esac
here=$(cd -P -- "$here" 2>/dev/null && pwd -P) || { printf 'report-to-pdf: refused: the installation cannot be resolved\n' >&2; exit 2; }
. "$here/lib/confine.sh" || { printf 'report-to-pdf: refused: scripts/lib/confine.sh cannot be read\n' >&2; exit 2; }
confine_init report-to-pdf "${here%/*}" 2
confine_need env git find wc cat sed mktemp rm mv
WT=$CONFINE_WT
FILTER="$here/pdf/no-remote.lua"
exec </dev/null

refuse() { confine_refuse "$1"; }
SHAPES='audit_<n>/REPORT.md, audit_<n>/RE-AUDIT.md, audit_<n>/PR-REPORT.md or incident_<n>/INCIDENT_REPORT.md'

# ---- Resolve input ----------------------------------------------------------
[ $# -le 1 ] || refuse "usage: report-to-pdf.sh [path/to/REPORT.md], one of $SHAPES"
INPUT="${1-}"

if [ -z "$INPUT" ]; then
  # Default: newest audit_*/REPORT.md in the current directory, among real run directories.
  for f in audit_*/REPORT.md; do
    confine_rundir_name "${f%/REPORT.md}" || continue
    [ ! -L "${f%/REPORT.md}" ] && [ ! -L "$f" ] && [ -f "$f" ] || continue
    if [ -z "$INPUT" ] || [ "$f" -nt "$INPUT" ]; then INPUT=$f; fi
  done
  if [ -z "$INPUT" ]; then
    echo "report-to-pdf: no input given and no audit_*/REPORT.md found." >&2
    echo "               usage: $0 [path/to/REPORT.md]" >&2
    exit 0
  fi
  echo "report-to-pdf: no input given; using newest report: $INPUT"
fi

IN=${INPUT#./}
RUN=""
case "$IN" in
  audit_*/REPORT.md|audit_*/RE-AUDIT.md|audit_*/PR-REPORT.md) RUN=${IN%/*} ;;
  incident_*/INCIDENT_REPORT.md) RUN=${IN%/*} ;;
esac
if [ -z "$RUN" ] || ! confine_rundir_name "$RUN"; then
  refuse "the report must be $SHAPES, relative to the working directory: $(confine_text "$INPUT")"
fi
if [ ! -e "$WT/$RUN" ] && [ ! -L "$WT/$RUN" ]; then
  echo "report-to-pdf: input file not found: $IN" >&2
  exit 0
fi
confine_rundir "$RUN" "the run directory"
confine_path "$IN" "the report" any
case "$CONFINE_TYPE" in
  none)
    echo "report-to-pdf: input file not found: $IN" >&2
    exit 0 ;;
  dir) refuse "the report is not a regular file: $IN" ;;
esac
confine_one_link "$WT/$IN" || refuse "the report is not a regular file with one link: $IN"
OUTPUT="${IN%.md}.pdf"
# own_output: the PDF beside the report is absent, or a regular file with one link that may be replaced.
own_output() {
  if [ -e "$WT/$OUTPUT" ] || [ -L "$WT/$OUTPUT" ]; then
    confine_one_link "$WT/$OUTPUT" || refuse "$OUTPUT exists and is not a regular file with one link, so it is not replaced"
  fi
}
own_output

# ---- Check for pandoc and an engine (soft dependencies) -----------------------
if ! command -v pandoc >/dev/null 2>&1; then
  echo "report-to-pdf: pandoc not found — skipping PDF generation (non-fatal)."
  echo "               The Markdown report is the primary deliverable: $IN"
  echo "               To enable PDF export, install pandoc:"
  echo "                 macOS:         brew install pandoc"
  echo "                 Debian/Ubuntu: sudo apt-get install pandoc"
  echo "                 (a LaTeX engine such as 'basictex' or 'texlive' may also be required)"
  exit 0
fi
# "pandoc 3.1.9" (the first line of --version): --sandbox came in 2.15.
ver=$(pandoc --version 2>/dev/null | sed -n '1s/^[^ ]* //p')
major=${ver%%.*}
minor=${ver#*.}
minor=${minor%%.*}
case "$major.$minor" in
  *[!0-9.]*|.*|*.) old=1 ;;
  *) if [ "$major" -gt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -ge 15 ]; }; then old=0; else old=1; fi ;;
esac
if [ "$old" -eq 1 ]; then
  echo "report-to-pdf: pandoc ${ver:-of an unknown version} is older than 2.15, which added --sandbox — skipping PDF generation (non-fatal)."
  echo "               The Markdown report is the primary deliverable: $IN"
  exit 0
fi
ENGINE=""
for e in xelatex lualatex pdflatex; do
  if command -v "$e" >/dev/null 2>&1; then ENGINE=$e; break; fi
done
if [ -z "$ENGINE" ]; then
  echo "report-to-pdf: no PDF engine (xelatex, lualatex or pdflatex) found — skipping PDF generation (non-fatal)."
  echo "               The Markdown report is the primary deliverable: $IN"
  echo "               A LaTeX engine provides one:"
  echo "                 macOS: brew install basictex   (or a full texlive)"
  exit 0
fi

# ---- Render -----------------------------------------------------------------
if confine_scratch report-to-pdf; then
  TMPD=$CONFINE_SCRATCH
elif [ $? -eq 2 ]; then
  refuse "TMPDIR lies inside the working directory; set it to a directory outside the tree"
else
  echo "report-to-pdf: cannot create a private temp directory — skipping PDF generation (non-fatal)." >&2
  exit 0
fi
trap 'rm -rf "$TMPD"' EXIT
[ ! -L "$WT/$IN" ] || refuse "the report is a symbolic link: $IN"
cat -- "$WT/$IN" > "$TMPD/report.md" || refuse "the report cannot be read: $IN"

echo "report-to-pdf: rendering $IN -> $OUTPUT"
if ( cd "$TMPD" && unset TEXMFOUTPUT && export openin_any=p openout_any=p shell_escape=f TMPDIR="$TMPD" &&
     exec pandoc --sandbox -f markdown-raw_tex-raw_attribute --lua-filter "$FILTER" \
       --pdf-engine="$ENGINE" --pdf-engine-opt=-no-shell-escape -o "$TMPD/report.pdf" report.md ) &&
   [ -s "$TMPD/report.pdf" ]; then
  # The run directory and the PDF's name are checked again, then the PDF goes into a new file beside
  # the report, written through the descriptor opened at creation, and is renamed into place.
  confine_rundir "$RUN" "the run directory"
  own_output
  PART="$OUTPUT.part-$$"
  [ ! -e "$WT/$PART" ] && [ ! -L "$WT/$PART" ] || refuse "$PART is in the way"
  confine_new_copy "$TMPD/report.pdf" "$WT/$PART" || refuse "cannot write $PART beside the report"
  own_output
  if ! mv -f -- "$WT/$PART" "$WT/$OUTPUT"; then
    rm -f -- "$WT/$PART"
    refuse "cannot rename $PART to $OUTPUT"
  fi
  echo "report-to-pdf: wrote $OUTPUT"
else
  echo "report-to-pdf: pandoc failed to render PDF (non-fatal)." >&2
  echo "               The Markdown report remains the deliverable: $IN" >&2
  echo "               A missing PDF engine (LaTeX) is the usual cause; try:" >&2
  echo "                 macOS: brew install basictex   (or a full texlive)" >&2
  exit 0
fi
