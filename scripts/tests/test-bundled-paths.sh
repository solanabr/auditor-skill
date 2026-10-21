#!/usr/bin/env bash
# test-bundled-paths.sh — bundled executables run from the auditor-skill root, never by a path relative to
# the working directory, which during an audit is usually the target repository (OUTPUT-RULES.md Rule 11e).
#   1. commands/ and agents/, where Claude Code fills in ${CLAUDE_PLUGIN_ROOT}, name no bundled tool,
#      Trail of Bits plugin, PoC template or script by a relative path, and never use ${CLAUDE_SKILL_DIR};
#   2. the skill body, references/, discovery/, docs/, templates/ and README.md never *run* one by a
#      relative path: an interpreter, `source` / `.`, `uv run`, `env …` or `cd` in front of it, a `test -d/-x`
#      on it, a copy of templates/poc, or a code span / code line that starts with a relative script and
#      passes it arguments. Prose that merely names a path ("a self-contained templates/poc crate", a
#      markdown link) is allowed there;
#   3. every site fixed so far keeps its rooted form (the PINS list);
#   4. every rooted path those files name exists in this checkout (binaries: declared in the crate);
#   5. Rule 11e and its pointers in SKILL.md / AGENTS.md / FULL-AUDIT.md are in place; 11a–11e keep their
#      headings.
# The detector is first run against known-good and known-bad lines, so a broken pattern fails the test.
# Usage (from the repo root): bash scripts/tests/test-bundled-paths.sh   (VERBOSE=1 lists every check)
# Needs bash >= 3.2, grep, sed, awk, find. No network.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 1
export LC_ALL=C
pass=0; failn=0
ok()  { pass=$((pass + 1)); if [ -n "${VERBOSE:-}" ]; then echo "ok   $*"; fi; }
bad() { failn=$((failn + 1)); echo "FAIL $*"; }

STRICT_FILES=$(ls commands/*.md agents/*.md)
RUN_FILES=$(ls SKILL.md FULL-AUDIT.md AGENTS.md OUTPUT-RULES.md README.md; find references discovery docs templates -name '*.md' | sort)

# A bundled path preceded by start of line or a non-path character, after any ./ or ../ prefix.
PRE='(^|[^A-Za-z0-9_./}>-])(\.\.?/)*'
TOKENS="${PRE}(tools/auditor-tools|vendor/trailofbits|templates/poc)"
BIN_REL="${PRE}tools/auditor-tools/target/"
PLUGINS_REL="${PRE}vendor/trailofbits/plugins"
TEST_REL='(test|\[)[[:space:]]+-[a-z][[:space:]]+"?(\.\.?/)*(vendor/trailofbits|tools/auditor-tools|templates/poc|scripts/)'
CP_REL='(^|[^A-Za-z0-9_-])(cp|rsync)[[:space:]][^|;&]*[[:space:]]"?(\.\.?/)*templates/poc'
CD_REL='(^|[^A-Za-z0-9_-])cd[[:space:]]+"?(\.\.?/)*(tools/auditor-tools|vendor/trailofbits|templates/poc|scripts)([/"[:space:]&;|)]|$)'
# An interpreter (options and VAR=value allowed in between) handed a relative scripts/ path.
RUNNER='(bash|sh|zsh|source|\.|python3?|uv[[:space:]]+run|node|perl|env)'
OPTS='([[:space:]]+(-[^[:space:]`]*|[A-Za-z_][A-Za-z0-9_]*=[^[:space:]`]*))*'
SCRIPT_RUN="(^|[^A-Za-z0-9_./-])${RUNNER}${OPTS}[[:space:]]+\"?(\\.\\.?/)*scripts/"
SCRIPT_SPAN='`(\.\.?/)*scripts/[^`[:space:]]*\.(sh|py)'
SPAN_ARGS='`(\.\.?/)*scripts/[^`[:space:]]+[[:space:]]+[^`]*`'
LINE_SCRIPT='^[[:space:]>]*"?(\.\.?/)*scripts/[^[:space:]"`]+\.(sh|py|js|mjs|ts|pl|rb)([[:space:]"]|$)'
DOT_SCRIPT='(^|[^A-Za-z0-9_./-])\.\.?/scripts/'
SKILL_DIR_VAR='[$][{]CLAUDE_SKILL_DIR[}]'

# Replace the rooted forms each kind of file may use, and markdown link targets (navigation, never a
# command), so only relative spellings are left to match.
strip_rooted() { # strip_rooted strict|run  (stdin -> stdout, same line count)
  if [ "$1" = strict ]; then
    sed -E -e 's#\]\([^)]*\)#]()#g' -e 's#[$][{]CLAUDE_PLUGIN_ROOT[}]/[A-Za-z0-9_./-]*#@ROOT@#g'
  else
    sed -E -e 's#\]\([^)]*\)#]()#g' \
      -e 's#([$][{]CLAUDE_(PLUGIN_ROOT|SKILL_DIR)[}]|<auditor-skill root>)/[A-Za-z0-9_./-]*#@ROOT@#g'
  fi
}
offending_lines() { # offending_lines strict|run  (stdin -> numbers of offending lines)
  if [ "$1" = strict ]; then
    strip_rooted strict | grep -nE -e "$TOKENS" -e "$SCRIPT_RUN" -e "$SCRIPT_SPAN" -e "$DOT_SCRIPT" \
      -e "$CD_REL" -e "$SKILL_DIR_VAR" | cut -d: -f1
  else
    strip_rooted run | grep -nE -e "$TEST_REL" -e "$BIN_REL" -e "$PLUGINS_REL" -e "$CP_REL" -e "$CD_REL" \
      -e "$SCRIPT_RUN" -e "$SPAN_ARGS" -e "$LINE_SCRIPT" -e "$DOT_SCRIPT" | cut -d: -f1
  fi
}

# ---- 0. the detector itself -------------------------------------------------------------------------
expect_flag() { # expect_flag strict|run yes|no LINE
  local got=no
  [ -n "$(printf '%s\n' "$3" | offending_lines "$1")" ] && got=yes
  if [ "$got" = "$2" ]; then ok "detector ($1) flagged=$2: $3"; else bad "detector ($1) flagged=$got, want $2: $3"; fi
}
for line in \
  'If `tools/auditor-tools` is built, run it.' \
  'run `test -x tools/auditor-tools/target/release/audit-mem` first' \
  'run ./tools/auditor-tools/target/release/audit-scan src' \
  'When `vendor/trailofbits/plugins` is present' \
  'Copy the harness from `templates/poc/` and fill it' \
  '`bash scripts/dnr/profile.sh` corpus.jsonl' \
  'python3 -I scripts/dnr/frames.py corpus.jsonl' \
  'Then run `uv run scripts/threat-model/extra.py --repo .`.' \
  'First `source scripts/tob-env.sh`.' \
  'then `./scripts/report-to-pdf.sh audit_1/REPORT.md`' \
  'then `scripts/report-to-pdf.sh audit_1/REPORT.md`' \
  'allowed-tools: Read, Bash(bash scripts/threat-model/collect.sh *)' \
  'run `"${CLAUDE_SKILL_DIR}/scripts/report-to-pdf.sh"`'; do
  expect_flag strict yes "$line"
done
for line in \
  'run `"${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-mem" check`' \
  'present (`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`)' \
  'copy from `"${CLAUDE_PLUGIN_ROOT}/templates/poc/"` and fill it' \
  '`bash "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/profile.sh" corpus.jsonl`' \
  '`python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/dnr/<name>.py"`' \
  'never a `scripts/…`, `tools/…` or `vendor/…` path relative to the working directory' \
  'never a relative `templates/` path' \
  'see [references/orchestration/poc-harness.md](../references/orchestration/poc-harness.md)'; do
  expect_flag strict no "$line"
done
for line in \
  'test -d vendor/trailofbits/plugins && echo present' \
  '[ -x tools/auditor-tools/target/release/audit-mem ] && echo built' \
  '"tools/auditor-tools/target/release/audit-scan" src --out prescan.json' \
  'bash scripts/threat-model/collect.sh --repo x --out y --detect' \
  'First `source scripts/tob-env.sh`.' \
  '. ./scripts/env.sh' \
  'uv run --no-project scripts/merge.py a b' \
  'env FOO=1 scripts/run.sh' \
  'node scripts/build.mjs' \
  'perl -w scripts/x.pl' \
  'Run `scripts/threat-model/collect.sh --repo . --offline` first.' \
  '  scripts/report-to-pdf.sh audit_1/REPORT.md   # writes REPORT.pdf' \
  'Run `cd tools/auditor-tools && cargo build --release` now.' \
  'cd templates/poc && ./run.sh' \
  'cp -R templates/poc audit_1/poc/F-001' \
  '| Capability | ToB plugin (`vendor/trailofbits/plugins/…`) |'; do
  expect_flag run yes "$line"
done
for line in \
  'test -d "<auditor-skill root>/vendor/trailofbits/plugins" && echo present' \
  '"<auditor-skill root>/tools/auditor-tools/target/release/audit-scan" src' \
  'cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release' \
  'PDF via `"${CLAUDE_SKILL_DIR}/scripts/report-to-pdf.sh"`' \
  'Optional PDF via `scripts/report-to-pdf.sh` (pandoc-gated)' \
  'a self-contained `templates/poc` crate is exempt' \
  'The bundled `scripts/threat-model/collect.sh`, run from the installation' \
  'If `tools/auditor-tools/` is built' \
  '- **Recipes:** [`scripts/dnr/`](../scripts/dnr/) — profiling' \
  'git submodule update --init --depth 1 -- vendor/trailofbits' \
  'grep -rn "clippy" .github/ Makefile* scripts/ --include="*.yml"' \
  'the semgrep skill runs `{baseDir}/scripts/run-scans.sh`' \
  'each node in scripts/ is listed'; do
  expect_flag run no "$line"
done

# ---- 1 + 2. the corpus -------------------------------------------------------------------------------
scan() { # scan strict|run FILES...
  local mode=$1 f n why; shift
  why='bundled executable run by a path relative to the working directory'
  [ "$mode" = strict ] && why='bundled path not written from ${CLAUDE_PLUGIN_ROOT}'
  for f in "$@"; do
    [ -f "$f" ] || { bad "$f: listed for the $mode scan but missing"; continue; }
    n=$(offending_lines "$mode" < "$f")
    if [ -z "$n" ]; then ok "$f: no relative bundled path ($mode)"; continue; fi
    for n in $n; do bad "$f:$n: $why: $(sed -n "${n}p" "$f" | cut -c1-160)"; done
  done
}
scan strict $STRICT_FILES
scan run $RUN_FILES

# ---- 3. pinned sites ------------------------------------------------------------------------------------
# file <TAB> text that must stay in it: each site fixed so far, in its rooted form.
while IFS='	' read -r f want; do
  [ -n "$f" ] || continue
  if grep -qF -- "$want" "$f" 2>/dev/null; then ok "pin $f: $want"; else bad "pin $f lost its rooted form: $want"; fi
done <<'PINS'
SKILL.md	"${CLAUDE_SKILL_DIR}/scripts/report-to-pdf.sh"
FULL-AUDIT.md	`test -x "<auditor-skill root>/tools/auditor-tools/target/release/audit-scan"`
FULL-AUDIT.md	`"<auditor-skill root>/tools/auditor-tools/target/release/audit-scan" <program-path>
FULL-AUDIT.md	`"<auditor-skill root>/tools/auditor-tools/target/release/audit-mem" warm
commands/audit.md	`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`
commands/quick-scan.md	`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`
commands/audit-assist.md	`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`
commands/audit-cycle.md	`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`
commands/audit-cycle.md	`"${CLAUDE_PLUGIN_ROOT}/scripts/report-to-pdf.sh" audit_<n>/REPORT.md`
commands/triage.md	`test -x "${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-mem"`
commands/triage.md	`"${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-mem" check
commands/triage.md	`"${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-mem" regressions
commands/triage.md	`"${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-mem" put-finding
commands/intake.md	`"${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-mem" warm
commands/threat-model.md	`"${CLAUDE_PLUGIN_ROOT}/tools/auditor-tools/target/release/audit-mem" warm
commands/threat-model.md	bash "${CLAUDE_PLUGIN_ROOT}/scripts/threat-model/collect.sh" --repo <target> --out audit_<n>/bootstrap --pin <sha from intake> --offline
commands/poc.md	`"${CLAUDE_PLUGIN_ROOT}/templates/poc/"`
agents/poc-engineer.md	`"${CLAUDE_PLUGIN_ROOT}/templates/poc/"`
agents/poc-engineer.md	`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`
agents/peer-reviewer.md	`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`
agents/vuln-hunter.md	`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`
agents/patch-engineer.md	`test -d "${CLAUDE_PLUGIN_ROOT}/vendor/trailofbits/plugins"`
references/orchestration/boundary-map.md	test -d "<auditor-skill root>/vendor/trailofbits/plugins" && echo present
references/orchestration/boundary-map.md	`<auditor-skill root>/vendor/trailofbits/plugins/<plugin>/`
references/orchestration/pre-scan.md	cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release
references/orchestration/poc-harness.md	`<auditor-skill root>/templates/poc/`
references/audit-lifecycle/methodology.md	`<auditor-skill root>/vendor/trailofbits/plugins`
docs/getting-started.md	cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release
docs/getting-started.md	git clone https://github.com/solanabr/auditor-skill.git ~/.claude/skills/auditor-skill
docs/power-tools.md	cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release
docs/power-tools.md	"<auditor-skill root>/tools/auditor-tools/target/release/audit-scan" ./programs/
docs/power-tools.md	test -d "<auditor-skill root>/vendor/trailofbits/plugins" && echo present
docs/poc-and-patches.md	`<auditor-skill root>/templates/poc/`
README.md	cd "<auditor-skill root>/tools/auditor-tools" && cargo build --release
README.md	"<auditor-skill root>/scripts/report-to-pdf.sh" audit_1/REPORT.md
README.md	./auditor-skill/install.sh ~/.claude/skills/auditor-skill
README.md	Read ~/.claude/skills/auditor-skill/SKILL.md
README.md	Read the auditor-skill files in ~/.claude/skills/auditor-skill/
OUTPUT-RULES.md	In a vendored Trail of Bits skill, `{baseDir}` and every relative path
OUTPUT-RULES.md	The installation never sits inside the repository under audit
scripts/threat-model/collect.sh	bash "${CLAUDE_PLUGIN_ROOT}/scripts/threat-model/collect.sh" --repo
scripts/report-to-pdf.sh	"${CLAUDE_PLUGIN_ROOT}/scripts/report-to-pdf.sh" [path/to/REPORT.md]
PINS

# ---- 4. every rooted path names something that ships --------------------------------------------------
bins=$(awk '/^\[\[bin\]\]/ { b = 1; next } b && /^name *=/ { gsub(/.*= *"|".*/, ""); print; b = 0 }' \
  tools/auditor-tools/Cargo.toml)
[ -n "$bins" ] && ok "crate binaries: $(echo $bins)" || bad "no [[bin]] names in tools/auditor-tools/Cargo.toml"
for p in $(grep -ohE '([$][{]CLAUDE_(PLUGIN_ROOT|SKILL_DIR)[}]|<auditor-skill root>)/[A-Za-z0-9_./-]*' \
    $STRICT_FILES $RUN_FILES | sed -E 's#^[^/]*/##; s#\.+$##' | sort -u); do
  case "$p" in
    tools/auditor-tools/target/release/?*)
      b=${p#tools/auditor-tools/target/release/}; b=${b%%/*}
      case " $(echo $bins) " in *" $b "*) ok "rooted binary $p" ;; *) bad "rooted path $p: '$b' is not a binary of tools/auditor-tools" ;; esac ;;
    tools/auditor-tools/target | tools/auditor-tools/target/ | tools/auditor-tools/target/release | tools/auditor-tools/target/release/)
      ok "rooted build-output path $p (created by cargo build)" ;;
    vendor/trailofbits | vendor/trailofbits/ | vendor/trailofbits/plugins | vendor/trailofbits/plugins/*)
      ok "rooted plugin path $p" ;;
    vendor/*) bad "rooted path $p is not under vendor/trailofbits/plugins" ;;
    *) if [ -e "$p" ]; then ok "rooted path $p exists"; else bad "rooted path $p does not exist in this checkout"; fi ;;
  esac
done

# ---- 5. the rule and its pointers ---------------------------------------------------------------------
for h in '### 11a — Execution mode' '### 11b — Outside-service disclosure' '### 11c — Untrusted git checkouts' \
         '### 11d — Output hygiene' '### 11e — Bundled paths'; do
  if grep -qxF -- "$h" OUTPUT-RULES.md; then ok "OUTPUT-RULES.md has '$h'"; else bad "OUTPUT-RULES.md lost the heading '$h'"; fi
done
for f in SKILL.md AGENTS.md FULL-AUDIT.md; do
  if grep -qF 'Rule 11e' "$f"; then ok "$f points to Rule 11e"; else bad "$f does not state the bundled-path rule (Rule 11e)"; fi
done
if grep -qF '${CLAUDE_SKILL_DIR}' SKILL.md; then ok "SKILL.md names its root as \${CLAUDE_SKILL_DIR}"
else bad "SKILL.md does not name its root as \${CLAUDE_SKILL_DIR}"; fi

echo "---- bundled paths: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
