#!/usr/bin/env bash
# test-threat-model.sh — self-test for scripts/threat-model/collect.sh.
# Builds throwaway git fixtures under ${TMPDIR:-/tmp}; needs git and awk, optionally jq / python3 /
# pdftotext (cases that need a missing tool are skipped, never failed). No network.
# Usage (from the repo root): bash scripts/tests/test-threat-model.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
COLLECT="$ROOT/scripts/threat-model/collect.sh"
T=$(mktemp -d "${TMPDIR:-/tmp}/tm-test.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT

# Isolate git from the caller's configuration (signing, hooks, templates).
export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_CEILING_DIRECTORIES="$T"
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
mkdir -p "$HOME"

pass=0 fail=0 skip=0
ok()   { pass=$((pass + 1)); echo "ok   - $1"; }
ko()   { fail=$((fail + 1)); echo "FAIL - $1"; }
skp()  { skip=$((skip + 1)); echo "skip - $1"; }
check() { if "${@:2}"; then ok "$1"; else ko "$1"; fi; }
has()   { grep -qF -- "$2" "$1"; }
hasnt() { ! grep -qF -- "$2" "$1"; }
section_of() { # section_of <history.md> <heading prefix> -> that section's text
  awk -v h="## $2" 'index($0, h) == 1 { p = 1; next } /^## / { p = 0 } p' "$1"
}

mkrepo() { git init -q "$1" && git -C "$1" symbolic-ref HEAD refs/heads/main; }
put()    { mkdir -p "$(dirname "$1/$2")" && printf '%s\n' "$3" > "$1/$2" && git -C "$1" add -- "$2"; }
commit() { git -C "$1" commit -q "${@:2}"; }
short()  { git -C "$1" rev-parse --short=7 "$2"; }
collect() { bash "$COLLECT" "$@" 2>"$T/stderr.log"; }

# =================================================================================================
# Target fixture: guard edits, attribute anchoring, quiet fix, whole-message keyword, revert.
# =================================================================================================
TGT="$T/tgt"; mkrepo "$TGT"
LIB=programs/demo/src/lib.rs
put "$TGT" "$LIB" '#[derive(Accounts)]
pub struct Withdraw<'"'"'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'"'"'info, Vault>,
    pub authority: Signer<'"'"'info>,
}'
commit "$TGT" -m "initial import"

# T-b: has_one retargeted from authority to payer (-S would miss it: the count of has_one is unchanged).
put "$TGT" "$LIB" '#[derive(Accounts)]
pub struct Withdraw<'"'"'info> {
    #[account(mut, has_one = payer)]
    pub vault: Account<'"'"'info, Vault>,
    pub payer: Signer<'"'"'info>,
}'
commit "$TGT" -m "Rework withdraw accounts"
C_RETARGET=$(short "$TGT" HEAD)

# T-d: attribute-position constraints versus variable names, added then removed.
put "$TGT" programs/demo/src/close.rs '#[derive(Accounts)]
pub struct Close<'"'"'info> {
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump,
	address = crate::admin::ID,
        close = receiver
    )]
    pub vault: Account<'"'"'info, Vault>,
}
pub fn helper(ctx: Ctx, new_owner: Pubkey) {
    let bump = ctx.bumps.vault;
    owner = new_owner;
}'
commit "$TGT" -m "Add close accounts"
put "$TGT" programs/demo/src/close.rs '// close moved elsewhere'
commit "$TGT" -m "Simplify close"
C_CLOSE=$(short "$TGT" HEAD)

# T-f (quiet fix): a small commit, no keyword, adds a guard.
put "$TGT" programs/demo/src/deposit.rs 'pub fn deposit(amount: u64) -> Result<()> {
    require!(amount > 0, DemoError::ZeroAmount);
    Ok(())
}'
commit "$TGT" -m "Tidy deposit"
C_QUIET=$(short "$TGT" HEAD)

# T-f (whole-message keyword): a large commit whose subject has no keyword but whose body does.
BIG=""; i=0; while [ $i -lt 60 ]; do BIG="$BIG// filler line $i"$'\n'; i=$((i + 1)); done
put "$TGT" programs/demo/src/layout.rs "${BIG}pub fn route(a: Pubkey, b: Pubkey) -> Result<()> {
    require_keys_eq!(a, b);
    Ok(())
}"
commit "$TGT" -m "Tidy module layout" -m "This also fixes a missing signer check on route."
C_BODYKW=$(short "$TGT" HEAD)
git -C "$TGT" revert --no-edit HEAD >/dev/null 2>&1
C_REVERT=$(short "$TGT" HEAD)

OUT1="$T/run1/audit_1/bootstrap"
collect --repo "$TGT" --out "$OUT1" --offline
H1="$OUT1/history.md"
check "collector exits 0 and writes history.md" test -s "$H1"
R3="$T/r3.txt"; section_of "$H1" "R3" > "$R3"
check "T-b: retargeted has_one prints the old text as REMOVED with its file path" \
  has "$R3" "$C_RETARGET"
check "T-b: REMOVED row names programs/demo/src/lib.rs and the authority constraint" \
  has "$R3" "REMOVED x1 programs/demo/src/lib.rs: #[account(mut, has_one = authority)]"
check "T-d: attribute-position bump is reported" has "$R3" "REMOVED x1 programs/demo/src/close.rs: bump = vault.bump,"
check "T-d: attribute-position close is reported" has "$R3" "close.rs: close = receiver"
check "T-d: a tab-indented attribute constraint is reported" has "$R3" "close.rs: address = crate::admin::ID,"
check "T-d: a let binding named bump is not reported" hasnt "$R3" "let bump = ctx.bumps.vault;"
check "T-d: an assignment statement to owner is not reported" hasnt "$R3" "owner = new_owner;"
check "T-f: small keyword-free guard addition is ADDED-QUIET" \
  has "$R3" "$C_QUIET $(git -C "$TGT" log -1 --format=%ad --date=short "$C_QUIET") ADDED-QUIET x1 programs/demo/src/deposit.rs: require!(amount > 0, DemoError::ZeroAmount);"
check "T-f: keyword in the message body (not the subject) marks the commit ADDED" \
  has "$R3" "$C_BODYKW $(git -C "$TGT" log -1 --format=%ad --date=short "$C_BODYKW") ADDED x1 programs/demo/src/layout.rs: require_keys_eq!(a, b);"
check "T-f: the body-keyword commit is listed in R1" sh -c "awk '/^## R1/,/^## R2/' '$H1' | grep -q '^$C_BODYKW '"
OUTC="$T/runc/audit_1/bootstrap"
collect --repo "$TGT" --out "$OUTC" --offline --fix-ceiling 10
check "--fix-ceiling: a keyword commit above the ceiling yields no ADDED row" \
  sh -c "! awk '/^## R3/,/^## R4/' '$OUTC/history.md' | grep -q '^$C_BODYKW .* ADDED x'"
check "--fix-ceiling: its R1 entry and REMOVED rows are unaffected" sh -c "awk '/^## R1/,/^## R2/' '$OUTC/history.md' | grep -q '^$C_BODYKW '"
check "T-h: R2 lists the revert and the commit it reverts" \
  sh -c "awk '/^## R2/,/^## R3/' '$H1' | grep -q '^$C_REVERT .*-> reverts $(git -C "$TGT" rev-parse --short=10 "$C_BODYKW")'"
check "R2/R5: an empty section prints NOT FOUND" sh -c "awk '/^## R5/,/^## R6/' '$H1' | grep -q 'NOT FOUND (no --parent given'"
check "files named in rows are under the default programs/ pathspec" has "$H1" '| Target paths | `programs/*.rs` |'
check "a diff is saved for each REMOVED commit" test -s "$OUT1/diffs/target-$C_CLOSE.diff"

OUTP="$T/runp/audit_1/bootstrap"
collect --repo "$TGT" --out "$OUTP" --offline --pin "$C_RETARGET" --paths 'programs/demo/src/lib.rs' --program-id Demo1111
check "--pin: commits after the pinned commit are not mined" sh -c "! grep -q '^$C_BODYKW ' '$OUTP/history.md'"
check "--pin: the pinned commit is recorded in full" has "$OUTP/history.md" "| Pinned commit | \`$(git -C "$TGT" rev-parse "$C_RETARGET")\` |"
check "--paths: rows stay inside the given pathspec" sh -c "! grep -q 'close.rs' '$OUTP/history.md'"
check "--program-id without the built tool says so" sh -c "grep -q 'NOT FOUND (tools/auditor-tools is not built)' '$OUTP/history.md' || grep -q 'NOT FOUND (no database at' '$OUTP/history.md'"

OUT2="$T/run2/audit_1/bootstrap"
collect --repo "$TGT" --out "$OUT2" --offline --cap 1
check "TRUNCATED (+n) is printed when a section exceeds --cap" \
  sh -c "awk '/^## R4/,/^## R5/' '$OUT2/history.md' | grep -qE '^TRUNCATED \(\+[0-9]+ more rows'"

# =================================================================================================
# Parent and forks: twin-guard hint (T-c), parent-only refs (T-a), shared history and blob identity.
# =================================================================================================
PAR="$T/par"; mkrepo "$PAR"
AMM=programs/amm/src/lib.rs
AMM_P1='pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    require_keys_eq!(ctx.accounts.vault.key(), pool.vault);
    Ok(())
}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    Ok(())
}'
put "$PAR" "$AMM" "$AMM_P1"
commit "$PAR" -m "amm v1"
P1=$(short "$PAR" HEAD)

FORKH="$T/fork-hist"
git clone -q "$PAR" "$FORKH"
put "$FORKH" programs/amm/src/extra.rs '// fork-specific module'
commit "$FORKH" -m "fork: add extra module"

FORKI="$T/fork-import"; mkrepo "$FORKI"
put "$FORKI" "$AMM" "$AMM_P1"
commit "$FORKI" -m "initial import of upstream amm"
put "$FORKI" programs/amm/src/extra.rs '// fork-specific module'
commit "$FORKI" -m "fork: add extra module"

# Parent fix after the fork: same guard text in withdraw as already in deposit (twin), plus a new guard.
put "$PAR" "$AMM" 'pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    require_keys_eq!(ctx.accounts.vault.key(), pool.vault);
    Ok(())
}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require_keys_eq!(ctx.accounts.vault.key(), pool.vault);
    require!(amount > 0, AmmError::ZeroAmount);
    Ok(())
}'
commit "$PAR" -m "fix: bind vault in withdraw (security)"
P2=$(short "$PAR" HEAD)
# T-a: the fork tracks upstream, so the parent's fix sits in refs/remotes/upstream/main, outside HEAD.
git -C "$FORKH" fetch -q "$PAR" main:refs/remotes/upstream/main

OUT3="$T/run3/audit_1/bootstrap"
collect --repo "$FORKH" --out "$OUT3" --parent "$PAR"
H3="$OUT3/history.md"
check "T-a: a parent-only commit reachable from another ref is not target history (R1)" \
  sh -c "! awk '/^## R1/,/^## R2/' '$H3' | grep -q '^$P2 '"
check "T-a: nor in R3" sh -c "! awk '/^## R3/,/^## R4/' '$H3' | grep -q '^$P2 '"
check "R5a: fork point found through shared history" \
  sh -c "grep -q '^fork point: $P1 .* shared history' '$H3'"
check "R5c: the parent's keyword commit after the fork point is listed" \
  sh -c "awk '/R5c parent commits/,/R5d guard lines/' '$H3' | grep -q '^$P2 '"
check "T-c: a twin guard is a hint ('present elsewhere'), never CARRIED" \
  sh -c "grep -q 'require_keys_eq!(ctx.accounts.vault.key(), pool.vault);.*\[text present elsewhere in target - verify\]' '$H3'"
check "T-c: the word CARRIED appears nowhere" hasnt "$H3" "CARRIED"
check "R5d: a guard the fork lacks is flagged absent" \
  sh -c "grep -q 'require!(amount > 0, AmmError::ZeroAmount);.*\[text absent from target @ pin - verify\]' '$H3'"
check "R5d: the parent diff behind an absent guard is saved" test -s "$OUT3/diffs/parent-$P2.diff"
check "R5d: absent rows come before present-elsewhere rows" \
  sh -c "awk '/R5d guard lines/,/^\`\`\`\$/' '$H3' | grep -n 'verify\]' | head -1 | grep -q 'text absent'"
# Output-shaping git settings must not change the result, whether the target or the auditor sets them.
git -C "$FORKH" config grep.lineNumber true; git -C "$FORKH" config grep.column true
git -C "$FORKH" config color.ui always; git -C "$FORKH" config color.grep always
mkdir -p "$T/home-cfg"; printf '[grep]\n\tlineNumber = true\n[color]\n\tui = always\n' > "$T/home-cfg/.gitconfig"
OUT3B="$T/run3b/audit_1/bootstrap"
HOME="$T/home-cfg" collect --repo "$FORKH" --out "$OUT3B" --parent "$PAR"
check "grep/colour config (target + ~/.gitconfig): the twin guard is still present elsewhere" \
  sh -c "grep -q 'require_keys_eq!(ctx.accounts.vault.key(), pool.vault);.*\[text present elsewhere in target - verify\]' '$OUT3B/history.md'"
check "grep/colour config: no escape sequences reach history.md" sh -c "! grep -q \"\$(printf '\\033')\" '$OUT3B/history.md'"

OUT4="$T/run4/audit_1/bootstrap"
collect --repo "$FORKI" --out "$OUT4" --parent "$PAR"
check "R5b: fork point found through blob identity for a history-less import" \
  sh -c "grep -q '^fork point: $P1 .* blob identity: 1 of 1 import blobs' '$OUT4/history.md'"

# =================================================================================================
# T-g: hostile .git/config and attributes. Nothing configured by the target may execute.
# =================================================================================================
HOS="$T/hostile"; mkrepo "$HOS"; mkdir -p "$T/bin" "$T/marks"
for m in textconv extdiff external fsmonitor gpg pager pagerlog; do
  printf '#!/bin/sh\ntouch "%s/marks/%s"\n[ -n "$1" ] && [ -f "$1" ] && cat "$1"\nexit 0\n' "$T" "$m" > "$T/bin/mark-$m"
  chmod +x "$T/bin/mark-$m"
done
put "$HOS" .gitattributes '*.rs diff=evil'
put "$HOS" programs/h/src/lib.rs '#[account(mut, has_one = authority)]'
commit "$HOS" -m "initial"
put "$HOS" programs/h/src/lib.rs '#[account(mut)]'
commit "$HOS" -m "fix: drop has_one"
cat >> "$HOS/.git/config" <<EOF
[core]
	fsmonitor = $T/bin/mark-fsmonitor
	pager = $T/bin/mark-pager
[diff "evil"]
	textconv = $T/bin/mark-textconv
	command = $T/bin/mark-extdiff
[diff]
	external = $T/bin/mark-external
[log]
	showSignature = true
[gpg]
	program = $T/bin/mark-gpg
[pager]
	log = $T/bin/mark-pagerlog
EOF
# Sanity: the fixture really is hostile for plain git.
git -C "$HOS" log -p -1 >/dev/null 2>&1
if ls "$T/marks" | grep -qE 'textconv|extdiff|external'; then ok "T-g sanity: plain 'git log -p' runs the configured diff program"
else skp "T-g sanity: this git did not run the configured diff program"; fi
git -C "$HOS" status >/dev/null 2>&1
if [ -e "$T/marks/fsmonitor" ]; then ok "T-g sanity: plain 'git status' runs core.fsmonitor"
else skp "T-g sanity: this git did not run core.fsmonitor"; fi
rm -f "$T/marks"/*
OUT5="$T/run5/audit_1/bootstrap"
collect --repo "$HOS" --out "$OUT5" --offline --paths '*.rs'
check "T-g: collector still produces rows on the hostile repo" has "$OUT5/history.md" "REMOVED x1 programs/h/src/lib.rs: #[account(mut, has_one = authority)]"
check "T-g: no textconv, external diff, fsmonitor, gpg or pager program ran" \
  sh -c "[ -z \"\$(ls '$T/marks')\" ]"

# T-py: the collector runs python3 isolated and outside the target, so a target json.py never loads.
if command -v python3 >/dev/null 2>&1; then
  PYT="$T/pyhijack"; mkrepo "$PYT"
  put "$PYT" programs/x/src/lib.rs 'pub fn a() { require!(x, E::A); }'
  put "$PYT" json.py 'import os
open(os.environ.get("TM_TEST_MARK", "/dev/null"), "w").write("loaded")'
  commit "$PYT" -m "initial"
  mkdir -p "$PYT/incident_1"; printf '{"schema": "auditor-incidents/1", "incidents": [\n' > "$PYT/incident_1/INCIDENTS.json"
  (cd "$PYT" && TM_TEST_MARK="$T/marks/py-sanity" python3 -c 'import json' 2>/dev/null)
  if [ -e "$T/marks/py-sanity" ]; then ok "T-py sanity: plain python3 in the target imports its json.py"
  else skp "T-py sanity: this python3 did not import the target json.py"; fi
  for tool in default python3; do
    rm -f "$T/marks/py-hijack"
    (cd "$PYT" && TM_TEST_MARK="$T/marks/py-hijack" TM_JSON_TOOL=$([ "$tool" = default ] || echo python3) \
      bash "$COLLECT" --repo . --out audit_1/bootstrap --offline >/dev/null 2>&1)
    check "T-py ($tool): an invalid INCIDENTS.json falls through without running the target json.py" test ! -e "$T/marks/py-hijack"
  done
  check "T-py: the invalid incident file is recorded, not copied" has "$PYT/audit_1/bootstrap/inputs.tsv" "not copied: no working jq or python3 parsed it"
  rm -f "$T/marks"/*
else
  skp "T-py: needs python3"
fi

# =================================================================================================
# T-j: egress rules — https only, explicit only, nothing in --offline.
# =================================================================================================
rc() { bash "$COLLECT" "$@" >/dev/null 2>&1; echo $?; }
check "T-j: --parent http:// is rejected (exit 2)" test "$(rc --repo "$TGT" --out "$T/x/b" --parent http://example.invalid/p.git)" = 2
check "T-j: --parent scp-style host:path is rejected" test "$(rc --repo "$TGT" --out "$T/x/b" --parent git@example.invalid:o/p.git)" = 2
check "T-j: --parent ssh:// is rejected" test "$(rc --repo "$TGT" --out "$T/x/b" --parent ssh://example.invalid/p.git)" = 2
check "T-j: --vulns file:// is rejected" test "$(rc --repo "$TGT" --out "$T/x/b" --vulns file:///etc/hosts)" = 2
check "T-j: a non-repository target exits 3" test "$(rc --repo "$T/home" --out "$T/x/b")" = 3
# Large input: classify_source used to pipe the argument into grep -q, whose early exit under pipefail
# could turn "rejected" into "path". A long multi-line scp-style value must still be rejected.
LONG=$(i=0; while [ $i -lt 3000 ]; do printf 'padding-line-%s\n' "$i"; i=$((i + 1)); done)
check "large input: a long multi-line scp-style --parent is still rejected (exit 2)" \
  test "$(rc --repo "$TGT" --out "$T/x/b" --parent "git@example.invalid:o/p.git
$LONG")" = 2
OUT6="$T/run6/audit_1/bootstrap"
collect --repo "$TGT" --out "$OUT6" --offline --parent https://example.invalid/parent.git --vulns https://example.invalid/report.pdf
check "T-j: --offline records the parent URL without cloning" has "$OUT6/history.md" "given, not cloned (offline)"
check "T-j: --offline records a --vulns URL without fetching" has "$OUT6/inputs.tsv" "recorded, not fetched (offline)"

# =================================================================================================
# T-k: INCIDENTS.json allowlist (schema auditor-incidents/1) and other inputs.
# =================================================================================================
mkdir -p "$TGT/incident_1"
cat > "$TGT/incident_1/INCIDENTS.json" <<'EOF'
{"schema": "auditor-incidents/1",
 "incidents": [{"id": "INC-1.1", "verdict": "suspected", "outcome": "failed", "root_cause_class": "code_flaw",
   "urgency": "immediate-PRIVATE",
   "vuln": {"program": "Demo1111", "instruction": "withdraw", "file": "programs/demo/src/lib.rs",
            "function": "withdraw", "line": 3, "mechanism": "has_one retargeted", "severity": 9,
            "kv": ["KV-004", {"note": "DROP-ME-NESTED"}], "checklist": ["AC-001"], "operator_notes": "DROP-ME-NOTES"},
   "poc": {"tier": "PoC-REPRODUCED", "path": "incident_1/poc/DROP-ME-PATH", "verified": true},
   "attacker": {"address": "ATTACKER-PII-ADDR"}, "transactions": ["TX-PII-SIG"],
   "blast_radius": {"victims": ["VICTIM-PII"]}, "timeline": ["TIMELINE-PII"],
   "evidence": {"logs": "EVIDENCE-PII"}, "binary_provenance": "BINPROV-PII",
   "collection_gaps": ["GAPS-PII"], "response_plan": "RESPONSE-PII.md"}],
 "ruled_out": [{"subject": "RULED-OUT-PII", "verdict": "benign"}]}
EOF
printf '{"schema": "something-else/2", "rows": []}\n' > "$T/other.json"
printf 'id,title,component,description\nF-1,Missing signer,withdraw,authority not a signer\n' > "$T/findings.csv"
for tool in jq python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then skp "T-k ($tool): $tool not installed"; continue; fi
  OUT7="$T/run7-$tool/audit_1/bootstrap"
  TM_JSON_TOOL=$tool collect --repo "$TGT" --out "$OUT7" --offline --vulns "$T/other.json" --vulns "$T/findings.csv"
  EX="$OUT7/inputs/incident1-INCIDENTS.json"
  check "T-k ($tool): INCIDENTS.json is extracted to inputs/" test -s "$EX"
  check "T-k ($tool): the stable read surface survives" \
    sh -c "grep -q 'INC-1.1' '$EX' && grep -q 'suspected' '$EX' && grep -q 'failed' '$EX' && grep -q 'code_flaw' '$EX' && grep -q 'KV-004' '$EX' && grep -q 'AC-001' '$EX' && grep -q 'PoC-REPRODUCED' '$EX'"
  for bad in ATTACKER-PII-ADDR TX-PII-SIG VICTIM-PII TIMELINE-PII EVIDENCE-PII BINPROV-PII GAPS-PII RESPONSE-PII \
             RULED-OUT-PII DROP-ME-NESTED DROP-ME-NOTES DROP-ME-PATH immediate-PRIVATE '"severity"' '"verified"'; do
    check "T-k ($tool): $bad is not copied" hasnt "$EX" "$bad"
  done
  check "T-k ($tool): another schema is recorded, not silently dropped" has "$OUT7/inputs.tsv" 'skipped: schema "something-else/2"'
  check "T-k ($tool): a CSV findings list is copied" has "$OUT7/inputs.tsv" "copied (list)"
  check "T-k ($tool): incidents count as trigger T4" has "$OUT7/history.md" "T4 yes incidents-json"
done
# An old or broken jq (jq < 1.7 lacks builtins newer programs use) must hand over to python3, and with
# no working JSON tool nothing is copied at all.
mkdir -p "$T/oldjq"
printf '#!/bin/sh\necho "jq: error: simulated old jq" >&2\nexit 3\n' > "$T/oldjq/jq"; chmod +x "$T/oldjq/jq"
if command -v python3 >/dev/null 2>&1; then
  OUTJ="$T/run-oldjq/audit_1/bootstrap"
  PATH="$T/oldjq:$PATH" collect --repo "$TGT" --out "$OUTJ" --offline
  check "T-k (failing jq): python3 takes over the incident extraction" has "$OUTJ/inputs.tsv" "allowlisted fields extracted (python3)"
  check "T-k (failing jq): the extract still holds the verdict" has "$OUTJ/inputs/incident1-INCIDENTS.json" "suspected"
  check "T-k (failing jq): and still drops the attacker" hasnt "$OUTJ/inputs/incident1-INCIDENTS.json" "ATTACKER-PII-ADDR"
else
  skp "T-k (failing jq): needs python3"
fi
OUTN="$T/run-nojson/audit_1/bootstrap"
TM_JSON_TOOL=none collect --repo "$TGT" --out "$OUTN" --offline --vulns "$T/other.json"
check "T-k (no JSON tool): INCIDENTS.json is recorded, not copied" sh -c "! ls '$OUTN/inputs/' | grep -q INCIDENTS"
check "T-k (no JSON tool): other JSON is not copied either" has "$OUTN/inputs.tsv" "not copied: no working jq or python3 parsed it"
if command -v jq >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
  printf '[{"id": "F-1", "description": "authority not a signer"}]\n' > "$T/Incidents-Export.json"
  OUTI="$T/runi/audit_1/bootstrap"
  collect --repo "$TGT" --out "$OUTI" --offline --vulns "$T/Incidents-Export.json"
  check "a schema-less JSON whose name mentions incidents is not copied" \
    has "$OUTI/inputs.tsv" "not copied: could not confirm it is not an incident file"
else
  skp "incident-named JSON: needs jq or python3"
fi
rm -rf "$TGT/incident_1"

# =================================================================================================
# PDF input (needs python3 to build the fixture and pdftotext to convert it).
# =================================================================================================
if command -v python3 >/dev/null 2>&1 && command -v pdftotext >/dev/null 2>&1; then
  python3 - "$T/report.pdf" <<'PY'
import sys
text = "Finding F-07: missing signer check on withdraw"
objs = ["<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        None,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
stream = "BT /F1 12 Tf 72 720 Td (%s) Tj ET" % text
objs[3] = "<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream)
out, offs = "%PDF-1.4\n", []
for i, o in enumerate(objs, 1):
    offs.append(len(out)); out += "%d 0 obj\n%s\nendobj\n" % (i, o)
xref = len(out)
out += "xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + "".join("%010d 00000 n \n" % o for o in offs)
out += "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
open(sys.argv[1], "w").write(out)
PY
  OUT8="$T/run8/audit_1/bootstrap"
  collect --repo "$TGT" --out "$OUT8" --offline --vulns "$T/report.pdf"
  check "PDF: converted with pdftotext and recorded" has "$OUT8/inputs.tsv" "converted (pdftotext -layout)"
  check "PDF: the text is searchable" sh -c "grep -rq 'missing signer check' '$OUT8/inputs/'"
else
  skp "PDF: needs python3 and pdftotext"
fi

# =================================================================================================
# --detect: T3 and T4 offline, and it writes nothing.
# =================================================================================================
CLEAN="$T/clean"; mkrepo "$CLEAN"; put "$CLEAN" programs/c/src/lib.rs 'pub fn c() {}'; commit "$CLEAN" -m "initial"
collect --repo "$CLEAN" --out "$CLEAN/audit_1/bootstrap" --offline
collect --repo "$CLEAN" --out "$CLEAN/notaudit/bootstrap" --offline
check "Rule 11d: the target's git status stays clean after collection" test -z "$(git -C "$CLEAN" status --porcelain)"
check "Rule 11d: bootstrap/ and its audit_<n>/ parent carry a .gitignore" sh -c "[ -f '$CLEAN/audit_1/bootstrap/.gitignore' ] && [ -f '$CLEAN/audit_1/.gitignore' ]"
check "Rule 11d: a parent not named audit_* gets no .gitignore" test ! -e "$CLEAN/notaudit/.gitignore"

put "$TGT" README.md 'Example AMM, forked from the upstream reference pool.'
put "$TGT" audits/Firm-2025.md '# Firm review 2025 — F-1: withdraw authority not a signer'
commit "$TGT" -m "docs: readme and prior review"
mkdir -p "$TGT/audit_1"; printf '# prior report\n' > "$TGT/audit_1/REPORT.md"
D1=$(bash "$COLLECT" --repo "$TGT" --out "$TGT/audit_2/bootstrap" --detect 2>/dev/null)
check "--detect: T3 fires on a README fork phrase" sh -c "printf '%s\n' '$D1' | grep -q '^T3 yes readme-phrase'"
check "--detect: T4 fires on a prior audit_*/REPORT.md" sh -c "printf '%s\n' '$D1' | grep -q '^T4 yes prior-audit-dir'"
check "--detect: T4 fires on a report inside an audits/ directory" sh -c "printf '%s\n' '$D1' | grep -q '^T4 yes .*in-tree-report'"
check "--detect: writes nothing" test ! -e "$TGT/audit_2"
OUT9="$T/run9/audit_1/bootstrap"
collect --repo "$TGT" --out "$OUT9" --offline
check "an in-tree report is ingested from the pinned tree" has "$OUT9/inputs.tsv" "pinned tree: audits/Firm-2025.md"
D2=$(bash "$COLLECT" --repo "$TGT" --out "$TGT/audit_1/bootstrap" --detect 2>/dev/null)
check "--detect: the current audit dir is not a prior audit" sh -c "printf '%s\n' '$D2' | grep -q '^T4 yes in-tree-report$'"

# =================================================================================================
# Large inputs: under pipefail an early-exit reader (grep -q) can report the writer's SIGPIPE instead of
# the match. Every detection whose status matters must survive trees and configs far above a pipe buffer.
# =================================================================================================
BIGT="$T/bigtree"; mkrepo "$BIGT"; mkdir -p "$BIGT/docs"
i=0; while [ $i -lt 1500 ]; do
  printf '# page %s\n' "$i" > "$BIGT/docs/a-reasonably-long-documentation-page-name-number-$i.md"; i=$((i + 1))
done
git -C "$BIGT" add -- docs
put "$BIGT" audits/2025-firm-audit.md '# Firm review 2025 — F-1: withdraw authority not a signer'
put "$BIGT" programs/b/src/lib.rs 'pub fn b() {}'
commit "$BIGT" -m "docs and prior review"
DB=$(bash "$COLLECT" --repo "$BIGT" --out "$T/bigrun/audit_1/bootstrap" --detect 2>/dev/null)
check "large tree (1,500 Markdown files): T4 still finds the one report" sh -c "printf '%s\n' '$DB' | grep -q '^T4 yes in-tree-report'"
MR="$T/manyremotes"; mkrepo "$MR"
put "$MR" programs/m/src/lib.rs 'security_txt! { source_code: "https://github.com/example/own-repo" }'
commit "$MR" -m "initial"
{ printf '[remote "origin"]\n\turl = https://github.com/example/own-repo.git\n'
  i=0; while [ $i -lt 2000 ]; do
    printf '[remote "mirror%s"]\n\turl = https://mirror%s.example.invalid/some/long/path/to/repository-%s.git\n' "$i" "$i" "$i"; i=$((i + 1))
  done; } >> "$MR/.git/config"
DM=$(bash "$COLLECT" --repo "$MR" --out "$T/mrrun/audit_1/bootstrap" --detect 2>/dev/null)
check "2,000 remotes: a source_code matching the first remote does not fire T3" sh -c "printf '%s\n' '$DM' | grep -q '^T3 no none'"

echo
echo "threat-model collector tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
