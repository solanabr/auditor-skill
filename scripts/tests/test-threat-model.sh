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
collect --repo "$TGT" --out "$OUTP" --offline --pin "$C_RETARGET" --paths 'programs/demo/src/lib.rs' --program-id Demo1111 --audit-mem-db "$T/no-such-store.db"
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
# A fork whose first commit holds only a README: the code arrives in a later commit, named by --import.
FORKR="$T/fork-readme"; mkrepo "$FORKR"
put "$FORKR" README.md '# our fork'
commit "$FORKR" -m "Initial commit"
put "$FORKR" "$AMM" "$AMM_P1"
commit "$FORKR" -m "import upstream amm"
C_IMPORT=$(git -C "$FORKR" rev-parse HEAD)
OUT4R="$T/run4r/audit_1/bootstrap"
collect --repo "$FORKR" --out "$OUT4R" --parent "$PAR"
check "R5b: without --import, a README-only root commit leaves R5 NOT FOUND" \
  sh -c "awk '/^## R5/,/^## R6/' '$OUT4R/history.md' | grep -q '^NOT FOUND (no shared commit'"
OUT4I="$T/run4i/audit_1/bootstrap"
collect --repo "$FORKR" --out "$OUT4I" --parent "$PAR" --import "$C_IMPORT"
check "R5b: --import names the commit that brought the code in" \
  sh -c "grep -q '^fork point: $P1 .* blob identity: 1 of 1 import blobs' '$OUT4I/history.md'"
check "--import: a value that is not a commit is refused (exit 2)" \
  test "$(bash "$COLLECT" --repo "$FORKR" --out "$T/run4x/audit_1/bootstrap" --parent "$PAR" --import "--output=$T/import-written.txt" >/dev/null 2>&1; echo $?)" = 2
check "--import: ... and nothing is created" sh -c "[ ! -e '$T/import-written.txt' ] && [ ! -e '$T/run4x' ]"

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

# =================================================================================================
# T-o: diff output. Diffs run as text with the big-file, hunk-fusing and root-commit settings pinned, so
# neither the target's attributes nor its config can hide a guard change; R4 pins git's rust pattern.
# =================================================================================================
SH_BIG=""; i=0; while [ $i -lt 60 ]; do SH_BIG="$SH_BIG// filler line $i"$'\n'; i=$((i + 1)); done
for how in gitattributes info-attributes bigfile; do
  AT="$T/shape-$how"; mkrepo "$AT"
  put "$AT" programs/a/src/lib.rs '#[account(mut, has_one = authority)]'
  commit "$AT" -m "initial"
  put "$AT" programs/a/src/lib.rs '#[account(mut)]'
  commit "$AT" -m "Rework accounts"
  put "$AT" programs/a/src/big.rs "${SH_BIG}pub fn b() -> Result<()> { require!(x, E::B); Ok(()) }"
  commit "$AT" -m "Reorganise helpers"
  case "$how" in
    gitattributes)   put "$AT" .gitattributes '*.rs -diff'; commit "$AT" -m "attributes" ;;
    info-attributes) mkdir -p "$AT/.git/info"; printf '*.rs -diff\n' > "$AT/.git/info/attributes" ;;
    bigfile)         git -C "$AT" config core.bigFileThreshold 1 ;;
  esac
  OUTA="$T/shape-run-$how/audit_1/bootstrap"
  collect --repo "$AT" --out "$OUTA" --offline
  check "T-o ($how): the removed guard line is still reported" \
    has "$OUTA/history.md" "REMOVED x1 programs/a/src/lib.rs: #[account(mut, has_one = authority)]"
  check "T-o ($how): a 61-line commit is not taken for a quiet fix" hasnt "$OUTA/history.md" "ADDED-QUIET x1 programs/a/src/big.rs"
done
# A commit's size counts every file it changes in the pathspec, not only the file holding the guard.
SPLIT="$T/shape-split"; mkrepo "$SPLIT"
put "$SPLIT" programs/s/src/lib.rs 'pub fn s() {}'
commit "$SPLIT" -m "initial"
put "$SPLIT" programs/s/src/lib.rs 'pub fn s() -> Result<()> { require!(ok, E::S); Ok(()) }'
put "$SPLIT" programs/s/src/filler.rs "$SH_BIG"
commit "$SPLIT" -m "Reorganise modules"
collect --repo "$SPLIT" --out "$T/shape-run-split/audit_1/bootstrap" --offline
check "T-o: a 62-line commit over two files is not taken for a quiet fix" \
  hasnt "$T/shape-run-split/audit_1/bootstrap/history.md" "ADDED-QUIET x"
R4T="$T/shape-r4"; mkrepo "$R4T"
R4_BODY='impl Pool {
    pub fn alpha_guard(&self) -> u64 {
        let a = 1;
        a
    }
    pub fn beta_guard(&self) -> u64 {
        let b = 2;
        b
    }
}'
put "$R4T" programs/f/src/lib.rs "$R4_BODY"
commit "$R4T" -m "initial"
put "$R4T" programs/f/src/lib.rs "$(printf '%s\n' "$R4_BODY" | sed 's/= 1;/= 10;/; s/= 2;/= 20;/')"
commit "$R4T" -m "Tune constants"
git -C "$R4T" config diff.rust.xfuncname '^NO_MATCH$'
git -C "$R4T" config diff.interHunkContext 100
git -C "$R4T" config log.showRoot false
if git -C "$R4T" --attr-source="$(git -C "$R4T" hash-object -t tree /dev/null)" check-attr diff -- x.rs >/dev/null 2>&1; then
  R4_ATTR=" (and committed .gitattributes)"
  put "$R4T" .gitattributes '*.rs diff=other'; commit "$R4T" -m "attributes"
  git -C "$R4T" config diff.other.xfuncname '^NO_MATCH$'
else
  R4_ATTR=""; skp "T-o (R4): committed .gitattributes are ignored only where git has --attr-source"
fi
OUTR4="$T/shape-run-r4/audit_1/bootstrap"
collect --repo "$R4T" --out "$OUTR4" --offline
R4S="$T/r4s.txt"; section_of "$OUTR4/history.md" "R4" > "$R4S"
check "T-o (R4): both function names survive a redefined rust driver and fused hunks$R4_ATTR" \
  sh -c "grep -q ' alpha_guard\$' '$R4S' && grep -q ' beta_guard\$' '$R4S'"
check "T-o (R4): log.showRoot=false does not hide the root commit" grep -qE '^ *2 programs/f/src/lib.rs$' "$R4S"
check "T-o (R4): no note when every .rs file uses the pinned driver" hasnt "$R4S" "note:"
check "T-o: history.md says what is pinned and what is not" has "$OUTR4/history.md" "rust hunk-header pattern, pinned"
mkdir -p "$R4T/.git/info"; printf '*.rs diff=other\n' > "$R4T/.git/info/attributes"
OUTR4N="$T/shape-run-r4n/audit_1/bootstrap"
collect --repo "$R4T" --out "$OUTR4N" --offline
check "T-o (R4): .rs files that .git/info/attributes sends to another driver are counted in a note" \
  sh -c "awk '/^## R4/,/^## R5/' '$OUTR4N/history.md' | grep -q '^note: the target.s attributes send 1 .rs file'"
GR="$T/shape-grep"; mkrepo "$GR"
put "$GR" programs/g/src/lib.rs 'declare_id!("Demo1111111111111111111111111111111111111111");
security_txt! { source_code: "https://example.invalid/not-a-remote" }'
commit "$GR" -m "initial"
mkdir -p "$GR/.git/info"; printf '*.rs -diff\n' > "$GR/.git/info/attributes"
collect --repo "$GR" --out "$T/shape-run-grep/audit_1/bootstrap" --offline
check "T-o (grep): a Rust file the target marks binary is still searched (R6 declare_id!)" \
  has "$T/shape-run-grep/audit_1/bootstrap/history.md" 'declare_id!("Demo1111'
check "T-o (grep): ... and still reaches the T3 source_code check" \
  has "$T/shape-run-grep/audit_1/bootstrap/history.md" "T3 yes security_txt-source_code"

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
check "--help prints the whole header, exit statuses included" \
  sh -c "bash '$COLLECT' --help | grep -q 'Exit status:' && bash '$COLLECT' --help | grep -q 'promisor remote)'"
# --repo must be the top level of its own repository; a plain directory inside another one is refused.
mkdir -p "$TGT/not-a-repo"
check "T-j: a plain directory inside another repository exits 3" \
  test "$(rc --repo "$TGT/not-a-repo" --out "$T/x/b" --detect)" = 3
bash "$COLLECT" --repo "$TGT/not-a-repo" --out "$T/x/b" --detect >/dev/null 2>"$T/nested.err"
check "T-j: ... and says it is not the top level" has "$T/nested.err" "not a git repository (or not its top level)"
ln -s "$TGT" "$T/tgt-link"
check "T-j: a symbolic link to a repository's top level is accepted" \
  test "$(rc --repo "$T/tgt-link" --out "$T/x/b" --detect)" = 0
git clone -q --bare "$TGT" "$T/tgt-bare.git"
check "T-j: a bare repository is accepted" test "$(rc --repo "$T/tgt-bare.git" --out "$T/x/b" --detect)" = 0
rmdir "$TGT/not-a-repo"
OUTNP="$T/run-nested-parent/audit_1/bootstrap"
collect --repo "$FORKH" --out "$OUTNP" --offline --parent "$PAR/programs"
check "T-j: a local --parent inside another repository is not used" \
  has "$OUTNP/history.md" "NOT FOUND (parent $PAR/programs: not a git repository (or not its top level))"
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
# jq and python3 agree on a malformed file: an incidents value that is not an array yields an empty
# extract and a note, whichever tool runs.
for tool in jq python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then skp "T-k ($tool): $tool not installed"; continue; fi
  for kind in object string; do
    case "$kind" in
      object) body='{"a": {"id": "INC-NOT-ARRAY", "verdict": "suspected"}}' ;;
      string) body='"INC-NOT-ARRAY"' ;;
    esac
    printf '{"schema": "auditor-incidents/1", "incidents": %s}\n' "$body" > "$T/incidents-$kind.json"
    OUTK="$T/runk-$tool-$kind/audit_1/bootstrap"
    TM_JSON_TOOL=$tool collect --repo "$TGT" --out "$OUTK" --offline --vulns "$T/incidents-$kind.json"
    check "T-k ($tool): incidents given as $kind is recorded as malformed" \
      has "$OUTK/inputs.tsv" "malformed: incidents is $kind, not an array"
    check "T-k ($tool): ... with an empty extract" has "$OUTK/inputs/v1-incidents-$kind.json" '"incidents": []'
    check "T-k ($tool): ... that holds nothing from it" hasnt "$OUTK/inputs/v1-incidents-$kind.json" "INC-NOT-ARRAY"
  done
done

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
# A source_code string is compared as written, never expanded against the filesystem: "/*"-style
# patterns would otherwise stall on deep trees. Here the glob would expand to exactly the configured
# remote, so an expansion shows up as T3 not firing.
GL="$T/globsrc"; mkrepo "$GL"; mkdir -p "$T/globdir"; : > "$T/globdir/only-entry"
put "$GL" programs/g/src/lib.rs "security_txt! { source_code: \"$T/globdir/*\" }"
commit "$GL" -m "initial"
git -C "$GL" config remote.origin.url "$T/globdir/only-entry"
DG=$(bash "$COLLECT" --repo "$GL" --out "$T/globrun/audit_1/bootstrap" --detect 2>/dev/null)
check "T3: a source_code glob is compared as a string, not expanded" \
  sh -c "printf '%s\n' '$DG' | grep -q '^T3 yes security_txt-source_code'"

# =================================================================================================
# T-m: audit memory is read only from a store passed with --audit-mem-db; the collector never looks for
# one in the target tree on its own. A copy of the collector under a stand-in installation root runs a
# fake audit-mem that leaves a mark, so "not read" is observed directly whether or not the real tools
# are built.
# =================================================================================================
FAKE="$T/fakeskill"; FAKEBIN="$FAKE/tools/auditor-tools/target/release"
mkdir -p "$FAKE/scripts/threat-model" "$FAKEBIN" "$T/marks"
cp "$COLLECT" "$FAKE/scripts/threat-model/collect.sh"
printf '#!/bin/sh\necho "$*" >> "%s/marks/audit-mem"\necho "{}"\n' "$T" > "$FAKEBIN/audit-mem"; chmod +x "$FAKEBIN/audit-mem"
fake_collect() { rm -f "$T/marks/audit-mem"; bash "$FAKE/scripts/threat-model/collect.sh" "$@" --offline --program-id Demo1111 2>/dev/null; }
MEMT="$T/memtgt"; mkrepo "$MEMT"
put "$MEMT" programs/m/src/lib.rs 'pub fn a() {}'
commit "$MEMT" -m "initial"
mkdir -p "$MEMT/.audit-memory"; printf 'db\n' > "$MEMT/.audit-memory/audit.db"
fake_collect --repo "$MEMT" --out "$T/mem1/audit_1/bootstrap"
check "T-m: an untracked in-tree store is not read without --audit-mem-db" test ! -e "$T/marks/audit-mem"
check "T-m: ... no audit-mem-warm.json is saved" test ! -e "$T/mem1/audit_1/bootstrap/audit-mem-warm.json"
check "T-m: ... and R8 says no store was given" has "$T/mem1/audit_1/bootstrap/history.md" "NOT FOUND (no --audit-mem-db given"
fake_collect --repo "$MEMT" --out "$T/mem2/audit_1/bootstrap" --audit-mem-db "$MEMT/.audit-memory/audit.db"
check "T-m: --audit-mem-db reads the store it names" grep -qF -- "--db $MEMT/.audit-memory/audit.db" "$T/marks/audit-mem"
check "T-m: ... and saves audit-mem-warm.json" test -s "$T/mem2/audit_1/bootstrap/audit-mem-warm.json"
git -C "$MEMT" add -f -- .audit-memory/audit.db; commit "$MEMT" -m "add a findings store"
fake_collect --repo "$MEMT" --out "$T/mem3/audit_1/bootstrap"
check "T-m: a tracked in-tree store is not read without --audit-mem-db either" test ! -e "$T/marks/audit-mem"
printf 'db\n' > "$T/outside.db"
fake_collect --repo "$MEMT" --out "$T/mem4/audit_1/bootstrap" --audit-mem-db "$T/outside.db"
check "T-m: a store outside the tree passed with --audit-mem-db is read" grep -qF -- "--db $T/outside.db" "$T/marks/audit-mem"

# =================================================================================================
# T-n: the collector writes only into a run directory this audit made (Rule 11d): never through a
# symbolic link, never into one that holds a link, never into one git tracks.
# =================================================================================================
RD="$T/rundirs"; mkrepo "$RD"
put "$RD" programs/r/src/lib.rs 'pub fn a() { require!(x, E::A); }'
put "$RD" audit_3/REPORT.md '# shipped report'
commit "$RD" -m "initial"
mkdir -p "$T/elsewhere" "$T/plainrun" "$RD/audit_1" "$RD/audit_2/bootstrap"
ln -s "$T/elsewhere" "$T/plainrun/bootstrap"
ln -s "$T/elsewhere" "$RD/audit_1/bootstrap"
ln -s "$T/elsewhere/gitignore-target" "$RD/audit_2/bootstrap/.gitignore"
ln -s "$T/elsewhere" "$RD/audit_4"
check "T-n: a bootstrap dir that is a symbolic link is refused (exit 2)" \
  test "$(rc --repo "$RD" --out "$T/plainrun/bootstrap" --offline)" = 2
check "T-n: ... also when --out ends in a slash" test "$(rc --repo "$RD" --out "$T/plainrun/bootstrap/" --offline)" = 2
check "T-n: an audit_<n> that holds a linked bootstrap dir is refused (exit 2)" \
  test "$(rc --repo "$RD" --out "$RD/audit_1/bootstrap" --offline)" = 2
check "T-n: a bootstrap dir that holds a symbolic link is refused (exit 2)" \
  test "$(rc --repo "$RD" --out "$RD/audit_2/bootstrap" --offline)" = 2
check "T-n: an audit_<n> parent that is a symbolic link is refused (exit 2)" \
  test "$(rc --repo "$RD" --out "$RD/audit_4/bootstrap" --offline)" = 2
check "T-n: a . component cannot hide the audit_<n> parent (exit 2)" \
  test "$(rc --repo "$RD" --out "$RD/audit_4/./bootstrap" --offline)" = 2
check "T-n: nothing was written through any of the links" test -z "$(ls -A "$T/elsewhere")"
check "T-n: a tracked audit_<n> is refused (exit 2)" test "$(rc --repo "$RD" --out "$RD/audit_3/bootstrap" --offline)" = 2
check "T-n: ... nothing is created in it and git status stays clean" \
  sh -c "[ ! -e '$RD/audit_3/bootstrap' ] && [ -z \"\$(git -C '$RD' status --porcelain --untracked-files=no)\" ]"
if command -v jq >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
  inc() { printf '{"schema": "auditor-incidents/1", "incidents": [{"id": "%s", "verdict": "suspected"}]}\n' "$1"; }
  mkdir -p "$RD/incident_6" "$RD/incident_7" "$T/elsewhere-inc/dir"
  inc INC-RUN-OK > "$RD/incident_6/INCIDENTS.json"
  inc INC-LINKED-FILE > "$T/elsewhere-inc/file.json"; ln -s "$T/elsewhere-inc/file.json" "$RD/incident_7/INCIDENTS.json"
  inc INC-LINKED-DIR > "$T/elsewhere-inc/dir/INCIDENTS.json"; ln -s "$T/elsewhere-inc/dir" "$RD/incident_8"
  put "$RD" incident_9/INCIDENTS.json "$(inc INC-TRACKED)"; commit "$RD" -m "ship an incident file"
  mkdir -p "$RD/audit_5"; printf '# intake\n' > "$RD/audit_5/intake.md"
  collect --repo "$RD" --out "$RD/audit_5/bootstrap" --offline
  check "T-n: an untracked audit_<n> without links is reused" test -s "$RD/audit_5/bootstrap/history.md"
  check "T-n: an incident file written in place is still extracted" sh -c "grep -rq 'INC-RUN-OK' '$RD/audit_5/bootstrap/inputs/'"
  for bad in INC-LINKED-FILE INC-LINKED-DIR INC-TRACKED; do
    check "T-n: $bad is not read" sh -c "! grep -rq '$bad' '$RD/audit_5/bootstrap/inputs/'"
  done
  check "T-n: inputs.tsv records the linked incident file as skipped" \
    sh -c "grep -F 'incident_7/INCIDENTS.json' '$RD/audit_5/bootstrap/inputs.tsv' | grep -q 'skipped: symbolic link'"
  check "T-n: inputs.tsv records the incident file in a linked dir as skipped" \
    sh -c "grep -F 'incident_8/INCIDENTS.json' '$RD/audit_5/bootstrap/inputs.tsv' | grep -q 'skipped: symbolic link'"
  check "T-n: inputs.tsv records the tracked incident file as skipped" \
    sh -c "grep -F 'incident_9/INCIDENTS.json' '$RD/audit_5/bootstrap/inputs.tsv' | grep -q 'skipped: tracked'"
else
  skp "T-n incident files: needs jq or python3"
fi

# =================================================================================================
# T-p: partial and shallow clones. A partial clone is refused (exit 3) before any object is read, so
# its promisor remote is never contacted; a shallow clone is collected with a note that history is cut.
# =================================================================================================
git_at_least() { # git_at_least <major> <minor>
  local v; v=$(git --version | sed -E 's/^git version ([0-9]+)\.([0-9]+).*/\1 \2/')
  [ "${v% *}" -gt "$1" ] || { [ "${v% *}" -eq "$1" ] && [ "${v#* }" -ge "$2" ]; }
}
SRV="$T/promisor-server"; mkrepo "$SRV"
put "$SRV" programs/s/src/lib.rs '#[account(mut, has_one = authority)]'
put "$SRV" README.md 'Example pool, forked from the upstream reference pool.'
commit "$SRV" -m "initial"
put "$SRV" programs/s/src/lib.rs '#[account(mut)]'
commit "$SRV" -m "Rework accounts"
git -C "$SRV" config uploadpack.allowFilter true
if ! git_at_least 2 44; then
  skp "T-p: partial clone needs git >= 2.44 (GIT_NO_LAZY_FETCH); this git is older"
elif ! git clone -q --filter=blob:none --no-local "file://$SRV" "$T/partial" >/dev/null 2>&1; then
  skp "T-p: this git could not make a blobless partial clone"
else
  printf '#!/bin/sh\ntouch "%s/marks/promisor-fetch"\nexit 1\n' "$T" > "$T/bin/mark-fetch"; chmod +x "$T/bin/mark-fetch"
  git -C "$T/partial" config remote.origin.uploadpack "$T/bin/mark-fetch"
  rm -f "$T/marks/promisor-fetch"
  git -C "$T/partial" log -p >/dev/null 2>&1
  if [ -e "$T/marks/promisor-fetch" ]; then ok "T-p sanity: plain 'git log -p' in the partial clone fetches from its promisor"
  else skp "T-p sanity: this git did not fetch a missing object"; fi
  rm -f "$T/marks/promisor-fetch"
  check "T-p: a partial clone is refused in --detect (exit 3)" \
    test "$(rc --repo "$T/partial" --out "$T/pc-run/audit_1/bootstrap" --detect)" = 3
  check "T-p: ... and in a full run (exit 3)" test "$(rc --repo "$T/partial" --out "$T/pc-run/audit_1/bootstrap" --offline)" = 3
  bash "$COLLECT" --repo "$T/partial" --out "$T/pc-run/audit_1/bootstrap" --offline >/dev/null 2>"$T/partial.err"
  check "T-p: ... with a message naming the promisor remote" has "$T/partial.err" "the target is a partial clone"
  check "T-p: the promisor remote is never contacted" test ! -e "$T/marks/promisor-fetch"
  check "T-p: nothing is written for a refused target" test ! -e "$T/pc-run"
  OUTPP="$T/pc-parent/audit_1/bootstrap"; rm -f "$T/marks/promisor-fetch"
  collect --repo "$TGT" --out "$OUTPP" --offline --parent "$T/partial"
  check "T-p: a local --parent that is a partial clone is not used" has "$OUTPP/history.md" "is a partial clone"
  check "T-p: ... and its promisor remote is never contacted" test ! -e "$T/marks/promisor-fetch"
fi
git clone -q --depth 1 --no-local "file://$SRV" "$T/shallow" >/dev/null 2>&1
OUTSH="$T/shallow-run/audit_1/bootstrap"
collect --repo "$T/shallow" --out "$OUTSH" --offline
check "T-p: a shallow clone is collected with a note that its history is cut" \
  has "$OUTSH/history.md" "Shallow clone: history before the shallow boundary is missing"
check "T-p: a full clone carries no such note" hasnt "$H1" "Shallow clone:"

echo
echo "threat-model collector tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
