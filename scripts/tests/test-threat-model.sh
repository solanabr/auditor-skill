#!/usr/bin/env bash
# test-threat-model.sh — self-test for scripts/threat-model/collect.sh.
# Builds throwaway git fixtures under ${TMPDIR:-/tmp}, inside a working directory the collector is run
# from, directly by its path, as the commands run it; needs git and awk, optionally jq / python3 /
# pdftotext (cases that need a missing tool are skipped, never failed). No network: what --network
# fetches goes to stand-ins for curl and git clone. The hostile-argument case file
# fixtures/threat-model/cases.txt runs under each bash on the machine (/bin/bash and the bash running
# this suite, when they differ), which must print the same.
# Usage (from the repo root): bash scripts/tests/test-threat-model.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
COLLECT="$ROOT/scripts/threat-model/collect.sh"
RUNDIR="$ROOT/scripts/rundir.sh"
CASES="$ROOT/scripts/tests/fixtures/threat-model/cases.txt"
T=$(mktemp -d "${TMPDIR:-/tmp}/tm-test.XXXXXX") || exit 1
T=$(cd -P "$T" && pwd -P) || exit 1
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
# W is the working directory of most runs: every fixture repository the --detect and --offline runs
# read lies inside it. Stand-in programs and marks live outside it, in $T.
W="$T/wt"
mkdir -p "$W" "$T/bin" "$T/marks"

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
# newrun [<dir>]: a new run directory in <dir> (default $W), made by rundir.sh; prints its name.
newrun() { (cd "${1:-$W}" && "$RUNDIR" new audit 2>/dev/null); }
# collect <mode> <args...>: the collector, run directly from $W into a new run directory; paths in
# <args> are relative to $W. RUN is the run directory's name, OUT its bootstrap/ (absolute).
collect() {
  local mode=$1
  shift
  RUN=$(newrun) || { ko "rundir.sh new audit failed in $W"; return 1; }
  OUT="$W/$RUN/bootstrap"
  (cd "$W" && "$COLLECT" "$mode" --out "$RUN/bootstrap" "$@") 2>"$T/stderr.log"
}
# rc <args...>: the collector's exit status, run from $W (stderr in $T/rc.err); rc_in <dir> <args...>: from <dir>.
rc() { (cd "$W" && "$COLLECT" "$@") >/dev/null 2>"$T/rc.err"; echo $?; }
rc_in() { local d=$1; shift; (cd "$d" && "$COLLECT" "$@") >/dev/null 2>"$T/rc.err"; echo $?; }
refused_with() { [ "$(cat "$T/rc.err")" = "collect.sh: refused: $1" ]; }

# =================================================================================================
# Target fixture: guard edits, attribute anchoring, quiet fix, whole-message keyword, revert.
# =================================================================================================
TGT="$W/tgt"; mkrepo "$TGT"
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

collect --offline --repo tgt
OUT1=$OUT; H1="$OUT1/history.md"
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
collect --offline --repo tgt --fix-ceiling 10
OUTC=$OUT
check "--fix-ceiling: a keyword commit above the ceiling yields no ADDED row" \
  sh -c "! awk '/^## R3/,/^## R4/' '$OUTC/history.md' | grep -q '^$C_BODYKW .* ADDED x'"
check "--fix-ceiling: its R1 entry and REMOVED rows are unaffected" sh -c "awk '/^## R1/,/^## R2/' '$OUTC/history.md' | grep -q '^$C_BODYKW '"
check "T-h: R2 lists the revert and the commit it reverts" \
  sh -c "awk '/^## R2/,/^## R3/' '$H1' | grep -q '^$C_REVERT .*-> reverts $(git -C "$TGT" rev-parse --short=10 "$C_BODYKW")'"
check "R2/R5: an empty section prints NOT FOUND" sh -c "awk '/^## R5/,/^## R6/' '$H1' | grep -q 'NOT FOUND (no --parent given'"
check "files named in rows are under the default programs/ pathspec" has "$H1" '| Target paths | `programs/*.rs` |'
check "a diff is saved for each REMOVED commit" test -s "$OUT1/diffs/target-$C_CLOSE.diff"
check "the target is named by its physical path" has "$H1" "| Target | \`$TGT\` |"
check "history.md says git ran with the system and global config dropped" has "$H1" "Git ran with the system and global config dropped"

collect --offline --repo tgt --pin "$C_RETARGET" --paths 'programs/demo/src/lib.rs' --program-id Demo1111 --audit-mem-db .audit-memory/audit.db
OUTP=$OUT
check "--pin: commits after the pinned commit are not mined" sh -c "! grep -q '^$C_BODYKW ' '$OUTP/history.md'"
check "--pin: the pinned commit is recorded in full" has "$OUTP/history.md" "| Pinned commit | \`$(git -C "$TGT" rev-parse "$C_RETARGET")\` |"
check "--paths: rows stay inside the given pathspec" sh -c "! grep -q 'close.rs' '$OUTP/history.md'"
check "--program-id without the built tool says so" sh -c "grep -q 'NOT FOUND (tools/auditor-tools is not built)' '$OUTP/history.md' || grep -q 'NOT FOUND (no database at' '$OUTP/history.md'"

collect --offline --repo tgt --cap 1
OUT2=$OUT
check "TRUNCATED (+n) is printed when a section exceeds --cap" \
  sh -c "awk '/^## R4/,/^## R5/' '$OUT2/history.md' | grep -qE '^TRUNCATED \(\+[0-9]+ more rows'"

# =================================================================================================
# The mode comes first; every other option once; bounded values. Refusals print one line, exit 2, and
# write nothing.
# =================================================================================================
RUN_A=$(newrun)
tree() { (cd "$1" && find . -path ./tgt/.git -prune -o -print | LC_ALL=C sort); }
tree "$W" > "$T/tree.before"
check "no arguments: refused (exit 2)" test "$(rc)" = 2
check "... naming the modes" refused_with "the mode comes first: --detect, --offline or --network, then --repo <dir> --out audit_<n>/bootstrap [options] (see --help)"
check "the form with the mode last is refused (exit 2)" test "$(rc --repo tgt --out "$RUN_A/bootstrap" --offline)" = 2
check "... with the same hint" refused_with "the mode comes first: --detect, --offline or --network, then --repo <dir> --out audit_<n>/bootstrap [options] (see --help)"
check "--detect last is refused too (exit 2)" test "$(rc --repo tgt --out "$RUN_A/bootstrap" --pin HEAD --detect)" = 2
check "a second mode after the first is refused (exit 2)" test "$(rc --detect --repo tgt --out "$RUN_A/bootstrap" --offline)" = 2
check "... naming it" refused_with "the mode is given once, as the first argument: --offline"
check "a mode in another letter case is not a mode (exit 2)" test "$(rc --Offline --repo tgt --out "$RUN_A/bootstrap")" = 2
check "--help with more arguments is refused (exit 2)" test "$(rc --help --offline)" = 2
check "an option given twice is refused (exit 2)" test "$(rc --offline --repo tgt --repo tgt --out "$RUN_A/bootstrap")" = 2
check "... naming it" refused_with "--repo is given twice"
check "--out given twice is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" --out "$RUN_A/bootstrap")" = 2
check "an unknown option is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" --fetch)" = 2
check "... naming it" refused_with "unknown argument: --fetch (see --help)"
(cd "$W" && CONFINE_HINT=planted "$COLLECT" --offline --repo tgt --out "$RUN_A/bootstrap" --fetch) >/dev/null 2>"$T/rc.err"
check "a CONFINE_HINT from the environment is not added to a refusal" refused_with "unknown argument: --fetch (see --help)"
check "an option with no value is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" --cap)" = 2
for opt in --cap --small --fix-ceiling; do
  check "$opt 10001 is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" "$opt" 10001)" = 2
  check "... with the bounds" refused_with "$opt must be a number from 0 to 10000"
  check "$opt -1 is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" "$opt" -1)" = 2
  check "$opt 1e3 is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" "$opt" 1e3)" = 2
  check "$opt with 99999999999999999999 is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" "$opt" 99999999999999999999)" = 2
done
KW200=$(i=0; while [ $i -lt 200 ]; do printf k; i=$((i + 1)); done)
check "--keywords of 201 characters is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" --keywords "${KW200}k")" = 2
check "... saying so" refused_with "--keywords is longer than 200 characters"
check "--keywords with a control character is refused (exit 2)" \
  test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" --keywords "$(printf 'drain\001bypass')")" = 2
check "--keywords with a newline is refused (exit 2)" \
  test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" --keywords "$(printf 'drain\nbypass')")" = 2
check "--paths with a newline is refused (exit 2)" \
  test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" --paths "$(printf 'a.rs\nb.rs')")" = 2
check "--program-id of 201 characters is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" --program-id "${KW200}x")" = 2
check "a --pin that looks like an option is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_A/bootstrap" --pin --output=x)" = 2
check "... saying so" refused_with "--pin takes a revision, not an option: --output=x"
tree "$W" > "$T/tree.after"
check "a refused run wrote nothing in the working directory" cmp -s "$T/tree.before" "$T/tree.after"
check "... nor where an option-shaped value named a file" test ! -e "$W/x"
collect --offline --repo tgt --cap 10000 --small 10000 --fix-ceiling 10000 --keywords "$KW200"
check "the bounds themselves are accepted (exit 0)" test -s "$OUT/history.md"
# A value is never taken for an option: --keywords swallows the word after it, and the mode stays first.
collect --offline --repo tgt --keywords --network
check "an option-shaped word after --keywords is its value, not a mode (exit 0, still offline)" \
  sh -c "grep -q '^| Network | offline |' '$OUT/history.md' && grep -q 'oracle|--network' '$OUT/history.md'"
check "--help prints the whole header, exit statuses included" \
  sh -c "cd '$W' && '$COLLECT' --help | grep -q 'Exit status:' && '$COLLECT' --help | grep -q 'promisor remote)'"
check "--help names the mode-first forms" sh -c "cd '$W' && '$COLLECT' --help | grep -q 'collect.sh\" --offline --repo <dir> --out audit_<n>/bootstrap'"

# =================================================================================================
# --out is audit_<n>/bootstrap in a run directory of the working directory.
# =================================================================================================
mkdir -p "$W/audit_77"
for out in audit_1 incident_1/bootstrap audit_1/bootstrap/x audit_x/bootstrap Audit_1/bootstrap \
           "$W/$RUN_A/bootstrap" "/tmp/$RUN_A/bootstrap" "../wt/$RUN_A/bootstrap" "$RUN_A/./bootstrap" "$RUN_A//bootstrap" \
           "$RUN_A/bootstrap2" "nested/$RUN_A/bootstrap"; do
  check "--out $out is refused (exit 2)" test "$(rc --offline --repo tgt --out "$out")" = 2
done
check "... saying what --out takes" refused_with "--out must be audit_<n>/bootstrap, in a run directory audit_<n> directly in the working directory: nested/$RUN_A/bootstrap"
check "a run directory that does not exist is refused (exit 2)" test "$(rc --offline --repo tgt --out audit_999/bootstrap)" = 2
check "... and not created" test ! -e "$W/audit_999"
check "a run directory without its .gitignore of * is refused (exit 2)" test "$(rc --offline --repo tgt --out audit_77/bootstrap)" = 2
check "... saying so" refused_with "the run directory has no .gitignore holding exactly *: audit_77"
check "--detect takes a run directory that does not exist yet (exit 0)" test "$(rc --detect --repo tgt --out audit_999/bootstrap)" = 0
check "... and creates nothing" test ! -e "$W/audit_999"
check "./audit_<n>/bootstrap/ is accepted (exit 0)" test "$(rc --offline --repo tgt --out "./$RUN_A/bootstrap/")" = 0
check "... and writes into the run directory" test -s "$W/$RUN_A/bootstrap/history.md"
check "the collector writes no .gitignore of its own (the run directory's covers it)" test ! -e "$W/$RUN_A/bootstrap/.gitignore"

# =================================================================================================
# Parent and forks: twin-guard hint (T-c), parent-only refs (T-a), shared history and blob identity.
# =================================================================================================
PAR="$W/par"; mkrepo "$PAR"
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

FORKH="$W/fork-hist"
git clone -q "$PAR" "$FORKH"
put "$FORKH" programs/amm/src/extra.rs '// fork-specific module'
commit "$FORKH" -m "fork: add extra module"

FORKI="$W/fork-import"; mkrepo "$FORKI"
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

collect --offline --repo fork-hist --parent par
OUT3=$OUT; H3="$OUT3/history.md"
check "a local --parent inside the working directory is read in --offline" has "$H3" "| Parent | $PAR — local repository"
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
HOME="$T/home-cfg" collect --offline --repo fork-hist --parent par
OUT3B=$OUT
check "grep/colour config (target + ~/.gitconfig): the twin guard is still present elsewhere" \
  sh -c "grep -q 'require_keys_eq!(ctx.accounts.vault.key(), pool.vault);.*\[text present elsewhere in target - verify\]' '$OUT3B/history.md'"
check "grep/colour config: no escape sequences reach history.md" sh -c "! grep -q \"\$(printf '\\033')\" '$OUT3B/history.md'"

collect --offline --repo fork-import --parent par
OUT4=$OUT
check "R5b: fork point found through blob identity for a history-less import" \
  sh -c "grep -q '^fork point: $P1 .* blob identity: 1 of 1 import blobs' '$OUT4/history.md'"
# A fork whose first commit holds only a README: the code arrives in a later commit, named by --import.
FORKR="$W/fork-readme"; mkrepo "$FORKR"
put "$FORKR" README.md '# our fork'
commit "$FORKR" -m "Initial commit"
put "$FORKR" "$AMM" "$AMM_P1"
commit "$FORKR" -m "import upstream amm"
C_IMPORT=$(git -C "$FORKR" rev-parse HEAD)
collect --offline --repo fork-readme --parent par
OUT4R=$OUT
check "R5b: without --import, a README-only root commit leaves R5 NOT FOUND" \
  sh -c "awk '/^## R5/,/^## R6/' '$OUT4R/history.md' | grep -q '^NOT FOUND (no shared commit'"
collect --offline --repo fork-readme --parent par --import "$C_IMPORT"
OUT4I=$OUT
check "R5b: --import names the commit that brought the code in" \
  sh -c "grep -q '^fork point: $P1 .* blob identity: 1 of 1 import blobs' '$OUT4I/history.md'"
RUN_X=$(newrun)
check "--import: a value that looks like an option is refused (exit 2)" \
  test "$(rc --offline --repo fork-readme --out "$RUN_X/bootstrap" --parent par --import "--output=$T/import-written.txt")" = 2
check "--import: ... and nothing is created" sh -c "[ ! -e '$T/import-written.txt' ] && [ ! -e '$W/$RUN_X/bootstrap' ]"
check "--import: a value that is not a commit is refused (exit 2)" \
  test "$(rc --offline --repo fork-readme --out "$RUN_X/bootstrap" --parent par --import no-such-revision)" = 2
check "--import: ... saying so" refused_with "--import does not resolve to a commit: no-such-revision"
check "--import: ... and nothing is created" test ! -e "$W/$RUN_X/bootstrap"

# =================================================================================================
# In --detect and --offline every local path stays inside the working directory and reaches nothing
# through a symbolic link; --network reads outside it. A refusal names --network.
# =================================================================================================
OUTSIDE="$T/outside-repo"; mkrepo "$OUTSIDE"
put "$OUTSIDE" programs/o/src/lib.rs '#[account(mut, has_one = authority)]'
commit "$OUTSIDE" -m "initial"
put "$OUTSIDE" programs/o/src/lib.rs '#[account(mut)]'
commit "$OUTSIDE" -m "Rework accounts"
ln -s tgt "$W/tgt-link"
ln -s "$OUTSIDE" "$W/outside-link"
mkdir -p "$W/plain" "$W/realdir"; printf '# prior\n' > "$W/realdir/prior.md"; ln -s realdir "$W/dirlink"
printf '# outside report\n' > "$T/outside-report.md"
NETHINT="only --network reads outside the working directory or through a symbolic link"
RUN_B=$(newrun)
for mode in --detect --offline; do
  check "$mode: an absolute --repo is refused (exit 2)" test "$(rc "$mode" --repo "$OUTSIDE" --out "$RUN_B/bootstrap")" = 2
  check "$mode: ... naming --network" refused_with "--repo must be relative to the working directory: $OUTSIDE; $NETHINT"
  check "$mode: a --repo with .. is refused (exit 2)" test "$(rc "$mode" --repo ../wt/tgt --out "$RUN_B/bootstrap")" = 2
  check "$mode: a --repo through a symbolic link is refused (exit 2)" test "$(rc "$mode" --repo tgt-link --out "$RUN_B/bootstrap")" = 2
  check "$mode: ... naming --network" refused_with "--repo passes through a symbolic link: tgt-link; $NETHINT"
  check "$mode: a link to a repository outside is refused (exit 2)" test "$(rc "$mode" --repo outside-link --out "$RUN_B/bootstrap")" = 2
  check "$mode: --repo ~ is refused (exit 2)" test "$(rc "$mode" --repo '~' --out "$RUN_B/bootstrap")" = 2
  check "$mode: an absolute --parent is refused (exit 2)" test "$(rc "$mode" --repo tgt --out "$RUN_B/bootstrap" --parent "$OUTSIDE")" = 2
  check "$mode: ... naming --network" refused_with "--parent must be relative to the working directory: $OUTSIDE; $NETHINT"
  check "$mode: a --parent through a link is refused (exit 2)" test "$(rc "$mode" --repo tgt --out "$RUN_B/bootstrap" --parent outside-link)" = 2
  check "$mode: an absolute --vulns is refused (exit 2)" test "$(rc "$mode" --repo tgt --out "$RUN_B/bootstrap" --vulns "$T/outside-report.md")" = 2
  check "$mode: ... naming --network" refused_with "--vulns must be relative to the working directory: $T/outside-report.md; $NETHINT"
  check "$mode: a --vulns through a directory link is refused (exit 2)" test "$(rc "$mode" --repo tgt --out "$RUN_B/bootstrap" --vulns dirlink/prior.md)" = 2
  check "$mode: a --vulns with .. is refused (exit 2)" test "$(rc "$mode" --repo tgt --out "$RUN_B/bootstrap" --vulns realdir/../realdir/prior.md)" = 2
done
check "nothing was written for the refused runs" test ! -e "$W/$RUN_B/bootstrap"
# A repository whose git directory lies outside the working directory, through a .git file.
git init -q --separate-git-dir "$T/sep.git" "$W/sepdir" && git -C "$W/sepdir" symbolic-ref HEAD refs/heads/main
put "$W/sepdir" a.rs 'fn a() {}'; commit "$W/sepdir" -m initial
check "--offline: a --repo whose git directory lies outside the working directory is refused (exit 2)" \
  test "$(rc --offline --repo sepdir --out "$RUN_B/bootstrap")" = 2
check "... saying so" refused_with "--repo keeps its git directory outside the working directory: sepdir; $NETHINT"
check "--detect: the same (exit 2)" test "$(rc --detect --repo sepdir --out "$RUN_B/bootstrap")" = 2
check "--offline: a --parent whose git directory lies outside is refused (exit 2)" \
  test "$(rc --offline --repo tgt --out "$RUN_B/bootstrap" --parent sepdir)" = 2
# --network: the same paths are read, as the human approved them.
collect --network --repo "$OUTSIDE"
check "--network: an absolute --repo outside the working directory is collected" \
  has "$OUT/history.md" "REMOVED x1 programs/o/src/lib.rs: #[account(mut, has_one = authority)]"
check "--network: ... and the Network row says URLs are recorded" has "$OUT/history.md" "| Network | explicit https URLs only, each recorded in disclosures.tsv |"
collect --network --repo tgt-link
check "--network: a --repo through a symbolic link is collected" test -s "$OUT/history.md"
collect --network --repo fork-hist --parent "$PAR"
check "--network: an absolute --parent is used" has "$OUT/history.md" "| Parent | $PAR — local repository"
collect --network --repo sepdir
check "--network: a repository whose git directory lies outside is collected" test -s "$OUT/history.md"
collect --network --repo tgt --vulns "$T/outside-report.md"
check "--network: an absolute --vulns outside the working directory is copied" \
  sh -c "grep -F '$T/outside-report.md' '$OUT/inputs.tsv' | grep -q 'copied'"
check "--network with no URL writes no disclosures.tsv" test ! -e "$W/$RUN/disclosures.tsv"
check "the installation inside the working directory is refused (exit 2)" \
  test "$(rc_in "$ROOT" --detect --repo . --out audit_1/bootstrap)" = 2
check "... naming Rule 11e" sh -c "grep -q 'the installation lies inside the working directory' '$T/rc.err'"
mkdir -p "$W/tmpin"
check "a TMPDIR inside the working directory is refused (exit 2)" \
  test "$(cd "$W" && TMPDIR="$W/tmpin" "$COLLECT" --offline --repo tgt --out "$RUN_B/bootstrap" >/dev/null 2>"$T/rc.err"; echo $?)" = 2
check "... and nothing is made there" test -z "$(ls -A "$W/tmpin")"

# =================================================================================================
# T-g: hostile .git/config and attributes. Nothing configured by the target may execute.
# =================================================================================================
HOS="$W/hostile"; mkrepo "$HOS"
for m in textconv extdiff external fsmonitor gpg pager pagerlog; do
  printf '#!/bin/sh\ntouch "%s/marks/%s"\n[ -n "$1" ] && [ -f "$1" ] && cat "$1"\nexit 0\n' "$T" "$m" > "$T/bin/mark-$m"
  chmod +x "$T/bin/mark-$m"
done
put "$HOS" .gitattributes '*.rs diff=evil'
put "$HOS" programs/h/src/lib.rs '#[account(mut, has_one = authority)]'
commit "$HOS" -m "initial"
put "$HOS" programs/h/src/lib.rs '#[account(mut)]'
commit "$HOS" -m "fix: drop has_one"
# Re-create HEAD as a signed commit (a gpgsig header, written with hash-object; no real gpg needed), so
# that log.showSignature below has a signature to verify with the configured gpg.program.
SIGNED=$(git -C "$HOS" cat-file commit HEAD | awk '{ print } /^committer / && !done {
  print "gpgsig -----BEGIN PGP SIGNATURE-----"; print " "; print " iQEzBAABCAAdFiEEZml4dHVyZS1zaWduYXR1cmUtbm90LXJlYWw="
  print " -----END PGP SIGNATURE-----"; done = 1 }' | git -C "$HOS" hash-object -t commit -w --stdin)
git -C "$HOS" update-ref refs/heads/main "$SIGNED"
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
if grep -qE 'textconv|extdiff|external' <<< "$(ls "$T/marks")"; then ok "T-g sanity: plain 'git log -p' runs the configured diff program"
else skp "T-g sanity: this git did not run the configured diff program"; fi
git -C "$HOS" status >/dev/null 2>&1
if [ -e "$T/marks/fsmonitor" ]; then ok "T-g sanity: plain 'git status' runs core.fsmonitor"
else skp "T-g sanity: this git did not run core.fsmonitor"; fi
if [ -e "$T/marks/gpg" ]; then ok "T-g sanity: plain 'git log' runs gpg.program for the signed commit"
else skp "T-g sanity: this git did not run gpg.program"; fi
rm -f "$T/marks"/*
collect --offline --repo hostile --paths '*.rs'
OUT5=$OUT
check "T-g: collector still produces rows on the hostile repo" has "$OUT5/history.md" "REMOVED x1 programs/h/src/lib.rs: #[account(mut, has_one = authority)]"
check "T-g: no textconv, external diff, fsmonitor, gpg or pager program ran" \
  sh -c "[ -z \"\$(ls '$T/marks')\" ]"
collect --network --repo "$HOS" --paths '*.rs'
check "T-g: nor in --network" sh -c "[ -z \"\$(ls '$T/marks')\" ]"

# =================================================================================================
# T-o: diff output. Diffs run as text with the big-file, hunk-fusing and root-commit settings pinned, so
# neither the target's attributes nor its config can hide a guard change; R4 pins git's rust pattern.
# =================================================================================================
SH_BIG=""; i=0; while [ $i -lt 60 ]; do SH_BIG="$SH_BIG// filler line $i"$'\n'; i=$((i + 1)); done
for how in gitattributes info-attributes bigfile; do
  AT="$W/shape-$how"; mkrepo "$AT"
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
  collect --offline --repo "shape-$how"
  OUTA=$OUT
  check "T-o ($how): the removed guard line is still reported" \
    has "$OUTA/history.md" "REMOVED x1 programs/a/src/lib.rs: #[account(mut, has_one = authority)]"
  check "T-o ($how): a 61-line commit is not taken for a quiet fix" hasnt "$OUTA/history.md" "ADDED-QUIET x1 programs/a/src/big.rs"
done
# A commit's size counts every file it changes in the pathspec, not only the file holding the guard.
SPLIT="$W/shape-split"; mkrepo "$SPLIT"
put "$SPLIT" programs/s/src/lib.rs 'pub fn s() {}'
commit "$SPLIT" -m "initial"
put "$SPLIT" programs/s/src/lib.rs 'pub fn s() -> Result<()> { require!(ok, E::S); Ok(()) }'
put "$SPLIT" programs/s/src/filler.rs "$SH_BIG"
commit "$SPLIT" -m "Reorganise modules"
collect --offline --repo shape-split
check "T-o: a 62-line commit over two files is not taken for a quiet fix" \
  hasnt "$OUT/history.md" "ADDED-QUIET x"
R4T="$W/shape-r4"; mkrepo "$R4T"
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
collect --offline --repo shape-r4
OUTR4=$OUT
R4S="$T/r4s.txt"; section_of "$OUTR4/history.md" "R4" > "$R4S"
check "T-o (R4): both function names survive a redefined rust driver and fused hunks$R4_ATTR" \
  sh -c "grep -q ' alpha_guard\$' '$R4S' && grep -q ' beta_guard\$' '$R4S'"
check "T-o (R4): log.showRoot=false does not hide the root commit" grep -qE '^ *2 programs/f/src/lib.rs$' "$R4S"
check "T-o (R4): no note when every .rs file uses the pinned driver" hasnt "$R4S" "note:"
check "T-o: history.md says what is pinned and what is not" has "$OUTR4/history.md" "rust hunk-header pattern, pinned"
# A target that sets diff.context 0 still gets saved diffs with three lines of context.
CX="$W/ctx0"; mkrepo "$CX"
put "$CX" programs/x/src/lib.rs 'pub fn f(ctx: Context) -> Result<()> {
    let a = 1;
    require!(ctx.accounts.a.is_signer, E::X);
    let b = 2;
    Ok(())
}'
commit "$CX" -m "initial"
put "$CX" programs/x/src/lib.rs 'pub fn f(ctx: Context) -> Result<()> {
    let a = 1;
    let b = 2;
    Ok(())
}'
commit "$CX" -m "Tidy f"
C_CX=$(short "$CX" HEAD)
git -C "$CX" config diff.context 0
collect --offline --repo ctx0
check "T-o: diff.context=0 in the target: the saved diff keeps three lines of context" \
  sh -c "grep -qx ' pub fn f(ctx: Context) -> Result<()> {' '$OUT/diffs/target-$C_CX.diff' && grep -qx '     Ok(())' '$OUT/diffs/target-$C_CX.diff'"
mkdir -p "$R4T/.git/info"; printf '*.rs diff=other\n' > "$R4T/.git/info/attributes"
collect --offline --repo shape-r4
check "T-o (R4): .rs files that .git/info/attributes sends to another driver are counted in a note" \
  sh -c "awk '/^## R4/,/^## R5/' '$OUT/history.md' | grep -q '^note: the target.s attributes send 1 .rs file'"
GR="$W/shape-grep"; mkrepo "$GR"
put "$GR" programs/g/src/lib.rs 'declare_id!("Demo1111111111111111111111111111111111111111");
security_txt! { source_code: "https://example.invalid/not-a-remote" }'
commit "$GR" -m "initial"
mkdir -p "$GR/.git/info"; printf '*.rs -diff\n' > "$GR/.git/info/attributes"
collect --offline --repo shape-grep
check "T-o (grep): a Rust file the target marks binary is still searched (R6 declare_id!)" \
  has "$OUT/history.md" 'declare_id!("Demo1111'
check "T-o (grep): ... and still reaches the T3 source_code check" \
  has "$OUT/history.md" "T3 yes security_txt-source_code"
# Committed attributes that mark the Rust files and the README binary change neither --detect nor R6.
GA="$W/shape-grep-attrs"; mkrepo "$GA"
put "$GA" programs/g/src/lib.rs 'declare_id!("Demo1111111111111111111111111111111111111111");
security_txt! { source_code: "https://example.invalid/not-a-remote" }'
put "$GA" README.md 'Example pool, forked from the upstream reference pool.'
put "$GA" .gitattributes '*.rs -diff
README* -diff'
commit "$GA" -m "initial"
DGA=$(cd "$W" && "$COLLECT" --detect --repo shape-grep-attrs --out audit_900/bootstrap 2>/dev/null)
check "T-o (grep): with *.rs and README* marked -diff, --detect still fires T3 on both signals" \
  sh -c "printf '%s\n' '$DGA' | grep -q '^T3 yes readme-phrase,security_txt-source_code'"
collect --offline --repo shape-grep-attrs
GAH="$OUT/history.md"
check "T-o (grep): ... and R6 still lists the fork phrase, source_code and declare_id!" \
  sh -c "grep -q '^README.md:1:Example pool, forked from' '$GAH' && grep -q 'source_code: \"https://example.invalid/not-a-remote\"' '$GAH' && grep -q 'declare_id!(\"Demo1111' '$GAH'"

# T-py: the collector runs python3 isolated and outside the target, so a target json.py never loads.
# Here the target is the working directory itself (--repo .), as when the audit runs inside it.
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
  PYRUN=$(newrun "$PYT")
  for tool in default python3; do
    rm -f "$T/marks/py-hijack"
    (cd "$PYT" && TM_TEST_MARK="$T/marks/py-hijack" TM_JSON_TOOL=$([ "$tool" = default ] || echo python3) \
      "$COLLECT" --offline --repo . --out "$PYRUN/bootstrap" >/dev/null 2>&1)
    check "T-py ($tool): an invalid INCIDENTS.json falls through without running the target json.py" test ! -e "$T/marks/py-hijack"
  done
  check "T-py: the invalid incident file is recorded, not copied" has "$PYT/$PYRUN/bootstrap/inputs.tsv" "not copied: no working jq or python3 parsed it"
  check "R6: with --repo ., the run directory itself is not listed as an output next to the target" \
    sh -c "! awk '/auditor-skill outputs next to the target/,/^\`\`\`\$/' '$PYT/$PYRUN/bootstrap/history.md' | grep -qF '$PYRUN/'"
  rm -f "$T/marks"/*
else
  skp "T-py: needs python3"
fi

# =================================================================================================
# T-j: egress rules — https only, explicit only, nothing in --detect or --offline.
# =================================================================================================
RUN_J=$(newrun)
for mode in --offline --network; do
  check "T-j ($mode): --parent http:// is rejected (exit 2)" test "$(rc "$mode" --repo tgt --out "$RUN_J/bootstrap" --parent http://example.invalid/p.git)" = 2
  check "T-j ($mode): ... saying so" refused_with "--parent accepts an https:// URL or a local path, not: http://example.invalid/p.git"
  check "T-j ($mode): --parent scp-style host:path is rejected" test "$(rc "$mode" --repo tgt --out "$RUN_J/bootstrap" --parent git@example.invalid:o/p.git)" = 2
  check "T-j ($mode): --parent ssh:// is rejected" test "$(rc "$mode" --repo tgt --out "$RUN_J/bootstrap" --parent ssh://example.invalid/p.git)" = 2
  check "T-j ($mode): --vulns file:// is rejected" test "$(rc "$mode" --repo tgt --out "$RUN_J/bootstrap" --vulns file:///etc/hosts)" = 2
done
check "T-j: a non-repository target exits 3" test "$(rc --offline --repo plain --out "$RUN_J/bootstrap")" = 3
check "T-j: ... saying it is not the top level of a repository git can read" \
  has "$T/rc.err" "not the top level of a git repository that git can read"
# --repo must be the top level of its own repository; a plain directory inside another one is refused.
mkdir -p "$TGT/not-a-repo"
check "T-j: a plain directory inside another repository exits 3" \
  test "$(rc --detect --repo tgt/not-a-repo --out "$RUN_J/bootstrap")" = 3
check "T-j: ... in --network too" test "$(rc --network --repo "$TGT/not-a-repo" --out "$RUN_J/bootstrap")" = 3
git clone -q --bare "$TGT" "$W/tgt-bare.git"
check "T-j: a bare repository is accepted" test "$(rc --detect --repo tgt-bare.git --out "$RUN_J/bootstrap")" = 0
rmdir "$TGT/not-a-repo"
collect --offline --repo fork-hist --parent par/programs
check "T-j: a local --parent inside another repository is not used" \
  has "$OUT/history.md" "NOT FOUND (parent $PAR/programs: not a git repository (or not its top level))"
collect --offline --repo fork-hist --parent no-such-parent
check "T-j: a --parent that does not exist is not used" \
  has "$OUT/history.md" "NOT FOUND (parent $W/no-such-parent: not a git repository (or not its top level))"
# Large input: classify_source used to pipe the argument into grep -q, whose early exit under pipefail
# could turn "rejected" into "path". A long scp-style value must still be rejected.
LONG=$(i=0; while [ $i -lt 3000 ]; do printf 'padding-%s-' "$i"; i=$((i + 1)); done)
check "large input: a long scp-style --parent is still rejected (exit 2)" \
  test "$(rc --offline --repo tgt --out "$RUN_J/bootstrap" --parent "git@example.invalid:o/p.git/${LONG:0:990}")" = 2
check "... for its scheme" has "$T/rc.err" "--parent accepts an https:// URL or a local path, not: git@example.invalid:o/p.git/padding-0-"
check "a value longer than 1024 bytes is refused (exit 2)" test "$(rc --offline --repo tgt --out "$RUN_J/bootstrap" --parent "$LONG")" = 2
check "... saying so" refused_with "--parent is longer than 1024 bytes"
collect --offline --repo tgt --parent https://example.invalid/parent.git --vulns https://example.invalid/report.pdf
OUT6=$OUT
check "T-j: --offline records the parent URL without cloning" has "$OUT6/history.md" "given, not cloned (offline)"
check "T-j: --offline records a --vulns URL without fetching" has "$OUT6/inputs.tsv" "recorded, not fetched (offline)"
check "T-j: --offline writes no disclosure row" test ! -e "$W/$RUN/disclosures.tsv"

# =================================================================================================
# --network: every URL is recorded in audit_<n>/disclosures.tsv before it is fetched. Stand-ins for curl
# and for git clone (any other git call goes to the real git) record each call and fetch nothing.
# =================================================================================================
REALGIT=$(command -v git)
mkdir -p "$T/netbin"
cat > "$T/netbin/curl" <<EOF
#!/bin/sh
printf 'curl %s\n' "\$*" >> "$T/net.log"
out=""
while [ \$# -gt 0 ]; do case "\$1" in -o) out=\$2; shift 2 ;; *) shift ;; esac; done
[ -n "\$out" ] && printf '# Fetched report\n\nF-9: missing owner check\n' > "\$out"
exit 0
EOF
cat > "$T/netbin/git" <<EOF
#!/bin/sh
for a in "\$@"; do
  case "\$a" in clone) printf 'git clone %s\n' "\$*" >> "$T/net.log"; exit 128 ;; esac
done
exec "$REALGIT" "\$@"
EOF
chmod +x "$T/netbin/curl" "$T/netbin/git"
: > "$T/net.log"
PATH="$T/netbin:$PATH" collect --network --repo tgt --parent 'https://user:TOKEN-P@example.invalid/org/parent.git?t=QUERY-P' \
  --vulns 'https://reports.example.invalid/a/r1.md?X-Amz-Signature=SIG-V'
DT="$W/$RUN/disclosures.tsv"
check "--network: the parent URL is cloned (the stand-in refuses) and the vulns URL fetched" \
  sh -c "grep -q '^git clone' '$T/net.log' && grep -q '^curl' '$T/net.log'"
check "--network: disclosures.tsv starts with its header" test "$(sed -n 1p "$DT")" = "$(printf 'time\ttool\tservice\tsent\tcount')"
check "--network: one row for each URL" test "$(wc -l < "$DT" | tr -d ' ')" = 3
check "--network: the clone's row names the service and the URL without its credentials" \
  sh -c "awk -F '\t' 'NR == 2 && \$2 == \"scripts/threat-model/collect.sh\" && \$3 == \"example.invalid\" && \$4 == \"https URL (git clone): https://***@example.invalid/org/parent.git?***\" && \$5 == 1 { f = 1 } END { exit !f }' '$DT'"
check "--network: the download's row too" \
  sh -c "awk -F '\t' 'NR == 3 && \$3 == \"example.invalid\" && \$4 == \"https URL (download): https://reports.example.invalid/a/r1.md?***\" { f = 1 } END { exit !f }' '$DT'"
check "--network: each row's time is UTC" sh -c "awk -F '\t' 'NR > 1 && \$1 !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\$/ { bad = 1 } END { exit bad }' '$DT'"
check "--network: no credential reaches disclosures.tsv" sh -c "! grep -q 'TOKEN-P\|QUERY-P\|SIG-V' '$DT'"
check "--network: the fetched report is ingested" has "$OUT/inputs.tsv" "copied"
check "--network: a failed clone is recorded as such" has "$OUT/history.md" "clone failed"
RUN_N=$(newrun); mkdir "$W/$RUN_N/disclosures.tsv"; : > "$T/net.log"
check "--network: a disclosures.tsv that is not a file is refused before any fetch (exit 2)" \
  test "$(PATH="$T/netbin:$PATH" rc --network --repo tgt --out "$RUN_N/bootstrap" --vulns https://example.invalid/x.md)" = 2
check "... saying so" refused_with "$RUN_N/disclosures.tsv is not a regular file of its own with the disclosure header, so no fetch could be recorded"
check "... and nothing was fetched" test ! -s "$T/net.log"
RUN_N2=$(newrun); printf 'not the header\n' > "$W/$RUN_N2/disclosures.tsv"
check "--network: a disclosures.tsv with another first line is refused (exit 2)" \
  test "$(PATH="$T/netbin:$PATH" rc --network --repo tgt --out "$RUN_N2/bootstrap" --vulns https://example.invalid/x.md)" = 2
RUN_N3=$(newrun); printf 'time\ttool\tservice\tsent\tcount\n' > "$T/elsewhere-disclosures.tsv"
ln "$T/elsewhere-disclosures.tsv" "$W/$RUN_N3/disclosures.tsv" 2>/dev/null &&
  check "--network: a disclosures.tsv with a second link is refused (exit 2)" \
    test "$(PATH="$T/netbin:$PATH" rc --network --repo tgt --out "$RUN_N3/bootstrap" --vulns https://example.invalid/x.md)" = 2
check "... and the other link is untouched" test "$(wc -l < "$T/elsewhere-disclosures.tsv" | tr -d ' ')" = 1
check "nothing was fetched for the refused runs" test ! -s "$T/net.log"

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
printf '{"schema": "something-else/2", "rows": []}\n' > "$W/other.json"
printf 'id,title,component,description\nF-1,Missing signer,withdraw,authority not a signer\n' > "$W/findings.csv"
for tool in jq python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then skp "T-k ($tool): $tool not installed"; continue; fi
  TM_JSON_TOOL=$tool collect --offline --repo tgt --vulns other.json --vulns findings.csv
  OUT7=$OUT
  EX="$OUT7/inputs/incident1-INCIDENTS.json"
  check "T-k ($tool): INCIDENTS.json is extracted to inputs/" test -s "$EX"
  check "T-k ($tool): the stable read surface survives" \
    sh -c "grep -q 'INC-1.1' '$EX' && grep -q 'suspected' '$EX' && grep -q 'failed' '$EX' && grep -q 'code_flaw' '$EX' && grep -q 'KV-004' '$EX' && grep -q 'AC-001' '$EX' && grep -q 'PoC-REPRODUCED' '$EX'"
  for bad in ATTACKER-PII-ADDR TX-PII-SIG VICTIM-PII TIMELINE-PII EVIDENCE-PII BINPROV-PII GAPS-PII RESPONSE-PII \
             RULED-OUT-PII DROP-ME-NESTED DROP-ME-NOTES DROP-ME-PATH immediate-PRIVATE '"severity"' '"verified"'; do
    check "T-k ($tool): $bad is not copied" hasnt "$EX" "$bad"
  done
  check "T-k ($tool): another schema is recorded, not silently dropped" has "$OUT7/inputs.tsv" 'skipped: schema "something-else/2"'
  if [ "$tool" = python3 ]; then
    # A python3 that logs where it runs: the JSON helpers run from /, so nothing in the working
    # directory (a .python-version a pyenv shim reads) picks the interpreter.
    REALPY=$(python3 -I -c 'import sys; print(sys.executable)')
    mkdir -p "$T/pycwd"; printf '#!/bin/sh\npwd -P >> "%s"\nexec "%s" "$@"\n' "$T/pycwd.log" "$REALPY" > "$T/pycwd/python3"; chmod +x "$T/pycwd/python3"
    : > "$T/pycwd.log"
    PATH="$T/pycwd:$PATH" TM_JSON_TOOL=python3 collect --offline --repo tgt --vulns other.json
    check "T-k (python3): the JSON helpers run from /" sh -c "[ -s '$T/pycwd.log' ] && [ \"\$(sort -u '$T/pycwd.log')\" = / ]"
  fi
  check "T-k ($tool): a CSV findings list is copied" has "$OUT7/inputs.tsv" "copied (list)"
  check "T-k ($tool): incidents count as trigger T4" has "$OUT7/history.md" "T4 yes incidents-json"
done
# An old or broken jq (jq < 1.7 lacks builtins newer programs use) must hand over to python3, and with
# no working JSON tool nothing is copied at all.
mkdir -p "$T/oldjq"
printf '#!/bin/sh\necho "jq: error: simulated old jq" >&2\nexit 3\n' > "$T/oldjq/jq"; chmod +x "$T/oldjq/jq"
if command -v python3 >/dev/null 2>&1; then
  PATH="$T/oldjq:$PATH" collect --offline --repo tgt
  OUTJ=$OUT
  check "T-k (failing jq): python3 takes over the incident extraction" has "$OUTJ/inputs.tsv" "allowlisted fields extracted (python3)"
  check "T-k (failing jq): the extract still holds the verdict" has "$OUTJ/inputs/incident1-INCIDENTS.json" "suspected"
  check "T-k (failing jq): and still drops the attacker" hasnt "$OUTJ/inputs/incident1-INCIDENTS.json" "ATTACKER-PII-ADDR"
else
  skp "T-k (failing jq): needs python3"
fi
TM_JSON_TOOL=none collect --offline --repo tgt --vulns other.json
OUTN=$OUT
check "T-k (no JSON tool): INCIDENTS.json is recorded, not copied" sh -c "! ls '$OUTN/inputs/' | grep -q INCIDENTS"
check "T-k (no JSON tool): other JSON is not copied either" has "$OUTN/inputs.tsv" "not copied: no working jq or python3 parsed it"
if command -v jq >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
  printf '[{"id": "F-1", "description": "authority not a signer"}]\n' > "$W/Incidents-Export.json"
  collect --offline --repo tgt --vulns Incidents-Export.json
  check "a schema-less JSON whose name mentions incidents is not copied" \
    has "$OUT/inputs.tsv" "not copied: could not confirm it is not an incident file"
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
    printf '{"schema": "auditor-incidents/1", "incidents": %s}\n' "$body" > "$W/incidents-$kind.json"
    TM_JSON_TOOL=$tool collect --offline --repo tgt --vulns "incidents-$kind.json"
    OUTK=$OUT
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
  python3 - "$W/report.pdf" <<'PY'
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
  collect --offline --repo tgt --vulns report.pdf
  OUT8=$OUT
  check "PDF: converted with pdftotext and recorded" has "$OUT8/inputs.tsv" "converted (pdftotext -layout)"
  check "PDF: the text is searchable" sh -c "grep -rq 'missing signer check' '$OUT8/inputs/'"
else
  skp "PDF: needs python3 and pdftotext"
fi

# =================================================================================================
# --detect: T3 and T4 offline, and it writes nothing.
# =================================================================================================
CLEAN="$T/clean"; mkrepo "$CLEAN"; put "$CLEAN" programs/c/src/lib.rs 'pub fn c() {}'; commit "$CLEAN" -m "initial"
CRUN=$(newrun "$CLEAN")
check "Rule 11d: collecting from inside the target (--repo .) exits 0" test "$(rc_in "$CLEAN" --offline --repo . --out "$CRUN/bootstrap")" = 0
check "Rule 11d: the target's git status stays clean after collection" test -z "$(git -C "$CLEAN" status --porcelain)"
check "Rule 11d: the run directory's .gitignore holds *, and bootstrap/ carries none of its own" \
  sh -c "[ \"\$(cat '$CLEAN/$CRUN/.gitignore')\" = '*' ] && [ ! -e '$CLEAN/$CRUN/bootstrap/.gitignore' ]"
check "Rule 11d: an output directory not named audit_<n>/bootstrap is refused (exit 2)" \
  test "$(rc_in "$CLEAN" --offline --repo . --out notaudit/bootstrap)" = 2
check "... and nothing is made" test ! -e "$CLEAN/notaudit"

put "$TGT" README.md 'Example AMM, forked from the upstream reference pool.'
put "$TGT" audits/Firm-2025.md '# Firm review 2025 — F-1: withdraw authority not a signer'
commit "$TGT" -m "docs: readme and prior review"
mkdir -p "$TGT/audit_1"; printf '# prior report\n' > "$TGT/audit_1/REPORT.md"
D1=$(cd "$W" && "$COLLECT" --detect --repo tgt --out audit_900/bootstrap 2>/dev/null)
check "--detect: T3 fires on a README fork phrase" sh -c "printf '%s\n' '$D1' | grep -q '^T3 yes readme-phrase'"
check "--detect: T4 fires on a prior audit_*/REPORT.md" sh -c "printf '%s\n' '$D1' | grep -q '^T4 yes prior-audit-dir'"
check "--detect: T4 fires on a report inside an audits/ directory" sh -c "printf '%s\n' '$D1' | grep -q '^T4 yes .*in-tree-report'"
check "--detect: writes nothing" test ! -e "$W/audit_900"
collect --offline --repo tgt
check "an in-tree report is ingested from the pinned tree" has "$OUT/inputs.tsv" "pinned tree: audits/Firm-2025.md"
D2=$(cd "$TGT" && "$COLLECT" --detect --repo . --out audit_1/bootstrap 2>/dev/null)
check "--detect: the current audit dir is not a prior audit" sh -c "printf '%s\n' '$D2' | grep -q '^T4 yes in-tree-report$'"
rm -rf "$TGT/audit_1"

# Links planted in the target's tree (an archive or a checkout can carry them) are never followed: T4,
# R6 and the incident files read the same whether what they point at exists or not.
LNK="$W/linked"; mkrepo "$LNK"; put "$LNK" programs/l/src/lib.rs 'pub fn l() {}'; commit "$LNK" -m "initial"
OUTL="$T/outside-links"; mkdir -p "$OUTL/proj" "$OUTL/incdir"
printf '# report kept elsewhere\n' > "$OUTL/proj/REPORT.md"; printf '# report kept elsewhere\n' > "$OUTL/report.md"
printf '{"schema": "auditor-incidents/1", "incidents": [{"id": "INC-OUTSIDE"}]}\n' > "$OUTL/INCIDENTS.json"
cp "$OUTL/INCIDENTS.json" "$OUTL/incdir/INCIDENTS.json"
ln -s "$OUTL/proj" "$LNK/audit_9"
mkdir "$LNK/audit_8"; ln -s "$OUTL/report.md" "$LNK/audit_8/REPORT.md"
mkdir "$LNK/incident_7"; ln -s "$OUTL/INCIDENTS.json" "$LNK/incident_7/INCIDENTS.json"
ln -s "$OUTL/incdir" "$LNK/incident_6"
ln -s "$OUTL/gone" "$LNK/incident_5"
DL=$(cd "$W" && "$COLLECT" --detect --repo linked --out audit_900/bootstrap 2>/dev/null)
check "--detect: T4 counts nothing through a link in the target's tree" sh -c "printf '%s\n' '$DL' | grep -qx 'T4 no none'"
links_seen() { # links_seen <out>: what R6 and inputs.tsv say about the target's audit_* and incident_* entries
  { section_of "$1/history.md" "R0"; section_of "$1/history.md" "R6"; grep -E 'audit_|incident_' "$1/inputs.tsv" | cut -f2-; } > "$2"
}
collect --offline --repo linked; links_seen "$OUT" "$T/links.present"
check "--offline: R6 lists a linked audit_<n> as a link, not followed" \
  has "$OUT/history.md" "$LNK/audit_9 (symbolic link, not followed)"
check "--offline: ... and a linked incident directory the same way, whether its target exists or not" \
  sh -c "grep -qF '$LNK/incident_6 (symbolic link, not followed)' '$OUT/history.md' && grep -qF '$LNK/incident_5 (symbolic link, not followed)' '$OUT/history.md'"
check "--offline: ... and a linked INCIDENTS.json" has "$OUT/history.md" "$LNK/incident_7/INCIDENTS.json (symbolic link, not followed)"
check "--offline: nothing behind a link is read" sh -c "! grep -rq 'INC-OUTSIDE\|kept elsewhere' '$OUT/'"
mv "$OUTL" "$OUTL.away"
collect --offline --repo linked; links_seen "$OUT" "$T/links.absent"
DL2=$(cd "$W" && "$COLLECT" --detect --repo linked --out audit_900/bootstrap 2>/dev/null)
mv "$OUTL.away" "$OUTL"
check "--offline: R0, R6 and inputs.tsv read the same with the links' targets gone" cmp -s "$T/links.present" "$T/links.absent"
check "--detect: ... and so does T4" test "$DL2" = "$DL"

# =================================================================================================
# Large inputs: under pipefail an early-exit reader (grep -q) can report the writer's SIGPIPE instead of
# the match. Every detection whose status matters must survive trees and configs far above a pipe buffer.
# =================================================================================================
BIGT="$W/bigtree"; mkrepo "$BIGT"; mkdir -p "$BIGT/docs"
i=0; while [ $i -lt 1500 ]; do
  printf '# page %s\n' "$i" > "$BIGT/docs/a-reasonably-long-documentation-page-name-number-$i.md"; i=$((i + 1))
done
git -C "$BIGT" add -- docs
put "$BIGT" audits/2025-firm-audit.md '# Firm review 2025 — F-1: withdraw authority not a signer'
put "$BIGT" programs/b/src/lib.rs 'pub fn b() {}'
commit "$BIGT" -m "docs and prior review"
DB=$(cd "$W" && "$COLLECT" --detect --repo bigtree --out audit_900/bootstrap 2>/dev/null)
check "large tree (1,500 Markdown files): T4 still finds the one report" sh -c "printf '%s\n' '$DB' | grep -q '^T4 yes in-tree-report'"
MR="$W/manyremotes"; mkrepo "$MR"
put "$MR" programs/m/src/lib.rs 'security_txt! { source_code: "https://github.com/example/own-repo" }'
commit "$MR" -m "initial"
{ printf '[remote "origin"]\n\turl = https://github.com/example/own-repo.git\n'
  i=0; while [ $i -lt 2000 ]; do
    printf '[remote "mirror%s"]\n\turl = https://mirror%s.example.invalid/some/long/path/to/repository-%s.git\n' "$i" "$i" "$i"; i=$((i + 1))
  done; } >> "$MR/.git/config"
DM=$(cd "$W" && "$COLLECT" --detect --repo manyremotes --out audit_900/bootstrap 2>/dev/null)
check "2,000 remotes: a source_code matching the first remote does not fire T3" sh -c "printf '%s\n' '$DM' | grep -q '^T3 no none'"
# A source_code string is compared as written, never expanded against the filesystem: "/*"-style
# patterns would otherwise stall on deep trees. Here the glob would expand to exactly the configured
# remote, so an expansion shows up as T3 not firing.
GL="$W/globsrc"; mkrepo "$GL"; mkdir -p "$T/globdir"; : > "$T/globdir/only-entry"
put "$GL" programs/g/src/lib.rs "security_txt! { source_code: \"$T/globdir/*\" }"
commit "$GL" -m "initial"
git -C "$GL" config remote.origin.url "$T/globdir/only-entry"
DG=$(cd "$W" && "$COLLECT" --detect --repo globsrc --out audit_900/bootstrap 2>/dev/null)
check "T3: a source_code glob is compared as a string, not expanded" \
  sh -c "printf '%s\n' '$DG' | grep -q '^T3 yes security_txt-source_code'"

# =================================================================================================
# T-m: audit memory is read only from a store passed with --audit-mem-db, and only from
# .audit-memory/audit.db or audit_<n>/audit-mem.db; the collector never looks for one in the target tree
# on its own. A copy of the collector under a stand-in installation root runs a fake audit-mem that
# leaves a mark, so "not read" is observed directly whether or not the real tools are built.
# =================================================================================================
FAKE="$T/fakeskill"; FAKEBIN="$FAKE/tools/auditor-tools/target/release"
mkdir -p "$FAKE/scripts/threat-model" "$FAKE/scripts/lib" "$FAKEBIN"
cp "$COLLECT" "$FAKE/scripts/threat-model/collect.sh"
cp "$ROOT/scripts/lib/confine.sh" "$FAKE/scripts/lib/confine.sh"
printf '#!/bin/sh\necho "$*" >> "%s/marks/audit-mem"\necho "{}"\n' "$T" > "$FAKEBIN/audit-mem"; chmod +x "$FAKEBIN/audit-mem"
MEMT="$T/memtgt"; mkrepo "$MEMT"
put "$MEMT" programs/m/src/lib.rs 'pub fn a() {}'
commit "$MEMT" -m "initial"
mkdir -p "$MEMT/.audit-memory"; printf 'db\n' > "$MEMT/.audit-memory/audit.db"
# fake_collect <args...>: the copy, from $MEMT (--repo .), into a new run directory; MOUT is its bootstrap/.
fake_collect() {
  local r
  rm -f "$T/marks/audit-mem"
  r=$(newrun "$MEMT"); MOUT="$MEMT/$r/bootstrap"
  (cd "$MEMT" && "$FAKE/scripts/threat-model/collect.sh" --offline --repo . --out "$r/bootstrap" --program-id Demo1111 "$@") >/dev/null 2>"$T/fake.err"
}
fake_collect
check "T-m: an untracked in-tree store is not read without --audit-mem-db" test ! -e "$T/marks/audit-mem"
check "T-m: ... no audit-mem-warm.json is saved" test ! -e "$MOUT/audit-mem-warm.json"
check "T-m: ... and R8 says no store was given" has "$MOUT/history.md" "NOT FOUND (no --audit-mem-db given"
fake_collect --audit-mem-db .audit-memory/audit.db
check "T-m: --audit-mem-db reads the store it names, through audit-mem warm" \
  grep -qxF -- "warm --db .audit-memory/audit.db --program-id=Demo1111" "$T/marks/audit-mem"
check "T-m: ... and saves audit-mem-warm.json" test -s "$MOUT/audit-mem-warm.json"
fake_collect --audit-mem-db ./.audit-memory/audit.db
check "T-m: ... written with a leading ./ too" grep -qF -- "--db .audit-memory/audit.db" "$T/marks/audit-mem"
r=$(newrun "$MEMT"); printf 'db\n' > "$MEMT/$r/audit-mem.db"
fake_collect --audit-mem-db "$r/audit-mem.db"
check "T-m: a store for one run, audit_<n>/audit-mem.db, is read" grep -qF -- "--db $r/audit-mem.db" "$T/marks/audit-mem"
git -C "$MEMT" add -f -- .audit-memory/audit.db; commit "$MEMT" -m "add a findings store"
fake_collect
check "T-m: a tracked in-tree store is not read without --audit-mem-db either" test ! -e "$T/marks/audit-mem"
printf 'db\n' > "$T/outside.db"
for db in "$T/outside.db" ../outside.db .audit-memory/other.db audit_1/other.db incident_1/audit-mem.db audit_x/audit-mem.db; do
  fake_collect --audit-mem-db "$db"
  check "T-m: --audit-mem-db $db is refused, and nothing is read" \
    sh -c "[ ! -e '$T/marks/audit-mem' ] && grep -q 'audit-mem-db must be .audit-memory/audit.db or audit_<n>/audit-mem.db' '$T/fake.err'"
done
mkdir -p "$T/realmem"; printf 'db\n' > "$T/realmem/audit.db"
mv "$MEMT/.audit-memory" "$T/moved-memory"; ln -s "$T/realmem" "$MEMT/.audit-memory"
fake_collect --audit-mem-db .audit-memory/audit.db
check "T-m: a store reached through a symbolic link is refused, and nothing is read" \
  sh -c "[ ! -e '$T/marks/audit-mem' ] && grep -q 'audit-mem-db passes through a symbolic link' '$T/fake.err'"
rm "$MEMT/.audit-memory"; mv "$T/moved-memory" "$MEMT/.audit-memory"
mkdir "$MEMT/audit_50"; printf 'db\n' > "$MEMT/audit_50/audit-mem.db"
fake_collect --audit-mem-db audit_50/audit-mem.db
check "T-m: an audit_<n>/audit-mem.db in a directory with no .gitignore of * is refused, and nothing is read" \
  sh -c "[ ! -e '$T/marks/audit-mem' ] && [ \"\$(cat '$T/fake.err')\" = 'collect.sh: refused: --audit-mem-db has no .gitignore holding exactly *: audit_50' ]"
# (rundir.sh makes no run directory while the repository tracks one, so --out's comes first.)
o=$(newrun "$MEMT"); r=$(newrun "$MEMT"); printf 'db\n' > "$MEMT/$r/audit-mem.db"
git -C "$MEMT" add -f -- "$r/audit-mem.db"; commit "$MEMT" -m "track a store"
rm -f "$T/marks/audit-mem"
(cd "$MEMT" && "$FAKE/scripts/threat-model/collect.sh" --offline --repo . --out "$o/bootstrap" --program-id Demo1111 \
   --audit-mem-db "$r/audit-mem.db") >/dev/null 2>"$T/fake.err"
check "T-m: ... and so is one in a run directory git tracks" \
  sh -c "[ ! -e '$T/marks/audit-mem' ] && [ \"\$(cat '$T/fake.err')\" = 'collect.sh: refused: --audit-mem-db is tracked by git: $r' ]"
git -C "$MEMT" rm -q --cached -- "$r/audit-mem.db"; commit "$MEMT" -m "untrack the store"

# =================================================================================================
# T-n: the collector writes only into a run directory this audit made (Rule 11d): never through a
# symbolic link, never into one that holds a link, never into one git tracks. Here the working
# directory is the target, as when the audit runs inside it; its run directories are made by hand.
# =================================================================================================
RD="$T/rundirs"; mkrepo "$RD"
put "$RD" programs/r/src/lib.rs 'pub fn a() { require!(x, E::A); }'
put "$RD" audit_3/REPORT.md '# shipped report'
commit "$RD" -m "initial"
mkrun() { mkdir "$RD/$1" && printf '*\n' > "$RD/$1/.gitignore"; }   # mkrun <name>: a run directory by hand
mkdir -p "$T/elsewhere"
mkrun audit_1; ln -s "$T/elsewhere" "$RD/audit_1/bootstrap"
mkrun audit_2; mkdir "$RD/audit_2/bootstrap"; ln -s "$T/elsewhere/gitignore-target" "$RD/audit_2/bootstrap/.gitignore"
ln -s "$T/elsewhere" "$RD/audit_4"
check "T-n: a bootstrap dir that is a symbolic link is refused (exit 2)" test "$(rc_in "$RD" --offline --repo . --out audit_1/bootstrap)" = 2
check "T-n: ... also when --out ends in a slash" test "$(rc_in "$RD" --offline --repo . --out audit_1/bootstrap/)" = 2
check "T-n: a bootstrap dir that holds a symbolic link is refused (exit 2)" test "$(rc_in "$RD" --offline --repo . --out audit_2/bootstrap)" = 2
check "T-n: ... saying the run directory holds one" refused_with "the run directory holds a symbolic link: audit_2"
check "T-n: an audit_<n> that is a symbolic link is refused (exit 2)" test "$(rc_in "$RD" --offline --repo . --out audit_4/bootstrap)" = 2
check "T-n: a . component cannot hide the audit_<n> parent (exit 2)" test "$(rc_in "$RD" --offline --repo . --out audit_4/./bootstrap)" = 2
check "T-n: --detect refuses an --out through a symbolic link too (exit 2)" test "$(rc_in "$RD" --detect --repo . --out audit_4/bootstrap)" = 2
check "T-n: nothing was written through any of the links" test -z "$(ls -A "$T/elsewhere")"
check "T-n: a tracked audit_<n> is refused (exit 2)" test "$(rc_in "$RD" --offline --repo . --out audit_3/bootstrap)" = 2
check "T-n: ... nothing is created in it and git status stays clean" \
  sh -c "[ ! -e '$RD/audit_3/bootstrap' ] && [ -z \"\$(git -C '$RD' status --porcelain --untracked-files=no)\" ]"
mkrun audit_8; mkrun Audit_9
git -C "$RD" add -f -- Audit_9/.gitignore
check "T-n: an audit_<n> tracked in another letter case is refused (exit 2)" test "$(rc_in "$RD" --offline --repo . --out audit_9/bootstrap)" = 2
git -C "$RD" rm -q --cached -- Audit_9/.gitignore; rm -rf "$RD/Audit_9"
# A working directory reached through a link above it, the operator's own, is resolved once and used.
ln -s "$RD" "$T/to-rd"
check "T-n: a working directory reached through the operator's link above it is used (exit 0)" \
  test "$(rc_in "$T/to-rd" --offline --repo . --out audit_8/bootstrap)" = 0
check "T-n: ... and the output lands in the run directory" test -s "$RD/audit_8/bootstrap/history.md"
# A re-run replaces the outputs of the run before; a file the collector did not write is left alone.
printf 'stale\n' > "$RD/audit_8/bootstrap/diffs/target-stale.diff"
printf 'keep me\n' > "$RD/audit_8/bootstrap/notes.md"
check "T-n: a re-run into the same run directory exits 0" test "$(rc_in "$RD" --offline --repo . --out audit_8/bootstrap)" = 0
check "T-n: ... removing the diffs of the run before" test ! -e "$RD/audit_8/bootstrap/diffs/target-stale.diff"
check "T-n: ... and leaving a file it did not write" test "$(cat "$RD/audit_8/bootstrap/notes.md")" = "keep me"
check "T-n: ... with new outputs, each a file of its own" \
  sh -c "[ -s '$RD/audit_8/bootstrap/history.md' ] && [ -s '$RD/audit_8/bootstrap/inputs.tsv' ]"
check "T-n: the output is readable by its owner only" test "$(ls -l "$RD/audit_8/bootstrap/history.md" | cut -c1-10)" = '-rw-------'
if command -v jq >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
  inc() { printf '{"schema": "auditor-incidents/1", "incidents": [{"id": "%s", "verdict": "suspected"}]}\n' "$1"; }
  mkdir -p "$RD/incident_6" "$RD/incident_7" "$T/elsewhere-inc/dir"
  inc INC-RUN-OK > "$RD/incident_6/INCIDENTS.json"
  inc INC-LINKED-FILE > "$T/elsewhere-inc/file.json"; ln -s "$T/elsewhere-inc/file.json" "$RD/incident_7/INCIDENTS.json"
  inc INC-LINKED-DIR > "$T/elsewhere-inc/dir/INCIDENTS.json"; ln -s "$T/elsewhere-inc/dir" "$RD/incident_8"
  put "$RD" incident_9/INCIDENTS.json "$(inc INC-TRACKED)"; commit "$RD" -m "ship an incident file"
  mkrun audit_5; printf '# intake\n' > "$RD/audit_5/intake.md"
  rc_in "$RD" --offline --repo . --out audit_5/bootstrap >/dev/null
  check "T-n: an untracked audit_<n> without links is reused" test -s "$RD/audit_5/bootstrap/history.md"
  check "T-n: an incident file written in place is still extracted" sh -c "grep -rq 'INC-RUN-OK' '$RD/audit_5/bootstrap/inputs/'"
  for bad in INC-LINKED-FILE INC-LINKED-DIR INC-TRACKED; do
    check "T-n: $bad is not read" sh -c "! grep -rq '$bad' '$RD/audit_5/bootstrap/inputs/'"
  done
  check "T-n: inputs.tsv records the linked incident file as skipped" \
    sh -c "grep -F 'incident_7/INCIDENTS.json' '$RD/audit_5/bootstrap/inputs.tsv' | grep -q 'skipped: symbolic link'"
  check "T-n: inputs.tsv records a linked incident dir as skipped, not followed" \
    sh -c "grep -F 'incident_8' '$RD/audit_5/bootstrap/inputs.tsv' | grep -q 'skipped: symbolic link (directory), not followed'"
  check "T-n: inputs.tsv records the tracked incident file as skipped" \
    sh -c "grep -F 'incident_9/INCIDENTS.json' '$RD/audit_5/bootstrap/inputs.tsv' | grep -q 'skipped: tracked'"
else
  skp "T-n incident files: needs jq or python3"
fi
# A link that appears in the run directory while the collector runs is found when it is checked again,
# before anything is copied in. The stand-in jq plants it on its first call.
if command -v jq >/dev/null 2>&1; then
  REALJQ=$(command -v jq)
  mkdir -p "$T/plantjq"
  printf '#!/bin/sh\n[ -L "%s/audit_10/late" ] || ln -s "%s/elsewhere" "%s/audit_10/late"\nexec "%s" "$@"\n' "$RD" "$T" "$RD" "$REALJQ" > "$T/plantjq/jq"
  chmod +x "$T/plantjq/jq"
  mkrun audit_10
  inc INC-LATE > "$W/late.json"; cp "$W/late.json" "$RD/late.json"
  check "T-n: a link that appears during the run is refused before any output is copied in (exit 2)" \
    test "$(cd "$RD" && PATH="$T/plantjq:$PATH" TM_JSON_TOOL=jq "$COLLECT" --offline --repo . --out audit_10/bootstrap --vulns late.json >/dev/null 2>"$T/rc.err"; echo $?)" = 2
  check "T-n: ... saying the run directory holds a link" refused_with "the run directory holds a symbolic link: audit_10"
  check "T-n: ... and nothing was copied in" test ! -e "$RD/audit_10/bootstrap"
  check "T-n: ... nor through the link" test -z "$(ls -A "$T/elsewhere")"
else
  skp "T-n late link: needs jq"
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
elif ! git clone -q --filter=blob:none --no-local "file://$SRV" "$W/partial" >/dev/null 2>&1; then
  skp "T-p: this git could not make a blobless partial clone"
else
  printf '#!/bin/sh\ntouch "%s/marks/promisor-fetch"\nexit 1\n' "$T" > "$T/bin/mark-fetch"; chmod +x "$T/bin/mark-fetch"
  git -C "$W/partial" config remote.origin.uploadpack "$T/bin/mark-fetch"
  rm -f "$T/marks/promisor-fetch"
  git -C "$W/partial" log -p >/dev/null 2>&1
  if [ -e "$T/marks/promisor-fetch" ]; then ok "T-p sanity: plain 'git log -p' in the partial clone fetches from its promisor"
  else skp "T-p sanity: this git did not fetch a missing object"; fi
  rm -f "$T/marks/promisor-fetch"
  PRUN=$(newrun)
  check "T-p: a partial clone is refused in --detect (exit 3)" test "$(rc --detect --repo partial --out audit_900/bootstrap)" = 3
  check "T-p: ... and in a full run (exit 3)" test "$(rc --offline --repo partial --out "$PRUN/bootstrap")" = 3
  check "T-p: ... with a message naming the promisor remote" has "$T/rc.err" "the target is a partial clone"
  check "T-p: the promisor remote is never contacted" test ! -e "$T/marks/promisor-fetch"
  check "T-p: nothing is written for a refused target" test ! -e "$W/$PRUN/bootstrap"
  rm -f "$T/marks/promisor-fetch"
  collect --offline --repo tgt --parent partial
  check "T-p: a local --parent that is a partial clone is not used" has "$OUT/history.md" "is a partial clone"
  check "T-p: ... and its promisor remote is never contacted" test ! -e "$T/marks/promisor-fetch"
fi
git clone -q --depth 1 --no-local "file://$SRV" "$W/shallow" >/dev/null 2>&1
collect --offline --repo shallow
check "T-p: a shallow clone is collected with a note that its history is cut" \
  has "$OUT/history.md" "Shallow clone: history before the shallow boundary is missing"
check "T-p: a full clone carries no such note" hasnt "$H1" "Shallow clone:"

# =================================================================================================
# T-q: target text in inputs.tsv and history.md stays one value per cell and one row per line: control
# characters are escaped and long values cut, whichever JSON tool runs.
# =================================================================================================
CR=$(printf '\r'); ESC=$(printf '\033'); TB=$(printf '\t')
tsv_ok() { # tsv_ok <inputs.tsv>: every row has exactly six cells and no carriage return
  awk -F '\t' 'NF != 6 { bad = 1 } END { exit bad }' "$1" && ! grep -q "$CR" "$1"
}
fences_ok() { # fences_ok <history.md>: code fences open and close in pairs, no stray CR or ESC
  [ $(( $(grep -c '^```' "$1") % 2 )) -eq 0 ] && ! grep -q "$CR" "$1" && ! grep -q "$ESC" "$1"
}
TQ="$W/textq"; mkrepo "$TQ"
put "$TQ" programs/q/src/lib.rs 'pub fn q() { require!(x, E::Q); }'
commit "$TQ" -m "initial"
put "$TQ" programs/q/src/lib.rs 'pub fn q() {}'
commit "$TQ" -m "$(printf 'Tidy q%s```%s[31m %s' "$CR" "$ESC" "$(i=0; while [ $i -lt 120 ]; do printf 'long-subject-'; i=$((i + 1)); done)")"
git -C "$TQ" config remote.mirror.url "$(printf 'https://example.invalid/m\n```\n## Extra heading')"
# The schema value holds a TAB and a newline (JSON escapes \t and \n) followed by a would-be manifest row.
printf '{"schema": "auditor-incidents/9\\t\\n99\\textra-row\\tjson\\t-\\t-\\textra", "incidents": []}\n' > "$W/control-schema.json"
mkdir -p "$TQ/incident_x
77${TB}extra-dir"
cp "$W/control-schema.json" "$TQ/incident_x
77${TB}extra-dir/INCIDENTS.json"
TQOUT=""
for tool in jq python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then skp "T-q ($tool): $tool not installed"; continue; fi
  TM_JSON_TOOL=$tool collect --offline --repo textq --vulns control-schema.json
  OUTQ=$OUT; [ -n "$TQOUT" ] || TQOUT=$OUTQ
  check "T-q ($tool): every inputs.tsv row has six cells" tsv_ok "$OUTQ/inputs.tsv"
  check "T-q ($tool): a schema string cannot add an inputs.tsv row" sh -c "! grep -q '^99' '$OUTQ/inputs.tsv'"
  check "T-q ($tool): ... it is recorded with its control characters escaped" has "$OUTQ/inputs.tsv" 'auditor-incidents/9\t\n99\textra-row'
  check "T-q ($tool): an incident directory name cannot add an inputs.tsv row" sh -c "! grep -q '^77' '$OUTQ/inputs.tsv'"
  check "T-q ($tool): ... it is recorded escaped" has "$OUTQ/inputs.tsv" 'incident_x\n77\textra-dir/INCIDENTS.json'
  check "T-q ($tool): history.md keeps its code fences paired, with no CR or ESC" fences_ok "$OUTQ/history.md"
done
if [ -n "$TQOUT" ] && [ -s "$TQOUT/history.md" ]; then
  OUTQ=$TQOUT
  check "T-q: a multi-line remote URL stays on one R6 line" sh -c "! grep -q '^## Extra heading' '$OUTQ/history.md'"
  check "T-q: ... shown escaped on the remote's own line" has "$OUTQ/history.md" 'remote.mirror.url https://example.invalid/m\n```\n'
  check "T-q: a CR in a commit subject is shown as \\r" has "$OUTQ/history.md" 'Tidy q\r```'
  check "T-q: an incident directory name in R6 is shown escaped" has "$OUTQ/history.md" 'incident_x\n77\textra-dir/INCIDENTS.json'
  check "T-q: a row with a long subject is cut, ending in ..." \
    sh -c "awk '/^## R3/,/^## R4/' '$OUTQ/history.md' | grep 'long-subject' | awk 'length(\$0) > 520 || !/[.][.][.]\$/ { bad = 1 } END { exit bad || NR != 1 }'"
else
  skp "T-q history checks: needs jq or python3"
fi

# =================================================================================================
# T-r: moves. Within one commit, identical guard text nets out across files and renames are detected,
# so a pure move prints nothing; a guard edited as it moves still prints both sides.
# =================================================================================================
MV="$W/moves"; mkrepo "$MV"
put "$MV" programs/m/src/vault.rs '#[account(mut, has_one = authority)]
pub struct Vault {}'
put "$MV" programs/m/src/lib.rs 'pub fn deposit(a: u64) -> Result<()> { require!(a > 0, E::Zero); Ok(()) }
pub fn withdraw(a: u64) -> Result<()> { require!(a <= cap, E::Cap); Ok(()) }'
put "$MV" programs/m/src/limits.rs 'pub fn f(a: u64) -> Result<()> { require!(a > 1, E::Min); Ok(()) }'
commit "$MV" -m "initial"
git -C "$MV" mv programs/m/src/vault.rs programs/m/src/vault_accounts.rs
commit "$MV" -m "Rename vault module"
C_GITMV=$(short "$MV" HEAD)
put "$MV" programs/m/src/lib.rs 'pub fn deposit(a: u64) -> Result<()> { require!(a > 0, E::Zero); Ok(()) }'
put "$MV" programs/m/src/withdraw.rs 'pub fn withdraw(a: u64) -> Result<()> { require!(a <= cap, E::Cap); Ok(()) }'
commit "$MV" -m "Split withdraw into its own module"
C_SPLIT=$(short "$MV" HEAD)
git -C "$MV" rm -q programs/m/src/limits.rs
put "$MV" programs/m/src/bounds.rs 'pub fn f(a: u64) -> Result<()> { require!(a > 2, E::Min); Ok(()) }'
commit "$MV" -m "Move f"
C_MOVEDIT=$(short "$MV" HEAD)
collect --offline --repo moves
RMV="$T/rmv.txt"; section_of "$OUT/history.md" "R3" > "$RMV"
check "T-r: a git mv of a small file prints no row" sh -c "! grep -q '^$C_GITMV ' '$RMV'"
check "T-r: a file split prints no ADDED-QUIET (or REMOVED) for the moved guard" sh -c "! grep -q '^$C_SPLIT ' '$RMV'"
check "T-r: a guard edited as it moves prints its old text as REMOVED in the old file" \
  has "$RMV" "$C_MOVEDIT $(git -C "$MV" log -1 --format=%ad --date=short "$C_MOVEDIT") REMOVED x1 programs/m/src/limits.rs: pub fn f(a: u64) -> Result<()> { require!(a > 1, E::Min); Ok(()) }"
check "T-r: ... and its new text as ADDED-QUIET in the new file" \
  has "$RMV" "ADDED-QUIET x1 programs/m/src/bounds.rs: pub fn f(a: u64) -> Result<()> { require!(a > 2, E::Min); Ok(()) }"
DR="$W/dirmove"; mkrepo "$DR"
DR_BODY=$(i=0; while [ $i -lt 70 ]; do printf '    require!(v%s > 0, E::V%s);\n' "$i" "$i"; i=$((i + 1)); done)
put "$DR" programs/old/src/lib.rs "pub fn check() -> Result<()> {
$DR_BODY
    require!(payer.is_signer, E::Signer);
    Ok(())
}"
commit "$DR" -m "initial"
put "$DR" programs/old/src/lib.rs "pub fn check() -> Result<()> {
$DR_BODY
    Ok(())
}"
commit "$DR" -m "Simplify checks"
C_REAL=$(short "$DR" HEAD)
git -C "$DR" mv programs/old programs/new
commit "$DR" -m "Rename program directory"
collect --offline --repo dirmove
OUTDR=$OUT
check "T-r: after a directory rename of 70 guards, an older real removal still appears" \
  sh -c "awk '/^## R3/,/^## R4/' '$OUTDR/history.md' | grep -q '^$C_REAL .* REMOVED x1 programs/old/src/lib.rs: require!(payer.is_signer, E::Signer);'"
check "T-r: ... and R3 is not truncated by the rename" sh -c "! awk '/^## R3/,/^## R4/' '$OUTDR/history.md' | grep -q '^TRUNCATED'"

# =================================================================================================
# T-s: saved diffs. Each holds the commit its row cites (by full id, never a same-named ref), only the
# files its rows name, and a visible TRUNCATED marker wherever it is cut, naming git-ro.sh's show of the
# repository by its path inside the working directory.
# =================================================================================================
GITRO="\"$ROOT/scripts/git-ro.sh\""
# rest_cmd / msg_cmd <diff file>: the command a cut diff's or a cut message's TRUNCATED line names
rest_cmd() { sed -n 's/^TRUNCATED ([0-9]* more lines; the rest: \(.*\))$/\1/p' "$1"; }
msg_cmd()  { sed -n 's/^TRUNCATED ([0-9]* more message lines; the whole message: \(.*\))$/\1/p' "$1"; }
SD="$W/saved"; mkrepo "$SD"
put "$SD" programs/s/src/guard.rs '#[account(mut, has_one = authority)]'
put "$SD" programs/s/src/other.rs '// other module'
commit "$SD" -m "initial"
put "$SD" programs/s/src/guard.rs '#[account(mut)]'
commit "$SD" -m "Rework guard accounts"
C_SD=$(short "$SD" HEAD); F_SD=$(git -C "$SD" rev-parse HEAD)
DECOY=$(printf 'decoy commit\n' | git -C "$SD" commit-tree "$(git -C "$SD" rev-parse 'HEAD~1^{tree}')")
git -C "$SD" update-ref "refs/$C_SD" "$DECOY"
git -C "$SD" update-ref "refs/tags/$C_SD" "$DECOY"
BIGMSG=$(i=0; while [ $i -lt 420 ]; do printf 'migration note line %s\n' "$i"; i=$((i + 1)); done)
BIGOTHER=$(i=0; while [ $i -lt 600 ]; do printf '// migrated line %s\n' "$i"; i=$((i + 1)); done)
put "$SD" programs/s/src/other.rs "$BIGOTHER"
put "$SD" programs/s/src/vault.rs '#[account(mut, has_one = owner)]'
commit "$SD" -m "Migrate modules" -m "$BIGMSG"
put "$SD" programs/s/src/vault.rs '#[account(mut)]'
put "$SD" programs/s/src/other.rs '// other module'
commit "$SD" -m "Migrate modules back" -m "$BIGMSG"
C_BIG=$(short "$SD" HEAD); F_BIG=$(git -C "$SD" rev-parse HEAD)
BIGGUARD=$(i=0; while [ $i -lt 500 ]; do printf '// padding line %s\n' "$i"; i=$((i + 1)); done)
put "$SD" programs/s/src/huge.rs "${BIGGUARD}#[account(mut, has_one = admin)]"
commit "$SD" -m "Add admin module"
put "$SD" programs/s/src/huge.rs '// emptied'
commit "$SD" -m "Remove admin module"
C_HUGE=$(short "$SD" HEAD); F_HUGE=$(git -C "$SD" rev-parse HEAD)
collect --offline --repo saved
OUTSD=$OUT
check "T-s: a ref named like the row's short id does not change the saved diff" \
  sh -c "head -n 1 '$OUTSD/diffs/target-$C_SD.diff' | grep -qx 'commit $F_SD' && ! grep -q 'decoy commit' '$OUTSD/diffs/target-$C_SD.diff'"
check "T-s: a large migration commit's saved diff still holds the row's hunk" \
  grep -qF -- '-#[account(mut, has_one = owner)]' "$OUTSD/diffs/target-$C_BIG.diff"
check "T-s: ... it holds only the files the rows name" sh -c "! grep -q 'other.rs' '$OUTSD/diffs/target-$C_BIG.diff'"
check "T-s: ... and its long message is cut with a marker naming git-ro.sh's show of the full id" \
  test "$(msg_cmd "$OUTSD/diffs/target-$C_BIG.diff")" = "$GITRO --repo 'saved' show --no-patch $F_BIG"
check "T-s: a cut diff ends in a TRUNCATED marker naming git-ro.sh, the full id and the quoted path" \
  test "$(rest_cmd "$OUTSD/diffs/target-$C_HUGE.diff")" = "$GITRO --repo 'saved' show $F_HUGE -- 'programs/s/src/huge.rs'"
check "T-s: every TRUNCATED line in diffs/ names git-ro.sh" \
  sh -c "! grep -h '^TRUNCATED' '$OUTSD'/diffs/* | grep -vqF '$ROOT/scripts/git-ro.sh'"
check "T-s: no TRUNCATED line names a raw git call" sh -c "! grep -h '^TRUNCATED' '$OUTSD'/diffs/* | grep -q 'GIT_NO_LAZY_FETCH'"
( cd "$W" && bash -c "$(rest_cmd "$OUTSD/diffs/target-$C_HUGE.diff")" ) > "$T/rest.out" 2>&1
check "T-s: the named command, run from the working directory, shows the rest of the diff" \
  grep -q '^-.*#\[account(mut, has_one = admin)\]$' "$T/rest.out"
SDRUN=$(newrun "$SD")
rc_in "$SD" --offline --repo . --out "$SDRUN/bootstrap" >/dev/null
check "T-s: with --repo ., the marker names git-ro.sh with no --repo" \
  test "$(rest_cmd "$SD/$SDRUN/bootstrap/diffs/target-$C_HUGE.diff")" = "$GITRO show $F_HUGE -- 'programs/s/src/huge.rs'"
git clone -q "$SD" "$T/saved-outside"
collect --network --repo "$T/saved-outside"
check "T-s: in --network, a repository outside the working directory is read from a copy made inside it" \
  test "$(sed -n 's/^TRUNCATED ([0-9]* more lines; \(.*\))$/\1/p' "$OUT/diffs/target-$C_HUGE.diff")" = \
       "the rest, from a copy of the repository inside the working directory, named with --repo: $GITRO show $F_HUGE -- 'programs/s/src/huge.rs'"

# =================================================================================================
# T-t: URLs are written without credentials: userinfo, query string and fragment become *** in
# history.md, inputs.tsv and on stderr.
# =================================================================================================
UR="$W/urls"; mkrepo "$UR"
put "$UR" programs/u/src/lib.rs 'pub fn u() {}'
commit "$UR" -m "initial"
git -C "$UR" config remote.origin.url 'https://bot:TOKEN-REMOTE@example.invalid/org/repo.git?token=QUERY-REMOTE'
collect --offline --repo urls \
  --parent 'https://user:TOKEN-PARENT@example.invalid/org/parent.git?token=QUERY-PARENT#FRAG-PARENT' \
  --vulns 'https://example.invalid/reports/r1.pdf?X-Amz-Signature=SIG-VULNS#FRAG-VULNS'
OUTUR=$OUT
for secret in TOKEN-REMOTE QUERY-REMOTE TOKEN-PARENT QUERY-PARENT FRAG-PARENT SIG-VULNS FRAG-VULNS; do
  check "T-t: $secret appears in neither history.md nor inputs.tsv" \
    sh -c "! grep -q '$secret' '$OUTUR/history.md' && ! grep -q '$secret' '$OUTUR/inputs.tsv'"
done
check "T-t: the parent URL keeps its host and path" has "$OUTUR/history.md" 'https://***@example.invalid/org/parent.git?***#***'
check "T-t: the --vulns URL keeps its host and path" has "$OUTUR/inputs.tsv" 'https://example.invalid/reports/r1.pdf?***#***'
check "T-t: a rejected URL is refused (exit 2)" \
  test "$(rc --offline --repo urls --out "$(newrun)/bootstrap" --parent 'ssh://user:TOKEN-SSH@example.invalid/x?k=QUERY-SSH')" = 2
check "T-t: ... and echoed on stderr without its credentials" \
  sh -c "grep -q 'ssh://\*\*\*@example.invalid/x?\*\*\*' '$T/rc.err' && ! grep -q 'TOKEN-SSH\|QUERY-SSH' '$T/rc.err'"

# =================================================================================================
# T-u: a fork that records the parent's fix with `git merge -s ours` (history merged, code not) is
# still compared from its own fork point, so the fix it lacks is listed as absent.
# =================================================================================================
PO="$W/par-ours"; mkrepo "$PO"
put "$PO" "$AMM" "$AMM_P1"
commit "$PO" -m "amm v1"
PO1=$(short "$PO" HEAD)
FO="$W/fork-ours"; git clone -q "$PO" "$FO"
put "$FO" programs/amm/src/extra.rs '// fork-specific module'
commit "$FO" -m "fork: add extra module"
put "$PO" "$AMM" 'pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    require_keys_eq!(ctx.accounts.vault.key(), pool.vault);
    Ok(())
}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require!(amount > 0, AmmError::ZeroAmount);
    Ok(())
}'
commit "$PO" -m "fix: reject zero withdrawals (security)"
git -C "$FO" fetch -q "$PO" main:refs/remotes/upstream/main
git -C "$FO" merge -q -s ours --no-edit upstream/main
collect --offline --repo fork-ours --parent par-ours
OUTFO=$OUT
check "T-u: after a merge -s ours, the fork point is the fork's own (first-parent) one" \
  sh -c "grep -q '^fork point: $PO1 ' '$OUTFO/history.md'"
check "T-u: ... and the parent's fix the fork never applied is listed as absent" \
  sh -c "grep -q 'require!(amount > 0, AmmError::ZeroAmount);.*\[text absent from target @ pin - verify\]' '$OUTFO/history.md'"

# =================================================================================================
# T-v: the run-directory and partial-clone checks refuse when git or find cannot answer, rather than
# treating "no answer" as "not tracked" or "no links". A stand-in git reports the error git gives for a
# repository owned by another user (safe.directory) for the calls under test and runs the real git
# for everything else.
# =================================================================================================
mkdir -p "$T/gitwrap-tracked" "$T/gitwrap-config"
printf '#!/bin/sh\nfor a in "$@"; do case "$a" in --is-inside-work-tree|ls-files) echo "fatal: detected dubious ownership in repository at '"'"'$PWD'"'"'" >&2; exit 128 ;; esac; done\nexec "%s" "$@"\n' "$REALGIT" > "$T/gitwrap-tracked/git"
printf '#!/bin/sh\nfor a in "$@"; do case "$a" in --get-regexp) echo "fatal: detected dubious ownership in repository at '"'"'$PWD'"'"'" >&2; exit 128 ;; esac; done\nexec "%s" "$@"\n' "$REALGIT" > "$T/gitwrap-config/git"
chmod +x "$T/gitwrap-tracked/git" "$T/gitwrap-config/git"
FC="$T/failclosed"; mkrepo "$FC"
put "$FC" programs/f/src/lib.rs 'pub fn f() {}'
commit "$FC" -m "initial"
FR1=$(newrun "$FC"); FR2=$(newrun "$FC"); FR3=$(newrun "$FC")
check "T-v: when git cannot say whether the run directory is tracked, it is refused (exit 2)" \
  test "$(cd "$FC" && PATH="$T/gitwrap-tracked:$PATH" "$COLLECT" --offline --repo . --out "$FR1/bootstrap" >/dev/null 2>"$T/rc.err"; echo $?)" = 2
check "T-v: ... saying so" refused_with "git cannot tell whether the run directory is tracked: $FR1"
check "T-v: ... and nothing is written" test ! -e "$FC/$FR1/bootstrap"
mkdir -p "$FC/$FR2/bootstrap/sub"; ln -s "$T/elsewhere" "$FC/$FR2/bootstrap/sub/link"
chmod 0300 "$FC/$FR2/bootstrap/sub"
check "T-v: a run directory that cannot be fully read (a 0300 subdirectory) is refused (exit 2)" \
  test "$(rc_in "$FC" --offline --repo . --out "$FR2/bootstrap")" = 2
chmod 0700 "$FC/$FR2/bootstrap/sub"
check "T-v: ... and nothing is written through the link it hides" test -z "$(ls -A "$T/elsewhere")"
check "T-v: when git cannot read the target's config, the partial-clone check refuses (exit 3)" \
  test "$(cd "$FC" && PATH="$T/gitwrap-config:$PATH" "$COLLECT" --offline --repo . --out "$FR3/bootstrap" >/dev/null 2>"$T/rc.err"; echo $?)" = 3
check "T-v: ... and nothing is written" test ! -e "$FC/$FR3/bootstrap"
check "T-v: git missing from PATH is refused (exit 2)" \
  test "$(cd "$FC" && PATH="$T/bin" /bin/bash "$COLLECT" --offline --repo . --out "$FR3/bootstrap" >/dev/null 2>"$T/rc.err"; echo $?)" = 2

# =================================================================================================
# T-w: a TRUNCATED line is inert text. Each path in the command it names is escaped like other target
# text and single-quoted, so pasting the command runs git-ro.sh on that path and nothing else.
# =================================================================================================
QP="$W/quoted"; mkrepo "$QP"
QNAME="a b;\$(touch ran-subst)\`touch ran-tick\`|touch ran-pipe&'q'.rs"
QPAD=$(i=0; while [ $i -lt 450 ]; do printf '// padding line %s\n' "$i"; i=$((i + 1)); done)
put "$QP" "programs/q/src/$QNAME" "$QPAD
#[account(mut, has_one = quoted_admin)]"
commit "$QP" -m "Add quoted module"
put "$QP" "programs/q/src/$QNAME" '// emptied'
commit "$QP" -m "Empty quoted module"
C_QP=$(short "$QP" HEAD); F_QP=$(git -C "$QP" rev-parse HEAD)
collect --offline --repo quoted
QHINT=$(rest_cmd "$OUT/diffs/target-$C_QP.diff")
check "T-w: a path with spaces and shell metacharacters is one single-quoted word in the TRUNCATED line" \
  test "$QHINT" = "$GITRO --repo 'quoted' show $F_QP -- 'programs/q/src/a b;\$(touch ran-subst)\`touch ran-tick\`|touch ran-pipe&'\\''q'\\''.rs'"
( cd "$W" && bash -c "$QHINT" ) > "$T/quoted-hint.out" 2>&1
check "T-w: run as pasted, the command runs nothing but git-ro.sh" \
  sh -c "[ ! -e '$W/ran-subst' ] && [ ! -e '$W/ran-tick' ] && [ ! -e '$W/ran-pipe' ] && [ ! -e '$QP/ran-subst' ]"
check "T-w: ... and shows the rest of that file's diff" grep -qF -- '-#[account(mut, has_one = quoted_admin)]' "$T/quoted-hint.out"

# =================================================================================================
# T-x: in --network, a local --vulns path is read only when it is not a symbolic link and reaches its
# file through no directory link inside the target tree; inputs.tsv records every skip. A directory link
# outside the tree (the caller's own) is followed. (--detect and --offline refuse every link.)
# =================================================================================================
mkdir -p "$T/vx-outside" "$T/vx-real"
printf '# VX-SECRET-FILE\n' > "$T/vx-outside/secret.md"
printf '# VX-SECRET-DIR\n' > "$T/vx-outside/report.md"
printf '# VX-USER-LINKED-DIR\n' > "$T/vx-real/review.md"
ln -s "$T/vx-real" "$T/vx-user-dir"
ln -s "$T/vx-outside/secret.md" "$T/vx-user-file.md"
VX="$W/vlinks"; mkrepo "$VX"
put "$VX" programs/v/src/lib.rs 'pub fn v() {}'
commit "$VX" -m "initial"
mkdir -p "$VX/audits"
ln -s "$T/vx-outside/secret.md" "$VX/audits/prior.md"
ln -s "$T/vx-outside" "$VX/reports"
collect --network --repo vlinks --vulns "$VX/audits/prior.md" --vulns "$VX/reports/report.md" \
  --vulns "$T/vx-user-file.md" --vulns "$T/vx-user-dir/review.md"
OUTVX=$OUT
check "T-x: a --vulns file in the target tree that is a symbolic link is not copied" \
  sh -c "! grep -rq 'VX-SECRET-FILE' '$OUTVX/inputs/'"
check "T-x: a --vulns path through a directory link in the target tree is not copied" \
  sh -c "! grep -rq 'VX-SECRET-DIR' '$OUTVX/inputs/'"
for vx in audits/prior.md reports/report.md vx-user-file.md; do
  check "T-x: inputs.tsv records $vx as a skipped symbolic link" \
    sh -c "grep -F '$vx' '$OUTVX/inputs.tsv' | grep -q 'skipped: symbolic link'"
done
check "T-x: a --vulns path through the caller's own directory link outside the tree is copied" \
  sh -c "grep -F 'vx-user-dir/review.md' '$OUTVX/inputs.tsv' | grep -q 'copied' && grep -rq 'VX-USER-LINKED-DIR' '$OUTVX/inputs/'"
check "T-x: --offline refuses the same link in the tree (exit 2)" \
  test "$(rc --offline --repo vlinks --out "$(newrun)/bootstrap" --vulns vlinks/audits/prior.md)" = 2

# =================================================================================================
# The case file: hostile argument vectors, each refused with one stderr line, nothing on stdout, and
# nothing changed in the working directory. It runs in $CW, which holds the repository tgt, the run
# directory audit_1 (made by rundir.sh), and the links tgt-link (to tgt) and audit_2 (to audit_1).
# =================================================================================================
SHELLS=("$BASH")
if [ -x /bin/bash ] && [ "$(/bin/bash -c 'printf %s "$BASH_VERSION"')" != "$BASH_VERSION" ]; then
  SHELLS+=(/bin/bash)
fi
echo "# shells: ${SHELLS[*]}"
CW="$T/cases-wt"; mkdir -p "$CW"; mkrepo "$CW/tgt"
put "$CW/tgt" programs/c/src/lib.rs 'pub fn c() {}'; commit "$CW/tgt" -m initial
newrun "$CW" >/dev/null
ln -s tgt "$CW/tgt-link"; ln -s audit_1 "$CW/audit_2"
ctree() { (cd "$CW" && find . -path ./tgt/.git -prune -o -print | LC_ALL=C sort); }
ctree > "$T/ctree.before"
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
    (cd "$CW" && "$sh" "$COLLECT" "${args[@]}") >"$T/case.out" 2>"$T/case.err" </dev/null
    got=$?
    if [ "$got" = "$want_rc" ] && [ "$(cat "$T/case.err")" = "$want_err" ] && [ ! -s "$T/case.out" ]; then
      [ "$i" -gt 0 ] || ok "case: collect.sh ${args[*]}"
    else
      ko "case ($sh): collect.sh ${args[*]} -> status $got, stderr: $(cat "$T/case.err")"
    fi
    i=$((i + 1))
  done
done < "$CASES"
check "the case file has cases ($ncase)" test "$ncase" -gt 40
ctree > "$T/ctree.after"
check "no case changed anything in the working directory" cmp -s "$T/ctree.before" "$T/ctree.after"

echo
echo "threat-model collector tests: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
