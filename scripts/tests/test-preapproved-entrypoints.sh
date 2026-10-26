#!/usr/bin/env bash
# test-preapproved-entrypoints.sh — every entry point a command, a skill or the root SKILL.md pre-approves
# (scripts/entrypoints.txt) against its case file of hostile arguments. Each runs directly by its absolute path,
# as a pre-approved call runs it, from the working directory its case file's header describes, with standard
# input from /dev/null, under env -i with HOME, PATH, TMPDIR and GIT_CEILING_DIRECTORIES, canary values in
# variables that hold secrets, and the variables the header sets (RPC_URL). The working directory, a directory
# outside it, HOME (a stand-in home holding canary credentials and git configs that name programs), TMPDIR
# and the stand-ins lie in one sentinel tree per entry point. A case passes only when all of these hold:
#   - it exits non-zero (a status-0 preflight case, with nothing on stderr, exits 0); its status, its one stderr
#     line and an empty stdout are the case file's, where the case file gives them, so the fixture is the one
#     the case was written for;
#   - nothing in the sentinel tree changed outside the run directories: no path added or removed, no file,
#     link or mode changed (a file over 1 MiB by its size, mtime, inode and link count), HOME included, and no
#     scratch directory left in TMPDIR;
#   - no stand-in for a network program ran (curl, wget, nc, ssh, npm, node, yarn, pip, uv, solana, semgrep,
#     pandoc, the TeX engines, anchor, cargo and rustup but for a version or help query, git for anything that
#     reaches a remote), and no program the fixture repository's config or the stand-in home's git config names;
#   - no canary text, from a variable or a file in the sentinel tree, appears on stdout or stderr.
# A case hung for 60 s fails. Section 0 first runs the harness on stub entry points, a bash and a python one,
# each acting outside its bounds in one way, so a harness that misses a kind fails the suite.
# The Rust tools: the binaries in AUDITOR_TOOLS_BIN=<dir> (audit-scan, audit-mem and audit-logs), else a
# release build of tools/auditor-tools into a temporary target directory. Without cargo their cases are
# skipped, loudly; with REQUIRE_TOOLCHAIN=1 (CI) that is a failure.
# Usage (from the repo root): bash scripts/tests/test-preapproved-entrypoints.sh [<entry point>...]
#   <entry point>: a path as scripts/entrypoints.txt lists it; only those run (section 0 always runs).
# Needs bash >= 3.2, git, python3, jq and mkfifo. No network beyond cargo's own fetch of the locked crates.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P) || exit 1
LIST="$ROOT/scripts/entrypoints.txt"
for t in git python3 jq mkfifo; do
  command -v "$t" >/dev/null 2>&1 || { echo "FAIL - $t is not on PATH"; exit 1; }
done
T=$(mktemp -d "${TMPDIR:-/tmp}/preapproved.XXXXXX") || exit 1
T=$(cd "$T" && pwd -P) || exit 1
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR GIT_NAMESPACE CDPATH
# The build of the Rust tools keeps the caller's cargo and rustup homes; everything else gets a home of its own.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export HOME="$T/build-home" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_CEILING_DIRECTORIES="$T"
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
mkdir -p "$HOME" "$T/mk" "$T/hooks" "$T/s" || exit 1
SYSPATH=$PATH
REAL_GIT=$(command -v git)
CALLS="$T/calls.log"; : > "$CALLS"
CANARY="cnry$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

pass=0 fail=0 skip=0
ok()  { pass=$((pass + 1)); echo "ok   - $1"; }
ko()  { fail=$((fail + 1)); echo "FAIL - $1"; }
skp() { skip=$((skip + 1)); echo "SKIP - $1"; }

# The fixtures' own git calls run with no hook, fsmonitor or global config.
fgit()   { GIT_CONFIG_GLOBAL=/dev/null git -c core.hooksPath=/dev/null -c core.fsmonitor=false "$@"; }
mkrepo() { fgit init -q "$1" && fgit -C "$1" symbolic-ref HEAD refs/heads/main; }
put()    { mkdir -p "$(dirname "$1/$2")" && printf '%s\n' "$3" > "$1/$2" && fgit -C "$1" add -- "$2"; }
commit() { fgit -C "$1" commit -q "${@:2}"; }
newrun() { (cd "$1" && shift && for k in "$@"; do "$ROOT/scripts/rundir.sh" new "$k" || exit 1; done) >/dev/null; }

# Programs a repository's config or the stand-in home's git config names: $T/mk/<name> records its run and
# copies its input through, as a pager or a textconv driver does. Hooks under $T/hooks do the same.
cat > "$T/mark" <<EOF
#!/bin/sh
n=\$1; shift
printf 'mark\t%s\t%s\n' "\$n" "\$*" >> "$CALLS"
exec cat "\${1:--}" 2>/dev/null
EOF
chmod 755 "$T/mark"
for m in pager pagerlog incpager fsmonitor external extdiff textconv clean smudge process gpg gpgssh gpgx509 \
         alias-log alias-lg packhook mergedriver command ext ext-up remote-helper global-pager; do
  printf '#!/bin/sh\nexec "%s" %s "$@"\n' "$T/mark" "$m" > "$T/mk/$m" && chmod 755 "$T/mk/$m"
done
for h in post-checkout post-index-change reference-transaction post-merge post-rewrite pre-auto-gc pre-commit; do
  printf '#!/bin/sh\nexec "%s" hook-%s "$@"\n' "$T/mark" "$h" > "$T/hooks/$h" && chmod 755 "$T/hooks/$h"
done

# standins <dir>: a stand-in for each network program, which answers a version or help query and records and
# fails any other call; cargo and rustup are such stand-ins too; git runs the real git, but records and fails a
# call that reaches a remote.
standins() {
  local d=$1 n
  cat > "$d/.standin" <<EOF
#!/bin/sh
n=\${0##*/}
q=""
case "\$#:\${1-}" in 1:--version|1:-V|1:version|1:--help|1:-h|1:help|1:--list) q=y ;; esac
case "\$#:\${2-}" in 2:--version|2:-V|2:--help|2:-h) case "\$1" in -*) ;; *) q=y ;; esac ;; esac
case "\$n:\$*" in rustup:show|rustup:default|rustup:which*) q=y ;; esac
if [ -n "\$q" ]; then
  printf 'info\t%s\t%s\n' "\$n" "\$*" >> "$CALLS"
  case "\$n" in pandoc) printf 'pandoc 3.1.9\nFeatures: +server +lua\n' ;; *) printf '%s 0.0.0 (stand-in)\n' "\$n" ;; esac
  exit 0
fi
printf 'net\t%s\t%s\n' "\$n" "\$*" >> "$CALLS"
printf '%s: stand-in: there is no network here\n' "\$n" >&2
exit 1
EOF
  chmod 755 "$d/.standin"
  for n in curl wget nc ncat socat ssh scp sftp rsync telnet ftp dig host nslookup whois npm npx node yarn pnpm bun \
           deno pip pip3 pipx uv uvx gem gh aws gcloud az kubectl docker podman solana solana-keygen semgrep pandoc \
           xelatex lualatex pdflatex tectonic latexmk anchor cargo cargo-build-sbf cargo-audit cargo-outdated \
           cargo-fuzz trident surfpool rustup; do
    ln -s .standin "$d/$n" || return 1
  done
  cat > "$d/git" <<EOF
#!/bin/sh
sub=""; prev=""; net=""; url=""
for a in "\$@"; do
  if [ -z "\$sub" ]; then
    case "\$prev" in -C|-c|--git-dir|--work-tree|--namespace|--exec-path|--config-env) prev=""; continue ;; esac
    case "\$a" in -C|-c|--git-dir|--work-tree|--namespace|--config-env) prev=\$a; continue ;; -*) continue ;; esac
    sub=\$a; continue
  fi
  case "\$a" in *://*|[A-Za-z0-9_.-]*@*:*|[a-z]*::*) url=y ;; esac
  case "\$sub:\$a" in remote:update|remote:show|remote:prune|remote:set-head|archive:--remote*) net=y ;; esac
done
case "\$sub" in fetch|pull|push|ls-remote|fetch-pack|send-pack|request-pull|submodule) net=y ;; clone) net=\$url ;; esac
if [ -n "\$net" ]; then
  printf 'net\tgit\t%s\n' "\$*" >> "$CALLS"
  echo "git: stand-in: there is no network here" >&2
  exit 128
fi
exec "$REAL_GIT" "\$@"
EOF
  chmod 755 "$d/git"
}

# sentinel <name>: the sentinel tree $T/s/<name> (S): home/, holding canary credentials, a canary jq library and
# git configs that name a program; outside/, a directory outside the working directory with a canary file;
# tmp/, the TMPDIR; and bin/, the stand-ins. The fixture puts the working directory at $S/wt.
sentinel() {
  S="$T/s/$1"
  mkdir -p "$S/home/.ssh" "$S/home/.aws" "$S/home/.config/solana" "$S/home/.config/git" "$S/home/.cargo" \
    "$S/outside" "$S/tmp" "$S/bin" || return 1
  printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\n%s-ssh\n' "$CANARY" > "$S/home/.ssh/id_ed25519"
  printf '[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s-aws\n' "$CANARY" "$CANARY" > "$S/home/.aws/credentials"
  printf '"%s-solana-keypair"\n' "$CANARY" > "$S/home/.config/solana/id.json"
  printf 'machine example.invalid login fixture password %s-netrc\n' "$CANARY" > "$S/home/.netrc"
  printf 'https://fixture:%s-git@example.invalid\n' "$CANARY" > "$S/home/.git-credentials"
  printf '//registry.npmjs.org/:_authToken=%s-npmrc\n' "$CANARY" > "$S/home/.npmrc"
  printf '[registry]\ntoken = "%s-cargo"\n' "$CANARY" > "$S/home/.cargo/credentials.toml"
  printf 'def homejq: "%s-jq";\n' "$CANARY" > "$S/home/.jq"
  printf '[core]\n\tpager = %s\n[url "https://%s-gitconfig@example.invalid/"]\n\tinsteadOf = https://example.invalid/\n' \
    "$T/mk/global-pager" "$CANARY" > "$S/home/.gitconfig"
  cp "$S/home/.gitconfig" "$S/home/.config/git/config"
  printf '%s-outside\n' "$CANARY" > "$S/outside/canary.txt"
  standins "$S/bin"
}

# ---- the fixtures: fx_<kind> builds what its case file's header describes, from $S/wt (W), and sets RUNS (the
# run directories, which a case may write into) and XENV (the variables the header sets).
fx_rundir() { # fixtures/rundir/cases.txt, as test-rundir.sh runs it: a repository whose config names programs
  W=$S/wt; mkrepo "$W" && put "$W" a.rs 'fn a() {}' && put "$W" src/lib.rs 'fn lib() {}' && commit "$W" -m initial || return 1
  printf '*.rs diff=evil filter=evil\n' > "$W/.gitattributes"
  cat >> "$W/.git/config" <<EOF
[core]
	fsmonitor = $T/mk/fsmonitor
	pager = $T/mk/pager
	hooksPath = $T/hooks
	untrackedCache = true
[diff "evil"]
	textconv = $T/mk/textconv
[filter "evil"]
	clean = $T/mk/clean
	smudge = $T/mk/smudge
[remote "origin"]
	url = ext::sh -c $T/mk/ext
	promisor = false
EOF
  newrun "$W" audit || return 1
  RUNS="audit_1"
}
fx_preflight() { # fixtures/preflight/cases.txt: each case builds its entries in a new directory under $S/wt
  W=$S/wt; mkdir -p "$W" || return 1
  RUNS=""
}
fx_git_ro() { # fixtures/git-ro/cases.txt, as test-git-ro.sh builds its hostile repository
  local O="$S/outside/repo" O1 O2 signed
  mkrepo "$O" && put "$O" secret.txt "$CANARY outside one" && commit "$O" -m 'outside first' \
    && put "$O" secret.txt "$CANARY outside two" && commit "$O" -m "$CANARY outside subject" || return 1
  O1=$(fgit -C "$O" rev-parse HEAD~1) && O2=$(fgit -C "$O" rev-parse HEAD) || return 1
  W=$S/wt; mkrepo "$W" && put "$W" .gitattributes '*.rs diff=evil filter=evil' && put "$W" a.rs 'fn a() {}' \
    && put "$W" programs/demo/src/lib.rs '#[account(mut, has_one = authority)]' && commit "$W" -m 'initial import' || return 1
  fgit -C "$W" checkout -q -b merged && put "$W" m.txt "$(printf 'a\nb\nc')" && commit "$W" -m 'merge base' \
    && fgit -C "$W" checkout -q -b theirs && put "$W" m.txt "$(printf 'a\nX\nc')" && commit "$W" -m theirs \
    && fgit -C "$W" checkout -q merged && put "$W" m.txt "$(printf 'a\nY\nc')" && commit "$W" -m ours || return 1
  fgit -C "$W" merge -q theirs -m 'merge theirs' >/dev/null 2>&1
  put "$W" m.txt "$(printf 'a\nZ\nc')" && commit "$W" -m 'merge theirs' && fgit -C "$W" checkout -q main \
    && fgit -C "$W" checkout -q -b side && put "$W" b.rs 'fn side() {}' && commit "$W" -m 'side work' \
    && fgit -C "$W" checkout -q main && put "$W" a.rs 'fn a() { require!(owner == authority); } // Owner check' || return 1
  awk 'BEGIN { for (i = 0; i < 4000; i++) printf "line %05d of a blob larger than a pipe buffer\n", i }' > "$W/big.txt"
  fgit -C "$W" add big.txt && commit "$W" -m 'Check the owner' || return 1
  printf '[submodule "sub"]\n\tpath = sub\n\turl = ./sub\n' > "$W/.gitmodules"
  fgit -C "$W" add .gitmodules && fgit -C "$W" update-index --add --cacheinfo "160000,$O1,sub" \
    && commit "$W" -m 'add the submodule' && fgit -C "$W" update-index --cacheinfo "160000,$O2,sub" \
    && commit "$W" -m "$(printf 'control \033[31mred\033[0m\r\a bytes')" || return 1
  signed=$(fgit -C "$W" cat-file commit HEAD | awk '{ print } /^committer / && !done {
    print "gpgsig -----BEGIN PGP SIGNATURE-----"; print " "; print " iQEzBAABCAAdFiEEZml4dHVyZS1zaWduYXR1cmUtbm90LXJlYWw="
    print " -----END PGP SIGNATURE-----"; done = 1 }' | fgit -C "$W" hash-object -t commit -w --stdin) \
    && fgit -C "$W" update-ref refs/heads/main "$signed" || return 1
  mkdir -p "$W/sub" && printf 'gitdir: %s/.git\n' "$O" > "$W/sub/.git"
  printf 'Mapped Outside <fixture@example.invalid>\n' > "$S/outside/mailmap"
  printf 'NOT-A-REVISION\n' > "$S/outside/revs"
  printf '[core]\n\tpager = %s\n[url "https://%s-include@example.invalid/"]\n\tinsteadOf = https://example.invalid/\n' \
    "$T/mk/incpager" "$CANARY" > "$S/outside/include.cfg"
  for h in post-checkout post-index-change reference-transaction; do cp "$T/hooks/$h" "$W/.git/hooks/$h"; done
  printf '* merge=evil\n' > "$W/.git/info/attributes"
  cat >> "$W/.git/config" <<EOF
[core]
	pager = $T/mk/pager
	fsmonitor = $T/mk/fsmonitor
	hooksPath = $T/hooks
	untrackedCache = true
[pager]
	log = $T/mk/pagerlog
[diff]
	external = $T/mk/external
	submodule = log
[diff "evil"]
	textconv = $T/mk/textconv
	command = $T/mk/extdiff
[filter "evil"]
	clean = $T/mk/clean
	smudge = $T/mk/smudge
	process = $T/mk/process
[gpg]
	program = $T/mk/gpg
[gpg "ssh"]
	program = $T/mk/gpgssh
[gpg "x509"]
	program = $T/mk/gpgx509
[log]
	showSignature = true
	diffMerges = remerge
[merge "evil"]
	name = evil
	driver = $T/mk/mergedriver %A %O %B
[format]
	pretty = sig
[pretty]
	sig = %h %G? %s
[alias]
	log = !$T/mk/alias-log
	lg = !$T/mk/alias-lg
[include]
	path = $S/outside/include.cfg
[submodule]
	recurse = true
[submodule "sub"]
	url = ./sub
	active = true
[mailmap]
	file = $S/outside/mailmap
[blame]
	ignoreRevsFile = $S/outside/revs
[color]
	ui = always
	diff = always
	grep = always
	decorate = always
[uploadpack]
	packObjectsHook = $T/mk/packhook
[remote "origin"]
	url = https://example.invalid/acme/pool.git
	pushurl = https://example.invalid/acme/pool-push.git
[remote "up"]
	url = ext::sh -c $T/mk/ext-up
EOF
  mkdir -p "$W/escape" "$W/escape-link" && printf 'gitdir: %s/.git\n' "$O" > "$W/escape/.git" && ln -s "$O/.git" "$W/escape-link/.git" || return 1
  for d in inner-link alt worktree; do mkrepo "$W/$d" && put "$W/$d" f.txt "$d" && commit "$W/$d" -m "$d" || return 1; done
  ln -s "$O/.git/refs/heads/main" "$W/inner-link/.git/refs/heads/outside" \
    && printf '%s/.git/objects\n' "$O" > "$W/alt/.git/objects/info/alternates" \
    && fgit -C "$W/worktree" config core.worktree "$O" && ln -s inner-link "$W/linkrepo" || return 1
  newrun "$W" audit && (cd "$W" && "$ROOT/scripts/git-ro.sh" copy . audit_1) >/dev/null 2>&1 || return 1
  RUNS="audit_1"
}
fx_threat_model() { # fixtures/threat-model/cases.txt: the repository tgt, audit_1, and the links tgt-link and audit_2
  W=$S/wt; mkdir -p "$W" && mkrepo "$W/tgt" && put "$W/tgt" programs/c/src/lib.rs 'pub fn c() {}' && commit "$W/tgt" -m initial \
    && newrun "$W" audit && ln -s tgt "$W/tgt-link" && ln -s audit_1 "$W/audit_2" || return 1
  RUNS="audit_1"
}
fx_incident() { # fixtures/{dnr-collect,snapshot-program,rpc-read}/cases.txt: incident_1 and the link incident_2
  W=$S/wt; mkdir -p "$W" && newrun "$W" incident && ln -s incident_1 "$W/incident_2" || return 1
  RUNS="incident_1"; XENV="RPC_URL=https://rpc.example.test/"
}
fx_report_pdf() { # fixtures/report-pdf/cases.txt
  W=$S/wt; mkdir -p "$W" && newrun "$W" audit incident && printf '# r\n' > "$W/audit_1/REPORT.md" \
    && ln -s audit_1 "$W/audit_2" && mkdir "$W/audit_3" && printf '# r\n' > "$W/audit_3/REPORT.md" || return 1
  RUNS="audit_1 incident_1"
}
fx_tools_common() { # the git repository wt and, beside it, outside/ with a file holding the canary
  W=$S/wt
  mkdir -p "$W/src" && printf 'fn secret() { let k = "%s"; }\n' "$CANARY" > "$S/outside/secret.rs" \
    && printf 'protected\n' > "$S/outside/protected" && fgit init -q "$W" && ln -s ../../outside/secret.rs "$W/src/link.rs" \
    && ln -s ../outside "$W/linkdir" && mkfifo "$W/fifo"
}
rundir_by_hand() { mkdir -p "$1" && printf '*\n' > "$1/.gitignore"; }   # as test-auditor-tools.sh makes them
fx_audit_scan() { # fixtures/audit-scan/cases.txt, as test-auditor-tools.sh lays it out
  local d
  fx_tools_common || return 1
  printf 'fn a() {}\n' > "$W/a.rs"; printf 'fn lib() { let x = 1 + 2; }\n' > "$W/src/lib.rs"; mv "$W/src/link.rs" "$W/src/linked.rs"
  for d in audit_1 incident_1 audit_4 audit_5 audit_6 audit_7 audit_8; do rundir_by_hand "$W/$d" || return 1; done
  mkdir "$W/audit_2" && ln -s audit_1 "$W/audit_3" && fgit -C "$W" add -f audit_4/.gitignore && ln -s ../../outside "$W/audit_5/out" \
    && ln -s ../../outside/protected "$W/audit_6/prescan.json" && ln "$S/outside/protected" "$W/audit_7/prescan.json" \
    && mkdir "$W/audit_8/prescan.json" || return 1
  RUNS="audit_1 incident_1"
}
fx_audit_mem() { # fixtures/audit-mem/cases.txt, as test-auditor-tools.sh lays it out, its stores made by audit-mem
  local d M="$BIN/audit-mem"
  fx_tools_common || return 1
  printf 'fn withdraw() {\n    require!(vault.balance >= amount);\n    vault.balance -= amount;\n}\n' > "$W/src/withdraw.rs"
  ( cd "$W" && "$M" init && "$M" put-finding --program-id VaultProg1111 --signature unchecked_sub@vault.balance \
      --root-cause 'unchecked subtraction' --title 'Vault underflow' --severity 3 \
    && "$M" rule --program-id VaultProg1111 --signature unchecked_sub@vault.balance --ruling FALSE_POSITIVE \
      --rationale guarded --by auditor --commit c0ffee1c0ffee1c0ffee1c0ffee1c0ffee1c0ffe --guard src/withdraw.rs:2 ) >/dev/null || return 1
  for d in audit_1 audit_4 audit_5 audit_6 audit_7 audit_8 audit_10 audit_11 audit_12 audit_13 incident_1 incident_2; do
    rundir_by_hand "$W/$d" || return 1
  done
  mkdir "$W/audit_2" && ln -s audit_1 "$W/audit_3" && fgit -C "$W" add -f audit_4/.gitignore && ln -s ../../outside "$W/audit_5/out" \
    && mkdir "$W/audit_6/audit-mem.db" && ln "$S/outside/protected" "$W/audit_7/audit-mem.db" || return 1
  for d in audit_1 audit_10 audit_12 audit_13; do (cd "$W" && "$M" init --db "$d/audit-mem.db") >/dev/null || return 1; done
  (cd "$W" && "$M" put-finding --db audit_13/audit-mem.db --program-id VaultProg1111 --signature s --root-cause r \
    --title t --severity 3) >/dev/null || return 1
  python3 -I - "$W" <<'PY' || return 1
import os, sqlite3, sys
wt = sys.argv[1]
c = sqlite3.connect(wt + "/audit_8/audit-mem.db")
c.execute("PRAGMA journal_mode=WAL")
c.execute("CREATE TABLE findings (finding_id TEXT PRIMARY KEY)")
c.commit()
c.close()
for side in ("-wal", "-shm"):
    if os.path.exists(wt + "/audit_8/audit-mem.db" + side):
        os.remove(wt + "/audit_8/audit-mem.db" + side)
open(wt + "/audit_12/audit-mem.db-wal", "w").close()
c = sqlite3.connect(wt + "/audit_10/audit-mem.db")
c.execute("CREATE VIEW v AS SELECT 1")
c.commit()
c.close()
c = sqlite3.connect(wt + "/audit_13/audit-mem.db")
c.execute("UPDATE findings SET status = ?", ("\x1b]0;x\x07",))
c.commit()
c.close()
with open(wt + "/audit_11/audit-mem.db", "w") as f:
    f.write("a findings list, not a database: " + "x" * 100 + "\n")
open(wt + "/incident_1/audit-mem.db", "w").close()
PY
  RUNS="audit_1 incident_1"
}
fx_target() { # fixtures/{target,deps,sast}/cases.txt, as test-runners.sh builds its working directory
  local h
  W=$S/wt
  mkdir -p "$W/programs/demo/src" "$W/src" "$W/.cargo" "$W/app" && mkrepo "$W" || return 1
  printf '[workspace]\nmembers = ["programs/demo"]\nresolver = "2"\n' > "$W/Cargo.toml"
  printf '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n' > "$W/programs/demo/Cargo.toml"
  printf '// v1\n' > "$W/programs/demo/src/lib.rs"
  printf '[provider]\ncluster = "mainnet"\nwallet = "~/.config/solana/id.json"\n' > "$W/Anchor.toml"
  printf '{\n  "name": "demo",\n  "version": "1.0.0"\n}\n' > "$W/package.json"
  printf '{\n  "name": "demo",\n  "version": "1.0.0",\n  "lockfileVersion": 3,\n  "packages": {}\n}\n' > "$W/package-lock.json"
  printf '[build]\nrustc-wrapper = "/nonexistent/wrapper"\n' > "$W/.cargo/config.toml"
  printf '[toolchain]\npath = "/nonexistent/toolchain"\n' > "$W/rust-toolchain.toml"
  printf 'fn a() {}\n' > "$W/a.rs"; printf 'fn lib() {}\n' > "$W/src/lib.rs"
  printf '[provider]\ncluster = "localnet"\n' > "$W/app/Anchor.toml"
  printf '[package]\nname = "app"\nversion = "0.1.0"\n' > "$W/app/Cargo.toml"
  printf '# yarn lockfile v1\n' > "$W/app/yarn.lock"
  fgit -C "$W" add -A && fgit -C "$W" commit -qm v1 && printf '// v2\n' > "$W/programs/demo/src/lib.rs" \
    && fgit -C "$W" commit -qam v2 || return 1
  printf '[core]\n\tfsmonitor = %s\n\thooksPath = %s\n' "$T/mk/fsmonitor" "$T/hooks" >> "$W/.git/config"
  newrun "$W" audit incident && printf 'native\n' > "$W/audit_1/exec-mode" || return 1
  printf -- '--- a/programs/demo/src/lib.rs\n+++ b/programs/demo/src/lib.rs\n@@ -1 +1 @@\n-// v2\n+// patched\n' > "$W/audit_1/patches/F-1.patch"
  printf -- '--- a/programs/demo/src/lib.rs\n+++ b/programs/demo/src/lib.rs\n@@ -1 +1 @@\n-// v9\n+// patched\n' > "$W/audit_1/patches/F-3.patch"
  dd if=/dev/zero of="$W/audit_1/patches/F-2.patch" bs=1 count=0 seek=16777217 2>/dev/null || return 1
  (cd "$W" && "$ROOT/scripts/git-ro.sh" copy . audit_1) >/dev/null 2>&1 && ln -s audit_1 "$W/linkdir" || return 1
  mkdir -p "$W/sub" "$W/big"
  printf '# generated\nversion = 3\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n' > "$W/Cargo.lock"
  cp "$W/Cargo.lock" "$W/sub/Cargo.lock" && cp "$W/Cargo.lock" "$W/.cargo/Cargo.lock" || return 1
  dd if=/dev/zero of="$W/big/Cargo.lock" bs=1 count=0 seek=52428801 2>/dev/null || return 1
  printf '//registry.npmjs.org/:_authToken=%s-target-npmrc\n' "$CANARY" > "$W/.npmrc"
  printf 'npmAuthToken: %s-target-yarnrc\n' "$CANARY" > "$W/.yarnrc.yml"
  cp "$W/package-lock.json" "$W/sub/package-lock.json" && cp "$W/package-lock.json" "$W/npm-shrinkwrap.json" || return 1
  RUNS="audit_1 incident_1"
}
fx_poc() { # fixtures/{poc-run,probe}/cases.txt, as test-dnr-poc-runner.sh builds its working directory
  local c
  W=$S/wt; mkdir -p "$W/src" && newrun "$W" audit incident || return 1
  c="$W/audit_1/poc/F-1"
  mkdir -p "$c/tests" "$c/shared-test-utils/src" && cp "$ROOT/templates/poc/run.sh" "$c/run.sh" \
    && printf '[package]\nname = "poc_shim"\nversion = "0.1.0"\nedition = "2021"\n' > "$c/Cargo.toml" \
    && cp "$ROOT/templates/poc/shared-test-utils/Cargo.toml" "$c/shared-test-utils/" \
    && cp "$ROOT/templates/poc/shared-test-utils/src/lib.rs" "$c/shared-test-utils/src/" \
    && cp "$ROOT/templates/poc/tests/exploit.rs" "$ROOT/templates/poc/tests/fixed_blocked.rs" "$c/tests/" || return 1
  mkdir -p "$W/audit_1/exec/build-sbf-1" && python3 -I - "$W" <<'PY' || return 1
import sys
w = sys.argv[1]
elf = b"\x7fELF" + bytes(range(1, 60))
open(w + "/audit_1/exec/build-sbf-1/vuln.so", "wb").write(elf + b"\x00" * 4096)
open(w + "/audit_1/exec/build-sbf-1/fixed.so", "wb").write(elf[:-1] + b"\x99" + b"\x00" * 128)
open(w + "/incident_1/bin/program.so", "wb").write(elf + b"\x00" * 4096)
PY
  printf 'notes\n' > "$W/audit_1/exec/build-sbf-1/notes.txt"; printf 'fn a() {}\n' > "$W/a.rs"
  ln -s audit_1 "$W/linkdir" && printf 'native\n' > "$W/audit_1/exec-mode" || return 1
  RUNS="audit_1 incident_1"
}
fx_jq_ro() { # fixtures/jq-ro/cases.txt, as test-jq-ro.sh lays it out
  local O=$S/outside
  W=$S/wt; mkdir -p "$W" && fgit init -q "$W" || return 1
  rundir_by_hand "$W/incident_1" && mkdir "$W/incident_1/corpus" || return 1
  printf '{"a":1,"s":"one"}\n{"a":2,"s":"two"}\n' > "$W/incident_1/data.json"
  printf '{"slot":10,"transaction":{"signatures":["sig1"]}}\n{"slot":11,"transaction":{"signatures":["sig2"]}}\n' \
    > "$W/incident_1/corpus/transactions.jsonl"
  rundir_by_hand "$W/audit_1" && printf '{"finding":"F-1"}\n' > "$W/audit_1/data.json" && mkdir "$W/notes" || return 1
  printf '{"note":true}\n' > "$W/notes/t.json"; printf '{"top":true}\n' > "$W/data.json"
  ln -s incident_1 "$W/incident_2" && rundir_by_hand "$W/incident_3" && printf '{"a":3}\n' > "$W/incident_3/data.json" \
    && ln -s ../notes/t.json "$W/incident_3/link.json" && mkdir "$W/incident_4" && printf '{"a":4}\n' > "$W/incident_4/data.json" \
    && rundir_by_hand "$W/incident_5" && printf '{"a":5}\n' > "$W/incident_5/data.json" \
    && fgit -C "$W" add -f incident_5/.gitignore && fgit -C "$W" commit -q -m fixture || return 1
  printf '{"secret":"%s-jq-ro"}\n' "$CANARY" > "$O/secret.json"
  rundir_by_hand "$W/incident_7" && ln "$O/secret.json" "$W/incident_7/hard.json" && rundir_by_hand "$W/incident_8" \
    && mkfifo "$W/incident_8/fifo" && rundir_by_hand "$W/INCIDENT_9" && printf '{}\n' > "$W/INCIDENT_9/data.json" \
    && rundir_by_hand "$W/incident_10" && ln -s "$O" "$W/incident_10/sub" && rundir_by_hand "$W/incident_1234567" \
    && printf '{}\n' > "$W/incident_1234567/data.json" && fgit -C "$W" config core.fsmonitor "$T/mk/fsmonitor" || return 1
  RUNS="incident_1 audit_1"; XENV="JQ_RO_CANARY=$CANARY-jq-ro-env RPC_URL=https://rpc.example.invalid/$CANARY-rpc"
}
fx_recipes() { # fixtures/recipes/{lock-delta,web3js-history}/cases.txt, as test-recipes.sh builds its repository
  local k v
  W=$S/wt; mkrepo "$W" && mkdir -p "$W/programs/p" "$W/notes" "$W/notarun" && echo x > "$W/a.rs" \
    && echo y > "$W/programs/p/lib.rs" && fgit -C "$W" add -A && fgit -C "$W" commit -qm base || return 1
  while IFS='=' read -r k v; do
    fgit -C "$W" config "$k" "$v" || return 1
  done <<EOF
core.pager=$T/mk/pager
core.fsmonitor=$T/mk/fsmonitor
diff.external=$T/mk/external
diff.lock.textconv=$T/mk/textconv
diff.lock.command=$T/mk/command
gpg.program=$T/mk/gpg
log.showSignature=true
color.ui=always
color.diff=always
diff.context=0
diff.interHunkContext=20
diff.noprefix=true
diff.srcPrefix=X/
diff.dstPrefix=Y/
diff.mnemonicPrefix=true
log.decorate=full
format.pretty=%H %an
core.attributesFile=$S/outside/attrs
EOF
  printf '* diff=lock\n' > "$S/outside/attrs"
  mkdir -p "$W/.git/info" && printf '*.lock diff=lock\n*.json diff=lock\n*.json -diff\n' >> "$W/.git/info/attributes" \
    && newrun "$W" audit && ln -s audit_1 "$W/audit_2" && ln -s . "$W/link" || return 1
  RUNS="audit_1"
}
fx_logs() { # fixtures/audit-logs/hostile-args.txt: the layout test-audit-logs.sh and test-dnr.sh call hostile_layout
  local HO=$S/outside canary f
  W=$S/wt
  mkdir -p "$W/incident_1/subdir" "$W/incident_1/corpus" "$W/incident_3" "$W/incident_4" "$W/audit_1" || return 1
  printf '*\n' > "$W/incident_1/.gitignore"; printf '*\n' > "$W/audit_1/.gitignore"
  printf '!x\n' > "$W/incident_4/.gitignore"; printf '*\n' > "$HO/.gitignore"
  canary="{\"meta\":{\"err\":null,\"fee\":0,\"preBalances\":[1],\"postBalances\":[2],\"logMessages\":[\"Program log: $CANARY\"]},\"transaction\":{\"signatures\":[\"Sig$CANARY\"],\"message\":{\"accountKeys\":[\"Key$CANARY\"],\"instructions\":[{\"programId\":\"Prog$CANARY\",\"accounts\":[0],\"data\":\"x\"}]}}}"
  for f in "$W/canary.jsonl" "$HO/secret.jsonl" "$W/incident_3/canary.jsonl" "$W/incident_4/canary.jsonl" "$W/audit_1/canary.jsonl"; do
    printf '%s\n' "$canary" > "$f"
  done
  sed -n 1p "$ROOT/scripts/dnr/fixtures/clean-mixed.jsonl" > "$W/incident_1/corpus.jsonl" \
    && cp "$W/incident_1/corpus.jsonl" "$W/incident_1/corpus/transactions.jsonl" || return 1
  printf '# ledger\n' > "$W/incident_1/LEDGER.md"
  ln -s ../canary.jsonl "$W/incident_1/link.jsonl" && ln -s "$HO" "$W/incident_1/dlink" && ln -s "$HO" "$W/incident_2" \
    && mkfifo "$W/incident_1/fifo" && printf 'protected\n' > "$W/protected.txt" && ln "$W/protected.txt" "$W/incident_1/hard.txt" \
    && ln -s ../protected.txt "$W/incident_1/out-link.txt" && cp "$W/incident_1/corpus.jsonl" "$W/incident_1/twin.jsonl" \
    && ln "$W/incident_1/twin.jsonl" "$W/incident_1/twin-2.jsonl" || return 1
  RUNS=""
}

# kind_of <case file>: the fixture its header describes, and the format of its lines
kind_of() {
  case "$1" in
    */rundir/cases.txt) KIND=rundir FMT=cases ;;
    */preflight/cases.txt) KIND=preflight FMT=preflight ;;
    */git-ro/cases.txt) KIND=git_ro FMT=cases ;;
    */threat-model/cases.txt) KIND=threat_model FMT=cases ;;
    */dnr-collect/cases.txt | */snapshot-program/cases.txt | */rpc-read/cases.txt) KIND=incident FMT=cases ;;
    */report-pdf/cases.txt) KIND=report_pdf FMT=cases ;;
    */audit-scan/cases.txt) KIND=audit_scan FMT=cases ;;
    */audit-mem/cases.txt) KIND=audit_mem FMT=cases ;;
    */target/cases.txt | */deps/cases.txt | */sast/cases.txt) KIND=target FMT=cases ;;
    */poc-run/cases.txt | */probe/cases.txt) KIND=poc FMT=cases ;;
    */jq-ro/cases.txt) KIND=jq_ro FMT=cases ;;
    */recipes/*/cases.txt) KIND=recipes FMT=cases ;;
    */audit-logs/hostile-args.txt) KIND=logs FMT=hostile ;;
    *) return 1 ;;
  esac
}

# The driver: python3 -I -c "$DRIVER" <entry> <case file> <format> <wt> <outside> <sentinel> <runs> <calls> <canary>
# <env file> <seconds>. One line per case, "ok<TAB><case>" or "FAIL<TAB><case><TAB><why>", then
# "cases<TAB><count><TAB><failed>".
DRIVER=
IFS= read -r -d '' DRIVER <<'EOF' || true
import hashlib, os, re, signal, stat, subprocess, sys

entry, cases, fmt, wt, outside, sent, runs, calls, canary, envfile, seconds = sys.argv[1:12]
with open(envfile, "rb") as f:
    env = dict(kv.split(b"=", 1) for kv in f.read().split(b"\0") if kv)
OK_LINE = b"preflight: ok: no Claude Code project config in the working tree or its parents up to the repository root"
skip = set(os.path.normpath(os.path.join(os.path.relpath(wt, sent), r)) for r in runs.split())

def plain(a):
    for k, v in (("@WT@", wt), ("@OUT@", outside), ("@NL@", "\n"), ("@ESC@", "\x1b"), ("@TAB@", "\t"),
                 ("@DEL@", "\x7f"), ("@RLO@", "\u202e"), ("@ZWSP@", "\u200b")):
        a = a.replace(k, v)
    return re.sub(r"@LONG:([0-9]+)@", lambda m: "a" * int(m.group(1)), a)

def shown(s):
    """As the Rust tools show a value in a message: cut after 200 bytes, then '...'."""
    t = ""
    for c in s:
        if len((t + c).encode("utf-8", "surrogateescape")) > 200:
            return t + "..."
        t += c
    return t

def fill(a):
    if a == "@EMPTY@":
        return ""
    parts = re.split(r"@SHOWN\((.*?)\)@", a)
    return "".join(shown(plain(p)) if i % 2 else plain(p) for i, p in enumerate(parts))

def enc(s):
    return s.encode("utf-8", "surrogateescape")

def snapshot():
    """Every path in the sentinel tree, no link followed and no run directory entered: type and mode; for a
    file its size, mtime, inode, link count and, up to 1 MiB, its SHA-256; for a link its target."""
    snap = {}
    for top, dirs, files in os.walk(sent):
        rel = os.path.relpath(top, sent)
        for name in dirs + files:
            p = os.path.join(top, name)
            st = os.lstat(p)
            m = st.st_mode
            rec = [stat.S_IFMT(m), stat.S_IMODE(m)]
            if stat.S_ISLNK(m):
                rec.append(os.readlink(p))
            elif stat.S_ISREG(m):
                rec += [st.st_size, st.st_mtime_ns, st.st_ino, st.st_nlink]
                if st.st_size <= 1 << 20:
                    with open(p, "rb") as f:
                        rec.append(hashlib.sha256(f.read()).hexdigest())
            elif not stat.S_ISDIR(m):
                rec += [st.st_ino, st.st_nlink]
            snap[os.path.normpath(os.path.join(rel, name))] = rec
        dirs[:] = [d for d in dirs if os.path.normpath(os.path.join(rel, d)) not in skip]
    return snap

def changes(a, b):
    out = ["%s added" % k for k in sorted(set(b) - set(a))]
    out += ["%s removed" % k for k in sorted(set(a) - set(b))]
    return out + ["%s changed" % k for k in sorted(set(a) & set(b)) if a[k] != b[k]]

def run(argv, cwd):
    p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = p.communicate(timeout=float(seconds))
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        out, err = p.communicate()
        return "hung", out, err

def show(b, n=160):
    s = b.decode("utf-8", "replace") if isinstance(b, bytes) else b
    s = re.sub(r"[\x00-\x1f\x7f]", "?", s)
    return s if len(s) <= n else s[:n] + "..."

def read_cases():
    """(the status, the stderr line, the arguments or entries, a label) of each case the format reads."""
    with open(cases, "rb") as f:
        text = f.read().decode("utf-8", "surrogateescape")
    for line in text.split("\n"):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if fmt == "cases":
            args = [enc(fill(a)) for a in fields[2:]]
            yield int(fields[0]), enc(fill(fields[1])), args, show(b" ".join(args), 100)
        elif fmt == "preflight":
            yield int(fields[0]), enc(fields[1]), fields[2:], show(" ".join(fields[2:]), 100)
        else:
            args = [enc(fill(a)) for a in fields[1:]]
            if ":" in fmt:
                if not args or args[0] != enc(fmt.split(":", 1)[1]):
                    continue
                args = args[1:]
            yield None, None, args, show(fields[0], 100)

def build(d, entries):
    for e in entries:
        kind, rest = e[:2], e[2:]
        p, v = rest.split("=", 1) if kind in ("j:", "l:") else (rest, "")
        full = os.path.join(d, p)
        os.makedirs(full if kind == "d:" else os.path.dirname(full), exist_ok=True)
        if kind == "f:":
            open(full, "w").close()
        elif kind == "j:":
            with open(full, "w") as f:
                f.write(v)
        elif kind == "l:":
            os.symlink(v, full)

with open(calls, "rb") as f:
    pos = len(f.read())
before = snapshot()
n = failed = 0
for want_rc, want_err, args, label in read_cases():
    n += 1
    cwd = wt
    if fmt == "preflight":
        cwd = os.path.join(wt, "case-%03d" % n)
        os.mkdir(cwd)
        build(cwd, args)
        args = []
        before = snapshot()
    rc, out, err = run([enc(entry)] + args, cwd)
    after = snapshot()
    with open(calls, "rb") as f:
        f.seek(pos)
        made = f.read()
    pos += len(made)
    why = []
    if rc == "hung":
        why.append("still running after %s s" % seconds)
    elif want_rc is None or want_rc != 0:
        if rc == 0:
            why.append("exit 0")
        elif want_rc is not None and rc != want_rc:
            why.append("exit %s, not %s" % (rc, want_rc))
    elif rc != 0:
        why.append("exit %s, not 0" % rc)
    if fmt == "cases" or (fmt == "preflight" and want_rc != 0):
        if err != (want_err + b"\n" if want_err else b""):
            why.append("stderr [%s], not [%s]" % (show(err), show(want_err)))
        if out:
            why.append("stdout [%s]" % show(out))
    elif fmt == "preflight" and (err or out.rstrip(b"\n").split(b"\n")[-1] != OK_LINE):
        why.append("not the ok line alone on stderr's silence: stderr [%s], stdout [%s]" % (show(err), show(out)))
    moved = changes(before, after)
    if moved:
        why.append("changed outside the run directories: " + "; ".join(moved[:4]) + (" ..." if len(moved) > 4 else ""))
    for c in made.decode("utf-8", "replace").split("\n"):
        kind, _, rest = c.partition("\t")
        name, _, what = rest.partition("\t")
        if kind == "net":
            why.append("called %s, a network program: %s" % (name, show(what, 100)))
        elif kind == "mark":
            why.append("started %s, which a git config names" % name)
    if enc(canary) in out or enc(canary) in err:
        why.append("printed canary text")
    if why:
        failed += 1
        print("FAIL\t%s\t%s" % (label, "; ".join(why)))
    else:
        print("ok\t%s" % label)
    before = after
print("cases\t%d\t%d" % (n, failed))
EOF

# drive <name> <entry> <case file> <format> [<seconds>]: the cases, with each FAIL line reported; NCASES and
# NFAILED hold the counts, and $T/drive-<name>.out every line.
drive() {
  local name=$1 entry=$2 cases=$3 fmt=$4 secs=${5:-60} line k v
  : > "$T/env-$name"
  for kv in "HOME=$S/home" "PATH=$S/bin:$SYSPATH" "TMPDIR=$S/tmp" "GIT_CEILING_DIRECTORIES=$T" \
            "AWS_SECRET_ACCESS_KEY=$CANARY-aws-env" "GITHUB_TOKEN=$CANARY-github-env" "NPM_TOKEN=$CANARY-npm-env" \
            "CARGO_REGISTRY_TOKEN=$CANARY-cargo-env" "ANTHROPIC_API_KEY=$CANARY-anthropic-env" ${XENV:-}; do
    printf '%s\0' "$kv" >> "$T/env-$name"
  done
  (cd / && exec python3 -I -c "$DRIVER" "$entry" "$cases" "$fmt" "$W" "$S/outside" "$S" "${RUNS:-}" "$CALLS" "$CANARY" \
    "$T/env-$name" "$secs") > "$T/drive-$name.out" 2> "$T/drive-$name.err"
  NCASES=0 NFAILED=0
  while IFS='	' read -r k v line; do
    case "$k" in
      cases) NCASES=$v; NFAILED=$line ;;
      FAIL) [ -z "${QUIET:-}" ] && ko "$name: $v: $line" ;;
      ok) [ -n "${VERBOSE:-}" ] && ok "$name: $v" ;;
    esac
  done < "$T/drive-$name.out"
  if [ -s "$T/drive-$name.err" ]; then ko "$name: the driver failed: $(head -c 600 "$T/drive-$name.err")"; NFAILED=x; fi
}

# =================================================================================================
# 0. The harness itself: stub entry points that act outside their bounds, each in one way, must fail, and
#    the stubs that stay inside them must pass. A bash stub and a python one, each run directly by its path.
# =================================================================================================
mkdir -p "$T/stubs"
stub() { # stub <name> <body>: a bash entry point that prints the refusal, does <body>, and exits 64
  printf '#!/bin/bash\nprintf '"'"'stub: refused: x\\n'"'"' >&2\n%s\nexit 64\n' "$2" > "$T/stubs/$1" && chmod 755 "$T/stubs/$1"
}
stub good ':'
stub run-write 'printf x > audit_1/written'
stub exit-0 'exit 0'
stub stdout 'echo hello'
stub home 'printf x >> "$HOME/.bashrc"'
stub outside 'printf x >> ../outside/canary.txt'
stub scratch 'mktemp -d "$TMPDIR/stub.XXXXXX" >/dev/null'
stub mode 'chmod u+x a.rs'
stub link 'ln -s ../outside x'
stub curl 'curl -s https://example.invalid/ >/dev/null 2>&1'
stub npm 'npm install left-pad >/dev/null 2>&1'
stub cargo-fetch 'cargo fetch >/dev/null 2>&1'
stub cargo-version 'cargo --version >/dev/null 2>&1'
stub git-remote 'git ls-remote https://example.invalid/x.git >/dev/null 2>&1'
stub git-clone 'git clone -q https://example.invalid/x.git x >/dev/null 2>&1'
stub git-local 'git rev-parse HEAD >/dev/null 2>&1'
stub git-config-program 'git log -p -1 -- a.rs >/dev/null 2>&1'
stub git-global-config 'p=$(git config --global core.pager) && "$p" </dev/null >/dev/null 2>&1'
stub env-canary 'printf "%s\n" "$AWS_SECRET_ACCESS_KEY" >&2'
stub hung 'sleep 30'
printf '#!/usr/bin/env -S python3 -I\nimport os, sys\nsys.stderr.write("stub: refused: x\\n")\nsys.stdout.write(open(os.path.expanduser("~/.ssh/id_ed25519")).read())\nsys.exit(64)\n' \
  > "$T/stubs/py-file-canary" && chmod 755 "$T/stubs/py-file-canary"
printf '#!/usr/bin/env -S python3 -I\nimport sys\nsys.stderr.write("stub: refused: x\\n")\nsys.exit(64)\n' > "$T/stubs/py-good" \
  && chmod 755 "$T/stubs/py-good"
printf '# one hostile case\n64\tstub: refused: x\t--x\n' > "$T/stub-cases.txt"
# One working directory for every stub: a repository whose attributes send a.rs to a textconv driver that
# records its run, and the run directory audit_1. Each run compares the tree with itself as the run found it.
sentinel stubs && W=$S/wt && mkrepo "$W" && put "$W" a.rs 'fn a() {}' && commit "$W" -m initial \
  && printf '*.rs diff=evil\n' > "$W/.gitattributes" && printf '[diff "evil"]\n\ttextconv = %s\n' "$T/mk/textconv" >> "$W/.git/config" \
  && newrun "$W" audit || { ko "harness: cannot build the stubs' working directory"; exit 1; }
SW=$W SS=$S
# expect_stub <stub> <text in its FAIL line, or "" for a pass> [<seconds>]
expect_stub() {
  local s=$1 want=$2 got
  W=$SW S=$SS RUNS="audit_1" XENV=""
  QUIET=1 drive "stub-$s" "$T/stubs/$s" "$T/stub-cases.txt" cases "${3:-60}"
  got=$(sed -n 's/^FAIL	[^	]*	//p' "$T/drive-stub-$s.out")
  if [ "$NCASES" != 1 ]; then ko "harness: the stub $s ran $NCASES cases"
  elif [ -z "$want" ] && [ -z "$got" ]; then ok "harness: the stub $s passes"
  elif [ -n "$want" ] && case "$got" in *"$want"*) true ;; *) false ;; esac; then ok "harness: the stub $s fails: $want"
  else ko "harness: the stub $s gives [${got:-a pass}], want [${want:-a pass}]"; fi
}
expect_stub good ""
expect_stub py-good ""
expect_stub run-write ""
expect_stub git-local ""
expect_stub cargo-version ""
expect_stub exit-0 "exit 0"
expect_stub stdout "stdout [hello?]"
expect_stub home "changed outside the run directories: home/.bashrc added"
expect_stub outside "changed outside the run directories: outside/canary.txt changed"
expect_stub scratch "changed outside the run directories: tmp/stub."
expect_stub mode "changed outside the run directories: wt/a.rs changed"
expect_stub link "changed outside the run directories: wt/x added"
expect_stub curl "called curl, a network program"
expect_stub npm "called npm, a network program"
expect_stub cargo-fetch "called cargo, a network program: fetch"
expect_stub git-remote "called git, a network program: ls-remote"
expect_stub git-clone "called git, a network program: clone"
expect_stub git-config-program "started textconv, which a git config names"
expect_stub git-global-config "started global-pager, which a git config names"
expect_stub env-canary "printed canary text"
expect_stub py-file-canary "printed canary text"
expect_stub hung "still running after 3 s" 3

# =================================================================================================
# 1. The Rust tools, when an entry point that is one runs.
# =================================================================================================
BIN="" BUILT=""
rust_tools() {
BUILT=y
if [ -n "${AUDITOR_TOOLS_BIN:-}" ]; then
  case "$AUDITOR_TOOLS_BIN" in /*) BIN=$AUDITOR_TOOLS_BIN ;; *) BIN="$PWD/$AUDITOR_TOOLS_BIN" ;; esac
  for b in audit-scan audit-mem audit-logs; do
    [ -f "$BIN/$b" ] && [ -x "$BIN/$b" ] || { ko "AUDITOR_TOOLS_BIN: $BIN/$b is not an executable file"; BIN=""; }
  done
  [ -z "$BIN" ] || ok "the Rust tools: the binaries in AUDITOR_TOOLS_BIN"
elif command -v cargo >/dev/null 2>&1; then
  if cargo build --release --locked --manifest-path "$ROOT/tools/auditor-tools/Cargo.toml" --target-dir "$T/target" \
      > "$T/build.log" 2>&1; then
    BIN="$T/target/release"
    # A cargo config that names a build target puts the binaries under target/<triple>/.
    for b in "$T"/target/*/release/audit-mem; do [ -x "$BIN/audit-mem" ] || [ ! -x "$b" ] || BIN="${b%/audit-mem}"; done
    ok "the Rust tools: built (cargo build --release --locked)"
  else
    ko "the Rust tools: cargo build --release failed: $(sed -n '1,30p' "$T/build.log")"
  fi
elif [ "${REQUIRE_TOOLCHAIN:-}" = 1 ]; then
  ko "REQUIRE_TOOLCHAIN=1, but cargo is not on PATH: the Rust tools cannot be built, so their cases do not run"
else
  skp "cargo is not on PATH: audit-scan, audit-mem and audit-logs are NOT run against their case files"
fi
}

# =================================================================================================
# 2. Each entry point against its case file.
# =================================================================================================
nep=0
nlisted=$(grep -c -v -e '^#' -e '^$' "$LIST")
while IFS='	' read -r ep cases words <&3; do
  case "$ep" in ''|'#'*) continue ;; esac
  if [ $# -gt 0 ]; then
    want=""; for a in "$@"; do [ "$a" = "$ep" ] && want=y; done
    [ -n "$want" ] || continue
  fi
  nep=$((nep + 1))
  name=$(printf '%s' "$ep" | tr '/' '_')
  if ! kind_of "$cases"; then ko "$ep: no fixture for its case file $cases"; continue; fi
  case "$ep" in
    tools/auditor-tools/target/release/*)
      [ -n "$BUILT" ] || rust_tools
      [ -n "$BIN" ] || continue
      exe="$BIN/${ep##*/}" ;;
    *) exe="$ROOT/$ep" ;;
  esac
  case "$ep" in
    scripts/dnr/profile.sh) FMT=hostile:profile ;;
    scripts/dnr/frames.py) FMT=hostile:frames ;;
    scripts/dnr/deltas.py) FMT=hostile:deltas ;;
  esac
  RUNS="" XENV=""
  if ! { sentinel "$name" && "fx_$KIND"; }; then ko "$ep: cannot build the working directory of $cases"; continue; fi
  drive "$name" "$exe" "$ROOT/$cases" "$FMT"
  if [ "$NFAILED" = 0 ] && [ "$NCASES" -gt 0 ]; then ok "$ep: $NCASES cases of $cases, each within its bounds"
  elif [ "$NCASES" = 0 ]; then ko "$ep: no case read from $cases"
  else ko "$ep: $NFAILED of $NCASES cases of $cases failed"; fi
done 3< "$LIST"
[ $# -gt 0 ] || [ "$nep" = "$nlisted" ] || ko "$nep of the $nlisted entry points in scripts/entrypoints.txt ran"

echo "---- pre-approved entry points: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
