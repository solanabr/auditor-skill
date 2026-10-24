# isolation.sh — the isolation self-check and environment cleaning for the bundled runners
# (templates/poc/run.sh, scripts/runner/*.sh), OUTPUT-RULES.md Rule 11a. Sourced, never run, after
# scripts/lib/confine.sh and its confine_init, whose cleaned PATH and WT these functions use.
#
# The self-check. The isolated runner is a container, VM or sandbox with no credentials in reach. In
# $HOME, and in the account's home directory from the passwd database when that differs, it tries to read
# one byte of each file below, and lists the directories:
#   ~/.ssh: every entry but known_hosts*, config, *.pub and authorized_keys*, subdirectories included; when
#     the directory cannot be listed, id_rsa, id_dsa, id_ecdsa, id_ed25519, id_ecdsa_sk, id_ed25519_sk and
#     identity;
#   ~/.config/solana/id.json and ~/.aws/credentials;
#   ~/.config/gcloud/credentials.db, access_tokens.db and application_default_credentials.json, and the
#     files in ~/.config/gcloud/legacy_credentials/;
#   ~/.azure/accessTokens.json, msal_token_cache.json, msal_token_cache.bin, service_principal_entries.json
#     and service_principal_entries.bin;
#   ~/.kube/config, ~/.docker/config.json, ~/.npmrc, ~/.cargo/credentials and ~/.cargo/credentials.toml
#     (and both in $CARGO_HOME when it is set);
#   ~/.git-credentials, ~/.netrc, ~/.config/gh/hosts.yml and ~/.pypirc;
#   the files in ~/.gnupg/private-keys-v1.d/.
# A path counts when it is a regular file, or a link to one, whose first byte can be read, or a socket that
# accepts a connection. The SSH agent counts when SSH_AUTH_SOCK names a socket that accepts a connection: a
# sandbox that blocks Unix sockets leaves the variable and the socket in place, out of reach. A sandbox that
# denies reads of these paths passes, so its credentials block must list them all; an unsandboxed retry, a
# sandbox without those deny rules and a host session that recorded "isolated" do not pass.
#
# Environment cleaning, in every mode. A child runs under env -i with only these variables: PATH as
# confine_init cleaned it; HOME, a throwaway directory holding a fresh Solana keypair at
# .config/solana/id.json; TMPDIR, a scratch directory; LC_ALL=C; USER, LOGNAME, LANG, TERM,
# RUSTUP_TOOLCHAIN, CARGO_NET_OFFLINE, SSL_CERT_FILE and SSL_CERT_DIR when they are set; the user's
# CARGO_HOME and RUSTUP_HOME, resolved against the real HOME; and the variables its caller adds. A child
# that downloads (cargo fetching crates) also gets the proxy variables http_proxy, https_proxy, all_proxy
# and no_proxy, in either case, when they are set: a sandbox's network allowlist works through them, and
# its proxy URL can carry a session token, so a test binary never gets them. No token, RPC_URL,
# SSH_AUTH_SOCK, or git or cargo setting in the environment reaches a child.
#
# Functions:
#   iso_homes                    prints the home directories the self-check reads, one per line.
#   iso_credentials [<home>...]  sets ISO_READABLE to the readable paths, one per line, with control
#                                characters printed as ?; status 0 when none is readable, 1 when some are,
#                                2 when the check cannot run. With no <home>, it reads the homes iso_homes
#                                prints. A caller in isolated mode stops on status 1 or 2; in native mode
#                                it prints what is readable and goes on.
#   iso_scratch <tool>           sets ISO_SCRATCH to a new directory, mktemp -d
#                                "${TMPDIR:-/tmp}/auditor-<tool>.XXXXXX", resolved physically. It refuses
#                                (confine_refuse) a scratch directory inside WT, or one where cargo or rustup
#                                would read a .cargo/config, .cargo/config.toml, rust-toolchain or
#                                rust-toolchain.toml at or above it (the user's CARGO_HOME excepted). Set
#                                the EXIT trap that removes ISO_SCRATCH first.
#   iso_inherited <dir>          prints the first such file at or above <dir>; nothing when there is none.
#   iso_env <dir> [keep-home]    makes <dir>/home, with the throwaway keypair, and <dir>/tmp, and sets
#                                ISO_ENV (an array of NAME=value words), ISO_NET (the proxy words, maybe
#                                none), ISO_HOME, ISO_TMP and ISO_REAL_HOME (the HOME it replaces); status 1
#                                when it cannot. With keep-home, for a caller that runs only fixed tools,
#                                HOME stays the real one and no throwaway HOME is made. Add a caller's own
#                                variables with ISO_ENV+=("NAME=value").
#   iso_run [NAME=value...] <program> [<arg>...]
#                                runs <program> under env -i "${ISO_ENV[@]}" and the NAME=value words, a
#                                later word for a name winning; status 126 for a program path holding "=".
#   iso_net [NAME=value...] <program> [<arg>...]
#                                the same, with the proxy words of ISO_NET as well: for a download.
# Needs bash >= 3.2, python3 (the self-check and the keypair), env, mkdir and mktemp.

# What iso_credentials, iso_homes and iso_env run, with python3 -I so that no module comes from the working
# directory or PYTHONPATH. "creds <socket> <cargo home> given|default [<home>...]" prints the readable paths
# (exit 1) or nothing (exit 0); "homes <home>" prints the homes; "wallet <path>" writes a fresh keypair,
# RFC 8032 key generation from 32 random bytes, as the 64-number array solana-keygen writes. Exit 2 on
# anything unexpected.
ISO_PY='import hashlib, json, os, pwd, re, socket, stat, sys

FILES = (".config/solana/id.json", ".aws/credentials", ".config/gcloud/credentials.db",
         ".config/gcloud/access_tokens.db", ".config/gcloud/application_default_credentials.json",
         ".azure/accessTokens.json", ".azure/msal_token_cache.json", ".azure/msal_token_cache.bin",
         ".azure/service_principal_entries.json", ".azure/service_principal_entries.bin", ".kube/config",
         ".docker/config.json", ".npmrc", ".cargo/credentials", ".cargo/credentials.toml", ".git-credentials",
         ".netrc", ".config/gh/hosts.yml", ".pypirc")
DIRS = (".config/gcloud/legacy_credentials", ".gnupg/private-keys-v1.d")
SSH_KEEP = re.compile(r"^(known_hosts.*|config|.*\.pub|authorized_keys.*)$")
SSH_KEYS = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "identity")


def shown(path):
    return re.sub(r"[\x00-\x1f\x7f]", "?", path)[:300]


def first_byte(path):
    # Opened without blocking, so a FIFO in place of a file cannot stall the check.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOCTTY", 0))
    except OSError:
        return False
    try:
        return stat.S_ISREG(os.fstat(fd).st_mode) and len(os.read(fd, 1)) == 1
    except OSError:
        return False
    finally:
        os.close(fd)


def accepts(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()


def walk(top, keep, found, budget, depth=0):
    try:
        names = sorted(os.listdir(top))
    except OSError:
        return False
    for name in names:
        if budget[0] <= 0:
            break
        budget[0] -= 1
        if keep and keep.match(name):
            continue
        path = os.path.join(top, name)
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            continue
        if stat.S_ISDIR(mode):
            if depth < 2:
                walk(path, keep, found, budget, depth + 1)
        elif stat.S_ISSOCK(mode):
            if accepts(path):
                found.append(path)
        elif first_byte(path):
            found.append(path)
    return True


def homes(home):
    out = [home] if home else []
    try:
        account = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        account = ""
    if account and not (home and os.path.realpath(account) == os.path.realpath(home)):
        out.append(account)
    return out


def creds(sock, cargo_home, which, given):
    found, budget = [], [2000]
    for home in (given if which == "given" else homes(os.environ.get("HOME", ""))):
        if not home:
            continue
        ssh = os.path.join(home, ".ssh")
        if not walk(ssh, SSH_KEEP, found, budget):
            found.extend(p for p in (os.path.join(ssh, k) for k in SSH_KEYS) if first_byte(p))
        found.extend(p for p in (os.path.join(home, f) for f in FILES) if first_byte(p))
        for d in DIRS:
            walk(os.path.join(home, d), None, found, budget)
    if cargo_home:
        found.extend(p for p in (os.path.join(cargo_home, f) for f in ("credentials", "credentials.toml")) if first_byte(p))
    if sock:
        try:
            if stat.S_ISSOCK(os.stat(sock).st_mode) and accepts(sock):
                found.append(sock + " (SSH_AUTH_SOCK)")
        except OSError:
            pass
    seen = set()
    for path in found:
        key = os.path.realpath(path.rsplit(" (SSH_AUTH_SOCK)", 1)[0])
        if key not in seen:
            seen.add(key)
            print(shown(path))
    return 1 if found else 0


P = 2 ** 255 - 19
D = -121665 * pow(121666, P - 2, P) % P


def add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P, (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P)


def wallet(path):
    by = 4 * pow(5, P - 2, P) % P
    xx = (by * by - 1) * pow(D * by * by + 1, P - 2, P)
    bx = pow(xx, (P + 3) // 8, P)
    if (bx * bx - xx) % P:
        bx = bx * pow(2, (P - 1) // 4, P) % P
    if bx % 2:
        bx = P - bx
    seed = os.urandom(32)
    a = int.from_bytes(hashlib.sha512(seed).digest()[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    point, acc = (bx, by), (0, 1)
    while a:
        if a & 1:
            acc = add(acc, point)
        point, a = add(point, point), a >> 1
    pub = bytearray(acc[1].to_bytes(32, "little"))
    pub[31] |= (acc[0] & 1) << 7
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(list(seed + bytes(pub)), separators=(",", ":")))
    return 0


try:
    command, args = sys.argv[1], sys.argv[2:]
    if command == "creds":
        sys.exit(creds(args[0], args[1], args[2], args[3:]))
    if command == "homes":
        for home in homes(args[0]):
            print(home)
        sys.exit(0)
    if command == "wallet":
        sys.exit(wallet(args[0]))
except SystemExit:
    raise
except Exception:
    pass
sys.exit(2)
'

iso_homes() {
  python3 -I -c "$ISO_PY" homes "${HOME:-}"
}

iso_credentials() { # iso_credentials [<home>...]
  local rc=0 which=given
  ISO_READABLE=""
  command -v python3 >/dev/null 2>&1 || return 2
  [ $# -gt 0 ] || which=default
  ISO_READABLE=$(python3 -I -c "$ISO_PY" creds "${SSH_AUTH_SOCK:-}" "${CARGO_HOME:-}" "$which" "$@") || rc=$?
  case "$rc" in
    0|1) return "$rc" ;;
  esac
  ISO_READABLE=""
  return 2
}

iso_inherited() { # iso_inherited <dir>
  local d=$1 f home_cargo=${CARGO_HOME:-${HOME:-/nonexistent}/.cargo}
  while :; do
    for f in "$d/.cargo/config" "$d/.cargo/config.toml" "$d/rust-toolchain" "$d/rust-toolchain.toml"; do
      [ -e "$f" ] || [ -L "$f" ] || continue
      case "$f" in "$home_cargo/config"|"$home_cargo/config.toml") continue ;; esac
      printf '%s\n' "$f"
      return 0
    done
    [ "$d" != / ] || return 0
    d=${d%/*}
    [ -n "$d" ] || d=/
  done
}

iso_scratch() { # iso_scratch <tool>
  local base=${TMPDIR:-/tmp} dir found
  ISO_SCRATCH=""
  dir=$(mktemp -d "${base%/}/auditor-$1.XXXXXX" 2>/dev/null) ||
    confine_refuse "cannot create a scratch directory under $(confine_text "$base")"
  confine_phys "$dir" || confine_refuse "the scratch directory $(confine_text "$dir") cannot be resolved"
  ISO_SCRATCH=$CONFINE_PHYS
  case "$ISO_SCRATCH/" in
    "${CONFINE_WT%/}/"*) confine_refuse "the scratch directory $(confine_text "$ISO_SCRATCH") lies inside the working directory; point TMPDIR outside it" ;;
  esac
  found=$(iso_inherited "$ISO_SCRATCH")
  [ -z "$found" ] ||
    confine_refuse "the scratch directory $(confine_text "$ISO_SCRATCH") would inherit $(confine_text "$found"); point TMPDIR outside any repository"
}

iso_env() { # iso_env <dir> [keep-home]
  local v value real=${HOME:-}
  ISO_REAL_HOME=$real
  ISO_TMP=$1/tmp
  confine_mkdir "$ISO_TMP" || return 1
  if [ "${2:-}" = keep-home ]; then
    ISO_HOME=$real
  else
    ISO_HOME=$1/home
    confine_mkdir "$ISO_HOME" && confine_mkdir "$ISO_HOME/.config" && confine_mkdir "$ISO_HOME/.config/solana" || return 1
    python3 -I -c "$ISO_PY" wallet "$ISO_HOME/.config/solana/id.json" || return 1
  fi
  ISO_ENV=("PATH=$PATH" "HOME=$ISO_HOME" "TMPDIR=$ISO_TMP" "LC_ALL=C"
    "CARGO_HOME=${CARGO_HOME:-${real:-/nonexistent}/.cargo}" "RUSTUP_HOME=${RUSTUP_HOME:-${real:-/nonexistent}/.rustup}")
  for v in USER LOGNAME LANG TERM RUSTUP_TOOLCHAIN CARGO_NET_OFFLINE SSL_CERT_FILE SSL_CERT_DIR; do
    value=${!v:-}
    [ -z "$value" ] || ISO_ENV+=("$v=$value")
  done
  ISO_NET=()
  for v in http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY; do
    value=${!v:-}
    [ -z "$value" ] || ISO_NET+=("$v=$value")
  done
}

iso_run() { # iso_run [NAME=value...] <program> [<arg>...]
  local w=""
  [ $# -gt 0 ] || return 126
  for w in "$@"; do
    case "$w" in
      [A-Za-z_]*=*) case "${w%%=*}" in *[!A-Za-z0-9_]*) break ;; esac ;;
      *) break ;;
    esac
  done
  case "$w" in *=*) return 126 ;; esac
  env -i "${ISO_ENV[@]}" "$@"
}

iso_net() { # iso_net [NAME=value...] <program> [<arg>...]
  iso_run ${ISO_NET[@]+"${ISO_NET[@]}"} "$@"
}
