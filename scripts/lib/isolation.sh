# isolation.sh — the isolation self-check and environment cleaning for the bundled runners
# (templates/poc/run.sh, scripts/runner/*.sh), OUTPUT-RULES.md Rule 11a. Sourced, never run, after
# scripts/lib/confine.sh and its confine_init, whose cleaned PATH and WT these functions use.
#
# The self-check. The isolated runner is a container, VM or sandbox with no credentials in reach. In
# $HOME, and in the account's home directory from the passwd database when that differs, it tries to read
# one byte of each file below, and lists the directories, through their subdirectories and the links in
# them, each directory once:
#   ~/.ssh: every entry but known_hosts*, config, *.pub and authorized_keys*; when the directory cannot be
#     listed, id_rsa, id_dsa, id_ecdsa, id_ed25519, id_ecdsa_sk, id_ed25519_sk and identity;
#   ~/.config/solana: every entry (cli/config.yml can hold an RPC URL with a key), and the keypair the
#     keypair_path line of cli/config.yml names, wherever it is;
#   ~/.aws/credentials, and the files in ~/.aws/sso/cache/ and ~/.aws/cli/cache/;
#   ~/.config/gcloud/credentials.db, access_tokens.db and application_default_credentials.json, and the
#     files in ~/.config/gcloud/legacy_credentials/;
#   ~/.azure/accessTokens.json, msal_token_cache.json, msal_token_cache.bin, service_principal_entries.json
#     and service_principal_entries.bin;
#   ~/.kube/config and ~/.docker/config.json;
#   ~/.npmrc, ~/.yarnrc.yml, ~/.gem/credentials, ~/.pypirc, ~/.cargo/credentials and
#     ~/.cargo/credentials.toml;
#   ~/.git-credentials, ~/.config/git/credentials, ~/.netrc and ~/.config/gh/hosts.yml;
#   the files in ~/.gnupg/private-keys-v1.d/, and the gpg-agent sockets ~/.gnupg/S.gpg-agent,
#     S.gpg-agent.ssh, S.gpg-agent.extra and S.gpg-agent.browser;
#   ~/.claude/.credentials.json;
#   1Password's agent socket: ~/.1password/agent.sock, and on macOS
#     ~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock.
# It reads the places these variables name as well, when they are set: SSH_AUTH_SOCK; CARGO_HOME
# (credentials and credentials.toml); XDG_CONFIG_HOME (gh/hosts.yml and git/credentials); GH_CONFIG_DIR
# (hosts.yml); AWS_SHARED_CREDENTIALS_FILE, GOOGLE_APPLICATION_CREDENTIALS, NETRC and NPM_CONFIG_USERCONFIG
# (in either case), each a file; KUBECONFIG, a list of files; DOCKER_CONFIG (config.json); CLOUDSDK_CONFIG
# and AZURE_CONFIG_DIR (the gcloud and azure files above); GNUPGHOME (its private-keys-v1.d/ and gpg-agent
# sockets); TMPDIR (ssh-*/agent.*) and XDG_RUNTIME_DIR (ssh-agent.socket, vscode-ssh-auth-*.sock and
# everything in gnupg/, keyring/ and gcr/). And the agent sockets anyone on the machine can name:
# /tmp/ssh-*/agent.*, /tmp/vscode-ssh-auth-*.sock, macOS's /private/tmp/com.apple.launchd.*/Listeners,
# and /run/user/<uid> as for XDG_RUNTIME_DIR.
# A path counts when it is a regular file, or a link to one, whose first byte can be read, or a socket that
# accepts a connection: a sandbox that blocks Unix sockets leaves SSH_AUTH_SOCK and its socket in place, out
# of reach. Past 5000 entries in the directories it lists, the check stops: it cannot tell (status 2). A
# sandbox that denies reads of these paths passes, so its credentials block must list them all; an
# unsandboxed retry, a sandbox without those deny rules and a host session that recorded "isolated" do not
# pass. The check also names the variables of its own environment whose names look like credentials (a
# part TOKEN, SECRET, PASSWORD, PASSWD or APIKEY, or API_KEY, ACCESS_KEY, PRIVATE_KEY or RPC_URL): no child
# gets them, but code running as the same user can read another process's environment (on Linux, in
# /proc/<pid>/environ).
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
#                                2 when the check cannot run or finish, with ISO_WHY saying why. With no
#                                <home>, it reads the homes iso_homes prints and the machine-wide sockets;
#                                with <home>s, those homes and the places the environment names only. A
#                                caller in isolated mode stops on status 1 or 2; in native mode it prints
#                                what is readable and goes on.
#   iso_cred_names               sets ISO_NAMES to the variables of this environment whose names look like
#                                credentials, separated by ", "; empty when there are none or python3 is
#                                missing.
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

# What iso_credentials, iso_cred_names, iso_homes and iso_env run, with python3 -I so that no module comes
# from the working directory or PYTHONPATH. "creds given|default [<home>...]" prints the readable paths
# (exit 1) or nothing (exit 0), and why the check could not finish (exit 2); "names" prints the variable
# names that look like credentials; "homes <home>" prints the homes; "wallet <path>" writes a fresh
# keypair, RFC 8032 key generation from 32 random bytes, as the 64-number array solana-keygen writes. Exit 2
# on anything unexpected.
ISO_PY='import glob, hashlib, json, os, pwd, re, socket, stat, sys

GCLOUD = ("credentials.db", "access_tokens.db", "application_default_credentials.json")
AZURE = ("accessTokens.json", "msal_token_cache.json", "msal_token_cache.bin", "service_principal_entries.json",
         "service_principal_entries.bin")
FILES = ((".config/solana/id.json", ".aws/credentials") + tuple(".config/gcloud/" + f for f in GCLOUD)
         + tuple(".azure/" + f for f in AZURE)
         + (".kube/config", ".docker/config.json", ".npmrc", ".yarnrc.yml", ".gem/credentials", ".pypirc",
            ".cargo/credentials", ".cargo/credentials.toml", ".git-credentials", ".config/git/credentials", ".netrc",
            ".config/gh/hosts.yml", ".claude/.credentials.json"))
DIRS = (".config/solana", ".aws/sso/cache", ".aws/cli/cache", ".config/gcloud/legacy_credentials",
        ".gnupg/private-keys-v1.d")
GPG_SOCKETS = ("S.gpg-agent", "S.gpg-agent.ssh", "S.gpg-agent.extra", "S.gpg-agent.browser")
SOCKETS = tuple(".gnupg/" + s for s in GPG_SOCKETS) + (
    ".1password/agent.sock", "Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock")
SSH_KEEP = re.compile(r"^(known_hosts.*|config|.*\.pub|authorized_keys.*)$")
SSH_KEYS = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "identity")
BUDGET = 5000
KEYPAIR = re.compile(r"^keypair_path:[ \t]*(?:\"([^\"]*)\"|\x27([^\x27]*)\x27|(.*?))(?:[ \t]+#.*)?[ \t]*$")


class Unfinished(Exception):
    pass


def shown(path):
    return re.sub(r"[\x00-\x1f\x7f]", "?", path)[:300]


def start(path, size):
    # The first <size> bytes of a regular file, or of a link to one, opened without blocking so that a FIFO in
    # its place cannot stall the check; None when it cannot be read.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOCTTY", 0))
    except OSError:
        return None
    try:
        return os.read(fd, size) if stat.S_ISREG(os.fstat(fd).st_mode) else None
    except OSError:
        return None
    finally:
        os.close(fd)


def first_byte(path):
    return len(start(path, 1) or b"") == 1


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


def readable(found, paths):
    found.extend(p for p in paths if p and first_byte(p))


def sockets(found, paths):
    for path in paths:
        try:
            if stat.S_ISSOCK(os.stat(path).st_mode) and accepts(path):
                found.append(path)
        except OSError:
            pass


def enter(path, stack, seen):
    # Queue a directory for listing, once: a link to one already listed adds nothing.
    try:
        st = os.stat(path)
        if not stat.S_ISDIR(st.st_mode):
            return False
        names = sorted(os.listdir(path), reverse=True)
    except OSError:
        return False
    if (st.st_dev, st.st_ino) not in seen:
        seen.add((st.st_dev, st.st_ino))
        stack.append((path, names))
    return True


def walk(top, keep, found, state):
    # Every entry under <top> but the names <keep> matches, through subdirectories and links to them. False
    # when <top> cannot be listed; past BUDGET entries in all the walks, the check cannot finish.
    stack = []
    if not enter(top, stack, state["seen"]):
        return False
    while stack:
        directory, names = stack[-1]
        if not names:
            stack.pop()
            continue
        name = names.pop()
        state["left"] -= 1
        if state["left"] < 0:
            raise Unfinished("more than %d entries in the directories it lists" % BUDGET)
        if keep and keep.match(name):
            continue
        path = os.path.join(directory, name)
        try:
            mode = os.stat(path).st_mode
        except OSError:
            continue
        if stat.S_ISDIR(mode):
            enter(path, stack, state["seen"])
        elif stat.S_ISSOCK(mode):
            if accepts(path):
                found.append(path)
        elif first_byte(path):
            found.append(path)
    return True


def keypair(home):
    # The keypair the keypair_path line of the Solana CLI config in <home> names, "~" standing for <home>.
    text = (start(os.path.join(home, ".config/solana/cli/config.yml"), 65536) or b"").decode("utf-8", "replace")
    for line in text.splitlines():
        m = KEYPAIR.match(line)
        if m:
            value = next((g for g in m.groups() if g is not None), "")
            if value == "~" or value.startswith("~/"):
                value = home + value[1:]
            return os.path.join(home, value) if value else ""
    return ""


def runtime(directory, dirs, socks):
    dirs.extend(os.path.join(directory, d) for d in ("gnupg", "keyring", "gcr"))
    socks.append(os.path.join(directory, "ssh-agent.socket"))
    socks.extend(glob.glob(os.path.join(glob.escape(directory), "vscode-ssh-auth-*.sock")))


def named(env, files, dirs, socks):
    # The places the environment names.
    for name in ("AWS_SHARED_CREDENTIALS_FILE", "GOOGLE_APPLICATION_CREDENTIALS", "NETRC", "NPM_CONFIG_USERCONFIG",
                 "npm_config_userconfig"):
        files.append(env.get(name, ""))
    files.extend(env.get("KUBECONFIG", "").split(os.pathsep))
    for name, under in (("CARGO_HOME", ("credentials", "credentials.toml")), ("XDG_CONFIG_HOME", ("gh/hosts.yml", "git/credentials")),
                        ("GH_CONFIG_DIR", ("hosts.yml",)), ("DOCKER_CONFIG", ("config.json",)), ("CLOUDSDK_CONFIG", GCLOUD),
                        ("AZURE_CONFIG_DIR", AZURE)):
        if env.get(name):
            files.extend(os.path.join(env[name], f) for f in under)
    if env.get("CLOUDSDK_CONFIG"):
        dirs.append(os.path.join(env["CLOUDSDK_CONFIG"], "legacy_credentials"))
    if env.get("GNUPGHOME"):
        dirs.append(os.path.join(env["GNUPGHOME"], "private-keys-v1.d"))
        socks.extend(os.path.join(env["GNUPGHOME"], s) for s in GPG_SOCKETS)
    if env.get("TMPDIR"):
        socks.extend(glob.glob(os.path.join(glob.escape(env["TMPDIR"]), "ssh-*", "agent.*")))
    if env.get("XDG_RUNTIME_DIR"):
        runtime(env["XDG_RUNTIME_DIR"], dirs, socks)


def homes(home):
    out = [home] if home else []
    try:
        account = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        account = ""
    if account and not (home and os.path.realpath(account) == os.path.realpath(home)):
        out.append(account)
    return out


def creds(which, given):
    env = os.environ
    found, state, files, dirs, socks = [], {"left": BUDGET, "seen": set()}, [], [], []
    for home in (given if which == "given" else homes(env.get("HOME", ""))):
        if not home:
            continue
        ssh = os.path.join(home, ".ssh")
        if not walk(ssh, SSH_KEEP, found, state):
            readable(found, (os.path.join(ssh, k) for k in SSH_KEYS))
        readable(found, (os.path.join(home, f) for f in FILES))
        for d in DIRS:
            walk(os.path.join(home, d), None, found, state)
        sockets(found, (os.path.join(home, s) for s in SOCKETS))
        readable(found, [keypair(home)])
    named(env, files, dirs, socks)
    if which == "default":
        # The agent sockets anyone on the machine can name.
        socks.extend(glob.glob("/tmp/ssh-*/agent.*") + glob.glob("/tmp/vscode-ssh-auth-*.sock")
                     + glob.glob("/private/tmp/com.apple.launchd.*/Listeners"))
        runtime("/run/user/%d" % os.getuid(), dirs, socks)
    readable(found, files)
    for d in dirs:
        walk(d, None, found, state)
    sockets(found, socks)
    sock = env.get("SSH_AUTH_SOCK", "")
    if sock:
        mark = []
        sockets(mark, [sock])
        found.extend(p + " (SSH_AUTH_SOCK)" for p in mark)
    seen = set()
    for path in found:
        key = os.path.realpath(path.rsplit(" (SSH_AUTH_SOCK)", 1)[0])
        if key not in seen:
            seen.add(key)
            print(shown(path))
    return 1 if found else 0


def names(env):
    # The variables whose names look like credentials: a part TOKEN, SECRET, PASSWORD, PASSWD or APIKEY, or
    # API_KEY, ACCESS_KEY, PRIVATE_KEY or RPC_URL.
    out = []
    for name in sorted(env):
        parts = name.upper().split("_")
        if (set(parts) & {"TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY"}
                or set(zip(parts, parts[1:])) & {("API", "KEY"), ("ACCESS", "KEY"), ("PRIVATE", "KEY"), ("RPC", "URL")}):
            out.append(shown(name))
    print(", ".join(out))
    return 0


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
        sys.exit(creds(args[0], args[1:]))
    if command == "names":
        sys.exit(names(os.environ))
    if command == "homes":
        for home in homes(args[0]):
            print(home)
        sys.exit(0)
    if command == "wallet":
        sys.exit(wallet(args[0]))
except SystemExit:
    raise
except Unfinished as why:
    print(why)
except BaseException:
    pass
sys.exit(2)
'

iso_homes() {
  python3 -I -c "$ISO_PY" homes "${HOME:-}"
}

iso_credentials() { # iso_credentials [<home>...]
  local rc=0 which=given out
  ISO_READABLE="" ISO_WHY=""
  command -v python3 >/dev/null 2>&1 || { ISO_WHY="python3 is not on PATH"; return 2; }
  [ $# -gt 0 ] || which=default
  out=$(python3 -I -c "$ISO_PY" creds "$which" "$@") || rc=$?
  case "$rc" in
    0|1) ISO_READABLE=$out; return "$rc" ;;
  esac
  ISO_WHY=${out%%$'\n'*}
  [ -n "$ISO_WHY" ] || ISO_WHY="the check stopped on an error"
  return 2
}

iso_cred_names() { # iso_cred_names
  ISO_NAMES=""
  command -v python3 >/dev/null 2>&1 || return 0
  ISO_NAMES=$(python3 -I -c "$ISO_PY" names 2>/dev/null) || ISO_NAMES=""
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
