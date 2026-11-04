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
#   ~/.aws/credentials, and the files in ~/.aws/sso/cache/ and ~/.aws/cli/cache/; ~/.aws/config when it
#     sets credential_process, aws_secret_access_key or aws_session_token;
#   ~/.config/gcloud/credentials.db, access_tokens.db and application_default_credentials.json, and the
#     files in ~/.config/gcloud/legacy_credentials/;
#   ~/.azure/accessTokens.json, msal_token_cache.json, msal_token_cache.bin, service_principal_entries.json
#     and service_principal_entries.bin;
#   ~/.vault-token and ~/.terraform.d/credentials.tfrc.json; ~/.terraformrc when it holds a credentials block
#     or names a credentials_helper;
#   ~/.kube/config and ~/.docker/config.json; the Docker TLS client keys ~/.docker/key.pem and
#     ~/.docker/contexts/tls/*/*/key.pem, which open a daemon that checks its clients;
#   ~/.npmrc, ~/.yarnrc.yml, ~/.gem/credentials, ~/.pypirc, ~/.cargo/credentials and
#     ~/.cargo/credentials.toml;
#   ~/.git-credentials, ~/.config/git/credentials, ~/.netrc, ~/.config/gh/hosts.yml and ~/.gitcookies;
#   ~/.gitconfig and ~/.config/git/config, with the files they include (include.path and
#     includeIf.<condition>.path, whatever the condition), when one names a credential helper
#     (credential.helper), an askpass program (core.askPass) or a cookie file (http.cookieFile), sends an HTTP
#     header (http.extraHeader), rewrites to an http(s) URL that carries a login (url.<base>), or goes through
#     a proxy with a login (http.proxy, remote.<name>.proxy): through each, git gives a login to any code here
#     that runs it. Dev Containers and Codespaces forward the host's git login through such a helper. git's
#     own store and cache helpers count by what they hand out: with no --file or --socket, through their
#     default file and socket, which count on their own; with one, when that file is readable or that socket
#     accepts a connection, the file or the socket counting. Written with shell syntax (quotes, an escape, a
#     variable, a glob) or with a relative path, either counts as any other helper does;
#   the files in ~/.gnupg/private-keys-v1.d/, and the gpg-agent sockets ~/.gnupg/S.gpg-agent,
#     S.gpg-agent.ssh, S.gpg-agent.extra and S.gpg-agent.browser;
#   Claude Code's login: .credentials.json in ~/.claude and in every other ~/.claude* directory (where
#     CLAUDE_CONFIG_DIR keeps a second account), and every file under ~/.config/anthropic (Anthropic
#     profiles and their tokens, which Claude Code also signs in with);
#   Claude Code's settings and state when one holds a credential: settings.json, settings.local.json,
#     remote-settings.json, .claude.json and backups/.claude.json* in each ~/.claude* directory, and
#     ~/.claude.json and its backups (the state file, which keeps the personal MCP servers). One counts when it
#     names a command that prints a credential (apiKeyHelper, awsCredentialExport, otelHeadersHelper, an MCP
#     server's headersHelper); when an env block in it, its own or an MCP server's, gives a value to a variable
#     whose name looks like a credential (as below; an RPC_URL counts only by what its URL carries), a value an
#     HTTP authentication scheme sends, a value with a URL that carries one, or, to a name that ends in HEADER
#     or HEADERS, a list of headers (Name: value lines, Name=value pairs or a JSON object) that sends a
#     credential header, or for OTEL_EXPORTER_OTLP_HEADERS and its per-signal forms, which authenticate the
#     exporter, any header; when a headers block sends a credential header; or when a URL (an MCP server's or a
#     hook's) or an MCP server's arguments carry one. An env block's CLAUDE_CODE_CLIENT_KEY, and
#     OTEL_EXPORTER_OTLP_CLIENT_KEY and its per-signal forms (the mTLS client keys of Claude Code and of its
#     OTLP exporter over gRPC), count by the file they name: at an absolute path or under "~/", the file counts
#     when it is readable; at another path, which the check cannot place, the settings file counts. A
#     credential header is Authorization, any *-Authorization, Cookie, a name a key goes by, or any name with a
#     value an authentication scheme sends. The name a key goes by, of a header, an option or a query
#     parameter, looks like a credential or has a last part KEY, AUTH, BEARER, AUTHORIZATION, CREDENTIAL or
#     CREDENTIALS, but for a key that is no secret: a public key, and a table's partition, sort or range key
#     (x-api-key, Ocp-Apim-Subscription-Key, Helicone-Auth, --oauth2Bearer; not --public-key or
#     --partition-key). An authentication scheme sends Bearer and a token of eight or more characters, or Basic
#     and the base64 of a user and a password. A URL carries one in its login (any user name in an http, ws or
#     socks URL, a user and a password in another), in a query or fragment parameter named as a key goes by or
#     sig or signature, or, when it has a host other than a code host (github.com, githubusercontent.com,
#     gitlab.com, bitbucket.org, codeberg.org and their subdomains, whose paths hold names and commits), in a
#     path segment that can be a key: 20 or more letters, digits, - and _, with a run of seven or more letters
#     and digits holding both (https://<name>.quiknode.pro/<token>/; an id such as a UUID counts too, while a
#     version or a date in a name holds none). Arguments carry one in an option named as a key goes by, with a
#     value (--api-key <value>, --key=<value>; a --no- option takes none, and a word that starts with - is the
#     next option), in NAME=<value> as an env block would set it, in a header option (-H, --header, --headers)
#     as Name: value, as a JSON object or as a name and a value of their own (mcp-proxy --headers Authorization
#     <value>), in a value an authentication scheme sends, or in a URL. A value that refers to a variable
#     (${NAME}) does not count, nor does a word that switches a setting or names an authentication method
#     (true, false, yes, no, on, off, 0, 1, none, null, oauth, oauth2, oidc, basic, bearer, digest, token,
#     apikey, jwt, mtls), and neither does a file that is not JSON; one larger than 16 MiB stops the check
#     (status 2);
#   1Password's agent socket: ~/.1password/agent.sock, and on macOS
#     ~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock;
#   the sockets of a container daemon, which gives whoever reaches it the host: Docker Desktop's
#     ~/.docker/run/docker.sock and ~/.docker/desktop/docker.sock, Colima's ~/.colima/*/docker.sock, Rancher
#     Desktop's ~/.rd/docker.sock, OrbStack's ~/.orbstack/run/docker.sock, Lima's ~/.lima/*/sock/docker.sock
#     and ~/.lima/*/sock/podman.sock, and a Podman machine's
#     ~/.local/share/containers/podman/machine/*/podman.sock;
#   git's credential cache sockets, ~/.cache/git/credential/socket and ~/.git-credential-cache/socket.
# It reads the places these variables name as well, when they are set: SSH_AUTH_SOCK; CARGO_HOME
# (credentials and credentials.toml); XDG_CONFIG_HOME (gh/hosts.yml, git/credentials, and git/config as
# ~/.gitconfig is read); XDG_CACHE_HOME (git/credential/socket); GH_CONFIG_DIR (hosts.yml);
# AWS_SHARED_CREDENTIALS_FILE, GOOGLE_APPLICATION_CREDENTIALS, NETRC, NPM_CONFIG_USERCONFIG (in either case),
# GIT_ASKPASS, SSH_ASKPASS, ANTHROPIC_IDENTITY_TOKEN_FILE, CLAUDE_CODE_CLIENT_KEY, and
# OTEL_EXPORTER_OTLP_CLIENT_KEY and its per-signal forms, each a file; GIT_CONFIG_GLOBAL and
# GIT_CONFIG_SYSTEM, read as ~/.gitconfig is; AWS_CONFIG_FILE, read as ~/.aws/config is; TF_CLI_CONFIG_FILE,
# read as ~/.terraformrc is; KUBECONFIG, a list of files; DOCKER_CONFIG (config.json and
# contexts/tls/*/*/key.pem); DOCKER_CERT_PATH (key.pem); CLAUDE_CONFIG_DIR (.credentials.json, and the
# settings and state files above); ANTHROPIC_CONFIG_DIR (every file under it); CLOUDSDK_CONFIG and
# AZURE_CONFIG_DIR (the gcloud and azure files above); GNUPGHOME (its private-keys-v1.d/ and gpg-agent
# sockets); DOCKER_HOST and CONTAINER_HOST (a unix:// socket, or a tcp:// address, port 2375 when it names
# none, that accepts a TCP connection: for DOCKER_HOST only when DOCKER_TLS_VERIFY is not set, since a daemon
# that checks TLS clients takes the key read above);
# VSCODE_GIT_IPC_HANDLE and REMOTE_CONTAINERS_IPC (the sockets through which VS Code and its Dev Containers
# answer git's credential requests with the host's login); TMPDIR (ssh-*/agent.*, vscode-git-*.sock and
# podman/*.sock) and XDG_RUNTIME_DIR (ssh-agent.socket, vscode-ssh-auth-*.sock, vscode-git-*.sock,
# docker.sock, podman/podman.sock and everything in gnupg/, keyring/ and gcr/). And what anyone on the machine
# can name: the sockets /tmp/ssh-*/agent.*, /tmp/vscode-ssh-auth-*.sock, /tmp/vscode-git-*.sock,
# /tmp/vscode-remote-containers-ipc-*.sock and macOS's /private/tmp/com.apple.launchd.*/Listeners; docker.sock,
# podman/podman.sock and containerd/containerd.sock in /run and /var/run; /run/user/<uid> as for
# XDG_RUNTIME_DIR; /etc/gitconfig, read as ~/.gitconfig is; and Claude Code's managed settings,
# managed-settings.json, managed-settings.d/*.json and managed-mcp.json in /Library/Application
# Support/ClaudeCode and /etc/claude-code, read as its settings are.
# A path counts when it is a regular file, or a link to one, whose first byte can be read, or a socket that
# accepts a connection: a sandbox that blocks Unix sockets leaves SSH_AUTH_SOCK and its socket in place, out
# of reach. Past 5000 entries in the directories it lists, the check stops: it cannot tell (status 2). A
# sandbox that denies reads of these paths passes, so its credentials block must list them all; an
# unsandboxed retry, a sandbox without those deny rules and a host session that recorded "isolated" do not
# pass. The check also names the variables of its own environment whose names look like credentials (a
# part TOKEN, SECRET, PASSWORD, PASSWD, PASSPHRASE, APIKEY, PWD, PASS or PAT, a part that ends in PASSWORD or
# PASSWD, API_KEY, ACCESS_KEY, PRIVATE_KEY or RPC_URL, or a last part KEY but for a key that is no secret as
# above, the parts apart at _, - and . and where a lower-case letter or a digit meets an upper-case one; not
# PWD and OLDPWD themselves, nor the client key variables, which name files): no child gets them, but code
# running as the same user can read another process's environment (on Linux, in /proc/<pid>/environ).
#
# Environment cleaning, in every mode. A child runs under env -i with only these variables: PATH as
# confine_init cleaned it; HOME, a throwaway directory holding a fresh Solana keypair at
# .config/solana/id.json; TMPDIR, a scratch directory; LC_ALL=C; USER, LOGNAME, LANG, TERM,
# RUSTUP_TOOLCHAIN, CARGO_NET_OFFLINE, SSL_CERT_FILE and SSL_CERT_DIR when they are set; the user's
# CARGO_HOME and RUSTUP_HOME, resolved against the real HOME; and the variables its caller adds. A child
# that only downloads (cargo fetch or cargo update, which run no build script, or an installer) also gets
# the proxy variables http_proxy, https_proxy, all_proxy and no_proxy, in either case, when they are set:
# a sandbox's network allowlist works through them, and its proxy URL can carry a session token, so
# nothing that compiles or runs code from the build gets them (a build script or proc-macro would see
# them too). No token, RPC_URL, SSH_AUTH_SOCK, or git or cargo setting in the environment reaches a
# child.
#
# Functions:
#   iso_homes                    prints the home directories the self-check reads, one per line.
#   iso_credentials [<home>...]  sets ISO_KINDS to what is readable, by kind and count ("SSH keys (2),
#                                cloud credentials (1)"), and ISO_READABLE to the readable paths, one per
#                                line: a path under a home it reads starts with ~, the gcloud account in
#                                legacy_credentials/ is <account>, and control characters are printed as ?.
#                                Status 0 when none is readable, 1 when some are, 2 when the check cannot
#                                run or finish, with ISO_WHY saying why. With no <home>, it reads the homes
#                                iso_homes prints, the places the environment names and the machine-wide
#                                places; with <home>s, those homes and the places the environment names
#                                only. A caller in isolated mode stops on status 1 or 2; in native mode it
#                                prints what is readable and goes on. What a report may carry is
#                                ISO_KINDS, never the paths.
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
#   iso_tmp_outside              refuses (confine_refuse) a TMPDIR (else /tmp) that cannot be resolved or
#                                resolves inside WT, before anything is made there; iso_scratch checks the
#                                directory it made as well.
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
#                                the same, with the proxy words of ISO_NET as well: for a download that
#                                runs no code from the build.
#   iso_watch <seconds> <report> <dir> [NAME=value...] <program> [<arg>...]
#                                runs <program> as iso_run does, in <dir>, with standard input closed, in a
#                                session of its own, under ulimit -t of four times <seconds> and ulimit -f of
#                                4194304 (ulimit -f counts 1024-byte blocks, so 4 GiB). After <seconds> of
#                                wall-clock time every process of that session's
#                                group gets SIGTERM, then SIGKILL five seconds later, and so does every one
#                                left when <program> exits. python3 starts from /, so nothing in the working
#                                directory picks the interpreter. It writes one line to <report>, a new file:
#                                "exit <n>", "signal <n>" (the program died of signal <n>), "timeout",
#                                "stopped by signal <n>" (the watchdog itself got it) or "cannot start:
#                                <why>". Its status is the program's, 128+<n> for a signal, 124 on a timeout.
#                                ISO_WATCH_PID names the watchdog while it runs, for a caller's signal trap.
#   iso_copy_new <file> <path>   copies the regular file <file>, never a symbolic link, into <path>, which
#                                must not exist (a link counts), through the descriptor opened at its
#                                creation; status 1 when it cannot.
#   iso_incident_class <INCIDENTS.json> [<INC-n.k>]
#                                sets ISO_CLASS to the root_cause_class that file (an absolute path) records
#                                for that incident, or, with no id, to supply_chain_or_ci when any incident has
#                                it and to "other" otherwise; status 3 with ISO_CLASS the reason when the file,
#                                an incident or a class cannot be read (references/detection-response/
#                                incidents-schema.md); the reason is "is missing" only when no file is there.
#                                python3 starts from /, as for the self-check.
#   iso_incident_runs <working directory>
#                                reads in turn, as iso_incident_class does with no id, the INCIDENTS.json of
#                                each directory at the top of <working directory> (an absolute path) named
#                                incident_* in any letter case, since a volume that ignores case finds
#                                incident_1 under the name INCIDENT_1: sets ISO_CLASS to supply_chain_or_ci at
#                                the first that records such an incident, and to "other" when none does, and
#                                ISO_INCIDENTS to that file, relative to <working directory> and cut as
#                                confine_shown cuts. A directory whose INCIDENTS.json is missing, or whose file
#                                records no incident (a hunt that ruled everything out), counts for nothing.
#                                Status 3, with ISO_CLASS the reason, at the first file that cannot be read:
#                                only python3 tells that a file is missing, so a stat that fails for another
#                                reason (a directory that cannot be searched, a path past PATH_MAX) gives it,
#                                and so does a working directory that cannot be listed (ISO_INCIDENTS is then
#                                "the working directory"). Status 2 when such a directory is there and python3
#                                is not on PATH. The list does not depend on the caller's set -f.
# Needs bash >= 3.2, python3 (the self-check, the keypair and the watchdog), env, mkdir, mktemp and cat.

# What iso_credentials, iso_cred_names, iso_homes and iso_env run, with python3 -I so that no module comes
# from the working directory or PYTHONPATH. python3 starts from /, so nothing in the working directory picks
# the interpreter (a .python-version a pyenv shim reads), and a relative path in a variable the check reads
# is taken from /, never from the tree under audit. "creds given|default [<home>...]" prints what is
# readable by kind and count on its first line and the readable paths after it (exit 1), nothing (exit 0),
# or why the check could not finish (exit 2); "names" prints the variable names that look like credentials;
# "homes <home>" prints the homes; "wallet <path>" writes a fresh keypair, RFC 8032 key generation from 32
# random bytes, as the 64-number array solana-keygen writes. Exit 2 on anything unexpected.
ISO_PY='import base64, glob, hashlib, json, os, pwd, re, socket, stat, sys, urllib.parse

KINDS = ("SSH keys", "agent sockets", "container daemon sockets", "Solana keypairs or CLI config", "cloud credentials",
         "Kubernetes or Docker config", "package registry tokens", "git or HTTP credentials", "GnuPG private keys",
         "Claude Code credentials")
SSH, AGENT, DAEMON, SOLANA, CLOUD, CLUSTER, REGISTRY, GIT, GPG, CLAUDE = KINDS
GCLOUD = ("credentials.db", "access_tokens.db", "application_default_credentials.json")
AZURE = ("accessTokens.json", "msal_token_cache.json", "msal_token_cache.bin", "service_principal_entries.json",
         "service_principal_entries.bin")
FILES = (((SOLANA, ".config/solana/id.json"), (CLOUD, ".aws/credentials"))
         + tuple((CLOUD, ".config/gcloud/" + f) for f in GCLOUD) + tuple((CLOUD, ".azure/" + f) for f in AZURE)
         + ((CLOUD, ".vault-token"), (CLOUD, ".terraform.d/credentials.tfrc.json"), (CLUSTER, ".kube/config"),
            (CLUSTER, ".docker/config.json"), (CLUSTER, ".docker/key.pem"), (REGISTRY, ".npmrc"), (REGISTRY, ".yarnrc.yml"),
            (REGISTRY, ".gem/credentials"), (REGISTRY, ".pypirc"), (REGISTRY, ".cargo/credentials"),
            (REGISTRY, ".cargo/credentials.toml"),
            (GIT, ".git-credentials"), (GIT, ".config/git/credentials"), (GIT, ".netrc"), (GIT, ".config/gh/hosts.yml"),
            (GIT, ".gitcookies")))
DIRS = ((SOLANA, ".config/solana"), (CLOUD, ".aws/sso/cache"), (CLOUD, ".aws/cli/cache"),
        (CLOUD, ".config/gcloud/legacy_credentials"), (GPG, ".gnupg/private-keys-v1.d"), (CLAUDE, ".config/anthropic"))
GPG_SOCKETS = ("S.gpg-agent", "S.gpg-agent.ssh", "S.gpg-agent.extra", "S.gpg-agent.browser")
# Under a home, as glob patterns.
SOCKETS = (tuple((AGENT, ".gnupg/" + s) for s in GPG_SOCKETS)
           + ((AGENT, ".1password/agent.sock"), (AGENT, "Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"),
              (DAEMON, ".docker/run/docker.sock"), (DAEMON, ".docker/desktop/docker.sock"), (DAEMON, ".colima/*/docker.sock"),
              (DAEMON, ".rd/docker.sock"), (DAEMON, ".orbstack/run/docker.sock"), (DAEMON, ".lima/*/sock/docker.sock"),
              (DAEMON, ".lima/*/sock/podman.sock"), (DAEMON, ".local/share/containers/podman/machine/*/podman.sock"),
              (GIT, ".cache/git/credential/socket"),
              (GIT, ".git-credential-cache/socket")))
GIT_CONFIGS = (".gitconfig", ".config/git/config")
# The TLS client keys of the Docker contexts, under a Docker config directory.
DOCKER_KEYS = "contexts/tls/*/*/key.pem"
SSH_KEEP = re.compile(r"^(known_hosts.*|config|.*\.pub|authorized_keys.*)$")
SSH_KEYS = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "identity")
BUDGET = 5000
KEYPAIR = re.compile(r"^keypair_path:[ \t]*(?:\"([^\"]*)\"|\x27([^\x27]*)\x27|(.*?))(?:[ \t]+#.*)?[ \t]*$")
# A git config section header (the name, a quoted subsection) and an entry (a name, then = and a value or nothing).
GIT_SECTION = re.compile(r"[ \t]*\[[ \t]*([A-Za-z0-9.-]+)[ \t]*(?:\"((?:[^\"\\]|\\.)*)\"[ \t]*)?\]")
GIT_ENTRY = re.compile(r"[ \t]*([A-Za-z][A-Za-z0-9-]*)[ \t]*(=?)(.*)")
URL_LOGIN = re.compile(r"(?i)https?://[^/@]+@")
# A proxy as git takes it, [protocol://][user[:password]@]host[:port], with a login.
PROXY_LOGIN = re.compile(r"(?i)^(?:[a-z][a-z0-9+.-]*://)?[^/@\s]+@")
# What a shell, which runs a credential helper, reads as more than plain words: quotes, an escape, a variable,
# a substitution, a glob, an operator or a comment.
SHELL_SYNTAX = re.compile(r"[\"\x27\\$`;&|<>(){}*?\[\]#\n]")
# The helpers git ships that hand out only what a file or a socket holds, and the option that names it.
GIT_HELPERS = {"git-credential-store": "file", "git-credential-cache": "socket"}
# Botocore reads an AWS config with either = or : between a name and its value.
AWS_SECRET = re.compile(r"(?im)^[ \t]*(credential_process|aws_secret_access_key|aws_session_token)[ \t]*[=:][ \t]*[^\s#;]")
# A credentials block (an API token for a host) or a credentials_helper block in a Terraform CLI config.
TF_CREDENTIALS = re.compile(r"(?m)^[ \t]*credentials(?:_helper)?[ \t]+\"")
# Claude Code: the settings and state files of a ~/.claude* directory or CLAUDE_CONFIG_DIR, and the managed
# settings in the system directories, as glob patterns; the settings that run a command printing a credential.
CLAUDE_FILES = ("settings.json", "settings.local.json", "remote-settings.json", ".claude.json*", "backups/.claude.json*")
MANAGED = ("/Library/Application Support/ClaudeCode", "/etc/claude-code")
MANAGED_FILES = ("managed-settings.json", "managed-settings.d/*.json", "managed-mcp.json")
CLAUDE_HELPERS = ("apiKeyHelper", "awsCredentialExport", "otelHeadersHelper", "headersHelper")
CLAUDE_LIMIT = 16 << 20
REFERENCE = re.compile(r"\$(?:\{|[A-Za-z_])")
# The values that switch a setting or name an authentication method (--auth none, --credentials=true), which no
# credential is.
SWITCHES = ("true", "false", "yes", "no", "on", "off", "0", "1", "none", "null", "oauth", "oauth2", "oidc", "basic",
            "bearer", "digest", "token", "apikey", "jwt", "mtls")
# The last parts of a name a key goes by when the rest of it does not look like a credential (--key, --auth,
# --oauth2Bearer, --credentials), and the parts before the last that make a key no secret (a public key; a
# table key, --partition-key pk).
KEY_PARTS = ("KEY", "AUTH", "BEARER", "AUTHORIZATION", "CREDENTIAL", "CREDENTIALS")
NOT_SECRET = ("PUBLIC", "PUBLISHABLE", "PUB", "PARTITION", "SORT", "RANGE")
# A value an HTTP authentication scheme sends, with nothing else: Bearer and a token of eight or more characters
# (RFC 6750), or Basic and the base64 of a user and a password (RFC 7617), which auth_value decodes.
BEARER = re.compile(r"(?i)[ \t]*bearer[ \t]+[A-Za-z0-9._~+/-]{8,}=*[ \t]*")
BASIC = re.compile(r"(?i)[ \t]*basic[ \t]+([A-Za-z0-9+/]+={0,2})[ \t]*")
# The variables that name an mTLS client key file, read as that file: CLAUDE_CODE_CLIENT_KEY, and
# OTEL_EXPORTER_OTLP_CLIENT_KEY and its per-signal forms, which Claude Code takes for an OTLP exporter over gRPC.
CLIENT_KEY = re.compile(r"CLAUDE_CODE_CLIENT_KEY|OTEL_EXPORTER_OTLP_(?:[A-Z]+_)?CLIENT_KEY")
# A URL in a value; the schemes whose user name alone can be a token (https://<token>@host); the names a query
# parameter holding a key takes beside those a key goes by (key_name); a path segment that can be a key
# (path_key), as a key in a path has no name (https://<name>.solana-mainnet.quiknode.pro/<token>/,
# https://anthropic.helicone.ai/<key>); the hosts that serve code by its commit, whose paths hold commits and
# names, never a key (https://raw.githubusercontent.com/<owner>/<repo>/<commit>/<file>).
URL_IN = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"\x27<>]+")
TOKEN_USER = ("http", "https", "ws", "wss", "socks", "socks4", "socks4a", "socks5", "socks5h")
QUERY_KEYS = ("SIG", "SIGNATURE")
PATH_KEY = re.compile(r"[A-Za-z0-9_-]{20,}")
CODE_HOSTS = ("github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "codeberg.org")
# One header of a list, Name: value or Name=value, the headers apart by newlines or commas; a header name on its
# own, as the argument after a header option that takes the name and the value apart (mcp-proxy --headers
# <name> <value>); the variables whose headers all count, since the OTLP exporter sends them to authenticate
# (OTEL_EXPORTER_OTLP_HEADERS and its per-signal forms).
HEADER = re.compile(r"(?:^|[\n,])[ \t]*([A-Za-z0-9_.-]+)[ \t]*[:=]([^\n,]*)")
HEADER_NAME = re.compile(r"[A-Za-z0-9_.-]+")
OTLP_HEADERS = re.compile(r"OTEL_EXPORTER_OTLP_(?:[A-Z]+_)?HEADERS")


class Unfinished(Exception):
    pass


def shown(path, bases=()):
    # A path under a home the check reads starts with ~, and the gcloud account in legacy_credentials/ is
    # <account>: the paths name kinds of credentials, not the user.
    for base in [b.rstrip("/") for b in bases] + [os.path.realpath(b) for b in bases]:
        if base and base != "/" and (path == base or path.startswith(base + "/")):
            path = "~" + path[len(base):]
            break
    path = re.sub(r"(legacy_credentials/)[^/]+", r"\1<account>", path)
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


def reaches(address):
    # A tcp:// address that accepts a TCP connection within two seconds, at port 2375 when it names none.
    try:
        url = urllib.parse.urlsplit(address)
        if url.hostname:
            socket.create_connection((url.hostname, url.port or 2375), timeout=2).close()
            return True
    except (OSError, UnicodeError, ValueError):
        pass
    return False


def readable(found, kind, paths):
    found.extend((kind, p) for p in paths if p and first_byte(p))


def sockets(found, socks):
    # A Unix socket that accepts a connection, or a tcp:// address that does.
    for kind, path in socks:
        if path.startswith("tcp://"):
            if reaches(path):
                found.append((kind, path))
            continue
        try:
            if stat.S_ISSOCK(os.stat(path).st_mode) and accepts(path):
                found.append((kind, path))
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


def walk(top, keep, found, state, kind):
    # Every entry under <top> but the names <keep> matches, through subdirectories and links to them: a file
    # counts as <kind>, a socket as an agent. False when <top> cannot be listed; past BUDGET entries in all
    # the walks, the check cannot finish.
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
                found.append((AGENT, path))
        elif first_byte(path):
            found.append((kind, path))
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


def git_value(text):
    # A git config value without its quotes, its escapes and a comment after it.
    out, quoted, i = [], False, 0
    while i < len(text):
        c = text[i]
        if c == "\"":
            quoted = not quoted
        elif c == "\\" and i + 1 < len(text):
            i += 1
            out.append(text[i])
        elif c in "#;" and not quoted:
            break
        else:
            out.append(c)
        i += 1
    return "".join(out).strip()


def git_helper(text, path, home, found):
    # A credential helper <path> names counts, but the store and cache helpers git ships hand out only what
    # their file or socket holds (git runs a helper not named by an absolute path as git credential-<name>,
    # through the shell). With no --file or --socket (or an abbreviation of it), that is their default file or
    # socket, which counts on its own; with one, that file counts when it is readable and that socket when it
    # accepts a connection, "~" as a word of its own standing for <home>. One written with shell syntax or a
    # relative path counts as any other helper does.
    words = text.split()
    command = os.path.basename(words[0]) if words[0].startswith("/") else "git-credential-" + words[0]
    option = GIT_HELPERS.get(command)
    if not option or SHELL_SYNTAX.search(text):
        found.append((GIT, path))
        return
    where, i = "", 1
    while i < len(words):
        name, eq, value = words[i].partition("=")
        if len(name) > 2 and name.startswith("--") and option.startswith(name[2:]):
            if not eq:
                i += 1
                value = words[i] if i < len(words) else ""
                if value == "~" or value.startswith("~/"):
                    value = home + value[1:]
            where = value
        i += 1
    if not where:
        return
    if not where.startswith("/"):
        found.append((GIT, path))
    elif option == "file":
        readable(found, GIT, [where])
    else:
        sockets(found, [(GIT, where)])


def git_config(path, home, found, state, depth=0):
    # A git config file counts when it names a credential helper (the store and cache git ships count by their
    # file and socket, git_helper), an askpass program or a cookie file, sends an HTTP header, rewrites to an
    # http(s) URL that carries a login, or goes through a proxy with a login (http.proxy, remote.<name>.proxy).
    # The files it includes count the same way, whatever the includeIf condition, ten deep at most; "~" in an
    # include path stands for <home>. As git does, it skips a byte order mark at the start, and reads the
    # headers a line starts with, then the entry after them.
    data = start(path, 1 << 20) if path and depth <= 10 else None
    key = os.path.realpath(path) if data is not None else ""
    if not key or key in state["configs"]:
        return
    state["configs"].add(key)
    section = ""
    content = data.decode("utf-8", "replace")
    for line in (content[1:] if content.startswith("\ufeff") else content).splitlines():
        m = GIT_SECTION.match(line)
        while m:
            section, _, legacy = m.group(1).lower().partition(".")
            if section == "url" and URL_LOGIN.match(legacy if m.group(2) is None else m.group(2)):
                found.append((GIT, path))
            line = line[m.end():]
            m = GIT_SECTION.match(line)
        m = GIT_ENTRY.match(line)
        if not m:
            continue
        name, text = m.group(1).lower(), git_value(m.group(3)) if m.group(2) else "true"
        if not text:
            continue
        if (section, name) == ("credential", "helper"):
            git_helper(text, path, home, found)
        elif ((section, name) in (("core", "askpass"), ("http", "extraheader"), ("http", "cookiefile"))
                or name == "proxy" and section in ("http", "remote") and PROXY_LOGIN.match(text)):
            found.append((GIT, path))
        elif section in ("include", "includeif") and name == "path":
            if text == "~" or text.startswith("~/"):
                text = home + text[1:]
            git_config(os.path.join(os.path.dirname(path), text), home, found, state, depth + 1)


def aws_config(path, home, found, state):
    # An AWS config file counts when it names a credential_process or holds a secret key or a session token.
    data = start(path, 1 << 20) if path else None
    if data and AWS_SECRET.search(data.decode("utf-8", "replace")):
        found.append((CLOUD, path))


def tf_config(path, home, found, state):
    # A Terraform CLI config counts when it holds a credentials block or names a credentials helper.
    data = start(path, 1 << 20) if path else None
    if data and TF_CREDENTIALS.search(data.decode("utf-8", "replace")):
        found.append((CLOUD, path))


def name_parts(name):
    # The parts of a name, in upper case: they end at _, - and . and where a lower-case letter or a digit meets
    # an upper-case one (api-key, accessToken).
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).upper().replace("-", "_").replace(".", "_").split("_")


def secretish(name, rpc=True):
    # A name that looks like a credential: a part TOKEN, SECRET, PASSWORD, PASSWD, PASSPHRASE or APIKEY, or
    # API_KEY, ACCESS_KEY or PRIVATE_KEY, or, with <rpc>, RPC_URL. A settings file or an argument that gives an
    # RPC URL counts only by what its URL carries (url_credential), as a public RPC URL carries nothing.
    parts = name_parts(name)
    pairs = set(zip(parts, parts[1:]))
    return bool(set(parts) & {"TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASSPHRASE", "APIKEY"}
                or pairs & {("API", "KEY"), ("ACCESS", "KEY"), ("PRIVATE", "KEY")} or rpc and ("RPC", "URL") in pairs)


def last_part(name, parts):
    # A name whose last part is one of <parts>, but for a key that is no secret (NOT_SECRET before it).
    p = name_parts(name)
    return p[-1] in parts and not (len(p) > 1 and p[-2] in NOT_SECRET)


def env_name(name, rpc=False):
    # A variable whose name looks like a credential: as secretish (an RPC_URL with <rpc> only), with a last part
    # KEY (a key that is no secret aside), with a part PWD, PASS or PAT (PWD and OLDPWD themselves aside), or with
    # a part that ends in PASSWORD or PASSWD (DD_APP_KEY, REDIS_PWD, AZURE_DEVOPS_PAT, PGPASSWORD). One that
    # names a client key file (CLIENT_KEY) is read as that file instead.
    parts = name_parts(name)
    return not CLIENT_KEY.fullmatch(name) and bool(
        secretish(name, rpc) or last_part(name, ("KEY",))
        or name.upper() not in ("PWD", "OLDPWD")
        and any(p in ("PWD", "PASS", "PAT") or p.endswith(("PASSWORD", "PASSWD")) for p in parts))


def key_name(name):
    # The name a header, an option or a query parameter carrying a key goes by: one a variable holding a
    # credential goes by (env_name), or one whose last part is KEY, AUTH, BEARER, AUTHORIZATION, CREDENTIAL or
    # CREDENTIALS (x-api-key, Ocp-Apim-Subscription-Key, subscription-key, --key, --pat, Helicone-Auth,
    # --oauth2Bearer), a key that is no secret aside.
    return env_name(name) or last_part(name, KEY_PARTS)


def set_here(value):
    # A value a settings file sets itself that can be a credential: not one that refers to a variable (${NAME} or
    # $NAME), nor a word that switches a setting or names an authentication method (SWITCHES).
    text = str(value).strip() if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ""
    return text != "" and not REFERENCE.search(text) and text.lower() not in SWITCHES


def auth_value(text):
    # A value an HTTP authentication scheme sends, with nothing else (BEARER, BASIC): Basic counts when what it
    # sends decodes to a user and a password.
    basic = BASIC.fullmatch(text)
    try:
        return bool(BEARER.fullmatch(text) or basic and b":" in base64.b64decode(basic.group(1), validate=True))
    except ValueError:
        return False


def credential_header(name, value):
    # A header that sends a credential, with a value set here: Authorization (Proxy-Authorization and any
    # *-Authorization too) or Cookie, a name a key goes by (key_name), or any name with a value an authentication
    # scheme sends (auth_value).
    upper = name.upper().replace("-", "_")
    return set_here(value) and bool(upper in ("AUTHORIZATION", "COOKIE") or upper.endswith("_AUTHORIZATION")
                                    or key_name(name) or auth_value(str(value)))


def header_credential(text, every=False):
    # A list of headers that sends a credential header, or with <every> any header with a value set here: Name:
    # value lines (ANTHROPIC_CUSTOM_HEADERS), Name=value pairs apart by commas (the OTLP exporter), or a JSON
    # object (OPENAPI_MCP_HEADERS, as an MCP server takes it).
    try:
        headers = json.loads(text)
    except (ValueError, RecursionError):
        headers = None
    pairs = headers.items() if isinstance(headers, dict) else HEADER.findall(text)
    return any(credential_header(str(name), value) or every and set_here(value) for name, value in pairs)


def path_key(segment):
    # A URL path segment that can be a key: 20 or more letters, digits, - and _, with a run of seven or more
    # letters and digits that holds both (a version or a date in a name holds none).
    return bool(PATH_KEY.fullmatch(segment)) and any(
        len(run) >= 7 and not run.isdigit() and not run.isalpha() for run in re.split(r"[-_]", segment))


def url_credential(text):
    # A URL in <text> that carries a key set here: in its login (any user name in an http, ws or socks URL, a
    # user and a password in any other), in a query or fragment parameter whose name a key goes by (key_name, sig
    # or signature), or, for a URL with a host that does not serve code by its commit (CODE_HOSTS), in a path
    # segment that can be one (path_key).
    for match in URL_IN.finditer(text):
        try:
            url = urllib.parse.urlsplit(match.group(0))
            host = url.hostname or ""
        except ValueError:
            continue
        login = url.netloc.rpartition("@")[0]
        if set_here(login) and (url.scheme.lower() in TOKEN_USER or login.partition(":")[2]):
            return True
        for name, eq, value in (part.partition("=") for part in (url.query + "&" + url.fragment).split("&")):
            name = urllib.parse.unquote_plus(name)
            if eq and set_here(urllib.parse.unquote_plus(value)) and (key_name(name) or name.upper() in QUERY_KEYS):
                return True
        if (url.netloc and not any(host == h or host.endswith("." + h) for h in CODE_HOSTS)
                and any(path_key(urllib.parse.unquote(segment)) for segment in url.path.split("/"))):
            return True
    return False


def env_credential(name, value):
    # An env entry that sets a credential: a value set here for a name that looks like one (env_name; an RPC URL
    # counts by its URL alone) or that an authentication scheme sends, a URL that carries one, or, for a name
    # that ends in HEADER or HEADERS, a list of headers that sends one, any header with a value counting for the
    # OTLP exporter. A client key file the entry names is read on its own (client_keys).
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return False
    text, upper = str(value), name.upper()
    return (set_here(value) and (env_name(name) or auth_value(text)) or url_credential(text)
            or upper.endswith(("HEADER", "HEADERS")) and header_credential(text, bool(OTLP_HEADERS.fullmatch(upper))))


def args_credential(args):
    # Arguments of a command that pass a credential: an option a key goes by (key_name) with a value set here
    # (--api-key <value>, --key=<value>; a --no- option takes none), NAME=<value> as an env block would set it,
    # as docker run -e takes it, a header option (-H, --header, --headers) that sends one, as Name: value or as a
    # name and a value of their own (mcp-proxy --headers Authorization <value>), a value an authentication scheme
    # sends, or an argument with a URL that carries one.
    words = [w for w in args if isinstance(w, str)]
    for i, word in enumerate(words):
        option = word.startswith("-")
        name, eq, value = word.lstrip("-").partition("=")
        if word.startswith("--no-"):
            value = ""
        elif not eq:
            value = words[i + 1] if option and i + 1 < len(words) and not words[i + 1].startswith("-") else ""
        header = option and name.lower() in ("h", "header", "headers")
        if (url_credential(word) or set_here(word) and auth_value(word)
                or (set_here(value) and key_name(name) if option else eq and env_credential(name, value))
                or header and (header_credential(value) or not eq and i + 2 < len(words)
                               and HEADER_NAME.fullmatch(value) and credential_header(value, words[i + 2]))):
            return True
    return False


def claude_files(directory, names=CLAUDE_FILES):
    at = glob.escape(directory)
    return [p for n in names for p in sorted(glob.glob(os.path.join(at, n)))]


def client_keys(env, home, found):
    # The mTLS client key files an env block names (CLIENT_KEY) with a value set here: at an absolute path, or
    # under "~/" (<home>), one counts when it is readable, the file counting, as the code here could read it
    # without Claude Code; True for another path, which the check cannot place, so that the settings file counts.
    other = False
    for name, value in env.items():
        if CLIENT_KEY.fullmatch(name) and set_here(value):
            where = str(value).strip()
            if where == "~" or where.startswith("~/"):
                where = home + where[1:]
            if where.startswith("/"):
                readable(found, CLAUDE, [where])
            else:
                other = True
    return other


def claude_json(path, home, found, state):
    # A Claude Code settings or state file counts when it names a command that prints a credential (the
    # headersHelper of an MCP server too), when an env block in it (of the file or of an MCP server) sets a
    # credential (env_credential) or names a client key file by a relative path, when a headers block (of an MCP
    # server or an HTTP hook) sends a credential header, or when a URL (of an MCP server or a hook) or the
    # arguments of an MCP server carry one; a readable client key file an env block names counts on its own
    # (client_keys). Past 16 MiB the check cannot finish; a file that is not JSON counts for nothing, as Claude
    # Code reads nothing from it.
    data = start(path, CLAUDE_LIMIT + 1) if path else None
    key = os.path.realpath(path) if data is not None else ""
    if not key or key in state["configs"]:
        return
    state["configs"].add(key)
    if len(data) > CLAUDE_LIMIT:
        raise Unfinished("a Claude Code settings or state file larger than 16 MiB")
    try:
        stack = [json.loads(data.decode("utf-8", "replace"))]
    except (ValueError, RecursionError):
        return
    counts = False
    while stack:
        node = stack.pop()
        items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()
        for name, value in items:
            if name == "env" and isinstance(value, dict):
                counts = client_keys(value, home, found) or counts
            counts = counts or bool(
                name in CLAUDE_HELPERS and isinstance(value, str) and value.strip()
                or name == "env" and isinstance(value, dict) and any(env_credential(k, v) for k, v in value.items())
                or name == "headers" and isinstance(value, dict)
                and any(credential_header(k, v) for k, v in value.items())
                or name == "url" and isinstance(value, str) and url_credential(value)
                or name == "args" and isinstance(value, list) and args_credential(value))
            stack.append(value)
    if counts:
        found.append((CLAUDE, path))


def runtime(directory, dirs, socks):
    dirs.extend((AGENT, os.path.join(directory, d)) for d in ("gnupg", "keyring", "gcr"))
    at = glob.escape(directory)
    socks.append((AGENT, os.path.join(directory, "ssh-agent.socket")))
    socks.extend((AGENT, p) for p in glob.glob(os.path.join(at, "vscode-ssh-auth-*.sock")))
    socks.extend((GIT, p) for p in glob.glob(os.path.join(at, "vscode-git-*.sock")))
    socks.extend((DAEMON, os.path.join(directory, s)) for s in ("docker.sock", "podman/podman.sock"))


def named(env, files, dirs, socks, configs):
    # The places the environment names.
    for kind, name in ((CLOUD, "AWS_SHARED_CREDENTIALS_FILE"), (CLOUD, "GOOGLE_APPLICATION_CREDENTIALS"), (GIT, "NETRC"),
                       (REGISTRY, "NPM_CONFIG_USERCONFIG"), (REGISTRY, "npm_config_userconfig"), (GIT, "GIT_ASKPASS"),
                       (GIT, "SSH_ASKPASS"), (CLAUDE, "ANTHROPIC_IDENTITY_TOKEN_FILE")):
        files.append((kind, env.get(name, "")))
    files.extend((CLAUDE, env[name]) for name in sorted(env) if CLIENT_KEY.fullmatch(name))
    files.extend((CLUSTER, p) for p in env.get("KUBECONFIG", "").split(os.pathsep))
    for kind, name, under in ((REGISTRY, "CARGO_HOME", ("credentials", "credentials.toml")),
                              (GIT, "XDG_CONFIG_HOME", ("gh/hosts.yml", "git/credentials")), (GIT, "GH_CONFIG_DIR", ("hosts.yml",)),
                              (CLUSTER, "DOCKER_CONFIG", ("config.json",)), (CLOUD, "CLOUDSDK_CONFIG", GCLOUD),
                              (CLOUD, "AZURE_CONFIG_DIR", AZURE), (CLAUDE, "CLAUDE_CONFIG_DIR", (".credentials.json",))):
        if env.get(name):
            files.extend((kind, os.path.join(env[name], f)) for f in under)
    if env.get("CLOUDSDK_CONFIG"):
        dirs.append((CLOUD, os.path.join(env["CLOUDSDK_CONFIG"], "legacy_credentials")))
    if env.get("ANTHROPIC_CONFIG_DIR"):
        dirs.append((CLAUDE, env["ANTHROPIC_CONFIG_DIR"]))
    if env.get("CLAUDE_CONFIG_DIR"):
        configs.extend((claude_json, p) for p in claude_files(env["CLAUDE_CONFIG_DIR"]))
    if env.get("GNUPGHOME"):
        dirs.append((GPG, os.path.join(env["GNUPGHOME"], "private-keys-v1.d")))
        socks.extend((AGENT, os.path.join(env["GNUPGHOME"], s)) for s in GPG_SOCKETS)
    configs.extend((git_config, env.get(name, "")) for name in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"))
    if env.get("XDG_CONFIG_HOME"):
        configs.append((git_config, os.path.join(env["XDG_CONFIG_HOME"], "git/config")))
    configs.append((aws_config, env.get("AWS_CONFIG_FILE", "")))
    configs.append((tf_config, env.get("TF_CLI_CONFIG_FILE", "")))
    socks.extend((GIT, env.get(name, "")) for name in ("VSCODE_GIT_IPC_HANDLE", "REMOTE_CONTAINERS_IPC"))
    for name in ("DOCKER_HOST", "CONTAINER_HOST"):
        value = env.get(name, "")
        if value.startswith("unix://"):
            socks.append((DAEMON, value[len("unix://"):]))
        elif value.startswith("tcp://") and not (name == "DOCKER_HOST" and env.get("DOCKER_TLS_VERIFY")):
            socks.append((DAEMON, value))
    if env.get("DOCKER_CERT_PATH"):
        files.append((CLUSTER, os.path.join(env["DOCKER_CERT_PATH"], "key.pem")))
    if env.get("DOCKER_CONFIG"):
        files.extend((CLUSTER, p) for p in glob.glob(os.path.join(glob.escape(env["DOCKER_CONFIG"]), DOCKER_KEYS)))
    if env.get("XDG_CACHE_HOME"):
        socks.append((GIT, os.path.join(env["XDG_CACHE_HOME"], "git/credential/socket")))
    if env.get("TMPDIR"):
        at = glob.escape(env["TMPDIR"])
        socks.extend((AGENT, p) for p in glob.glob(os.path.join(at, "ssh-*", "agent.*")))
        socks.extend((GIT, p) for p in glob.glob(os.path.join(at, "vscode-git-*.sock")))
        socks.extend((DAEMON, p) for p in glob.glob(os.path.join(at, "podman", "*.sock")))
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
    found, state, files, dirs, socks, configs = [], {"left": BUDGET, "seen": set(), "configs": set()}, [], [], [], []
    read = [h for h in (given if which == "given" else homes(env.get("HOME", ""))) if h]
    for home in read:
        at = glob.escape(home)
        ssh = os.path.join(home, ".ssh")
        if not walk(ssh, SSH_KEEP, found, state, SSH):
            readable(found, SSH, (os.path.join(ssh, k) for k in SSH_KEYS))
        for kind, f in FILES:
            readable(found, kind, [os.path.join(home, f)])
        readable(found, CLUSTER, glob.glob(os.path.join(at, ".docker", DOCKER_KEYS)))
        readable(found, CLAUDE, glob.glob(os.path.join(at, ".claude*", ".credentials.json")))
        for p in sorted(glob.glob(os.path.join(at, ".claude*"))):
            if os.path.isdir(p):
                for f in claude_files(p):
                    claude_json(f, home, found, state)
            elif os.path.basename(p).startswith(".claude.json"):
                claude_json(p, home, found, state)
        for kind, d in DIRS:
            walk(os.path.join(home, d), None, found, state, kind)
        sockets(found, ((kind, p) for kind, s in SOCKETS for p in glob.glob(os.path.join(at, s))))
        readable(found, SOLANA, [keypair(home)])
        for f in GIT_CONFIGS:
            git_config(os.path.join(home, f), home, found, state)
        aws_config(os.path.join(home, ".aws/config"), home, found, state)
        tf_config(os.path.join(home, ".terraformrc"), home, found, state)
    named(env, files, dirs, socks, configs)
    if which == "default":
        # What anyone on the machine can name: agent, VS Code and container daemon sockets, the git config of
        # the system and the managed settings of Claude Code.
        socks.extend((AGENT, p) for p in glob.glob("/tmp/ssh-*/agent.*") + glob.glob("/tmp/vscode-ssh-auth-*.sock")
                     + glob.glob("/private/tmp/com.apple.launchd.*/Listeners"))
        socks.extend((GIT, p) for p in glob.glob("/tmp/vscode-git-*.sock") + glob.glob("/tmp/vscode-remote-containers-ipc-*.sock"))
        socks.extend((DAEMON, os.path.join(d, s)) for d in ("/run", "/var/run")
                     for s in ("docker.sock", "podman/podman.sock", "containerd/containerd.sock"))
        runtime("/run/user/%d" % os.getuid(), dirs, socks)
        configs.append((git_config, "/etc/gitconfig"))
        configs.extend((claude_json, p) for d in MANAGED for p in claude_files(d, MANAGED_FILES))
    for kind, f in files:
        readable(found, kind, [f])
    for kind, d in dirs:
        walk(d, None, found, state, kind)
    for config, f in configs:
        config(f, env.get("HOME", ""), found, state)
    sockets(found, socks)
    sock = env.get("SSH_AUTH_SOCK", "")
    if sock:
        mark = []
        sockets(mark, [(AGENT, sock)])
        found.extend((kind, p + " (SSH_AUTH_SOCK)") for kind, p in mark)
    seen, out, count = set(), [], dict.fromkeys(KINDS, 0)
    for kind, path in found:
        key = os.path.realpath(path.rsplit(" (SSH_AUTH_SOCK)", 1)[0])
        if key not in seen:
            seen.add(key)
            count[kind] += 1
            out.append(shown(path, read))
    if not out:
        return 0
    print(", ".join("%s (%d)" % (kind, count[kind]) for kind in KINDS if count[kind]))
    for path in out:
        print(path)
    return 1


def names(env):
    # The variables whose names look like credentials (env_name, an RPC_URL too).
    print(", ".join(shown(name) for name in sorted(env) if env_name(name, rpc=True)))
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
  (cd / && exec python3 -I -c "$ISO_PY" homes "${HOME:-}")
}

iso_credentials() { # iso_credentials [<home>...]
  local rc=0 which=given out
  ISO_KINDS="" ISO_READABLE="" ISO_WHY=""
  command -v python3 >/dev/null 2>&1 || { ISO_WHY="python3 is not on PATH"; return 2; }
  [ $# -gt 0 ] || which=default
  out=$(cd / && exec python3 -I -c "$ISO_PY" creds "$which" "$@") || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) ISO_KINDS=${out%%$'\n'*}; ISO_READABLE=${out#*$'\n'}; return 1 ;;
  esac
  ISO_WHY=${out%%$'\n'*}
  [ -n "$ISO_WHY" ] || ISO_WHY="the check stopped on an error"
  return 2
}

iso_cred_names() { # iso_cred_names
  ISO_NAMES=""
  command -v python3 >/dev/null 2>&1 || return 0
  ISO_NAMES=$(cd / && exec python3 -I -c "$ISO_PY" names 2>/dev/null) || ISO_NAMES=""
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

iso_tmp_outside() { # iso_tmp_outside
  local base=${TMPDIR:-/tmp}
  confine_phys "$base" || confine_refuse "TMPDIR cannot be resolved: $(confine_text "$base")"
  ! confine_inside "$CONFINE_PHYS" "$CONFINE_WT" ||
    confine_refuse "TMPDIR lies inside the working directory; point it outside the tree under audit"
}

iso_scratch() { # iso_scratch <tool>
  local base=${TMPDIR:-/tmp} dir found
  ISO_SCRATCH=""
  dir=$(mktemp -d "${base%/}/auditor-$1.XXXXXX" 2>/dev/null) ||
    confine_refuse "cannot create a scratch directory under $(confine_text "$base")"
  confine_phys "$dir" || confine_refuse "the scratch directory $(confine_text "$dir") cannot be resolved"
  ISO_SCRATCH=$CONFINE_PHYS
  ! confine_inside "$ISO_SCRATCH" "$CONFINE_WT" ||
    confine_refuse "the scratch directory $(confine_text "$ISO_SCRATCH") lies inside the working directory; point TMPDIR outside it"
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
    (cd / && exec python3 -I -c "$ISO_PY" wallet "$ISO_HOME/.config/solana/id.json") || return 1
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

# What iso_watch runs, with python3 -I: "<report> <seconds> <dir> <program> [<arg>...]".
ISO_WATCH_PY='import os, signal, subprocess, sys

report, limit, where, argv = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4:]


def say(text):
    fd = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text + "\n")


def end(group, leader=None):
    # SIGTERM to every process of the group, five seconds for the leader to go, then SIGKILL.
    try:
        os.killpg(group, signal.SIGTERM)
    except OSError:
        return
    if leader is not None:
        try:
            leader.wait(5)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(group, signal.SIGKILL)
    except OSError:
        pass


try:
    child = subprocess.Popen(argv, cwd=where, stdin=subprocess.DEVNULL, start_new_session=True)
except OSError as why:
    say("cannot start: %s" % (why.strerror or why))
    sys.exit(127)


def stop(signum, frame):
    end(child.pid, child)
    say("stopped by signal %d" % signum)
    os._exit(128 + signum)


for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(s, stop)
try:
    rc = child.wait(limit)
except subprocess.TimeoutExpired:
    end(child.pid, child)
    child.wait()
    say("timeout")
    sys.exit(124)
end(child.pid)
if rc < 0:
    say("signal %d" % -rc)
    sys.exit(128 - rc)
say("exit %d" % rc)
sys.exit(rc)
'

iso_limit() { # iso_limit -t|-f <value>: that ulimit, soft and hard, at <value>, or at the hard limit when it is lower
  local hard
  hard=$(ulimit -H "$1") || return 1
  case "$hard" in
    unlimited) ;;
    ''|*[!0-9]*) return 1 ;;
    *) [ "$hard" -ge "$2" ] || set -- "$1" "$hard" ;;
  esac
  ulimit "$1" "$2"
}

iso_watch() { # iso_watch <seconds> <report> <dir> [NAME=value...] <program> [<arg>...]
  local secs=$1 report=$2 dir=$3 n=0 w rc
  shift 3
  for w in "$@"; do
    case "$w" in
      [A-Za-z_]*=*) case "${w%%=*}" in *[!A-Za-z0-9_]*) break ;; esac ;;
      *) break ;;
    esac
    n=$((n + 1))
  done
  [ "$n" -lt $# ] || return 126
  # The watchdog runs in the background and is waited for, so that a signal trap of the caller runs at once
  # and can stop it (ISO_WATCH_PID); exec makes that pid the watchdog's own.
  (
    cd / || exit 126
    iso_limit -t $((secs * 4)) && iso_limit -f 4194304 || exit 126
    exec env -i "${ISO_ENV[@]}" "${@:1:n}" python3 -I -c "$ISO_WATCH_PY" "$report" "$secs" "$dir" "${@:n+1}"
  ) &
  ISO_WATCH_PID=$!
  wait "$ISO_WATCH_PID"
  rc=$?
  ISO_WATCH_PID=""
  return "$rc"
}

iso_copy_new() { # iso_copy_new <file> <path>
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  if [ -e "$2" ] || [ -L "$2" ]; then return 1; fi
  ( set -C; exec 9>"$2" && cat -- "$1" >&9 ) 2>/dev/null
}

# What iso_incident_class runs, with python3 -I: "<INCIDENTS.json> [<INC-n.k>]" prints that incident's
# root_cause_class, or with no id supply_chain_or_ci when any incident has it and "other" otherwise; exit 3
# with the reason when the file, an incident or a class cannot be read.
ISO_INCIDENT_PY='import json, os, stat, sys

CLASSES = ("code_flaw", "key_compromise", "oracle_or_dependency", "economic_design", "off_chain",
           "supply_chain_or_ci", "unknown")
LIMIT = 4 * 1024 * 1024


def say(text, status):
    print(text)
    sys.exit(status)


path, wanted = sys.argv[1], sys.argv[2]
try:
    st = os.lstat(path)
except FileNotFoundError:
    say("is missing", 3)
except OSError:
    say("cannot be read", 3)
if not stat.S_ISREG(st.st_mode):
    say("is not a regular file", 3)
if st.st_size > LIMIT:
    say("is larger than 4 MiB", 3)
try:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NOCTTY", 0))
    with os.fdopen(fd, "rb") as f:
        data = json.loads(f.read(LIMIT + 1).decode("utf-8"))
except (OSError, UnicodeDecodeError, ValueError, RecursionError):
    say("cannot be read as JSON", 3)
incidents = data.get("incidents") if isinstance(data, dict) else None
if not isinstance(incidents, list):
    say("holds no incidents list", 3)
if not all(isinstance(i, dict) for i in incidents):
    say("holds an incident that is not an object", 3)
if wanted:
    incidents = [i for i in incidents if i.get("id") == wanted]
    if not incidents:
        say("records no incident %s" % wanted, 3)
    if len(incidents) > 1:
        say("records %s more than once" % wanted, 3)
if not incidents:
    say("records no incident", 3)
for i in incidents:
    if i.get("root_cause_class") not in CLASSES:
        say("gives %s no root_cause_class from incidents-schema.md" % (wanted or "an incident"), 3)
if wanted:
    say(incidents[0]["root_cause_class"], 0)
say("supply_chain_or_ci" if any(i["root_cause_class"] == "supply_chain_or_ci" for i in incidents) else "other", 0)
'

iso_incident_class() { # iso_incident_class <INCIDENTS.json> [<INC-n.k>]
  ISO_CLASS=$(cd / && exec python3 -I -c "$ISO_INCIDENT_PY" "$1" "${2:-}")
}

iso_incident_runs() { # iso_incident_runs <working directory>
  local d rc
  local -a dirs
  ISO_CLASS=other
  ISO_INCIDENTS=""
  # A directory that cannot be listed globs to nothing, so that is told first, whatever the glob options.
  if [ ! -r "$1" ]; then
    ISO_INCIDENTS="the working directory"
    ISO_CLASS="cannot be listed"
    return 3
  fi
  case $- in
    *f*) set +f; dirs=("$1"/[Ii][Nn][Cc][Ii][Dd][Ee][Nn][Tt]_*); set -f ;;
    *) dirs=("$1"/[Ii][Nn][Cc][Ii][Dd][Ee][Nn][Tt]_*) ;;
  esac
  for d in ${dirs[@]+"${dirs[@]}"}; do
    # The pattern itself comes back when nothing matches.
    [ "$d" != "$1/[Ii][Nn][Cc][Ii][Dd][Ee][Nn][Tt]_*" ] || continue
    # The shell's tests cannot tell a missing path from one a stat cannot reach, so only a name that is there
    # and is no directory is passed over here; python3 decides the rest.
    if [ ! -d "$d" ] && [ -e "$d" ]; then continue; fi
    confine_shown "${d##*/}"
    ISO_INCIDENTS=$CONFINE_SHOWN/INCIDENTS.json
    command -v python3 >/dev/null 2>&1 || { ISO_CLASS=""; return 2; }
    rc=0
    iso_incident_class "$d/INCIDENTS.json" || rc=$?
    case "$rc:$ISO_CLASS" in
      0:supply_chain_or_ci) return 0 ;;
      0:*|'3:is missing'|'3:records no incident') ;;
      3:?*) return 3 ;;
      *) ISO_CLASS="cannot be read"; return 3 ;;
    esac
  done
  ISO_CLASS=other
  ISO_INCIDENTS=""
}
