# Vuln Classes — Host Kernel & Network Attack Surface: Unpatched Kernel CVEs and Unused Features on Internet-Facing Nodes

> **Load when:** the target operates Linux hosts that accept connections from the Internet (validator, RPC node,
> keeper / bot, indexer, self-hosted CI runner), or ships the infra-as-code and runbooks that provision them. Grep
> markers: `ansible` · `cloud-init` · `terraform` · `packer` · `sysctl` · `sysctl.d` · `modprobe.d` · `nftables` /
> `nft ` / `iptables` / `ufw` · `linux-image` · `uname -r` · `net.mptcp.enabled` · `tcp_migrate_req` ·
> `accept_source_route` · `tailscale` / `wireguard` · `sshd_config` · `node_exporter` · `GODEBUG`.
>
> **Purpose:** the kernel is the one dependency every node runs and almost no team audits. Each feature compiled in
> or loaded, and each network sysctl left at its default, is reachable by anyone who can send a packet, whether the
> node uses it or not. This playbook turns that into two checkable things: an **inventory** of what the host has
> enabled against what it actually uses (§3), and a **reduction** that switches the rest off through configuration
> management (§4), plus the protocol for the days when upstream has a fix and the distribution does not (§5). It is
> written around CVE-2026-98432 (§1) because that bug made every one of these gaps visible at once, and it is not
> Solana-specific: any Linux host with a public TCP listener is in scope. Checklist items: DEP-097..102. Known
> vector: KV-141. Locator recipes K1–K5 and the read-only host inventory: `discovery/grep-commands.md`, section
> "Host kernel & network attack surface".
>
> **How to use:** §0 before anything else; §1 dates the facts this file relies on; §2 classifies every host in scope;
> §3 and §4 are the inventory and the reduction; §5 the patch-lag protocol; §6 maps it onto infra-as-code for a
> static review; §7 grounds severity; §8 is the fast pass.

---

## 0. Rules of engagement (read first)

This is a static review of infra-as-code, runbooks and host configuration files, with an optional read-only pass on
a live host. The auditor reports; the operator changes.

- **Nothing runs on a host without the operator's explicit go-ahead,** and then only the read-only commands of §3
  (`uname`, `lsmod`, `sysctl` reads, `ss`, `nft list`, package queries). No `sysctl -w`, no `nft -f`, no module
  load or unload, no package install, no reboot. A node operator applies mitigations through their configuration
  management after reading the report.
- **The audit machine never connects to a validator.** Host commands are run by the operator, or by the auditor on a
  session the operator opens. Exposing a validator's SSH to one more address to run an audit is the exact gap §4
  closes. Handle any copied output per [`OUTPUT-RULES.md` Rule 11](../../OUTPUT-RULES.md#rule-11-operating-safety).
- **A PoC is a written trace:** host → public listener → kernel feature reached → the advisory that says it is
  exploitable → the mitigation state, each with a file or command reference. No packet is ever sent at a target host.
- **Vendor statements are quoted, not improved.** Where a vendor says a filter reduces exposure and does not prevent
  exploitation, the report says so; a mitigation is never written up as a fix.

---

## 1. Facts and their dates (verify before citing)

| Fact | Value | Source, date |
|---|---|---|
| CVE-2026-98432 | Use-after-free in Linux IPv4 TCP: IP options of a connection request freed with `kfree()` while a retransmitted SYN-ACK or a request-socket migration still reads them; fix "ipv4: free inet_opt and ireq_opt after an RCU grace period" (`kfree_rcu()`) | NVD record, published 2026-10-15; kernel.org stable commits linked from it |
| Severity | CVSS 3.1 **9.8**, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`; vendors rate it as remote code execution | NVD; Ubuntu security blog 2026-11-02; RHSB-2026-016 |
| Affected | Linux 4.4 and later; IPv6 not affected by the first issue (a separate patch covers the IPv6 migration path) | NVD description |
| MPTCP | The demonstrated exploit needs an MPTCP listener; the bug is not MPTCP-specific. **Go 1.24+ opens MPTCP listeners by default**; `GODEBUG=multipathtcp=0` turns that off | lnd v0.20.7-beta release note; Ubuntu blog |
| Distribution status on 2026-11-02 | Ubuntu 22.04 `5.15.0-203.213`, 24.04 `6.8.0-149.149`, 26.04 `7.0.0-43.43` in `-proposed` only; 16.04 / 18.04 / 20.04 pending; Red Hat and Debian had shipped kernels | Ubuntu blog "Fixes available in proposed pocket for CVE-2026-98432" |
| Mitigation guidance for Solana validators | Drop inbound TCP packets carrying IPv4 options (nftables `ip protocol tcp ip hdrlength > 5 counter drop`), `net.mptcp.enabled=0`, `net.ipv4.tcp_migrate_req=0`, until the distribution kernel is patched | Anza and Solana Foundation validator relations, 2026-11-01/02 |
| Limits of the mitigation | Red Hat: the filter "reduces exposure" and "cannot fully prevent" exploitation, may disrupt workloads, is not a substitute for patching. Ubuntu Security Team: "security updates are the only appropriate mitigation" | RHSB-2026-016; Ubuntu blog |
| Validator baseline | Anza's validator requirements name Ubuntu 24.04 and public IPv4 connectivity, so the affected population is the Ubuntu-based share of the validator set | Anza validator docs, as reported 2026-11-02 |
| Incidents | No compromise of a Solana validator through this CVE has been reported as of 2026-11-03 | press review of the advisory |

Re-check the status row before every audit: it is a snapshot, and the distribution dates move.

---

## 2. Classify every host in scope

| Host role | Typical public listeners | Accepts TCP connection requests from untrusted sources? | In blast radius of a TCP request-socket bug |
|---|---|---|---|
| Validator (no public RPC) | gossip, TPU / QUIC, repair (UDP); SSH if public | SSH, any exporter or Go service on the public address | yes, through the management plane |
| RPC node | 8899 (HTTP), 8900 (WebSocket), SSH | yes, by design | yes |
| Keeper / liquidation bot / crank | outbound only, plus SSH and metrics | if SSH / metrics are public | yes, through the management plane |
| Indexer / Geyser consumer | database, API, SSH | yes if the API or SSH is public | yes |
| Self-hosted CI runner | outbound only, plus SSH | if SSH is public | yes; it also holds deploy keys (KV-116) |
| Managed SaaS / serverless only | none operated by the team | no | out of scope: KV-141 N/A |

Record, per host: distribution and kernel line, the public TCP listeners, who patches it, and whether SSH / metrics
answer on the public address. That table is the input to §3 and §6.

---

## 3. Inventory: show every kernel feature the host has on, and which ones it uses

Read-only. Run by the operator, or by the auditor with the operator's go-ahead (§0). Capture the output into the
infrastructure repository as `inventory/<host-role>.txt` and review it per kernel release.

```bash
# Kernel and packages
uname -r
dpkg -l 'linux-image*' 2>/dev/null | grep ^ii          # Debian / Ubuntu
rpm -q kernel 2>/dev/null                               # RHEL / Rocky / Amazon Linux

# Built-in features (=y is compiled in and cannot be unloaded; =m is a module)
grep -E '^CONFIG_(MPTCP|IP_SCTP|IP_DCCP|RDS|TIPC|USER_NS|BPF_UNPRIV_DEFAULT_OFF|IP_ADVANCED_ROUTER|NET_IPGRE|IPV6)=' /boot/config-"$(uname -r)"

# Loaded modules and what autoloads them
lsmod
cat /etc/modules-load.d/*.conf /etc/modprobe.d/*.conf 2>/dev/null

# Network behaviour switches
sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req net.ipv4.conf.all.accept_source_route \
       net.ipv4.conf.all.accept_redirects net.ipv4.tcp_syncookies kernel.unprivileged_bpf_disabled \
       kernel.kptr_restrict kernel.dmesg_restrict

# What actually listens, and on which address
ss -lntup

# What the firewall does with it
nft list ruleset 2>/dev/null; iptables -S 2>/dev/null; ufw status verbose 2>/dev/null
```

Reading the inventory:

- A protocol that is `=y` or loaded, **and** has no listener in `ss` and no consumer in the service list, is attack
  surface with no user: MPTCP (`net.mptcp.enabled`), SCTP, DCCP, RDS, TIPC are the usual ones. IPv4 options
  processing and request-socket migration (`tcp_migrate_req`) are features of the TCP path itself; a node that does
  not use `SO_REUSEPORT` groups with migration can turn migration off.
- A listener bound to `0.0.0.0` or `*` that is not a validator or RPC service port (SSH, `node_exporter` 9100, an
  admin API, any Go program) is management plane on the public interface (§4.3).
- An empty `nft list ruleset` on an Internet-facing host means every listener above is reachable by every address.

---

## 4. Reduction: switch off what the inventory does not justify

Everything below goes through configuration management (Ansible, cloud-init, Packer, NixOS, Terraform
`user_data`), never typed on the host: a `sysctl -w` disappears at reboot, and a hand-edited host is the one that
is missing from the next review.

### 4.1 Network features the node does not use

`/etc/sysctl.d/90-attack-surface.conf` (values for a node that uses none of these):

```
net.mptcp.enabled = 0
net.ipv4.tcp_migrate_req = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
kernel.unprivileged_bpf_disabled = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
```

`/etc/modprobe.d/attack-surface.conf` (modules that must never load; `install … /bin/false` beats `blacklist`,
which only stops autoload):

```
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
```

A feature compiled in (`=y`) cannot be removed this way, only switched off where a sysctl exists. The strong form
is a kernel built without the feature: a distribution variant or a custom build with `CONFIG_MPTCP`, `CONFIG_IP_SCTP`,
`CONFIG_IP_DCCP`, `CONFIG_RDS`, `CONFIG_TIPC` unset. For a validator fleet that is a reasonable investment; for
everyone else, the sysctl and modprobe files above remove the reachable paths.

### 4.2 Runtimes that open features on their own

Go 1.24 and later listen with MPTCP by default. Every Go service on the host (exporters, relayers, custom tooling)
runs with `GODEBUG=multipathtcp=0` in its unit file or container environment unless it needs MPTCP, and that need
is written in the inventory. The system-wide `net.mptcp.enabled = 0` covers them too; set both, so a host where
the sysctl is later relaxed does not silently reopen every Go listener.

### 4.3 Management plane off the public interface

- SSH, metrics (`node_exporter`, Prometheus scrape targets), admin or private RPC bind to the VPN interface
  (WireGuard, Tailscale) or carry an nftables source allowlist. `PasswordAuthentication no`, `PermitRootLogin no`.
- Only the service ports the host role needs accept connections from the Internet: RPC 8899 / 8900 on an RPC node;
  gossip, TPU / QUIC and repair on a validator; nothing on a keeper.
- Default-drop inbound. The nftables baseline opens the role's ports and drops the rest; the per-CVE rules of §5 are
  a separate, named table on top of it so they can be removed without touching the baseline.

### 4.4 Containers and runners

A container does not change the kernel: a Go service in a container still opens an MPTCP listener in the host
kernel, and a self-hosted CI runner that holds deploy keys (KV-116) runs on the same kernel as everything else on
the box. Apply §4.1–4.3 to the host, and keep runners off Internet-facing validators.

---

## 5. Patch lag: when upstream has the fix and the distribution does not

The public fix is the exploit map. The protocol, written down before it is needed:

1. **Deadline.** For a remote, unauthenticated kernel bug (CVSS `AV:N/PR:N`) on an Internet-facing host, the time to
   either a patched kernel or a deployed compensating control is hours, not the next maintenance window.
2. **Compensating control through configuration management, named after the CVE.** For CVE-2026-98432:

   ```
   table inet cve_2026_98432 {
       chain input {
           type filter hook input priority -310; policy accept;
           ip protocol tcp ip hdrlength > 5 counter drop
       }
   }
   ```

   plus `net.mptcp.enabled = 0` and `net.ipv4.tcp_migrate_req = 0` in a `sysctl.d` file, rolled out by the same
   tool that provisions the host. Test the rule on a canary first: Red Hat warns it may disrupt workloads.
3. **State the limit.** The runbook quotes the vendor: this reduces exposure and does not prevent exploitation; the
   patch is the exit.
4. **Decide the kernel source.** `-proposed` / a vendor kernel / an earlier reboot into a patched line is a decision
   with an owner, not a default.
5. **Exit.** When the patched kernel runs (`uname -r` matches the fixed version), the CVE-named table is deleted
   (`nft delete table inet cve_2026_98432`) and the sysctls that the inventory wants back are restored. The
   `counter` on the drop rule says whether anything ever hit it.
6. **Advisory source.** Someone owns the distribution's security feed for the exact release in use (Ubuntu
   `ubuntu.com/security/CVE-*`, Red Hat RHSB, Debian DSA, the kernel.org stable list) and the ecosystem channel
   that relays validator-relevant bugs. A team that learned of CVE-2026-98432 from a social-media post two weeks
   after NVD published it has no advisory source.

---

## 6. Static review worksheet (infra-as-code, runbooks, Dockerfiles)

| Item | Where it shows in the repository | PASS looks like | FAIL looks like |
|---|---|---|---|
| DEP-097 patch SLA and distro-lag plan | `docs/`, `runbooks/`, `SECURITY.md`, `ansible/` (unattended-upgrades, livepatch) | SLA by severity, named owner and feed, a documented past kernel update, a distro-lag section with deadline and compensating-control path | "we run `apt upgrade`" |
| DEP-098 kernel feature inventory | `inventory/`, `ansible/` facts, `docs/` | a per-role inventory (modules, built-ins, sysctls, listeners) re-reviewed per kernel release and referenced by the sysctl / modprobe files | sysctls and modules are the defaults, no file says what the node needs |
| DEP-099 unused features off | `sysctl.d`, `modprobe.d`, cloud-init `write_files`, Packer provisioners | the §4.1 switches present for every feature the inventory does not need | absent, or present only in a shell history / README "run this" |
| DEP-100 compensating controls managed with an exit | `ansible/`, `cloud-init`, `runbooks/` | CVE-named nft table and sysctls in configuration management, canary note, removal condition, vendor limit quoted | `sysctl -w` in a chat message; no record of which hosts have it |
| DEP-101 management plane off the public interface | `terraform` security groups, `nftables.conf`, `sshd_config`, exporter unit files | SSH / metrics / admin bound to VPN or allowlisted; default-drop inbound; only role ports public | `0.0.0.0/0` on 22 or 9100; `ListenAddress 0.0.0.0` for the exporter; no ruleset |
| DEP-102 runtimes that open features | systemd units, `docker-compose`, Dockerfiles for Go services | `GODEBUG=multipathtcp=0` on Go 1.24+ services that do not need MPTCP, and the system sysctl | Go services with defaults on a host that never turned MPTCP off |

Locator recipes K1–K5 for these paths are in `discovery/grep-commands.md`.

---

## 7. Severity grounding

- **CVE-2026-98432** (§1): 9.8, remote, unauthenticated, rated as RCE, against the kernel under every Solana
  validator, RPC node and keeper. A kernel compromise on a validator is custody of the identity and vote keys
  (KV-001) and of every hot key the box holds; on an RPC node it is a vantage point over every client; on a keeper
  it is the keeper's signing key. No exploitation of validators has been reported; the severity here follows the
  reachable asset, not an incident.
- **Class precedent:** remote TCP-stack bugs recur (the 2019 "SACK Panic" series, CVE-2019-11477 and siblings, was a
  remote denial of service in the same TCP code). The fix for each is the same two moves: a patch SLA that survives
  distribution lag, and a host that only exposes the kernel paths its role needs.
- A FAIL on DEP-097 or DEP-101 for an Internet-facing validator is High; with a published, unpatched remote kernel
  CVE and no compensating control it is Critical, independent of any program-level finding.

---

## 8. Fast pass

- [ ] Every host role in scope is listed with distribution, kernel line and public TCP listeners (§2)
- [ ] A kernel patch SLA with owner, advisory feed and distro-lag plan exists and has fired before (DEP-097)
- [ ] A per-role kernel feature inventory exists and drives `sysctl.d` / `modprobe.d` (DEP-098)
- [ ] MPTCP, SCTP, DCCP, RDS, TIPC, source routing and request-socket migration are off where unused (DEP-099)
- [ ] Any current CVE mitigation is in configuration management, named after the CVE, with a removal condition and the vendor's limit quoted (DEP-100)
- [ ] SSH, metrics and admin endpoints are behind VPN or allowlist; inbound is default-drop; only role ports are public (DEP-101)
- [ ] Go 1.24+ services run with `GODEBUG=multipathtcp=0` unless the inventory says otherwise (DEP-102)
- [ ] Nothing was run on a host without the operator's go-ahead, and nothing that writes (§0)
