---
id: 141
title: "Host Kernel & Network Attack Surface — Unpatched Kernel CVEs and Unused Network Features on Internet-Facing Nodes"
severity: 9
category: devops
---

### 141 — Host Kernel & Network Attack Surface — Unpatched Kernel CVEs and Unused Network Features on Internet-Facing Nodes

**Severity: 9** | **Real: CVE-2026-98432 (NVD, published 2026-10-15; CVSS 3.1 9.8, `AV:N/AC:L/PR:N/UI:N`): a use-after-free in the Linux kernel's IPv4 TCP code, present since 4.4. The IP options attached to a connection request are freed with `kfree()` while a retransmitted SYN-ACK or a request-socket migration can still read them; the upstream fix ("ipv4: free inet_opt and ireq_opt after an RCU grace period") moves the frees to `kfree_rcu()`. Remote, unauthenticated, no user interaction, rated as leading to remote code execution. The demonstrated exploit needs an MPTCP listener, which Go 1.24+ opens by default (lnd v0.20.7 release note); the bug itself is not MPTCP-specific. On 2026-11-02 the Ubuntu 22.04 / 24.04 / 26.04 kernels still carried it (fixes in `-proposed` only) while Red Hat and Debian had shipped, and Anza and the Solana Foundation told Ubuntu validators to drop inbound TCP packets carrying IPv4 options, set `net.mptcp.enabled=0` and `net.ipv4.tcp_migrate_req=0` until the patch landed. Red Hat's advisory (RHSB-2026-016) says the packet filter "reduces exposure" and "cannot fully prevent" exploitation; Ubuntu's says security updates are the only appropriate mitigation. No validator compromise has been reported; this entry covers the class.**

A validator, RPC node, keeper or indexer accepts packets from the whole Internet. Every kernel feature that is compiled in or loaded, and every network sysctl left at its default, is reachable by anyone who can send a packet, whether or not the node uses it. The program under audit may be flawless and the identity key still leaves the box through the kernel. Four failure modes ship together:

- **Patch lag the operator does not control.** The upstream fix is public before the distribution's kernel package carries it, and a public fix is an exploit map. A team whose only patch process is `apt upgrade` has no answer for the days or weeks in between: no deadline, no compensating control, no decision about `-proposed` or a vendor kernel.
- **Features enabled but unused.** Multipath TCP, SCTP, DCCP, RDS, TIPC, IP options processing, request-socket migration, unprivileged BPF, user namespaces: each is a code path an attacker can drive from outside, and a node that never uses them keeps them on because the defaults do. The strong form of the fix is a kernel built without the feature; the practical form is `sysctl.d` plus a `modprobe.d` blacklist, applied by configuration management and checked against an inventory of what the node actually needs.
- **Management plane on the public interface.** SSH, metrics exporters, admin RPC and any Go service (an MPTCP listener since Go 1.24) on the public address multiply the TCP paths into the kernel. Everything that does not have to accept connections from the Internet belongs behind a VPN (WireGuard, Tailscale) or a source allowlist.
- **Compensating controls that never expire, or never persist.** A `sysctl -w` typed on the host is gone at the next reboot; an nftables table named after a CVE is meant to be removed once the patch is in. Without configuration management and a removal date, the node either loses its mitigation silently or keeps a rule that later breaks a workload.

> Cross-ref: checklist 13 §13.14 (DEP-097..102: patch SLA, kernel feature inventory, unused protocols off, compensating controls with an exit, management plane off the public interface, runtimes that open MPTCP); `references/vuln-classes/kernel-attack-surface.md` (the inventory and reduction procedure, the CVE fact sheet, infra-as-code worksheet); KV-089 (unpatched server dependencies: the userland sibling of this vector); KV-001 (a kernel RCE on a validator host is custody of the identity and vote keys); KV-116 (CI hosts that hold deploy keys face the same surface); checklist 17 LM (advisory monitoring and alerting).

#### Verification Procedure

**Step 1: Establish which hosts face the Internet, on which OS and kernel, from infra-as-code and runbooks**
```
grep -rn -iE 'ubuntu|debian|rhel|rocky|amazon linux|ami-|image *=|linux-image|kernel' infra/ ansible/ terraform/ cloud-init/ packer/ docker-compose*.y*ml Dockerfile* docs/ 2>/dev/null
grep -rn -E '0\.0\.0\.0/0|::/0|from_port|to_port|ingress|ufw allow|nft |iptables|security_group|firewall' terraform/ ansible/ cloud-init/ infra/ 2>/dev/null
```
- Record each host role (validator, RPC, keeper / bot, indexer, CI runner), its distribution and kernel line, and every port that accepts TCP connection requests from untrusted sources (RPC 8899 / 8900, SSH 22, metrics exporters, any Go service). A host with no public TCP listener is out of this vector's blast radius for a TCP bug, but keep it in scope for the inventory items.
- If no host is operated by the team (fully managed SaaS / serverless deployment, no VM, no bare metal, no self-hosted runner), this vector is N/A (record this explicitly).

**Step 2: Kernel patch SLA and advisory source, including the distro-lag case**
```
grep -rn -iE 'unattended-upgrades|livepatch|kernel.*(sla|policy|patch)|security@|advisor(y|ies)|-proposed|cve-20' docs/ runbooks/ ansible/ cloud-init/ SECURITY.md .github/ 2>/dev/null
```
- ✅ PASS: a written SLA names who watches kernel advisories for the exact distribution in use, the maximum time to patch by severity, and what happens when upstream has a fix and the distribution does not (compensating control through configuration management, deadline, decision on `-proposed` / vendor kernel); the process has fired at least once (a past kernel update traceable to an advisory)
- ❌ FAIL: patching is "whenever `apt upgrade` runs", no owner, no distro-lag plan (the CVE-2026-98432 position of a validator that learned of the bug from the Foundation's post)
- On a host, with the operator's go-ahead and read-only: `uname -r`; Ubuntu `dpkg -l 'linux-image*' | grep ^ii`; RHEL `rpm -q kernel`; compare with the advisory's fixed version (for CVE-2026-98432 on 2026-11-02: Ubuntu 24.04 `6.8.0-149.149`, 22.04 `5.15.0-203.213`, both in `-proposed`)

**Step 3: An inventory of kernel features in use exists, and every enabled feature is justified**
```
grep -rn -E 'sysctl\.d|modprobe\.d|modules-load\.d|lsmod|/boot/config|CONFIG_[A-Z0-9_]+=' ansible/ cloud-init/ packer/ infra/ docs/ 2>/dev/null
```
- ✅ PASS: configuration management declares the network sysctls and the module blacklist from an inventory of what the node needs (loaded modules, built-in features, listeners), and the inventory is re-reviewed per kernel release
- ❌ FAIL: no inventory; sysctls and modules are the distribution's defaults; nobody can say whether the node uses MPTCP, SCTP or IP options
- On a host, read-only: `lsmod`; `grep -E '^CONFIG_(MPTCP|IP_SCTP|IP_DCCP|RDS|TIPC|USER_NS|BPF_UNPRIV_DEFAULT_OFF)=' /boot/config-$(uname -r)`; `sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req net.ipv4.conf.all.accept_source_route kernel.unprivileged_bpf_disabled`; `ss -lntup`

**Step 4: Unused network features are disabled, including the ones a runtime opens by itself**
```
grep -rn -E 'net\.mptcp\.enabled|tcp_migrate_req|accept_source_route|install (dccp|sctp|rds|tipc) /bin/(false|true)|blacklist (dccp|sctp|rds|tipc)|unprivileged_bpf_disabled' ansible/ cloud-init/ packer/ etc/ infra/ 2>/dev/null
grep -rn -E 'GODEBUG|multipathtcp' ansible/ cloud-init/ systemd/ docker-compose*.y*ml Dockerfile* 2>/dev/null
```
- ✅ PASS: every protocol and feature the inventory does not need is off in `sysctl.d` / `modprobe.d` (MPTCP, SCTP, DCCP, RDS, TIPC, source routing; unprivileged BPF where nothing needs it), and Go 1.24+ services that do not need MPTCP run with `GODEBUG=multipathtcp=0`
- ❌ FAIL: defaults untouched; or the features were disabled by hand with `sysctl -w` and are not in configuration management (gone at the next reboot)

**Step 5: Compensating controls for an unpatched CVE are managed, named and have an exit**
```
grep -rn -E 'cve[_-][0-9]{4}[_-][0-9]+|ip hdrlength > 5|hdrlength|sysctl -w' ansible/ cloud-init/ scripts/ runbooks/ docs/ 2>/dev/null
```
- ✅ PASS: the mitigation (for CVE-2026-98432: the nftables drop of TCP packets with IPv4 options, `net.mptcp.enabled=0`, `net.ipv4.tcp_migrate_req=0`) is applied by configuration management, the nftables table is named after the CVE, a removal date or condition is recorded (the patched kernel running), and the runbook states the limit the vendor states (Red Hat: reduces exposure, does not prevent)
- ❌ FAIL: applied by hand on some hosts, or treated as the fix (no patch deadline), or no record of which hosts carry it so it is never removed

**Step 6: The management plane is off the public interface**
```
grep -rn -iE 'tailscale|wireguard|wg0|AllowUsers|ListenAddress|PasswordAuthentication|PermitRootLogin|port 22\b|:22\b|9100|node_exporter|prometheus' ansible/ cloud-init/ terraform/ infra/ docs/ 2>/dev/null
```
- ✅ PASS: only the node's service ports (RPC where the role requires it; gossip / TPU as the validator needs) accept connections from the Internet; SSH, metrics and admin endpoints bind to the VPN interface or are restricted to a source allowlist; password SSH is off
- ❌ FAIL: SSH, exporters or admin RPC answer on the public address, each one another TCP path into the kernel for the next request-socket bug

**Overall verdict:**
- ✅: Hosts and their public TCP surface are known; a kernel patch SLA with a distro-lag plan exists and has fired; an inventory drives `sysctl.d` / `modprobe.d` so unused features (MPTCP, SCTP, DCCP, RDS, TIPC, source routing) are off and runtime-opened MPTCP is closed; compensating controls live in configuration management with a named exit; management plane behind VPN or allowlist
- ⚠️: Patching is current but there is no SLA or distro-lag plan; or features were disabled by hand; or mitigations exist without a removal condition; or SSH is public with keys only
- ❌: An Internet-facing host runs a kernel with a published remote fix it has not applied and no compensating control, or keeps MPTCP / request-socket migration / unused protocols on with no inventory saying why, or exposes SSH / metrics / admin RPC on the public address
- N/A: No host is operated by the team (managed SaaS / serverless only, no VM, bare metal or self-hosted runner)
