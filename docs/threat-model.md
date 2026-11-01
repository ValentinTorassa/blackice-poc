# Threat model

blackice is an experimental local network-permission system. The first intended usable release covers both ordinary applications and managed command sessions on macOS and Linux. A command-only demonstration does not complete that release.

Main implements policy parsing, a proxy and model relay, temporary grants, receipts, and two task launchers: an experimental macOS Seatbelt launcher and a Linux launcher with cgroup eBPF programs and a privileged helper. Task runs on both are recorded in `evidence/`; they do not cover the app filters. A successful build is not evidence that all of the guarantees below hold.

## Assets and actors

The assets are effective network permissions, workload-to-scope identity, temporary-grant lifetime, policy/control authority, provider credentials and useful decision records.

| Actor or component | Intended authority |
| --- | --- |
| Workload, agent and descendants | Use granted network access; request changes. They cannot approve their own expansion or disable mandatory policy. |
| Independent owner | Authorize bounded changes and recovery through a protected control path. |
| Core / control service | Validate requests, preserve scope identity and coordinate policy activation. |
| Native backend and privileged helper | Enforce the acknowledged boundary before execution, with only required privileges. |
| Proxy and model relay | Connect on behalf of one verified scope, within its destination and lifetime limits. |
| Observer or receipt consumer | Read authorized metadata. Observing an event does not grant policy authority. |

The OS and the trusted installation are part of the trusted computing base. A system administrator, compromised kernel, malicious firmware, and physical attacker with control of the machine are outside this model.

## What is being constrained

The managed command may be buggy or adversarial. It can try direct sockets, alternate address families and protocols, resolver APIs, subprocesses, detached children, inherited descriptors, local proxies, IPC to existing daemons, policy/control operations and malformed input.

Network filtering alone does not isolate files, protect all existing credentials, prevent same-user process tampering, inspect payloads for secrets or stop exfiltration to an authorized endpoint. A shared-UID workload is not automatically a securely isolated user. Filesystem and process-control exposure must not be hidden behind a general sandbox claim.

## Required boundaries

1. **Launch:** identify and enroll the exact process instance, attach the required policy generation, acknowledge success, then execute user code. A PID scan or moving a process after it starts is insufficient.
2. **Descendants and delegation:** qualify child inheritance and containment. Work delegated to an already-running service needs a separate boundary. Killing a parent does not prove that its children or proxy connections ended.
3. **Destination:** deny paths outside the supported policy. DNS, IPv4/IPv6, TCP/UDP, loopback, LAN and existing sockets require explicit coverage; one TCP test does not establish deny-all.
4. **Control:** authenticate the actor, operation and target scope independently of a claimed PID, executable name, environment variable or workspace file. Temporary permission must fit every applicable mandatory limit.
5. **Lifetime:** terminate temporary authority at the earliest applicable expiry/session boundary. Distinguish preventing new connections from terminating existing ones, including proxy-owned connections.
6. **Observation:** receipts explain decisions without influencing enforcement. Bounded logging, explicit gaps and owner-configurable retention are necessary; a logging failure cannot grant access.

## Linux installation and privileges

The intended Linux path uses a root-owned workload cgroup outside the user's delegated subtree and BPF `connect4`/`connect6` and `sendmsg4`/`sendmsg6` admission programs. A narrowly scoped helper forks its own paused child, binds it through a pidfd, enrolls it and arms containment before releasing it; callers cannot submit an arbitrary PID to attach. Denial events use a per-scope ring buffer, with loss counted separately. This design does not modify host nftables rules. The backend must prove enrollment, attribution and protocol coverage before advertising support.

These hooks provide admission at socket calls; their coverage does not extend to every protocol. [Seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html) must check the address family, socket type and protocol together when `socket()` is called. Only supported TCP/UDP combinations and their default-protocol equivalents may be created. SCTP, ICMP/ICMPv6 ping sockets and other unqualified protocols must be refused at creation, since their traffic may bypass the required hooks. Socket pairs and inherited or received descriptors need separate constraints; filtering new socket creation does not retroactively constrain them.

An operator reads and runs the setup script with sudo. The launcher does not invoke sudo on behalf of a workload. Setup and teardown must operate on owned paths, validate ownership and symlinks, and leave unrelated firewall/cgroup configuration intact. File capabilities are privileges: group membership and executable access do not replace validation of each helper operation.

Mount-namespace hiding of resolver or daemon paths is a targeted mitigation. It does not by itself cover already-open descriptors, alternate socket names, `/proc` access, external service requests or all same-user IPC. Landlock and any additional confinement must be probed for the required ABI and tested, not inferred from a kernel version. Failure to provide a mandatory boundary must refuse strict launch.

## Proxy and real-model relay

In `blackice run --relay`, the provider key belongs to the relay outside the managed command's scope. It must not appear in workload environment variables, arguments, state files, receipts or recorded demonstrations. Disable process dumps where supported, keep credentials out of errors, and consider inheritance and process-inspection paths separately. This mode does not isolate existing credential files or establish isolation between all same-user processes. Excluding the raw key does not eliminate the authority to spend through the relay.

The relay needs a fixed upstream, a model allowlist, bounded body/response sizes, request and spending limits, and a verified scope/lifetime binding. Client input must not override upstream credentials, choose arbitrary upstream destinations, or redirect a credential-bearing request elsewhere. Authentication to the relay is distinct from authentication of its upstream provider.

An allowed name on a shared front end can expose other sites behind the same address. For plaintext HTTP, the proxy must validate the destination and bind the forwarded `Host` to that same authority. For a name-based CONNECT tunnel, require a TLS ClientHello with SNI matching the authorized name before forwarding client bytes; refuse plaintext, missing SNI and mismatches. A matching SNI still cannot prevent **domain fronting**: a shared server may accept a different `Host` or HTTP/2 authority inside the encrypted request. Without TLS termination, that inner authority is not inspected. This remains a declared limit, not a guarantee that every request reaches only the named site. See the [shared-front-end review](https://github.com/ValentinTorassa/blackice/pull/4#discussion_r4420538067).

Treat attacker-controlled pages in the user's browser as potential callers of loopback services. A permitted `no-cors` POST can cause a side effect even when the page cannot read the response; DNS rebinding can give an attacker-controlled hostname a loopback address. Browser protections vary, so random ports, loopback binding and CORS response restrictions do not establish caller authority. The command-line-only relay and any future TCP control endpoint must reject requests carrying `Origin` (including `null`) or `Sec-Fetch-*`, require an exact configured loopback `Host` with the listening port, and require `application/json` for JSON POSTs. Reject ambiguous authority headers and do not enable browser access through permissive preflight responses. These checks address the [browser-to-loopback review](https://github.com/ValentinTorassa/blackice/pull/4#discussion_r4420538075); [Fetch Metadata headers](https://www.w3.org/TR/fetch-metadata/) describe the browser request context. Their absence does not authenticate a caller: native clients can omit or forge headers, so scope binding and independent control authority remain necessary.

A local listening port is not a scope identity. Prevent cross-scope reuse, stale-port takeover and unbound requests. The fx integration provides a declared `PreToolUse` patch to launch each shell command in a blackice scope while the controller stays outside. The [recorded hook test](../evidence/P0-07-fx-hook-scripted-macos.md) uses a scripted model; fx's own reads, writes inside the workspace and model traffic remain outside those scopes. Every relevant execution path must be audited before claiming that all launched commands are covered; a hook's existence does not establish coverage. The L0 whole-agent wrapper is a planned fallback, not qualified by the hook test. Such a wrapper would share one network envelope with its tools, including any destinations or relay access granted to the agent.

## Owner-grant limitation in the initial design

The current control path treats same-user processes outside managed scopes as the owner. This is a limited convenience model, not proof of independent authority against an adversarial shared-user process. Hiding a control socket pathname alone cannot establish that stronger property.

Before claiming resistance to self-grant, test direct IPC, alternate paths, existing descriptors, process injection, helper invocation and delegation to unconfined daemons. Document exactly which attempts were blocked and what trusted-owner assumptions remain. Do not widen the threat claim just because one CLI invocation from inside a scope failed.

## Failure and evidence

The backend must report whether protection is active, degraded or unknown. The behavior after extension loss, packet-rule removal, proxy failure, broker restart, sleep, reboot and storage failure is platform-specific. Preserve valid mandatory policy where supported and refuse new strict work when the required boundary is unknown. Recovery belongs to an independently authorized operator.

Each native claim needs a controlled receiving endpoint, allowed control traffic, denied probes, host/build details and recorded limits. Include DNS, inherited sockets, process escape, expiry and fault behavior as applicable. Test unsupported socket creation, plaintext and SNI-less named tunnels, conflicting HTTP authorities, and browser-shaped relay requests alongside a legitimate command-line control request. Refused proxy/relay requests must not forward workload bytes or spend provider authority. A generated receipt or a policy evaluator result alone is not a network test.

The [macOS deny run](../evidence/P0-02-real-deny-macos.md) records an observation limit: Apple-signed binaries produced kernel-denial receipts, while tested ad-hoc-signed binaries were refused without those receipts; third-party Developer ID signatures were not tested. The kernel log omits destination addresses and loses some lines under bursts. Absence of a receipt does not establish absence of an attempt or permission to connect.

The [policy contract](policy.md) describes the import capability gate. The repository's `evidence/` directory records actual runs; source review and unit vectors must be described as such.
