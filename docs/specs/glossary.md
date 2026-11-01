# Glossary

Every term the specs use. Each entry says what it means in plain words, then adds the technical detail.
Entries are in alphabetical order.

## ADR

**Plain.** Architecture Decision Record: a short note that records one design decision, the options that were
considered, what was chosen and why.

**Technical.** Each ADR has an ID, a status (proposed, accepted, rejected, superseded), the owner of the
decision and the evidence that would change it.

## AI Gateway

**Plain.** A Vercel service that gives one endpoint and one key for many AI model providers.

**Technical.** It exposes OpenAI-compatible endpoints such as chat completions. In blackice the gateway key
stays in the relay, outside every scope, so the agent never holds it.

**See also.** relay, credentials brokering

## allowlist

**Plain.** A list of the only places a program may connect to. Anything not on the list is refused.

**Technical.** In a blackice policy, `"mode": "allowlist"` with `network.allow` holding exact names
(`example.com`) or wildcard names (`*.example.com`), and `network.subnets.allow` holding address ranges.

**See also.** policy, subnet

## app scope

**Plain.** A scope that applies to an app already installed on the machine, however it was started, for example
a browser or an editor.

**Technical.** It needs the OS to say which app a connection comes from: a Network Extension on macOS, and a
grouping such as a desktop or service cgroup on Linux. Not part of v0; required for the
first usable release.

**See also.** scope, task scope, Network Extension

## backend

**Plain.** The part of blackice that does the confining on one operating system.

**Technical.** macOS: a Seatbelt profile applied through `sandbox-exec`. Linux: a root-owned cgroup with
eBPF socket programs, a private mount namespace, Landlock and seccomp. Every backend implements the same contract
(`src/core/backend.zig`): confine the command before it runs, and allow only the scope's own loopback ports.
With no working backend, blackice refuses to run the command.

**See also.** task scope, Seatbelt, cgroup v2

## cgroup v2

**Plain.** A Linux feature that puts processes into named groups. A process and every child it starts stay
in the same group, and the kernel can apply rules to the whole group.

**Technical.** The unified control-group hierarchy under `/sys/fs/cgroup`. nftables can match packets by the
cgroup of the sending socket (`socket cgroupv2`), and eBPF programs can attach to a cgroup. Who may move a
process between groups depends on who owns the directories, which is why blackice keeps its groups under a
root-owned `/sys/fs/cgroup/blackice/`.

**See also.** nftables, eBPF, task scope

## CIDR

**Plain.** A short way to write a range of network addresses, like `10.0.0.0/8`.

**Technical.** An address plus a prefix length: the number of leading bits that every address in the range
shares. Works for IPv4 (`/0` to `/32`) and IPv6 (`/0` to `/128`).

**See also.** subnet

## configured provider

**Plain.** An fx setting that tells fx which model endpoint to talk to. blackice points it at the relay.

**Technical.** In fx's settings, a provider with protocol `openai-chat-completions`, a `base_url` such as
`http://127.0.0.1:<relay port>/v1` (fx accepts plain HTTP only for loopback) and `auth: none`. fx ignores its
user settings unless `~/.fx` is mode 0700 and `settings.json` is 0600.

**See also.** relay, fx

## CONNECT proxy

**Plain.** A local helper that programs ask to open connections for them. It sees which host a program wants
before any data flows, so it can say yes or no.

**Technical.** An HTTP proxy that accepts `CONNECT host:port` for TLS and other tunnelled traffic, and plain
`GET http://...` requests. Programs find it through `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY`. The host
name in a CONNECT request is a claim by the client, so the blackice proxy resolves the name itself and dials
only the addresses the policy accepts.

**See also.** proxy, SNI, DNS gating

## control socket

**Plain.** The private channel the owner uses to talk to a running scope, for example to give a grant.

**Technical.** A Unix socket outside the scope. Processes inside cannot reach it: a Seatbelt rule on macOS, a
mount namespace on Linux.

**See also.** grant, owner

## credentials brokering

**Plain.** Keeping a secret, such as an API key, outside the program that uses it. A trusted helper adds the
secret to each request on the program's behalf.

**Technical.** In blackice the relay holds the key and injects it into requests to the model provider. The
key never enters the scope. This stops the key itself from leaking; it does not stop a program from sending
other data to the allowed provider.

**See also.** relay, AI Gateway

## DNS

**Plain.** The system that turns a name like `example.com` into a network address.

**Technical.** Lookups can travel as UDP or TCP on port 53, as DNS over HTTPS, or through local services
such as systemd-resolved on Linux or mDNSResponder on macOS. A lookup is itself a message leaving the
machine, so it can carry data out.

**See also.** DNS gating

## DNS gating

**Plain.** Making sure a program inside a scope cannot look up names on its own. It can only ask the blackice
proxy, which checks the policy first.

**Technical.** Each path is closed separately: direct port 53 traffic by the network rules, and local
resolver services by hiding their sockets (on Linux, a private mount namespace over the systemd-resolved,
D-Bus, avahi and nscd sockets; on macOS, Seatbelt's outbound deny also blocks the mDNSResponder socket).
A network namespace alone is not enough: a probe showed lookups still escaping through systemd-resolved.

**See also.** DNS, mount namespace, CONNECT proxy

## domain fronting

**Plain.** Using an allowed site's name on the outside of an encrypted connection while asking, on the
inside, for a different site served by the same provider.

**Technical.** Works where many sites share one CDN or hosting front end: the TLS server name says the
allowed host, the encrypted HTTP `Host` names another one, and the front end routes by the inner name. The
blackice proxy checks the server name but cannot read the encrypted request, so this stays a stated limit.

**See also.** SNI, TLS, CONNECT proxy

## eBPF

**Plain.** A way to load small, checked programs into the Linux kernel so it can make decisions quickly,
for example whether a connection may be opened.

**Technical.** The Linux backend attaches cgroup socket-address programs (`connect4`, `connect6`, `sendmsg4`,
`sendmsg6`) to each scope's cgroup. They act on the socket call itself, before a packet exists, so TCP,
connected and unconnected UDP and IPv6 go through the same check. Refusals reach blackice through a BPF ring
buffer.

**See also.** cgroup v2, nftables, backend

## ECH

**Plain.** Encrypted Client Hello: a newer TLS feature that hides the name of the site a program is
connecting to, even from the local network.

**Technical.** It encrypts the inner ClientHello, including the real SNI, behind a public outer name. Anything
that filters by reading SNI sees only the outer name. The blackice proxy requires the SNI it sees to equal the
`CONNECT` host (proxy.R10), so with ECH it compares the outer name: a tunnel whose outer name differs is closed
(`sni_mismatch`), and the inner name stays hidden from it. No run with ECH through the proxy is recorded.

**See also.** SNI, TLS, CONNECT proxy

## enforcement point

**Plain.** The place where a decision was made: the proxy, the kernel, the relay, or the control channel.

**Technical.** The `point` field of a receipt: `proxy`, `kernel`, `relay` or `control`.

**See also.** receipt

## evidence entry

**Plain.** A written record of a real run that proves a capability works: what was run, where, and what was
seen.

**Technical.** One file per run in `evidence/`, named after the checkpoint it covers (`P0-02-...md`), with
the platform, build, policy, commands, result, receipts, recording and limits. Only an evidence entry
verifies a requirement.

**See also.** evidence gate, probe, v0 checkpoints

## evidence gate

**Plain.** A question that must be answered with a real test before a capability can be claimed.

**Technical.** Each gate names what it blocks (for example a release cell) and who owns the test. Passing it
needs evidence entries, not reasoning or source reading.

**See also.** evidence entry, v0 checkpoints

## exit status

**Plain.** The number a command returns when it ends. 0 means success.

**Technical.** `blackice run` exits with the command's own status, or 128 plus the signal number when the
command was killed by a signal, so it can stand in front of any command in a script.

## fx

**Plain.** A coding agent from Vercel Labs that runs in the terminal. It reads code, edits files and runs
commands such as tests and installs.

**Technical.** Open source, written in Zig. Since 0.0.5 it runs approved commands as ordinary host
subprocesses, with no network boundary of its own. blackice pins the fx version it tests by release tag and
commit.

**See also.** fx auto mode, L0

## fx auto mode

**Plain.** fx's default way of working: it runs familiar project commands (tests, builds, local installs,
development servers) by itself, and asks a model to review anything unfamiliar.

**Technical.** Recognized project commands run directly, with no prompt and no model review; the code inside
them (test files, install scripts) is never shown to the reviewer. That is the case where a network boundary
matters most, because nobody looked at what the command does.

**See also.** fx, L0

## fx hook

**Plain.** A small, declared patch to fx so that every command fx launches runs in its own blackice scope. fx
itself stays outside. This is the main way blackice works with fx.

**Technical.** A builtin `PreToolUse` handler, kept in the repo under `integrations/fx/`, that rewrites each
shell tool call to `blackice run --policy <file> -- <command>` with a scrubbed environment. Each command gets its
own receipts. The patch names the fx release it applies to. L0 is the fallback.

**See also.** fx, L0, task scope

## grant

**Plain.** Extra access the owner gives a running scope, for a limited time, for example "allow
`api.example.com` for ten minutes".

**Technical.** `blackice grant <scope> <host> --for <duration>`, sent over a control socket the scope cannot
reach. Its own receipt records it, and the decisions it allows name it (`grant:<host>`). It ends at its
expiry, on revoke or when the scope ends, whichever comes first, and closes the connections it opened.

**See also.** owner, control socket, policy generation

## host ceiling

**Plain.** Machine-wide limits that sit above every scope. No scope can allow something the ceiling forbids.

**Technical.** The effective permission of a scope is the intersection of the host ceiling, any parent scope
and its own policy. A nested scope can only narrow. Designed, not part of v0.

**See also.** scope, policy

## JSON Lines

**Plain.** A text file with one JSON object per line. Easy to append to, and easy to search with `grep` or
`jq`.

**Technical.** Each line is a complete JSON value followed by a newline. Receipts use it: a reader can process
a file that is still being written, line by line.

**See also.** receipt

## kernel enforcement

**Plain.** The operating system itself refuses the connection, so the program cannot skip the check by
ignoring the proxy.

**Technical.** On Linux, eBPF programs attached to the scope's cgroup; on macOS, the Seatbelt sandbox in the
kernel. A
receipt records `point: kernel` when the kernel refused.

**See also.** enforcement point, nftables, Seatbelt

## L0

**Plain.** The fallback way to use blackice with fx: run all of fx inside one task scope, with no changes to
fx.

**Technical.** `blackice run --policy FILE -- fx`. fx and every tool it starts share one network envelope, and
fx reaches its model through the relay. The main mode is the fx hook, which gives each command its own scope.

**See also.** fx hook, relay, task scope

## Landlock

**Plain.** A Linux feature that lets an unprivileged program give up access to things, such as files or
certain sockets, for itself and its children.

**Technical.** A stackable Linux security module driven by system calls. Recent kernels can also scope
abstract Unix sockets and signals. blackice uses it, where the kernel supports it, to stop a scope from
reaching abstract Unix sockets outside it.

**See also.** mount namespace

## loopback

**Plain.** Connections a machine makes to itself, such as `127.0.0.1` or `localhost`.

**Technical.** `127.0.0.0/8` and `::1`. A scope may reach only the loopback ports of its own proxy and relay;
other local services are refused.

## mount namespace

**Plain.** A private view of the file system for a group of processes. blackice uses it to hide some files
from a scope.

**Technical.** Created with `unshare(CLONE_NEWNS)`. The Linux backend mounts empty directories over local
resolver and daemon sockets inside the scope, so those services cannot be asked to look up names or open
connections for it.

**See also.** DNS gating, Landlock

## Network Extension

**Plain.** Apple's supported way for a firewall app to see and decide every network connection on a Mac.

**Technical.** A system extension, such as one built on `NEFilterDataProvider`, shipped inside a signed app
with matching entitlements and activated with the user's consent. Needs an Apple Developer Program
membership to sign. Planned for macOS app scopes.

**See also.** app scope, SIP

## NFLOG

**Plain.** A way for the Linux firewall to hand a copy of a dropped packet's details to a program, so the
drop can be written down.

**Technical.** The nftables `log group N` statement sends packet metadata to user space over netlink. Part of
the first Linux plan; the current backend reports refusals through a BPF ring buffer instead.

**See also.** nftables, eBPF

## nftables

**Plain.** The Linux kernel's firewall.

**Technical.** It can match packets by the cgroup of the sending socket (`socket cgroupv2`) and log drops with
NFLOG. It was the first plan for the Linux backend; the backend owner chose socket-address eBPF programs
instead, because packets the kernel cannot attribute to a cgroup fall through a cgroup match. blackice does not
change host firewall rules.

**See also.** eBPF, NFLOG, cgroup v2

## owner

**Plain.** The person allowed to change a scope's access from outside it.

**Technical.** In v0, any process of the same user that runs outside every scope counts as the owner. That is
a declared limit: blackice does not defend against other programs of the same user that are not confined.

**See also.** grant, control socket

## policy

**Plain.** A small file that says where a scope may connect.

**Technical.** JSON, version `blackice.policy/v0`, with a mode (`deny-all`, `allow-all`, `allowlist`), allowed
names and allowed or denied subnets. Unknown fields are rejected. See [policy.md](policy.md).

**See also.** allowlist, policy digest, reason code

## policy digest

**Plain.** A fingerprint of the exact policy file, so a receipt shows which version of the rules made a
decision.

**Technical.** The first 12 hex digits of the SHA-256 of the file bytes.

**See also.** policy, policy generation

## policy generation

**Plain.** A counter for changes to a running scope's policy. In v0 a running scope's policy never changes, so
it is always 1.

**Technical.** The `gen` field of a receipt. Generation 1 is the policy the scope started with. v0 has no live
policy reload; grants are recorded by their own receipts, not as new generations.

**See also.** grant, receipt

## probe

**Plain.** A quick experiment that checks an OS feature works the way the design needs, before blackice code
exists for it.

**Technical.** Probes do not run blackice and never count as evidence that blackice works. They are kept as
context in a spec's evidence table with kind `probe`.

**See also.** evidence entry

## proxy

**Plain.** See CONNECT proxy.

## proxy variables

**Plain.** Environment settings that tell programs to send their web traffic through a proxy.

**Technical.** `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, in upper and lower case. blackice sets them to the
scope's proxy and removes `NO_PROXY`. A program that ignores them cannot connect at all, because the backend
allows only the proxy and relay ports: it fails closed.

**See also.** CONNECT proxy, backend

## reason code

**Plain.** A short fixed label that says why a decision went the way it did, such as `no_matching_rule`.

**Technical.** Stable identifiers carried in receipts. Renaming one is a contract change, because tools and
people grep for them.

**See also.** receipt, policy

## receipt

**Plain.** One line written for every decision: which scope, which destination, allowed or refused, and why.

**Technical.** A JSON line in `~/.local/state/blackice/scopes/<id>/receipts.jsonl` with time, scope, policy
digest, generation, enforcement point, event, verdict, reason code, rule and destination. Metadata only: no
payloads, no secrets. Lines that fail to write are counted and reported when the scope ends.

**See also.** reason code, enforcement point

## relay

**Plain.** A local helper outside the scope that forwards the agent's model requests to the model provider and
adds the API key on the way, so the agent never has the key. Only the L0 mode needs it.

**Technical.** An OpenAI-compatible endpoint on `127.0.0.1:<port>` that forwards to AI Gateway. It reads the key
from standard input, never from the environment, the command line or a file. It limits models, request size
and request count, and writes one receipt per call.

**See also.** credentials brokering, AI Gateway, L0

## revocation

**Plain.** Taking a permission back, for example when a grant expires.

**Technical.** In v0 a revocation applies to new connections only: a connection opened while the grant was
active stays open until it closes or the scope ends. blackice says so in its output and receipts.

**See also.** grant

## sandbox-exec

**Plain.** A macOS command that starts a program inside a Seatbelt sandbox described by a profile.

**Technical.** `/usr/bin/sandbox-exec -p PROFILE CMD...`. Apple marks it deprecated, but it ships with macOS and
is still the documented way to apply a profile to a command. The macOS task scope uses it.

**See also.** Seatbelt

## scope

**Plain.** A box that a policy applies to. Everything inside the box gets the same network permissions.

**Technical.** Two kinds: a task scope (a command and everything it starts) and an app scope (an installed app).
Each scope has an ID, a policy, a generation and a receipt log.

**See also.** task scope, app scope, host ceiling

## Seatbelt

**Plain.** The sandbox built into macOS. Apple uses it for its own apps and services.

**Technical.** A kernel policy module driven by profiles written in a Scheme-like language (SBPL). A profile
can deny `network-outbound` and allow only specific loopback ports. It cannot name remote hosts or addresses,
so blackice decides names in the proxy.

**See also.** sandbox-exec, SIP

## seccomp

**Plain.** A Linux feature that lets a program give up the right to make certain system calls, for itself and
everything it starts.

**Technical.** A filter on system calls and their arguments, installed before exec. The Linux backend uses it to
refuse raw sockets, unsupported socket families, Unix sockets that would reach outside the scope, new network
namespaces and io_uring.

**See also.** Landlock, backend

## SIP

**Plain.** System Integrity Protection: a macOS safety feature that stops even the administrator from changing
protected parts of the system.

**Technical.** Enabled by default. It can only be turned off or on from recoveryOS. blackice is tested with SIP
on; a result with SIP off is reported as such.

**See also.** Seatbelt, Network Extension

## SNI

**Plain.** The name of the website a program wants, sent in the clear at the start of an encrypted
connection.

**Technical.** Server Name Indication, a TLS ClientHello extension. It is a claim by the client, can be absent,
and is hidden by Encrypted Client Hello. The blackice proxy decides on the `CONNECT` host name and its own name
resolution, then reads the tunnel's first bytes: they must be a ClientHello, and for a destination given as a
name its SNI must be present and equal that host. Otherwise the proxy closes the tunnel before any of the
client's bytes is forwarded (`not_tls`, `tls_unparsed`, `sni_missing`, `sni_mismatch`; proxy.R10, proxy.R11).
The connection to the destination is already open by then. A matching name does not prove who the server is.

**See also.** CONNECT proxy, ECH, domain fronting

## state directory

**Plain.** The folder where blackice keeps one scope's files: the exact policy it started with and its
receipts.

**Technical.** `$XDG_STATE_HOME/blackice/scopes/<id>/`, by default `~/.local/state/blackice/scopes/<id>/`. Only
the blackice process writes it; inside the scope it is read-only or hidden. Other processes of the same user
outside every scope can still change it, so it is a record for diagnosis, not tamper-proof evidence.

**See also.** receipt, scope

## subnet

**Plain.** A block of network addresses, such as everything in a home network.

**Technical.** Written in CIDR form. A policy can allow subnets (`network.subnets.allow`) or deny them
(`network.subnets.deny`); a denied subnet always wins.

**See also.** CIDR, policy

## task scope

**Plain.** A scope that wraps one command and every process it starts. `blackice run -- fx` puts fx and all of
its tools in one task scope.

**Technical.** The policy is attached before the command runs, and children inherit it. On macOS a Seatbelt
profile; on Linux a root-owned cgroup with eBPF socket programs and a private mount namespace.

**See also.** scope, app scope, L0

## test vectors

**Plain.** A fixed list of example inputs with the exact output each one must produce. They define what a
component supports.

**Technical.** For the Sandbox importer: pairs of a Sandbox `networkPolicy` and the expected blackice policy or
refusal, plus destinations with their expected verdicts. Every enforcement point can run the same vectors.

**See also.** policy

## TLS

**Plain.** The encryption under HTTPS. It keeps the content of a connection private between the program
and the server.

**Technical.** Transport Layer Security. The CONNECT proxy carries TLS without decrypting it: it decides on the
host name and its own name resolution, before any TLS bytes flow.

**See also.** SNI, ECH, CONNECT proxy

## v0 checkpoints

**Plain.** The checkpoints for v0, the first version: a short list that shows the boundary works on real
machines. v0 is not a product release.

**Technical.** Checkpoints `P0-01` to `P0-10` (for example `P0-02`, real deny). Each is marked recorded only
when an evidence entry with its ID exists.

**See also.** evidence entry, evidence gate
