# Linux task scopes

This backend is experimental. It applies to commands that blackice starts itself; it is not an app or host
firewall. A run with the installed helper on Debian 13 x86_64, kernel 6.12.113, recorded
[policy-before-exec](https://github.com/ValentinTorassa/blackice/blob/aa5a048e1762a0c3c3c56cc8e7a0bf6c4473b0f8/evidence/P0-01-policy-before-exec-linux.md)
and [off-host TCP/UDP denial](https://github.com/ValentinTorassa/blackice/blob/aa5a048e1762a0c3c3c56cc8e7a0bf6c4473b0f8/evidence/P0-02-real-deny-linux.md)
with immediate and double-forked senders, over IPv4 on a LAN and IPv6 over Tailscale. Each entry names the
launcher and helper hashes and the limits of the run.

## Boundary

The core starts its proxy outside the workload and supplies the proxy's loopback ports. The helper attaches four
`BPF_PROG_TYPE_CGROUP_SOCK_ADDR` programs to a new, root-owned cgroup under `/sys/fs/cgroup/blackice`:

| Operation | Admission |
| --- | --- |
| IPv4 TCP connect | Only `127.0.0.1` and an explicitly supplied port |
| IPv6 TCP connect, including mapped addresses | Denied |
| IPv4/IPv6 UDP connect | Denied |
| IPv4/IPv6 unconnected UDP sendmsg/sendto | Denied |
| Raw, ping, SCTP, MPTCP and other socket protocols/families | Socket creation refused by seccomp |
| Filesystem and abstract Unix socket creation | Refused by seccomp; intra-workload socketpair remains available |
| Bind/listen, namespace creation, ptrace, BPF, io_uring | Refused by seccomp |

The evidence entries above cover only the TCP and UDP cases they list.
IPv6 and UDP have no allow path.
The external proxy handles names and allowed remote destinations; the kernel does not resolve names.
Direct DNS cannot use UDP or arbitrary TCP. Resolver and service-manager IPC is also restricted.
The backend does not change nftables rules or other host network configuration.

The setup grants `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_NET_ADMIN` and `CAP_BPF` only to a small, static,
stripped helper. The workload and `blackice` receive no file capabilities. The helper creates its own child;
there is no API to attach an arbitrary PID. It pins process lifetimes with pidfds and checks that the child is in
the cgroup and that all four programs are attached. The child waits on a pipe until containment is armed.

Before exec, the child closes all unexpected descriptors, drops host capabilities and creates private user and
mount namespaces. It then waits while its parent writes the uid/gid maps through the child's proc directory.
Each map covers one ID: the caller's uid or gid. The child stays non-dumpable throughout, so its mapping files
are owned by root, and the parent opens them with the `CAP_DAC_OVERRIDE` it already has. The PID comes only from
the helper's own fork and stays unreaped and pinned by a pidfd. A failed or partial mapping never releases the
child.

The child then masks `/run`, `/var/run`, `/tmp` and `/var/tmp`. It keeps the caller's numeric uid/gid and working
directory, and reopens cwd through the new mounts. When cwd is below `/tmp` or `/var/tmp`, only that directory and
its descendants are restored, from a pinned descriptor. Protected objects and the state root outside cwd are also
restored at their own paths. Everything else in the masked directories stays hidden, including cwd's siblings and
the rest of its parent directories. Run from the project root if commands need the whole project tree. A cwd of
`/tmp` or `/var/tmp` itself, or anywhere under `/run`, is refused. The whole blackice state root, including every
scope's receipts, policy copies and control sockets, is mounted read-only, recursively.

Landlock ABI 6 scopes abstract Unix sockets and signals. Finally, all capabilities are dropped, and an inherited
seccomp filter and `no_new_privs` prevent reacquiring privilege. Standard input, output or error backed by a socket
is rejected, so the command cannot inherit an outside socket's cgroup attribution.

The core passes the canonical absolute state root in `LaunchSpec.state_dir`; if the path is missing or invalid,
launch is refused. The standalone receiver probe protects its receipt directory instead. A read-only mount alone
does not stop a process from connecting to an existing socket; the seccomp rule against creating Unix sockets is
what prevents connections to `control.sock`.

The helper parent must be able to open its child's proc directory to install the ID maps. A `/proc` mount
with `hidepid=2` or `hidepid=invisible` that denies this access makes launch fail closed at
`child_id_mapping`. The helper does not request `CAP_SYS_PTRACE` to override that restriction.

## Protected files

`LaunchSpec.protected_paths` supplies the executable, policy and `--protect` files, including symlink entries
on the way to their resolved targets. The helper pins each object with `openat2`, refusing intermediate
symlinks and magic links. It bind-mounts the pinned file or final symlink node read-only, with `nosuid` and
`nodev`. Protected executables can still run. Every ancestor of these objects and of the state root becomes
a mount point, so renaming, removing or replacing an ancestor fails with `EBUSY`. Ancestors stay writable:
creating, editing, renaming and removing neighboring files still works.

A plain read-only bind leaves existing hard links and alternate mounts writable, so blackice refuses protected
files or symlinks with a link count other than one (`ProtectedFileHasHardLinks`). It also requires exactly one
initial mount-table entry for each filesystem that holds protected objects or the state root
(`ProtectionFilesystemHasAliases`). This is strict on purpose: a filesystem mounted more than once, including an
otherwise valid subvolume layout, may cause launch to be refused. The limits are 48 protected paths, 256 distinct
ancestors and a 64 KiB mount table; going over a limit refuses the launch before exec. Standard descriptors cannot
be directories or refer to a protected inode or a file within the state root; an old open descriptor would
otherwise keep access through its original mount.

These mounts are applied after dropping host capabilities, in the child's private namespaces. The launch uses
helper protocol v2; an older installed helper refuses it before running the command, and the core records
`linux_helper_upgrade_required`. There is no fallback that omits protected paths. A helper built before protocol v2
does not support it, so the owner has to build, review and install a new one.

## Build and install

Required: Zig 0.17.0, Linux with unified cgroup v2, cgroup BPF socket-address hooks and ring buffers, user/mount
namespaces, pidfds, `cgroup.kill`, `openat2`, `statx` mount IDs, `mount_setattr`, seccomp and Landlock ABI 6.
Linux 6.12 is the first target, but a kernel version alone does not prove the required configuration. The helper
refuses to run without its four capabilities. The source supports x86_64 and aarch64; only x86_64 has been tested
locally so far.

The Debian 13 test machine (kernel 6.12) did not have Ubuntu's AppArmor user-namespace restriction. Ubuntu added
`kernel.apparmor_restrict_unprivileged_userns` in 23.10, off by default
([23.10 release notes](https://documentation.ubuntu.com/release-notes/23.10/#security-improvements)), and turned
it on by default in
[24.04 and later](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions).
With that setting at `1` and no suitable AppArmor profile, scopes are expected to fail closed at
`child_containment`: the helper's child drops its capabilities before `unshare` and counts as unprivileged, so
the namespace's mount operations are denied. The namespace-mount failure was reproduced in Ubuntu 26.04 CI. CI
sets `kernel.apparmor_restrict_unprivileged_userns=0` for these tests; an installed-helper run on Ubuntu remains
unverified. Setup does not install an AppArmor profile; adding one would be a separate privileged change that
needs its own security review.

Build as the normal user:

```sh
zig build
zig build test
zig build linux-probe
./scripts/linux-build-helper.sh
```

The helper always uses ReleaseSafe with stripped debug information and an explicit `x86_64-linux` or
`aarch64-linux` target with the baseline CPU. Both `zig build` and the separate helper script use that target,
so host CPU features do not change the reviewed artifact. Its panic path does not symbolize or read source
files, and Zig's segmentation-fault handler is disabled. The helper script prints the target and binary's
SHA-256. Before installation, have the privileged helper and scripts reviewed, and compare that hash with an
independent build of the reviewed commit.

The owner runs the reviewed script manually, supplying that expected hash:

```sh
sudo ./scripts/linux-setup.sh USER EXPECTED_SHA256
```

Setup verifies a root-owned private copy against the expected hash before granting capabilities. It installs
`/usr/local/libexec/blackice-linux-helper` as root, executable only by root and the selected user's primary
group. Both the staged and installed files must have exactly mode 0750 and the four required effective and
permitted capabilities, with no inheritable capabilities. Setup records the installation namespaces in
`/etc/blackice-linux/namespaces` (root:root 0644, directory 0755), and creates the cgroup parent as root:root
0700. The Bash scripts use strict error handling, absolute command paths and an action trace. Setup adds no
sudoers entry or daemon, downloads no dependencies, changes no sysctls and does not flush the firewall.
Run commands as the normal user after setup. Repeat setup after a reboot; cgroups are not persistent.

`blackice run --policy examples/agent.json -- COMMAND ARGUMENTS` uses this backend through the shared
launcher. The core starts the scope's proxy and control socket outside the cgroup and supplies only the proxy
port; `--relay` adds the relay's port. All service and kernel receipts use the same core-owned log. With
`--relay`, the unprivileged launcher replaces stdin with `/dev/null` before executing the helper, so the
command cannot seek back through the provider-key input. Ordinary runs inherit non-socket stdin.

Recovery is a manual step for the owner:

```sh
sudo ./scripts/linux-teardown.sh
```

It disables new helper executions, terminates only blackice scope cgroups and removes only blackice's
helper/configuration, including root-owned setup staging files left by an uncatchable interruption. The
reserved temporary names are `blackice-linux-helper.XXXXXX` and `namespaces.XXXXXX` in their installation
directories. It is safe to repeat. A populated or stuck cgroup retains its attached policy;
teardown refuses to remove it and leaves new launches disabled until owner recovery. Never
detach programs from a live scope as a shortcut.

## Receipts and lifetime

Kernel admission refusals enter a per-scope 64 KiB ring buffer. They carry the destination, port, protocol,
hook and kernel-observed process ID. The helper forwards fixed-size, versioned records on a private pipe;
only the blackice process writes JSON receipts. `kernel_drop` with `point: kernel` means the socket operation
was refused before transmission; it does not mean a packet reached an nftables hook. Seccomp refusals
at socket creation, including `ping`, SCTP and ICMP `sendto` attempts, return `EPERM` without an individual
`kernel_drop` receipt. No socket-create BPF hook is installed. Failed changes to protected paths return the
kernel's errno (usually `EROFS`, `EBUSY` or `EXDEV`) and do not each write a receipt. If containment setup fails,
a kernel warning receipt is written and the command does not run.

Ring overflow increments an independent atomic loss counter. Nonblocking receipt-pipe overflow is counted
separately by the helper; their total is reported at shutdown. Neither kind of loss changes a deny verdict.
An abrupt helper failure can prevent the final loss summary from being delivered. The core reports failure
unless it receives activation, successful cleanup, and an exit record from a successful helper process.

Normal command exit, cancellation or supervisor death kills all remaining scope descendants before cgroup
removal. BPF attachments are persistent cgroup attachments, not links whose close would detach policy.
If the helper is killed while a scope runs, its direct child has a parent-death signal, but processes that
detached from the command keep running. They keep the BPF restrictions, so their only allowed destination is the
dead proxy's local port, and another local program can later listen on that port and receive their connections.
Removing them needs root: kill the processes listed in the scope cgroup's `cgroup.procs`, then remove the cgroup
(killing them by name misses children that were re-parented), or run the teardown script, which does both but
also removes the helper. In that case the receipts wrongly say the command did not start (`command_not_started`,
`scope_end` status 127). The P0-06 Linux fault run showed both. Open proxy connections and the proxy's lifetime and reuse are handled by the core and the proxy;
this backend does not revoke TCP connections that are already open.

## Testing

`zig build test` includes unprivileged namespace, Landlock and seccomp tests. The test runner must
allow ordinary socket creation and unprivileged user namespaces. Tool sandboxes and some CI hosts may
disable these facilities. Tests never invoke sudo or install a helper. Temporary-project tests cover cwd,
project writes and executable files, hidden siblings and read-only state for multiple scopes. Protection
fixtures run 58 mutation attempts in each of a normal directory, `/tmp` and `/var/tmp`: file content and
metadata, symlink metadata, rename-over and rename-exchange, file and ancestor removal, state writes, new
hard links and outside-process `/proc` aliases. They also check neighboring writes and protected execution.
Separate tests reject existing hard links, intermediate symlinks, an alternate bind mount, and
inherited standard descriptors that would bypass protection. Generated BPF branch bounds and invalid
launch inputs also have unit checks.

`zig build linux-probe` builds a standalone backend harness for receiver tests:

```sh
mkdir -p out/linux-probe
zig-out/bin/blackice-linux-probe 18780 out/linux-probe/receipts.local.jsonl -- COMMAND ARGUMENTS
```

This harness treats the supplied ports as controlled receivers; it is not a domain policy proxy. Use fresh
receipts and controlled destinations for each run. The broader regression matrix includes immediate/forked
execution, both UDP modes and families, direct DNS, daemon IPC, inherited sockets, cgroup migration,
SCTP/ping sockets, descendant cleanup and failure recovery.

After the reviewed helper is installed, the Python standard-library harness runs local receiver controls
and backend cases. It checks TCP, both UDP modes/families, SCTP, unconnected ping sockets, the ping
command, UDPLITE, MPTCP, helper re-entry, cgroup migration and double-forked descendants:

```sh
python3 src/linux/integration.py
python3 src/linux/integration.py --crash-tests
```

The optional crash cases send SIGKILL only to processes launched by that test, using pidfds. Killing the core
must terminate the scope; killing the helper must leave its surviving descendants filtered. That second case
leaves an empty cgroup on purpose, for the owner to remove with teardown. The run recorded in the evidence
entries above did not include the crash tests. Logs are stored under `out/`; the harness does not install
anything, run sudo or create an evidence entry. A missing helper is reported as blocked, never passed.

The build, unit and local integration tests do not replace the off-host receiver that P0-02 requires.

`python3 src/linux/evidence_check.py --help` describes the P0-01/P0-02 observation harness. It requires an
explicit installed-helper hash before invoking blackice and captures CLI output through pipes. A Python
receiver on a second machine runs over SSH; its log returns over that same connection, with no shared remote
log filename. IPv4/IPv6 TCP, UDP sendto and connected UDP controls must arrive before and after each scoped
sender, including a double-forked descendant. The harness checks kernel receipts as well as receiver silence,
saves raw observations in a fresh private `/tmp/bi-ev-*` directory, and never creates an evidence entry.
The summary omits the machine hostname and SSH command. Raw local logs remain private; public evidence
uses reviewed excerpts without hostnames, SSH login commands or private artifact paths.
`--controls-only` checks connectivity without executing blackice. Runs with a protocol v1 helper must pass
`--legacy-protected-paths`, and their evidence must list the missing file protection as a limit.

## Limits

The backend provides a network boundary and protection of the explicit trusted paths, not a general filesystem
or same-user sandbox. Filesystem triggers, other shared files, terminal output, and cooperation from an
unrelated outside process are not fully isolated. The state root and its ancestors are protected through their
mounted paths; pre-existing hard links to individual state files elsewhere are not scanned. An allowed endpoint
can receive any data the command sends it. Root resistance and arbitrary container or network namespaces are not
provided. Proxy port ownership, policy and grant authority, and model-relay authentication need their own
evidence.

Kernel references: [BPF UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/bpf.h),
[ring buffer](https://docs.kernel.org/bpf/ringbuf.html),
[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html),
[Landlock](https://docs.kernel.org/userspace-api/landlock.html),
[seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html) and
[openat2 path resolution](https://man7.org/linux/man-pages/man2/openat2.2.html).
