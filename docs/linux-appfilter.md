# Linux application filter (experimental)

**Status: NOT READY for host use.** This is experimental code: run it only in a disposable VM. It has not been
installed on a host or tested there with real application traffic, and VM runs of earlier commits do not
validate the current code. CI runs its userspace unit tests and cross-compiles it; nothing there loads BPF.
The task-scope helper does not use this code, and the filter is not part of the 0.1.0 release.

This filter routes ordinary applications' HTTP(S) through policy; the allowed DNS stub and delegation paths
mean it is not containment for an application deliberately trying to escape.

The initial target is Debian 13, `6.12.113+deb13-amd64`, x86-64 baseline. Startup checks the exact release and
SHA-256 of `/sys/kernel/btf/vmlinux`:
`5727b13fd2212290ae031719c9367251c0c8eda0a3f48181af71452ccf5f8943`.
A mismatch refuses arming; a refused start does not mean applications are filtered.

Build and userspace tests:

```sh
zig build linux-appfilter linux-appfilter-test
scripts/linux-build-appfilter.sh
```

The second command prints hashes for the stripped static `blackice-linux-appfilter` binary and its deterministic
installation bundle. Neither command installs anything. Do not run setup, `app on` or the service outside a
disposable VM. Host use first needs a security review of the exact commit, bundle, scripts and kernel-load plan.

Once installed in a VM, the CLI flow is `blackice app on --policy APPS.json`, `blackice app status`, and
owner-authorized `blackice app off`. `blackice app reload --policy APPS.json` replaces the armed policy in place;
it is experimental as well, see [live policy reload](linux-appfilter-live-policy.md). A sample policy is
[`examples/linux-apps.json`](../examples/linux-apps.json); close listed applications before arming.
These commands have not been run on a host.

## Identity and decisions

Three `tp_btf` programs tag an exec by its kernel `(device, inode)`, copy its tag at every fork, and clear it
only when the thread group dies. A 4,194,304-slot array covers every possible initial-namespace tgid; fork writes
zero too, preventing PID reuse from keeping an old tag. The first listed application remains the identity across
reexec and detached descendants. Only the authenticated owner's real UID acquires a new listed identity.

Five legacy cgroup programs attach at `/sys/fs/cgroup/user.slice`: connect4/6, UDP sendmsg4/6, and INET socket
creation. This attach point includes other users' sessions, not just `user-<uid>.slice`: their socket operations
also run these programs. New executable tags are assigned only for the configured owner's real UID; existing
tags remain inherited across UID changes. Two additional listener-only connect programs attach at the cgroup
root, `/sys/fs/cgroup`, with ALLOW_MULTI. They restrict the reserved local listener ports across all cgroups,
including other users, cron/at jobs and system services; they do not redirect other traffic outside `user.slice`.
Listed TCP 80/443 goes to the application's HTTP/TLS loopback listeners. IPv4, native IPv6 and mapped
IPv6 are handled explicitly. Other TCP ports, non-stub UDP, QUIC, raw INET sockets, ICMP/ping, SCTP, UDPLite and
MPTCP are refused. UDP DNS to `127.0.0.53:53`, including its mapped IPv6 spelling, is allowed. TCP DNS is refused.
Unlisted processes retain their network access, except that loopback listener ports require the matching app tag.
Tagged INET sockets are bound to the loopback interface at creation. Accepted sockets inherit this binding;
the intended effect is to block inbound LAN traffic and routing-header/device-selection detours. These effects
still need kernel tests in a VM, including UDP stub DNS and both proxy redirects.

Each app has HTTP and TLS ports in 760–773, with port 774 reserved. Both `127.0.0.1` and `::1` are bound; there
are no wildcard listeners. Arming reserves the entire 760–774 range and refuses any collision. The service checks
that `ip_unprivileged_port_start` is greater than 774 before binding. The connect hooks treat 127/8, 0/8, ::1,
::, and mapped IPv4 equivalents as local for `listener_peer` checks. The unspecified-address cases matter
because Linux can route them to loopback after the connect hook.

The proxy checks exactly one TLS ClientHello SNI, or one HTTP Host header in an origin-form request. It resolves
and dials that name using the existing policy and resolved-address checks, not the original destination IP.
Duplicate SNI, malformed/fragmented ClientHello, missing names, CONNECT on a transparent listener, ambiguous
HTTP Host and IP literal routing are refused. ECH is decided by the outer name. TLS contents are not inspected.

Receipts use the existing JSONL writer, with `point: app_filter`, `app_id` and `executable`. Kernel refusals go
through a ring buffer; overflow increments a counter and is reported as `receipt_loss`. Files are service-owned,
mode 0640 under a service-owned 2750 directory whose group can read but cannot change them. Queued kernel
receipts retain the event's monotonic nanoseconds in `detail`; `ts` is the writer's drain time.
Glibc can probe resolved addresses with UDP `connect()` while sorting them. Non-stub probes still fail;
`udp_connect` receipts aggregate counts by app and address family over approximately one second, with the
first and last kernel timestamps. They are not successful DNS or data connections.

Each log stops growing at 8 MiB. Failed writes and lines refused by that ceiling count in `app status`
(`write_dropped`); ring overflow appears separately as `ring_dropped`. The service attempts a `receipt_loss`
line when write loss changes, but that line can also fail, so status is authoritative for the running instance.
Proxy and kernel records use separate files with one writer per file. There is **no automatic rotation or
aggregate disk limit across restarts** yet: old files are retained. Write-drop counters reset on service
restart, and a crash can lose unflushed UDP aggregates. Do not claim complete receipts across those gaps.

## Service and recovery

The root-installed executable has **no file capabilities**. A dedicated system user receives BPF, PERFMON,
NET_ADMIN and NET_BIND_SERVICE through its unit. A separate root bootstrap unit mounts only the fixed private
bpffs. It runs outside the daemon's private mount namespace, so pins survive daemon restarts. The daemon uses
NoNewPrivileges, non-dumpability, read-only system/home views and a private temporary directory.

Arming pins maps and its phase, legacy-attaches the socket programs, reserves listeners, pins exit/fork/exec
links in that order, and runs a kernel task iterator. Already-running listed files without tags make arming
fail. Only after this does it persist `armed`, drop load capabilities and acknowledge the caller. A restart rolls
back an incomplete phase; an armed restart reopens pins, verifies program tags, referenced map IDs/layouts and
cgroup attachments, refreshes file identities, binds listeners and drains queued receipts. Pinned links keep
classification running during a service crash. Pinned legacy program handles permit exact detach at authorized
off without replacing another program.

BPF, PERFMON and NET_BIND_SERVICE are removed after binding and loading. The loader keeps NET_ADMIN in its
permitted set only, raises it to effective only for exact detach, and restores the previous effective set.
It verifies that it has only one thread before forking a separate proxy child. That child has zero effective,
permitted, inheritable and ambient capabilities; it retains only its listener sockets, its own receipt FDs,
stdout/stderr and a startup pipe. All loader, BPF, cgroup, control and instance-lock FDs are closed, and the
inherited ring mapping is unmapped. The startup pipe closes before traffic is acknowledged as armed.

Before creating proxy threads, the child applies Landlock ABI 6 to deny future filesystem writes and scope
signals/abstract Unix sockets. Its seccomp policy refuses BPF, ptrace, foreign-FD access, namespace operations,
exec, non-thread forks, filesystem metadata changes and Unix socket creation. Preopened receipts remain
writable. The loader monitors its pidfd; child failure exits the service with pinned filtering retained.
Parent death kills the child. These boundaries still need VM checks. The bounding set retains
the unit's four caps; cleared permitted/inheritable/ambient sets plus NoNewPrivileges prevent reacquisition.

All four listeners for an app share a 16-connection budget. A request has five seconds for its HTTP head or
TLS ClientHello, before any upstream dial. Overload closes the new connection without a blocking reply.
FD exhaustion pauses accepting, and a polkit exchange has one 15-second read budget. Policies are limited to
32 JSON nesting levels before parsing/stringification. The service uses LimitNOFILE=8192 and TasksMax=1024.

The control socket is systemd-owned. SO_PEERCRED plus SO_PEERPIDFD identify the configured non-root owner;
requests cannot supply a PID, UID, cgroup, program, map FD or BTF. Tagged callers are refused before polkit.
Off uses the peer pidfd over D-Bus/SCM_RIGHTS with an `auth_admin` action, without retained authorization or a
PID-number fallback. A dead peer or failed/ambiguous response refuses the operation.

For `app off` with a terminal on stdin, the unprivileged CLI starts `/usr/bin/pkttyagent` with its own PID
and process start time, waits for registration, and uses `--fallback` so an existing agent is not replaced.
The agent owns any password prompt; passwords never enter blackice's control messages or receipts. It is
terminated and reaped when the request ends, and the terminal mode is restored. Without a tty, the CLI does
not start an agent; authorization still requires an existing session agent. Registration failure, denial,
cancel or the daemon's 15-second authorization timeout leave the filter armed. This follows the
[pkttyagent contract](https://www.freedesktop.org/software/polkit/docs/latest/pkttyagent.1.html); real approve,
wrong-password, Ctrl-C and timeout cases remain VM tests. Answer the prompt promptly; on timeout,
run `app off` again.

`app on` refuses a different policy while armed. To change it, use `app reload` (experimental, VM only; see
[live policy reload](linux-appfilter-live-policy.md)), or an authorized `off` followed by a fresh `on`. Neither
reassigns the app IDs that running descendants already hold.

An acknowledged arm persists its policy digest and boot ID in an atomically replaced, fsynced intent file.
Pins still disappear on reboot: **this build does not automatically re-arm before user sessions**. Until
the owner re-arms, status says `disarmed_by_reboot`; missing pins during the same boot say
`disarmed_pins_missing`. Rearming another policy first requires authorized `off`, even after reboot.
A partially completed off reports `stopping_partial` and retains its stopping phase until cleanup succeeds.

The loopback listeners set `SO_REUSEADDR` before binding so a restart can reuse a port whose earlier
connections remain in `TIME_WAIT`. They do not enable `SO_REUSEPORT`: an existing live listener must still
make arming or recovery refuse. The dedicated IPv4/IPv6 socket test checks the options, observes server-side
`TIME_WAIT`, rebinds immediately and rejects a competing live listener. It is compiled separately from the
pure unit suite and runs only in a disposable QEMU VM; the full crash/restart check still needs a VM run.

The service restarts after a failure with a backoff, from 1 s up to 60 s over five steps, and keeps the pins while
it is down. The start limit (60 starts in 10 minutes) is only a backstop: while the filter is off, every control
request starts the service once, so a low limit would stop the socket. The pinned programs remain attached
if that limit is reached.

## Limits to review before installation

- Fresh arming requires the five user.slice hooks and the two root connect hooks to be vacant. Restart also
  requires exactly the pinned program IDs, with no foreign additions. It refuses an unknown program ID:
  Linux 6.12 requires SYS_ADMIN to open arbitrary program IDs for name inspection, and the service intentionally
  lacks that capability. ALLOW_MULTI is used, but this build does not yet accept pre-existing systemd programs
  at the same points. A root preflight on the target machine shows whether this limit applies there.
- Policy executable paths must be canonical, root-owned regular executable files with root-owned, non-writable
  ancestors, on ext4 or xfs. Other filesystems, including btrfs and overlayfs, refuse arming because their
  statx device identity may differ from the kernel inode's superblock device. Errors name the executable.
  Symlinks and home-directory applications are refused. List the resolved installed binary.
- Only readable ELF executables may be listed. The service reads a four-byte prefix from the same pinned
  inode used for identity: `#!` files refuse with `ScriptExecutableUnsupported`; empty, truncated and other
  formats refuse with `UnsupportedExecutableFormat`. An unreadable file also refuses. Initial `on` validates
  every file before creating kernel objects, and identity refresh repeats this check. The refusal receipt
  names the executable. List the native binary behind a launcher script (for example Debian's Firefox wrapper),
  not the script or a general interpreter. File identity is not code integrity or a publisher signature;
  this prefix check does not validate the complete ELF or its contents. AppImages are unsupported.
- Inotify adds replacement file identities and retains old entries. A launch before a replacement is noticed,
  including while the service is down, is not tagged. A descendant already started before arming and now running
  another file is not discoverable by the task iterator. Processes an app started before arming are not covered.
  New directory watches are installed before refreshing identities, so a concurrent replacement stays queued.
  Retained old inode numbers can be reused by the filesystem and falsely tag an unrelated executable;
  this build does not yet include inode generation in its key.
- DNS through the stub is a full two-way data channel. Unix sockets, delegated work through D-Bus/systemd/portals
  or cron/at, rootless containers relayed by pasta/slirp4netns (including raw AF_PACKET traffic),
  sockets connected before arming and sockets inherited or received from an unlisted process are not fully
  contained. Connected sockets, protocols without these connect/sendmsg hooks, and sockets created outside
  user.slice can bypass the checks on later use.
- Clipboard/session-socket access is not blocked by this app filter and has not been tested with real data.
- Root and other privileged software are outside the application's trust boundary. Other users' sessions
  traverse the hooks and reserved-listener peer checks, but acquire no new executable tags for this owner's
  policy. The root guard restricts reserved listener access from system services too; it does not make the
  broader application policy cover network sockets created outside `user.slice`.
- IO_uring identity attribution, kernel verifier acceptance, post-capability-drop map updates, crash recovery,
  polkit interaction, protected-port rebinding and application traffic all still need an installed VM run.
  Restart receipts report lost events; exact downtime is not measured and is labeled unknown.
- The retained executable-identity map has 4096 entries. Exhaustion refuses an update and stops the service;
  existing pinned identities remain restricted. A newly replaced file in that failure window is not covered.

## Before installation, and sources

Before any host installation, the setup, teardown, bootstrap, unit and polkit files and two reproducible builds
need a security review. Installing adds a dedicated system user and service, and may need the `bpftool` package.
Setup never installs packages or changes sysctls, nftables or sudoers. Its root-owned staged bundle and binary
must match the hashes passed to setup before any file is installed. Teardown stops socket activation, detaches
only pinned handles, unpins/unmounts and removes the service; receipts/policies are retained under a root-only
directory. Reinstallation refuses that archive until the owner moves it aside; setup never adopts or erases
preserved evidence.
Teardown names unexpected configuration entries before changing anything and keeps owner.json until runtime
cleanup and account deletion complete. Retained evidence entries become root:root without following symlinks;
the archive directory's setgid bit is explicitly cleared.

Before installation, record the existing cgroup programs, program list, nft ruleset, bpffs, groups, protected
hardlinks/BPF/Yama/port sysctls and listeners in 760–774. Do not conflate this record with a passing load.
The [pseudo-file audit and offline teardown checks](linux-appfilter-validation.md) document the kernel-release
read fix and the mocked interruption tests; they do not replace the installed VM run.

Implementation references: Linux 6.12 [`do_exit`](https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c)
decrements `signal->live` before the exit tracepoint; [`bpf_prog_calc_tag`](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/core.c)
normalizes map-FD immediates before hashing; [`BPF syscalls`](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/syscall.c)
define link and ID-access behavior. Polkit 126's
[subject decoding](https://github.com/polkit-org/polkit/blob/126/src/polkit/polkitsubject.c) accepts the passed pidfd
and UID without the legacy PID/start-time fallback used by older clients.

The [demo preparation](linux-appfilter-demo.md) supplies three executable policies, an evidence fixture and
the claims that a future recorded run could support. It contains no passing app-filter evidence.
