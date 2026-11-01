# Linux app-filter pseudo-file audit and teardown regression checks

The [Linux app filter](linux-appfilter.md) is **NOT READY for host use**. These are offline checks; they do not
show that it runs.

The service reads the kernel release with `std.posix.uname()`, not from procfs. The service unit
also sets `LockPersonality=yes`; the independent BTF SHA-256 check remains the kernel identity check.

## Procfs and sysfs reads

Audit of the service, CLI, Linux task backend and explicit test fixtures:

| Input | Read method and failure behavior |
|---|---|
| Kernel release | `uname()`, compared with the pinned release; no procfs file-size assumption. |
| `/sys/kernel/btf/vmlinux` | Bounded `readFileAlloc` (16 MiB), then SHA-256 verification. This binary sysfs attribute reports its actual size on the pinned Debian kernel: a read-only metadata check returned 4,952,870 bytes. An empty or different value fails the BTF hash check. |
| `/proc/sys/net/ipv4/ip_unprivileged_port_start` | `open` plus direct `read` into 32 bytes. Empty/invalid input is `InvalidPortFloor`; an insufficient floor also refuses. |
| `/proc/sys/kernel/random/boot_id` | `open` plus direct `read` into 64 bytes. UUID length and syntax are checked; empty/short input refuses. |
| `/proc/self/stat` for the tty agent | Direct `read` into 4096 bytes; a full buffer is rejected. Empty/invalid PID or start-time data refuses agent setup. |
| `/proc/self/task` | `getdents64` with record bounds checked. Capability drop requires exactly the expected single thread. |
| `/proc/self/fd/<owned fd>` for executable headers | Reopens the pinned regular file and directly reads at most four bytes. Device/inode are checked against the original FD; no reported file size is used. |
| Task-scope uid/gid maps, cgroup files and mount information | Bounded direct reads; namespace links use `readlink`. Cgroup filesystem checks use `statfs`, not file contents. The task helper is unchanged by this audit. |
| VM socket fixture: DMI vendor and `/proc/net/tcp{,6}` | Direct reads; the TCP-table reader is bounded. No socket fixture was run during this audit. |
| Python BTF/probe/evidence tools | Python file reads consume the stream. They do not use Zig's size-based allocation behavior. Runtime probes retain their explicit execution guards. |

The app filter's other `readFileAlloc` calls read ordinary policy, intent or unit-test files. A caller
supplying an empty pseudo-file as a CLI policy gets a parse refusal. No additional zero-size procfs
allocation bug was found. These are source and metadata checks, not a host installation preflight or
evidence that the service has run.

## Teardown interruptions

Teardown checks for unknown configuration entries before cleanup and retains `owner.json` until
runtime cleanup and account/group deletion finish. A policy left beside the marker
therefore refuses before teardown changes anything. Keep demo policies outside that configuration
directory; teardown preserves unexpected files for the owner to inspect.

Run the offline regression suite as a normal user:

```sh
python3 -I tools/test_linux_appfilter_teardown.py
```

The test executes a temporary copy of the production Bash body. Its root-only guard is changed to the
test UID, all data paths point into a temporary directory, and every external command is replaced by
an explicit mock. New command paths make the fixture refuse until a safe mock is supplied. The embedded
Python preflight/check/archive code runs against those temporary files with mocked account lookup and
ownership changes. The production script, real systemd, accounts, mounts and BPF are never invoked.

The suite checks:

- An extra configuration file refuses before any cleanup and is retained.
- Complete teardown and a second invocation finish, preserving receipt contents.
- Injected failures before/after the helper, after runtime-file removal, during runtime-directory removal,
  and before account or group deletion preserve the marker; rerunning finishes.
- Interruption after removing the marker still finishes because accounts were already removed.
- Missing teardown binary with retained pins refuses without deleting accounts or the marker.
- An unrecorded service account is never deleted.

This tests script control flow and interruption recovery with mocks. Real detach, systemd and
privileged ownership behavior still need a run in a disposable VM.

## UDP-connect receipts

The kernel receipts distinguish UDP `connect()` refusals as `udp_connect`, aggregated by
application and family with counts and first/last kernel timestamps. UDP sendmsg refusals retain `udp`.
Both remain refused except for the allowed DNS stub. This distinguishes glibc address-sorting probes
from an HTTP/TLS policy decision without allowing connected UDP to bypass sendmsg hooks. The full
receipts remain evidence; a recording may explicitly display only `event == "connect"` decisions.
