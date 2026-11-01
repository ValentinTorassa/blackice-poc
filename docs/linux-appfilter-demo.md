# Linux app-filter demo preparation

These policies and commands are preparation, not passing evidence. The app filter is **NOT READY for host use**:
run the service, its BPF programs and the installation only in a disposable VM. No demo run has been recorded.

Offline checks for these fixtures:

```sh
zig test src/linux_appfilter_demo_test.zig --test-filter 'appfilter demo'
python3 -I tools/test_linux_appfilter_probe.py
```

These parse policy files and exercise mocked socket failures. They do not execute the network, fork, service
or installation paths.

## Three applications

[`linux-apps-demo.json`](../examples/linux-apps-demo.json) lists actual executable files, not launch scripts,
desktop names, `argv[0]` or `comm`. These canonical root-owned files were found on the target Debian host by
read-only inspection; repeat that inspection after package updates. Close listed applications before arming.

| ID | Executable | Allowed HTTP(S) names | Example refusal |
|---|---|---|---|
| 1 | `/usr/lib/firefox-esr/firefox-esr` | `example.com`, `example.org` | `github.com`, `incoming.telemetry.mozilla.org` |
| 2 | `/usr/bin/wget` | `example.org` | `example.com` |
| 3 | `/usr/bin/curl` | `example.com` | `example.org` |

Use a new empty Firefox profile, without accounts, browsing history or extensions. The few allowed names are
deliberate: this is a small demonstration, not a usable general browsing policy. Other page dependencies,
updates, authentication services and CDNs may be refused. Allowlisting a name is not a guarantee that its
server, DNS or certificate is available.

Firefox's telemetry name is outside its allowlist; the current policy format has no domain-deny exceptions.
Mozilla identifies `incoming.telemetry.mozilla.org` as a telemetry endpoint in its
[source documentation](https://firefox-source-docs.mozilla.org/toolkit/components/telemetry/data/install-ping.html).
A manual navigation to that name proves a name-based refusal only if the corresponding receipt is present.
Label it **“manual request to a telemetry endpoint”**. It does not prove that Firefox attempted an automatic
telemetry upload, or that all telemetry is blocked. Do not turn on data collection or manufacture a telemetry
payload for the demo. If no automatic request is observed, record that result. Telemetry behavior varies by
build and settings; Mozilla documents those [controls](https://firefox-source-docs.mozilla.org/toolkit/components/telemetry/internals/preferences.html).

For the short take: show curl reaching `example.com` and refusing `example.org`, then wget reaching
`example.org` and refusing `example.com`. Open the fresh Firefox profile on an allowed page, navigate to a
refused name, and show actual `app_filter` receipts with different `app_id` and `executable` fields. Do not use
`blackice run`, explicit proxy variables or an existing browser instance for this shot: the intended claim is
automatic classification of a newly executed listed file, independent of a task scope.

## What identity evidence can establish

| Change | Intended behavior; confirm in the installed run |
|---|---|
| Change `argv[0]`, `comm`, desktop entry or path spelling | Does not change the executable inode used for classification. |
| Rename the same listed file or use a hard link to its inode | Device and inode stay the same, so identity stays the same. Do not rename system binaries for the demo. |
| Fork, double-fork or exec a different executable from a tagged process | The first listed identity persists in descendants, even through a UID change. |
| Copy a listed binary to a new inode and launch it from an unlisted process | The copy is unlisted. This is a coverage limit, not publisher/code-signing identity. |
| Execute that copy from an already tagged parent | Inherits the parent's restriction; copying does not clear an existing tag. |
| Root replaces a package file with a new inode | Inotify adds it; the interval before refresh, especially during service downtime, is not covered. |

No blanket “renaming or copying cannot bypass it” claim is supported. New tags use the configured owner's real
UID. A listed application can delegate work through unlisted helpers, portals, D-Bus or received sockets; see
the [full limits](linux-appfilter.md#limits-to-review-before-installation).

## Evidence fixture

[`linux-apps-evidence.json`](../examples/linux-apps-evidence.json) temporarily substitutes `/usr/bin/setsid`
for Firefox. A fresh `setsid --fork --wait python3 -I ...` should retain app ID 1 through exec and descendants,
without listing the system Python interpreter and restricting unrelated Python processes. This policy affects
every new invocation of that setsid executable by the configured owner while active; keep this phase brief
and isolated from other work. Switch policies only through authorized `app off`, then a fresh `app on`.

[`linux-appfilter-probe.py`](../scripts/e2e/linux-appfilter-probe.py) prepares synthetic TCP/UDP IPv4/IPv6,
mapped-IPv6, protocol-creation and double-fork checks. Every runtime mode requires an explicit runtime-test
flag, the exact guest hostname through `--vm-hostname`, QEMU DMI, and a non-root UID. The guard runs before
barriers, forks or sockets; these probes are for the disposable VM, never the host. Their network and fork
paths have not been executed during preparation. Error codes alone are insufficient: correlate them with
kernel receipts and controls at a separate receiver inside the VM's test network. The receiver logs no peer addresses.

### Protocol controls for the VM run

This phase uses the evidence policy's listed launcher, not the two-app recording policy. Do it only in the
disposable VM's kernel run, without changing the policy during a recording. The first probe must come
from an untagged process, with the same UID, capabilities and namespaces as the tagged probe. Retain that
context with the logs. An unprivileged `raw4` failure is normally a control limit, not filter evidence.

Inside the named VM, with `E` set to a fresh evidence directory and `VM_HOSTNAME` to its confirmed hostname:

```sh
python3 -I scripts/e2e/linux-appfilter-probe.py protocols --authorized-network-test \
  --vm-hostname "$VM_HOSTNAME" --expect control --phase untagged > "$E/protocol-control.jsonl"
/usr/bin/setsid --fork --wait python3 -I scripts/e2e/linux-appfilter-probe.py protocols \
  --authorized-network-test --vm-hostname "$VM_HOSTNAME" --expect deny --phase tagged \
  --control-log "$E/protocol-control.jsonl" > "$E/protocol-tagged.jsonl"
```

The deny probe requires a complete control log. It reports `PASS` only when the untagged socket opened and
the tagged socket returns `EPERM`/`EACCES`; receipts still establish the enforcement point. If the untagged
socket was already refused or unsupported, the case is `LIMIT`, with `passed: null`, even when the tagged
socket also fails. An opened tagged socket or unrelated error is a failure. Summaries separate passed,
limited and failed cases. Exit 0 means at least one comparable case passed and none failed; it does not
turn limited cases into passes. Exit 2 means there were no usable controls. Keep unsupported protocols and
control failures visible in the report, and capture command exit statuses separately from the JSONL.

### Kernel cases for the VM run

The emitted-program unit test already covers every tag, port 760–774, and nine local/unspecified address
forms for both the root and user guards. It is not a kernel runtime result. The VM harness for the runtime
cases below is not in this repository. Do not run another installer or policy sequence in the same guest at
the same time. Each row stays a requirement until the logs of an actual run have been checked.

| Area | Kernel cases and required controls |
|---|---|
| Listener ports | Untagged and tagged connects to every port 760–773, plus reserved 774, using `0.0.0.0`, `::`, `::ffff:0.0.0.0` and ordinary loopback spellings. Other apps' ports must refuse; tagged access may reach only its own listeners. Establish the caller's tag separately so a universal refusal cannot prove identity. |
| Listener guard outside `user.slice` | Repeat the listener guard through cron, at, system services and another UID; retain each caller's cgroup. The cgroup-root guards must cover callers outside `user.slice`. |
| Inbound traffic | Tagged listeners on `0.0.0.0`, `::`, and an autobound port accept nothing from a veth peer namespace. Equivalent untagged listeners must accept the control. Accepted tagged sockets retain `lo`. |
| Device selection | Tagged TCP/UDP sockets begin on `lo`; changing or clearing `SO_BINDTODEVICE`/`SO_BINDTOIFINDEX` refuses. `IP_PKTINFO`/`IPV6_PKTINFO` selecting the veth must deliver no tagged payload; the receiver must first observe an untagged control token. |
| IPv6 routing headers | An untagged IPv6 type-4 routing header reaches the first hop. Tagged SRH connects on 443, 80 and a disallowed port fail and no tagged packet arrives. Preserve the receiver log, not only the client's errno. |
| Regressions | Stub DNS at `127.0.0.53` and its mapped spelling still answers; tagged HTTP/TLS redirects over v4/v6/mapped still work. Record receipts for allowed and refused requests. |

Arming-phase recovery has only a userspace model test. Real crash/restart, kill-then-fork and
kill-at-each-arming-phase checks are still required before host use; this demo preparation does not mark them
passed.
