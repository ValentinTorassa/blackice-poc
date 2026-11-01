# P0-05: a grant's expiry cuts the live connection and refuses new ones (Linux: Debian 13, kernel 6.12)

**Claim.** On the Linux host below, when an owner grant ends, the proxy resets the connection opened under
it. The stream stops at the proxy at the expiry, and a new connection to the same name is refused again.
Checkpoint P0-05.

**Platform.** Debian GNU/Linux 13 (trixie), Linux 6.12.113+deb13-amd64, x86_64.
- Unified cgroup v2 and Landlock ABI 6.
- AppArmor is enabled, but this kernel has no unprivileged user-namespace restriction:
  `kernel.apparmor_restrict_unprivileged_userns` does not exist, and `kernel.unprivileged_userns_clone` is 1.

**Build.** The same launcher, helper and scripts as the P0-03 Linux entry.
- Launcher: `020f389`, `zig build release` with Zig 0.17.0. Binary `blackice-x86_64-linux`, sha256
  `b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762`.
- Helper: built from `7c3bcff`, sha256 `515ebfacc545e1a2ca4f66190630aae2f8ff09b68f2575a2bcf11ea7698aadbd`,
  installed by the owner.
- Scripts: `scripts/e2e/` as on main, byte-identical to `7cc5697`.

Both hashes were checked before the run, and the run prints the launcher's sha256 too.

**Policy.** `agent.json`, sha256 `b28c9f29dbeafbf9ae0fa9163a3affaefbc997aaedc19c23b3d20bf1dc662760` (policy
id `b28c9f29dbea`): allow list with `example.com` and `registry.npmjs.org`, the same file as P0-03 and P0-04.
httpbingo.org is not on it.

**Run.**

```sh
BLACKICE=/path/to/blackice-x86_64-linux bash scripts/e2e/grant-expiry.sh
```

One scope runs the bash script `INNER` from `scripts/e2e/grant-expiry.sh`. It waits on its standard input for
the owner's go-ahead. The owner, the script itself outside the scope, then grants httpbingo.org for 20 s.

The stream is server-paced. httpbingo.org's `/drip` sends its bytes evenly over the time asked for, and curl
`-N` reads each one as it arrives, so nothing waits unread on the client side. `/drip` allows at most 10 s per
request, so curl asks for six in a row on one connection: 6000 bytes over 60 s.

**Result.** 11 checks passed, 0 failed. Enforcement point: the scope's proxy.

Owner and scope output, verbatim (the script's indentation removed):

```
outside: 13:31:47Z $ blackice grant s-6cad3589 httpbingo.org --for 20s
granted httpbingo.org to scope s-6cad3589 until 2026-10-30T13:32:07.985Z
outside: grant exit 0
```

```
inside: 13:31:47Z waiting for the owner grant
inside: 13:31:47Z httpbingo.org right after the grant -> 200/200
inside: 13:31:48Z stream: six 10 s drips of 1000 bytes on one connection (100 bytes/s for 60 s); bytes so far, every 2 s:
  sample 13:31:48Z 0 bytes
  sample 13:31:50Z 161 bytes
  sample 13:31:52Z 361 bytes
  sample 13:31:54Z 561 bytes
  sample 13:31:56Z 761 bytes
  sample 13:31:58Z 962 bytes
  sample 13:32:00Z 1142 bytes
  sample 13:32:02Z 1342 bytes
  sample 13:32:04Z 1542 bytes
  sample 13:32:06Z 1743 bytes
inside: 13:32:08Z stream curl exit 56 after 1867 bytes in 20 s: curl: (56) OpenSSL SSL_read: OpenSSL/3.5.7: error:0A000126:SSL routines::unexpected eof while reading, errno 0
  [transfer done: HTTP 200, new connections 1]
  [transfer done: HTTP 200, new connections 0]
inside: 13:32:08Z httpbingo.org again, a new connection -> 403/000
blackice: scope s-6cad3589 ended with status 0; 9 receipts
```

Summary:
- The grant ran until 13:32:07.985. The `grant_expired` / `connection_reset` receipt has the same timestamp,
  to the millisecond.
- The stream had delivered 1867 of its 6000 bytes in 20 s: the first drip in full, and part of the second.
  Then curl failed with exit 56.
- A new connection right after was refused (`no_matching_rule`): the name is outside the policy again.

**Receipts.** Verbatim. The first scope is the script's `/usr/bin/true` probe:

```
{"ts":"2026-10-30T13:31:47.685Z","scope":"s-cffb7d02","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command true; proxy port 43265; 2 protected files"}
{"ts":"2026-10-30T13:31:47.714Z","scope":"s-cffb7d02","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:47.715Z","scope":"s-cffb7d02","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:47.715Z","scope":"s-cffb7d02","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:47.726Z","scope":"s-6cad3589","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command bash; proxy port 57387; 2 protected files"}
{"ts":"2026-10-30T13:31:47.729Z","scope":"s-6cad3589","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:47.985Z","scope":"s-6cad3589","policy":"b28c9f29dbea","gen":1,"point":"control","event":"grant","verdict":"allow","reason":"owner_grant","rule":"httpbingo.org","host":"httpbingo.org","detail":"pid=723245 for 20s until 2026-10-30T13:32:07.985Z"}
{"ts":"2026-10-30T13:31:48.374Z","scope":"s-6cad3589","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"allow","reason":"granted","rule":"grant:httpbingo.org","host":"httpbingo.org","ip":"66.241.125.232","port":443,"detail":"sni_match grant_until=2026-10-30T13:32:07.985Z"}
{"ts":"2026-10-30T13:31:48.749Z","scope":"s-6cad3589","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"allow","reason":"granted","rule":"grant:httpbingo.org","host":"httpbingo.org","ip":"66.241.125.232","port":443,"detail":"sni_match grant_until=2026-10-30T13:32:07.985Z"}
{"ts":"2026-10-30T13:32:07.985Z","scope":"s-6cad3589","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"deny","reason":"grant_expired","host":"httpbingo.org","ip":"66.241.125.232","port":443,"detail":"connection_reset"}
{"ts":"2026-10-30T13:32:08.751Z","scope":"s-6cad3589","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"deny","reason":"no_matching_rule","host":"httpbingo.org","port":443}
{"ts":"2026-10-30T13:32:08.753Z","scope":"s-6cad3589","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:32:08.753Z","scope":"s-6cad3589","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

Two tunnels were allowed under the grant: the `/get` check and the stream. Only the stream was still open at
the expiry, and it is the one reset.

**Recording.** None for this run.

**Limits.**
- **Buffered bytes.** Bytes that reach the client's socket buffer before the expiry stay readable after it,
  and no action by the proxy can take them back. Here the client read as the bytes arrived. A slow reader
  could still read some after the cut, as the macOS entry measured. The cut is at the proxy, not at the moment
  the client reads.
- **How curl reports the cut.** It reports an end of stream without TLS close_notify (exit 56, "unexpected
  eof"), not a reset error. The proxy's shutdown sends a FIN before its linger-0 close resets, and curl reads
  the FIN first. The receipt's `connection_reset` describes what the proxy does.
- **Proxy queue.** This run does not show a non-empty proxy queue being dropped. That is covered by the
  proxy's unit test with a flooding upstream.
- **Watchdog timing.** The watchdog wakes at least every 200 ms. Here its receipt has the grant's end time to
  the millisecond.
- **Not shown here.** Revoking a grant is in the P0-04 Linux entry. A plain HTTP exchange cut by an expiry is
  covered by the proxy's unit tests. Neither is shown in this run.
- **The host.** This entry covers only this host. On Ubuntu 24.04 and later, where
  `kernel.apparmor_restrict_unprivileged_userns=1` is the default, a scope is expected to fail closed before
  the command starts (not tested on Ubuntu).
- **httpbingo.org.** It is a public test service. Its `/drip` endpoint paced the stream.
- **The run.** One run, by the people building blackice, on the owner's machine. Not a recording.

**Date.** 2026-10-30, 13:31 UTC.
