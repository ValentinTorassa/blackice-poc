# P0-02: Linux kernel denial with an off-host receiver

**Claim:** P0-02 — the tested Linux cgroup BPF hooks refused direct TCP and UDP attempts over IPv4 and IPv6 from both an immediate child and a double-forked descendant, with matching kernel receipts and zero scoped arrivals at a separately reachable Mac receiver.

**Platform:** Debian GNU/Linux 13.7 (trixie), kernel `6.12.113+deb13-amd64`, x86_64; kernel build `#1 SMP PREEMPT_DYNAMIC Debian 6.12.113-1 (2026-10-15)`. This host has no Ubuntu AppArmor user-namespace restriction: `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` is absent. AppArmor itself is enabled, and the launching session is `unconfined`.

A read-only platform check after the run confirmed `VERSION_ID="13"` and `DEBIAN_VERSION_FULL=13.7` in `/etc/os-release`, the absent restriction knob, `Y` in `/sys/module/apparmor/parameters/enabled`, and `unconfined` in `/proc/self/attr/current`. No host policy was changed. These details qualify the Debian result; they do not establish Ubuntu compatibility.

**Build:** Zig `0.17.0`; frozen launcher and [harness](https://github.com/ValentinTorassa/blackice/blob/020f3892374c89a4bf0be722767ccd4d366cd5ca/src/linux/evidence_check.py) from `020f3892374c89a4bf0be722767ccd4d366cd5ca`; installed helper from `7c3bcff45dcdb122149b1a4ace282d0d749f9f53`.

| Artifact | SHA-256 |
| --- | --- |
| Launcher | `b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762` |
| Installed helper | `515ebfacc545e1a2ca4f66190630aae2f8ff09b68f2575a2bcf11ea7698aadbd` |
| Frozen harness | `daa07f757e12f5abc0bdf3b362f3e4cf033851a8788eac4965407c95d40c9962` |

The installed helper's hash, root ownership, mode 0750 and exact `cap_chown,cap_dac_override,cap_net_admin,cap_bpf=ep` capabilities were checked read-only before execution. The CLI snapshot remains fetchable as `codex/linux-demo-020f389`. The helper is the reviewed successor to the two failed startup builds, not the original helper listed in the frozen CLI's creation-time manifest.

**Policy:** `deny.json`, exactly the following line plus its final newline:

```json
{"version":"blackice.policy/v0","network":{"mode":"deny-all"}}
```

Policy SHA-256: `0190ed20090854c97dd032ead0c5bc775df9d9af65039e0efc26fb50df697438`.

**Run:** the following invocation produced both Linux entries in one run. Only local artifact paths, receiver addresses and the SSH login command are parameterized for privacy. `FROZEN` names the unchanged `out/demo-v2-020f389` snapshot; `SSH_MAC` is the trusted SSH connection to the off-host receiver. The harness starts `/usr/bin/python3 -I` remotely and opens no Mac applications.

```sh
/usr/bin/python3 -I "$FROZEN/evidence_check.py" \
  --blackice "$FROZEN/blackice" \
  --blackice-sha256 b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762 \
  --commit 020f3892374c89a4bf0be722767ccd4d366cd5ca \
  --helper-sha256 515ebfacc545e1a2ca4f66190630aae2f8ff09b68f2575a2bcf11ea7698aadbd \
  --ssh-command "$SSH_MAC" --v4 "$RECEIVER_V4" --v6 "$RECEIVER_V6"
```

The receiver bound TCP4 port 47121, TCP6 port 47122, UDP4 port 47123 and UDP6 port 47124. IPv4 used the LAN; IPv6 used the Tailscale IPv6 route. For each of `immediate` and `descendant`, the harness sent six unconfined positive controls, ran the scoped sender, observed for another second, then sent the same six positive controls again. Each payload carried a unique run nonce, phase and case name.

The two scoped invocations, with cwd `$WORK` and `XDG_STATE_HOME="$WORK/state"`, were:

```sh
"$FROZEN/blackice" run --policy "$WORK/deny.json" -- \
  /usr/bin/python3 -I "$WORK/worker.py" immediate "$RECEIVER_V4" "$RECEIVER_V6" \
  d340bbf6d0804968a9b24b5ff95807e8-scoped-immediate
"$FROZEN/blackice" run --policy "$WORK/deny.json" -- \
  /usr/bin/python3 -I "$WORK/worker.py" descendant "$RECEIVER_V4" "$RECEIVER_V6" \
  d340bbf6d0804968a9b24b5ff95807e8-scoped-descendant
```

`descendant` forks, calls `setsid()`, forks again, and performs the same socket operations in the grandchild. Its original parent waits for a completion byte. The exact worker and receiver source are embedded in the linked frozen harness.

**Result:** harness summary `CHECKS PASS`. Both scopes exited 0 after all expected refusals. All twelve socket operations returned errno 1 (`EPERM`); no timeout was counted as denial. Every corresponding receipt has `point: kernel`, `event: kernel_drop`, `verdict: deny`, and `reason: loopback_proxy_only`.

| Operation | Port | Immediate | Double-forked descendant | Control arrivals before/after each phase | Scoped arrivals |
| --- | ---: | --- | --- | --- | ---: |
| TCP IPv4 `connect` | 47121 | EPERM, hook 10 | EPERM, hook 10 | 1 / 1 in each phase | 0 |
| TCP IPv6 `connect` | 47122 | EPERM, hook 11 | EPERM, hook 11 | 1 / 1 in each phase | 0 |
| UDP IPv4 unconnected `sendto` | 47123 | EPERM, hook 14 | EPERM, hook 14 | 1 / 1 in each phase | 0 |
| UDP IPv6 unconnected `sendto` | 47124 | EPERM, hook 15 | EPERM, hook 15 | 1 / 1 in each phase | 0 |
| UDP IPv4 `connect` | 47123 | EPERM, hook 10 | EPERM, hook 10 | 1 / 1 in each phase | 0 |
| UDP IPv6 `connect` | 47124 | EPERM, hook 11 | EPERM, hook 11 | 1 / 1 in each phase | 0 |

Immediate PID `710575` reported `0::/blackice/s-36d928a6` for all six operations. Grandchild PID `710617` reported `0::/blackice/s-fcffb0da`. Receipts name those same PIDs and match destination, port and protocol (TCP 6, UDP 17). Both logs contain `backend_armed` before the drops, `backend_cleanup` with `cgroup_empty_and_removed`, and `scope_end` with status 0 and dropped count 0.

The receiver logged all **24/24** positive-control payloads and **0** scoped payloads. Its complete 26-row log contains only the listening event, those controls and the stopped event; no extra accepted connections were logged. This verifies an available off-host route before and after each tested phase, rather than treating an unreachable destination as proof of enforcement.

**Receipts and receiver log:** complete logs with only private address values redacted; timestamps, ports, process IDs, scope IDs, nonce labels and all other fields are unchanged. The [artifact notes](data/linux-20261030T132714Z/README.md) give original and redacted hashes.

- [Immediate scope: all ten receipts](data/linux-20261030T132714Z/immediate-receipts.jsonl).
- [Double-forked scope: all ten receipts](data/linux-20261030T132714Z/descendant-receipts.jsonl).
- [Off-host receiver: all 26 events](data/linux-20261030T132714Z/receiver.jsonl).

The receiver logged `stopped` at 13:27:17.280506 UTC. The harness waited for and reaped its SSH process (`receiver_exit: 0`, `receiver_stopped: true`). After verifying that completion, the coordination handoff recorded `MAC RECEIVER STOPPED 2026-10-30T10:31:04-03:00`. No Mac application was opened.

**Recording:** none; this is actual syscall, receipt and receiver output.

**Limits:** this run covers the six listed operations and one destination per family. The IPv6 result is over Tailscale, not native LAN IPv6. UDP `connect` was denied before a subsequent send; unconnected UDP sending was tested separately. The receiver logs connections/payloads, not a packet capture. The descendant test does not kill the launcher or test traffic after its parent has completed. Ping/ICMP, SCTP and other unsupported socket protocols are refused by seccomp, but do not emit individual `kernel_drop` receipts and were not exercised here. Allowed-name proxy behavior, grants and expiry have separate tests. General filesystem isolation, clipboard access and terminal-mediated clipboard operations were not tested. Earlier failed attempts remain recorded separately and are not part of this passing run. Hostname, SSH login command and private artifact paths are omitted.

**Date:** 2026-10-30, 13:27:14–13:27:17 UTC (10:27:14–10:27:17 ART).
