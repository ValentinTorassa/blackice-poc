# Linux containment failure after the BPF verifier correction

**Claim:** this retry got past BPF setup but failed closed during child containment, before workload execution. It does not establish P0-01 or P0-02 Linux. This file has no checkpoint prefix so it cannot mark either checkpoint as recorded.

**Platform:** Debian Linux, kernel `6.12.113+deb13-amd64`, x86_64; kernel build `#1 SMP PREEMPT_DYNAMIC Debian 6.12.113-1 (2026-10-15)`.

**Build:** Zig `0.17.0`; unchanged frozen launcher and harness from `020f3892374c89a4bf0be722767ccd4d366cd5ca`. Corrected helper source: `c962271617866d5de837b6661c6f2673738fe528`.

| Artifact | SHA-256 |
| --- | --- |
| Launcher | `b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762` |
| Installed helper | `c84a4f61b74e345ffc2766c54b5dffcc16bba9691a1271c583419602715f9fc9` |
| Frozen harness | `daa07f757e12f5abc0bdf3b362f3e4cf033851a8788eac4965407c95d40c9962` |

Before the run, the actual installed helper's hash, root ownership, mode 0750 and exact `cap_chown,cap_dac_override,cap_net_admin,cap_bpf=ep` capability set were checked without changing them.

**Policy:**

```json
{"version":"blackice.policy/v0","network":{"mode":"deny-all"}}
```

Policy SHA-256: `0190ed20090854c97dd032ead0c5bc775df9d9af65039e0efc26fb50df697438`.

**Run:** exact harness options below; local artifact paths, receiver addresses and the SSH login command are parameterized for privacy. The receiver was never opened.

```sh
/usr/bin/python3 -I "$FROZEN/evidence_check.py" \
  --blackice "$FROZEN/blackice" \
  --blackice-sha256 b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762 \
  --commit 020f3892374c89a4bf0be722767ccd4d366cd5ca \
  --helper-sha256 c84a4f61b74e345ffc2766c54b5dffcc16bba9691a1271c583419602715f9fc9 \
  --ssh-command "$SSH_MAC" --v4 "$RECEIVER_V4" --v6 "$RECEIVER_V6"
```

**Result:** harness exit 2 and summary `FAILED`. Invalid policy and mismatched policy hash again produced CLI exit 125 without a scope, receipt or command marker. The first valid-policy scope returned 127, with no workload stdout or command marker. Its stderr ended:

```text
blackice child containment: PermissionDenied
blackice Linux helper: child_containment: ChildContainmentFailed
blackice run: command_not_started: SpawnFailed
```

Unlike the [first attempt](linux-020f389-startup-failure.md), this run reached the child-containment stage. Source ordering places that stage after all four BPF loads, attachments and attachment queries, and child enrollment. That observation does not establish network denial: no command executed, and there was no `backend_armed` or `kernel_drop` receipt.

**Receipts:** actual lines from this failed scope, with no fields changed:

```jsonl
{"ts":"2026-10-30T12:49:09.619Z","scope":"s-f3468383","policy":"0190ed200908","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command python3; proxy port 39565; 2 protected files"}
{"ts":"2026-10-30T12:49:09.641Z","scope":"s-f3468383","policy":"0190ed200908","gen":1,"point":"kernel","event":"warning","verdict":"deny","reason":"linux_helper_failure","detail":"PermissionDenied"}
{"ts":"2026-10-30T12:49:09.641Z","scope":"s-f3468383","policy":"0190ed200908","gen":1,"point":"kernel","event":"warning","verdict":"deny","reason":"linux_helper_failure","detail":"child_containment: ChildContainmentFailed"}
{"ts":"2026-10-30T12:49:09.642Z","scope":"s-f3468383","policy":"0190ed200908","gen":1,"point":"control","event":"warning","verdict":"deny","reason":"linux_launch_refused","detail":"HelperFailed"}
{"ts":"2026-10-30T12:49:09.642Z","scope":"s-f3468383","policy":"0190ed200908","gen":1,"point":"control","event":"warning","reason":"command_not_started","detail":"SpawnFailed"}
{"ts":"2026-10-30T12:49:09.642Z","scope":"s-f3468383","policy":"0190ed200908","gen":1,"point":"control","event":"scope_end","status":127,"detail":"command_not_started","dropped":0}
```

**Recording:** none. No Mac receiver process was started, and no Mac application was opened.

**Limits:** no TCP/UDP sender, descendant test or off-host positive control ran. The unchanged launcher with the corrected filter still does not provide successful Linux scope evidence. A separate rootless diagnostic reproduced a non-dumpable process's inability to open its own ID mapping files after creating a user namespace; that diagnostic is not a successful privileged-helper run. A parent-side mapping correction requires its own review and installation before retrying. Clipboard isolation was not tested. Hostname, SSH login command and private artifact paths are omitted; raw output remains private.

**Date:** 2026-10-30, 12:49:09 UTC.
