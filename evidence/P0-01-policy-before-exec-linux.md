# P0-01: policy exists before a Linux command executes

**Claim:** P0-01 — the tested Linux launcher refused invalid or mismatched policy before creating a scope, and the valid scoped command observed its policy copy and initial receipt before doing work.

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

The harness creates an isolated temporary work directory and state root, then runs these commands with `XDG_STATE_HOME="$WORK/state"` and cwd `$WORK`:

```sh
"$FROZEN/blackice" run --policy "$WORK/invalid.json" -- /usr/bin/touch "$WORK/must-not-exist"
"$FROZEN/blackice" run --policy "$WORK/deny.json" \
  --policy-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  -- /usr/bin/touch "$WORK/must-not-exist"
"$FROZEN/blackice" run --policy "$WORK/deny.json" -- \
  /usr/bin/python3 -I "$WORK/worker.py" policy "$WORK/policy-command-ran" \
  0190ed20090854c97dd032ead0c5bc775df9d9af65039e0efc26fb50df697438
```

`invalid.json` contains `{"version":"unsupported"}`. The exact worker is embedded in the linked frozen harness.

**Result:** harness summary `CHECKS PASS`. Both rejection cases returned 125 with zero new scope directories, zero receipt files and no command marker. The invalid-policy diagnostic was `InvalidJson` / `MissingField`; the second diagnostic reported a policy-hash mismatch. These refusals are launcher checks before kernel setup, so they intentionally have no scope receipts.

The valid command returned 0 in `s-4347b3ed`. From inside the scope, the worker read `scope_start` as the first receipt and checked the copied policy's full hash and `deny-all` mode. It attempted to append a forged receipt; the open was refused. Only after those assertions did it write its command marker. Its actual stdout was:

```json
{"event": "policy_observed", "policy_sha256": "0190ed20090854c97dd032ead0c5bc775df9d9af65039e0efc26fb50df697438", "scope": "s-4347b3ed"}
```

**Receipts:** complete valid-scope log, unchanged:

```jsonl
{"ts":"2026-10-30T13:27:14.409Z","scope":"s-4347b3ed","policy":"0190ed200908","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command python3; proxy port 39487; 2 protected files"}
{"ts":"2026-10-30T13:27:14.454Z","scope":"s-4347b3ed","policy":"0190ed200908","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:27:14.480Z","scope":"s-4347b3ed","policy":"0190ed200908","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:27:14.481Z","scope":"s-4347b3ed","policy":"0190ed200908","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}

```

**Recording:** none; this is terminal and receipt evidence.

**Limits:** one real run on this kernel, not an exhaustive policy-race or filesystem mutation test. The receipt-write assertion accepts EROFS, EPERM or EACCES and does not record which one occurred. The `protected_paths` armed receipt is not evidence of every protected-file mutation attempt. General filesystem isolation, clipboard access and terminal-mediated clipboard operations were not tested. The [earlier verifier failure](linux-020f389-startup-failure.md) and [later containment failure](linux-c962271-containment-failure.md) remain separate records; neither is retroactively counted as passing. Hostname, SSH login command and private artifact paths are omitted.

**Date:** 2026-10-30, 13:27:14 UTC (10:27:14 ART).
