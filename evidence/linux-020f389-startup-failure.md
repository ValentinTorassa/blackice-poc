# Linux startup failure with the reviewed v2 helper

**Claim:** the first installed-helper run failed closed before workload execution. This is a failed attempt at P0-01/P0-02 Linux, not evidence that either checkpoint passed. The filename deliberately has no `P0-xx` prefix.

**Platform:** Debian Linux, kernel `6.12.113+deb13-amd64`, x86_64. Kernel build: `#1 SMP PREEMPT_DYNAMIC Debian 6.12.113-1 (2026-10-15)`.

**Build:** Zig `0.17.0`; frozen launcher commit `020f3892374c89a4bf0be722767ccd4d366cd5ca`, preserved on `codex/linux-demo-020f389`.

| Artifact | SHA-256 |
| --- | --- |
| Launcher | `b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762` |
| Installed helper, source pin `35ae1f8476a84083780d7c7115aa03558f2454d5` | `215094628a8d1e4e9a30a5dff6aba4700d42aab6a45020db1315860e02d5cf29` |
| Frozen `evidence_check.py` | `daa07f757e12f5abc0bdf3b362f3e4cf033851a8788eac4965407c95d40c9962` |

The launcher and actual installed helper hashes were checked before invoking the frozen harness.

**Policy:**

```json
{"version":"blackice.policy/v0","network":{"mode":"deny-all"}}
```

Policy SHA-256: `0190ed20090854c97dd032ead0c5bc775df9d9af65039e0efc26fb50df697438`.

**Run:** the following is the harness invocation, with local artifact paths, receiver addresses and the SSH login command parameterized for privacy. `FROZEN` holds the exact reviewed launcher and harness above; `SSH_MAC`, `RECEIVER_V4` and `RECEIVER_V6` identify the intended off-host Mac receiver. The harness failed before opening that receiver.

```sh
/usr/bin/python3 -I "$FROZEN/evidence_check.py" \
  --blackice "$FROZEN/blackice" \
  --blackice-sha256 b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762 \
  --commit 020f3892374c89a4bf0be722767ccd4d366cd5ca \
  --helper-sha256 215094628a8d1e4e9a30a5dff6aba4700d42aab6a45020db1315860e02d5cf29 \
  --ssh-command "$SSH_MAC" --v4 "$RECEIVER_V4" --v6 "$RECEIVER_V6"
```

**Result:** harness exit 2, summary `FAILED`.

| Check | Observed result |
| --- | --- |
| Invalid policy (`{"version":"unsupported"}`) | CLI exit 125; no scope directory, receipts or command marker. Parser reported `InvalidJson` / `MissingField`. |
| Valid policy with a SHA-256 pin of 64 zeroes | CLI exit 125; no scope directory, receipts or command marker. Policy hash mismatch reported. |
| Valid policy and ordinary command | CLI exit 127; one scope receipt log; no workload output or command marker. Kernel BPF program loading failed before exec. |
| TCP/UDP, IPv4/IPv6, immediate/descendant senders | Not run. |
| Off-host receiver and positive controls | Not started; no receiver process or traffic observations. |

The valid-policy attempt produced this stderr excerpt:

```text
unreachable insn 41
processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
blackice Linux helper: kernel_filter: KernelFailure
blackice run: command_not_started: SpawnFailed
```

The enforcement point observed here is kernel verifier rejection during setup. There is no `backend_armed` or `kernel_drop` receipt and no successful scope execution.

**Receipts:** actual lines from the failed scope, with no fields changed:

```jsonl
{"ts":"2026-10-30T12:33:41.107Z","scope":"s-4cf9c16f","policy":"0190ed200908","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command python3; proxy port 55991; 2 protected files"}
{"ts":"2026-10-30T12:33:41.108Z","scope":"s-4cf9c16f","policy":"0190ed200908","gen":1,"point":"kernel","event":"warning","verdict":"deny","reason":"linux_helper_failure","detail":"kernel_filter: KernelFailure"}
{"ts":"2026-10-30T12:33:41.108Z","scope":"s-4cf9c16f","policy":"0190ed200908","gen":1,"point":"control","event":"warning","verdict":"deny","reason":"linux_launch_refused","detail":"HelperFailed"}
{"ts":"2026-10-30T12:33:41.108Z","scope":"s-4cf9c16f","policy":"0190ed200908","gen":1,"point":"control","event":"warning","reason":"command_not_started","detail":"SpawnFailed"}
{"ts":"2026-10-30T12:33:41.109Z","scope":"s-4cf9c16f","policy":"0190ed200908","gen":1,"point":"control","event":"scope_end","status":127,"detail":"command_not_started","dropped":0}
```

**Recording:** none. The Mac receiver was never started and no Mac application was opened.

**Limits:** the two policy-rejection cases passed, but policy-before-exec for a successfully confined command remains unverified. This attempt demonstrates no network denial, descendant containment, off-host absence of traffic or clipboard isolation. The helper must be corrected, independently reviewed and installed before repeating the successful-scope checks. Existing private raw output is retained separately; hostname, SSH login command and private artifact paths are omitted here.

**Date:** 2026-10-30, 12:33:41 UTC.
