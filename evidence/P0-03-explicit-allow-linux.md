# P0-03: a small explicit allow on Linux (Debian 13, kernel 6.12)

**Claim.** With a policy that allows only `example.com` and `registry.npmjs.org`, a command in a task scope on
the Linux host below reaches both over HTTPS through the scope's proxy. github.com and the cloud metadata
address are refused by the proxy. The same destinations reached directly, without the proxy, are refused by
the kernel. Each decision leaves a receipt. Checkpoint P0-03.

**Platform.** Debian GNU/Linux 13 (trixie), Linux 6.12.113+deb13-amd64, x86_64.
- Unified cgroup v2 and Landlock ABI 6.
- AppArmor is enabled, but this kernel has no unprivileged user-namespace restriction:
  `kernel.apparmor_restrict_unprivileged_userns` does not exist, and `kernel.unprivileged_userns_clone` is 1.

**Build.**
- Launcher: `020f389` (branch `codex/linux-demo-020f389`: `claude/run` 5c3a546 merged with the Linux
  backend), `zig build release` with Zig 0.17.0. Binary `blackice-x86_64-linux`, sha256
  `b6aeee363f7de1460049eee3417eb4eef48ccfe57512cb26f5ae3da5a00b0762`, checked before the run.
  `blackice version` prints `blackice 0.0.0-poc`.
- Helper: `blackice-linux-helper` built from `7c3bcff` (branch `codex/linux-namespace-fix`; the same code is
  in #6) with `scripts/linux-build-helper.sh`, sha256
  `515ebfacc545e1a2ca4f66190630aae2f8ff09b68f2575a2bcf11ea7698aadbd`. Two independent builds gave that hash,
  and it was reviewed before the owner installed it with `scripts/linux-setup.sh` at 13:18 UTC:
  - owner root, group the user's, mode 0750;
  - capabilities `cap_chown,cap_dac_override,cap_net_admin,cap_bpf=ep`.

  The run checked the installed file's sha256 first.
- Scripts: `scripts/e2e/` as on main, byte-identical to `7cc5697`, the reviewed version.

**Policy.** `agent.json`, written by the script, sha256
`b28c9f29dbeafbf9ae0fa9163a3affaefbc997aaedc19c23b3d20bf1dc662760` (policy id `b28c9f29dbea`):

```json
{
  "version": "blackice.policy/v0",
  "network": {
    "mode": "allowlist",
    "allow": ["example.com", "registry.npmjs.org"]
  }
}
```

`blackice policy check`: `mode allowlist, 2 allowed names, 0 allowed subnets, 0 denied subnets, ports 80 443,
policy b28c9f29dbea`.

**Run.** The script runs each command below in its own scope, in a fresh work directory under `/tmp` with
`XDG_STATE_HOME` inside it.

```sh
BLACKICE=/path/to/blackice-x86_64-linux bash scripts/e2e/linux-run.sh
```

**Result.** 30 checks passed and 0 failed. 1 declared limit held (ping, below).

Enforcement points:
- **Proxy.** curl uses it through `HTTPS_PROXY` / `HTTP_PROXY`, which blackice sets.
- **Kernel.** The scope's cgroup has BPF `connect` and `sendmsg` hooks. They let a socket reach only the
  scope's own proxy on 127.0.0.1, and they write a `kernel_drop` receipt for everything else.

| Command inside the scope | Output | Exit | Receipt |
|---|---|---|---|
| `/bin/true` | | 0 | `backend_armed` (`linux_cgroup_bpf`) |
| `curl https://example.com` | `200` | 0 | proxy allow, `sni_match` |
| `curl https://registry.npmjs.org/left-pad` | `200` | 0 | proxy allow, `sni_match` |
| `curl -w %{http_connect} https://github.com` | `403`, `curl: (56) CONNECT tunnel failed, response 403` | 56 | proxy deny, `no_matching_rule` |
| `curl --noproxy '*' https://example.com` | `curl: (6) Could not resolve host: example.com` | 6 | two `kernel_drop`, 127.0.0.1:53 UDP (the name lookup) |
| `curl --noproxy '*' https://1.1.1.1` | `curl: (7) Failed to connect to 1.1.1.1 port 443 after 0 ms` | 7 | `kernel_drop`, 1.1.1.1:443 TCP |
| `curl http://169.254.169.254/latest/meta-data/` | `403` | 0 | proxy deny, `local_or_private_address` |
| the same with `--noproxy '*'` | `curl: (7) Failed to connect to 169.254.169.254 port 80 after 0 ms` | 7 | `kernel_drop`, 169.254.169.254:80 TCP |
| python3 `sendto` UDP to 127.0.0.1:33527 and 1.1.1.1:53 | `refused … EPERM` for both; a receiver outside on 33527 got nothing | 0 | two `kernel_drop`, UDP (`hook=14`, sendmsg) |
| `ping -n -c 1 -W 2 1.1.1.1` | `socket: Operation not permitted` | 2 | none (declared limit) |

The same run also checked:
- **Environment.** The scope saw `BLACKICE_SCOPE`, `HTTPS_PROXY` and `HTTP_PROXY` (`http://127.0.0.1:59819`)
  and `NO_PROXY`. A synthetic secret set in the caller's environment was absent.
- **Receipts.** Appending to its own receipts file and to another scope's failed with `Read-only file system`,
  and no forged line appeared in any receipts file.
- **Protected files.** Writing to and renaming the blackice binary, the policy and a `--protect` file failed
  from inside, and all three were byte-identical afterwards.
- **Modes.** The scope directory is mode 700 and its receipts file 600.

**Receipts.** One block per scope, verbatim, in the order the commands ran:

```
{"ts":"2026-10-30T13:31:17.980Z","scope":"s-87f48c0a","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command true; proxy port 60401; 2 protected files"}
{"ts":"2026-10-30T13:31:18.018Z","scope":"s-87f48c0a","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:18.019Z","scope":"s-87f48c0a","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:18.019Z","scope":"s-87f48c0a","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:18.045Z","scope":"s-7110c69f","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command curl; proxy port 59251; 2 protected files"}
{"ts":"2026-10-30T13:31:18.047Z","scope":"s-7110c69f","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:18.082Z","scope":"s-7110c69f","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"allow","reason":"allowed_by_rule","rule":"example.com","host":"example.com","ip":"172.66.147.243","port":443,"detail":"sni_match"}
{"ts":"2026-10-30T13:31:18.208Z","scope":"s-7110c69f","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:18.208Z","scope":"s-7110c69f","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:18.234Z","scope":"s-72a1e6f4","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command curl; proxy port 38285; 2 protected files"}
{"ts":"2026-10-30T13:31:18.266Z","scope":"s-72a1e6f4","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:18.300Z","scope":"s-72a1e6f4","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"allow","reason":"allowed_by_rule","rule":"registry.npmjs.org","host":"registry.npmjs.org","ip":"104.16.9.34","port":443,"detail":"sni_match"}
{"ts":"2026-10-30T13:31:20.732Z","scope":"s-72a1e6f4","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:20.732Z","scope":"s-72a1e6f4","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:20.762Z","scope":"s-cb85113f","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command curl; proxy port 42253; 2 protected files"}
{"ts":"2026-10-30T13:31:20.797Z","scope":"s-cb85113f","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:20.803Z","scope":"s-cb85113f","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"connect","verdict":"deny","reason":"no_matching_rule","host":"github.com","port":443}
{"ts":"2026-10-30T13:31:20.804Z","scope":"s-cb85113f","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:20.804Z","scope":"s-cb85113f","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":56,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:20.831Z","scope":"s-af7c677e","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command curl; proxy port 34997; 2 protected files"}
{"ts":"2026-10-30T13:31:20.833Z","scope":"s-af7c677e","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:20.840Z","scope":"s-af7c677e","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"kernel_drop","verdict":"deny","reason":"loopback_proxy_only","ip":"127.0.0.1","port":53,"detail":"backend=cgroup_sock_addr hook=10 protocol=17 pid=722004"}
{"ts":"2026-10-30T13:31:20.840Z","scope":"s-af7c677e","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"kernel_drop","verdict":"deny","reason":"loopback_proxy_only","ip":"127.0.0.1","port":53,"detail":"backend=cgroup_sock_addr hook=10 protocol=17 pid=722004"}
{"ts":"2026-10-30T13:31:20.841Z","scope":"s-af7c677e","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:20.841Z","scope":"s-af7c677e","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":6,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:20.866Z","scope":"s-a7b557df","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command curl; proxy port 50989; 2 protected files"}
{"ts":"2026-10-30T13:31:20.894Z","scope":"s-a7b557df","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:20.900Z","scope":"s-a7b557df","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"kernel_drop","verdict":"deny","reason":"loopback_proxy_only","ip":"1.1.1.1","port":443,"detail":"backend=cgroup_sock_addr hook=10 protocol=6 pid=722024"}
{"ts":"2026-10-30T13:31:20.901Z","scope":"s-a7b557df","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:20.902Z","scope":"s-a7b557df","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":7,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:20.925Z","scope":"s-2cbabcfe","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command curl; proxy port 47849; 2 protected files"}
{"ts":"2026-10-30T13:31:20.954Z","scope":"s-2cbabcfe","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:20.960Z","scope":"s-2cbabcfe","policy":"b28c9f29dbea","gen":1,"point":"proxy","event":"http","verdict":"deny","reason":"local_or_private_address","host":"169.254.169.254","ip":"169.254.169.254","port":80,"detail":"method=GET"}
{"ts":"2026-10-30T13:31:20.962Z","scope":"s-2cbabcfe","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:20.962Z","scope":"s-2cbabcfe","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:20.989Z","scope":"s-310b8315","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command curl; proxy port 41477; 2 protected files"}
{"ts":"2026-10-30T13:31:21.014Z","scope":"s-310b8315","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:21.020Z","scope":"s-310b8315","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"kernel_drop","verdict":"deny","reason":"loopback_proxy_only","ip":"169.254.169.254","port":80,"detail":"backend=cgroup_sock_addr hook=10 protocol=6 pid=722068"}
{"ts":"2026-10-30T13:31:21.021Z","scope":"s-310b8315","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:21.021Z","scope":"s-310b8315","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":7,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:21.049Z","scope":"s-ba7757a1","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command sh; proxy port 59819; 2 protected files"}
{"ts":"2026-10-30T13:31:21.090Z","scope":"s-ba7757a1","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:21.092Z","scope":"s-ba7757a1","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:21.092Z","scope":"s-ba7757a1","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:21.107Z","scope":"s-03a33dc9","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command sh; proxy port 33995; 2 protected files"}
{"ts":"2026-10-30T13:31:21.110Z","scope":"s-03a33dc9","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:21.111Z","scope":"s-03a33dc9","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:21.111Z","scope":"s-03a33dc9","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:21.133Z","scope":"s-8d19646e","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command sh; proxy port 42435; 3 protected files"}
{"ts":"2026-10-30T13:31:21.135Z","scope":"s-8d19646e","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:21.141Z","scope":"s-8d19646e","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:21.141Z","scope":"s-8d19646e","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:21.255Z","scope":"s-bd899955","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command python3; proxy port 47231; 2 protected files"}
{"ts":"2026-10-30T13:31:21.302Z","scope":"s-bd899955","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:21.316Z","scope":"s-bd899955","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"kernel_drop","verdict":"deny","reason":"loopback_proxy_only","ip":"127.0.0.1","port":33527,"detail":"backend=cgroup_sock_addr hook=14 protocol=17 pid=722168"}
{"ts":"2026-10-30T13:31:21.316Z","scope":"s-bd899955","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"kernel_drop","verdict":"deny","reason":"loopback_proxy_only","ip":"1.1.1.1","port":53,"detail":"backend=cgroup_sock_addr hook=14 protocol=17 pid=722168"}
{"ts":"2026-10-30T13:31:21.319Z","scope":"s-bd899955","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:21.319Z","scope":"s-bd899955","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":0,"dropped":0}
```

```
{"ts":"2026-10-30T13:31:22.401Z","scope":"s-a9814530","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_start","detail":"backend linux-cgroup-bpf; command ping; proxy port 34643; 2 protected files"}
{"ts":"2026-10-30T13:31:22.438Z","scope":"s-a9814530","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_armed","reason":"linux_cgroup_bpf","detail":"cgroup_sock_addr; landlock_abi6; seccomp; protected_paths; private_mounts"}
{"ts":"2026-10-30T13:31:22.439Z","scope":"s-a9814530","policy":"b28c9f29dbea","gen":1,"point":"kernel","event":"backend_cleanup","reason":"cgroup_removed","detail":"cgroup_empty_and_removed"}
{"ts":"2026-10-30T13:31:22.439Z","scope":"s-a9814530","policy":"b28c9f29dbea","gen":1,"point":"control","event":"scope_end","status":2,"dropped":0}
```

**Recording.** None for this run.

**Limits.**
- **Who decides what.** The allow and deny decisions for curl through the proxy are the proxy's. The direct
  attempts show the kernel hooks for TCP and UDP to the addresses above. Off-host receivers, IPv6 and
  descendants that double-fork are in the P0-02 Linux run, not here.
- **ping.** It is refused by seccomp, before any address is chosen, so the kernel hooks never see it and no
  receipt is written. The script reports this as a declared limit, not a pass.
- **The `--noproxy` name.** curl never got to connect. The name lookup's queries to the local resolver were
  refused first, as the two receipts show.
- **Not exercised.**
  - Exact names only: no wildcard rules, subnets or ports other than 80 and 443.
  - The proxy decides on the destination name and port. Content inside an allowed TLS connection is not
    inspected.
- **The host.** This entry covers only this host. Ubuntu 24.04 and later set
  `kernel.apparmor_restrict_unprivileged_userns=1` by default. There the helper's child gets no capabilities
  in its new user namespace, so its private mounts fail and the scope fails closed before the command starts.
  Nothing here shows a scope running there.
- **Coverage.** x86_64 only; aarch64 Linux was not run. The helper was installed by the owner before the run.
  This run does not test the installation.
- **The run.** One run, by the people building blackice, on the owner's machine. Not a recording.

**Date.** 2026-10-30, 13:31 UTC.
