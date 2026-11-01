<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="site/public/brand/mark-dark.svg">
    <img src="site/public/brand/mark-light.svg" width="88" height="88" alt="blackice">
  </picture>
</p>

# blackice

blackice limits which hosts a command can reach, along with every process that command starts. The rules come
from a policy file you can read and review like code. Today it runs on macOS and on Debian 13 (x86_64), from the
terminal, and it never asks you to click Allow.

## Why I built it

I'm [Valen Torassa](https://valentorassa.com), a security and backend engineer in Rosario, Argentina. Most days an
AI agent runs commands on my machine: tests, package installs, scripts. Each of those runs with my user's
permissions, so any of them can connect to anywhere my user can reach.

I wanted that limit written down in a file I can review in a pull request, and in place before the command
starts. The operating system lets the command connect only to a local proxy, and the proxy applies the file. My
earlier project, [VT-Agent-Firewall](https://github.com/ValentinTorassa/VT-Agent-Firewall),
checks which tools an agent calls. blackice works one layer down, on the connections the commands themselves open.

It's v0 and not ready for production. Only what has an entry under [Evidence](#evidence) has been tested, and each
entry says what held and what didn't.

## Status

A cell says Tested only when it has entries in [`evidence/`](evidence/).

| | Apps | Tasks |
|---|---|---|
| macOS | Built, waiting for Developer ID signing: a Network Extension content filter ([#8](https://github.com/ValentinTorassa/blackice/pull/8)). | Tested. A Seatbelt sandbox profile plus a local proxy. Experimental, because Apple has deprecated `sandbox-exec`. |
| Linux | In review: a first build, not cleared or installed yet. | Tested on Debian 13 (x86_64). cgroup v2 with eBPF socket programs plus a local proxy, and a small helper that a setup script installs with sudo. |
| Windows | Later | Later |

A task is a command, such as one an AI agent runs, and everything that command starts. An app is a program
already installed on the machine, however it gets opened.

## Quick start

You need [Zig 0.17.0](https://ziglang.org/download/).

```console
$ git clone https://github.com/ValentinTorassa/blackice
$ cd blackice
$ zig build -Doptimize=ReleaseSafe
```

That builds `zig-out/bin/blackice`. macOS needs nothing else.

On Linux it also builds a small helper. Read [`scripts/linux-setup.sh`](scripts/linux-setup.sh) first, then
install the helper. Do it again after each reboot.

```console
$ sha256sum zig-out/bin/blackice-linux-helper
$ sudo ./scripts/linux-setup.sh "$USER" <that sha256>
```

Setup copies the helper to `/usr/local/libexec` with four file capabilities (`CAP_BPF`, `CAP_NET_ADMIN`,
`CAP_CHOWN`, `CAP_DAC_OVERRIDE`), runnable by your group. It also creates `/sys/fs/cgroup/blackice` and writes
the host's namespace IDs to `/etc/blackice-linux/namespaces`. [`scripts/linux-teardown.sh`](scripts/linux-teardown.sh),
run with sudo, removes all three. Setup needs `setcap` and `getcap` (`libcap2-bin` on Debian).
[`docs/linux.md`](docs/linux.md) has the details.

Write a policy that allows one name:

```json
{
  "version": "blackice.policy/v0",
  "network": { "mode": "allowlist", "allow": ["example.com"] }
}
```

Run a command under it. This is the output on Linux; on macOS only the backend name changes. The allowed name
works:

```console
$ ./zig-out/bin/blackice run --policy policy.json -- curl -sS -o /dev/null -w '%{http_code}\n' https://example.com
blackice: scope s-1b1f4870 (policy 353b7e8328f9, linux-cgroup-bpf); receipts: ~/.local/state/blackice/scopes/s-1b1f4870/receipts.jsonl
blackice: to allow one more host for a while: blackice grant s-1b1f4870 HOST --for 10m
200
blackice: scope s-1b1f4870 ended with status 0; 5 receipts
```

Any other name is refused:

```console
$ ./zig-out/bin/blackice run --policy policy.json -- curl -sS -o /dev/null -w '%{http_code}\n' https://github.com
blackice: scope s-f79c31a5 (policy 353b7e8328f9, linux-cgroup-bpf); receipts: ~/.local/state/blackice/scopes/s-f79c31a5/receipts.jsonl
blackice: to allow one more host for a while: blackice grant s-f79c31a5 HOST --for 10m
curl: (56) CONNECT tunnel failed, response 403
000
blackice: scope s-f79c31a5 ended with status 56; 5 receipts
```

Each receipt is one JSON line in the scope's `receipts.jsonl`:

```json
{"ts":"2026-10-30T14:36:01.279Z","scope":"s-1b1f4870","policy":"353b7e8328f9","gen":1,"point":"proxy","event":"connect","verdict":"allow","reason":"allowed_by_rule","rule":"example.com","host":"example.com","ip":"104.20.23.154","port":443,"detail":"sni_match"}
{"ts":"2026-10-30T14:36:01.427Z","scope":"s-f79c31a5","policy":"353b7e8328f9","gen":1,"point":"proxy","event":"connect","verdict":"deny","reason":"no_matching_rule","host":"github.com","port":443}
```

Receipts live under `$XDG_STATE_HOME/blackice/scopes/`, or `~/.local/state/blackice/scopes/` when that is not
set. To check a policy without running anything: `blackice policy check policy.json`.

## How it works

- `blackice run --policy policy.json -- <command>` puts the command in a **task scope**. The policy is in place
  before the command starts, and every process it starts inherits it.
- The command reaches the network only through a local proxy that runs outside the scope. The proxy checks each
  name against the policy, then checks every address that name resolves to.
- Nothing inside a scope can widen its own policy. The owner can, from outside, for a limited time:
  `blackice grant SCOPE HOST --for 10m`.
- The policy is a strict JSON file (`blackice.policy/v0`): a mode (`deny-all`, `allow-all` or `allowlist`) plus
  allowed names, subnets and ports. Unknown fields are an error. See [`docs/policy.md`](docs/policy.md).
- Each receipt is one JSON line with the scope, the policy hash and generation, where it was enforced, the
  verdict, a reason code and the destination. Some refusals leave no receipt; see [Limits](#limits).
- An **app scope** applies a policy to an installed app. A **host ceiling** over every scope is planned. Nested
  scopes can only narrow.
- No model or remote service takes part in a decision. No account, no telemetry.

## Evidence

Every run below happened on my own machines: a MacBook Air (macOS 27.0.1, Apple silicon, SIP on) and a Debian 13
box (kernel 6.12.113, x86_64), plus a disposable virtual machine on that box for part of P0-06. Nobody else has reproduced them yet. Each entry names the commit it was built
from, the exact commands, the receipts and its own limits.

| Checkpoint | What it shows | macOS | Linux |
|---|---|---|---|
| P0-01 | A command whose policy doesn't load, or doesn't match its pinned hash, never starts. A valid policy is in place before the command does any work. | [entry](evidence/P0-01-policy-before-exec-macos.md) | [entry](evidence/P0-01-policy-before-exec-linux.md) |
| P0-02 | Direct TCP and UDP over IPv4 and IPv6 are refused. A receiver on another machine got nothing from inside the scope. | [entry](evidence/P0-02-real-deny-macos.md) | [entry](evidence/P0-02-real-deny-linux.md) |
| P0-03 | With an allowlist, allowed names go through the proxy and other names are refused, each with a receipt. | [entry](evidence/P0-03-explicit-allow-macos.md) | [entry](evidence/P0-03-explicit-allow-linux.md) |
| P0-04 | A command inside a scope can't widen its own policy. The owner's `blackice grant`, from outside, lets one more name through until an end time. | [entry](evidence/P0-04-owner-grant-macos.md) | [entry](evidence/P0-04-owner-grant-linux.md) |
| P0-05 | When a grant ends, the proxy resets the connection opened under it, and new connections to that name are refused. | [entry](evidence/P0-05-grant-expiry-macos.md) | [entry](evidence/P0-05-grant-expiry-linux.md) |
| P0-06 | Faults: the proxy stopped, the launcher or the helper killed, a full disk. No scoped connection left the host. After a helper kill, a surviving process could reach a local program on the dead proxy's port, and recovery and the receipts did not always hold: four findings, written down as failures. An extra, not part of v0's list. | | [entry](evidence/P0-06-faults-linux.md) |
| P0-07 | With fx 0.0.16 and the blackice hook patch, each shell command fx runs gets its own scope and receipts. One run used a scripted test model; the other, a real model asking for one command. | [scripted](evidence/P0-07-fx-hook-scripted-macos.md), [real model](evidence/P0-07-fx-real-model-macos.md) | |
| P0-08 | P0-01 to P0-05 pass on both platforms, each with its own mechanism. | [entry](evidence/P0-08-second-platform.md) | [entry](evidence/P0-08-second-platform.md) |

## Limits

- Network only. Files, processes and credentials need their own controls.
- The CLI and the policy format can still change.
- Only HTTP and TLS through the proxy can be allowed.
- Processes of the same user outside every scope count as the owner.
- Nothing inside a task scope can listen, not even on loopback, so dev servers and tests that open a port can't
  run inside one.
- blackice doesn't detect prompt injection. It blocks connections the policy doesn't allow; what gets sent to an
  allowed destination is up to that destination.
- Work handed to a service outside the task (launchd, `open`, `systemd-run --user`, Docker, a tmux server) is
  known to be refused only in the cases a test covers.
- An allowed name on a shared CDN can reach other sites on that CDN through domain fronting inside TLS: the
  proxy checks the TLS server name, not the encrypted request.
- Receipts are a local record for diagnosis. Other programs of the same user, and administrators, can change
  them.
- With fx, only the shell commands fx runs are scoped. fx's own file tools and its model traffic run outside
  the scopes, and what those tools read goes to the model's provider.
- On macOS, a refusal leaves a receipt only when the refused program is signed by Apple. A program you built
  yourself is still refused, without a receipt. Programs signed with a Developer ID weren't tested. A burst of
  refusals can lose receipts, and a process that outlives the command gets none.
- On Linux, if the helper is killed while a scope runs, processes that detached from the command keep running
  with access only to the dead proxy's local port, which another local program can later listen on. Removing
  them needs root, and the receipts wrongly say the command didn't start.
- On Linux, ping, SCTP and raw sockets are refused when they are created, so they leave no receipt. Only x86_64
  was run. On Ubuntu 24.04 and later, where `kernel.apparmor_restrict_unprivileged_userns=1` is the default,
  scopes are expected to fail closed. Ubuntu wasn't tested.

## fx

Since 0.0.5, [fx](https://github.com/vercel-labs/fx) runs approved commands as ordinary host subprocesses
([changelog](https://github.com/vercel-labs/fx/blob/main/CHANGELOG.md)). There are two ways to use blackice
with it:

- **A scope per command.** A small patch to fx's PreToolUse hook, in [`integrations/fx/`](integrations/fx/) and
  not part of fx upstream, runs every shell command fx launches as `blackice run`. This is what P0-07 tested.
- **One scope around fx.** `blackice run --policy policy.json -- fx` puts fx and everything it starts in one
  task scope, with no changes to fx. This mode has no evidence entry yet.

## Site and docs

The project page and the documentation live in [`site/`](site/), a static Next.js export with its own pinned
dependencies. The native tool doesn't import or build anything from it.

```console
$ cd site && npm ci && npm run dev
```

## Related projects

[sandbox-runtime](https://github.com/anthropics/sandbox-runtime) ·
[nono](https://github.com/nolabs-ai/nono) ·
[fence](https://github.com/fencesandbox/fence) ·
[OpenSnitch](https://github.com/evilsocket/opensnitch) ·
[LuLu](https://github.com/objective-see/LuLu) ·
[Vercel Sandbox firewall](https://vercel.com/docs/sandbox/concepts/firewall)

## Feedback

If you try it and something doesn't behave the way this page says, open an issue. For security problems, see
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
