---
id: app-scopes
title: App scopes
owner: lead, codex
stage: release
paths:
cases: P0-10
depends: policy, receipts
---

# App scopes

## What and why

A task scope covers a command that blackice starts. An app scope covers an app that is already on the machine
and was started some other way: a browser, an editor, a chat client. It gives that app a policy of its own,
checked from the app's first connection, so the owner can say "this app may reach only these places" without
wrapping it. blackice needs both kinds before its first usable release, on macOS and on Linux. App scopes are
not part of v0 and do not run yet: on macOS the filter is built but not signed, and on Linux the way to
recognise an app is designed and its first build is in review.

## Requirements

| ID | Requirement | Checks |
|---|---|---|
| app-scopes.R1 | When an app that blackice did not start opens a new connection, blackice shall decide it by that app's policy, starting with the app's first connection. | - |
| app-scopes.R2 | On macOS, blackice shall control apps through a signed Network Extension content filter, installed through Apple's supported activation flow on a Mac with normal security settings. | - |
| app-scopes.R3 | On macOS, blackice shall identify an app from identity the operating system provides (for example its code signature), never from a display name or a file path alone. | - |
| app-scopes.R4 | On Linux, blackice shall identify an app by the group the desktop or service manager put it in before it ran, and shall describe that identity as a grouping, not as proof of which program is running. | - |
| app-scopes.R5 | When a command started from a terminal app connects without `blackice run`, blackice shall attribute the connection to the terminal app's scope and say so in the receipt. | - |
| app-scopes.R6 | If blackice cannot establish an app's identity, it shall apply the owner's declared default for unknown apps and write a receipt. A missing identity shall never match an allow rule. | - |
| app-scopes.R7 | When the owner changes an app scope's policy, blackice shall apply it to new connections and report what happens to connections that are already open. | - |
| app-scopes.R8 | When a task scope runs inside an app scope, blackice shall allow a destination only if both allow it. | - |
| app-scopes.R9 | The owner shall be able to turn app control off from outside every scope without removing unrelated firewall rules on the host. | - |
| app-scopes.R10 | Until a platform's app scopes have evidence, blackice's status and docs shall show them on that platform as not available. | P0-10 |

## Design

App scopes are planned, not designed in detail. Each platform has one candidate mechanism.

**Technical.**

- macOS: a signed host app with a Network Extension content filter (`NEFilterDataProvider`). The filter sees
  each new flow with the source app's identity from the system and checks it against an acknowledged local
  copy of the policy; no model or shell runs inside the filter. Building it needs a paid Apple Developer
  Program membership for signing and the matching entitlements, full Xcode, and user approval in System
  Settings. Coexistence with other filters and VPNs already on the Mac (for example a VPN with a transparent
  proxy, and Tailscale) has to be tested.
- macOS filter as built (PR #8, unsigned): TLS flows to a name pass only when the ClientHello's server name
  matches exactly; UDP and QUIC are denied; turning the filter off or removing its configuration needs the
  owner's Touch ID, and the prompt describes the configuration being approved. A ClientHello with ECH, which
  Chromium and Electron apps send by default, passes only on an exact outer server name, with an
  `ech_present` note.
- Linux: desktops such as GNOME and KDE start each app in its own systemd scope under the user's `app.slice`
  (for example `app-<launcher>-<app-id>-<n>.scope`, or a snap or Flatpak scope). systemd places the process in
  that cgroup before exec, and children inherit it. Rules can match that cgroup, or its ancestor level, with
  the nftables socket match or cgroup eBPF programs.
- Linux limits to qualify:
  - The app id comes from a desktop entry or unit name. A user can create a unit with any name, so this is not
    code integrity.
  - Rules must cover a new app group before its first packet, not after blackice notices it.
  - Commands run from a terminal belong to the terminal's group (R5).
  - System services have unit identities; containers and other network namespaces are separate.
- Both platforms: unknown apps, policy changes on open connections, and owner recovery are qualified per
  platform. Per-executable identity (hashes, exec-time tagging) is a later capability.

## Tasks

| Task | Owner | State | Blocked by |
|---|---|---|---|
| macOS: Network Extension filter (Swift) and host app in `macos/`, deciding per app by code-signing identity, with the same policy and receipt formats; built unsigned (PR #8) | appfilter | done | |
| macOS: single-writer receipts from the extension, in a file only the owner can read, followed live with `tail -f`; the design is reviewed by security before it is built. Today each per-connection decision goes to the unified log as a private entry | appfilter | todo | |
| macOS: Developer ID signing and notarization steps for the host app and the filter | appfilter | doing | |
| macOS: ClientHellos with ECH: allow on the exact outer server name, with an `ech_present` note (013d718) | appfilter | done | |
| macOS: sign the extension and run it on a Mac | valen | blocked | No Apple Developer Program membership (signing) and no full Xcode on the Mac. Until then its state stays "built, unsigned" and never "verified" |
| Linux: qualify desktop app groups (first-packet coverage, unknown groups, user-created units, migration, terminal children) | codex | todo | |
| Linux: choose how an app is recognised and matched, and build it; a design is reviewed; its first build had a security review, and the fixes from it are in review; kernel tests in a virtual machine and a security clearance come before any install | codex | doing | |
| Show both app-scope cells as not available in status and docs | marketing | done | |

## Evidence

| Covers | Kind | Link | Note |
|---|---|---|---|
| app-scopes.R4 | probe | Read-only look at a GNOME desktop on Debian 13 | A terminal app ran in its own systemd scope under the user's `app.slice` (a snap scope). One grouping example; no rule was attached and no traffic was tested |
| app-scopes.R1, app-scopes.R3, app-scopes.R6 | test | `macos/test.sh` (PR #8, c76afe6) | Reported by the app-filter owner: built with Command Line Tools on macOS 27.0.1, SIP on, warnings as errors; 320 assertions pass. Nothing installed or activated: unsigned, so no traffic was filtered |

## Terms

app scope, task scope, scope, policy, receipt, Network Extension, cgroup v2, nftables, eBPF, host ceiling
