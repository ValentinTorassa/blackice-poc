# macOS application filter

State: **built, unsigned**. The Swift host and Network Extension compile with
Command Line Tools. The extension has **not** been installed, activated or tested
for live network enforcement. This is the application-scope backend; it does not
provide managed-command containment or a process-tree boundary.

## Build without Xcode

On a Mac with Command Line Tools:

```sh
./macos/build.sh
./macos/test.sh
./macos/build/Blackice.app/Contents/MacOS/BlackiceApp status
```

No packages or network downloads are required. The scripts use `xcrun swiftc`,
the macOS SDK and system frameworks. They target the current architecture and
macOS 13.0 or later (source-process audit tokens require macOS 13). Compilation
uses Swift 5 language mode on the installed Swift compiler, with warnings as
errors. This deployment target is not a claim of runtime qualification on every
macOS release.

`build.sh [output-directory]` requires a fresh app output path, so it cannot
accidentally preserve profiles or signatures from a previous signed build.
`test.sh [output-directory]` runs a standalone test executable; XCTest and full
Xcode are unnecessary. Build products are ignored by Git.

The output is:

```text
Blackice.app/Contents/
  Info.plist
  MacOS/BlackiceApp
  Library/SystemExtensions/com.valentorassa.blackice.filter.systemextension/Contents/
    Info.plist
    MacOS/BlackiceFilter
```

The Apple silicon linker can add an ad hoc execution signature. Here, **unsigned**
means no Developer ID identity, provisioning profile or Network Extension
entitlements. An ad hoc signature lets the host/test executable run locally;
it does not authorize a Network Extension. The build script never invokes
`codesign`, activates an extension, modifies filter preferences or changes SIP.

## Application identity and policy

`NEFilterDataProvider.handleNewFlow` evaluates new IPv4/IPv6 TCP/UDP
socket flows. It takes an immutable configuration snapshot, resolves the OS
source-app audit token through `SecCodeCopyGuestWithAttributes`, checks dynamic
code validity, and reads signing metadata and runtime status from that dynamic
code object. Team-signed bindings additionally require an Apple signing anchor,
the exact signing identifier and certificate Team ID. A path, bundle display name or PID alone
never authorizes an app. There is no parent scan.

Full validation also compares the running code with its file on disk, so an app
that updates itself while running (a new file renamed over the old one) fails it
with `errSecCSStaticCodeChanged` until it restarts. To keep such an app on its
own rules, a verified or ad hoc result is kept per process image, keyed by the
full audit token (the PID version changes on exec, so a key never names two
images). The cache is bounded and is used only while the kernel still reports
the running code as valid; code that becomes invalid goes back to full
validation and is denied. A bound app therefore stays bound after it updates
itself instead of escaping to `unmatched`. An app whose files changed before its
first flow is seen still fails closed.

Bindings require an exact `team_id` and `signing_id` pair. OS-confirmed valid ad
hoc code without a Team ID cannot match a binding: it follows `unmatched`, with
reason `outside_scope_adhoc`, including loopback. This keeps Homebrew tools,
locally built Zig/Go/Rust tools and the blackice proxy reachable when unmatched
traffic is allowed. Missing/unresolvable tokens, invalid dynamic signatures and
failed Team-ID validation still deny as `unknown_app_identity`; an invalidated
signed app never falls back to unmatched allow. Truly unsigned code for which
Security cannot establish a valid ad hoc identity also denies. Apple platform
processes without a Team ID can be verified as known but cannot be enrolled by
this binding format. Other verified identities follow the explicit `unmatched`
action. Inbound flows resolve identity too: a bound app always denies with
`inbound_not_allowed`; a verified unbound app follows `unmatched` with
`outside_scope_inbound` (ad hoc flows retain `outside_scope_adhoc`).

See Apple's [signing-information API](https://developer.apple.com/documentation/security/seccodecopysigninginformation(_:_:_:))
for dynamic-code information and its requirement to validate before trusting
the metadata. The resolver checks dynamic validity both before interpreting
flags and against the exact signed identity before binding it.

Source application and source process are recorded separately. A service may
create a connection for another app; its process identity does not replace the
source-app selector. See Apple's [audit token properties](https://developer.apple.com/documentation/networkextension/nefilterflow).
Helpers, interpreters and delegated traffic must be tested independently; a
binding to an app does not imply all descendants have that identity. With
`unmatched: allow`, a bound app can launch an unbound Electron Helper, shell,
`curl` or ad hoc executable whose traffic escapes that binding. This is especially
relevant to agents with shell tools; app scope is not process-tree confinement.

The network policy remains `blackice.policy/v0`, as defined in
`src/core/policy.zig`. It supports `deny-all`, `allow-all`, `allowlist`, exact
domains, `*.domain` subdomains, allow/deny CIDRs, and destination `ports`
(default `[80, 443]`; an empty array is invalid). Explicit subnet denies
win. Loopback, private, link-local, CGNAT and reserved addresses require an
explicit subnet allow. IPv4-mapped IPv6 destinations receive IPv4 checks, and
mapped CIDRs with a prefix of at least 96 normalize to IPv4. NAT64 destinations
are checked as both IPv6 and their embedded IPv4 address; 6to4, Teredo and other
transition addresses need an explicit subnet allow. Numeric/legacy IPv4 names
cannot satisfy domain rules.

The Swift evaluator preserves the policy's original UTF-8 bytes for the
SHA-256-based 12-character ID. It rejects unknown fields, duplicate JSON keys
(including escaped aliases), malformed patterns,
oversized/deep input, and unsupported app configuration fields. Configuration
limits are 1 MiB, 256 bindings, and 256 entries in each domain/subnet list.
As in the core, a null `ports` field uses the default. Other explicitly null
policy fields are invalid. Noncanonical dotted IPv4, including leading zeros,
is rejected before invoking the platform parser.

App bindings live in a separate `blackice.appscope/v0` configuration. The helper
embeds each unmodified network policy as a `policy_json` string and its full,
lowercase SHA-256 as `policy_sha256`. The provider recomputes the hash over the
decoded string's exact UTF-8 bytes and rejects a mismatch; it never reserializes
the inner JSON before hashing or asks the provider to read a user-supplied file
path. Receipts retain the core's first-12-hex policy ID. The digest checks byte
consistency, not owner authorization or tamper resistance against an actor who
can change the whole configuration.

Generate and validate a configuration:

```sh
APP=./macos/build/Blackice.app/Contents/MacOS/BlackiceApp
"$APP" make-config ./macos/Examples/deny-all.json ABCDE12345 com.example.probe app-probe allow ip-only > /tmp/apps.json
"$APP" validate /tmp/apps.json
```

`make-config` writes generation 1. `enable` replaces a saved configuration only
with a strictly higher generation, so give the replacement one as a last
argument:

```sh
"$APP" make-config ./macos/Examples/allow-test-subnet.json ABCDE12345 com.example.probe app-probe allow ip-only 2 > /tmp/apps-2.json
```

The Team ID and signing identifier above are synthetic; substitute a real signed
probe before future activation. Both examples use documentation addresses;
`allow-test-subnet.json` is an evaluator fixture, not a real reachable service.

The generated shape is:

```json
{
  "version": "blackice.appscope/v0",
  "generation": 1,
  "unmatched": "allow",
  "hostname_mode": "ip-only",
  "apps": [{
    "scope": "app-probe",
    "team_id": "ABCDE12345",
    "signing_id": "com.example.probe",
    "policy_json": "{\"version\":\"blackice.policy/v0\",\"network\":{\"mode\":\"deny-all\"}}",
    "policy_sha256": "f9789c9c9a6702d0db5723bad39cbfb2bfee0c7d786e71924d9373a84826e999"
  }]
}
```

The strict wrapper schema (JSON Schema 2020-12) is:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "blackice.appscope/v0",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "generation", "unmatched", "hostname_mode", "apps"],
  "properties": {
    "version": { "const": "blackice.appscope/v0" },
    "generation": { "type": "integer", "minimum": 1, "maximum": 4294967295 },
    "unmatched": { "enum": ["allow", "deny"] },
    "hostname_mode": { "enum": ["ip-only", "os-metadata"] },
    "apps": {
      "type": "array",
      "minItems": 1,
      "maxItems": 256,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["scope", "team_id", "signing_id", "policy_json", "policy_sha256"],
        "properties": {
          "scope": {
            "type": "string", "minLength": 4, "maxLength": 64, "pattern": "^app-",
            "not": { "anyOf": [
              { "pattern": "[^A-Za-z0-9_.-]" },
              { "enum": ["app-unbound", "app-unavailable", "app-provider", "app-control"] }
            ] }
          },
          "team_id": {
            "type": "string", "minLength": 10, "maxLength": 10,
            "not": { "pattern": "[^A-Z0-9]" }
          },
          "signing_id": {
            "type": "string", "minLength": 1, "maxLength": 255,
            "not": { "pattern": "[^A-Za-z0-9_.-]" }
          },
          "policy_json": {
            "type": "string",
            "minLength": 1,
            "contentMediaType": "application/json"
          },
          "policy_sha256": {
            "type": "string", "minLength": 64, "maxLength": 64,
            "not": { "pattern": "[^a-f0-9]" }
          }
        }
      }
    }
  }
}
```

The parser also enforces constraints that this wrapper schema cannot express:

- The complete UTF-8 wrapper and each embedded policy are at most 1 MiB, with
  nesting depth below 32. Duplicate object keys, including escaped aliases, are
  rejected before ordinary decoding. No required field accepts `null`.
- Each scope and each `(team_id, signing_id)` pair is unique. These are signing
  selectors, not a PID or filesystem path. Unknown selector fields are errors.
- Each `policy_json` must independently pass the strict `blackice.policy/v0`
  parser and the declared resource limits. The hash covers the policy bytes,
  including whitespace and trailing newlines, not the escaped wrapper string.
- A hash must match all 64 lowercase hex characters. Domain entries require
  `hostname_mode: "os-metadata"`; unsupported capabilities reject the candidate.
- The old provisional name `blackice.apps/v0` is rejected, with no implicit
  migration or relaxed fallback. `make-config` emits only the approved version.

Scope names start with `app-`. Duplicate scopes or identity pairs are rejected.
`app-unbound`, `app-unavailable`, `app-provider` and `app-control` are reserved
(`reserved_scope`): the provider and host write them in their own receipts, and a
binding with one of those names would be indistinguishable from them.
The provider validates the full candidate before installing a snapshot under a
lock. During a provider lifetime, a lower generation, or a different snapshot
at the same generation, is rejected. Invalid updates retain the last valid
snapshot. An invalid startup configuration fails startup; callbacks without a
snapshot deny while the provider runs. The host also requires a generation
strictly above the saved configuration for every replacement. Neither check is
durable rollback protection against deleting preferences or reinstalling.

## Destination coverage

`hostname_mode` must be explicit:

| Mode | Behavior |
| --- | --- |
| `ip-only` | Uses numeric socket endpoints and CIDRs. Rejects policies containing domain entries. |
| `os-metadata` | Uses `remoteHostname` and the actual numeric endpoint. Domain-rule allows require TCP and a first TLS ClientHello whose SNI exactly matches that hostname. Without a name, uses IP-literal policy. |

The hostname is optional OS metadata. Apple's SDK documents it for flows from
Network.framework and NSURLSession. A missing name cannot satisfy a domain rule;
a name without a numeric destination cannot authorize the flow. There is no DNS
correlation or reverse lookup. Malformed or unsupported required data denies.
See [`remoteHostname`](https://developer.apple.com/documentation/networkextension/nefiltersocketflow/remotehostname).

An allow based on a domain rule first requests outbound data inspection and
keeps `passBytes` at zero. The first complete TLS record must contain a parseable
ClientHello with one SNI matching the normalized metadata host exactly, even if
another host matches the same wildcard rule. Plain HTTP (`not_tls`), no SNI
(`sni_missing`), another SNI (`sni_mismatch`) and malformed/unsupported TLS
(`tls_unparsed`) deny with a receipt. UDP/QUIC cannot satisfy a domain decision
(`domain_requires_tls_tcp`). IP/subnet decisions do not depend on SNI and can
permit UDP. No allow receipt is emitted while TLS inspection is pending.

Peeks are bounded to 16,384 bytes per flow, 256 pending flows and 10 seconds
(timeouts are swept once a second). TCP callback slices can be reassembled, but
a ClientHello split across TLS records and duplicate extensions are rejected.
Pending handshakes
are dropped on a policy change; capacity exhaustion and timeout deny. Only the
bounded initial handshake is held transiently, never logged or written to disk.
The TCP connection handshake can occur before payload approval. This check
prevents switching the initial SNI or sending plaintext HTTP after a domain allow;
it does not validate TLS certificates, decrypt later HTTP Host/`:authority`, or
prevent routing/coalescing within a connection accepted under the same SNI.

The `encrypted_client_hello` extension (`0xfe0d`) is permitted when the **outer
SNI exactly matches** the allowed metadata hostname. The receipt's `detail`
includes `ech_present`; a mismatched outer SNI still denies. ECH-capable clients
send GREASE ECH even without a server ECH configuration; see
[RFC 9849, section 6.2](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.2)
and [Chromium's client configuration](https://chromium.googlesource.com/chromium/src/+/812dd783e5e140e555b6a8b8b31cdb8bdcd8988d/net/socket/ssl_client_socket_impl.cc).
This observer cannot distinguish GREASE from genuine ECH or inspect the inner
SNI. Allowing an ECH front end's public name can therefore allow a different
hidden inner name, within the same domain-fronting limit. `ech_present` reports
extension presence only; it does not claim ECH acceptance or inner-name approval.

The native settings request callback delivery for normal traffic and explicitly
include loopback rules for `127/8`, `::1` and IPv4-mapped loopback. Apple's
[`NEFilterSettings`](https://developer.apple.com/documentation/networkextension/nefiltersettings)
defaults do not filter loopback. These rules still require real signed-run
qualification, including all loopback aliases and VPN interactions.

After approval, a flow is allowed for its remaining lifetime. Already allowed
sockets are not revoked on policy changes; traffic predating activation is
unverified. Delivered inbound flows for a bound app deny. Unsupported socket
families/protocols delivered for a bound app also deny, but this socket filter
does not provide ICMP/unprivileged ping or other non-TCP/UDP coverage. Traffic
not delivered to the provider bypasses these decisions; this is not a packet
filter. Local IPC, file access and app tamper resistance are separate gaps.

System DNS lookups can leave through `mDNSResponder` under its own identity.
A bound app's DNS query names can therefore leave despite its network policy;
names such as `<data>.attacker.example` are an exfiltration channel. There is no
DNS proxy or delegated-DNS enforcement here. Helper/process identity gaps and
DNS must be covered separately before claiming confinement.

**When no provider is running, this backend does not filter traffic.** That
includes a failed `startFilter`, a crash before relaunch, disable/deactivation
and any OS-driven interruption. Denial inside a callback is not a system-wide
fail-closed guarantee. Updates keep the filter enabled rather than deliberately
disabling it, but availability across an OS update/restart is unqualified.
`status` cannot yet establish enforcement health. Future launch integration must
refuse to launch a bound app until the provider acknowledges the exact policy
generation, and must address loss of that acknowledgement/enforcement.

## Receipts and status

Decision receipts use the flat core schema: `ts`, `scope`, `policy`, `gen`,
`point`, `event`, `verdict`, `reason`, `rule`, `host`, `ip`, `port`, `detail`, with
optional `status` and `dropped` fields as in the core.
Absent optional values are omitted. Flow decisions use `point: "app_filter"` and
`detail` identifies `backend=network_extension;scope_kind=app`, the separate
validated app/process identities and hostname provenance. `gen`, `policy` and
`hostname_mode` come from the snapshot that made the decision, also when a
held TLS handshake is logged after a newer snapshot was installed.
Lifecycle/configuration events use `point: "control"`. `policy_activated` is
written only when a reload installs a new snapshot, not when the provider reads
the same generation and digest again. A refused startup or update records why in
`detail` as `cause=<reason>` (for example `stale_generation` or
`policy_sha256_mismatch`); decoder errors, which can quote the input, all become
`cause=invalid_configuration_document`. String fields are cleaned
and capped at the same byte limits as the core. Invalid UTF-8 bytes, C0/C1,
bidi and zero-width characters become `?`; truncation preserves UTF-8 character
boundaries and appends `...`. The raw-byte cleaner handles malformed UTF-8 before
string conversion; ordinary Swift string fields already contain valid Unicode.
Long identity labels retain a prefix and a hash of the complete label
so both app and process evidence fit within the detail field.

| Field | Maximum cleaned UTF-8 bytes |
| --- | ---: |
| `event` | 32 |
| `reason` | 64 |
| `rule` | 256 |
| `host` | 256 |
| `ip` | 64 |
| `detail` | 512 |

Only bound-app decisions and unresolved/invalid-identity or callback-error denials
produce per-flow diagnostics. Verified unbound and ad hoc connections produce
no per-flow log, including when `unmatched` denies. They increment allow/deny
counters, emitted at most once a minute and on stop as a `control` event named
`outside_scope_summary`. No destination or identity is retained in those counts.

Currently the provider emits bounded JSON lines to unified logging under
subsystem `com.valentorassa.blackice.filter`, category `receipts`. It never writes the
Zig scope's `receipts.jsonl`. This preserves one writer per persisted scope.
There is no durable ingestion/acknowledgement bridge yet. Unified logging may
drop or truncate entries, and has no application-level loss accounting; these
diagnostics are **not** a complete audit trail. Logging failure never changes a
deny into an allow. No runtime receipts have been captured from this unsigned
build. After future activation, inspect diagnostic output with:

```sh
log stream --style json --predicate 'subsystem == "com.valentorassa.blackice.filter" AND category == "receipts"'
```

This command produces unified-log envelopes. Per-flow JSON (including destinations
and identities) is marked private and is normally shown as `<private>` under the
OS privacy policy. Public control records contain lifecycle state, aggregate
counts or host authorization outcomes, never connection destinations. The host
uses category `control` for user-presence results. Each one's `policy` and `gen`
are the configuration digest and generation that the prompt showed (`unavailable`
and 0 when nothing readable was saved), and its `detail` includes the requesting
host's parent PID for audit only; that PID never authorizes anything. No payloads,
complete URLs, raw audit tokens, executable paths, credentials or environment
variables are logged. Retention follows OS policy; no logging privacy settings
are changed by this build. Durable receipt ingestion remains **pending**.

The host's `status` always reports `enforcement_verified: false` in this build.
Saving an enabled filter preference reports only `preferences_saved`. Neither
configuration save nor system-extension activation is an enforcement health
acknowledgement. Provider downtime leaves no app-filter protection; recovery and
lifecycle behavior remain runtime qualification gates.

## Signing, entitlements and installation

macOS content filters are deployed as system extensions inside a containing
app. Direct distribution supports Developer ID signing. See Apple's
[deployment matrix](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).

For the intended Developer ID route, obtain Apple Developer Program membership,
a Developer ID Application certificate and profiles for two explicit App IDs:
`com.valentorassa.blackice` and `com.valentorassa.blackice.filter`. These are build identifiers,
not a claim that they have already been registered. If another prefix is needed,
update `AppFilterConstants`, both Info plists and the build's extension path
together before signing.

Enable the Network Extensions capability for both identifiers and System
Extension installation for the host, and generate matching Developer ID
provisioning profiles. Validate the actual profile entitlements against the
intended distribution route. Apple specifies the
[`content-filter-provider-systemextension` entitlement value](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
for Developer ID. `filter-data-provider-systemextension` is not the entitlement
value; `com.apple.networkextension.filter-data` is the Info.plist provider class
mapping key.

| Target | Required entitlement |
| --- | --- |
| Host | `com.apple.developer.system-extension.install = true` |
| Host and extension | `com.apple.developer.networking.networkextension = ["content-filter-provider-systemextension"]` |
| Both, when signing | Matching `com.apple.application-identifier` and `com.apple.developer.team-identifier` from the profiles |

The templates in `macos/Resources/*.entitlements` contain only the capability
keys; they are not provisioned identities. For release, prepare copies with the
real application identifiers and Team ID allowed by each profile. Do not assume
an account's App ID prefix is interchangeable with its Team ID. Embed each
profile as `Contents/embedded.provisionprofile` in its respective bundle.
Profiles, certificates and private keys stay outside Git.

Sign the nested `.systemextension` first and the host `.app` last, with the same
team's Developer ID Application identity, hardened runtime, secure timestamp,
and their respective final entitlements. Verify both signatures/entitlements,
then notarize and staple the distributed app. Full Xcode may simplify capability
and profile management; it is not needed for this unsigned compile. Ad hoc
signing, manually adding entitlement strings, and a free Personal Team do not
complete this Developer ID deployment path. See Apple's
[system extension installation entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.system-extension.install)
and [notarization guidance](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

There is no Endpoint Security entitlement, app-group container or custom Mach
service in this implementation. Configuration travels through
`NEFilterManager.providerConfiguration.vendorConfiguration`; diagnostic receipts
use unified logging. A future durable control/receipt channel will need its own
authenticated transport and entitlement review.

After signing and notarization, install the host under `/Applications`, then
explicitly run the deployment helper from the bundle:

```sh
APP=/Applications/Blackice.app/Contents/MacOS/BlackiceApp
"$APP" activate
"$APP" enable /absolute/path/apps.json
"$APP" status
```

These are future deployment instructions, not steps performed by the build.
macOS must approve the system extension and the network filter; inspect the
normal System Settings prompts, or the corresponding managed deployment
authorization. A restart-required response is not treated as completed
activation. Keep SIP enabled and normal security settings. Never use developer
mode or disabled SIP as evidence of a supported installation.

`activate`, `enable`, `disable`, `remove-config` and `deactivate` refuse an
unsigned/ad hoc host. Each request also creates a fresh `LAContext` and requires
[`deviceOwnerAuthentication`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication),
with an operation-specific prompt (Touch ID or the macOS authentication fallback,
including password). The same complete summary is printed to stderr before
authentication: action, generation, configuration SHA-256 prefix, unmatched and
hostname modes, every bound signing identifier/Team ID and each original policy's
SHA-256 prefix. `enable` describes the frozen candidate; other actions describe
the saved policy. Absent or unreadable saved configuration is explicitly labeled
so recovery remains possible. For example:

```text
Blackice: enable or replace app filtering policy. generation 7; configuration sha256 <12 hex>; unmatched allow; hostname mode ip-only; apps: com.example.probe/ABCDE12345 (policy sha256 <12 hex>). Parent: zsh (pid 1234, audit only).
```

Every action includes the parent process name and PID as untrusted audit context;
name controls/bidi are cleaned and its length capped. A parent name/PID is never
authorization evidence. A preference change while the prompt is outstanding
aborts the operation and requires review and retry. No app binding is silently
omitted from the summary; real dialog layout remains a signed-run test gate.
Touch ID reuse duration is zero. Cancellation, unavailable
authentication or failure prevents the mutation; there is no CLI/environment
bypass or cached owner authorization. A request that would be refused anyway
fails before the prompt, so no approval is spent on it: `enable` with a
generation that is not above the saved one (`update_requires_higher_generation`)
or over an unreadable saved configuration (`invalid_saved_configuration`),
`disable` or `remove-config` with nothing saved (`no_owned_configuration`), and
`remove-config` or `deactivate` while the filter is enabled. The same checks run
again on the preferences reloaded after authentication. A confined app cannot
change the filter through this helper without user authentication. This does not prevent a user
from approving a malicious request or using macOS's own administration controls.
macOS separately enforces entitlement/profile and system-consent requirements.

`enable` validates and freezes the candidate bytes before requesting user
presence, then saves an update in place while keeping `isEnabled = true`. It
requires a generation strictly higher than the saved configuration and never
cycles through disable. The provider observes preference changes and validates
the candidate again. Already allowed sockets remain allowed; `preferences_saved`
does not mean the provider has acknowledged the update. The helper rejects a
configuration owned by a different provider identifier.

Recovery removes only this filter's configuration and extension:

```sh
"$APP" disable
"$APP" remove-config
"$APP" deactivate
```

Confirm the resulting state in System Settings and honor any restart request.
This restores the absence of this app's filtering, not a protection guarantee.
It neither flushes host firewall rules nor changes another filter. Local
diagnostic log retention is unchanged. Each recovery command requires its own
fresh user-presence check.

## Validation and remaining gates

Verified on 2026-10-30 on an arm64 Mac running macOS 27.0.1 (26A434), with SIP
enabled, Apple Swift 6.4 (`swiftlang-6.4.0.34.1`) and the Command Line Tools
macOS 27.0 SDK. Both bundles compiled with warnings as errors; the four resource
plists passed `plutil`; 351 test assertions passed. The host's `make-config` and
`validate` commands accepted both included examples, and `status` reported
`built, unsigned` with `enforcement_verified: false`. Signature inspection
confirmed only linker ad hoc signing with no Team ID. No activation or live
enforcement test was performed.

CI compiles both bundles and runs these tests on every pull request on GitHub's
`macos-latest` runner (`macos app filter` job), with whatever Command Line Tools
that image ships (Swift 6.3.3 and the macOS 26.5 SDK when the job was added).
That checks compilation and unit behaviour only; the runner never signs,
installs or activates the extension.

Tests cover exact/wildcard matching, private and mapped addresses, IPv6 CIDRs,
ports, strict configuration, identity binding isolation, inbound denial,
ad hoc unmatched allow/deny, unresolved/invalid-signed denial, delegated-source
handling, generations, receipt encoding and aggregate-only outside-scope logs.
The actual Security framework identifies the ad hoc test executable distinctly
and rejects missing/invalid audit tokens. Fake authenticators test denial and
approval for every mutating command without prompting the user or changing
preferences. Prompt tests check policy digests, identities, generation/unmatched
changes, parent-label cleaning and identical terminal/authentication text.
Precondition tests check the refusal the host applies before the prompt for
each action and saved state (the host CLI itself is not part of the test
executable), and that owner-authentication receipts carry the shown digest and
generation. Size, nesting and generation refusals are checked by their reason,
with valid input on the accepted side of each limit. TLS tests port the proxy's
ClientHello vectors and add truncated prefixes, callback slicing, exact-SNI
mismatch, plaintext HTTP, UDP, ECH, duplicate extensions, invalid names and
buffer limits. These tests do not replace
signed-app runtime identity, real LocalAuthentication UI or Network Extension
callback/timeout testing. No authentication prompt was displayed during testing.

An isolated headless Google Chrome 156.0.8078.48 instance on that Mac also sent a
real ClientHello to a temporary loopback listener for `ech-probe.blackice.test`.
No ECH configuration/feature override was supplied. The 1,931-byte TLS record
contained that outer SNI and a 186-byte ECH extension. Replaying the captured
record through the pre-fix parser reproduced `tls_unparsed`; the revised parser
accepted the exact outer name with `ech_present` and denied a different expected
name. This was capture of one controlled TCP stream, **not a raw packet capture
or live filter enforcement test**. Raw BPF devices required root and were not
used. Chrome used a temporary profile, which was removed; no personal browser
profile, filter preference, security setting or authentication UI was changed.

Before this app-scope backend can be called operational, record separate evidence
for normal-security signed activation; a signed probe launched outside blackice;
real allow/deny with an off-host receiver; direct TCP/UDP on IPv4/IPv6; loopback,
LAN, DNS and local proxies; unknown apps; PID reuse, exec and executable
replacement; helpers/interpreters and delegated services; existing sockets and
policy changes; crash/restart, sleep/wake, logout and VPN coexistence; recovery;
and durable receipt delivery with loss accounting. No four-cell release gate is
satisfied by compilation alone.
