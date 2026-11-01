---
id: proxy
title: Proxy
owner: network
stage: v0
paths: src/proxy/
cases: P0-02, P0-03
depends: policy, receipts, scope-core
---

# Proxy

## What and why

Operating system sandboxes can block a program's network access, but most of them cannot say "allow
`registry.npmjs.org`, refuse everything else". The proxy fills that gap. Each scope gets its own small proxy
that runs outside the scope, on the local machine only. The scoped command can reach nothing but this proxy;
the proxy checks the name the command asked for against the policy, looks the name up itself, and connects only
if both the name and the address it found are allowed. Every answer it gives is written as a receipt.

## Requirements

| ID | Requirement | Checks |
|---|---|---|
| proxy.R1 | When a scope starts, blackice shall start that scope's proxy outside the scope, listening only on 127.0.0.1 at a randomly chosen port, before the command starts. | P0-01 |
| proxy.R2 | When an HTTP `CONNECT` request or a plain HTTP request names a host the policy does not allow, the proxy shall answer 403, write one `deny` receipt with the reason code, and not look the name up. | P0-02 |
| proxy.R3 | When the host is allowed, the proxy shall resolve the name itself, check every address it gets against the policy, and connect only to an address that passes. It shall never connect to an address supplied by the client for that name. | P0-03 |
| proxy.R4 | If every address of an allowed name is refused, for example because it is a private or loopback address, the proxy shall answer 403 and write a `deny` receipt with the address reason code. | P0-02 |
| proxy.R5 | When the request names an IP address instead of a host name, the proxy shall decide it with the policy's address rules only. | P0-03 |
| proxy.R6 | When the proxy allows a connection, it shall write one `allow` receipt with the matching rule, the host, the address it connected to and the port. | P0-03 |
| proxy.R7 | If a request is malformed, its header exceeds a fixed size, or it is neither `CONNECT` nor a plain HTTP request with an absolute URL, the proxy shall refuse it with a 4xx status and write a `deny` receipt. | P0-02 |
| proxy.R8 | When the scope ends, blackice shall stop the proxy and close every connection it is relaying. | P0-05 |
| proxy.R9 | When a request names a port the policy does not allow, the proxy shall answer 403 and write a `deny` receipt with reason `port_not_allowed`. | P0-03 |
| proxy.R10 | When a `CONNECT` tunnel's first bytes are a TLS ClientHello whose server name (SNI) differs from the `CONNECT` host, the proxy shall close the tunnel before any of the client's bytes is forwarded to the destination and write a `deny` receipt (`sni_mismatch`). The connection to the destination is already open at that point; nothing from the client goes through it. | P0-03 |
| proxy.R11 | When a `CONNECT` tunnel's first bytes are not a TLS ClientHello, the proxy shall close the tunnel and write a `deny` receipt (`not_tls`). A tunnel the client closes before sending a byte keeps its allow verdict, with detail `client_closed`; no client byte is forwarded upstream. When a ClientHello for a name carries no server name, it shall do the same with `sni_missing`. Without a server name, a shared front end would pick the site from whatever the client sends next. | P0-03 |
| proxy.R12 | When the proxy starts a command's environment, blackice shall point `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lowercase forms at the proxy, and set `NO_PROXY` to loopback only. | P0-03 |
| proxy.R13 | If a plain HTTP request head has a bare CR or LF, a control byte in the target or a header name that is not a valid token, the proxy shall answer 400, write a `deny` receipt (`bad_request`, detail `invalid_request`) and send nothing upstream. | P0-03 |
| proxy.R14 | If the scope ends while the proxy is still dialing an upstream, the proxy shall stop dialing, open no further connection, and write `upstream_unreachable` with detail `canceled`. | P0-06 |

## Design

The proxy speaks the standard HTTP proxy protocol, which almost every command-line tool already supports
through the `HTTPS_PROXY` family of variables. For HTTPS it only opens a tunnel: it reads the host and port from
the `CONNECT` line, decides, and then copies bytes both ways without reading them. Because the proxy does its
own name lookups, a refused name is never resolved at all, and an allowed name cannot be pointed at a local
service by the program.

**Technical.**

- Listener: TCP on `127.0.0.1:<random port>`, one proxy per scope, inside the `blackice` process. The port is
  passed to the backend as an allowed loopback port.
- `CONNECT host:port`: decide on `host`; on allow, reply `200 Connection established`, read the first bytes,
  require a TLS ClientHello whose SNI equals `host` (R10, R11), then splice bytes. This stops a client from
  opening `CONNECT allowed.com` and then asking a shared CDN address for another site.
- Plain HTTP (`GET http://host/path`): decide on the URL host; rewrite `Host` from the URL, drop hop-by-hop
  and `Proxy-*` headers, re-frame the body (length or chunked), one request per upstream connection.
- Decision order: port check first, then the host or IP literal check, then active grants (names only, see
  [grant](grant.md)), then resolution (allowed names only), then the address check on each result (see
  [policy](policy.md)). A grant never lifts a port or address refusal.
- Dialing: Happy Eyeballs (RFC 8305). The checked addresses alternate between IPv6 and IPv4, starting with the
  family of the resolver's first answer; each attempt starts 250 ms after the previous one, or as soon as it
  fails; the first connection that opens wins and the others are canceled. One 10 s budget for the whole dial.
  The `CONNECT` reply (200) is sent only once the upstream connection is open. Receipts for a failed dial carry
  `wait_ms`.
- Reason codes beyond the policy's: `granted`, `bad_request`, `resolve_failed`, `upstream_unreachable`,
  `sni_mismatch`, `tls_unparsed`, `not_tls`, `sni_missing`, `grant_expired`, `grant_revoked`,
  `grant_watchdog_failed`.
- Responses on refusal: 403 for a policy refusal, 400 or 405 for a malformed or unsupported request.
- Every decision writes one receipt with `point: proxy` (see [receipts](receipts.md)).
- Limits:
  - The `CONNECT` host is what the client says. The proxy binds it to a real destination by resolving it
    itself and compares the TLS server name with it, but it does not check certificates and cannot see inside
    ECH. A matching name check does not prove who the remote server is.
  - Domain fronting: an allowed name served by a shared CDN or hosting front end can carry requests for other
    sites on that front end inside TLS. The server-name check stops the plaintext and SNI-less forms, not
    this one.
  - Ports: only the ports the policy allows, 80 and 443 by default.
  - Only HTTP and HTTPS through the proxy are covered. Other protocols, UDP and QUIC are meant to be blocked
    entirely by the backend, which allows only the proxy and relay ports; each platform spec says what is
    verified.
  - Data sent to an allowed destination is out of scope.
  - The proxy listens on `127.0.0.1`, so in v0 any local process, including other users' processes, can send
    requests through it and reach what the scope's policy allows. It cannot reach more than that, but the
    receipts attribute the traffic to the scope. A per-scope proxy credential is not planned for v0.
  - Untested in v0: another local process taking the proxy's port after a crash, and one scope trying to use
    another scope's proxy.

## Tasks

| Task | Owner | State | Blocked by |
|---|---|---|---|
| `CONNECT` and plain HTTP proxy on a random loopback port | network | done | |
| Resolve allowed names in the proxy and dial only checked addresses | network | done | |
| Happy Eyeballs dial, `client_closed` detail instead of `not_tls`, no dialing after a stop (c6b3c1a; found by the lead when a proxied example.com timed out on a slow IPv6 path) | network | done | |
| A `client_closed` receipt also when the 200 cannot be written; the dial always has its deadline, with no sequential fallback (afe126d, security review) | network | done | |
| One receipt per decision | network | done | |
| Bound header size and refuse unsupported requests | network | done | |
| Tests: refused name, allowed name, private address behind an allowed name, IP literal | network | done | |
| TLS server name must match the `CONNECT` host; non-TLS first bytes close the tunnel | network | done | |
| Close the tunnel when the ClientHello has no server name | network | done | |
| Test a TLS handshake the proxy cannot parse (`tls_unparsed`): tunnel closed, no client byte forwarded upstream | network | todo | |
| Port check before any name work (`network.ports`) | network | done | |
| Wire the proxy into `blackice run` (PR #7) | lead | done | |
| Scope end stops the proxy and closes its tunnels | lead | done | |

## Evidence

| Covers | Kind | Link | Note |
|---|---|---|---|
| proxy.R2, proxy.R5, proxy.R6, proxy.R12 | entry | [P0-03 Linux](../../evidence/P0-03-explicit-allow-linux.md) | Linux, same launcher and helper, one run. `example.com` and `registry.npmjs.org` allowed (`sni_match`); github.com 403 (`no_matching_rule`); 169.254.169.254 403 (`local_or_private_address`); the proxy variables were set |
| proxy.R9 | entry | [P0-02 macOS](../../evidence/P0-02-real-deny-macos.md) | macOS 27.0.1 arm64, SIP on, claude/run 58e73cc, Zig 0.17.0, one run, PR #11. curl through the proxy to port 47121 got 403 and a `deny` receipt with reason `port_not_allowed`; `https://example.com` was allowed (`sni_match`) |
| proxy.R1, proxy.R2, proxy.R3, proxy.R6, proxy.R10, proxy.R12 | entry | [P0-03 macOS](../../evidence/P0-03-explicit-allow-macos.md) | macOS 27.0.1 arm64, SIP on, claude/run 58e73cc, Zig 0.17.0, one run, PR #10. example.com allowed over HTTPS (`sni_match`) and HTTP; github.com refused with 403 on both, deny receipts without a lookup |
| proxy.R2 | probe | - | Feasibility only, no blackice code: on macOS 27.0.1 (SIP on and off) and Linux, a command confined to one loopback port reached a stand-in proxy, which received `CONNECT example.com:443` while direct DNS failed inside the sandbox |
| proxy.R2, proxy.R3, proxy.R4, proxy.R5, proxy.R6, proxy.R7, proxy.R10, proxy.R12 | test | `zig build test`, src/proxy/test.zig: "CONNECT to a name outside the policy is refused with 403 and a receipt", "an allowed name that resolves to a private address is refused", "CONNECT to an allowed name tunnels bytes to the checked address", "TLS server name must match the CONNECT host", "plain HTTP: Host comes from the URI and proxy headers are dropped", "IP literals need an allowed subnet; requests that are not proxy requests get 400", "setEnv points every proxy variable at the proxy and keeps loopback direct" | 65/65 passed at 986645a (PR #4), Zig 0.17.0, Linux x86_64, six runs, real loopback sockets, fixed resolver, stand-in upstreams; no network |
| proxy.R9, proxy.R11, proxy.R13 | test | src/proxy/test.zig: "ports outside the policy are refused before any name work, and grants do not lift them", "CONNECT carries TLS only: other bytes close the tunnel", "a ClientHello without a server name is refused for a name", "plain HTTP heads with bare CR or LF, or bad header names, never reach the upstream" | Same run. The not-TLS and SNI-less tests check that the upstream received 0 bytes |

## Terms

CONNECT proxy, proxy variables, policy, receipt, reason code, loopback, DNS, SNI, ECH, TLS, domain fronting, scope
