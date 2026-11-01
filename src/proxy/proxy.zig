//! The scope's proxy: the only way a confined command reaches a host by name.
//!
//! It runs outside the scope and listens on 127.0.0.1:<random>. The backend lets the command connect to that
//! port and nothing else, and the command gets HTTP_PROXY, HTTPS_PROXY and ALL_PROXY (and lowercase) pointing
//! at it (see `setEnv`).
//!
//! Two request forms:
//! - `CONNECT host:port`, for TLS only. After the tunnel opens, the first bytes the command sends must be a
//!   TLS ClientHello, and for a name its server name (SNI) must be present and equal the CONNECT host;
//!   otherwise the tunnel is closed before a byte reaches the upstream or comes back from it. This stops "CONNECT allowed.com"
//!   followed by "SNI evil.com" from reaching another site on a shared CDN address. A CONNECT to an IP
//!   literal (allowed only by a subnet) needs TLS but no particular server name.
//! - Plain HTTP with an absolute URI (`GET http://host/path`). The Host header is rewritten from the URI, so
//!   the request cannot name a different site, hop-by-hop headers are dropped, and the upstream connection
//!   carries exactly one request.
//!
//! Decision, in order:
//! 1. The destination port is checked with `Policy.checkPort`, before any name or DNS work. Grants never
//!    lift a port refusal.
//! 2. The host is normalized (lowercase, no trailing dot). An IP literal is decided by `Policy.checkLiteral`.
//! 3. A name is decided by `Policy.checkHost`; when the policy refuses it, an active grant may still allow it.
//! 4. An allowed name is resolved here, by the proxy, and every address is checked with
//!    `Policy.checkResolved`. Only addresses that pass are dialed. The command's own resolution is never used.
//!
//! Dialing (Happy Eyeballs, RFC 8305): the checked addresses alternate between IPv6 and IPv4, starting with
//! the family of the resolver's first answer. Each attempt starts `attempt_delay` after the previous one, or
//! as soon as the previous one fails, without waiting for it to give up; the first connection that opens is
//! used and the others are canceled. The whole dial has one `connect_timeout`. So an address whose packets
//! are dropped costs one `attempt_delay`, not a timeout. The CONNECT reply (200) is sent only once the
//! upstream connection is open.
//!
//! One receipt per decision (point "proxy"), event "connect" or "http". Besides the policy reason codes
//! (policy.Reason), the proxy uses:
//!   granted               allowed by an active grant (rule = the grant)
//!   bad_request           the request could not be parsed (400)
//!   resolve_failed        an allowed name did not resolve (502; rule = the allow entry)
//!   upstream_unreachable  no checked address accepted the connection within `connect_timeout` (502; rule =
//!                         the allow entry; detail = the last error, Timeout, or canceled when the scope ended
//!                         during the dial; wait_ms = time spent resolving and dialing)
//!   sni_mismatch          the TLS server name differs from the CONNECT host (tunnel closed)
//!   tls_unparsed          the first bytes were a TLS handshake that could not be parsed (tunnel closed)
//!   not_tls               the first bytes over CONNECT were not TLS (tunnel closed)
//!   sni_missing           a ClientHello for a name carried no server name (tunnel closed)
//!   grant_expired         a connection opened under a grant was reset when the grant expired
//!   grant_revoked         a connection opened under a grant was reset when the owner revoked it
//!   (Both sides are reset, not closed: bytes still queued toward the client or the upstream are dropped, so
//!   nothing moves through the proxy after the grant ends.)
//!   grant_watchdog_failed the task that enforces a grant's lifetime could not start (503)
//! App scopes (`Config.live`) decide with the policy binding in force when the request arrives, not the one in
//! force when the connection was accepted. After the dial, before any byte is forwarded, they decide again with
//! the binding in force then; a refusal there has detail rechecked_after_dial. They also use:
//!   policy_change_in_progress  a policy change was being published (503)
//!   retired_app_after_restart  the app was removed before the service restarted (403)
//!   policy_watchdog_failed     the task that cuts connections a narrowed policy refuses could not start (503)
//! A tunnel the client closes before sending a byte keeps its allow verdict and reason, with detail
//! client_closed (or canceled when the scope ended first) and wait_ms, the time the client waited for the 200.
//! Nothing reached the upstream. A client that gives up while the proxy is still dialing shows up this way.
//!
//! Declared limits (v0):
//! - Only the destination name and port are decided. Content inside TLS is not inspected: a request to an
//!   allowed host can carry any data to that host.
//! - Every process that can reach the port can use the proxy. A per-scope credential is a non-goal: each
//!   scope's backend lets it reach only its own proxy port, so another scope cannot use this one, and a
//!   process outside every scope already has direct network access, so a credential would stop nothing.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const http = std.http;
const policy = @import("../core/policy.zig");
const receipt = @import("../core/receipt.zig");
const grants_mod = @import("grants.zig");
pub const Grants = grants_mod.Grants;
pub const live_policy = @import("live_policy.zig");
const builtin = @import("builtin");

pub const Mode = enum { explicit, transparent_http, transparent_tls };

pub const ConnectionBudget = struct {
    active: std.atomic.Value(u32) = .init(0),
    limit: u32,
    pub fn acquire(b: *ConnectionBudget) bool {
        if (b.active.fetchAdd(1, .monotonic) < b.limit) return true;
        _ = b.active.fetchSub(1, .monotonic);
        return false;
    }
    pub fn release(b: *ConnectionBudget) void {
        _ = b.active.fetchSub(1, .monotonic);
    }
};
pub const HeaderState = struct {
    state: std.atomic.Value(u8) = .init(0), // waiting / complete / expired
    pub fn complete(h: *HeaderState) bool {
        return h.state.cmpxchgStrong(0, 1, .acq_rel, .acquire) == null;
    }
    pub fn expire(h: *HeaderState) bool {
        return h.state.cmpxchgStrong(0, 2, .acq_rel, .acquire) == null;
    }
};

pub const Config = struct {
    mode: Mode = .explicit,
    listen_address: net.IpAddress = .{ .ip4 = .loopback(0) },
    receipt_point: receipt.Point = .proxy,
    /// Connections served at the same time. More are answered with 503.
    max_connections: u32 = 256,
    /// Shared by all listeners for one app. Null preserves the per-proxy task-scope limit.
    connection_budget: ?*ConnectionBudget = null,
    /// Total time to receive a transparent HTTP head / TLS ClientHello; null preserves task-scope behavior.
    header_timeout: ?Io.Duration = null,
    /// Largest request head (request line and headers).
    max_head_bytes: usize = 16 * 1024,
    /// Time allowed for the whole dial, all addresses together.
    connect_timeout: Io.Duration = .fromSeconds(10),
    /// How long an attempt runs before the next address is tried alongside it.
    attempt_delay: Io.Duration = .fromMilliseconds(250),
    /// Addresses tried per name.
    max_addresses: usize = 8,
    /// Name resolution. `null` uses the system resolver (`std.Io.net.HostName.lookup`).
    resolver: ?Resolver = null,
    /// Grants consulted when the policy refuses a name. Owned by the caller.
    grants: ?*Grants = null,
    /// App scopes: the live policy binding, read when each request is decided and again after its dial. Task
    /// scopes leave this null.
    live: ?live_policy.Source = null,
};

/// Resolves `host` (normalized, not an IP literal) into `out`, returning how many addresses were written.
pub const Resolver = struct {
    context: ?*anyopaque = null,
    resolve: *const fn (context: ?*anyopaque, io: Io, host: []const u8, port: u16, out: []net.IpAddress) anyerror!usize,
};

const tls_record_max = 16384 + 5;

pub const Proxy = struct {
    gpa: std.mem.Allocator,
    io: Io,
    policy: *const policy.Policy,
    receipts: *receipt.Log,
    config: Config,
    server: net.Server,
    /// The port the proxy listens on, on 127.0.0.1.
    port: u16,
    group: Io.Group = .init,
    active: std.atomic.Value(u32) = .init(0),

    pub const StartError = net.IpAddress.ListenError || Io.ConcurrentError || error{OutOfMemory};

    /// Listens on 127.0.0.1:<random> and starts serving. `pol` and `receipts` must outlive the proxy.
    pub fn start(
        gpa: std.mem.Allocator,
        io: Io,
        pol: *const policy.Policy,
        receipts: *receipt.Log,
        config: Config,
    ) StartError!*Proxy {
        var server = try config.listen_address.listen(io, .{});
        return startListening(gpa, io, pol, receipts, config, server) catch |err| {
            server.deinit(io);
            return err;
        };
    }

    /// Takes ownership of an already-bound listener only on success.
    pub fn startListening(gpa: std.mem.Allocator, io: Io, pol: *const policy.Policy, receipts: *receipt.Log, config: Config, server: net.Server) StartError!*Proxy {
        const p = try gpa.create(Proxy);
        errdefer gpa.destroy(p);
        p.* = .{
            .gpa = gpa,
            .io = io,
            .policy = pol,
            .receipts = receipts,
            .config = config,
            .server = server,
            .port = server.socket.address.getPort(),
        };
        try p.group.concurrent(io, acceptLoop, .{p});
        return p;
    }

    /// Stops accepting, closes every open connection and frees the proxy.
    pub fn stop(p: *Proxy) void {
        const io = p.io;
        p.group.cancel(io);
        p.server.deinit(io);
        p.gpa.destroy(p);
    }

    fn writeEntry(p: *Proxy, entry: receipt.Entry) void {
        var e = entry;
        if (p.config.live) |source| if (source.current()) |view| {
            e.decision = view.decision;
            e.executable = view.executable;
        };
        p.receipts.write(e);
    }

    fn acceptLoop(p: *Proxy) Io.Cancelable!void {
        const io = p.io;
        while (true) {
            const stream = p.server.accept(io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                error.ConnectionAborted, error.WouldBlock => continue,
                error.SocketNotListening => return,
                else => {
                    p.writeEntry(.{ .event = "warning", .point = p.config.receipt_point, .reason = "accept_failed", .detail = @errorName(err) });
                    try io.sleep(.fromMilliseconds(100), .awake);
                    continue;
                },
            };
            if (!p.acquire()) {
                if (p.config.header_timeout != null) {
                    // Never block accept on an overload response to a client which does not read.
                    p.writeEntry(.{ .event = "connection_limit", .point = p.config.receipt_point, .verdict = .deny, .reason = "app_connection_limit" });
                    stream.close(io);
                    continue;
                }
                var wbuf: [256]u8 = undefined;
                var w = stream.writer(io, &wbuf);
                w.interface.writeAll("HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n") catch {};
                w.interface.flush() catch {};
                stream.close(io);
                continue;
            }
            p.group.concurrent(io, serveConnection, .{ p, stream }) catch {
                p.release();
                stream.close(io);
            };
        }
    }
    fn acquire(p: *Proxy) bool {
        if (p.config.connection_budget) |b| return b.acquire();
        if (p.active.fetchAdd(1, .monotonic) < p.config.max_connections) return true;
        _ = p.active.fetchSub(1, .monotonic);
        return false;
    }
    fn release(p: *Proxy) void {
        if (p.config.connection_budget) |b| b.release() else _ = p.active.fetchSub(1, .monotonic);
    }

    fn serveConnection(p: *Proxy, stream: net.Stream) Io.Cancelable!void {
        defer {
            stream.close(p.io);
            p.release();
        }
        var conn: Connection = undefined;
        conn.init(p, stream);
        if (p.config.live) |source| {
            if (source.paused.load(.acquire) or conn.view == null or !conn.view.?.serve) {
                conn.writeEntry(.{ .event = "connect", .point = p.config.receipt_point, .verdict = .deny, .reason = if (conn.view != null and !conn.view.?.serve) "retired_app_after_restart" else "policy_change_in_progress" });
                return;
            }
        }
        var guard: ?Io.Future(Io.Cancelable!void) = if (p.config.header_timeout) |duration|
            p.io.concurrent(headerDeadline, .{ &conn, duration }) catch {
                conn.writeEntry(.{ .event = "header_timeout", .point = p.config.receipt_point, .verdict = .deny, .reason = "header_watchdog_failed" });
                return;
            }
        else
            null;
        defer if (guard) |*g| g.cancel(p.io) catch {};
        conn.serve() catch |err| switch (err) {
            error.Canceled => |e| return e,
        };
    }
    fn headerDeadline(c: *Connection, duration: Io.Duration) Io.Cancelable!void {
        try c.io.sleep(duration, .awake);
        if (c.header.expire()) {
            shutdownProtected(c.io, c.client, .both);
            c.writeEntry(.{ .event = "header_timeout", .point = c.p.config.receipt_point, .verdict = .deny, .reason = "header_timeout" });
        }
    }
};

/// One client connection. Lives on the serving task's stack.
const Connection = struct {
    p: *Proxy,
    io: Io,
    client: net.Stream,
    in_buf: [16 * 1024 + tls_record_max]u8,
    out_buf: [4096]u8,
    reader: net.Stream.Reader,
    writer: net.Stream.Writer,
    header: HeaderState,
    /// App scopes: the binding read at accept, replaced by the one each decision used. It labels receipts.
    view: ?live_policy.Binding,

    fn init(c: *Connection, p: *Proxy, stream: net.Stream) void {
        c.p = p;
        c.io = p.io;
        c.client = stream;
        c.reader = stream.reader(p.io, &c.in_buf);
        c.writer = stream.writer(p.io, &c.out_buf);
        c.header = .{};
        c.view = if (p.config.live) |source| source.current() else null;
    }

    fn writeEntry(c: *Connection, entry: receipt.Entry) void {
        var e = entry;
        if (c.view) |view| {
            e.decision = view.decision;
            e.executable = view.executable;
        }
        c.p.receipts.write(e);
    }

    fn serve(c: *Connection) Io.Cancelable!void {
        if (c.p.config.mode == .transparent_tls) return c.serveTls();
        var hs = http.Server.init(&c.reader.interface, &c.writer.interface);
        hs.reader.max_head_len = @min(c.p.config.max_head_bytes, c.in_buf.len);
        var req = hs.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing, error.HttpRequestTruncated, error.ReadFailed => return c.canceled(),
            error.HttpHeadersOversize => return c.badRequest("431 Request Header Fields Too Large", "headers_too_large", null),
            error.HttpHeadersInvalid => return c.badRequest("400 Bad Request", "invalid_request", null),
        };
        if (!c.header.complete()) return;
        if (req.head.method == .CONNECT) {
            if (c.p.config.mode != .explicit) return c.badRequest("400 Bad Request", "connect_not_supported", "http");
            return c.serveConnect(&req);
        }
        return c.servePlain(&req);
    }

    /// Returns error.Canceled when a read or write failed because the task was canceled.
    fn canceled(c: *Connection) Io.Cancelable!void {
        if (c.reader.err) |e| if (e == error.Canceled) return error.Canceled;
        if (c.writer.err) |e| if (e == error.Canceled) return error.Canceled;
    }

    fn badRequest(c: *Connection, status: []const u8, detail: []const u8, event: ?[]const u8) Io.Cancelable!void {
        c.writeEntry(.{
            .event = event orelse "http",
            .point = c.p.config.receipt_point,
            .verdict = .deny,
            .reason = "bad_request",
            .detail = detail,
        });
        c.respondError(status, "blackice: bad proxy request\n");
        return c.canceled();
    }

    fn respondError(c: *Connection, status: []const u8, body: []const u8) void {
        if (c.p.config.mode == .transparent_tls) {
            shutdownProtected(c.io, c.client, .both);
            return;
        }
        const w = &c.writer.interface;
        w.print("HTTP/1.1 {s}\r\ncontent-type: text/plain\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}", .{
            status, body.len, body,
        }) catch return;
        w.flush() catch {};
    }

    fn serveConnect(c: *Connection, req: *http.Server.Request) Io.Cancelable!void {
        var host_buf: [policy.max_host_len + 2]u8 = undefined;
        const target = parseAuthority(req.head.target, null) catch
            return c.badRequest("400 Bad Request", "invalid_connect_target", "connect");
        if (target.host.len > host_buf.len) return c.badRequest("400 Bad Request", "invalid_connect_target", "connect");
        @memcpy(host_buf[0..target.host.len], target.host);
        const host_raw = host_buf[0..target.host.len];

        const t0 = Io.Clock.awake.now(c.io);
        var d: Decision = .{ .event = "connect", .port = target.port };
        var addrs_buf: [max_dial]net.IpAddress = undefined;
        const addrs = try c.decide(&d, host_raw, target.port, &addrs_buf);
        if (!d.allowed) return c.refuse(&d);

        const upstream = (try c.dial(&d, addrs, t0)) orelse return c.refuse(&d);
        defer upstream.close(c.io);
        if (!c.recheck(&d)) return c.refuse(&d);
        const wait_ms = t0.untilNow(c.io, .awake).toMilliseconds();

        // A grant's expiry or revocation closes the tunnel, not only new connections. No watchdog, no tunnel.
        var watchdog = c.armWatchdog(&d, upstream) catch return c.refuse(&d);
        defer if (watchdog) |*f| f.cancel(c.io) catch {};

        const w = &c.writer.interface;
        const replied = if (w.writeAll("HTTP/1.1 200 Connection Established\r\n\r\n")) |_| (if (w.flush()) |_| true else |_| false) else |_| false;

        // Nothing flows in either direction until the first client bytes pass: TLS only, and for a name the
        // ClientHello must carry exactly that name. A shared front end picks the site by SNI (or, without
        // TLS, by Host header), so anything else could reach a site the policy never allowed.
        const sni: SniResult = if (replied) c.checkSni(if (d.literal) null else d.host) else .no_data;
        if (sni == .no_data) {
            // The client left (or the scope ended) before sending a byte, or before the 200 could reach it:
            // nothing was refused and nothing reached the upstream. wait_ms shows whether the client gave up
            // while the proxy was dialing.
            const canceled_now = for ([_]?anyerror{ c.reader.err, c.writer.err }) |e| {
                if (e != null and e.? == error.Canceled) break true;
            } else false;
            d.detail = if (canceled_now) "canceled" else "client_closed";
            d.wait_ms = wait_ms;
            c.writeReceipt(&d);
            shutdownProtected(c.io, upstream, .both);
            shutdownProtected(c.io, c.client, .both);
            return c.canceled();
        }
        const refusal: ?[]const u8 = switch (sni) {
            .match => blk: {
                d.detail = if (d.literal) "ip_literal" else "sni_match";
                break :blk null;
            },
            .no_sni => if (d.literal) blk: {
                d.detail = "ip_literal";
                break :blk null;
            } else "sni_missing",
            .not_tls => "not_tls",
            .no_data => unreachable,
            .mismatch => |name| blk: {
                d.sni = name;
                break :blk "sni_mismatch";
            },
            .unparsed => "tls_unparsed",
        };
        if (refusal) |reason| {
            d.allowed = false;
            d.reason = reason;
            c.writeReceipt(&d);
            shutdownProtected(c.io, upstream, .both);
            shutdownProtected(c.io, c.client, .both);
            return;
        }
        // The client may have sent its first bytes long after the dial: decide once more before they go out.
        if (!c.recheck(&d)) {
            c.writeReceipt(&d);
            shutdownProtected(c.io, upstream, .both);
            shutdownProtected(c.io, c.client, .both);
            return;
        }
        c.writeReceipt(&d);

        var down_buf: [16 * 1024]u8 = undefined;
        var down_reader = upstream.reader(c.io, &down_buf);
        var down = c.io.concurrent(pump, .{ &down_reader, &c.writer }) catch {
            shutdownProtected(c.io, upstream, .both);
            return;
        };
        defer down.cancel(c.io) catch {};

        var up_buf: [0]u8 = undefined;
        var up_writer = upstream.writer(c.io, &up_buf);
        pump(&c.reader, &up_writer) catch |err| {
            down.cancel(c.io) catch {};
            return err;
        };
        // Awaiting is a cancelation point: a stop() while the response still flows cancels `down` too.
        try down.await(c.io);
    }

    /// Transparent TLS routes by the one unambiguous ClientHello name, before dialing.
    fn serveTls(c: *Connection) Io.Cancelable!void {
        var d: Decision = .{ .event = "connect", .port = 443 };
        const r = &c.reader.interface;
        const hdr = r.peek(5) catch return c.badRequest("400 Bad Request", "tls_unparsed", "connect");
        const n = std.mem.readInt(u16, hdr[3..5], .big);
        if (hdr[0] != 0x16 or n > tls_record_max - 5) return c.badRequest("400 Bad Request", "not_tls", "connect");
        const record = r.peek(5 + @as(usize, n)) catch return c.badRequest("400 Bad Request", "tls_unparsed", "connect");
        const name = (parseSni(record) catch return c.badRequest("400 Bad Request", "tls_unparsed", "connect")) orelse
            return c.badRequest("400 Bad Request", "sni_missing", "connect");
        if (!c.header.complete()) return;
        if (policy.parseIpLiteral(name) != null) return c.badRequest("400 Bad Request", "sni_not_name", "connect");
        const t0 = Io.Clock.awake.now(c.io);
        var addrs_buf: [max_dial]net.IpAddress = undefined;
        const addrs = try c.decide(&d, name, 443, &addrs_buf);
        if (!d.allowed) return c.refuse(&d);
        const upstream = (try c.dial(&d, addrs, t0)) orelse return c.refuse(&d);
        defer upstream.close(c.io);
        if (!c.recheck(&d)) return c.refuse(&d);
        d.detail = "transparent_sni";
        var watchdog = c.armWatchdog(&d, upstream) catch return c.refuse(&d);
        defer if (watchdog) |*f| f.cancel(c.io) catch {};
        c.writeReceipt(&d);
        var down_buf: [16 * 1024]u8 = undefined;
        var down_reader = upstream.reader(c.io, &down_buf);
        var down = c.io.concurrent(pump, .{ &down_reader, &c.writer }) catch {
            shutdownProtected(c.io, upstream, .both);
            return;
        };
        defer down.cancel(c.io) catch {};
        var up_buf: [0]u8 = undefined;
        var up_writer = upstream.writer(c.io, &up_buf);
        pump(&c.reader, &up_writer) catch |err| {
            down.cancel(c.io) catch {};
            return err;
        };
        try down.await(c.io);
    }

    fn servePlain(c: *Connection, req: *http.Server.Request) Io.Cancelable!void {
        // The head is forwarded, so it must be unambiguous: an upstream that splits lines on a bare LF would
        // otherwise read headers the proxy never saw (a second Host, a second Content-Length).
        if (!headIsClean(req)) return c.badRequest("400 Bad Request", "invalid_request", "http");
        const url = (if (c.p.config.mode == .transparent_http) originUrl(req) else parseHttpUrl(req.head.target)) catch |err| {
            const detail = if (err == error.HttpsNeedsConnect) "https_needs_connect" else "invalid_url";
            return c.badRequest("400 Bad Request", detail, "http");
        };

        const t0 = Io.Clock.awake.now(c.io);
        var d: Decision = .{ .event = "http", .port = url.port, .method = @tagName(req.head.method) };
        var addrs_buf: [max_dial]net.IpAddress = undefined;
        const addrs = try c.decide(&d, url.host, url.port, &addrs_buf);
        if (!d.allowed) return c.refuse(&d);

        const upstream = (try c.dial(&d, addrs, t0)) orelse return c.refuse(&d);
        defer upstream.close(c.io);
        if (!c.recheck(&d)) return c.refuse(&d);
        var watchdog = c.armWatchdog(&d, upstream) catch return c.refuse(&d);
        defer if (watchdog) |*f| f.cancel(c.io) catch {};
        c.writeReceipt(&d);

        // Request head, rewritten. Strings in req.head point into the client buffer and stay valid until
        // the body reader is created below.
        var up_buf: [4096]u8 = undefined;
        var up_writer = upstream.writer(c.io, &up_buf);
        const uw = &up_writer.interface;
        const has_body = req.head.method.requestHasBody();
        writeUpstreamHead(uw, req, url) catch return c.canceled();

        if (has_body) {
            const chunked = req.head.transfer_encoding == .chunked;
            var body_buf: [8192]u8 = undefined;
            const body = req.readerExpectContinue(&body_buf) catch return c.canceled();
            copyBody(body, uw, chunked) catch return c.canceled();
        }
        uw.flush() catch return c.canceled();

        // The response goes back as is. The upstream connection carries this one request and then closes.
        var down_buf: [16 * 1024]u8 = undefined;
        var down_reader = upstream.reader(c.io, &down_buf);
        try pump(&down_reader, &c.writer);
    }

    /// For a connection allowed by a grant, starts the task that closes it when the grant expires or is
    /// revoked. Fails (filling `d` as a refusal) when that task cannot start, so a grant is never unbounded.
    fn armWatchdog(c: *Connection, d: *Decision, upstream: net.Stream) error{WatchdogFailed}!?Io.Future(Io.Cancelable!void) {
        if (c.p.config.live != null) {
            std.debug.assert(c.p.config.grants == null);
            if (c.io.concurrent(watchPolicy, .{ c.p, c.client, upstream, d.host, d.ip_buf[0..d.ip_len], d.port })) |f| return f else |_| {}
            d.allowed = false;
            d.reason = "policy_watchdog_failed";
            d.status = "503 Service Unavailable";
            return error.WatchdogFailed;
        }
        const g = d.grant orelse return null;
        const fail = builtin.is_test and test_fail_watchdog;
        if (!fail) {
            if (c.io.concurrent(watchGrant, .{ c.p, g.id, g.deadline, c.client, upstream, d.event, d.host, d.ip_buf[0..d.ip_len], d.port })) |f| return f else |_| {}
        }
        d.allowed = false;
        d.policy_denied = false;
        d.reason = "grant_watchdog_failed";
        d.status = "503 Service Unavailable";
        return error.WatchdogFailed;
    }

    fn refuse(c: *Connection, d: *Decision) Io.Cancelable!void {
        c.writeReceipt(d);
        const status = d.status orelse if (d.policy_denied) "403 Forbidden" else "502 Bad Gateway";
        var body_buf: [512]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "blackice: {s} refused ({s})\n", .{ d.host, d.reason }) catch "blackice: refused\n";
        c.respondError(status, body);
        return c.canceled();
    }

    /// App scopes only: takes the policy binding in force now into `c.view`, so the decision and its receipt use
    /// the generation in force when the request arrived. False, with `d` filled as a refusal, while a policy
    /// change is being published or when the app was removed before the service restarted.
    fn bindNow(c: *Connection, d: *Decision) bool {
        const source = c.p.config.live orelse return true;
        if (source.capture()) |view| {
            c.view = view;
            return true;
        }
        const now = source.current();
        if (now) |view| c.view = view;
        d.allowed = false;
        d.rule = null;
        if (now != null and !now.?.serve) {
            d.policy_denied = true;
            d.reason = "retired_app_after_restart";
        } else {
            d.policy_denied = false;
            d.reason = "policy_change_in_progress";
            d.status = "503 Service Unavailable";
        }
        return false;
    }

    /// App scopes only: decides again, after the dial and before any byte is forwarded, with the binding in force
    /// now. A policy change published while the proxy resolved and dialed is applied here, so the upstream
    /// never gets a byte the new policy refuses; from here on the watchdog covers the open connection.
    /// False, with `d` filled as a refusal.
    fn recheck(c: *Connection, d: *Decision) bool {
        if (c.p.config.live == null) return true;
        if (!c.bindNow(d)) {
            d.detail = "rechecked_after_dial";
            return false;
        }
        const ip = if (d.ip_len > 0) policy.parseIpLiteral(d.ip_buf[0..d.ip_len]) else null;
        const v = live_policy.verdict(c.view.?, d.host, d.port, ip);
        d.setVerdict(v);
        if (!v.allowed) d.detail = "rechecked_after_dial";
        return v.allowed;
    }

    /// Fills `d` with the policy decision and returns the addresses that may be dialed.
    fn decide(c: *Connection, d: *Decision, host_raw: []const u8, port: u16, buf: *[max_dial]net.IpAddress) Io.Cancelable![]net.IpAddress {
        if (!c.bindNow(d)) {
            d.host = policy.normalizeHost(&d.host_buf, host_raw) catch host_raw;
            return buf[0..0];
        }
        const pol = if (c.view) |view| view.policy else c.p.policy;
        const pv = pol.checkPort(port);
        if (!pv.allowed) {
            d.host = policy.normalizeHost(&d.host_buf, host_raw) catch host_raw;
            d.setVerdict(pv);
            return buf[0..0];
        }
        if (policy.parseIpLiteral(host_raw)) |lit| {
            d.literal = true;
            d.host = host_raw;
            const v = pol.checkLiteral(lit);
            d.setVerdict(v);
            if (!v.allowed) {
                d.setIp(lit);
                return buf[0..0];
            }
            buf[0] = lit;
            buf[0].setPort(port);
            return buf[0..1];
        }

        const host = policy.normalizeHost(&d.host_buf, host_raw) catch {
            d.host = "";
            d.allowed = false;
            d.policy_denied = true;
            d.reason = policy.Reason.invalid_host.code();
            return buf[0..0];
        };
        d.host = host;

        var v = pol.checkHost(host);
        if (!v.allowed) {
            if (c.p.config.grants) |g| {
                if (g.check(c.io, host, &d.rule_buf)) |m| {
                    d.allowed = true;
                    d.policy_denied = false;
                    d.reason = "granted";
                    d.rule = m.rule;
                    d.expires = m.expires;
                    d.grant = .{ .id = m.id, .deadline = m.deadline };
                    v = .{ .allowed = true, .reason = .allowed_by_rule };
                }
            }
            if (!d.allowed) {
                d.setVerdict(v);
                return buf[0..0];
            }
        } else d.setVerdict(v);

        const max = @min(buf.len, c.p.config.max_addresses);
        const n = c.resolve(host, port, buf[0..max]) catch |err| switch (err) {
            error.Canceled => |e| return e,
            else => {
                d.allowed = false;
                d.reason = "resolve_failed";
                d.detail = @errorName(err);
                return buf[0..0];
            },
        };
        if (n == 0) {
            d.allowed = false;
            d.reason = "resolve_failed";
            d.detail = "no_address";
            return buf[0..0];
        }

        // Keep only the addresses the policy accepts; the first refusal explains a total refusal.
        var kept: usize = 0;
        var first_denied: ?policy.Verdict = null;
        var first_denied_addr: net.IpAddress = undefined;
        for (buf[0..n]) |a| {
            const rv = pol.checkResolved(a);
            if (rv.allowed) {
                buf[kept] = a;
                buf[kept].setPort(port);
                kept += 1;
            } else if (first_denied == null) {
                first_denied = rv;
                first_denied_addr = a;
            }
        }
        if (kept == 0) {
            const rv = first_denied.?;
            d.allowed = false;
            d.policy_denied = true;
            d.reason = rv.reason.code();
            d.rule = rv.rule;
            d.expires = null;
            d.grant = null;
            d.setIp(first_denied_addr);
        }
        return buf[0..kept];
    }

    fn resolve(c: *Connection, host: []const u8, port: u16, out: []net.IpAddress) anyerror!usize {
        if (c.p.config.resolver) |r| return r.resolve(r.context, c.io, host, port, out);
        return systemResolve(c.io, host, port, out);
    }

    /// Dials the checked addresses (see "Dialing" above). Returns null, with `d` filled as a refusal, when
    /// none opens in time. When the task is canceled mid-dial, writes that refusal's receipt and returns
    /// error.Canceled: a stopping proxy does not go on to the next address.
    fn dial(c: *Connection, d: *Decision, addrs: []const net.IpAddress, t0: Io.Timestamp) Io.Cancelable!?net.Stream {
        if (addrs.len == 0) {
            d.allowed = false;
            d.reason = "upstream_unreachable";
            d.detail = "no_address";
            return null;
        }
        var order_buf: [max_dial]net.IpAddress = undefined;
        const order = interleaveFamilies(&order_buf, addrs);
        const cfg = c.p.config;
        const result = dialRace(c.io, order, cfg.attempt_delay, cfg.connect_timeout) catch |err| switch (err) {
            error.Canceled => {
                d.allowed = false;
                d.reason = "upstream_unreachable";
                d.detail = "canceled";
                d.wait_ms = t0.untilNow(c.io, .awake).toMilliseconds();
                d.setIp(order[0]);
                c.writeReceipt(d);
                return error.Canceled;
            },
        };
        switch (result) {
            .open => |o| {
                d.setIp(order[o.index]);
                return o.stream;
            },
            .failed => |f| {
                d.allowed = false;
                d.reason = "upstream_unreachable";
                d.detail = @errorName(f.err);
                d.wait_ms = t0.untilNow(c.io, .awake).toMilliseconds();
                d.setIp(order[f.index]);
                return null;
            },
        }
    }

    const SniResult = union(enum) { match, no_sni, not_tls, no_data, unparsed, mismatch: []const u8 };

    /// Peeks at the first bytes of the tunnel without consuming them. With `host` null (an IP literal), any
    /// well-formed ClientHello matches.
    fn checkSni(c: *Connection, host: ?[]const u8) SniResult {
        const r = &c.reader.interface;
        const first = r.peek(1) catch return .no_data;
        if (first[0] != 0x16) return .not_tls;
        const hdr = r.peek(5) catch return .unparsed;
        const len = std.mem.readInt(u16, hdr[3..5], .big);
        if (5 + @as(usize, len) > tls_record_max) return .unparsed;
        const record = r.peek(5 + @as(usize, len)) catch return .unparsed;
        const sni = parseSni(record) catch return .unparsed;
        const name = sni orelse return .no_sni;
        const want = host orelse return .match;
        var buf: [policy.max_host_len]u8 = undefined;
        const norm = policy.normalizeHost(&buf, name) catch return .{ .mismatch = name };
        if (!std.mem.eql(u8, norm, want)) return .{ .mismatch = name };
        return .match;
    }

    fn writeReceipt(c: *Connection, d: *Decision) void {
        var detail_buf: [320]u8 = undefined;
        var w: Io.Writer = .fixed(&detail_buf);
        if (d.method) |m| w.print("method={s}", .{m}) catch {};
        if (d.detail) |x| {
            if (w.end > 0) w.writeByte(' ') catch {};
            w.writeAll(x) catch {};
        }
        if (d.wait_ms) |ms| {
            if (w.end > 0) w.writeByte(' ') catch {};
            w.print("wait_ms={d}", .{ms}) catch {};
        }
        if (d.sni) |s| {
            if (w.end > 0) w.writeByte(' ') catch {};
            w.writeAll("sni=") catch {};
            for (s) |ch| w.writeByte(if (std.ascii.isPrint(ch)) ch else '?') catch {};
        }
        if (d.expires) |e| {
            var ts_buf: [32]u8 = undefined;
            if (w.end > 0) w.writeByte(' ') catch {};
            w.print("grant_until={s}", .{receipt.formatTimestamp(&ts_buf, e)}) catch {};
        }
        // A cancelation that arrives during the write must neither drop the receipt nor be consumed by it:
        // a swallowed cancelation would leave the connection waiting on its pumps while the proxy stops.
        const old = c.io.swapCancelProtection(.blocked);
        defer _ = c.io.swapCancelProtection(old);
        c.writeEntry(.{
            .event = d.event,
            .point = c.p.config.receipt_point,
            .verdict = if (d.allowed) .allow else .deny,
            .reason = d.reason,
            .rule = d.rule,
            .host = if (d.host.len > 0) d.host else null,
            .ip = if (d.ip_len > 0) d.ip_buf[0..d.ip_len] else null,
            .port = d.port,
            .detail = if (w.end > 0) w.buffered() else null,
        });
    }
};

const Decision = struct {
    event: []const u8,
    port: u16,
    method: ?[]const u8 = null,
    allowed: bool = false,
    /// True when the refusal comes from the policy (403); false for network failures (502).
    policy_denied: bool = false,
    literal: bool = false,
    reason: []const u8 = "",
    rule: ?[]const u8 = null,
    detail: ?[]const u8 = null,
    /// Milliseconds spent resolving and dialing; shown for failed dials and tunnels closed before any data.
    wait_ms: ?i64 = null,
    sni: ?[]const u8 = null,
    /// Set when a grant allowed the connection: wall-clock expiry (display) and the grant to watch.
    expires: ?Io.Timestamp = null,
    grant: ?struct { id: u64, deadline: Io.Timestamp } = null,
    /// Overrides the refusal status line.
    status: ?[]const u8 = null,
    host: []const u8 = "",
    host_buf: [policy.max_host_len]u8 = undefined,
    rule_buf: [policy.max_host_len + 16]u8 = undefined,
    ip_buf: [64]u8 = undefined,
    ip_len: usize = 0,

    fn setVerdict(d: *Decision, v: policy.Verdict) void {
        d.allowed = v.allowed;
        d.policy_denied = !v.allowed;
        d.reason = v.reason.code();
        d.rule = v.rule;
    }

    fn setIp(d: *Decision, a: net.IpAddress) void {
        d.ip_len = formatIp(&d.ip_buf, a).len;
    }
};

/// Copies `from` to `to` until end of stream, flushing after every read so interactive protocols work.
/// When the source ends, the sending half of `to` is shut down so the other side sees end of stream.
/// Returns error.Canceled when a read or write was canceled, so the caller can cancel the other direction.
fn pump(from: *net.Stream.Reader, to: *net.Stream.Writer) Io.Cancelable!void {
    const r = &from.interface;
    while (true) {
        const data = r.peekGreedy(1) catch break;
        to.interface.writeAll(data) catch break;
        to.interface.flush() catch break;
        r.toss(data.len);
    }
    shutdownProtected(to.io, to.stream, .send);
    if (from.err) |e| if (e == error.Canceled) return error.Canceled;
    if (to.err) |e| if (e == error.Canceled) return error.Canceled;
}

/// Shuts a socket down without consuming a pending cancelation request. Otherwise a stop() that arrives
/// right after end of stream is swallowed here, and the task then waits forever on the other direction.
fn shutdownProtected(io: Io, stream: net.Stream, how: net.ShutdownHow) void {
    const old = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(old);
    stream.shutdown(io, how) catch {};
}

/// Addresses dialed per name, at most.
pub const max_dial = 16;

pub const Dialed = union(enum) {
    /// The first connection that opened, and the index of its address.
    open: struct { stream: net.Stream, index: usize },
    /// No connection opened: the last error (Timeout when the budget ran out) and the address it came from.
    failed: struct { err: anyerror, index: usize },
};

/// Happy Eyeballs over `addrs`, in the order given: the next attempt starts when an attempt fails or `delay`
/// after the latest attempt started, whichever is first; the first connection to open wins and the others are
/// canceled (one that opens late is closed). Gives up after `budget`. A dial that cannot get the threads for
/// its deadline or first attempt fails at once (error.ConcurrencyUnavailable) rather than run without a
/// budget. (Zig 0.17's threaded Io has no connect timeout option, so the attempts race timers.)
pub fn dialRace(io: Io, addrs: []const net.IpAddress, delay: Io.Duration, budget: Io.Duration) Io.Cancelable!Dialed {
    std.debug.assert(addrs.len > 0 and addrs.len <= max_dial);
    // Every task's result must fit: each attempt, each stagger timer (at most one per attempt) and the deadline.
    var buf: [2 * max_dial + 1]DialEvent = undefined;
    var sel: Io.Select(DialEvent) = .init(io, &buf);
    defer while (sel.cancel()) |late| switch (late) {
        .attempt => |a| if (a.result) |s| s.close(io) else |_| {},
        .stagger, .deadline => {},
    };
    var race: Race = .{ .sel = &sel, .io = io, .addrs = addrs, .delay = delay };

    sel.concurrent(.deadline, sleepFor, .{ io, budget }) catch |err|
        return .{ .failed = .{ .err = err, .index = 0 } };
    if (!race.startNext()) return race.last;
    race.armStagger();

    while (true) {
        switch (try sel.await()) {
            .attempt => |a| {
                race.running -= 1;
                if (a.result) |s| return .{ .open = .{ .stream = s, .index = a.index } } else |err| {
                    race.last = .{ .failed = .{ .err = err, .index = a.index } };
                }
                // A failed attempt hands over at once, and the next delay counts from there.
                if (race.startNext()) race.armStagger();
            },
            .stagger => |t| if (t.gen == race.gen) {
                if (race.startNext()) race.armStagger();
            },
            // The first address has waited longest; the receipt names it.
            .deadline => return .{ .failed = .{ .err = error.Timeout, .index = 0 } },
        }
        if (race.running == 0 and !race.startNext()) return race.last;
    }
}

const DialEvent = union(enum) {
    attempt: Attempt,
    stagger: Stagger,
    deadline: Io.Cancelable!void,
};

/// A stagger timer's end. Only the latest timer (`gen`) starts an attempt; an older one was overtaken by a
/// failure that started the next attempt early.
const Stagger = struct { gen: usize, result: Io.Cancelable!void };

fn staggerSleep(io: Io, d: Io.Duration, gen: usize) Stagger {
    return .{ .gen = gen, .result = io.sleep(d, .awake) };
}

const Race = struct {
    sel: *Io.Select(DialEvent),
    io: Io,
    addrs: []const net.IpAddress,
    delay: Io.Duration,
    next: usize = 0,
    running: usize = 0,
    /// The generation of the latest stagger timer.
    gen: usize = 0,
    last: Dialed = .{ .failed = .{ .err = error.Timeout, .index = 0 } },

    /// Starts the next address's attempt. False when no address is left or it could not start (that
    /// address then counts as failed).
    fn startNext(r: *Race) bool {
        if (r.next == r.addrs.len) return false;
        const i = r.next;
        r.next += 1;
        r.sel.concurrent(.attempt, attempt, .{ r.io, r.addrs[i], i }) catch |err| {
            r.last = .{ .failed = .{ .err = err, .index = i } };
            return false;
        };
        r.running += 1;
        return true;
    }

    /// Starts a new stagger timer, which supersedes any older one, while an address is left. Without it, the
    /// next address starts only when an attempt fails.
    fn armStagger(r: *Race) void {
        if (r.next == r.addrs.len) return;
        r.gen += 1;
        r.sel.concurrent(.stagger, staggerSleep, .{ r.io, r.delay, r.gen }) catch {};
    }
};

const Attempt = struct { index: usize, result: net.IpAddress.ConnectError!net.Stream };

fn attempt(io: Io, addr: net.IpAddress, index: usize) Attempt {
    return .{ .index = index, .result = addr.connect(io, .{ .mode = .stream }) };
}

/// Copies `addrs` into `out` with the address families alternating, starting with the family of the first
/// address; the order within each family is kept (RFC 8305, section 4).
pub fn interleaveFamilies(out: []net.IpAddress, addrs: []const net.IpAddress) []net.IpAddress {
    std.debug.assert(out.len >= addrs.len);
    if (addrs.len == 0) return out[0..0];
    const first = std.meta.activeTag(addrs[0]);
    var same: usize = 0; // next unused index of the first family
    var other: usize = 0; // next unused index of the other family
    var n: usize = 0;
    var want_first = true;
    while (n < addrs.len) {
        const pick_first = want_first;
        want_first = !want_first;
        const cursor = if (pick_first) &same else &other;
        while (cursor.* < addrs.len and (std.meta.activeTag(addrs[cursor.*]) == first) != pick_first) cursor.* += 1;
        if (cursor.* == addrs.len) continue;
        out[n] = addrs[cursor.*];
        n += 1;
        cursor.* += 1;
    }
    return out[0..n];
}

fn sleepFor(io: Io, d: Io.Duration) Io.Cancelable!void {
    return io.sleep(d, .awake);
}

/// Reuse the grant watchdog's bounded polling and reset semantics. A widening never
/// interrupts an allowed transfer. Retired slots keep their old immutable view.
fn watchPolicy(p: *Proxy, client: net.Stream, upstream: net.Stream, host: []const u8, ip: []const u8, port: u16) Io.Cancelable!void {
    const source = p.config.live.?;
    const resolved = if (ip.len > 0) policy.parseIpLiteral(ip) else null;
    while (true) {
        const view = source.current();
        if (view == null or !live_policy.permits(view.?, host, port, resolved)) {
            p.receipts.write(.{
                .event = "policy_changed",
                .point = p.config.receipt_point,
                .verdict = .deny,
                .reason = "policy_narrowed",
                .host = host,
                .ip = if (ip.len > 0) ip else null,
                .port = port,
                .detail = "connection_reset watchdog_ms=200",
                .decision = if (view) |v| v.decision else null,
                .executable = if (view) |v| v.executable else null,
            });
            // As with watchGrant, no receipt I/O follows shutdown: the pumps
            // wake and their close drops queued bytes with SO_LINGER=0.
            abortOnClose(upstream);
            abortOnClose(client);
            shutdownProtected(p.io, upstream, .both);
            shutdownProtected(p.io, client, .both);
            return;
        }
        try p.io.sleep(.fromMilliseconds(200), .awake);
    }
}

/// Closes a connection opened under a grant once the grant expires or is revoked, with a receipt. Follows
/// extensions: the deadline is re-read from the grant table on every tick.
/// `ip` and `port` repeat the connection's own receipt, so each reset can be matched to its connection.
fn watchGrant(p: *Proxy, id: u64, first_deadline: Io.Timestamp, client: net.Stream, upstream: net.Stream, event: []const u8, host: []const u8, ip: []const u8, port: u16) Io.Cancelable!void {
    const io = p.io;
    const g = p.config.grants.?;
    var deadline = first_deadline;
    const tick: Io.Duration = .fromMilliseconds(200);
    const reason: []const u8 = while (true) {
        const now = grants_mod.clock.now(io);
        if (g.deadlineOf(io, id)) |dl| {
            deadline = dl;
        } else {
            break if (now.nanoseconds >= deadline.nanoseconds) "grant_expired" else "grant_revoked";
        }
        if (now.nanoseconds >= deadline.nanoseconds) break "grant_expired";
        const left = now.durationTo(deadline);
        try io.sleep(if (left.nanoseconds < tick.nanoseconds) left else tick, grants_mod.clock);
    };
    p.receipts.write(.{
        .event = event,
        .point = p.config.receipt_point,
        .verdict = .deny,
        .reason = reason,
        .host = host,
        .ip = if (ip.len > 0) ip else null,
        .port = port,
        .detail = "connection_reset",
    });
    // A plain shutdown would still deliver what is queued in the socket buffers (on a loopback socket that can
    // be megabytes) before the FIN. With linger 0 the close that follows sends a reset and drops the queue.
    abortOnClose(upstream);
    abortOnClose(client);
    shutdownProtected(io, upstream, .both);
    shutdownProtected(io, client, .both);
}

/// Makes the socket's close send a reset and drop anything still queued, instead of delivering the queue and
/// then a FIN. The shutdown that follows wakes the pumps; the connection's own close then resets.
fn abortOnClose(stream: net.Stream) void {
    const l: std.posix.linger = .{ .onoff = 1, .linger = 0 };
    std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&l)) catch {};
}

/// Tests only: makes the grant watchdog fail to start.
pub var test_fail_watchdog: bool = false;

fn writeUpstreamHead(w: *Io.Writer, req: *http.Server.Request, url: HttpUrl) Io.Writer.Error!void {
    try w.print("{s} {s} HTTP/1.1\r\nhost: {s}\r\n", .{ @tagName(req.head.method), url.path, url.authority });

    // Headers named in Connection are hop-by-hop too.
    var named: [8][]const u8 = undefined;
    var named_len: usize = 0;
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, "connection")) continue;
        var tokens = std.mem.tokenizeAny(u8, h.value, ", \t");
        while (tokens.next()) |tok| {
            if (named_len < named.len) {
                named[named_len] = tok;
                named_len += 1;
            }
        }
    }

    it = req.iterateHeaders();
    outer: while (it.next()) |h| {
        for (hop_by_hop) |name| if (std.ascii.eqlIgnoreCase(h.name, name)) continue :outer;
        for (named[0..named_len]) |name| if (std.ascii.eqlIgnoreCase(h.name, name)) continue :outer;
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    if (req.head.method.requestHasBody()) {
        if (req.head.transfer_encoding == .chunked) {
            try w.writeAll("transfer-encoding: chunked\r\n");
        } else {
            try w.print("content-length: {d}\r\n", .{req.head.content_length orelse 0});
        }
    }
    try w.writeAll("connection: close\r\n\r\n");
}

/// The request target has only visible ASCII, every header name is a token, and no header value carries
/// a control character other than HTAB (so no bare CR or LF).
fn headIsClean(req: *const http.Server.Request) bool {
    for (req.head.target) |ch| if (ch <= 0x20 or ch >= 0x7f) return false;
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (h.name.len == 0) return false;
        for (h.name) |ch| if (!isTokenChar(ch)) return false;
        for (h.value) |ch| if ((ch < 0x20 and ch != '\t') or ch == 0x7f) return false;
    }
    return true;
}

fn isTokenChar(ch: u8) bool {
    return switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

const hop_by_hop = [_][]const u8{
    "host",                "connection",         "proxy-connection", "keep-alive",
    "proxy-authorization", "proxy-authenticate", "te",               "trailer",
    "transfer-encoding",   "upgrade",            "content-length",   "expect",
};

fn copyBody(body: *Io.Reader, w: *Io.Writer, chunked: bool) !void {
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try body.readSliceShort(&buf);
        if (n == 0) break;
        if (chunked) {
            try w.print("{x}\r\n", .{n});
            try w.writeAll(buf[0..n]);
            try w.writeAll("\r\n");
        } else {
            try w.writeAll(buf[0..n]);
        }
        if (n < buf.len) break;
    }
    if (chunked) try w.writeAll("0\r\n\r\n");
}

// ---------------------------------------------------------------- parsing

pub const Authority = struct {
    /// Without brackets for IPv6.
    host: []const u8,
    port: u16,
};

/// Parses "host:port", "[v6]:port", or, when `default_port` is given, a bare host.
pub fn parseAuthority(text: []const u8, default_port: ?u16) error{InvalidAuthority}!Authority {
    if (text.len == 0) return error.InvalidAuthority;
    var host: []const u8 = undefined;
    var rest: []const u8 = undefined;
    if (text[0] == '[') {
        const close = std.mem.findScalar(u8, text, ']') orelse return error.InvalidAuthority;
        host = text[1..close];
        rest = text[close + 1 ..];
    } else {
        if (std.mem.findScalar(u8, text, ':')) |colon| {
            if (std.mem.findScalarPos(u8, text, colon + 1, ':') != null) return error.InvalidAuthority;
            host = text[0..colon];
            rest = text[colon..];
        } else {
            host = text;
            rest = "";
        }
    }
    if (host.len == 0) return error.InvalidAuthority;
    for (host) |ch| if (ch <= ' ' or ch == '@' or ch == '/' or ch == 0x7f) return error.InvalidAuthority;
    var port: u16 = undefined;
    if (rest.len == 0) {
        port = default_port orelse return error.InvalidAuthority;
    } else {
        if (rest[0] != ':' or rest.len == 1) return error.InvalidAuthority;
        port = std.fmt.parseInt(u16, rest[1..], 10) catch return error.InvalidAuthority;
    }
    if (port == 0) return error.InvalidAuthority;
    return .{ .host = host, .port = port };
}

pub const HttpUrl = struct {
    /// As written, for the Host header.
    authority: []const u8,
    host: []const u8,
    port: u16,
    /// Origin form: path and query, "/" when empty.
    path: []const u8,
};

/// Origin-form requests need exactly one Host; no absolute URI or CONNECT tunnel is accepted.
pub fn originUrl(req: *const http.Server.Request) !HttpUrl {
    var host: ?[]const u8 = null;
    var it = req.iterateHeaders();
    while (it.next()) |h| if (std.ascii.eqlIgnoreCase(h.name, "host")) {
        if (host != null) return error.InvalidUrl;
        host = h.value;
    };
    return parseOriginTarget(req.head.target, host orelse return error.InvalidUrl);
}

pub fn parseOriginTarget(target: []const u8, host: []const u8) error{InvalidUrl}!HttpUrl {
    if (target.len == 0 or target[0] != '/' or std.mem.startsWith(u8, target, "//")) return error.InvalidUrl;
    for (target) |ch| if (ch <= 0x20 or ch >= 0x7f or ch == '#' or ch == '\\') return error.InvalidUrl;
    const auth = parseAuthority(host, 80) catch return error.InvalidUrl;
    if (auth.port != 80 or policy.parseIpLiteral(auth.host) != null) return error.InvalidUrl;
    return .{ .authority = host, .host = auth.host, .port = 80, .path = target };
}

pub fn parseHttpUrl(target: []const u8) error{ InvalidUrl, HttpsNeedsConnect }!HttpUrl {
    const scheme_end = std.mem.find(u8, target, "://") orelse return error.InvalidUrl;
    const scheme = target[0..scheme_end];
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return error.HttpsNeedsConnect;
    if (!std.ascii.eqlIgnoreCase(scheme, "http")) return error.InvalidUrl;
    const rest = target[scheme_end + 3 ..];
    const auth_end = std.mem.findAny(u8, rest, "/?#") orelse rest.len;
    const authority = rest[0..auth_end];
    const a = parseAuthority(authority, 80) catch return error.InvalidUrl;
    var path = rest[auth_end..];
    if (std.mem.findScalar(u8, path, '#')) |hash| path = path[0..hash];
    if (path.len == 0) path = "/";
    if (path[0] == '?') return error.InvalidUrl; // keep it simple: "http://h?q" is rare
    return .{ .authority = authority, .host = a.host, .port = a.port, .path = path };
}

/// Returns the server name of a TLS ClientHello record, or null when it carries none.
/// `record` is one complete TLS record, starting with its 5-byte header.
pub fn parseSni(record: []const u8) error{Malformed}!?[]const u8 {
    var r: ByteReader = .{ .data = record };
    if (try r.byte() != 0x16) return error.Malformed; // handshake
    _ = try r.int(u16); // record version
    const rec_len = try r.int(u16);
    var hs: ByteReader = .{ .data = try r.bytes(rec_len) };
    if (try hs.byte() != 0x01) return error.Malformed; // ClientHello
    const hs_len = try hs.int(u24);
    // A ClientHello split across records is refused rather than half-parsed.
    var ch: ByteReader = .{ .data = try hs.bytes(hs_len) };
    _ = try ch.int(u16); // legacy_version
    _ = try ch.bytes(32); // random
    _ = try ch.bytes(try ch.byte()); // session id
    _ = try ch.bytes(try ch.int(u16)); // cipher suites
    _ = try ch.bytes(try ch.byte()); // compression methods
    if (ch.pos == ch.data.len) return null; // no extensions
    var exts: ByteReader = .{ .data = try ch.bytes(try ch.int(u16)) };
    if (ch.pos != ch.data.len or hs.pos != hs.data.len or r.pos != r.data.len) return error.Malformed;
    var name_seen: ?[]const u8 = null;
    var server_name_seen = false;
    while (exts.pos < exts.data.len) {
        const ext_type = try exts.int(u16);
        const ext = try exts.bytes(try exts.int(u16));
        if (ext_type != 0) continue; // server_name
        if (server_name_seen) return error.Malformed;
        server_name_seen = true;
        var list_r: ByteReader = .{ .data = ext };
        var list: ByteReader = .{ .data = try list_r.bytes(try list_r.int(u16)) };
        if (list_r.pos != list_r.data.len) return error.Malformed;
        while (list.pos < list.data.len) {
            const name_type = try list.byte();
            const name = try list.bytes(try list.int(u16));
            if (name_type == 0) {
                if (name.len == 0 or name_seen != null) return error.Malformed;
                name_seen = name;
            }
        }
    }
    return name_seen;
}

const ByteReader = struct {
    data: []const u8,
    pos: usize = 0,

    fn byte(r: *ByteReader) error{Malformed}!u8 {
        if (r.pos >= r.data.len) return error.Malformed;
        r.pos += 1;
        return r.data[r.pos - 1];
    }

    fn int(r: *ByteReader, comptime T: type) error{Malformed}!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        const b = try r.bytes(n);
        return std.mem.readInt(T, b[0..n], .big);
    }

    fn bytes(r: *ByteReader, n: usize) error{Malformed}![]const u8 {
        if (r.data.len - r.pos < n) return error.Malformed;
        r.pos += n;
        return r.data[r.pos - n .. r.pos];
    }
};

/// The address without its port: "93.184.216.34" or "2606:2800::1".
pub fn formatIp(buf: *[64]u8, a: net.IpAddress) []const u8 {
    return switch (a) {
        .ip4 => |v| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3] }) catch unreachable,
        .ip6 => |v| std.fmt.bufPrint(buf, "{f}", .{net.Ip6Address.Unresolved{ .bytes = v.bytes, .interface_name = null }}) catch unreachable,
    };
}

fn systemResolve(io: Io, host: []const u8, port: u16, out: []net.IpAddress) !usize {
    const name = try net.HostName.init(host);
    // lookup does not block when the queue holds at least 16 results.
    var results: [32]net.HostName.LookupResult = undefined;
    var queue: Io.Queue(net.HostName.LookupResult) = .init(&results);
    try name.lookup(io, &queue, .{ .port = port });
    var n: usize = 0;
    while (queue.getOne(io)) |r| switch (r) {
        .address => |a| {
            if (n == out.len) continue;
            var dup = false;
            for (out[0..n]) |*o| {
                if (sameAddress(o.*, a)) dup = true;
            }
            if (!dup) {
                out[n] = a;
                n += 1;
            }
        },
        .canonical_name => {},
    } else |err| switch (err) {
        error.Canceled => |e| return e,
        error.Closed => {},
    }
    return n;
}

fn sameAddress(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |x| b == .ip4 and std.mem.eql(u8, &x.bytes, &b.ip4.bytes),
        .ip6 => |x| b == .ip6 and std.mem.eql(u8, &x.bytes, &b.ip6.bytes),
    };
}

/// Points the command at the proxy: HTTP_PROXY, HTTPS_PROXY, ALL_PROXY and their lowercase forms.
/// NO_PROXY is set to loopback only, replacing any inherited value: loopback stays direct (the backend
/// allows only the scope's own ports there), and an inherited NO_PROXY cannot send other hosts around
/// the proxy, where the backend would refuse them anyway.
pub fn setEnv(env: *std.process.Environ.Map, port: u16) error{OutOfMemory}!void {
    var buf: [32]u8 = undefined;
    const url = std.fmt.bufPrint(&buf, "http://127.0.0.1:{d}", .{port}) catch unreachable;
    for ([_][]const u8{ "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy" }) |k| {
        try env.put(k, url);
    }
    try env.put("NO_PROXY", no_proxy);
    try env.put("no_proxy", no_proxy);
}

pub const no_proxy = "localhost,127.0.0.1,::1";

test {
    _ = @import("test.zig");
}
