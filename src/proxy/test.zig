//! Proxy tests over real loopback sockets. Names resolve through a fixed table, so no test touches DNS
//! or the network.

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const testing = std.testing;
const policy = @import("../core/policy.zig");
const receipt = @import("../core/receipt.zig");
const proxy = @import("proxy.zig");

// ---------------------------------------------------------------- unit tests

test "parseAuthority" {
    const a = try proxy.parseAuthority("Example.com:443", null);
    try testing.expectEqualStrings("Example.com", a.host);
    try testing.expectEqual(@as(u16, 443), a.port);
    const b = try proxy.parseAuthority("[2001:db8::1]:8443", null);
    try testing.expectEqualStrings("2001:db8::1", b.host);
    try testing.expectEqual(@as(u16, 8443), b.port);
    try testing.expectEqual(@as(u16, 80), (try proxy.parseAuthority("example.com", 80)).port);
    try testing.expectError(error.InvalidAuthority, proxy.parseAuthority("example.com", null));
    try testing.expectError(error.InvalidAuthority, proxy.parseAuthority("example.com:0", null));
    try testing.expectError(error.InvalidAuthority, proxy.parseAuthority("example.com:99999", null));
    try testing.expectError(error.InvalidAuthority, proxy.parseAuthority("2001:db8::1:443", null));
    try testing.expectError(error.InvalidAuthority, proxy.parseAuthority("user@example.com:443", null));
    try testing.expectError(error.InvalidAuthority, proxy.parseAuthority(":443", null));
}

test "parseHttpUrl" {
    const u = try proxy.parseHttpUrl("http://Example.com:8080/a/b?c=d#frag");
    try testing.expectEqualStrings("Example.com:8080", u.authority);
    try testing.expectEqualStrings("Example.com", u.host);
    try testing.expectEqual(@as(u16, 8080), u.port);
    try testing.expectEqualStrings("/a/b?c=d", u.path);
    const v = try proxy.parseHttpUrl("HTTP://example.com");
    try testing.expectEqualStrings("/", v.path);
    try testing.expectEqual(@as(u16, 80), v.port);
    try testing.expectError(error.HttpsNeedsConnect, proxy.parseHttpUrl("https://example.com/"));
    try testing.expectError(error.InvalidUrl, proxy.parseHttpUrl("/relative"));
    try testing.expectError(error.InvalidUrl, proxy.parseHttpUrl("ftp://example.com/"));
    try testing.expectError(error.InvalidUrl, proxy.parseHttpUrl("http://user:pw@example.com/"));
}

/// A minimal TLS 1.3-style ClientHello record, with or without a server_name extension.
fn clientHello(buf: []u8, sni: ?[]const u8) []const u8 {
    var w: Io.Writer = .fixed(buf);
    var body_buf: [512]u8 = undefined;
    var body: Io.Writer = .fixed(&body_buf);
    body.writeInt(u16, 0x0303, .big) catch unreachable;
    body.splatByteAll(0xab, 32) catch unreachable; // random
    body.writeByte(0) catch unreachable; // session id
    body.writeInt(u16, 2, .big) catch unreachable;
    body.writeInt(u16, 0x1301, .big) catch unreachable; // TLS_AES_128_GCM_SHA256
    body.writeByte(1) catch unreachable;
    body.writeByte(0) catch unreachable; // null compression
    var ext_buf: [300]u8 = undefined;
    var ext: Io.Writer = .fixed(&ext_buf);
    // supported_versions first, so the parser has to skip an extension.
    ext.writeInt(u16, 43, .big) catch unreachable;
    ext.writeInt(u16, 3, .big) catch unreachable;
    ext.writeByte(2) catch unreachable;
    ext.writeInt(u16, 0x0304, .big) catch unreachable;
    if (sni) |name| {
        ext.writeInt(u16, 0, .big) catch unreachable;
        ext.writeInt(u16, @intCast(name.len + 5), .big) catch unreachable;
        ext.writeInt(u16, @intCast(name.len + 3), .big) catch unreachable;
        ext.writeByte(0) catch unreachable;
        ext.writeInt(u16, @intCast(name.len), .big) catch unreachable;
        ext.writeAll(name) catch unreachable;
    }
    body.writeInt(u16, @intCast(ext.end), .big) catch unreachable;
    body.writeAll(ext.buffered()) catch unreachable;

    w.writeByte(0x16) catch unreachable;
    w.writeInt(u16, 0x0301, .big) catch unreachable;
    w.writeInt(u16, @intCast(body.end + 4), .big) catch unreachable;
    w.writeByte(0x01) catch unreachable;
    w.writeInt(u24, @intCast(body.end), .big) catch unreachable;
    w.writeAll(body.buffered()) catch unreachable;
    return w.buffered();
}

test "parseSni" {
    var buf: [600]u8 = undefined;
    try testing.expectEqualStrings("api.example.com", (try proxy.parseSni(clientHello(&buf, "api.example.com"))).?);
    try testing.expectEqual(@as(?[]const u8, null), try proxy.parseSni(clientHello(&buf, null)));
    const full = clientHello(&buf, "api.example.com");
    try testing.expectError(error.Malformed, proxy.parseSni(full[0 .. full.len - 3]));
    try testing.expectError(error.Malformed, proxy.parseSni("GET / HTTP/1.1\r\n"));
}

test "setEnv points every proxy variable at the proxy and keeps loopback direct" {
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("NO_PROXY", "internal.corp");
    try proxy.setEnv(&env, 18781);
    for ([_][]const u8{ "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy" }) |k| {
        try testing.expectEqualStrings("http://127.0.0.1:18781", env.get(k).?);
    }
    try testing.expectEqualStrings(proxy.no_proxy, env.get("NO_PROXY").?);
    try testing.expectEqualStrings(proxy.no_proxy, env.get("no_proxy").?);
}

// ---------------------------------------------------------------- loopback fixtures

/// Accepts connections and runs `handler` on each, until stopped.
const TestServer = struct {
    io: Io,
    server: net.Server,
    port: u16,
    group: Io.Group = .init,
    kind: Kind,
    /// Connections accepted.
    accepted: std.atomic.Value(u32) = .init(0),
    /// Bytes the echo handler received, over all connections.
    received: std.atomic.Value(usize) = .init(0),
    /// Bytes the flood handler managed to send, over all connections.
    sent: std.atomic.Value(usize) = .init(0),
    /// The last request head the HTTP handler saw.
    last_head: [4096]u8 = undefined,
    last_head_len: usize = 0,

    const Kind = enum { echo, http, slow_http, flood };

    fn start(ts: *TestServer, io: Io, kind: Kind) !void {
        const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
        const server = try addr.listen(io, .{});
        ts.* = .{ .io = io, .server = server, .port = server.socket.address.getPort(), .kind = kind };
        try ts.group.concurrent(io, loop, .{ts});
    }

    fn stop(ts: *TestServer) void {
        ts.group.cancel(ts.io);
        ts.server.deinit(ts.io);
    }

    fn loop(ts: *TestServer) Io.Cancelable!void {
        while (true) {
            const s = ts.server.accept(ts.io) catch |err| switch (err) {
                error.Canceled => |e| return e,
                else => return,
            };
            _ = ts.accepted.fetchAdd(1, .monotonic);
            ts.group.concurrent(ts.io, handle, .{ ts.io, s, ts }) catch s.close(ts.io);
        }
    }

    fn handle(io: Io, s: net.Stream, ts: *TestServer) Io.Cancelable!void {
        return switch (ts.kind) {
            .echo => echoHandler(io, s, ts),
            .http => httpHandler(io, s, ts, false),
            .slow_http => httpHandler(io, s, ts, true),
            .flood => floodHandler(io, s, ts),
        };
    }

    fn head(ts: *TestServer) []const u8 {
        return ts.last_head[0..ts.last_head_len];
    }
};

fn echoHandler(io: Io, s: net.Stream, ctx: *TestServer) Io.Cancelable!void {
    defer s.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var r = s.reader(io, &rbuf);
    var w = s.writer(io, &wbuf);
    while (true) {
        const data = r.interface.peekGreedy(1) catch return;
        _ = ctx.received.fetchAdd(data.len, .monotonic);
        w.interface.writeAll(data) catch return;
        w.interface.flush() catch return;
        r.interface.toss(data.len);
    }
}

/// Waits for the client's first bytes, then sends as much as the connection takes (up to 256 MiB).
fn floodHandler(io: Io, s: net.Stream, ctx: *TestServer) Io.Cancelable!void {
    defer s.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var r = s.reader(io, &rbuf);
    var w = s.writer(io, &wbuf);
    _ = r.interface.peekGreedy(1) catch return;
    const chunk: [64 * 1024]u8 = @splat('x');
    var total: usize = 0;
    while (total < 256 << 20) : (total += chunk.len) {
        w.interface.writeAll(&chunk) catch return;
        _ = ctx.sent.fetchAdd(chunk.len, .monotonic);
    }
}

fn httpHandler(io: Io, s: net.Stream, ctx: *TestServer, slow: bool) Io.Cancelable!void {
    defer s.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [512]u8 = undefined;
    var r = s.reader(io, &rbuf);
    var w = s.writer(io, &wbuf);
    var len: usize = 0;
    while (true) {
        const line = r.interface.takeDelimiterInclusive('\n') catch return;
        if (len + line.len <= ctx.last_head.len) {
            @memcpy(ctx.last_head[len..][0..line.len], line);
            len += line.len;
        }
        if (std.mem.eql(u8, line, "\r\n")) break;
    }
    ctx.last_head_len = len;
    if (slow) try io.sleep(.fromSeconds(3), .awake);
    w.interface.writeAll("HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nupstream") catch return;
    w.interface.flush() catch return;
}

const names = [_]struct { []const u8, []const u8 }{
    .{ "allowed.test", "127.0.0.1" },
    .{ "granted.test", "127.0.0.1" },
    .{ "private.test", "10.1.2.3" },
    .{ "mixed.test", "10.9.9.9" },
};

fn fixedResolve(context: ?*anyopaque, io: Io, host: []const u8, port: u16, out: []net.IpAddress) anyerror!usize {
    _ = context;
    _ = io;
    var n: usize = 0;
    for (names) |entry| {
        if (!std.mem.eql(u8, entry[0], host)) continue;
        out[n] = try net.IpAddress.parse(entry[1], port);
        n += 1;
    }
    // mixed.test also resolves to loopback; the private answer must be skipped, not fatal.
    if (std.mem.eql(u8, host, "mixed.test")) {
        out[n] = try net.IpAddress.parse("127.0.0.1", port);
        n += 1;
    }
    // hole.test answers first with an address that drops connections (see Hole), then with the upstream;
    // blackhole.test only with the dropping one.
    if (std.mem.eql(u8, host, "hole.test") or std.mem.eql(u8, host, "blackhole.test")) {
        out[n] = try net.IpAddress.parse("::1", port);
        n += 1;
        if (host[0] == 'h') {
            out[n] = try net.IpAddress.parse("127.0.0.1", port);
            n += 1;
        }
    }
    if (n == 0) return error.UnknownHostName;
    return n;
}

const Harness = struct {
    io: Io,
    tmp: testing.TmpDir,
    pol: policy.Policy,
    log: receipt.Log,
    grants: proxy.Grants,
    p: *proxy.Proxy,

    fn init(h: *Harness, policy_json: []const u8) !void {
        return h.initConfig(policy_json, .{});
    }

    /// `cfg` with the test resolver and the harness's grant table filled in.
    fn initConfig(h: *Harness, policy_json: []const u8, cfg: proxy.Config) !void {
        h.io = testing.io;
        h.tmp = testing.tmpDir(.{});
        errdefer h.tmp.cleanup();
        h.pol = try policy.Policy.parse(testing.allocator, policy_json, null);
        errdefer h.pol.deinit();
        h.log = try receipt.Log.open(h.io, h.tmp.dir, "receipts.jsonl", "s-test0001", h.pol.id());
        errdefer h.log.close();
        h.grants = .init(testing.allocator);
        var c = cfg;
        if (c.resolver == null) c.resolver = .{ .resolve = fixedResolve };
        c.grants = if (c.live == null) &h.grants else null;
        h.p = try proxy.Proxy.start(testing.allocator, h.io, &h.pol, &h.log, c);
    }

    fn deinit(h: *Harness) void {
        h.p.stop();
        h.grants.deinit();
        h.log.close();
        h.pol.deinit();
        h.tmp.cleanup();
    }

    fn receipts(h: *Harness) ![]u8 {
        return h.tmp.dir.readFileAlloc(h.io, "receipts.jsonl", testing.allocator, .limited(1 << 20));
    }

    /// The n-th receipt line (0-based), parsed. Caller deinits.
    fn receiptAt(h: *Harness, n: usize) !std.json.Parsed(std.json.Value) {
        const bytes = try h.receipts();
        defer testing.allocator.free(bytes);
        var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, bytes, "\n"), '\n');
        var i: usize = 0;
        while (it.next()) |line| : (i += 1) {
            if (i == n) return std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
        }
        return error.MissingReceipt;
    }

    fn receiptCount(h: *Harness) !usize {
        const bytes = try h.receipts();
        defer testing.allocator.free(bytes);
        return std.mem.count(u8, bytes, "\n");
    }

    /// Waits up to 3 s for at least `n` receipt lines.
    fn waitReceipts(h: *Harness, n: usize) !void {
        var tries: usize = 0;
        while (tries < 300) : (tries += 1) {
            const bytes = try h.receipts();
            defer testing.allocator.free(bytes);
            if (std.mem.count(u8, bytes, "\n") >= n) return;
            try h.io.sleep(.fromMilliseconds(10), .awake);
        }
        return error.MissingReceipt;
    }

    fn connect(h: *Harness) !net.Stream {
        const addr: net.IpAddress = .{ .ip4 = .loopback(h.p.port) };
        return addr.connect(h.io, .{ .mode = .stream });
    }
};

const Client = struct {
    stream: net.Stream,
    rbuf: [8192]u8 = undefined,
    wbuf: [8192]u8 = undefined,
    r: net.Stream.Reader = undefined,
    w: net.Stream.Writer = undefined,

    fn init(c: *Client, io: Io, stream: net.Stream) void {
        c.stream = stream;
        c.r = stream.reader(io, &c.rbuf);
        c.w = stream.writer(io, &c.wbuf);
    }

    fn send(c: *Client, bytes: []const u8) !void {
        try c.w.interface.writeAll(bytes);
        try c.w.interface.flush();
    }

    /// Reads a response head and returns its status line (without CRLF), copied into `out`.
    fn status(c: *Client, out: []u8) ![]const u8 {
        const first = try c.r.interface.takeDelimiterInclusive('\n');
        const line = std.mem.trimEnd(u8, first, "\r\n");
        @memcpy(out[0..line.len], line);
        while (true) {
            const l = try c.r.interface.takeDelimiterInclusive('\n');
            if (std.mem.eql(u8, l, "\r\n")) break;
        }
        return out[0..line.len];
    }

    fn rest(c: *Client) ![]u8 {
        return c.r.interface.allocRemaining(testing.allocator, .limited(1 << 16));
    }

    const End = struct { bytes: usize, reset: bool };

    /// Reads until the proxy ends the connection, by FIN or by reset, and counts the bytes that arrived.
    fn untilClosed(c: *Client) !End {
        var n: usize = 0;
        while (true) {
            const data = c.r.interface.peekGreedy(1) catch |err| switch (err) {
                error.EndOfStream => return .{ .bytes = n, .reset = false },
                error.ReadFailed => {
                    if (c.r.err) |e| if (e == error.ConnectionResetByPeer) return .{ .bytes = n, .reset = true };
                    return err;
                },
            };
            n += data.len;
            c.r.interface.toss(data.len);
        }
    }
};

fn expectField(v: std.json.Value, key: []const u8, want: []const u8) !void {
    const got = v.object.get(key) orelse {
        std.debug.print("receipt has no \"{s}\"\n", .{key});
        return error.TestExpectedEqual;
    };
    try testing.expectEqualStrings(want, got.string);
}

/// The test policy, with the stand-in upstream's port added to the default ports.
fn testPolicy(buf: []u8, upstream_port: u16) []const u8 {
    return std.fmt.bufPrint(buf,
        \\{{"version":"blackice.policy/v0","network":{{"mode":"allowlist",
        \\ "allow":["allowed.test","private.test","mixed.test"],
        \\ "subnets":{{"allow":["127.0.0.0/8"]}},"ports":[80,443,{d}]}}}}
    , .{upstream_port}) catch unreachable;
}

// ---------------------------------------------------------------- integration tests

const LiveCell = struct {
    current: std.atomic.Value(*const proxy.live_policy.Binding),
    paused: std.atomic.Value(bool) = .init(false),
    fn read(ctx: *const anyopaque, _: usize) ?proxy.live_policy.Binding {
        const cell: *const LiveCell = @ptrCast(@alignCast(ctx));
        return cell.current.load(.acquire).*;
    }
    fn source(cell: *LiveCell) proxy.live_policy.Source {
        return .{ .context = cell, .slot = 0, .read = read, .paused = &cell.paused };
    }
};

fn liveTestPolicy(buf: []u8, port: u16, hosts: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "{{\"version\":\"blackice.policy/v0\",\"network\":{{\"mode\":\"allowlist\",\"allow\":[{s}],\"ports\":[{d}],\"subnets\":{{\"allow\":[\"127.0.0.0/8\"]}}}}}}", .{ hosts, port }) catch unreachable;
}

test "live policy widening keeps tunnels and narrowing resets only the newly refused host" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var buf: [600]u8 = undefined;
    var initial = try policy.Policy.parse(testing.allocator, liveTestPolicy(&buf, up.port, "\"allowed.test\",\"granted.test\""), null);
    defer initial.deinit();
    var widened = try policy.Policy.parse(testing.allocator, liveTestPolicy(&buf, up.port, "\"allowed.test\",\"granted.test\",\"other.test\""), null);
    defer widened.deinit();
    var narrowed = try policy.Policy.parse(testing.allocator, liveTestPolicy(&buf, up.port, "\"allowed.test\""), null);
    defer narrowed.deinit();
    const views = [_]proxy.live_policy.Binding{
        .{ .policy = &initial, .decision = .{ .policy = &initial.digest_hex, .generation = 1 }, .executable = "/usr/bin/probe" },
        .{ .policy = &widened, .decision = .{ .policy = &widened.digest_hex, .generation = 2 }, .executable = "/usr/bin/probe" },
        .{ .policy = &narrowed, .decision = .{ .policy = &narrowed.digest_hex, .generation = 3 }, .executable = "/usr/bin/probe" },
    };
    var cell: LiveCell = .{ .current = .init(&views[0]) };
    var h: Harness = undefined;
    try h.initConfig(liveTestPolicy(&buf, up.port, "\"allowed.test\",\"granted.test\""), .{ .live = cell.source() });
    defer h.deinit();
    var clients: [2]Client = undefined;
    for (&clients, [_][]const u8{ "allowed.test", "granted.test" }) |*c, host| {
        c.init(h.io, try h.connect());
        var request: [128]u8 = undefined;
        try c.send(try std.fmt.bufPrint(&request, "CONNECT {s}:{d} HTTP/1.1\r\n\r\n", .{ host, up.port }));
        var status: [128]u8 = undefined;
        try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&status));
        var hello_buf: [600]u8 = undefined;
        const hello = clientHello(&hello_buf, host);
        try c.send(hello);
        try testing.expectEqualSlices(u8, hello, try c.r.interface.take(hello.len));
    }
    defer for (clients) |c| c.stream.close(h.io);
    cell.current.store(&views[1], .release);
    try h.io.sleep(.fromMilliseconds(250), .awake);
    for (&clients) |*c| {
        try c.send("wide");
        try testing.expectEqualStrings("wide", try c.r.interface.take(4));
    }
    cell.current.store(&views[2], .release);
    const start = Io.Clock.awake.now(h.io);
    try testing.expectEqual(@as(usize, 0), (try clients[1].untilClosed()).bytes);
    try testing.expect(start.untilNow(h.io, .awake).toMilliseconds() < 1500);
    try clients[0].send("still-allowed");
    try testing.expectEqualStrings("still-allowed", try clients[0].r.interface.take(13));
    try h.waitReceipts(3);
    for (0..2) |i| {
        var row = try h.receiptAt(i);
        defer row.deinit();
        try testing.expectEqual(@as(i64, 1), row.value.object.get("gen").?.integer);
    }
    var reset = try h.receiptAt(2);
    defer reset.deinit();
    try expectField(reset.value, "event", "policy_changed");
    try expectField(reset.value, "reason", "policy_narrowed");
    try expectField(reset.value, "host", "granted.test");
    try expectField(reset.value, "policy", &narrowed.digest_hex);
    try testing.expectEqual(@as(i64, 3), reset.value.object.get("gen").?.integer);
}

test "live policy decides a connection opened before a change with the policy in force when its request arrives" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var buf: [600]u8 = undefined;
    var initial = try policy.Policy.parse(testing.allocator, liveTestPolicy(&buf, up.port, "\"allowed.test\",\"granted.test\""), null);
    defer initial.deinit();
    var narrowed = try policy.Policy.parse(testing.allocator, liveTestPolicy(&buf, up.port, "\"allowed.test\""), null);
    defer narrowed.deinit();
    const views = [_]proxy.live_policy.Binding{
        .{ .policy = &initial, .decision = .{ .policy = &initial.digest_hex, .generation = 1 }, .executable = "/usr/bin/probe" },
        .{ .policy = &narrowed, .decision = .{ .policy = &narrowed.digest_hex, .generation = 2 }, .executable = "/usr/bin/probe" },
    };
    var cell: LiveCell = .{ .current = .init(&views[0]) };
    var h: Harness = undefined;
    try h.initConfig(liveTestPolicy(&buf, up.port, "\"allowed.test\",\"granted.test\""), .{ .live = cell.source() });
    defer h.deinit();
    var request: [128]u8 = undefined;
    var status: [128]u8 = undefined;

    // Accepted under generation 1. The request arrives after generation 2 drops granted.test.
    var before: Client = undefined;
    before.init(h.io, try h.connect());
    defer before.stream.close(h.io);
    try h.io.sleep(.fromMilliseconds(150), .awake);
    cell.current.store(&views[1], .release);
    try before.send(try std.fmt.bufPrint(&request, "CONNECT granted.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    try testing.expectEqualStrings("HTTP/1.1 403 Forbidden", try before.status(&status));

    // Accepted before a change starts, request sent while the change is being published: refused.
    var during: Client = undefined;
    during.init(h.io, try h.connect());
    defer during.stream.close(h.io);
    try h.io.sleep(.fromMilliseconds(150), .awake);
    cell.paused.store(true, .release);
    try during.send(try std.fmt.bufPrint(&request, "CONNECT allowed.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    try testing.expectEqualStrings("HTTP/1.1 503 Service Unavailable", try during.status(&status));
    cell.paused.store(false, .release);

    // Neither request reached the upstream, and each has exactly one receipt, at generation 2: no allow line
    // from generation 1 and no reset line, because nothing was dialed.
    try h.io.sleep(.fromMilliseconds(300), .awake);
    try testing.expectEqual(@as(u32, 0), up.accepted.load(.monotonic));
    try testing.expectEqual(@as(usize, 2), try h.receiptCount());
    var refused = try h.receiptAt(0);
    defer refused.deinit();
    try expectField(refused.value, "event", "connect");
    try expectField(refused.value, "verdict", "deny");
    try expectField(refused.value, "reason", "no_matching_rule");
    try expectField(refused.value, "host", "granted.test");
    try expectField(refused.value, "policy", &narrowed.digest_hex);
    try testing.expectEqual(@as(i64, 2), refused.value.object.get("gen").?.integer);
    var paused = try h.receiptAt(1);
    defer paused.deinit();
    try expectField(paused.value, "verdict", "deny");
    try expectField(paused.value, "reason", "policy_change_in_progress");
    try expectField(paused.value, "host", "allowed.test");
    try testing.expectEqual(@as(i64, 2), paused.value.object.get("gen").?.integer);
}

/// Publishes another binding while the proxy resolves a name, as a policy change landing mid-dial would.
const ChangeOnResolve = struct {
    cell: *LiveCell,
    to: *const proxy.live_policy.Binding,
    fn resolve(context: ?*anyopaque, io: Io, host: []const u8, port: u16, out: []net.IpAddress) anyerror!usize {
        const self: *ChangeOnResolve = @ptrCast(@alignCast(context.?));
        const n = try fixedResolve(null, io, host, port, out);
        self.cell.current.store(self.to, .release);
        return n;
    }
};

test "live policy narrowing published during the dial refuses before any byte reaches the upstream" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var buf: [600]u8 = undefined;
    var initial = try policy.Policy.parse(testing.allocator, liveTestPolicy(&buf, up.port, "\"allowed.test\",\"granted.test\""), null);
    defer initial.deinit();
    var narrowed = try policy.Policy.parse(testing.allocator, liveTestPolicy(&buf, up.port, "\"allowed.test\""), null);
    defer narrowed.deinit();
    const views = [_]proxy.live_policy.Binding{
        .{ .policy = &initial, .decision = .{ .policy = &initial.digest_hex, .generation = 1 }, .executable = "/usr/bin/probe" },
        .{ .policy = &narrowed, .decision = .{ .policy = &narrowed.digest_hex, .generation = 2 }, .executable = "/usr/bin/probe" },
    };
    var cell: LiveCell = .{ .current = .init(&views[0]) };
    var change: ChangeOnResolve = .{ .cell = &cell, .to = &views[1] };
    var h: Harness = undefined;
    try h.initConfig(liveTestPolicy(&buf, up.port, "\"allowed.test\",\"granted.test\""), .{
        .live = cell.source(),
        .resolver = .{ .context = &change, .resolve = ChangeOnResolve.resolve },
    });
    defer h.deinit();
    var request: [160]u8 = undefined;
    var status: [128]u8 = undefined;
    const forms = [_][]const u8{
        "GET http://granted.test:{d}/ HTTP/1.1\r\nhost: granted.test\r\n\r\n",
        "CONNECT granted.test:{d} HTTP/1.1\r\n\r\n",
    };
    inline for (forms, 0..) |form, i| {
        cell.current.store(&views[0], .release);
        var c: Client = undefined;
        c.init(h.io, try h.connect());
        defer c.stream.close(h.io);
        try c.send(try std.fmt.bufPrint(&request, form, .{up.port}));
        try testing.expectEqualStrings("HTTP/1.1 403 Forbidden", try c.status(&status));
        var tries: usize = 0;
        while (up.accepted.load(.monotonic) < i + 1 and tries < 100) : (tries += 1) try h.io.sleep(.fromMilliseconds(10), .awake);
        try testing.expectEqual(@as(u32, i + 1), up.accepted.load(.monotonic));
    }
    try h.io.sleep(.fromMilliseconds(300), .awake);
    try testing.expectEqual(@as(usize, 0), up.received.load(.monotonic));
    try testing.expectEqual(@as(usize, 2), try h.receiptCount());
    for ([_][]const u8{ "http", "connect" }, 0..) |event, i| {
        var row = try h.receiptAt(i);
        defer row.deinit();
        try expectField(row.value, "event", event);
        try expectField(row.value, "verdict", "deny");
        try expectField(row.value, "reason", "no_matching_rule");
        try expectField(row.value, "host", "granted.test");
        try testing.expect(std.mem.find(u8, row.value.object.get("detail").?.string, "rechecked_after_dial") != null);
        try testing.expectEqual(@as(i64, 2), row.value.object.get("gen").?.integer);
    }
}

test "live policy narrowing drops queued bytes with the grant watchdog reset mechanism" {
    var up: TestServer = undefined;
    try up.start(testing.io, .flood);
    defer up.stop();
    var buf: [600]u8 = undefined;
    var initial = try policy.Policy.parse(testing.allocator, liveTestPolicy(&buf, up.port, "\"allowed.test\""), null);
    defer initial.deinit();
    var narrowed = try policy.Policy.parse(testing.allocator, liveTestPolicy(&buf, up.port, "\"other.test\""), null);
    defer narrowed.deinit();
    const views = [_]proxy.live_policy.Binding{
        .{ .policy = &initial, .decision = .{ .policy = &initial.digest_hex, .generation = 1 }, .executable = "/usr/bin/probe" },
        .{ .policy = &narrowed, .decision = .{ .policy = &narrowed.digest_hex, .generation = 2 }, .executable = "/usr/bin/probe" },
    };
    var cell: LiveCell = .{ .current = .init(&views[0]) };
    var h: Harness = undefined;
    try h.initConfig(liveTestPolicy(&buf, up.port, "\"allowed.test\""), .{ .live = cell.source() });
    defer h.deinit();
    var c: Client = undefined;
    c.init(h.io, try h.connect());
    defer c.stream.close(h.io);
    var request: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&request, "CONNECT allowed.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var status: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&status));
    var hello_buf: [600]u8 = undefined;
    try c.send(clientHello(&hello_buf, "allowed.test"));
    try h.waitReceipts(1);
    try h.io.sleep(.fromMilliseconds(250), .awake);
    cell.current.store(&views[1], .release);
    try h.waitReceipts(2);
    try h.io.sleep(.fromMilliseconds(250), .awake);
    const sent = up.sent.load(.monotonic);
    const end = try c.untilClosed();
    try testing.expect(end.reset);
    try testing.expect(end.bytes < sent);
    try testing.expectEqual(sent, up.sent.load(.monotonic));
    var row = try h.receiptAt(1);
    defer row.deinit();
    try expectField(row.value, "reason", "policy_narrowed");
    try testing.expectEqual(@as(i64, 2), row.value.object.get("gen").?.integer);
}

test "CONNECT to a name outside the policy is refused with 403 and a receipt" {
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, 443));
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    try c.send("CONNECT attacker.test:443 HTTP/1.1\r\nhost: attacker.test:443\r\n\r\n");
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 403 Forbidden", try c.status(&sbuf));

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "point", "proxy");
    try expectField(r.value, "event", "connect");
    try expectField(r.value, "verdict", "deny");
    try expectField(r.value, "reason", "no_matching_rule");
    try expectField(r.value, "host", "attacker.test");
    try testing.expectEqual(@as(i64, 443), r.value.object.get("port").?.integer);
}

test "an allowed name that resolves to a private address is refused" {
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, 443));
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    try c.send("CONNECT Private.Test.:443 HTTP/1.1\r\n\r\n");
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 403 Forbidden", try c.status(&sbuf));
    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "deny");
    try expectField(r.value, "reason", "local_or_private_address");
    try expectField(r.value, "host", "private.test");
    try expectField(r.value, "ip", "10.1.2.3");
}

test "CONNECT to an allowed name tunnels bytes to the checked address" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT mixed.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
    var hello_buf: [600]u8 = undefined;
    const hello = clientHello(&hello_buf, "mixed.test");
    try c.send(hello);
    try testing.expectEqualSlices(u8, hello, try c.r.interface.take(hello.len));

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "allow");
    try expectField(r.value, "reason", "allowed_by_rule");
    try expectField(r.value, "rule", "mixed.test");
    try expectField(r.value, "ip", "127.0.0.1");
    try expectField(r.value, "detail", "sni_match");
}

test "CONNECT carries TLS only: other bytes close the tunnel" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT allowed.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
    try c.send("SSH-2.0-OpenSSH_9.9\r\n");
    const after = try c.rest();
    defer testing.allocator.free(after);
    try testing.expectEqual(@as(usize, 0), after.len);

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "deny");
    try expectField(r.value, "reason", "not_tls");
    try expectField(r.value, "host", "allowed.test");
    try testing.expectEqual(@as(usize, 0), up.received.load(.monotonic));
}

test "a ClientHello without a server name is refused for a name" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT allowed.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
    var hello_buf: [600]u8 = undefined;
    try c.send(clientHello(&hello_buf, null));
    const after = try c.rest();
    defer testing.allocator.free(after);
    try testing.expectEqual(@as(usize, 0), after.len);
    try testing.expectEqual(@as(usize, 0), up.received.load(.monotonic));

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "deny");
    try expectField(r.value, "reason", "sni_missing");
}

test "TLS server name must match the CONNECT host" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    var hello_buf: [600]u8 = undefined;
    var req_buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "CONNECT allowed.test:{d} HTTP/1.1\r\n\r\n", .{up.port});
    var sbuf: [128]u8 = undefined;

    {
        // Matching SNI (case and trailing dot normalized): the ClientHello reaches the upstream untouched.
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send(req);
        try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
        const hello = clientHello(&hello_buf, "Allowed.Test.");
        try c.send(hello);
        const echoed = try c.r.interface.take(hello.len);
        try testing.expectEqualSlices(u8, hello, echoed);
        var r = try h.receiptAt(0);
        defer r.deinit();
        try expectField(r.value, "verdict", "allow");
        try expectField(r.value, "detail", "sni_match");
    }
    {
        // Another name in the SNI: the tunnel closes before a byte reaches the upstream.
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send(req);
        try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
        try c.send(clientHello(&hello_buf, "evil.test"));
        const after = try c.rest();
        defer testing.allocator.free(after);
        try testing.expectEqual(@as(usize, 0), after.len);
        var r = try h.receiptAt(1);
        defer r.deinit();
        try expectField(r.value, "verdict", "deny");
        try expectField(r.value, "reason", "sni_mismatch");
        try expectField(r.value, "host", "allowed.test");
        try expectField(r.value, "detail", "sni=evil.test");
    }
}

test "plain HTTP: Host comes from the URI and proxy headers are dropped" {
    var up: TestServer = undefined;
    try up.start(testing.io, .http);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    var req_buf: [512]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "GET http://allowed.test:{d}/path?q=1 HTTP/1.1\r\n" ++
        "Host: evil.test\r\nProxy-Authorization: Basic c2VjcmV0\r\nProxy-Connection: keep-alive\r\n" ++
        "Connection: x-drop-me\r\nX-Drop-Me: 1\r\nUser-Agent: test\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 OK", try c.status(&sbuf));
    const body = try c.rest();
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("upstream", body);

    var want_buf: [256]u8 = undefined;
    const want = try std.fmt.bufPrint(&want_buf, "GET /path?q=1 HTTP/1.1\r\nhost: allowed.test:{d}\r\n" ++
        "User-Agent: test\r\nconnection: close\r\n\r\n", .{up.port});
    try testing.expectEqualStrings(want, up.head());

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "event", "http");
    try expectField(r.value, "verdict", "allow");
    try expectField(r.value, "detail", "method=GET");
}

test "plain HTTP heads with bare CR or LF, or bad header names, never reach the upstream" {
    var up: TestServer = undefined;
    try up.start(testing.io, .http);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    const reqs = [_][]const u8{
        // A bare LF ends the request line early: an upstream that accepts it would see Host: evil.test first.
        try std.fmt.allocPrint(testing.allocator, "GET http://allowed.test:{d}/x HTTP/1.1\nHost: evil.test\nX: y HTTP/1.1\r\nUser-Agent: t\r\n\r\n", .{up.port}),
        // A bare CR inside a header value.
        try std.fmt.allocPrint(testing.allocator, "GET http://allowed.test:{d}/x HTTP/1.1\r\nX: a\rHost: evil.test\r\n\r\n", .{up.port}),
        // A header name that is not a token.
        try std.fmt.allocPrint(testing.allocator, "GET http://allowed.test:{d}/x HTTP/1.1\r\nBad Name: x\r\n\r\n", .{up.port}),
    };
    defer for (reqs) |r| testing.allocator.free(r);
    var sbuf: [128]u8 = undefined;
    for (reqs, 0..) |req, i| {
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send(req);
        try testing.expectEqualStrings("HTTP/1.1 400 Bad Request", try c.status(&sbuf));
        var r = try h.receiptAt(i);
        defer r.deinit();
        try expectField(r.value, "verdict", "deny");
        try expectField(r.value, "reason", "bad_request");
    }
    try testing.expectEqual(@as(u32, 0), up.accepted.load(.monotonic));
}

test "plain HTTP with a body is forwarded with its length" {
    var up: TestServer = undefined;
    try up.start(testing.io, .http);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    var req_buf: [512]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "POST http://allowed.test:{d}/ HTTP/1.1\r\n" ++
        "Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 OK", try c.status(&sbuf));
    try testing.expect(std.mem.find(u8, up.head(), "transfer-encoding: chunked\r\n") != null);
}

test "IP literals need an allowed subnet; requests that are not proxy requests get 400" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    var sbuf: [128]u8 = undefined;
    var req_buf: [128]u8 = undefined;
    {
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT 127.0.0.1:{d} HTTP/1.1\r\n\r\n", .{up.port}));
        try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
        var hello_buf: [600]u8 = undefined;
        const hello = clientHello(&hello_buf, null);
        try c.send(hello);
        try testing.expectEqualSlices(u8, hello, try c.r.interface.take(hello.len));
    }
    {
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send("CONNECT 93.184.216.34:443 HTTP/1.1\r\n\r\n");
        try testing.expectEqualStrings("HTTP/1.1 403 Forbidden", try c.status(&sbuf));
    }
    {
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send("GET /relative HTTP/1.1\r\nhost: x\r\n\r\n");
        try testing.expectEqualStrings("HTTP/1.1 400 Bad Request", try c.status(&sbuf));
    }
    var r0 = try h.receiptAt(0);
    defer r0.deinit();
    try expectField(r0.value, "reason", "allowed_subnet");
    try expectField(r0.value, "detail", "ip_literal");
    var r1 = try h.receiptAt(1);
    defer r1.deinit();
    try expectField(r1.value, "reason", "ip_literal_needs_subnet");
    var r2 = try h.receiptAt(2);
    defer r2.deinit();
    try expectField(r2.value, "reason", "bad_request");
}

test "a grant allows a refused name until it expires, and expiry closes the tunnel" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    var sbuf: [128]u8 = undefined;
    var req_buf: [128]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "CONNECT granted.test:{d} HTTP/1.1\r\n\r\n", .{up.port});
    {
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send(req);
        try testing.expectEqualStrings("HTTP/1.1 403 Forbidden", try c.status(&sbuf));
    }
    _ = try h.grants.add(h.io, "granted.test", .fromMilliseconds(400));
    {
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send(req);
        try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
        var hello_buf: [600]u8 = undefined;
        const hello = clientHello(&hello_buf, "granted.test");
        try c.send(hello);
        try testing.expectEqualSlices(u8, hello, try c.r.interface.take(hello.len));
        // The grant expires while the tunnel is open: the proxy ends it.
        try testing.expectEqual(@as(usize, 0), (try c.untilClosed()).bytes);
    }
    {
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send(req);
        try testing.expectEqualStrings("HTTP/1.1 403 Forbidden", try c.status(&sbuf));
    }
    var r0 = try h.receiptAt(0);
    defer r0.deinit();
    try expectField(r0.value, "verdict", "deny");
    var r1 = try h.receiptAt(1);
    defer r1.deinit();
    try expectField(r1.value, "verdict", "allow");
    try expectField(r1.value, "reason", "granted");
    try expectField(r1.value, "rule", "grant:granted.test");
    var r2 = try h.receiptAt(2);
    defer r2.deinit();
    try expectField(r2.value, "reason", "grant_expired");
    // The reset names the connection it cut, as its connect receipt did.
    try expectField(r2.value, "ip", "127.0.0.1");
    try testing.expectEqual(r1.value.object.get("port").?.integer, r2.value.object.get("port").?.integer);
    var r3 = try h.receiptAt(3);
    defer r3.deinit();
    try expectField(r3.value, "verdict", "deny");
    try expectField(r3.value, "reason", "no_matching_rule");
}

test "revoking a grant closes the tunnels opened under it" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    _ = try h.grants.add(h.io, "granted.test", .fromSeconds(60));

    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);
    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT granted.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
    var hello_buf: [600]u8 = undefined;
    const hello = clientHello(&hello_buf, "granted.test");
    try c.send(hello);
    try testing.expectEqualSlices(u8, hello, try c.r.interface.take(hello.len));

    try testing.expect(h.grants.revoke(h.io, "granted.test"));
    try testing.expectEqual(@as(usize, 0), (try c.untilClosed()).bytes);

    var r = try h.receiptAt(1);
    defer r.deinit();
    try expectField(r.value, "verdict", "deny");
    try expectField(r.value, "reason", "grant_revoked");
    try expectField(r.value, "host", "granted.test");
}

test "a grant's end resets the tunnel: bytes queued toward the client are dropped, not delivered" {
    var up: TestServer = undefined;
    try up.start(testing.io, .flood);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    _ = try h.grants.add(h.io, "granted.test", .fromMilliseconds(300));

    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);
    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT granted.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
    var hello_buf: [600]u8 = undefined;
    try c.send(clientHello(&hello_buf, "granted.test"));
    // The upstream floods the tunnel and the client reads nothing, so the proxy's socket toward the client fills
    // up. The grant ends meanwhile.
    try h.io.sleep(.fromMilliseconds(1000), .awake);
    const sent_at_end = up.sent.load(.monotonic);
    const end = try c.untilClosed();
    // A plain close would deliver the whole queue and then a FIN. The reset drops it: the client reads what its
    // own socket had already received, then gets the reset.
    try testing.expect(end.reset);
    try testing.expect(end.bytes < sent_at_end);
    // The upstream side was cut too: it sends nothing more.
    try testing.expectEqual(sent_at_end, up.sent.load(.monotonic));

    var r = try h.receiptAt(1);
    defer r.deinit();
    try expectField(r.value, "reason", "grant_expired");
    try expectField(r.value, "detail", "connection_reset");
}

test "a grant whose watchdog cannot start is refused, never unbounded" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    _ = try h.grants.add(h.io, "granted.test", .fromSeconds(60));
    proxy.test_fail_watchdog = true;
    defer proxy.test_fail_watchdog = false;

    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);
    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT granted.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 503 Service Unavailable", try c.status(&sbuf));
    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "deny");
    try expectField(r.value, "reason", "grant_watchdog_failed");
}

test "grant expiry also cuts a plain HTTP exchange in flight" {
    var up: TestServer = undefined;
    try up.start(testing.io, .slow_http);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    _ = try h.grants.add(h.io, "granted.test", .fromMilliseconds(300));

    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);
    var req_buf: [256]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "GET http://granted.test:{d}/slow HTTP/1.1\r\n\r\n", .{up.port}));
    // The upstream answers after 3 s; the grant ends after 0.3 s, so the connection ends with no answer.
    try testing.expectEqual(@as(usize, 0), (try c.untilClosed()).bytes);
    var r0 = try h.receiptAt(0);
    defer r0.deinit();
    try expectField(r0.value, "reason", "granted");
    var r1 = try h.receiptAt(1);
    defer r1.deinit();
    try expectField(r1.value, "event", "http");
    try expectField(r1.value, "reason", "grant_expired");
}

test "ports outside the policy are refused before any name work, and grants do not lift them" {
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, 443));
    defer h.deinit();
    _ = try h.grants.add(h.io, "granted.test", .fromSeconds(60));
    var sbuf: [128]u8 = undefined;
    const reqs = [_][]const u8{
        "CONNECT allowed.test:8443 HTTP/1.1\r\n\r\n",
        "CONNECT granted.test:22 HTTP/1.1\r\n\r\n",
        "GET http://allowed.test:8080/ HTTP/1.1\r\n\r\n",
        "CONNECT 127.0.0.1:6379 HTTP/1.1\r\n\r\n",
    };
    for (reqs) |req| {
        var c: Client = .{ .stream = try h.connect() };
        c.init(h.io, c.stream);
        defer c.stream.close(h.io);
        try c.send(req);
        try testing.expectEqualStrings("HTTP/1.1 403 Forbidden", try c.status(&sbuf));
    }
    const hosts = [_][]const u8{ "allowed.test", "granted.test", "allowed.test", "127.0.0.1" };
    const ports = [_]i64{ 8443, 22, 8080, 6379 };
    for (hosts, ports, 0..) |host, port, i| {
        var r = try h.receiptAt(i);
        defer r.deinit();
        try expectField(r.value, "verdict", "deny");
        try expectField(r.value, "reason", "port_not_allowed");
        try expectField(r.value, "host", host);
        try testing.expectEqual(port, r.value.object.get("port").?.integer);
        try testing.expect(r.value.object.get("rule") == null);
    }
}

test "the system resolver is used when none is injected; localhost stays refused" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pol = try policy.Policy.parse(testing.allocator,
        \\{"version":"blackice.policy/v0","network":{"mode":"allowlist","allow":["localhost"]}}
    , null);
    defer pol.deinit();
    var log = try receipt.Log.open(io, tmp.dir, "r.jsonl", "s-test0002", pol.id());
    defer log.close();
    const p = try proxy.Proxy.start(testing.allocator, io, &pol, &log, .{});
    defer p.stop();

    const addr: net.IpAddress = .{ .ip4 = .loopback(p.port) };
    var c: Client = .{ .stream = try addr.connect(io, .{ .mode = .stream }) };
    c.init(io, c.stream);
    defer c.stream.close(io);
    try c.send("CONNECT localhost:443 HTTP/1.1\r\n\r\n");
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 403 Forbidden", try c.status(&sbuf));
    const bytes = try tmp.dir.readFileAlloc(io, "r.jsonl", testing.allocator, .limited(1 << 16));
    defer testing.allocator.free(bytes);
    try testing.expect(std.mem.find(u8, bytes, "\"reason\":\"local_or_private_address\"") != null);
}

// ---------------------------------------------------------------- dialing

test "interleaveFamilies alternates families from the first answer's family, keeping each family's order" {
    const v6a = try net.IpAddress.parse("2001:db8::a", 443);
    const v6b = try net.IpAddress.parse("2001:db8::b", 443);
    const v4a = try net.IpAddress.parse("192.0.2.1", 443);
    const v4b = try net.IpAddress.parse("192.0.2.2", 443);
    const v4c = try net.IpAddress.parse("192.0.2.3", 443);
    var out: [8]net.IpAddress = undefined;

    const a = proxy.interleaveFamilies(&out, &.{ v6a, v6b, v4a, v4b, v4c });
    try testing.expectEqualSlices(net.IpAddress, &.{ v6a, v4a, v6b, v4b, v4c }, a);
    const b = proxy.interleaveFamilies(&out, &.{ v4a, v6a, v6b });
    try testing.expectEqualSlices(net.IpAddress, &.{ v4a, v6a, v6b }, b);
    const c = proxy.interleaveFamilies(&out, &.{ v4a, v4b });
    try testing.expectEqualSlices(net.IpAddress, &.{ v4a, v4b }, c);
    try testing.expectEqual(@as(usize, 0), proxy.interleaveFamilies(&out, &.{}).len);
}

/// A listener on [::1]:port whose accept queue is full and never drained, so the kernel drops new
/// connection attempts to it: a connect neither succeeds nor fails, like an address whose packets are lost.
/// Skips the test where that cannot be set up (no IPv6 loopback, or a kernel that refuses instead of dropping).
const Hole = struct {
    io: Io,
    server: net.Server,
    fillers: [8]net.Stream = undefined,
    filled: usize = 0,

    fn open(hole: *Hole, io: Io, port: u16) !void {
        const addr = try net.IpAddress.parse("::1", port);
        const server = addr.listen(io, .{ .kernel_backlog = 0 }) catch return error.SkipZigTest;
        hole.* = .{ .io = io, .server = server };
        errdefer hole.close();
        while (hole.filled < hole.fillers.len) {
            switch (try proxy.dialRace(io, &.{addr}, .fromSeconds(1), .fromMilliseconds(300))) {
                .open => |o| {
                    hole.fillers[hole.filled] = o.stream;
                    hole.filled += 1;
                },
                .failed => |f| {
                    if (f.err == error.Timeout) return; // the queue is full and attempts hang
                    return error.SkipZigTest;
                },
            }
        }
        return error.SkipZigTest;
    }

    fn close(hole: *Hole) void {
        for (hole.fillers[0..hole.filled]) |s| s.close(hole.io);
        hole.server.deinit(hole.io);
    }
};

/// The test policy plus the dialing names and the IPv6 loopback.
fn holePolicy(buf: []u8, upstream_port: u16) []const u8 {
    return std.fmt.bufPrint(buf,
        \\{{"version":"blackice.policy/v0","network":{{"mode":"allowlist",
        \\ "allow":["allowed.test","hole.test","blackhole.test"],
        \\ "subnets":{{"allow":["127.0.0.0/8","::1/128"]}},"ports":[443,{d}]}}}}
    , .{upstream_port}) catch unreachable;
}

test "an address that drops connections costs one attempt delay, then the next address answers" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var hole: Hole = undefined;
    try hole.open(testing.io, up.port);
    defer hole.close();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(holePolicy(&pbuf, up.port)); // default budget: 10 s
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    const t0 = Io.Clock.awake.now(h.io);
    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT hole.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
    // One 250 ms attempt delay, not the 10 s budget (dialing one address at a time took the whole budget).
    try testing.expect(t0.untilNow(h.io, .awake).toMilliseconds() < 2000);
    var hello_buf: [600]u8 = undefined;
    const hello = clientHello(&hello_buf, "hole.test");
    try c.send(hello);
    try testing.expectEqualSlices(u8, hello, try c.r.interface.take(hello.len));

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "allow");
    try expectField(r.value, "ip", "127.0.0.1");
    try expectField(r.value, "detail", "sni_match");
}

test "when every address drops connections, the dial gives up after its budget with upstream_unreachable" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var hole: Hole = undefined;
    try hole.open(testing.io, up.port);
    defer hole.close();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.initConfig(holePolicy(&pbuf, up.port), .{ .connect_timeout = .fromMilliseconds(500) });
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT blackhole.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 502 Bad Gateway", try c.status(&sbuf));

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "deny");
    try expectField(r.value, "reason", "upstream_unreachable");
    try expectField(r.value, "ip", "::1");
    const detail = r.value.object.get("detail").?.string;
    try testing.expect(std.mem.startsWith(u8, detail, "Timeout wait_ms="));
}

test "a client that leaves before sending a byte gets client_closed with wait_ms, not not_tls" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(testPolicy(&pbuf, up.port));
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);

    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT allowed.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    var sbuf: [128]u8 = undefined;
    try testing.expectEqualStrings("HTTP/1.1 200 Connection Established", try c.status(&sbuf));
    c.stream.close(h.io);
    try h.waitReceipts(1);

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "allow");
    try expectField(r.value, "reason", "allowed_by_rule");
    try expectField(r.value, "ip", "127.0.0.1");
    const detail = r.value.object.get("detail").?.string;
    try testing.expect(std.mem.startsWith(u8, detail, "client_closed wait_ms="));
    try testing.expectEqual(@as(usize, 0), up.received.load(.monotonic));
}

test "stopping the proxy mid-dial writes the refusal and does not go on to the next address" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var hole: Hole = undefined;
    try hole.open(testing.io, up.port);
    defer hole.close();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    // A long attempt delay keeps the dial on the dropping address when the stop comes.
    try h.initConfig(holePolicy(&pbuf, up.port), .{ .attempt_delay = .fromSeconds(5) });
    var stopped = false;
    defer if (!stopped) h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);
    defer c.stream.close(h.io);

    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT hole.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    try h.io.sleep(.fromMilliseconds(300), .awake);
    h.p.stop();
    stopped = true;
    defer {
        h.grants.deinit();
        h.log.close();
        h.pol.deinit();
        h.tmp.cleanup();
    }

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "deny");
    try expectField(r.value, "reason", "upstream_unreachable");
    try expectField(r.value, "ip", "::1");
    const detail = r.value.object.get("detail").?.string;
    try testing.expect(std.mem.startsWith(u8, detail, "canceled wait_ms="));
    try testing.expectError(error.MissingReceipt, h.receiptAt(1));
    try testing.expectEqual(@as(u32, 0), up.accepted.load(.monotonic));
}

test "a client that resets before the 200 reaches it still gets a client_closed receipt" {
    var up: TestServer = undefined;
    try up.start(testing.io, .echo);
    defer up.stop();
    var hole: Hole = undefined;
    try hole.open(testing.io, up.port);
    defer hole.close();
    var h: Harness = undefined;
    var pbuf: [512]u8 = undefined;
    try h.init(holePolicy(&pbuf, up.port));
    defer h.deinit();
    var c: Client = .{ .stream = try h.connect() };
    c.init(h.io, c.stream);

    // hole.test's first address drops connections, so the 200 comes one attempt delay (250 ms) later. By then
    // the client has reset the connection (linger 0), and writing the 200 fails.
    var req_buf: [128]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&req_buf, "CONNECT hole.test:{d} HTTP/1.1\r\n\r\n", .{up.port}));
    const l: std.posix.linger = .{ .onoff = 1, .linger = 0 };
    try std.posix.setsockopt(c.stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&l));
    c.stream.close(h.io);
    try h.waitReceipts(1);

    var r = try h.receiptAt(0);
    defer r.deinit();
    try expectField(r.value, "verdict", "allow");
    try expectField(r.value, "ip", "127.0.0.1");
    const detail = r.value.object.get("detail").?.string;
    try testing.expect(std.mem.startsWith(u8, detail, "client_closed wait_ms="));
    try testing.expectEqual(@as(usize, 0), up.received.load(.monotonic));
}
