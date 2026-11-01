//! Minimal bounded D-Bus client for fixed polkit actions. Sends the kernel peer pidfd via SCM_RIGHTS.
//! No PID-number fallback and no retained authorization. Wire-code fixtures make no bus calls.
const std = @import("std");
const sys = @import("../sys.zig");
const l = sys.l;
const ipc = @import("ipc.zig");
pub const action = "org.blackice.appfilter.change";
pub const Action = enum {
    change,
    reload,
    pub fn id(a: Action) []const u8 {
        return switch (a) {
            .change => action,
            .reload => "org.blackice.appfilter.reload",
        };
    }
};
const authority = "org.freedesktop.PolicyKit1";
const bus = "org.freedesktop.DBus";
const Wire = struct {
    bytes: [8192]u8 = @splat(0),
    len: usize = 0,
    fn alignTo(w: *Wire, n: usize) !void {
        const end = std.mem.alignForward(usize, w.len, n);
        if (end > w.bytes.len) return error.DbusTooLarge;
        @memset(w.bytes[w.len..end], 0);
        w.len = end;
    }
    fn raw(w: *Wire, s: []const u8) !void {
        if (s.len > w.bytes.len - w.len) return error.DbusTooLarge;
        @memcpy(w.bytes[w.len..][0..s.len], s);
        w.len += s.len;
    }
    fn byte(w: *Wire, b: u8) !void {
        try w.raw(&.{b});
    }
    fn u32val(w: *Wire, value: u32) !void {
        try w.alignTo(4);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, value, .little);
        try w.raw(&b);
    }
    fn string(w: *Wire, value: []const u8) !void {
        try w.u32val(@intCast(value.len));
        try w.raw(value);
        try w.byte(0);
    }
    fn signature(w: *Wire, value: []const u8) !void {
        if (value.len > 255) return error.DbusTooLarge;
        try w.byte(@intCast(value.len));
        try w.raw(value);
        try w.byte(0);
    }
    fn fieldString(w: *Wire, number: u8, sig: []const u8, value: []const u8) !void {
        try w.alignTo(8);
        try w.byte(number);
        try w.signature(sig);
        if (std.mem.eql(u8, sig, "g")) try w.signature(value) else try w.string(value);
    }
    fn fieldU32(w: *Wire, number: u8, value: u32) !void {
        try w.alignTo(8);
        try w.byte(number);
        try w.signature("u");
        try w.u32val(value);
    }
    fn arrayStart(w: *Wire) !usize {
        try w.alignTo(4);
        const at = w.len;
        try w.u32val(0);
        try w.alignTo(8);
        return at;
    }
    fn arrayEnd(w: *Wire, at: usize) void {
        const start = std.mem.alignForward(usize, at + 4, 8);
        std.mem.writeInt(u32, w.bytes[at..][0..4], @intCast(w.len - start), .little);
    }
};
fn authorizationBody(uid: u32, requested: Action) !Wire {
    var b: Wire = .{};
    try b.string("unix-process");
    const dict = try b.arrayStart();
    try b.alignTo(8);
    try b.string("uid");
    try b.signature("i");
    try b.u32val(uid);
    try b.alignTo(8);
    try b.string("pidfd");
    try b.signature("h");
    try b.u32val(0); // first SCM_RIGHTS descriptor
    b.arrayEnd(dict);
    try b.string(requested.id());
    const details = try b.arrayStart();
    b.arrayEnd(details);
    try b.u32val(1); // AllowUserInteraction, never cached *_keep authorization
    try b.string("");
    return b;
}
fn message(serial: u32, dest: []const u8, path: []const u8, interface: []const u8, method: []const u8, sig: []const u8, body: []const u8, has_fd: bool) !Wire {
    var h: Wire = .{};
    try h.raw(&.{ 'l', 1, 0, 1 });
    try h.u32val(@intCast(body.len));
    try h.u32val(serial);
    try h.u32val(0);
    try h.fieldString(1, "o", path);
    try h.fieldString(2, "s", interface);
    try h.fieldString(3, "s", method);
    try h.fieldString(6, "s", dest);
    if (sig.len > 0) try h.fieldString(8, "g", sig);
    if (has_fd) try h.fieldU32(9, 1);
    std.mem.writeInt(u32, h.bytes[12..16], @intCast(h.len - 16), .little);
    try h.alignTo(8);
    try h.raw(body);
    return h;
}
const Reader = struct {
    data: []const u8,
    pos: usize = 0,
    fn alignTo(r: *Reader, n: usize) !void {
        const end = std.mem.alignForward(usize, r.pos, n);
        if (end > r.data.len) return error.BadDbus;
        for (r.data[r.pos..end]) |b| if (b != 0) return error.BadDbus;
        r.pos = end;
    }
    fn bytes(r: *Reader, n: usize) ![]const u8 {
        if (n > r.data.len - r.pos) return error.BadDbus;
        const s = r.data[r.pos..][0..n];
        r.pos += n;
        return s;
    }
    fn u32val(r: *Reader) !u32 {
        try r.alignTo(4);
        return std.mem.readInt(u32, (try r.bytes(4))[0..4], .little);
    }
    fn string(r: *Reader, signature: bool) ![]const u8 {
        const n = if (signature) (try r.bytes(1))[0] else try r.u32val();
        const s = try r.bytes(n);
        if ((try r.bytes(1))[0] != 0 or std.mem.findScalar(u8, s, 0) != null) return error.BadDbus;
        return s;
    }
};
const Reply = struct { kind: u8, serial: u32, sender: []const u8, signature: []const u8, body: []const u8 };
fn parseReply(frame: []const u8) !Reply {
    if (frame.len < 16 or frame[0] != 'l' or frame[3] != 1 or frame[1] < 2 or frame[1] > 4) return error.BadDbus;
    const body_len = std.mem.readInt(u32, frame[4..8], .little);
    const header_len = std.mem.readInt(u32, frame[12..16], .little);
    if (header_len > frame.len - 16) return error.BadDbus;
    const start = std.mem.alignForward(usize, 16 + header_len, 8);
    if (start > frame.len or body_len != frame.len - start) return error.BadDbus;
    for (frame[16 + header_len .. start]) |b| if (b != 0) return error.BadDbus;
    var reply: Reply = .{ .kind = frame[1], .serial = 0, .sender = "", .signature = "", .body = frame[start..] };
    var r: Reader = .{ .data = frame[0 .. 16 + header_len], .pos = 16 };
    var seen: u16 = 0;
    while (r.pos < r.data.len) {
        try r.alignTo(8);
        const number = (try r.bytes(1))[0];
        if (number == 0 or number > 9 or seen & (@as(u16, 1) << @as(u4, @intCast(number))) != 0) return error.BadDbus;
        seen |= @as(u16, 1) << @as(u4, @intCast(number));
        const sig = try r.string(true);
        if (std.mem.eql(u8, sig, "u")) {
            const value = try r.u32val();
            if (number == 5) reply.serial = value;
            if (number == 9 and value != 0) return error.UnexpectedReplyFds;
        } else if (std.mem.eql(u8, sig, "s") or std.mem.eql(u8, sig, "o") or std.mem.eql(u8, sig, "g")) {
            const value = try r.string(std.mem.eql(u8, sig, "g"));
            if (number == 7) reply.sender = value;
            if (number == 8) reply.signature = value;
        } else return error.BadDbus;
    }
    return reply;
}
fn readReply(fd: l.fd_t, buffer: []u8, serial: u32, sender: []const u8, deadline: ipc.Deadline) !Reply {
    for (0..32) |_| {
        try deadline.read(fd, buffer[0..16]);
        const h = std.mem.readInt(u32, buffer[12..16], .little);
        const b = std.mem.readInt(u32, buffer[4..8], .little);
        if (h > 4096 or b > 8192) return error.DbusTooLarge;
        const length = std.mem.alignForward(usize, 16 + h, 8) + b;
        if (length > buffer.len) return error.DbusTooLarge;
        try deadline.read(fd, buffer[16..length]);
        const reply = try parseReply(buffer[0..length]);
        if (reply.kind == 4) continue;
        if (reply.serial != serial or !std.mem.eql(u8, reply.sender, sender)) return error.WrongDbusReply;
        if (reply.kind != 2) return error.PolkitUnavailable;
        return reply;
    }
    return error.TooManyBusSignals;
}
fn authLine(fd: l.fd_t, out: []u8, deadline: ipc.Deadline) ![]const u8 {
    for (0..out.len) |i| {
        try deadline.read(fd, out[i..][0..1]);
        if (i > 0 and out[i] == '\n' and out[i - 1] == '\r') return out[0 .. i - 1];
    }
    return error.BadDbusAuth;
}
fn sendWithFd(fd: l.fd_t, bytes: []const u8, pidfd: l.fd_t) !void {
    var control: [24]u8 align(8) = @splat(0);
    const c: *l.cmsghdr = @ptrCast(&control);
    c.* = .{ .len = @sizeOf(l.cmsghdr) + @sizeOf(l.fd_t), .level = l.SOL.SOCKET, .type = l.SCM.RIGHTS };
    @memcpy(control[@sizeOf(l.cmsghdr)..][0..4], std.mem.asBytes(&pidfd));
    const iov = [_]std.posix.iovec_const{.{ .base = bytes.ptr, .len = bytes.len }};
    const msg: l.msghdr_const = .{ .name = null, .namelen = 0, .iov = &iov, .iovlen = 1, .control = &control, .controllen = control.len, .flags = 0 };
    const n = try sys.check(l.sendmsg(fd, &msg, l.MSG.NOSIGNAL));
    if (n == 0 or n > bytes.len) return error.BadDbusWrite;
    try sys.writeAll(fd, bytes[n..]);
}
pub fn authorize(peer: ipc.Peer) !void {
    return authorizeAction(peer, .change);
}
pub fn authorizeAction(peer: ipc.Peer, requested: Action) !void {
    try peer.live();
    // One budget for authentication, bus discovery, queued signals and the interactive authorization.
    const deadline = try ipc.Deadline.after(15000);
    const fd = try ipc.unixConnect("/run/dbus/system_bus_socket");
    defer sys.close(fd);
    var uidbuf: [32]u8 = undefined;
    const uid = try std.fmt.bufPrint(&uidbuf, "{d}", .{l.getuid()});
    var encoded: [64]u8 = undefined;
    const hex = "0123456789abcdef";
    for (uid, 0..) |b, i| {
        encoded[2 * i] = hex[b >> 4];
        encoded[2 * i + 1] = hex[b & 15];
    }
    try sys.writeAll(fd, "\x00AUTH EXTERNAL ");
    try sys.writeAll(fd, encoded[0 .. uid.len * 2]);
    try sys.writeAll(fd, "\r\n");
    var line: [256]u8 = undefined;
    if (!std.mem.startsWith(u8, try authLine(fd, &line, deadline), "OK ")) return error.BadDbusAuth;
    try sys.writeAll(fd, "NEGOTIATE_UNIX_FD\r\n");
    if (!std.mem.eql(u8, try authLine(fd, &line, deadline), "AGREE_UNIX_FD")) return error.PidfdTransportRequired;
    try sys.writeAll(fd, "BEGIN\r\n");
    var buffer: [16384]u8 = undefined;
    var request = try message(1, bus, "/org/freedesktop/DBus", bus, "Hello", "", "", false);
    try sys.writeAll(fd, request.bytes[0..request.len]);
    _ = try readReply(fd, &buffer, 1, bus, deadline);
    var name: Wire = .{};
    try name.string(authority);
    request = try message(2, bus, "/org/freedesktop/DBus", bus, "GetNameOwner", "s", name.bytes[0..name.len], false);
    try sys.writeAll(fd, request.bytes[0..request.len]);
    const owner_reply = try readReply(fd, &buffer, 2, bus, deadline);
    if (!std.mem.eql(u8, owner_reply.signature, "s")) return error.BadDbus;
    var rr: Reader = .{ .data = owner_reply.body };
    const owner = try rr.string(false);
    var ownerbuf: [256]u8 = undefined;
    if (owner.len == 0 or owner.len > ownerbuf.len or owner[0] != ':' or rr.pos != rr.data.len) return error.BadDbus;
    @memcpy(ownerbuf[0..owner.len], owner);
    const expected = ownerbuf[0..owner.len];
    const body = try authorizationBody(peer.credentials.uid, requested);
    request = try message(3, expected, "/org/freedesktop/PolicyKit1/Authority", authority ++ ".Authority", "CheckAuthorization", "(sa{sv})sa{ss}us", body.bytes[0..body.len], true);
    try sendWithFd(fd, request.bytes[0..request.len], peer.pidfd);
    const answer = try readReply(fd, &buffer, 3, expected, deadline);
    try authorizationResult(answer.signature, answer.body);
    try peer.live();
}
fn authorizationResult(signature: []const u8, body: []const u8) !void {
    if (!std.mem.eql(u8, signature, "(bba{ss})")) return error.BadDbus;
    var ar: Reader = .{ .data = body };
    const authorized = try ar.u32val();
    const challenge = try ar.u32val();
    if (authorized > 1 or challenge > 1) return error.BadDbus;
    const size = try ar.u32val();
    try ar.alignTo(8);
    if (size > ar.data.len - ar.pos) return error.BadDbus;
    const end = ar.pos + size;
    while (ar.pos < end) {
        try ar.alignTo(8);
        _ = try ar.string(false);
        _ = try ar.string(false);
    }
    if (ar.pos != end or end != body.len) return error.BadDbus;
    if (authorized != 1 or challenge != 0) return error.OwnerAuthorizationRequired;
}
test "appfilter polkit uses a pidfd subject and an uncached admin action" {
    const body = try authorizationBody(1000, .change);
    try std.testing.expect(std.mem.find(u8, body.bytes[0..body.len], "pidfd") != null);
    try std.testing.expect(std.mem.find(u8, body.bytes[0..body.len], "start-time") == null);
    const req = try message(7, authority, "/org/freedesktop/PolicyKit1/Authority", authority ++ ".Authority", "CheckAuthorization", "(sa{sv})sa{ss}us", body.bytes[0..body.len], true);
    try std.testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, req.bytes[8..12], .little));
    try std.testing.expectError(error.BadDbus, parseReply(req.bytes[0..req.len]));
}

test "appfilter reload has a distinct pidfd-bound polkit action without a cached grant" {
    const body = try authorizationBody(1000, .reload);
    const bytes = body.bytes[0..body.len];
    try std.testing.expect(std.mem.find(u8, bytes, "org.blackice.appfilter.reload") != null);
    try std.testing.expect(std.mem.find(u8, bytes, action) == null);
    try std.testing.expect(std.mem.find(u8, bytes, "pidfd") != null);
    try std.testing.expect(std.mem.find(u8, bytes, "start-time") == null);
    // The final flags/string are AllowUserInteraction=1 and an empty cancellation ID.
    try std.testing.expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 0, 0, 0 }, bytes[bytes.len - 9 ..]);
}

test "appfilter polkit never treats malformed, challenged or denied replies as approval" {
    var reply: [16]u8 = @splat(0);
    try std.testing.expectError(error.OwnerAuthorizationRequired, authorizationResult("(bba{ss})", &reply));
    reply[0] = 1;
    try authorizationResult("(bba{ss})", &reply);
    for (0..reply.len) |n| try std.testing.expectError(error.BadDbus, authorizationResult("(bba{ss})", reply[0..n]));
    reply[4] = 1;
    try std.testing.expectError(error.OwnerAuthorizationRequired, authorizationResult("(bba{ss})", &reply));
    reply[4] = 2;
    try std.testing.expectError(error.BadDbus, authorizationResult("(bba{ss})", &reply));
}
test "appfilter polkit rejects nonzero header-to-body padding" {
    var frame = try message(1, bus, "/", bus, "x", "s", "", false);
    frame.bytes[1] = 2;
    const end = 16 + std.mem.readInt(u32, frame.bytes[12..16], .little);
    try std.testing.expect(end < std.mem.alignForward(usize, end, 8));
    _ = try parseReply(frame.bytes[0..frame.len]);
    frame.bytes[end] = 1;
    try std.testing.expectError(error.BadDbus, parseReply(frame.bytes[0..frame.len]));
}
