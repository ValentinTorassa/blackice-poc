//! Bounded control protocol and kernel-authenticated peers; no client-supplied PIDs or UIDs.
const std = @import("std");
const sys = @import("../sys.zig");
const l = sys.l;
pub const socket_path = "/run/blackice-appfilter/control.sock";
pub const max_policy = @import("config.zig").max_bytes;
pub const Op = enum(u8) { on = 1, off = 2, status = 3, reload = 4 };
pub const Credentials = extern struct { pid: i32, uid: u32, gid: u32 };
pub const Peer = struct {
    credentials: Credentials,
    pidfd: l.fd_t,
    pub fn open(fd: l.fd_t, owner: u32) !Peer {
        var c: Credentials = undefined;
        var len: l.socklen_t = @sizeOf(Credentials);
        _ = try sys.check(l.getsockopt(fd, l.SOL.SOCKET, l.SO.PEERCRED, std.mem.asBytes(&c), &len));
        if (len != @sizeOf(Credentials) or c.uid == 0 or c.uid != owner or c.pid <= 0) return error.NotOwner;
        var pidfd: l.fd_t = -1;
        len = @sizeOf(l.fd_t);
        _ = try sys.check(l.getsockopt(fd, l.SOL.SOCKET, 77, std.mem.asBytes(&pidfd), &len)); // SO_PEERPIDFD
        if (pidfd < 0) return error.PeerPidfdRequired;
        errdefer sys.close(pidfd);
        if (len != @sizeOf(l.fd_t)) return error.PeerPidfdRequired;
        _ = try sys.check(l.fcntl(pidfd, l.F.SETFD, @as(u32, l.FD_CLOEXEC)));
        const p: Peer = .{ .credentials = c, .pidfd = pidfd };
        try p.live();
        return p;
    }
    pub fn close(p: Peer) void {
        sys.close(p.pidfd);
    }
    pub fn live(p: Peer) !void {
        var fds = [_]l.pollfd{.{ .fd = p.pidfd, .events = l.POLL.IN, .revents = 0 }};
        if (try sys.poll(&fds, 0) != 0) return error.PeerExited;
    }
};
pub fn readExact(fd: l.fd_t, bytes: []u8, timeout_ms: i32) !void {
    const deadline = try Deadline.after(timeout_ms);
    try deadline.read(fd, bytes);
}
pub const Deadline = struct {
    at: i128,
    fn now() !i128 {
        var ts: l.timespec = undefined;
        _ = try sys.check(l.clock_gettime(l.CLOCK.MONOTONIC, &ts));
        return @as(i128, ts.sec) * 1000 + @divTrunc(ts.nsec, 1000000);
    }
    pub fn after(ms: i32) !Deadline {
        return .{ .at = try now() + ms };
    }
    pub fn read(d: Deadline, fd: l.fd_t, bytes: []u8) !void {
        var n: usize = 0;
        while (n < bytes.len) {
            const left = d.at - try now();
            if (left <= 0) return error.ControlTimeout;
            var fds = [_]l.pollfd{.{ .fd = fd, .events = l.POLL.IN, .revents = 0 }};
            if (try sys.poll(&fds, @intCast(left)) == 0) return error.ControlTimeout;
            const got = try sys.read(fd, bytes[n..]);
            if (got == 0) return error.UnexpectedEof;
            n += got;
        }
    }
};
pub const Header = struct { op: Op, length: u32 };
pub fn decodeHeader(bytes: *const [8]u8) !Header {
    if (!std.mem.eql(u8, bytes[0..3], "BA1")) return error.BadControlVersion;
    const op: Op = switch (bytes[3]) {
        1 => .on,
        2 => .off,
        3 => .status,
        4 => .reload,
        else => return error.BadOperation,
    };
    const len = std.mem.readInt(u32, bytes[4..8], .little);
    const has_policy = op == .on or op == .reload;
    if (len > max_policy or (!has_policy and len != 0) or (has_policy and len == 0)) return error.BadControlLength;
    return .{ .op = op, .length = len };
}
pub fn encodeHeader(op: Op, len: u32) [8]u8 {
    var b: [8]u8 = .{ 'B', 'A', '1', @backingInt(op), 0, 0, 0, 0 };
    std.mem.writeInt(u32, b[4..8], len, .little);
    return b;
}
pub fn unixConnect(path: []const u8) !l.fd_t {
    var addr: l.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..path.len], path);
    const fd = try sys.fd(l.socket(l.AF.UNIX, l.SOCK.STREAM | l.SOCK.CLOEXEC, 0));
    errdefer sys.close(fd);
    _ = try sys.check(l.connect(fd, @ptrCast(&addr), @intCast(@offsetOf(l.sockaddr.un, "path") + path.len + 1)));
    return fd;
}
test "appfilter control rejects oversized and ambiguous frames" {
    try std.testing.expectEqual(Op.off, (try decodeHeader(&encodeHeader(.off, 0))).op);
    try std.testing.expectError(error.BadControlLength, decodeHeader(&encodeHeader(.off, 1)));
    try std.testing.expectError(error.BadControlLength, decodeHeader(&encodeHeader(.on, max_policy + 1)));
    var bad = encodeHeader(.status, 0);
    bad[3] = 255;
    try std.testing.expectError(error.BadOperation, decodeHeader(&bad));
}

test "appfilter reload framing requires bounded policy bytes and preserves previous operation numbers" {
    try std.testing.expectEqual(@as(u8, 1), encodeHeader(.on, 1)[3]);
    try std.testing.expectEqual(@as(u8, 2), encodeHeader(.off, 0)[3]);
    try std.testing.expectEqual(@as(u8, 3), encodeHeader(.status, 0)[3]);
    try std.testing.expectEqual(Op.reload, (try decodeHeader(&encodeHeader(.reload, max_policy))).op);
    try std.testing.expectError(error.BadControlLength, decodeHeader(&encodeHeader(.reload, 0)));
    try std.testing.expectError(error.BadControlLength, decodeHeader(&encodeHeader(.reload, max_policy + 1)));
}
