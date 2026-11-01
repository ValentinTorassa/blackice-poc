//! Two pre-fork pipes. No fd passing, credentials, JSON or unbounded response from the worker.
const std = @import("std");
const sys = @import("../sys.zig");
const l = sys.l;
const wire = @import("reload_protocol.zig");
pub const Deadline = struct {
    at: i128,
    pub fn now() !i128 {
        var ts: l.timespec = undefined;
        _ = try sys.check(l.clock_gettime(l.CLOCK.MONOTONIC, &ts));
        return @as(i128, ts.sec) * 1000 + @divTrunc(ts.nsec, 1000000);
    }
    pub fn start() !Deadline {
        return .{ .at = try now() + wire.deadline_ms };
    }
    fn ready(d: Deadline, fd: l.fd_t, event: i16) !void {
        while (true) {
            const left = d.at - try now();
            if (left <= 0) return error.ReloadTimeout;
            var fds = [_]l.pollfd{.{ .fd = fd, .events = event, .revents = 0 }};
            // A signal does not renew the budget.
            const rc = l.poll(&fds, 1, @intCast(left));
            if (l.errno(rc) == .INTR) continue;
            if (try sys.check(rc) == 0) return error.ReloadTimeout;
            if (fds[0].revents & (l.POLL.ERR | l.POLL.NVAL) != 0) return error.ReloadPipeFailed;
            return;
        }
    }
    pub fn read(d: Deadline, fd: l.fd_t, bytes: []u8) !void {
        var n: usize = 0;
        while (n < bytes.len) {
            try d.ready(fd, l.POLL.IN);
            const rc = l.read(fd, bytes[n..].ptr, bytes.len - n);
            if (l.errno(rc) == .AGAIN or l.errno(rc) == .INTR) continue;
            const got = try sys.check(rc);
            if (got == 0) return error.ReloadPipeClosed;
            n += got;
        }
    }
    pub fn write(d: Deadline, fd: l.fd_t, bytes: []const u8) !void {
        var n: usize = 0;
        while (n < bytes.len) {
            try d.ready(fd, l.POLL.OUT);
            const rc = l.write(fd, bytes[n..].ptr, bytes.len - n);
            if (l.errno(rc) == .AGAIN or l.errno(rc) == .INTR) continue;
            const got = try sys.check(rc);
            if (got == 0) return error.ReloadPipeClosed;
            n += got;
        }
    }
};
pub fn pipe() ![2]l.fd_t {
    var fds: [2]l.fd_t = undefined;
    _ = try sys.check(l.pipe2(&fds, .{ .CLOEXEC = true, .NONBLOCK = true }));
    return fds;
}
pub fn exchange(write_fd: l.fd_t, read_fd: l.fd_t, deadline: Deadline, h: wire.Header, bytes: []const u8, status: wire.Status) !void {
    if (bytes.len != h.length) return error.InvalidReloadLength;
    const header = try wire.encodeHeader(h);
    try deadline.write(write_fd, &header);
    try deadline.write(write_fd, bytes);
    var answer: [wire.ack_bytes]u8 = undefined;
    try deadline.read(read_fd, &answer);
    const refused = answer[40] == @backingInt(wire.Status.refused);
    _ = try wire.decodeAck(&answer, h.stamp, if (refused) .refused else status);
    // A compromised child cannot smuggle a second answer into the next command.
    var byte: [1]u8 = undefined;
    const extra = l.read(read_fd, &byte, 1);
    if (l.errno(extra) != .AGAIN) return error.ExtraReloadAck;
    if (refused) return error.ProxyRefused;
}

test "appfilter reload deadline bounds empty reads and full pipe writes" {
    const p = try pipe();
    defer sys.close(p[0]);
    defer sys.close(p[1]);
    var b: [8192]u8 = @splat(0);
    try std.testing.expectError(error.ReloadTimeout, (Deadline{ .at = try Deadline.now() }).read(p[0], b[0..1]));
    while (true) {
        const rc = l.write(p[1], &b, b.len);
        if (l.errno(rc) == .AGAIN) break;
        _ = try sys.check(rc);
    }
    try std.testing.expectError(error.ReloadTimeout, (Deadline{ .at = try Deadline.now() + 5 }).write(p[1], b[0..1]));
}

test "appfilter reload pipe rejects stale malformed and oversized child replies" {
    const stamp: wire.Stamp = .{ .generation = 2, .digest = @splat(0x31) };
    for (0..6) |scenario| {
        const requests = try pipe();
        defer sys.close(requests[0]);
        defer sys.close(requests[1]);
        const answers = try pipe();
        defer sys.close(answers[0]);
        defer sys.close(answers[1]);
        const done = try pipe();
        defer sys.close(done[0]);
        defer sys.close(done[1]);
        const pid: l.pid_t = @intCast(try sys.check(l.fork()));
        if (pid == 0) {
            // Only syscall/stack operations in the child of the test runner.
            const deadline = Deadline.start() catch l.exit_group(90);
            var request: [wire.header_bytes + 1]u8 = undefined;
            deadline.read(requests[0], &request) catch l.exit_group(91);
            var ack = wire.encodeAck(.{ .stamp = stamp, .status = .prepared }) catch l.exit_group(92);
            if (scenario == 1) ack[8] ^= 1;
            if (scenario == 2) ack[40] = 255;
            if (scenario == 4 or scenario == 5) ack[40] = @backingInt(wire.Status.refused);
            if (scenario == 3 or scenario == 5) {
                var oversized: [wire.ack_bytes + 1]u8 = undefined;
                @memcpy(oversized[0..wire.ack_bytes], &ack);
                oversized[wire.ack_bytes] = 0;
                deadline.write(answers[1], &oversized) catch l.exit_group(93);
            } else {
                deadline.write(answers[1], ack[0..7]) catch l.exit_group(94);
                deadline.write(answers[1], ack[7..]) catch l.exit_group(95);
            }
            var mark: [1]u8 = undefined;
            deadline.read(done[0], &mark) catch l.exit_group(96);
            l.exit_group(0);
        }
        const result = exchange(requests[1], answers[0], try Deadline.start(), .{ .command = .prepare, .stamp = stamp, .length = 1 }, "x", .prepared);
        try (try Deadline.start()).write(done[1], "x");
        try std.testing.expectEqual(@as(u32, 0), try sys.wait(pid));
        switch (scenario) {
            0 => try result,
            1 => try std.testing.expectError(error.ReloadAckMismatch, result),
            2 => try std.testing.expectError(error.InvalidReloadAck, result),
            3, 5 => try std.testing.expectError(error.ExtraReloadAck, result),
            4 => try std.testing.expectError(error.ProxyRefused, result),
            else => unreachable,
        }
    }
}
