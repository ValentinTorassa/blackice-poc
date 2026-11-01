//! Socket integration test for a disposable QEMU VM only. Excluded from linux-appfilter-test.
//! Compile on the host with `zig test ... --test-no-exec`; execute the artifact only in the VM.
const std = @import("std");
const sys = @import("linux/sys.zig");
const l = sys.l;
const listener = @import("linux/apps/listener.zig");

fn requireVm() !void {
    const fd = try sys.fd(l.open("/sys/class/dmi/id/sys_vendor", .{ .CLOEXEC = true }, 0));
    defer sys.close(fd);
    var bytes: [64]u8 = undefined;
    const n = try sys.read(fd, &bytes);
    if (!std.mem.eql(u8, std.mem.trim(u8, bytes[0..n], "\n"), "QEMU")) return error.DisposableQemuVmRequired;
}

fn socketOption(fd: l.fd_t, option: u32) !c_int {
    var value: c_int = -1;
    var len: l.socklen_t = @sizeOf(c_int);
    _ = try sys.check(l.getsockopt(fd, l.SOL.SOCKET, option, std.mem.asBytes(&value), &len));
    try std.testing.expectEqual(@as(l.socklen_t, @sizeOf(c_int)), len);
    return value;
}

fn timeWait(port: u16, ipv6: bool) !bool {
    const fd = try sys.fd(l.open(if (ipv6) "/proc/net/tcp6" else "/proc/net/tcp", .{ .CLOEXEC = true }, 0));
    defer sys.close(fd);
    var bytes: [65536]u8 = undefined;
    var used: usize = 0;
    while (used < bytes.len) {
        const n = try sys.read(fd, bytes[used..]);
        if (n == 0) break;
        used += n;
    }
    if (used == bytes.len) return error.TcpTableTooLarge;
    var lines = std.mem.tokenizeScalar(u8, bytes[0..used], '\n');
    _ = lines.next(); // header
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        _ = fields.next() orelse continue; // slot
        const local = fields.next() orelse continue;
        _ = fields.next() orelse continue; // peer
        const state = fields.next() orelse continue;
        const colon = std.mem.findScalarLast(u8, local, ':') orelse continue;
        const candidate = std.fmt.parseInt(u16, local[colon + 1 ..], 16) catch continue;
        if (candidate == port and std.mem.eql(u8, state, "06")) return true;
    }
    return false;
}

fn exercise(ipv6: bool) !void {
    try requireVm(); // refuse before creating any socket on the developer's host
    const io = std.testing.io;
    var server = try listener.listen(0, ipv6);
    var server_open = true;
    defer if (server_open) server.deinit(io);
    const port = server.socket.address.getPort();
    try std.testing.expect(port != 0);
    try std.testing.expectEqual(@as(c_int, 1), try socketOption(server.socket.handle, l.SO.REUSEADDR));
    try std.testing.expectEqual(@as(c_int, 0), try socketOption(server.socket.handle, l.SO.REUSEPORT));
    try std.testing.expectError(error.AddressInUse, listener.listen(port, ipv6));

    const client = try server.socket.address.connect(io, .{ .mode = .stream, .protocol = .tcp });
    var client_open = true;
    defer if (client_open) client.close(io);
    const accepted = try server.accept(io);
    var accepted_open = true;
    defer if (accepted_open) accepted.close(io);
    // The server sends FIN first, so it is the side that must enter TIME_WAIT after the peer's FIN.
    _ = try sys.check(l.shutdown(accepted.socket.handle, l.SHUT.WR));
    var byte: [1]u8 = undefined;
    var readable = [_]l.pollfd{.{ .fd = client.socket.handle, .events = l.POLL.IN, .revents = 0 }};
    try std.testing.expect(try sys.poll(&readable, 2000) > 0);
    try std.testing.expectEqual(@as(usize, 0), try sys.read(client.socket.handle, &byte));
    client.close(io);
    client_open = false;
    readable[0] = .{ .fd = accepted.socket.handle, .events = l.POLL.IN, .revents = 0 };
    try std.testing.expect(try sys.poll(&readable, 2000) > 0);
    try std.testing.expectEqual(@as(usize, 0), try sys.read(accepted.socket.handle, &byte));
    accepted.close(io);
    accepted_open = false;
    var found = false;
    for (0..100) |_| {
        if (try timeWait(port, ipv6)) {
            found = true;
            break;
        }
        var none: [0]l.pollfd = .{};
        _ = try sys.poll(&none, 10);
    }
    try std.testing.expect(found); // no rebind claim unless TIME_WAIT was actually observed
    server.deinit(io);
    server_open = false;
    var rebound = try listener.listen(port, ipv6);
    defer rebound.deinit(io);
    try std.testing.expectEqual(@as(c_int, 1), try socketOption(rebound.socket.handle, l.SO.REUSEADDR));
    try std.testing.expectEqual(@as(c_int, 0), try socketOption(rebound.socket.handle, l.SO.REUSEPORT));
    try std.testing.expectError(error.AddressInUse, listener.listen(port, ipv6));
}

test "VM listener rebinds through IPv4 TIME_WAIT but refuses a live collision" {
    try exercise(false);
}
test "VM listener rebinds through IPv6 TIME_WAIT but refuses a live collision" {
    try exercise(true);
}
