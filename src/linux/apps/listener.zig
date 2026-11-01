//! Reserve loopback TCP ports across TIME_WAIT without allowing a second live listener.
const std = @import("std");
const sys = @import("../sys.zig");
const l = sys.l;

pub fn listen(port: u16, ipv6: bool) !std.Io.net.Server {
    const fd = try sys.fd(l.socket(if (ipv6) l.AF.INET6 else l.AF.INET, l.SOCK.STREAM | l.SOCK.CLOEXEC, l.IPPROTO.TCP));
    errdefer sys.close(fd);
    const yes: c_int = 1;
    // Zig's ListenOptions.reuse_address also sets SO_REUSEPORT. Never enable that: a live listener
    // must remain exclusive, including during recovery from a failed or stopped proxy process.
    _ = try sys.check(l.setsockopt(fd, l.SOL.SOCKET, l.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(c_int)));
    var address: std.Io.net.IpAddress = undefined;
    if (ipv6) {
        var raw: l.sockaddr.in6 = .{
            .port = std.mem.nativeToBig(u16, port),
            .flowinfo = 0,
            .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .scope_id = 0,
        };
        try bindSocket(fd, @ptrCast(&raw), @sizeOf(@TypeOf(raw)));
        var len: l.socklen_t = @sizeOf(@TypeOf(raw));
        _ = try sys.check(l.getsockname(fd, @ptrCast(&raw), &len));
        if (len != @sizeOf(@TypeOf(raw)) or raw.family != l.AF.INET6) return error.InvalidListenerAddress;
        address = .{ .ip6 = .loopback(std.mem.bigToNative(u16, raw.port)) };
    } else {
        var raw: l.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        try bindSocket(fd, @ptrCast(&raw), @sizeOf(@TypeOf(raw)));
        var len: l.socklen_t = @sizeOf(@TypeOf(raw));
        _ = try sys.check(l.getsockname(fd, @ptrCast(&raw), &len));
        if (len != @sizeOf(@TypeOf(raw)) or raw.family != l.AF.INET) return error.InvalidListenerAddress;
        address = .{ .ip4 = .loopback(std.mem.bigToNative(u16, raw.port)) };
    }
    const defaults: std.Io.net.IpAddress.ListenOptions = .{};
    _ = try sys.check(l.listen(fd, defaults.kernel_backlog));
    return .{ .socket = .{ .handle = fd, .address = address }, .options = {} };
}

fn bindSocket(fd: l.fd_t, addr: *const l.sockaddr, len: l.socklen_t) !void {
    const rc = l.bind(fd, addr, len);
    if (l.errno(rc) == .ADDRINUSE) return error.AddressInUse;
    _ = try sys.check(rc);
}
