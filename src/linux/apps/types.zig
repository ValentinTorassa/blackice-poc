//! Fixed kernel/userspace ABI, ADR revision 3.1.
const std = @import("std");
pub const max_apps = 7;
pub const pid_slots = 4194304;
pub const ring_bytes = 65536;
pub const first_port = 760;
pub const last_port = 774;
pub const FileKey = extern struct { device: u32, zero: u32 = 0, inode: u64 };
pub const Ports = extern struct { tls4: u16, http4: u16, tls6: u16, http6: u16 };
pub const Phase = enum(u32) { maps = 1, cgroup, listeners, tracking, armed, stopping };
pub const State = extern struct {
    phase: Phase,
    owner_uid: u32,
    app_count: u32,
    version: u32 = 1,
    policy_sha256: [32]u8,
};
pub const Reason = enum(u32) {
    other_port = 1,
    udp,
    socket_protocol,
    listener_peer,
    listener_missing,
    unsupported_family,
    tag_missing,
    udp_connect,
    generation_fenced,
};
pub const Event = extern struct {
    timestamp_ns: u64,
    tgid: u32,
    reserved: [3]u32 = @splat(0),
    app_id: u32,
    hook: u32,
    family: u32,
    protocol: u32,
    port: u32,
    reason: Reason,
    ip: [16]u8,
};
pub fn kernelDevice(major: u32, minor: u32) error{UnsupportedDevice}!u32 {
    if (major >= 1 << 12 or minor >= 1 << 20) return error.UnsupportedDevice;
    return (major << 20) | minor;
}
pub fn ports(app: u32) Ports {
    std.debug.assert(app > 0 and app <= max_apps);
    const tls: u16 = @intCast(first_port + (app - 1) * 2);
    return .{ .tls4 = tls, .http4 = tls + 1, .tls6 = tls, .http6 = tls + 1 };
}
test "appfilter fixed PID array cannot exhaust through forks and ports are privileged" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(FileKey));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(Event));
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), pid_slots * @sizeOf(u32));
    try std.testing.expectEqual(@as(u16, 773), ports(max_apps).http6);
    try std.testing.expectEqual(@as(u32, 259 << 20 | 2), try kernelDevice(259, 2));
    try std.testing.expectError(error.UnsupportedDevice, kernelDevice(4096, 0));
}
