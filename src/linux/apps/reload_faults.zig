//! Explicit VM test build only. Default binaries compile these operations out.
//! Root selects one transaction in test3-vm by its exact loader PID. No control
//! client, environment variable or child message can choose a fault.
const std = @import("std");
const sys = @import("../sys.zig");
const l = sys.l;
pub const enabled = @import("appfilter_build").vm_faults;
const path = "/etc/blackice-appfilter/vm-reload-fault";
pub const Mode = enum { none, after_validation, after_prepare, after_intent, stop_child, kill_child, invalid_policy, off_stopping, after_stage };

pub fn requireGuest() !void {
    if (!enabled) return;
    const uts = std.posix.uname();
    if (!std.mem.eql(u8, std.mem.sliceTo(&uts.nodename, 0), "test3-vm")) return error.FaultBuildRequiresVM3;
    try sys.writeAll(2, "VM-ONLY RELOAD FAULT BUILD; not a host/release artifact\n");
}

fn parse(bytes: []const u8, pid: l.pid_t) !Mode {
    if (bytes.len == 0 or bytes[bytes.len - 1] != '\n') return error.InvalidReloadFault;
    var words = std.mem.splitScalar(u8, bytes[0 .. bytes.len - 1], ' ');
    const number = words.next() orelse return error.InvalidReloadFault;
    const mode = words.next() orelse return error.InvalidReloadFault;
    if (words.next() != null) return error.InvalidReloadFault;
    const target = std.fmt.parseInt(l.pid_t, number, 10) catch return error.InvalidReloadFault;
    if (target <= 0) return error.InvalidReloadFault;
    const result = std.meta.stringToEnum(Mode, mode) orelse return error.InvalidReloadFault;
    return if (target == pid) result else .none;
}

pub fn read() !Mode {
    if (!enabled) return .none;
    const raw = l.open(path, .{ .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true }, 0);
    if (l.errno(raw) == .NOENT) return .none;
    const fd = try sys.fd(raw);
    defer sys.close(fd);
    const info = try sys.stat(fd);
    if (info.uid != 0 or info.mode & 0o022 != 0 or info.mode & l.S.IFMT != l.S.IFREG) return error.InvalidReloadFaultOwner;
    var bytes: [128]u8 = undefined;
    const n = try sys.read(fd, &bytes);
    if (n == bytes.len) return error.InvalidReloadFault;
    return parse(bytes[0..n], l.getpid());
}

pub fn pause(selected: Mode, point: Mode) !void {
    if (!enabled or selected != point) return;
    var message: [128]u8 = undefined;
    try sys.writeAll(2, try std.fmt.bufPrint(&message, "VM_RELOAD_PAUSE pid={d} point={s}\n", .{ l.getpid(), @tagName(point) }));
    const end = try @import("reload_channel.zig").Deadline.now() + 60_000;
    // Only this writer thread pauses. The concurrent-control refuser keeps
    // running; SIGSTOP would incorrectly suspend that thread too.
    while (try read() == selected) {
        if (try @import("reload_channel.zig").Deadline.now() >= end) return error.ReloadFaultPauseTimeout;
        _ = try sys.poll(&.{}, 25);
    }
}

pub fn announce(selected: Mode) !void {
    if (!enabled or selected == .none) return;
    var message: [128]u8 = undefined;
    try sys.writeAll(2, try std.fmt.bufPrint(&message, "VM_RELOAD_FAULT pid={d} mode={s}\n", .{ l.getpid(), @tagName(selected) }));
}

test "appfilter VM faults are PID scoped strict and inert in default builds" {
    try std.testing.expectEqual(Mode.after_intent, try parse("123 after_intent\n", 123));
    try std.testing.expectEqual(Mode.none, try parse("123 after_intent\n", 124));
    try std.testing.expectEqual(Mode.off_stopping, try parse("123 off_stopping\n", 123));
    for ([_][]const u8{ "0 after_intent\n", "123 after_intent", "123 bad\n", "123 after_intent extra\n" }) |bad|
        try std.testing.expectError(error.InvalidReloadFault, parse(bad, 123));
    if (!enabled) try std.testing.expectEqual(Mode.none, try read());
}
