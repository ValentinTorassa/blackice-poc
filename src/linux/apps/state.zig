//! Pure lifecycle decisions used by the service and fault-injection tests.
const std = @import("std");
const abi = @import("types.zig");
pub const Recovery = enum { fresh, rollback, reopen };
pub fn recover(phase: ?abi.Phase) Recovery {
    return if (phase) |p| (if (p == .armed) .reopen else .rollback) else .fresh;
}
pub fn execTag(inherited: u32, file_app: u32, real_uid: u32, owner_uid: u32) u32 {
    if (inherited != 0) return inherited;
    return if (real_uid == owner_uid) file_app else 0;
}
pub fn forkTag(parent: u32, _: u32) u32 {
    return parent;
}
pub fn exitTag(old: u32, live_threads: u32) u32 {
    return if (live_threads == 0) 0 else old;
}
pub fn validPortFloor(floor: u32) bool {
    return floor > abi.last_port;
}
test "appfilter first listed identity survives reexec, double fork and changed uid" {
    const first = execTag(0, 2, 1000, 1000);
    try std.testing.expectEqual(@as(u32, 2), execTag(forkTag(forkTag(first, 0), 0), 3, 0, 1000));
    try std.testing.expectEqual(@as(u32, 0), execTag(0, 2, 1001, 1000));
}
test "appfilter every fork replaces stale PID state including an unlisted parent's zero" {
    try std.testing.expectEqual(@as(u32, 0), forkTag(0, 7));
    try std.testing.expectEqual(@as(u32, 2), forkTag(2, 7));
    try std.testing.expectEqual(@as(u32, 2), exitTag(2, 1));
    try std.testing.expectEqual(@as(u32, 0), exitTag(2, 0));
}
test "appfilter a crash in each arming phase rolls back; armed pins reopen" {
    try std.testing.expectEqual(Recovery.fresh, recover(null));
    for (std.meta.tags(abi.Phase)) |phase| {
        try std.testing.expectEqual(if (phase == .armed) Recovery.reopen else Recovery.rollback, recover(phase));
    }
    try std.testing.expect(!validPortFloor(774));
    try std.testing.expect(!validPortFloor(0));
    try std.testing.expect(validPortFloor(1024));
}
