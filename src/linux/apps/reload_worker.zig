//! The capability-free child's protocol state. Invalid policy JSON is a bounded
//! refusal; framing/order faults terminate the channel and require recovery.
const std = @import("std");
const wire = @import("reload_protocol.zig");
const history = @import("reload_history.zig");
pub const Machine = struct {
    policies: *history.History,
    pending: ?*history.Generation = null,
    prepared: ?wire.Stamp = null,
    pub fn deinit(m: *Machine) void {
        if (m.pending) |p| m.policies.discard(p);
    }
    pub fn handle(m: *Machine, h: wire.Header, bytes: []const u8) !wire.Status {
        _ = try wire.encodeHeader(h);
        if (h.length != bytes.len) return error.InvalidReloadLength;
        switch (h.command) {
            .prepare => {
                if (m.pending != null or m.prepared != null) return error.ChildChangeInProgress;
                const candidate = m.policies.prepare(bytes, null) catch return .refused;
                if (!candidate.snapshot.stamp.eql(h.stamp)) {
                    m.policies.discard(candidate);
                    return .refused;
                }
                m.pending = candidate;
                m.prepared = h.stamp;
                return .prepared;
            },
            .quiesce => {
                if (m.pending == null or !h.stamp.eql(m.prepared.?)) return error.ChildNotPrepared;
                m.policies.paused.store(true, .release);
                return .quiesced;
            },
            .activate => {
                if (m.pending == null or !h.stamp.eql(m.prepared.?) or !m.policies.paused.load(.acquire)) return error.ChildNotQuiesced;
                m.policies.publish(m.pending.?);
                m.pending = null;
                return .activated;
            },
            .resume_admission => {
                if (m.pending != null or m.prepared == null or !h.stamp.eql(m.prepared.?) or !h.stamp.eql(m.policies.head.load(.acquire).?.snapshot.stamp)) return error.ChildNotActivated;
                m.policies.paused.store(false, .release);
                m.prepared = null;
                return .resumed;
            },
            .abort => return error.ChildAbortRequiresRestart,
        }
    }
};

test "appfilter child refuses bad policy without losing its active generation or channel state" {
    const first = "{\"version\":\"blackice.apps/v0\",\"generation\":1,\"applications\":[{\"executable\":\"/usr/bin/a\",\"policy\":{\"version\":\"blackice.policy/v0\",\"network\":{\"mode\":\"deny-all\"}}}]}";
    var second: [first.len]u8 = first.*;
    const at = std.mem.find(u8, &second, "generation\":1").? + "generation\":".len;
    second[at] = '2';
    var h: history.History = .{ .allocator = std.testing.allocator };
    defer h.deinit();
    h.publish(try h.prepare(first, &.{.{ .device = 17, .inode = 1234 }}));
    h.workerIdentities(); // the forked child never needs filesystem access
    var machine: Machine = .{ .policies = &h };
    defer machine.deinit();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&second, &digest, .{});
    const stamp: wire.Stamp = .{ .generation = 2, .digest = digest };
    try std.testing.expectEqual(wire.Status.refused, try machine.handle(.{ .command = .prepare, .stamp = stamp, .length = 1 }, "{"));
    try std.testing.expectEqual(@as(u32, 1), h.count);
    try std.testing.expect(!h.paused.load(.acquire));
    try std.testing.expect(machine.prepared == null);
    try std.testing.expectEqual(wire.Status.prepared, try machine.handle(.{ .command = .prepare, .stamp = stamp, .length = second.len }, &second));
    try std.testing.expectError(error.ChildNotQuiesced, machine.handle(.{ .command = .activate, .stamp = stamp, .length = 0 }, ""));
    try std.testing.expectEqual(wire.Status.quiesced, try machine.handle(.{ .command = .quiesce, .stamp = stamp, .length = 0 }, ""));
    try std.testing.expectEqual(wire.Status.activated, try machine.handle(.{ .command = .activate, .stamp = stamp, .length = 0 }, ""));
    try std.testing.expect(h.paused.load(.acquire));
    try std.testing.expectEqual(wire.Status.resumed, try machine.handle(.{ .command = .resume_admission, .stamp = stamp, .length = 0 }, ""));
    try std.testing.expectEqual(@as(u32, 2), h.count);
    try std.testing.expect(!h.paused.load(.acquire));
}
