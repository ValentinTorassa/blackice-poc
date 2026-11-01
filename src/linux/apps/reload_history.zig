//! Retained objects: published configs, strings, policies and views live until off.
const std = @import("std");
const config = @import("config.zig");
const snap = @import("reload_snapshot.zig");
const abi = @import("types.zig");
const live = @import("../../proxy/live_policy.zig");
pub const Generation = struct { cfg: config.Config, snapshot: snap.Snapshot };
pub const History = struct {
    allocator: std.mem.Allocator,
    generations: [config.max_generations]?*Generation = @splat(null),
    count: u32 = 0,
    head: std.atomic.Value(?*const Generation) = .init(null),
    paused: std.atomic.Value(bool) = .init(false),
    blocked_retired: u8 = 0,

    pub fn deinit(h: *History) void {
        for (h.generations) |item| if (item) |g| {
            g.cfg.deinit();
            h.allocator.destroy(g);
        };
    }
    pub fn prepare(h: *History, bytes: []const u8, identities: ?[]const abi.FileKey) !*Generation {
        const g = try h.allocator.create(Generation);
        errdefer h.allocator.destroy(g);
        g.cfg = if (h.count == 0) try config.Config.parse(h.allocator, bytes) else try config.Config.parseReload(h.allocator, bytes);
        errdefer g.cfg.deinit();
        if (g.cfg.generation != h.count + 1 or h.count >= config.max_generations) return error.ExpectedNextGeneration;
        var digest: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&digest, &g.cfg.digest);
        const stamp: snap.Stamp = .{ .generation = g.cfg.generation, .digest = digest };
        if (identities) |ids| if (ids.len != g.cfg.apps.len) return error.InvalidIdentityCount;
        var inputs: [abi.max_apps]snap.Input = undefined;
        for (g.cfg.apps, 0..) |*app, i| {
            // The worker cannot inspect executables. Only the loader supplies real,
            // validated identities. Synthetic identities are local layout keys.
            inputs[i] = .{ .executable = app.executable, .network = &app.network, .identity = if (identities) |ids| ids[i] else synthetic(app.executable), .running_untagged = false };
        }
        if (h.count == 0) {
            g.snapshot = try snap.Snapshot.initial(stamp, inputs[0..g.cfg.apps.len]);
        } else {
            g.snapshot = (try snap.Plan.build(&h.head.load(.acquire).?.snapshot, stamp, inputs[0..g.cfg.apps.len])).snapshot;
        }
        return g;
    }
    /// Only for an unpublished candidate. Published objects are never freed here.
    pub fn discard(h: *History, g: *Generation) void {
        g.cfg.deinit();
        h.allocator.destroy(g);
    }
    pub fn publish(h: *History, g: *Generation) void {
        std.debug.assert(g.cfg.generation == h.count + 1 and h.generations[h.count] == null);
        h.generations[h.count] = g;
        h.count += 1;
        h.head.store(g, .release);
    }
    pub fn source(h: *History, slot: usize) live.Source {
        return .{ .context = h, .slot = slot, .read = read, .paused = &h.paused };
    }
    /// After fork, before threads start: worker-local layout checks do not use
    /// filesystem identities or any loader descriptors.
    pub fn workerIdentities(h: *History) void {
        for (h.generations[0..h.count]) |g| for (&g.?.snapshot.slots) |*slot| if (slot.*) |*b| {
            b.identity = synthetic(b.executable);
        };
    }
    fn read(ctx: *const anyopaque, slot: usize) ?live.Binding {
        const h: *const History = @ptrCast(@alignCast(ctx));
        const g = h.head.load(.acquire) orelse return null;
        const b = g.snapshot.slots[slot] orelse return null;
        return .{ .policy = b.network, .executable = b.executable, .serve = h.blocked_retired & (@as(u8, 1) << @as(u3, @intCast(slot))) == 0, .decision = .{ .policy = &b.network.digest_hex, .generation = b.stamp.generation } };
    }
    pub fn decision(h: *History, generation: u32, app_id: u32) ?live.Binding {
        if (generation == 0 or generation > h.count or app_id == 0 or app_id > abi.max_apps) return null;
        const b = h.generations[generation - 1].?.snapshot.slots[app_id - 1] orelse return null;
        return .{ .policy = b.network, .executable = b.executable, .decision = .{ .policy = &b.network.digest_hex, .generation = b.stamp.generation } };
    }
};
fn synthetic(path: []const u8) abi.FileKey {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(path, &hash, .{});
    return .{ .device = std.mem.readInt(u32, hash[0..4], .little), .inode = std.mem.readInt(u64, hash[4..12], .little) };
}

test "appfilter history retains retired decisions and atomically publishes all slots" {
    const a = "{\"version\":\"blackice.apps/v0\",\"generation\":1,\"applications\":[{\"executable\":\"/usr/bin/a\",\"policy\":{\"version\":\"blackice.policy/v0\",\"network\":{\"mode\":\"deny-all\"}}}]}";
    const b = "{\"version\":\"blackice.apps/v0\",\"generation\":2,\"applications\":[{\"executable\":\"/usr/bin/b\",\"policy\":{\"version\":\"blackice.policy/v0\",\"network\":{\"mode\":\"allowlist\",\"allow\":[\"example.com\"]}}}]}";
    var h: History = .{ .allocator = std.testing.allocator };
    defer h.deinit();
    h.publish(try h.prepare(a, null));
    const old = h.source(0).capture().?;
    const next = try h.prepare(b, null);
    try std.testing.expect(h.source(1).capture() == null);
    h.paused.store(true, .release);
    try std.testing.expect(h.source(0).capture() == null);
    h.publish(next);
    h.paused.store(false, .release);
    try std.testing.expectEqual(@as(u32, 1), h.source(0).capture().?.decision.generation);
    try std.testing.expectEqual(@as(u32, 2), h.source(1).capture().?.decision.generation);
    try std.testing.expectEqualStrings("/usr/bin/a", old.executable);
    h.blocked_retired = 1;
    try std.testing.expect(!h.source(0).current().?.serve);
    try std.testing.expect(h.source(0).capture() == null);
    try std.testing.expect(h.source(1).current() != null);
}
