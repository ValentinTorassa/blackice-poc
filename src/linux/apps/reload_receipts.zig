//! Reload records use the existing flat receipt writer and captured contexts.
const std = @import("std");
const receipt = @import("../../core/receipt.zig");
const snapshot = @import("reload_snapshot.zig");

/// The writer still cleans/caps detail at 512 bytes. Per-slot proxy records also
/// carry each executable, so long membership summaries are not the only record.
pub fn activationDetail(buffer: []u8, old: *const snapshot.Snapshot, new: *const snapshot.Snapshot) ![]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    inline for (.{ "added", "removed", "retired", "changed" }) |kind| {
        try writer.print("{s}=[", .{kind});
        var comma = false;
        for (new.slots, 0..) |slot, i| if (slot) |b| {
            const before = old.slots[i];
            const include = if (comptime std.mem.eql(u8, kind, "added")) before == null else if (comptime std.mem.eql(u8, kind, "removed")) before != null and before.?.active and !b.active else if (comptime std.mem.eql(u8, kind, "retired")) !b.active else before != null and before.?.active and b.active and !std.mem.eql(u8, &before.?.network.digest_hex, &b.network.digest_hex);
            if (!include) continue;
            if (comma) try writer.writeByte(',');
            try writer.print("{f}", .{std.json.fmt(b.executable, .{})});
            comma = true;
        };
        try writer.writeAll("]; ");
    }
    try writer.writeAll("tags_retained; narrowing_watchdog_ms=200");
    return writer.buffered();
}

pub fn activated(log: *receipt.Log, old: receipt.Decision, new: receipt.Decision, detail: []const u8) !void {
    if (old.generation == 0 or old.generation >= @import("config.zig").max_generations or new.generation != old.generation + 1) return error.ExpectedNextGeneration;
    try digest(old.policy);
    try digest(new.policy);
    log.write(.{ .event = "policy_activated", .point = .app_filter, .decision = new, .old_policy = old.policy, .new_policy = new.policy, .detail = detail });
}
/// A reload refused before its pending record was written: nothing changed.
pub fn refused(log: *receipt.Log, current: ?receipt.Decision, reason: []const u8) void {
    log.write(.{ .event = "policy_change_refused", .point = .app_filter, .verdict = .deny, .decision = current, .old_policy = if (current) |c| c.policy else null, .reason = reason });
}

/// How far a reload got after writing its pending record.
pub const Progress = enum {
    /// The intent still names the previous generation.
    pending,
    /// The intent write itself failed. The file names one generation or the other; the restart reads it.
    committing,
    /// The intent names the new generation. The restart serves it.
    committed,

    pub fn field(p: Progress) []const u8 {
        return switch (p) {
            .pending => "committed=false",
            .committing => "committed=unknown",
            .committed => "committed=true",
        };
    }
};

/// A reload that failed after its pending record, with copies of the change's two hashes. `restarting` is false
/// only when the proxy child refused the candidate policy: the service then keeps serving the previous generation.
pub const Failure = struct {
    progress: Progress,
    old_generation: u32,
    new_generation: u32,
    old_policy: [64]u8,
    new_policy: [64]u8,
    restarting: bool,
};

/// The service receipt for a failed reload: policy_change_failed, never policy_change_refused, because the change
/// may already be committed. `gen` and `policy` name the new generation once it is committed, otherwise the
/// previous one; old_policy and new_policy are the change's two hashes.
pub fn failed(log: *receipt.Log, failure: *const Failure, reason: []const u8) void {
    var buf: [64]u8 = undefined;
    const detail = std.fmt.bufPrint(&buf, "{s} service={s}", .{ failure.progress.field(), if (failure.restarting) "restarting" else "running" }) catch unreachable;
    const decision: receipt.Decision = if (failure.progress == .committed)
        .{ .policy = &failure.new_policy, .generation = failure.new_generation }
    else
        .{ .policy = &failure.old_policy, .generation = failure.old_generation };
    log.write(.{ .event = "policy_change_failed", .point = .app_filter, .decision = decision, .old_policy = &failure.old_policy, .new_policy = &failure.new_policy, .reason = reason, .detail = detail });
}

/// The control reply for a failed request. A refusal (`failure` null) keeps the plain `ERROR <name>` line. A failed
/// reload adds whether its change was committed and, when known, the generation the service serves next.
pub fn reply(buf: []u8, name: []const u8, failure: ?Failure) error{WriteFailed}![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.print("ERROR {s}", .{name});
    if (failure) |f| {
        try w.print(" {s}", .{f.progress.field()});
        switch (f.progress) {
            .pending => try w.print(" gen={d}", .{f.old_generation}),
            .committing => {},
            .committed => try w.print(" gen={d}", .{f.new_generation}),
        }
        try w.print(" service={s}", .{if (f.restarting) "restarting" else "running"});
    }
    try w.writeByte('\n');
    return w.buffered();
}
fn digest(value: []const u8) !void {
    if (value.len != 64) return error.InvalidPolicyDigest;
    for (value) |c| if (!(c >= '0' and c <= '9') and !(c >= 'a' and c <= 'f')) return error.InvalidPolicyDigest;
}

test "appfilter reload activation records both exact hashes and does not invent skipped generations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const old_hash: [64]u8 = @splat('1');
    const new_hash: [64]u8 = @splat('2');
    const old: receipt.Decision = .{ .generation = 1, .policy = &old_hash };
    const new: receipt.Decision = .{ .generation = 2, .policy = &new_hash };
    var log = try receipt.Log.open(io, tmp.dir, "r.jsonl", "service", old.policy);
    try std.testing.expectError(error.ExpectedNextGeneration, activated(&log, old, .{ .generation = 3, .policy = new.policy }, ""));
    try std.testing.expectError(error.InvalidPolicyDigest, activated(&log, old, .{ .generation = 2, .policy = "wrong" }, ""));
    try std.testing.expectEqual(@as(u64, 0), log.written);
    try activated(&log, old, new, "changed=/usr/bin/curl");
    log.close();
    const data = try tmp.dir.readFileAlloc(io, "r.jsonl", std.testing.allocator, .limited(16384));
    defer std.testing.allocator.free(data);
    const row = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, data, .{});
    defer row.deinit();
    try std.testing.expectEqual(@as(i64, 2), row.value.object.get("gen").?.integer);
    try std.testing.expectEqualStrings(old.policy, row.value.object.get("old_policy").?.string);
    try std.testing.expectEqualStrings(new.policy, row.value.object.get("new_policy").?.string);
    try std.testing.expectEqualStrings(new.policy, row.value.object.get("policy").?.string);
}

test "appfilter activation detail distinguishes changed removed retired added and unchanged apps" {
    var allow = try @import("../../core/policy.zig").Policy.parse(std.testing.allocator, "{\"version\":\"blackice.policy/v0\",\"network\":{\"mode\":\"allowlist\",\"allow\":[\"example.com\"]}}", null);
    defer allow.deinit();
    var deny = try @import("../../core/policy.zig").Policy.parse(std.testing.allocator, "{\"version\":\"blackice.policy/v0\",\"network\":{\"mode\":\"deny-all\"}}", null);
    defer deny.deinit();
    var old: snapshot.Snapshot = .{ .stamp = .{ .generation = 1, .digest = @splat(1) } };
    for ([_][]const u8{ "/usr/bin/changed", "/usr/bin/removed", "/usr/bin/retired", "/usr/bin/unchanged" }, 0..) |path, i| {
        old.slots[i] = .{ .executable = path, .network = &allow, .identity = .{ .device = 1, .inode = i + 1 }, .stamp = old.stamp, .active = i != 2 };
    }
    var new = old;
    new.slots[0].?.network = &deny;
    new.slots[1].?.active = false;
    new.slots[4] = .{ .executable = "/usr/bin/added", .network = &allow, .identity = .{ .device = 1, .inode = 5 }, .stamp = old.stamp, .active = true };
    var bytes: [16384]u8 = undefined;
    const detail = try activationDetail(&bytes, &old, &new);
    try std.testing.expectEqualStrings("added=[\"/usr/bin/added\"]; removed=[\"/usr/bin/removed\"]; retired=[\"/usr/bin/removed\",\"/usr/bin/retired\"]; changed=[\"/usr/bin/changed\"]; tags_retained; narrowing_watchdog_ms=200", detail);
}

test "appfilter a reload failing after its pending record is never logged as refused and says whether it was committed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const old_hash: [64]u8 = @splat('1');
    const new_hash: [64]u8 = @splat('2');
    var log = try receipt.Log.open(io, tmp.dir, "r.jsonl", "service", &old_hash);
    const base: Failure = .{ .progress = .pending, .old_generation = 1, .new_generation = 2, .old_policy = old_hash, .new_policy = new_hash, .restarting = true };
    const cases = [_]struct { Progress, bool, []const u8, i64, []const u8 }{
        .{ .pending, false, "proxy_refused", 1, "committed=false service=running" },
        .{ .pending, true, "ReloadTimeout", 1, "committed=false service=restarting" },
        .{ .committing, true, "NoSpaceLeft", 1, "committed=unknown service=restarting" },
        .{ .committed, true, "ReloadTimeout", 2, "committed=true service=restarting" },
    };
    for (cases) |case| {
        var failure = base;
        failure.progress = case[0];
        failure.restarting = case[1];
        failed(&log, &failure, case[2]);
    }
    log.close();
    const data = try tmp.dir.readFileAlloc(io, "r.jsonl", std.testing.allocator, .limited(16384));
    defer std.testing.allocator.free(data);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, data, "\n"), '\n');
    for (cases) |case| {
        const row = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, lines.next().?, .{});
        defer row.deinit();
        const o = row.value.object;
        try std.testing.expectEqualStrings("policy_change_failed", o.get("event").?.string);
        try std.testing.expectEqualStrings(case[2], o.get("reason").?.string);
        try std.testing.expectEqualStrings(case[4], o.get("detail").?.string);
        try std.testing.expectEqual(case[3], o.get("gen").?.integer);
        try std.testing.expectEqualStrings(if (case[3] == 2) &new_hash else &old_hash, o.get("policy").?.string);
        try std.testing.expectEqualStrings(&old_hash, o.get("old_policy").?.string);
        try std.testing.expectEqualStrings(&new_hash, o.get("new_policy").?.string);
    }
    try std.testing.expect(lines.next() == null);
    try std.testing.expect(std.mem.find(u8, data, "policy_change_refused") == null);
}

test "appfilter control reply keeps plain refusals and names the commit state of a failed reload" {
    var buf: [160]u8 = undefined;
    const base: Failure = .{ .progress = .pending, .old_generation = 3, .new_generation = 4, .old_policy = @splat('3'), .new_policy = @splat('4'), .restarting = false };
    try std.testing.expectEqualStrings("ERROR ChangeInProgress\n", try reply(&buf, "ChangeInProgress", null));
    try std.testing.expectEqualStrings("ERROR ProxyRefused committed=false gen=3 service=running\n", try reply(&buf, "ProxyRefused", base));
    var committing = base;
    committing.progress = .committing;
    committing.restarting = true;
    try std.testing.expectEqualStrings("ERROR AccessDenied committed=unknown service=restarting\n", try reply(&buf, "AccessDenied", committing));
    var committed = committing;
    committed.progress = .committed;
    try std.testing.expectEqualStrings("ERROR ReloadTimeout committed=true gen=4 service=restarting\n", try reply(&buf, "ReloadTimeout", committed));
    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.WriteFailed, reply(&tiny, "ReloadTimeout", null));
}
