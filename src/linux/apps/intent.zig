//! Durable intent is separate from volatile pins. A reboot must not look like an authorized off.
const std = @import("std");
const sys = @import("../sys.zig");
const host = @import("host.zig");
const max_generations = @import("config.zig").max_generations;
const History = @import("reload_history.zig").History;
const abi = @import("types.zig");
const Identity = struct { device: u32, inode: u64 };
pub const Intent = struct { armed: bool, boot: [36]u8, policy: [64]u8, generation: u32 = 1, retired_slots: u8 = 0, history: [max_generations][64]u8 = @splat(@splat(0)), identities: [abi.max_apps]?Identity = @splat(null) };
const Wire = struct { version: u32, armed: bool, boot_id: []const u8, policy_sha256: []const u8, generation: u32 = 1, retired_slots: u8 = 0, generations: ?[]const []const u8 = null, identities: ?[]const ?Identity = null };
const max_intent_bytes = 20 * 1024;

pub fn bootId() ![36]u8 {
    const fd = try sys.fd(sys.l.open("/proc/sys/kernel/random/boot_id", .{ .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer sys.close(fd);
    var buf: [64]u8 = undefined;
    const n = try sys.read(fd, &buf);
    const value = std.mem.trim(u8, buf[0..n], "\n");
    if (!validBoot(value)) return error.InvalidBootId;
    return value[0..36].*;
}
fn validBoot(value: []const u8) bool {
    if (value.len != 36) return false;
    for (value, 0..) |ch, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (ch != '-') return false;
        } else if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}
fn parse(gpa: std.mem.Allocator, bytes: []const u8) !Intent {
    if (bytes.len > max_intent_bytes) return error.InvalidIntent;
    const decoded = std.json.parseFromSlice(Wire, gpa, bytes, .{ .duplicate_field_behavior = .@"error" }) catch return error.InvalidIntent;
    defer decoded.deinit();
    const w = decoded.value;
    if ((w.version != 1 and w.version != 2) or !validBoot(w.boot_id) or w.policy_sha256.len != 64) return error.InvalidIntent;
    for (w.policy_sha256) |ch| if (!std.ascii.isHex(ch)) return error.InvalidIntent;
    var result: Intent = .{ .armed = w.armed, .boot = w.boot_id[0..36].*, .policy = w.policy_sha256[0..64].* };
    if (w.version == 1) {
        if (w.generation != 1 or w.generations != null or w.retired_slots != 0 or w.identities != null) return error.InvalidIntent;
        result.history[0] = result.policy;
    } else {
        const hashes = w.generations orelse return error.InvalidIntent;
        if (w.generation == 0 or w.generation > max_generations or hashes.len != w.generation or w.retired_slots > 127) return error.InvalidIntent;
        for (hashes, 0..) |hash, i| {
            if (hash.len != 64) return error.InvalidIntent;
            for (hash) |ch| if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'))) return error.InvalidIntent;
            result.history[i] = hash[0..64].*;
        }
        if (!std.mem.eql(u8, hashes[hashes.len - 1], w.policy_sha256)) return error.InvalidIntent;
        result.generation = w.generation;
        result.retired_slots = w.retired_slots;
        if (w.identities) |ids| {
            if (ids.len != abi.max_apps) return error.InvalidIntent;
            for (ids, 0..) |id, i| {
                if (id) |key| if (key.inode == 0) return error.InvalidIntent;
                result.identities[i] = id;
            }
        }
        for (result.identities, 0..) |id, i| if (w.retired_slots & (@as(u8, 1) << @as(u3, @intCast(i))) != 0 and id == null) return error.InvalidIntent;
    }
    return result;
}
pub fn read(gpa: std.mem.Allocator, io: std.Io) !?Intent {
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, host.state_root ++ "/intent.json", gpa, .limited(max_intent_bytes)) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer gpa.free(bytes);
    return try parse(gpa, bytes);
}
pub fn writeHistory(gpa: std.mem.Allocator, io: std.Io, h: *const History, candidate: ?*@import("reload_history.zig").Generation) !void {
    var hashes: [max_generations][]const u8 = undefined;
    for (h.generations[0..h.count], 0..) |g, i| hashes[i] = &g.?.cfg.digest;
    const head = candidate orelse h.head.load(.acquire).?;
    const count = h.count + @as(u32, if (candidate != null) 1 else 0);
    if (count == 0 or count > max_generations or head.cfg.generation != count) return error.InvalidIntent;
    if (candidate != null) hashes[count - 1] = &head.cfg.digest;
    var retired: u8 = 0;
    var identities: [abi.max_apps]?Identity = @splat(null);
    for (head.snapshot.slots, 0..) |slot, i| if (slot) |b| {
        identities[i] = .{ .device = b.identity.device, .inode = b.identity.inode };
        if (!b.active) {
            retired |= @as(u8, 1) << @as(u3, @intCast(i));
        }
    };
    const boot = try bootId();
    const bytes = try std.json.Stringify.valueAlloc(gpa, Wire{ .version = 2, .armed = true, .boot_id = &boot, .policy_sha256 = &head.cfg.digest, .generation = count, .retired_slots = retired, .generations = hashes[0..count], .identities = &identities }, .{});
    defer gpa.free(bytes);
    var dir = try std.Io.Dir.openDirAbsolute(io, host.state_root, .{});
    defer dir.close(io);
    try host.atomicWrite(dir, io, "intent.json", bytes, true);
}

/// The record of a reload in progress, written before its first stage and cleared once it is settled. `boot` is
/// the boot that wrote it; null only in records written before the boot was recorded.
pub const Pending = struct { generation: u32, old_policy: [64]u8, new_policy: [64]u8, boot: ?[36]u8 = null };
const PendingWire = struct { generation: u32, old_policy: []const u8, new_policy: []const u8, boot_id: ?[]const u8 = null };
const pending_name = "reload-pending.json";

/// Records the current boot with the change.
pub fn pendingWrite(gpa: std.mem.Allocator, io: std.Io, value: Pending) !void {
    var record = value;
    record.boot = try bootId();
    var dir = try std.Io.Dir.openDirAbsolute(io, host.state_root, .{});
    defer dir.close(io);
    try pendingWriteIn(gpa, io, dir, record);
}
pub fn pendingWriteIn(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, value: Pending) !void {
    const boot = value.boot orelse return error.InvalidIntent;
    const bytes = try std.json.Stringify.valueAlloc(gpa, PendingWire{ .generation = value.generation, .old_policy = &value.old_policy, .new_policy = &value.new_policy, .boot_id = &boot }, .{});
    defer gpa.free(bytes);
    try host.atomicWrite(dir, io, pending_name, bytes, true);
}
pub fn pendingRead(gpa: std.mem.Allocator, io: std.Io) !?Pending {
    var dir = try std.Io.Dir.openDirAbsolute(io, host.state_root, .{});
    defer dir.close(io);
    return pendingReadIn(gpa, io, dir);
}
pub fn pendingReadIn(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !?Pending {
    const bytes = dir.readFileAlloc(io, pending_name, gpa, .limited(2048)) catch |err| {
        if (err == error.FileNotFound) return null;
        return err;
    };
    defer gpa.free(bytes);
    const parsed = std.json.parseFromSlice(PendingWire, gpa, bytes, .{ .duplicate_field_behavior = .@"error" }) catch return error.InvalidIntent;
    defer parsed.deinit();
    const w = parsed.value;
    if (w.generation < 2 or w.generation > max_generations or !isDigest(w.old_policy) or !isDigest(w.new_policy)) return error.InvalidIntent;
    var result: Pending = .{ .generation = w.generation, .old_policy = w.old_policy[0..64].*, .new_policy = w.new_policy[0..64].* };
    if (w.boot_id) |boot| {
        if (!validBoot(boot)) return error.InvalidIntent;
        result.boot = boot[0..36].*;
    }
    return result;
}
fn isDigest(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |ch| if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'))) return false;
    return true;
}
pub fn pendingClear(io: std.Io) !void {
    var dir = try std.Io.Dir.openDirAbsolute(io, host.state_root, .{});
    defer dir.close(io);
    try pendingClearIn(io, dir);
}
pub fn pendingClearIn(io: std.Io, dir: std.Io.Dir) !void {
    dir.deleteFile(io, pending_name) catch |err| if (err != error.FileNotFound) return err;
    const fd = try sys.fd(sys.l.openat(dir.handle, ".", .{ .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer sys.close(fd);
    _ = try sys.check(sys.l.fsync(fd));
}

/// The service receipt that settles a pending record.
pub const Settled = struct { event: []const u8, reason: []const u8, detail: []const u8 };
const restart_detail = "persisted_intent_authoritative; retired_slots_not_served";
/// A record from another boot belongs to an arming that ended with that boot, whatever its hashes say.
const from_another_boot: Settled = .{ .event = "policy_change_failed", .reason = "interrupted_by_reboot", .detail = "pending_record_from_another_boot" };
/// A record that cannot be read. `on` and `off` settle it too, so it can never block them.
pub const unreadable: Settled = .{ .event = "policy_change_failed", .reason = "invalid_pending_record", .detail = "pending_record_unreadable" };

/// An armed restart. In the same boot the intent decides: completed when it names the record's new
/// generation, interrupted when it still names the previous one. Anything else in the same boot contradicts the
/// commit order, so startup refuses with admission still fenced. A record from another boot is settled without
/// comparing it with the current arming, which started after that boot.
pub fn settleAtRestart(p: Pending, boot: *const [36]u8, generation: u32, digest: *const [64]u8) error{InvalidPendingReload}!Settled {
    if (p.boot) |recorded| if (!std.mem.eql(u8, &recorded, boot)) return from_another_boot;
    if (std.mem.eql(u8, &p.new_policy, digest) and p.generation == generation)
        return .{ .event = "policy_change_completed_after_restart", .reason = "completed_after_restart", .detail = restart_detail };
    if (std.mem.eql(u8, &p.old_policy, digest) and p.generation == generation + 1)
        return .{ .event = "policy_change_failed", .reason = "interrupted", .detail = restart_detail };
    return error.InvalidPendingReload;
}

/// `app on` (a new arming) or `app off`. The record's arming has ended, by a reboot, an off or lost pins, so the
/// record is settled and cleared instead of being left for a later restart to compare with another arming.
pub fn settleAtArmingChange(p: Pending, boot: *const [36]u8) Settled {
    if (p.boot) |recorded| if (!std.mem.eql(u8, &recorded, boot)) return from_another_boot;
    return .{ .event = "policy_change_failed", .reason = "interrupted_arming_ended", .detail = "pending_record_settled_by_on_or_off" };
}
pub fn write(gpa: std.mem.Allocator, io: std.Io, armed: bool, digest: *const [64]u8) !void {
    const boot = try bootId();
    const bytes = try std.json.Stringify.valueAlloc(gpa, Wire{ .version = 1, .armed = armed, .boot_id = &boot, .policy_sha256 = digest }, .{});
    defer gpa.free(bytes);
    var dir = try std.Io.Dir.openDirAbsolute(io, host.state_root, .{});
    defer dir.close(io);
    try host.atomicWrite(dir, io, "intent.json", bytes, true);
}
pub fn absentPinsStatus(saved: ?Intent, boot: *const [36]u8) []const u8 {
    const s = saved orelse return "off";
    if (!s.armed) return "off";
    return if (std.mem.eql(u8, &s.boot, boot)) "disarmed_pins_missing" else "disarmed_by_reboot";
}
test "appfilter persisted intent distinguishes reboot, missing pins and authorized off" {
    const boot = "00000000-0000-0000-0000-000000000001".*;
    var saved: Intent = .{ .armed = true, .boot = boot, .policy = @splat('0') };
    try std.testing.expectEqualStrings("disarmed_pins_missing", absentPinsStatus(saved, &boot));
    saved.boot[35] = '2';
    try std.testing.expectEqualStrings("disarmed_by_reboot", absentPinsStatus(saved, &boot));
    saved.armed = false;
    try std.testing.expectEqualStrings("off", absentPinsStatus(saved, &boot));
    try std.testing.expectEqualStrings("off", absentPinsStatus(null, &boot));
    try std.testing.expectError(error.InvalidIntent, parse(std.testing.allocator, "{\"armed\":false}"));
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, Wire{ .version = 1, .armed = true, .boot_id = &boot, .policy_sha256 = &saved.policy }, .{});
    defer std.testing.allocator.free(bytes);
    const got = try parse(std.testing.allocator, bytes);
    try std.testing.expect(got.armed);
    try std.testing.expectEqualSlices(u8, &boot, &got.boot);
}

test "appfilter v2 intent binds the ordered bounded history to the committed digest" {
    const boot = "00000000-0000-0000-0000-000000000001";
    const first: [64]u8 = @splat('1');
    const second: [64]u8 = @splat('2');
    const hashes = [_][]const u8{ &first, &second };
    var identities: [abi.max_apps]?Identity = @splat(null);
    identities[0] = .{ .device = 8, .inode = 12 };
    const w: Wire = .{ .version = 2, .armed = true, .boot_id = boot, .policy_sha256 = &second, .generation = 2, .retired_slots = 1, .generations = &hashes, .identities = &identities };
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, w, .{});
    defer std.testing.allocator.free(bytes);
    const saved = try parse(std.testing.allocator, bytes);
    try std.testing.expectEqual(@as(u32, 2), saved.generation);
    try std.testing.expectEqual(@as(u8, 1), saved.retired_slots);
    try std.testing.expectEqualStrings(&first, &saved.history[0]);
    try std.testing.expectEqualStrings(&second, &saved.history[1]);
    for (0..5) |scenario| {
        var bad = w;
        switch (scenario) {
            0 => bad.generation = 1,
            1 => bad.policy_sha256 = &first,
            2 => bad.generations = null,
            3 => bad.retired_slots = 128,
            4 => bad.identities = null,
            else => unreachable,
        }
        const malformed = try std.json.Stringify.valueAlloc(std.testing.allocator, bad, .{});
        defer std.testing.allocator.free(malformed);
        try std.testing.expectError(error.InvalidIntent, parse(std.testing.allocator, malformed));
    }
}

test "appfilter pending reload record keeps its boot and reads older records without one" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    try std.testing.expectEqual(@as(?Pending, null), try pendingReadIn(gpa, io, tmp.dir));
    const record: Pending = .{ .generation = 3, .old_policy = @splat('a'), .new_policy = @splat('b'), .boot = "00000000-0000-0000-0000-000000000001".* };
    try pendingWriteIn(gpa, io, tmp.dir, record);
    const got = (try pendingReadIn(gpa, io, tmp.dir)).?;
    try std.testing.expectEqual(@as(u32, 3), got.generation);
    try std.testing.expectEqualStrings(&record.boot.?, &got.boot.?);
    try std.testing.expectEqualStrings(&record.new_policy, &got.new_policy);
    var unbooted = record;
    unbooted.boot = null;
    try std.testing.expectError(error.InvalidIntent, pendingWriteIn(gpa, io, tmp.dir, unbooted));
    const fields = "\"old_policy\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"new_policy\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"";
    const legacy = "{\"generation\":2," ++ fields ++ "}";
    try tmp.dir.writeFile(io, .{ .sub_path = pending_name, .data = legacy });
    try std.testing.expectEqual(@as(?[36]u8, null), (try pendingReadIn(gpa, io, tmp.dir)).?.boot);
    const bad_records = [_][]const u8{ "{", "{\"generation\":1," ++ fields ++ "}", "{\"generation\":2," ++ fields ++ ",\"boot_id\":\"not-a-boot\"}" };
    for (bad_records) |bad| {
        try tmp.dir.writeFile(io, .{ .sub_path = pending_name, .data = bad });
        try std.testing.expectError(error.InvalidIntent, pendingReadIn(gpa, io, tmp.dir));
    }
    try pendingClearIn(io, tmp.dir);
    try std.testing.expectEqual(@as(?Pending, null), try pendingReadIn(gpa, io, tmp.dir));
    try pendingClearIn(io, tmp.dir);
}

test "appfilter restart settles a pending record from another boot and refuses an inconsistent one from this boot" {
    const boot = "00000000-0000-0000-0000-000000000001".*;
    const other = "00000000-0000-0000-0000-000000000002".*;
    const old: [64]u8 = @splat('a');
    const new: [64]u8 = @splat('b');
    const unrelated: [64]u8 = @splat('c');
    const record: Pending = .{ .generation = 2, .old_policy = old, .new_policy = new, .boot = boot };
    try std.testing.expectEqualStrings("completed_after_restart", (try settleAtRestart(record, &boot, 2, &new)).reason);
    try std.testing.expectEqualStrings("policy_change_completed_after_restart", (try settleAtRestart(record, &boot, 2, &new)).event);
    try std.testing.expectEqualStrings("interrupted", (try settleAtRestart(record, &boot, 1, &old)).reason);
    // Same boot, matching neither the committed generation nor its predecessor: fail closed.
    try std.testing.expectError(error.InvalidPendingReload, settleAtRestart(record, &boot, 1, &unrelated));
    try std.testing.expectError(error.InvalidPendingReload, settleAtRestart(record, &boot, 3, &new));
    // Another boot: never compared with the current arming, even when the hashes happen to match it.
    var stale = record;
    stale.boot = other;
    for ([_]struct { u32, *const [64]u8 }{ .{ 1, &unrelated }, .{ 1, &old }, .{ 2, &new } }) |arming| {
        const settled = try settleAtRestart(stale, &boot, arming[0], arming[1]);
        try std.testing.expectEqualStrings("policy_change_failed", settled.event);
        try std.testing.expectEqualStrings("interrupted_by_reboot", settled.reason);
    }
    // A record without a boot keeps the same-boot rules.
    var legacy = record;
    legacy.boot = null;
    try std.testing.expectError(error.InvalidPendingReload, settleAtRestart(legacy, &boot, 1, &unrelated));
    try std.testing.expectEqualStrings("interrupted", (try settleAtRestart(legacy, &boot, 1, &old)).reason);
}

test "appfilter on and off settle any pending record" {
    const boot = "00000000-0000-0000-0000-000000000001".*;
    const record: Pending = .{ .generation = 2, .old_policy = @splat('a'), .new_policy = @splat('b'), .boot = "00000000-0000-0000-0000-000000000002".* };
    try std.testing.expectEqualStrings("interrupted_by_reboot", settleAtArmingChange(record, &boot).reason);
    var same = record;
    same.boot = boot;
    try std.testing.expectEqualStrings("interrupted_arming_ended", settleAtArmingChange(same, &boot).reason);
    same.boot = null;
    try std.testing.expectEqualStrings("interrupted_arming_ended", settleAtArmingChange(same, &boot).reason);
    for ([_]Settled{ settleAtArmingChange(record, &boot), settleAtArmingChange(same, &boot), unreadable }) |settled|
        try std.testing.expectEqualStrings("policy_change_failed", settled.event);
}
