//! Generation map writer used by the reload coordinator. Never loads/attaches code.
//! All maps are created at arming, before dropping capabilities. Later operations
//! use those FDs only. The service coordinates these writes with the child and intent.
const std = @import("std");
const sys = @import("../sys.zig");
const bpf = sys.l.BPF;
const abi = @import("types.zig");
pub const types = @import("reload_kernel_types.zig");
const snapshot = @import("reload_snapshot.zig");
const zero: u32 = 0;
const FileRow = struct { key: types.FileKey, app_id: u32 };
const PortRow = struct { key: types.PortKey, value: types.PortValue };
pub const Image = struct {
    state: types.State,
    files: [abi.max_apps]?FileRow = @splat(null),
    ports: [abi.max_apps]?PortRow = @splat(null),

    pub fn fromSnapshot(owner: u32, s: *const snapshot.Snapshot) !Image {
        var image: Image = .{ .state = .{
            .base = .{ .phase = .armed, .owner_uid = owner, .app_count = 0, .version = 2, .policy_sha256 = s.stamp.digest },
            .generation = s.stamp.generation,
            .fenced = 1,
        } };
        for (s.slots, 0..) |slot, i| if (slot) |binding| {
            const app: u32 = @intCast(i + 1);
            image.state.base.app_count += 1;
            if (binding.stamp.generation == 0 or binding.stamp.generation > s.stamp.generation) return error.InvalidBindingGeneration;
            var ports = abi.ports(app);
            inline for (@typeInfo(abi.Ports).@"struct".field_names) |field| @field(ports, field) = std.mem.nativeToBig(u16, @field(ports, field));
            image.ports[i] = .{ .key = .{ .app_id = app, .generation = s.stamp.generation }, .value = .{ .ports = ports, .decision_generation = binding.stamp.generation } };
            if (binding.active) image.files[i] = .{ .key = .{ .device = binding.identity.device, .inode = binding.identity.inode, .generation = s.stamp.generation }, .app_id = app };
        };
        if (!types.valid(image.state)) return error.InvalidGenerationState;
        return image;
    }
};
pub const Prepared = struct { previous: snapshot.Stamp, state: types.State };
pub fn stamp(s: types.State) snapshot.Stamp {
    return .{ .generation = s.generation, .digest = s.base.policy_sha256 };
}

/// The sole writer stages only previously unused keys (BPF_NOEXIST). A failure
/// may leave unreachable rows; it never changes the active generation. Do not
/// retry/reuse that namespace without explicit crash/abort reconciliation.
pub fn stage(writer: anytype, image: *const Image) !Prepared {
    try validateImage(image);
    const old = try writer.active();
    if (!types.valid(old) or !types.valid(image.state)) return error.InvalidGenerationState;
    if (old.generation >= types.max_generations or image.state.generation != old.generation + 1) return error.ExpectedNextGeneration;
    if (old.base.owner_uid != image.state.base.owner_uid or image.state.fenced != 1) return error.InvalidGenerationState;
    for (image.ports) |row| if (row) |r| try writer.addPort(r.key, r.value);
    for (image.files) |row| if (row) |r| try writer.addFile(r.key, r.app_id);
    return .{ .previous = stamp(old), .state = image.state };
}

fn validateImage(image: *const Image) !void {
    if (!types.valid(image.state) or image.state.fenced != 1) return error.InvalidGenerationState;
    var slots: u32 = 0;
    var active: u32 = 0;
    for (image.ports, image.files, 0..) |port, file, i| {
        const id: u32 = @intCast(i + 1);
        if (port) |p| {
            slots += 1;
            if (p.key.app_id != id or p.key.generation != image.state.generation or
                p.value.decision_generation == 0 or p.value.decision_generation > image.state.generation) return error.InvalidGenerationRow;
            const expected = abi.ports(id);
            inline for (@typeInfo(abi.Ports).@"struct".field_names) |field|
                if (@field(p.value.ports, field) != std.mem.nativeToBig(u16, @field(expected, field))) return error.InvalidGenerationRow;
        }
        if (file) |f| {
            active += 1;
            if (port == null or f.app_id != id or f.key.generation != image.state.generation or
                port.?.value.decision_generation != image.state.generation) return error.InvalidGenerationRow;
            for (image.files[0..i]) |old| if (old) |o| {
                if (o.key.device == f.key.device and o.key.inode == f.key.inode) return error.DuplicateExecutableIdentity;
            };
        }
    }
    if (active == 0 or slots != image.state.base.app_count) return error.InvalidGenerationRow;
}

/// A single hash-element replacement publishes the complete kernel generation.
/// Admission stays fenced. The future coordinator alone may reopen it after
/// durable intent, service and proxy all acknowledge the same generation/digest.
pub fn publishFenced(writer: anytype, prepared: Prepared) !void {
    const current = try writer.active();
    if (!types.valid(current) or !types.valid(prepared.state)) return error.InvalidGenerationState;
    if (!stamp(current).eql(prepared.previous)) return error.StalePreparedGeneration;
    if (prepared.state.generation != current.generation + 1 or prepared.state.base.owner_uid != current.base.owner_uid) return error.InvalidGenerationState;
    if (current.fenced != 1 or prepared.state.fenced != 1) return error.AdmissionNotFenced;
    try writer.replaceActive(prepared.state);
}

pub const Maps = struct {
    state: sys.l.fd_t = -1,
    files: sys.l.fd_t = -1,
    ports: sys.l.fd_t = -1,

    pub fn create() !Maps {
        var m: Maps = .{};
        errdefer m.close();
        // An array's in-place update would not publish a coherent composite value.
        m.state = try bpf.map_create(.hash, 4, @sizeOf(types.State), 1);
        m.files = try bpf.map_create(.hash, @sizeOf(types.FileKey), 4, types.max_rows);
        m.ports = try bpf.map_create(.hash, @sizeOf(types.PortKey), @sizeOf(types.PortValue), types.max_rows);
        return m;
    }
    pub fn close(m: *Maps) void {
        for ([_]sys.l.fd_t{ m.state, m.files, m.ports }) |fd| if (fd >= 0) sys.close(fd);
        m.* = .{};
    }
    pub fn active(m: *Maps) !types.State {
        var s: types.State = undefined;
        try bpf.map_lookup_elem(m.state, std.mem.asBytes(&zero), std.mem.asBytes(&s));
        if (!types.valid(s)) return error.InvalidGenerationState;
        return s;
    }
    pub fn addFile(m: *Maps, key: types.FileKey, app: u32) !void {
        try bpf.map_update_elem(m.files, std.mem.asBytes(&key), std.mem.asBytes(&app), 1); // BPF_NOEXIST
    }
    pub fn addPort(m: *Maps, key: types.PortKey, value: types.PortValue) !void {
        try bpf.map_update_elem(m.ports, std.mem.asBytes(&key), std.mem.asBytes(&value), 1);
    }
    pub fn replaceActive(m: *Maps, value: types.State) !void {
        if (!types.valid(value)) return error.InvalidGenerationState;
        try bpf.map_update_elem(m.state, std.mem.asBytes(&zero), std.mem.asBytes(&value), 2); // BPF_EXIST
    }
    pub fn initialize(m: *Maps, image: *const Image) !void {
        try validateImage(image);
        if (image.state.generation != 1) return error.InvalidGenerationState;
        for (image.ports) |row| if (row) |r| try m.addPort(r.key, r.value);
        for (image.files) |row| if (row) |r| try m.addFile(r.key, r.app_id);
        try bpf.map_update_elem(m.state, std.mem.asBytes(&zero), std.mem.asBytes(&image.state), 1);
    }
};

const Fake = struct {
    state: types.State,
    writes: usize = 0,
    fail_at: usize = 999,
    publications: usize = 0,
    tags: [3]u32 = .{ 1, 2, 2 },
    fn active(f: *Fake) !types.State {
        return f.state;
    }
    fn write(f: *Fake) !void {
        if (f.writes == f.fail_at) return error.InjectedMapFailure;
        f.writes += 1;
    }
    fn addPort(f: *Fake, _: types.PortKey, _: types.PortValue) !void {
        try f.write();
    }
    fn addFile(f: *Fake, _: types.FileKey, _: u32) !void {
        try f.write();
    }
    fn replaceActive(f: *Fake, s: types.State) !void {
        try f.write();
        f.state = s;
        f.publications += 1;
    }
};
fn fixture(gen: u32) Image {
    var image: Image = .{ .state = .{ .base = .{ .phase = .armed, .owner_uid = 1000, .app_count = 2, .version = 2, .policy_sha256 = @splat(@truncate(gen)) }, .generation = gen, .fenced = 1 } };
    for (0..2) |i| {
        const app: u32 = @intCast(i + 1);
        image.files[i] = .{ .key = .{ .device = 1, .inode = app, .generation = gen }, .app_id = app };
        var ports = abi.ports(app);
        inline for (@typeInfo(abi.Ports).@"struct".field_names) |field| @field(ports, field) = std.mem.nativeToBig(u16, @field(ports, field));
        image.ports[i] = .{ .key = .{ .app_id = app, .generation = gen }, .value = .{ .ports = ports, .decision_generation = gen } };
    }
    return image;
}
test "appfilter generation staging failures never publish or clear process tags" {
    const image = fixture(2);
    for (0..4) |failure| {
        var f: Fake = .{ .state = fixture(1).state, .fail_at = failure };
        try std.testing.expectError(error.InjectedMapFailure, stage(&f, &image));
        try std.testing.expectEqual(@as(u32, 1), f.state.generation);
        try std.testing.expectEqual(@as(usize, 0), f.publications);
        try std.testing.expectEqualSlices(u32, &.{ 1, 2, 2 }, &f.tags);
    }
}
test "appfilter staged generation needs a fence and a matching active record before one publication" {
    var f: Fake = .{ .state = fixture(1).state };
    const image = fixture(2);
    const prepared = try stage(&f, &image);
    try std.testing.expectEqual(@as(u32, 1), f.state.generation);
    f.state.fenced = 0;
    try std.testing.expectError(error.AdmissionNotFenced, publishFenced(&f, prepared));
    f.state.fenced = 1;
    f.fail_at = f.writes;
    try std.testing.expectError(error.InjectedMapFailure, publishFenced(&f, prepared));
    try std.testing.expectEqual(@as(u32, 1), f.state.generation);
    f.fail_at = 999;
    try publishFenced(&f, prepared);
    try std.testing.expectEqual(@as(usize, 1), f.publications);
    try std.testing.expect(stamp(f.state).eql(stamp(image.state)) and f.state.fenced == 1);
    try std.testing.expectError(error.StalePreparedGeneration, publishFenced(&f, prepared));
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 2 }, &f.tags);
}
test "appfilter generation syscall adapter compiles without invoking kernel operations" {
    try std.testing.expect(@intFromPtr(&Maps.create) != 0);
    try std.testing.expect(@intFromPtr(&Maps.initialize) != 0);
    try std.testing.expect(@intFromPtr(&Maps.active) != 0);
    try std.testing.expect(@intFromPtr(&Maps.replaceActive) != 0);
}

test "appfilter malformed staged rows refuse before any map write" {
    var f: Fake = .{ .state = fixture(1).state };
    var image = fixture(2);
    image.files[0].?.key.generation = 1;
    try std.testing.expectError(error.InvalidGenerationRow, stage(&f, &image));
    image = fixture(2);
    image.ports[0].?.value.decision_generation = 3;
    try std.testing.expectError(error.InvalidGenerationRow, stage(&f, &image));
    image = fixture(2);
    image.files[1].?.key = image.files[0].?.key;
    try std.testing.expectError(error.DuplicateExecutableIdentity, stage(&f, &image));
    try std.testing.expectEqual(@as(usize, 0), f.writes);
}

test "appfilter candidate image keeps retired listener policy and omits its new epoch file entry" {
    var policy = try @import("../../core/policy.zig").Policy.parse(std.testing.allocator,
        \\{"version":"blackice.policy/v0","network":{"mode":"deny-all"}}
    , null);
    defer policy.deinit();
    const a: snapshot.Input = .{ .executable = "/usr/bin/app-a", .network = &policy, .identity = .{ .device = 1, .inode = 1 }, .running_untagged = false };
    const b: snapshot.Input = .{ .executable = "/usr/bin/app-b", .network = &policy, .identity = .{ .device = 1, .inode = 2 }, .running_untagged = false };
    const c: snapshot.Input = .{ .executable = "/usr/bin/app-c", .network = &policy, .identity = .{ .device = 1, .inode = 3 }, .running_untagged = false };
    const first = try snapshot.Snapshot.initial(stamp(fixture(1).state), &.{ a, b });
    const next = try snapshot.Plan.build(&first, stamp(fixture(2).state), &.{ a, c });
    const image = try Image.fromSnapshot(1000, &next.snapshot);
    try validateImage(&image);
    try std.testing.expect(image.files[1] == null);
    try std.testing.expectEqual(@as(u32, 1), image.ports[1].?.value.decision_generation);
    try std.testing.expectEqual(@as(u32, 2), image.ports[0].?.value.decision_generation);
    try std.testing.expectEqual(@as(u32, 3), image.files[2].?.app_id);
    try std.testing.expectEqual(@as(u32, 3), image.state.base.app_count);
}
