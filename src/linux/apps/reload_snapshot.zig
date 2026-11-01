//! Immutable whole-generation policy snapshots. The caller must retain
//! every input policy/path and published snapshot until all workers have stopped.
const std = @import("std");
const abi = @import("types.zig");
const config = @import("config.zig");
const policy = @import("../../core/policy.zig");

pub const max_generations = config.max_generations;
pub const Stamp = struct {
    generation: u32,
    digest: [32]u8,

    pub fn eql(a: Stamp, b: Stamp) bool {
        return a.generation == b.generation and std.mem.eql(u8, &a.digest, &b.digest);
    }
};

pub const Input = struct {
    executable: []const u8,
    network: *const policy.Policy,
    /// Validated kernel identity, never a client-provided device/inode pair.
    identity: abi.FileKey,
    /// A positive result refuses the plan. A negative result alone is NOT proof
    /// against a concurrent exec/fork: the admission fence remains required.
    running_untagged: bool,
};

pub const Binding = struct {
    executable: []const u8,
    network: *const policy.Policy,
    identity: abi.FileKey,
    stamp: Stamp,
    active: bool,
};

pub const Snapshot = struct {
    stamp: Stamp,
    slots: [abi.max_apps]?Binding = @splat(null),

    pub fn initial(stamp: Stamp, inputs: []const Input) !Snapshot {
        if (stamp.generation != 1) return error.InitialGenerationMustBeOne;
        try validate(inputs);
        var s: Snapshot = .{ .stamp = stamp };
        for (inputs, 0..) |input, i| {
            if (input.running_untagged) return error.CloseListedAppsFirst;
            s.slots[i] = bind(input, stamp);
        }
        return s;
    }

    pub fn capture(s: *const Snapshot, app_id: u32) !Capture {
        if (app_id == 0 or app_id > abi.max_apps) return error.InvalidAppId;
        const binding = s.slots[app_id - 1] orelse return error.UnassignedApp;
        // A retired slot deliberately retains the last policy and generation.
        return .{ .app_id = app_id, .binding = binding };
    }
};

pub const Capture = struct {
    app_id: u32,
    binding: Binding,

    pub fn checkPort(c: Capture, port: u16) policy.Verdict {
        return c.binding.network.checkPort(port);
    }
    pub fn checkHost(c: Capture, host: []const u8) policy.Verdict {
        return c.binding.network.checkHost(host);
    }
};

/// One cell for the ENTIRE generation, shared by every listener. Loading two
/// independent per-app cells could observe half of a multi-app update.
pub const Cell = struct {
    current: std.atomic.Value(*const Snapshot),

    pub fn init(initial: *const Snapshot) Cell {
        return .{ .current = .init(initial) };
    }
    pub fn capture(c: *const Cell, app_id: u32) !Capture {
        return c.current.load(.acquire).capture(app_id);
    }
    /// Only the coordinator may call this, while admission is fenced and
    /// after durable intent/kernel reconciliation. This is NOT a commit protocol.
    pub fn publish(c: *Cell, next: *const Snapshot) void {
        c.current.store(next, .release);
    }
};

pub const Plan = struct {
    snapshot: Snapshot,
    added: u8 = 0,
    removed: u8 = 0,

    pub fn build(previous: *const Snapshot, stamp: Stamp, inputs: []const Input) !Plan {
        if (previous.stamp.generation >= max_generations) return error.GenerationLimit;
        if (stamp.generation != previous.stamp.generation + 1) return error.ExpectedNextGeneration;
        try validate(inputs);
        var plan: Plan = .{ .snapshot = previous.* };
        plan.snapshot.stamp = stamp;
        var seen: u8 = 0;
        for (inputs) |input| {
            var index: ?usize = null;
            for (previous.slots, 0..) |slot, i| if (slot) |old| {
                if (std.mem.eql(u8, old.executable, input.executable)) {
                    if (!old.active) return error.RetiredAppRequiresRearm;
                    // Executable replacement needs a separate identity transaction;
                    // a path match cannot silently substitute a different inode.
                    if (!sameFile(old.identity, input.identity)) return error.ExecutableChanged;
                    index = i;
                    break;
                }
            };
            if (index == null) {
                if (input.running_untagged) return error.CloseAddedAppsFirst;
                // Reject aliasing a retired binding as well as another active one.
                for (previous.slots) |slot| if (slot) |old| {
                    if (sameFile(old.identity, input.identity)) return error.DuplicateExecutableIdentity;
                };
                for (plan.snapshot.slots, 0..) |slot, i| if (slot == null) {
                    index = i;
                    plan.added |= bit(i);
                    break;
                };
            }
            const i = index orelse return error.NoUnusedAppSlot;
            plan.snapshot.slots[i] = bind(input, stamp);
            seen |= bit(i);
        }
        for (&plan.snapshot.slots, 0..) |*slot, i| if (slot.*) |*binding| {
            if (binding.active and seen & bit(i) == 0) {
                binding.active = false;
                plan.removed |= bit(i);
            }
        };
        return plan;
    }
};

fn bit(i: usize) u8 {
    return @as(u8, 1) << @as(u3, @intCast(i));
}
fn bind(input: Input, stamp: Stamp) Binding {
    return .{ .executable = input.executable, .network = input.network, .identity = input.identity, .stamp = stamp, .active = true };
}
fn sameFile(a: abi.FileKey, b: abi.FileKey) bool {
    return a.device == b.device and a.inode == b.inode;
}
fn validate(inputs: []const Input) !void {
    if (inputs.len == 0 or inputs.len > abi.max_apps) return error.InvalidAppCount;
    for (inputs, 0..) |input, i| {
        if (!config.validPath(input.executable) or input.identity.zero != 0) return error.InvalidExecutable;
        for (inputs[0..i]) |old| {
            if (std.mem.eql(u8, input.executable, old.executable)) return error.DuplicateApp;
            if (sameFile(input.identity, old.identity)) return error.DuplicateExecutableIdentity;
        }
    }
}

fn testPolicy(host: []const u8, port: u16) !policy.Policy {
    const bytes = try std.fmt.allocPrint(std.testing.allocator, "{{\"version\":\"blackice.policy/v0\",\"network\":{{\"mode\":\"allowlist\",\"allow\":[\"{s}\"],\"ports\":[{d}]}}}}", .{ host, port });
    defer std.testing.allocator.free(bytes);
    return policy.Policy.parse(std.testing.allocator, bytes, null);
}
fn testInput(path: []const u8, pol: *const policy.Policy, inode: u64) Input {
    return .{ .executable = path, .network = pol, .identity = .{ .device = 1, .inode = inode }, .running_untagged = false };
}
fn testStamp(gen: u32) Stamp {
    return .{ .generation = gen, .digest = @splat(@truncate(gen)) };
}

test "appfilter reload capture holds port host and receipt stamp from one generation" {
    var old = try testPolicy("example.com", 80);
    defer old.deinit();
    var new = try testPolicy("httpbingo.org", 443);
    defer new.deinit();
    const first = try Snapshot.initial(testStamp(1), &.{testInput("/usr/bin/app-a", &old, 1)});
    const plan = try Plan.build(&first, testStamp(2), &.{testInput("/usr/bin/app-a", &new, 1)});
    var cell = Cell.init(&first);
    const accepted = try cell.capture(1);
    try std.testing.expect(accepted.checkPort(80).allowed);
    cell.publish(&plan.snapshot);
    try std.testing.expect(accepted.checkHost("example.com").allowed);
    try std.testing.expect(!accepted.checkHost("httpbingo.org").allowed);
    try std.testing.expectEqual(@as(u32, 1), accepted.binding.stamp.generation);
    const next = try cell.capture(1);
    try std.testing.expect(!next.checkPort(80).allowed);
    try std.testing.expect(next.checkHost("httpbingo.org").allowed);
    try std.testing.expect(next.binding.stamp.eql(testStamp(2)));
    try std.testing.expectError(error.InvalidAppId, cell.capture(0));
    try std.testing.expectError(error.UnassignedApp, cell.capture(7));
}

test "appfilter reload reordering preserves slots and tags need no rewrite" {
    var pol = try testPolicy("example.com", 443);
    defer pol.deinit();
    const a = testInput("/usr/bin/app-a", &pol, 11);
    const b = testInput("/usr/bin/app-b", &pol, 12);
    const first = try Snapshot.initial(testStamp(1), &.{ a, b });
    const plan = try Plan.build(&first, testStamp(2), &.{ b, a });
    try std.testing.expectEqualStrings(a.executable, plan.snapshot.slots[0].?.executable);
    try std.testing.expectEqualStrings(b.executable, plan.snapshot.slots[1].?.executable);
    try std.testing.expectEqual(@as(u8, 0), plan.added | plan.removed);
}

test "appfilter reload removal retains the old decision and never reuses its slot" {
    var old = try testPolicy("example.com", 443);
    defer old.deinit();
    var new = try testPolicy("httpbingo.org", 443);
    defer new.deinit();
    const a = testInput("/usr/bin/app-a", &old, 11);
    const b = testInput("/usr/bin/app-b", &old, 12);
    const first = try Snapshot.initial(testStamp(1), &.{ a, b });
    const second = try Plan.build(&first, testStamp(2), &.{testInput(a.executable, &new, 11)});
    const retired = try second.snapshot.capture(2);
    try std.testing.expect(!retired.binding.active);
    try std.testing.expect(retired.checkHost("example.com").allowed);
    try std.testing.expectEqual(@as(u32, 1), retired.binding.stamp.generation);
    const third = try Plan.build(&second.snapshot, testStamp(3), &.{ a, testInput("/usr/bin/app-c", &new, 13) });
    try std.testing.expectEqualStrings("/usr/bin/app-c", third.snapshot.slots[2].?.executable);
    try std.testing.expectEqual(@as(u8, 4), third.added);
    try std.testing.expectError(error.RetiredAppRequiresRearm, Plan.build(&second.snapshot, testStamp(3), &.{ a, b }));
}

test "appfilter reload refuses already running additions and inode aliases without mutation" {
    var pol = try testPolicy("example.com", 443);
    defer pol.deinit();
    const a = testInput("/usr/bin/app-a", &pol, 11);
    const first = try Snapshot.initial(testStamp(1), &.{a});
    var b = testInput("/usr/bin/app-b", &pol, 12);
    b.running_untagged = true;
    try std.testing.expectError(error.CloseAddedAppsFirst, Plan.build(&first, testStamp(2), &.{ a, b }));
    try std.testing.expect(first.stamp.eql(testStamp(1)));
    try std.testing.expect(first.slots[1] == null);
    b.running_untagged = false;
    b.identity.inode = 11;
    try std.testing.expectError(error.DuplicateExecutableIdentity, Plan.build(&first, testStamp(2), &.{ a, b }));
    var replaced = a;
    replaced.identity.inode = 99;
    try std.testing.expectError(error.ExecutableChanged, Plan.build(&first, testStamp(2), &.{replaced}));
}

test "appfilter reload rejects skipped stale and exhausted generations" {
    var pol = try testPolicy("example.com", 443);
    defer pol.deinit();
    const a = testInput("/usr/bin/app-a", &pol, 11);
    var first = try Snapshot.initial(testStamp(1), &.{a});
    for ([_]u32{ 0, 1, 3, 256 }) |gen|
        try std.testing.expectError(error.ExpectedNextGeneration, Plan.build(&first, testStamp(gen), &.{a}));
    first.stamp = testStamp(max_generations);
    try std.testing.expectError(error.GenerationLimit, Plan.build(&first, testStamp(max_generations + 1), &.{a}));
}

test "appfilter reload retired slots count toward the seven slot bound" {
    var pol = try testPolicy("example.com", 443);
    defer pol.deinit();
    const paths = [_][]const u8{ "/bin/app-a", "/bin/app-b", "/bin/app-c", "/bin/app-d", "/bin/app-e", "/bin/app-f", "/bin/app-g" };
    var inputs: [abi.max_apps]Input = undefined;
    for (paths, 0..) |path, i| inputs[i] = testInput(path, &pol, i + 1);
    const first = try Snapshot.initial(testStamp(1), &inputs);
    const second = try Plan.build(&first, testStamp(2), inputs[0..1]);
    try std.testing.expectError(error.NoUnusedAppSlot, Plan.build(&second.snapshot, testStamp(3), &.{ inputs[0], testInput("/bin/app-h", &pol, 8) }));
    try std.testing.expect(second.snapshot.stamp.eql(testStamp(2)));
    try std.testing.expect(!second.snapshot.slots[1].?.active);
}

test "appfilter reload counterexample a negative executable rescan misses an untagged descendant" {
    const lifecycle = @import("state.zig");
    // App A executes before its new files entry exists. It spawns a helper whose
    // executable is B, then exits. A scan for running A sees none; the helper
    // remains untagged even after A's files entry is published. This is a model
    // counterexample, NOT a successful live-add implementation or a kernel test.
    const before_insertion = lifecycle.execTag(0, 0, 1000, 1000);
    const child = lifecycle.forkTag(before_insertion, 0);
    const helper = lifecycle.execTag(child, 0, 1000, 1000);
    const running_added_executable = false;
    const next_launch = lifecycle.execTag(0, 3, 1000, 1000);
    try std.testing.expect(!running_added_executable);
    try std.testing.expectEqual(@as(u32, 0), helper);
    try std.testing.expectEqual(@as(u32, 3), next_launch);
}
