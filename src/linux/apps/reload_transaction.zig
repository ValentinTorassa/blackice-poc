//! Pure coordinator contract, NOT an implemented runtime transaction.
//! Methods represent verified effects. They never perform auth, BPF, I/O or IPC.
//! Do not expose these acknowledgements as client-controlled control messages.
const std = @import("std");
const snapshot = @import("reload_snapshot.zig");
const Stamp = snapshot.Stamp;

pub const Authorization = struct {
    owner_uid: u32,
    peer_uid: u32,
    tagged: bool,
    /// Must come from a fresh polkit check against the SO_PEERPIDFD identity.
    polkit_authenticated: bool,
};
pub const Phase = enum { idle, preparing, prepared, fenced, durable, kernel_ready, proxy_ready, complete, failed };
pub const Recovery = struct { target: Stamp, interrupted: bool, retain_fence: bool = true };
pub const Transaction = struct {
    previous: Stamp,
    candidate: ?Stamp = null,
    phase: Phase = .idle,
    kernel_fenced: bool = false,
    proxy_fenced: bool = false,

    pub fn begin(t: *Transaction, candidate: Stamp, auth: Authorization, armed: bool, stopping: bool) !void {
        if (stopping) return error.Stopping;
        if (!armed) return error.NotArmed;
        if (t.phase != .idle) return error.ChangeInProgress;
        if (auth.owner_uid == 0 or auth.peer_uid != auth.owner_uid) return error.NotOwner;
        if (auth.tagged) return error.TaggedCaller;
        if (!auth.polkit_authenticated) return error.NotAuthorized;
        if (t.previous.generation >= snapshot.max_generations) return error.GenerationLimit;
        if (candidate.generation != t.previous.generation + 1) return error.ExpectedNextGeneration;
        t.candidate = candidate;
        t.phase = .preparing;
    }
    pub fn prepared(t: *Transaction, acknowledged: Stamp) !void {
        try t.expectPhase(.preparing);
        try t.expectStamp(acknowledged);
        t.phase = .prepared;
    }
    pub fn kernelFence(t: *Transaction) !void {
        try t.expectPhase(.prepared);
        t.kernel_fenced = true;
        t.fencedIfReady();
    }
    pub fn proxyFence(t: *Transaction, acknowledged: Stamp) !void {
        try t.expectPhase(.prepared);
        try t.expectStamp(acknowledged);
        t.proxy_fenced = true;
        t.fencedIfReady();
    }
    fn fencedIfReady(t: *Transaction) void {
        if (t.kernel_fenced and t.proxy_fenced) t.phase = .fenced;
    }
    pub fn intentCommitted(t: *Transaction, durable_stamp: Stamp) !void {
        try t.expectPhase(.fenced);
        try t.expectStamp(durable_stamp);
        t.phase = .durable;
    }
    pub fn kernelReconciled(t: *Transaction, verified_stamp: Stamp) !void {
        try t.expectPhase(.durable);
        try t.expectStamp(verified_stamp);
        t.phase = .kernel_ready;
    }
    pub fn proxyActivated(t: *Transaction, acknowledged: Stamp) !void {
        try t.expectPhase(.kernel_ready);
        try t.expectStamp(acknowledged);
        t.phase = .proxy_ready;
    }
    pub fn releaseAdmission(t: *Transaction, kernel_stamp: Stamp, service_stamp: Stamp, proxy_stamp: Stamp) !Stamp {
        try t.expectPhase(.proxy_ready);
        try t.expectStamp(kernel_stamp);
        try t.expectStamp(service_stamp);
        try t.expectStamp(proxy_stamp);
        t.phase = .complete;
        t.kernel_fenced = false;
        t.proxy_fenced = false;
        return t.candidate.?;
    }
    /// Any loss of acknowledgement makes the worker unavailable, not implicitly
    /// ready. A future runtime must retain pins and reconcile before admitting.
    pub fn failed(t: *Transaction) void {
        t.phase = .failed;
    }
    pub fn recovery(t: Transaction, durable_intent: Stamp) !Recovery {
        const candidate = t.candidate orelse return error.NoTransaction;
        if (durable_intent.eql(candidate)) return .{ .target = candidate, .interrupted = false };
        if (durable_intent.eql(t.previous)) return .{ .target = t.previous, .interrupted = true };
        return error.UnknownDurableIntent;
    }
    fn expectPhase(t: Transaction, phase: Phase) !void {
        if (t.phase != phase) return error.InvalidReloadOrder;
    }
    fn expectStamp(t: Transaction, value: Stamp) !void {
        if (!(t.candidate orelse return error.NoTransaction).eql(value)) return error.ReloadStampMismatch;
    }
};

const old: Stamp = .{ .generation = 1, .digest = @splat(0x11) };
const new: Stamp = .{ .generation = 2, .digest = @splat(0x22) };
const owner: Authorization = .{ .owner_uid = 1000, .peer_uid = 1000, .tagged = false, .polkit_authenticated = true };

test "appfilter reload cannot publish proxy early or release a half committed generation" {
    var t: Transaction = .{ .previous = old };
    try t.begin(new, owner, true, false);
    try t.prepared(new);
    try std.testing.expectError(error.InvalidReloadOrder, t.proxyActivated(new));
    try std.testing.expectError(error.InvalidReloadOrder, t.intentCommitted(new));
    try t.proxyFence(new);
    try std.testing.expectError(error.InvalidReloadOrder, t.intentCommitted(new));
    try t.kernelFence();
    try t.intentCommitted(new);
    try std.testing.expectError(error.InvalidReloadOrder, t.releaseAdmission(new, new, new));
    try t.kernelReconciled(new);
    try t.proxyActivated(new);
    try std.testing.expectError(error.ReloadStampMismatch, t.releaseAdmission(old, new, new));
    try std.testing.expectError(error.ReloadStampMismatch, t.releaseAdmission(new, old, new));
    try std.testing.expectError(error.ReloadStampMismatch, t.releaseAdmission(new, new, old));
    try std.testing.expect(t.kernel_fenced and t.proxy_fenced);
    try std.testing.expect((try t.releaseAdmission(new, new, new)).eql(new));
    try std.testing.expectEqual(Phase.complete, t.phase);
}

test "appfilter reload untagged owner still needs fresh polkit and tagged callers refuse" {
    var t: Transaction = .{ .previous = old };
    var denied = owner;
    denied.polkit_authenticated = false;
    try std.testing.expectError(error.NotAuthorized, t.begin(new, denied, true, false));
    denied = owner;
    denied.tagged = true;
    try std.testing.expectError(error.TaggedCaller, t.begin(new, denied, true, false));
    denied = owner;
    denied.peer_uid = 1001;
    try std.testing.expectError(error.NotOwner, t.begin(new, denied, true, false));
    try std.testing.expectEqual(Phase.idle, t.phase);
    try std.testing.expect(t.candidate == null);
    try std.testing.expectError(error.NotArmed, t.begin(new, owner, false, false));
    try std.testing.expectError(error.Stopping, t.begin(new, owner, true, true));
    try t.begin(new, owner, true, false);
    try std.testing.expectError(error.ChangeInProgress, t.begin(new, owner, true, false));
}

test "appfilter reload recovery obeys durable intent across every interruption" {
    for (std.meta.tags(Phase)) |phase| {
        var t: Transaction = .{ .previous = old, .candidate = new, .phase = phase };
        const before = try t.recovery(old);
        try std.testing.expect(before.target.eql(old) and before.interrupted and before.retain_fence);
        const after = try t.recovery(new);
        try std.testing.expect(after.target.eql(new) and !after.interrupted and after.retain_fence);
        t.failed();
        try std.testing.expectError(error.InvalidReloadOrder, t.releaseAdmission(new, new, new));
        var foreign = new;
        foreign.digest[0] ^= 1;
        try std.testing.expectError(error.UnknownDurableIntent, t.recovery(foreign));
    }
}
