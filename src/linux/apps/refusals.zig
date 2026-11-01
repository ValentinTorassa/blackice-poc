//! Bounded aggregation for glibc's UDP-connect source-address sorting probes. No packets are allowed.
const std = @import("std");
const abi = @import("types.zig");
pub const Batch = struct {
    /// Zero is the legacy v1 stream. Candidate v2 readers must use addGeneration.
    generation: u32 = 0,
    ipv4: u64 = 0,
    ipv6: u64 = 0,
    first_ns: u64 = 0,
    last_ns: u64 = 0,
    pub fn add(b: *Batch, event: abi.Event) void {
        std.debug.assert(b.generation == 0);
        b.addCounts(event);
    }
    /// The caller flushes the old batch before retrying a different generation.
    /// A delayed old event must not be merged into a newer generation's summary.
    pub fn addGeneration(b: *Batch, event: abi.Event, generation: u32) !void {
        if (generation == 0 or generation > @import("config.zig").max_generations) return error.InvalidEventGeneration;
        if (!b.empty() and b.generation != generation) return error.GenerationBoundary;
        b.generation = generation;
        b.addCounts(event);
    }
    fn addCounts(b: *Batch, event: abi.Event) void {
        if (b.ipv4 == 0 and b.ipv6 == 0) b.first_ns = event.timestamp_ns;
        b.last_ns = event.timestamp_ns;
        if (event.hook == @backingInt(std.os.linux.BPF.AttachType.cgroup_inet4_connect)) b.ipv4 +|= 1 else b.ipv6 +|= 1;
    }
    pub fn empty(b: Batch) bool {
        return b.ipv4 == 0 and b.ipv6 == 0;
    }
};
test "appfilter UDP connect aggregation preserves refusal counts and event time bounds" {
    var batch: Batch = .{};
    var event: abi.Event = std.mem.zeroes(abi.Event);
    event.hook = @backingInt(std.os.linux.BPF.AttachType.cgroup_inet4_connect);
    event.timestamp_ns = 10;
    batch.add(event);
    event.hook = @backingInt(std.os.linux.BPF.AttachType.cgroup_inet6_connect);
    event.timestamp_ns = 20;
    batch.add(event);
    try std.testing.expectEqual(@as(u64, 1), batch.ipv4);
    try std.testing.expectEqual(@as(u64, 1), batch.ipv6);
    try std.testing.expectEqual(@as(u64, 10), batch.first_ns);
    try std.testing.expectEqual(@as(u64, 20), batch.last_ns);
    try std.testing.expect(!batch.empty());
}

test "appfilter UDP summaries refuse to relabel delayed events across a generation boundary" {
    var b: Batch = .{};
    var event: abi.Event = std.mem.zeroes(abi.Event);
    event.hook = @backingInt(std.os.linux.BPF.AttachType.cgroup_inet4_connect);
    event.timestamp_ns = 10;
    try b.addGeneration(event, 1);
    event.timestamp_ns = 20;
    try std.testing.expectError(error.GenerationBoundary, b.addGeneration(event, 2));
    try std.testing.expectEqual(@as(u64, 1), b.ipv4);
    try std.testing.expectEqual(@as(u64, 10), b.last_ns);
    b = .{}; // after the caller has emitted the generation-1 summary
    try b.addGeneration(event, 2);
    try std.testing.expectError(error.GenerationBoundary, b.addGeneration(event, 1));
    try std.testing.expectEqual(@as(u32, 2), b.generation);
    try std.testing.expectError(error.InvalidEventGeneration, b.addGeneration(event, 0));
}
