//! Explicit generation ABI 2; incompatible v1 pins are refused by the loader.
const std = @import("std");
const abi = @import("types.zig");
pub const max_generations = @import("config.zig").max_generations;
pub const max_rows = abi.max_apps * max_generations;
pub const State = extern struct {
    base: abi.State,
    generation: u32,
    fenced: u32,
};
pub const FileKey = extern struct { device: u32, generation: u32, inode: u64 };
pub const PortKey = extern struct { app_id: u32, generation: u32 };
pub const PortValue = extern struct { ports: abi.Ports, decision_generation: u32 };
// The v1 record's first reserved word becomes an event-time generation. The size
// stays 64 bytes, but this interpretation must never be silently used for v1 pins.
pub const event_generation_offset = @offsetOf(abi.Event, "reserved");

pub fn valid(s: State) bool {
    const phase = std.mem.readInt(u32, std.mem.asBytes(&s)[0..4], .little);
    return phase == @backingInt(abi.Phase.armed) and s.base.version == 2 and
        s.base.owner_uid != 0 and s.base.app_count > 0 and s.base.app_count <= abi.max_apps and
        s.generation > 0 and s.generation <= max_generations and s.fenced <= 1;
}

test "appfilter generation ABI separates active publication from generation keyed rows" {
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(State));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(FileKey));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(PortKey));
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(PortValue));
    try std.testing.expectEqual(@as(usize, 12), event_generation_offset);
    try std.testing.expectEqual(@as(usize, 1792), max_rows);
}
