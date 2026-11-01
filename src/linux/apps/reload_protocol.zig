//! Bounded loader/worker protocol, transported over the two pre-fork pipes.
//! The only worker-to-loader record is exactly 41 bytes; no JSON is accepted.
const std = @import("std");
const snapshot = @import("reload_snapshot.zig");
const config = @import("config.zig");
pub const Stamp = snapshot.Stamp;
pub const deadline_ms = 5000;
pub const header_bytes = 52;
pub const ack_bytes = 41;
pub const Command = enum(u8) { prepare = 1, quiesce = 2, activate = 3, resume_admission = 4, abort = 5 };
pub const Status = enum(u8) { prepared = 1, quiesced = 2, activated = 3, resumed = 4, refused = 5 };
pub const Header = struct { command: Command, stamp: Stamp, length: u32 };
pub const Ack = struct { stamp: Stamp, status: Status };

pub fn encodeHeader(h: Header) ![header_bytes]u8 {
    try validHeader(h);
    var bytes: [header_bytes]u8 = @splat(0);
    @memcpy(bytes[0..4], "BAR1");
    bytes[4] = @backingInt(h.command);
    std.mem.writeInt(u64, bytes[8..16], h.stamp.generation, .little);
    std.mem.writeInt(u32, bytes[16..20], h.length, .little);
    @memcpy(bytes[20..52], &h.stamp.digest);
    return bytes;
}
pub fn decodeHeader(bytes: []const u8) !Header {
    if (bytes.len != header_bytes) return error.InvalidReloadHeader;
    if (!std.mem.eql(u8, bytes[0..4], "BAR1") or !std.mem.allEqual(u8, bytes[5..8], 0)) return error.InvalidReloadHeader;
    const command: Command = switch (bytes[4]) {
        1 => .prepare,
        2 => .quiesce,
        3 => .activate,
        4 => .resume_admission,
        5 => .abort,
        else => return error.InvalidReloadCommand,
    };
    const gen = std.mem.readInt(u64, bytes[8..16], .little);
    try validGeneration(gen);
    const h: Header = .{
        .command = command,
        .stamp = .{ .generation = @intCast(gen), .digest = bytes[20..52].* },
        .length = std.mem.readInt(u32, bytes[16..20], .little),
    };
    try validHeader(h);
    return h;
}
pub fn encodeAck(ack: Ack) ![ack_bytes]u8 {
    try validGeneration(ack.stamp.generation);
    var bytes: [ack_bytes]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..8], ack.stamp.generation, .little);
    @memcpy(bytes[8..40], &ack.stamp.digest);
    bytes[40] = @backingInt(ack.status);
    return bytes;
}
pub fn decodeAck(bytes: []const u8, expected: Stamp, expected_status: Status) !Ack {
    if (bytes.len != ack_bytes) return error.InvalidReloadAck;
    const gen = std.mem.readInt(u64, bytes[0..8], .little);
    try validGeneration(gen);
    const stamp: Stamp = .{ .generation = @intCast(gen), .digest = bytes[8..40].* };
    if (!stamp.eql(expected)) return error.ReloadAckMismatch;
    const status: Status = switch (bytes[40]) {
        1 => .prepared,
        2 => .quiesced,
        3 => .activated,
        4 => .resumed,
        5 => .refused,
        else => return error.InvalidReloadAck,
    };
    if (status != expected_status) return error.ReloadAckPhaseMismatch;
    return .{ .stamp = stamp, .status = status };
}
fn validGeneration(generation: u64) !void {
    if (generation < 1 or generation > snapshot.max_generations) return error.InvalidReloadGeneration;
}
fn validHeader(h: Header) !void {
    try validGeneration(h.stamp.generation);
    if (h.length > config.max_bytes or (h.command == .prepare and h.length == 0) or
        (h.command != .prepare and h.length != 0)) return error.InvalidReloadLength;
}

const test_stamp: Stamp = .{ .generation = 2, .digest = @splat(0x42) };
test "appfilter reload frame bounds precede allocation and any policy parsing" {
    const h: Header = .{ .command = .prepare, .stamp = test_stamp, .length = 4096 };
    const raw = try encodeHeader(h);
    const decoded = try decodeHeader(&raw);
    try std.testing.expect(decoded.stamp.eql(h.stamp));
    try std.testing.expectEqual(h.length, decoded.length);
    try std.testing.expectError(error.InvalidReloadHeader, decodeHeader(raw[0..51]));
    var bad = raw;
    std.mem.writeInt(u32, bad[16..20], config.max_bytes + 1, .little);
    try std.testing.expectError(error.InvalidReloadLength, decodeHeader(&bad));
    bad = raw;
    bad[4] = @backingInt(Command.activate);
    try std.testing.expectError(error.InvalidReloadLength, decodeHeader(&bad));
    bad = raw;
    bad[5] = 1;
    try std.testing.expectError(error.InvalidReloadHeader, decodeHeader(&bad));
    bad = raw;
    std.mem.writeInt(u64, bad[8..16], std.math.maxInt(u64), .little);
    try std.testing.expectError(error.InvalidReloadGeneration, decodeHeader(&bad));
    try std.testing.expectError(error.InvalidReloadLength, encodeHeader(.{ .command = .prepare, .stamp = test_stamp, .length = 0 }));
}

test "appfilter reload acknowledgements bind fixed size status generation and digest" {
    for (std.meta.tags(Status)) |status| {
        var raw = try encodeAck(.{ .stamp = test_stamp, .status = status });
        const decoded = try decodeAck(&raw, test_stamp, status);
        try std.testing.expectEqual(status, decoded.status);
        for (std.meta.tags(Status)) |other| {
            if (other != status) try std.testing.expectError(error.ReloadAckPhaseMismatch, decodeAck(&raw, test_stamp, other));
        }
        try std.testing.expectError(error.InvalidReloadAck, decodeAck(raw[0..40], test_stamp, status));
        raw[8] ^= 1;
        try std.testing.expectError(error.ReloadAckMismatch, decodeAck(&raw, test_stamp, status));
        raw[8] ^= 1;
        raw[0] = 3;
        try std.testing.expectError(error.ReloadAckMismatch, decodeAck(&raw, test_stamp, status));
        raw[0] = 2;
        raw[40] = 255;
        try std.testing.expectError(error.InvalidReloadAck, decodeAck(&raw, test_stamp, status));
    }
    var extra: [ack_bytes + 1]u8 = @splat(0);
    const valid = try encodeAck(.{ .stamp = test_stamp, .status = .prepared });
    @memcpy(extra[0..ack_bytes], &valid);
    try std.testing.expectError(error.InvalidReloadAck, decodeAck(&extra, test_stamp, .prepared));
}
