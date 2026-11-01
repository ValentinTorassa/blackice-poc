//! Immutable per-connection views. Publishers retain every view until shutdown.
const std = @import("std");
const policy = @import("../core/policy.zig");
const receipt = @import("../core/receipt.zig");
pub const Binding = struct {
    policy: *const policy.Policy,
    decision: receipt.Decision,
    executable: []const u8,
    serve: bool = true,
};
pub const Source = struct {
    context: *const anyopaque,
    slot: usize,
    read: *const fn (*const anyopaque, usize) ?Binding,
    paused: *const std.atomic.Value(bool),

    pub fn capture(s: Source) ?Binding {
        if (s.paused.load(.acquire)) return null;
        const b = s.read(s.context, s.slot) orelse return null;
        return if (b.serve) b else null;
    }
    pub fn current(s: Source) ?Binding {
        return s.read(s.context, s.slot);
    }
};

pub fn permits(b: Binding, host: []const u8, port: u16, ip: ?std.Io.net.IpAddress) bool {
    return b.serve and verdict(b, host, port, ip).allowed;
}

/// The policy's verdict for a connection to `host`:`port` that uses address `ip`, with the proxy's checks in its
/// order: the port, then the IP literal or the name, then the selected address. `serve` is not checked here.
pub fn verdict(b: Binding, host: []const u8, port: u16, ip: ?std.Io.net.IpAddress) policy.Verdict {
    const pv = b.policy.checkPort(port);
    if (!pv.allowed) return pv;
    if (policy.parseIpLiteral(host)) |literal| return b.policy.checkLiteral(literal);
    const hv = b.policy.checkHost(host);
    if (!hv.allowed) return hv;
    if (ip) |resolved| {
        const rv = b.policy.checkResolved(resolved);
        if (!rv.allowed) return rv;
    }
    return hv;
}

test "appfilter live view narrowing checks host port and the already selected address" {
    var p = try policy.Policy.parse(std.testing.allocator, "{\"version\":\"blackice.policy/v0\",\"network\":{\"mode\":\"allowlist\",\"allow\":[\"example.com\"]}}", null);
    defer p.deinit();
    const b: Binding = .{ .policy = &p, .decision = .{ .policy = &p.digest_hex, .generation = 2 }, .executable = "/usr/bin/curl" };
    try std.testing.expect(permits(b, "example.com", 443, null));
    try std.testing.expect(!permits(b, "other.example", 443, null));
    try std.testing.expect(!permits(b, "example.com", 22, null));
    try std.testing.expect(!permits(b, "example.com", 443, .{ .ip4 = .loopback(443) }));
}

test "appfilter open connection recheck preserves widening and refuses mode port or subnet narrowing" {
    const cases = .{
        .{ "{\"mode\":\"allowlist\",\"allow\":[\"example.com\",\"other.example\"]}", true },
        .{ "{\"mode\":\"allow-all\"}", true },
        .{ "{\"mode\":\"deny-all\"}", false },
        .{ "{\"mode\":\"allowlist\",\"allow\":[\"other.example\"]}", false },
        .{ "{\"mode\":\"allowlist\",\"allow\":[\"example.com\"],\"ports\":[80]}", false },
        .{ "{\"mode\":\"allowlist\",\"allow\":[\"example.com\"],\"subnets\":{\"deny\":[\"93.184.216.0/24\"]}}", false },
    };
    const connected_ip = policy.parseIpLiteral("93.184.216.34").?;
    inline for (cases) |case| {
        var p = try policy.Policy.parse(std.testing.allocator, "{\"version\":\"blackice.policy/v0\",\"network\":" ++ case[0] ++ "}", null);
        defer p.deinit();
        const b: Binding = .{ .policy = &p, .decision = .{ .policy = &p.digest_hex, .generation = 3 }, .executable = "/usr/bin/curl" };
        try std.testing.expectEqual(case[1], permits(b, "example.com", 443, connected_ip));
        var retired_after_restart = b;
        retired_after_restart.serve = false;
        try std.testing.expect(!permits(retired_after_restart, "example.com", 443, connected_ip));
    }
}
