//! Bounded application policy data, parsed without using capabilities.
const std = @import("std");
const policy = @import("../../core/policy.zig");
const abi = @import("types.zig");

pub const max_bytes = 1024 * 1024;
pub const max_generations = 256;
pub const App = struct { executable: []const u8, network: policy.Policy };
const Raw = struct {
    version: []const u8,
    generation: ?std.json.Value = null,
    applications: []const struct { executable: []const u8, policy: std.json.Value },
};

pub const Config = struct {
    arena: std.heap.ArenaAllocator,
    apps: []App,
    digest: [64]u8,
    generation: u32,
    explicit_generation: bool,

    pub fn parse(gpa: std.mem.Allocator, bytes: []const u8) !Config {
        if (bytes.len > max_bytes) return error.PolicyTooLarge;
        try checkDepth(bytes);
        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const alloc = arena.allocator();
        const raw = std.json.parseFromSliceLeaky(Raw, alloc, bytes, .{
            .allocate = .alloc_always,
            .duplicate_field_behavior = .@"error",
            .ignore_unknown_fields = false,
        }) catch return error.InvalidAppPolicy;
        if (!std.mem.eql(u8, raw.version, "blackice.apps/v0")) return error.UnsupportedAppPolicy;
        const generation: u32 = if (raw.generation) |value| switch (value) {
            .integer => |n| if (n >= 1 and n <= max_generations) @intCast(n) else return error.InvalidGeneration,
            else => return error.InvalidGeneration,
        } else 1; // Existing initial-on files retain their generation-1 meaning.
        if (raw.applications.len == 0 or raw.applications.len > abi.max_apps) return error.InvalidAppCount;
        const apps = try alloc.alloc(App, raw.applications.len);
        var done: usize = 0;
        errdefer for (apps[0..done]) |*app| app.network.deinit();
        for (raw.applications, apps, 0..) |item, *app, i| {
            if (!validPath(item.executable)) return error.InvalidExecutablePath;
            for (apps[0..i]) |old| if (std.mem.eql(u8, old.executable, item.executable)) return error.DuplicateApp;
            const data = try std.json.Stringify.valueAlloc(alloc, item.policy, .{});
            app.* = .{ .executable = item.executable, .network = try policy.Policy.parse(gpa, data, null) };
            done += 1;
            // Redirection implements names on HTTP(S), not arbitrary destination protocols.
            for (app.network.ports) |port| if (port != 80 and port != 443) return error.UnsupportedAppPort;
            if (app.network.allow_subnets.len != 0) return error.AppLiteralAllowUnsupported;
        }
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        return .{ .arena = arena, .apps = apps, .digest = std.fmt.bytesToHex(digest, .lower), .generation = generation, .explicit_generation = raw.generation != null };
    }

    pub fn parseReload(gpa: std.mem.Allocator, bytes: []const u8) !Config {
        var c = try parse(gpa, bytes);
        errdefer c.deinit();
        if (!c.explicit_generation) return error.ReloadGenerationRequired;
        return c;
    }

    pub fn deinit(c: *Config) void {
        for (c.apps) |*app| app.network.deinit();
        c.arena.deinit();
    }
};

fn checkDepth(bytes: []const u8) !void {
    // The JSON parser can allocate deeper trees than Stringify can print. Bound the wire input first.
    var depth: usize = 0;
    var quoted = false;
    var escape = false;
    for (bytes) |ch| {
        if (quoted) {
            if (escape) {
                escape = false;
                continue;
            }
            if (ch == '\\') escape = true else if (ch == '"') quoted = false;
            continue;
        }
        switch (ch) {
            '"' => quoted = true,
            '{', '[' => {
                depth += 1;
                if (depth > 32) return error.PolicyTooDeep;
            },
            '}', ']' => {
                if (depth == 0) return error.InvalidAppPolicy;
                depth -= 1;
            },
            else => {},
        }
    }
    if (quoted or depth != 0) return error.InvalidAppPolicy;
}

test "appfilter rejects JSON nesting before Stringify without counting quoted brackets" {
    var deep: [67]u8 = @splat('[');
    deep[33] = '0';
    @memset(deep[34..], ']');
    try std.testing.expectError(error.PolicyTooDeep, Config.parse(std.testing.allocator, &deep));
    try checkDepth("{\"name\":\"[[[\\\"{{{\"}");
    try std.testing.expectError(error.InvalidAppPolicy, checkDepth("[\"unterminated"));
}

pub fn validPath(path: []const u8) bool {
    if (path.len < 2 or path.len > 512 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
        for (part) |ch| if (ch < 0x20 or ch == 0x7f) return false;
    }
    return true;
}

test "appfilter application policy reuses the strict core network policy" {
    const bytes =
        \\{"version":"blackice.apps/v0","applications":[{"executable":"/usr/bin/curl","policy":{"version":"blackice.policy/v0","network":{"mode":"allowlist","allow":["example.com"]}}}]}
    ;
    var c = try Config.parse(std.testing.allocator, bytes);
    defer c.deinit();
    try std.testing.expect(c.apps[0].network.checkHost("example.com").allowed);
    try std.testing.expect(!c.apps[0].network.checkHost("github.com").allowed);
    try std.testing.expect(!c.apps[0].network.checkPort(22).allowed);
}

test "appfilter ambiguous executable paths and unsupported fields refuse before a loader exists" {
    for ([_][]const u8{ "relative", "/tmp/../usr/bin/curl", "/usr//bin/curl", "/usr/bin/", "/usr/\x00bin" }) |path|
        try std.testing.expect(!validPath(path));
    try std.testing.expectError(error.InvalidAppPolicy, Config.parse(std.testing.allocator,
        \\{"version":"blackice.apps/v0","applications":[],"btf":"/tmp/attacker"}
    ));
    try std.testing.expectError(error.InvalidAppCount, Config.parse(std.testing.allocator,
        \\{"version":"blackice.apps/v0","applications":[]}
    ));
}

test "appfilter reload requires an explicit bounded integer generation without changing network policy" {
    const suffix = ",\"applications\":[{\"executable\":\"/usr/bin/curl\",\"policy\":{\"version\":\"blackice.policy/v0\",\"network\":{\"mode\":\"allowlist\",\"allow\":[\"example.com\"]}}}]}";
    const legacy = "{\"version\":\"blackice.apps/v0\"" ++ suffix;
    var first = try Config.parse(std.testing.allocator, legacy);
    defer first.deinit();
    try std.testing.expectEqual(@as(u32, 1), first.generation);
    try std.testing.expectError(error.ReloadGenerationRequired, Config.parseReload(std.testing.allocator, legacy));
    var next = try Config.parseReload(std.testing.allocator, "{\"version\":\"blackice.apps/v0\",\"generation\":2" ++ suffix);
    defer next.deinit();
    try std.testing.expectEqual(@as(u32, 2), next.generation);
    try std.testing.expectEqualStrings(first.apps[0].network.id(), next.apps[0].network.id());
    inline for (.{ "0", "257", "-1", "2.0", "true", "\"2\"" }) |invalid|
        try std.testing.expectError(error.InvalidGeneration, Config.parseReload(std.testing.allocator, "{\"version\":\"blackice.apps/v0\",\"generation\":" ++ invalid ++ suffix));
    try std.testing.expectError(error.ReloadGenerationRequired, Config.parseReload(std.testing.allocator, "{\"version\":\"blackice.apps/v0\",\"generation\":null" ++ suffix));
    try std.testing.expectError(error.InvalidAppPolicy, Config.parseReload(std.testing.allocator, "{\"version\":\"blackice.apps/v0\",\"generation\":2,\"generation\":3" ++ suffix));
}
