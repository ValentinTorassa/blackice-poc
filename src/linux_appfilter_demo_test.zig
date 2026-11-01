//! File parsing and policy decisions only. Never connects to the service or creates sockets.
const std = @import("std");
const config = @import("linux/apps/config.zig");

fn readConfig(path: []const u8) !config.Config {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(config.max_bytes));
    defer std.testing.allocator.free(bytes);
    return config.Config.parse(std.testing.allocator, bytes);
}

test "appfilter demo has distinct executable policies and excludes telemetry" {
    var demo = try readConfig("examples/linux-apps-demo.json");
    defer demo.deinit();
    try std.testing.expectEqual(@as(usize, 3), demo.apps.len);
    try std.testing.expectEqualStrings("/usr/lib/firefox-esr/firefox-esr", demo.apps[0].executable);
    try std.testing.expectEqualStrings("/usr/bin/wget", demo.apps[1].executable);
    try std.testing.expectEqualStrings("/usr/bin/curl", demo.apps[2].executable);
    for (demo.apps) |*app| {
        try std.testing.expect(!app.network.checkHost("incoming.telemetry.mozilla.org").allowed);
        try std.testing.expect(!app.network.checkHost("github.com").allowed);
        try std.testing.expect(!app.network.checkPort(47121).allowed);
    }
    try std.testing.expect(demo.apps[0].network.checkHost("example.com").allowed);
    try std.testing.expect(demo.apps[0].network.checkHost("example.org").allowed);
    try std.testing.expect(!demo.apps[1].network.checkHost("example.com").allowed);
    try std.testing.expect(demo.apps[1].network.checkHost("example.org").allowed);
    try std.testing.expect(demo.apps[2].network.checkHost("example.com").allowed);
    try std.testing.expect(!demo.apps[2].network.checkHost("example.org").allowed);
}

test "appfilter demo evidence uses a listed launcher without listing Python globally" {
    var evidence = try readConfig("examples/linux-apps-evidence.json");
    defer evidence.deinit();
    try std.testing.expectEqual(@as(usize, 3), evidence.apps.len);
    try std.testing.expectEqualStrings("/usr/bin/setsid", evidence.apps[0].executable);
    for (evidence.apps) |app| try std.testing.expect(!std.mem.containsAtLeast(u8, app.executable, 1, "python"));
    try std.testing.expect(evidence.apps[0].network.checkHost("example.com").allowed);
    try std.testing.expect(!evidence.apps[0].network.checkHost("example.org").allowed);
}
