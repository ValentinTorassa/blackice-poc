const std = @import("std");
const proxy = @import("../../proxy/proxy.zig");
test "appfilter all listeners share a connection budget and expired headers cannot complete" {
    var budget: proxy.ConnectionBudget = .{ .limit = 2 };
    try std.testing.expect(budget.acquire());
    try std.testing.expect(budget.acquire());
    try std.testing.expect(!budget.acquire());
    budget.release();
    try std.testing.expect(budget.acquire());
    budget.release();
    budget.release();
    try std.testing.expectEqual(@as(u32, 0), budget.active.load(.monotonic));
    var expired: proxy.HeaderState = .{};
    try std.testing.expect(expired.expire());
    try std.testing.expect(!expired.complete());
    var completed: proxy.HeaderState = .{};
    try std.testing.expect(completed.complete());
    try std.testing.expect(!completed.expire());
}
test "appfilter file cap counts dropped receipts without extending the file" {
    const receipt = @import("../../core/receipt.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var log = try receipt.Log.open(io, tmp.dir, "bounded.jsonl", "app-1", "hash");
    defer log.close();
    var count: std.atomic.Value(u64) = .init(0);
    log.shared_failures = &count;
    log.write(.{ .event = "first", .point = .app_filter });
    const limit = log.offset;
    log.max_bytes = limit;
    log.write(.{ .event = "second", .point = .app_filter });
    try std.testing.expectEqual(limit, try log.file.length(io));
    try std.testing.expectEqual(@as(u64, 1), log.droppedCount());
    try std.testing.expectEqual(@as(u64, 1), count.load(.acquire));
}
test "appfilter transparent HTTP accepts names and origin form only" {
    const parsed = try proxy.parseOriginTarget("/path?q=1", "example.com");
    try std.testing.expectEqualStrings("example.com", parsed.host);
    try std.testing.expectEqual(@as(u16, 80), parsed.port);
    for ([_][]const u8{ "http://example.com/", "//evil.test/", "/bad\r\nHost: other", "/bad#frag" }) |target|
        try std.testing.expectError(error.InvalidUrl, proxy.parseOriginTarget(target, "example.com"));
    for ([_][]const u8{ "example.com:443", "127.0.0.1", "a@b", "", "[::1]" }) |host|
        try std.testing.expectError(error.InvalidUrl, proxy.parseOriginTarget("/", host));
}

fn hello(comptime copies: usize) [52 + 20 * copies]u8 {
    var b: [52 + 20 * copies]u8 = @splat(0);
    b[0] = 22;
    b[1] = 3;
    b[2] = 1;
    std.mem.writeInt(u16, b[3..5], b.len - 5, .big);
    b[5] = 1;
    std.mem.writeInt(u24, b[6..9], b.len - 9, .big);
    b[9] = 3;
    b[10] = 3;
    std.mem.writeInt(u16, b[44..46], 2, .big);
    b[46] = 0x13;
    b[47] = 1;
    b[48] = 1;
    std.mem.writeInt(u16, b[50..52], 20 * copies, .big);
    for (0..copies) |i| {
        const at = 52 + i * 20;
        std.mem.writeInt(u16, b[at + 2 ..][0..2], 16, .big);
        std.mem.writeInt(u16, b[at + 4 ..][0..2], 14, .big);
        std.mem.writeInt(u16, b[at + 7 ..][0..2], 11, .big);
        @memcpy(b[at + 9 ..][0..11], "example.com");
    }
    return b;
}
test "appfilter TLS accepts one SNI and rejects duplicate names and fragmented records" {
    const one = hello(1);
    try std.testing.expectEqualStrings("example.com", (try proxy.parseSni(&one)).?);
    const duplicate = hello(2);
    try std.testing.expectError(error.Malformed, proxy.parseSni(&duplicate));
    for (0..one.len) |n| try std.testing.expectError(error.Malformed, proxy.parseSni(one[0..n]));
    const absent = hello(0);
    try std.testing.expectEqual(@as(?[]const u8, null), try proxy.parseSni(&absent));
}
test "appfilter transparent HTTP duplicate Host is refused before forwarding" {
    var reader: std.Io.Reader = .fixed("GET / HTTP/1.1\r\nHost: example.com\r\nHost: github.com\r\n\r\n");
    var out: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    var server = std.http.Server.init(&reader, &writer);
    var req = try server.receiveHead();
    try std.testing.expectError(error.InvalidUrl, proxy.originUrl(&req));
}
test "appfilter receipts carry app identity without allowing malformed fields to drop lines" {
    const receipt = @import("../../core/receipt.zig");
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try receipt.Log.open(io, tmp.dir, "apps.jsonl", "app-1", "policy123");
    log.app_id = 1;
    log.executable = "/usr/bin/test-app";
    log.write(.{ .event = "kernel_drop", .point = .app_filter, .verdict = .deny, .reason = "socket_protocol" });
    log.write(.{ .event = "http", .point = .app_filter, .host = "example.com\nforged", .detail = "quoted\"value" });
    log.close();
    const bytes = try tmp.dir.readFileAlloc(io, "apps.jsonl", std.testing.allocator, .limited(16384));
    defer std.testing.allocator.free(bytes);
    var lines = std.mem.tokenizeScalar(u8, bytes, '\n');
    var n: u32 = 0;
    while (lines.next()) |line| {
        const value = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line, .{});
        defer value.deinit();
        try std.testing.expectEqual(@as(i64, 1), value.value.object.get("app_id").?.integer);
        try std.testing.expectEqualStrings("/usr/bin/test-app", value.value.object.get("executable").?.string);
        try std.testing.expectEqualStrings("app_filter", value.value.object.get("point").?.string);
        n += 1;
    }
    try std.testing.expectEqual(@as(u32, 2), n);
    try std.testing.expectEqual(@as(u64, 0), log.failures);
}
