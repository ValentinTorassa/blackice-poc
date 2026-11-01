//! Receipts: one JSON line per decision or scope event.
//!
//! A scope has a single writer, the blackice process. Backends (for example the Linux helper) report their
//! events to it instead of writing the file, so lines never interleave.
//!
//! Every string field is cleaned before it is written: invalid UTF-8, control characters and bidirectional
//! controls become '?', and each field is cut to a fixed size (ending in "..."). A line therefore always fits,
//! and a scoped command cannot get its own receipt dropped by sending a long or malformed name. Lines that still
//! cannot be written are counted and reported as "dropped" in scope_end.
//!
//! Example line:
//!     {"ts":"2026-10-30T04:12:33.123Z","scope":"s-1a2b3c4d","policy":"cae35a3beb20","gen":1,"point":"proxy",
//!      "event":"connect","verdict":"deny","reason":"no_matching_rule","host":"attacker.test","port":443}

const std = @import("std");
const Io = std.Io;

/// Where the decision was enforced. app_filter identifies application scopes on either platform.
pub const Point = enum { proxy, kernel, relay, control, app_filter };
pub const Verdict = enum { allow, deny };
/// Capture these together at the decision boundary; never combine an old policy
/// with a mutable log's later generation when asynchronously emitting a record.
pub const Decision = struct { policy: []const u8, generation: u32 };

pub const Entry = struct {
    /// connect | http | scope_start | scope_end | grant | revoke | relay_call | kernel_drop | warning
    event: []const u8,
    point: Point,
    decision: ?Decision = null,
    old_policy: ?[]const u8 = null,
    new_policy: ?[]const u8 = null,
    verdict: ?Verdict = null,
    app_id: ?u32 = null,
    executable: ?[]const u8 = null,
    /// A stable reason code (policy.Reason, or a code listed by the component that writes it) or a short
    /// error name.
    reason: ?[]const u8 = null,
    /// The policy entry that decided, as written in the file.
    rule: ?[]const u8 = null,
    host: ?[]const u8 = null,
    ip: ?[]const u8 = null,
    port: ?u16 = null,
    /// The command's exit status, on scope_end.
    status: ?u8 = null,
    detail: ?[]const u8 = null,
};

/// Bytes kept per field after cleaning.
pub const limits = struct {
    pub const event = 64; // Includes policy_change_completed_after_restart without truncation.
    pub const reason = 64;
    pub const rule = 256;
    pub const host = 256;
    pub const ip = 64;
    pub const detail = 512;
    pub const executable = 512;
    pub const policy = 64;
};

const line_max = 6144;

comptime {
    // JSON escaping at most doubles a cleaned field ('"' and '\' become two bytes); the rest of a line
    // (timestamp, ids, numbers, keys) stays under 512 bytes.
    const fields = limits.event + limits.reason + limits.rule + limits.host + limits.ip + limits.detail + limits.executable + 3 * limits.policy;
    std.debug.assert(2 * fields + 512 <= line_max);
}

const Line = struct {
    ts: []const u8,
    scope: []const u8,
    policy: []const u8,
    gen: u32,
    old_policy: ?[]const u8,
    new_policy: ?[]const u8,
    point: Point,
    event: []const u8,
    verdict: ?Verdict,
    app_id: ?u32,
    executable: ?[]const u8,
    reason: ?[]const u8,
    rule: ?[]const u8,
    host: ?[]const u8,
    ip: ?[]const u8,
    port: ?u16,
    status: ?u8,
    detail: ?[]const u8,
    dropped: ?u64,
};

/// Owner read and write only, where the OS has POSIX modes.
pub const private_file: Io.File.Permissions = if (@hasDecl(Io.File.Permissions, "fromMode"))
    .fromMode(0o600)
else
    .default_file;

pub const Log = struct {
    io: Io,
    file: Io.File,
    offset: u64,
    mutex: Io.Mutex = .init,
    scope: []const u8,
    policy_id: []const u8,
    generation: u32 = 1,
    app_id: ?u32 = null,
    executable: ?[]const u8 = null,
    written: u64 = 0,
    /// Lines that could not be written. Reported in scope_end, so a gap in the log is visible.
    failures: u64 = 0,
    /// Optional per-file ceiling for long-running services; task scopes retain their existing behavior.
    max_bytes: ?u64 = null,
    /// A service may publish failures to a shared counter when a separate process owns this log.
    shared_failures: ?*std.atomic.Value(u64) = null,

    /// Creates the receipts file (owner-only). It refuses an existing file.
    pub fn open(io: Io, dir: Io.Dir, sub_path: []const u8, scope: []const u8, policy_id: []const u8) !Log {
        const file = try dir.createFile(io, sub_path, .{ .truncate = false, .exclusive = true, .permissions = private_file });
        errdefer file.close(io);
        return .{ .io = io, .file = file, .offset = try file.length(io), .scope = scope, .policy_id = policy_id };
    }

    pub fn close(log: *Log) void {
        log.file.close(log.io);
    }

    pub fn write(log: *Log, e: Entry) void {
        log.writeLine(e, null);
    }
    pub fn droppedCount(log: *Log) u64 {
        log.mutex.lockUncancelable(log.io);
        defer log.mutex.unlock(log.io);
        return log.failures;
    }

    /// Writes scope_end with the command's exit status and the number of lines that could not be written.
    pub fn end(log: *Log, status: ?u8, detail: ?[]const u8) void {
        log.mutex.lockUncancelable(log.io);
        const dropped = log.failures;
        log.mutex.unlock(log.io);
        log.writeLine(.{ .event = "scope_end", .point = .control, .status = status, .detail = detail }, dropped);
    }

    fn writeLine(log: *Log, e: Entry, dropped: ?u64) void {
        var ts_buf: [32]u8 = undefined;
        var event_buf: [limits.event]u8 = undefined;
        var reason_buf: [limits.reason]u8 = undefined;
        var rule_buf: [limits.rule]u8 = undefined;
        var host_buf: [limits.host]u8 = undefined;
        var ip_buf: [limits.ip]u8 = undefined;
        var detail_buf: [limits.detail]u8 = undefined;
        var executable_buf: [limits.executable]u8 = undefined;
        var policy_buf: [limits.policy]u8 = undefined;
        var old_policy_buf: [limits.policy]u8 = undefined;
        var new_policy_buf: [limits.policy]u8 = undefined;
        const decision = e.decision orelse Decision{ .policy = log.policy_id, .generation = log.generation };
        const line: Line = .{
            .ts = formatTimestamp(&ts_buf, Io.Clock.real.now(log.io)),
            .scope = log.scope,
            .policy = clean(&policy_buf, decision.policy),
            .gen = decision.generation,
            .old_policy = cleanOptional(&old_policy_buf, e.old_policy),
            .new_policy = cleanOptional(&new_policy_buf, e.new_policy),
            .point = e.point,
            .event = clean(&event_buf, e.event),
            .verdict = e.verdict,
            .app_id = e.app_id orelse log.app_id,
            .executable = cleanOptional(&executable_buf, e.executable orelse log.executable),
            .reason = cleanOptional(&reason_buf, e.reason),
            .rule = cleanOptional(&rule_buf, e.rule),
            .host = cleanOptional(&host_buf, e.host),
            .ip = cleanOptional(&ip_buf, e.ip),
            .port = e.port,
            .status = e.status,
            .detail = cleanOptional(&detail_buf, e.detail),
            .dropped = dropped,
        };
        var buf: [line_max]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        w.print("{f}\n", .{std.json.fmt(line, .{ .emit_null_optional_fields = false })}) catch {
            log.countFailure();
            return;
        };
        const bytes = w.buffered();
        log.mutex.lockUncancelable(log.io);
        defer log.mutex.unlock(log.io);
        if (log.max_bytes) |limit| if (log.offset > limit or bytes.len > limit - log.offset) {
            log.failed();
            return;
        };
        // A cancel that lands during the write (for example a proxy stop) must neither lose the line nor
        // consume the task's cancel request, so the write runs with cancelation blocked.
        const old = log.io.swapCancelProtection(.blocked);
        defer _ = log.io.swapCancelProtection(old);
        log.file.writePositionalAll(log.io, bytes, log.offset) catch {
            log.failed();
            return;
        };
        log.offset += bytes.len;
        log.written += 1;
    }

    fn countFailure(log: *Log) void {
        log.mutex.lockUncancelable(log.io);
        defer log.mutex.unlock(log.io);
        log.failed();
    }
    fn failed(log: *Log) void {
        log.failures +|= 1;
        if (log.shared_failures) |counter| counter.store(log.failures, .release);
    }
};

fn printable(cp: u21) bool {
    return switch (cp) {
        0x00...0x1f, 0x7f...0x9f => false, // C0 controls, DEL, C1 controls
        0x200b...0x200f, 0x2028...0x202e, 0x2060...0x2069, 0xfeff => false, // zero-width, separators, bidi controls
        else => true,
    };
}

/// Copies `s` into `out` as printable UTF-8. Invalid bytes, control characters, line separators and
/// bidirectional controls become '?'. Text that does not fit is cut at a character boundary and ends in "...".
/// The result is never longer than `s` or `out`.
pub fn clean(out: []u8, s: []const u8) []const u8 {
    std.debug.assert(out.len >= 4);
    // Cleaning never makes text longer, so input that fits needs no room for the "...".
    const cap = if (s.len <= out.len) out.len else out.len - 3;
    var o: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        var n: usize = 1;
        var keep = false;
        if (std.unicode.utf8ByteSequenceLength(s[i])) |len| {
            if (i + len <= s.len) {
                if (std.unicode.utf8Decode(s[i .. i + len])) |cp| {
                    n = len;
                    keep = printable(cp);
                } else |_| {}
            }
        } else |_| {}
        const w: usize = if (keep) n else 1;
        if (o + w > cap) {
            @memcpy(out[o..][0..3], "...");
            return out[0 .. o + 3];
        }
        if (keep) @memcpy(out[o..][0..n], s[i..][0..n]) else out[o] = '?';
        o += w;
        i += n;
    }
    return out[0..o];
}

fn cleanOptional(out: []u8, s: ?[]const u8) ?[]const u8 {
    return if (s) |v| clean(out, v) else null;
}

/// RFC 3339 in UTC with milliseconds, e.g. 2026-10-30T04:12:33.123Z.
pub fn formatTimestamp(buf: *[32]u8, t: Io.Timestamp) []const u8 {
    const ms = t.toMilliseconds();
    const secs: u64 = @intCast(@divFloor(ms, 1000));
    const milli: u64 = @intCast(@mod(ms, 1000));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        yd.year,
        md.month.numeric(),
        md.day_index + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
        milli,
    }) catch unreachable;
}

test formatTimestamp {
    var buf: [32]u8 = undefined;
    const t: Io.Timestamp = .{ .nanoseconds = 1761800000123 * std.time.ns_per_ms };
    try std.testing.expectEqualStrings("2025-10-30T04:53:20.123Z", formatTimestamp(&buf, t));
}

test clean {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("plain.example", clean(&buf, "plain.example"));
    try std.testing.expectEqualStrings("a?b?c", clean(&buf, "a\x1bb\xffc"));
    try std.testing.expectEqualStrings("ñandú", clean(&buf, "ñandú"));
    try std.testing.expectEqualStrings("x?y", clean(&buf, "x\u{202e}y"));
    try std.testing.expectEqualStrings("0123456789abcdef", clean(&buf, "0123456789abcdef"));
    try std.testing.expectEqualStrings("0123456789abc...", clean(&buf, "0123456789abcdefg"));
    // A cut never splits a character.
    try std.testing.expectEqualStrings("0123456789ab...", clean(&buf, "0123456789abñññ"));
    // Overlong encodings and surrogates are invalid.
    try std.testing.expectEqualStrings("??", clean(&buf, "\xc0\xaf"));
    try std.testing.expectEqualStrings("???", clean(&buf, "\xed\xa0\x80"));
}

test "receipt lines are JSON with nulls omitted" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try Log.open(io, tmp.dir, "r.jsonl", "s-00000000", "abc123abc123");
    log.write(.{ .event = "connect", .point = .proxy, .verdict = .deny, .reason = "no_matching_rule", .host = "a\"b.test", .port = 443 });
    log.end(0, null);
    log.close();
    const bytes = try tmp.dir.readFileAlloc(io, "r.jsonl", std.testing.allocator, .limited(1 << 16));
    defer std.testing.allocator.free(bytes);
    var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, bytes, "\n"), '\n');
    const first = it.next().?;
    try std.testing.expect(std.mem.find(u8, first, "\"verdict\":\"deny\"") != null);
    try std.testing.expect(std.mem.find(u8, first, "\"host\":\"a\\\"b.test\"") != null);
    try std.testing.expect(std.mem.find(u8, first, "dropped") == null);
    try std.testing.expect(std.mem.find(u8, first, "old_policy") == null);
    try std.testing.expect(std.mem.find(u8, first, "new_policy") == null);
    const second = it.next().?;
    try std.testing.expect(std.mem.find(u8, second, "verdict") == null);
    try std.testing.expect(std.mem.find(u8, second, "\"status\":0") != null);
    try std.testing.expect(std.mem.find(u8, second, "\"dropped\":0") != null);
    try std.testing.expect(it.next() == null);
    // The receipts file is new and owner-only.
    try std.testing.expectError(error.PathAlreadyExists, Log.open(io, tmp.dir, "r.jsonl", "s-00000000", "abc123abc123"));
    if (@hasDecl(Io.File.Permissions, "fromMode")) {
        const st = try tmp.dir.statFile(io, "r.jsonl", .{});
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);
    }
}

test "appfilter receipt captures policy and generation together despite a later log default" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try Log.open(io, tmp.dir, "r.jsonl", "app-1", "new-policy");
    log.generation = 2;
    log.write(.{ .event = "kernel_drop", .point = .app_filter, .decision = .{ .policy = "old-policy", .generation = 1 } });
    log.write(.{ .event = "policy_activated", .point = .app_filter, .decision = .{ .policy = "new-policy", .generation = 2 }, .old_policy = "old-policy", .new_policy = "new-policy" });
    log.close();
    const data = try tmp.dir.readFileAlloc(io, "r.jsonl", std.testing.allocator, .limited(16384));
    defer std.testing.allocator.free(data);
    var lines = std.mem.tokenizeScalar(u8, data, '\n');
    const old = lines.next().?;
    try std.testing.expect(std.mem.find(u8, old, "\"policy\":\"old-policy\",\"gen\":1") != null);
    const activation = lines.next().?;
    try std.testing.expect(std.mem.find(u8, activation, "\"policy\":\"new-policy\",\"gen\":2") != null);
    try std.testing.expect(std.mem.find(u8, activation, "\"old_policy\":\"old-policy\"") != null);
    try std.testing.expect(std.mem.find(u8, activation, "\"new_policy\":\"new-policy\"") != null);
    try std.testing.expect(lines.next() == null);
    try std.testing.expectEqual(@as(u64, 0), log.failures);
}

test "long and malformed fields cannot drop a receipt" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var log = try Log.open(io, tmp.dir, "r.jsonl", "s-00000000", "abc123abc123");
    const quotes: [8192]u8 = @splat('"');
    const junk: [8192]u8 = @splat(0xff);
    log.write(.{ .event = &quotes, .point = .proxy, .verdict = .deny, .decision = .{ .policy = &quotes, .generation = 2 }, .old_policy = &junk, .new_policy = &quotes, .reason = &junk, .rule = &quotes, .host = &quotes, .ip = &junk, .detail = &quotes });
    log.end(null, null);
    log.close();
    try std.testing.expectEqual(@as(u64, 0), log.failures);
    try std.testing.expectEqual(@as(u64, 2), log.written);
    const bytes = try tmp.dir.readFileAlloc(io, "r.jsonl", std.testing.allocator, .limited(1 << 16));
    defer std.testing.allocator.free(bytes);
    var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, bytes, "\n"), '\n');
    const first = it.next().?;
    try std.testing.expect(first.len < line_max);
    try std.testing.expect(std.unicode.utf8ValidateSlice(first));
    try std.testing.expect(std.mem.find(u8, first, "\"verdict\":\"deny\"") != null);
}
