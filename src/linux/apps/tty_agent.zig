//! Unprivileged, temporary polkit text agent for an owner's interactive `app off`.
//! The daemon still authorizes its kernel-authenticated pidfd subject; no password enters the CLI protocol.
const std = @import("std");
const sys = @import("../sys.zig");
const l = sys.l;
const executable = "/usr/bin/pkttyagent";

pub const Agent = struct {
    child: std.process.Child,
    pidfd: l.fd_t,
    terminal: std.posix.termios,

    pub fn stop(a: *Agent, io: std.Io) void {
        // Give the text agent a chance to restore its terminal before the bounded hard-stop fallback.
        _ = l.pidfd_send_signal(a.pidfd, .TERM, null, 0);
        var fds = [_]l.pollfd{.{ .fd = a.pidfd, .events = l.POLL.IN, .revents = 0 }};
        _ = sys.poll(&fds, 1000) catch 0;
        a.child.kill(io); // reaps the unreused child even if it already exited
        sys.close(a.pidfd);
        std.posix.tcsetattr(0, .NOW, a.terminal) catch {};
    }
};

pub fn start(io: std.Io) !?Agent {
    if (!try std.Io.File.stdin().isTty(io)) return null;
    const terminal = try std.posix.tcgetattr(0);
    const pid = l.getpid();
    const stat_fd = try sys.fd(l.open("/proc/self/stat", .{ .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer sys.close(stat_fd);
    var stat: [4096]u8 = undefined;
    const n = try sys.read(stat_fd, &stat);
    if (n == stat.len) return error.InvalidProcessStat;
    const born = try startTime(stat[0..n], pid);
    const ready = try sys.pipe();
    defer sys.close(ready[0]);
    var write_open = true;
    defer if (write_open) sys.close(ready[1]);
    var subject: [64]u8 = undefined;
    var notify: [16]u8 = undefined;
    const argv = try arguments(&subject, &notify, pid, born, ready[1]);
    var child = try std.process.spawn(io, .{
        .argv = &argv,
        .inherit_files = &.{.{ .handle = ready[1], .flags = .{ .nonblocking = false } }},
    });
    sys.close(ready[1]);
    write_open = false;
    const pidfd = sys.fd(l.pidfd_open(child.id.?, 0)) catch |err| {
        child.kill(io);
        std.posix.tcsetattr(0, .NOW, terminal) catch {};
        return err;
    };
    var agent: Agent = .{ .child = child, .pidfd = pidfd, .terminal = terminal };
    errdefer agent.stop(io);
    // pkttyagent closes --notify-fd after registration. EOF alone also happens on failed exec/exit,
    // so require a live child as well. A later agent failure still cannot authorize the daemon's off.
    var fds = [_]l.pollfd{
        .{ .fd = ready[0], .events = l.POLL.IN | l.POLL.HUP, .revents = 0 },
        .{ .fd = pidfd, .events = l.POLL.IN, .revents = 0 },
    };
    if (try sys.poll(&fds, 5000) == 0) return error.PolkitAgentTimeout;
    if (fds[1].revents != 0) return error.PolkitAgentExited;
    var byte: [1]u8 = undefined;
    if (try sys.read(ready[0], &byte) != 0) return error.InvalidAgentNotification;
    fds[1].revents = 0;
    if (try sys.poll(fds[1..], 0) != 0) return error.PolkitAgentExited;
    return agent;
}

fn arguments(subject: *[64]u8, notify: *[16]u8, pid: l.pid_t, born: u64, fd: l.fd_t) ![6][]const u8 {
    if (pid <= 0 or born == 0 or fd < 3) return error.InvalidAgentSubject;
    return .{
        executable,    "--process",                                try std.fmt.bufPrint(subject, "{d},{d}", .{ pid, born }),
        "--notify-fd", try std.fmt.bufPrint(notify, "{d}", .{fd}), "--fallback",
    };
}
fn startTime(stat: []const u8, pid: l.pid_t) !u64 {
    const first_space = std.mem.findScalar(u8, stat, ' ') orelse return error.InvalidProcessStat;
    if ((std.fmt.parseInt(l.pid_t, stat[0..first_space], 10) catch 0) != pid) return error.InvalidProcessStat;
    if (first_space + 1 >= stat.len or stat[first_space + 1] != '(') return error.InvalidProcessStat;
    const end_name = std.mem.findScalarLast(u8, stat, ')') orelse return error.InvalidProcessStat;
    if (end_name + 1 >= stat.len or stat[end_name + 1] != ' ') return error.InvalidProcessStat;
    // The comm field can itself contain spaces and ')'. Numeric fields start after its final ')'.
    var fields = std.mem.tokenizeAny(u8, stat[end_name + 1 ..], " \n");
    for (0..19) |_| _ = fields.next() orelse return error.InvalidProcessStat;
    const born = std.fmt.parseInt(u64, fields.next() orelse return error.InvalidProcessStat, 10) catch return error.InvalidProcessStat;
    if (born == 0) return error.InvalidProcessStat;
    return born;
}

test "appfilter text agent uses a PID and start time and a fallback notification FD" {
    var subject: [64]u8 = undefined;
    var notify: [16]u8 = undefined;
    const argv = try arguments(&subject, &notify, 123, 456, 9);
    try std.testing.expectEqualStrings(executable, argv[0]);
    try std.testing.expectEqualStrings("--process", argv[1]);
    try std.testing.expectEqualStrings("123,456", argv[2]);
    try std.testing.expectEqualStrings("--notify-fd", argv[3]);
    try std.testing.expectEqualStrings("9", argv[4]);
    try std.testing.expectEqualStrings("--fallback", argv[5]);
    try std.testing.expectError(error.InvalidAgentSubject, arguments(&subject, &notify, 0, 456, 9));
    try std.testing.expectError(error.InvalidAgentSubject, arguments(&subject, &notify, 123, 456, 2));
}
test "appfilter agent process identity parses comm containing parentheses and refuses truncation" {
    const stat = "123 (name ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20\n";
    try std.testing.expectEqual(@as(u64, 987654), try startTime(stat, 123));
    try std.testing.expectError(error.InvalidProcessStat, startTime(stat, 124));
    try std.testing.expectError(error.InvalidProcessStat, startTime("123 (name) S 1 2", 123));
}
