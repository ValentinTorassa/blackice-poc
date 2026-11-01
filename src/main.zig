const std = @import("std");
const Io = std.Io;

pub const policy = @import("core/policy.zig");
pub const receipt = @import("core/receipt.zig");
pub const scope = @import("core/scope.zig");
pub const backend = @import("core/backend.zig");
pub const seatbelt = @import("macos/seatbelt.zig");
pub const run_cmd = @import("cli/run.zig");
pub const grant_cmd = @import("cli/grant.zig");

pub const version = "0.1.0";

const usage =
    \\blackice: network permissions for apps and agent tasks
    \\
    \\usage:
    \\  blackice version
    \\  blackice --version
    \\  blackice policy check FILE
    \\  blackice run --policy FILE [--env NAME]... [--relay --model ID...] -- CMD [ARG]...
    \\  blackice grant SCOPE HOST [--for 10m]
    \\  blackice revoke SCOPE HOST
    \\  blackice app on --policy APPS.json | off | status (Linux)
    \\  blackice app reload --policy APPS.json (Linux; prepared only, unavailable)
    \\
;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    // Streaming, never positional: with `blackice run ... > log 2>&1` the command shares this file and its
    // offset, so a positional write would overwrite the command's output.
    var out_buf: [4096]u8 = undefined;
    var out_w: Io.File.Writer = .initStreaming(.stdout(), io, &out_buf);
    const out = &out_w.interface;
    defer out.flush() catch {};
    var err_buf: [4096]u8 = undefined;
    var err_w: Io.File.Writer = .initStreaming(.stderr(), io, &err_buf);
    const errw = &err_w.interface;
    defer errw.flush() catch {};

    if (args.len < 2) {
        try errw.writeAll(usage);
        return 2;
    }
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "app") and @import("builtin").os.tag == .linux) {
        return @import("linux/apps/client.zig").run(init.gpa, io, args[2..], out, errw);
    }
    if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version")) {
        try out.print("blackice {s}\n", .{version});
        return 0;
    }
    if (std.mem.eql(u8, cmd, "grant") or std.mem.eql(u8, cmd, "revoke")) {
        const op: grant_cmd.Op = if (cmd[0] == 'g') .grant else .revoke;
        return grant_cmd.run(init.gpa, io, init.environ_map, op, args[2..], out, errw);
    }
    if (std.mem.eql(u8, cmd, "run")) {
        errw.flush() catch {};
        return run_cmd.run(init.gpa, io, init.environ_map, args[0], args[2..], errw);
    }
    if (std.mem.eql(u8, cmd, "policy") and args.len == 4 and std.mem.eql(u8, args[2], "check")) {
        return policyCheck(init.gpa, io, args[3], out, errw);
    }
    try errw.writeAll(usage);
    return 2;
}

fn policyCheck(gpa: std.mem.Allocator, io: Io, path: []const u8, out: *Io.Writer, errw: *Io.Writer) !u8 {
    const bytes = Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| {
        try errw.print("blackice: cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return 1;
    };
    defer gpa.free(bytes);
    var diag: policy.Diagnostic = .{};
    var p = policy.Policy.parse(gpa, bytes, &diag) catch |err| {
        try errw.print("blackice: {s}: {s}: {s} ({s})\n", .{ path, @errorName(err), diag.message, diag.item() });
        return 1;
    };
    defer p.deinit();
    try out.print("ok: {s}, mode {s}, {d} allowed names, {d} allowed subnets, {d} denied subnets, ports", .{
        path, p.mode.label(), p.allow.len, p.allow_subnets.len, p.deny_subnets.len,
    });
    for (p.ports) |port| try out.print(" {d}", .{port});
    try out.print(", policy {s}\n", .{p.id()});
    const ignored = p.ignoredAllowCount();
    if (ignored > 0) {
        try errw.print("blackice: warning: mode {s} ignores the {d} allow entries; use allowlist to apply them\n", .{
            p.mode.label(), ignored,
        });
    }
    return 0;
}

test {
    _ = policy;
    _ = @import("core/sandbox_import.zig");
    _ = receipt;
    _ = scope;
    _ = backend;
    _ = seatbelt;
    _ = @import("macos/kernel_log.zig");
    _ = @import("proxy/proxy.zig");
    _ = @import("relay/relay.zig");
    _ = @import("control/control.zig");
    _ = run_cmd;
    _ = grant_cmd;
}
