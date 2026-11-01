const std = @import("std");
const sys = @import("linux/sys.zig");
pub const std_options: std.Options = .{ .enable_segfault_handler = false };
pub const panic = std.debug.FullPanic(fatalPanic);
fn fatalPanic(_: []const u8, _: ?usize) noreturn {
    sys.writeAll(2, "blackice app filter: internal failure; pinned policy retained\n") catch {};
    sys.l.exit_group(125);
}
pub fn main(init: std.process.Init) u8 {
    return @import("linux/apps/service.zig").main(init);
}
test "appfilter units register only pure fixtures" {
    _ = @import("linux/apps/types.zig");
    _ = @import("linux/apps/state.zig");
    _ = @import("linux/apps/config.zig");
    _ = @import("linux/apps/pinning.zig");
    _ = @import("linux/apps/programs.zig");
    _ = @import("linux/apps/kernel.zig");
    _ = @import("linux/apps/host.zig");
    _ = @import("linux/apps/intent.zig");
    _ = @import("linux/apps/worker.zig");
    _ = @import("linux/apps/refusals.zig");
    _ = @import("linux/apps/reload_snapshot.zig");
    _ = @import("linux/apps/reload_protocol.zig");
    _ = @import("linux/apps/reload_channel.zig");
    _ = @import("linux/apps/reload_faults.zig");
    _ = @import("linux/apps/reload_history.zig");
    _ = @import("linux/apps/reload_worker.zig");
    _ = @import("proxy/live_policy.zig");
    _ = @import("linux/apps/reload_transaction.zig");
    _ = @import("linux/apps/reload_control.zig");
    _ = @import("linux/apps/reload_receipts.zig");
    _ = @import("linux/apps/reload_kernel.zig");
    _ = @import("linux/apps/client.zig");
    _ = @import("linux/apps/vm_test.zig");
    _ = @import("linux/apps/proxy_test.zig");
    _ = @import("linux/apps/ipc.zig");
    _ = @import("linux/apps/polkit.zig");
}
