//! Reload has its own fresh owner authorization; no retained polkit grant.
const std = @import("std");
const ipc = @import("ipc.zig");
const polkit = @import("polkit.zig");

pub const help =
    "blackice app reload --policy FILE\n" ++
    "availability=experimental_vm_only\n" ++
    "Generation must be current + 1 (maximum 256). New applications must be closed first.\n" ++
    "Requires fresh owner polkit authorization. Experimental: run it only in a disposable VM;\n" ++
    "it is not ready for host use.\n";

pub fn requireAvailable() error{}!void {}

/// Uses the kernel-derived peer and a fresh, non-retained reload-specific action.
pub fn authorize(peer: ipc.Peer) !void {
    try requireAvailable();
    try polkit.authorizeAction(peer, .reload);
}

test "appfilter reload help says it is experimental and not for host use" {
    try std.testing.expect(std.mem.find(u8, help, "availability=experimental_vm_only\n") != null);
    try std.testing.expect(std.mem.find(u8, help, "not ready for host use") != null);
}
