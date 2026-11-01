const std = @import("std");
pub const pin = @import("kernel_pin.zig");

pub fn verify(release: []const u8, btf: []const u8) !void {
    if (!std.mem.eql(u8, release, pin.release)) return error.KernelReleaseMismatch;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(btf, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    if (!std.mem.eql(u8, &hex, pin.btf_sha256)) return error.KernelBtfMismatch;
}

test "appfilter kernel release alone never satisfies the BTF pin" {
    try std.testing.expectError(error.KernelReleaseMismatch, verify("6.12.other", ""));
    try std.testing.expectError(error.KernelBtfMismatch, verify(pin.release, "different BTF for the same release"));
}
