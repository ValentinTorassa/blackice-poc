//! Writes the release's SHA256SUMS. Run by `zig build release`; not part of blackice.
//!
//! Usage: sha256sums OUTPUT NAME PATH [NAME PATH]...
//!
//! One line per file, "<sha256 in hex>  <NAME>", sorted by name: the format `sha256sum -c` and
//! `shasum -a 256 -c` read. NAME is the file's name in the release, PATH where the build put it.
const std = @import("std");

const Entry = struct { name: []const u8, path: []const u8 };

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 4 or args.len % 2 != 0) {
        std.debug.print("usage: sha256sums OUTPUT NAME PATH [NAME PATH]...\n", .{});
        return 2;
    }
    const entries = try arena.alloc(Entry, (args.len - 2) / 2);
    for (entries, 0..) |*e, i| e.* = .{ .name = args[2 + 2 * i], .path = args[3 + 2 * i] };
    std.mem.sort(Entry, entries, {}, byName);

    var sums: std.ArrayList(u8) = .empty;
    for (entries, 0..) |e, i| {
        // A name is one plain file name: checkers read everything after the two spaces as the name.
        if (e.name.len == 0 or std.mem.findAny(u8, e.name, "/\\ \t\r\n") != null) {
            std.debug.print("sha256sums: bad release file name '{s}'\n", .{e.name});
            return 1;
        }
        if (i > 0 and std.mem.eql(u8, e.name, entries[i - 1].name)) {
            std.debug.print("sha256sums: '{s}' given twice\n", .{e.name});
            return 1;
        }
        const data = try std.Io.Dir.cwd().readFileAlloc(io, e.path, arena, .limited(256 << 20));
        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
        try sums.print(arena, "{s}  {s}\n", .{ std.fmt.bytesToHex(digest, .lower), e.name });
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = args[1], .data = sums.items });
    return 0;
}

fn byName(_: void, a: Entry, b: Entry) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}
