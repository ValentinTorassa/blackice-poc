const std = @import("std");
const sys = @import("../sys.zig");
const l = sys.l;
const abi = @import("types.zig");

pub const Ring = struct {
    consumer_map: []align(4096) u8,
    producer_map: []align(4096) u8,
    page: usize,

    pub fn open(fd: l.fd_t) !Ring {
        const page = std.heap.pageSize();
        const a = try sys.check(l.mmap(null, page, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, fd, 0));
        errdefer _ = l.munmap(@ptrFromInt(a), page);
        const b = try sys.check(l.mmap(null, page + 2 * abi.ring_bytes, .{ .READ = true }, .{ .TYPE = .SHARED }, fd, @intCast(page)));
        return .{ .consumer_map = @as([*]align(4096) u8, @ptrFromInt(a))[0..page], .producer_map = @as([*]align(4096) u8, @ptrFromInt(b))[0 .. page + 2 * abi.ring_bytes], .page = page };
    }
    pub fn close(r: *Ring) void {
        _ = l.munmap(r.consumer_map.ptr, r.consumer_map.len);
        _ = l.munmap(r.producer_map.ptr, r.producer_map.len);
    }
    pub fn next(r: *Ring) !?abi.Event {
        const consumer: *u64 = @ptrCast(r.consumer_map.ptr);
        const producer: *const u64 = @ptrCast(r.producer_map.ptr);
        var pos = @atomicLoad(u64, consumer, .acquire);
        const end = @atomicLoad(u64, producer, .acquire);
        if (end -% pos > abi.ring_bytes) return error.InvalidRing;
        while (pos != end) {
            const start: usize = r.page + @as(usize, @intCast(pos & (abi.ring_bytes - 1)));
            const header: *const u32 = @ptrCast(@alignCast(r.producer_map.ptr + start));
            const len_flags = @atomicLoad(u32, header, .acquire);
            if (len_flags & (1 << 31) != 0) return null; // producer still writing
            const len = len_flags & 0x3fffffff;
            if (len != @sizeOf(abi.Event)) return error.InvalidRing;
            pos +%= std.mem.alignForward(u64, len + 8, 8);
            if (len_flags & (1 << 30) != 0) {
                @atomicStore(u64, consumer, pos, .release);
                continue;
            }
            var result: abi.Event = undefined;
            @memcpy(std.mem.asBytes(&result), r.producer_map[start + 8 ..][0..@sizeOf(abi.Event)]);
            @atomicStore(u64, consumer, pos, .release);
            return result;
        }
        return null;
    }
};
