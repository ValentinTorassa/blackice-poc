//! Fixed host paths and root-trusted executable identities. No caller path is opened with DAC privileges.
const std = @import("std");
const sys = @import("../sys.zig");
const l = sys.l;
const abi = @import("types.zig");
const kernel = @import("kernel.zig");
pub const state_root = "/var/lib/blackice-appfilter";
pub const Install = struct { version: u32, owner_uid: u32, owner_gid: u32, service_uid: u32, service_gid: u32 };
pub fn installation(gpa: std.mem.Allocator) !Install {
    const fd = try sys.fd(l.open("/etc/blackice-appfilter/owner.json", .{ .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer sys.close(fd);
    try sys.rootOwned(fd);
    var bytes: [512]u8 = undefined;
    const n = try sys.read(fd, &bytes);
    if (n == bytes.len) return error.BadInstallation;
    const parsed = try std.json.parseFromSlice(Install, gpa, bytes[0..n], .{ .ignore_unknown_fields = false, .duplicate_field_behavior = .@"error" });
    defer parsed.deinit();
    const cfg = parsed.value;
    if (cfg.version != 1 or cfg.owner_uid == 0 or cfg.service_uid == 0 or cfg.owner_uid == cfg.service_uid) return error.BadInstallation;
    return cfg;
}
pub fn directories(cfg: Install) !void {
    const p = try sys.fd(l.open(kernel.pin_root, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
    defer sys.close(p);
    const s = try sys.stat(p);
    if (s.uid != cfg.service_uid or s.mode & 0o777 != 0o700) return error.UnprotectedPins;
    var fs: [32]u64 = @splat(0);
    _ = try sys.check(l.syscall2(.fstatfs, @as(usize, @intCast(p)), @intFromPtr(&fs)));
    if (fs[0] != 0xcafe4a11) return error.PrivateBpffsRequired;
    const d = try sys.fd(l.open(state_root, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
    defer sys.close(d);
    const ds = try sys.stat(d);
    if (ds.uid != cfg.service_uid or ds.gid != cfg.owner_gid or ds.mode & 0o7777 != 0o2750) return error.UnprotectedServiceState;
}
pub fn cgroup() !l.fd_t {
    return openCgroup(kernel.cgroup_path);
}
pub fn rootCgroup() !l.fd_t {
    return openCgroup(kernel.root_cgroup_path);
}
fn openCgroup(path: [:0]const u8) !l.fd_t {
    const fd = try sys.fd(l.open(path, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
    errdefer sys.close(fd);
    try sys.rootOwned(fd);
    var fs: [32]u64 = @splat(0);
    _ = try sys.check(l.syscall2(.fstatfs, @as(usize, @intCast(fd)), @intFromPtr(&fs)));
    if (fs[0] != 0x63677270) return error.CgroupV2Required;
    return fd;
}
pub fn portFloor() !void {
    const fd = try sys.fd(l.open("/proc/sys/net/ipv4/ip_unprivileged_port_start", .{ .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer sys.close(fd);
    var buf: [32]u8 = undefined;
    const n = try sys.read(fd, &buf);
    const value = std.fmt.parseInt(u32, std.mem.trim(u8, buf[0..n], "\n"), 10) catch return error.InvalidPortFloor;
    if (!@import("state.zig").validPortFloor(value)) return error.ListenerPortsAreUnprivileged;
}
pub fn identity(gpa: std.mem.Allocator, path: []const u8) !abi.FileKey {
    if (!@import("config.zig").validPath(path)) return error.InvalidExecutablePath;
    var dir = try sys.fd(l.open("/", .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0));
    defer sys.close(dir);
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        const name = try gpa.dupeSentinel(u8, part, 0);
        defer gpa.free(name);
        const next = try sys.fd(l.openat(dir, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
        var next_owned = true;
        defer if (next_owned) sys.close(next);
        try sys.rootOwned(next);
        const s = try sys.stat(next);
        const last = parts.peek() == null;
        if (s.mode & 0o170000 != (if (last) @as(u16, 0o100000) else @as(u16, 0o040000))) return error.CanonicalRootOwnedExecutableRequired;
        sys.close(dir);
        dir = next;
        next_owned = false; // dir's outer defer owns this fd, including header-validation failures.
        if (last) {
            if (s.mode & 0o111 == 0) return error.ExecutableRequired;
            var fs: [32]u64 = @splat(0);
            _ = try sys.check(l.syscall2(.fstatfs, @as(usize, @intCast(dir)), @intFromPtr(&fs)));
            if (!identityFilesystemSupported(fs[0])) return error.UnsupportedExecutableFilesystem;
            try requireNativeExecutable(dir);
            return .{ .device = try abi.kernelDevice(s.dev_major, s.dev_minor), .inode = s.ino };
        }
    }
    return error.ExecutableRequired;
}

fn requireNativeExecutable(pinned: l.fd_t) !void {
    const original = try sys.stat(pinned);
    if (original.mode & 0o170000 != 0o100000) return error.CanonicalRootOwnedExecutableRequired;
    // O_PATH cannot read. Follow only our own fixed fd link, never the policy's pathname again:
    // a rename-over must not make the header belong to a different inode than the registered key.
    var path: [64]u8 = undefined;
    const fd_path = try std.fmt.bufPrintSentinel(&path, "/proc/self/fd/{d}", .{pinned}, 0);
    const readable = try sys.fd(l.open(fd_path, .{ .CLOEXEC = true, .NONBLOCK = true }, 0));
    defer sys.close(readable);
    const opened = try sys.stat(readable);
    if (opened.ino != original.ino or opened.dev_major != original.dev_major or opened.dev_minor != original.dev_minor)
        return error.ExecutableIdentityChanged;
    var magic: [4]u8 = undefined;
    var n: usize = 0;
    while (n < magic.len) {
        const got = try sys.read(readable, magic[n..]);
        if (got == 0) break;
        n += got;
    }
    if (n >= 2 and std.mem.eql(u8, magic[0..2], "#!")) return error.ScriptExecutableUnsupported;
    // Other interpreter/binfmt formats also cannot be identified by the configured file's inode.
    // This checks the format prefix only; the kernel still validates the full ELF at exec.
    if (n != magic.len or !std.mem.eql(u8, &magic, "\x7fELF")) return error.UnsupportedExecutableFormat;
}

pub fn identityFilesystemSupported(magic: u64) bool {
    // statx st_dev must equal inode->i_sb->s_dev. btrfs subvolumes and overlayfs do not meet this contract.
    return magic == 0xef53 or magic == 0x58465342; // ext4 (ext family ABI) / xfs
}
test "appfilter executable filesystem identity rejects overlay and btrfs" {
    try std.testing.expect(identityFilesystemSupported(0xef53));
    try std.testing.expect(identityFilesystemSupported(0x58465342));
    for ([_]u64{ 0x9123683e, 0x794c7630, 0x01021994, 0 }) |magic| try std.testing.expect(!identityFilesystemSupported(magic));
}

test "appfilter executable headers refuse scripts and incomplete or foreign formats" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    for ([_][]const u8{ "#!", "#!/bin/sh\necho test\n", "#!/usr/bin/env python3\npass\n" }) |bytes| {
        try tmp.dir.writeFile(io, .{ .sub_path = "listed", .data = bytes });
        const fd = try sys.fd(l.openat(tmp.dir.handle, "listed", .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
        defer sys.close(fd);
        try std.testing.expectError(error.ScriptExecutableUnsupported, requireNativeExecutable(fd));
    }
    for ([_][]const u8{ "", "#", "\x7fEL", "echo test\n", "MZ\x00\x00" }) |bytes| {
        try tmp.dir.writeFile(io, .{ .sub_path = "listed", .data = bytes });
        const fd = try sys.fd(l.openat(tmp.dir.handle, "listed", .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
        defer sys.close(fd);
        try std.testing.expectError(error.UnsupportedExecutableFormat, requireNativeExecutable(fd));
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "listed", .data = "\x7fELF\x02\x01\x01\x00" });
    const native = try sys.fd(l.openat(tmp.dir.handle, "listed", .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
    defer sys.close(native);
    try requireNativeExecutable(native);
    try std.testing.expectError(error.CanonicalRootOwnedExecutableRequired, requireNativeExecutable(tmp.dir.handle));
}

test "appfilter executable header stays with the pinned inode across rename replacement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const script = "#!/bin/sh\nexit 0\n";
    const native = "\x7fELF\x02\x01\x01\x00";
    for ([_]bool{ false, true }) |script_first| {
        try tmp.dir.writeFile(io, .{ .sub_path = "listed", .data = if (script_first) script else native });
        try tmp.dir.writeFile(io, .{ .sub_path = "replacement", .data = if (script_first) native else script });
        const pinned = try sys.fd(l.openat(tmp.dir.handle, "listed", .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
        defer sys.close(pinned);
        try tmp.dir.rename("replacement", tmp.dir, "listed", io);
        const replaced = try sys.fd(l.openat(tmp.dir.handle, "listed", .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
        defer sys.close(replaced);
        try std.testing.expect((try sys.stat(pinned)).ino != (try sys.stat(replaced)).ino);
        try requireNativeExecutable(if (script_first) replaced else pinned);
        try std.testing.expectError(error.ScriptExecutableUnsupported, requireNativeExecutable(if (script_first) pinned else replaced));
    }
}

test "appfilter unreadable executable header refuses instead of accepting an unchecked identity" {
    if (l.geteuid() == 0) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const file = try tmp.dir.createFile(io, "listed", .{});
    defer file.close(io);
    try file.writePositionalAll(io, "\x7fELF\x02\x01\x01\x00", 0);
    _ = try sys.check(l.fchmod(file.handle, 0o111));
    const pinned = try sys.fd(l.openat(tmp.dir.handle, "listed", .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0));
    defer sys.close(pinned);
    try std.testing.expectError(error.PermissionDenied, requireNativeExecutable(pinned));
}

pub fn writePolicy(gpa: std.mem.Allocator, io: std.Io, digest: []const u8, bytes: []const u8) !void {
    const path = try std.fmt.allocPrint(gpa, "policy-{s}.json", .{digest});
    defer gpa.free(path);
    var dir = try std.Io.Dir.openDirAbsolute(io, state_root, .{});
    defer dir.close(io);
    atomicWrite(dir, io, path, bytes, false) catch |err| {
        if (err != error.PathAlreadyExists) return err;
        const old = try dir.readFileAlloc(io, path, gpa, .limited(@import("config.zig").max_bytes));
        defer gpa.free(old);
        if (!std.mem.eql(u8, old, bytes)) return error.StoredPolicyMismatch;
    };
}
pub fn atomicWrite(dir: std.Io.Dir, io: std.Io, name: []const u8, bytes: []const u8, replace: bool) !void {
    var file = try dir.createFileAtomic(io, name, .{ .permissions = .fromMode(0o600), .replace = replace });
    defer file.deinit(io);
    try file.file.writePositionalAll(io, bytes, 0);
    _ = try sys.check(l.fsync(file.file.handle));
    if (replace) try file.replace(io) else try file.link(io);
    // Io.Dir may hold O_PATH, which cannot be fsynced. Reopen this pinned directory read-only.
    const sync_dir = try sys.fd(l.openat(dir.handle, ".", .{ .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer sys.close(sync_dir);
    _ = try sys.check(l.fsync(sync_dir));
}
pub fn watch(gpa: std.mem.Allocator, paths: []const @import("config.zig").App) !l.fd_t {
    const fd = try sys.fd(l.inotify_init1(l.SOCK.CLOEXEC | l.SOCK.NONBLOCK));
    errdefer sys.close(fd);
    for (paths) |app| {
        // Watch the containing directory: rename-over replaces the file being watched.
        const slash = std.mem.findScalarLast(u8, app.executable, '/') orelse return error.InvalidExecutablePath;
        const parent = try gpa.dupeSentinel(u8, if (slash == 0) "/" else app.executable[0..slash], 0);
        defer gpa.free(parent);
        _ = try sys.check(l.inotify_add_watch(fd, parent, l.IN.CREATE | l.IN.MOVED_TO | l.IN.DELETE_SELF | l.IN.MOVE_SELF | l.IN.ATTRIB | l.IN.CLOSE_WRITE));
    }
    return fd;
}

pub fn refreshWatch(gpa: std.mem.Allocator, paths: []const @import("config.zig").App, old: l.fd_t, context: anytype, comptime refresh: anytype) !l.fd_t {
    const fresh = try watch(gpa, paths);
    errdefer sys.close(fresh);
    // A replacement during refresh is queued on the NEW fd and survives closing the old one.
    try refresh(context);
    if (old >= 0) sys.close(old);
    return fresh;
}

test "appfilter replacement during refresh remains queued on the new watch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const base = try tmp.dir.realPathFileAlloc(io, ".", gpa);
    defer gpa.free(base);
    const path = try std.fmt.allocPrint(gpa, "{s}/listed", .{base});
    defer gpa.free(path);
    try tmp.dir.writeFile(io, .{ .sub_path = "listed", .data = "old" });
    try tmp.dir.writeFile(io, .{ .sub_path = "replacement", .data = "new" });
    const apps = [_]@import("config.zig").App{.{ .executable = path, .network = undefined }};
    const callback = struct {
        fn replace(dir: std.Io.Dir) !void {
            try dir.rename("replacement", dir, "listed", std.testing.io);
        }
    }.replace;
    const old = try watch(gpa, &apps);
    const fresh = try refreshWatch(gpa, &apps, old, tmp.dir, callback);
    defer sys.close(fresh);
    var bytes: [1024]u8 = undefined;
    const n = try sys.read(fresh, &bytes);
    try std.testing.expect(n >= 16);
    const mask = std.mem.readInt(u32, bytes[4..8], .little);
    try std.testing.expect(mask & l.IN.MOVED_TO != 0);
    try std.testing.expect(std.mem.find(u8, bytes[0..n], "listed") != null);
}

test "appfilter policy storage is exclusive and intent replacement is atomic" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try atomicWrite(tmp.dir, io, "policy", "first", false);
    try std.testing.expectError(error.PathAlreadyExists, atomicWrite(tmp.dir, io, "policy", "second", false));
    try atomicWrite(tmp.dir, io, "intent", "armed", true);
    try atomicWrite(tmp.dir, io, "intent", "off", true);
    const bytes = try tmp.dir.readFileAlloc(io, "intent", std.testing.allocator, .limited(100));
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("off", bytes);
}
