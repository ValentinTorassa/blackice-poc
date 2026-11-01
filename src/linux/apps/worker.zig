//! Capability-free proxy child. No BPF, cgroup, control or loader descriptor crosses its FD allowlist.
//! The sandbox is applied before starting any proxy thread. Unit tests interpret filters only.
const std = @import("std");
const builtin = @import("builtin");
const sys = @import("../sys.zig");
const l = sys.l;
const abi = @import("types.zig");

pub const Stats = struct {
    failures: [abi.max_apps]std.atomic.Value(u64) = @splat(.init(0)),
    pub fn create() !*Stats {
        const ptr = try sys.check(l.mmap(null, std.heap.pageSize(), .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED, .ANONYMOUS = true }, -1, 0));
        const s: *Stats = @ptrFromInt(ptr);
        s.* = .{};
        return s;
    }
    pub fn close(s: *Stats) void {
        _ = l.munmap(@ptrCast(s), std.heap.pageSize());
    }
};

pub fn sandbox(keep: []const l.fd_t, parent: l.pid_t) !void {
    _ = try sys.check(l.prctl(@backingInt(l.PR.SET_PDEATHSIG), @backingInt(l.SIG.KILL), 0, 0, 0));
    if (l.getppid() != parent) return error.LoaderExited;
    try closeExcept(keep);
    try sys.noNewPrivileges();
    _ = try sys.check(l.prctl(47, 4, 0, 0, 0)); // clear ambient
    try sys.dropCapabilities();
    try sys.nonDumpable();
    const caps = try sys.capabilities();
    for (caps) |c| if (c.effective != 0 or c.permitted != 0 or c.inheritable != 0) return error.ProxyHasCapabilities;
    // No future filesystem writes, including the service's pins, saved policies and intent. Preopened
    // receipt FDs remain writable. Scope signals/abstract Unix so the child cannot attack its loader.
    const version = try sys.check(l.syscall3(.landlock_create_ruleset, 0, 0, 1));
    if (version < 6) return error.LandlockAbi6Required;
    const Attr = extern struct { fs: u64 = 0x7ff2, net: u64 = 0, scoped: u64 = 3 };
    const attr: Attr = .{};
    const rules = try sys.fd(l.syscall3(.landlock_create_ruleset, @intFromPtr(&attr), @sizeOf(Attr), 0));
    defer sys.close(rules);
    _ = try sys.check(l.syscall2(.landlock_restrict_self, @intCast(rules), 0));
    const b = filters();
    const descriptor = extern struct { len: u16, filter: [*]const Filter }{ .len = @intCast(b.len), .filter = &b.items };
    _ = try sys.check(l.prctl(@backingInt(l.PR.SET_SECCOMP), l.SECCOMP.MODE.FILTER, @intFromPtr(&descriptor), 0, 0));
}

fn closeExcept(keep: []const l.fd_t) !void {
    if (keep.len > 64) return error.TooManyProxyDescriptors;
    var fds: [64]l.fd_t = undefined;
    @memcpy(fds[0..keep.len], keep);
    std.mem.sort(l.fd_t, fds[0..keep.len], {}, std.sort.asc(l.fd_t));
    var first: l.fd_t = 3;
    for (fds[0..keep.len]) |fd| {
        if (fd < 3) return error.InvalidProxyDescriptor;
        if (fd < first) continue;
        if (fd > first) _ = try sys.check(l.close_range(first, fd - 1, .{ .UNSHARE = false, .CLOEXEC = false }));
        first = fd + 1;
    }
    _ = try sys.check(l.close_range(first, -1, .{ .UNSHARE = false, .CLOEXEC = false }));
    sys.close(0); // no control input in the parser process
}

const Filter = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 };
const deny: u32 = l.SECCOMP.RET.ERRNO | @as(u32, @backingInt(l.E.PERM));
const allow = l.SECCOMP.RET.ALLOW;
const native_arch: u32 = switch (builtin.cpu.arch) {
    .x86_64 => 0xc000003e,
    .aarch64 => 0xc00000b7,
    else => @compileError("unsupported proxy architecture"),
};
const Builder = struct {
    items: [192]Filter = undefined,
    len: usize = 0,
    fn add(b: *Builder, code: u16, k: u32, jt: u8, jf: u8) void {
        std.debug.assert(b.len < b.items.len);
        b.items[b.len] = .{ .code = code, .k = k, .jt = jt, .jf = jf };
        b.len += 1;
    }
    fn refuse(b: *Builder, call: l.SYS, result: u32) void {
        b.add(0x15, @intCast(@backingInt(call)), 0, 1);
        b.add(0x06, result, 0, 0);
    }
};
fn filters() Builder {
    var b: Builder = .{};
    b.add(0x20, 4, 0, 0);
    b.add(0x15, native_arch, 1, 0);
    b.add(0x06, l.SECCOMP.RET.KILL_PROCESS, 0, 0);
    b.add(0x20, 0, 0, 0);
    if (builtin.cpu.arch == .x86_64) {
        b.add(0x45, 0x40000000, 0, 1);
        b.add(0x06, l.SECCOMP.RET.KILL_PROCESS, 0, 0);
    }
    const denied = [_]l.SYS{
        .bpf,            .perf_event_open, .ptrace,            .process_vm_writev, .process_vm_readv, .pidfd_getfd,
        .io_uring_setup, .io_uring_enter,  .io_uring_register, .userfaultfd,       .capset,           .unshare,
        .setns,          .mount,           .umount2,           .pivot_root,        .chroot,           .open_tree,
        .move_mount,     .fsopen,          .fsmount,           .fspick,            .mount_setattr,    .open_by_handle_at,
        .execve,         .execveat,        .fchmod,            .fchmodat,          .fchmodat2,        .fchown,
        .fchownat,       .utimensat,       .setxattr,          .lsetxattr,         .fsetxattr,        .removexattr,
        .lremovexattr,   .fremovexattr,    .unlinkat,          .renameat,          .renameat2,        .linkat,
        .symlinkat,      .mkdirat,         .mknodat,
    };
    for (denied) |call| b.refuse(call, deny);
    if (builtin.cpu.arch == .x86_64) for ([_]l.SYS{ .fork, .vfork, .chmod, .chown, .lchown, .utime, .utimes, .unlink, .rename, .link, .symlink, .mkdir, .rmdir, .mknod }) |call| b.refuse(call, deny);
    b.refuse(.clone3, l.SECCOMP.RET.ERRNO | @as(u32, @backingInt(l.E.NOSYS)));
    b.add(0x15, @backingInt(l.SYS.clone), 0, 6);
    b.add(0x20, 16, 0, 0);
    b.add(0x45, 0x7e020000, 0, 1); // no new namespaces
    b.add(0x06, deny, 0, 0);
    b.add(0x45, l.CLONE.THREAD, 1, 0); // only threads, no new processes
    b.add(0x06, deny, 0, 0);
    b.add(0x06, allow, 0, 0);
    for ([_]l.SYS{ .socket, .socketpair }) |call| {
        b.add(0x15, @intCast(@backingInt(call)), 0, 5);
        b.add(0x20, 16, 0, 0);
        b.add(0x15, l.AF.INET, 2, 0);
        b.add(0x15, l.AF.INET6, 1, 0);
        b.add(0x06, deny, 0, 0);
        b.add(0x06, allow, 0, 0);
    }
    b.add(0x06, allow, 0, 0);
    return b;
}

fn verdict(call: usize, arg0: u32, arch: u32) !u32 {
    const b = filters();
    var pc: usize = 0;
    var acc: u32 = 0;
    while (pc < b.len) : (pc += 1) {
        const op = b.items[pc];
        switch (op.code) {
            0x20 => acc = switch (op.k) {
                0 => @intCast(call),
                4 => arch,
                16 => arg0,
                else => return error.InvalidFilter,
            },
            0x15 => pc += if (acc == op.k) op.jt else op.jf,
            0x45 => pc += if (acc & op.k != 0) op.jt else op.jf,
            0x06 => return op.k,
            else => return error.InvalidFilter,
        }
    }
    return error.FallsOffFilter;
}
test "appfilter proxy sandbox denies BPF, loader access and mutation but allows parsing and threads" {
    for ([_]l.SYS{ .bpf, .ptrace, .pidfd_getfd, .process_vm_writev, .capset, .unlinkat, .renameat2, .fchmod, .setns, .mount, .execve }) |call|
        try std.testing.expectEqual(deny, try verdict(@backingInt(call), 0, native_arch));
    for ([_]l.SYS{ .read, .write, .pwrite64, .accept4, .connect, .futex, .mmap }) |call|
        try std.testing.expectEqual(allow, try verdict(@backingInt(call), 0, native_arch));
    try std.testing.expectEqual(deny, try verdict(@backingInt(l.SYS.clone), 0, native_arch));
    try std.testing.expectEqual(allow, try verdict(@backingInt(l.SYS.clone), l.CLONE.THREAD, native_arch));
    try std.testing.expectEqual(deny, try verdict(@backingInt(l.SYS.clone), l.CLONE.THREAD | l.CLONE.NEWUSER, native_arch));
    try std.testing.expectEqual(deny, try verdict(@backingInt(l.SYS.socket), l.AF.UNIX, native_arch));
    try std.testing.expectEqual(allow, try verdict(@backingInt(l.SYS.socket), l.AF.INET, native_arch));
    try std.testing.expectEqual(l.SECCOMP.RET.KILL_PROCESS, try verdict(@backingInt(l.SYS.read), 0, 0));
}
