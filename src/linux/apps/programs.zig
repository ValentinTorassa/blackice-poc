//! Fixed BPF programs. Pure emission; tests execute a userspace interpreter only.
const std = @import("std");
const a = @import("assembler.zig");
const I = a.I;
const bpf = a.bpf;
const abi = @import("types.zig");
const pin = @import("kernel_pin.zig");
const epoch = @import("reload_kernel_types.zig");
pub const Layout = enum { legacy, generations };
pub const Fds = struct { files: i32, tags: i32, ports: i32, state: i32, ring: i32, lost: i32, existing: i32, checks: i32 = -1 };
pub const trace_events = enum { exec, fork, exit, iterator };
pub const hooks = [_]bpf.AttachType{ .cgroup_inet4_connect, .cgroup_inet6_connect, .cgroup_udp4_sendmsg, .cgroup_udp6_sendmsg, .cgroup_inet_sock_create };
const Fixups = struct {
    sites: [64]usize = undefined,
    len: usize = 0,
    fn add(f: *Fixups, p: *a.Program, i: I) void {
        std.debug.assert(f.len < f.sites.len);
        f.sites[f.len] = p.add(i);
        f.len += 1;
    }
    fn patch(f: *const Fixups, p: *a.Program, target: usize) void {
        for (f.sites[0..f.len]) |at| p.patch(at, target);
    }
};

// r1 is a file pointer. File identity key at fp-48; no path/argv/comm enters classification.
fn fileKey(p: *a.Program, bad: *Fixups, comptime layout: Layout) void {
    bad.add(p, I.jeq(.r1, 0, 0));
    p.emit(I.ldx(.double_word, .r1, .r1, pin.file_f_inode));
    bad.add(p, I.jeq(.r1, 0, 0));
    p.emit(I.ldx(.double_word, .r0, .r1, pin.inode_i_ino));
    p.emit(I.stx(.double_word, .r10, -40, .r0));
    p.emit(I.ldx(.double_word, .r1, .r1, pin.inode_i_sb));
    bad.add(p, I.jeq(.r1, 0, 0));
    p.emit(I.ldx(.word, .r0, .r1, pin.super_block_s_dev));
    p.emit(I.stx(.word, .r10, -48, .r0));
    if (layout == .generations) {
        p.emit(I.ldx(.word, .r0, .r10, -56));
        p.emit(I.stx(.word, .r10, -44, .r0));
    } else p.emit(I.st(.word, .r10, -44, 0));
}

// Key uses task->tgid in the initial PID namespace, including for namespace children.
fn key(p: *a.Program, bad: *Fixups) void {
    bad.add(p, I.jeq(.r7, 0, 0));
    p.emit(I.ldx(.word, .r0, .r7, pin.task_struct_tgid));
    p.emit(I.stx(.word, .r10, -16, .r0));
}
fn owner(p: *a.Program, fds: Fds, done: *Fixups, comptime layout: Layout) void {
    p.emit(I.st(.word, .r10, -52, 0));
    p.lookup(fds.state, -52);
    done.add(p, I.jeq(.r0, 0, 0));
    if (layout == .generations) {
        p.emit(I.ldx(.word, .r1, .r0, @offsetOf(abi.State, "version")));
        done.add(p, I.jne(.r1, 2, 0));
        p.emit(I.ldx(.word, .r1, .r0, @offsetOf(epoch.State, "generation")));
        done.add(p, I.jeq(.r1, 0, 0));
        p.emit(I.stx(.word, .r10, -56, .r1));
    }
    p.emit(I.ldx(.word, .r8, .r0, @offsetOf(abi.State, "owner_uid")));
    p.emit(I.ldx(.double_word, .r1, .r7, pin.task_struct_real_cred));
    done.add(p, I.jeq(.r1, 0, 0));
    p.emit(I.ldx(.word, .r1, .r1, pin.cred_uid + pin.kuid_t_val));
    done.add(p, I.jne(.r1, .r8, 0));
}
fn storeTag(p: *a.Program, fds: Fds, done: *Fixups) void {
    p.lookup(fds.tags, -16);
    done.add(p, I.jeq(.r0, 0, 0));
    p.emit(I.stx(.word, .r0, 0, .r9)); // array store: no allocation and no insertion failure
}
pub fn tracing(event: trace_events, fds: Fds) a.Program {
    return tracingLayout(event, fds, .legacy);
}
pub fn tracingLayout(event: trace_events, fds: Fds, comptime layout: Layout) a.Program {
    var p: a.Program = .{};
    var done: Fixups = .{};
    p.emit(I.mov(.r6, .r1));
    p.emit(I.ldx(.double_word, .r7, .r6, if (event == .iterator) pin.bpf_iter__task_task else 0));
    key(&p, &done);
    switch (event) {
        .exit => {
            p.emit(I.ldx(.double_word, .r1, .r7, pin.task_struct_signal));
            done.add(&p, I.jeq(.r1, 0, 0));
            p.emit(I.ldx(.word, .r1, .r1, pin.signal_struct_live + pin.atomic_t_counter));
            done.add(&p, I.jne(.r1, 0, 0));
            p.emit(I.mov(.r9, 0));
            storeTag(&p, fds, &done);
        },
        .exec => {
            p.lookup(fds.tags, -16);
            done.add(&p, I.jeq(.r0, 0, 0));
            p.emit(I.ldx(.word, .r9, .r0, 0));
            done.add(&p, I.jne(.r9, 0, 0)); // first listed app wins across every exec
            owner(&p, fds, &done, layout);
            p.emit(I.ldx(.double_word, .r1, .r6, 16));
            done.add(&p, I.jeq(.r1, 0, 0));
            p.emit(I.ldx(.double_word, .r1, .r1, pin.linux_binprm_file));
            fileKey(&p, &done, layout);
            p.lookup(fds.files, -48);
            done.add(&p, I.jeq(.r0, 0, 0));
            p.emit(I.ldx(.word, .r9, .r0, 0));
            storeTag(&p, fds, &done);
        },
        .fork => {
            p.lookup(fds.tags, -16);
            done.add(&p, I.jeq(.r0, 0, 0));
            p.emit(I.ldx(.word, .r9, .r0, 0));
            p.emit(I.ldx(.double_word, .r7, .r6, 8));
            key(&p, &done);
            storeTag(&p, fds, &done); // unconditional, including zero (ADR C1)
        },
        .iterator => {
            owner(&p, fds, &done, layout);
            p.lookup(fds.tags, -16);
            done.add(&p, I.jeq(.r0, 0, 0));
            p.emit(I.ldx(.word, .r0, .r0, 0));
            done.add(&p, I.jne(.r0, 0, 0)); // exec after tracking started is already covered
            p.emit(I.ldx(.double_word, .r1, .r7, pin.task_struct_mm));
            done.add(&p, I.jeq(.r1, 0, 0));
            p.emit(I.ldx(.double_word, .r1, .r1, pin.mm_struct_exe_file));
            // Reload checks a separate candidate map, never the active exec map.
            fileKey(&p, &done, .legacy);
            p.lookup(if (layout == .generations) fds.checks else fds.files, -48);
            done.add(&p, I.jeq(.r0, 0, 0));
            p.emit(I.ldx(.word, .r9, .r0, 0));
            if (layout == .generations) p.emit(I.stx(.word, .r10, -52, .r9));
            p.lookup(fds.existing, -52);
            done.add(&p, I.jeq(.r0, 0, 0));
            if (layout == .generations) p.emit(I.ldx(.word, .r9, .r10, -16));
            p.emit(I.stx(.word, .r0, 0, .r9)); // reports an app that must be closed first
        },
    }
    const end = p.len;
    p.ret(0);
    done.patch(&p, end);
    return p;
}

// Branches to `yes` for all loopback spellings; falls through otherwise.
fn loopback(p: *a.Program, v6: bool, yes: *Fixups) void {
    if (!v6) {
        p.emit(I.ldx(.word, .r0, .r6, 4));
        p.emit(I.alu_and(.r0, 255));
        yes.add(p, I.jeq(.r0, 127, 0));
        yes.add(p, I.jeq(.r0, 0, 0)); // Linux routes unspecified IPv4 destinations locally.
    } else {
        var no: Fixups = .{};
        p.emit(I.ldx(.word, .r0, .r6, 8));
        no.add(p, I.jne(.r0, 0, 0));
        p.emit(I.ldx(.word, .r0, .r6, 12));
        no.add(p, I.jne(.r0, 0, 0));
        p.emit(I.ldx(.word, .r0, .r6, 16));
        const mapped = p.add(a.word(I.jeq(.r0, @as(i32, @bitCast(std.mem.nativeToBig(u32, 65535))), 0)));
        no.add(p, I.jne(.r0, 0, 0));
        p.emit(I.ldx(.word, .r0, .r6, 20));
        yes.add(p, I.jeq(.r0, @as(i32, @bitCast(std.mem.nativeToBig(u32, 1))), 0));
        yes.add(p, I.jeq(.r0, 0, 0)); // tcp_v6_connect maps :: to ::1 after this hook.
        no.add(p, I.ja(0));
        const m = p.len;
        p.emit(I.ldx(.word, .r0, .r6, 20));
        p.emit(I.alu_and(.r0, 255));
        yes.add(p, I.jeq(.r0, 127, 0));
        yes.add(p, I.jeq(.r0, 0, 0));
        const end = p.len;
        p.emit(I.mov(.r0, 0));
        p.patch(mapped, m);
        no.patch(p, end);
    }
}
fn listenerPeer(p: *a.Program, v6: bool, allow: *Fixups, deny: *Fixups, root: bool) void {
    const not_tcp = if (!root) blk: {
        p.emit(I.ldx(.word, .r0, .r6, 36));
        break :blk p.add(I.jne(.r0, 6, 0));
    } else null;
    var is_loop: Fixups = .{};
    loopback(p, v6, &is_loop);
    const outside = p.add(I.ja(0));
    const check = p.len;
    p.emit(I.mov(.r8, @as(i32, @backingInt(abi.Reason.listener_peer))));
    p.emit(I.ldx(.word, .r1, .r6, 24));
    for (abi.first_port..abi.last_port + 1) |port| {
        const next = p.add(I.jne(.r1, std.mem.nativeToBig(u16, @intCast(port)), 0));
        if (port == abi.last_port) deny.add(p, I.ja(0)) else {
            allow.add(p, I.jeq(.r9, @as(i32, @intCast(1 + (port - abi.first_port) / 2)), 0));
            deny.add(p, I.ja(0));
        }
        const end = p.len;
        p.emit(I.mov(.r0, 0));
        p.patch(next, end);
    }
    const end = p.len;
    p.emit(I.mov(.r0, 0));
    is_loop.patch(p, check);
    p.patch(outside, end);
    if (not_tcp) |at| p.patch(at, end);
}

/// Root-cgroup guard: only reserved local listener ports are restricted, across every cgroup.
pub fn listenerGuard(hook: bpf.AttachType, fds: Fds) a.Program {
    return listenerGuardLayout(hook, fds, .legacy);
}
pub fn listenerGuardLayout(hook: bpf.AttachType, fds: Fds, comptime layout: Layout) a.Program {
    std.debug.assert(hook == .cgroup_inet4_connect or hook == .cgroup_inet6_connect);
    var p: a.Program = .{};
    var allow: Fixups = .{};
    var deny: Fixups = .{};
    p.emit(I.mov(.r6, .r1));
    p.emit(I.mov(.r9, 0));
    p.emit(I.mov(.r8, @as(i32, @backingInt(abi.Reason.tag_missing))));
    if (layout == .generations) captureEpoch(&p, fds);
    p.emit(I.call(.get_current_pid_tgid));
    p.emit(I.rsh(.r0, 32));
    p.emit(I.stx(.word, .r10, -16, .r0));
    p.lookup(fds.tags, -16);
    deny.add(&p, I.jeq(.r0, 0, 0));
    p.emit(I.ldx(.word, .r9, .r0, 0));
    // Even MPTCP or another connect protocol must not give an untagged caller a local listener.
    listenerPeer(&p, hook == .cgroup_inet6_connect, &allow, &deny, true);
    const yes = p.len;
    p.ret(1);
    const no = p.len;
    if (layout == .generations) captureReceiptGeneration(&p, fds);
    emitRefusal(&p, hook, fds, layout);
    allow.patch(&p, yes);
    deny.patch(&p, no);
    return p;
}

pub fn admission(hook: bpf.AttachType, fds: Fds) a.Program {
    return admissionLayout(hook, fds, .legacy);
}
pub fn admissionLayout(hook: bpf.AttachType, fds: Fds, comptime layout: Layout) a.Program {
    const create = hook == .cgroup_inet_sock_create;
    const v6 = hook == .cgroup_inet6_connect or hook == .cgroup_udp6_sendmsg;
    const send = hook == .cgroup_udp4_sendmsg or hook == .cgroup_udp6_sendmsg;
    var p: a.Program = .{};
    var deny: Fixups = .{};
    var allow: Fixups = .{};
    p.emit(I.mov(.r6, .r1));
    p.emit(I.mov(.r9, 0));
    p.emit(I.mov(.r8, @as(i32, @backingInt(abi.Reason.tag_missing))));
    if (layout == .generations) captureEpoch(&p, fds);
    p.emit(I.call(.get_current_pid_tgid));
    p.emit(I.rsh(.r0, 32));
    p.emit(I.stx(.word, .r10, -16, .r0));
    p.lookup(fds.tags, -16);
    deny.add(&p, I.jeq(.r0, 0, 0));
    p.emit(I.ldx(.word, .r9, .r0, 0));
    if (layout == .generations) captureBinding(&p, fds, &deny);
    if (!create and !send) listenerPeer(&p, v6, &allow, &deny, false);
    allow.add(&p, I.jeq(.r9, 0, 0));
    p.emit(I.mov(.r8, @as(i32, @backingInt(abi.Reason.socket_protocol))));
    if (create) {
        // bpf_sock.bound_dev_if: tagged sockets are bound to lo before sending or accepting.
        p.emit(I.st(.word, .r6, 0, 1));
        p.emit(I.ldx(.word, .r0, .r6, 12));
        const tcp = p.add(I.jeq(.r0, 6, 0));
        deny.add(&p, I.jne(.r0, 17, 0));
        p.emit(I.ldx(.word, .r0, .r6, 8));
        deny.add(&p, I.jne(.r0, 2, 0));
        allow.add(&p, I.ja(0));
        const stream = p.len;
        p.emit(I.ldx(.word, .r0, .r6, 8));
        deny.add(&p, I.jne(.r0, 1, 0));
        allow.add(&p, I.ja(0));
        p.patch(tcp, stream);
    } else {
        p.emit(I.ldx(.word, .r0, .r6, 36));
        const tcp = p.add(I.jeq(.r0, 6, 0));
        deny.add(&p, I.jne(.r0, 17, 0));
        p.emit(I.mov(.r8, @as(i32, @intCast(@backingInt(if (send) abi.Reason.udp else abi.Reason.udp_connect)))));
        // Only UDP to the IPv4 system stub. Mapped IPv6 is covered too.
        p.emit(I.ldx(.word, .r1, .r6, 24));
        deny.add(&p, I.jne(.r1, std.mem.nativeToBig(u16, 53), 0));
        if (v6) {
            for ([_]i16{ 8, 12 }) |off| {
                p.emit(I.ldx(.word, .r1, .r6, off));
                deny.add(&p, I.jne(.r1, 0, 0));
            }
            p.emit(I.ldx(.word, .r1, .r6, 16));
            deny.add(&p, a.word(I.jne(.r1, @as(i32, @bitCast(std.mem.nativeToBig(u32, 65535))), 0)));
        }
        p.emit(I.ldx(.word, .r1, .r6, if (v6) 20 else 4));
        deny.add(&p, I.jne(.r1, @as(i32, @bitCast(std.mem.nativeToBig(u32, 0x7f000035))), 0));
        allow.add(&p, I.ja(0));
        const tcp_at = p.len;
        p.emit(I.mov(.r8, @as(i32, @backingInt(abi.Reason.other_port))));
        p.patch(tcp, tcp_at);
        if (send) deny.add(&p, I.ja(0)) else {
            p.emit(I.ldx(.word, .r1, .r6, 24));
            const tls = p.add(I.jeq(.r1, std.mem.nativeToBig(u16, 443), 0));
            deny.add(&p, I.jne(.r1, std.mem.nativeToBig(u16, 80), 0));
            p.emit(I.mov(.r7, 2));
            const http = p.add(I.ja(0));
            const tls_at = p.len;
            p.emit(I.mov(.r7, 0));
            const select = p.len;
            p.emit(I.stx(.word, .r10, -28, .r9));
            if (layout == .generations) {
                p.emit(I.ldx(.word, .r0, .r10, -56));
                p.emit(I.stx(.word, .r10, -24, .r0));
            }
            p.lookup(fds.ports, -28);
            p.emit(I.mov(.r8, @as(i32, @backingInt(abi.Reason.listener_missing))));
            deny.add(&p, I.jeq(.r0, 0, 0));
            const select_tls = p.add(I.jeq(.r7, 0, 0));
            p.emit(I.ldx(.half_word, .r1, .r0, if (v6) 6 else 2));
            const selected = p.add(I.ja(0));
            const tls_load = p.len;
            p.emit(I.ldx(.half_word, .r1, .r0, if (v6) 4 else 0));
            const redirect = p.len;
            deny.add(&p, I.jeq(.r1, 0, 0));
            p.emit(I.stx(.word, .r6, 24, .r1));
            if (v6) {
                // Keep IPv4-mapped sockets mapped. A v4-mapped peer cannot connect to native ::1.
                p.emit(I.mov(.r7, 0));
                var native: Fixups = .{};
                for ([_]i16{ 8, 12 }) |off| {
                    p.emit(I.ldx(.word, .r0, .r6, off));
                    native.add(&p, I.jne(.r0, 0, 0));
                }
                p.emit(I.ldx(.word, .r0, .r6, 16));
                native.add(&p, a.word(I.jne(.r0, @as(i32, @bitCast(std.mem.nativeToBig(u32, 65535))), 0)));
                p.emit(I.mov(.r7, 1));
                const rewrite = p.len;
                for ([_]i16{ 8, 12 }) |off| p.emit(I.st(.word, .r6, off, 0));
                const mapped = p.add(I.jne(.r7, 0, 0));
                p.emit(I.st(.word, .r6, 16, 0));
                p.emit(I.st(.word, .r6, 20, @bitCast(std.mem.nativeToBig(u32, 1))));
                allow.add(&p, I.ja(0));
                const rewrite_mapped = p.len;
                p.emit(I.st(.word, .r6, 16, @bitCast(std.mem.nativeToBig(u32, 65535))));
                p.emit(I.st(.word, .r6, 20, @bitCast(std.mem.nativeToBig(u32, 0x7f000001))));
                p.patch(mapped, rewrite_mapped);
                native.patch(&p, rewrite);
            } else p.emit(I.st(.word, .r6, 4, @bitCast(std.mem.nativeToBig(u32, 0x7f000001))));
            allow.add(&p, I.ja(0));
            p.patch(tls, tls_at);
            p.patch(http, select);
            p.patch(select_tls, tls_load);
            p.patch(selected, redirect);
        }
    }
    const refusal = p.len;
    emitRefusal(&p, hook, fds, layout);
    const permitted = p.len;
    p.ret(1);
    deny.patch(&p, refusal);
    allow.patch(&p, permitted);
    return p;
}
fn emitRefusal(p: *a.Program, hook: bpf.AttachType, fds: Fds, comptime layout: Layout) void {
    const create = hook == .cgroup_inet_sock_create;
    const v6 = hook == .cgroup_inet6_connect or hook == .cgroup_udp6_sendmsg;
    p.map(.r1, fds.ring);
    p.emit(I.mov(.r2, @sizeOf(abi.Event)));
    p.emit(I.mov(.r3, 0));
    p.emit(I.call(.ringbuf_reserve));
    const lost = p.add(I.jeq(.r0, 0, 0));
    p.emit(I.mov(.r7, .r0));
    p.emit(I.call(.ktime_get_ns));
    p.emit(I.stx(.double_word, .r7, 0, .r0));
    p.emit(I.ldx(.word, .r0, .r10, -16));
    p.emit(I.stx(.double_word, .r7, 8, .r0));
    if (layout == .generations) {
        p.emit(I.ldx(.word, .r0, .r10, -60));
        p.emit(I.stx(.word, .r7, epoch.event_generation_offset, .r0));
    }
    p.emit(I.mov(.r0, 0));
    p.emit(I.stx(.double_word, .r7, 16, .r0));
    p.emit(I.stx(.word, .r7, 24, .r9));
    p.emit(I.st(.word, .r7, 28, @intCast(@backingInt(hook))));
    p.emit(I.ldx(.word, .r0, .r6, if (create) 4 else 0));
    p.emit(I.stx(.word, .r7, 32, .r0));
    p.emit(I.ldx(.word, .r0, .r6, if (create) 12 else 36));
    p.emit(I.stx(.word, .r7, 36, .r0));
    if (create) p.emit(I.mov(.r0, 0)) else p.emit(I.ldx(.word, .r0, .r6, 24));
    p.emit(I.stx(.word, .r7, 40, .r0));
    p.emit(I.stx(.word, .r7, 44, .r8));
    for (0..4) |i| {
        if (!create and (v6 or i == 0)) {
            p.emit(I.ldx(.word, .r0, .r6, @intCast(if (v6) 8 + i * 4 else 4)));
        } else p.emit(I.mov(.r0, 0));
        p.emit(I.stx(.word, .r7, @intCast(48 + i * 4), .r0));
    }
    p.emit(I.mov(.r1, .r7));
    p.emit(I.mov(.r2, 0));
    p.emit(I.call(.ringbuf_submit));
    p.ret(0);
    const lost_at = p.len;
    p.emit(I.st(.word, .r10, -28, 0));
    p.lookup(fds.lost, -28);
    const absent = p.add(I.jeq(.r0, 0, 0));
    p.emit(I.mov(.r1, 1));
    p.emit(I.xadd(.r0, .r1));
    const end = p.len;
    p.ret(0);
    p.patch(lost, lost_at);
    p.patch(absent, end);
}

// One active hash lookup per hook. Generation and fence are copied before any
// other map lookup. Old rows remain available for a reader crossing publication.
fn captureEpoch(p: *a.Program, fds: Fds) void {
    p.emit(I.st(.word, .r10, -56, 0));
    p.emit(I.st(.word, .r10, -60, 0));
    p.emit(I.st(.word, .r10, -64, 1));
    p.emit(I.st(.word, .r10, -52, 0));
    p.lookup(fds.state, -52);
    var missing: Fixups = .{};
    missing.add(p, I.jeq(.r0, 0, 0));
    p.emit(I.ldx(.word, .r1, .r0, @offsetOf(abi.State, "version")));
    missing.add(p, I.jne(.r1, 2, 0));
    p.emit(I.ldx(.word, .r1, .r0, @offsetOf(epoch.State, "generation")));
    missing.add(p, I.jeq(.r1, 0, 0));
    p.emit(I.stx(.word, .r10, -56, .r1));
    p.emit(I.stx(.word, .r10, -60, .r1));
    p.emit(I.ldx(.word, .r1, .r0, @offsetOf(epoch.State, "fenced")));
    p.emit(I.stx(.word, .r10, -64, .r1));
    const end = p.len;
    p.emit(I.mov(.r0, 0));
    missing.patch(p, end);
}
fn captureBinding(p: *a.Program, fds: Fds, deny: *Fixups) void {
    const unlisted = p.add(I.jeq(.r9, 0, 0));
    p.emit(I.mov(.r8, @as(i32, @backingInt(abi.Reason.generation_fenced))));
    p.emit(I.ldx(.word, .r0, .r10, -64));
    deny.add(p, I.jne(.r0, 0, 0));
    p.emit(I.stx(.word, .r10, -28, .r9));
    p.emit(I.ldx(.word, .r0, .r10, -56));
    p.emit(I.stx(.word, .r10, -24, .r0));
    p.lookup(fds.ports, -28);
    p.emit(I.mov(.r8, @as(i32, @backingInt(abi.Reason.listener_missing))));
    deny.add(p, I.jeq(.r0, 0, 0));
    p.emit(I.ldx(.word, .r0, .r0, @offsetOf(epoch.PortValue, "decision_generation")));
    deny.add(p, I.jeq(.r0, 0, 0));
    p.emit(I.stx(.word, .r10, -60, .r0));
    const end = p.len;
    p.emit(I.mov(.r0, 0));
    p.patch(unlisted, end);
}

// A root-guard refusal is already decided. Resolve a retired slot's stamp for
// the receipt only; never extend this guard's traffic restrictions or refetch the epoch.
fn captureReceiptGeneration(p: *a.Program, fds: Fds) void {
    var done: Fixups = .{};
    done.add(p, I.jeq(.r9, 0, 0));
    p.emit(I.stx(.word, .r10, -28, .r9));
    p.emit(I.ldx(.word, .r0, .r10, -56));
    p.emit(I.stx(.word, .r10, -24, .r0));
    p.lookup(fds.ports, -28);
    done.add(p, I.jeq(.r0, 0, 0));
    p.emit(I.ldx(.word, .r0, .r0, @offsetOf(epoch.PortValue, "decision_generation")));
    done.add(p, I.jeq(.r0, 0, 0));
    p.emit(I.stx(.word, .r10, -60, .r0));
    const end = p.len;
    p.emit(I.mov(.r0, 0));
    done.patch(p, end);
}

pub const fixture_fds: Fds = .{ .files = 10, .tags = 11, .ports = 12, .state = 13, .ring = 14, .lost = 15, .existing = 16, .checks = 17 };
test "appfilter every emitted trace, iterator and admission instruction is reachable" {
    for (std.meta.tags(trace_events)) |event| try a.validate(&tracing(event, fixture_fds));
    for (hooks) |hook| try a.validate(&admission(hook, fixture_fds));
    for (hooks[0..2]) |hook| try a.validate(&listenerGuard(hook, fixture_fds));
    for (std.meta.tags(trace_events)) |event| try a.validate(&tracingLayout(event, fixture_fds, .generations));
    for (hooks) |hook| try a.validate(&admissionLayout(hook, fixture_fds, .generations));
    for (hooks[0..2]) |hook| try a.validate(&listenerGuardLayout(hook, fixture_fds, .generations));
}
