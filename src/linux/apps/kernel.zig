//! Fixed loader and protected-pin lifecycle. Unit tests never call capability-using operations.
const std = @import("std");
const sys = @import("../sys.zig");
const l = sys.l;
const bpf = l.BPF;
const abi = @import("types.zig");
const programs = @import("programs.zig");
const pin = @import("kernel_pin.zig");
const a = @import("assembler.zig");
const epoch = @import("reload_kernel_types.zig");
pub const pin_root = "/run/blackice-appfilter/bpf";
pub const cgroup_path = "/sys/fs/cgroup/user.slice";
pub const root_cgroup_path = "/sys/fs/cgroup";
const Map = struct { name: [:0]const u8, kind: bpf.MapType, key: u32, value: u32, count: u32 };
const maps = [_]Map{
    .{ .name = "state", .kind = .hash, .key = 4, .value = @sizeOf(epoch.State), .count = 1 },
    .{ .name = "files", .kind = .hash, .key = @sizeOf(abi.FileKey), .value = 4, .count = 4096 },
    .{ .name = "tags", .kind = .array, .key = 4, .value = 4, .count = abi.pid_slots },
    .{ .name = "ports", .kind = .hash, .key = @sizeOf(epoch.PortKey), .value = @sizeOf(epoch.PortValue), .count = epoch.max_rows },
    .{ .name = "ring", .kind = .ringbuf, .key = 0, .value = 0, .count = abi.ring_bytes },
    .{ .name = "lost", .kind = .array, .key = 4, .value = 8, .count = 1 },
    .{ .name = "existing", .kind = .array, .key = 4, .value = 4, .count = abi.max_apps + 1 },
    .{ .name = "checks", .kind = .hash, .key = @sizeOf(abi.FileKey), .value = 4, .count = abi.max_apps },
};
const trace_events = [_]programs.trace_events{ .exit, .fork, .exec };
const trace_ids = [_]u32{ pin.sched_process_exit_btf_id, pin.sched_process_fork_btf_id, pin.sched_process_exec_btf_id };
const trace_names = [_][:0]const u8{ "exit", "fork", "exec" };
const socket_names = [_][:0]const u8{ "conn4", "conn6", "send4", "send6", "create", "peer4", "peer6" };
const socket_hooks = programs.hooks ++ programs.hooks[0..2].*;
fn socketProgram(index: usize, fds: programs.Fds) a.Program {
    return if (index < programs.hooks.len) programs.admissionLayout(socket_hooks[index], fds, .generations) else programs.listenerGuardLayout(socket_hooks[index], fds, .generations);
}
fn socketKind(index: usize) bpf.ProgType {
    return if (index == 4) .cgroup_sock else .cgroup_sock_addr;
}
const zero: u32 = 0;

fn clearMap(fd: l.fd_t, comptime Key: type) !void {
    // Sole writer; delete the first key until empty. No iteration over live values.
    while (true) {
        var next: Key = undefined;
        var attr: bpf.Attr = .{ .map_elem = std.mem.zeroes(bpf.MapElemAttr) };
        attr.map_elem.map_fd = fd;
        attr.map_elem.result.next_key = @intFromPtr(&next);
        const rc = l.bpf(.map_get_next_key, &attr, @sizeOf(bpf.MapElemAttr));
        if (l.errno(rc) == .NOENT) return;
        _ = try sys.check(rc);
        try bpf.map_delete_elem(fd, std.mem.asBytes(&next));
    }
}
fn discardFuture(fd: l.fd_t, comptime Key: type, generation: u32) !void {
    var previous: Key = undefined;
    var have_previous = false;
    while (true) {
        var next: Key = undefined;
        var attr: bpf.Attr = .{ .map_elem = std.mem.zeroes(bpf.MapElemAttr) };
        attr.map_elem.map_fd = fd;
        attr.map_elem.key = if (have_previous) @intFromPtr(&previous) else 0;
        attr.map_elem.result.next_key = @intFromPtr(&next);
        const rc = l.bpf(.map_get_next_key, &attr, @sizeOf(bpf.MapElemAttr));
        if (l.errno(rc) == .NOENT) return;
        _ = try sys.check(rc);
        if (next.generation > generation) {
            try bpf.map_delete_elem(fd, std.mem.asBytes(&next));
            // Keep the previous live key; a deleted cursor would restart iteration.
        } else {
            previous = next;
            have_previous = true;
        }
    }
}

pub const Loaded = struct {
    maps: programs.Fds = .{ .files = -1, .tags = -1, .ports = -1, .state = -1, .ring = -1, .lost = -1, .existing = -1 },
    traces: [3]l.fd_t = @splat(-1),
    trace_links: [3]l.fd_t = @splat(-1),
    sockets: [socket_names.len]l.fd_t = @splat(-1),
    iterator_prog: l.fd_t = -1,
    iterator_link: l.fd_t = -1,

    pub fn create(state: abi.State) !Loaded {
        var f: Loaded = .{};
        errdefer f.close();
        inline for (maps) |m| @field(f.maps, m.name) = try bpf.map_create(m.kind, m.key, m.value, m.count);
        var initial = state;
        initial.version = 2;
        try f.setEpoch(.{ .base = initial, .generation = 1, .fenced = 1 });
        // State is the first pin, before any persistent attachment can exist.
        inline for (maps) |m| try pinFd(@field(f.maps, m.name), m.name);
        return f;
    }
    pub fn openExisting(partial: bool) !?Loaded {
        var f: Loaded = .{};
        errdefer f.close();
        f.maps.state = (try getPin("state")) orelse return null;
        inline for (maps) |m| {
            if (!std.mem.eql(u8, m.name, "state")) @field(f.maps, m.name) = (try getPin(m.name)) orelse -1;
            const fd = @field(f.maps, m.name);
            if (fd < 0) {
                if (!partial) return error.IncompletePins;
            } else try verifyMap(fd, m);
        }
        inline for (trace_names, 0..) |name, i| {
            f.traces[i] = (try getPin("prog_" ++ name)) orelse -1;
            f.trace_links[i] = (try getPin("link_" ++ name)) orelse -1;
            if (f.traces[i] < 0 or f.trace_links[i] < 0) {
                if (!partial) return error.IncompletePins;
            } else {
                try verifyProgram(f.traces[i], &programs.tracingLayout(trace_events[i], f.maps, .generations), .tracing, trace_ids[i]);
                var info: LinkInfo = undefined;
                try getInfo(f.trace_links[i], &info);
                const prog = try programInfo(f.traces[i]);
                // RAW_TRACEPOINT_OPEN uses BPF_LINK_TYPE_RAW_TRACEPOINT (1), also for tp_btf.
                if (info.kind != 1 or info.prog_id != prog.id) return error.WrongTracingLink;
            }
        }
        inline for (socket_names, 0..) |name, i| {
            f.sockets[i] = (try getPin("prog_" ++ name)) orelse -1;
            if (f.sockets[i] < 0) {
                if (!partial) return error.IncompletePins;
            } else try verifyProgram(f.sockets[i], &socketProgram(i, f.maps), socketKind(i), 0);
        }
        f.iterator_prog = (try getPin("prog_iter")) orelse -1;
        f.iterator_link = (try getPin("link_iter")) orelse -1;
        if (f.iterator_prog < 0 or f.iterator_link < 0) {
            if (!partial) return error.IncompletePins;
        } else {
            try verifyProgram(f.iterator_prog, &programs.tracingLayout(.iterator, f.maps, .generations), .tracing, pin.iter_task_btf_id);
            var info: LinkInfo = undefined;
            try getInfo(f.iterator_link, &info);
            if (info.kind != 4 or info.prog_id != (try programInfo(f.iterator_prog)).id) return error.WrongIteratorLink;
        }
        return f;
    }
    pub fn getState(f: *const Loaded) !abi.State {
        return (try f.getEpoch()).base;
    }
    pub fn getEpoch(f: *const Loaded) !epoch.State {
        var state: epoch.State = undefined;
        try bpf.map_lookup_elem(f.maps.state, std.mem.asBytes(&zero), std.mem.asBytes(&state));
        // Decode the enum only after validating its raw discriminant.
        const phase = std.mem.readInt(u32, std.mem.asBytes(&state)[0..4], .little);
        if (phase < 1 or phase > @backingInt(abi.Phase.stopping) or state.base.version != 2 or state.base.app_count == 0 or state.base.app_count > abi.max_apps or state.base.owner_uid == 0 or state.generation == 0 or state.generation > epoch.max_generations or state.fenced > 1) return error.InvalidPinnedState;
        return state;
    }
    pub fn setState(f: *Loaded, state: abi.State) !void {
        var current = try f.getEpoch();
        current.base = state;
        current.base.version = 2;
        try f.setEpoch(current);
    }
    pub fn setEpoch(f: *Loaded, state: epoch.State) !void {
        try bpf.map_update_elem(f.maps.state, std.mem.asBytes(&zero), std.mem.asBytes(&state), 0);
    }
    pub fn generationMaps(f: *Loaded) @import("reload_kernel.zig").Maps {
        return .{ .state = f.maps.state, .files = f.maps.files, .ports = f.maps.ports };
    }
    pub fn reconcile(f: *Loaded, image: @import("reload_kernel.zig").Image) !void {
        const before = try f.getEpoch();
        // This coordinator persists intent BEFORE publishing the new kernel
        // generation. A kernel ahead of intent is an unknown writer, not recovery.
        if (before.generation > image.state.generation) return error.KernelAheadOfIntent;
        var fenced = before;
        fenced.fenced = 1;
        try f.setEpoch(fenced);
        for (image.ports) |row| if (row) |p| {
            var old: epoch.PortValue = undefined;
            if (bpf.map_lookup_elem(f.maps.ports, std.mem.asBytes(&p.key), std.mem.asBytes(&old))) |_| {
                if (!std.mem.eql(u8, std.mem.asBytes(&old), std.mem.asBytes(&p.value))) return error.PinnedPolicyMismatch;
            } else |err| {
                if (err != error.NotFound) return err;
                try bpf.map_update_elem(f.maps.ports, std.mem.asBytes(&p.key), std.mem.asBytes(&p.value), 1);
            }
        };
        for (image.files) |row| if (row) |file| {
            var old: u32 = undefined;
            if (bpf.map_lookup_elem(f.maps.files, std.mem.asBytes(&file.key), std.mem.asBytes(&old))) |_| {
                if (old != file.app_id) return error.DuplicateExecutableIdentity;
            } else |err| {
                if (err != error.NotFound) return err;
                try bpf.map_update_elem(f.maps.files, std.mem.asBytes(&file.key), std.mem.asBytes(&file.app_id), 1);
            }
        };
        try f.setEpoch(image.state);
        // Only unpublished staging rows can be ahead of authoritative intent.
        // Tags and every formerly active generation remain untouched.
        try discardFuture(f.maps.files, epoch.FileKey, image.state.generation);
        try discardFuture(f.maps.ports, epoch.PortKey, image.state.generation);
    }
    pub fn tag(f: *const Loaded, tgid: u32) !u32 {
        if (tgid == 0 or tgid >= abi.pid_slots) return error.InvalidProcess;
        var app: u32 = 0;
        try bpf.map_lookup_elem(f.maps.tags, std.mem.asBytes(&tgid), std.mem.asBytes(&app));
        return app;
    }
    pub fn addFile(f: *Loaded, key: abi.FileKey, app_id: u32) !void {
        const qualified: epoch.FileKey = .{ .device = key.device, .inode = key.inode, .generation = (try f.getEpoch()).generation };
        var old: u32 = 0;
        if (bpf.map_lookup_elem(f.maps.files, std.mem.asBytes(&qualified), std.mem.asBytes(&old))) |_| {
            if (old != app_id) return error.DuplicateExecutableIdentity;
            return;
        } else |err| if (err != error.NotFound) return err;
        try bpf.map_update_elem(f.maps.files, std.mem.asBytes(&qualified), std.mem.asBytes(&app_id), 1);
    }
    pub fn setPorts(f: *Loaded, app_id: u32) !void {
        var ports = abi.ports(app_id);
        inline for (@typeInfo(abi.Ports).@"struct".field_names) |name| @field(ports, name) = std.mem.nativeToBig(u16, @field(ports, name));
        const gen = (try f.getEpoch()).generation;
        const key: epoch.PortKey = .{ .app_id = app_id, .generation = gen };
        const value: epoch.PortValue = .{ .ports = ports, .decision_generation = gen };
        try bpf.map_update_elem(f.maps.ports, std.mem.asBytes(&key), std.mem.asBytes(&value), 0);
    }
    pub fn track(f: *Loaded, verifier: []u8) !void {
        // Exit first, fork second, exec LAST. Pin each dependency before attaching the next.
        inline for (trace_events, 0..) |event, i| {
            const code = programs.tracingLayout(event, f.maps, .generations);
            f.traces[i] = try load(&code, .tracing, .trace_raw_tp, trace_ids[i], "bi_af_" ++ trace_names[i], verifier);
            try pinFd(f.traces[i], "prog_" ++ trace_names[i]);
            var attr: bpf.Attr = .{ .raw_tracepoint = .{ .name = 0, .prog_fd = f.traces[i] } };
            f.trace_links[i] = try sys.fd(l.bpf(.raw_tracepoint_open, &attr, @sizeOf(bpf.RawTracepointAttr)));
            try pinFd(f.trace_links[i], "link_" ++ trace_names[i]);
        }
    }
    pub fn classifyExisting(f: *Loaded, verifier: []u8) !void {
        const code = programs.tracingLayout(.iterator, f.maps, .generations);
        f.iterator_prog = try load(&code, .tracing, .trace_iter, pin.iter_task_btf_id, "bi_af_iter", verifier);
        try pinFd(f.iterator_prog, "prog_iter");
        var link_attr: bpf.Attr = .{ .link_create = std.mem.zeroes(bpf.LinkCreateAttr) };
        link_attr.link_create.prog_fd = f.iterator_prog;
        link_attr.link_create.attach_type = @backingInt(bpf.AttachType.trace_iter);
        f.iterator_link = try sys.fd(l.bpf(.link_create, &link_attr, @sizeOf(bpf.LinkCreateAttr)));
        try pinFd(f.iterator_link, "link_iter");
        const results = try f.scanExisting();
        for (results) |tgid| if (tgid != 0) return error.CloseListedAppsFirst;
    }
    pub fn scanExisting(f: *Loaded) ![abi.max_apps]u32 {
        for (1..abi.max_apps + 1) |id| {
            const key: u32 = @intCast(id);
            try bpf.map_update_elem(f.maps.existing, std.mem.asBytes(&key), std.mem.asBytes(&zero), 0);
        }
        var iter_attr: bpf.Attr = .{ .iter_create = .{ .link_fd = f.iterator_link, .flags = 0 } };
        const iter = try sys.fd(l.bpf(.iter_create, &iter_attr, @sizeOf(bpf.IterCreateAttr)));
        defer sys.close(iter);
        var buf: [256]u8 = undefined;
        while (try sys.read(iter, &buf) != 0) {}
        var results: [abi.max_apps]u32 = undefined;
        for (&results, 1..) |*result, id| {
            const key: u32 = @intCast(id);
            try bpf.map_lookup_elem(f.maps.existing, std.mem.asBytes(&key), std.mem.asBytes(result));
        }
        return results;
    }
    pub fn checkFile(f: *Loaded, key: abi.FileKey, app_id: u32) !void {
        try bpf.map_update_elem(f.maps.checks, std.mem.asBytes(&key), std.mem.asBytes(&app_id), 0);
    }
    pub fn clearChecks(f: *Loaded) !void {
        try clearMap(f.maps.checks, abi.FileKey);
    }
    pub fn attach(f: *Loaded, cgroup: l.fd_t, root_cgroup: l.fd_t, verifier: []u8) !void {
        // Without CAP_SYS_ADMIN an unknown ID cannot be opened to check its name. Refuse conservatively.
        try requireVacant(cgroup);
        try requireRootVacant(root_cgroup);
        inline for (socket_hooks, 0..) |hook, i| {
            const target = if (i < programs.hooks.len) cgroup else root_cgroup;
            const code = socketProgram(i, f.maps);
            f.sockets[i] = try load(&code, socketKind(i), hook, 0, "bi_af_" ++ socket_names[i], verifier);
            try pinFd(f.sockets[i], "prog_" ++ socket_names[i]);
            var attr: bpf.Attr = .{ .prog_attach = std.mem.zeroes(bpf.ProgAttachAttr) };
            attr.prog_attach.target_fd = target;
            attr.prog_attach.attach_bpf_fd = f.sockets[i];
            attr.prog_attach.attach_type = @backingInt(hook);
            attr.prog_attach.attach_flags = 2;
            _ = try sys.check(l.bpf(.prog_attach, &attr, @sizeOf(bpf.ProgAttachAttr)));
            try exactlyAttached(target, hook, (try programInfo(f.sockets[i])).id);
        }
    }
    pub fn verifyAttachments(f: *const Loaded, cgroup: l.fd_t, root_cgroup: l.fd_t) !void {
        for (f.sockets, socket_hooks, 0..) |fd, hook, i| {
            if (fd < 0) return error.AttachmentNotVerified;
            try exactlyAttached(if (i < programs.hooks.len) cgroup else root_cgroup, hook, (try programInfo(fd)).id);
        }
    }
    pub fn detach(f: *Loaded, cgroup: l.fd_t, root_cgroup: l.fd_t) !void {
        const before = try sys.capabilities();
        var raised = before;
        raised[0].effective |= 1 << 12;
        try setCaps(raised);
        defer setCaps(before) catch l.exit_group(125);
        for (f.sockets, socket_hooks, 0..) |fd, hook, i| {
            const target = if (i < programs.hooks.len) cgroup else root_cgroup;
            if (fd < 0 or !try attached(target, hook, (try programInfo(fd)).id)) continue;
            var attr: bpf.Attr = .{ .prog_attach = std.mem.zeroes(bpf.ProgAttachAttr) };
            attr.prog_attach.target_fd = target;
            attr.prog_attach.attach_bpf_fd = fd;
            attr.prog_attach.attach_type = @backingInt(hook);
            _ = try sys.check(l.bpf(.prog_detach, &attr, @sizeOf(bpf.ProgAttachAttr)));
            if (try attached(target, hook, (try programInfo(fd)).id)) return error.DetachmentNotVerified;
        }
    }
    pub fn loss(f: *const Loaded) !u64 {
        var n: u64 = 0;
        try bpf.map_lookup_elem(f.maps.lost, std.mem.asBytes(&zero), std.mem.asBytes(&n));
        return n;
    }
    /// Closing process FDs never detaches or unpins. Armed classification and denial survive death.
    pub fn close(f: *Loaded) void {
        if (f.iterator_link >= 0) sys.close(f.iterator_link);
        if (f.iterator_prog >= 0) sys.close(f.iterator_prog);
        for (f.trace_links) |fd| if (fd >= 0) sys.close(fd);
        for (f.traces) |fd| if (fd >= 0) sys.close(fd);
        for (f.sockets) |fd| if (fd >= 0) sys.close(fd);
        inline for (@typeInfo(programs.Fds).@"struct".field_names) |name| {
            const fd = @field(f.maps, name);
            if (fd >= 0) sys.close(fd);
        }
        f.* = .{};
    }
};

fn load(code: *const a.Program, kind: bpf.ProgType, attach_type: bpf.AttachType, btf_id: u32, name: []const u8, verifier: []u8) !l.fd_t {
    try a.validate(code);
    @memset(verifier, 0);
    var attr: bpf.Attr = .{ .prog_load = std.mem.zeroes(bpf.ProgLoadAttr) };
    attr.prog_load.prog_type = @backingInt(kind);
    attr.prog_load.expected_attach_type = @backingInt(attach_type);
    attr.prog_load.attact_btf_id = btf_id;
    attr.prog_load.insns = @intFromPtr(&code.code);
    attr.prog_load.insn_cnt = @intCast(code.len);
    attr.prog_load.license = @intFromPtr("Dual BSD/GPL");
    if (name.len >= attr.prog_load.prog_name.len) return error.ProgramNameTooLong;
    @memcpy(attr.prog_load.prog_name[0..name.len], name);
    // A successful verifier run must not fail merely because its diagnostic log exceeds our buffer.
    const first = l.bpf(.prog_load, &attr, @sizeOf(bpf.ProgLoadAttr));
    const fd = sys.fd(first) catch retry: {
        attr.prog_load.log_level = 1;
        attr.prog_load.log_size = @intCast(verifier.len);
        attr.prog_load.log_buf = @intFromPtr(verifier.ptr);
        break :retry try sys.fd(l.bpf(.prog_load, &attr, @sizeOf(bpf.ProgLoadAttr)));
    };
    errdefer sys.close(fd);
    try verifyProgram(fd, code, kind, btf_id);
    return fd;
}
const ProgInfo = extern struct {
    kind: u32,
    id: u32,
    tag: [8]u8,
    jited_len: u32,
    xlated_len: u32,
    jited_insns: u64,
    xlated_insns: u64,
    load_time: u64,
    uid: u32,
    map_count: u32,
    map_ids: u64,
    name: [16]u8,
    ifindex: u32,
    gpl_compatible: u32,
    netns_dev: u64,
    netns_ino: u64,
    nr_jited_ksyms: u32,
    nr_jited_func_lens: u32,
    jited_ksyms: u64,
    jited_func_lens: u64,
    btf_id: u32,
    func_info_rec_size: u32,
    func_info: u64,
    nr_func_info: u32,
    nr_line_info: u32,
    line_info: u64,
    jited_line_info: u64,
    nr_jited_line_info: u32,
    line_info_rec_size: u32,
    jited_line_info_rec_size: u32,
    nr_prog_tags: u32,
    prog_tags: u64,
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
    verified_insns: u32,
    attach_btf_obj_id: u32,
    attach_btf_id: u32,
    padding: u32,
};
const LinkInfo = extern struct { kind: u32, id: u32, prog_id: u32, padding: u32, details: [32]u8 };
const MapInfo = extern struct { kind: u32, id: u32, key: u32, value: u32, count: u32, flags: u32 };
fn getInfo(fd: l.fd_t, value: anytype) !void {
    @memset(std.mem.asBytes(value), 0);
    var attr: bpf.Attr = .{ .info = .{ .bpf_fd = fd, .info_len = @intCast(@sizeOf(@TypeOf(value.*))), .info = @intFromPtr(value) } };
    _ = try sys.check(l.bpf(.obj_get_info_by_fd, &attr, @sizeOf(bpf.InfoAttr)));
}
fn programInfo(fd: l.fd_t) !ProgInfo {
    var info: ProgInfo = undefined;
    try getInfo(fd, &info);
    return info;
}
fn verifyProgram(fd: l.fd_t, code: *const a.Program, kind: bpf.ProgType, btf_id: u32) !void {
    var ids: [16]u32 = @splat(0);
    var info: ProgInfo = std.mem.zeroes(ProgInfo);
    info.map_count = ids.len;
    info.map_ids = @intFromPtr(&ids);
    var attr: bpf.Attr = .{ .info = .{ .bpf_fd = fd, .info_len = @sizeOf(ProgInfo), .info = @intFromPtr(&info) } };
    _ = try sys.check(l.bpf(.obj_get_info_by_fd, &attr, @sizeOf(bpf.InfoAttr)));
    if (info.kind != @backingInt(kind) or info.attach_btf_id != btf_id) return error.ProgramTypeMismatch;
    if (!std.mem.eql(u8, &info.tag, &programTag(code))) return error.ProgramTagMismatch;
    if (info.map_count > ids.len) return error.ProgramMapMismatch;
    var expected: [16]u32 = @splat(0);
    var count: usize = 0;
    for (code.code[0..code.len]) |insn| {
        if (insn.code != 0x18 or insn.src != 1) continue;
        var map: MapInfo = undefined;
        try getInfo(insn.imm, &map);
        if (std.mem.findScalar(u32, expected[0..count], map.id) == null) {
            if (count == expected.len) return error.ProgramMapMismatch;
            expected[count] = map.id;
            count += 1;
        }
    }
    if (count != info.map_count) return error.ProgramMapMismatch;
    for (ids[0..info.map_count]) |id| if (std.mem.findScalar(u32, expected[0..count], id) == null) return error.ProgramMapMismatch;
}
fn verifyMap(fd: l.fd_t, want: Map) !void {
    var got: MapInfo = undefined;
    try getInfo(fd, &got);
    if (got.kind != @backingInt(want.kind) or got.key != want.key or got.value != want.value or got.count != want.count or got.flags != 0) return error.MapLayoutMismatch;
}
pub fn programTag(code: *const a.Program) [8]u8 {
    var copy = code.*;
    var pc: usize = 0;
    while (pc < copy.len) : (pc += 1) {
        if (copy.code[pc].code == 0x18 and copy.code[pc].src == 1) {
            copy.code[pc].imm = 0;
            copy.code[pc + 1].imm = 0;
            pc += 1;
        }
    }
    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(std.mem.sliceAsBytes(copy.code[0..copy.len]), &digest, .{});
    return digest[0..8].*;
}
fn pinPath(name: []const u8, buf: *[160]u8) ![:0]const u8 {
    return std.fmt.bufPrintSentinel(buf, pin_root ++ "/{s}", .{name}, 0);
}
fn pinFd(fd: l.fd_t, name: []const u8) !void {
    var path: [160]u8 = undefined;
    var attr: bpf.Attr = .{ .obj = std.mem.zeroes(bpf.ObjAttr) };
    attr.obj.pathname = @intFromPtr((try pinPath(name, &path)).ptr);
    attr.obj.bpf_fd = fd;
    _ = try sys.check(l.bpf(.obj_pin, &attr, @sizeOf(bpf.ObjAttr)));
}
fn getPin(name: []const u8) !?l.fd_t {
    var path: [160]u8 = undefined;
    var attr: bpf.Attr = .{ .obj = std.mem.zeroes(bpf.ObjAttr) };
    attr.obj.pathname = @intFromPtr((try pinPath(name, &path)).ptr);
    const rc = l.bpf(.obj_get, &attr, @sizeOf(bpf.ObjAttr));
    if (l.errno(rc) == .NOENT) return null;
    return try sys.fd(rc);
}
pub fn unpinAll() !void {
    try unpin("link_iter");
    try unpin("prog_iter");
    inline for (trace_names) |name| {
        try unpin("link_" ++ name);
        try unpin("prog_" ++ name);
    }
    inline for (socket_names) |name| try unpin("prog_" ++ name);
    // State last: an interrupted teardown can always be resumed.
    inline for (maps[1..]) |m| try unpin(m.name);
    try unpin("state");
}
fn unpin(name: []const u8) !void {
    var path: [160]u8 = undefined;
    const rc = l.unlink((try pinPath(name, &path)).ptr);
    if (l.errno(rc) != .NOENT) _ = try sys.check(rc);
}
fn query(cgroup: l.fd_t, hook: bpf.AttachType, ids: *[128]u32) ![]const u32 {
    var attr: bpf.Attr = .{ .query = std.mem.zeroes(bpf.QueryAttr) };
    attr.query.target_fd = cgroup;
    attr.query.attach_type = @backingInt(hook);
    attr.query.prog_ids = @intFromPtr(ids);
    attr.query.prog_cnt = ids.len;
    _ = try sys.check(l.bpf(.prog_query, &attr, @sizeOf(bpf.QueryAttr)));
    if (attr.query.prog_cnt > ids.len) return error.TooManyAttachedPrograms;
    return ids[0..attr.query.prog_cnt];
}
fn attached(cgroup: l.fd_t, hook: bpf.AttachType, id: u32) !bool {
    var ids: [128]u32 = undefined;
    for (try query(cgroup, hook, &ids)) |got| if (got == id) return true;
    return false;
}
fn exactlyAttached(cgroup: l.fd_t, hook: bpf.AttachType, id: u32) !void {
    var ids: [128]u32 = undefined;
    const got = try query(cgroup, hook, &ids);
    if (got.len != 1 or got[0] != id) return error.ForeignOrMissingAttachment;
}
pub fn requireVacant(cgroup: l.fd_t) !void {
    var ids: [128]u32 = undefined;
    for (programs.hooks) |hook| if ((try query(cgroup, hook, &ids)).len != 0) return error.AttachPointOccupiedNeedsOwnerReview;
}
pub fn requireRootVacant(cgroup: l.fd_t) !void {
    var ids: [128]u32 = undefined;
    for (programs.hooks[0..2]) |hook| if ((try query(cgroup, hook, &ids)).len != 0) return error.AttachPointOccupiedNeedsOwnerReview;
}
fn requireSingleThread() !void {
    const fd = try sys.fd(l.open("/proc/self/task", .{ .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0));
    defer sys.close(fd);
    var buf: [4096]u8 align(8) = undefined;
    var count: usize = 0;
    while (true) {
        const n = try sys.check(l.getdents64(fd, &buf, buf.len));
        if (n == 0) break;
        var pos: usize = 0;
        while (pos < n) {
            if (n - pos < 20) return error.InvalidTaskDirectory;
            const size = std.mem.readInt(u16, buf[pos + 16 ..][0..2], .little);
            if (size < 20 or size > n - pos) return error.InvalidTaskDirectory;
            const bytes = buf[pos + 19 .. pos + size];
            const end = std.mem.findScalar(u8, bytes, 0) orelse return error.InvalidTaskDirectory;
            const name = bytes[0..end];
            if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                if ((std.fmt.parseInt(u32, name, 10) catch 0) != l.getpid()) return error.PrivilegedWorkerThread;
                count += 1;
            }
            pos += size;
        }
    }
    if (count != 1) return error.PrivilegedWorkerThread;
}
pub fn dropLoadCapabilities() !void {
    try requireSingleThread();
    try sys.noNewPrivileges();
    _ = try sys.check(l.prctl(47, 4, 0, 0, 0)); // PR_CAP_AMBIENT_CLEAR_ALL
    const keep: u32 = 1 << 12; // permitted only; raised only during exact detach
    const caps = [_]sys.Caps{ .{ .effective = 0, .permitted = keep }, .{} };
    try setCaps(caps);
    const actual = try sys.capabilities();
    if (actual[0].effective != 0 or actual[0].permitted != keep or actual[0].inheritable != 0 or actual[1].effective != 0 or actual[1].permitted != 0 or actual[1].inheritable != 0) return error.CapabilityDropNotVerified;
    // No CAP_SETPCAP is added just to alter the bounding set. Cleared permitted/inheritable/ambient
    // plus NNP prevent regaining BPF/PERFMON at exec; the unit bounds what could ever be acquired.
}
fn setCaps(caps: [2]sys.Caps) !void {
    var hdr: sys.CapHeader = .{};
    _ = try sys.check(l.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&caps)));
}
test "appfilter program tags ignore FD numbers but detect instruction changes" {
    const one = programs.admission(.cgroup_inet4_connect, programs.fixture_fds);
    var fds = programs.fixture_fds;
    fds.tags += 100;
    var two = programs.admission(.cgroup_inet4_connect, fds);
    try std.testing.expectEqualSlices(u8, &programTag(&one), &programTag(&two));
    two.code[two.len - 2].imm = 0;
    try std.testing.expect(!std.mem.eql(u8, &programTag(&one), &programTag(&two)));
}
