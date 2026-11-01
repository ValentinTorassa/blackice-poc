//! Single dedicated-user instance. No client-controlled code, target cgroup or kernel offsets.
const std = @import("std");
const Io = std.Io;
const sys = @import("../sys.zig");
const l = sys.l;
const abi = @import("types.zig");
const config = @import("config.zig");
const kernel = @import("kernel.zig");
const host = @import("host.zig");
const intent = @import("intent.zig");
const worker = @import("worker.zig");
const refusals = @import("refusals.zig");
const ipc = @import("ipc.zig");
const polkit = @import("polkit.zig");
const proxy = @import("../../proxy/proxy.zig");
const receipt = @import("../../core/receipt.zig");
const Ring = @import("ring.zig").Ring;
const pinning = @import("pinning.zig");
const pin = @import("kernel_pin.zig");
const reload_history = @import("reload_history.zig");
const reload_maps = @import("reload_kernel.zig");
const channel = @import("reload_channel.zig");
const wire = @import("reload_protocol.zig");
const faults = @import("reload_faults.zig");
const reload_receipts = @import("reload_receipts.zig");
const port_count = abi.last_port - abi.first_port + 1;

pub fn main(init: std.process.Init) u8 {
    run(init) catch |err| {
        sys.writeAll(2, "blackice app filter: ") catch {};
        sys.writeAll(2, @errorName(err)) catch {};
        sys.writeAll(2, "; no new enforcement claim; existing pins retained unless authorized off completed\n") catch {};
        return 125;
    };
    return 0;
}
fn run(init: std.process.Init) !void {
    try faults.requireGuest();
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.ExpectedServiceOrTeardown;
    const teardown = std.mem.eql(u8, args[1], "--teardown");
    if (!teardown and !std.mem.eql(u8, args[1], "--service")) return error.ExpectedServiceOrTeardown;
    const install = try host.installation(init.gpa);
    if (teardown) {
        if (l.geteuid() != 0) return error.OwnerRootTeardownRequired;
    } else {
        if (l.geteuid() != install.service_uid or l.getuid() != install.service_uid) return error.DedicatedSystemServiceRequired;
        const caps = try sys.capabilities();
        if (caps[0].effective != ((1 << 10) | (1 << 12)) or caps[1].effective != ((1 << 6) | (1 << 7))) return error.ServiceCapabilitiesRequired;
        try sys.noNewPrivileges();
        try sys.nonDumpable();
        try activatedSocket(init);
    }
    if (!teardown) try host.directories(install);
    const cg = try host.cgroup();
    defer sys.close(cg);
    const root_cg = try host.rootCgroup();
    defer sys.close(root_cg);
    const lock = try sys.fd(l.open(host.state_root ++ "/instance.lock", .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600));
    defer sys.close(lock);
    _ = try sys.check(l.flock(lock, 2 | 4));
    if (teardown) {
        if (try kernel.Loaded.openExisting(true)) |got| {
            var f = got;
            defer f.close();
            try f.detach(cg, root_cg);
            try kernel.unpinAll();
        }
        // Without pins do not guess an ID or detach someone else's program.
        try kernel.requireVacant(cg);
        try kernel.requireRootVacant(root_cg);
        return;
    }
    // procfs files report size 0, so readFileAlloc on /proc/sys/kernel/osrelease returns no bytes and the
    // release check could never pass. uname(2) returns the same release string.
    const uts = std.posix.uname();
    const release = std.mem.sliceTo(&uts.release, 0);
    const btf = try Io.Dir.cwd().readFileAlloc(init.io, "/sys/kernel/btf/vmlinux", init.gpa, .limited(16 * 1024 * 1024));
    defer init.gpa.free(btf);
    try pinning.verify(release, btf);
    var runtime: Runtime = .{ .gpa = init.gpa, .io = init.io, .install = install, .cg = cg, .root_cg = root_cg, .history = .{ .allocator = init.gpa } };
    defer runtime.deinit();
    runtime.service_log = try newLog(init.gpa, init.io, "service", "appfilter");
    if (try kernel.Loaded.openExisting(true)) |got| {
        runtime.loaded = got;
        const state = try runtime.loaded.?.getState();
        if (state.owner_uid != install.owner_uid) return error.PinnedOwnerMismatch;
        if (state.phase != .armed) {
            try runtime.rollback();
            if (state.phase == .stopping) {
                const digest = std.fmt.bytesToHex(state.policy_sha256, .lower);
                try intent.write(init.gpa, init.io, false, &digest);
            }
            runtime.service_log.?.write(.{ .event = "app_filter_on_failed", .point = .app_filter, .reason = "interrupted_arming" });
        } else {
            runtime.loaded.?.close();
            runtime.loaded = (try kernel.Loaded.openExisting(false)) orelse return error.IncompletePins;
            try runtime.loaded.?.verifyAttachments(cg, root_cg);
            // Fence first. Persisted intent, not the last volatile state write,
            // determines the generation restored after a killed loader/worker.
            var fenced = try runtime.loaded.?.getEpoch();
            fenced.fenced = 1;
            try runtime.loaded.?.setEpoch(fenced);
            const saved = (try intent.read(init.gpa, init.io)) orelse return error.MissingArmedIntent;
            if (!saved.armed or !std.mem.eql(u8, &saved.boot, &try intent.bootId())) return error.InvalidArmedIntent;
            try runtime.restoreHistory(saved);
            // Checked while admission is still fenced: a record this boot cannot explain stops startup here.
            const pending = try runtime.pendingAtRestart();
            const image = try reload_maps.Image.fromSnapshot(install.owner_uid, &runtime.history.head.load(.acquire).?.snapshot);
            try runtime.loaded.?.reconcile(image);
            try runtime.configureChecks();
            try runtime.refreshWatchedFiles();
            try runtime.openLogs();
            try runtime.bindListeners();
            runtime.ring = try Ring.open(runtime.loaded.?.maps.ring);
            try kernel.dropLoadCapabilities();
            try runtime.startProxyWorker();
            runtime.armed = true;
            var active = try runtime.loaded.?.getEpoch();
            active.fenced = 0;
            try runtime.loaded.?.setEpoch(active);
            runtime.service_log.?.policy_id = &runtime.cfg.?.digest;
            runtime.service_log.?.generation = runtime.cfg.?.generation;
            try runtime.drain();
            runtime.service_log.?.write(.{ .event = "app_filter_restart", .point = .app_filter, .detail = "reopened verified pins; receipts drained; file identities refreshed; downtime=unknown" });
            try runtime.recoveryReceipt(pending);
        }
    } else {
        try kernel.requireVacant(cg);
        try kernel.requireRootVacant(root_cg);
    }
    while (true) {
        try runtime.drain();
        var fds = [_]l.pollfd{
            .{ .fd = 3, .events = l.POLL.IN, .revents = 0 },
            .{ .fd = runtime.watch_fd, .events = l.POLL.IN, .revents = 0 },
            .{ .fd = runtime.worker_fd, .events = l.POLL.IN, .revents = 0 },
        };
        _ = try sys.poll(&fds, 100);
        if (fds[2].revents != 0) return error.ProxyExited; // pinned classification/denial remain active
        if (fds[1].revents != 0) {
            var events: [8192]u8 = undefined;
            const n = l.read(runtime.watch_fd, &events, events.len);
            if (l.errno(n) != .AGAIN) _ = try sys.check(n);
            // Any event, including an overflow, causes a complete identity refresh and new watches.
            try runtime.refreshWatchedFiles();
        }
        if (fds[0].revents == 0) continue;
        const accepted = l.accept4(3, null, null, l.SOCK.CLOEXEC);
        switch (l.errno(accepted)) {
            .MFILE, .NFILE, .AGAIN => {
                _ = try sys.poll(&.{}, 100);
                continue;
            },
            else => {},
        }
        const client = try sys.fd(accepted);
        defer sys.close(client);
        const keep_running = runtime.request(client) catch |err| {
            const failure = runtime.reload_failure;
            runtime.service_log.?.write(.{ .event = "app_filter_control", .point = .app_filter, .verdict = .deny, .reason = @errorName(err), .detail = if (failure) |f| f.progress.field() else null });
            var reply: [192]u8 = undefined;
            sys.writeAll(client, reload_receipts.reply(&reply, @errorName(err), failure) catch "ERROR\n") catch {};
            if (runtime.failed_start) return error.ArmingFailed;
            continue;
        };
        if (!keep_running) return;
    }
}
fn activatedSocket(init: std.process.Init) !void {
    const count = init.environ_map.get("LISTEN_FDS") orelse return error.SocketActivationRequired;
    const pid = init.environ_map.get("LISTEN_PID") orelse return error.SocketActivationRequired;
    if (!std.mem.eql(u8, count, "1") or (std.fmt.parseInt(u32, pid, 10) catch 0) != l.getpid()) return error.SocketActivationRequired;
    var accepting: u32 = 0;
    var n: l.socklen_t = 4;
    _ = try sys.check(l.getsockopt(3, l.SOL.SOCKET, l.SO.ACCEPTCONN, std.mem.asBytes(&accepting), &n));
    if (accepting != 1) return error.SocketActivationRequired;
    var address: l.sockaddr.un = undefined;
    n = @sizeOf(l.sockaddr.un);
    _ = try sys.check(l.getsockname(3, @ptrCast(&address), &n));
    if (address.family != l.AF.UNIX or n != @offsetOf(l.sockaddr.un, "path") + ipc.socket_path.len + 1 or !std.mem.eql(u8, address.path[0..ipc.socket_path.len], ipc.socket_path)) return error.WrongControlSocket;
    _ = try sys.check(l.fcntl(3, l.F.SETFD, @as(u32, l.FD_CLOEXEC)));
    const flags = try sys.check(l.fcntl(3, l.F.GETFL, 0));
    _ = try sys.check(l.fcntl(3, l.F.SETFL, flags | @as(u32, @bitCast(l.O{ .NONBLOCK = true }))));
}
fn newLog(gpa: std.mem.Allocator, io: Io, scope: []const u8, policy: []const u8) !receipt.Log {
    const name = try std.fmt.allocPrint(gpa, "receipt-{d}-{d}-{s}.jsonl", .{ Io.Clock.real.now(io).nanoseconds, l.getpid(), scope });
    defer gpa.free(name);
    var dir = try Io.Dir.openDirAbsolute(io, host.state_root, .{});
    defer dir.close(io);
    var log = try receipt.Log.open(io, dir, name, scope, policy);
    errdefer log.close();
    _ = try sys.check(l.fchmod(log.file.handle, 0o640));
    log.max_bytes = 8 * 1024 * 1024;
    return log;
}
const Runtime = struct {
    gpa: std.mem.Allocator,
    io: Io,
    install: host.Install,
    cg: l.fd_t,
    root_cg: l.fd_t,
    cfg: ?*config.Config = null,
    history: reload_history.History,
    loaded: ?kernel.Loaded = null,
    ring: ?Ring = null,
    service_log: ?receipt.Log = null,
    logs: [abi.max_apps]?receipt.Log = @splat(null),
    proxy_logs: [abi.max_apps]?receipt.Log = @splat(null),
    scopes: [abi.max_apps]?[]const u8 = @splat(null),
    proxy_scopes: [abi.max_apps]?[]const u8 = @splat(null),
    servers: [port_count * 2]?Io.net.Server = @splat(null),
    proxies: [abi.max_apps * 4]?*proxy.Proxy = @splat(null),
    budgets: [abi.max_apps]proxy.ConnectionBudget = @splat(.{ .limit = 16 }),
    proxy_stats: ?*worker.Stats = null,
    worker_fd: l.fd_t = -1,
    worker_pid: l.pid_t = 0,
    policy_write: l.fd_t = -1,
    policy_read: l.fd_t = -1,
    added_running: [abi.max_apps]u32 = @splat(0),
    added_pidfds: [abi.max_apps]l.fd_t = @splat(-1),
    changing: bool = false,
    /// Set when the current request is a reload that failed after its pending record.
    reload_failure: ?reload_receipts.Failure = null,
    refuse_stop: std.atomic.Value(bool) = .init(false),
    watch_fd: l.fd_t = -1,
    armed: bool = false,
    stopping: bool = false,
    failed_start: bool = false,
    reported_loss: u64 = 0,
    reported_write_loss: u64 = 0,
    udp_connect: [abi.max_apps + 1]refusals.Batch = @splat(.{}),
    udp_flushed_ns: i128 = 0,
    verifier: [65536]u8 = @splat(0),

    fn closeListeners(r: *Runtime) void {
        if (r.policy_write >= 0) {
            sys.close(r.policy_write);
            r.policy_write = -1;
        }
        if (r.policy_read >= 0) {
            sys.close(r.policy_read);
            r.policy_read = -1;
        }
        if (r.worker_fd >= 0) {
            _ = l.pidfd_send_signal(r.worker_fd, .KILL, null, 0);
            _ = sys.wait(r.worker_pid) catch 0;
            sys.close(r.worker_fd);
            r.worker_fd = -1;
            r.worker_pid = 0;
        }
        for (&r.proxies) |*p| if (p.*) |value| {
            value.stop();
            p.* = null;
        };
        for (&r.servers) |*s| if (s.*) |*value| {
            value.deinit(r.io);
            s.* = null;
        };
    }
    fn deinit(r: *Runtime) void {
        r.closeListeners();
        r.flushUdp();
        if (r.watch_fd >= 0) sys.close(r.watch_fd);
        for (r.added_pidfds) |fd| if (fd >= 0) sys.close(fd);
        if (r.ring) |*ring| ring.close();
        if (r.loaded) |*loaded| loaded.close(); // pins survive all unplanned termination
        for (&r.logs) |*log| if (log.*) |*value| value.close();
        for (&r.proxy_logs) |*log| if (log.*) |*value| value.close();
        for (r.scopes) |scope| if (scope) |value| r.gpa.free(value);
        for (r.proxy_scopes) |scope| if (scope) |value| r.gpa.free(value);
        if (r.proxy_stats) |stats| stats.close();
        if (r.service_log) |*log| log.close();
        r.history.deinit();
    }
    fn openLogs(r: *Runtime) !void {
        r.proxy_stats = try worker.Stats.create();
        for (0..abi.max_apps) |i| {
            r.scopes[i] = try std.fmt.allocPrint(r.gpa, "app-{d}", .{i + 1});
            r.logs[i] = try newLog(r.gpa, r.io, r.scopes[i].?, "unassigned");
            r.logs[i].?.app_id = @intCast(i + 1);
            r.proxy_scopes[i] = try std.fmt.allocPrint(r.gpa, "app-{d}-proxy", .{i + 1});
            r.proxy_logs[i] = try newLog(r.gpa, r.io, r.proxy_scopes[i].?, "unassigned");
            r.proxy_logs[i].?.app_id = @intCast(i + 1);
            r.proxy_logs[i].?.shared_failures = &r.proxy_stats.?.failures[i];
        }
    }
    fn refreshFiles(r: *Runtime) !void {
        const current = r.history.head.load(.acquire).?;
        for (current.snapshot.slots, 0..) |slot, i| if (slot) |b| {
            if (b.active) try r.loaded.?.addFile(try r.identity(b.executable), @intCast(i + 1));
        };
    }
    fn refreshWatchedFiles(r: *Runtime) !void {
        r.watch_fd = try host.refreshWatch(r.gpa, r.cfg.?.apps, r.watch_fd, r, Runtime.refreshFiles);
    }
    fn identity(r: *Runtime, path: []const u8) !abi.FileKey {
        return host.identity(r.gpa, path) catch |err| {
            r.service_log.?.write(.{ .event = "app_filter_identity", .point = .app_filter, .verdict = .deny, .reason = @errorName(err), .executable = path });
            sys.writeAll(2, path) catch {};
            sys.writeAll(2, ": ") catch {};
            sys.writeAll(2, @errorName(err)) catch {};
            sys.writeAll(2, "\n") catch {};
            return err;
        };
    }
    fn bindListeners(r: *Runtime) !void {
        try host.portFloor();
        errdefer r.closeListeners();
        // Reserve the ENTIRE range before any proxy starts, so a collision cannot produce partial arming.
        for (abi.first_port..abi.last_port + 1) |port| for (0..2) |family| {
            r.servers[(port - abi.first_port) * 2 + family] = @import("listener.zig").listen(@intCast(port), family == 1) catch |err| {
                var b: [128]u8 = undefined;
                const detail = try std.fmt.bufPrint(&b, "loopback port={d} family={d}: {s}", .{ port, family + 4, @errorName(err) });
                r.service_log.?.write(.{ .event = "app_filter_on_failed", .point = .app_filter, .reason = "listener_unavailable", .detail = detail });
                return error.ListenerPortOccupied;
            };
        };
    }
    fn serveListeners(r: *Runtime) !void {
        // Only the capability-free child calls this. Its log files have no second writer in the parent.
        errdefer r.closeListeners();
        for (0..abi.max_apps) |i| for (0..4) |j| {
            const slot = i * 4 + j;
            const cfg: proxy.Config = .{ .mode = if (j < 2) .transparent_tls else .transparent_http, .receipt_point = .app_filter, .connection_budget = &r.budgets[i], .header_timeout = .fromSeconds(5), .live = r.history.source(i) };
            r.proxies[slot] = try proxy.Proxy.startListening(r.gpa, r.io, &r.cfg.?.apps[0].network, &r.proxy_logs[i].?, cfg, r.servers[slot].?);
            r.servers[slot] = null;
        };
    }
    fn startProxyWorker(r: *Runtime) !void {
        // dropLoadCapabilities has just verified the loader has exactly one thread.
        const ready = try sys.pipe();
        defer sys.close(ready[0]);
        var ready_write_owned = true;
        errdefer if (ready_write_owned) sys.close(ready[1]);
        const requests = try channel.pipe();
        var pipes_owned = true;
        errdefer if (pipes_owned) {
            sys.close(requests[0]);
            sys.close(requests[1]);
        };
        const answers = try channel.pipe();
        errdefer if (pipes_owned) {
            sys.close(answers[0]);
            sys.close(answers[1]);
        };
        const parent = l.getpid();
        const child: l.pid_t = @intCast(try sys.check(l.fork()));
        if (child == 0) {
            r.proxyChild(ready[1], parent, requests[0], answers[1]) catch |err| {
                sys.writeAll(2, "blackice proxy worker: ") catch {};
                sys.writeAll(2, @errorName(err)) catch {};
                sys.writeAll(2, "\n") catch {};
            };
            l.exit_group(125);
        }
        sys.close(ready[1]);
        ready_write_owned = false;
        sys.close(requests[0]);
        sys.close(answers[1]);
        r.policy_write = requests[1];
        r.policy_read = answers[0];
        pipes_owned = false;
        errdefer r.closeListeners();
        const pidfd = sys.fd(l.pidfd_open(child, 0)) catch |err| {
            _ = l.kill(child, .KILL); // unreaped child; its PID cannot be reused
            _ = sys.wait(child) catch 0;
            return err;
        };
        r.worker_fd = pidfd;
        r.worker_pid = child;
        var mark: [1]u8 = undefined;
        try ipc.readExact(ready[0], &mark, 5000);
        if (mark[0] != 'P') return error.ProxyNotReady;
        // The child alone owns listener and proxy-receipt descriptors after the handshake.
        for (&r.servers) |*server| if (server.*) |*s| {
            s.deinit(r.io);
            server.* = null;
        };
        for (&r.proxy_logs) |*log| if (log.*) |*value| {
            value.close();
            log.* = null;
        };
    }
    fn proxyChild(r: *Runtime, ready: l.fd_t, parent: l.pid_t, requests: l.fd_t, answers: l.fd_t) !void {
        // The only inherited shared BPF mapping is the ring. Unmap it before processing any traffic.
        if (r.ring) |*ring| ring.close();
        r.ring = null;
        var keep: [64]l.fd_t = undefined;
        var n: usize = 3;
        keep[0] = ready;
        keep[1] = requests;
        keep[2] = answers;
        for (r.servers) |server| if (server) |s| {
            keep[n] = s.socket.handle;
            n += 1;
        };
        for (r.proxy_logs) |log| if (log) |value| {
            keep[n] = value.file.handle;
            n += 1;
        };
        try worker.sandbox(keep[0..n], parent);
        r.history.workerIdentities();
        try r.serveListeners();
        for (0..abi.max_apps) |i| r.slotAssigned(i);
        try sys.writeAll(ready, "P");
        sys.close(ready);
        try r.childPolicies(requests, answers);
    }
    fn slotAssigned(r: *Runtime, i: usize) void {
        if (r.history.source(i).current()) |b| r.proxy_logs[i].?.write(.{ .event = "slot_assigned", .point = .app_filter, .decision = b.decision, .executable = b.executable });
    }
    fn childPolicies(r: *Runtime, requests: l.fd_t, answers: l.fd_t) !void {
        var machine: @import("reload_worker.zig").Machine = .{ .policies = &r.history };
        while (true) {
            var fds = [_]l.pollfd{.{ .fd = requests, .events = l.POLL.IN, .revents = 0 }};
            if (try sys.poll(&fds, 1000) == 0) continue;
            const deadline = try channel.Deadline.start();
            var raw: [wire.header_bytes]u8 = undefined;
            try deadline.read(requests, &raw);
            const h = try wire.decodeHeader(&raw);
            const bytes = try r.gpa.alloc(u8, h.length);
            defer r.gpa.free(bytes);
            try deadline.read(requests, bytes);
            const old = r.history.head.load(.acquire).?;
            const status = try machine.handle(h, bytes);
            if (status == .activated) {
                const current = r.history.head.load(.acquire).?;
                for (current.snapshot.slots, 0..) |slot, i| if (slot) |binding| {
                    if (old.snapshot.slots[i] == null) r.slotAssigned(i);
                    r.proxy_logs[i].?.write(.{ .event = "policy_changed", .point = .app_filter, .reason = if (binding.active) "policy_updated" else "app_retired", .executable = binding.executable, .old_policy = if (old.snapshot.slots[i]) |before| &before.network.digest_hex else null, .new_policy = &binding.network.digest_hex, .decision = .{ .policy = &binding.network.digest_hex, .generation = current.cfg.generation } });
                };
            }
            const ack = try wire.encodeAck(.{ .stamp = h.stamp, .status = status });
            try deadline.write(answers, &ack);
        }
    }
    fn rollback(r: *Runtime) !void {
        r.closeListeners();
        if (r.loaded == null) r.loaded = try kernel.Loaded.openExisting(true);
        if (r.loaded) |*f| {
            try f.detach(r.cg, r.root_cg);
            try kernel.unpinAll();
            f.close();
            r.loaded = null;
        }
    }
    fn start(r: *Runtime, bytes: []const u8, peer: ipc.Peer) !void {
        const initial = try r.history.prepare(bytes, null);
        var published = false;
        errdefer if (!published) {
            r.history.discard(initial);
            r.cfg = null;
        };
        r.cfg = &initial.cfg;
        if (r.cfg.?.generation != 1) return error.InitialGenerationMustBeOne;
        if (try intent.read(r.gpa, r.io)) |saved| {
            if (saved.armed and !std.mem.eql(u8, &saved.policy, &r.cfg.?.digest)) return error.PolicyChangeRequiresAuthorizedOff;
        }
        // A new arming starts at generation 1. A reload record left by an earlier arming is settled now.
        try r.settlePending();
        // Validate every executable and its ancestors before creating kernel objects.
        for (&initial.snapshot.slots) |*slot| if (slot.*) |*b| {
            b.identity = try r.identity(b.executable);
        };
        r.history.publish(initial);
        published = true;
        r.failed_start = true;
        try host.writePolicy(r.gpa, r.io, &r.cfg.?.digest, bytes);
        var hash: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&hash, &r.cfg.?.digest);
        var state: abi.State = .{ .phase = .maps, .owner_uid = peer.credentials.uid, .app_count = @intCast(r.cfg.?.apps.len), .policy_sha256 = hash };
        r.failed_start = true;
        errdefer {
            r.rollback() catch {};
            const log = std.mem.sliceTo(&r.verifier, 0);
            if (log.len > 0) {
                sys.writeAll(2, log) catch {};
                sys.writeAll(2, "\n") catch {};
            }
        }
        r.loaded = try kernel.Loaded.create(state);
        try r.refreshWatchedFiles();
        for (initial.snapshot.slots, 0..) |slot, i| if (slot) |b| try r.loaded.?.checkFile(b.identity, @intCast(i + 1));
        for (r.cfg.?.apps, 0..) |_, i| try r.loaded.?.setPorts(@intCast(i + 1));
        try r.loaded.?.attach(r.cg, r.root_cg, &r.verifier);
        state.phase = .cgroup;
        try r.loaded.?.setState(state);
        try r.openLogs();
        try r.bindListeners();
        state.phase = .listeners;
        try r.loaded.?.setState(state);
        try r.loaded.?.track(&r.verifier);
        state.phase = .tracking;
        try r.loaded.?.setState(state);
        try r.loaded.?.classifyExisting(&r.verifier);
        r.ring = try Ring.open(r.loaded.?.maps.ring);
        try peer.live();
        if (try r.loaded.?.tag(@intCast(peer.credentials.pid)) != 0) return error.TaggedCaller;
        try intent.writeHistory(r.gpa, r.io, &r.history, null);
        state.phase = .armed;
        try r.loaded.?.setState(state);
        try kernel.dropLoadCapabilities();
        try r.startProxyWorker();
        r.armed = true;
        var active = try r.loaded.?.getEpoch();
        active.fenced = 0;
        try r.loaded.?.setEpoch(active);
        r.failed_start = false;
        r.service_log.?.policy_id = &r.cfg.?.digest;
        var detail: [160]u8 = undefined;
        r.service_log.?.write(.{ .event = "app_filter_on", .point = .app_filter, .detail = try std.fmt.bufPrint(&detail, "caller_uid={d} caller_tgid={d}; pinned tracing; legacy user.slice attachments verified", .{ peer.credentials.uid, peer.credentials.pid }) });
    }
    fn restoreHistory(r: *Runtime, saved: intent.Intent) !void {
        for (saved.history[0..saved.generation], 1..) |hash, gen| {
            const path = try std.fmt.allocPrint(r.gpa, host.state_root ++ "/policy-{s}.json", .{hash});
            defer r.gpa.free(path);
            const bytes = try Io.Dir.cwd().readFileAlloc(r.io, path, r.gpa, .limited(config.max_bytes));
            defer r.gpa.free(bytes);
            const g = try r.history.prepare(bytes, null);
            if (!std.mem.eql(u8, &hash, &g.cfg.digest) or g.cfg.generation != gen) {
                r.history.discard(g);
                return error.StoredPolicyMismatch;
            }
            r.history.publish(g);
        }
        const current = r.history.generations[r.history.count - 1].?;
        var retired: u8 = 0;
        for (&current.snapshot.slots, 0..) |*slot, i| if (slot.*) |*b| {
            if (b.active) {
                b.identity = try r.identity(b.executable);
            } else {
                retired |= @as(u8, 1) << @as(u3, @intCast(i));
                const saved_identity = saved.identities[i] orelse return error.MissingRetiredIdentity;
                b.identity = .{ .device = saved_identity.device, .inode = saved_identity.inode };
            }
        };
        if (retired != saved.retired_slots) return error.RetiredSlotMismatch;
        r.cfg = &current.cfg;
        r.history.blocked_retired = retired; // Only slots already retired at this restart.
    }
    const Recovery = struct { record: intent.Pending, settled: intent.Settled };
    fn pendingAtRestart(r: *Runtime) !?Recovery {
        const record = (try intent.pendingRead(r.gpa, r.io)) orelse return null;
        return .{ .record = record, .settled = try intent.settleAtRestart(record, &try intent.bootId(), r.cfg.?.generation, &r.cfg.?.digest) };
    }
    fn recoveryReceipt(r: *Runtime, pending: ?Recovery) !void {
        const found = pending orelse return;
        r.writeSettled(&found.record, found.settled);
        try intent.pendingClear(r.io);
    }
    /// `on` and `off` end the arming a pending record belongs to, so they settle it, never a later restart.
    /// An unreadable record is settled too: it must not block `off`.
    fn settlePending(r: *Runtime) !void {
        const boot = try intent.bootId();
        const record = intent.pendingRead(r.gpa, r.io) catch {
            r.writeSettled(null, intent.unreadable);
            return intent.pendingClear(r.io);
        };
        if (record) |found| {
            r.writeSettled(&found, intent.settleAtArmingChange(found, &boot));
            try intent.pendingClear(r.io);
        }
    }
    fn writeSettled(r: *Runtime, record: ?*const intent.Pending, settled: intent.Settled) void {
        r.service_log.?.write(.{ .event = settled.event, .point = .app_filter, .reason = settled.reason, .old_policy = if (record) |p| &p.old_policy else null, .new_policy = if (record) |p| &p.new_policy else null, .detail = settled.detail });
    }
    fn request(r: *Runtime, client: l.fd_t) !bool {
        r.reload_failure = null;
        const peer = try ipc.Peer.open(client, r.install.owner_uid);
        defer peer.close();
        if (r.loaded) |*f| if (try f.tag(@intCast(peer.credentials.pid)) != 0) return error.TaggedCaller;
        var raw: [8]u8 = undefined;
        try ipc.readExact(client, &raw, 5000);
        const header = try ipc.decodeHeader(&raw);
        switch (header.op) {
            .status => {
                const saved = if (!r.armed and !r.stopping) try intent.read(r.gpa, r.io) else null;
                const boot = try intent.bootId();
                const label = if (r.stopping) "stopping_partial" else if (r.armed) "armed" else intent.absentPinsStatus(saved, &boot);
                var response: [320]u8 = undefined;
                var untagged: u8 = 0;
                for (r.added_running, 0..) |tgid, i| if (tgid != 0) {
                    untagged |= @as(u8, 1) << @as(u3, @intCast(i));
                };
                try sys.writeAll(client, try std.fmt.bufPrint(&response, "OK {s} gen={d} ring_dropped={d} write_dropped={d} receipt_file_limit=8388608 reload=experimental_vm_only added_app_running_untagged={d}\n", .{ label, if (r.cfg) |cfg| cfg.generation else @as(u32, 0), r.reported_loss, r.writeLoss(), untagged }));
                return r.armed or r.stopping;
            },
            .off => {
                if (r.armed or r.stopping) {
                    try polkit.authorize(peer);
                    if (try r.loaded.?.tag(@intCast(peer.credentials.pid)) != 0) return error.TaggedCaller;
                    var state = try r.loaded.?.getState();
                    state.phase = .stopping;
                    try r.loaded.?.setState(state);
                    r.stopping = true;
                    // Test only: exercise a partial off before teardown. The
                    // default build contains no selector read or interruption.
                    if (faults.enabled and try faults.read() == .off_stopping) return error.VMOffStopping;
                    r.closeListeners();
                    try r.loaded.?.detach(r.cg, r.root_cg);
                    try kernel.unpinAll();
                    try intent.write(r.gpa, r.io, false, &r.cfg.?.digest);
                    r.armed = false;
                    r.stopping = false;
                    var detail: [80]u8 = undefined;
                    r.service_log.?.write(.{ .event = "app_filter_off", .point = .app_filter, .reason = "owner_authorized", .detail = try std.fmt.bufPrint(&detail, "caller_uid={d} caller_tgid={d}", .{ peer.credentials.uid, peer.credentials.pid }) });
                } else if (try intent.read(r.gpa, r.io)) |saved| {
                    if (saved.armed) {
                        try polkit.authorize(peer);
                        try intent.write(r.gpa, r.io, false, &saved.policy);
                    }
                }
                // The filter is off at this point; a record that cannot be cleared is reported, and the next
                // `on` settles it before arming.
                r.settlePending() catch |err| r.service_log.?.write(.{ .event = "warning", .point = .app_filter, .reason = "pending_record_not_cleared", .detail = @errorName(err) });
                try sys.writeAll(client, "OK off\n");
                return false;
            },
            .on => {
                if (r.stopping) return error.OffIncomplete;
                const bytes = try r.gpa.alloc(u8, header.length);
                defer r.gpa.free(bytes);
                try ipc.readExact(client, bytes, 5000);
                try peer.live();
                if (r.armed) {
                    var replacement = try config.Config.parse(r.gpa, bytes);
                    defer replacement.deinit();
                    if (!std.mem.eql(u8, &replacement.digest, &r.cfg.?.digest)) {
                        // A new app set changes identity IDs. v0 requires an explicitly authorized off/on.
                        // No partial update can reassign the policy of an existing tagged descendant.
                        return error.PolicyChangeRequiresAuthorizedOff;
                    }
                } else try r.start(bytes, peer);
                try sys.writeAll(client, "OK armed\n");
                return true;
            },
            .reload => {
                return r.reloadRequest(client, peer, header.length) catch |err| {
                    if (r.reload_failure) |*failure| {
                        reload_receipts.failed(&r.service_log.?, failure, if (err == error.ProxyRefused) "proxy_refused" else @errorName(err));
                    } else reload_receipts.refused(&r.service_log.?, if (r.cfg) |cfg| .{ .policy = &cfg.digest, .generation = cfg.generation } else null, @errorName(err));
                    return err;
                };
            },
        }
    }
    fn reloadRequest(r: *Runtime, client: l.fd_t, peer: ipc.Peer, length: u32) !bool {
        if (r.stopping) return error.Stopping;
        if (!r.armed) return error.NotArmed;
        if (r.changing) return error.ChangeInProgress;
        r.changing = true;
        r.refuse_stop.store(false, .release);
        const refuser = std.Thread.spawn(.{}, refuseChanges, .{r}) catch |err| {
            r.changing = false;
            return err;
        };
        var refuser_joined = false;
        defer {
            if (!refuser_joined) {
                r.refuse_stop.store(true, .release);
                refuser.join();
            }
            r.changing = false;
        }
        const bytes = try r.gpa.alloc(u8, length);
        defer r.gpa.free(bytes);
        try ipc.readExact(client, bytes, 5000);
        try peer.live();
        var candidate = try config.Config.parseReload(r.gpa, bytes);
        defer candidate.deinit();
        if (r.cfg.?.generation >= config.max_generations) return error.GenerationLimit;
        if (candidate.generation != r.cfg.?.generation + 1) return error.ExpectedNextGeneration;
        if (try r.loaded.?.tag(@intCast(peer.credentials.pid)) != 0) return error.TaggedCaller;
        try @import("reload_control.zig").authorize(peer);
        try peer.live();
        if (try r.loaded.?.tag(@intCast(peer.credentials.pid)) != 0) return error.TaggedCaller;
        var identities: [abi.max_apps]abi.FileKey = undefined;
        for (candidate.apps, 0..) |app, i| identities[i] = try r.identity(app.executable);
        const next = try r.history.prepare(bytes, identities[0..candidate.apps.len]);
        var published = false;
        defer if (!published) {
            r.history.discard(next);
            r.configureChecks() catch {
                r.failed_start = true;
            };
        };
        const previous = r.history.head.load(.acquire).?;
        var activation_detail: [16384]u8 = undefined;
        const detail = try reload_receipts.activationDetail(&activation_detail, &previous.snapshot, &next.snapshot);
        try r.loaded.?.clearChecks();
        for (next.snapshot.slots, 0..) |slot, i| if (slot) |b| {
            if (b.active) try r.loaded.?.checkFile(b.identity, @intCast(i + 1));
        };
        const running = try r.loaded.?.scanExisting();
        for (running, 0..) |tgid, i| if (tgid != 0 and previous.snapshot.slots[i] == null) return error.CloseAddedAppsFirst;
        const fault = try faults.read();
        try faults.pause(fault, .after_validation);
        try host.writePolicy(r.gpa, r.io, &next.cfg.digest, bytes);
        try intent.pendingWrite(r.gpa, r.io, .{ .generation = next.cfg.generation, .old_policy = previous.cfg.digest, .new_policy = next.cfg.digest });
        // From this point any failed stage/ACK/disk write terminates the service.
        // Pins/tags survive; startup reconciles to durable intent with admission fenced.
        var stop_on_error = true;
        // A failure from here on is recorded by request() as policy_change_failed with how far the change got,
        // never as refused.
        var progress: reload_receipts.Progress = .pending;
        errdefer r.reload_failure = .{ .progress = progress, .old_generation = previous.cfg.generation, .new_generation = next.cfg.generation, .old_policy = previous.cfg.digest, .new_policy = next.cfg.digest, .restarting = stop_on_error };
        errdefer if (stop_on_error) {
            r.failed_start = true;
            r.closeListeners();
        };
        try faults.announce(fault);
        const deadline = try channel.Deadline.start();
        const stamp = next.snapshot.stamp;
        if (faults.enabled and (fault == .stop_child or fault == .kill_child))
            _ = try sys.check(l.pidfd_send_signal(r.worker_fd, if (fault == .stop_child) .STOP else .KILL, null, 0));
        const worker_bytes: []const u8 = if (faults.enabled and fault == .invalid_policy) "{" else bytes;
        channel.exchange(r.policy_write, r.policy_read, deadline, .{ .command = .prepare, .stamp = stamp, .length = @intCast(worker_bytes.len) }, worker_bytes, .prepared) catch |err| {
            if (err == error.ProxyRefused) {
                try intent.pendingClear(r.io);
                stop_on_error = false;
            }
            return err;
        };
        try faults.pause(fault, .after_prepare);
        var maps = r.loaded.?.generationMaps();
        const image = try reload_maps.Image.fromSnapshot(r.install.owner_uid, &next.snapshot);
        const staged = try reload_maps.stage(&maps, &image);
        try faults.pause(fault, .after_stage);
        var active = try r.loaded.?.getEpoch();
        active.fenced = 1;
        try r.loaded.?.setEpoch(active);
        try channel.exchange(r.policy_write, r.policy_read, deadline, .{ .command = .quiesce, .stamp = stamp, .length = 0 }, "", .quiesced);
        progress = .committing;
        try intent.writeHistory(r.gpa, r.io, &r.history, next);
        progress = .committed;
        try faults.pause(fault, .after_intent);
        try reload_maps.publishFenced(&maps, staged);
        try channel.exchange(r.policy_write, r.policy_read, deadline, .{ .command = .activate, .stamp = stamp, .length = 0 }, "", .activated);
        r.history.publish(next);
        published = true;
        r.cfg = &next.cfg;
        r.service_log.?.policy_id = &next.cfg.digest;
        r.service_log.?.generation = next.cfg.generation;
        try reload_receipts.activated(&r.service_log.?, .{ .policy = &previous.cfg.digest, .generation = previous.cfg.generation }, .{ .policy = &next.cfg.digest, .generation = next.cfg.generation }, detail);
        try channel.exchange(r.policy_write, r.policy_read, deadline, .{ .command = .resume_admission, .stamp = stamp, .length = 0 }, "", .resumed);
        active = try r.loaded.?.getEpoch();
        active.fenced = 0;
        try r.loaded.?.setEpoch(active);
        try r.refreshWatchedFiles();
        try r.scanWarnings();
        try intent.pendingClear(r.io);
        // A request sent immediately after OK must see a finished transaction.
        r.refuse_stop.store(true, .release);
        refuser.join();
        refuser_joined = true;
        var response: [160]u8 = undefined;
        sys.writeAll(client, try std.fmt.bufPrint(&response, "OK reloaded gen={d} policy={s}\n", .{ next.cfg.generation, next.cfg.digest })) catch {};
        return true;
    }
    fn configureChecks(r: *Runtime) !void {
        try r.loaded.?.clearChecks();
        for (r.history.head.load(.acquire).?.snapshot.slots, 0..) |slot, i| if (slot) |b| {
            if (b.active) try r.loaded.?.checkFile(try r.identity(b.executable), @intCast(i + 1));
        };
    }
    fn scanWarnings(r: *Runtime) !void {
        const running = try r.loaded.?.scanExisting();
        for (running, 0..) |tgid, i| {
            if (r.added_pidfds[i] >= 0) {
                var fds = [_]l.pollfd{.{ .fd = r.added_pidfds[i], .events = l.POLL.IN, .revents = 0 }};
                if (try sys.poll(&fds, 0) == 0) continue; // remains flagged even after exec-away
                sys.close(r.added_pidfds[i]);
                r.added_pidfds[i] = -1;
                r.added_running[i] = 0;
            }
            if (tgid == 0) continue;
            const fd = sys.fd(l.pidfd_open(@intCast(tgid), 0)) catch continue; // it may have exited
            const again = try r.loaded.?.scanExisting();
            if (again[i] != tgid) {
                sys.close(fd);
                continue;
            }
            r.added_pidfds[i] = fd;
            r.added_running[i] = tgid;
            const b = r.history.head.load(.acquire).?.snapshot.slots[i] orelse continue;
            var detail: [128]u8 = undefined;
            r.service_log.?.write(.{ .event = "policy_change_warning", .point = .app_filter, .reason = "added_app_running_untagged", .executable = b.executable, .app_id = @intCast(i + 1), .detail = try std.fmt.bufPrint(&detail, "tgid={d}; close this process; descendants may be untagged", .{tgid}) });
        }
    }
    fn refuseChanges(r: *Runtime) void {
        // Dedicated acceptor only while the sole state writer is in a reload.
        // It never parses policy, calls polkit, changes a map or changes state.
        while (!r.refuse_stop.load(.acquire)) {
            var fds = [_]l.pollfd{.{ .fd = 3, .events = l.POLL.IN, .revents = 0 }};
            if ((sys.poll(&fds, 25) catch return) == 0) continue;
            const client = sys.fd(l.accept4(3, null, null, l.SOCK.CLOEXEC | l.SOCK.NONBLOCK)) catch continue;
            defer sys.close(client);
            const peer = ipc.Peer.open(client, r.install.owner_uid) catch continue;
            defer peer.close();
            const tagged = if (r.loaded) |*loaded| (loaded.tag(@intCast(peer.credentials.pid)) catch 1) != 0 else false;
            sys.writeAll(client, if (tagged) "ERROR TaggedCaller\n" else "ERROR ChangeInProgress\n") catch {};
            const current = r.history.head.load(.acquire).?;
            r.service_log.?.write(.{ .event = "policy_change_refused", .point = .app_filter, .verdict = .deny, .reason = if (tagged) "TaggedCaller" else "ChangeInProgress", .decision = .{ .policy = &current.cfg.digest, .generation = current.cfg.generation } });
        }
    }
    fn drain(r: *Runtime) !void {
        if (r.ring) |*ring| {
            // Bound each batch so a flood cannot starve owner control.
            for (0..1024) |_| {
                const event = try ring.next() orelse break;
                const generation = event.reserved[0];
                if (generation == 0 or generation > r.history.count) return error.InvalidEventGeneration;
                if (event.reason == .udp_connect and event.app_id <= abi.max_apps) {
                    r.udp_connect[event.app_id].addGeneration(event, generation) catch |err| {
                        if (err != error.GenerationBoundary) return err;
                        r.flushUdp();
                        try r.udp_connect[event.app_id].addGeneration(event, generation);
                    };
                    continue;
                }
                const binding = r.history.decision(generation, event.app_id);
                const log = if (event.app_id > 0 and event.app_id <= abi.max_apps) &r.logs[event.app_id - 1].? else &r.service_log.?;
                const decision: receipt.Decision = if (binding) |b| b.decision else .{ .policy = &r.history.generations[generation - 1].?.cfg.digest, .generation = generation };
                var ipbuf: [64]u8 = undefined;
                const ipv4 = event.family == 2 or event.hook == @backingInt(l.BPF.AttachType.cgroup_udp4_sendmsg);
                const ip = if (ipv4) proxy.formatIp(&ipbuf, .{ .ip4 = .{ .bytes = event.ip[0..4].*, .port = 0 } }) else proxy.formatIp(&ipbuf, .{ .ip6 = .{ .bytes = event.ip, .port = 0, .interface = .none } });
                var detail: [160]u8 = undefined;
                log.write(.{ .event = "kernel_drop", .point = .app_filter, .verdict = .deny, .reason = @tagName(event.reason), .decision = decision, .executable = if (binding) |b| b.executable else null, .app_id = event.app_id, .ip = if (event.port != 0) ip else null, .port = if (event.port != 0) std.mem.bigToNative(u16, @truncate(event.port)) else null, .detail = try std.fmt.bufPrint(&detail, "tgid={d} family={d} protocol={d} hook={d} kernel_monotonic_ns={d}", .{ event.tgid, event.family, event.protocol, event.hook, event.timestamp_ns }) });
            }
            const loss = try r.loaded.?.loss();
            if (loss != r.reported_loss) {
                var b: [64]u8 = undefined;
                r.service_log.?.write(.{ .event = "receipt_loss", .point = .app_filter, .reason = "ring_full", .detail = try std.fmt.bufPrint(&b, "total={d}", .{loss}) });
                r.reported_loss = loss;
            }
        }
        const now = Io.Clock.awake.now(r.io).nanoseconds;
        if (now - r.udp_flushed_ns >= std.time.ns_per_s) {
            if (r.armed) try r.scanWarnings();
            r.flushUdp();
            r.udp_flushed_ns = now;
        }
        const write_loss = r.writeLoss();
        if (write_loss != r.reported_write_loss) {
            var b: [80]u8 = undefined;
            r.service_log.?.write(.{ .event = "receipt_loss", .point = .app_filter, .reason = "write_failed_or_file_limit", .detail = try std.fmt.bufPrint(&b, "total={d}; see status if this receipt cannot be written", .{write_loss}) });
            r.reported_write_loss = r.writeLoss();
        }
    }
    fn flushUdp(r: *Runtime) void {
        for (&r.udp_connect, 0..) |*batch, id| {
            if (batch.empty()) continue;
            const log = if (id != 0 and r.logs[id - 1] != null) &r.logs[id - 1].? else if (r.service_log != null) &r.service_log.? else continue;
            var detail: [192]u8 = undefined;
            const binding = r.history.decision(batch.generation, @intCast(id));
            const decision: ?receipt.Decision = if (binding) |b| b.decision else if (batch.generation > 0 and batch.generation <= r.history.count) .{ .policy = &r.history.generations[batch.generation - 1].?.cfg.digest, .generation = batch.generation } else null;
            log.write(.{ .event = "kernel_drop", .point = .app_filter, .verdict = .deny, .reason = "udp_connect", .decision = decision, .executable = if (binding) |b| b.executable else null, .app_id = @intCast(id), .detail = std.fmt.bufPrint(&detail, "aggregate; ipv4={d} ipv6={d} first_kernel_ns={d} last_kernel_ns={d}", .{ batch.ipv4, batch.ipv6, batch.first_ns, batch.last_ns }) catch unreachable });
            batch.* = .{};
        }
    }
    fn writeLoss(r: *Runtime) u64 {
        var total = if (r.service_log) |*log| log.droppedCount() else 0;
        for (&r.logs) |*log| if (log.*) |*value| {
            total +|= value.droppedCount();
        };
        if (r.proxy_stats) |stats| for (&stats.failures) |*count| {
            total +|= count.load(.acquire);
        };
        return total;
    }
};
