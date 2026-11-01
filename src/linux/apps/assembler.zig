//! Bounded instruction emitter following the task-scope filter's direct BPF emitter.
//! Kept separate so the reviewed task helper's inputs remain unchanged.
const std = @import("std");
pub const bpf = std.os.linux.BPF;
pub const I = bpf.Insn;
pub const Reg = I.Reg;

pub fn word(i: I) I {
    var result = i;
    result.code = (result.code & 0xf8) | 6;
    return result;
}

pub const Program = struct {
    code: [2048]I = undefined,
    len: usize = 0,

    pub fn add(p: *Program, i: I) usize {
        std.debug.assert(p.len < p.code.len);
        const at = p.len;
        p.code[at] = i;
        p.len += 1;
        return at;
    }
    pub fn emit(p: *Program, i: I) void {
        _ = p.add(i);
    }
    pub fn patch(p: *Program, at: usize, target: usize) void {
        std.debug.assert(target > at and target < p.len);
        p.code[at].off = @intCast(target - at - 1);
    }
    pub fn map(p: *Program, dst: Reg, fd: i32) void {
        p.emit(I.ld_map_fd1(dst, fd));
        p.emit(I.ld_map_fd2(fd));
    }
    pub fn stack(p: *Program, dst: Reg, off: i16) void {
        p.emit(I.mov(dst, .r10));
        p.emit(I.add(dst, off));
    }
    pub fn lookup(p: *Program, fd: i32, key: i16) void {
        p.map(.r1, fd);
        p.stack(.r2, key);
        p.emit(I.call(.map_lookup_elem));
    }
    pub fn update(p: *Program, fd: i32, key: i16, value: i16) void {
        p.map(.r1, fd);
        p.stack(.r2, key);
        p.stack(.r3, value);
        p.emit(I.mov(.r4, 0));
        p.emit(I.call(.map_update_elem));
    }
    pub fn ret(p: *Program, value: i32) void {
        p.emit(I.mov(.r0, value));
        p.emit(I.exit());
    }
};

/// Userspace analogue of the verifier's CFG phase. No BPF syscall is made.
pub fn validate(p: *const Program) !void {
    if (p.len == 0 or p.len > p.code.len) return error.InvalidProgram;
    var seen: [2048]bool = @splat(false);
    var continuation: [2048]bool = @splat(false);
    var pc: usize = 0;
    while (pc < p.len) : (pc += 1) {
        if (p.code[pc].code == 0x18) {
            if (pc + 1 >= p.len or p.code[pc + 1].code != 0) return error.InvalidLoad;
            pc += 1;
            continuation[pc] = true;
        }
    }
    var pending: [4096]usize = undefined;
    var n: usize = 1;
    pending[0] = 0;
    while (n > 0) {
        n -= 1;
        pc = pending[n];
        if (pc >= p.len or continuation[pc]) return error.InvalidTarget;
        if (seen[pc]) continue;
        seen[pc] = true;
        const insn = p.code[pc];
        if (insn.code == 0x95) continue;
        if ((insn.code & 7 == bpf.JMP or insn.code & 7 == 6) and insn.code != 0x85) {
            if (insn.off < 0) return error.BackEdge;
            const target = pc + 1 + @as(usize, @intCast(insn.off));
            if (target >= p.len or continuation[target]) return error.InvalidTarget;
            pending[n] = target;
            n += 1;
            if (insn.code == 0x05) continue;
        }
        const next = pc + @as(usize, if (insn.code == 0x18) 2 else 1);
        if (next >= p.len) return error.FallsOffEnd;
        pending[n] = next;
        n += 1;
    }
    for (0..p.len) |i| if (!seen[i] and !continuation[i]) return error.UnreachableInstruction;
}

test "appfilter CFG validator rejects dead returns, backward jumps and jumps into load data" {
    var p: Program = .{};
    p.ret(0);
    p.ret(1);
    try std.testing.expectError(error.UnreachableInstruction, validate(&p));
    p = .{};
    p.emit(I.ja(-1));
    p.ret(0);
    try std.testing.expectError(error.BackEdge, validate(&p));
    p = .{};
    p.emit(I.ja(1));
    p.map(.r1, 9);
    p.ret(0);
    try std.testing.expectError(error.InvalidTarget, validate(&p));
}
