const std = @import("std");
const linux = std.os.linux;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../../../Supervisor.zig");
const Proc = @import("../../proc/Proc.zig");
const Procs = @import("../../proc/Procs.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

const Self = @This();

kernel_pid: Proc.KernelPID,

pub fn parse(notif: linux.SECCOMP.notif) Self {
    return .{ .kernel_pid = @intCast(notif.pid) };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const proc = supervisor.virtual_procs.get(self.kernel_pid) catch |err| {
        // getpid() never fails in the kernel - if we can't find the process,
        // it's a supervisor invariant violation
        std.debug.panic("getpid: supervisor invariant violated - kernel pid {d} not in virtual_procs: {}", .{ self.kernel_pid, err });
    };
    return Result.replySuccess(@intCast(proc.pid));
}

test "getpid returns kernel pid" {
    const allocator = testing.allocator;
    const kernel_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, kernel_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.getpid, .{ .pid = kernel_pid });
    const parsed = Self.parse(notif);

    try testing.expectEqual(kernel_pid, parsed.kernel_pid);

    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .reply);
    try testing.expect(!res.isError());
    // Returns actual kernel PID
    try testing.expectEqual(@as(i64, kernel_pid), res.reply.val);
}

test "getpid for child process returns child kernel pid" {
    const allocator = testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_pid);
    defer supervisor.deinit();

    // Add a child process
    const child_pid: Proc.KernelPID = 200;
    const parent = supervisor.virtual_procs.lookup.get(init_pid).?;
    _ = try supervisor.virtual_procs.registerChild(parent, child_pid, Procs.CloneFlags.from(0));

    // Child calls getpid
    const notif = makeNotif(.getpid, .{ .pid = child_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(!res.isError());
    try testing.expectEqual(@as(i64, child_pid), res.reply.val);
}
