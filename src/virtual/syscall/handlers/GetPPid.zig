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
        // getppid() never fails in the kernel - if we can't find the process,
        // it's a supervisor invariant violation
        std.debug.panic("getppid: supervisor invariant violated - kernel pid {d} not in virtual_procs: {}", .{ self.kernel_pid, err });
    };

    // Return parent's kernel PID, or 0 if:
    // - No parent (sandbox root)
    // - Parent not visible (e.g., in CLONE_NEWPID case where parent is in different namespace)
    const ppid: Proc.KernelPID = if (proc.parent) |p|
        if (proc.can_see(p)) p.pid else 0
    else
        0;

    return Result.reply_success(@intCast(ppid));
}

test "getppid for init process returns 0" {
    const allocator = testing.allocator;
    const kernel_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, -1, kernel_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.getppid, .{ .pid = kernel_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(!res.is_error());
    try testing.expectEqual(@as(i64, 0), res.reply.val);
}

test "getppid for child process returns parent kernel pid" {
    const allocator = testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, init_pid);
    defer supervisor.deinit();

    // Add a child process
    const child_pid: Proc.KernelPID = 200;
    const parent = supervisor.virtual_procs.lookup.get(init_pid).?;
    _ = try supervisor.virtual_procs.register_child(parent, child_pid, Procs.CloneFlags.from(0));

    // Child calls getppid
    const notif = makeNotif(.getppid, .{ .pid = child_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(!res.is_error());
    // Parent kernel PID
    try testing.expectEqual(@as(i64, init_pid), res.reply.val);
}

test "getppid for grandchild returns parent kernel pid" {
    const allocator = testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, init_pid);
    defer supervisor.deinit();

    // Create: init(100) -> child(200) -> grandchild(300)
    const child_pid: Proc.KernelPID = 200;
    const parent = supervisor.virtual_procs.lookup.get(init_pid).?;
    _ = try supervisor.virtual_procs.register_child(parent, child_pid, Procs.CloneFlags.from(0));

    const grandchild_pid: Proc.KernelPID = 300;
    const child = supervisor.virtual_procs.lookup.get(child_pid).?;
    _ = try supervisor.virtual_procs.register_child(child, grandchild_pid, Procs.CloneFlags.from(0));

    // Grandchild calls getppid
    const notif = makeNotif(.getppid, .{ .pid = grandchild_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(!res.is_error());
    // Parent (child) kernel PID
    try testing.expectEqual(@as(i64, child_pid), res.reply.val);
}

test "getppid for CLONE_NEWPID child returns 0" {
    const allocator = testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, init_pid);
    defer supervisor.deinit();

    // Child in new namespace
    const child_pid: Proc.KernelPID = 200;
    const parent = supervisor.virtual_procs.lookup.get(init_pid).?;
    _ = try supervisor.virtual_procs.register_child(parent, child_pid, Procs.CloneFlags.from(linux.CLONE.NEWPID));

    // Child calls getppid - parent is not visible in child's namespace
    const notif = makeNotif(.getppid, .{ .pid = child_pid });
    const parsed = Self.parse(notif);
    const res = try parsed.handle(&supervisor);

    try testing.expect(!res.is_error());
    // Parent not visible, returns 0
    try testing.expectEqual(@as(i64, 0), res.reply.val);
}
