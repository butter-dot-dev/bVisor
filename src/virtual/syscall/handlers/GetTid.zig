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

/// For now, return pid as tid. This is correct for single-threaded processes
/// where tid == pid. Multi-threaded support would need per-thread tracking.
pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const proc = supervisor.virtual_procs.get(self.kernel_pid) catch
        return Result.reply_err(.SRCH);
    return Result.reply_success(@intCast(proc.pid));
}

test "gettid returns kernel pid for main thread" {
    const allocator = testing.allocator;
    const kernel_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, -1, kernel_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.gettid, .{ .pid = kernel_pid });
    const parsed = Self.parse(notif);

    const res = try parsed.handle(&supervisor);
    try testing.expect(!res.is_error());
    // For main thread, tid == pid
    try testing.expectEqual(@as(i64, kernel_pid), res.reply.val);
}
