const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const NsTgid = Thread.NsTgid;
const Threads = @import("../../proc/Threads.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;

// `kill` kills processes/thread groups specified by a TGID
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_tid: AbsTid = @intCast(notif.pid);
    const target_tgid: NsTgid = @intCast(@as(i64, @bitCast(notif.data.arg0)));
    const signal: u6 = @truncate(notif.data.arg1);

    // Non-positive TGIDs not supported, for now
    // TODO: support all integer target PIDS
    if (target_tgid <= 0) {
        return replyErr(notif.id, .INVAL);
    }

    const caller = supervisor.guest_procs.get(caller_tid) catch |err| {
        std.log.err("kill: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };

    // There may be *many* candidate Thread-s satisfying `candidate.getTgid() == target_tgid`
    // But, we know there must be a thread group leader with `candidate.tid == target_tgid`
    const target_group_leader = supervisor.guest_threads.getNamespaced(caller, target_tgid) catch |err| {
        std.log.err("kill: target Thread not found with tid={d}: {}", .{ target_tgid, err });
        return replyErr(notif.id, .SRCH);
    };

    // Check the group leader invariant
    if (target_group_leader.get_tgid() != target_tgid) unreachable;

    // Execute real kill syscall
    const sig: posix.SIG = @enumFromInt(signal);
    posix.kill(@intCast(target_tgid), sig) catch |err| {
        const errno: linux.E = switch (err) {
            error.PermissionDenied => .PERM,
            error.ProcessNotFound => .SRCH,
            else => .INVAL,
        };
        return replyErr(notif.id, errno);
    };

    return replySuccess(notif.id, 0);
}

test "kill with negative pid returns EINVAL" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = @as(u64, @bitCast(@as(i64, -1))), // -1 = all processes
        .arg1 = 9,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intFromEnum(linux.E.INVAL)), resp.@"error");
}

test "kill with zero pid returns EINVAL" {
    const allocator = testing.allocator;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, 100);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = 0, // process group
        .arg1 = 9,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intFromEnum(linux.E.INVAL)), resp.@"error");
}
