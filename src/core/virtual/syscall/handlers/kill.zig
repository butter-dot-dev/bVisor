const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../LinuxErr.zig").LinuxErr;
const checkErr = @import("../../../LinuxErr.zig").checkErr;
const Supervisor = @import("../../../Supervisor.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const LogBuffer = @import("../../../LogBuffer.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const AbsTgid = Thread.AbsTgid;
const NsTgid = Thread.NsTgid;
const Threads = @import("../../proc/Threads.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

// `kill` kills processes/thread groups specified by a namespaced TGID
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);
    const target_nstgid: NsTgid = @intCast(@as(i64, @bitCast(notif.data.arg0)));
    const signal: u6 = @truncate(notif.data.arg1);

    // Non-positive namespaced TGIDs not supported, for now
    // TODO: support all integer target PIDS
    if (target_nstgid <= 0) {
        return LinuxErr.INVAL;
    }

    // Critical section just to normalize target namespaced TGID to absolute
    var target_abstgid: AbsTgid = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        // Get caller Thread
        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            std.log.err("kill: Thread not found with tid={d}: {}", .{ caller_tid, err });
            return LinuxErr.SRCH;
        };
        std.debug.assert(caller.tid == caller_tid);

        // There may be *many* candidate Thread-s satisfying having namespaced TGID == target_nstgid.
        // But, we know there must be a group leader whose namespaced TID == target_nstgid
        const target_leader = supervisor.guest_threads.getNamespaced(caller, target_nstgid) catch |err| {
            std.log.err("kill: target Thread not found with tid={d}: {}", .{ target_nstgid, err });
            return LinuxErr.SRCH;
        };

        // Yield the targetted TGID in absolute terms
        target_abstgid = target_leader.get_tgid();
        std.debug.assert(target_abstgid == target_leader.tid);
    }

    // Execute real kill syscall outside the lock
    const rc = linux.kill(@intCast(target_abstgid), @enumFromInt(signal));
    try checkErr(rc, "", .{});

    // Do not remove from internal Threads tracking.
    // Killing a thread is just a signal invocation.
    // exit_group is what actually removes it from threads.

    return replySuccess(notif.id, 0);
}

test "kill with negative pid returns EINVAL" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = @as(u64, @bitCast(@as(i64, -1))), // -1 = all processes
        .arg1 = 9,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(if (resp) |_| false else |_| true);
    try testing.expectEqual(-@as(i32, @intFromEnum(linux.E.INVAL)), resp.@"error");
}

test "kill with zero pid returns EINVAL" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.kill, .{
        .pid = 100,
        .arg0 = 0, // process group
        .arg1 = 9,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(if (resp) |_| false else |_| true);
    try testing.expectEqual(-@as(i32, @intFromEnum(linux.E.INVAL)), resp.@"error");
}
