const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;
    const allocator = supervisor.allocator;

    const caller_tid: AbsTid = @intCast(notif.pid);
    const domain: u32 = @truncate(notif.data.arg0);
    const sock_type: u32 = @truncate(notif.data.arg1);
    const protocol: u32 = @truncate(notif.data.arg2);
    const sv_ptr: u64 = notif.data.arg3;

    const cloexec = sock_type & linux.SOCK.CLOEXEC != 0;

    // Create the kernel socket pair
    var kernel_fds: [2]i32 = undefined;
    const rc = linux.socketpair(domain, sock_type, protocol, &kernel_fds);
    try checkErr(rc, "socketpair: kernel socketpair failed", .{});

    // Wrap both ends as passthrough Files
    const file0 = try File.init(allocator, .{ .passthrough = .{ .fd = kernel_fds[0] } });
    errdefer file0.unref();

    const file1 = try File.init(allocator, .{ .passthrough = .{ .fd = kernel_fds[1] } });
    errdefer file1.unref();

    // Register both in the caller's FdTable
    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    const caller = try supervisor.guest_threads.get(caller_tid);

    const vfd0 = try caller.fd_table.insert(file0, .{ .cloexec = cloexec });
    errdefer _ = caller.fd_table.remove(vfd0);

    const vfd1 = try caller.fd_table.insert(file1, .{ .cloexec = cloexec });
    errdefer _ = caller.fd_table.remove(vfd1);

    // Write the virtual fds back to the caller's sv[2] array
    const vfds = [2]i32{ vfd0, vfd1 };
    try memory_bridge.write([2]i32, caller_tid, vfds, sv_ptr);

    logger.log("socketpair: created vfd0={d} vfd1={d}", .{ vfd0, vfd1 });
    return replySuccess(notif.id, 0);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

test "socketpair creates two virtual fds and writes them back" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var sv: [2]i32 = .{ -1, -1 };

    const notif = makeNotif(.socketpair, .{
        .pid = init_tid,
        .arg0 = linux.AF.UNIX,
        .arg1 = linux.SOCK.STREAM,
        .arg2 = 0,
        .arg3 = @intFromPtr(&sv),
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Both vfds should be >= 3
    try testing.expect(sv[0] >= 3);
    try testing.expect(sv[1] >= 3);
    try testing.expect(sv[0] != sv[1]);

    // Both should exist in the FdTable
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const ref0 = caller.fd_table.get_ref(sv[0]);
    defer if (ref0) |f| f.unref();
    try testing.expect(ref0 != null);

    const ref1 = caller.fd_table.get_ref(sv[1]);
    defer if (ref1) |f| f.unref();
    try testing.expect(ref1 != null);
}

test "socketpair with SOCK_CLOEXEC sets cloexec flag" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var sv: [2]i32 = .{ -1, -1 };

    const notif = makeNotif(.socketpair, .{
        .pid = init_tid,
        .arg0 = linux.AF.UNIX,
        .arg1 = linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        .arg2 = 0,
        .arg3 = @intFromPtr(&sv),
    });

    _ = try handle(notif, &supervisor);

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    try testing.expect(caller.fd_table.getCloexec(sv[0]));
    try testing.expect(caller.fd_table.getCloexec(sv[1]));
}

test "socketpair unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var sv: [2]i32 = .{ -1, -1 };

    const notif = makeNotif(.socketpair, .{
        .pid = 999,
        .arg0 = linux.AF.UNIX,
        .arg1 = linux.SOCK.STREAM,
        .arg2 = 0,
        .arg3 = @intFromPtr(&sv),
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}
