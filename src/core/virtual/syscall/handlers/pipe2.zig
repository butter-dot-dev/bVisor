const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Passthrough = @import("../../fs/backend/passthrough.zig").Passthrough;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;
    const allocator = supervisor.allocator;

    // Parse args: pipe2(pipefd[2], flags)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const pipefd_ptr: u64 = notif.data.arg0;
    const flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg1)));
    const cloexec = flags.CLOEXEC;

    // Create the kernel pipe
    var kernel_fds: [2]i32 = undefined;
    const rc = linux.pipe2(&kernel_fds, @bitCast(flags));
    try checkErr(rc, "pipe2: kernel pipe2 failed", .{});

    // Wrap both ends as passthrough Files
    const read_file = try File.init(allocator, .{ .passthrough = .{ .fd = kernel_fds[0] } });
    errdefer read_file.unref();

    const write_file = try File.init(allocator, .{ .passthrough = .{ .fd = kernel_fds[1] } });
    errdefer write_file.unref();

    // Register both in the caller's FdTable
    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = try supervisor.guest_threads.get(caller_tid);

    const read_vfd = try caller.fd_table.insert(read_file, .{ .cloexec = cloexec });
    errdefer _ = caller.fd_table.remove(read_vfd);

    const write_vfd = try caller.fd_table.insert(write_file, .{ .cloexec = cloexec });
    errdefer _ = caller.fd_table.remove(write_vfd);

    // Write the virtual fds back to the caller's pipefd[2] array
    const vfds = [2]i32{ read_vfd, write_vfd };
    try memory_bridge.write([2]i32, caller_tid, vfds, pipefd_ptr);

    logger.log("pipe2: created pipe read_vfd={d} write_vfd={d}", .{ read_vfd, write_vfd });
    return replySuccess(notif.id, 0);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

test "pipe2 creates two virtual fds and writes them back" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // pipefd array in our local memory (TestingMemoryBridge treats addr as local ptr)
    var pipefd: [2]i32 = .{ -1, -1 };

    const notif = makeNotif(.pipe2, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(&pipefd),
        .arg1 = 0,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Both vfds should be >= 3
    try testing.expect(pipefd[0] >= 3);
    try testing.expect(pipefd[1] >= 3);
    try testing.expect(pipefd[0] != pipefd[1]);

    // Both should exist in the FdTable
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const read_ref = caller.fd_table.get_ref(pipefd[0]);
    defer if (read_ref) |f| f.unref();
    try testing.expect(read_ref != null);

    const write_ref = caller.fd_table.get_ref(pipefd[1]);
    defer if (write_ref) |f| f.unref();
    try testing.expect(write_ref != null);
}

test "pipe2 with O_CLOEXEC sets cloexec flag" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var pipefd: [2]i32 = .{ -1, -1 };

    const notif = makeNotif(.pipe2, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(&pipefd),
        .arg1 = @as(u32, @bitCast(@as(linux.O, .{ .CLOEXEC = true }))),
    });

    _ = try handle(notif, &supervisor);

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    try testing.expect(caller.fd_table.getCloexec(pipefd[0]));
    try testing.expect(caller.fd_table.getCloexec(pipefd[1]));
}

test "pipe2 unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var pipefd: [2]i32 = .{ -1, -1 };

    const notif = makeNotif(.pipe2, .{
        .pid = 999,
        .arg0 = @intFromPtr(&pipefd),
        .arg1 = 0,
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}
