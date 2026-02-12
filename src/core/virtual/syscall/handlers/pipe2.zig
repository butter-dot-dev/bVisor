const std = @import("std");
const linux = std.os.linux;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Passthrough = @import("../../fs/backend/passthrough.zig").Passthrough;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
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
    const errno = linux.errno(rc);
    if (errno != .SUCCESS) {
        logger.log("pipe2: kernel pipe2 failed: {s}", .{@tagName(errno)});
        return replyErr(notif.id, errno);
    }

    // Wrap both ends as passthrough Files
    const read_file = File.init(allocator, .{ .passthrough = .{ .fd = kernel_fds[0] } }) catch {
        _ = std.posix.system.close(kernel_fds[0]);
        _ = std.posix.system.close(kernel_fds[1]);
        logger.log("pipe2: failed to alloc read File", .{});
        return replyErr(notif.id, .NOMEM);
    };

    const write_file = File.init(allocator, .{ .passthrough = .{ .fd = kernel_fds[1] } }) catch {
        read_file.unref(); // already closes kernel_fds[0] via Passthrough.close
        _ = std.posix.system.close(kernel_fds[1]);
        logger.log("pipe2: failed to alloc write File", .{});
        return replyErr(notif.id, .NOMEM);
    };

    // Register both in the caller's FdTable
    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        read_file.unref();
        write_file.unref();
        logger.log("pipe2: Thread not found for tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };

    const read_vfd = caller.fd_table.insert(read_file, .{ .cloexec = cloexec }) catch {
        read_file.unref();
        write_file.unref();
        logger.log("pipe2: failed to insert read fd", .{});
        return replyErr(notif.id, .MFILE);
    };

    const write_vfd = caller.fd_table.insert(write_file, .{ .cloexec = cloexec }) catch {
        _ = caller.fd_table.remove(read_vfd);
        read_file.unref();
        write_file.unref();
        logger.log("pipe2: failed to insert write fd", .{});
        return replyErr(notif.id, .MFILE);
    };

    // Write the virtual fds back to the caller's pipefd[2] array
    const vfds = [2]i32{ read_vfd, write_vfd };
    memory_bridge.write([2]i32, caller_tid, vfds, pipefd_ptr) catch |err| {
        _ = caller.fd_table.remove(read_vfd);
        _ = caller.fd_table.remove(write_vfd);
        read_file.unref();
        write_file.unref();
        logger.log("pipe2: failed to write fds to caller: {}", .{err});
        return replyErr(notif.id, .FAULT);
    };

    logger.log("pipe2: created pipe read_vfd={d} write_vfd={d}", .{ read_vfd, write_vfd });
    return replySuccess(notif.id, 0);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
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

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
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

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));

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

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}
