const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../LinuxErr.zig").LinuxErr;
const checkErr = @import("../../../LinuxErr.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;
    const allocator = supervisor.allocator;

    const caller_tid: AbsTid = @intCast(notif.pid);
    const domain: u32 = @truncate(notif.data.arg0);
    const sock_type: u32 = @truncate(notif.data.arg1);
    const protocol: u32 = @truncate(notif.data.arg2);

    const cloexec = sock_type & linux.SOCK.CLOEXEC != 0;

    // Create the kernel socket
    const rc = linux.socket(domain, sock_type, protocol);
    try checkErr(rc, "socket: kernel socket failed", .{});

    const kernel_fd: i32 = @intCast(rc);

    // Wrap as passthrough File
    const file = File.init(allocator, .{ .passthrough = .{ .fd = kernel_fd } }) catch {
        _ = linux.close(kernel_fd);
        logger.log("socket: failed to alloc File", .{});
        return LinuxErr.NOMEM;
    };

    // Register in the caller's FdTable
    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        file.unref();
        logger.log("socket: Thread not found for tid={d}: {}", .{ caller_tid, err });
        return LinuxErr.SRCH;
    };

    const vfd = caller.fd_table.insert(file, .{ .cloexec = cloexec }) catch {
        file.unref();
        logger.log("socket: failed to insert fd", .{});
        return LinuxErr.MFILE;
    };

    logger.log("socket: created vfd={d}", .{vfd});
    return replySuccess(notif.id, vfd);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

test "socket creates a virtual fd" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.socket, .{
        .pid = init_tid,
        .arg0 = linux.AF.UNIX,
        .arg1 = linux.SOCK.STREAM,
        .arg2 = 0,
    });

    const resp = try handle(notif, &supervisor);

    const vfd: i32 = @intCast(resp.val);
    try testing.expect(vfd >= 3);

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const file_ref = caller.fd_table.get_ref(vfd);
    defer if (file_ref) |f| f.unref();
    try testing.expect(file_ref != null);
}

test "socket with SOCK_CLOEXEC sets cloexec flag" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.socket, .{
        .pid = init_tid,
        .arg0 = linux.AF.UNIX,
        .arg1 = linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        .arg2 = 0,
    });

    const resp = try handle(notif, &supervisor);

    const vfd: i32 = @intCast(resp.val);
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    try testing.expect(caller.fd_table.getCloexec(vfd));
}

test "socket unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.socket, .{
        .pid = 999,
        .arg0 = linux.AF.UNIX,
        .arg1 = linux.SOCK.STREAM,
        .arg2 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(if (resp) |_| false else |_| true);
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}
