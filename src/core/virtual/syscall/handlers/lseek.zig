const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: lseek(fd, offset, whence)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const offset: i64 = @bitCast(notif.data.arg1);
    const whence: u32 = @truncate(notif.data.arg2);

    // stdin/stdout/stderr are not seekable
    if (fd == linux.STDIN_FILENO or fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        return LinuxErr.SPIPE;
    }

    // Critical section: File lookup
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        // Get caller Thread
        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            logger.log("lseek: Thread not found for tid={d}: {}", .{ caller_tid, err });
            return LinuxErr.SRCH;
        };
        std.debug.assert(caller.tid == caller_tid);

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("lseek: EBADF for fd={d}", .{fd});
            return LinuxErr.BADF;
        };
    }
    defer file.unref();

    const new_offset = file.lseek(offset, whence) catch |err| {
        logger.log("lseek: error for fd={d}: {s}", .{ fd, @errorName(err) });
        return LinuxErr.INVAL;
    };

    logger.log("lseek: fd={d} new_offset={d}", .{ fd, new_offset });
    return replySuccess(notif.id, new_offset);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const Threads = @import("../../proc/Threads.zig");
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

test "lseek SEEK_SET repositions to given offset" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Insert a proc file (content "100\n" = 4 bytes)
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    var proc_file = try ProcFile.open(caller, "/proc/self");
    // Advance offset by reading
    var tmp: [2]u8 = undefined;
    _ = try proc_file.read(&tmp);
    // offset is now 2

    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }), .{});

    // Seek back to 0
    const notif = makeNotif(.lseek, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @as(u64, @bitCast(@as(i64, 0))),
        .arg2 = linux.SEEK.SET,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "lseek SEEK_END positions relative to content end" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Insert a proc file (content "100\n" = 4 bytes)
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }), .{});

    // Seek to end (offset 0 from END = content_len)
    const notif = makeNotif(.lseek, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @as(u64, @bitCast(@as(i64, 0))),
        .arg2 = linux.SEEK.END,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 4), resp.val); // 4 bytes
}

test "lseek SEEK_CUR advances from current position" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    var proc_file = try ProcFile.open(caller, "/proc/self");
    // Read 1 byte to advance offset to 1
    var tmp: [1]u8 = undefined;
    _ = try proc_file.read(&tmp);

    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }), .{});

    // Seek +2 from current
    const notif = makeNotif(.lseek, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @as(u64, @bitCast(@as(i64, 2))),
        .arg2 = linux.SEEK.CUR,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 3), resp.val); // 1 + 2 = 3
}

test "lseek to negative offset returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }), .{});

    // SEEK_SET with negative offset
    const notif = makeNotif(.lseek, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @as(u64, @bitCast(@as(i64, -1))),
        .arg2 = linux.SEEK.SET,
    });

    try testing.expectError(error.INVAL, handle(notif, &supervisor));
}

test "lseek on stdin returns ESPIPE" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.lseek, .{
        .pid = init_tid,
        .arg0 = linux.STDIN_FILENO, // stdin
        .arg1 = 0,
        .arg2 = linux.SEEK.SET,
    });

    try testing.expectError(error.SPIPE, handle(notif, &supervisor));
}

test "lseek on stdout returns ESPIPE" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.lseek, .{
        .pid = init_tid,
        .arg0 = linux.STDOUT_FILENO, // stdout
        .arg1 = 0,
        .arg2 = linux.SEEK.SET,
    });

    try testing.expectError(error.SPIPE, handle(notif, &supervisor));
}

test "lseek on non-existent VFD returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.lseek, .{
        .pid = init_tid,
        .arg0 = 99, // non-existent vfd
        .arg1 = 0,
        .arg2 = linux.SEEK.SET,
    });

    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "lseek with invalid whence returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }), .{});

    const notif = makeNotif(.lseek, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = 0,
        .arg2 = 99, // invalid whence
    });

    try testing.expectError(error.INVAL, handle(notif, &supervisor));
}

test "lseek with unknown caller PID returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.lseek, .{
        .pid = 999, // unknown PID
        .arg0 = 3,
        .arg1 = 0,
        .arg2 = linux.SEEK.SET,
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}
