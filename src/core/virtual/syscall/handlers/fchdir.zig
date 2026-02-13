const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const path_router = @import("../../path.zig");
const route = path_router.route;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

/// Changes the current working directory to the directory referenced by the given fd.
/// The fd must have been opened with openat and must refer to a directory.
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: fchdir(int fd)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        logger.log("fchdir: Thread not found for tid={d}: {}", .{ caller_tid, err });
        return LinuxErr.SRCH;
    };
    std.debug.assert(caller.tid == caller_tid);

    // Look up fd in caller's fd_table
    const file = caller.fd_table.get_ref(fd) orelse {
        logger.log("fchdir: EBADF for fd={d}", .{fd});
        return LinuxErr.BADF;
    };
    defer file.unref();

    // Get the path this fd was opened with
    const path = file.opened_path orelse {
        logger.log("fchdir: fd={d} has no associated path", .{fd});
        return LinuxErr.NOTDIR;
    };

    // Validate path through routing rules before updating cwd
    const route_result = route(path) catch {
        return LinuxErr.NAMETOOLONG;
    };
    if (route_result == .block) {
        logger.log("fchdir: blocked path: {s}", .{path});
        return LinuxErr.PERM;
    }

    // Verify it's a directory via statx
    const statx_buf = file.statx() catch |err| {
        logger.log("fchdir: statx failed for fd={d}: {}", .{ fd, err });
        return LinuxErr.IO;
    };

    if (statx_buf.mode & linux.S.IFMT != linux.S.IFDIR) {
        return LinuxErr.NOTDIR;
    }

    // Update cwd
    caller.fs_info.setCwd(path) catch {
        return LinuxErr.NOMEM;
    };

    logger.log("fchdir: changed to {s}", .{caller.fs_info.cwd});
    return replySuccess(notif.id, 0);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const openat = @import("openat.zig");
const getcwd = @import("getcwd.zig");

test "fchdir with unknown tid returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.fchdir, .{
        .pid = 999,
        .arg0 = 3,
    });
    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}

test "fchdir with invalid fd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.fchdir, .{
        .pid = init_tid,
        .arg0 = 99, // no such fd
    });
    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "fchdir on fd without opened_path returns ENOTDIR" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Manually insert a file without opened_path
    const thread = supervisor.guest_threads.lookup.get(init_tid).?;
    const file = try File.init(allocator, .{ .passthrough = .{ .fd = 42 } });
    const vfd = try thread.fd_table.insert(file, .{});

    const notif = makeNotif(.fchdir, .{
        .pid = init_tid,
        .arg0 = @as(u64, @intCast(vfd)),
    });
    try testing.expectError(error.NOTDIR, handle(notif, &supervisor));
}

test "fchdir + getcwd roundtrip via openat" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Open /tmp via openat
    const open_notif = makeNotif(.openat, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/tmp")),
        .arg2 = @as(u64, 0), // O_RDONLY
        .arg3 = @as(u64, 0),
    });
    const open_resp = try openat.handle(open_notif, &supervisor);
    const dir_fd = open_resp.val;

    // fchdir to that fd
    const fchdir_notif = makeNotif(.fchdir, .{
        .pid = init_tid,
        .arg0 = @as(u64, @intCast(dir_fd)),
    });
    _ = try handle(fchdir_notif, &supervisor);

    // getcwd should now return /tmp
    var buf: [256]u8 = undefined;
    const getcwd_notif = makeNotif(.getcwd, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(&buf),
        .arg1 = buf.len,
    });
    _ = try getcwd.handle(getcwd_notif, &supervisor);
    try testing.expectEqualStrings("/tmp", std.mem.sliceTo(&buf, 0));
}

test "fchdir on fd with blocked path returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Manually insert a file with a blocked opened_path
    const thread = supervisor.guest_threads.lookup.get(init_tid).?;
    const file = try File.init(allocator, .{ .passthrough = .{ .fd = 42 } });
    try file.setOpenedPath("/sys/class/net");
    const vfd = try thread.fd_table.insert(file, .{});

    const notif = makeNotif(.fchdir, .{
        .pid = init_tid,
        .arg0 = @as(u64, @intCast(vfd)),
    });
    try testing.expectError(error.PERM, handle(notif, &supervisor));
}

test "fchdir on non-directory fd returns ENOTDIR" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Manually insert a ProcFile (regular file, not a directory) with opened_path
    const thread = supervisor.guest_threads.lookup.get(init_tid).?;
    var proc_content: [256]u8 = undefined;
    @memcpy(proc_content[0..4], "100\n");
    const file = try File.init(allocator, .{ .proc = .{
        .content = proc_content,
        .content_len = 4,
        .offset = 0,
    } });
    try file.setOpenedPath("/proc/self/status");
    const vfd = try thread.fd_table.insert(file, .{});

    const notif = makeNotif(.fchdir, .{
        .pid = init_tid,
        .arg0 = @as(u64, @intCast(vfd)),
    });
    try testing.expectError(error.NOTDIR, handle(notif, &supervisor));
}
