const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const LinuxErr = @import("../../../LinuxErr.zig").LinuxErr;
const checkErr = @import("../../../LinuxErr.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const Logger = @import("../../../types.zig").Logger;
const F = linux.F;

/// F_DUPFD_CLOEXEC is not in Zig's linux.F struct
const F_DUPFD_CLOEXEC = 1030;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const cmd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg1)));
    const arg: u64 = notif.data.arg2; // versatile role depending on cmd

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        logger.log("fcntl: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return LinuxErr.SRCH;
    };

    return switch (cmd) {
        F.DUPFD => handleDupFd(notif.id, fd, arg, caller, logger, false),
        F_DUPFD_CLOEXEC => handleDupFd(notif.id, fd, arg, caller, logger, true),
        F.GETFD => handleGetFd(notif.id, fd, caller, logger),
        F.SETFD => handleSetFd(notif.id, fd, arg, caller, logger),
        F.GETFL => handleGetFl(notif.id, fd, caller, logger),
        F.SETFL => handleSetFl(notif.id, fd, arg, caller, logger),

        // TODO: right now, we just stub these commands related to advisory locking and signal ownership
        F.GETLK,
        F.SETLK,
        F.SETLKW,
        F.OFD_GETLK,
        F.OFD_SETLK,
        F.OFD_SETLKW,
        F.GETOWN,
        F.SETOWN,
        F.GETOWN_EX,
        F.SETOWN_EX,
        F.GETSIG,
        F.SETSIG,
        => {
            logger.log("fcntl: stubbed cmd={d} on fd={d}", .{ cmd, fd });
            return replySuccess(notif.id, 0);
        },

        else => {
            logger.log("fcntl: unsupported cmd={d} on fd={d}", .{ cmd, fd });
            return LinuxErr.INVAL;
        },
    };
}

// TODO: respect "lowest fd >= arg" constraint even for VirtualFD's
/// Duplicate fd
fn handleDupFd(
    id: u64,
    fd: i32,
    arg: u64,
    caller: *Thread,
    logger: Logger,
    cloexec: bool,
) !linux.SECCOMP.notif_resp {
    _ = arg;

    const file = caller.fd_table.get_ref(fd) orelse {
        logger.log("fcntl: F_DUPFD EBADF for fd={d}", .{fd});
        return LinuxErr.BADF;
    };
    defer file.unref();

    const newfd = caller.fd_table.dup(file) catch {
        logger.log("fcntl: F_DUPFD failed to allocate new fd", .{});
        return LinuxErr.NOMEM;
    };

    // CLOEXEC defaults to false
    if (cloexec) {
        _ = caller.fd_table.setCloexec(newfd, true);
    }

    const cloexeString = if (cloexec) "_CLOEXEC" else "";
    logger.log("fcntl: F_DUPFD{s} fd={d} -> {d}", .{ cloexeString, fd, newfd });
    return replySuccess(id, newfd);
}

/// Read per-fd flags
fn handleGetFd(
    id: u64,
    fd: i32,
    caller: *Thread,
    logger: Logger,
) !linux.SECCOMP.notif_resp {
    // Verify the fd exists
    const file = caller.fd_table.get_ref(fd) orelse {
        logger.log("fcntl: F_GETFD EBADF for fd={d}", .{fd});
        return LinuxErr.BADF;
    };
    file.unref();

    const cloexec = caller.fd_table.getCloexec(fd);
    const val: i64 = if (cloexec) linux.FD_CLOEXEC else 0;
    logger.log("fcntl: F_GETFD fd={d} -> {d}", .{ fd, val });
    return replySuccess(id, val);
}

/// Mutate per-fd flags
fn handleSetFd(
    id: u64,
    fd: i32,
    arg: u64,
    caller: *Thread,
    logger: Logger,
) !linux.SECCOMP.notif_resp {
    const new_cloexec = (arg & linux.FD_CLOEXEC) != 0;

    if (!caller.fd_table.setCloexec(fd, new_cloexec)) {
        logger.log("fcntl: F_SETFD EBADF for fd={d}", .{fd});
        return LinuxErr.BADF;
    }

    logger.log("fcntl: F_SETFD fd={d} cloexec={}", .{ fd, new_cloexec });
    return replySuccess(id, 0);
}

/// Read per-File flags
fn handleGetFl(
    id: u64,
    fd: i32,
    caller: *Thread,
    logger: Logger,
) !linux.SECCOMP.notif_resp {
    const file = caller.fd_table.get_ref(fd) orelse {
        logger.log("fcntl: F_GETFL EBADF for fd={d}", .{fd});
        return LinuxErr.BADF;
    };
    defer file.unref();

    const flags: u32 = @bitCast(file.open_flags);
    logger.log("fcntl: F_GETFL fd={d} -> 0x{x}", .{ fd, flags });
    return replySuccess(id, @intCast(flags));
}

/// Write per-File flags
fn handleSetFl(
    id: u64,
    fd: i32,
    arg: u64,
    caller: *Thread,
    logger: Logger,
) !linux.SECCOMP.notif_resp {
    const file = caller.fd_table.get_ref(fd) orelse {
        logger.log("fcntl: F_SETFL EBADF for fd={d}", .{fd});
        return LinuxErr.BADF;
    };
    defer file.unref();

    const new_flags: linux.O = @bitCast(@as(u32, @truncate(arg)));

    // Only mutable flags can be changed via F_SETFL.
    // Preserve immutable flags (ACCMODE, CREAT, EXCL, etc.) from the original
    var updated: linux.O = file.open_flags;
    updated.APPEND = new_flags.APPEND;
    updated.ASYNC = new_flags.ASYNC;
    updated.DIRECT = new_flags.DIRECT;
    updated.NOATIME = new_flags.NOATIME;
    updated.NONBLOCK = new_flags.NONBLOCK;
    file.open_flags = updated;

    // Propagate to kernel for backends with real FDs
    if (!builtin.is_test) {
        if (file.backingFd()) |backing_fd| {
            const flags_u32: u32 = @bitCast(updated);
            const rc = linux.fcntl(backing_fd, F.SETFL, @as(usize, flags_u32));
            try checkErr(rc, "fcntl: F_SETFL kernel propagation failed for fd={d}", .{fd}); // used to manually return .INVAL
        }
    }

    logger.log("fcntl: F_SETFL fd={d} flags=0x{x}", .{ fd, @as(u32, @bitCast(updated)) });
    return replySuccess(id, 0);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const File = @import("../../fs/File.zig");
const FdTable = @import("../../fs/FdTable.zig");
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

fn makeFcntlNotif(pid: AbsTid, fd: i32, cmd: i32, arg: u64) linux.SECCOMP.notif {
    return makeNotif(.fcntl, .{
        .pid = pid,
        .arg0 = @bitCast(@as(i64, fd)),
        .arg1 = @bitCast(@as(i64, cmd)),
        .arg2 = arg,
    });
}

test "F_GETFD returns 0 for non-cloexec fd" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const init_tid: AbsTid = 100;
    const caller = try supervisor.guest_threads.get(init_tid);
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    file.open_flags = .{};
    const vfd = try caller.fd_table.insert(file, .{});

    const resp = try handle(makeFcntlNotif(100, vfd, F.GETFD, 0), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "F_GETFD returns FD_CLOEXEC for cloexec fd" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const init_tid: AbsTid = 100;
    const caller = try supervisor.guest_threads.get(init_tid);
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    file.open_flags = .{};
    const vfd = try caller.fd_table.insert(file, .{});

    _ = caller.fd_table.setCloexec(vfd, true);

    const resp = try handle(makeFcntlNotif(100, vfd, F.GETFD, 0), &supervisor);
    try testing.expectEqual(@as(i64, linux.FD_CLOEXEC), resp.val);
}

test "F_SETFD sets cloexec" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const init_tid: AbsTid = 100;
    const caller = try supervisor.guest_threads.get(init_tid);
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    file.open_flags = .{};
    const vfd = try caller.fd_table.insert(file, .{});

    try handle(makeFcntlNotif(100, vfd, F.SETFD, linux.FD_CLOEXEC), &supervisor);

    const get_resp = handle(makeFcntlNotif(100, vfd, F.GETFD, 0), &supervisor);
    try testing.expectEqual(@as(i64, linux.FD_CLOEXEC), get_resp.val);

    try handle(makeFcntlNotif(100, vfd, F.SETFD, 0), &supervisor);

    const get_resp2 = handle(makeFcntlNotif(100, vfd, F.GETFD, 0), &supervisor);
    try testing.expectEqual(@as(i64, 0), get_resp2.val);
}

test "F_GETFL returns stored open flags" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const flags: linux.O = .{ .ACCMODE = .RDWR, .APPEND = true };
    const init_tid: AbsTid = 100;
    const caller = try supervisor.guest_threads.get(init_tid);
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    file.open_flags = flags;
    const vfd = try caller.fd_table.insert(file, .{});

    const resp = try handle(makeFcntlNotif(100, vfd, F.GETFL, 0), &supervisor);

    const returned: linux.O = @bitCast(@as(u32, @intCast(resp.val)));
    try testing.expect(returned.ACCMODE == .RDWR);
    try testing.expect(returned.APPEND);
}

test "F_SETFL changes mutable flags but preserves ACCMODE" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const flags: linux.O = .{ .ACCMODE = .RDONLY };
    const init_tid: AbsTid = 100;
    const caller = try supervisor.guest_threads.get(init_tid);
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    file.open_flags = flags;
    const vfd = try caller.fd_table.insert(file, .{});

    // Set NONBLOCK (mutable) and try to change ACCMODE (immutable)
    const new_flags: linux.O = .{ .ACCMODE = .RDWR, .NONBLOCK = true };
    try handle(makeFcntlNotif(100, vfd, F.SETFL, @as(u32, @bitCast(new_flags))), &supervisor);

    // Verify: NONBLOCK should be set, ACCMODE should still be RDONLY
    const get_resp = handle(makeFcntlNotif(100, vfd, F.GETFL, 0), &supervisor);
    const result: linux.O = @bitCast(@as(u32, @intCast(get_resp.val)));
    try testing.expect(result.NONBLOCK);
    try testing.expect(result.ACCMODE == .RDONLY);
}

test "F_DUPFD duplicates fd" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const init_tid: AbsTid = 100;
    const caller = try supervisor.guest_threads.get(init_tid);
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    file.open_flags = .{};
    const vfd = try caller.fd_table.insert(file, .{});
    const resp = try handle(makeFcntlNotif(100, vfd, F.DUPFD, 0), &supervisor);

    const newfd: i32 = @intCast(resp.val);
    try testing.expect(newfd != vfd);

    try testing.expect(!caller.fd_table.getCloexec(newfd));
}

test "F_DUPFD_CLOEXEC duplicates fd with cloexec" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const init_tid: AbsTid = 100;
    const caller = try supervisor.guest_threads.get(init_tid);
    const file = try File.init(testing.allocator, .{ .passthrough = .{ .fd = 42 } });
    file.open_flags = .{};
    const vfd = try caller.fd_table.insert(file, .{});

    const resp = try handle(makeFcntlNotif(100, vfd, F_DUPFD_CLOEXEC, 0), &supervisor);

    const newfd: i32 = @intCast(resp.val);
    try testing.expect(newfd != vfd);

    try testing.expect(caller.fd_table.getCloexec(newfd));
}

test "fcntl on bad fd returns EBADF" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = handle(makeFcntlNotif(100, 999, F.GETFD, 0), &supervisor);
    const err = if (resp) |_| return error.TestExpectedEqual else |e| e;
    try testing.expectEqual(error.BADF, err);
}

test "fcntl on unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, 100, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = handle(makeFcntlNotif(999, 3, F.GETFD, 0), &supervisor);
    const err = if (resp) |_| return error.TestExpectedEqual else |e| e;
    try testing.expectEqual(error.SRCH, err);
}
