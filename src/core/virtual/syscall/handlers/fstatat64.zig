const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const statxToStat = File.statxToStat;
const path_router = @import("../../path.zig");

const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const AT_EMPTY_PATH: u32 = 0x1000;

// fstatat64(dirfd, pathname, statbuf, flags)
//   Mode 1: AT_EMPTY_PATH + empty pathname → equivalent to fstat(dirfd)
//   Mode 2: Non-empty pathname → stat by path (no file opened)
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);
    const dirfd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const pathname_ptr: u64 = notif.data.arg1;
    const statbuf_addr: u64 = notif.data.arg2;
    const at_flags: u32 = @truncate(notif.data.arg3);

    // Read pathname from guest memory
    var path_buf: [256]u8 = undefined;
    const path = memory_bridge.readString(&path_buf, caller_tid, pathname_ptr) catch |err| {
        logger.log("fstatat64: failed to read path string: {}", .{err});
        return replyErr(notif.id, .FAULT);
    };

    // AT_EMPTY_PATH + empty pathname -> fd-based stat (same as fstat)
    if ((at_flags & AT_EMPTY_PATH) != 0 and path.len == 0) {
        // stdio: passthrough
        if (dirfd >= 0 and dirfd <= 2) {
            logger.log("fstatat64: passthrough for stdio fd={d}", .{dirfd});
            return replyContinue(notif.id);
        }

        var file: *File = undefined;
        {
            supervisor.mutex.lockUncancelable(supervisor.io);
            defer supervisor.mutex.unlock(supervisor.io);

            // Get caller Thread
            const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
                std.log.err("fstatat64: Thread not found with tid={d}: {}", .{ caller_tid, err });
                return replyContinue(notif.id);
            };
            std.debug.assert(caller.tid == caller_tid);

            file = caller.fd_table.get_ref(dirfd) orelse {
                logger.log("fstatat64: EBADF for fd={d}", .{dirfd});
                return replyErr(notif.id, .BADF);
            };
        }
        defer file.unref();

        const statx_buf = file.statx() catch |err| {
            logger.log("fstatat64: statx failed for fd={d}: {}", .{ dirfd, err });
            return replyErr(notif.id, .IO);
        };

        return writeStatResponse(notif, statx_buf, statbuf_addr);
    }

    // path-based stat
    if (path.len == 0) {
        return replyErr(notif.id, .INVAL);
    }

    // Get caller's cwd for relative path resolution (copy to stack, release lock)
    var cwd_buf: [512]u8 = undefined;
    const cwd: []const u8 = blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            logger.log("fstatat64: Thread not found for tid={d}: {}", .{ caller_tid, err });
            return replyErr(notif.id, .SRCH);
        };

        const c = caller.fs_info.cwd;
        @memcpy(cwd_buf[0..c.len], c);
        break :blk cwd_buf[0..c.len];
    };

    // Resolve path against cwd and route through access rules
    var resolve_buf: [512]u8 = undefined;
    const route_result = path_router.resolveAndRoute(cwd, path, &resolve_buf) catch {
        return replyErr(notif.id, .NAMETOOLONG);
    };

    switch (route_result) {
        .block => {
            logger.log("fstatat64: blocked path: {s}", .{path});
            return replyErr(notif.id, .PERM);
        },
        .handle => |h| {
            // Note all are lock-free (independent of internal Supervisor state) except for proc
            // For proc, sync Threads and get caller
            var caller: ?*Thread = null;
            if (h.backend == .proc) {
                supervisor.mutex.lockUncancelable(supervisor.io);
                defer supervisor.mutex.unlock(supervisor.io);

                supervisor.guest_threads.syncNewThreads() catch |err| {
                    logger.log("fstatat64: syncNewThreads failed: {}", .{err});
                    return replyErr(notif.id, .NOSYS);
                };

                caller = supervisor.guest_threads.get(caller_tid) catch |err| {
                    logger.log("fstatat64: Thread not found for tid={d}: {}", .{ caller_tid, err });
                    return replyErr(notif.id, .SRCH);
                };
            }

            const statx_buf = File.statxByPath(h.backend, &supervisor.overlay, h.normalized, caller) catch |err| {
                logger.log("fstatat64: statx failed for {s}: {s}", .{ h.normalized, @errorName(err) });
                return replyErr(notif.id, if (err == error.FileNotFound) .NOENT else .IO);
            };

            return writeStatResponse(notif, statx_buf, statbuf_addr);
        },
    }
}

fn writeStatResponse(notif: linux.SECCOMP.notif, statx_buf: linux.Statx, statbuf_addr: u64) linux.SECCOMP.notif_resp {
    const stat_buf = statxToStat(statx_buf);
    const stat_bytes = std.mem.asBytes(&stat_buf);
    memory_bridge.writeSlice(stat_bytes, @intCast(notif.pid), statbuf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };
    return replySuccess(notif.id, 0);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const Stat = @import("../../../types.zig").Stat;

test "fstatat64 path-based /proc/self succeeds" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var stat_result: Stat = undefined;
    const notif = makeNotif(.fstatat64, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/proc/self")),
        .arg2 = @intFromPtr(&stat_result),
        .arg3 = @as(u64, 0),
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "fstatat64 blocked path /sys returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var stat_result: Stat = undefined;
    const notif = makeNotif(.fstatat64, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/sys/class")),
        .arg2 = @intFromPtr(&stat_result),
        .arg3 = @as(u64, 0),
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.PERM))), resp.@"error");
}

test "fstatat64 empty path without AT_EMPTY_PATH returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var stat_result: Stat = undefined;
    const notif = makeNotif(.fstatat64, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "")),
        .arg2 = @intFromPtr(&stat_result),
        .arg3 = @as(u64, 0), // no AT_EMPTY_PATH
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.INVAL))), resp.@"error");
}

test "fstatat64 unknown tid returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var stat_result: Stat = undefined;
    const notif = makeNotif(.fstatat64, .{
        .pid = 999,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/proc/self")),
        .arg2 = @intFromPtr(&stat_result),
        .arg3 = @as(u64, 0),
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}

test "fstatat64 AT_EMPTY_PATH with proc fd succeeds" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Manually insert a ProcFile into the fd table
    const thread = supervisor.guest_threads.lookup.get(init_tid).?;
    var proc_content: [256]u8 = undefined;
    @memcpy(proc_content[0..4], "100\n");
    const file = try File.init(allocator, .{ .proc = .{
        .content = proc_content,
        .content_len = 4,
        .offset = 0,
    } });
    const vfd = try thread.fd_table.insert(file, .{});

    var stat_result: Stat = undefined;
    const notif = makeNotif(.fstatat64, .{
        .pid = init_tid,
        .arg0 = @as(u64, @intCast(vfd)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "")),
        .arg2 = @intFromPtr(&stat_result),
        .arg3 = AT_EMPTY_PATH,
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
    // ProcFile statx returns S_IFREG | 0o444
    try testing.expect(stat_result.st_mode & linux.S.IFMT == linux.S.IFREG);
}
