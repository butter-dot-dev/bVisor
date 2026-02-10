const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const statxByPath = File.statxByPath;
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

/// Changes the current working directory of the calling Thread.
/// Validates the target path exists and is a directory before updating.
/// Supports both absolute and relative paths (relative resolved against cwd).
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: chdir(const char *path)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const path_ptr: u64 = notif.data.arg0;

    // Read path from caller's memory
    var path_buf: [256]u8 = undefined;
    const path = memory_bridge.readString(&path_buf, caller_tid, path_ptr) catch |err| {
        logger.log("chdir: failed to read path string of caller with tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .FAULT);
    };

    if (path.len == 0) {
        return replyErr(notif.id, .NOENT);
    }

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        logger.log("chdir: Thread not found for tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };
    std.debug.assert(caller.tid == caller_tid);

    // Resolve route against cwd
    var resolve_buf: [512]u8 = undefined;
    const route_result = resolveAndRoute(caller.fs_info.cwd, path, &resolve_buf) catch {
        return replyErr(notif.id, .NAMETOOLONG);
    };

    switch (route_result) {
        .block => return replyErr(notif.id, .PERM),
        .handle => |h| {
            // Stat the target to verify it exists and is a directory
            var caller_for_stat: ?*Thread = null;
            if (h.backend == .proc) {
                supervisor.guest_threads.syncNewThreads() catch |err| {
                    logger.log("chdir: syncNewThreads failed: {}", .{err});
                    return replyErr(notif.id, .NOSYS);
                };
                caller_for_stat = caller;
            }

            const statx_buf = statxByPath(h.backend, &supervisor.overlay, h.normalized, caller_for_stat) catch |err| {
                logger.log("chdir: stat failed for {s}: {s}", .{ h.normalized, @errorName(err) });
                return replyErr(notif.id, if (err == error.FileNotFound) .NOENT else .IO);
            };

            // Verify it's a directory
            if (statx_buf.mode & linux.S.IFMT != linux.S.IFDIR) {
                return replyErr(notif.id, .NOTDIR);
            }

            // Update cwd
            caller.fs_info.setCwd(h.normalized) catch {
                return replyErr(notif.id, .NOMEM);
            };

            logger.log("chdir: changed to {s}", .{caller.fs_info.cwd});
            return replySuccess(notif.id, 0);
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const getcwd = @import("getcwd.zig");

test "chdir to / succeeds" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "/")),
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "chdir to blocked path returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "/sys")),
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.PERM))), resp.@"error");
}

test "chdir to empty path returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "")),
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.NOENT))), resp.@"error");
}

test "chdir with unknown tid returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.chdir, .{
        .pid = 999,
        .arg0 = @intFromPtr(@as([*:0]const u8, "/")),
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}

test "chdir + getcwd roundtrip" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // chdir to /tmp
    const chdir_notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "/tmp")),
    });
    const chdir_resp = handle(chdir_notif, &supervisor);
    try testing.expect(!isError(chdir_resp));

    // getcwd should now return /tmp
    var buf: [256]u8 = undefined;
    const getcwd_notif = makeNotif(.getcwd, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(&buf),
        .arg1 = buf.len,
    });
    const getcwd_resp = getcwd.handle(getcwd_notif, &supervisor);
    try testing.expect(!isError(getcwd_resp));
    try testing.expectEqualStrings("/tmp", std.mem.sliceTo(&buf, 0));
}

test "chdir relative path to blocked dir returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // cwd is "/" so "sys" resolves to "/sys" which is blocked
    const notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "sys")),
    });
    const resp = handle(notif, &supervisor);

    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.PERM))), resp.@"error");
}
