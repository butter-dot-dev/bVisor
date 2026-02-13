const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const statxByPath = File.statxByPath;
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

/// Changes the current working directory of the calling Thread.
/// Validates the target path exists and is a directory before updating.
/// Supports both absolute and relative paths (relative resolved against cwd).
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: chdir(const char *path)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const path_ptr: u64 = notif.data.arg0;

    // Read path from caller's memory
    var path_buf: [256]u8 = undefined;
    const path = try memory_bridge.readString(&path_buf, caller_tid, path_ptr);

    if (path.len == 0) {
        return LinuxErr.NOENT;
    }

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = try supervisor.guest_threads.get(caller_tid);
    std.debug.assert(caller.tid == caller_tid);

    // Resolve route against cwd
    var resolve_buf: [512]u8 = undefined;
    const route_result = resolveAndRoute(caller.fs_info.cwd, path, &resolve_buf) catch {
        return LinuxErr.NAMETOOLONG;
    };

    switch (route_result) {
        .block => return LinuxErr.PERM,
        .handle => |h| {
            // Stat the target to verify it exists and is a directory
            var caller_for_stat: ?*Thread = null;
            if (h.backend == .proc) {
                try supervisor.guest_threads.syncNewThreads();
                caller_for_stat = caller;
            }

            const statx_buf = try statxByPath(h.backend, &supervisor.overlay, h.normalized, caller_for_stat);

            // Verify it's a directory
            if (statx_buf.mode & linux.S.IFMT != linux.S.IFDIR) {
                return LinuxErr.NOTDIR;
            }

            // Update cwd
            try caller.fs_info.setCwd(h.normalized);

            logger.log("chdir: changed to {s}", .{caller.fs_info.cwd});
            return replySuccess(notif.id, 0);
        },
    }
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
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
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "/")),
    });
    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "chdir to blocked path returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "/sys")),
    });
    try testing.expectError(error.PERM, handle(notif, &supervisor));
}

test "chdir to empty path returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "")),
    });
    try testing.expectError(error.NOENT, handle(notif, &supervisor));
}

test "chdir with unknown tid returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.chdir, .{
        .pid = 999,
        .arg0 = @intFromPtr(@as([*:0]const u8, "/")),
    });
    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}

test "chdir + getcwd roundtrip" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // chdir to /tmp
    const chdir_notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "/tmp")),
    });
    _ = try handle(chdir_notif, &supervisor);

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

test "chdir relative path to blocked dir returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // cwd is "/" so "sys" resolves to "/sys" which is blocked
    const notif = makeNotif(.chdir, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(@as([*:0]const u8, "sys")),
    });
    try testing.expectError(error.PERM, handle(notif, &supervisor));
}
