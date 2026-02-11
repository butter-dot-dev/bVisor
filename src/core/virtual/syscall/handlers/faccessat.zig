const std = @import("std");
const linux = std.os.linux;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const path_router = @import("../../path.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: faccessat(dirfd, pathname, mode, flags)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const path_ptr: u64 = notif.data.arg1;
    const mode: u32 = @truncate(notif.data.arg2);

    // Read path from caller's memory
    var path_buf: [256]u8 = undefined;
    const path = memory_bridge.readString(&path_buf, caller_tid, path_ptr) catch |err| {
        logger.log("faccessat: failed to read path string: {}", .{err});
        return replyErr(notif.id, .FAULT);
    };

    // Only absolute paths supported for now
    if (path.len == 0 or path[0] != '/') {
        logger.log("faccessat: path must be absolute: {s}", .{path});
        return replyErr(notif.id, .INVAL);
    }

    // Route the path through the same rules as openat
    const route_result = path_router.route(path) catch {
        logger.log("faccessat: path normalization failed for: {s}", .{path});
        return replyErr(notif.id, .INVAL);
    };

    switch (route_result) {
        .block => {
            logger.log("faccessat: blocked path: {s}", .{path});
            return replyErr(notif.id, .ACCES);
        },
        .handle => |backend| {
            switch (backend) {
                .proc => {
                    // For /proc paths, check if the virtualized file would exist.
                    // We only check F_OK (existence) - proc files are always readable.
                    supervisor.mutex.lockUncancelable(supervisor.io);
                    defer supervisor.mutex.unlock(supervisor.io);

                    supervisor.guest_threads.syncNewThreads() catch |err| {
                        logger.log("faccessat: syncNewThreads failed: {}", .{err});
                        return replyErr(notif.id, .NOSYS);
                    };

                    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
                        logger.log("faccessat: Thread not found for tid={d}: {}", .{ caller_tid, err });
                        return replyErr(notif.id, .SRCH);
                    };

                    const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
                    _ = ProcFile.open(caller, path) catch {
                        logger.log("faccessat: proc path not found: {s}", .{path});
                        return replyErr(notif.id, .NOENT);
                    };

                    logger.log("faccessat: proc path accessible: {s}", .{path});
                    return replySuccess(notif.id, 0);
                },
                // For passthrough/cow/tmp, check the real filesystem via overlay
                .passthrough, .cow, .tmp => {
                    // Use kernel faccessat on the actual path (which works for
                    // passthrough paths like /dev/null and overlay-backed paths).
                    // The overlay resolves cow/tmp paths to the sandbox root.
                    const rc = linux.faccessat(linux.AT.FDCWD, path.ptr, mode, 0);
                    const errno = linux.errno(rc);
                    if (errno != .SUCCESS) {
                        logger.log("faccessat: kernel check failed for {s}: {s}", .{ path, @tagName(errno) });
                        return replyErr(notif.id, errno);
                    }

                    logger.log("faccessat: accessible: {s}", .{path});
                    return replySuccess(notif.id, 0);
                },
            }
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

fn makeAccessatNotif(pid: AbsTid, path: [*:0]const u8, mode: u32) linux.SECCOMP.notif {
    return makeNotif(.faccessat, .{
        .pid = pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path),
        .arg2 = mode,
    });
}

test "faccessat blocked path returns EACCES" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = handle(makeAccessatNotif(init_tid, "/sys/class/net", 0), &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.ACCES))), resp.@"error");
}

test "faccessat /proc/self returns success" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = handle(makeAccessatNotif(init_tid, "/proc/self", 0), &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "faccessat relative path returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = handle(makeAccessatNotif(init_tid, "relative/path", 0), &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.INVAL))), resp.@"error");
}

test "faccessat unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = handle(makeAccessatNotif(999, "/proc/self", 0), &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}

test "faccessat /proc/999 non-existent returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = handle(makeAccessatNotif(init_tid, "/proc/999", 0), &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.NOENT))), resp.@"error");
}
