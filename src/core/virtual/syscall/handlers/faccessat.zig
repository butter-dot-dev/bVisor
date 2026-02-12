const std = @import("std");
const linux = std.os.linux;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: faccessat(dirfd, pathname, mode, flags)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const dirfd: i32 = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    const path_ptr: u64 = notif.data.arg1;
    const mode: u32 = @truncate(notif.data.arg2);

    // Read path from caller's memory
    var path_buf: [256]u8 = undefined;
    const path = memory_bridge.readString(&path_buf, caller_tid, path_ptr) catch |err| {
        logger.log("faccessat: failed to read path string: {}", .{err});
        return replyErr(notif.id, .FAULT);
    };

    if (path.len == 0) {
        return replyErr(notif.id, .INVAL);
    }

    // Determine base directory for path resolution
    // - Absolute paths: base is irrelevant (resolveAndRoute ignores it)
    // - Relative + AT_FDCWD: resolve against caller's cwd
    // - Relative + real dirfd: resolve against dirfd's opened path
    var base_buf: [512]u8 = undefined;
    const base: []const u8 = if (path[0] == '/') "/" else blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        // Get caller Thread
        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            logger.log("faccessat: Thread not found for tid={d}: {}", .{ caller_tid, err });
            return replyErr(notif.id, .SRCH);
        };

        if (dirfd != -100) {
            const dir_file = caller.fd_table.get_ref(dirfd) orelse {
                logger.log("faccessat: EBADF for dirfd={d}", .{dirfd});
                return replyErr(notif.id, .BADF);
            };
            defer dir_file.unref();

            const dir_path = dir_file.opened_path orelse {
                logger.log("faccessat: dirfd={d} has no associated path", .{dirfd});
                return replyErr(notif.id, .NOTDIR);
            };
            if (dir_path.len > base_buf.len) return replyErr(notif.id, .NAMETOOLONG);
            @memcpy(base_buf[0..dir_path.len], dir_path);
            break :blk base_buf[0..dir_path.len];
        }

        const c = caller.fs_info.cwd;
        if (c.len > base_buf.len) return replyErr(notif.id, .NAMETOOLONG);
        @memcpy(base_buf[0..c.len], c);
        break :blk base_buf[0..c.len];
    };

    // Resolve path against base and route through access rules
    var resolve_buf: [512]u8 = undefined;
    const route_result = resolveAndRoute(base, path, &resolve_buf) catch {
        return replyErr(notif.id, .NAMETOOLONG);
    };

    switch (route_result) {
        .block => {
            logger.log("faccessat: blocked path: {s}", .{path});
            return replyErr(notif.id, .ACCES);
        },
        .handle => |h| {
            switch (h.backend) {
                .proc => {
                    // For /proc paths, check if the virtualized file would exist.
                    // We only check F_OK (existence) - proc files are always readable.
                    supervisor.mutex.lockUncancelable(supervisor.io);
                    defer supervisor.mutex.unlock(supervisor.io);

                    supervisor.guest_threads.syncNewThreads() catch |err| {
                        logger.log("faccessat: syncNewThreads failed: {}", .{err});
                        return replyErr(notif.id, .NOSYS);
                    };

                    // Get caller Thread
                    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
                        logger.log("faccessat: Thread not found for tid={d}: {}", .{ caller_tid, err });
                        return replyErr(notif.id, .SRCH);
                    };

                    const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
                    _ = ProcFile.open(caller, h.normalized) catch {
                        logger.log("faccessat: proc path not found: {s}", .{h.normalized});
                        return replyErr(notif.id, .NOENT);
                    };

                    logger.log("faccessat: proc path accessible: {s}", .{h.normalized});
                    return replySuccess(notif.id, 0);
                },
                // For passthrough/cow/tmp, check the real filesystem via overlay
                .passthrough, .cow, .tmp => {
                    // Null-terminate the normalized path for kernel syscall
                    var kern_path_buf: [513]u8 = undefined;
                    if (h.normalized.len >= kern_path_buf.len) return replyErr(notif.id, .NAMETOOLONG);
                    @memcpy(kern_path_buf[0..h.normalized.len], h.normalized);
                    kern_path_buf[h.normalized.len] = 0;

                    const rc = linux.faccessat(linux.AT.FDCWD, kern_path_buf[0..h.normalized.len :0], mode, 0);
                    const errno = linux.errno(rc);
                    if (errno != .SUCCESS) {
                        logger.log("faccessat: kernel check failed for {s}: {s}", .{ h.normalized, @tagName(errno) });
                        return replyErr(notif.id, errno);
                    }

                    logger.log("faccessat: accessible: {s}", .{h.normalized});
                    return replySuccess(notif.id, 0);
                },
            }
        },
    }
}

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
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
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
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = handle(makeAccessatNotif(init_tid, "/proc/self", 0), &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "faccessat relative path resolves against cwd" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // cwd is "/" so "proc/self" resolves to "/proc/self" (same as the absolute path test)
    const resp = handle(makeAccessatNotif(init_tid, "proc/self", 0), &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "faccessat unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
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
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const resp = handle(makeAccessatNotif(init_tid, "/proc/999", 0), &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.NOENT))), resp.@"error");
}
