const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Passthrough = @import("../../fs/backend/passthrough.zig").Passthrough;
const Cow = @import("../../fs/backend/cow.zig").Cow;
const Tmp = @import("../../fs/backend/tmp.zig").Tmp;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const Supervisor = @import("../../../Supervisor.zig");
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;
    const allocator = supervisor.allocator;

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    // Read path from caller's memory
    const path_ptr: u64 = notif.data.arg1;
    var path_buf: [256]u8 = undefined;
    const path = try memory_bridge.readString(&path_buf, caller_tid, path_ptr);

    const dirfd: i32 = @truncate(@as(i64, @bitCast(notif.data.arg0)));

    if (path.len == 0) {
        return LinuxErr.INVAL;
    }

    // Determine base directory for path resolution (copy to stack, release lock)
    // - Absolute paths: base is irrelevant (resolveAndRoute ignores it)
    // - Relative + AT_FDCWD: resolve against caller's cwd
    // - Relative + real dirfd: resolve against dirfd's opened path
    var base_buf: [512]u8 = undefined;
    const base: []const u8 = blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        // Relative path with a real dirfd: use dirfd's opened path as base
        if (path[0] != '/' and dirfd != -100) {
            const dir_file = caller.fd_table.get_ref(dirfd) orelse {
                logger.log("openat: EBADF for dirfd={d}", .{dirfd});
                return LinuxErr.BADF;
            };
            defer dir_file.unref();

            const dir_path = dir_file.opened_path orelse {
                logger.log("openat: dirfd={d} has no associated path", .{dirfd});
                return LinuxErr.NOTDIR;
            };
            if (dir_path.len > base_buf.len) return LinuxErr.NAMETOOLONG;
            @memcpy(base_buf[0..dir_path.len], dir_path);
            break :blk base_buf[0..dir_path.len];
        }

        // Otherwise use cwd
        const c = caller.fs_info.cwd;
        if (c.len > base_buf.len) return LinuxErr.NAMETOOLONG;
        @memcpy(base_buf[0..c.len], c);
        break :blk base_buf[0..c.len];
    };

    // Resolve path against base and route through access rules
    var resolve_buf: [512]u8 = undefined;
    const route_result = resolveAndRoute(base, path, &resolve_buf) catch {
        return LinuxErr.NAMETOOLONG;
    };

    switch (route_result) {
        .block => {
            logger.log("openat: blocked path: {s}", .{path});
            return LinuxErr.PERM;
        },
        .handle => |h| {
            const flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg2)));
            const mode: linux.mode_t = @truncate(notif.data.arg3);

            // Special case: if we're in the /proc filepath
            // We need to sync guest_threads with the kernel to ensure all current PIDs are registered
            if (h.backend == .proc) {
                supervisor.mutex.lockUncancelable(supervisor.io);
                defer supervisor.mutex.unlock(supervisor.io);

                try supervisor.guest_threads.syncNewThreads();
            }

            // Open the file via the appropriate backend
            // Note all are lock-free (independent of internal supervisor state) except for proc
            const file: *File = switch (h.backend) {
                .passthrough => try File.init(allocator, .{ .passthrough = try Passthrough.open(&supervisor.overlay, h.normalized, flags, mode) }),
                .cow => try File.init(allocator, .{ .cow = try Cow.open(&supervisor.overlay, h.normalized, flags, mode) }),
                .tmp => try File.init(allocator, .{ .tmp = try Tmp.open(&supervisor.overlay, h.normalized, flags, mode) }),
                .proc => blk: {
                    // Special case: the open of ProcFile requires passing in the caller
                    // So we need a critical section since get does lazy registration
                    supervisor.mutex.lockUncancelable(supervisor.io);
                    defer supervisor.mutex.unlock(supervisor.io);
                    const caller = try supervisor.guest_threads.get(caller_tid);
                    break :blk try File.init(allocator, .{ .proc = try ProcFile.open(caller, h.normalized) });
                },
            };
            errdefer file.unref();

            // Set the File's flags
            file.open_flags = flags;

            // Store the opened path on the File (already normalized by resolveAndRoute)
            try file.setOpenedPath(h.normalized);

            // Enter critical section for all backends
            // Registering newly opened file to caller's fd_table

            // note there's subtle complexity here for the .proc case
            // since we're re-acquiring the lock and a new instance of a caller *Thread

            supervisor.mutex.lockUncancelable(supervisor.io);
            defer supervisor.mutex.unlock(supervisor.io);

            const caller = try supervisor.guest_threads.get(caller_tid);

            // Insert into fd table and return the virtual fd
            const vfd = try caller.fd_table.insert(file, .{ .cloexec = flags.CLOEXEC });
            logger.log("openat: opened {s} as vfd={d}", .{ h.normalized, vfd });
            return replySuccess(notif.id, @intCast(vfd));
        },
    }
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const FdTable = @import("../../fs/FdTable.zig");

fn makeOpenatNotif(pid: AbsTid, path: [*:0]const u8, flags: u32, mode: u32) linux.SECCOMP.notif {
    return makeNotif(.openat, .{
        .pid = pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path),
        .arg2 = flags,
        .arg3 = mode,
    });
}

test "openat /dev/null returns VFD >= 3" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeOpenatNotif(init_tid, "/dev/null", 0, 0);
    const resp = try handle(notif, &supervisor);
    try testing.expect(resp.val >= 3);
}

test "openat /proc/self returns VFD >= 3" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeOpenatNotif(init_tid, "/proc/self", 0, 0);
    const resp = try handle(notif, &supervisor);
    try testing.expect(resp.val >= 3);
}

test "openat /sys/class/net returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeOpenatNotif(init_tid, "/sys/class/net", 0, 0);
    try testing.expectError(error.PERM, handle(notif, &supervisor));
}

test "openat /tmp/.bvisor/secret returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeOpenatNotif(init_tid, "/tmp/.bvisor/secret", 0, 0);
    try testing.expectError(error.PERM, handle(notif, &supervisor));
}

test "openat relative path resolves against cwd" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // cwd is "/" so "proc/self" resolves to "/proc/self" (same as the absolute path test)
    const notif = makeOpenatNotif(init_tid, "proc/self", 0, 0);
    const resp = try handle(notif, &supervisor);
    try testing.expect(resp.val >= 3);
}

test "openat empty path returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeOpenatNotif(init_tid, "", 0, 0);
    try testing.expectError(error.INVAL, handle(notif, &supervisor));
}

test "openat unknown caller PID returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeOpenatNotif(999, "/dev/null", 0, 0);
    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}

test "openat /proc/999 non-existent returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeOpenatNotif(init_tid, "/proc/999", 0, 0);
    try testing.expectError(error.NOENT, handle(notif, &supervisor));
}
