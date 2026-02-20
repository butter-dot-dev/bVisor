const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const Cow = @import("../../fs/backend/cow.zig").Cow;
const Tmp = @import("../../fs/backend/tmp.zig").Tmp;
const cow_mod = @import("../../fs/backend/cow.zig");
const tmp_mod = @import("../../fs/backend/tmp.zig");
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const OverlayRoot = @import("../../OverlayRoot.zig");
const Tombstones = @import("../../Tombstones.zig");
const Supervisor = @import("../../../Supervisor.zig");
const ScratchArena = Supervisor.ScratchArena;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: unlinkat(dirfd, pathname, flags)
    //  flags == 0: unlink file
    //  flags & AT_REMOVEDIR: rmdir
    const caller_tid: AbsTid = @intCast(notif.pid);
    const dirfd: i32 = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    const path_ptr: u64 = notif.data.arg1;
    const flags: u32 = @truncate(notif.data.arg2);
    const is_rmdir = (flags & linux.AT.REMOVEDIR) != 0;

    var path_buf: [256]u8 = undefined;
    const path = try memory_bridge.readString(&path_buf, caller_tid, path_ptr);

    // Invalid flags return EINVAL
    if ((flags & ~@as(u32, linux.AT.REMOVEDIR)) != 0) return LinuxErr.INVAL;

    if (path.len == 0) return LinuxErr.INVAL;

    // rmdir(".") gives EINVAL
    if (is_rmdir and std.mem.eql(u8, path, ".")) return LinuxErr.INVAL;

    // Resolve base directory
    var base_buf: [512]u8 = undefined;
    const base: []const u8 = if (path[0] == '/') "/" else blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        if (dirfd != linux.AT.FDCWD) {
            const dir_file = caller.fd_table.get_ref(dirfd) orelse {
                logger.log("unlinkat: EBADF for dirfd={d}", .{dirfd});
                return LinuxErr.BADF;
            };
            defer dir_file.unref();

            const dir_path = dir_file.opened_path orelse {
                logger.log("unlinkat: dirfd={d} has no associated path", .{dirfd});
                return LinuxErr.NOTDIR;
            };
            if (dir_path.len > base_buf.len) return LinuxErr.NAMETOOLONG;
            @memcpy(base_buf[0..dir_path.len], dir_path);
            break :blk base_buf[0..dir_path.len];
        }

        const c = caller.fs_info.cwd;
        if (c.len > base_buf.len) return LinuxErr.NAMETOOLONG;
        @memcpy(base_buf[0..c.len], c);
        break :blk base_buf[0..c.len];
    };

    var resolve_buf: [512]u8 = undefined;
    const route_result = resolveAndRoute(base, path, &resolve_buf) catch {
        return LinuxErr.NAMETOOLONG;
    };

    switch (route_result) {
        .block => {
            logger.log("unlinkat: blocked path: {s}", .{path});
            return LinuxErr.PERM;
        },
        .handle => |h| {
            switch (h.backend) {
                .passthrough, .proc => return LinuxErr.PERM,
                .cow => {
                    if (is_rmdir) {
                        try handleCowRmdir(h.normalized, supervisor);
                    } else {
                        try handleCowUnlink(h.normalized, supervisor);
                    }
                    logger.log("unlinkat: removed {s} (rmdir={any})", .{ h.normalized, is_rmdir });
                    return replySuccess(notif.id, 0);
                },
                .tmp => {
                    if (is_rmdir) {
                        try handleTmpRmdir(h.normalized, supervisor);
                    } else {
                        try handleTmpUnlink(h.normalized, supervisor);
                    }
                    logger.log("unlinkat: removed {s} (rmdir={any})", .{ h.normalized, is_rmdir });
                    return replySuccess(notif.id, 0);
                },
            }
        },
    }
}

fn handleCowUnlink(normalized: []const u8, supervisor: *Supervisor) !void {
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        if (supervisor.tombstones.isAncestorTombstoned(normalized)) {
            return error.NOENT;
        }

        const parent = std.fs.path.dirname(normalized) orelse "/";
        if (supervisor.overlay.guestPathExists(parent) and !supervisor.overlay.isGuestDir(parent)) {
            return error.NOTDIR;
        }

        if (supervisor.tombstones.isTombstoned(normalized)) {
            return error.NOENT;
        }
        if (!supervisor.overlay.guestPathExists(normalized)) {
            return error.NOENT;
        }
        if (supervisor.overlay.isGuestDir(normalized)) {
            return error.ISDIR;
        }

        try supervisor.tombstones.add(normalized);
    }

    // Physical cleanup: remove overlay copy if it exists
    Cow.unlink(&supervisor.overlay, normalized);
}

fn handleCowRmdir(normalized: []const u8, supervisor: *Supervisor) !void {
    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    if (supervisor.tombstones.isAncestorTombstoned(normalized)) {
        return error.NOENT;
    }

    const parent = std.fs.path.dirname(normalized) orelse "/";
    if (supervisor.overlay.guestPathExists(parent) and !supervisor.overlay.isGuestDir(parent)) {
        return error.NOTDIR;
    }

    if (supervisor.tombstones.isTombstoned(normalized)) {
        return error.NOENT;
    }
    if (!supervisor.overlay.guestPathExists(normalized)) {
        return error.NOENT;
    }
    if (!supervisor.overlay.isGuestDir(normalized)) {
        return error.NOTDIR;
    }

    // Check directory is empty from guest perspective (merged view)
    var scratch = ScratchArena.init(supervisor.allocator);
    defer scratch.deinit();
    const empty = try cow_mod.isDirEmpty(scratch.allocator(), normalized, &supervisor.overlay, &supervisor.tombstones);
    if (!empty) {
        return error.NOTEMPTY;
    }

    supervisor.tombstones.removeChildren(normalized);
    try supervisor.tombstones.add(normalized);

    // Physical cleanup (ignore errors — tombstone is the source of truth)
    Cow.rmdir(&supervisor.overlay, normalized);
}

fn handleTmpUnlink(normalized: []const u8, supervisor: *Supervisor) !void {
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        if (supervisor.tombstones.isAncestorTombstoned(normalized)) {
            return error.NOENT;
        }

        const parent = std.fs.path.dirname(normalized) orelse "/tmp";
        if (!std.mem.eql(u8, parent, "/tmp")) {
            if (supervisor.overlay.tmpExists(parent) and !supervisor.overlay.isTmpDir(parent)) {
                return error.NOTDIR;
            }
        }

        if (supervisor.tombstones.isTombstoned(normalized)) {
            return error.NOENT;
        }
        if (!supervisor.overlay.tmpExists(normalized)) {
            return error.NOENT;
        }
        if (supervisor.overlay.isTmpDir(normalized)) {
            return error.ISDIR;
        }

        try supervisor.tombstones.add(normalized);
    }

    Tmp.unlink(&supervisor.overlay, normalized);
}

fn handleTmpRmdir(normalized: []const u8, supervisor: *Supervisor) !void {
    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    if (supervisor.tombstones.isAncestorTombstoned(normalized)) {
        return error.NOENT;
    }

    const parent = std.fs.path.dirname(normalized) orelse "/tmp";
    if (!std.mem.eql(u8, parent, "/tmp")) {
        if (supervisor.overlay.tmpExists(parent) and !supervisor.overlay.isTmpDir(parent)) {
            return error.NOTDIR;
        }
    }

    if (supervisor.tombstones.isTombstoned(normalized)) {
        return error.NOENT;
    }
    if (!supervisor.overlay.tmpExists(normalized)) {
        return error.NOENT;
    }
    if (!supervisor.overlay.isTmpDir(normalized)) {
        return error.NOTDIR;
    }

    // Check emptiness: read overlay entries, filter tombstoned children
    var scratch = ScratchArena.init(supervisor.allocator);
    defer scratch.deinit();
    const empty = try tmp_mod.isDirEmpty(scratch.allocator(), &supervisor.overlay, normalized, &supervisor.tombstones);
    if (!empty) {
        return error.NOTEMPTY;
    }

    supervisor.tombstones.removeChildren(normalized);
    try supervisor.tombstones.add(normalized);

    // Physical cleanup (ignore errors — tombstone is the source of truth)
    Tmp.rmdir(&supervisor.overlay, normalized);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const mkdirat = @import("mkdirat.zig");

fn makeUnlinkatNotif(pid: AbsTid, path: [*:0]const u8, flags: u32) linux.SECCOMP.notif {
    return makeNotif(.unlinkat, .{
        .pid = pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path),
        .arg2 = flags,
    });
}

fn makeMkdiratNotif(pid: AbsTid, path: [*:0]const u8, mode: u32) linux.SECCOMP.notif {
    return makeNotif(.mkdirat, .{
        .pid = pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path),
        .arg2 = mode,
    });
}

test "unlinkat blocked path returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.PERM, handle(makeUnlinkatNotif(init_tid, "/sys/something", 0), &supervisor));
}

test "unlinkat non-existent path returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.NOENT, handle(makeUnlinkatNotif(init_tid, "/tmp/does_not_exist.txt", 0), &supervisor));
}

test "unlinkat on tombstoned path returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try supervisor.tombstones.add("/etc/passwd");
    try testing.expectError(error.NOENT, handle(makeUnlinkatNotif(init_tid, "/etc/passwd", 0), &supervisor));
}

test "unlinkat file on COW path tombstones it" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /etc/hostname exists on the real FS and is a file
    const resp = try handle(makeUnlinkatNotif(init_tid, "/etc/hostname", 0), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Should now be tombstoned
    try testing.expect(supervisor.tombstones.isTombstoned("/etc/hostname"));
}

test "unlinkat without REMOVEDIR on directory returns EISDIR" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /etc is a directory
    try testing.expectError(error.ISDIR, handle(makeUnlinkatNotif(init_tid, "/etc", 0), &supervisor));
}

test "unlinkat with REMOVEDIR on file returns ENOTDIR" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.NOTDIR, handle(makeUnlinkatNotif(init_tid, "/etc/hostname", linux.AT.REMOVEDIR), &supervisor));
}

test "unlinkat REMOVEDIR on empty tmp dir succeeds" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a directory in /tmp, then rmdir it
    const mk_resp = try mkdirat.handle(makeMkdiratNotif(init_tid, "/tmp/test_rmdir_empty", 0o755), &supervisor);
    try testing.expectEqual(@as(i64, 0), mk_resp.val);

    const resp = try handle(makeUnlinkatNotif(init_tid, "/tmp/test_rmdir_empty", linux.AT.REMOVEDIR), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    try testing.expect(supervisor.tombstones.isTombstoned("/tmp/test_rmdir_empty"));
}

test "unlinkat REMOVEDIR on non-empty COW dir returns ENOTEMPTY" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /etc has children, so rmdir should fail
    try testing.expectError(error.NOTEMPTY, handle(makeUnlinkatNotif(init_tid, "/etc", linux.AT.REMOVEDIR), &supervisor));
}

test "unlinkat empty path returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.INVAL, handle(makeUnlinkatNotif(init_tid, "", 0), &supervisor));
}

test "unlinkat with invalid flags returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.INVAL, handle(makeUnlinkatNotif(init_tid, "/tmp/foo", 0x300), &supervisor));
}

test "unlinkat REMOVEDIR on '.' returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.INVAL, handle(makeUnlinkatNotif(init_tid, ".", linux.AT.REMOVEDIR), &supervisor));
}

test "unlinkat unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Use relative path so handler must look up caller's cwd, triggering ESRCH
    try testing.expectError(error.SRCH, handle(makeUnlinkatNotif(999, "foo", 0), &supervisor));
}

test "unlinkat with file as parent on COW path returns ENOTDIR" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // /etc/hostname is a file, not a directory
    try testing.expectError(error.NOTDIR, handle(makeUnlinkatNotif(init_tid, "/etc/hostname/foo", 0), &supervisor));
}

test "after unlinkat, path is tombstoned and fstatat64 returns ENOENT" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Unlink a real file
    const resp = try handle(makeUnlinkatNotif(init_tid, "/etc/hostname", 0), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Verify tombstoned
    try testing.expect(supervisor.tombstones.isTombstoned("/etc/hostname"));

    // Verify fstatat64 would also see it as deleted
    const fstatat64 = @import("fstatat64.zig");
    const stat_notif = makeNotif(.fstatat64, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/etc/hostname")),
        .arg2 = @intFromPtr(&@as(@import("../../../types.zig").Stat, undefined)),
        .arg3 = @as(u64, 0),
    });
    try testing.expectError(error.NOENT, fstatat64.handle(stat_notif, &supervisor));
}

test "unlinkat file in /tmp tombstones and physically deletes" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a file in /tmp via openat
    const openat = @import("openat.zig");
    const openat_notif = makeNotif(.openat, .{
        .pid = init_tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(@as([*:0]const u8, "/tmp/test_unlink_file.txt")),
        .arg2 = @as(u32, @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true })),
        .arg3 = @as(u64, 0o644),
    });
    const open_resp = try openat.handle(openat_notif, &supervisor);
    try testing.expect(open_resp.val >= 3);

    // Now unlink it
    const resp = try handle(makeUnlinkatNotif(init_tid, "/tmp/test_unlink_file.txt", 0), &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);

    try testing.expect(supervisor.tombstones.isTombstoned("/tmp/test_unlink_file.txt"));
    // Physical file should be gone from overlay
    try testing.expect(!supervisor.overlay.tmpExists("/tmp/test_unlink_file.txt"));
}
