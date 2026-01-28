const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Proc = @import("../../proc/Proc.zig");
const File = @import("../../fs/file.zig").File;
const path_router = @import("../../path.zig");
const Supervisor = @import("../../../Supervisor.zig");
const types = @import("../../../types.zig");
const SupervisorFD = types.SupervisorFD;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    const pid: Proc.SupervisorPID = @intCast(notif.pid);

    // Ensure calling process exists
    const proc = supervisor.guest_procs.lookup.get(pid) orelse {
        logger.log("openat: process lookup failed for pid: {d}", .{pid});
        return replyErr(notif.id, .SRCH);
    };

    // Read path from guest memory
    const path_ptr: u64 = notif.data.arg1;
    var path_buf: [256]u8 = undefined;
    const path = memory_bridge.readString(&path_buf, pid, path_ptr) catch |err| {
        logger.log("openat: failed to read path string: {}", .{err});
        return replyErr(notif.id, .FAULT);
    };

    // Only absolute paths supported for now
    const dirfd: SupervisorFD = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    _ = dirfd; // dirfd only matters for relative paths
    if (path.len == 0 or path[0] != '/') {
        logger.log("openat: path must be absolute: {s}", .{path});
        return replyErr(notif.id, .INVAL);
    }

    // Route the path to determine which backend handles it
    const route_result = path_router.route(path) catch {
        logger.log("openat: path normalization failed for: {s}", .{path});
        return replyErr(notif.id, .INVAL);
    };

    switch (route_result) {
        .block => {
            logger.log("openat: blocked path: {s}", .{path});
            return replyErr(notif.id, .PERM);
        },
        .handle => |backend| {
            // Convert linux.O to posix.O
            const linux_flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg2)));
            const flags = linuxToPosixFlags(linux_flags);
            const mode: posix.mode_t = @truncate(notif.data.arg3);

            // Open the file via the appropriate backend
            const file = File.open(backend, &supervisor.overlay, path, flags, mode) catch |err| {
                logger.log("openat: failed to open {s}: {s}", .{ path, @errorName(err) });
                return replyErr(notif.id, .IO);
            };

            // Insert into fd table and return the virtual fd
            const vfd = proc.fd_table.insert(file) catch {
                logger.log("openat: failed to insert fd", .{});
                return replyErr(notif.id, .MFILE);
            };

            logger.log("openat: opened {s} as vfd={d}", .{ path, vfd });
            return replySuccess(notif.id, @intCast(vfd));
        },
    }
}

/// Convert linux.O flags to posix.O flags at the syscall boundary
fn linuxToPosixFlags(linux_flags: linux.O) posix.O {
    var flags: posix.O = .{};

    flags.ACCMODE = switch (linux_flags.ACCMODE) {
        .RDONLY => .RDONLY,
        .WRONLY => .WRONLY,
        .RDWR => .RDWR,
    };

    if (linux_flags.CREAT) flags.CREAT = true;
    if (linux_flags.EXCL) flags.EXCL = true;
    if (linux_flags.TRUNC) flags.TRUNC = true;
    if (linux_flags.APPEND) flags.APPEND = true;
    if (linux_flags.NONBLOCK) flags.NONBLOCK = true;
    if (linux_flags.CLOEXEC) flags.CLOEXEC = true;
    if (linux_flags.DIRECTORY) flags.DIRECTORY = true;

    return flags;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const Procs = @import("../../proc/Procs.zig");
const OverlayRoot = @import("../../OverlayRoot.zig");

fn testSupervisor() !*Supervisor {
    const allocator = testing.allocator;
    const supervisor = try allocator.create(Supervisor);
    supervisor.* = .{
        .allocator = allocator,
        .io = undefined,
        .init_guest_pid = 100,
        .notify_fd = -1,
        .logger = .{ .name = .supervisor },
        .guest_procs = Procs.init(allocator),
        .overlay = .{ .uid = "testtesttesttest".* },
    };
    return supervisor;
}

fn cleanupSupervisor(supervisor: *Supervisor) void {
    supervisor.guest_procs.deinit();
    supervisor.allocator.destroy(supervisor);
}

test "open blocked path returns EPERM" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);

    // Path in memory - /sys/class/net is blocked
    const path = "/sys/class/net";
    const notif = makeNotif(.openat, .{
        .pid = 100,
        .arg0 = 0, // dirfd (ignored for absolute paths)
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0, // flags
        .arg3 = 0, // mode
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.PERM)))), resp.@"error");
}

test "open /proc/self succeeds, returns vfd >= 3" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);

    const path = "/proc/self";
    const notif = makeNotif(.openat, .{
        .pid = 100,
        .arg0 = 0,
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0,
        .arg3 = 0,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(!isError(resp));
    try testing.expect(resp.val >= 3);
}

test "open with invalid (non-absolute) path returns EINVAL" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);

    const path = "relative/path";
    const notif = makeNotif(.openat, .{
        .pid = 100,
        .arg0 = 0,
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0,
        .arg3 = 0,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.INVAL)))), resp.@"error");
}

test "process lookup failure returns ESRCH" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    // Don't register pid 100, so lookup will fail
    const path = "/proc/self";
    const notif = makeNotif(.openat, .{
        .pid = 100,
        .arg0 = 0,
        .arg1 = @intFromPtr(path.ptr),
        .arg2 = 0,
        .arg3 = 0,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.SRCH)))), resp.@"error");
}
