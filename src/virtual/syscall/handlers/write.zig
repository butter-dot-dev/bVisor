const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Proc = @import("../../proc/Proc.zig");
const File = @import("../../fs/file.zig").File;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const pid: Proc.SupervisorPID = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_addr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    // Continue in case of stdout or stderr
    // In the future we'll virtualize this ourselves for more control of where logs go
    if (fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        return replyContinue(notif.id);
    }

    // From here, fd is a virtualFD returned by openat
    // Look up the calling process
    const proc = supervisor.guest_procs.lookup.get(pid) orelse {
        logger.log("write: process not found for pid={d}", .{pid});
        return replyErr(notif.id, .SRCH);
    };

    // Look up the file object
    const file = proc.fd_table.get(fd) orelse {
        logger.log("write: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Copy guest process buf to local
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(count, max_len);
    const buf: []u8 = max_buf[0..max_count];
    memory_bridge.readSlice(buf, @intCast(pid), buf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };

    // Write local buf to file
    const n = file.write(buf) catch |err| {
        logger.log("write: error writing to fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    logger.log("write: wrote {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

// ============================================================================
// Tests
// ============================================================================

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

test "write to stdout returns continue" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    const data = "hello";
    const notif = makeNotif(.write, .{
        .pid = 100,
        .arg0 = linux.STDOUT_FILENO,
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isContinue(resp));
}

test "write to stderr returns continue" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    const data = "error";
    const notif = makeNotif(.write, .{
        .pid = 100,
        .arg0 = linux.STDERR_FILENO,
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isContinue(resp));
}

test "write to invalid fd returns EBADF" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);

    const data = "data";
    const notif = makeNotif(.write, .{
        .pid = 100,
        .arg0 = 99, // invalid fd
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.BADF)))), resp.@"error");
}

test "write to proc fd returns EIO (read-only)" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);
    const proc = supervisor.guest_procs.lookup.get(100).?;

    // Insert a proc file (proc files are read-only)
    const file = File{ .proc = .{ .guest_pid = 1, .offset = 0 } };
    const vfd = try proc.fd_table.insert(file);

    const data = "data";
    const notif = makeNotif(.write, .{
        .pid = 100,
        .arg0 = @as(u32, @bitCast(vfd)),
        .arg1 = @intFromPtr(data.ptr),
        .arg2 = data.len,
    });

    const resp = handle(notif, supervisor);
    // Proc files return error.ReadOnlyFileSystem which gets converted to EIO
    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.IO)))), resp.@"error");
}
