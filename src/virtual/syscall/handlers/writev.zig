const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const SupervisorFD = types.SupervisorFD;
const Proc = @import("../../proc/Proc.zig");
const File = @import("../../fs/file.zig").File;
const Supervisor = @import("../../../Supervisor.zig");
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const MAX_IOV = 16;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const pid: Proc.SupervisorPID = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const iovec_ptr: u64 = notif.data.arg1;
    const iovec_count: usize = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV);

    // Continue in case of stdout or stderr
    // In the future we'll virtualize this ourselves for more control of where logs go
    if (fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        return replyContinue(notif.id);
    }

    // From here, fd is a virtualFD returned by openat
    // Look up the calling process
    const proc = supervisor.guest_procs.lookup.get(pid) orelse {
        logger.log("writev: process not found for pid={d}", .{pid});
        return replyErr(notif.id, .SRCH);
    };

    // Look up the file object
    const file = proc.fd_table.get(fd) orelse {
        logger.log("writev: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Read iovec array from child memory
    var iovecs: [MAX_IOV]posix.iovec_const = undefined;
    var data_buf: [4096]u8 = undefined;
    var data_len: usize = 0;

    for (0..iovec_count) |i| {
        const iov_addr = iovec_ptr + i * @sizeOf(posix.iovec_const);
        iovecs[i] = memory_bridge.read(posix.iovec_const, pid, iov_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
    }

    // Read buffer data from child memory for each iovec
    for (0..iovec_count) |i| {
        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, data_buf.len - data_len);

        if (buf_len > 0) {
            const dest = data_buf[data_len..][0..buf_len];
            memory_bridge.readSlice(dest, pid, buf_ptr) catch {
                return replyErr(notif.id, .FAULT);
            };
            data_len += buf_len;
        }
    }

    // Write to the file
    const n = file.write(data_buf[0..data_len]) catch |err| {
        logger.log("writev: error writing to fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    logger.log("writev: wrote {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
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

test "writev to stdout returns continue" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    const data1 = "hello";
    const data2 = "world";
    var iovecs = [_]posix.iovec_const{
        .{ .base = data1.ptr, .len = data1.len },
        .{ .base = data2.ptr, .len = data2.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = 100,
        .arg0 = linux.STDOUT_FILENO,
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isContinue(resp));
}

test "writev to stderr returns continue" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    const data = "error";
    var iovecs = [_]posix.iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = 100,
        .arg0 = linux.STDERR_FILENO,
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isContinue(resp));
}

test "writev to invalid fd returns EBADF" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);

    const data = "data";
    var iovecs = [_]posix.iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = 100,
        .arg0 = 99, // invalid fd
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.BADF)))), resp.@"error");
}

test "writev gathers data from multiple iovecs" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);
    const proc = supervisor.guest_procs.lookup.get(100).?;

    // Insert a proc file (writes will fail with EIO since proc is read-only)
    const file = File{ .proc = .{ .guest_pid = 1, .offset = 0 } };
    const vfd = try proc.fd_table.insert(file);

    const data1 = "hello";
    const data2 = "world";
    var iovecs = [_]posix.iovec_const{
        .{ .base = data1.ptr, .len = data1.len },
        .{ .base = data2.ptr, .len = data2.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = 100,
        .arg0 = @as(u32, @bitCast(vfd)),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const resp = handle(notif, supervisor);
    // Proc files are read-only, so write returns EIO
    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.IO)))), resp.@"error");
}
