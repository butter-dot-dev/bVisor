const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Proc = @import("../../proc/Proc.zig");
const File = @import("../../fs/file.zig").File;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

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

    // Handle stdin - passthrough to kernel
    if (fd == linux.STDIN_FILENO) {
        logger.log("readv: passthrough for stdin", .{});
        return replyContinue(notif.id);
    }

    // Ensure calling process exists
    const proc = supervisor.guest_procs.get(pid) catch {
        logger.log("readv: process lookup failed for pid: {d}", .{pid});
        return replyErr(notif.id, .SRCH);
    };

    // Look up the virtual FD
    const file = proc.fd_table.get(fd) orelse {
        logger.log("readv: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Read iovec array from child memory
    var iovecs: [MAX_IOV]posix.iovec = undefined;
    var total_requested: usize = 0;

    for (0..iovec_count) |i| {
        const iov_addr = iovec_ptr + i * @sizeOf(posix.iovec);
        iovecs[i] = memory_bridge.read(posix.iovec, pid, iov_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
        total_requested += iovecs[i].len;
    }

    // Perform read into supervisor-local buf
    // It's ok to only partially resolve count if count is larger than we're willing to stack allocate
    // This is valid POSIX behavior
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(total_requested, max_len);
    const read_buf: []u8 = max_buf[0..max_count];
    const n = file.read(read_buf) catch |err| {
        logger.log("readv: error reading from fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    // Distribute the read data across the child's iovec buffers
    var bytes_written: usize = 0;
    for (0..iovec_count) |i| {
        if (bytes_written >= n) break;

        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const remaining = n - bytes_written;
        const to_write = @min(iov.len, remaining);

        if (to_write > 0) {
            memory_bridge.writeSlice(read_buf[bytes_written..][0..to_write], pid, buf_ptr) catch {
                return replyErr(notif.id, .FAULT);
            };
            bytes_written += to_write;
        }
    }

    logger.log("readv: read {d} bytes", .{n});
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

test "readv from stdin returns continue" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    var buf: [32]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf, .len = buf.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = 100,
        .arg0 = linux.STDIN_FILENO,
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isContinue(resp));
}

test "readv from invalid fd returns EBADF" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);

    var buf: [32]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf, .len = buf.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = 100,
        .arg0 = 99, // invalid fd
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.BADF)))), resp.@"error");
}

test "readv distributes data across multiple iovecs" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);
    const proc = supervisor.guest_procs.lookup.get(100).?;

    // Insert a proc file for guest pid 12345 (produces "12345\n")
    const file = File{ .proc = .{ .guest_pid = 12345, .offset = 0 } };
    const vfd = try proc.fd_table.insert(file);

    // Use two small buffers to test distribution
    var buf1: [3]u8 = undefined;
    var buf2: [3]u8 = undefined;
    var iovecs = [_]posix.iovec{
        .{ .base = &buf1, .len = buf1.len },
        .{ .base = &buf2, .len = buf2.len },
    };

    const notif = makeNotif(.readv, .{
        .pid = 100,
        .arg0 = @as(u32, @bitCast(vfd)),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = iovecs.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 6), resp.val);

    // First buffer should have "123"
    try testing.expectEqualStrings("123", &buf1);
    // Second buffer should have "45\n"
    try testing.expectEqualStrings("45\n", &buf2);
}
