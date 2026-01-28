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

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const pid: Proc.SupervisorPID = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_addr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    // Handle stdin - passthrough to kernel
    if (fd == linux.STDIN_FILENO) {
        logger.log("read: passthrough for stdin", .{});
        return replyContinue(notif.id);
    }

    // Ensure calling process exists
    const proc = supervisor.guest_procs.lookup.get(pid) orelse {
        logger.log("read: process lookup failed for pid: {d}", .{pid});
        return replyErr(notif.id, .SRCH);
    };

    // Look up the virtual FD
    const file = proc.fd_table.get(fd) orelse {
        logger.log("read: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Perform read into supervisor-local buf
    // It's ok to only partially resolve count if count is larger than we're willing to stack allocate
    // This is valid POSIX behavior
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(count, max_len);
    const read_buf: []u8 = max_buf[0..max_count];

    const n = file.read(read_buf) catch |err| {
        logger.log("read: error reading from fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    // Copy into child memory space
    if (n > 0) {
        memory_bridge.writeSlice(read_buf[0..n], @intCast(notif.pid), buf_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
    }

    logger.log("read: read {d} bytes", .{n});
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

test "read from stdin returns continue" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    var buf: [32]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = 100,
        .arg0 = linux.STDIN_FILENO,
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isContinue(resp));
}

test "read from invalid fd returns EBADF" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);

    var buf: [32]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = 100,
        .arg0 = 99, // invalid fd
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.BADF)))), resp.@"error");
}

test "read from proc fd returns guest pid as string" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    try supervisor.guest_procs.handleInitialProcess(100);
    const proc = supervisor.guest_procs.lookup.get(100).?;

    // Insert a proc file for guest pid 42
    const file = File{ .proc = .{ .guest_pid = 42, .offset = 0 } };
    const vfd = try proc.fd_table.insert(file);

    var buf: [32]u8 = undefined;
    const notif = makeNotif(.read, .{
        .pid = 100,
        .arg0 = @as(u32, @bitCast(vfd)),
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    const resp = handle(notif, supervisor);
    try testing.expect(!isError(resp));
    try testing.expect(resp.val > 0);
    // The buffer should contain "42\n"
    try testing.expectEqualStrings("42\n", buf[0..@intCast(resp.val)]);
}
