const std = @import("std");
const linux = std.os.linux;
const Proc = @import("../../proc/Proc.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const pid: Proc.SupervisorPID = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));

    // Passthrough stdin/stdout/stderr
    if (fd == linux.STDIN_FILENO or fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        logger.log("close: passthrough for fd={d}", .{fd});
        return replyContinue(notif.id);
    }

    // Look up the calling process
    const proc = supervisor.guest_procs.lookup.get(pid) orelse {
        logger.log("close: process not found for pid={d}", .{pid});
        return replyErr(notif.id, .SRCH);
    };

    // Look up the file in the fd table
    const file = proc.fd_table.get(fd) orelse {
        logger.log("close: EBADF for fd={d}", .{fd});
        return replyErr(notif.id, .BADF);
    };

    // Close the file
    file.close();

    // Remove from fd table
    _ = proc.fd_table.remove(fd);

    logger.log("close: closed fd={d}", .{fd});
    return replySuccess(notif.id, 0);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const Procs = @import("../../proc/Procs.zig");
const FdTable = @import("../../fs/FdTable.zig");
const File = @import("../../fs/file.zig").File;
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

test "close stdin returns continue" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    const notif = makeNotif(.close, .{ .pid = 100, .arg0 = linux.STDIN_FILENO });
    const resp = handle(notif, supervisor);

    try testing.expect(isContinue(resp));
}

test "close stdout returns continue" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    const notif = makeNotif(.close, .{ .pid = 100, .arg0 = linux.STDOUT_FILENO });
    const resp = handle(notif, supervisor);

    try testing.expect(isContinue(resp));
}

test "close stderr returns continue" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    const notif = makeNotif(.close, .{ .pid = 100, .arg0 = linux.STDERR_FILENO });
    const resp = handle(notif, supervisor);

    try testing.expect(isContinue(resp));
}

test "close invalid fd returns EBADF" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    // Register a process
    try supervisor.guest_procs.handleInitialProcess(100);

    const notif = makeNotif(.close, .{ .pid = 100, .arg0 = 99 });
    const resp = handle(notif, supervisor);

    try testing.expect(isError(resp));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.BADF)))), resp.@"error");
}

test "close valid vfd succeeds" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    // Register a process
    try supervisor.guest_procs.handleInitialProcess(100);
    const proc = supervisor.guest_procs.lookup.get(100).?;

    // Insert a dummy file (proc backend doesn't need real fd)
    const file = File{ .proc = .{ .guest_pid = 1, .offset = 0 } };
    const vfd = try proc.fd_table.insert(file);

    const notif = makeNotif(.close, .{ .pid = 100, .arg0 = @as(u32, @bitCast(vfd)) });
    const resp = handle(notif, supervisor);

    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);

    // Verify fd was removed
    try testing.expect(proc.fd_table.get(vfd) == null);
}

test "double close returns EBADF" {
    const supervisor = try testSupervisor();
    defer cleanupSupervisor(supervisor);

    // Register a process
    try supervisor.guest_procs.handleInitialProcess(100);
    const proc = supervisor.guest_procs.lookup.get(100).?;

    // Insert a dummy file
    const file = File{ .proc = .{ .guest_pid = 1, .offset = 0 } };
    const vfd = try proc.fd_table.insert(file);

    // First close should succeed
    const notif1 = makeNotif(.close, .{ .pid = 100, .arg0 = @as(u32, @bitCast(vfd)) });
    const resp1 = handle(notif1, supervisor);
    try testing.expect(!isError(resp1));

    // Second close should return EBADF
    const notif2 = makeNotif(.close, .{ .pid = 100, .arg0 = @as(u32, @bitCast(vfd)) });
    const resp2 = handle(notif2, supervisor);
    try testing.expect(isError(resp2));
    try testing.expectEqual(@as(i32, -@as(i32, @intCast(@intFromEnum(linux.E.BADF)))), resp2.@"error");
}
