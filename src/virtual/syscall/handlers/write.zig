const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Proc = @import("../../proc/Proc.zig");
const OpenFile = @import("../../fs/OpenFile.zig").OpenFile;
const Supervisor = @import("../../../Supervisor.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

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
    const max_buf: [max_len]u8 = undefined;
    const max_count = @min(count, max_len);
    const buf: []u8 = max_buf[0..max_count];
    memory_bridge.readSlice(buf, @intCast(pid), buf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };

    // Write local buf to file
    const n = try file.write(buf);

    logger.log("write: wrote {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

test "write to stdout returns success" {
    // Zig test harness uses stdout for IPC so we can't test this :(
}

test "write to stderr returns success" {
    // The below passes, but for reason similar to above, the prints cause zig test to format weird

    //     const allocator = testing.allocator;
    //     const guest_pid: Proc.SupervisorPID = 100;
    //     var supervisor = try Supervisor.init(allocator, testing.io, -1, guest_pid);
    //     defer supervisor.deinit();

    //     const test_data = "hello stderr";
    //     const notif = makeNotif(.write, .{
    //         .pid = guest_pid,
    //         .arg0 = linux.STDERR_FILENO,
    //         .arg1 = @intFromPtr(test_data.ptr),
    //         .arg2 = test_data.len,
    //     });

    //     const resp = handle(notif, &supervisor);
    //     try testing.expect(!isError(resp));
    //     try testing.expectEqual(@as(i64, @intCast(test_data.len)), resp.val);
}

test "write to invalid fd returns EBADF" {
    const allocator = testing.allocator;
    const guest_pid: Proc.SupervisorPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, guest_pid);
    defer supervisor.deinit();

    const test_data = "test";
    const notif = makeNotif(.write, .{
        .pid = guest_pid,
        .arg0 = 999, // invalid fd
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intFromEnum(linux.E.BADF)), resp.@"error");
}

test "write to kernel fd works" {
    const allocator = testing.allocator;
    const guest_pid: Proc.SupervisorPID = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, guest_pid);
    defer supervisor.deinit();

    // Create a temp file and open it
    const OpenAt = @import("OpenAt.zig");
    const test_path = "/tmp/bvisor_write_test.txt";

    // Set up I/O for file operations
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    // Clean up any existing file
    std.Io.Dir.deleteFileAbsolute(io, test_path) catch {};
    defer std.Io.Dir.deleteFileAbsolute(io, test_path) catch {};

    // Open file for writing
    const open_notif = makeNotif(.openat, .{
        .pid = guest_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(test_path),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true }))),
        .arg3 = 0o644,
    });
    const open_res = OpenAt.handle(open_notif, &supervisor);
    try testing.expect(!isError(open_res));
    const vfd: i32 = @intCast(open_res.val);

    // Write to the file
    const test_data = "hello write";
    const write_notif = makeNotif(.write, .{
        .pid = guest_pid,
        .arg0 = @as(u64, @intCast(vfd)),
        .arg1 = @intFromPtr(test_data.ptr),
        .arg2 = test_data.len,
    });

    const write_res = handle(write_notif, &supervisor);
    try testing.expect(!isError(write_res));
    try testing.expectEqual(@as(i64, @intCast(test_data.len)), write_res.val);

    // Close and verify by reading the file
    const proc = supervisor.guest_procs.lookup.get(guest_pid).?;
    var fd = proc.fd_table.get(vfd).?;
    fd.close();
    _ = proc.fd_table.remove(vfd);

    // Read back via a new open - COW should have the content
    const read_notif = makeNotif(.openat, .{
        .pid = guest_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(test_path),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });
    const read_open_res = OpenAt.handle(read_notif, &supervisor);
    try testing.expect(!isError(read_open_res));

    const read_vfd: i32 = @intCast(read_open_res.val);
    const proc2 = supervisor.guest_procs.lookup.get(guest_pid).?;
    var read_fd = proc2.fd_table.get(read_vfd).?;
    var buf: [64]u8 = undefined;
    const n = try read_fd.read(&buf);
    try testing.expectEqualStrings(test_data, buf[0..n]);

    read_fd.close();
}
