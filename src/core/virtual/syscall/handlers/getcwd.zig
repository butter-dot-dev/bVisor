const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

const memory_bridge = @import("../../../utils/memory_bridge.zig");

/// Writes the current working directory (null-terminated) into the caller's buffer.
/// Returns the length of the path including the null terminator on success
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: getcwd(char *buf, size_t size)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const buf_addr: u64 = notif.data.arg0;
    const buf_size: u64 = notif.data.arg1;

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        logger.log("getcwd: Thread not found for tid={d}: {}", .{ caller_tid, err });
        return LinuxErr.SRCH;
    };
    std.debug.assert(caller.tid == caller_tid);

    const cwd = caller.fs_info.cwd;

    // Linux getcwd returns ERANGE if buffer is too small
    // Required size includes the null terminator
    if (buf_size < cwd.len + 1) {
        return LinuxErr.RANGE;
    }

    // Write the null-terminated cwd to the caller's buffer
    memory_bridge.writeString(cwd, caller_tid, buf_addr) catch {
        return LinuxErr.FAULT;
    };

    // Return length including null terminator
    return replySuccess(notif.id, @intCast(cwd.len + 1));
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

test "getcwd returns / for initial thread" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [256]u8 = undefined;
    const notif = makeNotif(.getcwd, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(&buf),
        .arg1 = buf.len,
    });
    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 2), resp.val); // "/" + null = 2
    try testing.expectEqualStrings("/", std.mem.sliceTo(&buf, 0));
}

test "getcwd returns ERANGE when buffer too small" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [1]u8 = undefined;
    const notif = makeNotif(.getcwd, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(&buf),
        .arg1 = buf.len, // 1 byte, too small for "/" + null
    });
    try testing.expectError(error.RANGE, handle(notif, &supervisor));
}

test "getcwd returns ESRCH for unknown tid" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [256]u8 = undefined;
    const notif = makeNotif(.getcwd, .{
        .pid = 999,
        .arg0 = @intFromPtr(&buf),
        .arg1 = buf.len,
    });
    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}

test "getcwd reflects cwd change" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Manually change cwd via fs_info
    const thread = supervisor.guest_threads.lookup.get(init_tid).?;
    try thread.fs_info.setCwd("/tmp");

    var buf: [256]u8 = undefined;
    const notif = makeNotif(.getcwd, .{
        .pid = init_tid,
        .arg0 = @intFromPtr(&buf),
        .arg1 = buf.len,
    });
    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 5), resp.val); // "/tmp" + null = 5
    try testing.expectEqualStrings("/tmp", std.mem.sliceTo(&buf, 0));
}
