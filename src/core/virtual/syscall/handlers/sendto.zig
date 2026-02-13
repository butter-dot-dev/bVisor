const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: sendto(sockfd, buf, len, flags, dest_addr, addrlen)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_addr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);
    const flags: u32 = @truncate(notif.data.arg3);
    const dest_addr_ptr: u64 = notif.data.arg4;
    const addrlen: u32 = @truncate(notif.data.arg5);

    // Critical section: File lookup
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("sendto: EBADF for fd={d}", .{fd});
            return LinuxErr.BADF;
        };
    }
    defer file.unref();

    // Read data from child memory
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(count, max_len);
    const data: []u8 = max_buf[0..max_count];
    try memory_bridge.readSlice(data, caller_tid, buf_addr);

    // Conditionally include a destination address
    // https://man7.org/linux/man-pages/man3/sendto.3p.html#DESCRIPTION
    // When a socket has .connect called on it, the kernel maintains the destination state for the FD
    // But if the socket is not connected, the destination must be passed in every time
    // file.sendTo accepts an optional destDir, and behaves like plain .send for null

    // Read dest_addr from child memory if provided
    var addr_buf: [128]u8 = undefined;
    const dest_addr: ?[*]const u8 = if (dest_addr_ptr != 0 and addrlen > 0 and addrlen <= 128) blk: {
        try memory_bridge.readSlice(addr_buf[0..addrlen], caller_tid, dest_addr_ptr);
        break :blk &addr_buf;
    } else null;

    const actual_addrlen: linux.socklen_t = if (dest_addr != null) addrlen else 0;

    const n = try file.sendTo(data, flags, dest_addr, actual_addrlen);

    logger.log("sendto: fd={d} sent {d} bytes", .{ fd, n });
    return replySuccess(notif.id, @intCast(n));
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const socketpair_handler = @import("socketpair.zig");

test "sendto unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var data = "hello".*;
    const notif = makeNotif(.sendto, .{
        .pid = 999,
        .arg0 = 3,
        .arg1 = @intFromPtr(&data),
        .arg2 = data.len,
        .arg3 = 0,
        .arg4 = 0,
        .arg5 = 0,
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}

test "sendto invalid vfd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var data = "hello".*;
    const notif = makeNotif(.sendto, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&data),
        .arg2 = data.len,
        .arg3 = 0,
        .arg4 = 0,
        .arg5 = 0,
    });

    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "sendto on non-socket file returns ENOTSOCK" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }), .{});

    var data = "hello".*;
    const notif = makeNotif(.sendto, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&data),
        .arg2 = data.len,
        .arg3 = 0,
        .arg4 = 0,
        .arg5 = 0,
    });

    try testing.expectError(error.NOTSOCK, handle(notif, &supervisor));
}

test "sendto on socketpair succeeds" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a socketpair
    var sv: [2]i32 = .{ -1, -1 };
    const sp_notif = makeNotif(.socketpair, .{
        .pid = init_tid,
        .arg0 = linux.AF.UNIX,
        .arg1 = linux.SOCK.STREAM,
        .arg2 = 0,
        .arg3 = @intFromPtr(&sv),
    });
    _ = try socketpair_handler.handle(sp_notif, &supervisor);

    // Send data on sv[0]
    var data = "sendto test".*;
    const notif = makeNotif(.sendto, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[0]))),
        .arg1 = @intFromPtr(&data),
        .arg2 = data.len,
        .arg3 = 0,
        .arg4 = 0,
        .arg5 = 0,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, @intCast(data.len)), resp.val);
}

test "sendto + recvfrom round-trip" {
    const recvfrom_handler = @import("recvfrom.zig");
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a socketpair
    var sv: [2]i32 = .{ -1, -1 };
    const sp_notif = makeNotif(.socketpair, .{
        .pid = init_tid,
        .arg0 = linux.AF.UNIX,
        .arg1 = linux.SOCK.STREAM,
        .arg2 = 0,
        .arg3 = @intFromPtr(&sv),
    });
    _ = try socketpair_handler.handle(sp_notif, &supervisor);

    // Send data on sv[0]
    var send_data = "round-trip test data".*;
    const send_notif = makeNotif(.sendto, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[0]))),
        .arg1 = @intFromPtr(&send_data),
        .arg2 = send_data.len,
        .arg3 = 0,
        .arg4 = 0,
        .arg5 = 0,
    });
    _ = try handle(send_notif, &supervisor);

    // Recv on sv[1]
    var recv_buf: [64]u8 = undefined;
    const recv_notif = makeNotif(.recvfrom, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[1]))),
        .arg1 = @intFromPtr(&recv_buf),
        .arg2 = recv_buf.len,
        .arg3 = 0,
    });
    const recv_resp = try recvfrom_handler.handle(recv_notif, &supervisor);
    const n: usize = @intCast(recv_resp.val);
    try testing.expectEqualStrings("round-trip test data", recv_buf[0..n]);
}
