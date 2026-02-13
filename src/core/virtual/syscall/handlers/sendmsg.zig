const std = @import("std");
const linux = std.os.linux;
const iovec_const = std.posix.iovec_const;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

const MAX_IOV = 16;

/// Sendmsg is the scattered write version of sendto
/// Similar to how writev is a scatter of write
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: sendmsg(sockfd, msg, flags)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const msg_ptr: u64 = notif.data.arg1;
    const flags: u32 = @truncate(notif.data.arg2);

    // Critical section: File lookup
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("sendmsg: EBADF for fd={d}", .{fd});
            return LinuxErr.BADF;
        };
    }
    defer file.unref();

    // Read msghdr from guest memory
    // This is the scattered iovecs
    const msg = try memory_bridge.read(linux.msghdr_const, caller_tid, msg_ptr);

    // Read iovec array from guest memory and gather data
    const iovec_count = @min(msg.iovlen, MAX_IOV);
    var data_buf: [4096]u8 = undefined;
    var data_len: usize = 0;

    for (0..iovec_count) |i| {
        const iov_addr = @intFromPtr(msg.iov) + i * @sizeOf(iovec_const);
        const iov = try memory_bridge.read(iovec_const, caller_tid, iov_addr);

        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, data_buf.len - data_len);
        if (buf_len > 0) {
            try memory_bridge.readSlice(data_buf[data_len..][0..buf_len], caller_tid, buf_ptr);
            data_len += buf_len;
        }
    }

    // Read optional destination address
    var addr_buf: [128]u8 = undefined;
    const dest_addr: ?[*]const u8 = if (msg.name != null and msg.namelen > 0 and msg.namelen <= 128) blk: {
        try memory_bridge.readSlice(addr_buf[0..msg.namelen], caller_tid, @intFromPtr(msg.name.?));
        break :blk &addr_buf;
    } else null;

    const actual_addrlen: linux.socklen_t = if (dest_addr != null) msg.namelen else 0;

    const n = try file.sendTo(data_buf[0..data_len], flags, dest_addr, actual_addrlen);

    logger.log("sendmsg: fd={d} sent {d} bytes", .{ fd, n });
    return replySuccess(notif.id, @intCast(n));
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const socketpair_handler = @import("socketpair.zig");

test "sendmsg unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var data = "hello".*;
    var iov = [_]iovec_const{
        .{ .base = &data, .len = data.len },
    };
    var msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const notif = makeNotif(.sendmsg, .{
        .pid = 999,
        .arg0 = 3,
        .arg1 = @intFromPtr(&msg),
        .arg2 = 0,
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}

test "sendmsg invalid vfd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var data = "hello".*;
    var iov = [_]iovec_const{
        .{ .base = &data, .len = data.len },
    };
    var msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const notif = makeNotif(.sendmsg, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&msg),
        .arg2 = 0,
    });

    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "sendmsg on non-socket file returns ENOTSOCK" {
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
    var iov = [_]iovec_const{
        .{ .base = &data, .len = data.len },
    };
    var msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const notif = makeNotif(.sendmsg, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&msg),
        .arg2 = 0,
    });

    try testing.expectError(error.NOTSOCK, handle(notif, &supervisor));
}

test "sendmsg on socketpair with single iovec succeeds" {
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

    // Send data via sendmsg on sv[0]
    var data = "single iov msg".*;
    var iov = [_]iovec_const{
        .{ .base = &data, .len = data.len },
    };
    var msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const notif = makeNotif(.sendmsg, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[0]))),
        .arg1 = @intFromPtr(&msg),
        .arg2 = 0,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, @intCast(data.len)), resp.val);
}

test "sendmsg multi-iovec + recvfrom round-trip" {
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

    // sendmsg with multiple iovecs
    var d1 = "aaa".*;
    var d2 = "bbb".*;
    var d3 = "ccc".*;
    var iov = [_]iovec_const{
        .{ .base = &d1, .len = d1.len },
        .{ .base = &d2, .len = d2.len },
        .{ .base = &d3, .len = d3.len },
    };
    var msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 3,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const send_notif = makeNotif(.sendmsg, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[0]))),
        .arg1 = @intFromPtr(&msg),
        .arg2 = 0,
    });
    const send_resp = try handle(send_notif, &supervisor);
    try testing.expectEqual(@as(i64, 9), send_resp.val);

    // recvfrom on sv[1]
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
    try testing.expectEqualStrings("aaabbbccc", recv_buf[0..n]);
}
