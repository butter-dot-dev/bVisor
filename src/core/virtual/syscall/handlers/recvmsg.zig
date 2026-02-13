const std = @import("std");
const linux = std.os.linux;
const iovec = std.posix.iovec;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

const MAX_IOV = 16;

/// Recvmsg is the scattered read version of recv
/// Similar to how readv is a scatter of read
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: recvmsg(sockfd, msg, flags)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const msg_ptr: u64 = notif.data.arg1;
    const flags: u32 = @truncate(notif.data.arg2);

    // Critical section: File lookup
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            logger.log("recvmsg: Thread not found for tid={d}: {}", .{ caller_tid, err });
            return replyErr(notif.id, .SRCH);
        };

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("recvmsg: EBADF for fd={d}", .{fd});
            return replyErr(notif.id, .BADF);
        };
    }
    defer file.unref();

    // Read msghdr from guest memory
    // This is the scattered iovecs
    var msg = memory_bridge.read(linux.msghdr, caller_tid, msg_ptr) catch {
        return replyErr(notif.id, .FAULT);
    };

    // Read iovec array from guest memory
    const iovec_count = @min(msg.iovlen, MAX_IOV);
    var iovecs: [MAX_IOV]iovec = undefined;
    var total_requested: usize = 0;

    for (0..iovec_count) |i| {
        const iov_addr = @intFromPtr(msg.iov) + i * @sizeOf(iovec);
        iovecs[i] = memory_bridge.read(iovec, caller_tid, iov_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
        total_requested += iovecs[i].len;
    }

    // Receive into supervisor-local buffer, with optional source address
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(total_requested, max_len);
    const recv_buf: []u8 = max_buf[0..max_count];

    var addr_buf: [128]u8 align(@alignOf(linux.sockaddr)) = undefined;
    var src_addrlen: linux.socklen_t = @sizeOf(@TypeOf(addr_buf));
    const wants_addr = msg.name != null;

    const n = file.recvFrom(
        recv_buf,
        flags,
        if (wants_addr) &addr_buf else null,
        if (wants_addr) &src_addrlen else null,
    ) catch |err| {
        return switch (err) {
            error.NotASocket => replyErr(notif.id, .NOTSOCK),
            else => replyErr(notif.id, .IO),
        };
    };

    // Scatter received data across guest iov buffers
    var bytes_written: usize = 0;
    for (0..iovec_count) |i| {
        if (bytes_written >= n) break;

        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const remaining = n - bytes_written;
        const to_write = @min(iov.len, remaining);

        if (to_write > 0) {
            memory_bridge.writeSlice(recv_buf[bytes_written..][0..to_write], caller_tid, buf_ptr) catch {
                return replyErr(notif.id, .FAULT);
            };
            bytes_written += to_write;
        }
    }

    // Write source address into guest's name buffer
    if (wants_addr and src_addrlen > 0) {
        const copy_len = @min(src_addrlen, msg.namelen);
        if (copy_len > 0) {
            memory_bridge.writeSlice(addr_buf[0..copy_len], caller_tid, @intFromPtr(msg.name.?)) catch {
                return replyErr(notif.id, .FAULT);
            };
        }
    }

    // Write back updated msghdr
    msg.namelen = if (wants_addr) src_addrlen else 0;
    msg.controllen = 0;
    msg.flags = 0;
    memory_bridge.write(linux.msghdr, caller_tid, msg, msg_ptr) catch {
        return replyErr(notif.id, .FAULT);
    };

    logger.log("recvmsg: fd={d} received {d} bytes", .{ fd, n });
    return replySuccess(notif.id, @intCast(n));
}

const testing = std.testing;
const iovec_const = std.posix.iovec_const;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const socketpair_handler = @import("socketpair.zig");
const sendmsg_handler = @import("sendmsg.zig");
const sendto_handler = @import("sendto.zig");

test "recvmsg unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var recv_buf: [64]u8 = undefined;
    var iov = [_]iovec{
        .{ .base = &recv_buf, .len = recv_buf.len },
    };
    var msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const notif = makeNotif(.recvmsg, .{
        .pid = 999,
        .arg0 = 3,
        .arg1 = @intFromPtr(&msg),
        .arg2 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}

test "recvmsg invalid vfd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var recv_buf: [64]u8 = undefined;
    var iov = [_]iovec{
        .{ .base = &recv_buf, .len = recv_buf.len },
    };
    var msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const notif = makeNotif(.recvmsg, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&msg),
        .arg2 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}

test "recvmsg on non-socket file returns ENOTSOCK" {
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

    var recv_buf: [64]u8 = undefined;
    var iov = [_]iovec{
        .{ .base = &recv_buf, .len = recv_buf.len },
    };
    var msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const notif = makeNotif(.recvmsg, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&msg),
        .arg2 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.NOTSOCK))), resp.@"error");
}

test "recvmsg on socketpair with single iovec" {
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
    const sp_resp = socketpair_handler.handle(sp_notif, &supervisor);
    try testing.expect(!isError(sp_resp));

    // Send data via sendto on sv[0]
    var send_data = "hello recvmsg".*;
    const send_notif = makeNotif(.sendto, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[0]))),
        .arg1 = @intFromPtr(&send_data),
        .arg2 = send_data.len,
        .arg3 = 0,
        .arg4 = 0,
        .arg5 = 0,
    });
    const send_resp = sendto_handler.handle(send_notif, &supervisor);
    try testing.expect(!isError(send_resp));

    // Receive via recvmsg on sv[1]
    var recv_buf: [64]u8 = undefined;
    var iov = [_]iovec{
        .{ .base = &recv_buf, .len = recv_buf.len },
    };
    var msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const notif = makeNotif(.recvmsg, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[1]))),
        .arg1 = @intFromPtr(&msg),
        .arg2 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    const n: usize = @intCast(resp.val);
    try testing.expectEqualStrings("hello recvmsg", recv_buf[0..n]);
}

test "sendmsg + recvmsg multi-iovec scatter round-trip" {
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
    const sp_resp = socketpair_handler.handle(sp_notif, &supervisor);
    try testing.expect(!isError(sp_resp));

    // sendmsg with 3 iovecs: "aaa", "bbb", "ccc"
    var d1 = "aaa".*;
    var d2 = "bbb".*;
    var d3 = "ccc".*;
    var send_iov = [_]iovec_const{
        .{ .base = &d1, .len = d1.len },
        .{ .base = &d2, .len = d2.len },
        .{ .base = &d3, .len = d3.len },
    };
    var send_msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &send_iov,
        .iovlen = 3,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const send_notif = makeNotif(.sendmsg, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[0]))),
        .arg1 = @intFromPtr(&send_msg),
        .arg2 = 0,
    });
    const send_resp = sendmsg_handler.handle(send_notif, &supervisor);
    try testing.expect(!isError(send_resp));
    try testing.expectEqual(@as(i64, 9), send_resp.val);

    // recvmsg with 3 iovecs of len 3 each
    var r1: [3]u8 = undefined;
    var r2: [3]u8 = undefined;
    var r3: [3]u8 = undefined;
    var recv_iov = [_]iovec{
        .{ .base = &r1, .len = 3 },
        .{ .base = &r2, .len = 3 },
        .{ .base = &r3, .len = 3 },
    };
    var recv_msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &recv_iov,
        .iovlen = 3,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const recv_notif = makeNotif(.recvmsg, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[1]))),
        .arg1 = @intFromPtr(&recv_msg),
        .arg2 = 0,
    });
    const recv_resp = handle(recv_notif, &supervisor);
    try testing.expect(!isError(recv_resp));
    try testing.expectEqual(@as(i64, 9), recv_resp.val);

    // Verify scatter correctness
    try testing.expectEqualStrings("aaa", &r1);
    try testing.expectEqualStrings("bbb", &r2);
    try testing.expectEqualStrings("ccc", &r3);
}
