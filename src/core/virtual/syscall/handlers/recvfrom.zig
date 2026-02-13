const std = @import("std");
const linux = std.os.linux;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: recvfrom(sockfd, buf, len, flags, src_addr, addrlen)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_addr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);
    const flags: u32 = @truncate(notif.data.arg3);
    const src_addr_ptr: u64 = notif.data.arg4;
    const addrlen_ptr: u64 = notif.data.arg5;

    // Critical section: File lookup
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            logger.log("recvfrom: Thread not found for tid={d}: {}", .{ caller_tid, err });
            return replyErr(notif.id, .SRCH);
        };

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("recvfrom: EBADF for fd={d}", .{fd});
            return replyErr(notif.id, .BADF);
        };
    }
    defer file.unref();

    // Receive into supervisor-local buffer, with optional source address
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(count, max_len);
    const recv_buf: []u8 = max_buf[0..max_count];

    var addr_buf: [128]u8 align(@alignOf(linux.sockaddr)) = undefined;
    var src_addrlen: linux.socklen_t = @sizeOf(@TypeOf(addr_buf));
    const wants_addr = src_addr_ptr != 0 and addrlen_ptr != 0;

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

    // Write received data to child memory
    if (n > 0) {
        memory_bridge.writeSlice(recv_buf[0..n], caller_tid, buf_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
    }

    // Write source address back to guest memory
    if (wants_addr) {
        if (src_addrlen > 0) {
            const guest_addrlen = memory_bridge.read(linux.socklen_t, caller_tid, addrlen_ptr) catch {
                return replyErr(notif.id, .FAULT);
            };
            const copy_len = @min(src_addrlen, guest_addrlen);
            if (copy_len > 0) {
                memory_bridge.writeSlice(addr_buf[0..copy_len], caller_tid, src_addr_ptr) catch {
                    return replyErr(notif.id, .FAULT);
                };
            }
        }
        memory_bridge.write(linux.socklen_t, caller_tid, src_addrlen, addrlen_ptr) catch {
            return replyErr(notif.id, .FAULT);
        };
    }

    logger.log("recvfrom: fd={d} received {d} bytes", .{ fd, n });
    return replySuccess(notif.id, @intCast(n));
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const socketpair_handler = @import("socketpair.zig");
const sendto_handler = @import("sendto.zig");

test "recvfrom unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.recvfrom, .{
        .pid = 999,
        .arg0 = 3,
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
        .arg3 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}

test "recvfrom invalid vfd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.recvfrom, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
        .arg3 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}

test "recvfrom on non-socket file returns ENOTSOCK" {
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

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.recvfrom, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
        .arg3 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.NOTSOCK))), resp.@"error");
}

test "recvfrom on socketpair receives sent data" {
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

    // Send data on sv[0]
    var send_data = "hello from recvfrom test".*;
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

    // Recv on sv[1]
    var recv_buf: [64]u8 = undefined;
    const notif = makeNotif(.recvfrom, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[1]))),
        .arg1 = @intFromPtr(&recv_buf),
        .arg2 = recv_buf.len,
        .arg3 = 0,
    });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    const n: usize = @intCast(resp.val);
    try testing.expect(n > 0);
    try testing.expectEqualStrings("hello from recvfrom test", recv_buf[0..n]);
}
