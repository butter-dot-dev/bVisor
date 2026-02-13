const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: connect(sockfd, addr, addrlen)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const addr_ptr: u64 = notif.data.arg1;
    const addrlen: u32 = @truncate(notif.data.arg2);

    // Validate addrlen (sockaddr_storage max is 128)
    if (addrlen == 0 or addrlen > 128) {
        return LinuxErr.INVAL;
    }

    // Critical section: File lookup
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            logger.log("connect: Thread not found for tid={d}: {}", .{ caller_tid, err });
            return LinuxErr.SRCH;
        };

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("connect: EBADF for fd={d}", .{fd});
            return LinuxErr.BADF;
        };
    }
    defer file.unref();

    // Read sockaddr from guest memory
    var addr_buf: [128]u8 = undefined;
    memory_bridge.readSlice(addr_buf[0..addrlen], caller_tid, addr_ptr) catch {
        return LinuxErr.FAULT;
    };

    file.connect(&addr_buf, addrlen) catch |err| {
        return switch (err) {
            error.NotASocket => LinuxErr.NOTSOCK,
            else => LinuxErr.IO,
        };
    };

    logger.log("connect: fd={d} success", .{fd});
    return replySuccess(notif.id, 0);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const socket_handler = @import("socket.zig");

test "connect unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var addr = std.mem.zeroes(linux.sockaddr.un);
    const notif = makeNotif(.connect, .{
        .pid = 999,
        .arg0 = 3,
        .arg1 = @intFromPtr(&addr),
        .arg2 = @sizeOf(linux.sockaddr.un),
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}

test "connect invalid vfd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var addr = std.mem.zeroes(linux.sockaddr.un);
    const notif = makeNotif(.connect, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&addr),
        .arg2 = @sizeOf(linux.sockaddr.un),
    });

    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "connect on non-socket file returns ENOTSOCK" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Insert a proc file (not a socket)
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }), .{});

    var addr = std.mem.zeroes(linux.sockaddr.un);
    const notif = makeNotif(.connect, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&addr),
        .arg2 = @sizeOf(linux.sockaddr.un),
    });

    try testing.expectError(error.NOTSOCK, handle(notif, &supervisor));
}

test "connect UDP socket to localhost succeeds" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a UDP socket via socket handler
    const sock_notif = makeNotif(.socket, .{
        .pid = init_tid,
        .arg0 = linux.AF.INET,
        .arg1 = linux.SOCK.DGRAM,
        .arg2 = 0,
    });
    const sock_resp = try socket_handler.handle(sock_notif, &supervisor);
    const vfd: i32 = @intCast(sock_resp.val);

    // UDP connect just sets the default destination, always succeeds
    var addr = std.mem.zeroes(linux.sockaddr.in);
    addr.family = linux.AF.INET;
    addr.port = std.mem.nativeToBig(u16, 12345);
    addr.addr = std.mem.nativeToBig(u32, 0x7f000001); // 127.0.0.1

    const notif = makeNotif(.connect, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&addr),
        .arg2 = @sizeOf(linux.sockaddr.in),
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 0), resp.val);
}
