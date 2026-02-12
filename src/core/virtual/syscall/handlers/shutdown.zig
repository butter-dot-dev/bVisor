const std = @import("std");
const linux = std.os.linux;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: shutdown(sockfd, how)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const how: i32 = @bitCast(@as(u32, @truncate(notif.data.arg1)));

    // Critical section: File lookup
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            logger.log("shutdown: Thread not found for tid={d}: {}", .{ caller_tid, err });
            return replyErr(notif.id, .SRCH);
        };

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("shutdown: EBADF for fd={d}", .{fd});
            return replyErr(notif.id, .BADF);
        };
    }
    defer file.unref();

    file.shutdown(how) catch |err| {
        return switch (err) {
            error.NotASocket => replyErr(notif.id, .NOTSOCK),
            else => replyErr(notif.id, .IO),
        };
    };

    logger.log("shutdown: fd={d} how={d} success", .{ fd, how });
    return replySuccess(notif.id, 0);
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isError = @import("../../../seccomp/notif.zig").isError;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const memory_bridge = @import("../../../utils/memory_bridge.zig");
const socketpair_handler = @import("socketpair.zig");

test "shutdown unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.shutdown, .{
        .pid = 999,
        .arg0 = 3,
        .arg1 = linux.SHUT.RD,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}

test "shutdown invalid vfd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.shutdown, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = linux.SHUT.RD,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}

test "shutdown on socketpair succeeds" {
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

    // Shutdown one end for writing
    const notif = makeNotif(.shutdown, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[0]))),
        .arg1 = linux.SHUT.WR,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}
