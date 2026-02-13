const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../LinuxErr.zig").LinuxErr;
const checkErr = @import("../../../LinuxErr.zig").checkErr;
const iovec_const = std.posix.iovec_const;
const types = @import("../../../types.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

const MAX_IOV = 16;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const iovec_ptr: u64 = notif.data.arg1;
    const iovec_count: usize = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV);

    // Virtualize stdout/stderr: gather iovecs and capture into log buffer
    if (fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        var stdio_iovecs: [MAX_IOV]iovec_const = undefined;
        var stdio_buf: [4096]u8 = undefined;
        var stdio_len: usize = 0;

        for (0..iovec_count) |i| {
            const iov_addr = iovec_ptr + i * @sizeOf(iovec_const);
            stdio_iovecs[i] = memory_bridge.read(iovec_const, caller_tid, iov_addr) catch {
                return LinuxErr.FAULT;
            };
        }

        for (0..iovec_count) |i| {
            const iov = stdio_iovecs[i];
            const buf_ptr = @intFromPtr(iov.base);
            const buf_len = @min(iov.len, stdio_buf.len - stdio_len);
            if (buf_len > 0) {
                memory_bridge.readSlice(stdio_buf[stdio_len..][0..buf_len], caller_tid, buf_ptr) catch {
                    return LinuxErr.FAULT;
                };
                stdio_len += buf_len;
            }
        }

        if (fd == linux.STDOUT_FILENO) {
            supervisor.stdout.write(supervisor.io, stdio_buf[0..stdio_len]) catch {
                return LinuxErr.IO;
            };
        } else {
            supervisor.stderr.write(supervisor.io, stdio_buf[0..stdio_len]) catch {
                return LinuxErr.IO;
            };
        }
        return replySuccess(notif.id, @intCast(stdio_len));
    }

    // Critical section: File lookup
    // File refcounting allows us to keep a pointer to the file outside of the critical section
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        // Get caller Thread
        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            logger.log("writev: Thread not found for tid={d}: {}", .{ caller_tid, err });
            return LinuxErr.SRCH;
        };
        std.debug.assert(caller.tid == caller_tid);

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("writev: EBADF for fd={d}", .{fd});
            return LinuxErr.BADF;
        };
    }
    defer file.unref();

    // Read iovec array from child memory
    var iovecs: [MAX_IOV]iovec_const = undefined;
    var data_buf: [4096]u8 = undefined;
    var data_len: usize = 0;

    for (0..iovec_count) |i| {
        const iov_addr = iovec_ptr + i * @sizeOf(iovec_const);
        iovecs[i] = memory_bridge.read(iovec_const, caller_tid, iov_addr) catch {
            return LinuxErr.FAULT;
        };
    }

    // Read buffer data from child memory for each iovec
    for (0..iovec_count) |i| {
        const iov = iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, data_buf.len - data_len);

        if (buf_len > 0) {
            const dest = data_buf[data_len..][0..buf_len];
            memory_bridge.readSlice(dest, caller_tid, buf_ptr) catch {
                return LinuxErr.FAULT;
            };
            data_len += buf_len;
        }
    }

    // Write to the File
    const n = file.write(data_buf[0..data_len]) catch |err| {
        logger.log("writev: error writing to fd: {s}", .{@errorName(err)});
        return LinuxErr.IO;
    };

    logger.log("writev: wrote {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const FdTable = @import("../../fs/FdTable.zig");
const Tmp = @import("../../fs/backend/tmp.zig").Tmp;

test "writev single iovec writes data" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const tmp_file = try Tmp.open(&supervisor.overlay, "/tmp/writev_test1", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .tmp = tmp_file }), .{});

    const data = "hello";
    var iovecs = [_]iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 5), resp.val);
}

test "writev multiple iovecs concatenated write" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const tmp_file = try Tmp.open(&supervisor.overlay, "/tmp/writev_test2", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .tmp = tmp_file }), .{});

    const d1 = "hel";
    const d2 = "lo ";
    const d3 = "world";
    var iovecs = [_]iovec_const{
        .{ .base = d1.ptr, .len = d1.len },
        .{ .base = d2.ptr, .len = d2.len },
        .{ .base = d3.ptr, .len = d3.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 3,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 11), resp.val);
}

test "writev FD 1 (stdout) captures into log buffer" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const io = testing.io;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, io, generateUid(io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const data = "hello";
    var iovecs = [_]iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = 1, // stdout
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 5), resp.val);
}

test "writev FD 2 (stderr) captures into log buffer" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const io = testing.io;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, io, generateUid(io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const data = "error";
    var iovecs = [_]iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = 2, // stderr
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expectEqual(@as(i64, 5), resp.val);
}

test "writev stdout: write, write, drain, write, drain" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const io = testing.io;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, io, generateUid(io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // writev "hel" + "lo "
    const d1a = "hel";
    const d1b = "lo ";
    var iovecs1 = [_]iovec_const{
        .{ .base = d1a.ptr, .len = d1a.len },
        .{ .base = d1b.ptr, .len = d1b.len },
    };
    try handle(makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = 1,
        .arg1 = @intFromPtr(&iovecs1),
        .arg2 = 2,
    }), &supervisor);

    // writev "world"
    const d2 = "world";
    var iovecs2 = [_]iovec_const{
        .{ .base = d2.ptr, .len = d2.len },
    };
    try handle(makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = 1,
        .arg1 = @intFromPtr(&iovecs2),
        .arg2 = 1,
    }), &supervisor);

    // drain — should see "hel" + "lo " + "world"
    const drain1 = try supervisor.stdout.read(allocator, io);
    defer allocator.free(drain1);
    try testing.expectEqualStrings("hello world", drain1);

    // writev "!"
    const d3 = "!";
    var iovecs3 = [_]iovec_const{
        .{ .base = d3.ptr, .len = d3.len },
    };
    try handle(makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = 1,
        .arg1 = @intFromPtr(&iovecs3),
        .arg2 = 1,
    }), &supervisor);

    // drain — should see only "!"
    const drain2 = try supervisor.stdout.read(allocator, io);
    defer allocator.free(drain2);
    try testing.expectEqualStrings("!", drain2);
}

test "writev non-existent VFD returns EBADF" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const data = "hello";
    var iovecs = [_]iovec_const{
        .{ .base = data.ptr, .len = data.len },
    };

    const notif = makeNotif(.writev, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&iovecs),
        .arg2 = 1,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(if (resp) |_| false else |_| true);
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}
