const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_addr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    // Virtualize stdout/stderr: capture into log buffer
    if (fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        const max_len = 4096;
        var max_buf: [max_len]u8 = undefined;
        const max_count = @min(count, max_len);
        const buf: []u8 = max_buf[0..max_count];
        memory_bridge.readSlice(buf, @intCast(caller_tid), buf_addr) catch {
            return replyErr(notif.id, .FAULT);
        };
        if (fd == linux.STDOUT_FILENO) {
            supervisor.stdout.write(supervisor.io, buf) catch {
                return replyErr(notif.id, .IO);
            };
        } else {
            supervisor.stderr.write(supervisor.io, buf) catch {
                return replyErr(notif.id, .IO);
            };
        }
        return replySuccess(notif.id, @intCast(max_count));
    }

    // Critical section: File lookup
    // File refcounting allows us to keep a pointer to the file outside of the critical section
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        // Get caller Thread
        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            logger.log("write: Thread not found for tid={d}: {}", .{ caller_tid, err });
            return replyErr(notif.id, .SRCH);
        };
        std.debug.assert(caller.tid == caller_tid);

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("write: EBADF for fd={d}", .{fd});
            return replyErr(notif.id, .BADF);
        };
    }
    defer file.unref();

    // Copy caller Thread buf to local
    const max_len = 4096;
    var max_buf: [max_len]u8 = undefined;
    const max_count = @min(count, max_len);
    const buf: []u8 = max_buf[0..max_count];
    memory_bridge.readSlice(buf, @intCast(caller_tid), buf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };

    // Write local buf to file
    const n = file.write(buf) catch |err| {
        logger.log("write: error writing to fd: {s}", .{@errorName(err)});
        return replyErr(notif.id, .IO);
    };

    logger.log("write: wrote {d} bytes", .{n});
    return replySuccess(notif.id, @intCast(n));
}

// ============================================================================
// Tests
// ============================================================================

const Threads = @import("../../proc/Threads.zig");
const FdTable = @import("../../fs/FdTable.zig");
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const Tmp = @import("../../fs/backend/tmp.zig").Tmp;

test "write to FD 1 (stdout) captures into log buffer" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const io = testing.io;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var data = "hello".*;
    const notif = makeNotif(.write, .{
        .pid = init_tid,
        .arg0 = 1, // stdout
        .arg1 = @intFromPtr(&data),
        .arg2 = data.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 5), resp.val);
}

test "write to FD 2 (stderr) captures into log buffer" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const io = testing.io;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var data = "error".*;
    const notif = makeNotif(.write, .{
        .pid = init_tid,
        .arg0 = 2, // stderr
        .arg1 = @intFromPtr(&data),
        .arg2 = data.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 5), resp.val);
}

test "write stdout: write, write, drain, write, drain" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const io = testing.io;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // write "aaa"
    var d1 = "aaa".*;
    const r1 = handle(makeNotif(.write, .{
        .pid = init_tid,
        .arg0 = 1,
        .arg1 = @intFromPtr(&d1),
        .arg2 = d1.len,
    }), &supervisor);
    try testing.expect(!isError(r1));

    // write "bbb"
    var d2 = "bbb".*;
    const r2 = handle(makeNotif(.write, .{
        .pid = init_tid,
        .arg0 = 1,
        .arg1 = @intFromPtr(&d2),
        .arg2 = d2.len,
    }), &supervisor);
    try testing.expect(!isError(r2));

    // drain — should see "aaabbb"
    const drain1 = try supervisor.stdout.read(allocator, io);
    defer allocator.free(drain1);
    try testing.expectEqualStrings("aaabbb", drain1);

    // write "ccc"
    var d3 = "ccc".*;
    const r3 = handle(makeNotif(.write, .{
        .pid = init_tid,
        .arg0 = 1,
        .arg1 = @intFromPtr(&d3),
        .arg2 = d3.len,
    }), &supervisor);
    try testing.expect(!isError(r3));

    // drain — should see only "ccc"
    const drain2 = try supervisor.stdout.read(allocator, io);
    defer allocator.free(drain2);
    try testing.expectEqualStrings("ccc", drain2);
}

test "write count=0 returns 0" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a tmp file to write to
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const tmp_file = try Tmp.open(&supervisor.overlay, "/tmp/write_test_0", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .tmp = tmp_file }), .{});

    var data: [0]u8 = undefined;
    const notif = makeNotif(.write, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&data),
        .arg2 = 0,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "write to non-existent VFD returns EBADF" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var data = "hello".*;
    const notif = makeNotif(.write, .{
        .pid = init_tid,
        .arg0 = 99, // non-existent
        .arg1 = @intFromPtr(&data),
        .arg2 = data.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), resp.@"error");
}

test "write with unknown caller PID returns ESRCH" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var data = "hello".*;
    const notif = makeNotif(.write, .{
        .pid = 999,
        .arg0 = 3,
        .arg1 = @intFromPtr(&data),
        .arg2 = data.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.SRCH))), resp.@"error");
}

test "write to read-only backend (proc) returns EIO" {
    const LogBuffer = @import("../../../LogBuffer.zig");
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const proc_file = try ProcFile.open(caller, "/proc/self");
    const vfd = try caller.fd_table.insert(try File.init(allocator, .{ .proc = proc_file }), .{});

    var data = "test".*;
    const notif = makeNotif(.write, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&data),
        .arg2 = data.len,
    });

    const resp = handle(notif, &supervisor);
    try testing.expect(isError(resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.IO))), resp.@"error");
}
