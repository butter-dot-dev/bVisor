const std = @import("std");
const linux = std.os.linux;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const testing = std.testing;

const Supervisor = @import("../../Supervisor.zig");
const LinuxErr = @import("../../linux_error.zig").LinuxErr;
const LogBuffer = @import("../../LogBuffer.zig");
const generateUid = @import("../../setup.zig").generateUid;
const Thread = @import("../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const NsTid = Thread.NsTid;
const Threads = @import("../proc/Threads.zig");
const CloneFlags = Threads.CloneFlags;
const File = @import("../fs/file.zig").File;
const ProcFile = @import("../fs/backend/procfile.zig").ProcFile;
const Tmp = @import("../fs/backend/tmp.zig").Tmp;

const makeNotif = @import("../../seccomp/notif.zig").makeNotif;
const isContinue = @import("../../seccomp/notif.zig").isContinue;

const openat_handler = @import("handlers/openat.zig").handle;
const read_handler = @import("handlers/read.zig").handle;
const write_handler = @import("handlers/write.zig").handle;
const close_handler = @import("handlers/close.zig").handle;
const readv_handler = @import("handlers/readv.zig").handle;
const writev_handler = @import("handlers/writev.zig").handle;
const fstat_handler = @import("handlers/fstatat64.zig").handle;
const socketpair_handler = @import("handlers/socketpair.zig").handle;
const sendto_handler = @import("handlers/sendto.zig").handle;
const recvfrom_handler = @import("handlers/recvfrom.zig").handle;
const shutdown_handler = @import("handlers/shutdown.zig").handle;
const sendmsg_handler = @import("handlers/sendmsg.zig").handle;
const recvmsg_handler = @import("handlers/recvmsg.zig").handle;

const Stat = @import("../../types.zig").Stat;

const proc_info = @import("../../utils/proc_info.zig");

fn makeFstatNotif(tid: AbsTid, vfd: i32, statbuf: *Stat) linux.SECCOMP.notif {
    return makeNotif(.fstatat64, .{
        .pid = tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))), // dirfd
        .arg1 = @intFromPtr(@as([*:0]const u8, "")), // empty pathname
        .arg2 = @intFromPtr(statbuf), // statbuf
        .arg3 = 0x1000, // AT_EMPTY_PATH
    });
}

fn makeOpenatNotif(tid: AbsTid, path: [*:0]const u8, flags: u32, mode: u32) linux.SECCOMP.notif {
    return makeNotif(.openat, .{
        .pid = tid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path),
        .arg2 = flags,
        .arg3 = mode,
    });
}

fn makeReadNotif(tid: AbsTid, vfd: i32, buf: *anyopaque, count: usize) linux.SECCOMP.notif {
    return makeNotif(.read, .{
        .pid = tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(buf),
        .arg2 = count,
    });
}

fn makeWriteNotif(tid: AbsTid, vfd: i32, buf: *const anyopaque, count: usize) linux.SECCOMP.notif {
    return makeNotif(.write, .{
        .pid = tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(buf),
        .arg2 = count,
    });
}

fn makeCloseNotif(tid: AbsTid, vfd: i32) linux.SECCOMP.notif {
    return makeNotif(.close, .{
        .pid = tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
    });
}

test "open proc -> read -> close returns NsTid" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Open /proc/self
    const open_resp = try openat_handler(
        makeOpenatNotif(init_tid, "/proc/self", 0, 0),
        &supervisor,
    );
    const vfd: i32 = @intCast(open_resp.val);
    try testing.expect(vfd >= 3);

    // Read
    var buf: [64]u8 = undefined;
    const read_resp = try read_handler(
        makeReadNotif(init_tid, vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expectEqualStrings("100\n", buf[0..@intCast(read_resp.val)]);

    // Close
    _ = try close_handler(
        makeCloseNotif(init_tid, vfd),
        &supervisor,
    );
}

test "open tmp -> write -> close -> reopen -> read -> close" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Open /tmp/e2e_test.txt with CREAT|WRONLY|TRUNC
    const creat_flags: u32 = @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true });
    const open_resp1 = try openat_handler(
        makeOpenatNotif(init_tid, "/tmp/e2e_test.txt", creat_flags, 0o644),
        &supervisor,
    );
    const write_vfd: i32 = @intCast(open_resp1.val);

    // Write data
    var write_data = "hello e2e".*;
    const write_resp = try write_handler(
        makeWriteNotif(init_tid, write_vfd, &write_data, write_data.len),
        &supervisor,
    );
    try testing.expectEqual(@as(i64, 9), write_resp.val);

    // Close
    _ = try close_handler(
        makeCloseNotif(init_tid, write_vfd),
        &supervisor,
    );

    // Reopen RDONLY
    const open_resp2 = try openat_handler(
        makeOpenatNotif(init_tid, "/tmp/e2e_test.txt", 0, 0),
        &supervisor,
    );
    const read_vfd: i32 = @intCast(open_resp2.val);

    // Read back
    var buf: [64]u8 = undefined;
    const read_resp = try read_handler(
        makeReadNotif(init_tid, read_vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expectEqualStrings("hello e2e", buf[0..@intCast(read_resp.val)]);

    // Close
    _ = try close_handler(
        makeCloseNotif(init_tid, read_vfd),
        &supervisor,
    );
}

test "three files open simultaneously, each returns correct data" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Open a proc file
    const proc_resp = try openat_handler(
        makeOpenatNotif(init_tid, "/proc/self", 0, 0),
        &supervisor,
    );
    const proc_vfd: i32 = @intCast(proc_resp.val);

    // Open /dev/null
    const devnull_resp = try openat_handler(
        makeOpenatNotif(init_tid, "/dev/null", 0, 0),
        &supervisor,
    );
    const devnull_vfd: i32 = @intCast(devnull_resp.val);

    // Open a tmp file
    const creat_flags: u32 = @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true });
    const tmp_resp = try openat_handler(
        makeOpenatNotif(init_tid, "/tmp/e2e_multi.txt", creat_flags, 0o644),
        &supervisor,
    );
    const tmp_vfd: i32 = @intCast(tmp_resp.val);

    // All VFDs should be different
    try testing.expect(proc_vfd != devnull_vfd);
    try testing.expect(proc_vfd != tmp_vfd);
    try testing.expect(devnull_vfd != tmp_vfd);

    // Read from proc file
    var buf: [64]u8 = undefined;
    const proc_read = try read_handler(
        makeReadNotif(init_tid, proc_vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expectEqualStrings("100\n", buf[0..@intCast(proc_read.val)]);

    // Read from /dev/null - should return 0 (EOF)
    const devnull_read = try read_handler(
        makeReadNotif(init_tid, devnull_vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expectEqual(@as(i64, 0), devnull_read.val);

    // Close all
    _ = try close_handler(makeCloseNotif(init_tid, proc_vfd), &supervisor);
    _ = try close_handler(makeCloseNotif(init_tid, devnull_vfd), &supervisor);
    _ = try close_handler(makeCloseNotif(init_tid, tmp_vfd), &supervisor);
}

test "close one of three, other two remain accessible, closed one EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Open three files
    const vfd1: i32 = @intCast((try openat_handler(
        makeOpenatNotif(init_tid, "/proc/self", 0, 0),
        &supervisor,
    )).val);
    const vfd2: i32 = @intCast((try openat_handler(
        makeOpenatNotif(init_tid, "/dev/null", 0, 0),
        &supervisor,
    )).val);
    const vfd3: i32 = @intCast((try openat_handler(
        makeOpenatNotif(init_tid, "/dev/zero", 0, 0),
        &supervisor,
    )).val);

    // Close the middle one
    _ = try close_handler(
        makeCloseNotif(init_tid, vfd2),
        &supervisor,
    );

    // vfd1 and vfd3 should still be readable
    var buf: [64]u8 = undefined;
    _ = try read_handler(
        makeReadNotif(init_tid, vfd1, &buf, buf.len),
        &supervisor,
    );

    _ = try read_handler(
        makeReadNotif(init_tid, vfd3, &buf, buf.len),
        &supervisor,
    );

    // vfd2 should EBADF
    try testing.expectError(error.BADF, read_handler(
        makeReadNotif(init_tid, vfd2, &buf, buf.len),
        &supervisor,
    ));

    // Cleanup
    _ = try close_handler(makeCloseNotif(init_tid, vfd1), &supervisor);
    _ = try close_handler(makeCloseNotif(init_tid, vfd3), &supervisor);
}

test "open -> close -> open -> second open gets next VFD (no reuse)" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Open first file
    const resp1 = try openat_handler(
        makeOpenatNotif(init_tid, "/dev/null", 0, 0),
        &supervisor,
    );
    const vfd1: i32 = @intCast(resp1.val);

    // Close it
    _ = try close_handler(makeCloseNotif(init_tid, vfd1), &supervisor);

    // Open another file
    const resp2 = try openat_handler(
        makeOpenatNotif(init_tid, "/dev/null", 0, 0),
        &supervisor,
    );
    const vfd2: i32 = @intCast(resp2.val);

    // Second VFD should be strictly greater (no reuse)
    try testing.expect(vfd2 > vfd1);
}

test "CLONE_FILES fork - child sees parents FDs, parent sees childs" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Parent opens a file
    const parent_open = try openat_handler(
        makeOpenatNotif(init_tid, "/proc/self", 0, 0),
        &supervisor,
    );
    const parent_vfd: i32 = @intCast(parent_open.val);

    // Fork with CLONE_FILES
    const parent = supervisor.guest_threads.lookup.get(init_tid).?;
    _ = try supervisor.guest_threads.registerChild(parent, 200, CloneFlags.from(linux.CLONE.FILES));

    // Child should see parent's FD (shared fd_table)
    const child = supervisor.guest_threads.lookup.get(200).?;
    const child_ref = child.fd_table.get_ref(parent_vfd);
    defer if (child_ref) |f| f.unref();
    try testing.expect(child_ref != null);

    // Child opens a new file - parent should see it too (shared table)
    const child_open = try openat_handler(
        makeOpenatNotif(200, "/dev/null", 0, 0),
        &supervisor,
    );
    const child_vfd: i32 = @intCast(child_open.val);
    const parent_ref = parent.fd_table.get_ref(child_vfd);
    defer if (parent_ref) |f| f.unref();
    try testing.expect(parent_ref != null);

    // Cleanup
    _ = try close_handler(makeCloseNotif(init_tid, parent_vfd), &supervisor);
    _ = try close_handler(makeCloseNotif(200, child_vfd), &supervisor);
}

test "non-CLONE_FILES fork - independent tables, parent close doesnt affect child" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Parent opens a file
    const parent_open = try openat_handler(
        makeOpenatNotif(init_tid, "/proc/self", 0, 0),
        &supervisor,
    );
    const parent_vfd: i32 = @intCast(parent_open.val);

    // Fork without CLONE_FILES (independent copy)
    const parent = supervisor.guest_threads.lookup.get(init_tid).?;
    _ = try supervisor.guest_threads.registerChild(parent, 200, CloneFlags.from(0));
    const child = supervisor.guest_threads.lookup.get(200).?;

    // Child should have a copy of the VFD
    const child_ref1 = child.fd_table.get_ref(parent_vfd);
    defer if (child_ref1) |f| f.unref();
    try testing.expect(child_ref1 != null);

    // Parent closes - should not affect child
    _ = try close_handler(makeCloseNotif(init_tid, parent_vfd), &supervisor);
    const parent_ref = parent.fd_table.get_ref(parent_vfd);
    defer if (parent_ref) |f| f.unref();
    try testing.expect(parent_ref == null);
    const child_ref2 = child.fd_table.get_ref(parent_vfd);
    defer if (child_ref2) |f| f.unref();
    try testing.expect(child_ref2 != null);
}

test "child namespace reads /proc/self -> sees NsTid 1" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();
    defer proc_info.mock.reset(allocator);

    // Create child in new namespace
    const parent = supervisor.guest_threads.lookup.get(init_tid).?;
    const nstids = [_]NsTid{ 200, 1 };
    try proc_info.mock.setupNsTids(allocator, 200, &nstids);
    _ = try supervisor.guest_threads.registerChild(parent, 200, CloneFlags.from(linux.CLONE.NEWPID));

    // Child opens /proc/self
    const open_resp = try openat_handler(
        makeOpenatNotif(200, "/proc/self", 0, 0),
        &supervisor,
    );

    const vfd: i32 = @intCast(open_resp.val);

    // Read should show NsTid 1 (child's view)
    var buf: [64]u8 = undefined;
    const read_resp = try read_handler(
        makeReadNotif(200, vfd, &buf, buf.len),
        &supervisor,
    );
    try testing.expectEqualStrings("1\n", buf[0..@intCast(read_resp.val)]);

    _ = try close_handler(makeCloseNotif(200, vfd), &supervisor);
}

test "openat /tmp/../sys/class/net normalizes to blocked EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    try testing.expectError(error.PERM, openat_handler(
        makeOpenatNotif(init_tid, "/tmp/../sys/class/net", 0, 0),
        &supervisor,
    ));
}

test "unknown VFD returns EBADF across all handlers" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const bad_vfd: i32 = 99;
    var buf: [64]u8 = undefined;

    // read
    try testing.expectError(error.BADF, read_handler(
        makeReadNotif(init_tid, bad_vfd, &buf, buf.len),
        &supervisor,
    ));

    // write
    var wdata = "test".*;
    try testing.expectError(error.BADF, write_handler(
        makeWriteNotif(init_tid, bad_vfd, &wdata, wdata.len),
        &supervisor,
    ));

    // close
    try testing.expectError(error.BADF, close_handler(
        makeCloseNotif(init_tid, bad_vfd),
        &supervisor,
    ));

    // readv
    var iovecs_r = [_]iovec{
        .{ .base = &buf, .len = buf.len },
    };
    try testing.expectError(error.BADF, readv_handler(
        makeNotif(.readv, .{
            .pid = init_tid,
            .arg0 = @as(u64, @bitCast(@as(i64, bad_vfd))),
            .arg1 = @intFromPtr(&iovecs_r),
            .arg2 = 1,
        }),
        &supervisor,
    ));

    // writev
    const wv_data = "test";
    var iovecs_w = [_]iovec_const{
        .{ .base = wv_data.ptr, .len = wv_data.len },
    };
    try testing.expectError(error.BADF, writev_handler(
        makeNotif(.writev, .{
            .pid = init_tid,
            .arg0 = @as(u64, @bitCast(@as(i64, bad_vfd))),
            .arg1 = @intFromPtr(&iovecs_w),
            .arg2 = 1,
        }),
        &supervisor,
    ));
}

test "unknown PID returns ESRCH across all handlers" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const bad_tid: AbsTid = 999;
    var buf: [64]u8 = undefined;

    // openat
    try testing.expectError(error.SRCH, openat_handler(
        makeOpenatNotif(bad_tid, "/dev/null", 0, 0),
        &supervisor,
    ));

    // read (non-stdin fd)
    try testing.expectError(error.SRCH, read_handler(
        makeReadNotif(bad_tid, 3, &buf, buf.len),
        &supervisor,
    ));

    // write (non-stdout/stderr fd)
    var wdata = "test".*;
    try testing.expectError(error.SRCH, write_handler(
        makeWriteNotif(bad_tid, 3, &wdata, wdata.len),
        &supervisor,
    ));

    // close (non-stdio fd)
    try testing.expectError(error.SRCH, close_handler(
        makeCloseNotif(bad_tid, 3),
        &supervisor,
    ));
}

test "fstat on proc file writes correct struct stat" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Open /proc/self
    const open_resp = try openat_handler(
        makeOpenatNotif(init_tid, "/proc/self", 0, 0),
        &supervisor,
    );
    const vfd: i32 = @intCast(open_resp.val);

    // fstat
    var stat_buf: Stat = std.mem.zeroes(Stat);
    const fstat_resp = try fstat_handler(
        makeFstatNotif(init_tid, vfd, &stat_buf),
        &supervisor,
    );
    try testing.expectEqual(@as(i64, 0), fstat_resp.val);

    // ProcFile.statx sets: mode = S.IFREG | 0o444, nlink = 1, blksize = 4096, size = content_len
    // Content of /proc/self for tid 100 is "100\n" (4 bytes)
    try testing.expectEqual(linux.S.IFREG | 0o444, stat_buf.st_mode);
    try testing.expectEqual(@as(@TypeOf(stat_buf.st_nlink), 1), stat_buf.st_nlink);
    try testing.expectEqual(@as(@TypeOf(stat_buf.st_blksize), 4096), stat_buf.st_blksize);
    try testing.expectEqual(@as(i64, 4), stat_buf.st_size);

    _ = try close_handler(makeCloseNotif(init_tid, vfd), &supervisor);
}

test "fstat on stdio fd returns continue" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var stat_buf: Stat = std.mem.zeroes(Stat);

    // stdin
    const resp0 = try fstat_handler(makeFstatNotif(init_tid, 0, &stat_buf), &supervisor);
    try testing.expect(isContinue(resp0));

    // stdout
    const resp1 = try fstat_handler(makeFstatNotif(init_tid, 1, &stat_buf), &supervisor);
    try testing.expect(isContinue(resp1));

    // stderr
    const resp2 = try fstat_handler(makeFstatNotif(init_tid, 2, &stat_buf), &supervisor);
    try testing.expect(isContinue(resp2));
}

test "fstat on unknown VFD returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var stat_buf: Stat = std.mem.zeroes(Stat);
    try testing.expectError(error.BADF, fstat_handler(makeFstatNotif(init_tid, 99, &stat_buf), &supervisor));
}

fn makeSocketpairNotif(tid: AbsTid, domain: u32, sock_type: u32, protocol: u32, sv_ptr: u64) linux.SECCOMP.notif {
    return makeNotif(.socketpair, .{
        .pid = tid,
        .arg0 = domain,
        .arg1 = sock_type,
        .arg2 = protocol,
        .arg3 = sv_ptr,
    });
}

fn makeSendtoNotif(tid: AbsTid, vfd: i32, data_ptr: u64, len: usize, flags: u32) linux.SECCOMP.notif {
    return makeNotif(.sendto, .{
        .pid = tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = data_ptr,
        .arg2 = len,
        .arg3 = flags,
        .arg4 = 0,
        .arg5 = 0,
    });
}

fn makeRecvfromNotif(tid: AbsTid, vfd: i32, buf_ptr: u64, len: usize, flags: u32) linux.SECCOMP.notif {
    return makeNotif(.recvfrom, .{
        .pid = tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = buf_ptr,
        .arg2 = len,
        .arg3 = flags,
    });
}

fn makeShutdownNotif(tid: AbsTid, vfd: i32, how: u32) linux.SECCOMP.notif {
    return makeNotif(.shutdown, .{
        .pid = tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = how,
    });
}

fn makeSendmsgNotif(tid: AbsTid, vfd: i32, msg_ptr: u64, flags: u32) linux.SECCOMP.notif {
    return makeNotif(.sendmsg, .{
        .pid = tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = msg_ptr,
        .arg2 = flags,
    });
}

fn makeRecvmsgNotif(tid: AbsTid, vfd: i32, msg_ptr: u64, flags: u32) linux.SECCOMP.notif {
    return makeNotif(.recvmsg, .{
        .pid = tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = msg_ptr,
        .arg2 = flags,
    });
}

test "socketpair -> sendto -> recvfrom -> close round-trip" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // socketpair(AF_UNIX, SOCK_STREAM)
    var sv: [2]i32 = .{ -1, -1 };
    const sp_resp = socketpair_handler(
        makeSocketpairNotif(init_tid, linux.AF.UNIX, linux.SOCK.STREAM, 0, @intFromPtr(&sv)),
        &supervisor,
    );
    try testing.expect(!isError(sp_resp));

    // sendto sv[0] with "hello sockets"
    var send_data = "hello sockets".*;
    const send_resp = sendto_handler(
        makeSendtoNotif(init_tid, sv[0], @intFromPtr(&send_data), send_data.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(send_resp));
    try testing.expectEqual(@as(i64, @intCast(send_data.len)), send_resp.val);

    // recvfrom sv[1]
    var recv_buf: [64]u8 = undefined;
    const recv_resp = recvfrom_handler(
        makeRecvfromNotif(init_tid, sv[1], @intFromPtr(&recv_buf), recv_buf.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(recv_resp));
    try testing.expectEqualStrings("hello sockets", recv_buf[0..@intCast(recv_resp.val)]);

    // close both
    const c0 = close_handler(makeCloseNotif(init_tid, sv[0]), &supervisor);
    try testing.expect(!isError(c0));
    const c1 = close_handler(makeCloseNotif(init_tid, sv[1]), &supervisor);
    try testing.expect(!isError(c1));
}

test "shutdown write end -> recvfrom returns 0 (EOF)" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // socketpair
    var sv: [2]i32 = .{ -1, -1 };
    const sp_resp = socketpair_handler(
        makeSocketpairNotif(init_tid, linux.AF.UNIX, linux.SOCK.STREAM, 0, @intFromPtr(&sv)),
        &supervisor,
    );
    try testing.expect(!isError(sp_resp));

    // sendto sv[0] with "before shutdown"
    var send_data = "before shutdown".*;
    const send_resp = sendto_handler(
        makeSendtoNotif(init_tid, sv[0], @intFromPtr(&send_data), send_data.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(send_resp));

    // shutdown sv[0] SHUT_WR
    const shut_resp = shutdown_handler(
        makeShutdownNotif(init_tid, sv[0], linux.SHUT.WR),
        &supervisor,
    );
    try testing.expect(!isError(shut_resp));

    // recvfrom sv[1] -> should get "before shutdown"
    var recv_buf: [64]u8 = undefined;
    const recv_resp = recvfrom_handler(
        makeRecvfromNotif(init_tid, sv[1], @intFromPtr(&recv_buf), recv_buf.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(recv_resp));
    try testing.expectEqualStrings("before shutdown", recv_buf[0..@intCast(recv_resp.val)]);

    // recvfrom sv[1] again -> should return 0 (EOF)
    const eof_resp = recvfrom_handler(
        makeRecvfromNotif(init_tid, sv[1], @intFromPtr(&recv_buf), recv_buf.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(eof_resp));
    try testing.expectEqual(@as(i64, 0), eof_resp.val);

    // close both
    _ = close_handler(makeCloseNotif(init_tid, sv[0]), &supervisor);
    _ = close_handler(makeCloseNotif(init_tid, sv[1]), &supervisor);
}

test "sendto on closed fd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // socketpair
    var sv: [2]i32 = .{ -1, -1 };
    const sp_resp = socketpair_handler(
        makeSocketpairNotif(init_tid, linux.AF.UNIX, linux.SOCK.STREAM, 0, @intFromPtr(&sv)),
        &supervisor,
    );
    try testing.expect(!isError(sp_resp));

    // close sv[0]
    const c0 = close_handler(makeCloseNotif(init_tid, sv[0]), &supervisor);
    try testing.expect(!isError(c0));

    // sendto on closed sv[0] -> EBADF
    var send_data = "should fail".*;
    const send_resp = sendto_handler(
        makeSendtoNotif(init_tid, sv[0], @intFromPtr(&send_data), send_data.len, 0),
        &supervisor,
    );
    try testing.expect(isError(send_resp));
    try testing.expectEqual(-@as(i32, @intCast(@intFromEnum(linux.E.BADF))), send_resp.@"error");

    // close sv[1]
    _ = close_handler(makeCloseNotif(init_tid, sv[1]), &supervisor);
}

test "sendmsg single iovec -> recvfrom round-trip" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // socketpair
    var sv: [2]i32 = .{ -1, -1 };
    const sp_resp = socketpair_handler(
        makeSocketpairNotif(init_tid, linux.AF.UNIX, linux.SOCK.STREAM, 0, @intFromPtr(&sv)),
        &supervisor,
    );
    try testing.expect(!isError(sp_resp));

    // sendmsg with single iovec
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

    const send_resp = sendmsg_handler(
        makeSendmsgNotif(init_tid, sv[0], @intFromPtr(&msg), 0),
        &supervisor,
    );
    try testing.expect(!isError(send_resp));
    try testing.expectEqual(@as(i64, @intCast(data.len)), send_resp.val);

    // recvfrom on sv[1]
    var recv_buf: [64]u8 = undefined;
    const recv_resp = recvfrom_handler(
        makeRecvfromNotif(init_tid, sv[1], @intFromPtr(&recv_buf), recv_buf.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(recv_resp));
    try testing.expectEqualStrings("single iov msg", recv_buf[0..@intCast(recv_resp.val)]);

    // close both
    _ = close_handler(makeCloseNotif(init_tid, sv[0]), &supervisor);
    _ = close_handler(makeCloseNotif(init_tid, sv[1]), &supervisor);
}

test "sendmsg multi-iovec -> recvmsg multi-iovec scatter" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // socketpair
    var sv: [2]i32 = .{ -1, -1 };
    const sp_resp = socketpair_handler(
        makeSocketpairNotif(init_tid, linux.AF.UNIX, linux.SOCK.STREAM, 0, @intFromPtr(&sv)),
        &supervisor,
    );
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

    const send_resp = sendmsg_handler(
        makeSendmsgNotif(init_tid, sv[0], @intFromPtr(&send_msg), 0),
        &supervisor,
    );
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

    const recv_resp = recvmsg_handler(
        makeRecvmsgNotif(init_tid, sv[1], @intFromPtr(&recv_msg), 0),
        &supervisor,
    );
    try testing.expect(!isError(recv_resp));
    try testing.expectEqual(@as(i64, 9), recv_resp.val);

    // Verify scatter correctness
    try testing.expectEqualStrings("aaa", &r1);
    try testing.expectEqualStrings("bbb", &r2);
    try testing.expectEqualStrings("ccc", &r3);

    // close both
    _ = close_handler(makeCloseNotif(init_tid, sv[0]), &supervisor);
    _ = close_handler(makeCloseNotif(init_tid, sv[1]), &supervisor);
}

test "sendto -> recvmsg cross-API round-trip" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // socketpair
    var sv: [2]i32 = .{ -1, -1 };
    const sp_resp = socketpair_handler(
        makeSocketpairNotif(init_tid, linux.AF.UNIX, linux.SOCK.STREAM, 0, @intFromPtr(&sv)),
        &supervisor,
    );
    try testing.expect(!isError(sp_resp));

    // sendto sv[0] with "cross api"
    var send_data = "cross api".*;
    const send_resp = sendto_handler(
        makeSendtoNotif(init_tid, sv[0], @intFromPtr(&send_data), send_data.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(send_resp));

    // recvmsg sv[1] with single iovec
    var recv_buf: [64]u8 = undefined;
    var recv_iov = [_]iovec{
        .{ .base = &recv_buf, .len = recv_buf.len },
    };
    var recv_msg = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &recv_iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    const recv_resp = recvmsg_handler(
        makeRecvmsgNotif(init_tid, sv[1], @intFromPtr(&recv_msg), 0),
        &supervisor,
    );
    try testing.expect(!isError(recv_resp));
    try testing.expectEqualStrings("cross api", recv_buf[0..@intCast(recv_resp.val)]);

    // close both
    _ = close_handler(makeCloseNotif(init_tid, sv[0]), &supervisor);
    _ = close_handler(makeCloseNotif(init_tid, sv[1]), &supervisor);
}

test "multiple sends -> single large recvfrom" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // socketpair (SOCK_STREAM so data coalesces)
    var sv: [2]i32 = .{ -1, -1 };
    const sp_resp = socketpair_handler(
        makeSocketpairNotif(init_tid, linux.AF.UNIX, linux.SOCK.STREAM, 0, @intFromPtr(&sv)),
        &supervisor,
    );
    try testing.expect(!isError(sp_resp));

    // sendto sv[0] "chunk1"
    var c1 = "chunk1".*;
    const s1 = sendto_handler(
        makeSendtoNotif(init_tid, sv[0], @intFromPtr(&c1), c1.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(s1));

    // sendto sv[0] "chunk2"
    var c2 = "chunk2".*;
    const s2 = sendto_handler(
        makeSendtoNotif(init_tid, sv[0], @intFromPtr(&c2), c2.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(s2));

    // recvfrom sv[1] with large buffer
    var recv_buf: [256]u8 = undefined;
    const recv_resp = recvfrom_handler(
        makeRecvfromNotif(init_tid, sv[1], @intFromPtr(&recv_buf), recv_buf.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(recv_resp));
    try testing.expectEqualStrings("chunk1chunk2", recv_buf[0..@intCast(recv_resp.val)]);

    // close both
    _ = close_handler(makeCloseNotif(init_tid, sv[0]), &supervisor);
    _ = close_handler(makeCloseNotif(init_tid, sv[1]), &supervisor);
}

test "recvfrom writes back source address length" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // socketpair(AF_UNIX, SOCK_STREAM)
    var sv: [2]i32 = .{ -1, -1 };
    const sp_resp = socketpair_handler(
        makeSocketpairNotif(init_tid, linux.AF.UNIX, linux.SOCK.STREAM, 0, @intFromPtr(&sv)),
        &supervisor,
    );
    try testing.expect(!isError(sp_resp));

    // sendto sv[0]
    var send_data = "addr test".*;
    const send_resp = sendto_handler(
        makeSendtoNotif(init_tid, sv[0], @intFromPtr(&send_data), send_data.len, 0),
        &supervisor,
    );
    try testing.expect(!isError(send_resp));

    // recvfrom sv[1] with src_addr and addrlen pointers
    var recv_buf: [64]u8 = undefined;
    var src_addr: [128]u8 = undefined;
    var addrlen: linux.socklen_t = @sizeOf(@TypeOf(src_addr));
    const notif = makeNotif(.recvfrom, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, sv[1]))),
        .arg1 = @intFromPtr(&recv_buf),
        .arg2 = recv_buf.len,
        .arg3 = 0,
        .arg4 = @intFromPtr(&src_addr),
        .arg5 = @intFromPtr(&addrlen),
    });
    const recv_resp = recvfrom_handler(notif, &supervisor);
    try testing.expect(!isError(recv_resp));
    try testing.expectEqualStrings("addr test", recv_buf[0..@intCast(recv_resp.val)]);

    // addrlen should have been written back by the handler
    // For AF_UNIX SOCK_STREAM socketpair, the kernel writes back the actual address length
    try testing.expect(addrlen <= @sizeOf(@TypeOf(src_addr)));

    // close both
    _ = close_handler(makeCloseNotif(init_tid, sv[0]), &supervisor);
    _ = close_handler(makeCloseNotif(init_tid, sv[1]), &supervisor);
}
