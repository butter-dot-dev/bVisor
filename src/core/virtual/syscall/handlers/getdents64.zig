const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");
const Supervisor = @import("../../../Supervisor.zig");
const ScratchArena = Supervisor.ScratchArena;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const memory_bridge = @import("../../../utils/memory_bridge.zig");
const dirent = @import("../../fs/dirent.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const buf_addr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    // Passthrough for stdio (kernel will return ENOTDIR)
    if (fd == linux.STDIN_FILENO or fd == linux.STDOUT_FILENO or fd == linux.STDERR_FILENO) {
        return replyContinue(notif.id);
    }

    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("getdents64: EBADF for fd={d}", .{fd});
            return LinuxErr.BADF;
        };
    }
    defer file.unref();

    const max_len = 4096;
    var stack_buf: [max_len]u8 = undefined;
    const capped_count = @min(count, max_len);

    // Mutex protects namespace threads (proc) and tombstones (cow/tmp)
    var scratch = ScratchArena.init(supervisor.allocator);
    defer scratch.deinit();

    const n: usize = switch (file.backend) {
        .proc, .cow, .tmp => blk: {
            supervisor.mutex.lockUncancelable(supervisor.io);
            defer supervisor.mutex.unlock(supervisor.io);
            const caller = if (file.backend == .proc) try supervisor.guest_threads.get(caller_tid) else null;
            break :blk try file.getdents64(
                scratch.allocator(),
                stack_buf[0..capped_count],
                caller,
                &supervisor.overlay,
                &supervisor.tombstones,
            );
        },
        else => try file.getdents64(
            scratch.allocator(),
            stack_buf[0..capped_count],
            null,
            &supervisor.overlay,
            &supervisor.tombstones,
        ),
    };

    if (n > 0) try memory_bridge.writeSlice(stack_buf[0..n], @intCast(notif.pid), buf_addr);

    logger.log("getdents64: fd={d} returned {d} bytes", .{ fd, n });
    return replySuccess(notif.id, @intCast(n));
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const ProcFile = @import("../../fs/backend/procfile.zig").ProcFile;
const Cow = @import("../../fs/backend/cow.zig").Cow;

test "getdents64 on directory returns entries" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a test directory with a known file
    const dir_path: [:0]const u8 = "/tmp/bvisor_test_getdents_pt";
    const file_path: [:0]const u8 = "/tmp/bvisor_test_getdents_pt/hello.txt";
    var dir_path_z: [dir_path.len + 1]u8 = undefined;
    @memcpy(dir_path_z[0..dir_path.len], dir_path);
    dir_path_z[dir_path.len] = 0;
    _ = linux.mkdir(dir_path_z[0..dir_path.len :0], 0o755);
    var file_path_z: [file_path.len + 1]u8 = undefined;
    @memcpy(file_path_z[0..file_path.len], file_path);
    file_path_z[file_path.len] = 0;
    const create_rc = linux.openat(linux.AT.FDCWD, file_path_z[0..file_path.len :0], .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(create_rc) == .SUCCESS) _ = linux.close(@intCast(create_rc));
    defer {
        _ = linux.unlink(file_path_z[0..file_path.len :0]);
        _ = linux.rmdir(dir_path_z[0..dir_path.len :0]);
    }

    const open_rc = linux.openat(linux.AT.FDCWD, dir_path_z[0..dir_path.len :0], .{ .ACCMODE = .RDONLY }, 0);
    try checkErr(open_rc, "test: open dir", .{});
    const raw_fd: linux.fd_t = @intCast(open_rc);

    const f = try File.init(allocator, .{ .passthrough = .{ .fd = raw_fd } });
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const vfd = try caller.fd_table.insert(f, .{});

    var result_buf: [1024]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&result_buf),
        .arg2 = result_buf.len,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expect(resp.val > 0);

    var names: [64][]const u8 = undefined;
    const name_count = dirent.parseDirentNames(result_buf[0..@intCast(resp.val)], &names);
    var found = false;
    for (names[0..name_count]) |name| {
        if (std.mem.eql(u8, name, "hello.txt")) found = true;
    }
    try testing.expect(found);
}

test "getdents64 on non-existent VFD returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid,
        .arg0 = 99,
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "getdents64 with unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid + 1,
        .arg0 = 3,
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}

test "getdents64 on proc /proc/self lists status entry" {
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
    const file = try File.init(allocator, .{ .proc = proc_file });
    try file.setOpenedPath("/proc/self");
    const vfd = try caller.fd_table.insert(file, .{});

    var result_buf: [512]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&result_buf),
        .arg2 = result_buf.len,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expect(resp.val > 0);
}

test "getdents64 on stdio returns replyContinue" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var buf: [64]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid,
        .arg0 = 0, // stdin
        .arg1 = @intFromPtr(&buf),
        .arg2 = buf.len,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "COW getdents64 lists real directory contents" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a test directory with a known file
    const dir_path: [:0]const u8 = "/tmp/bvisor_test_getdents_cow";
    const known_file: [:0]const u8 = "/tmp/bvisor_test_getdents_cow/known.txt";
    var dir_path_z: [dir_path.len + 1]u8 = undefined;
    @memcpy(dir_path_z[0..dir_path.len], dir_path);
    dir_path_z[dir_path.len] = 0;
    _ = linux.mkdir(dir_path_z[0..dir_path.len :0], 0o755);
    var known_file_z: [known_file.len + 1]u8 = undefined;
    @memcpy(known_file_z[0..known_file.len], known_file);
    known_file_z[known_file.len] = 0;
    const create_rc = linux.openat(linux.AT.FDCWD, known_file_z[0..known_file.len :0], .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(create_rc) == .SUCCESS) _ = linux.close(@intCast(create_rc));
    defer {
        _ = linux.unlink(known_file_z[0..known_file.len :0]);
        _ = linux.rmdir(dir_path_z[0..dir_path.len :0]);
    }

    const raw_fd_rc = linux.openat(linux.AT.FDCWD, dir_path_z[0..dir_path.len :0], .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    try checkErr(raw_fd_rc, "test: open dir", .{});
    const raw_fd: linux.fd_t = @intCast(raw_fd_rc);

    const file = try File.init(allocator, .{ .cow = .{ .readthrough = raw_fd } });
    try file.setOpenedPath(dir_path);
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const vfd = try caller.fd_table.insert(file, .{});

    var result_buf: [4096]u8 = undefined;
    const notif = makeNotif(.getdents64, .{
        .pid = init_tid,
        .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
        .arg1 = @intFromPtr(&result_buf),
        .arg2 = result_buf.len,
    });

    const resp = try handle(notif, &supervisor);
    try testing.expect(resp.val > 0);

    var names: [64][]const u8 = undefined;
    const name_count = dirent.parseDirentNames(result_buf[0..@intCast(resp.val)], &names);
    try testing.expect(name_count >= 3);

    var found_dot = false;
    var found_dotdot = false;
    var found_known = false;
    for (names[0..name_count]) |name| {
        if (std.mem.eql(u8, name, ".")) found_dot = true;
        if (std.mem.eql(u8, name, "..")) found_dotdot = true;
        if (std.mem.eql(u8, name, "known.txt")) found_known = true;
    }
    try testing.expect(found_dot);
    try testing.expect(found_dotdot);
    try testing.expect(found_known);
}

test "COW getdents64 filters tombstoned entries" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a test directory with a known file
    const dir_path: [:0]const u8 = "/tmp/bvisor_test_getdents_ts";
    const file_path: [:0]const u8 = "/tmp/bvisor_test_getdents_ts/target.txt";

    // Create directory and file
    var dir_path_z: [dir_path.len + 1]u8 = undefined;
    @memcpy(dir_path_z[0..dir_path.len], dir_path);
    dir_path_z[dir_path.len] = 0;
    _ = linux.mkdir(dir_path_z[0..dir_path.len :0], 0o755);

    var file_path_z: [file_path.len + 1]u8 = undefined;
    @memcpy(file_path_z[0..file_path.len], file_path);
    file_path_z[file_path.len] = 0;
    const create_rc = linux.openat(linux.AT.FDCWD, file_path_z[0..file_path.len :0], .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(create_rc) == .SUCCESS) _ = linux.close(@intCast(create_rc));
    defer {
        _ = linux.unlink(file_path_z[0..file_path.len :0]);
        _ = linux.rmdir(dir_path_z[0..dir_path.len :0]);
    }

    // Open directory as COW readthrough
    const raw_fd_rc = linux.openat(linux.AT.FDCWD, dir_path_z[0..dir_path.len :0], .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    try checkErr(raw_fd_rc, "test: open dir", .{});
    const raw_fd: linux.fd_t = @intCast(raw_fd_rc);

    const file = try File.init(allocator, .{ .cow = .{ .readthrough = raw_fd } });
    try file.setOpenedPath(dir_path);
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const vfd = try caller.fd_table.insert(file, .{});

    // First: verify target.txt appears without tombstone
    {
        var result_buf: [4096]u8 = undefined;
        const notif = makeNotif(.getdents64, .{
            .pid = init_tid,
            .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
            .arg1 = @intFromPtr(&result_buf),
            .arg2 = result_buf.len,
        });
        const resp = try handle(notif, &supervisor);
        var names: [64][]const u8 = undefined;
        const count_ = dirent.parseDirentNames(result_buf[0..@intCast(resp.val)], &names);
        var found = false;
        for (names[0..count_]) |name| {
            if (std.mem.eql(u8, name, "target.txt")) found = true;
        }
        try testing.expect(found);
    }

    // Add tombstone and reset dirents_offset
    try supervisor.tombstones.add(file_path);
    file.dirents_offset = 0;

    // Second: verify target.txt is hidden after tombstone
    {
        var result_buf: [4096]u8 = undefined;
        const notif = makeNotif(.getdents64, .{
            .pid = init_tid,
            .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
            .arg1 = @intFromPtr(&result_buf),
            .arg2 = result_buf.len,
        });
        const resp = try handle(notif, &supervisor);
        var names: [64][]const u8 = undefined;
        const count_ = dirent.parseDirentNames(result_buf[0..@intCast(resp.val)], &names);
        for (names[0..count_]) |name| {
            try testing.expect(!std.mem.eql(u8, name, "target.txt"));
        }
    }
}

test "COW getdents64 second call returns EOF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Create a test directory with a known file
    const dir_path: [:0]const u8 = "/tmp/bvisor_test_getdents_eof";
    const known_file: [:0]const u8 = "/tmp/bvisor_test_getdents_eof/entry.txt";
    var dir_path_z: [dir_path.len + 1]u8 = undefined;
    @memcpy(dir_path_z[0..dir_path.len], dir_path);
    dir_path_z[dir_path.len] = 0;
    _ = linux.mkdir(dir_path_z[0..dir_path.len :0], 0o755);
    var known_file_z: [known_file.len + 1]u8 = undefined;
    @memcpy(known_file_z[0..known_file.len], known_file);
    known_file_z[known_file.len] = 0;
    const create_rc = linux.openat(linux.AT.FDCWD, known_file_z[0..known_file.len :0], .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(create_rc) == .SUCCESS) _ = linux.close(@intCast(create_rc));
    defer {
        _ = linux.unlink(known_file_z[0..known_file.len :0]);
        _ = linux.rmdir(dir_path_z[0..dir_path.len :0]);
    }

    const raw_fd_rc = linux.openat(linux.AT.FDCWD, dir_path_z[0..dir_path.len :0], .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    try checkErr(raw_fd_rc, "test: open dir", .{});
    const raw_fd: linux.fd_t = @intCast(raw_fd_rc);

    const file = try File.init(allocator, .{ .cow = .{ .readthrough = raw_fd } });
    try file.setOpenedPath(dir_path);
    const caller = supervisor.guest_threads.lookup.get(init_tid).?;
    const vfd = try caller.fd_table.insert(file, .{});

    // First call: returns entries
    {
        var result_buf: [4096]u8 = undefined;
        const notif = makeNotif(.getdents64, .{
            .pid = init_tid,
            .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
            .arg1 = @intFromPtr(&result_buf),
            .arg2 = result_buf.len,
        });
        const resp = try handle(notif, &supervisor);
        try testing.expect(resp.val > 0);
    }

    // Second call: returns 0 (EOF)
    {
        var result_buf: [4096]u8 = undefined;
        const notif = makeNotif(.getdents64, .{
            .pid = init_tid,
            .arg0 = @as(u64, @bitCast(@as(i64, vfd))),
            .arg1 = @intFromPtr(&result_buf),
            .arg2 = result_buf.len,
        });
        const resp = try handle(notif, &supervisor);
        try testing.expectEqual(@as(i64, 0), resp.val);
    }
}
