const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("types.zig");
const syscall = @import("syscall.zig");
const Notification = @import("Notification.zig");
const VirtualFileSystem = @import("VirtualFilesystem.zig");
const FD = types.FD;
const MemoryBridge = @import("memory_bridge.zig").MemoryBridge;
const Result = types.LinuxResult;
const Logger = types.Logger;

const Self = @This();

notify_fd: FD,
logger: Logger,
mem_bridge: MemoryBridge,
filesystem: VirtualFileSystem,

pub fn init(notify_fd: FD, child_pid: linux.pid_t, allocator: std.mem.Allocator) Self {
    return .{
        .notify_fd = notify_fd,
        .logger = Logger.init(.supervisor),
        .mem_bridge = MemoryBridge.init(child_pid),
        .filesystem = VirtualFileSystem.init(allocator),
    };
}

pub fn deinit(self: *Self) void {
    self.filesystem.deinit();
    if (self.notify_fd >= 0) {
        posix.close(self.notify_fd);
    }
}

/// Test-only init that doesn't require a real notify_fd
pub fn initForTesting(allocator: std.mem.Allocator) Self {
    return .{
        .notify_fd = -1, // Invalid FD, won't be used in tests
        .logger = Logger.init(.supervisor),
        .mem_bridge = MemoryBridge.init(0), // Dummy PID, TestingMemoryBridge ignores it
        .filesystem = VirtualFileSystem.init(allocator),
    };
}

/// Main notification loop. Reads syscall notifications from the kernel,
pub fn run(self: *Self) !void {
    while (true) {
        // Receive syscall notification from kernel
        const notif = try self.recv() orelse return;
        const notification = try Notification.from_notif(self.mem_bridge, notif);

        // Handle (or prepare passthrough resp)
        const response = try notification.handle(self);

        // Reply to kernel
        try self.send(response.to_notif_resp());
    }
}

fn recv(self: *const Self) !?linux.SECCOMP.notif {
    var notif: linux.SECCOMP.notif = std.mem.zeroes(linux.SECCOMP.notif);
    const recv_result = linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&notif));
    switch (Result(usize).from(recv_result)) {
        .Ok => return notif,
        .Error => |err| switch (err) {
            .NOENT => {
                self.logger.log("Child exited, stopping notification handler", .{});
                return null;
            },
            else => |_| return posix.unexpectedErrno(err),
        },
    }
}

fn send(self: *const Self, resp: linux.SECCOMP.notif_resp) !void {
    _ = try Result(usize).from(
        linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&resp)),
    ).unwrap();
}

// ============================================================================
// E2E Tests
// ============================================================================

const testing = std.testing;

fn makeNotif(syscall_nr: linux.SYS, args: struct { arg0: u64 = 0, arg1: u64 = 0, arg2: u64 = 0, arg3: u64 = 0 }) linux.SECCOMP.notif {
    var notif = std.mem.zeroes(linux.SECCOMP.notif);
    notif.id = 1;
    notif.data.nr = @intCast(@intFromEnum(syscall_nr));
    notif.data.arg0 = args.arg0;
    notif.data.arg1 = args.arg1;
    notif.data.arg2 = args.arg2;
    notif.data.arg3 = args.arg3;
    return notif;
}

test "openat with O_CREAT creates virtual FD" {
    var supervisor = Self.initForTesting(testing.allocator);
    defer supervisor.deinit();

    // Path buffer in local memory (TestingMemoryBridge reads it directly)
    const path_buf = "/test.txt";

    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)), // dirfd
        .arg1 = @intFromPtr(path_buf.ptr), // pathname (string literal is null-terminated)
        .arg2 = 0o101, // O_WRONLY | O_CREAT
        .arg3 = 0o644, // mode
    });

    const notification = try Notification.from_notif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.to_notif_resp();

    // Should return success with FD >= 3
    try testing.expectEqual(@as(i32, 0), resp.@"error");
    try testing.expect(resp.val >= 3);
    try testing.expectEqual(@as(u32, 0), resp.flags); // Not passthrough
}

test "openat without O_CREAT on missing file returns ENOENT" {
    var supervisor = Self.initForTesting(testing.allocator);
    defer supervisor.deinit();

    const path_buf = "/missing.txt";

    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o0, // O_RDONLY, no O_CREAT
        .arg3 = 0,
    });

    const notification = try Notification.from_notif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.to_notif_resp();

    // Should return ENOENT
    try testing.expectEqual(@intFromEnum(linux.E.NOENT), resp.@"error");
}

test "write to virtual FD returns bytes written" {
    var supervisor = Self.initForTesting(testing.allocator);
    defer supervisor.deinit();

    // First open a file
    const path_buf = "/test.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o101, // O_WRONLY | O_CREAT
        .arg3 = 0o644,
    });

    const open_notification = try Notification.from_notif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.to_notif_resp().val;

    // Now write to it
    const write_buf = "Hello world!";
    const write_notif = makeNotif(.write, .{
        .arg0 = @intCast(fd),
        .arg1 = @intFromPtr(write_buf.ptr),
        .arg2 = 12, // count
    });

    const write_notification = try Notification.from_notif(supervisor.mem_bridge, write_notif);
    const write_response = try write_notification.handle(&supervisor);
    const write_resp = write_response.to_notif_resp();

    // Should return 12 bytes written
    try testing.expectEqual(@as(i32, 0), write_resp.@"error");
    try testing.expectEqual(@as(i64, 12), write_resp.val);
}

test "write to stdout (fd=1) passthroughs" {
    var supervisor = Self.initForTesting(testing.allocator);
    defer supervisor.deinit();

    const write_buf = "hello";
    const notif = makeNotif(.write, .{
        .arg0 = 1, // stdout
        .arg1 = @intFromPtr(write_buf.ptr),
        .arg2 = 5,
    });

    const notification = try Notification.from_notif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.to_notif_resp();

    // Should passthrough (USER_NOTIF_FLAG_CONTINUE)
    try testing.expectEqual(linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "write to stderr (fd=2) passthroughs" {
    var supervisor = Self.initForTesting(testing.allocator);
    defer supervisor.deinit();

    const write_buf = "error";
    const notif = makeNotif(.write, .{
        .arg0 = 2, // stderr
        .arg1 = @intFromPtr(write_buf.ptr),
        .arg2 = 5,
    });

    const notification = try Notification.from_notif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.to_notif_resp();

    // Should passthrough
    try testing.expectEqual(linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "write to bad FD returns EBADF" {
    var supervisor = Self.initForTesting(testing.allocator);
    defer supervisor.deinit();

    const write_buf = "hello";
    const notif = makeNotif(.write, .{
        .arg0 = 999, // bad FD
        .arg1 = @intFromPtr(write_buf.ptr),
        .arg2 = 5,
    });

    const notification = try Notification.from_notif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.to_notif_resp();

    // Should return EBADF
    try testing.expectEqual(@intFromEnum(linux.E.BADF), resp.@"error");
}

test "close virtual FD returns success" {
    var supervisor = Self.initForTesting(testing.allocator);
    defer supervisor.deinit();

    // First open a file
    const path_buf = "/test.txt";
    const open_notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr(path_buf.ptr),
        .arg2 = 0o101,
        .arg3 = 0o644,
    });

    const open_notification = try Notification.from_notif(supervisor.mem_bridge, open_notif);
    const open_response = try open_notification.handle(&supervisor);
    const fd = open_response.to_notif_resp().val;

    // Now close it
    const close_notif = makeNotif(.close, .{
        .arg0 = @intCast(fd),
    });

    const close_notification = try Notification.from_notif(supervisor.mem_bridge, close_notif);
    const close_response = try close_notification.handle(&supervisor);
    const close_resp = close_response.to_notif_resp();

    // Should return success
    try testing.expectEqual(@as(i32, 0), close_resp.@"error");
    try testing.expectEqual(@as(i64, 0), close_resp.val);
}

test "close stdin (fd=0) passthroughs" {
    var supervisor = Self.initForTesting(testing.allocator);
    defer supervisor.deinit();

    const notif = makeNotif(.close, .{
        .arg0 = 0, // stdin
    });

    const notification = try Notification.from_notif(supervisor.mem_bridge, notif);
    const response = try notification.handle(&supervisor);
    const resp = response.to_notif_resp();

    // Should passthrough
    try testing.expectEqual(linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE, resp.flags);
}
