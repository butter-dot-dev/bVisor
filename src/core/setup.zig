const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const types = @import("types.zig");
const seccomp = @import("seccomp/filter.zig");
const Logger = types.Logger;
const Supervisor = @import("Supervisor.zig");
const LogBuffer = @import("LogBuffer.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const pidfd = @import("utils/pidfd.zig");
const lookupGuestFd = pidfd.lookupGuestFdWithRetry;

pub fn execute(allocator: Allocator, io: Io, uid: [16]u8, runnable: *const fn () void, stdout: *LogBuffer, stderr: *LogBuffer) !void {
    // Probe the next available FD: dup gives the lowest free FD, then close it.
    // After fork, seccomp.install() in the child will allocate the same FD number.
    // This will race with other noise in the env, and is a temp solution
    const dup_rc = linux.dup(0);
    if (linux.errno(dup_rc) != .SUCCESS) return error.SyscallFailed;
    const expected_notify_fd: linux.fd_t = @intCast(dup_rc);
    posix.close(expected_notify_fd);

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) return error.SyscallFailed;
    const fork_result: linux.pid_t = @intCast(fork_rc);
    if (fork_result == 0) {
        try guestProcess(runnable, expected_notify_fd);
    } else {
        const init_guest_tid: linux.pid_t = fork_result;
        try supervisorProcess(allocator, io, uid, init_guest_tid, expected_notify_fd, stdout, stderr);
    }
}

fn guestProcess(runnable: *const fn () void, expected_notify_fd: linux.fd_t) !void {
    const notify_fd = try seccomp.install();
    if (notify_fd != expected_notify_fd) {
        return error.NotifyFdMismatch;
    }
    @call(.never_inline, runnable, .{});
    linux.exit(0);
}

fn supervisorProcess(allocator: Allocator, io: Io, uid: [16]u8, init_guest_tid: linux.pid_t, expected_notify_fd: linux.fd_t, stdout: *LogBuffer, stderr: *LogBuffer) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Supervisor process starting", .{});
    defer logger.log("Supervisor process exiting", .{});

    const notify_fd = try lookupGuestFd(init_guest_tid, expected_notify_fd, io);

    var supervisor = try Supervisor.init(allocator, io, uid, notify_fd, init_guest_tid, stdout, stderr);
    defer supervisor.deinit();
    try supervisor.run();
}

pub fn generateUid(io: Io) [16]u8 {
    var uid_bytes: [8]u8 = undefined;
    io.random(&uid_bytes);
    return std.fmt.bytesToHex(uid_bytes, .lower);
}
