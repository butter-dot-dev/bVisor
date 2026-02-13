const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const checkErr = @import("../linux_error.zig").checkErr;

pub inline fn lookupGuestFd(child_pid: linux.pid_t, local_fd: linux.fd_t) !linux.fd_t {
    if (comptime builtin.is_test) return local_fd;

    const pidfd_rc = linux.pidfd_open(child_pid, 0);
    try checkErr(pidfd_rc, "pidfd_open", .{});
    const child_fd_table: linux.fd_t = @intCast(pidfd_rc);

    const getfd_rc = linux.pidfd_getfd(child_fd_table, local_fd, 0);
    try checkErr(getfd_rc, "pidfd_getfd", .{});
    return @intCast(getfd_rc);
}

pub inline fn lookupGuestFdWithRetry(child_pid: linux.pid_t, local_fd: linux.fd_t, io: std.Io) !linux.fd_t {
    if (comptime builtin.is_test) return local_fd;

    const pidfd_rc = linux.pidfd_open(child_pid, 0);
    try checkErr(pidfd_rc, "pidfd_open", .{});
    const child_fd_table: linux.fd_t = @intCast(pidfd_rc);

    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        const result = linux.pidfd_getfd(child_fd_table, local_fd, 0);
        checkErr(result, "pidfd_getfd", .{}) catch |err| {
            if (err == error.BADF) {
                // FD doesn't exist yet in child - retry
                // ERIK TODO: why 1ms? why not exponential backoff? polling also seems gross
                try io.sleep(std.Io.Duration.fromMilliseconds(1), .awake);
                continue;
            }
            return err;
        };
        return @intCast(result);
    }
    return error.NotifyFdTimeout;
}
