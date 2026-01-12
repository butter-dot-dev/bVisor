const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const FD = types.FD;
const Result = types.LinuxResult;

pub inline fn lookup_child_fd(child_pid: linux.pid_t, local_fd: FD) !FD {
    const child_fd_table: FD = try Result(FD).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    return Result(FD).from(
        linux.pidfd_getfd(child_fd_table, local_fd, 0),
    ).unwrap();
}

pub inline fn lookup_child_fd_with_retry(child_pid: linux.pid_t, local_fd: FD, io: std.Io) !FD {
    const child_fd_table: FD = try Result(FD).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        const result = linux.pidfd_getfd(child_fd_table, local_fd, 0);
        switch (Result(FD).from(result)) {
            .Ok => |value| return value,
            .Error => |err| switch (err) {
                .BADF => {
                    // FD doesn't exist yet in child - retry
                    try io.sleep(std.Io.Duration.fromMilliseconds(1), .awake);
                    continue;
                },
                else => return posix.unexpectedErrno(err),
            },
        }
    }
    return error.NotifyFdTimeout;
}
