const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const FD = types.FD;
const Result = types.LinuxResult;

pub inline fn lookup_child_fd(_: linux.pid_t, local_fd: FD) !FD {
    return local_fd;
}

pub inline fn lookup_child_fd_with_retry(_: linux.pid_t, local_fd: FD, _: std.Io) !FD {
    return local_fd;
}
