const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Proc = @import("../../../virtual/proc/Proc.zig");
const Procs = @import("../../../virtual/proc/Procs.zig");
const OpenFile = @import("../../../virtual/fs/OpenFile.zig").OpenFile;
const FdTable = @import("../../../virtual/fs/FdTable.zig");
const types = @import("../../../types.zig");
const Supervisor = @import("../../../Supervisor.zig");
const SupervisorFD = types.SupervisorFD;
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;
const route = @import("../../../virtual/fs/path.zig").route;
const File = @import("../../../virtual/fs/file.zig").File;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;
    const pid: Proc.SupervisorPID = @intCast(notif.pid);

    // Ensure calling process exists
    const proc = supervisor.guest_procs.lookup.get(pid) orelse {
        logger.log("openat: process lookup failed for pid: {d}", .{pid});
        return replyErr(notif.id, .SRCH);
    };

    // Parse arguments
    const path_ptr: u64 = notif.data.arg1;
    var path_buf: [256]u8 = undefined;
    const path_slice = memory_bridge.readString(
        &path_buf,
        @intCast(notif.pid),
        path_ptr,
    ) catch |err| {
        logger.log("openat: failed to read path string: {}", .{err});
        return replyErr(notif.id, .FAULT);
    };

    // Only absolute paths supported for now
    const dirfd: SupervisorFD = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    _ = dirfd; // dirfd only matters for relative paths
    if (path_slice.len == 0 or path_slice[0] != '/') {
        logger.log("openat: invalid path: {s}, must be absolute", .{path_slice});
        return replyErr(notif.id, .INVAL);
    }

    const flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg2)));
    const mode: linux.mode_t = @truncate(notif.data.arg3);
    const route_result = try route(path_slice);
    switch (route_result) {
        .block => {
            return replyErr(notif.id, .PERM);
        },
        .handle => |backend| {
            const file = try File.open(backend, path_slice, flags, mode);
            const vfd = try proc.fd_table.insert(file);
            return replySuccess(notif.id, @intCast(vfd));
        },
    }
}
