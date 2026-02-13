const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: dup(oldfd)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const oldfd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = try supervisor.guest_threads.get(caller_tid);
    std.debug.assert(caller.tid == caller_tid);

    // Look up oldfd
    const file = caller.fd_table.get_ref(oldfd) orelse {
        logger.log("dup: EBADF for oldfd={d}", .{oldfd});
        return LinuxErr.BADF;
    };
    defer file.unref();

    // Duplicate to next available fd
    const newfd = try caller.fd_table.dup(file);

    logger.log("dup: duplicated fd {d} -> {d}", .{ oldfd, newfd });
    return replySuccess(notif.id, newfd);
}
