const std = @import("std");
const linux = std.os.linux;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const Supervisor = @import("../../../Supervisor.zig");
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: dup(oldfd)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const oldfd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));

    supervisor.mutex.lock();
    defer supervisor.mutex.unlock();

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        logger.log("dup: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };
    std.debug.assert(caller.tid == caller_tid);

    // Look up oldfd
    const file = caller.fd_table.get_ref(oldfd) orelse {
        logger.log("dup: EBADF for oldfd={d}", .{oldfd});
        return replyErr(notif.id, .BADF);
    };
    defer file.unref();

    // Duplicate to next available fd
    const newfd = caller.fd_table.dup(file) catch {
        logger.log("dup: failed to allocate new fd", .{});
        return replyErr(notif.id, .NOMEM);
    };

    logger.log("dup: duplicated fd {d} -> {d}", .{ oldfd, newfd });
    return replySuccess(notif.id, newfd);
}
