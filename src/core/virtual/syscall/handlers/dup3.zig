const std = @import("std");
const linux = std.os.linux;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const Supervisor = @import("../../../Supervisor.zig");
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: dup3(oldfd, newfd, flags)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const oldfd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const newfd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg1)));
    const flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg2)));

    // dup3 only allows O_CLOEXEC flag
    const expected_flags: linux.O = .{ .CLOEXEC = flags.CLOEXEC };
    if (!std.meta.eql(flags, expected_flags)) {
        return replyErr(notif.id, .INVAL);
    }

    // dup3 requires oldfd != newfd (unlike dup2 which is a no-op)
    if (oldfd == newfd) {
        logger.log("dup3: EINVAL oldfd == newfd == {d}", .{oldfd});
        return replyErr(notif.id, .INVAL);
    }

    // TODO: instead of blocking, need to track stdio in the FdTable, which will require some changes in read/write/close syscall handlers, too
    if (newfd >= 0 and newfd <= 2) {
        logger.log("dup3: stdio redirection not yet supported", .{});
        return replyErr(notif.id, .INVAL);
    }

    supervisor.mutex.lock();
    defer supervisor.mutex.unlock();

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        logger.log("dup3: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };

    // Look up oldfd - get_ref() already adds a reference for us
    // This reference will be owned by the new fd entry
    const file = caller.fd_table.get_ref(oldfd) orelse {
        logger.log("dup3: EBADF for oldfd={d}", .{oldfd});
        return replyErr(notif.id, .BADF);
    };
    defer file.unref();

    // If newfd already exists, close and remove it first
    if (caller.fd_table.get_ref(newfd)) |existing| {
        existing.close();
        existing.unref();
        _ = caller.fd_table.remove(newfd);
    }

    // Duplicate: both fds now point to the same File (mimicking true POSIX dup semantics)
    // The cloexec flag is per-fd, not inherited from oldfd
    _ = caller.fd_table.dup_at(file, newfd, .{ .cloexec = flags.CLOEXEC }) catch {
        logger.log("dup3: failed to dup to newfd={d}", .{newfd});
        return replyErr(notif.id, .NOMEM);
    };

    logger.log("dup3: duplicated fd {d} -> {d}", .{ oldfd, newfd });
    return replySuccess(notif.id, newfd);
}
