const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const File = @import("../../fs/File.zig");

const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

/// I don't quite understand what to do about the fact that we might try to passthrough our VirtualFDs to the kernel, which wouldn't make sense... do we have a way to translate?
/// Still a WIP
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: fstat(fd, statbuf)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));
    const statbuf_addr: u64 = notif.data.arg1;

    // stdio: passthrough
    if (fd >= 0 and fd <= 2) {
        logger.log("fstat: passthrough for stdio fd={d}", .{fd});
        return replyContinue(notif.id);
    }

    // Look up the file
    var file: *File = undefined;
    {
        supervisor.mutex.lock();
        defer supervisor.mutex.unlock();

        // Get caller Thread
        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            std.log.err("fstat: Thread not found with tid={d}: {}", .{ caller_tid, err });
            return replyContinue(notif.id);
        };
        std.debug.assert(caller.tid == caller_tid);

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("fstat: EBADF for fd={d}", .{fd});
            return replyErr(notif.id, .BADF);
        };
    }
    defer file.unref();

    // Get stat based on the backend type
    const statx_buf = file.statx() catch |err| {
        logger.log("fstat: Unable to produce stat for fd={d}: {}", .{ fd, err });
        return replyErr(notif.id, .IO);
    };

    // Write stat struct to guest memory
    const statx_bytes = std.mem.asBytes(&statx_buf);
    memory_bridge.writeSlice(statx_bytes, @intCast(notif.pid), statbuf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };

    return replySuccess(notif.id, 0);
}
