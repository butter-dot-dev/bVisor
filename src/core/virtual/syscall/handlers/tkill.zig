const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const NsTid = Thread.NsTid;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

/// tkill(tid, sig) sends a signal to a specific thread.
/// Unlike kill, tid is always a positive TID — no process group semantics.
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);
    const target_nstid: NsTid = @intCast(@as(i64, @bitCast(notif.data.arg0)));
    const signal: u6 = @truncate(notif.data.arg1);

    if (target_nstid <= 0) {
        return replyErr(notif.id, .INVAL);
    }

    // Critical section just to normalize target namespaced TID to absolute TID
    var target_abs_tid: AbsTid = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        // Get caller Thread
        const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
            std.log.err("tkill: Thread not found with tid={d}: {}", .{ caller_tid, err });
            return replyErr(notif.id, .SRCH);
        };
        std.debug.assert(caller.tid == caller_tid);

        // Lookup Thread with matching namespaced TID
        const target = supervisor.guest_threads.getNamespaced(caller, target_nstid) catch |err| {
            std.log.err("tkill: target Thread not found for tid={d}: {}", .{ target_nstid, err });
            return replyErr(notif.id, .SRCH);
        };

        // Yield the targetted TID in absolute terms
        target_abs_tid = target.tid;
    }

    // Execute real tkill syscall outside the lock
    const rc = linux.kill(@intCast(target_abs_tid), @enumFromInt(signal));
    const errno = linux.errno(rc);
    if (errno != .SUCCESS) {
        return replyErr(notif.id, errno);
    }

    // Do not remove from internal Threads tracking.
    // Killing a thread is just a signal invocation.
    // exit is what actually removes it from threads.

    return replySuccess(notif.id, 0);
}
