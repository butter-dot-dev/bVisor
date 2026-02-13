const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

// exit_group exits all threads in a thread group
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch return replyContinue(notif.id);
    std.debug.assert(caller.tid == caller_tid);

    // Send SIGKILL for any Thread-s in the caller's ThreadGroup
    var tg_iter = caller.thread_group.threads.iterator();
    while (tg_iter.next()) |entry| {
        const thread = entry.value_ptr.*;
        if (thread != caller) {
            const rc = linux.kill(thread.tid, linux.SIG.KILL);
            checkErr(rc, "exit_group: kill({d})", .{thread.tid}) catch {};
        }
    }

    // Clean up virtual Thread entry before kernel handles the exit
    // Ignore errors - Thread may have already been cleaned up
    supervisor.guest_threads.handleThreadExit(caller_tid) catch {};

    // Let kernel execute the actual exit_group syscall
    return replyContinue(notif.id);
}
