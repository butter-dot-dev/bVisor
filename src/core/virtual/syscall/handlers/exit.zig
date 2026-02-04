const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

/// exit exits just the calling thread. In a multi-threaded process, other threads continue.
/// exit_group exits all threads in the thread group.
/// Since bVisor doesn't support multi-threading yet, both behave the same.
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    supervisor.mutex.lock();
    defer supervisor.mutex.unlock();

    // Clean up virtual Thread entry before kernel handles the exit
    // Ignore errors - process may have already been cleaned up
    supervisor.guest_threads.handleThreadExit(caller_tid) catch {};

    // Let kernel execute the actual exit syscall
    return replyContinue(notif.id);
}
