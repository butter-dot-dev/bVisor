const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {

    supervisor.mutex.lock();
    defer supervisor.mutex.unlock();

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    // Clean up virtual Thread entry before kernel handles the exit
    // Ignore errors - Thread may have already been cleaned up
    supervisor.guest_threads.handleThreadExit(caller_tid) catch {};

    // Let kernel execute the actual exit_group syscall
    return replyContinue(notif.id);
}
