const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const checkErr = @import("../../../linux_error.zig").checkErr;
const Allocator = std.mem.Allocator;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;

/// exit exits just the calling thread. In a multi-threaded process, other threads continue.
/// exit_group exits all threads in the thread group.
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        std.log.err("exit: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyContinue(notif.id);
    };
    std.debug.assert(caller.tid == caller_tid);

    if (caller.isNamespaceRoot()) {
        // Namespace root exit: kill entire namespace / all descendants of the root process
        var iter = caller.namespace.threads.iterator();
        while (iter.next()) |entry| {
            const thread = entry.value_ptr.*;
            if (thread != caller) {
                // Send SIGKILL for any descendants (which will trigger other `exit` syscalls via the kernel)
                const rc = linux.kill(thread.tid, linux.SIG.KILL);
                checkErr(rc, "exit: kill({d}) during namespace cleanup", .{thread.tid}) catch {};
            }
        }
    }

    // Clean up virtual Thread entry before kernel handles the exit
    // Ignore errors - process may have already been cleaned up
    supervisor.guest_threads.handleThreadExit(caller_tid) catch {};

    // Let kernel execute the actual exit syscall
    return replyContinue(notif.id);
}
