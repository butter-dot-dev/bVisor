const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const NsTid = Thread.NsTid;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

/// gettid returns the namespaced TID of a thread
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    // Get caller Thread
    const caller = try supervisor.guest_threads.get(caller_tid);
    std.debug.assert(caller.tid == caller_tid);

    // Get namespaced TID of this caller Thread
    const ns_tid = caller.namespace.getNsTid(caller) orelse std.debug.panic("gettid: Supervisor invariant violated - Thread's Namespace doesn't contain the Thread itself", .{});

    return replySuccess(notif.id, @intCast(ns_tid));
}
