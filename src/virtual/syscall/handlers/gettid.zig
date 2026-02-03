const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const NsTid = Thread.NsTid;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

/// gettid returns the TID of a thread.
/// For the thread group leader, this equals its TID.
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_tid: AbsTid = @intCast(notif.pid);

    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        std.log.err("gettid: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };

    // should hold that the resulting caller's TID : AbsTid matches the original caller_tid : AbsTid
    if (caller.tid != caller_tid) unreachable;

    const ns_tid = caller.namespace.getNsTid(caller) orelse std.debug.panic("gettid: Supervisor invariant violated - Thread's Namespace doesn't contain the Thread itself", .{});

    return replySuccess(notif.id, @intCast(ns_tid));
}
