const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../LinuxErr.zig").LinuxErr;
const checkErr = @import("../../../LinuxErr.zig").checkErr;
const Supervisor = @import("../../../Supervisor.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const LogBuffer = @import("../../../LogBuffer.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const AbsTgid = Thread.AbsTgid;
const NsTgid = Thread.NsTgid;
const Threads = @import("../../proc/Threads.zig");
const CloneFlags = Threads.CloneFlags;
const proc_info = @import("../../../utils/proc_info.zig");
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;

/// getpid return the namespaced TGID of the thread
pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    supervisor.mutex.lockUncancelable(supervisor.io);
    defer supervisor.mutex.unlock(supervisor.io);

    // Parse args
    const caller_tid: AbsTid = @intCast(notif.pid);

    // Get caller Thread
    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        std.log.err("getpid: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return LinuxErr.SRCH;
    };
    std.debug.assert(caller.tid == caller_tid);

    // Get leader of caller's ThreadGroup
    const leader = caller.thread_group.getLeader() catch |err| {
        std.log.err("getpid: Thread not found with tid={d}: {}", .{ caller.get_tgid(), err });
        return LinuxErr.SRCH;
    };

    // Get namespaced TGID of the caller's ThreadGroup, which matches the namespaced TID of its leader
    const ns_tgid: NsTgid = leader.namespace.getNsTid(leader) orelse std.debug.panic("getpid: Supervisor invariant violated - Thread's group leader's Namespace doesn't contain the leader Thread itself", .{});

    return replySuccess(notif.id, @intCast(ns_tgid));
}

test "getpid returns init Thread's AbsTgid" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 12345;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.getpid, .{ .pid = init_tid });
    const resp = handle(notif, &supervisor);
    try testing.expectEqual(init_tid, resp.val);
}

test "getpid for child Thread returns its AbsTgid" {
    const allocator = testing.allocator;
    // Add an initial guest
    const init_guest_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_guest_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    // Add a child to the initial guest
    const child_tid: AbsTid = 200;
    const init_thread = supervisor.guest_threads.lookup.get(init_guest_tid).?;
    _ = try supervisor.guest_threads.registerChild(init_thread, child_tid, CloneFlags.from(0));

    // Child calls getpid
    //   ... supposing converted child's requested pid to be :AbsTid
    const notif = makeNotif(.getpid, .{ .pid = child_tid });
    const resp = handle(notif, &supervisor);
    try testing.expectEqual(child_tid, resp.val);
}
