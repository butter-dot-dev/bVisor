const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const AbsTgid = Thread.AbsTgid;
const Threads = @import("../../proc/Threads.zig");
const CloneFlags = Threads.CloneFlags;
const proc_info = @import("../../../deps/deps.zig").proc_info;
const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;
const isError = @import("../../../seccomp/notif.zig").isError;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const caller_tid: AbsTid = @intCast(notif.pid);

    const caller = supervisor.guest_threads.get(caller_tid) catch |err| {
        std.log.err("getppid: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };

    // Return parent's kernel TGID, or 0 if:
    // - No parent (sandbox root)
    // - Parent not visible (e.g., in CLONE_NEWPID case where parent is in different namespace)
    if (caller.parent == null) return replySuccess(notif.id, 0);
    const parent = caller.parent.?;
    if (!caller.canSee(parent)) return replySuccess(notif.id, 0);

    // Caller can see parent, but we need to remap to AbsTgid
    const abs_ptgid = caller.namespace.getAbsTgid(parent) orelse std.debug.panic("getppid: Supervisor invariant violated - Thread's Namespace doesn't contain itself", .{});

    return replySuccess(notif.id, @intCast(abs_ptgid));
}

test "getppid for init Thread returns 0" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const notif = makeNotif(.getppid, .{ .pid = init_tid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(@as(i64, 0), resp.val);
}

test "getppid for child returns parent's AbsTgid" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    // Add a child Thread
    const child_tid: AbsTid = 200;
    const parent = supervisor.guest_threads.lookup.get(init_tid).?;
    _ = try supervisor.guest_threads.registerChild(parent, child_tid, CloneFlags.from(0));

    // Child calls getppid
    const notif = makeNotif(.getppid, .{ .pid = child_tid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    // Parent's AbsTgid
    try testing.expectEqual(@as(i64, init_tid), resp.val);
}

test "getppid for grandchild returns parent's AbsTgid" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    // Create: init(100) -> child(200) -> grandchild(300)
    const child_tid: AbsTid = 200;
    const parent = supervisor.guest_threads.lookup.get(init_tid).?;
    _ = try supervisor.guest_threads.registerChild(parent, child_tid, CloneFlags.from(0));

    const grandchild_tid: AbsTid = 300;
    const child = supervisor.guest_threads.lookup.get(child_tid).?;
    _ = try supervisor.guest_threads.registerChild(child, grandchild_tid, CloneFlags.from(0));

    // Grandchild calls getppid
    const notif = makeNotif(.getppid, .{ .pid = grandchild_tid });
    const resp = handle(notif, &supervisor);

    try testing.expect(!isError(resp));
    // Parent's AbsTgid
    try testing.expectEqual(@as(i64, child_tid), resp.val);
}

test "getppid for CLONE_NEWPID immediate child returns 0" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();
    defer proc_info.testing.reset(allocator);

    // Child in new Namespace (depth 2, PID 1 in its own Namespace)
    const child_tid: AbsTid = 200;
    const abstgids = [_]AbsTgid{ 200, 1 };
    try proc_info.testing.setupAbsTgids(allocator, child_tid, &abstgids);

    const parent = supervisor.guest_threads.lookup.get(init_tid).?;
    _ = try supervisor.guest_threads.registerChild(parent, child_tid, CloneFlags.from(linux.CLONE.NEWPID));

    // Child calls getppid - parent is not visible from within child's Namespace
    const notif = makeNotif(.getppid, .{ .pid = child_tid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    // Parent not visible, returns 0
    try testing.expectEqual(@as(i64, 0), resp.val);
}
