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
        std.log.err("getpid: Thread not found with tid={d}: {}", .{ caller_tid, err });
        return replyErr(notif.id, .SRCH);
    };

    const ns_tgid = caller.namespace.getAbsTgid(caller) orelse std.debug.panic("getpid: Supervisor invariant violated - Thread's Namespace doesn't contain itself", .{});

    return replySuccess(notif.id, @intCast(ns_tgid));
}

test "getpid returns init Thread's AbsTgid" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    const notif = makeNotif(.getpid, .{ .pid = init_tid });
    const resp = handle(notif, &supervisor);
    try testing.expectEqual(init_tid, resp.val);
}

test "getpid for child Thread returns its AbsTgid" {
    const allocator = testing.allocator;
    // Add an initial guest
    const init_guest_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_guest_tid);
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

test "getpid from immediate child in new Namespace returns absolute TGID (deprecated?)" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();
    defer proc_info.testing.reset(allocator);

    // Child in new Namespace (depth 2, PID 1 in its own Namespace)
    const child_tid: AbsTid = 9999;
    const abstgids = [_]AbsTgid{ 9999, 1 };
    try proc_info.testing.setupAbsTgids(allocator, child_tid, &abstgids);

    const parent = supervisor.guest_threads.lookup.get(init_tid).?;
    _ = try supervisor.guest_threads.registerChild(parent, child_tid, CloneFlags.from(linux.CLONE.NEWPID));

    // Child calls getpid
    const notif = makeNotif(.getpid, .{ .pid = child_tid });
    const resp = handle(notif, &supervisor);
    try testing.expect(!isError(resp));
    try testing.expectEqual(1, resp.val);
    // Child's AbsTgid should (almost certainly) not match the AbsTid for that child Thread (e.g., 1)
    try testing.expect(child_tid != resp.val);
}
