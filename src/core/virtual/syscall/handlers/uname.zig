const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

const memory_bridge = @import("../../../utils/memory_bridge.zig");

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

/// Convert a comptime string literal into a [64:0]u8 utsname field.
fn utsField(comptime str: []const u8) [64:0]u8 {
    if (str.len > 64) @compileError("utsname field exceeds 64 bytes");
    var field: [64:0]u8 = std.mem.zeroes([64:0]u8);
    @memcpy(field[0..str.len], str);
    return field;
}

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: uname(struct utsname *buf)
    const buf_addr: u64 = notif.data.arg0;

    // Get real kernel utsname (sysname, release, version, machine)
    var uts: linux.utsname = undefined;
    const rc = linux.uname(&uts);
    if (linux.errno(rc) != .SUCCESS) {
        logger.log("uname: kernel uname failed", .{});
        return replyErr(notif.id, .NOSYS);
    }

    // Virtualize only identity-leaking fields
    uts.nodename = utsField("bvisor");
    uts.domainname = utsField("(none)");

    const uts_bytes = std.mem.asBytes(&uts);
    memory_bridge.writeSlice(uts_bytes, @intCast(notif.pid), buf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };

    return replySuccess(notif.id, 0);
}

test "uname returns virtualized system info" {
    const allocator = testing.allocator;
    const init_tid: linux.pid_t = 12345;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var uts: linux.utsname = undefined;
    const notif = makeNotif(.uname, .{ .pid = init_tid, .arg0 = @intFromPtr(&uts) });
    const resp = handle(notif, &supervisor);

    try testing.expectEqual(@as(i64, 0), resp.val);
    try testing.expectEqual(@as(i32, 0), resp.@"error");

    // Virtualized fields
    try testing.expectEqualStrings("bvisor", std.mem.sliceTo(&uts.nodename, 0));
    try testing.expectEqualStrings("(none)", std.mem.sliceTo(&uts.domainname, 0));

    // Kernel-sourced fields should be populated from real uname()
    try testing.expect(std.mem.sliceTo(&uts.sysname, 0).len > 0);
    try testing.expect(std.mem.sliceTo(&uts.release, 0).len > 0);
    try testing.expect(std.mem.sliceTo(&uts.machine, 0).len > 0);
}
