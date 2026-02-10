const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

/// Machine name derived from the build target's CPU architecture.
const machine_name = switch (builtin.cpu.arch) {
    .aarch64 => "aarch64",
    .x86_64 => "x86_64",
    .arm => "armv7l",
    .riscv64 => "riscv64",
    else => "unknown",
};

/// Convert a comptime string literal into a [64:0]u8 utsname field.
fn utsField(comptime str: []const u8) [64:0]u8 {
    comptime {
        if (str.len > 64) @compileError("utsname field exceeds 64 bytes");
        var field: [64:0]u8 = std.mem.zeroes([64:0]u8);
        @memcpy(field[0..str.len], str);
        return field;
    }
}

pub fn handle(notif: linux.SECCOMP.notif, _: *Supervisor) linux.SECCOMP.notif_resp {
    // Parse args: uname(struct utsname *buf)
    const buf_addr: u64 = notif.data.arg0;

    // Construct a virtualized utsname:
    // - sysname, release, version, machine: safe to report (kernel/hardware info)
    // - nodename, domainname: virtualized (host identity leak)
    const uts = linux.utsname{
        .sysname = utsField("Linux"),
        .nodename = utsField("bvisor"),
        .release = utsField("6.1.0"),
        .version = utsField("#1 SMP"),
        .machine = utsField(machine_name),
        .domainname = utsField("(none)"),
    };

    const uts_bytes = std.mem.asBytes(&uts);
    memory_bridge.writeSlice(uts_bytes, @intCast(notif.pid), buf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };

    return replySuccess(notif.id, 0);
}

test "uname returns virtualized system info" {
    const allocator = testing.allocator;
    const init_tid: linux.pid_t = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    var uts: linux.utsname = undefined;
    const notif = makeNotif(.uname, .{ .pid = init_tid, .arg0 = @intFromPtr(&uts) });
    const resp = handle(notif, &supervisor);

    try testing.expectEqual(@as(i64, 0), resp.val);
    try testing.expectEqual(@as(i32, 0), resp.@"error");
    try testing.expectEqualStrings("Linux", std.mem.sliceTo(&uts.sysname, 0));
    try testing.expectEqualStrings("bvisor", std.mem.sliceTo(&uts.nodename, 0));
    try testing.expectEqualStrings("6.1.0", std.mem.sliceTo(&uts.release, 0));
    try testing.expectEqualStrings("#1 SMP", std.mem.sliceTo(&uts.version, 0));
    try testing.expectEqualStrings(machine_name, std.mem.sliceTo(&uts.machine, 0));
    try testing.expectEqualStrings("(none)", std.mem.sliceTo(&uts.domainname, 0));
}
