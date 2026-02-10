const std = @import("std");
const linux = std.os.linux;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;

const TWO_GB: usize = 2 * 1024 * 1024 * 1024;
const ONE_GB: usize = 1 * 1024 * 1024 * 1024;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    // Parse args: sysinfo(struct sysinfo *info)
    const buf_addr: u64 = notif.data.arg0;

    const procs: u16 = undefined;
    const uptime: isize = undefined;

    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        procs = @intCast(@min(supervisor.guest_threads.lookup.count(), std.math.maxInt(u16)));
        uptime = std.time.timestamp() - supervisor.start_time;
    }

    // Construct virtualized sysinfo:
    // - totalram, freeram: hardcoded (hides real host memory config) ?
    // - loads: zeroed (hides host activity from other tenants) ?
    // - procs: supervisor's guest thread count
    // - uptime: difference between now and supervisor's start time
    // - mem_unit: 1 (values are already in bytes)
    var info = std.mem.zeroes(linux.Sysinfo);
    info.totalram = TWO_GB;
    info.freeram = ONE_GB;
    info.procs = procs;
    info.uptime = uptime;
    info.mem_unit = 1;

    const info_bytes = std.mem.asBytes(&info);
    memory_bridge.writeSlice(info_bytes, @intCast(notif.pid), buf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };

    return replySuccess(notif.id, 0);
}

test "sysinfo returns virtualized system info" {
    const allocator = testing.allocator;
    const init_tid: linux.pid_t = 12345;
    var supervisor = try Supervisor.init(allocator, testing.io, -1, init_tid);
    defer supervisor.deinit();

    var info: linux.Sysinfo = undefined;
    const notif = makeNotif(.sysinfo, .{ .pid = init_tid, .arg0 = @intFromPtr(&info) });
    const resp = handle(notif, &supervisor);

    try testing.expectEqual(@as(i64, 0), resp.val);
    try testing.expectEqual(@as(i32, 0), resp.@"error");
    try testing.expectEqual(@as(usize, TWO_GB), info.totalram);
    try testing.expectEqual(@as(usize, ONE_GB), info.freeram);
    try testing.expectEqual(@as(u16, 1), info.procs); // one initial thread
    try testing.expectEqual(@as(u32, 1), info.mem_unit);
    try testing.expectEqual(@as(isize, 0), info.uptime);
    try testing.expectEqual(@as(usize, 0), info.loads[0]);
    try testing.expectEqual(@as(usize, 0), info.loads[1]);
    try testing.expectEqual(@as(usize, 0), info.loads[2]);
    try testing.expectEqual(@as(usize, 0), info.sharedram);
    try testing.expectEqual(@as(usize, 0), info.totalswap);
}
