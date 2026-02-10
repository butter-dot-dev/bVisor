const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");
const Io = std.Io;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const replyErr = @import("../../../seccomp/notif.zig").replyErr;

// comptime dependency injection
const deps = @import("../../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: sysinfo(struct sysinfo *info)
    const buf_addr: u64 = notif.data.arg0;

    // Get real kernel sysinfo (memory, loads, swap, etc.)
    var info: linux.Sysinfo = undefined;
    if (comptime builtin.is_test) {
        info = std.mem.zeroes(linux.Sysinfo);
    } else {
        const rc = linux.sysinfo(&info);
        if (linux.errno(rc) != .SUCCESS) {
            logger.log("sysinfo: kernel sysinfo failed", .{});
            return replyErr(notif.id, .NOSYS);
        }
    }

    // Virtualize only procs and uptime
    // TODO: come back and virtualize totalram and freeram
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        info.procs = @intCast(@min(supervisor.guest_threads.lookup.count(), std.math.maxInt(u16)));
        const now = Io.Clock.awake.now(supervisor.io) catch |err| {
            logger.log("sysinfo: failed to get current timestamp: {}", .{err});
            return replyErr(notif.id, .INVAL);
        };
        info.uptime = supervisor.start_time.durationTo(now).toSeconds();
    }

    const info_bytes = std.mem.asBytes(&info);
    memory_bridge.writeSlice(info_bytes, @intCast(notif.pid), buf_addr) catch {
        return replyErr(notif.id, .FAULT);
    };

    return replySuccess(notif.id, 0);
}

test "sysinfo returns virtualized system info" {
    const allocator = testing.allocator;
    const init_tid: linux.pid_t = 12345;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    var info: linux.Sysinfo = undefined;
    const notif = makeNotif(.sysinfo, .{ .pid = init_tid, .arg0 = @intFromPtr(&info) });
    const resp = handle(notif, &supervisor);

    try testing.expectEqual(@as(i64, 0), resp.val);
    try testing.expectEqual(@as(i32, 0), resp.@"error");

    // Virtualized fields
    try testing.expectEqual(@as(u16, 1), info.procs); // one initial thread
    try testing.expectEqual(@as(isize, 0), info.uptime);

    // Kernel-sourced fields are zeroed in test mode (no real syscall)
    try testing.expectEqual(@as(usize, 0), info.totalram);
    try testing.expectEqual(@as(usize, 0), info.freeram);
    try testing.expectEqual(@as(u32, 0), info.mem_unit);
}
