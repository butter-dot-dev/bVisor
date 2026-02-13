const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const Supervisor = @import("../../../Supervisor.zig");
const replySuccess = @import("../../../seccomp/notif.zig").replySuccess;
const File = @import("../../fs/File.zig");
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    const logger = supervisor.logger;

    // Parse args: ioctl(fd, request, argp)
    const caller_tid: AbsTid = @intCast(notif.pid);
    const fd: i32 = @bitCast(@as(u32, @truncate(notif.data.arg0)));

    // argp is either a pointer to guest-owned data, or an integer
    const argp: u64 = notif.data.arg2;
    // request tells us how to treat that argp
    const request: linux.IOCTL.Request = @bitCast(@as(u32, @truncate(notif.data.arg1)));

    // Critical section: File lookup
    var file: *File = undefined;
    {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);
        std.debug.assert(caller.tid == caller_tid);

        file = caller.fd_table.get_ref(fd) orelse {
            logger.log("ioctl: EBADF for fd={d}", .{fd});
            return LinuxErr.BADF;
        };
    }
    defer file.unref();

    // If size is 0, argp is an integer value, not a pointer
    const size: usize = @intCast(request.size);
    if (size == 0) {
        const ret = try file.ioctl(request, @truncate(argp));
        logger.log("ioctl: fd={d} request=0x{x} (integer) ret={d}", .{ fd, @as(u32, @bitCast(request)), ret });
        return replySuccess(notif.id, @as(i64, @intCast(ret)));
    }

    // Pointer-based ioctl: data is behind a pointer to the guest
    // Direction tells us which way to bridge that data (read, write, read|write)

    // Stack allocate and enforce a size limit
    const max_size = 256;
    if (size > max_size) return LinuxErr.INVAL;
    var buf: [max_size]u8 = undefined;
    const data = buf[0..size];

    // Direction bits: none=0, write=1, read=2, read|write=3
    const dir = request.dir;
    const dir_write = comptime blk: {
        const w: linux.IOCTL.Request = @bitCast(linux.IOCTL.IOW(0, 0, u8));
        break :blk w.dir;
    };
    const dir_read = comptime blk: {
        const r: linux.IOCTL.Request = @bitCast(linux.IOCTL.IOR(0, 0, u8));
        break :blk r.dir;
    };

    // If direction includes write (guest-to-kernel), bridge read data from guest so we can do the supervisor-to-kernel
    if (dir & dir_write != 0) {
        try memory_bridge.readSlice(data, @intCast(notif.pid), argp);
    } else {
        @memset(data, 0);
    }

    // Call the ioctl with write from supervisor memory
    const ret = try file.ioctl(request, @intFromPtr(data.ptr));

    // If direction includes read (kernel-to-guest), bridge write data back to guest
    if (dir & dir_read != 0) {
        try memory_bridge.writeSlice(data, @intCast(notif.pid), argp);
    }

    logger.log("ioctl: fd={d} request=0x{x} size={d} ret={d}", .{ fd, @as(u32, @bitCast(request)), size, ret });
    return replySuccess(notif.id, @as(i64, @intCast(ret)));
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;
const Passthrough = @import("../../fs/backend/passthrough.zig").Passthrough;
const OverlayRoot = @import("../../OverlayRoot.zig");

test "ioctl on non-existent fd returns EBADF" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.ioctl, .{
        .pid = init_tid,
        .arg0 = 99, // non-existent fd
        .arg1 = 0,
        .arg2 = 0,
    });

    try testing.expectError(error.BADF, handle(notif, &supervisor));
}

test "ioctl with unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeNotif(.ioctl, .{
        .pid = 999,
        .arg0 = 3,
        .arg1 = 0,
        .arg2 = 0,
    });

    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}
