const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

fd: FD,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    _ = mem_bridge;
    return .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
    };
}

pub fn handle(self: Self, supervisor: anytype) !Result {
    const logger = supervisor.logger;
    const filesystem = &supervisor.filesystem;

    logger.log("Emulating close: fd={d}", .{self.fd});

    // Only stdin/stdout/stderr (0, 1, 2) pass through - all others are virtual
    if (self.fd >= 0 and self.fd <= 2) {
        logger.log("close: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Otherwise, close virtual file
    if (!filesystem.isVirtualFD(self.fd)) {
        logger.log("close: fd={d} is not a virtual FD, returning EBADF", .{self.fd});
        return .{ .handled = Result.Handled.err(.BADF) };
    }

    filesystem.close(self.fd);
    logger.log("close: closed virtual fd={d}", .{self.fd});
    return .{ .handled = Result.Handled.success(0) };
}
