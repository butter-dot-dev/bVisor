const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../Supervisor.zig");

const Self = @This();

fd: FD,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    _ = mem_bridge;
    return .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
    };
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const filesystem = &supervisor.filesystem;

    logger.log("Emulating close: fd={d}", .{self.fd});

    // stdin/stdout/stderr always passthrough
    if (self.fd >= 0 and self.fd <= 2) {
        logger.log("close: passthrough for stdio fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Check FDBackend - passthrough for kernel FDs or unknown FDs
    const kind = filesystem.getFDBackend(self.fd);
    if (kind == null or std.meta.activeTag(kind.?) == .kernel) {
        // Unknown or kernel FD - passthrough to kernel
        logger.log("close: passthrough for kernel/unknown fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Virtual FD - close in VFS
    filesystem.close(self.fd);
    logger.log("close: closed virtual fd={d}", .{self.fd});
    return .{ .handled = Result.Handled.success(0) };
}
