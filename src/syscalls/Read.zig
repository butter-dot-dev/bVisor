const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

fd: FD,
buf_ptr: u64,
count: usize,

pub fn parse(_: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    return .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .buf_ptr = notif.data.arg1,
        .count = @min(@as(usize, @truncate(notif.data.arg2)), 4096),
    };
}

pub fn handle(self: Self, supervisor: anytype) !Result {
    const logger = supervisor.logger;
    const filesystem = &supervisor.filesystem;

    logger.log("Emulating read: fd={d} count={d}", .{ self.fd, self.count });

    // If fd is stdin (0), passthrough to kernel
    if (self.fd == 0) {
        logger.log("read: passthrough for fd=0 (stdin)", .{});
        return .{ .passthrough = {} };
    }

    // Check FDBackend - passthrough for kernel FDs or unknown FDs
    const kind = filesystem.getFDBackend(self.fd);
    if (kind == null or std.meta.activeTag(kind.?) == .kernel) {
        logger.log("read: passthrough for kernel/unknown fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Read from virtual filesystem into local buffer
    var local_buf: [4096]u8 = undefined;
    const bytes_read = filesystem.read(self.fd, local_buf[0..self.count]) catch |err| {
        logger.log("read failed: {}", .{err});
        return switch (err) {
            error.NotOpenForReading => .{ .handled = Result.Handled.err(.BADF) },
            error.KernelFD => .{ .passthrough = {} },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    // Write data to child's buffer
    if (bytes_read > 0) {
        try supervisor.mem_bridge.writeSlice(local_buf[0..bytes_read], self.buf_ptr);
    }

    logger.log("read: read {d} bytes from virtual fd={d}", .{ bytes_read, self.fd });
    return .{ .handled = Result.Handled.success(@intCast(bytes_read)) };
}
