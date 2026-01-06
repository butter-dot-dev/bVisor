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
// Buffer to hold the data
data_buf: [4096]u8,
data_len: usize,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .buf_ptr = notif.data.arg1,
        .count = @min(@as(usize, @truncate(notif.data.arg2)), 4096),
        .data_buf = undefined,
        .data_len = 0,
    };

    // Read buffer data from child memory in one syscall
    try mem_bridge.readSlice(self.data_buf[0..self.count], self.buf_ptr);
    self.data_len = self.count;

    return self;
}

pub fn handle(self: Self, supervisor: anytype) !Result {
    const logger = supervisor.logger;

    logger.log("Emulating write: fd={d} count={d}", .{ self.fd, self.data_len });

    // If fd is stdout (1) or stderr (2), passthrough to kernel
    if (self.fd == 1 or self.fd == 2) {
        logger.log("write: passthrough for fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Otherwise, write to virtual filesystem
    const filesystem = &supervisor.filesystem;

    // Check if this is a virtual FD
    if (!filesystem.isVirtualFD(self.fd)) {
        logger.log("write: fd={d} is not a virtual FD, returning BADF", .{self.fd});
        return .{ .handled = Result.Handled.err(.BADF) };
    }

    const data = self.data_buf[0..self.data_len];
    const bytes_written = filesystem.write(self.fd, data) catch |err| {
        logger.log("write failed: {}", .{err});
        return .{ .handled = Result.Handled.err(.BADF) };
    };

    logger.log("write: wrote {d} bytes to virtual fd={d}", .{ bytes_written, self.fd });
    return .{ .handled = Result.Handled.success(@intCast(bytes_written)) };
}
