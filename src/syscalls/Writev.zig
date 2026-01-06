const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

const MAX_IOV = 16;

fd: FD,
iov_ptr: u64,
iovcnt: usize,
// Store the iovec array and buffer data
iovecs: [MAX_IOV]posix.iovec_const,
// Total data to write (concatenated from all iovecs)
data_buf: [4096]u8,
data_len: usize,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .iov_ptr = notif.data.arg1,
        .iovcnt = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV),
        .iovecs = undefined,
        .data_buf = undefined,
        .data_len = 0,
    };

    // Read iovec array from child memory
    for (0..self.iovcnt) |i| {
        const iov_addr = self.iov_ptr + i * @sizeOf(posix.iovec_const);
        self.iovecs[i] = try mem_bridge.read(posix.iovec_const, iov_addr);
    }

    // Read buffer data from child memory for each iovec (one syscall per iovec)
    for (0..self.iovcnt) |i| {
        const iov = self.iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const buf_len = @min(iov.len, self.data_buf.len - self.data_len);

        if (buf_len > 0) {
            const dest = self.data_buf[self.data_len..][0..buf_len];
            try mem_bridge.readSlice(dest, buf_ptr);
            self.data_len += buf_len;
        }
    }

    return self;
}

pub fn handle(self: Self, supervisor: anytype) !Result {
    const logger = supervisor.logger;

    logger.log("Emulating writev: fd={d} iovcnt={d} total_bytes={d}", .{
        self.fd,
        self.iovcnt,
        self.data_len,
    });

    // If fd is stdout (1) or stderr (2), passthrough to kernel
    if (self.fd == 1 or self.fd == 2) {
        logger.log("writev: passthrough for fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Otherwise, write to virtual filesystem
    const filesystem = &supervisor.filesystem;

    // Check if this is a virtual FD
    if (!filesystem.isVirtualFD(self.fd)) {
        logger.log("writev: fd={d} is not a virtual FD, returning EBADF", .{self.fd});
        return .{ .handled = Result.Handled.err(.BADF) };
    }

    const data = self.data_buf[0..self.data_len];
    const bytes_written = filesystem.write(self.fd, data) catch |err| {
        logger.log("writev failed: {}", .{err});
        return .{ .handled = Result.Handled.err(.BADF) };
    };

    logger.log("writev: wrote {d} bytes to virtual fd={d}", .{ bytes_written, self.fd });
    return .{ .handled = Result.Handled.success(@intCast(bytes_written)) };
}
