const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;
const Supervisor = @import("../Supervisor.zig");

const Self = @This();

const MAX_IOV = 16;

fd: FD,
iov_ptr: u64,
iovcnt: usize,
// Store the iovec array (buffer addresses and lengths)
iovecs: [MAX_IOV]posix.iovec,
total_len: usize,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .fd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .iov_ptr = notif.data.arg1,
        .iovcnt = @min(@as(usize, @truncate(notif.data.arg2)), MAX_IOV),
        .iovecs = undefined,
        .total_len = 0,
    };

    // Read iovec array from child memory
    for (0..self.iovcnt) |i| {
        const iov_addr = self.iov_ptr + i * @sizeOf(posix.iovec);
        self.iovecs[i] = try mem_bridge.read(posix.iovec, iov_addr);
        self.total_len += self.iovecs[i].len;
    }

    return self;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;
    const filesystem = &supervisor.filesystem;

    logger.log("Emulating readv: fd={d} iovcnt={d} total_len={d}", .{
        self.fd,
        self.iovcnt,
        self.total_len,
    });

    // stdin passthrough
    if (self.fd == 0) {
        logger.log("readv: passthrough for fd=0 (stdin)", .{});
        return .{ .passthrough = {} };
    }

    // Check FDBackend - passthrough for kernel FDs or unknown FDs
    const kind = filesystem.getFDBackend(self.fd);
    if (kind == null or std.meta.activeTag(kind.?) == .kernel) {
        logger.log("readv: passthrough for kernel/unknown fd={d}", .{self.fd});
        return .{ .passthrough = {} };
    }

    // Read from virtual filesystem into local buffer
    const read_len = @min(self.total_len, 4096);
    var local_buf: [4096]u8 = undefined;
    const bytes_read = filesystem.read(self.fd, local_buf[0..read_len]) catch |err| {
        logger.log("readv failed: {}", .{err});
        return switch (err) {
            error.NotOpenForReading => .{ .handled = Result.Handled.err(.BADF) },
            error.KernelFD => .{ .passthrough = {} },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    // Write data to child's iovec buffers
    var offset: usize = 0;
    for (0..self.iovcnt) |i| {
        if (offset >= bytes_read) break;

        const iov = self.iovecs[i];
        const buf_ptr = @intFromPtr(iov.base);
        const to_copy = @min(iov.len, bytes_read - offset);

        if (to_copy > 0) {
            try supervisor.mem_bridge.writeSlice(local_buf[offset..][0..to_copy], buf_ptr);
            offset += to_copy;
        }
    }

    logger.log("readv: read {d} bytes from virtual fd={d}", .{ bytes_read, self.fd });
    return .{ .handled = Result.Handled.success(@intCast(bytes_read)) };
}
