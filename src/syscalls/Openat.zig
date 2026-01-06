const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

dirfd: i32,
pathname_ptr: u64,
pathname: [256]u8,
pathname_len: usize,
flags: u32,
mode: u32,

pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !Self {
    var self: Self = .{
        .dirfd = @bitCast(@as(u32, @truncate(notif.data.arg0))),
        .pathname_ptr = notif.data.arg1,
        .pathname = undefined,
        .pathname_len = 0,
        .flags = @truncate(notif.data.arg2),
        .mode = @truncate(notif.data.arg3),
    };

    // Read pathname from child memory (null-terminated string)
    // Read up to 256 bytes
    self.pathname = try mem_bridge.read([256]u8, notif.data.arg1);

    // Find null terminator
    self.pathname_len = std.mem.indexOfScalar(u8, &self.pathname, 0) orelse 256;

    return self;
}

pub fn handle(self: Self, supervisor: anytype) !Result {
    const logger = supervisor.logger;
    const filesystem = &supervisor.filesystem;

    const path = self.pathname[0..self.pathname_len];
    logger.log("Emulating openat: dirfd={d} path=\"{s}\" flags=0x{x} mode=0o{o}", .{
        self.dirfd,
        path,
        self.flags,
        self.mode,
    });

    // Create virtual file
    const fd = filesystem.open(path, self.flags, self.mode) catch |err| {
        logger.log("openat failed: {}", .{err});
        return switch (err) {
            error.PermissionDenied => .{ .handled = Result.Handled.err(.ACCES) },
            error.FileNotFound => .{ .handled = Result.Handled.err(.NOENT) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    logger.log("openat: created virtual fd={d}", .{fd});
    return .{ .handled = Result.Handled.success(fd) };
}
