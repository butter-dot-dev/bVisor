const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory_bridge.zig").MemoryBridge;
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;

const Self = @This();

// Access mode is in the bottom 2 bits of flags
const O_ACCMODE: u32 = 0o3;
const O_RDONLY: u32 = 0o0;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;

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
    const access_mode = self.flags & O_ACCMODE;
    const wants_write = access_mode == O_WRONLY or access_mode == O_RDWR or (self.flags & O_CREAT) != 0;

    logger.log("Emulating openat: dirfd={d} path=\"{s}\" flags=0x{x} mode=0o{o} wants_write={}", .{
        self.dirfd,
        path,
        self.flags,
        self.mode,
        wants_write,
    });

    // Check if file exists in VFS first
    if (filesystem.virtualPathExists(path)) {
        // File in VFS - always use VFS
        const fd = filesystem.open(path, self.flags, self.mode) catch |err| {
            logger.log("openat: VFS open failed: {}", .{err});
            return switch (err) {
                error.PermissionDenied => .{ .handled = Result.Handled.err(.ACCES) },
                error.FileNotFound => .{ .handled = Result.Handled.err(.NOENT) },
                else => .{ .handled = Result.Handled.err(.IO) },
            };
        };
        logger.log("openat: opened from VFS fd={d}", .{fd});
        return .{ .handled = Result.Handled.success(fd) };
    }

    // File not in VFS
    if (!wants_write) {
        // Read-only - passthrough to kernel (no tracking needed)
        logger.log("openat: read-only passthrough for path=\"{s}\"", .{path});
        return .{ .passthrough = {} };
    }

    // Writing - create in VFS (COW: copy from host if exists)
    // TODO: Copy existing file content from host using pidfd_getfd
    const fd = filesystem.open(path, self.flags, self.mode) catch |err| {
        logger.log("openat: VFS create failed: {}", .{err});
        return switch (err) {
            error.PermissionDenied => .{ .handled = Result.Handled.err(.ACCES) },
            error.FileNotFound => .{ .handled = Result.Handled.err(.NOENT) },
            else => .{ .handled = Result.Handled.err(.IO) },
        };
    };

    logger.log("openat: created virtual fd={d}", .{fd});
    return .{ .handled = Result.Handled.success(fd) };
}
