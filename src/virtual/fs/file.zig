const std = @import("std");
const posix = std.posix;
const Cow = @import("backend/cow.zig").Cow;
const Tmp = @import("backend/tmp.zig").Tmp;
const Proc = @import("backend/proc.zig").Proc;
const Passthrough = @import("backend/passthrough.zig").Passthrough;
const OverlayRoot = @import("../OverlayRoot.zig");

pub const FileBackend = enum { passthrough, cow, tmp, proc };

pub const File = union(FileBackend) {
    passthrough: Passthrough,
    cow: Cow,
    tmp: Tmp,
    proc: Proc,

    pub fn open(backend: FileBackend, overlay: *OverlayRoot, path: []const u8, flags: posix.O, mode: posix.mode_t) !File {
        return switch (backend) {
            .passthrough => .{ .passthrough = try Passthrough.open(overlay, path, flags, mode) },
            .cow => .{ .cow = try Cow.open(overlay, path, flags, mode) },
            .tmp => .{ .tmp = try Tmp.open(overlay, path, flags, mode) },
            .proc => .{ .proc = try Proc.open(path, flags, mode) },
        };
    }

    pub fn read(self: *File, buf: []u8) !usize {
        switch (self.*) {
            inline else => |*f| return f.read(buf),
        }
    }

    pub fn write(self: *File, data: []const u8) !usize {
        switch (self.*) {
            inline else => |*f| return f.write(data),
        }
    }

    pub fn close(self: *File) void {
        switch (self.*) {
            inline else => |*f| f.close(),
        }
    }
};
