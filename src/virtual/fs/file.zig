const Readonly = @import("./files/Readonly.zig");
const Cow = @import("./files/Cow.zig");
const Proc = @import("./files/Proc.zig");
const Tmp = @import("./files/Tmp.zig");

const std = @import("std");
const posix = std.posix;

const FileBackend = enum {
    readonly,
    cow,
    proc,
    tmp,
};

/// File is an FD-like handle on various virtualized file backends
/// FdTable holds VirtualFD -> File mapping
/// Implementations for File found in ./files
pub const File = union(FileBackend) {
    readonly: Readonly,
    cow: Cow,
    proc: Proc,
    tmp: Tmp,

    pub fn open(file_backend: FileBackend, path: []const u8, flags: posix.O, mode: posix.mode_t) !File {
        return switch (file_backend) {
            .readonly => .{ .readonly = try Readonly.open(path, flags, mode) },
            .cow => .{ .cow = try Cow.open(path, flags, mode) },
            .proc => .{ .proc = try Proc.open(path, flags, mode) },
            .tmp => .{ .tmp = try Tmp.open(path, flags, mode) },
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
