const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Io = std.Io;
const File = Io.File;

const Self = @This();

// Buffer is entirely in-memory, no disk offload yet
// Add disk buffering if this starts OOMing
backing: Writer.Allocating,
mutex: Io.Mutex = .init,

pub fn init(gpa: Allocator) Self {
    return .{ .backing = Writer.Allocating.init(gpa) };
}

pub fn deinit(self: *Self) void {
    self.backing.deinit();
}

/// Append data to buffer.
/// Awaits internal mutex.
pub fn write(self: *Self, io: Io, data: []const u8) !void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    try self.backing.writer.writeAll(data);
}

/// Drain buffer: returns a copy of accumulated data and clears the buffer.
/// Caller owns the returned slice.
pub fn read(self: *Self, allocator: Allocator, io: Io) ![]u8 {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const data = self.backing.written();
    const copy = try allocator.dupe(u8, data);
    self.backing.clearRetainingCapacity();
    return copy;
}

pub fn len(self: *Self, io: Io) usize {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    return self.backing.written().len;
}

/// Drain buffer to a file.
pub fn flush(self: *Self, io: Io, file: File) !void {
    self.mutex.lockUncancelable(io);
    defer self.mutex.unlock(io);
    const data = self.backing.written();
    if (data.len > 0) {
        try writeToFile(file, io, data);
        self.backing.clearRetainingCapacity();
    }
}

fn writeToFile(file: File, io: Io, data: []const u8) !void {
    if (comptime builtin.is_test) return;
    var buf: [4096]u8 = undefined;
    var w = file.writerStreaming(io, &buf);
    try w.interface.writeAll(data);
    try w.interface.flush();
}

test "write and read" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var buf = Self.init(allocator);
    defer buf.deinit();

    try buf.write(io, "hello");
    try std.testing.expectEqual(5, buf.len(io));

    const data = try buf.read(allocator, io);
    defer allocator.free(data);
    try std.testing.expectEqualStrings("hello", data);

    try std.testing.expectEqual(0, buf.len(io));
}

test "read returns independent copy" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var buf = Self.init(allocator);
    defer buf.deinit();

    try buf.write(io, "before");
    const copy = try buf.read(allocator, io);
    defer allocator.free(copy);

    try buf.write(io, " after");

    try std.testing.expectEqualStrings("before", copy);
}

test "successive drains" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var buf = Self.init(allocator);
    defer buf.deinit();

    try buf.write(io, "first");
    const d1 = try buf.read(allocator, io);
    defer allocator.free(d1);
    try std.testing.expectEqualStrings("first", d1);

    try buf.write(io, "second");
    const d2 = try buf.read(allocator, io);
    defer allocator.free(d2);
    try std.testing.expectEqualStrings("second", d2);
}
