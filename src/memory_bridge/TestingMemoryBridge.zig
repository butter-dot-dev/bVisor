const std = @import("std");
const linux = std.os.linux;

const Self = @This();

// No child_pid needed for testing - we read/write local memory

pub fn init(_: linux.pid_t) Self {
    return .{};
}

/// Read an object of type T from addr (treated as local pointer)
pub fn read(_: Self, T: type, addr: u64) !T {
    const ptr: *const T = @ptrFromInt(addr);
    return ptr.*;
}

/// Read bytes from addr into dest (local memcpy)
pub fn readSlice(_: Self, dest: []u8, addr: u64) !void {
    const src: [*]const u8 = @ptrFromInt(addr);
    @memcpy(dest, src[0..dest.len]);
}

/// Write val to addr (treated as local pointer)
pub fn write(_: Self, T: type, val: T, addr: u64) !void {
    const ptr: *T = @ptrFromInt(addr);
    ptr.* = val;
}
