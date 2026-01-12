const std = @import("std");
const linux = std.os.linux;

/// Read an object of type T from addr (treated as local pointer)
pub inline fn read(T: type, _: linux.pid_t, addr: u64) !T {
    const ptr: *const T = @ptrFromInt(addr);
    return ptr.*;
}

/// Read bytes from addr into dest (local memcpy)
pub inline fn readSlice(dest: []u8, _: linux.pid_t, addr: u64) !void {
    const src: [*]const u8 = @ptrFromInt(addr);
    @memcpy(dest, src[0..dest.len]);
}

/// Write val to addr (treated as local pointer)
pub inline fn write(T: type, _: linux.pid_t, val: T, addr: u64) !void {
    const ptr: *T = @ptrFromInt(addr);
    ptr.* = val;
}

/// Write bytes from src to addr (local memcpy)
pub inline fn writeSlice(src: []const u8, _: linux.pid_t, addr: u64) !void {
    const dest: [*]u8 = @ptrFromInt(addr);
    @memcpy(dest[0..src.len], src);
}
