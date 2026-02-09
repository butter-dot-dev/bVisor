const std = @import("std");
const napi = @import("napi.zig");
const core = @import("core");
const c = napi.c;
const LogBuffer = core.LogBuffer;

/// Stream is the interface exposed to Node
/// It's a simple wrapper around a LogBuffer for stdout or stderr
const Self = @This();

io: std.Io,
buffer: LogBuffer,

pub fn init(allocator: std.mem.Allocator, io: std.Io) !*Self {
    const self = try allocator.create(Self);
    self.* = .{ .io = io, .buffer = LogBuffer.init(allocator) };
    return self;
}

pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    self.buffer.deinit();
    allocator.destroy(self);
}

/// Returns JS type (Uint8array | none)
pub fn next(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
    const self = napi.ZigExternal(Self).unwrap(env, info) catch return null;

    const data = self.buffer.read(napi.allocator, self.io) catch |err| {
        std.log.err("streamNext failed: {s}", .{@errorName(err)});
        return null;
    };
    defer napi.allocator.free(data); // free the data after it's been returned as a JS-managed Uint8Array
    if (data.len == 0) return null;
    return napi.createUint8Array(env, data.ptr, data.len) catch return null;
}
