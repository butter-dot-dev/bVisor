const napi = @import("napi.zig");
const c = napi.c;
const std = @import("std");

counter: i32 = 0,

const Self = @This();

// Lifecycle helpers expect init/deinit
pub fn init(allocator: std.mem.Allocator) !*Self {
    const self = try allocator.create(Self);
    self.* = .{};
    return self;
}

pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    allocator.destroy(self);
}

// Public API must use napi interface
pub fn increment(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
    const self = napi.castSelf(Self, env, info) catch return null;
    self.counter += 1;
    return napi.getUndefined(env) catch return null;
}

pub fn getValue(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
    const self = napi.castSelf(Self, env, info) catch return null;
    var result: c.napi_value = undefined;
    if (c.napi_create_int32(env, self.counter, &result) != c.napi_ok) {
        napi.throw(env, "Failed to create int32");
        return null;
    }
    return result;
}
