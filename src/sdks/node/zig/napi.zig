pub const c = @cImport(@cInclude("node_api.h"));
const std = @import("std");

// Global allocator is unique per thread that imports this lib
var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
pub const allocator = gpa.allocator();

// Helpful utils

pub fn throw(env: c.napi_env, comptime msg: [:0]const u8) void {
    const res = c.napi_throw_error(env, null, msg);
    if (res != c.napi_ok and res != c.napi_pending_exception) unreachable;
}

pub fn getUndefined(env: c.napi_env) !c.napi_value {
    var result: c.napi_value = undefined;
    if (c.napi_get_undefined(env, &result) != c.napi_ok) {
        throw(env, "Failed to get undefined");
        return error.NapiError;
    }
    return result;
}

pub fn castSelf(comptime T: type, env: c.napi_env, info: c.napi_callback_info) !*T {
    var argc: usize = 1;
    var argv: [1]c.napi_value = undefined;
    if (c.napi_get_cb_info(env, info, &argc, &argv, null, null) != c.napi_ok) {
        throw(env, "Failed to get callback info");
        return error.NapiError;
    }
    if (argc < 1) {
        throw(env, "Expected " ++ @typeName(T) ++ " argument");
        return error.NapiError;
    }
    var data: ?*anyopaque = null;
    if (c.napi_get_value_external(env, argv[0], &data) != c.napi_ok) {
        throw(env, "Argument must be " ++ @typeName(T));
        return error.NapiError;
    }
    if (data) |ptr| {
        const self: *T = @ptrCast(@alignCast(ptr));
        return self;
    }
    throw(env, "Null " ++ @typeName(T) ++ " pointer");
    return error.NapiError;
}

// Module declaration

pub fn External(comptime T: type) type {
    return struct {
        pub fn create(env: c.napi_env, _: c.napi_callback_info) callconv(.c) c.napi_value {
            const self = T.init(allocator) catch {
                throw(env, "Failed to initialize " ++ @typeName(T));
                return null;
            };
            var result: c.napi_value = undefined;
            if (c.napi_create_external(env, self, finalize, null, &result) != c.napi_ok) {
                self.deinit(allocator);
                throw(env, "Failed to create " ++ @typeName(T));
                return null;
            }
            return result;
        }

        pub fn finalize(_: c.napi_env, data: ?*anyopaque, _: ?*anyopaque) callconv(.c) void {
            if (data) |ptr| {
                var self: *T = @ptrCast(@alignCast(ptr));
                self.deinit(allocator);
            }
            return;
        }
    };
}

pub fn registerFunction(
    env: c.napi_env,
    exports: c.napi_value,
    comptime name: [:0]const u8,
    func: *const fn (c.napi_env, c.napi_callback_info) callconv(.c) c.napi_value,
) !void {
    var napi_fn: c.napi_value = undefined;
    if (c.napi_create_function(env, null, 0, func, null, &napi_fn) != c.napi_ok) {
        throw(env, "Failed to create " ++ name);
        return error.NapiError;
    }
    if (c.napi_set_named_property(env, exports, name, napi_fn) != c.napi_ok) {
        throw(env, "Failed to export " ++ name);
        return error.NapiError;
    }
}
