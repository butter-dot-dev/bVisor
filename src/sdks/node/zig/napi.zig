pub const c = @cImport(@cInclude("node_api.h"));
const std = @import("std");

// Global allocator is unique per thread that imports this lib
var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
pub const global_allocator = gpa.allocator();

// Global Io instance, initialized in napi_register_module_v1
var threaded: std.Io.Threaded = undefined;
pub var io: std.Io = undefined;
var io_initialized: bool = false;

pub fn initIo() void {
    threaded = .init(global_allocator, .{ .environ = .empty });
    io = threaded.io();
    io_initialized = true;
}

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

pub fn getNull(env: c.napi_env) !c.napi_value {
    var result: c.napi_value = undefined;
    if (c.napi_get_null(env, &result) != c.napi_ok) {
        throw(env, "Failed to get null");
        return error.NapiError;
    }
    return result;
}

/// Create a JS Uint8Array from a Zig slice
pub fn createUint8Array(env: c.napi_env, ptr: [*]const u8, len: usize) !c.napi_value {
    // Create an ArrayBuffer and copy the data into it
    var data: ?*anyopaque = null;
    var arraybuffer: c.napi_value = undefined;
    if (c.napi_create_arraybuffer(env, len, &data, &arraybuffer) != c.napi_ok) {
        throw(env, "Failed to create arraybuffer");
        return error.NapiError;
    }

    // Copy Zig data into the ArrayBuffer
    if (data) |dest| {
        const dest_slice: [*]u8 = @ptrCast(dest);
        @memcpy(dest_slice[0..len], ptr[0..len]);
    }

    // Create a Uint8Array view over the ArrayBuffer
    var uint8array: c.napi_value = undefined;
    if (c.napi_create_typedarray(env, c.napi_uint8_array, len, arraybuffer, 0, &uint8array) != c.napi_ok) {
        throw(env, "Failed to create Uint8Array");
        return error.NapiError;
    }

    return uint8array;
}

/// Create an empty JS object {}
pub fn createObject(env: c.napi_env) !c.napi_value {
    var result: c.napi_value = undefined;
    if (c.napi_create_object(env, &result) != c.napi_ok) {
        throw(env, "Failed to create object");
        return error.NapiError;
    }
    return result;
}

/// Extract a UTF-8 string from a napi_value
/// Caller owns and must free
pub fn getStringOwned(allocator: std.mem.Allocator, env: c.napi_env, value: c.napi_value) ![:0]const u8 {
    // Get string length (excluding null terminator)
    var len: usize = 0;
    if (c.napi_get_value_string_utf8(env, value, null, 0, &len) != c.napi_ok) {
        throw(env, "Failed to get string length");
        return error.NapiError;
    }

    // Allocate len+1 for the null terminator
    const buf = allocator.alloc(u8, len + 1) catch {
        throw(env, "Failed to allocate string buffer");
        return error.NapiError;
    };
    errdefer allocator.free(buf);

    var actual_len: usize = 0;
    if (c.napi_get_value_string_utf8(env, value, buf.ptr, len + 1, &actual_len) != c.napi_ok) {
        throw(env, "Failed to get string");
        return error.NapiError;
    }
    buf[len] = 0;

    return buf[0..len :0];
}

/// Set a named property on a JS object: obj[name] = value
pub fn setProperty(env: c.napi_env, obj: c.napi_value, comptime name: [:0]const u8, value: c.napi_value) !void {
    if (c.napi_set_named_property(env, obj, name, value) != c.napi_ok) {
        throw(env, "Failed to set " ++ name);
        return error.NapiError;
    }
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


/// Get up to arg_count arguments from the callback info
pub fn getArgs(env: c.napi_env, info: c.napi_callback_info, comptime arg_count: usize) ![arg_count]c.napi_value {
    var argc: usize = arg_count;
    var argv: [arg_count]c.napi_value = undefined;
    if (c.napi_get_cb_info(env, info, &argc, &argv, null, null) != c.napi_ok) {
        throw(env, "Failed to get callback info");
        return error.NapiError;
    }
    return argv;
}

/// Extract a *T from a napi_value external
pub fn getSelf(comptime T: type, env: c.napi_env, value: c.napi_value) !*T {
    var data: ?*anyopaque = null;
    if (c.napi_get_value_external(env, value, &data) != c.napi_ok) {
        throw(env, "Argument must be " ++ @typeName(T));
        return error.NapiError;
    }
    if (data) |ptr| {
        return @ptrCast(@alignCast(ptr));
    }
    throw(env, "Null " ++ @typeName(T) ++ " pointer");
    return error.NapiError;
}

/// Generates create/wrap/unwrap/finalize helpers for exposing a Zig type as an N-API external.
/// All JS-facing values are plain c.napi_value — type discipline lives on the TS side via External<T>.
pub fn ZigExternal(comptime T: type) type {
    return struct {
        /// N-API callback: creates a new T instance and wraps it as an external.
        /// Use this in lib.zig to declare the constructor function.
        pub fn create(env: c.napi_env, _: c.napi_callback_info) callconv(.c) c.napi_value {
            const self = T.init(global_allocator) catch {
                throw(env, "Failed to initialize " ++ @typeName(T));
                return null;
            };
            return wrap(env, self) catch {
                self.deinit(global_allocator);
                return null;
            };
        }

        /// Called automatically when the external gets GC'ed.
        fn finalize(_: c.napi_env, data: ?*anyopaque, _: ?*anyopaque) callconv(.c) void {
            if (data) |ptr| {
                var self: *T = @ptrCast(@alignCast(ptr));
                self.deinit(global_allocator);
            }
        }

        /// Wrap an existing Zig pointer as an N-API external.
        /// Registers finalize as a destructor for when the GC collects the external.
        pub fn wrap(env: c.napi_env, ptr: *T) !c.napi_value {
            var result: c.napi_value = undefined;
            if (c.napi_create_external(env, ptr, finalize, null, &result) != c.napi_ok) {
                throw(env, "Failed to create external " ++ @typeName(T));
                return error.NapiError;
            }
            return result;
        }

        /// Extract the first argument as an external and unwrap it to *T
        pub fn unwrap(env: c.napi_env, info: c.napi_callback_info) !*T {
            const args = getArgs(env, info, 1) catch return error.NapiError;
            return getSelf(T, env, args[0]);
        }
    };
}
