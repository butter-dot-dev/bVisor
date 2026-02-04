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

pub fn ZigExternal(comptime T: type) type {
    return struct {
        pub fn ZigPtr(comptime InnerT: type) type {
            // InnerT is phantom, just to add apparent typing
            // To match the TS-side type for this same construct
            _ = InnerT;
            return *c.struct_napi_value__;
        }

        /// N-API callback: creates a new T instance an
        /// Use this in lib.zig to declare the constructor function
        pub fn create(env: c.napi_env, _: c.napi_callback_info) callconv(.c) ?ZigPtr(T) {
            const self = T.init(allocator) catch {
                throw(env, "Failed to initialize " ++ @typeName(T));
                return null;
            };
            return wrap(env, self) catch {
                self.deinit(allocator);
                return null;
            };
        }

        /// Called automatically when wrapped value gets GC'ed
        fn finalize(_: c.napi_env, data: ?*anyopaque, _: ?*anyopaque) callconv(.c) void {
            if (data) |ptr| {
                var self: *T = @ptrCast(@alignCast(ptr));
                self.deinit(allocator);
            }
        }

        /// Wrap an existing Zig pointer as an N-API external value.
        /// This registers finalize as a callback when the GC runs on the external.
        pub fn wrap(env: c.napi_env, ptr: *T) !ZigPtr(T) {
            var result: ?ZigPtr(T) = undefined;
            if (c.napi_create_external(env, ptr, finalize, null, &result) != c.napi_ok) {
                throw(env, "Failed to create external " ++ @typeName(T));
                return error.NapiError;
            }
            if (result == null) return error.NapiError;
            return result.?;
        }

        pub fn unwrap(env: c.napi_env, info: c.napi_callback_info) !*T {
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
            const external_ptr: ?ZigPtr(T) = argv[0]; // First arg is the external pointer

            // Unwrap external pointer into underlying data
            if (c.napi_get_value_external(env, external_ptr, &data) != c.napi_ok) {
                throw(env, "Argument must be " ++ @typeName(T));
                return error.NapiError;
            }

            // Cast data to the expected zig type
            if (data) |ptr| {
                const self: *T = @ptrCast(@alignCast(ptr));
                return self;
            }
            throw(env, "Null " ++ @typeName(T) ++ " pointer");
            return error.NapiError;
        }
    };
}
