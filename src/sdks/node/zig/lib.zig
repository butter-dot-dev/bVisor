const napi = @import("napi.zig");
const c = napi.c;
const Sandbox = @import("Sandbox.zig");

export fn napi_register_module_v1(env: napi.c.napi_env, exports: napi.c.napi_value) napi.c.napi_value {
    const funcs = .{
        .{ "createSandbox", napi.External(Sandbox).create },
        .{ "sandboxIncrement", Sandbox.increment },
        .{ "sandboxGetValue", Sandbox.getValue },
    };
    inline for (funcs) |f| {
        registerFunction(env, exports, f[0], f[1]) catch return null;
    }
    return exports;
}

pub fn registerFunction(
    env: c.napi_env,
    exports: c.napi_value,
    comptime name: [:0]const u8,
    func: *const fn (c.napi_env, c.napi_callback_info) callconv(.c) c.napi_value,
) !void {
    var napi_fn: c.napi_value = undefined;
    if (c.napi_create_function(env, null, 0, func, null, &napi_fn) != c.napi_ok) {
        napi.throw(env, "Failed to create " ++ name);
        return error.NapiError;
    }
    if (c.napi_set_named_property(env, exports, name, napi_fn) != c.napi_ok) {
        napi.throw(env, "Failed to export " ++ name);
        return error.NapiError;
    }
}
