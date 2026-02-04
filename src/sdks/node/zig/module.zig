const napi = @import("napi.zig");
const Sandbox = @import("Sandbox.zig").Sandbox;

export fn napi_register_module_v1(env: napi.c.napi_env, exports: napi.c.napi_value) napi.c.napi_value {
    const funcs = .{
        .{ "createSandbox", napi.External(Sandbox).create },
        .{ "sandboxIncrement", Sandbox.increment },
        .{ "sandboxGetValue", Sandbox.getValue },
    };
    inline for (funcs) |f| {
        napi.registerFunction(env, exports, f[0], f[1]) catch return null;
    }
    return exports;
}
