const napi = @import("napi.zig");
const c = napi.c;
const std = @import("std");
const core = @import("core");
const LogBuffer = core.LogBuffer;
const Stream = @import("Stream.zig");

const Self = @This();

uid: [16]u8,

// Lifecycle helpers expect init/deinit
pub fn init(allocator: std.mem.Allocator) !*Self {
    const self = try allocator.create(Self);
    self.* = .{
        .uid = core.generateUid(napi.io),
    };
    return self;
}

pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    allocator.destroy(self);
}

// Public API must follow napi interface
// Returns JS type (RunCmdResult)
pub fn runCmd(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
    const allocator = napi.global_allocator;
    const io = napi.io;

    // Copy args into native zig types
    const args = napi.getArgs(env, info, 2) catch return null;
    const self = napi.getSelf(Self, env, args[0]) catch return null;
    const cmd = napi.getStringOwned(allocator, env, args[1]) catch return null;
    defer allocator.free(cmd);

    // Allocate stdout and stderr buffers for this run, owned by node
    var stdout_stream: ?*Stream = Stream.init(allocator, io) catch return null;
    errdefer if (stdout_stream) |s| s.deinit(allocator);
    var stderr_stream: ?*Stream = Stream.init(allocator, io) catch return null;
    errdefer if (stderr_stream) |s| s.deinit(allocator);

    // Run in seccomp — fills the LogBuffers inside stdout/stderr Streams
    core.execute(
        allocator,
        io,
        self.uid,
        cmd,
        &stdout_stream.?.buffer,
        &stderr_stream.?.buffer,
    ) catch |err| {
        std.log.err("execute failed: {s}", .{@errorName(err)});
        return null;
    };

    // Wrap into externals - after wrap(), JS owns the memory via GC finalizer
    const stdoutExternal = napi.ZigExternal(Stream).wrap(env, stdout_stream.?) catch return null;
    stdout_stream = null;
    const stderrExternal = napi.ZigExternal(Stream).wrap(env, stderr_stream.?) catch return null;
    stderr_stream = null;

    // Create object to return
    const result = napi.createObject(env) catch return null;
    if (result == null) return null;

    // Register externals as properties on object
    napi.setProperty(env, result, "stdout", stdoutExternal) catch return null;
    napi.setProperty(env, result, "stderr", stderrExternal) catch return null;

    return result;
}
