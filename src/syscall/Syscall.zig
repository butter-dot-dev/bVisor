const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const MemoryBridge = @import("../memory/ProcessMemoryBridge.zig");
const Logger = types.Logger;
const Supervisor = @import("../Supervisor.zig");

// All supported syscalls
const ClockNanosleep = @import("handlers/ClockNanosleep.zig");
const Writev = @import("handlers/Writev.zig");

/// Union of all emulated syscalls.
pub const Syscall = union(enum) {
    clock_nanosleep: ClockNanosleep,
    writev: Writev,

    const Self = @This();

    /// Parse seccomp notif into Syscall
    /// Null return means the syscall is not supported and should passthrough
    pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !?Self {
        const sys_code: linux.SYS = @enumFromInt(notif.data.nr);
        switch (sys_code) {
            .clock_nanosleep => return .{ .clock_nanosleep = try ClockNanosleep.parse(mem_bridge, notif) },
            .writev => return .{ .writev = try Writev.parse(mem_bridge, notif) },
            else => return null,
        }
    }

    pub fn handle(self: Self, supervisor: *Supervisor) !Self.Result {
        return switch (self) {
            inline else => |inner| inner.handle(supervisor),
        };
    }

    pub const Result = union(enum) {
        passthrough: void, // If the handler implementation decided to passthrough
        handled: Handled,

        pub const Handled = struct {
            val: i64,
            errno: i32,

            pub fn success(val: i64) @This() {
                return .{ .val = val, .errno = 0 };
            }

            pub fn err(errno: linux.E) @This() {
                return .{ .val = 0, .errno = @intFromEnum(errno) };
            }
        };
    };
};
