const std = @import("std");
const linux = std.os.linux;
const types = @import("./types.zig");
const MemoryBridge = @import("memory_bridge.zig").MemoryBridge;
const Logger = types.Logger;
const Supervisor = @import("Supervisor.zig");

// All supported syscalls
const ClockNanosleep = @import("./syscalls/ClockNanosleep.zig");
const Openat = @import("./syscalls/Openat.zig");
const Read = @import("./syscalls/Read.zig");
const Readv = @import("./syscalls/Readv.zig");
const Write = @import("./syscalls/Write.zig");
const Writev = @import("./syscalls/Writev.zig");
const Close = @import("./syscalls/Close.zig");

/// Union of all emulated syscalls.
pub const Syscall = union(enum) {
    clock_nanosleep: ClockNanosleep,
    openat: Openat,
    read: Read,
    readv: Readv,
    write: Write,
    writev: Writev,
    close: Close,

    const Self = @This();

    /// Parse seccomp notif into Syscall
    /// Null return means the syscall is not supported and should passthrough
    pub fn parse(mem_bridge: MemoryBridge, notif: linux.SECCOMP.notif) !?Self {
        const sys_code: linux.SYS = @enumFromInt(notif.data.nr);
        switch (sys_code) {
            .clock_nanosleep => return .{ .clock_nanosleep = try ClockNanosleep.parse(mem_bridge, notif) },
            .openat => return .{ .openat = try Openat.parse(mem_bridge, notif) },
            .read => return .{ .read = try Read.parse(mem_bridge, notif) },
            .readv => return .{ .readv = try Readv.parse(mem_bridge, notif) },
            .write => return .{ .write = try Write.parse(mem_bridge, notif) },
            .writev => return .{ .writev = try Writev.parse(mem_bridge, notif) },
            .close => return .{ .close = try Close.parse(mem_bridge, notif) },
            else => return null,
        }
    }

    /// Handle the syscall, passing supervisor for access to mem_bridge, logger, filesystem
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
