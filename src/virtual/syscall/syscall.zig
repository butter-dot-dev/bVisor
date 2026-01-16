const std = @import("std");
const linux = std.os.linux;
const types = @import("../../types.zig");
const Logger = types.Logger;
const Supervisor = @import("../../Supervisor.zig");

// All supported syscalls
const Writev = @import("handlers/Writev.zig");
const OpenAt = @import("handlers/OpenAt.zig");

/// Union of all virtualized syscalls.
pub const Syscall = union(enum) {
    writev: Writev,
    openat: OpenAt,

    const Self = @This();

    /// Parse seccomp notif into Syscall
    /// Null return means the syscall is not supported and should passthrough
    pub fn parse(notif: linux.SECCOMP.notif) !?Self {
        const sys_code: linux.SYS = @enumFromInt(notif.data.nr);
        switch (sys_code) {
            .writev => return .{ .writev = try Writev.parse(notif) },
            .openat => return .{ .openat = try OpenAt.parse(notif) },
            else => return null,
        }
    }

    pub fn handle(self: Self, supervisor: *Supervisor) !Self.Result {
        return switch (self) {
            // Inline else forces all enum variants to have .handle(supervisor) signatures
            inline else => |inner| inner.handle(supervisor),
        };
    }

    pub const Result = union(enum) {
        use_kernel: void,
        reply: Reply,

        pub const Reply = struct {
            val: i64,
            errno: i32,
        };

        pub fn reply_success(val: i64) @This() {
            return .{ .reply = .{ .val = val, .errno = 0 } };
        }

        pub fn reply_err(errno: linux.E) @This() {
            return .{ .reply = .{ .val = 0, .errno = @intFromEnum(errno) } };
        }

        pub fn is_error(self: @This()) bool {
            return switch (self) {
                .use_kernel => false,
                .reply => |reply| reply.errno != 0,
            };
        }
    };
};
