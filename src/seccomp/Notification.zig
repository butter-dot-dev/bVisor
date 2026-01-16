const std = @import("std");
const linux = std.os.linux;
const types = @import("../types.zig");
const Logger = types.Logger;
const Syscall = @import("../virtual/syscall/syscall.zig").Syscall;
const Supervisor = @import("../Supervisor.zig");

/// Notification is a wrapper around linux.SECCOMP.notif
const Self = @This();

id: u64,
backend: union(enum) {
    kernel: void, // The native kernel will handle the syscall
    virtual: Syscall,
},

/// Parse a linux.SECCOMP.notif into a Notification
pub fn from_notif(notif: linux.SECCOMP.notif) !Self {
    const supported = try Syscall.parse(notif);

    if (supported) |syscall| {
        return .{
            .id = notif.id,
            .backend = .{
                .virtual = syscall,
            },
        };
    }

    // Else not supported, passthrough
    return .{
        .id = notif.id,
        .backend = .{ .kernel = {} },
    };
}

/// Invoke the handler, or perform passthrough
pub fn handle(self: Self, supervisor: *Supervisor) !Response {
    switch (self.backend) {
        .kernel => {
            return Response.use_kernel(self.id);
        },
        .virtual => |syscall| {
            const syscall_res = try syscall.handle(supervisor);
            return Response.virtual_res(self.id, syscall_res);
        },
    }
}

/// Wrapper around linux.SECCOMP.notif_resp
pub const Response = struct {
    id: u64,
    backend: union(enum) {
        kernel: void,
        virtual: Syscall.Result,
    },

    pub fn use_kernel(id: u64) @This() {
        return .{
            .id = id,
            .backend = .{ .kernel = {} },
        };
    }

    pub fn virtual_res(id: u64, result: Syscall.Result) @This() {
        return .{
            .id = id,
            .backend = .{ .virtual = result },
        };
    }

    pub fn to_notif_resp(self: @This()) linux.SECCOMP.notif_resp {
        return switch (self.backend) {
            .kernel => .{
                .id = self.id,
                .flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE,
                .val = 0,
                .@"error" = 0,
            },
            .virtual => |syscall_res| switch (syscall_res) {
                .use_kernel => .{
                    .id = self.id,
                    .flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE,
                    .val = 0,
                    .@"error" = 0,
                },
                .reply => |reply| .{
                    .id = self.id,
                    .flags = 0,
                    .val = reply.val,
                    .@"error" = reply.errno,
                },
            },
        };
    }
};
