const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("types.zig");
const FD = types.FD;
const MemoryBridge = types.MemoryBridge;
const Result = types.Result;
const Logger = types.Logger;

pub fn handle_notifications(notify_fd: FD, mem_bridge: MemoryBridge) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Starting notification handler on fd {d}", .{notify_fd});

    // Allocate zeroed structures
    var req: linux.SECCOMP.notif = std.mem.zeroes(linux.SECCOMP.notif);
    var resp: linux.SECCOMP.notif_resp = std.mem.zeroes(linux.SECCOMP.notif_resp);

    while (true) : ({
        // On continue, re-zero buffers
        req = std.mem.zeroes(linux.SECCOMP.notif);
        resp = std.mem.zeroes(linux.SECCOMP.notif_resp);
    }) {
        // Receive notification
        const recv_result = linux.ioctl(notify_fd, linux.SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&req));
        switch (Result(usize).from(recv_result)) {
            .Ok => {},
            .Error => |err| switch (err) {
                .NOENT => {
                    // Thrown when child exits
                    logger.log("Child exited, stopping notification handler", .{});
                    break;
                },
                else => |_| return posix.unexpectedErrno(err),
            },
        }

        const sys_call = try SysCall.parse(mem_bridge, req);
        switch (sys_call) {
            .passthrough => |sys_code| {
                logger.log("Syscall: passthrough: {s}", .{@tagName(sys_code)});
            },
            .clock_nanosleep => |inner| {
                logger.log("Syscall: clock_nanosleep", .{});
                logger.log("Original seconds: {d}.{d}", .{ inner.request.sec, inner.request.nsec });

                // experiment: fuck around with sleep by overwriting requested duration in child
                const total_nanos = inner.request.sec * 1_000_000_000 + inner.request.nsec;
                const new_total_nanos = @divFloor(total_nanos, 5);
                var new_req = inner.request;
                new_req.nsec = @mod(new_total_nanos, 1_000_000_000);
                new_req.sec = @divFloor(new_total_nanos, 1_000_000_000);
                logger.log("New seconds: {d}.{d}", .{ new_req.sec, new_req.nsec });
                try mem_bridge.write(linux.timespec, new_req, req.data.arg2);
            },
        }

        // Allow the syscall to proceed (passthrough mode)
        resp.id = req.id;
        resp.@"error" = 0;
        resp.val = 0;
        resp.flags = linux.SECCOMP.USER_NOTIF_FLAG_CONTINUE;

        _ = try Result(usize).from(
            linux.ioctl(notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&resp)),
        ).unwrap();
    }
}

const SysCall = union(enum) {
    // Unsupported syscalls passthrough
    passthrough: linux.SYS,

    // Supported:
    clock_nanosleep: struct {
        clock_id: linux.clockid_t,
        flags: u64,
        request: linux.timespec,
        remain: linux.timespec,
    },

    const Self = @This();

    fn parse(mem_bridge: MemoryBridge, req: linux.SECCOMP.notif) !Self {
        const sys_code: linux.SYS = @enumFromInt(req.data.nr);
        switch (sys_code) {
            else => {
                return Self{ .passthrough = sys_code };
            },
            .clock_nanosleep => {
                return Self{
                    .clock_nanosleep = .{
                        .clock_id = @enumFromInt(req.data.arg0),
                        .flags = req.data.arg1,
                        .request = try mem_bridge.read(linux.timespec, req.data.arg2),
                        .remain = try mem_bridge.read(linux.timespec, req.data.arg3),
                    },
                };
            },
        }
    }
};
