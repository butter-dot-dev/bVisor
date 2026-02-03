const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;
const types = @import("types.zig");
const syscalls = @import("virtual/syscall/syscalls.zig");
const Result = types.LinuxResult;
const Logger = types.Logger;
const Threads = @import("virtual/proc/Threads.zig");
const OverlayRoot = @import("virtual/OverlayRoot.zig");
const Allocator = std.mem.Allocator;

const Self = @This();

allocator: Allocator,
io: Io,
init_guest_tid: linux.pid_t,
notify_fd: linux.fd_t,
logger: Logger,

// All Thread-s starting from the initial guest Thread are assigned a virtual TID and tracked via guest_threads
// Each Thread tracks its own virtual namespaces and file descriptors
// TODO: decide whether this should be a pointer?
guest_threads: Threads,

// Overlay root for sandbox filesystem isolation (COW + private /tmp)
overlay: OverlayRoot,

pub fn init(allocator: Allocator, io: Io, notify_fd: linux.fd_t, init_guest_tid: linux.pid_t) !Self {
    const logger = Logger.init(.supervisor);
    var guest_threads = Threads.init(allocator);
    errdefer guest_threads.deinit();
    _ = try guest_threads.handleInitialThread(init_guest_tid);

    const uid = generateUid();
    var overlay = try OverlayRoot.init(io, uid);
    errdefer overlay.deinit();

    return .{
        .allocator = allocator,
        .io = io,
        .init_guest_tid = init_guest_tid,
        .notify_fd = notify_fd,
        .logger = logger,
        .guest_threads = guest_threads,
        .overlay = overlay,
    };
}

fn generateUid() [16]u8 {
    var uid_bytes: [8]u8 = undefined;
    if (builtin.is_test) {
        @memcpy(&uid_bytes, "testtest");
    } else {
        std.crypto.random.bytes(&uid_bytes);
    }
    return std.fmt.bytesToHex(uid_bytes, .lower);
}

pub fn deinit(self: *Self) void {
    if (self.notify_fd >= 0) {
        posix.close(self.notify_fd);
    }
    self.guest_threads.deinit();
    self.overlay.deinit();
}

/// Main notification loop. Reads syscall notifications from the kernel,
pub fn run(self: *Self) !void {
    // Supervisor handles syscalls in a single blocking thread.
    // 80/20 solution for now, will rethink once we benchmark
    while (true) {
        // Receive syscall notification from kernel
        const notif = try self.recv() orelse return;
        const resp = syscalls.handle(notif, self);
        try self.send(resp);
    }
}

fn recv(self: Self) !?linux.SECCOMP.notif {
    var notif: linux.SECCOMP.notif = std.mem.zeroes(linux.SECCOMP.notif);
    const recv_result = linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.RECV, @intFromPtr(&notif));
    switch (Result(usize).from(recv_result)) {
        .Ok => return notif,
        .Error => |err| switch (err) {
            .NOENT => {
                self.logger.log("Guest exited, stopping notification handler", .{});
                return null;
            },
            else => |_| return posix.unexpectedErrno(err),
        },
    }
}

fn send(self: Self, resp: linux.SECCOMP.notif_resp) !void {
    const send_result = linux.ioctl(self.notify_fd, linux.SECCOMP.IOCTL_NOTIF.SEND, @intFromPtr(&resp));
    switch (Result(usize).from(send_result)) {
        .Ok => {},
        .Error => |err| switch (err) {
            .NOENT => {
                // Task exited before we could respond - this is fine
                self.logger.log("Task exited before response could be sent", .{});
            },
            else => return posix.unexpectedErrno(err),
        },
    }
}
