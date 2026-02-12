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
const LogBuffer = @import("LogBuffer.zig");
const Allocator = std.mem.Allocator;

const Self = @This();

allocator: Allocator,
io: Io,
init_guest_tid: linux.pid_t,
notify_fd: linux.fd_t,
start_time: Io.Timestamp,
logger: Logger,

// All Thread-s starting from the initial guest Thread are assigned a virtual TID and tracked via guest_threads
// Each Thread tracks its own virtual namespaces and file descriptors
guest_threads: Threads,

// Mutex protecting the entirety of Supervisor's internal state, (Procs/Proc/Namespace/FdTable)
// Io.Mutex yields instead of blocking OS threads, compatible with Io async workers.
mutex: Io.Mutex = .init,

// Overlay root for sandbox filesystem isolation (COW + private /tmp)
overlay: OverlayRoot,

// Log buffers for stdout/stderr
// Owned by the runCmd invocation in SDK
stdout: *LogBuffer,
stderr: *LogBuffer,

pub fn init(allocator: Allocator, io: Io, uid: [16]u8, notify_fd: linux.fd_t, init_guest_tid: linux.pid_t, stdout: *LogBuffer, stderr: *LogBuffer) !Self {
    const logger = Logger.init(.supervisor);
    var guest_threads = Threads.init(allocator);
    errdefer guest_threads.deinit();
    _ = try guest_threads.handleInitialThread(init_guest_tid);

    var overlay = try OverlayRoot.init(io, uid);
    errdefer overlay.deinit();

    return .{
        .allocator = allocator,
        .io = io,
        .stdout = stdout,
        .stderr = stderr,
        .init_guest_tid = init_guest_tid,
        .notify_fd = notify_fd,
        .start_time = try Io.Clock.awake.now(io),
        .logger = logger,
        .guest_threads = guest_threads,
        .overlay = overlay,
    };
}

pub fn deinit(self: *Self) void {
    if (self.notify_fd >= 0) {
        posix.close(self.notify_fd);
    }
    self.guest_threads.deinit();
    self.overlay.deinit();
    // LogBuffers are owned by caller, not freed here
}

/// Single reader loop with async dispatch for parallel syscall handling.
/// Only one thread calls recv (avoiding a kernel bug where multiple workers
/// competing for the recv ioctl can block forever when the seccomp filter dies).
/// Each notification is dispatched to the Io thread pool for concurrent handling.
pub fn run(self: *Self) !void {
    const max_inflight = 8;
    const HandlerReturn = @typeInfo(@TypeOf(Self.handleNotif)).@"fn".return_type.?;
    var futures: [max_inflight]Io.Future(HandlerReturn) = undefined;
    var count: usize = 0;

    while (true) {
        const notif = try self.recv() orelse break;

        if (count >= max_inflight) {
            try futures[0].await(self.io);
            for (0..count - 1) |i| futures[i] = futures[i + 1];
            count -= 1;
        }

        futures[count] = self.io.async(Self.handleNotif, .{ self, notif });
        count += 1;
    }

    for (futures[0..count]) |*f| {
        try f.await(self.io);
    }
}

fn handleNotif(self: *Self, notif: linux.SECCOMP.notif) !void {
    const resp = syscalls.handle(notif, self);
    try self.send(resp);
}

fn recv(self: Self) !?linux.SECCOMP.notif {
    // Poll the notify_fd before the recv ioctl. On some kernels, the recv
    // ioctl's internal wait_event_interruptible condition doesn't check the
    // seccomp filter's dead flag, causing workers to block forever after the
    // guest exits. poll() correctly reports POLLHUP on all kernels when the
    // filter dies.
    var pfds = [1]linux.pollfd{.{
        .fd = self.notify_fd,
        .events = linux.POLL.IN,
        .revents = 0,
    }};
    _ = try posix.poll(&pfds, -1);

    if (pfds[0].revents & linux.POLL.IN == 0) {
        self.logger.log("Guest exited (POLLHUP), stopping notification handler", .{});
        return null;
    }

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
