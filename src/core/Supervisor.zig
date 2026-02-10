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
start_time: i64,
logger: Logger,

// All Thread-s starting from the initial guest Thread are assigned a virtual TID and tracked via guest_threads
// Each Thread tracks its own virtual namespaces and file descriptors
guest_threads: Threads,

// Mutex protecting the entirety of Supervisor's internal state, (Procs/Proc/Namespace/FdTable)
// Io.Mutex yields instead of blocking OS threads, compatible with Io async workers.
mutex: Io.Mutex = .init,

// Overlay root for sandbox filesystem isolation (COW + private /tmp)
overlay: OverlayRoot,

// Log buffer for stdout/stderr
log_buffer: LogBuffer,

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
        .log_buffer = .init(allocator),
        .init_guest_tid = init_guest_tid,
        .notify_fd = notify_fd,
        .start_time = std.time.timestamp(),
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
    self.log_buffer.flushAll(self.io);
    if (self.notify_fd >= 0) {
        posix.close(self.notify_fd);
    }
    self.guest_threads.deinit();
    self.overlay.deinit();
    self.log_buffer.deinit();
}

pub fn run(self: *Self) !void {
    const max_workers = 8;
    const num_workers = @min(std.Thread.getCpuCount() catch 1, max_workers);

    // To build an array of futures, must get the exact type of the worker function's return value
    const WorkerReturn = @typeInfo(@TypeOf(Self.worker)).@"fn".return_type.?;
    const WorkerFuture = Io.Future(WorkerReturn);
    var futures: [max_workers]WorkerFuture = undefined;

    // Spawn workers
    for (0..num_workers) |i| {
        futures[i] = self.io.async(Self.worker, .{ self, i });
    }

    // Cancel workers on exit
    defer for (futures[0..num_workers]) |*f| {
        _ = f.cancel(self.io) catch {};
    };

    // Wait for any worker to exit
    for (futures[0..num_workers]) |*f| {
        try f.await(self.io);
    }
}

/// Main notification loop. Reads syscall notifications from the kernel and responds
/// Multiple workers may run at a single time
fn worker(self: *Self, worker_id: usize) !void {
    self.logger.log("Worker {d} starting", .{worker_id});
    while (true) {
        // Receive syscall notification from kernel
        const notif = try self.recv() orelse return;
        self.logger.log("Worker {d} received syscall notification", .{worker_id});
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
