const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Proc = @import("../../virtual/proc/Proc.zig");
const Procs = @import("../../virtual/proc/Procs.zig");
const types = @import("../../types.zig");
const Supervisor = @import("../../Supervisor.zig");
const FD = types.FD;
const Result = @import("../syscall.zig").Syscall.Result;
const testing = std.testing;
const makeNotif = @import("../../seccomp/notif.zig").makeNotif;

// comptime dependency injection
const deps = @import("../../deps/deps.zig");
const memory_bridge = deps.memory_bridge;

const Self = @This();

dirfd: FD,
path_len: usize,
path_buf: [256]u8, // fixed stack buffer, limits size of string read
flags: linux.O,

pub fn path(self: *const Self) []const u8 {
    return self.path_buf[0..self.path_len];
}

/// Normalize a path, resolving . and .. components.
/// Returns the normalized path in the provided buffer, or error if buffer too small.
pub fn normalizePath(path_str: []const u8, buf: []u8) ![]const u8 {
    var fba = std.heap.FixedBufferAllocator.init(buf);
    return std.fs.path.resolvePosix(fba.allocator(), &.{path_str}) catch |err| switch (err) {
        error.OutOfMemory => return error.PathTooLong,
    };
}

pub fn parse(notif: linux.SECCOMP.notif) !Self {
    const path_ptr: u64 = notif.data.arg1;
    var path_buf: [256]u8 = undefined;
    const path_slice = try memory_bridge.readString(
        &path_buf,
        @intCast(notif.pid),
        path_ptr,
    );

    const dirfd: FD = @truncate(@as(i64, @bitCast(notif.data.arg0)));
    const flags: linux.O = @bitCast(@as(u32, @truncate(notif.data.arg2)));

    return .{
        .dirfd = dirfd,
        .path_len = path_slice.len,
        .path_buf = path_buf,
        .flags = flags,
    };
}

// Path resolution rules

pub const Action = enum {
    block,
    allow,
    // Special handlers
    virtualize_proc,
};

pub const Rule = union(enum) {
    /// Terminal - this prefix resolves to an action
    terminal: Action,
    /// Branch - check children, with a default if none match
    branch: struct {
        children: []const PathRule,
        default: Action,
    },
};

pub const PathRule = struct {
    prefix: []const u8,
    rule: Rule,
};

/// The root filesystem rules
pub const default_action: Action = .block;
pub const fs_rules: []const PathRule = &.{
    // Hard blocks
    .{ .prefix = "/sys/", .rule = .{ .terminal = .block } },
    .{ .prefix = "/run/", .rule = .{ .terminal = .block } },

    // Virtualized
    .{ .prefix = "/proc/", .rule = .{ .terminal = .virtualize_proc } },
};

/// Resolve a path to an action, normalizing it first to handle .. components.
pub fn resolve(path_str: []const u8) !Action {
    var buf: [512]u8 = undefined;
    const normalized = try normalizePath(path_str, &buf);
    return resolveWithRules(normalized, fs_rules, default_action);
}

fn resolveWithRules(path_str: []const u8, rules: []const PathRule, default: Action) Action {
    for (rules) |rule| {
        if (std.mem.startsWith(u8, path_str, rule.prefix)) {
            const remainder = path_str[rule.prefix.len..];
            switch (rule.rule) {
                .terminal => |action| return action,
                .branch => |branch| {
                    return resolveWithRules(remainder, branch.children, branch.default);
                },
            }
        }
    }
    return default;
}

/// Returns true if the path is absolute (starts with '/')
pub fn isAbsolutePath(path_str: []const u8) bool {
    return path_str.len > 0 and path_str[0] == '/';
}

/// Returns true if the flags indicate a write operation requiring VFS redirect
pub fn useVFS(flags: linux.O) bool {
    return flags.ACCMODE == .WRONLY or flags.ACCMODE == .RDWR or flags.CREAT;
}

pub fn handle(self: Self, supervisor: *Supervisor) !Result {
    const logger = supervisor.logger;

    logger.log("Emulating openat: dirfd={d} path={s} flags={any}", .{
        self.dirfd,
        self.path(),
        self.flags,
    });

    const action = try resolve(self.path());
    logger.log("Action: {s}", .{@tagName(action)});
    switch (action) {
        .block => {
            logger.log("openat: blocked path: {s}", .{self.path()});
            return .{ .handled = Result.Handled.err(linux.E.PERM) };
        },
        .allow => {
            logger.log("openat: allowed path: {s}", .{self.path()});
            return .{ .passthrough = {} };
        },
        .virtualize_proc => {
            logger.log("openat: virtualizing proc path: {s}", .{self.path()});
            return error.NotImplemented;
        },
    }
}

test "openat blocks private paths" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();
    _ = io;

    const child_pid: Proc.KernelPID = 345; // some arbitrary kernel PID
    const notify_fd: FD = -1; // makes deinit ignore closing the fd

    var supervisor = try Supervisor.init(allocator, notify_fd, child_pid);
    defer supervisor.deinit();

    const flags = linux.O{
        .ACCMODE = .RDONLY,
        .CREAT = true,
    };

    const notif = makeNotif(.openat, .{
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/sys/private.txt"),
        .arg2 = @intCast(@as(u32, @bitCast(flags))),
        .arg3 = 0,
    });

    const parsed = try Self.parse(notif);
    std.debug.print("path: {s}\n", .{parsed.path()});
    try testing.expectEqualStrings("/sys/private.txt", parsed.path());
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(res.handled.is_error());
}

test "openat blocks /sys/class/net" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/sys/class/net"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(res.handled.is_error());
}

test "openat blocks /sys/kernel/security" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/sys/kernel/security/lsm"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(res.handled.is_error());
}

test "openat blocks /run/docker.sock" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/run/docker.sock"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(res.handled.is_error());
}

test "openat blocks /run/user paths" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/run/user/1000/bus"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(res.handled.is_error());
}

test "isAbsolutePath detects absolute paths" {
    try testing.expect(isAbsolutePath("/foo"));
    try testing.expect(isAbsolutePath("/"));
    try testing.expect(isAbsolutePath("/proc/self"));
}

test "isAbsolutePath detects relative paths" {
    try testing.expect(!isAbsolutePath("foo"));
    try testing.expect(!isAbsolutePath("./foo"));
    try testing.expect(!isAbsolutePath("../foo"));
    try testing.expect(!isAbsolutePath(""));
}

test "useVFS detects write modes" {
    try testing.expect(!useVFS(linux.O{ .ACCMODE = .RDONLY }));
    try testing.expect(useVFS(linux.O{ .ACCMODE = .WRONLY }));
    try testing.expect(useVFS(linux.O{ .ACCMODE = .RDWR }));
    try testing.expect(useVFS(linux.O{ .ACCMODE = .RDONLY, .CREAT = true }));
}

test "openat virtualizes /proc/self/status" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/proc/self/status"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(!res.handled.is_error());
}

test "openat virtualizes /proc/1/status" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/proc/1/status"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(!res.handled.is_error());
}

test "openat virtualizes /proc/meminfo" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 12345;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/proc/meminfo"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(!res.handled.is_error());
}

test "openat /proc/self resolves to vpid 2 for child process" {
    const allocator = std.testing.allocator;
    const init_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, init_pid);
    defer supervisor.deinit();

    // Add a child process - should get vpid 2
    const child_pid: Proc.KernelPID = 200;
    const child_vpid = try supervisor.virtual_procs.handle_clone(init_pid, child_pid, Procs.CloneFlags.from(0));
    try testing.expectEqual(2, child_vpid);

    // Child opens /proc/self/status - should resolve to vpid 2
    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/proc/self/status"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(!res.handled.is_error());
}

test "openat passthrough for read-only on /tmp" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/tmp/test.txt"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .RDONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .passthrough);
}

test "openat redirects to VFS for O_WRONLY on /tmp" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/tmp/test.txt"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .WRONLY }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(!res.handled.is_error());
}

test "openat redirects to VFS for O_CREAT on /tmp" {
    const allocator = std.testing.allocator;
    const child_pid: Proc.KernelPID = 100;
    var supervisor = try Supervisor.init(allocator, -1, child_pid);
    defer supervisor.deinit();

    const notif = makeNotif(.openat, .{
        .pid = child_pid,
        .arg0 = @bitCast(@as(i64, linux.AT.FDCWD)),
        .arg1 = @intFromPtr("/tmp/newfile.txt"),
        .arg2 = @intCast(@as(u32, @bitCast(linux.O{ .ACCMODE = .WRONLY, .CREAT = true }))),
    });

    const parsed = try Self.parse(notif);
    const res = try parsed.handle(&supervisor);
    try testing.expect(res == .handled);
    try testing.expect(!res.handled.is_error());
}

test "resolve /proc/self triggers virtualize" {
    try testing.expect(try resolve("/proc/self") == .virtualize_proc);
}

test "path traversal /proc/../etc/passwd does not virtualize" {
    try testing.expect(try resolve("/proc/../etc/passwd") == .block);
}
