const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

// File Descriptor
pub const FD = i32;

pub fn Result(comptime T: type) type {
    return union(enum) {
        Ok: T,
        Error: linux.E,

        const Self = @This();

        pub fn from(result: usize) Self {
            return switch (linux.errno(result)) {
                .SUCCESS => Self{ .Ok = @intCast(result) },
                else => Self{ .Error = linux.errno(result) },
            };
        }

        /// Returns inner value, or throws a general error
        /// If specific error types are needed, prefer to switch on Result then switch on Error branch
        pub fn unwrap(self: Self) !T {
            return switch (self) {
                .Ok => |value| value,
                .Error => |_| error.SyscallFailed, // Some general error
            };
        }
    };
}

/// MemoryBridge allows cross-process reading and writing of arbitrary data from a child process
/// This is needed for cases where syscalls from a child contain pointers
/// pointing to its own process-local address space
pub const MemoryBridge = struct {
    child_pid: linux.pid_t,

    pub fn init(child_pid: linux.pid_t) @This() {
        return .{ .child_pid = child_pid };
    }

    /// Read an object of type T from child_addr in child's address space
    /// This creates a copy in the local process
    /// Remember any nested pointers returned are still in child's address space
    pub fn read(self: @This(), T: type, child_addr: u64) !T {
        const child_iovec: [1]posix.iovec_const = .{.{
            .base = @ptrFromInt(child_addr),
            .len = @sizeOf(T),
        }};

        var local_T: T = undefined;
        const local_iovec: [1]posix.iovec = .{.{
            .base = @ptrCast(&local_T),
            .len = @sizeOf(T),
        }};

        _ = try Result(usize).from(
            // https://man7.org/linux/man-pages/man2/process_vm_readv.2.html
            linux.process_vm_readv(
                self.child_pid,
                &local_iovec,
                &child_iovec,
                0,
            ),
        ).unwrap();
        return local_T;
    }

    /// Write an object of type T into child's address space at child_addr
    /// Misuse could seriously corrupt child process
    pub fn write(self: @This(), T: type, val: T, child_addr: u64) !void {
        const local_iovec: [1]posix.iovec_const = .{.{
            .base = @ptrCast(&val),
            .len = @sizeOf(T),
        }};

        const child_iovec: [1]posix.iovec_const = .{.{
            .base = @ptrFromInt(child_addr),
            .len = @sizeOf(T),
        }};

        _ = try Result(usize).from(
            // https://man7.org/linux/man-pages/man2/process_vm_writev.2.html
            linux.process_vm_writev(
                self.child_pid,
                &local_iovec,
                &child_iovec,
                0,
            ),
        ).unwrap();
    }
};

pub const Logger = struct {
    pub const Name = enum {
        prefork,
        child,
        supervisor,
    };

    name: Name,

    pub fn init(name: Name) @This() {
        return .{ .name = name };
    }

    pub fn log(self: @This(), comptime format: []const u8, args: anytype) void {
        var buf: [1024]u8 = undefined;
        const fmtlog = std.fmt.bufPrint(&buf, format, args) catch unreachable;
        const color = switch (self.name) {
            .prefork => "\x1b[96m",
            .child => "\x1b[92m",
            .supervisor => "\x1b[95m",
        };
        const padding: []const u8 = switch (self.name) {
            .prefork => "      ",
            .child => "        ",
            .supervisor => "   ",
        };

        std.debug.print("{s}[{s}]{s}{s}\x1b[0m\n", .{ color, @tagName(self.name), padding, fmtlog });
    }
};
