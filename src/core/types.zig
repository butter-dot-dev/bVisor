const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

pub fn LinuxResult(comptime T: type) type {
    return union(enum) {
        Ok: T,
        Error: linux.E,

        const Self = @This();

        pub fn from(result: usize) Self {
            const err = linux.errno(result);
            if (err != .SUCCESS) {
                return Self{ .Error = err };
            }
            // Type-specific success value handling
            const ok_value: T = switch (@typeInfo(T)) {
                .bool => true,
                .void => {},
                else => @intCast(result),
            };
            return Self{ .Ok = ok_value };
        }

        /// Returns inner value, or throws a general error
        /// If specific error types are needed, prefer to switch on Result then switch on Error branch
        pub fn unwrap(self: Self) !T {
            return switch (self) {
                .Ok => |value| value,
                .Error => error.SyscallFailed,
            };
        }
    };
}

pub const Logger = struct {
    pub const Name = enum {
        prefork,
        guest,
        supervisor,
    };

    name: Name,

    pub fn init(name: Name) @This() {
        return .{ .name = name };
    }

    pub fn log(self: @This(), comptime format: []const u8, args: anytype) void {
        if (builtin.is_test) return;

        var buf: [1024]u8 = undefined;
        const fmtlog = std.fmt.bufPrint(&buf, format, args) catch unreachable;
        const color = switch (self.name) {
            .prefork => "\x1b[96m",
            .guest => "\x1b[92m",
            .supervisor => "\x1b[95m",
        };
        const padding: []const u8 = switch (self.name) {
            .prefork => "      ",
            .guest => "        ",
            .supervisor => "   ",
        };

        std.debug.print("{s}[{s}]{s}{s}\x1b[0m\n", .{ color, @tagName(self.name), padding, fmtlog });
    }
};

/// Convert linux.O flags to posix.O flags at the syscall boundary
pub fn linuxToPosixFlags(linux_flags: linux.O) posix.O {
    var flags: posix.O = .{};

    flags.ACCMODE = switch (linux_flags.ACCMODE) {
        .RDONLY => .RDONLY,
        .WRONLY => .WRONLY,
        .RDWR => .RDWR,
    };

    if (linux_flags.CREAT) flags.CREAT = true;
    if (linux_flags.EXCL) flags.EXCL = true;
    if (linux_flags.TRUNC) flags.TRUNC = true;
    if (linux_flags.APPEND) flags.APPEND = true;
    if (linux_flags.NONBLOCK) flags.NONBLOCK = true;
    if (linux_flags.CLOEXEC) flags.CLOEXEC = true;
    if (linux_flags.DIRECTORY) flags.DIRECTORY = true;

    return flags;
}

/// Linux kernel's `struct stat`, selected by target architecture at comptime.
///
/// This is the ABI struct written by the
///     fstat(2), stat(2), lstat(2), and newfstatat(2)
/// syscalls.
///
/// NOT the same as `linux.Statx` (256 bytes, used by the statx(2) syscall).
pub const Stat = switch (builtin.cpu.arch) {
    .aarch64 => AArch64Stat,
    .x86_64 => X86_64Stat,
    else => @compileError("Stat layout not defined for " ++ @tagName(builtin.cpu.arch)),
};

/// aarch64 layout from `asm-generic/stat.h` — 128 bytes
/// Reference: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/asm-generic/stat.h
const AArch64Stat = extern struct {
    st_dev: u64, // Device
    st_ino: u64, // File serial number
    st_mode: u32, // File mode
    st_nlink: u32, // Link count
    st_uid: u32, // Use ID of the file's owner
    st_gid: u32, // Group ID of the file's group
    st_rdev: u64, // Device number, if device
    __pad1: u64,
    st_size: i64, // Size of file, in bytes
    st_blksize: i32, // Optimal block size for I/O
    __pad2: i32,
    st_blocks: i64, // Number 512-byte blocks allocated
    st_atime: i64, // Time of last access
    st_atime_nsec: u64,
    st_mtime: i64, // Time of last modification
    st_mtime_nsec: u64,
    st_ctime: i64, // Time of last status change
    st_ctime_nsec: u64,
    __unused4: u32,
    __unused5: u32,

    comptime {
        std.debug.assert(@sizeOf(AArch64Stat) == 128);
    }
};

/// x86_64 layout from `arch/x86/include/uapi/asm/stat.h` — 144 bytes
/// Reference: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/uapi/asm/stat.h
const X86_64Stat = extern struct {
    st_dev: u64, // Device
    st_ino: u64, // File serial number
    st_nlink: u64, // Link count (u64, not u32)
    st_mode: u32, // File mode
    st_uid: u32, // User ID of the file's owner
    st_gid: u32, // Group ID of the file's group
    __pad0: u32,
    st_rdev: u64, // Device number, if device
    st_size: i64, // Size of file, in bytes
    st_blksize: i64, // Optimal block size for I/O (i64, not i32)
    st_blocks: i64, // Number 512-byte blocks allocated
    st_atime: u64, // Time of last access
    st_atime_nsec: u64,
    st_mtime: u64, // Time of last modification
    st_mtime_nsec: u64,
    st_ctime: u64, // Time of last status change
    st_ctime_nsec: u64,
    __unused: [3]i64,

    comptime {
        std.debug.assert(@sizeOf(X86_64Stat) == 144);
    }
};
