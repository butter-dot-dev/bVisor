const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../../../types.zig");
const LinuxResult = types.LinuxResult;
const FD = types.FD;

/// Read an object of type T from child_addr in child's address space
/// This creates a copy in the local process
/// Remember any nested pointers returned are still in child's address space
pub inline fn read(T: type, child_pid: linux.pid_t, child_addr: u64) !T {
    const child_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrFromInt(child_addr),
        .len = @sizeOf(T),
    }};
    var local_T: T = undefined;
    const local_iovec: [1]posix.iovec = .{.{
        .base = @ptrCast(&local_T),
        .len = @sizeOf(T),
    }};

    _ = try LinuxResult(usize).from(
        linux.process_vm_readv(
            child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
    return local_T;
}

/// Read bytes from child's address space into a local buffer
pub inline fn readSlice(dest: []u8, child_pid: linux.pid_t, child_addr: u64) !void {
    const child_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrFromInt(child_addr),
        .len = dest.len,
    }};

    const local_iovec: [1]posix.iovec = .{.{
        .base = dest.ptr,
        .len = dest.len,
    }};

    _ = try LinuxResult(usize).from(
        linux.process_vm_readv(
            child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
}

/// Write an object of type T into child's address space at child_addr
/// Misuse could seriously corrupt child process
pub inline fn write(T: type, child_pid: linux.pid_t, val: T, child_addr: u64) !void {
    const local_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrCast(&val),
        .len = @sizeOf(T),
    }};

    const child_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrFromInt(child_addr),
        .len = @sizeOf(T),
    }};

    _ = try LinuxResult(usize).from(
        linux.process_vm_writev(
            child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
}

/// Write bytes from local buffer into child's address space
pub inline fn writeSlice(src: []const u8, child_pid: linux.pid_t, child_addr: u64) !void {
    const local_iovec: [1]posix.iovec_const = .{.{
        .base = src.ptr,
        .len = src.len,
    }};

    const child_iovec: [1]posix.iovec_const = .{.{
        .base = @ptrFromInt(child_addr),
        .len = src.len,
    }};

    _ = try LinuxResult(usize).from(
        linux.process_vm_writev(
            child_pid,
            &local_iovec,
            &child_iovec,
            0,
        ),
    ).unwrap();
}
