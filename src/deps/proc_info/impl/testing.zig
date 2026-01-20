const std = @import("std");
const Allocator = std.mem.Allocator;

pub const KernelPID = @import("../../../virtual/proc/Proc.zig").KernelPID;
pub const CloneFlags = @import("../../../virtual/proc/Procs.zig").CloneFlags;

/// Mock parent PID map: child_pid -> parent_pid
pub var mock_ppid_map: std.AutoHashMapUnmanaged(KernelPID, KernelPID) = .empty;

/// Mock clone flags map: child_pid -> CloneFlags
pub var mock_clone_flags: std.AutoHashMapUnmanaged(KernelPID, CloneFlags) = .empty;

/// Read parent PID from mock map
pub fn readPpid(pid: KernelPID) !KernelPID {
    return mock_ppid_map.get(pid) orelse error.ProcNotInKernel;
}

/// Return mock clone flags for a child
pub fn detectCloneFlags(parent_pid: KernelPID, child_pid: KernelPID) CloneFlags {
    _ = parent_pid;
    return mock_clone_flags.get(child_pid) orelse CloneFlags{};
}

/// Reset mock state - call in test cleanup
pub fn reset(allocator: Allocator) void {
    mock_ppid_map.deinit(allocator);
    mock_clone_flags.deinit(allocator);
    mock_ppid_map = .empty;
    mock_clone_flags = .empty;
}

/// Setup a parent relationship in the mock
pub fn setupParent(allocator: Allocator, child: KernelPID, parent: KernelPID) !void {
    try mock_ppid_map.put(allocator, child, parent);
}

/// Setup clone flags for a child in the mock
pub fn setupCloneFlags(allocator: Allocator, child: KernelPID, flags: CloneFlags) !void {
    try mock_clone_flags.put(allocator, child, flags);
}
