const builtin = @import("builtin");

const impl = if (builtin.is_test)
    @import("impl/testing.zig")
else
    @import("impl/linux.zig");

pub const KernelPID = @import("../../virtual/proc/Proc.zig").KernelPID;
pub const CloneFlags = @import("../../virtual/proc/Procs.zig").CloneFlags;

pub const readPpid = impl.readPpid;
pub const detectCloneFlags = impl.detectCloneFlags;

pub const testing = if (builtin.is_test) impl else struct {};
