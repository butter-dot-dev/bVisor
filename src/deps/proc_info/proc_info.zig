const builtin = @import("builtin");

const impl = if (builtin.is_test)
    @import("impl/testing.zig")
else
    @import("impl/linux.zig");

const Proc = @import("../../virtual/proc/Proc.zig");
pub const SupervisorPID = Proc.SupervisorPID;
pub const GuestPID = Proc.GuestPID;
pub const CloneFlags = @import("../../virtual/proc/Procs.zig").CloneFlags;

pub const detectCloneFlags = impl.detectCloneFlags;
pub const readNsPids = impl.readNsPids;
pub const getStatus = impl.getStatus;
pub const listPids = impl.listPids;

pub const testing = if (builtin.is_test) impl else struct {};
