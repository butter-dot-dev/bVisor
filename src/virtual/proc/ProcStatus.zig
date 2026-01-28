const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Proc = @import("Proc.zig");
const GuestPID = Proc.GuestPID;
const SupervisorPID = Proc.SupervisorPID;

const Self = @This();

pub const MAX_NS_DEPTH = 128;

/// A ProcStatus is generated when reading from /proc/[pid]/status
pub const ProcStatus = struct {
    pid: SupervisorPID,
    ppid: SupervisorPID,
    nspids_buf: [MAX_NS_DEPTH]GuestPID = undefined,
    nspids_len: usize = 0,

    pub fn nspids(self: *const ProcStatus) []const GuestPID {
        return self.nspids_buf[0..self.nspids_len];
    }

    // pub fn init(pid: SupervisorPID, ppid: SupervisorPID) Self {
    //     return .{
    //         .pid = pid,
    //         .ppid = ppid,
    //         .nspids = nspids,
    //     };
    // }
};
