const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const Thread = @import("Thread.zig");
// Thread IDs
pub const AbsTid = Thread.AbsTid;
pub const NsTid = Thread.NsTid;
// ThreadGroup IDs
pub const AbsTgid = Thread.AbsTgid;
pub const NsTgid = Thread.NsTgid;

const Self = @This();

pub const MAX_NS_DEPTH = 128;

tid: AbsTid, // Thread's TID
tgid: AbsTgid, // Thread's group ID
ptid: AbsTid, // Parent Thread's TID
nstgids_buf: [MAX_NS_DEPTH]NsTgid = undefined,
nstgids_len: usize = 0,
nstids_buf: [MAX_NS_DEPTH]NsTid = undefined,
nstids_len: usize = 0,

pub fn nstgids(self: *const Self) []const NsTgid {
    return self.nstgids_buf[0..self.nstgids_len];
}

pub fn nstids(self: *const Self) []const NsTid {
    return self.nstids_buf[0..self.nstids_len];
}
