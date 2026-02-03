const Thread = @import("Thread.zig");

// Thread IDs
pub const AbsTid = Thread.AbsTid;
pub const NsTid = Thread.NsTid;
// ThreadGroup IDs
pub const AbsTgid = Thread.AbsTgid;
pub const NsTgid = Thread.NsTgid;

nstgids: []NsTgid,
nstids: []NsTid,
