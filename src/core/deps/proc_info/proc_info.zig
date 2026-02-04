const builtin = @import("builtin");

const impl = if (builtin.is_test)
    @import("impl/testing.zig")
else
    @import("impl/linux.zig");

// TODO: tidy this up, and add implementations to testing.zig
pub const detectCloneFlags = impl.detectCloneFlags;
pub const readNsTids = impl.readNsTids;
// pub const readNsIds = impl.readNsIds;
pub const getStatus = impl.getStatus;
pub const listTids = impl.listTids;
// pub const listTgids = impl.listTgids; // TODO: decide: used?

pub const testing = if (builtin.is_test) impl else struct {};
