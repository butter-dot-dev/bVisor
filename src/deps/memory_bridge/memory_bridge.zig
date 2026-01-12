const builtin = @import("builtin");

const impl = if (builtin.is_test)
    @import("impl/testing.zig")
else
    @import("impl/linux.zig");

pub const read = impl.read;
pub const readSlice = impl.readSlice;
pub const write = impl.write;
pub const writeSlice = impl.writeSlice;
