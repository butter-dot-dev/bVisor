const builtin = @import("builtin");
const impl = if (builtin.is_test)
    @import("impl/testing.zig")
else
    @import("impl/linux.zig");

pub const lookupChildFd = impl.lookupChildFd;
pub const lookupChildFdWithRetry = impl.lookupChildFdWithRetry;
