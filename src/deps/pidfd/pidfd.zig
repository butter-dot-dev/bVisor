const builtin = @import("builtin");
const impl = if (builtin.is_test)
    @import("impl/testing.zig")
else
    @import("impl/linux.zig");

pub const lookup_child_fd = impl.lookup_child_fd;
pub const lookup_child_fd_with_retry = impl.lookup_child_fd_with_retry;
