const builtin = @import("builtin");

// Use different implementations of MemoryBridge based on if running tests
// This allows tests to run on Mac.
pub const MemoryBridge = if (builtin.is_test)
    @import("memory_bridge/TestingMemoryBridge.zig")
else
    @import("memory_bridge/ProcessMemoryBridge.zig");
