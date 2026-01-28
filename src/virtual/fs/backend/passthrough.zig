const std = @import("std");
const posix = std.posix;
const OverlayRoot = @import("../../OverlayRoot.zig");

/// Passthrough backend - directly wraps a kernel file descriptor.
/// Used for safe device files like /dev/null, /dev/zero, /dev/urandom.
pub const Passthrough = struct {
    fd: posix.fd_t,

    pub fn open(overlay: *OverlayRoot, path: []const u8, flags: posix.O, mode: posix.mode_t) !Passthrough {
        _ = overlay;
        _ = path;
        _ = flags;
        _ = mode;
        //todo: posix.open(path, flags, mode)
        return error.NotImplemented;
    }

    pub fn read(self: *Passthrough, buf: []u8) !usize {
        _ = self;
        _ = buf;
        //todo: posix.read(self.fd, buf)
        return error.NotImplemented;
    }

    pub fn write(self: *Passthrough, data: []const u8) !usize {
        _ = self;
        _ = data;
        //todo: posix.write(self.fd, data)
        return error.NotImplemented;
    }

    pub fn close(self: *Passthrough) void {
        _ = self;
        //todo: posix.close(self.fd)
    }
};

// ============================================================================
// Tests - these WILL FAIL until implementation is complete
// ============================================================================

const testing = std.testing;
const builtin = @import("builtin");

test "open /dev/null succeeds" {}

test "write to /dev/null succeeds" {}

test "read from /dev/null returns 0 (EOF)" {}

test "read from /dev/zero returns zeros" {}

test "open nonexistent file returns FileNotFound" {}
