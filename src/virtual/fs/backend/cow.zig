const std = @import("std");
const posix = std.posix;
const OverlayRoot = @import("../../OverlayRoot.zig");

pub const Cow = union(enum) {
    passthrough: posix.fd_t,
    writecopy: posix.fd_t,

    pub fn open(overlay: *OverlayRoot, path: []const u8, flags: posix.O, mode: posix.mode_t) !Cow {
        _ = path;
        _ = flags;
        _ = mode;
        _ = overlay;
        //todo: if wants_write or overlay.cowExists(path) -> writecopy, else passthrough
        return error.NotImplemented;
    }

    pub fn read(self: *Cow, buf: []u8) !usize {
        _ = self;
        _ = buf;
        //todo: posix.read on either variant's fd
        return error.NotImplemented;
    }

    pub fn write(self: *Cow, data: []const u8) !usize {
        _ = self;
        _ = data;
        //todo: passthrough -> error.ReadOnlyFileSystem, writecopy -> posix.write
        return error.NotImplemented;
    }

    pub fn close(self: *Cow) void {
        _ = self;
        //todo: posix.close on fd
    }
};

// ============================================================================
// Tests - to implement
// ============================================================================

const testing = std.testing;
const builtin = @import("builtin");

test "open file for read (passthrough mode) succeeds" {}

test "read from passthrough returns host file content" {}

test "write to passthrough returns ReadOnlyFileSystem" {}

test "open file for write triggers copy to overlay" {}

test "write to writecopy succeeds" {}

test "close cow file, reopen in read mode reads from cow overlay" {}
