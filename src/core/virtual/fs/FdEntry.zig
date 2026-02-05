const File = @import("File.zig");

/// FdEntry represents an entry in the file descriptor table.
/// Multiple FdEntry-s can point to the same File (for dup semantics).
/// The cloexec flag is per-fd, not per-file.
pub const FdEntry = struct {
    file: *File,
    cloexec: bool = false,

    /// Create a new entry with default flags
    pub fn init(file: *File) FdEntry {
        return .{ .file = file, .cloexec = false };
    }

    /// Create a new entry with specified cloexec flag
    pub fn initWithFlags(file: *File, cloexec: bool) FdEntry {
        return .{ .file = file, .cloexec = cloexec };
    }
};
