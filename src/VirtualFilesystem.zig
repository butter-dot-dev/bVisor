const std = @import("std");
const linux = std.os.linux;
const types = @import("types.zig");
const FD = types.FD;

const Self = @This();

// Use managed ArrayList that stores allocator internally
const ManagedArrayList = std.array_list.AlignedManaged(u8, null);

// Access mode is in the bottom 2 bits of flags
const O_ACCMODE: u32 = 0o3;
const O_RDONLY: u32 = 0o0;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;

allocator: std.mem.Allocator,
files: std.StringHashMap(*File), // path → File (owns data, persists after close)
open_fds: std.AutoHashMap(FD, OpenFile), // FD → open file state
next_fd: FD = 3, // Start at 3 since 0,1,2 are stdin/stdout/stderr

pub fn init(allocator: std.mem.Allocator) Self {
    return .{
        .allocator = allocator,
        .files = std.StringHashMap(*File).init(allocator),
        .open_fds = std.AutoHashMap(FD, OpenFile).init(allocator),
    };
}

pub fn deinit(self: *Self) void {
    // Free all open file entries
    self.open_fds.deinit();

    // Free all file data and paths
    var it = self.files.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.*.data.deinit();
        self.allocator.destroy(entry.value_ptr.*);
        self.allocator.free(entry.key_ptr.*);
    }
    self.files.deinit();
}

/// Open a file, creating it if it doesn't exist (based on flags)
pub fn open(self: *Self, path: []const u8, flags: u32, mode: u32) !FD {
    const access_mode = flags & O_ACCMODE;

    // Check if file exists
    var file: *File = undefined;
    if (self.files.get(path)) |existing| {
        file = existing;

        // Check permissions against requested access (owner bits)
        const owner_read = (file.mode & 0o400) != 0;
        const owner_write = (file.mode & 0o200) != 0;

        if (access_mode == O_RDONLY and !owner_read) {
            return error.PermissionDenied;
        }
        if (access_mode == O_WRONLY and !owner_write) {
            return error.PermissionDenied;
        }
        if (access_mode == O_RDWR and (!owner_read or !owner_write)) {
            return error.PermissionDenied;
        }

        // Handle O_TRUNC - truncate file if opened for writing
        if ((flags & O_TRUNC) != 0 and (access_mode == O_WRONLY or access_mode == O_RDWR)) {
            file.data.clearRetainingCapacity();
        }
    } else {
        // File doesn't exist - need O_CREAT to create
        if ((flags & O_CREAT) == 0) {
            return error.FileNotFound;
        }

        // Create new file with specified mode
        const new_file = try self.allocator.create(File);
        new_file.* = .{
            .data = ManagedArrayList.init(self.allocator),
            .mode = mode & 0o777, // Mask to permission bits only
        };
        // Dupe the path for storage
        const owned_path = try self.allocator.dupe(u8, path);
        try self.files.put(owned_path, new_file);
        file = new_file;
    }

    // Allocate FD and create open file entry
    const fd = self.next_fd;
    self.next_fd += 1;

    try self.open_fds.put(fd, .{
        .file = file,
        .offset = 0,
        .flags = flags,
    });

    return fd;
}

/// Write data to an open file descriptor
pub fn write(self: *Self, fd: FD, data: []const u8) !usize {
    const open_file = self.open_fds.getPtr(fd) orelse return error.BadFD;

    // Check if opened for writing
    const access_mode = open_file.flags & O_ACCMODE;
    if (access_mode != O_WRONLY and access_mode != O_RDWR) {
        return error.NotOpenForWriting;
    }

    // Append data to file
    try open_file.file.data.appendSlice(data);
    open_file.offset += data.len;

    return data.len;
}

/// Read data from an open file descriptor
pub fn read(self: *Self, fd: FD, buf: []u8) !usize {
    const open_file = self.open_fds.getPtr(fd) orelse return error.BadFD;

    // Check if opened for reading
    const access_mode = open_file.flags & O_ACCMODE;
    if (access_mode != O_RDONLY and access_mode != O_RDWR) {
        return error.NotOpenForReading;
    }

    const file_data = open_file.file.data.items;
    const remaining = file_data.len - @min(open_file.offset, file_data.len);
    const to_read = @min(buf.len, remaining);

    if (to_read > 0) {
        @memcpy(buf[0..to_read], file_data[open_file.offset..][0..to_read]);
        open_file.offset += to_read;
    }

    return to_read;
}

/// Close a file descriptor (keeps file data for persistence)
pub fn close(self: *Self, fd: FD) void {
    _ = self.open_fds.remove(fd);
}

/// Check if an FD is a virtual file descriptor
pub fn isVirtualFD(self: *Self, fd: FD) bool {
    return self.open_fds.contains(fd);
}

pub const File = struct {
    data: ManagedArrayList,
    mode: u32, // Unix permissions (e.g., 0o644)
};

pub const OpenFile = struct {
    file: *File, // Points to File in files map
    offset: usize, // Per-FD read/write offset
    flags: u32, // Open flags (read/write mode)
};

// ============================================================================
// Tests
// ============================================================================

test "open and write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644);
    const written = try vfs.write(fd, "hello");
    try std.testing.expectEqual(5, written);
}

test "persitence: open, write, close, reopen, read" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Write and close
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644);
    _ = try vfs.write(fd1, "persistent data");
    vfs.close(fd1);

    // Reopen and read
    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0o644);
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd2, &buf);
    try std.testing.expectEqualStrings("persistent data", buf[0..n]);
}

test "file not found without O_CREAT" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const result = vfs.open("/nonexistent.txt", O_RDONLY, 0o644);
    try std.testing.expectError(error.FileNotFound, result);
}

test "bad FD on write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const result = vfs.write(999, "data");
    try std.testing.expectError(error.BadFD, result);
}

test "bad FD on read" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    var buf: [32]u8 = undefined;
    const result = vfs.read(999, &buf);
    try std.testing.expectError(error.BadFD, result);
}

test "isVirtualFD" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // stdin/stdout/stderr are not virtual
    try std.testing.expect(!vfs.isVirtualFD(0));
    try std.testing.expect(!vfs.isVirtualFD(1));
    try std.testing.expect(!vfs.isVirtualFD(2));

    // Open a file, check it's virtual
    const fd = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644);
    try std.testing.expect(vfs.isVirtualFD(fd));

    // Close it, no longer virtual
    vfs.close(fd);
    try std.testing.expect(!vfs.isVirtualFD(fd));
}

test "permission denied - read-only file, open for write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create read-only file
    const fd1 = try vfs.open("/readonly.txt", O_WRONLY | O_CREAT, 0o400);
    vfs.close(fd1);

    // Try to open for writing
    const result = vfs.open("/readonly.txt", O_WRONLY, 0o400);
    try std.testing.expectError(error.PermissionDenied, result);
}

test "permission denied - write-only file, open for read" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create write-only file
    const fd1 = try vfs.open("/writeonly.txt", O_WRONLY | O_CREAT, 0o200);
    vfs.close(fd1);

    // Try to open for reading
    const result = vfs.open("/writeonly.txt", O_RDONLY, 0o200);
    try std.testing.expectError(error.PermissionDenied, result);
}

test "permission denied - no permissions" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with no permissions
    const fd1 = try vfs.open("/noperm.txt", O_WRONLY | O_CREAT, 0o000);
    vfs.close(fd1);

    // Can't read
    try std.testing.expectError(error.PermissionDenied, vfs.open("/noperm.txt", O_RDONLY, 0));
    // Can't write
    try std.testing.expectError(error.PermissionDenied, vfs.open("/noperm.txt", O_WRONLY, 0));
    // Can't read-write
    try std.testing.expectError(error.PermissionDenied, vfs.open("/noperm.txt", O_RDWR, 0));
}

test "permission denied - O_RDWR needs both bits" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create read-only file
    const fd1 = try vfs.open("/ro.txt", O_WRONLY | O_CREAT, 0o400);
    vfs.close(fd1);

    // O_RDWR should fail (missing write permission)
    try std.testing.expectError(error.PermissionDenied, vfs.open("/ro.txt", O_RDWR, 0));

    // Create write-only file
    const fd2 = try vfs.open("/wo.txt", O_WRONLY | O_CREAT, 0o200);
    vfs.close(fd2);

    // O_RDWR should fail (missing read permission)
    try std.testing.expectError(error.PermissionDenied, vfs.open("/wo.txt", O_RDWR, 0));
}

test "write to read-only FD" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with rw permissions
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644);
    _ = try vfs.write(fd1, "data");
    vfs.close(fd1);

    // Open read-only
    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0);
    const result = vfs.write(fd2, "more");
    try std.testing.expectError(error.NotOpenForWriting, result);
}

test "read from write-only FD" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644);
    var buf: [32]u8 = undefined;
    const result = vfs.read(fd, &buf);
    try std.testing.expectError(error.NotOpenForReading, result);
}

test "O_TRUNC truncates existing file" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create and write
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644);
    _ = try vfs.write(fd1, "original content");
    vfs.close(fd1);

    // Reopen with O_TRUNC
    const fd2 = try vfs.open("/test.txt", O_RDWR | O_TRUNC, 0);
    _ = try vfs.write(fd2, "new");
    vfs.close(fd2);

    // Read back
    const fd3 = try vfs.open("/test.txt", O_RDONLY, 0);
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd3, &buf);
    try std.testing.expectEqualStrings("new", buf[0..n]);
}

test "multiple FDs same file have independent offsets" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with content
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644);
    _ = try vfs.write(fd1, "abcdefghij");
    vfs.close(fd1);

    // Open twice for reading
    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0);
    const fd3 = try vfs.open("/test.txt", O_RDONLY, 0);

    var buf2: [3]u8 = undefined;
    var buf3: [5]u8 = undefined;

    // Read 3 from fd2
    _ = try vfs.read(fd2, &buf2);
    try std.testing.expectEqualStrings("abc", &buf2);

    // Read 5 from fd3 (should start at beginning)
    _ = try vfs.read(fd3, &buf3);
    try std.testing.expectEqualStrings("abcde", &buf3);

    // Read 3 more from fd2 (should continue from offset 3)
    _ = try vfs.read(fd2, &buf2);
    try std.testing.expectEqualStrings("def", &buf2);
}

test "read at EOF returns 0" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644);
    _ = try vfs.write(fd1, "short");
    vfs.close(fd1);

    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0);
    var buf: [32]u8 = undefined;

    // Read all
    const n1 = try vfs.read(fd2, &buf);
    try std.testing.expectEqual(5, n1);

    // Read again at EOF
    const n2 = try vfs.read(fd2, &buf);
    try std.testing.expectEqual(0, n2);
}

test "O_RDWR allows both read and write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644);

    // Write should work
    const written = try vfs.write(fd, "hello");
    try std.testing.expectEqual(5, written);

    // Read should work (but returns 0 since offset is at end)
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd, &buf);
    try std.testing.expectEqual(0, n);
}
