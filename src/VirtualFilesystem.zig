const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");
const types = @import("types.zig");
const FD = types.FD;

const Self = @This();

const O_ACCMODE: u32 = 0o3;
const O_RDONLY: u32 = 0o0;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;

/// Where a FD's operations are handled. Kernel FDs upgrade to virtual on write (COW).
pub const FDBackend = union(enum) {
    kernel: []const u8, // path, for COW
    virtual: VirtualFile.Handle,
};

allocator: std.mem.Allocator,
virtual_files: std.StringHashMap(*VirtualFile), // persists after close
open_fds: std.AutoHashMap(FD, FDBackend),
next_fd: FD = 3, // 0,1,2 are stdio

pub fn init(allocator: std.mem.Allocator) Self {
    return .{
        .allocator = allocator,
        .virtual_files = std.StringHashMap(*VirtualFile).init(allocator),
        .open_fds = std.AutoHashMap(FD, FDBackend).init(allocator),
    };
}

pub fn deinit(self: *Self) void {
    // Free allocated paths tracked in open_fds
    var fd_it = self.open_fds.iterator();
    while (fd_it.next()) |entry| {
        switch (entry.value_ptr.*) {
            .virtual => {},
            .kernel => |path| self.allocator.free(path),
        }
    }
    self.open_fds.deinit();

    // Free allocated virtual files
    var file_it = self.virtual_files.iterator();
    while (file_it.next()) |entry| {
        entry.value_ptr.*.data.deinit(self.allocator);
        self.allocator.destroy(entry.value_ptr.*);
        self.allocator.free(entry.key_ptr.*);
    }
    self.virtual_files.deinit();

    // Debug: dump VFS contents (skip in tests)
    if (!builtin.is_test and self.virtual_files.count() > 0) {
        std.debug.print("\n\x1b[93m=== Virtual Filesystem Contents ===\x1b[0m\n", .{});
        var debug_it = self.virtual_files.iterator();
        while (debug_it.next()) |entry| {
            const path = entry.key_ptr.*;
            const file = entry.value_ptr.*;
            std.debug.print("\x1b[96m{s}\x1b[0m ({d} bytes, mode=0o{o}):\n", .{
                path,
                file.data.items.len,
                file.mode,
            });
            if (file.data.items.len > 0) {
                std.debug.print("{s}\n", .{file.data.items});
            }
        }
        std.debug.print("\x1b[93m===================================\x1b[0m\n\n", .{});
    }
}

/// Open or create a file. Pass content for COW from host.
pub fn open(self: *Self, path: []const u8, flags: u32, mode: u32, content: ?[]const u8) !FD {
    const access_mode = flags & O_ACCMODE;
    var file: *VirtualFile = undefined;
    if (self.virtual_files.get(path)) |existing| {
        file = existing;
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
        if ((flags & O_TRUNC) != 0 and (access_mode == O_WRONLY or access_mode == O_RDWR)) {
            file.data.clearRetainingCapacity();
        }
    } else {
        if ((flags & O_CREAT) == 0 and content == null) return error.FileNotFound;

        const new_file = try self.allocator.create(VirtualFile);
        new_file.* = .{ .mode = mode & 0o777 };
        if (content) |c| try new_file.data.appendSlice(self.allocator, c);
        const owned_path = try self.allocator.dupe(u8, path);
        try self.virtual_files.put(owned_path, new_file);
        file = new_file;
    }

    const fd = self.next_fd;
    self.next_fd += 1;
    try self.open_fds.put(fd, .{ .virtual = .{ .file = file, .offset = 0, .flags = flags } });
    return fd;
}

pub fn write(self: *Self, fd: FD, data: []const u8) !usize {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;
    const handle = switch (entry.*) {
        .virtual => |*h| h,
        .kernel => return error.KernelFD,
    };
    const access_mode = handle.flags & O_ACCMODE;
    if (access_mode != O_WRONLY and access_mode != O_RDWR) {
        return error.NotOpenForWriting;
    }
    try handle.file.data.appendSlice(self.allocator, data);
    handle.offset += data.len;
    return data.len;
}

pub fn read(self: *Self, fd: FD, buf: []u8) !usize {
    const entry = self.open_fds.getPtr(fd) orelse return error.BadFD;
    const handle = switch (entry.*) {
        .virtual => |*h| h,
        .kernel => return error.KernelFD,
    };
    const access_mode = handle.flags & O_ACCMODE;
    if (access_mode != O_RDONLY and access_mode != O_RDWR) {
        return error.NotOpenForReading;
    }

    const file_data = handle.file.data.items;
    const remaining = file_data.len - @min(handle.offset, file_data.len);
    const to_read = @min(buf.len, remaining);

    if (to_read > 0) {
        @memcpy(buf[0..to_read], file_data[handle.offset..][0..to_read]);
        handle.offset += to_read;
    }
    return to_read;
}

/// Close FD but keep file data.
pub fn close(self: *Self, fd: FD) void {
    if (self.open_fds.fetchRemove(fd)) |entry| {
        switch (entry.value) {
            .virtual => {},
            .kernel => |path| self.allocator.free(path),
        }
    }
}

pub fn getFDBackend(self: *Self, fd: FD) ?FDBackend {
    return self.open_fds.get(fd);
}

/// Track a passthrough FD for later COW.
pub fn registerKernelFD(self: *Self, fd: FD, path: []const u8) !void {
    const owned_path = try self.allocator.dupe(u8, path);
    try self.open_fds.put(fd, .{ .kernel = owned_path });
}

/// Upgrade kernel FD to virtual by copying content to VFS.
pub fn copyOnWrite(self: *Self, fd: FD, path: []const u8, content: []const u8, mode: u32) !void {
    var file: *VirtualFile = undefined;
    if (self.virtual_files.get(path)) |existing| {
        file = existing;
        file.data.clearRetainingCapacity();
        try file.data.appendSlice(self.allocator, content);
    } else {
        const new_file = try self.allocator.create(VirtualFile);
        new_file.* = .{ .mode = mode & 0o777 };
        try new_file.data.appendSlice(self.allocator, content);
        const owned_path = try self.allocator.dupe(u8, path);
        try self.virtual_files.put(owned_path, new_file);
        file = new_file;
    }

    if (self.open_fds.fetchRemove(fd)) |entry| {
        switch (entry.value) {
            .kernel => |old_path| self.allocator.free(old_path),
            .virtual => {}, // embedded, nothing to free
        }
    }
    try self.open_fds.put(fd, .{ .virtual = .{ .file = file, .offset = 0, .flags = O_RDWR } });
}

pub fn virtualPathExists(self: *Self, path: []const u8) bool {
    return self.virtual_files.contains(path);
}

/// A virtual file containing its data in memory
pub const VirtualFile = struct {
    data: std.ArrayListUnmanaged(u8) = .{},
    mode: u32,

    pub const Handle = struct {
        file: *VirtualFile,
        offset: usize,
        flags: u32,
    };
};

// ============================================================================
// Tests
// ============================================================================

test "open and write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    const written = try vfs.write(fd, "hello");
    try std.testing.expectEqual(5, written);
}

test "persitence: open, write, close, reopen, read" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Write and close
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "persistent data");
    vfs.close(fd1);

    // Reopen and read
    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0o644, null);
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd2, &buf);
    try std.testing.expectEqualStrings("persistent data", buf[0..n]);
}

test "file not found without O_CREAT" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const result = vfs.open("/nonexistent.txt", O_RDONLY, 0o644, null);
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

test "getFDBackend" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // stdin/stdout/stderr are not tracked
    try std.testing.expect(vfs.getFDBackend(0) == null);
    try std.testing.expect(vfs.getFDBackend(1) == null);
    try std.testing.expect(vfs.getFDBackend(2) == null);

    // Open a file, check it's virtual
    const fd = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    try std.testing.expect(vfs.getFDBackend(fd).? == .virtual);

    // Close it, no longer tracked
    vfs.close(fd);
    try std.testing.expect(vfs.getFDBackend(fd) == null);
}

test "permission denied - read-only file, open for write" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create read-only file
    const fd1 = try vfs.open("/readonly.txt", O_WRONLY | O_CREAT, 0o400, null);
    vfs.close(fd1);

    // Try to open for writing
    const result = vfs.open("/readonly.txt", O_WRONLY, 0o400, null);
    try std.testing.expectError(error.PermissionDenied, result);
}

test "permission denied - write-only file, open for read" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create write-only file
    const fd1 = try vfs.open("/writeonly.txt", O_WRONLY | O_CREAT, 0o200, null);
    vfs.close(fd1);

    // Try to open for reading
    const result = vfs.open("/writeonly.txt", O_RDONLY, 0o200, null);
    try std.testing.expectError(error.PermissionDenied, result);
}

test "permission denied - no permissions" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with no permissions
    const fd1 = try vfs.open("/noperm.txt", O_WRONLY | O_CREAT, 0o000, null);
    vfs.close(fd1);

    // Can't read
    try std.testing.expectError(error.PermissionDenied, vfs.open("/noperm.txt", O_RDONLY, 0, null));
    // Can't write
    try std.testing.expectError(error.PermissionDenied, vfs.open("/noperm.txt", O_WRONLY, 0, null));
    // Can't read-write
    try std.testing.expectError(error.PermissionDenied, vfs.open("/noperm.txt", O_RDWR, 0, null));
}

test "permission denied - O_RDWR needs both bits" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create read-only file
    const fd1 = try vfs.open("/ro.txt", O_WRONLY | O_CREAT, 0o400, null);
    vfs.close(fd1);

    // O_RDWR should fail (missing write permission)
    try std.testing.expectError(error.PermissionDenied, vfs.open("/ro.txt", O_RDWR, 0, null));

    // Create write-only file
    const fd2 = try vfs.open("/wo.txt", O_WRONLY | O_CREAT, 0o200, null);
    vfs.close(fd2);

    // O_RDWR should fail (missing read permission)
    try std.testing.expectError(error.PermissionDenied, vfs.open("/wo.txt", O_RDWR, 0, null));
}

test "write to read-only FD" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with rw permissions
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "data");
    vfs.close(fd1);

    // Open read-only
    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0, null);
    const result = vfs.write(fd2, "more");
    try std.testing.expectError(error.NotOpenForWriting, result);
}

test "read from write-only FD" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    const fd = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    var buf: [32]u8 = undefined;
    const result = vfs.read(fd, &buf);
    try std.testing.expectError(error.NotOpenForReading, result);
}

test "O_TRUNC truncates existing file" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create and write
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "original content");
    vfs.close(fd1);

    // Reopen with O_TRUNC
    const fd2 = try vfs.open("/test.txt", O_RDWR | O_TRUNC, 0, null);
    _ = try vfs.write(fd2, "new");
    vfs.close(fd2);

    // Read back
    const fd3 = try vfs.open("/test.txt", O_RDONLY, 0, null);
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd3, &buf);
    try std.testing.expectEqualStrings("new", buf[0..n]);
}

test "multiple FDs same file have independent offsets" {
    var vfs = Self.init(std.testing.allocator);
    defer vfs.deinit();

    // Create file with content
    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "abcdefghij");
    vfs.close(fd1);

    // Open twice for reading
    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0, null);
    const fd3 = try vfs.open("/test.txt", O_RDONLY, 0, null);

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

    const fd1 = try vfs.open("/test.txt", O_WRONLY | O_CREAT, 0o644, null);
    _ = try vfs.write(fd1, "short");
    vfs.close(fd1);

    const fd2 = try vfs.open("/test.txt", O_RDONLY, 0, null);
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

    const fd = try vfs.open("/test.txt", O_RDWR | O_CREAT, 0o644, null);

    // Write should work
    const written = try vfs.write(fd, "hello");
    try std.testing.expectEqual(5, written);

    // Read should work (but returns 0 since offset is at end)
    var buf: [32]u8 = undefined;
    const n = try vfs.read(fd, &buf);
    try std.testing.expectEqual(0, n);
}
