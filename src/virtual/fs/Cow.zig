const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const Io = std.Io;
const Dir = Io.Dir;
const types = @import("../../types.zig");
const KernelFD = types.KernelFD;

const Self = @This();

uid: [16]u8,
root_dir: Dir,
root_path: [64]u8,
root_path_len: usize,

pub fn generateUid() [16]u8 {
    var uid_bytes: [8]u8 = undefined;
    if (builtin.is_test) {
        @memcpy(&uid_bytes, "testtest");
    } else {
        std.crypto.random.bytes(&uid_bytes);
    }
    return std.fmt.bytesToHex(uid_bytes, .lower);
}

pub fn init(io: Io, uid: [16]u8) !Self {
    var root_path: [64]u8 = undefined;
    const root_slice = std.fmt.bufPrint(&root_path, "/tmp/.bvisor/sb/{s}/vfs/cow", .{uid}) catch unreachable;
    const root_dir = try Dir.cwd().createDirPathOpen(io, root_slice, .{});
    return .{
        .uid = uid,
        .root_dir = root_dir,
        .root_path = root_path,
        .root_path_len = root_slice.len,
    };
}

pub fn deinit(self: *Self, io: Io) void {
    self.root_dir.close(io);
}

fn relPath(path: []const u8) []const u8 {
    return if (path.len > 0 and path[0] == '/') path[1..] else path;
}

pub fn exists(self: *const Self, io: Io, virtual_path: []const u8) bool {
    const rel_path = relPath(virtual_path);
    self.root_dir.access(io, rel_path, .{}) catch return false;
    return true;
}

/// Opens COW file, copying from original on first write.
pub fn open(self: *const Self, io: Io, virtual_path: []const u8, flags: linux.O, mode: linux.mode_t) !KernelFD {
    const rel_path = relPath(virtual_path);

    var posix_flags: posix.O = .{};
    posix_flags.ACCMODE = switch (flags.ACCMODE) {
        .RDONLY => .RDONLY,
        .WRONLY => .WRONLY,
        .RDWR => .RDWR,
    };
    if (flags.CREAT) posix_flags.CREAT = true;
    if (flags.EXCL) posix_flags.EXCL = true;
    if (flags.TRUNC) posix_flags.TRUNC = true;
    if (flags.APPEND) posix_flags.APPEND = true;
    if (flags.NONBLOCK) posix_flags.NONBLOCK = true;
    if (flags.CLOEXEC) posix_flags.CLOEXEC = true;

    if (posix.openat(self.root_dir.handle, rel_path, posix_flags, @truncate(mode))) |fd| {
        return fd;
    } else |err| {
        if (err != error.FileNotFound) return err;
    }

    // COW file doesn't exist - create parent dirs and copy original if it exists
    if (std.fs.path.dirnamePosix(rel_path)) |parent| {
        try self.root_dir.createDirPath(io, parent);
    }

    var vpath_buf: [256]u8 = undefined;
    if (virtual_path.len >= vpath_buf.len) return error.NameTooLong;
    @memcpy(vpath_buf[0..virtual_path.len], virtual_path);
    vpath_buf[virtual_path.len] = 0;
    const vpath_z = vpath_buf[0..virtual_path.len :0];

    if (posix.openat(linux.AT.FDCWD, vpath_z, .{ .ACCMODE = .RDONLY }, 0)) |orig_fd| {
        defer posix.close(orig_fd);

        const cow_fd = try posix.openat(self.root_dir.handle, rel_path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
        }, @truncate(mode));
        errdefer posix.close(cow_fd);

        var copy_buf: [4096]u8 = undefined;
        while (true) {
            const n = try posix.read(orig_fd, &copy_buf);
            if (n == 0) break;
            var written: usize = 0;
            while (written < n) {
                written += try posix.write(cow_fd, copy_buf[written..n]);
            }
        }

        posix.close(cow_fd);
        var reopen_flags = posix_flags;
        reopen_flags.CREAT = true;
        return posix.openat(self.root_dir.handle, rel_path, reopen_flags, @truncate(mode));
    } else |_| {
        var create_flags = posix_flags;
        create_flags.CREAT = true;
        return posix.openat(self.root_dir.handle, rel_path, create_flags, @truncate(mode));
    }
}

const testing = std.testing;

test "Cow.init creates directory structure" {
    const io = testing.io;
    const uid = generateUid();
    var cow = try Self.init(io, uid);
    defer cow.deinit(io);

    try testing.expectEqualStrings("7465737474657374", &cow.uid); // "testtest" as hex

    // Verify root path format
    const root = cow.root_path[0..cow.root_path_len];
    try testing.expect(std.mem.startsWith(u8, root, "/tmp/.bvisor/sb/"));
    try testing.expect(std.mem.endsWith(u8, root, "/vfs/cow"));
}

test "Cow.exists returns false for nonexistent file" {
    const io = testing.io;
    const uid = generateUid();
    var cow = try Self.init(io, uid);
    defer cow.deinit(io);

    try testing.expect(!cow.exists(io, "/nonexistent/path/file.txt"));
}

test "Cow.open creates COW file" {
    const io = testing.io;
    const uid = generateUid();
    var cow = try Self.init(io, uid);
    defer cow.deinit(io);

    // Open a new file for writing
    const fd = try cow.open(io, "/test_cow_file.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
    defer posix.close(fd);

    // Write some data
    _ = try posix.write(fd, "hello cow");

    // Verify COW file now exists
    try testing.expect(cow.exists(io, "/test_cow_file.txt"));

    // Read it back via a new open
    const fd2 = try cow.open(io, "/test_cow_file.txt", .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(fd2);

    var buf: [64]u8 = undefined;
    const n = try posix.read(fd2, &buf);
    try testing.expectEqualStrings("hello cow", buf[0..n]);
}
