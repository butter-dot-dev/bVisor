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
root_path: [48]u8,
root_path_len: usize,

pub fn init(io: Io, uid: [16]u8) !Self {
    var root_path: [48]u8 = undefined;
    const root_slice = std.fmt.bufPrint(&root_path, "/tmp/.bvisor/sb/{s}/tmp", .{uid}) catch unreachable;
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

/// "/tmp/foo.txt" -> "foo.txt"
fn relPath(tmp_path: []const u8) ![]const u8 {
    if (!std.mem.startsWith(u8, tmp_path, "/tmp")) return error.InvalidPath;
    const after_tmp = tmp_path[4..];
    return if (after_tmp.len > 0 and after_tmp[0] == '/') after_tmp[1..] else after_tmp;
}

pub fn open(self: *const Self, io: Io, tmp_path: []const u8, flags: linux.O, mode: linux.mode_t) !KernelFD {
    const suffix = try relPath(tmp_path);

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
    if (flags.DIRECTORY) posix_flags.DIRECTORY = true;

    if (posix.openat(self.root_dir.handle, suffix, posix_flags, @truncate(mode))) |fd| {
        return fd;
    } else |err| {
        if (err == error.FileNotFound and flags.CREAT) {
            if (std.fs.path.dirnamePosix(suffix)) |parent| {
                try self.root_dir.createDirPath(io, parent);
            }
            return posix.openat(self.root_dir.handle, suffix, posix_flags, @truncate(mode));
        }
        return err;
    }
}

const testing = std.testing;

test "Tmp.init creates directory" {
    const io = testing.io;
    const uid = std.fmt.bytesToHex("testtest".*, .lower);
    var tmp = try Self.init(io, uid);
    defer tmp.deinit(io);

    // Verify root path format
    const root = tmp.root_path[0..tmp.root_path_len];
    try testing.expect(std.mem.startsWith(u8, root, "/tmp/.bvisor/sb/"));
    try testing.expect(std.mem.endsWith(u8, root, "/tmp"));
}

test "Tmp.open rejects non-tmp paths" {
    const io = testing.io;
    const uid = std.fmt.bytesToHex("testtest".*, .lower);
    var tmp = try Self.init(io, uid);
    defer tmp.deinit(io);

    try testing.expectError(error.InvalidPath, tmp.open(io, "/etc/passwd", .{ .ACCMODE = .RDONLY }, 0));
}

test "Tmp.open creates and reads file" {
    const io = testing.io;
    const uid = std.fmt.bytesToHex("testtest".*, .lower);
    var tmp = try Self.init(io, uid);
    defer tmp.deinit(io);

    // Open for writing
    const wfd = try tmp.open(io, "/tmp/test_tmp.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644);
    _ = try posix.write(wfd, "private tmp");
    posix.close(wfd);

    // Open for reading
    const rfd = try tmp.open(io, "/tmp/test_tmp.txt", .{ .ACCMODE = .RDONLY }, 0);
    defer posix.close(rfd);

    var buf: [64]u8 = undefined;
    const n = try posix.read(rfd, &buf);
    try testing.expectEqualStrings("private tmp", buf[0..n]);
}
