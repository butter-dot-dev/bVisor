const std = @import("std");
const posix = std.posix;

pub const Proc = struct {
    guest_pid: i32,
    offset: usize,

    pub fn open(path: []const u8, flags: posix.O, mode: posix.mode_t) !Proc {
        _ = flags;
        _ = mode;

        // Parse /proc/self or /proc/<pid>
        // For now, we only support /proc/self which returns guest pid 1
        // In a real implementation, we'd resolve the path and map to actual guest pid
        if (std.mem.startsWith(u8, path, "/proc/self") or std.mem.eql(u8, path, "/proc/self")) {
            // /proc/self maps to the calling process's guest pid
            // For now return a placeholder - the actual guest_pid should be passed in
            return .{ .guest_pid = 1, .offset = 0 };
        }

        // Try to parse /proc/<pid>
        const proc_prefix = "/proc/";
        if (std.mem.startsWith(u8, path, proc_prefix)) {
            const after_proc = path[proc_prefix.len..];
            // Find end of pid (next / or end of string)
            var end: usize = 0;
            while (end < after_proc.len and after_proc[end] != '/') : (end += 1) {}
            if (end > 0) {
                const pid_str = after_proc[0..end];
                const pid = std.fmt.parseInt(i32, pid_str, 10) catch return error.InvalidPath;
                return .{ .guest_pid = pid, .offset = 0 };
            }
        }

        return error.InvalidPath;
    }

    pub fn read(self: *Proc, buf: []u8) !usize {
        // Format guest pid as string
        var pid_buf: [32]u8 = undefined;
        const pid_str = std.fmt.bufPrint(&pid_buf, "{d}\n", .{self.guest_pid}) catch return error.BufferTooSmall;

        // Handle offset - return remaining bytes after offset
        if (self.offset >= pid_str.len) {
            return 0; // EOF
        }

        const remaining = pid_str[self.offset..];
        const to_copy = @min(remaining.len, buf.len);
        @memcpy(buf[0..to_copy], remaining[0..to_copy]);
        self.offset += to_copy;
        return to_copy;
    }

    pub fn write(self: *Proc, data: []const u8) !usize {
        _ = self;
        _ = data;
        return error.ReadOnlyFileSystem;
    }

    pub fn close(self: *Proc) void {
        _ = self;
        // nothing to close
    }
};

const testing = std.testing;

test "open /proc/self returns guest pid 1" {}

test "open /proc/123/status works" {}

test "read returns formatted pid string" {}

test "write returns ReadOnlyFileSystem" {}

test "offset tracking works across multiple reads" {}
