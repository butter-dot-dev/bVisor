const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const types = @import("types.zig");
const Logger = types.Logger;
const run = @import("setup.zig").run;

test {
    // Zig tests must be imported from the test root,
    // Otherwise they're not included
    _ = @import("VirtualFilesystem.zig");
    _ = @import("Supervisor.zig");
}

// Example child process demonstrating virtual filesystem
fn example_child(io: std.Io) void {
    _ = io;

    // This goes to stderr - should passthrough to terminal
    std.debug.print("Child starting - this is stderr (passthrough)\n", .{});

    // Open a virtual file
    std.debug.print("Opening virtual file /test.txt...\n", .{});
    const fd = posix.openat(linux.AT.FDCWD, "/test.txt", .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o644) catch |err| {
        std.debug.print("Failed to open file: {}\n", .{err});
        return;
    };
    std.debug.print("Opened virtual file, fd={d}\n", .{fd});

    // Write to it
    const msg = "Hello from sandbox!\n";
    const written = posix.write(fd, msg) catch |err| {
        std.debug.print("Failed to write: {}\n", .{err});
        return;
    };
    std.debug.print("Wrote {d} bytes to virtual file\n", .{written});

    // Close it
    posix.close(fd);
    std.debug.print("Closed virtual file\n", .{});

    std.debug.print("Child done!\n", .{});
}

pub fn main() !void {
    const logger = Logger.init(.prefork);

    // Run child in syscall interception mode with virtual filesystem
    logger.log("Running child with syscall interception:", .{});
    try run(example_child);
}
