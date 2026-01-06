const std = @import("std");
const types = @import("types.zig");
const Logger = types.Logger;
const setup = @import("setup.zig");

test {
    // Zig tests must be imported from the test root,
    // Otherwise they're not included
    _ = @import("VirtualFilesystem.zig");
    _ = @import("Supervisor.zig");
}

pub fn main() !void {
    const logger = Logger.init(.prefork);

    // Get command-line arguments
    var args = std.process.args();
    _ = args.skip(); // Skip program name

    // Collect remaining args into a buffer
    var argv_buf: [64][:0]const u8 = undefined;
    var argc: usize = 0;
    while (args.next()) |arg| {
        if (argc >= 64) break;
        argv_buf[argc] = arg;
        argc += 1;
    }

    if (argc == 0) {
        std.debug.print("Usage: bVisor <command> [args...]\n", .{});
        std.debug.print("Example: bVisor /bin/sh -c 'echo hello'\n", .{});
        return;
    }

    const argv = argv_buf[0..argc];
    logger.log("Running command in sandbox: {s}", .{argv[0]});
    try setup.runCommand(argv);
}
