const std = @import("std");
const types = @import("types.zig"); // ERIK TODO: kitchen sink utils, think about what else we could do here
const Logger = types.Logger;
const LogBuffer = @import("LogBuffer.zig");
const setup = @import("setup.zig");
const Io = std.Io;
const File = Io.File;
const linux = std.os.linux;
const execute = setup.execute;

test {
    _ = @import("Supervisor.zig");
    _ = @import("LogBuffer.zig");
    _ = @import("utils/proc_info.zig");
    _ = @import("virtual/proc/Threads.zig");
    _ = @import("virtual/fs/FdTable.zig");
    _ = @import("virtual/fs/FsInfo.zig");
    _ = @import("virtual/path.zig");
    _ = @import("virtual/fs/backend/procfile.zig");
    _ = @import("virtual/fs/backend/cow.zig");
    _ = @import("virtual/fs/backend/tmp.zig");
    _ = @import("virtual/syscall/handlers/exit.zig");
    _ = @import("virtual/syscall/handlers/exit_group.zig");
    _ = @import("virtual/syscall/handlers/tkill.zig");
    _ = @import("virtual/syscall/handlers/getpid.zig");
    _ = @import("virtual/syscall/handlers/getppid.zig");
    _ = @import("virtual/syscall/handlers/gettid.zig");
    _ = @import("virtual/syscall/handlers/kill.zig");
    _ = @import("virtual/syscall/handlers/openat.zig");
    _ = @import("virtual/syscall/handlers/close.zig");
    _ = @import("virtual/syscall/handlers/read.zig");
    _ = @import("virtual/syscall/handlers/readv.zig");
    _ = @import("virtual/syscall/handlers/write.zig");
    _ = @import("virtual/syscall/handlers/writev.zig");
    _ = @import("virtual/syscall/handlers/dup.zig");
    _ = @import("virtual/syscall/handlers/dup3.zig");
    _ = @import("virtual/syscall/handlers/fstat.zig");
    _ = @import("virtual/syscall/handlers/fstatat64.zig");
    _ = @import("virtual/syscall/handlers/uname.zig");
    _ = @import("virtual/syscall/handlers/sysinfo.zig");
    _ = @import("virtual/syscall/handlers/lseek.zig");
    _ = @import("virtual/syscall/handlers/getcwd.zig");
    _ = @import("virtual/syscall/handlers/chdir.zig");
    _ = @import("virtual/syscall/handlers/fchdir.zig");
    _ = @import("virtual/syscall/handlers/faccessat.zig");
    _ = @import("virtual/syscall/handlers/pipe2.zig");
    _ = @import("virtual/syscall/handlers/fcntl.zig");
    _ = @import("virtual/syscall/handlers/socket.zig");
    _ = @import("virtual/syscall/handlers/socketpair.zig");
    _ = @import("virtual/syscall/handlers/connect.zig");
    _ = @import("virtual/syscall/handlers/shutdown.zig");
    _ = @import("virtual/syscall/handlers/ioctl.zig");
    _ = @import("virtual/syscall/handlers/recvfrom.zig");
    _ = @import("virtual/syscall/handlers/sendto.zig");
    _ = @import("virtual/syscall/handlers/sendmsg.zig");
    _ = @import("virtual/syscall/handlers/recvmsg.zig");
    _ = @import("virtual/syscall/handlers/execve.zig");
    _ = @import("virtual/syscall/e2e_test.zig");
    _ = @import("virtual/OverlayRoot.zig");
    _ = @import("virtual/fs/backend/passthrough.zig");
}

fn runBash() void {
    const argv = [_:null]?[*:0]const u8{ "/bin/sh", "-c", "echo hello world" };
    const envp = [_:null]?[*:0]const u8{};
    _ = linux.execve("/bin/sh", &argv, &envp);
    linux.exit_group(1); // only reached if execve fails
}

pub fn main() !void {
    const logger = Logger.init(.prefork);
    logger.log("Running bash via execve:", .{});

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded: std.Io.Threaded = .init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var stdout = LogBuffer.init(allocator);
    var stderr = LogBuffer.init(allocator);
    defer stdout.deinit();
    defer stderr.deinit();

    try execute(allocator, io, setup.generateUid(io), runBash, &stdout, &stderr);
    try stdout.flush(io, File.stdout());
    try stderr.flush(io, File.stderr());
}
