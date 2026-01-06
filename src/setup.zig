const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const types = @import("types.zig");
const FD = types.FD;
const Result = types.LinuxResult;
const MemoryBridge = types.MemoryBridge;
const Logger = types.Logger;
const Supervisor = @import("Supervisor.zig");

/// Run an external command in the sandbox
pub fn runCommand(argv: []const [:0]const u8) !void {
    const socket_pair: [2]FD = try posix.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM,
        0,
    );
    const child_sock: FD, const supervisor_sock: FD = socket_pair;

    const fork_result = try std.posix.fork();
    if (fork_result == 0) {
        posix.close(supervisor_sock);
        try child_process_exec(child_sock, argv);
    } else {
        posix.close(child_sock);
        const child_pid: linux.pid_t = fork_result;
        try supervisor_process(supervisor_sock, child_pid);
    }
}

pub fn run(runnable: *const fn (io: std.Io) void) !void {
    // Create socket pair for child and supervisor
    // To allow inter-process communication
    const socket_pair: [2]FD = try posix.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM,
        0,
    );
    const child_sock: FD, const supervisor_sock: FD = socket_pair;

    // Fork into both subprocesses
    const fork_result = try std.posix.fork();
    if (fork_result == 0) {
        // Child process
        posix.close(supervisor_sock);
        try child_process(child_sock, runnable);
    } else {
        // Supervisor process
        posix.close(child_sock);

        // fork_result is the child PID, needed for looking up the notify FD
        const child_pid: linux.pid_t = fork_result;
        try supervisor_process(supervisor_sock, child_pid);
    }
}

const BPFInstruction = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const BPFFilterProgram = extern struct {
    len: u16,
    filter: [*]const BPFInstruction,
};

fn child_process(socket: FD, runnable: *const fn (io: std.Io) void) !void {
    const logger = Logger.init(.child);
    logger.log("Child process starting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Before starting seccomp, there's a chicken-and-egg issue
    // The supervisor needs seccomp's FD to listen on
    // But we can't send that FD across the socket once seccomp is running
    // since that .write command to the socket would get blocked

    // To get around this, we predict the FD that seccomp will use
    // and send it on the socket before starting seccomp

    // Posix.dup(0) returns the lowest available fd, which we immediately close
    const next_fd: FD = try posix.dup(0);
    posix.close(next_fd);

    // Send to supervisor then close socket
    var fd_bytes: [4]u8 = undefined;
    std.mem.writeInt(FD, &fd_bytes, next_fd, .little);
    _ = try posix.write(socket, &fd_bytes);
    // posix.close(socket);

    // ===== SECCOMP SETUP =====

    // Set "No New Privileges" mode to prevent this process (and children)
    // from re-elevating their permissions. Required by seccomp.
    _ = try posix.prctl(posix.PR.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });
    logger.log("Privilege elevation locked", .{});

    // Write a BPF program that instructs the kernel to intercept all syscalls
    // and trigger USER_NOTIF
    var instructions = [_]BPFInstruction{
        .{ .code = linux.BPF.RET | linux.BPF.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.USER_NOTIF },
    };
    var prog = BPFFilterProgram{
        .len = instructions.len,
        .filter = &instructions,
    };

    logger.log("Entering seccomp mode", .{});

    // Install program using seccomp
    const notify_fd: FD = try Result(FD).from(
        linux.seccomp(
            linux.SECCOMP.SET_MODE_FILTER,
            linux.SECCOMP.FILTER_FLAG.NEW_LISTENER,
            @ptrCast(&prog),
        ),
    ).unwrap();

    // Verify prediction was correct
    if (notify_fd != next_fd) {
        // Prediction failed - exit
        // Can't print, since seccomp is running without a supervisor listening
        return error.PredictionFailed;
    }

    // Now we just run some other process!
    // Shell out to bash with cmd in the future
    @call(.never_inline, runnable, .{io});
}

fn child_process_exec(socket: FD, argv: []const [:0]const u8) !void {
    const logger = Logger.init(.child);
    logger.log("Child process starting (exec mode)", .{});

    // Predict the FD that seccomp will use
    const next_fd: FD = try posix.dup(0);
    posix.close(next_fd);

    // Send to supervisor then close socket
    var fd_bytes: [4]u8 = undefined;
    std.mem.writeInt(FD, &fd_bytes, next_fd, .little);
    _ = try posix.write(socket, &fd_bytes);

    // Set "No New Privileges" mode
    _ = try posix.prctl(posix.PR.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });
    logger.log("Privilege elevation locked", .{});

    // BPF program to intercept all syscalls
    var instructions = [_]BPFInstruction{
        .{ .code = linux.BPF.RET | linux.BPF.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.USER_NOTIF },
    };
    var prog = BPFFilterProgram{
        .len = instructions.len,
        .filter = &instructions,
    };

    logger.log("Entering seccomp mode", .{});

    // Install program using seccomp
    const notify_fd: FD = try Result(FD).from(
        linux.seccomp(
            linux.SECCOMP.SET_MODE_FILTER,
            linux.SECCOMP.FILTER_FLAG.NEW_LISTENER,
            @ptrCast(&prog),
        ),
    ).unwrap();

    // Verify prediction was correct
    if (notify_fd != next_fd) {
        return error.PredictionFailed;
    }

    // Convert argv to null-terminated array for execve
    var argv_buf: [64:null]?[*:0]const u8 = undefined;
    for (argv, 0..) |arg, i| {
        if (i >= 64) break;
        argv_buf[i] = arg.ptr;
    }
    argv_buf[argv.len] = null;

    logger.log("Executing command: {s}", .{argv[0]});

    // execve replaces the current process - doesn't return on success
    const envp: [*:null]const ?[*:0]const u8 = @ptrCast(std.os.environ.ptr);
    const err = posix.execveZ(argv_buf[0].?, &argv_buf, envp);
    std.debug.print("execve failed: {}\n", .{err});
}

fn supervisor_process(socket: FD, child_pid: linux.pid_t) !void {
    const logger = Logger.init(.supervisor);
    logger.log("Supervisor process starting", .{});
    defer logger.log("Supervisor process exiting", .{});

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // ===== Dereferencing notify FD =====
    // The child sends its process-local notify FD across the socket
    // We use its own PID + FD to look up the actual FD

    var child_notify_fd_bytes: [4]u8 = undefined;
    const bytes_read = try posix.read(socket, &child_notify_fd_bytes);
    if (bytes_read != 4) {
        std.debug.print("failed to read fd from socket\n", .{});
        return error.ReadFailed;
    }
    const child_notify_fd: FD = std.mem.readInt(i32, &child_notify_fd_bytes, .little);

    // Use child PID to look up its FD table
    const child_fd_table: FD = try Result(FD).from(
        linux.pidfd_open(child_pid, 0),
    ).unwrap();

    // Since notify FD was sent eagerly, poll child's FD table until FD is visible
    // Otherwise we'd have race condition
    var notify_fd: FD = undefined;
    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        const result = linux.pidfd_getfd(child_fd_table, child_notify_fd, 0);
        switch (Result(FD).from(result)) {
            .Ok => |value| {
                notify_fd = value;
                break;
            },
            .Error => |err| switch (err) {
                .BADF => {
                    // FD doesn't exist yet in child - retry
                    try io.sleep(std.Io.Duration.fromMilliseconds(10), .awake);
                    continue;
                },
                else => |_| return posix.unexpectedErrno(err),
            },
        }
    } else {
        return error.PidfdGetfdFailed;
    }

    var supervisor = Supervisor.init(notify_fd, child_pid, gpa, io);
    defer supervisor.deinit();
    try supervisor.run();
}
