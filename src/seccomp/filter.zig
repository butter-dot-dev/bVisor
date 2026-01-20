const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const types = @import("../types.zig");
const KernelFD = types.KernelFD;
const Result = types.LinuxResult;

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

/// Predict the next available FD (used for pre-sending notify FD to supervisor).
/// Caller must ensure no FDs are opened between this call and install().
pub fn predictNotifyFd() !KernelFD {
    // dup(0) returns the lowest available fd
    const next_fd: KernelFD = try posix.dup(0);
    posix.close(next_fd);
    return next_fd;
}

/// Install seccomp filter that intercepts all syscalls via USER_NOTIF.
/// Returns the notify FD that the supervisor should listen on.
/// Requires NO_NEW_PRIVS to be set first.
pub fn install() !KernelFD {
    // BPF program that triggers USER_NOTIF for all syscalls
    // In the future we can make this more restrictive
    var instructions = [_]BPFInstruction{
        .{ .code = linux.BPF.RET | linux.BPF.K, .jt = 0, .jf = 0, .k = linux.SECCOMP.RET.USER_NOTIF },
    };
    var prog = BPFFilterProgram{
        .len = instructions.len,
        .filter = &instructions,
    };

    // Set NO_NEW_PRIVS mode
    // Required before installing seccomp filter
    _ = try posix.prctl(posix.PR.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });

    return try Result(KernelFD).from(
        linux.seccomp(
            linux.SECCOMP.SET_MODE_FILTER,
            linux.SECCOMP.FILTER_FLAG.NEW_LISTENER,
            @ptrCast(&prog),
        ),
    ).unwrap();
}
