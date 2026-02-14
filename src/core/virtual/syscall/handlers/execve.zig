const std = @import("std");
const linux = std.os.linux;
const LinuxErr = @import("../../../linux_error.zig").LinuxErr;
const Thread = @import("../../proc/Thread.zig");
const AbsTid = Thread.AbsTid;
const path_router = @import("../../path.zig");
const resolveAndRoute = path_router.resolveAndRoute;
const Supervisor = @import("../../../Supervisor.zig");
const replyContinue = @import("../../../seccomp/notif.zig").replyContinue;
const memory_bridge = @import("../../../utils/memory_bridge.zig");

pub fn handle(notif: linux.SECCOMP.notif, supervisor: *Supervisor) !linux.SECCOMP.notif_resp {
    // Handling execve is tricky because, similar to clone, it must be called by the guest process
    // IE supervisor can't call it on guest's behalf

    // To direct the exec to happen on the correct sandboxed file, we must overwrite the
    // path directly in the guest process's memory, before a replyContinue

    // TODO: since sandbox filesystem lives at /tmp/.bvisor/ ..., it's more likely than not
    // that a specified path like /usr/bin would be LONGER in the sandbox than the guest process
    // has available; we can't write longer paths into guest memory, only shorter
    // We need a way to figure out how to handle this.
    // For now, any file that's not at its specified location, IE COW or TMP files, will error.PERM

    const logger = supervisor.logger;
    const caller_tid: AbsTid = @intCast(notif.pid);

    // Read pathname from child memory (arg0 is pointer to path)
    const path_ptr: u64 = notif.data.arg0;
    var path_buf: [256]u8 = undefined;
    const path = try memory_bridge.readString(&path_buf, caller_tid, path_ptr);
    if (path.len == 0) {
        return LinuxErr.INVAL;
    }

    // Resolve against cwd
    var cwd_buf: [512]u8 = undefined;
    const cwd: []const u8 = blk: {
        supervisor.mutex.lockUncancelable(supervisor.io);
        defer supervisor.mutex.unlock(supervisor.io);

        const caller = try supervisor.guest_threads.get(caller_tid);
        const c = caller.fs_info.cwd;
        if (c.len > cwd_buf.len) return LinuxErr.NAMETOOLONG;
        @memcpy(cwd_buf[0..c.len], c);
        break :blk cwd_buf[0..c.len];
    };

    var resolve_buf: [512]u8 = undefined;
    const route_result = resolveAndRoute(cwd, path, &resolve_buf) catch {
        return LinuxErr.NAMETOOLONG;
    };

    switch (route_result) {
        .block => {
            logger.log("execve: blocked path: {s}", .{path});
            return LinuxErr.PERM;
        },
        .handle => |h| {
            switch (h.backend) {
                .proc => {
                    logger.log("execve: cannot exec proc file: {s}", .{path});
                    return LinuxErr.ACCES;
                },
                .passthrough => {
                    // guest's presumed path maps directly to the actual kernel path
                    logger.log("execve: passthrough {s}", .{h.normalized});
                    return replyContinue(notif.id);
                },
                .cow => {
                    if (supervisor.overlay.cowExists(h.normalized)) {
                        // guest's presumed path maps to a COW copy
                        // unfortunately, we can't support this because the kernel path is almost certainly
                        // longer than the guest's speciified path, so we can't overwrite it
                        // For now, we reply error PERM
                        logger.log("execve: the specified executable at path cannot be executed because its sandboxed path cannot be overwritten in guest memory", .{});
                        // TODO: figure out how to support this
                        return LinuxErr.PERM;
                    }
                    // guest's presumed path maps to the actual kernel path, as it hasn't been written to yet
                    return replyContinue(notif.id);
                },
                .tmp => {
                    // guest's presumed path maps to a TMP file
                    // unfortunately, we can't supprt this either, for the same reasons as above.
                    // For now, we reply error PERM
                    logger.log("execve: the specified executable at path cannot be executed because its sandboxed path cannot be overwritten in guest memory", .{});
                    return LinuxErr.PERM;
                    // TODO: figure out how to support this
                },
            }
        },
    }
}

const testing = std.testing;
const makeNotif = @import("../../../seccomp/notif.zig").makeNotif;
const isContinue = @import("../../../seccomp/notif.zig").isContinue;
const LogBuffer = @import("../../../LogBuffer.zig");
const generateUid = @import("../../../setup.zig").generateUid;

fn makeExecveNotif(pid: AbsTid, path: [*:0]const u8) linux.SECCOMP.notif {
    return makeNotif(.execve, .{
        .pid = pid,
        .arg0 = @intFromPtr(path),
    });
}

test "execve /bin/sh returns CONTINUE" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(init_tid, "/bin/sh");
    const resp = try handle(notif, &supervisor);
    try testing.expect(isContinue(resp));
}

test "execve /sys/blocked returns EPERM" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(init_tid, "/sys/something");
    try testing.expectError(error.PERM, handle(notif, &supervisor));
}

test "execve /proc/self returns EACCES" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(init_tid, "/proc/self");
    try testing.expectError(error.ACCES, handle(notif, &supervisor));
}

test "execve empty path returns EINVAL" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(init_tid, "");
    try testing.expectError(error.INVAL, handle(notif, &supervisor));
}

test "execve unknown caller returns ESRCH" {
    const allocator = testing.allocator;
    const init_tid: AbsTid = 100;
    var stdout_buf = LogBuffer.init(allocator);
    var stderr_buf = LogBuffer.init(allocator);
    defer stdout_buf.deinit();
    defer stderr_buf.deinit();
    var supervisor = try Supervisor.init(allocator, testing.io, generateUid(testing.io), -1, init_tid, &stdout_buf, &stderr_buf);
    defer supervisor.deinit();

    const notif = makeExecveNotif(999, "/bin/sh");
    try testing.expectError(error.SRCH, handle(notif, &supervisor));
}
