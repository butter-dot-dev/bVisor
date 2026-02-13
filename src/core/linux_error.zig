// Generic handling for any fallible linux function invocation
// const rc: usize = linux.some_fallible_fn
// try checkErr(rc);

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

// Identical set of literals to the entries in the std.linux.E enum
pub const LinuxErr = error{
    PERM,
    NOENT,
    SRCH,
    INTR,
    IO,
    NXIO,
    @"2BIG",
    NOEXEC,
    BADF,
    CHILD,
    AGAIN,
    NOMEM,
    ACCES,
    FAULT,
    NOTBLK,
    BUSY,
    EXIST,
    XDEV,
    NODEV,
    NOTDIR,
    ISDIR,
    INVAL,
    NFILE,
    MFILE,
    NOTTY,
    TXTBSY,
    FBIG,
    NOSPC,
    SPIPE,
    ROFS,
    MLINK,
    PIPE,
    DOM,
    RANGE,
    DEADLK,
    NAMETOOLONG,
    NOLCK,
    NOSYS,
    NOTEMPTY,
    LOOP,
    NOMSG,
    IDRM,
    CHRNG,
    L2NSYNC,
    L3HLT,
    L3RST,
    LNRNG,
    UNATCH,
    NOCSI,
    L2HLT,
    BADE,
    BADR,
    XFULL,
    NOANO,
    BADRQC,
    BADSLT,
    BFONT,
    NOSTR,
    NODATA,
    TIME,
    NOSR,
    NONET,
    NOPKG,
    REMOTE,
    NOLINK,
    ADV,
    SRMNT,
    COMM,
    PROTO,
    MULTIHOP,
    DOTDOT,
    BADMSG,
    OVERFLOW,
    NOTUNIQ,
    BADFD,
    REMCHG,
    LIBACC,
    LIBBAD,
    LIBSCN,
    LIBMAX,
    LIBEXEC,
    ILSEQ,
    RESTART,
    STRPIPE,
    USERS,
    NOTSOCK,
    DESTADDRREQ,
    MSGSIZE,
    PROTOTYPE,
    NOPROTOOPT,
    PROTONOSUPPORT,
    SOCKTNOSUPPORT,
    OPNOTSUPP,
    PFNOSUPPORT,
    AFNOSUPPORT,
    ADDRINUSE,
    ADDRNOTAVAIL,
    NETDOWN,
    NETUNREACH,
    NETRESET,
    CONNABORTED,
    CONNRESET,
    NOBUFS,
    ISCONN,
    NOTCONN,
    SHUTDOWN,
    TOOMANYREFS,
    TIMEDOUT,
    CONNREFUSED,
    HOSTDOWN,
    HOSTUNREACH,
    ALREADY,
    INPROGRESS,
    STALE,
    UCLEAN,
    NOTNAM,
    NAVAIL,
    ISNAM,
    REMOTEIO,
    DQUOT,
    NOMEDIUM,
    MEDIUMTYPE,
    CANCELED,
    NOKEY,
    KEYEXPIRED,
    KEYREVOKED,
    KEYREJECTED,
    OWNERDEAD,
    NOTRECOVERABLE,
    RFKILL,
    HWPOISON,
    NSRNODATA,
    NSRFORMERR,
    NSRSERVFAIL,
    NSRNOTFOUND,
    NSRNOTIMP,
    NSRREFUSED,
    NSRBADQUERY,
    NSRBADNAME,
    NSRBADFAMILY,
    NSRBADRESP,
    NSRCONNREFUSED,
    NSRTIMEOUT,
    NSROF,
    NSRFILE,
    NSRNOMEM,
    NSRDESTRUCTION,
    NSRQUERYDOMAINTOOLONG,
    NSRCNAMELOOP,
};

/// Map any error in a linux return code to the corresponding error in LinuxErr.
/// Include a formatted string for error case
pub fn checkErr(return_code: usize, comptime format: []const u8, args: anytype) LinuxErr!void {
    const rc = linux.errno(return_code);
    if (rc == .SUCCESS) return;

    var buf: [1024]u8 = undefined;
    const fmtlog = std.fmt.bufPrint(&buf, format, args) catch unreachable;
    const rc_name = @tagName(rc);

    // When error, print red error message
    if (!builtin.is_test) {
        std.debug.print("\x1b[91m[supervisor]   {s}: {s}\x1b[0m\n", .{ rc_name, fmtlog });
    }

    // Map the return code to a LinuxErr
    inline for (@typeInfo(LinuxErr).error_set.?) |err_info| {
        if (std.mem.eql(u8, err_info.name, rc_name))
            return @field(LinuxErr, err_info.name);
    }
    unreachable;
}

pub fn toLinuxE(err: anytype) linux.E {
    return switch (err) {
        // Non-LinuxErr → linux.E mappings (std.Io and std.fs errors)
        error.AccessDenied => .ACCES,
        error.BadPathName => .INVAL,
        error.Canceled => .CANCELED,
        error.DeviceBusy => .BUSY,
        error.DiskQuota => .DQUOT,
        error.FileBusy => .TXTBSY,
        error.FileLocksUnsupported => .OPNOTSUPP,
        error.FileNotFound => .NOENT,
        error.FileTooBig => .FBIG,
        error.InsufficientBufferLength => .RANGE,
        error.InvalidPath => .INVAL,
        error.IsDir => .ISDIR,
        error.LeaderNotFound => .SRCH,
        error.LinkQuotaExceeded => .MLINK,
        error.NameTooLong => .NAMETOOLONG,
        error.NoDevice => .NODEV,
        error.NoSpaceLeft => .NOSPC,
        error.NotDir => .NOTDIR,
        error.OutOfMemory => .NOMEM,
        error.PathAlreadyExists => .EXIST,
        error.PermissionDenied => .PERM,
        error.ProcessFdQuotaExceeded => .MFILE,
        error.ReadOnlyFileSystem => .ROFS,
        error.Streaming => .SPIPE,
        error.SymLinkLoop => .LOOP,
        error.SystemFdQuotaExceeded => .NFILE,
        error.SystemResources => .NOMEM,
        error.Unexpected => .IO,
        error.WouldBlock => .AGAIN,
        error.WriteFailed => .IO,

        // Some windows errors that end up in the error set
        // which we don't care about on linux
        error.AntivirusInterference,
        error.PipeBusy,
        error.NetworkNotFound,
        => unreachable,

        // All remaining errors must be LinuxErr members (name-matched to linux.E)
        inline else => |e| {
            const name = @errorName(e);
            if (comptime !@hasField(linux.E, name))
                @compileError("Unhandled non-LinuxErr error: " ++ name);
            return @field(linux.E, name);
        },
    };
}
