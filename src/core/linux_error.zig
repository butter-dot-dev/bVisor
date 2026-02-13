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

    // When error
    std.debug.print("\x1b[95m[supervisor]   {s}: {s}\x1b[0m\n", .{ rc_name, fmtlog });

    inline for (@typeInfo(LinuxErr).error_set.?) |err_info| {
        if (std.mem.eql(u8, err_info.name, rc_name))
            return @field(LinuxErr, err_info.name);
    }
    unreachable;
}

/// Map any LinuxErr into the corresponding entry in linux.E
fn strictToLinuxE(err: anyerror) anyerror!linux.E {
    inline for (@typeInfo(linux.E).@"enum".fields) |field| {
        if (std.mem.eql(u8, @errorName(err), field.name))
            return @enumFromInt(field.value);
    }
    return err;
}

// Coerces any error to some LinuxErr
pub fn toLinuxE(err: anyerror) linux.E {
    return strictToLinuxE(err) catch |e| switch (e) {
        // e.g., error.SyscallFailed => ...,
        else => .NOSYS, // TODO: handle specific non-LinuxErr errors
    };
}
