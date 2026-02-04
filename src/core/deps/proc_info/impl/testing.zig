const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const Thread = @import("../../../virtual/proc/Thread.zig");
// Thread IDs
pub const AbsTid = Thread.AbsTid;
pub const NsTid = Thread.NsTid;
// ThreadGroup IDs
pub const AbsTgid = Thread.AbsTgid;
pub const NsTgid = Thread.NsTgid;

const Threads = @import("../../../virtual/proc/Threads.zig");
pub const CloneFlags = Threads.CloneFlags;
const ThreadStatus = @import("../../../virtual/proc/ThreadStatus.zig");
const MAX_NS_DEPTH = ThreadStatus.MAX_NS_DEPTH;

/// Mock parent TID map: child_tid -> parent_tid
pub var mock_ptid_map: std.AutoHashMapUnmanaged(AbsTid, AbsTid) = .empty;

/// Mock clone flags map: child_tid -> CloneFlags
pub var mock_clone_flags: std.AutoHashMapUnmanaged(AbsTid, CloneFlags) = .empty;

/// Mock NSpid map: AbsTid -> array of NsTids (outermost to innermost)
pub var mock_nstids: std.AutoHashMapUnmanaged(AbsTid, []const NsTid) = .empty;

/// Mock NStgid map: AbsTid -> array of NsTgids (outermost to innermost)
pub var mock_nstgids: std.AutoHashMapUnmanaged(AbsTid, []const NsTgid) = .empty;

/// Return mock clone flags for a child
pub fn detectCloneFlags(parent_tid: AbsTid, child_tid: AbsTid) CloneFlags {
    _ = parent_tid;
    return mock_clone_flags.get(child_tid) orelse CloneFlags{};
}

/// Read NSpid chain from mock map.
/// If not explicitly configured, returns [tid] as a single-element array,
/// which is correct for a thread in a single (root) namespace.
/// The tgid parameter is ignored in testing (we key by tid only).
pub fn readNsTids(tgid: AbsTgid, tid: AbsTid, nstid_buf: []NsTid) ![]NsTid {
    _ = tgid;
    if (mock_nstids.get(tid)) |nstids| {
        if (nstids.len > nstid_buf.len) return error.BufferTooSmall;
        @memcpy(nstid_buf[0..nstids.len], nstids);
        return nstid_buf[0..nstids.len];
    }
    // Default: single namespace, NsTid = AbsTid
    if (nstid_buf.len < 1) return error.BufferTooSmall;
    nstid_buf[0] = tid;
    return nstid_buf[0..1];
}

/// Mock TGID map: tid -> tgid (for threads that aren't group leaders)
pub var mock_tgid_map: std.AutoHashMapUnmanaged(AbsTid, AbsTgid) = .empty;

/// Get the status of a Thread from mock maps.
/// TGID is looked up from mock_tgid_map, or defaults to tid (thread is leader).
pub fn getStatus(tid: AbsTid) !ThreadStatus {
    // Read parent TID from mock map
    const ptid = mock_ptid_map.get(tid) orelse return error.ThreadNotInKernel;

    // Get TGID from mock, or default to tid (thread group leader)
    const tgid = mock_tgid_map.get(tid) orelse tid;

    var status = ThreadStatus{
        .tid = tid,
        .tgid = tgid,
        .ptid = ptid,
    };

    // Populate NsTgids from mock or default to [tgid]
    if (mock_nstgids.get(tid)) |nstgids| {
        if (nstgids.len > MAX_NS_DEPTH) return error.BufferTooSmall;
        @memcpy(status.nstgids_buf[0..nstgids.len], nstgids);
        status.nstgids_len = nstgids.len;
    } else {
        status.nstgids_buf[0] = tgid;
        status.nstgids_len = 1;
    }

    // Populate NsTids from mock or default to [tid]
    if (mock_nstids.get(tid)) |nstids| {
        if (nstids.len > MAX_NS_DEPTH) return error.BufferTooSmall;
        @memcpy(status.nstids_buf[0..nstids.len], nstids);
        status.nstids_len = nstids.len;
    } else {
        status.nstids_buf[0] = tid;
        status.nstids_len = 1;
    }

    return status;
}

/// List all TIDs from mock - returns keys from mock_ptid_map
pub fn listTids(allocator: Allocator) ![]AbsTid {
    var tids: std.ArrayListUnmanaged(AbsTid) = .empty;
    errdefer tids.deinit(allocator);

    var iter = mock_ptid_map.keyIterator();
    while (iter.next()) |tid_ptr| {
        try tids.append(allocator, tid_ptr.*);
    }

    return tids.toOwnedSlice(allocator);
}

// ============================================================================
// Test Setup Functions
// ============================================================================

/// Reset all mock state - call in test cleanup
pub fn reset(allocator: Allocator) void {
    mock_ptid_map.deinit(allocator);
    mock_tgid_map.deinit(allocator);
    mock_clone_flags.deinit(allocator);
    mock_nstids.deinit(allocator);
    mock_nstgids.deinit(allocator);
    mock_ptid_map = .empty;
    mock_tgid_map = .empty;
    mock_clone_flags = .empty;
    mock_nstids = .empty;
    mock_nstgids = .empty;
}

/// Setup a parent relationship in the mock
pub fn setupParent(allocator: Allocator, child_tid: AbsTid, parent_tid: AbsTid) !void {
    try mock_ptid_map.put(allocator, child_tid, parent_tid);
}

/// Setup clone flags for a child in the mock
pub fn setupCloneFlags(allocator: Allocator, child_tid: AbsTid, flags: CloneFlags) !void {
    try mock_clone_flags.put(allocator, child_tid, flags);
}

/// Setup NSpid chain for a thread in the mock.
/// nstids should be ordered from outermost (root) to innermost (thread's own namespace).
pub fn setupNsTids(allocator: Allocator, tid: AbsTid, nstids: []const NsTid) !void {
    try mock_nstids.put(allocator, tid, nstids);
}

/// Setup NStgid chain for a thread in the mock.
/// nstgids should be ordered from outermost (root) to innermost (thread's own namespace).
pub fn setupNsTgids(allocator: Allocator, tid: AbsTid, nstgids: []const NsTgid) !void {
    try mock_nstgids.put(allocator, tid, nstgids);
}

/// Setup TGID for a thread that is not the group leader.
/// If not set, getStatus() defaults to tid == tgid (thread is leader).
pub fn setupTgid(allocator: Allocator, tid: AbsTid, tgid: AbsTgid) !void {
    try mock_tgid_map.put(allocator, tid, tgid);
}
