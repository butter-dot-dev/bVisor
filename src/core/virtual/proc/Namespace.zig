const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Thread = @import("Thread.zig");

const proc_info = @import("../../deps/proc_info/proc_info.zig");
const readNsTids = proc_info.readNsTids;

// Thread IDs
pub const AbsTid = Thread.AbsTid;
pub const NsTid = Thread.NsTid;
// ThreadGroup IDs
pub const AbsTgid = Thread.AbsTgid;
pub const NsTgid = Thread.NsTgid;

const ThreadMap = std.AutoHashMapUnmanaged(NsTid, *Thread);

const Self = @This();

/// Namespaces are refcounted and shared between Threads.
/// Used for visibility filtering - Thread (Groups) can only see other Thread (Groups)
/// in the same Namespace or descendent Namespace.
const AtomicUsize = std.atomic.Value(usize);

ref_count: AtomicUsize = undefined,
allocator: Allocator,
parent: ?*Self,
threads: ThreadMap = .empty,

pub fn init(allocator: Allocator, parent: ?*Self) !*Self {
    const self = try allocator.create(Self);
    self.* = .{
        .ref_count = AtomicUsize.init(1),
        .allocator = allocator,
        // TODO: check consistency of calling p.ref() here versus elsewhere
        .parent = if (parent) |p| p.ref() else null,
    };
    return self;
}

pub fn ref(self: *Self) *Self {
    const prev = self.ref_count.fetchAdd(1, .monotonic);
    _ = prev;
    return self;
}

pub fn unref(self: *Self) void {
    // .acq_rel required to ensure full memory syncronization before deinit
    const prev = self.ref_count.fetchSub(1, .acq_rel);
    if (prev == 1) {
        if (self.parent) |p| p.unref();
        self.threads.deinit(self.allocator);
        self.allocator.destroy(self);
    }
}

/// Register a Thread in this Namespace and all ancestor Namespaces.
pub fn registerThread(self: *Self, allocator: Allocator, thread: *Thread) !void {
    // Prepare buffer for namespace TID chain
    var nstid_buf: [128]NsTid = undefined;

    // Read of tid and tgid from the Thread
    const tgid = thread.get_tgid();
    const tid = thread.tid;

    // Read NSpid (NsTid) chains from kernel
    const nstids = try readNsTids(tgid, tid, &nstid_buf);

    // Count namespace depth (self + ancestors)
    var ns_depth: usize = 1;
    var ns = self.parent;
    while (ns) |p| : (ns = p.parent) {
        ns_depth += 1;
    }

    // TID length should match namespace depth
    if (nstids.len != ns_depth) {
        return error.NamespaceDepthMismatch;
    }

    // Register in own Namespace
    try self.threads.put(allocator, nstids[nstids.len - 1], thread);

    // Register in all ancestor Namespaces (walking backwards through nstids)
    // Only enter loop if there are ancestors (nstids.len > 1)
    if (nstids.len > 1) {
        var ancestor = self.parent;
        var idx: usize = nstids.len - 2; // Start from second-to-last
        while (ancestor) |anc_ns| {
            try anc_ns.threads.put(allocator, nstids[idx], thread);
            ancestor = anc_ns.parent;
            if (idx == 0) break;
            idx -= 1;
        }
    }
}

/// Unregister a Thread from this Namespace and all ancestor Namespaces.
pub fn unregisterThread(self: *Self, thread: *Thread) void {
    // Find and remove from own namespace
    if (self.getNsTid(thread)) |ns_tid| {
        _ = self.threads.remove(ns_tid);
    }

    // Remove from all ancestor Namespaces
    var ancestor = self.parent;
    while (ancestor) |ns| {
        if (ns.getNsTid(thread)) |ns_tid| {
            _ = ns.threads.remove(ns_tid);
        }
        ancestor = ns.parent;
    }
}

/// Check if a Thread is visible in this Namespace.
pub fn contains(self: *Self, thread: *Thread) bool {
    return self.getNsTid(thread) != null;
}

/// Reverse lookup in ThreadMap for NsTid of a Thread
pub fn getNsTid(self: *Self, thread: *Thread) ?NsTid {
    var iterator = self.threads.iterator();
    while (iterator.next()) |entry| {
        const key = entry.key_ptr;
        const val = entry.value_ptr;
        if (val.* == thread) return key.*;
    }
    return null;
}

const testing = std.testing;

test "Namespace refcount - ref increases count" {
    const allocator = testing.allocator;
    const ns1 = try Self.init(allocator, null);
    defer ns1.unref();

    try testing.expectEqual(1, ns1.ref_count.load(.unordered));

    const ns2 = ns1.ref();
    try testing.expectEqual(2, ns1.ref_count.load(.unordered));
    try testing.expect(ns1 == ns2);

    ns2.unref();
    try testing.expectEqual(1, ns1.ref_count.load(.unordered));
}

test "Namespace refcount - unref at zero frees" {
    const allocator = testing.allocator;
    const ns = try Self.init(allocator, null);
    ns.unref();
    // No leak detected by testing.allocator
}

test "Namespace refcount - child holds parent" {
    const allocator = testing.allocator;
    const parent = try Self.init(allocator, null);

    const child = try Self.init(allocator, parent);
    try testing.expectEqual(2, parent.ref_count.raw); // original + child reference

    parent.unref(); // refcount -> 1
    try testing.expectEqual(1, parent.ref_count.raw);

    child.unref(); // child frees, then parent refcount -> 0, parent frees
    // No leaks detected by testing.allocator
}
