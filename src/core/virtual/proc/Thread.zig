const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Namespace = @import("Namespace.zig");
const ThreadGroup = @import("ThreadGroup.zig");
const FdTable = @import("../fs/FdTable.zig");

// Thread IDs
pub const AbsTid = linux.pid_t;
pub const NsTid = linux.pid_t;
// ThreadGroup IDs
pub const AbsTgid = linux.pid_t;
pub const NsTgid = linux.pid_t;

const ThreadSet = std.AutoHashMapUnmanaged(*Self, void);
const ThreadList = std.ArrayList(*Self);

const Self = @This();

tid: AbsTid,
thread_group: *ThreadGroup,
namespace: *Namespace,
fd_table: *FdTable,
parent: ?*Self,
children: ThreadSet = .empty,

pub fn init(allocator: Allocator, tid: AbsTid, thread_group: ?*ThreadGroup, namespace: ?*Namespace, fd_table: ?*FdTable, parent: ?*Self) !*Self {
    // Create or use provided fd_table
    const fdt = fd_table orelse try FdTable.init(allocator);
    errdefer if (fd_table == null) fdt.unref();

    var thread_group_acquired: *ThreadGroup = undefined;
    var namespace_acquired: *Namespace = undefined;

    const self = try allocator.create(Self);
    errdefer allocator.destroy(self);

    // Either inherit ThreadGroup or make this Thread the leader of its own ThreadGroup
    if (thread_group) |tg| {
        // Thread inherits ThreadGroup - acquire it
        thread_group_acquired = tg.ref();
    } else {
        // Create this Thread as leader of a new ThreadGroup.
        // As leader, tgid == tid. Parent ThreadGroup becomes the new group's parent.
        const parent_thread_group = if (parent) |p| p.thread_group else null;
        thread_group_acquired = try ThreadGroup.init(
            allocator,
            tid,
            parent_thread_group,
        );
    }
    errdefer thread_group_acquired.unref();

    // Either inherit Namespace or make this Thread the root of its own namespace
    if (namespace) |ns| {
        // Thread inherits Namespace - acquire it
        namespace_acquired = ns.ref();
    } else {
        // Create this Thread as root in a new Namespace: either that of parent or its own
        const parent_namespace = if (parent) |p| p.namespace else null;
        namespace_acquired = try Namespace.init(
            allocator,
            parent_namespace,
        );
    }
    errdefer namespace_acquired.unref();

    // Initialize struct
    self.* = .{
        .tid = tid,
        .thread_group = thread_group_acquired,
        .namespace = namespace_acquired,
        .fd_table = fdt,
        .parent = parent,
    };

    // Register in own ThreadGroup and all ancestors
    try thread_group_acquired.registerThread(
        allocator,
        self,
    );
    errdefer thread_group_acquired.unregisterThread(self);

    // Register in own Namespace and all ancestors
    try namespace_acquired.registerThread(allocator, self);
    errdefer namespace_acquired.unregisterThread(self);

    return self;
}

/// Return the AbsTgid of a Thread
pub fn get_tgid(self: *Self) AbsTgid {
    return self.thread_group.tgid;
}

/// Whether this Thread represents a root process of its Namespace
pub fn isNamespaceRoot(self: *Self) bool {
    if (self.parent) |p| {
        return self.namespace != p.namespace; // crossed boundary
    }
    return true; // no parent = top-level root
}

pub fn deinit(self: *Self, allocator: Allocator) void {
    // unregister from its own ThreadGroup and Namespace, and those of all ancestors
    self.thread_group.unregisterThread(self);
    self.namespace.unregisterThread(self);

    // release references (will free if refcount hits 0)
    self.thread_group.unref();
    self.namespace.unref();
    self.fd_table.unref();

    self.children.deinit(allocator);
    allocator.destroy(self);
}

/// Walk up to Thread which is at the root of this Thread's Namespace
pub fn getNamespaceRoot(self: *Self) *Self {
    var current = self;
    while (current.parent) |p| {
        if (current.namespace != p.namespace) break;
        current = p;
    }
    return current;
}

pub fn initChild(self: *Self, allocator: Allocator, tid: AbsTid, namespace: ?*Namespace, fd_table: ?*FdTable) !*Self {
    const child = try Self.init(
        allocator,
        tid,
        null,
        namespace,
        fd_table,
        self,
    );
    errdefer child.deinit(allocator);

    try self.children.put(allocator, child, {});

    return child;
}

pub fn deinitChild(self: *Self, child: *Self, allocator: Allocator) void {
    self.removeChildLink(child);
    child.deinit(allocator);
}

pub fn removeChildLink(self: *Self, child: *Self) void {
    _ = self.children.remove(child);
}

/// Check if this Thread can see the target Thread.
pub fn canSee(self: *Self, target: *Self) bool {
    return self.namespace.contains(target);
}

/// Collect all descendant Threads (crosses namespace boundaries).
/// Used for thread exit to kill entire subtree.
/// Returned slice must be freed by caller.
pub fn collectSubtreeOwned(self: *Self, allocator: Allocator) ![]*Self {
    var accumulator = try ThreadList.initCapacity(allocator, 16);
    try self._collectSubtreeRecursive(&accumulator, allocator);
    return accumulator.toOwnedSlice(allocator);
}

fn _collectSubtreeRecursive(self: *Self, accumulator: *ThreadList, allocator: Allocator) !void {
    // Children first, then self - ensures namespace roots are deinitialized after their children
    var iter = self.children.iterator();
    while (iter.next()) |child_entry| {
        const child: *Self = child_entry.key_ptr.*;
        try child._collectSubtreeRecursive(accumulator, allocator);
    }
    try accumulator.append(allocator, self);
}
