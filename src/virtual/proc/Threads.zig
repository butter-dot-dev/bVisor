const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const deps = @import("../../deps/deps.zig");

const proc_info = deps.proc_info;
pub const detectCloneFlags = proc_info.detectCloneFlags;
pub const getStatus = proc_info.getStatus;
pub const listTids = proc_info.listTids;
pub const listTgids = proc_info.listTgids;

pub const Thread = @import("Thread.zig");
// Thread IDs
pub const AbsTid = Thread.AbsTid;
pub const NsTid = Thread.NsTid;
// ThreadGroup IDs
pub const AbsTgid = Thread.AbsTgid;
pub const NsTgid = Thread.NsTgid;

pub const ThreadGroup = @import("ThreadGroup.zig");
pub const Namespace = @import("Namespace.zig");
pub const FdTable = @import("../fs/FdTable.zig");
pub const ThreadStatus = @import("ThreadStatus.zig");

const ThreadLookup = std.AutoHashMapUnmanaged(AbsTid, *Thread);

const Self = @This();

pub const CloneFlags = struct {
    raw: u64 = 0,

    /// Returns error if unsupported namespace flags are set
    pub fn checkSupported(self: CloneFlags) !void {
        if (self.raw & linux.CLONE.NEWUSER != 0) return error.UnsupportedCloneFlag;
        if (self.raw & linux.CLONE.NEWNET != 0) return error.UnsupportedCloneFlag;
        if (self.raw & linux.CLONE.NEWNS != 0) return error.UnsupportedCloneFlag;
    }

    pub fn from(raw: u64) CloneFlags {
        return .{ .raw = raw };
    }

    pub fn createTidNamespace(self: CloneFlags) bool {
        return self.raw & linux.CLONE.NEWPID != 0;
    }

    pub fn isThread(self: CloneFlags) bool {
        return self.raw & linux.CLONE.THREAD != 0;
    }

    pub fn shareParent(self: CloneFlags) bool {
        return self.raw & linux.CLONE.PARENT != 0;
    }

    pub fn shareFiles(self: CloneFlags) bool {
        return self.raw & linux.CLONE.FILES != 0;
    }
};

/// Tracks kernel to virtual mappings, handling parent/child relationships.
/// Note: we don't currently re-parent orphaned children to init; killing a
/// process kills its entire subtree, including any nested Namespaces.
allocator: Allocator,

// Flat list of mappings from kernel's TID to Thread
// Owns underlying Thread-s
lookup: ThreadLookup = .empty,

pub fn init(allocator: Allocator) Self {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *Self) void {
    var iter = self.lookup.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.*.parent == null) {
            const subtree = entry.value_ptr.*.collectSubtreeOwned(self.allocator) catch break;
            defer self.allocator.free(subtree);
            for (subtree) |thread| {
                thread.deinit(self.allocator);
            }
            break;
        }
    }
    self.lookup.deinit(self.allocator);
}

/// Get the Thread of this AbsTid from self.lookup
///
/// This is a hotpath for most syscalls, so we try to avoid syncing with the kernel unless necessary.
/// Syncs happen only if the initial lookup fails.
pub fn get(self: *Self, tid: AbsTid) !*Thread {
    // Initial lookup
    if (self.lookup.get(tid)) |thread| return thread;

    // Initial lookup failed, try lazy register
    try self.syncNewThreads();
    if (self.lookup.get(tid)) |thread| return thread;

    // Still not found, give up
    return error.ThreadNotRegistered;
}

/// Get Thread from an NsTid via a reference Thread's Namespace
///
/// This is a hotpath for any NsTid, targeting syscalls like kill and waitpid.
/// So, syncs with kernel only happen if initial lookup fails.
pub fn getNamespaced(
    self: *Self,
    ref_thread: *Thread,
    nstid: NsTid,
) !*Thread {
    // Initial lookup
    if (ref_thread.namespace.threads.get(nstid)) |thread| return thread;

    // Initial lookup failed, try lazy register
    try self.syncNewThreads();
    if (ref_thread.namespace.threads.get(nstid)) |thread| return thread;

    // Still not found, give up
    return error.ThreadNotRegistered;
}

/// Recursive lazy registration of Thread-s if necessary
fn ensureRegistered(
    self: *Self,
    status_map: *std.AutoHashMap(AbsTid, ThreadStatus),
    tid: AbsTid,
) !void {
    // If already registered, done
    if (self.lookup.contains(tid)) return;

    // Get cached status (ptid and namespace info)
    const status = status_map.get(tid) orelse return error.ThreadNotInKernel;
    const ptid = status.ptid;

    // Ensure parent is registered first (recursive call)
    if (!self.lookup.contains(ptid)) {
        // Stop recursion if we've reached init or outside sandbox
        if (ptid <= 1) return error.ThreadNotInSandbox;
        try self.ensureRegistered(status_map, ptid);
    }

    // Get the parent Thread (must be registered now)
    const parent = self.lookup.get(ptid) orelse return error.ParentNotRegistered;

    // Detect clone flags and register this Thread
    const flags = detectCloneFlags(ptid, tid);
    _ = try self.registerChild(parent, tid, flags);
}

/// Confer with the kernel to check for any guest Thread-s
/// which might need to be lazily added.
///
/// This scans /proc/... once to collect status for all Thread-s.
/// Then, recursively registers any missing Thread-s using the cached status data
pub fn syncNewThreads(self: *Self) !void {
    var status_map = std.AutoHashMap(AbsTid, ThreadStatus).init(self.allocator);
    defer status_map.deinit();

    // Scan /proc and collect statuses
    const tids = try listTids(self.allocator);
    defer self.allocator.free(tids);

    for (tids) |tid| {
        const status = getStatus(tid) catch continue;
        try status_map.put(tid, status);
    }

    // Try to register all TIDs (ancestors before descendants)
    var iter = status_map.keyIterator();
    while (iter.next()) |tid_ptr| {
        self.ensureRegistered(&status_map, tid_ptr.*) catch continue;
    }

    // TODO?: processes that no longer exist in the kernel should be deleted
    // Would involve calling handleThreadExit() on whichever TIDs have disappeared
}

/// Register the initial sandbox root Thread
///
/// This creates new a ThreadGroup, Namespace, and FdTable, too
pub fn handleInitialThread(self: *Self, tid: AbsTid) !void {
    if (self.lookup.count() != 0) return error.InitialThreadExists;

    // Passing null thread_group/namespace/fd_table creates new ones
    const root_thread = try Thread.init(
        self.allocator,
        tid,
        null,
        null,
        null,
        null,
    );
    errdefer root_thread.deinit(self.allocator);

    try self.lookup.put(self.allocator, tid, root_thread);
}

/// Register a child Thread with given parent and flags
pub fn registerChild(
    self: *Self,
    parent: *Thread,
    child_tid: AbsTid,
    clone_flags: CloneFlags,
) !*Thread {
    try clone_flags.checkSupported();

    // CLONE_NEWPID creates a new TID namespace; otherwise inherit parent's
    const namespace: ?*Namespace = if (clone_flags.createTidNamespace())
        null // triggers new Namespace creation in initChild
    else
        parent.namespace;

    // CLONE_FILES shares the FdTable; otherwise clone it
    const fd_table: *FdTable = if (clone_flags.shareFiles())
        parent.fd_table.ref()
    else
        try parent.fd_table.clone(self.allocator);
    errdefer fd_table.unref();

    const child = try parent.initChild(self.allocator, child_tid, namespace, fd_table);
    errdefer parent.deinitChild(child, self.allocator);

    try self.lookup.put(self.allocator, child_tid, child);

    return child;
}

pub fn handleThreadExit(self: *Self, tid: AbsTid) !void {
    const target_thread = self.lookup.get(tid) orelse return;

    // remove target from parent's children
    if (target_thread.parent) |parent| {
        parent.removeChildLink(target_thread);
    }

    // collect all descendant Thread-s (crosses namespace boundaries)
    const descendant_threads = try target_thread.collectSubtreeOwned(self.allocator);
    defer self.allocator.free(descendant_threads);

    // remove from lookup table and deinit each Thread
    for (descendant_threads) |thread| {
        _ = self.lookup.remove(thread.tid);
        thread.deinit(self.allocator);
    }
}

// ============================================================================
// Tests
// ============================================================================

test "state is correct after initial thread" {
    var v_threads = Self.init(std.testing.allocator);
    defer v_threads.deinit();
    try std.testing.expect(v_threads.lookup.count() == 0);

    const init_tid = 22;
    try v_threads.handleInitialThread(init_tid);
    try std.testing.expectEqual(1, v_threads.lookup.count());
    const thread = v_threads.lookup.get(init_tid).?;
    try std.testing.expectEqual(init_tid, thread.tid);
    try std.testing.expectEqual(null, thread.parent);
    try std.testing.expectEqual(0, thread.children.count());
    try std.testing.expect(thread.isNamespaceRoot());
}

test "basic tree operations work - add, kill" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    try std.testing.expectEqual(0, v_threads.lookup.count());

    // create threads of this layout
    // a
    // - b
    // - c
    //   - d

    const a_tid = 33;
    try v_threads.handleInitialThread(a_tid);
    try std.testing.expectEqual(1, v_threads.lookup.count());

    const b_tid = 44;
    const a_thread = v_threads.lookup.get(a_tid).?;
    _ = try v_threads.registerChild(a_thread, b_tid, CloneFlags.from(0));
    try std.testing.expectEqual(2, v_threads.lookup.count());
    try std.testing.expectEqual(1, v_threads.lookup.get(a_tid).?.children.count());
    try std.testing.expectEqual(0, v_threads.lookup.get(b_tid).?.children.count());

    const c_tid = 55;
    _ = try v_threads.registerChild(a_thread, c_tid, CloneFlags.from(0));
    try std.testing.expectEqual(3, v_threads.lookup.count());
    try std.testing.expectEqual(2, v_threads.lookup.get(a_tid).?.children.count());
    try std.testing.expectEqual(0, v_threads.lookup.get(c_tid).?.children.count());
    try std.testing.expectEqual(0, v_threads.lookup.get(b_tid).?.children.count());

    const d_tid = 66;
    const c_thread = v_threads.lookup.get(c_tid).?;
    _ = try v_threads.registerChild(c_thread, d_tid, CloneFlags.from(0));
    try std.testing.expectEqual(4, v_threads.lookup.count());
    try std.testing.expectEqual(2, v_threads.lookup.get(a_tid).?.children.count());
    try std.testing.expectEqual(1, v_threads.lookup.get(c_tid).?.children.count());
    try std.testing.expectEqual(0, v_threads.lookup.get(b_tid).?.children.count());
    try std.testing.expectEqual(0, v_threads.lookup.get(d_tid).?.children.count());

    // shrink to
    // a
    // - c
    //   - d
    try v_threads.handleThreadExit(b_tid);
    try std.testing.expectEqual(3, v_threads.lookup.count());
    try std.testing.expectEqual(1, v_threads.lookup.get(a_tid).?.children.count());
    try std.testing.expectEqual(1, v_threads.lookup.get(c_tid).?.children.count());
    try std.testing.expectEqual(0, v_threads.lookup.get(d_tid).?.children.count());
    try std.testing.expectEqual(null, v_threads.lookup.get(b_tid));

    // verify namespace visibility via namespace.threads
    try std.testing.expectEqual(3, v_threads.lookup.get(a_tid).?.namespace.threads.count());

    // re-add b, should work
    const b_tid_2 = 45;
    _ = try v_threads.registerChild(v_threads.lookup.get(a_tid).?, b_tid_2, CloneFlags.from(0));

    try std.testing.expectEqual(4, v_threads.lookup.get(a_tid).?.namespace.threads.count());

    // clear whole tree
    try v_threads.handleThreadExit(a_tid);
    try std.testing.expectEqual(0, v_threads.lookup.count());
    try std.testing.expectEqual(null, v_threads.lookup.get(a_tid));
    try std.testing.expectEqual(null, v_threads.lookup.get(b_tid));
    try std.testing.expectEqual(null, v_threads.lookup.get(b_tid_2));
    try std.testing.expectEqual(null, v_threads.lookup.get(c_tid));
    try std.testing.expectEqual(null, v_threads.lookup.get(d_tid));
}

test "handle_initial_thread fails if already registered" {
    var v_threads = Self.init(std.testing.allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    try std.testing.expectError(error.InitialThreadExists, v_threads.handleInitialThread(200));
}

test "handle_thread_exit on non-existent tid is no-op" {
    var v_threads = Self.init(std.testing.allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    try v_threads.handleThreadExit(999);
    try std.testing.expectEqual(1, v_threads.lookup.count());
}

test "kill intermediate node removes subtree but preserves siblings" {
    var v_threads = Self.init(std.testing.allocator);
    defer v_threads.deinit();

    // a
    // - b
    // - c
    //   - d
    const a_tid = 10;
    try v_threads.handleInitialThread(a_tid);
    const a_thread = v_threads.lookup.get(a_tid).?;

    const b_tid = 20;
    _ = try v_threads.registerChild(a_thread, b_tid, CloneFlags.from(0));
    const c_tid = 30;
    _ = try v_threads.registerChild(a_thread, c_tid, CloneFlags.from(0));
    const c_thread = v_threads.lookup.get(c_tid).?;
    const d_tid = 40;
    _ = try v_threads.registerChild(c_thread, d_tid, CloneFlags.from(0));

    try std.testing.expectEqual(4, v_threads.lookup.count());

    // kill c (intermediate) - should also remove d but preserve a and b
    try v_threads.handleThreadExit(c_tid);

    try std.testing.expectEqual(2, v_threads.lookup.count());
    try std.testing.expect(v_threads.lookup.get(a_tid) != null);
    try std.testing.expect(v_threads.lookup.get(b_tid) != null);
    try std.testing.expectEqual(null, v_threads.lookup.get(c_tid));
    try std.testing.expectEqual(null, v_threads.lookup.get(d_tid));
}

test "namespace visibility on single node" {
    var v_threads = Self.init(std.testing.allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const thread = v_threads.lookup.get(100).?;

    try std.testing.expectEqual(1, thread.namespace.threads.count());
    try std.testing.expect(thread.namespace.contains(thread));
}

test "deep nesting" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();

    // chain: a -> b -> c -> d -> e
    var tids = [_]AbsTid{ 10, 20, 30, 40, 50 };

    try v_threads.handleInitialThread(tids[0]);
    for (1..5) |i| {
        const parent = v_threads.lookup.get(tids[i - 1]).?;
        _ = try v_threads.registerChild(parent, tids[i], CloneFlags.from(0));
    }

    try std.testing.expectEqual(5, v_threads.lookup.count());

    // kill middle (c) - should remove c, d, e
    try v_threads.handleThreadExit(tids[2]);
    try std.testing.expectEqual(2, v_threads.lookup.count());
}

test "wide tree with many siblings" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();

    const parent_tid = 100;
    try v_threads.handleInitialThread(parent_tid);
    const parent = v_threads.lookup.get(parent_tid).?;

    // add 10 children
    for (1..11) |i| {
        const child_tid: AbsTid = @intCast(100 + i);
        _ = try v_threads.registerChild(parent, child_tid, CloneFlags.from(0));
    }

    try std.testing.expectEqual(11, v_threads.lookup.count());
    try std.testing.expectEqual(10, v_threads.lookup.get(parent_tid).?.children.count());
}

test "nested namespace - visibility rules" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    // Create structure:
    // ns1: A -> B (B is ns2 root with CLONE_NEWPID)
    //           ns2: B -> C

    const a_tid = 100;
    try v_threads.handleInitialThread(a_tid);
    const a_thread = v_threads.lookup.get(a_tid).?;

    // B: child of A but root of new namespace (CLONE_NEWPID)
    // B is TID 1 in its own namespace, 200 from root namespace view
    const b_tid = 200;
    const b_nstids = [_]NsTid{ 200, 1 };
    try proc_info.testing.setupNsTids(allocator, b_tid, &b_nstids);
    _ = try v_threads.registerChild(a_thread, b_tid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_thread = v_threads.lookup.get(b_tid).?;

    try std.testing.expect(b_thread.isNamespaceRoot());
    try std.testing.expect(a_thread.namespace != b_thread.namespace);

    // C: child of B in ns2
    // C is TID 2 in B's namespace, 300 from root namespace view
    const c_tid = 300;
    const c_nstids = [_]NsTid{ 300, 2 };
    try proc_info.testing.setupNsTids(allocator, c_tid, &c_nstids);
    _ = try v_threads.registerChild(b_thread, c_tid, CloneFlags.from(0));
    const c_thread = v_threads.lookup.get(c_tid).?;
    try std.testing.expect(b_thread.namespace == c_thread.namespace);

    // Parent namespace (ns1) can see all threads including those in child namespaces
    // This is the correct Linux behavior: parent namespaces have visibility into children
    try std.testing.expectEqual(3, a_thread.namespace.threads.count());
    try std.testing.expect(a_thread.canSee(a_thread));
    try std.testing.expect(a_thread.canSee(b_thread));
    try std.testing.expect(a_thread.canSee(c_thread));

    // Child namespace (ns2) can only see threads in its own namespace
    try std.testing.expectEqual(2, b_thread.namespace.threads.count());
    try std.testing.expect(b_thread.canSee(b_thread));
    try std.testing.expect(b_thread.canSee(c_thread));
    try std.testing.expect(!b_thread.canSee(a_thread)); // cannot see parent namespace

    // C has same visibility as B (same namespace)
    try std.testing.expectEqual(2, c_thread.namespace.threads.count());
    try std.testing.expect(c_thread.canSee(b_thread));
    try std.testing.expect(!c_thread.canSee(a_thread));
}

test "nested namespace - killing parent kills nested namespace" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    // ns1: A -> B(ns2 root) -> C
    const a_tid = 100;
    try v_threads.handleInitialThread(a_tid);
    const a_thread = v_threads.lookup.get(a_tid).?;

    // B: namespace root, TID 1 in its namespace
    const b_tid = 200;
    const b_nstids = [_]NsTid{ 200, 1 };
    try proc_info.testing.setupNsTids(allocator, b_tid, &b_nstids);
    _ = try v_threads.registerChild(a_thread, b_tid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_thread = v_threads.lookup.get(b_tid).?;

    // C: TID 2 in B's namespace
    const c_tid = 300;
    const c_nstids = [_]NsTid{ 300, 2 };
    try proc_info.testing.setupNsTids(allocator, c_tid, &c_nstids);
    _ = try v_threads.registerChild(b_thread, c_tid, CloneFlags.from(0));

    try std.testing.expectEqual(3, v_threads.lookup.count());

    // Kill B - should also kill C (entire subtree, crossing namespace boundary)
    try v_threads.handleThreadExit(b_tid);

    try std.testing.expectEqual(1, v_threads.lookup.count());
    try std.testing.expect(v_threads.lookup.get(a_tid) != null);
    try std.testing.expectEqual(null, v_threads.lookup.get(b_tid));
    try std.testing.expectEqual(null, v_threads.lookup.get(c_tid));
}

test "nested namespace - killing grandparent kills all" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    // ns1: A -> B (ns2 root) -> C -> D (ns3 root) -> E
    const a_tid = 100;
    try v_threads.handleInitialThread(a_tid);
    const a_thread = v_threads.lookup.get(a_tid).?;

    // B: ns2 root, depth 2
    const b_tid = 200;
    const b_nstids = [_]NsTid{ 200, 1 };
    try proc_info.testing.setupNsTids(allocator, b_tid, &b_nstids);
    _ = try v_threads.registerChild(a_thread, b_tid, CloneFlags.from(linux.CLONE.NEWPID));
    const b_thread = v_threads.lookup.get(b_tid).?;

    // C: in ns2, depth 2
    const c_tid = 300;
    const c_nstids = [_]NsTid{ 300, 2 };
    try proc_info.testing.setupNsTids(allocator, c_tid, &c_nstids);
    _ = try v_threads.registerChild(b_thread, c_tid, CloneFlags.from(0));
    const c_thread = v_threads.lookup.get(c_tid).?;

    // D: ns3 root, depth 3
    const d_tid = 400;
    const d_nstids = [_]NsTid{ 400, 3, 1 };
    try proc_info.testing.setupNsTids(allocator, d_tid, &d_nstids);
    _ = try v_threads.registerChild(c_thread, d_tid, CloneFlags.from(linux.CLONE.NEWPID));
    const d_thread = v_threads.lookup.get(d_tid).?;

    // E: in ns3, depth 3
    const e_tid = 500;
    const e_nstids = [_]NsTid{ 500, 4, 2 };
    try proc_info.testing.setupNsTids(allocator, e_tid, &e_nstids);
    _ = try v_threads.registerChild(d_thread, e_tid, CloneFlags.from(0));

    try std.testing.expectEqual(5, v_threads.lookup.count());

    // Kill A - should kill everything
    try v_threads.handleThreadExit(a_tid);
    try std.testing.expectEqual(0, v_threads.lookup.count());
}

test "tid is stored correctly" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();

    const a_tid = 12345;
    try v_threads.handleInitialThread(a_tid);
    const a_thread = v_threads.lookup.get(a_tid).?;
    try std.testing.expectEqual(a_tid, a_thread.tid);

    const b_tid = 67890;
    _ = try v_threads.registerChild(a_thread, b_tid, CloneFlags.from(0));
    const b_thread = v_threads.lookup.get(b_tid).?;
    try std.testing.expectEqual(b_tid, b_thread.tid);
}

test "can_see - same namespace" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);
    const a = v_threads.lookup.get(100).?;
    _ = try v_threads.registerChild(a, 200, CloneFlags.from(0));
    const b = v_threads.lookup.get(200).?;

    try std.testing.expect(a.canSee(b));
    try std.testing.expect(b.canSee(a));
}

test "can_see - child namespace cannot see parent-only threads" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    try v_threads.handleInitialThread(100);
    const a = v_threads.lookup.get(100).?;

    // B is in new namespace (depth 2)
    const b_nstids = [_]NsTid{ 200, 1 };
    try proc_info.testing.setupNsTids(allocator, 200, &b_nstids);
    _ = try v_threads.registerChild(a, 200, CloneFlags.from(linux.CLONE.NEWPID));
    const b = v_threads.lookup.get(200).?;

    // A can see B (B is registered in parent namespace too)
    try std.testing.expect(a.canSee(b));
    // B cannot see A (A is only in parent namespace)
    try std.testing.expect(!b.canSee(a));
}

test "deep namespace hierarchy (10 levels)" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    const DEPTH = 10;

    // Create a chain: ns0 -> ns1 -> ns2 -> ... -> ns9
    // Each level has one thread that is the root of a new namespace
    var tids: [DEPTH]AbsTid = undefined;
    var threads: [DEPTH]*Thread = undefined;

    // Root thread (depth 1)
    tids[0] = 1000;
    try v_threads.handleInitialThread(tids[0]);
    threads[0] = v_threads.lookup.get(tids[0]).?;

    // Create nested namespaces
    for (1..DEPTH) |i| {
        tids[i] = @intCast(1000 + i);

        // Build NStid array: [tid_as_seen_from_ns0, ..., tid_as_seen_from_own_ns]
        // For depth i+1, we need i+1 entries
        var nstid_buf: [DEPTH]NsTid = undefined;
        for (0..i + 1) |j| {
            // From ancestor namespace j's view, this thread has a certain TID
            // For simplicity: from ns_j, the TID is (1000 + i) - j
            // This simulates different TIDs in different namespaces
            nstid_buf[j] = @intCast(tids[i] - @as(AbsTid, @intCast(j)));
        }
        try proc_info.testing.setupNsTids(allocator, tids[i], nstid_buf[0 .. i + 1]);

        _ = try v_threads.registerChild(threads[i - 1], tids[i], CloneFlags.from(linux.CLONE.NEWPID));
        threads[i] = v_threads.lookup.get(tids[i]).?;

        // Verify namespace is different from parent
        try std.testing.expect(threads[i].namespace != threads[i - 1].namespace);
        try std.testing.expect(threads[i].isNamespaceRoot());
    }

    // Verify visibility rules:
    // Root namespace (ns0) should see ALL threads
    try std.testing.expectEqual(DEPTH, threads[0].namespace.threads.count());

    // Each namespace should see fewer threads as we go deeper
    for (1..DEPTH) |i| {
        const expected_visible = DEPTH - i;
        try std.testing.expectEqual(expected_visible, threads[i].namespace.threads.count());

        // Can see self and descendants
        for (i..DEPTH) |j| {
            try std.testing.expect(threads[i].canSee(threads[j]));
        }
        // Cannot see ancestors
        for (0..i) |j| {
            try std.testing.expect(!threads[i].canSee(threads[j]));
        }
    }

    // Kill middle of chain (ns4) - should kill ns4 through ns9
    try v_threads.handleThreadExit(tids[4]);

    // Only ns0-ns3 remain
    try std.testing.expectEqual(4, v_threads.lookup.count());
    for (0..4) |i| {
        try std.testing.expect(v_threads.lookup.get(tids[i]) != null);
    }
    for (4..DEPTH) |i| {
        try std.testing.expect(v_threads.lookup.get(tids[i]) == null);
    }
}

test "wide tree with many threads per namespace" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    const CHILDREN_PER_LEVEL = 20;

    // Root thread
    const root_tid: AbsTid = 1;
    try v_threads.handleInitialThread(root_tid);
    const root = v_threads.lookup.get(root_tid).?;

    var total_threads: usize = 1; // root

    // Level 1: 20 children of root (same namespace)
    var level1_threads: [CHILDREN_PER_LEVEL]*Thread = undefined;
    for (0..CHILDREN_PER_LEVEL) |i| {
        const tid: AbsTid = @intCast(100 + i);
        _ = try v_threads.registerChild(root, tid, CloneFlags.from(0));
        level1_threads[i] = v_threads.lookup.get(tid).?;
        total_threads += 1;
    }

    // Level 2: Each level1 thread has 20 children (same namespace)
    var level2_threads: [CHILDREN_PER_LEVEL][CHILDREN_PER_LEVEL]*Thread = undefined;
    for (0..CHILDREN_PER_LEVEL) |i| {
        for (0..CHILDREN_PER_LEVEL) |j| {
            const tid: AbsTid = @intCast(1000 + i * 100 + j);
            _ = try v_threads.registerChild(level1_threads[i], tid, CloneFlags.from(0));
            level2_threads[i][j] = v_threads.lookup.get(tid).?;
            total_threads += 1;
        }
    }

    // Verify total count: 1 + 20 + 20*20 = 421
    const expected_total = 1 + CHILDREN_PER_LEVEL + CHILDREN_PER_LEVEL * CHILDREN_PER_LEVEL;
    try std.testing.expectEqual(expected_total, total_threads);
    try std.testing.expectEqual(expected_total, v_threads.lookup.count());

    // All in same namespace, so everyone should see everyone
    try std.testing.expectEqual(expected_total, root.namespace.threads.count());

    // Kill one level1 thread, which should kill it and its 20 children
    try v_threads.handleThreadExit(level1_threads[5].tid);
    try std.testing.expectEqual(expected_total - 1 - CHILDREN_PER_LEVEL, v_threads.lookup.count());
}

test "mixed namespaces: some shared, some isolated" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    // Structure:
    // ns0: root(1) -> A(10), B(20), C(30)
    //                  |       |
    //                  v       v
    //          ns1: A1(11) -> A2(12)    ns2: B1(21) -> B2(22)
    //                                          |
    //                                          v
    //                                  ns3: B1a(211)

    // Root namespace
    try v_threads.handleInitialThread(1);
    const root = v_threads.lookup.get(1).?;

    // A, B, C in root namespace
    _ = try v_threads.registerChild(root, 10, CloneFlags.from(0));
    const thread_a = v_threads.lookup.get(10).?;
    _ = try v_threads.registerChild(root, 20, CloneFlags.from(0));
    const thread_b = v_threads.lookup.get(20).?;
    _ = try v_threads.registerChild(root, 30, CloneFlags.from(0));
    const thread_c = v_threads.lookup.get(30).?;

    // ns1: A's children in new namespace
    const a1_nstids = [_]NsTid{ 11, 1 };
    try proc_info.testing.setupNsTids(allocator, 11, &a1_nstids);
    _ = try v_threads.registerChild(thread_a, 11, CloneFlags.from(linux.CLONE.NEWPID));
    const thread_a1 = v_threads.lookup.get(11).?;

    const a2_nstids = [_]NsTid{ 12, 2 };
    try proc_info.testing.setupNsTids(allocator, 12, &a2_nstids);
    _ = try v_threads.registerChild(thread_a1, 12, CloneFlags.from(0));
    const thread_a2 = v_threads.lookup.get(12).?;

    // ns2: B's children in new namespace
    const b1_nstids = [_]NsTid{ 21, 1 };
    try proc_info.testing.setupNsTids(allocator, 21, &b1_nstids);
    _ = try v_threads.registerChild(thread_b, 21, CloneFlags.from(linux.CLONE.NEWPID));
    const thread_b1 = v_threads.lookup.get(21).?;

    const b2_nstids = [_]NsTid{ 22, 2 };
    try proc_info.testing.setupNsTids(allocator, 22, &b2_nstids);
    _ = try v_threads.registerChild(thread_b1, 22, CloneFlags.from(0));

    // ns3: nested inside ns2
    const b1a_nstids = [_]NsTid{ 211, 3, 1 }; // seen as 211 from ns0, 3 from ns2, 1 from ns3
    try proc_info.testing.setupNsTids(allocator, 211, &b1a_nstids);
    _ = try v_threads.registerChild(thread_b1, 211, CloneFlags.from(linux.CLONE.NEWPID));
    const thread_b1a = v_threads.lookup.get(211).?;

    // Total: 9 threads (root, A, B, C, A1, A2, B1, B2, B1a)
    try std.testing.expectEqual(9, v_threads.lookup.count());

    // Verify namespace counts:
    // ns0 (root): sees all 9
    try std.testing.expectEqual(9, root.namespace.threads.count());

    // ns1 (A's namespace): sees A1, A2 = 2
    try std.testing.expectEqual(2, thread_a1.namespace.threads.count());
    try std.testing.expect(thread_a1.namespace == thread_a2.namespace);

    // ns2 (B's namespace): sees B1, B2, B1a = 3
    try std.testing.expectEqual(3, thread_b1.namespace.threads.count());

    // ns3 (B1a's namespace): sees only B1a = 1
    try std.testing.expectEqual(1, thread_b1a.namespace.threads.count());

    // Cross-namespace visibility
    // Root can see everything
    try std.testing.expect(root.canSee(thread_a));
    try std.testing.expect(root.canSee(thread_a1));
    try std.testing.expect(root.canSee(thread_b1a));

    // A1 cannot see root or B's subtree
    try std.testing.expect(!thread_a1.canSee(root));
    try std.testing.expect(!thread_a1.canSee(thread_b));
    try std.testing.expect(!thread_a1.canSee(thread_b1));

    // B1 can see B1a (descendant namespace) but not A1 (sibling namespace)
    try std.testing.expect(thread_b1.canSee(thread_b1a));
    try std.testing.expect(!thread_b1.canSee(thread_a1));

    // C is isolated, so shares root namespace but has no children
    try std.testing.expect(thread_c.canSee(root));
    try std.testing.expect(thread_c.canSee(thread_a));
    try std.testing.expect(thread_c.canSee(thread_a1));

    // Kill A, which should kill A, A1, A2 (entire subtree), showing 9 - 3 = 6
    try v_threads.handleThreadExit(10);
    try std.testing.expectEqual(6, v_threads.lookup.count());
    try std.testing.expect(v_threads.lookup.get(10) == null);
    try std.testing.expect(v_threads.lookup.get(11) == null);
    try std.testing.expect(v_threads.lookup.get(12) == null);

    // Kill B1, which should kill B1, B2, B1a, giving 6 - 3 = 3
    try v_threads.handleThreadExit(21);
    try std.testing.expectEqual(3, v_threads.lookup.count());

    // Only root, B, C should remain
    try std.testing.expect(v_threads.lookup.get(1) != null);
    try std.testing.expect(v_threads.lookup.get(20) != null);
    try std.testing.expect(v_threads.lookup.get(30) != null);
}

test "stress: verify NsTid mapping correctness across namespaces" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    // Create: root(100) -> child(200) in new namespace
    // NStid for child: [200, 1] meaning:
    //   - From root namespace: NsTid = 200
    //   - From child's own namespace: NsTid = 1

    try v_threads.handleInitialThread(100);
    const root = v_threads.lookup.get(100).?;

    const child_nstids = [_]NsTid{ 200, 1 };
    try proc_info.testing.setupNsTids(allocator, 200, &child_nstids);
    _ = try v_threads.registerChild(root, 200, CloneFlags.from(linux.CLONE.NEWPID));
    const child = v_threads.lookup.get(200).?;

    // Verify NsTid from each namespace's perspective
    // From root namespace, child's NsTid should be 200
    const child_nstid_from_root = root.namespace.getNsTid(child);
    try std.testing.expectEqual(@as(?NsTid, 200), child_nstid_from_root);

    // From child's namespace, child's NsTid should be 1
    const child_nstid_from_self = child.namespace.getNsTid(child);
    try std.testing.expectEqual(@as(?NsTid, 1), child_nstid_from_self);

    // Root should not be visible from child's namespace
    const root_nstid_from_child = child.namespace.getNsTid(root);
    try std.testing.expectEqual(@as(?NsTid, null), root_nstid_from_child);

    // Root's NsTid from root namespace should be 100
    const root_nstid_from_self = root.namespace.getNsTid(root);
    try std.testing.expectEqual(@as(?NsTid, 100), root_nstid_from_self);

    // Add grandchild: child(200) -> grandchild(300) in same namespace as child
    // NStid for grandchild: [300, 2] meaning:
    //   - From root namespace: NsTid = 300
    //   - From child's namespace: NsTid = 2
    const grandchild_nstids = [_]NsTid{ 300, 2 };
    try proc_info.testing.setupNsTids(allocator, 300, &grandchild_nstids);
    _ = try v_threads.registerChild(child, 300, CloneFlags.from(0));
    const grandchild = v_threads.lookup.get(300).?;

    // Grandchild should be in same namespace as child
    try std.testing.expect(grandchild.namespace == child.namespace);

    // Verify NsTid of grandchild
    //  from root's perspective
    const gc_nstid_from_root = root.namespace.getNsTid(grandchild);
    try std.testing.expectEqual(@as(?NsTid, 300), gc_nstid_from_root);

    //  from child's perspective
    const gc_nstid_from_child_ns = child.namespace.getNsTid(grandchild);
    try std.testing.expectEqual(@as(?NsTid, 2), gc_nstid_from_child_ns);

    // Lookup by NsTid from child's namespace
    const found_child = child.namespace.threads.get(1);
    try std.testing.expectEqual(child, found_child);

    const found_grandchild = child.namespace.threads.get(2);
    try std.testing.expectEqual(grandchild, found_grandchild);
}

test "ensureRegistered registers thread and ancestors" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    // Register initial thread 100
    try v_threads.handleInitialThread(100);
    try std.testing.expectEqual(1, v_threads.lookup.count());

    // Build a status_map with chain: 300 -> 200 -> 100
    var status_map = std.AutoHashMap(AbsTid, ThreadStatus).init(allocator);
    defer status_map.deinit();

    try proc_info.testing.setupParent(allocator, 200, 100);
    try proc_info.testing.setupParent(allocator, 300, 200);

    const status_200 = try getStatus(200);
    const status_300 = try getStatus(300);
    try status_map.put(200, status_200);
    try status_map.put(300, status_300);

    // Register 300 should also register 200
    try v_threads.ensureRegistered(&status_map, 300);

    try std.testing.expectEqual(3, v_threads.lookup.count());
    try std.testing.expect(v_threads.lookup.get(100) != null);
    try std.testing.expect(v_threads.lookup.get(200) != null);
    try std.testing.expect(v_threads.lookup.get(300) != null);

    // Verify parental relationships
    const thread_100 = v_threads.lookup.get(100).?;
    const thread_200 = v_threads.lookup.get(200).?;
    const thread_300 = v_threads.lookup.get(300).?;

    try std.testing.expectEqual(thread_100, thread_200.parent.?);
    try std.testing.expectEqual(thread_200, thread_300.parent.?);
}

test "ensureRegistered is idempotent for already registered thread" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();
    defer proc_info.testing.reset(allocator);

    // Register initial thread 100
    try v_threads.handleInitialThread(100);

    var status_map = std.AutoHashMap(AbsTid, ThreadStatus).init(allocator);
    defer status_map.deinit();

    // Calling ensureRegistered on already registered thread is a no-op
    try v_threads.ensureRegistered(&status_map, 100);
    try std.testing.expectEqual(1, v_threads.lookup.count());
}

test "ensureRegistered fails for thread not in status_map" {
    const allocator = std.testing.allocator;
    var v_threads = Self.init(allocator);
    defer v_threads.deinit();

    try v_threads.handleInitialThread(100);

    var status_map = std.AutoHashMap(AbsTid, ThreadStatus).init(allocator);
    defer status_map.deinit();
    // status_map is empty, 200 not in it

    try std.testing.expectError(error.ThreadNotInKernel, v_threads.ensureRegistered(&status_map, 200));
}
