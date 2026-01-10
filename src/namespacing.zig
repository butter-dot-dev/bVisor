const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const assert = std.debug.assert;

const FD = union { kernel: KernelFD, virtual: VirtualFD };
const VirtualFD = linux.fd_t;
const KernelFD = linux.fd_t;

const PID = union { kernel: KernelPID, virtual: VirtualPID };
const VirtualPID = linux.pid_t;
const KernelPID = linux.pid_t;

const ProcLookup = std.AutoHashMapUnmanaged(KernelPID, *Proc);
const ProcSet = std.AutoHashMapUnmanaged(*Proc, void);
const ProcList = std.ArrayList(*Proc);

/// Namespaces are owned by their root proc
const Namespace = struct {
    vpid_counter: VirtualPID = 0,

    const Self = @This();

    pub fn init(allocator: Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{};
        return self;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.destroy(self);
    }

    pub fn next_vpid(self: *Namespace) VirtualPID {
        self.vpid_counter += 1;
        return self.vpid_counter;
    }
};

const Proc = struct {
    namespace: *Namespace,
    vpid: VirtualPID,
    parent: ?*Proc,
    children: ProcSet = .empty,

    const Self = @This();

    pub fn init(allocator: Allocator, namespace: ?*Namespace, parent: ?*Proc) !*Self {
        if (namespace) |ns| {
            // proc inherits parent namespace
            const vpid = ns.next_vpid();
            const self = try allocator.create(Self);
            self.* = .{
                .namespace = ns,
                .vpid = vpid,
                .parent = parent,
            };
            return self;
        }

        // create this proc as root in a new namespace
        var ns = try Namespace.init(allocator);
        errdefer ns.deinit(allocator);
        const vpid = ns.next_vpid();
        const self = try allocator.create(Self);
        self.* = .{
            .namespace = ns,
            .vpid = vpid,
            .parent = parent,
        };
        return self;
    }

    pub fn is_namespace_root(self: *Self) bool {
        if (self.parent) |parent| {
            return self.namespace != parent.namespace; // crossed boundary
        }
        return true; // no parent = top-level root
    }

    fn deinit(self: *Self, allocator: Allocator) void {
        if (self.is_namespace_root()) {
            // the root Proc in a namespace is responsible for deallocating it
            self.namespace.deinit(allocator);
        }
        self.children.deinit(allocator);
        allocator.destroy(self);
    }

    fn get_namespace_root(self: *Self) *Proc {
        if (self.is_namespace_root()) return self;

        var current = self;
        while (current.parent) |parent| {
            if (parent.is_namespace_root()) return parent;
            current = parent;
        }

        // root should always be hit in parent if self is not already root
        // so this should never happen
        std.debug.panic("Proc.get_namespace_root: root not found", .{});
    }

    fn init_child(self: *Self, allocator: Allocator, namespace: ?*Namespace) !*Self {
        // TODO: support different clone flags to determine what gets copied over from parent

        const child = try Proc.init(allocator, namespace, self);
        errdefer child.deinit(allocator);

        try self.children.put(allocator, child, {});

        return child;
    }

    pub fn deinit_child(self: *Self, child: *Self, allocator: Allocator) void {
        self.remove_child_link(child);
        child.deinit(allocator);
    }

    pub fn remove_child_link(self: *Self, child: *Self) void {
        _ = self.children.remove(child);
    }

    /// Get a sorted list of all PIDs in this process's namespace
    fn get_pids_owned(self: *Self, allocator: Allocator) ![]VirtualPID {
        const root = self.get_namespace_root();
        const procs = try root.collect_subtree_owned(allocator);
        defer allocator.free(procs);

        var vpids = try std.ArrayList(VirtualPID).initCapacity(allocator, procs.len);
        for (procs) |proc| {
            try vpids.append(allocator, proc.vpid);
        }
        std.mem.sort(VirtualPID, vpids.items, {}, std.sort.asc(VirtualPID));
        return vpids.toOwnedSlice(allocator);
    }

    /// Collect a flat list of this process and all descendents
    /// Returned ArrayList must be freed by caller
    fn collect_subtree_owned(self: *Self, allocator: Allocator) ![]*Proc {
        var accumulator = try ProcList.initCapacity(allocator, 16);
        try self._collect_subtree_recursive(&accumulator, allocator);
        return accumulator.toOwnedSlice(allocator);
    }

    fn _collect_subtree_recursive(self: *Self, accumulator: *ProcList, allocator: Allocator) !void {
        var iter = self.children.iterator();
        while (iter.next()) |child_entry| {
            const child: *Proc = child_entry.key_ptr.*;
            try child._collect_subtree_recursive(accumulator, allocator);
        }
        try accumulator.append(allocator, self);
    }
};

/// Tracks kernel to virtual mappings, handling parent/child relationships
const Virtualizer = struct {
    allocator: Allocator,

    // flat list of mappings from kernel to virtual PID
    // owns underlying procs
    procs: ProcLookup = .empty,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        var proc_iter = self.procs.iterator();
        while (proc_iter.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
        }
        self.procs.deinit(self.allocator);
    }

    pub fn handle_initial_process(self: *Self, pid: KernelPID) !VirtualPID {
        if (self.procs.size != 0) return error.InitialProcessExists;

        // passing null namespace creates a new one
        const root_proc = try Proc.init(self.allocator, null, null);
        errdefer root_proc.deinit(self.allocator);

        try self.procs.put(self.allocator, pid, root_proc);

        return root_proc.vpid;
    }

    pub fn handle_clone(self: *Self, parent_pid: KernelPID, child_pid: KernelPID) !VirtualPID {
        const parent: *Proc = self.procs.get(parent_pid) orelse return error.KernelPIDNotFound;
        // TODO: handle different clone cases
        // For now, inherit parent namespace
        const namespace = parent.namespace;

        const child = try parent.init_child(self.allocator, namespace);
        errdefer parent.deinit_child(child, self.allocator);

        try self.procs.put(self.allocator, child_pid, child);

        return child.vpid;
    }

    pub fn handle_process_exit(self: *Self, pid: KernelPID) !void {
        var target_proc = self.procs.get(pid) orelse return;

        // remove target from parent's children
        if (target_proc.parent) |parent| {
            parent.remove_child_link(target_proc);
        }

        // collect all descendent procs
        var descendent_procs = try target_proc.collect_subtree_owned(self.allocator);
        defer self.allocator.free(descendent_procs); // frees the slice, not the items

        // collect all kernel PIDs of descendents
        var kernel_pids = try std.ArrayList(KernelPID).initCapacity(self.allocator, descendent_procs.len);
        defer kernel_pids.deinit(self.allocator);
        outer: for (descendent_procs) |proc| {
            var iter = self.procs.iterator();
            while (iter.next()) |entry| {
                const entry_proc = entry.value_ptr.*;
                const entry_kernel_pid = entry.key_ptr.*;
                if (entry_proc == proc) {
                    try kernel_pids.append(self.allocator, entry_kernel_pid);
                    continue :outer;
                }
            }
        }

        // remove entries from proc lookup table
        for (kernel_pids.items) |kernel_pid| {
            _ = self.procs.remove(kernel_pid);
        }

        // deinit the procs themselves
        for (descendent_procs) |proc| {
            proc.deinit(self.allocator);
        }
    }
};

test "state is correct after initial proc" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();
    try std.testing.expect(virtualizer.procs.size == 0);

    // supervisor spawns child proc of say PID=22, need to register that virtually
    const init_pid = 22;
    const init_vpid = try virtualizer.handle_initial_process(init_pid);
    try std.testing.expectEqual(1, init_vpid);
    try std.testing.expectEqual(1, virtualizer.procs.size);
    const proc = virtualizer.procs.get(init_pid).?;
    try std.testing.expectEqual(init_vpid, proc.vpid);
    try std.testing.expectEqual(null, proc.parent);
    try std.testing.expectEqual(0, proc.children.size);
    try std.testing.expect(proc.is_namespace_root());
    try std.testing.expectEqual(@as(VirtualPID, 1), proc.get_namespace_root().vpid);
}

test "basic tree operations work - add, kill" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();
    try std.testing.expectEqual(0, virtualizer.procs.size);

    // create procs of this layout
    // a
    // - b
    // - c
    //   - d

    const a_pid = 33;
    const a_vpid = try virtualizer.handle_initial_process(a_pid);
    try std.testing.expectEqual(1, virtualizer.procs.size);
    try std.testing.expectEqual(1, a_vpid);

    const b_pid = 44;
    const b_vpid = try virtualizer.handle_clone(a_pid, b_pid);
    try std.testing.expectEqual(2, b_vpid);
    try std.testing.expectEqual(2, virtualizer.procs.size);
    try std.testing.expectEqual(1, virtualizer.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(b_pid).?.children.size);

    const c_pid = 55;
    const c_vpid = try virtualizer.handle_clone(a_pid, c_pid);
    try std.testing.expectEqual(3, c_vpid);
    try std.testing.expectEqual(3, virtualizer.procs.size);
    try std.testing.expectEqual(2, virtualizer.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(b_pid).?.children.size);

    const d_pid = 66;
    const d_vpid = try virtualizer.handle_clone(c_pid, d_pid);
    try std.testing.expectEqual(4, d_vpid);
    try std.testing.expectEqual(4, virtualizer.procs.size);
    try std.testing.expectEqual(2, virtualizer.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, virtualizer.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(b_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(d_pid).?.children.size);

    // shrink to
    // a
    // - c
    //   - d
    try virtualizer.handle_process_exit(b_pid);
    try std.testing.expectEqual(3, virtualizer.procs.size);
    try std.testing.expectEqual(1, virtualizer.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, virtualizer.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, virtualizer.procs.get(d_pid).?.children.size);
    try std.testing.expectEqual(null, virtualizer.procs.get(b_pid));

    // get vpids
    var a_vpids = try virtualizer.procs.get(a_pid).?.get_pids_owned(allocator);
    try std.testing.expectEqual(3, a_vpids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[3]VirtualPID{ 1, 3, 4 }, a_vpids);
    allocator.free(a_vpids); // free immediately, since we reuse a_vpids var later

    // re-add b, should issue a new vpid 5
    const b_pid_2 = 45;
    const b_vpid_2 = try virtualizer.handle_clone(a_pid, b_pid_2);
    try std.testing.expectEqual(5, b_vpid_2);

    a_vpids = try virtualizer.procs.get(a_pid).?.get_pids_owned(allocator);
    defer allocator.free(a_vpids);
    try std.testing.expectEqual(4, a_vpids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[4]VirtualPID{ 1, 3, 4, 5 }, a_vpids);

    // clear whole tree
    try virtualizer.handle_process_exit(a_pid);
    try std.testing.expectEqual(0, virtualizer.procs.size);
    try std.testing.expectEqual(null, virtualizer.procs.get(a_pid));
    try std.testing.expectEqual(null, virtualizer.procs.get(b_pid));
    try std.testing.expectEqual(null, virtualizer.procs.get(b_pid_2));
    try std.testing.expectEqual(null, virtualizer.procs.get(c_pid));
    try std.testing.expectEqual(null, virtualizer.procs.get(d_pid));
}

test "handle_initial_process fails if already registered" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();

    _ = try virtualizer.handle_initial_process(100);
    try std.testing.expectError(error.InitialProcessExists, virtualizer.handle_initial_process(200));
}

test "handle_clone fails with unknown parent" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();

    _ = try virtualizer.handle_initial_process(100);
    try std.testing.expectError(error.KernelPIDNotFound, virtualizer.handle_clone(999, 200));
}

test "handle_process_exit on non-existent pid is no-op" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();

    _ = try virtualizer.handle_initial_process(100);
    try virtualizer.handle_process_exit(999);
    try std.testing.expectEqual(1, virtualizer.procs.size);
}

test "kill intermediate node removes subtree but preserves siblings" {
    var virtualizer = Virtualizer.init(std.testing.allocator);
    defer virtualizer.deinit();

    // a
    // - b
    // - c
    //   - d
    const a_pid = 10;
    _ = try virtualizer.handle_initial_process(a_pid);
    const b_pid = 20;
    _ = try virtualizer.handle_clone(a_pid, b_pid);
    const c_pid = 30;
    _ = try virtualizer.handle_clone(a_pid, c_pid);
    const d_pid = 40;
    _ = try virtualizer.handle_clone(c_pid, d_pid);

    try std.testing.expectEqual(4, virtualizer.procs.size);

    // kill c (intermediate) - should also remove d but preserve a and b
    try virtualizer.handle_process_exit(c_pid);

    try std.testing.expectEqual(2, virtualizer.procs.size);
    try std.testing.expect(virtualizer.procs.get(a_pid) != null);
    try std.testing.expect(virtualizer.procs.get(b_pid) != null);
    try std.testing.expectEqual(null, virtualizer.procs.get(c_pid));
    try std.testing.expectEqual(null, virtualizer.procs.get(d_pid));
}

test "collect_tree on single node" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    _ = try virtualizer.handle_initial_process(100);
    const proc = virtualizer.procs.get(100).?;

    const vpids = try proc.get_pids_owned(allocator);
    defer allocator.free(vpids);

    try std.testing.expectEqual(1, vpids.len);
    try std.testing.expectEqual(1, vpids[0]);
}

test "deep nesting" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    // chain: a -> b -> c -> d -> e
    var pids = [_]KernelPID{ 10, 20, 30, 40, 50 };

    _ = try virtualizer.handle_initial_process(pids[0]);
    for (1..5) |i| {
        _ = try virtualizer.handle_clone(pids[i - 1], pids[i]);
    }

    try std.testing.expectEqual(5, virtualizer.procs.size);

    // kill middle (c) - should remove c, d, e
    try virtualizer.handle_process_exit(pids[2]);
    try std.testing.expectEqual(2, virtualizer.procs.size);
}

test "wide tree with many siblings" {
    const allocator = std.testing.allocator;
    var virtualizer = Virtualizer.init(allocator);
    defer virtualizer.deinit();

    const parent_pid = 100;
    _ = try virtualizer.handle_initial_process(parent_pid);

    // add 10 children
    for (1..11) |i| {
        const child_pid: KernelPID = @intCast(100 + i);
        const vpid = try virtualizer.handle_clone(parent_pid, child_pid);
        try std.testing.expectEqual(@as(VirtualPID, @intCast(i + 1)), vpid);
    }

    try std.testing.expectEqual(11, virtualizer.procs.size);
    try std.testing.expectEqual(10, virtualizer.procs.get(parent_pid).?.children.size);
}
