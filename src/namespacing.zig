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

const KernelToVirtualProcMap = std.AutoHashMapUnmanaged(KernelPID, *VirtualProc);
const VirtualProcSet = std.AutoHashMapUnmanaged(*VirtualProc, void);
const VirtualProcList = std.ArrayList(*VirtualProc);

const VirtualProc = struct {
    role: NamespaceRole,
    parent: ?*VirtualProc,
    children: VirtualProcSet = .empty,

    const Self = @This();

    const RoleTag = enum {
        namespace_root,
        child,
    };

    const NamespaceRole = union(Tag) {
        root: Root,
        child: Child,

        pub const Tag = enum {
            root,
            child,
        };

        pub const init_root: @This() = .{ .root = .{} };
    };

    const Root = struct {
        // Roots are always virtual PID 1
        // Roots may be children of other nodes - this denotes a nested namespace boundary

        highest_pid: VirtualPID = 1, // monotonically increasing PID; linux doesn't promise gap-filling, so we don't need to.

        pub fn next_pid(self: *Root) VirtualPID {
            self.highest_pid += 1;
            return self.highest_pid;
        }

        pub inline fn pid(_: *Root) VirtualPID {
            // roots are implicitly always 1
            // inlined to avoid extra function call overhead
            return 1;
        }
    };

    const Child = struct {
        // Children can be any PID except 1
        pid: VirtualPID,
    };

    fn init(allocator: Allocator, role: NamespaceRole, parent: ?*VirtualProc) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .role = role,
            .parent = parent,
        };
        return self;
    }

    fn deinit(self: *Self, allocator: Allocator) void {
        self.children.deinit(allocator);
        allocator.destroy(self);
    }

    pub inline fn pid(self: *Self) VirtualPID {
        // inlined to avoid extra function call overhead
        return switch (self.role) {
            .root => |*root| root.pid(),
            .child => |*child| child.pid,
        };
    }

    /// Walk up the tree until a root is found
    fn get_namespace_root(self: *Self) !*VirtualProc {
        if (self.role == .root) {
            return self;
        }
        var current = self;
        while (current.parent) |parent| {
            if (parent.role == .root) {
                return parent;
            }
            current = parent;
        }
        return error.NoRootFound;
    }

    fn init_child(self: *Self, allocator: Allocator, role_tag: NamespaceRole.Tag) !*Self {
        // TODO: support different clone flags to determine what gets copied over from parent

        const role: NamespaceRole = switch (role_tag) {
            .root => .{ .root = .{} },
            .child => blk: {
                const root = try self.get_namespace_root();
                assert(root.role == .root); // crashes program if get_root incorrectly implemented
                const child_pid = root.role.root.next_pid();
                break :blk .{ .child = .{ .pid = child_pid } };
            },
        };

        const child = try VirtualProc.init(
            allocator,
            role,
            self,
        );
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
        const root = try self.get_namespace_root();
        const procs = try root.collect_subtree_owned(allocator);
        defer allocator.free(procs);

        var pids = try std.ArrayList(VirtualPID).initCapacity(allocator, procs.len);
        for (procs) |proc| {
            try pids.append(allocator, proc.pid());
        }
        std.mem.sort(VirtualPID, pids.items, {}, std.sort.asc(VirtualPID));
        return pids.toOwnedSlice(allocator);
    }

    /// Collect a flat list of this process and all descendents
    /// Returned ArrayList must be freed by caller
    fn collect_subtree_owned(self: *Self, allocator: Allocator) ![]*VirtualProc {
        var accumulator = try VirtualProcList.initCapacity(allocator, 16);
        try self._collect_subtree_recursive(&accumulator, allocator);
        return accumulator.toOwnedSlice(allocator);
    }

    fn _collect_subtree_recursive(self: *Self, accumulator: *VirtualProcList, allocator: Allocator) !void {
        var iter = self.children.iterator();
        while (iter.next()) |child_entry| {
            const child: *VirtualProc = child_entry.key_ptr.*;
            try child._collect_subtree_recursive(accumulator, allocator);
        }
        try accumulator.append(allocator, self);
    }
};

/// Tracks kernel to virtual mappings, handling parent/child relationships
const VirtualProcesses = struct {
    allocator: Allocator,

    // flat list of mappings from kernel to virtual PID
    // the VirtualProc pointed to may be arbitrarily nested
    procs: KernelToVirtualProcMap = .empty,
    root_proc: ?*VirtualProc = null, // cached initial proc for quick access

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.procs.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
        }
        self.procs.deinit(self.allocator);
    }

    /// Called once on sandbox startup, to track the initial root process virtually
    pub fn register_root_proc(self: *Self, pid: KernelPID) !VirtualPID {
        // should only ever happen once on sandbox boot. We don't allow new top-level processes, only cloned children.
        if (self.procs.size != 0) return error.InitialProcessExists;

        const proc = try VirtualProc.init(
            self.allocator,
            .init_root,
            null,
        );
        errdefer proc.deinit(self.allocator);
        assert(proc.role == .root);

        try self.procs.put(self.allocator, pid, proc);
        self.root_proc = proc;

        return proc.pid();
    }

    pub fn register_child_proc(self: *Self, parent_pid: KernelPID, child_pid: KernelPID) !VirtualPID {
        // TODO: handle different clone cases

        const parent: *VirtualProc = self.procs.get(parent_pid) orelse return error.KernelPIDNotFound;
        const child = try parent.init_child(self.allocator, .child);
        errdefer parent.deinit_child(child, self.allocator);

        try self.procs.put(self.allocator, child_pid, child);

        return child.pid();
    }

    pub fn kill_proc(self: *Self, pid: KernelPID) !void {
        var target_proc = self.procs.get(pid) orelse return;
        const parent = target_proc.parent;

        // collect all descendents
        var procs_to_delete = try target_proc.collect_subtree_owned(self.allocator);
        defer self.allocator.free(procs_to_delete);

        // remove target from parent's children
        if (parent) |parent_proc| {
            parent_proc.remove_child_link(target_proc);
        }

        // remove mappings from procs
        var kernel_pids_to_remove = try std.ArrayList(KernelPID).initCapacity(self.allocator, procs_to_delete.len);
        defer kernel_pids_to_remove.deinit(self.allocator);
        for (procs_to_delete) |child| {
            var iter = self.procs.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.* == child) {
                    try kernel_pids_to_remove.append(self.allocator, entry.key_ptr.*);
                }
            }
        }
        for (kernel_pids_to_remove.items) |kernel_pid| {
            _ = self.procs.remove(kernel_pid);
        }

        // mass-deinit items
        for (procs_to_delete) |proc| {
            proc.deinit(self.allocator);
        }
    }
};

test "state is correct after initial proc" {
    var flat_map = VirtualProcesses.init(std.testing.allocator);
    defer flat_map.deinit();
    try std.testing.expect(flat_map.procs.count() == 0);

    // supervisor spawns child proc of say PID=22, need to register that virtually
    const init_pid = 22;
    const init_vpid = try flat_map.register_root_proc(init_pid);
    try std.testing.expectEqual(1, init_vpid);
    try std.testing.expectEqual(1, flat_map.procs.count());
    const maybe_proc = flat_map.procs.get(init_pid);
    try std.testing.expect(maybe_proc != null);
    const proc = maybe_proc.?;
    try std.testing.expectEqual(1, proc.pid()); // correct virtual PID assignment
    try std.testing.expect(proc.role == .root);
    try std.testing.expectEqual(0, proc.children.size);
}

test "basic tree operations work - add, kill" {
    const allocator = std.testing.allocator;
    var flat_map = VirtualProcesses.init(allocator);
    defer flat_map.deinit();
    try std.testing.expectEqual(0, flat_map.procs.count());

    // create procs of this layout
    // a
    // - b
    // - c
    //   - d

    const a_pid = 33;
    const a_vpid = try flat_map.register_root_proc(a_pid);
    try std.testing.expectEqual(1, flat_map.procs.count());
    try std.testing.expectEqual(1, a_vpid);

    const b_pid = 44;
    const b_vpid = try flat_map.register_child_proc(a_pid, b_pid);
    try std.testing.expectEqual(2, b_vpid);
    try std.testing.expectEqual(2, flat_map.procs.count());
    try std.testing.expectEqual(1, flat_map.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(b_pid).?.children.size);

    const c_pid = 55;
    const c_vpid = try flat_map.register_child_proc(a_pid, c_pid);
    try std.testing.expectEqual(3, c_vpid);
    try std.testing.expectEqual(3, flat_map.procs.count());
    try std.testing.expectEqual(2, flat_map.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(b_pid).?.children.size);

    const d_pid = 66;
    const d_vpid = try flat_map.register_child_proc(c_pid, d_pid);
    try std.testing.expectEqual(4, d_vpid);
    try std.testing.expectEqual(4, flat_map.procs.count());
    try std.testing.expectEqual(2, flat_map.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, flat_map.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(b_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(d_pid).?.children.size);

    // shrink to
    // a
    // - c
    //   - d
    try flat_map.kill_proc(b_pid);
    try std.testing.expectEqual(3, flat_map.procs.count());
    try std.testing.expectEqual(1, flat_map.procs.get(a_pid).?.children.size);
    try std.testing.expectEqual(1, flat_map.procs.get(c_pid).?.children.size);
    try std.testing.expectEqual(0, flat_map.procs.get(d_pid).?.children.size);
    try std.testing.expectEqual(null, flat_map.procs.get(b_pid));

    // get pids
    var a_pids = try flat_map.procs.get(a_pid).?.get_pids_owned(allocator);
    try std.testing.expectEqual(3, a_pids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[3]VirtualPID{ 1, 3, 4 }, a_pids);
    allocator.free(a_pids); // free immediately, since we reuse a_pids var later

    // re-add b, should issue a new vpid 5
    const b_pid_2 = 45;
    const b_vpid_2 = try flat_map.register_child_proc(a_pid, b_pid_2);
    try std.testing.expectEqual(5, b_vpid_2);

    a_pids = try flat_map.procs.get(a_pid).?.get_pids_owned(allocator);
    defer allocator.free(a_pids);
    try std.testing.expectEqual(4, a_pids.len);
    try std.testing.expectEqualSlices(VirtualPID, &[4]VirtualPID{ 1, 3, 4, 5 }, a_pids);

    // clear whole tree
    try flat_map.kill_proc(a_pid);
    try std.testing.expectEqual(0, flat_map.procs.count());
    try std.testing.expectEqual(null, flat_map.procs.get(a_pid));
    try std.testing.expectEqual(null, flat_map.procs.get(b_pid));
    try std.testing.expectEqual(null, flat_map.procs.get(b_pid_2));
    try std.testing.expectEqual(null, flat_map.procs.get(c_pid));
    try std.testing.expectEqual(null, flat_map.procs.get(d_pid));
}

test "register_root_proc fails if already registered" {
    var flat_map = VirtualProcesses.init(std.testing.allocator);
    defer flat_map.deinit();

    _ = try flat_map.register_root_proc(100);
    try std.testing.expectError(error.InitialProcessExists, flat_map.register_root_proc(200));
}

test "register_child_proc fails with unknown parent" {
    var flat_map = VirtualProcesses.init(std.testing.allocator);
    defer flat_map.deinit();

    _ = try flat_map.register_root_proc(100);
    try std.testing.expectError(error.KernelPIDNotFound, flat_map.register_child_proc(999, 200));
}

test "kill_proc on non-existent pid is no-op" {
    var flat_map = VirtualProcesses.init(std.testing.allocator);
    defer flat_map.deinit();

    _ = try flat_map.register_root_proc(100);
    try flat_map.kill_proc(999);
    try std.testing.expectEqual(1, flat_map.procs.count());
}

test "kill intermediate node removes subtree but preserves siblings" {
    var flat_map = VirtualProcesses.init(std.testing.allocator);
    defer flat_map.deinit();

    // a
    // - b
    // - c
    //   - d
    const a_pid = 10;
    _ = try flat_map.register_root_proc(a_pid);
    const b_pid = 20;
    _ = try flat_map.register_child_proc(a_pid, b_pid);
    const c_pid = 30;
    _ = try flat_map.register_child_proc(a_pid, c_pid);
    const d_pid = 40;
    _ = try flat_map.register_child_proc(c_pid, d_pid);

    try std.testing.expectEqual(4, flat_map.procs.count());

    // kill c (intermediate) - should also remove d but preserve a and b
    try flat_map.kill_proc(c_pid);

    try std.testing.expectEqual(2, flat_map.procs.count());
    try std.testing.expect(flat_map.procs.get(a_pid) != null);
    try std.testing.expect(flat_map.procs.get(b_pid) != null);
    try std.testing.expectEqual(null, flat_map.procs.get(c_pid));
    try std.testing.expectEqual(null, flat_map.procs.get(d_pid));
}

test "collect_tree on single node" {
    const allocator = std.testing.allocator;
    var flat_map = VirtualProcesses.init(allocator);
    defer flat_map.deinit();

    _ = try flat_map.register_root_proc(100);
    const proc = flat_map.procs.get(100).?;

    const pids = try proc.get_pids_owned(allocator);
    defer allocator.free(pids);

    try std.testing.expectEqual(1, pids.len);
    try std.testing.expectEqual(1, pids[0]);
}

test "deep nesting" {
    const allocator = std.testing.allocator;
    var flat_map = VirtualProcesses.init(allocator);
    defer flat_map.deinit();

    // chain: a -> b -> c -> d -> e
    var kernel_pids = [_]KernelPID{ 10, 20, 30, 40, 50 };

    _ = try flat_map.register_root_proc(kernel_pids[0]);
    for (1..5) |i| {
        _ = try flat_map.register_child_proc(kernel_pids[i - 1], kernel_pids[i]);
    }

    try std.testing.expectEqual(5, flat_map.procs.count());

    // kill middle (c) - should remove c, d, e
    try flat_map.kill_proc(kernel_pids[2]);
    try std.testing.expectEqual(2, flat_map.procs.count());
}

test "wide tree with many siblings" {
    const allocator = std.testing.allocator;
    var flat_map = VirtualProcesses.init(allocator);
    defer flat_map.deinit();

    const parent_pid = 100;
    _ = try flat_map.register_root_proc(parent_pid);

    // add 10 children
    for (1..11) |i| {
        const child_pid: KernelPID = @intCast(100 + i);
        const vpid = try flat_map.register_child_proc(parent_pid, child_pid);
        try std.testing.expectEqual(@as(VirtualPID, @intCast(i + 1)), vpid);
    }

    try std.testing.expectEqual(11, flat_map.procs.count());
    try std.testing.expectEqual(10, flat_map.procs.get(parent_pid).?.children.size);
}
