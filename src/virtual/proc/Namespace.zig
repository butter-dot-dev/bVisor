const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const Proc = @import("Proc.zig");

pub const VirtualPID = linux.pid_t;

const VpidLookup = std.AutoHashMapUnmanaged(VirtualPID, *Proc);

const Self = @This();

/// Namespaces are owned by their root proc.
/// Each namespace tracks all procs visible to it (own procs + procs in child namespaces).

vpid_counter: VirtualPID = 0,
parent: ?*Self,
procs: VpidLookup = .empty, // vpid → Proc for all visible procs

pub fn init(allocator: Allocator, parent: ?*Self) !*Self {
    const self = try allocator.create(Self);
    self.* = .{ .parent = parent };
    return self;
}

pub fn deinit(self: *Self, allocator: Allocator) void {
    self.procs.deinit(allocator);
    allocator.destroy(self);
}

pub fn next_vpid(self: *Self) VirtualPID {
    self.vpid_counter += 1;
    return self.vpid_counter;
}

/// Get a proc by its vpid as visible from this namespace
pub fn get_proc(self: *Self, vpid: VirtualPID) ?*Proc {
    return self.procs.get(vpid);
}

/// Register a proc in this namespace and all ancestor namespaces.
/// Each namespace assigns its own vpid to the proc.
pub fn register_proc(self: *Self, allocator: Allocator, proc: *Proc) !void {
    // Register in this namespace (proc already has vpid assigned from this ns)
    try self.procs.put(allocator, proc.vpid, proc);

    // Register in all ancestor namespaces with their own vpids
    var ancestor = self.parent;
    while (ancestor) |ns| {
        const ancestor_vpid = ns.next_vpid();
        try ns.procs.put(allocator, ancestor_vpid, proc);
        ancestor = ns.parent;
    }
}

/// Unregister a proc from this namespace and all ancestor namespaces.
/// Searches by proc pointer since we don't store vpid-per-namespace in Proc.
pub fn unregister_proc(self: *Self, proc: *Proc) void {
    // Remove from this namespace
    _ = self.procs.remove(proc.vpid);

    // Remove from all ancestor namespaces (search by pointer)
    var ancestor = self.parent;
    while (ancestor) |ns| {
        var iter = ns.procs.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.* == proc) {
                _ = ns.procs.remove(entry.key_ptr.*);
                break;
            }
        }
        ancestor = ns.parent;
    }
}
