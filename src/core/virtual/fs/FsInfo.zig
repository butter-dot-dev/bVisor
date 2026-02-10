const std = @import("std");
const Allocator = std.mem.Allocator;

const AtomicUsize = std.atomic.Value(usize);

const Self = @This();

/// FsInfo is a refcounted filesystem info structure (analogous to Linux's fs_struct).
/// When CLONE_FS is set, parent and child share the same FsInfo (refd).
/// When CLONE_FS is not set, child gets a clone (copy with fresh refcount)
ref_count: AtomicUsize = undefined,
allocator: Allocator,
cwd: []u8,
umask: u32, // TODO: implement umask virtualization, might intercept guest process's umask() calls and track mutations to it accordingly
root: []u8,

pub fn init(allocator: Allocator) !*Self {
    const self = try allocator.create(Self);
    errdefer allocator.destroy(self);

    const cwd = try allocator.dupe(u8, "/");
    errdefer allocator.free(cwd);

    const root = try allocator.dupe(u8, "/");
    errdefer allocator.free(root);

    self.* = .{
        .ref_count = AtomicUsize.init(1),
        .allocator = allocator,
        .cwd = cwd,
        .umask = 0o022, // default: removes write privileges for group and others
        .root = root,
    };
    return self;
}

pub fn ref(self: *Self) *Self {
    _ = self.ref_count.fetchAdd(1, .monotonic);
    return self;
}

pub fn unref(self: *Self) void {
    const prev = self.ref_count.fetchSub(1, .acq_rel);
    if (prev == 1) {
        self.allocator.free(self.cwd);
        self.allocator.free(self.root);
        self.allocator.destroy(self);
    }
}

/// Create an independent copy with refcount=1.
/// Used when CLONE_FS is not set.
pub fn clone(self: *Self, allocator: Allocator) !*Self {
    const new = try allocator.create(Self);
    errdefer allocator.destroy(new);

    const cwd_copy = try allocator.dupe(u8, self.cwd);
    errdefer allocator.free(cwd_copy);

    const root_copy = try allocator.dupe(u8, self.root);
    errdefer allocator.free(root_copy);

    new.* = .{
        .ref_count = AtomicUsize.init(1),
        .allocator = allocator,
        .cwd = cwd_copy,
        .umask = self.umask,
        .root = root_copy,
    };
    return new;
}

/// Update the cwd, freeing the old one.
pub fn setCwd(self: *Self, new_cwd: []const u8) !void {
    const copy = try self.allocator.dupe(u8, new_cwd);
    self.allocator.free(self.cwd);
    self.cwd = copy;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "init creates FsInfo with cwd=/" {
    const fs = try Self.init(testing.allocator);
    defer fs.unref();

    try testing.expectEqualStrings("/", fs.cwd);
    try testing.expectEqualStrings("/", fs.root);
    try testing.expectEqual(@as(u32, 0o022), fs.umask);
}

test "ref increments refcount" {
    const fs = try Self.init(testing.allocator);
    defer fs.unref();

    const shared = fs.ref();
    defer shared.unref();

    try testing.expectEqual(@as(usize, 2), fs.ref_count.raw);
}

test "clone creates independent copy" {
    const fs = try Self.init(testing.allocator);
    defer fs.unref();

    try fs.setCwd("/tmp");

    const cloned = try fs.clone(testing.allocator);
    defer cloned.unref();

    try testing.expectEqualStrings("/tmp", cloned.cwd);

    // Mutating original doesn't affect clone
    try fs.setCwd("/home");
    try testing.expectEqualStrings("/tmp", cloned.cwd);
    try testing.expectEqualStrings("/home", fs.cwd);
}

test "setCwd updates cwd" {
    const fs = try Self.init(testing.allocator);
    defer fs.unref();

    try fs.setCwd("/usr/bin");
    try testing.expectEqualStrings("/usr/bin", fs.cwd);

    try fs.setCwd("/");
    try testing.expectEqualStrings("/", fs.cwd);
}

test "CLONE_FS scenario: shared FsInfo, changes visible to both" {
    const fs = try Self.init(testing.allocator);
    defer fs.unref();

    const shared = fs.ref();
    defer shared.unref();

    try fs.setCwd("/tmp");
    try testing.expectEqualStrings("/tmp", shared.cwd);
}
