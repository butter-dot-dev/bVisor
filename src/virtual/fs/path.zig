const std = @import("std");
const FileBackend = @import("./file.zig").FileBackend;

pub fn route(path: []const u8) !RouteResult {
    // normalize ".." out of path
    const buf: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const normalized = try std.fs.path.resolvePosix(fba.allocator(), &.{path});

    // route through prefix tree
    return routeByPrefix(normalized, router_rules, global_default);
}

pub const RouteResult = union(enum) {
    block: void,
    handle: FileBackend,
};

fn routeByPrefix(path: []const u8, rules: []const Rule, default: RouteResult) !RouteResult {
    for (rules) |rule| {
        if (matchesPrefix(path, rule.prefix)) |remainder| {
            switch (rule.node) {
                .terminal => |result| return result,
                .branch => |branch| return routeByPrefix(remainder, branch.subrules, branch.default),
            }
        }
    }
    return default;
}

/// Check if path matches a directory prefix (handles trailing slash variations)
/// Returns remainder after prefix, or null if no match
fn matchesPrefix(path: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    if (path.len == prefix.len) return ""; // exact match
    if (path[prefix.len] == '/') return path[prefix.len + 1 ..]; // skip the /
    return null; // e.g., /tmpfoo doesn't match /tmp
}

// Routing rules
const global_default: RouteResult = .block;
const router_rules: []const Rule = &.{
    // Hard blocks
    .{ .prefix = "/sys", .node = .{ .terminal = .block } },
    .{ .prefix = "/run", .node = .{ .terminal = .block } },
    .{ .prefix = "/dev", .node = .{ .terminal = .block } },

    // Proc symbolic path gets special virtualization
    .{ .prefix = "/proc", .node = .{ .terminal = .{ .handle = .proc } } },

    // /tmp/.bvisor contains per-sandbox data like cow and private /tmp files
    // block access to .bvisor
    // and redirect all others to virtual /tmp
    .{ .prefix = "/tmp", .rule = .{ .branch = .{
        .children = &.{
            .{ .prefix = ".bvisor", .rule = .{ .terminal = .blocked } },
        },
        .default = .{ .allow = .tmp },
    } } },
};

const Node = union(enum) {
    terminal: RouteResult,
    branch: struct {
        subrules: []const Rule,
        default: RouteResult,
    },
};

pub const Rule = struct {
    prefix: []const u8,
    node: Node,
};
