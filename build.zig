const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64, // ARM64 for Apple Silicon Macs running Docker, update for other targets
        .os_tag = .linux,
        .abi = .musl,
    });

    const exe = b.addExecutable(.{
        .name = "bVisor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run e2e smoke tests in a Linux container");
    var docker_args = std.ArrayList([]const u8).empty;
    defer docker_args.deinit(b.allocator);
    docker_args.append(b.allocator, "docker") catch @panic("OOM");
    docker_args.append(b.allocator, "run") catch @panic("OOM");
    docker_args.append(b.allocator, "--rm") catch @panic("OOM");
    docker_args.append(b.allocator, "-v") catch @panic("OOM");
    docker_args.append(b.allocator, "./zig-out:/zig-out") catch @panic("OOM");
    docker_args.append(b.allocator, "alpine") catch @panic("OOM");
    docker_args.append(b.allocator, "/zig-out/bin/bVisor") catch @panic("OOM");
    if (b.args) |args| {
        docker_args.appendSlice(b.allocator, args) catch @panic("OOM");
    }

    const run_cmd = b.addSystemCommand(docker_args.items);
    run_cmd.step.dependOn(b.getInstallStep());
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Tests run on host (not cross-compiled)
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = b.graph.host,
            .optimize = optimize,
        }),
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
