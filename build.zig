const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const linux_target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .musl,
    });

    // Build node bindings library for each platform
    const node_api = b.dependency("node_api", .{});

    const node_platforms = [_]struct {
        cpu_arch: std.Target.Cpu.Arch,
        abi: std.Target.Abi,
        dest_dir: []const u8,
    }{
        .{ .cpu_arch = .aarch64, .abi = .musl, .dest_dir = "../src/sdks/node/platforms/linux-arm64-musl" },
        .{ .cpu_arch = .aarch64, .abi = .gnu, .dest_dir = "../src/sdks/node/platforms/linux-arm64-gnu" },

        // .{ .cpu_arch = .x86_64, .abi = .musl, .dest_dir = "../src/sdks/node/platforms/linux-x64-musl" },
        // .{ .cpu_arch = .x86_64, .abi = .gnu, .dest_dir = "../src/sdks/node/platforms/linux-x64-gnu" },
    };

    for (node_platforms) |platform| {
        const target = b.resolveTargetQuery(.{
            .cpu_arch = platform.cpu_arch,
            .os_tag = .linux,
            .abi = platform.abi,
        });

        const core_module = b.createModule(.{
            .root_source_file = b.path("src/core/root.zig"),
            .target = target,
            .optimize = optimize,
        });

        const node_lib = b.addLibrary(.{
            .name = "libbvisor",
            .linkage = .dynamic,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/sdks/node/zig/root.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        node_lib.root_module.addImport("core", core_module);
        node_lib.root_module.addIncludePath(node_api.path("include"));
        node_lib.linker_allow_shlib_undefined = true;

        const install = b.addInstallArtifact(node_lib, .{
            .dest_dir = .{ .override = .{ .custom = platform.dest_dir } },
            .dest_sub_path = "libbvisor.node",
        });
        b.getInstallStep().dependOn(&install.step);
    }

    // Build and install linux executable
    // to ./zig-out/bin
    const linux_exe = b.addExecutable(.{
        .name = "bVisor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/main.zig"),
            .target = linux_target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(linux_exe);

    // Build and install zig tests for running in linux container
    const linux_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/main.zig"),
            .target = linux_target,
            .optimize = optimize,
        }),
    });
    const test_install = b.addInstallArtifact(linux_tests, .{ .dest_sub_path = "tests" });
    b.getInstallStep().dependOn(&test_install.step);

    // 'run' mounts built linux exe into a linux container and runs it there
    const run_cli_step = b.step("run", "Run executable in a Linux container");
    const run_args = [_][]const u8{ "docker", "run", "--rm", "--cap-add=SYS_PTRACE", "-v", "./zig-out:/zig-out", "alpine", "/zig-out/bin/bVisor" };
    const run_cmd = b.addSystemCommand(&run_args);
    run_cmd.step.dependOn(b.getInstallStep()); // docker run depends on linux exe being built
    run_cli_step.dependOn(&run_cmd.step);

    // 'test' runs unit tests in a linux container
    const test_cli_step = b.step("test", "Run unit tests in Docker container");
    const docker_test_args = [_][]const u8{ "docker", "run", "--rm", "-v", "./zig-out:/zig-out", "alpine", "/zig-out/bin/tests" };
    const docker_test_cmd = b.addSystemCommand(&docker_test_args);
    docker_test_cmd.step.dependOn(b.getInstallStep());
    test_cli_step.dependOn(&docker_test_cmd.step);
}
