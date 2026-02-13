const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    const fail_loudly = b.option(bool, "fail-loudly", "crash immediately on unsupported syscall") orelse false;
    options.addOption(bool, "fail_loudly", fail_loudly);

    // Callers can select an architecture to target
    // It defaults to the host architecture
    const Arch = enum { aarch64, x86_64 };
    const arch_arg = b.option(Arch, "arch", "Architecture for Docker run/test (default: host)") orelse switch (builtin.cpu.arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
        else => @compileError("unsupported host architecture"),
    };
    const arch: std.Target.Cpu.Arch = switch (arch_arg) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
    };

    const bin_suffix: []const u8 = switch (arch_arg) {
        .aarch64 => "-aarch64",
        .x86_64 => "-x86_64",
    };

    const targets = [_]struct {
        cpu_arch: std.Target.Cpu.Arch,
        suffix: []const u8,
    }{
        .{ .cpu_arch = .aarch64, .suffix = "-aarch64" },
        .{ .cpu_arch = .x86_64, .suffix = "-x86_64" },
    };

    // Build node bindings library for each platform
    const node_api = b.dependency("node_api", .{});

    const node_platforms = [_]struct {
        cpu_arch: std.Target.Cpu.Arch,
        abi: std.Target.Abi,
        dest_dir: []const u8,
    }{
        .{ .cpu_arch = .aarch64, .abi = .musl, .dest_dir = "../src/sdks/node/platforms/linux-arm64-musl" },
        .{ .cpu_arch = .aarch64, .abi = .gnu, .dest_dir = "../src/sdks/node/platforms/linux-arm64-gnu" },
        .{ .cpu_arch = .x86_64, .abi = .musl, .dest_dir = "../src/sdks/node/platforms/linux-x64-musl" },
        .{ .cpu_arch = .x86_64, .abi = .gnu, .dest_dir = "../src/sdks/node/platforms/linux-x64-gnu" },
    };

    var node_installs: [node_platforms.len]*std.Build.Step = undefined;
    var arch_node_installs: [node_platforms.len]*std.Build.Step = undefined;
    var arch_node_count: usize = 0;
    for (node_platforms, 0..) |platform, i| {
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
        // Add config module to enable fail-loudly from core
        core_module.addOptions("config", options);

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
        node_installs[i] = &install.step;
        if (platform.cpu_arch == arch) {
            arch_node_installs[arch_node_count] = &install.step;
            arch_node_count += 1;
        }
    }

    // Build exe and test binaries for both architectures
    var exe_install_step: ?*std.Build.Step = null;
    var test_install_step: ?*std.Build.Step = null;
    for (targets) |t| {
        const linux_target = b.resolveTargetQuery(.{
            .cpu_arch = t.cpu_arch,
            .os_tag = .linux,
            .abi = .musl,
        });

        const linux_exe = b.addExecutable(.{
            .name = "bVisor",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/core/main.zig"),
                .target = linux_target,
                .optimize = optimize,
            }),
        });
        // Add config module to enable fail-loudly
        linux_exe.root_module.addOptions("config", options);

        const exe_install = b.addInstallArtifact(linux_exe, .{
            .dest_sub_path = b.fmt("bVisor{s}", .{t.suffix}),
        });
        b.getInstallStep().dependOn(&exe_install.step);
        if (t.cpu_arch == arch) exe_install_step = &exe_install.step;

        const linux_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/core/main.zig"),
                .target = linux_target,
                .optimize = optimize,
            }),
        });
        const test_install = b.addInstallArtifact(linux_tests, .{
            .dest_sub_path = b.fmt("tests{s}", .{t.suffix}),
        });
        b.getInstallStep().dependOn(&test_install.step);
        if (t.cpu_arch == arch) test_install_step = &test_install.step;
    }
    std.debug.assert(exe_install_step != null);
    std.debug.assert(test_install_step != null);

    // 'run' executes the sandbox in a Linux container
    // Seccomp does not work cross-architecture due to the emulation layer
    const run_cli_step = b.step("run", "Run executable in a Linux container");
    if (arch != builtin.cpu.arch) {
        run_cli_step.dependOn(&b.addFail("zig build run requires native arch (seccomp does not work under emulation)").step);
    } else {
        const run_cmd = b.addSystemCommand(&.{ "docker", "run", "--rm", "--security-opt", "seccomp=unconfined" });
        run_cmd.addArgs(&.{ "-v", "./zig-out:/zig-out", "alpine" });
        run_cmd.addArg(b.fmt("/zig-out/bin/bVisor{s}", .{bin_suffix}));
        run_cmd.step.dependOn(exe_install_step.?);
        run_cli_step.dependOn(&run_cmd.step);
    }

    // 'test' runs unit tests in a Linux container
    const test_cli_step = b.step("test", "Run unit tests in Docker container");
    const docker_test_cmd = b.addSystemCommand(&.{ "docker", "run", "--rm", "--security-opt", "seccomp=unconfined" });
    if (arch != builtin.cpu.arch) {
        if (arch == .x86_64) {
            docker_test_cmd.addArgs(&.{ "--platform", "linux/amd64" });
        } else if (arch == .aarch64) {
            docker_test_cmd.addArgs(&.{ "--platform", "linux/arm64" });
        }
    }
    docker_test_cmd.addArgs(&.{ "-v", "./zig-out:/zig-out", "alpine" });
    docker_test_cmd.addArg(b.fmt("/zig-out/bin/tests{s}", .{bin_suffix}));
    docker_test_cmd.step.dependOn(test_install_step.?);
    test_cli_step.dependOn(&docker_test_cmd.step);

    // 'run-node' runs Node SDK test in a Docker container
    const node_cli_step = b.step("run-node", "Run Node SDK test.ts in Docker container against the current build");
    if (arch != builtin.cpu.arch) {
        node_cli_step.dependOn(&b.addFail("zig build run-node requires native arch").step);
    } else {
        const node_cmd = b.addSystemCommand(&.{
            "docker", "run",                  "--rm",                       "--security-opt", "seccomp=unconfined",
            "-v",     "./src/sdks/node:/app", "-w",                         "/app",           "oven/bun:alpine",
            "sh",     "-c",                   "bun install && bun test.ts",
        });
        for (arch_node_installs[0..arch_node_count]) |step| node_cmd.step.dependOn(step);
        node_cli_step.dependOn(&node_cmd.step);
    }
}
