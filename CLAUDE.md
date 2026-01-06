# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bVisor is an in-process Linux sandbox SDK and runtime written in Zig. It intercepts and virtualizes Linux syscalls from userspace using seccomp user notifier, providing isolation without VM overhead. Unlike gVisor (which runs as a separate service), bVisor runs directly in your application for millisecond-level sandbox lifecycle.

The goal of bVisor is to be lightweight sandbox for untrusted user or LLM-generated code run on the server. Its most minimal implementation creates a virtualized filesystem and runs a bash command inside of it, but the goal is to increase sandboxing over time. This is intended as alternative to docker, gvisor, or other vm-based sandboxes.

**Status**: Early proof-of-concept. Core seccomp interception works; syscall virtualization is incomplete.

## Build Commands

```bash
zig build              # Build for aarch64-linux-musl
zig build test         # Run tests
```

The build targets aarch64 Linux with musl ABI (for ARM64/Apple Silicon Docker). Modify `build.zig` line 6-8 for other targets.

**Requires**: Zig 0.16.0-dev or later

## Running on macOS

Seccomp only works on Linux. To test on macOS, use Docker:

```bash
zig build
docker run --rm -v ./zig-out:/zig-out alpine /zig-out/bin/bVisor
# Inside container: /zig-out/bin/bVisor
```

## Architecture

**Supervisor-child process model with syscall interception:**

```
src/
  main.zig              # Entry point, demonstrates sandbox usage
  setup.zig             # Fork into child/supervisor, seccomp BPF installation
  types.zig             # LinuxResult, Logger, FD (re-exports MemoryBridge)
  memory_bridge.zig     # Comptime selector for MemoryBridge implementation
  memory_bridge/
    ProcessMemoryBridge.zig  # Production: uses process_vm_readv/writev
    TestingMemoryBridge.zig  # Testing: local pointer access (no child process)
  Supervisor.zig        # Main loop: recv notif → handle → send response
  Notification.zig      # Parses seccomp notif, dispatches to handler or passthrough
  syscall.zig           # Syscall union (all emulated syscalls) and Result type
  VirtualFilesystem.zig # In-memory filesystem with Unix permissions
  syscalls/
    Openat.zig          # openat handler - creates virtual FDs
    Write.zig           # write handler
    Writev.zig          # writev handler
    Close.zig           # close handler
    ClockNanosleep.zig  # clock_nanosleep handler
```

**Syscall flow**: Child syscall → kernel USER_NOTIF → Supervisor.recv() → Notification.handle() → Syscall handler or passthrough → Supervisor.send()

**FD handling**: FDs 0,1,2 (stdin/stdout/stderr) passthrough to kernel. All other FDs are virtual - the child process is spawned from scratch so no other real FDs should exist.

**VirtualFilesystem design**:
- Dual-map: `files` (path → File) persists data, `open_fds` (FD → OpenFile) tracks open state
- Files persist by path after close - reopening returns same data
- Unix permissions enforced on open (owner bits only)
- Handlers return `Result.passthrough` or `Result.handled` at runtime

**Adding a new emulated syscall:**
1. Create `src/syscalls/NewSyscall.zig` with `parse()` and `handle()` methods
2. Add variant to `Syscall` union in `syscall.zig`
3. Add case to `Syscall.parse()` switch

## Testing

**Comptime dependency injection**: `memory_bridge.zig` uses `builtin.is_test` to select implementation:
```zig
pub const MemoryBridge = if (builtin.is_test)
    @import("memory_bridge/TestingMemoryBridge.zig")
else
    @import("memory_bridge/ProcessMemoryBridge.zig");
```

**Test discovery**: Zig only runs tests from files transitively imported by the test root. Tests in standalone files (like `VirtualFilesystem.zig`, `Supervisor.zig`) must be explicitly imported in `main.zig`:
```zig
test {
    _ = @import("VirtualFilesystem.zig");
    _ = @import("Supervisor.zig");
}
```

**E2E tests**: `Supervisor.zig` contains e2e tests that construct `linux.SECCOMP.notif` structs with local buffer addresses. `TestingMemoryBridge` treats these as local pointers, enabling full syscall handler testing without a real child process.

**Logger**: Disabled during tests (`builtin.is_test`) to avoid interfering with `zig build test` IPC.

## Key Linux APIs Used
- Seccomp user notifier (`SECCOMP_SET_MODE_FILTER`, `SECCOMP_IOCTL_NOTIF_*`)
- BPF filter programs
- `process_vm_readv`/`process_vm_writev` for cross-process memory
- `pidfd_open`/`pidfd_getfd` for FD operations across processes

## Zig Guidelines
- Zig 0.16 is required, and includes a new `std.Io` module that provides a unified interface for asynchronous I/O.
- The std lib can be found in the same directory as the Zig binary, plus ./lib/std. Use grep to find the current APIs. If further documentation is needed, use https://ziglang.org/documentation/master/std/ as a reference.
- Use the installed ZLS language server for up-to-date feedback on 0.16 features. 
- Where possible, keep structs as individual files, using the file-as-struct pattern with `const Self = @This()`.
- Prefer the `try` keyword over `catch` when possible.
- Prefer to use stack buffers over heap allocation when possible.
- PascalCase for types (and functions returning types), snake_case for variables, camelCase for functions.
- Use init(...) as constructor, and a deferrable deinit(...) if destructor is needed.
- Use std.linux specific APIs rather than calling syscalls directly. When in doubt, grep std.linux. The std lib can be found in the same directory as the Zig binary, plus ./lib/std/os/linux.zig.
- Batch operations when possible - avoid syscall-per-byte patterns (e.g., use `readSlice` to read known-length buffers in one call).