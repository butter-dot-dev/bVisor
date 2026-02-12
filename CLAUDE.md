# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bVisor is an in-process Linux sandbox SDK and runtime written in Zig. It intercepts and virtualizes Linux syscalls from userspace using seccomp user notifier, providing isolation without VM overhead. Unlike gVisor (which runs as a separate service), bVisor runs directly in your application for millisecond-level sandbox lifecycle.

The goal of bVisor is to be a lightweight sandbox for untrusted user or LLM-generated code run on the server. Its most minimal implementation creates a virtualized filesystem and runs a bash command inside of it, but the goal is to increase sandboxing over time. This is intended as alternative to docker, gvisor, or other vm-based sandboxes.

**Status**: Early proof-of-concept. Core seccomp interception works; syscall virtualization is incomplete.

**Greenfield project**: No users, no backward compatibility concerns. Delete dead code freely.

## Build Commands

```bash
zig build                    # Build all targets (exe, tests, node .node binaries)
zig build test               # Run unit tests in Docker container
zig build run                # Run executable in Docker container
```


**Requires**: Zig 0.16.0-dev or later, Docker


## Architecture

**Supervisor-child process model with syscall interception:**

```
src/
  core/                 # Zig sandbox runtime
    root.zig            # Public exports for SDK usage
    main.zig            # Entry point, runs smoke test
    setup.zig           # Fork into child/supervisor, seccomp BPF installation
    Supervisor.zig      # Main loop: recv notif → handle → send response
    types.zig           # LinuxResult, Logger
    LogBuffer.zig       # Thread-safe buffered output capture (stdout/stderr)
    smoke_test.zig      # TDD-style smoke test scorecard

    seccomp/
      filter.zig        # BPF filter installation, returns notify FD
      notif.zig         # Helper to construct test notifications

    utils/              # Linux utility modules
      memory_bridge.zig # process_vm_readv/writev (test mode: local pointer access)
      pidfd.zig         # pidfd_open/pidfd_getfd (test mode: passthrough)
      proc_info.zig     # TID/TGID info, clone flags via /proc (test mode: mock maps)

    virtual/            # Virtualization layer
      OverlayRoot.zig   # Root overlay filesystem management
      path.zig          # Path routing: prefix-tree rules (block/passthrough/cow/tmp/proc)
      proc/             # Thread/process virtualization
        Threads.zig     # Manages all threads, kernel TID → Thread mapping
        Thread.zig      # Single thread: tid, thread_group, namespace, fd_table, parent/children
        ThreadGroup.zig # Thread group (process): tgid, threads map
        ThreadStatus.zig # Thread status information
        Namespace.zig   # TID namespace with refcounting, NsTid allocation
      fs/               # File descriptor virtualization
        FdTable.zig     # Per-process fd table, refcounted (shared on CLONE_FILES)
        FdEntry.zig     # Entry type in fd table, containing pointer to File and CLOEXEC flag
        File.zig        # Virtual file with Backend union and refcounting
        backend/        # File backend implementations
          passthrough.zig # Kernel FD passthrough (/dev/null, /dev/zero, /dev/random, /dev/urandom)
          cow.zig       # Copy-on-write files (default for most paths)
          tmp.zig       # Overlay-redirected /tmp files
          procfile.zig  # Virtualized /proc files
      syscall/          # Syscall handlers
        syscalls.zig    # Switch statement over syscalls, parsing notifications
        e2e_test.zig    # End-to-end syscall tests
        handlers/       # Individual syscall handlers
          openat.zig    # openat handler with path rules (block/allow/virtualize)
          close.zig     # close handler
          read.zig, write.zig, readv.zig, writev.zig  # I/O handlers
          lseek.zig     # File seek
          dup.zig, dup3.zig  # FD duplication
          fstat.zig, fstatat64.zig  # File metadata
          getpid.zig, getppid.zig, gettid.zig         # ID handlers
          exit.zig, exit_group.zig                    # Exit handlers
          kill.zig, tkill.zig                         # Signal handlers
          uname.zig     # System info (virtualizes hostname/domainname)
          sysinfo.zig   # System stats (virtualizes uptime/procs)
          lseek.zig     # repositioning file offsets
          faccessat.zig # checking user permissions to directory
          pipe2.zig     # pipe creation

  sdks/
    node/               # Node.js SDK (see src/sdks/node/CLAUDE.md)
      index.ts          # Package entry point
      src/
        sandbox.ts      # Sandbox class, public API
        native.ts       # FFI contract: NativeModule interface
        napi.ts         # External<T> phantom type for opaque native handles
      test.ts           # Smoke test (npm run dev)
      zig/              # Zig N-API bindings source
        root.zig        # Module registration entry
        napi.zig        # N-API helpers, ZigExternal(T)
        Sandbox.zig     # Sandbox implementation
        Stream.zig      # Output stream management
      platforms/        # Platform-specific npm packages with built .node binaries
    python/             # Python SDK (placeholder, not yet implemented)
```

**Syscall flow**: Child syscall → kernel USER_NOTIF → Supervisor.recv() → Notification.handle() → Syscall handler or passthrough → Supervisor.send()

**Thread virtualization** (follows Linux kernel model where threads are the basic unit):
- `Threads` tracks all sandboxed threads with kernel TID → `Thread` mapping
- ID types: `AbsTid`/`NsTid` (thread IDs), `AbsTgid`/`NsTgid` (thread group IDs, aka PIDs)
- `Thread` has `.tid`, `.thread_group`, `.namespace`, `.fd_table`, `.parent`, `.children`
- `ThreadGroup` represents a process (group of threads sharing address space)
- For the thread group leader: TID == TGID. For other threads: TID is unique, while TGID == leader's TID
- `CLONE_FILES` shares fd_table (refcounted), otherwise cloned
- `CLONE_NEWPID` creates new TID namespace, otherwise inherited
- Killing a thread kills its entire subtree (including nested namespaces)

**FD handling**: Uses virtual FD abstraction with `File.zig` containing a `Backend` union enum:
- `.passthrough` - kernel FD passthrough (from the perspective of the supervisor)
- `.proc` - virtualized `/proc` files (e.g., `/proc/self` returns guest PID)
- `.cow` - copy-on-write files
- `.tmp` - temporary files
- FDs 0,1,2 (stdin/stdout/stderr) are handled specially

**Path routing in OpenAt**:
- Paths are normalized (resolving `..`) before matching against prefix rules
- Examples: `/sys/` blocked, `/dev/null` passthrough, `/proc/` virtualized, `/tmp/` overlay-redirected, everything else COW
- For up-to-date documentation of pathing, see `path.zig`

**Adding a new emulated syscall:**
When implementing a new emulated syscall,
1. Create `src/core/virtual/syscall/handlers/{newsyscall}.zig` (lowercase) with `handle()` method
2. Update the corresponding case in the switch in `src/core/virtual/syscall/syscalls.zig`
3. Add test import in `src/core/main.zig` test block: `_ = @import("virtual/syscall/handlers/{newsyscall}.zig");`

## Testing

All tests run in Docker (`zig build test`). The test binary is cross-compiled for aarch64-linux and executed in an Alpine container.

**Test-mode behavior**: `src/core/utils/` modules use `builtin.is_test` to provide lightweight test alternatives (e.g., `memory_bridge` treats addresses as local pointers, `proc_info` uses mock maps instead of `/proc`). This allows unit tests to construct fake notifications without a real child process.

**Test discovery**: Zig only runs tests from files imported by the test root. All test files must be reachable from `src/core/main.zig` via `_ = @import(...)` in its `test` block. When adding a new file with tests, add an import there or the tests won't run.

**E2E tests**: Use `makeNotif()` from `src/seccomp/notif.zig` to construct test notifications.

**Logger**: Disabled during tests (`builtin.is_test`) to avoid interfering with `zig build test` IPC.

**Node SDK tests**: From `src/sdks/node/`, run `npm run dev`. This runs `zig build` then executes `test.ts` inside a `oven/bun:alpine` Docker container.

## Key Linux APIs Used
- Seccomp user notifier (`SECCOMP_SET_MODE_FILTER`, `SECCOMP_IOCTL_NOTIF_*`)
- BPF filter programs
- `process_vm_readv`/`process_vm_writev` for cross-process memory
- `pidfd_open`/`pidfd_getfd` for FD operations across processes

**Preference**: Use `pidfd_getfd` to access child FDs rather than `proc/pid/fd` symlinks. This is more reliable and doesn't require filesystem access.

## Zig Guidelines
- Zig 0.16 is required, and includes a new `std.Io` module that provides a unified interface for asynchronous I/O.
- We use `anyzig`, a CLI aliased as `zig` which ensures we are using the correct version of Zig. `zig build` etc runs as expected. To find the std lib source code, use `zig env` to find the path to the std lib. If further documentation is needed, use https://ziglang.org/documentation/master/std/ as a reference.
- Use the installed ZLS language server for up-to-date feedback on 0.16 features.
- Where possible, keep structs as individual files, using the file-as-struct pattern with `const Self = @This()`.
- Prefer the `try` keyword over `catch` when possible.
- Prefer enums with switches for dynamic dispatch. Inline else to enforce that all enum variants contain methods of a certain signature (see syscall.zig for ref).
- Prefer to use stack buffers over heap allocation when possible.
- PascalCase for types (and functions returning types), snake_case for variables, camelCase for functions.
- Use init(...) as constructor, and a deferrable deinit(...) if destructor is needed.
- If the lifetime of an object requires refcounting, store the refcount atomically, and use `ref()` and `unref()` to increment and decrement the count, init() to create a new object with refcount=1, and make deinit(...) private to enforce the refcount pattern. deinit should be triggered by unref() when the refcount reaches 0.
- Use std.linux specific APIs rather than calling syscalls directly. When in doubt, grep std.linux. The std lib can be found in the same directory as the Zig binary, plus `./lib/std/os/linux.zig`.
- Batch operations when possible - avoid syscall-per-byte patterns (e.g., use `readSlice` to read known-length buffers in one call).
- The std library is full of useful APIs. Before writing a new function, check if it already exists in std.

## Comment Style
- Only include comments if the code is not self-explanatory.
- Comments are intended to inform future readers about the code. Do not include commentary related to the conversations had with the user, which may look something like "Do ... (this is what we agreed on)". 
- Do NOT create section dividers like `// =============================================================================`. These are not useful and clutter the code. Do not add them.
- Do not remove or modify comments unless they are no longer accurate.