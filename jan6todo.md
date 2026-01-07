# bVisor: TDD Security Sprint

**Vision**: gVisor's security model + QuickJS's ergonomics = embeddable, millisecond-startup Linux sandboxes.

---

# Sprint Goal: Test-Driven Security

## The TDD Loop

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. WRITE FAILING TESTS                                             │
│     - Document known escapes (runc CVEs, gVisor issues, etc.)       │
│     - Encode as executable test cases                               │
│     - Run against current bVisor (in docker) → watch them FAIL      │
│                                                                     │
│  2. IMPLEMENT FIX                                                   │
│     - Add syscall handler (virtualize)                              │
│     - Or add to block list (return -EPERM)                          │
│     - Or fix existing handler logic                                 │
│                                                                     │
│  3. RUN TESTS → PASS                                                │
│     - Verify escape is blocked                                      │
│     - Verify no regressions                                         │
│                                                                     │
│  4. REPEAT                                                          │
└─────────────────────────────────────────────────────────────────────┘
```

## Sprint Deliverables

1. **Executable test suite** (`test/exec-in-docker/`) - Shell scripts that run in Docker, exit 0 on pass, exit 1 on fail
2. **CVE regression tests** - Every documented runc/gVisor/containerd escape encoded as a test
3. **Syscall coverage map** - Which syscalls are virtualized, passed through, or blocked
4. **Hardened bVisor** - All security tests passing

## Success Criteria

```bash
# This command should exit 0 with all tests passing
./test/run-exec-in-docker-suite.sh
```

---

# Known Escapes to Test Against

These are real CVEs and escape techniques from runc, gVisor, containerd, and Firecracker. Each becomes a test case.

## File Descriptor Leaks

### CVE-2024-21626: runc FD Leak (CVSS 8.6)
**What**: File descriptors leaked into container, including handle to host's `/sys/fs/cgroup`
**Attack**: Set `process.cwd` to `/proc/self/fd/7/` to access host filesystem
**Test**:
```bash
# test/security/cve-2024-21626-fd-leak.sh
#!/bin/bash
set -e
docker run --rm --security-opt seccomp=unconfined -v ./zig-out:/zig-out:ro alpine /bin/sh -c '
  # Attempt to access high-numbered FDs that might leak to host
  LEAKED=0
  for fd in 3 4 5 6 7 8 9 10; do
    if /zig-out/bin/bVisor /bin/sh -c "cat /proc/self/fd/$fd 2>/dev/null" | grep -q "cgroup\|host"; then
      echo "FAIL: FD $fd leaks host access"
      LEAKED=1
    fi
  done
  [ $LEAKED -eq 0 ] && echo "PASS: No FD leaks detected"
  exit $LEAKED
'
```

### CVE-2019-5736: /proc/self/exe Overwrite (CVSS 8.6)
**What**: Container can overwrite host's runc binary via /proc/self/exe
**Attack**: Open /proc/self/exe for writing, replace runtime binary
**Test**:
```bash
# test/security/cve-2019-5736-proc-self-exe.sh
#!/bin/bash
set -e
docker run --rm --security-opt seccomp=unconfined -v ./zig-out:/zig-out:ro alpine /bin/sh -c '
  BEFORE=$(md5sum /zig-out/bin/bVisor | cut -d" " -f1)

  # Attempt to overwrite via /proc/self/exe
  /zig-out/bin/bVisor /bin/sh -c "echo PWNED > /proc/self/exe" 2>/dev/null || true

  AFTER=$(md5sum /zig-out/bin/bVisor | cut -d" " -f1)

  if [ "$BEFORE" = "$AFTER" ]; then
    echo "PASS: /proc/self/exe protected"
    exit 0
  else
    echo "FAIL: Binary was modified!"
    exit 1
  fi
'
```

## /proc and /sys Escapes

### CVE-2025-52565: /proc/sysrq-trigger (CVSS 7.3)
**What**: Write to /proc/sysrq-trigger can crash/reboot host
**Attack**: `echo b > /proc/sysrq-trigger` triggers immediate reboot
**Test**:
```bash
# test/security/cve-2025-52565-sysrq.sh
#!/bin/bash
set -e
docker run --rm --security-opt seccomp=unconfined -v ./zig-out:/zig-out:ro alpine /bin/sh -c '
  # If this succeeds and we are still running, the write was blocked/virtualized
  /zig-out/bin/bVisor /bin/sh -c "echo b > /proc/sysrq-trigger" 2>/dev/null || true
  echo "PASS: Host did not reboot (sysrq blocked)"
  exit 0
'
```

### CVE-2025-52881: /proc/sys/kernel/core_pattern (CVSS 7.3)
**What**: Write to core_pattern executes arbitrary command on host when process crashes
**Attack**: `echo "|/malicious" > /proc/sys/kernel/core_pattern`
**Test**:
```bash
# test/security/cve-2025-52881-core-pattern.sh
#!/bin/bash
set -e
docker run --rm --security-opt seccomp=unconfined -v ./zig-out:/zig-out:ro alpine /bin/sh -c '
  BEFORE=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "UNREADABLE")

  /zig-out/bin/bVisor /bin/sh -c "echo \"|/malicious\" > /proc/sys/kernel/core_pattern" 2>/dev/null || true

  AFTER=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "UNREADABLE")

  if [ "$BEFORE" = "$AFTER" ]; then
    echo "PASS: core_pattern unchanged"
    exit 0
  else
    echo "FAIL: core_pattern was modified!"
    exit 1
  fi
'
```

## Symlink and Path Traversal

### CVE-2021-30465: Symlink-Exchange Mount Escape
**What**: TOCTOU race swapping symlink during mount
**Test**:
```bash
# test/security/symlink-escape.sh
#!/bin/bash
set -e
docker run --rm --security-opt seccomp=unconfined -v ./zig-out:/zig-out:ro alpine /bin/sh -c '
  # Attempt symlink to escape
  /zig-out/bin/bVisor /bin/sh -c "ln -s /etc/passwd /tmp/escape && cat /tmp/escape" 2>/dev/null || true

  # Symlink should not exist in container filesystem
  if [ -L /tmp/escape ]; then
    echo "FAIL: Symlink escaped to container filesystem"
    exit 1
  fi
  echo "PASS: Symlink contained in VFS"
  exit 0
'
```

### Path Traversal
**Test**:
```bash
# test/security/path-traversal.sh
#!/bin/bash
set -e
docker run --rm --security-opt seccomp=unconfined -v ./zig-out:/zig-out:ro alpine /bin/sh -c '
  BEFORE=$(md5sum /etc/passwd | cut -d" " -f1)

  /zig-out/bin/bVisor /bin/sh -c "echo PWNED > /../../../etc/passwd" 2>/dev/null || true
  /zig-out/bin/bVisor /bin/sh -c "echo PWNED > /....//....//etc/passwd" 2>/dev/null || true

  AFTER=$(md5sum /etc/passwd | cut -d" " -f1)

  if [ "$BEFORE" = "$AFTER" ]; then
    echo "PASS: Path traversal blocked"
    exit 0
  else
    echo "FAIL: /etc/passwd modified via traversal"
    exit 1
  fi
'
```

## Resource Exhaustion

### Fork Bomb
**Test**:
```bash
# test/security/fork-bomb.sh
#!/bin/bash
set -e
timeout 10 docker run --rm --security-opt seccomp=unconfined -v ./zig-out:/zig-out:ro alpine \
  /zig-out/bin/bVisor /bin/sh -c ':(){ :|:& };:' 2>/dev/null || true
echo "PASS: Fork bomb contained (did not hang host)"
exit 0
```

### Memory Exhaustion
**Test**:
```bash
# test/security/memory-exhaustion.sh
#!/bin/bash
set -e
timeout 10 docker run --rm --security-opt seccomp=unconfined -v ./zig-out:/zig-out:ro alpine \
  /zig-out/bin/bVisor /bin/sh -c 'dd if=/dev/zero of=/dev/null bs=1G count=100' 2>/dev/null || true
echo "PASS: Memory exhaustion contained"
exit 0
```

---

# Syscall Reference

Every Linux syscall must be categorized. This is the complete map for bVisor.

## Legend
- **V** = VIRTUALIZE (reimplement in Zig, return synthetic result)
- **P** = PASSTHROUGH (let kernel handle, namespace/cgroup contains)
- **B** = BLOCK (return -EPERM or -ENOSYS)
- **?** = TODO (needs decision)

## Filesystem Syscalls

| Syscall | Status | Notes |
|---------|--------|-------|
| `openat` | **V** | Virtualize writes (O_WRONLY/O_RDWR/O_CREAT), passthrough reads |
| `open` | **V** | Legacy, same as openat |
| `read` | **V** | Virtual FDs return VFS data, kernel FDs passthrough |
| `write` | **V** | Virtual FDs write to VFS, kernel FDs passthrough (or COW) |
| `close` | **V** | Track FD lifecycle |
| `readv` | **V** | Scatter read from VFS |
| `writev` | **V** | Gather write to VFS |
| `pread64` | **V** | Positional read |
| `pwrite64` | **V** | Positional write |
| `lseek` | **V** | Track offset in VFS |
| `stat` | **V** | Return VFS metadata for virtual files, passthrough for real |
| `fstat` | **V** | Same as stat for FDs |
| `lstat` | **V** | Stat without following symlinks |
| `statx` | **V** | Extended stat |
| `access` | **V** | Check VFS permissions |
| `faccessat` | **V** | Same with dirfd |
| `mkdir` | **V** | Create in VFS only |
| `mkdirat` | **V** | Same with dirfd |
| `rmdir` | **V** | Remove from VFS only |
| `unlink` | **V** | Remove from VFS only |
| `unlinkat` | **V** | Same with dirfd |
| `rename` | **V** | Move within VFS |
| `renameat` | **V** | Same with dirfd |
| `link` | **V** | Hardlink in VFS |
| `linkat` | **V** | Same with dirfd |
| `symlink` | **V** | Symlink in VFS |
| `symlinkat` | **V** | Same with dirfd |
| `readlink` | **V** | Read VFS symlink |
| `readlinkat` | **V** | Same with dirfd |
| `getdents64` | **V** | List VFS directory |
| `getcwd` | **P** | Current working directory (passthrough OK) |
| `chdir` | **P** | Change directory (passthrough OK) |
| `fchdir` | **P** | Same with FD |
| `chmod` | **V** | VFS permissions only |
| `fchmod` | **V** | Same with FD |
| `chown` | **V** | VFS ownership only (no real effect) |
| `fchown` | **V** | Same with FD |
| `truncate` | **V** | Truncate VFS file |
| `ftruncate` | **V** | Same with FD |
| `utimensat` | **V** | VFS timestamps |
| `fsync` | **P** | No-op for VFS, passthrough for kernel FDs |
| `fdatasync` | **P** | Same |
| `sync` | **P** | Passthrough (affects host, but harmless) |

## Process Syscalls

| Syscall | Status | Notes |
|---------|--------|-------|
| `fork` | **P** | PID namespace contains children |
| `vfork` | **P** | Same |
| `clone` | **P** | Same (block CLONE_NEWUSER, CLONE_NEWNS escape attempts) |
| `clone3` | **P** | Same |
| `execve` | **P** | Stays in sandbox |
| `execveat` | **P** | Same |
| `exit` | **P** | Normal exit |
| `exit_group` | **P** | Same |
| `wait4` | **P** | Wait for children |
| `waitid` | **P** | Same |
| `getpid` | **P** | Returns namespace PID |
| `getppid` | **P** | Same |
| `gettid` | **P** | Same |
| `getuid` | **P** | Returns namespace UID |
| `getgid` | **P** | Same |
| `geteuid` | **P** | Same |
| `getegid` | **P** | Same |
| `setuid` | **B** | Block privilege changes |
| `setgid` | **B** | Same |
| `setreuid` | **B** | Same |
| `setregid` | **B** | Same |
| `setresuid` | **B** | Same |
| `setresgid` | **B** | Same |
| `getgroups` | **P** | Passthrough |
| `setgroups` | **B** | Block |
| `setsid` | **P** | Session management OK |
| `setpgid` | **P** | Process group OK |
| `getpgid` | **P** | Same |
| `getsid` | **P** | Same |
| `kill` | **P** | PID namespace restricts targets |
| `tkill` | **P** | Same |
| `tgkill` | **P** | Same |
| `ptrace` | **B** | Block entirely - escape vector |
| `prctl` | **?** | Selective - block dangerous options |

## Memory Syscalls

| Syscall | Status | Notes |
|---------|--------|-------|
| `mmap` | **P** | Cgroup memory limit contains |
| `munmap` | **P** | Same |
| `mprotect` | **P** | Same |
| `mremap` | **P** | Same |
| `brk` | **P** | Same |
| `msync` | **P** | Same |
| `madvise` | **P** | Same |
| `mlock` | **P** | Cgroup limit contains |
| `munlock` | **P** | Same |
| `mlockall` | **P** | Same |
| `munlockall` | **P** | Same |

## Network Syscalls

| Syscall | Status | Notes |
|---------|--------|-------|
| `socket` | **P/V** | Network namespace isolates; virtualize for port mapping |
| `connect` | **P/V** | Block localhost unless virtual port |
| `bind` | **P/V** | Virtualize port allocation |
| `listen` | **P/V** | Same |
| `accept` | **P/V** | Same |
| `accept4` | **P/V** | Same |
| `sendto` | **P** | Network namespace isolates |
| `recvfrom` | **P** | Same |
| `sendmsg` | **P** | Same |
| `recvmsg` | **P** | Same |
| `shutdown` | **P** | Same |
| `getsockname` | **P** | Same |
| `getpeername` | **P** | Same |
| `setsockopt` | **P** | Same |
| `getsockopt` | **P** | Same |
| `socketpair` | **P** | Same |

## Signal Syscalls

| Syscall | Status | Notes |
|---------|--------|-------|
| `rt_sigaction` | **P** | Signal handling OK |
| `rt_sigprocmask` | **P** | Same |
| `rt_sigreturn` | **P** | Same |
| `sigaltstack` | **P** | Same |
| `rt_sigsuspend` | **P** | Same |
| `rt_sigpending` | **P** | Same |
| `rt_sigtimedwait` | **P** | Same |
| `rt_sigqueueinfo` | **P** | Same |

## Time Syscalls

| Syscall | Status | Notes |
|---------|--------|-------|
| `clock_gettime` | **P** | Passthrough (time observation OK) |
| `clock_nanosleep` | **P** | Same |
| `nanosleep` | **P** | Same |
| `gettimeofday` | **P** | Same |
| `time` | **P** | Same |
| `times` | **P** | Same |
| `clock_getres` | **P** | Same |
| `clock_settime` | **B** | Block - affects host |
| `settimeofday` | **B** | Same |
| `adjtimex` | **B** | Same |

## IPC Syscalls

| Syscall | Status | Notes |
|---------|--------|-------|
| `pipe` | **P** | OK within sandbox |
| `pipe2` | **P** | Same |
| `eventfd` | **P** | Same |
| `eventfd2` | **P** | Same |
| `epoll_create` | **P** | Same |
| `epoll_create1` | **P** | Same |
| `epoll_ctl` | **P** | Same |
| `epoll_wait` | **P** | Same |
| `epoll_pwait` | **P** | Same |
| `poll` | **P** | Same |
| `ppoll` | **P** | Same |
| `select` | **P** | Same |
| `pselect6` | **P** | Same |
| `futex` | **P** | Same |
| `shmget` | **?** | IPC namespace may isolate |
| `shmat` | **?** | Same |
| `shmdt` | **?** | Same |
| `shmctl` | **?** | Same |
| `semget` | **?** | Same |
| `semop` | **?** | Same |
| `semctl` | **?** | Same |
| `msgget` | **?** | Same |
| `msgsnd` | **?** | Same |
| `msgrcv` | **?** | Same |
| `msgctl` | **?** | Same |

## Dangerous Syscalls (BLOCK ALL)

| Syscall | Status | Notes |
|---------|--------|-------|
| `mount` | **B** | Escape vector |
| `umount2` | **B** | Same |
| `pivot_root` | **B** | Same |
| `chroot` | **B** | Same |
| `setns` | **B** | Namespace escape |
| `unshare` | **B** | Same (except initial setup) |
| `init_module` | **B** | Kernel manipulation |
| `finit_module` | **B** | Same |
| `delete_module` | **B** | Same |
| `kexec_load` | **B** | Same |
| `kexec_file_load` | **B** | Same |
| `reboot` | **B** | Host disruption |
| `swapon` | **B** | Same |
| `swapoff` | **B** | Same |
| `acct` | **B** | Same |
| `iopl` | **B** | Hardware access |
| `ioperm` | **B** | Same |
| `create_module` | **B** | Kernel manipulation |
| `query_module` | **B** | Same |
| `quotactl` | **B** | Disk quotas |
| `nfsservctl` | **B** | NFS |
| `personality` | **B** | Execution domain |
| `uselib` | **B** | Legacy |
| `ustat` | **B** | Legacy |
| `sysfs` | **B** | Legacy |
| `vhangup` | **B** | Terminal |
| `modify_ldt` | **B** | x86 specific |
| `_sysctl` | **B** | Legacy |
| `kcmp` | **B** | Process comparison |
| `seccomp` | **B** | Don't let child modify filter |
| `bpf` | **B** | eBPF programs |
| `userfaultfd` | **B** | Page fault handling |
| `perf_event_open` | **B** | Performance monitoring |
| `lookup_dcookie` | **B** | Profiling |
| `fanotify_init` | **B** | File monitoring |
| `fanotify_mark` | **B** | Same |
| `name_to_handle_at` | **B** | File handle escape |
| `open_by_handle_at` | **B** | Same - used in escapes |
| `clock_adjtime` | **B** | Time manipulation |
| `process_vm_readv` | **B** | Cross-process memory |
| `process_vm_writev` | **B** | Same |
| `memfd_create` | **?** | Useful but potential escape |
| `memfd_secret` | **B** | Secret memory |
| `landlock_create_ruleset` | **?** | Security policy |
| `landlock_add_rule` | **?** | Same |
| `landlock_restrict_self` | **?** | Same |
| `io_uring_setup` | **B** | Async I/O - complex attack surface |
| `io_uring_enter` | **B** | Same |
| `io_uring_register` | **B** | Same |

## Special /proc and /sys Paths

| Path | Status | Notes |
|------|--------|-------|
| `/proc/self/exe` | **V** | Return virtualized or block write |
| `/proc/self/fd/*` | **V** | Only show sandbox FDs |
| `/proc/self/mem` | **B** | Block - memory access |
| `/proc/self/root` | **V** | Return sandbox root |
| `/proc/self/cwd` | **V** | Return sandbox cwd |
| `/proc/self/environ` | **V** | Filter sensitive vars |
| `/proc/[pid]/*` | **V** | Only sandbox PIDs visible |
| `/proc/sysrq-trigger` | **B** | Host crash |
| `/proc/sys/kernel/core_pattern` | **B** | Code execution |
| `/proc/sys/kernel/modprobe` | **B** | Module loading |
| `/proc/sys/vm/*` | **B** | Memory configuration |
| `/proc/kcore` | **B** | Kernel memory |
| `/proc/kmem` | **B** | Same |
| `/proc/kallsyms` | **B** | Kernel symbols |
| `/sys/fs/cgroup/*` | **B** | Cgroup escape |
| `/sys/kernel/*` | **B** | Kernel parameters |
| `/sys/devices/virtual/powercap/*` | **B** | RAPL side-channel |

---

# Why bVisor Exists

LLM agents need to execute code. Current options all have fatal flaws:

| Option | Fatal Flaw |
|--------|------------|
| **Remote sandboxes** (E2B, Modal) | Network latency + cold boot = seconds. Overkill for `2+2`. |
| **Docker-in-docker** | Most cloud providers don't support it. Weak isolation anyway. |
| **Language VMs** (QuickJS, WASM) | Not full Linux. Can't run `npm install` or `python script.py`. |
| **Browser emulation** (WebVM) | 100x slower than native due to hardware emulation. Dead end. |

**The insight**: Seccomp USER_NOTIF intercepts syscalls at **native speed** - not emulated, just paused. This gives gVisor's power (syscall-level control) without gVisor's overhead (Go runtime, OCI complexity, 500ms startup).

**The product**: Embeddable Linux sandbox as a library.

```python
from bvisor import Sandbox

with Sandbox() as sb:
    sb.bash("pip install requests")
    sb.bash("python script.py")
    output = sb.read_file("/output.json")
    # Writes contained, full Linux, milliseconds overhead
```

---

# What bVisor Is

| Property | Description |
|----------|-------------|
| **Embeddable library** | Import into Python/TS/Go, not a separate runtime |
| **gVisor-level isolation** | Syscall interception, not just namespaces |
| **Full Linux** | bash, python, npm, curl, gcc - everything works |
| **Millisecond startup** | <10ms to spawn, not 500ms container boot |
| **Native speed** | Passthrough syscalls have ~0 overhead |
| **Virtual filesystem** | Writes contained in-memory, reads passthrough (COW) |
| **Virtual network** | Outbound allowed, inbound controlled via port mapping |

# What bVisor is NOT

- NOT a container runtime (no OCI, no images)
- NOT a VM (no hypervisor, runs on host kernel)
- NOT a remote service (no network hop)
- NOT persistent (ephemeral by design)

---

# Target API

## Python (Primary)
```python
from bvisor import Sandbox, SandboxConfig

config = SandboxConfig(
    timeout_ms=5000,
    memory_limit_mb=256,
    network_outbound=True,
    port_mappings={8080: 0},  # Map sandbox:8080 to random host port
)

with Sandbox(config) as sb:
    sb.write_file("/input.json", data)
    result = sb.bash("python process.py")
    output = sb.read_file("/output.json")
```

## CLI (Testing/Debugging)
```bash
bVisor --timeout 5000 --memory 256 -- /bin/sh -c "echo hello"
```

---

# Syscall Strategy

**Design principle**: Intercept via seccomp USER_NOTIF. Virtualize what's dangerous. Passthrough what's safe. Block what's unnecessary.

```
VIRTUALIZE (reimplement in Zig):
├── Filesystem writes: openat(O_WRONLY), write, writev, mkdir, unlink
├── Filesystem metadata: stat, fstat, readdir (for virtual files)
├── /proc access: open("/proc/..."), reads on /proc FDs
└── Sensitive paths: /sys/*, /dev/* (selective blocking)

PASSTHROUGH (kernel handles, namespaces contain):
├── Filesystem reads: openat(O_RDONLY), read, readv, lseek
├── Memory: mmap, mprotect, brk (cgroup-limited)
├── Process: fork, exec, exit, wait (PID namespace isolates)
├── Time: clock_gettime, nanosleep
└── Signals: rt_sigaction, rt_sigprocmask

BLOCK (return -EPERM):
├── Kernel: init_module, delete_module, kexec_load
├── Privilege: setuid, setgid, capset
├── Escape: setns, unshare, ptrace, mount, pivot_root
└── Dangerous: chroot, reboot, swapon
```

**Namespaces/cgroups are defense-in-depth**, not primary isolation. Syscall interception is primary.

---

# Configuration Scope

## Filesystem
- **Virtual writes** (in-memory VFS) - CURRENT, working
- **Read passthrough** (COW on write) - CURRENT, working
- **write_file() API** - NEW, inject files before exec
- **read_file() API** - NEW, extract files after exec
- **Virtual /proc** - NEW, return sandbox-scoped data

## Network
- **Outbound**: ALLOWED (like Docker)
- **Inbound**: BLOCKED unless port mapped
- **Localhost**: BLOCKED unless to virtual ports
- **Implementation**: Network namespace + iptables, upgrade to syscall interception if needed

## Resource Limits (via cgroups v2)
- Execution timeout (supervisor timer)
- Memory limit (memory.max)
- Max processes (pids.max)
- CPU time (cpu.max)
- VFS size (supervisor-enforced)

## Process Spawning
- fork/exec: PASSTHROUGH (PID namespace isolates)
- All descendants tracked, killed on sandbox destroy
- ps shows only sandbox processes (virtual /proc)

---

# Safe Testing Harness

**All tests run in Docker. Host machine never executes untrusted code.**

```
┌─────────────────────────────────────────────────────────┐
│  macOS Host (PROTECTED)                                 │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Docker Container (Alpine) - ISOLATION LAYER 1   │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │  bVisor Supervisor - ISOLATION LAYER 2     │  │  │
│  │  │  ┌───────────────────────────────────────┐  │  │  │
│  │  │  │  Sandboxed Child (untrusted code)    │  │  │  │
│  │  │  └───────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Base Test Command
```bash
docker run --rm \
  --security-opt seccomp=unconfined \
  -v ./zig-out:/zig-out:ro \
  alpine \
  /zig-out/bin/bVisor /bin/sh -c '<COMMAND>'
```

**Why seccomp=unconfined**: bVisor installs its own seccomp filter. Docker's would conflict.

**Why :ro**: Binary mount is read-only. Never writable.

## Test Pattern
```bash
docker run --rm --security-opt seccomp=unconfined -v ./zig-out:/zig-out:ro alpine /bin/sh -c '
  # Run bVisor
  /zig-out/bin/bVisor /bin/sh -c "echo ESCAPE > /test.txt"

  # Assert: file must NOT exist in real filesystem
  [ ! -f /test.txt ] && echo "PASS" || echo "FAIL: escape detected"
'
```

---

# TDD Test Cases

## Phase 1: Filesystem Isolation (Current Focus)

| Test | Command | Pass Condition |
|------|---------|----------------|
| 1.1 Write containment | `echo X > /test.txt` | File not in container FS |
| 1.2 /etc/passwd protection | `echo X >> /etc/passwd` | /etc/passwd unchanged |
| 1.3 Read passthrough | `cat /etc/hostname` | Returns real hostname |
| 1.4 COW semantics | `cat /etc/hostname; echo X >> /etc/hostname; cat /etc/hostname` | Real file unchanged, sandbox sees modification |
| 1.5 Path traversal | `echo X > /../../../etc/passwd` | /etc/passwd unchanged |
| 1.6 Symlink containment | `ln -s /etc/passwd /tmp/link` | Symlink not in container FS |
| 1.7 File deletion blocked | Create file, `rm` it via bVisor | File still exists |

## Phase 2: /proc Protection (CVE Prevention)

| Test | Command | Pass Condition |
|------|---------|----------------|
| 2.1 /proc/sysrq-trigger | `echo b > /proc/sysrq-trigger` | No host reboot |
| 2.2 /proc/sys/kernel/core_pattern | `echo X > /proc/sys/kernel/core_pattern` | core_pattern unchanged |
| 2.3 /proc/self/exe | `cat /proc/self/exe` | Blocked or virtualized |
| 2.4 /proc/self/fd leak | `ls /proc/self/fd` | Only sandbox FDs visible |

## Phase 3: Process Isolation

| Test | Command | Pass Condition |
|------|---------|----------------|
| 3.1 External kill blocked | Start sleep outside, `kill` it from sandbox | Process survives |
| 3.2 Fork bomb contained | `:(){ :\|:& };:` | Container survives (timeout) |
| 3.3 ps shows sandbox only | `ps aux` | Only sandbox processes |

## Phase 4: Network

| Test | Command | Pass Condition |
|------|---------|----------------|
| 4.1 Outbound works | `wget http://example.com` | Success |
| 4.2 Localhost blocked | `curl localhost:22` | Blocked |
| 4.3 Port mapping | Start server on 8080, curl from outside | Works via mapped port |

## Phase 5: Resource Limits

| Test | Command | Pass Condition |
|------|---------|----------------|
| 5.1 Timeout | `sleep 100` with 1s timeout | Killed after 1s |
| 5.2 Memory limit | Allocate 1GB with 256MB limit | OOM killed |
| 5.3 VFS size limit | Write 1GB with 100MB limit | Write fails |

---

# Implementation Priority

## Now: Core Filesystem (make bash work)
1. Expand VFS: mkdir, readdir, stat, fstat, unlink
2. Virtual /proc: intercept reads, return sandbox-scoped data
3. Block dangerous paths: /sys/fs/cgroup, /proc/sysrq-trigger, etc.

## Next: Resource Limits
4. cgroups v2 integration: memory, pids, cpu
5. Supervisor timeout enforcement
6. VFS size tracking and limits

## Then: Network
7. Network namespace setup
8. Port mapping via iptables
9. Localhost blocking (except virtual ports)

## Finally: Language Bindings
10. Python bindings (PyO3 or FFI)
11. TypeScript bindings (NAPI or FFI)
12. Go bindings (cgo)

---

# Security Model

## What bVisor Protects Against
- Filesystem escape (writes go to VFS, not host)
- Data exfiltration via filesystem (reads COW, writes contained)
- Process interference (PID namespace)
- Resource exhaustion (cgroups)
- Common CVEs (FD leaks, /proc escapes, symlink attacks)

## What bVisor Does NOT Protect Against
- Kernel exploits (shared kernel with host - use Docker as outer layer)
- Hardware side-channels (Spectre, etc.)
- Timing attacks
- Sophisticated attackers with 0-days

## Defense in Depth
Always run bVisor inside Docker/VM in production. bVisor is Layer 2 isolation. Docker/VM is Layer 1.

---

# References

- [gVisor Security Model](https://gvisor.dev/docs/architecture_guide/security/)
- [Firecracker Design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
- [seccomp USER_NOTIF](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
- [CVE-2024-21626 (runc FD leak)](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)
- [CVE-2019-5736 (/proc/self/exe)](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)
