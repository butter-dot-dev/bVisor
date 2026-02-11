### bVisor is a lightweight local Linux sandbox.

bVisor is an SDK and runtime for securely running Linux workloads on your local machine.

Inspired by [gVisor](https://github.com/google/gVisor), bVisor runs programs directly on the host machine, providing isolation by intercepting and virtualizing [Linux syscalls](https://en.wikipedia.org/wiki/System_call) from userspace, allowing for secure and isolated I/O without the overhead of a virtual machine or remote infra.

Unlike gVisor, bVisor is built to run directly in your application, spinning up and tearing down sandboxes in milliseconds. This makes it ideal for ephemeral tasks commonly performed by LLM agents, such as code execution or filesystem operations.

## Usage

The bVisor sandbox runtime and TS/JS SDK can be installed via npm.
```bash
npm install bvisor
```

Example usage:
```typescript
import { Sandbox } from "bvisor";

const sb = new Sandbox();
const output = sb.runCmd("echo 'Hello, world!'");

console.log(await output.stdout());
```

This executes `echo 'Hello, world!'` inside a sandbox. Though for now, until bash is fully supported, bVisor ignores the command and runs a hardcoded smoke test instead.

Filesystem operations are safely virtualized (copy-on-write):
```typescript
sb.runCmd("echo 'Hello, world!' > /tmp/test.txt"); // only visible from this sandbox
```

Unsafe commands are blocked:
```typescript
sb.runCmd("chroot /tmp"); // error
```

Python SDK and CLI are also planned.

## Architecture

bVisor is built on [Seccomp user notifier](https://man7.org/linux/man-pages/man2/seccomp.2.html), a Linux kernel feature that allows userspace processes to intercept and optionally handle syscalls from a child process. This allows bVisor to block or mock the kernel API (such as filesystem read/write, network access, etc.) to ensure the child process remains sandboxed.

Other than the overhead of syscall emulation, child processes run natively.

bVisor is imageless, meaning it does not require a base image to run. It runs with direct visibility to the host filesystem. This allows system dependencies such as `npm` to work out of the box. Isolation is achieved via a copy-on-write overlay on top of the host filesystem. Files opened with write flags are copied to a sandbox-local directory. Read-only files are passed through to the real filesystem.

## Syscall Support

Every Linux syscall falls into one of four categories in bVisor:

#### Virtualized
Syscalls are intercepted and handled in userspace by the bVisor virtual kernel.

| | Syscalls |
|-|----------|
| File I/O | `openat`, `close`, `read`, `write`, `readv`, `writev`, `lseek`, `dup`, `dup3` |
| File metadata | `fstat`, `fstatat64` |
| Process | `getpid`, `getppid`, `gettid`, `kill`, `tkill`, `exit`, `exit_group` |
| System info | `uname`, `sysinfo` |

Note that bVisor may still call into the underlying kernel to virtualize any given syscall.

#### Passthrough
Syscalls are forwarded to the kernel unmodified. These syscalls are process-local or read-only and do not require any virtualization.

| | Syscalls |
|-|----------|
| Process | `clone`, `wait4`, `waitid` |
| Identity | `getuid`, `geteuid`, `getgid`, `getegid` |
| Memory | `brk`, `mmap`, `mprotect`, `munmap`, `mremap`, `madvise` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `rt_sigsuspend`, `rt_sigpending`, `rt_sigtimedwait`, `sigaltstack`, `restart_syscall` |
| Time | `clock_gettime`, `clock_getres`, `gettimeofday`, `nanosleep`, `clock_nanosleep` |
| Sync | `futex`, `futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv`, `set_robust_list`, `rseq` |
| Random | `getrandom` |

#### Blocked
Syscalls are blocked and return `ENOSYS`. These could allow sandbox escape or privilege escalation.

| | Syscalls |
|-|----------|
| Privilege escalation | `ptrace`, `mount`, `umount2`, `chroot`, `pivot_root`, `reboot`, `setns`, `unshare`, `seccomp`, `bpf` |
| Cross-process memory | `process_vm_readv`, `process_vm_writev` |
| Kernel modules | `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module` |
| Resource control | `setrlimit`, `prlimit64` |
| Execution domain | `personality` |

#### Roadmap
Not yet handled but likely necessary for Bash compatibility. Currently return `ENOSYS`.

| | Syscalls |
|-|----------|
| File I/O | `fcntl`, `ioctl`, `pipe2` |
| File metadata | `faccessat` |
| Directory | `getcwd`, `chdir`, `fchdir`, `getdents64`, `mkdirat`, `unlinkat` |
| Process | `execve`, `set_tid_address` |
| System info | `getrlimit`, `getrusage` |
| Networking | not started |
| Resource limits | not started (cgroups) |

<details>
<summary>See full list of other unhandled syscalls (~240)</summary>

| | Syscalls |
|-|----------|
| File I/O | `pread64`, `pwrite64`, `preadv`, `pwritev`, `preadv2`, `pwritev2`, `sendfile`, `splice`, `tee`, `vmsplice`, `readahead`, `copy_file_range` |
| File metadata | `statx`, `statfs`, `fstatfs`, `readlinkat`, `utimensat`, `truncate`, `ftruncate`, `fallocate`, `fadvise64`, `flock`, `fchmod`, `fchmodat`, `fchmodat2`, `fchown`, `fchownat`, `faccessat2`, `cachestat` |
| Directory | `mknodat`, `symlinkat`, `linkat`, `renameat`, `renameat2` |
| Process | `execveat`, `clone3`, `tgkill`, `prctl`, `pidfd_open`, `pidfd_getfd`, `pidfd_send_signal`, `kcmp`, `userfaultfd` |
| System info | `syslog`, `umask`, `getcpu`, `acct`, `vhangup`, `sethostname`, `setdomainname` |
| Identity (write) | `setuid`, `setgid`, `setreuid`, `setregid`, `setresuid`, `getresuid`, `setresgid`, `getresgid`, `setfsuid`, `setfsgid`, `getgroups`, `setgroups`, `setpriority`, `getpriority` |
| Session/pgid | `setpgid`, `getpgid`, `getsid`, `setsid` |
| Memory | `msync`, `mlock`, `munlock`, `mlockall`, `munlockall`, `mincore`, `remap_file_pages`, `mbind`, `get_mempolicy`, `set_mempolicy`, `set_mempolicy_home_node`, `migrate_pages`, `move_pages`, `process_madvise`, `mlock2`, `memfd_create`, `memfd_secret`, `map_shadow_stack`, `pkey_mprotect`, `pkey_alloc`, `pkey_free`, `mseal`, `membarrier`, `process_mrelease` |
| Signals | `rt_sigqueueinfo`, `rt_tgsigqueueinfo`, `signalfd4` |
| Time | `clock_settime`, `clock_adjtime`, `settimeofday`, `adjtimex`, `getitimer`, `setitimer`, `times`, `timer_create`, `timer_gettime`, `timer_getoverrun`, `timer_settime`, `timer_delete`, `timerfd_create`, `timerfd_settime`, `timerfd_gettime` |
| Networking | `socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`, `connect`, `getsockname`, `getpeername`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`, `shutdown`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg` |
| Polling/events | `epoll_create1`, `epoll_ctl`, `epoll_pwait`, `epoll_pwait2`, `pselect6`, `ppoll`, `eventfd2` |
| File sync | `sync`, `fsync`, `fdatasync`, `sync_file_range`, `syncfs` |
| File handles | `name_to_handle_at`, `open_by_handle_at`, `openat2`, `close_range` |
| Async I/O | `io_setup`, `io_destroy`, `io_submit`, `io_cancel`, `io_getevents`, `io_pgetevents`, `io_uring_setup`, `io_uring_enter`, `io_uring_register` |
| IPC | `mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`, `mq_notify`, `mq_getsetattr`, `msgget`, `msgctl`, `msgrcv`, `msgsnd`, `semget`, `semctl`, `semtimedop`, `semop`, `shmget`, `shmctl`, `shmat`, `shmdt` |
| Extended attributes | `setxattr`, `lsetxattr`, `fsetxattr`, `getxattr`, `lgetxattr`, `fgetxattr`, `listxattr`, `llistxattr`, `flistxattr`, `removexattr`, `lremovexattr`, `fremovexattr`, `setxattrat`, `getxattrat`, `listxattrat`, `removexattrat` |
| Scheduling | `sched_setparam`, `sched_setscheduler`, `sched_getscheduler`, `sched_getparam`, `sched_setaffinity`, `sched_getaffinity`, `sched_yield`, `sched_get_priority_max`, `sched_get_priority_min`, `sched_rr_get_interval`, `sched_setattr`, `sched_getattr` |
| Capabilities | `capget`, `capset` |
| Mount/namespace | `mount_setattr`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `open_tree`, `open_tree_attr`, `statmount`, `listmount` |
| Security | `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`, `lsm_get_self_attr`, `lsm_set_self_attr`, `lsm_list_modules` |
| Keys | `add_key`, `request_key`, `keyctl` |
| Inotify/fanotify | `inotify_init1`, `inotify_add_watch`, `inotify_rm_watch`, `fanotify_init`, `fanotify_mark` |
| I/O priority | `ioprio_set`, `ioprio_get` |
| Swap | `swapon`, `swapoff` |
| Misc | `nfsservctl`, `quotactl`, `quotactl_fd`, `lookup_dcookie`, `perf_event_open`, `get_robust_list`, `file_getattr`, `file_setattr` |

</details>

## Development Guide

#### Zig
bVisor is written in Zig. Zig is pre-1.0, so compilation is only guaranteed with the exact zig build. We're using a tagged commit on 0.16 dev, which includes major breaking changes (Io) compared to previous versions, so please use the exact version specified in the `build.zig.zon` file. It's also recommended to compile ZLS from source using a tagged commit compatible with Zig. You'll be flying blind otherwise.

#### Cross-compilation
bVisor depends on Linux kernel features, although it's developed primarily on ARM Macs. Zig cross-compiles to Linux, and all tests run in Docker.

```bash
zig build        # Cross-compile for all targets (exe, tests, N-API .node binaries)
zig build test   # Unit tests in Docker container
zig build run    # E2E smoke test in Docker (scorecard of supported syscalls)
```
