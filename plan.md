# Filesystem Refactor Plan

## Goal

Refactor the filesystem layer so syscall handlers just call `file.read()` / `file.write()` / `file.close()` without caring about file types or paths. Mirror the syscall dispatch pattern: path resolution determines file type, file types own their behavior.

**Key principle:** Use `posix` types internally. Convert `linux.*` ↔ `posix.*` only at syscall boundaries.

---

## Architecture

```
Syscall Boundary              Path Resolution              File Types
(linux types)                 (posix types)                (posix types)
      │                            │                            │
linux.O ──convert──→ posix.O ──→ resolve() ──→ FileType.open() ──→ File
      │                                                          │
      │                                                     file.read/write
      │                                                          │
      ←─────────────────── error ──convert──→ linux.E ───────────┘
```

- **Inbound:** `linux.O` → `posix.O` conversion happens ONCE in openat handler
- **Outbound:** Zig error → `linux.E` conversion happens ONCE when building response
- **Internal:** Everything uses `posix.O`, standard Zig errors

---

## New File Structure

```
src/virtual/fs/
  path.zig              # Path normalization, rules, resolve() → FileType
  File.zig              # Tagged union with inline else dispatch
  files/
    Readonly.zig        # Read-only host file access (file-as-struct)
    Tmp.zig             # Sandboxed /tmp (file-as-struct)
    Cow.zig             # Copy-on-write (file-as-struct)
    Proc.zig            # Virtualized /proc (file-as-struct)
```

---

## Type Conversions (at syscall boundary only)

### Flag Conversion (inline in openat handler)

```zig
fn linuxOToPosixO(flags: linux.O) posix.O {
    return .{
        .ACCMODE = switch (flags.ACCMODE) {
            .RDONLY => .RDONLY,
            .WRONLY => .WRONLY,
            .RDWR => .RDWR,
        },
        .CREAT = flags.CREAT,
        .EXCL = flags.EXCL,
        .TRUNC = flags.TRUNC,
        .APPEND = flags.APPEND,
        .NONBLOCK = flags.NONBLOCK,
        .CLOEXEC = flags.CLOEXEC,
        .DIRECTORY = flags.DIRECTORY,
    };
}
```

### Error Conversion (inline in response helpers)

```zig
// NOTE: No else case - explicitly handle all errors to avoid hidden behavior.
// A finite error set will be defined in a future PR.
fn errToErrno(err: anyerror) linux.E {
    return switch (err) {
        error.AccessDenied => .ACCES,
        error.PermissionDenied => .PERM,
        error.FileNotFound => .NOENT,
        error.IsDir => .ISDIR,
        error.NotDir => .NOTDIR,
        error.SymLinkLoop => .LOOP,
        error.NoSpaceLeft => .NOSPC,
        error.PathAlreadyExists => .EXIST,
        error.FileTooBig => .FBIG,
        error.NoDevice => .NODEV,
        error.DeviceBusy, error.FileBusy => .BUSY,
        error.WouldBlock => .AGAIN,
        error.NameTooLong => .NAMETOOLONG,
        error.SystemResources => .NOMEM,
        error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => .MFILE,
        error.ReadOnlyFileSystem => .ROFS,
        error.InvalidArgument => .INVAL,
        // Add more as needed - no else case
    };
}
```

---

## Key Types

### `path.zig` - Path Resolution

```zig
pub const FileType = enum {
    readonly,
    tmp,
    cow,
    proc,
    blocked,

    pub fn open(
        self: FileType,
        path: []const u8,
        flags: posix.O,           // <-- posix, not linux
        mode: posix.mode_t,       // <-- posix, not linux
        ctx: *Supervisor,
    ) !File {
        return switch (self) {
            .blocked => error.PermissionDenied,
            .readonly => .{ .readonly = try Readonly.open(path, flags, mode) },
            .tmp => .{ .tmp = try Tmp.open(path, flags, mode, ctx) },
            .cow => .{ .cow = try Cow.open(path, flags, mode, ctx) },
            .proc => .{ .proc = try Proc.open(path, flags, mode, ctx) },
        };
    }
};

pub fn resolve(path: []const u8) FileType {
    const normalized = normalizePath(path);
    // Rules:
    // /sys/*, /run/* → .blocked
    // /tmp/.bvisor/* → .blocked
    // /tmp/* → .tmp
    // /proc/* → .proc
    // write flags or cow exists → .cow
    // else → .readonly
}
```

### `File.zig` - Tagged Union with Interface Enforcement

```zig
pub const File = union(enum) {
    readonly: Readonly,
    tmp: Tmp,
    cow: Cow,
    proc: Proc,

    pub fn read(self: *File, buf: []u8) !usize {
        switch (self.*) {
            inline else => |*f| return f.read(buf),
        }
    }

    pub fn write(self: *File, data: []const u8) !usize {
        switch (self.*) {
            inline else => |*f| return f.write(data),
        }
    }

    pub fn close(self: *File) void {
        switch (self.*) {
            inline else => |*f| f.close(),
        }
    }
};
```

### File Type Implementations

Each file type implements static `open()` + instance `read()`, `write()`, `close()`.
All take `posix.O` and `posix.mode_t` - no linux types leak into file implementations.

```zig
// files/Readonly.zig (file-as-struct pattern)
const Self = @This();
const posix = std.posix;

fd: posix.fd_t,

pub fn open(path: []const u8, flags: posix.O, mode: posix.mode_t) !Self {
    if (flags.ACCMODE != .RDONLY) return error.ReadOnlyFileSystem;
    const fd = try posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, mode);
    return .{ .fd = fd };
}

pub fn read(self: *Self, buf: []u8) !usize {
    return posix.read(self.fd, buf);
}

pub fn write(self: *Self, data: []const u8) !usize {
    _ = data;
    return error.ReadOnlyFileSystem;
}

pub fn close(self: *Self) void {
    posix.close(self.fd);
}
```

```zig
// files/Proc.zig (file-as-struct pattern)
const Self = @This();

pid: GuestPID,
offset: usize = 0,

pub fn open(path: []const u8, flags: posix.O, mode: posix.mode_t, ctx: *Supervisor) !Self {
    _ = flags; _ = mode;  // proc files ignore flags/mode
    // Parse /proc/self or /proc/<pid>
    // Validate namespace visibility
    return .{ .pid = target_pid };
}

pub fn read(self: *Self, buf: []u8) !usize {
    // Format PID as string, track offset
}

pub fn write(self: *Self, data: []const u8) !usize {
    _ = data;
    return error.ReadOnlyFileSystem;
}

pub fn close(self: *Self) void {}
```

---

## Syscall Handlers

### `openat.zig`

Conversion happens HERE - this is the boundary where linux types enter and leave.

```zig
pub fn handle(notif: Notif, supervisor: *Supervisor) Response {
    const proc = supervisor.procs.get(notif.pid) catch return replyErr(.SRCH);

    var path_buf: [256]u8 = undefined;
    const path = memory_bridge.readString(&path_buf, notif.pid, notif.data.arg1) catch
        return replyErr(.FAULT);

    // === CONVERSION AT BOUNDARY ===
    const linux_flags: linux.O = @bitCast(@truncate(notif.data.arg2));
    const flags = linuxOToPosixO(linux_flags);  // convert once
    const mode: posix.mode_t = @truncate(notif.data.arg3);

    const file_type = path.resolve(path);
    if (file_type == .blocked) return replyErr(.PERM);

    // Everything below uses posix types
    const file = file_type.open(path, flags, mode, supervisor) catch |err|
        return replyErr(errToErrno(err));  // convert error at boundary

    const vfd = proc.fd_table.open(file) catch return replyErr(.MFILE);
    return replySuccess(vfd);
}
```

### `read.zig`

```zig
pub fn handle(notif: Notif, supervisor: *Supervisor) Response {
    const proc = supervisor.procs.get(notif.pid) catch return replyErr(.SRCH);
    const vfd: VirtualFD = @truncate(notif.data.arg0);
    const buf_ptr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    if (vfd == 0) return replyContinue();  // stdin passthrough

    const file = proc.fd_table.get(vfd) orelse return replyErr(.BADF);

    var buf: [4096]u8 = undefined;
    const to_read = @min(count, buf.len);
    const n = file.read(buf[0..to_read]) catch |err| return replyErr(errToErrno(err));

    memory_bridge.writeSlice(notif.pid, buf_ptr, buf[0..n]) catch return replyErr(.FAULT);
    return replySuccess(n);
}
```

### `write.zig`

```zig
pub fn handle(notif: Notif, supervisor: *Supervisor) Response {
    const proc = supervisor.procs.get(notif.pid) catch return replyErr(.SRCH);
    const vfd: VirtualFD = @truncate(notif.data.arg0);
    const buf_ptr: u64 = notif.data.arg1;
    const count: usize = @truncate(notif.data.arg2);

    if (vfd == 1 or vfd == 2) return replyContinue();  // stdout/stderr passthrough

    const file = proc.fd_table.get(vfd) orelse return replyErr(.BADF);

    var buf: [4096]u8 = undefined;
    const to_write = @min(count, buf.len);
    const data = memory_bridge.readSlice(&buf, notif.pid, buf_ptr, to_write) catch
        return replyErr(.FAULT);

    const n = file.write(data) catch |err| return replyErr(errToErrno(err));
    return replySuccess(n);
}
```

### `close.zig`

```zig
pub fn handle(notif: Notif, supervisor: *Supervisor) Response {
    const proc = supervisor.procs.get(notif.pid) catch return replyErr(.SRCH);
    const vfd: VirtualFD = @truncate(notif.data.arg0);

    if (vfd <= 2) return replySuccess(0);  // don't close stdin/stdout/stderr

    var file = proc.fd_table.remove(vfd) orelse return replyErr(.BADF);
    file.close();
    return replySuccess(0);
}
```

---

## Migration Steps

1. **Create `path.zig`** - Extract path normalization and rules from current openat.zig, add FileType enum with resolve() and open()

2. **Create `files/` directory** with (all file-as-struct pattern):
   - `Readonly.zig` - new, simple wrapper around kernel fd
   - `Tmp.zig` - refactor from current Tmp.zig, add read/write/close methods, **remove inline flag conversion**
   - `Cow.zig` - refactor from current Cow.zig, add read/write/close methods, **remove inline flag conversion**
   - `Proc.zig` - extract ProcFile from current OpenFile.zig

3. **Refactor `File.zig`** - Change from data-holding union to struct-holding union with `inline else` dispatch

4. **Simplify syscall handlers**:
   - `openat.zig`: Add single `linuxOToPosixO()` conversion, add single `errToErrno()` for response
   - `read.zig`, `write.zig`, `close.zig`: Just call `file.method()`, use `errToErrno()` for errors
   - **Delete** the 3 duplicate error converters (`posixErrorToLinuxErrno`, `tmpErrorToLinuxErrno`, `cowErrorToLinuxErrno`)
   - **Delete** the duplicate flag converters from Tmp.zig and Cow.zig

5. **Implement `close.zig`** - Currently missing, add to syscalls.zig dispatch

6. **Delete dead code** - Old inline logic, duplicate converters, old Tmp.zig/Cow.zig

---

## Code Cleanup Summary

**Deleted duplicate code (~100 lines):**
- `linuxOToPosixO()` in openat.zig (23 lines) → keep one copy
- Flag conversion in Tmp.zig (14 lines) → delete
- Flag conversion in Cow.zig (12 lines) → delete
- `posixErrorToLinuxErrno()` (20 lines) → consolidate to `errToErrno()`
- `tmpErrorToLinuxErrno()` (16 lines) → delete
- `cowErrorToLinuxErrno()` (15 lines) → delete

**Net result:** One flag converter, one error converter, both inline in openat.zig (or a shared response helper).

---

## Files to Modify

| File | Action |
|------|--------|
| `src/virtual/fs/path.zig` | **Create** - FileType enum, resolve(), path rules |
| `src/virtual/fs/files/Readonly.zig` | **Create** - read-only host file (file-as-struct) |
| `src/virtual/fs/files/Tmp.zig` | **Create** - refactor from current Tmp.zig (file-as-struct) |
| `src/virtual/fs/files/Cow.zig` | **Create** - refactor from current Cow.zig (file-as-struct) |
| `src/virtual/fs/files/Proc.zig` | **Create** - extract from current OpenFile.zig (file-as-struct) |
| `src/virtual/fs/File.zig` | **Rewrite** - union of new file types |
| `src/virtual/fs/FdTable.zig` | **Keep** - no changes needed |
| `src/virtual/fs/Tmp.zig` | **Delete** - replaced by files/Tmp.zig |
| `src/virtual/fs/Cow.zig` | **Delete** - replaced by files/Cow.zig |
| `src/virtual/syscall/handlers/openat.zig` | **Simplify** - single flag/error conversion at boundary |
| `src/virtual/syscall/handlers/read.zig` | **Simplify** - just file.read() |
| `src/virtual/syscall/handlers/write.zig` | **Simplify** - just file.write() |
| `src/virtual/syscall/handlers/close.zig` | **Create** - implement close syscall |
| `src/virtual/syscall/syscalls.zig` | **Update** - add close to dispatch |

---

## Verification

1. `zig build test` - all existing tests pass
2. `zig build test -Duse-docker` - integration tests in container
3. Manual test: open, read, write, close cycle on /tmp file
4. Manual test: read from /proc/self returns correct guest PID
5. Manual test: write to readonly file returns EROFS
6. Manual test: open /sys/... returns EPERM
