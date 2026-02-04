# bVisor Node SDK

Node.js bindings for bVisor. Linux only.

## Dev

Requires: Zig 0.16+, Docker

```bash
npm run dev    # builds native binaries (zig build), then runs test.ts in a linux container
```

## How it works

Native binaries are cross-compiled by `zig build` into platform-specific packages:

- `platforms/linux-arm64/libbvisor.node`
- `platforms/linux-x64/libbvisor.node`

At runtime, `sandbox.ts` loads the correct binary via `require("@bvisor/linux-${arch()}")`.
