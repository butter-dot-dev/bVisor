# bVisor Node SDK

Node.js bindings for bVisor. Linux only.

## Dev

Requires: Zig 0.16+, Docker

From the repo root (next to build.zig), run:

```bash
zig build test-node
```

For a targeted test, from this directory, run:
```bash
# Install the latest published bvisor and run test.ts in a linux container
npm run test:published
```

## Publishing

Bump versions across all packages, then publish:

```bash
bun run version:patch
bun run publish:all
```
