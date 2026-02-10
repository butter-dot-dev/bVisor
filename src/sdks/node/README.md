# bVisor Node SDK

Node.js bindings for bVisor. Linux only.

## Dev

Requires: Zig 0.16+, Docker

```bash
# Build native binaries (zig build), then run test.ts in a linux container
npm run dev    
```

```bash
# Install the latest published bvisor and run test.ts in a linux container
npm run test:published
```

## Publishing

Bump versions across all packages, then publish:

```bash
bun run version:patch
bun publish --access public
```

