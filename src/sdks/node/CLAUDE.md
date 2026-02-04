# Node SDK

## Layout

```
src/sdks/node/
  index.ts              # Package entry point, re-exports Sandbox
  src/sandbox.ts        # Sandbox class, loads native binary for current platform
  test.ts               # Smoke test, run via `npm run dev`
  platforms/
    linux-arm64/        # @bvisor/linux-arm64 package
      package.json
      libbvisor.node    # Built by `zig build` (gitignored)
    linux-x64/          # @bvisor/linux-x64 package
      package.json
      libbvisor.node    # Built by `zig build` (gitignored)
  zig/                  # Zig source for native bindings
    lib.zig             # Entry point, napi module registration
    napi.zig            # N-API helpers
    Sandbox.zig         # Sandbox implementation
```

## Build

`zig build` (from project root) cross-compiles native binaries for both linux platforms. The build is defined in the root `build.zig` which loops over aarch64 and x86_64 targets.

`npm run dev` runs `zig build` then executes `test.ts` inside a `oven/bun:alpine` Docker container (musl-based, matching the native binary ABI).

## Platform packages

The `platforms/` subdirectories are npm workspace packages. `npm install` on Linux resolves them locally via workspaces. On macOS, `npm install` will fail due to `os`/`cpu` filtering in the platform package.json files -- use `npm run dev` to build and test in Docker instead.

The native binary is loaded at runtime based on `os.arch()`. A platform check in `sandbox.ts` throws before loading if not on Linux.
