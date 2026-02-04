const native = require("../../../../zig-out/lib/libbvisor.node");

export class Sandbox {
  private handle: unknown;

  constructor() {
    this.handle = native.createSandbox();
  }

  increment() {
    native.sandboxIncrement(this.handle);
  }

  getValue(): number {
    return native.sandboxGetValue(this.handle);
  }
}
