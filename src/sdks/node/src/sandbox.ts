import { arch, platform } from "os";

if (platform() !== "linux") {
  throw new Error("bVisor only supports Linux");
}

const native = require(`@bvisor/linux-${arch()}`);

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
