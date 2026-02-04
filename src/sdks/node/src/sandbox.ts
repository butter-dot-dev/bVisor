import { arch, platform } from "os";
import { ZigPtr } from "./napi";

if (platform() !== "linux") {
  throw new Error("bVisor only supports Linux");
}

const libBvisor = require(`@bvisor/linux-${arch()}`);

class Stream {
  private ptr: ZigPtr<"Stream">;

  constructor(ptr: ZigPtr<"Stream">) {
    this.ptr = ptr;
  }

  toReadableStream(): ReadableStream<Uint8Array> {
    const self = this;
    return new ReadableStream({
      async pull(controller) {
        // TODO: make streamNext return a promise
        const chunk: Uint8Array | null = libBvisor.streamNext(self.ptr);
        if (chunk) {
          controller.enqueue(chunk);
        } else {
          controller.close();
        }
      },
    });
  }
}

interface RunCmdResult {
  stdout: ZigPtr<"Stream">;
  stderr: ZigPtr<"Stream">;
}

export class Sandbox {
  private ptr: unknown;

  constructor() {
    this.ptr = libBvisor.createSandbox();
  }

  runCmd(command: string) {
    const result: RunCmdResult = libBvisor.sandboxRunCmd(this.ptr, command);
    return createOutput(
      new Stream(result.stdout).toReadableStream(),
      new Stream(result.stderr).toReadableStream()
    );
  }
}

export interface Output {
  stdoutStream: ReadableStream<Uint8Array>;
  stderrStream: ReadableStream<Uint8Array>;
  stdout: () => Promise<string>;
  stderr: () => Promise<string>;
}

function createOutput(
  stdoutStream: ReadableStream<Uint8Array>,
  stderrStream: ReadableStream<Uint8Array>
): Output {
  return {
    stdoutStream,
    stderrStream,
    stdout: () => new Response(stdoutStream).text(),
    stderr: () => new Response(stderrStream).text(),
  };
}
