import { Sandbox } from "bvisor";

const cmds = ["echo 'Hello, world!'", "sleep 1", "pwd", "ls"];

for (const cmd of cmds) {
  const sb = new Sandbox();
  const output = sb.runCmd(cmd);
  console.log(cmd, "->", await output.stdout());
}
