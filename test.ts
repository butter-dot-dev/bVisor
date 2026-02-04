import { Sandbox } from "./src/sdks/node";

const sb = new Sandbox();
console.log(sb.getValue()); // 0
sb.increment();
sb.increment();
console.log(sb.getValue()); // 2
