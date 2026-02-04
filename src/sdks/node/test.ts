import { Sandbox } from "./index";

const sb = new Sandbox();
console.log(sb.getValue()); // 0
sb.increment();
sb.increment();
console.log(sb.getValue()); // 2
