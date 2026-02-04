// This is just a typing trick
// to make it clear what's an external pointer
// T is phantom, can be named anything
declare const __external: unique symbol;
export type ZigPtr<T> = unknown & { [__external]: T };
