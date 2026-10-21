// Compile-time checks of the ported Go reflection tests: `make ts-lint`
// type-checks the test files, so an assertType call whose argument is not
// `true` fails the lint, not the run.

/** `true` when A and B are the same type, `false` otherwise. */
export type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;

/** Compiles only when T is `true`. */
export function assertType<T extends true>(..._: T extends true ? [] : [never]): void {}
