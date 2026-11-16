/** Small assertion and encoding helpers shared by the tests (no Node-only APIs: the tests are type-checked against the browser libs). */
import { expect } from "vitest";

/** `fn` must throw, and the error must pass `check`. */
export function expectThrow(fn: () => unknown, check: (e: any) => boolean) {
  let thrown = false;
  try {
    fn();
  } catch (e) {
    thrown = true;
    expect(check(e), `unexpected error: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`).toBe(true);
  }
  expect(thrown, "expected a throw").toBe(true);
}

/** The promise must reject with an error that passes `check`. */
export async function expectReject(p: Promise<unknown>, check: (e: any) => boolean) {
  let thrown = false;
  try {
    await p;
  } catch (e) {
    thrown = true;
    expect(check(e), `unexpected error: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`).toBe(true);
  }
  expect(thrown, "expected a rejection").toBe(true);
}

export const fromB64u = (s: string): Uint8Array => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

export const toB64u = (b: Uint8Array): string =>
  btoa(String.fromCharCode(...b))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

/** A promise with its resolve function, for tests that hold an async step open. */
export function deferred<T = void>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}
