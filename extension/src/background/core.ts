/**
 * The Rust core (crates/core-wasm) in the service worker: crypto (vault.ts) and the site logic (site.ts). Loaded once
 * per worker, single-flight (`initCore`); every entry point that reaches the site logic waits for it first — the
 * router (every request), the passkey bridge, the toolbar badge, the right-click menu, the keyboard commands and the
 * tab events — because those functions are synchronous.
 */
import init from "../wasm/passauth_core";

let ready: Promise<unknown> | null = null;

/** Load the core (cheap once it has loaded). A failed load is tried again by the next caller. */
export function initCore(): Promise<unknown> {
  // Vite emits the .wasm as a packaged extension file and rewrites this URL.
  ready ??= init({ module_or_path: new URL("../wasm/passauth_core_bg.wasm", import.meta.url) }).catch((e: unknown) => {
    ready = null;
    throw e;
  });
  return ready;
}
