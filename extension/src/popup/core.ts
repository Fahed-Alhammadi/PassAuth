/**
 * The Rust core (WASM) in the popup page, loaded only when needed and once per page: for what must stay in this page
 * — a sign-in request's key (it can't be saved, so the request lives as long as this page: device-sign-in.tsx) and
 * decrypting a downloaded file (files.tsx: the plaintext never crosses a message). Everything else asks the worker.
 */
type Core = typeof import("../wasm/passauth_core");

let loading: Promise<Core> | null = null;

export function popupCore(): Promise<Core> {
  loading ??= import("../wasm/passauth_core")
    .then(async (core) => {
      // Vite emits the .wasm as a packaged extension file and rewrites this URL.
      await core.default({ module_or_path: new URL("../wasm/passauth_core_bg.wasm", import.meta.url) });
      return core;
    })
    .catch((e: unknown) => {
      loading = null;
      throw e;
    });
  return loading;
}
