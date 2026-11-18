// The Send page's password keys in a Web Worker (see `send-kdf.ts`): it loads its own copy of the core, works out one
// verifier and content key and is then ended, taking the memory Argon2 used with it.
import init, { sendPasswordKeys } from "../wasm/passauth_core";

addEventListener("message", async (e: MessageEvent) => {
  const { password, salt, key } = (e.data ?? {}) as { password?: unknown; salt?: unknown; key?: unknown };
  try {
    await init();
  } catch (err) {
    postMessage({ ok: false, stage: "load", error: String(err) });
    return;
  }
  try {
    // Only strings reach the core.
    if (typeof password !== "string" || typeof salt !== "string" || typeof key !== "string") throw new Error("expected a password, a salt and a key");
    const k = sendPasswordKeys(password, salt, key);
    try {
      postMessage({ ok: true, verifier: k.verifier, contentKey: k.contentKey });
    } finally {
      k.free();
    }
  } catch (err) {
    postMessage({ ok: false, stage: "derive", error: err instanceof Error ? err.message : String(err) });
  }
});
