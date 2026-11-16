// The Send page's password check in a Web Worker (see `send-kdf.ts`): it loads its own copy of the core, works out one
// verifier and is then ended, taking the memory Argon2 used with it.
import init, { sendPasswordVerifier } from "../wasm/passauth_core";

addEventListener("message", async (e: MessageEvent) => {
  const { password, salt } = (e.data ?? {}) as { password?: unknown; salt?: unknown };
  try {
    await init();
  } catch (err) {
    postMessage({ ok: false, stage: "load", error: String(err) });
    return;
  }
  try {
    // Only strings reach the core.
    if (typeof password !== "string" || typeof salt !== "string") throw new Error("expected a password and a salt");
    postMessage({ ok: true, verifier: sendPasswordVerifier(password, salt) });
  } catch (err) {
    postMessage({ ok: false, stage: "derive", error: err instanceof Error ? err.message : String(err) });
  }
});
