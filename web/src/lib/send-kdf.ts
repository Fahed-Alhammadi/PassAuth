/**
 * The Send visitor's password check (core `sendPasswordVerifier`: Argon2 with the Send's own settings), worked out in a
 * Web Worker (`send-kdf.worker.ts`). The page stays responsive while it runs, so its progress shows, and the memory
 * Argon2 takes is given back when the worker ends: WASM memory never shrinks while a page lives. When a worker can't be
 * started or can't load the core (an old browser, a policy that blocks workers), it runs on the page's thread instead.
 *
 * The worker is a script of the page's own origin: the server's Content-Security-Policy allows it with `script-src
 * 'self'` (workers fall back to it when there is no `worker-src`), and the worker's own response carries the same
 * policy, whose `'wasm-unsafe-eval'` and `connect-src 'self'` let it fetch and compile the core.
 */
import * as core from "../wasm/passauth_core";

/** What the page needs of a worker (a browser `Worker`; tests pass a fake one). */
export interface KdfWorker {
  onmessage: ((e: MessageEvent) => void) | null;
  onerror: ((e: ErrorEvent) => void) | null;
  onmessageerror: ((e: MessageEvent) => void) | null;
  postMessage(message: unknown): void;
  terminate(): void;
}

/** The worker's answer: the verifier, or why there is none ("load": it couldn't load the core; "derive": the core refused). */
export type KdfAnswer = { ok: true; verifier: string } | { ok: false; stage: "load" | "derive"; error: string };

/**
 * `inline(password, salt)` worked out in the worker `start()` makes, which is ended once it answers. The core's own
 * refusal (settings it won't run) is thrown as the core's error; anything wrong with the worker itself runs `inline`
 * on this thread instead, after a moment so the page can show that it is working.
 */
export function deriveInWorker(password: string, salt: string, start: () => KdfWorker, inline: (password: string, salt: string) => string): Promise<string> {
  return new Promise((resolve, reject) => {
    let worker: KdfWorker | null = null;
    let settled = false;
    const end = (then: () => void) => {
      if (settled) return;
      settled = true;
      worker?.terminate();
      worker = null;
      then();
    };
    const onThisThread = () =>
      end(() =>
        setTimeout(() => {
          try {
            resolve(inline(password, salt));
          } catch (e) {
            reject(e);
          }
        }, 30),
      );
    try {
      worker = start();
    } catch {
      return onThisThread();
    }
    worker.onmessage = (e) => {
      const a = e.data as Partial<{ ok: boolean; verifier: unknown; stage: unknown; error: unknown }> | null;
      if (a?.ok === true && typeof a.verifier === "string") {
        const verifier = a.verifier;
        end(() => resolve(verifier));
      } else if (a?.ok === false && a.stage === "derive") end(() => reject(new Error(typeof a.error === "string" ? a.error : "key derivation failed")));
      else onThisThread();
    };
    worker.onerror = (e) => {
      e.preventDefault();
      onThisThread();
    };
    worker.onmessageerror = () => onThisThread();
    worker.postMessage({ password, salt });
  });
}

/** The verifier for a Send's password (`access_salt` holds its settings), off the page's thread when it can be. */
export function sendVerifier(password: string, salt: string): Promise<string> {
  return deriveInWorker(password, salt, () => new Worker(new URL("./send-kdf.worker.ts", import.meta.url), { type: "module" }), core.sendPasswordVerifier);
}
