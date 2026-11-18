/**
 * The Send visitor's password keys (core `sendPasswordKeys`: one Argon2 run with the Send's own settings gives the
 * verifier the server checks and, with the link key, the content key that opens a v2 Send's text), worked out in a
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

/** A Send password's keys: the verifier for the server, the content key for this page only (it never leaves it). */
export interface SendKeys {
  verifier: string;
  contentKey: string;
}

/** The worker's answer: the keys, or why there are none ("load": it couldn't load the core; "derive": the core refused). */
export type KdfAnswer = ({ ok: true } & SendKeys) | { ok: false; stage: "load" | "derive"; error: string };

/**
 * `inline(password, salt, key)` worked out in the worker `start()` makes, which is ended once it answers. The core's
 * own refusal (settings it won't run) is thrown as the core's error; anything wrong with the worker itself runs
 * `inline` on this thread instead, after a moment so the page can show that it is working.
 */
export function deriveInWorker(
  password: string,
  salt: string,
  key: string,
  start: () => KdfWorker,
  inline: (password: string, salt: string, key: string) => SendKeys,
): Promise<SendKeys> {
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
            resolve(inline(password, salt, key));
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
      const a = e.data as Partial<{ ok: boolean; verifier: unknown; contentKey: unknown; stage: unknown; error: unknown }> | null;
      if (a?.ok === true && typeof a.verifier === "string" && typeof a.contentKey === "string") {
        const keys = { verifier: a.verifier, contentKey: a.contentKey };
        end(() => resolve(keys));
      } else if (a?.ok === false && a.stage === "derive") end(() => reject(new Error(typeof a.error === "string" ? a.error : "key derivation failed")));
      else onThisThread();
    };
    worker.onerror = (e) => {
      e.preventDefault();
      onThisThread();
    };
    worker.onmessageerror = () => onThisThread();
    worker.postMessage({ password, salt, key });
  });
}

/** The core's keys on this thread (the handle freed at once). */
export function sendKeysHere(password: string, salt: string, key: string): SendKeys {
  const k = core.sendPasswordKeys(password, salt, key);
  try {
    return { verifier: k.verifier, contentKey: k.contentKey };
  } finally {
    k.free();
  }
}

/**
 * The keys for a Send's password (`access_salt` holds its settings, `key` is the link's key), off the page's thread
 * when it can be.
 */
export function sendKeys(password: string, salt: string, key: string): Promise<SendKeys> {
  return deriveInWorker(password, salt, key, () => new Worker(new URL("./send-kdf.worker.ts", import.meta.url), { type: "module" }), sendKeysHere);
}
