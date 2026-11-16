import { describe, expect, it } from "vitest";
import { deriveInWorker, type KdfWorker } from "./send-kdf";

/** A worker that answers each message with `reply(message)` (or fails as told), and notes whether it was ended. */
class FakeWorker implements KdfWorker {
  onmessage: ((e: MessageEvent) => void) | null = null;
  onerror: ((e: ErrorEvent) => void) | null = null;
  onmessageerror: ((e: MessageEvent) => void) | null = null;
  sent: unknown[] = [];
  ended = false;
  constructor(private reply: (msg: unknown) => unknown, private fail = false) {}
  postMessage(message: unknown) {
    this.sent.push(message);
    queueMicrotask(() => {
      if (this.fail) this.onerror?.({ preventDefault() {} } as ErrorEvent);
      else this.onmessage?.({ data: this.reply(message) } as MessageEvent);
    });
  }
  terminate() {
    this.ended = true;
  }
}

const inline = (password: string, salt: string) => `inline(${password},${salt})`;

describe("the Send password check off the page's thread", () => {
  it("works out the verifier in the worker, then ends it", async () => {
    const w = new FakeWorker((m) => ({ ok: true, verifier: `worker(${(m as { password: string }).password})` }));
    await expect(deriveInWorker("pw", "salt", () => w, inline)).resolves.toBe("worker(pw)");
    expect(w.sent).toEqual([{ password: "pw", salt: "salt" }]);
    expect(w.ended).toBe(true);
  });

  it("passes on the core's refusal (settings it won't run) instead of trying again here", async () => {
    const w = new FakeWorker(() => ({ ok: false, stage: "derive", error: "kdf parameters out of range" }));
    await expect(deriveInWorker("pw", "salt", () => w, inline)).rejects.toThrow("kdf parameters out of range");
    expect(w.ended).toBe(true);
  });

  it("works it out on this thread when there is no worker, it can't load the core, it fails or it answers nonsense", async () => {
    await expect(
      deriveInWorker("pw", "s", () => {
        throw new Error("Worker is not defined");
      }, inline),
    ).resolves.toBe("inline(pw,s)");
    for (const w of [
      new FakeWorker(() => ({ ok: false, stage: "load", error: "CompileError" })),
      new FakeWorker(() => null, true),
      new FakeWorker(() => ({ ok: true, verifier: { length: 1e9 } })),
      new FakeWorker(() => "hello"),
    ]) {
      await expect(deriveInWorker("pw", "s", () => w, inline)).resolves.toBe("inline(pw,s)");
      expect(w.ended).toBe(true);
    }
  });

  it("throws what the core throws on this thread", async () => {
    const refuse = () => {
      throw new Error("key derivation failed");
    };
    await expect(deriveInWorker("pw", "s", () => new FakeWorker(() => null, true), refuse)).rejects.toThrow("key derivation failed");
  });
});
