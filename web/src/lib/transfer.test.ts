import { describe, expect, it } from "vitest";
import {
  DownloadFailed,
  MissingFile,
  StreamRefused,
  TransferCancelled,
  UnreadableFile,
  downloadFile,
  uploadFile,
  type Cipher,
  type DownloadSteps,
  type Progress,
  type UploadBody,
  type UploadSteps,
} from "./transfer";

/** A stand-in for the core: "encrypts" by flipping every bit, and adds a 3-byte trailer when finished. */
function fakeCipher(opts: { failFinish?: boolean; failPushAt?: number } = {}) {
  let freed = 0;
  let pushes = 0;
  const cipher: Cipher & { freed(): number } = {
    push(chunk) {
      pushes++;
      if (opts.failPushAt === pushes) throw new Error("decrypt_failed");
      return chunk.map((b) => b ^ 0xff);
    },
    finish() {
      if (opts.failFinish) throw new Error("decrypt_failed");
      return new Uint8Array([7, 7, 7]);
    },
    free() {
      freed++;
    },
    freed: () => freed,
  };
  return cipher;
}

const bytes = (n: number) => Uint8Array.from({ length: n }, (_, i) => i % 251);
const flipped = (b: Uint8Array) => b.map((x) => x ^ 0xff);
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return concat(...parts);
    parts.push(value);
  }
}
const blobBytes = async (b: Blob) => new Uint8Array(await b.arrayBuffer());

interface Calls {
  log: string[];
  keys: string[];
  ciphers: ReturnType<typeof fakeCipher>[];
  received: Uint8Array[];
  bodies: ("blob" | "stream")[];
}

/** Upload steps that record what happens; `put` takes the body like a server would. */
function uploadSteps(opts: { canStream?: boolean; put?: (body: UploadBody, calls: Calls, signal: AbortSignal) => Promise<void>; register?: () => Promise<void> } = {}) {
  const calls: Calls = { log: [], keys: [], ciphers: [], received: [], bodies: [] };
  let keyNo = 0;
  const steps: UploadSteps = {
    newId: () => "att-1",
    newKey: () => {
      const k = `key-${++keyNo}`;
      calls.keys.push(k);
      return k;
    },
    encryptedSize: (n) => n + 3,
    encryptor: (key, itemId, id) => {
      calls.log.push(`encryptor ${key} ${itemId} ${id}`);
      const c = fakeCipher();
      calls.ciphers.push(c);
      return c;
    },
    register: async (itemId, id, size) => {
      calls.log.push(`register ${itemId} ${id} ${size}`);
      await opts.register?.();
    },
    put: async (id, body, size, sent, signal) => {
      calls.log.push(`put ${id} ${size}`);
      calls.bodies.push("blob" in body ? "blob" : "stream");
      if (opts.put) return opts.put(body, calls, signal);
      const data = "blob" in body ? await blobBytes(body.blob) : await readAll(body.stream);
      calls.received.push(data);
      sent(data.length);
    },
    discard: async (id) => {
      calls.log.push(`discard ${id}`);
    },
    canStream: opts.canStream ?? false,
  };
  return { steps, calls };
}

const file = (n: number) => new Blob([bytes(n)]);

describe("uploadFile", () => {
  it("registers the encrypted size, then sends the file assembled from encrypted pieces", async () => {
    const { steps, calls } = uploadSteps();
    const seen: Progress[] = [];
    const done = await uploadFile(file(10), "item-1", steps, { signal: new AbortController().signal, chunk: 4, progress: (p) => seen.push(p) });
    expect(done).toEqual({ id: "att-1", key: "key-1" });
    expect(calls.log).toEqual(["register item-1 att-1 13", "encryptor key-1 item-1 att-1", "put att-1 13"]);
    expect(calls.received[0]).toEqual(concat(flipped(bytes(10)), new Uint8Array([7, 7, 7])));
    expect(calls.bodies).toEqual(["blob"]);
    expect(seen.filter((p) => p.phase === "encrypting").map((p) => p.done)).toEqual([0, 4, 8, 10]);
    expect(seen.at(-1)).toEqual({ phase: "uploading", done: 13, total: 13 });
    expect(calls.ciphers[0].freed()).toBe(1);
  });

  it("encrypts an empty file too", async () => {
    const { steps, calls } = uploadSteps();
    await uploadFile(new Blob([]), "item-1", steps, { signal: new AbortController().signal });
    expect(calls.received[0]).toEqual(new Uint8Array([7, 7, 7]));
  });

  it("streams the file as the request reads it when the browser can", async () => {
    const { steps, calls } = uploadSteps({ canStream: true });
    const seen: Progress[] = [];
    const done = await uploadFile(file(10), "item-1", steps, { signal: new AbortController().signal, chunk: 4, progress: (p) => seen.push(p) });
    expect(done).toEqual({ id: "att-1", key: "key-1" });
    expect(calls.bodies).toEqual(["stream"]);
    expect(calls.received[0]).toEqual(concat(flipped(bytes(10)), new Uint8Array([7, 7, 7])));
    expect(seen.every((p) => p.phase === "uploading")).toBe(true);
    expect(seen.at(-1)).toEqual({ phase: "uploading", done: 13, total: 13 });
    expect(calls.ciphers[0].freed()).toBe(1);
  });

  it("reads nothing ahead of the request", async () => {
    let pulledBeforeReading = -1;
    const { steps } = uploadSteps({
      canStream: true,
      put: async (body) => {
        if ("blob" in body) throw new Error("expected a stream");
        await new Promise((r) => setTimeout(r, 5));
        pulledBeforeReading = body.pulled();
        await readAll(body.stream);
      },
    });
    await uploadFile(file(10), "item-1", steps, { signal: new AbortController().signal, chunk: 4 });
    expect(pulledBeforeReading).toBe(0);
  });

  it("sends a refused stream again as a Blob, with a new key", async () => {
    const { steps, calls } = uploadSteps({
      canStream: true,
      put: async (body, c) => {
        if (!("blob" in body)) throw new StreamRefused();
        c.received.push(await blobBytes(body.blob));
      },
    });
    const done = await uploadFile(file(9), "item-1", steps, { signal: new AbortController().signal, chunk: 4 });
    expect(calls.bodies).toEqual(["stream", "blob"]);
    expect(calls.keys).toEqual(["key-1", "key-2"]);
    expect(done.key).toBe("key-2");
    expect(calls.log.filter((l) => l.startsWith("encryptor"))).toEqual(["encryptor key-1 item-1 att-1", "encryptor key-2 item-1 att-1"]);
    expect(calls.log).not.toContain("discard att-1");
    expect(calls.ciphers.map((c) => c.freed())).toEqual([1, 1]);
  });

  it("deletes the attachment again when the upload fails", async () => {
    const failure = new Error("413 too large");
    const { steps, calls } = uploadSteps({
      put: async () => {
        throw failure;
      },
    });
    await expect(uploadFile(file(5), "item-1", steps, { signal: new AbortController().signal })).rejects.toBe(failure);
    expect(calls.log.at(-1)).toBe("discard att-1");
  });

  it("deletes the attachment again when cancelled, and says it was cancelled", async () => {
    const ctrl = new AbortController();
    const { steps, calls } = uploadSteps({
      put: async (_body, _c, signal) => {
        ctrl.abort();
        throw signal.aborted ? new Error("aborted by the transport") : new Error("?");
      },
    });
    await expect(uploadFile(file(5), "item-1", steps, { signal: ctrl.signal })).rejects.toBeInstanceOf(TransferCancelled);
    expect(calls.log.at(-1)).toBe("discard att-1");
  });

  it("stops while encrypting when cancelled", async () => {
    const ctrl = new AbortController();
    const { steps, calls } = uploadSteps();
    let pieces = 0;
    const p = uploadFile(file(40), "item-1", steps, {
      signal: ctrl.signal,
      chunk: 4,
      progress: (pr) => {
        if (pr.phase === "encrypting" && ++pieces === 3) ctrl.abort();
      },
    });
    await expect(p).rejects.toBeInstanceOf(TransferCancelled);
    expect(calls.log).not.toContain("put att-1 43");
    expect(calls.log.at(-1)).toBe("discard att-1");
    expect(calls.ciphers[0].freed()).toBe(1);
  });

  it("registers nothing when cancelled before it starts, and deletes nothing when registering fails", async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    const first = uploadSteps();
    await expect(uploadFile(file(5), "item-1", first.steps, { signal: ctrl.signal })).rejects.toBeInstanceOf(TransferCancelled);
    expect(first.calls.log).toEqual([]);

    const refused = new Error("403 quota");
    const second = uploadSteps({
      register: async () => {
        throw refused;
      },
    });
    await expect(uploadFile(file(5), "item-1", second.steps, { signal: new AbortController().signal })).rejects.toBe(refused);
    expect(second.calls.log).toEqual(["register item-1 att-1 8"]);
  });

  it("reports a file that can't be read", async () => {
    const broken = { size: 8, slice: () => ({ arrayBuffer: () => Promise.reject(new Error("NotReadableError")) }) } as unknown as Blob;
    const { steps, calls } = uploadSteps();
    await expect(uploadFile(broken, "item-1", steps, { signal: new AbortController().signal })).rejects.toBeInstanceOf(UnreadableFile);
    expect(calls.log.at(-1)).toBe("discard att-1");
  });
});

// ---------------------------------------------------------------- download

function streamOf(...chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  let i = 0;
  return new ReadableStream<Uint8Array>({
    pull(ctrl) {
      if (i < chunks.length) ctrl.enqueue(chunks[i++]);
      else ctrl.close();
    },
  });
}

function downloadSteps(status: number, chunks: Uint8Array[], cipher = fakeCipher()) {
  const log: string[] = [];
  const steps: DownloadSteps = {
    decryptor: (key, itemId, id) => {
      log.push(`decryptor ${key} ${itemId} ${id}`);
      return cipher;
    },
    get: async () => ({ status, body: streamOf(...chunks) }),
  };
  return { steps, log, cipher };
}

describe("downloadFile", () => {
  const att = { id: "att-1", key: "file-key" };

  it("decrypts the file as it arrives and hands it over once it is whole", async () => {
    const enc = flipped(bytes(10));
    const { steps, log, cipher } = downloadSteps(200, [enc.slice(0, 4), enc.slice(4)]);
    const seen: Progress[] = [];
    const blob = await downloadFile(att, "item-1", steps, { signal: new AbortController().signal, total: 10, progress: (p) => seen.push(p) });
    expect(await blobBytes(blob)).toEqual(concat(bytes(10), new Uint8Array([7, 7, 7])));
    expect(blob.type).toBe("application/octet-stream");
    expect(log).toEqual(["decryptor file-key item-1 att-1"]);
    expect(seen.map((p) => p.done)).toEqual([0, 4, 10]);
    expect(cipher.freed()).toBe(1);
  });

  it("gathers large files in a Blob as they come", async () => {
    const enc = flipped(bytes(64));
    const chunks = [0, 16, 32, 48].map((at) => enc.slice(at, at + 16));
    const { steps } = downloadSteps(200, chunks);
    const blob = await downloadFile(att, "item-1", steps, { signal: new AbortController().signal, foldBytes: 20 });
    expect(await blobBytes(blob)).toEqual(concat(bytes(64), new Uint8Array([7, 7, 7])));
  });

  it("throws everything away when the file isn't whole", async () => {
    const cipher = fakeCipher({ failFinish: true });
    const { steps } = downloadSteps(200, [flipped(bytes(8))], cipher);
    await expect(downloadFile(att, "item-1", steps, { signal: new AbortController().signal })).rejects.toThrow("decrypt_failed");
    expect(cipher.freed()).toBe(1);
  });

  it("stops at a damaged piece", async () => {
    const cipher = fakeCipher({ failPushAt: 2 });
    const { steps } = downloadSteps(200, [bytes(4), bytes(4), bytes(4)], cipher);
    await expect(downloadFile(att, "item-1", steps, { signal: new AbortController().signal })).rejects.toThrow("decrypt_failed");
    expect(cipher.freed()).toBe(1);
  });

  it("says when the server doesn't have the file", async () => {
    const { steps, log } = downloadSteps(404, []);
    await expect(downloadFile(att, "item-1", steps, { signal: new AbortController().signal })).rejects.toBeInstanceOf(MissingFile);
    expect(log).toEqual([]);
    const other = downloadSteps(500, []);
    await expect(downloadFile(att, "item-1", other.steps, { signal: new AbortController().signal })).rejects.toBeInstanceOf(DownloadFailed);
  });

  it("can be cancelled", async () => {
    const ctrl = new AbortController();
    const cipher = fakeCipher();
    const steps: DownloadSteps = {
      decryptor: () => cipher,
      get: async () => ({
        status: 200,
        body: new ReadableStream<Uint8Array>({
          pull(c) {
            c.enqueue(bytes(4));
            ctrl.abort();
          },
        }),
      }),
    };
    await expect(downloadFile(att, "item-1", steps, { signal: ctrl.signal })).rejects.toBeInstanceOf(TransferCancelled);
    expect(cipher.freed()).toBe(1);
  });
});
