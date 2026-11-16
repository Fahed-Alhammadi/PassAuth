/**
 * The desktop app's path for attachment files (`putNative` / `getNative`, the gate and the save): the native client is a
 * fake, so these check the pieces handed over, the rules for answers (401, 409) and cancelling. The browser path is
 * unchanged and the step order is in transfer.test.ts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, UnreachableError, renewSession, setTokens } from "./api";
import { filesSupported, getNative, putNative, saveBlob } from "./files";
import { registerDesktop, type DesktopHooks } from "./platform";
import { configureServer, type NativeAnswer, type NativeTransfers } from "./server";
import { READ_CHUNK, StreamRefused, TransferCancelled, type UploadBody } from "./transfer";

vi.mock("./api", async (importOriginal) => ({ ...(await importOriginal<typeof import("./api")>()), renewSession: vi.fn() }));
// files.ts reads the vault state and shows toasts; neither matters here.
vi.mock("./vault", () => ({ getState: () => ({ status: "locked" }), onVaultChange: () => () => {}, sync: async () => {}, updateItem: async () => {} }));
vi.mock("../components/ui", () => ({ toast: () => {} }));

const renew = vi.mocked(renewSession);

const answer = (status: number, body: unknown = {}, headers: Record<string, string> = {}): NativeAnswer => ({
  status,
  headers: { "content-type": "application/json", ...headers },
  body: typeof body === "string" ? body : JSON.stringify(body),
});

const bytes = (n: number, seed = 0) => Uint8Array.from({ length: n }, (_, i) => (i + seed) % 251);
const concat = (parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

/** A stream of `parts` that records whether it was cancelled. */
function streamOf(parts: Uint8Array[]) {
  let cancelled = false;
  let i = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(ctrl) {
      if (i < parts.length) ctrl.enqueue(parts[i++]);
      else ctrl.close();
    },
    cancel() {
      cancelled = true;
    },
  });
  return { body: { stream, pulled: () => 0 } as UploadBody, cancelled: () => cancelled };
}

type Download = { answer: NativeAnswer; pieces?: Uint8Array[] };

/** A native client: uploads take pieces (`accept` of them, then report the request ended), downloads hand out `pieces`. */
function fakeNative(opts: { uploads?: NativeAnswer[]; accept?: number; downloads?: Download[]; failChunk?: string } = {}) {
  const uploads = [...(opts.uploads ?? [])];
  const downloads = [...(opts.downloads ?? [])];
  let next = 0;
  const pieces = new Map<number, Uint8Array[]>();
  const bodies = new Map<number, Uint8Array[]>();
  const pending = new Map<number, (reason: unknown) => void>();
  const log = {
    starts: [] as { path: string; headers: Record<string, string>; size: number }[],
    downloadStarts: [] as { path: string; headers: Record<string, string> }[],
    finished: [] as number[],
    cancelled: [] as number[],
  };
  const t: NativeTransfers = {
    async uploadStart(path, headers, size, sent) {
      log.starts.push({ path, headers, size });
      const id = ++next;
      pieces.set(id, []);
      sent(0);
      return id;
    },
    async uploadChunk(id, piece) {
      if (opts.failChunk) throw opts.failChunk;
      const list = pieces.get(id)!;
      if (opts.accept !== undefined && list.length >= opts.accept) return false;
      list.push(piece.slice());
      return true;
    },
    async uploadFinish(id) {
      log.finished.push(id);
      return uploads.shift() ?? answer(200);
    },
    async downloadStart(path, headers) {
      log.downloadStarts.push({ path, headers });
      const d = downloads.shift() ?? { answer: answer(404) };
      if (!d.pieces) return { ...d.answer, id: null };
      const id = ++next;
      bodies.set(id, [...d.pieces]);
      return { ...d.answer, id };
    },
    downloadRead(id) {
      const queue = bodies.get(id);
      if (!queue) return Promise.reject("cancelled");
      // An empty list means the server hasn't sent the next bytes yet: wait until cancelled.
      if (queue.length === 0 && pending.has(-1)) return new Promise((_, reject) => pending.set(id, reject));
      return Promise.resolve(queue.shift() ?? new Uint8Array(0));
    },
    async cancel(id) {
      log.cancelled.push(id);
      bodies.delete(id);
      pending.get(id)?.("cancelled");
    },
  };
  /** From now on, a read of an emptied body waits (a slow server) instead of ending. */
  const stall = () => pending.set(-1, () => {});
  return { t, log, pieces, stall };
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return concat(parts);
    parts.push(value);
  }
}

beforeEach(() => {
  renew.mockReset();
  setTokens({ access: "access-1", refresh: "refresh-1" });
});

afterEach(() => {
  setTokens(null);
  vi.useRealTimers();
});

describe("putNative", () => {
  it("hands a Blob over in 1 MiB pieces, with the session and app name, and the size it announced", async () => {
    const file = bytes(READ_CHUNK * 2 + 10);
    const { t, log, pieces } = fakeNative();
    const sent = vi.fn();
    await putNative(t, "/attachments/a1", { blob: new Blob([file]) }, file.length, sent, new AbortController().signal);
    expect(log.starts).toHaveLength(1);
    expect(log.starts[0].path).toBe("/attachments/a1");
    expect(log.starts[0].size).toBe(file.length);
    expect(log.starts[0].headers.authorization).toBe("Bearer access-1");
    expect(log.starts[0].headers["x-passauth-client"]).toMatch(/^(web|desktop)\//);
    expect(pieces.get(1)!.map((p) => p.length)).toEqual([READ_CHUNK, READ_CHUNK, 10]);
    expect(concat(pieces.get(1)!)).toEqual(file);
    expect(sent).toHaveBeenCalledWith(0);
    expect(log.finished).toEqual([1]);
    expect(log.cancelled).toEqual([]);
  });

  it("hands a stream over as it is read", async () => {
    const parts = [bytes(5), bytes(7, 3), bytes(1, 9)];
    const { body, cancelled } = streamOf(parts);
    const { t, pieces } = fakeNative();
    await putNative(t, "/attachments/a1", body, 13, () => {}, new AbortController().signal);
    expect(pieces.get(1)).toEqual(parts);
    expect(cancelled()).toBe(false);
  });

  it("stops handing over once the server has answered, and reports its answer", async () => {
    const { body, cancelled } = streamOf([bytes(5), bytes(5), bytes(5)]);
    const { t, log, pieces } = fakeNative({ accept: 1, uploads: [answer(413, { error: "too_large", message: "attachments may be at most 1 MB on this server" })] });
    const error = await putNative(t, "/attachments/a1", body, 15, () => {}, new AbortController().signal).catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 413, code: "too_large" });
    expect(pieces.get(1)).toHaveLength(1);
    expect(log.finished).toEqual([1]);
    // The rest of the file isn't read (its encryptor is freed).
    expect(cancelled()).toBe(true);
  });

  it("counts an upload the server already has as done", async () => {
    const { t } = fakeNative({ uploads: [answer(409, { error: "already_uploaded", message: "already uploaded" })] });
    await expect(putNative(t, "/attachments/a1", { blob: new Blob([bytes(3)]) }, 3, () => {}, new AbortController().signal)).resolves.toBeUndefined();
  });

  it("renews the session once after a 401 and sends a Blob again with the new token", async () => {
    renew.mockImplementation(async () => {
      setTokens({ access: "access-2", refresh: "refresh-2" });
      return "refreshed";
    });
    const { t, log, pieces } = fakeNative({ uploads: [answer(401, { error: "unauthorized" }), answer(200)] });
    await putNative(t, "/attachments/a1", { blob: new Blob([bytes(4)]) }, 4, () => {}, new AbortController().signal);
    expect(renew).toHaveBeenCalledTimes(1);
    expect(log.starts.map((s) => s.headers.authorization)).toEqual(["Bearer access-1", "Bearer access-2"]);
    expect(pieces.get(2)).toEqual([bytes(4)]);
  });

  it("can't send a stream twice: after a renewed session the Blob try sends the file", async () => {
    renew.mockResolvedValue("refreshed");
    const { t } = fakeNative({ uploads: [answer(401)] });
    const { body } = streamOf([bytes(2)]);
    await expect(putNative(t, "/attachments/a1", body, 2, () => {}, new AbortController().signal)).rejects.toBeInstanceOf(StreamRefused);
  });

  it("gives up after a second 401, and says so when the server can't be reached to renew", async () => {
    renew.mockResolvedValue("refreshed");
    const twice = fakeNative({ uploads: [answer(401), answer(401, { error: "unauthorized", message: "sign in again" })] });
    await expect(putNative(twice.t, "/attachments/a1", { blob: new Blob([bytes(1)]) }, 1, () => {}, new AbortController().signal)).rejects.toMatchObject({ status: 401 });
    renew.mockResolvedValue("unavailable");
    const offline = fakeNative({ uploads: [answer(401)] });
    await expect(putNative(offline.t, "/attachments/a1", { blob: new Blob([bytes(1)]) }, 1, () => {}, new AbortController().signal)).rejects.toBeInstanceOf(
      UnreachableError,
    );
  });

  it("waits for an earlier try that is still running on the server, then sends again", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const { t, log } = fakeNative({ uploads: [answer(409, { error: "upload_in_progress" }), answer(200)] });
    const done = putNative(t, "/attachments/a1", { blob: new Blob([bytes(1)]) }, 1, () => {}, new AbortController().signal);
    // Reading the Blob takes real turns of the event loop: advance until the second try has started.
    for (let i = 0; i < 20 && log.starts.length < 2; i++) await vi.advanceTimersByTimeAsync(500);
    await done;
    expect(log.starts).toHaveLength(2);
  });

  it("passes on Retry-After and the request id of an error answer", async () => {
    const { t } = fakeNative({ uploads: [answer(429, { error: "rate_limited", message: "slow down" }, { "retry-after": "30", "x-request-id": "req-9" })] });
    await expect(putNative(t, "/attachments/a1", { blob: new Blob([bytes(1)]) }, 1, () => {}, new AbortController().signal)).rejects.toMatchObject({
      status: 429,
      retryAfter: 30,
      requestId: "req-9",
    });
  });

  it("stops the request on cancel", async () => {
    const ctrl = new AbortController();
    const { t, log } = fakeNative();
    const slow = t.uploadChunk;
    t.uploadChunk = async (id, piece) => {
      ctrl.abort();
      return slow(id, piece);
    };
    const error = await putNative(t, "/attachments/a1", { blob: new Blob([bytes(READ_CHUNK + 1)]) }, READ_CHUNK + 1, () => {}, ctrl.signal).catch((e) => e);
    expect(error).toBeInstanceOf(TransferCancelled);
    expect(log.cancelled).toContain(1);
    expect(log.finished).toEqual([]);
  });

  it("shows the native client's own message when the transfer fails, and stops it", async () => {
    const { t, log } = fakeNative({ failChunk: "vault.example.com took too long to answer. Check your connection, then try again." });
    const error = await putNative(t, "/attachments/a1", { blob: new Blob([bytes(1)]) }, 1, () => {}, new AbortController().signal).catch((e) => e);
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toMatch(/took too long/);
    expect(log.cancelled).toEqual([1]);
  });
});

describe("getNative", () => {
  it("streams the body the native client reads, with the session and app name", async () => {
    const parts = [bytes(4), bytes(3, 1)];
    const { t, log } = fakeNative({ downloads: [{ answer: answer(200, "", { "content-type": "application/octet-stream" }), pieces: parts }] });
    const res = await getNative(t, "/attachments/a1", new AbortController().signal);
    expect(res.status).toBe(200);
    expect(await readAll(res.body!)).toEqual(concat(parts));
    expect(log.downloadStarts[0].headers.authorization).toBe("Bearer access-1");
    expect(log.downloadStarts[0].headers["x-passauth-client"]).toMatch(/^(web|desktop)\//);
    expect(log.cancelled).toEqual([]);
  });

  it("returns a 404 for the caller to report as a missing file", async () => {
    const { t } = fakeNative({ downloads: [{ answer: answer(404, { error: "not_found" }) }] });
    await expect(getNative(t, "/emergency-access/g1/attachments/a1", new AbortController().signal)).resolves.toEqual({ status: 404, body: null });
  });

  it("renews the session once after a 401", async () => {
    renew.mockImplementation(async () => {
      setTokens({ access: "access-2", refresh: "refresh-2" });
      return "refreshed";
    });
    const { t, log } = fakeNative({ downloads: [{ answer: answer(401) }, { answer: answer(200), pieces: [bytes(2)] }] });
    const res = await getNative(t, "/attachments/a1", new AbortController().signal);
    expect(await readAll(res.body!)).toEqual(bytes(2));
    expect(log.downloadStarts.map((d) => d.headers.authorization)).toEqual(["Bearer access-1", "Bearer access-2"]);
    expect(renew).toHaveBeenCalledTimes(1);
  });

  it("throws other answers as the app's errors", async () => {
    const { t } = fakeNative({ downloads: [{ answer: answer(500, { error: "internal", message: "boom", request_id: "r1" }, { "x-request-id": "r1" }) }] });
    await expect(getNative(t, "/attachments/a1", new AbortController().signal)).rejects.toMatchObject({ status: 500, code: "internal", requestId: "r1" });
    const gateway = fakeNative({ downloads: [{ answer: answer(502, "<html>") }] });
    await expect(getNative(gateway.t, "/attachments/a1", new AbortController().signal)).rejects.toBeInstanceOf(UnreachableError);
  });

  it("stops the download when the reader cancels it", async () => {
    const { t, log } = fakeNative({ downloads: [{ answer: answer(200), pieces: [bytes(2), bytes(2)] }] });
    const res = await getNative(t, "/attachments/a1", new AbortController().signal);
    const reader = res.body!.getReader();
    await reader.read();
    await reader.cancel();
    expect(log.cancelled).toEqual([1]);
  });

  it("stops a read that is waiting when the transfer is cancelled", async () => {
    const ctrl = new AbortController();
    const { t, log, stall } = fakeNative({ downloads: [{ answer: answer(200), pieces: [bytes(2)] }] });
    stall();
    const res = await getNative(t, "/attachments/a1", ctrl.signal);
    const reader = res.body!.getReader();
    expect((await reader.read()).value).toEqual(bytes(2));
    const waiting = reader.read();
    ctrl.abort();
    await expect(waiting).rejects.toBeInstanceOf(TransferCancelled);
    expect(log.cancelled).toEqual([1]);
  });

  it("drops a download that started after the caller gave up", async () => {
    const ctrl = new AbortController();
    const { t, log } = fakeNative({ downloads: [{ answer: answer(200), pieces: [bytes(1)] }] });
    const start = t.downloadStart;
    t.downloadStart = async (path, headers) => {
      const res = await start(path, headers);
      ctrl.abort();
      return res;
    };
    await expect(getNative(t, "/attachments/a1", ctrl.signal)).rejects.toBeInstanceOf(TransferCancelled);
    expect(log.cancelled).toEqual([1]);
  });

  it("turns the native client's failures into errors with its message", async () => {
    const { t } = fakeNative();
    t.downloadStart = () => Promise.reject("Can't reach vault.example.com. Check the address and your connection, then try again.");
    await expect(getNative(t, "/attachments/a1", new AbortController().signal)).rejects.toThrow(/Can't reach vault.example.com/);
  });
});

describe("on the desktop", () => {
  const saveBytes = vi.fn(async () => true);

  beforeEach(() => {
    saveBytes.mockClear();
    registerDesktop({ version: "0.7.0", saveBytes } as unknown as DesktopHooks);
  });

  afterEach(() => {
    registerDesktop(null as unknown as DesktopHooks);
    configureServer({ base: "", fetch: globalThis.fetch.bind(globalThis) });
  });

  it("moves files once the native client is connected", () => {
    configureServer({ base: "https://vault.example.com", fetch: globalThis.fetch.bind(globalThis) });
    expect(filesSupported()).toBe(false);
    configureServer({ base: "https://vault.example.com", fetch: globalThis.fetch.bind(globalThis), transfers: fakeNative().t });
    expect(filesSupported()).toBe(true);
  });

  it("saves a downloaded file through the app, not the browser's downloads", () => {
    const blob = new Blob([bytes(3)]);
    saveBlob(blob, "scan.pdf");
    expect(saveBytes).toHaveBeenCalledWith("scan.pdf", blob);
  });
});
