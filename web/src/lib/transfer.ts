/**
 * Moving attachment files: encrypt a file while reading it and upload it; download a file and decrypt it. Written
 * against small step interfaces, so the order of requests, the fallback from a streamed to an assembled upload and the
 * clean-up after a failure or a cancel are unit-tested with fakes (`transfer.test.ts`); `files.ts` wires the steps to
 * the core (`FileEncryptor` / `FileDecryptor`) and the network.
 *
 * Upload: register the attachment (`POST`, with the encrypted size), then `PUT` the ciphertext, as a stream when the
 * browser can send one (the file is read and encrypted 1 MiB at a time as the request goes out), else as a Blob built
 * piece by piece (the plaintext is never held twice: each piece is read from the file, encrypted and dropped). A stream
 * the browser or the connection refuses (Chrome needs HTTP/2 for it) is sent again as a Blob with a new key: nothing of
 * the first try was kept. Any failure or a cancel after registering deletes the attachment again.
 *
 * Download: decrypt as the ciphertext arrives; the plaintext stays inside this function (gathered into a Blob) until the
 * core's `finish()` has confirmed the file is whole and authentic, and is thrown away otherwise.
 */

/** The core's streaming encryptor or decryptor (`push` any size, `finish` once, then `free`). */
export interface Cipher {
  push(chunk: Uint8Array): Uint8Array;
  finish(): Uint8Array;
  free(): void;
}

export type Phase = "encrypting" | "uploading" | "downloading";

export interface Progress {
  phase: Phase;
  /** Bytes done and in all: of the file while encrypting, of the ciphertext while uploading or downloading. */
  done: number;
  total: number;
}

/** Plaintext read and encrypted per step: 1 MiB (16 of the core's 64 KiB chunks), small enough to keep WASM memory low. */
export const READ_CHUNK = 1024 * 1024;
/** Decrypted bytes gathered before they are moved into the Blob being built (which browsers may keep on disk). */
const FOLD_BYTES = 8 * 1024 * 1024;

export class TransferCancelled extends Error {
  constructor() {
    super("cancelled");
  }
}

/** The file is gone from the server (deleted, or never finished uploading). */
export class MissingFile extends Error {
  constructor() {
    super("This file is no longer on the server.");
  }
}

/** The picked file couldn't be read (moved, deleted or changed since it was picked). */
export class UnreadableFile extends Error {
  constructor() {
    super("The file couldn't be read. It may have been moved or changed since you picked it. Pick it again.");
  }
}

/**
 * `put` could not send the stream: the browser or the connection doesn't take one (nothing of it was read), or the
 * session had to be renewed first (a stream can't be sent twice). The file is then sent as a Blob.
 */
export class StreamRefused extends Error {
  constructor() {
    super("stream_refused");
  }
}

/** A request body: an assembled Blob, or a stream that encrypts as it is read (`pulled`: bytes read from it so far). */
export type UploadBody = { blob: Blob } | { stream: ReadableStream<Uint8Array>; pulled: () => number };

export interface UploadSteps {
  newId(): string;
  newKey(): string;
  encryptedSize(plainSize: number): number;
  encryptor(key: string, itemId: string, attachmentId: string): Cipher;
  /** `POST /items/{itemId}/attachments {id, size}`. */
  register(itemId: string, attachmentId: string, size: number): Promise<void>;
  /**
   * `PUT /attachments/{id}` with `size` bytes. `body` is a stream only when `canStream`; `sent` hears how many bytes of a
   * Blob went out so far. Throws `StreamRefused` when a stream couldn't be sent.
   */
  put(attachmentId: string, body: UploadBody, size: number, sent: (bytes: number) => void, signal: AbortSignal): Promise<void>;
  /** `DELETE /attachments/{id}`; failures are ignored by the caller. */
  discard(attachmentId: string): Promise<void>;
  /** Whether `put` can take a stream as the request body. */
  canStream: boolean;
}

/** What an upload made: the attachment's id and the key its file is encrypted with (for the item's list). */
export interface Uploaded {
  id: string;
  key: string;
}

const check = (signal: AbortSignal) => {
  if (signal.aborted) throw new TransferCancelled();
};

/** `free()` once, whatever happens: a handle is freed after `finish()`, after an error and on cancel. */
function once(cipher: Cipher): Cipher & { release(): void } {
  let freed = false;
  return {
    push: (chunk) => cipher.push(chunk),
    finish: () => cipher.finish(),
    free: () => {
      if (!freed) {
        freed = true;
        cipher.free();
      }
    },
    release() {
      this.free();
    },
  };
}

async function readSlice(file: Blob, start: number, end: number): Promise<Uint8Array> {
  try {
    return new Uint8Array(await file.slice(start, end).arrayBuffer());
  } catch {
    throw new UnreadableFile();
  }
}

/**
 * The file encrypted piece by piece as the request reads it: nothing is read or encrypted ahead (high-water mark 0), so
 * `pulled` tells how much the request took.
 */
function encryptingStream(file: Blob, cipher: Cipher & { release(): void }, chunk: number, pulled: (bytes: number) => void): ReadableStream<Uint8Array> {
  let offset = 0;
  let out = 0;
  let closed = false;
  const emit = (ctrl: ReadableStreamDefaultController<Uint8Array>, bytes: Uint8Array) => {
    if (!bytes.length) return;
    out += bytes.length;
    ctrl.enqueue(bytes);
    pulled(out);
  };
  return new ReadableStream<Uint8Array>(
    {
      async pull(ctrl) {
        try {
          // Keep reading until something comes out (a piece smaller than the core's chunk may give nothing yet).
          while (offset < file.size) {
            const plain = await readSlice(file, offset, offset + chunk);
            if (!plain.length) throw new UnreadableFile();
            offset += plain.length;
            const enc = cipher.push(plain);
            if (enc.length) return emit(ctrl, enc);
          }
          if (!closed) {
            closed = true;
            emit(ctrl, cipher.finish());
            cipher.release();
            ctrl.close();
          }
        } catch (e) {
          closed = true;
          cipher.release();
          ctrl.error(e);
        }
      },
      cancel() {
        closed = true;
        cipher.release();
      },
    },
    { highWaterMark: 0 },
  );
}

/** The whole ciphertext as a Blob, built from pieces as the file is read. */
async function encryptToBlob(file: Blob, cipher: Cipher & { release(): void }, chunk: number, signal: AbortSignal, progress: (p: Progress) => void): Promise<Blob> {
  const parts: BlobPart[] = [];
  try {
    let offset = 0;
    progress({ phase: "encrypting", done: 0, total: file.size });
    while (offset < file.size) {
      check(signal);
      const plain = await readSlice(file, offset, offset + chunk);
      if (!plain.length) throw new UnreadableFile();
      offset += plain.length;
      const enc = cipher.push(plain);
      if (enc.length) parts.push(enc as Uint8Array<ArrayBuffer>);
      progress({ phase: "encrypting", done: offset, total: file.size });
    }
    parts.push(cipher.finish() as Uint8Array<ArrayBuffer>);
    return new Blob(parts, { type: "application/octet-stream" });
  } finally {
    cipher.release();
  }
}

/**
 * Encrypt `file` for item `itemId` and upload it as a new attachment. Returns its id and key, to list in the item. On
 * a failure or a cancel after the attachment was registered, it is deleted again (best effort) before this throws.
 */
export async function uploadFile(
  file: Blob,
  itemId: string,
  steps: UploadSteps,
  opts: { signal: AbortSignal; progress?: (p: Progress) => void; chunk?: number },
): Promise<Uploaded> {
  const { signal } = opts;
  const progress = opts.progress ?? (() => {});
  const chunk = opts.chunk ?? READ_CHUNK;
  const id = steps.newId();
  const size = steps.encryptedSize(file.size);
  check(signal);
  await steps.register(itemId, id, size);
  try {
    check(signal);
    const uploading = (bytes: number) => progress({ phase: "uploading", done: Math.min(bytes, size), total: size });
    if (steps.canStream) {
      const key = steps.newKey();
      const cipher = once(steps.encryptor(key, itemId, id));
      let pulled = 0;
      const stream = encryptingStream(file, cipher, chunk, (bytes) => {
        pulled = bytes;
        uploading(bytes);
      });
      try {
        uploading(0);
        await steps.put(id, { stream, pulled: () => pulled }, size, () => {}, signal);
        return { id, key };
      } catch (e) {
        if (!(e instanceof StreamRefused)) throw e;
      } finally {
        cipher.release();
      }
      check(signal);
    }
    // A new key for the second try: the stream's key encrypted bytes that never became a file.
    const key = steps.newKey();
    const blob = await encryptToBlob(file, once(steps.encryptor(key, itemId, id)), chunk, signal, progress);
    check(signal);
    uploading(0);
    await steps.put(id, { blob }, size, uploading, signal);
    return { id, key };
  } catch (e) {
    await steps.discard(id).catch(() => {});
    throw signal.aborted ? new TransferCancelled() : e;
  }
}

// ---------------------------------------------------------------- download

export interface DownloadSteps {
  decryptor(key: string, itemId: string, attachmentId: string): Cipher;
  /** `GET` the encrypted file: its status and body (null when there is none). */
  get(signal: AbortSignal): Promise<{ status: number; body: ReadableStream<Uint8Array> | null }>;
}

/** A download that failed with an HTTP status other than 404. */
export class DownloadFailed extends Error {
  constructor(public status: number) {
    super(`download_failed_${status}`);
  }
}

/**
 * Download and decrypt the file of attachment `att` of item `itemId`. Resolves with the plaintext only after the core
 * confirmed the whole file (`finish()`); any error discards everything decrypted so far. `total`: the encrypted size
 * expected, for progress.
 */
export async function downloadFile(
  att: { id: string; key: string },
  itemId: string,
  steps: DownloadSteps,
  opts: { signal: AbortSignal; progress?: (p: Progress) => void; total?: number; foldBytes?: number },
): Promise<Blob> {
  const { signal } = opts;
  const progress = opts.progress ?? (() => {});
  const fold = opts.foldBytes ?? FOLD_BYTES;
  check(signal);
  let res: { status: number; body: ReadableStream<Uint8Array> | null };
  try {
    res = await steps.get(signal);
  } catch (e) {
    throw signal.aborted ? new TransferCancelled() : e;
  }
  if (res.status === 404) throw new MissingFile();
  if (res.status < 200 || res.status > 299 || !res.body) throw new DownloadFailed(res.status);
  const reader = res.body.getReader();
  const cipher = once(steps.decryptor(att.key, itemId, att.id));
  const total = opts.total ?? 0;
  let received = 0;
  let built = new Blob([]);
  let pending: BlobPart[] = [];
  let pendingBytes = 0;
  try {
    progress({ phase: "downloading", done: 0, total });
    for (;;) {
      check(signal);
      const { done, value } = await reader.read();
      if (done) break;
      if (!value?.length) continue;
      received += value.length;
      const plain = cipher.push(value);
      if (plain.length) {
        pending.push(plain as Uint8Array<ArrayBuffer>);
        pendingBytes += plain.length;
      }
      if (pendingBytes >= fold) {
        built = new Blob([built, ...pending]);
        pending = [];
        pendingBytes = 0;
      }
      progress({ phase: "downloading", done: received, total: Math.max(total, received) });
    }
    const last = cipher.finish();
    return new Blob([built, ...pending, last as Uint8Array<ArrayBuffer>], { type: "application/octet-stream" });
  } catch (e) {
    reader.cancel().catch(() => {});
    throw signal.aborted ? new TransferCancelled() : e;
  } finally {
    cipher.release();
  }
}
