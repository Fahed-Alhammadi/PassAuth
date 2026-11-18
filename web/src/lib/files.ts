/**
 * Attachments in the web vault: the transfer steps (`transfer.ts`) wired to the core and the network, the flows that
 * keep an item's file list in step with the server (attach, remove, download) and the uploads in progress.
 *
 * Uploads run outside any page, one after the other (leaving the item doesn't stop them; the page asks before it is
 * closed while one runs) and stop when the vault locks or signs out, deleting their attachment again. After the file is
 * on the server, the item is saved with it in its list, starting from the item as last synced (tried again after a sync
 * if the item changed meanwhile); if that fails for good, the attachment is deleted.
 *
 * The desktop app moves files through its native client (`server.transfers`: the encrypted bytes cross to it piece by
 * piece, `putNative` / `getNative` below) with the same rules for answers, and saves a downloaded file through the
 * system save dialog (`saveBytes` hook), since its WebView has no downloads.
 */
import { useMemo, useSyncExternalStore } from "react";
import * as core from "../wasm/passauth_core";
import { toast } from "../components/ui";
import { ApiError, UnreachableError, api, friendlyError, getTokens, hasErrorCode, isOutOfStorage, renewSession } from "./api";
import { MANIFEST_HELD, manifestRaced } from "./manifest";
import { addAttachments, cleanFileName, readStoredAttachments, removeAttachment as withoutAttachment, type StoredAttachment } from "./attachments";
import { clientId, getDesktop, isDesktop } from "./platform";
import { server, type NativeAnswer, type NativeTransfers } from "./server";
import {
  DownloadFailed,
  MissingFile,
  READ_CHUNK,
  StreamRefused,
  TransferCancelled,
  UnreadableFile,
  downloadFile,
  uploadFile,
  type Progress,
  type UploadBody,
  type UploadSteps,
} from "./transfer";
import type { Attachment } from "./types";
import { getState, onVaultChange, sync, updateItem } from "./vault";

/** Whether this app can move files: a browser can, and the desktop app once it is connected (its native client). */
export const filesSupported = (): boolean =>
  isDesktop() ? server.transfers !== null : typeof Blob === "function" && typeof XMLHttpRequest === "function";

export const attachmentPath = (id: string) => `/attachments/${encodeURIComponent(id)}`;
export const emergencyAttachmentPath = (grantId: string, id: string) => `/emergency-access/${encodeURIComponent(grantId)}/attachments/${encodeURIComponent(id)}`;

/** The encrypted size of a file of `plain` bytes (what the server counts); 0 for a size the core refuses. */
export function encryptedSize(plain: number): number {
  try {
    return core.fileEncryptedSize(plain);
  } catch {
    return 0;
  }
}

// ------------------------------------------------------------- transport

function authHeaders(): Record<string, string> {
  const t = getTokens();
  return { "x-passauth-client": clientId(), ...(t ? { authorization: `Bearer ${t.access}` } : {}) };
}

/** Whether `fetch` takes a stream as a request body here (`duplex: "half"`); false after a stream was refused once. */
let streamUploads: boolean | null = null;
function canStreamUploads(): boolean {
  // The desktop app's native client sends a stream as it is read.
  if (server.transfers) return true;
  if (streamUploads !== null) return streamUploads;
  try {
    let duplex = false;
    const init = {
      method: "POST",
      body: new ReadableStream(),
      get duplex() {
        duplex = true;
        return "half";
      },
    };
    const hasType = new Request(location.href, init as RequestInit).headers.has("content-type");
    streamUploads = duplex && !hasType;
  } catch {
    streamUploads = false;
  }
  return streamUploads;
}

/** An error answer as the rest of the app knows it (`ApiError`, or unreachable for gateway errors). */
function answerError(status: number, text: string, retryAfter: string | null, requestId: string | null): Error {
  if (status >= 502 && status <= 504) return new UnreachableError(status);
  let body: { error?: unknown; message?: unknown } | null = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  const code = typeof body?.error === "string" ? body.error : "error";
  const message = typeof body?.message === "string" ? body.message : `Request failed (${status})`;
  const seconds = retryAfter !== null && Number.isFinite(Number(retryAfter)) ? Number(retryAfter) : undefined;
  return new ApiError(status, code, message, seconds, requestId ?? undefined);
}

/** An upload that was already stored (an earlier try landed and only its answer got lost) counts as done. */
const alreadyUploaded = (status: number, text: string) => status === 409 && text.includes("already_uploaded");

/** `PUT` a Blob with upload progress (XMLHttpRequest: fetch has none), renewing the session once after a 401. */
async function putBlob(path: string, blob: Blob, sent: (bytes: number) => void, signal: AbortSignal): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    const res = await new Promise<{ status: number; text: string; retryAfter: string | null; requestId: string | null }>((resolve, reject) => {
      if (signal.aborted) return reject(new TransferCancelled());
      const xhr = new XMLHttpRequest();
      xhr.open("PUT", server.apiUrl(path));
      for (const [name, value] of Object.entries(authHeaders())) xhr.setRequestHeader(name, value);
      xhr.setRequestHeader("content-type", "application/octet-stream");
      xhr.upload.onprogress = (e) => sent(e.loaded);
      const abort = () => xhr.abort();
      signal.addEventListener("abort", abort, { once: true });
      const done = () => signal.removeEventListener("abort", abort);
      xhr.onload = () => {
        done();
        resolve({ status: xhr.status, text: xhr.responseText, retryAfter: xhr.getResponseHeader("retry-after"), requestId: xhr.getResponseHeader("x-request-id") });
      };
      xhr.onerror = () => {
        done();
        reject(new UnreachableError());
      };
      xhr.onabort = () => {
        done();
        reject(new TransferCancelled());
      };
      xhr.send(blob);
    });
    if ((res.status >= 200 && res.status < 300) || alreadyUploaded(res.status, res.text)) return;
    if (res.status === 401 && attempt === 1) {
      const r = await renewSession();
      if (r === "refreshed") continue;
      if (r === "unavailable") throw new UnreachableError();
    }
    // Another try of this upload hasn't ended on the server yet (a stream the connection dropped): wait for it.
    if (res.status === 409 && res.text.includes("upload_in_progress") && attempt < 3) {
      await pause(2000 * attempt, signal);
      continue;
    }
    throw answerError(res.status, res.text, res.retryAfter, res.requestId);
  }
}

/** `PUT` a stream (`duplex: "half"`). Anything that keeps it from going out makes the upload start again as a Blob. */
async function putStream(path: string, body: { stream: ReadableStream<Uint8Array> }, signal: AbortSignal): Promise<void> {
  let res: Response;
  try {
    res = await fetch(server.apiUrl(path), {
      method: "PUT",
      headers: { ...authHeaders(), "content-type": "application/octet-stream" },
      body: body.stream,
      duplex: "half",
      signal,
    } as RequestInit);
  } catch {
    if (signal.aborted) throw new TransferCancelled();
    // Refused by the browser or the connection (Chrome sends streams only over HTTP/2), or the network failed: either
    // way the Blob try decides. Later uploads of this page go straight to a Blob.
    streamUploads = false;
    throw new StreamRefused();
  }
  const text = await res.text().catch(() => "");
  if (res.ok || alreadyUploaded(res.status, text)) return;
  if (res.status === 401) {
    // A stream can't be sent twice: renew the session, and the Blob try sends the file again.
    const r = await renewSession();
    if (r === "refreshed") throw new StreamRefused();
  }
  throw answerError(res.status, text, res.headers.get("retry-after"), res.headers.get("x-request-id"));
}

function putFile(path: string, body: UploadBody, size: number, sent: (bytes: number) => void, signal: AbortSignal): Promise<void> {
  if (server.transfers) return putNative(server.transfers, path, body, size, sent, signal);
  return "blob" in body ? putBlob(path, body.blob, sent, signal) : putStream(path, body, signal);
}

/** `GET` an encrypted file as a stream, renewing the session once after a 401. A 404 is returned, other errors thrown. */
async function getFile(path: string, signal: AbortSignal): Promise<{ status: number; body: ReadableStream<Uint8Array> | null }> {
  if (server.transfers) return getNative(server.transfers, path, signal);
  for (let attempt = 1; ; attempt++) {
    let res: Response;
    try {
      res = await fetch(server.apiUrl(path), { headers: authHeaders(), signal, cache: "no-store" });
    } catch {
      throw signal.aborted ? new TransferCancelled() : new UnreachableError();
    }
    if (res.status === 401 && attempt === 1) {
      const r = await renewSession();
      if (r === "refreshed") continue;
      if (r === "unavailable") throw new UnreachableError();
    }
    if (res.ok || res.status === 404) return { status: res.status, body: res.body };
    throw answerError(res.status, await res.text().catch(() => ""), res.headers.get("retry-after"), res.headers.get("x-request-id"));
  }
}

const pause = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new TransferCancelled());
      },
      { once: true },
    );
  });

// -------------------------------------------------- desktop: native client

/** What a native transfer's failure means here: a cancel, an error of the file itself, or the native client's message. */
function nativeError(e: unknown, signal: AbortSignal): Error {
  if (signal.aborted || e instanceof TransferCancelled) return new TransferCancelled();
  return e instanceof Error ? e : new Error(String(e));
}

const nativeAnswerError = (res: NativeAnswer) => answerError(res.status, res.body, res.headers["retry-after"] ?? null, res.headers["x-request-id"] ?? null);

/** Hand `body` to native upload `id` piece by piece (1 MiB). Stops early once the request has ended (the server answered). */
async function sendPieces(t: NativeTransfers, id: number, body: UploadBody, signal: AbortSignal): Promise<void> {
  if ("blob" in body) {
    const { blob } = body;
    for (let at = 0; at < blob.size; at += READ_CHUNK) {
      if (signal.aborted) throw new TransferCancelled();
      const piece = new Uint8Array(await blob.slice(at, at + READ_CHUNK).arrayBuffer());
      if (!(await t.uploadChunk(id, piece))) return;
    }
    return;
  }
  const reader = body.stream.getReader();
  let finished = false;
  try {
    for (;;) {
      if (signal.aborted) throw new TransferCancelled();
      const next = await reader.read();
      if (next.done) {
        finished = true;
        return;
      }
      if (next.value.length > 0 && !(await t.uploadChunk(id, next.value))) return;
    }
  } finally {
    // Stopped early: the rest of the file isn't read (its encryptor is freed).
    if (!finished) reader.cancel().catch(() => {});
  }
}

/** One upload through the native client: the server's answer. Cancelling (or any failure) stops the request. */
async function uploadOnce(
  t: NativeTransfers,
  path: string,
  body: UploadBody,
  size: number,
  sent: (bytes: number) => void,
  signal: AbortSignal,
): Promise<NativeAnswer> {
  if (signal.aborted) throw new TransferCancelled();
  let id: number;
  try {
    id = await t.uploadStart(path, authHeaders(), size, sent);
  } catch (e) {
    throw nativeError(e, signal);
  }
  const stop = () => void t.cancel(id).catch(() => {});
  signal.addEventListener("abort", stop, { once: true });
  try {
    await sendPieces(t, id, body, signal);
    if (signal.aborted) throw new TransferCancelled();
    return await t.uploadFinish(id);
  } catch (e) {
    stop();
    throw nativeError(e, signal);
  } finally {
    signal.removeEventListener("abort", stop);
  }
}

/**
 * Desktop: `PUT` through the native client, with the browser's rules. A 401 renews the session once: a Blob is sent
 * again; a stream can't be, so the Blob try sends the file again (`StreamRefused`). A 409 `already_uploaded` counts as
 * done; a Blob waits for another try of it that is still running on the server.
 */
export async function putNative(
  t: NativeTransfers,
  path: string,
  body: UploadBody,
  size: number,
  sent: (bytes: number) => void,
  signal: AbortSignal,
): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    const res = await uploadOnce(t, path, body, size, sent, signal);
    if ((res.status >= 200 && res.status < 300) || alreadyUploaded(res.status, res.body)) return;
    if (res.status === 401 && attempt === 1) {
      const r = await renewSession();
      if (r === "refreshed") {
        if ("stream" in body) throw new StreamRefused();
        continue;
      }
      if (r === "unavailable") throw new UnreachableError();
    }
    if (res.status === 409 && res.body.includes("upload_in_progress") && "blob" in body && attempt < 3) {
      await pause(2000 * attempt, signal);
      continue;
    }
    throw nativeAnswerError(res);
  }
}

/** A native download's body as a stream: read as the consumer pulls; cancelling it (or `signal`) stops the download. */
function nativeBody(t: NativeTransfers, id: number, signal: AbortSignal): ReadableStream<Uint8Array> {
  let open = true;
  const close = () => {
    open = false;
    signal.removeEventListener("abort", stop);
  };
  function stop() {
    if (!open) return;
    close();
    void t.cancel(id).catch(() => {});
  }
  signal.addEventListener("abort", stop, { once: true });
  return new ReadableStream<Uint8Array>(
    {
      async pull(ctrl) {
        try {
          const piece = await t.downloadRead(id);
          if (piece.length > 0) return ctrl.enqueue(piece);
          close();
          ctrl.close();
        } catch (e) {
          // The native client has dropped the download already (failed or cancelled).
          close();
          ctrl.error(nativeError(e, signal));
        }
      },
      cancel: stop,
    },
    { highWaterMark: 0 },
  );
}

/** Desktop: `GET` through the native client, renewing the session once after a 401. A 404 is returned, other errors thrown. */
export async function getNative(t: NativeTransfers, path: string, signal: AbortSignal): Promise<{ status: number; body: ReadableStream<Uint8Array> | null }> {
  for (let attempt = 1; ; attempt++) {
    if (signal.aborted) throw new TransferCancelled();
    let res: NativeAnswer & { id: number | null };
    try {
      res = await t.downloadStart(path, authHeaders());
    } catch (e) {
      throw nativeError(e, signal);
    }
    if (res.id !== null && signal.aborted) {
      void t.cancel(res.id).catch(() => {});
      throw new TransferCancelled();
    }
    if (res.id !== null) return { status: res.status, body: nativeBody(t, res.id, signal) };
    if (res.status === 401 && attempt === 1) {
      const r = await renewSession();
      if (r === "refreshed") continue;
      if (r === "unavailable") throw new UnreachableError();
    }
    if (res.status === 404) return { status: 404, body: null };
    throw nativeAnswerError(res);
  }
}

function uploadSteps(): UploadSteps {
  return {
    newId: () => core.newId(),
    newKey: () => core.fileNewKey(),
    encryptedSize: (plain) => core.fileEncryptedSize(plain),
    encryptor: (key, itemId, id) => new core.FileEncryptor(key, itemId, id),
    register: async (itemId, id, size) => {
      await api(`/items/${encodeURIComponent(itemId)}/attachments`, { body: { id, size } });
    },
    put: (id, body, size, sent, signal) => putFile(attachmentPath(id), body, size, sent, signal),
    discard: async (id) => {
      await api(attachmentPath(id), { method: "DELETE" });
    },
    canStream: canStreamUploads(),
  };
}

// ----------------------------------------------------------------- errors

/** What went wrong with a file, in plain words. */
export function fileError(e: unknown): string {
  if (e instanceof MissingFile || e instanceof UnreadableFile) return e.message;
  if (e instanceof DownloadFailed) return `The download failed (${e.status}). Try again.`;
  if (e instanceof Error && e.message === "decrypt_failed") return "This file couldn't be decrypted: it is damaged or incomplete. Try again.";
  if (hasErrorCode(e, "too_large")) return `${friendlyError(e)} Pick a smaller file.`;
  if (e instanceof ApiError && e.status === 429) return "Too many uploads at once. Wait a minute, then try again.";
  return friendlyError(e);
}

// --------------------------------------------------------------- download

/**
 * Download and decrypt an attachment's file (from `path`: the item's own, or an emergency access's). Resolves only with
 * the whole, authentic file; `MissingFile` when the server doesn't have it any more.
 */
export function fetchAttachment(path: string, itemId: string, att: Attachment, opts: { signal: AbortSignal; progress?: (p: Progress) => void }): Promise<Blob> {
  return downloadFile(
    att,
    itemId,
    { decryptor: (key, item, id) => new core.FileDecryptor(key, item, id), get: (signal) => getFile(path, signal) },
    { ...opts, total: encryptedSize(att.size) },
  );
}

/** Hand a decrypted file to the browser's downloads, under its own name (desktop: the system save dialog). */
export function saveBlob(blob: Blob, name: string) {
  // A WebView has no downloads: the desktop app writes the file where the user picks.
  const desktop = getDesktop();
  if (desktop) {
    void desktop.saveBytes(name, blob);
    return;
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Long enough for the browser to start reading it, then the decrypted copy is released.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

// ----------------------------------------------------------- item's list

/** The item as last synced, or why it can't be changed. */
function currentEntry(itemId: string) {
  const s = getState();
  if (s.status !== "unlocked") throw new Error("The vault is locked. Unlock it and try again.");
  const entry = s.items.find((x) => x.id === itemId);
  if (!entry) throw new Error("This item is no longer in your vault. It may have been deleted on another device.");
  return entry;
}

/** Worth trying the save again after a sync: not an answer that will stay the same (a full storage, a gone item). */
const retrySave = (e: unknown) =>
  e instanceof ApiError ? e.status === 409 || e.status === 429 || (e.status >= 500 && !isOutOfStorage(e)) || manifestRaced(e) : !(e instanceof Error && e.message === MANIFEST_HELD);

/** Save the item with `att` added to its list, starting from the item as last synced each try. */
async function listInItem(itemId: string, att: Attachment): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    const entry = currentEntry(itemId);
    try {
      await updateItem(entry, addAttachments(entry.item, [att]));
      return;
    } catch (e) {
      if (attempt >= 3 || !retrySave(e) || getState().status !== "unlocked") throw e;
      await pause(1500 * attempt);
      await sync().catch(() => {});
    }
  }
}

/** Remove a file: the item is saved without it first, then the server deletes the file (a file already gone is fine). */
export async function removeAttachment(itemId: string, attachmentId: string): Promise<void> {
  const entry = currentEntry(itemId);
  await updateItem(entry, withoutAttachment(entry.item, attachmentId));
  await deleteStored(attachmentId).catch(() => {});
}

/** The files the server keeps for an item (any member may list them): which listed ones are missing, what was left over. */
export async function storedAttachments(itemId: string): Promise<StoredAttachment[]> {
  return readStoredAttachments(await api(`/items/${encodeURIComponent(itemId)}/attachments`));
}

/** Delete a file on the server (one no item lists any more). Already gone counts as done. */
export async function deleteStored(attachmentId: string): Promise<void> {
  try {
    await api(attachmentPath(attachmentId), { method: "DELETE" });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
  }
}

// ---------------------------------------------------------------- uploads

export type UploadState = "queued" | "encrypting" | "uploading" | "saving" | "failed";

export interface UploadTask {
  key: string;
  itemId: string;
  name: string;
  /** The file's size in bytes. */
  size: number;
  state: UploadState;
  /** Progress of the current step, 0–1. */
  fraction: number;
  error: string | null;
}

let tasks: UploadTask[] = [];
let taskSeq = 0;
const controllers = new Map<string, AbortController>();
const taskSubs = new Set<() => void>();
let queue: Promise<void> = Promise.resolve();

function setTasks(next: UploadTask[]) {
  tasks = next;
  taskSubs.forEach((fn) => fn());
}
const patchTask = (key: string, patch: Partial<UploadTask>) => setTasks(tasks.map((t) => (t.key === key ? { ...t, ...patch } : t)));
const dropTask = (key: string) => setTasks(tasks.filter((t) => t.key !== key));
const subscribeTasks = (fn: () => void) => {
  taskSubs.add(fn);
  return () => {
    taskSubs.delete(fn);
  };
};
const tasksSnapshot = () => tasks;

/** The uploads of item `itemId` (running, waiting or failed), oldest first. */
export function useUploads(itemId: string): UploadTask[] {
  const all = useSyncExternalStore(subscribeTasks, tasksSnapshot);
  return useMemo(() => all.filter((t) => t.itemId === itemId), [all, itemId]);
}

/** Whether an upload is running or waiting (the page asks before it is closed then). */
const busy = () => tasks.some((t) => t.state !== "failed");

/** Attach `files` to item `itemId`, one after the other. Check their sizes first (`tooLarge`). */
export function attachFiles(itemId: string, files: File[]) {
  for (const file of files) {
    const key = `upload-${++taskSeq}`;
    const ctrl = new AbortController();
    controllers.set(key, ctrl);
    setTasks([...tasks, { key, itemId, name: cleanFileName(file.name), size: file.size, state: "queued", fraction: 0, error: null }]);
    queue = queue.then(() => runUpload(key, file));
  }
}

/** Stop an upload that hasn't reached its save yet (its attachment is deleted), or forget a failed one. */
export function cancelUpload(key: string) {
  const task = tasks.find((t) => t.key === key);
  if (!task || task.state === "saving") return;
  controllers.get(key)?.abort();
  if (task.state === "failed" || task.state === "queued") dropTask(key);
}

async function runUpload(key: string, file: File) {
  const ctrl = controllers.get(key);
  const task = tasks.find((t) => t.key === key);
  if (!ctrl || !task || ctrl.signal.aborted) {
    controllers.delete(key);
    return dropTask(key);
  }
  let last = 0;
  const report = (p: Progress) => {
    const fraction = p.total > 0 ? p.done / p.total : 0;
    const state: UploadState = p.phase === "encrypting" ? "encrypting" : "uploading";
    const now = Date.now();
    // Progress events can come thousands of times a second: show at most ten a second, and every change of step.
    if (state === tasks.find((t) => t.key === key)?.state && now - last < 100 && fraction < 1) return;
    last = now;
    patchTask(key, { state, fraction });
  };
  try {
    currentEntry(task.itemId);
    patchTask(key, { state: "encrypting", fraction: 0 });
    const done = await uploadFile(file, task.itemId, uploadSteps(), { signal: ctrl.signal, progress: report });
    patchTask(key, { state: "saving", fraction: 1 });
    const att: Attachment = { id: done.id, name: task.name, size: task.size, key: done.key };
    try {
      await listInItem(task.itemId, att);
    } catch (e) {
      // The item doesn't list the file, so nobody could open it: delete it again.
      await deleteStored(att.id).catch(() => {});
      throw e;
    }
    dropTask(key);
    toast(`"${task.name}" attached`);
  } catch (e) {
    if (e instanceof TransferCancelled) dropTask(key);
    else patchTask(key, { state: "failed", error: fileError(e) });
  } finally {
    controllers.delete(key);
  }
}

// Locked or signed out: nothing can be saved into an item any more, so running uploads stop (and delete their file).
onVaultChange(() => {
  if (getState().status === "unlocked" || controllers.size === 0) return;
  for (const [key, ctrl] of controllers) {
    if (tasks.find((t) => t.key === key)?.state !== "saving") ctrl.abort();
  }
  setTasks(tasks.filter((t) => t.state === "saving"));
});

if (typeof window !== "undefined") {
  window.addEventListener("beforeunload", (e) => {
    if (busy()) e.preventDefault();
  });
}
