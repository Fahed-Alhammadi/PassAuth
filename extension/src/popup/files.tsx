/**
 * An item's files in the popup (servers with `attachments`): name and size, marked when the server no longer has one,
 * and Download. The popup fetches and decrypts a file itself, with the core's `FileDecryptor` (`@web/lib/transfer`
 * `downloadFile`: the plaintext is gathered in this page and released only after the core has checked the whole
 * file), then hands it to the browser as an object URL and `<a download>` (PassAuth has no downloads permission).
 * The worker only says where the file is and lends a current access token (background/attachments.ts). Adding and
 * removing files happens in the web vault.
 */

import { Icon } from "@web/components/ui";
import { downloadName, readAttachments } from "@web/lib/attachments";
import { formatBytes } from "@web/lib/sizes";
import { DownloadFailed, downloadFile, MissingFile, TransferCancelled } from "@web/lib/transfer";
import type { Attachment, Item } from "@web/lib/types";
import { useEffect, useRef, useState } from "react";
import { callPopup } from "../shared/protocol";
import { popupCore } from "./core";
import { type Ctx, msg } from "./ctx";

/** What went wrong with a download, in plain words. */
export function fileError(e: unknown): string {
  if (e instanceof MissingFile) return e.message;
  if (e instanceof DownloadFailed) return `The download failed (${e.status}). Try again.`;
  if (e instanceof Error && e.message === "decrypt_failed") return "This file couldn't be decrypted: it is damaged or incomplete. Try again.";
  if (e instanceof TypeError) return "Can't reach your PassAuth server. Check your connection and try again.";
  return msg(e);
}

/**
 * `GET` the encrypted file with the account's token; after a 401 once more with a new token. A 404 is returned (the
 * file is gone: `downloadFile` says so), like any other answer.
 */
async function getFile(itemId: string, attachmentId: string, signal: AbortSignal): Promise<{ status: number; body: ReadableStream<Uint8Array> | null }> {
  for (let attempt = 1; ; attempt++) {
    const access = await callPopup("files:access", { itemId, attachmentId, ...(attempt > 1 ? { renew: true } : {}) });
    const res = await fetch(access.url, { headers: { authorization: `Bearer ${access.token}`, "x-passauth-client": access.client }, signal, cache: "no-store" });
    if (res.status === 401 && attempt === 1) {
      await res.body?.cancel().catch(() => {});
      continue;
    }
    return { status: res.status, body: res.body };
  }
}

/** Download and decrypt one file of item `itemId`; resolves with the whole, authentic file only. */
export async function fetchFile(itemId: string, att: Attachment, signal: AbortSignal, progress: (done: number, total: number) => void): Promise<Blob> {
  const core = await popupCore();
  let total = 0;
  try {
    total = core.fileEncryptedSize(att.size);
  } catch {
    total = 0;
  }
  return downloadFile(
    att,
    itemId,
    { decryptor: (key, item, id) => new core.FileDecryptor(key, item, id), get: (s) => getFile(itemId, att.id, s) },
    { signal, total, progress: (p) => progress(p.done, p.total) },
  );
}

/** Hand a decrypted file to the browser's downloads, under its own name; the copy is released after a minute. */
function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = downloadName(name);
  a.rel = "noopener";
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

export function Files({ itemId, item, ctx }: { itemId: string; item: Item; ctx: Ctx }) {
  const files = readAttachments(item);
  const [missing, setMissing] = useState<ReadonlySet<string>>(new Set());
  const [busy, setBusy] = useState<{ id: string; done: number; total: number } | null>(null);
  const abort = useRef<AbortController | null>(null);
  const count = files.length;

  useEffect(() => {
    if (!count) return;
    let alive = true;
    // Which listed files the server no longer has (null: it can't say; nothing is marked then).
    callPopup("files:missing", { id: itemId }).then(
      (ids) => alive && ids && setMissing(new Set(ids)),
      () => {},
    );
    return () => {
      alive = false;
    };
  }, [itemId, count]);
  // Leaving the item (or closing the popup) stops a download; nothing of it is kept.
  useEffect(() => () => abort.current?.abort(), []);

  if (!count) return null;

  async function download(att: Attachment) {
    const stop = new AbortController();
    abort.current = stop;
    setBusy({ id: att.id, done: 0, total: 0 });
    try {
      const blob = await fetchFile(itemId, att, stop.signal, (done, total) => setBusy({ id: att.id, done, total }));
      save(blob, att.name);
      ctx.notify(`${att.name} downloaded.`);
    } catch (e) {
      if (e instanceof MissingFile) setMissing((old) => new Set(old).add(att.id));
      if (!(e instanceof TransferCancelled)) ctx.notify(fileError(e));
    } finally {
      if (abort.current === stop) abort.current = null;
      setBusy(null);
    }
  }

  return (
    <section className="group">
      <h2 className="group-title">
        <span>Files</span>
        <span className="count">{count}</span>
      </h2>
      <div className="card-box">
        {files.map((f) => {
          const gone = missing.has(f.id);
          const mine = busy?.id === f.id;
          const pct = mine && busy.total > 0 ? Math.min(100, Math.round((busy.done / busy.total) * 100)) : 0;
          return (
            <div className="kv file-row" key={f.id}>
              <div className="grow">
                <div className="v">
                  <span className="clip">{f.name}</span>
                  <span className={gone ? "sub warn-text" : "sub"}>{gone ? `${formatBytes(f.size)} · No longer on the server` : formatBytes(f.size)}</span>
                  {mine && (
                    <span className="file-progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label={`Downloading ${f.name}`}>
                      <i style={{ width: `${pct}%` }} />
                    </span>
                  )}
                </div>
              </div>
              <div className="acts">
                {mine ? (
                  <button type="button" className="btn btn-icon" aria-label={`Stop downloading ${f.name}`} title="Stop" onClick={() => abort.current?.abort()}>
                    <Icon name="close" />
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn btn-icon"
                    aria-label={`Download ${f.name}`}
                    title={gone ? "This file is no longer on the server" : "Download"}
                    disabled={!!busy || gone}
                    onClick={() => void download(f)}
                  >
                    <Icon name="download" />
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
      <p className="small muted">
        Add or remove files in the{" "}
        <button type="button" className="link" onClick={() => void chrome.tabs.create({ url: `${ctx.state.server}/vault/all/${encodeURIComponent(itemId)}` })}>
          web vault
        </button>
        .
      </p>
    </section>
  );
}
