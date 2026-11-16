/**
 * Attachment files through the native client (`src-tauri/src/transfer.rs`). Pieces cross the IPC as raw bytes, never
 * JSON: a piece is the request body of `upload_chunk` / `save_chunk` (the transfer's id in a header), and
 * `download_read` answers with raw bytes. Upload progress comes back through a Channel. The rules for the server's
 * answers (renewing the session, 409s) are the web vault's, in web/src/lib/files.ts.
 */
import { Channel, invoke } from "@tauri-apps/api/core";
import type { NativeAnswer, NativeTransfers } from "@web/lib/server";

/** The IPC header naming the transfer a raw piece belongs to. */
const TRANSFER = "passauth-transfer";
/** Bytes of a decrypted file handed over per call when saving it. */
const SAVE_PIECE = 1024 * 1024;

const sendPiece = <T>(command: string, id: number, piece: Uint8Array) => invoke<T>(command, piece, { headers: { [TRANSFER]: String(id) } });

export const transfers: NativeTransfers = {
  uploadStart: (path, headers, size, sent) => invoke<number>("upload_start", { path, headers, size, onProgress: new Channel<number>(sent) }),
  uploadChunk: (id, piece) => sendPiece<boolean>("upload_chunk", id, piece),
  uploadFinish: (id) => invoke<NativeAnswer>("upload_finish", { id }),
  downloadStart: (path, headers) => invoke<NativeAnswer & { id: number | null }>("download_start", { path, headers }),
  downloadRead: async (id) => new Uint8Array(await invoke<ArrayBuffer>("download_read", { id })),
  cancel: (id) => invoke<void>("transfer_cancel", { id }),
};

/**
 * Save `blob` (a decrypted attachment) where the user picks in the system save dialog. Rust writes it to a temporary file
 * beside the chosen one and renames it when whole. False when the user cancels the dialog.
 */
export async function saveBytes(filename: string, blob: Blob): Promise<boolean> {
  const id = await invoke<number | null>("save_start", { filename });
  if (id === null) return false;
  try {
    for (let at = 0; at < blob.size; at += SAVE_PIECE) {
      await sendPiece<void>("save_chunk", id, new Uint8Array(await blob.slice(at, at + SAVE_PIECE).arrayBuffer()));
    }
    await invoke("save_finish", { id });
    return true;
  } catch (e) {
    await invoke("transfer_cancel", { id }).catch(() => {});
    throw e;
  }
}
