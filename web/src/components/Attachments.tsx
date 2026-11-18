import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { hasFeature, usePublicConfig } from "../lib/api";
import {
  attachmentLimitMb,
  cleanFileName,
  downloadName,
  leftovers,
  missingOnServer,
  readAttachments,
  tooLarge,
  type StoredAttachment,
} from "../lib/attachments";
import {
  attachFiles,
  attachmentPath,
  cancelUpload,
  deleteStored,
  encryptedSize,
  fetchAttachment,
  fileError,
  filesSupported,
  removeAttachment,
  saveBlob,
  storedAttachments,
  useUploads,
  type UploadTask,
} from "../lib/files";
import { getDesktop } from "../lib/platform";
import { server } from "../lib/server";
import { formatBytes } from "../lib/sizes";
import { MissingFile, TransferCancelled } from "../lib/transfer";
import { isTrashed, type Attachment, type VaultEntry } from "../lib/types";
import { ConfirmDialog, ErrorText, Icon, toast } from "./ui";
import "../styles/files.css";

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Split picked files into those the server takes and a message about the others (too large). */
function checkSizes(files: File[], limitMb: number | null): { ok: File[]; error: string | null } {
  const big = files.filter((f) => tooLarge(f.size, limitMb, encryptedSize));
  const ok = files.filter((f) => !big.includes(f));
  if (big.length === 0) return { ok, error: null };
  const names = big.map((f) => `"${cleanFileName(f.name)}"`).join(", ");
  return { ok, error: `${names} ${big.length === 1 ? "is" : "are"} too large: files can be at most ${limitMb} MB on this server.` };
}

/** A progress bar for a transfer, 0–1. */
function Bar({ fraction, label }: { fraction: number; label: string }) {
  const pct = Math.round(Math.min(1, Math.max(0, fraction)) * 100);
  return (
    <div className="transfer-bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} aria-label={label}>
      <i style={{ width: `${pct}%` }} />
    </div>
  );
}

/** Where the desktop app sends people for files: this server's web vault in the browser. */
function WebVaultNote({ action }: { action: string }) {
  const desktop = getDesktop();
  return (
    <p className="small muted">
      This app can't transfer files yet. To {action}, use the web vault
      {desktop ? (
        <>
          {": "}
          <button type="button" className="link" onClick={() => void desktop.openUrl(`${server.origin()}/vault`)}>
            open it in your browser
          </button>
          .
        </>
      ) : (
        "."
      )}
    </p>
  );
}

/**
 * One file: its name and size, Download (decrypted on this device, saved under its own name) and, where allowed,
 * Remove. `path` is where its encrypted file is fetched from (the item's own, or an emergency access's). The name is
 * shown and saved cleaned (`cleanFileName`, `downloadName`): whoever attached the file chose it.
 */
export function FileRow({
  file,
  itemId,
  path,
  missing = false,
  onRemove,
}: {
  file: Attachment;
  itemId: string;
  path: string;
  missing?: boolean;
  onRemove?: () => void;
}) {
  const [download, setDownload] = useState<{ fraction: number; ctrl: AbortController } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [gone, setGone] = useState(false);
  const running = useRef<AbortController | null>(null);
  const transfers = filesSupported();
  const absent = missing || gone;
  const name = cleanFileName(file.name);
  // A download in progress stops when the row goes (the item closed, the vault locked).
  useEffect(() => () => running.current?.abort(), []);

  async function start() {
    const ctrl = new AbortController();
    running.current = ctrl;
    setError(null);
    setDownload({ fraction: 0, ctrl });
    let shown = 0;
    try {
      const blob = await fetchAttachment(path, itemId, file, {
        signal: ctrl.signal,
        progress: (p) => {
          const fraction = p.total > 0 ? p.done / p.total : 0;
          // At most one update per percent.
          if (fraction - shown < 0.01 && fraction < 1) return;
          shown = fraction;
          setDownload((d) => (d && d.ctrl === ctrl ? { ...d, fraction } : d));
        },
      });
      saveBlob(blob, downloadName(name));
    } catch (e) {
      if (e instanceof TransferCancelled) return;
      if (e instanceof MissingFile) setGone(true);
      else setError(fileError(e));
    } finally {
      if (running.current === ctrl) running.current = null;
      setDownload((d) => (d?.ctrl === ctrl ? null : d));
    }
  }

  return (
    <div className="file-row">
      <div className="file-main">
        <span className="tile" aria-hidden="true">
          <Icon name="file" />
        </span>
        <span className="grow">
          <span className="row-title">{name}</span>
          <span className={absent ? "row-sub file-missing" : "row-sub"}>{absent ? "This file is no longer on the server" : formatBytes(file.size)}</span>
        </span>
        {transfers && !absent && !download && (
          <button type="button" className="btn btn-icon" aria-label={`Download ${name}`} title="Download" onClick={start}>
            <Icon name="download" />
          </button>
        )}
        {download && (
          <button type="button" className="btn btn-sm btn-text" onClick={() => download.ctrl.abort()}>
            Cancel
          </button>
        )}
        {onRemove && !download && (
          <button type="button" className="btn btn-icon btn-quiet-danger" aria-label={`Remove ${name}`} title="Remove file" onClick={onRemove}>
            <Icon name="trash" />
          </button>
        )}
      </div>
      {download && <Bar fraction={download.fraction} label={`Downloading ${name}`} />}
      {error && (
        <p className="small file-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

const UPLOAD_STATE_TEXT: Record<UploadTask["state"], string> = {
  queued: "Waiting…",
  encrypting: "Encrypting…",
  uploading: "Uploading…",
  saving: "Saving to the item…",
  failed: "Not attached",
};

function UploadRow({ task }: { task: UploadTask }) {
  const running = task.state === "encrypting" || task.state === "uploading";
  return (
    <div className="file-row">
      <div className="file-main">
        <span className="tile" aria-hidden="true">
          <Icon name="upload" />
        </span>
        <span className="grow">
          <span className="row-title">{task.name}</span>
          <span className={task.state === "failed" ? "row-sub file-missing" : "row-sub"} aria-live="polite">
            {UPLOAD_STATE_TEXT[task.state]}
            {running && ` ${Math.round(task.fraction * 100)}%`}
            {task.state !== "failed" && `, ${formatBytes(task.size)}`}
          </span>
        </span>
        {task.state !== "saving" && (
          <button type="button" className="btn btn-sm btn-text" onClick={() => cancelUpload(task.key)}>
            {task.state === "failed" ? "Dismiss" : "Cancel"}
          </button>
        )}
      </div>
      {running && <Bar fraction={task.fraction} label={`${UPLOAD_STATE_TEXT[task.state]} ${task.name}`} />}
      {task.error && (
        <p className="small file-error" role="alert">
          {task.error}
        </p>
      )}
    </div>
  );
}

/**
 * The files of an item (servers with `attachments`, or an item that lists files): download for everyone who can read
 * it; attach and remove for those who can edit it (not while it is in the trash).
 */
export function ItemAttachments({ entry, canWrite }: { entry: VaultEntry; canWrite: boolean }) {
  const config = usePublicConfig();
  const feature = hasFeature(config, "attachments");
  const files = readAttachments(entry.item);
  const uploads = useUploads(entry.id);
  const transfers = filesSupported();
  const limitMb = attachmentLimitMb(config?.limits);
  const editable = canWrite && !isTrashed(entry);
  const canAttach = feature && editable && transfers;
  const [stored, setStored] = useState<StoredAttachment[] | null>(null);
  const [removing, setRemoving] = useState<Attachment | null>(null);
  const [cleaning, setCleaning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const show = feature || files.length > 0 || uploads.length > 0;
  const fileKey = files.map((f) => f.id).join(",");

  // The server's list says which listed files are gone and which uploads no item lists (left over).
  useEffect(() => {
    if (!show || (files.length === 0 && !editable)) return setStored(null);
    let live = true;
    storedAttachments(entry.id).then(
      (list) => live && setStored(list),
      () => live && setStored(null),
    );
    return () => {
      live = false;
    };
    // `fileKey` and the revision: the server's list changes when files come and go.
  }, [entry.id, entry.revision, fileKey, show, editable]);

  if (!show) return null;
  const missing = stored ? missingOnServer(files, stored) : new Set<string>();
  const extra = stored && editable ? leftovers(entry.item, stored, nowSeconds()) : [];

  function pick(e: ChangeEvent<HTMLInputElement>) {
    const picked = Array.from(e.target.files ?? []);
    e.target.value = "";
    if (picked.length === 0) return;
    const { ok, error: tooBig } = checkSizes(picked, limitMb);
    setError(tooBig);
    if (ok.length) attachFiles(entry.id, ok);
  }

  async function clean() {
    setCleaning(true);
    setError(null);
    try {
      for (const s of extra) await deleteStored(s.id);
      setStored(await storedAttachments(entry.id));
      toast(extra.length === 1 ? "Unfinished upload deleted" : "Unfinished uploads deleted");
    } catch (e) {
      setError(fileError(e));
    } finally {
      setCleaning(false);
    }
  }

  return (
    <section className="stack-s" aria-label="Attachments">
      <div className="row-between">
        <h2 className="section-title">Attachments{files.length > 0 ? ` (${files.length})` : ""}</h2>
        {canAttach && (
          <>
            <button type="button" className="btn btn-sm" onClick={() => input.current?.click()}>
              <Icon name="paperclip" size={16} /> Attach file
            </button>
            <input ref={input} type="file" multiple hidden onChange={pick} />
          </>
        )}
      </div>
      {(files.length > 0 || uploads.length > 0) && (
        <div className="file-list">
          {files.map((f) => (
            <FileRow key={f.id} file={f} itemId={entry.id} path={attachmentPath(f.id)} missing={missing.has(f.id)} onRemove={editable ? () => setRemoving(f) : undefined} />
          ))}
          {uploads.map((t) => (
            <UploadRow key={t.key} task={t} />
          ))}
        </div>
      )}
      {canAttach && files.length === 0 && uploads.length === 0 && (
        <p className="small muted">
          Add scans, documents or keys. Each file is encrypted on this device before it's uploaded{limitMb ? `, up to ${limitMb} MB each` : ""}.
        </p>
      )}
      {!transfers && (files.length > 0 || (feature && editable)) && <WebVaultNote action={files.length > 0 ? "download or add files" : "attach files"} />}
      {extra.length > 0 && (
        <div className="alert alert-warn small notice" role="note">
          <div className="grow">
            <span>
              {extra.length === 1 ? "An upload" : `${extra.length} uploads`} to this item didn't finish, and {extra.length === 1 ? "its file is" : "their files are"} still
              using {formatBytes(extra.reduce((n, s) => n + s.size, 0))} of storage.
            </span>
            <div className="row">
              <button type="button" className="link" onClick={clean} disabled={cleaning}>
                {cleaning ? "Deleting…" : extra.length === 1 ? "Delete it" : "Delete them"}
              </button>
            </div>
          </div>
        </div>
      )}
      <ErrorText error={error} />
      {removing && (
        <ConfirmDialog
          title="Remove this file?"
          subtitle={cleanFileName(removing.name)}
          icon="file"
          action="Remove file"
          busyAction="Removing…"
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            await removeAttachment(entry.id, removing.id);
            setRemoving(null);
            toast("File removed");
          }}
        >
          <p className="card-text">It's deleted from the server, for everyone who can open this item. Earlier versions of the item that list it can't bring it back.</p>
        </ConfirmDialog>
      )}
    </section>
  );
}

/**
 * Files picked while creating an item: kept here and uploaded after the item is saved (an upload needs the item to
 * exist on the server). For the editor's `extra` slot.
 */
export function NewItemFiles({ files, onChange }: { files: File[]; onChange: (files: File[]) => void }) {
  const config = usePublicConfig();
  const limitMb = attachmentLimitMb(config?.limits);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  if (!hasFeature(config, "attachments") || !filesSupported()) return null;

  function pick(e: ChangeEvent<HTMLInputElement>) {
    const picked = Array.from(e.target.files ?? []);
    e.target.value = "";
    const { ok, error: tooBig } = checkSizes(picked, limitMb);
    setError(tooBig);
    if (ok.length) onChange([...files, ...ok]);
  }

  return (
    <section className="stack-s" aria-label="Attachments">
      <div className="row-between">
        <h2 className="section-title">Attachments</h2>
        <button type="button" className="btn btn-sm" onClick={() => input.current?.click()}>
          <Icon name="paperclip" size={16} /> Attach file
        </button>
        <input ref={input} type="file" multiple hidden onChange={pick} />
      </div>
      {files.length > 0 && (
        <div className="file-list">
          {files.map((f, n) => (
            <div key={`${n}-${f.name}`} className="file-row">
              <div className="file-main">
                <span className="tile" aria-hidden="true">
                  <Icon name="file" />
                </span>
                <span className="grow">
                  <span className="row-title">{cleanFileName(f.name)}</span>
                  <span className="row-sub">{formatBytes(f.size)}</span>
                </span>
                <button
                  type="button"
                  className="btn btn-icon btn-quiet-danger"
                  aria-label={`Don't attach ${cleanFileName(f.name)}`}
                  title="Don't attach"
                  onClick={() => onChange(files.filter((_, j) => j !== n))}
                >
                  <Icon name="close" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="small muted">
        {files.length > 0 ? "They're encrypted and uploaded when you save the item." : "Files are encrypted on this device and uploaded when you save the item."}
      </p>
      <ErrorText error={error} />
    </section>
  );
}

/** Files of an item seen through emergency access: download only, from the access's own address. */
export function ReadOnlyFiles({ itemId, files, path }: { itemId: string; files: Attachment[]; path: (attachmentId: string) => string }) {
  if (files.length === 0) return null;
  return (
    <section className="stack-s" aria-label="Attachments">
      <h2 className="section-title">Attachments ({files.length})</h2>
      <div className="file-list">
        {files.map((f) => (
          <FileRow key={f.id} file={f} itemId={itemId} path={path(f.id)} />
        ))}
      </div>
      {!filesSupported() && <WebVaultNote action="download them" />}
    </section>
  );
}
