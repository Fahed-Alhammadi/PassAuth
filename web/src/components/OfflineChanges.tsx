/**
 * Offline changes in the vault UI (desktop app; ARCHITECTURE "Offline changes"): the marker on changed items, the sync
 * status, the item page's bar (decide, Discard this change), the "Changed on another device" decision sheet, and the
 * warning before a list is deleted (sign-out). Nothing renders where the platform keeps no offline changes.
 */
import { useEffect, useState } from "react";
import {
  DISCARD_ACTION,
  DISCARD_BODY,
  DISCARD_TITLE,
  LIST_DROPPED,
  RESOLUTIONS,
  RESOLUTION_TEXT,
  diffFields,
  lostText,
  markerOf,
  statusLines,
  type OfflineChange,
  type Resolution,
} from "../lib/offline-changes";
import { isTrashed, type Item, type VaultEntry } from "../lib/types";
import { conflictView, deleteOfflineChanges, discardChange, dismissOfflineNotice, getState, logout, offlineChangesOn, pendingChangeCount, resolveChange, useVault } from "../lib/vault";
import { ConfirmDialog, ErrorText, Icon, Modal, SheetActions, toast } from "./ui";
import "../styles/offline.css";

const changeOf = (list: readonly OfflineChange[], itemId: string) => list.find((c) => c.item_id === itemId);

/** After a save: what to tell the user (a change that waits says so). */
export function savedText(itemId: string, online: string): string {
  return changeOf(getState().offlineChanges, itemId) ? "Saved on this device. It's sent when PassAuth can reach your server." : online;
}

/** The small marker on a changed item's row: "Waiting to sync", "Not sent: …", "Changed on another device". */
export function ChangeMarker({ itemId }: { itemId: string }) {
  const { offlineChanges } = useVault();
  const c = changeOf(offlineChanges, itemId);
  if (!c) return null;
  const m = markerOf(c);
  return (
    <span className={`offline-mark offline-${m.state}`} data-offline-mark={m.state} title={m.text}>
      <Icon name={m.state === "waiting" ? "sync" : "info"} size={12} />
      <span className="offline-mark-text">{m.text}</span>
    </span>
  );
}

const unseenName = (c: OfflineChange) => c.item?.name || (c.kind === "trash" ? "An item you moved to the trash" : "Untitled");

/** The sync status: "N changes waiting to sync" / "N changes need your decision", with a way to the first decision. */
export function OfflineStatus() {
  const { offlineChanges, offlineNotice, items } = useVault();
  const [deciding, setDeciding] = useState<string | null>(null);
  const [discarding, setDiscarding] = useState<OfflineChange | null>(null);
  const notice = offlineNotice && (
    <div className="alert small notice alert-warn" role="status" data-offline-notice>
      <div className="grow">
        <span>{offlineNotice}</span>
        {offlineNotice === LIST_DROPPED && (
          <div className="row">
            <button type="button" className="link" onClick={dismissOfflineNotice}>
              OK
            </button>
          </div>
        )}
      </div>
    </div>
  );
  if (!offlineChanges.length) return notice || null;
  const lines = statusLines({ version: 1, changes: offlineChanges });
  const first = offlineChanges.find((c) => c.state === "conflict");
  // Changes whose item isn't shown (its vault is gone or not shown here) have no item page: discarded from here.
  const shown = new Set(items.map((e) => e.id));
  const unseen = offlineChanges.filter((c) => !shown.has(c.item_id));
  return (
    <>
      {notice}
      <div className={`alert small notice ${lines.decisions ? "alert-warn" : "alert-info"}`} role="status" data-offline-status>
        <div className="grow">
          {[lines.decisions, lines.waiting].filter(Boolean).map((l) => (
            <span key={l} className="offline-status-line">
              {l}
            </span>
          ))}
          {first && (
            <div className="row">
              <button type="button" className="link" onClick={() => setDeciding(first.item_id)}>
                Decide now
              </button>
            </div>
          )}
          {unseen.map((c) => (
            <div key={c.id} className="row" data-offline-unseen>
              <span className="grow">
                {unseenName(c)}: {markerOf(c).text}
              </span>
              <button type="button" className="link" onClick={() => setDiscarding(c)}>
                {DISCARD_ACTION}
              </button>
            </div>
          ))}
        </div>
        {deciding && <ConflictSheet itemId={deciding} onClose={() => setDeciding(null)} />}
        {discarding && (
          <ConfirmDialog
            title={DISCARD_TITLE}
            subtitle={unseenName(discarding)}
            icon="trash"
            action={DISCARD_ACTION}
            busyAction="Discarding…"
            onClose={() => setDiscarding(null)}
            onConfirm={async () => {
              await discardChange(discarding.item_id);
              setDiscarding(null);
              toast("Change discarded");
            }}
          >
            <p className="card-text">{DISCARD_BODY}</p>
          </ConfirmDialog>
        )}
      </div>
    </>
  );
}

/** The item page's bar for an item with a change: its state, the decision (conflicts) and Discard this change. */
export function ItemChangeBar({ entry }: { entry: VaultEntry }) {
  const { offlineChanges } = useVault();
  const [discarding, setDiscarding] = useState(false);
  const [deciding, setDeciding] = useState(false);
  const c = changeOf(offlineChanges, entry.id);
  if (!c) return null;
  const m = markerOf(c);
  return (
    <div className={`alert small notice ${m.state === "waiting" ? "alert-info" : "alert-warn"}`} role="note" data-offline-item={m.state}>
      <div className="grow">
        <span>
          {m.state === "waiting"
            ? `${m.text}. ${c.kind === "trash" ? "Moving it to the trash" : c.kind === "create" ? "This new item" : "Your change"} is sent when PassAuth can reach your server.`
            : m.state === "conflict"
              ? `${m.text}. Choose which version to keep. Nothing is sent until you do.`
              : m.text}
        </span>
        <div className="row">
          {m.state === "conflict" && (
            <button type="button" className="link" onClick={() => setDeciding(true)}>
              Decide…
            </button>
          )}
          <button type="button" className="link" onClick={() => setDiscarding(true)}>
            {DISCARD_ACTION}
          </button>
        </div>
      </div>
      {discarding && (
        <ConfirmDialog
          title={DISCARD_TITLE}
          subtitle={entry.item.name || "Untitled"}
          icon="trash"
          action={DISCARD_ACTION}
          busyAction="Discarding…"
          onClose={() => setDiscarding(false)}
          onConfirm={async () => {
            await discardChange(entry.id);
            setDiscarding(false);
            toast("Change discarded");
          }}
        >
          <p className="card-text">{DISCARD_BODY}</p>
        </ConfirmDialog>
      )}
      {deciding && <ConflictSheet itemId={entry.id} onClose={() => setDeciding(false)} />}
    </div>
  );
}

const PRIMARY: Record<Resolution, string> = {
  "keep-mine": "Keep mine",
  "keep-other": "Keep the other",
  "keep-both": "Keep both",
  "save-new": "Save mine as a new item",
  discard: "Discard mine",
  "trash-anyway": "Move to trash anyway",
};

/** One version's fields, with the ones that differ marked and secrets hidden until shown. */
function Compare({ mine, other, mineNote, otherNote }: { mine: Item | null; other: Item | null; mineNote?: string; otherNote?: string }) {
  const [shown, setShown] = useState(false);
  // A trash keeps no copy of the item on this device: only the state differs, so no field is marked.
  const rows = diffFields(mine, other).map((r) => (mine ? r : { ...r, differs: false }));
  const anySecret = rows.some((r) => r.secret && r.differs);
  const value = (v: string, secret: boolean) => (!v ? <span className="muted">—</span> : secret && !shown ? "••••••••" : v);
  return (
    <div className="offline-compare" role="table" aria-label="Both versions">
      <div className="offline-compare-row offline-compare-head" role="row">
        <span role="columnheader" />
        <span role="columnheader">This device</span>
        <span role="columnheader">Other device</span>
      </div>
      {(mineNote || otherNote) && (
        <div className="offline-compare-row" role="row">
          <span role="rowheader" className="offline-compare-label">
            State
          </span>
          <span role="cell">{mineNote ?? "—"}</span>
          <span role="cell">{otherNote ?? "—"}</span>
        </div>
      )}
      {rows.map((r) => (
        <div key={r.label} className={r.differs ? "offline-compare-row differs" : "offline-compare-row"} role="row" data-differs={r.differs || undefined}>
          <span role="rowheader" className="offline-compare-label">
            {r.differs && <span className="offline-dot" aria-label="Differs" />}
            {r.label}
          </span>
          <span role="cell" className={r.secret ? "mono" : undefined}>
            {value(r.mine, r.secret)}
          </span>
          <span role="cell" className={r.secret ? "mono" : undefined}>
            {value(r.other, r.secret)}
          </span>
        </div>
      ))}
      {anySecret && (
        <button type="button" className="btn btn-text btn-sm" onClick={() => setShown(!shown)}>
          <Icon name={shown ? "eyeOff" : "eye"} size={16} /> {shown ? "Hide passwords" : "Show passwords"}
        </button>
      )}
    </div>
  );
}

/** Decision sheet "Changed on another device": both versions, then the answers this kind of change has. */
export function ConflictSheet({ itemId, onClose }: { itemId: string; onClose: () => void }) {
  const { offlineChanges } = useVault();
  const view = conflictView(itemId);
  const choices = view ? RESOLUTIONS[view.kind] : [];
  const [answer, setAnswer] = useState<Resolution | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Decided (or discarded) meanwhile: nothing left to ask.
  useEffect(() => {
    if (!changeOf(offlineChanges, itemId) && !busy) onClose();
  }, [offlineChanges, itemId, busy, onClose]);
  if (!view) return null;
  const picked = answer ?? choices[0];
  const mine = view.change.item;
  const other = view.other?.item ?? null;
  const name = mine?.name || other?.name || "Untitled";
  const subtitle =
    view.moved
      ? view.kind === "trash"
        ? "You moved it to the trash here. It was moved to another vault on another device."
        : "Moved to another vault on another device while you changed it here."
      : view.kind === "deleted"
      ? "Deleted on another device while you changed it here."
      : view.kind === "trash"
        ? "You moved it to the trash here. It was changed on another device."
        : "Changed here and on another device.";

  async function decide() {
    setBusy(true);
    setError(null);
    try {
      await resolveChange(itemId, picked);
      toast(picked === "keep-other" || picked === "discard" ? "Change discarded" : "Saved on this device. Sending…");
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <Modal title={view.moved ? "Moved on another device" : "Changed on another device"} subtitle={`${name} · ${subtitle}`} icon="sync" onClose={() => !busy && onClose()}>
      <div className="stack-s" data-conflict-sheet={view.kind}>
        <Compare
          mine={mine}
          other={other}
          mineNote={view.kind === "trash" ? "Moved to the trash" : view.kind === "deleted" ? "Changed" : undefined}
          otherNote={view.moved ? "In another vault" : view.kind === "deleted" ? "Deleted" : view.other && isTrashed(view.other) ? "In the trash" : view.kind === "trash" ? "Changed" : undefined}
        />
        <div className="choices choices-plain" role="radiogroup" aria-label="Which version to keep">
          {choices.map((r) => (
            <label key={r} className="choice">
              <input type="radio" name="offline-answer" checked={picked === r} onChange={() => setAnswer(r)} />
              <span className="choice-text">
                <span className="choice-title">{RESOLUTION_TEXT[r].title}</span>
                <span className="choice-sub">{RESOLUTION_TEXT[r].sub}</span>
              </span>
            </label>
          ))}
        </div>
        <ErrorText error={error} />
        <SheetActions
          quiet={
            <button type="button" className="btn btn-text" onClick={onClose} disabled={busy}>
              Not now
            </button>
          }
        >
          <button type="button" className="btn btn-primary btn-block" onClick={decide} disabled={busy} data-autofocus="">
            {busy ? "Saving…" : PRIMARY[picked]}
          </button>
        </SheetActions>
      </div>
    </Modal>
  );
}

// ----------------------------------------------------------- losing the list

/** The number of changes that would be lost (null: some, but the vault is locked), or 0. Re-read on every change. */
export function usePendingChangeCount(): number | null {
  const { offlineChanges, status } = useVault();
  const [count, setCount] = useState<number | null>(0);
  useEffect(() => {
    let live = true;
    if (!offlineChangesOn()) return;
    void pendingChangeCount().then((n) => live && setCount(n));
    return () => {
      live = false;
    };
  }, [offlineChanges, status]);
  return count;
}

/** The warning paragraph for a dialog that deletes the list (empty when nothing would be lost). */
export function LostChangesWarning() {
  const count = usePendingChangeCount();
  if (count === 0) return null;
  return (
    <div className="alert alert-warn small" role="alert" data-lost-changes>
      {lostText(count)}
    </div>
  );
}

let askSignOut: ((yes: boolean) => void) | null = null;
const signOutListeners = new Set<() => void>();

/**
 * Sign out. With offline changes waiting on this device the user is warned first ("N changes haven't been sent and will
 * be lost."), and the list is deleted when they go on. Elsewhere (no changes, browser, extension) it signs out at once.
 */
export async function signOut(): Promise<void> {
  const count = await pendingChangeCount();
  if (count !== 0) {
    const yes = await new Promise<boolean>((resolve) => {
      askSignOut = (answer) => {
        askSignOut = null;
        signOutListeners.forEach((fn) => fn());
        resolve(answer);
      };
      signOutListeners.forEach((fn) => fn());
    });
    if (!yes) return;
    await deleteOfflineChanges();
  }
  await logout();
}

/** Where the sign-out warning shows; mounted once at the app's root. */
export function SignOutPrompt() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const refresh = () => setOpen(askSignOut !== null);
    signOutListeners.add(refresh);
    return () => {
      signOutListeners.delete(refresh);
    };
  }, []);
  if (!open) return null;
  return (
    <ConfirmDialog title="Sign out?" icon="logout" action="Sign out" onClose={() => askSignOut?.(false)} onConfirm={() => askSignOut?.(true)}>
      <LostChangesWarning />
    </ConfirmDialog>
  );
}
