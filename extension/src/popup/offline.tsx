/**
 * Offline changes in the popup (ARCHITECTURE "Offline changes"): the marker an item carries, "Discard this change",
 * the "Waiting to sync" page with every change, and the decision sheet "Changed on another device" (both versions,
 * the fields that differ marked, passwords hidden until shown, then the choices). The background decides and sends
 * (background/vault.ts section "offline changes").
 */
import { ConfirmDialog, ErrorText, Icon, SheetActions, SiteIcon } from "@web/components/ui";
import { type FormEvent, useCallback, useEffect, useState } from "react";
import { DISCARD_TEXT } from "../shared/offline-text";
import { callPopup } from "../shared/protocol";
import type { ConflictView, OfflineChangeList, OfflineMark } from "../shared/types";
import { type Ctx, msg } from "./ctx";
import { BrandBar, Choices, Context, Tile } from "./sheet";
import { Page, PopOut } from "./shell";

/** An item's marker: "Waiting to sync", "Not sent: <reason>", "Changed on another device". */
export function OfflineBadge({ mark, className = "" }: { mark: OfflineMark; className?: string }) {
  return (
    <span className={`offline-mark ${mark.state} ${className}`.trim()}>
      <Icon name={mark.state === "conflict" ? "shield" : "sync"} size={13} />
      <span>{mark.text}</span>
    </span>
  );
}

/** Ask before a change is dropped, then drop it. */
export function DiscardDialog({ itemId, name, onClose, onDone }: { itemId: string; name: string; onClose: () => void; onDone: () => void }) {
  return (
    <ConfirmDialog
      title="Discard this change?"
      subtitle={name}
      icon="trash"
      action="Discard change"
      busyAction="Discarding…"
      onClose={onClose}
      onConfirm={async () => {
        await callPopup("offline:discard", { itemId });
        onDone();
      }}
    >
      <p className="card-text">{DISCARD_TEXT}</p>
    </ConfirmDialog>
  );
}

/** The item page's box: the marker, then Decide (a conflict) and Discard this change. */
export function OfflineBox({ itemId, name, mark, ctx, onDiscarded }: { itemId: string; name: string; mark: OfflineMark; ctx: Ctx; onDiscarded: () => void }) {
  const [discarding, setDiscarding] = useState(false);
  return (
    <div className={`offline-box ${mark.state}`} role="note">
      <OfflineBadge mark={mark} />
      <div className="row offline-actions">
        {mark.state === "conflict" && (
          <button type="button" className="btn btn-primary" onClick={() => ctx.go({ tab: "vault", page: "conflict", id: itemId })}>
            Decide…
          </button>
        )}
        <button type="button" className="btn btn-text" onClick={() => setDiscarding(true)}>
          Discard this change
        </button>
      </div>
      {discarding && (
        <DiscardDialog
          itemId={itemId}
          name={name}
          onClose={() => setDiscarding(false)}
          onDone={() => {
            ctx.notify("Your change was discarded.");
            onDiscarded();
          }}
        />
      )}
    </div>
  );
}

/** Every change waiting, oldest first: open it, decide it, or discard it; "Sync now" tries to send them. */
export function ChangesPage({ ctx }: { ctx: Ctx }) {
  const [data, setData] = useState<OfflineChangeList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [discard, setDiscard] = useState<{ itemId: string; name: string } | null>(null);
  const load = useCallback(() => callPopup("offline:list").then(setData, (e) => setError(msg(e))), []);
  useEffect(() => void load(), [load]);
  const back = () => ctx.go({ tab: "vault", page: "list" });
  async function syncNow() {
    setSyncing(true);
    setError(null);
    try {
      await callPopup("sync");
      await load();
    } catch (e) {
      setError(msg(e));
    } finally {
      setSyncing(false);
    }
  }
  return (
    <Page
      title="Waiting to sync"
      onBack={back}
      actions={<PopOut />}
      footer={
        <button type="button" className="btn btn-primary btn-block" disabled={syncing} onClick={() => void syncNow()}>
          <Icon name="sync" /> {syncing ? "Syncing…" : "Sync now"}
        </button>
      }
    >
      <p className="small muted offline-intro">Changes you made while PassAuth couldn't reach your server. They're sent when it answers again. {data?.text ? <strong>{data.text}.</strong> : null}</p>
      <ErrorText error={error} />
      {data && !data.changes.length && <p className="card-text">Everything is synced.</p>}
      {data && data.changes.length > 0 && (
        <div className="list offline-list">
          {data.changes.map((c) => (
            <div key={c.itemId} className="item-row offline-row">
              <button type="button" className="main" disabled={c.kind === "trash"} onClick={() => ctx.go({ tab: "vault", page: "item", id: c.itemId })}>
                <Tile name={c.name} />
                <span className="txt">
                  <span className="title">
                    <span>{c.name}</span>
                  </span>
                  <span className="sub">
                    {c.kind === "create" ? "New item" : c.kind === "trash" ? "Move to trash" : "Edited"} · {c.vaultName}
                  </span>
                  <OfflineBadge mark={c} className="sub" />
                </span>
              </button>
              {c.state === "conflict" && (
                <button type="button" className="btn btn-fill" onClick={() => ctx.go({ tab: "vault", page: "conflict", id: c.itemId })}>
                  Decide
                </button>
              )}
              <button type="button" className="btn btn-icon" aria-label={`Discard the change to ${c.name}`} title="Discard this change" onClick={() => setDiscard({ itemId: c.itemId, name: c.name })}>
                <Icon name="close" />
              </button>
            </div>
          ))}
        </div>
      )}
      {discard && (
        <DiscardDialog
          itemId={discard.itemId}
          name={discard.name}
          onClose={() => setDiscard(null)}
          onDone={() => {
            setDiscard(null);
            ctx.notify("Your change was discarded.");
            void load();
          }}
        />
      )}
    </Page>
  );
}

const TITLES: Record<ConflictView["kind"], string> = {
  edit: "Changed on another device",
  deleted: "Deleted on another device",
  trash: "Changed on another device",
};

const INTRO: Record<ConflictView["kind"], string> = {
  edit: "You changed this item while offline, and it was also changed on another device. Choose what to keep.",
  deleted: "You changed this item while offline, but it was deleted on another device.",
  trash: "You moved this item to the trash while offline, but it was changed on another device.",
};

/** Each choice's icon on its row. */
const CHOICE_ICON: Record<ConflictView["choices"][number]["id"], "desktop" | "sync" | "copy" | "plus" | "close" | "trash"> = {
  mine: "desktop",
  other: "sync",
  both: "copy",
  new: "plus",
  discard: "close",
  trash: "trash",
};

/** What the primary button says for each choice. */
const ACTION: Record<ConflictView["choices"][number]["id"], string> = {
  mine: "Keep mine",
  other: "Keep the other",
  both: "Keep both",
  new: "Save mine as a new item",
  discard: "Discard mine",
  trash: "Move to trash anyway",
};

/** One field of the comparison: this device's value and the other device's, the differing ones marked. */
function FieldPair({ f, view, shown, toggle }: { f: ConflictView["fields"][number]; view: ConflictView; shown: boolean; toggle: () => void }) {
  const hide = f.secret && !shown;
  // Marked only when there are two versions to compare (a trash or a deletion shows one side).
  const differs = f.differs && view.hasMine && view.hasTheirs;
  const value = (v: string) => (v ? hide ? "••••••••" : v : <span className="muted">—</span>);
  return (
    <div className={differs ? "diff-row differs" : "diff-row"}>
      <div className="diff-label">
        <span>{f.label}</span>
        {differs && <span className="diff-flag">Different</span>}
        {f.secret && (
          <button type="button" className="btn btn-text diff-show" aria-pressed={shown} onClick={toggle}>
            {shown ? "Hide" : "Show"}
          </button>
        )}
      </div>
      {view.hasMine && (
        <div className="diff-side">
          <span className="diff-who">This device</span>
          <span className={f.secret && shown ? "diff-value mono" : "diff-value"}>{value(f.mine)}</span>
        </div>
      )}
      {view.hasTheirs && (
        <div className="diff-side">
          <span className="diff-who">Other device</span>
          <span className={f.secret && shown ? "diff-value mono" : "diff-value"}>{value(f.theirs)}</span>
        </div>
      )}
    </div>
  );
}

/**
 * The decision sheet for one change in conflict ("Decision sheet" anatomy: brand bar, context row, the comparison,
 * one grouped card of choices, then one primary action with "Not now" beneath it).
 */
export function ConflictPage({ id, ctx }: { id: string; ctx: Ctx }) {
  const [view, setView] = useState<ConflictView | null>(null);
  const [choice, setChoice] = useState<string | undefined>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState<Set<string>>(new Set());
  useEffect(() => {
    callPopup("offline:conflict", { itemId: id }).then(
      (v) => {
        setView(v);
        setChoice(v.choices[0]?.id);
      },
      (e) => setError(msg(e)),
    );
  }, [id]);
  const done = () => ctx.go({ tab: "vault", page: "list" });
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!view || !choice) return;
    setBusy(true);
    setError(null);
    try {
      await callPopup("offline:resolve", { itemId: id, choice: choice as ConflictView["choices"][number]["id"] });
      ctx.notify(choice === "other" || choice === "discard" ? "Your change was dropped." : "Saved. It's sent when your server answers.");
      done();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }
  const differing = view?.fields.filter((f) => f.differs).length ?? 0;
  return (
    <div className="pop-sheet">
      <form className="sheet" onSubmit={submit} aria-busy={busy} aria-label={view ? TITLES[view.kind] : "Changed on another device"}>
        <BrandBar />
        <div className="modal-body">
          <Context
            icon={view?.host ? <SiteIcon host={view.host} name={view.name} server={ctx.state.server} enabled={ctx.state.iconsShown ?? ctx.state.settings.showIcons} /> : <Tile name={view?.name} />}
            title={view ? TITLES[view.kind] : "Changed on another device"}
            sub={view ? `${view.name} · ${view.vaultName}` : undefined}
          />
          {view && (
            <>
              <p className="sheet-note">{INTRO[view.kind]}</p>
              {view.fields.length > 0 && (
                <section className="diff" aria-label={differing ? `${differing} ${differing === 1 ? "field differs" : "fields differ"}` : "Both versions"}>
                  {view.fields.map((f, n) => (
                    <FieldPair
                      // biome-ignore lint/suspicious/noArrayIndexKey: labels repeat (custom fields); the list is fixed for this sheet
                      key={n}
                      f={f}
                      view={view}
                      shown={shown.has(String(n))}
                      toggle={() =>
                        setShown((s) => {
                          const next = new Set(s);
                          if (!next.delete(String(n))) next.add(String(n));
                          return next;
                        })
                      }
                    />
                  ))}
                </section>
              )}
              <Choices
                label="What to keep"
                options={view.choices.map((c) => ({
                  id: c.id,
                  title: c.title,
                  sub: c.sub,
                  icon: (
                    <Tile>
                      <Icon name={CHOICE_ICON[c.id]} />
                    </Tile>
                  ),
                }))}
                value={choice}
                onChange={setChoice}
                disabled={busy}
              />
            </>
          )}
          <ErrorText error={error} />
          <SheetActions
            quiet={
              <button type="button" className="btn btn-text" disabled={busy} onClick={done}>
                Not now
              </button>
            }
          >
            <button type="submit" className="btn btn-primary btn-block" disabled={busy || !view || !choice}>
              {busy ? "Saving…" : choice ? ACTION[choice as keyof typeof ACTION] : "Choose"}
            </button>
          </SheetActions>
        </div>
      </form>
    </div>
  );
}
