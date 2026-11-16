/**
 * New item (a login starts with the current website, or what the background asked for: `popupRoute`) or edit an
 * existing one, with the web vault's shared editor. Leaving with unsaved changes (Back, Cancel) asks first; the
 * pop-out window also asks the browser to confirm closing. The dice uses the generator's saved options. What is typed
 * is kept with the popup's view (view-state.ts `saveDraft`, 2 minutes, gone on lock, sign-out and account switch), so
 * a toolbar popup that closes (it does whenever the page is clicked) comes back with the draft. Under a website that
 * runs as a regular expression (spec §2; the web vault's `patternNote`, with this page's own core) the editor says why
 * the core refuses it (it would never match a page) or that it isn't tied to one website, so it could match other
 * sites (saving isn't blocked); a plain address under a "regex" default matches by domain and gets no note.
 */

import { ItemEditor } from "@web/components/ItemEditor";
import { ConfirmDialog } from "@web/components/ui";
import { patternNote } from "@web/lib/patterns";
import { emptyItem, type Item, type ItemKind, KIND_LABEL, kindOf } from "@web/lib/types";
import { useEffect, useRef, useState } from "react";
import { callPopup } from "../shared/protocol";
import { popupCore } from "./core";
import { activeTab, type Ctx, msg, type Prefill, parseUrl } from "./ctx";
import { generateWithSaved } from "./generator";
import { Page } from "./shell";
import { type Draft, saveDraft } from "./view-state";

/** A new item of `kind`, filled in from `prefill` or the page the user is on. */
export async function newItem(kind: ItemKind, prefill?: Prefill): Promise<Item> {
  const item = emptyItem(kind);
  const tab = prefill?.url ? null : await activeTab().catch(() => undefined);
  const address = prefill?.url ?? (tab?.url?.startsWith("http") ? tab.url : undefined);
  const page = address ? parseUrl(address) : null;
  if (item.login) {
    if (page && /^https?:$/.test(page.protocol)) {
      item.name = page.hostname.replace(/^www\./, "");
      item.login.urls = [{ url: page.origin, match: "default" }];
    }
    if (prefill?.username) item.login.username = prefill.username;
  }
  if (item.identity && prefill?.username) item.identity.username = prefill.username;
  return item;
}

export function EditPage({ id, kind, prefill, draft, ctx }: { id?: string; kind?: ItemKind; prefill?: Prefill; draft?: Draft | undefined; ctx: Ctx }) {
  const [init, setInit] = useState<{ item: Item; vaults: { id: string; name: string }[]; vaultId: string; folders: string[] } | null>(null);
  // This page's core, for the notes under websites that run as regular expressions (none until it has loaded).
  const [core, setCore] = useState<Awaited<ReturnType<typeof popupCore>> | null>(null);
  useEffect(() => {
    let live = true;
    popupCore().then(
      (c) => live && setCore(c),
      () => {},
    );
    return () => {
      live = false;
    };
  }, []);
  const defaultMatch = ctx.state.settings.defaultMatch;
  // Reopened with a draft: it is unsaved work from the start.
  const [dirty, setDirty] = useState(!!draft);
  const [leaving, setLeaving] = useState<(() => void) | null>(null);
  // The new item's id, kept for this editor (and its draft): saving again after a failure or a timeout can't create it twice.
  const newId = useRef(draft?.newId ?? crypto.randomUUID());
  const key = id ? `edit:${id}` : `new:${kind ?? "login"}`;
  const done = (to?: string) => {
    saveDraft(null);
    ctx.go(to ? { tab: "vault", page: "item", id: to } : { tab: "vault", page: "list" });
  };
  /** Leave the editor, after asking when there are unsaved changes. */
  const leave = () => (dirty ? setLeaving(() => () => done(id)) : done(id));
  // Leaving the editor any other way (the tab bar): the draft goes. Closing the popup keeps it (nothing unmounts).
  useEffect(() => () => saveDraft(null), []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: loads once per item or new kind (ctx and prefill change with every state reload)
  useEffect(() => {
    (async () => {
      const info = await callPopup("editorInfo");
      if (id) {
        const r = await callPopup("item", { id });
        return setInit({ item: structuredClone(draft?.item ?? r.item), vaults: [], vaultId: r.vaultId, folders: info.folders });
      }
      setInit({ item: draft ? structuredClone(draft.item) : await newItem(kind ?? "login", prefill), vaults: info.vaults, vaultId: info.defaultVault, folders: info.folders });
    })().catch((e) => ctx.notify(msg(e)));
  }, [id, kind]);

  // Closing the pop-out window with unsaved changes: the browser asks (a toolbar popup closes without asking).
  useEffect(() => {
    if (!dirty) return;
    const ask = (e: BeforeUnloadEvent) => e.preventDefault();
    addEventListener("beforeunload", ask);
    return () => removeEventListener("beforeunload", ask);
  }, [dirty]);

  const label = KIND_LABEL[init ? kindOf(init.item) : (kind ?? "login")].toLowerCase();
  return (
    <Page title={id ? `Edit ${label}` : `New ${label}`} onBack={leave}>
      {init && (
        <div className="pop-editor">
          <ItemEditor
            initial={init.item}
            isNew={!id}
            vaults={init.vaults}
            defaultVault={init.vaultId}
            folders={init.folders}
            generate={generateWithSaved}
            onDirtyChange={(d) => setDirty(d || !!draft)}
            onChange={(item) => saveDraft({ key, item, ...(id ? {} : { newId: newId.current }) })}
            {...(core ? { websiteNote: (url: string, match: Parameters<typeof patternNote>[2]) => patternNote(core, url, match, defaultMatch) } : {})}
            onCancel={leave}
            onSave={async (item, vaultId) => {
              if (id) {
                await callPopup("updateItem", { id, item });
                setDirty(false);
                ctx.notify("Changes saved.");
                done(id);
              } else {
                const saved = await callPopup("createItem", { item, vaultId, id: newId.current });
                setDirty(false);
                ctx.notify("Item saved.");
                done(saved);
              }
            }}
          />
        </div>
      )}
      {leaving && (
        <ConfirmDialog
          title="Discard your changes?"
          subtitle={init?.item.name || `New ${label}`}
          icon="edit"
          action="Discard changes"
          cancel="Keep editing"
          onClose={() => setLeaving(null)}
          onConfirm={() => {
            const go = leaving;
            setLeaving(null);
            setDirty(false);
            go();
          }}
        >
          <p className="card-text">What you changed in this {label} isn't saved yet.</p>
        </ConfirmDialog>
      )}
    </Page>
  );
}
