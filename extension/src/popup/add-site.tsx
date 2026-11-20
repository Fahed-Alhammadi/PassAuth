/**
 * "Add this site to a login" (popup → Add → Existing login): one account used on several sites, e.g. a mail login
 * that also signs in to a developer console on another domain. The user picks one of their logins and confirms;
 * the page's address becomes one more website of it (background/add-site.ts), so it is suggested and filled here
 * from now on instead of being saved twice. Once added, the login is filled on the page right away.
 *
 * The same confirmation (`AddSiteConfirm`) is used from the vault list's search: a login that isn't saved for the
 * page gets "Fill" too, which asks first, adds the site and fills. Never without that confirmation, so a look-alike
 * site can't get a login filled just because it was found by a search.
 */
import { ConfirmDialog, Icon } from "@web/components/ui";
import { useEffect, useRef, useState } from "react";
import { callPopup } from "../shared/protocol";
import type { ItemSummary } from "../shared/types";
import { activeTab, type Ctx, hostOf, msg } from "./ctx";
import { searchItems } from "./search";
import { Page } from "./shell";
import { ItemAvatar } from "./vault";

export function AddSitePage({ url, ctx }: { url: string; ctx: Ctx }) {
  const host = hostOf(url).replace(/^www\./, "");
  const [targets, setTargets] = useState<ItemSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [picked, setPicked] = useState<ItemSummary | null>(null);
  const [tabId, setTabId] = useState<number | undefined>();
  const searchRef = useRef<HTMLInputElement>(null);
  const back = () => ctx.go({ tab: "vault", page: "list" });

  useEffect(() => {
    callPopup("addSite:targets", { url }).then(setTargets, (e) => setError(msg(e)));
    // The tab to fill once the site is added: only while it still shows this site (the worker checks the frame again).
    activeTab().then(
      (tab) => tab?.id !== undefined && tab.url && sameOrigin(tab.url, url) && setTabId(tab.id),
      () => {},
    );
  }, [url]);

  const shown = targets ? (query.trim() ? searchItems(targets, query, new Set()) : targets) : [];

  return (
    <Page title="Add to a login" onBack={back}>
      <p className="card-text add-site-intro">
        Pick the login you use on <strong>{host}</strong>. PassAuth adds this site to it, so it is suggested here from now on.
      </p>
      <div className="search-bar">
        <label className="search">
          <Icon name="search" size={16} />
          <input ref={searchRef} type="search" placeholder="Search logins" aria-label="Search logins" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus />
          {query && (
            <button type="button" className="btn btn-icon" aria-label="Clear search" onClick={() => setQuery("")}>
              <Icon name="close" size={16} />
            </button>
          )}
        </label>
      </div>
      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}
      {targets && (
        <section className="group">
          <h2 className="group-title">
            <span>{query.trim() ? "Search results" : "Your logins"}</span>
            <span className="count">{shown.length}</span>
          </h2>
          {shown.length ? (
            <div className="list">
              {shown.map((i) => (
                <div key={i.id} className="item-row">
                  <button type="button" className="main" onClick={() => setPicked(i)}>
                    <ItemAvatar item={i} ctx={ctx} />
                    <span className="txt">
                      <span className="title">
                        <span>{i.name}</span>
                        {i.shared && (
                          <span className="mark" title={`In ${i.vaultName}, shared with you`}>
                            Shared
                          </span>
                        )}
                      </span>
                      <span className="sub">{[i.username, i.host].filter(Boolean).join(" · ")}</span>
                    </span>
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty">
              <p className="empty-title">{query.trim() ? `No logins match "${query.trim()}"` : "No logins to add this site to"}</p>
              <p>{query.trim() ? "Search looks in names, user names, websites, tags and folders." : "Logins already saved for this site are suggested on the vault page."}</p>
            </div>
          )}
        </section>
      )}
      {picked && <AddSiteConfirm item={picked} url={url} tabId={tabId} ctx={ctx} onClose={() => setPicked(null)} onDone={back} />}
    </Page>
  );
}

const sameOrigin = (a: string, b: string) => {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
};

/**
 * "Add <site> to <login>?": adds the page's address to the login, then fills it on the page (`tabId`, when the
 * login has something to fill). `onDone` runs when the popup stays open (nothing filled, or the fill failed).
 */
export function AddSiteConfirm({ item, url, tabId, ctx, onClose, onDone }: { item: ItemSummary; url: string; tabId: number | undefined; ctx: Ctx; onClose: () => void; onDone: () => void }) {
  const host = hostOf(url).replace(/^www\./, "");
  const fills = tabId !== undefined && (item.hasPassword || !!item.username);
  return (
    <ConfirmDialog
      title={`Add ${host} to ${item.name}?`}
      subtitle={item.username || undefined}
      icon="plus"
      action={fills ? "Add and fill" : "Add site"}
      busyAction="Adding…"
      danger={false}
      onClose={onClose}
      onConfirm={async () => {
        const added = await callPopup("addSite", { id: item.id, url });
        if (fills) {
          try {
            await callPopup("fill", { id: item.id, tabId });
            window.close();
            return;
          } catch (e) {
            ctx.notify(`${host} was added to ${item.name}, but it couldn't be filled: ${msg(e)}`);
            onDone();
            return;
          }
        }
        ctx.notify(added ? `${host} added to ${item.name}.` : `${item.name} is already saved for ${host}.`);
        onDone();
      }}
    >
      <p className="card-text">
        {fills ? `${item.name} will be filled now and suggested on ${host} from now on.` : `${item.name} will be suggested and filled on ${host}.`} Its user name and password stay the same. Add a site
        only when it uses the same account{item.host ? ` as ${item.host}` : ""}.
      </p>
      {item.shared && <p className="alert alert-warn">This login is in {item.vaultName}: everyone in that vault sees the new website.</p>}
    </ConfirmDialog>
  );
}
