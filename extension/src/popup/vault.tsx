/**
 * Vault tab: the item list. It stays mounted while an item is open (Main hides it), so the search, the filters and
 * the scroll position are still there on the way back; the data is reloaded then. Keyboard: ↓ from the search field
 * enters the list, ↑/↓ move between rows (one tab stop for the list), Enter fills on the page (or opens the item),
 * → opens it, Ctrl/⌘+C copies the password, with Shift the user name, with Alt the verification code.
 */

import { Icon, type IconName, SiteIcon } from "@web/components/ui";
import { type ItemKind, KIND_LABEL } from "@web/lib/types";
import { type KeyboardEvent, type ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { callPopup } from "../shared/protocol";
import type { ItemList, ItemSummary } from "../shared/types";
import { activeTab, type Ctx, hostOf, msg } from "./ctx";
import { Notices } from "./notices";
import { searchItems } from "./search";
import { Account, Menu, MenuItem, Page, PopOut } from "./shell";
import { type ListFilter, NO_FILTER } from "./view-state";

const KINDS = Object.keys(KIND_LABEL) as ItemKind[];
const PLURAL: Record<ItemKind, string> = { login: "Logins", card: "Cards", identity: "Identities", note: "Notes", ssh_key: "SSH keys" };
/** Non-logins show what they are instead of a site icon. */
export const GLYPH: Record<ItemKind, IconName> = { login: "globe", note: "note", card: "card", identity: "person", ssh_key: "terminal" };

type Field = "username" | "password" | "totp";
const FIELD_LABEL: Record<Field, string> = { username: "Username", password: "Password", totp: "Verification code" };

/** The fields of a login row that can be copied. */
const copyable = (i: ItemSummary): Field[] => (i.kind !== "login" ? [] : ([i.username ? "username" : null, i.hasPassword ? "password" : null, i.hasTotp ? "totp" : null].filter(Boolean) as Field[]));

/** "GitHub (alex)": rows of the same site differ by user name in every label. */
const rowName = (i: ItemSummary) => (i.username ? `${i.name} (${i.username})` : i.name);

export const filtering = (f: ListFilter) => !!f.query.trim() || !!f.kind || f.folder !== null || f.favorite || f.vault !== null;

interface Row {
  key: string;
  item: ItemSummary;
  canFill: boolean;
}

export function VaultList({
  ctx,
  visible,
  version,
  filter,
  setFilter,
  scroll,
  onScroll,
}: {
  ctx: Ctx;
  /** Shown (the list is the current page); hidden while an item is open. */
  visible: boolean;
  /** Bumped to load the items again (back from an item, after a change). */
  version: number;
  filter: ListFilter;
  setFilter: (f: ListFilter) => void;
  /** Where the list was scrolled to (restored when it shows again). */
  scroll: number;
  onScroll: (top: number) => void;
}) {
  const [data, setData] = useState<ItemList | null>(null);
  const [tabId, setTabId] = useState<number | undefined>();
  const [host, setHost] = useState("");
  const [pageUrl, setPageUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [showFilter, setShowFilter] = useState(!!(filter.kind || filter.folder !== null || filter.favorite || filter.vault !== null));
  const [favOpen, setFavOpen] = useState<boolean | null>(null);
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const bodyRef = useRef<HTMLElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  /** Where the list is scrolled to (from the last visit when the popup reopens). */
  const lastScroll = useRef(scroll);

  useEffect(() => {
    // `version` asks for a fresh load; the rows on screen stay until it arrives.
    void version;
    let alive = true;
    activeTab()
      .then((tab) => {
        const url = tab?.url?.startsWith("http") ? tab.url : undefined;
        if (alive && url) {
          setHost(hostOf(url));
          setPageUrl(url);
          setTabId(tab?.id);
        }
        return callPopup("items", { url, ...(url && tab?.id !== undefined ? { tabId: tab.id } : {}) });
      })
      .then(
        (d) => {
          if (!alive) return;
          setData(d);
          setError(null);
        },
        (e) => alive && setError(msg(e)),
      );
    return () => {
      alive = false;
    };
  }, [version]);

  // Back to where the list was: once the first load is drawn, and whenever it shows again.
  useLayoutEffect(() => {
    const el = bodyRef.current;
    if (el && visible && data && el.scrollTop !== lastScroll.current) el.scrollTop = lastScroll.current;
  }, [visible, data]);

  // Back from an item: the focus returns to the row that was opened (else the search field).
  const wasVisible = useRef(visible);
  useEffect(() => {
    if (visible && !wasVisible.current) {
      const row = activeKey ? listRef.current?.querySelector<HTMLElement>(`.item-row[data-row="${CSS.escape(activeKey)}"] > .main`) : null;
      (row ?? searchRef.current)?.focus({ preventScroll: true });
    }
    wasVisible.current = visible;
  }, [visible, activeKey]);

  const fill = useCallback(
    async (id: string) => {
      if (tabId === undefined) return;
      try {
        await callPopup("fill", { id, tabId });
        window.close();
      } catch (e) {
        ctx.notify(msg(e));
      }
    },
    [tabId, ctx],
  );

  const suggestedIds = new Set(data?.suggested.map((i) => i.id));
  const searching = filtering(filter);
  const vaults = data ? [...new Map(data.all.map((i) => [i.vaultId ?? i.vaultName, i.vaultName])).entries()] : [];
  const folders = data ? [...new Set(data.all.map((i) => i.folder).filter(Boolean))].sort() : [];
  const keep = (i: ItemSummary) =>
    (!filter.kind || i.kind === filter.kind) &&
    (filter.folder === null || i.folder === filter.folder) &&
    (!filter.favorite || i.favorite) &&
    (filter.vault === null || (i.vaultId ?? i.vaultName) === filter.vault);
  const results = data && searching ? searchItems(data.all.filter(keep), filter.query, suggestedIds) : [];

  // The sections on screen, in order: the keyboard walks the rows in this order.
  const sections: { title: ReactNode; count: number; rows: Row[]; empty?: ReactNode; collapsed?: boolean; add?: ReactNode }[] = [];
  const newLogin = () => ctx.go({ tab: "vault", page: "new", kind: "login" });
  const addToExisting = () => pageUrl && ctx.go({ tab: "vault", page: "addSite", url: pageUrl });
  const rowsOf = (name: string, items: ItemSummary[]): Row[] =>
    items.map((item) => ({ key: `${name}:${item.id}`, item, canFill: suggestedIds.has(item.id) && item.kind === "login" && (item.hasPassword || !!item.username) }));
  if (data && searching) {
    sections.push({
      title: filter.query.trim() ? "Search results" : "Filtered items",
      count: results.length,
      rows: rowsOf("r", results),
      empty: (
        <div className="empty">
          <p className="empty-title">{filter.query.trim() ? `No items match "${filter.query.trim()}"` : "No items match these filters"}</p>
          <p>Search looks in names, user names, websites, tags and folders.</p>
          <button type="button" className="btn btn-text" onClick={() => setFilter(NO_FILTER)}>
            {filter.query.trim() && !filtering({ ...filter, query: "" }) ? "Clear search" : "Clear search and filters"}
          </button>
        </div>
      ),
    });
  } else if (data) {
    if (host) {
      sections.push({
        title: "Autofill suggestions",
        count: data.suggested.length,
        rows: rowsOf("s", data.suggested),
        add: <AddMenu host={host} onNew={newLogin} onExisting={addToExisting} />,
        empty: (
          <div className="empty">
            <p className="empty-title">No logins for {host}</p>
            <p>Use the same account here as on another site? Add {host} to that login. Or sign in on the page and PassAuth offers to save it.</p>
            <div className="empty-actions">
              <AddMenu host={host} onNew={newLogin} onExisting={addToExisting} primary />
            </div>
          </div>
        ),
      });
    }
    const favorites = data.all.filter((i) => i.favorite);
    // While the page has suggestions, Favorites start folded so the page's logins stay in view.
    const favExpanded = favOpen ?? !(host && data.suggested.length);
    if (favorites.length) {
      sections.push({
        title: (
          <button type="button" className="disclosure" aria-expanded={favExpanded} onClick={() => setFavOpen(!favExpanded)}>
            <Icon name="chevron" size={14} />
            Favorites
          </button>
        ),
        count: favorites.length,
        rows: favExpanded ? rowsOf("f", favorites) : [],
        collapsed: !favExpanded,
      });
    }
    sections.push({
      title: "All items",
      count: data.all.length,
      rows: rowsOf("a", data.all),
      empty: (
        <div className="empty">
          <span className="tile" aria-hidden="true">
            <Icon name="vault" size={22} />
          </span>
          <p className="empty-title">Your vault is empty</p>
          <p>Add your first login, or import your passwords in the web vault.</p>
          <div className="empty-actions">
            <button type="button" className="btn btn-primary" onClick={() => ctx.go({ tab: "vault", page: "new", kind: "login" })}>
              <Icon name="plus" /> New login
            </button>
          </div>
        </div>
      ),
    });
  }
  const order = sections.flatMap((s) => s.rows);
  const tabStop = order.some((r) => r.key === activeKey) ? activeKey : (order[0]?.key ?? null);

  const focusRow = (n: number) => {
    const mains = [...(listRef.current?.querySelectorAll<HTMLButtonElement>(".item-row > .main") ?? [])];
    if (n < 0) return searchRef.current?.focus();
    mains[Math.min(n, mains.length - 1)]?.focus();
  };

  function onListKey(e: KeyboardEvent<HTMLDivElement>) {
    const el = (e.target as HTMLElement).closest<HTMLElement>(".item-row");
    const index = order.findIndex((r) => r.key === el?.dataset.row);
    const row = order[index];
    if (!row) return;
    const onMain = (e.target as HTMLElement).classList.contains("main");
    const mod = e.ctrlKey || e.metaKey;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") focusRow(index + (e.key === "ArrowDown" ? 1 : -1));
    else if (e.key === "Home") focusRow(0);
    else if (e.key === "End") focusRow(order.length - 1);
    else if (onMain && e.key === "Enter") void (row.canFill ? fill(row.item.id) : ctx.go({ tab: "vault", page: "item", id: row.item.id }));
    else if (onMain && e.key === "ArrowRight") ctx.go({ tab: "vault", page: "item", id: row.item.id });
    else if (mod && e.code === "KeyC") {
      const field: Field = e.altKey ? "totp" : e.shiftKey ? "username" : "password";
      if (!copyable(row.item).includes(field)) return;
      void ctx.copy({ id: row.item.id, field }, FIELD_LABEL[field]);
    } else return;
    e.preventDefault();
  }

  const chip = (label: ReactNode, on: boolean, toggle: () => void, key: string) => (
    <button key={key} type="button" className="chip" aria-pressed={on} onClick={toggle}>
      {label}
    </button>
  );

  return (
    <Page
      title="Vault"
      brand
      bodyRef={bodyRef}
      onScroll={() => {
        if (!bodyRef.current || !visible) return;
        lastScroll.current = bodyRef.current.scrollTop;
        onScroll(lastScroll.current);
      }}
      actions={
        <>
          <Menu
            label="New item"
            className="btn btn-new"
            trigger={
              <>
                <Icon name="plus" /> New
              </>
            }
          >
            {KINDS.map((k) => (
              <MenuItem key={k} icon={GLYPH[k]} onClick={() => ctx.go({ tab: "vault", page: "new", kind: k })}>
                {KIND_LABEL[k]}
              </MenuItem>
            ))}
          </Menu>
          <PopOut />
          <Account state={ctx.state} onChange={ctx.reload} onSignOut={ctx.signOut} />
        </>
      }
    >
      <div className="search-bar">
        <label className="search">
          <Icon name="search" size={16} />
          <input
            ref={searchRef}
            type="search"
            placeholder="Search vault"
            aria-label="Search vault"
            aria-describedby="search-help"
            value={filter.query}
            onChange={(e) => setFilter({ ...filter, query: e.target.value })}
            onKeyDown={(e) => {
              if (e.key !== "ArrowDown") return;
              e.preventDefault();
              focusRow(0);
            }}
            autoFocus={visible}
          />
          {filter.query && (
            <button type="button" className="btn btn-icon" aria-label="Clear search" onClick={() => setFilter({ ...filter, query: "" })}>
              <Icon name="close" size={16} />
            </button>
          )}
        </label>
        <span id="search-help" className="sr-only">
          Press the down arrow to move to the results.
        </span>
        <button type="button" className={`btn btn-icon${showFilter ? " on" : ""}`} aria-label="Filters" title="Filters" aria-expanded={showFilter} onClick={() => setShowFilter(!showFilter)}>
          <Icon name="filter" />
        </button>
      </div>
      {showFilter && (
        <div className="filters">
          {/* biome-ignore lint/a11y/useSemanticElements: a row of toggle chips; a fieldset would bring its own border and spacing */}
          <div className="chips" role="group" aria-label="Show">
            {chip("All", !filter.kind && !filter.favorite && filter.vault === null, () => setFilter({ ...filter, kind: "", favorite: false, vault: null }), "all")}
            {KINDS.map((k) => chip(PLURAL[k], filter.kind === k, () => setFilter({ ...filter, kind: filter.kind === k ? "" : k }), k))}
            {chip(
              <>
                <Icon name="star" size={12} /> Favorites
              </>,
              filter.favorite,
              () => setFilter({ ...filter, favorite: !filter.favorite }),
              "fav",
            )}
            {vaults.length > 1 && vaults.map(([id, name]) => chip(name, filter.vault === id, () => setFilter({ ...filter, vault: filter.vault === id ? null : id }), `v:${id}`))}
          </div>
          {folders.length > 0 && (
            <select
              className="select"
              aria-label="Folder"
              value={filter.folder === null ? "\u0000any" : filter.folder}
              onChange={(e) => setFilter({ ...filter, folder: e.target.value === "\u0000any" ? null : e.target.value })}
            >
              <option value={"\u0000any"}>All folders</option>
              <option value="">No folder</option>
              {folders.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
          )}
        </div>
      )}
      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}
      <Notices ctx={ctx} data={data} tabId={tabId} />
      <p className="sr-only" role="status">
        {data && searching ? `${results.length} ${results.length === 1 ? "result" : "results"}` : ""}
      </p>
      {/* biome-ignore lint/a11y/noStaticElementInteractions: keyboard navigation for the rows inside (their buttons take the focus) */}
      <div className="sections" ref={listRef} onKeyDown={onListKey}>
        {sections.map((s, n) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the sections are fixed in number and order for one render
          <section key={n} className="group">
            <h2 className="group-title">
              <span>{s.title}</span>
              <span className="count">{s.count}</span>
              {s.add && s.rows.length > 0 && <span className="group-action">{s.add}</span>}
            </h2>
            {s.rows.length ? (
              <div className="list">
                {s.rows.map((r) => (
                  <ItemRow key={r.key} row={r} ctx={ctx} tabStop={r.key === tabStop} onFocusRow={setActiveKey} onFill={() => fill(r.item.id)} />
                ))}
              </div>
            ) : s.collapsed ? null : (
              s.empty
            )}
          </section>
        ))}
      </div>
    </Page>
  );
}

/**
 * "Add" for the page the user is on: a new login for it, or the site added to a login they already have (the same
 * account on another site). In the suggestions' heading, and as the button of their empty state.
 */
function AddMenu({ host, onNew, onExisting, primary }: { host: string; onNew: () => void; onExisting: () => void; primary?: boolean }) {
  return (
    <Menu
      label={`Add a login for ${host}`}
      className={primary ? "btn btn-primary" : "btn btn-text btn-sm"}
      trigger={
        <>
          <Icon name="plus" size={primary ? undefined : 14} /> Add
        </>
      }
    >
      <MenuItem icon="plus" onClick={onNew}>
        New login
      </MenuItem>
      <MenuItem icon="globe" onClick={onExisting}>
        Existing login…
      </MenuItem>
    </Menu>
  );
}

/** Copies at once and shows a check mark for a moment. */
function CopyNow({ label, tabIndex, onCopy }: { label: string; tabIndex: number; onCopy: () => Promise<boolean> }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1500);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <button type="button" className={`btn btn-icon${done ? " done" : ""}`} aria-label={label} title={label} tabIndex={tabIndex} onClick={() => void onCopy().then((ok) => ok && setDone(true))}>
      <Icon name={done ? "check" : "copy"} />
    </button>
  );
}

/** The row's picture: the site's icon for logins, a glyph of the item's type otherwise. */
export function ItemAvatar({ item, ctx }: { item: Pick<ItemSummary, "kind" | "host" | "name">; ctx: Ctx }) {
  if (item.kind !== "login")
    return (
      <span className="avatar glyph" aria-hidden="true">
        <Icon name={GLYPH[item.kind]} />
      </span>
    );
  return <SiteIcon host={item.host} name={item.name} server={ctx.state.server} enabled={ctx.state.iconsShown ?? ctx.state.settings.showIcons} />;
}

function ItemRow({ row, ctx, tabStop, onFocusRow, onFill }: { row: Row; ctx: Ctx; tabStop: boolean; onFocusRow: (key: string) => void; onFill: () => void }) {
  const i = row.item;
  const open = () => ctx.go({ tab: "vault", page: "item", id: i.id });
  const tab = tabStop ? 0 : -1;
  const fields = copyable(i);
  const who = rowName(i);
  const only = fields.length === 1 ? fields[0] : undefined;
  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: focus inside the row makes it the list's tab stop (keyboard handled on the list)
    <div className="item-row" data-row={row.key} onFocus={() => onFocusRow(row.key)}>
      <button type="button" className="main" tabIndex={tab} onClick={open}>
        <ItemAvatar item={i} ctx={ctx} />
        <span className="txt">
          <span className="title">
            <span>{i.name}</span>
            {i.favorite && (
              <span className="mark-icon" title="Favorite">
                <Icon name="star" size={12} />
                <span className="sr-only">, favorite</span>
              </span>
            )}
            {i.passkeys > 0 && (
              <span className="mark-icon passkey" title="Has a passkey">
                <Icon name="key" size={12} />
                <span className="sr-only">, has a passkey</span>
              </span>
            )}
            {i.shared && (
              <span className="mark" title={`In ${i.vaultName}, shared with you${i.vaultLabel ? ` (${i.vaultLabel})` : ""}`}>
                Shared
              </span>
            )}
          </span>
          {i.subtitle && <span className="sub">{i.subtitle}</span>}
        </span>
      </button>
      {row.canFill ? (
        <button type="button" className="btn btn-fill" aria-label={`Fill ${who}`} tabIndex={tab} onClick={onFill}>
          Fill
        </button>
      ) : i.url ? (
        <a className="btn btn-icon" href={i.url} target="_blank" rel="noreferrer" aria-label={`Open ${i.host || i.name}`} title="Open website" tabIndex={tab}>
          <Icon name="external" />
        </a>
      ) : null}
      {only ? (
        <CopyNow label={`Copy ${FIELD_LABEL[only].toLowerCase()} of ${who}`} tabIndex={tab} onCopy={() => ctx.copy({ id: i.id, field: only }, FIELD_LABEL[only])} />
      ) : fields.length > 1 ? (
        <Menu label={`Copy from ${who}`} trigger={<Icon name="copy" />} tabIndex={tab}>
          {fields.map((f) => (
            <MenuItem key={f} onClick={() => void ctx.copy({ id: i.id, field: f }, FIELD_LABEL[f])}>
              Copy {FIELD_LABEL[f].toLowerCase()}
            </MenuItem>
          ))}
        </Menu>
      ) : null}
      <Menu label={`More options for ${who}`} trigger={<Icon name="dots" />} tabIndex={tab}>
        {row.canFill && <MenuItem onClick={onFill}>Fill on this page</MenuItem>}
        <MenuItem onClick={open}>View</MenuItem>
        <MenuItem onClick={() => ctx.go({ tab: "vault", page: "edit", id: i.id })}>Edit</MenuItem>
        <MenuItem
          onClick={async () => {
            try {
              const r = await callPopup("item", { id: i.id });
              await callPopup("updateItem", { id: i.id, item: { ...r.item, favorite: !i.favorite } });
              ctx.notify(i.favorite ? "Removed from favorites." : "Added to favorites.");
              ctx.go({ tab: "vault", page: "list" });
            } catch (e) {
              ctx.notify(msg(e));
            }
          }}
        >
          {i.favorite ? "Remove from favorites" : "Add to favorites"}
        </MenuItem>
      </Menu>
    </div>
  );
}
