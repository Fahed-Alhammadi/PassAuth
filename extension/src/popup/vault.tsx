/** Vault tab: item list, item page, editor. */
import { useEffect, useState, type ReactNode } from "react";
import { ItemEditor } from "@web/components/ItemEditor";
import { ErrorText, Icon, SiteIcon } from "@web/components/ui";
import { emptyItem, KIND_LABEL, kindOf, type Item, type ItemKind } from "@web/lib/types";
import { send, type ItemSummary } from "../shared/messages";
import { activeTab, formatDate, msg, type Ctx } from "./ctx";
import { Account, Menu, MenuItem, Page, PopOut, Ring } from "./shell";

const KINDS = Object.keys(KIND_LABEL) as ItemKind[];

export interface ListFilter {
  query: string;
  kind: ItemKind | "";
  folder: string | null; // null = any, "" = no folder
}

// ------------------------------------------------------------------ list

export function VaultList({ ctx, filter, setFilter }: { ctx: Ctx; filter: ListFilter; setFilter: (f: ListFilter) => void }) {
  const [data, setData] = useState<{ suggested: ItemSummary[]; all: ItemSummary[] } | null>(null);
  const [tabId, setTabId] = useState<number | undefined>();
  const [host, setHost] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [showFilter, setShowFilter] = useState(!!(filter.kind || filter.folder !== null));

  useEffect(() => {
    activeTab().then((tab) => {
      const url = tab?.url?.startsWith("http") ? tab.url : undefined;
      if (url) (setHost(new URL(url).hostname), setTabId(tab?.id));
      send({ type: "items", url }).then(setData, (e) => setError(msg(e)));
    });
  }, []);

  async function fill(id: string) {
    if (tabId === undefined) return;
    try {
      await send({ type: "fill", id, tabId });
      window.close();
    } catch (e) {
      ctx.notify(msg(e));
    }
  }

  const q = filter.query.trim().toLowerCase();
  const filtering = !!q || !!filter.kind || filter.folder !== null;
  const keep = (i: ItemSummary) =>
    (!q || i.name.toLowerCase().includes(q) || i.subtitle.toLowerCase().includes(q) || i.host.includes(q)) &&
    (!filter.kind || i.kind === filter.kind) &&
    (filter.folder === null || i.folder === filter.folder);
  const folders = data ? [...new Set(data.all.map((i) => i.folder).filter(Boolean))].sort() : [];
  const suggestedIds = new Set(data?.suggested.map((i) => i.id));

  const row = (i: ItemSummary) => <ItemRow key={i.id} item={i} ctx={ctx} canFill={suggestedIds.has(i.id)} onFill={() => fill(i.id)} />;
  const section = (title: string, items: ItemSummary[], empty?: ReactNode) => (
    <section className="group">
      <h2 className="group-title">
        <span>{title}</span>
        <span className="count">{items.length}</span>
      </h2>
      {items.length ? <div className="list">{items.slice(0, 300).map(row)}</div> : empty}
    </section>
  );

  return (
    <Page
      title="Vault"
      brand
      actions={
        <>
          <Menu label="New item" className="btn btn-accent btn-new" trigger={<><Icon name="plus" /> New</>}>
            {KINDS.map((k) => (
              <MenuItem key={k} onClick={() => ctx.go({ tab: "vault", page: "new", kind: k })}>
                {KIND_LABEL[k]}
              </MenuItem>
            ))}
          </Menu>
          <PopOut />
          <Account state={ctx.state} onChange={ctx.reload} />
        </>
      }
    >
      <div className="search-bar">
        <label className="search">
          <Icon name="search" size={16} />
          <input type="search" placeholder="Search vault" aria-label="Search vault" value={filter.query} onChange={(e) => setFilter({ ...filter, query: e.target.value })} autoFocus />
          {filter.query && (
            <button className="btn btn-icon" aria-label="Clear search" onClick={() => setFilter({ ...filter, query: "" })}>
              <Icon name="close" size={16} />
            </button>
          )}
        </label>
        <button className={`btn btn-icon${showFilter ? " on" : ""}`} aria-label="Filters" title="Filters" aria-expanded={showFilter} onClick={() => setShowFilter(!showFilter)}>
          <Icon name="filter" />
        </button>
      </div>
      {showFilter && (
        <div className="filters">
          <select className="select" aria-label="Type" value={filter.kind} onChange={(e) => setFilter({ ...filter, kind: e.target.value as ItemKind | "" })}>
            <option value="">All types</option>
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {KIND_LABEL[k]}
              </option>
            ))}
          </select>
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
        </div>
      )}
      <ErrorText error={error} />
      {data &&
        (filtering ? (
          section(q ? "Search results" : "Filtered items", data.all.filter(keep), <p className="empty">No items match. Try another search or clear the filters.</p>)
        ) : (
          <>
            {host &&
              section(
                "Autofill suggestions",
                data.suggested,
                <p className="empty">No logins saved for {host}. Sign in on the page and PassAuth will offer to save it.</p>,
              )}
            {data.all.some((i) => i.favorite) && section("Favorites", data.all.filter((i) => i.favorite))}
            {section(
              "All items",
              data.all,
              <div className="empty">
                <p>Your vault is empty.</p>
                <button className="btn btn-accent" onClick={() => ctx.go({ tab: "vault", page: "new", kind: "login" })}>
                  <Icon name="plus" /> New login
                </button>
              </div>,
            )}
          </>
        ))}
    </Page>
  );
}

function ItemRow({ item: i, ctx, canFill, onFill }: { item: ItemSummary; ctx: Ctx; canFill: boolean; onFill: () => void }) {
  const open = () => ctx.go({ tab: "vault", page: "item", id: i.id });
  const { server, settings } = ctx.state;
  return (
    <div className="item-row">
      <button className="main" onClick={open}>
        <SiteIcon host={i.host} name={i.name} server={server} enabled={settings.showIcons} />
        <span className="txt">
          <span className="title">
            {i.name}
            {i.favorite && <Icon name="star" size={12} />}
          </span>
          {i.subtitle && <span className="sub">{i.subtitle}</span>}
        </span>
      </button>
      {canFill && i.hasPassword ? (
        <button className="btn btn-fill" onClick={onFill}>
          Fill
        </button>
      ) : i.url ? (
        <a className="btn btn-icon" href={i.url} target="_blank" rel="noreferrer" aria-label={`Open ${i.host}`} title="Open website">
          <Icon name="external" />
        </a>
      ) : null}
      {i.kind === "login" && (i.subtitle || i.hasPassword || i.hasTotp) && (
        <Menu label={`Copy from ${i.name}`} trigger={<Icon name="copy" />}>
          {i.subtitle && <MenuItem onClick={() => ctx.copy({ id: i.id, field: "username" }, "Username")}>Copy username</MenuItem>}
          {i.hasPassword && <MenuItem onClick={() => ctx.copy({ id: i.id, field: "password" }, "Password")}>Copy password</MenuItem>}
          {i.hasTotp && <MenuItem onClick={() => ctx.copy({ id: i.id, field: "totp" }, "Verification code")}>Copy verification code</MenuItem>}
        </Menu>
      )}
      <Menu label={`More options for ${i.name}`} trigger={<Icon name="dots" />}>
        {canFill && i.hasPassword && <MenuItem onClick={onFill}>Fill on this page</MenuItem>}
        <MenuItem onClick={open}>View</MenuItem>
        <MenuItem onClick={() => ctx.go({ tab: "vault", page: "edit", id: i.id })}>Edit</MenuItem>
        <MenuItem
          onClick={async () => {
            try {
              const r = await send<{ item: Item }>({ type: "item", id: i.id });
              await send({ type: "updateItem", id: i.id, item: { ...r.item, favorite: !i.favorite } });
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

// ------------------------------------------------------------------ item

interface ItemData {
  item: Item;
  vaultName: string;
  canWrite: boolean;
  weakPassword: boolean;
}

/** One labelled value with actions, inside a card. */
function Field({ label, children, actions }: { label: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="kv">
      <div className="grow">
        <div className="k">{label}</div>
        <div className="v">{children}</div>
      </div>
      {actions && <div className="acts">{actions}</div>}
    </div>
  );
}

function CopyBtn({ ctx, text, label }: { ctx: Ctx; text: string; label: string }) {
  return (
    <button className="btn btn-icon" aria-label={`Copy ${label.toLowerCase()}`} title={`Copy ${label.toLowerCase()}`} onClick={() => ctx.copy({ text }, label)}>
      <Icon name="copy" />
    </button>
  );
}

function Secret({ ctx, label, value }: { ctx: Ctx; label: string; value: string }) {
  const [show, setShow] = useState(false);
  return (
    <Field
      label={label}
      actions={
        <>
          <button className="btn btn-icon" aria-label={show ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`} onClick={() => setShow(!show)}>
            <Icon name={show ? "eyeOff" : "eye"} />
          </button>
          <CopyBtn ctx={ctx} text={value} label={label} />
        </>
      }
    >
      <span className="mono">{show ? value : "••••••••"}</span>
    </Field>
  );
}

function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="group">
      {title && <h2 className="group-title">{title}</h2>}
      <div className="card-box">{children}</div>
    </section>
  );
}

export function ItemPage({ id, ctx }: { id: string; ctx: Ctx }) {
  const [data, setData] = useState<ItemData | null>(null);
  const [code, setCode] = useState<{ code: string; remaining: number; period: number } | null>(null);
  const [tabId, setTabId] = useState<number | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const back = () => ctx.go({ tab: "vault", page: "list" });

  useEffect(() => {
    send<ItemData>({ type: "item", id }).then(setData, (e) => (ctx.notify(msg(e)), back()));
    activeTab().then(async (tab) => {
      if (!tab?.id || !tab.url?.startsWith("http")) return;
      const r = await send<{ suggested: ItemSummary[] }>({ type: "items", url: tab.url });
      if (r.suggested.some((s) => s.id === id)) setTabId(tab.id);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);
  useEffect(() => {
    if (!data?.item.login?.totp) return;
    const tick = () => send({ type: "totp", id }).then(setCode, () => {});
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [data, id]);

  const i = data?.item;
  const kind = i ? kindOf(i) : "login";
  const l = i?.login;
  const host = l?.urls.map((u) => u.url).find((u) => /^https?:\/\//i.test(u)) ?? "";

  const footer = data?.canWrite ? (
    confirmDelete ? (
      <>
        <span className="grow small">Move this item to the trash?</span>
        <button className="btn" onClick={() => setConfirmDelete(false)}>
          Cancel
        </button>
        <button
          className="btn btn-danger"
          onClick={() => send({ type: "trashItem", id }).then(() => (ctx.notify("Moved to trash. You can restore it from the web vault."), back()), (e) => ctx.notify(msg(e)))}
        >
          Move to trash
        </button>
      </>
    ) : (
      <>
        <button className="btn btn-accent" onClick={() => ctx.go({ tab: "vault", page: "edit", id })}>
          Edit
        </button>
        <span className="grow" />
        <button className="btn btn-icon danger" aria-label="Move to trash" title="Move to trash" onClick={() => setConfirmDelete(true)}>
          <Icon name="trash" />
        </button>
      </>
    )
  ) : undefined;

  return (
    <Page title={`View ${KIND_LABEL[kind].toLowerCase()}`} onBack={back} actions={<PopOut />} footer={footer}>
      {i && data && (
        <>
          <section className="card-box item-head">
            <div className="row">
              <SiteIcon host={host ? new URL(host).hostname : ""} name={i.name} server={ctx.state.server} enabled={ctx.state.settings.showIcons} />
              <h2 className="grow">{i.name}</h2>
              {i.favorite && <Icon name="star" />}
            </div>
            <div className="meta">
              <span>
                <Icon name="folder" size={15} /> {i.folder || "No folder"}
              </span>
              <span>
                <Icon name="vault" size={15} /> {data.vaultName}
              </span>
            </div>
            {tabId !== null && l?.password && (
              <button className="btn btn-accent btn-block" onClick={() => send({ type: "fill", id, tabId }).then(() => window.close(), (e) => ctx.notify(msg(e)))}>
                Fill on this page
              </button>
            )}
          </section>

          {l && (l.username || l.password || l.passkeys.length > 0 || code) && (
            <Card title="Login credentials">
              {l.username && (
                <Field label="Username" actions={<CopyBtn ctx={ctx} text={l.username} label="Username" />}>
                  {l.username}
                </Field>
              )}
              {l.password && (
                <>
                  <Secret ctx={ctx} label="Password" value={l.password} />
                  {data.weakPassword && (
                    <p className="warn">
                      <Icon name="shield" size={14} /> This password is easy to guess.{" "}
                      {data.canWrite && (
                        <button className="link" onClick={() => ctx.go({ tab: "vault", page: "edit", id })}>
                          Change it
                        </button>
                      )}
                    </p>
                  )}
                </>
              )}
              {l.passkeys.map((p) => (
                <Field key={p.credential_id} label="Passkey">
                  {p.user_name || p.rp_id}
                  <span className="sub">Created {formatDate(p.created_at)}</span>
                </Field>
              ))}
              {code && (
                <Field
                  label="Verification code"
                  actions={
                    <>
                      <Ring remaining={code.remaining} period={code.period} />
                      <CopyBtn ctx={ctx} text={code.code} label="Verification code" />
                    </>
                  }
                >
                  <span className="totp">
                    {code.code.slice(0, 3)} {code.code.slice(3)}
                  </span>
                </Field>
              )}
            </Card>
          )}

          {i.card && (
            <Card title="Card details">
              {i.card.cardholder_name && <Field label="Cardholder name">{i.card.cardholder_name}</Field>}
              {i.card.number && <Secret ctx={ctx} label="Number" value={i.card.number} />}
              {(i.card.exp_month || i.card.exp_year) && (
                <Field label="Expires">
                  {i.card.exp_month}/{i.card.exp_year}
                </Field>
              )}
              {i.card.code && <Secret ctx={ctx} label="Security code" value={i.card.code} />}
            </Card>
          )}

          {i.identity && (
            <Card title="Personal details">
              {[
                ["Name", [i.identity.title, i.identity.first_name, i.identity.last_name].filter(Boolean).join(" ")],
                ["Email", i.identity.email],
                ["Phone", i.identity.phone],
                ["Company", i.identity.company],
                ["Address", [i.identity.address1, i.identity.city, i.identity.postal_code, i.identity.country].filter(Boolean).join(", ")],
                ["Passport number", i.identity.passport_number],
                ["Licence number", i.identity.license_number],
              ]
                .filter(([, v]) => v)
                .map(([k, v]) => (
                  <Field key={k} label={k} actions={<CopyBtn ctx={ctx} text={v} label={k} />}>
                    {v}
                  </Field>
                ))}
            </Card>
          )}

          {i.ssh_key && (
            <Card title="SSH key">
              {i.ssh_key.public_key && (
                <Field label="Public key" actions={<CopyBtn ctx={ctx} text={i.ssh_key.public_key} label="Public key" />}>
                  <span className="mono clip">{i.ssh_key.public_key}</span>
                </Field>
              )}
              {i.ssh_key.fingerprint && <Field label="Fingerprint">{i.ssh_key.fingerprint}</Field>}
              {i.ssh_key.private_key && <Secret ctx={ctx} label="Private key" value={i.ssh_key.private_key} />}
            </Card>
          )}

          {l && l.urls.some((u) => u.url) && (
            <Card title="Autofill options">
              {l.urls
                .filter((u) => u.url)
                .map((u, n) => (
                  <Field
                    key={n}
                    label={l.urls.length > 1 ? `Website ${n + 1}` : "Website"}
                    actions={
                      <>
                        {/^https?:\/\//i.test(u.url) && u.match !== "regex" && (
                          <a className="btn btn-icon" href={u.url} target="_blank" rel="noreferrer" aria-label="Open website" title="Open website">
                            <Icon name="external" />
                          </a>
                        )}
                        <CopyBtn ctx={ctx} text={u.url} label="Website" />
                      </>
                    }
                  >
                    <span className="clip">{u.url}</span>
                  </Field>
                ))}
            </Card>
          )}

          {i.fields.length > 0 && (
            <Card title="Custom fields">
              {i.fields.map((f, n) =>
                f.type === "hidden" ? (
                  <Secret key={n} ctx={ctx} label={f.name || "Hidden field"} value={f.value} />
                ) : (
                  <Field key={n} label={f.name || "Field"} actions={f.type === "text" && f.value ? <CopyBtn ctx={ctx} text={f.value} label={f.name || "Field"} /> : undefined}>
                    {f.type === "boolean" ? (f.value === "true" ? "Yes" : "No") : f.value}
                  </Field>
                ),
              )}
            </Card>
          )}

          {i.notes && (
            <Card title="Notes">
              <p className="notes">{i.notes}</p>
            </Card>
          )}

          <Card title="Item history">
            <p className="history">
              {i.updated_at > 0 && <span>Last edited {formatDate(i.updated_at)}</span>}
              {i.created_at > 0 && <span>Created {formatDate(i.created_at)}</span>}
              {i.password_history[0] && <span>Password changed {formatDate(i.password_history[0].changed_at)}</span>}
            </p>
          </Card>
        </>
      )}
    </Page>
  );
}

// ---------------------------------------------------------------- editor

/** New item (logins are pre-filled with the current website) or edit an existing one. */
export function EditPage({ id, kind, ctx }: { id?: string; kind?: ItemKind; ctx: Ctx }) {
  const [init, setInit] = useState<{ item: Item; vaults: { id: string; name: string }[]; vaultId: string; folders: string[] } | null>(null);
  const done = (to?: string) => ctx.go(to ? { tab: "vault", page: "item", id: to } : { tab: "vault", page: "list" });
  useEffect(() => {
    (async () => {
      const info = await send<{ vaults: { id: string; name: string }[]; folders: string[] }>({ type: "editorInfo" });
      if (id) {
        const r = await send<{ item: Item; vaultId: string }>({ type: "item", id });
        return setInit({ item: structuredClone(r.item), vaults: [], vaultId: r.vaultId, folders: info.folders });
      }
      const item = emptyItem(kind ?? "login");
      const tab = await activeTab();
      if (item.login && tab?.url?.startsWith("http")) {
        const u = new URL(tab.url);
        item.name = u.hostname.replace(/^www\./, "");
        item.login.urls = [{ url: u.origin, match: "default" }];
      }
      setInit({ item, vaults: info.vaults, vaultId: info.vaults[0]?.id ?? "", folders: info.folders });
    })().catch((e) => ctx.notify(msg(e)));
  }, [id, kind, ctx]);
  const label = KIND_LABEL[init ? kindOf(init.item) : (kind ?? "login")].toLowerCase();
  return (
    <Page title={id ? `Edit ${label}` : `New ${label}`} onBack={() => done(id)}>
      {init && (
        <div className="pop-editor">
          <ItemEditor
            initial={init.item}
            isNew={!id}
            vaults={init.vaults}
            defaultVault={init.vaultId}
            folders={init.folders}
            generate={() => send<string>({ type: "generate", mode: "password" })}
            onCancel={() => done(id)}
            onSave={async (item, vaultId) => {
              if (id) {
                await send({ type: "updateItem", id, item });
                ctx.notify("Changes saved.");
                done(id);
              } else {
                const newId = await send<string>({ type: "createItem", item, vaultId });
                ctx.notify("Item saved.");
                done(newId);
              }
            }}
          />
        </div>
      )}
    </Page>
  );
}
