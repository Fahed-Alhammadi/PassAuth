import { useDeferredValue, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { ItemEditor } from "../components/ItemEditor";
import { ConfirmDialog, CopyButton, ErrorText, Icon, Modal, SheetActions, SiteIcon, TotpView, toast, type IconName } from "../components/ui";
import { errorMessage } from "../lib/api";
import { clearDraft, setEditorDirty, useDraft } from "../lib/drafts";
import { createItem, defaultVaultId, purgeItem, restoreItem, trashItem, updateItem, useVault, writableVaults } from "../lib/vault";
import { useShowIcons } from "../lib/prefs";
import { emptyItem, KIND_LABEL, kindOf, safeHref, siteHost, type Item, type ItemKind, type VaultEntry } from "../lib/types";
import { FilterSelect, filterPath, Notices } from "./Shell";

function matches(e: VaultEntry, filter: string): boolean {
  if (filter === "trash") return !!e.deletedAt;
  if (e.deletedAt) return false;
  if (filter === "all") return true;
  if (filter === "favorites") return e.item.favorite;
  if (filter.startsWith("vault:")) return e.vaultId === filter.slice(6);
  if (filter.startsWith("folder:")) return e.item.folder === filter.slice(7);
  return kindOf(e.item) === filter;
}

function subtitle(i: Item): string {
  if (i.login) return i.login.username || hostOf(i.login.urls[0]?.url ?? "");
  if (i.card) return i.card.number ? `•••• ${i.card.number.slice(-4)}` : i.card.brand;
  if (i.identity) return [i.identity.first_name, i.identity.last_name].filter(Boolean).join(" ") || i.identity.email;
  if (i.ssh_key) return i.ssh_key.fingerprint;
  return i.notes.split("\n")[0].slice(0, 60);
}

const KIND_ICON: Record<ItemKind, IconName> = { login: "globe", note: "note", card: "card", identity: "person", ssh_key: "terminal" };
const KIND_HINT: Record<ItemKind, string> = {
  login: "Password, one-time codes and passkeys for a site or app",
  note: "Free text kept encrypted",
  card: "Number, expiry date and security code",
  identity: "Name, address and documents for filling forms",
  ssh_key: "Private and public key with its fingerprint",
};
const KIND_PLURAL: Record<ItemKind, string> = { login: "Logins", note: "Secure notes", card: "Cards", identity: "Identities", ssh_key: "SSH keys" };

const formatWhen = (seconds: number) => new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const formatDay = (seconds: number) => new Date(seconds * 1000).toLocaleDateString(undefined, { dateStyle: "medium" });

function hostOf(url: string) {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).host;
  } catch {
    return url;
  }
}

export function VaultPage() {
  const params = useParams();
  const showIcons = useShowIcons();
  const filter = params.filter ?? "all";
  const itemId = params.itemId;
  const nav = useNavigate();
  const { items } = useVault();
  const [query, setQuery] = useState("");
  // Filtering thousands of items on every keystroke would make typing lag: let React render it in the background.
  const deferredQuery = useDeferredValue(query);
  const [creating, setCreating] = useState(false);
  const draft = useDraft();

  const list = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase();
    return items.filter(
      (e) =>
        matches(e, filter) &&
        (!q ||
          e.item.name.toLowerCase().includes(q) ||
          e.item.login?.username.toLowerCase().includes(q) ||
          e.item.login?.urls.some((u) => u.url.toLowerCase().includes(q)) ||
          e.item.tags.some((t) => t.toLowerCase().includes(q))),
    );
  }, [items, filter, deferredQuery]);

  const selected = items.find((e) => e.id === itemId);
  const newKind = itemId?.startsWith("new-") ? (itemId.slice(4) as ItemKind) : null;
  // A prepared edit (desktop: a verification code from a link) shows while its item's route is open.
  const drafted = draft && draft.itemId === itemId && (selected || newKind) ? draft : null;
  const open = (id: string) => nav(`${filterPath(filter)}/${id}`);
  const close = () => nav(filterPath(filter));
  useNarrowFocus(itemId);

  const { vaults } = useVault();
  const title =
    filter === "trash"
      ? "Trash"
      : filter === "all"
        ? "All items"
        : filter === "favorites"
          ? "Favorites"
          : filter.startsWith("vault:")
            ? (vaults.find((v) => v.id === filter.slice(6))?.name ?? "Vault")
            : filter.startsWith("folder:")
              ? filter.slice(7)
              : (KIND_PLURAL[filter as ItemKind] ?? "Items");

  return (
    <>
      <section className="list-pane" aria-label="Items">
        <div className="list-head">
          <div className="row-between">
            <h2 className="grow">{title}</h2>
            {filter !== "trash" && (
              <button className="btn btn-primary" onClick={() => setCreating(true)}>
                <Icon name="plus" /> New item
              </button>
            )}
          </div>
          <FilterSelect filter={filter} />
          <Notices />
          <div className="input-group">
            <span className="input-lead">
              <Icon name="search" />
            </span>
            <input className="input" type="search" placeholder="Search" aria-label="Search items" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
        </div>
        <div className="list">
          {list.length === 0 ? (
            <div className="empty">
              {query ? (
                <>
                  <p className="empty-title">No items match "{query}"</p>
                  <p>Check the spelling, or search by name, user name, website or tag.</p>
                  <button type="button" className="btn btn-text" onClick={() => setQuery("")}>
                    Clear search
                  </button>
                </>
              ) : filter === "trash" ? (
                <>
                  <p className="empty-title">Trash is empty</p>
                  <p>Items you move to the trash stay here until you delete them forever.</p>
                </>
              ) : (
                <>
                  <span className="tile" aria-hidden="true">
                    <Icon name={filter === "favorites" ? "star" : "vault"} size={22} />
                  </span>
                  <p className="empty-title">{filter === "all" ? "Your vault is empty" : filter === "favorites" ? "No favorites yet" : "Nothing here yet"}</p>
                  <p>{filter === "favorites" ? "Open an item and select the star to keep it here." : "Add your first item, or bring your passwords from another app."}</p>
                  {filter !== "favorites" && (
                    <div className="empty-actions">
                      <button type="button" className="btn" onClick={() => setCreating(true)}>
                        <Icon name="plus" /> Add an item
                      </button>
                      <Link className="btn btn-text" to="/import">
                        Import from another app
                      </Link>
                    </div>
                  )}
                </>
              )}
            </div>
          ) : (
            list.map((e) => (
              <button key={e.id} className="list-item" data-item={e.id} aria-current={e.id === itemId} onClick={() => open(e.id)}>
                <SiteIcon host={siteHost(e.item)} name={e.item.name} enabled={showIcons} />
                <span className="grow">
                  <span className="title">{e.item.name || "Untitled"}</span>
                  <span className="sub">{subtitle(e.item)}</span>
                </span>
                {e.item.favorite && (
                  <span className="fav" title="Favorite">
                    <Icon name="star" size={14} />
                    <span className="sr-only">Favorite</span>
                  </span>
                )}
              </button>
            ))
          )}
        </div>
      </section>

      <section className="detail-pane" aria-label="Item details">
        {drafted ? (
          <Editor
            key={`draft-${drafted.seq}`}
            entry={selected}
            kind={newKind ?? kindOf(selected!.item)}
            prefill={drafted.apply}
            onDone={(id) => {
              clearDraft();
              if (id) open(id);
              else close();
            }}
          />
        ) : newKind ? (
          <Editor key={itemId} kind={newKind} onDone={(id) => (id ? open(id) : close())} />
        ) : selected ? (
          // Keyed by id only: a sync that changes the item must not throw away an edit in progress.
          <Detail key={selected.id} entry={selected} onClose={close} />
        ) : (
          <div className="empty empty-fill">
            <p>{items.some((e) => !e.deletedAt) ? "Select an item to see its details." : "Items you add show their details here."}</p>
          </div>
        )}
      </section>

      {creating && (
        <Modal title="New item" subtitle="Choose what to add" icon="plus" onClose={() => setCreating(false)}>
          <div className="choices">
            {(Object.keys(KIND_LABEL) as ItemKind[]).map((k) => (
              <button
                key={k}
                type="button"
                className="choice"
                onClick={() => {
                  setCreating(false);
                  nav(`${filterPath(filter)}/new-${k}`);
                }}
              >
                <span className="tile" aria-hidden="true">
                  <Icon name={KIND_ICON[k]} />
                </span>
                <span className="choice-text">
                  <span className="choice-title">{KIND_LABEL[k]}</span>
                  <span className="choice-sub">{KIND_HINT[k]}</span>
                </span>
                <span className="choice-trail" aria-hidden="true">
                  <Icon name="chevron" size={16} />
                </span>
              </button>
            ))}
          </div>
          <SheetActions
            quiet={
              <button type="button" className="btn btn-text" onClick={() => setCreating(false)}>
                Cancel
              </button>
            }
          />
        </Modal>
      )}
      <ShellDetailFlag active={!!(selected || newKind || drafted)} />
    </>
  );
}

/**
 * Narrow screens show either the list or the item, so the focused element disappears when switching:
 * move focus to the item's heading when it opens, and back to its row when returning to the list.
 */
function useNarrowFocus(itemId: string | undefined) {
  const last = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!window.matchMedia("(max-width: 820px)").matches) {
      last.current = itemId;
      return;
    }
    if (itemId) document.querySelector<HTMLElement>(".detail-pane h1")?.focus();
    else if (last.current) document.querySelector<HTMLElement>(`[data-item="${CSS.escape(last.current)}"]`)?.focus();
    last.current = itemId;
  }, [itemId]);
}

/** Mobile: show the detail pane instead of the list while an item is open. */
function ShellDetailFlag({ active }: { active: boolean }) {
  useEffect(() => {
    const shell = document.querySelector("[data-shell]");
    shell?.classList.toggle("has-detail", active);
    return () => shell?.classList.remove("has-detail");
  }, [active]);
  return null;
}

// ------------------------------------------------------------------ detail

function Row({ label, value, secret, mono, children }: { label: string; value?: string; secret?: boolean; mono?: boolean; children?: ReactNode }) {
  const [show, setShow] = useState(false);
  if (!value && !children) return null;
  return (
    <div>
      <dl className="grow">
        <dt>{label}</dt>
        <dd className={mono || secret ? "mono" : undefined}>{children ?? (secret && !show ? "••••••••••••" : value)}</dd>
      </dl>
      {secret && value && (
        <button type="button" className="btn btn-icon" aria-label={show ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`} onClick={() => setShow(!show)}>
          <Icon name={show ? "eyeOff" : "eye"} />
        </button>
      )}
      {value && <CopyButton value={value} label={`Copy ${label.toLowerCase()}`} />}
    </div>
  );
}

function Detail({ entry, onClose }: { entry: VaultEntry; onClose: () => void }) {
  const { vaults } = useVault();
  const showIcons = useShowIcons();
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [purging, setPurging] = useState(false);
  const i = entry.item;
  const vault = vaults.find((v) => v.id === entry.vaultId);
  const canWrite = vault && vault.role !== "read";

  if (editing) return <Editor entry={entry} kind={kindOf(i)} onDone={() => setEditing(false)} />;
  const href = (url: string) => safeHref(url);

  const run = async (fn: () => Promise<void>, msg: string, then?: () => void) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      toast(msg);
      then?.();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const where = `${KIND_LABEL[kindOf(i)]} in ${vault?.name ?? "a vault"}${i.folder ? `, folder ${i.folder}` : ""}`;

  return (
    <article className="detail">
      <div className="detail-top">
        <button type="button" className="btn btn-text back" onClick={onClose}>
          <Icon name="back" /> Back
        </button>
        <header className="detail-head grow">
          <SiteIcon host={siteHost(i)} name={i.name} enabled={showIcons} />
          <div className="grow">
            <h1 tabIndex={-1}>{i.name || "Untitled"}</h1>
            <p className="muted small">
              {where}
              {!canWrite && ", view only"}
            </p>
          </div>
        </header>
        {canWrite && (
          <div className="detail-actions">
            {entry.deletedAt ? (
              <>
                <button type="button" className="btn" disabled={busy} onClick={() => run(() => restoreItem(entry.id), "Item restored")}>
                  <Icon name="restore" /> Restore
                </button>
                <button type="button" className="btn btn-text btn-danger" disabled={busy} onClick={() => setPurging(true)}>
                  Delete forever
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  className="btn btn-icon"
                  aria-pressed={i.favorite}
                  aria-label="Favorite"
                  title={i.favorite ? "Remove from favorites" : "Add to favorites"}
                  disabled={busy}
                  onClick={() => run(() => updateItem(entry, { ...i, favorite: !i.favorite }), i.favorite ? "Removed from favorites" : "Added to favorites")}
                >
                  <Icon name="star" />
                </button>
                <button type="button" className="btn btn-icon btn-quiet-danger" aria-label="Move to trash" title="Move to trash" disabled={busy} onClick={() => run(() => trashItem(entry.id), "Moved to trash", onClose)}>
                  <Icon name="trash" />
                </button>
                <button type="button" className="btn" onClick={() => setEditing(true)}>
                  <Icon name="edit" /> Edit
                </button>
              </>
            )}
          </div>
        )}
      </div>
      {entry.deletedAt && (
        <div className="alert small" role="note">
          This item is in the trash. Restore it to use it again.
        </div>
      )}
      <ErrorText error={error} />

      {i.login && (
        <div className="fields">
          <Row label="Username" value={i.login.username} />
          <Row label="Password" value={i.login.password} secret />
          {i.login.totp && (
            <Row label="One-time code">
              <TotpView secret={i.login.totp} />
            </Row>
          )}
          {i.login.urls
            .filter((u) => u.url)
            .map((u, n) => (
              <Row key={n} label={n === 0 ? "Website" : `Website ${n + 1}`} value={u.url}>
                {href(u.url) && u.match !== "regex" ? (
                  <a href={href(u.url)!} target="_blank" rel="noopener noreferrer">
                    {u.url}
                  </a>
                ) : (
                  u.url
                )}
              </Row>
            ))}
        </div>
      )}

      {i.login && i.login.passkeys.length > 0 && (
        <section className="stack-s">
          <h2 className="section-title">Passkeys</h2>
          <div className="fields">
            {i.login.passkeys.map((p) => (
              <div key={p.credential_id}>
                <span className="tile" aria-hidden="true">
                  <Icon name="key" />
                </span>
                <dl className="grow">
                  <dt>{p.rp_id}</dt>
                  <dd>{p.user_name || p.user_display_name || "This account"}</dd>
                </dl>
                {p.created_at > 0 && <span className="trail">Added {formatDay(p.created_at)}</span>}
              </div>
            ))}
          </div>
        </section>
      )}

      {i.card && (
        <div className="fields">
          <Row label="Cardholder" value={i.card.cardholder_name} />
          <Row label="Card number" value={i.card.number} secret />
          <Row label="Brand" value={i.card.brand} />
          <Row label="Expires" value={i.card.exp_month || i.card.exp_year ? `${i.card.exp_month.padStart(2, "0")}/${i.card.exp_year}` : ""} />
          <Row label="Security code" value={i.card.code} secret />
        </div>
      )}

      {i.identity && (
        <div className="fields">
          <Row label="Name" value={[i.identity.title, i.identity.first_name, i.identity.middle_name, i.identity.last_name].filter(Boolean).join(" ")} />
          <Row label="Email" value={i.identity.email} />
          <Row label="Phone" value={i.identity.phone} />
          <Row label="Company" value={i.identity.company} />
          <Row
            label="Address"
            value={[i.identity.address1, i.identity.address2, i.identity.city, i.identity.state, i.identity.postal_code, i.identity.country].filter(Boolean).join(", ")}
          />
          <Row label="Username" value={i.identity.username} />
          <Row label="National ID" value={i.identity.ssn} secret />
          <Row label="Passport number" value={i.identity.passport_number} secret />
          <Row label="Licence number" value={i.identity.license_number} secret />
        </div>
      )}

      {i.ssh_key && (
        <div className="fields">
          <Row label="Public key" value={i.ssh_key.public_key} mono />
          <Row label="Fingerprint" value={i.ssh_key.fingerprint} mono />
          <Row label="Private key" value={i.ssh_key.private_key} secret />
        </div>
      )}

      {i.fields.length > 0 && (
        <section className="stack-s">
          <h2 className="section-title">Custom fields</h2>
          <div className="fields">
            {i.fields.map((f, n) => (
              <Row key={n} label={f.name || "Field"} value={f.type === "boolean" ? (f.value === "true" ? "Yes" : "No") : f.value} secret={f.type === "hidden"} />
            ))}
          </div>
        </section>
      )}

      {i.notes && (
        <section className="stack-s">
          <h2 className="section-title">Notes</h2>
          <div className="card pre-wrap">{i.notes}</div>
        </section>
      )}

      {i.password_history.length > 0 && (
        <details className="disclosure">
          <summary className="section-title">Password history ({i.password_history.length})</summary>
          <div className="fields">
            {i.password_history.map((h, n) => (
              <Row key={n} label={h.changed_at ? `Changed ${formatWhen(h.changed_at)}` : "Previous password"} value={h.password} secret />
            ))}
          </div>
        </details>
      )}

      <p className="small muted">
        Last edited {formatWhen(i.updated_at || entry.revision / 1000)}
        {i.tags.length > 0 && `. Tags: ${i.tags.join(", ")}`}
      </p>

      {purging && (
        <ConfirmDialog
          title="Delete this item forever?"
          subtitle={i.name || "Untitled"}
          icon={<SiteIcon host={siteHost(i)} name={i.name} enabled={showIcons} />}
          action="Delete forever"
          busyAction="Deleting…"
          onClose={() => setPurging(false)}
          onConfirm={async () => {
            await purgeItem(entry.id);
            toast("Item deleted");
            onClose();
          }}
        >
          <p className="card-text">It is removed from the trash on every device and can't be restored.</p>
        </ConfirmDialog>
      )}
    </article>
  );
}

// ------------------------------------------------------------------ editor

function Editor({ entry, kind, prefill, onDone }: { entry?: VaultEntry; kind: ItemKind; prefill?: (item: Item) => Item; onDone: (id?: string) => void }) {
  const writable = writableVaults();
  const { items } = useVault();
  const folders = [...new Set(items.map((e) => e.item.folder).filter(Boolean))] as string[];
  // The version the edit started from. Saving sends its revision, so the server refuses to overwrite a
  // change made elsewhere in the meantime; the user then decides which version wins.
  const [base, setBase] = useState(entry);
  const [initial] = useState(() => {
    const item = entry ? structuredClone(entry.item) : emptyItem(kind);
    return prefill ? prefill(item) : item;
  });
  const changed = !!(entry && base && entry.revision !== base.revision);
  return (
    <>
      {changed && (
        <div className="alert alert-warn small notice" role="alert">
          <div className="grow">
            <span>This item was changed on another device or by someone you share the vault with. Saving now would fail.</span>
            <div className="row">
              <button type="button" className="link" onClick={() => setBase(entry)}>
                Keep my changes (overwrite)
              </button>
              <button type="button" className="link" onClick={() => onDone(entry?.id)}>
                Discard my changes
              </button>
            </div>
          </div>
        </div>
      )}
      <ItemEditor
        initial={initial}
        isNew={!entry}
        vaults={writable}
        defaultVault={entry?.vaultId ?? defaultVaultId()}
        folders={folders}
        onDirtyChange={setEditorDirty}
        onCancel={() => onDone(entry?.id)}
        onSave={async (item, vaultId) => {
          if (base) {
            await updateItem(base, item, vaultId);
            toast("Changes saved");
            onDone(base.id);
          } else {
            const id = await createItem(vaultId, item);
            toast("Item saved");
            onDone(id);
          }
        }}
      />
    </>
  );
}
