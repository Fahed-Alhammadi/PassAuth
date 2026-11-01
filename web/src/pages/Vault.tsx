import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { ItemEditor } from "../components/ItemEditor";
import { CopyButton, ErrorText, Icon, Modal, SiteIcon, TotpView, toast } from "../components/ui";
import { errorMessage } from "../lib/api";
import { createItem, purgeItem, restoreItem, trashItem, updateItem, useVault, writableVaults } from "../lib/vault";
import { useShowIcons } from "../lib/prefs";
import { emptyItem, KIND_LABEL, kindOf, siteHost, type Item, type ItemKind, type VaultEntry } from "../lib/types";
import { filterPath } from "./Shell";

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
  const [creating, setCreating] = useState(false);

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items.filter(
      (e) =>
        matches(e, filter) &&
        (!q ||
          e.item.name.toLowerCase().includes(q) ||
          e.item.login?.username.toLowerCase().includes(q) ||
          e.item.login?.urls.some((u) => u.url.toLowerCase().includes(q)) ||
          e.item.tags.some((t) => t.toLowerCase().includes(q))),
    );
  }, [items, filter, query]);

  const selected = items.find((e) => e.id === itemId);
  const newKind = itemId?.startsWith("new-") ? (itemId.slice(4) as ItemKind) : null;
  const open = (id: string) => nav(`${filterPath(filter)}/${id}`);
  const close = () => nav(filterPath(filter));

  return (
    <>
      <section className={`list-pane`} aria-label="Items">
        <div className="list-head">
          <div className="row-between">
            <h2>{filter === "trash" ? "Trash" : "Items"}</h2>
            {filter !== "trash" && (
              <button className="btn btn-primary" onClick={() => setCreating(true)}>
                <Icon name="plus" /> New item
              </button>
            )}
          </div>
          <div className="input-group">
            <span className="row" style={{ paddingLeft: 10, color: "var(--ink-3)" }}>
              <Icon name="search" />
            </span>
            <input className="input" type="search" placeholder="Search" aria-label="Search items" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
        </div>
        <div className="list">
          {list.length === 0 ? (
            <div className="empty">
              {query ? (
                <p>No items match "{query}".</p>
              ) : filter === "trash" ? (
                <p>Trash is empty.</p>
              ) : (
                <>
                  <p>Nothing here yet.</p>
                  <div className="row">
                    <button className="btn" onClick={() => setCreating(true)}>
                      Add an item
                    </button>
                    <Link className="btn" to="/import">
                      Import from another app
                    </Link>
                  </div>
                </>
              )}
            </div>
          ) : (
            list.map((e) => (
              <button key={e.id} className="list-item" aria-current={e.id === itemId} onClick={() => open(e.id)}>
                <SiteIcon host={siteHost(e.item)} name={e.item.name} enabled={showIcons} />
                <span className="grow">
                  <span className="title" style={{ display: "block" }}>
                    {e.item.name || "Untitled"}
                  </span>
                  <span className="sub" style={{ display: "block" }}>
                    {subtitle(e.item)}
                  </span>
                </span>
                {e.item.favorite && <Icon name="star" size={14} />}
              </button>
            ))
          )}
        </div>
      </section>

      <section className="detail-pane" aria-label="Item details">
        {newKind ? (
          <Editor key={itemId} kind={newKind} onDone={(id) => (id ? open(id) : close())} />
        ) : selected ? (
          <Detail key={selected.id + selected.revision} entry={selected} onClose={close} />
        ) : (
          <div className="empty" style={{ height: "100%", justifyContent: "center" }}>
            <p>Select an item to see its details.</p>
          </div>
        )}
      </section>

      {creating && (
        <Modal title="New item" onClose={() => setCreating(false)}>
          <div className="stack-s">
            {(Object.keys(KIND_LABEL) as ItemKind[]).map((k) => (
              <button
                key={k}
                className="btn"
                style={{ justifyContent: "flex-start" }}
                onClick={() => {
                  setCreating(false);
                  nav(`${filterPath(filter)}/new-${k}`);
                }}
              >
                {KIND_LABEL[k]}
              </button>
            ))}
          </div>
        </Modal>
      )}
      <ShellDetailFlag active={!!(selected || newKind)} />
    </>
  );
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
      <dl className="grow" style={{ margin: 0 }}>
        <dt>{label}</dt>
        <dd className={mono || secret ? "mono" : undefined}>{children ?? (secret && !show ? "••••••••••••" : value)}</dd>
      </dl>
      {secret && value && (
        <button className="btn btn-icon" aria-label={show ? `Hide ${label}` : `Show ${label}`} onClick={() => setShow(!show)}>
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
  const i = entry.item;
  const vault = vaults.find((v) => v.id === entry.vaultId);
  const canWrite = vault && vault.role !== "read";

  if (editing) return <Editor entry={entry} kind={kindOf(i)} onDone={() => setEditing(false)} />;

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

  return (
    <article className="detail">
      <button className="btn btn-ghost back" onClick={onClose}>
        <Icon name="back" /> Back
      </button>
      <header className="detail-head">
        <SiteIcon host={siteHost(i)} name={i.name} enabled={showIcons} />
        <div className="grow">
          <h1 style={{ overflowWrap: "anywhere" }}>{i.name || "Untitled"}</h1>
          <p className="muted small">
            {KIND_LABEL[kindOf(i)]} in {vault?.name ?? "a vault"}
            {i.folder ? `, folder ${i.folder}` : ""}
          </p>
        </div>
      </header>

      {canWrite && (
        <div className="toolbar">
          {entry.deletedAt ? (
            <>
              <button className="btn" disabled={busy} onClick={() => run(() => restoreItem(entry.id), "Item restored")}>
                <Icon name="restore" /> Restore
              </button>
              <button
                className="btn btn-danger"
                disabled={busy}
                onClick={() => confirm(`Delete "${i.name}" forever? This can't be undone.`) && run(() => purgeItem(entry.id), "Item deleted", onClose)}
              >
                Delete forever
              </button>
            </>
          ) : (
            <>
              <button className="btn" onClick={() => setEditing(true)}>
                <Icon name="edit" /> Edit
              </button>
              <button className="btn" disabled={busy} onClick={() => run(() => updateItem(entry, { ...i, favorite: !i.favorite }), i.favorite ? "Removed from favorites" : "Added to favorites")}>
                <Icon name="star" /> {i.favorite ? "Unfavorite" : "Favorite"}
              </button>
              <button className="btn btn-danger" disabled={busy} onClick={() => run(() => trashItem(entry.id), "Moved to trash", onClose)}>
                <Icon name="trash" /> Move to trash
              </button>
            </>
          )}
        </div>
      )}
      <ErrorText error={error} />

      {i.login && (
        <dl className="fields" style={{ margin: 0 }}>
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
                <a href={u.url.includes("://") ? u.url : `https://${u.url}`} target="_blank" rel="noopener noreferrer">
                  {u.url}
                </a>
              </Row>
            ))}
        </dl>
      )}

      {i.login && i.login.passkeys.length > 0 && (
        <section className="stack-s">
          <h3 className="section-title">Passkeys</h3>
          <div className="fields">
            {i.login.passkeys.map((p) => (
              <div key={p.credential_id}>
                <Icon name="key" />
                <span className="grow">
                  {p.rp_id} <span className="muted small">for {p.user_name || p.user_display_name || "this account"}</span>
                </span>
                {p.created_at > 0 && <span className="small muted">Added {new Date(p.created_at * 1000).toLocaleDateString()}</span>}
              </div>
            ))}
          </div>
        </section>
      )}

      {i.card && (
        <dl className="fields" style={{ margin: 0 }}>
          <Row label="Cardholder" value={i.card.cardholder_name} />
          <Row label="Card number" value={i.card.number} secret />
          <Row label="Brand" value={i.card.brand} />
          <Row label="Expires" value={i.card.exp_month || i.card.exp_year ? `${i.card.exp_month.padStart(2, "0")}/${i.card.exp_year}` : ""} />
          <Row label="Security code" value={i.card.code} secret />
        </dl>
      )}

      {i.identity && (
        <dl className="fields" style={{ margin: 0 }}>
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
        </dl>
      )}

      {i.ssh_key && (
        <dl className="fields" style={{ margin: 0 }}>
          <Row label="Public key" value={i.ssh_key.public_key} mono />
          <Row label="Fingerprint" value={i.ssh_key.fingerprint} mono />
          <Row label="Private key" value={i.ssh_key.private_key} secret />
        </dl>
      )}

      {i.fields.length > 0 && (
        <section className="stack-s">
          <h3 className="section-title">Custom fields</h3>
          <dl className="fields" style={{ margin: 0 }}>
            {i.fields.map((f, n) => (
              <Row key={n} label={f.name || "Field"} value={f.type === "boolean" ? (f.value === "true" ? "Yes" : "No") : f.value} secret={f.type === "hidden"} />
            ))}
          </dl>
        </section>
      )}

      {i.notes && (
        <section className="stack-s">
          <h3 className="section-title">Notes</h3>
          <div className="card" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
            {i.notes}
          </div>
        </section>
      )}

      {i.password_history.length > 0 && (
        <details>
          <summary className="section-title" style={{ cursor: "pointer" }}>
            Password history ({i.password_history.length})
          </summary>
          <dl className="fields" style={{ marginTop: 8 }}>
            {i.password_history.map((h, n) => (
              <Row key={n} label={h.changed_at ? `Changed ${new Date(h.changed_at * 1000).toLocaleString()}` : "Previous password"} value={h.password} secret />
            ))}
          </dl>
        </details>
      )}

      <p className="small muted">
        Last edited {new Date((i.updated_at || entry.revision / 1000) * 1000).toLocaleString()}
        {i.tags.length > 0 && `. Tags: ${i.tags.join(", ")}`}
      </p>
    </article>
  );
}

// ------------------------------------------------------------------ editor

function Editor({ entry, kind, onDone }: { entry?: VaultEntry; kind: ItemKind; onDone: (id?: string) => void }) {
  const writable = writableVaults();
  const { items } = useVault();
  const folders = [...new Set(items.map((e) => e.item.folder).filter(Boolean))] as string[];
  return (
    <ItemEditor
      initial={entry ? structuredClone(entry.item) : emptyItem(kind)}
      isNew={!entry}
      vaults={writable}
      defaultVault={entry?.vaultId ?? writable[0]?.id ?? ""}
      folders={folders}
      onCancel={() => onDone(entry?.id)}
      onSave={async (item, vaultId) => {
        if (entry) {
          await updateItem(entry, item, vaultId);
          toast("Changes saved");
          onDone(entry.id);
        } else {
          const id = await createItem(vaultId, item);
          toast("Item saved");
          onDone(id);
        }
      }}
    />
  );
}
