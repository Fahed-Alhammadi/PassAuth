import { useState, type FormEvent } from "react";
import { errorMessage } from "../lib/api";
import { KIND_LABEL, kindOf, type Field, type Item } from "../lib/types";
import { ErrorText, Icon, PasswordInput } from "./ui";

/**
 * Item form shared by the web vault and the extension popup. Saving goes
 * through `onSave`, so each client uses its own store.
 */
export function ItemEditor({
  initial,
  isNew,
  vaults,
  defaultVault,
  folders,
  onSave,
  onCancel,
  generate,
}: {
  initial: Item;
  isNew: boolean;
  /** Vaults the item can be saved to; a picker shows when there is more than one. */
  vaults: { id: string; name: string }[];
  defaultVault: string;
  folders: string[];
  onSave: (item: Item, vaultId: string) => Promise<void>;
  onCancel: () => void;
  /** Password generator; defaults to the web vault's. */
  generate?: () => Promise<string>;
}) {
  const [item, setItem] = useState<Item>(initial);
  const [vaultId, setVaultId] = useState(defaultVault);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const writable = vaults;

  const patch = <K extends keyof Item>(k: K, v: Item[K]) => setItem((x) => ({ ...x, [k]: v }));
  const sub = <K extends "login" | "card" | "identity" | "ssh_key">(k: K, v: Partial<NonNullable<Item[K]>>) =>
    setItem((x) => ({ ...x, [k]: { ...(x[k] as object), ...v } }));

  async function save(e: FormEvent) {
    e.preventDefault();
    if (!item.name.trim()) return setError("Give this item a name.");
    if (!vaultId) return setError("You don't have a vault you can write to.");
    setBusy(true);
    setError(null);
    try {
      const clean: Item = { ...item, name: item.name.trim(), login: item.login && { ...item.login, urls: item.login.urls.filter((u) => u.url.trim()) } };
      await onSave(clean, vaultId);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  const text = (label: string, value: string, set: (v: string) => void, opts: { mono?: boolean; type?: string; auto?: string } = {}) => (
    <label className="field">
      <span>{label}</span>
      <input className={`input${opts.mono ? " mono" : ""}`} type={opts.type ?? "text"} value={value} onChange={(e) => set(e.target.value)} autoComplete={opts.auto ?? "off"} spellCheck={false} />
    </label>
  );

  return (
    <form className="detail" onSubmit={save}>
      <div className="row-between">
        <h1>{isNew ? `New ${KIND_LABEL[kindOf(initial)].toLowerCase()}` : "Edit item"}</h1>
      </div>
      {text("Name", item.name, (v) => patch("name", v))}

      {item.login && (
        <div className="stack">
          {text("Username", item.login.username, (v) => sub("login", { username: v }), { auto: "off" })}
          <label className="field">
            <span>Password</span>
            <PasswordInput value={item.login.password} onChange={(v) => sub("login", { password: v })} generate={generate ?? true} autoComplete="new-password" />
          </label>
          <label className="field">
            <span>Authenticator key (TOTP)</span>
            <input
              className="input mono"
              value={item.login.totp ?? ""}
              onChange={(e) => sub("login", { totp: e.target.value || null })}
              placeholder="otpauth://… or the setup key"
              spellCheck={false}
            />
          </label>
          {item.login.urls.map((u, n) => (
            <div key={n} className="row">
              <label className="field grow">
                <span>{n === 0 ? "Website" : `Website ${n + 1}`}</span>
                <input
                  className="input"
                  value={u.url}
                  placeholder="https://example.com"
                  onChange={(e) => sub("login", { urls: item.login!.urls.map((x, j) => (j === n ? { ...x, url: e.target.value } : x)) })}
                />
              </label>
              <label className="field">
                <span>Match</span>
                <select
                  className="select"
                  value={u.match}
                  onChange={(e) => sub("login", { urls: item.login!.urls.map((x, j) => (j === n ? { ...x, match: e.target.value as typeof u.match } : x)) })}
                >
                  <option value="default">Default (extension setting)</option>
                  <option value="domain">Base domain</option>
                  <option value="host">Host</option>
                  <option value="starts_with">Starts with</option>
                  <option value="regex">Regular expression</option>
                  <option value="exact">Exact</option>
                  <option value="never">Never</option>
                </select>
              </label>
            </div>
          ))}
          <button type="button" className="btn btn-ghost" style={{ alignSelf: "flex-start" }} onClick={() => sub("login", { urls: [...item.login!.urls, { url: "", match: "default" }] })}>
            <Icon name="plus" /> Add website
          </button>
        </div>
      )}

      {item.card && (
        <div className="stack">
          {text("Cardholder name", item.card.cardholder_name, (v) => sub("card", { cardholder_name: v }))}
          {text("Card number", item.card.number, (v) => sub("card", { number: v.replace(/[^\d ]/g, "") }), { mono: true })}
          <div className="row">
            {text("Brand", item.card.brand, (v) => sub("card", { brand: v }))}
            {text("Expiry month", item.card.exp_month, (v) => sub("card", { exp_month: v }))}
            {text("Expiry year", item.card.exp_year, (v) => sub("card", { exp_year: v }))}
          </div>
          <label className="field">
            <span>Security code</span>
            <PasswordInput value={item.card.code} onChange={(v) => sub("card", { code: v })} autoComplete="off" />
          </label>
        </div>
      )}

      {item.identity && (
        <div className="stack">
          <div className="row">
            {text("First name", item.identity.first_name, (v) => sub("identity", { first_name: v }))}
            {text("Last name", item.identity.last_name, (v) => sub("identity", { last_name: v }))}
          </div>
          {text("Email", item.identity.email, (v) => sub("identity", { email: v }), { type: "email" })}
          {text("Phone", item.identity.phone, (v) => sub("identity", { phone: v }))}
          {text("Company", item.identity.company, (v) => sub("identity", { company: v }))}
          {text("Address", item.identity.address1, (v) => sub("identity", { address1: v }))}
          <div className="row">
            {text("City", item.identity.city, (v) => sub("identity", { city: v }))}
            {text("Postal code", item.identity.postal_code, (v) => sub("identity", { postal_code: v }))}
            {text("Country", item.identity.country, (v) => sub("identity", { country: v }))}
          </div>
          {text("Passport number", item.identity.passport_number, (v) => sub("identity", { passport_number: v }))}
          {text("Licence number", item.identity.license_number, (v) => sub("identity", { license_number: v }))}
        </div>
      )}

      {item.ssh_key && (
        <div className="stack">
          <label className="field">
            <span>Private key</span>
            <textarea className="textarea mono" value={item.ssh_key.private_key} onChange={(e) => sub("ssh_key", { private_key: e.target.value })} spellCheck={false} />
          </label>
          <label className="field">
            <span>Public key</span>
            <textarea className="textarea mono" value={item.ssh_key.public_key} onChange={(e) => sub("ssh_key", { public_key: e.target.value })} spellCheck={false} />
          </label>
          {text("Fingerprint", item.ssh_key.fingerprint, (v) => sub("ssh_key", { fingerprint: v }), { mono: true })}
        </div>
      )}

      <FieldsEditor fields={item.fields} onChange={(f) => patch("fields", f)} />

      <label className="field">
        <span>Notes</span>
        <textarea className="textarea" value={item.notes} onChange={(e) => patch("notes", e.target.value)} />
      </label>

      <div className="row">
        <label className="field grow">
          <span>Folder</span>
          <input className="input" list="folders" value={item.folder ?? ""} onChange={(e) => patch("folder", e.target.value || null)} />
          <datalist id="folders">
            {folders.map((f) => (
              <option key={f} value={f} />
            ))}
          </datalist>
        </label>
        {writable.length > 1 && (
          <label className="field grow">
            <span>Vault</span>
            <select className="select" value={vaultId} onChange={(e) => setVaultId(e.target.value)}>
              {writable.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>

      <ErrorText error={error} />
      <div className="toolbar">
        <button className="btn btn-accent" disabled={busy}>
          {busy ? "Saving…" : isNew ? "Save item" : "Save changes"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function FieldsEditor({ fields, onChange }: { fields: Field[]; onChange: (f: Field[]) => void }) {
  const set = (n: number, f: Partial<Field>) => onChange(fields.map((x, j) => (j === n ? { ...x, ...f } : x)));
  return (
    <section className="stack-s">
      <h3 className="section-title">Custom fields</h3>
      {fields.map((f, n) => (
        <div key={n} className="row">
          <input className="input" aria-label="Field name" placeholder="Name" value={f.name} onChange={(e) => set(n, { name: e.target.value })} />
          <input
            className={`input${f.type === "hidden" ? " mono" : ""}`}
            aria-label="Field value"
            placeholder="Value"
            type={f.type === "hidden" ? "password" : "text"}
            value={f.value}
            onChange={(e) => set(n, { value: e.target.value })}
          />
          <select className="select" style={{ width: 120 }} aria-label="Field type" value={f.type} onChange={(e) => set(n, { type: e.target.value as Field["type"] })}>
            <option value="text">Text</option>
            <option value="hidden">Hidden</option>
            <option value="boolean">Yes/No</option>
          </select>
          <button type="button" className="btn btn-icon" aria-label="Remove field" onClick={() => onChange(fields.filter((_, j) => j !== n))}>
            <Icon name="trash" />
          </button>
        </div>
      ))}
      <button type="button" className="btn btn-ghost" style={{ alignSelf: "flex-start" }} onClick={() => onChange([...fields, { name: "", value: "", type: "text" }])}>
        <Icon name="plus" /> Add field
      </button>
    </section>
  );
}
