import { useState, type FormEvent } from "react";
import { errorMessage } from "../lib/api";
import { KIND_LABEL, kindOf, type Field, type Item, type LoginUrl } from "../lib/types";
import { ErrorText, Icon, PasswordField } from "./ui";

type Section = "login" | "card" | "identity" | "ssh_key";

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
  /** Vaults the item can be saved to; a picker shows when there is more than one (or no default). */
  vaults: { id: string; name: string }[];
  /** Pre-selected vault. Empty means the user must choose: shared vaults are never picked for them. */
  defaultVault: string;
  folders: string[];
  onSave: (item: Item, vaultId: string) => Promise<void>;
  onCancel: () => void;
  /** Password generator; defaults to the web vault's. */
  generate?: () => Promise<string>;
}) {
  const [item, setItem] = useState<Item>(initial);
  // No vault list = editing an existing item without a vault picker: it stays in its own vault.
  const [vaultId, setVaultId] = useState(vaults.length === 0 || vaults.some((v) => v.id === defaultVault) ? defaultVault : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const writable = vaults;

  const patch = <K extends keyof Item>(k: K, v: Item[K]) => setItem((x) => ({ ...x, [k]: v }));
  /** Update one section; pass a function to derive the change from the latest state. */
  const sub = <K extends Section>(k: K, v: Partial<NonNullable<Item[K]>> | ((cur: NonNullable<Item[K]>) => Partial<NonNullable<Item[K]>>)) =>
    setItem((x) => {
      const cur = x[k] as NonNullable<Item[K]>;
      return { ...x, [k]: { ...cur, ...(typeof v === "function" ? v(cur) : v) } };
    });
  const setUrls = (fn: (urls: LoginUrl[]) => LoginUrl[]) => sub("login", (l) => ({ urls: fn(l.urls) }));

  async function save(e: FormEvent) {
    e.preventDefault();
    if (!item.name.trim()) return setError("Give this item a name.");
    if (!vaultId) return setError(writable.length ? "Choose the vault to save this item in." : "You don't have a vault you can write to.");
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

  const text = (
    label: string,
    value: string,
    set: (v: string) => void,
    opts: { mono?: boolean; type?: string; auto?: string; inputMode?: "numeric" | "email" | "tel" | "url"; placeholder?: string } = {},
  ) => (
    <label className="field">
      <span>{label}</span>
      <input
        className={`input${opts.mono ? " mono" : ""}`}
        type={opts.type ?? "text"}
        value={value}
        onChange={(e) => set(e.target.value)}
        autoComplete={opts.auto ?? "off"}
        inputMode={opts.inputMode}
        placeholder={opts.placeholder}
        spellCheck={false}
      />
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
          <PasswordField label="Password" value={item.login.password} onChange={(v) => sub("login", { password: v })} generate={generate ?? true} autoComplete="new-password" />
          <label className="field">
            <span>Authenticator key (TOTP)</span>
            <input className="input mono" value={item.login.totp ?? ""} onChange={(e) => sub("login", { totp: e.target.value || null })} spellCheck={false} autoComplete="off" />
          </label>
          {item.login.urls.map((u, n) => (
            <div key={n} className="row" style={{ alignItems: "flex-end" }}>
              <label className="field grow">
                <span>{n === 0 ? "Website" : `Website ${n + 1}`}</span>
                <input
                  className="input"
                  type="text"
                  inputMode={u.match === "regex" ? undefined : "url"}
                  autoComplete="off"
                  spellCheck={false}
                  value={u.url}
                  placeholder="https://example.com"
                  onChange={(e) => {
                    const url = e.target.value;
                    setUrls((urls) => urls.map((x, j) => (j === n ? { ...x, url } : x)));
                  }}
                />
              </label>
              <label className="field">
                <span>Match</span>
                <select
                  className="select"
                  value={u.match}
                  onChange={(e) => {
                    const match = e.target.value as LoginUrl["match"];
                    setUrls((urls) => urls.map((x, j) => (j === n ? { ...x, match } : x)));
                  }}
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
              {item.login!.urls.length > 1 && (
                <button type="button" className="btn btn-icon" aria-label={`Remove website ${n + 1}`} onClick={() => setUrls((urls) => urls.filter((_, j) => j !== n))}>
                  <Icon name="trash" />
                </button>
              )}
            </div>
          ))}
          <button type="button" className="btn btn-ghost" style={{ alignSelf: "flex-start" }} onClick={() => setUrls((urls) => [...urls, { url: "", match: "default" }])}>
            <Icon name="plus" /> Add website
          </button>
        </div>
      )}

      {item.card && (
        <div className="stack">
          {text("Cardholder name", item.card.cardholder_name, (v) => sub("card", { cardholder_name: v }), { auto: "off" })}
          {text("Card number", item.card.number, (v) => sub("card", { number: v.replace(/[^\d ]/g, "") }), { mono: true, inputMode: "numeric" })}
          <div className="row">
            {text("Brand", item.card.brand, (v) => sub("card", { brand: v }))}
            <label className="field">
              <span>Expiry month</span>
              <select className="select" value={item.card.exp_month.replace(/^0(?=\d)/, "")} onChange={(e) => sub("card", { exp_month: e.target.value })}>
                <option value="">—</option>
                {Array.from({ length: 12 }, (_, m) => String(m + 1)).map((m) => (
                  <option key={m} value={m}>
                    {m.padStart(2, "0")}
                  </option>
                ))}
              </select>
            </label>
            {text("Expiry year", item.card.exp_year, (v) => sub("card", { exp_year: v.replace(/\D/g, "").slice(0, 4) }), { inputMode: "numeric", placeholder: "YYYY" })}
          </div>
          <PasswordField label="Security code" value={item.card.code} onChange={(v) => sub("card", { code: v })} autoComplete="off" />
        </div>
      )}

      {item.identity && (
        <div className="stack">
          <div className="row">
            {text("Title", item.identity.title, (v) => sub("identity", { title: v }))}
            {text("First name", item.identity.first_name, (v) => sub("identity", { first_name: v }))}
          </div>
          <div className="row">
            {text("Middle name", item.identity.middle_name, (v) => sub("identity", { middle_name: v }))}
            {text("Last name", item.identity.last_name, (v) => sub("identity", { last_name: v }))}
          </div>
          {text("Username", item.identity.username, (v) => sub("identity", { username: v }))}
          {text("Email", item.identity.email, (v) => sub("identity", { email: v }), { inputMode: "email" })}
          {text("Phone", item.identity.phone, (v) => sub("identity", { phone: v }), { type: "tel", inputMode: "tel" })}
          {text("Company", item.identity.company, (v) => sub("identity", { company: v }))}
          {text("Address", item.identity.address1, (v) => sub("identity", { address1: v }))}
          {text("Address line 2", item.identity.address2, (v) => sub("identity", { address2: v }))}
          <div className="row">
            {text("City", item.identity.city, (v) => sub("identity", { city: v }))}
            {text("State or region", item.identity.state, (v) => sub("identity", { state: v }))}
          </div>
          <div className="row">
            {text("Postal code", item.identity.postal_code, (v) => sub("identity", { postal_code: v }))}
            {text("Country", item.identity.country, (v) => sub("identity", { country: v }))}
          </div>
          <PasswordField label="National ID" value={item.identity.ssn} onChange={(v) => sub("identity", { ssn: v })} autoComplete="off" />
          <PasswordField label="Passport number" value={item.identity.passport_number} onChange={(v) => sub("identity", { passport_number: v })} autoComplete="off" />
          <PasswordField label="Licence number" value={item.identity.license_number} onChange={(v) => sub("identity", { license_number: v })} autoComplete="off" />
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

      <FieldsEditor fields={item.fields} onChange={(fn) => setItem((x) => ({ ...x, fields: fn(x.fields) }))} />

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
        {(writable.length > 1 || (!vaultId && writable.length > 0)) && (
          <label className="field grow">
            <span>Vault</span>
            <select className="select" value={vaultId} onChange={(e) => setVaultId(e.target.value)} required>
              {!vaultId && <option value="">Choose a vault…</option>}
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

function FieldsEditor({ fields, onChange }: { fields: Field[]; onChange: (fn: (f: Field[]) => Field[]) => void }) {
  const set = (n: number, f: Partial<Field>) => onChange((all) => all.map((x, j) => (j === n ? { ...x, ...f } : x)));
  return (
    <section className="stack-s">
      <h3 className="section-title">Custom fields</h3>
      {fields.map((f, n) => (
        <div key={n} className="row">
          <input className="input" aria-label={`Field ${n + 1} name`} placeholder="Name" value={f.name} onChange={(e) => set(n, { name: e.target.value })} />
          {f.type === "boolean" ? (
            <label className="check" style={{ alignItems: "center", flex: 1, minWidth: 0 }}>
              <input type="checkbox" checked={f.value === "true"} onChange={(e) => set(n, { value: e.target.checked ? "true" : "false" })} style={{ marginTop: 0 }} />
              <span>{f.value === "true" ? "Yes" : "No"}</span>
            </label>
          ) : (
            <input
              className={`input${f.type === "hidden" ? " mono" : ""}`}
              aria-label={`Field ${n + 1} value`}
              placeholder="Value"
              type={f.type === "hidden" ? "password" : "text"}
              value={f.value}
              onChange={(e) => set(n, { value: e.target.value })}
              autoComplete="off"
            />
          )}
          <select
            className="select"
            style={{ width: 120 }}
            aria-label={`Field ${n + 1} type`}
            value={f.type}
            onChange={(e) => {
              const type = e.target.value as Field["type"];
              set(n, type === "boolean" ? { type, value: f.value === "true" ? "true" : "false" } : { type });
            }}
          >
            <option value="text">Text</option>
            <option value="hidden">Hidden</option>
            <option value="boolean">Yes/No</option>
          </select>
          <button type="button" className="btn btn-icon" aria-label={`Remove field ${n + 1}`} onClick={() => onChange((all) => all.filter((_, j) => j !== n))}>
            <Icon name="trash" />
          </button>
        </div>
      ))}
      <button type="button" className="btn btn-ghost" style={{ alignSelf: "flex-start" }} onClick={() => onChange((all) => [...all, { name: "", value: "", type: "text" }])}>
        <Icon name="plus" /> Add field
      </button>
    </section>
  );
}
