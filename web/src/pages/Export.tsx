import { useState, type FormEvent } from "react";
import { ErrorText, Icon, PasswordInput, toast } from "../components/ui";
import { errorMessage } from "../lib/api";
import { exportVaultCsv, exportVaultEncrypted, exportVaultJson, reauth, useVault } from "../lib/vault";
import "../styles/tools.css";

type Format = "encrypted" | "json" | "csv";

const FORMATS: { value: Format; title: string; text: string }[] = [
  { value: "encrypted", title: "Password-protected JSON", text: "Everything in your vaults, encrypted with an export password you choose. Recommended." },
  { value: "json", title: "JSON", text: "Everything in your vaults, unencrypted." },
  { value: "csv", title: "CSV", text: "Logins and secure notes only, unencrypted. Opens in spreadsheets and most password managers." },
];

function save(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Export the vault to a file. Runs in the browser; nothing new is sent to the server. */
export function ExportPage() {
  const { items } = useVault();
  const [format, setFormat] = useState<Format>("encrypted");
  const [exportPassword, setExportPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [master, setMaster] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const live = items.filter((e) => !e.deletedAt).map((e) => e.item);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (format === "encrypted") {
      if (exportPassword.length < 10) return setError("Use an export password of at least 10 characters.");
      if (exportPassword !== confirm) return setError("The two export passwords don't match.");
    }
    setBusy(true);
    try {
      await reauth(master); // confirms the master password before anything is written
      const date = new Date().toISOString().slice(0, 10);
      // Let the "Exporting…" state paint before the key derivation blocks the page.
      await new Promise((r) => setTimeout(r, 30));
      if (format === "encrypted") save(`passauth-export-${date}-protected.json`, exportVaultEncrypted(live, exportPassword), "application/json");
      else if (format === "json") save(`passauth-export-${date}.json`, exportVaultJson(live), "application/json");
      else save(`passauth-export-${date}.csv`, exportVaultCsv(live), "text/csv");
      toast("Vault exported");
      setMaster("");
      setExportPassword("");
      setConfirm("");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <div className="page-inner">
        <header className="page-head">
          <h1>Export</h1>
          <p>Save a copy of your vault as a file, for a backup or to move to another app. PassAuth can import all three formats again.</p>
        </header>

        <form className="card stack" onSubmit={submit}>
          <fieldset className="stack-s" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="section-title">File format</legend>
            {FORMATS.map((f) => (
              <label key={f.value} className="check">
                <input type="radio" name="format" checked={format === f.value} onChange={() => setFormat(f.value)} />
                <span>
                  {f.title}
                  <span className="small muted block">{f.text}</span>
                </span>
              </label>
            ))}
          </fieldset>

          {format === "encrypted" ? (
            <div className="row">
              <label className="field grow">
                <span>Export password</span>
                <PasswordInput value={exportPassword} onChange={setExportPassword} autoComplete="new-password" />
              </label>
              <label className="field grow">
                <span>Confirm export password</span>
                <PasswordInput value={confirm} onChange={setConfirm} autoComplete="new-password" />
              </label>
            </div>
          ) : (
            <div className="alert alert-error" role="note">
              This file isn't encrypted. Anyone who gets it can read your passwords. Keep it somewhere safe and delete it when you no longer need it.
            </div>
          )}

          <label className="field">
            <span>Master password</span>
            <PasswordInput value={master} onChange={setMaster} autoComplete="current-password" />
          </label>

          <ErrorText error={error} />
          <div className="row">
            <button className="btn btn-primary" disabled={busy || !master || live.length === 0}>
              <Icon name="download" /> {busy ? "Exporting…" : `Export ${live.length} ${live.length === 1 ? "item" : "items"}`}
            </button>
          </div>
          <p className="small muted">Items in the trash aren't exported.</p>
        </form>
      </div>
    </div>
  );
}
