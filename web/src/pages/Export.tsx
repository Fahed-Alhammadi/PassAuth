import { useState, type FormEvent } from "react";
import { ErrorText, Icon, PasswordField, toast } from "../components/ui";
import { friendlyError } from "../lib/api";
import { downloadFile } from "../lib/kit";
import { exportVaultCsv, exportVaultEncrypted, exportVaultJson, reauth, useVault } from "../lib/vault";
import "../styles/tools.css";

type Format = "encrypted" | "json" | "csv";

const FORMATS: { value: Format; title: string; text: string }[] = [
  { value: "encrypted", title: "Password-protected JSON", text: "Everything in your vaults, encrypted with an export password you choose. Recommended." },
  { value: "json", title: "JSON", text: "Everything in your vaults, unencrypted." },
  { value: "csv", title: "CSV", text: "Logins and secure notes only, unencrypted. Opens in spreadsheets and most password managers." },
];

const save = (name: string, text: string, type: string) => downloadFile(name, text, type);

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
      setError(friendlyError(err));
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
          <fieldset className="choice-group">
            <legend className="field-label">File format</legend>
            <div className="choices choices-plain">
              {FORMATS.map((f) => (
                <label key={f.value} className="choice">
                  <span className="choice-text">
                    <span className="choice-title">{f.title}</span>
                    <span className="choice-sub">{f.text}</span>
                  </span>
                  <input type="radio" name="format" checked={format === f.value} onChange={() => setFormat(f.value)} />
                </label>
              ))}
            </div>
          </fieldset>

          {format === "encrypted" ? (
            <div className="field-pair">
              <PasswordField label="Export password" value={exportPassword} onChange={setExportPassword} autoComplete="new-password" />
              <PasswordField label="Confirm export password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
            </div>
          ) : (
            <div className="alert alert-warn" role="note">
              This file isn't encrypted. Anyone who gets it can read your passwords. Keep it somewhere safe and delete it when you no longer need it.
            </div>
          )}

          <PasswordField
            label="Master password"
            value={master}
            onChange={setMaster}
            autoComplete="current-password"
            hint={<span className="field-hint">Confirms that it's you exporting the vault.</span>}
          />

          <ErrorText error={error} />
          <div className="card-actions">
            <button className="btn btn-primary" disabled={busy || !master || live.length === 0}>
              <Icon name="download" /> {busy ? "Exporting…" : `Export ${live.length} ${live.length === 1 ? "item" : "items"}`}
            </button>
            <span className="small muted">{live.length === 0 ? "There is nothing to export yet." : "Items in the trash aren't exported."}</span>
          </div>
        </form>
      </div>
    </div>
  );
}
