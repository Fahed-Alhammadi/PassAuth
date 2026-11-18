import { isTrashed } from "../lib/types";
import { useState, type FormEvent } from "react";
import { ErrorText, Icon, PasswordField, toast } from "../components/ui";
import { friendlyError, usePolicies } from "../lib/api";
import { anyAttachments, stripAttachments } from "../lib/attachments";
import { downloadFile } from "../lib/kit";
import { exportAllowed } from "../lib/policies";
import { cleanText } from "../lib/signing";
import { exportVaultCsv, exportVaultEncrypted, exportVaultJson, reauth, useVault, type BlockedVault, type ConsentVault } from "../lib/vault";
import "../styles/tools.css";

type Format = "encrypted" | "json" | "csv";

const FORMATS: { value: Format; title: string; text: string }[] = [
  { value: "encrypted", title: "Password-protected JSON", text: "Everything in your vaults, encrypted with an export password you choose. Recommended." },
  { value: "json", title: "JSON", text: "Everything in your vaults, unencrypted." },
  { value: "csv", title: "CSV", text: "Logins and secure notes only, unencrypted. Opens in spreadsheets and most password managers." },
];

const save = (name: string, text: string, type: string) => downloadFile(name, text, type);

/**
 * The vaults this export leaves out because they aren't opened here (signed sharing): those waiting for the user's OK, by
 * name, and those PassAuth couldn't verify (never opened, so only counted). Null when there are none.
 */
export function leftOutText(consents: readonly ConsentVault[], blocked: readonly BlockedVault[]): string | null {
  const names = consents.map((c) => `"${cleanText(c.name) || "Shared vault"}"`);
  if (blocked.length) names.push(blocked.length === 1 ? "1 shared vault PassAuth couldn't verify" : `${blocked.length} shared vaults PassAuth couldn't verify`);
  if (!names.length) return null;
  return `Not in this export, because they aren't opened on this device: ${names.join(", ")}. Accept or check them in Settings, Vaults & sharing first if you need them.`;
}

/** Export the vault to a file, unless the server's admin turned export off (policy `disable_export`). */
export function ExportPage() {
  return exportAllowed(usePolicies()) ? <ExportForm /> : <ExportTurnedOff />;
}

function ExportTurnedOff() {
  return (
    <div className="page">
      <div className="page-inner">
        <header className="page-head">
          <h1>Export</h1>
        </header>
        <div className="alert alert-info" role="note">
          Your server's admin turned off export. Ask them if you need a copy of your vault.
        </div>
      </div>
    </div>
  );
}

/** Runs in the browser; nothing new is sent to the server. */
function ExportForm() {
  const { items, consents, blockedVaults } = useVault();
  const leftOut = leftOutText(consents, blockedVaults);
  const [format, setFormat] = useState<Format>("encrypted");
  const [exportPassword, setExportPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [master, setMaster] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const kept = items.filter((e) => !isTrashed(e)).map((e) => e.item);
  // Files aren't exported: their list (with each file's key) is left out of every format.
  const withFiles = anyAttachments(kept);
  const live = kept.map(stripAttachments);

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

          {leftOut && (
            <p className="small muted" role="note">
              {leftOut}
            </p>
          )}
          {withFiles && (
            <p className="small muted" role="note">
              Files attached to items aren't exported. Download the ones you need from each item.
            </p>
          )}
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
