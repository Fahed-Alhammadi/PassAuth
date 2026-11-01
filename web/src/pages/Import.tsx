import { useEffect, useRef, useState, type DragEvent, type FormEvent, type RefObject } from "react";
import { Link } from "react-router";
import { ErrorText, Icon, PasswordInput } from "../components/ui";
import { errorMessage } from "../lib/api";
import { kindOf, type Item, type ItemKind } from "../lib/types";
import { importFile, importItems, useVault, writableVaults } from "../lib/vault";
import { filterPath } from "./Shell";
import "../styles/tools.css";

type Step =
  | { kind: "choose" }
  | { kind: "reading" }
  | { kind: "password" }
  | { kind: "preview"; format: string; items: Item[]; warnings: string[] }
  | { kind: "importing"; total: number; done: number }
  | { kind: "done"; count: number; vaultId: string; vaultName: string };

const FORMAT_LABEL: Record<string, string> = {
  bitwarden_json: "Bitwarden JSON",
  bitwarden_csv: "Bitwarden CSV",
  one_password1pux: "1Password (.1pux)",
  one_password_1pux: "1Password (.1pux)",
  one_password_csv: "1Password CSV",
  passbolt_csv: "Passbolt CSV",
  kdbx: "KeePass database",
  lastpass_csv: "LastPass CSV",
  chrome_csv: "Browser CSV (Chrome, Edge, Firefox or Safari)",
  generic_csv: "CSV file (columns matched by name)",
};

const KIND_PLURAL: Record<ItemKind, [string, string]> = {
  login: ["Login", "Logins"],
  note: ["Secure note", "Secure notes"],
  card: ["Card", "Cards"],
  identity: ["Identity", "Identities"],
  ssh_key: ["SSH key", "SSH keys"],
};

const ACCEPT = ".json,.csv,.1pux,.kdbx";
const fmt = (n: number) => n.toLocaleString();

/** Core warnings are terse lower-case notes; present them as sentences. */
function sentence(s: string) {
  const t = s.trim();
  if (!t) return t;
  const up = t[0].toUpperCase() + t.slice(1);
  return /[.!?]$/.test(up) ? up : `${up}.`;
}

function summarize(items: Item[]) {
  const counts = new Map<ItemKind, number>();
  const folders = new Set<string>();
  for (const it of items) {
    const k = kindOf(it);
    counts.set(k, (counts.get(k) ?? 0) + 1);
    if (it.folder) folders.add(it.folder);
  }
  const order: ItemKind[] = ["login", "note", "card", "identity", "ssh_key"];
  return {
    counts: order.filter((k) => counts.has(k)).map((k) => ({ kind: k, n: counts.get(k)! })),
    folders: [...folders].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" })),
  };
}

function readError(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  if (msg === "decrypt_failed") return "That password did not open the file. Check it and try again; it is the password set when the file was exported, not your PassAuth master password.";
  return `PassAuth could not read this file: ${sentence(msg)} Check that it is an unmodified export from Bitwarden, Vaultwarden, 1Password, Passbolt, KeePass, LastPass or a browser, then try again.`;
}

export function ImportPage() {
  useVault(); // re-render when vaults change
  const vaults = writableVaults();
  const [step, setStep] = useState<Step>({ kind: "choose" });
  const [fileName, setFileName] = useState("");
  const [password, setPassword] = useState("");
  const [chosenVault, setVaultId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [over, setOver] = useState(false);
  const bytes = useRef<Uint8Array | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);

  const clearBytes = () => {
    bytes.current?.fill(0);
    bytes.current = null;
  };

  // Never keep the plaintext export around after leaving the page.
  useEffect(() => clearBytes, []);

  const vaultId = vaults.some((v) => v.id === chosenVault) ? chosenVault : (vaults[0]?.id ?? "");

  // Move focus to the new step's heading for keyboard and screen reader users.
  const firstStep = useRef(true);
  useEffect(() => {
    if (firstStep.current) {
      firstStep.current = false;
      return;
    }
    heading.current?.focus();
  }, [step.kind]);

  function reset() {
    clearBytes();
    setPassword("");
    setFileName("");
    setError(null);
    setStep({ kind: "choose" });
  }

  async function parse(pw?: string) {
    if (!bytes.current) return reset();
    setError(null);
    setStep({ kind: "reading" });
    // Let the "Reading" state paint; KeePass key derivation can take a moment.
    await new Promise((r) => setTimeout(r, 30));
    try {
      const res = importFile(bytes.current, pw) as { format: string; items: Item[]; warnings: string[] };
      clearBytes();
      setPassword("");
      setStep({ kind: "preview", format: res.format, items: res.items, warnings: res.warnings.map(sentence) });
    } catch (e) {
      if (e instanceof Error && e.message === "password_required") {
        setStep({ kind: "password" });
        return;
      }
      setPassword("");
      if (pw !== undefined) {
        setStep({ kind: "password" });
        setError(readError(e));
      } else {
        clearBytes();
        setStep({ kind: "choose" });
        setError(readError(e));
      }
    }
  }

  async function takeFile(file: File | undefined) {
    if (!file) return;
    clearBytes();
    setFileName(file.name);
    setError(null);
    try {
      bytes.current = new Uint8Array(await file.arrayBuffer());
    } catch {
      setStep({ kind: "choose" });
      setError("The browser could not read that file. Check that it still exists and that you have permission to open it, then choose it again.");
      return;
    }
    await parse();
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setOver(false);
    takeFile(e.dataTransfer.files[0]);
  }

  function onPassword(e: FormEvent) {
    e.preventDefault();
    if (!password) return setError("Enter the password that protects this export.");
    parse(password);
  }

  async function runImport() {
    if (step.kind !== "preview") return;
    const target = vaults.find((v) => v.id === vaultId);
    if (!target) return setError("Choose a vault to import into.");
    const { items, format, warnings } = step;
    const total = items.length;
    let done = 0;
    setError(null);
    setStep({ kind: "importing", total, done: 0 });
    try {
      await importItems(target.id, items, (n) => {
        done = n;
        setStep({ kind: "importing", total, done: n });
      });
      setStep({ kind: "done", count: total, vaultId: target.id, vaultName: target.name });
      setFileName("");
    } catch (e) {
      if (done >= total) {
        // Every item was saved; only the follow-up vault refresh failed.
        setStep({ kind: "done", count: total, vaultId: target.id, vaultName: target.name });
        setFileName("");
        return;
      }
      const why = sentence(errorMessage(e));
      if (done > 0) {
        setStep({ kind: "done", count: done, vaultId: target.id, vaultName: target.name });
        setError(
          `The import stopped after ${fmt(done)} of ${fmt(total)} items. ${why} The ${fmt(done)} items already saved are in "${target.name}". To finish, import the file again; items already saved will appear twice, so delete the duplicates afterwards.`,
        );
      } else {
        setStep({ kind: "preview", format, items, warnings });
        setError(`Nothing was imported. ${why} Check your connection and try again.`);
      }
    }
  }

  const stepNo = step.kind === "choose" || step.kind === "reading" || step.kind === "password" ? 1 : step.kind === "preview" ? 2 : 3;

  return (
    <div className="page">
      <div className="page-inner">
        <header className="page-head">
          <h1>Import</h1>
          <p>Bring your passwords from another password manager into PassAuth.</p>
        </header>

        <div className="alert privacy-note">
          <Icon name="shield" />
          <span>
            Your file is read and encrypted in this browser. Its contents are never uploaded unencrypted; only the encrypted items reach the server.
          </span>
        </div>

        <section className="card" aria-labelledby="import-step">
          <span className="step-label">Step {stepNo} of 3</span>

          {(step.kind === "choose" || step.kind === "reading") && (
            <>
              <h2 id="import-step" ref={heading} tabIndex={-1}>
                Choose your export file
              </h2>
              <div
                className={`dropzone${over ? " over" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setOver(true);
                }}
                onDragLeave={() => setOver(false)}
                onDrop={onDrop}
              >
                <span className="dz-icon">
                  <Icon name="upload" size={22} />
                </span>
                {step.kind === "reading" ? (
                  <p role="status">Reading {fileName}</p>
                ) : (
                  <>
                    <p>
                      <strong>Drop a file here</strong> or choose one from your computer.
                    </p>
                    <button type="button" className="btn btn-primary" onClick={() => fileInput.current?.click()}>
                      Choose file
                    </button>
                    <span className="small muted">.json, .csv, .1pux or .kdbx</span>
                  </>
                )}
                <input
                  ref={fileInput}
                  type="file"
                  accept={ACCEPT}
                  className="sr-only"
                  tabIndex={-1}
                  aria-hidden="true"
                  onChange={(e) => {
                    takeFile(e.target.files?.[0]);
                    e.target.value = "";
                  }}
                />
              </div>
              <ErrorText error={error} />
            </>
          )}

          {step.kind === "password" && (
            <form className="stack" onSubmit={onPassword}>
              <h2 id="import-step" ref={heading} tabIndex={-1}>
                Unlock {fileName}
              </h2>
              <p className="muted">
                This export is protected with a password. Enter the password you set when exporting it, or the KeePass database password.
              </p>
              <label className="field">
                <span>Export or database password</span>
                <PasswordInput id="import-password" value={password} onChange={setPassword} autoComplete="off" autoFocus />
              </label>
              <ErrorText error={error} />
              <div className="row">
                <button type="submit" className="btn btn-brass">
                  Unlock file
                </button>
                <button type="button" className="btn btn-ghost" onClick={reset}>
                  Choose a different file
                </button>
              </div>
            </form>
          )}

          {step.kind === "preview" && (
            <Preview
              step={step}
              fileName={fileName}
              vaults={vaults}
              vaultId={vaultId}
              setVaultId={setVaultId}
              error={error}
              onImport={runImport}
              onCancel={reset}
              headingRef={heading}
            />
          )}

          {step.kind === "importing" && (
            <>
              <h2 id="import-step" ref={heading} tabIndex={-1}>
                Importing
              </h2>
              <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={step.total} aria-valuenow={step.done} aria-label="Import progress">
                <i style={{ width: `${step.total ? (step.done / step.total) * 100 : 100}%` }} />
              </div>
              <p role="status" aria-live="polite">
                {step.done < step.total
                  ? `Encrypting and uploading ${fmt(step.done)} of ${fmt(step.total)}`
                  : "All items uploaded. Refreshing your vault."}
              </p>
              <p className="small muted">Keep this tab open until the import finishes.</p>
            </>
          )}

          {step.kind === "done" && (
            <>
              <h2 id="import-step" ref={heading} tabIndex={-1}>
                {error ? "Import stopped" : "Import complete"}
              </h2>
              {error ? (
                <ErrorText error={error} />
              ) : (
                <div className="alert alert-ok" role="status">
                  {fmt(step.count)} {step.count === 1 ? "item was" : "items were"} encrypted and saved to "{step.vaultName}". The export file is no longer held in this page.
                </div>
              )}
              <p className="small muted">You can now delete the export file from your computer; it holds your passwords unencrypted.</p>
              <div className="row">
                <Link className="btn btn-primary" to={filterPath(`vault:${step.vaultId}`)}>
                  Open {step.vaultName}
                </Link>
                <button type="button" className="btn btn-ghost" onClick={reset}>
                  Import another file
                </button>
              </div>
            </>
          )}
        </section>

        <section className="card" aria-labelledby="import-help">
          <h2 id="import-help" className="section-title">
            How to export from another password manager
          </h2>
          <ul className="help-list">
            <li>
              <b>Bitwarden or Vaultwarden:</b> in the web vault open Tools, choose Export vault and pick .json (a password-protected .json works too).
            </li>
            <li>
              <b>1Password:</b> in the desktop app choose File, then Export, select your account and save the .1pux file.
            </li>
            <li>
              <b>Passbolt:</b> select the passwords, choose Export and pick CSV or KeePass (.kdbx).
            </li>
          </ul>
          <p className="small muted">KeePass databases, LastPass CSV and browser password CSV files also work.</p>
        </section>
      </div>
    </div>
  );
}

function Preview({
  step,
  fileName,
  vaults,
  vaultId,
  setVaultId,
  error,
  onImport,
  onCancel,
  headingRef,
}: {
  step: { format: string; items: Item[]; warnings: string[] };
  fileName: string;
  vaults: { id: string; name: string }[];
  vaultId: string;
  setVaultId: (id: string) => void;
  error: string | null;
  onImport: () => void;
  onCancel: () => void;
  headingRef: RefObject<HTMLHeadingElement | null>;
}) {
  const { counts, folders } = summarize(step.items);
  const total = step.items.length;
  const shownFolders = folders.slice(0, 24);
  return (
    <>
      <h2 id="import-step" ref={headingRef} tabIndex={-1}>
        Review and choose a vault
      </h2>
      <div className="file-chip">
        <span className="avatar">
          <Icon name="note" />
        </span>
        <div className="grow">
          <div style={{ fontWeight: 500, overflowWrap: "anywhere" }}>{fileName}</div>
          <div className="small muted">Detected as {FORMAT_LABEL[step.format] ?? "an export file"}</div>
        </div>
      </div>

      {total > 0 && (
        <div className="stat-grid">
          <div className="stat">
            <span className="num">{fmt(total)}</span>
            <span className="lbl">{total === 1 ? "Item in total" : "Items in total"}</span>
          </div>
          {counts.map((c) => (
            <div className="stat" key={c.kind}>
              <span className="num">{fmt(c.n)}</span>
              <span className="lbl">{KIND_PLURAL[c.kind][c.n === 1 ? 0 : 1]}</span>
            </div>
          ))}
        </div>
      )}

      {folders.length > 0 && (
        <div className="stack-s">
          <h3 className="section-title">
            {folders.length === 1 ? "1 folder found" : `${fmt(folders.length)} folders found`}
          </h3>
          <div className="tag-list">
            {shownFolders.map((f) => (
              <span className="badge" key={f}>
                {f}
              </span>
            ))}
            {folders.length > shownFolders.length && <span className="small muted">and {fmt(folders.length - shownFolders.length)} more</span>}
          </div>
        </div>
      )}

      {step.warnings.length > 0 && (
        <div className="alert alert-brass">
          <p style={{ fontWeight: 500, marginBottom: 4 }}>{step.warnings.length === 1 ? "1 note about this file" : `${step.warnings.length} notes about this file`}</p>
          <ul className="warn-list">
            {step.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {total === 0 ? (
        <>
          <p>There is nothing to import from this file. Check that you exported the right account or vault, then choose the file again.</p>
          <div className="row">
            <button type="button" className="btn btn-primary" onClick={onCancel}>
              Choose a different file
            </button>
          </div>
        </>
      ) : vaults.length === 0 ? (
        <>
          <ErrorText error="You don't have a vault you can add items to. Create a vault, or ask the vault owner for write access, then come back here." />
          <div className="row">
            <button type="button" className="btn btn-ghost" onClick={onCancel}>
              Choose a different file
            </button>
          </div>
        </>
      ) : (
        <>
          <label className="field" style={{ maxWidth: 360 }}>
            <span>Import into</span>
            <select className="select" value={vaultId} onChange={(e) => setVaultId(e.target.value)}>
              {vaults.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
            </select>
          </label>
          <ErrorText error={error} />
          <div className="row">
            <button type="button" className="btn btn-brass" onClick={onImport}>
              Import {fmt(total)} {total === 1 ? "item" : "items"}
            </button>
            <button type="button" className="btn btn-ghost" onClick={onCancel}>
              Choose a different file
            </button>
          </div>
        </>
      )}
    </>
  );
}
