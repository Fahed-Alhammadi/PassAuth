import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { setShowIcons, setTheme, useShowIcons, useTheme, type Theme } from "../lib/prefs";
import { Link, Navigate, useParams } from "react-router";
import QRCode from "qrcode";
import { CopyButton, ErrorText, Icon, Modal, PasswordInput, StrengthMeter, copySecret, toast } from "../components/ui";
import { ApiError, api, errorMessage } from "../lib/api";
import type { Role } from "../lib/types";
import {
  changeKeys,
  createVault,
  deleteVault,
  fingerprint,
  getAccount,
  getBundle,
  logout,
  lookupUser,
  reauth,
  removeMember,
  renameVault,
  shareVault,
  sync,
  useVault,
  type Vault,
} from "../lib/vault";
import "../styles/settings.css";

// ------------------------------------------------------------------ types

interface AccountInfo {
  user_id: string;
  email: string;
  name: string;
  email_verified: boolean;
  created_at: number;
  secret_key_enabled: boolean;
  fingerprint: string | null;
  two_factor: string[];
  recovery_codes_left: number;
  email_enabled: boolean;
}

interface Member {
  user_id: string;
  email: string;
  name: string;
  role: Role;
  public_key: string;
}

interface Session {
  id: string;
  device_id: string;
  device_name: string;
  device_kind: string;
  created_at: number;
  last_used: number;
}

const TABS = [
  { key: "account", label: "Account" },
  { key: "security", label: "Security" },
  { key: "two-step", label: "Two-step login" },
  { key: "vaults", label: "Vaults & sharing" },
  { key: "sessions", label: "Sessions" },
] as const;
type TabKey = (typeof TABS)[number]["key"];

const ROLE_LABEL: Record<Role, string> = { owner: "Owner", admin: "Admin", write: "Can edit", read: "Can view" };
const MIN_PASSWORD = 10;

// ---------------------------------------------------------------- helpers

/** Turn server and crypto errors into a sentence that says how to fix it. */
function friendly(e: unknown): string {
  if (e instanceof ApiError && e.status === 429) return "Too many attempts. Wait a minute, then try again.";
  const m = errorMessage(e);
  switch (m) {
    case "secret_key_required":
      return "This browser doesn't have your Secret Key saved. Sign out, sign in again with your Secret Key, then retry.";
    case "Wrong email, master password or Secret Key.":
    case "Wrong master password or Secret Key.":
      return "That master password is wrong. Check it and try again.";
    case "invalid code":
      return "That code didn't work. Enter the code that's showing now and try again.";
    case "start setup first":
      return "The setup expired. Cancel and start setup again.";
    case "reauth_required":
      return "Your confirmation expired. Enter your master password again.";
  }
  const s = m.charAt(0).toUpperCase() + m.slice(1);
  return /[.!?]$/.test(s) ? s : `${s}.`;
}

function download(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function formatDate(ts: number) {
  return new Date(ts * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function ago(ts: number) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "Just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) {
    const h = Math.floor(s / 3600);
    return `${h} hour${h === 1 ? "" : "s"} ago`;
  }
  if (s < 30 * 86400) {
    const d = Math.floor(s / 86400);
    return `${d} day${d === 1 ? "" : "s"} ago`;
  }
  return new Date(ts * 1000).toLocaleDateString(undefined, { dateStyle: "medium" });
}

function kindLabel(kind: string) {
  const known: Record<string, string> = { web: "Web vault", extension: "Browser extension", cli: "Command line", desktop: "Desktop app", mobile: "Mobile app" };
  return known[kind] ?? kind.charAt(0).toUpperCase() + kind.slice(1);
}

function safeFingerprint(publicKey: string): string {
  try {
    return fingerprint(publicKey);
  } catch {
    return "Unavailable";
  }
}

// ------------------------------------------------------------------- page

export function SettingsPage() {
  const { tab = "account" } = useParams();
  const [account, setAccount] = useState<AccountInfo | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setAccount(await api<AccountInfo>("/account"));
      setLoadError(null);
    } catch (e) {
      setLoadError(`Couldn't load your account settings. ${friendly(e)} Reload the page to try again.`);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  if (!TABS.some((t) => t.key === tab)) return <Navigate to="/settings/account" replace />;
  const current = tab as TabKey;

  let body: ReactNode = <p className="muted">Loading…</p>;
  if (current === "vaults") body = <VaultsTab />;
  else if (current === "sessions") body = <SessionsTab />;
  else if (current === "security") body = <SecurityTab />;
  else if (account) body = current === "account" ? <AccountTab account={account} reload={reload} /> : <TwoStepTab account={account} reload={reload} />;
  else if (loadError) body = <ErrorText error={loadError} />;

  return (
    <div className="page">
      <div className="page-inner">
        <div className="settings-head">
          <h1>Settings</h1>
          <nav className="settings-tabs" aria-label="Settings sections">
            {TABS.map((t) => (
              <Link key={t.key} to={`/settings/${t.key}`} aria-current={t.key === current ? "page" : undefined}>
                {t.label}
              </Link>
            ))}
          </nav>
        </div>
        <div className="settings-section">{body}</div>
      </div>
    </div>
  );
}

// ------------------------------------------------------- shared dialogs

/** Ask for the master password before a sensitive action. */
function ConfirmPassword({
  title,
  children,
  action,
  danger,
  onConfirm,
  onClose,
}: {
  title: string;
  children?: ReactNode;
  action: string;
  danger?: boolean;
  onConfirm: (password: string) => Promise<void>;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = useCallback(() => {
    if (!busy) onClose();
  }, [busy, onClose]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password) return setError("Enter your master password to continue.");
    setBusy(true);
    setError(null);
    try {
      await onConfirm(password);
    } catch (err) {
      setError(friendly(err));
      setBusy(false);
    }
  }

  return (
    <Modal title={title} onClose={close}>
      <form className="stack" onSubmit={submit}>
        {children}
        <div className="field">
          <label htmlFor="confirm-password">
            Master password
          </label>
          <PasswordInput id="confirm-password" value={password} onChange={setPassword} autoFocus />
        </div>
        <ErrorText error={error} />
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn btn-ghost" onClick={close} disabled={busy}>
            Cancel
          </button>
          <button type="submit" className={`btn ${danger ? "btn-danger" : "btn-primary"}`} disabled={busy}>
            {busy ? "Working…" : action}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Plain yes/no confirmation for destructive actions that don't need reauth. */
function ConfirmDialog({
  title,
  children,
  action,
  onConfirm,
  onClose,
}: {
  title: string;
  children: ReactNode;
  action: string;
  onConfirm: () => Promise<void>;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = useCallback(() => {
    if (!busy) onClose();
  }, [busy, onClose]);

  async function confirm() {
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
    } catch (e) {
      setError(friendly(e));
      setBusy(false);
    }
  }

  return (
    <Modal title={title} onClose={close}>
      <div className="stack">
        {children}
        <ErrorText error={error} />
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn btn-ghost" onClick={close} disabled={busy}>
            Cancel
          </button>
          <button type="button" className="btn btn-danger" onClick={confirm} disabled={busy} autoFocus>
            {busy ? "Working…" : action}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------- account

function AccountTab({ account, reload }: { account: AccountInfo; reload: () => Promise<void> }) {
  const [name, setName] = useState(account.name);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const fp = account.fingerprint ?? getAccount()?.fingerprint() ?? null;
  const showIcons = useShowIcons();
  const theme = useTheme();

  async function saveName(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (trimmed.length > 100) return setError("Names can be at most 100 characters. Shorten it and save again.");
    setSaving(true);
    setError(null);
    try {
      await api("/account/profile", { method: "PUT", body: { name: trimmed } });
      await Promise.all([reload(), sync()]);
      toast("Name saved");
    } catch (err) {
      setError(friendly(err));
    } finally {
      setSaving(false);
    }
  }

  async function deleteAccount(password: string) {
    const token = await reauth(password);
    await api("/account", { method: "DELETE", headers: { "x-reauth-token": token } });
    await logout();
  }

  return (
    <>
      <section className="card" aria-labelledby="profile-title">
        <h2 id="profile-title">Profile</h2>
        <form className="inline-form" onSubmit={saveName}>
          <label className="field">
            <span>Name</span>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" maxLength={100} />
          </label>
          <button type="submit" className="btn btn-primary" disabled={saving || name.trim() === account.name}>
            {saving ? "Saving…" : "Save name"}
          </button>
        </form>
        <ErrorText error={error} />
        <div className="field">
          <span>Email</span>
          <div className="row">
            <span>{account.email}</span>
            {account.email_verified ? <span className="badge badge-ok">Verified</span> : <span className="badge badge-warn">Not verified</span>}
          </div>
          {!account.email_verified && (
            <span className="small muted">Others can't share vaults with you until you verify your email. Check your inbox for the verification link.</span>
          )}
        </div>
      </section>

      <section className="card" aria-labelledby="fp-title">
        <h2 id="fp-title">Your public key fingerprint</h2>
        <p className="card-text">
          When someone shares a vault with you, PassAuth shows them this fingerprint. Ask them to read it back to you, in person or over a call, and
          check that it matches exactly. A match means the vault is encrypted for you and nobody else.
        </p>
        {fp ? (
          <div className="row">
            <div className="fingerprint grow">{fp}</div>
            <CopyButton value={fp} label="Copy fingerprint" />
          </div>
        ) : (
          <p className="muted">Your fingerprint isn't available. Reload the page to try again.</p>
        )}
      </section>

      <section className="card danger-zone" aria-labelledby="danger-title">
        <h2 id="danger-title">Delete account</h2>
        <p className="card-text">
          This permanently deletes your account, every vault you own and every item in them. People you shared those vaults with lose access too.
          You can't undo this.
        </p>
        <div>
          <button type="button" className="btn btn-danger" onClick={() => setDeleting(true)}>
            <Icon name="trash" />
            Delete account
          </button>
        </div>
      </section>

      <section className="card" aria-labelledby="appearance-title">
        <h2 id="appearance-title">Appearance</h2>
        <label className="field">
          <span>Theme</span>
          <select className="select" value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
            <option value="system">Same as system</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={showIcons} onChange={(e) => setShowIcons(e.target.checked)} />
          <span>
            Show website icons
            <span className="small muted block">Icons are fetched by your PassAuth server, which learns the website addresses but never your vault contents. Applies to this browser.</span>
          </span>
        </label>
      </section>

      {deleting && (
        <ConfirmPassword title="Delete your account" action="Delete account" danger onConfirm={deleteAccount} onClose={() => setDeleting(false)}>
          <p className="card-text">Enter your master password to permanently delete {account.email} and all vaults you own.</p>
        </ConfirmPassword>
      )}
    </>
  );
}

// --------------------------------------------------------------- security

function SecurityTab() {
  const { email } = useVault();
  const [skOn, setSkOn] = useState<boolean>(() => !!getBundle()?.secret_key_enabled);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toggling, setToggling] = useState(false);
  const [newSecretKey, setNewSecretKey] = useState<string | null>(null);

  async function changePassword(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!current) return setError("Enter your current master password.");
    if (next.length < MIN_PASSWORD) return setError(`Use at least ${MIN_PASSWORD} characters for your new master password.`);
    if (next !== confirm) return setError("The new passwords don't match. Type the same password in both fields.");
    setBusy(true);
    try {
      const sk = await changeKeys(current, next, skOn);
      setCurrent("");
      setNext("");
      setConfirm("");
      toast("Master password changed. Other devices were signed out.");
      if (sk) setNewSecretKey(sk);
    } catch (err) {
      setError(friendly(err));
    } finally {
      setBusy(false);
    }
  }

  async function toggleSecretKey(password: string) {
    const turnOn = !skOn;
    const sk = await changeKeys(password, password, turnOn);
    setSkOn(!!getBundle()?.secret_key_enabled);
    setToggling(false);
    if (sk) setNewSecretKey(sk);
    else toast("Secret Key turned off. Other devices were signed out.");
  }

  return (
    <>
      <section className="card" aria-labelledby="pw-title">
        <h2 id="pw-title">Change master password</h2>
        <p className="card-text">
          Your master password encrypts your vault and is never sent to the server. If you forget it, nobody can recover your data.
          {skOn && " Changing it also creates a new Secret Key."}
        </p>
        <form className="stack" onSubmit={changePassword}>
          <div className="field">
            <label htmlFor="pw-current">
              Current master password
            </label>
            <PasswordInput id="pw-current" value={current} onChange={setCurrent} />
          </div>
          <div className="field">
            <label htmlFor="pw-new">
              New master password
            </label>
            <PasswordInput id="pw-new" value={next} onChange={setNext} autoComplete="new-password" />
            <StrengthMeter password={next} />
            <span className="small muted">At least {MIN_PASSWORD} characters. A few unrelated words are easy to remember and hard to guess.</span>
          </div>
          <div className="field">
            <label htmlFor="pw-confirm">
              Confirm new master password
            </label>
            <PasswordInput id="pw-confirm" value={confirm} onChange={setConfirm} autoComplete="new-password" />
          </div>
          <ErrorText error={error} />
          <p className="small muted">Changing your master password signs out all your other devices.</p>
          <div>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Changing password…" : "Change master password"}
            </button>
          </div>
        </form>
      </section>

      <section className="card" aria-labelledby="sk-title">
        <div className="card-head">
          <h2 id="sk-title">Secret Key</h2>
          {skOn ? <span className="badge badge-ok">On</span> : <span className="badge">Off</span>}
        </div>
        <p className="card-text">
          A Secret Key is a long random code that's combined with your master password when you sign in on a new device. Even if someone learns
          your master password, they can't open your vault without it.
        </p>
        {skOn ? (
          <p className="small muted">
            This browser remembers your Secret Key. Keep your Emergency Kit somewhere safe: you need it to sign in on any other device.
          </p>
        ) : (
          <p className="small muted">When you turn it on, you'll get a Secret Key to save in an Emergency Kit.</p>
        )}
        <div>
          <button type="button" className={skOn ? "btn" : "btn btn-primary"} onClick={() => setToggling(true)}>
            <Icon name="key" />
            {skOn ? "Turn off Secret Key" : "Turn on Secret Key"}
          </button>
        </div>
      </section>

      {toggling && (
        <ConfirmPassword
          title={skOn ? "Turn off Secret Key" : "Turn on Secret Key"}
          action={skOn ? "Turn off Secret Key" : "Turn on Secret Key"}
          onConfirm={toggleSecretKey}
          onClose={() => setToggling(false)}
        >
          <p className="card-text">
            {skOn
              ? "After this, your master password alone unlocks your vault on a new device. Your current Secret Key and Emergency Kit stop working."
              : "PassAuth will create a Secret Key and show it once. You'll need it, together with your master password, to sign in on other devices."}{" "}
            All your other devices will be signed out.
          </p>
        </ConfirmPassword>
      )}

      {newSecretKey && <SecretKeyModal secretKey={newSecretKey} email={email} onClose={() => setNewSecretKey(null)} />}
    </>
  );
}

function SecretKeyModal({ secretKey, email, onClose }: { secretKey: string; email: string; onClose: () => void }) {
  const [saved, setSaved] = useState(false);
  const close = useCallback(() => {
    if (saved) onClose();
  }, [saved, onClose]);

  function downloadKit() {
    const kit = [
      "PassAuth Emergency Kit",
      "",
      "Keep this somewhere safe and offline, such as printed in a drawer.",
      "To sign in on a new device you need your master password and this Secret Key.",
      "",
      `Server: ${location.origin}`,
      `Email: ${email}`,
      `Secret Key: ${secretKey}`,
      "",
      "Master password: ________________________________________",
      "",
      `Created: ${new Date().toLocaleString()}`,
      "",
    ].join("\n");
    download("PassAuth Emergency Kit.txt", kit);
  }

  return (
    <Modal title="Save your new Secret Key" onClose={close}>
      <p className="card-text">
        This is the only time PassAuth shows your Secret Key. Any older Secret Key no longer works. Save it now: without it, you can't sign in on a
        new device.
      </p>
      <div className="secret-key" aria-label="Secret Key">
        {secretKey}
      </div>
      <div className="row" style={{ flexWrap: "wrap" }}>
        <button type="button" className="btn btn-accent" onClick={downloadKit}>
          <Icon name="upload" />
          Download Emergency Kit
        </button>
        <button type="button" className="btn" onClick={() => copySecret(secretKey, "Secret Key copied")}>
          <Icon name="copy" />
          Copy
        </button>
      </div>
      <label className="check">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span>I saved my Secret Key</span>
      </label>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button type="button" className="btn btn-primary" disabled={!saved} onClick={onClose}>
          Done
        </button>
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------- two-step login

function TwoStepTab({ account, reload }: { account: AccountInfo; reload: () => Promise<void> }) {
  const [codes, setCodes] = useState<string[] | null>(null);
  const [disabling, setDisabling] = useState<"totp" | "email" | null>(null);
  const [regenerating, setRegenerating] = useState(false);
  const totpOn = account.two_factor.includes("totp");
  const emailOn = account.two_factor.includes("email");
  const anyOn = account.two_factor.length > 0;

  async function enabled(recovery: string[] | null) {
    await reload();
    if (recovery?.length) setCodes(recovery);
  }

  async function disable(password: string) {
    const token = await reauth(password);
    await api(`/account/2fa/${disabling}`, { method: "DELETE", headers: { "x-reauth-token": token } });
    toast(disabling === "totp" ? "Authenticator app turned off" : "Email codes turned off");
    setDisabling(null);
    await reload();
  }

  async function regenerate(password: string) {
    const token = await reauth(password);
    const r = await api<{ recovery_codes: string[] }>("/account/2fa/recovery", { method: "POST", headers: { "x-reauth-token": token } });
    setRegenerating(false);
    setCodes(r.recovery_codes);
    await reload();
  }

  const lastOne = account.two_factor.length === 1;

  return (
    <>
      <p className="card-text">
        Two-step login asks for a code after your master password when you sign in on a new device, so a stolen password isn't enough.
      </p>

      <TotpCard on={totpOn} onEnabled={enabled} onDisable={() => setDisabling("totp")} />
      <EmailCard on={emailOn} available={account.email_enabled} email={account.email} onEnabled={enabled} onDisable={() => setDisabling("email")} />

      <section className="card" aria-labelledby="rc-title">
        <h2 id="rc-title">Recovery codes</h2>
        {anyOn ? (
          <>
            <p className="card-text">
              Use a recovery code to sign in if you lose access to your other methods. You have {account.recovery_codes_left} unused{" "}
              {account.recovery_codes_left === 1 ? "code" : "codes"} left.
            </p>
            {account.recovery_codes_left <= 3 && (
              <div className="alert alert-info">You're running low on recovery codes. Generate new ones and store them somewhere safe.</div>
            )}
            <div>
              <button type="button" className="btn" onClick={() => setRegenerating(true)}>
                Generate new recovery codes
              </button>
            </div>
          </>
        ) : (
          <p className="card-text">You'll get recovery codes when you turn on your first two-step method.</p>
        )}
      </section>

      {disabling && (
        <ConfirmPassword
          title={disabling === "totp" ? "Turn off authenticator app" : "Turn off email codes"}
          action="Turn off"
          danger
          onConfirm={disable}
          onClose={() => setDisabling(null)}
        >
          <p className="card-text">
            {lastOne
              ? "This is your only two-step method. Turning it off also deletes your recovery codes, and signing in will need only your master password."
              : "You can turn it on again at any time."}
          </p>
        </ConfirmPassword>
      )}

      {regenerating && (
        <ConfirmPassword title="Generate new recovery codes" action="Generate new codes" onConfirm={regenerate} onClose={() => setRegenerating(false)}>
          <p className="card-text">Your current recovery codes stop working as soon as the new ones are created.</p>
        </ConfirmPassword>
      )}

      {codes && <RecoveryCodesModal codes={codes} onClose={() => setCodes(null)} />}
    </>
  );
}

function CodeField({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  return (
    <div className="field">
      <label htmlFor={id}>
        Verification code
      </label>
      <input
        id={id}
        className="input mono code-input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={10}
        spellCheck={false}
      />
    </div>
  );
}

function TotpCard({ on, onEnabled, onDisable }: { on: boolean; onEnabled: (codes: string[] | null) => Promise<void>; onDisable: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ secret: string; uri: string }>("/account/2fa/totp/setup", { method: "POST" });
      const qr = await QRCode.toDataURL(r.uri, { margin: 1, width: 200 });
      setSetup({ secret: r.secret, qr });
      setCode("");
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(false);
    }
  }

  async function enable(e: FormEvent) {
    e.preventDefault();
    if (!code.trim()) return setError("Enter the 6-digit code from your authenticator app.");
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ recovery_codes: string[] | null }>("/account/2fa/totp/enable", { body: { code: code.replace(/\s/g, "") } });
      setSetup(null);
      toast("Authenticator app turned on");
      await onEnabled(r.recovery_codes);
    } catch (err) {
      setError(friendly(err));
    } finally {
      setBusy(false);
    }
  }

  const prettySecret = setup?.secret.replace(/(.{4})/g, "$1 ").trim();

  return (
    <section className="card" aria-labelledby="totp-title">
      <div className="card-head">
        <h2 id="totp-title">Authenticator app</h2>
        {on ? <span className="badge badge-ok">On</span> : <span className="badge">Off</span>}
      </div>
      <p className="card-text">Get a new 6-digit code every 30 seconds from an app like 1Password, Aegis, Google Authenticator or Microsoft Authenticator.</p>

      {on ? (
        <div>
          <button type="button" className="btn btn-danger" onClick={onDisable}>
            Turn off authenticator app
          </button>
        </div>
      ) : setup ? (
        <form className="stack" onSubmit={enable}>
          <div className="totp-setup">
            <div className="qr">
              <img src={setup.qr} alt="QR code to add PassAuth to your authenticator app" width={200} height={200} />
            </div>
            <div className="stack-s">
              <p className="card-text">1. Scan the QR code with your authenticator app.</p>
              <p className="small muted">Can't scan it? Enter this setup key in the app instead:</p>
              <div className="row">
                <code className="mono" style={{ wordBreak: "break-all" }}>
                  {prettySecret}
                </code>
                <CopyButton value={setup.secret} label="Copy setup key" />
              </div>
              <p className="card-text">2. Enter the code the app shows.</p>
              <CodeField id="totp-code" value={code} onChange={setCode} />
            </div>
          </div>
          <ErrorText error={error} />
          <div className="row">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Checking code…" : "Turn on authenticator app"}
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => setSetup(null)} disabled={busy}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <>
          <ErrorText error={error} />
          <div>
            <button type="button" className="btn btn-primary" onClick={start} disabled={busy}>
              {busy ? "Starting setup…" : "Set up authenticator app"}
            </button>
          </div>
        </>
      )}
    </section>
  );
}

function EmailCard({
  on,
  available,
  email,
  onEnabled,
  onDisable,
}: {
  on: boolean;
  available: boolean;
  email: string;
  onEnabled: (codes: string[] | null) => Promise<void>;
  onDisable: () => void;
}) {
  const [sent, setSent] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send() {
    setBusy(true);
    setError(null);
    try {
      await api("/account/2fa/email/setup", { method: "POST" });
      setSent(true);
      setCode("");
      toast(`Code sent to ${email}`);
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(false);
    }
  }

  async function enable(e: FormEvent) {
    e.preventDefault();
    if (!code.trim()) return setError("Enter the code from the email we sent you.");
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ recovery_codes: string[] | null }>("/account/2fa/email/enable", { body: { code: code.trim() } });
      setSent(false);
      toast("Email codes turned on");
      await onEnabled(r.recovery_codes);
    } catch (err) {
      setError(friendly(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="email2fa-title">
      <div className="card-head">
        <h2 id="email2fa-title">Email codes</h2>
        {on ? <span className="badge badge-ok">On</span> : <span className="badge">Off</span>}
      </div>
      <p className="card-text">Get a one-time code by email at {email} when you sign in.</p>

      {on ? (
        <div>
          <button type="button" className="btn btn-danger" onClick={onDisable}>
            Turn off email codes
          </button>
        </div>
      ) : !available ? (
        <>
          <p className="small muted">This server isn't set up to send email, so email codes aren't available. Ask your PassAuth administrator to configure email.</p>
          <div>
            <button type="button" className="btn" disabled>
              Send setup code
            </button>
          </div>
        </>
      ) : sent ? (
        <form className="stack" onSubmit={enable}>
          <p className="card-text">We sent a code to {email}. Enter it below.</p>
          <CodeField id="email-code" value={code} onChange={setCode} />
          <ErrorText error={error} />
          <div className="row" style={{ flexWrap: "wrap" }}>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Checking code…" : "Turn on email codes"}
            </button>
            <button type="button" className="btn btn-ghost" onClick={send} disabled={busy}>
              Send a new code
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => setSent(false)} disabled={busy}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <>
          <ErrorText error={error} />
          <div>
            <button type="button" className="btn btn-primary" onClick={send} disabled={busy}>
              {busy ? "Sending…" : "Send setup code"}
            </button>
          </div>
        </>
      )}
    </section>
  );
}

function RecoveryCodesModal({ codes, onClose }: { codes: string[]; onClose: () => void }) {
  const text = codes.join("\n");
  return (
    <Modal title="Save your recovery codes" onClose={onClose}>
      <p className="card-text">
        If you lose your phone or can't get email, a recovery code lets you sign in. Each code works once. This is the only time PassAuth shows them.
      </p>
      <div className="codes recovery-codes" aria-label="Recovery codes">
        {codes.map((c) => (
          <span key={c}>{c}</span>
        ))}
      </div>
      <div className="row" style={{ flexWrap: "wrap" }}>
        <button type="button" className="btn" onClick={() => copySecret(text, "Recovery codes copied")}>
          <Icon name="copy" />
          Copy all
        </button>
        <button
          type="button"
          className="btn"
          onClick={() => download("PassAuth recovery codes.txt", `PassAuth recovery codes\n${location.origin}\n\nEach code works once.\n\n${text}\n`)}
        >
          <Icon name="upload" />
          Download
        </button>
      </div>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button type="button" className="btn btn-primary" onClick={onClose}>
          Done
        </button>
      </div>
    </Modal>
  );
}

// -------------------------------------------------------- vaults & sharing

function VaultsTab() {
  const { vaults, items } = useVault();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function create(e: FormEvent) {
    e.preventDefault();
    const n = name.trim();
    if (!n) return setError("Enter a name for the new vault.");
    setBusy(true);
    setError(null);
    try {
      await createVault(n);
      setName("");
      toast(`Vault "${n}" created`);
    } catch (err) {
      setError(friendly(err));
    } finally {
      setBusy(false);
    }
  }

  const counts = new Map<string, number>();
  for (const it of items) if (!it.deletedAt) counts.set(it.vaultId, (counts.get(it.vaultId) ?? 0) + 1);

  return (
    <>
      <section className="card" aria-labelledby="newvault-title">
        <h2 id="newvault-title">Create a vault</h2>
        <p className="card-text">Use separate vaults to keep things apart, or to share a set of items with family or colleagues.</p>
        <form className="inline-form" onSubmit={create}>
          <label className="field">
            <span>Vault name</span>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
          </label>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            <Icon name="plus" />
            {busy ? "Creating…" : "Create vault"}
          </button>
        </form>
        <ErrorText error={error} />
      </section>

      {vaults.map((v) => (
        <VaultCard key={v.id} vault={v} count={counts.get(v.id) ?? 0} />
      ))}
    </>
  );
}

function VaultCard({ vault, count }: { vault: Vault; count: number }) {
  const { userId } = useVault();
  const [open, setOpen] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const canManage = vault.role === "owner" || vault.role === "admin";

  async function leave() {
    await api(`/vaults/${vault.id}/members/${userId}`, { method: "DELETE" });
    await sync();
    toast(`You left "${vault.name}"`);
  }

  return (
    <section className="card" aria-labelledby={`vault-${vault.id}`}>
      <div className="card-head">
        <div className="row">
          <Icon name="vault" />
          <h2 id={`vault-${vault.id}`}>{vault.name}</h2>
          <span className={`badge${vault.role === "owner" ? " badge-ok" : ""}`}>{ROLE_LABEL[vault.role]}</span>
        </div>
        <div className="row">
          {canManage && (
            <button type="button" className="btn" aria-expanded={open} onClick={() => setOpen(!open)}>
              <Icon name="share" />
              {open ? "Close" : "Manage and share"}
            </button>
          )}
          {vault.role !== "owner" && (
            <button type="button" className="btn btn-danger" onClick={() => setLeaving(true)}>
              Leave vault
            </button>
          )}
        </div>
      </div>
      <p className="small muted">
        {count} {count === 1 ? "item" : "items"}
        {vault.kind === "sealed" ? ". Shared with you." : "."}
      </p>

      {open && canManage && <VaultManager vault={vault} count={count} />}

      {leaving && (
        <ConfirmDialog title={`Leave "${vault.name}"`} action="Leave vault" onConfirm={leave} onClose={() => setLeaving(false)}>
          <p className="card-text">
            You'll lose access to the {count} {count === 1 ? "item" : "items"} in this vault. To get access again, someone who manages the vault has to
            share it with you again.
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}

function VaultManager({ vault, count }: { vault: Vault; count: number }) {
  const { userId } = useVault();
  const [name, setName] = useState(vault.name);
  const [renaming, setRenaming] = useState(false);
  const [renameError, setRenameError] = useState<string | null>(null);
  const [members, setMembers] = useState<Member[] | null>(null);
  const [membersError, setMembersError] = useState<string | null>(null);
  const [removing, setRemoving] = useState<Member | null>(null);
  const [deleting, setDeleting] = useState(false);

  const loadMembers = useCallback(async () => {
    try {
      const r = await api<{ members: Member[] }>(`/vaults/${vault.id}/members`);
      setMembers(r.members);
      setMembersError(null);
    } catch (e) {
      setMembersError(`Couldn't load the members of this vault. ${friendly(e)}`);
    }
  }, [vault.id]);

  useEffect(() => {
    loadMembers();
  }, [loadMembers]);

  async function rename(e: FormEvent) {
    e.preventDefault();
    const n = name.trim();
    if (!n) return setRenameError("Enter a name for the vault.");
    setRenaming(true);
    setRenameError(null);
    try {
      await renameVault(vault.id, n);
      toast("Vault renamed");
    } catch (err) {
      setRenameError(friendly(err));
    } finally {
      setRenaming(false);
    }
  }

  async function remove() {
    if (!removing) return;
    await removeMember(vault.id, removing.user_id);
    toast(`${removing.name || removing.email} removed`);
    setRemoving(null);
    await loadMembers();
  }

  async function destroy() {
    await deleteVault(vault.id);
    toast(`Vault "${vault.name}" deleted`);
  }

  return (
    <div className="vault-manage">
      <form className="inline-form" onSubmit={rename}>
        <label className="field">
          <span>Vault name</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
        </label>
        <button type="submit" className="btn" disabled={renaming || name.trim() === vault.name}>
          {renaming ? "Saving…" : "Rename vault"}
        </button>
      </form>
      <ErrorText error={renameError} />

      <div className="stack-s">
        <h3>Members</h3>
        <ErrorText error={membersError} />
        {members === null && !membersError && <p className="muted small">Loading members…</p>}
        {members && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Person</th>
                  <th scope="col">Access</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.user_id}>
                    <td>
                      <div>
                        {m.name || m.email}
                        {m.user_id === userId && <span className="muted"> (you)</span>}
                      </div>
                      {m.name && <div className="small muted">{m.email}</div>}
                      <div className="fingerprint-s" title="Public key fingerprint">
                        {safeFingerprint(m.public_key)}
                      </div>
                    </td>
                    <td>
                      <span className="badge">{ROLE_LABEL[m.role] ?? m.role}</span>
                    </td>
                    <td className="actions">
                      {m.role !== "owner" && m.user_id !== userId && (
                        <button type="button" className="btn btn-danger" onClick={() => setRemoving(m)}>
                          Remove
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <AddMember vault={vault} members={members ?? []} onAdded={loadMembers} />

      {vault.role === "owner" && (
        <div className="stack-s">
          <h3>Delete vault</h3>
          <p className="card-text">Deletes the vault and every item in it, for you and everyone it's shared with.</p>
          <div>
            <button type="button" className="btn btn-danger" onClick={() => setDeleting(true)}>
              <Icon name="trash" />
              Delete vault
            </button>
          </div>
        </div>
      )}

      {removing && (
        <ConfirmDialog title={`Remove ${removing.name || removing.email}`} action="Remove" onConfirm={remove} onClose={() => setRemoving(null)}>
          <p className="card-text">
            They lose access to "{vault.name}" right away. PassAuth then replaces the vault key and re-encrypts every item, so they can't read any
            future changes. Anything they already copied or saw stays with them, so change important passwords if needed.
          </p>
        </ConfirmDialog>
      )}

      {deleting && (
        <ConfirmDialog title={`Delete "${vault.name}"`} action="Delete vault" onConfirm={destroy} onClose={() => setDeleting(false)}>
          <p className="card-text">
            This permanently deletes the vault and its {count} {count === 1 ? "item" : "items"} for everyone who has access. You can't undo this.
          </p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function AddMember({ vault, members, onAdded }: { vault: Vault; members: Member[]; onAdded: () => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [found, setFound] = useState<{ user_id: string; name: string; public_key: string; email: string } | null>(null);
  const [role, setRole] = useState<Role>("read");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function find(e: FormEvent) {
    e.preventDefault();
    const addr = email.trim();
    if (!addr) return setError("Enter the email address of the person you want to share with.");
    setBusy(true);
    setError(null);
    setFound(null);
    try {
      const u = await lookupUser(addr);
      setFound({ ...u, email: addr });
      setRole("read");
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 404
          ? "No verified PassAuth account uses that email on this server. Ask them to create an account and verify their email, then try again."
          : friendly(err),
      );
    } finally {
      setBusy(false);
    }
  }

  async function share() {
    if (!found) return;
    setBusy(true);
    setError(null);
    try {
      await shareVault(vault.id, found, role);
      toast(`"${vault.name}" shared with ${found.name || found.email}`);
      setFound(null);
      setEmail("");
      await onAdded();
    } catch (err) {
      setError(friendly(err));
    } finally {
      setBusy(false);
    }
  }

  const existing = found && members.find((m) => m.user_id === found.user_id);
  const roles: Role[] = ["read", "write", "admin"];

  return (
    <div className="stack-s">
      <h3>Share this vault</h3>
      <form className="inline-form" onSubmit={find}>
        <label className="field">
          <span>Email address</span>
          <input
            className="input"
            type="email"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
              setFound(null);
            }}
            autoComplete="off"
          />
        </label>
        <button type="submit" className="btn" disabled={busy}>
          <Icon name="search" />
          {busy && !found ? "Looking up…" : "Find person"}
        </button>
      </form>

      {found && (
        <div className="person">
          <div>
            <strong>{found.name || found.email}</strong>
            {found.name && <div className="small muted">{found.email}</div>}
          </div>
          <div className="stack-s">
            <span className="small">Their key fingerprint</span>
            <div className="fingerprint">{safeFingerprint(found.public_key)}</div>
            <p className="small muted">
              Ask {found.name || "them"} to open Settings, then Account, and read you their fingerprint. Share only if it matches exactly. If it doesn't,
              don't share and tell your PassAuth administrator.
            </p>
          </div>
          {existing && (
            <div className="alert alert-info">
              They already have {ROLE_LABEL[existing.role].toLowerCase()} access. Sharing again changes their access to what you choose below.
            </div>
          )}
          <label className="field">
            <span>Access</span>
            <select className="select" value={role} onChange={(e) => setRole(e.target.value as Role)}>
              {roles.map((r) => (
                <option key={r} value={r}>
                  {r === "read" ? "Can view" : r === "write" ? "Can edit" : "Admin (can edit and share)"}
                </option>
              ))}
            </select>
          </label>
          <div className="row">
            <button type="button" className="btn btn-primary" onClick={share} disabled={busy || existing?.role === "owner"}>
              {busy ? "Sharing…" : "Share vault"}
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => setFound(null)} disabled={busy}>
              Cancel
            </button>
          </div>
        </div>
      )}
      <ErrorText error={error} />
    </div>
  );
}

// ---------------------------------------------------------------- sessions

function SessionsTab() {
  const [data, setData] = useState<{ current: string; sessions: Session[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api<{ current: string; sessions: Session[] }>("/account/sessions"));
      setError(null);
    } catch (e) {
      setError(`Couldn't load your sessions. ${friendly(e)}`);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function revoke(ids: string[], key: string) {
    setBusy(key);
    setError(null);
    try {
      for (const id of ids) await api(`/account/sessions/${id}`, { method: "DELETE" });
      toast(ids.length === 1 ? "Session revoked" : `${ids.length} sessions revoked`);
      await load();
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(null);
    }
  }

  const others = data?.sessions.filter((s) => s.id !== data.current) ?? [];

  return (
    <section className="card" aria-labelledby="sessions-title">
      <div className="card-head">
        <h2 id="sessions-title">Signed-in devices</h2>
        {others.length > 1 && (
          <button
            type="button"
            className="btn btn-danger"
            disabled={busy !== null}
            onClick={() =>
              revoke(
                others.map((s) => s.id),
                "all",
              )
            }
          >
            {busy === "all" ? "Revoking…" : "Revoke all other sessions"}
          </button>
        )}
      </div>
      <p className="card-text">Revoking a session signs that device out. It will need your master password to sign in again.</p>
      <ErrorText error={error} />
      {!data && !error && <p className="muted small">Loading sessions…</p>}
      {data && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Device</th>
                <th scope="col">Type</th>
                <th scope="col">Signed in</th>
                <th scope="col">Last used</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.sessions.map((s) => {
                const isCurrent = s.id === data.current;
                return (
                  <tr key={s.id}>
                    <td>
                      {s.device_name || "Unknown device"}
                      {isCurrent && (
                        <>
                          {" "}
                          <span className="badge badge-ok">This device</span>
                        </>
                      )}
                    </td>
                    <td>{kindLabel(s.device_kind)}</td>
                    <td>{formatDate(s.created_at)}</td>
                    <td title={formatDate(s.last_used)}>{isCurrent ? "Now" : ago(s.last_used)}</td>
                    <td className="actions">
                      {!isCurrent && (
                        <button type="button" className="btn btn-danger" disabled={busy !== null} onClick={() => revoke([s.id], s.id)}>
                          {busy === s.id ? "Revoking…" : "Revoke"}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {data && others.length === 0 && <p className="small muted">You're not signed in anywhere else.</p>}
    </section>
  );
}
