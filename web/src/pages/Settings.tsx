import { useCallback, useEffect, useState, useSyncExternalStore, type FormEvent, type ReactNode } from "react";
import { setShowIcons, setTheme, useShowIcons, useTheme, type Theme } from "../lib/prefs";
import { Link, Navigate, useParams } from "react-router";
import QRCode from "qrcode";
import { KitActions } from "../components/KitActions";
import { ActionRow, ConfirmDialog, CopyButton, ErrorText, Icon, Modal, PasswordInput, SheetActions, StrengthMeter, copySecret, toast, type IconName } from "../components/ui";
import { ApiError, api, friendlyError, usePublicConfig } from "../lib/api";
import { downloadFile } from "../lib/kit";
import { clientName, getDesktop, isDesktop, type DesktopAppHook, type DesktopHooks, type TimeoutSettings, type VaultTimeoutHook } from "../lib/platform";
import { server } from "../lib/server";
import type { Role } from "../lib/types";
import { createCredential, webauthnSupported } from "../lib/webauthn";
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
  rememberedSecretKey,
  removeMember,
  renameVault,
  rotateVaultKey,
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
  passkeys: PasskeyInfo[];
  /** False when the server's DOMAIN isn't a full address (no WebAuthn relying party). */
  passkeys_available: boolean;
}

interface PasskeyInfo {
  id: string;
  name: string;
  created_at: number;
  last_used_at: number | null;
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
const friendly = friendlyError;
const download = (filename: string, text: string) => downloadFile(filename, text);

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

const KIND_ICON: Record<string, IconName> = { web: "globe", extension: "puzzle", cli: "terminal", desktop: "desktop", mobile: "phone" };

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
          <div className="row-between">
            <h1>Settings</h1>
            <button type="button" className="btn btn-ghost" onClick={logout}>
              <Icon name="logout" /> Sign out
            </button>
          </div>
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
  subtitle,
  icon = "lock",
  children,
  action,
  busyAction = "Working…",
  danger,
  onConfirm,
  onClose,
}: {
  title: string;
  subtitle?: ReactNode;
  icon?: IconName;
  children?: ReactNode;
  action: string;
  busyAction?: string;
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
    <Modal title={title} subtitle={subtitle} icon={icon} tone={danger ? "danger" : undefined} onClose={close}>
      <form onSubmit={submit}>
        {children}
        <div className="field">
          <label htmlFor="confirm-password">Master password</label>
          <PasswordInput id="confirm-password" value={password} onChange={setPassword} autoFocus />
          <span className="field-hint">Confirms that it's you making this change.</span>
        </div>
        <ErrorText error={error} />
        <SheetActions
          quiet={
            <button type="button" className="btn btn-text" onClick={close} disabled={busy}>
              Cancel
            </button>
          }
        >
          <button type="submit" className={`btn btn-block ${danger ? "btn-danger-solid" : "btn-primary"}`} disabled={busy}>
            {busy ? busyAction : action}
          </button>
        </SheetActions>
      </form>
    </Modal>
  );
}

/** A setting on one row: what it is at the leading edge, its control at the trailing edge. */
function Setting({ title, children, control, as: Tag = "div" }: { title: ReactNode; children?: ReactNode; control: ReactNode; as?: "div" | "label" }) {
  return (
    <Tag className="setting">
      <span className="setting-text">
        <span className="setting-title">{title}</span>
        {children && <span className="setting-desc">{children}</span>}
      </span>
      {control}
    </Tag>
  );
}

const OnOff = ({ on }: { on: boolean }) => (on ? <span className="badge badge-ok">On</span> : <span className="badge">Off</span>);

// ---------------------------------------------------------------- account

function AccountTab({ account, reload }: { account: AccountInfo; reload: () => Promise<void> }) {
  const [name, setName] = useState(account.name);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const fp = account.fingerprint ?? getAccount()?.fingerprint() ?? null;
  const showIcons = useShowIcons();
  const theme = useTheme();
  const desktop = getDesktop();

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
          <div className="row row-wrap">
            <span className="wrap-anywhere">{account.email}</span>
            {account.email_verified ? <span className="badge badge-ok">Verified</span> : <span className="badge badge-warn">Not verified</span>}
          </div>
          {!account.email_verified && (
            <span className="field-hint">Others can't share vaults with you until you verify your email. Check your inbox for the verification link.</span>
          )}
        </div>
      </section>

      <section className="card" aria-labelledby="appearance-title">
        <h2 id="appearance-title">Appearance</h2>
        <Setting
          as="label"
          title="Theme"
          control={
            <select className="select" value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
              <option value="system">Same as system</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          }
        />
        <Setting as="label" title="Show website icons" control={<input type="checkbox" role="switch" className="switch" checked={showIcons} onChange={(e) => setShowIcons(e.target.checked)} />}>
          Icons are fetched by your PassAuth server, which learns the website addresses but never your vault contents. Applies to {clientName()}.
        </Setting>
      </section>

      {desktop?.vaultTimeout && <VaultTimeoutCard hook={desktop.vaultTimeout} />}
      {desktop?.app && <DesktopAppCard hook={desktop.app} />}

      <section className="card" aria-labelledby="fp-title">
        <h2 id="fp-title">Your public key fingerprint</h2>
        <p className="card-text">
          When someone shares a vault with you, PassAuth shows them this fingerprint. Ask them to read it back to you, in person or over a call, and
          check that it matches exactly. A match means the vault is encrypted for you and nobody else.
        </p>
        {fp ? (
          <div className="secret-box">
            <div className="fingerprint grow">{fp}</div>
            <CopyButton value={fp} label="Copy fingerprint" />
          </div>
        ) : (
          <p className="muted">Your fingerprint isn't available. Reload the page to try again.</p>
        )}
      </section>

      {desktop && <AboutDesktop desktop={desktop} />}

      <section className="card" aria-labelledby="danger-title">
        <div className="card-head">
          <h2 id="danger-title">Delete account</h2>
          <button type="button" className="btn btn-danger" onClick={() => setDeleting(true)}>
            Delete account…
          </button>
        </div>
        <p className="card-text">
          Permanently deletes your account, every vault you own and every item in them. People you shared those vaults with lose access too. You can't
          undo this.
        </p>
      </section>

      {deleting && (
        <ConfirmPassword
          title="Delete your account?"
          subtitle={account.email}
          icon="trash"
          action="Delete account"
          busyAction="Deleting…"
          danger
          onConfirm={deleteAccount}
          onClose={() => setDeleting(false)}
        >
          <p className="card-text">This permanently deletes the account, every vault you own and every item in them. You can't undo this.</p>
        </ConfirmPassword>
      )}
    </>
  );
}

/** Desktop app only: when the vault locks by itself, and whether it locks or signs out (the extension's options). */
function VaultTimeoutCard({ hook }: { hook: VaultTimeoutHook }) {
  const settings = useSyncExternalStore(hook.subscribe, hook.get);
  const lockShortcut = getDesktop()?.lockShortcut;
  const current = String(settings.vaultTimeout);
  const unavailable = hook.options.map(([v, label]) => [label, hook.disabledReason(v)] as const).filter(([, reason]) => reason);
  const neverActive = settings.vaultTimeout === "never" && !hook.disabledReason("never");
  return (
    <section className="card" aria-labelledby="timeout-title">
      <h2 id="timeout-title">Vault timeout</h2>
      <Setting
        as="label"
        title="Lock the vault"
        control={
          <select
            className="select"
            value={String(settings.vaultTimeout)}
            onChange={(e) => {
              const picked = hook.options.find(([v]) => String(v) === e.target.value);
              if (picked) hook.set({ vaultTimeout: picked[0] });
            }}
          >
            {hook.options.map(([v, label]) => (
              <option key={String(v)} value={String(v)} disabled={hook.disabledReason(v) !== null}>
                {label}
              </option>
            ))}
          </select>
        }
      >
        {!neverActive && hook.help[current]}
      </Setting>
      {unavailable.map(([label, reason]) => (
        <p key={label} className="small muted">
          {label}: {reason}
        </p>
      ))}
      {neverActive && (
        <div className="alert alert-error small" role="note">
          With "Never", your vault key is stored in this computer's keychain without the master password protecting it. Anyone who can use this computer account can
          open your vault.
        </div>
      )}
      <Setting
        as="label"
        title="When the time is up"
        control={
          <select className="select" value={settings.timeoutAction} onChange={(e) => hook.set({ timeoutAction: e.target.value as TimeoutSettings["timeoutAction"] })}>
            <option value="lock">Lock</option>
            <option value="logout">Sign out</option>
          </select>
        }
      >
        {settings.timeoutAction === "lock"
          ? "Locking keeps your encrypted vault here; unlock with your master password."
          : "Signing out removes the vault from this app; sign in again (with two-step login) to use it."}
        {lockShortcut && ` Lock at any time with ${lockShortcut}; that always needs the master password again.`}
      </Setting>
    </section>
  );
}

/** Desktop app only: login item, Dock icon (macOS) and background sync. */
function DesktopAppCard({ hook }: { hook: DesktopAppHook }) {
  const s = useSyncExternalStore(hook.subscribe, hook.get);
  return (
    <section className="card" aria-labelledby="app-title">
      <h2 id="app-title">This app</h2>
      <Setting
        as="label"
        title="Start PassAuth when you sign in to this computer"
        control={<input type="checkbox" role="switch" className="switch" checked={s.startAtLogin} onChange={(e) => void hook.set({ startAtLogin: e.target.checked })} />}
      >
        It starts in the {hook.platform === "macos" ? "menu bar" : "tray"} without opening the window.
      </Setting>
      {hook.platform === "macos" && (
        <Setting
          as="label"
          title="Keep the Dock icon while the window is closed"
          control={<input type="checkbox" role="switch" className="switch" checked={s.keepDock} onChange={(e) => void hook.set({ keepDock: e.target.checked })} />}
        >
          Closing the window leaves PassAuth running in the menu bar. When this is off, the Dock icon goes away until you open the window again.
        </Setting>
      )}
      <Setting
        as="label"
        title="Background sync"
        control={
          <select className="select" value={String(s.backgroundSyncMinutes)} onChange={(e) => void hook.set({ backgroundSyncMinutes: Number(e.target.value) })}>
            {hook.syncOptions.map(([m, label]) => (
              <option key={m} value={String(m)}>
                {label}
              </option>
            ))}
          </select>
        }
      >
        Changes reach this app as they happen while it's connected. On this schedule, and after the computer wakes, it also checks the server and reconnects,
        so the vault stays current if the connection dropped. Runs only while the vault is unlocked.
      </Setting>
    </section>
  );
}

/** Desktop app only: app and server versions, update check, change server. */
const LICENSE_URL = "https://github.com/Fahed-Alhammadi/PassAuth/blob/main/LICENSE";

function AboutDesktop({ desktop }: { desktop: DesktopHooks }) {
  const config = usePublicConfig();
  const [check, setCheck] = useState<{ busy?: boolean; version?: string | null; failed?: boolean }>({});

  async function checkNow() {
    setCheck({ busy: true });
    try {
      setCheck({ version: await desktop.checkForUpdates(false) });
    } catch {
      setCheck({ failed: true });
    }
  }

  return (
    <section className="card" aria-labelledby="about-title">
      <h2 id="about-title">About</h2>
      <Setting
        title={`PassAuth for desktop ${desktop.version}`}
        control={
          <button type="button" className="btn" disabled={check.busy} onClick={checkNow}>
            {check.busy ? "Checking…" : "Check for updates"}
          </button>
        }
      >
        {check.failed && "Couldn't check for updates. Try again later."}
        {check.version === null && "Up to date. Checked just now."}
        {check.version && (
          <>
            {check.version} is available.{" "}
            <button type="button" className="link" onClick={() => desktop.installUpdate()}>
              Install and restart
            </button>
          </>
        )}
      </Setting>
      <Setting
        title={server.host()}
        control={
          <button type="button" className="btn" onClick={() => desktop.changeServer()}>
            Change server…
          </button>
        }
      >
        {config?.version ? `Your server, running PassAuth server ${config.version}` : "Your server"}
      </Setting>
      <p className="small muted">
        © Fahed Alhammadi.{" "}
        <button type="button" className="link" onClick={() => desktop.openUrl(LICENSE_URL)}>
          MIT License
        </button>
      </p>
    </section>
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
  const savedKey = rememberedSecretKey(email);

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
          {skOn &&
            (savedKey
              ? " Your Secret Key stays the same."
              : ` Changing it also creates a new Secret Key, shown once, because ${clientName()} doesn't have the current one saved.`)}
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
            <span className="field-hint">At least {MIN_PASSWORD} characters. A few unrelated words are easy to remember and hard to guess.</span>
          </div>
          <div className="field">
            <label htmlFor="pw-confirm">
              Confirm new master password
            </label>
            <PasswordInput id="pw-confirm" value={confirm} onChange={setConfirm} autoComplete="new-password" />
          </div>
          <ErrorText error={error} />
          <div className="card-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Changing password…" : "Change master password"}
            </button>
            <span className="small muted">Your other devices are signed out.</span>
          </div>
        </form>
      </section>

      <section className="card" aria-labelledby="sk-title">
        <div className="card-head">
          <div className="card-title">
            <h2 id="sk-title">Secret Key</h2>
            <OnOff on={skOn} />
          </div>
          <button type="button" className={skOn ? "btn btn-danger" : "btn"} onClick={() => setToggling(true)}>
            {skOn ? "Turn off…" : "Turn on…"}
          </button>
        </div>
        <p className="card-text">
          A Secret Key is a long random code that's combined with your master password when you sign in on a new device. Even if someone learns
          your master password, they can't open your vault without it.
        </p>
        <p className="small muted">
          {!skOn
            ? "When you turn it on, you get a Secret Key to save in an Emergency Kit."
            : savedKey
              ? `${clientName(true)} remembers your Secret Key. Keep your Emergency Kit somewhere safe: you need it to sign in on any other device.`
              : `${clientName(true)} doesn't have your Secret Key saved. Use the Emergency Kit you saved when you turned it on.`}
        </p>
      </section>

      {(!skOn || savedKey) && (
        <section className="card" aria-labelledby="kit-title">
          <h2 id="kit-title">Emergency Kit</h2>
          <p className="card-text">What you need to sign in on a new device, on one page. Keep it where only you can reach it.</p>
          <KitActions email={email} secretKey={skOn ? savedKey : null} />
        </section>
      )}

      {toggling && (
        <ConfirmPassword
          title={skOn ? "Turn off your Secret Key?" : "Turn on a Secret Key?"}
          subtitle={email}
          icon="key"
          action={skOn ? "Turn off Secret Key" : "Turn on Secret Key"}
          danger={skOn}
          onConfirm={toggleSecretKey}
          onClose={() => setToggling(false)}
        >
          <p className="card-text">
            {skOn
              ? "After this, your master password alone unlocks your vault on a new device. Your current Secret Key and Emergency Kit stop working."
              : "PassAuth creates a Secret Key and shows it once. You need it, together with your master password, to sign in on other devices."}{" "}
            Your other devices are signed out.
          </p>
        </ConfirmPassword>
      )}

      {newSecretKey && <SecretKeyModal secretKey={newSecretKey} email={email} onClose={() => setNewSecretKey(null)} />}
    </>
  );
}

function SecretKeyModal({ secretKey, email, onClose }: { secretKey: string; email: string; onClose: () => void }) {
  const [saved, setSaved] = useState(false);
  // It's shown only once: Escape or a click outside must not throw it away.
  const close = useCallback(() => {
    if (saved) onClose();
  }, [saved, onClose]);

  return (
    <Modal title="Save your new Secret Key" subtitle="Shown only once. Any older Secret Key no longer works." icon="key" closable={false} onClose={close}>
      <p className="card-text">Without it, you can't sign in on a new device.</p>
      <div className="secret-box">
        <div className="secret-key grow" aria-label="Secret Key">
          {secretKey}
        </div>
        <CopyButton value={secretKey} label="Copy Secret Key" />
      </div>
      <KitActions email={email} secretKey={secretKey} />
      <label className="check">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span>I saved my Secret Key somewhere safe</span>
      </label>
      <SheetActions>
        <button type="button" className="btn btn-primary btn-block" disabled={!saved} onClick={onClose}>
          Done
        </button>
      </SheetActions>
    </Modal>
  );
}

// ---------------------------------------------------------- two-step login

function TwoStepTab({ account, reload }: { account: AccountInfo; reload: () => Promise<void> }) {
  const [codes, setCodes] = useState<string[] | null>(null);
  const [disabling, setDisabling] = useState<"totp" | "email" | null>(null);
  const [regenerating, setRegenerating] = useState(false);
  const [addingKey, setAddingKey] = useState(false);
  const [removingKey, setRemovingKey] = useState<PasskeyInfo | null>(null);
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

  async function removeKey(password: string) {
    if (!removingKey) return;
    const token = await reauth(password);
    await api(`/account/2fa/passkey/${encodeURIComponent(removingKey.id)}`, { method: "DELETE", headers: { "x-reauth-token": token } });
    toast("Security key removed");
    setRemovingKey(null);
    await reload();
  }

  const lastOne = account.two_factor.length === 1;
  const lastKey = account.passkeys.length === 1 && lastOne;

  return (
    <>
      <p className="card-text settings-intro">
        Two-step login asks for a code after your master password when you sign in on a new device, so a stolen password isn't enough.
      </p>

      <TotpCard on={totpOn} onEnabled={enabled} onDisable={() => setDisabling("totp")} />
      <EmailCard on={emailOn} available={account.email_enabled} email={account.email} onEnabled={enabled} onDisable={() => setDisabling("email")} />
      <PasskeysCard account={account} onAdd={() => setAddingKey(true)} onRemove={setRemovingKey} />

      <section className="card" aria-labelledby="rc-title">
        <div className="card-head">
          <div className="card-title">
            <h2 id="rc-title">Recovery codes</h2>
            {anyOn && <span className="badge">{account.recovery_codes_left} left</span>}
          </div>
          {anyOn && (
            <button type="button" className="btn" onClick={() => setRegenerating(true)}>
              Generate new codes…
            </button>
          )}
        </div>
        {anyOn ? (
          <>
            <p className="card-text">Use a recovery code to sign in if you lose access to your other methods. Each code works once.</p>
            {account.recovery_codes_left <= 3 && (
              <div className="alert alert-warn" role="note">
                You're running low on recovery codes. Generate new ones and store them somewhere safe.
              </div>
            )}
          </>
        ) : (
          <p className="card-text">You get recovery codes when you turn on your first two-step method.</p>
        )}
      </section>

      {disabling && (
        <ConfirmPassword
          title={disabling === "totp" ? "Turn off the authenticator app?" : "Turn off email codes?"}
          subtitle={account.email}
          icon={disabling === "totp" ? "phone" : "mail"}
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
        <ConfirmPassword title="Generate new recovery codes?" subtitle={account.email} icon="note" action="Generate new codes" onConfirm={regenerate} onClose={() => setRegenerating(false)}>
          <p className="card-text">Your current recovery codes stop working as soon as the new ones are created.</p>
        </ConfirmPassword>
      )}

      {addingKey && (
        <AddPasskeyModal
          onAdded={async (recovery) => {
            setAddingKey(false);
            await enabled(recovery);
          }}
          onClose={() => setAddingKey(false)}
        />
      )}

      {removingKey && (
        <ConfirmPassword title="Remove this security key?" subtitle={removingKey.name} icon="key" action="Remove security key" danger onConfirm={removeKey} onClose={() => setRemovingKey(null)}>
          <p className="card-text">
            {lastKey
              ? "This is your only two-step method. Removing it also deletes your recovery codes, and signing in will need only your master password."
              : "You can add it again at any time."}
          </p>
        </ConfirmPassword>
      )}

      {codes && <RecoveryCodesModal codes={codes} onClose={() => setCodes(null)} />}
    </>
  );
}

// ------------------------------------------------- security keys / passkeys

function PasskeysCard({ account, onAdd, onRemove }: { account: AccountInfo; onAdd: () => void; onRemove: (key: PasskeyInfo) => void }) {
  const on = account.passkeys.length > 0;
  const desktop = isDesktop();
  const supported = !desktop && webauthnSupported();
  const canAdd = account.passkeys_available && supported && account.passkeys.length < 10;

  return (
    <section className="card" aria-labelledby="passkeys-title">
      <div className="card-head">
        <div className="card-title">
          <h2 id="passkeys-title">Security keys and passkeys</h2>
          <OnOff on={on} />
        </div>
        <button type="button" className="btn" onClick={onAdd} disabled={!canAdd}>
          <Icon name="plus" /> Add a key…
        </button>
      </div>
      <p className="card-text">
        Confirm your sign-in by touching a hardware security key or with a passkey on your device (fingerprint, face or PIN). Nothing to type.
      </p>

      {on && (
        <div className="fields" role="list" aria-label="Your security keys">
          {account.passkeys.map((k) => (
            <div key={k.id} role="listitem">
              <span className="tile" aria-hidden="true">
                <Icon name="key" />
              </span>
              <span className="grow">
                <span className="row-title">{k.name}</span>
                <span className="row-sub" title={k.last_used_at ? formatDate(k.last_used_at) : undefined}>
                  Added {formatDate(k.created_at)}. {k.last_used_at ? `Last used ${ago(k.last_used_at).toLowerCase()}.` : "Not used yet."}
                </span>
              </span>
              <button type="button" className="btn btn-text btn-danger btn-sm" aria-label={`Remove ${k.name}`} onClick={() => onRemove(k)}>
                Remove
              </button>
            </div>
          ))}
        </div>
      )}

      {!account.passkeys_available ? (
        <p className="small muted">This server's DOMAIN setting isn't its full public address, so security keys can't be set up. Ask your PassAuth administrator.</p>
      ) : desktop ? (
        <p className="small muted">Add or use security keys from the web vault in a browser.</p>
      ) : !supported ? (
        <p className="small muted">This browser can't use security keys here. Open the web vault over https (or localhost) in a current browser.</p>
      ) : null}
      <div className="alert alert-warn small" role="note">
        The phone apps, browser extension and desktop app can't use a security key for two-step login yet. If you sign in there, keep an authenticator app
        or email codes turned on as well. Recovery codes work everywhere.
      </div>
    </section>
  );
}

/** Name the key, confirm the master password, then register it with the browser's WebAuthn prompt. */
function AddPasskeyModal({ onAdded, onClose }: { onAdded: (recovery: string[] | null) => Promise<void>; onClose: () => void }) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [step, setStep] = useState<"form" | "confirming" | "waiting" | "saving">("form");
  const [error, setError] = useState<string | null>(null);
  const busy = step !== "form";
  const close = useCallback(() => {
    if (!busy) onClose();
  }, [busy, onClose]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) return setError("Give the key a name, such as the key's model or the device it's on.");
    if (!password) return setError("Enter your master password to continue.");
    setError(null);
    try {
      setStep("confirming");
      const token = await reauth(password);
      const start = await api<{ registration_id: string; options: unknown }>("/account/2fa/passkey/register/start", {
        method: "POST",
        headers: { "x-reauth-token": token },
      });
      setStep("waiting");
      const credential = await createCredential(start.options);
      setStep("saving");
      const r = await api<{ id: string; recovery_codes: string[] | null }>("/account/2fa/passkey/register/finish", {
        body: { registration_id: start.registration_id, name: trimmed, credential },
      });
      toast("Security key added");
      await onAdded(r.recovery_codes);
    } catch (err) {
      setError(friendly(err));
      setStep("form");
    }
  }

  return (
    <Modal title="Add a security key or passkey" subtitle={server.host()} icon="key" onClose={close}>
      <form onSubmit={submit}>
        <p className="card-text">After you continue, your browser asks you to touch your security key or to use the passkey on this device.</p>
        <div className="field">
          <label htmlFor="passkey-name">Name</label>
          <input
            id="passkey-name"
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Blue key, work laptop…"
            maxLength={60}
            autoFocus
            disabled={busy}
          />
          <span className="field-hint">Helps you tell your keys apart later.</span>
        </div>
        <div className="field">
          <label htmlFor="passkey-password">Master password</label>
          <PasswordInput id="passkey-password" value={password} onChange={setPassword} />
          <span className="field-hint">Confirms that it's you adding the key.</span>
        </div>
        {step === "waiting" && (
          <div className="alert alert-info" role="status">
            Waiting for your security key or passkey…
          </div>
        )}
        <ErrorText error={error} />
        <SheetActions
          quiet={
            <button type="button" className="btn btn-text" onClick={close} disabled={busy}>
              Cancel
            </button>
          }
        >
          <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
            {step === "form" ? "Continue" : step === "confirming" ? "Confirming…" : step === "waiting" ? "Waiting for key…" : "Saving…"}
          </button>
        </SheetActions>
      </form>
    </Modal>
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
        <div className="card-title">
          <h2 id="totp-title">Authenticator app</h2>
          <OnOff on={on} />
        </div>
        {on ? (
          <button type="button" className="btn btn-danger" onClick={onDisable}>
            Turn off…
          </button>
        ) : (
          !setup && (
            <button type="button" className="btn" onClick={start} disabled={busy}>
              {busy ? "Starting setup…" : "Set up…"}
            </button>
          )
        )}
      </div>
      <p className="card-text">Get a new 6-digit code every 30 seconds from an authenticator app on your phone.</p>

      {!on && setup && (
        <form className="stack" onSubmit={enable}>
          <div className="totp-setup">
            <div className="qr">
              <img src={setup.qr} alt="QR code to add PassAuth to your authenticator app" width={200} height={200} />
            </div>
            <ol className="steps">
              <li>
                <span className="row-title">Scan the QR code with your authenticator app</span>
                <span className="row-sub">Can't scan it? Enter this setup key in the app instead:</span>
                <span className="secret-box">
                  <code className="mono wrap-anywhere">{prettySecret}</code>
                  <CopyButton value={setup.secret} label="Copy setup key" />
                </span>
              </li>
              <li>
                <span className="row-title">Enter the code the app shows</span>
                <CodeField id="totp-code" value={code} onChange={setCode} />
              </li>
            </ol>
          </div>
          <ErrorText error={error} />
          <div className="card-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Checking code…" : "Turn on authenticator app"}
            </button>
            <button type="button" className="btn btn-text" onClick={() => setSetup(null)} disabled={busy}>
              Cancel
            </button>
          </div>
        </form>
      )}
      {!on && !setup && <ErrorText error={error} />}
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
        <div className="card-title">
          <h2 id="email2fa-title">Email codes</h2>
          <OnOff on={on} />
        </div>
        {on ? (
          <button type="button" className="btn btn-danger" onClick={onDisable}>
            Turn off…
          </button>
        ) : (
          !sent &&
          available && (
            <button type="button" className="btn" onClick={send} disabled={busy}>
              {busy ? "Sending…" : "Send setup code"}
            </button>
          )
        )}
      </div>
      <p className="card-text">Get a one-time code by email at {email} when you sign in.</p>

      {!on && !available && (
        <p className="small muted">This server isn't set up to send email, so email codes aren't available. Ask your PassAuth administrator to configure email.</p>
      )}
      {!on && available && sent && (
        <form className="stack" onSubmit={enable}>
          <p className="card-text">We sent a code to {email}. Enter it below.</p>
          <CodeField id="email-code" value={code} onChange={setCode} />
          <ErrorText error={error} />
          <div className="card-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Checking code…" : "Turn on email codes"}
            </button>
            <button type="button" className="btn btn-text" onClick={send} disabled={busy}>
              Send a new code
            </button>
            <button type="button" className="btn btn-text" onClick={() => setSent(false)} disabled={busy}>
              Cancel
            </button>
          </div>
        </form>
      )}
      {!on && available && !sent && <ErrorText error={error} />}
    </section>
  );
}

function RecoveryCodesModal({ codes, onClose }: { codes: string[]; onClose: () => void }) {
  const text = codes.join("\n");
  const [saved, setSaved] = useState(false);
  const [done, setDone] = useState<{ download?: boolean; copy?: boolean }>({});
  // They're shown only once: Escape or a click outside must not throw them away.
  const close = useCallback(() => {
    if (saved) onClose();
  }, [saved, onClose]);
  return (
    <Modal title="Save your recovery codes" subtitle="Shown only once. Each code works once." icon="note" closable={false} onClose={close}>
      <p className="card-text">If you lose your phone or can't get email, a recovery code lets you sign in.</p>
      <div className="codes recovery-codes" aria-label="Recovery codes">
        {codes.map((c) => (
          <span key={c}>{c}</span>
        ))}
      </div>
      <div className="choices">
        <ActionRow
          icon="download"
          title="Download recovery codes"
          sub={`A text file with all ${codes.length} codes`}
          done={done.download ? "Downloaded. Keep the file somewhere safe." : undefined}
          onClick={() => {
            download("PassAuth recovery codes.txt", `PassAuth recovery codes\n${server.origin()}\n\nEach code works once.\n\n${text}\n`);
            setDone((d) => ({ ...d, download: true }));
          }}
        />
        <ActionRow
          icon="copy"
          title="Copy all codes"
          sub="To paste into a note you keep safe"
          done={done.copy ? "Copied" : undefined}
          onClick={async () => {
            if (await copySecret(text, "Recovery codes copied")) setDone((d) => ({ ...d, copy: true }));
          }}
        />
      </div>
      <label className="check">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span>I saved my recovery codes somewhere safe</span>
      </label>
      <SheetActions>
        <button type="button" className="btn btn-primary btn-block" disabled={!saved} onClick={onClose}>
          Done
        </button>
      </SheetActions>
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
          <button type="submit" className="btn btn-primary" disabled={busy || !name.trim()}>
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
        <div className="card-title">
          <span className="tile" aria-hidden="true">
            <Icon name={vault.kind === "sealed" ? "share" : "vault"} />
          </span>
          <div className="grow">
            <h2 id={`vault-${vault.id}`} className="wrap-anywhere">
              {vault.name}
            </h2>
            <p className="row-sub">
              {count} {count === 1 ? "item" : "items"}
              {vault.kind === "sealed" && ", shared with you"}
            </p>
          </div>
          <span className="badge">{ROLE_LABEL[vault.role]}</span>
        </div>
        <div className="card-actions">
          {vault.role !== "owner" && (
            <button type="button" className="btn btn-text btn-danger" onClick={() => setLeaving(true)}>
              Leave vault…
            </button>
          )}
          {canManage && (
            <button type="button" className="btn" aria-expanded={open} onClick={() => setOpen(!open)}>
              {open ? "Done" : "Manage and share"}
            </button>
          )}
        </div>
      </div>

      {open && canManage && <VaultManager vault={vault} count={count} />}

      {leaving && (
        <ConfirmDialog title="Leave this vault?" subtitle={vault.name} icon="share" action="Leave vault" busyAction="Leaving…" onConfirm={leave} onClose={() => setLeaving(false)}>
          <p className="card-text">
            You lose access to the {count} {count === 1 ? "item" : "items"} in this vault. To get access again, someone who manages the vault has to
            share it with you again.
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}

function VaultManager({ vault, count }: { vault: Vault; count: number }) {
  const { userId, pendingRotations } = useVault();
  const [securing, setSecuring] = useState(false);
  const [secureError, setSecureError] = useState<string | null>(null);
  const needsRotation = pendingRotations.includes(vault.id);

  async function secure() {
    setSecuring(true);
    setSecureError(null);
    try {
      await rotateVaultKey(vault.id);
      toast("Vault key replaced");
    } catch (e) {
      setSecureError(friendly(e));
    } finally {
      setSecuring(false);
    }
  }
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
      {needsRotation && (
        <div className="alert alert-warn stack-s" role="alert">
          <strong>Finish securing this vault</strong>
          <span>
            Someone left or was removed, but the vault key wasn't replaced yet, so they could still read items added from now on. Replace the key to re-encrypt
            every item for the remaining members.
          </span>
          <ErrorText error={secureError} />
          <div>
            <button type="button" className="btn btn-primary" onClick={secure} disabled={securing}>
              {securing ? "Replacing the key…" : "Replace vault key"}
            </button>
          </div>
        </div>
      )}
      <form className="inline-form" onSubmit={rename}>
        <label className="field">
          <span>Vault name</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
        </label>
        <button type="submit" className="btn" disabled={renaming || name.trim() === vault.name}>
          {renaming ? "Saving…" : "Rename"}
        </button>
      </form>
      <ErrorText error={renameError} />

      <div className="stack-s">
        <h3>Members</h3>
        <ErrorText error={membersError} />
        {members === null && !membersError && <p className="muted small">Loading members…</p>}
        {members && (
          <div className="fields" role="list" aria-label="Members">
            {members.map((m) => (
              <div key={m.user_id} role="listitem">
                <span className="avatar" aria-hidden="true">
                  {((m.name || m.email).trim()[0] ?? "?").toUpperCase()}
                </span>
                <span className="grow">
                  <span className="row-title">
                    {m.name || m.email}
                    {m.user_id === userId && <span className="muted"> (you)</span>}
                  </span>
                  {m.name && <span className="row-sub">{m.email}</span>}
                  <span className="fingerprint-s" title="Public key fingerprint">
                    {safeFingerprint(m.public_key)}
                  </span>
                </span>
                <span className="badge">{ROLE_LABEL[m.role] ?? m.role}</span>
                {m.role !== "owner" && m.user_id !== userId && (
                  <button type="button" className="btn btn-text btn-danger btn-sm" aria-label={`Remove ${m.name || m.email}`} onClick={() => setRemoving(m)}>
                    Remove
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <AddMember vault={vault} members={members ?? []} onAdded={loadMembers} />

      {vault.role === "owner" && (
        <Setting
          title="Delete this vault"
          control={
            <button type="button" className="btn btn-danger" onClick={() => setDeleting(true)}>
              Delete vault…
            </button>
          }
        >
          Deletes the vault and every item in it, for you and everyone it's shared with.
        </Setting>
      )}

      {removing && (
        <ConfirmDialog
          title={`Remove ${removing.name || removing.email}?`}
          subtitle={`From ${vault.name}`}
          icon="person"
          action="Remove from vault"
          busyAction="Removing…"
          onConfirm={remove}
          onClose={() => setRemoving(null)}
        >
          <p className="card-text">
            They lose access right away. PassAuth then replaces the vault key and re-encrypts every item, so they can't read any future changes.
            Anything they already copied or saw stays with them, so change important passwords if needed.
          </p>
        </ConfirmDialog>
      )}

      {deleting && (
        <ConfirmDialog
          title="Delete this vault?"
          subtitle={`${vault.name}, ${count} ${count === 1 ? "item" : "items"}`}
          icon="trash"
          action="Delete vault"
          busyAction="Deleting…"
          confirmText={vault.name}
          onConfirm={destroy}
          onClose={() => setDeleting(false)}
        >
          <p className="card-text">This permanently deletes the vault and its items for everyone who has access. You can't undo this.</p>
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
          <span>Email address of the person</span>
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
          <div className="sheet-context">
            <span className="avatar" aria-hidden="true">
              {((found.name || found.email).trim()[0] ?? "?").toUpperCase()}
            </span>
            <div className="grow">
              <div className="row-title">{found.name || found.email}</div>
              {found.name && <div className="row-sub">{found.email}</div>}
            </div>
          </div>
          <div className="field">
            <span>Their key fingerprint</span>
            <div className="fingerprint">{safeFingerprint(found.public_key)}</div>
            <span className="field-hint">
              Ask {found.name || "them"} to open Settings, then Account, and read you their fingerprint. Share only if it matches exactly. If it doesn't,
              don't share and tell your PassAuth administrator.
            </span>
          </div>
          {existing && (
            <div className="alert alert-info small" role="note">
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
          <div className="card-actions">
            <button type="button" className="btn btn-primary" onClick={share} disabled={busy || existing?.role === "owner"}>
              {busy ? "Sharing…" : "Share vault"}
            </button>
            <button type="button" className="btn btn-text" onClick={() => setFound(null)} disabled={busy}>
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
      toast(ids.length === 1 ? "Device signed out" : `${ids.length} devices signed out`);
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
            {busy === "all" ? "Signing out…" : "Sign out all other devices"}
          </button>
        )}
      </div>
      <p className="card-text">Signing a device out ends its session. It needs your master password to sign in again.</p>
      <ErrorText error={error} />
      {!data && !error && <p className="muted small">Loading devices…</p>}
      {data && (
        <div className="fields" role="list" aria-label="Signed-in devices">
          {data.sessions.map((s) => {
            const isCurrent = s.id === data.current;
            return (
              <div key={s.id} role="listitem">
                <span className="tile" aria-hidden="true">
                  <Icon name={KIND_ICON[s.device_kind] ?? "desktop"} />
                </span>
                <span className="grow">
                  <span className="row-title">{s.device_name || "Unknown device"}</span>
                  <span className="row-sub" title={`Last used ${formatDate(s.last_used)}`}>
                    {kindLabel(s.device_kind)}. Signed in {formatDate(s.created_at)}. {isCurrent ? "In use now." : `Last used ${ago(s.last_used).toLowerCase()}.`}
                  </span>
                </span>
                {isCurrent ? (
                  <span className="badge badge-ok">This device</span>
                ) : (
                  <button type="button" className="btn btn-text btn-danger btn-sm" disabled={busy !== null} aria-label={`Sign out ${s.device_name || "this device"}`} onClick={() => revoke([s.id], s.id)}>
                    {busy === s.id ? "Signing out…" : "Sign out"}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
      {data && others.length === 0 && <p className="small muted">You're not signed in anywhere else.</p>}
    </section>
  );
}
