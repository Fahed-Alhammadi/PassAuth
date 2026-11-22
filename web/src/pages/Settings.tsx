import { ManifestNotices } from "./Shell";
import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type ChangeEvent, type FormEvent, type ReactNode } from "react";
import { setShowIcons, setTheme, useShowIcons, useTheme, type Theme } from "../lib/prefs";
import { Link, Navigate, useParams } from "react-router";
import QRCode from "qrcode";
import { SignInRequestsCard } from "../components/DeviceSignIn";
import { KitActions } from "../components/KitActions";
import { PersonTrust, PinBadge, ReviewDialog, SignerTrust, SigningNotices, TrustBadge, VerifyDialog, conflictText, personLabel, signerText } from "../components/SignedSharing";
import { CodeField, MasterPasswordField, RecoveryCodesModal } from "../components/TwoStep";
import { AccountPicture, ConfirmDialog, ConfirmPassword, CopyButton, ErrorText, Icon, Modal, PasswordInput, SheetActions, StrengthMeter, toast } from "../components/ui";
import { ATTACHMENT_QUOTA_EXCEEDED, ApiError, api, friendlyError, hasErrorCode, hasFeature, usePolicies, usePublicConfig } from "../lib/api";
import { clientInfo, deviceKindInfo } from "../lib/clients";
import { sharerListedAs, sharerName, sharerShortName, type Invitation } from "../lib/invitations";
import { clientName, getDesktop, isDesktop, type DesktopAppHook, type DesktopHooks, type TimeoutSettings, type VaultTimeoutHook } from "../lib/platform";
import { MIN_MASTER_PASSWORD, clampTimeout, minPasswordLength, minutesLabel, newKeysMeetKdf, timeoutOptions } from "../lib/policies";
import { server } from "../lib/server";
import { UNEXPECTED_RESPONSE, isTrashed, readRecoveryCodes, type Role } from "../lib/types";
import {
  ASK_OWNER_TO_SIGN,
  NOT_NOW_HINT,
  NOT_YET_SIGNED,
  cleanText,
  consentText,
  firstSignedText,
  firstTimeText,
  heldInvitationText,
  ownVaultReplacedText,
  replacedSignedText,
  replacedText,
  unsignedInvitationText,
  type SignedMemberRow,
} from "../lib/signing";
import {
  KeyChangedError,
  consentAcceptable,
  consentDeclinable,
  emailText,
  invitationDeclinable,
  needsSigning,
  type Consent,
  type InvitationTrust,
  type SignerView,
} from "../lib/signed-sharing";
import { formatBytes } from "../lib/sizes";
import { makeAvatarJpeg, removeAvatar, uploadAvatar, useAvatarUrl } from "../lib/avatar";
import { createCredential, webauthnSupported } from "../lib/webauthn";
import { KEY_PAGE_FEATURE } from "../lib/key-page";
import {
  acceptConsent,
  acceptInvitation,
  changeKeys,
  createVault,
  declineConsent,
  declineInvitation,
  deleteOfflineChanges,
  deleteVault,
  fingerprint,
  forgetDevice,
  getAccount,
  getBundle,
  identityFingerprint,
  leaveVault,
  loadMembers,
  logout,
  lookupUser,
  ReviewNeededError,
  personState,
  resignVault,
  signsSharing,
  type FoundUser,
  notePolicyViolations,
  reauth,
  rememberedSecretKey,
  removeMember,
  renameVault,
  rotateVaultKey,
  sealAvatar,
  shareVault,
  sync,
  useVault,
  type ConsentVault,
  type Confirmation,
  type ReviewView,
  type Vault,
} from "../lib/vault";
import { LostChangesWarning, signOut } from "../components/OfflineChanges";
import { ActivityTab, VaultActivity } from "./Activity";
import { EmergencyTab } from "./Emergency";
import "../styles/settings.css";
import "../styles/sections.css";

// ------------------------------------------------------------------ types

export interface AccountInfo {
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
  /** Items and encrypted bytes in the vaults this account owns, trash included (servers with quotas); attachments' bytes on newer servers. */
  usage?: { item_count: number; storage_bytes: number; attachment_bytes?: number };
  /** The admin's limits for them; 0 = no limit. */
  limits?: { max_items: number; max_storage_bytes: number; max_attachment_bytes?: number };
  /** What the account still has to change for the server's policies (servers with `policies`). */
  policy_violations?: unknown;
}

export interface PasskeyInfo {
  id: string;
  name: string;
  created_at: number;
  last_used_at: number | null;
}

/** A vault member, or someone invited who hasn't accepted yet (`status` "invited"), with their signing identity. */
type Member = SignedMemberRow;

interface Session {
  id: string;
  device_id: string;
  device_name: string;
  device_kind: string;
  created_at: number;
  last_used: number;
  /** The app's `X-PassAuth-Client`, e.g. "desktop/0.7.0" (older servers and sessions don't have it). */
  client?: string | null;
}

/**
 * Settings sections, grouped by what people come for. Keys are the URL (`/settings/<key>`); emails and apps link to
 * `account`, `security`, `two-step`, `vaults`, `emergency` and `sessions`, so those keys never change.
 */
const TABS = [
  { key: "account", group: "You", label: "Account", intro: "Your name, email address, storage and fingerprint." },
  { key: "preferences", group: "You", label: "Preferences", intro: "How PassAuth looks and behaves here." },
  { key: "security", group: "Security", label: "Password and keys", intro: "Your master password, Secret Key and Emergency Kit." },
  { key: "two-step", group: "Security", label: "Two-step login", intro: "A second step when you sign in on a new device." },
  { key: "sessions", group: "Security", label: "Devices", intro: "Where you're signed in, and requests to sign in." },
  // Listed only when the server keeps an activity log (`activity_log`).
  { key: "activity", group: "Security", label: "Activity", intro: "Sign-ins and changes to your account, newest first." },
  { key: "vaults", group: "Sharing", label: "Vaults", intro: "Your vaults, the people you share them with, and invitations." },
  // Listed only when the server has emergency access (`emergency_access`); its emails link here either way.
  { key: "emergency", group: "Sharing", label: "Emergency access", intro: "People who can ask for access to your vaults if something happens to you." },
] as const;
const GROUPS = ["You", "Security", "Sharing"] as const;
type TabKey = (typeof TABS)[number]["key"];

const ROLE_LABEL: Record<Role, string> = { owner: "Owner", admin: "Admin", write: "Can edit", read: "Can view" };

// ---------------------------------------------------------------- helpers

/** Turn server and crypto errors into a sentence that says how to fix it. */
const friendly = friendlyError;

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

function safeFingerprint(publicKey: unknown): string {
  // Only a string reaches the core (anything else from the server would trap it or make its memory grow).
  if (typeof publicKey !== "string" || !publicKey) return "Unavailable";
  try {
    return fingerprint(publicKey);
  } catch {
    return "Unavailable";
  }
}

// ------------------------------------------------------------------- page

export function SettingsPage() {
  const { tab } = useParams();
  const [account, setAccount] = useState<AccountInfo | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const config = usePublicConfig();
  const activityLog = hasFeature(config, "activity_log");
  const emergency = hasFeature(config, "emergency_access");
  const waiting = useVault().invitations.length;

  const reload = useCallback(async () => {
    try {
      const a = await api<AccountInfo>("/account");
      setAccount(a);
      notePolicyViolations(a.policy_violations);
      setLoadError(null);
    } catch (e) {
      setLoadError(`Couldn't load your account settings. ${friendly(e)} Reload the page to try again.`);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  // `/settings` alone: the section list on phones, Account beside it on wider screens (CSS `.is-index`).
  if (tab !== undefined && !TABS.some((t) => t.key === tab)) return <Navigate to="/settings/account" replace />;
  const current = (tab ?? "account") as TabKey;
  const section = TABS.find((t) => t.key === current)!;

  let body: ReactNode = <p className="muted">Loading…</p>;
  if (current === "vaults") body = <VaultsTab />;
  else if (current === "sessions")
    body = (
      <>
        <SignInRequestsCard />
        <SessionsTab />
      </>
    );
  else if (current === "activity") body = <ActivityTab />;
  else if (current === "emergency") body = <EmergencyTab />;
  else if (current === "security") body = <SecurityTab />;
  else if (current === "preferences") body = <PreferencesTab />;
  else if (account) body = current === "account" ? <AccountTab account={account} reload={reload} /> : <TwoStepTab account={account} reload={reload} />;
  else if (loadError) body = <ErrorText error={loadError} />;

  const shown = TABS.filter((t) => (t.key !== "activity" || activityLog || current === t.key) && (t.key !== "emergency" || emergency || current === t.key));
  /** What the rail says next to a section, at a glance. */
  const status = (key: TabKey): ReactNode => {
    if (key === "two-step" && account) {
      return account.two_factor.length > 0 || account.passkeys.length > 0 ? (
        <span className="rail-status is-ok">On</span>
      ) : (
        <span className="rail-status is-warn">Off</span>
      );
    }
    if (key === "vaults" && waiting > 0) {
      return (
        <>
          <span className="rail-status is-count" aria-hidden="true">
            {waiting}
          </span>
          <span className="sr-only">, {waiting === 1 ? "1 invitation" : `${waiting} invitations`}</span>
        </>
      );
    }
    if (key === "account" && account && !account.email_verified) return <span className="rail-status is-warn">Verify email</span>;
    return null;
  };

  return (
    <div className="page sections-host">
      <div className={`sections${tab === undefined ? " is-index" : ""}`}>
        <nav className="sections-rail" aria-label="Settings sections">
          <h1 className="sections-rail-title">Settings</h1>
          {GROUPS.map((g) => {
            const items = shown.filter((t) => t.group === g);
            return (
              <div key={g} className="rail-group" role="group" aria-labelledby={`rail-${g}`}>
                <h2 id={`rail-${g}`} className="rail-group-title">
                  {g}
                </h2>
                <ul>
                  {items.map((t) => (
                    <li key={t.key}>
                      <Link to={`/settings/${t.key}`} aria-current={t.key === current && tab !== undefined ? "page" : undefined} className={t.key === current ? "is-current" : undefined}>
                        <span className="rail-label">{t.label}</span>
                        {status(t.key)}
                        <span className="rail-chevron" aria-hidden="true">
                          <Icon name="chevron" size={16} />
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
          <button type="button" className="btn btn-ghost rail-signout" onClick={() => void signOut()}>
            <Icon name="logout" /> Sign out
          </button>
        </nav>
        <section className="sections-content" aria-labelledby="section-title">
          <header className="section-head">
            <Link to="/settings" className="section-back">
              <Icon name="back" /> Settings
            </Link>
            <h2 id="section-title" className="section-name">
              {section.label}
            </h2>
            <p className="section-intro">{section.intro}</p>
          </header>
          <div className="settings-section">{body}</div>
        </section>
      </div>
    </div>
  );
}

// ------------------------------------------------------- shared dialogs

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

/** Settings → Account: the picture with Change / Remove (servers with `avatar` only; older ones show nothing here). */
function ProfilePicture({ name, email }: { name: string; email: string }) {
  const config = usePublicConfig();
  const url = useAvatarUrl();
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState<"set" | "remove" | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (!hasFeature(config, "avatar")) return null;

  async function pick(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setBusy("set");
    setError(null);
    try {
      // Re-drawn here as a small square JPEG: the original file and its metadata (location, camera) never leave the device.
      const jpeg = await makeAvatarJpeg(file);
      await uploadAvatar(jpeg, sealAvatar);
      toast("Picture saved");
    } catch (err) {
      setError(friendly(err));
    } finally {
      setBusy(null);
    }
  }

  async function remove() {
    setBusy("remove");
    setError(null);
    try {
      await removeAvatar();
      toast("Picture removed");
    } catch (err) {
      setError(friendly(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="stack-s">
      <div className="profile-pic">
        <AccountPicture name={name} email={email} />
        <div className="row row-wrap">
          <button type="button" className="btn btn-sm" disabled={busy !== null} onClick={() => input.current?.click()}>
            <Icon name="person" size={16} /> {busy === "set" ? "Saving…" : url ? "Change picture" : "Add picture"}
          </button>
          {url && (
            <button type="button" className="btn btn-sm btn-ghost" disabled={busy !== null} onClick={remove}>
              {busy === "remove" ? "Removing…" : "Remove"}
            </button>
          )}
          <input ref={input} type="file" accept="image/*" hidden onChange={pick} />
        </div>
      </div>
      <span className="field-hint">Only your devices can see it: it is encrypted like your vault.</span>
      <ErrorText error={error} />
    </div>
  );
}

function AccountTab({ account, reload }: { account: AccountInfo; reload: () => Promise<void> }) {
  const [name, setName] = useState(account.name);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  // Worked out from this app's own key, never taken from the server: it is what others compare a key the server gave them with.
  // With signed sharing, the identity fingerprint (user id, encryption and signing key); before, the encryption key's.
  useVault();
  const identityFp = identityFingerprint();
  const fp = identityFp ?? getAccount()?.fingerprint() ?? (typeof account.fingerprint === "string" ? account.fingerprint : null);

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
    // The account is gone: changes waiting on this device for it can never be sent.
    await deleteOfflineChanges();
    await logout();
  }

  return (
    <>
      <section className="card" aria-labelledby="profile-title">
        <h2 id="profile-title">Profile</h2>
        <ProfilePicture name={account.name} email={account.email} />
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

      <UsageCard account={account} />

      <section className="card" aria-labelledby="fp-title">
        <h2 id="fp-title">{identityFp ? "Your identity fingerprint" : "Your public key fingerprint"}</h2>
        <p className="card-text">
          When someone shares a vault with you, PassAuth shows them this fingerprint. Ask them to read it back to you, in person or over a call, and
          check that it matches exactly. A match means the vault is encrypted for you and nobody else
          {identityFp ? ", and that what you share is signed by you." : "."}
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
          <LostChangesWarning />
        </ConfirmPassword>
      )}
    </>
  );
}

// ------------------------------------------------------------ preferences

/** How PassAuth looks and behaves in this browser or app: theme, icons, and the desktop app's own settings. */
function PreferencesTab() {
  const showIcons = useShowIcons();
  const theme = useTheme();
  const desktop = getDesktop();
  return (
    <>
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

      {desktop && <AboutDesktop desktop={desktop} />}
    </>
  );
}

/** What this account stores against the server's limits; shown only when the admin set a limit. */
/** A count the server sent, or 0 for anything that isn't one (nothing it sends may break this page). */
const count = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0);

function UsageCard({ account }: { account: AccountInfo }) {
  const { usage, limits } = account;
  if (!usage || !limits) return null;
  const [items, maxItems] = [count(usage.item_count), count(limits.max_items)];
  const [stored, maxStored] = [count(usage.storage_bytes), count(limits.max_storage_bytes)];
  const [files, maxFiles] = [count(usage.attachment_bytes), count(limits.max_attachment_bytes)];
  const meters = [
    maxItems > 0 && { label: "Items", used: items, max: maxItems, text: `${items.toLocaleString()} of ${maxItems.toLocaleString()} items` },
    maxStored > 0 && { label: "Storage", used: stored, max: maxStored, text: `${formatBytes(stored)} of ${formatBytes(maxStored)}` },
    maxFiles > 0 && { label: "Attachments", used: files, max: maxFiles, text: `${formatBytes(files)} of ${formatBytes(maxFiles)}` },
  ].filter((m): m is { label: string; used: number; max: number; text: string } => !!m);
  if (meters.length === 0) return null;
  const full = meters.some((m) => m.label !== "Attachments" && m.used >= m.max);
  const filesFull = maxFiles > 0 && files >= maxFiles;
  return (
    <section className="card" aria-labelledby="usage-title">
      <h2 id="usage-title">Storage</h2>
      <p className="card-text">
        This server limits what each account can store. Everything in the vaults you own counts, the trash included; vaults others share with you
        count toward their owner's limit.
      </p>
      {meters.map((m) => {
        const pct = Math.min(100, (m.used / m.max) * 100);
        return (
          <div className="usage" key={m.label}>
            <div className="row-between">
              <span className="setting-title">{m.label}</span>
              <span className="small muted">{m.text}</span>
            </div>
            <div
              className={`meter usage-bar${m.used >= m.max ? " is-full" : pct >= 90 ? " is-near" : ""}`}
              role="progressbar"
              aria-label={m.label}
              aria-valuemin={0}
              aria-valuemax={m.max}
              aria-valuenow={Math.min(m.used, m.max)}
              aria-valuetext={m.text}
            >
              <i style={{ width: `${pct}%` }} />
            </div>
          </div>
        );
      })}
      {full && <p className="field-hint">You've reached this server's storage limit. Delete items or ask the server's admin.</p>}
      {filesFull && <p className="field-hint">{ATTACHMENT_QUOTA_EXCEEDED}</p>}
    </section>
  );
}

/**
 * Desktop app only: when the vault locks by itself, and whether it locks or signs out (the extension's options). Under
 * the server's longest vault timeout (policy) only the choices within it are offered, and a saved choice above it
 * gives way to the limit.
 */
function VaultTimeoutCard({ hook }: { hook: VaultTimeoutHook }) {
  const settings = useSyncExternalStore(hook.subscribe, hook.get);
  // The app's own record of the limit (it applies it offline too), else the server's current answer.
  const known = useSyncExternalStore(hook.subscribe, () => hook.maxMinutes?.() ?? null);
  const policyMax = usePolicies().maxVaultTimeoutMinutes;
  const max = known ?? policyMax;
  const lockShortcut = getDesktop()?.lockShortcut;
  const options = timeoutOptions(hook.options, max);
  const effective = clampTimeout(settings.vaultTimeout, max);
  const clamped = effective !== settings.vaultTimeout;
  const savedLabel = hook.options.find(([v]) => v === settings.vaultTimeout)?.[1] ?? (typeof settings.vaultTimeout === "number" ? minutesLabel(settings.vaultTimeout) : "");
  const current = String(effective);
  const help = hook.help[current] ?? (typeof effective === "number" ? hook.help.minutes : undefined);
  const unavailable = options.map(([v, label]) => [label, hook.disabledReason(v)] as const).filter(([, reason]) => reason);
  const neverActive = effective === "never" && !hook.disabledReason("never");
  return (
    <section className="card" aria-labelledby="timeout-title">
      <h2 id="timeout-title">Vault timeout</h2>
      <Setting
        as="label"
        title="Lock the vault"
        control={
          <select
            className="select"
            value={current}
            onChange={(e) => {
              const picked = options.find(([v]) => String(v) === e.target.value);
              if (picked) hook.set({ vaultTimeout: picked[0] });
            }}
          >
            {options.map(([v, label]) => (
              <option key={String(v)} value={String(v)} disabled={hook.disabledReason(v) !== null}>
                {label}
              </option>
            ))}
          </select>
        }
      >
        {!neverActive && help}
      </Setting>
      {max > 0 &&
        (clamped ? (
          <div className="alert alert-info small" role="note">
            Your server's admin allows a vault timeout of at most {minutesLabel(max)}, so the vault locks after {minutesLabel(max)} instead of "{savedLabel}".
          </div>
        ) : (
          <p className="small muted">Your server's admin allows a vault timeout of at most {minutesLabel(max)}.</p>
        ))}
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
  // The AutoFill extension may have changed its setting since the app started.
  useEffect(() => {
    void hook.refresh?.();
  }, [hook]);
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
      {hook.autofillMatchOptions && s.autofillDefaultMatch !== undefined && (
        <>
          <h3>AutoFill on this Mac</h3>
          <Setting
            as="label"
            title="Default URI match detection"
            control={
              <select className="select" value={s.autofillDefaultMatch} onChange={(e) => void hook.set({ autofillDefaultMatch: e.target.value })}>
                {hook.autofillMatchOptions.map(([v, label]) => (
                  <option key={v} value={v}>
                    {label}
                  </option>
                ))}
              </select>
            }
          >
            Used by AutoFill in Safari and apps for websites set to Default in a login.
          </Setting>
          {s.autofillSuggestAll !== undefined && (
            <Setting
              as="label"
              title="Suggest every login in Safari's AutoFill list"
              control={
                <input type="checkbox" role="switch" className="switch" checked={s.autofillSuggestAll} onChange={(e) => void hook.set({ autofillSuggestAll: e.target.checked })} />
              }
            >
              Each login is listed with its name, such as "admin · Portainer". Safari may also list logins of other sites on the same domain: check the name
              before you pick one. When this is off, logins set to Host, Exact or Starts with are under "PassAuth…".
            </Setting>
          )}
          {s.autofillFillSingleMatch !== undefined && (
            <Setting
              as="label"
              title="Fill at once when one login matches"
              control={
                <input
                  type="checkbox"
                  role="switch"
                  className="switch"
                  checked={s.autofillFillSingleMatch}
                  onChange={(e) => void hook.set({ autofillFillSingleMatch: e.target.checked })}
                />
              }
            >
              When you choose "PassAuth…" and only one login is saved for the page, it is filled without showing the list.
            </Setting>
          )}
        </>
      )}
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
  const { email, policyViolations } = useVault();
  const policies = usePolicies();
  const minLength = minPasswordLength(policies);
  const [skOn, setSkOn] = useState<boolean>(() => !!getBundle()?.secret_key_enabled);
  // The server requires a Secret Key (policy): new keys get one, and it can't be turned off.
  const skRequired = policies.requireSecretKey;
  const kdfAsked = policyViolations.includes("kdf");
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
    if (next.length < minLength) return setError(`Use at least ${minLength} characters for your new master password.`);
    if (next !== confirm) return setError("The new passwords don't match. Type the same password in both fields.");
    setBusy(true);
    try {
      const sk = await changeKeys(current, next, skOn || skRequired);
      setSkOn(!!getBundle()?.secret_key_enabled);
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
          {!skOn && skRequired && " Your server requires a Secret Key, so changing it also turns one on. It's shown once, to save in your Emergency Kit."}
        </p>
        {kdfAsked && (
          <div className="alert alert-info small" role="note">
            {newKeysMeetKdf(policies)
              ? "Your server asks for stronger encryption settings for your account. Changing your master password creates your keys again with them: you can enter your current password as the new one."
              : "Your server asks for stronger encryption settings for your account than PassAuth supports. Ask the server's admin to check the minimum key settings."}
          </div>
        )}
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
            <span className="field-hint">
              At least {minLength} characters{minLength > MIN_MASTER_PASSWORD ? ", as your server requires" : ""}. A few unrelated words are easy to remember and hard to guess.
            </span>
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
          {!(skOn && skRequired) && (
            <button type="button" className={skOn ? "btn btn-danger" : "btn"} onClick={() => setToggling(true)}>
              {skOn ? "Turn off…" : "Turn on…"}
            </button>
          )}
        </div>
        <p className="card-text">
          A Secret Key is a long random code that's combined with your master password when you sign in on a new device. Even if someone learns
          your master password, they can't open your vault without it.
        </p>
        {skRequired && (
          <p className="small muted">{skOn ? "Your server requires a Secret Key, so it can't be turned off." : "Your server asks you to turn on a Secret Key."}</p>
        )}
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

/** The server refused to turn off the account's last two-step method because it requires two-step login (policy). */
function keptLast(e: unknown): never {
  if (hasErrorCode(e, "two_step_required"))
    throw new Error("Your server requires two-step login, so your only method can't be turned off. Turn on another one first.");
  throw e;
}

function TwoStepTab({ account, reload }: { account: AccountInfo; reload: () => Promise<void> }) {
  const [codes, setCodes] = useState<string[] | null>(null);
  const [disabling, setDisabling] = useState<"totp" | "email" | null>(null);
  const [regenerating, setRegenerating] = useState(false);
  const [addingKey, setAddingKey] = useState(false);
  const [removingKey, setRemovingKey] = useState<PasskeyInfo | null>(null);
  const totpOn = account.two_factor.includes("totp");
  const emailOn = account.two_factor.includes("email");
  const anyOn = account.two_factor.length > 0;
  const lastOne = account.two_factor.length === 1;
  const lastKey = account.passkeys.length === 1 && lastOne;
  // The server requires two-step login (policy): it refuses to turn off the only method.
  const keepLast = usePolicies().requireTwoStep && lastOne;

  async function enabled(recovery: string[] | null) {
    await reload();
    if (recovery?.length) setCodes(recovery);
  }

  async function disable(password: string) {
    const token = await reauth(password);
    await api(`/account/2fa/${disabling}`, { method: "DELETE", headers: { "x-reauth-token": token }, twoStepGate: false }).catch(keptLast);
    toast(disabling === "totp" ? "Authenticator app turned off" : "Email codes turned off");
    setDisabling(null);
    await reload();
  }

  async function regenerate(password: string) {
    const token = await reauth(password);
    const r = await api("/account/2fa/recovery", { method: "POST", headers: { "x-reauth-token": token } });
    const fresh = readRecoveryCodes(r);
    if (!fresh) throw new Error(UNEXPECTED_RESPONSE);
    setRegenerating(false);
    setCodes(fresh);
    await reload();
  }

  async function removeKey(password: string) {
    if (!removingKey) return;
    const token = await reauth(password);
    await api(`/account/2fa/passkey/${encodeURIComponent(removingKey.id)}`, {
      method: "DELETE",
      headers: { "x-reauth-token": token },
      twoStepGate: false,
    }).catch(keptLast);
    toast("Security key removed");
    setRemovingKey(null);
    await reload();
  }

  return (
    <>
      <p className="card-text settings-intro">
        Two-step login asks for a code after your master password when you sign in on a new device, so a stolen password isn't enough.
      </p>

      {keepLast && (
        <div className="alert alert-info small" role="note">
          Your server requires two-step login, so your only method can't be turned off. Turn on another one first if you want to replace it.
        </div>
      )}
      <TotpCard on={totpOn} onEnabled={enabled} onDisable={keepLast ? undefined : () => setDisabling("totp")} />
      <EmailCard
        on={emailOn}
        available={account.email_enabled}
        email={account.email}
        onEnabled={enabled}
        onDisable={keepLast ? undefined : () => setDisabling("email")}
      />
      <PasskeysCard account={account} onAdd={() => setAddingKey(true)} onRemove={keepLast ? undefined : setRemovingKey} />

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

/** `onRemove` left out: the keys can't be removed (the last two-step method while the server requires one). */
export function PasskeysCard({ account, onAdd, onRemove }: { account: AccountInfo; onAdd: () => void; onRemove?: (key: PasskeyInfo) => void }) {
  const on = account.passkeys.length > 0;
  const desktop = isDesktop();
  const supported = !desktop && webauthnSupported();
  const canAdd = account.passkeys_available && supported && account.passkeys.length < 10;
  // Servers with the key page: every app can use a key to sign in (through the server's page in the browser).
  const keyPage = hasFeature(usePublicConfig(), KEY_PAGE_FEATURE);

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
              {onRemove && (
                <button type="button" className="btn btn-text btn-danger btn-sm" aria-label={`Remove ${k.name}`} onClick={() => onRemove(k)}>
                  Remove
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {!account.passkeys_available ? (
        <p className="small muted">This server's DOMAIN setting isn't its full public address, so security keys can't be set up. Ask your PassAuth administrator.</p>
      ) : desktop ? (
        <p className="small muted">{keyPage ? "Add security keys from the web vault in a browser." : "Add or use security keys from the web vault in a browser."}</p>
      ) : !supported ? (
        <p className="small muted">This browser can't use security keys here. Open the web vault over https (or localhost) in a current browser.</p>
      ) : null}
      {keyPage ? (
        <p className="small muted">
          The phone apps, browser extension and desktop app open this server's page in your browser to use a security key. Older versions of the apps
          can't, so keep your recovery codes.
        </p>
      ) : (
        <div className="alert alert-warn small" role="note">
          The phone apps, browser extension and desktop app can't use a security key for two-step login yet. If you sign in there, keep an authenticator app
          or email codes turned on as well. Recovery codes work everywhere.
        </div>
      )}
    </section>
  );
}

/** Name the key, confirm the master password, then register it with the browser's WebAuthn prompt. */
export function AddPasskeyModal({ onAdded, onClose }: { onAdded: (recovery: string[] | null) => Promise<void>; onClose: () => void }) {
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
      const r = await api("/account/2fa/passkey/register/finish", {
        body: { registration_id: start.registration_id, name: trimmed, credential },
      });
      toast("Security key added");
      await onAdded(readRecoveryCodes(r));
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


/**
 * Turn on a two-step method with the code that proves it works. The master password comes first, traded for a fresh
 * reauth token, which servers that require it check (as for removing a security key); older servers ignore it. The
 * answer's recovery codes, if this is the account's first method.
 */
async function enableTwoStep(method: "totp" | "email", code: string, password: string): Promise<string[] | null> {
  const token = await reauth(password);
  return readRecoveryCodes(await api(`/account/2fa/${method}/enable`, { body: { code }, headers: { "x-reauth-token": token } }));
}

/** `onDisable` left out: no "Turn off" (the last two-step method while the server requires one, or nothing to turn off). */
export function TotpCard({ on, onEnabled, onDisable }: { on: boolean; onEnabled: (codes: string[] | null) => Promise<void>; onDisable?: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ secret: string; uri: string }>("/account/2fa/totp/setup", { method: "POST" });
      if (typeof r?.secret !== "string" || typeof r.uri !== "string") throw new Error(UNEXPECTED_RESPONSE);
      const qr = await QRCode.toDataURL(r.uri, { margin: 1, width: 200 });
      setSetup({ secret: r.secret, qr });
      setCode("");
      setPassword("");
    } catch (e) {
      setError(friendly(e));
    } finally {
      setBusy(false);
    }
  }

  async function enable(e: FormEvent) {
    e.preventDefault();
    if (!code.trim()) return setError("Enter the 6-digit code from your authenticator app.");
    if (!password) return setError("Enter your master password to continue.");
    setBusy(true);
    setError(null);
    try {
      const recovery = await enableTwoStep("totp", code.replace(/\s/g, ""), password);
      setSetup(null);
      setPassword("");
      toast("Authenticator app turned on");
      await onEnabled(recovery);
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
          onDisable && (
            <button type="button" className="btn btn-danger" onClick={onDisable}>
              Turn off…
            </button>
          )
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
          <MasterPasswordField id="totp-password" value={password} onChange={setPassword} hint="Confirms that it's you turning on two-step login." />
          <ErrorText error={error} />
          <div className="card-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Checking code…" : "Turn on authenticator app"}
            </button>
            <button
              type="button"
              className="btn btn-text"
              onClick={() => {
                setSetup(null);
                setPassword("");
              }}
              disabled={busy}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
      {!on && !setup && <ErrorText error={error} />}
    </section>
  );
}

export function EmailCard({
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
  /** Left out: no "Turn off" (see `TotpCard`). */
  onDisable?: () => void;
}) {
  const [sent, setSent] = useState(false);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
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
    if (!password) return setError("Enter your master password to continue.");
    setBusy(true);
    setError(null);
    try {
      const recovery = await enableTwoStep("email", code.trim(), password);
      setSent(false);
      setPassword("");
      toast("Email codes turned on");
      await onEnabled(recovery);
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
          onDisable && (
            <button type="button" className="btn btn-danger" onClick={onDisable}>
              Turn off…
            </button>
          )
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
          <MasterPasswordField id="email-password" value={password} onChange={setPassword} hint="Confirms that it's you turning on two-step login." />
          <ErrorText error={error} />
          <div className="card-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Checking code…" : "Turn on email codes"}
            </button>
            <button type="button" className="btn btn-text" onClick={send} disabled={busy}>
              Send a new code
            </button>
            <button
              type="button"
              className="btn btn-text"
              onClick={() => {
                setSent(false);
                setPassword("");
              }}
              disabled={busy}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
      {!on && available && !sent && <ErrorText error={error} />}
    </section>
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
  for (const it of items) if (!isTrashed(it)) counts.set(it.vaultId, (counts.get(it.vaultId) ?? 0) + 1);

  return (
    <>
      <SigningNotices />
      <ManifestNotices />
      <InvitationsCard />
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

/** What a role lets the person who accepts do, in a sentence. */
const ROLE_SENTENCE: Partial<Record<Role, string>> = {
  read: "You'll be able to view its items.",
  write: "You'll be able to view and edit its items.",
  admin: "You'll be able to edit its items and share the vault.",
};

/** Vaults shared with the user and waiting for an answer (servers with invitations). The invitation email links here. */
function InvitationsCard() {
  const { invitations, consents } = useVault();
  const total = invitations.length + consents.length;
  if (total === 0) return null;
  return (
    <section className="card" aria-labelledby="invitations-title">
      <div className="stack-s">
        <h2 id="invitations-title">{total === 1 ? "Invitation to a shared vault" : `Invitations to shared vaults (${total})`}</h2>
        <p className="card-text">A vault shared with you appears in your apps only after you accept it.</p>
      </div>
      {invitations.map((inv) => (
        <InvitationRow key={inv.vaultId} invitation={inv} />
      ))}
      {consents.map((c) => (
        <ConsentRow key={c.id} vault={c} />
      ))}
    </section>
  );
}

/** A vault key id as shown for an unsigned vault (accepted by this key: the next sync checks it is still this one). */
function KeyIdField({ epoch }: { epoch: Consent["epoch"] }) {
  return (
    <div className="field">
      <span>Key id</span>
      <div className="fingerprint-s">{cleanText(epoch.key_id) || "Unavailable"}</div>
      <span className="field-hint">The vault is accepted with this key. If its key changes, PassAuth asks again.</span>
    </div>
  );
}

/** Who signed a replaced key, as shown: their pinned email, else only "someone listed by your server as …". */
const replacedBy = (signer: SignerView) =>
  signer.pin === "new" ? `someone listed by your server as ${emailText(signer.email) || cleanText(signer.label) || "an unknown account"}` : signer.label;

/** The warning a vault needing consent shows. */
function consentWarning(c: Consent, name: string): string {
  if (c.own) return ownVaultReplacedText(name);
  if (c.replaced) return c.signer ? replacedSignedText(name, replacedBy(c.signer)) : replacedText(name);
  if (c.firstSigned && c.signer) return firstSignedText(name, replacedBy(c.signer));
  return consentText(name);
}

/** The warning a signed invitation shows for its admission flags (own, replaced, first signed, held); null for none. */
function invitationWarning(t: InvitationTrust | undefined, name: string): string | null {
  if (t?.kind !== "signed") return null;
  if (t.own) return ownVaultReplacedText(name);
  if (t.replaced) return replacedSignedText(name, replacedBy(t.signer));
  if (t.held) return heldInvitationText(name, replacedBy(t.signer));
  if (t.firstSigned) return firstSignedText(name, replacedBy(t.signer));
  return null;
}

/** A sealed vault the server lists that the account never accepted: shown like an invitation (signed sharing). */
function ConsentRow({ vault: c }: { vault: ConsentVault }) {
  const [asking, setAsking] = useState<"accept" | "decline" | null>(null);
  // What the Accept dialog shows, captured when it opens: accepting is bound to exactly this (review L-B).
  const [shown, setShown] = useState<Consent | null>(null);
  const titleId = `consent-${c.id}`;
  const role = ROLE_LABEL[c.role] ?? c.role;
  const signer = c.consent.signer;
  const name = c.name ?? "Shared vault";
  const replaced = c.consent.replaced;
  // Signed, or (unsigned) a replaced key, or while the account's trust memory is missing: by the key id shown.
  const acceptable = consentAcceptable(c.consent);
  // Only where the core says `declinable`, and only a signed one that names its signer (rule 1: a server could make a
  // real vault look like an unsigned one waiting here; round 5 M2: never a re-join, replaced, own, first-signed or held
  // one). Otherwise "Not now": it stays locked until accepted.
  const declinable = consentDeclinable(c.consent);
  return (
    <div className="person" role="group" aria-labelledby={titleId}>
      <div className="sheet-context">
        <span className="tile" aria-hidden="true">
          <Icon name="share" />
        </span>
        <div className="grow">
          <div className="row-title" id={titleId}>
            {name}
          </div>
          <div className="row-sub">{c.consent.rejoin ? "Shared with you again" : "Added by your server"}</div>
        </div>
        <span className="badge">{role}</span>
      </div>
      <div className="alert alert-warn small" role="note">
        {consentWarning(c.consent, name)}
      </div>
      {signer ? (
        <SignerTrust signer={signer} />
      ) : replaced ? (
        <>
          <KeyIdField epoch={c.consent.epoch} />
          <span className="field-hint">Until you accept, the vault stays locked on this device. You can accept later.</span>
        </>
      ) : acceptable ? (
        <>
          <span className="badge badge-attn">{NOT_YET_SIGNED}</span>
          <KeyIdField epoch={c.consent.epoch} />
        </>
      ) : (
        <div className="alert alert-warn small" role="note">
          This vault isn't signed, so it stays locked on this device. {ASK_OWNER_TO_SIGN}
        </div>
      )}
      {c.consent.unsignedAllowed && !replaced && (
        <span className="field-hint">Until you accept, the vault stays locked on this device. If you don't recognise it, leave it for later and ask your server's admin.</span>
      )}
      {signer && !declinable && <span className="field-hint">{NOT_NOW_HINT}</span>}
      <div className="card-actions">
        {acceptable && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              setShown(c.consent);
              setAsking("accept");
            }}
          >
            Accept…
          </button>
        )}
        {declinable && (
          <button type="button" className="btn btn-text btn-danger" onClick={() => setAsking("decline")}>
            Decline…
          </button>
        )}
      </div>
      {asking === "accept" && acceptable && shown && (
        <ConfirmDialog
          title={`Accept "${name}"?`}
          subtitle={shown.signer ? signerText(shown.signer) : NOT_YET_SIGNED}
          icon="share"
          danger={false}
          action="Accept vault"
          busyAction="Accepting…"
          onConfirm={async () => {
            await acceptConsent(c.id, shown);
            toast(`"${name}" accepted`);
          }}
          onClose={() => {
            setAsking(null);
            setShown(null);
          }}
        >
          {(shown.own || shown.replaced || shown.firstSigned) && (
            <div className="alert alert-warn small" role="note">
              {consentWarning(shown, name)}
            </div>
          )}
          <p className="card-text">
            The vault and its items appear in all your apps. {ROLE_SENTENCE[c.role as Role] ?? ""} Accept only if you expected it.
          </p>
          {shown.signer ? <SignerTrust signer={shown.signer} /> : <KeyIdField epoch={shown.epoch} />}
        </ConfirmDialog>
      )}
      {asking === "decline" && declinable && (
        <ConfirmDialog
          title="Decline this vault?"
          subtitle={name}
          icon="share"
          action="Decline vault"
          busyAction="Declining…"
          onConfirm={async () => {
            await declineConsent(c.id);
            toast("Vault declined");
          }}
          onClose={() => setAsking(null)}
        >
          <p className="card-text">The vault won't appear in your apps. If it's shared with you again, PassAuth asks you again.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function InvitationRow({ invitation: inv }: { invitation: Invitation }) {
  const [asking, setAsking] = useState<"accept" | "decline" | "trust" | null>(null);
  // What the Accept dialog shows, captured when it opens: accepting is bound to exactly this (review L-B).
  const [shown, setShown] = useState<{ trust: Invitation["trust"] } | null>(null);
  // A verified signer is named by their pinned email; the server's `invited_by` only as "listed by your server as …".
  const from = sharerName(inv);
  const sharer = sharerShortName(inv);
  const listedBy = sharerListedAs(inv);
  const trust = inv.trust;
  const fp = inv.invitedBy?.publicKey ? safeFingerprint(inv.invitedBy.publicKey) : null;
  const titleId = `invitation-${inv.vaultId}`;
  const role = ROLE_LABEL[inv.role] ?? inv.role;
  // Signed sharing: only a signed invitation that passed every check can be accepted; the rest can only be declined.
  const acceptable = inv.name !== null && (trust === undefined || trust.kind === "signed");
  // A signed one only where its admission says `declinable` (round 5 M2); otherwise "Not now".
  const declinable = invitationDeclinable(trust);
  const warning = invitationWarning(trust, inv.name ?? "Shared vault");
  // The server says who sent it and gives that account's key: the fingerprint shows which key it lists, but it can't
  // prove the invitation is genuine, so it isn't presented as a check.
  const listedFor = cleanText(inv.invitedBy?.email) || sharer;
  const fingerprintBlock =
    trust?.kind === "signed" ? (
      <SignerTrust signer={trust.signer} />
    ) : (
      fp && (
        <div className="field">
          <span>Fingerprint your server lists for {listedFor}</span>
          <div className="fingerprint">{fp}</div>
        </div>
      )
    );

  return (
    <div className="person" role="group" aria-labelledby={titleId}>
      <div className="sheet-context">
        <span className="tile" aria-hidden="true">
          <Icon name="share" />
        </span>
        <div className="grow">
          <div className="row-title" id={titleId}>
            {inv.name ?? "Invitation that can't be opened"}
          </div>
          <div className="row-sub">
            {trust?.kind === "signed" ? signerText(trust.signer) : `From ${from}`}
            {inv.invitedAt ? `, ${formatDate(inv.invitedAt)}` : ""}
          </div>
          {listedBy && <div className="row-sub">{listedBy}</div>}
        </div>
        <span className="badge">{role}</span>
      </div>
      {inv.name === null ? (
        <div className="alert alert-warn small" role="note">
          Your account's keys can't open this invitation, so PassAuth can't show the vault's name. Decline it, then ask {sharer} to share the vault again.
        </div>
      ) : trust?.kind === "unsigned" ? (
        <div className="alert alert-warn small" role="note">
          {unsignedInvitationText(sharer)}
        </div>
      ) : trust?.kind === "refused" ? (
        <div className="alert alert-warn small stack-s" role="note">
          <span>{trust.reason}</span>
          {trust.changed && (
            <div>
              <button type="button" className="link" onClick={() => setAsking("trust")}>
                Compare and trust…
              </button>
            </div>
          )}
        </div>
      ) : fingerprintBlock ? (
        <>
          {warning && (
            <div className="alert alert-warn small" role="note">
              {warning}
            </div>
          )}
          {fingerprintBlock}
          <span className="field-hint">{declinable ? "Accept only invitations you expected." : NOT_NOW_HINT}</span>
        </>
      ) : (
        <div className="alert alert-warn small" role="note">
          The account that shared this vault no longer exists. Accept only invitations you expected.
        </div>
      )}
      <div className="card-actions">
        {acceptable && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              setShown({ trust });
              setAsking("accept");
            }}
          >
            Accept…
          </button>
        )}
        {declinable && (
          <button type="button" className="btn btn-text btn-danger" onClick={() => setAsking("decline")}>
            Decline…
          </button>
        )}
      </div>

      {asking === "trust" && trust?.kind === "refused" && trust.changed && (
        <VerifyDialog
          identity={trust.changed.identity}
          label={trust.changed.email}
          fingerprint={trust.changed.fingerprint}
          hash={trust.changed.hash}
          changed
          conflict={trust.changed.status === "email_conflict"}
          onClose={() => setAsking(null)}
        />
      )}
      {asking === "accept" && acceptable && inv.name !== null && shown && (
        <ConfirmDialog
          title={`Accept "${inv.name}"?`}
          subtitle={shown.trust?.kind === "signed" ? signerText(shown.trust.signer) : `Shared by ${from}`}
          icon="share"
          danger={false}
          action="Accept invitation"
          busyAction="Accepting…"
          onConfirm={async () => {
            await acceptInvitation(inv.vaultId, shown.trust);
            toast(`You joined "${inv.name}"`);
          }}
          onClose={() => {
            setAsking(null);
            setShown(null);
          }}
        >
          {invitationWarning(shown.trust, inv.name) && (
            <div className="alert alert-warn small" role="note">
              {invitationWarning(shown.trust, inv.name)}
            </div>
          )}
          <p className="card-text">
            The vault and its items appear in all your apps. {ROLE_SENTENCE[inv.role] ?? ""} The people who manage it can add and change items in it.
          </p>
          {shown.trust?.kind === "signed" ? <SignerTrust signer={shown.trust.signer} /> : fingerprintBlock}
          <p className="small muted">Accept only invitations you expected.</p>
        </ConfirmDialog>
      )}
      {asking === "decline" && declinable && (
        <ConfirmDialog
          title="Decline this invitation?"
          subtitle={inv.name ?? `From ${from}`}
          icon="share"
          action="Decline invitation"
          busyAction="Declining…"
          onConfirm={async () => {
            await declineInvitation(inv.vaultId);
            toast("Invitation declined");
          }}
          onClose={() => setAsking(null)}
        >
          <p className="card-text">
            The vault won't appear in your apps. The invitation already gave your account the vault's key, so the people who manage the vault will be asked to
            replace it.
          </p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function VaultCard({ vault, count }: { vault: Vault; count: number }) {
  const [open, setOpen] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const canManage = vault.role === "owner" || vault.role === "admin";
  // Signed sharing: a vault without a member roster yet may be shared from before; its managers are asked to sign it.
  const [unsignedShared, setUnsignedShared] = useState(false);
  const signing = signsSharing();
  useEffect(() => {
    if (!signing || !canManage || vault.rosterSeq !== 0) return setUnsignedShared(false);
    let live = true;
    loadMembers(vault.id)
      .then((a) => live && setUnsignedShared(needsSigning(a)))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [signing, canManage, vault.id, vault.rosterSeq]);

  async function leave() {
    await leaveVault(vault.id);
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
          <TrustBadge trust={vault.trust} />
          {unsignedShared && vault.trust?.kind !== "unsigned" && <span className="badge badge-attn">{NOT_YET_SIGNED}</span>}
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
              {open ? "Done" : unsignedShared ? "Sign and manage" : "Manage and share"}
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

/** What to call a member in a message: the pinned email first, else the server's name or email (cleaned). */
function memberTitle(m: Member): string {
  return personLabel(personState(m, m.email).pinnedEmail, m.email, m.name).title;
}

function VaultManager({ vault, count }: { vault: Vault; count: number }) {
  const { userId, pendingRotations } = useVault();
  const activityLog = hasFeature(usePublicConfig(), "activity_log");
  const [securing, setSecuring] = useState(false);
  const [secureError, setSecureError] = useState<string | null>(null);
  const needsRotation = pendingRotations.includes(vault.id);

  // Signed sharing: the member review the user confirms before the members are signed (the vault's first signed list,
  // re-signing, or people the signed list names who are gone). Confirming runs the change again with that review.
  const [review, setReview] = useState<{ review: ReviewView; title: string; action: string; run: (c: Confirmation) => Promise<void> } | null>(null);
  const signing = signsSharing();

  async function secure(confirmed?: Confirmation) {
    setSecuring(true);
    setSecureError(null);
    try {
      await rotateVaultKey(vault.id, { confirmed });
      toast("Vault key replaced");
    } catch (e) {
      if (e instanceof ReviewNeededError) setReview({ review: e.review, title: "Replace this vault's key?", action: "Replace vault key", run: (c) => secure(c) });
      else setSecureError(friendly(e));
    } finally {
      setSecuring(false);
    }
  }

  async function resign(confirmed?: Confirmation) {
    try {
      await resignVault(vault.id, { confirmed });
    } catch (e) {
      if (!(e instanceof ReviewNeededError)) throw e;
      setReview({ review: e.review, title: "Sign this vault?", action: "Sign vault", run: (c) => resign(c) });
      return;
    }
    toast("Vault signed");
    await reloadMembers();
  }
  const [name, setName] = useState(vault.name);
  const [renaming, setRenaming] = useState(false);
  const [renameError, setRenameError] = useState<string | null>(null);
  const [members, setMembers] = useState<Member[] | null>(null);
  const [unsigned, setUnsigned] = useState(false);
  const [membersError, setMembersError] = useState<string | null>(null);
  const [removing, setRemoving] = useState<Member | null>(null);
  const [deleting, setDeleting] = useState(false);

  const reloadMembers = useCallback(async () => {
    try {
      const answer = await loadMembers(vault.id);
      setMembers(answer.members);
      setUnsigned(needsSigning(answer));
      setMembersError(null);
    } catch (e) {
      setMembersError(`Couldn't load the members of this vault. ${friendly(e)}`);
    }
  }, [vault.id]);

  useEffect(() => {
    reloadMembers();
  }, [reloadMembers, vault.rosterSeq, vault.epoch]);

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

  async function remove(who: Member, confirmed?: Confirmation) {
    // Cancelling an invitation is a removal too: the invitee's app could open the vault key to show its name.
    const shown = memberTitle(who);
    try {
      await removeMember(vault.id, who.user_id, { confirmed });
    } catch (e) {
      if (!(e instanceof ReviewNeededError)) throw e;
      setRemoving(null);
      setReview({
        review: e.review,
        title: who.status === "invited" ? `Cancel the invitation for ${shown}?` : `Remove ${shown}?`,
        action: who.status === "invited" ? "Cancel invitation" : "Remove from vault",
        run: (c) => remove(who, c),
      });
      return;
    }
    toast(who.status === "invited" ? "Invitation cancelled" : `${shown} removed`);
    setRemoving(null);
    await reloadMembers();
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
            Someone who had this vault's key left or was removed (a member, or an emergency contact), but the key wasn't replaced yet, so they could still read
            items added from now on. Replace the key to re-encrypt every item for you and the remaining members. Earlier versions of its items are deleted.
          </span>
          <ErrorText error={secureError} />
          <div>
            <button type="button" className="btn btn-primary" onClick={() => void secure()} disabled={securing}>
              {securing ? "Replacing the key…" : "Replace vault key"}
            </button>
          </div>
        </div>
      )}
      {signing && unsigned && members && (
        <div className="alert alert-warn stack-s" role="note">
          <strong>Sign this vault</strong>
          <span>
            This vault was shared before PassAuth signed shared vaults, so the apps of the people in it can't tell its key comes from you. Check each person's
            fingerprint below, then sign it: PassAuth seals the key to each of them again with your signature and signs the list of members.
          </span>
          <div>
            <button type="button" className="btn btn-primary" onClick={() => resign().catch((e) => setMembersError(friendly(e)))}>
              Sign this vault…
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
            {members.map((m) => {
              const invited = m.status === "invited";
              const self = m.user_id === userId;
              // A known person is called by the email pinned for them; the server's only as "listed by your server as …".
              const label = signing && !self ? personLabel(personState(m, m.email).pinnedEmail, m.email, m.name) : personLabel(null, m.email, m.name);
              return (
                <div key={m.user_id} role="listitem">
                  {self ? (
                    <AccountPicture name={m.name} email={m.email} size="s" />
                  ) : (
                    <span className="avatar" aria-hidden="true">
                      {(label.title.trim()[0] ?? "?").toUpperCase()}
                    </span>
                  )}
                  <span className="grow">
                    <span className="row-title">
                      {label.title}
                      {self && <span className="muted"> (you)</span>}
                    </span>
                    {label.sub && <span className="row-sub">{label.sub}</span>}
                    {invited && (
                      <span className="row-sub">
                        Invited{m.invited_at ? ` ${formatDate(m.invited_at)}` : ""}. The vault reaches them once they accept.
                      </span>
                    )}
                    {signing ? (
                      <span className="row row-wrap">
                        <PersonTrust identity={m} email={m.email} compact />
                        {m.key_kind === "sealed" && m.share === null && <span className="badge badge-attn">{NOT_YET_SIGNED}</span>}
                      </span>
                    ) : (
                      <span className="fingerprint-s" title="Public key fingerprint">
                        {safeFingerprint(m.public_key)}
                      </span>
                    )}
                  </span>
                  {invited && <span className="badge">Invited</span>}
                  <span className="badge">{ROLE_LABEL[m.role] ?? m.role}</span>
                  {m.role !== "owner" && !self && (
                    <button
                      type="button"
                      className="btn btn-text btn-danger btn-sm"
                      aria-label={invited ? `Cancel the invitation for ${label.title}` : `Remove ${label.title}`}
                      onClick={() => setRemoving(m)}
                    >
                      {invited ? "Cancel invitation" : "Remove"}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <AddMember vault={vault} members={members ?? []} onAdded={reloadMembers} />

      {activityLog && <VaultActivity vault={vault} />}

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

      {removing && removing.status === "invited" && (
        <ConfirmDialog
          title={`Cancel the invitation for ${memberTitle(removing)}?`}
          subtitle={`To ${vault.name}`}
          icon="person"
          action="Cancel invitation"
          busyAction="Cancelling…"
          cancel="Keep invitation"
          onConfirm={() => remove(removing)}
          onClose={() => setRemoving(null)}
        >
          <p className="card-text">
            They can no longer accept it. The invitation already gave their account the vault's key, so PassAuth then replaces the key and re-encrypts every
            item.
          </p>
        </ConfirmDialog>
      )}
      {removing && removing.status !== "invited" && (
        <ConfirmDialog
          title={`Remove ${memberTitle(removing)}?`}
          subtitle={`From ${vault.name}`}
          icon="person"
          action="Remove from vault"
          busyAction="Removing…"
          onConfirm={() => remove(removing)}
          onClose={() => setRemoving(null)}
        >
          <p className="card-text">
            They lose access right away. PassAuth then replaces the vault key and re-encrypts every item, so they can't read any future changes.
            Anything they already copied or saw stays with them, so change important passwords if needed.
          </p>
        </ConfirmDialog>
      )}

      {review && (
        <ReviewDialog
          review={review.review}
          title={review.title}
          action={review.action}
          onConfirm={async (c) => {
            const run = review.run;
            setReview(null);
            await run(c);
          }}
          onClose={() => setReview(null)}
        />
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
  const [found, setFound] = useState<(FoundUser & { email: string }) | null>(null);
  const signing = signsSharing();
  // Signed sharing: their identity against the account's known keys (changed keys stop the share).
  const person = found && signing ? personState(found, found.email) : null;
  const blocked = !!person && (person.status === "changed" || person.status === "email_conflict" || person.status === "invalid");
  const [trusting, setTrusting] = useState(false);
  const [review, setReview] = useState<ReviewView | null>(null);
  const [role, setRole] = useState<Role>("read");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Servers with invitations: someone new gets an invitation and sees the vault once they accept it.
  const invitations = hasFeature(usePublicConfig(), "vault_invitations");

  async function find(e: FormEvent) {
    e.preventDefault();
    const addr = email.trim();
    if (!addr) return setError("Enter the email address of the person you want to share with.");
    setBusy(true);
    setError(null);
    setFound(null);
    try {
      const u = await lookupUser(addr);
      setFound({ ...u, email: cleanText(addr) });
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

  async function share(confirmed?: Confirmation) {
    if (!found) return;
    setBusy(true);
    setError(null);
    try {
      const before = members.find((m) => m.user_id === found.user_id);
      let status: Awaited<ReturnType<typeof shareVault>>;
      try {
        status = await shareVault(vault.id, found, role, { confirmed });
      } catch (err) {
        // The vault's first signed member list (or people who left): the user checks the members first.
        if (err instanceof ReviewNeededError) return setReview(err.review);
        throw err;
      }
      const who = personLabel(person?.pinnedEmail ?? null, found.email, found.name).title;
      if (before?.status === "invited") toast(`Invitation for ${who} changed`);
      else if (before) toast(`${who}'s access changed`);
      else if (status === "invited") toast(`Invitation sent to ${who}. "${vault.name}" reaches them once they accept.`);
      else toast(`"${vault.name}" shared with ${who}`);
      setFound(null);
      setEmail("");
      await onAdded();
    } catch (err) {
      setError(err instanceof KeyChangedError ? err.message : friendly(err));
    } finally {
      setBusy(false);
    }
  }

  const existing = found && members.find((m) => m.user_id === found.user_id);
  const foundLabel = found ? personLabel(person?.pinnedEmail ?? null, found.email, found.name) : null;
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
              {(foundLabel!.title.trim()[0] ?? "?").toUpperCase()}
            </span>
            <div className="grow">
              <div className="row-title">{foundLabel!.title}</div>
              {foundLabel!.sub && <div className="row-sub">{foundLabel!.sub}</div>}
            </div>
          </div>
          {person ? (
            <div className="field">
              <span>{person.signing ? "Their identity fingerprint" : "Their key fingerprint"}</span>
              <div className="fingerprint">{person.fingerprint ?? "Unavailable"}</div>
              <div className="row row-wrap">
                <PinBadge pin={person.status} verified={person.verified} />
              </div>
              {person.status === "changed" || person.status === "email_conflict" ? (
                <div className="alert alert-warn small stack-s" role="alert">
                  <span>
                    {person.status === "email_conflict"
                      ? conflictText(emailText(found.email))
                      : `${person.pinnedEmail || emailText(found.email)}'s keys changed. Compare their fingerprint with them before you continue.`}
                  </span>
                  {person.fingerprint && (
                    <div>
                      <button type="button" className="link" onClick={() => setTrusting(true)}>
                        Compare and trust…
                      </button>
                    </div>
                  )}
                </div>
              ) : person.status === "invalid" ? (
                <div className="alert alert-warn small" role="alert">
                  This account's keys can't be checked, so PassAuth won't share with it. Tell your PassAuth administrator.
                </div>
              ) : (
                <span className="field-hint">
                  {person.status === "new" || person.status === "upgraded" ? `${firstTimeText(found.email)} ` : ""}
                  Ask {found.name || "them"} to open Settings, then Account, and read you their fingerprint. Share only if it matches exactly. If it doesn't,
                  don't share and tell your PassAuth administrator.
                </span>
              )}
              {trusting && person.fingerprint && person.hash && (
                <VerifyDialog
                  identity={found}
                  label={person.pinnedEmail || emailText(found.email)}
                  fingerprint={person.fingerprint}
                  hash={person.hash}
                  changed
                  conflict={person.status === "email_conflict"}
                  onClose={() => setTrusting(false)}
                />
              )}
            </div>
          ) : (
            <div className="field">
              <span>Their key fingerprint</span>
              <div className="fingerprint">{safeFingerprint(found.public_key)}</div>
              <span className="field-hint">
                Ask {found.name || "them"} to open Settings, then Account, and read you their fingerprint. Share only if it matches exactly. If it doesn't,
                don't share and tell your PassAuth administrator.
              </span>
            </div>
          )}
          {existing && existing.status === "invited" && (
            <div className="alert alert-info small" role="note">
              They're already invited with {(ROLE_LABEL[existing.role] ?? existing.role).toLowerCase()} access and haven't accepted yet. Sharing again changes
              the invitation to what you choose below.
            </div>
          )}
          {existing && existing.status !== "invited" && (
            <div className="alert alert-info small" role="note">
              They already have {(ROLE_LABEL[existing.role] ?? existing.role).toLowerCase()} access. Sharing again changes their access to what you choose below.
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
            <button type="button" className="btn btn-primary" onClick={() => void share()} disabled={busy || blocked || existing?.role === "owner"}>
              {busy ? "Sharing…" : existing ? "Change access" : invitations ? "Send invitation" : "Share vault"}
            </button>
            <button type="button" className="btn btn-text" onClick={() => setFound(null)} disabled={busy}>
              Cancel
            </button>
          </div>
          {invitations && !existing && (
            <span className="field-hint">They get an invitation, by email too when the server sends email. The vault appears in their apps after they accept it.</span>
          )}
        </div>
      )}
      <ErrorText error={error} />
      {review && (
        <ReviewDialog
          review={review}
          title={`Share "${vault.name}"?`}
          action={invitations ? "Send invitation" : "Share vault"}
          onConfirm={async (c) => {
            setReview(null);
            await share(c);
          }}
          onClose={() => setReview(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- sessions

function SessionsTab() {
  const { email } = useVault();
  const [data, setData] = useState<{ current: string; sessions: Session[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmOthers, setConfirmOthers] = useState(false);
  const [forgetting, setForgetting] = useState<Session | null>(null);
  const config = usePublicConfig();
  // One request that signs out every other session; older servers sign them out one at a time below.
  const revokeOthers = hasFeature(config, "revoke_others");
  // Forget a device: all its sessions end and its next sign-in counts as new (two-step login again).
  const canForget = hasFeature(config, "forget_device");

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

  async function signOutOthers() {
    const r = await api<{ revoked?: number } | null>("/account/sessions/revoke-others", { method: "POST", body: {} });
    setConfirmOthers(false);
    const n = typeof r?.revoked === "number" ? r.revoked : null;
    toast(n === null ? "Other sessions signed out" : `${n} other ${n === 1 ? "session" : "sessions"} signed out`);
    await load();
  }

  async function forget(session: Session) {
    const r = await forgetDevice(session.device_id);
    // This device: `forgetDevice` signed this app out, and the sign-in page takes over.
    if (r.current) return toast("This device was forgotten and signed out.");
    setForgetting(null);
    toast(`${session.device_name || "Device"} forgotten`);
    await load();
  }

  const others = data?.sessions.filter((s) => s.id !== data.current) ?? [];
  const sessionsOn = (deviceId: string) => data?.sessions.filter((s) => s.device_id === deviceId).length ?? 0;
  const forgettingHere = !!forgetting && !!data?.sessions.some((s) => s.device_id === forgetting.device_id && s.id === data.current);

  return (
    <section className="card" aria-labelledby="sessions-title">
      <div className="card-head">
        <h2 id="sessions-title">Signed-in devices</h2>
        {revokeOthers && others.length > 0 && (
          <button type="button" className="btn btn-danger" disabled={busy !== null} onClick={() => setConfirmOthers(true)}>
            Sign out other sessions
          </button>
        )}
        {!revokeOthers && others.length > 1 && (
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
      <p className="card-text">
        Signing a device out ends its session. It needs your master password to sign in again.
        {canForget &&
          " Forgetting a device also ends its other sessions and makes its next sign-in count as a new device, so a remembered device has to use two-step login again."}
      </p>
      <ErrorText error={error} />
      {!data && !error && <p className="muted small">Loading devices…</p>}
      {data && (
        <div className="fields" role="list" aria-label="Signed-in devices">
          {data.sessions.map((s) => {
            const isCurrent = s.id === data.current;
            const client = clientInfo(s.client);
            return (
              <div key={s.id} role="listitem">
                <span className="tile" aria-hidden="true">
                  <Icon name={client?.icon ?? deviceKindInfo(s.device_kind).icon ?? "desktop"} />
                </span>
                <span className="grow">
                  <span className="row-title">{s.device_name || "Unknown device"}</span>
                  <span className="row-sub" title={`Last used ${formatDate(s.last_used)}`}>
                    {client?.label ?? deviceKindInfo(s.device_kind).label}. Signed in {formatDate(s.created_at)}.{" "}
                    {isCurrent ? "In use now." : `Last used ${ago(s.last_used).toLowerCase()}.`}
                  </span>
                </span>
                {isCurrent ? (
                  <span className="badge badge-ok">This device</span>
                ) : (
                  <button type="button" className="btn btn-text btn-danger btn-sm" disabled={busy !== null} aria-label={`Sign out ${s.device_name || "this device"}`} onClick={() => revoke([s.id], s.id)}>
                    {busy === s.id ? "Signing out…" : "Sign out"}
                  </button>
                )}
                {canForget && (
                  <button
                    type="button"
                    className="btn btn-text btn-danger btn-sm"
                    disabled={busy !== null}
                    aria-label={`Forget ${s.device_name || "this device"}`}
                    onClick={() => setForgetting(s)}
                  >
                    Forget…
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
      {data && others.length === 0 && <p className="small muted">You're not signed in anywhere else.</p>}
      {forgetting && (
        <ConfirmDialog
          title="Forget this device?"
          subtitle={forgetting.device_name || "Unknown device"}
          icon="logout"
          action={forgettingHere ? "Forget and sign out" : "Forget device"}
          busyAction="Forgetting…"
          onConfirm={() => forget(forgetting)}
          onClose={() => setForgetting(null)}
        >
          <p className="card-text">
            {sessionsOn(forgetting.device_id) > 1
              ? `Its ${sessionsOn(forgetting.device_id)} sessions are signed out at once.`
              : "Its session is signed out at once."}{" "}
            The next time it signs in, it counts as a new device: a remembered device has to use two-step login again, and you get an email about it.
            {forgettingHere && " This is the device you're using, so you're signed out here too."}
          </p>
        </ConfirmDialog>
      )}
      {confirmOthers && (
        <ConfirmDialog
          title="Sign out other sessions?"
          subtitle={email || undefined}
          icon="logout"
          action="Sign out other sessions"
          busyAction="Signing out…"
          onConfirm={signOutOthers}
          onClose={() => setConfirmOthers(false)}
        >
          <p className="card-text">
            Every other device and app signed in to your account is signed out at once, including any you don't recognize. Each one needs your master
            password to sign in again. This device stays signed in.
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}
