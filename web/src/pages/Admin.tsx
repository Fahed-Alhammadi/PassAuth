import { Fragment, useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import { Wordmark } from "../components/Logo";
import { CodeField, RecoveryCodesModal } from "../components/TwoStep";
import { ConfirmDialog, CopyButton, ErrorText, Icon, Modal, PasswordInput, SheetActions, toast } from "../components/ui";
import { EVENT_TYPES, type ActivityEvent, type DescribeContext } from "../lib/activity";
import { hasFeature, usePublicConfig } from "../lib/api";
import { clientId } from "../lib/platform";
import { formatBytes } from "../lib/sizes";
import { EventList } from "./Activity";
import "../styles/tools.css";

const TOKEN_KEY = "pa.admin";

interface Overview {
  version: string;
  users: number;
  vaults: number;
  items: number;
  /**
   * The least free space, in bytes, on the disks that hold the database and the attachment files (null when there is
   * none to measure; older servers omit it). Below the `min_free_disk_mb` reserve the server stores nothing new.
   */
  disk_free_bytes?: number | null;
  config: {
    domain: string;
    database: "sqlite" | "postgresql";
    signups_allowed: boolean;
    signups_domains: string[] | string | null;
    signups_verify: boolean;
    smtp_enabled: boolean;
    admin_login: "password" | "token";
    admin_2fa: boolean;
    admin_networks: boolean;
  };
}

interface TwoStep {
  enabled: boolean;
  recovery_codes_left: number;
}

type LoginMode = { mode: "password" | "token" | "off"; weak_password: boolean };

type SmtpSecurity = "starttls" | "force_tls" | "off";

interface Smtp {
  host: string;
  port: number;
  security: SmtpSecurity;
  username: string;
  password_set: boolean;
  from: string;
  from_name: string;
}

/** Accepted values of a limit (`GET /admin/settings` `ranges`). */
interface LimitRange {
  min: number;
  max: number;
  default: number;
}

interface Settings {
  log_level: string;
  log_levels: string[];
  icons: boolean;
  signups_verify: boolean;
  smtp: Smtp | null;
  /** Days items stay in the trash before they are deleted for good; 0 = never (older servers omit it). */
  trash_days?: number;
  /** Password health may ask Have I Been Pwned (older servers omit it). */
  breach_check?: boolean;
  /** Range and default of every limit by name; the limits' values are fields of the same name (older servers omit both). */
  ranges?: Record<string, LimitRange>;
  /** Default of every on/off setting by name (Send, account policies); their values are booleans of the same name. */
  switches?: Record<string, { default: boolean }>;
  [limit: string]: unknown;
}

interface User {
  id: string;
  email: string;
  name: string;
  email_verified: number;
  disabled: number;
  created_at: number;
  last_seen: number | null;
  /** Items in the vaults the user owns (older name of `item_count`). */
  items: number;
  /** What counts against the quotas: items and bytes (encrypted) in the vaults the user owns, trash included (older servers omit them). */
  item_count?: number;
  storage_bytes?: number;
  two_factor: number;
}

interface Invite {
  email: string;
  created_at: number;
  expires_at: number;
}

class AdminError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function loadToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

function saveToken(t: string | null) {
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: token lasts until reload */
  }
}

function sentence(s: string) {
  const t = s.trim();
  if (!t) return t;
  const up = t[0].toUpperCase() + t.slice(1);
  return /[.!?]$/.test(up) ? up : `${up}.`;
}

async function adminFetch<T = any>(token: string, path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const { body, method = body === undefined ? "GET" : "POST" } = opts;
  let res: Response;
  try {
    res = await fetch(`/api/admin${path}`, {
      method,
      headers: {
        "x-passauth-client": clientId(),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new AdminError(0, "Could not reach the PassAuth server. Check that it is running and that this device is online, then try again.");
  }
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON error page from a proxy */
  }
  if (!res.ok) {
    const msg =
      res.status === 401
        ? "Your admin session has ended."
        : res.status === 429
          ? "Too many attempts from this address. Wait a minute, then try again."
          : json?.message
            ? sentence(String(json.message))
            : `The server answered with status ${res.status}. Check the server logs for details.`;
    throw new AdminError(res.status, msg);
  }
  return json as T;
}

const TURNED_OFF =
  "The admin panel is turned off. To turn it on, set PASSAUTH_ADMIN_USERNAME and PASSAUTH_ADMIN_PASSWORD in the server's .env file, then run docker compose up -d.";
const WEAK_PASSWORD =
  "The admin panel is turned off because PASSAUTH_ADMIN_PASSWORD in the server's .env file is still the example or shorter than 12 characters. Set a longer password, then run docker compose up -d.";
const SESSION_ENDED = "Your admin session has ended. Sign in again to continue.";

function formatDate(t: number) {
  return new Date(t * 1000).toLocaleDateString(undefined, { dateStyle: "medium" });
}

function formatDateTime(t: number) {
  return new Date(t * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function relative(t: number) {
  const diff = t - Date.now() / 1000;
  const abs = Math.abs(diff);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (abs < 60) return "Just now";
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  if (abs < 30 * 86400) return rtf.format(Math.round(diff / 86400), "day");
  return formatDate(t);
}

function signupText(c: Overview["config"]) {
  if (!c.signups_allowed) return "Invite only";
  const domains = Array.isArray(c.signups_domains) ? c.signups_domains : c.signups_domains ? String(c.signups_domains).split(",") : [];
  const list = domains.map((d) => d.trim()).filter(Boolean);
  return list.length ? `Open to ${list.join(", ")}` : "Open to anyone";
}

// ------------------------------------------------------------------- page

export function AdminPage() {
  const [token, setToken] = useState(loadToken);
  const [fatal, setFatal] = useState<string | null>(null);

  useEffect(() => {
    document.title = "Administration - PassAuth";
  }, []);

  const signOut = useCallback((message: string | null = null) => {
    const old = loadToken();
    if (old) adminFetch(old, "/logout", { body: {} }).catch(() => {});
    saveToken(null);
    setToken("");
    setFatal(message);
  }, []);

  return (
    <div className="admin">
      <header className="admin-header">
        <div className="title">
          <Wordmark />
          <span className="muted">Server administration</span>
        </div>
        {token && (
          <button type="button" className="btn btn-text" onClick={() => signOut()}>
            <Icon name="logout" /> Sign out
          </button>
        )}
      </header>
      {token ? (
        <Dashboard token={token} onAuthLost={signOut} />
      ) : (
        <SignInForm
          initialError={fatal}
          onSignedIn={(t) => {
            saveToken(t);
            setFatal(null);
            setToken(t);
          }}
        />
      )}
    </div>
  );
}

// ----------------------------------------------------------- sign-in form

function SignInForm({ initialError, onSignedIn }: { initialError: string | null; onSignedIn: (token: string) => void }) {
  const [mode, setMode] = useState<LoginMode | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(initialError);
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const [code, setCode] = useState("");

  const loadMode = useCallback(async () => {
    try {
      setMode(await adminFetch<LoginMode>("", "/login"));
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  useEffect(() => {
    loadMode();
  }, [loadMode]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!mode) return;
    const byPassword = mode.mode === "password";
    if (byPassword && (!username.trim() || !password)) return setError("Enter the admin user name and password from the server's .env file.");
    if (!byPassword && !password.trim()) return setError("Enter the admin token from the server's .env file.");
    setBusy(true);
    setError(null);
    try {
      const res = await adminFetch<{ token?: string; two_factor?: boolean; pending?: string }>("", "/login", {
        body: byPassword ? { username: username.trim(), password } : { token: password.trim() },
      });
      if (res.two_factor && res.pending) {
        setPending(res.pending);
        setCode("");
      } else if (res.token) onSignedIn(res.token);
    } catch (err) {
      if (err instanceof AdminError && err.status === 401) setError(byPassword ? "That user name or password is not right." : "That admin token is not valid.");
      else if (err instanceof AdminError && err.status === 404) setError(TURNED_OFF);
      else setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    if (!pending) return;
    if (!code.trim()) return setError("Enter the code from your authenticator app, or a recovery code.");
    setBusy(true);
    setError(null);
    try {
      const res = await adminFetch<{ token: string }>("", "/login/2fa", { body: { pending, code: code.trim() } });
      onSignedIn(res.token);
    } catch (err) {
      setError((err as Error).message);
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  function back() {
    setPending(null);
    setCode("");
    setPassword("");
    setError(null);
  }

  const off = mode?.mode === "off";
  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <h1>Server administration</h1>
          <p className="muted">Manage users, invitations and email for this PassAuth server.</p>
        </div>
        {!mode ? (
          <div className="auth-panel stack">
            {error ? (
              <>
                <ErrorText error={error} />
                <SheetActions>
                  <button type="button" className="btn btn-block" onClick={() => loadMode()}>
                    Try again
                  </button>
                </SheetActions>
              </>
            ) : (
              <p className="muted" role="status">
                Loading…
              </p>
            )}
          </div>
        ) : off ? (
          <div className="auth-panel stack">
            <div className="alert alert-info" role="note">
              {mode.weak_password ? WEAK_PASSWORD : TURNED_OFF}
            </div>
          </div>
        ) : pending ? (
          <form className="auth-panel stack" onSubmit={submitCode}>
            <p className="card-text">Enter the 6-digit code from your authenticator app. If you don't have your phone, enter one of your recovery codes.</p>
            <CodeField id="admin-code" label="Code" value={code} onChange={setCode} autoFocus />
            <ErrorText error={error} />
            <SheetActions>
              <button type="submit" className="btn btn-accent btn-block" disabled={busy}>
                {busy ? "Checking code…" : "Sign in"}
              </button>
              <button type="button" className="btn btn-text btn-block" onClick={back} disabled={busy}>
                Back
              </button>
            </SheetActions>
          </form>
        ) : (
          <form className="auth-panel stack" onSubmit={submit}>
            {mode.mode === "password" ? (
              <>
                <div className="field">
                  <label htmlFor="admin-user">User name</label>
                  <input
                    id="admin-user"
                    className="input"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="username"
                    autoCapitalize="none"
                    spellCheck={false}
                    autoFocus
                  />
                </div>
                <div className="field">
                  <label htmlFor="admin-password">Password</label>
                  <PasswordInput id="admin-password" value={password} onChange={setPassword} autoComplete="current-password" />
                </div>
              </>
            ) : (
              <div className="field">
                <label htmlFor="admin-token">Admin token</label>
                <PasswordInput id="admin-token" value={password} onChange={setPassword} autoComplete="off" autoFocus />
                <span className="field-hint">The token you set in ADMIN_TOKEN, not a user password. You stay signed in only in this tab.</span>
              </div>
            )}
            <ErrorText error={error} />
            <SheetActions>
              <button type="submit" className="btn btn-accent btn-block" disabled={busy}>
                {busy ? "Signing in…" : "Sign in"}
              </button>
            </SheetActions>
          </form>
        )}
      </div>
    </main>
  );
}

// -------------------------------------------------------------- dashboard

function Dashboard({ token, onAuthLost }: { token: string; onAuthLost: (message: string | null) => void }) {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [users, setUsers] = useState<User[] | null>(null);
  const [invites, setInvites] = useState<Invite[] | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [twoStep, setTwoStep] = useState<TwoStep | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  // Servers with the activity log: the Activity card, and "Show activity" for each user.
  const activityLog = hasFeature(usePublicConfig(), "activity_log");
  const [activityUser, setActivityUser] = useState("");

  /** Run an admin call; a 401 or 404 here means the token or panel is gone. */
  const call = useCallback(
    async <T,>(path: string, opts?: { method?: string; body?: unknown }): Promise<T> => {
      try {
        return await adminFetch<T>(token, path, opts);
      } catch (e) {
        if (e instanceof AdminError && e.status === 401) onAuthLost(SESSION_ENDED);
        throw e;
      }
    },
    [token, onAuthLost],
  );

  const load = useCallback(async () => {
    try {
      const [o, u, i, st, ts] = await Promise.all([
        call<Overview>("/overview"),
        call<{ users: User[] }>("/users"),
        call<{ invites: Invite[] }>("/invites"),
        call<Settings>("/settings"),
        call<TwoStep>("/2fa"),
      ]);
      setTwoStep(ts);
      setOverview(o);
      setUsers(u.users);
      setInvites(i.invites);
      setSettings(st);
      setLoadError(null);
    } catch (e) {
      if (e instanceof AdminError && e.status === 404) return onAuthLost(TURNED_OFF);
      if (!(e instanceof AdminError && e.status === 401)) setLoadError((e as Error).message);
    }
  }, [call, onAuthLost]);

  useEffect(() => {
    load();
  }, [load]);

  if (!overview || !users || !invites || !settings || !twoStep) {
    return (
      <main className="admin-main">
        {loadError ? (
          <div className="stack">
            <ErrorText error={loadError} />
            <div className="row">
              <button type="button" className="btn" onClick={load}>
                Try again
              </button>
            </div>
          </div>
        ) : (
          <p className="muted" role="status">
            Loading server details…
          </p>
        )}
      </main>
    );
  }

  return (
    <main className="admin-main">
      <OverviewCard o={overview} />
      <SignupsCard config={overview.config} call={call} reload={load} />
      <UsersCard
        users={users}
        call={call}
        reload={load}
        onShowActivity={
          activityLog
            ? (id) => {
                setActivityUser(id);
                document.getElementById("admin-activity")?.scrollIntoView({ behavior: "smooth", block: "start" });
              }
            : undefined
        }
      />
      {activityLog && <ActivityCard users={users} call={call} user={activityUser} onUser={setActivityUser} />}
      <InvitesCard invites={invites} smtp={overview.config.smtp_enabled} domain={overview.config.domain} call={call} reload={load} />
      <SettingsCard settings={settings} call={call} reload={load} />
      {settings.ranges && (
        <LimitsCard settings={settings} call={call} reload={load} withoutTwoStep={users.filter((u) => !u.disabled && !u.two_factor).length} />
      )}
      <EmailCard smtp={settings.smtp} call={call} reload={load} />
      <AdminSecurityCard twoStep={twoStep} networks={overview.config.admin_networks} call={call} reload={load} />
    </main>
  );
}

type Call = <T>(path: string, opts?: { method?: string; body?: unknown }) => Promise<T>;

function OverviewCard({ o }: { o: Overview }) {
  const c = o.config;
  return (
    <section className="stack" aria-labelledby="ov-title">
      <div className="row-between">
        <h1 id="ov-title">Overview</h1>
        <span className="small muted">PassAuth server version {o.version}</span>
      </div>
      {c.admin_login === "token" && (
        <div className="alert alert-info" role="note">
          You sign in with ADMIN_TOKEN. To sign in with a user name and password instead, set PASSAUTH_ADMIN_USERNAME and PASSAUTH_ADMIN_PASSWORD in the
          server's .env file and run <code className="mono">docker compose up -d</code>. ADMIN_TOKEN can then be removed.
        </div>
      )}
      <div className="stat-grid">
        <div className="stat">
          <span className="num">{o.users.toLocaleString()}</span>
          <span className="lbl">{o.users === 1 ? "User" : "Users"}</span>
        </div>
        <div className="stat">
          <span className="num">{o.vaults.toLocaleString()}</span>
          <span className="lbl">{o.vaults === 1 ? "Vault" : "Vaults"}</span>
        </div>
        <div className="stat">
          <span className="num">{o.items.toLocaleString()}</span>
          <span className="lbl">{o.items === 1 ? "Item" : "Items"}</span>
        </div>
      </div>
      <div className="card">
        <h2>Configuration</h2>
        <dl className="facts">
          <div>
            <dt>Domain</dt>
            <dd className="wrap-anywhere">{c.domain}</dd>
          </div>
          <div>
            <dt>Database</dt>
            <dd>{c.database === "postgresql" ? "PostgreSQL" : "SQLite"}</dd>
          </div>
          <div>
            <dt>Sign-ups</dt>
            <dd>{signupText(c)}</dd>
          </div>
          <div>
            <dt>Email verification on sign-up</dt>
            <dd>{c.signups_verify ? "Required" : "Not required"}</dd>
          </div>
          <div>
            <dt>Email (SMTP)</dt>
            <dd>{c.smtp_enabled ? <span className="badge badge-ok">On</span> : <span className="badge">Off</span>}</dd>
          </div>
          <div>
            <dt>Admin sign-in</dt>
            <dd>
              {c.admin_login === "password" ? "User name and password" : "Admin token"}
              {c.admin_2fa ? " + code" : ""}
            </dd>
          </div>
          {typeof o.disk_free_bytes === "number" && Number.isFinite(o.disk_free_bytes) && (
            <div>
              <dt>Free disk space</dt>
              <dd>{formatBytes(Math.max(0, o.disk_free_bytes))}</dd>
            </div>
          )}
        </dl>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- sign-ups

function SignupsCard({ config, call, reload }: { config: Overview["config"]; call: Call; reload: () => Promise<void> }) {
  const current = Array.isArray(config.signups_domains) ? config.signups_domains : config.signups_domains ? String(config.signups_domains).split(",") : [];
  const [allowed, setAllowed] = useState(config.signups_allowed);
  const [domains, setDomains] = useState(current.join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const list = domains
    .split(/[\s,]+/)
    .map((d) => d.trim())
    .filter(Boolean);
  const changed = allowed !== config.signups_allowed || list.join(",") !== current.join(",");

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call("/settings/signups", { method: "PUT", body: { allowed, domains: list } });
      await reload();
      toast(allowed ? "Sign-ups are open" : "Sign-ups are closed");
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="signups-title">
      <h2 id="signups-title">Sign-ups</h2>
      <form className="stack" onSubmit={save}>
        <label className="check">
          <input type="checkbox" checked={allowed} onChange={(e) => setAllowed(e.target.checked)} />
          <span>
            Allow new accounts to sign up
            <span className="field-hint block">When off, only people you invite below can create an account. Existing accounts are not affected.</span>
          </span>
        </label>
        {allowed && (
          <label className="field">
            <span>Only these email domains (optional)</span>
            <input className="input" value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="example.com, example.org" spellCheck={false} />
            <span className="field-hint">Leave empty to allow any email address. Separate domains with commas.</span>
          </label>
        )}
        <ErrorText error={error} />
        <div className="card-actions">
          <button type="submit" className="btn btn-primary" disabled={busy || !changed}>
            {busy ? "Saving…" : "Save sign-up settings"}
          </button>
          <span className="small muted">Takes effect immediately and overrides SIGNUPS_ALLOWED and SIGNUPS_DOMAINS_WHITELIST from the server configuration.</span>
        </div>
      </form>
    </section>
  );
}

// ------------------------------------------------------------------ users

function UsersCard({
  users,
  call,
  reload,
  onShowActivity,
}: {
  users: User[];
  call: Call;
  reload: () => Promise<void>;
  /** Show the Activity card for this user (servers with the activity log). */
  onShowActivity?: (userId: string) => void;
}) {
  // Servers with quotas report each user's storage.
  const storage = users.some((u) => typeof u.storage_bytes === "number");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const [resetting, setResetting] = useState<User | null>(null);
  const [managing, setManaging] = useState<string | null>(null);

  async function act(u: User, path: string, done: string) {
    setBusy(u.id);
    setError(null);
    try {
      await call(`/users/${encodeURIComponent(u.id)}${path}`, { method: "POST" });
      toast(done);
      await reload();
    } catch (e) {
      if (e instanceof AdminError && e.status === 404) {
        setError(`${u.email} no longer exists. The list has been refreshed.`);
        await reload();
      } else if (!(e instanceof AdminError && e.status === 401)) {
        setError((e as Error).message);
      }
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="card" aria-labelledby="users-title">
      <div className="card-head">
        <h2 id="users-title">Users</h2>
        <span className="small muted">{users.length === 1 ? "1 account" : `${users.length.toLocaleString()} accounts`}</span>
      </div>
      <ErrorText error={error} />
      {users.length === 0 ? (
        <p className="muted">No one has created an account yet. Invite someone below.</p>
      ) : (
        <div className="table-wrap">
          <table className="table users-table">
            <thead>
              <tr>
                <th scope="col">User</th>
                <th scope="col">Two-step login</th>
                <th scope="col" className="col-wide">
                  Items
                </th>
                {storage && (
                  <th scope="col" className="col-wide">
                    Storage
                  </th>
                )}
                <th scope="col" className="col-wide">
                  Last seen
                </th>
                <th scope="col">Status</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const open = managing === u.id;
                return (
                  <Fragment key={u.id}>
                    <tr className={open ? "is-open" : undefined}>
                      <td>
                        <div className="user-cell">
                          <span className="avatar" aria-hidden="true">
                            {((u.name || u.email).trim()[0] ?? "?").toUpperCase()}
                          </span>
                          <div className="grow">
                            <div className="row-title">{u.name || u.email}</div>
                            {u.name && <div className="row-sub">{u.email}</div>}
                            {!u.email_verified && <div className="row-sub">Email not verified</div>}
                          </div>
                        </div>
                      </td>
                      <td>{u.two_factor ? <span className="badge badge-ok">On</span> : <span className="badge">Off</span>}</td>
                      <td className="col-wide num">{(u.item_count ?? u.items).toLocaleString()}</td>
                      {storage && (
                        <td className="col-wide num" title="Encrypted size of the items in the vaults this user owns, trash included">
                          {typeof u.storage_bytes === "number" ? formatBytes(u.storage_bytes) : ""}
                        </td>
                      )}
                      <td className="col-wide" title={u.last_seen ? formatDateTime(u.last_seen) : undefined}>
                        {u.last_seen ? relative(u.last_seen) : <span className="muted">Never</span>}
                      </td>
                      <td>{u.disabled ? <span className="badge badge-warn">Disabled</span> : <span className="badge badge-ok">Active</span>}</td>
                      <td className="actions">
                        <button type="button" className="btn btn-text btn-sm" aria-expanded={open} aria-label={`Manage ${u.email}`} onClick={() => setManaging(open ? null : u.id)}>
                          {open ? "Done" : "Manage"}
                        </button>
                      </td>
                    </tr>
                    {open && (
                      <tr className="row-detail">
                        <td colSpan={storage ? 7 : 6}>
                          <div className="card-actions">
                            {u.disabled ? (
                              <button type="button" className="btn btn-sm" disabled={busy === u.id} onClick={() => act(u, "/enable", `${u.email} can sign in again`)}>
                                Allow sign-in
                              </button>
                            ) : (
                              <button
                                type="button"
                                className="btn btn-sm"
                                disabled={busy === u.id}
                                title="Block sign-in and end all sessions"
                                onClick={() => act(u, "/disable", `${u.email} is disabled and signed out`)}
                              >
                                Disable account
                              </button>
                            )}
                            <button type="button" className="btn btn-sm" disabled={busy === u.id} onClick={() => act(u, "/sessions/revoke", `${u.email} is signed out on every device`)}>
                              Sign out everywhere
                            </button>
                            {onShowActivity && (
                              <button type="button" className="btn btn-sm" onClick={() => onShowActivity(u.id)}>
                                Show activity
                              </button>
                            )}
                            {u.two_factor > 0 && (
                              <button type="button" className="btn btn-sm" disabled={busy === u.id} onClick={() => setResetting(u)}>
                                Reset two-step login…
                              </button>
                            )}
                            <button type="button" className="btn btn-sm btn-text btn-danger" disabled={busy === u.id} onClick={() => setDeleting(u)}>
                              Delete account…
                            </button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {deleting && <DeleteUserModal user={deleting} call={call} onClose={() => setDeleting(null)} onDeleted={reload} />}
      {resetting && <ResetTwoFactorModal user={resetting} call={call} onClose={() => setResetting(null)} onDone={reload} />}
    </section>
  );
}

/** Turn off every two-step method of a user who lost them all, after the admin confirms who asked. */
function ResetTwoFactorModal({ user, call, onClose, onDone }: { user: User; call: Call; onClose: () => void; onDone: () => Promise<void> }) {
  const [checked, setChecked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!checked) return setError("Confirm that the account owner asked for this.");
    setBusy(true);
    setError(null);
    try {
      const r = await call<{ email_sent?: boolean }>(`/users/${encodeURIComponent(user.id)}/two-factor/reset`, { method: "POST" });
      toast(r?.email_sent ? `Two-step login turned off for ${user.email}. They were emailed.` : `Two-step login turned off for ${user.email}`);
      onClose();
      await onDone();
    } catch (err) {
      setBusy(false);
      if (err instanceof AdminError && err.status === 404) setError(`${user.email} no longer exists.`);
      else if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    }
  }

  return (
    <Modal title="Reset two-step login?" subtitle={user.email} icon="shield" tone="danger" onClose={() => !busy && onClose()}>
      <form onSubmit={submit}>
        <p className="card-text">
          This turns off every two-step method for this account: authenticator app, email codes, security keys and recovery codes, and forgets the
          devices they marked as trusted. They can then sign in with their master password (and Secret Key, if they use one) and turn two-step login
          on again. Their vault stays encrypted and nothing else changes.
        </p>
        <p className="small muted">
          Only do this when you're sure the request comes from the account owner, for example in person or over a channel you already trust. They
          get an email about it if this server can send email.
        </p>
        <label className="check">
          <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} data-autofocus="" />
          <span>I confirmed this request with the account owner</span>
        </label>
        <ErrorText error={error} />
        <SheetActions
          quiet={
            <button type="button" className="btn btn-text" onClick={onClose} disabled={busy}>
              Cancel
            </button>
          }
        >
          <button type="submit" className="btn btn-danger-solid btn-block" disabled={!checked || busy}>
            {busy ? "Resetting…" : "Reset two-step login"}
          </button>
        </SheetActions>
      </form>
    </Modal>
  );
}

function DeleteUserModal({ user, call, onClose, onDeleted }: { user: User; call: Call; onClose: () => void; onDeleted: () => Promise<void> }) {
  return (
    <ConfirmDialog
      title="Delete this account?"
      subtitle={user.email}
      icon="trash"
      action="Delete account"
      busyAction="Deleting account…"
      confirmText={user.email}
      matchCase={false}
      onClose={onClose}
      onConfirm={async () => {
        try {
          await call(`/users/${encodeURIComponent(user.id)}`, { method: "DELETE" });
        } catch (err) {
          // A lost admin session already sends the admin back to the token form.
          if (err instanceof AdminError && err.status === 401) return;
          throw err;
        }
        toast(`${user.email} was deleted`);
        onClose();
        await onDeleted();
      }}
    >
      <p className="card-text">
        This permanently deletes the account, every vault they own and all items in those vaults ({user.items.toLocaleString()}{" "}
        {user.items === 1 ? "item" : "items"}). They lose access to vaults shared with them. This cannot be undone.
      </p>
    </ConfirmDialog>
  );
}

// ---------------------------------------------------------------- invites

function InvitesCard({ invites, smtp, domain, call, reload }: { invites: Invite[]; smtp: boolean; domain: string; call: Call; reload: () => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const now = Date.now() / 1000;

  async function invite(e: FormEvent) {
    e.preventDefault();
    const addr = email.trim();
    if (!addr.includes("@")) return setError("Enter a full email address, such as name@example.com.");
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await call<{ invited: string; email_sent: boolean }>("/invites", { body: { email: addr } });
      setEmail("");
      setNotice(
        r.email_sent
          ? `Invitation sent to ${r.invited}. It is valid for 7 days.`
          : `Invitation saved for ${r.invited}, but email is not set up on this server. Send them this link yourself: ${domain}/register?email=${encodeURIComponent(r.invited)}`,
      );
      await reload();
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(addr: string) {
    setError(null);
    setNotice(null);
    try {
      await call(`/invites/${encodeURIComponent(addr)}`, { method: "DELETE" });
      toast(`Invitation for ${addr} revoked`);
      await reload();
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    }
  }

  return (
    <section className="card" aria-labelledby="inv-title">
      <h2 id="inv-title">Invitations</h2>
      <p className="card-text">
        Invited people can create an account even when sign-ups are closed.{" "}
        {smtp ? "They receive an email with a sign-up link." : "Email is off, so share the sign-up link with them yourself."}
      </p>
      <form className="inline-form" onSubmit={invite}>
        <label className="field">
          <span>Email address</span>
          <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" placeholder="name@example.com" />
        </label>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Sending invitation…" : smtp ? "Send invitation" : "Create invitation"}
        </button>
      </form>
      <ErrorText error={error} />
      {notice && (
        <div className="alert alert-ok wrap-anywhere" role="status">
          {notice}
        </div>
      )}
      {invites.length === 0 ? (
        <p className="muted">There are no open invitations.</p>
      ) : (
        <div className="fields" role="list" aria-label="Open invitations">
          {invites.map((i) => (
            <div key={i.email} role="listitem">
              <span className="tile" aria-hidden="true">
                <Icon name="mail" />
              </span>
              <span className="grow">
                <span className="row-title">{i.email}</span>
                <span className="row-sub" title={`Invited ${formatDateTime(i.created_at)}, expires ${formatDateTime(i.expires_at)}`}>
                  Invited {formatDate(i.created_at)}. {i.expires_at < now ? "The invitation has expired." : `Expires ${formatDate(i.expires_at)}.`}
                </span>
              </span>
              {i.expires_at < now && <span className="badge badge-warn">Expired</span>}
              <button type="button" className="btn btn-text btn-danger btn-sm" onClick={() => revoke(i.email)} aria-label={`Revoke invitation for ${i.email}`}>
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

// --------------------------------------------------------------- settings

const LEVEL_LABELS: Record<string, string> = {
  error: "Errors only",
  warn: "Warnings and errors",
  info: "Normal",
  debug: "Detailed (for troubleshooting)",
  trace: "Everything (very large)",
};

// --------------------------------------------------------------- activity

/** The admin page decrypts nothing: vaults and items are named by what happened to them, and filtered by id. */
const ADMIN_CONTEXT: DescribeContext = { me: null, admin: true, vaultName: () => null, itemName: () => null };

/** The server's activity log (`GET /admin/events`), filtered by type or category, person and vault. */
function ActivityCard({ users, call, user, onUser }: { users: User[]; call: Call; user: string; onUser: (userId: string) => void }) {
  const [type, setType] = useState("");
  const [vault, setVault] = useState("");
  const [vaultText, setVaultText] = useState("");
  const emails = useMemo(() => new Map(users.map((u) => [u.id, u.email])), [users]);

  const load = useCallback(
    (before: string | null) => {
      const q = new URLSearchParams();
      if (type) q.set("type", type);
      if (user) q.set("user", user);
      if (vault) q.set("vault", vault);
      if (before) q.set("before", before);
      const s = q.toString();
      return call<unknown>(`/events${s ? `?${s}` : ""}`);
    },
    [call, type, user, vault],
  );

  const showVault = (id: string) => {
    setVault(id);
    setVaultText(id);
  };
  const filtered = !!(type || user || vault);

  /** Under each event: narrow the list to a person or a vault it names. */
  const extra = (e: ActivityEvent) => {
    const people = new Map<string, string>();
    for (const p of [e.actor, e.target_user]) if (p && p.id !== user) people.set(p.id, p.email ?? "a deleted account");
    if (!people.size && (!e.vault_id || e.vault_id === vault)) return null;
    return (
      <span className="activity-tags">
        {[...people].map(([id, email]) => (
          <button key={id} type="button" className="link" onClick={() => onUser(id)}>
            Only {email}
          </button>
        ))}
        {e.vault_id && e.vault_id !== vault && (
          <button type="button" className="link" title={`Vault ${e.vault_id}`} onClick={() => showVault(e.vault_id!)}>
            Only vault {e.vault_id.slice(0, 8)}
          </button>
        )}
      </span>
    );
  };

  return (
    <section className="card" id="admin-activity" aria-labelledby="activity-title">
      <div className="stack-s">
        <h2 id="activity-title">Activity</h2>
        <p className="card-text">
          Sign-ins, account and sharing changes and item changes on this server, newest first. Vault contents are never recorded, so vaults and items are
          known here by what happened to them.
        </p>
      </div>
      <div className="activity-filters">
        <label className="field">
          <span>What</span>
          <select className="select" value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">Everything</option>
            {EVENT_TYPES.map((c) => (
              <optgroup key={c.category} label={c.label}>
                <option value={c.category}>All: {c.label.toLowerCase()}</option>
                {c.types.map(([t, label]) => (
                  <option key={t} value={t}>
                    {label}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Person</span>
          <select className="select" value={user} onChange={(e) => onUser(e.target.value)}>
            <option value="">Everyone</option>
            {user && !emails.has(user) && <option value={user}>A deleted account</option>}
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.email}
              </option>
            ))}
          </select>
        </label>
        <form
          className="field"
          onSubmit={(e) => {
            e.preventDefault();
            setVault(vaultText.trim());
          }}
        >
          <label htmlFor="activity-vault">Vault id</label>
          <input
            id="activity-vault"
            className="input mono"
            value={vaultText}
            onChange={(e) => setVaultText(e.target.value)}
            onBlur={() => setVault(vaultText.trim())}
            placeholder="Any vault"
            spellCheck={false}
            autoComplete="off"
          />
        </form>
      </div>
      {filtered && (
        <div className="row">
          <button
            type="button"
            className="btn btn-text btn-sm"
            onClick={() => {
              setType("");
              onUser("");
              showVault("");
            }}
          >
            Clear filters
          </button>
        </div>
      )}
      <EventList
        load={load}
        context={ADMIN_CONTEXT}
        label="Server activity"
        empty={filtered ? "Nothing matches these filters." : "Nothing has been recorded yet."}
        errorText={(e) => (e as Error).message}
        extra={extra}
      />
    </section>
  );
}

/** "Empty trash after" choices in days; 0 keeps the trash until someone empties it. */
const TRASH_DAYS = [0, 30, 60, 90];

function SettingsCard({ settings, call, reload }: { settings: Settings; call: Call; reload: () => Promise<void> }) {
  const [level, setLevel] = useState(settings.log_level);
  const [icons, setIcons] = useState(settings.icons);
  const [verify, setVerify] = useState(settings.signups_verify);
  const hasBreach = typeof settings.breach_check === "boolean";
  const [breach, setBreach] = useState(settings.breach_check ?? true);
  // Only servers that can empty the trash by themselves report trash_days; with `ranges` it is set under Limits.
  const trashDaysNow = typeof settings.trash_days === "number" ? settings.trash_days : undefined;
  const hasTrash = trashDaysNow !== undefined && !settings.ranges;
  const [trashDays, setTrashDays] = useState(trashDaysNow ?? 0);
  const trashChoices = TRASH_DAYS.includes(trashDaysNow ?? 0) ? TRASH_DAYS : [...TRASH_DAYS, trashDaysNow!].sort((a, b) => a - b);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const changed =
    level !== settings.log_level ||
    icons !== settings.icons ||
    verify !== settings.signups_verify ||
    (hasBreach && breach !== settings.breach_check) ||
    (hasTrash && trashDays !== trashDaysNow);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call("/settings", {
        method: "PUT",
        body: { log_level: level, icons, signups_verify: verify, ...(hasBreach ? { breach_check: breach } : {}), ...(hasTrash ? { trash_days: trashDays } : {}) },
      });
      await reload();
      toast("Server settings saved");
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="settings-title">
      <h2 id="settings-title">Server settings</h2>
      <form className="stack" onSubmit={save}>
        <label className="check">
          <input type="checkbox" checked={verify} onChange={(e) => setVerify(e.target.checked)} />
          <span>
            New accounts must confirm their email address
            <span className="field-hint block">Needs email delivery (below). Without email, new accounts are confirmed automatically.</span>
          </span>
        </label>
        <label className="check">
          <input type="checkbox" checked={icons} onChange={(e) => setIcons(e.target.checked)} />
          <span>
            Show website icons
            <span className="field-hint block">
              The server fetches each website's icon for the apps. It learns which websites' icons are asked for, never anything in a vault. When off, apps
              show the first letter instead.
            </span>
          </span>
        </label>
        {hasBreach && (
          <label className="check">
            <input type="checkbox" checked={breach} onChange={(e) => setBreach(e.target.checked)} />
            <span>
              Check passwords against Have I Been Pwned
              <span className="field-hint block">
                Lets people find out in Password health whether their passwords appear in known data breaches, sending only the first 5 characters of
                each password's SHA-1 hash from their device (never a password, and never through this server).
              </span>
            </span>
          </label>
        )}
        <label className="field">
          <span>Server log</span>
          <select className="select" value={level} onChange={(e) => setLevel(e.target.value)}>
            {level === "custom" && <option value="custom">Custom (LOG_LEVEL in .env)</option>}
            {settings.log_levels.map((l) => (
              <option key={l} value={l}>
                {LEVEL_LABELS[l] ?? l}
              </option>
            ))}
          </select>
          <span className="field-hint">How much the server writes to its log (docker compose logs). Vault contents and passwords are never logged.</span>
        </label>
        {hasTrash && (
          <label className="field">
            <span>Empty trash after</span>
            <select className="select" value={trashDays} onChange={(e) => setTrashDays(Number(e.target.value))}>
              {trashChoices.map((d) => (
                <option key={d} value={d}>
                  {d === 0 ? "Never" : `${d} days`}
                </option>
              ))}
            </select>
            <span className="field-hint">
              Items that stay in the trash longer than this are deleted for good, for every account on this server. With Never, items stay in the trash
              until someone deletes them.
            </span>
          </label>
        )}
        <ErrorText error={error} />
        <div className="card-actions">
          <button type="submit" className="btn btn-primary" disabled={busy || !changed}>
            {busy ? "Saving…" : "Save server settings"}
          </button>
          <span className="small muted">Takes effect immediately and replaces SIGNUPS_VERIFY, ICON_SERVICE and LOG_LEVEL from the server's .env file.</span>
        </div>
      </form>
    </section>
  );
}

// ------------------------------------------------------------------ limits

interface LimitField {
  name: string;
  label: string;
  /** Shown after the input, e.g. "days". */
  unit: string;
  hint: string;
  /** What 0 means, for limits that may be turned off. */
  zero?: string;
}

/** What a switch's confirmation can mention. */
interface ConfirmContext {
  /** Accounts (not disabled) without any two-step method, from the user list. */
  withoutTwoStep: number;
}

/** An on/off setting in a group (`GET /admin/settings` booleans), shown when the server reports it. */
interface SwitchField {
  name: string;
  label: string;
  hint: string;
  /** Saving it at `when` asks first: it erases something, or changes a lot for users. */
  confirm?: {
    when: boolean;
    title: string;
    subtitle: string;
    action: string;
    /** Red action button (the default for ConfirmDialog): erases something for good. */
    danger: boolean;
    text: (ctx: ConfirmContext) => string;
  };
}

const EVENT_IP: SwitchField = {
  name: "event_ip",
  label: "Record IP addresses in the activity log",
  hint: "Shown on this page, to the person who acted, and to account owners for failed sign-ins to their account. Turning this off also erases the addresses already kept.",
  confirm: {
    when: false,
    title: "Stop recording IP addresses?",
    subtitle: "Activity log",
    action: "Erase addresses and save",
    danger: true,
    text: () =>
      "The activity log stops keeping the IP address of each event, and every address it has kept so far is erased for good. The events themselves stay. You can turn recording on again later, but erased addresses don't come back.",
  },
};

const ACCOUNTS = (n: number) => (n === 1 ? "1 account" : `${n.toLocaleString()} accounts`);

const POLICY_SWITCHES: SwitchField[] = [
  {
    name: "require_two_step",
    label: "Require two-step login",
    hint: "Accounts without two-step login can only set it up (or sign out) until they do, and nobody can turn off their last method.",
    confirm: {
      when: true,
      title: "Require two-step login?",
      subtitle: "Account policies",
      action: "Require two-step login",
      danger: false,
      text: ({ withoutTwoStep: n }) =>
        `Accounts without two-step login will only be able to set it up: until they turn on a method, they can sign in but can't open or sync their vaults in any app. ${
          n === 0 ? "Every active account uses it already." : `${ACCOUNTS(n)} ${n === 1 ? "doesn't" : "don't"} use it yet.`
        } While this is on, nobody can turn off their last method.`,
    },
  },
  {
    name: "require_secret_key",
    label: "Require a Secret Key",
    hint: "New accounts and master password changes must use a Secret Key, and accounts without one are asked to turn it on.",
  },
  {
    name: "disable_export",
    label: "Turn off export",
    hint: "The apps stop offering to export a vault to a file.",
  },
  {
    name: "login_with_device",
    label: "Allow approving sign-ins from another device",
    hint: "A new device can sign in when one of the account's signed-in devices approves it, without typing the master password there. While this is off, nobody can ask or approve, and requests already waiting can't be used.",
  },
];

const SENDS: SwitchField = {
  name: "sends",
  label: "Allow Send",
  hint: "People can share text through an encrypted link that expires; while this is off, existing links stop opening.",
};

const ATTACHMENTS: SwitchField = {
  name: "attachments",
  label: "Allow attachments",
  hint: "People can attach files to items, encrypted on their devices. While this is off, nobody can add files; files already attached can still be downloaded and removed.",
};

const EMERGENCY_ACCESS: SwitchField = {
  name: "emergency_access",
  label: "Allow emergency access",
  hint: "People can name trusted contacts who may ask to view their vaults after a waiting period. While this is off, nobody can add contacts, ask for access or view a vault through it.",
};

/**
 * The limits and policies, by group. A field is shown only when the server reports its value and range, a switch only
 * when the server reports its value.
 */
const LIMIT_GROUPS: { title: string; note?: string; fields: LimitField[]; switches?: SwitchField[]; switchesFirst?: true }[] = [
  {
    title: "Sign-in",
    fields: [
      { name: "session_days", label: "Sign-ins last", unit: "days", hint: "Devices must sign in again this long after signing in, however often they're used." },
      { name: "refresh_days", label: "Unused devices stay signed in", unit: "days", hint: "A device that hasn't been used for this long must sign in again." },
      { name: "remember_device_days", label: "Remember a device for two-step login", unit: "days", hint: "How long \"Remember this device\" skips the second step." },
      { name: "signin_attempts_per_minute", label: "Sign-in attempts per address", unit: "per minute", hint: "Further attempts from that address wait until the minute is over." },
      { name: "two_step_attempts_per_hour", label: "Wrong two-step codes per account", unit: "per hour", hint: "Then two-step login pauses for an hour and the user gets an email." },
    ],
  },
  {
    title: "Storage",
    fields: [
      { name: "max_items_per_user", label: "Items per user", unit: "items", zero: "no limit", hint: "Every item in the vaults a user owns counts, the trash included." },
      { name: "max_storage_mb_per_user", label: "Storage per user", unit: "MB", zero: "no limit", hint: "The encrypted size of the items in the vaults a user owns, the trash included." },
      { name: "max_item_kib", label: "Largest item", unit: "KB", hint: "The encrypted size of one item. Apps leave larger items out of imports." },
      { name: "max_import_items", label: "Items per import request", unit: "items", hint: "Apps split larger imports into several requests." },
      {
        name: "min_free_disk_mb",
        label: "Keep this much disk space free",
        unit: "MB",
        zero: "no check",
        hint: "Below it nothing new is stored; sign-in, sync and deleting keep working.",
      },
    ],
  },
  {
    title: "Attachments",
    switchesFirst: true,
    switches: [ATTACHMENTS],
    fields: [
      { name: "max_attachment_mb", label: "Largest attachment", unit: "MB", hint: "The encrypted size of one file." },
      {
        name: "max_attachment_storage_mb_per_user",
        label: "Attachment storage per user",
        unit: "MB",
        zero: "no limit",
        hint: "Files attached to items in the vaults a user owns, and uploads they started that haven't finished.",
      },
    ],
  },
  {
    title: "Sync and trash",
    fields: [
      { name: "trash_days", label: "Empty the trash after", unit: "days", zero: "never", hint: "Items in the trash longer than this are deleted for good, for every account." },
      { name: "tombstone_days", label: "Remember deletions for", unit: "days", hint: "Apps that sync only changes and were away longer than this download their vaults in full once." },
      { name: "websocket_ping_seconds", label: "Check live-sync connections every", unit: "seconds", hint: "Shorter notices dropped connections sooner, for a little more traffic." },
    ],
  },
  {
    title: "History and activity",
    fields: [
      { name: "event_days", label: "Keep the activity log for", unit: "days", hint: "Older entries are deleted. The log never holds vault contents or setting values." },
      {
        name: "item_versions_kept",
        label: "Earlier versions kept per item",
        unit: "versions",
        zero: "no item history",
        hint: "They count toward the vault owner's storage. Lowering this deletes the oldest versions at once.",
      },
    ],
    switches: [EVENT_IP],
  },
  {
    title: "Account policies",
    note: "Apps that can't create keys as strong as the key derivation minimums can't create accounts or change master passwords while they apply.",
    switchesFirst: true,
    switches: POLICY_SWITCHES,
    fields: [
      {
        name: "master_password_min_length",
        label: "Shortest master password",
        unit: "characters",
        hint: "New accounts and master password changes need at least this many characters; current passwords keep working.",
      },
      {
        name: "max_vault_timeout_minutes",
        label: "Longest vault timeout",
        unit: "minutes",
        zero: "no limit",
        hint: "The apps lock after this much inactivity at the latest and stop offering longer timeouts or Never.",
      },
      {
        name: "min_kdf_memory_mib",
        label: "Least memory for key derivation",
        unit: "MiB",
        hint: "New account keys must use at least this much memory to derive keys from the master password; accounts below it are asked to update.",
      },
      {
        name: "min_kdf_iterations",
        label: "Least key derivation passes",
        unit: "passes",
        hint: "New account keys must use at least this many passes; accounts below it are asked to update.",
      },
    ],
  },
  {
    title: "Send",
    switchesFirst: true,
    switches: [SENDS],
    fields: [{ name: "send_max_days", label: "Delete Sends after at most", unit: "days", hint: "Nobody can keep a Send longer than this; each one is deleted by then." }],
  },
  {
    title: "Emergency access",
    switches: [EMERGENCY_ACCESS],
    fields: [],
  },
];

/**
 * Lifetimes, attempt limits, quotas, sync settings, account policies and Send (`GET /admin/settings` values,
 * `ranges` and `switches`); saves only what changed, after asking for the switches that need it.
 */
function LimitsCard({ settings, call, reload, withoutTwoStep }: { settings: Settings; call: Call; reload: () => Promise<void>; withoutTwoStep: number }) {
  const ranges = settings.ranges ?? {};
  const savedValue = (name: string) => settings[name] as number;
  const savedSwitch = (name: string) => settings[name] as boolean;
  const groups = LIMIT_GROUPS.map((g) => ({
    ...g,
    fields: g.fields.filter((f) => ranges[f.name] && typeof settings[f.name] === "number"),
    switches: (g.switches ?? []).filter((sw) => typeof settings[sw.name] === "boolean"),
  })).filter((g) => g.fields.length > 0 || g.switches.length > 0);
  const fields = groups.flatMap((g) => g.fields);
  const switches = groups.flatMap((g) => g.switches);
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(fields.map((f) => [f.name, String(savedValue(f.name))])));
  const [on, setOn] = useState<Record<string, boolean>>(() => Object.fromEntries(switches.map((sw) => [sw.name, savedSwitch(sw.name)])));
  /** Switches whose confirmation is still to be given, in order. */
  const [confirming, setConfirming] = useState<SwitchField[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const valueOf = (f: LimitField) => (values[f.name] ?? String(savedValue(f.name))).trim();
  const switchOf = (sw: SwitchField) => on[sw.name] ?? savedSwitch(sw.name);
  const changed = fields.filter((f) => valueOf(f) !== String(savedValue(f.name)));
  const changedSwitches = switches.filter((sw) => switchOf(sw) !== savedSwitch(sw.name));
  const unsaved = changed.length + changedSwitches.length;
  const erasesIps = changedSwitches.some((sw) => sw.name === "event_ip" && !switchOf(sw));

  function problem(f: LimitField): string | null {
    const r = ranges[f.name];
    const text = valueOf(f);
    const n = Number(text);
    return /^\d+$/.test(text) && n >= r.min && n <= r.max ? null : `Enter a whole number from ${r.min.toLocaleString()} to ${r.max.toLocaleString()}.`;
  }

  function edit(f: LimitField, value: string) {
    setValues((v) => ({ ...v, [f.name]: value }));
    if (errors[f.name]) setErrors(({ [f.name]: _gone, ...rest }) => rest);
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const found = Object.fromEntries(changed.flatMap((f) => (problem(f) ? [[f.name, problem(f)!]] : [])));
    setErrors(found);
    if (Object.keys(found).length) return;
    // Erasing the kept IP addresses, or requiring two-step login: ask first.
    const asks = changedSwitches.filter((sw) => sw.confirm && switchOf(sw) === sw.confirm.when);
    if (asks.length) return setConfirming(asks);
    await send();
  }

  async function send() {
    setBusy(true);
    setError(null);
    try {
      const numbers = Object.fromEntries(changed.map((f) => [f.name, Number(valueOf(f))]));
      const flags = Object.fromEntries(changedSwitches.map((sw) => [sw.name, switchOf(sw)]));
      await call("/settings", { method: "PUT", body: { ...numbers, ...flags } });
      // As the server stores them ("090" is 90), so they don't show as unsaved.
      setValues((v) => ({ ...v, ...Object.fromEntries(Object.entries(numbers).map(([name, n]) => [name, String(n)])) }));
      await reload();
      toast(erasesIps ? "Changes saved. IP addresses in the activity log were erased." : "Changes saved");
    } catch (err) {
      if (err instanceof AdminError && err.status === 401) return;
      const message = (err as Error).message;
      // The server names a refused setting in parentheses, e.g. "… (session_days) must be …": show it at that field.
      const named = err instanceof AdminError && err.status === 400 ? fields.find((f) => message.includes(`(${f.name})`)) : undefined;
      if (named) setErrors({ [named.name]: message });
      else setError(message);
    } finally {
      setBusy(false);
    }
  }

  const asking = confirming[0]?.confirm;

  const switchRow = (sw: SwitchField) => (
    <label className="setting" key={sw.name}>
      <span className="setting-text">
        <span className="setting-title">{sw.label}</span>
        <span className="setting-desc">{sw.hint}</span>
      </span>
      <input type="checkbox" role="switch" className="switch" checked={switchOf(sw)} onChange={(e) => setOn((o) => ({ ...o, [sw.name]: e.target.checked }))} />
    </label>
  );

  return (
    <section className="card" aria-labelledby="limits-title">
      <div className="stack-s">
        <h2 id="limits-title">Limits and policies</h2>
        <p className="card-text">These apply to every account on this server and take effect immediately.</p>
      </div>
      <form className="stack" onSubmit={save} noValidate>
        {groups.map((g) => (
          <fieldset key={g.title} className="limit-group">
            <legend className="section-title">{g.title}</legend>
            {g.switchesFirst && g.switches.map(switchRow)}
            {g.fields.length > 0 && (
              <div className="limit-grid">
                {g.fields.map((f) => {
                  const r = ranges[f.name];
                  const id = `limit-${f.name}`;
                  const fieldError = errors[f.name];
                  return (
                    <div className="field" key={f.name}>
                      <label htmlFor={id}>
                        {f.label}
                        <span className="sr-only"> ({f.unit})</span>
                      </label>
                      <div className="input-group limit-input">
                        <input
                          id={id}
                          className="input"
                          type="number"
                          inputMode="numeric"
                          min={r.min}
                          max={r.max}
                          step={1}
                          value={values[f.name] ?? ""}
                          aria-invalid={fieldError ? true : undefined}
                          aria-describedby={fieldError ? `${id}-error ${id}-hint` : `${id}-hint`}
                          onChange={(e) => edit(f, e.target.value)}
                        />
                        <span className="input-trail" aria-hidden="true">
                          {f.unit}
                        </span>
                      </div>
                      {fieldError && (
                        <span className="field-error" id={`${id}-error`}>
                          {fieldError}
                        </span>
                      )}
                      <span className="field-hint" id={`${id}-hint`}>
                        {f.hint} {f.zero ? `0 means ${f.zero}. ` : ""}From {r.min.toLocaleString()} to {r.max.toLocaleString()}, {r.default.toLocaleString()} by default.
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
            {!g.switchesFirst && g.switches.map(switchRow)}
            {g.note && g.fields.length > 0 && <p className="small muted">{g.note}</p>}
          </fieldset>
        ))}
        <ErrorText error={error} />
        <div className="card-actions">
          <button type="submit" className="btn btn-primary" disabled={busy || unsaved === 0}>
            {busy ? "Saving…" : "Save changes"}
          </button>
          {unsaved > 0 && !busy && (
            <span className="small muted" role="status">
              {unsaved === 1 ? "1 change not saved yet" : `${unsaved} changes not saved yet`}
            </span>
          )}
        </div>
      </form>
      {asking && (
        <ConfirmDialog
          key={confirming[0].name}
          title={asking.title}
          subtitle={asking.subtitle}
          icon="shield"
          action={asking.action}
          busyAction="Saving…"
          danger={asking.danger}
          onConfirm={() => {
            const rest = confirming.slice(1);
            setConfirming(rest);
            return rest.length ? undefined : send();
          }}
          onClose={() => setConfirming([])}
        >
          <p className="card-text">{asking.text({ withoutTwoStep })}</p>
        </ConfirmDialog>
      )}
    </section>
  );
}

// ------------------------------------------------------------------- email

const DEFAULT_PORTS: Record<SmtpSecurity, number> = { starttls: 587, force_tls: 465, off: 25 };

function EmailCard({ smtp, call, reload }: { smtp: Smtp | null; call: Call; reload: () => Promise<void> }) {
  const [host, setHost] = useState(smtp?.host ?? "");
  const [security, setSecurity] = useState<SmtpSecurity>(smtp?.security ?? "starttls");
  const [port, setPort] = useState(smtp && smtp.port !== DEFAULT_PORTS[smtp.security] ? String(smtp.port) : "");
  const [username, setUsername] = useState(smtp?.username ?? "");
  const [password, setPassword] = useState("");
  const [from, setFrom] = useState(smtp?.from ?? "");
  const [fromName, setFromName] = useState(smtp?.from_name ?? "PassAuth");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmOff, setConfirmOff] = useState(false);

  const [to, setTo] = useState("");
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [sent, setSent] = useState<string | null>(null);

  async function save(e: FormEvent) {
    e.preventDefault();
    if (!host.trim()) return setError("Enter your mail provider's SMTP server, such as smtp.example.com.");
    if (!from.includes("@")) return setError("Enter the address emails are sent from, such as passauth@example.com.");
    const portNum = port.trim() ? Number(port) : undefined;
    if (portNum !== undefined && !(Number.isInteger(portNum) && portNum > 0 && portNum < 65536)) return setError("The port must be a number from 1 to 65535.");
    setBusy(true);
    setError(null);
    try {
      await call("/settings/smtp", {
        method: "PUT",
        body: {
          host: host.trim(),
          security,
          port: portNum,
          username: username.trim(),
          // Left empty: keep the saved password.
          ...(password || !smtp?.password_set ? { password } : {}),
          from: from.trim(),
          from_name: fromName.trim(),
        },
      });
      setPassword("");
      await reload();
      toast("Email settings saved");
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function send(e: FormEvent) {
    e.preventDefault();
    const addr = to.trim();
    if (!addr.includes("@")) return setTestError("Enter a full email address, such as name@example.com.");
    setTesting(true);
    setTestError(null);
    setSent(null);
    try {
      await call("/smtp/test", { body: { to: addr } });
      setSent(`Test email sent to ${addr}. If it does not arrive within a few minutes, check the spam folder and the server logs.`);
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setTestError((err as Error).message);
    } finally {
      setTesting(false);
    }
  }

  return (
    <section className="card" aria-labelledby="smtp-title">
      <h2 id="smtp-title">Email delivery</h2>
      <p className="card-text">
        {smtp
          ? "The server sends verification codes, invitations and security alerts through this mail server."
          : "Email is off. Enter your mail provider's SMTP details to send verification codes, invitations and security alerts."}
      </p>
      <form className="stack" onSubmit={save}>
        <label className="field">
          <span>SMTP server</span>
          <input className="input" value={host} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.com" autoCapitalize="none" spellCheck={false} />
        </label>
        <label className="field">
          <span>Encryption</span>
          <select className="select" value={security} onChange={(e) => setSecurity(e.target.value as SmtpSecurity)}>
            <option value="starttls">STARTTLS (usually port 587)</option>
            <option value="force_tls">TLS (usually port 465)</option>
            <option value="off">None (unencrypted, only inside your own network)</option>
          </select>
        </label>
        <label className="field">
          <span>Port (optional)</span>
          <input className="input" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} placeholder={String(DEFAULT_PORTS[security])} />
        </label>
        <label className="field">
          <span>User name (optional)</span>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} />
        </label>
        <div className="field">
          <label htmlFor="smtp-password">Password{smtp?.password_set ? "" : " (optional)"}</label>
          <PasswordInput
            id="smtp-password"
            value={password}
            onChange={setPassword}
            autoComplete="new-password"
            placeholder={smtp?.password_set ? "Saved. Leave empty to keep it." : undefined}
          />
        </div>
        <label className="field">
          <span>Send from</span>
          <input className="input" type="email" value={from} onChange={(e) => setFrom(e.target.value)} placeholder="passauth@example.com" autoCapitalize="none" spellCheck={false} />
        </label>
        <label className="field">
          <span>Sender name</span>
          <input className="input" value={fromName} onChange={(e) => setFromName(e.target.value)} placeholder="PassAuth" />
        </label>
        <ErrorText error={error} />
        <div className="card-actions">
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "Saving…" : "Save email settings"}
          </button>
          {smtp && (
            <button type="button" className="btn" onClick={() => setConfirmOff(true)}>
              Turn off email
            </button>
          )}
          <span className="small muted">Takes effect immediately and replaces the SMTP settings from the server's .env file.</span>
        </div>
      </form>
      {smtp && (
        <div className="stack">
          <h3>Test email</h3>
          <p className="card-text">Send a test message to confirm the server can deliver verification codes and invitations.</p>
          <form className="inline-form" onSubmit={send}>
            <label className="field">
              <span>Send test email to</span>
              <input className="input" type="email" value={to} onChange={(e) => setTo(e.target.value)} autoComplete="email" placeholder="you@example.com" />
            </label>
            <button type="submit" className="btn" disabled={testing}>
              {testing ? "Sending test email…" : "Send test email"}
            </button>
          </form>
          <ErrorText error={testError} />
          {sent && (
            <div className="alert alert-ok" role="status">
              {sent}
            </div>
          )}
        </div>
      )}
      {confirmOff && (
        <ConfirmDialog
          title="Turn off email?"
          icon="mail"
          action="Turn off email"
          busyAction="Turning off…"
          onClose={() => setConfirmOff(false)}
          onConfirm={async () => {
            await call("/settings/smtp", { method: "DELETE" });
            setConfirmOff(false);
            setHost("");
            setUsername("");
            setFrom("");
            setPort("");
            await reload();
            toast("Email is off");
          }}
        >
          <p className="card-text">
            The saved mail server details are removed. New accounts are then confirmed without an email, invitations aren't emailed and email codes for two-step
            login stop working.
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}

// --------------------------------------------------------- admin security

function AdminSecurityCard({ twoStep, networks, call, reload }: { twoStep: TwoStep; networks: boolean; call: Call; reload: () => Promise<void> }) {
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [asking, setAsking] = useState<"disable" | "codes" | null>(null);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const r = await call<{ secret: string; uri: string }>("/2fa/setup", { body: {} });
      setSetup({ secret: r.secret, qr: await QRCode.toDataURL(r.uri, { margin: 1, width: 200 }) });
      setCode("");
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
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
      const r = await call<{ recovery_codes: string[] }>("/2fa/enable", { body: { code: code.replace(/\s/g, "") } });
      setSetup(null);
      setCodes(r.recovery_codes);
      toast("Two-step login is on for the admin page");
    } catch (err) {
      if (!(err instanceof AdminError && err.status === 401)) setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const prettySecret = setup?.secret.replace(/(.{4})/g, "$1 ").trim();

  return (
    <section className="card" aria-labelledby="admin-security-title">
      <div className="card-head">
        <div className="card-title">
          <h2 id="admin-security-title">Admin security</h2>
          {twoStep.enabled ? <span className="badge badge-ok">Two-step login on</span> : <span className="badge">Two-step login off</span>}
        </div>
        {twoStep.enabled ? (
          <div className="card-actions">
            <button type="button" className="btn" onClick={() => setAsking("codes")}>
              New recovery codes…
            </button>
            <button type="button" className="btn btn-danger" onClick={() => setAsking("disable")}>
              Turn off…
            </button>
          </div>
        ) : (
          !setup && (
            <button type="button" className="btn" onClick={start} disabled={busy}>
              {busy ? "Starting setup…" : "Set up two-step login…"}
            </button>
          )
        )}
      </div>
      <p className="card-text">
        {twoStep.enabled
          ? `Signing in to the admin page needs the password and a code from your authenticator app. ${twoStep.recovery_codes_left} recovery ${twoStep.recovery_codes_left === 1 ? "code" : "codes"} left.`
          : "Ask for a code from an authenticator app on your phone, in addition to the admin password."}
      </p>
      {twoStep.enabled && twoStep.recovery_codes_left <= 3 && (
        <div className="alert alert-warn" role="note">
          You're running low on recovery codes. Create new ones and keep them somewhere safe.
        </div>
      )}
      {!twoStep.enabled && setup && (
        <form className="stack" onSubmit={enable}>
          <div className="totp-setup">
            <div className="qr">
              <img src={setup.qr} alt="QR code to add the PassAuth admin page to your authenticator app" width={200} height={200} />
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
                <CodeField id="admin-totp-code" value={code} onChange={setCode} />
              </li>
            </ol>
          </div>
          <ErrorText error={error} />
          <div className="card-actions">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? "Checking code…" : "Turn on two-step login"}
            </button>
            <button type="button" className="btn btn-text" onClick={() => setSetup(null)} disabled={busy}>
              Cancel
            </button>
          </div>
        </form>
      )}
      {!setup && <ErrorText error={error} />}
      <p className="small muted">
        If you lose your phone and your recovery codes, run <code className="mono">docker compose exec passauth passauth-server reset-admin-2fa</code> on the
        server to turn two-step login off.
      </p>
      <p className="small muted">
        {networks
          ? "The admin page only opens from the networks in PASSAUTH_ADMIN_ALLOWED_NETWORKS."
          : "The admin page opens from any network. To allow only your own networks, set PASSAUTH_ADMIN_ALLOWED_NETWORKS in the server's .env file."}
      </p>
      {asking && (
        <AskCode
          kind={asking}
          call={call}
          onClose={() => setAsking(null)}
          onDone={async (newCodes) => {
            setAsking(null);
            if (newCodes) setCodes(newCodes);
            else toast("Two-step login is off for the admin page");
            await reload();
          }}
        />
      )}
      {codes && (
        <RecoveryCodesModal
          codes={codes}
          title="PassAuth admin recovery codes"
          intro="If you lose your phone, a recovery code lets you sign in to the admin page."
          onClose={async () => {
            setCodes(null);
            await reload();
          }}
        />
      )}
    </section>
  );
}

/** Ask for a current code before turning two-step login off or replacing the recovery codes. */
function AskCode({ kind, call, onClose, onDone }: { kind: "disable" | "codes"; call: Call; onClose: () => void; onDone: (codes: string[] | null) => Promise<void> }) {
  const [code, setCode] = useState("");
  const off = kind === "disable";
  return (
    <ConfirmDialog
      title={off ? "Turn off two-step login?" : "Create new recovery codes?"}
      icon={off ? "shield" : "note"}
      danger={off}
      action={off ? "Turn off" : "Create new codes"}
      busyAction={off ? "Turning off…" : "Creating…"}
      onClose={onClose}
      onConfirm={async () => {
        if (!code.trim()) throw new Error("Enter a code from your authenticator app, or a recovery code.");
        if (off) {
          await call("/2fa/disable", { body: { code: code.trim() } });
          await onDone(null);
        } else {
          const r = await call<{ recovery_codes: string[] }>("/2fa/recovery-codes", { body: { code: code.trim() } });
          await onDone(r.recovery_codes);
        }
      }}
    >
      <p className="card-text">
        {off
          ? "Signing in to the admin page will need only the user name and password."
          : "Your current recovery codes stop working as soon as the new ones are created."}
      </p>
      <CodeField id="admin-confirm-code" label="Code from your authenticator app, or a recovery code" value={code} onChange={setCode} autoFocus />
    </ConfirmDialog>
  );
}
