/** Settings tab: a list of categories, each opening its own page. */
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { LogoMark } from "@web/components/Logo";
import { ActionRow, ErrorText, Icon, Modal, SheetActions, type IconName } from "@web/components/ui";
import { send, type PopupState, type SecurityKey, type SecurityKeys, type Settings, type VaultTimeout } from "../shared/messages";
import { msg, seconds, type Ctx } from "./ctx";
import { Account, Page, PopOut } from "./shell";
import { applyTheme } from "./theme";

type Control = chrome.types.LevelOfControl | "no-permission" | "unknown";

/**
 * "Default password manager": turn off Chrome's own password saving and
 * address/card autofill (chrome.privacy, an optional permission) so its
 * prompts don't compete with PassAuth's. Turning it off hands control back.
 */
function DefaultManager({ notify }: { notify: (t: string) => void }) {
  const [control, setControl] = useState<Control>("unknown");
  const read = async () => {
    if (!(await chrome.permissions.contains({ permissions: ["privacy"] }))) return setControl("no-permission");
    const d = await chrome.privacy.services.passwordSavingEnabled.get({});
    setControl(d.levelOfControl);
  };
  useEffect(() => void read(), []);
  const services = () => [chrome.privacy.services.passwordSavingEnabled, chrome.privacy.services.autofillAddressEnabled, chrome.privacy.services.autofillCreditCardEnabled];

  async function toggle(on: boolean) {
    try {
      if (on) {
        if (!(await chrome.permissions.request({ permissions: ["privacy"] }))) return notify("PassAuth needs the privacy permission to turn off Chrome's password manager.");
        for (const s of services()) await s.set({ value: false });
        notify("PassAuth is now your default password manager.");
      } else {
        for (const s of services()) await s.clear({});
        notify("Chrome's password manager and autofill are back on.");
      }
    } catch (e) {
      notify(msg(e));
    }
    await read();
  }

  const on = control === "controlled_by_this_extension";
  return (
    <>
      <Toggle
        label="Make PassAuth your default password manager"
        help="Turns off Chrome's built-in password saving and address and card autofill, so only PassAuth offers to save and fill."
        checked={on}
        onChange={toggle}
      />
      {control === "controlled_by_other_extensions" && (
        <p className="small muted">Another extension (for example another password manager) controls this Chrome setting. Remove or turn off that extension first.</p>
      )}
      {control === "not_controllable" && <p className="small muted">This setting is managed by your organization's Chrome policy.</p>}
    </>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="kv">
      <div className="grow">
        <div className="k">{label}</div>
        <div className="v clip">{children}</div>
      </div>
    </div>
  );
}


const TIMEOUTS: [VaultTimeout, string][] = [
  ["immediately", "Immediately"],
  [1, "1 minute"],
  [5, "5 minutes"],
  [15, "15 minutes"],
  [30, "30 minutes"],
  [60, "1 hour"],
  [240, "4 hours"],
  ["system-lock", "On system lock"],
  ["restart", "On browser restart"],
  ["never", "Never"],
];

const MATCHES: [Settings["defaultMatch"], string][] = [
  ["domain", "Base domain"],
  ["host", "Host"],
  ["starts_with", "Starts with"],
  ["regex", "Regular expression"],
  ["exact", "Exact"],
  ["never", "Never"],
];

const THEMES: Record<Settings["theme"], string> = { system: "System", light: "Light", dark: "Dark" };

const MATCH_HELP: Record<Settings["defaultMatch"], string> = {
  domain: "login.example.com and www.example.com both match example.com.",
  host: "Same host name and port only: login.example.com doesn't match www.example.com.",
  starts_with: "The page address must start with the saved website address.",
  regex: "The saved website is a regular expression tested against the page address. Advanced.",
  exact: "The page address must be exactly the saved website address.",
  never: "Never suggest or fill logins automatically. Items can still set their own matching.",
};

function Toggle({ label, help, checked, onChange }: { label: string; help?: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="setting">
      <span className="setting-text">
        <span className="setting-title">{label}</span>
        {help && <span className="setting-desc">{help}</span>}
      </span>
      <input type="checkbox" role="switch" className="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} />
    </label>
  );
}

/**
 * Two-step login security keys (registered in the web vault): list them and
 * remove one after the master password. Adding a key needs the web vault.
 */
function SecurityKeysSettings({ notify }: { notify: (t: string) => void }) {
  const [data, setData] = useState<SecurityKeys | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [removing, setRemoving] = useState<SecurityKey | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = () =>
    send<SecurityKeys>({ type: "securityKeys" }).then(
      (d) => (setData(d), setLoadError(null)),
      (e) => setLoadError(msg(e)),
    );
  useEffect(() => void load(), []);

  function cancel() {
    setRemoving(null);
    setPassword("");
    setError(null);
  }

  async function remove(e: FormEvent) {
    e.preventDefault();
    if (!removing || busy) return;
    if (!password) return setError("Enter your master password to continue.");
    setBusy(true);
    setError(null);
    try {
      setData(await send<SecurityKeys>({ type: "securityKeys:remove", id: removing.id, password }));
      notify(`Security key "${removing.name}" removed.`);
      cancel();
    } catch (err) {
      setError(msg(err));
    } finally {
      setBusy(false);
    }
  }

  // Removing the last key when it's the only two-step method turns two-step login off (and deletes the recovery codes).
  const lastMethod = !!data && data.keys.length === 1 && data.methods.every((m) => m === "passkey");

  return (
    <section className="stack-s" aria-labelledby="sk-title">
      <h3 className="section-title" id="sk-title">
        Security keys for two-step login
      </h3>
      {loadError ? (
        <>
          <ErrorText error={loadError} />
          <button type="button" className="btn" style={{ alignSelf: "flex-start" }} onClick={load}>
            Try again
          </button>
        </>
      ) : !data ? (
        <p className="small muted">Loading…</p>
      ) : data.keys.length === 0 ? (
        <p className="small muted">No security keys. You can add one in the web vault under Settings → Two-step login.</p>
      ) : (
        <ul className="plain-list">
          {data.keys.map((k) => (
            <li key={k.id}>
              <span className="grow" style={{ overflowWrap: "anywhere" }}>
                {k.name}
                <span className="row-sub">
                  Added {new Date(k.created_at * 1000).toLocaleDateString()}
                  {k.last_used_at ? `, last used ${new Date(k.last_used_at * 1000).toLocaleDateString()}` : ", never used"}
                </span>
              </span>
              <button type="button" className="btn btn-icon" aria-label={`Remove security key ${k.name}`} title="Remove" onClick={() => (setRemoving(k), setPassword(""), setError(null))} disabled={busy}>
                <Icon name="trash" />
              </button>
            </li>
          ))}
        </ul>
      )}
      {removing && (
        <Modal title="Remove security key?" subtitle={removing.name} icon="key" tone="danger" onClose={() => !busy && cancel()}>
          <form onSubmit={remove}>
            <p className={lastMethod ? "alert alert-warn" : "card-text"}>
              {lastMethod
                ? "This is your only two-step method. Removing it turns two-step login off and deletes your recovery codes."
                : "You won't be able to use this key for two-step login any more."}
            </p>
            <ErrorText error={error} />
            <div className="field">
              <label htmlFor="sk-password">Master password</label>
              <input id="sk-password" className="input mono" type="password" autoComplete="current-password" aria-describedby="sk-reason" data-autofocus="" value={password} onChange={(e) => setPassword(e.target.value)} disabled={busy} />
              <span id="sk-reason" className="field-hint">
                Confirms it's you before the key is removed.
              </span>
            </div>
            <SheetActions
              quiet={
                <button type="button" className="btn btn-text" onClick={cancel} disabled={busy}>
                  Cancel
                </button>
              }
            >
              <button type="submit" className="btn btn-danger-solid btn-block" disabled={busy}>
                {busy ? "Removing…" : "Remove security key"}
              </button>
            </SheetActions>
          </form>
        </Modal>
      )}
    </section>
  );
}

function formatTime(ms: number) {
  if (!ms) return "never";
  const d = new Date(ms);
  const sameDay = d.toDateString() === new Date().toDateString();
  return sameDay ? `today at ${d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" })}` : d.toLocaleString();
}

export function SettingsPage({ ctx, section }: { ctx: Ctx; section?: string }) {
  const { state, notify } = ctx;
  const [settings, setSettings] = useState(state.settings);
  const [syncing, setSyncing] = useState(false);
  const [synced, setSynced] = useState(false);
  const [lastSync, setLastSync] = useState(state.lastSync);
  const [neverSave, setNeverSave] = useState(state.neverSave);

  const update = (patch: Partial<Settings>) => {
    setSettings({ ...settings, ...patch });
    send<Settings>({ type: "settings", patch }).then(setSettings, (e) => notify(msg(e)));
  };
  async function sync() {
    if (syncing) return;
    setSyncing(true);
    try {
      await send({ type: "sync" });
      const s = await send<PopupState>({ type: "state" });
      setLastSync(s.lastSync);
      setSynced(true);
      notify("Sync complete. Your vault is up to date.");
    } catch (e) {
      notify(`Sync failed: ${msg(e)}`);
    } finally {
      setSyncing(false);
    }
  }
  const timeoutValue = String(settings.vaultTimeout);
  const isMac = navigator.platform.toLowerCase().includes("mac");

  const sections: { key: string; title: string; icon: IconName; body: ReactNode; /** The body brings its own cards. */ plain?: boolean }[] = [
    {
      key: "security",
      title: "Account security",
      icon: "lock",
      body: (
        <>
        <label className="field">
          <span>Vault timeout</span>
          <select
            className="select"
            value={timeoutValue}
            onChange={(e) => {
              const v = TIMEOUTS.find(([t]) => String(t) === e.target.value)![0];
              update({ vaultTimeout: v });
            }}
          >
            {TIMEOUTS.map(([v, label]) => (
              <option key={String(v)} value={String(v)}>
                {label}
              </option>
            ))}
          </select>
        </label>
        {settings.vaultTimeout === "never" && (
          <div className="alert alert-error small">With "Never", your vault key is stored on this device without the master password protecting it. Anyone who can use this browser profile can open your vault.</div>
        )}
        <label className="field">
          <span>Timeout action</span>
          <select className="select" value={settings.timeoutAction} onChange={(e) => update({ timeoutAction: e.target.value as Settings["timeoutAction"] })}>
            <option value="lock">Lock</option>
            <option value="logout">Sign out</option>
          </select>
        </label>
        <p className="small muted">
          {settings.timeoutAction === "lock"
            ? "Locking keeps your encrypted vault here; unlock with your master password."
            : "Signing out removes the vault from this browser; sign in again (with two-step login) to use it."}
        </p>
        <button className="btn" onClick={() => send({ type: "lock" }).then(ctx.reload)}>
          <Icon name="lock" /> Lock now
        </button>
        <hr />
        <SecurityKeysSettings notify={notify} />
        </>
      ),
    },
    {
      key: "autofill",
      title: "Autofill",
      icon: "wand",
      body: (
        <>
        <DefaultManager notify={notify} />
        <label className="field">
          <span>Show inline autofill menu</span>
          <select className="select" value={settings.inlineMenu} onChange={(e) => update({ inlineMenu: e.target.value as Settings["inlineMenu"] })}>
            <option value="focus">When a login field is selected</option>
            <option value="click">When I click the PassAuth icon in a field</option>
            <option value="off">Off</option>
          </select>
        </label>
        <label className="field">
          <span>Default URI match detection</span>
          <select className="select" value={settings.defaultMatch} onChange={(e) => update({ defaultMatch: e.target.value as Settings["defaultMatch"] })}>
            {MATCHES.map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <p className="small muted">{MATCH_HELP[settings.defaultMatch]} Applies to websites set to "Default" in an item.</p>
        <Toggle
          label="Copy verification code automatically"
          help="After filling a login that has an authenticator key, the current code is copied so you can paste it."
          checked={settings.autoCopyTotp}
          onChange={(v) => update({ autoCopyTotp: v })}
        />
        <p className="small muted">
          Fill the login for the current page with <kbd>{isMac ? "⌘ ⇧ L" : "Ctrl+Shift+L"}</kbd>.{" "}
          <button className="link" onClick={() => chrome.tabs.create({ url: "chrome://extensions/shortcuts" })}>
            Change shortcuts
          </button>
        </p>
        <label className="field">
          <span>Clear clipboard</span>
          <select className="select" value={settings.clearClipboard} onChange={(e) => update({ clearClipboard: +e.target.value })}>
            <option value={0}>Never</option>
            {[10, 20, 30, 60, 120, 300].map((s) => (
              <option key={s} value={s}>
                After {seconds(s)}
              </option>
            ))}
          </select>
          <span className="small muted">Applies to everything PassAuth copies: passwords, usernames and verification codes.</span>
        </label>
        </>
      ),
    },
    {
      key: "notifications",
      title: "Notifications",
      icon: "bell",
      body: (
        <>
        <Toggle label="Ask to save and update logins" checked={settings.askToSave} onChange={(v) => update({ askToSave: v })} />
        {neverSave.length > 0 && (
          <section className="stack-s" aria-labelledby="never-title">
            <hr />
            <h3 className="section-title" id="never-title">
              Never ask on these sites
            </h3>
            <ul className="plain-list">
              {neverSave.map((d) => (
                <li key={d}>
                  <span className="grow clip">{d}</span>
                  <button
                    className="btn btn-icon"
                    aria-label={`Ask again on ${d}`}
                    title="Ask again on this site"
                    onClick={() => send({ type: "neverSave:remove", domain: d }).then(() => setNeverSave(neverSave.filter((x) => x !== d)))}
                  >
                    <Icon name="close" />
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}
        </>
      ),
    },
    {
      key: "vault",
      title: "Vault options",
      icon: "vault",
      plain: true,
      body: (
        <div className="choices">
          <ActionRow icon="sync" title={syncing ? "Syncing…" : "Sync vault now"} sub={<span aria-live="polite">Last sync: {formatTime(lastSync)}</span>} done={synced && !syncing ? "Up to date" : undefined} onClick={sync} />
          <ActionRow icon="upload" title="Import items" sub="Opens the web vault" onClick={() => chrome.tabs.create({ url: `${state.server}/import` })} />
          <ActionRow icon="external" title="Open web vault" sub={new URL(state.server).host} onClick={() => chrome.tabs.create({ url: state.server })} />
        </div>
      ),
    },
    {
      key: "appearance",
      title: "Appearance",
      icon: "eye",
      body: (
        <>
        <label className="field">
          <span>Theme</span>
          <select
            className="select"
            value={settings.theme}
            onChange={(e) => {
              const theme = e.target.value as Settings["theme"];
              applyTheme(theme);
              update({ theme });
            }}
          >
            {(Object.keys(THEMES) as Settings["theme"][]).map((t) => (
              <option key={t} value={t}>
                {t === "system" ? "Same as system" : THEMES[t]}
              </option>
            ))}
          </select>
        </label>
        <Toggle
          label="Show the number of logins on the PassAuth icon"
          help="The toolbar icon shows how many saved logins match the site you're on."
          checked={settings.badge}
          onChange={(v) => update({ badge: v })}
        />
        <Toggle
          label="Show website icons"
          help="Icons are fetched by your PassAuth server, which learns the website addresses but never your vault contents."
          checked={settings.showIcons}
          onChange={(v) => update({ showIcons: v })}
        />
        </>
      ),
    },
    {
      key: "about",
      title: "About",
      icon: "info",
      body: (
        <>
        <div className="about-brand">
          <LogoMark size={40} />
          <div>
            <span className="name">PassAuth</span>
            <span className="sub">Version {chrome.runtime.getManifest().version}</span>
            <span className="sub">© Fahed Alhammadi</span>
          </div>
        </div>
        <hr />
        <div>
          <Field label="Signed in as">{state.email}</Field>
          <Field label="Server">{state.server}</Field>
        </div>
        <p className="small muted">To use another PassAuth server, sign out and choose "Change server" on the sign-in screen.</p>
        <button className="btn btn-danger" onClick={() => send({ type: "logout" }).then(ctx.reload)}>
          <Icon name="logout" /> Sign out
        </button>
        </>
      ),
    },
  ];
  const open = sections.find((x) => x.key === section);
  const toList = () => ctx.go({ tab: "settings" });
  if (open) {
    return (
      <Page title={open.title} onBack={toList} actions={<PopOut />}>
        {open.plain ? open.body : <div className="card-box settings-body">{open.body}</div>}
      </Page>
    );
  }
  return (
    <Page title="Settings" brand actions={<><PopOut /><Account state={state} onChange={ctx.reload} /></>}>
      <nav className="choices" aria-label="Settings">
        {sections.map((x) => (
          <ActionRow key={x.key} icon={x.icon} title={x.title} onClick={() => ctx.go({ tab: "settings", section: x.key })} />
        ))}
      </nav>
    </Page>
  );
}
