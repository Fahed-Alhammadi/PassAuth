/** Settings tab: a list of categories, each opening its own page. */
import { useEffect, useState, type ReactNode } from "react";
import { Icon, type IconName } from "@web/components/ui";
import { send, type PopupState, type Settings, type VaultTimeout } from "../shared/messages";
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
    <label className="check">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>
        {label}
        {help && <span className="small muted block">{help}</span>}
      </span>
    </label>
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
  const [lastSync, setLastSync] = useState(state.lastSync);
  const [neverSave, setNeverSave] = useState(state.neverSave);

  const update = (patch: Partial<Settings>) => {
    setSettings({ ...settings, ...patch });
    send<Settings>({ type: "settings", patch }).then(setSettings, (e) => notify(msg(e)));
  };
  async function sync() {
    setSyncing(true);
    try {
      await send({ type: "sync" });
      const s = await send<PopupState>({ type: "state" });
      setLastSync(s.lastSync);
      notify("Sync complete. Your vault is up to date.");
    } catch (e) {
      notify(`Sync failed: ${msg(e)}`);
    } finally {
      setSyncing(false);
    }
  }
  const timeoutValue = String(settings.vaultTimeout);
  const isMac = navigator.platform.toLowerCase().includes("mac");

  const sections: { key: string; title: string; icon: IconName; body: ReactNode }[] = [
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
            <option value="logout">Log out</option>
          </select>
        </label>
        <p className="small muted">
          {settings.timeoutAction === "lock"
            ? "Locking keeps your encrypted vault here; unlock with your master password."
            : "Logging out removes the vault from this browser; sign in again (with two-step login) to use it."}
        </p>
        <button className="btn" onClick={() => send({ type: "lock" }).then(ctx.reload)}>
          <Icon name="lock" /> Lock now
        </button>
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
          <div className="stack-s">
            <span className="small muted">Never ask on these sites:</span>
            {neverSave.map((d) => (
              <div className="row" key={d}>
                <span className="grow mono small">{d}</span>
                <button
                  className="btn btn-ghost btn-icon"
                  aria-label={`Ask again on ${d}`}
                  title="Ask again on this site"
                  onClick={() => send({ type: "neverSave:remove", domain: d }).then(() => setNeverSave(neverSave.filter((x) => x !== d)))}
                >
                  <Icon name="close" />
                </button>
              </div>
            ))}
          </div>
        )}
        </>
      ),
    },
    {
      key: "vault",
      title: "Vault options",
      icon: "vault",
      body: (
        <>
        <button className="btn" onClick={sync} disabled={syncing}>
          <Icon name="sync" /> {syncing ? "Syncing…" : "Sync vault now"}
        </button>
        <p className="small muted" aria-live="polite">
          Last sync: {formatTime(lastSync)}
        </p>
        <button className="btn" onClick={() => chrome.tabs.create({ url: `${state.server}/import` })}>
          <Icon name="upload" /> Import items
        </button>
        <button className="btn" onClick={() => chrome.tabs.create({ url: state.server })}>
          <Icon name="external" /> Open web vault
        </button>
        </>
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
        <Field label="Signed in as">{state.email}</Field>
        <Field label="Server">{state.server}</Field>
        <Field label="Extension version">{chrome.runtime.getManifest().version}</Field>
        <p className="small muted">To use another PassAuth server, log out and choose "Change server" on the sign-in screen.</p>
        <button className="btn btn-danger" onClick={() => send({ type: "logout" }).then(ctx.reload)}>
          Log out
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
        <div className="card-box settings-body">{open.body}</div>
      </Page>
    );
  }
  return (
    <Page title="Settings" brand actions={<><PopOut /><Account state={state} onChange={ctx.reload} /></>}>
      <nav className="settings-list" aria-label="Settings">
        {sections.map((x) => (
          <button key={x.key} className="settings-row" onClick={() => ctx.go({ tab: "settings", section: x.key })}>
            <Icon name={x.icon} />
            <span className="grow">{x.title}</span>
            <Icon name="chevron" />
          </button>
        ))}
      </nav>
    </Page>
  );
}
