/** Settings tab: a list of categories, each opening its own page. */

import { LogoMark } from "@web/components/Logo";
import { ActionRow, ErrorText, Icon, type IconName, Modal, SheetActions } from "@web/components/ui";
import { minutesLabel, timeoutOptions } from "@web/lib/policies";
import { type FormEvent, type ReactNode, useEffect, useRef, useState } from "react";
import { callPopup } from "../shared/protocol";
import type { PopupState, SecurityKey, SecurityKeys, Settings, SharingIdentity, VaultTimeout } from "../shared/types";
import { avatarJpeg, bytesToBase64 } from "./avatar-image";
import { type Ctx, msg, seconds } from "./ctx";
import { Account, AccountPicture, isPopOut, openPopOut, Page, PopOut } from "./shell";
import { applyTheme } from "./theme";

/** The keyboard commands in the order Settings and the welcome page list them, with PassAuth's wording. */
const COMMANDS: [name: string, label: string, help?: string][] = [
  ["_execute_action", "Open PassAuth"],
  ["autofill", "Fill the login for this page", "Press again within 5 seconds for the next login."],
  ["generate_password", "Copy a strong password", "Uses the generator's options."],
  ["lock", "Lock PassAuth"],
];

/** The shortcuts as Chrome has them now (the user can change them on chrome://extensions/shortcuts). */
export function Shortcuts() {
  const [commands, setCommands] = useState<chrome.commands.Command[] | null>(null);
  useEffect(() => {
    chrome.commands.getAll().then(setCommands, () => setCommands([]));
  }, []);
  return (
    <section className="stack-s" aria-labelledby="keys-title">
      <h3 className="section-title" id="keys-title">
        Keyboard shortcuts
      </h3>
      {commands && (
        <ul className="plain-list shortcuts">
          {COMMANDS.map(([name, label, help]) => {
            const key = commands.find((c) => c.name === name)?.shortcut;
            return (
              <li key={name}>
                <span className="grow">
                  {label}
                  {help && <span className="row-sub">{help}</span>}
                </span>
                {key ? <kbd>{key}</kbd> : <span className="small muted">Not set</span>}
              </li>
            );
          })}
        </ul>
      )}
      <button type="button" className="link" style={{ alignSelf: "flex-start" }} onClick={() => void chrome.tabs.create({ url: "chrome://extensions/shortcuts" })}>
        Change shortcuts
      </button>
    </section>
  );
}

/** "Unlock with a PIN": set (PIN twice + the master password) or turn off. Not offered with the timeout "Never". */
function PinSettings({ state, never, notify, reload }: { state: PopupState; never: boolean; notify: (t: string) => void; reload: () => void }) {
  const [setting, setSetting] = useState(false);
  if (never) return null;
  async function toggle(on: boolean) {
    if (on) return setSetting(true);
    try {
      await callPopup("pin:remove");
      notify("PIN unlock is off.");
      reload();
    } catch (e) {
      notify(msg(e));
    }
  }
  return (
    <>
      <Toggle
        label="Unlock with a PIN"
        help="Unlock with 6 or more digits instead of your master password until you close the browser. After 5 wrong PINs, PassAuth asks for your master password."
        checked={!!state.pinUnlock}
        onChange={(v) => void toggle(v)}
      />
      {setting && (
        <PinDialog
          onClose={() => setSetting(false)}
          onDone={() => {
            setSetting(false);
            notify("PIN unlock is on until you close the browser.");
            reload();
          }}
        />
      )}
    </>
  );
}

const digits = (v: string) => v.replace(/\D+/g, "").slice(0, 64);

function PinDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [pin, setPin] = useState("");
  const [again, setAgain] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    if (pin.length < 6) return setError("Use 6 or more digits.");
    if (pin !== again) return setError("The two PINs are different. Type the same PIN twice.");
    if (!password) return setError("Enter your master password to turn on PIN unlock.");
    setBusy(true);
    setError(null);
    try {
      await callPopup("pin:set", { pin, password });
      onDone();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }
  return (
    <Modal title="Set a PIN" subtitle="Until you close the browser" icon="lock" onClose={() => !busy && onClose()}>
      <form onSubmit={submit}>
        <p className="card-text">Your PIN unlocks PassAuth in this browser until it closes. It never leaves this device.</p>
        <div className="field">
          <label htmlFor="pin-new">PIN</label>
          <input
            id="pin-new"
            className="input mono"
            type="password"
            inputMode="numeric"
            autoComplete="off"
            value={pin}
            onChange={(e) => setPin(digits(e.target.value))}
            data-autofocus=""
            disabled={busy}
          />
        </div>
        <div className="field">
          <label htmlFor="pin-again">PIN again</label>
          <input id="pin-again" className="input mono" type="password" inputMode="numeric" autoComplete="off" value={again} onChange={(e) => setAgain(digits(e.target.value))} disabled={busy} />
        </div>
        <div className="field">
          <label htmlFor="pin-master">Master password</label>
          <input
            id="pin-master"
            className="input mono"
            type="password"
            autoComplete="current-password"
            aria-describedby="pin-master-why"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
          <span id="pin-master-why" className="field-hint">
            Confirms it's you before a PIN can open your vault.
          </span>
        </div>
        <ErrorText error={error} />
        <SheetActions
          quiet={
            <button type="button" className="btn btn-text" onClick={onClose} disabled={busy}>
              Cancel
            </button>
          }
        >
          <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
            {busy ? "Turning on…" : "Turn on PIN unlock"}
          </button>
        </SheetActions>
      </form>
    </Modal>
  );
}

/** Sites where PassAuth hides its inline menu and fill entries (hidden from the inline menu), with "Show again". */
function HiddenSites({ initial, notify }: { initial: string[]; notify: (t: string) => void }) {
  const [sites, setSites] = useState(initial);
  if (!sites.length) return null;
  return (
    <section className="stack-s" aria-labelledby="hidden-title">
      <hr />
      <h3 className="section-title" id="hidden-title">
        Hidden on these sites
      </h3>
      <p className="small muted">PassAuth shows no inline menu and no fill entries here.</p>
      <ul className="plain-list">
        {sites.map((d) => (
          <li key={d}>
            <span className="grow clip">{d}</span>
            <button
              type="button"
              className="btn btn-text btn-sm"
              aria-label={`Show PassAuth again on ${d}`}
              onClick={() =>
                callPopup("hiddenSites:remove", { domain: d }).then(
                  () => {
                    setSites((all) => all.filter((x) => x !== d));
                    notify(`PassAuth shows again on ${d}.`);
                  },
                  (e) => notify(msg(e)),
                )
              }
            >
              Show again
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

type Control = chrome.types.LevelOfControl | "no-permission" | "unknown";

/**
 * "Default password manager": turn off Chrome's own password saving and
 * address/card autofill (chrome.privacy, an optional permission) so its
 * prompts don't compete with PassAuth's. Turning it off hands control back.
 */
export function DefaultManager({ notify }: { notify: (t: string) => void }) {
  const [control, setControl] = useState<Control>("unknown");
  const read = async () => {
    if (!(await chrome.permissions.contains({ permissions: ["privacy"] }))) return setControl("no-permission");
    const d = await chrome.privacy.services.passwordSavingEnabled.get({});
    setControl(d.levelOfControl);
  };
  // biome-ignore lint/correctness/useExhaustiveDependencies: read once when the page opens (read is recreated on every render)
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

export const TIMEOUTS: [VaultTimeout, string][] = [
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
      {/* biome-ignore lint/a11y/useAriaPropsForRole: a native checkbox reports its checked state to the switch role itself */}
      <input type="checkbox" role="switch" className="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} />
    </label>
  );
}

/**
 * Two-step login security keys (registered in the web vault): list them and
 * remove one after the master password. Adding a key needs the web vault.
 */
/**
 * Signed sharing: this account's identity fingerprint, computed here from the unlocked key (never the server's), for
 * the people the user shares with to compare. Nothing is shown on servers without signed sharing.
 */
function SharingIdentitySettings() {
  const [data, setData] = useState<SharingIdentity | null>(null);
  useEffect(() => {
    callPopup("sharingIdentity").then(setData, () => {});
  }, []);
  if (!data || (!data.fingerprint && !data.paused)) return null;
  return (
    <>
      <hr />
      <div className="field">
        <span>Your sharing fingerprint</span>
        {data.fingerprint ? (
          <p className="mono">{data.fingerprint}</p>
        ) : (
          <div className="alert alert-error small">Your server lists a signing key that isn't yours. Sharing is paused on this device.</div>
        )}
        <p className="small muted">People you share vaults with see this fingerprint for you. Compare it with them in person or on a call.</p>
      </div>
    </>
  );
}

function SecurityKeysSettings({ notify }: { notify: (t: string) => void }) {
  const [data, setData] = useState<SecurityKeys | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [removing, setRemoving] = useState<SecurityKey | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = () =>
    callPopup("securityKeys").then(
      (d) => {
        setData(d);
        setLoadError(null);
      },
      (e) => setLoadError(msg(e)),
    );
  // biome-ignore lint/correctness/useExhaustiveDependencies: load once when the page opens (load is recreated on every render)
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
      setData(await callPopup("securityKeys:remove", { id: removing.id, password }));
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
              <button
                type="button"
                className="btn btn-icon"
                aria-label={`Remove security key ${k.name}`}
                title="Remove"
                onClick={() => {
                  setRemoving(k);
                  setPassword("");
                  setError(null);
                }}
                disabled={busy}
              >
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
              <input
                id="sk-password"
                className="input mono"
                type="password"
                autoComplete="current-password"
                aria-describedby="sk-reason"
                data-autofocus=""
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={busy}
              />
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

/**
 * The account's profile picture (servers with the `avatar` feature, while unlocked): Change picture picks an image
 * file, which is cropped, resized and re-encoded here (never uploaded as it was) and sealed by the background; Remove
 * only when there is one. Without a picture the initials show.
 */
function ProfilePicture({ state, notify, reload }: { state: PopupState; notify: (t: string) => void; reload: () => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  async function run(work: () => Promise<void>, done: string) {
    setBusy(true);
    try {
      await work();
      notify(done);
      reload();
    } catch (e) {
      notify(msg(e));
    } finally {
      setBusy(false);
    }
  }
  async function picked(file: File | undefined) {
    if (input.current) input.current.value = "";
    if (!file) return;
    await run(async () => {
      const jpeg = await avatarJpeg(file);
      await callPopup("avatar:set", { jpeg: bytesToBase64(jpeg) });
    }, "Profile picture changed.");
  }
  return (
    <>
      <section className="stack-s" aria-labelledby="profile-title">
        <h3 className="section-title" id="profile-title">
          Profile picture
        </h3>
        <div className="profile">
          <span className="profile-pic" aria-hidden="true">
            <AccountPicture name={state.name} email={state.email} avatar={state.avatar} />
          </span>
          <span className="profile-text">
            <span className="title">{state.name || state.email}</span>
            {state.name && <span className="sub">{state.email}</span>}
          </span>
        </div>
        <div className="profile-actions">
          <button type="button" className="btn" disabled={busy} onClick={() => (isPopOut() ? input.current?.click() : void openPopOut())}>
            {state.avatar ? "Change picture" : "Choose picture"}
          </button>
          {state.avatar && (
            <button type="button" className="btn" disabled={busy} onClick={() => run(() => callPopup("avatar:remove"), "Profile picture removed.")}>
              Remove
            </button>
          )}
        </div>
        <input ref={input} type="file" accept="image/*" hidden onChange={(e) => void picked(e.target.files?.[0])} />
        <p className="small muted">
          {isPopOut() ? "" : "PassAuth opens in its own window first, so the file chooser can stay open. "}Your picture is encrypted before it leaves this browser. Your other devices show it after
          their next sync.
        </p>
      </section>
      <hr />
    </>
  );
}

/**
 * "Forget this browser": the account's Secret Key and two-step "remember this
 * device" token stored here go, so the next unlock or sign-in asks for them again.
 */
function ForgetBrowser({ state, notify, reload }: { state: PopupState; notify: (t: string) => void; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const nothing = !state.secretKeyStored && !state.rememberedDevice;
  async function forget() {
    setBusy(true);
    try {
      await callPopup("account:forgetBrowser");
      notify("This browser no longer remembers your Secret Key or skips two-step login.");
      reload();
    } catch (e) {
      notify(msg(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="stack-s" aria-labelledby="forget-title">
      <h3 className="section-title" id="forget-title">
        This browser
      </h3>
      <p className="small muted">
        {nothing
          ? "This browser doesn't keep your Secret Key or a two-step login pass for this account."
          : "Forgetting it means your next sign-in here asks for your Secret Key (if you use one) and a two-step code again."}
      </p>
      <button type="button" className="btn" style={{ alignSelf: "flex-start" }} onClick={forget} disabled={busy || nothing}>
        Forget this browser
      </button>
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
  const [offlineText, setOfflineText] = useState(state.offlineText);
  const [neverSave, setNeverSave] = useState(state.neverSave);

  const update = (patch: Partial<Settings>) => {
    setSettings({ ...settings, ...patch });
    callPopup("settings", { patch }).then(
      (saved) => {
        setSettings(saved);
        // The rest of the popup follows these (the PIN option, the list's density).
        if ("vaultTimeout" in patch || "density" in patch) ctx.reload();
      },
      (e) => notify(msg(e)),
    );
  };
  async function sync() {
    if (syncing) return;
    setSyncing(true);
    try {
      await callPopup("sync");
      const s = await callPopup("state");
      setLastSync(s.lastSync);
      setOfflineText(s.offlineText);
      setSynced(true);
      notify(s.offlineText ? `Sync complete. ${s.offlineText}.` : "Sync complete. Your vault is up to date.");
    } catch (e) {
      notify(`Sync failed: ${msg(e)}`);
    } finally {
      setSyncing(false);
    }
  }
  const timeoutValue = String(settings.vaultTimeout);
  // The servers' policies may set a longest timeout: only the choices within it (the limit itself included).
  const limit = state.timeoutLimit ?? 0;
  const timeouts = timeoutOptions(TIMEOUTS, limit);
  const lowered = state.timeoutLowered;
  const loweredFrom =
    limit && lowered !== undefined && settings.vaultTimeout === limit ? (TIMEOUTS.find(([v]) => v === lowered)?.[1] ?? (typeof lowered === "number" ? minutesLabel(lowered) : undefined)) : undefined;

  const sections: { key: string; title: string; icon: IconName; body: ReactNode /** The body brings its own cards. */; plain?: boolean }[] = [
    {
      key: "security",
      title: "Account security",
      icon: "lock",
      body: (
        <>
          {state.avatarEditable && <ProfilePicture state={state} notify={notify} reload={ctx.reload} />}
          <label className="field">
            <span>Vault timeout</span>
            <select
              className="select"
              value={timeoutValue}
              onChange={(e) => {
                const v = timeouts.find(([t]) => String(t) === e.target.value)![0];
                update({ vaultTimeout: v });
              }}
            >
              {timeouts.map(([v, label]) => (
                <option key={String(v)} value={String(v)}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          {limit > 0 && (
            <p className="small muted">
              Your server allows a vault timeout of at most {minutesLabel(limit)}.{loweredFrom ? ` Your choice (${loweredFrom}) was lowered to ${minutesLabel(limit)}.` : ""}
            </p>
          )}
          {settings.vaultTimeout === "never" && (
            <div className="alert alert-error small">
              With "Never", your vault key is stored on this device without the master password protecting it. Anyone who can use this browser profile can open your vault.
              <br />
              Passkeys don't ask for your master password either: the unlocked vault counts as your confirmation.
            </div>
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
          <PinSettings state={state} never={settings.vaultTimeout === "never"} notify={notify} reload={ctx.reload} />
          <button type="button" className="btn" onClick={() => callPopup("lock").then(ctx.reload)}>
            <Icon name="lock" /> {state.accounts.length > 1 ? "Lock all accounts now" : "Lock now"}
          </button>
          <hr />
          <ForgetBrowser state={state} notify={notify} reload={ctx.reload} />
          <hr />
          <SecurityKeysSettings notify={notify} />
          <SharingIdentitySettings />
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
            label="Offer a strong password on sign-up forms"
            help="The inline menu suggests a new password from the generator on sign-up and change-password fields."
            checked={settings.inlineOnSignup}
            onChange={(v) => update({ inlineOnSignup: v })}
          />
          <Toggle
            label="Show PassAuth in the right-click menu"
            help="Fill, copy a user name, password or code, or a strong password, from the page's right-click menu."
            checked={settings.contextMenu}
            onChange={(v) => update({ contextMenu: v })}
          />
          <Toggle
            label="Copy verification code automatically"
            help="After filling a login that has an authenticator key, the current code is copied so you can paste it."
            checked={settings.autoCopyTotp}
            onChange={(v) => update({ autoCopyTotp: v })}
          />
          <hr />
          <Shortcuts />
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
          <HiddenSites initial={state.hiddenSites} notify={notify} />
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
                      type="button"
                      className="btn btn-icon"
                      aria-label={`Ask again on ${d}`}
                      title="Ask again on this site"
                      onClick={() => callPopup("neverSave:remove", { domain: d }).then(() => setNeverSave(neverSave.filter((x) => x !== d)))}
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
          <ActionRow
            icon="sync"
            title={syncing ? "Syncing…" : "Sync vault now"}
            sub={
              <span aria-live="polite">
                Last sync: {formatTime(lastSync)}
                {offlineText ? ` · ${offlineText}` : ""}
              </span>
            }
            done={synced && !syncing && !offlineText ? "Up to date" : undefined}
            onClick={sync}
          />
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
            label="Compact list"
            help="Smaller rows, so more of your vault fits in the popup."
            checked={settings.density === "compact"}
            onChange={(v) => update({ density: v ? "compact" : "comfortable" })}
          />
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
          <button type="button" className="btn btn-danger" onClick={ctx.signOut}>
            <Icon name="logout" /> Sign out…
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
    <Page
      title="Settings"
      brand
      actions={
        <>
          <PopOut />
          <Account state={state} onChange={ctx.reload} onSignOut={ctx.signOut} />
        </>
      }
    >
      <nav className="choices" aria-label="Settings">
        {sections.map((x) => (
          <ActionRow key={x.key} icon={x.icon} title={x.title} onClick={() => ctx.go({ tab: "settings", section: x.key })} />
        ))}
      </nav>
    </Page>
  );
}
