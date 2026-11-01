import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { LogoMark, Wordmark } from "@web/components/Logo";
import { ItemEditor } from "@web/components/ItemEditor";
import { ErrorText, Icon, PasswordInput, SiteIcon, type IconName } from "@web/components/ui";
import { emptyItem, KIND_LABEL, type Item, type ItemKind } from "@web/lib/types";
import { send, type ItemSummary, type PopupState, type Settings, type TwoFactorChallenge, type VaultTimeout } from "../shared/messages";

const msg = (e: unknown) => {
  const m = e instanceof Error ? e.message : String(e);
  return m === "secret_key_required" ? "This account uses a Secret Key. Enter it from your Emergency Kit." : m === "email_not_verified" ? "Confirm your email address first, then sign in." : m;
};

const seconds = (s: number) => (s < 60 ? `${s} seconds` : `${s / 60} minute${s > 60 ? "s" : ""}`);

/** Copies through the background, which also clears the clipboard after the user's delay (even once the popup closes). */
const copiedNote = (label: string, clearAfter: number) => `${label} copied.${clearAfter ? ` Clipboard clears in ${seconds(clearAfter)}.` : ""}`;

export function App() {
  const [state, setState] = useState<PopupState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const reload = useCallback(() => send<PopupState>({ type: "state" }).then(setState, (e) => setError(msg(e))), []);
  useEffect(() => void reload(), [reload]);

  if (!state) return <div className="pop-auth">{error ? <ErrorText error={error} /> : null}</div>;
  if (state.status === "setup") return <Setup onDone={reload} />;
  if (state.status === "logged-out") return <Login state={state} onDone={reload} />;
  if (state.status === "locked") return <Unlock state={state} onDone={reload} />;
  return <Main state={state} onChange={reload} />;
}

// ------------------------------------------------------------------ setup

function Setup({ onDone, initial = "" }: { onDone: () => void; initial?: string }) {
  const [url, setUrl] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await send({ type: "setServer", url });
      onDone();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }
  return (
    <form className="pop-auth" onSubmit={submit}>
      <div className="logo">
        <LogoMark size={48} />
      </div>
      <h1>Connect to your PassAuth server</h1>
      <label className="field">
        <span>Server address</span>
        <input className="input" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://vault.example.com" autoFocus required />
      </label>
      <ErrorText error={error} />
      <button className="btn btn-accent btn-block" disabled={busy || !url}>
        {busy ? "Checking…" : "Connect"}
      </button>
    </form>
  );
}

// ------------------------------------------------------------------ login

function Login({ state, onDone }: { state: PopupState; onDone: () => void }) {
  const [email, setEmail] = useState(state.email);
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [needKey, setNeedKey] = useState(false);
  const [challenge, setChallenge] = useState<TwoFactorChallenge | null>(null);
  const [provider, setProvider] = useState("totp");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await send<{ done?: true; twoFactor?: TwoFactorChallenge }>({ type: "login", email, password, secretKey: secretKey || undefined });
      if (r.twoFactor) {
        setChallenge(r.twoFactor);
        setProvider(r.twoFactor.providers[0]);
      } else onDone();
    } catch (err) {
      if (err instanceof Error && err.message === "secret_key_required") setNeedKey(true);
      setError(msg(err));
    } finally {
      setBusy(false);
    }
  }

  async function verify(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await send({ type: "verify2fa", token: challenge!.token, provider, code, remember: true });
      onDone();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }

  if (challenge) {
    return (
      <form className="pop-auth" onSubmit={verify}>
        <h1>Two-step login</h1>
        {challenge.providers.length > 1 && (
          <label className="field">
            <span>Verify with</span>
            <select className="select" value={provider} onChange={(e) => setProvider(e.target.value)}>
              {challenge.providers.map((p) => (
                <option key={p} value={p}>
                  {p === "totp" ? "Authenticator app" : p === "email" ? "Email code" : "Recovery code"}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="field">
          <span>{provider === "recovery" ? "Recovery code" : "6-digit code"}</span>
          <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" autoFocus required />
        </label>
        {provider === "email" && (
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => send({ type: "email2fa", token: challenge.token }).then(() => setNote(`Code sent to ${email}.`), (e) => setError(msg(e)))}
          >
            Email me a code
          </button>
        )}
        {note && <div className="alert alert-ok">{note}</div>}
        <ErrorText error={error} />
        <button className="btn btn-accent btn-block" disabled={busy || !code}>
          {busy ? "Verifying…" : "Verify and sign in"}
        </button>
      </form>
    );
  }

  return (
    <form className="pop-auth" onSubmit={submit}>
      <div className="logo">
        <LogoMark size={48} />
      </div>
      <h1>Sign in to PassAuth</h1>
      <label className="field">
        <span>Email</span>
        <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required autoFocus={!email} />
      </label>
      <label className="field">
        <span>Master password</span>
        <PasswordInput value={password} onChange={setPassword} autoFocus={!!email} />
      </label>
      {needKey && (
        <label className="field">
          <span>Secret Key</span>
          <input className="input mono" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} placeholder="PA1-XXXXXX-…" spellCheck={false} required />
        </label>
      )}
      <ErrorText error={error} />
      <button className="btn btn-accent btn-block" disabled={busy || !email || !password}>
        {busy ? "Signing in…" : "Sign in"}
      </button>
      <p className="small muted" style={{ textAlign: "center" }}>
        {new URL(state.server).host}
      </p>
    </form>
  );
}

function Unlock({ state, onDone }: { state: PopupState; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const needKey = state.secretKeyRequired && !state.secretKeyStored;
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await send({ type: "unlock", password, secretKey: secretKey || undefined });
      onDone();
    } catch (err) {
      setError(msg(err));
      setBusy(false);
    }
  }
  return (
    <form className="pop-auth" onSubmit={submit}>
      <div className="logo">
        <LogoMark size={48} />
      </div>
      <h1>Unlock PassAuth</h1>
      <p className="muted small" style={{ textAlign: "center" }}>
        {state.email}
      </p>
      <label className="field">
        <span>Master password</span>
        <PasswordInput value={password} onChange={setPassword} autoFocus />
      </label>
      {needKey && (
        <label className="field">
          <span>Secret Key</span>
          <input className="input mono" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} spellCheck={false} required />
        </label>
      )}
      <ErrorText error={error} />
      <button className="btn btn-accent btn-block" disabled={busy || !password}>
        {busy ? "Unlocking…" : "Unlock"}
      </button>
      <button type="button" className="btn btn-ghost" onClick={() => send({ type: "logout" }).then(onDone)}>
        Sign out
      </button>
    </form>
  );
}

// ------------------------------------------------------------------- main

type Tab = "vault" | "generator" | "settings";

type View = { at: "list" } | { at: "item"; id: string } | { at: "edit"; id: string } | { at: "new"; kind: ItemKind };

function Main({ state, onChange }: { state: PopupState; onChange: () => void }) {
  const [tab, setTab] = useState<Tab>("vault");
  const [view, setView] = useState<View>({ at: "list" });
  const [adding, setAdding] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const notify = useCallback((text: string) => {
    setNote(text);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setNote(null), 4000);
  }, []);
  const copy = useCallback(
    (req: { text: string } | { id: string; field: "username" | "password" | "totp" }, label: string) =>
      send("text" in req ? { type: "copy", text: req.text } : { type: "copyField", ...req }).then(
        () => notify(copiedNote(label, state.settings.clearClipboard)),
        (e) => notify(msg(e)),
      ),
    [notify, state.settings.clearClipboard],
  );
  const ctx = useMemo(() => ({ state, copy, notify }), [state, copy, notify]);
  return (
    <div className="pop">
      <header className="pop-head">
        <Wordmark />
        <span className="grow" />
        <div className="pop-more">
          <button className="btn btn-icon" title="New item" aria-label="New item" aria-expanded={adding} onClick={() => setAdding(!adding)}>
            <Icon name="plus" />
          </button>
          {adding && (
            <div className="pop-menu" role="menu" onClick={() => setAdding(false)}>
              {(Object.keys(KIND_LABEL) as ItemKind[]).map((k) => (
                <button key={k} role="menuitem" onClick={() => (setTab("vault"), setView({ at: "new", kind: k }))}>
                  {KIND_LABEL[k]}
                </button>
              ))}
            </div>
          )}
        </div>
        <button className="btn btn-icon" title="Open web vault" aria-label="Open web vault" onClick={() => chrome.tabs.create({ url: state.server })}>
          <Icon name="external" />
        </button>
        <button className="btn btn-icon" title="Lock" aria-label="Lock" onClick={() => send({ type: "lock" }).then(onChange)}>
          <Icon name="lock" />
        </button>
      </header>
      <main className="pop-body">
        {tab === "vault" && view.at === "list" && <ItemList ctx={ctx} onOpen={(id) => setView({ at: "item", id })} />}
        {tab === "vault" && view.at === "item" && (
          <Detail key={view.id} id={view.id} ctx={ctx} onBack={() => setView({ at: "list" })} onEdit={() => setView({ at: "edit", id: view.id })} />
        )}
        {tab === "vault" && (view.at === "edit" || view.at === "new") && (
          <EditorView
            key={view.at === "edit" ? view.id : view.kind}
            id={view.at === "edit" ? view.id : undefined}
            kind={view.at === "new" ? view.kind : undefined}
            ctx={ctx}
            onDone={(id) => setView(id ? { at: "item", id } : { at: "list" })}
          />
        )}
        {tab === "generator" && <Generator ctx={ctx} />}
        {tab === "settings" && <SettingsView state={state} onChange={onChange} notify={notify} />}
      </main>
      {note && (
        <div className="pop-note" role="status">
          {note}
        </div>
      )}
      <nav className="pop-tabs" aria-label="Sections">
        {(
          [
            ["vault", "Vault", "vault"],
            ["generator", "Generator", "dice"],
            ["settings", "Settings", "settings"],
          ] as const
        ).map(([t, label, icon]) => (
          <button key={t} aria-current={tab === t} onClick={() => (setTab(t), setView({ at: "list" }))}>
            <Icon name={icon} />
            {label}
          </button>
        ))}
      </nav>
    </div>
  );
}

interface Ctx {
  state: PopupState;
  copy: (req: { text: string } | { id: string; field: "username" | "password" | "totp" }, label: string) => Promise<void>;
  notify: (text: string) => void;
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function ItemList({ ctx, onOpen }: { ctx: Ctx; onOpen: (id: string) => void }) {
  const [data, setData] = useState<{ suggested: ItemSummary[]; all: ItemSummary[] } | null>(null);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [host, setHost] = useState("");
  const [menuFor, setMenuFor] = useState<string | null>(null);
  const { server, settings } = ctx.state;
  useEffect(() => {
    activeTab().then(async (tab) => {
      const url = tab?.url?.startsWith("http") ? tab.url : undefined;
      if (url) setHost(new URL(url).hostname);
      send({ type: "items", url }).then(setData, (e) => setError(msg(e)));
    });
  }, []);

  async function fill(id: string) {
    try {
      const tab = await activeTab();
      if (!tab?.id) return;
      await send({ type: "fill", id, tabId: tab.id });
      window.close();
    } catch (e) {
      setError(msg(e));
    }
  }

  if (!data) return error ? <ErrorText error={error} /> : null;
  const q = query.trim().toLowerCase();
  const filtered = q ? data.all.filter((i) => i.name.toLowerCase().includes(q) || i.subtitle.toLowerCase().includes(q)) : data.all;
  const row = (i: ItemSummary, canFill: boolean) => (
    <div className="pop-row" key={i.id}>
      <SiteIcon host={i.host} name={i.name} server={server} enabled={settings.showIcons} />
      <button className="main" onClick={() => onOpen(i.id)}>
        <span className="title">{i.name}</span>
        <span className="sub">{i.subtitle}</span>
      </button>
      {canFill && i.hasPassword && (
        <button className="btn btn-primary pop-fill" onClick={() => fill(i.id)}>
          Fill
        </button>
      )}
      {i.kind === "login" && (
        <div className="pop-more">
          <button className="btn btn-icon" aria-label={`Options for ${i.name}`} aria-expanded={menuFor === i.id} onClick={() => setMenuFor(menuFor === i.id ? null : i.id)}>
            <Icon name="more" />
          </button>
          {menuFor === i.id && (
            <div className="pop-menu" role="menu" onClick={() => setMenuFor(null)}>
              {i.subtitle && (
                <button role="menuitem" onClick={() => ctx.copy({ id: i.id, field: "username" }, "Username")}>
                  Copy username
                </button>
              )}
              {i.hasPassword && (
                <button role="menuitem" onClick={() => ctx.copy({ id: i.id, field: "password" }, "Password")}>
                  Copy password
                </button>
              )}
              {i.hasTotp && (
                <button role="menuitem" onClick={() => ctx.copy({ id: i.id, field: "totp" }, "Verification code")}>
                  Copy verification code
                </button>
              )}
              <button role="menuitem" onClick={() => onOpen(i.id)}>
                View item
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );

  return (
    <>
      <div className="pop-search">
        <input className="input" type="search" placeholder="Search vault" aria-label="Search vault" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus />
      </div>
      <ErrorText error={error} />
      {!q && host && (
        <>
          <div className="pop-section">Autofill suggestions for {host}</div>
          {data.suggested.length ? (
            <div className="pop-list">{data.suggested.map((i) => row(i, true))}</div>
          ) : (
            <p className="small muted">No logins saved for this site yet. Sign in and PassAuth will offer to save it.</p>
          )}
        </>
      )}
      <div className="pop-section">{q ? `Results for "${query}"` : `All items (${data.all.length})`}</div>
      {filtered.length ? (
        <div className="pop-list">{filtered.slice(0, 300).map((i) => row(i, data.suggested.some((s) => s.id === i.id)))}</div>
      ) : (
        <p className="small muted">{q ? "Nothing matches your search." : "Your vault is empty. Add items in the web vault."}</p>
      )}
    </>
  );
}

function Detail({ id, ctx, onBack, onEdit }: { id: string; ctx: Ctx; onBack: () => void; onEdit: () => void }) {
  const [item, setItem] = useState<Item | null>(null);
  const [canWrite, setCanWrite] = useState(false);
  const [code, setCode] = useState<{ code: string; remaining: number } | null>(null);
  const [show, setShow] = useState(false);
  const [confirmTrash, setConfirmTrash] = useState(false);
  useEffect(() => {
    send<{ item: Item; canWrite: boolean }>({ type: "item", id }).then((r) => (setItem(r.item), setCanWrite(r.canWrite)), (e) => ctx.notify(msg(e)));
  }, [id, ctx]);
  useEffect(() => {
    if (!item?.login?.totp) return;
    const tick = () => send({ type: "totp", id }).then(setCode, () => {});
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [item, id]);
  if (!item) return null;
  const l = item.login;
  const field = (label: string, value: string, secret = false) =>
    value ? (
      <div className="pop-row" key={label}>
        <div className="grow">
          <span className="sub">{label}</span>
          <span className={secret ? "mono" : undefined} style={{ display: "block", overflowWrap: "anywhere" }}>
            {secret && !show ? "••••••••••" : value}
          </span>
        </div>
        {secret && (
          <button className="btn btn-icon" aria-label={show ? "Hide" : "Show"} onClick={() => setShow(!show)}>
            <Icon name={show ? "eyeOff" : "eye"} />
          </button>
        )}
        <button className="btn btn-icon" aria-label={`Copy ${label.toLowerCase()}`} onClick={() => ctx.copy({ text: value }, label)}>
          <Icon name="copy" />
        </button>
      </div>
    ) : null;
  return (
    <>
      <div className="row-between">
        <button className="btn btn-ghost" onClick={onBack}>
          <Icon name="back" /> Back
        </button>
        {canWrite && (
          <button className="btn" onClick={onEdit}>
            <Icon name="edit" /> Edit
          </button>
        )}
      </div>
      <h2 style={{ overflowWrap: "anywhere" }}>{item.name}</h2>
      <div className="pop-list">
        {l && field("Username", l.username)}
        {l && field("Password", l.password, true)}
        {code && (
          <div className="pop-row">
            <div className="grow">
              <span className="sub">Verification code, {code.remaining}s left</span>
              <span className="totp-code" style={{ fontSize: "1.3rem" }}>
                {code.code.slice(0, 3)} {code.code.slice(3)}
              </span>
            </div>
            <button className="btn btn-icon" aria-label="Copy code" onClick={() => ctx.copy({ text: code.code }, "Verification code")}>
              <Icon name="copy" />
            </button>
          </div>
        )}
        {l?.urls.filter((u) => u.url).map((u, n) => field(n ? `Website ${n + 1}` : "Website", u.url))}
        {item.card && field("Card number", item.card.number, true)}
        {item.card && field("Security code", item.card.code, true)}
        {item.notes && field("Notes", item.notes)}
      </div>
      {l?.passkeys.length ? <p className="small muted">{l.passkeys.length === 1 ? "Has a passkey" : `Has ${l.passkeys.length} passkeys`} for {l.passkeys[0].rp_id}.</p> : null}
      {canWrite &&
        (confirmTrash ? (
          <div className="pop-card">
            <p className="small">Move "{item.name}" to the trash? You can restore it from the web vault.</p>
            <div className="row">
              <button className="btn btn-danger grow" onClick={() => send({ type: "trashItem", id }).then(() => (ctx.notify("Moved to trash."), onBack()), (e) => ctx.notify(msg(e)))}>
                Move to trash
              </button>
              <button className="btn grow" onClick={() => setConfirmTrash(false)}>
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <button className="btn btn-ghost pop-danger-link" onClick={() => setConfirmTrash(true)}>
            <Icon name="trash" /> Move to trash
          </button>
        ))}
    </>
  );
}

/** New item (pre-filled with the current website for logins) or edit an existing one. */
function EditorView({ id, kind, ctx, onDone }: { id?: string; kind?: ItemKind; ctx: Ctx; onDone: (id?: string) => void }) {
  const [init, setInit] = useState<{ item: Item; vaults: { id: string; name: string }[]; vaultId: string; folders: string[] } | null>(null);
  useEffect(() => {
    (async () => {
      const info = await send<{ vaults: { id: string; name: string }[]; folders: string[] }>({ type: "editorInfo" });
      if (id) {
        const r = await send<{ item: Item; vaultId: string }>({ type: "item", id });
        return setInit({ item: structuredClone(r.item), vaults: [], vaultId: r.vaultId, folders: info.folders });
      }
      const item = emptyItem(kind ?? "login");
      const tab = await activeTab();
      if (item.login && tab?.url?.startsWith("http")) {
        const u = new URL(tab.url);
        item.name = u.hostname.replace(/^www\./, "");
        item.login.urls = [{ url: u.origin, match: "default" }];
      }
      setInit({ item, vaults: info.vaults, vaultId: info.vaults[0]?.id ?? "", folders: info.folders });
    })().catch((e) => ctx.notify(msg(e)));
  }, [id, kind, ctx]);
  if (!init) return null;
  return (
    <div className="pop-editor">
      <ItemEditor
        initial={init.item}
        isNew={!id}
        vaults={init.vaults}
        defaultVault={init.vaultId}
        folders={init.folders}
        generate={() => send<string>({ type: "generate", mode: "password" })}
        onCancel={() => onDone(id)}
        onSave={async (item, vaultId) => {
          if (id) {
            await send({ type: "updateItem", id, item });
            ctx.notify("Changes saved.");
            onDone(id);
          } else {
            const newId = await send<string>({ type: "createItem", item, vaultId });
            ctx.notify("Item saved.");
            onDone(newId);
          }
        }}
      />
    </div>
  );
}

function Generator({ ctx }: { ctx: Ctx }) {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [length, setLength] = useState(20);
  const [value, setValue] = useState("");
  const gen = useCallback(
    () => send<string>({ type: "generate", mode, options: mode === "password" ? { length } : { words: Math.max(3, Math.round(length / 4)) } }).then(setValue),
    [mode, length],
  );
  useEffect(() => void gen(), [gen]);
  return (
    <>
      <div className="row">
        <button className={`btn grow${mode === "password" ? " btn-primary" : ""}`} onClick={() => setMode("password")}>
          Password
        </button>
        <button className={`btn grow${mode === "passphrase" ? " btn-primary" : ""}`} onClick={() => setMode("passphrase")}>
          Passphrase
        </button>
      </div>
      <div className="gen-out">{value}</div>
      <label className="field">
        <span>{mode === "password" ? `Length: ${length}` : `Words: ${Math.max(3, Math.round(length / 4))}`}</span>
        <input type="range" min={mode === "password" ? 8 : 12} max={mode === "password" ? 64 : 40} value={length} onChange={(e) => setLength(+e.target.value)} />
      </label>
      <div className="row">
        <button className="btn btn-accent grow" onClick={() => ctx.copy({ text: value }, mode === "password" ? "Password" : "Passphrase")}>
          Copy
        </button>
        <button className="btn grow" onClick={gen}>
          Regenerate
        </button>
      </div>
    </>
  );
}

// --------------------------------------------------------------- settings

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

function SettingsView({ state, onChange, notify }: { state: PopupState; onChange: () => void; notify: (t: string) => void }) {
  const [settings, setSettings] = useState(state.settings);
  const [changingServer, setChangingServer] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [lastSync, setLastSync] = useState(state.lastSync);
  const [neverSave, setNeverSave] = useState(state.neverSave);
  const [section, setSection] = useState<string | null>(null);
  if (changingServer) return <Setup initial={state.server} onDone={onChange} />;

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

  const timeoutLabel = TIMEOUTS.find(([v]) => v === settings.vaultTimeout)?.[1] ?? "";
  const sections: { key: string; title: string; icon: IconName; summary: string; body: ReactNode }[] = [
    {
      key: "security",
      title: "Account security",
      icon: "lock",
      summary: `${timeoutLabel} · ${settings.timeoutAction === "lock" ? "Lock" : "Log out"}`,
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
        <button className="btn" onClick={() => send({ type: "lock" }).then(onChange)}>
          <Icon name="lock" /> Lock now
        </button>
        </>
      ),
    },
    {
      key: "autofill",
      title: "Autofill",
      icon: "wand",
      summary: `Inline menu ${settings.inlineMenu === "off" ? "off" : settings.inlineMenu === "focus" ? "on field select" : "on icon click"} · ${MATCHES.find(([m]) => m === settings.defaultMatch)?.[1]}`,
      body: (
        <>
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
        </>
      ),
    },
    {
      key: "notifications",
      title: "Notifications",
      icon: "bell",
      summary: settings.askToSave ? `Ask to save logins${neverSave.length ? ` · ${neverSave.length} excluded` : ""}` : "Don't ask to save logins",
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
      key: "appearance",
      title: "Appearance",
      icon: "eye",
      summary: settings.showIcons ? "Website icons on" : "Website icons off",
      body: (
        <>
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
      key: "clipboard",
      title: "Clipboard",
      icon: "copy",
      summary: settings.clearClipboard ? `Clear after ${seconds(settings.clearClipboard)}` : "Never clear",
      body: (
        <>
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
        </label>
        </>
      ),
    },
    {
      key: "sync",
      title: "Sync",
      icon: "sync",
      summary: `Last sync: ${formatTime(lastSync)}`,
      body: (
        <>
        <button className="btn" onClick={sync} disabled={syncing}>
          <Icon name="sync" /> {syncing ? "Syncing…" : "Sync vault now"}
        </button>
        <p className="small muted" aria-live="polite">
          Last sync: {formatTime(lastSync)}
        </p>
        </>
      ),
    },
    {
      key: "account",
      title: "Account",
      icon: "person",
      summary: state.email,
      body: (
        <>
        <div>
          <div>{state.email}</div>
          <div className="small muted">{state.server}</div>
        </div>
        <button className="btn" onClick={() => send({ type: "logout" }).then(() => setChangingServer(true))}>
          Change server
        </button>
        <button className="btn btn-danger" onClick={() => send({ type: "logout" }).then(onChange)}>
          Log out
        </button>
        </>
      ),
    },
  ];
  const open = sections.find((x) => x.key === section);
  if (open) {
    return (
      <div className="stack">
        <div className="row">
          <button className="btn btn-ghost" onClick={() => setSection(null)}>
            <Icon name="back" /> Settings
          </button>
        </div>
        <h2>{open.title}</h2>
        <div className="pop-card">{open.body}</div>
      </div>
    );
  }
  return (
    <nav className="pop-list pop-settings-menu" aria-label="Settings">
      {sections.map((x) => (
        <button key={x.key} className="pop-row" onClick={() => setSection(x.key)}>
          <span className="pop-set-ic">
            <Icon name={x.icon} />
          </span>
          <span className="grow">
            <span className="title">{x.title}</span>
            <span className="sub">{x.summary}</span>
          </span>
          <Icon name="chevron" />
        </button>
      ))}
    </nav>
  );
}
